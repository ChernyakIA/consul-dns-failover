#!/usr/bin/env python3
"""
Selectel DNS Manager script. Run by Consul Template when Consul service statuses change.
Manages A records only.

1. Reads the JSON file produced by template-service.tpl.
2. Groups records by sel_zone_id and requests the rrset index once per zone.
3. Preserves DNS when the number of observers is insufficient (`unknown`).
4. When the state is known, selects IPs with site confirmations >= quorum;
   if none qualify, applies on_all_fail: keep/remove/fallback.
5. The CONSUL_HTTP_ADDR value -- the Consul API URL -- comes from the selectel.hcl template.

Current URL list: https://docs.selectel.ru/api/urls/

Variables:
  Required:
    SEL_ACCOUNT_ID                  Account/contract number
    SEL_SERVICE_USER                Service user name
    SEL_SERVICE_PASS                Service user password
    SEL_PROJECT_NAME                Name of the project that manages the DNS zones
    DNS_PROVIDER_NAME               Provider name (default: selecteldns)
    CONSUL_GC_PATH                  Consul KV path where the current state is stored

  Optional:
    LOG_LEVEL                       Logging level (default: INFO)
    SEL_AUTH_PROJECT_TOKEN_URL      Default: https://cloud.api.selcloud.ru/identity/v3/auth/tokens.
                                    Docs: https://docs.selectel.ru/api/authorization/#get-iam-token-project-scoped
    SEL_DNS_API_BASE                DNS API v2 (default: https://api.selectel.ru/domains/v2)
    SEL_LIST_RECORDS_LIMIT          Number of records requested per page (default: 40)
    HTTP_CONNECT_TIMEOUT            Connection timeout (default: 5 seconds)
    HTTP_READ_TIMEOUT               Response timeout (default: HTTP_TIMEOUT or 15 seconds)
    HTTP_RETRY_TOTAL                Number of retries for safe GET requests (default: 2)
    CONSUL_HTTP_TOKEN               Consul ACL token (if ACLs are enabled)
"""
from __future__ import annotations

import os
import sys
import logging
import requests

from dataclasses import dataclass
from typing import Any, Dict, Hashable, List, Optional, Tuple
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from dns_controller_common import (
    Decision,
    OwnershipBlocked,
    ProviderBackend,
    ProviderStateStore,
    build_identity,
    consul_addr_from_env,
    relative_record_name,
    run_sync,
)

# --------------------------------------------------------------------------- #
# Logging                                                                     #
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("dns-manager-selectel")

# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Config:
    account_id:         str
    service_user:       str
    service_pass:       str
    project_name:       str
    consul_gc_path:     str
    auth_url:           str
    dns_api_base:       str
    page_limit:         int
    http_connect_timeout: int
    http_read_timeout:  int
    http_retry_total:   int
    consul_addr:        str
    consul_token:       Optional[str]
    consul_cacert:      Optional[str]
    consul_config_path: str
    dns_provider_name:  str

    @staticmethod
    def from_env() -> "Config":
        # Validate required environment variables
        required_envs = [
            "SEL_ACCOUNT_ID",
            "SEL_SERVICE_USER",
            "SEL_SERVICE_PASS",
            "SEL_PROJECT_NAME",
            "CONSUL_GC_PATH",
            "CONSUL_HTTP_ADDR",
        ]
        missing_envs = [var for var in required_envs if var not in os.environ]
        if missing_envs:
            log.error("Missing required environment variables: %s", ", ".join(missing_envs))
            sys.exit(1)

        return Config(
            account_id   = os.environ["SEL_ACCOUNT_ID"],
            service_user = os.environ["SEL_SERVICE_USER"],
            service_pass = os.environ["SEL_SERVICE_PASS"],
            project_name = os.environ["SEL_PROJECT_NAME"],
            consul_gc_path = os.environ["CONSUL_GC_PATH"],
            auth_url     = os.environ.get(
                "SEL_AUTH_PROJECT_TOKEN_URL", "https://cloud.api.selcloud.ru/identity/v3/auth/tokens",
            ),
            dns_api_base = os.environ.get(
                "SEL_DNS_API_BASE", "https://api.selectel.ru/domains/v2",
            ).rstrip("/"),
            page_limit   = int(os.environ.get("SEL_LIST_RECORDS_LIMIT", "40")),
            http_connect_timeout = int(os.environ.get("HTTP_CONNECT_TIMEOUT", "5")),
            http_read_timeout = int(os.environ.get("HTTP_READ_TIMEOUT", os.environ.get("HTTP_TIMEOUT", "15"))),
            http_retry_total = int(os.environ.get("HTTP_RETRY_TOTAL", "2")),
            dns_provider_name = os.environ.get("DNS_PROVIDER_NAME", "selecteldns"),
            consul_addr  = consul_addr_from_env(),
            consul_token = os.environ.get("CONSUL_HTTP_TOKEN") or None,
            consul_cacert = os.environ.get("CONSUL_CACERT") or None,
            consul_config_path = os.environ.get(
                "CONSUL_CONFIG_PATH", "dns-failover/dns-failover-monitoring-config.yml"
            ),
        )

# --------------------------------------------------------------------------- #
# State storage in Consul KV                                                   #
# --------------------------------------------------------------------------- #
class ConsulStateStore(ProviderStateStore):
    """Ownership registry and desired records of the Selectel provider."""

    zone_backend_field = "sel_zone_id"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg, log)

    def desired_record(self, zone_name: str, backend: str,
                       record_name: str) -> Tuple[Hashable, Dict[str, Any]]:
        fqdn = make_fqdn(record_name, zone_name).casefold()
        return (backend, fqdn, "A"), {
            "fqdn": fqdn,
            "record": record_name,
            "zone": zone_name,
            "sel_zone_id": backend,
            "service_name": None,
        }

# --------------------------------------------------------------------------- #
# Selectel API                                                                #
# --------------------------------------------------------------------------- #
def get_iam_token(cfg: Config) -> str:
    """
    IAM project-scoped token. Automatically retries requests after network failures.
    Docs: https://docs.selectel.ru/api/authorization/#get-iam-token-project-scoped
    """
    payload = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": cfg.service_user,
                        "domain": {"name": cfg.account_id},
                        "password": cfg.service_pass,
                    }
                },
            },
            "scope": {
                "project": {
                    "name": cfg.project_name,
                    "domain": {"name": cfg.account_id},
                }
            },
        }
    }

    # Configure retries for DNS errors, timeouts, and 5xx responses
    # https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html
    # urllib3 does not retry POST by default; requesting a token is safe to repeat.
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1.5,
        allowed_methods=frozenset({"POST"}),
        status_forcelist=[500, 502, 503, 504],
        raise_on_status=False,
        connect=3,
        read=3
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    log.info("Requesting a Selectel IAM token ...")
    try:
        r = session.post(
            cfg.auth_url,
            json=payload,
            timeout=(cfg.http_connect_timeout, cfg.http_read_timeout),
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        # Log the error instead of a traceback and exit
        log.error("Selectel authentication failed: %s", e)
        raise SystemExit(1) from e
    tok = r.headers.get("X-Subject-Token")
    if not tok:
        raise RuntimeError("Selectel auth: X-Subject-Token was not returned")
    return tok

class SelectelDNS:
    """Interact with DNS API v2."""

    def __init__(self, cfg: Config, token: str):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.headers.update({
            "X-Auth-Token": token,
            "Content-Type": "application/json",
        })
        # Retry only safe GET requests. Automatic POST/PATCH/DELETE retries
        # may repeat an already applied DNS change.
        retries = Retry(
            total=cfg.http_retry_total,
            connect=cfg.http_retry_total,
            read=cfg.http_retry_total,
            status=cfg.http_retry_total,
            allowed_methods=frozenset({"GET"}),
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1.5,
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        self.s.mount("https://", HTTPAdapter(max_retries=retries))

    @property
    def timeout(self) -> Tuple[int, int]:
        return self.cfg.http_connect_timeout, self.cfg.http_read_timeout

    def _zone_url(self, zone_id: str) -> str:
        return f"{self.cfg.dns_api_base}/zones/{zone_id}"

    def _check(self, r: requests.Response, action: str) -> None:
        if r.status_code >= 400:
            body = (r.text or "").strip().replace("\n", " ")[:300]
            if r.status_code in (401, 403):
                explanation = "check the IAM token, project scope, and service user permissions for the DNS zone"
            elif r.status_code == 404:
                explanation = "check sel_zone_id and verify that the zone exists in the SEL_PROJECT_NAME project"
            elif r.status_code == 429:
                explanation = "Selectel rate-limited the requests; check the synchronization frequency and Retry-After"
            elif r.status_code >= 500:
                explanation = "check the Selectel DNS API status (https://selectel.live/status_pages/selectel/) and retry later"
            else:
                explanation = "inspect the HTTP response and check the response body and request parameters"
            raise RuntimeError(
                f"Selectel DNS API: operation {action} received HTTP response {r.status_code} -- {explanation}. API response: {body or '<empty>'}"
            )

    def _network_error(self, error: requests.RequestException, zone_id: str,
                       offset: int, attempts: int) -> RuntimeError:
        """Add request context to the original network error."""
        endpoint = f"{self._zone_url(zone_id)}/rrset"
        return RuntimeError(
            f"Selectel DNS API: request failed; zone={zone_id}, offset={offset}, endpoint={endpoint},"
            f"attempts={attempts} (connect timeout={self.cfg.http_connect_timeout}s, read timeout={self.cfg.http_read_timeout}s)."
            f"Error: {type(error).__name__}: {error}. DNS changes for this zone are skipped, and the state in Consul KV will not be updated.",
        )

    def list_rrsets(self, zone_id: str) -> Dict[Tuple[str, str], Dict[str, Any]]:
        """Build a paginated {(name_lower_no_dot, type): rrset} index."""
        idx: Dict[Tuple[str, str], Dict[str, Any]] = {}
        offset = 0
        url = f"{self._zone_url(zone_id)}/rrset"
        while True:
            attempts = self.cfg.http_retry_total + 1
            log.info(
                "Reading zone %s RRsets: offset=%s, up to %s attempts, connect/read timeout=%ss/%ss",
                zone_id,
                offset,
                attempts,
                self.cfg.http_connect_timeout,
                self.cfg.http_read_timeout,
            )
            try:
                r = self.s.get(
                    url,
                    params={"limit": self.cfg.page_limit, "offset": offset},
                    timeout=self.timeout,
                )
            except requests.RequestException as error:
                raise self._network_error(error, zone_id, offset, attempts) from error
            self._check(r, f"LIST rrset zone={zone_id}")
            data = r.json()
            results = data.get("result", []) or []
            for rs in results:
                name = (rs.get("name") or "").rstrip(".").lower()
                rtype = rs.get("type") or ""
                idx[(name, rtype)] = rs
            next_offset = data.get("next_offset", 0) or 0
            if not next_offset or len(results) < self.cfg.page_limit:
                break
            offset = next_offset
        return idx

    def create(self, zone_id: str, fqdn: str, rtype: str,
               ttl: int, ips: List[str]) -> None:
        payload = {
            "name": fqdn.rstrip(".") + ".",  # The FQDN must end with a dot
            "type": rtype,
            "ttl": int(ttl),
            "records": [{"content": ip, "disabled": False} for ip in ips],
        }
        r = self.s.post(f"{self._zone_url(zone_id)}/rrset", json=payload, timeout=self.timeout)
        self._check(r, f"CREATE {fqdn} {rtype}")

    def patch(self, zone_id: str, rrset_id: str,
              ttl: int, ips: List[str]) -> None:
        payload = {
            "ttl":     int(ttl),
            "records": [{"content": ip, "disabled": False} for ip in ips],
        }
        r = self.s.patch(f"{self._zone_url(zone_id)}/rrset/{rrset_id}", json=payload, timeout=self.timeout)
        self._check(r, f"PATCH rrset={rrset_id}")

    def delete(self, zone_id: str, rrset_id: str) -> None:
        r = self.s.delete(f"{self._zone_url(zone_id)}/rrset/{rrset_id}",
                          timeout=self.timeout)
        self._check(r, f"DELETE rrset={rrset_id}")

# --------------------------------------------------------------------------- #
# Record reconciliation                                                       #
# --------------------------------------------------------------------------- #
def make_fqdn(record: str, zone: str) -> str:
    record = (record or "").strip(".")
    zone   = (zone   or "").strip(".")
    if not record or record == "@":
        return zone
    return f"{record}.{zone}"


def identity_for_item(cfg: Config, item: Dict[str, Any]) -> Dict[str, str]:
    return build_identity(
        cfg.dns_provider_name,
        f"{cfg.account_id}/{cfg.project_name}",
        str(item["zone"]),
        str(item["sel_zone_id"]),
        "A",
        str(item.get("fqdn") or make_fqdn(str(item.get("record", "")), str(item["zone"]))),
    )

def reconcile_one(api: SelectelDNS,
                  item: Dict[str, Any],
                  decision: Decision,
                  zone_index: Dict[Tuple[str, str], Dict[str, Any]],
                  allow_delete: bool = True) -> bool:
    fqdn    = make_fqdn(item["record"], item["zone"])
    rtype   = "A"
    ttl     = int(item.get("ttl") or 60)
    svc     = item.get("service_name", fqdn)
    zone_id = item["sel_zone_id"]

    action, ips = decision.action, decision.ips
    existing = zone_index.get((fqdn.lower(), rtype))

    if action == "keep":
        log.info(
            "[%s] %s %s: keeping the current record -- %s",
            svc,
            fqdn,
            rtype,
            decision.explanation,
        )
        return False

    if action == "remove":
        if not allow_delete:
            log.warning("[%s] %s %s: deletion blocked -- the record is absent from the ownership registry", svc, fqdn, rtype)
            return False
        if existing:
            log.warning(
                "[%s] %s %s: deleting id=%s -- %s",
                svc,
                fqdn,
                rtype,
                existing["id"],
                decision.explanation,
            )
            api.delete(zone_id, existing["id"])
            return True
        log.info("[%s] %s %s: already absent", svc, fqdn, rtype)
        return False

    # action == "set"
    # Selectel rejects an empty list in a patch; handle and log it here.
    if not ips:
        log.warning(
            "[%s] %s %s: set with an empty IP list -- skipping; %s",
            svc,
            fqdn,
            rtype,
            decision.explanation,
        )
        return False

    # The rrset does not exist
    if not existing:
        log.warning(
            "[%s] %s %s: creating record with ttl=%s ips=%s -- %s",
            svc,
            fqdn,
            rtype,
            ttl,
            ips,
            decision.explanation,
        )
        api.create(zone_id, fqdn, rtype, ttl, ips)
        return True

    # The rrset exists
    cur_ips = sorted(
        (r.get("content") or "")
        for r in (existing.get("records") or [])
        if not r.get("disabled")
    )
    cur_ttl = int(existing.get("ttl") or 0)

    if cur_ips == ips and cur_ttl == ttl:
        log.info(
            "[%s] %s %s: already has %s with ttl=%s -- skipping; %s",
            svc,
            fqdn,
            rtype,
            ips,
            ttl,
            decision.explanation,
        )
        return False

    if not allow_delete:
        raise OwnershipBlocked(
            f"{fqdn} {rtype}: the record was not changed because it is absent from the ownership registry "
            "and differs from the desired state; "
            f"current state: ttl={cur_ttl}, ips={cur_ips}; "
            f"desired state: ttl={ttl}, ips={ips}"
        )

    log.warning(
        "[%s] %s %s: patching ttl %s->%s and/or ips %s->%s -- %s",
        svc,
        fqdn,
        rtype,
        cur_ttl,
        ttl,
        cur_ips,
        ips,
        decision.explanation,
    )
    api.patch(zone_id, existing["id"], ttl, ips)
    return True

def selectel_verified(index: Dict[Tuple[str, str], Dict[str, Any]],
                      item: Dict[str, Any], decision: Decision) -> Tuple[bool, bool]:
    fqdn = make_fqdn(str(item.get("record", "")), str(item["zone"])).rstrip(".").casefold()
    existing = index.get((fqdn, "A"))
    if decision.action == "remove":
        return False, existing is None
    if decision.action != "set" or existing is None:
        return False, False
    current_ips = sorted(
        str(record.get("content") or "")
        for record in (existing.get("records") or [])
        if not record.get("disabled")
    )
    current_ttl = int(existing.get("ttl") or 0)
    expected_ips = sorted(str(ip) for ip in decision.ips)
    expected_ttl = int(item.get("ttl") or 60)
    return current_ips == expected_ips and current_ttl == expected_ttl, False


# --------------------------------------------------------------------------- #
# Main script                                                                 #
# --------------------------------------------------------------------------- #
class SelectelBackend(ProviderBackend):
    """Selectel side of the shared synchronization flow; records are grouped by zone ID."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.api: Optional[SelectelDNS] = None

    @property
    def client(self) -> SelectelDNS:
        if self.api is None:
            raise RuntimeError("the Selectel client was used before connect()")
        return self.api

    def identity_for_item(self, item: Dict[str, Any]) -> Dict[str, str]:
        return identity_for_item(self.cfg, item)

    def group_key(self, item: Dict[str, Any]) -> Optional[Hashable]:
        zone_id = item.get("sel_zone_id")
        return str(zone_id) if zone_id else None

    def describe_group(self, group: Any) -> str:
        return f"zone {group}"

    def orphan_item(self, identity: Dict[str, str]) -> Dict[str, Any]:
        return {
            "record": relative_record_name(identity["fqdn"], identity["zone"]),
            "zone": identity["zone"],
            "sel_zone_id": identity["zone_id"],
            "status": "all_critical",
            "on_all_fail": "remove",
            "service_name": f"orphaned-{identity['fqdn']}",
        }

    def connect(self) -> None:
        # The IAM token is requested only when a provider change may be required.
        self.api = SelectelDNS(self.cfg, get_iam_token(self.cfg))

    def list_records(self, group: Any) -> Dict[Tuple[str, str], Dict[str, Any]]:
        return self.client.list_rrsets(str(group))

    def reconcile_one(self, item: Dict[str, Any], decision: Decision,
                      index: Any, allow_delete: bool) -> bool:
        return reconcile_one(self.client, item, decision, index, allow_delete=allow_delete)

    def verified(self, index: Any, item: Dict[str, Any], decision: Decision) -> Tuple[bool, bool]:
        return selectel_verified(index, item, decision)


def main() -> int:
    if len(sys.argv) < 2:
        log.error("Usage: dns-failover-manager-selectel.py <state.json>")
        return 2

    cfg = Config.from_env()
    return run_sync(sys.argv[1], ConsulStateStore(cfg), SelectelBackend(cfg), log)


if __name__ == "__main__":
    sys.exit(main())

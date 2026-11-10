#!/usr/bin/env python3
"""
Yandex Cloud DNS Manager script. Run by Consul Template when Consul service statuses change.
Manages A records only.

1. Reads the JSON file rendered by service-meta-output.tpl.
2. Groups records by yc_zone_id and requests the record-set index once per zone.
3. Preserves DNS when the number of observers is insufficient (`unknown`).
4. When the state is known, selects IPs with site confirmations >= quorum;
   if none qualify, applies on_all_fail: keep/remove/fallback.
5. The CONSUL_HTTP_ADDR value -- the Consul API URL -- comes from the yandex.hcl template.

API reference: https://yandex.cloud/en/docs/dns/api-ref/
The service account needs the dns.editor role for the zone or its folder.

Variables:
  Required:
    YC_SA_KEY_FILE                  Path to the service account authorized key (JSON with
                                    id, service_account_id, and private_key)
    DNS_PROVIDER_NAME               Provider name (default: yandexdns)
    CONSUL_GC_PATH                  Consul KV path where the current state is stored

  Optional:
    LOG_LEVEL                       Logging level (default: INFO)
    YC_IAM_TOKEN_URL                Default: https://iam.api.cloud.yandex.net/iam/v1/tokens.
                                    Docs: https://yandex.cloud/en/docs/iam/operations/iam-token/create-for-sa
    YC_DNS_API_BASE                 DNS API (default: https://dns.api.cloud.yandex.net/dns/v1)
    YC_OPERATION_API_BASE           Operation API (default: https://operation.api.cloud.yandex.net)
    YC_LIST_RECORDS_LIMIT           Number of record sets requested per page (default: 1000)
    YC_OPERATION_TIMEOUT            Seconds to wait for a DNS change to complete (default: 60)
    HTTP_CONNECT_TIMEOUT            Connection timeout (default: 5 seconds)
    HTTP_READ_TIMEOUT               Response timeout (default: HTTP_TIMEOUT or 15 seconds)
    HTTP_RETRY_TOTAL                Number of retries for safe GET requests (default: 2)
    CONSUL_HTTP_TOKEN               Consul ACL token (if ACLs are enabled)
"""
from __future__ import annotations

import json
import os
import sys
import time
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
log = logging.getLogger("dns-manager-yandex")

# Zone IDs are unique across Yandex Cloud, so the ownership identity needs no account scope.
IDENTITY_BACKEND = "yandex-cloud"
# The IAM API accepts a JWT that lives for at most one hour.
JWT_LIFETIME_SECONDS = 600

# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Config:
    sa_key_file:        str
    consul_gc_path:     str
    iam_token_url:      str
    dns_api_base:       str
    operation_api_base: str
    page_limit:         int
    operation_timeout:  int
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
        required_envs = ["YC_SA_KEY_FILE", "CONSUL_GC_PATH", "CONSUL_HTTP_ADDR"]
        missing_envs = [var for var in required_envs if var not in os.environ]
        if missing_envs:
            log.error("Missing required environment variables: %s", ", ".join(missing_envs))
            sys.exit(1)

        return Config(
            sa_key_file  = os.environ["YC_SA_KEY_FILE"],
            consul_gc_path = os.environ["CONSUL_GC_PATH"],
            iam_token_url = os.environ.get(
                "YC_IAM_TOKEN_URL", "https://iam.api.cloud.yandex.net/iam/v1/tokens",
            ),
            dns_api_base = os.environ.get(
                "YC_DNS_API_BASE", "https://dns.api.cloud.yandex.net/dns/v1",
            ).rstrip("/"),
            operation_api_base = os.environ.get(
                "YC_OPERATION_API_BASE", "https://operation.api.cloud.yandex.net",
            ).rstrip("/"),
            page_limit   = int(os.environ.get("YC_LIST_RECORDS_LIMIT", "1000")),
            operation_timeout = int(os.environ.get("YC_OPERATION_TIMEOUT", "60")),
            http_connect_timeout = int(os.environ.get("HTTP_CONNECT_TIMEOUT", "5")),
            http_read_timeout = int(os.environ.get("HTTP_READ_TIMEOUT", os.environ.get("HTTP_TIMEOUT", "15"))),
            http_retry_total = int(os.environ.get("HTTP_RETRY_TOTAL", "2")),
            dns_provider_name = os.environ.get("DNS_PROVIDER_NAME", "yandexdns"),
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
    """Ownership registry and desired records of the Yandex Cloud DNS provider."""

    zone_backend_field = "yc_zone_id"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg, log)

    def desired_record(self, zone_name: str, backend: str,
                       record_name: str) -> Tuple[Hashable, Dict[str, Any]]:
        fqdn = make_fqdn(record_name, zone_name).casefold()
        return (backend, fqdn, "A"), {
            "fqdn": fqdn,
            "record": record_name,
            "zone": zone_name,
            "yc_zone_id": backend,
            "service_name": None,
        }

# --------------------------------------------------------------------------- #
# Yandex Cloud API                                                            #
# --------------------------------------------------------------------------- #
def build_jwt(key: Dict[str, Any], audience: str, now: Optional[int] = None) -> str:
    """Sign the JWT that is exchanged for an IAM token (PS256 is the only accepted algorithm)."""
    missing = [field for field in ("id", "service_account_id", "private_key") if not key.get(field)]
    if missing:
        raise ValueError(f"the authorized key lacks required fields: {', '.join(missing)}")
    # Yandex Cloud puts a comment line before the PEM block.
    private_key = str(key["private_key"])
    pem_start = private_key.find("-----BEGIN")
    if pem_start < 0:
        raise ValueError("the authorized key private_key is not PEM-encoded")
    import jwt  # PyJWT with cryptography; imported here so the rest of the module works without it

    issued_at = int(time.time()) if now is None else now
    payload = {
        "aud": audience,
        "iss": key["service_account_id"],
        "iat": issued_at,
        "exp": issued_at + JWT_LIFETIME_SECONDS,
    }
    return jwt.encode(payload, private_key[pem_start:], algorithm="PS256", headers={"kid": key["id"]})


def get_iam_token(cfg: Config) -> str:
    """
    IAM token of the service account. Automatically retries requests after network failures.
    Docs: https://yandex.cloud/en/docs/iam/operations/iam-token/create-for-sa
    """
    try:
        with open(cfg.sa_key_file, "r", encoding="utf-8") as source:
            key = json.load(source)
        if not isinstance(key, dict):
            raise ValueError("the authorized key must be a JSON object")
        # The audience is fixed by the IAM API and does not follow YC_IAM_TOKEN_URL.
        signed = build_jwt(key, "https://iam.api.cloud.yandex.net/iam/v1/tokens")
    except Exception as e:
        # The message never includes key material.
        log.error("Yandex Cloud authentication failed: cannot use the authorized key %s: %s: %s",
                  cfg.sa_key_file, type(e).__name__, e)
        raise SystemExit(1) from e

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
    log.info("Requesting a Yandex Cloud IAM token ...")
    try:
        r = session.post(
            cfg.iam_token_url,
            json={"jwt": signed},
            timeout=(cfg.http_connect_timeout, cfg.http_read_timeout),
        )
        r.raise_for_status()
        tok = r.json().get("iamToken")
    except (requests.exceptions.RequestException, ValueError) as e:
        # Log the error instead of a traceback and exit
        log.error("Yandex Cloud authentication failed: %s", e)
        raise SystemExit(1) from e
    if not tok:
        raise RuntimeError("Yandex Cloud auth: iamToken was not returned")
    return tok


class YandexDNS:
    """Interact with the Cloud DNS API."""

    def __init__(self, cfg: Config, token: str):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        # Retry only safe GET requests. Automatic POST retries
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

    def _zone_url(self, zone_id: str, verb: str) -> str:
        return f"{self.cfg.dns_api_base}/zones/{zone_id}:{verb}"

    def _check(self, r: requests.Response, action: str) -> None:
        if r.status_code >= 400:
            body = (r.text or "").strip().replace("\n", " ")[:300]
            if r.status_code in (401, 403):
                explanation = "check the authorized key and the dns.editor role of the service account for the zone"
            elif r.status_code == 404:
                explanation = "check yc_zone_id and verify that the zone exists"
            elif r.status_code == 429:
                explanation = "Yandex Cloud rate-limited the requests; check the synchronization frequency"
            elif r.status_code >= 500:
                explanation = "check the Yandex Cloud status (https://status.yandex.cloud/) and retry later"
            else:
                explanation = "inspect the HTTP response and check the response body and request parameters"
            raise RuntimeError(
                f"Yandex Cloud DNS API: operation {action} received HTTP response {r.status_code} -- {explanation}. API response: {body or '<empty>'}"
            )

    def _request(self, method: str, url: str, action: str, **kwargs: Any) -> Dict[str, Any]:
        try:
            r = self.s.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as error:
            raise RuntimeError(
                f"Yandex Cloud DNS API: request failed; operation {action}, endpoint={url} "
                f"(connect timeout={self.cfg.http_connect_timeout}s, read timeout={self.cfg.http_read_timeout}s). "
                f"Error: {type(error).__name__}: {error}"
            ) from error
        self._check(r, action)
        data = r.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Yandex Cloud DNS API: operation {action} returned an unexpected response")
        return data

    def _wait(self, operation: Dict[str, Any], action: str) -> None:
        """DNS changes are asynchronous: wait for the operation and raise when it fails."""
        deadline = time.monotonic() + self.cfg.operation_timeout
        while True:
            error = operation.get("error")
            if error:
                raise RuntimeError(
                    f"Yandex Cloud DNS API: operation {action} failed -- "
                    f"code={error.get('code')}, message={error.get('message')}"
                )
            if operation.get("done"):
                return
            operation_id = operation.get("id")
            if not operation_id:
                raise RuntimeError(f"Yandex Cloud DNS API: operation {action} returned no operation ID")
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"Yandex Cloud DNS API: operation {action} (id={operation_id}) did not complete "
                    f"within {self.cfg.operation_timeout}s"
                )
            time.sleep(1)
            operation = self._request(
                "GET", f"{self.cfg.operation_api_base}/operations/{operation_id}", f"WAIT {action}",
            )

    def list_record_sets(self, zone_id: str) -> Dict[Tuple[str, str], Dict[str, Any]]:
        """Build a paginated {(name_lower_no_dot, type): record set} index of A record sets."""
        idx: Dict[Tuple[str, str], Dict[str, Any]] = {}
        page_token = ""
        while True:
            params = {"pageSize": self.cfg.page_limit, "filter": 'type="A"'}
            if page_token:
                params["pageToken"] = page_token
            log.info("Reading zone %s record sets%s", zone_id, " (next page)" if page_token else "")
            data = self._request(
                "GET", self._zone_url(zone_id, "listRecordSets"), f"LIST record sets zone={zone_id}",
                params=params,
            )
            for rs in data.get("recordSets") or []:
                name = (rs.get("name") or "").rstrip(".").lower()
                idx[(name, rs.get("type") or "")] = rs
            page_token = data.get("nextPageToken") or ""
            if not page_token:
                break
        return idx

    @staticmethod
    def _record_set(fqdn: str, ttl: int, ips: List[str]) -> Dict[str, Any]:
        return {
            "name": fqdn.rstrip(".") + ".",  # The FQDN must end with a dot
            "type": "A",
            "ttl": str(int(ttl)),  # int64 values are JSON strings in this API
            "data": list(ips),
        }

    def add_record_set(self, zone_id: str, fqdn: str, ttl: int, ips: List[str]) -> None:
        """Strict creation: the API rejects it when the record set already exists."""
        action = f"CREATE {fqdn} A"
        operation = self._request(
            "POST", self._zone_url(zone_id, "updateRecordSets"), action,
            json={"additions": [self._record_set(fqdn, ttl, ips)]},
        )
        self._wait(operation, action)

    def replace_record_set(self, zone_id: str, fqdn: str, ttl: int, ips: List[str]) -> None:
        """Replace the whole record set in one request, without a window with no record."""
        action = f"REPLACE {fqdn} A"
        operation = self._request(
            "POST", self._zone_url(zone_id, "upsertRecordSets"), action,
            json={"replacements": [self._record_set(fqdn, ttl, ips)]},
        )
        self._wait(operation, action)

    def delete_record_set(self, zone_id: str, record_set: Dict[str, Any]) -> None:
        """Strict deletion: the API rejects it when the record set changed since it was listed."""
        action = f"DELETE {record_set.get('name')} A"
        operation = self._request(
            "POST", self._zone_url(zone_id, "updateRecordSets"), action,
            json={"deletions": [record_set]},
        )
        self._wait(operation, action)

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
        IDENTITY_BACKEND,
        str(item["zone"]),
        str(item["yc_zone_id"]),
        "A",
        str(item.get("fqdn") or make_fqdn(str(item.get("record", "")), str(item["zone"]))),
    )


def _current_state(record_set: Dict[str, Any]) -> Tuple[int, List[str]]:
    return int(record_set.get("ttl") or 0), sorted(str(ip) for ip in (record_set.get("data") or []))


def reconcile_one(api: YandexDNS,
                  item: Dict[str, Any],
                  decision: Decision,
                  zone_index: Dict[Tuple[str, str], Dict[str, Any]],
                  allow_delete: bool = True) -> bool:
    fqdn    = make_fqdn(item["record"], item["zone"])
    rtype   = "A"
    ttl     = int(item.get("ttl") or 60)
    svc     = item.get("service_name", fqdn)
    zone_id = item["yc_zone_id"]

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
                "[%s] %s %s: deleting (current ips=%s) -- %s",
                svc,
                fqdn,
                rtype,
                _current_state(existing)[1],
                decision.explanation,
            )
            api.delete_record_set(zone_id, existing)
            return True
        log.info("[%s] %s %s: already absent", svc, fqdn, rtype)
        return False

    # action == "set"
    # A record set cannot be empty; handle and log it here.
    if not ips:
        log.warning(
            "[%s] %s %s: set with an empty IP list -- skipping; %s",
            svc,
            fqdn,
            rtype,
            decision.explanation,
        )
        return False

    # The record set does not exist
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
        api.add_record_set(zone_id, fqdn, ttl, ips)
        return True

    # The record set exists
    cur_ttl, cur_ips = _current_state(existing)

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
        "[%s] %s %s: updating ttl %s->%s and/or ips %s->%s -- %s",
        svc,
        fqdn,
        rtype,
        cur_ttl,
        ttl,
        cur_ips,
        ips,
        decision.explanation,
    )
    api.replace_record_set(zone_id, fqdn, ttl, ips)
    return True


def yandex_verified(index: Dict[Tuple[str, str], Dict[str, Any]],
                    item: Dict[str, Any], decision: Decision) -> Tuple[bool, bool]:
    fqdn = make_fqdn(str(item.get("record", "")), str(item["zone"])).rstrip(".").casefold()
    existing = index.get((fqdn, "A"))
    if decision.action == "remove":
        return False, existing is None
    if decision.action != "set" or existing is None:
        return False, False
    current_ttl, current_ips = _current_state(existing)
    expected_ips = sorted(str(ip) for ip in decision.ips)
    expected_ttl = int(item.get("ttl") or 60)
    return current_ips == expected_ips and current_ttl == expected_ttl, False


# --------------------------------------------------------------------------- #
# Main script                                                                 #
# --------------------------------------------------------------------------- #
class YandexBackend(ProviderBackend):
    """Yandex Cloud side of the shared synchronization flow; records are grouped by zone ID."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.api: Optional[YandexDNS] = None

    @property
    def client(self) -> YandexDNS:
        if self.api is None:
            raise RuntimeError("the Yandex Cloud DNS client was used before connect()")
        return self.api

    def identity_for_item(self, item: Dict[str, Any]) -> Dict[str, str]:
        return identity_for_item(self.cfg, item)

    def group_key(self, item: Dict[str, Any]) -> Optional[Hashable]:
        zone_id = item.get("yc_zone_id")
        return str(zone_id) if zone_id else None

    def describe_group(self, group: Any) -> str:
        return f"zone {group}"

    def orphan_item(self, identity: Dict[str, str]) -> Dict[str, Any]:
        return {
            "record": relative_record_name(identity["fqdn"], identity["zone"]),
            "zone": identity["zone"],
            "yc_zone_id": identity["zone_id"],
            "status": "all_critical",
            "on_all_fail": "remove",
            "service_name": f"orphaned-{identity['fqdn']}",
        }

    def connect(self) -> None:
        # The IAM token is requested only when a provider change may be required.
        self.api = YandexDNS(self.cfg, get_iam_token(self.cfg))

    def list_records(self, group: Any) -> Dict[Tuple[str, str], Dict[str, Any]]:
        return self.client.list_record_sets(str(group))

    def reconcile_one(self, item: Dict[str, Any], decision: Decision,
                      index: Any, allow_delete: bool) -> bool:
        return reconcile_one(self.client, item, decision, index, allow_delete=allow_delete)

    def verified(self, index: Any, item: Dict[str, Any], decision: Decision) -> Tuple[bool, bool]:
        return yandex_verified(index, item, decision)


def main() -> int:
    if len(sys.argv) < 2:
        log.error("Usage: dns-failover-manager-yandex.py <state.json>")
        return 2

    cfg = Config.from_env()
    return run_sync(sys.argv[1], ConsulStateStore(cfg), YandexBackend(cfg), log)


if __name__ == "__main__":
    sys.exit(main())

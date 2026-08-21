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
import json
import logging
import base64
import requests
import yaml

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from dns_controller_common import (
    ConsulProviderLock,
    OwnershipBlocked,
    build_identity,
    identity_key,
    load_registry_payload,
    registry_payload,
    transition_ownership,
    finish_ownership_sync,
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
            "CONSUL_GC_PATH"
        ]
        missing_envs = [var for var in required_envs if var not in os.environ]
        if missing_envs:
            log.error("Missing required environment variables: %s", ", ".join(missing_envs))
            sys.exit(1)

        consul_addr = os.environ["CONSUL_HTTP_ADDR"].rstrip("/")
        if not consul_addr.startswith(("http://", "https://")):
            consul_http_ssl = os.environ.get("CONSUL_HTTP_SSL", "true").strip().lower()
            scheme = "https" if consul_http_ssl in ("1", "true", "yes", "on") else "http"
            consul_addr = f"{scheme}://{consul_addr}"

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
            consul_addr  = consul_addr,
            consul_token = os.environ.get("CONSUL_HTTP_TOKEN") or None,
            consul_cacert = os.environ.get("CONSUL_CACERT") or None,
            consul_config_path = os.environ.get(
                "CONSUL_CONFIG_PATH", "dns-failover/dns-failover-monitoring-config.yml"
            ),
        )

# --------------------------------------------------------------------------- #
# State storage in Consul KV                                                   #
# --------------------------------------------------------------------------- #
class ConsulStateStore:
    """
    Stores the current list of provider-managed domains as separate JSON in KV.
    GC uses this file to identify records removed from the previous config version.
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.consul_cacert:
            self.session.verify = cfg.consul_cacert
        if cfg.consul_token:
            self.session.headers["X-Consul-Token"] = cfg.consul_token

    def provider_lock(self) -> ConsulProviderLock:
        lock_key = f"{self.cfg.consul_gc_path.rstrip('/')}/locks/{self.cfg.dns_provider_name}"
        return ConsulProviderLock(
            self.session, self.cfg.consul_addr, lock_key, self.cfg.dns_provider_name,
            ttl_seconds=30, renew_interval_seconds=10, lock_delay_seconds=5,
        )

    def load_active_records(self) -> Tuple[List[Dict[str, str]], str, bool]:
        """Read the current registry."""
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_gc_path}{self.cfg.dns_provider_name}-active-config"
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 404:
                log.info("The ownership registry is empty (first run).")
                return [], "N/A (cold start)", True
            response.raise_for_status()
            raw_value = response.json()[0].get("Value")
            if not raw_value:
                return [], "N/A (empty key value)", True
            payload = json.loads(base64.b64decode(raw_value).decode("utf-8"))
            records = load_registry_payload(payload, self.cfg.dns_provider_name)
            updated_at = payload.get("updated_at") or "Date/time not specified"
            return records, updated_at, True
        except Exception as error:
            log.warning(
                "Failed to read the registry: %s. "
                "Provider changes and registry writes are disabled.",
                error,
            )
            return [], "N/A (Consul API read error)", False

    def load_desired_records(self) -> Tuple[List[Dict[str, Any]], bool]:
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_config_path}"
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 404:
                log.error("The desired YAML configuration is missing from KV at %s; GC is disabled", self.cfg.consul_config_path)
                return [], False
            response.raise_for_status()
            encoded = response.json()[0].get("Value")
            if not encoded:
                return [], False
            document = yaml.safe_load(base64.b64decode(encoded).decode("utf-8"))
            if not isinstance(document, dict) or not isinstance(document.get("zones"), list):
                raise ValueError("The desired YAML configuration in KV must contain a zones array")
            records: List[Dict[str, Any]] = []
            seen = set()
            for zone_index, zone in enumerate(document["zones"]):
                if not isinstance(zone, dict) or not isinstance(zone.get("dns_provider"), str):
                    raise ValueError(f"zones[{zone_index}]: dns_provider is required")
                if zone["dns_provider"] != self.cfg.dns_provider_name:
                    continue
                zone_name = zone.get("zone_name")
                zone_id = zone.get("sel_zone_id")
                zone_records = zone.get("records")
                if not zone_name or not zone_id or not isinstance(zone_records, list):
                    raise ValueError(f"zones[{zone_index}]: zone_name, sel_zone_id, and records are required")
                for record_index, record in enumerate(zone_records):
                    if not isinstance(record, dict) or record.get("name") is None:
                        raise ValueError(f"zones[{zone_index}].records[{record_index}]: name is required")
                    fqdn = make_fqdn(str(record["name"]), str(zone_name)).casefold()
                    duplicate_key = (str(zone_id), fqdn, "A")
                    if duplicate_key in seen:
                        raise ValueError(f"duplicate record in the configuration file: {duplicate_key}")
                    seen.add(duplicate_key)
                    records.append({
                        "fqdn": fqdn,
                        "record": str(record["name"]),
                        "zone": str(zone_name),
                        "sel_zone_id": str(zone_id),
                        "service_name": None,
                    })
            return records, True
        except (requests.RequestException, ValueError, KeyError, yaml.YAMLError) as error:
            log.error("Failed to read the desired YAML configuration from KV; GC is disabled: %s", error)
            return [], False

    def save_active_records(self, ownership_records: List[Dict[str, Any]]) -> None:
        """Save the minimal ownership registry; called only by the lock holder."""
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_gc_path}{self.cfg.dns_provider_name}-active-config"
        payload = json.dumps(
            registry_payload(ownership_records),
            indent=2,
            ensure_ascii=False,
        )
        response = self.session.put(url, data=payload, timeout=5)
        response.raise_for_status()
        log.info("The ownership registry (GC registry) was updated in Consul KV")

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
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1.5,
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
# Decision logic                                                              #
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

@dataclass(frozen=True)
class Decision:
    action: str
    ips: List[str]
    explanation: str


def _format_counts(values: Dict[str, Any], ips: List[str], threshold: int) -> str:
    return ", ".join(
        f"{ip}={int(values.get(ip, 0))}/{threshold}" for ip in sorted(ips)
    )


def decide(item: Dict[str, Any]) -> Decision:
    """
    Return the action, IPs, and a clear explanation of the decision.
    Count votes by unique sites rather than by the number of Consul agents.
    """
    quorum = int(item.get("quorum") or 1)
    minimum_observers = int(item.get("minimum_observers") or quorum)
    candidates = item.get("candidates") or list((item.get("observations") or {}).keys())
    observations = item.get("observations") or {}
    confirms = item.get("confirmations") or {}
    on_all_fail = (item.get("on_all_fail") or "keep").lower()
    fallback = (item.get("fallback_ip") or "").strip()

    insufficient = [
        ip for ip in candidates
        if int(observations.get(ip, 0)) < minimum_observers
    ]
    if insufficient:
        return Decision(
            "keep",
            [],
            "insufficient observations: "
            f"{_format_counts(observations, insufficient, minimum_observers)}; "
            f"minimum_observers={minimum_observers}, quorum={quorum}",
        )

    ips = sorted(ip for ip in candidates if int(confirms.get(ip, 0)) >= quorum)
    if ips:
        return Decision(
            "set",
            ips,
            f"quorum={quorum} reached: {_format_counts(confirms, ips, quorum)}",
        )

    failed_summary = _format_counts(confirms, candidates, quorum)
    if on_all_fail == "remove":
        return Decision(
            "remove",
            [],
            f"no IP reached quorum={quorum}: {failed_summary}; on_all_fail=remove",
        )
    if on_all_fail == "fallback" and fallback:
        return Decision(
            "set",
            [fallback],
            f"no IP reached quorum={quorum}: {failed_summary}; "
            f"on_all_fail=fallback, fallback_ip={fallback}",
        )
    return Decision(
        "keep",
        [],
        f"no IP reached quorum={quorum}: {failed_summary}; on_all_fail=keep",
    )

def reconcile_one(api: SelectelDNS,
                  item: Dict[str, Any],
                  zone_index: Dict[Tuple[str, str], Dict[str, Any]],
                  allow_delete: bool = True) -> bool:
    fqdn    = make_fqdn(item["record"], item["zone"])
    rtype   = "A"
    ttl     = int(item.get("ttl") or 60)
    svc     = item.get("service_name", fqdn)
    zone_id = item["sel_zone_id"]

    decision = decide(item)
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

# --------------------------------------------------------------------------- #
# Main script                                                                 #
# --------------------------------------------------------------------------- #
def load_items(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Expected a top-level JSON array, but received an object")
    return data


def relative_record_name(fqdn: str, zone: str) -> str:
    fqdn_value = fqdn.rstrip(".")
    zone_value = zone.rstrip(".")
    if fqdn_value.casefold() == zone_value.casefold():
        return "@"
    suffix = "." + zone_value.casefold()
    if fqdn_value.casefold().endswith(suffix):
        return fqdn_value[: -len(suffix)]
    raise ValueError(f"FQDN {fqdn!r} does not belong to zone {zone!r}")


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


def main() -> int:
    if len(sys.argv) < 2:
        log.error("Usage: dns-failover-manager-selectel.py <state.json>")
        return 2

    src = sys.argv[1]
    cfg = Config.from_env()
    state_store = ConsulStateStore(cfg)

    try:
        with state_store.provider_lock() as provider_lock:
            provider_lock.assert_held()
            log.info("After acquiring the provider lock, reading the current final state from %s", src)
            items = load_items(src)

            previous_records, last_updated_at, previous_known = state_store.load_active_records()
            current_desired, desired_known = state_store.load_desired_records()
            log.info("Ownership registry read; previous update time: %s", last_updated_at)
            if not previous_known or not desired_known:
                log.error(
                    "The ownership registry or desired configuration is unavailable: "
                    "provider synchronization and all DNS changes are disabled"
                )
                return 1

            owned = {identity_key(identity): identity for identity in previous_records}
            desired_by_key: Dict[str, Dict[str, Any]] = {}
            for record in current_desired:
                desired_by_key[identity_key(identity_for_item(cfg, record))] = record

            orphan_keys = set(owned) - set(desired_by_key) if previous_known and desired_known else set()
            by_zone: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

            for item in items:
                zone_id = item.get("sel_zone_id")
                if not zone_id:
                    continue
                identity = identity_for_item(cfg, item)
                key = identity_key(identity)
                if not desired_known or key in desired_by_key:
                    enriched = dict(item)
                    enriched["_identity"] = identity
                    by_zone[str(zone_id)].append(enriched)

            for key in orphan_keys:
                identity = owned[key]
                by_zone[str(identity["zone_id"])].append({
                    "record": relative_record_name(identity["fqdn"], identity["zone"]),
                    "zone": identity["zone"],
                    "sel_zone_id": identity["zone_id"],
                    "status": "all_critical",
                    "on_all_fail": "remove",
                    "service_name": f"orphaned-{identity['fqdn']}",
                    "_identity": identity,
                })

            if not by_zone:
                log.info("No records to synchronize; saving the known empty ownership registry")
                provider_lock.assert_held()
                state_store.save_active_records(list(owned.values()))
                return 0

            decision_pairs = [(item, decide(item)) for values in by_zone.values() for item in values]
            if all(decision.action == "keep" for _, decision in decision_pairs):
                log.info("All decisions are keep; the DNS provider will not be queried")
                return 0

            provider_lock.assert_held()
            api = SelectelDNS(cfg, get_iam_token(cfg))
            errors = 0
            safely_skipped = 0

            for zone_id, zone_items in by_zone.items():
                try:
                    before = api.list_rrsets(zone_id)
                except Exception as error:
                    log.error("Failed to read RRsets for zone %s: %s", zone_id, error)
                    errors += len(zone_items)
                    continue

                attempted: List[Tuple[Dict[str, Any], Decision, bool, bool]] = []
                for item in zone_items:
                    identity = item["_identity"]
                    key = identity_key(identity)
                    decision = decide(item)
                    allow_delete = key in owned
                    try:
                        provider_lock.assert_held()
                        changed = reconcile_one(api, item, before, allow_delete=allow_delete)
                        attempted.append((item, decision, allow_delete, changed))
                    except OwnershipBlocked as reason:
                        log.warning("[%s] safely skipping record: %s", item.get("service_name"), reason)
                        safely_skipped += 1
                    except Exception as error:
                        log.error("[%s] failed to apply changes: %s", item.get("service_name"), error)
                        errors += 1

                needs_readback = any(
                    # item, decision, and allow_delete are unused
                    changed for _, _, _, changed in attempted
                )
                after = before
                if needs_readback:
                    try:
                        provider_lock.assert_held()
                        after = api.list_rrsets(zone_id)
                    except Exception as error:
                        log.error("Failed to reread the state of zone %s: %s", zone_id, error)
                        errors += len(attempted)
                        continue

                # changed is unused
                for item, decision, allow_delete, _ in attempted:
                    identity = item["_identity"]
                    if decision.action == "remove" and not allow_delete:
                        continue
                    present, absent = selectel_verified(after, item, decision)
                    _, transition_error = transition_ownership(
                        owned, identity, decision.action, present, absent
                    )
                    if transition_error:
                        log.error("[%s] record ownership was not confirmed: %s", item.get("service_name"), transition_error)
                        errors += 1

            if safely_skipped:
                log.warning(
                    "Safely skipped unconfirmed records: %d. "
                    "DNS was not changed; waiting for the next final-state update.",
                    safely_skipped,
                )
            if errors:
                log.error(
                    "Synchronization completed with errors (%d); "
                    "only confirmed ownership-registry changes are saved",
                    errors,
                )
            if not previous_known or not desired_known:
                log.warning("The ownership registry or desired configuration is unavailable: the registry will not be updated")
            return finish_ownership_sync(
                state_store, provider_lock, owned, previous_known, desired_known, errors
            )
    except (OSError, json.JSONDecodeError, ValueError, requests.RequestException, RuntimeError) as error:
        log.error("DNS synchronization failed: %s", error)
        return 1


if __name__ == "__main__":
    sys.exit(main())

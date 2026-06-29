#!/usr/bin/env python3
"""
Selectel DNS-Manager script. Triggered by Consul-Template upon changes in Consul service statuses.
Manages A-records exclusively.

1. Reads a JSON file output from template-service.tpl.
2. Groups records by sel_zone_id and fetches the rrset index once per zone.
3. Filters records based on conditions: on_all_fail, fallback_ip, and quorum:
    status == "ok" -- Reconciles the rrset address list with the desired set.
    status == "all_critical" -- Handled according to the on_all_fail parameter:
        "keep" -- skip / no action
        "remove" -- delete the rrset
        "fallback" -- apply the specified fallback address

Up-to-date API Documentation: https://docs.selectel.ru/api/urls/

Environment Variables:
  Required:
    SEL_ACCOUNT_ID                  Account / Contract number
    SEL_SERVICE_USER                Service user name
    SEL_SERVICE_PASS                Service user password
    SEL_PROJECT_NAME                Project name under which DNS zones are managed
    CONSUL_GC_PATH                  Consul KV path where the current state is stored

  Optional:
    LOG_LEVEL                       Logging severity level (defaults to INFO)
    CONSUL_HTTP_ADDR                Consul UI URL (defaults to http://consul.example.com)
    DNS_PROVIDER_NAME               DNS provider name (defaults to "selecteldns")
    SEL_AUTH_PROJECT_TOKEN_URL      OAuth authorization token URL. Defaults to 
                                    https://cloud.api.selcloud.ru/identity/v3/auth/tokens.
                                    Docs: https://docs.selectel.ru/api/authorization/#get-iam-token-project-scoped
    SEL_DNS_API_BASE                DNS API v2 endpoint (defaults to https://api.selectel.ru/domains/v2)
    SEL_LIST_RECORDS_LIMIT          Number of requested records per page for pagination (defaults to 40)
    HTTP_TIMEOUT                    HTTP request timeout in seconds (defaults to 15)
    CONSUL_HTTP_TOKEN               Consul ACL token (if ACLs are enabled)
"""
from __future__ import annotations

import os
import sys
import json
import logging
import base64
import requests

from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --------------------------------------------------------------------------- #
# Logging Setup                                                               #
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
    http_timeout:       int
    consul_addr:        str
    consul_token:       Optional[str]
    dns_provider_name:  str

    @staticmethod
    def from_env() -> "Config":
        # Validate mandatory environment variables
        required_envs = [
            "SEL_ACCOUNT_ID",
            "SEL_SERVICE_USER",
            "SEL_SERVICE_PASS",
            "SEL_PROJECT_NAME",
            "CONSUL_GC_PATH"
        ]
        missing_envs = [var for var in required_envs if var not in os.environ]
        if missing_envs:
            log.error("Missing mandatory environment variables: %s", ", ".join(missing_envs))
            sys.exit(1)

        consul_addr = os.environ.get("CONSUL_HTTP_ADDR", "http://consul.example.com").rstrip("/")
        if not consul_addr.startswith(("http://", "https://")):
            log.warning("CONSUL_HTTP_ADDR '%s' does not start with a protocol schema. Prepending 'http://'", consul_addr)
            consul_addr = f"http://{consul_addr}"

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
            http_timeout = int(os.environ.get("HTTP_TIMEOUT", "15")),
            dns_provider_name = os.environ.get("DNS_PROVIDER_NAME", "selecteldns"),
            consul_addr  = consul_addr,
            consul_token = os.environ.get("CONSUL_HTTP_TOKEN") or None
        )

# --------------------------------------------------------------------------- #
# State Store in Consul KV                                                    #
# --------------------------------------------------------------------------- #
class ConsulStateStore:
    """
    Persists the actively tracked list of provider domains in a separate JSON payload in Consul KV.
    This manifest is used by the Garbage Collector cycle to identify and delete legacy records
    removed from the previous configuration state.
    """
    
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.consul_token:
            self.session.headers["X-Consul-Token"] = cfg.consul_token

    def load_active_records(self) -> Tuple[List[Dict[str, Any]], str]:
        """Loads the registry of active tracked FQDNs and its commit timestamp."""
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_gc_path}{self.cfg.dns_provider_name}-active-config"
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code == 404:
                log.info("Tracked domains registry is empty (cold start).")
                return [], "N/A (cold start)"
            r.raise_for_status()

            raw_val = r.json()[0].get("Value")
            if not raw_val:
                return [], "N/A (empty key content)"
            
            decoded = base64.b64decode(raw_val).decode("utf-8")
            parsed_data = json.loads(decoded)

            if isinstance(parsed_data, dict):
                records = parsed_data.get("records") or []
                updated_at = parsed_data.get("updated_at") or "Timestamp not specified"
                return records, updated_at

            return [], "N/A (invalid payload structure in KV)"

        except Exception as e:
            log.warning("Failed to retrieve state from Consul KV: %s. Proceeding without historical state context.", e)
            return [], "N/A (Consul API read failure)"

    def save_active_records(self, state_records: List[Dict[str, Any]]) -> None:
        """Atomically persists the active tracked record set to Consul KV."""
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_gc_path}{self.cfg.dns_provider_name}-active-config"
        now_str = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        payload_dict = {
            "updated_at": now_str,
            "records": state_records
        }
        try:
            payload = json.dumps(payload_dict, indent=2, ensure_ascii=False)
            r = self.session.put(url, data=payload, timeout=5)
            r.raise_for_status()
            log.info("Active domain registry successfully synchronized inside Consul KV. Timestamp: %s", now_str)
        except Exception as e:
            log.error("Failed to persist state inside Consul KV: %s", e)

# --------------------------------------------------------------------------- #
# Selectel API Integration                                                    #
# --------------------------------------------------------------------------- #
def get_iam_token(cfg: Config) -> str:
    """
    Requests a project-scoped IAM token. Handles request retries dynamically on transient network errors.
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

    # Setup automated retries for DNS issues, connection limits, timeouts, and redundant 5xx errors
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
    log.info("Requesting Selectel IAM Token...")
    try:
        r = session.post(cfg.auth_url, json=payload, timeout=cfg.http_timeout)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        # Gracefully log authorization exceptions instead of exposing raw call stacks
        log.error("Selectel authentication failed: %s", e)
        raise SystemExit(1) from e
    tok = r.headers.get("X-Subject-Token")
    if not tok:
        raise RuntimeError("Selectel auth authorization error: Empty X-Subject-Token header received")
    return tok

class SelectelDNS:
    """Selectel DNS API v2 interface."""

    def __init__(self, cfg: Config, token: str):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.headers.update({
            "X-Auth-Token": token,
            "Content-Type": "application/json",
        })

    def _zone_url(self, zone_id: str) -> str:
        return f"{self.cfg.dns_api_base}/zones/{zone_id}"

    def _check(self, r: requests.Response, action: str) -> None:
        if r.status_code >= 400:
            body = (r.text or "").strip().replace("\n", " ")[:300]
            raise RuntimeError(f"{action} failed: HTTP {r.status_code} - {body}")

    def list_rrsets(self, zone_id: str) -> Dict[Tuple[str, str], Dict[str, Any]]:
        """Retrieves a {(name_lower_no_dot, type): rrset} record index, supporting API pagination."""
        idx: Dict[Tuple[str, str], Dict[str, Any]] = {}
        offset = 0
        url = f"{self._zone_url(zone_id)}/rrset"
        while True:
            r = self.s.get(
                url,
                params={"limit": self.cfg.page_limit, "offset": offset},
                timeout=self.cfg.http_timeout,
            )
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
            "name": fqdn.rstrip(".") + ".",  # FQDN must carry a trailing dot
            "type": rtype,
            "ttl": int(ttl),
            "records": [{"content": ip, "disabled": False} for ip in ips],
        }
        r = self.s.post(f"{self._zone_url(zone_id)}/rrset", json=payload, timeout=self.cfg.http_timeout)
        self._check(r, f"CREATE {fqdn} {rtype}")

    def patch(self, zone_id: str, rrset_id: str,
              ttl: int, ips: List[str]) -> None:
        payload = {
            "ttl":     int(ttl),
            "records": [{"content": ip, "disabled": False} for ip in ips],
        }
        r = self.s.patch(f"{self._zone_url(zone_id)}/rrset/{rrset_id}", json=payload, timeout=self.cfg.http_timeout)
        self._check(r, f"PATCH rrset={rrset_id}")

    def delete(self, zone_id: str, rrset_id: str) -> None:
        r = self.s.delete(f"{self._zone_url(zone_id)}/rrset/{rrset_id}",
                          timeout=self.cfg.http_timeout)
        self._check(r, f"DELETE rrset={rrset_id}")

# --------------------------------------------------------------------------- #
# Failover & Reconciliation Logic                                              #
# --------------------------------------------------------------------------- #
def make_fqdn(record: str, zone: str) -> str:
    record = (record or "").strip(".")
    zone   = (zone   or "").strip(".")
    if not record or record == "@":
        return zone
    return f"{record}.{zone}"

def decide(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    """
    Evaluates service cluster health and determines the targets.
    Returns (action, ips). Actions: "set", "remove", "keep".
    [DEV NOTE]: The 'quorum' option validation is pre-handled during configuration templating;
    however, this logical branch handles any valid integer parameter >= 1.
    """
    status      = item.get("status")
    quorum      = int(item.get("quorum") or 1)
    confirms    = item.get("confirmations") or {}
    on_all_fail = (item.get("on_all_fail") or "keep").lower()
    fallback    = (item.get("fallback_ip") or "").strip()

    if status == "ok":
        ips = sorted(ip for ip, c in confirms.items() if int(c) >= quorum)
        if ips:
            return "set", ips
        # All validations failed to meet quorum threshold -> treat as 'all_critical'
        status = "all_critical"

    if status == "all_critical":
        if on_all_fail == "remove":
            return "remove", []
        if on_all_fail == "fallback" and fallback:
            return "set", [fallback]
        return "keep", []

    log.warning("Unknown status='%s' -- falling back to 'keep'", status)
    return "keep", []

def reconcile_one(api: SelectelDNS,
                  item: Dict[str, Any],
                  zone_index: Dict[Tuple[str, str], Dict[str, Any]]) -> None:
    fqdn    = make_fqdn(item["record"], item["zone"])
    rtype   = "A"
    ttl     = int(item.get("ttl") or 60)
    svc     = item.get("service_name", fqdn)
    zone_id = item["sel_zone_id"]

    action, ips = decide(item)
    existing    = zone_index.get((fqdn.lower(), rtype))

    if action == "keep":
        log.info("[%s] %s %s: holding record (on_all_fail=keep)",
                 svc, fqdn, rtype)
        return

    if action == "remove":
        if existing:
            log.warning("[%s] %s %s: purging rrset id=%s",
                     svc, fqdn, rtype, existing["id"])
            api.delete(zone_id, existing["id"])
        else:
            log.info("[%s] %s %s: record resource is already absent",
                     svc, fqdn, rtype)
        return

    # action == "set"
    # Selectel DNS API raises validation exceptions on blank updates; skip to prevent hard failures.
    if not ips:
        log.warning("[%s] %s %s: 'set' operation received with blank IP payload -- skipping",
                    svc, fqdn, rtype)
        return

    # If rrset does not exist
    if not existing:
        log.warning("[%s] %s %s: creating new rrset with ttl=%s ips=%s",
                 svc, fqdn, rtype, ttl, ips)
        api.create(zone_id, fqdn, rtype, ttl, ips)
        return
    
    # If rrset already exists
    cur_ips = sorted(
        (r.get("content") or "")
        for r in (existing.get("records") or [])
        if not r.get("disabled")
    )
    cur_ttl = int(existing.get("ttl") or 0)

    if cur_ips == ips and cur_ttl == ttl:
        log.info("[%s] %s %s: configuration aligns with desired state (%s, ttl=%s) -- skipping",
                 svc, fqdn, rtype, ips, ttl)
        return

    log.info("[%s] %s %s: patching record (ttl: %s->%s, ips: %s->%s)",
             svc, fqdn, rtype, cur_ttl, ttl, cur_ips, ips)
    api.patch(zone_id, existing["id"], ttl, ips)

# --------------------------------------------------------------------------- #
# Main Execution                                                              #
# --------------------------------------------------------------------------- #
def load_items(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Expected a root-level JSON array, but parsed a JSON object instead.")
    return data

def main() -> int:
    if len(sys.argv) < 2:
        log.error("Usage: dns-failover-manager-selectel.py <state.json>")
        return 2

    src = sys.argv[1]
    log.info("Reading active targets from %s", src)
    
    try:
        items = load_items(src)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        log.error("Failed to parse configuration file %s: %s", src, e)
        return 2

    cfg = Config.from_env()
    state_store = ConsulStateStore(cfg)

    previous_managed, last_updated_at = state_store.load_active_records()
    log.info("Loaded tracked domain manifest. Comparing to active configuration tracked at: '%s'", last_updated_at)
    
    previous_by_fqdn = {x["fqdn"]: x for x in previous_managed}

    # Extract target states
    current_managed_list: List[Dict[str, Any]] = []
    for it in items:
        if not it.get("sel_zone_id") or not it.get("zone"):
            continue
        fqdn = make_fqdn(it["record"], it["zone"]).lower()
        current_managed_list.append({
            "fqdn": fqdn,
            "zone": it["zone"],
            "sel_zone_id": it["sel_zone_id"],
            "service_name": it.get("service_name")
        })
    current_by_fqdn = {x["fqdn"]: x for x in current_managed_list}

    # Detect legacy orphaned records scheduled for Garbage Collection (GC)
    orphans_fqdns = set(previous_by_fqdn.keys()) - set(current_by_fqdn.keys())

    # Segment target records by DNS Zone ID
    by_zone: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for it in items:
        zid = it.get("sel_zone_id")
        if zid:
            by_zone[zid].append(it)

    # Inject legacy orphans into GC cycle
    for orphan_fqdn in orphans_fqdns:
        orphan = previous_by_fqdn[orphan_fqdn]
        zid = orphan["sel_zone_id"]
        by_zone[zid].append({
            "record": orphan_fqdn.replace("." + orphan["zone"].lower(), ""),
            "zone": orphan["zone"],
            "sel_zone_id": zid,
            "status": "all_critical",
            "on_all_fail": "remove",  # Enforce hard removal strategy for orphaned zones
            "service_name": f"orphaned-{orphan_fqdn}"
        })

    if not by_zone:
        log.info("Zero active records and no legacy orphans found to purge. No work to do.")
        state_store.save_active_records([])
        return 0

    api = SelectelDNS(cfg, get_iam_token(cfg))
    errors = 0

    # Execute reconciliation loop nested by DNS Zone ID
    for zone_id, zitems in by_zone.items():
        log.info("Zone %s: reconciling %d records (including active garbage collection)", zone_id, len(zitems))
        try:
            index = api.list_rrsets(zone_id)
        except Exception as e:
            log.error("Failed to read current record sets for zone %s: %s", zone_id, e)
            errors += len(zitems)
            continue
            
        for it in zitems:
            try:
                reconcile_one(api, it, index)
            except Exception as e:
                log.error("[%s] Failed to reconcile changes: %s", it.get("service_name"), e)
                errors += 1

    # Commit updated domain state only when there are zero failed transactions
    if errors == 0:
        prev_sorted = sorted(previous_managed, key=lambda x: x.get("fqdn", ""))
        curr_sorted = sorted(current_managed_list, key=lambda x: x.get("fqdn", ""))
        
        # Compare a domain list without taking timespamps into account
        if prev_sorted == curr_sorted:
            log.info("The list of managed domains hasn't changed. Skipping the registry update in Consul KV.")
        else:
            state_store.save_active_records(current_managed_list)
        return 0
    else:
        log.error("Reconciliation completed with %d error(s). Consul KV key registry update aborted.", errors)
        return 1
    
if __name__ == "__main__":
    sys.exit(main())

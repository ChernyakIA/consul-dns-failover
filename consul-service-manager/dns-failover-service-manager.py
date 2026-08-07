#!/usr/bin/env python3
"""
DNS-Failover daemon.

1. Reads the yaml-file `kv/dev-dns-failover/config` from Consul KV.
2. Filters records, related only to the current SITE (Instance name)
3. REgisters, updates and deletes health-checks in the local Consul Agent.

Variables:
  Required:
    SITE                    daemon name
    NODE_NAME               host name. In case of multiple daemons in HA
    SERVICE_NAME_PREFIX     service name prefix
    CONSUL_KV_PATH          path to the yaml config file in the Consul store
    MANAGED_TAG             tag for registered services

  Optional:
    CONSUL_ADDR             agent url (default: http://127.0.0.1:8500)
    CONSUL_HTTP_TOKEN       Consul ACL token (if ACLs are enabled)
    BLOCKING_WAIT           blocking query wait time (default 5m)
    HTTP_TIMEOUT_BLOCKING   HTTP timeout for blocking query (default: 330s)
    ALLOW_EMPTY_BOOTSTRAP   whether to allow automatic deregistration of managed services on cold start with an empty config (default: false)
    LOG_LEVEL               logging level (default INFO)

The Consul agent must be started with the `enable_local_script_checks = true` option, otherwise script checks will silently fail.
"""
from __future__ import annotations

import base64
import logging
import os
import signal
import sys
import time
import requests
import yaml
import hashlib
import json
import re

from dataclasses import dataclass, field
from types import FrameType
from typing import Any, Dict, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Logging Setup                                                               #
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("consul-service-manager")

# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #
# SlugHelper for zone_name
_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def _envbool(name: str, default: bool) -> bool:
    """Safely parse bool from environment variables."""
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


@dataclass(frozen=True)
class Config:
    site: str
    node_name: Optional[str]
    scope_tag: str
    service_name_prefix: str
    consul_addr: str
    consul_http_token: Optional[str]
    consul_kv_path: str
    blocking_wait: str
    managed_tag: str
    http_timeout_blocking: int
    http_timeout_short: int = 10
    allow_empty_bootstrap: bool = False
    backoff_base: float = 1.0
    backoff_cap: float = 60.0


    @staticmethod
    def from_env() -> Config:
        if "SITE" not in os.environ:
            raise KeyError("Environment variable 'SITE' must be set.")
        site = os.environ["SITE"]
        node_name = os.environ.get("NODE_NAME")
        
        scope_tag = f"daemon-site-{site}-node-{node_name}"
        consul_kv_path = os.environ.get("CONSUL_KV_PATH")
        if not consul_kv_path:
            raise KeyError("Environment variable 'CONSUL_KV_PATH' must be set.")
        
        return Config(
            site=site,
            node_name=node_name,
            scope_tag=scope_tag,
            service_name_prefix=os.environ.get("SERVICE_NAME_PREFIX", "dev-dns-failover"),
            consul_addr=os.environ.get("CONSUL_ADDR", "http://127.0.0.1:8500").rstrip("/"),
            consul_http_token=os.environ.get("CONSUL_HTTP_TOKEN") or None,
            consul_kv_path=consul_kv_path,
            blocking_wait=os.environ.get("BLOCKING_WAIT", "5m"),
            managed_tag=os.environ.get("MANAGED_TAG", "dev-dns-failover-managed"),
            http_timeout_blocking=int(os.environ.get("HTTP_TIMEOUT_BLOCKING", "330")),
            http_timeout_short=10,
            allow_empty_bootstrap=_envbool("ALLOW_EMPTY_BOOTSTRAP", False)
        )

# --------------------------------------------------------------------------- #
# Shutdown Management                                                         #
# --------------------------------------------------------------------------- #
class Shutdown:
    """Graceful shutdown flag, ensures transactions are not interrupted."""


    def __init__(self) -> None:
        self.stop: bool = False
        # Перехватываем сигналы
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)


    def _handle(self, signum: int, frame: Optional[FrameType]) -> None:
        log.info("Received signal %d, shutting down gracefully...", signum)
        self.stop = True


    def sleep(self, seconds: float) -> None:
        # Wait mode. Break out if a shutdown has been requested
        deadline = time.monotonic() + seconds
        while not self.stop:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.5, remaining))

# --------------------------------------------------------------------------- #
# Parse YAML file, build object and check rules                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DesiredService:
    """
    Service blueprint. Converts YAML to Consul format and generates a unique ID.
    """
    service_id: str
    name: str
    address: str
    tags: Tuple[str, ...]
    check: Dict[str, Any]
    check_proto: str
    meta: Dict[str, str] = field(default_factory=dict)


    def config_hash(self) -> str:
        """SHA256 from all fields determining the service/check behavior."""
        material = {
            "name":    self.name,
            "address": self.address,
            "tags":    sorted(self.tags),
            "check":   self.check,
            "meta":    {k: v for k, v in self.meta.items() if k != "config_hash"},
        }
        # sort_keys=True guarantees determinism
        blob = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


    @staticmethod
    def build(
        cfg: Config,
        zone_name: str,
        dns_provider: str,
        provider_meta: Dict[str, str],
        record_dict: Dict[str, Any],
        ep: Dict[str, Any],
        defaults: Optional[Dict[str, Any]] = None) -> DesiredService:
        """
        Transforms a YAML section into a DesiredService object.
        Priority: endpoints > records > defaults.
        """
        defaults = defaults or {}
        def_check = (defaults.get("check") or {})
        record   = record_dict["name"]
        ttl      = int(record_dict.get("ttl", defaults.get("ttl", 60)))
        on_fail  = record_dict.get("on_all_fail", "keep")
        fallback = record_dict.get("fallback_ip", "")

        if on_fail not in ("keep", "remove", "fallback"):
            raise ValueError(f"on_all_fail={on_fail!r} is invalid")
        if on_fail == "fallback" and not fallback:
            raise ValueError(f"on_all_fail=fallback requires fallback_ip")
        
        ip        = ep["ip"]
        uplink_provider = ep["uplink_provider"]
        chk       = ep["check"]
        target    = chk.get("target", ip)
        sites     = ep.get("sites") or []
        num_sites = len(sites)

        # Priority: endpoints (ep) > records (record_dict) > defaults
        raw_quorum = ep.get("quorum")
        if raw_quorum is None:
            raw_quorum = defaults.get("quorum")
        if raw_quorum is None:
            raise ValueError(f"A quorum value is not defined at any level for endpoint={ip}, record={record}")
        try:
            quorum = int(raw_quorum)
        except (ValueError, TypeError) as err:
            raise ValueError(f"Invalid quorum value format: {raw_quorum!r}. Expected int.") from err
        if quorum < 1:
            raise ValueError(f"The quorum value must be >= 1, but got {quorum}")
        if quorum > num_sites:
            raise ValueError(f"quorum={quorum} cannot be greater than the number of sites {num_sites} for endpoint {record} {ip}")

        interval = chk.get("interval", def_check.get("interval"))
        timeout  = chk.get("timeout", def_check.get("timeout"))
        if not interval:
            raise ValueError(f"check.interval/timeout not set for endpoint={ep!r}")
        dereg    = chk.get("deregister_critical_after", def_check.get("deregister_critical_after"))
        kind     = chk["kind"].lower()

        base_check = {"Interval": interval, "Timeout": timeout}
        
        sbp  = chk.get("success_before_passing", def_check.get("success_before_passing"))
        fbw  = chk.get("failures_before_warning", def_check.get("failures_before_warning"))
        fbc  = chk.get("failures_before_critical", def_check.get("failures_before_critical"))
        
        if sbp: base_check["SuccessBeforePassing"]  = int(sbp)
        fbw_val = int(fbw) if fbw else None
        fbc_val = int(fbc) if fbc else None

        if fbw_val is not None:
            base_check["FailuresBeforeWarning"] = fbw_val

        if fbc_val is not None:
            if fbw_val is not None:
                # fbc in the yaml config is the number of checks after warning
                # For Consul, we convert it using the formula int(warning) + int(critical)
                consul_absolute_fbc = fbw_val + fbc_val
                base_check["FailuresBeforeCritical"] = consul_absolute_fbc
                
                log.debug(
                    "For record %s, the config has checks before warning=%d, adding critical=%d and passing FailuresBeforeCritical=%d to Consul",
                    record, fbw_val, fbc_val, consul_absolute_fbc
                )
            else:
                # If warning is not set, then fbc_val is the number of failures directly until critical
                base_check["FailuresBeforeCritical"] = fbc_val

        # Consul treats "0s" and an empty string as "never deregister"
        if dereg and dereg != "0s":
            base_check["DeregisterCriticalServiceAfter"] = dereg
        
        # --------------------------------------------------------------------------- #
        # Checks                                                                      #
        # --------------------------------------------------------------------------- #
        if kind == "tcp":
            port = chk.get("port")
            check = {**base_check, "TCP": f"{target}:{port}"}

        # each response code except 0 will be 2
        elif kind == "icmp":
            check = {
                **base_check,
                "Args": [
                    "/bin/sh", "-c",
                    'ping -c 1 -W 1 "$1" || exit 2',
                    "--", target,
                ],
            }

        elif kind == "smtp":
            port = chk.get("port", 25)
            timeout_sec = 5  # таймаут в сек для netcat
            if timeout:
                match = re.match(r"(\d+)", str(timeout))
                if match:
                    timeout_sec = int(match.group(1))
            shell_cmd = (
                'out=$( (sleep 1; echo "QUIT") | nc -w "$1" "$2" "$3" 2>&1 ); '
                'echo "$out"; '
                'echo "$out" | grep -q "^220" || exit 2'
            )

            check = {
                **base_check,
                "Args": [
                    "/bin/sh", "-c", shell_cmd,
                    "--", str(timeout_sec), str(target), str(port),
                ],
            }

        elif kind == "http":
            if "url" in chk:
                url = chk["url"]
            else:
                scheme = chk.get("scheme", "http")
                port   = chk.get("port")
                path   = chk.get("path") or "/"
                if not path.startswith("/"):
                    path = "/" + path
                url = f"{scheme}://{target}:{port}{path}"
            check = {**base_check, "HTTP": url, "Method": chk.get("method", "GET"),}
            # опционально header, tls_skip_verify
            if "header" in chk:
                check["Header"] = chk["header"]
            if chk.get("tls_skip_verify"):
                check["TLSSkipVerify"] = True
        else:
            raise ValueError(f"Неизвестное значение check.kind={kind!r}")
        
        # Dots break dns names in Consul
        zone_slug = _slug(zone_name)
        record_slug = _slug(record)
        dns_prov_slug = _slug(dns_provider)

        sid  = f"failover-{cfg.site}-{dns_prov_slug}-{record_slug}-{zone_slug}-{uplink_provider}-{ip}"
        name = f"{cfg.service_name_prefix}-{dns_prov_slug}-{record_slug}-{zone_slug}"
        tags = [
            cfg.site,
            cfg.managed_tag,
            cfg.scope_tag,
            f"record-{record_slug}",
            f"zone-{zone_slug}",
            f"dns-provider-{dns_prov_slug}",
            f"uplink_provider-{uplink_provider}",
        ]
        meta = {
            "ttl": str(ttl),
            "site": cfg.site,
            "uplink_provider": uplink_provider,
            "zone": zone_name,
            "dns_provider": dns_provider,
            "record": record,
            "check_target": target,
            "on_all_fail": on_fail,
            "fallback_ip": fallback,
            "quorum": str(quorum),
            **provider_meta  # Dynamic provider fields == new fields go here
        }
        return DesiredService(sid, name, ip, tuple(tags), check, kind, meta)


    def to_payload(self) -> Dict[str, Any]:
        meta_with_hash = {**self.meta, "config_hash": self.config_hash()}
        return {
            "ID":      self.service_id,
            "Name":    self.name,
            "Address": self.address,
            "Tags":    list(self.tags),
            "Meta":    meta_with_hash,
            "Check":   self.check,
        }


def _has_drift(current: Dict[str, Any], desired: DesiredService) -> bool:
    """
    True -> re-register.

    Comparing the config_hash from Meta. If there is no hash (an old service,
    pre-upgrade daemon), consider it a drift and re-register to add the hash.
    """
    current_hash = (current.get("Meta") or {}).get("config_hash")
    if not current_hash:
        log.info("Service id=%s has no config_hash — migrating, re-registering",
                 current.get("ID"))
        return True
    return current_hash != desired.config_hash()


def _slug(value: str) -> str:
    """
    Sanitizes strings making them safe for Consul: keeps [A-Za-z0-9_-],
    everything else is replaced with '-'.
    Example: 'dev-rezonit.ru' -> 'dev-rezonit-ru'.
    """
    return _SLUG_RE.sub("-", value).strip("-")

# --------------------------------------------------------------------------- #
# Consul HTTP Client                                                          #
# --------------------------------------------------------------------------- #
class KVUnavailable(Exception):
    """Consul KV is temporarily unavailable (network/5xx). Do not perform reconcile."""


def _raise_with_body(r: requests.Response, what: str) -> None:
    if r.status_code >= 400:
        body = (r.text or "").strip().replace("\n", " ")[:500]
        raise requests.HTTPError(
            f"{what}: HTTP {r.status_code} {r.reason} — {body}",
            response=r,
        )


class ConsulClient:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.base_url = cfg.consul_addr.rstrip("/")
        # Sessions reuse underlying tcp connections
        self.session = requests.Session()
        # Standard Consul ACL token header
        # If ACL is disabled, the agent simply ignores the header
        if cfg.consul_http_token:
            self.session.headers["X-Consul-Token"] = cfg.consul_http_token
            log.info("Using ACL token from CONSUL_HTTP_TOKEN (len=%d)", len(cfg.consul_http_token))
        else:
            log.debug("CONSUL_HTTP_TOKEN is not set -- working without an ACL token")


    def deregister(self, service_id: str) -> None:
        r = self.session.put(f"{self.base_url}/v1/agent/service/deregister/{service_id}",
                             timeout=self.cfg.http_timeout_short)
        _raise_with_body(r, f"Deregistering id={service_id}")


    def agent_self(self) -> Dict[str, Any]:
        r = self.session.get(f"{self.base_url}/v1/agent/self", timeout=self.cfg.http_timeout_short)
        r.raise_for_status()
        return r.json()


    # Read KV
    def kv_read(self, key: str, index: Optional[int], wait: Optional[str]) -> Tuple[Optional[str], int]:
        """
        Returns (value, new_index)
        value = None -- http 404 (file not found), effectively "config deleted"
        value = "" -- file is empty
        value = "..." -- ok

        Raises:
        requests.exceptions.ReadTimeout -- blocking query timed out -- ok
        KVUnavailable -- on any other error
        """
        params: Dict[str, str] = {}
        if wait:
            params["wait"] = wait
        if index is not None and index > 0:
            params["index"] = str(index)
        
        timeout = self.cfg.http_timeout_blocking if wait and index else self.cfg.http_timeout_short
        url = f"{self.base_url}/v1/kv/{key}"

        try:
            r = self.session.get(url, params=params, timeout=timeout)
        except requests.exceptions.ReadTimeout:
            raise
        except requests.exceptions.RequestException as e:
            # ConnectionError, DNS, other
            raise KVUnavailable(f"Network error reaching Consul KV: {e}") from e
        
        new_index = int(r.headers.get("X-Consul-Index", "0"))

        if r.status_code == 404:
            return None, new_index

        if r.status_code >= 500:
            raise KVUnavailable(f"Consul returned {r.status_code}: {r.text[:200]}")

        try:
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise KVUnavailable(f"HTTP error: {e}") from e

        body = r.json()
        if not body:
            return None, new_index
        raw = body[0].get("Value")
        if raw is None:
            return "", new_index
        return base64.b64decode(raw).decode("utf-8"), new_index


    # List of services
    def list_managed_services(self) -> Dict[str, Dict[str, Any]]:
        # Fetch services through the agent. API differs from querying the server
        url = f"{self.base_url}/v1/agent/services"
        # Consul applies filtering on the server side
        params = {"filter": f'"{self.cfg.managed_tag}" in Tags and "{self.cfg.scope_tag}" in Tags'}
        r = self.session.get(url, params=params, timeout=self.cfg.http_timeout_short)
        r.raise_for_status()
        services: Dict[str, Dict[str, Any]] = r.json() or {}
        
        # Tag check fallback in case server-side filtering didn't trigger
        return {
            sid: svc
            for sid, svc in services.items()
            if self.cfg.managed_tag in (svc.get("Tags") or [])
        }


    def register(self, payload: Dict[str, Any]) -> None:
        """Registering the service via agent"""
        # Registration through the agent is different from direct server registration
        url = f"{self.base_url}/v1/agent/service/register"
        r = self.session.put(url, json=payload, params={"replace-existing-checks": "true"},
                             timeout=self.cfg.http_timeout_short)
        _raise_with_body(r, f"register id={payload.get('ID')}")

# --------------------------------------------------------------------------- #
# Parse Config. Validation Checks                                             #
# --------------------------------------------------------------------------- #
def parse_desired_state(yaml_text: str, cfg: Config) -> Dict[str, DesiredService]:
    """Parse yaml string into {service_id: DesiredService} with error checking."""
    if not yaml_text or not yaml_text.strip():
        return {}
    try:
        doc = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as e:
        log.error("YAML error: %s. Previous state remains untouched.", e)
        return {}

    defaults = doc.get("defaults") or {}
    # Define key constant schema fields to separate them from provider metadata
    KNOWN_ZONE_KEYS = {"zone_name", "dns_provider", "records"}

    desired: Dict[str, DesiredService] = {}
    # Iterate through all zones in config
    for i, zone in enumerate(doc.get("zones", []) or []):
        zone_name = zone.get("zone_name")
        dns_provider = zone.get("dns_provider")

        if not zone_name or not dns_provider:
            log.error("Block #%d in the configuration file is missing zone_name or dns_provider. Skipping the entire zone", i)
            continue

        # Everything not in KNOWN_ZONE_KEYS is considered a provider parameter -- pushed to meta
        provider_meta: Dict[str, str] = {
            k: str(v)
            for k, v in zone.items()
            if k not in KNOWN_ZONE_KEYS and v is not None
        }

        for record in zone.get("records", []) or []:
            rec_name = record.get("name")
            if not rec_name:
                log.warning("zone=%s: record without a name value. Skipping", zone_name)
                continue
            for ep in record.get("endpoints", []) or []:
                sites = ep.get("sites")
                # If site in the yaml config is not for this daemon, skip it
                if not sites or cfg.site not in sites:
                    continue
                ip = ep.get("ip")
                check_proto = ep.get("check")
                if not ip or not check_proto:
                    log.warning("zone=%s record=%s: missing ip / check. Skipping %r",
                                zone_name, rec_name, ep)
                    continue
                try:
                    ds = DesiredService.build(
                        cfg,
                        zone_name=zone_name,
                        dns_provider=dns_provider,
                        provider_meta=provider_meta,
                        record_dict=record,
                        ep=ep,
                        defaults=defaults
                    )
                except (ValueError, KeyError, TypeError) as e:
                    log.error("zone=%s record=%s endpoint=%r: parsing error (%s: %s) -- skipping",
                              zone_name, rec_name, ep, type(e).__name__, e)
                    continue
                if ds.service_id in desired:
                    log.warning("Duplicate service_id=%s, overwriting", ds.service_id)
                desired[ds.service_id] = ds
    return desired

# --------------------------------------------------------------------------- #
# Service Reconciliation                                                      #
# --------------------------------------------------------------------------- #
def reconcile(consul: ConsulClient, desired: Dict[str, DesiredService]) -> bool:
    """
    Reconcile differences. Does not raise exceptions -- logs them and continues
    Returns:
    - True, if all operations completed successfully
    - False, if at least one [de]register failed
    The main loop relies on this flag to determine whether to advance last_index
    """
    try:
        current = consul.list_managed_services()
    except requests.RequestException as e:
        log.error("Error fetching current services from agent: %s", e)
        return False
    
    current_ids: Set[str] = set(current.keys())
    desired_ids: Set[str] = set(desired.keys())

    to_add      = desired_ids - current_ids
    to_remove   = current_ids - desired_ids
    to_keep     = desired_ids & current_ids

    log.info("Reconciliation. Desired=%d, Current in Agent=%d, Adding=%d, Removing=%d, Keeping=%d",
             len(desired_ids), len(current_ids), len(to_add), len(to_remove), len(to_keep))

    all_ok = True

    # Registering new
    for sid in sorted(to_add):
        ds = desired[sid]
        try:
            consul.register(ds.to_payload())
            log.warning("Registered service id=%s name=%s address=%s check=%s",
                     ds.service_id, ds.name, ds.address, ds.check_proto)
        except requests.RequestException as e:
            log.error("Registration of id=%s failed: %s", sid, e)
            all_ok = False

    # Drift Handling
    # Re-register current services if config_hash changed.
    # The Service ID remains the same
    for sid in sorted(to_keep):
        ds = desired[sid]
        if _has_drift(current[sid], ds):
            try:
                consul.register(ds.to_payload())
                log.info("Re-registered drifted service id=%s", sid)
            except requests.RequestException as e:
                log.error("Re-registration of id=%s failed: %s", sid, e)
                all_ok = False

    # Remove obsolete IDs
    for sid in sorted(to_remove):
        try:
            consul.deregister(sid)
            log.warning("Deregistered obsolete service id=%s", sid)
        except requests.RequestException as e:
            log.error("Deregistration of id=%s failed: %s", sid, e)
            all_ok = False
    
    return all_ok

# --------------------------------------------------------------------------- #
# Checking Connection to Consul                                               #
# Docker compose may start the daemon faster than the agent exposes port 8500 #
# --------------------------------------------------------------------------- #
def wait_for_consul(consul: ConsulClient, shutdown: Shutdown) -> None:
    backoff = consul.cfg.backoff_base
    while not shutdown.stop:
        try:
            info = consul.agent_self()
            agent_cfg = info.get("Config", {})
            log.info("Local Consul agent is available (node=%s dc=%s version=%s)",
                     agent_cfg.get("NodeName", "?"), agent_cfg.get("Datacenter", "?"), agent_cfg.get("Version", "?"),)
            return
        except requests.RequestException as e:
            log.warning("Consul agent not yet available: %s (retrying in %.1fs)",
                        e, backoff)
        shutdown.sleep(backoff)
        backoff = min(backoff * 2, consul.cfg.backoff_cap)

# --------------------------------------------------------------------------- #
# Main Loop                                                                   #
# --------------------------------------------------------------------------- #
def main() -> int:
    try:
        cfg = Config.from_env()
    except Exception as e:
        log.error("Environment configuration initialization error: %s", e)
        return 1
    
    log.info("Starting DNS-Failover Control Plane (consul=%s, kv=%s, wait=%s, allow_empty_bootstrap=%s)",
             cfg.consul_addr, cfg.consul_kv_path, cfg.blocking_wait, cfg.allow_empty_bootstrap)
    shutdown = Shutdown()
    consul = ConsulClient(cfg)

    wait_for_consul(consul, shutdown)
    if shutdown.stop:
        return 0
    
    # 1. Syncing state. Reading without blocks initially
    log.info("Step 1. Initial state synchronization")
    last_index: int = 0
    backoff = cfg.backoff_base
    
    while not shutdown.stop:
        try:
            value, new_index = consul.kv_read(cfg.consul_kv_path, index=last_index, wait=cfg.blocking_wait)
        
        # Exception order matters!
        # ReadTimeout is a subclass of RequestException, which is a subclass of ConnectionError.
        # If swapped, blocking query timeouts would erroneously trigger backoff handling.
        # Consul holds the blocking-query for (wait + wait/16)sec = 5min + 18.75sec
        # HTTP_TIMEOUT_BLOCKING=330s must be strictly larger than that!
        # https://developer.hashicorp.com/consul/api-docs/features/blocking

        except requests.exceptions.ReadTimeout:
            log.debug("Blocking query timed out (normal), reconnecting")
            continue

        except KVUnavailable as e:
            # Consul KV inaccessible -> do not deregister anything, preserve last_index
            log.error("KV unavailable: %s (retrying in %.1fs)", e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
            continue

        except Exception as e:
            log.exception("Unexpected error: %s", e)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
            continue

        # Processing successful read result
        config_missing = value is None
        desired = ({} if config_missing else parse_desired_state(value, cfg))

        if config_missing:
            log.warning("KV file %s is missing (HTTP 404).", cfg.consul_kv_path)
        elif not desired:
            log.warning("KV file %s loaded, but desired services for site=%s = 0.",
                        cfg.consul_kv_path, cfg.site)
        else:
            log.info("Config loaded (index=%d), desired services for site=%s: %d",
                     new_index, cfg.site, len(desired))
            
        # Cold start protection:
        # Avoid deregistering existing managed services when an empty/deleted config is detected.
        # Can be bypassed via ALLOW_EMPTY_BOOTSTRAP=true flag.
        if not desired and not cfg.allow_empty_bootstrap:
            log.warning(
                "Bootstrap: desired state is empty, ALLOW_EMPTY_BOOTSTRAP=false -- "
                "skipping reconcile to prevent purging managed services. "
                "Waiting for a valid config in KV (index=%d) ...",
                new_index,
            )
            # Advance the index, preventing instant loops on the next iteration
            last_index = new_index
            backoff = cfg.backoff_base
            shutdown.sleep(2.0)
            continue

        if reconcile(consul, desired):
            last_index = new_index
            backoff = cfg.backoff_base
            break
        else:
            # Reconcile partially failed -- leaving index unshifted, retry bootstrap over backoff.
            log.warning("Initial synchronization had errors, retrying in %.1fs",
                        backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
            continue

    if shutdown.stop:
        log.info("Shutdown during bootstrap")
        return 0
    
    # Context: last_index equals X-Consul-Index of the key at the time of bootstrap.
    # Step 2 utilizes it as a jump-off point for blocking queries.
    log.info("Step 2. Watching KV (starting index=%d)", last_index)
    backoff = cfg.backoff_base

    while not shutdown.stop:
        try:
            value, new_index = consul.kv_read(cfg.consul_kv_path, index=last_index, wait=cfg.blocking_wait)
            if new_index < 1:
                new_index = 1
            if new_index < last_index:
                log.warning("X-Consul-Index rolled back (%d -> %d), resetting timer",
                            last_index, new_index)
                last_index = 0
                continue
            if new_index == last_index:
                # The blocked query returned entirely unchanged via timeout expiration
                log.debug("No changes in KV for index=%d", new_index)
                backoff = cfg.backoff_base
                continue

            log.info("Change detected in KV: index %d -> %d, reconciling services ...",
                     last_index, new_index)
            desired = parse_desired_state(value, cfg) if value is not None else {}
            if value is None:
                log.warning("Configuration file %s was deleted. Deregistering all associated services", cfg.consul_kv_path)
            if reconcile(consul, desired):
                last_index = new_index
                backoff = cfg.backoff_base
            else:
                # Without shifting last_index here, the next loop initiates reconciliation again.
                # Consul replies instantly (non-blocking) when index < real_index.
                # shutdown.sleep(backoff) prevents overwhelming the agent locally.
                log.warning("Reconcile finished with errors, not shifting index (retrying in %.1fs)",
                            backoff)
                shutdown.sleep(backoff)
                backoff = min(backoff * 2, cfg.backoff_cap)

        except requests.exceptions.ReadTimeout:
            # Client-side timeout triggers while Server keeps holding response query.
            # Safe to silently restart block. Do not alter last_index limits!
            log.debug("Blocking query timed out. Reconnecting")
            backoff = cfg.backoff_base
        except requests.RequestException as e:
            log.error("Consul API error: %s (retrying in %.1fs)", e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
        except Exception as e:  # noqa: BLE001 -- main loop must flow
            log.exception("Unexpected error in watch loop: %s (retrying in %.1fs)",
                          e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)

    log.info("Shutdown complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())

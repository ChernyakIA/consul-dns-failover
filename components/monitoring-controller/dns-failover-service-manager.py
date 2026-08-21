#!/usr/bin/env python3
"""
DNS-Failover daemon.

1. Reads the YAML configuration from Consul KV.
2. Filters endpoints assigned to the current SITE.
3. Runs checks in Python and updates TTL checks on the local Consul agent.

Variables:
    SITE                    daemon site name (required)
    NODE_NAME               host name, used when multiple daemons run in HA
    SERVICE_NAME_PREFIX     service name prefix
    CONSUL_ADDR             local agent URL (in Kubernetes: https://POD_IP:8501)
    CONSUL_HTTP_TOKEN       Consul ACL token (if ACLs are enabled)
    CONSUL_CACERT           CA used to verify Consul servers
    CONSUL_AUTO_ENCRYPT_CA_ADDR  HTTPS server API URL from which to obtain the Auto Encrypt CA
    CONSUL_KV_PATH          path to the YAML configuration file in Consul KV
    BLOCKING_WAIT           blocking-query wait duration (default: 5m)
    HTTP_TIMEOUT_BLOCKING   HTTP timeout for blocking queries (default: 330s)
    HEARTBEAT_INTERVAL      interval between INFO messages for the active KV watch (default: 3600s)
    ALLOW_EMPTY_BOOTSTRAP   whether managed services may be removed by an empty config on cold start (default: false)
    LOG_LEVEL               logging level (default: INFO)
    MANAGED_TAG             tag applied to registered services

Script checks are not used by the Consul agent and must remain disabled.
"""
from __future__ import annotations

import base64
import logging
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import requests
import yaml
import hashlib
import json
import re

from dataclasses import dataclass, field, replace
from enum import Enum
from requests.adapters import HTTPAdapter
from types import FrameType
from typing import Any, Dict, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Configuration                                                                #
# --------------------------------------------------------------------------- #
# Slug helper for zone_name
_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")


class CheckResult(Enum):
    """Active-check result before conversion to a Consul TTL status."""

    PASS = "PASS"      # The target confirmed availability.
    FAIL = "FAIL"      # The check ran, but the target is unavailable.
    ERROR = "ERROR"    # The check itself could not be executed correctly.


def _envbool(name: str, default: bool) -> bool:
    """Safely parse a boolean from an environment variable."""
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
    consul_cacert: Optional[str]
    consul_auto_encrypt_ca_addr: Optional[str]
    consul_ca_bundle_pem: Optional[str]
    consul_kv_path: str
    blocking_wait: str
    managed_tag: str
    http_timeout_blocking: int
    heartbeat_interval: int
    http_timeout_short: int = 10
    allow_empty_bootstrap: bool = False
    backoff_base: float = 1.0
    backoff_cap: float = 60.0


    @staticmethod
    def from_env() -> Config:
        if "SITE" not in os.environ:
            raise KeyError("Set the 'SITE' environment variable.")
        site = os.environ["SITE"]
        node_name = os.environ.get("NODE_NAME")
        if not node_name:
            raise KeyError("Set a unique 'NODE_NAME' environment variable.")

        scope_tag = f"daemon-site-{site}-node-{node_name}"
        consul_kv_path = os.environ.get("CONSUL_KV_PATH")
        if not consul_kv_path:
            raise KeyError("Set the 'CONSUL_KV_PATH' environment variable.")

        return Config(
            site=site,
            node_name=node_name,
            scope_tag=scope_tag,
            service_name_prefix=os.environ.get("SERVICE_NAME_PREFIX", "dns-failover"),
            consul_addr=os.environ.get("CONSUL_ADDR", "http://127.0.0.1:8500").rstrip("/"),
            consul_http_token=os.environ.get("CONSUL_HTTP_TOKEN") or None,
            consul_cacert=os.environ.get("CONSUL_CACERT") or None,
            consul_auto_encrypt_ca_addr=(
                os.environ.get("CONSUL_AUTO_ENCRYPT_CA_ADDR", "").rstrip("/") or None
            ),
            consul_ca_bundle_pem=None,
            consul_kv_path=consul_kv_path,
            blocking_wait=os.environ.get("BLOCKING_WAIT", "5m"),
            managed_tag=os.environ.get("MANAGED_TAG", "dns-failover-managed"),
            http_timeout_blocking=int(os.environ.get("HTTP_TIMEOUT_BLOCKING", "330")),
            heartbeat_interval=int(os.environ.get("HEARTBEAT_INTERVAL", "3600")),
            http_timeout_short=10,
            allow_empty_bootstrap=_envbool("ALLOW_EMPTY_BOOTSTRAP", False)
        )

# --------------------------------------------------------------------------- #
# Logging                                                                 #
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("consul-service-manager")

# --------------------------------------------------------------------------- #
# Shutdown handling                                               #
# --------------------------------------------------------------------------- #
class Shutdown:
    """Graceful-shutdown flag that allows in-flight transactions to finish."""


    def __init__(self) -> None:
        self.stop: bool = False
        # Intercept termination signals.
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)


    def _handle(self, signum: int, frame: Optional[FrameType]) -> None:
        log.info("Received signal %d; shutting down", signum)
        self.stop = True
        raise SystemExit(0)


    def sleep(self, seconds: float) -> None:
        # Interruptible wait: exit early when shutdown is requested.
        deadline = time.monotonic() + seconds
        while not self.stop:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.5, remaining))

# --------------------------------------------------------------------------- #
# Read the YAML file and build the object and check rules                       #
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
    interval_seconds: float
    timeout_seconds: float
    success_before_passing: int
    failures_before_warning: int
    failures_before_critical: int
    meta: Dict[str, str] = field(default_factory=dict)


    def config_hash(self) -> str:
        """SHA256 of all fields that affect service or check behavior."""
        material = {
            "name":    self.name,
            "address": self.address,
            "tags":    sorted(self.tags),
            "check":   self.check,
            "interval_seconds": self.interval_seconds,
            "timeout_seconds": self.timeout_seconds,
            "success_before_passing": self.success_before_passing,
            "failures_before_warning": self.failures_before_warning,
            "failures_before_critical": self.failures_before_critical,
            "meta":    {k: v for k, v in self.meta.items() if k != "config_hash"},
        }
        # sort_keys=True guarantees deterministic output.
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
        Transform a YAML section into a DesiredService object.
        Precedence: endpoints > records > defaults.
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
        owner_site = ep.get("owner_site") or record_dict.get("owner_site")
        if not owner_site:
            raise ValueError(f"owner_site is not set for endpoint={ip}, record={record}")

        # Precedence: endpoints (ep) > records (record_dict) > defaults
        raw_quorum = ep.get("quorum")
        if raw_quorum is None:
            raw_quorum = defaults.get("quorum")
        if raw_quorum is None:
            raise ValueError(f"No quorum value is set at any level for endpoint={ip}, record={record}")
        try:
            quorum = int(raw_quorum)
        except (ValueError, TypeError) as err:
            raise ValueError(f"Invalid quorum value format: {raw_quorum!r}. An int is required.") from err
        if quorum < 1:
            raise ValueError(f"quorum must be >= 1; received {quorum}")
        if quorum > num_sites:
            raise ValueError(f"quorum={quorum} cannot exceed the number of sites ({num_sites}) for endpoint {record} {ip}")

        raw_minimum_observers = ep.get("minimum_observers")
        if raw_minimum_observers is None:
            raw_minimum_observers = record_dict.get("minimum_observers", defaults.get("minimum_observers", quorum))
        minimum_observers = int(raw_minimum_observers)
        if minimum_observers < 1 or minimum_observers > num_sites:
            raise ValueError(
                f"minimum_observers={minimum_observers} must be between 1 and the number of sites ({num_sites}) "
                f"for endpoint={ip}, record={record}"
            )

        interval = chk.get("interval", def_check.get("interval"))
        timeout  = chk.get("timeout", def_check.get("timeout"))
        if not interval or not timeout:
            raise ValueError(f"check.interval/timeout are not set for endpoint={ep!r}")
        kind     = chk["kind"].lower()

        sbp  = chk.get("success_before_passing", def_check.get("success_before_passing"))
        fbw  = chk.get("failures_before_warning", def_check.get("failures_before_warning"))
        fbc  = chk.get("failures_before_critical", def_check.get("failures_before_critical"))
        sbp_val = max(1, int(sbp or 1))
        fbw_val = max(1, int(fbw or 1))
        fbc_val = max(1, int(fbc or 1))
        interval_seconds = _parse_duration(interval)
        timeout_seconds = _parse_duration(timeout)

        # --------------------------------------------------------------------------- #
        # Checks                                                                    #
        # --------------------------------------------------------------------------- #
        if kind == "tcp":
            port = chk.get("port")
            if not port:
                raise ValueError(f"check.port is required for TCP endpoint={ip}")

        elif kind == "icmp":
            pass

        elif kind == "smtp":
            port = chk.get("port", 25)

        elif kind == "http":
            if "url" in chk:
                url = chk["url"]
            else:
                scheme = chk.get("scheme", "http")
                port   = chk.get("port")
                if not port:
                    raise ValueError(f"check.port is required for HTTP endpoint={ip} when check.url is not set")
                path   = chk.get("path") or "/"
                if not path.startswith("/"):
                    path = "/" + path
                url = f"{scheme}://{target}:{port}{path}"
            chk = {**chk, "url": url}
        else:
            raise ValueError(f"Unknown check.kind value: {kind!r}")

        # Dots make Consul DNS names invalid.
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
            "owner_site": str(owner_site),
            "on_all_fail": on_fail,
            "fallback_ip": fallback,
            "quorum": str(quorum),
            "minimum_observers": str(minimum_observers),
            **provider_meta  # Dynamic provider fields: new fields are stored here.
        }
        return DesiredService(
            sid, name, ip, tuple(tags), dict(chk), kind,
            interval_seconds, timeout_seconds, sbp_val, fbw_val, fbc_val, meta,
        )


    def to_payload(self) -> Dict[str, Any]:
        meta_with_hash = {**self.meta, "config_hash": self.config_hash()}
        return {
            "ID":      self.service_id,
            "Name":    self.name,
            "Address": self.address,
            "Tags":    list(self.tags),
            "Meta":    meta_with_hash,
            "Check": {
                "CheckID": self.check_id,
                "Name": f"{self.check_proto} check from {self.meta['site']}",
                "TTL": f"{max(30, int(self.interval_seconds * 3 + self.timeout_seconds))}s",
                # The state is unknown until the first check completes.
                "Status": "warning",
                "DeregisterCriticalServiceAfter": "0s",
            },
        }

    @property
    def check_id(self) -> str:
        return f"dns-failover:{self.service_id}"


def _has_drift(current: Dict[str, Any], desired: DesiredService) -> bool:
    """
    True means the service must be re-registered.

    Compare config_hash from Meta. If the hash is absent (an old service created before
    the daemon upgrade), treat it as drift and re-register it to store the hash.
    """
    current_hash = (current.get("Meta") or {}).get("config_hash")
    if not current_hash:
        log.info("Service id=%s has no config_hash; migrating by re-registering it",
                 current.get("ID"))
        return True
    return current_hash != desired.config_hash()


def _slug(value: str) -> str:
    """
    Convert a string to a Consul-safe form: retain [A-Za-z0-9_-] and
    replace every other character with '-'.
    Example: 'app.example.com' -> 'app-example-com'.
    """
    return _SLUG_RE.sub("-", value).strip("-")


def _parse_duration(value: Any) -> float:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)\s*", str(value))
    if not match:
        raise ValueError(f"Invalid duration {value!r}; expected a value such as 500ms, 15s, or 2m")
    number = float(match.group(1))
    return number * {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}[match.group(2)]

# --------------------------------------------------------------------------- #
# Consul HTTP client                                                          #
# --------------------------------------------------------------------------- #
class KVUnavailable(Exception):
    """Consul KV is temporarily unavailable (network/5xx). Do not reconcile."""


class InvalidDesiredState(Exception):
    """The configuration is invalid. The current state must not be partially removed."""


def _raise_with_body(r: requests.Response, what: str) -> None:
    if r.status_code >= 400:
        body = (r.text or "").strip().replace("\n", " ")[:500]
        raise requests.HTTPError(
            f"{what}: HTTP {r.status_code} {r.reason} -- {body}",
            response=r,
        )


def with_auto_encrypt_ca_bundle(cfg: Config) -> Config:
    """Retrieve the service-mesh CA through the server API and return the config with a CA bundle.

    The server API is verified with the static Consul Agent CA. The retrieved roots are used
    to verify the local client agent HTTPS certificate issued through
    Auto Encrypt. The bundle is kept in process memory.
    """
    if not cfg.consul_auto_encrypt_ca_addr:
        return cfg
    if not cfg.consul_cacert:
        raise ValueError(
            "CONSUL_CACERT is required when CONSUL_AUTO_ENCRYPT_CA_ADDR is used"
        )

    headers = {}
    if cfg.consul_http_token:
        headers["X-Consul-Token"] = cfg.consul_http_token
    url = f"{cfg.consul_auto_encrypt_ca_addr}/v1/connect/ca/roots"
    response = requests.get(
        url,
        headers=headers,
        timeout=cfg.http_timeout_short,
        verify=cfg.consul_cacert,
    )
    _raise_with_body(response, "Retrieving Consul Auto Encrypt CA")
    payload = response.json()

    certificates = []
    for root in payload.get("Roots") or []:
        root_cert = root.get("RootCert")
        if root_cert:
            certificates.append(root_cert.strip())
        certificates.extend(
            cert.strip()
            for cert in (root.get("IntermediateCerts") or [])
            if cert and cert.strip()
        )
    if not certificates:
        raise ValueError(f"Consul returned no CA certificates from {url}")

    # Include both trust anchors: the Agent CA and the Auto Encrypt/service-mesh CA.
    with open(cfg.consul_cacert, "r", encoding="utf-8") as source:
        certificates.insert(0, source.read().strip())
    unique_certificates = list(dict.fromkeys(certificates))

    bundle_pem = "\n".join(unique_certificates) + "\n"
    log.info("Retrieved Auto Encrypt CA; prepared the TLS bundle in memory")
    return replace(cfg, consul_ca_bundle_pem=bundle_pem)


class SSLContextAdapter(HTTPAdapter):
    """
    Requests adapter that uses in-memory CA certificates without a temporary file.
    The pod runs with readOnlyRootFilesystem: true, so no temporary file is created in /tmp.
    """

    def __init__(self, context: ssl.SSLContext) -> None:
        self.context = context
        super().__init__()

    def init_poolmanager(self, connections: int, maxsize: int,
                         block: bool = False, **pool_kwargs: Any) -> None:
        pool_kwargs["ssl_context"] = self.context
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        proxy_kwargs["ssl_context"] = self.context
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class ConsulClient:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.base_url = cfg.consul_addr.rstrip("/")
        # The session reuses TCP connections.
        self.session = requests.Session()
        if cfg.consul_ca_bundle_pem:
            context = ssl.create_default_context()
            context.load_verify_locations(cadata=cfg.consul_ca_bundle_pem)
            self.session.mount("https://", SSLContextAdapter(context))
        elif cfg.consul_cacert:
            self.session.verify = cfg.consul_cacert
        # Consul ACL token header; the agent ignores it when ACLs are disabled.
        if cfg.consul_http_token:
            self.session.headers["X-Consul-Token"] = cfg.consul_http_token
            log.debug("Using the ACL token from CONSUL_HTTP_TOKEN")
        else:
            log.debug("CONSUL_HTTP_TOKEN is not set; operating without an ACL token")


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
        Return (value, new_index).
        value = None -- http 404 (no file exists at the path), the state is "config deleted"
        value = "" -- the file is empty
        value = "..." -- valid content

        Raises:
        requests.exceptions.ReadTimeout -- the blocking query timed out -- expected behavior
        KVUnvailable -- for any other error
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
            # ConnectionError, DNS, other errors
            raise KVUnavailable(f"Network error while accessing Consul KV: {e}") from e

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


    # List services
    def list_managed_services(self) -> Dict[str, Dict[str, Any]]:
        # List services through the agent. This API differs from direct server access.
        url = f"{self.base_url}/v1/agent/services"
        # Consul applies the filter server-side.
        params = {"filter": f'"{self.cfg.managed_tag}" in Tags and "{self.cfg.scope_tag}" in Tags'}
        r = self.session.get(url, params=params, timeout=self.cfg.http_timeout_short)
        r.raise_for_status()
        services: Dict[str, Dict[str, Any]] = r.json() or {}

        # Verify tags in case the server-side filter was not applied.
        return {
            sid: svc
            for sid, svc in services.items()
            if self.cfg.managed_tag in (svc.get("Tags") or [])
            and self.cfg.scope_tag in (svc.get("Tags") or [])
        }


    def register(self, payload: Dict[str, Any]) -> None:
        """Register a service through the agent."""
        # Registration through the agent differs from registration directly on the server.
        url = f"{self.base_url}/v1/agent/service/register"
        r = self.session.put(url, json=payload, params={"replace-existing-checks": "true"},
                             timeout=self.cfg.http_timeout_short)
        _raise_with_body(r, f"register id={payload.get('ID')}")

    def update_ttl(self, check_id: str, status: str, output: str) -> None:
        endpoint = {"passing": "pass", "warning": "warn", "critical": "fail"}[status]
        r = self.session.put(
            f"{self.base_url}/v1/agent/check/{endpoint}/{check_id}",
            params={"note": output[:512]},
            timeout=self.cfg.http_timeout_short,
        )
        _raise_with_body(r, f"TTL check {check_id} -> {status}")


def _execute_check(desired: DesiredService) -> Tuple[CheckResult, str]:
    check = desired.check
    target = str(check.get("target", desired.address))
    timeout = desired.timeout_seconds

    try:
        if desired.check_proto == "icmp":
            timeout_arg = max(1, int(timeout))
            completed = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout_arg), target],
                capture_output=True,
                text=True,
                timeout=timeout + 1,
                check=False,
            )
            output = (completed.stdout or completed.stderr or "ping failed").strip().splitlines()[-1]
            if completed.returncode == 0:
                return CheckResult.PASS, output
            if completed.returncode == 1:
                return CheckResult.FAIL, output
            return CheckResult.ERROR, (
                f"ICMP check execution error (ping rc={completed.returncode}): {output}"
            )

        if desired.check_proto == "tcp":
            port = int(check["port"])
            with socket.create_connection((target, port), timeout=timeout):
                return CheckResult.PASS, f"TCP {target}:{port} connected"

        if desired.check_proto == "smtp":
            port = int(check.get("port", 25))
            with socket.create_connection((target, port), timeout=timeout) as connection:
                connection.settimeout(timeout)
                banner = connection.recv(1024).decode("utf-8", errors="replace").strip()
                if banner.startswith("220"):
                    connection.sendall(b"QUIT\r\n")
                    return CheckResult.PASS, banner
                return CheckResult.FAIL, banner or "SMTP server returned an empty response"

        if desired.check_proto == "http":
            verify: Any = not bool(check.get("tls_skip_verify"))
            response = requests.request(
                str(check.get("method", "GET")),
                str(check["url"]),
                headers=check.get("header"),
                timeout=timeout,
                verify=verify,
                allow_redirects=bool(check.get("follow_redirects", True)),
            )
            result = CheckResult.PASS if response.status_code < 400 else CheckResult.FAIL
            return result, f"HTTP {response.status_code}"
    except (OSError, subprocess.SubprocessError, requests.RequestException) as error:
        result = CheckResult.ERROR if desired.check_proto == "icmp" else CheckResult.FAIL
        return result, f"{type(error).__name__}: {error}"

    return CheckResult.ERROR, f"unsupported check type: {desired.check_proto}"


class ActiveCheckWorker:
    def __init__(self, consul: ConsulClient, desired: DesiredService) -> None:
        # Do not share requests.Session between the blocking KV watch and worker threads.
        self.consul = ConsulClient(consul.cfg)
        self.desired = desired
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name=f"check-{desired.service_id}",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def join(self) -> None:
        self.thread.join(timeout=self.desired.timeout_seconds + 2)

    def _run(self) -> None:
        successes = 0
        failures = 0
        last_status: Optional[str] = None

        while not self.stop_event.is_set():
            started = time.monotonic()
            result, output = _execute_check(self.desired)
            if result is CheckResult.PASS:
                successes += 1
                failures = 0
                status = "passing" if successes >= self.desired.success_before_passing else (last_status or "warning")
            elif result is CheckResult.FAIL:
                failures += 1
                successes = 0
                if failures >= self.desired.failures_before_warning + self.desired.failures_before_critical:
                    status = "critical"
                elif failures >= self.desired.failures_before_warning:
                    status = "warning"
                else:
                    status = last_status or "warning"
            else:
                # A local check error does not prove that the target is unavailable.
                # Reset the streak counters and publish the unknown state as a TTL warning.
                successes = 0
                failures = 0
                status = "warning"
                output = f"ERROR: {output}"
                log.error(
                    "check=%s result=ERROR target=%s output=%s",
                    self.desired.check_id,
                    self.desired.check.get("target", self.desired.address),
                    output,
                )

            try:
                self.consul.update_ttl(self.desired.check_id, status, output)
                if status != last_status:
                    if last_status is None:
                    # The first publication after startup is the initial observation,
                    # not a service state change.
                        log.info(
                            "check=%s initial_status=%s output=%s",
                            self.desired.check_id,
                            status,
                            output,
                        )
                    elif status == "passing":
                        log.info(
                            "check=%s status=%s->%s output=%s",
                            self.desired.check_id,
                            last_status,
                            status,
                            output,
                        )
                    else:
                        log.warning(
                            "check=%s status=%s->%s output=%s",
                            self.desired.check_id,
                            last_status,
                            status,
                            output,
                        )
                last_status = status
            except requests.RequestException as error:
                log.error("Failed to update TTL check=%s: %s", self.desired.check_id, error)

            elapsed = time.monotonic() - started
            self.stop_event.wait(max(0.1, self.desired.interval_seconds - elapsed))


class ActiveCheckSet:
    def __init__(self, consul: ConsulClient) -> None:
        self.consul = consul
        self.workers: Dict[str, ActiveCheckWorker] = {}

    def replace(self, desired: Dict[str, DesiredService]) -> None:
        for worker in self.workers.values():
            worker.stop()
        for worker in self.workers.values():
            worker.join()
        self.workers = {sid: ActiveCheckWorker(self.consul, item) for sid, item in desired.items()}
        for worker in self.workers.values():
            worker.start()
        log.info("Started active checks: %d", len(self.workers))

    def stop(self) -> None:
        self.replace({})

# --------------------------------------------------------------------------- #
# Parse and validate the configuration                                 #
# --------------------------------------------------------------------------- #
def parse_desired_state(yaml_text: str, cfg: Config) -> Dict[str, DesiredService]:
    """Parse a YAML string into {service_id: DesiredService} and validate it."""
    if not yaml_text or not yaml_text.strip():
        return {}
    try:
        doc = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as e:
        raise InvalidDesiredState(f"YAML error: {e}") from e

    defaults = doc.get("defaults") or {}
    # Define the fixed schema keys so they are excluded from provider metadata.
    KNOWN_ZONE_KEYS = {"zone_name", "dns_provider", "records"}

    desired: Dict[str, DesiredService] = {}
    # Iterate over every zone in the configuration.
    for i, zone in enumerate(doc.get("zones", []) or []):
        zone_name = zone.get("zone_name")
        dns_provider = zone.get("dns_provider")

        if not zone_name or not dns_provider:
            raise InvalidDesiredState(
                f"zones[{i}] does not specify zone_name or dns_provider"
            )

        # Anything outside KNOWN_ZONE_KEYS is treated as a provider parameter and stored in meta.
        provider_meta: Dict[str, str] = {
            k: str(v)
            for k, v in zone.items()
            if k not in KNOWN_ZONE_KEYS and v is not None
        }

        for record in zone.get("records", []) or []:
            rec_name = record.get("name")
            if not rec_name:
                raise InvalidDesiredState(f"zone={zone_name}: record without name")
            for ep in record.get("endpoints", []) or []:
                sites = ep.get("sites")
                # Skip the endpoint if its site in the YAML configuration does not match this daemon.
                if not sites or cfg.site not in sites:
                    continue
                ip = ep.get("ip")
                check_proto = ep.get("check")
                if not ip or not check_proto:
                    raise InvalidDesiredState(
                        f"zone={zone_name} record={rec_name}: endpoint without ip/check: {ep!r}"
                    )
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
                    raise InvalidDesiredState(
                        f"zone={zone_name} record={rec_name} endpoint={ep!r}: "
                        f"{type(e).__name__}: {e}"
                    ) from e
                if ds.service_id in desired:
                    raise InvalidDesiredState(f"Duplicate service_id={ds.service_id}")
                desired[ds.service_id] = ds
    return desired

# --------------------------------------------------------------------------- #
# Service reconciliation                                                       #
# --------------------------------------------------------------------------- #
def reconcile(consul: ConsulClient, desired: Dict[str, DesiredService]) -> bool:
    """
    Reconcile differences. Do not raise exceptions; log them and continue.
    Returns:
    - True, if all operations succeeded
    - False, if at least one [de]register operation failed
    The main loop uses this flag to decide whether to advance last_index.
    """
    try:
        current = consul.list_managed_services()
    except requests.RequestException as e:
        log.error("Failed to list current services from the agent: %s", e)
        return False

    current_ids: Set[str] = set(current.keys())
    desired_ids: Set[str] = set(desired.keys())

    to_add      = desired_ids - current_ids
    to_remove   = current_ids - desired_ids
    to_keep     = desired_ids & current_ids

    log.info("Reconciliation: desired=%d, current on agent=%d, adding=%d, removing=%d, keeping=%d",
             len(desired_ids), len(current_ids), len(to_add), len(to_remove), len(to_keep))

    all_ok = True

    # Register new services.
    for sid in sorted(to_add):
        ds = desired[sid]
        try:
            consul.register(ds.to_payload())
            log.warning("Registered service id=%s name=%s address=%s check=%s",
                     ds.service_id, ds.name, ds.address, ds.check_proto)
        except requests.RequestException as e:
            log.error("Registration failed for id=%s: %s", sid, e)
            all_ok = False

    # Drift handling.
    # Re-register current services when config_hash has changed.
    # The service ID does not change.
    for sid in sorted(to_keep):
        ds = desired[sid]
        if _has_drift(current[sid], ds):
            try:
                consul.register(ds.to_payload())
                log.info("Re-registered drifted service id=%s", sid)
            except requests.RequestException as e:
                log.error("Re-registration failed for id=%s: %s", sid, e)
                all_ok = False

    # Remove obsolete IDs.
    for sid in sorted(to_remove):
        try:
            consul.deregister(sid)
            log.warning("Deregistered obsolete service id=%s", sid)
        except requests.RequestException as e:
            log.error("Deregistration failed for id=%s: %s", sid, e)
            all_ok = False

    return all_ok

# --------------------------------------------------------------------------- #
# Consul connectivity check                                               #
# Docker Compose may start the daemon before the agent opens port 8500.         #
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
            log.warning("Consul agent is not available yet: %s (retrying in %.1fs)",
                        e, backoff)
        shutdown.sleep(backoff)
        backoff = min(backoff * 2, consul.cfg.backoff_cap)

# --------------------------------------------------------------------------- #
# Main loop                                                                #
# --------------------------------------------------------------------------- #
def main() -> int:
    try:
        cfg = Config.from_env()
        cfg = with_auto_encrypt_ca_bundle(cfg)
    except Exception as e:
        log.error("Failed to initialize configuration from the environment: %s", e)
        return 1

    log.info("Starting DNS-Failover Control Plane (consul=%s, kv=%s, wait=%s, allow_empty_bootstrap=%s)",
             cfg.consul_addr, cfg.consul_kv_path, cfg.blocking_wait, cfg.allow_empty_bootstrap)
    shutdown = Shutdown()
    consul = ConsulClient(cfg)
    active_checks = ActiveCheckSet(consul)

    wait_for_consul(consul, shutdown)
    if shutdown.stop:
        return 0

    # 1. Synchronize state with a non-blocking read.
    log.info("Step 1. Initial state synchronization")
    last_index: int = 0
    backoff = cfg.backoff_base

    while not shutdown.stop:
        try:
            value, new_index = consul.kv_read(cfg.consul_kv_path, index=last_index, wait=cfg.blocking_wait)

        # Exception order is important!
        # ReadTimeout is a subclass of RequestException, which is a subclass of ConnectionError.
        # If these are reversed, a blocking-query timeout will be mistaken for a failure and trigger backoff.
        # Consul holds a blocking query for (wait + wait/16) seconds = 5 minutes + 18.75 seconds.
        # HTTP_TIMEOUT_BLOCKING=330s must be greater than this value!
        # https://developer.hashicorp.com/consul/api-docs/features/blocking

        except requests.exceptions.ReadTimeout:
            log.debug("Blocking query timed out normally; reconnecting")
            continue

        except KVUnavailable as e:
            # Consul KV is unavailable: do not deregister anything and preserve last_index.
            log.error("KV is unavailable: %s (retrying in %.1fs)", e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
            continue

        except Exception as e:
            log.exception("Unexpected error: %s", e)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
            continue

        # The read succeeded; determine how to handle the result.
        config_missing = value is None
        try:
            desired = ({} if config_missing else parse_desired_state(value, cfg))
        except InvalidDesiredState as error:
            log.error("Invalid desired config: %s. Existing services are unchanged.", error)
            last_index = new_index
            backoff = cfg.backoff_base
            shutdown.sleep(2.0)
            continue

        if config_missing:
            log.warning("KV file %s is missing (HTTP 404).", cfg.consul_kv_path)
        elif not desired:
            log.warning("KV file %s was read, but desired services for site=%s = 0.",
                        cfg.consul_kv_path, cfg.site)
        else:
            log.info("Configuration read (index=%d); desired services for site=%s: %d",
                     new_index, cfg.site, len(desired))

        # Cold-start safeguard:
        # when the configuration is empty or deleted, preserve existing managed services and wait for a valid configuration.
        # Disable this safeguard with ALLOW_EMPTY_BOOTSTRAP=true.
        if not desired and not cfg.allow_empty_bootstrap:
            log.warning(
                "Bootstrap: desired state is empty and ALLOW_EMPTY_BOOTSTRAP=false; "
                "skipping reconciliation to preserve managed services. "
                "Waiting for a valid configuration in KV (index=%d) ...",
                new_index,
            )
            # Advance the index; otherwise the next iteration will return immediately again.
            last_index = new_index
            backoff = cfg.backoff_base
            shutdown.sleep(2.0)
            continue

        if reconcile(consul, desired):
            active_checks.replace(desired)
            last_index = new_index
            backoff = cfg.backoff_base
            break
        else:
            # Some operations failed: do not advance the index; retry bootstrap after backoff.
            log.warning("Initial synchronization completed with errors; retrying in %.1fs",
                        backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
            continue

    if shutdown.stop:
        log.info("Shutdown during bootstrap")
        return 0

    # last_index here equals the key X-Consul-Index at bootstrap time.
    # Step 2 uses it as the blocking-query starting point.
    log.info("Step 2. Start watching KV (initial index=%d)", last_index)
    backoff = cfg.backoff_base
    outage_started: Optional[float] = None
    consecutive_failures = 0
    last_heartbeat = time.monotonic()

    while not shutdown.stop:
        query_started = time.monotonic()
        try:
            value, new_index = consul.kv_read(cfg.consul_kv_path, index=last_index, wait=cfg.blocking_wait)
            if shutdown.stop:
                break
            query_finished = time.monotonic()

            if outage_started is not None:
                log.info(
                    "Consul KV connection restored: outage=%.1fs, attempts=%d, index=%d",
                    query_finished - outage_started,
                    consecutive_failures,
                    new_index,
                )
                outage_started = None
                consecutive_failures = 0

            if query_finished - last_heartbeat >= cfg.heartbeat_interval:
                log.info(
                    "KV watch is active: index=%d, last request=%.1fs, consecutive errors=%d",
                    new_index,
                    query_finished - query_started,
                    consecutive_failures,
                )
                last_heartbeat = query_finished

            if new_index < 1:
                new_index = 1
            if new_index < last_index:
                log.warning("X-Consul-Index moved backward (%d -> %d); resetting the timer",
                            last_index, new_index)
                last_index = 0
                continue
            if new_index == last_index:
                # The blocking query timed out and returned without changes.
                log.debug("No KV changes at index=%d", new_index)
                backoff = cfg.backoff_base
                continue

            log.info("Detected a KV change: index %d -> %d; reconciling services ...",
                     last_index, new_index)
            try:
                desired = parse_desired_state(value, cfg) if value is not None else {}
            except InvalidDesiredState as error:
                log.error(
                    "Invalid desired config: %s. Existing services and checks are unchanged.",
                    error,
                )
                # Wait for the next key change without creating a busy loop.
                last_index = new_index
                backoff = cfg.backoff_base
                continue
            if value is None:
                log.warning("Configuration file %s was deleted. Deregistering all associated services", cfg.consul_kv_path)
            if reconcile(consul, desired):
                active_checks.replace(desired)
                last_index = new_index
                backoff = cfg.backoff_base
            else:
                # Do not advance last_index; the next iteration will retry reconciliation.
                # When index < real_index, Consul responds immediately without blocking,
                # but shutdown.sleep(backoff) prevents request flooding against the agent.
                log.warning("Reconciliation completed with errors; not advancing the index (retrying in %.1fs)",
                            backoff)
                shutdown.sleep(backoff)
                backoff = min(backoff * 2, cfg.backoff_cap)

        except requests.exceptions.ReadTimeout:
            # The client timed out while the server held the long-poll request.
            # It is safe to reconnect without changing last_index.
            if shutdown.stop:
                break
            log.debug("Blocking query timed out; reconnecting")
            backoff = cfg.backoff_base
        except KVUnavailable as e:
            if shutdown.stop:
                break
            now = time.monotonic()
            if outage_started is None:
                outage_started = now
            consecutive_failures += 1
            log.error(
                "Consul KV is unavailable: %s (attempt=%d, index=%d, retrying in %.1fs)",
                e,
                consecutive_failures,
                last_index,
                backoff,
            )
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
        except requests.RequestException as e:
            if shutdown.stop:
                break
            log.error("Consul API error: %s (retrying in %.1fs)", e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
        except Exception as e:  # noqa: BLE001 -- main loop must flow
            if shutdown.stop:
                break
            log.exception("Unexpected error in the monitoring loop: %s (retrying in %.1fs)",
                          e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)

    active_checks.stop()
    log.info("Shutdown complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())

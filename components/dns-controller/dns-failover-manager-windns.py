#!/usr/bin/env python3
"""
Windows DNS manager. Consul Template runs it whenever the rendered Consul service state changes.
Manages Microsoft DNS A records over SSH and PowerShell.

1. Reads the JSON file rendered by service-meta-output.tpl.
2. Preserves DNS when there are insufficient observers (`unknown`).
3. When state is known, selects IPs whose site confirmations meet quorum;
   if none qualify, applies on_all_fail: keep/remove/fallback.
4. Reads the Consul API URL from CONSUL_HTTP_ADDR provided by windns.hcl.

Environment variables:
  Required:
    WIN_SSH_HOST                            SSH target (jump host or DNS server)
    WIN_SSH_USER                            SSH user (for example, 'EXAMPLE\\dns-failover-mgmt')
    WIN_SSH_KEY_PATH / WIN_SSH_PASSWORD     SSH key or password; the key takes precedence
    DNS_PROVIDER_NAME                       Provider name (default: windns)
    CONSUL_GC_PATH                          Consul KV prefix for ownership state

  Optional:
    LOG_LEVEL                               Logging level (default: INFO)
    WIN_SSH_PORT                            SSH port (default: 22)
    WIN_SSH_EXTRA_OPTS                      Reserved for additional SSH options
    SSH_CONNECT_TIMEOUT                     Connection timeout (default: 10 seconds)
    SSH_TIMEOUT                             Overall command timeout (default: 60 seconds)
    CONSUL_HTTP_TOKEN                       Consul ACL token (if ACLs are enabled)
    WIN_SSH_INSECURE_SKIP_HOST_KEY_CHECK    Set true to disable known_hosts verification (unsafe; default: false)
"""
from __future__ import annotations

import os
import sys
import json
import base64
import requests
import yaml
import logging
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

from dns_controller_common import (
    ConsulProviderLock,
    OwnershipBlocked,
    build_identity,
    identity_key,
    load_registry_payload,
    registry_payload,
    transition_ownership,
    canonical_dns_name,
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
log = logging.getLogger("dns-manager-windns")

# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Config:
    ssh_host:           str
    ssh_user:           str
    consul_gc_path:     str
    ssh_port:           int
    ssh_password:       Optional[str]
    ssh_key_path:       Optional[str]
    ssh_known_hosts:    Optional[str]
    insecure_skip_host_key_check: bool
    connect_timeout:    int
    cmd_timeout:        int
    consul_addr:        str
    consul_token:       Optional[str]
    consul_cacert:      Optional[str]
    consul_config_path: str
    dns_provider_name:  str


    @staticmethod
    def from_env() -> "Config":
        # Validate required environment variables
        required_envs = ["WIN_SSH_HOST", "WIN_SSH_USER", "CONSUL_GC_PATH", "CONSUL_HTTP_ADDR"]
        missing_envs = [var for var in required_envs if var not in os.environ]
        if missing_envs:
            log.error("Missing required environment variables: %s", ", ".join(missing_envs))
            sys.exit(1)

        password = os.environ.get("WIN_SSH_PASSWORD") or None
        key      = os.environ.get("WIN_SSH_KEY_PATH") or None

        if not password and not key:
            log.error("WIN_SSH_PASSWORD or WIN_SSH_KEY_PATH is required")
            sys.exit(1)

        if password and key:
            log.warning("Both WIN_SSH_KEY_PATH and WIN_SSH_PASSWORD are set; using the SSH key")
            password = None

        ssh_known_hosts = os.environ.get("WIN_SSH_KNOWN_HOSTS") or None
        insecure_skip_host_key_check = os.environ.get(
            "WIN_SSH_INSECURE_SKIP_HOST_KEY_CHECK", "false"
        ).strip().lower() in ("1", "true", "yes", "on")
        if not ssh_known_hosts and not insecure_skip_host_key_check:
            log.error(
                "WIN_SSH_KNOWN_HOSTS is required. For temporary migration only, set "
                "WIN_SSH_INSECURE_SKIP_HOST_KEY_CHECK=true"
            )
            sys.exit(1)

        consul_addr = os.environ["CONSUL_HTTP_ADDR"].rstrip("/")
        if not consul_addr.startswith(("http://", "https://")):
            consul_http_ssl = os.environ.get("CONSUL_HTTP_SSL", "true").strip().lower()
            scheme = "https" if consul_http_ssl in ("1", "true", "yes", "on") else "http"
            consul_addr = f"{scheme}://{consul_addr}"

        return Config(
            ssh_host        = os.environ["WIN_SSH_HOST"],
            ssh_user        = os.environ["WIN_SSH_USER"],
            consul_gc_path  = os.environ["CONSUL_GC_PATH"],
            consul_addr     = consul_addr,
            ssh_port        = int(os.environ.get("WIN_SSH_PORT", "22")),
            ssh_password    = password,
            ssh_key_path    = key,
            ssh_known_hosts = ssh_known_hosts,
            insecure_skip_host_key_check = insecure_skip_host_key_check,
            connect_timeout = int(os.environ.get("SSH_CONNECT_TIMEOUT", "10")),
            cmd_timeout     = int(os.environ.get("SSH_TIMEOUT", "60")),
            dns_provider_name = os.environ.get("DNS_PROVIDER_NAME", "windns"),
            consul_token    = os.environ.get("CONSUL_HTTP_TOKEN") or None,
            consul_cacert   = os.environ.get("CONSUL_CACERT") or None,
            consul_config_path = os.environ.get(
                "CONSUL_CONFIG_PATH", "dns-failover/dns-failover-monitoring-config.yml"
            ),
        )

# --------------------------------------------------------------------------- #
# Consul KV state store                                                       #
# --------------------------------------------------------------------------- #
class ConsulStateStore:
    """
    Stores the provider ownership registry as JSON in Consul KV.
    Garbage collection uses it to find records removed from desired state.
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
            ttl_seconds=max(30, self.cfg.cmd_timeout + 30),
            renew_interval_seconds=10,
            lock_delay_seconds=5,
        )

    def load_active_records(self) -> Tuple[List[Dict[str, str]], str, bool]:
        """Read and validate the current minimal ownership registry."""
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
                "Failed to read the ownership registry: %s. "
                "Provider changes and registry writes are disabled.",
                error,
            )
            return [], "N/A (Consul API read error)", False

    def load_desired_records(self) -> Tuple[List[Dict[str, Any]], bool]:
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_config_path}"
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 404:
                log.error("The desired configuration is missing at %s; GC is disabled", self.cfg.consul_config_path)
                return [], False
            response.raise_for_status()
            encoded = response.json()[0].get("Value")
            if not encoded:
                return [], False
            document = yaml.safe_load(base64.b64decode(encoded).decode("utf-8"))
            if not isinstance(document, dict) or not isinstance(document.get("zones"), list):
                raise ValueError("The desired YAML configuration must contain a zones array")
            records: List[Dict[str, Any]] = []
            seen = set()
            for zone_index, zone in enumerate(document["zones"]):
                if not isinstance(zone, dict) or not isinstance(zone.get("dns_provider"), str):
                    raise ValueError(f"zones[{zone_index}]: dns_provider is required")
                if zone["dns_provider"] != self.cfg.dns_provider_name:
                    continue
                zone_name = zone.get("zone_name")
                dns_server = zone.get("win_dns_server")
                zone_records = zone.get("records")
                if not zone_name or not dns_server or not isinstance(zone_records, list):
                    raise ValueError(f"zones[{zone_index}]: zone_name, win_dns_server, and records are required")
                for record_index, record in enumerate(zone_records):
                    if not isinstance(record, dict) or record.get("name") is None:
                        raise ValueError(f"zones[{zone_index}].records[{record_index}]: name is required; use @ for the zone apex")
                    name = ps_record_name(str(record["name"]))
                    fqdn = make_fqdn(name, str(zone_name))
                    duplicate_key = (str(dns_server).casefold(), fqdn, "A")
                    if duplicate_key in seen:
                        raise ValueError(f"duplicate desired identity: {duplicate_key}")
                    seen.add(duplicate_key)
                    records.append({
                        "fqdn": fqdn,
                        "record": name,
                        "zone": str(zone_name),
                        "win_dns_server": str(dns_server),
                        "service_name": None,
                    })
            return records, True
        except (requests.RequestException, ValueError, KeyError, yaml.YAMLError) as error:
            log.error("Failed to read the desired YAML configuration; GC is disabled: %s", error)
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
# SSH and PowerShell client                                                   #
# --------------------------------------------------------------------------- #
class WinDNS:
    """
    Each operation uses one short SSH session and one PowerShell command
    passed through -EncodedCommand (UTF-16LE base64).
    """


    def __init__(self, cfg: Config):
        self.cfg = cfg


    # Build the SSH and PowerShell command
    @staticmethod
    def _encode_ps(script: str) -> str:
        return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


    def _ssh_argv(self, ps_b64: str) -> List[str]:
        argv: List[str] = []
        if self.cfg.ssh_password:
            argv += ["sshpass", "-e"]

        argv += [
            "ssh",
            "-p", str(self.cfg.ssh_port),
            "-o", f"ConnectTimeout={self.cfg.connect_timeout}",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=3",
        ]
        if self.cfg.insecure_skip_host_key_check:
            log.warning("SSH host-key verification was disabled by an explicit unsafe flag")
            argv += [
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
            ]
        else:
            argv += [
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={self.cfg.ssh_known_hosts}",
            ]
        argv += [
            "-o", "LogLevel=ERROR",
            "-o", "BatchMode=" + ("yes" if self.cfg.ssh_key_path else "no"),
        ]
        if self.cfg.ssh_key_path:
            argv += ["-i", self.cfg.ssh_key_path,
                     "-o", "IdentitiesOnly=yes",
                     "-o", "PreferredAuthentications=publickey"]
        else:
            argv += ["-o", "PreferredAuthentications=password",
                     "-o", "PubkeyAuthentication=no"]

        argv += [
            f"{self.cfg.ssh_user}@{self.cfg.ssh_host}",
            # One command line for the remote shell:
            f"powershell -NoProfile -NonInteractive -EncodedCommand {ps_b64}",
        ]
        return argv


    def _run_ps(self, script: str, action: str) -> str:
        # 1) Silence the progress stream that emits 'Preparing modules for first use'
        # 2) Encode unhandled errors as JSON prefixed with PSERR:
        full = (
            "$ProgressPreference='SilentlyContinue';"
            "$ErrorActionPreference='Stop';"
            "try {\n" + script + "\n} catch {"
            "  $e = @{"
            "    message  = $_.Exception.Message;"
            "    type     = $_.Exception.GetType().FullName;"
            "    category = $_.CategoryInfo.ToString();"
            "    fqeid    = $_.FullyQualifiedErrorId"
            "  } | ConvertTo-Json -Compress -Depth 4;"
            "  [Console]::Error.WriteLine('PSERR:' + $e);"
            "  exit 1"
            "}"
        )
        argv = self._ssh_argv(self._encode_ps(full))
        env  = os.environ.copy()
        if self.cfg.ssh_password:
            env["SSHPASS"] = self.cfg.ssh_password

        try:
            cp = subprocess.run(argv, env=env, input="",
                                capture_output=True, text=True,
                                timeout=self.cfg.cmd_timeout)
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"{action}: SSH timeout ({e.timeout}s)") from None

        if cp.returncode != 0:
            err = cp.stderr or cp.stdout or ""
            # Extract the JSON error marker when present
            if "PSERR:" in err:
                err = err.split("PSERR:", 1)[1].strip().splitlines()[0]
            else:
                err = err.strip().replace("\n", " ")
            raise RuntimeError(f"{action}: rc={cp.returncode}; {err}")
        return cp.stdout


    @staticmethod
    def _ps_str(s: str) -> str:
        """Quote a string safely for a single-quoted PowerShell literal."""
        return "'" + s.replace("'", "''") + "'"

    # API
    def list_a_records(self, dns_server: str, zone: str) -> Dict[str, Dict[str, Any]]:
        """
        Return an index: {hostname_lower: {"ttl": int, "ips": sorted[str]}}.
        Hostname is relative; @ represents the zone apex.
        """
        script = (
            f"$rs = Get-DnsServerResourceRecord -ComputerName {self._ps_str(dns_server)} "
            f"-ZoneName {self._ps_str(zone)} -RRType A;"
            "$out = $rs | Group-Object HostName | ForEach-Object {"
            "  [PSCustomObject]@{"
            "    HostName = $_.Name;"
            "    TTL      = [int]($_.Group[0].TimeToLive.TotalSeconds);"
            "    IPs      = @($_.Group | ForEach-Object { $_.RecordData.IPv4Address.IPAddressToString })"
            "  }"
            "};"
            "ConvertTo-Json -Depth 5 -Compress -InputObject @($out)"
        )
        raw = self._run_ps(script, f"LIST {dns_server}/{zone}").strip()
        idx: Dict[str, Dict[str, Any]] = {}
        if not raw:
            return idx
        data = json.loads(raw)
        if isinstance(data, dict):  # PowerShell returns an object for a single item
            data = [data]
        for rs in data:
            host = (rs.get("HostName") or "").lower()
            ips  = rs.get("IPs") or []
            if isinstance(ips, str):
                ips = [ips]
            idx[host] = {
                "ttl": int(rs.get("TTL") or 0),
                "ips": sorted(ips),
            }
        return idx


    def create_a(self, dns_server: str, zone: str, name: str, ttl: int,
                 ips: List[str]) -> None:
        """Create a missing RRset with one PowerShell cmdlet."""
        addresses = ", ".join(self._ps_str(ip) for ip in ips)
        script = (
            "Add-DnsServerResourceRecordA "
            f"-ComputerName {self._ps_str(dns_server)} "
            f"-ZoneName {self._ps_str(zone)} "
            f"-Name {self._ps_str(name)} "
            f"-IPv4Address @({addresses}) "
            f"-TimeToLive (New-TimeSpan -Seconds {int(ttl)});"
        )
        self._run_ps(script, f"CREATE {name}.{zone}@{dns_server}")


    def replace_a(self, dns_server: str, zone: str, name: str, ttl: int, ips: List[str]) -> None:
        """Replace all A records for a name in one PowerShell invocation."""
        adds = "\n".join(
            f"Add-DnsServerResourceRecordA "
            f"-ComputerName {self._ps_str(dns_server)} "
            f"-ZoneName {self._ps_str(zone)} "
            f"-Name {self._ps_str(name)} "
            f"-IPv4Address {self._ps_str(ip)} "
            f"-TimeToLive (New-TimeSpan -Seconds {int(ttl)});"
            for ip in ips
        )
        script = (
            "try {"
            "  Remove-DnsServerResourceRecord "
            f"   -ComputerName {self._ps_str(dns_server)}"
            f"   -ZoneName     {self._ps_str(zone)}"
            f"   -Name         {self._ps_str(name)}"
            "    -RRType A -Force"
            "} catch [Microsoft.Management.Infrastructure.CimException] {"
            # 9714 == DNS_ERROR_RECORD_DOES_NOT_EXIST: absence is expected
            "  if ($_.FullyQualifiedErrorId -notlike 'WIN32 9714*') { throw }"
            "}\n"
            f"{adds}"
        )
        self._run_ps(script, f"REPLACE {name}.{zone}@{dns_server}")


    def delete_a(self, dns_server: str, zone: str, name: str) -> None:
        script = (
            "try {"
            f"  Remove-DnsServerResourceRecord "
            f"    -ComputerName {self._ps_str(dns_server)}"
            f"    -ZoneName     {self._ps_str(zone)}"
            f"    -Name         {self._ps_str(name)}"
            "     -RRType A -Force"
            "} catch [Microsoft.Management.Infrastructure.CimException] {"
            "  if ($_.FullyQualifiedErrorId -notlike 'WIN32 9714*') { throw }"
            "}"
        )
        self._run_ps(script, f"DELETE {name}.{zone}@{dns_server}")

# --------------------------------------------------------------------------- #
# Decision logic                                                              #
# --------------------------------------------------------------------------- #
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
    Return the action, IPs, and a human-readable decision explanation.
    Votes are counted by unique sites, not by Consul agent count.
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


def ps_record_name(record: str) -> str:
    """Return a WinDNS record name; empty and @ both mean the zone apex."""
    r = (record or "").strip().strip(".")
    return r if r else "@"


def make_fqdn(record: str, zone: str) -> str:
    name = ps_record_name(record)
    return zone.lower() if name == "@" else f"{name}.{zone}".lower()


def identity_for_item(cfg: Config, item: Dict[str, Any]) -> Dict[str, str]:
    return build_identity(
        cfg.dns_provider_name,
        canonical_dns_name(str(item["win_dns_server"])),
        str(item["zone"]),
        "",
        "A",
        make_fqdn(str(item.get("record", "")), str(item["zone"])),
    )


def reconcile_one(api: WinDNS, item: Dict[str, Any], zone_index: Dict[str, Dict[str, Any]],
                  allow_delete: bool = True) -> bool:
    zone       = item["zone"]
    dns_server = item["win_dns_server"]
    name       = ps_record_name(item.get("record", ""))
    ttl        = int(item.get("ttl") or 60)
    svc        = item.get("service_name", f"{name}.{zone}")
    fqdn       = zone if name == "@" else f"{name}.{zone}"

    decision = decide(item)
    action, ips = decision.action, decision.ips
    existing = zone_index.get(name.lower())

    if action == "keep":
        log.warning(
            "[%s] %s A: keeping the current record -- %s",
            svc,
            fqdn,
            decision.explanation,
        )
        return False

    if action == "remove":
        if not allow_delete:
            log.warning("[%s] %s A: deletion blocked because the record is absent from the ownership registry", svc, fqdn)
            return False
        if existing:
            log.warning(
                "[%s] %s A: deleting (current ips=%s) -- %s",
                svc,
                fqdn,
                existing["ips"],
                decision.explanation,
            )
            api.delete_a(dns_server, zone, name)
            return True
        log.info("[%s] %s A: already absent", svc, fqdn)
        return False

    # action == "set"
    if not ips:
        log.warning(
            "[%s] %s A: set requested with an empty IP list -- skipping; %s",
            svc,
            fqdn,
            decision.explanation,
        )
        return False

    want = sorted(ips)
    if existing and existing["ips"] == want and existing["ttl"] == ttl:
        log.info(
            "[%s] %s A: already has %s ttl=%s -- skipping; %s",
            svc,
            fqdn,
            want,
            ttl,
            decision.explanation,
        )
        return False

    if not existing:
        log.warning(
            "[%s] %s A: creating ttl=%s ips=%s -- %s",
            svc,
            fqdn,
            ttl,
            want,
            decision.explanation,
        )
        api.create_a(dns_server, zone, name, ttl, want)
        return True

    if not allow_delete:
        raise OwnershipBlocked(
            f"{fqdn} A: record not changed because it is absent from the ownership registry "
            "and differs from desired state; "
            f"current state: ttl={existing['ttl']}, ips={existing['ips']}; "
            f"desired state: ttl={ttl}, ips={want}"
        )

    log.warning(
        "[%s] %s A: updating ttl %s->%s, ips %s->%s -- %s",
        svc,
        fqdn,
        existing["ttl"],
        ttl,
        existing["ips"],
        want,
        decision.explanation,
    )
    api.replace_a(dns_server, zone, name, ttl, want)
    return True

# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #
def load_items(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Expected a top-level JSON array")
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


def windns_verified(index: Dict[str, Dict[str, Any]], item: Dict[str, Any],
                   decision: Decision) -> Tuple[bool, bool]:
    name = ps_record_name(str(item.get("record", ""))).casefold()
    existing = index.get(name)
    if decision.action == "remove":
        return False, existing is None
    if decision.action != "set" or existing is None:
        return False, False
    expected_ips = sorted(str(ip) for ip in decision.ips)
    expected_ttl = int(item.get("ttl") or 60)
    return (
        sorted(str(ip) for ip in existing.get("ips", [])) == expected_ips
        and int(existing.get("ttl") or 0) == expected_ttl,
        False,
    )


def main() -> int:
    if len(sys.argv) < 2:
        log.error("Usage: dns-failover-manager-windns.py <state.json>")
        return 2

    src = sys.argv[1]
    try:
        cfg = Config.from_env()
    except (KeyError, RuntimeError) as error:
        log.error("Configuration initialization failed: %s", error)
        return 2
    state_store = ConsulStateStore(cfg)

    try:
        with state_store.provider_lock() as provider_lock:
            provider_lock.assert_held()
            log.info("Provider lock acquired; reading the current rendered state from %s", src)
            items = load_items(src)

            previous_records, last_updated_at, previous_known = state_store.load_active_records()
            current_desired, desired_known = state_store.load_desired_records()
            log.info("Ownership registry read; previous update time: %s", last_updated_at)
            if not previous_known or not desired_known:
                log.error(
                    "Ownership registry or desired configuration is unavailable: "
                    "provider synchronization and all DNS changes are disabled"
                )
                return 1

            owned = {identity_key(identity): identity for identity in previous_records}
            desired_by_key: Dict[str, Dict[str, Any]] = {}
            for record in current_desired:
                desired_by_key[identity_key(identity_for_item(cfg, record))] = record

            orphan_keys = set(owned) - set(desired_by_key) if previous_known and desired_known else set()
            by_pair: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)

            for item in items:
                server, zone = item.get("win_dns_server"), item.get("zone")
                if not server or not zone:
                    continue
                identity = identity_for_item(cfg, item)
                key = identity_key(identity)
                if not desired_known or key in desired_by_key:
                    enriched = dict(item)
                    enriched["_identity"] = identity
                    by_pair[(str(server), str(zone))].append(enriched)

            for key in orphan_keys:
                identity = owned[key]
                record = ps_record_name(relative_record_name(identity["fqdn"], identity["zone"]))
                by_pair[(identity["backend"], identity["zone"])].append({
                    "record": record,
                    "zone": identity["zone"],
                    "win_dns_server": identity["backend"],
                    "status": "all_critical",
                    "on_all_fail": "remove",
                    "service_name": f"orphaned-{identity['fqdn']}",
                    "_identity": identity,
                })

            if not by_pair:
                log.info("No records to synchronize; saving the known empty ownership registry")
                provider_lock.assert_held()
                state_store.save_active_records(list(owned.values()))
                return 0

            api = WinDNS(cfg)
            errors = 0
            safely_skipped = 0
            for (server, zone), pair_items in by_pair.items():
                try:
                    before = api.list_a_records(server, zone)
                except Exception as error:
                    log.error("Failed to read records for %s/%s: %s", server, zone, error)
                    errors += len(pair_items)
                    continue

                attempted: List[Tuple[Dict[str, Any], Decision, bool, bool]] = []
                for item in pair_items:
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
                    # item, decision, and allow_delete are not used here
                    changed for _, _, _, changed in attempted
                )
                after = before
                if needs_readback:
                    try:
                        provider_lock.assert_held()
                        after = api.list_a_records(server, zone)
                    except Exception as error:
                        log.error("Failed to verify state for %s/%s: %s", server, zone, error)
                        errors += len(attempted)
                        continue

                # changed is not used here
                for item, decision, allow_delete, _ in attempted:
                    identity = item["_identity"]
                    if decision.action == "remove" and not allow_delete:
                        continue
                    present, absent = windns_verified(after, item, decision)
                    _, transition_error = transition_ownership(
                        owned, identity, decision.action, present, absent
                    )
                    if transition_error:
                        log.error("[%s] record ownership was not confirmed: %s", item.get("service_name"), transition_error)
                        errors += 1

            if safely_skipped:
                log.warning(
                    "Safely skipped unconfirmed records: %d. "
                    "DNS was not changed; waiting for the next rendered-state update.",
                    safely_skipped,
                )
            if errors:
                log.error(
                    "Synchronization completed with errors (%d); "
                    "only confirmed ownership-registry changes are saved",
                    errors,
                )
            if not previous_known or not desired_known:
                log.warning("Ownership registry or desired configuration is unavailable; registry not updated")
            return finish_ownership_sync(
                state_store, provider_lock, owned, previous_known, desired_known, errors
            )
    except (OSError, json.JSONDecodeError, ValueError, requests.RequestException, RuntimeError) as error:
        log.error("DNS synchronization failed: %s", error)
        return 1


if __name__ == "__main__":
    sys.exit(main())

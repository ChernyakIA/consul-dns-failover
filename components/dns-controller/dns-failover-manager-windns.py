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
import logging
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Hashable, List, Optional, Tuple

from dns_controller_common import (
    Decision,
    OwnershipBlocked,
    ProviderBackend,
    ProviderStateStore,
    build_identity,
    canonical_dns_name,
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

        return Config(
            ssh_host        = os.environ["WIN_SSH_HOST"],
            ssh_user        = os.environ["WIN_SSH_USER"],
            consul_gc_path  = os.environ["CONSUL_GC_PATH"],
            consul_addr     = consul_addr_from_env(),
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
class ConsulStateStore(ProviderStateStore):
    """Ownership registry and desired records of the Windows DNS provider."""

    zone_backend_field = "win_dns_server"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg, log)

    @property
    def lock_ttl_seconds(self) -> int:
        # The lock must outlive one SSH command.
        return max(30, self.cfg.cmd_timeout + 30)

    def desired_record(self, zone_name: str, backend: str,
                       record_name: str) -> Tuple[Hashable, Dict[str, Any]]:
        name = ps_record_name(record_name)
        fqdn = make_fqdn(name, zone_name)
        return (backend.casefold(), fqdn, "A"), {
            "fqdn": fqdn,
            "record": name,
            "zone": zone_name,
            "win_dns_server": backend,
            "service_name": None,
        }

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
# Record reconciliation                                                       #
# --------------------------------------------------------------------------- #
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


def reconcile_one(api: WinDNS, item: Dict[str, Any], decision: Decision,
                  zone_index: Dict[str, Dict[str, Any]], allow_delete: bool = True) -> bool:
    zone       = item["zone"]
    dns_server = item["win_dns_server"]
    name       = ps_record_name(item.get("record", ""))
    ttl        = int(item.get("ttl") or 60)
    svc        = item.get("service_name", f"{name}.{zone}")
    fqdn       = zone if name == "@" else f"{name}.{zone}"

    action, ips = decision.action, decision.ips
    existing = zone_index.get(name.lower())

    if action == "keep":
        log.info(
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


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #
class WinDNSBackend(ProviderBackend):
    """Windows DNS side of the shared synchronization flow; records are grouped by (server, zone)."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.api: Optional[WinDNS] = None

    @property
    def client(self) -> WinDNS:
        if self.api is None:
            raise RuntimeError("the Windows DNS client was used before connect()")
        return self.api

    def identity_for_item(self, item: Dict[str, Any]) -> Dict[str, str]:
        return identity_for_item(self.cfg, item)

    def group_key(self, item: Dict[str, Any]) -> Optional[Hashable]:
        server, zone = item.get("win_dns_server"), item.get("zone")
        return (str(server), str(zone)) if server and zone else None

    def describe_group(self, group: Any) -> str:
        server, zone = group
        return f"{server}/{zone}"

    def orphan_item(self, identity: Dict[str, str]) -> Dict[str, Any]:
        return {
            "record": ps_record_name(relative_record_name(identity["fqdn"], identity["zone"])),
            "zone": identity["zone"],
            "win_dns_server": identity["backend"],
            "status": "all_critical",
            "on_all_fail": "remove",
            "service_name": f"orphaned-{identity['fqdn']}",
        }

    def connect(self) -> None:
        self.api = WinDNS(self.cfg)

    def list_records(self, group: Any) -> Dict[str, Dict[str, Any]]:
        server, zone = group
        return self.client.list_a_records(server, zone)

    def reconcile_one(self, item: Dict[str, Any], decision: Decision,
                      index: Any, allow_delete: bool) -> bool:
        return reconcile_one(self.client, item, decision, index, allow_delete=allow_delete)

    def verified(self, index: Any, item: Dict[str, Any], decision: Decision) -> Tuple[bool, bool]:
        return windns_verified(index, item, decision)


def main() -> int:
    if len(sys.argv) < 2:
        log.error("Usage: dns-failover-manager-windns.py <state.json>")
        return 2

    try:
        cfg = Config.from_env()
    except (KeyError, RuntimeError) as error:
        log.error("Configuration initialization failed: %s", error)
        return 2
    return run_sync(sys.argv[1], ConsulStateStore(cfg), WinDNSBackend(cfg), log)


if __name__ == "__main__":
    sys.exit(main())

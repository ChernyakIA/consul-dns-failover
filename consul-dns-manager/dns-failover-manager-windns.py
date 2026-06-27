#!/usr/bin/env python3
"""
Windows DNS-Manager script. Executed by consul-template upon changes in Consul service health states.
Manages only A-records in Microsoft DNS via SSH + PowerShell.

1. Reads a JSON state file rendered from template-service.tpl.
2. Filters records relative to on_all_fail, fallback_ip, and quorum settings:
    status == "ok" -- Reconciles the rrset target IPs to the desired set.
    status == "all_critical" -- Behavior depends on the 'on_all_fail' setting:
        "keep"     -- Skip / leave intact.
        "remove"   -- Delete the rrset.
        "fallback" -- Set to the defined fallback_ip address.

Variables:
  Required:
    WIN_SSH_HOST                            Jump host or Active Directory Domain Controller IP/FQDN
    WIN_SSH_USER                            SSH username (e.g., 'CORP\\dns-failover-username')
    WIN_SSH_KEY_PATH / WIN_SSH_PASSWORD     Define identity key OR password. Key takes precedence.
    CONSUL_HTTP_ADDR                        Consul URL (default: http://consul.example.com)
    DNS_PROVIDER_NAME                       Provider identifier (default: windns)
    CONSUL_GC_PATH                          Consul KV path used to store current state tracking

  Optional:
    LOG_LEVEL                               Logging level (default: INFO)
    WIN_SSH_PORT                            SSH daemon port (default: 22)
    WIN_SSH_KNOWN_HOSTS                     Path to known_hosts file
    WIN_SSH_STRICT                          'yes'/'no' (default: 'no'); toggles StrictHostKeyChecking=yes
    WIN_SSH_EXTRA_OPTS                      Arguments passed to SSH cmd (e.g. "-o ProxyJump=...")
    SSH_CONNECT_TIMEOUT                     SSH connect timeout in seconds (default: 10)
    SSH_TIMEOUT                             Command execution timeout (default: 60)
    CONSUL_HTTP_TOKEN                       Consul ACL token (if ACLs are enabled)
"""
from __future__ import annotations

import os
import sys
import json
import base64
import requests
import logging
import subprocess

from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

# --------------------------------------------------------------------------- #
# Logging Configurations                                                      #
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("dns-manager-windns")

# --------------------------------------------------------------------------- #
# Configuration Interface                                                    #
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
    ssh_strict:         bool
    connect_timeout:    int
    cmd_timeout:        int
    consul_addr:        str
    consul_token:       Optional[str]
    dns_provider_name:  str


    @staticmethod
    def from_env() -> "Config":
        # Validate critical environment variables
        required_envs = ["WIN_SSH_HOST", "WIN_SSH_USER", "CONSUL_GC_PATH", "CONSUL_HTTP_ADDR"]
        missing_envs = [var for var in required_envs if var not in os.environ]
        if missing_envs:
            log.error("Missing required environment variables: %s", ", ".join(missing_envs))
            sys.exit(1)

        password = os.environ.get("WIN_SSH_PASSWORD") or None
        key      = os.environ.get("WIN_SSH_KEY_PATH") or None
        
        if not password and not key:
            log.error("Either WIN_SSH_PASSWORD or WIN_SSH_KEY_PATH must be specified")
            sys.exit(1)
            
        if password and key:
            log.warning("Both WIN_SSH_KEY_PATH and WIN_SSH_PASSWORD are set. Prioritizing the SSH cryptographic key.")
            password = None

        consul_addr = os.environ["CONSUL_HTTP_ADDR"].rstrip("/")
        if not consul_addr.startswith(("http://", "https://")):
            log.warning("CONSUL_HTTP_ADDR '%s' does not specify a protocol schema. Defaulting to 'http://'", consul_addr)
            consul_addr = f"http://{consul_addr}"

        return Config(
            ssh_host        = os.environ["WIN_SSH_HOST"],
            ssh_user        = os.environ["WIN_SSH_USER"],
            consul_gc_path  = os.environ["CONSUL_GC_PATH"],
            consul_addr     = consul_addr,
            ssh_port        = int(os.environ.get("WIN_SSH_PORT", "22")),
            ssh_password    = password,
            ssh_key_path    = key,
            ssh_known_hosts = os.environ.get("WIN_SSH_KNOWN_HOSTS") or None,
            ssh_strict      = os.environ.get("WIN_SSH_STRICT", "no").lower() in ("yes", "true", "1"),
            connect_timeout = int(os.environ.get("SSH_CONNECT_TIMEOUT", "10")),
            cmd_timeout     = int(os.environ.get("SSH_TIMEOUT", "60")),
            dns_provider_name = os.environ.get("DNS_PROVIDER_NAME", "windns"),
            consul_token    = os.environ.get("CONSUL_HTTP_TOKEN") or None
        )

# --------------------------------------------------------------------------- #
# State Storage Engine (Consul KV)                                            #
# --------------------------------------------------------------------------- #
class ConsulStateStore:
    """
    Saves the list of the provider's managed domains to a dedicated JSON structure inside Consul KV.
    This schema is evaluated by the GC routine to detect and prune entries removed from prior configs.
    """


    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.consul_token:
            self.session.headers["X-Consul-Token"] = cfg.consul_token


    def load_active_records(self) -> Tuple[List[Dict[str, Any]], str]:
        """Loads tracked FQDN structures and their last configuration update timestamp."""
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_gc_path}{self.cfg.dns_provider_name}-active-config"
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code == 404:
                log.info("Tracked domains registry is empty (cold start detected).")
                return [], "N/A (cold start)"
            r.raise_for_status()

            raw_val = r.json()[0].get("Value")
            if not raw_val:
                return [], "N/A (empty KV token payload)"
            
            decoded = base64.b64decode(raw_val).decode("utf-8")
            parsed_data = json.loads(decoded)

            if isinstance(parsed_data, dict):
                records = parsed_data.get("records") or []
                updated_at = parsed_data.get("updated_at") or "Timestamp not provided"
                return records, updated_at

            return [], "N/A (invalid data schema format in Consul KV)"

        except Exception as e:
            log.warning("Could not retrieve state from Consul KV: %s. Proceeding with clear state assumptions.", e)
            return [], "N/A (Consul KV HTTP read error)"


    def save_active_records(self, state_records: List[Dict[str, Any]]) -> None:
        """Atomically stores the updated set of active target domains."""
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
            log.info("Active domain registry successfully updated in Consul KV. Timestamp: %s", now_str)
        except Exception as e:
            log.error("Failed to commit tracking state to Consul KV: %s", e)

# --------------------------------------------------------------------------- #
# SSH and PowerShell Client                                                   #
# --------------------------------------------------------------------------- #
class WinDNS:
    """
    Executes tasks over clean short-lived SSH connections running PowerShell 
    commands serialized as UTF-16LE inside a Base64-encoded string (-EncodedCommand).
    """


    def __init__(self, cfg: Config):
        self.cfg = cfg


    # Base64 initialization helper
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
            "-o", "StrictHostKeyChecking="
                  + ("yes" if self.cfg.ssh_strict else "accept-new"),
            "-o", "BatchMode=" + ("yes" if self.cfg.ssh_key_path else "no"),
        ]
        if self.cfg.ssh_key_path:
            argv += ["-i", self.cfg.ssh_key_path,
                     "-o", "IdentitiesOnly=yes",
                     "-o", "PreferredAuthentications=publickey"]
        else:
            argv += ["-o", "PreferredAuthentications=password",
                     "-o", "PubkeyAuthentication=no"]

        if self.cfg.ssh_known_hosts:
            argv += ["-o", f"UserKnownHostsFile={self.cfg.ssh_known_hosts}"]
        else:
            argv += ["-o", "UserKnownHostsFile=/dev/null",
                     "-o", "LogLevel=ERROR"]

        argv += [
            f"{self.cfg.ssh_user}@{self.cfg.ssh_host}",
            # Executed within a remote non-interactive shell profile
            f"powershell -NoProfile -NonInteractive -EncodedCommand {ps_b64}",
        ]
        return argv


    def _run_ps(self, script: str, action: str) -> str:
        # 1) Stop the progress stream to avoid intrusive OS module initialization output
        # 2) Encapsulate unhandled exceptions into structured JSON stdout strings prefixed with 'PSERR:'
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
            raise RuntimeError(f"{action}: SSH execution timed out ({e.timeout}s)") from None

        if cp.returncode != 0:
            err = cp.stderr or cp.stdout or ""
            # Sift raw output for PowerShell-based exception markers
            if "PSERR:" in err:
                err = err.split("PSERR:", 1)[1].strip().splitlines()[0]
            else:
                err = err.strip().replace("\n", " ")
            raise RuntimeError(f"{action}: rc={cp.returncode}; {err}")
        return cp.stdout


    @staticmethod
    def _ps_str(s: str) -> str:
        """Safely escape single quotes for literal string injection in PowerShell modules."""
        return "'" + s.replace("'", "''") + "'"

    # API Methods
    def list_a_records(self, dns_server: str, zone: str) -> Dict[str, Dict[str, Any]]:
        """
        Retrieves records indexed as: {hostname_lower: {"ttl": int, "ips": sorted[str]}}.
        Expects a relative hostname returning '@' for zone apex targets.
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
        if isinstance(data, dict):  # PowerShell converts single arrays objects to simple dicts
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


    def replace_a(self, dns_server: str, zone: str, name: str, ttl: int, ips: List[str]) -> None:
        """Atomically wipes outdated A records for target Name, committing updated IPs inside a single sequence."""
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
            # 9714 == DNS_ERROR_RECORD_DOES_NOT_EXIST -- Safe to ignore if there is nothing to prune
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
# State Decision-Making Interface                                             #
# --------------------------------------------------------------------------- #
def decide(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    status      = item.get("status")
    quorum      = int(item.get("quorum") or 1)
    confirms    = item.get("confirmations") or {}
    on_all_fail = (item.get("on_all_fail") or "keep").lower()
    fallback    = (item.get("fallback_ip") or "").strip()

    if status == "ok":
        ips = sorted(ip for ip, c in confirms.items() if int(c) >= quorum)
        if ips:
            return "set", ips
        status = "all_critical"

    if status == "all_critical":
        if on_all_fail == "remove":
            return "remove", []
        if on_all_fail == "fallback" and fallback:
            return "set", [fallback]
        return "keep", []

    log.warning("Unknown service status encountered '%s' -- evaluation set to keep", status)
    return "keep", []


def ps_record_name(record: str) -> str:
    """Canonical record mapping identifier: empty or trailing separator converts to '@'."""
    r = (record or "").strip().strip(".")
    return r if r else "@"


def make_fqdn(record: str, zone: str) -> str:
    name = ps_record_name(record)
    return zone.lower() if name == "@" else f"{name}.{zone}".lower()


def reconcile_one(api: WinDNS, item: Dict[str, Any], zone_index: Dict[str, Dict[str, Any]]) -> None:
    zone       = item["zone"]
    dns_server = item["win_dns_server"]
    name       = ps_record_name(item.get("record", ""))
    ttl        = int(item.get("ttl") or 60)
    svc        = item.get("service_name", f"{name}.{zone}")
    fqdn       = zone if name == "@" else f"{name}.{zone}"

    action, ips = decide(item)
    existing    = zone_index.get(name.lower())

    if action == "keep":
        log.warning("[%s] %s A: Preserving state configuration (on_all_fail=keep)", svc, fqdn)
        return

    if action == "remove":
        if existing:
            log.warning("[%s] %s A: Removing DNS resource (current resolution lists: ips=%s)",
                     svc, fqdn, existing["ips"])
            api.delete_a(dns_server, zone, name)
        else:
            log.info("[%s] %s A: Target record is already deleted", svc, fqdn)
        return

    # action == "set"
    if not ips:
        log.warning("[%s] %s A: Action called with empty target IPs -- skipping modification cycle",
                    svc, fqdn)
        return

    want = sorted(ips)
    if existing and existing["ips"] == want and existing["ttl"] == ttl:
        log.info("[%s] %s A: Record corresponds to planned state (ips=%s, ttl=%s) -- skipping modification",
                 svc, fqdn, want, ttl)
        return

    if existing:
        log.warning("[%s] %s A: Adjusting parameters; ttl %s->%s, ips %s->%s",
                 svc, fqdn, existing["ttl"], ttl, existing["ips"], want)
    else:
        log.warning("[%s] %s A: Generating missing record with ttl=%s, ips=%s",
                 svc, fqdn, ttl, want)
    api.replace_a(dns_server, zone, name, ttl, want)

# --------------------------------------------------------------------------- #
# Application Entry Point                                                     #
# --------------------------------------------------------------------------- #
def load_items(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Malformatted state file: Expected a raw array format as structural JSON parent.")
    return data


def main() -> int:
    if len(sys.argv) < 2:
        log.error("Usage: dns-failover-manager-windns.py <state.json>")
        return 2

    src = sys.argv[1]
    log.info("Loading execution state configuration from: %s", src)
    try:
        items = load_items(src)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        log.error("Unable to parse source JSON configuration payload %s: %s", src, e)
        return 2

    try:
        cfg = Config.from_env()
    except (KeyError, RuntimeError) as e:
        log.error("Failed to properly initialize environment context configurations: %s", e)
        return 2

    state_store = ConsulStateStore(cfg)

    # Reclaim record catalog from global Consul Key-Value Store
    previous_managed, last_updated_at = state_store.load_active_records()
    log.info("Tracked domain registry imported. Reconciling with database updated on: '%s'", last_updated_at)
    
    previous_by_fqdn = {x["fqdn"]: x for x in previous_managed}

    # Evaluate targeted configuration parameters
    current_managed_list: List[Dict[str, Any]] = []
    for it in items:
        srv = it.get("win_dns_server")
        zone = it.get("zone")
        if not srv or not zone:
            continue
        
        name = ps_record_name(it.get("record", ""))
        fqdn = make_fqdn(name, zone)
        current_managed_list.append({
            "fqdn": fqdn,
            "record": name,
            "zone": zone,
            "win_dns_server": srv,
            "service_name": it.get("service_name")
        })
    current_by_fqdn = {x["fqdn"]: x for x in current_managed_list}

    # Identify orphaned domains that require cleanup
    orphans_fqdns = set(previous_by_fqdn.keys()) - set(current_by_fqdn.keys())
    
    # Sort all targeted records into server-zone mapping tuples
    by_pair: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for it in items:
        srv  = it.get("win_dns_server")
        zone = it.get("zone")
        if srv and zone:
            by_pair[(srv, zone)].append(it)

    # Process orphaned assets
    for orphan_fqdn in orphans_fqdns:
        orphan = previous_by_fqdn[orphan_fqdn]
        srv = orphan["win_dns_server"]
        zone = orphan["zone"]
        record = orphan["record"]
        by_pair[(srv, zone)].append({
            "record": record,
            "zone": zone,
            "win_dns_server": srv,
            "status": "all_critical",
            "on_all_fail": "remove",  # Enforce decommissioning action for absolute orphans
            "service_name": f"orphaned-{orphan_fqdn}"
        })

    if not by_pair:
        log.info("No active domains or orphaned records discovered. Exiting safely.")
        state_store.save_active_records([])
        return 0

    api = WinDNS(cfg)
    errors = 0

    # Reconcile on a server-to-zone basis
    for (dns_server, zone), zitems in by_pair.items():
        log.info("Processing target server %s, Zone %s: active payload size %d (including garbage logs/orphans)", dns_server, zone, len(zitems))
        try:
            index = api.list_a_records(dns_server, zone)
        except Exception as e:
            log.error("Failed to query target entries lookup on server %s [Zone: %s]: %s", dns_server, zone, e)
            errors += len(zitems)
            continue

        for it in zitems:
            try:
                reconcile_one(api, it, index)
            except Exception as e:
                log.error("[%s] State verification failed: %s", it.get("service_name"), e)
                errors += 1

    # Only finalize updates in Consul KV tracking if all updates pass without failures
    if errors == 0:
        state_store.save_active_records(current_managed_list)
        return 0
    else:
        log.error("State synchronization loop completed with (%d) error(s). Execution state catalog updates in Consul KV skipped.", errors)
        return 1


if __name__ == "__main__":
    sys.exit(main())
    
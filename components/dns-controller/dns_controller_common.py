"""Shared functions for DNS Manager scripts."""
from __future__ import annotations

import base64
import json
import logging
import os
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Hashable, List, Optional, Tuple
from urllib.parse import quote

import requests
import yaml

log = logging.getLogger("dns-controller-common")


class LockLostError(RuntimeError):
    """The Consul session no longer confirms ownership of the provider lock."""


class OwnershipBlocked(RuntimeError):
    """The record was safely skipped because its ownership has not yet been confirmed."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_dns_name(value: str) -> str:
    """Normalize the domain name to lowercase without a trailing dot."""
    return (value or "").strip().rstrip(".").casefold()


def build_identity(provider: str, backend: str, zone: str, zone_id: str,
                   record_type: str, fqdn: str) -> Dict[str, str]:
    """Build the record identity data"""
    return {
        "provider": (provider or "").strip().casefold(),
        "backend": (backend or "").strip(),
        "zone": canonical_dns_name(zone),
        "zone_id": (zone_id or "").strip(),
        "record_type": (record_type or "").strip().upper(),
        "fqdn": canonical_dns_name(fqdn),
    }


def identity_key(identity: Dict[str, Any]) -> str:
    """Build the record identity key"""
    fields = ("provider", "backend", "zone", "zone_id", "record_type", "fqdn")
    return "|".join(str(identity.get(field, "")) for field in fields)


def load_registry_payload(payload: Dict[str, Any], provider: str) -> List[Dict[str, str]]:
    """Validate and load the ownership registry from Consul KV."""
    if not isinstance(payload, dict):
        raise ValueError("the ownership registry must be a JSON object")
    if set(payload) - {"updated_at", "records"}:
        raise ValueError("the ownership registry contains unsupported fields; delete the old GC key")
    records = payload.get("records")
    if not isinstance(records, list):
        raise ValueError("the ownership registry records field must be an array")
    required = {"provider", "backend", "zone", "zone_id", "record_type", "fqdn"}
    result: List[Dict[str, str]] = []
    seen = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != required:
            raise ValueError("invalid composite identity; delete the old GC key")
        if record.get("provider") != provider:
            raise ValueError("the composite identity belongs to another provider")
        if not all(isinstance(record.get(field), str) for field in required):
            raise ValueError("all composite identity fields must be strings")
        if not record["backend"] or not record["zone"] or not record["record_type"] or not record["fqdn"]:
            raise ValueError("the composite identity contains empty required fields")
        key = identity_key(record)
        if key in seen:
            raise ValueError(f"duplicate composite identity: {key}")
        seen.add(key)
        result.append(record)
    return result


def transition_ownership(
    owned: Dict[str, Dict[str, str]],
    identity: Dict[str, str],
    action: str,
    verified_present: bool,
    verified_absent: bool,
) -> Tuple[bool, Optional[str]]:
    """
    Modify the owned dictionary that is subsequently saved as the GC registry.
    Determine whether a record can be changed in or removed from the registry after verification.
    """
    key = identity_key(identity)
    existing = owned.get(key)
    if action == "keep":
        return False, None
    if action == "set":
        if not verified_present:
            return False, "provider verification did not confirm the desired DNS record"
        owned[key] = identity
        return owned[key] != existing, None
    if action == "remove":
        if existing is None:
            return False, None
        if not verified_absent:
            return False, "provider verification did not confirm the deletion"
        del owned[key]
        return True, None
    return False, f"unknown record ownership action: {action}"


def finish_ownership_sync(
    state_store: Any,
    provider_lock: Any,
    owned: Dict[str, Dict[str, Any]],
    previous_known: bool,
    desired_known: bool,
    errors: int,
) -> int:
    """Save confirmed changes even when other records have errors."""
    if not previous_known or not desired_known:
        return 1
    provider_lock.assert_held()
    state_store.save_active_records(list(owned.values()))
    return 1 if errors else 0


def registry_payload(records: List[Dict[str, str]],
                     now: Optional[str] = None) -> Dict[str, Any]:
    """Build the ownership registry payload for Consul KV."""
    return {
        "updated_at": now or utc_now(),
        "records": sorted(records, key=identity_key),
    }


class ConsulProviderLock:
    """Session-backed Consul KV lock"""

    def __init__(self, session: Any, consul_addr: str, lock_key: str, provider: str,
                 ttl_seconds: int = 30, renew_interval_seconds: int = 10,
                 lock_delay_seconds: int = 5) -> None:
        """Store the lock settings"""
        self.session = session  # Consul ACL token, TLS CA, connection reuse
        self.consul_addr = consul_addr.rstrip("/")
        self.lock_key = lock_key.strip("/")  # dns-failover/gc/locks/selecteldns
        self.provider = provider
        self.ttl_seconds = ttl_seconds
        self.renew_interval_seconds = renew_interval_seconds  # Session renewal interval
        self.lock_delay_seconds = lock_delay_seconds  # Delay before reacquiring the lock after an unexpected session loss
        self.session_id: Optional[str] = None
        self.held = False
        self._stop = threading.Event()  # Stop lock renewal
        self._lost = threading.Event()  # Renewal failed; consider the session lost
        self._renew_thread: Optional[threading.Thread] = None  # background session-renewal thread

    @property
    def _kv_url(self) -> str:
        return f"{self.consul_addr}/v1/kv/{quote(self.lock_key, safe='/')}"

    def _create_session(self) -> None:
        response = self.session.put(
            f"{self.consul_addr}/v1/session/create",
            json={
                "Name": f"dns-failover-{self.provider}",
                "TTL": f"{self.ttl_seconds}s",
                "LockDelay": f"{self.lock_delay_seconds}s",
                "Behavior": "delete",  # Delete the lock key when the session ends
            }, timeout=10,
        )
        response.raise_for_status()
        self.session_id = str(response.json()["ID"])

    def _renew_loop(self) -> None:
        while not self._stop.wait(self.renew_interval_seconds):
            try:
                response = self.session.put(
                    f"{self.consul_addr}/v1/session/renew/{self.session_id}", timeout=10)
                response.raise_for_status()
                if not response.json():
                    raise LockLostError("Consul returned an empty renew response")
            except Exception as error:
                log.error("Lost the provider Consul session %s: %s", self.provider, error)
                self._lost.set()
                return

    def _start_renewer(self) -> None:
        self._renew_thread = threading.Thread(
            target=self._renew_loop,
            name=f"consul-lock-renew-{self.provider}", daemon=True)
        self._renew_thread.start()

    def _wait_for_change(self) -> None:
        """Wait when another process holds the lock"""
        current = self.session.get(self._kv_url, timeout=10)
        if current.status_code == 404:
            return
        if current.status_code != 200:
            current.raise_for_status()
        current_value = current.json() or []
        if not current_value or not current_value[0].get("Session"):
            return
        index = current.headers.get("X-Consul-Index", "0")
        waiting = self.session.get(
            f"{self._kv_url}?index={index}&wait=30s", timeout=35)
        if waiting.status_code not in (200, 404):
            waiting.raise_for_status()

    def acquire(self) -> None:
        """Acquire the lock"""
        self._create_session()
        self._start_renewer()
        while True:
            if self._lost.is_set():
                raise LockLostError("The Consul session was lost while waiting for the provider lock")
            response = self.session.put(
                f"{self._kv_url}?acquire={self.session_id}",
                data=json.dumps({"provider": self.provider, "session": self.session_id}),
                timeout=10,
            )
            response.raise_for_status()
            if response.json() is True:
                self.held = True
                log.info("Acquired provider lock %s", self.lock_key)
                return
            log.info("Provider lock %s is held; waiting for release", self.lock_key)
            self._wait_for_change()

    def assert_held(self) -> None:
        if not self.held or self._lost.is_set():
            raise LockLostError(f"provider lock {self.lock_key} was lost")

    def release(self) -> None:
        self._stop.set()
        if self._renew_thread is not None:
            self._renew_thread.join(timeout=2)
        try:
            if self.held and self.session_id:
                response = self.session.put(
                    f"{self._kv_url}?release={self.session_id}", timeout=10)
                response.raise_for_status()
        finally:
            self.held = False
            if self.session_id:
                try:
                    response = self.session.put(
                        f"{self.consul_addr}/v1/session/destroy/{self.session_id}", timeout=10)
                    response.raise_for_status()
                except Exception as error:
                    log.warning("Failed to delete Consul session %s: %s", self.session_id, error)

    def __enter__(self) -> "ConsulProviderLock":
        """Use the class as a context manager"""
        try:
            self.acquire()
            return self
        except Exception:
            self.release()
            raise

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


def consul_addr_from_env() -> str:
    """Return the Consul API URL from CONSUL_HTTP_ADDR, adding a scheme when it is absent."""
    consul_addr = os.environ["CONSUL_HTTP_ADDR"].rstrip("/")
    if not consul_addr.startswith(("http://", "https://")):
        consul_http_ssl = os.environ.get("CONSUL_HTTP_SSL", "true").strip().lower()
        scheme = "https" if consul_http_ssl in ("1", "true", "yes", "on") else "http"
        consul_addr = f"{scheme}://{consul_addr}"
    return consul_addr


def load_items(path: str) -> List[Dict[str, Any]]:
    """Read the state rendered by Consul Template."""
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
    Return the action, IPs, and a human-readable explanation of the decision.
    Votes are counted by unique sites, not by the number of Consul agents.
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


# --------------------------------------------------------------------------- #
# State storage in Consul KV                                                  #
# --------------------------------------------------------------------------- #
class ProviderStateStore:
    """
    Stores the provider ownership registry as JSON in Consul KV.
    Garbage collection uses it to find records removed from the desired state.

    A provider subclass sets zone_backend_field and implements desired_record().
    cfg must provide consul_addr, consul_token, consul_cacert, consul_gc_path,
    consul_config_path, and dns_provider_name.
    """

    # Zone-level key of the desired YAML configuration that addresses the provider backend.
    zone_backend_field = ""

    def __init__(self, cfg: Any, logger: logging.Logger = log) -> None:
        self.cfg = cfg
        self.log = logger
        self.session = requests.Session()
        if cfg.consul_cacert:
            self.session.verify = cfg.consul_cacert
        if cfg.consul_token:
            self.session.headers["X-Consul-Token"] = cfg.consul_token

    @property
    def lock_ttl_seconds(self) -> int:
        return 30

    @property
    def _registry_url(self) -> str:
        return f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_gc_path}{self.cfg.dns_provider_name}-active-config"

    def provider_lock(self) -> ConsulProviderLock:
        lock_key = f"{self.cfg.consul_gc_path.rstrip('/')}/locks/{self.cfg.dns_provider_name}"
        return ConsulProviderLock(
            self.session, self.cfg.consul_addr, lock_key, self.cfg.dns_provider_name,
            ttl_seconds=self.lock_ttl_seconds, renew_interval_seconds=10, lock_delay_seconds=5,
        )

    def load_active_records(self) -> Tuple[List[Dict[str, str]], str, bool]:
        """Read and validate the current ownership registry."""
        try:
            response = self.session.get(self._registry_url, timeout=5)
            if response.status_code == 404:
                self.log.info("The ownership registry is empty (first run).")
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
            self.log.warning(
                "Failed to read the ownership registry: %s. "
                "Provider changes and registry writes are disabled.",
                error,
            )
            return [], "N/A (Consul API read error)", False

    def desired_record(self, zone_name: str, backend: str,
                       record_name: str) -> Tuple[Hashable, Dict[str, Any]]:
        """Return (duplicate key, desired record) for one record of the desired configuration."""
        raise NotImplementedError

    def load_desired_records(self) -> Tuple[List[Dict[str, Any]], bool]:
        """Read this provider's records from the desired YAML configuration."""
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_config_path}"
        field = self.zone_backend_field
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 404:
                self.log.error(
                    "The desired YAML configuration is missing from KV at %s; GC is disabled",
                    self.cfg.consul_config_path,
                )
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
                backend = zone.get(field)
                zone_records = zone.get("records")
                if not zone_name or not backend or not isinstance(zone_records, list):
                    raise ValueError(f"zones[{zone_index}]: zone_name, {field}, and records are required")
                for record_index, record in enumerate(zone_records):
                    if not isinstance(record, dict) or record.get("name") is None:
                        raise ValueError(
                            f"zones[{zone_index}].records[{record_index}]: name is required; "
                            "use @ for the zone apex"
                        )
                    duplicate_key, desired = self.desired_record(
                        str(zone_name), str(backend), str(record["name"])
                    )
                    if duplicate_key in seen:
                        raise ValueError(f"duplicate record in the desired configuration: {duplicate_key}")
                    seen.add(duplicate_key)
                    records.append(desired)
            return records, True
        except (requests.RequestException, ValueError, KeyError, yaml.YAMLError) as error:
            self.log.error("Failed to read the desired YAML configuration from KV; GC is disabled: %s", error)
            return [], False

    def save_active_records(self, ownership_records: List[Dict[str, Any]]) -> None:
        """Save the minimal ownership registry; called only by the lock holder."""
        payload = json.dumps(
            registry_payload(ownership_records),
            indent=2,
            ensure_ascii=False,
        )
        response = self.session.put(self._registry_url, data=payload, timeout=5)
        response.raise_for_status()
        self.log.info("The ownership registry (GC registry) was updated in Consul KV")


# --------------------------------------------------------------------------- #
# Synchronization flow                                                        #
# --------------------------------------------------------------------------- #
class ProviderBackend:
    """Provider-specific operations used by run_sync()."""

    def identity_for_item(self, item: Dict[str, Any]) -> Dict[str, str]:
        """Build the ownership identity of a rendered-state item or desired record."""
        raise NotImplementedError

    def group_key(self, item: Dict[str, Any]) -> Optional[Hashable]:
        """Return the unit read with one list call, or None when the item lacks provider fields."""
        raise NotImplementedError

    def describe_group(self, group: Any) -> str:
        raise NotImplementedError

    def orphan_item(self, identity: Dict[str, str]) -> Dict[str, Any]:
        """Build an item that removes an owned record absent from the desired configuration."""
        raise NotImplementedError

    def connect(self) -> None:
        """Prepare the provider client; called once, only when a change may be required."""
        raise NotImplementedError

    def list_records(self, group: Any) -> Any:
        raise NotImplementedError

    def reconcile_one(self, item: Dict[str, Any], decision: Decision,
                      index: Any, allow_delete: bool) -> bool:
        """Apply the decision; return True when the provider was changed."""
        raise NotImplementedError

    def verified(self, index: Any, item: Dict[str, Any], decision: Decision) -> Tuple[bool, bool]:
        """Return (desired record is present, record is absent) according to the index."""
        raise NotImplementedError


@dataclass(frozen=True)
class _Planned:
    item: Dict[str, Any]
    identity: Dict[str, str]
    decision: Decision


def run_sync(src: str, state_store: Any, backend: ProviderBackend,
             logger: logging.Logger = log) -> int:
    """Reconcile the rendered state with the DNS provider under the provider lock."""
    try:
        with state_store.provider_lock() as provider_lock:
            provider_lock.assert_held()
            logger.info("Provider lock acquired; reading the current rendered state from %s", src)
            items = load_items(src)

            previous_records, last_updated_at, previous_known = state_store.load_active_records()
            current_desired, desired_known = state_store.load_desired_records()
            logger.info("Ownership registry read; previous update time: %s", last_updated_at)
            if not previous_known or not desired_known:
                logger.error(
                    "The ownership registry or desired configuration is unavailable: "
                    "provider synchronization and all DNS changes are disabled"
                )
                return 1

            owned = {identity_key(identity): identity for identity in previous_records}
            desired_keys = {
                identity_key(backend.identity_for_item(record)) for record in current_desired
            }
            groups: Dict[Hashable, List[_Planned]] = defaultdict(list)

            for item in items:
                group = backend.group_key(item)
                if group is None:
                    continue
                identity = backend.identity_for_item(item)
                if identity_key(identity) in desired_keys:
                    groups[group].append(_Planned(item, identity, decide(item)))

            # Owned records that left the desired configuration are removed.
            for key in sorted(set(owned) - desired_keys):
                item = backend.orphan_item(owned[key])
                groups[backend.group_key(item)].append(_Planned(item, owned[key], decide(item)))

            if not groups:
                logger.info("No records to synchronize; saving the known empty ownership registry")
                provider_lock.assert_held()
                state_store.save_active_records(list(owned.values()))
                return 0

            if all(planned.decision.action == "keep" for values in groups.values() for planned in values):
                for values in groups.values():
                    for planned in values:
                        fqdn = planned.identity["fqdn"]
                        logger.info(
                            "[%s] %s %s: keeping the current record -- %s",
                            planned.item.get("service_name", fqdn),
                            fqdn,
                            planned.identity["record_type"],
                            planned.decision.explanation,
                        )
                logger.info("All decisions are keep; the DNS provider will not be queried")
                return 0

            provider_lock.assert_held()
            backend.connect()
            errors = 0
            safely_skipped = 0

            for group, planned_records in groups.items():
                try:
                    before = backend.list_records(group)
                except Exception as error:
                    logger.error("Failed to read records for %s: %s", backend.describe_group(group), error)
                    errors += len(planned_records)
                    continue

                attempted: List[Tuple[_Planned, bool]] = []
                needs_readback = False
                for planned in planned_records:
                    service_name = planned.item.get("service_name")
                    allow_delete = identity_key(planned.identity) in owned
                    try:
                        provider_lock.assert_held()
                        if backend.reconcile_one(planned.item, planned.decision, before, allow_delete):
                            needs_readback = True
                        attempted.append((planned, allow_delete))
                    except OwnershipBlocked as reason:
                        logger.warning("[%s] safely skipping record: %s", service_name, reason)
                        safely_skipped += 1
                    except Exception as error:
                        logger.error("[%s] failed to apply changes: %s", service_name, error)
                        errors += 1

                after = before
                if needs_readback:
                    try:
                        provider_lock.assert_held()
                        after = backend.list_records(group)
                    except Exception as error:
                        logger.error("Failed to verify state for %s: %s", backend.describe_group(group), error)
                        errors += len(attempted)
                        continue

                for planned, allow_delete in attempted:
                    decision = planned.decision
                    if decision.action == "remove" and not allow_delete:
                        continue
                    present, absent = backend.verified(after, planned.item, decision)
                    _, transition_error = transition_ownership(
                        owned, planned.identity, decision.action, present, absent
                    )
                    if transition_error:
                        logger.error(
                            "[%s] record ownership was not confirmed: %s",
                            planned.item.get("service_name"), transition_error,
                        )
                        errors += 1

            if safely_skipped:
                logger.warning(
                    "Safely skipped unconfirmed records: %d. "
                    "DNS was not changed; waiting for the next rendered-state update.",
                    safely_skipped,
                )
            if errors:
                logger.error(
                    "Synchronization completed with errors (%d); "
                    "only confirmed ownership-registry changes are saved",
                    errors,
                )
            return finish_ownership_sync(state_store, provider_lock, owned, True, True, errors)
    except (OSError, json.JSONDecodeError, ValueError, requests.RequestException, RuntimeError) as error:
        logger.error("DNS synchronization failed: %s", error)
        return 1

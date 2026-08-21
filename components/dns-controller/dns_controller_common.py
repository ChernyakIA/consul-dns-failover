"""Shared functions for DNS Manager scripts."""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

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

"""End-to-end synchronization flow of both DNS managers against an in-memory DNS backend."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from conftest import load_module

ZONE = "example.com"
IP = "192.0.2.10"
PROVIDERS = {
    "selectel": {
        "path": "components/dns-controller/dns-failover-manager-selectel.py",
        "provider": "selecteldns",
        "zone_field": "sel_zone_id",
        "zone_value": "zone-1",
    },
    "windns": {
        "path": "components/dns-controller/dns-failover-manager-windns.py",
        "provider": "windns",
        "zone_field": "win_dns_server",
        "zone_value": "dc1.example.com",
    },
    "yandex": {
        "path": "components/dns-controller/dns-failover-manager-yandex.py",
        "provider": "yandexdns",
        "zone_field": "yc_zone_id",
        "zone_value": "dns-zone-1",
    },
}


class FakeDns:
    """One zone held in memory as {relative name: (ttl, ips)}; implements both provider clients."""

    def __init__(self, records=None, fail_list=False):
        self.records = dict(records or {})
        self.fail_list = fail_list
        self.calls = []

    def _list(self):
        if self.fail_list:
            raise RuntimeError("backend is down")

    # Selectel client
    def list_rrsets(self, zone_id):
        self._list()
        return {
            (f"{name}.{ZONE}", "A"): {"id": name, "ttl": ttl, "records": [{"content": ip} for ip in ips]}
            for name, (ttl, ips) in self.records.items()
        }

    def create(self, zone_id, fqdn, rtype, ttl, ips):
        self.calls.append("create")
        self.records[fqdn.split(".")[0]] = (ttl, list(ips))

    def patch(self, zone_id, rrset_id, ttl, ips):
        self.calls.append("update")
        self.records[rrset_id] = (ttl, list(ips))

    def delete(self, zone_id, rrset_id):
        self.calls.append("delete")
        del self.records[rrset_id]

    # Yandex Cloud client
    def list_record_sets(self, zone_id):
        self._list()
        return {
            (f"{name}.{ZONE}", "A"): {"name": f"{name}.{ZONE}.", "type": "A", "ttl": str(ttl), "data": list(ips)}
            for name, (ttl, ips) in self.records.items()
        }

    def add_record_set(self, zone_id, fqdn, ttl, ips):
        self.calls.append("create")
        self.records[fqdn.split(".")[0]] = (ttl, list(ips))

    def replace_record_set(self, zone_id, fqdn, ttl, ips):
        self.calls.append("update")
        self.records[fqdn.split(".")[0]] = (ttl, list(ips))

    def delete_record_set(self, zone_id, record_set):
        self.calls.append("delete")
        del self.records[record_set["name"].split(".")[0]]

    # WinDNS client
    def list_a_records(self, dns_server, zone):
        self._list()
        return {name: {"ttl": ttl, "ips": sorted(ips)} for name, (ttl, ips) in self.records.items()}

    def create_a(self, dns_server, zone, name, ttl, ips):
        self.calls.append("create")
        self.records[name] = (ttl, list(ips))

    def replace_a(self, dns_server, zone, name, ttl, ips):
        self.calls.append("update")
        self.records[name] = (ttl, list(ips))

    def delete_a(self, dns_server, zone, name):
        self.calls.append("delete")
        del self.records[name]


class Lock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def assert_held(self):
        return None


class Store:
    def __init__(self, registry, desired):
        self.registry = registry
        self.desired = desired
        self.saved = []

    def provider_lock(self):
        return Lock()

    def load_active_records(self):
        return list(self.registry), "never", True

    def load_desired_records(self):
        return list(self.desired), True

    def save_active_records(self, records):
        self.saved.append(sorted(record["fqdn"] for record in records))


@pytest.fixture(params=sorted(PROVIDERS))
def sync(request, monkeypatch, tmp_path):
    spec = PROVIDERS[request.param]
    module = load_module(f"test_sync_flow_{request.param}", spec["path"])
    cfg = SimpleNamespace(dns_provider_name=spec["provider"], account_id="account", project_name="project")

    def record(name):
        return {"record": name, "zone": ZONE, spec["zone_field"]: spec["zone_value"]}

    def state(name, observed=1, confirmed=1):
        return {
            **record(name),
            "service_name": f"dns-failover-{name}",
            "ttl": "60",
            "quorum": 1,
            "minimum_observers": 1,
            "on_all_fail": "keep",
            "candidates": [IP],
            "observations": {IP: observed},
            "confirmations": {IP: confirmed},
        }

    def run(*, owned=(), desired=("app",), states=(), dns):
        store = Store(
            [module.identity_for_item(cfg, record(name)) for name in owned],
            [record(name) for name in desired],
        )
        monkeypatch.setattr(module.Config, "from_env", staticmethod(lambda: cfg))
        monkeypatch.setattr(module, "ConsulStateStore", lambda cfg: store)
        if request.param == "selectel":
            monkeypatch.setattr(module, "SelectelDNS", lambda cfg, token: dns)
            monkeypatch.setattr(module, "get_iam_token", lambda cfg: "token")
        elif request.param == "yandex":
            monkeypatch.setattr(module, "YandexDNS", lambda cfg, token: dns)
            monkeypatch.setattr(module, "get_iam_token", lambda cfg: "token")
        else:
            monkeypatch.setattr(module, "WinDNS", lambda cfg: dns)
        path = tmp_path / "service-state.json"
        path.write_text(json.dumps(list(states)))
        monkeypatch.setattr(module.sys, "argv", ["dns-manager", str(path)])
        return module.main(), store

    return SimpleNamespace(run=run, state=state)


def test_missing_record_is_created_and_becomes_owned(sync):
    dns = FakeDns()
    code, store = sync.run(states=[sync.state("app")], dns=dns)

    assert code == 0
    assert dns.calls == ["create"]
    assert dns.records == {"app": (60, [IP])}
    assert store.saved == [[f"app.{ZONE}"]]


def test_identical_existing_record_is_adopted_without_changes(sync):
    dns = FakeDns({"app": (60, [IP])})
    code, store = sync.run(states=[sync.state("app")], dns=dns)

    assert code == 0
    assert dns.calls == []
    assert store.saved == [[f"app.{ZONE}"]]


def test_foreign_record_that_differs_is_not_overwritten(sync):
    dns = FakeDns({"app": (60, ["198.51.100.1"])})
    code, store = sync.run(states=[sync.state("app")], dns=dns)

    assert code == 0
    assert dns.calls == []
    assert dns.records == {"app": (60, ["198.51.100.1"])}
    assert store.saved == [[]]


def test_owned_record_is_updated(sync):
    dns = FakeDns({"app": (300, ["198.51.100.1"])})
    code, store = sync.run(owned=["app"], states=[sync.state("app")], dns=dns)

    assert code == 0
    assert dns.calls == ["update"]
    assert dns.records == {"app": (60, [IP])}
    assert store.saved == [[f"app.{ZONE}"]]


def test_orphaned_owned_record_is_removed_while_others_are_kept(sync):
    dns = FakeDns({"old": (60, [IP]), "app": (60, [IP])})
    code, store = sync.run(
        owned=["old", "app"], states=[sync.state("app", observed=0, confirmed=0)], dns=dns,
    )

    assert code == 0
    assert dns.calls == ["delete"]
    assert dns.records == {"app": (60, [IP])}
    assert store.saved == [[f"app.{ZONE}"]]


def test_state_for_record_absent_from_desired_config_is_ignored(sync):
    dns = FakeDns()
    code, store = sync.run(states=[sync.state("app"), sync.state("stray")], dns=dns)

    assert code == 0
    assert dns.records == {"app": (60, [IP])}
    assert store.saved == [[f"app.{ZONE}"]]


def test_backend_read_failure_is_an_error_and_keeps_the_registry(sync):
    dns = FakeDns(fail_list=True)
    code, store = sync.run(owned=["app"], states=[sync.state("app")], dns=dns)

    assert code == 1
    assert dns.calls == []
    assert store.saved == [[f"app.{ZONE}"]]


def test_all_keep_does_not_touch_backend_or_registry(sync):
    dns = FakeDns(fail_list=True)
    code, store = sync.run(states=[sync.state("app", observed=0, confirmed=0)], dns=dns)

    assert code == 0
    assert store.saved == []

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import ROOT, load_module


@pytest.fixture
def manager():
    return load_module(
        "test_monitoring_manager",
        "components/monitoring-controller/dns-failover-service-manager.py",
    )


def config(manager, site="site-a"):
    return manager.Config(
        site=site,
        node_name="node-a",
        scope_tag=f"daemon-site-{site}-node-node-a",
        service_name_prefix="dns-failover",
        consul_addr="http://127.0.0.1:8500",
        consul_http_token=None,
        consul_cacert=None,
        consul_auto_encrypt_ca_addr=None,
        consul_ca_bundle_pem=None,
        consul_kv_path="dns-failover/config.yml",
        blocking_wait="5m",
        managed_tag="dns-failover-managed",
        http_timeout_blocking=330,
        heartbeat_interval=3600,
    )


def test_documented_example_is_valid_and_site_filtered(manager):
    text = (ROOT / "config/monitoring.example.yml").read_text()
    desired = manager.parse_desired_state(text, config(manager, "site-a"))

    assert len(desired) == 1
    service = next(item for item in desired.values() if item.address == "192.0.2.20")
    assert service.check_proto == "http"
    assert service.check["url"] == "http://192.0.2.20:8080/healthz"
    assert service.meta["minimum_observers"] == "2"
    assert service.to_payload()["Check"]["Status"] == "warning"


def test_invalid_quorum_is_rejected(manager):
    text = """
defaults:
  check: {interval: 15s, timeout: 5s}
  quorum: 2
zones:
  - zone_name: example.com
    dns_provider: selecteldns
    records:
      - name: app
        endpoints:
          - ip: 192.0.2.10
            uplink_provider: provider-a
            owner_site: site-b
            sites: [site-a]
            check: {kind: icmp}
"""
    with pytest.raises(manager.InvalidDesiredState, match="quorum=2"):
        manager.parse_desired_state(text, config(manager))


def test_duration_parser_supports_documented_units(manager):
    assert manager._parse_duration("500ms") == 0.5
    assert manager._parse_duration("2m") == 120.0


def test_http_check_without_url_requires_port(manager):
    text = """
defaults:
  check: {interval: 15s, timeout: 5s}
  quorum: 1
zones:
  - zone_name: example.com
    dns_provider: selecteldns
    records:
      - name: app
        endpoints:
          - ip: 192.0.2.10
            uplink_provider: provider-a
            owner_site: site-b
            sites: [site-a]
            check: {kind: http, target: 192.0.2.10}
"""
    with pytest.raises(manager.InvalidDesiredState, match="check.port"):
        manager.parse_desired_state(text, config(manager))


TWO_ENDPOINTS = """
defaults:
  check: {{interval: {interval}, timeout: 5s}}
  quorum: 1
zones:
  - zone_name: example.com
    dns_provider: selecteldns
    records:
      - name: app
        endpoints:
          - ip: 192.0.2.10
            uplink_provider: provider-a
            owner_site: site-b
            sites: [site-a]
            check: {{kind: tcp, port: 443}}
          - ip: 192.0.2.20
            uplink_provider: provider-b
            owner_site: site-b
            sites: [site-a]
            check: {{kind: tcp, port: 443, interval: 30s}}
"""


def test_active_checks_restart_only_changed_workers(manager, monkeypatch):
    def idle(self):
        self.stop_event.wait()

    monkeypatch.setattr(manager.ActiveCheckWorker, "_run", idle)
    cfg = config(manager)
    checks = manager.ActiveCheckSet(manager.ConsulClient(cfg))

    def by_address(desired):
        return {item.address: sid for sid, item in desired.items()}

    try:
        first = manager.parse_desired_state(TWO_ENDPOINTS.format(interval="15s"), cfg)
        checks.replace(first)
        ids = by_address(first)
        changed_before = checks.workers[ids["192.0.2.10"]]
        unchanged_before = checks.workers[ids["192.0.2.20"]]

        # Only the first endpoint inherits defaults.check.interval.
        second = manager.parse_desired_state(TWO_ENDPOINTS.format(interval="20s"), cfg)
        checks.replace(second)

        assert checks.workers[ids["192.0.2.20"]] is unchanged_before
        assert unchanged_before.thread.is_alive()
        assert checks.workers[ids["192.0.2.10"]] is not changed_before
        assert not changed_before.thread.is_alive()
        assert checks.workers[ids["192.0.2.10"]].desired.interval_seconds == 20.0

        del second[ids["192.0.2.20"]]
        checks.replace(second)
        assert set(checks.workers) == {ids["192.0.2.10"]}
        assert not unchanged_before.thread.is_alive()
    finally:
        checks.stop()
    assert checks.workers == {}


def test_icmp_pass_output_does_not_depend_on_round_trip_time(manager, monkeypatch):
    from types import SimpleNamespace

    text = """
defaults:
  check: {interval: 15s, timeout: 5s}
  quorum: 1
zones:
  - zone_name: example.com
    dns_provider: selecteldns
    records:
      - name: app
        endpoints:
          - ip: 192.0.2.10
            uplink_provider: provider-a
            owner_site: site-b
            sites: [site-a]
            check: {kind: icmp}
"""
    (service,) = manager.parse_desired_state(text, config(manager)).values()
    replies = iter([
        SimpleNamespace(returncode=0, stdout="rtt min/avg/max/mdev = 0.045/0.045/0.045/0.000 ms\n", stderr=""),
        SimpleNamespace(returncode=0, stdout="rtt min/avg/max/mdev = 1.310/1.310/1.310/0.000 ms\n", stderr=""),
        SimpleNamespace(returncode=1, stdout="1 packets transmitted, 0 received, 100% packet loss, time 0ms\n", stderr=""),
    ])
    monkeypatch.setattr(manager.subprocess, "run", lambda *args, **kwargs: next(replies))

    first = manager._execute_check(service)
    second = manager._execute_check(service)
    failed = manager._execute_check(service)

    assert first == second == (manager.CheckResult.PASS, "ICMP 192.0.2.10 reachable")
    assert failed[0] is manager.CheckResult.FAIL
    assert "100% packet loss" in failed[1]

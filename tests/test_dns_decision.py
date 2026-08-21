from __future__ import annotations

import pytest

from conftest import load_module


@pytest.fixture(params=[
    ("selectel", "components/dns-controller/dns-failover-manager-selectel.py"),
    ("windns", "components/dns-controller/dns-failover-manager-windns.py"),
])
def controller(request):
    name, path = request.param
    return load_module(f"test_{name}_controller", path)


def test_unknown_state_keeps_dns_unchanged(controller):
    item = {
        "candidates": ["192.0.2.10", "192.0.2.20"],
        "observations": {"192.0.2.10": 2, "192.0.2.20": 1},
        "confirmations": {"192.0.2.10": 2, "192.0.2.20": 0},
        "quorum": 2,
        "minimum_observers": 2,
        "on_all_fail": "remove",
    }
    decision = controller.decide(item)
    assert (decision.action, decision.ips) == ("keep", [])


def test_quorum_sets_only_confirmed_candidates(controller):
    item = {
        "candidates": ["192.0.2.20", "192.0.2.10"],
        "observations": {"192.0.2.10": 3, "192.0.2.20": 3},
        "confirmations": {"192.0.2.10": 2, "192.0.2.20": 1},
        "quorum": 2,
        "minimum_observers": 2,
    }
    decision = controller.decide(item)
    assert (decision.action, decision.ips) == ("set", ["192.0.2.10"])


def test_all_failed_uses_fallback(controller):
    item = {
        "candidates": ["192.0.2.10"],
        "observations": {"192.0.2.10": 2},
        "confirmations": {"192.0.2.10": 0},
        "quorum": 2,
        "minimum_observers": 2,
        "on_all_fail": "fallback",
        "fallback_ip": "192.0.2.100",
    }
    decision = controller.decide(item)
    assert (decision.action, decision.ips) == ("set", ["192.0.2.100"])


def test_all_failed_can_remove_record(controller):
    item = {
        "candidates": ["192.0.2.10"],
        "observations": {"192.0.2.10": 2},
        "confirmations": {"192.0.2.10": 0},
        "quorum": 2,
        "minimum_observers": 2,
        "on_all_fail": "remove",
    }
    decision = controller.decide(item)
    assert (decision.action, decision.ips) == ("remove", [])

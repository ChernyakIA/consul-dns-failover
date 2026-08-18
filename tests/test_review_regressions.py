from __future__ import annotations

import base64
from dataclasses import replace

import pytest

from conftest import ROOT, load_module


class Response:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class Session:
    def __init__(self, payload=None, put_error=None):
        self.payload = payload
        self.put_error = put_error
        self.verify = True
        self.headers = {}

    def get(self, *args, **kwargs):
        return Response(self.payload)

    def put(self, *args, **kwargs):
        if self.put_error:
            raise self.put_error
        return Response({})


@pytest.fixture(params=["selectel", "windns"])
def state_store(request):
    if request.param == "selectel":
        module = load_module("test_selectel_state", "components/dns-controller/dns-failover-manager-selectel.py")
        cfg = module.Config(
            account_id="account", service_user="user", service_pass="password",
            project_name="project", consul_gc_path="dns-failover/gc/",
            auth_url="https://identity.example.com", dns_api_base="https://dns.example.com",
            page_limit=40, http_connect_timeout=5, http_read_timeout=15,
            http_retry_total=2, consul_addr="https://consul.example.com",
            consul_token=None, consul_cacert=None,
            consul_config_path="dns-failover/config.yml", dns_provider_name="selecteldns",
        )
        invalid = """zones:
  - dns_provider: selecteldns
    records:
      - name: app
"""
    else:
        module = load_module("test_windns_state", "components/dns-controller/dns-failover-manager-windns.py")
        cfg = module.Config(
            ssh_host="dns.example.com", ssh_user="EXAMPLE\\dns-failover",
            consul_gc_path="dns-failover/gc/", ssh_port=22, ssh_password=None,
            ssh_key_path="/keys/id", ssh_known_hosts="/etc/ssh/known_hosts",
            insecure_skip_host_key_check=False, connect_timeout=10, cmd_timeout=60,
            consul_addr="https://consul.example.com", consul_token=None,
            consul_cacert=None, consul_config_path="dns-failover/config.yml",
            dns_provider_name="windns",
        )
        invalid = """zones:
  - dns_provider: windns
    records:
      - name: app
"""
    return module, module.ConsulStateStore(cfg), invalid


def test_incomplete_desired_state_disables_gc(state_store):
    module, store, invalid = state_store
    encoded = base64.b64encode(invalid.encode()).decode()
    store.session = Session([{"Value": encoded}])
    records, desired_known = store.load_desired_records()
    assert records == []
    assert desired_known is False


def test_registry_write_failure_is_reported(state_store):
    module, store, _ = state_store
    store.session = Session(put_error=module.requests.ConnectionError("down"))
    assert store.save_active_records([]) is False


def test_check_timing_changes_config_hash():
    manager = load_module(
        "test_monitoring_hash",
        "components/monitoring-controller/dns-failover-service-manager.py",
    )
    cfg = manager.Config(
        site="site-a", node_name="node-a", scope_tag="daemon-site-site-a-node-node-a",
        service_name_prefix="dns-failover", consul_addr="http://127.0.0.1:8500",
        consul_http_token=None, consul_cacert=None, consul_auto_encrypt_ca_addr=None,
        consul_ca_bundle_pem=None, consul_kv_path="dns-failover/config.yml",
        blocking_wait="5m", managed_tag="dns-failover-managed",
        http_timeout_blocking=330, heartbeat_interval=3600,
    )
    desired = manager.parse_desired_state((ROOT / "config/monitoring.example.yml").read_text(), cfg)
    service = next(iter(desired.values()))
    assert service.config_hash() != replace(service, interval_seconds=service.interval_seconds + 1).config_hash()


def test_example_overlay_preserves_observability_namespace():
    overlay = __import__("yaml").safe_load((ROOT / "deploy/k8s/overlays/example/kustomization.yml").read_text())
    alerts = __import__("yaml").safe_load((ROOT / "deploy/k8s/base/observability/loki-alert-rules-cm.yml").read_text())
    assert "namespace" not in overlay
    assert alerts["metadata"]["namespace"] == "monitoring"


def test_documented_config_is_valid_for_every_site():
    manager = load_module(
        "test_monitoring_all_sites",
        "components/monitoring-controller/dns-failover-service-manager.py",
    )
    source = (ROOT / "config/monitoring.example.yml").read_text()
    for site in ("site-a", "site-b", "site-c"):
        cfg = manager.Config(
            site=site, node_name=f"node-{site}",
            scope_tag=f"daemon-site-{site}-node-node-{site}",
            service_name_prefix="dns-failover", consul_addr="http://127.0.0.1:8500",
            consul_http_token=None, consul_cacert=None, consul_auto_encrypt_ca_addr=None,
            consul_ca_bundle_pem=None, consul_kv_path="dns-failover/config.yml",
            blocking_wait="5m", managed_tag="dns-failover-managed",
            http_timeout_blocking=330, heartbeat_interval=3600,
        )
        assert manager.parse_desired_state(source, cfg)


def test_selectel_orphan_record_keeps_zone_text_inside_relative_name():
    module = load_module(
        "test_selectel_relative_name",
        "components/dns-controller/dns-failover-manager-selectel.py",
    )
    assert module.relative_record_name(
        "foo.example.com.example.com", "example.com"
    ) == "foo.example.com"
    assert module.relative_record_name("example.com", "example.com") == "@"
    assert module.relative_record_name("foo.example.com", "Example.COM") == "foo"

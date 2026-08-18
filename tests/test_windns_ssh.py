from conftest import load_module


def test_ssh_host_key_verification_is_strict_by_default():
    module = load_module(
        "test_windns_ssh_controller",
        "components/dns-controller/dns-failover-manager-windns.py",
    )
    cfg = module.Config(
        ssh_host="dns01.internal.example.com",
        ssh_user="EXAMPLE\\dns-failover",
        consul_gc_path="dns-failover/gc/",
        ssh_port=22,
        ssh_password=None,
        ssh_key_path="/keys/id_ed25519",
        ssh_known_hosts="/etc/ssh/known_hosts",
        insecure_skip_host_key_check=False,
        connect_timeout=10,
        cmd_timeout=60,
        consul_addr="https://consul-server.consul.svc:8501",
        consul_token=None,
        consul_cacert="/consul/tls/ca/tls.crt",
        consul_config_path="dns-failover/config.yml",
        dns_provider_name="windns",
    )

    argv = module.WinDNS(cfg)._ssh_argv("encoded")
    joined = " ".join(argv)
    assert "StrictHostKeyChecking=yes" in joined
    assert "UserKnownHostsFile=/etc/ssh/known_hosts" in joined
    assert "StrictHostKeyChecking=no" not in joined

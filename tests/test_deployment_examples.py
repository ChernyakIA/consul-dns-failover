from pathlib import Path

import yaml

from conftest import ROOT


def test_dns_controller_manifest_passes_consul_address_to_both_containers():
    config = yaml.safe_load(
        (ROOT / "deploy/k8s/base/dns-manager/consul-template-config-cm.yml").read_text()
    )
    deployment = yaml.safe_load(
        (ROOT / "deploy/k8s/base/dns-manager/dns-manager-deploy.yml").read_text()
    )

    assert config["data"]["CONSUL_HTTP_ADDR"].startswith("https://")
    for container in deployment["spec"]["template"]["spec"]["containers"]:
        env = {item["name"]: item for item in container["env"]}
        source = env["CONSUL_HTTP_ADDR"]["valueFrom"]["configMapKeyRef"]
        assert source == {"name": "dns-manager-config", "key": "CONSUL_HTTP_ADDR"}

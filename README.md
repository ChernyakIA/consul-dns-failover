# Consul DNS Failover

[![CI](https://github.com/ChernyakIA/consul-dns-failover/actions/workflows/ci.yml/badge.svg)](https://github.com/ChernyakIA/consul-dns-failover/actions/workflows/ci.yml)
[![Release images](https://github.com/ChernyakIA/consul-dns-failover/actions/workflows/release.yml/badge.svg)](https://github.com/ChernyakIA/consul-dns-failover/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/ChernyakIA/consul-dns-failover)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/ChernyakIA/consul-dns-failover)](https://github.com/ChernyakIA/consul-dns-failover/releases)

Distributed health checking and automated DNS A-record reconciliation built on HashiCorp Consul.

The system observes each endpoint from multiple independent sites, distinguishes a confirmed outage from missing monitoring data, and changes DNS only after the configured quorum has been reached. It supports Selectel DNS and Microsoft DNS over SSH/PowerShell.

> [!WARNING]
> This software can create, replace, and delete DNS records. Test with delegated zones, keep `on_all_fail: keep` during rollout, use least-privilege credentials, and never run two controllers for the same provider and zone set.

## How it works

```text
Consul KV (desired YAML)
        |
        v
monitoring-controller on every site
  active ICMP/TCP/HTTP/SMTP checks
        |
        v
Consul Catalog + TTL checks + site metadata
        |
        v
consul-template -> aggregated JSON snapshot
        |
        +--> Selectel DNS reconciler
        `--> Microsoft DNS reconciler over SSH
```

| Image | Purpose |
| --- | --- |
| `ghcr.io/chernyakia/consul-dns-failover-monitoring-controller` | Reads desired state from Consul KV, runs active checks and publishes TTL state to the local Consul agent. |
| `ghcr.io/chernyakia/consul-dns-failover-dns-controller` | Renders Catalog state and reconciles Selectel or Microsoft DNS. |

## Safety model

1. Results are deduplicated by `site`; multiple agents in one site produce at most one vote.
2. Fewer than `minimum_observers` valid site results means **unknown** and DNS is left unchanged.
3. Candidates with at least `quorum` confirmations are published.
4. If no candidate reaches quorum, `on_all_fail` selects `keep`, `remove`, or `fallback`.

| Check result | Consul TTL state | DNS meaning |
| --- | --- | --- |
| `PASS` | `passing` after the success threshold | observation and confirmation |
| `FAIL` | `warning`, then `critical` after failure thresholds | observation without confirmation |
| `ERROR` | `warning` | no valid observation; a broken checker is not an outage |

The DNS controller keeps a provider-specific managed-record registry in Consul KV. Garbage collection is disabled whenever the previous registry or current desired configuration cannot be read, preventing a transient Consul/TLS/ACL error from becoming a mass deletion.

## Repository layout

```text
components/
  monitoring-controller/  active checks and Consul reconciliation
  dns-controller/         provider reconcilers and consul-template template
config/                    documented desired-state example
deploy/                    Docker, Kustomize and Argo CD examples
docs/                      architecture, configuration, operations, versioning
tests/                     minimal decision and configuration tests
```

## Quick start

1. Copy `config/monitoring.example.yml` to `config/monitoring.yml`, customize it, and upload it:

   ```sh
   consul kv put dns-failover/dns-failover-monitoring-config.yml @config/monitoring.yml
   ```

2. Deploy one monitoring controller per independent site. For Docker, copy the example files under `deploy/docker/monitoring`, add the Consul CA and ACL tokens, then run:

   ```sh
   AGENT_NAME=consul-monitor-1 CONSUL_HTTP_TOKEN='<token>' \
     docker compose -f deploy/docker/monitoring/compose.yml up -d
   ```

3. Create Kubernetes secrets from `deploy/k8s/overlays/example/secrets.example.yml` outside Git, customize Consul TLS/address settings, pin an image version, and apply:

   ```sh
   kubectl apply -k deploy/k8s/overlays/example
   ```

Real secrets, CA files, live desired state, internal hostnames, and environment-specific overlays are intentionally excluded from Git.

## Documentation

- [Architecture and failure semantics](docs/architecture.md)
- [Desired state and environment variables](docs/configuration.md)
- [Deployment and operations](docs/operations.md)
- [Versioning and image tags](docs/versioning.md)
- [Security policy](SECURITY.md)

## Local checks

```sh
python -m pip install -r components/monitoring-controller/requirements.txt pytest
python -m compileall -q components
pytest
docker build components/monitoring-controller
docker build components/dns-controller
kubectl kustomize deploy/k8s/overlays/example >/dev/null
```

`CI` runs minimal checks and both image builds for pull requests and `main`. Release tags publish multi-architecture images.

## Versioning

The repository and both images share one SemVer version. Tag `v1.4.2` publishes `1.4.2`, `1.4`, `1`, and `latest`. Pin `1.4.2` or a digest in production; `latest` is for evaluation. See [versioning](docs/versioning.md).

## License

[Apache License 2.0](LICENSE).

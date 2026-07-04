# Consul DNS Failover System

A full-stack, distributed automated DNS failover and monitoring solution powered by HashiCorp Consul. This system continuously tracks critical services, performs distributed health checking, and dynamically reconciles target A records across your DNS-provider systems based on active monitoring data.

The project consists of two components:

1. **Consul Service Manager** – A declarative Python daemon that dynamically translates YAML configurations stored in Consul KV into local agent health checks.
2. **Consul DNS Manager** – An automated failover controller running inside Kubernetes that watches the service registry and updates external DNS providers.

Current DNS-provider support:

- Selectel DNS Cloud API
- Microsoft Active Directory DNS

## Content

- [End-to-End Architecture](#end-to-end-architecture)
- [Componentsn](#components)
- [Global Deployment Workflow](#global-deployment-workflow)

## End-to-End Architecture

```text
[ Consul Server KV / YAML Configuration ]
        │
        │ (Long-Polling / Blocking Query)
        ▼
[ consul-service-manager ] (Runs on edge sites/hosts)
        │
        ├── 1. Filters monitoring targets by 'SITE' env
        ├── 2. Computes 'config_hash' to identify drift
        └── 3. Registers endpoint checks via HTTP API
        ▼
[ Local Consul Agent ] (Executes ICMP, HTTP, TCP, SMTP checks)
        │
        │ (Syncs service status & metadata)
        ▼
[ Consul Service Registry ]
        │
        │ (Consul Template watch index & serfHealth status)
        ▼
[ consul-dns-manager ] (Runs centrally inside Kubernetes)
        │
        ├── 1. Evaluates metadata (ttl, quorum, on_all_fail)
        ├── 2. Renders unified target state to JSON
        └── 3. Triggers provider-specific script
        ▼
[ DNS-Providers (Selectel Cloud API / MS Active Directory) ]
```

## Components

1. Consul Service Manager
Designed to run alongside your edge nodes. It dynamically translates YAML configuration into local Consul host health checks, talking directly to the local Consul Agent's HTTP API (/v1/agent/service) to keep checks in sync and detect configuration drift.

    [Consul Service Manager Documentation](consul-service-manager/README.md)

2. Consul DNS Manager
A Kubernetes-native failover manager. It evaluates service metrics extracting Consul Service Metadata (like on_all_fail, quorum, agents_alive), automatically filters active service IPs, and triggers provider scripts based on operational state shifts via a Reconciliation Loop.

    [Consul DNS Manager Documentation](consul-dns-manager/README.md)

## Global Deployment Workflow

To bring up the entire system, follow this.

1. Initialize Global State:
Push your monitoring configuration (e.g., example-dns-failover-monitoring-config.yml) to Consul Server KV under the assigned path.

2. Deploy Edge Daemons (Service Managers):
Setup the Consul Agent and service manager daemon by docker compose on your target edge nodes.
(See [component doc](consul-service-manager/README.md) for manifests details and routing logic).

3. Deploy DNS Controller (Kubernetes):
Configure your DNS provider credentials (e.g., Selectel API tokens, Windows AD SSH creds) within the Kubernetes secrets, adjust the ConfigMap, and apply the deployment manifests to your K8s cluster.
(See [component doc](consul-dns-manager/README.md) for manifests details and routing logic).

## Alerts

The `consul-dns-manager/alerts/loki-alertmanager-alerts.yml` file contains alerting rules for Grafana Alertmanager.

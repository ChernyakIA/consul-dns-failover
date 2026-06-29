# Consul Service Manager

A declarative Python daemon that dynamically translates YAML-config with monitoring configuration stored in Consul KV into local Consul host health checks.
It's designed to run alongisde with Consul Agent, continiously monitoring the config state, filtering checks assigned to its `SITE` (instance name), and reconsiling the agent's service registry.

## Content

- [Architecture](#architecture)
- [Technical Prerequisites](#technical-prerequisites)
  - [Required Consul Agent Parameters](#required-consul-agent-parameters)
- [Directory Structure](#directory-structure)
- [YAML-config](#yaml-config)
- [Agent Configuration](#agent-configuration)
- [Service Manager Configuration](#service-manager-configuration)
- [Deployment](#deployment)

## Architecture

```html
[ Consul Server KV ]
        ▼
        │ (Long-Polling / Blocking Query)
        │
    [ consul-service-manager ]
        ▼
        │ 1. Filters targeted targets by 'SITE' env
        │ 2. Computes 'config_hash' fingerprints
        │ 3. Identifies configuration drift
        |
    [ Local Consul Agent ] (Via Localhost HTTP API)
        ▼
        |
        └──► Health Checking Engines
```

1. Watches Consul KV: The daemon monitors YAML-config in Consul KV using long-polling.
2. Filters Local Checks Only: It parses the config file and extracs only the endpoints that match instance specific id `SITE`.
3. Sync with Local Agent API: The daemon talks directly to the local Consul Agent's HTTP API (`/v1/agent/service`) to keep health checks in sync. It automatically registers new checks, updates modified checks and delete old (orphaned) checks from registry. It uses SHA256 `config_hash` to detect changes in YAML-config file.

## Technical Prerequisites

### Required Consul Agent Parameters

For scripted health checks to work, Agent configuration must allow such kind checks:

`agents-configs/hostname1-agent.json`:

```json
{
  "enable_local_script_checks": true,
  "enable_script_checks": true
}
```

## Directory Structure

`/agents-configs/hostname1-agent.json` -- Agent configurations.
`/service-manager-configs/hostname1.env` -- py-daemon configurations
`dns-failover-service-manager.py` -- daemon Python logic
`docker-compose.yml` -- compose manifest to run the service
`Dockefile` -- instruction to build image for service-manager daemon.
`example-dns-failover-monitoring-config.yml` -- example YAML-config for Consul KV.

## YAML-config

Stored in Consul Server KV.
Explanations of YAML-config fields:

```yml
defaults:
  check:
    interval: "15s"                   # Overridden at endpoints.[].check levels
    timeout: "5s"                     # Overridden at endpoints.[].check levels
    deregister_critical_after: "10m"  # Time elapsed before a failing ("critical") service is deregistered. Set to "0s" or "" to keep registered. Highly recommended to set this to at least 5x the threshold execution interval.
    success_before_passing: 2         # Consecutive passes required to transition a service health status from 'critical' to 'passing'
    failures_before_warning: 2        # Consecutive check timeouts/failures required to transition status from 'passing' to 'warning'
    failures_before_critical: 3       # Consecutive check timeouts/failures required to transition status from 'warning' to 'critical'
  quorum: 1                           # Binds DNS target if at least N tracking sites report the service status as 'passing'
  ttl: 60

zones:
## PROVIDER: EXTERNAL CLOUD DNS (e.g., SELECTEL)
- zone_name: "example.com"
  dns_provider: "selecteldns"         # Pick backend driver: selecteldns | windns
  sel_zone_id: "00000000-0000-0000-0000-000000000000"
  records:

  - name: "dev-test-1"
    ttl: 60
    on_all_fail: "fallback"           # Action code: keep | remove | fallback. Determines target status if all checks fail. If omitted or removed from this config, dns-manager enforces "remove".
    fallback_ip: "192.0.2.10"         # Mandatory destination address if on_all_fail is set to fallback
    endpoints:
    - ip: "198.51.100.50"
      uplink_provider: "isp-primary"  # Upstream ISP identifier. Compiled directly into consul service_id fields
      sites: ["host-a", "host-b"]     # Tracking endpoints/daemons which monitor health on targeted routes
      quorum: 2                       # (Optional) Overrides default quorum configuration for this endpoint context. Enforces confirmation constraints <= len(sites)
      check:                          # kinds: icmp -> ping execution; tcp -> {"TCP": "target:port"}; http -> {"HTTP": "uri"}. Optional: tls_skip_verify: bool, custom headers
        kind: "icmp"                  # Options: icmp (set target) / tcp (set target and port, e.g. 25 for SMTP) / http (set port, path, and method) / smtp (set target, port [defaults to 25])
        target: "203.0.113.179"       # Physical check destination (if null, defaults to resolving against the primary endpoint IP)

## PROVIDER: ACTIVE DIRECTORY / WINDOWS DNS
- zone_name: "corp.example.com"
  dns_provider: "windns"
  win_dns_server: "corp-dc-01"
  records:

  - name: "vpn"
    ttl: 60
    on_all_fail: "remove"
    endpoints:
    - ip: "192.0.2.123"
      uplink_provider: "isp-primary"
      sites: ["host-a"]
      check:
        kind: "http"
        target: "198.51.100.130"
        port: 8080
        path: "/healthz"
        method: "GET"
```

## Agent Configuration

Consul doc: <https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file>

```json
{
  "datacenter": "<FILL_THIS_FIELD>",        // name of the Consul Server
  "encrypt": "<FILL_THIS_FIELD>",           // gossyp key
  "retry_join": ["<FILL_THIS_FIELD>"],      // consul-server ip's
  "enable_local_script_checks": true,
  "log_level": "INFO",
  "client_addr": "0.0.0.0",                 // Consul will listen and respond to client operations (HTTP and DNS) on this IP address.
  "bind_addr": "0.0.0.0",                   // The address to bind to for internal cluster communications. 
  "advertise_addr": "<FILL_THIS_FIELD>",    // The advertise address is used to change the address advertised to other nodes in the cluster. By default, the bind address is advertised.
  "node_name": "<FILL_THIS_FIELD>",         // How this instance will be visible in Consul Server
  "disable_update_check": true,             // Optional
  "enable_script_checks": true              // So agent will be able to run custom shell scripts
}
```

## Service Manager Configuration

```env
SITE = host-a                               # Instance name. Used by daemon to filter health check registration
NODE_NAME = consul-manager                  # If there will be several nodes on one SITE
CONSUL_ADDR = http://127.0.0.1:8500         # Http to local Consul-Agent
CONSUL_KV_PATH = dns-failover/dns-failover-monitoring-config.yml    # Path to YAML-config in Consul KV
BLOCKING_WAIT = 5m                          # For how long works Consul Blocking Query
LOG_LEVEL = info
SERVICE_NAME_PREFIX = dns-failover          # Prefix for all services that are registered by daemon.
MANAGED_TAG = dns-failover-managed          # Service Tag
```

## Deployment

1. Build and push the Runtime Container with Dockerfile

    ```bash
    docker build -t $YOURREGISTRY/consul-service-manager:$TAG .
    docker push $YOURREGISTRY/consul-service-manager:$TAG
    ```

2. Configure Manifests and variables

    Fill in the fields marked <FILL_THIS_FIELD> within the files.

3. Deploy the stack

    Run docker compose:

    ```bash
    export HOSTNAME=$(hostname)
    docker compose up -d
    ```

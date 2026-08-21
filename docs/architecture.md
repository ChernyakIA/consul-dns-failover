# Architecture and failure semantics

## Monitoring controller

The monitoring controller runs next to a Consul client agent. It uses a blocking KV query to read YAML desired state, filters endpoints by `SITE`, validates the document, and reconciles managed services against `/v1/agent/service`. A deterministic `config_hash` detects drift without changing service IDs.

Checks are executed by Python workers; Consul receives TTL checks. This permits thresholds and explicit `PASS`/`FAIL`/`ERROR` semantics. TTL is `max(30, interval * 3 + timeout)`. Before the first result, status is `warning`. Invalid YAML leaves the previous service set running. An empty cold start cannot remove services unless `ALLOW_EMPTY_BOOTSTRAP=true`.

## DNS controller

`consul-template` watches Catalog, ignores observations from agents whose `serfHealth` is not passing, deduplicates votes by site, and writes a JSON snapshot. Provider reconcilers run when the rendered result changes.

The Selectel backend uses DNS API v2. Safe GET requests may be retried; mutating requests are not automatically retried. The Microsoft DNS backend runs encoded PowerShell over SSH. Reconciliation is idempotent: existing records are read before mutation and already-correct records are skipped.

## Site, owner site and node

- `SITE` identifies an observer and participates in quorum.
- `owner_site` is descriptive metadata and does not exclude an observer automatically.
- Consul node name is an ACL identity. TTL updates commonly need both `service:write` and matching `node:write`.

Omit an endpoint's owner from its `sites` list to avoid correlated observations. Site names are opaque strings.

## State transitions

- Success becomes `passing` at `success_before_passing`.
- Failure becomes `warning` at `failures_before_warning` and later `critical`.
- Checker `ERROR` resets streaks and publishes `warning`; it is not a negative observation.
- An expired TTL can become `critical` while the agent is healthy, so monitoring-controller availability matters.

## Unknown state and GC

DNS remains unchanged if any candidate has fewer than `minimum_observers` valid observations. Missing sites produce unknown state, not a confirmed outage.

Managed-record registries use:

```text
dns-failover/gc/selecteldns-active-config
dns-failover/gc/windns-active-config
```

A missing first-run registry is valid. A failed registry or desired-config read blocks garbage collection and registry overwrite.

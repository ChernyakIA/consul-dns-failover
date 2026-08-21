# Deployment and operations

## Kubernetes

The base runs one pod with Selectel and Microsoft DNS containers. `strategy: Recreate` prevents overlapping writers. Each container has separate `/work` and `/tmp` volumes and removes only its stale rendered snapshot before starting `consul-template`.

Before applying an overlay: customize the Consul API address, CA and TLS server name; replace the example WinDNS `known_hosts` entry with the real SSH host key; create secrets outside Git; pin a release or digest; ensure only one writer manages a provider/zone set; and render with `kubectl kustomize`. Argo CD does not create credentials.

## External Docker site

Copy the example agent, sensitive-agent and environment files to the names expected by Compose. Add the Consul CA and separate least-privilege tokens. The agent needs LAN gossip and RPC connectivity. Targets must allow selected ICMP/TCP/HTTP/SMTP traffic. Unprivileged ICMP needs suitable `net.ipv4.ping_group_range` or effective `CAP_NET_RAW`.

## ACL outline

Monitoring needs desired-KV read, managed-service write, and `node:write` for its actual node. DNS needs Catalog read, desired-config read, and GC-registry write. Keep provider credentials separate from Consul tokens.

## Troubleshooting

- Invalid YAML: rejected; previous services remain.
- Empty cold start: blocked unless explicitly allowed.
- `warning` with `ERROR:`: checker failure; inspect binary, permission, DNS, TLS and timeouts.
- No DNS update: inspect observers, quorum, `serfHealth`, `/work/service-state.json`, and logs.
- Provider or Consul failure: GC must remain disabled; unavailable is never an empty desired state.

Loki rules are included. Prometheus metrics are not yet implemented; useful metrics include check duration/result, endpoint states, last successful sync age, provider/Consul errors, and mutation counts.

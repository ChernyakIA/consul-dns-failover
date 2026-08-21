# Configuration

The authoritative YAML is stored in Consul KV. `config/monitoring.example.yml` is a sanitized example. Precedence is endpoint -> record -> defaults.

| Key | Meaning |
| --- | --- |
| `zone_name` | DNS zone. |
| `dns_provider` | `selecteldns` or `windns`. |
| `sel_zone_id` / `win_dns_server` | Provider-specific zone/server identifier. |
| `record.name` | Relative A-record name. |
| `ttl` | DNS TTL. |
| `on_all_fail` | `keep`, `remove`, or `fallback`. |
| `fallback_ip` | Required for `fallback`. |
| `endpoint.ip` | Address published in DNS. |
| `endpoint.sites` | Independent observers. |
| `owner_site` | Descriptive endpoint location. |
| `quorum` | Confirmations required to publish. |
| `minimum_observers` | Results required before state is known. |
| `check.target` | Checked address; defaults to `endpoint.ip`. |

Checks: `icmp`; `tcp` with port; `http` with full URL or target/scheme/port/path/method; and `smtp` with optional port 25. Durations accept `ms`, `s`, `m`, and `h`; timeout should be less than interval.

## Monitoring controller environment

Required: `SITE`, `NODE_NAME`, `CONSUL_KV_PATH`.

| Variable | Default / purpose |
| --- | --- |
| `CONSUL_ADDR` | `http://127.0.0.1:8500`; local agent API. |
| `CONSUL_HTTP_TOKEN` | Consul ACL token. |
| `CONSUL_CACERT` | CA file for Consul HTTPS. |
| `CONSUL_AUTO_ENCRYPT_CA_ADDR` | Server API used to fetch Auto Encrypt roots. |
| `SERVICE_NAME_PREFIX` | `dns-failover`. |
| `MANAGED_TAG` | `dns-failover-managed`. |
| `BLOCKING_WAIT` | `5m`. |
| `HTTP_TIMEOUT_BLOCKING` | `330`; must exceed blocking wait plus jitter. |
| `HEARTBEAT_INTERVAL` | `3600`. |
| `ALLOW_EMPTY_BOOTSTRAP` | `false`. |
| `LOG_LEVEL` | `INFO`. |

## DNS controller environment

Common: `CONSUL_HTTP_ADDR`, `CONSUL_GC_PATH`, `CONSUL_CONFIG_PATH`, `CONSUL_HTTP_TOKEN`, `CONSUL_CACERT`, `CONSUL_HTTP_SSL`, `DNS_PROVIDER_NAME`, `LOG_LEVEL`.

Selectel required: `SEL_ACCOUNT_ID`, `SEL_SERVICE_USER`, `SEL_SERVICE_PASS`, `SEL_PROJECT_NAME`. Optional: `SEL_AUTH_PROJECT_TOKEN_URL`, `SEL_DNS_API_BASE`, `SEL_LIST_RECORDS_LIMIT` (40), `HTTP_CONNECT_TIMEOUT` (5), `HTTP_READ_TIMEOUT` (15), `HTTP_RETRY_TOTAL` (2).

Microsoft DNS required: `WIN_SSH_HOST`, `WIN_SSH_USER`, `WIN_SSH_KNOWN_HOSTS`, and one of `WIN_SSH_PASSWORD` or `WIN_SSH_KEY_PATH`. Optional: `WIN_SSH_PORT` (22), `SSH_CONNECT_TIMEOUT` (10), `SSH_TIMEOUT` (60). `WIN_SSH_INSECURE_SKIP_HOST_KEY_CHECK=true` is an explicit migration-only escape hatch and must not be used in production.

Never commit credentials. Prefer an SSH key and keep the trusted server key in the mounted `known_hosts` file.

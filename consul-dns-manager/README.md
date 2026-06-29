# consul-dns-manager

An automated DNS failover manager running inside Kubernetes. It continuously tracks critical services in Consul and dynamically reconciles their target A records in your DNS-provider systems.

Current DNS-provider support:

- Selectel DNS Cloud API;
- Microsoft Active Directory DNS.

## Content

- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Envs](#envs)
- [Deployment](#deployment)

## Architecture

```html
[ Consul Service Registry ]
    │
    │ (Consul Template watch index)
    ▼
    │
    ├──► Consul-Template + py-script instance
    ▼       ▼
    │       │
    │       [ DNS-provider name ]
    │       ├── 1. Template filter active service IPs per provider
    │       ├── 2. Renders unified operational target state to JSON
    │       └── 3. Triggers py-script to manage DNS
    │
    └──► Consul-Template + py-script instance
            ▼
            │
            [ DNS-provider name ]
            ├── 1. Template filter active service IPs per provider
            ├── 2. Renders unified operational target state to JSON
            └── 3. Triggers py-script to manage DNS
```

1. Service Detection: `consul-template` generate JSON-output with services and IPs filtered by `SERVICE_NAME_REGEX` and `DNS_PROVIDER_NAME`.
2. Metadata Evaluation: The Template checks node liveness (testing `serfHealth`) and service metrics. It extracts options from Consul Service Metadata fields:

    - `service_name`
    - `record`
    - `zone`
    - `dns_provider`
    - `ttl`
    - `status`
    - `on_all_fail`
    - `fallback_ip`
    - `quorum`
    - Additional provider-specific fields, e.g. `sel_zone_id` or `win_dns_server`, etc.
    - `agents_total`
    - `agents_alive`
    - `ips`
    - `confirmations`

3. Reconciliation Loop: Upon service-state shift, `consul-template` triggers the provider-cpecific script passing the rendered JSON-output.
4. Garbage Collector (GC): The script synchronizes active records that was registered by `Consul-Service-Manager` in a JSON-file in Conusl-KV by path `CONSUL_GC_PATH`. Compares current state with backed and removes orphaned records (deleted from YAML-config) in DNS-provider.

## Directory Structure

`consul-template-config-cm.yml` -- ConfigMap includes:

- `config.hcl` -- template config.
- `template-service.tpl` -- state template parser.
- `dns-failover-manager-{$DNS_PROVIDER_NAME}.py` -- scripts to manage DNS-records
- configuration variables

`dns-manager-{$DNS_PROVIDER_NAME}-deploy.yml` -- Deployment manifest with runtime for dns-manager scripts.
`Dockerfile` -- instruction to build image for deployments.
`sensitive-{$DNS_PROVIDER_NAME}-secrets.yml` -- sensitive secrets for auth to DNS-provider
`service-meta-output.tpl` -- state template parser code. Sync it with ConfigMap.
`dns-failover-manager-{$DNS_PROVIDER_NAME}.py` -- dns-manager scripts. Sync it with ConfigMap.

## Envs

Global envs (in ConfigMap):

- `CONSUL_HTTP_ADDR` -- Domain address of the Consul server.
- `SERVICE_NAME_REGEX` -- Regex selector to filter managed services (defaults to ^dns-failover-).
- `CONSUL_GC_PATH` -- Active KV registry path directory suffix (e.g., dns-failover/gc/).

Selectel DNS Backend Creds (doc: <https://docs.selectel.ru/en/>; API doc: <https://docs.selectel.ru/en/api/dns-actual/#tag/RRSets>)

- `SEL_ACCOUNT_ID` -- Sel master account
- `SEL_SERVICE_USER` -- service account name
- `SEL_SERVICE_PASS` -- service account pass
- `SEL_PROJECT_NAME` -- project name

Microsoft Active Directory DNS SSH Settings

- `WIN_SSH_HOST` -- domain host AD host name
- `WIN_SSH_USER` -- ssh domain operator name
- `WIN_SSH_PASSWORD` -- user pass

## Deployment

1. Build and push the Runtime Container with Dockerfile

    ```bash
    docker build -t $YOURREGISTRY/consul-dns-manager:$TAG .
    docker push $YOURREGISTRY/consul-dns-manager:$TAG
    ```

2. Configure Manifests and variables

    Fill in the fields marked <FILL_THIS_FIELD> within the files.

3. Deploy to k8s cluster.

    `k apply -f $PATH_TO_MANIFESTS`

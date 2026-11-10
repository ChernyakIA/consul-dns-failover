# Based on the Alpine release used by consul-template 0.43
FROM hashicorp/consul-template:0.43
USER root
# Runtime dependencies for provider API and SSH backends
RUN apk upgrade --no-cache && apk add --no-cache python3=~3.12 py3-requests py3-yaml openssh-client=~10.2 sshpass=~1.10
COPY --chown=consul-template:consul-template \
    dns_controller_common.py \
    dns-failover-manager-selectel.py \
    dns-failover-manager-windns.py \
    templates/service-meta-output.tpl \
    /opt/dns-failover/
USER consul-template

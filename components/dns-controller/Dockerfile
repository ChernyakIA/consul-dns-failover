# Based on the Alpine release used by consul-template 0.42
FROM hashicorp/consul-template:0.42
USER root
# Runtime dependencies for provider API and SSH backends
RUN apk update && apk upgrade && apk add --no-cache python3=~3.12 py3-requests py3-yaml openssh-client=~10.2 sshpass=~1.10
COPY --chown=consul-template:consul-template dns-failover-manager-selectel.py /opt/dns-failover/dns-failover-manager-selectel.py
COPY --chown=consul-template:consul-template dns-failover-manager-windns.py /opt/dns-failover/dns-failover-manager-windns.py
COPY --chown=consul-template:consul-template templates/service-meta-output.tpl /opt/dns-failover/service-meta-output.tpl
USER consul-template

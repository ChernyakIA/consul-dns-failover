# Based on Alpine 3.23.3
FROM hashicorp/consul-template:0.42
USER root
# Current package versions for Alpine 3.23.3
RUN apk update && apk upgrade && apk add --no-cache python3=~3.12 py3-requests openssh-client=~10.2 sshpass=~1.10
USER consul-template

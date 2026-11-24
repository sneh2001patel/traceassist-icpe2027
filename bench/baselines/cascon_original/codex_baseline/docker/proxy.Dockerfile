# Egress proxy: the agent's only way out of the sandbox network.
# Allows HTTPS CONNECT to the hosts in `allowlist` (the model API) and nothing else.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends tinyproxy \
 && rm -rf /var/lib/apt/lists/*

COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY allowlist /etc/tinyproxy/allowlist

EXPOSE 8888
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]

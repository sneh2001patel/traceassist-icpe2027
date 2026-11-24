# The Codex agent's machine: a plain Linux box with standard trace tooling.
# No Trace Compass, no TMLL: the agent gets general-purpose tools only.
FROM debian:trixie-slim

ARG CODEX_VERSION=0.167.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      babeltrace2 python3 python3-bt2 python3-numpy python3-pandas \
      nodejs npm ca-certificates \
      procps coreutils findutils grep gawk sed less file jq ripgrep bc xz-utils \
 && npm install -g @openai/codex@${CODEX_VERSION} \
 && npm cache clean --force \
 && rm -rf /var/lib/apt/lists/*

# /work: the agent's scratch space. /codex: CODEX_HOME (sessions, config, auth).
# /data/trace: the trace, bind-mounted read-only at run time.
RUN mkdir -p /work /codex /data /tmp/home && chmod 1777 /work /codex /tmp/home

ENV HOME=/tmp/home \
    CODEX_HOME=/codex \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /work
CMD ["sleep", "infinity"]

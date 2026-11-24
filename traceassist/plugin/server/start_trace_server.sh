#!/bin/bash
# (Re)starts the Trace Server with the TraceAssist bundle (install it first: server/build.sh --install).
#
# - stops a running Trace Server (this install's);
# - takes OPENAI_API_KEY from the environment, or else from the Eclipse launch configuration
#   (never printed), so the AI skills work in the server;
# - starts it with -clean (OSGi re-reads the installed and patched jars), on port 8081 as before;
# - waits for the TSP API (8081) and the TraceAssist endpoint (8092).
#
# Usage: server/start_trace_server.sh [log file]   (default: ~/.cache/traceassist/trace-server.log)
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../../.." && pwd)
SERVER=${TRACE_SERVER:-"$REPO/trace-server/trace-compass-server"}
LAUNCH=${ECLIPSE_LAUNCH:-"$HOME/eclipse-workspace/.metadata/.plugins/org.eclipse.debug.core/.launches/tracing.product.launch"}
LOG=${1:-$HOME/.cache/traceassist/trace-server.log}
mkdir -p "$(dirname "$LOG")"

for pid in $(pgrep -f -- "$SERVER/+plugins/org.eclipse.justj" || true) $(pgrep -x tracecompass-ser || true); do
    echo "Stopping Trace Server process $pid"
    kill "$pid" 2>/dev/null || true
done
for _ in $(seq 1 30); do
    pgrep -f -- "$SERVER/+plugins/org.eclipse.justj" >/dev/null || break
    sleep 1
done

if [ -z "${OPENAI_API_KEY:-}" ] && [ -f "$LAUNCH" ]; then
    OPENAI_API_KEY=$(python3 - "$LAUNCH" <<'EOF'
import sys, xml.etree.ElementTree as ET
for entry in ET.parse(sys.argv[1]).iter("mapEntry"):
    if entry.get("key") == "OPENAI_API_KEY":
        print(entry.get("value", ""))
EOF
)
fi
[ -n "${OPENAI_API_KEY:-}" ] || echo "warning: OPENAI_API_KEY not found; the AI skills will fall back to the rules" >&2
export OPENAI_API_KEY

cd "$SERVER"
setsid nohup ./tracecompass-server -clean -vmargs -Dtraceserver.port=8081 -Xmx8g > "$LOG" 2>&1 < /dev/null &
echo "Trace Server starting (log: $LOG)"

for _ in $(seq 1 90); do
    if curl -s -m 2 http://127.0.0.1:8081/tsp/api/health | grep -q UP \
            && curl -s -m 2 http://127.0.0.1:8092/test/health | grep -q ok; then
        echo "Up: TSP on 8081, TraceAssist on 8092"
        grep -m1 "TraceAssist endpoint" "$LOG" || true
        exit 0
    fi
    sleep 2
done
echo "Not up after 3 minutes; see $LOG" >&2
exit 1

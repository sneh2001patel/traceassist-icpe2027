#!/bin/bash
# Starts the plain Trace Compass Trace Server the TMLL baseline uses: the release in server/
# (unpacked from trace-server/trace-compass-server.tar.gz), with no TraceAssist bundle, on port
# 8080, with its own workspace (server-workspace/), so it shares nothing with TraceAssist's server
# (port 8081/8092, workspace ~/.tracecompass-webapp).
#
# Note: TraceAssist's server/start_trace_server.sh stops every process named tracecompass-server,
# this one included. Restart this one after restarting TraceAssist's.
#
# Usage: tmll/start_server.sh        (log: tmll/server.log)    Stop: tmll/start_server.sh stop
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SERVER="$HERE/server/trace-compass-server"
PORT=${TMLL_SERVER_PORT:-8080}

for pid in $(pgrep -f -- "$SERVER/+plugins/org.eclipse.justj" || true); do
    echo "Stopping the TMLL baseline's Trace Server ($pid)"
    kill "$pid" 2>/dev/null || true
done
[ "${1:-}" = stop ] && exit 0
for _ in $(seq 1 30); do
    pgrep -f -- "$SERVER/+plugins/org.eclipse.justj" >/dev/null || break
    sleep 1
done

cd "$SERVER"
setsid nohup ./tracecompass-server -data "$HERE/server-workspace" -vmargs -Dtraceserver.port="$PORT" -Xmx8g \
    > "$HERE/server.log" 2>&1 < /dev/null &
for _ in $(seq 1 90); do
    if curl -s -m 2 "http://127.0.0.1:$PORT/tsp/api/health" | grep -q UP; then
        echo "Up: plain Trace Server on $PORT (log: $HERE/server.log)"
        exit 0
    fi
    sleep 2
done
echo "Not up after 3 minutes; see $HERE/server.log" >&2
exit 1

#!/usr/bin/env bash
#
# Records every scenario in scenarios.json (each program's healthy run and every fault), then
# the variants without the events a symptom needs or is easier to see with.
#
# Usage: ./record_all.sh [-d DURATION]      (default 30s; ~40 minutes in all)
#
# Requires a root session daemon (sudo lttng-sessiond --daemonize). Progress goes to
# runs/record_all.log; each recording is listed in runs/index.csv (see capture.sh).

set -uo pipefail

DURATION=30s
[ "${1:-}" = "-d" ] && DURATION="$2"
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${BENCH_DIR}"
make -s all scenarios.json
mkdir -p runs
LOG=runs/record_all.log

record() { # record <program> <fault> [capture.sh options]
    local start=$SECONDS
    if ./capture.sh "$@" -d "${DURATION}" < /dev/null >> "${LOG}" 2>&1; then
        echo "$(date +%T) ok    $* ($((SECONDS - start)) s)" | tee -a "${LOG}.summary"
    else
        echo "$(date +%T) FAIL  $* ($((SECONDS - start)) s)" | tee -a "${LOG}.summary"
    fi
}

python3 -c '
import json
for p in json.load(open("scenarios.json")):
    for f in p["faults"]:
        print(p["program"], f["name"])
' | while read -r program fault; do
    record "${program}" "${fault}"
done

# Without the events that show the symptom: the right answer becomes "the trace can't show it"
# (crash needs signals) or a less direct inference (disk and network waits).
record jobrunner crash --without signal
record filestore disk_wait --without block
record kvstore network_wait --without net

echo "$(date +%T) done" | tee -a "${LOG}.summary"

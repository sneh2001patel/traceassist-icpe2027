#!/bin/bash
# Checks the data archives against SHA256SUMS and unpacks them where the scripts expect them:
#   traces/<run>.tar.xz                  -> bench/runs/<run>/trace/
#   baseline_inputs/slices.tar.xz        -> bench/baselines/slices/        (LLM-only and RAG inputs)
#   baseline_inputs/tmll_evidence.tar.xz -> bench/baselines/tmll/evidence/ (TMLL baseline input)
#   trace-server/trace-compass-server.tar.gz (stock Trace Server 0.18.0, Linux x86-64)
#                                        -> trace-server/                  (for TraceAssist)
#                                        -> bench/baselines/tmll/server/   (plain, for the TMLL baseline)
# Already unpacked parts are skipped. Usage: data/unpack.sh [traces|inputs|server ...] (default: all)
set -euo pipefail
DATA=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$DATA")
PARTS=${*:-traces inputs server}

cd "$DATA"
echo "Checking archives against SHA256SUMS"
sha256sum --quiet -c SHA256SUMS

for part in $PARTS; do
    case $part in
    traces)
        for f in traces/*.tar.xz; do
            run=$(basename "$f" .tar.xz)
            dest="$ROOT/bench/runs/$run"
            [ -d "$dest/trace" ] && continue
            mkdir -p "$dest"
            tar -C "$dest" -xJf "$f"
            echo "unpacked $run"
        done ;;
    inputs)
        [ -d "$ROOT/bench/baselines/slices" ] || tar -C "$ROOT/bench/baselines" -xJf baseline_inputs/slices.tar.xz
        [ -d "$ROOT/bench/baselines/tmll/evidence" ] || tar -C "$ROOT/bench/baselines/tmll" -xJf baseline_inputs/tmll_evidence.tar.xz
        echo "unpacked the baselines' inputs" ;;
    server)
        for dest in "$ROOT/trace-server" "$ROOT/bench/baselines/tmll/server"; do
            [ -d "$dest/trace-compass-server" ] && continue
            mkdir -p "$dest"
            tar -C "$dest" -xzf trace-server/trace-compass-server.tar.gz
            echo "unpacked the Trace Server in $dest"
        done ;;
    *) echo "unknown part: $part (traces, inputs or server)" >&2; exit 2 ;;
    esac
done

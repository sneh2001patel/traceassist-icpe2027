#!/bin/bash
# Downloads the data archives listed in SHA256SUMS from the repository's GitHub release into
# data/traces, data/baseline_inputs and data/trace-server (1.3 GB), skipping any already here.
# Then run data/unpack.sh, which checks every archive against SHA256SUMS.
# Usage: data/download.sh
set -euo pipefail
RELEASE=${RELEASE_URL:-https://github.com/sneh2001patel/traceassist-icpe2027/releases/download/v1.0-icpe2027}
DATA=$(cd "$(dirname "$0")" && pwd)
cd "$DATA"
awk '{print $2}' SHA256SUMS | while read -r path; do
    [ -f "$path" ] && continue
    mkdir -p "$(dirname "$path")"
    echo "downloading $path"
    curl -fL --retry 3 -o "$path.part" "$RELEASE/$(basename "$path")"
    mv "$path.part" "$path"
done
echo "done; now run data/unpack.sh"

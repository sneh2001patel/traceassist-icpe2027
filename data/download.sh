#!/bin/bash
# Downloads the data archives listed in SHA256SUMS from their Zenodo record
# (https://doi.org/10.5281/zenodo.24489091) into
# data/traces, data/baseline_inputs and data/trace-server (1.3 GB; about 20 min at 1 MB/s), skipping any already here.
# Then run data/unpack.sh, which checks every archive against SHA256SUMS.
# Usage: data/download.sh
set -euo pipefail
RECORD=${ZENODO_RECORD:-https://zenodo.org/records/24489091}
DATA=$(cd "$(dirname "$0")" && pwd)
cd "$DATA"
awk '{print $2}' SHA256SUMS | while read -r path; do
    [ -f "$path" ] && continue
    mkdir -p "$(dirname "$path")"
    echo "downloading $path"
    curl -fL --retry 3 --progress-bar -o "$path.part" "$RECORD/files/$(basename "$path")?download=1"
    mv "$path.part" "$path"
done
echo "done; now run data/unpack.sh"

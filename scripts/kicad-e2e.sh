#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 PCBEX_BINARY OUTPUT_DIRECTORY" >&2
  exit 2
fi

pcbex_binary=$1
output_directory=$2
fixtures=(
  examples/simple.kicad_pcb
  examples/nonrect.kicad_pcb
  examples/keepout.kicad_pcb
)

mkdir -p "$output_directory"
kicad-cli --version

for fixture in "${fixtures[@]}"; do
  name=$(basename "$fixture" .kicad_pcb)
  first="$output_directory/$name.routed.kicad_pcb"
  second="$output_directory/$name.rerouted.kicad_pcb"
  routes="$output_directory/$name.routes.json"
  reroutes="$output_directory/$name.reroutes.json"

  "$pcbex_binary" route-kicad "$fixture" \
    --output "$first" \
    --json-output "$routes" \
    --drc
  jq -e '.routes | length > 0' "$routes" >/dev/null

  "$pcbex_binary" route-kicad "$first" \
    --output "$second" \
    --json-output "$reroutes" \
    --drc
  jq -e '.routes | length > 0' "$reroutes" >/dev/null
  cmp "$first" "$second"
done

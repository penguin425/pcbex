#!/usr/bin/env bash
set -euo pipefail

binary="${1:-target/release/pcbex}"
output_dir="${2:-build/regression-corpus}"
mkdir -p "$output_dir"

run_fixture() {
  local name="$1"
  local budget="$2"
  local input="corpus/${name}.json"
  local routed="${output_dir}/${name}.routed.json"
  local rerouted="${output_dir}/${name}.rerouted.json"
  local report
  report="$("$binary" route "$input" --output "$routed" 2>&1)"
  echo "${name}: ${report}"
  local expanded
  expanded="$(sed -n 's/.*expanded states: \([0-9][0-9]*\).*/\1/p' <<<"$report")"
  if [[ -z "$expanded" || "$expanded" -gt "$budget" ]]; then
    echo "${name}: expanded-state budget exceeded (${expanded:-missing} > ${budget})" >&2
    return 1
  fi
  "$binary" check "$routed"
  "$binary" route "$routed" --output "$rerouted" >/dev/null 2>&1
  cmp "$routed" "$rerouted"
}

run_fixture usb_diff 8000
run_fixture four_layer_power 15000
run_fixture bga_fanout 12000

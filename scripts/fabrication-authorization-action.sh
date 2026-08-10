#!/usr/bin/env bash
set -euo pipefail

# Verification-only Action bridge. Signing, private keys, scope construction,
# caller-selected time, network/factory submission, ordering, and payment are
# deliberately absent from this interface.

action_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="${PCBEX_REPOSITORY_ROOT:-$(cd -- "$action_script_dir/.." && pwd -P)}"
runtime_script="$repository_root/scripts/ci_runtime.py"
summary_helper="$repository_root/scripts/fabrication_authorization_summary.py"
mode="${1:-}"

if [[ "$mode" != "" && "$mode" != "--revalidate" ]]; then
  echo "unknown wrapper argument" >&2
  exit 2
fi

required_variables=(
  GITHUB_OUTPUT
  GITHUB_STEP_SUMMARY
  PCBEX_FABRICATION_PLAN
  PCBEX_FABRICATION_RETAINED_REPORT
  PCBEX_FABRICATION_MANUFACTURING_PACKAGE
  PCBEX_FABRICATION_FACTORY_RECEIPT
  PCBEX_FABRICATION_POLICY_PACK
  PCBEX_FABRICATION_APPROVAL_FILES
  PCBEX_FABRICATION_REQUIRE_AUTHORIZED
  PCBEX_OUTPUT_DIR
)
if [[ "$mode" == "" ]]; then
  required_variables+=(PCBEX_BINARY)
fi
if [[ "$mode" == "--revalidate" ]]; then
  required_variables+=(PCBEX_FABRICATION_REPORT PCBEX_FABRICATION_INPUT_SNAPSHOT)
  for suffix in \
    SCHEMA_VERSION STATUS FABRICATION_AUTHORIZED AUTHORIZATION_ID CHALLENGE QUANTITY CURRENCY \
    MAXIMUM_TOTAL_MINOR_UNITS VALID_FROM_UNIX EXPIRES_AT_UNIX EVALUATED_AT_UNIX APPROVALS REJECTIONS \
    GATE_FAILURE_COUNT PLAN_SHA256 RUN_SHA256 MANUFACTURING_PACKAGE_SHA256 FACTORY_RECEIPT_SHA256 \
    POLICY_PACK_SHA256 QUOTE_AUTHENTICITY_VERIFIED CHALLENGE_ONE_TIME_USE_ENFORCED REPORT_BYTES REPORT_SHA256; do
    required_variables+=("PCBEX_FABRICATION_SUMMARY_$suffix")
  done
fi
for variable in "${required_variables[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "required environment variable is empty: $variable" >&2
    exit 2
  fi
done
if [[ ! -f "$runtime_script" || ! -f "$summary_helper" ]]; then
  echo "pcbex Action helpers are unavailable" >&2
  exit 2
fi

MAX_APPROVALS=100
MAX_REPORT_BYTES=134217728
FIXED_REPORT_NAME="fabrication-authorization.json"

write_output() {
  # Only fixed literals, bounded scalar fields, and the authenticated fixed
  # report path are emitted. The complete report and full summary never enter
  # GITHUB_OUTPUT.
  printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
}

approval_paths=()
all_input_paths=()

load_approval_files() {
  local raw="$PCBEX_FABRICATION_APPROVAL_FILES"
  local line
  approval_paths=()
  if [[ "$raw" == *$'\n' ]]; then
    raw="${raw%$'\n'}"
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$line" ]]; then
      echo "approval-files must contain one non-empty relative path per line" >&2
      return 2
    fi
    approval_paths+=("$line")
    if (( ${#approval_paths[@]} > MAX_APPROVALS )); then
      echo "approval-files must contain 1 through $MAX_APPROVALS paths" >&2
      return 2
    fi
  done <<< "$raw"
  if (( ${#approval_paths[@]} < 1 )); then
    echo "approval-files must contain 1 through $MAX_APPROVALS paths" >&2
    return 2
  fi
}

validate_common_inputs() {
  case "$PCBEX_FABRICATION_REQUIRE_AUTHORIZED" in
    true|false) ;;
    *) echo "require-authorized must be true or false" >&2; return 2 ;;
  esac
  [[ -n "$PCBEX_OUTPUT_DIR" ]] || {
    echo "output-dir must not be empty" >&2
    return 2
  }
}

validate_inputs() {
  local path
  for path in \
    "$PCBEX_FABRICATION_PLAN" \
    "$PCBEX_FABRICATION_RETAINED_REPORT" \
    "$PCBEX_FABRICATION_MANUFACTURING_PACKAGE" \
    "$PCBEX_FABRICATION_FACTORY_RECEIPT" \
    "$PCBEX_FABRICATION_POLICY_PACK"; do
    python3 "$runtime_script" validate-input "--path=$path"
  done
  for path in "${approval_paths[@]}"; do
    python3 "$runtime_script" validate-input "--path=$path"
  done
  python3 "$runtime_script" validate-output "--output-root=$PCBEX_OUTPUT_DIR"
}

build_input_list() {
  all_input_paths=(
    "$PCBEX_FABRICATION_PLAN"
    "$PCBEX_FABRICATION_RETAINED_REPORT"
    "$PCBEX_FABRICATION_MANUFACTURING_PACKAGE"
    "$PCBEX_FABRICATION_FACTORY_RECEIPT"
    "$PCBEX_FABRICATION_POLICY_PACK"
    "${approval_paths[@]}"
  )
}

snapshot_inputs() {
  # Stable-read every caller source and retain only one freshness digest.
  PYTHONPATH="$repository_root/scripts" python3 - "${all_input_paths[@]}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

from ci_runtime import read_bytes

maximums = [
    4 * 1024 * 1024,
    128 * 1024 * 1024,
    128 * 1024 * 1024,
    64 * 1024 * 1024,
    64 * 1024 * 1024,
]
maximums.extend([1024 * 1024] * max(0, len(sys.argv[1:]) - len(maximums)))
records = []
try:
    for index, raw in enumerate(sys.argv[1:]):
        path = Path(raw)
        first = read_bytes(path, max_bytes=maximums[index])
        second = read_bytes(path, max_bytes=maximums[index])
        if first != second:
            raise ValueError(f"input changed between bounded reads: {path}")
        records.append([raw, len(first), hashlib.sha256(first).hexdigest()])
    encoded = json.dumps(records, ensure_ascii=True, separators=(",", ":")).encode()
    print(hashlib.sha256(encoded).hexdigest())
except (OSError, TypeError, ValueError) as error:
    print(f"could not snapshot fabrication authorization inputs: {error}", file=sys.stderr)
    raise SystemExit(2)
PY
}

validate_fresh_output_dir() {
  python3 - "$PCBEX_OUTPUT_DIR" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
try:
    metadata = os.lstat(path)
except FileNotFoundError:
    raise SystemExit(0)
except OSError as error:
    print(f"could not inspect output directory: {error}", file=sys.stderr)
    raise SystemExit(2)
if stat.S_ISLNK(metadata.st_mode):
    print("output directory must not be a symlink", file=sys.stderr)
    raise SystemExit(2)
if not stat.S_ISDIR(metadata.st_mode):
    print("output directory must be a directory", file=sys.stderr)
    raise SystemExit(2)
try:
    with os.scandir(path) as entries:
        if next(entries, None) is not None:
            print("output directory must be empty before verification", file=sys.stderr)
            raise SystemExit(2)
except OSError as error:
    print(f"could not inspect output directory: {error}", file=sys.stderr)
    raise SystemExit(2)
PY
}

prepare_output() {
  validate_fresh_output_dir
  if [[ ! -e "$PCBEX_OUTPUT_DIR" ]]; then
    mkdir -p -- "$PCBEX_OUTPUT_DIR"
  fi
  artifact_dir="$PCBEX_OUTPUT_DIR"
  report_candidate="$artifact_dir/$FIXED_REPORT_NAME"
  if [[ -e "$report_candidate" || -L "$report_candidate" ]]; then
    echo "refusing to reuse an existing fabrication authorization report" >&2
    return 2
  fi
}

scan_one_file() {
  local usage
  usage="$(python3 "$runtime_script" scan \
    "--output-root=$PCBEX_OUTPUT_DIR" \
    --max-entries 1 \
    --max-depth 1 \
    --max-file-bytes "$MAX_REPORT_BYTES" \
    --max-total-bytes "$MAX_REPORT_BYTES")"
  [[ "$usage" == *"1 entries, 1 files,"* ]] || {
    echo "fabrication authorization evidence must contain exactly one bounded file" >&2
    return 2
  }
}

summary_fields=(
  schema_version status fabrication_authorized authorization_id challenge quantity currency
  maximum_total_minor_units valid_from_unix expires_at_unix evaluated_at_unix approvals rejections
  gate_failure_count plan_sha256 run_sha256 manufacturing_package_sha256 factory_receipt_sha256
  policy_pack_sha256 quote_authenticity_verified challenge_one_time_use_enforced report_bytes report_sha256
)
summary_output_names=(
  schema-version authorization-status fabrication-authorized authorization-id challenge quantity currency
  maximum-total-minor-units valid-from-unix expires-at-unix evaluated-at-unix approvals rejections
  gate-failure-count plan-sha256 run-sha256 manufacturing-package-sha256 factory-receipt-sha256
  policy-pack-sha256 quote-authenticity-verified challenge-one-time-use-enforced report-bytes report-sha256
)
summary_json_from_environment() {
  python3 - <<'PY'
import json
import os

fields = (
    "schema_version", "status", "fabrication_authorized", "authorization_id", "challenge",
    "quantity", "currency", "maximum_total_minor_units", "valid_from_unix", "expires_at_unix",
    "evaluated_at_unix", "approvals", "rejections", "gate_failure_count", "plan_sha256", "run_sha256",
    "manufacturing_package_sha256", "factory_receipt_sha256", "policy_pack_sha256",
    "quote_authenticity_verified", "challenge_one_time_use_enforced", "report_bytes", "report_sha256",
)
suffixes = (
    "SCHEMA_VERSION", "STATUS", "FABRICATION_AUTHORIZED", "AUTHORIZATION_ID", "CHALLENGE", "QUANTITY",
    "CURRENCY", "MAXIMUM_TOTAL_MINOR_UNITS", "VALID_FROM_UNIX", "EXPIRES_AT_UNIX", "EVALUATED_AT_UNIX",
    "APPROVALS", "REJECTIONS", "GATE_FAILURE_COUNT", "PLAN_SHA256", "RUN_SHA256",
    "MANUFACTURING_PACKAGE_SHA256", "FACTORY_RECEIPT_SHA256", "POLICY_PACK_SHA256",
    "QUOTE_AUTHENTICITY_VERIFIED", "CHALLENGE_ONE_TIME_USE_ENFORCED", "REPORT_BYTES", "REPORT_SHA256",
)
integer_fields = {
    "schema_version", "quantity", "maximum_total_minor_units", "valid_from_unix",
    "expires_at_unix", "evaluated_at_unix", "approvals", "rejections", "gate_failure_count", "report_bytes",
}
boolean_fields = {"fabrication_authorized", "quote_authenticity_verified", "challenge_one_time_use_enforced"}
result = {}
for field, suffix in zip(fields, suffixes):
    raw = os.environ.get(f"PCBEX_FABRICATION_SUMMARY_{suffix}", "")
    if raw == "":
        raise SystemExit(f"missing scalar summary field: {field}")
    if field in integer_fields:
        result[field] = int(raw, 10)
    elif field in boolean_fields:
        if raw not in ("true", "false"):
            raise SystemExit(f"invalid scalar summary boolean: {field}")
        result[field] = raw == "true"
    else:
        result[field] = raw
print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
PY
}

parse_summary_values() {
  local summary_json="$1"
  local values
  values="$(python3 - "$summary_json" <<'PY'
import json
import sys

fields = (
    "schema_version", "status", "fabrication_authorized", "authorization_id", "challenge", "quantity",
    "currency", "maximum_total_minor_units", "valid_from_unix", "expires_at_unix", "evaluated_at_unix",
    "approvals", "rejections", "gate_failure_count", "plan_sha256", "run_sha256",
    "manufacturing_package_sha256", "factory_receipt_sha256", "policy_pack_sha256",
    "quote_authenticity_verified", "challenge_one_time_use_enforced", "report_bytes", "report_sha256",
)
value = json.loads(sys.argv[1])
if type(value) is not dict or set(value) != set(fields):
    raise SystemExit(2)
for field in fields:
    rendered = str(value[field]).lower() if type(value[field]) is bool else str(value[field])
    if any(character in rendered for character in "\r\n="):
        raise SystemExit(2)
    print(rendered)
PY
)"
  summary_values=()
  while IFS= read -r value; do
    [[ -n "$value" ]] || return 2
    summary_values+=("$value")
  done <<< "$values"
  [[ ${#summary_values[@]} -eq ${#summary_fields[@]} ]] || return 2
}

run_summary_helper() {
  local summary_input="$1"
  printf '%s\n' "$summary_input" |
    python3 "$summary_helper" --verify "--report=$report_candidate"
}

write_error_outputs() {
  write_output status error
  write_output artifact-dir ""
  write_output fabrication-authorization-report ""
  write_output input-snapshot-sha256 ""
  local output_name
  for output_name in "${summary_output_names[@]}"; do
    write_output "$output_name" ""
  done
}

append_summary() {
  local status="$1"
  local authorized="$2"
  {
    printf '# pcbex fabrication authorization\n\n'
    printf -- '- Status: `%s`\n' "$status"
    if [[ "$status" == ok ]]; then
      printf -- '- Fabrication authorized: `%s`\n' "$authorized"
      printf -- '- Report: `%s`\n' "$report_candidate"
      printf -- '- Report bytes: `%s`\n' "${summary_values[21]}"
      printf -- '- Report SHA-256: `%s`\n' "${summary_values[22]}"
    else
      printf -- '- Report: unavailable\n'
    fi
  } >> "$GITHUB_STEP_SUMMARY"
}

publication_revalidate() {
  validate_common_inputs
  load_approval_files
  validate_inputs
  build_input_list
  artifact_dir="$PCBEX_OUTPUT_DIR"
  report_candidate="$artifact_dir/$FIXED_REPORT_NAME"
  if [[ "$PCBEX_FABRICATION_REPORT" != "$report_candidate" ]]; then
    echo "fabrication authorization report path is not the fixed Action path" >&2
    return 2
  fi
  if [[ ! "$PCBEX_FABRICATION_INPUT_SNAPSHOT" =~ ^[0-9a-f]{64}$ ]]; then
    echo "fabrication authorization input snapshot is malformed" >&2
    return 2
  fi
  current_snapshot="$(snapshot_inputs)"
  if [[ "$current_snapshot" != "$PCBEX_FABRICATION_INPUT_SNAPSHOT" ]]; then
    echo "fabrication authorization inputs changed before publication" >&2
    return 2
  fi
  summary_json="$(summary_json_from_environment)"
  validated_summary="$(run_summary_helper "$summary_json")"
  [[ -n "$validated_summary" ]] || {
    echo "publication summary authentication produced no summary" >&2
    return 2
  }
  parse_summary_values "$validated_summary"
  scan_one_file
  write_output artifact-dir "$artifact_dir"
  write_output fabrication-authorization-report "$report_candidate"
  for index in "${!summary_fields[@]}"; do
    write_output "${summary_output_names[$index]}" "${summary_values[$index]}"
  done
  printf 'safe=true\n' >> "$GITHUB_OUTPUT"
}

summary_values=()

if [[ "$mode" == "--revalidate" ]]; then
  publication_revalidate
  exit 0
fi

artifact_dir=""
report_candidate=""

validate_common_inputs
load_approval_files
validate_inputs
build_input_list
before_snapshot="$(snapshot_inputs)"
prepare_output
write_error_outputs

verification_arguments=(
  verify-fabrication-authorization
  "--report=$PCBEX_FABRICATION_RETAINED_REPORT"
  "--manufacturing-package=$PCBEX_FABRICATION_MANUFACTURING_PACKAGE"
  "--factory-receipt=$PCBEX_FABRICATION_FACTORY_RECEIPT"
  "--policy-pack=$PCBEX_FABRICATION_POLICY_PACK"
)
for approval in "${approval_paths[@]}"; do
  verification_arguments+=("--approval=$approval")
done
verification_arguments+=(
  "--output=$report_candidate"
  --mcp-echo-report-summary
  --
  "$PCBEX_FABRICATION_PLAN"
)

validated_summary=""
if ! validated_summary="$(
  # Keep the bounded child stdout stream raw.  In particular, do not capture
  # it and printf it back: command substitution would normalize trailing LF
  # bytes before the strict summary helper can authenticate the stream.
  python3 "$runtime_script" exec \
    --timeout-seconds 600 \
    --max-stdout-bytes 4096 \
    --max-stderr-bytes 8388608 \
    "--output-root=$PCBEX_OUTPUT_DIR" \
    -- "$PCBEX_BINARY" "${verification_arguments[@]}" |
  python3 "$summary_helper" --verify "--report=$report_candidate"
)"; then
  append_summary error false
  exit 2
fi

parse_summary_values "$validated_summary"
after_snapshot="$(snapshot_inputs)"
if [[ "$before_snapshot" != "$after_snapshot" ]]; then
  echo "fabrication authorization inputs changed during verification" >&2
  append_summary error false
  exit 2
fi
scan_one_file

write_output status ok
write_output artifact-dir "$artifact_dir"
write_output fabrication-authorization-report "$report_candidate"
write_output input-snapshot-sha256 "$after_snapshot"
for index in "${!summary_fields[@]}"; do
  write_output "${summary_output_names[$index]}" "${summary_values[$index]}"
done
append_summary ok "${summary_values[2]}"

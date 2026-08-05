#!/usr/bin/env bash
set -euo pipefail

required_variables=(
  GITHUB_OUTPUT
  GITHUB_STEP_SUMMARY
  PCBEX_BINARY
  PCBEX_NATIVE_KICAD_DRC_BOARD
  PCBEX_NATIVE_KICAD_DRC_KICAD_CLI
  PCBEX_NATIVE_KICAD_DRC_REQUIRE_APPROVED
  PCBEX_OUTPUT_DIR
)
for variable in "${required_variables[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "required environment variable is empty: $variable" >&2
    exit 2
  fi
done

action_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
native_kicad_drc_mode="${PCBEX_NATIVE_KICAD_DRC_MODE:-run}"
native_kicad_drc_retained_report="${PCBEX_NATIVE_KICAD_DRC_REPORT:-}"
case "$native_kicad_drc_mode" in
  run)
    if [[ -n "$native_kicad_drc_retained_report" ]]; then
      echo "report must be empty when mode is run" >&2
      exit 2
    fi
    ;;
  verify)
    if [[ -z "$native_kicad_drc_retained_report" ]]; then
      echo "report must not be empty when mode is verify" >&2
      exit 2
    fi
    ;;
  *)
    echo "mode must be run or verify" >&2
    exit 2
    ;;
esac
python3 "$action_script_dir/ci_runtime.py" validate-input \
  "--path=$PCBEX_NATIVE_KICAD_DRC_BOARD"
if [[ -n "${PCBEX_NATIVE_KICAD_DRC_PROJECT:-}" ]]; then
  python3 "$action_script_dir/ci_runtime.py" validate-input \
    "--path=$PCBEX_NATIVE_KICAD_DRC_PROJECT"
fi
if [[ -n "${PCBEX_NATIVE_KICAD_DRC_RULES_FILE:-}" ]]; then
  python3 "$action_script_dir/ci_runtime.py" validate-input \
    "--path=$PCBEX_NATIVE_KICAD_DRC_RULES_FILE"
fi
if [[ "$native_kicad_drc_mode" == "verify" ]]; then
  python3 "$action_script_dir/ci_runtime.py" validate-input \
    "--path=$native_kicad_drc_retained_report"
fi
PYTHONPATH="$action_script_dir" python3 - "$PCBEX_OUTPUT_DIR" <<'PY'
import sys

from ci_runtime import ExecutionBoundaryError, validate_literal_relative_output_root

try:
    validate_literal_relative_output_root(sys.argv[1])
except (ExecutionBoundaryError, OSError, TypeError, ValueError) as error:
    print(f"invalid PCBEX_OUTPUT_DIR: {error}", file=sys.stderr)
    raise SystemExit(2)
PY

artifact_dir="$PCBEX_OUTPUT_DIR"
if [[ -L "$artifact_dir" ]]; then
  echo "refusing to use a linked PCBEX_OUTPUT_DIR" >&2
  exit 2
fi
if [[ -e "$artifact_dir" ]]; then
  if [[ ! -d "$artifact_dir" ]]; then
    echo "PCBEX_OUTPUT_DIR must be a directory" >&2
    exit 2
  fi
  if python3 - "$artifact_dir" <<'PY'
import os
import sys

with os.scandir(sys.argv[1]) as entries:
    raise SystemExit(0 if next(entries, None) is not None else 1)
PY
  then
    echo "PCBEX_OUTPUT_DIR must be empty before native KiCad DRC" >&2
    exit 2
  fi
else
  mkdir -p -- "$artifact_dir"
fi

write_output() {
  printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
}

write_output status error
write_output artifact-dir "$artifact_dir"
write_output native-kicad-drc-report ""
write_output schema-version ""
write_output approved ""
write_output violation-count ""
write_output unconnected-item-count ""
write_output schematic-parity-count ""
write_output error-count ""
write_output warning-count ""
write_output ignored-check-count ""
write_output board-bytes ""
write_output board-sha256 ""
write_output project-bytes ""
write_output project-sha256 ""
write_output rules-file-bytes ""
write_output rules-file-sha256 ""
write_output run-sha256 ""
write_output report-bytes ""
write_output report-sha256 ""

case "$PCBEX_NATIVE_KICAD_DRC_REQUIRE_APPROVED" in
  true|false) ;;
  *)
    echo "PCBEX_NATIVE_KICAD_DRC_REQUIRE_APPROVED must be true or false" >&2
    exit 2
    ;;
esac

native_kicad_drc_project="${PCBEX_NATIVE_KICAD_DRC_PROJECT:-}"
native_kicad_drc_rules_file="${PCBEX_NATIVE_KICAD_DRC_RULES_FILE:-}"
native_kicad_drc_report_candidate="${artifact_dir}/native-kicad-drc.json"
if [[ -e "$native_kicad_drc_report_candidate" ||
  -L "$native_kicad_drc_report_candidate" ]]; then
  echo "refusing to reuse an existing native KiCad DRC report" >&2
  exit 2
fi

if [[ "$native_kicad_drc_mode" == "run" ]]; then
  native_kicad_drc_arguments=(
    run-native-kicad-drc
    "--output=$native_kicad_drc_report_candidate"
    "--kicad-cli=$PCBEX_NATIVE_KICAD_DRC_KICAD_CLI"
    --mcp-echo-report-summary
  )
  native_kicad_drc_summary_report="$native_kicad_drc_report_candidate"
else
  native_kicad_drc_arguments=(
    verify-native-kicad-drc-report
    "--kicad-cli=$PCBEX_NATIVE_KICAD_DRC_KICAD_CLI"
    --mcp-echo-report-summary
  )
  native_kicad_drc_summary_report="$native_kicad_drc_retained_report"
fi
native_kicad_drc_summary_arguments=(
  --verify
  "--board=$PCBEX_NATIVE_KICAD_DRC_BOARD"
  "--report=$native_kicad_drc_summary_report"
)
if [[ -n "$native_kicad_drc_project" ]]; then
  native_kicad_drc_arguments+=("--project=$native_kicad_drc_project")
  native_kicad_drc_summary_arguments+=("--project=$native_kicad_drc_project")
fi
if [[ -n "$native_kicad_drc_rules_file" ]]; then
  native_kicad_drc_arguments+=("--rules-file=$native_kicad_drc_rules_file")
  native_kicad_drc_summary_arguments+=("--rules-file=$native_kicad_drc_rules_file")
fi
# Keep caller-controlled paths after `--`: a basename can never become an
# option to clap or KiCad, even when it begins with a dash.
if [[ "$native_kicad_drc_mode" == "run" ]]; then
  native_kicad_drc_arguments+=(-- "$PCBEX_NATIVE_KICAD_DRC_BOARD")
else
  native_kicad_drc_arguments+=(-- "$PCBEX_NATIVE_KICAD_DRC_BOARD" "$native_kicad_drc_retained_report")
fi

native_kicad_drc_summary_json=""
native_kicad_drc_rc=0
if native_kicad_drc_summary_json="$(
  python3 "$action_script_dir/ci_runtime.py" exec \
    --timeout-seconds 600 \
    --max-stdout-bytes 4096 \
    --max-stderr-bytes 8388608 \
    "--output-root=$PCBEX_OUTPUT_DIR" \
    -- "$PCBEX_BINARY" "${native_kicad_drc_arguments[@]}" |
  python3 "$action_script_dir/native_kicad_drc_summary.py" \
    "${native_kicad_drc_summary_arguments[@]}"
)"; then
  native_kicad_drc_rc=0
else
  native_kicad_drc_rc=$?
fi

native_kicad_drc_report=""
schema_version=""
approved=""
violation_count=""
unconnected_item_count=""
schematic_parity_count=""
error_count=""
warning_count=""
ignored_check_count=""
board_bytes=""
board_sha256=""
project_bytes=""
project_sha256=""
rules_file_bytes=""
rules_file_sha256=""
run_sha256=""
report_bytes=""
report_sha256=""

if ((native_kicad_drc_rc == 0)) && [[ -n "$native_kicad_drc_summary_json" ]]; then
  summary_values=""
  if summary_values="$(
    python3 - "$native_kicad_drc_summary_json" <<'PY'
import json
import sys

def reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate summary key: {key}")
        value[key] = item
    return value

def reject_constant(value):
    raise ValueError(f"non-standard JSON number: {value}")

fields = (
    "schema_version", "approved", "violation_count", "unconnected_item_count",
    "schematic_parity_count", "error_count", "warning_count", "ignored_check_count",
    "board_bytes", "board_sha256", "project_bytes", "project_sha256",
    "rules_file_bytes", "rules_file_sha256", "run_sha256", "report_bytes", "report_sha256",
)
try:
    value = json.loads(
        sys.argv[1],
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_constant,
    )
except (IndexError, json.JSONDecodeError, TypeError, ValueError):
    raise SystemExit(2)
if type(value) is not dict or set(value) != set(fields) or len(value) != len(fields):
    raise SystemExit(2)
for field in fields:
    item = value[field]
    if field == "approved":
        if type(item) is not bool:
            raise SystemExit(2)
        rendered = str(item).lower()
    elif field.endswith("_sha256"):
        if not isinstance(item, str) or (item and (len(item) != 64 or any(c not in "0123456789abcdef" for c in item))):
            raise SystemExit(2)
        rendered = item
    elif field.endswith("_bytes") or field.endswith("_count") or field == "schema_version":
        if type(item) not in (int, str):
            raise SystemExit(2)
        rendered = str(item)
    else:
        raise SystemExit(2)
    if any(ch in rendered for ch in "\r\n="):
        raise SystemExit(2)
    print(f"{field}={rendered}")
PY
)"; then
    while IFS='=' read -r field value; do
      case "$field" in
        schema_version) schema_version="$value" ;;
        approved) approved="$value" ;;
        violation_count) violation_count="$value" ;;
        unconnected_item_count) unconnected_item_count="$value" ;;
        schematic_parity_count) schematic_parity_count="$value" ;;
        error_count) error_count="$value" ;;
        warning_count) warning_count="$value" ;;
        ignored_check_count) ignored_check_count="$value" ;;
        board_bytes) board_bytes="$value" ;;
        board_sha256) board_sha256="$value" ;;
        project_bytes) project_bytes="$value" ;;
        project_sha256) project_sha256="$value" ;;
        rules_file_bytes) rules_file_bytes="$value" ;;
        rules_file_sha256) rules_file_sha256="$value" ;;
        run_sha256) run_sha256="$value" ;;
        report_bytes) report_bytes="$value" ;;
        report_sha256) report_sha256="$value" ;;
        *) native_kicad_drc_rc=2 ;;
      esac
    done <<< "$summary_values"
  else
    native_kicad_drc_rc=2
  fi

  if [[ ! "$schema_version" =~ ^1$ ||
    ! "$approved" =~ ^(true|false)$ ||
    ! "$violation_count" =~ ^(0|[1-9][0-9]*)$ ||
    ! "$unconnected_item_count" =~ ^(0|[1-9][0-9]*)$ ||
    ! "$schematic_parity_count" =~ ^(0|[1-9][0-9]*)$ ||
    ! "$error_count" =~ ^(0|[1-9][0-9]*)$ ||
    ! "$warning_count" =~ ^(0|[1-9][0-9]*)$ ||
    ! "$ignored_check_count" =~ ^(0|[1-9][0-9]*)$ ||
    ! "$board_bytes" =~ ^[1-9][0-9]*$ ||
    ! "$board_sha256" =~ ^[0-9a-f]{64}$ ||
    ! "$run_sha256" =~ ^[0-9a-f]{64}$ ||
    ! "$report_bytes" =~ ^[1-9][0-9]*$ ||
    ! "$report_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    native_kicad_drc_rc=2
  fi
  if { [[ -n "$project_bytes" ]] && [[ -z "$project_sha256" ]]; } ||
    { [[ -z "$project_bytes" ]] && [[ -n "$project_sha256" ]]; } ||
    { [[ -n "$rules_file_bytes" ]] && [[ -z "$rules_file_sha256" ]]; } ||
    { [[ -z "$rules_file_bytes" ]] && [[ -n "$rules_file_sha256" ]]; } ||
    [[ -n "$project_bytes" && ! "$project_bytes" =~ ^[1-9][0-9]*$ ]] ||
    [[ -n "$project_sha256" && ! "$project_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    [[ -n "$rules_file_bytes" && ! "$rules_file_bytes" =~ ^[1-9][0-9]*$ ]] ||
    [[ -n "$rules_file_sha256" && ! "$rules_file_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    native_kicad_drc_rc=2
  fi
  if ((native_kicad_drc_rc == 0)); then
    if [[ "$native_kicad_drc_mode" == "verify" ]]; then
      if ! PYTHONPATH="$action_script_dir" python3 - \
        "$native_kicad_drc_retained_report" \
        "$native_kicad_drc_report_candidate" \
        "$report_bytes" \
        "$report_sha256" <<'PY'
import hashlib
import sys

from ci_runtime import ExecutionBoundaryError, atomic_write_no_clobber, read_bytes

REPORT_MAX_BYTES = 32 * 1024 * 1024

source, destination, expected_bytes, expected_sha256 = sys.argv[1:]
try:
    expected_size = int(expected_bytes)
    # Read the authenticated source twice immediately before publication. A
    # source mutation is therefore rejected instead of copied into evidence.
    first = read_bytes(source, max_bytes=REPORT_MAX_BYTES)
    second = read_bytes(source, max_bytes=REPORT_MAX_BYTES)
    if first != second:
        raise ExecutionBoundaryError("retained report changed between bounded reads")
    if len(first) != expected_size or hashlib.sha256(first).hexdigest() != expected_sha256:
        raise ExecutionBoundaryError("retained report no longer matches authenticated summary")
    # Publish the exact authenticated bytes through the bounded no-clobber
    # primitive; links, aliases, and creator races fail closed.
    atomic_write_no_clobber(destination, first, max_bytes=REPORT_MAX_BYTES)
except (ExecutionBoundaryError, OSError, TypeError, ValueError) as error:
    print(f"could not publish authenticated retained report: {error}", file=sys.stderr)
    raise SystemExit(2)
PY
      then
        native_kicad_drc_rc=2
      fi
      if ((native_kicad_drc_rc == 0)); then
        native_kicad_drc_copy_summary_arguments=(
          --verify
          "--board=$PCBEX_NATIVE_KICAD_DRC_BOARD"
          "--report=$native_kicad_drc_report_candidate"
        )
        if [[ -n "$native_kicad_drc_project" ]]; then
          native_kicad_drc_copy_summary_arguments+=("--project=$native_kicad_drc_project")
        fi
        if [[ -n "$native_kicad_drc_rules_file" ]]; then
          native_kicad_drc_copy_summary_arguments+=("--rules-file=$native_kicad_drc_rules_file")
        fi
        native_kicad_drc_copy_summary_json=""
        if native_kicad_drc_copy_summary_json="$({
          printf '%s\n' "$native_kicad_drc_summary_json" |
            python3 "$action_script_dir/native_kicad_drc_summary.py" \
              "${native_kicad_drc_copy_summary_arguments[@]}"
        })"; then
          if ! python3 - "$native_kicad_drc_summary_json" "$native_kicad_drc_copy_summary_json" <<'PY'
import json
import sys

try:
    original = json.loads(sys.argv[1])
    copied = json.loads(sys.argv[2])
except (IndexError, json.JSONDecodeError, TypeError, ValueError):
    raise SystemExit(2)
if type(original) is not dict or type(copied) is not dict or original != copied:
    raise SystemExit(2)
PY
          then
            native_kicad_drc_rc=2
          fi
        else
          native_kicad_drc_rc=2
        fi
      fi
    fi
    if ((native_kicad_drc_rc == 0)) &&
      [[ -f "$native_kicad_drc_report_candidate" &&
        ! -L "$native_kicad_drc_report_candidate" ]]; then
      native_kicad_drc_report="$native_kicad_drc_report_candidate"
    else
      native_kicad_drc_rc=2
    fi
  fi
else
  native_kicad_drc_rc=2
fi

{
  printf '# pcbex native KiCad PCB DRC\n\n'
  printf -- '- Approved: `%s`\n' "${approved:-unavailable}"
  printf -- '- Violations: `%s`\n' "${violation_count:-unavailable}"
  printf -- '- Unconnected items: `%s`\n' "${unconnected_item_count:-unavailable}"
  printf -- '- Schematic parity: `%s`\n' "${schematic_parity_count:-unavailable}"
  printf -- '- Errors: `%s`\n' "${error_count:-unavailable}"
  printf -- '- Warnings: `%s`\n' "${warning_count:-unavailable}"
  printf -- '- Ignored checks: `%s`\n' "${ignored_check_count:-unavailable}"
  if [[ -n "$native_kicad_drc_report" ]]; then
    printf -- '- Report: `%s`\n' "$native_kicad_drc_report"
  else
    printf -- '- Report: unavailable\n'
  fi
} >> "$GITHUB_STEP_SUMMARY"

if ((native_kicad_drc_rc != 0)); then
  exit "$native_kicad_drc_rc"
fi

write_output native-kicad-drc-report "$native_kicad_drc_report"
write_output schema-version "$schema_version"
write_output approved "$approved"
write_output violation-count "$violation_count"
write_output unconnected-item-count "$unconnected_item_count"
write_output schematic-parity-count "$schematic_parity_count"
write_output error-count "$error_count"
write_output warning-count "$warning_count"
write_output ignored-check-count "$ignored_check_count"
write_output board-bytes "$board_bytes"
write_output board-sha256 "$board_sha256"
write_output project-bytes "$project_bytes"
write_output project-sha256 "$project_sha256"
write_output rules-file-bytes "$rules_file_bytes"
write_output rules-file-sha256 "$rules_file_sha256"
write_output run-sha256 "$run_sha256"
write_output report-bytes "$report_bytes"
write_output report-sha256 "$report_sha256"
write_output status ok

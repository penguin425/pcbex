#!/usr/bin/env bash
set -euo pipefail

required_variables=(
  GITHUB_OUTPUT
  GITHUB_STEP_SUMMARY
  PCBEX_BINARY
  PCBEX_NATIVE_KICAD_ERC_SCHEMATIC
  PCBEX_NATIVE_KICAD_ERC_KICAD_CLI
  PCBEX_NATIVE_KICAD_ERC_REQUIRE_APPROVED
  PCBEX_OUTPUT_DIR
)
for variable in "${required_variables[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "required environment variable is empty: $variable" >&2
    exit 2
  fi
done

action_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
native_kicad_erc_mode="${PCBEX_NATIVE_KICAD_ERC_MODE:-run}"
native_kicad_erc_retained_report="${PCBEX_NATIVE_KICAD_ERC_REPORT:-}"
case "$native_kicad_erc_mode" in
  run)
    if [[ -n "$native_kicad_erc_retained_report" ]]; then
      echo "report must be empty when mode is run" >&2
      exit 2
    fi
    ;;
  verify)
    if [[ -z "$native_kicad_erc_retained_report" ]]; then
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
  "--path=$PCBEX_NATIVE_KICAD_ERC_SCHEMATIC"
if [[ -n "${PCBEX_NATIVE_KICAD_ERC_WARNING_POLICY:-}" ]]; then
  python3 "$action_script_dir/ci_runtime.py" validate-input \
    "--path=$PCBEX_NATIVE_KICAD_ERC_WARNING_POLICY"
fi
if [[ "$native_kicad_erc_mode" == "verify" ]]; then
  python3 "$action_script_dir/ci_runtime.py" validate-input \
    "--path=$native_kicad_erc_retained_report"
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
    echo "PCBEX_OUTPUT_DIR must be empty before native KiCad ERC" >&2
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
write_output native-kicad-erc-report ""
write_output native-kicad-erc-schema-version ""
write_output native-kicad-erc-approved ""
write_output native-kicad-erc-error-count ""
write_output native-kicad-erc-warning-count ""
write_output native-kicad-erc-policy-failure-count ""
write_output native-kicad-erc-warning-policy-sha256 ""
write_output native-kicad-erc-warning-policy-source-bytes ""
write_output native-kicad-erc-warning-policy-source-sha256 ""
write_output native-kicad-erc-run-sha256 ""
write_output native-kicad-erc-report-bytes ""
write_output native-kicad-erc-report-sha256 ""

case "$PCBEX_NATIVE_KICAD_ERC_REQUIRE_APPROVED" in
  true|false) ;;
  *)
    echo "PCBEX_NATIVE_KICAD_ERC_REQUIRE_APPROVED must be true or false" >&2
    exit 2
    ;;
esac

native_kicad_erc_warning_policy="${PCBEX_NATIVE_KICAD_ERC_WARNING_POLICY:-}"
native_kicad_erc_report_candidate="${artifact_dir}/native-kicad-erc.json"
if [[ -e "$native_kicad_erc_report_candidate" ||
  -L "$native_kicad_erc_report_candidate" ]]; then
  echo "refusing to reuse an existing boardless native KiCad ERC report" >&2
  exit 2
fi

# The output directory was empty when this script started, so this is the
# only report path that this wrapper is allowed to remove on an authentication
# failure.  Never recurse or follow a link while cleaning up a failed run.
cleanup_candidate_on_failure() {
  if ! PYTHONPATH="$action_script_dir" python3 - "$artifact_dir" <<'PY'
import os
import stat
import sys

directory = sys.argv[1]
basename = "native-kicad-erc.json"
if not all(
    hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "supports_dir_fd")
):
    raise SystemExit(2)
if os.stat not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
    raise SystemExit(2)
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
try:
    directory_fd = os.open(directory, flags)
except OSError:
    raise SystemExit(2)
try:
    try:
        metadata = os.stat(basename, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise SystemExit(0)
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(2)
    try:
        os.unlink(basename, dir_fd=directory_fd)
    except FileNotFoundError:
        pass
finally:
    os.close(directory_fd)
PY
  then
    # A platform without race-resistant dir-fd primitives must fail closed:
    # do not let the always-running artifact boundary upload an unverified
    # candidate if it could not be safely removed.
    write_output artifact-dir ""
  fi
}

if [[ "$native_kicad_erc_mode" == "run" ]]; then
  native_kicad_erc_arguments=(
    run-native-kicad-erc
    "--output=$native_kicad_erc_report_candidate"
    "--kicad-cli=$PCBEX_NATIVE_KICAD_ERC_KICAD_CLI"
    --mcp-echo-report-summary
  )
  native_kicad_erc_summary_report="$native_kicad_erc_report_candidate"
else
  native_kicad_erc_arguments=(
    verify-native-kicad-erc-report
    "--kicad-cli=$PCBEX_NATIVE_KICAD_ERC_KICAD_CLI"
    --mcp-echo-report-summary
  )
  native_kicad_erc_summary_report="$native_kicad_erc_retained_report"
fi
native_kicad_erc_summary_arguments=(
  --verify
  "--schematic=$PCBEX_NATIVE_KICAD_ERC_SCHEMATIC"
  "--report=$native_kicad_erc_summary_report"
)
if [[ -n "$native_kicad_erc_warning_policy" ]]; then
  native_kicad_erc_arguments+=(
    "--warning-policy=$native_kicad_erc_warning_policy"
  )
  native_kicad_erc_summary_arguments+=(
    "--warning-policy=$native_kicad_erc_warning_policy"
  )
fi
if [[ "$native_kicad_erc_mode" == "run" ]]; then
  native_kicad_erc_arguments+=(-- "$PCBEX_NATIVE_KICAD_ERC_SCHEMATIC")
else
  # Keep caller-controlled paths after `--`: a basename can never become an
  # option to clap or KiCad, even when it begins with a dash.
  native_kicad_erc_arguments+=(-- "$PCBEX_NATIVE_KICAD_ERC_SCHEMATIC" "$native_kicad_erc_retained_report")
fi

native_kicad_erc_summary_json=""
if native_kicad_erc_summary_json="$(
  python3 "$action_script_dir/ci_runtime.py" exec \
    --timeout-seconds 600 \
    --max-stdout-bytes 4096 \
    --max-stderr-bytes 8388608 \
    "--output-root=$PCBEX_OUTPUT_DIR" \
    -- "$PCBEX_BINARY" "${native_kicad_erc_arguments[@]}" |
  python3 "$action_script_dir/native_kicad_erc_summary.py" \
    "${native_kicad_erc_summary_arguments[@]}"
)"; then
  native_kicad_erc_rc=0
else
  native_kicad_erc_rc=$?
fi

native_kicad_erc_report=""
native_kicad_erc_schema_version=""
native_kicad_erc_approved=""
native_kicad_erc_error_count=""
native_kicad_erc_warning_count=""
native_kicad_erc_policy_failure_count=""
native_kicad_erc_warning_policy_sha256=""
native_kicad_erc_warning_policy_source_bytes=""
native_kicad_erc_warning_policy_source_sha256=""
native_kicad_erc_run_sha256=""
native_kicad_erc_report_bytes=""
native_kicad_erc_report_sha256=""

if ((native_kicad_erc_rc == 0)) &&
  [[ -n "$native_kicad_erc_summary_json" ]] &&
  { [[ "$native_kicad_erc_mode" == "verify" ]] ||
    [[ -f "$native_kicad_erc_report_candidate" &&
      ! -L "$native_kicad_erc_report_candidate" ]]; }; then
  native_kicad_erc_summary_values=""
  if native_kicad_erc_summary_values="$(
    python3 - "$native_kicad_erc_summary_json" <<'PY'
import json
import sys

v1_fields = (
    "schema_version",
    "approved",
    "error_count",
    "run_sha256",
    "report_bytes",
    "report_sha256",
)
v2_fields = v1_fields + (
    "warning_count",
    "policy_failure_count",
    "warning_policy_sha256",
    "warning_policy_source_bytes",
    "warning_policy_source_sha256",
)
value = json.loads(sys.argv[1])
if type(value) is not dict:
    raise SystemExit(2)
schema_version = value.get("schema_version")
expected = v1_fields if schema_version == 1 else v2_fields if schema_version == 2 else ()
if not expected or set(value) != set(expected) or len(value) != len(expected):
    raise SystemExit(2)
for field in v2_fields:
    item = value.get(field, "")
    if type(item) is bool:
        rendered = str(item).lower()
    elif type(item) in (int, str):
        rendered = str(item)
    else:
        raise SystemExit(2)
    print(f"{field}={rendered}")
PY
  )"; then
    while IFS='=' read -r field value; do
      case "$field" in
        schema_version) native_kicad_erc_schema_version="$value" ;;
        approved) native_kicad_erc_approved="$value" ;;
        error_count) native_kicad_erc_error_count="$value" ;;
        warning_count) native_kicad_erc_warning_count="$value" ;;
        policy_failure_count) native_kicad_erc_policy_failure_count="$value" ;;
        warning_policy_sha256) native_kicad_erc_warning_policy_sha256="$value" ;;
        warning_policy_source_bytes) native_kicad_erc_warning_policy_source_bytes="$value" ;;
        warning_policy_source_sha256) native_kicad_erc_warning_policy_source_sha256="$value" ;;
        run_sha256) native_kicad_erc_run_sha256="$value" ;;
        report_bytes) native_kicad_erc_report_bytes="$value" ;;
        report_sha256) native_kicad_erc_report_sha256="$value" ;;
        *) native_kicad_erc_rc=2 ;;
      esac
    done <<< "$native_kicad_erc_summary_values"
  else
    native_kicad_erc_rc=2
  fi

  if [[ ! "$native_kicad_erc_schema_version" =~ ^[12]$ ||
    ! "$native_kicad_erc_approved" =~ ^(true|false)$ ||
    ! "$native_kicad_erc_error_count" =~ ^(0|[1-9][0-9]*)$ ||
    ! "$native_kicad_erc_run_sha256" =~ ^[0-9a-f]{64}$ ||
    ! "$native_kicad_erc_report_bytes" =~ ^[1-9][0-9]*$ ||
    ! "$native_kicad_erc_report_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    native_kicad_erc_rc=2
  elif [[ "$native_kicad_erc_schema_version" == "2" ]] &&
    { [[ ! "$native_kicad_erc_warning_count" =~ ^(0|[1-9][0-9]*)$ ]] ||
      [[ ! "$native_kicad_erc_policy_failure_count" =~ ^(0|[1-9][0-9]*)$ ]] ||
      [[ ! "$native_kicad_erc_warning_policy_sha256" =~ ^[0-9a-f]{64}$ ]] ||
      [[ ! "$native_kicad_erc_warning_policy_source_bytes" =~ ^[1-9][0-9]*$ ]] ||
      [[ ! "$native_kicad_erc_warning_policy_source_sha256" =~ ^[0-9a-f]{64}$ ]]; }; then
    native_kicad_erc_rc=2
  elif [[ "$native_kicad_erc_schema_version" == "1" ]] &&
    [[ -n "$native_kicad_erc_warning_count" ||
      -n "$native_kicad_erc_policy_failure_count" ||
      -n "$native_kicad_erc_warning_policy_sha256" ||
      -n "$native_kicad_erc_warning_policy_source_bytes" ||
      -n "$native_kicad_erc_warning_policy_source_sha256" ]]; then
    native_kicad_erc_rc=2
  fi

  if ((native_kicad_erc_rc == 0)); then
    if [[ "$native_kicad_erc_mode" == "verify" ]]; then
      if ! PYTHONPATH="$action_script_dir" python3 - \
        "$native_kicad_erc_retained_report" \
        "$native_kicad_erc_report_candidate" \
        "$native_kicad_erc_report_bytes" \
        "$native_kicad_erc_report_sha256" <<'PY'
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
        native_kicad_erc_rc=2
      fi
      if ((native_kicad_erc_rc == 0)); then
        native_kicad_erc_copy_summary_arguments=(
          --verify
          "--schematic=$PCBEX_NATIVE_KICAD_ERC_SCHEMATIC"
          "--report=$native_kicad_erc_report_candidate"
        )
        if [[ -n "$native_kicad_erc_warning_policy" ]]; then
          native_kicad_erc_copy_summary_arguments+=(
            "--warning-policy=$native_kicad_erc_warning_policy"
          )
        fi
        native_kicad_erc_copy_summary_json=""
        if native_kicad_erc_copy_summary_json="$({
          printf '%s\n' "$native_kicad_erc_summary_json" |
            python3 "$action_script_dir/native_kicad_erc_summary.py" \
              "${native_kicad_erc_copy_summary_arguments[@]}"
        })"; then
          if ! python3 - "$native_kicad_erc_summary_json" "$native_kicad_erc_copy_summary_json" <<'PY'
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
            native_kicad_erc_rc=2
          fi
        else
          native_kicad_erc_rc=2
        fi
      fi
    fi
    if ((native_kicad_erc_rc == 0)) &&
      [[ -f "$native_kicad_erc_report_candidate" &&
        ! -L "$native_kicad_erc_report_candidate" ]]; then
      native_kicad_erc_report="$native_kicad_erc_report_candidate"
    else
      native_kicad_erc_rc=2
    fi
  fi
else
  native_kicad_erc_rc=2
fi

# Re-authenticate the exact artifact immediately before exposing any output
# fields.  The first summary check authenticates the CLI response, while this
# second pass closes the post-check mutation window for both run and replay.
if ((native_kicad_erc_rc == 0)); then
  if [[ ! -f "$native_kicad_erc_report_candidate" ||
    -L "$native_kicad_erc_report_candidate" ]]; then
    native_kicad_erc_rc=2
  else
    native_kicad_erc_final_summary_arguments=(
      --verify
      "--schematic=$PCBEX_NATIVE_KICAD_ERC_SCHEMATIC"
      "--report=$native_kicad_erc_report_candidate"
    )
    if [[ -n "$native_kicad_erc_warning_policy" ]]; then
      native_kicad_erc_final_summary_arguments+=(
        "--warning-policy=$native_kicad_erc_warning_policy"
      )
    fi
    native_kicad_erc_final_summary_json=""
    if native_kicad_erc_final_summary_json="$({
      printf '%s\n' "$native_kicad_erc_summary_json" |
        python3 "$action_script_dir/native_kicad_erc_summary.py" \
          "${native_kicad_erc_final_summary_arguments[@]}"
    })"; then
      if ! python3 - "$native_kicad_erc_summary_json" "$native_kicad_erc_final_summary_json" <<'PY'
import json
import sys

try:
    original = json.loads(sys.argv[1])
    final = json.loads(sys.argv[2])
except (IndexError, json.JSONDecodeError, TypeError, ValueError):
    raise SystemExit(2)
if type(original) is not dict or type(final) is not dict or original != final:
    raise SystemExit(2)
PY
      then
        native_kicad_erc_rc=2
      fi
      if ((native_kicad_erc_rc == 0)); then
        if ! PYTHONPATH="$action_script_dir" python3 - \
          "$native_kicad_erc_report_candidate" \
          "$native_kicad_erc_report_bytes" \
          "$native_kicad_erc_report_sha256" <<'PY'
import hashlib
import sys

from ci_runtime import ExecutionBoundaryError, read_bytes

REPORT_MAX_BYTES = 32 * 1024 * 1024
path, expected_bytes, expected_sha256 = sys.argv[1:]
try:
    first = read_bytes(path, max_bytes=REPORT_MAX_BYTES)
    second = read_bytes(path, max_bytes=REPORT_MAX_BYTES)
    if first != second:
        raise ExecutionBoundaryError("native KiCad ERC report changed between bounded reads")
    if len(first) != int(expected_bytes) or hashlib.sha256(first).hexdigest() != expected_sha256:
        raise ExecutionBoundaryError("native KiCad ERC report no longer matches authenticated summary")
except (ExecutionBoundaryError, OSError, TypeError, ValueError) as error:
    print(f"native KiCad ERC report authentication failed: {error}", file=sys.stderr)
    raise SystemExit(2)
PY
        then
          native_kicad_erc_rc=2
        fi
      fi
    else
      native_kicad_erc_rc=2
    fi
  fi
fi

if ((native_kicad_erc_rc != 0)); then
  native_kicad_erc_report=""
  cleanup_candidate_on_failure
  # Do not let the always-running artifact boundary inspect/upload a failed
  # output tree, even when cleanup succeeded and left an empty directory.
  write_output artifact-dir ""
fi

{
  printf '# pcbex boardless native KiCad ERC\n\n'
  printf -- '- Approved: `%s`\n' "${native_kicad_erc_approved:-unavailable}"
  printf -- '- Errors: `%s`\n' "${native_kicad_erc_error_count:-unavailable}"
  if [[ -n "$native_kicad_erc_warning_count" ]]; then
    printf -- '- Warnings: `%s`\n' "$native_kicad_erc_warning_count"
    printf -- '- Warning-policy failures: `%s`\n' "$native_kicad_erc_policy_failure_count"
  fi
  if [[ -n "$native_kicad_erc_report" ]]; then
    printf -- '- Report: `%s`\n' "$native_kicad_erc_report"
  else
    printf -- '- Report: unavailable\n'
  fi
} >> "$GITHUB_STEP_SUMMARY"

if ((native_kicad_erc_rc != 0)); then
  exit "$native_kicad_erc_rc"
fi

write_output native-kicad-erc-report "$native_kicad_erc_report"
write_output native-kicad-erc-schema-version "$native_kicad_erc_schema_version"
write_output native-kicad-erc-approved "$native_kicad_erc_approved"
write_output native-kicad-erc-error-count "$native_kicad_erc_error_count"
write_output native-kicad-erc-warning-count "$native_kicad_erc_warning_count"
write_output native-kicad-erc-policy-failure-count "$native_kicad_erc_policy_failure_count"
write_output native-kicad-erc-warning-policy-sha256 "$native_kicad_erc_warning_policy_sha256"
write_output native-kicad-erc-warning-policy-source-bytes "$native_kicad_erc_warning_policy_source_bytes"
write_output native-kicad-erc-warning-policy-source-sha256 "$native_kicad_erc_warning_policy_source_sha256"
write_output native-kicad-erc-run-sha256 "$native_kicad_erc_run_sha256"
write_output native-kicad-erc-report-bytes "$native_kicad_erc_report_bytes"
write_output native-kicad-erc-report-sha256 "$native_kicad_erc_report_sha256"
write_output status ok

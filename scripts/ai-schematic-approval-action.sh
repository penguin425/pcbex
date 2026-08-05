#!/usr/bin/env bash
set -euo pipefail

# This wrapper deliberately has no provider, network, or secret boundary.  It
# only forwards bounded workspace files to the local pcbex verifier and
# publishes its schema-v1 report after closed structural revalidation.

MAX_MEMBERS=100

required_variables=(
  GITHUB_OUTPUT
  GITHUB_STEP_SUMMARY
  PCBEX_REPOSITORY_ROOT
  PCBEX_AI_SCHEMATIC
  PCBEX_AI_REQUEST
  PCBEX_AI_APPROVAL_FILES
  PCBEX_AI_RESPONSE_FILES
  PCBEX_AI_POLICY_PACK
  PCBEX_AI_MINIMUM_APPROVALS
  PCBEX_AI_MINIMUM_DISTINCT_PROVIDERS
  PCBEX_AI_MINIMUM_DISTINCT_MODELS
  PCBEX_OUTPUT_DIR
)
for variable in "${required_variables[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "required environment variable is empty: $variable" >&2
    exit 2
  fi
done

repository_root="$PCBEX_REPOSITORY_ROOT"
runtime_script="$repository_root/scripts/ci_runtime.py"
evidence_helper="$repository_root/scripts/ai_schematic_approval_evidence.py"
mode="${1:-}"
preflight_mode=false
revalidate_mode=false
if [[ "$mode" == "--preflight" ]]; then
  preflight_mode=true
fi
if [[ "$mode" == "--revalidate" ]]; then
  revalidate_mode=true
fi
if [[ ! -f "$runtime_script" ]]; then
  echo "pcbex runtime helper is unavailable" >&2
  exit 2
fi
if [[ ! -f "$evidence_helper" ]]; then
  echo "pcbex evidence helper is unavailable" >&2
  exit 2
fi
if [[ "$preflight_mode" == false && "$revalidate_mode" == false &&
  ( -z "${PCBEX_BINARY:-}" || ! -f "$PCBEX_BINARY" || ! -x "$PCBEX_BINARY" ) ]]; then
  echo "pcbex verifier is unavailable" >&2
  exit 2
fi

write_output() {
  # Every value passed here is either a fixed literal or a path already
  # rejected for control characters. Never use multiline GITHUB_OUTPUT data.
  printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
}

load_paths() {
  local raw="$1"
  local label="$2"
  local -n destination="$3"
  local line
  destination=()
  # A YAML block scalar normally ends with one newline. Remove that single
  # terminator before the here-string adds its own record delimiter; interior
  # blank records remain rejected.
  if [[ "$raw" == *$'\n' ]]; then
    raw="${raw%$'\n'}"
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$line" ]]; then
      echo "$label must contain one non-empty relative path per line" >&2
      return 2
    fi
    destination+=("$line")
  done <<< "$raw"
  if (( ${#destination[@]} < 1 || ${#destination[@]} > MAX_MEMBERS )); then
    echo "$label must contain 1 through $MAX_MEMBERS paths" >&2
    return 2
  fi
}

validate_input_path() {
  local path="$1"
  python3 "$runtime_script" validate-input "--path=$path"
}

validate_common_inputs() {
  case "${PCBEX_AI_REQUIRE_QUORUM:-false}" in
    true|false) ;;
    *) echo "require-quorum must be true or false" >&2; return 2 ;;
  esac
  case "${PCBEX_AI_UPLOAD_ARTIFACT:-true}" in
    true|false) ;;
    *) echo "upload-artifact must be true or false" >&2; return 2 ;;
  esac
  if [[ -z "${PCBEX_AI_ARTIFACT_NAME:-}" ]]; then
    echo "artifact-name must not be empty" >&2
    return 2
  fi
  if [[ "$PCBEX_AI_ARTIFACT_NAME" =~ [[:cntrl:]] ]]; then
    echo "artifact-name must not contain control characters" >&2
    return 2
  fi
  if [[ ! "${PCBEX_AI_RETENTION_DAYS:-}" =~ ^([1-9]|[1-8][0-9]|90)$ ]]; then
    echo "retention-days must be an integer from 1 through 90" >&2
    return 2
  fi
  local pair label value
  for pair in \
    "minimum-approvals:$PCBEX_AI_MINIMUM_APPROVALS" \
    "minimum-distinct-providers:$PCBEX_AI_MINIMUM_DISTINCT_PROVIDERS" \
    "minimum-distinct-models:$PCBEX_AI_MINIMUM_DISTINCT_MODELS"; do
    label="${pair%%:*}"
    value="${pair#*:}"
    if [[ ! "$value" =~ ^([1-9]|[1-9][0-9]|100)$ ]]; then
      echo "$label must be an integer from 1 through 100" >&2
      return 2
    fi
  done
  if [[ -z "$PCBEX_OUTPUT_DIR" ]]; then
    echo "output-dir must not be empty" >&2
    return 2
  fi
  python3 "$runtime_script" validate-output "--output-root=$PCBEX_OUTPUT_DIR"
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

all_input_paths=()

snapshot_inputs() {
  PYTHONPATH="$repository_root/scripts" python3 \
    "$evidence_helper" snapshot "${all_input_paths[@]}"
}

validate_bounded_inputs() {
  all_input_paths=("$PCBEX_AI_SCHEMATIC" "$PCBEX_AI_REQUEST" "$PCBEX_AI_POLICY_PACK")
  if [[ -n "${PCBEX_AI_SESSION:-}" ]]; then
    all_input_paths+=("$PCBEX_AI_SESSION")
  fi
  all_input_paths+=("${approval_paths[@]}" "${response_paths[@]}")
  local path
  for path in "${all_input_paths[@]}"; do
    validate_input_path "$path"
  done
  # The snapshot helper performs two bounded descriptor reads per input and
  # enforces both the per-file and aggregate byte ceilings.
  snapshot_inputs >/dev/null
}

read_request_metadata() {
  PYTHONPATH="$repository_root/scripts" python3 - "$PCBEX_AI_REQUEST" <<'PY'
import json
import re
import sys

from ci_runtime import ExecutionBoundaryError, read_bytes

MAX_REQUEST_BYTES = 32 * 1024 * 1024
path = sys.argv[1]
try:
    payload = read_bytes(path, max_bytes=MAX_REQUEST_BYTES)
    value = json.loads(payload.decode("utf-8"))
except (ExecutionBoundaryError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    print(f"invalid AI review request: {error}", file=sys.stderr)
    raise SystemExit(2)
if (
    type(value) is not dict
    or type(value.get("schema_version")) is not int
    or value.get("schema_version") != 1
):
    print("AI schematic approval Action requires request schema_version 1", file=sys.stderr)
    raise SystemExit(2)
if "artifact_binding" in value:
    print("schema-v1 AI review request must not contain artifact_binding", file=sys.stderr)
    raise SystemExit(2)
request_sha = value.get("request_sha256")
review = value.get("electrical_review")
schematic = value.get("schematic")
ir_sha = review.get("schematic_sha256") if type(review) is dict else None
if not isinstance(request_sha, str) or re.fullmatch(r"[0-9a-f]{64}", request_sha) is None:
    print("AI review request_sha256 is malformed", file=sys.stderr)
    raise SystemExit(2)
if not isinstance(ir_sha, str) or re.fullmatch(r"[0-9a-f]{64}", ir_sha) is None:
    print("AI review schematic IR SHA-256 is malformed", file=sys.stderr)
    raise SystemExit(2)
if type(schematic) is not dict:
    print("AI review request schematic is malformed", file=sys.stderr)
    raise SystemExit(2)
print(f"request-sha256={request_sha}")
print(f"schematic-ir-sha256={ir_sha}")
PY
}

cleanup_outputs() {
  # The output root was checked as fresh and is never recursively removed.
  # Use a no-follow directory descriptor so a replacement symlink cannot make
  # cleanup unlink a file outside the caller workspace.
  python3 - "$PCBEX_OUTPUT_DIR" <<'PY' || true
import os
import stat
import sys

directory = sys.argv[1]
names = ("ai-approval-quorum.json", "ai-approval-quorum.md")
if not all(
    hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "supports_dir_fd")
):
    raise SystemExit(2)
if os.stat not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
    raise SystemExit(2)
try:
    descriptor = os.open(
        directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
except OSError:
    raise SystemExit(2)
try:
    for name in names:
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            raise SystemExit(2)
        try:
            os.unlink(name, dir_fd=descriptor)
        except FileNotFoundError:
            pass
finally:
    os.close(descriptor)
PY
}

cleanup_summary_candidate() {
  # A verifier must never be able to choose the Markdown that gets published.
  # Remove only the fixed candidate name, without following a replacement
  # symlink, before the wrapper writes its canonical summary.
  python3 - "$PCBEX_OUTPUT_DIR" <<'PY'
import os
import stat
import sys

directory = sys.argv[1]
name = "ai-approval-quorum.md"
if not all(hasattr(os, item) for item in ("O_DIRECTORY", "O_NOFOLLOW", "supports_dir_fd")):
    raise SystemExit(2)
if os.stat not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
    raise SystemExit(2)
try:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as error:
    print(f"could not open AI quorum output directory: {error}", file=sys.stderr)
    raise SystemExit(2)
try:
    try:
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        raise SystemExit(0)
    if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
        print("AI quorum summary candidate is not a regular file", file=sys.stderr)
        raise SystemExit(2)
    os.unlink(name, dir_fd=descriptor)
finally:
    os.close(descriptor)
PY
}

preflight() {
  validate_common_inputs
  load_paths "$PCBEX_AI_APPROVAL_FILES" approval approval_paths
  load_paths "$PCBEX_AI_RESPONSE_FILES" response response_paths
  if (( ${#approval_paths[@]} != ${#response_paths[@]} )); then
    echo "approval-files and response-files must contain the same number of paths" >&2
    return 2
  fi
  validate_bounded_inputs
  request_metadata="$(read_request_metadata)"
  request_sha256=""
  schematic_ir_sha256=""
  while IFS='=' read -r key value; do
    case "$key" in
      request-sha256) request_sha256="$value" ;;
      schematic-ir-sha256) schematic_ir_sha256="$value" ;;
      *) echo "invalid request metadata" >&2; return 2 ;;
    esac
  done <<< "$request_metadata"
  if [[ ! "$request_sha256" =~ ^[0-9a-f]{64}$ ||
    ! "$schematic_ir_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "request metadata is malformed" >&2
    return 2
  fi
  validate_fresh_output_dir
}

publication_revalidate() {
  if [[ "$#" -ne 1 ]]; then
    echo "unknown wrapper argument" >&2
    return 2
  fi
  validate_common_inputs
  load_paths "$PCBEX_AI_APPROVAL_FILES" approval approval_paths
  load_paths "$PCBEX_AI_RESPONSE_FILES" response response_paths
  if (( ${#approval_paths[@]} != ${#response_paths[@]} )); then
    echo "approval-files and response-files must contain the same number of paths" >&2
    return 2
  fi
  validate_bounded_inputs
  if [[ -z "${PCBEX_AI_REPORT:-}" || -z "${PCBEX_AI_SUMMARY:-}" ]]; then
    echo "publication evidence paths are empty" >&2
    return 2
  fi
  if [[ "$PCBEX_AI_REPORT" != "$PCBEX_OUTPUT_DIR/ai-approval-quorum.json" ||
    "$PCBEX_AI_SUMMARY" != "$PCBEX_OUTPUT_DIR/ai-approval-quorum.md" ]]; then
    echo "publication evidence paths are not the fixed Action outputs" >&2
    return 2
  fi
  if [[ ! "${PCBEX_EXPECTED_INPUT_SNAPSHOT:-}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "expected input snapshot is malformed" >&2
    return 2
  fi
  current_snapshot="$(snapshot_inputs)"
  if [[ "$current_snapshot" != "$PCBEX_EXPECTED_INPUT_SNAPSHOT" ]]; then
    echo "AI approval inputs changed after verification" >&2
    return 2
  fi
  request_metadata="$(read_request_metadata)"
  request_sha256=""
  schematic_ir_sha256=""
  while IFS='=' read -r key value; do
    case "$key" in
      request-sha256) request_sha256="$value" ;;
      schematic-ir-sha256) schematic_ir_sha256="$value" ;;
      *) echo "invalid request metadata" >&2; return 2 ;;
    esac
  done <<< "$request_metadata"
  if [[ "${PCBEX_EXPECTED_QUORUM_MET:-}" != true &&
    "${PCBEX_EXPECTED_QUORUM_MET:-}" != false ]]; then
    echo "expected quorum result is malformed" >&2
    return 2
  fi
  local publication_metadata
  if ! publication_metadata="$(
    PYTHONPATH="$repository_root/scripts" python3 \
      "$evidence_helper" revalidate \
      "$PCBEX_AI_REPORT" "$PCBEX_AI_SUMMARY" "$request_sha256" \
      "$PCBEX_AI_MINIMUM_APPROVALS" \
      "$PCBEX_AI_MINIMUM_DISTINCT_PROVIDERS" \
      "$PCBEX_AI_MINIMUM_DISTINCT_MODELS"
  )"; then
    return 2
  fi
  local publication_quorum_met=""
  local key value
  while IFS="=" read -r key value; do
    case "$key" in
      quorum-met) publication_quorum_met="$value" ;;
      *) echo "publication evidence metadata is malformed" >&2; return 2 ;;
    esac
  done <<< "$publication_metadata"
  if [[ "$publication_quorum_met" != true && "$publication_quorum_met" != false ]]; then
    echo "publication quorum result is malformed" >&2
    return 2
  fi
  if [[ "$publication_quorum_met" != "$PCBEX_EXPECTED_QUORUM_MET" ]]; then
    echo "AI approval quorum result changed after verification" >&2
    return 2
  fi
  python3 "$runtime_script" scan \
    "--output-root=$PCBEX_OUTPUT_DIR" \
    --max-entries 2 \
    --max-depth 1 \
    --max-file-bytes 16777216 \
    --max-total-bytes 33554432 >/dev/null
  printf 'quorum-met=%s\n' "$publication_quorum_met" >> "$GITHUB_OUTPUT"
  printf 'safe=true\n' >> "$GITHUB_OUTPUT"
}

approval_paths=()
response_paths=()
request_metadata=""
request_sha256=""
schematic_ir_sha256=""
if [[ "$revalidate_mode" == true ]]; then
  publication_revalidate "$mode"
  exit 0
fi
preflight
if [[ "$preflight_mode" == true ]]; then
  if [[ "$#" -ne 1 ]]; then
    echo "unknown wrapper argument" >&2
    exit 2
  fi
  printf 'valid=true\n' >> "$GITHUB_OUTPUT"
  exit 0
fi
if [[ "$#" -ne 0 ]]; then
  echo "unknown wrapper argument" >&2
  exit 2
fi

mkdir -p -- "$PCBEX_OUTPUT_DIR"
validate_fresh_output_dir

write_output status error
write_output artifact-dir ""
write_output ai-approval-quorum ""
write_output ai-approval-quorum-summary ""
write_output ai-approval-quorum-met ""
write_output request-sha256 ""
write_output schematic-ir-sha256 ""
write_output input-snapshot-sha256 ""

report_path="$PCBEX_OUTPUT_DIR/ai-approval-quorum.json"
summary_path="$PCBEX_OUTPUT_DIR/ai-approval-quorum.md"
quorum_arguments=(verify-ai-quorum)
if [[ "$PCBEX_AI_REQUEST" == -* ]]; then
  request_after_options=true
else
  quorum_arguments+=("$PCBEX_AI_REQUEST")
  request_after_options=false
fi
quorum_arguments+=(
  "--schematic=$PCBEX_AI_SCHEMATIC"
  "--policy-pack=$PCBEX_AI_POLICY_PACK"
  "--minimum-approvals=$PCBEX_AI_MINIMUM_APPROVALS"
  "--minimum-distinct-providers=$PCBEX_AI_MINIMUM_DISTINCT_PROVIDERS"
  "--minimum-distinct-models=$PCBEX_AI_MINIMUM_DISTINCT_MODELS"
  "--output=$report_path"
)
if [[ -n "${PCBEX_AI_SESSION:-}" ]]; then
  quorum_arguments+=("--session=$PCBEX_AI_SESSION")
fi
for approval in "${approval_paths[@]}"; do
  quorum_arguments+=("--approval=$approval")
done
for response in "${response_paths[@]}"; do
  quorum_arguments+=("--response=$response")
done
if [[ "$request_after_options" == true ]]; then
  # Put the positional request after `--` so an option-like filename cannot
  # become a clap flag. All options and their values remain array elements.
  quorum_arguments+=(-- "$PCBEX_AI_REQUEST")
fi

# Capture the complete, stable input set immediately before invoking the
# verifier.  The matching post-verifier snapshot below turns replacement or
# mutation during execution into a hard failure.
input_snapshot_before="$(snapshot_inputs)"

quorum_rc=0
if python3 "$runtime_script" exec \
  --timeout-seconds 900 \
  --max-stdout-bytes 1048576 \
  --max-stderr-bytes 8388608 \
  --output-root="$PCBEX_OUTPUT_DIR" \
  -- "$PCBEX_BINARY" "${quorum_arguments[@]}"; then
  quorum_rc=0
else
  quorum_rc=$?
fi

input_snapshot_after=""
snapshot_after_rc=0
if input_snapshot_after="$(snapshot_inputs)"; then
  :
else
  snapshot_after_rc=$?
fi

if (( snapshot_after_rc != 0 )) || [[ "$input_snapshot_before" != "$input_snapshot_after" ]]; then
  cleanup_outputs
  write_output status error
  write_output artifact-dir ""
  echo "AI approval inputs changed during verifier execution" >&2
  printf '%s\n' '# pcbex AI schematic approval quorum' '' '- Report: unavailable' >> "$GITHUB_STEP_SUMMARY"
  exit 2
fi

if (( quorum_rc != 0 )); then
  cleanup_outputs
  write_output status error
  write_output artifact-dir ""
  printf '%s\n' '# pcbex AI schematic approval quorum' '' '- Report: unavailable' >> "$GITHUB_STEP_SUMMARY"
  exit "$quorum_rc"
fi

# Ignore any Markdown emitted by a verifier and publish only the fixed
# report-derived summary.
cleanup_summary_candidate
report_metadata=""
if ! report_metadata="$(PYTHONPATH="$repository_root/scripts" python3 "$evidence_helper" render "$report_path" "$summary_path" "$request_sha256" "$PCBEX_AI_MINIMUM_APPROVALS" "$PCBEX_AI_MINIMUM_DISTINCT_PROVIDERS" "$PCBEX_AI_MINIMUM_DISTINCT_MODELS")"; then
  cleanup_outputs
  write_output status error
  write_output artifact-dir ""
  printf '%s\n' '# pcbex AI schematic approval quorum' '' '- Report: unavailable' >> "$GITHUB_STEP_SUMMARY"
  exit 2
fi
ai_approval_quorum_met=""
while IFS="=" read -r key value; do
  case "$key" in
    quorum-met) ai_approval_quorum_met="$value" ;;
    report-bytes|summary-bytes) ;;
    *)
      cleanup_outputs
      write_output status error
      write_output artifact-dir ""
      exit 2
      ;;
  esac
done <<< "$report_metadata"
if [[ "$ai_approval_quorum_met" != true && "$ai_approval_quorum_met" != false ]]; then
  cleanup_outputs
  write_output status error
  write_output artifact-dir ""
  exit 2
fi

revalidated_metadata=""
if ! revalidated_metadata="$(PYTHONPATH="$repository_root/scripts" python3 "$evidence_helper" revalidate "$report_path" "$summary_path" "$request_sha256" "$PCBEX_AI_MINIMUM_APPROVALS" "$PCBEX_AI_MINIMUM_DISTINCT_PROVIDERS" "$PCBEX_AI_MINIMUM_DISTINCT_MODELS")"; then
  cleanup_outputs
  write_output status error
  write_output artifact-dir ""
  exit 2
fi
revalidated_quorum_met=""
while IFS="=" read -r key value; do
  case "$key" in
    quorum-met) revalidated_quorum_met="$value" ;;
    *)
      cleanup_outputs
      write_output status error
      write_output artifact-dir ""
      exit 2
      ;;
  esac
done <<< "$revalidated_metadata"
if [[ "$revalidated_quorum_met" != "$ai_approval_quorum_met" ]]; then
  cleanup_outputs
  write_output status error
  write_output artifact-dir ""
  exit 2
fi
if ! python3 - "$PCBEX_OUTPUT_DIR" <<'PY'
import os
import stat
import sys

expected = {"ai-approval-quorum.json", "ai-approval-quorum.md"}
try:
    with os.scandir(sys.argv[1]) as entries:
        names = []
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise SystemExit("AI quorum output tree contains a non-regular entry")
            names.append(entry.name)
except OSError as error:
    print(f"could not inspect AI quorum output tree: {error}", file=sys.stderr)
    raise SystemExit(2)
if set(names) != expected or len(names) != len(expected):
    raise SystemExit("AI quorum output tree contains unexpected files")
PY
then
  cleanup_outputs
  write_output status error
  write_output artifact-dir ""
  exit 2
fi

write_output status ok
write_output artifact-dir "$PCBEX_OUTPUT_DIR"
write_output ai-approval-quorum "$report_path"
write_output ai-approval-quorum-summary "$summary_path"
write_output ai-approval-quorum-met "$ai_approval_quorum_met"
write_output request-sha256 "$request_sha256"
write_output schematic-ir-sha256 "$schematic_ir_sha256"
write_output input-snapshot-sha256 "$input_snapshot_before"
{
  printf '# pcbex AI schematic approval quorum\n\n'
  cat -- "$summary_path"
} >> "$GITHUB_STEP_SUMMARY"

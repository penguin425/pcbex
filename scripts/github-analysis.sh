#!/usr/bin/env bash
set -euo pipefail

required_variables=(
  GITHUB_OUTPUT
  GITHUB_STEP_SUMMARY
  PCBEX_BINARY
  PCBEX_BOARD
  PCBEX_OUTPUT_DIR
)
for variable in "${required_variables[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "required environment variable is empty: $variable" >&2
    exit 2
  fi
done

case "${PCBEX_OUTPUT_DIR}" in
  /) echo "refusing to use the filesystem root as PCBEX_OUTPUT_DIR" >&2; exit 2 ;;
esac

artifact_dir="${PCBEX_OUTPUT_DIR}"
current_dir="${artifact_dir}/current"
baseline_dir="${artifact_dir}/baseline"
comparison_dir="${artifact_dir}/comparison"
sarif_dir="${artifact_dir}/sarif"
comment_body="${artifact_dir}/pr-comment.md"

mkdir -p "$current_dir" "$sarif_dir"

write_output() {
  printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
}

write_output status error
write_output artifact-dir "$artifact_dir"
write_output sarif-dir ""
write_output current-sarif ""
write_output comparison-sarif ""
write_output comment-body ""
write_output violation-count ""
write_output regression false
write_output verified-policy-trust-state ""
write_output fetched-signed-policy-pack ""
write_output policy-pack-fetch-receipt ""
write_output manufacturing-feedback ""
write_output manufacturing-feedback-passed ""
write_output policy-recommendation ""
write_output schematic-diff ""
write_output schematic-review-required ""
write_output schematic-reviewer-routing ""
write_output schematic-review-all-routed ""
write_output ai-approval-quorum ""
write_output ai-approval-quorum-met ""
write_output human-escalation ""
write_output human-escalation-approved ""
write_output schematic-approval-met ""
write_output approval-log-verification ""
write_output approval-log-verified ""
write_output approval-log-anchor-verification ""
write_output approval-log-anchored ""
write_output approval-log-witness-quorum ""
write_output approval-log-witness-quorum-met ""
write_output remote-witness ""
write_output remote-witness-receipt ""

analysis_arguments=(analyze-kicad "$PCBEX_BOARD" --output-dir "$current_dir")
profile_selections=0
if [[ -n "${PCBEX_FAB:-}" ]]; then ((profile_selections += 1)); fi
if [[ -n "${PCBEX_FAB_PROFILE:-}" ]]; then ((profile_selections += 1)); fi
if [[ -n "${PCBEX_POLICY_PACK:-}" ]]; then ((profile_selections += 1)); fi
if [[ -n "${PCBEX_SIGNED_POLICY_PACK:-}" ]]; then ((profile_selections += 1)); fi
if [[ -n "${PCBEX_POLICY_PACK_URL:-}" ]]; then ((profile_selections += 1)); fi
if ((profile_selections > 1)); then
  echo "physical policy inputs are mutually exclusive" >&2
  exit 2
fi
has_authenticated_policy_pack=false
has_policy_public_key=false
if [[ -n "${PCBEX_SIGNED_POLICY_PACK:-}" || -n "${PCBEX_POLICY_PACK_URL:-}" ]]; then
  has_authenticated_policy_pack=true
fi
if [[ -n "${PCBEX_POLICY_PUBLIC_KEY:-}" ]]; then has_policy_public_key=true; fi
if [[ "$has_authenticated_policy_pack" != "$has_policy_public_key" ]]; then
  echo "a signed local or remote policy pack and PCBEX_POLICY_PUBLIC_KEY must be supplied together" >&2
  exit 2
fi
if [[ -n "${PCBEX_POLICY_TRUST_STATE:-}" && "$has_authenticated_policy_pack" != "true" ]]; then
  echo "PCBEX_POLICY_TRUST_STATE requires a signed local or remote policy pack" >&2
  exit 2
fi
if [[ -n "${PCBEX_POLICY_PACK_BEARER_TOKEN:-}" && -z "${PCBEX_POLICY_PACK_URL:-}" ]]; then
  echo "PCBEX_POLICY_PACK_BEARER_TOKEN requires PCBEX_POLICY_PACK_URL" >&2
  exit 2
fi
effective_policy_pack="${PCBEX_POLICY_PACK:-}"
verified_policy_trust_state=""
fetched_signed_policy_pack=""
policy_pack_fetch_receipt=""
if [[ -n "${PCBEX_SIGNED_POLICY_PACK:-}" ]]; then
  effective_policy_pack="${artifact_dir}/verified-policy-pack.json"
  verified_policy_trust_state="${artifact_dir}/verified-policy-trust-state.json"
  verify_arguments=(verify-policy-pack \
    "$PCBEX_SIGNED_POLICY_PACK" \
    --public-key "$PCBEX_POLICY_PUBLIC_KEY" \
    --output "$effective_policy_pack" \
    --state-output "$verified_policy_trust_state")
  if [[ -n "${PCBEX_POLICY_TRUST_STATE:-}" ]]; then
    verify_arguments+=(--baseline-state "$PCBEX_POLICY_TRUST_STATE")
  fi
  "$PCBEX_BINARY" "${verify_arguments[@]}"
fi
if [[ -n "${PCBEX_POLICY_PACK_URL:-}" ]]; then
  fetched_signed_policy_pack="${artifact_dir}/fetched-signed-policy-pack.json"
  effective_policy_pack="${artifact_dir}/verified-policy-pack.json"
  verified_policy_trust_state="${artifact_dir}/verified-policy-trust-state.json"
  policy_pack_fetch_receipt="${artifact_dir}/policy-pack-fetch-receipt.json"
  fetch_arguments=(fetch-policy-pack \
    --endpoint "$PCBEX_POLICY_PACK_URL" \
    --public-key "$PCBEX_POLICY_PUBLIC_KEY" \
    --timeout-seconds "${PCBEX_POLICY_PACK_TIMEOUT_SECONDS:-30}" \
    --signed-output "$fetched_signed_policy_pack" \
    --output "$effective_policy_pack" \
    --state-output "$verified_policy_trust_state" \
    --receipt-output "$policy_pack_fetch_receipt")
  if [[ -n "${PCBEX_POLICY_TRUST_STATE:-}" ]]; then
    fetch_arguments+=(--baseline-state "$PCBEX_POLICY_TRUST_STATE")
  fi
  if [[ -n "${PCBEX_POLICY_PACK_BEARER_TOKEN:-}" ]]; then
    fetch_arguments+=(--bearer-token-env PCBEX_POLICY_PACK_BEARER_TOKEN)
  fi
  if [[ "${PCBEX_POLICY_PACK_ALLOW_HTTP_LOOPBACK:-false}" == "true" ]]; then
    fetch_arguments+=(--allow-http-loopback)
  fi
  "$PCBEX_BINARY" "${fetch_arguments[@]}"
fi
if [[ -n "${PCBEX_FAB:-}" ]]; then
  analysis_arguments+=(--fab "$PCBEX_FAB")
fi
if [[ -n "${PCBEX_FAB_PROFILE:-}" ]]; then
  analysis_arguments+=(--fab-profile "$PCBEX_FAB_PROFILE")
fi
if [[ -n "$effective_policy_pack" ]]; then
  analysis_arguments+=(--policy-pack "$effective_policy_pack")
fi
"$PCBEX_BINARY" "${analysis_arguments[@]}"
cp "$current_dir/report.sarif" "$sarif_dir/current.sarif"

violation_count="$(
  python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["result"]["violations"])' \
    "$current_dir/run.json"
)"

{
  printf '# pcbex hardware analysis\n\n'
  cat "$current_dir/summary.md"
} > "$comment_body"
cat "$comment_body" >> "$GITHUB_STEP_SUMMARY"

manufacturing_feedback=""
manufacturing_feedback_passed=""
if [[ -z "${PCBEX_MANUFACTURING_FEEDBACK_DECLARATION:-}" && -n "${PCBEX_MANUFACTURING_FEEDBACK_ARTIFACTS:-}" ]]; then
  echo "PCBEX_MANUFACTURING_FEEDBACK_ARTIFACTS requires PCBEX_MANUFACTURING_FEEDBACK_DECLARATION" >&2
  exit 2
fi
if [[ -n "${PCBEX_MANUFACTURING_FEEDBACK_DECLARATION:-}" ]]; then
  manufacturing_feedback="${artifact_dir}/manufacturing-feedback.json"
  manufacturing_summary="${artifact_dir}/manufacturing-feedback.md"
  manufacturing_sarif="${sarif_dir}/manufacturing-feedback.sarif"
  feedback_arguments=(record-manufacturing-feedback \
    "$PCBEX_MANUFACTURING_FEEDBACK_DECLARATION" \
    --analysis-dir "$current_dir" \
    --board "$PCBEX_BOARD" \
    --output "$manufacturing_feedback" \
    --summary-output "$manufacturing_summary" \
    --sarif-output "$manufacturing_sarif")
  while IFS= read -r artifact; do
    if [[ -n "$artifact" ]]; then
      feedback_arguments+=(--artifact "$artifact")
    fi
  done <<< "${PCBEX_MANUFACTURING_FEEDBACK_ARTIFACTS:-}"
  "$PCBEX_BINARY" "${feedback_arguments[@]}"
  manufacturing_feedback_passed="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["passed"]).lower())' \
      "$manufacturing_feedback"
  )"
  {
    printf '\n'
    cat "$manufacturing_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

policy_recommendation=""
if [[ -z "${PCBEX_POLICY_RECOMMENDATION_GENERATED_ON:-}" && \
  ( -n "${PCBEX_POLICY_RECOMMENDATION_FEEDBACK_FILES:-}" || \
    -n "${PCBEX_POLICY_RECOMMENDATION_ANALYSIS_MANIFESTS:-}" ) ]]; then
  echo "historical policy recommendation inputs require PCBEX_POLICY_RECOMMENDATION_GENERATED_ON" >&2
  exit 2
fi
if [[ -n "${PCBEX_POLICY_RECOMMENDATION_GENERATED_ON:-}" ]]; then
  if [[ -z "$effective_policy_pack" ]]; then
    echo "policy recommendation generation requires an organization policy pack" >&2
    exit 2
  fi
  recommendation_feedback=()
  recommendation_manifests=()
  while IFS= read -r path; do
    if [[ -n "$path" ]]; then recommendation_feedback+=("$path"); fi
  done <<< "${PCBEX_POLICY_RECOMMENDATION_FEEDBACK_FILES:-}"
  while IFS= read -r path; do
    if [[ -n "$path" ]]; then recommendation_manifests+=("$path"); fi
  done <<< "${PCBEX_POLICY_RECOMMENDATION_ANALYSIS_MANIFESTS:-}"
  if ((${#recommendation_feedback[@]} != ${#recommendation_manifests[@]})); then
    echo "policy recommendation feedback and manifest inputs must be paired" >&2
    exit 2
  fi
  if [[ -n "$manufacturing_feedback" ]]; then
    recommendation_feedback+=("$manufacturing_feedback")
    recommendation_manifests+=("$current_dir/run.json")
  fi
  if ((${#recommendation_feedback[@]} == 0)); then
    echo "policy recommendation generation requires bound manufacturing feedback" >&2
    exit 2
  fi
  policy_recommendation="${artifact_dir}/policy-recommendation.json"
  policy_recommendation_summary="${artifact_dir}/policy-recommendation.md"
  recommendation_arguments=(recommend-policy \
    "$effective_policy_pack" \
    --generated-on "$PCBEX_POLICY_RECOMMENDATION_GENERATED_ON" \
    --minimum-occurrences "${PCBEX_POLICY_RECOMMENDATION_MINIMUM_OCCURRENCES:-2}" \
    --output "$policy_recommendation" \
    --summary-output "$policy_recommendation_summary")
  for path in "${recommendation_feedback[@]}"; do
    recommendation_arguments+=(--feedback "$path")
  done
  for path in "${recommendation_manifests[@]}"; do
    recommendation_arguments+=(--analysis-manifest "$path")
  done
  "$PCBEX_BINARY" "${recommendation_arguments[@]}"
  {
    printf '\n'
    cat "$policy_recommendation_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

has_schematic=false
has_baseline_schematic=false
if [[ -n "${PCBEX_SCHEMATIC:-}" ]]; then has_schematic=true; fi
if [[ -n "${PCBEX_BASELINE_SCHEMATIC:-}" ]]; then has_baseline_schematic=true; fi
if [[ "$has_schematic" != "$has_baseline_schematic" ]]; then
  echo "PCBEX_SCHEMATIC and PCBEX_BASELINE_SCHEMATIC must be supplied together" >&2
  exit 2
fi
schematic_diff=""
schematic_review_required=""
schematic_reviewer_routing=""
schematic_review_all_routed=""
if [[ -n "${PCBEX_SCHEMATIC_REVIEWER_ROUTING_POLICY:-}" && "$has_schematic" != "true" ]]; then
  echo "PCBEX_SCHEMATIC_REVIEWER_ROUTING_POLICY requires PCBEX_SCHEMATIC and PCBEX_BASELINE_SCHEMATIC" >&2
  exit 2
fi
if [[ "$has_schematic" == "true" ]]; then
  schematic_diff="${artifact_dir}/schematic-diff.json"
  schematic_summary="${artifact_dir}/schematic-diff.md"
  schematic_sarif="${sarif_dir}/schematic-diff.sarif"
  "$PCBEX_BINARY" compare-schematics \
    "$PCBEX_BASELINE_SCHEMATIC" \
    "$PCBEX_SCHEMATIC" \
    --output "$schematic_diff" \
    --summary-output "$schematic_summary" \
    --sarif-output "$schematic_sarif"
  schematic_review_required="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["review_required"]).lower())' \
      "$schematic_diff"
  )"
  {
    printf '\n'
    cat "$schematic_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
  if [[ -n "${PCBEX_SCHEMATIC_REVIEWER_ROUTING_POLICY:-}" ]]; then
    schematic_reviewer_routing="${artifact_dir}/schematic-reviewer-routing.json"
    schematic_reviewer_routing_summary="${artifact_dir}/schematic-reviewer-routing.md"
    "$PCBEX_BINARY" route-schematic-review \
      "$PCBEX_BASELINE_SCHEMATIC" \
      "$PCBEX_SCHEMATIC" \
      --routing-policy "$PCBEX_SCHEMATIC_REVIEWER_ROUTING_POLICY" \
      --output "$schematic_reviewer_routing" \
      --summary-output "$schematic_reviewer_routing_summary" \
      --require-routed
    schematic_review_all_routed="$(
      python3 -c \
        'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["all_changes_routed"]).lower())' \
        "$schematic_reviewer_routing"
    )"
    {
      printf '\n'
      cat "$schematic_reviewer_routing_summary"
    } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
  fi
fi

ai_approval_quorum=""
ai_approval_quorum_met=""
ai_quorum_inputs=0
if [[ -n "${PCBEX_AI_REVIEW_REQUEST:-}" ]]; then ((ai_quorum_inputs += 1)); fi
if [[ -n "${PCBEX_AI_APPROVAL_FILES:-}" ]]; then ((ai_quorum_inputs += 1)); fi
if [[ -n "${PCBEX_AI_RESPONSE_FILES:-}" ]]; then ((ai_quorum_inputs += 1)); fi
if ((ai_quorum_inputs != 0 && ai_quorum_inputs != 3)); then
  echo "PCBEX_AI_REVIEW_REQUEST, PCBEX_AI_APPROVAL_FILES, and PCBEX_AI_RESPONSE_FILES must be supplied together" >&2
  exit 2
fi
if [[ -n "${PCBEX_AI_REVIEW_SESSION:-}" ]] && ((ai_quorum_inputs != 3)); then
  echo "PCBEX_AI_REVIEW_SESSION requires the complete AI quorum input set" >&2
  exit 2
fi
if ((ai_quorum_inputs == 3)); then
  if [[ -z "$effective_policy_pack" ]]; then
    echo "AI approval quorum verification requires a policy pack or signed policy pack" >&2
    exit 2
  fi
  ai_approval_quorum="${artifact_dir}/ai-approval-quorum.json"
  ai_approval_quorum_summary="${artifact_dir}/ai-approval-quorum.md"
  quorum_arguments=(verify-ai-quorum \
    "$PCBEX_AI_REVIEW_REQUEST" \
    --policy-pack "$effective_policy_pack" \
    --minimum-approvals "${PCBEX_AI_QUORUM_MINIMUM_APPROVALS:-2}" \
    --minimum-distinct-providers "${PCBEX_AI_QUORUM_MINIMUM_DISTINCT_PROVIDERS:-2}" \
    --minimum-distinct-models "${PCBEX_AI_QUORUM_MINIMUM_DISTINCT_MODELS:-2}" \
    --output "$ai_approval_quorum" \
    --summary-output "$ai_approval_quorum_summary")
  if [[ -n "${PCBEX_AI_REVIEW_SESSION:-}" ]]; then
    quorum_arguments+=(--session "$PCBEX_AI_REVIEW_SESSION")
  fi
  if [[ -n "${PCBEX_SCHEMATIC_REVIEWER_ROUTING_POLICY:-}" ]]; then
    quorum_arguments+=( \
      --baseline-schematic "$PCBEX_BASELINE_SCHEMATIC" \
      --current-schematic "$PCBEX_SCHEMATIC" \
      --reviewer-routing-policy "$PCBEX_SCHEMATIC_REVIEWER_ROUTING_POLICY")
  fi
  while IFS= read -r approval; do
    if [[ -n "$approval" ]]; then
      quorum_arguments+=(--approval "$approval")
    fi
  done <<< "${PCBEX_AI_APPROVAL_FILES:-}"
  while IFS= read -r response; do
    if [[ -n "$response" ]]; then
      quorum_arguments+=(--response "$response")
    fi
  done <<< "${PCBEX_AI_RESPONSE_FILES:-}"
  "$PCBEX_BINARY" "${quorum_arguments[@]}"
  ai_approval_quorum_met="$(
    python3 -c \
      'import json,sys; data=json.load(open(sys.argv[1], encoding="utf-8")); routed=data.get("routed_quorum", data); quorum=data.get("quorum", data); print(str(routed.get("routed_quorum_met", quorum.get("quorum_met"))).lower())' \
      "$ai_approval_quorum"
  )"
  {
    printf '\n'
    cat "$ai_approval_quorum_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

human_escalation=""
human_escalation_approved=""
if [[ -n "${PCBEX_HUMAN_ESCALATION_AI_QUORUM:-}" && -z "${PCBEX_HUMAN_ESCALATION_FILES:-}" ]]; then
  echo "PCBEX_HUMAN_ESCALATION_AI_QUORUM requires human escalation files" >&2
  exit 2
fi
if [[ -n "${PCBEX_HUMAN_ESCALATION_FILES:-}" ]]; then
  if [[ -z "$ai_approval_quorum" || -z "${PCBEX_AI_REVIEW_SESSION:-}" || -z "${PCBEX_HUMAN_ESCALATION_AI_QUORUM:-}" ]]; then
    echo "human escalation requires a complete time-bound AI quorum set and its exact retained evidence" >&2
    exit 2
  fi
  python3 -c '
import json,sys
retained=json.load(open(sys.argv[1], encoding="utf-8"))
fresh=json.load(open(sys.argv[2], encoding="utf-8"))
def session(value):
    return value.get("session", value)
def core(value):
    return value.get("routed_quorum", value.get("quorum"))
if session(retained)["session_sha256"] != session(fresh)["session_sha256"]:
    raise SystemExit("retained AI quorum uses a different review session")
if session(retained)["request_sha256"] != session(fresh)["request_sha256"]:
    raise SystemExit("retained AI quorum uses a different review request")
if core(retained) != core(fresh):
    raise SystemExit("retained AI quorum does not match freshly verified AI evidence")
' "$PCBEX_HUMAN_ESCALATION_AI_QUORUM" "$ai_approval_quorum"
  human_escalation="${artifact_dir}/human-escalation.json"
  human_escalation_summary="${artifact_dir}/human-escalation.md"
  human_arguments=(verify-human-escalation \
    "$PCBEX_AI_REVIEW_REQUEST" \
    --session "$PCBEX_AI_REVIEW_SESSION" \
    --ai-quorum "$PCBEX_HUMAN_ESCALATION_AI_QUORUM" \
    --policy-pack "$effective_policy_pack" \
    --minimum-approvals "${PCBEX_HUMAN_ESCALATION_MINIMUM_APPROVALS:-2}" \
    --output "$human_escalation" \
    --summary-output "$human_escalation_summary")
  while IFS= read -r escalation; do
    if [[ -n "$escalation" ]]; then
      human_arguments+=(--escalation "$escalation")
    fi
  done <<< "${PCBEX_HUMAN_ESCALATION_FILES:-}"
  "$PCBEX_BINARY" "${human_arguments[@]}"
  human_escalation_approved="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["escalation_approved"]).lower())' \
      "$human_escalation"
  )"
  {
    printf '\n'
    cat "$human_escalation_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

schematic_approval_met=false
if [[ "$ai_approval_quorum_met" == "true" || "$human_escalation_approved" == "true" ]]; then
  schematic_approval_met=true
fi

approval_log_verification=""
approval_log_verified=""
approval_log_inputs=0
if [[ -n "${PCBEX_APPROVAL_TRANSPARENCY_LOG:-}" ]]; then ((approval_log_inputs += 1)); fi
if [[ -n "${PCBEX_APPROVAL_LOG_CHECKPOINT:-}" ]]; then ((approval_log_inputs += 1)); fi
if [[ -n "${PCBEX_APPROVAL_LOG_PUBLIC_KEY:-}" ]]; then ((approval_log_inputs += 1)); fi
if ((approval_log_inputs != 0 && approval_log_inputs != 3)); then
  echo "PCBEX_APPROVAL_TRANSPARENCY_LOG, PCBEX_APPROVAL_LOG_CHECKPOINT, and PCBEX_APPROVAL_LOG_PUBLIC_KEY must be supplied together" >&2
  exit 2
fi
if ((approval_log_inputs == 3)); then
  approval_log_verification="${artifact_dir}/approval-log-verification.json"
  "$PCBEX_BINARY" verify-approval-log \
    "$PCBEX_APPROVAL_TRANSPARENCY_LOG" \
    --checkpoint "$PCBEX_APPROVAL_LOG_CHECKPOINT" \
    --public-key "$PCBEX_APPROVAL_LOG_PUBLIC_KEY" \
    --output "$approval_log_verification"
  approval_log_verified="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["verified"]).lower())' \
      "$approval_log_verification"
  )"
  {
    printf '\n# Approval transparency log\n\n'
    printf -- '- Verified: `%s`\n' "$approval_log_verified"
    printf -- '- Entries: `%s`\n' "$(
      python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["entry_count"])' \
        "$approval_log_verification"
    )"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

approval_log_anchor_verification=""
approval_log_anchored=""
approval_log_anchor_inputs=0
if [[ -n "${PCBEX_APPROVAL_LOG_ANCHOR_PROOF:-}" ]]; then ((approval_log_anchor_inputs += 1)); fi
if [[ -n "${PCBEX_APPROVAL_LOG_ANCHOR_PUBLIC_KEY:-}" ]]; then ((approval_log_anchor_inputs += 1)); fi
if ((approval_log_anchor_inputs != 0 && approval_log_anchor_inputs != 2)); then
  echo "PCBEX_APPROVAL_LOG_ANCHOR_PROOF and PCBEX_APPROVAL_LOG_ANCHOR_PUBLIC_KEY must be supplied together" >&2
  exit 2
fi
if ((approval_log_anchor_inputs == 2)); then
  if [[ -z "${PCBEX_APPROVAL_LOG_CHECKPOINT:-}" ]]; then
    echo "approval-log public anchor requires PCBEX_APPROVAL_LOG_CHECKPOINT" >&2
    exit 2
  fi
  approval_log_anchor_verification="${artifact_dir}/approval-log-anchor-verification.json"
  "$PCBEX_BINARY" verify-approval-log-anchor \
    "$PCBEX_APPROVAL_LOG_CHECKPOINT" \
    --proof "$PCBEX_APPROVAL_LOG_ANCHOR_PROOF" \
    --public-key "$PCBEX_APPROVAL_LOG_ANCHOR_PUBLIC_KEY" \
    --output "$approval_log_anchor_verification"
  approval_log_anchored="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["anchored"]).lower())' \
      "$approval_log_anchor_verification"
  )"
  {
    printf '\n# Approval public-log anchor\n\n'
    printf -- '- Anchored: `%s`\n' "$approval_log_anchored"
    printf -- '- Tree size: `%s`\n' "$(
      python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["tree_size"])' \
        "$approval_log_anchor_verification"
    )"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

remote_witness=""
remote_witness_receipt=""
remote_witness_public_key=""
remote_witness_trust_sources=0
if [[ -n "${PCBEX_REMOTE_WITNESS_PUBLIC_KEY:-}" ]]; then ((remote_witness_trust_sources += 1)); fi
if [[ -n "${PCBEX_REMOTE_WITNESS_TRUST_STATE:-}" ]]; then ((remote_witness_trust_sources += 1)); fi
if ((remote_witness_trust_sources > 1)); then
  echo "PCBEX_REMOTE_WITNESS_PUBLIC_KEY and PCBEX_REMOTE_WITNESS_TRUST_STATE are mutually exclusive" >&2
  exit 2
fi
if [[ -n "${PCBEX_REMOTE_WITNESS_ENDPOINT:-}" ]] && ((remote_witness_trust_sources != 1)); then
  echo "remote witness endpoint requires exactly one public key or trust state" >&2
  exit 2
fi
if [[ -z "${PCBEX_REMOTE_WITNESS_ENDPOINT:-}" ]] && ((remote_witness_trust_sources != 0)); then
  echo "remote witness trust requires PCBEX_REMOTE_WITNESS_ENDPOINT" >&2
  exit 2
fi
if [[ -n "${PCBEX_REMOTE_WITNESS_ENDPOINT:-}" ]]; then
  if [[ -z "${PCBEX_APPROVAL_LOG_CHECKPOINT:-}" ]]; then
    echo "remote witness requires PCBEX_APPROVAL_LOG_CHECKPOINT" >&2
    exit 2
  fi
  if [[ -n "${PCBEX_REMOTE_WITNESS_TRUST_STATE:-}" ]]; then
    remote_witness_public_key="${artifact_dir}/remote-witness-trusted.pub"
    "$PCBEX_BINARY" export-approval-log-witness-public-key \
      "$PCBEX_REMOTE_WITNESS_TRUST_STATE" \
      --output "$remote_witness_public_key"
  else
    remote_witness_public_key="$PCBEX_REMOTE_WITNESS_PUBLIC_KEY"
  fi
  remote_witness="${artifact_dir}/remote-witness.json"
  remote_witness_receipt="${artifact_dir}/remote-witness-receipt.json"
  remote_arguments=(request-approval-log-witness \
    "$PCBEX_APPROVAL_LOG_CHECKPOINT" \
    --endpoint "$PCBEX_REMOTE_WITNESS_ENDPOINT" \
    --public-key "$remote_witness_public_key" \
    --timeout-seconds "${PCBEX_REMOTE_WITNESS_TIMEOUT_SECONDS:-30}" \
    --output "$remote_witness" \
    --receipt-output "$remote_witness_receipt")
  if [[ -n "${PCBEX_REMOTE_WITNESS_BEARER_TOKEN:-}" ]]; then
    remote_arguments+=(--bearer-token-env PCBEX_REMOTE_WITNESS_BEARER_TOKEN)
  fi
  if [[ "${PCBEX_REMOTE_WITNESS_ALLOW_HTTP_LOOPBACK:-false}" == "true" ]]; then
    remote_arguments+=(--allow-http-loopback)
  fi
  "$PCBEX_BINARY" "${remote_arguments[@]}"
  {
    printf '\n# Remote approval-log witness\n\n'
    printf -- '- Witness: `%s`\n' "$(
      python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["witness_id"])' \
        "$remote_witness"
    )"
    printf -- '- Verified: `true`\n'
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

approval_log_witness_quorum=""
approval_log_witness_quorum_met=""
witness_inputs=0
if [[ -n "${PCBEX_APPROVAL_LOG_WITNESS_FILES:-}" ]]; then ((witness_inputs += 1)); fi
if [[ -n "${PCBEX_APPROVAL_LOG_WITNESS_PUBLIC_KEYS:-}" ]]; then ((witness_inputs += 1)); fi
if ((witness_inputs != 0 && witness_inputs != 2)); then
  echo "PCBEX_APPROVAL_LOG_WITNESS_FILES and PCBEX_APPROVAL_LOG_WITNESS_PUBLIC_KEYS must be supplied together" >&2
  exit 2
fi
if ((witness_inputs == 2)) || [[ -n "$remote_witness" ]]; then
  if [[ -z "${PCBEX_APPROVAL_LOG_CHECKPOINT:-}" ]]; then
    echo "approval-log witnesses require PCBEX_APPROVAL_LOG_CHECKPOINT" >&2
    exit 2
  fi
  approval_log_witness_quorum="${artifact_dir}/approval-log-witness-quorum.json"
  witness_arguments=(verify-approval-log-witnesses \
    "$PCBEX_APPROVAL_LOG_CHECKPOINT" \
    --minimum-witnesses "${PCBEX_APPROVAL_LOG_MINIMUM_WITNESSES:-2}" \
    --output "$approval_log_witness_quorum")
  while IFS= read -r witness; do
    if [[ -n "$witness" ]]; then witness_arguments+=(--witness "$witness"); fi
  done <<< "${PCBEX_APPROVAL_LOG_WITNESS_FILES:-}"
  while IFS= read -r public_key; do
    if [[ -n "$public_key" ]]; then witness_arguments+=(--public-key "$public_key"); fi
  done <<< "${PCBEX_APPROVAL_LOG_WITNESS_PUBLIC_KEYS:-}"
  if [[ -n "$remote_witness" ]]; then
    witness_arguments+=(--witness "$remote_witness")
    witness_arguments+=(--public-key "$remote_witness_public_key")
  fi
  "$PCBEX_BINARY" "${witness_arguments[@]}"
  approval_log_witness_quorum_met="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["quorum_met"]).lower())' \
      "$approval_log_witness_quorum"
  )"
  {
    printf '\n# Approval transparency-log witnesses\n\n'
    printf -- '- Quorum met: `%s`\n' "$approval_log_witness_quorum_met"
    printf -- '- Valid witnesses: `%s`\n' "$(
      python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["valid_witnesses"])' \
        "$approval_log_witness_quorum"
    )"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

comparison_sarif=""
regression=false
if [[ -n "${PCBEX_BASELINE_BOARD:-}" ]]; then
  mkdir -p "$baseline_dir" "$comparison_dir"
  baseline_arguments=(analyze-kicad "$PCBEX_BASELINE_BOARD" --output-dir "$baseline_dir")
  if [[ -n "${PCBEX_FAB:-}" ]]; then
    baseline_arguments+=(--fab "$PCBEX_FAB")
  fi
  if [[ -n "${PCBEX_FAB_PROFILE:-}" ]]; then
    baseline_arguments+=(--fab-profile "$PCBEX_FAB_PROFILE")
  fi
  if [[ -n "$effective_policy_pack" ]]; then
    baseline_arguments+=(--policy-pack "$effective_policy_pack")
  fi
  "$PCBEX_BINARY" "${baseline_arguments[@]}"
  "$PCBEX_BINARY" compare-analysis \
    "$baseline_dir" \
    "$current_dir" \
    --output-dir "$comparison_dir"
  cp "$comparison_dir/report.sarif" "$sarif_dir/comparison.sarif"
  comparison_sarif="$comparison_dir/report.sarif"
  regression="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["regression"]).lower())' \
      "$comparison_dir/run.json"
  )"
  {
    printf '\n# pcbex baseline comparison\n\n'
    cat "$comparison_dir/summary.md"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

write_output sarif-dir "$sarif_dir"
write_output current-sarif "$current_dir/report.sarif"
write_output comparison-sarif "$comparison_sarif"
write_output comment-body "$comment_body"
write_output violation-count "$violation_count"
write_output regression "$regression"
write_output verified-policy-trust-state "$verified_policy_trust_state"
write_output fetched-signed-policy-pack "$fetched_signed_policy_pack"
write_output policy-pack-fetch-receipt "$policy_pack_fetch_receipt"
write_output manufacturing-feedback "$manufacturing_feedback"
write_output manufacturing-feedback-passed "$manufacturing_feedback_passed"
write_output policy-recommendation "$policy_recommendation"
write_output schematic-diff "$schematic_diff"
write_output schematic-review-required "$schematic_review_required"
write_output schematic-reviewer-routing "$schematic_reviewer_routing"
write_output schematic-review-all-routed "$schematic_review_all_routed"
write_output ai-approval-quorum "$ai_approval_quorum"
write_output ai-approval-quorum-met "$ai_approval_quorum_met"
write_output human-escalation "$human_escalation"
write_output human-escalation-approved "$human_escalation_approved"
write_output schematic-approval-met "$schematic_approval_met"
write_output approval-log-verification "$approval_log_verification"
write_output approval-log-verified "$approval_log_verified"
write_output approval-log-anchor-verification "$approval_log_anchor_verification"
write_output approval-log-anchored "$approval_log_anchored"
write_output approval-log-witness-quorum "$approval_log_witness_quorum"
write_output approval-log-witness-quorum-met "$approval_log_witness_quorum_met"
write_output remote-witness "$remote_witness"
write_output remote-witness-receipt "$remote_witness_receipt"
write_output status ok

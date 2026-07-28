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
write_output manufacturing-feedback ""
write_output manufacturing-feedback-passed ""
write_output schematic-diff ""
write_output schematic-review-required ""
write_output schematic-reviewer-routing ""
write_output schematic-review-all-routed ""
write_output ai-approval-quorum ""
write_output ai-approval-quorum-met ""

analysis_arguments=(analyze-kicad "$PCBEX_BOARD" --output-dir "$current_dir")
profile_selections=0
if [[ -n "${PCBEX_FAB:-}" ]]; then ((profile_selections += 1)); fi
if [[ -n "${PCBEX_FAB_PROFILE:-}" ]]; then ((profile_selections += 1)); fi
if [[ -n "${PCBEX_POLICY_PACK:-}" ]]; then ((profile_selections += 1)); fi
if [[ -n "${PCBEX_SIGNED_POLICY_PACK:-}" ]]; then ((profile_selections += 1)); fi
if ((profile_selections > 1)); then
  echo "physical policy inputs are mutually exclusive" >&2
  exit 2
fi
has_signed_policy_pack=false
has_policy_public_key=false
if [[ -n "${PCBEX_SIGNED_POLICY_PACK:-}" ]]; then has_signed_policy_pack=true; fi
if [[ -n "${PCBEX_POLICY_PUBLIC_KEY:-}" ]]; then has_policy_public_key=true; fi
if [[ "$has_signed_policy_pack" != "$has_policy_public_key" ]]; then
  echo "PCBEX_SIGNED_POLICY_PACK and PCBEX_POLICY_PUBLIC_KEY must be supplied together" >&2
  exit 2
fi
if [[ -n "${PCBEX_POLICY_TRUST_STATE:-}" && "$has_signed_policy_pack" != "true" ]]; then
  echo "PCBEX_POLICY_TRUST_STATE requires PCBEX_SIGNED_POLICY_PACK" >&2
  exit 2
fi
effective_policy_pack="${PCBEX_POLICY_PACK:-}"
verified_policy_trust_state=""
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
write_output manufacturing-feedback "$manufacturing_feedback"
write_output manufacturing-feedback-passed "$manufacturing_feedback_passed"
write_output schematic-diff "$schematic_diff"
write_output schematic-review-required "$schematic_review_required"
write_output schematic-reviewer-routing "$schematic_reviewer_routing"
write_output schematic-review-all-routed "$schematic_review_all_routed"
write_output ai-approval-quorum "$ai_approval_quorum"
write_output ai-approval-quorum-met "$ai_approval_quorum_met"
write_output status ok

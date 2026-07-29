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
write_output policy-rollout-profile ""
write_output policy-rollout ""
write_output canary-rollout-authorization ""
write_output canary-rollout-authorized ""
write_output canary-monitoring ""
write_output canary-monitoring-passed ""
write_output canary-completion ""
write_output canary-completion-finalized ""
write_output canary-completion-decision ""
write_output policy-deployment ""
write_output policy-deployment-status ""
write_output policy-deployment-active-revision ""
write_output policy-deployment-verification ""
write_output policy-deployment-verified ""
write_output policy-deployment-rollback-required ""
write_output policy-deployment-rollback ""
write_output policy-deployment-rollback-status ""
write_output policy-deployment-rollback-active-revision ""
write_output policy-rollback-recovery ""
write_output policy-rollback-recovery-verified ""
write_output rollback-incident-closure ""
write_output rollback-incident-status ""
write_output policy-incident-ledger ""
write_output policy-incident-suspension-review-required ""
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

policy_rollout_profile=""
policy_rollout=""
if [[ -n "${PCBEX_POLICY_ROLLOUT_PROJECT_ID:-}" ]]; then
  rollout_recommendation="${PCBEX_POLICY_ROLLOUT_RECOMMENDATION:-$policy_recommendation}"
  if [[ -z "$rollout_recommendation" || -z "$effective_policy_pack" || \
    -z "${PCBEX_POLICY_ROLLOUT_GENERATED_ON:-}" ]]; then
    echo "policy rollout simulation requires a recommendation, generated-on date, and organization policy pack" >&2
    exit 2
  fi
  policy_rollout_profile="${artifact_dir}/policy-rollout-profile.json"
  policy_rollout="${artifact_dir}/policy-rollout.json"
  policy_rollout_summary="${artifact_dir}/policy-rollout.md"
  policy_rollout_candidate_dir="${artifact_dir}/policy-rollout-candidate"
  "$PCBEX_BINARY" policy-rollout-profile \
    "$effective_policy_pack" \
    "$rollout_recommendation" \
    --generated-on "$PCBEX_POLICY_ROLLOUT_GENERATED_ON" \
    --output "$policy_rollout_profile"
  "$PCBEX_BINARY" analyze-kicad \
    "$PCBEX_BOARD" \
    --fab-profile "$policy_rollout_profile" \
    --output-dir "$policy_rollout_candidate_dir"
  "$PCBEX_BINARY" simulate-policy-rollout \
    "$effective_policy_pack" \
    "$rollout_recommendation" \
    --project-id "$PCBEX_POLICY_ROLLOUT_PROJECT_ID" \
    --board "$PCBEX_BOARD" \
    --baseline-analysis "$current_dir" \
    --candidate-analysis "$policy_rollout_candidate_dir" \
    --generated-on "$PCBEX_POLICY_ROLLOUT_GENERATED_ON" \
    --output "$policy_rollout" \
    --summary-output "$policy_rollout_summary"
  {
    printf '\n'
    cat "$policy_rollout_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

canary_rollout_authorization=""
canary_rollout_authorized=""
canary_approval_inputs=0
if [[ -n "${PCBEX_CANARY_ROLLOUT_APPROVAL_FILES:-}" ]]; then
  ((canary_approval_inputs += 1))
fi
if [[ -n "${PCBEX_CANARY_ROLLOUT_EVALUATED_AT_UNIX:-}" ]]; then
  ((canary_approval_inputs += 1))
fi
if ((canary_approval_inputs != 0 && canary_approval_inputs != 2)); then
  echo "canary rollout approvals and evaluated-at Unix time must be supplied together" >&2
  exit 2
fi
if ((canary_approval_inputs == 2)); then
  rollout_to_authorize="${PCBEX_CANARY_ROLLOUT_REPORT:-$policy_rollout}"
  if [[ -z "$rollout_to_authorize" || -z "$effective_policy_pack" ]]; then
    echo "canary rollout authorization requires a rollout report and organization policy pack" >&2
    exit 2
  fi
  canary_rollout_authorization="${artifact_dir}/canary-rollout-authorization.json"
  canary_rollout_summary="${artifact_dir}/canary-rollout-authorization.md"
  canary_arguments=(verify-rollout-approvals \
    "$rollout_to_authorize" \
    --policy-pack "$effective_policy_pack" \
    --evaluated-at-unix "$PCBEX_CANARY_ROLLOUT_EVALUATED_AT_UNIX" \
    --minimum-approvals "${PCBEX_CANARY_ROLLOUT_MINIMUM_APPROVALS:-2}" \
    --output "$canary_rollout_authorization" \
    --summary-output "$canary_rollout_summary")
  while IFS= read -r approval; do
    if [[ -n "$approval" ]]; then
      canary_arguments+=(--approval "$approval")
    fi
  done <<< "${PCBEX_CANARY_ROLLOUT_APPROVAL_FILES:-}"
  "$PCBEX_BINARY" "${canary_arguments[@]}"
  canary_rollout_authorized="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["canary_authorized"]).lower())' \
      "$canary_rollout_authorization"
  )"
  {
    printf '\n'
    cat "$canary_rollout_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

canary_monitoring=""
canary_monitoring_passed=""
monitoring_inputs=0
for value in \
  "${PCBEX_CANARY_MONITORING_PROJECT_ID:-}" \
  "${PCBEX_CANARY_MONITORING_BASELINE_ANALYSIS:-}" \
  "${PCBEX_CANARY_MONITORING_OBSERVED_ANALYSIS:-}" \
  "${PCBEX_CANARY_MONITORING_OBSERVED_AT_UNIX:-}"; do
  if [[ -n "$value" ]]; then ((monitoring_inputs += 1)); fi
done
if ((monitoring_inputs != 0 && monitoring_inputs != 4)); then
  echo "canary monitoring project, baseline, observation, and time must be supplied together" >&2
  exit 2
fi
if ((monitoring_inputs == 4)); then
  rollout_to_monitor="${PCBEX_CANARY_ROLLOUT_REPORT:-$policy_rollout}"
  if [[ -z "$rollout_to_monitor" || -z "$canary_rollout_authorization" ]]; then
    echo "canary monitoring requires the exact rollout and verified authorization" >&2
    exit 2
  fi
  canary_monitoring="${artifact_dir}/canary-monitoring.json"
  canary_monitoring_summary="${artifact_dir}/canary-monitoring.md"
  "$PCBEX_BINARY" record-canary-monitoring \
    "$rollout_to_monitor" \
    "$canary_rollout_authorization" \
    --project-id "$PCBEX_CANARY_MONITORING_PROJECT_ID" \
    --board "$PCBEX_BOARD" \
    --baseline-analysis "$PCBEX_CANARY_MONITORING_BASELINE_ANALYSIS" \
    --observed-analysis "$PCBEX_CANARY_MONITORING_OBSERVED_ANALYSIS" \
    --observed-at-unix "$PCBEX_CANARY_MONITORING_OBSERVED_AT_UNIX" \
    --output "$canary_monitoring" \
    --summary-output "$canary_monitoring_summary"
  canary_monitoring_passed="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["promotion_eligible"]).lower())' \
      "$canary_monitoring"
  )"
  {
    printf '\n'
    cat "$canary_monitoring_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

canary_completion=""
canary_completion_finalized=""
canary_completion_decision=""
if [[ -n "${PCBEX_CANARY_COMPLETION_DECISION_FILES:-}" ]]; then
  completion_rollout="${PCBEX_CANARY_ROLLOUT_REPORT:-$policy_rollout}"
  completion_monitoring="${PCBEX_CANARY_COMPLETION_MONITORING_REPORT:-$canary_monitoring}"
  if [[ -z "$completion_rollout" || -z "$completion_monitoring" || -z "$canary_rollout_authorization" || -z "$effective_policy_pack" ]]; then
    echo "canary completion requires rollout, monitoring, verified authorization, and an organization policy pack" >&2
    exit 2
  fi
  canary_completion="${artifact_dir}/canary-completion.json"
  canary_completion_summary="${artifact_dir}/canary-completion.md"
  completion_arguments=(verify-canary-completion \
    "$completion_rollout" \
    "$completion_monitoring" \
    "$canary_rollout_authorization" \
    --policy-pack "$effective_policy_pack" \
    --minimum-decisions "${PCBEX_CANARY_COMPLETION_MINIMUM_DECISIONS:-2}" \
    --output "$canary_completion" \
    --summary-output "$canary_completion_summary")
  while IFS= read -r decision; do
    if [[ -n "$decision" ]]; then
      completion_arguments+=(--decision "$decision")
    fi
  done <<< "${PCBEX_CANARY_COMPLETION_DECISION_FILES:-}"
  "$PCBEX_BINARY" "${completion_arguments[@]}"
  readarray -t completion_values < <(
    python3 -c '
import json,sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
print(str(data["finalized"]).lower())
print(data["final_decision"] or "")
' "$canary_completion"
  )
  canary_completion_finalized="${completion_values[0]}"
  canary_completion_decision="${completion_values[1]}"
  {
    printf '\n'
    cat "$canary_completion_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

policy_deployment=""
policy_deployment_status=""
policy_deployment_active_revision=""
deployment_inputs=0
for value in \
  "${PCBEX_POLICY_DEPLOYMENT_CANDIDATE_POLICY_PACK:-}" \
  "${PCBEX_POLICY_DEPLOYMENT_SOURCE_TRUST_STATE:-}" \
  "${PCBEX_POLICY_DEPLOYMENT_CANDIDATE_TRUST_STATE:-}" \
  "${PCBEX_POLICY_DEPLOYMENT_BASELINE_STATE:-}" \
  "${PCBEX_POLICY_DEPLOYMENT_RECORDED_AT_UNIX:-}"; do
  if [[ -n "$value" ]]; then ((deployment_inputs += 1)); fi
done
if ((deployment_inputs != 0)) && [[ -z "${PCBEX_POLICY_DEPLOYMENT_RECORDED_AT_UNIX:-}" ]]; then
  echo "policy deployment candidate inputs require policy-deployment-recorded-at-unix" >&2
  exit 2
fi
if [[ -n "${PCBEX_POLICY_DEPLOYMENT_RECORDED_AT_UNIX:-}" ]]; then
  deployment_rollout="${PCBEX_CANARY_ROLLOUT_REPORT:-$policy_rollout}"
  deployment_monitoring="${PCBEX_CANARY_COMPLETION_MONITORING_REPORT:-$canary_monitoring}"
  deployment_source_trust_state="${PCBEX_POLICY_DEPLOYMENT_SOURCE_TRUST_STATE:-$verified_policy_trust_state}"
  deployment_candidate_trust_state="${PCBEX_POLICY_DEPLOYMENT_CANDIDATE_TRUST_STATE:-}"
  deployment_candidate_policy="${PCBEX_POLICY_DEPLOYMENT_CANDIDATE_POLICY_PACK:-}"
  if [[ -z "$deployment_rollout" || -z "$deployment_monitoring" || -z "$canary_rollout_authorization" || -z "$effective_policy_pack" || -z "$deployment_candidate_policy" || -z "$deployment_source_trust_state" || -z "$deployment_candidate_trust_state" || -z "${PCBEX_CANARY_COMPLETION_DECISION_FILES:-}" ]]; then
    echo "policy deployment requires rollout, monitoring, authorization, source and candidate policy packs, both accepted trust states, and completion decisions" >&2
    exit 2
  fi
  policy_deployment="${artifact_dir}/policy-deployment.json"
  policy_deployment_summary="${artifact_dir}/policy-deployment.md"
  deployment_arguments=(advance-policy-deployment \
    "$deployment_rollout" \
    "$deployment_monitoring" \
    "$canary_rollout_authorization" \
    --policy-pack "$effective_policy_pack" \
    --candidate-policy-pack "$deployment_candidate_policy" \
    --source-policy-trust-state "$deployment_source_trust_state" \
    --candidate-policy-trust-state "$deployment_candidate_trust_state" \
    --minimum-decisions "${PCBEX_CANARY_COMPLETION_MINIMUM_DECISIONS:-2}" \
    --recorded-at-unix "$PCBEX_POLICY_DEPLOYMENT_RECORDED_AT_UNIX" \
    --output "$policy_deployment" \
    --summary-output "$policy_deployment_summary")
  if [[ -n "${PCBEX_POLICY_DEPLOYMENT_BASELINE_STATE:-}" ]]; then
    deployment_arguments+=(--baseline-state "$PCBEX_POLICY_DEPLOYMENT_BASELINE_STATE")
  fi
  while IFS= read -r decision; do
    if [[ -n "$decision" ]]; then
      deployment_arguments+=(--decision "$decision")
    fi
  done <<< "${PCBEX_CANARY_COMPLETION_DECISION_FILES:-}"
  "$PCBEX_BINARY" "${deployment_arguments[@]}"
  readarray -t deployment_values < <(
    python3 -c '
import json,sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
print(data["status"])
print(data["active_revision"])
' "$policy_deployment"
  )
  policy_deployment_status="${deployment_values[0]}"
  policy_deployment_active_revision="${deployment_values[1]}"
  {
    printf '\n'
    cat "$policy_deployment_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

policy_deployment_verification=""
policy_deployment_verified=""
policy_deployment_rollback_required=""
verification_inputs=0
for value in \
  "${PCBEX_POLICY_DEPLOYMENT_VERIFICATION_PROJECT_ID:-}" \
  "${PCBEX_POLICY_DEPLOYMENT_VERIFICATION_EXPECTED_ANALYSIS:-}" \
  "${PCBEX_POLICY_DEPLOYMENT_VERIFICATION_OBSERVED_ANALYSIS:-}" \
  "${PCBEX_POLICY_DEPLOYMENT_VERIFICATION_VERIFIED_AT_UNIX:-}"; do
  if [[ -n "$value" ]]; then ((verification_inputs += 1)); fi
done
if ((verification_inputs != 0 && verification_inputs != 4)); then
  echo "post-deployment verification project, expected analysis, observation, and time must be supplied together" >&2
  exit 2
fi
if ((verification_inputs == 4)); then
  verification_state="${PCBEX_POLICY_DEPLOYMENT_VERIFICATION_STATE:-$policy_deployment}"
  verification_rollout="${PCBEX_CANARY_ROLLOUT_REPORT:-$policy_rollout}"
  verification_candidate="${PCBEX_POLICY_DEPLOYMENT_CANDIDATE_POLICY_PACK:-}"
  if [[ -z "$verification_state" || -z "$verification_rollout" || -z "$verification_candidate" ]]; then
    echo "post-deployment verification requires a pending state, exact rollout, and active candidate policy pack" >&2
    exit 2
  fi
  policy_deployment_verification="${artifact_dir}/policy-deployment-verification.json"
  policy_deployment_verification_summary="${artifact_dir}/policy-deployment-verification.md"
  "$PCBEX_BINARY" verify-policy-deployment \
    "$verification_state" \
    "$verification_rollout" \
    --candidate-policy-pack "$verification_candidate" \
    --project-id "$PCBEX_POLICY_DEPLOYMENT_VERIFICATION_PROJECT_ID" \
    --board "$PCBEX_BOARD" \
    --expected-analysis "$PCBEX_POLICY_DEPLOYMENT_VERIFICATION_EXPECTED_ANALYSIS" \
    --observed-analysis "$PCBEX_POLICY_DEPLOYMENT_VERIFICATION_OBSERVED_ANALYSIS" \
    --verified-at-unix "$PCBEX_POLICY_DEPLOYMENT_VERIFICATION_VERIFIED_AT_UNIX" \
    --output "$policy_deployment_verification" \
    --summary-output "$policy_deployment_verification_summary"
  readarray -t verification_values < <(
    python3 -c '
import json,sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
print(str(data["deployment_verified"]).lower())
print(str(data["rollback_required"]).lower())
' "$policy_deployment_verification"
  )
  policy_deployment_verified="${verification_values[0]}"
  policy_deployment_rollback_required="${verification_values[1]}"
  {
    printf '\n'
    cat "$policy_deployment_verification_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

policy_deployment_rollback=""
policy_deployment_rollback_status=""
policy_deployment_rollback_active_revision=""
rollback_inputs=0
for value in \
  "${PCBEX_POLICY_DEPLOYMENT_ROLLBACK_APPROVAL_FILES:-}" \
  "${PCBEX_POLICY_DEPLOYMENT_ROLLBACK_RECORDED_AT_UNIX:-}"; do
  if [[ -n "$value" ]]; then ((rollback_inputs += 1)); fi
done
if ((rollback_inputs != 0 && rollback_inputs != 2)); then
  echo "production rollback approvals and recorded time must be supplied together" >&2
  exit 2
fi
if ((rollback_inputs == 2)); then
  rollback_deployment="${PCBEX_POLICY_DEPLOYMENT_VERIFICATION_STATE:-$policy_deployment}"
  rollback_verification="${PCBEX_POLICY_DEPLOYMENT_ROLLBACK_VERIFICATION:-$policy_deployment_verification}"
  rollback_active_policy="${PCBEX_POLICY_DEPLOYMENT_CANDIDATE_POLICY_PACK:-}"
  if [[ -z "$rollback_deployment" || -z "$rollback_verification" || -z "$rollback_active_policy" ]]; then
    echo "production rollback requires the promoted state, failed verification, and failed active policy pack" >&2
    exit 2
  fi
  policy_deployment_rollback="${artifact_dir}/policy-deployment-rollback.json"
  policy_deployment_rollback_summary="${artifact_dir}/policy-deployment-rollback.md"
  rollback_arguments=(apply-policy-deployment-rollback \
    "$rollback_deployment" \
    "$rollback_verification" \
    --active-policy-pack "$rollback_active_policy" \
    --minimum-approvals "${PCBEX_POLICY_DEPLOYMENT_ROLLBACK_MINIMUM_APPROVALS:-2}" \
    --recorded-at-unix "$PCBEX_POLICY_DEPLOYMENT_ROLLBACK_RECORDED_AT_UNIX" \
    --output "$policy_deployment_rollback" \
    --summary-output "$policy_deployment_rollback_summary")
  while IFS= read -r approval; do
    if [[ -n "$approval" ]]; then
      rollback_arguments+=(--approval "$approval")
    fi
  done <<< "${PCBEX_POLICY_DEPLOYMENT_ROLLBACK_APPROVAL_FILES:-}"
  "$PCBEX_BINARY" "${rollback_arguments[@]}"
  readarray -t rollback_values < <(
    python3 -c '
import json,sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
print(data["status"])
print(data["active_revision"])
' "$policy_deployment_rollback"
  )
  policy_deployment_rollback_status="${rollback_values[0]}"
  policy_deployment_rollback_active_revision="${rollback_values[1]}"
  {
    printf '\n'
    cat "$policy_deployment_rollback_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

policy_rollback_recovery=""
policy_rollback_recovery_verified=""
recovery_inputs=0
for value in \
  "${PCBEX_POLICY_ROLLBACK_RECOVERY_PROJECT_ID:-}" \
  "${PCBEX_POLICY_ROLLBACK_RECOVERY_EXPECTED_ANALYSIS:-}" \
  "${PCBEX_POLICY_ROLLBACK_RECOVERY_OBSERVED_ANALYSIS:-}" \
  "${PCBEX_POLICY_ROLLBACK_RECOVERY_VERIFIED_AT_UNIX:-}"; do
  if [[ -n "$value" ]]; then ((recovery_inputs += 1)); fi
done
if ((recovery_inputs != 0 && recovery_inputs != 4)); then
  echo "rollback recovery project, expected analysis, observation, and time must be supplied together" >&2
  exit 2
fi
if ((recovery_inputs == 4)); then
  recovery_state="${PCBEX_POLICY_ROLLBACK_RECOVERY_STATE:-$policy_deployment_rollback}"
  recovery_rollout="${PCBEX_POLICY_ROLLBACK_RECOVERY_ROLLOUT:-${PCBEX_CANARY_ROLLOUT_REPORT:-$policy_rollout}}"
  recovery_deployment="${PCBEX_POLICY_ROLLBACK_RECOVERY_DEPLOYMENT:-${PCBEX_POLICY_DEPLOYMENT_VERIFICATION_STATE:-$policy_deployment}}"
  recovery_failed_verification="${PCBEX_POLICY_ROLLBACK_RECOVERY_FAILED_VERIFICATION:-${PCBEX_POLICY_DEPLOYMENT_ROLLBACK_VERIFICATION:-$policy_deployment_verification}}"
  recovery_previous_deployment="${PCBEX_POLICY_ROLLBACK_RECOVERY_PREVIOUS_DEPLOYMENT:-}"
  recovery_baseline_verification="${PCBEX_POLICY_ROLLBACK_RECOVERY_BASELINE_VERIFICATION:-}"
  recovery_policy="${PCBEX_POLICY_ROLLBACK_RECOVERY_RESTORED_POLICY_PACK:-}"
  if [[ -z "$recovery_state" || -z "$recovery_rollout" || -z "$recovery_deployment" || -z "$recovery_failed_verification" || -z "$recovery_previous_deployment" || -z "$recovery_baseline_verification" || -z "$recovery_policy" ]]; then
    echo "rollback recovery requires rollback, failed and previous deployments, both verifications, exact rollout, and restored policy pack" >&2
    exit 2
  fi
  policy_rollback_recovery="${artifact_dir}/policy-rollback-recovery.json"
  policy_rollback_recovery_summary="${artifact_dir}/policy-rollback-recovery.md"
  "$PCBEX_BINARY" verify-policy-rollback-recovery \
    "$recovery_state" \
    "$recovery_rollout" \
    --deployment "$recovery_deployment" \
    --failed-verification "$recovery_failed_verification" \
    --previous-deployment "$recovery_previous_deployment" \
    --baseline-verification "$recovery_baseline_verification" \
    --restored-policy-pack "$recovery_policy" \
    --project-id "$PCBEX_POLICY_ROLLBACK_RECOVERY_PROJECT_ID" \
    --board "$PCBEX_BOARD" \
    --expected-analysis "$PCBEX_POLICY_ROLLBACK_RECOVERY_EXPECTED_ANALYSIS" \
    --observed-analysis "$PCBEX_POLICY_ROLLBACK_RECOVERY_OBSERVED_ANALYSIS" \
    --verified-at-unix "$PCBEX_POLICY_ROLLBACK_RECOVERY_VERIFIED_AT_UNIX" \
    --output "$policy_rollback_recovery" \
    --summary-output "$policy_rollback_recovery_summary"
  policy_rollback_recovery_verified="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["recovery_verified"]).lower())' \
      "$policy_rollback_recovery"
  )"
  {
    printf '\n'
    cat "$policy_rollback_recovery_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

rollback_incident_closure=""
rollback_incident_status=""
closure_inputs=0
for value in \
  "${PCBEX_ROLLBACK_INCIDENT_ACKNOWLEDGMENT:-}" \
  "${PCBEX_ROLLBACK_INCIDENT_CLOSED_AT_UNIX:-}"; do
  if [[ -n "$value" ]]; then ((closure_inputs += 1)); fi
done
if ((closure_inputs != 0 && closure_inputs != 2)); then
  echo "rollback incident acknowledgment and closed time must be supplied together" >&2
  exit 2
fi
if ((closure_inputs == 2)); then
  closure_state="${PCBEX_POLICY_ROLLBACK_RECOVERY_STATE:-$policy_deployment_rollback}"
  closure_recovery="$policy_rollback_recovery"
  closure_policy="${PCBEX_POLICY_ROLLBACK_RECOVERY_RESTORED_POLICY_PACK:-}"
  if [[ -z "$closure_state" || -z "$closure_recovery" || -z "$closure_policy" ]]; then
    echo "rollback incident closure requires rollback state, clean recovery, and restored policy pack" >&2
    exit 2
  fi
  rollback_incident_closure="${artifact_dir}/rollback-incident-closure.json"
  rollback_incident_closure_summary="${artifact_dir}/rollback-incident-closure.md"
  "$PCBEX_BINARY" close-rollback-incident \
    "$closure_state" \
    "$closure_recovery" \
    --restored-policy-pack "$closure_policy" \
    --acknowledgment "$PCBEX_ROLLBACK_INCIDENT_ACKNOWLEDGMENT" \
    --closed-at-unix "$PCBEX_ROLLBACK_INCIDENT_CLOSED_AT_UNIX" \
    --output "$rollback_incident_closure" \
    --summary-output "$rollback_incident_closure_summary"
  rollback_incident_status="$(
    python3 -c \
      'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["status"])' \
      "$rollback_incident_closure"
  )"
  {
    printf '\n'
    cat "$rollback_incident_closure_summary"
  } | tee -a "$comment_body" >> "$GITHUB_STEP_SUMMARY"
fi

policy_incident_ledger=""
policy_incident_suspension_review_required=""
if [[ "${PCBEX_RECORD_POLICY_INCIDENT:-false}" == "true" ]]; then
  if [[ -z "$policy_deployment_rollback" || -z "$policy_rollback_recovery" || -z "$rollback_incident_closure" || -z "${recovery_failed_verification:-}" ]]; then
    echo "policy incident retention requires rollback, failed verification, clean recovery, and closure from this run" >&2
    exit 2
  fi
  policy_incident_ledger="${artifact_dir}/policy-incident-ledger.json"
  policy_incident_ledger_summary="${artifact_dir}/policy-incident-ledger.md"
  incident_arguments=(append-policy-incident-ledger \
    "$policy_deployment_rollback" \
    --failed-verification "$recovery_failed_verification" \
    --recovery "$policy_rollback_recovery" \
    --closure "$rollback_incident_closure" \
    --suspension-threshold "${PCBEX_POLICY_INCIDENT_SUSPENSION_THRESHOLD:-2}" \
    --output "$policy_incident_ledger" \
    --summary-output "$policy_incident_ledger_summary")
  if [[ -n "${PCBEX_POLICY_INCIDENT_LEDGER_BASELINE:-}" ]]; then
    incident_arguments+=(--baseline-ledger "$PCBEX_POLICY_INCIDENT_LEDGER_BASELINE")
  fi
  "$PCBEX_BINARY" "${incident_arguments[@]}"
  policy_incident_suspension_review_required="$(
    python3 -c \
      'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["requires_human_suspension_review"]).lower())' \
      "$policy_incident_ledger"
  )"
  {
    printf '\n'
    cat "$policy_incident_ledger_summary"
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
write_output policy-rollout-profile "$policy_rollout_profile"
write_output policy-rollout "$policy_rollout"
write_output canary-rollout-authorization "$canary_rollout_authorization"
write_output canary-rollout-authorized "$canary_rollout_authorized"
write_output canary-monitoring "$canary_monitoring"
write_output canary-monitoring-passed "$canary_monitoring_passed"
write_output canary-completion "$canary_completion"
write_output canary-completion-finalized "$canary_completion_finalized"
write_output canary-completion-decision "$canary_completion_decision"
write_output policy-deployment "$policy_deployment"
write_output policy-deployment-status "$policy_deployment_status"
write_output policy-deployment-active-revision "$policy_deployment_active_revision"
write_output policy-deployment-verification "$policy_deployment_verification"
write_output policy-deployment-verified "$policy_deployment_verified"
write_output policy-deployment-rollback-required "$policy_deployment_rollback_required"
write_output policy-deployment-rollback "$policy_deployment_rollback"
write_output policy-deployment-rollback-status "$policy_deployment_rollback_status"
write_output policy-deployment-rollback-active-revision "$policy_deployment_rollback_active_revision"
write_output policy-rollback-recovery "$policy_rollback_recovery"
write_output policy-rollback-recovery-verified "$policy_rollback_recovery_verified"
write_output rollback-incident-closure "$rollback_incident_closure"
write_output rollback-incident-status "$rollback_incident_status"
write_output policy-incident-ledger "$policy_incident_ledger"
write_output policy-incident-suspension-review-required "$policy_incident_suspension_review_required"
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

#!/usr/bin/env bash
set -euo pipefail

required_variables=(
  PCBEX_PREFLIGHT_VALID
  PCBEX_FABRICATION_OUTCOME
  PCBEX_FABRICATION_STATUS
  PCBEX_FABRICATION_REPORT
  PCBEX_FABRICATION_AUTHORIZED
  PCBEX_ARTIFACT_SAFE
  PCBEX_PUBLICATION_SAFE
  PCBEX_UPLOAD_ARTIFACT
  PCBEX_UPLOAD_OUTCOME
  PCBEX_REQUIRE_AUTHORIZED
  PCBEX_OUTPUT_DIR
)
for variable in "${required_variables[@]}"; do
  if ! declare -p "$variable" >/dev/null 2>&1; then
    echo "required environment variable is unset: $variable" >&2
    exit 2
  fi
done

if [[ "$PCBEX_PREFLIGHT_VALID" != true ]]; then
  echo "fabrication authorization Action inputs are invalid" >&2
  exit 1
fi
if [[ "$PCBEX_FABRICATION_OUTCOME" != success ]]; then
  echo "fabrication authorization verifier step did not complete successfully" >&2
  exit 1
fi
if [[ "$PCBEX_FABRICATION_STATUS" != ok ]]; then
  echo "fabrication authorization verification failed" >&2
  exit 1
fi
if [[ -z "$PCBEX_FABRICATION_REPORT" ||
  "$PCBEX_FABRICATION_REPORT" != "$PCBEX_OUTPUT_DIR/fabrication-authorization.json" ]]; then
  echo "fabrication authorization report is unavailable or not the fixed Action path" >&2
  exit 1
fi
if [[ "$PCBEX_ARTIFACT_SAFE" != true ]]; then
  echo "fabrication authorization evidence failed the bounded artifact scan" >&2
  exit 1
fi
if [[ "$PCBEX_PUBLICATION_SAFE" != true ]]; then
  echo "fabrication authorization evidence failed publication-time revalidation" >&2
  exit 1
fi
case "$PCBEX_UPLOAD_ARTIFACT" in
  true)
    if [[ "$PCBEX_UPLOAD_OUTCOME" != success ]]; then
      echo "fabrication authorization evidence artifact was not uploaded" >&2
      exit 1
    fi
    ;;
  false) ;;
  *)
    echo "upload-artifact must be true or false" >&2
    exit 2
    ;;
esac
case "$PCBEX_FABRICATION_AUTHORIZED" in
  true|false) ;;
  *)
    echo "fabrication authorization decision is malformed" >&2
    exit 2
    ;;
esac
case "$PCBEX_REQUIRE_AUTHORIZED" in
  true)
    if [[ "$PCBEX_FABRICATION_AUTHORIZED" != true ]]; then
      echo "fabrication authorization quorum did not authorize the exact scope" >&2
      exit 1
    fi
    ;;
  false) ;;
  *)
    echo "require-authorized must be true or false" >&2
    exit 2
    ;;
esac

#!/usr/bin/env bash
set -euo pipefail

required_variables=(
  PCBEX_PREFLIGHT_VALID
  PCBEX_NATIVE_ERC_OUTCOME
  PCBEX_NATIVE_ERC_STATUS
  PCBEX_NATIVE_ERC_REPORT
  PCBEX_NATIVE_ERC_APPROVED
  PCBEX_ARTIFACT_SAFE
  PCBEX_UPLOAD_ARTIFACT
  PCBEX_UPLOAD_OUTCOME
  PCBEX_REQUIRE_APPROVED
)
for variable in "${required_variables[@]}"; do
  if ! declare -p "$variable" >/dev/null 2>&1; then
    echo "required environment variable is unset: $variable" >&2
    exit 2
  fi
done

if [[ "$PCBEX_PREFLIGHT_VALID" != "true" ]]; then
  echo "native KiCad ERC Action inputs are invalid" >&2
  exit 1
fi
if [[ "$PCBEX_NATIVE_ERC_OUTCOME" != "success" ]]; then
  echo "native KiCad ERC wrapper step did not complete successfully" >&2
  exit 1
fi
if [[ "$PCBEX_NATIVE_ERC_STATUS" != "ok" ]]; then
  echo "native KiCad ERC execution or evidence verification failed" >&2
  exit 1
fi
if [[ "$PCBEX_ARTIFACT_SAFE" != "true" ]]; then
  echo "native KiCad ERC evidence failed the bounded artifact scan" >&2
  exit 1
fi
case "$PCBEX_UPLOAD_ARTIFACT" in
  true)
    if [[ "$PCBEX_UPLOAD_OUTCOME" != "success" ]]; then
      echo "native KiCad ERC evidence artifact was not uploaded" >&2
      exit 1
    fi
    ;;
  false) ;;
  *)
    echo "upload-artifact must be true or false" >&2
    exit 2
    ;;
esac
case "$PCBEX_REQUIRE_APPROVED" in
  true)
    if [[ -z "$PCBEX_NATIVE_ERC_REPORT" ||
      "$PCBEX_NATIVE_ERC_APPROVED" != "true" ]]; then
      echo "native KiCad ERC report is absent or not approved" >&2
      exit 1
    fi
    ;;
  false) ;;
  *)
    echo "require-approved must be true or false" >&2
    exit 2
    ;;
esac

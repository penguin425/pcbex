#!/usr/bin/env bash
set -euo pipefail

required_variables=(
  PCBEX_PREFLIGHT_VALID
  PCBEX_AI_OUTCOME
  PCBEX_AI_STATUS
  PCBEX_AI_REPORT
  PCBEX_AI_SUMMARY
  PCBEX_AI_QUORUM_MET
  PCBEX_ARTIFACT_SAFE
  PCBEX_PUBLICATION_SAFE
  PCBEX_PUBLICATION_QUORUM_MET
  PCBEX_UPLOAD_ARTIFACT
  PCBEX_UPLOAD_OUTCOME
  PCBEX_REQUIRE_QUORUM
)
for variable in "${required_variables[@]}"; do
  if ! declare -p "$variable" >/dev/null 2>&1; then
    echo "required environment variable is unset: $variable" >&2
    exit 2
  fi
done

if [[ "$PCBEX_PREFLIGHT_VALID" != true ]]; then
  echo "AI schematic approval Action inputs are invalid" >&2
  exit 1
fi
if [[ "$PCBEX_AI_OUTCOME" != success ]]; then
  echo "AI schematic approval verifier step did not complete successfully" >&2
  exit 1
fi
if [[ "$PCBEX_AI_STATUS" != ok ]]; then
  echo "AI schematic approval verification failed" >&2
  exit 1
fi
if [[ -z "$PCBEX_AI_REPORT" || -z "$PCBEX_AI_SUMMARY" ]]; then
  echo "AI schematic approval evidence is unavailable" >&2
  exit 1
fi
if [[ "$PCBEX_ARTIFACT_SAFE" != true ]]; then
  echo "AI schematic approval evidence failed the bounded artifact scan" >&2
  exit 1
fi
if [[ "$PCBEX_PUBLICATION_SAFE" != true ]]; then
  echo "AI schematic approval evidence failed publication-time revalidation" >&2
  exit 1
fi
case "$PCBEX_PUBLICATION_QUORUM_MET" in
  true|false) ;;
  *)
    echo "publication-time AI schematic approval quorum result is malformed" >&2
    exit 2
    ;;
esac
if [[ "$PCBEX_PUBLICATION_QUORUM_MET" != "$PCBEX_AI_QUORUM_MET" ]]; then
  echo "AI schematic approval quorum changed before publication" >&2
  exit 1
fi
case "$PCBEX_UPLOAD_ARTIFACT" in
  true)
    if [[ "$PCBEX_UPLOAD_OUTCOME" != success ]]; then
      echo "AI schematic approval evidence artifact was not uploaded" >&2
      exit 1
    fi
    ;;
  false) ;;
  *)
    echo "upload-artifact must be true or false" >&2
    exit 2
    ;;
esac
case "$PCBEX_AI_QUORUM_MET" in
  true|false) ;;
  *)
    echo "AI schematic approval quorum result is malformed" >&2
    exit 2
    ;;
esac
case "$PCBEX_REQUIRE_QUORUM" in
  true)
    if [[ "$PCBEX_AI_QUORUM_MET" != true ]]; then
      echo "AI schematic approval quorum did not meet every threshold" >&2
      exit 1
    fi
    ;;
  false) ;;
  *)
    echo "require-quorum must be true or false" >&2
    exit 2
    ;;
esac

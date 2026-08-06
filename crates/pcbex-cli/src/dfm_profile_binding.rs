//! Canonical identity for fabrication (DFM) profiles.
//!
//! Physical constraint profiles have a separate binding contract because they
//! describe board geometry as well as manufacturing rules.  This module only
//! binds the DFM profile selected by `--fab`/`--fab-profile`; the two kinds of
//! profile remain mutually exclusive at the CLI boundary.

use anyhow::{Context, Result, bail};
use pcbex_core::{DfmProfile, MAX_DFM_PROFILE_TEXT_BYTES, dfm_profile, validate_dfm_profile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(crate) const DFM_PROFILE_BINDING_SCHEMA_VERSION: u32 = 1;
const DFM_PROFILE_DIGEST_DOMAIN: &[u8] = b"pcbex-dfm-profile-v1\0";

/// The exact external file descriptor retained in a DFM binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DfmProfileSource {
    pub(crate) path: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

/// Explicit provenance for one normalized DFM profile.
///
/// Policy-pack provenance is intentionally not represented in v1.447.  The
/// policy-pack path remains on its existing analysis-only contract until a
/// later release can bind the containing pack as well as its embedded object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DfmProfileOrigin {
    External { source: DfmProfileSource },
    Builtin { id: String },
}

/// Stable identity for the normalized DFM profile selected for a run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DfmProfileBinding {
    pub(crate) schema_version: u32,
    pub(crate) id: String,
    pub(crate) revision: u32,
    pub(crate) canonical_sha256: String,
    pub(crate) origin: DfmProfileOrigin,
}

pub(crate) fn external_dfm_profile_binding(
    profile: &DfmProfile,
    path: &Path,
    bytes: &[u8],
) -> Result<DfmProfileBinding> {
    let source_path = portable_source_name(path)?;
    let source_bytes = u64::try_from(bytes.len())
        .map_err(|_| anyhow::anyhow!("DFM profile byte count cannot be represented"))?;
    if source_bytes == 0 || source_bytes > MAX_DFM_PROFILE_TEXT_BYTES as u64 {
        bail!(
            "DFM profile source must contain 1 to {} bytes",
            MAX_DFM_PROFILE_TEXT_BYTES
        );
    }
    let binding = DfmProfileBinding {
        schema_version: DFM_PROFILE_BINDING_SCHEMA_VERSION,
        id: profile.id.clone(),
        revision: profile.revision,
        canonical_sha256: canonical_dfm_profile_sha256(profile)?,
        origin: DfmProfileOrigin::External {
            source: DfmProfileSource {
                path: source_path,
                bytes: source_bytes,
                sha256: hex::encode(Sha256::digest(bytes)),
            },
        },
    };
    validate_dfm_profile_binding(&binding)?;
    binding_matches_profile(&binding, profile)?;
    Ok(binding)
}

pub(crate) fn builtin_dfm_profile_binding(profile: &DfmProfile) -> Result<DfmProfileBinding> {
    let binding = DfmProfileBinding {
        schema_version: DFM_PROFILE_BINDING_SCHEMA_VERSION,
        id: profile.id.clone(),
        revision: profile.revision,
        canonical_sha256: canonical_dfm_profile_sha256(profile)?,
        origin: DfmProfileOrigin::Builtin {
            id: profile.id.clone(),
        },
    };
    validate_dfm_profile_binding(&binding)?;
    binding_matches_profile(&binding, profile)?;
    Ok(binding)
}

pub(crate) fn canonical_dfm_profile_sha256(profile: &DfmProfile) -> Result<String> {
    validate_dfm_profile(profile).map_err(anyhow::Error::msg)?;
    let canonical = serde_json::to_vec(profile).context("serializing canonical DFM profile")?;
    let mut digest = Sha256::new();
    digest.update(DFM_PROFILE_DIGEST_DOMAIN);
    digest.update(canonical);
    Ok(hex::encode(digest.finalize()))
}

pub(crate) fn validate_dfm_profile_binding(binding: &DfmProfileBinding) -> Result<()> {
    if binding.schema_version != DFM_PROFILE_BINDING_SCHEMA_VERSION {
        bail!(
            "DFM profile binding must use schema_version {}",
            DFM_PROFILE_BINDING_SCHEMA_VERSION
        );
    }
    validate_identifier(&binding.id, "DFM profile binding id")?;
    if binding.revision == 0 {
        bail!("DFM profile binding revision must be greater than zero");
    }
    if !is_sha256(&binding.canonical_sha256) {
        bail!("DFM profile binding canonical_sha256 is invalid");
    }
    match &binding.origin {
        DfmProfileOrigin::External { source } => {
            validate_source_name(&source.path)?;
            if source.bytes == 0 || source.bytes > MAX_DFM_PROFILE_TEXT_BYTES as u64 {
                bail!(
                    "DFM profile binding source must contain 1 to {} bytes",
                    MAX_DFM_PROFILE_TEXT_BYTES
                );
            }
            if !is_sha256(&source.sha256) {
                bail!("DFM profile binding source sha256 is invalid");
            }
        }
        DfmProfileOrigin::Builtin { id } => {
            validate_identifier(id, "DFM built-in profile id")?;
            if id != &binding.id {
                bail!("DFM built-in origin id does not match binding id");
            }
            let Some(profile) = dfm_profile(id) else {
                bail!("DFM built-in origin id is not a known built-in profile");
            };
            if profile.id != binding.id || profile.revision != binding.revision {
                bail!("DFM built-in origin identity does not match the binding");
            }
            if binding.canonical_sha256 != canonical_dfm_profile_sha256(&profile)? {
                bail!("DFM built-in origin canonical digest does not match the built-in profile");
            }
        }
    }
    Ok(())
}

pub(crate) fn binding_matches_profile(
    binding: &DfmProfileBinding,
    profile: &DfmProfile,
) -> Result<()> {
    validate_dfm_profile_binding(binding)?;
    validate_dfm_profile(profile).map_err(anyhow::Error::msg)?;
    if binding.id != profile.id || binding.revision != profile.revision {
        bail!("DFM profile binding identity does not match the normalized profile");
    }
    if binding.canonical_sha256 != canonical_dfm_profile_sha256(profile)? {
        bail!("DFM profile binding canonical digest does not match the normalized profile");
    }
    if let DfmProfileOrigin::Builtin { id } = &binding.origin
        && id != &profile.id
    {
        bail!("DFM built-in origin id does not match the normalized profile");
    }
    Ok(())
}

fn portable_source_name(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("DFM profile must have a UTF-8 filename"))?
        .to_string();
    validate_source_name(&name)?;
    Ok(name)
}

fn validate_source_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        bail!("DFM profile source path must be one portable filename");
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(b'a'..=b'z' | b'0'..=b'9'))
        || value.len() > 128
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
    {
        bail!("{label} must match [a-z0-9][a-z0-9.-]{{0,127}}");
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcbex_core::dfm_profile;
    use std::fs;

    fn profile() -> DfmProfile {
        dfm_profile("jlcpcb-2layer").unwrap()
    }

    #[test]
    fn external_binding_separates_raw_and_canonical_digests() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.json");
        let second = directory.path().join("second.json");
        let source = serde_json::to_string_pretty(&profile()).unwrap();
        fs::write(&first, source.as_bytes()).unwrap();
        let compact = serde_json::to_vec(&profile()).unwrap();
        fs::write(&second, &compact).unwrap();
        let first = external_dfm_profile_binding(&profile(), &first, source.as_bytes()).unwrap();
        let second = external_dfm_profile_binding(&profile(), &second, &compact).unwrap();
        assert_eq!(first.canonical_sha256, second.canonical_sha256);
        assert_ne!(
            external_source(&first).sha256,
            external_source(&second).sha256
        );
        binding_matches_profile(&first, &profile()).unwrap();
    }

    #[test]
    fn builtin_binding_has_closed_origin_without_fake_source() {
        let binding = builtin_dfm_profile_binding(&profile()).unwrap();
        assert!(matches!(binding.origin, DfmProfileOrigin::Builtin { .. }));
        binding_matches_profile(&binding, &profile()).unwrap();
        let value = serde_json::to_value(binding).unwrap();
        assert!(value["origin"]["source"].is_null());
    }

    #[test]
    fn forged_binding_is_rejected() {
        let mut binding = builtin_dfm_profile_binding(&profile()).unwrap();
        binding.canonical_sha256 = "0".repeat(64);
        assert!(binding_matches_profile(&binding, &profile()).is_err());
    }

    #[test]
    fn binding_identifiers_reject_uppercase_and_underscore() {
        let mut uppercase = builtin_dfm_profile_binding(&profile()).unwrap();
        uppercase.id = "JLCPCB-2LAYER".into();
        assert!(validate_dfm_profile_binding(&uppercase).is_err());

        let mut underscore = builtin_dfm_profile_binding(&profile()).unwrap();
        underscore.id = "jlcpcb_2layer".into();
        assert!(validate_dfm_profile_binding(&underscore).is_err());
    }

    #[test]
    fn builtin_binding_rejects_alias_ids_and_revision_forgery() {
        let resolved = profile();
        let canonical = canonical_dfm_profile_sha256(&resolved).unwrap();

        let mut alias = builtin_dfm_profile_binding(&resolved).unwrap();
        alias.id = "jlcpcb-2layer".into();
        alias.origin = DfmProfileOrigin::Builtin {
            id: "jlcpcb-2layer".into(),
        };
        alias.canonical_sha256 = canonical.clone();
        assert!(validate_dfm_profile_binding(&alias).is_err());

        let mut forged_revision = builtin_dfm_profile_binding(&resolved).unwrap();
        forged_revision.revision += 1;
        forged_revision.canonical_sha256 = canonical;
        assert!(validate_dfm_profile_binding(&forged_revision).is_err());
    }

    fn external_source(binding: &DfmProfileBinding) -> &DfmProfileSource {
        match &binding.origin {
            DfmProfileOrigin::External { source } => source,
            DfmProfileOrigin::Builtin { .. } => panic!("expected external origin"),
        }
    }
}

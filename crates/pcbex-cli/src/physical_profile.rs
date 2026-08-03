//! Bounded loading and deterministic evidence for physical constraint profiles.

use crate::bounded_io;
use anyhow::{Context, Result, bail};
use pcbex_core::{PhysicalConstraintProfile, parse_physical_profile, validate_physical_profile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(crate) const MAX_PHYSICAL_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
const PHYSICAL_PROFILE_DIGEST_DOMAIN: &[u8] = b"pcbex-physical-profile-v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhysicalProfileSource {
    pub(crate) path: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhysicalProfileBinding {
    pub(crate) schema_version: u32,
    pub(crate) id: String,
    pub(crate) revision: u32,
    pub(crate) canonical_sha256: String,
    pub(crate) source: PhysicalProfileSource,
}

#[derive(Clone, Debug)]
pub(crate) struct LoadedPhysicalProfile {
    pub(crate) profile: PhysicalConstraintProfile,
    pub(crate) binding: PhysicalProfileBinding,
}

pub(crate) fn load_physical_profile(path: &Path) -> Result<LoadedPhysicalProfile> {
    let bytes = bounded_io::read_with_limit(path, MAX_PHYSICAL_PROFILE_BYTES)
        .with_context(|| format!("reading physical profile {}", path.display()))?;
    if bytes.is_empty() {
        bail!("physical profile must not be empty");
    }
    let source = std::str::from_utf8(&bytes)
        .with_context(|| format!("decoding physical profile {} as UTF-8", path.display()))?;
    let profile = parse_physical_profile(source)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("validating physical profile {}", path.display()))?;
    let path = portable_source_name(path)?;
    let source_bytes = u64::try_from(bytes.len())
        .map_err(|_| anyhow::anyhow!("physical profile byte count cannot be represented"))?;
    let binding = PhysicalProfileBinding {
        schema_version: 1,
        id: profile.id.clone(),
        revision: profile.revision,
        canonical_sha256: canonical_profile_sha256(&profile)?,
        source: PhysicalProfileSource {
            path,
            bytes: source_bytes,
            sha256: hex::encode(Sha256::digest(&bytes)),
        },
    };
    validate_physical_profile_binding(&binding)?;
    Ok(LoadedPhysicalProfile { profile, binding })
}

pub(crate) fn canonical_profile_sha256(profile: &PhysicalConstraintProfile) -> Result<String> {
    validate_physical_profile(profile).map_err(anyhow::Error::msg)?;
    let canonical = serde_json::to_vec(profile)?;
    let mut digest = Sha256::new();
    digest.update(PHYSICAL_PROFILE_DIGEST_DOMAIN);
    digest.update(canonical);
    Ok(hex::encode(digest.finalize()))
}

pub(crate) fn validate_physical_profile_binding(binding: &PhysicalProfileBinding) -> Result<()> {
    if binding.schema_version != 1 {
        bail!("physical profile binding must use schema_version 1");
    }
    validate_identifier(&binding.id, "physical profile binding id")?;
    if binding.revision == 0 {
        bail!("physical profile binding revision must be greater than zero");
    }
    if !is_sha256(&binding.canonical_sha256) {
        bail!("physical profile binding canonical_sha256 is invalid");
    }
    validate_source_name(&binding.source.path)?;
    if binding.source.bytes == 0 || binding.source.bytes > MAX_PHYSICAL_PROFILE_BYTES {
        bail!(
            "physical profile binding source must contain 1 to {} bytes",
            MAX_PHYSICAL_PROFILE_BYTES
        );
    }
    if !is_sha256(&binding.source.sha256) {
        bail!("physical profile binding source sha256 is invalid");
    }
    Ok(())
}

pub(crate) fn binding_matches_profile(
    binding: &PhysicalProfileBinding,
    profile: &PhysicalConstraintProfile,
) -> Result<()> {
    validate_physical_profile_binding(binding)?;
    if binding.id != profile.id || binding.revision != profile.revision {
        bail!("physical profile binding identity does not match the normalized profile");
    }
    if binding.canonical_sha256 != canonical_profile_sha256(profile)? {
        bail!("physical profile binding canonical digest does not match the normalized profile");
    }
    Ok(())
}

fn portable_source_name(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("physical profile must have a UTF-8 filename"))?
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
        bail!("physical profile source path must be one portable filename");
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'))
        || value.len() > 128
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{label} must be a non-empty safe identifier");
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
    use std::fs;

    fn profile_source() -> &'static str {
        r#"{
          "schema_version": 1,
          "id": "fixture-v1",
          "revision": 1,
          "description": "fixture",
          "board_width_nm": 60000000,
          "board_height_nm": 40000000,
          "outline": [],
          "fixed_components": [],
          "keepouts": [],
          "manufacturing_rules": null
        }"#
    }

    #[test]
    fn binding_separates_raw_and_canonical_digests() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.json");
        let second = directory.path().join("second.json");
        fs::write(&first, profile_source()).unwrap();
        let compact: serde_json::Value = serde_json::from_str(profile_source()).unwrap();
        fs::write(&second, serde_json::to_vec(&compact).unwrap()).unwrap();

        let first = load_physical_profile(&first).unwrap();
        let second = load_physical_profile(&second).unwrap();
        assert_eq!(
            first.binding.canonical_sha256,
            second.binding.canonical_sha256
        );
        assert_ne!(first.binding.source.sha256, second.binding.source.sha256);
        binding_matches_profile(&first.binding, &first.profile).unwrap();
    }

    #[test]
    fn rejects_forged_binding() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.json");
        fs::write(&path, profile_source()).unwrap();
        let loaded = load_physical_profile(&path).unwrap();
        let mut forged = loaded.binding;
        forged.canonical_sha256 = "0".repeat(64);
        assert!(binding_matches_profile(&forged, &loaded.profile).is_err());
    }
}

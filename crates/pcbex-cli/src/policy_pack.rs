use pcbex_core::{DfmProfile, dfm_profile, dfm_profile_json_schema, validate_dfm_profile};
use pcbex_kicad::{
    AiRequirement, ElectricalPolicy, electrical_policy_json_schema, parse_electrical_policy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;

pub const POLICY_PACK_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedApprovalKey {
    pub signer_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationPolicyPack {
    pub schema_version: u32,
    pub id: String,
    pub revision: u32,
    pub verified_on: String,
    pub description: String,
    pub dfm_profile: DfmProfile,
    pub electrical_policy: ElectricalPolicy,
    pub ai_requirements: Vec<AiRequirement>,
    pub require_simulation_evidence: bool,
    pub trusted_approval_keys: Vec<TrustedApprovalKey>,
}

pub fn parse_policy_pack(source: &str) -> Result<OrganizationPolicyPack, String> {
    let pack: OrganizationPolicyPack = serde_json::from_str(source)
        .map_err(|error| format!("invalid organization policy pack JSON: {error}"))?;
    validate_policy_pack(&pack)?;
    Ok(pack)
}

pub fn validate_policy_pack(pack: &OrganizationPolicyPack) -> Result<(), String> {
    if pack.schema_version != POLICY_PACK_SCHEMA_VERSION {
        return Err(format!(
            "unsupported organization policy pack schema_version {}; expected {}",
            pack.schema_version, POLICY_PACK_SCHEMA_VERSION
        ));
    }
    validate_slug("policy pack id", &pack.id)?;
    if pack.revision == 0 {
        return Err("organization policy pack revision must be greater than zero".into());
    }
    validate_date(&pack.verified_on)?;
    if pack.description.trim().is_empty() || pack.description.len() > 1024 {
        return Err("organization policy pack description must contain 1 to 1024 bytes".into());
    }
    validate_dfm_profile(&pack.dfm_profile)?;
    for name in std::iter::once(&pack.dfm_profile.id).chain(&pack.dfm_profile.aliases) {
        if let Some(builtin) = dfm_profile(name)
            && builtin != pack.dfm_profile
        {
            return Err(format!(
                "DFM profile name {name:?} collides with a different built-in profile"
            ));
        }
    }
    parse_electrical_policy(
        &serde_json::to_string(&pack.electrical_policy)
            .map_err(|error| format!("serializing electrical policy: {error}"))?,
    )?;
    if pack.ai_requirements.is_empty() || pack.ai_requirements.len() > 1_000 {
        return Err("ai_requirements must contain 1 to 1000 entries".into());
    }
    let mut requirements = HashSet::new();
    for requirement in &pack.ai_requirements {
        validate_slug("AI requirement id", &requirement.id)?;
        if requirement.text.trim().is_empty() || requirement.text.len() > 4096 {
            return Err(format!(
                "AI requirement {} text must contain 1 to 4096 bytes",
                requirement.id
            ));
        }
        if !requirements.insert(&requirement.id) {
            return Err(format!("duplicate AI requirement id {:?}", requirement.id));
        }
    }
    if pack.trusted_approval_keys.is_empty() || pack.trusted_approval_keys.len() > 100 {
        return Err("trusted_approval_keys must contain 1 to 100 entries".into());
    }
    let mut signers = HashSet::new();
    let mut keys = HashSet::new();
    for trusted in &pack.trusted_approval_keys {
        validate_slug("trusted signer id", &trusted.signer_id)?;
        validate_public_key(&trusted.public_key)?;
        if !signers.insert(&trusted.signer_id) {
            return Err(format!(
                "duplicate trusted signer id {:?}",
                trusted.signer_id
            ));
        }
        if !keys.insert(&trusted.public_key) {
            return Err("duplicate trusted approval public key".into());
        }
    }
    Ok(())
}

pub fn policy_pack_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/organization-policy-pack-v1.json",
        "title": "pcbex organization policy pack",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "id", "revision", "verified_on", "description",
            "dfm_profile", "electrical_policy", "ai_requirements",
            "require_simulation_evidence", "trusted_approval_keys"
        ],
        "properties": {
            "schema_version": {"const": POLICY_PACK_SCHEMA_VERSION},
            "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "revision": {"type": "integer", "minimum": 1, "maximum": 4294967295_u64},
            "verified_on": {"type": "string", "format": "date"},
            "description": {"type": "string", "minLength": 1, "maxLength": 1024},
            "dfm_profile": dfm_profile_json_schema(),
            "electrical_policy": electrical_policy_json_schema(),
            "ai_requirements": {
                "type": "array", "minItems": 1, "maxItems": 1000,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["id", "text"],
                    "properties": {
                        "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                        "text": {"type": "string", "minLength": 1, "maxLength": 4096}
                    }
                }
            },
            "require_simulation_evidence": {"type": "boolean"},
            "trusted_approval_keys": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["signer_id", "public_key"],
                    "properties": {
                        "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                        "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    }
                }
            }
        }
    })
}

fn validate_slug(label: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit());
    if !valid {
        return Err(format!(
            "{label} {value:?} must match [a-z0-9][a-z0-9.-]{{0,127}}"
        ));
    }
    Ok(())
}

fn validate_date(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return Err(format!(
            "verified_on {value:?} must be a valid YYYY-MM-DD date"
        ));
    }
    let values = value
        .split('-')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("verified_on {value:?} must be a valid YYYY-MM-DD date"))?;
    let (year, month, day) = (values[0], values[1], values[2]);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days {
        return Err(format!(
            "verified_on {value:?} must be a valid YYYY-MM-DD date"
        ));
    }
    Ok(())
}

fn validate_public_key(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "trusted approval public keys must contain 64 lowercase hexadecimal digits".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OrganizationPolicyPack {
        parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json")).unwrap()
    }

    #[test]
    fn parses_complete_strict_policy_pack() {
        let pack = sample();
        assert_eq!(pack.id, "acme-production-v1");
        assert_eq!(pack.ai_requirements.len(), 2);
        assert!(pack.require_simulation_evidence);
    }

    #[test]
    fn rejects_unknown_fields_and_builtin_dfm_impersonation() {
        let mut value = serde_json::to_value(sample()).unwrap();
        value["unexpected"] = true.into();
        assert!(parse_policy_pack(&value.to_string()).is_err());

        value.as_object_mut().unwrap().remove("unexpected");
        value["dfm_profile"]["id"] = "jlcpcb-2layer".into();
        value["dfm_profile"]["aliases"] = serde_json::json!([]);
        assert!(
            parse_policy_pack(&value.to_string())
                .unwrap_err()
                .contains("collides")
        );
    }

    #[test]
    fn schema_closes_pack_and_trusted_keys() {
        let schema = policy_pack_json_schema();
        assert_eq!(schema["properties"]["schema_version"]["const"], 1);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["trusted_approval_keys"]["items"]["additionalProperties"],
            false
        );
    }
}

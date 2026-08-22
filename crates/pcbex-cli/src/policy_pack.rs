use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_core::{DfmProfile, dfm_profile, dfm_profile_json_schema, validate_dfm_profile};
use pcbex_kicad::{
    AiRequirement, ElectricalPolicy, electrical_policy_json_schema, parse_electrical_policy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;

pub const POLICY_PACK_SCHEMA_VERSION: u32 = 1;
pub const SIGNED_POLICY_PACK_SCHEMA_VERSION: u32 = 1;
pub const POLICY_TRUST_STATE_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-organization-policy-pack-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedApprovalKey {
    pub signer_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricationAuthorizationPolicy {
    pub minimum_approvals: u32,
    pub maximum_validity_seconds: u64,
    pub trusted_keys: Vec<TrustedApprovalKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcurementAuthorizationPolicy {
    pub minimum_approvals: u32,
    pub currency: String,
    pub maximum_validity_seconds: u64,
    pub maximum_receipt_observation_age_seconds: u64,
    pub maximum_component_subtotal_micros: u64,
    pub trusted_keys: Vec<TrustedApprovalKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedFactoryReceiptKey {
    pub factory_id: String,
    pub provider: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryReceiptAttestationPolicy {
    pub maximum_validity_seconds: u64,
    pub trusted_keys: Vec<TrustedFactoryReceiptKey>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_human_escalation_keys: Vec<TrustedApprovalKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fabrication_authorization_policy: Option<FabricationAuthorizationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procurement_authorization_policy: Option<ProcurementAuthorizationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factory_receipt_attestation_policy: Option<FactoryReceiptAttestationPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyPack {
    pub schema_version: u32,
    pub policy_pack: OrganizationPolicyPack,
    pub policy_pack_sha256: String,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTrustState {
    pub schema_version: u32,
    pub policy_pack_id: String,
    pub accepted_revision: u32,
    pub policy_pack_sha256: String,
    pub signer_id: String,
    pub public_key: String,
}

#[derive(Serialize)]
struct PolicyPackSignaturePayload<'a> {
    domain: &'static str,
    policy_pack_sha256: &'a str,
    policy_pack_id: &'a str,
    policy_pack_revision: u32,
    signer_id: &'a str,
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
    if pack.trusted_human_escalation_keys.len() > 100 {
        return Err("trusted_human_escalation_keys cannot exceed 100 entries".into());
    }
    let mut human_signers = HashSet::new();
    for trusted in &pack.trusted_human_escalation_keys {
        validate_slug("trusted human escalation signer id", &trusted.signer_id)?;
        validate_public_key(&trusted.public_key)?;
        if !human_signers.insert(&trusted.signer_id) {
            return Err(format!(
                "duplicate trusted human escalation signer id {:?}",
                trusted.signer_id
            ));
        }
        if signers.contains(&trusted.signer_id) {
            return Err(format!(
                "signer {:?} cannot hold both AI and human escalation roles",
                trusted.signer_id
            ));
        }
        if !keys.insert(&trusted.public_key) {
            return Err("a public key cannot hold both AI and human escalation trust roles".into());
        }
    }
    let mut assigned_signers: HashSet<&String> = signers.union(&human_signers).copied().collect();
    let mut assigned_keys = keys;
    if let Some(policy) = &pack.fabrication_authorization_policy {
        if !(2..=100).contains(&policy.minimum_approvals) {
            return Err(
                "fabrication authorization minimum_approvals must be between 2 and 100".into(),
            );
        }
        if !(1..=604_800).contains(&policy.maximum_validity_seconds) {
            return Err(
                "fabrication authorization maximum_validity_seconds must be between 1 and 604800"
                    .into(),
            );
        }
        if !(2..=100).contains(&policy.trusted_keys.len()) {
            return Err(
                "fabrication authorization trusted_keys must contain 2 to 100 entries".into(),
            );
        }
        if policy.minimum_approvals as usize > policy.trusted_keys.len() {
            return Err(
                "fabrication authorization minimum_approvals cannot exceed trusted_keys".into(),
            );
        }
        let mut fabrication_signers = HashSet::new();
        let mut fabrication_keys = HashSet::new();
        for trusted in &policy.trusted_keys {
            validate_slug("trusted fabrication signer id", &trusted.signer_id)?;
            validate_public_key(&trusted.public_key)?;
            if !fabrication_signers.insert(&trusted.signer_id) {
                return Err(format!(
                    "duplicate trusted fabrication signer id {:?}",
                    trusted.signer_id
                ));
            }
            if assigned_signers.contains(&trusted.signer_id) {
                return Err(format!(
                    "signer {:?} cannot hold both fabrication authorization and another trust role",
                    trusted.signer_id
                ));
            }
            if !fabrication_keys.insert(&trusted.public_key) {
                return Err("duplicate trusted fabrication authorization public key".into());
            }
            if assigned_keys.contains(&trusted.public_key) {
                return Err(
                    "a public key cannot hold fabrication authorization and another trust role"
                        .into(),
                );
            }
            assigned_signers.insert(&trusted.signer_id);
            assigned_keys.insert(&trusted.public_key);
        }
    }
    if let Some(policy) = &pack.procurement_authorization_policy {
        if !(2..=100).contains(&policy.minimum_approvals) {
            return Err(
                "procurement authorization minimum_approvals must be between 2 and 100".into(),
            );
        }
        if policy.currency.len() != 3
            || !policy
                .currency
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
        {
            return Err(
                "procurement authorization currency must contain exactly three uppercase ASCII letters"
                    .into(),
            );
        }
        if !(1..=604_800).contains(&policy.maximum_validity_seconds) {
            return Err(
                "procurement authorization maximum_validity_seconds must be between 1 and 604800"
                    .into(),
            );
        }
        if !(1..=604_800).contains(&policy.maximum_receipt_observation_age_seconds) {
            return Err(
                "procurement authorization maximum_receipt_observation_age_seconds must be between 1 and 604800"
                    .into(),
            );
        }
        if !(1..=9_007_199_254_740_991).contains(&policy.maximum_component_subtotal_micros) {
            return Err(
                "procurement authorization maximum_component_subtotal_micros must be between 1 and 9007199254740991"
                    .into(),
            );
        }
        if !(2..=100).contains(&policy.trusted_keys.len()) {
            return Err(
                "procurement authorization trusted_keys must contain 2 to 100 entries".into(),
            );
        }
        if policy.minimum_approvals as usize > policy.trusted_keys.len() {
            return Err(
                "procurement authorization minimum_approvals cannot exceed trusted_keys".into(),
            );
        }
        let mut procurement_signers = HashSet::new();
        let mut procurement_keys = HashSet::new();
        for trusted in &policy.trusted_keys {
            validate_slug("trusted procurement signer id", &trusted.signer_id)?;
            validate_public_key(&trusted.public_key)?;
            let public_key = hex_decode_array::<32>(
                &trusted.public_key,
                "trusted procurement approval public key",
            )?;
            let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|error| {
                format!(
                    "invalid trusted procurement approval public key for signer {:?}: {error}",
                    trusted.signer_id
                )
            })?;
            if verifying_key.is_weak() {
                return Err(format!(
                    "weak trusted procurement approval public key for signer {:?}",
                    trusted.signer_id
                ));
            }
            if !procurement_signers.insert(&trusted.signer_id) {
                return Err(format!(
                    "duplicate trusted procurement signer id {:?}",
                    trusted.signer_id
                ));
            }
            if assigned_signers.contains(&trusted.signer_id) {
                return Err(format!(
                    "signer {:?} cannot hold both procurement authorization and another trust role",
                    trusted.signer_id
                ));
            }
            if !procurement_keys.insert(&trusted.public_key) {
                return Err("duplicate trusted procurement authorization public key".into());
            }
            if assigned_keys.contains(&trusted.public_key) {
                return Err(
                    "a public key cannot hold procurement authorization and another trust role"
                        .into(),
                );
            }
            assigned_signers.insert(&trusted.signer_id);
            assigned_keys.insert(&trusted.public_key);
        }
    }
    if let Some(policy) = &pack.factory_receipt_attestation_policy {
        if !(1..=604_800).contains(&policy.maximum_validity_seconds) {
            return Err(
                "factory receipt attestation maximum_validity_seconds must be between 1 and 604800"
                    .into(),
            );
        }
        if !(1..=100).contains(&policy.trusted_keys.len()) {
            return Err(
                "factory receipt attestation trusted_keys must contain 1 to 100 entries".into(),
            );
        }
        let mut factory_ids = HashSet::new();
        let mut factory_keys = HashSet::new();
        for trusted in &policy.trusted_keys {
            validate_slug("trusted factory receipt signer id", &trusted.factory_id)?;
            if !matches!(trusted.provider.as_str(), "jlcpcb" | "pcbway" | "generic") {
                return Err(
                    "trusted factory receipt provider must be one of jlcpcb, pcbway, or generic"
                        .into(),
                );
            }
            validate_public_key(&trusted.public_key)?;
            let public_key = hex_decode_array::<32>(
                &trusted.public_key,
                "trusted factory receipt attestation public key",
            )?;
            let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|error| {
                format!(
                    "invalid trusted factory receipt attestation public key for factory {:?}: {error}",
                    trusted.factory_id
                )
            })?;
            if verifying_key.is_weak() {
                return Err(format!(
                    "weak trusted factory receipt attestation public key for factory {:?}",
                    trusted.factory_id
                ));
            }
            if !factory_ids.insert(&trusted.factory_id) {
                return Err(format!(
                    "duplicate trusted factory receipt signer id {:?}",
                    trusted.factory_id
                ));
            }
            if assigned_signers.contains(&trusted.factory_id) {
                return Err(format!(
                    "signer {:?} cannot hold both factory receipt attestation and another trust role",
                    trusted.factory_id
                ));
            }
            if !factory_keys.insert(&trusted.public_key) {
                return Err("duplicate trusted factory receipt attestation public key".into());
            }
            if assigned_keys.contains(&trusted.public_key) {
                return Err(
                    "a public key cannot hold factory receipt attestation and another trust role"
                        .into(),
                );
            }
            assigned_signers.insert(&trusted.factory_id);
            assigned_keys.insert(&trusted.public_key);
        }
    }
    Ok(())
}

pub fn parse_signed_policy_pack(source: &str) -> Result<SignedPolicyPack, String> {
    let signed: SignedPolicyPack = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed policy pack JSON: {error}"))?;
    validate_signed_policy_pack(&signed)?;
    Ok(signed)
}

pub fn sign_policy_pack(
    pack: OrganizationPolicyPack,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedPolicyPack, String> {
    validate_policy_pack(&pack)?;
    validate_slug("policy pack signer id", signer_id)?;
    let policy_pack_sha256 = policy_pack_sha256(&pack)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload = signature_payload(&pack, &policy_pack_sha256, signer_id)?;
    let signature = signing_key.sign(&payload).to_bytes();
    Ok(SignedPolicyPack {
        schema_version: SIGNED_POLICY_PACK_SCHEMA_VERSION,
        policy_pack: pack,
        policy_pack_sha256,
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signature),
    })
}

pub fn verify_signed_policy_pack(
    signed: &SignedPolicyPack,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    validate_signed_policy_pack(signed)?;
    let public_key = hex_decode_array::<32>(&signed.public_key, "policy pack public key")?;
    if &public_key != trusted_public_key {
        return Err("policy pack public key does not match the trusted public key".into());
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid policy pack public key: {error}"))?;
    let signature = Signature::from_bytes(&hex_decode_array::<64>(
        &signed.signature,
        "policy pack signature",
    )?);
    let payload = signature_payload(
        &signed.policy_pack,
        &signed.policy_pack_sha256,
        &signed.signer_id,
    )?;
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|error| format!("invalid policy pack signature: {error}"))
}

pub fn validate_signed_policy_pack(signed: &SignedPolicyPack) -> Result<(), String> {
    if signed.schema_version != SIGNED_POLICY_PACK_SCHEMA_VERSION {
        return Err(format!(
            "unsupported signed policy pack schema_version {}; expected {}",
            signed.schema_version, SIGNED_POLICY_PACK_SCHEMA_VERSION
        ));
    }
    validate_policy_pack(&signed.policy_pack)?;
    validate_slug("policy pack signer id", &signed.signer_id)?;
    if signed.algorithm != "ed25519" {
        return Err(format!(
            "unsupported policy pack signature algorithm {:?}",
            signed.algorithm
        ));
    }
    validate_public_key(&signed.public_key)?;
    validate_hex(&signed.signature, 128, "policy pack signature")?;
    let expected = policy_pack_sha256(&signed.policy_pack)?;
    if signed.policy_pack_sha256 != expected {
        return Err("signed policy pack digest does not match its embedded policy pack".into());
    }
    Ok(())
}

pub fn signed_policy_pack_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-organization-policy-pack-v1.json",
        "title": "pcbex signed organization policy pack",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "policy_pack", "policy_pack_sha256", "signer_id",
            "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": SIGNED_POLICY_PACK_SCHEMA_VERSION},
            "policy_pack": policy_pack_json_schema(),
            "policy_pack_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn parse_policy_trust_state(source: &str) -> Result<PolicyTrustState, String> {
    let state: PolicyTrustState = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy trust state JSON: {error}"))?;
    validate_policy_trust_state(&state)?;
    Ok(state)
}

pub fn advance_policy_trust_state(
    signed: &SignedPolicyPack,
    baseline: Option<&PolicyTrustState>,
) -> Result<PolicyTrustState, String> {
    validate_signed_policy_pack(signed)?;
    if let Some(baseline) = baseline {
        validate_policy_trust_state(baseline)?;
        if baseline.policy_pack_id != signed.policy_pack.id {
            return Err(format!(
                "policy pack id {:?} does not match trusted id {:?}",
                signed.policy_pack.id, baseline.policy_pack_id
            ));
        }
        if baseline.public_key != signed.public_key {
            return Err("policy pack signing key does not match trust state".into());
        }
        if baseline.signer_id != signed.signer_id {
            return Err(format!(
                "policy pack signer {:?} does not match trusted signer {:?}",
                signed.signer_id, baseline.signer_id
            ));
        }
        if signed.policy_pack.revision < baseline.accepted_revision {
            return Err(format!(
                "policy pack revision {} rolls back trusted revision {}",
                signed.policy_pack.revision, baseline.accepted_revision
            ));
        }
        if signed.policy_pack.revision == baseline.accepted_revision
            && signed.policy_pack_sha256 != baseline.policy_pack_sha256
        {
            return Err(format!(
                "policy pack revision {} has a different digest than the trusted revision",
                signed.policy_pack.revision
            ));
        }
    }
    Ok(PolicyTrustState {
        schema_version: POLICY_TRUST_STATE_SCHEMA_VERSION,
        policy_pack_id: signed.policy_pack.id.clone(),
        accepted_revision: signed.policy_pack.revision,
        policy_pack_sha256: signed.policy_pack_sha256.clone(),
        signer_id: signed.signer_id.clone(),
        public_key: signed.public_key.clone(),
    })
}

pub fn policy_trust_state_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-trust-state-v1.json",
        "title": "pcbex organization policy trust state",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "policy_pack_id", "accepted_revision",
            "policy_pack_sha256", "signer_id", "public_key"
        ],
        "properties": {
            "schema_version": {"const": POLICY_TRUST_STATE_SCHEMA_VERSION},
            "policy_pack_id": {
                "type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
            },
            "accepted_revision": {
                "type": "integer", "minimum": 1, "maximum": 4294967295_u64
            },
            "policy_pack_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signer_id": {
                "type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
            },
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        }
    })
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
            },
            "trusted_human_escalation_keys": {
                "type": "array", "maxItems": 100,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["signer_id", "public_key"],
                    "properties": {
                        "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                        "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    }
                }
            },
            "fabrication_authorization_policy": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "minimum_approvals", "maximum_validity_seconds", "trusted_keys"
                ],
                "properties": {
                    "minimum_approvals": {
                        "type": "integer", "minimum": 2, "maximum": 100
                    },
                    "maximum_validity_seconds": {
                        "type": "integer", "minimum": 1, "maximum": 604800
                    },
                    "trusted_keys": {
                        "type": "array", "minItems": 2, "maxItems": 100,
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
            },
            "procurement_authorization_policy": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "minimum_approvals", "currency", "maximum_validity_seconds",
                    "maximum_receipt_observation_age_seconds",
                    "maximum_component_subtotal_micros", "trusted_keys"
                ],
                "properties": {
                    "minimum_approvals": {
                        "type": "integer", "minimum": 2, "maximum": 100
                    },
                    "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
                    "maximum_validity_seconds": {
                        "type": "integer", "minimum": 1, "maximum": 604800
                    },
                    "maximum_receipt_observation_age_seconds": {
                        "type": "integer", "minimum": 1, "maximum": 604800
                    },
                    "maximum_component_subtotal_micros": {
                        "type": "integer", "minimum": 1, "maximum": 9007199254740991_u64
                    },
                    "trusted_keys": {
                        "type": "array", "minItems": 2, "maxItems": 100,
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
            },
            "factory_receipt_attestation_policy": {
                "type": "object", "additionalProperties": false,
                "required": ["maximum_validity_seconds", "trusted_keys"],
                "properties": {
                    "maximum_validity_seconds": {
                        "type": "integer", "minimum": 1, "maximum": 604800
                    },
                    "trusted_keys": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {
                            "type": "object", "additionalProperties": false,
                            "required": ["factory_id", "provider", "public_key"],
                            "properties": {
                                "factory_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                                "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
                                "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                            }
                        }
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
    validate_hex(value, 64, "trusted approval public key")
}

pub fn validate_policy_trust_state(state: &PolicyTrustState) -> Result<(), String> {
    if state.schema_version != POLICY_TRUST_STATE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported policy trust state schema_version {}; expected {}",
            state.schema_version, POLICY_TRUST_STATE_SCHEMA_VERSION
        ));
    }
    validate_slug("trusted policy pack id", &state.policy_pack_id)?;
    if state.accepted_revision == 0 {
        return Err("accepted policy revision must be greater than zero".into());
    }
    validate_hex(&state.policy_pack_sha256, 64, "trusted policy pack SHA-256")?;
    validate_slug("trusted policy signer id", &state.signer_id)?;
    validate_public_key(&state.public_key)
}

fn validate_hex(value: &str, length: usize, label: &str) -> Result<(), String> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "{label} must contain {length} lowercase hexadecimal digits"
        ))
    }
}

pub(crate) fn policy_pack_sha256(pack: &OrganizationPolicyPack) -> Result<String, String> {
    let bytes = serde_json::to_vec(pack)
        .map_err(|error| format!("serializing organization policy pack: {error}"))?;
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn signature_payload(
    pack: &OrganizationPolicyPack,
    policy_pack_sha256: &str,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&PolicyPackSignaturePayload {
        domain: SIGNATURE_DOMAIN,
        policy_pack_sha256,
        policy_pack_id: &pack.id,
        policy_pack_revision: pack.revision,
        signer_id,
    })
    .map_err(|error| format!("serializing policy pack signature payload: {error}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    validate_hex(value, N * 2, label)?;
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("decoding {label}: {error}"))?;
    }
    Ok(bytes)
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
        assert!(pack.fabrication_authorization_policy.is_none());
        assert!(pack.procurement_authorization_policy.is_none());
        assert!(pack.factory_receipt_attestation_policy.is_none());
        assert!(
            !serde_json::to_string(&pack)
                .unwrap()
                .contains("fabrication_authorization_policy")
        );
        assert!(
            !serde_json::to_string(&pack)
                .unwrap()
                .contains("procurement_authorization_policy")
        );
        assert!(
            !serde_json::to_string(&pack)
                .unwrap()
                .contains("factory_receipt_attestation_policy")
        );
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

        let mut value = serde_json::to_value(sample()).unwrap();
        value["trusted_human_escalation_keys"] =
            serde_json::json!([value["trusted_approval_keys"][0].clone()]);
        assert!(
            parse_policy_pack(&value.to_string())
                .unwrap_err()
                .contains("both AI and human escalation")
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
        assert_eq!(
            schema["properties"]["trusted_human_escalation_keys"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["fabrication_authorization_policy"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["fabrication_authorization_policy"]["properties"]["trusted_keys"]
                ["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["procurement_authorization_policy"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["procurement_authorization_policy"]["properties"]["trusted_keys"]
                ["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["factory_receipt_attestation_policy"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["factory_receipt_attestation_policy"]["properties"]["trusted_keys"]
                ["items"]["additionalProperties"],
            false
        );
        assert!(
            !schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "fabrication_authorization_policy")
        );
        assert!(
            !schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "procurement_authorization_policy")
        );
        assert!(
            !schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "factory_receipt_attestation_policy")
        );
    }

    #[test]
    fn validates_factory_receipt_attestation_policy_and_role_separation() {
        let mut pack = sample();
        pack.factory_receipt_attestation_policy = Some(FactoryReceiptAttestationPolicy {
            maximum_validity_seconds: 3_600,
            trusted_keys: vec![TrustedFactoryReceiptKey {
                factory_id: "factory-a".into(),
                provider: "generic".into(),
                public_key: hex::encode(
                    SigningKey::from_bytes(&[71; 32]).verifying_key().to_bytes(),
                ),
            }],
        });
        validate_policy_pack(&pack).unwrap();
        assert_eq!(
            parse_policy_pack(&serde_json::to_string(&pack).unwrap()).unwrap(),
            pack
        );

        pack.factory_receipt_attestation_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .provider = "unknown".into();
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("provider must be one of")
        );
        let ai_signer = pack.trusted_approval_keys[0].signer_id.clone();
        pack.factory_receipt_attestation_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .provider = "generic".into();
        pack.factory_receipt_attestation_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .factory_id = ai_signer;
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("another trust role")
        );

        let procurement_key =
            hex::encode(SigningKey::from_bytes(&[72; 32]).verifying_key().to_bytes());
        pack.procurement_authorization_policy = Some(ProcurementAuthorizationPolicy {
            minimum_approvals: 2,
            currency: "USD".into(),
            maximum_validity_seconds: 3_600,
            maximum_receipt_observation_age_seconds: 300,
            maximum_component_subtotal_micros: 5_000_000,
            trusted_keys: vec![
                TrustedApprovalKey {
                    signer_id: "procurement-factory-shared".into(),
                    public_key: procurement_key.clone(),
                },
                TrustedApprovalKey {
                    signer_id: "procurement-other".into(),
                    public_key: hex::encode(
                        SigningKey::from_bytes(&[73; 32]).verifying_key().to_bytes(),
                    ),
                },
            ],
        });
        let trusted = &mut pack
            .factory_receipt_attestation_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0];
        trusted.factory_id = "factory-a".into();
        trusted.public_key = procurement_key;
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("another trust role")
        );

        pack.procurement_authorization_policy = None;
        pack.factory_receipt_attestation_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .public_key = format!("01{}", "00".repeat(31));
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("weak trusted factory receipt attestation public key")
        );
    }

    #[test]
    fn validates_closed_dedicated_procurement_policy_and_role_separation() {
        let mut pack = sample();
        pack.procurement_authorization_policy = Some(ProcurementAuthorizationPolicy {
            minimum_approvals: 2,
            currency: "USD".into(),
            maximum_validity_seconds: 3_600,
            maximum_receipt_observation_age_seconds: 300,
            maximum_component_subtotal_micros: 5_000_000,
            trusted_keys: vec![
                TrustedApprovalKey {
                    signer_id: "procurement-a".into(),
                    public_key: hex::encode(
                        SigningKey::from_bytes(&[51; 32]).verifying_key().to_bytes(),
                    ),
                },
                TrustedApprovalKey {
                    signer_id: "procurement-b".into(),
                    public_key: hex::encode(
                        SigningKey::from_bytes(&[52; 32]).verifying_key().to_bytes(),
                    ),
                },
            ],
        });
        validate_policy_pack(&pack).unwrap();
        assert_eq!(
            parse_policy_pack(&serde_json::to_string(&pack).unwrap()).unwrap(),
            pack
        );

        let ai_signer = pack.trusted_approval_keys[0].signer_id.clone();
        pack.procurement_authorization_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .signer_id = ai_signer;
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("another trust role")
        );

        pack.procurement_authorization_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .signer_id = "procurement-a".into();
        pack.procurement_authorization_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .public_key = format!("02{}", "00".repeat(31));
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("invalid trusted procurement approval public key")
        );

        pack.procurement_authorization_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .public_key = format!("01{}", "00".repeat(31));
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("weak trusted procurement approval public key")
        );

        let shared_key = hex::encode(SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes());
        pack.procurement_authorization_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0] = TrustedApprovalKey {
            signer_id: "shared-authorization".into(),
            public_key: shared_key.clone(),
        };
        pack.fabrication_authorization_policy = Some(FabricationAuthorizationPolicy {
            minimum_approvals: 2,
            maximum_validity_seconds: 3_600,
            trusted_keys: vec![
                TrustedApprovalKey {
                    signer_id: "shared-authorization".into(),
                    public_key: shared_key,
                },
                TrustedApprovalKey {
                    signer_id: "fabrication-only".into(),
                    public_key: hex::encode(
                        SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
                    ),
                },
            ],
        });
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("another trust role")
        );
    }

    #[test]
    fn validates_dedicated_fabrication_dual_control_policy() {
        let keys = [
            hex::encode(SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes()),
            hex::encode(SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes()),
        ];
        let mut pack = sample();
        pack.fabrication_authorization_policy = Some(FabricationAuthorizationPolicy {
            minimum_approvals: 2,
            maximum_validity_seconds: 3_600,
            trusted_keys: vec![
                TrustedApprovalKey {
                    signer_id: "fabrication-a".into(),
                    public_key: keys[0].clone(),
                },
                TrustedApprovalKey {
                    signer_id: "fabrication-b".into(),
                    public_key: keys[1].clone(),
                },
            ],
        });
        validate_policy_pack(&pack).unwrap();
        let reparsed = parse_policy_pack(&serde_json::to_string(&pack).unwrap()).unwrap();
        assert_eq!(reparsed, pack);
        let ai_signer = pack.trusted_approval_keys[0].signer_id.clone();
        let ai_key = pack.trusted_approval_keys[0].public_key.clone();

        pack.fabrication_authorization_policy
            .as_mut()
            .unwrap()
            .minimum_approvals = 3;
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("cannot exceed")
        );
        pack.fabrication_authorization_policy
            .as_mut()
            .unwrap()
            .minimum_approvals = 2;
        pack.fabrication_authorization_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .signer_id = ai_signer;
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("another trust role")
        );
        pack.fabrication_authorization_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .signer_id = "fabrication-a".into();
        pack.fabrication_authorization_policy
            .as_mut()
            .unwrap()
            .trusted_keys[0]
            .public_key = ai_key;
        assert!(
            validate_policy_pack(&pack)
                .unwrap_err()
                .contains("another trust role")
        );
    }

    #[test]
    fn signs_and_strictly_verifies_policy_packs() {
        let signed = sign_policy_pack(sample(), "hardware-security", &[7; 32]).unwrap();
        let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        verify_signed_policy_pack(&signed, &public_key).unwrap();

        let wrong_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert!(verify_signed_policy_pack(&signed, &wrong_key).is_err());

        let mut tampered = signed;
        tampered.policy_pack.revision += 1;
        assert!(verify_signed_policy_pack(&tampered, &public_key).is_err());
    }

    #[test]
    fn signed_schema_is_closed_and_versioned() {
        let schema = signed_policy_pack_json_schema();
        assert_eq!(schema["properties"]["schema_version"]["const"], 1);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["policy_pack"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn trust_state_rejects_rollback_equivocation_and_identity_changes() {
        let signed = sign_policy_pack(sample(), "hardware-security", &[7; 32]).unwrap();
        let baseline = advance_policy_trust_state(&signed, None).unwrap();
        assert_eq!(
            advance_policy_trust_state(&signed, Some(&baseline)).unwrap(),
            baseline
        );

        let mut rollback_pack = sample();
        rollback_pack.revision = 2;
        let newer = sign_policy_pack(rollback_pack, "hardware-security", &[7; 32]).unwrap();
        let newer_state = advance_policy_trust_state(&newer, Some(&baseline)).unwrap();
        assert_eq!(newer_state.accepted_revision, 2);
        assert!(advance_policy_trust_state(&signed, Some(&newer_state)).is_err());

        let mut changed_pack = newer.policy_pack.clone();
        changed_pack.description = "different content at the same revision".into();
        let changed = sign_policy_pack(changed_pack, "hardware-security", &[7; 32]).unwrap();
        assert!(advance_policy_trust_state(&changed, Some(&newer_state)).is_err());

        let changed_signer =
            sign_policy_pack(newer.policy_pack.clone(), "another-security-team", &[7; 32]).unwrap();
        assert!(advance_policy_trust_state(&changed_signer, Some(&newer_state)).is_err());
    }

    #[test]
    fn trust_state_schema_is_closed_and_strictly_parsed() {
        let schema = policy_trust_state_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["schema_version"]["const"], 1);

        let signed = sign_policy_pack(sample(), "hardware-security", &[7; 32]).unwrap();
        let state = advance_policy_trust_state(&signed, None).unwrap();
        let mut value = serde_json::to_value(state).unwrap();
        value["unexpected"] = true.into();
        assert!(parse_policy_trust_state(&value.to_string()).is_err());
    }
}

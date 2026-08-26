//! Retained-root checkpoints for portable factory-release registry histories.
//!
//! v1.499 leaves every v1.493-v1.498 wire artifact unchanged. It binds one
//! freshly replayed portable history head to the retained registry root, pins
//! accepted heads monotonically, and verifies fresh distinct witnesses over
//! one exact checkpoint.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_state_transparency_external_gossip_registry::{
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION,
    audit_factory_release_state_transparency_external_gossip_organization_registry_history,
    factory_release_state_transparency_external_gossip_organization_registry_history_audit_report_sha256,
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CHECKPOINT_DOMAIN: &str = "pcbex-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-v1";
const WITNESS_DOMAIN: &str = "pcbex-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-v1";
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_BYTES: u64 =
    32 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_TRUST_STATE_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_BYTES: u64 =
    32 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES: u64 =
    128 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES: usize = 100;
const MAXIMUM_ACCEPTANCE_DELAY_SECONDS: u64 = 86_400;
const MAXIMUM_WITNESS_AGE_SECONDS: u64 = 86_400;
const MAX_TIMESTAMP: u64 = 999_999_999_999_999;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint
{
    pub schema_version: u32,
    pub registry_id: String,
    pub generation: u64,
    pub history_audit_sha256: String,
    pub final_registry_sha256: String,
    pub last_transition_sha256: Option<String>,
    pub active_governance_sha256: Option<String>,
    pub authority_public_key: String,
    pub issued_at_unix: u64,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState
{
    pub schema_version: u32,
    pub registry_id: String,
    pub accepted_generation: u64,
    pub checkpoint_sha256: String,
    pub history_audit_sha256: String,
    pub final_registry_sha256: String,
    pub last_transition_sha256: Option<String>,
    pub active_governance_sha256: Option<String>,
    pub authority_public_key: String,
    pub issued_at_unix: u64,
    pub accepted_at_unix: u64,
    pub signed_checkpoint:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness
{
    pub schema_version: u32,
    pub registry_id: String,
    pub generation: u64,
    pub checkpoint_sha256: String,
    pub witness_id: String,
    pub witnessed_at_unix: u64,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessMember
{
    pub witness_id: String,
    pub public_key: String,
    pub witness_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport {
    pub schema_version: u32,
    pub registry_id: String,
    pub generation: u64,
    pub checkpoint_sha256: String,
    pub history_audit_sha256: String,
    pub evaluated_at_unix: u64,
    pub minimum_witnesses: u32,
    pub valid_witnesses: u32,
    pub members: Vec<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessMember>,
    pub quorum_met: bool,
}

#[derive(Serialize)]
struct CheckpointPayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    generation: u64,
    history_audit_sha256: &'a str,
    final_registry_sha256: &'a str,
    last_transition_sha256: Option<&'a str>,
    active_governance_sha256: Option<&'a str>,
    authority_public_key: &'a str,
    issued_at_unix: u64,
}

#[derive(Serialize)]
struct WitnessPayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    generation: u64,
    checkpoint_sha256: &'a str,
    witness_id: &'a str,
    witnessed_at_unix: u64,
}

pub fn sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
    history: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
    authority_secret_key: &[u8; 32],
    issued_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
    String,
> {
    let audit =
        audit_factory_release_state_transparency_external_gossip_organization_registry_history(
            history,
        )?;
    let final_registry = &audit.final_registry;
    if final_registry
        .last_updated_at_unix
        .is_some_and(|last| issued_at_unix < last)
    {
        return Err("gossip registry history checkpoint predates its final registry".into());
    }
    let signing_key = SigningKey::from_bytes(authority_secret_key);
    let authority_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    if authority_public_key != final_registry.authority_public_key {
        return Err("gossip registry history checkpoint signer is not the retained root".into());
    }
    let history_audit_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_history_audit_report_sha256(&audit)?;
    let payload = checkpoint_payload(
        &audit,
        &history_audit_sha256,
        &authority_public_key,
        issued_at_unix,
    )?;
    let checkpoint =
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint {
            schema_version: 1,
            registry_id: audit.registry_id,
            generation: audit.final_registry.generation,
            history_audit_sha256,
            final_registry_sha256: audit.final_registry_sha256,
            last_transition_sha256: audit.final_registry.last_transition_sha256,
            active_governance_sha256: audit.final_registry.active_governance_sha256,
            authority_public_key,
            issued_at_unix,
            algorithm: "ed25519".into(),
            signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
        };
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
        &checkpoint,
    )?;
    Ok(checkpoint)
}

pub fn accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
    history: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
    checkpoint: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
    baseline: Option<&FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState>,
    accepted_at_unix: u64,
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
    String,
> {
    let audit =
        audit_factory_release_state_transparency_external_gossip_organization_registry_history(
            history,
        )?;
    verify_checkpoint_for_audit(&audit, checkpoint)?;
    if accepted_at_unix < checkpoint.issued_at_unix
        || accepted_at_unix.saturating_sub(checkpoint.issued_at_unix)
            > MAXIMUM_ACCEPTANCE_DELAY_SECONDS
    {
        return Err("gossip registry history checkpoint acceptance time is invalid".into());
    }
    let checkpoint_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_sha256(
            checkpoint,
        )?;
    if let Some(baseline) = baseline {
        validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
            baseline,
        )?;
        if baseline.registry_id != checkpoint.registry_id {
            return Err("gossip registry history checkpoint trust identity changed".into());
        }
        if checkpoint.generation < baseline.accepted_generation {
            return Err("gossip registry history checkpoint rollback is forbidden".into());
        }
        if checkpoint.generation == baseline.accepted_generation {
            if checkpoint_sha256 == baseline.checkpoint_sha256 {
                return Ok(baseline.clone());
            }
            return Err("gossip registry history checkpoint generation equivocated".into());
        }
        if checkpoint.issued_at_unix < baseline.issued_at_unix
            || accepted_at_unix < baseline.accepted_at_unix
        {
            return Err("gossip registry history checkpoint time moved backwards".into());
        }
        verify_audit_extends_trust_state(&audit, baseline)?;
    }
    let state = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState {
        schema_version: 1,
        registry_id: checkpoint.registry_id.clone(),
        accepted_generation: checkpoint.generation,
        checkpoint_sha256,
        history_audit_sha256: checkpoint.history_audit_sha256.clone(),
        final_registry_sha256: checkpoint.final_registry_sha256.clone(),
        last_transition_sha256: checkpoint.last_transition_sha256.clone(),
        active_governance_sha256: checkpoint.active_governance_sha256.clone(),
        authority_public_key: checkpoint.authority_public_key.clone(),
        issued_at_unix: checkpoint.issued_at_unix,
        accepted_at_unix,
        signed_checkpoint: checkpoint.clone(),
    };
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
        &state,
    )?;
    Ok(state)
}

pub fn sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
    history: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
    checkpoint: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
    witness_id: &str,
    witness_secret_key: &[u8; 32],
    witnessed_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    String,
> {
    let audit =
        audit_factory_release_state_transparency_external_gossip_organization_registry_history(
            history,
        )?;
    verify_checkpoint_for_audit(&audit, checkpoint)?;
    validate_slug(witness_id, "gossip registry history checkpoint witness id")?;
    if witnessed_at_unix < checkpoint.issued_at_unix {
        return Err("gossip registry history witness predates its checkpoint".into());
    }
    let checkpoint_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_sha256(
            checkpoint,
        )?;
    let signing_key = SigningKey::from_bytes(witness_secret_key);
    let public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    if registry_privileged_keys(history, &audit).contains(&public_key) {
        return Err(
            "gossip registry history witness key must be role-disjoint from registry root and governance keys"
                .into(),
        );
    }
    let payload = witness_payload(
        &checkpoint.registry_id,
        checkpoint.generation,
        &checkpoint_sha256,
        witness_id,
        witnessed_at_unix,
    )?;
    let witness = SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness {
        schema_version: 1,
        registry_id: checkpoint.registry_id.clone(),
        generation: checkpoint.generation,
        checkpoint_sha256,
        witness_id: witness_id.into(),
        witnessed_at_unix,
        algorithm: "ed25519".into(),
        public_key,
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
        &witness,
    )?;
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
    history: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
    checkpoint: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
    witnesses: &[SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness],
    trusted_witnesses: &[(String, [u8; 32])],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport, String>
{
    let audit =
        audit_factory_release_state_transparency_external_gossip_organization_registry_history(
            history,
        )?;
    verify_checkpoint_for_audit(&audit, checkpoint)?;
    if !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
        .contains(&minimum_witnesses)
        || witnesses.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
        || trusted_witnesses.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
    {
        return Err(
            "gossip registry history witness quorum must require 2 to 100 witnesses".into(),
        );
    }
    if evaluated_at_unix < checkpoint.issued_at_unix {
        return Err("gossip registry history witness evaluation predates its checkpoint".into());
    }
    let trusted = trusted_witness_map(trusted_witnesses)?;
    let checkpoint_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_sha256(
            checkpoint,
        )?;
    let privileged_keys = registry_privileged_keys(history, &audit);
    let mut seen_ids = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let mut members = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
            witness,
        )?;
        if witness.registry_id != checkpoint.registry_id
            || witness.generation != checkpoint.generation
            || witness.checkpoint_sha256 != checkpoint_sha256
        {
            return Err("gossip registry history witness is bound to another checkpoint".into());
        }
        if witness.witnessed_at_unix < checkpoint.issued_at_unix
            || witness.witnessed_at_unix > evaluated_at_unix
            || evaluated_at_unix.saturating_sub(witness.witnessed_at_unix)
                > MAXIMUM_WITNESS_AGE_SECONDS
        {
            return Err("gossip registry history witness is stale or future-dated".into());
        }
        if !seen_ids.insert(witness.witness_id.as_str())
            || !seen_keys.insert(witness.public_key.as_str())
        {
            return Err(
                "gossip registry history witnesses require distinct identities and keys".into(),
            );
        }
        if privileged_keys.contains(&witness.public_key) {
            return Err(
                "gossip registry history witness key reuses a registry root or governance key"
                    .into(),
            );
        }
        let trusted_key = trusted
            .get(&witness.witness_id)
            .ok_or_else(|| "untrusted gossip registry history witness identity".to_string())?;
        if witness.public_key != hex_encode(trusted_key) {
            return Err("gossip registry history witness key substitution".into());
        }
        let payload = witness_payload(
            &witness.registry_id,
            witness.generation,
            &witness.checkpoint_sha256,
            &witness.witness_id,
            witness.witnessed_at_unix,
        )?;
        let signature = Signature::from_bytes(&hex_decode::<64>(
            &witness.signature,
            "gossip registry history witness signature",
        )?);
        VerifyingKey::from_bytes(trusted_key)
            .map_err(|error| format!("invalid trusted history witness key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| {
                "gossip registry history witness signature verification failed".to_string()
            })?;
        members.push(
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessMember {
                witness_id: witness.witness_id.clone(),
                public_key: witness.public_key.clone(),
                witness_sha256:
                    signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_sha256(
                        witness,
                    )?,
            },
        );
    }
    members.sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
    let valid_witnesses = u32::try_from(members.len())
        .map_err(|_| "gossip registry history witness count overflow".to_string())?;
    let report = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport {
        schema_version: 1,
        registry_id: checkpoint.registry_id.clone(),
        generation: checkpoint.generation,
        checkpoint_sha256,
        history_audit_sha256: checkpoint.history_audit_sha256.clone(),
        evaluated_at_unix,
        minimum_witnesses,
        valid_witnesses,
        members,
        quorum_met: valid_witnesses >= minimum_witnesses,
    };
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report(
        &report,
    )?;
    Ok(report)
}

pub fn parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
    source: &[u8],
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
    String,
> {
    let checkpoint = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_BYTES,
        "factory release transparency external gossip registry history checkpoint",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
        &checkpoint,
    )?;
    Ok(checkpoint)
}

pub fn parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
    source: &[u8],
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
    String,
> {
    let state = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_TRUST_STATE_BYTES,
        "factory release transparency external gossip registry history checkpoint trust state",
    )?;
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
        &state,
    )?;
    Ok(state)
}

pub fn parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
    source: &[u8],
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    String,
> {
    let witness = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_BYTES,
        "factory release transparency external gossip registry history checkpoint witness",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
        &witness,
    )?;
    Ok(witness)
}

pub fn parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport, String>
{
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES,
        "factory release transparency external gossip registry history checkpoint witness quorum report",
    )?;
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report(
        &report,
    )?;
    Ok(report)
}

pub fn render_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
    checkpoint: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
        checkpoint,
    )?;
    render_bounded(
        checkpoint,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_BYTES,
        "factory release transparency external gossip registry history checkpoint",
    )
}

pub fn render_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
    state: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
) -> Result<Vec<u8>, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
        state,
    )?;
    render_bounded(
        state,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_TRUST_STATE_BYTES,
        "factory release transparency external gossip registry history checkpoint trust state",
    )
}

pub fn render_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
    witness: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
        witness,
    )?;
    render_bounded(
        witness,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_BYTES,
        "factory release transparency external gossip registry history checkpoint witness",
    )
}

pub fn render_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report(
    report: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport,
) -> Result<Vec<u8>, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report(
        report,
    )?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES,
        "factory release transparency external gossip registry history checkpoint witness quorum report",
    )
}

pub fn signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_sha256(
    checkpoint: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
) -> Result<String, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
        checkpoint,
    )?;
    normalized_sha256(checkpoint, "gossip registry history checkpoint")
}

pub fn signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_sha256(
    witness: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
) -> Result<String, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
        witness,
    )?;
    normalized_sha256(witness, "gossip registry history checkpoint witness")
}

pub fn validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
    checkpoint: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
) -> Result<(), String> {
    if checkpoint.schema_version != 1
        || checkpoint.algorithm != "ed25519"
        || checkpoint.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || checkpoint.issued_at_unix > MAX_TIMESTAMP
    {
        return Err("invalid gossip registry history checkpoint invariants".into());
    }
    validate_slug(&checkpoint.registry_id, "gossip registry id")?;
    validate_digest(&checkpoint.history_audit_sha256, "history audit SHA-256")?;
    validate_digest(&checkpoint.final_registry_sha256, "final registry SHA-256")?;
    match (checkpoint.generation, &checkpoint.last_transition_sha256) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err("genesis history checkpoint cannot reference a transition".into());
        }
        (_, Some(digest)) => validate_digest(digest, "last registry transition SHA-256")?,
        (_, None) => return Err("advanced history checkpoint requires transition evidence".into()),
    }
    if let Some(digest) = &checkpoint.active_governance_sha256 {
        validate_digest(digest, "active registry governance SHA-256")?;
    }
    validate_key(
        &checkpoint.authority_public_key,
        "registry checkpoint authority key",
    )?;
    let key = hex_decode::<32>(
        &checkpoint.authority_public_key,
        "registry checkpoint authority key",
    )?;
    let signature = Signature::from_bytes(&hex_decode::<64>(
        &checkpoint.signature,
        "registry history checkpoint signature",
    )?);
    let payload = checkpoint_payload_from_checkpoint(checkpoint)?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid registry checkpoint authority key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| "gossip registry history checkpoint signature verification failed".into())
}

pub fn validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
    state: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
) -> Result<(), String> {
    if state.schema_version != 1
        || state.accepted_at_unix < state.issued_at_unix
        || state.accepted_at_unix.saturating_sub(state.issued_at_unix)
            > MAXIMUM_ACCEPTANCE_DELAY_SECONDS
        || state.accepted_at_unix > MAX_TIMESTAMP
        || state.accepted_generation != state.signed_checkpoint.generation
        || state.registry_id != state.signed_checkpoint.registry_id
        || state.history_audit_sha256 != state.signed_checkpoint.history_audit_sha256
        || state.final_registry_sha256 != state.signed_checkpoint.final_registry_sha256
        || state.last_transition_sha256 != state.signed_checkpoint.last_transition_sha256
        || state.active_governance_sha256 != state.signed_checkpoint.active_governance_sha256
        || state.authority_public_key != state.signed_checkpoint.authority_public_key
        || state.issued_at_unix != state.signed_checkpoint.issued_at_unix
    {
        return Err("invalid gossip registry history checkpoint trust-state invariants".into());
    }
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
        &state.signed_checkpoint,
    )?;
    validate_digest(
        &state.checkpoint_sha256,
        "trusted history checkpoint SHA-256",
    )?;
    if state.checkpoint_sha256
        != signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_sha256(
            &state.signed_checkpoint,
        )?
    {
        return Err("gossip registry history trust state checkpoint digest is inconsistent".into());
    }
    Ok(())
}

pub fn validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
    witness: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
) -> Result<(), String> {
    if witness.schema_version != 1
        || witness.algorithm != "ed25519"
        || witness.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || witness.witnessed_at_unix > MAX_TIMESTAMP
    {
        return Err("invalid gossip registry history checkpoint witness invariants".into());
    }
    validate_slug(&witness.registry_id, "gossip registry id")?;
    validate_slug(&witness.witness_id, "gossip registry history witness id")?;
    validate_digest(
        &witness.checkpoint_sha256,
        "witnessed history checkpoint SHA-256",
    )?;
    validate_key(
        &witness.public_key,
        "gossip registry history witness public key",
    )?;
    let key = hex_decode::<32>(
        &witness.public_key,
        "gossip registry history witness public key",
    )?;
    let signature = Signature::from_bytes(&hex_decode::<64>(
        &witness.signature,
        "gossip registry history witness signature",
    )?);
    let payload = witness_payload(
        &witness.registry_id,
        witness.generation,
        &witness.checkpoint_sha256,
        &witness.witness_id,
        witness.witnessed_at_unix,
    )?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid gossip registry history witness key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| "gossip registry history witness signature verification failed".into())
}

pub fn validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report(
    report: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || report.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || report.evaluated_at_unix > MAX_TIMESTAMP
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
            .contains(&report.minimum_witnesses)
        || report.members.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
        || report.valid_witnesses != report.members.len() as u32
        || report.quorum_met != (report.valid_witnesses >= report.minimum_witnesses)
    {
        return Err("invalid gossip registry history witness quorum invariants".into());
    }
    validate_slug(&report.registry_id, "gossip registry id")?;
    validate_digest(&report.checkpoint_sha256, "history checkpoint SHA-256")?;
    validate_digest(&report.history_audit_sha256, "history audit SHA-256")?;
    let mut previous = None;
    let mut keys = BTreeSet::new();
    for member in &report.members {
        validate_slug(&member.witness_id, "history witness id")?;
        validate_key(&member.public_key, "history witness public key")?;
        validate_digest(&member.witness_sha256, "history witness SHA-256")?;
        if previous.is_some_and(|id: &String| id >= &member.witness_id)
            || !keys.insert(member.public_key.as_str())
        {
            return Err("history witness quorum members must be ordered and distinct".into());
        }
        previous = Some(&member.witness_id);
    }
    Ok(())
}

pub fn signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-v1.json",
        "title": "Root-signed complete gossip registry history checkpoint",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "generation", "history_audit_sha256",
            "final_registry_sha256", "last_transition_sha256",
            "active_governance_sha256", "authority_public_key", "issued_at_unix",
            "algorithm", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION},
            "history_audit_sha256": digest_schema(),
            "final_registry_sha256": digest_schema(),
            "last_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "active_governance_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "authority_public_key": key_schema(),
            "issued_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "signature": signature_schema()
        }
    })
}

pub fn factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-trust-state-v1.json",
        "title": "Monotonic gossip registry history checkpoint trust state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "accepted_generation",
            "checkpoint_sha256", "history_audit_sha256", "final_registry_sha256",
            "last_transition_sha256", "active_governance_sha256",
            "authority_public_key", "issued_at_unix", "accepted_at_unix",
            "signed_checkpoint"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "accepted_generation": {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION},
            "checkpoint_sha256": digest_schema(),
            "history_audit_sha256": digest_schema(),
            "final_registry_sha256": digest_schema(),
            "last_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "active_governance_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "authority_public_key": key_schema(),
            "issued_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "accepted_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "signed_checkpoint": embedded_schema(
                signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_json_schema()
            )
        }
    })
}

pub fn signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-v1.json",
        "title": "Independent complete gossip registry history checkpoint witness",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "generation", "checkpoint_sha256",
            "witness_id", "witnessed_at_unix", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION},
            "checkpoint_sha256": digest_schema(),
            "witness_id": slug_schema(),
            "witnessed_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "public_key": key_schema(),
            "signature": signature_schema()
        }
    })
}

pub fn factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-quorum-v1.json",
        "title": "Independent complete gossip registry history checkpoint witness quorum",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "generation", "checkpoint_sha256",
            "history_audit_sha256", "evaluated_at_unix", "minimum_witnesses",
            "valid_witnesses", "members", "quorum_met"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION},
            "checkpoint_sha256": digest_schema(),
            "history_audit_sha256": digest_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES},
            "valid_witnesses": {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES},
            "members": {
                "type": "array", "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["witness_id", "public_key", "witness_sha256"],
                    "properties": {
                        "witness_id": slug_schema(),
                        "public_key": key_schema(),
                        "witness_sha256": digest_schema()
                    }
                }
            },
            "quorum_met": {"type": "boolean"}
        }
    })
}

fn verify_checkpoint_for_audit(
    audit: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
    checkpoint: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
) -> Result<(), String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(audit)?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
        checkpoint,
    )?;
    let history_audit_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_history_audit_report_sha256(audit)?;
    if checkpoint.registry_id != audit.registry_id
        || checkpoint.generation != audit.final_registry.generation
        || checkpoint.history_audit_sha256 != history_audit_sha256
        || checkpoint.final_registry_sha256 != audit.final_registry_sha256
        || checkpoint.last_transition_sha256 != audit.final_registry.last_transition_sha256
        || checkpoint.active_governance_sha256 != audit.final_registry.active_governance_sha256
        || checkpoint.authority_public_key != audit.final_registry.authority_public_key
        || audit
            .final_registry
            .last_updated_at_unix
            .is_some_and(|last| checkpoint.issued_at_unix < last)
    {
        return Err(
            "gossip registry history checkpoint does not bind the verified audit head".into(),
        );
    }
    let payload = checkpoint_payload(
        audit,
        &history_audit_sha256,
        &checkpoint.authority_public_key,
        checkpoint.issued_at_unix,
    )?;
    let key = hex_decode::<32>(
        &checkpoint.authority_public_key,
        "gossip registry history checkpoint authority key",
    )?;
    let signature = Signature::from_bytes(&hex_decode::<64>(
        &checkpoint.signature,
        "gossip registry history checkpoint signature",
    )?);
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid gossip registry checkpoint authority key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| "gossip registry history checkpoint signature verification failed".to_string())
}

fn verify_audit_extends_trust_state(
    audit: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
    baseline: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
) -> Result<(), String> {
    let matches = if baseline.accepted_generation == 0 {
        audit.initial_registry_sha256 == baseline.final_registry_sha256
            && baseline.last_transition_sha256.is_none()
    } else {
        let index = usize::try_from(baseline.accepted_generation - 1)
            .map_err(|_| "trusted history checkpoint generation overflow".to_string())?;
        audit.entries.get(index).is_some_and(|entry| {
            entry.to_generation == baseline.accepted_generation
                && entry.resulting_registry_sha256 == baseline.final_registry_sha256
                && entry.event_sha256 == baseline.last_transition_sha256.clone().unwrap_or_default()
                && entry.authority_public_key == baseline.authority_public_key
                && entry.active_governance_sha256 == baseline.active_governance_sha256
        })
    };
    if !matches {
        return Err("gossip registry history checkpoint does not extend retained trust".into());
    }
    Ok(())
}

fn checkpoint_payload(
    audit: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
    history_audit_sha256: &str,
    authority_public_key: &str,
    issued_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&CheckpointPayload {
        domain: CHECKPOINT_DOMAIN,
        registry_id: &audit.registry_id,
        generation: audit.final_registry.generation,
        history_audit_sha256,
        final_registry_sha256: &audit.final_registry_sha256,
        last_transition_sha256: audit.final_registry.last_transition_sha256.as_deref(),
        active_governance_sha256: audit.final_registry.active_governance_sha256.as_deref(),
        authority_public_key,
        issued_at_unix,
    })
    .map_err(|error| format!("serializing gossip registry history checkpoint: {error}"))
}

fn checkpoint_payload_from_checkpoint(
    checkpoint: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpoint,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&CheckpointPayload {
        domain: CHECKPOINT_DOMAIN,
        registry_id: &checkpoint.registry_id,
        generation: checkpoint.generation,
        history_audit_sha256: &checkpoint.history_audit_sha256,
        final_registry_sha256: &checkpoint.final_registry_sha256,
        last_transition_sha256: checkpoint.last_transition_sha256.as_deref(),
        active_governance_sha256: checkpoint.active_governance_sha256.as_deref(),
        authority_public_key: &checkpoint.authority_public_key,
        issued_at_unix: checkpoint.issued_at_unix,
    })
    .map_err(|error| format!("serializing gossip registry history checkpoint: {error}"))
}

fn witness_payload(
    registry_id: &str,
    generation: u64,
    checkpoint_sha256: &str,
    witness_id: &str,
    witnessed_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&WitnessPayload {
        domain: WITNESS_DOMAIN,
        registry_id,
        generation,
        checkpoint_sha256,
        witness_id,
        witnessed_at_unix,
    })
    .map_err(|error| format!("serializing gossip registry history witness: {error}"))
}

fn trusted_witness_map(
    witnesses: &[(String, [u8; 32])],
) -> Result<BTreeMap<String, [u8; 32]>, String> {
    let mut map = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for (id, key) in witnesses {
        validate_slug(id, "trusted gossip registry history witness id")?;
        let verifying_key = VerifyingKey::from_bytes(key)
            .map_err(|error| format!("invalid trusted history witness key: {error}"))?;
        if verifying_key.is_weak() {
            return Err("trusted history witness key is weak".into());
        }
        if map.insert(id.clone(), *key).is_some() || !keys.insert(*key) {
            return Err("trusted history witnesses require distinct identities and keys".into());
        }
    }
    Ok(map)
}

fn registry_privileged_keys(
    history: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
    audit: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
) -> BTreeSet<String> {
    let mut keys = BTreeSet::from([history.initial_registry.authority_public_key.clone()]);
    keys.extend(
        audit
            .entries
            .iter()
            .map(|entry| entry.authority_public_key.clone()),
    );
    for event in &history.events {
        let governances = match event {
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::ThresholdTransition {
                transition,
                ..
            } => vec![&transition.governance],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::GovernanceRotation {
                rotation,
                ..
            } => vec![&rotation.old_governance, &rotation.new_governance],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::GovernedAuthorityKeyRotation {
                rotation,
                ..
            } => vec![&rotation.old_governance, &rotation.new_governance],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::OrganizationTransition { .. }
            | FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::AuthorityKeyRotation { .. } => Vec::new(),
        };
        for governance in governances {
            keys.extend(
                governance
                    .authorities
                    .iter()
                    .map(|authority| authority.public_key.clone()),
            );
        }
    }
    keys
}

fn render_bounded<T: Serialize>(value: &T, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut source =
        serde_json::to_vec_pretty(value).map_err(|error| format!("rendering {label}: {error}"))?;
    source.push(b'\n');
    if source.is_empty() || source.len() as u64 > maximum {
        return Err(format!("{label} exceeds the {maximum}-byte limit"));
    }
    Ok(source)
}

fn parse_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    source: &[u8],
    maximum: u64,
    label: &str,
) -> Result<T, String> {
    if source.is_empty() || source.len() as u64 > maximum {
        return Err(format!("{label} must contain 1 to {maximum} bytes"));
    }
    reject_duplicate_json_keys(source)
        .map_err(|error| format!("invalid {label} JSON: {error:#}"))?;
    let value: T =
        serde_json::from_slice(source).map_err(|error| format!("invalid {label} JSON: {error}"))?;
    if render_bounded(&value, maximum, label)? != source {
        return Err(format!("{label} is not canonical pretty JSON"));
    }
    Ok(value)
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'-' => index != 0,
            _ => false,
        })
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    hex_decode::<32>(value, label).map(|_| ())
}

fn validate_key(value: &str, label: &str) -> Result<(), String> {
    let key = hex_decode::<32>(value, label)?;
    let key =
        VerifyingKey::from_bytes(&key).map_err(|error| format!("invalid {label}: {error}"))?;
    if key.is_weak() {
        return Err(format!("{label} is weak"));
    }
    Ok(())
}

fn hex_decode<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("invalid {label}"));
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("invalid {label}"))?;
    }
    Ok(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
    })
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn key_schema() -> Value {
    digest_schema()
}

fn signature_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{128}$"})
}

fn embedded_schema(mut schema: Value) -> Value {
    if let Some(object) = schema.as_object_mut() {
        object.remove("$schema");
        object.remove("$id");
        object.remove("title");
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_release_state_transparency_external_gossip_quorum::{
        FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE,
        FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
        TrustedFactoryReleaseTransparencyExternalGossipObserver,
        factory_release_state_transparency_external_gossip_quorum_policy_sha256,
    };
    use crate::factory_release_state_transparency_external_gossip_registry::{
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent,
        apply_factory_release_state_transparency_external_gossip_organization_registry_transition,
        new_factory_release_state_transparency_external_gossip_organization_registry,
        render_factory_release_state_transparency_external_gossip_organization_registry,
        render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation,
        render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition,
        sign_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation,
        sign_factory_release_state_transparency_external_gossip_organization_registry_transition,
    };
    use crate::factory_release_state_transparency_external_gossip_trust::new_factory_release_state_transparency_external_gossip_observer_trust_state;
    use pcbex_kicad::ExactArtifactIdentity;

    fn public(secret: [u8; 32]) -> String {
        hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
    }

    fn policy() -> FactoryReleaseStateTransparencyExternalGossipQuorumPolicy {
        FactoryReleaseStateTransparencyExternalGossipQuorumPolicy {
            schema_version: 1,
            policy_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE
                .into(),
            policy_id: "checkpoint-unit".into(),
            minimum_organizations: 2,
            maximum_receipt_age_seconds: 300,
            trusted_observers: vec![
                TrustedFactoryReleaseTransparencyExternalGossipObserver {
                    organization_id: "lab-a".into(),
                    observer_id: "observer-a".into(),
                    algorithm: "ed25519".into(),
                    public_key: public([11; 32]),
                },
                TrustedFactoryReleaseTransparencyExternalGossipObserver {
                    organization_id: "lab-b".into(),
                    observer_id: "observer-b".into(),
                    algorithm: "ed25519".into(),
                    public_key: public([21; 32]),
                },
            ],
        }
    }

    fn identity(source: &[u8]) -> ExactArtifactIdentity {
        ExactArtifactIdentity {
            bytes: source.len() as u64,
            sha256: hex::encode(Sha256::digest(source)),
        }
    }

    fn genesis_fixture() -> (
        FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
        String,
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
    ) {
        let policy = policy();
        let policy_sha256 =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&policy)
                .unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_organization_registry(
            &policy,
            &policy_sha256,
            "production-observers",
            &SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let initial_source =
            render_factory_release_state_transparency_external_gossip_organization_registry(
                &initial,
            )
            .unwrap();
        let history = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory {
            schema_version: 1,
            initial_registry_artifact: identity(&initial_source),
            initial_registry: initial.clone(),
            events: Vec::new(),
        };
        (policy, policy_sha256, initial, history)
    }

    fn history_with_admission(
        policy: &FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
        policy_sha256: &str,
        initial: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
        reason: char,
    ) -> (
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    ) {
        let trust = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            policy,
            policy_sha256,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        let transition = sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
            initial,
            &[31; 32],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
            "lab-a",
            Some(&trust),
            &reason.to_string().repeat(64),
            100,
        )
        .unwrap();
        let transition_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &transition,
        )
        .unwrap();
        let initial_source =
            render_factory_release_state_transparency_external_gossip_organization_registry(
                initial,
            )
            .unwrap();
        let history = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory {
            schema_version: 1,
            initial_registry_artifact: identity(&initial_source),
            initial_registry: initial.clone(),
            events: vec![FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::OrganizationTransition {
                artifact: identity(&transition_source),
                transition: transition.clone(),
            }],
        };
        let next = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
            initial,
            &transition,
        )
        .unwrap();
        (history, next)
    }

    #[test]
    fn checkpoint_trust_and_fresh_distinct_witnesses_are_canonical() {
        let (_, _, _, history) = genesis_fixture();
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &history,
                &[32; 32],
                100,
            )
            .is_err()
        );
        let checkpoint = sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &history,
            &[31; 32],
            100,
        )
        .unwrap();
        let checkpoint_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &checkpoint,
        )
        .unwrap();
        assert_eq!(
            parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &checkpoint_source,
            )
            .unwrap(),
            checkpoint
        );
        let mut tampered_checkpoint = checkpoint.clone();
        let replacement = if tampered_checkpoint.signature.starts_with("00") {
            "ff"
        } else {
            "00"
        };
        tampered_checkpoint
            .signature
            .replace_range(..2, replacement);
        assert!(
            validate_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &tampered_checkpoint,
            )
            .is_err()
        );
        let compact = serde_json::to_vec(&checkpoint).unwrap();
        assert!(
            parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &compact,
            )
            .is_err()
        );

        let state = accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &history,
            &checkpoint,
            None,
            101,
        )
        .unwrap();
        assert_eq!(
            accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &history,
                &checkpoint,
                Some(&state),
                102,
            )
            .unwrap(),
            state
        );
        let state_source = render_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
            &state,
        )
        .unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
                &state_source,
            )
            .unwrap(),
            state
        );
        let mut stale_state = state.clone();
        stale_state.accepted_at_unix = stale_state.issued_at_unix + 86_401;
        assert!(
            validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
                &stale_state,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
                &history,
                &checkpoint,
                "root-reuse",
                &[31; 32],
                110,
            )
            .is_err()
        );

        let witness_a = sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
            &history,
            &checkpoint,
            "witness-a",
            &[41; 32],
            110,
        )
        .unwrap();
        let witness_b = sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
            &history,
            &checkpoint,
            "witness-b",
            &[42; 32],
            111,
        )
        .unwrap();
        let report = verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
            &history,
            &checkpoint,
            &[witness_b.clone(), witness_a.clone()],
            &[
                (
                    "witness-b".into(),
                    SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
                ),
                (
                    "witness-a".into(),
                    SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes(),
                ),
            ],
            2,
            112,
        )
        .unwrap();
        assert!(report.quorum_met);
        assert_eq!(report.valid_witnesses, 2);
        assert_eq!(report.members[0].witness_id, "witness-a");
        let report_source = render_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report(
            &report,
        )
        .unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report(
                &report_source,
            )
            .unwrap(),
            report
        );
        let mut out_of_range_report = report.clone();
        out_of_range_report.generation =
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION + 1;
        assert!(
            validate_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_quorum_report(
                &out_of_range_report,
            )
            .is_err()
        );

        let below = verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
            &history,
            &checkpoint,
            std::slice::from_ref(&witness_a),
            &[(
                "witness-a".into(),
                SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes(),
            )],
            2,
            112,
        )
        .unwrap();
        assert!(!below.quorum_met);

        let mut tampered = witness_a.clone();
        let replacement = if tampered.signature.starts_with("00") {
            "ff"
        } else {
            "00"
        };
        tampered.signature.replace_range(..2, replacement);
        assert!(
            verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
                &history,
                &checkpoint,
                &[tampered],
                &[(
                    "witness-a".into(),
                    SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes(),
                )],
                2,
                112,
            )
            .is_err()
        );
        assert!(
            verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
                &history,
                &checkpoint,
                &[witness_a, witness_b],
                &[
                    (
                        "witness-a".into(),
                        SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes(),
                    ),
                    (
                        "witness-b".into(),
                        SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
                    ),
                ],
                2,
                86_512,
            )
            .is_err()
        );
    }

    #[test]
    fn accepted_heads_reject_rollback_equivocation_and_nonextending_forks() {
        let (policy, policy_sha256, initial, genesis) = genesis_fixture();
        let genesis_checkpoint = sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &genesis,
            &[31; 32],
            90,
        )
        .unwrap();
        let genesis_state = accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &genesis,
            &genesis_checkpoint,
            None,
            91,
        )
        .unwrap();

        let (history_a, _) = history_with_admission(&policy, &policy_sha256, &initial, 'a');
        let checkpoint_a = sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &history_a,
            &[31; 32],
            110,
        )
        .unwrap();
        let state_a = accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &history_a,
            &checkpoint_a,
            Some(&genesis_state),
            111,
        )
        .unwrap();
        assert!(
            accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &genesis,
                &genesis_checkpoint,
                Some(&state_a),
                112,
            )
            .is_err()
        );

        let (history_b, state_b) = history_with_admission(&policy, &policy_sha256, &initial, 'b');
        let checkpoint_b = sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &history_b,
            &[31; 32],
            110,
        )
        .unwrap();
        assert!(
            accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &history_b,
                &checkpoint_b,
                Some(&state_a),
                112,
            )
            .is_err()
        );

        let suspension = sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &state_b,
            &[31; 32],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
            "lab-a",
            None,
            &"c".repeat(64),
            120,
        )
        .unwrap();
        let suspension_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &suspension,
        )
        .unwrap();
        let mut fork = history_b;
        fork.events.push(FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::OrganizationTransition {
            artifact: identity(&suspension_source),
            transition: suspension,
        });
        let fork_checkpoint = sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &fork,
            &[31; 32],
            130,
        )
        .unwrap();
        assert!(
            accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &fork,
                &fork_checkpoint,
                Some(&state_a),
                131,
            )
            .is_err()
        );

        let rotation = sign_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
            &initial,
            &[31; 32],
            &[32; 32],
            100,
        )
        .unwrap();
        let rotation_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
            &rotation,
        )
        .unwrap();
        let initial_source =
            render_factory_release_state_transparency_external_gossip_organization_registry(
                &initial,
            )
            .unwrap();
        let rotated_history =
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory {
                schema_version: 1,
                initial_registry_artifact: identity(&initial_source),
                initial_registry: initial,
                events: vec![FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::AuthorityKeyRotation {
                    artifact: identity(&rotation_source),
                    rotation,
                }],
            };
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &rotated_history,
                &[31; 32],
                110,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
                &rotated_history,
                &[32; 32],
                110,
            )
            .is_ok()
        );
    }
}

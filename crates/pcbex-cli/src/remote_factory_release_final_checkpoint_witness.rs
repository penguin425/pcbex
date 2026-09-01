//! Independent witnesses for the dedicated final factory-release checkpoint.
//!
//! The v1.524 boundary re-verifies the exact v1.521 final witness-quorum
//! report, complete admission log, v1.523 dedicated checkpoint, and pinned
//! checkpoint key before a witness key is used. It then signs the checkpoint
//! digest beneath a new domain. Quorum verification accepts 2–100 fresh,
//! distinct, non-weak witness keys that cannot reuse the checkpoint signing
//! key.
//!
//! The v1.525 boundary binds each v1.524 witness identity to a generation-zero
//! trust state and advances its key only through a dual-signed,
//! digest-chained, one-generation rotation. The unchanged v1.524 quorum can
//! consume either direct key pins or current trust states.
//!
//! This is bounded, selected-witness evidence. It does not establish trusted
//! time, legal identity, independent operation, global publication, or
//! non-equivocation.

use crate::factory_release_state_transparency_external_gossip_registry::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION;
use crate::factory_release_state_transparency_external_gossip_registry_checkpoint::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES;
use crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::{
    MAX_TIMESTAMP,
    RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint, decode_hex,
    digest_schema, parse_canonical, render_bounded, sha256, slug_schema, validate_digest,
    validate_nonweak_public_key,
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint,
    validate_slug,
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::ApprovalTransparencyLog;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const FINAL_CHECKPOINT_WITNESS_DOMAIN: &str =
    "pcbex-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-v1";
const FINAL_CHECKPOINT_WITNESS_KEY_ROTATION_DOMAIN: &str = "pcbex-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-key-rotation-v1";
const MAXIMUM_FINAL_CHECKPOINT_WITNESS_AGE_SECONDS: u64 = 86_400;

pub(crate) const MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES: u64 =
    128 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_TRUST_STATE_BYTES: u64 =
    32 * 1024;
pub(crate) const MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_KEY_ROTATION_BYTES: u64 =
    32 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness
{
    pub(crate) schema_version: u32,
    pub(crate) checkpoint_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) receipt_quorum_checkpoint_sha256: String,
    pub(crate) checkpoint_witness_receipt_quorum_checkpoint_sha256: String,
    pub(crate) final_admission_log_id: String,
    pub(crate) final_admission_log_entry_count: u64,
    pub(crate) final_admission_log_head_sha256: String,
    pub(crate) final_admission_log_sha256: String,
    pub(crate) witness_id: String,
    pub(crate) witnessed_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport
{
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) checkpoint_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) receipt_quorum_checkpoint_sha256: String,
    pub(crate) checkpoint_witness_receipt_quorum_checkpoint_sha256: String,
    pub(crate) final_admission_log_id: String,
    pub(crate) final_admission_log_entry_count: u64,
    pub(crate) final_admission_log_head_sha256: String,
    pub(crate) final_admission_log_sha256: String,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) minimum_witnesses: u32,
    pub(crate) valid_witnesses: u32,
    pub(crate) witness_ids: Vec<String>,
    pub(crate) witness_public_keys: Vec<String>,
    pub(crate) quorum_met: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState
{
    pub(crate) schema_version: u32,
    pub(crate) witness_id: String,
    pub(crate) generation: u64,
    pub(crate) current_public_key: String,
    pub(crate) last_rotation_sha256: Option<String>,
    pub(crate) last_rotated_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessKeyRotation
{
    pub(crate) schema_version: u32,
    pub(crate) witness_id: String,
    pub(crate) from_generation: u64,
    pub(crate) to_generation: u64,
    pub(crate) previous_rotation_sha256: Option<String>,
    pub(crate) old_public_key: String,
    pub(crate) new_public_key: String,
    pub(crate) rotated_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) old_signature: String,
    pub(crate) new_signature: String,
}

pub(crate) fn render_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
    witness: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
) -> Result<Vec<u8>, String> {
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
        witness,
    )?;
    render_bounded(
        witness,
        MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES,
        "signed factory final checkpoint-witness receipt quorum checkpoint witness",
    )
}

pub(crate) fn parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
    source: &[u8],
) -> Result<SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness, String>
{
    let witness = parse_canonical(
        source,
        MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES,
        "signed factory final checkpoint-witness receipt quorum checkpoint witness",
    )?;
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
        &witness,
    )?;
    Ok(witness)
}

pub(crate) fn render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
    report: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
        report,
    )?;
    render_bounded(
        report,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES,
        "factory final checkpoint-witness receipt quorum checkpoint witness quorum report",
    )
}

pub(crate) fn parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
    source: &[u8],
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport,
    String,
> {
    let report = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES,
        "factory final checkpoint-witness receipt quorum checkpoint witness quorum report",
    )?;
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
        &report,
    )?;
    Ok(report)
}

pub(crate) fn render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
    state: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        state,
    )?;
    render_bounded(
        state,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_TRUST_STATE_BYTES,
        "factory final checkpoint-witness receipt quorum checkpoint witness trust state",
    )
}

pub(crate) fn parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
    source: &[u8],
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
    String,
> {
    let state = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_TRUST_STATE_BYTES,
        "factory final checkpoint-witness receipt quorum checkpoint witness trust state",
    )?;
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        &state,
    )?;
    Ok(state)
}

pub(crate) fn render_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
    rotation: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<Vec<u8>, String> {
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
        rotation,
    )?;
    render_bounded(
        rotation,
        MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_KEY_ROTATION_BYTES,
        "signed factory final checkpoint-witness receipt quorum checkpoint witness key rotation",
    )
}

pub(crate) fn parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
    source: &[u8],
) -> Result<
    SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessKeyRotation,
    String,
> {
    let rotation = parse_canonical(
        source,
        MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_KEY_ROTATION_BYTES,
        "signed factory final checkpoint-witness receipt quorum checkpoint witness key rotation",
    )?;
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-v1.json",
        "title": "pcbex independent factory final checkpoint-witness receipt-quorum checkpoint witness",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "checkpoint_sha256", "registry_id", "generation",
            "receipt_quorum_checkpoint_sha256",
            "checkpoint_witness_receipt_quorum_checkpoint_sha256",
            "final_admission_log_id", "final_admission_log_entry_count",
            "final_admission_log_head_sha256", "final_admission_log_sha256",
            "witness_id", "witnessed_at_unix", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "checkpoint_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "receipt_quorum_checkpoint_sha256": digest.clone(),
            "checkpoint_witness_receipt_quorum_checkpoint_sha256": digest.clone(),
            "final_admission_log_id": slug_schema(),
            "final_admission_log_entry_count": {"type": "integer", "minimum": 2},
            "final_admission_log_head_sha256": digest.clone(),
            "final_admission_log_sha256": digest.clone(),
            "witness_id": slug_schema(),
            "witnessed_at_unix": {
                "type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP
            },
            "algorithm": {"const": "ed25519"},
            "public_key": digest,
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-report-v1.json",
        "title": "pcbex independent factory final checkpoint-witness receipt-quorum checkpoint witness quorum",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "checkpoint_sha256", "registry_id", "generation",
            "receipt_quorum_checkpoint_sha256",
            "checkpoint_witness_receipt_quorum_checkpoint_sha256",
            "final_admission_log_id", "final_admission_log_entry_count",
            "final_admission_log_head_sha256", "final_admission_log_sha256",
            "evaluated_at_unix", "minimum_witnesses", "valid_witnesses",
            "witness_ids", "witness_public_keys", "quorum_met"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "status": {"enum": ["witness_quorum_met", "insufficient_witnesses"]},
            "checkpoint_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "receipt_quorum_checkpoint_sha256": digest.clone(),
            "checkpoint_witness_receipt_quorum_checkpoint_sha256": digest.clone(),
            "final_admission_log_id": slug_schema(),
            "final_admission_log_entry_count": {"type": "integer", "minimum": 2},
            "final_admission_log_head_sha256": digest.clone(),
            "final_admission_log_sha256": digest.clone(),
            "evaluated_at_unix": {
                "type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP
            },
            "minimum_witnesses": {
                "type": "integer", "minimum": 2,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
            },
            "valid_witnesses": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
            },
            "witness_ids": {
                "type": "array",
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES,
                "uniqueItems": true,
                "items": slug_schema()
            },
            "witness_public_keys": {
                "type": "array",
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES,
                "uniqueItems": true,
                "items": digest
            },
            "quorum_met": {"type": "boolean"}
        }
    })
}

pub(crate) fn remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-trust-state-v1.json",
        "title": "pcbex generation-chained factory final checkpoint-witness receipt-quorum checkpoint witness trust state",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "witness_id", "generation", "current_public_key",
            "last_rotation_sha256", "last_rotated_at_unix"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "witness_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "current_public_key": digest.clone(),
            "last_rotation_sha256": {
                "oneOf": [{"type": "null"}, digest]
            },
            "last_rotated_at_unix": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}
                ]
            }
        }
    })
}

pub(crate) fn signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-key-rotation-v1.json",
        "title": "pcbex dual-signed factory final checkpoint-witness receipt-quorum checkpoint witness key rotation",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "witness_id", "from_generation", "to_generation",
            "previous_rotation_sha256", "old_public_key", "new_public_key",
            "rotated_at_unix", "algorithm", "old_signature", "new_signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "witness_id": slug_schema(),
            "from_generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION - 1
            },
            "to_generation": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "previous_rotation_sha256": {
                "oneOf": [{"type": "null"}, digest.clone()]
            },
            "old_public_key": digest.clone(),
            "new_public_key": digest,
            "rotated_at_unix": {
                "type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP
            },
            "algorithm": {"const": "ed25519"},
            "old_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "new_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
    witness: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
) -> Result<(), String> {
    if witness.schema_version != 1
        || witness.algorithm != "ed25519"
        || witness.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || witness.final_admission_log_entry_count < 2
        || witness.witnessed_at_unix > MAX_TIMESTAMP
    {
        return Err(
            "signed factory final checkpoint-witness receipt quorum checkpoint witness invariants are invalid"
                .into(),
        );
    }
    validate_slug(&witness.registry_id, "factory release registry id")?;
    validate_slug(
        &witness.final_admission_log_id,
        "factory final checkpoint-witness receipt admission log id",
    )?;
    validate_slug(
        &witness.witness_id,
        "factory final checkpoint-witness receipt quorum checkpoint witness id",
    )?;
    for (digest, label) in [
        (
            &witness.checkpoint_sha256,
            "factory final checkpoint-witness receipt quorum checkpoint SHA-256",
        ),
        (
            &witness.receipt_quorum_checkpoint_sha256,
            "factory receipt quorum checkpoint SHA-256",
        ),
        (
            &witness.checkpoint_witness_receipt_quorum_checkpoint_sha256,
            "factory checkpoint-witness receipt quorum checkpoint SHA-256",
        ),
        (
            &witness.final_admission_log_head_sha256,
            "final admission log head SHA-256",
        ),
        (
            &witness.final_admission_log_sha256,
            "final admission log SHA-256",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    let public_key = decode_hex::<32>(
        &witness.public_key,
        "factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &public_key,
        "factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    decode_hex::<64>(
        &witness.signature,
        "factory final checkpoint-witness receipt quorum checkpoint witness signature",
    )?;
    Ok(())
}

pub(crate) fn validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
    state: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
) -> Result<(), String> {
    if state.schema_version != 1
        || state.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || state
            .last_rotated_at_unix
            .is_some_and(|timestamp| timestamp > MAX_TIMESTAMP)
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness trust-state invariants are invalid"
                .into(),
        );
    }
    validate_slug(
        &state.witness_id,
        "factory final checkpoint-witness receipt quorum checkpoint witness id",
    )?;
    let public_key = decode_hex::<32>(
        &state.current_public_key,
        "current factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &public_key,
        "current factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    match (
        state.generation,
        &state.last_rotation_sha256,
        state.last_rotated_at_unix,
    ) {
        (0, None, None) => Ok(()),
        (0, _, _) => Err(
            "initial factory final checkpoint-witness receipt quorum checkpoint witness trust state references rotation"
                .into(),
        ),
        (_, Some(digest), Some(_)) => validate_digest(
            digest,
            "factory final checkpoint-witness receipt quorum checkpoint witness rotation SHA-256",
        ),
        _ => Err(
            "rotated factory final checkpoint-witness receipt quorum checkpoint witness trust state is incomplete"
                .into(),
        ),
    }
}

pub(crate) fn validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
    rotation: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<(), String> {
    let expected_generation = rotation.from_generation.checked_add(1).ok_or_else(|| {
        "factory final checkpoint-witness receipt quorum checkpoint witness generation overflow"
            .to_string()
    })?;
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.from_generation
            >= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || rotation.to_generation != expected_generation
        || rotation.to_generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || rotation.rotated_at_unix > MAX_TIMESTAMP
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness key-rotation invariants are invalid"
                .into(),
        );
    }
    validate_slug(
        &rotation.witness_id,
        "factory final checkpoint-witness receipt quorum checkpoint witness id",
    )?;
    match (rotation.from_generation, &rotation.previous_rotation_sha256) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err(
                "initial factory final checkpoint-witness receipt quorum checkpoint witness rotation cannot reference a predecessor"
                    .into(),
            );
        }
        (_, Some(digest)) => validate_digest(
            digest,
            "previous factory final checkpoint-witness receipt quorum checkpoint witness rotation SHA-256",
        )?,
        (_, None) => {
            return Err(
                "advanced factory final checkpoint-witness receipt quorum checkpoint witness rotation requires predecessor evidence"
                    .into(),
            );
        }
    }
    let old_key = decode_hex::<32>(
        &rotation.old_public_key,
        "old factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    let new_key = decode_hex::<32>(
        &rotation.new_public_key,
        "new factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &old_key,
        "old factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &new_key,
        "new factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    let payload = factory_final_checkpoint_witness_key_rotation_payload(rotation)?;
    for (key, signature, label) in [
        (
            &old_key,
            &rotation.old_signature,
            "old factory final checkpoint-witness receipt quorum checkpoint witness rotation",
        ),
        (
            &new_key,
            &rotation.new_signature,
            "new factory final checkpoint-witness receipt quorum checkpoint witness rotation",
        ),
    ] {
        let signature = decode_hex::<64>(signature, label)?;
        VerifyingKey::from_bytes(key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &Signature::from_bytes(&signature))
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    Ok(())
}

pub(crate) fn validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
    report: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || report.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || report.final_admission_log_entry_count < 2
        || report.evaluated_at_unix > MAX_TIMESTAMP
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
            .contains(&report.minimum_witnesses)
        || report.valid_witnesses as usize != report.witness_ids.len()
        || report.valid_witnesses as usize != report.witness_public_keys.len()
        || report.valid_witnesses as usize
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
        || report.quorum_met != (report.valid_witnesses >= report.minimum_witnesses)
        || report.status
            != if report.quorum_met {
                "witness_quorum_met"
            } else {
                "insufficient_witnesses"
            }
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness quorum invariants are invalid"
                .into(),
        );
    }
    validate_slug(&report.registry_id, "factory release registry id")?;
    validate_slug(
        &report.final_admission_log_id,
        "factory final checkpoint-witness receipt admission log id",
    )?;
    for (digest, label) in [
        (
            &report.checkpoint_sha256,
            "factory final checkpoint-witness receipt quorum checkpoint SHA-256",
        ),
        (
            &report.receipt_quorum_checkpoint_sha256,
            "factory receipt quorum checkpoint SHA-256",
        ),
        (
            &report.checkpoint_witness_receipt_quorum_checkpoint_sha256,
            "factory checkpoint-witness receipt quorum checkpoint SHA-256",
        ),
        (
            &report.final_admission_log_head_sha256,
            "final admission log head SHA-256",
        ),
        (
            &report.final_admission_log_sha256,
            "final admission log SHA-256",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    let mut previous_id: Option<&str> = None;
    let mut ids = BTreeSet::new();
    for witness_id in &report.witness_ids {
        validate_slug(
            witness_id,
            "factory final checkpoint-witness receipt quorum checkpoint witness id",
        )?;
        if previous_id.is_some_and(|previous| previous >= witness_id.as_str())
            || !ids.insert(witness_id)
        {
            return Err(
                "factory final checkpoint-witness receipt quorum checkpoint witness ids must be sorted and distinct"
                    .into(),
            );
        }
        previous_id = Some(witness_id);
    }
    let mut previous_key: Option<&str> = None;
    let mut keys = BTreeSet::new();
    for key in &report.witness_public_keys {
        let bytes = decode_hex::<32>(
            key,
            "factory final checkpoint-witness receipt quorum checkpoint witness public key",
        )?;
        validate_nonweak_public_key(
            &bytes,
            "factory final checkpoint-witness receipt quorum checkpoint witness public key",
        )?;
        if previous_key.is_some_and(|previous| previous >= key.as_str()) || !keys.insert(key) {
            return Err(
                "factory final checkpoint-witness receipt quorum checkpoint witness keys must be sorted and distinct"
                    .into(),
            );
        }
        previous_key = Some(key);
    }
    Ok(())
}

pub(crate) fn new_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
    witness_id: &str,
    public_key: &[u8; 32],
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
    String,
> {
    let state =
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState {
            schema_version: 1,
            witness_id: witness_id.to_string(),
            generation: 0,
            current_public_key: hex::encode(public_key),
            last_rotation_sha256: None,
            last_rotated_at_unix: None,
        };
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        &state,
    )?;
    Ok(state)
}

pub(crate) fn remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trusted_public_key(
    state: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
) -> Result<[u8; 32], String> {
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        state,
    )?;
    decode_hex::<32>(
        &state.current_public_key,
        "current factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )
}

pub(crate) fn sign_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
    state: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<
    SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessKeyRotation,
    String,
> {
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        state,
    )?;
    if rotated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness rotation time exceeds its bound"
                .into(),
        );
    }
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key_bytes = old_key.verifying_key().to_bytes();
    let new_public_key_bytes = new_key.verifying_key().to_bytes();
    validate_nonweak_public_key(
        &old_public_key_bytes,
        "old factory final checkpoint-witness receipt quorum checkpoint witness key",
    )?;
    validate_nonweak_public_key(
        &new_public_key_bytes,
        "new factory final checkpoint-witness receipt quorum checkpoint witness key",
    )?;
    let old_public_key = hex::encode(old_public_key_bytes);
    let new_public_key = hex::encode(new_public_key_bytes);
    if old_public_key != state.current_public_key {
        return Err(
            "old factory final checkpoint-witness receipt quorum checkpoint witness key is not currently trusted"
                .into(),
        );
    }
    if new_public_key == old_public_key {
        return Err(
            "new factory final checkpoint-witness receipt quorum checkpoint witness key must differ"
                .into(),
        );
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness rotation time moved backwards"
                .into(),
        );
    }
    let to_generation = state
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        })
        .ok_or_else(|| {
            "factory final checkpoint-witness receipt quorum checkpoint witness generation overflow"
                .to_string()
        })?;
    let mut rotation =
        SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessKeyRotation {
            schema_version: 1,
            witness_id: state.witness_id.clone(),
            from_generation: state.generation,
            to_generation,
            previous_rotation_sha256: state.last_rotation_sha256.clone(),
            old_public_key,
            new_public_key,
            rotated_at_unix,
            algorithm: "ed25519".into(),
            old_signature: String::new(),
            new_signature: String::new(),
        };
    let payload = factory_final_checkpoint_witness_key_rotation_payload(&rotation)?;
    rotation.old_signature = hex::encode(old_key.sign(&payload).to_bytes());
    rotation.new_signature = hex::encode(new_key.sign(&payload).to_bytes());
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn apply_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
    state: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
    rotation: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
    String,
> {
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        state,
    )?;
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
        rotation,
    )?;
    let expected_generation = state
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        })
        .ok_or_else(|| {
            "factory final checkpoint-witness receipt quorum checkpoint witness generation overflow"
                .to_string()
        })?;
    if rotation.witness_id != state.witness_id
        || rotation.from_generation != state.generation
        || rotation.to_generation != expected_generation
        || rotation.previous_rotation_sha256 != state.last_rotation_sha256
        || rotation.old_public_key != state.current_public_key
        || state
            .last_rotated_at_unix
            .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness rotation does not extend retained trust"
                .into(),
        );
    }
    let next =
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState {
            schema_version: 1,
            witness_id: state.witness_id.clone(),
            generation: rotation.to_generation,
            current_public_key: rotation.new_public_key.clone(),
            last_rotation_sha256: Some(
                signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation_sha256(
                    rotation,
                )?,
            ),
            last_rotated_at_unix: Some(rotation.rotated_at_unix),
        };
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        &next,
    )?;
    Ok(next)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn witness_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint(
    report: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint,
    trusted_checkpoint_public_key: &[u8; 32],
    witness_id: &str,
    witnessed_at_unix: u64,
    secret_key: &[u8; 32],
) -> Result<SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness, String>
{
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint(
        report,
        log,
        checkpoint,
        trusted_checkpoint_public_key,
    )?;
    validate_slug(
        witness_id,
        "factory final checkpoint-witness receipt quorum checkpoint witness id",
    )?;
    if witnessed_at_unix > MAX_TIMESTAMP || witnessed_at_unix < report.evaluated_at_unix {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness predates its quorum report or exceeds the timestamp bound"
                .into(),
        );
    }
    let signing_key = SigningKey::from_bytes(secret_key);
    let witness_public_key = signing_key.verifying_key().to_bytes();
    validate_nonweak_public_key(
        &witness_public_key,
        "factory final checkpoint-witness receipt quorum checkpoint witness key",
    )?;
    if &witness_public_key == trusted_checkpoint_public_key {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness key must be independent from the checkpoint signing key"
                .into(),
        );
    }
    let mut witness =
        SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness {
            schema_version: 1,
            checkpoint_sha256:
                signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_sha256(
                    checkpoint,
                )?,
            registry_id: checkpoint.registry_id.clone(),
            generation: checkpoint.generation,
            receipt_quorum_checkpoint_sha256: checkpoint
                .receipt_quorum_checkpoint_sha256
                .clone(),
            checkpoint_witness_receipt_quorum_checkpoint_sha256: checkpoint
                .checkpoint_witness_receipt_quorum_checkpoint_sha256
                .clone(),
            final_admission_log_id: checkpoint.final_admission_log_id.clone(),
            final_admission_log_entry_count: checkpoint.final_admission_log_entry_count,
            final_admission_log_head_sha256: checkpoint
                .final_admission_log_head_sha256
                .clone(),
            final_admission_log_sha256: checkpoint.final_admission_log_sha256.clone(),
            witness_id: witness_id.to_string(),
            witnessed_at_unix,
            algorithm: "ed25519".into(),
            public_key: hex::encode(witness_public_key),
            signature: String::new(),
        };
    witness.signature = hex::encode(
        signing_key
            .sign(&factory_final_checkpoint_witness_payload(&witness)?)
            .to_bytes(),
    );
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
        &witness,
    )?;
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses(
    report: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint,
    trusted_checkpoint_public_key: &[u8; 32],
    witnesses: &[SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness],
    trusted_witness_public_keys: &[[u8; 32]],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport,
    String,
> {
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint(
        report,
        log,
        checkpoint,
        trusted_checkpoint_public_key,
    )?;
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness evaluation time exceeds its bound"
                .into(),
        );
    }
    if evaluated_at_unix < report.evaluated_at_unix {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness evaluation predates its quorum report"
                .into(),
        );
    }
    if !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
        .contains(&minimum_witnesses)
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness quorum must require 2 to 100 witnesses"
                .into(),
        );
    }
    if witnesses.len() != trusted_witness_public_keys.len()
        || witnesses.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witnesses and trusted keys must be paired and bounded"
                .into(),
        );
    }
    let checkpoint_sha256 =
        signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_sha256(
            checkpoint,
        )?;
    let mut witness_ids = BTreeSet::new();
    let mut witness_public_keys = BTreeSet::new();
    for (witness, trusted_key) in witnesses.iter().zip(trusted_witness_public_keys) {
        validate_nonweak_public_key(
            trusted_key,
            "trusted factory final checkpoint-witness receipt quorum checkpoint witness key",
        )?;
        if trusted_key == trusted_checkpoint_public_key {
            return Err(
                "factory final checkpoint-witness receipt quorum checkpoint witness key must be independent from the checkpoint signing key"
                    .into(),
            );
        }
        verify_factory_final_checkpoint_witness(
            checkpoint,
            &checkpoint_sha256,
            witness,
            trusted_key,
            report.evaluated_at_unix,
            evaluated_at_unix,
        )?;
        if !witness_ids.insert(witness.witness_id.clone())
            || !witness_public_keys.insert(hex::encode(trusted_key))
        {
            return Err(
                "factory final checkpoint-witness receipt quorum checkpoint witnesses must use distinct identities and keys"
                    .into(),
            );
        }
    }
    let valid_witnesses = u32::try_from(witnesses.len()).map_err(|_| {
        "factory final checkpoint-witness receipt quorum checkpoint witness count overflow"
            .to_string()
    })?;
    let quorum_met = valid_witnesses >= minimum_witnesses;
    let quorum =
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport {
            schema_version: 1,
            status: if quorum_met {
                "witness_quorum_met"
            } else {
                "insufficient_witnesses"
            }
            .into(),
            checkpoint_sha256,
            registry_id: checkpoint.registry_id.clone(),
            generation: checkpoint.generation,
            receipt_quorum_checkpoint_sha256: checkpoint.receipt_quorum_checkpoint_sha256.clone(),
            checkpoint_witness_receipt_quorum_checkpoint_sha256: checkpoint
                .checkpoint_witness_receipt_quorum_checkpoint_sha256
                .clone(),
            final_admission_log_id: checkpoint.final_admission_log_id.clone(),
            final_admission_log_entry_count: checkpoint.final_admission_log_entry_count,
            final_admission_log_head_sha256: checkpoint.final_admission_log_head_sha256.clone(),
            final_admission_log_sha256: checkpoint.final_admission_log_sha256.clone(),
            evaluated_at_unix,
            minimum_witnesses,
            valid_witnesses,
            witness_ids: witness_ids.into_iter().collect(),
            witness_public_keys: witness_public_keys.into_iter().collect(),
            quorum_met,
        };
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
        &quorum,
    )?;
    Ok(quorum)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses_with_trust_states(
    report: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint,
    trusted_checkpoint_public_key: &[u8; 32],
    witnesses: &[SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness],
    witness_trust_states: &[RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport,
    String,
> {
    if witnesses.len() != witness_trust_states.len()
        || witnesses.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witnesses and trust states must be paired and bounded"
                .into(),
        );
    }
    for (witness, state) in witnesses.iter().zip(witness_trust_states) {
        validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
            state,
        )?;
        if witness.witness_id != state.witness_id {
            return Err(
                "factory final checkpoint-witness receipt quorum checkpoint witness identity does not match retained trust"
                    .into(),
            );
        }
    }
    let trusted_keys = witness_trust_states
        .iter()
        .map(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trusted_public_key,
        )
        .collect::<Result<Vec<_>, _>>()?;
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses(
        report,
        log,
        checkpoint,
        trusted_checkpoint_public_key,
        witnesses,
        &trusted_keys,
        minimum_witnesses,
        evaluated_at_unix,
    )
}

fn signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation_sha256(
    rotation: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<String, String> {
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
        rotation,
    )?;
    serde_json::to_vec(rotation)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| {
            format!(
                "serializing factory final checkpoint-witness receipt quorum checkpoint witness rotation: {error}"
            )
        })
}

fn signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_sha256(
    checkpoint: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint,
) -> Result<String, String> {
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint(
        checkpoint,
    )?;
    serde_json::to_vec(checkpoint)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| {
            format!(
                "serializing factory final checkpoint-witness receipt quorum checkpoint: {error}"
            )
        })
}

fn factory_final_checkpoint_witness_payload(
    witness: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
) -> Result<Vec<u8>, String> {
    let body = json!({
        "schema_version": witness.schema_version,
        "checkpoint_sha256": witness.checkpoint_sha256,
        "registry_id": witness.registry_id,
        "generation": witness.generation,
        "receipt_quorum_checkpoint_sha256": witness.receipt_quorum_checkpoint_sha256,
        "checkpoint_witness_receipt_quorum_checkpoint_sha256": witness.checkpoint_witness_receipt_quorum_checkpoint_sha256,
        "final_admission_log_id": witness.final_admission_log_id,
        "final_admission_log_entry_count": witness.final_admission_log_entry_count,
        "final_admission_log_head_sha256": witness.final_admission_log_head_sha256,
        "final_admission_log_sha256": witness.final_admission_log_sha256,
        "witness_id": witness.witness_id,
        "witnessed_at_unix": witness.witnessed_at_unix,
        "algorithm": witness.algorithm
    });
    let mut payload = FINAL_CHECKPOINT_WITNESS_DOMAIN.as_bytes().to_vec();
    payload.push(0);
    payload.extend(serde_json::to_vec(&body).map_err(|error| {
        format!(
            "serializing factory final checkpoint-witness receipt quorum checkpoint witness: {error}"
        )
    })?);
    Ok(payload)
}

fn factory_final_checkpoint_witness_key_rotation_payload(
    rotation: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<Vec<u8>, String> {
    let body = json!({
        "schema_version": rotation.schema_version,
        "witness_id": rotation.witness_id,
        "from_generation": rotation.from_generation,
        "to_generation": rotation.to_generation,
        "previous_rotation_sha256": rotation.previous_rotation_sha256,
        "old_public_key": rotation.old_public_key,
        "new_public_key": rotation.new_public_key,
        "rotated_at_unix": rotation.rotated_at_unix,
        "algorithm": rotation.algorithm
    });
    let mut payload = FINAL_CHECKPOINT_WITNESS_KEY_ROTATION_DOMAIN
        .as_bytes()
        .to_vec();
    payload.push(0);
    payload.extend(serde_json::to_vec(&body).map_err(|error| {
        format!(
            "serializing factory final checkpoint-witness receipt quorum checkpoint witness rotation: {error}"
        )
    })?);
    Ok(payload)
}

fn verify_factory_final_checkpoint_witness(
    checkpoint: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint,
    checkpoint_sha256: &str,
    witness: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
    trusted_public_key: &[u8; 32],
    earliest_witnessed_at_unix: u64,
    evaluated_at_unix: u64,
) -> Result<(), String> {
    validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
        witness,
    )?;
    validate_nonweak_public_key(
        trusted_public_key,
        "trusted factory final checkpoint-witness receipt quorum checkpoint witness key",
    )?;
    if witness.checkpoint_sha256 != checkpoint_sha256
        || witness.registry_id != checkpoint.registry_id
        || witness.generation != checkpoint.generation
        || witness.receipt_quorum_checkpoint_sha256 != checkpoint.receipt_quorum_checkpoint_sha256
        || witness.checkpoint_witness_receipt_quorum_checkpoint_sha256
            != checkpoint.checkpoint_witness_receipt_quorum_checkpoint_sha256
        || witness.final_admission_log_id != checkpoint.final_admission_log_id
        || witness.final_admission_log_entry_count != checkpoint.final_admission_log_entry_count
        || witness.final_admission_log_head_sha256 != checkpoint.final_admission_log_head_sha256
        || witness.final_admission_log_sha256 != checkpoint.final_admission_log_sha256
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness is bound to different evidence"
                .into(),
        );
    }
    if witness.public_key != hex::encode(trusted_public_key) {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness key is not trusted"
                .into(),
        );
    }
    if witness.witnessed_at_unix < earliest_witnessed_at_unix
        || evaluated_at_unix < witness.witnessed_at_unix
        || evaluated_at_unix - witness.witnessed_at_unix
            > MAXIMUM_FINAL_CHECKPOINT_WITNESS_AGE_SECONDS
    {
        return Err(
            "factory final checkpoint-witness receipt quorum checkpoint witness is outside the 24-hour window"
                .into(),
        );
    }
    let signature = decode_hex::<64>(
        &witness.signature,
        "factory final checkpoint-witness receipt quorum checkpoint witness signature",
    )?;
    VerifyingKey::from_bytes(trusted_public_key)
        .map_err(|error| {
            format!(
                "invalid factory final checkpoint-witness receipt quorum checkpoint witness key: {error}"
            )
        })?
        .verify_strict(
            &factory_final_checkpoint_witness_payload(witness)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|error| {
            format!(
                "invalid factory final checkpoint-witness receipt quorum checkpoint witness signature: {error}"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint() -> SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint {
        let key = SigningKey::from_bytes(&[141; 32]);
        SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint {
            schema_version: 1,
            final_checkpoint_witness_receipt_quorum_report_sha256: "1".repeat(64),
            registry_id: "factory-registry".into(),
            generation: 7,
            registry_checkpoint_sha256: "2".repeat(64),
            receipt_quorum_checkpoint_sha256: "3".repeat(64),
            checkpoint_witness_receipt_quorum_checkpoint_sha256: "4".repeat(64),
            final_admission_log_id: "final-admission".into(),
            final_admission_log_entry_count: 2,
            final_admission_log_head_sha256: "5".repeat(64),
            final_admission_log_sha256: "6".repeat(64),
            minimum_witnesses: 2,
            valid_witnesses: 2,
            signer_id: "final-checkpoint".into(),
            algorithm: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            signature: "0".repeat(128),
        }
    }

    fn witness(
        checkpoint: &SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint,
        secret: [u8; 32],
        witness_id: &str,
    ) -> SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness {
        let signing_key = SigningKey::from_bytes(&secret);
        let mut witness =
            SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness {
                schema_version: 1,
                checkpoint_sha256:
                    signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_sha256(
                        checkpoint,
                    )
                    .unwrap(),
                registry_id: checkpoint.registry_id.clone(),
                generation: checkpoint.generation,
                receipt_quorum_checkpoint_sha256: checkpoint
                    .receipt_quorum_checkpoint_sha256
                    .clone(),
                checkpoint_witness_receipt_quorum_checkpoint_sha256: checkpoint
                    .checkpoint_witness_receipt_quorum_checkpoint_sha256
                    .clone(),
                final_admission_log_id: checkpoint.final_admission_log_id.clone(),
                final_admission_log_entry_count: checkpoint.final_admission_log_entry_count,
                final_admission_log_head_sha256: checkpoint
                    .final_admission_log_head_sha256
                    .clone(),
                final_admission_log_sha256: checkpoint.final_admission_log_sha256.clone(),
                witness_id: witness_id.into(),
                witnessed_at_unix: 2_000,
                algorithm: "ed25519".into(),
                public_key: hex::encode(signing_key.verifying_key().to_bytes()),
                signature: String::new(),
            };
        witness.signature = hex::encode(
            signing_key
                .sign(&factory_final_checkpoint_witness_payload(&witness).unwrap())
                .to_bytes(),
        );
        witness
    }

    #[test]
    fn witness_and_quorum_documents_are_canonical_and_closed() {
        let checkpoint = checkpoint();
        let witness_a = witness(&checkpoint, [142; 32], "final-witness-a");
        let source = render_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
            &witness_a,
        )
        .unwrap();
        assert_eq!(
            parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
                &source,
            )
            .unwrap(),
            witness_a
        );
        assert!(
            parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
                &serde_json::to_vec(&witness_a).unwrap(),
            )
            .is_err()
        );
        assert_eq!(
            signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_json_schema(
            )["additionalProperties"],
            false
        );

        verify_factory_final_checkpoint_witness(
            &checkpoint,
            &witness_a.checkpoint_sha256,
            &witness_a,
            &SigningKey::from_bytes(&[142; 32])
                .verifying_key()
                .to_bytes(),
            1_999,
            2_000,
        )
        .unwrap();
        let mut wrong_domain = witness_a.clone();
        let key = SigningKey::from_bytes(&[142; 32]);
        let mut payload = factory_final_checkpoint_witness_payload(&wrong_domain).unwrap();
        payload.splice(
            ..FINAL_CHECKPOINT_WITNESS_DOMAIN.len(),
            b"pcbex-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-v1"
                .iter()
                .copied(),
        );
        wrong_domain.signature = hex::encode(key.sign(&payload).to_bytes());
        assert!(
            verify_factory_final_checkpoint_witness(
                &checkpoint,
                &wrong_domain.checkpoint_sha256,
                &wrong_domain,
                &key.verifying_key().to_bytes(),
                1_999,
                2_000,
            )
            .is_err()
        );

        let witness_b = witness(&checkpoint, [143; 32], "final-witness-b");
        let mut ids = vec![witness_a.witness_id.clone(), witness_b.witness_id.clone()];
        ids.sort();
        let mut keys = vec![witness_a.public_key.clone(), witness_b.public_key.clone()];
        keys.sort();
        let report =
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport {
                schema_version: 1,
                status: "witness_quorum_met".into(),
                checkpoint_sha256: witness_a.checkpoint_sha256.clone(),
                registry_id: checkpoint.registry_id.clone(),
                generation: checkpoint.generation,
                receipt_quorum_checkpoint_sha256: checkpoint
                    .receipt_quorum_checkpoint_sha256
                    .clone(),
                checkpoint_witness_receipt_quorum_checkpoint_sha256: checkpoint
                    .checkpoint_witness_receipt_quorum_checkpoint_sha256
                    .clone(),
                final_admission_log_id: checkpoint.final_admission_log_id.clone(),
                final_admission_log_entry_count: checkpoint.final_admission_log_entry_count,
                final_admission_log_head_sha256: checkpoint
                    .final_admission_log_head_sha256
                    .clone(),
                final_admission_log_sha256: checkpoint.final_admission_log_sha256.clone(),
                evaluated_at_unix: 2_000,
                minimum_witnesses: 2,
                valid_witnesses: 2,
                witness_ids: ids,
                witness_public_keys: keys,
                quorum_met: true,
            };
        let report_source = render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
            &report,
        )
        .unwrap();
        assert_eq!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
                &report_source,
            )
            .unwrap(),
            report
        );
        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report_json_schema(
            )["additionalProperties"],
            false
        );
        let mut unsorted = report;
        unsorted.witness_ids.reverse();
        assert!(
            validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
                &unsorted,
            )
            .is_err()
        );
    }

    #[test]
    fn witness_trust_rotation_is_dual_signed_chained_and_closed() {
        let old_key = SigningKey::from_bytes(&[144; 32]);
        let next_key = SigningKey::from_bytes(&[145; 32]);
        let last_key = SigningKey::from_bytes(&[146; 32]);
        let state = new_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
            "final-witness-a",
            &old_key.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(state.generation, 0);
        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trusted_public_key(
                &state,
            )
            .unwrap(),
            old_key.verifying_key().to_bytes()
        );
        let state_source = render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
            &state,
        )
        .unwrap();
        assert_eq!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
                &state_source,
            )
            .unwrap(),
            state
        );

        let rotation_1 = sign_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
            &state,
            &old_key.to_bytes(),
            &next_key.to_bytes(),
            2_001,
        )
        .unwrap();
        let rotation_source = render_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
            &rotation_1,
        )
        .unwrap();
        assert_eq!(
            parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &rotation_source,
            )
            .unwrap(),
            rotation_1
        );
        let state_1 = apply_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
            &state,
            &rotation_1,
        )
        .unwrap();
        assert_eq!(state_1.generation, 1);
        assert_eq!(
            state_1.current_public_key,
            hex::encode(next_key.verifying_key().to_bytes())
        );

        let rotation_2 = sign_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
            &state_1,
            &next_key.to_bytes(),
            &last_key.to_bytes(),
            2_002,
        )
        .unwrap();
        assert_eq!(
            rotation_2.previous_rotation_sha256,
            state_1.last_rotation_sha256
        );
        let state_2 = apply_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
            &state_1,
            &rotation_2,
        )
        .unwrap();
        assert_eq!(state_2.generation, 2);
        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trusted_public_key(
                &state_2,
            )
            .unwrap(),
            last_key.verifying_key().to_bytes()
        );

        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state_json_schema(
            )["additionalProperties"],
            false
        );
        assert_eq!(
            signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation_json_schema(
            )["additionalProperties"],
            false
        );

        let mut tampered = rotation_1.clone();
        tampered.new_signature.replace_range(..2, "00");
        assert!(
            validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &tampered,
            )
            .is_err()
        );

        let mut wrong_domain = rotation_1.clone();
        let mut wrong_domain_payload =
            factory_final_checkpoint_witness_key_rotation_payload(&wrong_domain).unwrap();
        wrong_domain_payload.splice(
            ..FINAL_CHECKPOINT_WITNESS_KEY_ROTATION_DOMAIN.len(),
            b"pcbex-factory-release-registry-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-key-rotation-v1"
                .iter()
                .copied(),
        );
        wrong_domain.old_signature = hex::encode(old_key.sign(&wrong_domain_payload).to_bytes());
        wrong_domain.new_signature = hex::encode(next_key.sign(&wrong_domain_payload).to_bytes());
        assert!(
            validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &wrong_domain,
            )
            .is_err()
        );

        let mut skipped = rotation_1.clone();
        skipped.to_generation = 2;
        assert!(
            validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &skipped,
            )
            .is_err()
        );
        let mut missing_predecessor = rotation_2.clone();
        missing_predecessor.previous_rotation_sha256 = None;
        assert!(
            validate_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &missing_predecessor,
            )
            .is_err()
        );
        assert!(
            sign_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &state_1,
                &next_key.to_bytes(),
                &last_key.to_bytes(),
                2_000,
            )
            .is_err()
        );
        assert!(
            sign_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &state,
                &old_key.to_bytes(),
                &old_key.to_bytes(),
                2_001,
            )
            .is_err()
        );
        assert!(
            sign_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &state,
                &last_key.to_bytes(),
                &next_key.to_bytes(),
                2_001,
            )
            .is_err()
        );
        assert!(
            apply_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &state_1,
                &rotation_1,
            )
            .is_err()
        );
        assert!(
            new_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
                "weak-final-witness",
                &[0; 32],
            )
            .is_err()
        );
        let exhausted =
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState {
                schema_version: 1,
                witness_id: "final-witness-a".into(),
                generation:
                    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION,
                current_public_key: hex::encode(last_key.verifying_key().to_bytes()),
                last_rotation_sha256: Some("a".repeat(64)),
                last_rotated_at_unix: Some(2_002),
            };
        assert!(
            sign_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_key_rotation(
                &exhausted,
                &last_key.to_bytes(),
                &SigningKey::from_bytes(&[147; 32]).to_bytes(),
                2_003,
            )
            .is_err()
        );
    }
}

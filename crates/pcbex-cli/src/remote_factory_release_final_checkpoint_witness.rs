//! Independent witnesses for the dedicated final factory-release checkpoint.
//!
//! The v1.524 boundary re-verifies the exact v1.521 final witness-quorum
//! report, complete admission log, v1.523 dedicated checkpoint, and pinned
//! checkpoint key before a witness key is used. It then signs the checkpoint
//! digest beneath a new domain. Quorum verification accepts 2–100 fresh,
//! distinct, non-weak witness keys that cannot reuse the checkpoint signing
//! key.
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
const MAXIMUM_FINAL_CHECKPOINT_WITNESS_AGE_SECONDS: u64 = 86_400;

pub(crate) const MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES: u64 =
    128 * 1024;

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
}

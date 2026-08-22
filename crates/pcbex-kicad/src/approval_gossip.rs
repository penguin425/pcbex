use crate::{
    ApprovalLogAnchorProof, ApprovalLogConsistencyProof, SignedApprovalPublicLogTreeHead,
    approval_public_log_tree_head_sha256, validate_approval_log_anchor_proof,
    verify_approval_log_tree_head_consistency, verify_approval_public_log_tree_head,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const GOSSIP_RECEIPT_DOMAIN: &str = "pcbex-approval-public-log-gossip-receipt-v1";
const MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalLogGossipReceipt {
    pub schema_version: u32,
    pub observer_id: String,
    pub tree_head_sha256: String,
    pub tree_head: SignedApprovalPublicLogTreeHead,
    pub received_at_unix: u64,
    pub expires_at_unix: u64,
    pub algorithm: String,
    pub observer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipVerificationReport {
    pub schema_version: u32,
    pub log_id: String,
    pub local_tree_head_sha256: String,
    pub local_tree_size: u64,
    pub local_root_sha256: String,
    pub observed_tree_head_sha256: String,
    pub observed_tree_size: u64,
    pub observed_root_sha256: String,
    pub relationship: String,
    pub consistency_proof_sha256: Option<String>,
    pub observer_id: String,
    pub observer_public_key: String,
    pub gossip_receipt_sha256: String,
    pub received_at_unix: u64,
    pub expires_at_unix: u64,
    pub verified_at_unix: u64,
    pub split_view_detected: bool,
    pub verified: bool,
}

#[derive(Serialize)]
struct GossipReceiptPayload<'a> {
    domain: &'static str,
    observer_id: &'a str,
    tree_head_sha256: &'a str,
    log_id: &'a str,
    tree_size: u64,
    root_sha256: &'a str,
    log_public_key: &'a str,
    received_at_unix: u64,
    expires_at_unix: u64,
}

pub fn sign_approval_log_gossip_receipt(
    anchor: &ApprovalLogAnchorProof,
    trusted_log_public_key: &[u8; 32],
    observer_id: &str,
    received_at_unix: u64,
    expires_at_unix: u64,
    observer_secret_key: &[u8; 32],
) -> Result<SignedApprovalLogGossipReceipt, String> {
    validate_approval_log_anchor_proof(anchor)?;
    validate_slug(observer_id, "approval gossip observer id")?;
    let head = &anchor.tree_head;
    verify_approval_public_log_tree_head(head, trusted_log_public_key)?;
    validate_receipt_window(head, received_at_unix, expires_at_unix)?;
    let signing_key = SigningKey::from_bytes(observer_secret_key);
    let observer_public_key = signing_key.verifying_key().to_bytes();
    if &observer_public_key == trusted_log_public_key {
        return Err("approval gossip observer key must be independent from the log key".into());
    }
    let tree_head_sha256 = approval_public_log_tree_head_sha256(head)?;
    let payload = gossip_receipt_payload(
        observer_id,
        &tree_head_sha256,
        head,
        received_at_unix,
        expires_at_unix,
    )?;
    Ok(SignedApprovalLogGossipReceipt {
        schema_version: 1,
        observer_id: observer_id.into(),
        tree_head_sha256,
        tree_head: head.clone(),
        received_at_unix,
        expires_at_unix,
        algorithm: "ed25519".into(),
        observer_public_key: hex_encode(&observer_public_key),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_approval_log_gossip_receipt(
    local_anchor: &ApprovalLogAnchorProof,
    receipt: &SignedApprovalLogGossipReceipt,
    consistency_proof: Option<&ApprovalLogConsistencyProof>,
    trusted_log_public_key: &[u8; 32],
    trusted_observer_id: &str,
    trusted_observer_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<ApprovalLogGossipVerificationReport, String> {
    validate_approval_log_anchor_proof(local_anchor)?;
    validate_approval_log_gossip_receipt(receipt)?;
    validate_slug(trusted_observer_id, "trusted approval gossip observer id")?;
    if receipt.observer_id != trusted_observer_id {
        return Err("approval gossip observer id does not match the trusted observer".into());
    }
    if trusted_observer_public_key == trusted_log_public_key {
        return Err("approval gossip observer key must be independent from the log key".into());
    }
    let local_head = &local_anchor.tree_head;
    let observed_head = &receipt.tree_head;
    verify_approval_public_log_tree_head(local_head, trusted_log_public_key)?;
    verify_approval_public_log_tree_head(observed_head, trusted_log_public_key)?;
    if local_head.log_id != observed_head.log_id {
        return Err("approval gossip tree heads use different log identities".into());
    }
    validate_receipt_window(
        observed_head,
        receipt.received_at_unix,
        receipt.expires_at_unix,
    )?;
    if evaluated_at_unix < receipt.received_at_unix {
        return Err("approval gossip receipt is not valid yet".into());
    }
    if evaluated_at_unix > receipt.expires_at_unix {
        return Err("approval gossip receipt has expired".into());
    }
    let tree_head_sha256 = approval_public_log_tree_head_sha256(observed_head)?;
    if receipt.tree_head_sha256 != tree_head_sha256 {
        return Err("approval gossip receipt tree-head digest does not match".into());
    }
    let observer_public_key =
        hex_decode::<32>(&receipt.observer_public_key, "approval gossip observer key")?;
    if &observer_public_key != trusted_observer_public_key {
        return Err("approval gossip observer key does not match the trusted public key".into());
    }
    let signature = hex_decode::<64>(&receipt.signature, "approval gossip signature")?;
    let payload = gossip_receipt_payload(
        &receipt.observer_id,
        &receipt.tree_head_sha256,
        observed_head,
        receipt.received_at_unix,
        receipt.expires_at_unix,
    )?;
    VerifyingKey::from_bytes(&observer_public_key)
        .map_err(|error| format!("invalid approval gossip observer key: {error}"))?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|error| format!("invalid approval gossip receipt signature: {error}"))?;

    let local_tree_head_sha256 = approval_public_log_tree_head_sha256(local_head)?;
    let same_tree = local_head.tree_size == observed_head.tree_size
        && local_head.root_sha256 == observed_head.root_sha256;
    let (relationship, consistency_proof_sha256) = if same_tree {
        if consistency_proof.is_some() {
            return Err("approval gossip consistency proof is redundant for one tree".into());
        }
        ("same_tree".to_string(), None)
    } else {
        if local_head.tree_size == observed_head.tree_size {
            return Err("approval public log presented split-view roots at one tree size".into());
        }
        let proof = consistency_proof.ok_or_else(|| {
            "approval gossip requires a consistency proof for different tree sizes".to_string()
        })?;
        let (expected_old, expected_new, relationship) =
            if observed_head.tree_size < local_head.tree_size {
                (observed_head, local_head, "observed_precedes_local")
            } else {
                (local_head, observed_head, "local_precedes_observed")
            };
        if &proof.old_tree_head != expected_old || &proof.new_tree_head != expected_new {
            return Err(
                "approval gossip consistency proof does not bind the compared tree heads".into(),
            );
        }
        verify_approval_log_tree_head_consistency(proof, trusted_log_public_key)?;
        (
            relationship.to_string(),
            Some(normalized_sha256(proof, "approval consistency proof")?),
        )
    };

    Ok(ApprovalLogGossipVerificationReport {
        schema_version: 1,
        log_id: local_head.log_id.clone(),
        local_tree_head_sha256,
        local_tree_size: local_head.tree_size,
        local_root_sha256: local_head.root_sha256.clone(),
        observed_tree_head_sha256: tree_head_sha256,
        observed_tree_size: observed_head.tree_size,
        observed_root_sha256: observed_head.root_sha256.clone(),
        relationship,
        consistency_proof_sha256,
        observer_id: receipt.observer_id.clone(),
        observer_public_key: receipt.observer_public_key.clone(),
        gossip_receipt_sha256: normalized_sha256(receipt, "approval gossip receipt")?,
        received_at_unix: receipt.received_at_unix,
        expires_at_unix: receipt.expires_at_unix,
        verified_at_unix: evaluated_at_unix,
        split_view_detected: false,
        verified: true,
    })
}

pub fn validate_approval_log_gossip_receipt(
    receipt: &SignedApprovalLogGossipReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1 || receipt.algorithm != "ed25519" {
        return Err("unsupported approval gossip receipt".into());
    }
    validate_slug(&receipt.observer_id, "approval gossip observer id")?;
    validate_sha256(
        &receipt.tree_head_sha256,
        "approval gossip tree-head SHA-256",
    )?;
    approval_public_log_tree_head_sha256(&receipt.tree_head)?;
    validate_receipt_window(
        &receipt.tree_head,
        receipt.received_at_unix,
        receipt.expires_at_unix,
    )?;
    hex_decode::<32>(
        &receipt.observer_public_key,
        "approval gossip observer public key",
    )?;
    hex_decode::<64>(&receipt.signature, "approval gossip signature")?;
    Ok(())
}

fn validate_receipt_window(
    head: &SignedApprovalPublicLogTreeHead,
    received_at_unix: u64,
    expires_at_unix: u64,
) -> Result<(), String> {
    if received_at_unix < head.observed_at_unix {
        return Err("approval gossip receipt predates its observed tree head".into());
    }
    let lifetime = expires_at_unix
        .checked_sub(received_at_unix)
        .ok_or_else(|| "approval gossip receipt expiry precedes receipt time".to_string())?;
    if lifetime == 0 || lifetime > MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS {
        return Err(format!(
            "approval gossip receipt lifetime must be 1 to {MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS} seconds"
        ));
    }
    Ok(())
}

fn gossip_receipt_payload(
    observer_id: &str,
    tree_head_sha256: &str,
    head: &SignedApprovalPublicLogTreeHead,
    received_at_unix: u64,
    expires_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&GossipReceiptPayload {
        domain: GOSSIP_RECEIPT_DOMAIN,
        observer_id,
        tree_head_sha256,
        log_id: &head.log_id,
        tree_size: head.tree_size,
        root_sha256: &head.root_sha256,
        log_public_key: &head.public_key,
        received_at_unix,
        expires_at_unix,
    })
    .map_err(|error| format!("serializing approval gossip receipt: {error}"))
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| format!("serializing {label}: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit());
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{label} {value:?} must match [a-z0-9][a-z0-9.-]{{0,127}}"
        ))
    }
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} must be 64 lowercase hexadecimal digits"))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{label} must contain {} hexadecimal digits", N * 2));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex_nibble(pair[0], label)? << 4) | hex_nibble(pair[1], label)?;
    }
    Ok(output)
}

fn hex_nibble(byte: u8, label: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(format!("{label} must be lowercase hexadecimal")),
    }
}

pub fn signed_approval_log_gossip_receipt_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/signed-approval-log-gossip-receipt-v1.json",
        "title": "pcbex signed approval public-log gossip receipt",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "observer_id", "tree_head_sha256", "tree_head",
            "received_at_unix", "expires_at_unix", "algorithm",
            "observer_public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "observer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "tree_head_sha256": digest.clone(),
            "tree_head": signed_tree_head_json_schema(),
            "received_at_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 1},
            "algorithm": {"const": "ed25519"},
            "observer_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn approval_log_gossip_verification_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/approval-log-gossip-verification-report-v1.json",
        "title": "pcbex approval public-log gossip verification",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "log_id", "local_tree_head_sha256", "local_tree_size",
            "local_root_sha256", "observed_tree_head_sha256", "observed_tree_size",
            "observed_root_sha256", "relationship", "consistency_proof_sha256",
            "observer_id", "observer_public_key", "gossip_receipt_sha256",
            "received_at_unix", "expires_at_unix", "verified_at_unix",
            "split_view_detected", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "local_tree_head_sha256": digest.clone(),
            "local_tree_size": {"type": "integer", "minimum": 1, "maximum": 100000},
            "local_root_sha256": digest.clone(),
            "observed_tree_head_sha256": digest.clone(),
            "observed_tree_size": {"type": "integer", "minimum": 1, "maximum": 100000},
            "observed_root_sha256": digest.clone(),
            "relationship": {
                "enum": ["same_tree", "observed_precedes_local", "local_precedes_observed"]
            },
            "consistency_proof_sha256": {"oneOf": [digest.clone(), {"type": "null"}]},
            "observer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "observer_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "gossip_receipt_sha256": digest,
            "received_at_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 1},
            "verified_at_unix": {"type": "integer", "minimum": 0},
            "split_view_detected": {"const": false},
            "verified": {"const": true}
        }
    })
}

fn signed_tree_head_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "log_id", "tree_size", "root_sha256",
            "observed_at_unix", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "tree_size": {"type": "integer", "minimum": 1, "maximum": 100000},
            "root_sha256": digest,
            "observed_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        create_approval_log_anchor_proof, create_approval_log_consistency_proof,
        new_approval_transparency_log, sign_approval_log_checkpoint,
        signed_approval_log_checkpoint_sha256,
    };

    fn anchors() -> (
        ApprovalLogAnchorProof,
        ApprovalLogAnchorProof,
        ApprovalLogConsistencyProof,
    ) {
        let log = new_approval_transparency_log("approvals").unwrap();
        let checkpoints = (1_u8..=4)
            .map(|marker| sign_approval_log_checkpoint(&log, "origin", &[marker; 32]).unwrap())
            .collect::<Vec<_>>();
        let digests = checkpoints
            .iter()
            .map(signed_approval_log_checkpoint_sha256)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let old = create_approval_log_anchor_proof(
            &checkpoints[1],
            &digests[..2],
            1,
            "public-approvals",
            100,
            &[9; 32],
        )
        .unwrap();
        let current = create_approval_log_anchor_proof(
            &checkpoints[3],
            &digests,
            3,
            "public-approvals",
            101,
            &[9; 32],
        )
        .unwrap();
        let consistency = create_approval_log_consistency_proof(&old, &current, &digests).unwrap();
        (old, current, consistency)
    }

    #[test]
    fn verifies_same_and_consistent_cross_consumer_views() {
        let (old, current, consistency) = anchors();
        let log_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let observer_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let receipt =
            sign_approval_log_gossip_receipt(&current, &log_key, "observer-a", 102, 200, &[8; 32])
                .unwrap();
        let report = verify_approval_log_gossip_receipt(
            &old,
            &receipt,
            Some(&consistency),
            &log_key,
            "observer-a",
            &observer_key,
            150,
        )
        .unwrap();
        assert_eq!(report.relationship, "local_precedes_observed");
        assert!(report.verified);
        assert!(!report.split_view_detected);

        let same = verify_approval_log_gossip_receipt(
            &current,
            &receipt,
            None,
            &log_key,
            "observer-a",
            &observer_key,
            150,
        )
        .unwrap();
        assert_eq!(same.relationship, "same_tree");
        assert!(same.consistency_proof_sha256.is_none());
    }

    #[test]
    fn rejects_split_views_staleness_redundancy_and_substitution() {
        let (old, current, consistency) = anchors();
        let log_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let observer_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let receipt =
            sign_approval_log_gossip_receipt(&current, &log_key, "observer-a", 102, 200, &[8; 32])
                .unwrap();
        assert!(
            verify_approval_log_gossip_receipt(
                &current,
                &receipt,
                Some(&consistency),
                &log_key,
                "observer-a",
                &observer_key,
                150,
            )
            .is_err()
        );
        assert!(
            verify_approval_log_gossip_receipt(
                &old,
                &receipt,
                Some(&consistency),
                &log_key,
                "observer-a",
                &observer_key,
                201,
            )
            .is_err()
        );
        assert!(
            verify_approval_log_gossip_receipt(
                &old,
                &receipt,
                Some(&consistency),
                &log_key,
                "observer-b",
                &observer_key,
                150,
            )
            .is_err()
        );

        let log = new_approval_transparency_log("approvals").unwrap();
        let forked = (11_u8..=12)
            .map(|marker| sign_approval_log_checkpoint(&log, "origin", &[marker; 32]).unwrap())
            .collect::<Vec<_>>();
        let forked_digests = forked
            .iter()
            .map(signed_approval_log_checkpoint_sha256)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let split = create_approval_log_anchor_proof(
            &forked[1],
            &forked_digests,
            1,
            "public-approvals",
            103,
            &[9; 32],
        )
        .unwrap();
        let split_receipt =
            sign_approval_log_gossip_receipt(&split, &log_key, "observer-a", 104, 200, &[8; 32])
                .unwrap();
        assert!(
            verify_approval_log_gossip_receipt(
                &old,
                &split_receipt,
                None,
                &log_key,
                "observer-a",
                &observer_key,
                150,
            )
            .is_err()
        );
    }

    #[test]
    fn schemas_are_closed() {
        assert_eq!(
            signed_approval_log_gossip_receipt_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            signed_approval_log_gossip_receipt_json_schema()["properties"]["tree_head"]["additionalProperties"],
            false
        );
        assert_eq!(
            approval_log_gossip_verification_report_json_schema()["additionalProperties"],
            false
        );
    }
}

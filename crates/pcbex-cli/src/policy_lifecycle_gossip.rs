use crate::policy_lifecycle_anchor::{
    PolicyLifecycleLogAnchorProof, PolicyLifecycleLogConsistencyProof,
    SignedPolicyLifecyclePublicLogTreeHead, policy_lifecycle_public_log_tree_head_sha256,
    validate_policy_lifecycle_log_anchor_proof, verify_policy_lifecycle_log_tree_head_consistency,
    verify_policy_lifecycle_public_log_tree_head,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const GOSSIP_RECEIPT_DOMAIN: &str = "pcbex-policy-lifecycle-public-log-gossip-receipt-v1";
const MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipReceipt {
    pub schema_version: u32,
    pub observer_id: String,
    pub tree_head_sha256: String,
    pub tree_head: SignedPolicyLifecyclePublicLogTreeHead,
    pub received_at_unix: u64,
    pub expires_at_unix: u64,
    pub algorithm: String,
    pub observer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipVerificationReport {
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

pub fn sign_policy_lifecycle_log_gossip_receipt(
    anchor: &PolicyLifecycleLogAnchorProof,
    trusted_log_id: &str,
    trusted_log_public_key: &[u8; 32],
    observer_id: &str,
    received_at_unix: u64,
    expires_at_unix: u64,
    observer_secret_key: &[u8; 32],
) -> Result<SignedPolicyLifecycleLogGossipReceipt, String> {
    validate_policy_lifecycle_log_anchor_proof(anchor)?;
    validate_slug(observer_id, "policy lifecycle gossip observer id")?;
    let head = &anchor.tree_head;
    verify_policy_lifecycle_public_log_tree_head(head, trusted_log_id, trusted_log_public_key)?;
    validate_receipt_window(head, received_at_unix, expires_at_unix)?;
    let signing_key = SigningKey::from_bytes(observer_secret_key);
    let observer_public_key = signing_key.verifying_key().to_bytes();
    if &observer_public_key == trusted_log_public_key {
        return Err(
            "policy lifecycle gossip observer key must be independent from the log key".into(),
        );
    }
    let tree_head_sha256 = policy_lifecycle_public_log_tree_head_sha256(head)?;
    let payload = gossip_receipt_payload(
        observer_id,
        &tree_head_sha256,
        head,
        received_at_unix,
        expires_at_unix,
    )?;
    Ok(SignedPolicyLifecycleLogGossipReceipt {
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
pub fn verify_policy_lifecycle_log_gossip_receipt(
    local_anchor: &PolicyLifecycleLogAnchorProof,
    receipt: &SignedPolicyLifecycleLogGossipReceipt,
    consistency_proof: Option<&PolicyLifecycleLogConsistencyProof>,
    trusted_log_id: &str,
    trusted_log_public_key: &[u8; 32],
    trusted_observer_id: &str,
    trusted_observer_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<PolicyLifecycleLogGossipVerificationReport, String> {
    validate_policy_lifecycle_log_anchor_proof(local_anchor)?;
    validate_policy_lifecycle_log_gossip_receipt(receipt)?;
    validate_slug(
        trusted_observer_id,
        "trusted policy lifecycle gossip observer id",
    )?;
    if receipt.observer_id != trusted_observer_id {
        return Err(
            "policy lifecycle gossip observer id does not match the trusted observer".into(),
        );
    }
    if trusted_observer_public_key == trusted_log_public_key {
        return Err(
            "policy lifecycle gossip observer key must be independent from the log key".into(),
        );
    }
    let local_head = &local_anchor.tree_head;
    let observed_head = &receipt.tree_head;
    verify_policy_lifecycle_public_log_tree_head(
        local_head,
        trusted_log_id,
        trusted_log_public_key,
    )?;
    verify_policy_lifecycle_public_log_tree_head(
        observed_head,
        trusted_log_id,
        trusted_log_public_key,
    )?;
    validate_receipt_window(
        observed_head,
        receipt.received_at_unix,
        receipt.expires_at_unix,
    )?;
    if evaluated_at_unix < receipt.received_at_unix {
        return Err("policy lifecycle gossip receipt is not valid yet".into());
    }
    if evaluated_at_unix > receipt.expires_at_unix {
        return Err("policy lifecycle gossip receipt has expired".into());
    }
    let tree_head_sha256 = policy_lifecycle_public_log_tree_head_sha256(observed_head)?;
    if receipt.tree_head_sha256 != tree_head_sha256 {
        return Err("policy lifecycle gossip receipt tree-head digest does not match".into());
    }
    let observer_public_key = hex_decode::<32>(
        &receipt.observer_public_key,
        "policy lifecycle gossip observer public key",
    )?;
    if &observer_public_key != trusted_observer_public_key {
        return Err(
            "policy lifecycle gossip observer key does not match the trusted public key".into(),
        );
    }
    let signature = hex_decode::<64>(
        &receipt.signature,
        "policy lifecycle gossip receipt signature",
    )?;
    let payload = gossip_receipt_payload(
        &receipt.observer_id,
        &receipt.tree_head_sha256,
        observed_head,
        receipt.received_at_unix,
        receipt.expires_at_unix,
    )?;
    VerifyingKey::from_bytes(&observer_public_key)
        .map_err(|error| format!("invalid policy lifecycle gossip observer key: {error}"))?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|error| format!("invalid policy lifecycle gossip receipt signature: {error}"))?;

    let local_tree_head_sha256 = policy_lifecycle_public_log_tree_head_sha256(local_head)?;
    let same_tree = local_head.tree_size == observed_head.tree_size
        && local_head.root_sha256 == observed_head.root_sha256;
    let (relationship, consistency_proof_sha256) = if same_tree {
        if consistency_proof.is_some() {
            return Err(
                "policy lifecycle gossip consistency proof is redundant for an identical tree head"
                    .into(),
            );
        }
        ("same_tree".to_string(), None)
    } else {
        if local_head.tree_size == observed_head.tree_size {
            return Err(
                "policy lifecycle public log presented split-view roots at one tree size".into(),
            );
        }
        let proof = consistency_proof.ok_or_else(|| {
            "policy lifecycle gossip requires a consistency proof for different tree sizes"
                .to_string()
        })?;
        let (expected_old, expected_new, relationship) =
            if observed_head.tree_size < local_head.tree_size {
                (observed_head, local_head, "observed_precedes_local")
            } else {
                (local_head, observed_head, "local_precedes_observed")
            };
        if &proof.old_tree_head != expected_old || &proof.new_tree_head != expected_new {
            return Err(
                "policy lifecycle gossip consistency proof does not bind the compared tree heads"
                    .into(),
            );
        }
        verify_policy_lifecycle_log_tree_head_consistency(
            proof,
            trusted_log_id,
            trusted_log_public_key,
        )?;
        (
            relationship.to_string(),
            Some(normalized_sha256(
                proof,
                "policy lifecycle consistency proof",
            )?),
        )
    };

    Ok(PolicyLifecycleLogGossipVerificationReport {
        schema_version: 1,
        log_id: trusted_log_id.into(),
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
        gossip_receipt_sha256: normalized_sha256(receipt, "policy lifecycle gossip receipt")?,
        received_at_unix: receipt.received_at_unix,
        expires_at_unix: receipt.expires_at_unix,
        verified_at_unix: evaluated_at_unix,
        split_view_detected: false,
        verified: true,
    })
}

pub fn parse_policy_lifecycle_log_gossip_receipt(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipReceipt, String> {
    let receipt = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy lifecycle gossip receipt JSON: {error}"))?;
    validate_policy_lifecycle_log_gossip_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_policy_lifecycle_log_gossip_receipt(
    receipt: &SignedPolicyLifecycleLogGossipReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1 || receipt.algorithm != "ed25519" {
        return Err("unsupported policy lifecycle gossip receipt".into());
    }
    validate_slug(&receipt.observer_id, "policy lifecycle gossip observer id")?;
    validate_sha256(
        &receipt.tree_head_sha256,
        "policy lifecycle gossip tree-head SHA-256",
    )?;
    policy_lifecycle_public_log_tree_head_sha256(&receipt.tree_head)?;
    validate_receipt_window(
        &receipt.tree_head,
        receipt.received_at_unix,
        receipt.expires_at_unix,
    )?;
    hex_decode::<32>(
        &receipt.observer_public_key,
        "policy lifecycle gossip observer public key",
    )?;
    hex_decode::<64>(
        &receipt.signature,
        "policy lifecycle gossip receipt signature",
    )?;
    Ok(())
}

fn validate_receipt_window(
    head: &SignedPolicyLifecyclePublicLogTreeHead,
    received_at_unix: u64,
    expires_at_unix: u64,
) -> Result<(), String> {
    if received_at_unix < head.observed_at_unix {
        return Err("policy lifecycle gossip receipt predates its observed tree head".into());
    }
    let lifetime = expires_at_unix
        .checked_sub(received_at_unix)
        .ok_or_else(|| {
            "policy lifecycle gossip receipt expiry precedes receipt time".to_string()
        })?;
    if lifetime == 0 || lifetime > MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS {
        return Err(format!(
            "policy lifecycle gossip receipt lifetime must be 1 to {MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS} seconds"
        ));
    }
    Ok(())
}

fn gossip_receipt_payload(
    observer_id: &str,
    tree_head_sha256: &str,
    head: &SignedPolicyLifecyclePublicLogTreeHead,
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
    .map_err(|error| format!("serializing policy lifecycle gossip receipt: {error}"))
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
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
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

pub fn signed_policy_lifecycle_log_gossip_receipt_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-receipt-v1.json",
        "title": "pcbex signed policy lifecycle public-log gossip receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "observer_id", "tree_head_sha256", "tree_head",
            "received_at_unix", "expires_at_unix", "algorithm",
            "observer_public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "observer_id": {
                "type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
            },
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

pub fn policy_lifecycle_log_gossip_verification_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-verification-report-v1.json",
        "title": "pcbex policy lifecycle public-log gossip verification",
        "type": "object",
        "additionalProperties": false,
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
            "consistency_proof_sha256": {
                "oneOf": [digest.clone(), {"type": "null"}]
            },
            "observer_id": {
                "type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
            },
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
        "type": "object",
        "additionalProperties": false,
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
    use crate::policy_lifecycle_anchor::{
        create_policy_lifecycle_log_anchor_proof, create_policy_lifecycle_log_consistency_proof,
        policy_lifecycle_signed_checkpoint_sha256,
    };
    use crate::policy_lifecycle_checkpoint::SignedPolicyLifecycleCheckpoint;

    fn checkpoint(marker: u8) -> SignedPolicyLifecycleCheckpoint {
        SignedPolicyLifecycleCheckpoint {
            schema_version: 1,
            policy_pack_id: "organization".into(),
            generation: 1,
            entry_count: 1,
            ledger_sha256: format!("{marker:064x}"),
            head_sha256: format!("{:064x}", marker + 1),
            issued_at_unix: 10,
            signer_id: "lifecycle-root".into(),
            algorithm: "ed25519".into(),
            public_key: format!("{:064x}", marker + 2),
            signature: format!("{:0128x}", marker + 3),
        }
    }

    fn anchors() -> (
        PolicyLifecycleLogAnchorProof,
        PolicyLifecycleLogAnchorProof,
        PolicyLifecycleLogConsistencyProof,
    ) {
        let checkpoints = [checkpoint(1), checkpoint(2), checkpoint(3)];
        let digests = checkpoints
            .iter()
            .map(policy_lifecycle_signed_checkpoint_sha256)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let old = create_policy_lifecycle_log_anchor_proof(
            &checkpoints[0],
            &digests[..2],
            0,
            "lifecycle-log",
            20,
            &[9; 32],
        )
        .unwrap();
        let current = create_policy_lifecycle_log_anchor_proof(
            &checkpoints[0],
            &digests,
            0,
            "lifecycle-log",
            30,
            &[9; 32],
        )
        .unwrap();
        let consistency =
            create_policy_lifecycle_log_consistency_proof(&old, &current, &digests).unwrap();
        (old, current, consistency)
    }

    #[test]
    fn verifies_same_and_consistent_cross_consumer_observations() {
        let (old, current, consistency) = anchors();
        let log_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let observer_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let same = sign_policy_lifecycle_log_gossip_receipt(
            &current,
            "lifecycle-log",
            &log_key,
            "observer-a",
            31,
            100,
            &[8; 32],
        )
        .unwrap();
        let report = verify_policy_lifecycle_log_gossip_receipt(
            &current,
            &same,
            None,
            "lifecycle-log",
            &log_key,
            "observer-a",
            &observer_key,
            50,
        )
        .unwrap();
        assert_eq!(report.relationship, "same_tree");
        assert!(report.consistency_proof_sha256.is_none());

        let older = sign_policy_lifecycle_log_gossip_receipt(
            &old,
            "lifecycle-log",
            &log_key,
            "observer-a",
            21,
            100,
            &[8; 32],
        )
        .unwrap();
        assert!(
            verify_policy_lifecycle_log_gossip_receipt(
                &current,
                &older,
                None,
                "lifecycle-log",
                &log_key,
                "observer-a",
                &observer_key,
                50,
            )
            .is_err()
        );
        let report = verify_policy_lifecycle_log_gossip_receipt(
            &current,
            &older,
            Some(&consistency),
            "lifecycle-log",
            &log_key,
            "observer-a",
            &observer_key,
            50,
        )
        .unwrap();
        assert_eq!(report.relationship, "observed_precedes_local");
        assert!(report.consistency_proof_sha256.is_some());

        let report = verify_policy_lifecycle_log_gossip_receipt(
            &old,
            &same,
            Some(&consistency),
            "lifecycle-log",
            &log_key,
            "observer-a",
            &observer_key,
            50,
        )
        .unwrap();
        assert_eq!(report.relationship, "local_precedes_observed");
        assert!(
            verify_policy_lifecycle_log_gossip_receipt(
                &current,
                &same,
                Some(&consistency),
                "lifecycle-log",
                &log_key,
                "observer-a",
                &observer_key,
                50,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_split_views_tampering_expiry_and_trust_substitution() {
        let (_, current, _) = anchors();
        let log_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let observer_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let receipt = sign_policy_lifecycle_log_gossip_receipt(
            &current,
            "lifecycle-log",
            &log_key,
            "observer-a",
            31,
            100,
            &[8; 32],
        )
        .unwrap();
        assert!(
            sign_policy_lifecycle_log_gossip_receipt(
                &current,
                "lifecycle-log",
                &log_key,
                "observer-a",
                31,
                100,
                &[9; 32],
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_receipt(
                &current,
                "lifecycle-log",
                &log_key,
                "observer-a",
                31,
                31 + MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS + 1,
                &[8; 32],
            )
            .is_err()
        );

        let split_checkpoints = [checkpoint(1), checkpoint(2), checkpoint(4)];
        let split_digests = split_checkpoints
            .iter()
            .map(policy_lifecycle_signed_checkpoint_sha256)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let split_anchor = create_policy_lifecycle_log_anchor_proof(
            &split_checkpoints[0],
            &split_digests,
            0,
            "lifecycle-log",
            30,
            &[9; 32],
        )
        .unwrap();
        assert!(
            verify_policy_lifecycle_log_gossip_receipt(
                &split_anchor,
                &receipt,
                None,
                "lifecycle-log",
                &log_key,
                "observer-a",
                &observer_key,
                50,
            )
            .is_err()
        );

        let mut tampered = receipt.clone();
        tampered.tree_head_sha256 = "0".repeat(64);
        assert!(
            verify_policy_lifecycle_log_gossip_receipt(
                &current,
                &tampered,
                None,
                "lifecycle-log",
                &log_key,
                "observer-a",
                &observer_key,
                50,
            )
            .is_err()
        );
        for (observer_id, key, time) in [
            ("observer-b", observer_key, 50),
            ("observer-a", [7; 32], 50),
            ("observer-a", observer_key, 101),
            ("observer-a", observer_key, 30),
        ] {
            assert!(
                verify_policy_lifecycle_log_gossip_receipt(
                    &current,
                    &receipt,
                    None,
                    "lifecycle-log",
                    &log_key,
                    observer_id,
                    &key,
                    time,
                )
                .is_err()
            );
        }

        let mut invalid_signature = receipt;
        invalid_signature.signature = "0".repeat(128);
        assert!(
            verify_policy_lifecycle_log_gossip_receipt(
                &current,
                &invalid_signature,
                None,
                "lifecycle-log",
                &log_key,
                "observer-a",
                &observer_key,
                50,
            )
            .is_err()
        );
    }

    #[test]
    fn schemas_are_closed() {
        let receipt = signed_policy_lifecycle_log_gossip_receipt_json_schema();
        assert_eq!(receipt["additionalProperties"], false);
        assert_eq!(
            receipt["properties"]["tree_head"]["additionalProperties"],
            false
        );
        assert_eq!(
            policy_lifecycle_log_gossip_verification_report_json_schema()["additionalProperties"],
            false
        );
    }
}

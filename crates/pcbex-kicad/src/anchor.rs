use crate::{SignedApprovalLogCheckpoint, signed_approval_log_checkpoint_sha256};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const TREE_HEAD_DOMAIN: &str = "pcbex-approval-public-log-tree-head-v1";
const LEAF_DOMAIN: &[u8] = b"pcbex-approval-public-log-leaf-v1";
const MAX_ANCHOR_LEAVES: usize = 100_000;
const MAX_AUDIT_PATH: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalPublicLogTreeHead {
    pub schema_version: u32,
    pub log_id: String,
    pub tree_size: u64,
    pub root_sha256: String,
    pub observed_at_unix: u64,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogAnchorProof {
    pub schema_version: u32,
    pub checkpoint_sha256: String,
    pub leaf_index: u64,
    pub audit_path: Vec<String>,
    pub tree_head: SignedApprovalPublicLogTreeHead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogAnchorVerificationReport {
    pub schema_version: u32,
    pub checkpoint_sha256: String,
    pub log_id: String,
    pub leaf_index: u64,
    pub tree_size: u64,
    pub root_sha256: String,
    pub tree_head_public_key: String,
    pub anchored: bool,
}

#[derive(Serialize)]
struct TreeHeadPayload<'a> {
    domain: &'static str,
    log_id: &'a str,
    tree_size: u64,
    root_sha256: &'a str,
    observed_at_unix: u64,
}

pub fn create_approval_log_anchor_proof(
    checkpoint: &SignedApprovalLogCheckpoint,
    ordered_checkpoint_sha256: &[String],
    leaf_index: u64,
    log_id: &str,
    observed_at_unix: u64,
    secret_key: &[u8; 32],
) -> Result<ApprovalLogAnchorProof, String> {
    validate_slug(log_id, "approval public-log id")?;
    if ordered_checkpoint_sha256.is_empty() || ordered_checkpoint_sha256.len() > MAX_ANCHOR_LEAVES {
        return Err(format!(
            "approval public log must contain 1 to {MAX_ANCHOR_LEAVES} leaves"
        ));
    }
    let index = usize::try_from(leaf_index)
        .map_err(|_| "approval anchor leaf index is too large".to_string())?;
    if index >= ordered_checkpoint_sha256.len() {
        return Err("approval anchor leaf index is outside the tree".into());
    }
    for digest in ordered_checkpoint_sha256 {
        validate_sha256(digest, "approval public-log checkpoint SHA-256")?;
    }
    let checkpoint_sha256 = signed_approval_log_checkpoint_sha256(checkpoint)?;
    if ordered_checkpoint_sha256[index] != checkpoint_sha256 {
        return Err("approval anchor leaf does not match the supplied checkpoint".into());
    }
    let leaves = ordered_checkpoint_sha256
        .iter()
        .map(|digest| leaf_hash(digest))
        .collect::<Result<Vec<_>, _>>()?;
    let root = merkle_root(&leaves);
    let audit_path = merkle_audit_path(&leaves, index)?
        .into_iter()
        .map(|digest| hex_encode(&digest))
        .collect();
    let root_sha256 = hex_encode(&root);
    let payload = tree_head_payload(log_id, leaves.len() as u64, &root_sha256, observed_at_unix)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let tree_head = SignedApprovalPublicLogTreeHead {
        schema_version: 1,
        log_id: log_id.into(),
        tree_size: leaves.len() as u64,
        root_sha256,
        observed_at_unix,
        algorithm: "ed25519".into(),
        public_key: hex_encode(&signing_key.verifying_key().to_bytes()),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    Ok(ApprovalLogAnchorProof {
        schema_version: 1,
        checkpoint_sha256,
        leaf_index,
        audit_path,
        tree_head,
    })
}

pub fn verify_approval_log_anchor_proof(
    checkpoint: &SignedApprovalLogCheckpoint,
    proof: &ApprovalLogAnchorProof,
    trusted_public_key: &[u8; 32],
) -> Result<ApprovalLogAnchorVerificationReport, String> {
    if proof.schema_version != 1 {
        return Err("unsupported approval-log anchor proof".into());
    }
    let checkpoint_sha256 = signed_approval_log_checkpoint_sha256(checkpoint)?;
    if proof.checkpoint_sha256 != checkpoint_sha256 {
        return Err("approval-log anchor proof is bound to a different checkpoint".into());
    }
    let head = &proof.tree_head;
    if head.schema_version != 1 || head.algorithm != "ed25519" {
        return Err("unsupported approval public-log tree head".into());
    }
    validate_slug(&head.log_id, "approval public-log id")?;
    validate_sha256(&head.root_sha256, "approval public-log root SHA-256")?;
    if head.tree_size == 0 || proof.leaf_index >= head.tree_size {
        return Err("approval anchor leaf index is outside the tree".into());
    }
    if proof.audit_path.len() > MAX_AUDIT_PATH {
        return Err(format!(
            "approval anchor audit path cannot exceed {MAX_AUDIT_PATH} nodes"
        ));
    }
    let path = proof
        .audit_path
        .iter()
        .map(|digest| hex_decode::<32>(digest, "approval anchor audit node"))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = leaf_hash(&checkpoint_sha256)?;
    let mut cursor = 0;
    let reconstructed =
        root_from_audit_path(leaf, proof.leaf_index, head.tree_size, &path, &mut cursor)?;
    if cursor != path.len() || hex_encode(&reconstructed) != head.root_sha256 {
        return Err("approval anchor audit path does not reconstruct the signed root".into());
    }
    let public_key = hex_decode::<32>(&head.public_key, "approval public-log public key")?;
    if &public_key != trusted_public_key {
        return Err("approval public-log key does not match the trusted public key".into());
    }
    let signature = hex_decode::<64>(&head.signature, "approval public-log signature")?;
    let payload = tree_head_payload(
        &head.log_id,
        head.tree_size,
        &head.root_sha256,
        head.observed_at_unix,
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid approval public-log public key: {error}"))?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|error| format!("invalid approval public-log signature: {error}"))?;
    Ok(ApprovalLogAnchorVerificationReport {
        schema_version: 1,
        checkpoint_sha256,
        log_id: head.log_id.clone(),
        leaf_index: proof.leaf_index,
        tree_size: head.tree_size,
        root_sha256: head.root_sha256.clone(),
        tree_head_public_key: head.public_key.clone(),
        anchored: true,
    })
}

fn leaf_hash(checkpoint_sha256: &str) -> Result<[u8; 32], String> {
    validate_sha256(checkpoint_sha256, "approval public-log checkpoint SHA-256")?;
    let digest = hex_decode::<32>(checkpoint_sha256, "approval public-log checkpoint SHA-256")?;
    let mut input = Vec::with_capacity(1 + LEAF_DOMAIN.len() + digest.len());
    input.push(0);
    input.extend_from_slice(LEAF_DOMAIN);
    input.extend_from_slice(&digest);
    Ok(Sha256::digest(input).into())
}

fn node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(65);
    input.push(1);
    input.extend_from_slice(&left);
    input.extend_from_slice(&right);
    Sha256::digest(input).into()
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let split = largest_power_of_two_less_than(leaves.len());
    node_hash(merkle_root(&leaves[..split]), merkle_root(&leaves[split..]))
}

fn merkle_audit_path(leaves: &[[u8; 32]], index: usize) -> Result<Vec<[u8; 32]>, String> {
    if leaves.len() == 1 {
        return Ok(Vec::new());
    }
    let split = largest_power_of_two_less_than(leaves.len());
    if index < split {
        let mut path = merkle_audit_path(&leaves[..split], index)?;
        path.push(merkle_root(&leaves[split..]));
        Ok(path)
    } else {
        let mut path = merkle_audit_path(&leaves[split..], index - split)?;
        path.push(merkle_root(&leaves[..split]));
        Ok(path)
    }
}

fn root_from_audit_path(
    leaf: [u8; 32],
    index: u64,
    size: u64,
    path: &[[u8; 32]],
    cursor: &mut usize,
) -> Result<[u8; 32], String> {
    if size == 1 {
        return Ok(leaf);
    }
    let split = largest_power_of_two_less_than_u64(size);
    if index < split {
        let left = root_from_audit_path(leaf, index, split, path, cursor)?;
        let right = next_audit_node(path, cursor)?;
        Ok(node_hash(left, right))
    } else {
        let right = root_from_audit_path(leaf, index - split, size - split, path, cursor)?;
        let left = next_audit_node(path, cursor)?;
        Ok(node_hash(left, right))
    }
}

fn next_audit_node(path: &[[u8; 32]], cursor: &mut usize) -> Result<[u8; 32], String> {
    let node = path
        .get(*cursor)
        .copied()
        .ok_or_else(|| "approval anchor audit path is incomplete".to_string())?;
    *cursor += 1;
    Ok(node)
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    1_usize << (usize::BITS - (value - 1).leading_zeros() - 1)
}

fn largest_power_of_two_less_than_u64(value: u64) -> u64 {
    1_u64 << (u64::BITS - (value - 1).leading_zeros() - 1)
}

fn tree_head_payload(
    log_id: &str,
    tree_size: u64,
    root_sha256: &str,
    observed_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&TreeHeadPayload {
        domain: TREE_HEAD_DOMAIN,
        log_id,
        tree_size,
        root_sha256,
        observed_at_unix,
    })
    .map_err(|error| format!("serializing approval public-log tree head: {error}"))
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
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("decoding {label}: {error}"))?;
    }
    Ok(bytes)
}

pub fn approval_log_anchor_proof_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/approval-log-anchor-proof-v1.json",
        "title": "pcbex approval-log public anchor proof",
        "type": "object", "additionalProperties": false,
        "required": ["schema_version", "checkpoint_sha256", "leaf_index", "audit_path", "tree_head"],
        "properties": {
            "schema_version": {"const": 1},
            "checkpoint_sha256": digest.clone(),
            "leaf_index": {"type": "integer", "minimum": 0},
            "audit_path": {
                "type": "array", "maxItems": MAX_AUDIT_PATH,
                "items": digest.clone()
            },
            "tree_head": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "schema_version", "log_id", "tree_size", "root_sha256",
                    "observed_at_unix", "algorithm", "public_key", "signature"
                ],
                "properties": {
                    "schema_version": {"const": 1},
                    "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "tree_size": {"type": "integer", "minimum": 1},
                    "root_sha256": digest,
                    "observed_at_unix": {"type": "integer", "minimum": 0},
                    "algorithm": {"const": "ed25519"},
                    "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
                }
            }
        }
    })
}

pub fn approval_log_anchor_verification_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/approval-log-anchor-verification-report-v1.json",
        "title": "pcbex approval-log public anchor verification report",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "checkpoint_sha256", "log_id", "leaf_index",
            "tree_size", "root_sha256", "tree_head_public_key", "anchored"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "checkpoint_sha256": digest.clone(),
            "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "leaf_index": {"type": "integer", "minimum": 0},
            "tree_size": {"type": "integer", "minimum": 1},
            "root_sha256": digest,
            "tree_head_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "anchored": {"const": true}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{new_approval_transparency_log, sign_approval_log_checkpoint};

    #[test]
    fn verifies_merkle_inclusion_and_rejects_tampering() {
        let log = new_approval_transparency_log("approvals").unwrap();
        let checkpoints = (1_u8..=5)
            .map(|secret| sign_approval_log_checkpoint(&log, "origin", &[secret; 32]).unwrap())
            .collect::<Vec<_>>();
        let digests = checkpoints
            .iter()
            .map(signed_approval_log_checkpoint_sha256)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let proof = create_approval_log_anchor_proof(
            &checkpoints[3],
            &digests,
            3,
            "public-log",
            100,
            &[9; 32],
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let report = verify_approval_log_anchor_proof(&checkpoints[3], &proof, &key).unwrap();
        assert!(report.anchored);
        assert_eq!(report.tree_size, 5);

        let mut tampered = proof.clone();
        tampered.audit_path[0] = "0".repeat(64);
        assert!(verify_approval_log_anchor_proof(&checkpoints[3], &tampered, &key).is_err());

        let mut wrong_index = proof.clone();
        wrong_index.leaf_index = 2;
        assert!(verify_approval_log_anchor_proof(&checkpoints[3], &wrong_index, &key).is_err());

        let mut wrong_root = proof.clone();
        wrong_root.tree_head.root_sha256 = "0".repeat(64);
        assert!(verify_approval_log_anchor_proof(&checkpoints[3], &wrong_root, &key).is_err());

        let mut wrong_signature = proof.clone();
        wrong_signature.tree_head.signature = "0".repeat(128);
        assert!(verify_approval_log_anchor_proof(&checkpoints[3], &wrong_signature, &key).is_err());

        let mut extra_node = proof.clone();
        extra_node.audit_path.push("0".repeat(64));
        assert!(verify_approval_log_anchor_proof(&checkpoints[3], &extra_node, &key).is_err());

        assert!(verify_approval_log_anchor_proof(&checkpoints[2], &proof, &key).is_err());
        assert!(verify_approval_log_anchor_proof(&checkpoints[3], &proof, &[8; 32]).is_err());
    }

    #[test]
    fn schemas_are_closed() {
        let proof = approval_log_anchor_proof_json_schema();
        assert_eq!(proof["additionalProperties"], false);
        assert_eq!(
            proof["properties"]["tree_head"]["additionalProperties"],
            false
        );
        assert_eq!(
            approval_log_anchor_verification_report_json_schema()["additionalProperties"],
            false
        );
    }
}

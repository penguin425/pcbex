use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CHECKPOINT_DOMAIN: &str = "pcbex-approval-transparency-checkpoint-v1";
const MAX_LOG_ENTRIES: usize = 100_000;
const MAX_TEXT_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalArtifactKind {
    SignedAiApproval,
    AiQuorumReport,
    SignedHumanEscalation,
    HumanEscalationReport,
    SignedPolicyPack,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEventDescriptor {
    pub artifact_kind: ApprovalArtifactKind,
    pub artifact_sha256: String,
    pub subject_id: String,
    pub request_sha256: Option<String>,
    pub session_sha256: Option<String>,
    pub signer_id: Option<String>,
    pub outcome: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTransparencyEntry {
    pub schema_version: u32,
    pub sequence: u64,
    pub previous_entry_sha256: Option<String>,
    pub recorded_at_unix: u64,
    pub event: ApprovalEventDescriptor,
    pub entry_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTransparencyLog {
    pub schema_version: u32,
    pub log_id: String,
    pub entries: Vec<ApprovalTransparencyEntry>,
    pub head_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalLogCheckpoint {
    pub schema_version: u32,
    pub log_id: String,
    pub entry_count: u64,
    pub head_sha256: Option<String>,
    pub log_sha256: String,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogVerificationReport {
    pub schema_version: u32,
    pub log_id: String,
    pub entry_count: u64,
    pub head_sha256: Option<String>,
    pub log_sha256: String,
    pub checkpoint_signer_id: String,
    pub checkpoint_public_key: String,
    pub verified: bool,
}

#[derive(Serialize)]
struct CheckpointPayload<'a> {
    domain: &'static str,
    log_id: &'a str,
    entry_count: u64,
    head_sha256: Option<&'a str>,
    log_sha256: &'a str,
    signer_id: &'a str,
}

pub fn new_approval_transparency_log(log_id: &str) -> Result<ApprovalTransparencyLog, String> {
    validate_slug(log_id, "approval transparency log id")?;
    Ok(ApprovalTransparencyLog {
        schema_version: 1,
        log_id: log_id.into(),
        entries: Vec::new(),
        head_sha256: None,
    })
}

pub fn append_approval_transparency_event(
    log: &mut ApprovalTransparencyLog,
    event: ApprovalEventDescriptor,
    recorded_at_unix: u64,
) -> Result<String, String> {
    approval_transparency_log_sha256(log)?;
    validate_event(&event)?;
    if log.entries.len() >= MAX_LOG_ENTRIES {
        return Err(format!(
            "approval transparency log cannot exceed {MAX_LOG_ENTRIES} entries"
        ));
    }
    if log
        .entries
        .last()
        .is_some_and(|entry| recorded_at_unix < entry.recorded_at_unix)
    {
        return Err("approval transparency log timestamps must be monotonic".into());
    }
    let mut entry = ApprovalTransparencyEntry {
        schema_version: 1,
        sequence: log.entries.len() as u64,
        previous_entry_sha256: log.head_sha256.clone(),
        recorded_at_unix,
        event,
        entry_sha256: String::new(),
    };
    entry.entry_sha256 = entry_body_sha256(&entry)?;
    let digest = entry.entry_sha256.clone();
    log.entries.push(entry);
    log.head_sha256 = Some(digest.clone());
    Ok(digest)
}

pub fn approval_transparency_log_sha256(log: &ApprovalTransparencyLog) -> Result<String, String> {
    if log.schema_version != 1 {
        return Err(format!(
            "unsupported approval transparency log schema version {}",
            log.schema_version
        ));
    }
    validate_slug(&log.log_id, "approval transparency log id")?;
    if log.entries.len() > MAX_LOG_ENTRIES {
        return Err(format!(
            "approval transparency log cannot exceed {MAX_LOG_ENTRIES} entries"
        ));
    }
    let mut previous: Option<&str> = None;
    let mut previous_time = None;
    for (index, entry) in log.entries.iter().enumerate() {
        if entry.schema_version != 1 || entry.sequence != index as u64 {
            return Err(format!(
                "approval transparency entry {index} has an invalid version or sequence"
            ));
        }
        if entry.previous_entry_sha256.as_deref() != previous {
            return Err(format!(
                "approval transparency entry {index} breaks the hash chain"
            ));
        }
        if previous_time.is_some_and(|time| entry.recorded_at_unix < time) {
            return Err("approval transparency log timestamps are not monotonic".into());
        }
        validate_event(&entry.event)?;
        let expected = entry_body_sha256(entry)?;
        if entry.entry_sha256 != expected {
            return Err(format!(
                "approval transparency entry {index} digest does not match its normalized content"
            ));
        }
        previous = Some(&entry.entry_sha256);
        previous_time = Some(entry.recorded_at_unix);
    }
    if log.head_sha256.as_deref() != previous {
        return Err("approval transparency log head does not match its final entry".into());
    }
    let bytes = serde_json::to_vec(log)
        .map_err(|error| format!("serializing approval transparency log: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn sign_approval_log_checkpoint(
    log: &ApprovalTransparencyLog,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedApprovalLogCheckpoint, String> {
    validate_slug(signer_id, "approval checkpoint signer id")?;
    let log_sha256 = approval_transparency_log_sha256(log)?;
    let entry_count = log.entries.len() as u64;
    let payload = checkpoint_payload(
        &log.log_id,
        entry_count,
        log.head_sha256.as_deref(),
        &log_sha256,
        signer_id,
    )?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let signature = signing_key.sign(&payload).to_bytes();
    Ok(SignedApprovalLogCheckpoint {
        schema_version: 1,
        log_id: log.log_id.clone(),
        entry_count,
        head_sha256: log.head_sha256.clone(),
        log_sha256,
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signature),
    })
}

pub fn verify_approval_log_checkpoint(
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedApprovalLogCheckpoint,
    trusted_public_key: &[u8; 32],
) -> Result<ApprovalLogVerificationReport, String> {
    if checkpoint.schema_version != 1 {
        return Err(format!(
            "unsupported approval checkpoint schema version {}",
            checkpoint.schema_version
        ));
    }
    if checkpoint.algorithm != "ed25519" {
        return Err(format!(
            "unsupported approval checkpoint algorithm {}",
            checkpoint.algorithm
        ));
    }
    validate_slug(&checkpoint.signer_id, "approval checkpoint signer id")?;
    let log_sha256 = approval_transparency_log_sha256(log)?;
    if checkpoint.log_id != log.log_id
        || checkpoint.entry_count != log.entries.len() as u64
        || checkpoint.head_sha256 != log.head_sha256
        || checkpoint.log_sha256 != log_sha256
    {
        return Err("approval checkpoint is bound to a different log state".into());
    }
    let public_key =
        hex_decode_array::<32>(&checkpoint.public_key, "approval checkpoint public key")?;
    if &public_key != trusted_public_key {
        return Err("approval checkpoint key does not match the trusted public key".into());
    }
    let signature = hex_decode_array::<64>(&checkpoint.signature, "approval checkpoint signature")?;
    let payload = checkpoint_payload(
        &checkpoint.log_id,
        checkpoint.entry_count,
        checkpoint.head_sha256.as_deref(),
        &checkpoint.log_sha256,
        &checkpoint.signer_id,
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid approval checkpoint public key: {error}"))?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|error| format!("invalid approval checkpoint signature: {error}"))?;
    Ok(ApprovalLogVerificationReport {
        schema_version: 1,
        log_id: log.log_id.clone(),
        entry_count: checkpoint.entry_count,
        head_sha256: checkpoint.head_sha256.clone(),
        log_sha256,
        checkpoint_signer_id: checkpoint.signer_id.clone(),
        checkpoint_public_key: checkpoint.public_key.clone(),
        verified: true,
    })
}

fn validate_event(event: &ApprovalEventDescriptor) -> Result<(), String> {
    validate_sha256(&event.artifact_sha256, "approval event artifact SHA-256")?;
    validate_text(&event.subject_id, "approval event subject id")?;
    validate_text(&event.outcome, "approval event outcome")?;
    if let Some(value) = &event.request_sha256 {
        validate_sha256(value, "approval event request SHA-256")?;
    }
    if let Some(value) = &event.session_sha256 {
        validate_sha256(value, "approval event session SHA-256")?;
        if event.request_sha256.is_none() {
            return Err("session-bound approval events require a request digest".into());
        }
    }
    if let Some(value) = &event.signer_id {
        validate_slug(value, "approval event signer id")?;
    }
    Ok(())
}

fn entry_body_sha256(entry: &ApprovalTransparencyEntry) -> Result<String, String> {
    let mut body = entry.clone();
    body.entry_sha256.clear();
    let bytes = serde_json::to_vec(&body)
        .map_err(|error| format!("serializing approval transparency entry: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn checkpoint_payload(
    log_id: &str,
    entry_count: u64,
    head_sha256: Option<&str>,
    log_sha256: &str,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&CheckpointPayload {
        domain: CHECKPOINT_DOMAIN,
        log_id,
        entry_count,
        head_sha256,
        log_sha256,
        signer_id,
    })
    .map_err(|error| format!("serializing approval checkpoint payload: {error}"))
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(format!("{label} must be 64 lowercase hexadecimal digits"))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES {
        Err(format!("{label} must contain 1 to {MAX_TEXT_BYTES} bytes"))
    } else {
        Ok(())
    }
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
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

pub fn approval_transparency_log_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let nullable_digest = json!({"anyOf": [digest.clone(), {"type": "null"}]});
    let nullable_text = json!({
        "anyOf": [{"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES}, {"type": "null"}]
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/approval-transparency-log-v1.json",
        "title": "pcbex approval transparency log",
        "type": "object", "additionalProperties": false,
        "required": ["schema_version", "log_id", "entries", "head_sha256"],
        "properties": {
            "schema_version": {"const": 1},
            "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "entries": {
                "type": "array", "maxItems": MAX_LOG_ENTRIES,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "schema_version", "sequence", "previous_entry_sha256",
                        "recorded_at_unix", "event", "entry_sha256"
                    ],
                    "properties": {
                        "schema_version": {"const": 1},
                        "sequence": {"type": "integer", "minimum": 0},
                        "previous_entry_sha256": nullable_digest,
                        "recorded_at_unix": {"type": "integer", "minimum": 0},
                        "event": {
                            "type": "object", "additionalProperties": false,
                            "required": [
                                "artifact_kind", "artifact_sha256", "subject_id",
                                "request_sha256", "session_sha256", "signer_id", "outcome"
                            ],
                            "properties": {
                                "artifact_kind": {"enum": [
                                    "signed_ai_approval", "ai_quorum_report",
                                    "signed_human_escalation", "human_escalation_report",
                                    "signed_policy_pack"
                                ]},
                                "artifact_sha256": digest,
                                "subject_id": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                                "request_sha256": nullable_digest,
                                "session_sha256": nullable_digest,
                                "signer_id": nullable_text,
                                "outcome": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES}
                            }
                        },
                        "entry_sha256": digest
                    }
                }
            },
            "head_sha256": nullable_digest
        }
    })
}

pub fn signed_approval_log_checkpoint_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/signed-approval-log-checkpoint-v1.json",
        "title": "pcbex signed approval-log checkpoint",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "log_id", "entry_count", "head_sha256", "log_sha256",
            "signer_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "entry_count": {"type": "integer", "minimum": 0},
            "head_sha256": {"anyOf": [digest.clone(), {"type": "null"}]},
            "log_sha256": digest,
            "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn approval_log_verification_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/approval-log-verification-report-v1.json",
        "title": "pcbex approval-log verification report",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "log_id", "entry_count", "head_sha256", "log_sha256",
            "checkpoint_signer_id", "checkpoint_public_key", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "entry_count": {"type": "integer", "minimum": 0},
            "head_sha256": {"anyOf": [digest.clone(), {"type": "null"}]},
            "log_sha256": digest,
            "checkpoint_signer_id": {"type": "string", "minLength": 1},
            "checkpoint_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "verified": {"const": true}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(digest: char, outcome: &str) -> ApprovalEventDescriptor {
        ApprovalEventDescriptor {
            artifact_kind: ApprovalArtifactKind::SignedAiApproval,
            artifact_sha256: digest.to_string().repeat(64),
            subject_id: "request".into(),
            request_sha256: Some("f".repeat(64)),
            session_sha256: None,
            signer_id: Some("reviewer-a".into()),
            outcome: outcome.into(),
        }
    }

    #[test]
    fn chains_events_and_verifies_a_signed_checkpoint() {
        let mut log = new_approval_transparency_log("production-approvals").unwrap();
        let first =
            append_approval_transparency_event(&mut log, event('a', "approved"), 100).unwrap();
        let second =
            append_approval_transparency_event(&mut log, event('b', "rejected"), 101).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            log.entries[1].previous_entry_sha256.as_deref(),
            Some(first.as_str())
        );
        let checkpoint = sign_approval_log_checkpoint(&log, "security-log", &[7; 32]).unwrap();
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let report = verify_approval_log_checkpoint(&log, &checkpoint, &key).unwrap();
        assert!(report.verified);
        assert_eq!(report.entry_count, 2);
    }

    #[test]
    fn rejects_tampering_truncation_stale_checkpoints_and_time_reversal() {
        let mut log = new_approval_transparency_log("production-approvals").unwrap();
        append_approval_transparency_event(&mut log, event('a', "approved"), 100).unwrap();
        let checkpoint = sign_approval_log_checkpoint(&log, "security-log", &[8; 32]).unwrap();
        append_approval_transparency_event(&mut log, event('b', "approved"), 101).unwrap();
        let key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert!(verify_approval_log_checkpoint(&log, &checkpoint, &key).is_err());
        assert!(append_approval_transparency_event(&mut log, event('c', "approved"), 99).is_err());

        let mut tampered = log.clone();
        tampered.entries[0].event.outcome = "rejected".into();
        assert!(approval_transparency_log_sha256(&tampered).is_err());

        let mut truncated = log;
        truncated.entries.pop();
        assert!(approval_transparency_log_sha256(&truncated).is_err());
    }

    #[test]
    fn schemas_close_every_object() {
        let log = approval_transparency_log_json_schema();
        assert_eq!(log["additionalProperties"], false);
        assert_eq!(
            log["properties"]["entries"]["items"]["properties"]["event"]["additionalProperties"],
            false
        );
        assert_eq!(
            signed_approval_log_checkpoint_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            approval_log_verification_report_json_schema()["additionalProperties"],
            false
        );
    }
}

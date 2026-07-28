use super::{AiReviewRequest, ai_review_request_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_AI_REVIEW_SESSION_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiReviewSession {
    pub schema_version: u32,
    pub session_sha256: String,
    pub request_sha256: String,
    pub challenge: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

pub fn build_ai_review_session(
    request: &AiReviewRequest,
    challenge: &str,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> Result<AiReviewSession, String> {
    let mut session = AiReviewSession {
        schema_version: 1,
        session_sha256: String::new(),
        request_sha256: ai_review_request_sha256(request)?,
        challenge: challenge.into(),
        issued_at_unix,
        expires_at_unix,
    };
    validate_session_contents(&session)?;
    session.session_sha256 = session_body_sha256(&session)?;
    Ok(session)
}

pub fn ai_review_session_sha256(
    session: &AiReviewSession,
    request: &AiReviewRequest,
) -> Result<String, String> {
    if session.schema_version != 1 {
        return Err(format!(
            "unsupported AI review session schema version {}",
            session.schema_version
        ));
    }
    validate_session_contents(session)?;
    let request_sha256 = ai_review_request_sha256(request)?;
    if session.request_sha256 != request_sha256 {
        return Err("AI review session is bound to a different request".into());
    }
    let expected = session_body_sha256(session)?;
    if session.session_sha256 != expected {
        return Err("AI review session SHA-256 does not match its normalized content".into());
    }
    Ok(expected)
}

pub fn validate_ai_review_session(
    session: &AiReviewSession,
    request: &AiReviewRequest,
    evaluated_at_unix: u64,
) -> Result<String, String> {
    let digest = ai_review_session_sha256(session, request)?;
    if evaluated_at_unix < session.issued_at_unix {
        return Err("AI review session is not active yet".into());
    }
    if evaluated_at_unix > session.expires_at_unix {
        return Err("AI review session has expired".into());
    }
    Ok(digest)
}

fn validate_session_contents(session: &AiReviewSession) -> Result<(), String> {
    validate_sha256(&session.request_sha256, "AI review session request SHA-256")?;
    validate_hex(&session.challenge, 64, "AI review session challenge")?;
    if session.expires_at_unix <= session.issued_at_unix {
        return Err("AI review session expiration must be after issuance".into());
    }
    if session.expires_at_unix - session.issued_at_unix > MAX_AI_REVIEW_SESSION_SECONDS {
        return Err(format!(
            "AI review session lifetime cannot exceed {MAX_AI_REVIEW_SESSION_SECONDS} seconds"
        ));
    }
    Ok(())
}

fn session_body_sha256(session: &AiReviewSession) -> Result<String, String> {
    let mut body = session.clone();
    body.session_sha256.clear();
    let bytes = serde_json::to_vec(&body)
        .map_err(|error| format!("serializing AI review session: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    validate_hex(value, 64, label)
}

fn validate_hex(value: &str, length: usize, label: &str) -> Result<(), String> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(format!(
            "{label} must be {length} lowercase hexadecimal digits"
        ))
    } else {
        Ok(())
    }
}

pub fn ai_review_session_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/ai-review-session-v1.json",
        "title": "pcbex time-bound AI schematic review session",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "session_sha256", "request_sha256", "challenge",
            "issued_at_unix", "expires_at_unix"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "session_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "challenge": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "issued_at_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 1}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AiRequirement, ElectricalPolicy, ElectricalRulePolicy, ElectricalSeverity,
        build_ai_review_request, check_schematic, import_schematic,
    };
    use std::collections::BTreeMap;

    fn request() -> AiReviewRequest {
        let schematic =
            import_schematic(include_str!("../../../examples/simple.kicad_sch")).unwrap();
        let mut policy = ElectricalPolicy::default();
        policy.rules = policy
            .rules
            .into_iter()
            .map(|(id, mut setting)| {
                if setting.severity == ElectricalSeverity::Error {
                    setting.enabled = false;
                }
                (id, setting)
            })
            .collect::<BTreeMap<String, ElectricalRulePolicy>>();
        let review = check_schematic(&schematic, &policy).unwrap();
        build_ai_review_request(
            schematic,
            &policy,
            review,
            "a".repeat(64),
            Vec::new(),
            vec![AiRequirement {
                id: "intent".into(),
                text: "The circuit intent is satisfied".into(),
            }],
            false,
        )
        .unwrap()
    }

    #[test]
    fn validates_only_during_the_bound_window() {
        let request = request();
        let session = build_ai_review_session(&request, &"b".repeat(64), 1_000, 2_000).unwrap();
        assert!(validate_ai_review_session(&session, &request, 1_000).is_ok());
        assert!(validate_ai_review_session(&session, &request, 2_000).is_ok());
        assert!(validate_ai_review_session(&session, &request, 999).is_err());
        assert!(validate_ai_review_session(&session, &request, 2_001).is_err());
        let mut tampered = session.clone();
        tampered.expires_at_unix -= 1;
        assert!(validate_ai_review_session(&tampered, &request, 1_500).is_err());
    }

    #[test]
    fn rejects_excessive_lifetimes_and_invalid_challenges() {
        let request = request();
        assert!(
            build_ai_review_session(
                &request,
                &"c".repeat(64),
                1,
                MAX_AI_REVIEW_SESSION_SECONDS + 2,
            )
            .is_err()
        );
        assert!(build_ai_review_session(&request, "predictable", 1, 2).is_err());
    }

    #[test]
    fn schema_is_closed() {
        assert_eq!(
            ai_review_session_json_schema()["additionalProperties"],
            false
        );
    }
}

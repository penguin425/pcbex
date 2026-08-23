//! Closed markers for local at-most-once admission of one authenticated release.
//!
//! The marker proves only that one descriptor-pinned local ledger accepted the
//! signed receipt challenge. It does not reserve factory capacity, submit an
//! order, perform payment, or make the challenge globally unique.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCHEMA_VERSION: u32 = 1;
pub(crate) const SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE: &str =
    "pinned-local-signed-factory-receipt-release-ledger-at-most-once-v1";
const SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_STATUS: &str = "local_reservation_committed";
const SIGNED_FACTORY_RECEIPT_RELEASE_STATUS: &str = "release_authenticated";
const MAXIMUM_TIMESTAMP: u64 = 9_223_372_036_854_775_807;

pub(crate) const MAX_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES: u64 = 16 * 1024;
pub(crate) const SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_LEDGER_MANIFEST_FILENAME: &str =
    ".pcbex-signed-factory-receipt-release-reservation-ledger-v1.json";
pub(crate) const MAX_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_LEDGER_MANIFEST_BYTES: u64 =
    4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReceiptReleaseReservation {
    pub(crate) schema_version: u32,
    pub(crate) reservation_scope: String,
    pub(crate) status: String,
    pub(crate) local_challenge_reserved: bool,
    pub(crate) adapter_network_performed: bool,
    pub(crate) global_challenge_one_time_use_enforced: bool,
    pub(crate) external_submission_performed: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) ledger_id: String,
    pub(crate) release_report_summary: SignedFactoryReceiptReleaseReportSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReceiptReleaseReportSummary {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) release_authenticated: bool,
    pub(crate) executable_pinned_fabrication_release_authorized: bool,
    pub(crate) factory_receipt_attestation_verified: bool,
    pub(crate) factory_receipt_authenticity_verified: bool,
    pub(crate) attestation_id: String,
    pub(crate) challenge: String,
    pub(crate) issued_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) fabrication_authorization_id: String,
    pub(crate) fabrication_authorization_challenge: String,
    pub(crate) fabrication_valid_from_unix: u64,
    pub(crate) fabrication_expires_at_unix: u64,
    pub(crate) factory_id: String,
    pub(crate) provider: String,
    pub(crate) manufacturing_package_sha256: String,
    pub(crate) factory_receipt_sha256: String,
    pub(crate) policy_pack_sha256: String,
    pub(crate) policy_pack_canonical_sha256: String,
    pub(crate) signed_attestation_sha256: String,
    pub(crate) attestation_verifier_sha256: String,
    pub(crate) retained_report_bytes: u64,
    pub(crate) retained_report_sha256: String,
    pub(crate) retained_report_binding_sha256: String,
    pub(crate) fresh_report_bytes: u64,
    pub(crate) fresh_report_sha256: String,
    pub(crate) fresh_report_binding_sha256: String,
    pub(crate) release_subject_sha256: String,
    pub(crate) gate_failure_count: u32,
    pub(crate) trusted_time_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) endpoint_transport_authenticity_verified: bool,
    pub(crate) raw_response_authenticity_verified: bool,
    pub(crate) source_authenticity_verified: bool,
    pub(crate) executable_origin_authenticity_verified: bool,
    pub(crate) toolchain_authenticity_verified: bool,
    pub(crate) policy_pack_authenticity_verified: bool,
    pub(crate) manufacturability_verified: bool,
    pub(crate) external_submission_performed: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) challenge_one_time_use_enforced: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedFactoryReceiptReleaseReservationLedgerManifest {
    schema_version: u32,
    ledger_scope: String,
    ledger_id: String,
}

pub(crate) fn signed_factory_receipt_release_reservation_filename(
    challenge: &str,
) -> Result<String, String> {
    validate_digest(
        challenge,
        "signed factory receipt release reservation challenge",
    )?;
    Ok(format!(
        "signed-factory-receipt-release-reservation-v1-{challenge}.json"
    ))
}

pub(crate) fn parse_signed_factory_receipt_release_reservation(
    source: &[u8],
    expected_ledger_id: &str,
) -> Result<SignedFactoryReceiptReleaseReservation, String> {
    validate_digest(
        expected_ledger_id,
        "expected signed factory receipt release reservation ledger id",
    )?;
    if source.is_empty()
        || source.len() as u128 > u128::from(MAX_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES)
    {
        return Err(format!(
            "signed factory receipt release reservation must contain 1 to {} bytes",
            MAX_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES
        ));
    }
    reject_duplicate_json_keys(source).map_err(|error| {
        format!("invalid signed factory receipt release reservation JSON: {error:#}")
    })?;
    let marker: SignedFactoryReceiptReleaseReservation =
        serde_json::from_slice(source).map_err(|error| {
            format!("invalid signed factory receipt release reservation JSON: {error}")
        })?;
    validate_signed_factory_receipt_release_reservation(&marker, expected_ledger_id)?;
    let mut expected = serde_json::to_vec_pretty(&marker).map_err(|error| {
        format!("rendering signed factory receipt release reservation: {error}")
    })?;
    expected.push(b'\n');
    if expected != source {
        return Err(
            "signed factory receipt release reservation is not canonical pretty JSON".into(),
        );
    }
    Ok(marker)
}

pub(crate) fn validate_signed_factory_receipt_release_reservation_time(
    marker: &SignedFactoryReceiptReleaseReservation,
    current_unix: u64,
) -> Result<(), String> {
    validate_timestamp(current_unix, "signed release reservation current timestamp")?;
    let summary = &marker.release_report_summary;
    if current_unix < summary.issued_at_unix || current_unix > summary.expires_at_unix {
        return Err("factory receipt attestation is not active at reservation commit time".into());
    }
    if current_unix < summary.fabrication_valid_from_unix
        || current_unix > summary.fabrication_expires_at_unix
    {
        return Err("fabrication authorization is not active at reservation commit time".into());
    }
    Ok(())
}

pub(crate) fn validate_signed_factory_receipt_release_reservation_ledger_manifest(
    source: &[u8],
    expected_ledger_id: &str,
) -> Result<(), String> {
    validate_digest(
        expected_ledger_id,
        "expected signed factory receipt release reservation ledger id",
    )?;
    if source.len() as u128
        > u128::from(MAX_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_LEDGER_MANIFEST_BYTES)
    {
        return Err(format!(
            "signed factory receipt release reservation ledger manifest exceeds the {}-byte limit",
            MAX_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_LEDGER_MANIFEST_BYTES
        ));
    }
    reject_duplicate_json_keys(source).map_err(|error| {
        format!(
            "invalid signed factory receipt release reservation ledger manifest JSON: {error:#}"
        )
    })?;
    let manifest: SignedFactoryReceiptReleaseReservationLedgerManifest =
        serde_json::from_slice(source).map_err(|error| {
            format!(
                "invalid signed factory receipt release reservation ledger manifest JSON: {error}"
            )
        })?;
    if manifest.schema_version != SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCHEMA_VERSION {
        return Err(
            "unsupported signed factory receipt release reservation ledger schema_version".into(),
        );
    }
    if manifest.ledger_scope != SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE {
        return Err("signed factory receipt release reservation ledger scope is invalid".into());
    }
    validate_digest(
        &manifest.ledger_id,
        "signed factory receipt release reservation manifest ledger id",
    )?;
    if manifest.ledger_id != expected_ledger_id {
        return Err(
            "signed factory receipt release reservation manifest ledger id does not match the expected ledger id"
                .into(),
        );
    }
    Ok(())
}

fn validate_signed_factory_receipt_release_reservation(
    marker: &SignedFactoryReceiptReleaseReservation,
    expected_ledger_id: &str,
) -> Result<(), String> {
    if marker.schema_version != SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCHEMA_VERSION
        || marker.reservation_scope != SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE
        || marker.status != SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_STATUS
        || !marker.local_challenge_reserved
        || marker.adapter_network_performed
        || marker.global_challenge_one_time_use_enforced
        || marker.external_submission_performed
        || marker.capacity_reserved
        || marker.order_placed
        || marker.payment_performed
    {
        return Err(
            "signed factory receipt release reservation identity or nonclaims are invalid".into(),
        );
    }
    validate_digest(
        &marker.ledger_id,
        "signed factory receipt release reservation ledger id",
    )?;
    if marker.ledger_id != expected_ledger_id {
        return Err(
            "signed factory receipt release reservation ledger id does not match the expected ledger id"
                .into(),
        );
    }
    let summary = &marker.release_report_summary;
    if summary.schema_version != 1
        || summary.status != SIGNED_FACTORY_RECEIPT_RELEASE_STATUS
        || !summary.release_authenticated
        || !summary.executable_pinned_fabrication_release_authorized
        || !summary.factory_receipt_attestation_verified
        || !summary.factory_receipt_authenticity_verified
        || summary.gate_failure_count != 0
        || summary.trusted_time_verified
        || summary.factory_legal_identity_verified
        || summary.endpoint_transport_authenticity_verified
        || summary.raw_response_authenticity_verified
        || summary.source_authenticity_verified
        || summary.executable_origin_authenticity_verified
        || summary.toolchain_authenticity_verified
        || summary.policy_pack_authenticity_verified
        || summary.manufacturability_verified
        || summary.external_submission_performed
        || summary.capacity_reserved
        || summary.order_placed
        || summary.payment_performed
        || summary.challenge_one_time_use_enforced
    {
        return Err(
            "signed factory receipt release reservation summary is not authenticated".into(),
        );
    }
    validate_slug(&summary.attestation_id, "factory receipt attestation id")?;
    validate_digest(&summary.challenge, "factory receipt attestation challenge")?;
    validate_slug(
        &summary.fabrication_authorization_id,
        "fabrication authorization id",
    )?;
    validate_digest(
        &summary.fabrication_authorization_challenge,
        "fabrication authorization challenge",
    )?;
    validate_slug(&summary.factory_id, "factory receipt signer id")?;
    if !matches!(summary.provider.as_str(), "jlcpcb" | "pcbway" | "generic") {
        return Err("factory receipt signer provider is invalid".into());
    }
    for (value, label) in [
        (
            &summary.manufacturing_package_sha256,
            "manufacturing package SHA-256",
        ),
        (&summary.factory_receipt_sha256, "factory receipt SHA-256"),
        (
            &summary.policy_pack_sha256,
            "organization policy pack SHA-256",
        ),
        (
            &summary.policy_pack_canonical_sha256,
            "canonical organization policy pack SHA-256",
        ),
        (
            &summary.signed_attestation_sha256,
            "signed attestation SHA-256",
        ),
        (
            &summary.attestation_verifier_sha256,
            "attestation verifier SHA-256",
        ),
        (
            &summary.retained_report_sha256,
            "retained release report SHA-256",
        ),
        (
            &summary.retained_report_binding_sha256,
            "retained release report binding SHA-256",
        ),
        (&summary.fresh_report_sha256, "fresh release report SHA-256"),
        (
            &summary.fresh_report_binding_sha256,
            "fresh release report binding SHA-256",
        ),
        (
            &summary.release_subject_sha256,
            "signed release subject SHA-256",
        ),
    ] {
        validate_digest(value, label)?;
    }
    if summary.retained_report_bytes == 0
        || summary.retained_report_bytes > 16 * 1024 * 1024
        || summary.fresh_report_bytes == 0
        || summary.fresh_report_bytes > 16 * 1024 * 1024
    {
        return Err("signed release report byte count is outside its bound".into());
    }
    for (value, label) in [
        (summary.issued_at_unix, "attestation issued timestamp"),
        (summary.expires_at_unix, "attestation expiry timestamp"),
        (
            summary.evaluated_at_unix,
            "attestation evaluation timestamp",
        ),
        (
            summary.fabrication_valid_from_unix,
            "fabrication authorization start timestamp",
        ),
        (
            summary.fabrication_expires_at_unix,
            "fabrication authorization expiry timestamp",
        ),
    ] {
        validate_timestamp(value, label)?;
    }
    if summary.issued_at_unix >= summary.expires_at_unix
        || summary.fabrication_valid_from_unix >= summary.fabrication_expires_at_unix
        || summary.evaluated_at_unix < summary.issued_at_unix
        || summary.evaluated_at_unix > summary.expires_at_unix
        || summary.evaluated_at_unix < summary.fabrication_valid_from_unix
        || summary.evaluated_at_unix > summary.fabrication_expires_at_unix
    {
        return Err("signed factory receipt release reservation timing is invalid".into());
    }
    Ok(())
}

pub(crate) fn signed_factory_receipt_release_reservation_json_schema() -> Value {
    let digest = digest_schema();
    let timestamp = json!({"type": "integer", "minimum": 0, "maximum": MAXIMUM_TIMESTAMP});
    let false_value = json!({"const": false});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-receipt-release-reservation-v1.json",
        "title": "pcbex signed factory receipt release reservation",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "reservation_scope", "status", "local_challenge_reserved",
            "adapter_network_performed", "global_challenge_one_time_use_enforced",
            "external_submission_performed", "capacity_reserved", "order_placed",
            "payment_performed", "ledger_id", "release_report_summary"
        ],
        "properties": {
            "schema_version": {"const": SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCHEMA_VERSION},
            "reservation_scope": {"const": SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE},
            "status": {"const": SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_STATUS},
            "local_challenge_reserved": {"const": true},
            "adapter_network_performed": false_value,
            "global_challenge_one_time_use_enforced": false_value,
            "external_submission_performed": false_value,
            "capacity_reserved": false_value,
            "order_placed": false_value,
            "payment_performed": false_value,
            "ledger_id": digest,
            "release_report_summary": release_report_summary_schema(timestamp)
        }
    })
}

pub(crate) fn signed_factory_receipt_release_reservation_ledger_manifest_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-receipt-release-reservation-ledger-manifest-v1.json",
        "title": "pcbex signed factory receipt release reservation ledger manifest",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "ledger_scope", "ledger_id"],
        "properties": {
            "schema_version": {"const": SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCHEMA_VERSION},
            "ledger_scope": {"const": SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE},
            "ledger_id": digest_schema()
        }
    })
}

fn release_report_summary_schema(timestamp: Value) -> Value {
    let digest = digest_schema();
    let id = json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"});
    let false_value = json!({"const": false});
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "release_authenticated",
            "executable_pinned_fabrication_release_authorized",
            "factory_receipt_attestation_verified", "factory_receipt_authenticity_verified",
            "attestation_id", "challenge", "issued_at_unix", "expires_at_unix",
            "evaluated_at_unix", "fabrication_authorization_id",
            "fabrication_authorization_challenge", "fabrication_valid_from_unix",
            "fabrication_expires_at_unix", "factory_id", "provider",
            "manufacturing_package_sha256", "factory_receipt_sha256", "policy_pack_sha256",
            "policy_pack_canonical_sha256", "signed_attestation_sha256",
            "attestation_verifier_sha256", "retained_report_bytes",
            "retained_report_sha256", "retained_report_binding_sha256",
            "fresh_report_bytes", "fresh_report_sha256", "fresh_report_binding_sha256",
            "release_subject_sha256", "gate_failure_count", "trusted_time_verified",
            "factory_legal_identity_verified", "endpoint_transport_authenticity_verified",
            "raw_response_authenticity_verified", "source_authenticity_verified",
            "executable_origin_authenticity_verified", "toolchain_authenticity_verified",
            "policy_pack_authenticity_verified", "manufacturability_verified",
            "external_submission_performed", "capacity_reserved", "order_placed",
            "payment_performed", "challenge_one_time_use_enforced"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "status": {"const": SIGNED_FACTORY_RECEIPT_RELEASE_STATUS},
            "release_authenticated": {"const": true},
            "executable_pinned_fabrication_release_authorized": {"const": true},
            "factory_receipt_attestation_verified": {"const": true},
            "factory_receipt_authenticity_verified": {"const": true},
            "attestation_id": id,
            "challenge": digest,
            "issued_at_unix": timestamp,
            "expires_at_unix": timestamp,
            "evaluated_at_unix": timestamp,
            "fabrication_authorization_id": id,
            "fabrication_authorization_challenge": digest,
            "fabrication_valid_from_unix": timestamp,
            "fabrication_expires_at_unix": timestamp,
            "factory_id": id,
            "provider": {"enum": ["generic", "jlcpcb", "pcbway"]},
            "manufacturing_package_sha256": digest,
            "factory_receipt_sha256": digest,
            "policy_pack_sha256": digest,
            "policy_pack_canonical_sha256": digest,
            "signed_attestation_sha256": digest,
            "attestation_verifier_sha256": digest,
            "retained_report_bytes": {"type": "integer", "minimum": 1, "maximum": 16777216},
            "retained_report_sha256": digest,
            "retained_report_binding_sha256": digest,
            "fresh_report_bytes": {"type": "integer", "minimum": 1, "maximum": 16777216},
            "fresh_report_sha256": digest,
            "fresh_report_binding_sha256": digest,
            "release_subject_sha256": digest,
            "gate_failure_count": {"const": 0},
            "trusted_time_verified": false_value,
            "factory_legal_identity_verified": false_value,
            "endpoint_transport_authenticity_verified": false_value,
            "raw_response_authenticity_verified": false_value,
            "source_authenticity_verified": false_value,
            "executable_origin_authenticity_verified": false_value,
            "toolchain_authenticity_verified": false_value,
            "policy_pack_authenticity_verified": false_value,
            "manufacturability_verified": false_value,
            "external_submission_performed": false_value,
            "capacity_reserved": false_value,
            "order_placed": false_value,
            "payment_performed": false_value,
            "challenge_one_time_use_enforced": false_value
        }
    })
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(format!(
            "{label} must contain 64 lowercase hexadecimal digits"
        ));
    }
    Ok(())
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || !value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_timestamp(value: u64, label: &str) -> Result<(), String> {
    if value > MAXIMUM_TIMESTAMP {
        return Err(format!("{label} is outside its bound"));
    }
    Ok(())
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_recursively_closed(value: &Value) {
        match value {
            Value::Object(object) => {
                if object.get("type") == Some(&Value::String("object".into())) {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&Value::Bool(false))
                    );
                }
                if object.get("type") == Some(&Value::String("array".into())) {
                    assert!(object.get("maxItems").is_some());
                }
                for nested in object.values() {
                    assert_recursively_closed(nested);
                }
            }
            Value::Array(values) => {
                for nested in values {
                    assert_recursively_closed(nested);
                }
            }
            _ => {}
        }
    }

    fn marker() -> SignedFactoryReceiptReleaseReservation {
        SignedFactoryReceiptReleaseReservation {
            schema_version: 1,
            reservation_scope: SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE.into(),
            status: SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_STATUS.into(),
            local_challenge_reserved: true,
            adapter_network_performed: false,
            global_challenge_one_time_use_enforced: false,
            external_submission_performed: false,
            capacity_reserved: false,
            order_placed: false,
            payment_performed: false,
            ledger_id: "1".repeat(64),
            release_report_summary: SignedFactoryReceiptReleaseReportSummary {
                schema_version: 1,
                status: SIGNED_FACTORY_RECEIPT_RELEASE_STATUS.into(),
                release_authenticated: true,
                executable_pinned_fabrication_release_authorized: true,
                factory_receipt_attestation_verified: true,
                factory_receipt_authenticity_verified: true,
                attestation_id: "receipt-1481".into(),
                challenge: "2".repeat(64),
                issued_at_unix: 100,
                expires_at_unix: 200,
                evaluated_at_unix: 150,
                fabrication_authorization_id: "fabrication-1481".into(),
                fabrication_authorization_challenge: "3".repeat(64),
                fabrication_valid_from_unix: 90,
                fabrication_expires_at_unix: 210,
                factory_id: "factory-a".into(),
                provider: "generic".into(),
                manufacturing_package_sha256: "4".repeat(64),
                factory_receipt_sha256: "5".repeat(64),
                policy_pack_sha256: "6".repeat(64),
                policy_pack_canonical_sha256: "7".repeat(64),
                signed_attestation_sha256: "8".repeat(64),
                attestation_verifier_sha256: "9".repeat(64),
                retained_report_bytes: 1000,
                retained_report_sha256: "a".repeat(64),
                retained_report_binding_sha256: "b".repeat(64),
                fresh_report_bytes: 1001,
                fresh_report_sha256: "c".repeat(64),
                fresh_report_binding_sha256: "d".repeat(64),
                release_subject_sha256: "e".repeat(64),
                gate_failure_count: 0,
                trusted_time_verified: false,
                factory_legal_identity_verified: false,
                endpoint_transport_authenticity_verified: false,
                raw_response_authenticity_verified: false,
                source_authenticity_verified: false,
                executable_origin_authenticity_verified: false,
                toolchain_authenticity_verified: false,
                policy_pack_authenticity_verified: false,
                manufacturability_verified: false,
                external_submission_performed: false,
                capacity_reserved: false,
                order_placed: false,
                payment_performed: false,
                challenge_one_time_use_enforced: false,
            },
        }
    }

    #[test]
    fn marker_round_trips_and_time_is_rechecked() {
        let marker = marker();
        let mut raw = serde_json::to_vec_pretty(&marker).unwrap();
        raw.push(b'\n');
        assert_eq!(
            parse_signed_factory_receipt_release_reservation(&raw, &"1".repeat(64)).unwrap(),
            marker
        );
        validate_signed_factory_receipt_release_reservation_time(&marker, 150).unwrap();
        assert!(validate_signed_factory_receipt_release_reservation_time(&marker, 201).is_err());
        assert!(
            signed_factory_receipt_release_reservation_filename(&"2".repeat(64))
                .unwrap()
                .ends_with(&format!("{}.json", "2".repeat(64)))
        );
    }

    #[test]
    fn manifest_and_schemas_are_closed() {
        let manifest = format!(
            "{{\"schema_version\":1,\"ledger_scope\":\"{}\",\"ledger_id\":\"{}\"}}",
            SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE,
            "1".repeat(64)
        );
        validate_signed_factory_receipt_release_reservation_ledger_manifest(
            manifest.as_bytes(),
            &"1".repeat(64),
        )
        .unwrap();
        assert_recursively_closed(&signed_factory_receipt_release_reservation_json_schema());
        assert_recursively_closed(
            &signed_factory_receipt_release_reservation_ledger_manifest_json_schema(),
        );
    }
}

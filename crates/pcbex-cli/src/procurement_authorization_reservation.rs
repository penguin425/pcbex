//! Closed markers for local at-most-once procurement authorization admission.
//!
//! A marker proves only that one descriptor-pinned local ledger accepted one
//! challenge. It does not change the underlying v1.471 report, authenticate a
//! supplier or clock, reserve stock, place an order, perform payment, or make
//! the challenge globally unique.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const PROCUREMENT_AUTHORIZATION_RESERVATION_SCHEMA_VERSION: u32 = 1;
pub(crate) const PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE: &str =
    "pinned-local-procurement-authorization-ledger-at-most-once-v1";
const PROCUREMENT_AUTHORIZATION_RESERVATION_STATUS: &str = "local_reservation_committed";
const PROCUREMENT_AUTHORIZATION_REPORT_SCHEMA_VERSION: u32 = 1;
const PROCUREMENT_AUTHORIZATION_REPORT_STATUS: &str = "procurement_authorized";
const MAXIMUM_TIMESTAMP: u64 = 9_223_372_036_854_775_807;
const MAXIMUM_MONEY_MICROS: u64 = 9_007_199_254_740_991;
const MAXIMUM_REQUESTED_BOARDS: u32 = 1_000_000;
const MAXIMUM_VALIDITY_SECONDS: u64 = 604_800;
const MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES: u64 = 128 * 1024 * 1024;

pub(crate) const MAX_PROCUREMENT_AUTHORIZATION_RESERVATION_BYTES: u64 = 16 * 1024;
pub(crate) const PROCUREMENT_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_FILENAME: &str =
    ".pcbex-procurement-authorization-reservation-ledger-v1.json";
pub(crate) const MAX_PROCUREMENT_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_BYTES: u64 = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementAuthorizationReservation {
    pub(crate) schema_version: u32,
    pub(crate) reservation_scope: String,
    pub(crate) status: String,
    pub(crate) local_challenge_reserved: bool,
    pub(crate) adapter_network_performed: bool,
    pub(crate) global_challenge_one_time_use_enforced: bool,
    pub(crate) inventory_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) ledger_id: String,
    pub(crate) authorization_report_summary: ProcurementAuthorizationReportSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementAuthorizationReportSummary {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) procurement_authorized: bool,
    pub(crate) authorization_id: String,
    pub(crate) challenge: String,
    pub(crate) supplier: String,
    pub(crate) offer_id: String,
    pub(crate) requested_boards: u32,
    pub(crate) currency: String,
    pub(crate) component_subtotal_micros: u64,
    pub(crate) maximum_component_subtotal_micros: u64,
    pub(crate) offer_valid_from_unix: u64,
    pub(crate) offer_valid_until_unix: u64,
    pub(crate) receipt_fetched_at_unix: u64,
    pub(crate) maximum_receipt_observation_age_seconds: u64,
    pub(crate) valid_from_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) approvals: u32,
    pub(crate) rejections: u32,
    pub(crate) gate_failure_count: u32,
    pub(crate) current_availability_verified: bool,
    pub(crate) supplier_authenticity_verified: bool,
    pub(crate) offer_authenticity_verified: bool,
    pub(crate) price_authenticity_verified: bool,
    pub(crate) receipt_observation_authenticity_verified: bool,
    pub(crate) policy_pack_authenticity_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) challenge_one_time_use_enforced: bool,
    pub(crate) report_bytes: u64,
    pub(crate) report_sha256: String,
    pub(crate) report_binding_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcurementAuthorizationReservationLedgerManifest {
    schema_version: u32,
    ledger_scope: String,
    ledger_id: String,
}

pub(crate) fn procurement_authorization_reservation_filename(
    challenge: &str,
) -> Result<String, String> {
    validate_digest(challenge, "procurement authorization reservation challenge")?;
    Ok(format!(
        "procurement-authorization-reservation-v1-{challenge}.json"
    ))
}

pub(crate) fn parse_procurement_authorization_reservation(
    source: &[u8],
    expected_ledger_id: &str,
) -> Result<ProcurementAuthorizationReservation, String> {
    validate_digest(
        expected_ledger_id,
        "expected procurement authorization reservation ledger id",
    )?;
    if source.is_empty()
        || source.len() as u128 > u128::from(MAX_PROCUREMENT_AUTHORIZATION_RESERVATION_BYTES)
    {
        return Err(format!(
            "procurement authorization reservation must contain 1 to {} bytes",
            MAX_PROCUREMENT_AUTHORIZATION_RESERVATION_BYTES
        ));
    }
    reject_duplicate_json_keys(source).map_err(|error| {
        format!("invalid procurement authorization reservation JSON: {error:#}")
    })?;
    let marker: ProcurementAuthorizationReservation = serde_json::from_slice(source)
        .map_err(|error| format!("invalid procurement authorization reservation JSON: {error}"))?;
    validate_procurement_authorization_reservation(&marker, expected_ledger_id)?;
    let mut expected = serde_json::to_vec_pretty(&marker)
        .map_err(|error| format!("rendering procurement authorization reservation: {error}"))?;
    expected.push(b'\n');
    if expected != source {
        return Err("procurement authorization reservation is not canonical pretty JSON".into());
    }
    Ok(marker)
}

pub(crate) fn validate_procurement_authorization_reservation_time(
    marker: &ProcurementAuthorizationReservation,
    current_unix: u64,
) -> Result<(), String> {
    validate_timestamp(current_unix, "procurement reservation current timestamp")?;
    let summary = &marker.authorization_report_summary;
    if current_unix < summary.valid_from_unix || current_unix > summary.expires_at_unix {
        return Err("procurement authorization is not active at reservation commit time".into());
    }
    if current_unix < summary.offer_valid_from_unix
        || current_unix >= summary.offer_valid_until_unix
    {
        return Err("supplier offer window is not active at reservation commit time".into());
    }
    if summary.receipt_fetched_at_unix > current_unix {
        return Err("receipt observation is from the future at reservation commit time".into());
    }
    let age = current_unix - summary.receipt_fetched_at_unix;
    if age > summary.maximum_receipt_observation_age_seconds {
        return Err("receipt observation is too old at reservation commit time".into());
    }
    Ok(())
}

pub(crate) fn validate_procurement_authorization_reservation_ledger_manifest(
    source: &[u8],
    expected_ledger_id: &str,
) -> Result<(), String> {
    validate_digest(
        expected_ledger_id,
        "expected procurement authorization reservation ledger id",
    )?;
    if source.len() as u128
        > u128::from(MAX_PROCUREMENT_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_BYTES)
    {
        return Err(format!(
            "procurement authorization reservation ledger manifest exceeds the {}-byte limit",
            MAX_PROCUREMENT_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_BYTES
        ));
    }
    reject_duplicate_json_keys(source).map_err(|error| {
        format!("invalid procurement authorization reservation ledger manifest JSON: {error:#}")
    })?;
    let manifest: ProcurementAuthorizationReservationLedgerManifest =
        serde_json::from_slice(source).map_err(|error| {
            format!("invalid procurement authorization reservation ledger manifest JSON: {error}")
        })?;
    if manifest.schema_version != PROCUREMENT_AUTHORIZATION_RESERVATION_SCHEMA_VERSION {
        return Err(
            "unsupported procurement authorization reservation ledger schema_version".into(),
        );
    }
    if manifest.ledger_scope != PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE {
        return Err("procurement authorization reservation ledger scope is invalid".into());
    }
    validate_digest(
        &manifest.ledger_id,
        "procurement authorization reservation manifest ledger id",
    )?;
    if manifest.ledger_id != expected_ledger_id {
        return Err(
            "procurement authorization reservation manifest ledger id does not match the expected ledger id"
                .into(),
        );
    }
    Ok(())
}

fn validate_procurement_authorization_reservation(
    marker: &ProcurementAuthorizationReservation,
    expected_ledger_id: &str,
) -> Result<(), String> {
    if marker.schema_version != PROCUREMENT_AUTHORIZATION_RESERVATION_SCHEMA_VERSION
        || marker.reservation_scope != PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE
        || marker.status != PROCUREMENT_AUTHORIZATION_RESERVATION_STATUS
        || !marker.local_challenge_reserved
        || marker.adapter_network_performed
        || marker.global_challenge_one_time_use_enforced
        || marker.inventory_reserved
        || marker.order_placed
        || marker.payment_performed
    {
        return Err(
            "procurement authorization reservation identity or nonclaims are invalid".into(),
        );
    }
    validate_digest(
        &marker.ledger_id,
        "procurement authorization reservation ledger id",
    )?;
    if marker.ledger_id != expected_ledger_id {
        return Err(
            "procurement authorization reservation ledger id does not match the expected ledger id"
                .into(),
        );
    }
    let summary = &marker.authorization_report_summary;
    if summary.schema_version != PROCUREMENT_AUTHORIZATION_REPORT_SCHEMA_VERSION
        || summary.status != PROCUREMENT_AUTHORIZATION_REPORT_STATUS
        || !summary.procurement_authorized
        || summary.rejections != 0
        || summary.gate_failure_count != 0
        || summary.current_availability_verified
        || summary.supplier_authenticity_verified
        || summary.offer_authenticity_verified
        || summary.price_authenticity_verified
        || summary.receipt_observation_authenticity_verified
        || summary.policy_pack_authenticity_verified
        || summary.trusted_time_verified
        || summary.challenge_one_time_use_enforced
    {
        return Err("only a freshly verified authorized procurement report may be reserved".into());
    }
    validate_slug(&summary.authorization_id, "procurement authorization id")?;
    validate_digest(&summary.challenge, "procurement authorization challenge")?;
    validate_supplier(&summary.supplier)?;
    validate_text(&summary.offer_id, 128, "procurement supplier offer id")?;
    if summary.requested_boards == 0 || summary.requested_boards > MAXIMUM_REQUESTED_BOARDS {
        return Err("procurement reservation requested boards are outside the closed bound".into());
    }
    validate_currency(&summary.currency)?;
    if summary.component_subtotal_micros > MAXIMUM_MONEY_MICROS
        || summary.maximum_component_subtotal_micros == 0
        || summary.maximum_component_subtotal_micros > MAXIMUM_MONEY_MICROS
        || summary.component_subtotal_micros > summary.maximum_component_subtotal_micros
    {
        return Err(
            "procurement reservation component subtotal is outside the authorized ceiling".into(),
        );
    }
    for (value, label) in [
        (
            summary.offer_valid_from_unix,
            "supplier offer valid-from timestamp",
        ),
        (
            summary.offer_valid_until_unix,
            "supplier offer valid-until timestamp",
        ),
        (
            summary.receipt_fetched_at_unix,
            "receipt observation timestamp",
        ),
        (
            summary.valid_from_unix,
            "procurement authorization valid-from timestamp",
        ),
        (
            summary.expires_at_unix,
            "procurement authorization expiry timestamp",
        ),
        (
            summary.evaluated_at_unix,
            "procurement authorization evaluation timestamp",
        ),
    ] {
        validate_timestamp(value, label)?;
    }
    if summary.offer_valid_from_unix >= summary.offer_valid_until_unix
        || summary.valid_from_unix >= summary.expires_at_unix
        || summary.expires_at_unix - summary.valid_from_unix > MAXIMUM_VALIDITY_SECONDS
        || summary.valid_from_unix < summary.offer_valid_from_unix
        || summary.expires_at_unix >= summary.offer_valid_until_unix
    {
        return Err("procurement reservation validity intervals are invalid".into());
    }
    if summary.maximum_receipt_observation_age_seconds == 0
        || summary.maximum_receipt_observation_age_seconds > MAXIMUM_VALIDITY_SECONDS
    {
        return Err("procurement reservation receipt observation age bound is invalid".into());
    }
    if !(2..=100).contains(&summary.approvals) {
        return Err("procurement reservation approval count must be between 2 and 100".into());
    }
    if summary.report_bytes == 0
        || summary.report_bytes > MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES
    {
        return Err(
            "procurement authorization report byte count is outside the closed bound".into(),
        );
    }
    validate_digest(
        &summary.report_sha256,
        "procurement authorization report SHA-256",
    )?;
    validate_digest(
        &summary.report_binding_sha256,
        "procurement authorization report binding SHA-256",
    )?;
    validate_procurement_authorization_reservation_time(marker, summary.evaluated_at_unix)
}

pub(crate) fn procurement_authorization_reservation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/procurement-authorization-reservation-v1.json",
        "title": "pcbex procurement authorization reservation",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "reservation_scope", "status", "local_challenge_reserved",
            "adapter_network_performed", "global_challenge_one_time_use_enforced",
            "inventory_reserved", "order_placed", "payment_performed", "ledger_id",
            "authorization_report_summary"
        ],
        "properties": {
            "schema_version": {"const": PROCUREMENT_AUTHORIZATION_RESERVATION_SCHEMA_VERSION},
            "reservation_scope": {"const": PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE},
            "status": {"const": PROCUREMENT_AUTHORIZATION_RESERVATION_STATUS},
            "local_challenge_reserved": {"const": true},
            "adapter_network_performed": {"const": false},
            "global_challenge_one_time_use_enforced": {"const": false},
            "inventory_reserved": {"const": false},
            "order_placed": {"const": false},
            "payment_performed": {"const": false},
            "ledger_id": digest_schema(),
            "authorization_report_summary": authorization_report_summary_schema()
        }
    })
}

pub(crate) fn procurement_authorization_reservation_ledger_manifest_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/procurement-authorization-reservation-ledger-manifest-v1.json",
        "title": "pcbex procurement authorization reservation ledger manifest",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "ledger_scope", "ledger_id"],
        "properties": {
            "schema_version": {"const": PROCUREMENT_AUTHORIZATION_RESERVATION_SCHEMA_VERSION},
            "ledger_scope": {"const": PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE},
            "ledger_id": digest_schema()
        }
    })
}

fn authorization_report_summary_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "procurement_authorized", "authorization_id",
            "challenge", "supplier", "offer_id", "requested_boards", "currency",
            "component_subtotal_micros", "maximum_component_subtotal_micros",
            "offer_valid_from_unix", "offer_valid_until_unix", "receipt_fetched_at_unix",
            "maximum_receipt_observation_age_seconds", "valid_from_unix", "expires_at_unix",
            "evaluated_at_unix", "approvals", "rejections", "gate_failure_count",
            "current_availability_verified", "supplier_authenticity_verified",
            "offer_authenticity_verified", "price_authenticity_verified",
            "receipt_observation_authenticity_verified", "policy_pack_authenticity_verified",
            "trusted_time_verified", "challenge_one_time_use_enforced",
            "report_bytes", "report_sha256", "report_binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": PROCUREMENT_AUTHORIZATION_REPORT_SCHEMA_VERSION},
            "status": {"const": PROCUREMENT_AUTHORIZATION_REPORT_STATUS},
            "procurement_authorized": {"const": true},
            "authorization_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "challenge": digest_schema(),
            "supplier": {"type": "string", "pattern": "^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$"},
            "offer_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "requested_boards": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_REQUESTED_BOARDS},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "component_subtotal_micros": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_MONEY_MICROS},
            "maximum_component_subtotal_micros": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_MONEY_MICROS},
            "offer_valid_from_unix": timestamp_schema(),
            "offer_valid_until_unix": timestamp_schema(),
            "receipt_fetched_at_unix": timestamp_schema(),
            "maximum_receipt_observation_age_seconds": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_VALIDITY_SECONDS},
            "valid_from_unix": timestamp_schema(),
            "expires_at_unix": timestamp_schema(),
            "evaluated_at_unix": timestamp_schema(),
            "approvals": {"type": "integer", "minimum": 2, "maximum": 100},
            "rejections": {"const": 0},
            "gate_failure_count": {"const": 0},
            "current_availability_verified": {"const": false},
            "supplier_authenticity_verified": {"const": false},
            "offer_authenticity_verified": {"const": false},
            "price_authenticity_verified": {"const": false},
            "receipt_observation_authenticity_verified": {"const": false},
            "policy_pack_authenticity_verified": {"const": false},
            "trusted_time_verified": {"const": false},
            "challenge_one_time_use_enforced": {"const": false},
            "report_bytes": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES},
            "report_sha256": digest_schema(),
            "report_binding_sha256": digest_schema()
        }
    })
}

fn timestamp_schema() -> Value {
    json!({"type": "integer", "minimum": 0, "maximum": MAXIMUM_TIMESTAMP})
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn validate_timestamp(value: u64, label: &str) -> Result<(), String> {
    if value > MAXIMUM_TIMESTAMP {
        return Err(format!("{label} exceeds the closed timestamp bound"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must contain 64 lowercase hexadecimal digits"
        ));
    }
    Ok(())
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'-'))
        });
    if !valid {
        return Err(format!("{label} must match [a-z0-9][a-z0-9.-]{{0,127}}"));
    }
    Ok(())
}

fn validate_supplier(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err("procurement reservation supplier id is invalid".into());
    }
    Ok(())
}

fn validate_currency(value: &str) -> Result<(), String> {
    if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(
            "procurement reservation currency must contain three uppercase ASCII letters".into(),
        );
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn marker() -> ProcurementAuthorizationReservation {
        ProcurementAuthorizationReservation {
            schema_version: 1,
            reservation_scope: PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE.into(),
            status: PROCUREMENT_AUTHORIZATION_RESERVATION_STATUS.into(),
            local_challenge_reserved: true,
            adapter_network_performed: false,
            global_challenge_one_time_use_enforced: false,
            inventory_reserved: false,
            order_placed: false,
            payment_performed: false,
            ledger_id: DIGEST.into(),
            authorization_report_summary: ProcurementAuthorizationReportSummary {
                schema_version: 1,
                status: PROCUREMENT_AUTHORIZATION_REPORT_STATUS.into(),
                procurement_authorized: true,
                authorization_id: "release-1".into(),
                challenge: DIGEST.into(),
                supplier: "supplier-a".into(),
                offer_id: "offer-1".into(),
                requested_boards: 25,
                currency: "USD".into(),
                component_subtotal_micros: 10_000_000,
                maximum_component_subtotal_micros: 11_000_000,
                offer_valid_from_unix: 900,
                offer_valid_until_unix: 2_000,
                receipt_fetched_at_unix: 950,
                maximum_receipt_observation_age_seconds: 600,
                valid_from_unix: 1_000,
                expires_at_unix: 1_500,
                evaluated_at_unix: 1_100,
                approvals: 2,
                rejections: 0,
                gate_failure_count: 0,
                current_availability_verified: false,
                supplier_authenticity_verified: false,
                offer_authenticity_verified: false,
                price_authenticity_verified: false,
                receipt_observation_authenticity_verified: false,
                policy_pack_authenticity_verified: false,
                trusted_time_verified: false,
                challenge_one_time_use_enforced: false,
                report_bytes: 4_096,
                report_sha256: DIGEST.into(),
                report_binding_sha256: DIGEST.into(),
            },
        }
    }

    #[test]
    fn canonical_marker_round_trips_and_derives_name() {
        let mut raw = serde_json::to_vec_pretty(&marker()).unwrap();
        raw.push(b'\n');
        assert_eq!(
            parse_procurement_authorization_reservation(&raw, DIGEST).unwrap(),
            marker()
        );
        assert_eq!(
            procurement_authorization_reservation_filename(DIGEST).unwrap(),
            format!("procurement-authorization-reservation-v1-{DIGEST}.json")
        );
    }

    #[test]
    fn marker_rejects_noncanonical_and_inactive_inputs() {
        let compact = serde_json::to_vec(&marker()).unwrap();
        assert!(parse_procurement_authorization_reservation(&compact, DIGEST).is_err());
        let mut expired = marker();
        expired.authorization_report_summary.evaluated_at_unix = 1_600;
        let mut raw = serde_json::to_vec_pretty(&expired).unwrap();
        raw.push(b'\n');
        assert!(parse_procurement_authorization_reservation(&raw, DIGEST).is_err());
        assert!(validate_procurement_authorization_reservation_time(&marker(), 1_501).is_err());
    }

    #[test]
    fn manifest_is_closed_and_pinned() {
        let source = format!(
            "{{\"schema_version\":1,\"ledger_scope\":\"{}\",\"ledger_id\":\"{}\"}}",
            PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE, DIGEST
        );
        validate_procurement_authorization_reservation_ledger_manifest(source.as_bytes(), DIGEST)
            .unwrap();
        let extra = source.replace("}", ",\"extra\":true}");
        assert!(
            validate_procurement_authorization_reservation_ledger_manifest(
                extra.as_bytes(),
                DIGEST
            )
            .is_err()
        );
    }

    #[test]
    fn schemas_are_closed() {
        let marker = procurement_authorization_reservation_json_schema();
        let ledger = procurement_authorization_reservation_ledger_manifest_json_schema();
        assert_eq!(marker["additionalProperties"], false);
        assert_eq!(
            marker["properties"]["authorization_report_summary"]["additionalProperties"],
            false
        );
        assert_eq!(ledger["additionalProperties"], false);
    }
}

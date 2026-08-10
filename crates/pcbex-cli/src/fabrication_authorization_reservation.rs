//! Closed, path-free records for a trusted local fabrication reservation ledger.
//!
//! A successfully installed reservation record is evidence that one pinned
//! local ledger accepted a fabrication authorization challenge.  It does not
//! make the underlying offline authorization report stateful, authenticate a
//! factory, place an order, reserve funds, or provide cross-host replay
//! protection.  Durable no-clobber installation is the caller's responsibility.

use crate::bounded_io::MAX_FILE_BYTES;
use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::fabrication_authorization::{
    FABRICATION_AUTHORIZATION_REPORT_SCHEMA_VERSION, FabricationAuthorizationReport,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FABRICATION_AUTHORIZATION_RESERVATION_SCHEMA_VERSION: u32 = 1;
const FABRICATION_AUTHORIZATION_RESERVATION_SCOPE: &str = "pinned-local-ledger-at-most-once-v1";
const FABRICATION_AUTHORIZATION_RESERVATION_STATUS: &str = "local_reservation_committed";

/// Reservation records intentionally contain only a compact authorization
/// summary, never the full policy, approvals, reasons, tickets, or paths.
pub(crate) const MAX_FABRICATION_AUTHORIZATION_RESERVATION_BYTES: usize = 16 * 1024;

/// A ledger must already contain this manifest before it may accept records.
pub(crate) const FABRICATION_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_FILENAME: &str =
    ".pcbex-fabrication-authorization-reservation-ledger-v1.json";
pub(crate) const MAX_FABRICATION_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_BYTES: u64 = 4 * 1024;

#[derive(Serialize)]
struct FabricationAuthorizationReservation<'a> {
    schema_version: u32,
    reservation_scope: &'static str,
    status: &'static str,
    ledger_id: &'a str,
    authorization_report_summary: FabricationAuthorizationReportSummary<'a>,
}

/// This is deliberately identical in field order and meaning to the existing
/// 23-field CLI fabrication-authorization report summary.
#[derive(Serialize)]
struct FabricationAuthorizationReportSummary<'a> {
    schema_version: u32,
    status: &'a str,
    fabrication_authorized: bool,
    authorization_id: &'a str,
    challenge: &'a str,
    quantity: u32,
    currency: &'a str,
    maximum_total_minor_units: u64,
    valid_from_unix: u64,
    expires_at_unix: u64,
    evaluated_at_unix: u64,
    approvals: u32,
    rejections: u32,
    gate_failure_count: u64,
    plan_sha256: &'a str,
    run_sha256: &'a str,
    manufacturing_package_sha256: &'a str,
    factory_receipt_sha256: &'a str,
    policy_pack_sha256: &'a str,
    quote_authenticity_verified: bool,
    challenge_one_time_use_enforced: bool,
    report_bytes: u64,
    report_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FabricationAuthorizationReservationLedgerManifest {
    schema_version: u32,
    ledger_scope: String,
    ledger_id: String,
}

/// Derive the only permitted marker name from a verified authorization
/// challenge.  Validation happens before interpolation so this cannot create a
/// path separator, hidden file, or traversal component.
pub(crate) fn fabrication_authorization_reservation_filename(
    challenge: &str,
) -> Result<String, String> {
    validate_digest(challenge, "fabrication authorization reservation challenge")?;
    Ok(format!(
        "fabrication-authorization-reservation-v1-{challenge}.json"
    ))
}

/// Render the immutable payload that the trusted-ledger installer must commit.
///
/// `rendered_report` must be the exact pretty-printed, LF-terminated rendering
/// of `report`.  This binds `report_bytes` and `report_sha256` to the fresh full
/// authorization report rather than arbitrary caller-selected bytes.
pub(crate) fn render_fabrication_authorization_reservation(
    report: &FabricationAuthorizationReport,
    rendered_report: &[u8],
    ledger_id: &str,
) -> Result<Vec<u8>, String> {
    validate_digest(ledger_id, "fabrication authorization reservation ledger id")?;
    validate_reservable_report(report)?;
    validate_exact_report_rendering(report, rendered_report)?;

    let report_bytes = u64::try_from(rendered_report.len())
        .map_err(|_| "fabrication authorization report byte count is not representable")?;
    let reservation = FabricationAuthorizationReservation {
        schema_version: FABRICATION_AUTHORIZATION_RESERVATION_SCHEMA_VERSION,
        reservation_scope: FABRICATION_AUTHORIZATION_RESERVATION_SCOPE,
        status: FABRICATION_AUTHORIZATION_RESERVATION_STATUS,
        ledger_id,
        authorization_report_summary: FabricationAuthorizationReportSummary {
            schema_version: report.schema_version,
            status: &report.status,
            fabrication_authorized: report.fabrication_authorized,
            authorization_id: &report.scope.authorization_id,
            challenge: &report.scope.challenge,
            quantity: report.scope.quantity,
            currency: &report.scope.currency,
            maximum_total_minor_units: report.scope.maximum_total_minor_units,
            valid_from_unix: report.scope.valid_from_unix,
            expires_at_unix: report.scope.expires_at_unix,
            evaluated_at_unix: report.evaluated_at_unix,
            approvals: report.approvals,
            rejections: report.rejections,
            gate_failure_count: report.gate_failures.len() as u64,
            plan_sha256: &report.evidence.pipeline.plan_sha256,
            run_sha256: &report.evidence.pipeline.run_sha256,
            manufacturing_package_sha256: &report.evidence.manufacturing_package.sha256,
            factory_receipt_sha256: &report.evidence.factory_receipt.receipt.sha256,
            policy_pack_sha256: &report.evidence.policy_pack.source.sha256,
            quote_authenticity_verified: report
                .evidence
                .factory_receipt
                .quote_authenticity_verified,
            challenge_one_time_use_enforced: report.challenge_one_time_use_enforced,
            report_bytes,
            report_sha256: hex::encode(Sha256::digest(rendered_report)),
        },
    };
    let mut rendered = serde_json::to_vec_pretty(&reservation)
        .map_err(|error| format!("rendering fabrication authorization reservation: {error}"))?;
    rendered.push(b'\n');
    if rendered.len() > MAX_FABRICATION_AUTHORIZATION_RESERVATION_BYTES {
        return Err(format!(
            "fabrication authorization reservation exceeds the {}-byte limit",
            MAX_FABRICATION_AUTHORIZATION_RESERVATION_BYTES
        ));
    }
    Ok(rendered)
}

/// Validate the pre-existing ledger manifest and its explicit caller-pinned
/// identity.  The parser is byte-bounded, duplicate-key rejecting, and closed.
pub(crate) fn validate_fabrication_authorization_reservation_ledger_manifest(
    source: &[u8],
    expected_ledger_id: &str,
) -> Result<(), String> {
    validate_digest(
        expected_ledger_id,
        "expected fabrication authorization reservation ledger id",
    )?;
    if source.len() as u128
        > u128::from(MAX_FABRICATION_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_BYTES)
    {
        return Err(format!(
            "fabrication authorization reservation ledger manifest exceeds the {}-byte limit",
            MAX_FABRICATION_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_BYTES
        ));
    }
    reject_duplicate_json_keys(source).map_err(|error| {
        format!("invalid fabrication authorization reservation ledger manifest JSON: {error:#}")
    })?;
    let manifest: FabricationAuthorizationReservationLedgerManifest =
        serde_json::from_slice(source).map_err(|error| {
            format!("invalid fabrication authorization reservation ledger manifest JSON: {error}")
        })?;
    if manifest.schema_version != FABRICATION_AUTHORIZATION_RESERVATION_SCHEMA_VERSION {
        return Err(format!(
            "unsupported fabrication authorization reservation ledger manifest schema_version {}; expected {}",
            manifest.schema_version, FABRICATION_AUTHORIZATION_RESERVATION_SCHEMA_VERSION
        ));
    }
    if manifest.ledger_scope != FABRICATION_AUTHORIZATION_RESERVATION_SCOPE {
        return Err("fabrication authorization reservation ledger scope is invalid".into());
    }
    validate_digest(
        &manifest.ledger_id,
        "fabrication authorization reservation manifest ledger id",
    )?;
    if manifest.ledger_id != expected_ledger_id {
        return Err(
            "fabrication authorization reservation manifest ledger id does not match the expected ledger id"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn fabrication_authorization_reservation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/fabrication-authorization-reservation-v1.json",
        "title": "pcbex fabrication authorization reservation",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "reservation_scope", "status", "ledger_id",
            "authorization_report_summary"
        ],
        "properties": {
            "schema_version": {
                "const": FABRICATION_AUTHORIZATION_RESERVATION_SCHEMA_VERSION
            },
            "reservation_scope": {"const": FABRICATION_AUTHORIZATION_RESERVATION_SCOPE},
            "status": {"const": FABRICATION_AUTHORIZATION_RESERVATION_STATUS},
            "ledger_id": digest_schema(),
            "authorization_report_summary": authorization_report_summary_schema()
        }
    })
}

pub(crate) fn fabrication_authorization_reservation_ledger_manifest_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/fabrication-authorization-reservation-ledger-manifest-v1.json",
        "title": "pcbex fabrication authorization reservation ledger manifest",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "ledger_scope", "ledger_id"],
        "properties": {
            "schema_version": {
                "const": FABRICATION_AUTHORIZATION_RESERVATION_SCHEMA_VERSION
            },
            "ledger_scope": {"const": FABRICATION_AUTHORIZATION_RESERVATION_SCOPE},
            "ledger_id": digest_schema()
        }
    })
}

fn validate_reservable_report(report: &FabricationAuthorizationReport) -> Result<(), String> {
    if report.schema_version != FABRICATION_AUTHORIZATION_REPORT_SCHEMA_VERSION
        || report.status != "fabrication_authorized"
        || !report.fabrication_authorized
        || report.rejections != 0
        || !report.gate_failures.is_empty()
        || report.challenge_one_time_use_enforced
        || report.evidence.factory_receipt.quote_authenticity_verified
    {
        return Err(
            "only a freshly verified, authorized fabrication report may be reserved".into(),
        );
    }
    validate_slug(
        &report.scope.authorization_id,
        "fabrication authorization reservation authorization id",
    )?;
    validate_digest(
        &report.scope.challenge,
        "fabrication authorization reservation challenge",
    )?;
    if report.scope.quantity == 0 || report.scope.quantity > 1_000_000 {
        return Err(
            "fabrication authorization reservation quantity must be between 1 and 1000000".into(),
        );
    }
    if report.scope.currency.len() != 3
        || !report
            .scope
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err(
            "fabrication authorization reservation currency must contain three uppercase ASCII letters"
                .into(),
        );
    }
    if report.scope.maximum_total_minor_units == 0
        || report.scope.maximum_total_minor_units > 9_007_199_254_740_991
    {
        return Err(
            "fabrication authorization reservation maximum total is outside the closed bound"
                .into(),
        );
    }
    if !(2..=100).contains(&report.approvals) {
        return Err(
            "fabrication authorization reservation approval count must be between 2 and 100".into(),
        );
    }
    for (value, label) in [
        (
            report.evidence.pipeline.plan_sha256.as_str(),
            "fabrication authorization plan SHA-256",
        ),
        (
            report.evidence.pipeline.run_sha256.as_str(),
            "fabrication authorization run SHA-256",
        ),
        (
            report.evidence.manufacturing_package.sha256.as_str(),
            "fabrication authorization manufacturing package SHA-256",
        ),
        (
            report.evidence.factory_receipt.receipt.sha256.as_str(),
            "fabrication authorization factory receipt SHA-256",
        ),
        (
            report.evidence.policy_pack.source.sha256.as_str(),
            "fabrication authorization policy pack SHA-256",
        ),
    ] {
        validate_digest(value, label)?;
    }
    Ok(())
}

fn validate_exact_report_rendering(
    report: &FabricationAuthorizationReport,
    rendered_report: &[u8],
) -> Result<(), String> {
    if rendered_report.is_empty() || rendered_report.len() as u128 > u128::from(MAX_FILE_BYTES) {
        return Err(format!(
            "fabrication authorization report must contain 1 to {MAX_FILE_BYTES} bytes"
        ));
    }
    let mut expected = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("rendering fabrication authorization report: {error}"))?;
    expected.push(b'\n');
    if expected != rendered_report {
        return Err(
            "fabrication authorization report bytes are not the exact fresh report rendering"
                .into(),
        );
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

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn authorization_report_summary_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "fabrication_authorized",
            "authorization_id", "challenge", "quantity", "currency",
            "maximum_total_minor_units", "valid_from_unix", "expires_at_unix",
            "evaluated_at_unix", "approvals", "rejections", "gate_failure_count",
            "plan_sha256", "run_sha256", "manufacturing_package_sha256",
            "factory_receipt_sha256", "policy_pack_sha256",
            "quote_authenticity_verified", "challenge_one_time_use_enforced",
            "report_bytes", "report_sha256"
        ],
        "properties": {
            "schema_version": {"const": FABRICATION_AUTHORIZATION_REPORT_SCHEMA_VERSION},
            "status": {"const": "fabrication_authorized"},
            "fabrication_authorized": {"const": true},
            "authorization_id": {
                "type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
            },
            "challenge": digest_schema(),
            "quantity": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "maximum_total_minor_units": {
                "type": "integer", "minimum": 1, "maximum": 9_007_199_254_740_991_u64
            },
            "valid_from_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 0},
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "approvals": {"type": "integer", "minimum": 2, "maximum": 100},
            "rejections": {"const": 0},
            "gate_failure_count": {"const": 0},
            "plan_sha256": digest_schema(),
            "run_sha256": digest_schema(),
            "manufacturing_package_sha256": digest_schema(),
            "factory_receipt_sha256": digest_schema(),
            "policy_pack_sha256": digest_schema(),
            "quote_authenticity_verified": {"const": false},
            "challenge_one_time_use_enforced": {"const": false},
            "report_bytes": {
                "type": "integer", "minimum": 1, "maximum": MAX_FILE_BYTES
            },
            "report_sha256": digest_schema()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fabrication_authorization::{
        FabricationAuthorizationEvidence, FabricationAuthorizationScope,
        FabricationFactoryReceiptEvidence, FabricationPipelineEvidence,
        FabricationPolicyPackEvidence,
    };
    use crate::factory::FactoryProvider;
    use crate::policy_pack::parse_policy_pack;
    use pcbex_kicad::ExactArtifactIdentity;

    const LEDGER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CHALLENGE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn identity(byte: char) -> ExactArtifactIdentity {
        ExactArtifactIdentity {
            bytes: 1,
            sha256: byte.to_string().repeat(64),
        }
    }

    fn sample_report() -> FabricationAuthorizationReport {
        FabricationAuthorizationReport {
            schema_version: FABRICATION_AUTHORIZATION_REPORT_SCHEMA_VERSION,
            status: "fabrication_authorized".into(),
            evidence: FabricationAuthorizationEvidence {
                pipeline: FabricationPipelineEvidence {
                    plan_source: identity('1'),
                    plan_sha256: "2".repeat(64),
                    retained_report: identity('3'),
                    run_sha256: "4".repeat(64),
                },
                manufacturing_package: identity('5'),
                factory_receipt: FabricationFactoryReceiptEvidence {
                    receipt: identity('6'),
                    provider: FactoryProvider::Generic,
                    endpoint: "https://factory-secret.example/quote".into(),
                    quote_sha256: "7".repeat(64),
                    quote_authenticity_verified: false,
                },
                policy_pack: FabricationPolicyPackEvidence {
                    source: identity('8'),
                    canonical_sha256: "9".repeat(64),
                    id: "secret-policy".into(),
                    revision: 1,
                },
            },
            scope: FabricationAuthorizationScope {
                authorization_id: "fab-reservation".into(),
                challenge: CHALLENGE.into(),
                quantity: 25,
                currency: "USD".into(),
                maximum_total_minor_units: 125_000,
                valid_from_unix: 100,
                expires_at_unix: 200,
            },
            policy_pack: parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json"))
                .unwrap(),
            evaluated_at_unix: 150,
            approvals: 2,
            rejections: 0,
            members: Vec::new(),
            signed_approvals: Vec::new(),
            fabrication_authorized: true,
            gate_failures: Vec::new(),
            challenge_one_time_use_enforced: false,
        }
    }

    fn render_report(report: &FabricationAuthorizationReport) -> Vec<u8> {
        let mut rendered = serde_json::to_vec_pretty(report).unwrap();
        rendered.push(b'\n');
        rendered
    }

    #[test]
    fn marker_is_closed_path_free_and_preserves_the_exact_summary_contract() {
        let report = sample_report();
        let report_bytes = render_report(&report);
        let rendered =
            render_fabrication_authorization_reservation(&report, &report_bytes, LEDGER_ID)
                .unwrap();
        assert!(rendered.ends_with(b"\n"));
        assert!(rendered.len() <= MAX_FABRICATION_AUTHORIZATION_RESERVATION_BYTES);

        let value: Value = serde_json::from_slice(&rendered).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 5);
        assert_eq!(object["schema_version"], 1);
        assert_eq!(
            object["reservation_scope"],
            FABRICATION_AUTHORIZATION_RESERVATION_SCOPE
        );
        assert_eq!(
            object["status"],
            FABRICATION_AUTHORIZATION_RESERVATION_STATUS
        );
        assert_eq!(object["ledger_id"], LEDGER_ID);

        let summary = object["authorization_report_summary"].as_object().unwrap();
        assert_eq!(summary.len(), 23);
        let expected_summary_fields = [
            "schema_version",
            "status",
            "fabrication_authorized",
            "authorization_id",
            "challenge",
            "quantity",
            "currency",
            "maximum_total_minor_units",
            "valid_from_unix",
            "expires_at_unix",
            "evaluated_at_unix",
            "approvals",
            "rejections",
            "gate_failure_count",
            "plan_sha256",
            "run_sha256",
            "manufacturing_package_sha256",
            "factory_receipt_sha256",
            "policy_pack_sha256",
            "quote_authenticity_verified",
            "challenge_one_time_use_enforced",
            "report_bytes",
            "report_sha256",
        ];
        assert!(
            expected_summary_fields
                .iter()
                .all(|field| summary.contains_key(*field))
        );
        assert_eq!(summary["schema_version"], 1);
        assert_eq!(summary["status"], "fabrication_authorized");
        assert_eq!(summary["fabrication_authorized"], true);
        assert_eq!(summary["challenge"], CHALLENGE);
        assert_eq!(summary["rejections"], 0);
        assert_eq!(summary["gate_failure_count"], 0);
        assert_eq!(summary["quote_authenticity_verified"], false);
        assert_eq!(summary["challenge_one_time_use_enforced"], false);
        assert_eq!(summary["report_bytes"], report_bytes.len() as u64);
        assert_eq!(
            summary["report_sha256"],
            hex::encode(Sha256::digest(&report_bytes))
        );

        let text = std::str::from_utf8(&rendered).unwrap();
        for forbidden in [
            "factory-secret.example",
            "\"policy_pack\"",
            "\"signed_approvals\"",
            "\"reason\"",
            "\"ticket\"",
            "\"provider\"",
            "\"quote_sha256\"",
            "\"path\"",
        ] {
            assert!(
                !text.contains(forbidden),
                "leaked forbidden field {forbidden}"
            );
        }
    }

    #[test]
    fn marker_schema_has_exact_fields_and_never_claims_global_one_time_use() {
        let schema = fabrication_authorization_reservation_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        let properties = schema["properties"].as_object().unwrap();
        assert_eq!(properties.len(), 5);
        assert_eq!(
            schema["required"],
            json!([
                "schema_version",
                "reservation_scope",
                "status",
                "ledger_id",
                "authorization_report_summary"
            ])
        );
        assert!(!properties.contains_key("challenge_one_time_use_enforced"));
        assert_eq!(
            properties["reservation_scope"]["const"],
            FABRICATION_AUTHORIZATION_RESERVATION_SCOPE
        );
        assert_eq!(
            properties["status"]["const"],
            FABRICATION_AUTHORIZATION_RESERVATION_STATUS
        );
        let summary = properties["authorization_report_summary"]["properties"]
            .as_object()
            .unwrap();
        assert_eq!(summary.len(), 23);
        assert_eq!(
            properties["authorization_report_summary"]["required"]
                .as_array()
                .unwrap()
                .len(),
            23
        );
        assert_eq!(summary["status"]["const"], "fabrication_authorized");
        assert_eq!(summary["fabrication_authorized"]["const"], true);
        assert_eq!(summary["rejections"]["const"], 0);
        assert_eq!(summary["gate_failure_count"]["const"], 0);
        assert_eq!(summary["challenge_one_time_use_enforced"]["const"], false);
    }

    #[test]
    fn filename_is_fixed_and_rejects_non_digest_challenges() {
        assert_eq!(
            fabrication_authorization_reservation_filename(CHALLENGE).unwrap(),
            format!("fabrication-authorization-reservation-v1-{CHALLENGE}.json")
        );
        for invalid in [
            "a",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            "../../aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(fabrication_authorization_reservation_filename(invalid).is_err());
        }
    }

    #[test]
    fn marker_rejects_unauthorized_or_inexact_reports_and_malformed_ids() {
        let mut report = sample_report();
        let rendered = render_report(&report);
        assert!(
            render_fabrication_authorization_reservation(&report, &rendered, &"A".repeat(64))
                .is_err()
        );

        let mut changed = rendered.clone();
        changed.push(b' ');
        assert!(
            render_fabrication_authorization_reservation(&report, &changed, LEDGER_ID).is_err()
        );

        report.fabrication_authorized = false;
        assert!(
            render_fabrication_authorization_reservation(
                &report,
                &render_report(&report),
                LEDGER_ID
            )
            .is_err()
        );
        report.fabrication_authorized = true;
        report.status = "not_authorized".into();
        assert!(
            render_fabrication_authorization_reservation(
                &report,
                &render_report(&report),
                LEDGER_ID
            )
            .is_err()
        );
        report.status = "fabrication_authorized".into();
        report.rejections = 1;
        assert!(
            render_fabrication_authorization_reservation(
                &report,
                &render_report(&report),
                LEDGER_ID
            )
            .is_err()
        );
        report.rejections = 0;
        report.gate_failures.push("insufficient_quorum".into());
        assert!(
            render_fabrication_authorization_reservation(
                &report,
                &render_report(&report),
                LEDGER_ID
            )
            .is_err()
        );
        report.gate_failures.clear();
        report.challenge_one_time_use_enforced = true;
        assert!(
            render_fabrication_authorization_reservation(
                &report,
                &render_report(&report),
                LEDGER_ID
            )
            .is_err()
        );
        report.challenge_one_time_use_enforced = false;
        report.scope.challenge = "A".repeat(64);
        assert!(
            render_fabrication_authorization_reservation(
                &report,
                &render_report(&report),
                LEDGER_ID
            )
            .is_err()
        );
    }

    #[test]
    fn manifest_is_small_closed_duplicate_free_and_identity_pinned() {
        let manifest = format!(
            "{{\"schema_version\":1,\"ledger_scope\":\"{FABRICATION_AUTHORIZATION_RESERVATION_SCOPE}\",\"ledger_id\":\"{LEDGER_ID}\"}}\n"
        );
        validate_fabrication_authorization_reservation_ledger_manifest(
            manifest.as_bytes(),
            LEDGER_ID,
        )
        .unwrap();

        let duplicate = format!(
            "{{\"schema_version\":1,\"schema_version\":1,\"ledger_scope\":\"{FABRICATION_AUTHORIZATION_RESERVATION_SCOPE}\",\"ledger_id\":\"{LEDGER_ID}\"}}"
        );
        assert!(
            validate_fabrication_authorization_reservation_ledger_manifest(
                duplicate.as_bytes(),
                LEDGER_ID
            )
            .unwrap_err()
            .contains("duplicate")
        );
        let unknown = format!(
            "{{\"schema_version\":1,\"ledger_scope\":\"{FABRICATION_AUTHORIZATION_RESERVATION_SCOPE}\",\"ledger_id\":\"{LEDGER_ID}\",\"path\":\"secret\"}}"
        );
        assert!(
            validate_fabrication_authorization_reservation_ledger_manifest(
                unknown.as_bytes(),
                LEDGER_ID
            )
            .is_err()
        );
        assert!(
            validate_fabrication_authorization_reservation_ledger_manifest(
                manifest.as_bytes(),
                &"f".repeat(64)
            )
            .is_err()
        );
        assert!(
            validate_fabrication_authorization_reservation_ledger_manifest(
                manifest.as_bytes(),
                &"F".repeat(64)
            )
            .is_err()
        );
        let malformed_manifest_id = format!(
            "{{\"schema_version\":1,\"ledger_scope\":\"{FABRICATION_AUTHORIZATION_RESERVATION_SCOPE}\",\"ledger_id\":\"{}\"}}",
            "A".repeat(64)
        );
        assert!(
            validate_fabrication_authorization_reservation_ledger_manifest(
                malformed_manifest_id.as_bytes(),
                LEDGER_ID
            )
            .is_err()
        );
        let oversized = vec![
            b' ';
            usize::try_from(
                MAX_FABRICATION_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_BYTES + 1
            )
            .unwrap()
        ];
        assert!(
            validate_fabrication_authorization_reservation_ledger_manifest(&oversized, LEDGER_ID)
                .unwrap_err()
                .contains("byte limit")
        );
    }

    #[test]
    fn manifest_schema_is_closed_and_exact() {
        let schema = fabrication_authorization_reservation_ledger_manifest_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["required"],
            json!(["schema_version", "ledger_scope", "ledger_id"])
        );
        let properties = schema["properties"].as_object().unwrap();
        assert_eq!(properties.len(), 3);
        assert_eq!(properties["schema_version"]["const"], 1);
        assert_eq!(
            properties["ledger_scope"]["const"],
            FABRICATION_AUTHORIZATION_RESERVATION_SCOPE
        );
        assert_eq!(properties["ledger_id"]["pattern"], "^[0-9a-f]{64}$");
        assert_eq!(
            FABRICATION_AUTHORIZATION_RESERVATION_LEDGER_MANIFEST_FILENAME,
            ".pcbex-fabrication-authorization-reservation-ledger-v1.json"
        );
    }
}

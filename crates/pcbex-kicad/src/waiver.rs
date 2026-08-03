use super::{ElectricalReview, ElectricalSeverity, electrical::is_electrical_safety_floor_rule};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_WAIVERS: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalWaiver {
    pub id: String,
    pub finding_id: String,
    pub reason: String,
    pub approved_by: String,
    pub expires_on: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalWaiverSet {
    pub schema_version: u32,
    pub id: String,
    pub waivers: Vec<ElectricalWaiver>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElectricalFindingDisposition {
    Unwaived,
    Waived,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalWaiverDecision {
    pub finding_id: String,
    pub severity: ElectricalSeverity,
    pub disposition: ElectricalFindingDisposition,
    pub waiver_id: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalWaiverCounts {
    pub waived: usize,
    pub expired: usize,
    pub remaining_errors: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalWaiverReport {
    pub schema_version: u32,
    pub electrical_review_sha256: String,
    pub waiver_set_sha256: String,
    pub waiver_set_id: String,
    pub evaluated_on: String,
    pub approved: bool,
    pub counts: ElectricalWaiverCounts,
    pub decisions: Vec<ElectricalWaiverDecision>,
}

pub fn apply_electrical_waivers(
    review: &ElectricalReview,
    waiver_set: &ElectricalWaiverSet,
    evaluated_on: &str,
) -> Result<ElectricalWaiverReport, String> {
    if review.schema_version != 1 {
        return Err(format!(
            "unsupported electrical review schema version {}",
            review.schema_version
        ));
    }
    validate_waiver_set(waiver_set)?;
    validate_date(evaluated_on, "waiver evaluation date")?;

    let known_findings = review
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<BTreeSet<_>>();
    if let Some(unknown) = waiver_set
        .waivers
        .iter()
        .find(|waiver| !known_findings.contains(waiver.finding_id.as_str()))
    {
        return Err(format!(
            "waiver {} references unknown finding {}",
            unknown.id, unknown.finding_id
        ));
    }
    for waiver in &waiver_set.waivers {
        let finding = review
            .findings
            .iter()
            .find(|finding| finding.id == waiver.finding_id)
            .expect("unknown finding waivers are rejected above");
        if is_electrical_safety_floor_rule(&finding.rule) {
            return Err(format!(
                "immutable safety floor violation: waiver {} targets rule {}",
                waiver.id, finding.rule
            ));
        }
    }

    let review_bytes = serde_json::to_vec(review)
        .map_err(|error| format!("serializing electrical review: {error}"))?;
    let waiver_bytes = serde_json::to_vec(waiver_set)
        .map_err(|error| format!("serializing electrical waiver set: {error}"))?;
    let waivers_by_finding = waiver_set
        .waivers
        .iter()
        .map(|waiver| (waiver.finding_id.as_str(), waiver))
        .collect::<BTreeMap<_, _>>();
    let mut decisions = review
        .findings
        .iter()
        .map(|finding| {
            let waiver = waivers_by_finding.get(finding.id.as_str()).copied();
            let disposition = match waiver {
                Some(waiver) if evaluated_on <= waiver.expires_on.as_str() => {
                    ElectricalFindingDisposition::Waived
                }
                Some(_) => ElectricalFindingDisposition::Expired,
                None => ElectricalFindingDisposition::Unwaived,
            };
            ElectricalWaiverDecision {
                finding_id: finding.id.clone(),
                severity: finding.severity,
                disposition,
                waiver_id: waiver.map(|waiver| waiver.id.clone()),
            }
        })
        .collect::<Vec<_>>();
    decisions.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let counts = ElectricalWaiverCounts {
        waived: decisions
            .iter()
            .filter(|decision| decision.disposition == ElectricalFindingDisposition::Waived)
            .count(),
        expired: decisions
            .iter()
            .filter(|decision| decision.disposition == ElectricalFindingDisposition::Expired)
            .count(),
        remaining_errors: decisions
            .iter()
            .filter(|decision| {
                decision.severity == ElectricalSeverity::Error
                    && decision.disposition != ElectricalFindingDisposition::Waived
            })
            .count(),
    };
    Ok(ElectricalWaiverReport {
        schema_version: 1,
        electrical_review_sha256: hex_digest(&review_bytes),
        waiver_set_sha256: hex_digest(&waiver_bytes),
        waiver_set_id: waiver_set.id.clone(),
        evaluated_on: evaluated_on.into(),
        approved: counts.remaining_errors == 0,
        counts,
        decisions,
    })
}

fn validate_waiver_set(waiver_set: &ElectricalWaiverSet) -> Result<(), String> {
    if waiver_set.schema_version != 1 {
        return Err(format!(
            "unsupported electrical waiver-set schema version {}",
            waiver_set.schema_version
        ));
    }
    if waiver_set.id.trim().is_empty() {
        return Err("electrical waiver-set id must not be blank".into());
    }
    if waiver_set.waivers.len() > MAX_WAIVERS {
        return Err(format!(
            "electrical waiver set exceeds the {MAX_WAIVERS} waiver limit"
        ));
    }
    let mut ids = BTreeSet::new();
    let mut findings = BTreeSet::new();
    for waiver in &waiver_set.waivers {
        if waiver.id.trim().is_empty()
            || waiver.reason.trim().is_empty()
            || waiver.approved_by.trim().is_empty()
        {
            return Err("waiver id, reason, and approved_by must not be blank".into());
        }
        if !is_finding_id(&waiver.finding_id) {
            return Err(format!(
                "waiver {} has invalid finding id {}",
                waiver.id, waiver.finding_id
            ));
        }
        validate_date(&waiver.expires_on, "waiver expiration date")?;
        if !ids.insert(waiver.id.as_str()) {
            return Err(format!("duplicate waiver id {}", waiver.id));
        }
        if !findings.insert(waiver.finding_id.as_str()) {
            return Err(format!(
                "multiple waivers target finding {}",
                waiver.finding_id
            ));
        }
    }
    Ok(())
}

fn validate_date(value: &str, label: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(format!("{label} must use YYYY-MM-DD"));
    }
    let year = value[0..4]
        .parse::<u32>()
        .map_err(|_| format!("{label} must use YYYY-MM-DD"))?;
    let month = value[5..7]
        .parse::<u32>()
        .map_err(|_| format!("{label} must use YYYY-MM-DD"))?;
    let day = value[8..10]
        .parse::<u32>()
        .map_err(|_| format!("{label} must use YYYY-MM-DD"))?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > maximum {
        return Err(format!("{label} is not a valid calendar date"));
    }
    Ok(())
}

fn is_finding_id(value: &str) -> bool {
    value.strip_prefix("pcbex-er-").is_some_and(|suffix| {
        suffix.len() == 16
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn electrical_waiver_set_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/electrical-waiver-set-v1.json",
        "title": "pcbex electrical waiver set",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "id", "waivers"],
        "properties": {
            "schema_version": {"const": 1},
            "id": {"type": "string", "minLength": 1},
            "waivers": {"type": "array", "items": {"$ref": "#/$defs/waiver"}}
        },
        "$defs": {
            "waiver": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "finding_id", "reason", "approved_by", "expires_on"],
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "finding_id": {"type": "string", "pattern": "^pcbex-er-[0-9a-f]{16}$"},
                    "reason": {"type": "string", "minLength": 1},
                    "approved_by": {"type": "string", "minLength": 1},
                    "expires_on": {"type": "string", "format": "date"}
                }
            }
        }
    })
}

pub fn electrical_waiver_report_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/electrical-waiver-report-v1.json",
        "title": "pcbex electrical waiver report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "electrical_review_sha256", "waiver_set_sha256",
            "waiver_set_id", "evaluated_on", "approved", "counts", "decisions"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "electrical_review_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "waiver_set_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "waiver_set_id": {"type": "string", "minLength": 1},
            "evaluated_on": {"type": "string", "format": "date"},
            "approved": {"type": "boolean"},
            "counts": {"$ref": "#/$defs/counts"},
            "decisions": {"type": "array", "items": {"$ref": "#/$defs/decision"}}
        },
        "$defs": {
            "counts": {
                "type": "object",
                "additionalProperties": false,
                "required": ["waived", "expired", "remaining_errors"],
                "properties": {
                    "waived": {"type": "integer", "minimum": 0},
                    "expired": {"type": "integer", "minimum": 0},
                    "remaining_errors": {"type": "integer", "minimum": 0}
                }
            },
            "decision": {
                "type": "object",
                "additionalProperties": false,
                "required": ["finding_id", "severity", "disposition", "waiver_id"],
                "properties": {
                    "finding_id": {"type": "string", "pattern": "^pcbex-er-[0-9a-f]{16}$"},
                    "severity": {"enum": ["info", "warning", "error"]},
                    "disposition": {"enum": ["unwaived", "waived", "expired"]},
                    "waiver_id": {"type": ["string", "null"], "minLength": 1}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ElectricalPolicy, check_schematic, import_schematic};

    const SOURCE: &str = include_str!("../../../examples/simple.kicad_sch");

    fn review() -> ElectricalReview {
        check_schematic(
            &import_schematic(SOURCE).unwrap(),
            &ElectricalPolicy::default(),
        )
        .unwrap()
    }

    fn waiver_set(review: &ElectricalReview) -> ElectricalWaiverSet {
        ElectricalWaiverSet {
            schema_version: 1,
            id: "prototype-waivers".into(),
            waivers: review
                .findings
                .iter()
                .filter(|finding| finding.severity == ElectricalSeverity::Error)
                .map(|finding| ElectricalWaiver {
                    id: format!("waive-{}", finding.id),
                    finding_id: finding.id.clone(),
                    reason: "Accepted for the isolated prototype build".into(),
                    approved_by: "hardware-lead".into(),
                    expires_on: "2026-08-31".into(),
                })
                .collect(),
        }
    }

    fn non_floor_error_review() -> ElectricalReview {
        ElectricalReview {
            schema_version: 1,
            schematic_sha256: "a".repeat(64),
            policy_sha256: "b".repeat(64),
            policy_id: "non-floor-error".into(),
            approved: false,
            counts: crate::ElectricalFindingCounts {
                errors: 1,
                warnings: 0,
                info: 0,
            },
            findings: vec![crate::ElectricalFinding {
                id: "pcbex-er-1111111111111111".into(),
                rule: "input_not_driven".into(),
                severity: ElectricalSeverity::Error,
                message: "promoted input rule".into(),
                net_id: None,
                symbols: Vec::new(),
                pins: Vec::new(),
            }],
        }
    }

    #[test]
    fn floor_rule_waivers_are_rejected() {
        let review = review();
        let waivers = waiver_set(&review);
        assert!(!waivers.waivers.is_empty());
        let error = apply_electrical_waivers(&review, &waivers, "2026-08-31").unwrap_err();
        assert!(error.contains("immutable safety floor"));
    }

    #[test]
    fn non_floor_error_waivers_approve_and_expired_waivers_fail_closed() {
        let review = non_floor_error_review();
        let waivers = waiver_set(&review);
        let active = apply_electrical_waivers(&review, &waivers, "2026-08-31").unwrap();
        assert!(active.approved);
        assert!(active.counts.waived > 0);
        assert_eq!(active.counts.remaining_errors, 0);

        let expired = apply_electrical_waivers(&review, &waivers, "2026-09-01").unwrap();
        assert!(!expired.approved);
        assert_eq!(expired.counts.expired, waivers.waivers.len());
        assert!(expired.counts.remaining_errors > 0);
    }

    #[test]
    fn malformed_duplicate_and_unknown_waivers_fail_closed() {
        let review = review();
        let mut waivers = waiver_set(&review);
        waivers.waivers[0].expires_on = "2026-02-30".into();
        assert!(apply_electrical_waivers(&review, &waivers, "2026-01-01").is_err());

        let mut waivers = waiver_set(&review);
        let duplicate = waivers.waivers[0].clone();
        waivers.waivers.push(duplicate);
        assert!(apply_electrical_waivers(&review, &waivers, "2026-01-01").is_err());

        let mut waivers = waiver_set(&review);
        waivers.waivers[0].finding_id = "pcbex-er-0000000000000000".into();
        assert!(apply_electrical_waivers(&review, &waivers, "2026-01-01").is_err());
    }

    #[test]
    fn waiver_schemas_close_every_object() {
        for schema in [
            electrical_waiver_set_json_schema(),
            electrical_waiver_report_json_schema(),
        ] {
            assert_eq!(schema["additionalProperties"], false);
            for definition in schema["$defs"].as_object().unwrap().values() {
                assert_eq!(definition["additionalProperties"], false);
            }
        }
    }
}

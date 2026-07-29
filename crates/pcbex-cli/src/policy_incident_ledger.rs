use crate::policy_deployment_rollback::{
    PolicyDeploymentRollbackState, validate_policy_deployment_rollback_state,
};
use crate::policy_deployment_verification::{
    PolicyDeploymentVerificationReport, validate_policy_deployment_verification,
};
use crate::policy_rollback_recovery::{
    PolicyRollbackRecoveryReport, RollbackIncidentClosureState, validate_policy_rollback_recovery,
    validate_rollback_incident_closure,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write;

pub const POLICY_INCIDENT_LEDGER_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_INCIDENTS: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyIncidentEntry {
    pub schema_version: u32,
    pub sequence: u64,
    pub previous_entry_sha256: Option<String>,
    pub closure_sha256: String,
    pub rollback_sha256: String,
    pub recovery_sha256: String,
    pub failed_verification_sha256: String,
    pub policy_pack_id: String,
    pub failed_revision: u32,
    pub failed_policy_pack_sha256: String,
    pub restored_revision: u32,
    pub restored_policy_pack_sha256: String,
    pub detected_at_unix: u64,
    pub rollback_applied_at_unix: u64,
    pub recovery_verified_at_unix: u64,
    pub closed_at_unix: u64,
    pub time_to_rollback_seconds: u64,
    pub time_to_recovery_seconds: u64,
    pub time_to_close_seconds: u64,
    pub ticket: String,
    pub operator_id: String,
    pub entry_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyIncidentRevisionMetric {
    pub failed_revision: u32,
    pub failed_policy_pack_sha256: String,
    pub incidents: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyIncidentLedger {
    pub schema_version: u32,
    pub policy_pack_id: String,
    pub generation: u64,
    pub entry_count: u64,
    pub head_sha256: String,
    pub suspension_threshold: u32,
    pub incident_revisions: Vec<PolicyIncidentRevisionMetric>,
    pub suspension_candidates: Vec<PolicyIncidentRevisionMetric>,
    pub total_time_to_rollback_seconds: u64,
    pub maximum_time_to_rollback_seconds: u64,
    pub total_time_to_recovery_seconds: u64,
    pub maximum_time_to_recovery_seconds: u64,
    pub total_time_to_close_seconds: u64,
    pub maximum_time_to_close_seconds: u64,
    pub requires_human_suspension_review: bool,
    pub automatic_policy_suspension: bool,
    pub entries: Vec<PolicyIncidentEntry>,
}

#[derive(Serialize)]
struct EntryPayload<'a> {
    domain: &'static str,
    sequence: u64,
    previous_entry_sha256: Option<&'a str>,
    closure_sha256: &'a str,
    rollback_sha256: &'a str,
    recovery_sha256: &'a str,
    failed_verification_sha256: &'a str,
    policy_pack_id: &'a str,
    failed_revision: u32,
    failed_policy_pack_sha256: &'a str,
    restored_revision: u32,
    restored_policy_pack_sha256: &'a str,
    detected_at_unix: u64,
    rollback_applied_at_unix: u64,
    recovery_verified_at_unix: u64,
    closed_at_unix: u64,
    time_to_rollback_seconds: u64,
    time_to_recovery_seconds: u64,
    time_to_close_seconds: u64,
    ticket: &'a str,
    operator_id: &'a str,
}

pub fn append_policy_incident(
    baseline: Option<&PolicyIncidentLedger>,
    rollback: &PolicyDeploymentRollbackState,
    failed_verification: &PolicyDeploymentVerificationReport,
    recovery: &PolicyRollbackRecoveryReport,
    closure: &RollbackIncidentClosureState,
    suspension_threshold: u32,
) -> Result<PolicyIncidentLedger, String> {
    validate_policy_deployment_rollback_state(rollback)?;
    validate_policy_deployment_verification(failed_verification)?;
    validate_policy_rollback_recovery(recovery)?;
    validate_rollback_incident_closure(closure)?;
    if !(2..=100).contains(&suspension_threshold) {
        return Err("policy incident suspension threshold must be 2 to 100".into());
    }
    let rollback_sha256 = normalized_sha256(rollback, "rollback state")?;
    let failed_verification_sha256 =
        normalized_sha256(failed_verification, "failed deployment verification")?;
    let recovery_sha256 = normalized_sha256(recovery, "rollback recovery")?;
    let closure_sha256 = normalized_sha256(closure, "rollback incident closure")?;
    if rollback.verification_sha256 != failed_verification_sha256
        || recovery.rollback_state_sha256 != rollback_sha256
        || recovery.failed_verification_sha256 != failed_verification_sha256
        || closure.rollback_state_sha256 != rollback_sha256
        || closure.recovery_sha256 != recovery_sha256
        || failed_verification.deployment_verified
        || !failed_verification.rollback_required
        || !recovery.recovery_verified
        || !closure.incident_closed
    {
        return Err("policy incident evidence does not form one closed rollback chain".into());
    }
    if rollback.policy_pack_id != recovery.policy_pack_id
        || rollback.policy_pack_id != closure.policy_pack_id
        || rollback.failed_revision != recovery.failed_revision
        || rollback.failed_revision != closure.failed_revision
        || rollback.active_revision != recovery.restored_revision
        || rollback.active_revision != closure.active_revision
        || rollback.active_policy_pack_sha256 != recovery.restored_policy_pack_sha256
        || rollback.active_policy_pack_sha256 != closure.active_policy_pack_sha256
    {
        return Err("policy incident identity differs across retained evidence".into());
    }
    let detected_at_unix = failed_verification.verified_at_unix;
    if detected_at_unix > rollback.recorded_at_unix
        || rollback.recorded_at_unix > recovery.verified_at_unix
        || recovery.verified_at_unix > closure.closed_at_unix
    {
        return Err("policy incident evidence timestamps are not monotonic".into());
    }
    let (mut entries, generation, previous_entry_sha256) = match baseline {
        Some(baseline) => {
            validate_policy_incident_ledger(baseline)?;
            if baseline.policy_pack_id != rollback.policy_pack_id
                || baseline.suspension_threshold != suspension_threshold
            {
                return Err("policy incident ledger identity or threshold changed".into());
            }
            if baseline.entries.iter().any(|entry| {
                entry.closure_sha256 == closure_sha256 || entry.recovery_sha256 == recovery_sha256
            }) {
                return Err("policy incident is already retained in the ledger".into());
            }
            (
                baseline.entries.clone(),
                baseline
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| "policy incident ledger generation overflowed".to_string())?,
                Some(baseline.head_sha256.clone()),
            )
        }
        None => (Vec::new(), 1, None),
    };
    if entries.len() >= MAXIMUM_INCIDENTS {
        return Err("policy incident ledger reached its entry limit".into());
    }
    let sequence = entries.len() as u64 + 1;
    let mut entry = PolicyIncidentEntry {
        schema_version: POLICY_INCIDENT_LEDGER_SCHEMA_VERSION,
        sequence,
        previous_entry_sha256,
        closure_sha256,
        rollback_sha256,
        recovery_sha256,
        failed_verification_sha256,
        policy_pack_id: rollback.policy_pack_id.clone(),
        failed_revision: rollback.failed_revision,
        failed_policy_pack_sha256: rollback.failed_policy_pack_sha256.clone(),
        restored_revision: rollback.active_revision,
        restored_policy_pack_sha256: rollback.active_policy_pack_sha256.clone(),
        detected_at_unix,
        rollback_applied_at_unix: rollback.recorded_at_unix,
        recovery_verified_at_unix: recovery.verified_at_unix,
        closed_at_unix: closure.closed_at_unix,
        time_to_rollback_seconds: rollback.recorded_at_unix - detected_at_unix,
        time_to_recovery_seconds: recovery.verified_at_unix - detected_at_unix,
        time_to_close_seconds: closure.closed_at_unix - detected_at_unix,
        ticket: closure.ticket.clone(),
        operator_id: closure.operator_id.clone(),
        entry_sha256: String::new(),
    };
    entry.entry_sha256 = entry_sha256(&entry)?;
    entries.push(entry);
    let mut ledger = metrics(
        rollback.policy_pack_id.clone(),
        generation,
        suspension_threshold,
        entries,
    )?;
    validate_policy_incident_ledger(&ledger)?;
    ledger.entries.shrink_to_fit();
    Ok(ledger)
}

fn metrics(
    policy_pack_id: String,
    generation: u64,
    suspension_threshold: u32,
    entries: Vec<PolicyIncidentEntry>,
) -> Result<PolicyIncidentLedger, String> {
    let mut revisions = BTreeMap::<(u32, String), u32>::new();
    let mut total_rollback = 0_u64;
    let mut total_recovery = 0_u64;
    let mut total_close = 0_u64;
    let mut maximum_rollback = 0_u64;
    let mut maximum_recovery = 0_u64;
    let mut maximum_close = 0_u64;
    for entry in &entries {
        *revisions
            .entry((
                entry.failed_revision,
                entry.failed_policy_pack_sha256.clone(),
            ))
            .or_default() += 1;
        total_rollback = total_rollback
            .checked_add(entry.time_to_rollback_seconds)
            .ok_or_else(|| "policy incident rollback duration overflowed".to_string())?;
        total_recovery = total_recovery
            .checked_add(entry.time_to_recovery_seconds)
            .ok_or_else(|| "policy incident recovery duration overflowed".to_string())?;
        total_close = total_close
            .checked_add(entry.time_to_close_seconds)
            .ok_or_else(|| "policy incident closure duration overflowed".to_string())?;
        maximum_rollback = maximum_rollback.max(entry.time_to_rollback_seconds);
        maximum_recovery = maximum_recovery.max(entry.time_to_recovery_seconds);
        maximum_close = maximum_close.max(entry.time_to_close_seconds);
    }
    let incident_revisions = revisions
        .into_iter()
        .map(
            |((failed_revision, failed_policy_pack_sha256), incidents)| {
                PolicyIncidentRevisionMetric {
                    failed_revision,
                    failed_policy_pack_sha256,
                    incidents,
                }
            },
        )
        .collect::<Vec<_>>();
    let suspension_candidates = incident_revisions
        .iter()
        .filter(|metric| metric.incidents >= suspension_threshold)
        .cloned()
        .collect::<Vec<_>>();
    let head_sha256 = entries
        .last()
        .map(|entry| entry.entry_sha256.clone())
        .ok_or_else(|| "policy incident ledger cannot be empty".to_string())?;
    Ok(PolicyIncidentLedger {
        schema_version: POLICY_INCIDENT_LEDGER_SCHEMA_VERSION,
        policy_pack_id,
        generation,
        entry_count: entries.len() as u64,
        head_sha256,
        suspension_threshold,
        incident_revisions,
        requires_human_suspension_review: !suspension_candidates.is_empty(),
        suspension_candidates,
        total_time_to_rollback_seconds: total_rollback,
        maximum_time_to_rollback_seconds: maximum_rollback,
        total_time_to_recovery_seconds: total_recovery,
        maximum_time_to_recovery_seconds: maximum_recovery,
        total_time_to_close_seconds: total_close,
        maximum_time_to_close_seconds: maximum_close,
        automatic_policy_suspension: false,
        entries,
    })
}

pub fn parse_policy_incident_ledger(source: &str) -> Result<PolicyIncidentLedger, String> {
    let ledger = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy incident ledger JSON: {error}"))?;
    validate_policy_incident_ledger(&ledger)?;
    Ok(ledger)
}

pub fn validate_policy_incident_ledger(ledger: &PolicyIncidentLedger) -> Result<(), String> {
    if ledger.schema_version != POLICY_INCIDENT_LEDGER_SCHEMA_VERSION
        || ledger.entries.is_empty()
        || ledger.entries.len() > MAXIMUM_INCIDENTS
        || ledger.entry_count != ledger.entries.len() as u64
        || ledger.generation != ledger.entry_count
        || !(2..=100).contains(&ledger.suspension_threshold)
        || ledger.automatic_policy_suspension
    {
        return Err("policy incident ledger governance boundary is invalid".into());
    }
    validate_slug("policy pack id", &ledger.policy_pack_id)?;
    validate_digest(&ledger.head_sha256)?;
    let mut closures = HashSet::new();
    let mut recoveries = HashSet::new();
    for (index, entry) in ledger.entries.iter().enumerate() {
        let sequence = index as u64 + 1;
        let expected_previous = index
            .checked_sub(1)
            .map(|previous| ledger.entries[previous].entry_sha256.as_str());
        if entry.schema_version != POLICY_INCIDENT_LEDGER_SCHEMA_VERSION
            || entry.sequence != sequence
            || entry.previous_entry_sha256.as_deref() != expected_previous
            || entry.policy_pack_id != ledger.policy_pack_id
            || entry.failed_revision <= entry.restored_revision
            || entry.detected_at_unix > entry.rollback_applied_at_unix
            || entry.rollback_applied_at_unix > entry.recovery_verified_at_unix
            || entry.recovery_verified_at_unix > entry.closed_at_unix
            || entry.time_to_rollback_seconds
                != entry.rollback_applied_at_unix - entry.detected_at_unix
            || entry.time_to_recovery_seconds
                != entry.recovery_verified_at_unix - entry.detected_at_unix
            || entry.time_to_close_seconds != entry.closed_at_unix - entry.detected_at_unix
            || entry.entry_sha256 != entry_sha256(entry)?
            || !closures.insert(entry.closure_sha256.as_str())
            || !recoveries.insert(entry.recovery_sha256.as_str())
        {
            return Err("policy incident ledger entry chain is invalid".into());
        }
        for digest in [
            &entry.closure_sha256,
            &entry.rollback_sha256,
            &entry.recovery_sha256,
            &entry.failed_verification_sha256,
            &entry.failed_policy_pack_sha256,
            &entry.restored_policy_pack_sha256,
            &entry.entry_sha256,
        ] {
            validate_digest(digest)?;
        }
        validate_slug("policy incident operator", &entry.operator_id)?;
        validate_text(&entry.ticket)?;
    }
    if ledger.head_sha256 != ledger.entries.last().unwrap().entry_sha256 {
        return Err("policy incident ledger head does not match its final entry".into());
    }
    let expected = metrics(
        ledger.policy_pack_id.clone(),
        ledger.generation,
        ledger.suspension_threshold,
        ledger.entries.clone(),
    )?;
    if expected.incident_revisions != ledger.incident_revisions
        || expected.suspension_candidates != ledger.suspension_candidates
        || expected.total_time_to_rollback_seconds != ledger.total_time_to_rollback_seconds
        || expected.maximum_time_to_rollback_seconds != ledger.maximum_time_to_rollback_seconds
        || expected.total_time_to_recovery_seconds != ledger.total_time_to_recovery_seconds
        || expected.maximum_time_to_recovery_seconds != ledger.maximum_time_to_recovery_seconds
        || expected.total_time_to_close_seconds != ledger.total_time_to_close_seconds
        || expected.maximum_time_to_close_seconds != ledger.maximum_time_to_close_seconds
        || expected.requires_human_suspension_review != ledger.requires_human_suspension_review
    {
        return Err("policy incident ledger metrics are inconsistent".into());
    }
    Ok(())
}

pub fn render_policy_incident_ledger_summary(ledger: &PolicyIncidentLedger) -> String {
    let mut summary = format!(
        "# Policy incident ledger\n\n\
         - Incidents: `{}`\n\
         - Head: `{}`\n\
         - Suspension threshold: `{}`\n\
         - Human suspension review required: `{}`\n\
         - Automatic policy suspension: `false`\n\
         - Maximum time to rollback: `{}s`\n\
         - Maximum time to recovery: `{}s`\n\
         - Maximum time to closure: `{}s`\n",
        ledger.entry_count,
        ledger.head_sha256,
        ledger.suspension_threshold,
        ledger.requires_human_suspension_review,
        ledger.maximum_time_to_rollback_seconds,
        ledger.maximum_time_to_recovery_seconds,
        ledger.maximum_time_to_close_seconds
    );
    let _ = writeln!(
        summary,
        "\n| Failed revision | Incidents | Suspension candidate |\n|---:|---:|---:|"
    );
    for metric in &ledger.incident_revisions {
        let _ = writeln!(
            summary,
            "| {} | {} | `{}` |",
            metric.failed_revision,
            metric.incidents,
            metric.incidents >= ledger.suspension_threshold
        );
    }
    summary
}

pub fn policy_incident_ledger_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let metric = json!({
        "type": "object", "additionalProperties": false,
        "required": ["failed_revision", "failed_policy_pack_sha256", "incidents"],
        "properties": {
            "failed_revision": {"type": "integer", "minimum": 2},
            "failed_policy_pack_sha256": digest,
            "incidents": {"type": "integer", "minimum": 1}
        }
    });
    let entry = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "sequence", "previous_entry_sha256", "closure_sha256",
            "rollback_sha256", "recovery_sha256", "failed_verification_sha256",
            "policy_pack_id", "failed_revision", "failed_policy_pack_sha256",
            "restored_revision", "restored_policy_pack_sha256", "detected_at_unix",
            "rollback_applied_at_unix", "recovery_verified_at_unix", "closed_at_unix",
            "time_to_rollback_seconds", "time_to_recovery_seconds", "time_to_close_seconds",
            "ticket", "operator_id", "entry_sha256"
        ],
        "properties": {
            "schema_version": {"const": POLICY_INCIDENT_LEDGER_SCHEMA_VERSION},
            "sequence": {"type": "integer", "minimum": 1},
            "previous_entry_sha256": {"oneOf": [digest, {"type": "null"}]},
            "closure_sha256": digest, "rollback_sha256": digest,
            "recovery_sha256": digest, "failed_verification_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "failed_revision": {"type": "integer", "minimum": 2},
            "failed_policy_pack_sha256": digest,
            "restored_revision": {"type": "integer", "minimum": 1},
            "restored_policy_pack_sha256": digest,
            "detected_at_unix": {"type": "integer", "minimum": 0},
            "rollback_applied_at_unix": {"type": "integer", "minimum": 0},
            "recovery_verified_at_unix": {"type": "integer", "minimum": 0},
            "closed_at_unix": {"type": "integer", "minimum": 0},
            "time_to_rollback_seconds": {"type": "integer", "minimum": 0},
            "time_to_recovery_seconds": {"type": "integer", "minimum": 0},
            "time_to_close_seconds": {"type": "integer", "minimum": 0},
            "ticket": {"type": "string", "minLength": 1, "maxLength": 256},
            "operator_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
            "entry_sha256": digest
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-incident-ledger-v1.json",
        "title": "pcbex append-only policy incident ledger",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "policy_pack_id", "generation", "entry_count",
            "head_sha256", "suspension_threshold", "incident_revisions",
            "suspension_candidates", "total_time_to_rollback_seconds",
            "maximum_time_to_rollback_seconds", "total_time_to_recovery_seconds",
            "maximum_time_to_recovery_seconds", "total_time_to_close_seconds",
            "maximum_time_to_close_seconds", "requires_human_suspension_review",
            "automatic_policy_suspension", "entries"
        ],
        "properties": {
            "schema_version": {"const": POLICY_INCIDENT_LEDGER_SCHEMA_VERSION},
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "generation": {"type": "integer", "minimum": 1},
            "entry_count": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_INCIDENTS},
            "head_sha256": digest,
            "suspension_threshold": {"type": "integer", "minimum": 2, "maximum": 100},
            "incident_revisions": {"type": "array", "items": metric},
            "suspension_candidates": {"type": "array", "items": metric},
            "total_time_to_rollback_seconds": {"type": "integer", "minimum": 0},
            "maximum_time_to_rollback_seconds": {"type": "integer", "minimum": 0},
            "total_time_to_recovery_seconds": {"type": "integer", "minimum": 0},
            "maximum_time_to_recovery_seconds": {"type": "integer", "minimum": 0},
            "total_time_to_close_seconds": {"type": "integer", "minimum": 0},
            "maximum_time_to_close_seconds": {"type": "integer", "minimum": 0},
            "requires_human_suspension_review": {"type": "boolean"},
            "automatic_policy_suspension": {"const": false},
            "entries": {"type": "array", "minItems": 1, "maxItems": MAXIMUM_INCIDENTS, "items": entry}
        }
    })
}

fn entry_sha256(entry: &PolicyIncidentEntry) -> Result<String, String> {
    normalized_sha256(
        &EntryPayload {
            domain: "pcbex-policy-incident-ledger-entry-v1",
            sequence: entry.sequence,
            previous_entry_sha256: entry.previous_entry_sha256.as_deref(),
            closure_sha256: &entry.closure_sha256,
            rollback_sha256: &entry.rollback_sha256,
            recovery_sha256: &entry.recovery_sha256,
            failed_verification_sha256: &entry.failed_verification_sha256,
            policy_pack_id: &entry.policy_pack_id,
            failed_revision: entry.failed_revision,
            failed_policy_pack_sha256: &entry.failed_policy_pack_sha256,
            restored_revision: entry.restored_revision,
            restored_policy_pack_sha256: &entry.restored_policy_pack_sha256,
            detected_at_unix: entry.detected_at_unix,
            rollback_applied_at_unix: entry.rollback_applied_at_unix,
            recovery_verified_at_unix: entry.recovery_verified_at_unix,
            closed_at_unix: entry.closed_at_unix,
            time_to_rollback_seconds: entry.time_to_rollback_seconds,
            time_to_recovery_seconds: entry.time_to_recovery_seconds,
            time_to_close_seconds: entry.time_to_close_seconds,
            ticket: &entry.ticket,
            operator_id: &entry.operator_id,
        },
        "policy incident entry",
    )
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("invalid lowercase SHA-256 digest".into())
    }
}

fn validate_slug(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        Err(format!("{label} is invalid"))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 256 || value.contains(['\0', '\r']) {
        Err("policy incident ticket is invalid".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn entry(sequence: u64, previous: Option<String>, offset: u64) -> PolicyIncidentEntry {
        let mut entry = PolicyIncidentEntry {
            schema_version: 1,
            sequence,
            previous_entry_sha256: previous,
            closure_sha256: digest(if sequence == 1 { 'a' } else { 'b' }),
            rollback_sha256: digest(if sequence == 1 { 'c' } else { 'd' }),
            recovery_sha256: digest(if sequence == 1 { 'e' } else { 'f' }),
            failed_verification_sha256: digest(if sequence == 1 { '1' } else { '2' }),
            policy_pack_id: "acme-production-v1".into(),
            failed_revision: 3,
            failed_policy_pack_sha256: digest('3'),
            restored_revision: 2,
            restored_policy_pack_sha256: digest('4'),
            detected_at_unix: offset,
            rollback_applied_at_unix: offset + 2,
            recovery_verified_at_unix: offset + 5,
            closed_at_unix: offset + 8,
            time_to_rollback_seconds: 2,
            time_to_recovery_seconds: 5,
            time_to_close_seconds: 8,
            ticket: format!("HW-{sequence}"),
            operator_id: "incident-operator".into(),
            entry_sha256: String::new(),
        };
        entry.entry_sha256 = entry_sha256(&entry).unwrap();
        entry
    }

    #[test]
    fn schema_closes_ledger_metrics_and_entries() {
        let schema = policy_incident_ledger_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["incident_revisions"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["entries"]["items"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn ledger_detects_repeated_revisions_and_chain_tampering() {
        let first = entry(1, None, 100);
        let second = entry(2, Some(first.entry_sha256.clone()), 200);
        let ledger = metrics("acme-production-v1".into(), 2, 2, vec![first, second]).unwrap();
        validate_policy_incident_ledger(&ledger).unwrap();
        assert!(ledger.requires_human_suspension_review);
        assert!(!ledger.automatic_policy_suspension);
        assert_eq!(ledger.suspension_candidates[0].incidents, 2);

        let mut tampered = ledger.clone();
        tampered.entries[0].time_to_close_seconds += 1;
        assert!(
            validate_policy_incident_ledger(&tampered)
                .unwrap_err()
                .contains("entry chain")
        );

        let mut truncated = ledger.clone();
        truncated.entries.pop();
        assert!(validate_policy_incident_ledger(&truncated).is_err());

        let mut reversed = ledger;
        reversed.entries.reverse();
        assert!(
            validate_policy_incident_ledger(&reversed)
                .unwrap_err()
                .contains("entry chain")
        );
    }
}

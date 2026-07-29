use crate::policy_remediation::{
    PolicyRemediationState, policy_remediation_state_json_schema, validate_policy_remediation_state,
};
use crate::policy_suspension::{
    PolicySuspensionDecision, PolicySuspensionState, policy_suspension_state_json_schema,
    validate_policy_suspension_state,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;

pub const POLICY_LIFECYCLE_LEDGER_SCHEMA_VERSION: u32 = 1;
pub const POLICY_LIFECYCLE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_EVENTS: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLifecycleEventType {
    SuspensionDecision,
    Remediation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLifecycleStatus {
    ContinuedUnderReview,
    AwaitingRemediation,
    Released,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleEntry {
    pub schema_version: u32,
    pub sequence: u64,
    pub previous_entry_sha256: Option<String>,
    pub event_type: PolicyLifecycleEventType,
    pub policy_pack_id: String,
    pub suspension_state_sha256: Option<String>,
    pub remediation_state_sha256: Option<String>,
    pub suspension_state: Option<Box<PolicySuspensionState>>,
    pub remediation_state: Option<Box<PolicyRemediationState>>,
    pub recorded_at_unix: u64,
    pub entry_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleRecord {
    pub suspension_state_sha256: String,
    pub failed_revision: u32,
    pub failed_policy_pack_sha256: String,
    pub decision: PolicySuspensionDecision,
    pub status: PolicyLifecycleStatus,
    pub decision_sequence: u64,
    pub remediation_state_sha256: Option<String>,
    pub remediation_revision: Option<u32>,
    pub remediation_policy_pack_sha256: Option<String>,
    pub resolution_sequence: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLedger {
    pub schema_version: u32,
    pub policy_pack_id: String,
    pub generation: u64,
    pub entry_count: u64,
    pub head_sha256: String,
    pub awaiting_remediation: u64,
    pub released: u64,
    pub superseded: u64,
    pub continued_under_review: u64,
    pub records: Vec<PolicyLifecycleRecord>,
    pub entries: Vec<PolicyLifecycleEntry>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleSnapshot {
    pub schema_version: u32,
    pub policy_pack_id: String,
    pub generation: u64,
    pub ledger_sha256: String,
    pub ledger_head_sha256: String,
    pub generation_head_sha256: String,
    pub awaiting_remediation: u64,
    pub released: u64,
    pub superseded: u64,
    pub continued_under_review: u64,
    pub records: Vec<PolicyLifecycleRecord>,
    pub ledger: Box<PolicyLifecycleLedger>,
}

#[derive(Serialize)]
struct EntryPayload<'a> {
    domain: &'static str,
    sequence: u64,
    previous_entry_sha256: Option<&'a str>,
    event_type: PolicyLifecycleEventType,
    policy_pack_id: &'a str,
    suspension_state_sha256: Option<&'a str>,
    remediation_state_sha256: Option<&'a str>,
    recorded_at_unix: u64,
}

pub fn append_policy_lifecycle_event(
    baseline: Option<&PolicyLifecycleLedger>,
    suspension: Option<&PolicySuspensionState>,
    remediation: Option<&PolicyRemediationState>,
) -> Result<PolicyLifecycleLedger, String> {
    if suspension.is_some() == remediation.is_some() {
        return Err(
            "policy lifecycle append requires exactly one suspension or remediation state".into(),
        );
    }
    let (mut entries, policy_pack_id, generation, previous_entry_sha256) = match baseline {
        Some(baseline) => {
            validate_policy_lifecycle_ledger(baseline)?;
            (
                baseline.entries.clone(),
                baseline.policy_pack_id.clone(),
                baseline
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| "policy lifecycle generation overflowed".to_string())?,
                Some(baseline.head_sha256.clone()),
            )
        }
        None => {
            let policy_pack_id = suspension
                .map(|state| state.policy_pack_id.clone())
                .or_else(|| remediation.map(|state| state.policy_pack_id.clone()))
                .ok_or_else(|| "policy lifecycle event is absent".to_string())?;
            (Vec::new(), policy_pack_id, 1, None)
        }
    };
    if entries.len() >= MAXIMUM_EVENTS {
        return Err("policy lifecycle ledger reached its event limit".into());
    }
    let sequence = entries.len() as u64 + 1;
    let mut entry = match (suspension, remediation) {
        (Some(state), None) => {
            validate_policy_suspension_state(state)?;
            if state.policy_pack_id != policy_pack_id {
                return Err("policy lifecycle suspension has a different policy identity".into());
            }
            PolicyLifecycleEntry {
                schema_version: POLICY_LIFECYCLE_LEDGER_SCHEMA_VERSION,
                sequence,
                previous_entry_sha256,
                event_type: PolicyLifecycleEventType::SuspensionDecision,
                policy_pack_id: policy_pack_id.clone(),
                suspension_state_sha256: Some(normalized_sha256(state, "policy suspension state")?),
                remediation_state_sha256: None,
                suspension_state: Some(Box::new(state.clone())),
                remediation_state: None,
                recorded_at_unix: state.recorded_at_unix,
                entry_sha256: String::new(),
            }
        }
        (None, Some(state)) => {
            validate_policy_remediation_state(state)?;
            if state.policy_pack_id != policy_pack_id {
                return Err("policy lifecycle remediation has a different policy identity".into());
            }
            PolicyLifecycleEntry {
                schema_version: POLICY_LIFECYCLE_LEDGER_SCHEMA_VERSION,
                sequence,
                previous_entry_sha256,
                event_type: PolicyLifecycleEventType::Remediation,
                policy_pack_id: policy_pack_id.clone(),
                suspension_state_sha256: Some(state.suspension_state_sha256.clone()),
                remediation_state_sha256: Some(normalized_sha256(
                    state,
                    "policy remediation state",
                )?),
                suspension_state: None,
                remediation_state: Some(Box::new(state.clone())),
                recorded_at_unix: state.recorded_at_unix,
                entry_sha256: String::new(),
            }
        }
        _ => unreachable!(),
    };
    if entries
        .last()
        .is_some_and(|previous| previous.recorded_at_unix > entry.recorded_at_unix)
    {
        return Err("policy lifecycle event timestamps must be monotonic".into());
    }
    entry.entry_sha256 = entry_sha256(&entry)?;
    entries.push(entry);
    let ledger = build_ledger(policy_pack_id, generation, entries)?;
    validate_policy_lifecycle_ledger(&ledger)?;
    Ok(ledger)
}

pub fn snapshot_policy_lifecycle(
    ledger: &PolicyLifecycleLedger,
    generation: u64,
) -> Result<PolicyLifecycleSnapshot, String> {
    validate_policy_lifecycle_ledger(ledger)?;
    if generation == 0 || generation > ledger.generation {
        return Err(format!(
            "policy lifecycle generation must be between 1 and {}",
            ledger.generation
        ));
    }
    let entries = &ledger.entries[..generation as usize];
    let records = derive_records(&ledger.policy_pack_id, entries)?;
    let counts = record_counts(&records);
    Ok(PolicyLifecycleSnapshot {
        schema_version: POLICY_LIFECYCLE_SNAPSHOT_SCHEMA_VERSION,
        policy_pack_id: ledger.policy_pack_id.clone(),
        generation,
        ledger_sha256: normalized_sha256(ledger, "policy lifecycle ledger")?,
        ledger_head_sha256: ledger.head_sha256.clone(),
        generation_head_sha256: entries.last().unwrap().entry_sha256.clone(),
        awaiting_remediation: counts.0,
        released: counts.1,
        superseded: counts.2,
        continued_under_review: counts.3,
        records,
        ledger: Box::new(ledger.clone()),
    })
}

pub fn lifecycle_evidence(
    ledger: &PolicyLifecycleLedger,
) -> Result<(Vec<PolicySuspensionState>, Vec<PolicyRemediationState>), String> {
    validate_policy_lifecycle_ledger(ledger)?;
    let suspensions = ledger
        .entries
        .iter()
        .filter_map(|entry| entry.suspension_state.as_deref().cloned())
        .collect();
    let remediations = ledger
        .entries
        .iter()
        .filter_map(|entry| entry.remediation_state.as_deref().cloned())
        .collect();
    Ok((suspensions, remediations))
}

pub fn parse_policy_lifecycle_ledger(source: &str) -> Result<PolicyLifecycleLedger, String> {
    let ledger = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy lifecycle ledger JSON: {error}"))?;
    validate_policy_lifecycle_ledger(&ledger)?;
    Ok(ledger)
}

pub fn parse_policy_lifecycle_snapshot(source: &str) -> Result<PolicyLifecycleSnapshot, String> {
    let snapshot = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy lifecycle snapshot JSON: {error}"))?;
    validate_policy_lifecycle_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub fn validate_policy_lifecycle_ledger(ledger: &PolicyLifecycleLedger) -> Result<(), String> {
    if ledger.schema_version != POLICY_LIFECYCLE_LEDGER_SCHEMA_VERSION
        || ledger.entries.is_empty()
        || ledger.entries.len() > MAXIMUM_EVENTS
        || ledger.entry_count != ledger.entries.len() as u64
        || ledger.generation != ledger.entry_count
    {
        return Err("policy lifecycle ledger governance boundary is invalid".into());
    }
    validate_slug(&ledger.policy_pack_id)?;
    validate_digest(&ledger.head_sha256)?;
    let mut suspension_hashes = HashSet::new();
    let mut remediation_hashes = HashSet::new();
    for (index, entry) in ledger.entries.iter().enumerate() {
        let sequence = index as u64 + 1;
        let expected_previous = index
            .checked_sub(1)
            .map(|previous| ledger.entries[previous].entry_sha256.as_str());
        if entry.schema_version != POLICY_LIFECYCLE_LEDGER_SCHEMA_VERSION
            || entry.sequence != sequence
            || entry.previous_entry_sha256.as_deref() != expected_previous
            || entry.policy_pack_id != ledger.policy_pack_id
            || entry.entry_sha256 != entry_sha256(entry)?
            || index > 0 && ledger.entries[index - 1].recorded_at_unix > entry.recorded_at_unix
        {
            return Err("policy lifecycle entry chain is invalid".into());
        }
        validate_digest(&entry.entry_sha256)?;
        match entry.event_type {
            PolicyLifecycleEventType::SuspensionDecision => {
                let state = entry
                    .suspension_state
                    .as_deref()
                    .ok_or_else(|| "policy lifecycle suspension evidence is absent".to_string())?;
                validate_policy_suspension_state(state)?;
                let state_sha256 = normalized_sha256(state, "policy suspension state")?;
                if entry.remediation_state.is_some()
                    || entry.remediation_state_sha256.is_some()
                    || entry.suspension_state_sha256.as_deref() != Some(&state_sha256)
                    || entry.recorded_at_unix != state.recorded_at_unix
                    || state.policy_pack_id != ledger.policy_pack_id
                    || !suspension_hashes.insert(state_sha256)
                {
                    return Err("policy lifecycle suspension entry is inconsistent".into());
                }
            }
            PolicyLifecycleEventType::Remediation => {
                let state = entry
                    .remediation_state
                    .as_deref()
                    .ok_or_else(|| "policy lifecycle remediation evidence is absent".to_string())?;
                validate_policy_remediation_state(state)?;
                let state_sha256 = normalized_sha256(state, "policy remediation state")?;
                if entry.suspension_state.is_some()
                    || entry.suspension_state_sha256.as_deref()
                        != Some(state.suspension_state_sha256.as_str())
                    || entry.remediation_state_sha256.as_deref() != Some(&state_sha256)
                    || entry.recorded_at_unix != state.recorded_at_unix
                    || state.policy_pack_id != ledger.policy_pack_id
                    || !remediation_hashes.insert(state_sha256)
                {
                    return Err("policy lifecycle remediation entry is inconsistent".into());
                }
            }
        }
    }
    if ledger.head_sha256 != ledger.entries.last().unwrap().entry_sha256 {
        return Err("policy lifecycle head does not match its final entry".into());
    }
    let expected_records = derive_records(&ledger.policy_pack_id, &ledger.entries)?;
    let counts = record_counts(&expected_records);
    if ledger.records != expected_records
        || (
            ledger.awaiting_remediation,
            ledger.released,
            ledger.superseded,
            ledger.continued_under_review,
        ) != counts
    {
        return Err("policy lifecycle derived state is inconsistent".into());
    }
    Ok(())
}

pub fn validate_policy_lifecycle_snapshot(
    snapshot: &PolicyLifecycleSnapshot,
) -> Result<(), String> {
    validate_policy_lifecycle_ledger(&snapshot.ledger)?;
    if snapshot.schema_version != POLICY_LIFECYCLE_SNAPSHOT_SCHEMA_VERSION
        || snapshot.generation == 0
        || snapshot.generation > snapshot.ledger.generation
        || snapshot.records.is_empty()
        || snapshot.policy_pack_id != snapshot.ledger.policy_pack_id
        || snapshot.ledger_head_sha256 != snapshot.ledger.head_sha256
        || snapshot.ledger_sha256 != normalized_sha256(&snapshot.ledger, "policy lifecycle ledger")?
    {
        return Err("policy lifecycle snapshot invariants are invalid".into());
    }
    validate_slug(&snapshot.policy_pack_id)?;
    validate_digest(&snapshot.ledger_sha256)?;
    validate_digest(&snapshot.ledger_head_sha256)?;
    validate_digest(&snapshot.generation_head_sha256)?;
    let expected = snapshot_policy_lifecycle(&snapshot.ledger, snapshot.generation)?;
    if snapshot.generation_head_sha256 != expected.generation_head_sha256
        || snapshot.awaiting_remediation != expected.awaiting_remediation
        || snapshot.released != expected.released
        || snapshot.superseded != expected.superseded
        || snapshot.continued_under_review != expected.continued_under_review
        || snapshot.records != expected.records
    {
        return Err("policy lifecycle snapshot does not match its retained ledger".into());
    }
    Ok(())
}

fn build_ledger(
    policy_pack_id: String,
    generation: u64,
    entries: Vec<PolicyLifecycleEntry>,
) -> Result<PolicyLifecycleLedger, String> {
    let records = derive_records(&policy_pack_id, &entries)?;
    let counts = record_counts(&records);
    Ok(PolicyLifecycleLedger {
        schema_version: POLICY_LIFECYCLE_LEDGER_SCHEMA_VERSION,
        policy_pack_id,
        generation,
        entry_count: entries.len() as u64,
        head_sha256: entries
            .last()
            .ok_or_else(|| "policy lifecycle ledger cannot be empty".to_string())?
            .entry_sha256
            .clone(),
        awaiting_remediation: counts.0,
        released: counts.1,
        superseded: counts.2,
        continued_under_review: counts.3,
        records,
        entries,
    })
}

fn derive_records(
    policy_pack_id: &str,
    entries: &[PolicyLifecycleEntry],
) -> Result<Vec<PolicyLifecycleRecord>, String> {
    let mut records = Vec::<PolicyLifecycleRecord>::new();
    for entry in entries {
        match entry.event_type {
            PolicyLifecycleEventType::SuspensionDecision => {
                let state = entry
                    .suspension_state
                    .as_deref()
                    .ok_or_else(|| "policy lifecycle suspension evidence is absent".to_string())?;
                if state.policy_pack_id != policy_pack_id {
                    return Err("policy lifecycle contains a different policy identity".into());
                }
                if state.policy_suspended {
                    for record in &mut records {
                        if record.status == PolicyLifecycleStatus::Released
                            && record
                                .remediation_revision
                                .is_some_and(|revision| revision <= state.failed_revision)
                        {
                            record.status = PolicyLifecycleStatus::Superseded;
                        }
                    }
                }
                records.push(PolicyLifecycleRecord {
                    suspension_state_sha256: entry.suspension_state_sha256.clone().ok_or_else(
                        || "policy lifecycle suspension digest is absent".to_string(),
                    )?,
                    failed_revision: state.failed_revision,
                    failed_policy_pack_sha256: state.failed_policy_pack_sha256.clone(),
                    decision: state.decision,
                    status: if state.policy_suspended {
                        PolicyLifecycleStatus::AwaitingRemediation
                    } else {
                        PolicyLifecycleStatus::ContinuedUnderReview
                    },
                    decision_sequence: entry.sequence,
                    remediation_state_sha256: None,
                    remediation_revision: None,
                    remediation_policy_pack_sha256: None,
                    resolution_sequence: None,
                });
            }
            PolicyLifecycleEventType::Remediation => {
                let state = entry
                    .remediation_state
                    .as_deref()
                    .ok_or_else(|| "policy lifecycle remediation evidence is absent".to_string())?;
                let record = records
                    .iter_mut()
                    .find(|record| record.suspension_state_sha256 == state.suspension_state_sha256)
                    .ok_or_else(|| {
                        "policy lifecycle remediation has no retained suspension".to_string()
                    })?;
                if record.status != PolicyLifecycleStatus::AwaitingRemediation
                    || record.failed_revision != state.suspended_revision
                    || record.failed_policy_pack_sha256 != state.suspended_policy_pack_sha256
                {
                    return Err(
                        "policy lifecycle remediation does not resolve one active suspension"
                            .into(),
                    );
                }
                record.status = PolicyLifecycleStatus::Released;
                record.remediation_state_sha256 = entry.remediation_state_sha256.clone();
                record.remediation_revision = Some(state.remediation_revision);
                record.remediation_policy_pack_sha256 =
                    Some(state.remediation_policy_pack_sha256.clone());
                record.resolution_sequence = Some(entry.sequence);
            }
        }
    }
    validate_records(&records)?;
    Ok(records)
}

fn validate_records(records: &[PolicyLifecycleRecord]) -> Result<(), String> {
    let mut suspension_hashes = HashSet::new();
    let mut remediation_hashes = HashSet::new();
    let mut previous_sequence = 0;
    for record in records {
        validate_digest(&record.suspension_state_sha256)?;
        validate_digest(&record.failed_policy_pack_sha256)?;
        if record.decision_sequence <= previous_sequence
            || !suspension_hashes.insert(record.suspension_state_sha256.as_str())
        {
            return Err("policy lifecycle records are not an ordered unique history".into());
        }
        previous_sequence = record.decision_sequence;
        match record.status {
            PolicyLifecycleStatus::ContinuedUnderReview => {
                if record.decision != PolicySuspensionDecision::Continue
                    || record.remediation_state_sha256.is_some()
                    || record.remediation_revision.is_some()
                    || record.remediation_policy_pack_sha256.is_some()
                    || record.resolution_sequence.is_some()
                {
                    return Err("continued policy lifecycle record is inconsistent".into());
                }
            }
            PolicyLifecycleStatus::AwaitingRemediation => {
                if record.decision != PolicySuspensionDecision::Suspend
                    || record.remediation_state_sha256.is_some()
                    || record.remediation_revision.is_some()
                    || record.remediation_policy_pack_sha256.is_some()
                    || record.resolution_sequence.is_some()
                {
                    return Err("active policy lifecycle suspension is inconsistent".into());
                }
            }
            PolicyLifecycleStatus::Released | PolicyLifecycleStatus::Superseded => {
                let remediation_sha256 =
                    record.remediation_state_sha256.as_deref().ok_or_else(|| {
                        "resolved policy lifecycle record lacks remediation evidence".to_string()
                    })?;
                let remediation_revision = record.remediation_revision.ok_or_else(|| {
                    "resolved policy lifecycle record lacks a successor revision".to_string()
                })?;
                let remediation_digest = record
                    .remediation_policy_pack_sha256
                    .as_deref()
                    .ok_or_else(|| {
                        "resolved policy lifecycle record lacks a successor digest".to_string()
                    })?;
                let resolution_sequence = record.resolution_sequence.ok_or_else(|| {
                    "resolved policy lifecycle record lacks a resolution sequence".to_string()
                })?;
                validate_digest(remediation_sha256)?;
                validate_digest(remediation_digest)?;
                if record.decision != PolicySuspensionDecision::Suspend
                    || remediation_revision <= record.failed_revision
                    || resolution_sequence <= record.decision_sequence
                    || !remediation_hashes.insert(remediation_sha256)
                {
                    return Err("resolved policy lifecycle record is inconsistent".into());
                }
            }
        }
    }
    Ok(())
}

fn record_counts(records: &[PolicyLifecycleRecord]) -> (u64, u64, u64, u64) {
    records.iter().fold((0, 0, 0, 0), |mut counts, record| {
        match record.status {
            PolicyLifecycleStatus::AwaitingRemediation => counts.0 += 1,
            PolicyLifecycleStatus::Released => counts.1 += 1,
            PolicyLifecycleStatus::Superseded => counts.2 += 1,
            PolicyLifecycleStatus::ContinuedUnderReview => counts.3 += 1,
        }
        counts
    })
}

fn entry_sha256(entry: &PolicyLifecycleEntry) -> Result<String, String> {
    normalized_sha256(
        &EntryPayload {
            domain: "pcbex-policy-lifecycle-entry-v1",
            sequence: entry.sequence,
            previous_entry_sha256: entry.previous_entry_sha256.as_deref(),
            event_type: entry.event_type,
            policy_pack_id: &entry.policy_pack_id,
            suspension_state_sha256: entry.suspension_state_sha256.as_deref(),
            remediation_state_sha256: entry.remediation_state_sha256.as_deref(),
            recorded_at_unix: entry.recorded_at_unix,
        },
        "policy lifecycle entry",
    )
}

pub fn render_policy_lifecycle_summary(ledger: &PolicyLifecycleLedger) -> String {
    let mut summary = format!(
        "# Policy lifecycle ledger\n\n\
         - Generation: `{}`\n\
         - Events: `{}`\n\
         - Head: `{}`\n\
         - Awaiting remediation: `{}`\n\
         - Released: `{}`\n\
         - Superseded: `{}`\n\
         - Continued under review: `{}`\n",
        ledger.generation,
        ledger.entry_count,
        ledger.head_sha256,
        ledger.awaiting_remediation,
        ledger.released,
        ledger.superseded,
        ledger.continued_under_review
    );
    let _ = writeln!(
        summary,
        "\n| Failed revision | Decision | Status | Successor |\n|---:|---|---|---:|"
    );
    for record in &ledger.records {
        let _ = writeln!(
            summary,
            "| {} | `{:?}` | `{:?}` | {} |",
            record.failed_revision,
            record.decision,
            record.status,
            record
                .remediation_revision
                .map_or_else(|| "-".into(), |revision| revision.to_string())
        );
    }
    summary
}

pub fn policy_lifecycle_ledger_json_schema() -> Value {
    let digest = digest_schema();
    let suspension = embedded_schema(policy_suspension_state_json_schema());
    let remediation = embedded_schema(policy_remediation_state_json_schema());
    let record = record_schema();
    let entry = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "sequence", "previous_entry_sha256", "event_type",
            "policy_pack_id", "suspension_state_sha256", "remediation_state_sha256",
            "suspension_state", "remediation_state", "recorded_at_unix", "entry_sha256"
        ],
        "properties": {
            "schema_version": {"const": POLICY_LIFECYCLE_LEDGER_SCHEMA_VERSION},
            "sequence": {"type": "integer", "minimum": 1},
            "previous_entry_sha256": {"oneOf": [digest, {"type": "null"}]},
            "event_type": {"enum": ["suspension_decision", "remediation"]},
            "policy_pack_id": slug_schema(),
            "suspension_state_sha256": {"oneOf": [digest, {"type": "null"}]},
            "remediation_state_sha256": {"oneOf": [digest, {"type": "null"}]},
            "suspension_state": {"oneOf": [suspension, {"type": "null"}]},
            "remediation_state": {"oneOf": [remediation, {"type": "null"}]},
            "recorded_at_unix": {"type": "integer", "minimum": 0},
            "entry_sha256": digest
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-ledger-v1.json",
        "title": "pcbex append-only policy suspension and remediation lifecycle ledger",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "policy_pack_id", "generation", "entry_count",
            "head_sha256", "awaiting_remediation", "released", "superseded",
            "continued_under_review", "records", "entries"
        ],
        "properties": {
            "schema_version": {"const": POLICY_LIFECYCLE_LEDGER_SCHEMA_VERSION},
            "policy_pack_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 1},
            "entry_count": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_EVENTS},
            "head_sha256": digest,
            "awaiting_remediation": {"type": "integer", "minimum": 0},
            "released": {"type": "integer", "minimum": 0},
            "superseded": {"type": "integer", "minimum": 0},
            "continued_under_review": {"type": "integer", "minimum": 0},
            "records": {"type": "array", "minItems": 1, "items": record},
            "entries": {
                "type": "array", "minItems": 1, "maxItems": MAXIMUM_EVENTS, "items": entry
            }
        }
    })
}

pub fn policy_lifecycle_snapshot_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-snapshot-v1.json",
        "title": "pcbex policy lifecycle historical snapshot",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "policy_pack_id", "generation", "ledger_sha256", "ledger_head_sha256",
            "generation_head_sha256", "awaiting_remediation", "released", "superseded",
            "continued_under_review", "records", "ledger"
        ],
        "properties": {
            "schema_version": {"const": POLICY_LIFECYCLE_SNAPSHOT_SCHEMA_VERSION},
            "policy_pack_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 1},
            "ledger_sha256": digest_schema(),
            "ledger_head_sha256": digest_schema(),
            "generation_head_sha256": digest_schema(),
            "awaiting_remediation": {"type": "integer", "minimum": 0},
            "released": {"type": "integer", "minimum": 0},
            "superseded": {"type": "integer", "minimum": 0},
            "continued_under_review": {"type": "integer", "minimum": 0},
            "records": {"type": "array", "minItems": 1, "items": record_schema()},
            "ledger": embedded_schema(policy_lifecycle_ledger_json_schema())
        }
    })
}

fn record_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "suspension_state_sha256", "failed_revision", "failed_policy_pack_sha256",
            "decision", "status", "decision_sequence", "remediation_state_sha256",
            "remediation_revision", "remediation_policy_pack_sha256", "resolution_sequence"
        ],
        "properties": {
            "suspension_state_sha256": digest_schema(),
            "failed_revision": {"type": "integer", "minimum": 1},
            "failed_policy_pack_sha256": digest_schema(),
            "decision": {"enum": ["suspend", "continue"]},
            "status": {
                "enum": [
                    "continued_under_review", "awaiting_remediation", "released", "superseded"
                ]
            },
            "decision_sequence": {"type": "integer", "minimum": 1},
            "remediation_state_sha256": {
                "oneOf": [digest_schema(), {"type": "null"}]
            },
            "remediation_revision": {
                "oneOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]
            },
            "remediation_policy_pack_sha256": {
                "oneOf": [digest_schema(), {"type": "null"}]
            },
            "resolution_sequence": {
                "oneOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]
            }
        }
    })
}

fn embedded_schema(mut schema: Value) -> Value {
    if let Some(object) = schema.as_object_mut() {
        object.remove("$schema");
        object.remove("$id");
    }
    schema
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

fn validate_slug(value: &str) -> Result<(), String> {
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
        Err("policy lifecycle identity is invalid".into())
    } else {
        Ok(())
    }
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_remediation::tests::lifecycle_test_states;

    #[test]
    fn schemas_close_ledger_snapshot_entries_and_records() {
        let ledger = policy_lifecycle_ledger_json_schema();
        assert_eq!(ledger["additionalProperties"], false);
        assert_eq!(
            ledger["properties"]["entries"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            ledger["properties"]["records"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            ledger["properties"]["entries"]["items"]["properties"]["suspension_state"]["oneOf"][0]
                ["additionalProperties"],
            false
        );
        let snapshot = policy_lifecycle_snapshot_json_schema();
        assert_eq!(snapshot["additionalProperties"], false);
        assert_eq!(
            snapshot["properties"]["records"]["items"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn lifecycle_retains_exact_evidence_and_reconstructs_history() {
        let (candidate, suspension, remediation) = lifecycle_test_states();
        let suspended = append_policy_lifecycle_event(None, Some(&suspension), None).unwrap();
        assert_eq!(suspended.generation, 1);
        assert_eq!(suspended.awaiting_remediation, 1);
        assert_eq!(
            suspended.records[0].status,
            PolicyLifecycleStatus::AwaitingRemediation
        );
        let (retained_suspensions, retained_remediations) = lifecycle_evidence(&suspended).unwrap();
        assert!(
            crate::policy_suspension::enforce_policy_suspensions(
                &candidate,
                &retained_suspensions,
                &retained_remediations,
            )
            .unwrap_err()
            .contains("requires an independently verified remediation")
        );

        let released =
            append_policy_lifecycle_event(Some(&suspended), None, Some(&remediation)).unwrap();
        assert_eq!(released.generation, 2);
        assert_eq!(released.awaiting_remediation, 0);
        assert_eq!(released.released, 1);
        assert_eq!(released.records[0].status, PolicyLifecycleStatus::Released);
        assert_eq!(
            released.records[0].remediation_revision,
            Some(remediation.remediation_revision)
        );

        let historical = snapshot_policy_lifecycle(&released, 1).unwrap();
        assert_eq!(historical.awaiting_remediation, 1);
        assert_eq!(historical.released, 0);
        assert_eq!(historical.generation_head_sha256, suspended.head_sha256);
        let current = snapshot_policy_lifecycle(&released, 2).unwrap();
        assert_eq!(current.released, 1);
        assert_eq!(current.ledger_head_sha256, released.head_sha256);
        validate_policy_lifecycle_snapshot(&current).unwrap();

        let mut forged = current;
        forged.awaiting_remediation = 1;
        forged.released = 0;
        assert!(
            validate_policy_lifecycle_snapshot(&forged)
                .unwrap_err()
                .contains("does not match")
        );

        let (retained_suspensions, retained_remediations) = lifecycle_evidence(&released).unwrap();
        assert_eq!(retained_suspensions, vec![suspension]);
        assert_eq!(retained_remediations, vec![remediation]);
        crate::policy_suspension::enforce_policy_suspensions(
            &candidate,
            &retained_suspensions,
            &retained_remediations,
        )
        .unwrap();
    }

    #[test]
    fn lifecycle_rejects_tampering_truncation_reordering_and_double_release() {
        let (_, suspension, remediation) = lifecycle_test_states();
        let suspended = append_policy_lifecycle_event(None, Some(&suspension), None).unwrap();
        let released =
            append_policy_lifecycle_event(Some(&suspended), None, Some(&remediation)).unwrap();

        assert!(
            append_policy_lifecycle_event(Some(&released), None, Some(&remediation))
                .unwrap_err()
                .contains("active suspension")
        );

        let mut tampered = released.clone();
        tampered.entries[0]
            .suspension_state
            .as_mut()
            .unwrap()
            .recorded_at_unix += 1;
        assert!(validate_policy_lifecycle_ledger(&tampered).is_err());

        let mut truncated = released.clone();
        truncated.entries.pop();
        assert!(validate_policy_lifecycle_ledger(&truncated).is_err());

        let mut reordered = released;
        reordered.entries.reverse();
        assert!(
            validate_policy_lifecycle_ledger(&reordered)
                .unwrap_err()
                .contains("entry chain")
        );
    }
}

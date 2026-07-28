use super::{AiModelIdentity, SchematicDocument, SchematicSemanticDiff, compare_schematics};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

const SCHEMA_VERSION: u32 = 1;
const MAX_PROFILES: usize = 100;
const MAX_ITEMS: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchematicReviewChangeKind {
    CoverageChanged,
    CoverageIncomplete,
    SymbolAdded,
    SymbolRemoved,
    SymbolModified,
    NetAdded,
    NetRemoved,
    NetModified,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicReviewSelector {
    pub change_kinds: Vec<SchematicReviewChangeKind>,
    pub reference_prefixes: Vec<String>,
    pub library_prefixes: Vec<String>,
    pub net_name_prefixes: Vec<String>,
    pub changed_fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicReviewerProfile {
    pub id: String,
    pub title: String,
    pub minimum_reviewers: u32,
    pub reviewer_candidates: Vec<AiModelIdentity>,
    pub instructions: Vec<String>,
    pub selectors: Vec<SchematicReviewSelector>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicReviewerRoutingPolicy {
    pub schema_version: u32,
    pub id: String,
    pub fallback_profile_id: String,
    pub profiles: Vec<SchematicReviewerProfile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicReviewChange {
    pub id: String,
    pub kind: SchematicReviewChangeKind,
    pub reference: Option<String>,
    pub library_id: Option<String>,
    pub net_key: Option<String>,
    pub net_name: Option<String>,
    pub changed_fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicReviewerRoute {
    pub profile_id: String,
    pub title: String,
    pub minimum_reviewers: u32,
    pub reviewer_candidates: Vec<AiModelIdentity>,
    pub instructions: Vec<String>,
    pub matched_changes: Vec<SchematicReviewChange>,
    pub fallback_changes: Vec<SchematicReviewChange>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicReviewerRoutingPlan {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_sha256: String,
    pub baseline_schematic_sha256: String,
    pub current_schematic_sha256: String,
    pub changed: bool,
    pub review_required: bool,
    pub all_changes_routed: bool,
    pub change_count: usize,
    pub route_count: usize,
    pub minimum_review_assignments: u32,
    pub routes: Vec<SchematicReviewerRoute>,
}

pub fn parse_schematic_reviewer_routing_policy(
    source: &str,
) -> Result<SchematicReviewerRoutingPolicy, String> {
    let mut policy: SchematicReviewerRoutingPolicy = serde_json::from_str(source)
        .map_err(|error| format!("invalid schematic reviewer routing policy: {error}"))?;
    normalize_and_validate_policy(&mut policy)?;
    Ok(policy)
}

pub fn route_schematic_review(
    baseline: &SchematicDocument,
    current: &SchematicDocument,
    policy: &SchematicReviewerRoutingPolicy,
) -> Result<SchematicReviewerRoutingPlan, String> {
    let mut policy = policy.clone();
    normalize_and_validate_policy(&mut policy)?;
    let diff = compare_schematics(baseline, current)?;
    let changes = review_changes(&diff, baseline, current)?;
    if changes.len() > MAX_ITEMS {
        return Err(format!(
            "schematic reviewer routing exceeds the {MAX_ITEMS} change limit"
        ));
    }

    let policy_bytes = serde_json::to_vec(&policy)
        .map_err(|error| format!("could not serialize reviewer routing policy: {error}"))?;
    let policy_sha256 = format!("{:x}", Sha256::digest(policy_bytes));
    let fallback = policy
        .profiles
        .iter()
        .find(|profile| profile.id == policy.fallback_profile_id)
        .expect("validated fallback profile exists");
    let mut routes =
        BTreeMap::<String, (Vec<SchematicReviewChange>, Vec<SchematicReviewChange>)>::new();

    for change in &changes {
        let mut matched = false;
        for profile in policy
            .profiles
            .iter()
            .filter(|profile| profile.id != fallback.id)
        {
            if profile
                .selectors
                .iter()
                .any(|selector| selector_matches(selector, change))
            {
                routes
                    .entry(profile.id.clone())
                    .or_default()
                    .0
                    .push(change.clone());
                matched = true;
            }
        }
        if !matched {
            routes
                .entry(fallback.id.clone())
                .or_default()
                .1
                .push(change.clone());
        }
    }

    let routes = policy
        .profiles
        .iter()
        .filter_map(|profile| {
            let (matched_changes, fallback_changes) = routes.remove(&profile.id)?;
            Some(SchematicReviewerRoute {
                profile_id: profile.id.clone(),
                title: profile.title.clone(),
                minimum_reviewers: profile.minimum_reviewers,
                reviewer_candidates: profile.reviewer_candidates.clone(),
                instructions: profile.instructions.clone(),
                matched_changes,
                fallback_changes,
            })
        })
        .collect::<Vec<_>>();
    let minimum_review_assignments = routes.iter().try_fold(0_u32, |total, route| {
        total
            .checked_add(route.minimum_reviewers)
            .ok_or_else(|| "minimum reviewer assignment count overflowed".to_string())
    })?;

    let routed_change_ids = routes
        .iter()
        .flat_map(|route| route.matched_changes.iter().chain(&route.fallback_changes))
        .map(|change| change.id.as_str())
        .collect::<BTreeSet<_>>();
    Ok(SchematicReviewerRoutingPlan {
        schema_version: SCHEMA_VERSION,
        policy_id: policy.id,
        policy_sha256,
        baseline_schematic_sha256: diff.baseline.schematic_sha256,
        current_schematic_sha256: diff.current.schematic_sha256,
        changed: diff.changed,
        review_required: diff.review_required,
        all_changes_routed: routed_change_ids.len() == changes.len(),
        change_count: changes.len(),
        route_count: routes.len(),
        minimum_review_assignments,
        routes,
    })
}

pub fn render_schematic_reviewer_routing_summary(plan: &SchematicReviewerRoutingPlan) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "## AI schematic reviewer routing\n");
    let _ = writeln!(output, "- Policy: `{}`", plan.policy_id);
    let _ = writeln!(output, "- Review required: `{}`", plan.review_required);
    let _ = writeln!(output, "- Changes: {}", plan.change_count);
    let _ = writeln!(output, "- Reviewer profiles: {}", plan.route_count);
    let _ = writeln!(
        output,
        "- Minimum review assignments: {}",
        plan.minimum_review_assignments
    );
    let _ = writeln!(
        output,
        "- All changes routed: `{}`",
        plan.all_changes_routed
    );
    for route in &plan.routes {
        let _ = writeln!(
            output,
            "\n### {} (`{}`)\n\n- Minimum reviewers: {}\n- Direct matches: {}\n- Fallback matches: {}\n- Candidate models: {}",
            route.title,
            route.profile_id,
            route.minimum_reviewers,
            route.matched_changes.len(),
            route.fallback_changes.len(),
            route
                .reviewer_candidates
                .iter()
                .map(model_name)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    output
}

fn model_name(model: &AiModelIdentity) -> String {
    match &model.version {
        Some(version) => format!("{}/{}@{}", model.provider, model.model, version),
        None => format!("{}/{}", model.provider, model.model),
    }
}

fn review_changes(
    diff: &SchematicSemanticDiff,
    baseline: &SchematicDocument,
    current: &SchematicDocument,
) -> Result<Vec<SchematicReviewChange>, String> {
    let baseline_symbols = baseline
        .symbols
        .iter()
        .map(|symbol| (symbol.uuid.as_str(), symbol))
        .collect::<BTreeMap<_, _>>();
    let current_symbols = current
        .symbols
        .iter()
        .map(|symbol| (symbol.uuid.as_str(), symbol))
        .collect::<BTreeMap<_, _>>();
    let mut changes = Vec::new();
    if diff.coverage_changed {
        changes.push(change(
            "coverage:changed",
            SchematicReviewChangeKind::CoverageChanged,
        ));
    }
    if !diff.baseline.coverage_complete || !diff.current.coverage_complete {
        changes.push(change(
            "coverage:incomplete",
            SchematicReviewChangeKind::CoverageIncomplete,
        ));
    }
    for symbol in &diff.added_symbols {
        changes.push(symbol_change(
            format!("symbol:added:{}", symbol.uuid),
            SchematicReviewChangeKind::SymbolAdded,
            &symbol.reference,
            &symbol.lib_id,
            Vec::new(),
        ));
    }
    for symbol in &diff.removed_symbols {
        changes.push(symbol_change(
            format!("symbol:removed:{}", symbol.uuid),
            SchematicReviewChangeKind::SymbolRemoved,
            &symbol.reference,
            &symbol.lib_id,
            Vec::new(),
        ));
    }
    for symbol in &diff.modified_symbols {
        let source = current_symbols
            .get(symbol.uuid.as_str())
            .copied()
            .or_else(|| baseline_symbols.get(symbol.uuid.as_str()).copied())
            .ok_or_else(|| {
                format!(
                    "modified symbol {} is absent from both schematics",
                    symbol.uuid
                )
            })?;
        let mut fields = symbol.changed_fields.clone();
        for pin in &symbol.changed_pins {
            fields.extend(
                pin.changed_fields
                    .iter()
                    .map(|field| format!("pin.{field}")),
            );
        }
        if !symbol.added_pins.is_empty() {
            fields.push("pins.added".into());
        }
        if !symbol.removed_pins.is_empty() {
            fields.push("pins.removed".into());
        }
        fields.sort();
        fields.dedup();
        changes.push(symbol_change(
            format!("symbol:modified:{}", symbol.uuid),
            SchematicReviewChangeKind::SymbolModified,
            &symbol.current_reference,
            &source.lib_id,
            fields,
        ));
    }
    for net in &diff.added_nets {
        changes.push(net_change(
            format!("net:added:{}", net.key),
            SchematicReviewChangeKind::NetAdded,
            &net.key,
            &net.name,
        ));
    }
    for net in &diff.removed_nets {
        changes.push(net_change(
            format!("net:removed:{}", net.key),
            SchematicReviewChangeKind::NetRemoved,
            &net.key,
            &net.name,
        ));
    }
    for net in &diff.modified_nets {
        changes.push(net_change(
            format!("net:modified:{}", net.key),
            SchematicReviewChangeKind::NetModified,
            &net.key,
            &net.name,
        ));
    }
    changes.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(changes)
}

fn change(id: &str, kind: SchematicReviewChangeKind) -> SchematicReviewChange {
    SchematicReviewChange {
        id: id.into(),
        kind,
        reference: None,
        library_id: None,
        net_key: None,
        net_name: None,
        changed_fields: Vec::new(),
    }
}

fn symbol_change(
    id: String,
    kind: SchematicReviewChangeKind,
    reference: &str,
    library_id: &str,
    changed_fields: Vec<String>,
) -> SchematicReviewChange {
    SchematicReviewChange {
        id,
        kind,
        reference: Some(reference.into()),
        library_id: Some(library_id.into()),
        net_key: None,
        net_name: None,
        changed_fields,
    }
}

fn net_change(
    id: String,
    kind: SchematicReviewChangeKind,
    net_key: &str,
    net_name: &str,
) -> SchematicReviewChange {
    SchematicReviewChange {
        id,
        kind,
        reference: None,
        library_id: None,
        net_key: Some(net_key.into()),
        net_name: Some(net_name.into()),
        changed_fields: Vec::new(),
    }
}

fn selector_matches(selector: &SchematicReviewSelector, change: &SchematicReviewChange) -> bool {
    (selector.change_kinds.is_empty() || selector.change_kinds.contains(&change.kind))
        && prefix_group_matches(&selector.reference_prefixes, change.reference.as_deref())
        && prefix_group_matches(&selector.library_prefixes, change.library_id.as_deref())
        && prefix_group_matches(&selector.net_name_prefixes, change.net_name.as_deref())
        && (selector.changed_fields.is_empty()
            || selector
                .changed_fields
                .iter()
                .any(|field| change.changed_fields.contains(field)))
}

fn prefix_group_matches(prefixes: &[String], value: Option<&str>) -> bool {
    prefixes.is_empty()
        || value.is_some_and(|value| prefixes.iter().any(|prefix| value.starts_with(prefix)))
}

fn normalize_and_validate_policy(
    policy: &mut SchematicReviewerRoutingPolicy,
) -> Result<(), String> {
    if policy.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schematic reviewer routing policy schema version {}",
            policy.schema_version
        ));
    }
    validate_text(&policy.id, "routing policy id")?;
    validate_text(&policy.fallback_profile_id, "fallback profile id")?;
    if policy.profiles.is_empty() || policy.profiles.len() > MAX_PROFILES {
        return Err(format!(
            "schematic reviewer routing policy must contain 1 to {MAX_PROFILES} profiles"
        ));
    }
    policy
        .profiles
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut profile_ids = BTreeSet::new();
    for profile in &mut policy.profiles {
        validate_text(&profile.id, "reviewer profile id")?;
        validate_text(&profile.title, "reviewer profile title")?;
        if !profile_ids.insert(profile.id.clone()) {
            return Err(format!("duplicate reviewer profile id {:?}", profile.id));
        }
        if profile.minimum_reviewers == 0 || profile.minimum_reviewers > 100 {
            return Err(format!(
                "reviewer profile {} minimum_reviewers must be between 1 and 100",
                profile.id
            ));
        }
        if profile.reviewer_candidates.is_empty()
            || profile.reviewer_candidates.len() > MAX_PROFILES
        {
            return Err(format!(
                "reviewer profile {} must contain 1 to {MAX_PROFILES} candidates",
                profile.id
            ));
        }
        for model in &profile.reviewer_candidates {
            validate_text(&model.provider, "reviewer candidate provider")?;
            validate_text(&model.model, "reviewer candidate model")?;
            if let Some(version) = &model.version {
                validate_text(version, "reviewer candidate version")?;
            }
        }
        profile.reviewer_candidates.sort_by(|left, right| {
            (&left.provider, &left.model, &left.version).cmp(&(
                &right.provider,
                &right.model,
                &right.version,
            ))
        });
        profile.reviewer_candidates.dedup();
        if profile.minimum_reviewers as usize > profile.reviewer_candidates.len() {
            return Err(format!(
                "reviewer profile {} requires {} reviewer(s) but has only {} unique candidate(s)",
                profile.id,
                profile.minimum_reviewers,
                profile.reviewer_candidates.len()
            ));
        }
        normalize_strings(&mut profile.instructions, "reviewer instruction")?;
        if profile.instructions.is_empty() {
            return Err(format!(
                "reviewer profile {} must contain at least one instruction",
                profile.id
            ));
        }
        if profile.selectors.len() > MAX_PROFILES {
            return Err(format!(
                "reviewer profile {} exceeds the {MAX_PROFILES} selector limit",
                profile.id
            ));
        }
        for selector in &mut profile.selectors {
            selector.change_kinds.sort();
            selector.change_kinds.dedup();
            normalize_strings(&mut selector.reference_prefixes, "reference prefix")?;
            normalize_strings(&mut selector.library_prefixes, "library prefix")?;
            normalize_strings(&mut selector.net_name_prefixes, "net-name prefix")?;
            normalize_strings(&mut selector.changed_fields, "changed field")?;
            if selector.change_kinds.is_empty()
                && selector.reference_prefixes.is_empty()
                && selector.library_prefixes.is_empty()
                && selector.net_name_prefixes.is_empty()
                && selector.changed_fields.is_empty()
            {
                return Err("reviewer selectors must constrain at least one field".into());
            }
        }
        profile.selectors.sort();
        profile.selectors.dedup();
    }
    let fallback = policy
        .profiles
        .iter()
        .find(|profile| profile.id == policy.fallback_profile_id)
        .ok_or_else(|| "fallback_profile_id does not name a reviewer profile".to_string())?;
    if !fallback.selectors.is_empty() {
        return Err("the fallback reviewer profile must have no selectors".into());
    }
    for profile in policy
        .profiles
        .iter()
        .filter(|profile| profile.id != policy.fallback_profile_id)
    {
        if profile.selectors.is_empty() {
            return Err(format!(
                "non-fallback reviewer profile {} must contain at least one selector",
                profile.id
            ));
        }
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value != value.trim() || value.len() > 512 {
        return Err(format!(
            "{label} must be nonblank, trimmed, and at most 512 bytes"
        ));
    }
    Ok(())
}

fn normalize_strings(values: &mut Vec<String>, label: &str) -> Result<(), String> {
    if values.len() > MAX_ITEMS {
        return Err(format!("{label} list exceeds the {MAX_ITEMS} item limit"));
    }
    for value in values.iter() {
        validate_text(value, label)?;
    }
    values.sort();
    values.dedup();
    Ok(())
}

pub fn schematic_reviewer_routing_policy_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/schematic-reviewer-routing-policy-v1.json",
        "title": "pcbex schematic reviewer routing policy",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "id", "fallback_profile_id", "profiles"],
        "properties": {
            "schema_version": {"const": 1},
            "id": {"type": "string", "minLength": 1, "maxLength": 512},
            "fallback_profile_id": {"type": "string", "minLength": 1, "maxLength": 512},
            "profiles": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": {"$ref": "#/$defs/profile"}
            }
        },
        "$defs": {
            "model": {
                "type": "object", "additionalProperties": false,
                "required": ["provider", "model", "version"],
                "properties": {
                    "provider": {"type": "string", "minLength": 1, "maxLength": 512},
                    "model": {"type": "string", "minLength": 1, "maxLength": 512},
                    "version": {"type": ["string", "null"], "minLength": 1, "maxLength": 512}
                }
            },
            "selector": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "change_kinds", "reference_prefixes", "library_prefixes",
                    "net_name_prefixes", "changed_fields"
                ],
                "properties": {
                    "change_kinds": {
                        "type": "array", "uniqueItems": true,
                        "items": {"enum": [
                            "coverage_changed", "coverage_incomplete", "symbol_added",
                            "symbol_removed", "symbol_modified", "net_added",
                            "net_removed", "net_modified"
                        ]}
                    },
                    "reference_prefixes": {"$ref": "#/$defs/strings"},
                    "library_prefixes": {"$ref": "#/$defs/strings"},
                    "net_name_prefixes": {"$ref": "#/$defs/strings"},
                    "changed_fields": {"$ref": "#/$defs/strings"}
                }
            },
            "strings": {
                "type": "array", "maxItems": 10000, "uniqueItems": true,
                "items": {"type": "string", "minLength": 1, "maxLength": 512}
            },
            "profile": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "id", "title", "minimum_reviewers", "reviewer_candidates",
                    "instructions", "selectors"
                ],
                "properties": {
                    "id": {"type": "string", "minLength": 1, "maxLength": 512},
                    "title": {"type": "string", "minLength": 1, "maxLength": 512},
                    "minimum_reviewers": {"type": "integer", "minimum": 1, "maximum": 100},
                    "reviewer_candidates": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"$ref": "#/$defs/model"}
                    },
                    "instructions": {"$ref": "#/$defs/strings"},
                    "selectors": {
                        "type": "array", "maxItems": 100,
                        "items": {"$ref": "#/$defs/selector"}
                    }
                }
            }
        }
    })
}

pub fn schematic_reviewer_routing_plan_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/schematic-reviewer-routing-plan-v1.json",
        "title": "pcbex schematic reviewer routing plan",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "policy_id", "policy_sha256",
            "baseline_schematic_sha256", "current_schematic_sha256", "changed",
            "review_required", "all_changes_routed", "change_count", "route_count",
            "minimum_review_assignments", "routes"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "policy_id": {"type": "string"},
            "policy_sha256": {"$ref": "#/$defs/digest"},
            "baseline_schematic_sha256": {"$ref": "#/$defs/digest"},
            "current_schematic_sha256": {"$ref": "#/$defs/digest"},
            "changed": {"type": "boolean"},
            "review_required": {"type": "boolean"},
            "all_changes_routed": {"type": "boolean"},
            "change_count": {"type": "integer", "minimum": 0},
            "route_count": {"type": "integer", "minimum": 0},
            "minimum_review_assignments": {"type": "integer", "minimum": 0},
            "routes": {
                "type": "array", "maxItems": 100,
                "items": {"$ref": "#/$defs/route"}
            }
        },
        "$defs": {
            "digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "model": {
                "type": "object", "additionalProperties": false,
                "required": ["provider", "model", "version"],
                "properties": {
                    "provider": {"type": "string"},
                    "model": {"type": "string"},
                    "version": {"type": ["string", "null"]}
                }
            },
            "change": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "id", "kind", "reference", "library_id", "net_key",
                    "net_name", "changed_fields"
                ],
                "properties": {
                    "id": {"type": "string"},
                    "kind": {"enum": [
                        "coverage_changed", "coverage_incomplete", "symbol_added",
                        "symbol_removed", "symbol_modified", "net_added",
                        "net_removed", "net_modified"
                    ]},
                    "reference": {"type": ["string", "null"]},
                    "library_id": {"type": ["string", "null"]},
                    "net_key": {"type": ["string", "null"]},
                    "net_name": {"type": ["string", "null"]},
                    "changed_fields": {"type": "array", "items": {"type": "string"}}
                }
            },
            "route": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "profile_id", "title", "minimum_reviewers", "reviewer_candidates",
                    "instructions", "matched_changes", "fallback_changes"
                ],
                "properties": {
                    "profile_id": {"type": "string"},
                    "title": {"type": "string"},
                    "minimum_reviewers": {"type": "integer", "minimum": 1},
                    "reviewer_candidates": {
                        "type": "array", "items": {"$ref": "#/$defs/model"}
                    },
                    "instructions": {"type": "array", "items": {"type": "string"}},
                    "matched_changes": {
                        "type": "array", "maxItems": 10000,
                        "items": {"$ref": "#/$defs/change"}
                    },
                    "fallback_changes": {
                        "type": "array", "maxItems": 10000,
                        "items": {"$ref": "#/$defs/change"}
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import_schematic;

    fn policy() -> SchematicReviewerRoutingPolicy {
        parse_schematic_reviewer_routing_policy(
            r#"{
              "schema_version": 1,
              "id": "hardware-review-v1",
              "fallback_profile_id": "general",
              "profiles": [
                {
                  "id": "power", "title": "Power reviewer", "minimum_reviewers": 1,
                  "reviewer_candidates": [
                    {"provider": "provider-a", "model": "power-model", "version": "2026-07"}
                  ],
                  "instructions": ["Check power integrity and protection."],
                  "selectors": [{
                    "change_kinds": [], "reference_prefixes": [],
                    "library_prefixes": [], "net_name_prefixes": ["VCC"],
                    "changed_fields": []
                  }]
                },
                {
                  "id": "general", "title": "General reviewer", "minimum_reviewers": 1,
                  "reviewer_candidates": [
                    {"provider": "provider-b", "model": "general-model", "version": null}
                  ],
                  "instructions": ["Review every otherwise unmatched change."],
                  "selectors": []
                }
              ]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn routes_matching_and_unmatched_changes() {
        let baseline =
            import_schematic(include_str!("../../../examples/simple.kicad_sch")).unwrap();
        let changed_source = include_str!("../../../examples/simple.kicad_sch")
            .replace("(global_label \"VCC\"", "(global_label \"VCC_NEW\"")
            .replace("(property \"Value\" \"10k\"", "(property \"Value\" \"22k\"");
        let current = import_schematic(&changed_source).unwrap();
        let plan = route_schematic_review(&baseline, &current, &policy()).unwrap();
        assert!(plan.review_required);
        assert!(plan.all_changes_routed);
        assert!(plan.change_count > 0);
        assert!(plan.routes.iter().any(|route| route.profile_id == "power"));
        assert!(
            plan.routes
                .iter()
                .any(|route| route.profile_id == "general" && !route.fallback_changes.is_empty())
        );
    }

    #[test]
    fn rejects_missing_or_selecting_fallback() {
        let mut value = serde_json::to_value(policy()).unwrap();
        value["fallback_profile_id"] = json!("missing");
        assert!(parse_schematic_reviewer_routing_policy(&value.to_string()).is_err());
        let mut value = serde_json::to_value(policy()).unwrap();
        value["profiles"][1]["id"] = json!("general");
        assert!(parse_schematic_reviewer_routing_policy(&value.to_string()).is_err());
        let mut value = serde_json::to_value(policy()).unwrap();
        value["profiles"][0]["minimum_reviewers"] = json!(2);
        assert!(parse_schematic_reviewer_routing_policy(&value.to_string()).is_err());
        let mut value = serde_json::to_value(policy()).unwrap();
        value["fallback_profile_id"] = json!("general");
        value["profiles"][0]["selectors"] = json!([{
            "change_kinds": ["symbol_added"],
            "reference_prefixes": [],
            "library_prefixes": [],
            "net_name_prefixes": [],
            "changed_fields": []
        }]);
        assert!(parse_schematic_reviewer_routing_policy(&value.to_string()).is_err());
    }

    #[test]
    fn schemas_are_closed() {
        let policy_schema = schematic_reviewer_routing_policy_json_schema();
        let plan_schema = schematic_reviewer_routing_plan_json_schema();
        assert_eq!(policy_schema["additionalProperties"], false);
        assert_eq!(
            policy_schema["$defs"]["profile"]["additionalProperties"],
            false
        );
        assert_eq!(plan_schema["additionalProperties"], false);
        assert_eq!(plan_schema["$defs"]["route"]["additionalProperties"], false);
    }
}

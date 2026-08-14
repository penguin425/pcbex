//! Digest-bound verification of a circuit-spec v2 or v3 document against a real
//! KiCad schematic.
//!
//! This module deliberately verifies a handoff; it does not generate or
//! rewrite KiCad files.  Geometry, UUIDs, and net ids are ignored for the
//! logical comparison.  The source digests and the two deterministic ERC
//! reviews remain in the report so a caller can retain an auditable binding.

use super::{
    CIRCUIT_SPEC_V2_SCHEMA_VERSION, CIRCUIT_SPEC_V3_SCHEMA_VERSION, ElectricalPolicy,
    ElectricalReview, SchematicDocument, SchematicPin, SchematicSymbol, check_circuit_spec,
    check_circuit_spec_v3, check_schematic, circuit_spec_source_schema_version,
    circuit_spec_v2_to_schematic, circuit_spec_v3_to_schematic, electrical_review_json_schema,
    import_schematic, parse_circuit_spec_v2, parse_circuit_spec_v3,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Schema version of [`CircuitKicadHandoffReport`].
pub const CIRCUIT_KICAD_HANDOFF_SCHEMA_VERSION: u32 = 1;
/// Compatibility alias used by clients that name report schemas explicitly.
pub const CIRCUIT_KICAD_HANDOFF_REPORT_SCHEMA_VERSION: u32 = CIRCUIT_KICAD_HANDOFF_SCHEMA_VERSION;
/// This is the engine version embedded in a handoff report.
pub const CIRCUIT_KICAD_HANDOFF_ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Maximum KiCad schematic source accepted by the handoff API.
pub const CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES: u64 = 64 * 1024 * 1024;

const HANDOFF_FINDING_CODES: [&str; 23] = [
    "coverage_incomplete",
    "missing_symbol",
    "duplicate_symbol_reference",
    "extra_power_symbol",
    "extra_symbol",
    "missing_net",
    "duplicate_net_name",
    "extra_net",
    "net_voltage_mismatch",
    "net_label_mismatch",
    "merged_expected_nets",
    "net_mismatch",
    "net_pin_reference_invalid",
    "multi_unit_symbol",
    "symbol_mismatch",
    "metadata_missing",
    "metadata_mismatch",
    "metadata_extra",
    "duplicate_pin_number",
    "missing_pin",
    "extra_pin",
    "pin_mismatch",
    "no_connect_mismatch",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitKicadHandoffFinding {
    pub code: String,
    pub message: String,
    pub reference: Option<String>,
    pub pin: Option<String>,
    pub net: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitKicadHandoffFindingCounts {
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
}

/// A deterministic, closed report for a circuit-spec-to-KiCad handoff.
///
/// `circuit_check_sha256` binds the complete canonical immutable circuit
/// check without duplicating its normalized spec in this report.  The two
/// reviews are retained because their findings are useful to CI callers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitKicadHandoffReport {
    pub schema_version: u32,
    pub engine_version: String,
    pub circuit_source_bytes: u64,
    pub circuit_source_sha256: String,
    pub schematic_source_bytes: u64,
    pub schematic_source_sha256: String,
    pub circuit_spec_sha256: String,
    pub circuit_check_sha256: String,
    pub circuit_review: ElectricalReview,
    pub schematic_sha256: String,
    pub schematic_review: ElectricalReview,
    pub policy_sha256: String,
    pub findings: Vec<CircuitKicadHandoffFinding>,
    pub counts: CircuitKicadHandoffFindingCounts,
    pub approved: bool,
}

/// Verify a JSON circuit-spec v2 or v3 against an actual KiCad `.kicad_sch` source.
///
/// Input parsing/contract errors are returned as `Err`.  Once both documents
/// have been imported, ERC and logical mapping failures are represented in a
/// report and make `approved` false; callers therefore retain useful evidence
/// even for a rejected handoff.
pub fn verify_circuit_kicad_handoff(
    circuit_source: &str,
    schematic_source: &str,
    policy: &ElectricalPolicy,
) -> Result<CircuitKicadHandoffReport, String> {
    if circuit_source.len() as u64 > super::CIRCUIT_SPEC_V2_MAX_BYTES {
        return Err(format!(
            "circuit specification exceeds the {}-byte handoff limit",
            super::CIRCUIT_SPEC_V2_MAX_BYTES
        ));
    }
    if schematic_source.len() as u64 > CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES {
        return Err(format!(
            "KiCad schematic exceeds the {CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES}-byte handoff limit"
        ));
    }
    let (circuit_spec_sha256, circuit_review, circuit_check_bytes, expected) =
        match circuit_spec_source_schema_version(circuit_source)? {
            CIRCUIT_SPEC_V2_SCHEMA_VERSION => {
                let spec = parse_circuit_spec_v2(circuit_source)?;
                let check = check_circuit_spec(&spec)?;
                let expected = circuit_spec_v2_to_schematic(&check.normalized_spec)?;
                let bytes = canonical_json(&check)?;
                (
                    check.circuit_spec_sha256,
                    check.electrical_review,
                    bytes,
                    expected,
                )
            }
            CIRCUIT_SPEC_V3_SCHEMA_VERSION => {
                let spec = parse_circuit_spec_v3(circuit_source)?;
                let check = check_circuit_spec_v3(&spec)?;
                let expected = circuit_spec_v3_to_schematic(&check.normalized_spec)?;
                let bytes = canonical_json(&check)?;
                (
                    check.circuit_spec_sha256,
                    check.electrical_review,
                    bytes,
                    expected,
                )
            }
            version => {
                return Err(format!(
                    "unsupported circuit-spec schema version {version} (expected {CIRCUIT_SPEC_V2_SCHEMA_VERSION} or {CIRCUIT_SPEC_V3_SCHEMA_VERSION})"
                ));
            }
        };
    let schematic = import_schematic(schematic_source)?;
    let schematic_review = check_schematic(&schematic, policy)?;
    let mut findings = compare_semantics(&expected, &schematic);

    // Coverage is safety-critical for a handoff even when an electrical policy
    // has no corresponding configurable rule.  Keep the finding deterministic
    // and avoid leaking any source paths.
    if !schematic.coverage.complete {
        let unsupported = schematic
            .coverage
            .unsupported_features
            .iter()
            .map(|feature| format!("{} ({})", feature.kind, feature.count))
            .collect::<Vec<_>>()
            .join(", ");
        push_finding(
            &mut findings,
            "coverage_incomplete",
            format!("KiCad schematic coverage is incomplete: {unsupported}"),
            None,
            None,
            None,
        );
    }
    sort_findings(&mut findings);

    let counts = CircuitKicadHandoffFindingCounts {
        errors: findings
            .len()
            .saturating_add(circuit_review.counts.errors)
            .saturating_add(schematic_review.counts.errors),
        warnings: circuit_review
            .counts
            .warnings
            .saturating_add(schematic_review.counts.warnings),
        info: circuit_review
            .counts
            .info
            .saturating_add(schematic_review.counts.info),
    };
    let schematic_sha256 = schematic_review.schematic_sha256.clone();
    let policy_sha256 = schematic_review.policy_sha256.clone();
    let approved = circuit_review.approved && schematic_review.approved && findings.is_empty();
    Ok(CircuitKicadHandoffReport {
        schema_version: CIRCUIT_KICAD_HANDOFF_SCHEMA_VERSION,
        engine_version: CIRCUIT_KICAD_HANDOFF_ENGINE_VERSION.to_string(),
        circuit_source_bytes: circuit_source.len() as u64,
        circuit_source_sha256: digest_hex(circuit_source.as_bytes()),
        schematic_source_bytes: schematic_source.len() as u64,
        schematic_source_sha256: digest_hex(schematic_source.as_bytes()),
        circuit_spec_sha256,
        circuit_check_sha256: digest_hex(&circuit_check_bytes),
        circuit_review,
        schematic_sha256,
        schematic_review,
        policy_sha256,
        findings,
        counts,
        approved,
    })
}

/// Return the manually closed JSON schema for [`CircuitKicadHandoffReport`].
pub fn circuit_kicad_handoff_report_json_schema() -> Value {
    let review_schema = electrical_review_json_schema();
    let mut definitions = Map::new();
    if let Some(review_defs) = review_schema["$defs"].as_object() {
        for (name, definition) in review_defs {
            definitions.insert(
                format!("electrical_{name}"),
                prefix_refs(definition.clone(), "electrical_"),
            );
        }
    }
    definitions.insert(
        "electrical_review".into(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": review_schema["required"].clone(),
            "properties": prefix_refs(review_schema["properties"].clone(), "electrical_")
        }),
    );
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/circuit-kicad-handoff-v1.json",
        "title": "pcbex circuit-spec v2 to KiCad schematic handoff",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "engine_version", "circuit_source_bytes",
            "circuit_source_sha256", "schematic_source_bytes", "schematic_source_sha256",
            "circuit_spec_sha256", "circuit_check_sha256", "circuit_review",
            "schematic_sha256", "schematic_review", "policy_sha256", "findings", "counts",
            "approved"
        ],
        "properties": {
            "schema_version": {"const": CIRCUIT_KICAD_HANDOFF_SCHEMA_VERSION},
            "engine_version": {"type": "string", "minLength": 1},
            "circuit_source_bytes": {"type": "integer", "minimum": 1},
            "circuit_source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "schematic_source_bytes": {"type": "integer", "minimum": 1},
            "schematic_source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "circuit_spec_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "circuit_check_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "circuit_review": {"$ref": "#/$defs/electrical_review"},
            "schematic_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "schematic_review": {"$ref": "#/$defs/electrical_review"},
            "policy_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "findings": {"type": "array", "items": {"$ref": "#/$defs/handoff_finding"}},
            "counts": {"$ref": "#/$defs/handoff_counts"},
            "approved": {"type": "boolean"}
        },
        "$defs": {
            "handoff_finding": {
                "type": "object",
                "additionalProperties": false,
                "required": ["code", "message", "reference", "pin", "net"],
                "properties": {
                    "code": {"enum": HANDOFF_FINDING_CODES},
                    "message": {"type": "string", "minLength": 1},
                    "reference": {"type": ["string", "null"], "minLength": 1},
                    "pin": {"type": ["string", "null"], "minLength": 1},
                    "net": {"type": ["string", "null"], "minLength": 1}
                }
            },
            "handoff_counts": {
                "type": "object",
                "additionalProperties": false,
                "required": ["errors", "warnings", "info"],
                "properties": {
                    "errors": {"type": "integer", "minimum": 0},
                    "warnings": {"type": "integer", "minimum": 0},
                    "info": {"type": "integer", "minimum": 0}
                }
            }
        }
    })
    .tap(|schema| {
        // Keep construction explicit while adding the reused electrical
        // definitions under the top-level closed `$defs` object.
        if let Some(defs) = schema["$defs"].as_object_mut() {
            defs.extend(definitions);
        }
    })
}

fn compare_semantics(
    expected: &SchematicDocument,
    actual: &SchematicDocument,
) -> Vec<CircuitKicadHandoffFinding> {
    let mut findings = Vec::new();
    let expected_by_key = expected
        .symbols
        .iter()
        .map(|symbol| ((symbol.reference.as_str(), symbol.unit), symbol))
        .collect::<BTreeMap<_, _>>();
    let mut actual_by_key = BTreeMap::<(&str, u32), Vec<&SchematicSymbol>>::new();
    for symbol in &actual.symbols {
        actual_by_key
            .entry((symbol.reference.as_str(), symbol.unit))
            .or_default()
            .push(symbol);
    }
    for (&(reference, unit), expected_symbol) in &expected_by_key {
        let Some(actual_symbols) = actual_by_key.get(&(reference, unit)) else {
            push_finding(
                &mut findings,
                "missing_symbol",
                if unit == 1 {
                    format!("KiCad schematic is missing symbol {reference}")
                } else {
                    format!("KiCad schematic is missing symbol {reference} unit {unit}")
                },
                Some(reference.to_string()),
                None,
                None,
            );
            continue;
        };
        if actual_symbols.len() > 1 {
            push_finding(
                &mut findings,
                "duplicate_symbol_reference",
                if unit == 1 {
                    format!("KiCad schematic has multiple symbols with reference {reference}")
                } else {
                    format!(
                        "KiCad schematic has multiple symbols with reference {reference} unit {unit}"
                    )
                },
                Some(reference.to_string()),
                None,
                None,
            );
        }
        compare_symbol(&mut findings, expected_symbol, actual_symbols[0]);
    }
    for (&(reference, unit), symbols) in &actual_by_key {
        if !expected_by_key.contains_key(&(reference, unit)) {
            for symbol in symbols {
                let power = symbol.lib_id.starts_with("power:") || reference.starts_with("#PWR");
                push_finding(
                    &mut findings,
                    if power {
                        "extra_power_symbol"
                    } else {
                        "extra_symbol"
                    },
                    format!(
                        "KiCad schematic contains an unexpected {} symbol {reference}{}",
                        if power { "power" } else { "normal" },
                        if unit == 1 {
                            String::new()
                        } else {
                            format!(" unit {unit}")
                        }
                    ),
                    Some(reference.to_string()),
                    None,
                    None,
                );
            }
        }
    }

    // Index imported pin identities once.  A large schematic may contain
    // tens of thousands of isolated no-connect nets, so repeatedly scanning
    // every symbol from every net would make this safety gate quadratic.
    let actual_symbol_by_uuid = actual
        .symbols
        .iter()
        .map(|symbol| (symbol.uuid.as_str(), symbol))
        .collect::<BTreeMap<_, _>>();
    let mut actual_pin_no_connect = BTreeMap::<(&str, &str), bool>::new();
    for symbol in &actual.symbols {
        for pin in &symbol.pins {
            actual_pin_no_connect
                .entry((symbol.uuid.as_str(), pin.number.as_str()))
                .and_modify(|all_no_connect| *all_no_connect &= pin.no_connect)
                .or_insert(pin.no_connect);
        }
    }

    // A circuit-spec net name is represented by an explicit KiCad label.
    // The optional voltage is represented by one additional canonical label.
    // Requiring the exact set both binds voltage_uv and rejects hidden aliases
    // that the configurable multiple-net-name ERC rule might only warn about.
    // Geometry-only wire islands and isolated no-connect pins remain ignored.
    let meaningful_actual_nets = actual
        .nets
        .iter()
        .filter(|net| {
            !net.labels.is_empty()
                || net.pins.iter().any(|pin| {
                    !actual_pin_no_connect
                        .get(&(pin.symbol_uuid.as_str(), pin.number.as_str()))
                        .copied()
                        .unwrap_or(false)
                })
        })
        .collect::<Vec<_>>();
    let mut expected_pin_no_connect = BTreeMap::<(&str, &str), bool>::new();
    for symbol in &expected.symbols {
        for pin in &symbol.pins {
            expected_pin_no_connect
                .insert((symbol.uuid.as_str(), pin.number.as_str()), pin.no_connect);
        }
    }
    let meaningful_expected_nets = expected
        .nets
        .iter()
        .filter(|net| {
            !net.labels.is_empty()
                || net.pins.iter().any(|pin| {
                    !expected_pin_no_connect
                        .get(&(pin.symbol_uuid.as_str(), pin.number.as_str()))
                        .copied()
                        .unwrap_or(false)
                })
        })
        .collect::<Vec<_>>();
    let mut matched_actual_net_ids = BTreeSet::new();
    let mut actual_net_to_expected = BTreeMap::<u32, &str>::new();
    let mut ambiguous_actual_net_ids = BTreeSet::new();
    for expected_net in meaningful_expected_nets {
        let expected_labels = std::iter::once(expected_net.name.clone())
            .chain(expected_net.labels.iter().cloned())
            .collect::<BTreeSet<_>>();
        let named_candidates = meaningful_actual_nets
            .iter()
            .copied()
            .filter(|actual_net| {
                actual_net
                    .labels
                    .iter()
                    .any(|label| label == &expected_net.name)
            })
            .collect::<Vec<_>>();
        let exact_candidates = named_candidates
            .iter()
            .copied()
            .filter(|actual_net| {
                actual_net.labels.iter().cloned().collect::<BTreeSet<_>>() == expected_labels
            })
            .collect::<Vec<_>>();
        // Exact label-set selection disambiguates a valid net whose canonical
        // voltage label is also the declared name of a different net.
        let candidates = if exact_candidates.is_empty() {
            &named_candidates
        } else {
            &exact_candidates
        };
        if candidates.is_empty() {
            push_finding(
                &mut findings,
                "missing_net",
                format!(
                    "KiCad schematic is missing the explicit net label {}",
                    expected_net.name
                ),
                None,
                None,
                Some(expected_net.name.clone()),
            );
            continue;
        }
        if candidates.len() > 1 {
            push_finding(
                &mut findings,
                "duplicate_net_name",
                format!(
                    "KiCad schematic uses net label {} on multiple nets",
                    expected_net.name
                ),
                None,
                None,
                Some(expected_net.name.clone()),
            );
            continue;
        }
        let actual_net = candidates[0];
        matched_actual_net_ids.insert(actual_net.id);
        if ambiguous_actual_net_ids.contains(&actual_net.id) {
            // A prior expected name already demonstrated that this imported
            // net merges multiple declared circuit nets.
        } else if let Some(previous) =
            actual_net_to_expected.insert(actual_net.id, &expected_net.name)
            && previous != expected_net.name
        {
            ambiguous_actual_net_ids.insert(actual_net.id);
            actual_net_to_expected.remove(&actual_net.id);
            push_finding(
                &mut findings,
                "merged_expected_nets",
                format!(
                    "KiCad net merges declared circuit nets {previous} and {}",
                    expected_net.name
                ),
                None,
                None,
                Some(expected_net.name.clone()),
            );
        }

        let actual_labels = actual_net.labels.iter().cloned().collect::<BTreeSet<_>>();
        for voltage_label in expected_net
            .labels
            .iter()
            .filter(|label| !actual_labels.contains(*label))
        {
            push_finding(
                &mut findings,
                "net_voltage_mismatch",
                format!(
                    "KiCad net {} is missing canonical voltage label {voltage_label}",
                    expected_net.name
                ),
                None,
                None,
                Some(expected_net.name.clone()),
            );
        }
        if actual_labels != expected_labels {
            push_finding(
                &mut findings,
                "net_label_mismatch",
                format!(
                    "KiCad net {} labels mismatch: expected {:?}, got {:?}",
                    expected_net.name, expected_labels, actual_labels
                ),
                None,
                None,
                Some(expected_net.name.clone()),
            );
        }
    }
    for actual_net in meaningful_actual_nets
        .iter()
        .filter(|net| !matched_actual_net_ids.contains(&net.id))
    {
        push_finding(
            &mut findings,
            "extra_net",
            format!(
                "KiCad schematic contains unexpected net {}",
                actual_net.name
            ),
            None,
            None,
            Some(actual_net.name.clone()),
        );
    }

    // Compare every reference/pin connection, not just the set of net names.
    // This prevents two pins from being swapped while preserving the same
    // collection of declared nets.
    let expected_net_names = expected
        .nets
        .iter()
        .map(|net| (net.id, net.name.as_str()))
        .collect::<BTreeMap<_, _>>();
    let expected_pin_nets = expected
        .symbols
        .iter()
        .flat_map(|symbol| {
            symbol.pins.iter().map(|pin| {
                (
                    (symbol.reference.as_str(), symbol.unit, pin.number.as_str()),
                    if pin.no_connect {
                        None
                    } else {
                        expected_net_names.get(&pin.net_id).copied()
                    },
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    for ((reference, unit, pin), expected_net) in expected_pin_nets {
        let Some(actual_symbol) = actual_by_key
            .get(&(reference, unit))
            .and_then(|symbols| symbols.first())
        else {
            continue;
        };
        let Some(actual_pin) = actual_symbol
            .pins
            .iter()
            .find(|candidate| candidate.number == pin)
        else {
            continue;
        };
        let actual_net = if actual_pin.no_connect {
            None
        } else {
            actual_net_to_expected.get(&actual_pin.net_id).copied()
        };
        if expected_net != actual_net {
            push_finding(
                &mut findings,
                "net_mismatch",
                format!(
                    "symbol {reference}{} pin {pin} net mismatch: expected {:?}, got {:?}",
                    if unit == 1 {
                        String::new()
                    } else {
                        format!(" unit {unit}")
                    },
                    expected_net,
                    actual_net
                ),
                Some(reference.to_string()),
                Some(pin.to_string()),
                expected_net.map(str::to_string),
            );
        }
    }
    // Keep the lookup above intentionally tied to actual imported UUIDs; a
    // malformed pin reference must not silently be treated as a match.
    for net in &actual.nets {
        for pin_ref in &net.pins {
            let valid = actual_symbol_by_uuid
                .get(pin_ref.symbol_uuid.as_str())
                .is_some_and(|symbol| {
                    symbol.reference == pin_ref.reference
                        && symbol.unit == pin_ref.unit
                        && symbol.pins.iter().any(|pin| pin.number == pin_ref.number)
                });
            if !valid {
                push_finding(
                    &mut findings,
                    "net_pin_reference_invalid",
                    format!("net {} references an unknown symbol UUID", net.name),
                    Some(pin_ref.reference.clone()),
                    Some(pin_ref.number.clone()),
                    Some(net.name.clone()),
                );
            }
        }
    }

    findings
}

fn compare_symbol(
    findings: &mut Vec<CircuitKicadHandoffFinding>,
    expected: &SchematicSymbol,
    actual: &SchematicSymbol,
) {
    let reference = Some(expected.reference.clone());
    if actual.unit != expected.unit || actual.convert != expected.convert {
        push_finding(
            findings,
            "multi_unit_symbol",
            if expected.unit == 1 && expected.convert == 1 {
                format!(
                    "symbol {} must be flat unit 1/convert 1 (got {}/{})",
                    expected.reference, actual.unit, actual.convert
                )
            } else {
                format!(
                    "symbol {} must be unit {}/convert {} (got {}/{})",
                    expected.reference,
                    expected.unit,
                    expected.convert,
                    actual.unit,
                    actual.convert
                )
            },
            reference.clone(),
            None,
            None,
        );
    }
    for (field, expected_value, actual_value) in [
        ("lib_id", expected.lib_id.as_str(), actual.lib_id.as_str()),
        ("value", expected.value.as_str(), actual.value.as_str()),
    ] {
        if expected_value != actual_value {
            push_finding(
                findings,
                "symbol_mismatch",
                format!(
                    "symbol {} {field} mismatch: expected {expected_value:?}, got {actual_value:?}",
                    expected.reference
                ),
                reference.clone(),
                None,
                None,
            );
        }
    }
    if expected.footprint != actual.footprint
        || expected.in_bom != actual.in_bom
        || expected.on_board != actual.on_board
        || expected.dnp != actual.dnp
    {
        push_finding(
            findings,
            "symbol_mismatch",
            format!(
                "symbol {} manufacturing properties mismatch",
                expected.reference
            ),
            reference.clone(),
            None,
            None,
        );
    }
    let expected_metadata = expected
        .properties
        .iter()
        .filter(|(key, _)| key.starts_with("pcbex:"))
        .collect::<BTreeMap<_, _>>();
    let actual_metadata = actual
        .properties
        .iter()
        .filter(|(key, _)| key.starts_with("pcbex:"))
        .collect::<BTreeMap<_, _>>();
    for (key, value) in &expected_metadata {
        match actual_metadata.get(key) {
            None => push_finding(
                findings,
                "metadata_missing",
                format!(
                    "symbol {} is missing expected {key} metadata",
                    expected.reference
                ),
                reference.clone(),
                None,
                None,
            ),
            Some(actual_value) if *actual_value != *value => push_finding(
                findings,
                "metadata_mismatch",
                format!(
                    "symbol {} metadata {key} mismatch: expected {value:?}, got {actual_value:?}",
                    expected.reference
                ),
                reference.clone(),
                None,
                None,
            ),
            Some(_) => {}
        }
    }
    for key in actual_metadata
        .keys()
        .filter(|key| !expected_metadata.contains_key(*key))
    {
        push_finding(
            findings,
            "metadata_extra",
            format!(
                "symbol {} has unexpected {key} metadata",
                expected.reference
            ),
            reference.clone(),
            None,
            None,
        );
    }

    let expected_pins = expected
        .pins
        .iter()
        .map(|pin| (pin.number.as_str(), pin))
        .collect::<BTreeMap<_, _>>();
    let mut actual_pins = BTreeMap::new();
    for pin in &actual.pins {
        if actual_pins.insert(pin.number.as_str(), pin).is_some() {
            push_finding(
                findings,
                "duplicate_pin_number",
                format!(
                    "symbol {} contains duplicate pin number {}",
                    expected.reference, pin.number
                ),
                reference.clone(),
                Some(pin.number.clone()),
                None,
            );
        }
    }
    for (&number, expected_pin) in &expected_pins {
        let Some(actual_pin) = actual_pins.get(number) else {
            push_finding(
                findings,
                "missing_pin",
                format!("symbol {} is missing pin {number}", expected.reference),
                reference.clone(),
                Some(number.to_string()),
                None,
            );
            continue;
        };
        compare_pin(findings, expected, expected_pin, actual_pin);
    }
    for &number in actual_pins
        .keys()
        .filter(|number| !expected_pins.contains_key(*number))
    {
        push_finding(
            findings,
            "extra_pin",
            format!(
                "symbol {} contains unexpected pin {number}",
                expected.reference
            ),
            reference.clone(),
            Some(number.to_string()),
            None,
        );
    }
}

fn compare_pin(
    findings: &mut Vec<CircuitKicadHandoffFinding>,
    expected_symbol: &SchematicSymbol,
    expected: &SchematicPin,
    actual: &SchematicPin,
) {
    let reference = Some(expected_symbol.reference.clone());
    if expected.name != actual.name
        || expected.electrical_type != actual.electrical_type
        || expected.hidden != actual.hidden
    {
        push_finding(
            findings,
            "pin_mismatch",
            format!(
                "symbol {} pin {} definition mismatch",
                expected_symbol.reference, expected.number
            ),
            reference.clone(),
            Some(expected.number.clone()),
            None,
        );
    }
    if expected.no_connect != actual.no_connect {
        push_finding(
            findings,
            "no_connect_mismatch",
            format!(
                "symbol {} pin {} no-connect mismatch",
                expected_symbol.reference, expected.number
            ),
            reference,
            Some(expected.number.clone()),
            None,
        );
    }
}

fn push_finding(
    findings: &mut Vec<CircuitKicadHandoffFinding>,
    code: &str,
    message: String,
    reference: Option<String>,
    pin: Option<String>,
    net: Option<String>,
) {
    findings.push(CircuitKicadHandoffFinding {
        code: code.into(),
        message,
        reference,
        pin,
        net,
    });
}

fn sort_findings(findings: &mut [CircuitKicadHandoffFinding]) {
    findings.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then_with(|| left.reference.cmp(&right.reference))
            .then_with(|| left.pin.cmp(&right.pin))
            .then_with(|| left.net.cmp(&right.net))
            .then_with(|| left.message.cmp(&right.message))
    });
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value)
        .map_err(|error| format!("serializing canonical handoff JSON: {error}"))
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn prefix_refs(value: Value, prefix: &str) -> Value {
    match value {
        Value::String(text) if text.starts_with("#/$defs/") => {
            Value::String(format!("#/$defs/{prefix}{}", &text[8..]))
        }
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| prefix_refs(value, prefix))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, prefix_refs(value, prefix)))
                .collect(),
        ),
        value => value,
    }
}

// serde_json::Value has no stable `tap` method; keep schema assembly readable
// without relying on an extension trait.
trait ValueTap {
    fn tap(self, f: impl FnOnce(&mut Value)) -> Value;
}
impl ValueTap for Value {
    fn tap(mut self, f: impl FnOnce(&mut Value)) -> Value {
        f(&mut self);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two passive symbols share a labelled net; pin 2 of each is explicitly
    // no-connect.  The fixture intentionally has no geometry-sensitive
    // assertions in the handoff tests.
    const SPEC: &str = r#"{
      "schema_version":2,
      "parts":[
        {"reference":"R1","lib_id":"Device:R","value":"10k","footprint":"Package:R_0603","mpn":null,
         "power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},
         "pins":[{"number":"1","name":"~","net":"SIG","electrical_type":"passive"},{"number":"2","name":"~","net":null,"electrical_type":"no_connect"}]},
        {"reference":"R2","lib_id":"Device:R","value":"10k","footprint":"Package:R_0603","mpn":null,
         "power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},
         "pins":[{"number":"1","name":"~","net":"SIG","electrical_type":"passive"},{"number":"2","name":"~","net":null,"electrical_type":"no_connect"}]}
      ],
      "nets":[{"name":"SIG","voltage_uv":null,"connections":[{"reference":"R1","pin":"1"},{"reference":"R2","pin":"1"}]}]
    }"#;

    const SCHEMATIC: &str = r#"(kicad_sch
      (version 20231120) (generator eeschema) (generator_version "8.0") (uuid root)
      (lib_symbols
        (symbol "Device:R"
          (symbol "R_1_1"
            (pin passive line (at -2.54 0 0) (length 2.54) (name "~") (number "1"))
            (pin no_connect line (at 2.54 0 180) (length 2.54) (name "~") (number "2")))))
      (wire (pts (xy 10 20) (xy 10 10) (xy 27.46 10) (xy 27.46 20)) (uuid wire1))
      (label "SIG" (at 20 10 0) (uuid label1))
      (no_connect (at 15.08 20) (uuid nc1))
      (no_connect (at 32.54 20) (uuid nc2))
      (symbol (lib_id "Device:R") (at 12.54 20 0) (unit 1)
        (in_bom yes) (on_board yes) (uuid sr1)
        (property "Reference" "R1") (property "Value" "10k") (property "Footprint" "Package:R_0603")
        (property "pcbex:requires_decoupling" "false") (property "pcbex:decoupling" "false")
        (pin "1" (uuid pr11)) (pin "2" (uuid pr12)))
      (symbol (lib_id "Device:R") (at 30 20 0) (unit 1)
        (in_bom yes) (on_board yes) (uuid sr2)
        (property "Reference" "R2") (property "Value" "10k") (property "Footprint" "Package:R_0603")
        (property "pcbex:requires_decoupling" "false") (property "pcbex:decoupling" "false")
        (pin "1" (uuid pr21)) (pin "2" (uuid pr22)))
    )"#;

    const SWAP_SPEC: &str = r#"{
      "schema_version":2,
      "parts":[
        {"reference":"R1","lib_id":"Device:R","value":"1k","footprint":"Package:R_0603","mpn":null,
         "power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},
         "pins":[{"number":"1","name":"~","net":"A","electrical_type":"passive"},{"number":"2","name":"~","net":null,"electrical_type":"no_connect"}]},
        {"reference":"R2","lib_id":"Device:R","value":"1k","footprint":"Package:R_0603","mpn":null,
         "power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},
         "pins":[{"number":"1","name":"~","net":"A","electrical_type":"passive"},{"number":"2","name":"~","net":null,"electrical_type":"no_connect"}]},
        {"reference":"R3","lib_id":"Device:R","value":"2k","footprint":"Package:R_0603","mpn":null,
         "power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},
         "pins":[{"number":"1","name":"~","net":"B","electrical_type":"passive"},{"number":"2","name":"~","net":null,"electrical_type":"no_connect"}]},
        {"reference":"R4","lib_id":"Device:R","value":"2k","footprint":"Package:R_0603","mpn":null,
         "power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},
         "pins":[{"number":"1","name":"~","net":"B","electrical_type":"passive"},{"number":"2","name":"~","net":null,"electrical_type":"no_connect"}]}
      ],
      "nets":[
        {"name":"A","voltage_uv":null,"connections":[{"reference":"R1","pin":"1"},{"reference":"R2","pin":"1"}]},
        {"name":"B","voltage_uv":null,"connections":[{"reference":"R3","pin":"1"},{"reference":"R4","pin":"1"}]}
      ]
    }"#;

    #[test]
    fn schema_is_closed_and_reviews_are_reused() {
        let schema = circuit_kicad_handoff_report_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["$defs"]["handoff_finding"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["$defs"]["electrical_review"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn rejects_malformed_contract() {
        assert!(
            verify_circuit_kicad_handoff("{}", SCHEMATIC, &ElectricalPolicy::default()).is_err()
        );
        assert!(
            verify_circuit_kicad_handoff(SPEC, "not a schematic", &ElectricalPolicy::default())
                .is_err()
        );
    }

    #[test]
    fn report_binds_raw_sources_deterministically() {
        let report =
            verify_circuit_kicad_handoff(SPEC, SCHEMATIC, &ElectricalPolicy::default()).unwrap();
        let again =
            verify_circuit_kicad_handoff(SPEC, SCHEMATIC, &ElectricalPolicy::default()).unwrap();
        assert_eq!(report, again);
        assert_eq!(report.circuit_source_bytes, SPEC.len() as u64);
        assert_eq!(report.schematic_source_bytes, SCHEMATIC.len() as u64);
        assert_eq!(report.circuit_spec_sha256.len(), 64);
        assert_eq!(
            report.schematic_sha256,
            report.schematic_review.schematic_sha256
        );
        assert!(report.approved);
        assert!(report.findings.is_empty());
        assert_eq!(report.counts.errors, 0);
    }

    #[test]
    fn rejects_missing_voltage_annotation_and_extra_net_alias() {
        let voltage_spec = SPEC.replacen("\"voltage_uv\":null", "\"voltage_uv\":5000000", 1);
        let missing_voltage =
            verify_circuit_kicad_handoff(&voltage_spec, SCHEMATIC, &ElectricalPolicy::default())
                .unwrap();
        assert!(!missing_voltage.approved);
        assert!(
            missing_voltage
                .findings
                .iter()
                .any(|finding| finding.code == "net_voltage_mismatch")
        );

        let annotated = SCHEMATIC.replace(
            "      (no_connect (at 15.08 20) (uuid nc1))",
            "      (label \"5V\" (at 20 10 0) (uuid label2))\n      (no_connect (at 15.08 20) (uuid nc1))",
        );
        let exact_voltage =
            verify_circuit_kicad_handoff(&voltage_spec, &annotated, &ElectricalPolicy::default())
                .unwrap();
        assert!(exact_voltage.approved, "{:?}", exact_voltage.findings);

        let mut strict_labels = ElectricalPolicy::default();
        strict_labels
            .rules
            .get_mut("multiple_net_names")
            .unwrap()
            .severity = super::super::ElectricalSeverity::Error;
        let erc_rejected =
            verify_circuit_kicad_handoff(&voltage_spec, &annotated, &strict_labels).unwrap();
        assert!(!erc_rejected.approved);
        assert!(erc_rejected.findings.is_empty());
        assert_eq!(erc_rejected.counts.errors, 1);
        assert_eq!(erc_rejected.schematic_review.counts.errors, 1);

        let aliased = SCHEMATIC.replace(
            "      (no_connect (at 15.08 20) (uuid nc1))",
            "      (label \"SIG_ALIAS\" (at 20 10 0) (uuid label2))\n      (no_connect (at 15.08 20) (uuid nc1))",
        );
        let extra_alias =
            verify_circuit_kicad_handoff(SPEC, &aliased, &ElectricalPolicy::default()).unwrap();
        assert!(!extra_alias.approved);
        assert!(
            extra_alias
                .findings
                .iter()
                .any(|finding| finding.code == "net_label_mismatch")
        );
    }

    #[test]
    fn detects_swapped_pin_net_membership_with_same_net_set() {
        let spec = parse_circuit_spec_v2(SWAP_SPEC).unwrap();
        let expected = circuit_spec_v2_to_schematic(&spec).unwrap();
        let mut actual = expected.clone();
        for net in &mut actual.nets {
            if net.name == "A" || net.name == "B" {
                net.labels = vec![net.name.clone()];
            }
        }
        let net_a = actual.nets.iter().find(|net| net.name == "A").unwrap().id;
        let net_b = actual.nets.iter().find(|net| net.name == "B").unwrap().id;
        for symbol in &mut actual.symbols {
            if symbol.reference == "R1" || symbol.reference == "R3" {
                symbol
                    .pins
                    .iter_mut()
                    .find(|pin| pin.number == "1")
                    .unwrap()
                    .net_id = if symbol.reference == "R1" {
                    net_b
                } else {
                    net_a
                };
            }
        }
        let findings = compare_semantics(&expected, &actual);
        assert!(findings.iter().any(|finding| {
            finding.code == "net_mismatch"
                && finding.reference.as_deref() == Some("R1")
                && finding.pin.as_deref() == Some("1")
        }));
        assert!(
            !findings
                .iter()
                .any(|finding| { matches!(finding.code.as_str(), "missing_net" | "extra_net") })
        );

        let mut duplicate_pin = actual.clone();
        let duplicate = duplicate_pin.symbols[0].pins[0].clone();
        duplicate_pin.symbols[0].pins.push(duplicate);
        let findings = compare_semantics(&expected, &duplicate_pin);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "duplicate_pin_number")
        );
    }
}

use super::{ElectricalPinType, SchematicDocument, SchematicNet, SchematicPin, SchematicSymbol};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

const SCHEMA_VERSION: u32 = 1;
const MAX_ITEMS: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicDiffIdentity {
    pub schematic_sha256: String,
    pub document_uuid: String,
    pub source_version: u32,
    pub coverage_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicSymbolSummary {
    pub uuid: String,
    pub reference: String,
    pub lib_id: String,
    pub value: String,
    pub footprint: Option<String>,
    pub unit: u32,
    pub pin_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicPinSummary {
    pub id: String,
    pub number: String,
    pub name: String,
    pub electrical_type: ElectricalPinType,
    pub hidden: bool,
    pub no_connect: bool,
    pub net_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicPinChange {
    pub id: String,
    pub number: String,
    pub changed_fields: Vec<String>,
    pub baseline: SchematicPinSummary,
    pub current: SchematicPinSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicSymbolChange {
    pub uuid: String,
    pub baseline_reference: String,
    pub current_reference: String,
    pub changed_fields: Vec<String>,
    pub added_pins: Vec<SchematicPinSummary>,
    pub removed_pins: Vec<SchematicPinSummary>,
    pub changed_pins: Vec<SchematicPinChange>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicNetSummary {
    pub key: String,
    pub name: String,
    pub labels: Vec<String>,
    pub pins: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicNetChange {
    pub key: String,
    pub name: String,
    pub added_labels: Vec<String>,
    pub removed_labels: Vec<String>,
    pub added_pins: Vec<String>,
    pub removed_pins: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicDiffCounts {
    pub added_symbols: usize,
    pub removed_symbols: usize,
    pub modified_symbols: usize,
    pub added_pins: usize,
    pub removed_pins: usize,
    pub modified_pins: usize,
    pub added_nets: usize,
    pub removed_nets: usize,
    pub modified_nets: usize,
    pub affected_symbols: usize,
    pub affected_nets: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicSemanticDiff {
    pub schema_version: u32,
    pub baseline: SchematicDiffIdentity,
    pub current: SchematicDiffIdentity,
    pub changed: bool,
    pub review_required: bool,
    pub coverage_changed: bool,
    pub counts: SchematicDiffCounts,
    pub added_symbols: Vec<SchematicSymbolSummary>,
    pub removed_symbols: Vec<SchematicSymbolSummary>,
    pub modified_symbols: Vec<SchematicSymbolChange>,
    pub added_nets: Vec<SchematicNetSummary>,
    pub removed_nets: Vec<SchematicNetSummary>,
    pub modified_nets: Vec<SchematicNetChange>,
    pub affected_symbol_uuids: Vec<String>,
    pub affected_references: Vec<String>,
    pub affected_net_keys: Vec<String>,
}

pub fn compare_schematics(
    baseline: &SchematicDocument,
    current: &SchematicDocument,
) -> Result<SchematicSemanticDiff, String> {
    validate_document(baseline, "baseline")?;
    validate_document(current, "current")?;
    let baseline_net_keys = net_keys(baseline)?;
    let current_net_keys = net_keys(current)?;
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

    let added_symbols = current_symbols
        .iter()
        .filter(|(uuid, _)| !baseline_symbols.contains_key(**uuid))
        .map(|(_, symbol)| symbol_summary(symbol))
        .collect::<Vec<_>>();
    let removed_symbols = baseline_symbols
        .iter()
        .filter(|(uuid, _)| !current_symbols.contains_key(**uuid))
        .map(|(_, symbol)| symbol_summary(symbol))
        .collect::<Vec<_>>();
    let mut modified_symbols = Vec::new();
    for (uuid, current_symbol) in &current_symbols {
        let Some(baseline_symbol) = baseline_symbols.get(uuid) else {
            continue;
        };
        if let Some(change) = compare_symbol(
            baseline_symbol,
            current_symbol,
            &baseline_net_keys,
            &current_net_keys,
        )? {
            modified_symbols.push(change);
        }
    }

    let baseline_nets = semantic_nets(baseline, &baseline_net_keys)?;
    let current_nets = semantic_nets(current, &current_net_keys)?;
    let added_nets = current_nets
        .iter()
        .filter(|(key, _)| !baseline_nets.contains_key(*key))
        .map(|(_, net)| net.clone())
        .collect::<Vec<_>>();
    let removed_nets = baseline_nets
        .iter()
        .filter(|(key, _)| !current_nets.contains_key(*key))
        .map(|(_, net)| net.clone())
        .collect::<Vec<_>>();
    let mut modified_nets = Vec::new();
    for (key, current_net) in &current_nets {
        let Some(baseline_net) = baseline_nets.get(key) else {
            continue;
        };
        let added_labels = difference(&current_net.labels, &baseline_net.labels);
        let removed_labels = difference(&baseline_net.labels, &current_net.labels);
        let added_pins = difference(&current_net.pins, &baseline_net.pins);
        let removed_pins = difference(&baseline_net.pins, &current_net.pins);
        if !added_labels.is_empty()
            || !removed_labels.is_empty()
            || !added_pins.is_empty()
            || !removed_pins.is_empty()
        {
            modified_nets.push(SchematicNetChange {
                key: key.clone(),
                name: current_net.name.clone(),
                added_labels,
                removed_labels,
                added_pins,
                removed_pins,
            });
        }
    }

    let coverage_changed = baseline.coverage != current.coverage;
    let changed = coverage_changed
        || !added_symbols.is_empty()
        || !removed_symbols.is_empty()
        || !modified_symbols.is_empty()
        || !added_nets.is_empty()
        || !removed_nets.is_empty()
        || !modified_nets.is_empty();
    let review_required = changed || !baseline.coverage.complete || !current.coverage.complete;

    let mut affected_symbol_uuids = BTreeSet::new();
    let mut affected_references = BTreeSet::new();
    for symbol in &added_symbols {
        affected_symbol_uuids.insert(symbol.uuid.clone());
        affected_references.insert(symbol.reference.clone());
    }
    for symbol in &removed_symbols {
        affected_symbol_uuids.insert(symbol.uuid.clone());
        affected_references.insert(symbol.reference.clone());
    }
    for symbol in &modified_symbols {
        affected_symbol_uuids.insert(symbol.uuid.clone());
        affected_references.insert(symbol.baseline_reference.clone());
        affected_references.insert(symbol.current_reference.clone());
    }
    let mut affected_net_keys = added_nets
        .iter()
        .chain(&removed_nets)
        .map(|net| net.key.clone())
        .chain(modified_nets.iter().map(|net| net.key.clone()))
        .collect::<BTreeSet<_>>();
    for symbol in &modified_symbols {
        for pin in symbol.added_pins.iter().chain(&symbol.removed_pins).chain(
            symbol
                .changed_pins
                .iter()
                .flat_map(|pin| [&pin.baseline, &pin.current]),
        ) {
            affected_net_keys.insert(pin.net_key.clone());
        }
    }
    for net_key in &affected_net_keys {
        for net in [baseline_nets.get(net_key), current_nets.get(net_key)]
            .into_iter()
            .flatten()
        {
            for pin in &net.pins {
                if let Some((uuid, _)) = pin.split_once(':') {
                    affected_symbol_uuids.insert(uuid.to_string());
                    if let Some(symbol) = baseline_symbols
                        .get(uuid)
                        .copied()
                        .or_else(|| current_symbols.get(uuid).copied())
                    {
                        affected_references.insert(symbol.reference.clone());
                    }
                }
            }
        }
    }
    let counts = SchematicDiffCounts {
        added_symbols: added_symbols.len(),
        removed_symbols: removed_symbols.len(),
        modified_symbols: modified_symbols.len(),
        added_pins: added_symbols
            .iter()
            .map(|item| item.pin_count)
            .sum::<usize>()
            + modified_symbols
                .iter()
                .map(|item| item.added_pins.len())
                .sum::<usize>(),
        removed_pins: removed_symbols
            .iter()
            .map(|item| item.pin_count)
            .sum::<usize>()
            + modified_symbols
                .iter()
                .map(|item| item.removed_pins.len())
                .sum::<usize>(),
        modified_pins: modified_symbols
            .iter()
            .map(|item| item.changed_pins.len())
            .sum(),
        added_nets: added_nets.len(),
        removed_nets: removed_nets.len(),
        modified_nets: modified_nets.len(),
        affected_symbols: affected_symbol_uuids.len(),
        affected_nets: affected_net_keys.len(),
    };
    Ok(SchematicSemanticDiff {
        schema_version: SCHEMA_VERSION,
        baseline: identity(baseline)?,
        current: identity(current)?,
        changed,
        review_required,
        coverage_changed,
        counts,
        added_symbols,
        removed_symbols,
        modified_symbols,
        added_nets,
        removed_nets,
        modified_nets,
        affected_symbol_uuids: affected_symbol_uuids.into_iter().collect(),
        affected_references: affected_references.into_iter().collect(),
        affected_net_keys: affected_net_keys.into_iter().collect(),
    })
}

pub fn schematic_diff_to_sarif(diff: &SchematicSemanticDiff) -> Value {
    let mut results = Vec::new();
    for symbol in &diff.added_symbols {
        results.push(sarif_result(
            "schematic_symbol_added",
            format!("symbol {} ({}) was added", symbol.reference, symbol.lib_id),
            Some(&symbol.uuid),
        ));
    }
    for symbol in &diff.removed_symbols {
        results.push(sarif_result(
            "schematic_symbol_removed",
            format!(
                "symbol {} ({}) was removed",
                symbol.reference, symbol.lib_id
            ),
            Some(&symbol.uuid),
        ));
    }
    for symbol in &diff.modified_symbols {
        results.push(sarif_result(
            "schematic_symbol_modified",
            format!(
                "symbol {} changed: {}",
                symbol.current_reference,
                symbol.changed_fields.join(", ")
            ),
            Some(&symbol.uuid),
        ));
    }
    for net in &diff.added_nets {
        results.push(sarif_result(
            "schematic_net_added",
            format!("net {} was added", net.name),
            None,
        ));
    }
    for net in &diff.removed_nets {
        results.push(sarif_result(
            "schematic_net_removed",
            format!("net {} was removed", net.name),
            None,
        ));
    }
    for net in &diff.modified_nets {
        results.push(sarif_result(
            "schematic_net_modified",
            format!(
                "net {} changed: {} pin(s) added, {} removed",
                net.name,
                net.added_pins.len(),
                net.removed_pins.len()
            ),
            None,
        ));
    }
    if !diff.baseline.coverage_complete || !diff.current.coverage_complete {
        results.push(sarif_result(
            "schematic_coverage_incomplete",
            "schematic semantic diff has incomplete importer coverage".into(),
            None,
        ));
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pcbex compare-schematics",
                "informationUri": "https://github.com/penguin425/pcbex"
            }},
            "results": results
        }]
    })
}

pub fn render_schematic_diff_summary(diff: &SchematicSemanticDiff) -> String {
    format!(
        "## Schematic semantic diff\n\n\
         - Changed: `{}`\n\
         - Review required: `{}`\n\
         - Symbols: +{} / -{} / ~{}\n\
         - Pins: +{} / -{} / ~{}\n\
         - Nets: +{} / -{} / ~{}\n\
         - Affected references: {}\n\
         - Baseline SHA-256: `{}`\n\
         - Current SHA-256: `{}`\n",
        diff.changed,
        diff.review_required,
        diff.counts.added_symbols,
        diff.counts.removed_symbols,
        diff.counts.modified_symbols,
        diff.counts.added_pins,
        diff.counts.removed_pins,
        diff.counts.modified_pins,
        diff.counts.added_nets,
        diff.counts.removed_nets,
        diff.counts.modified_nets,
        if diff.affected_references.is_empty() {
            "(none)".into()
        } else {
            diff.affected_references.join(", ")
        },
        diff.baseline.schematic_sha256,
        diff.current.schematic_sha256
    )
}

pub fn schematic_diff_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/schematic-semantic-diff-v1.json",
        "title": "pcbex schematic semantic diff",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "baseline", "current", "changed", "review_required",
            "coverage_changed", "counts", "added_symbols", "removed_symbols",
            "modified_symbols", "added_nets", "removed_nets", "modified_nets",
            "affected_symbol_uuids", "affected_references", "affected_net_keys"
        ],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "baseline": {"$ref": "#/$defs/identity"},
            "current": {"$ref": "#/$defs/identity"},
            "changed": {"type": "boolean"},
            "review_required": {"type": "boolean"},
            "coverage_changed": {"type": "boolean"},
            "counts": {"$ref": "#/$defs/counts"},
            "added_symbols": {"type": "array", "items": {"$ref": "#/$defs/symbol"}},
            "removed_symbols": {"type": "array", "items": {"$ref": "#/$defs/symbol"}},
            "modified_symbols": {"type": "array", "items": {"$ref": "#/$defs/symbol_change"}},
            "added_nets": {"type": "array", "items": {"$ref": "#/$defs/net"}},
            "removed_nets": {"type": "array", "items": {"$ref": "#/$defs/net"}},
            "modified_nets": {"type": "array", "items": {"$ref": "#/$defs/net_change"}},
            "affected_symbol_uuids": {"type": "array", "items": {"type": "string", "minLength": 1}},
            "affected_references": {"type": "array", "items": {"type": "string", "minLength": 1}},
            "affected_net_keys": {"type": "array", "items": {"type": "string", "minLength": 1}}
        },
        "$defs": {
            "identity": {
                "type": "object", "additionalProperties": false,
                "required": ["schematic_sha256", "document_uuid", "source_version", "coverage_complete"],
                "properties": {
                    "schematic_sha256": digest_schema(),
                    "document_uuid": {"type": "string", "minLength": 1},
                    "source_version": {"type": "integer", "minimum": 1},
                    "coverage_complete": {"type": "boolean"}
                }
            },
            "symbol": symbol_schema(),
            "pin": pin_schema(),
            "pin_change": {
                "type": "object", "additionalProperties": false,
                "required": ["id", "number", "changed_fields", "baseline", "current"],
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "number": {"type": "string", "minLength": 1},
                    "changed_fields": string_array_schema(),
                    "baseline": {"$ref": "#/$defs/pin"},
                    "current": {"$ref": "#/$defs/pin"}
                }
            },
            "symbol_change": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "uuid", "baseline_reference", "current_reference", "changed_fields",
                    "added_pins", "removed_pins", "changed_pins"
                ],
                "properties": {
                    "uuid": {"type": "string", "minLength": 1},
                    "baseline_reference": {"type": "string", "minLength": 1},
                    "current_reference": {"type": "string", "minLength": 1},
                    "changed_fields": string_array_schema(),
                    "added_pins": {"type": "array", "items": {"$ref": "#/$defs/pin"}},
                    "removed_pins": {"type": "array", "items": {"$ref": "#/$defs/pin"}},
                    "changed_pins": {"type": "array", "items": {"$ref": "#/$defs/pin_change"}}
                }
            },
            "net": net_schema(),
            "net_change": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "key", "name", "added_labels", "removed_labels",
                    "added_pins", "removed_pins"
                ],
                "properties": {
                    "key": {"type": "string", "minLength": 1},
                    "name": {"type": "string", "minLength": 1},
                    "added_labels": string_array_schema(),
                    "removed_labels": string_array_schema(),
                    "added_pins": string_array_schema(),
                    "removed_pins": string_array_schema()
                }
            },
            "counts": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "added_symbols", "removed_symbols", "modified_symbols",
                    "added_pins", "removed_pins", "modified_pins",
                    "added_nets", "removed_nets", "modified_nets",
                    "affected_symbols", "affected_nets"
                ],
                "properties": {
                    "added_symbols": count_schema(),
                    "removed_symbols": count_schema(),
                    "modified_symbols": count_schema(),
                    "added_pins": count_schema(),
                    "removed_pins": count_schema(),
                    "modified_pins": count_schema(),
                    "added_nets": count_schema(),
                    "removed_nets": count_schema(),
                    "modified_nets": count_schema(),
                    "affected_symbols": count_schema(),
                    "affected_nets": count_schema()
                }
            }
        }
    })
}

fn compare_symbol(
    baseline: &SchematicSymbol,
    current: &SchematicSymbol,
    baseline_net_keys: &BTreeMap<u32, String>,
    current_net_keys: &BTreeMap<u32, String>,
) -> Result<Option<SchematicSymbolChange>, String> {
    let mut changed_fields = Vec::new();
    macro_rules! changed {
        ($field:ident) => {
            if baseline.$field != current.$field {
                changed_fields.push(stringify!($field).to_string());
            }
        };
    }
    changed!(lib_id);
    changed!(reference);
    changed!(value);
    changed!(footprint);
    changed!(unit);
    changed!(convert);
    changed!(in_bom);
    changed!(on_board);
    changed!(dnp);
    if custom_properties(baseline) != custom_properties(current) {
        changed_fields.push("properties".into());
    }
    let baseline_pins = pin_summaries(baseline, baseline_net_keys)?;
    let current_pins = pin_summaries(current, current_net_keys)?;
    let added_pins = current_pins
        .iter()
        .filter(|(id, _)| !baseline_pins.contains_key(*id))
        .map(|(_, pin)| pin.clone())
        .collect::<Vec<_>>();
    let removed_pins = baseline_pins
        .iter()
        .filter(|(id, _)| !current_pins.contains_key(*id))
        .map(|(_, pin)| pin.clone())
        .collect::<Vec<_>>();
    let mut changed_pins = Vec::new();
    for (id, current_pin) in &current_pins {
        let Some(baseline_pin) = baseline_pins.get(id) else {
            continue;
        };
        let mut fields = Vec::new();
        macro_rules! pin_changed {
            ($field:ident) => {
                if baseline_pin.$field != current_pin.$field {
                    fields.push(stringify!($field).to_string());
                }
            };
        }
        pin_changed!(number);
        pin_changed!(name);
        pin_changed!(electrical_type);
        pin_changed!(hidden);
        pin_changed!(no_connect);
        if baseline_pin.net_key != current_pin.net_key {
            fields.push("connectivity".into());
        }
        if !fields.is_empty() {
            changed_pins.push(SchematicPinChange {
                id: (*id).clone(),
                number: current_pin.number.clone(),
                changed_fields: fields,
                baseline: (*baseline_pin).clone(),
                current: current_pin.clone(),
            });
        }
    }
    if !added_pins.is_empty() || !removed_pins.is_empty() || !changed_pins.is_empty() {
        changed_fields.push("pins".into());
    }
    if added_pins.is_empty()
        && removed_pins.is_empty()
        && changed_pins.is_empty()
        && changed_fields.is_empty()
    {
        Ok(None)
    } else {
        Ok(Some(SchematicSymbolChange {
            uuid: current.uuid.clone(),
            baseline_reference: baseline.reference.clone(),
            current_reference: current.reference.clone(),
            changed_fields,
            added_pins,
            removed_pins,
            changed_pins,
        }))
    }
}

fn pin_summaries(
    symbol: &SchematicSymbol,
    net_keys: &BTreeMap<u32, String>,
) -> Result<BTreeMap<String, SchematicPinSummary>, String> {
    let mut result = BTreeMap::new();
    for pin in &symbol.pins {
        let id = pin_identity(pin);
        let net_key = net_keys.get(&pin.net_id).cloned().ok_or_else(|| {
            format!(
                "symbol {} pin {} references unknown net {}",
                symbol.reference, pin.number, pin.net_id
            )
        })?;
        let summary = SchematicPinSummary {
            id: id.clone(),
            number: pin.number.clone(),
            name: pin.name.clone(),
            electrical_type: pin.electrical_type,
            hidden: pin.hidden,
            no_connect: pin.no_connect,
            net_key,
        };
        if result.insert(id.clone(), summary).is_some() {
            return Err(format!(
                "symbol {} has duplicate semantic pin identity {id:?}",
                symbol.reference
            ));
        }
    }
    Ok(result)
}

fn net_keys(document: &SchematicDocument) -> Result<BTreeMap<u32, String>, String> {
    let mut result = BTreeMap::new();
    let mut used = HashSet::new();
    for net in &document.nets {
        let key = if net.pins.is_empty() && net.labels.is_empty() {
            format!("ignored:{}", net.id)
        } else if let Some(label) = net.labels.first() {
            format!("label:{label}")
        } else {
            let pins = net_pin_keys(net);
            let payload = pins.join("\n");
            format!("pins:{:x}", Sha256::digest(payload.as_bytes()))
        };
        if !used.insert(key.clone()) {
            return Err(format!(
                "schematic contains duplicate semantic net key {key:?}"
            ));
        }
        if result.insert(net.id, key).is_some() {
            return Err(format!("schematic contains duplicate net id {}", net.id));
        }
    }
    Ok(result)
}

fn semantic_nets(
    document: &SchematicDocument,
    keys: &BTreeMap<u32, String>,
) -> Result<BTreeMap<String, SchematicNetSummary>, String> {
    let mut result = BTreeMap::new();
    for net in &document.nets {
        if net.pins.is_empty() && net.labels.is_empty() {
            continue;
        }
        let key = keys
            .get(&net.id)
            .cloned()
            .ok_or_else(|| format!("missing semantic key for net {}", net.id))?;
        result.insert(
            key.clone(),
            SchematicNetSummary {
                key,
                name: if net.labels.is_empty() {
                    "(unnamed)".into()
                } else {
                    net.name.clone()
                },
                labels: sorted_unique(net.labels.clone()),
                pins: net_pin_keys(net),
            },
        );
    }
    Ok(result)
}

fn net_pin_keys(net: &SchematicNet) -> Vec<String> {
    sorted_unique(
        net.pins
            .iter()
            .map(|pin| format!("{}:{}:{}", pin.symbol_uuid, pin.unit, pin.number))
            .collect(),
    )
}

fn validate_document(document: &SchematicDocument, label: &str) -> Result<(), String> {
    if document.schema_version != 1 {
        return Err(format!(
            "unsupported {label} schematic schema version {}",
            document.schema_version
        ));
    }
    if document.symbols.len() > MAX_ITEMS || document.nets.len() > MAX_ITEMS {
        return Err(format!(
            "{label} schematic exceeds semantic diff item limits"
        ));
    }
    if document.uuid.trim().is_empty() {
        return Err(format!("{label} schematic document UUID must not be blank"));
    }
    if document.coverage.complete != document.coverage.unsupported_features.is_empty() {
        return Err(format!(
            "{label} schematic coverage flag is inconsistent with unsupported features"
        ));
    }
    let keys = net_keys(document)?;
    let mut uuids = HashSet::new();
    for symbol in &document.symbols {
        if symbol.uuid.trim().is_empty() || !uuids.insert(&symbol.uuid) {
            return Err(format!(
                "{label} schematic has blank or duplicate symbol UUID {:?}",
                symbol.uuid
            ));
        }
        pin_summaries(symbol, &keys)?;
    }
    for net in &document.nets {
        let pins = net_pin_keys(net);
        if pins.len() != net.pins.len() {
            return Err(format!(
                "{label} schematic net {} contains duplicate pin references",
                net.id
            ));
        }
    }
    Ok(())
}

fn identity(document: &SchematicDocument) -> Result<SchematicDiffIdentity, String> {
    let bytes = serde_json::to_vec(document)
        .map_err(|error| format!("serializing schematic IR: {error}"))?;
    Ok(SchematicDiffIdentity {
        schematic_sha256: format!("{:x}", Sha256::digest(bytes)),
        document_uuid: document.uuid.clone(),
        source_version: document.source_version,
        coverage_complete: document.coverage.complete,
    })
}

fn symbol_summary(symbol: &SchematicSymbol) -> SchematicSymbolSummary {
    SchematicSymbolSummary {
        uuid: symbol.uuid.clone(),
        reference: symbol.reference.clone(),
        lib_id: symbol.lib_id.clone(),
        value: symbol.value.clone(),
        footprint: symbol.footprint.clone(),
        unit: symbol.unit,
        pin_count: symbol.pins.len(),
    }
}

fn custom_properties(symbol: &SchematicSymbol) -> BTreeMap<&str, &str> {
    symbol
        .properties
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "Reference" | "Value" | "Footprint"))
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

fn pin_identity(pin: &SchematicPin) -> String {
    pin.uuid
        .as_ref()
        .map(|uuid| format!("uuid:{uuid}"))
        .unwrap_or_else(|| format!("number:{}", pin.number))
}

fn difference(current: &[String], baseline: &[String]) -> Vec<String> {
    let baseline = baseline.iter().collect::<BTreeSet<_>>();
    current
        .iter()
        .filter(|value| !baseline.contains(value))
        .cloned()
        .collect()
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn sarif_result(rule: &str, message: String, symbol_uuid: Option<&str>) -> Value {
    let mut properties = json!({});
    if let Some(uuid) = symbol_uuid {
        properties["symbolUuid"] = uuid.into();
    }
    json!({
        "ruleId": rule,
        "level": "warning",
        "message": {"text": message},
        "properties": properties
    })
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn count_schema() -> Value {
    json!({"type": "integer", "minimum": 0})
}

fn string_array_schema() -> Value {
    json!({"type": "array", "items": {"type": "string", "minLength": 1}})
}

fn symbol_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "uuid", "reference", "lib_id", "value", "footprint", "unit", "pin_count"
        ],
        "properties": {
            "uuid": {"type": "string", "minLength": 1},
            "reference": {"type": "string", "minLength": 1},
            "lib_id": {"type": "string", "minLength": 1},
            "value": {"type": "string"},
            "footprint": {"type": ["string", "null"]},
            "unit": {"type": "integer", "minimum": 1},
            "pin_count": count_schema()
        }
    })
}

fn pin_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "id", "number", "name", "electrical_type", "hidden", "no_connect", "net_key"
        ],
        "properties": {
            "id": {"type": "string", "minLength": 1},
            "number": {"type": "string", "minLength": 1},
            "name": {"type": "string"},
            "electrical_type": {
                "enum": [
                    "input", "output", "bidirectional", "tri_state", "passive",
                    "free", "unspecified", "power_input", "power_output",
                    "open_collector", "open_emitter", "no_connect"
                ]
            },
            "hidden": {"type": "boolean"},
            "no_connect": {"type": "boolean"},
            "net_key": {"type": "string", "minLength": 1}
        }
    })
}

fn net_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["key", "name", "labels", "pins"],
        "properties": {
            "key": {"type": "string", "minLength": 1},
            "name": {"type": "string", "minLength": 1},
            "labels": string_array_schema(),
            "pins": string_array_schema()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import_schematic;

    fn schematic() -> SchematicDocument {
        import_schematic(include_str!("../../../examples/simple.kicad_sch")).unwrap()
    }

    #[test]
    fn ignores_drawing_changes_but_detects_electrical_intent() {
        let baseline = schematic();
        let mut drawing_only = baseline.clone();
        drawing_only.symbols[0].position.x_nm += 1_000_000;
        drawing_only.wires.reverse();
        let unchanged = compare_schematics(&baseline, &drawing_only).unwrap();
        assert!(!unchanged.changed);
        assert!(!unchanged.review_required);
        assert_ne!(
            unchanged.baseline.schematic_sha256,
            unchanged.current.schematic_sha256
        );

        let mut current = baseline.clone();
        current.symbols[0].value = "22k".into();
        current.symbols[0]
            .properties
            .insert("Value".into(), "22k".into());
        current.symbols[1].pins[0].electrical_type = ElectricalPinType::Bidirectional;
        let diff = compare_schematics(&baseline, &current).unwrap();
        assert!(diff.changed);
        assert!(diff.review_required);
        assert_eq!(diff.counts.modified_symbols, 2);
        assert_eq!(diff.counts.modified_pins, 1);
        assert!(
            diff.modified_symbols
                .iter()
                .any(|symbol| symbol.changed_fields.contains(&"value".into()))
        );
    }

    #[test]
    fn detects_connectivity_changes_without_using_net_numbers() {
        let baseline = schematic();
        let mut current = baseline.clone();
        let signal_id = current
            .nets
            .iter()
            .find(|net| net.name == "SIGNAL")
            .unwrap()
            .id;
        let other_id = current
            .nets
            .iter()
            .find(|net| net.id != signal_id)
            .unwrap()
            .id;
        current.symbols[0].pins[0].net_id = other_id;
        let pin_ref = current
            .nets
            .iter_mut()
            .find(|net| net.id == signal_id)
            .unwrap()
            .pins
            .remove(0);
        current
            .nets
            .iter_mut()
            .find(|net| net.id == other_id)
            .unwrap()
            .pins
            .push(pin_ref);
        let diff = compare_schematics(&baseline, &current).unwrap();
        assert!(diff.review_required);
        assert!(!diff.modified_nets.is_empty() || !diff.added_nets.is_empty());
        assert!(!diff.affected_references.is_empty());
    }

    #[test]
    fn net_number_and_collection_order_do_not_create_changes() {
        let baseline = schematic();
        let mut current = baseline.clone();
        let mapping = current
            .nets
            .iter()
            .map(|net| (net.id, 1_000 - net.id))
            .collect::<BTreeMap<_, _>>();
        for net in &mut current.nets {
            net.id = mapping[&net.id];
            net.pins.reverse();
        }
        current.nets.reverse();
        current.symbols.reverse();
        for symbol in &mut current.symbols {
            symbol.pins.reverse();
            for pin in &mut symbol.pins {
                pin.net_id = mapping[&pin.net_id];
            }
        }
        for label in &mut current.labels {
            label.net_id = mapping[&label.net_id];
        }
        let diff = compare_schematics(&baseline, &current).unwrap();
        assert!(!diff.changed);
        assert!(!diff.review_required);
    }

    #[test]
    fn schema_is_closed_and_incomplete_coverage_requires_review() {
        let schema = schematic_diff_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["$defs"]["symbol_change"]["additionalProperties"],
            false
        );
        let baseline = schematic();
        let mut current = baseline.clone();
        current.coverage.complete = false;
        current
            .coverage
            .unsupported_features
            .push(crate::SchematicUnsupportedFeature {
                kind: "sheet".into(),
                count: 1,
            });
        let diff = compare_schematics(&baseline, &current).unwrap();
        assert!(diff.coverage_changed);
        assert!(diff.review_required);
        assert_eq!(schematic_diff_to_sarif(&diff)["version"], "2.1.0");
    }
}

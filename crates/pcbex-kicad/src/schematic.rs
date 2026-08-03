use super::{Sexp, atom, parse};
use pcbex_core::Point;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const NM_PER_MM: f64 = 1_000_000.0;
const MAX_SUPPORTED_SCHEMATIC_VERSION: u32 = 20_250_318;
const MAX_ITEMS: usize = 100_000;
const MAX_CONNECTIVITY_TESTS: usize = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElectricalPinType {
    Input,
    Output,
    Bidirectional,
    TriState,
    Passive,
    Free,
    Unspecified,
    PowerInput,
    PowerOutput,
    OpenCollector,
    OpenEmitter,
    NoConnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchematicLabelKind {
    Local,
    Global,
    PowerGlobal,
    PowerLocal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicWire {
    pub uuid: String,
    pub points: Vec<Point>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicMarker {
    pub uuid: String,
    pub position: Point,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicLabel {
    pub uuid: Option<String>,
    pub name: String,
    pub kind: SchematicLabelKind,
    pub position: Point,
    pub net_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicPinRef {
    pub symbol_uuid: String,
    pub reference: String,
    pub unit: u32,
    pub number: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicPin {
    pub uuid: Option<String>,
    pub number: String,
    pub name: String,
    pub electrical_type: ElectricalPinType,
    pub position: Point,
    pub hidden: bool,
    pub net_id: u32,
    pub no_connect: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicSymbol {
    pub uuid: String,
    pub lib_id: String,
    pub reference: String,
    pub value: String,
    pub footprint: Option<String>,
    pub unit: u32,
    pub convert: u32,
    pub in_bom: bool,
    pub on_board: bool,
    pub dnp: bool,
    pub position: Point,
    pub rotation_deg: u16,
    pub mirror_x: bool,
    pub mirror_y: bool,
    pub properties: BTreeMap<String, String>,
    pub pins: Vec<SchematicPin>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicNet {
    pub id: u32,
    pub name: String,
    pub labels: Vec<String>,
    pub pins: Vec<SchematicPinRef>,
    pub points: Vec<Point>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicUnsupportedFeature {
    pub kind: String,
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicCoverage {
    pub complete: bool,
    pub unsupported_features: Vec<SchematicUnsupportedFeature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchematicDocument {
    pub schema_version: u32,
    pub source_version: u32,
    pub generator: String,
    pub generator_version: Option<String>,
    pub uuid: String,
    pub symbols: Vec<SchematicSymbol>,
    pub wires: Vec<SchematicWire>,
    pub junctions: Vec<SchematicMarker>,
    pub no_connects: Vec<SchematicMarker>,
    pub labels: Vec<SchematicLabel>,
    pub nets: Vec<SchematicNet>,
    pub coverage: SchematicCoverage,
}

pub fn schematic_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/schematic-ir-v1.json",
        "title": "pcbex schematic electrical IR",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "source_version", "generator", "generator_version", "uuid",
            "symbols", "wires", "junctions", "no_connects", "labels", "nets", "coverage"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "source_version": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_SUPPORTED_SCHEMATIC_VERSION
            },
            "generator": {"type": "string", "minLength": 1},
            "generator_version": {"type": ["string", "null"]},
            "uuid": {"type": "string", "minLength": 1},
            "symbols": {"type": "array", "items": {"$ref": "#/$defs/symbol"}},
            "wires": {"type": "array", "items": {"$ref": "#/$defs/wire"}},
            "junctions": {"type": "array", "items": {"$ref": "#/$defs/marker"}},
            "no_connects": {"type": "array", "items": {"$ref": "#/$defs/marker"}},
            "labels": {"type": "array", "items": {"$ref": "#/$defs/label"}},
            "nets": {"type": "array", "items": {"$ref": "#/$defs/net"}},
            "coverage": {"$ref": "#/$defs/coverage"}
        },
        "$defs": {
            "point": {
                "type": "object",
                "additionalProperties": false,
                "required": ["x_nm", "y_nm"],
                "properties": {
                    "x_nm": {"type": "integer"},
                    "y_nm": {"type": "integer"}
                }
            },
            "wire": {
                "type": "object",
                "additionalProperties": false,
                "required": ["uuid", "points"],
                "properties": {
                    "uuid": {"type": "string", "minLength": 1},
                    "points": {
                        "type": "array",
                        "minItems": 2,
                        "items": {"$ref": "#/$defs/point"}
                    }
                }
            },
            "marker": {
                "type": "object",
                "additionalProperties": false,
                "required": ["uuid", "position"],
                "properties": {
                    "uuid": {"type": "string", "minLength": 1},
                    "position": {"$ref": "#/$defs/point"}
                }
            },
            "pin_ref": {
                "type": "object",
                "additionalProperties": false,
                "required": ["symbol_uuid", "reference", "unit", "number"],
                "properties": {
                    "symbol_uuid": {"type": "string", "minLength": 1},
                    "reference": {"type": "string", "minLength": 1},
                    "unit": {"type": "integer", "minimum": 1},
                    "number": {"type": "string", "minLength": 1}
                }
            },
            "pin": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "uuid", "number", "name", "electrical_type", "position", "hidden",
                    "net_id", "no_connect"
                ],
                "properties": {
                    "uuid": {"type": ["string", "null"]},
                    "number": {"type": "string", "minLength": 1},
                    "name": {"type": "string"},
                    "electrical_type": {
                        "enum": [
                            "input", "output", "bidirectional", "tri_state", "passive",
                            "free", "unspecified", "power_input", "power_output",
                            "open_collector", "open_emitter", "no_connect"
                        ]
                    },
                    "position": {"$ref": "#/$defs/point"},
                    "hidden": {"type": "boolean"},
                    "net_id": {"type": "integer", "minimum": 1},
                    "no_connect": {"type": "boolean"}
                }
            },
            "symbol": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "uuid", "lib_id", "reference", "value", "footprint", "unit", "convert",
                    "in_bom", "on_board", "dnp", "position", "rotation_deg", "mirror_x",
                    "mirror_y", "properties", "pins"
                ],
                "properties": {
                    "uuid": {"type": "string", "minLength": 1},
                    "lib_id": {"type": "string", "minLength": 1},
                    "reference": {"type": "string", "minLength": 1},
                    "value": {"type": "string", "minLength": 1},
                    "footprint": {"type": ["string", "null"]},
                    "unit": {"type": "integer", "minimum": 1},
                    "convert": {"type": "integer", "minimum": 0},
                    "in_bom": {"type": "boolean"},
                    "on_board": {"type": "boolean"},
                    "dnp": {"type": "boolean"},
                    "position": {"$ref": "#/$defs/point"},
                    "rotation_deg": {"enum": [0, 90, 180, 270]},
                    "mirror_x": {"type": "boolean"},
                    "mirror_y": {"type": "boolean"},
                    "properties": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "pins": {"type": "array", "items": {"$ref": "#/$defs/pin"}}
                }
            },
            "label": {
                "type": "object",
                "additionalProperties": false,
                "required": ["uuid", "name", "kind", "position", "net_id"],
                "properties": {
                    "uuid": {"type": ["string", "null"]},
                    "name": {"type": "string", "minLength": 1},
                    "kind": {"enum": ["local", "global", "power_global", "power_local"]},
                    "position": {"$ref": "#/$defs/point"},
                    "net_id": {"type": "integer", "minimum": 1}
                }
            },
            "net": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "name", "labels", "pins", "points"],
                "properties": {
                    "id": {"type": "integer", "minimum": 1},
                    "name": {"type": "string", "minLength": 1},
                    "labels": {"type": "array", "items": {"type": "string", "minLength": 1}},
                    "pins": {"type": "array", "items": {"$ref": "#/$defs/pin_ref"}},
                    "points": {"type": "array", "items": {"$ref": "#/$defs/point"}}
                }
            },
            "unsupported_feature": {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "count"],
                "properties": {
                    "kind": {"type": "string", "minLength": 1},
                    "count": {"type": "integer", "minimum": 1}
                }
            },
            "coverage": {
                "type": "object",
                "additionalProperties": false,
                "required": ["complete", "unsupported_features"],
                "properties": {
                    "complete": {"type": "boolean"},
                    "unsupported_features": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/unsupported_feature"}
                    }
                }
            }
        }
    })
}

#[derive(Clone)]
struct LibraryPin {
    number: String,
    name: String,
    electrical_type: ElectricalPinType,
    position: Point,
    hidden: bool,
}

struct LibrarySymbol<'a> {
    values: &'a [Sexp],
    power: Option<PowerScope>,
    extends: bool,
}

#[derive(Clone, Copy)]
enum PowerScope {
    Global,
    Local,
}

pub fn import_schematic(source: &str) -> Result<SchematicDocument, String> {
    let root = parse(source)?;
    let top = root
        .as_list()
        .ok_or_else(|| "KiCad schematic is not an s-expression".to_string())?;
    if atom(top.first()) != Some("kicad_sch") {
        return Err("expected a kicad_sch document".into());
    }
    let source_version = required_u32(top, "version")?;
    if source_version > MAX_SUPPORTED_SCHEMATIC_VERSION {
        return Err(format!(
            "KiCad schematic version {source_version} is newer than supported version \
             {MAX_SUPPORTED_SCHEMATIC_VERSION}"
        ));
    }
    let generator = required_atom(top, "generator")?.to_string();
    let generator_version = optional_atom(top, "generator_version")?.map(str::to_string);
    let uuid = required_atom(top, "uuid")?.to_string();

    let libraries = library_symbols(top)?;
    let mut unsupported = BTreeMap::<String, usize>::new();
    for kind in [
        "bus",
        "bus_entry",
        "bus_alias",
        "directive_label",
        "netclass_flag",
        "hierarchical_label",
        "sheet",
    ] {
        let count = direct_lists(top, kind).count();
        if count != 0 {
            unsupported.insert(kind.to_string(), count);
        }
    }

    let mut symbols = Vec::new();
    let mut seen_uuids = BTreeSet::new();
    for values in direct_lists(top, "symbol") {
        if symbols.len() >= MAX_ITEMS {
            return Err(format!("schematic exceeds the {MAX_ITEMS} symbol limit"));
        }
        let lib_id = optional_atom(values, "lib_id")?
            .or_else(|| atom(values.get(1)))
            .ok_or_else(|| "schematic symbol is missing a library identifier".to_string())?;
        let library = libraries.get(lib_id).ok_or_else(|| {
            format!("schematic symbol references missing library symbol {lib_id}")
        })?;
        if library.extends {
            *unsupported.entry("extended_lib_symbol".into()).or_default() += 1;
        }
        let symbol = import_symbol(values, lib_id, library)?;
        if !seen_uuids.insert(symbol.uuid.clone()) {
            return Err(format!("duplicate schematic symbol UUID {}", symbol.uuid));
        }
        symbols.push(symbol);
    }
    symbols.sort_by(|left, right| {
        left.reference
            .cmp(&right.reference)
            .then_with(|| left.unit.cmp(&right.unit))
            .then_with(|| left.uuid.cmp(&right.uuid))
    });

    let mut wires = Vec::new();
    let mut wire_uuids = BTreeSet::new();
    for values in direct_lists(top, "wire") {
        if wires.len() >= MAX_ITEMS {
            return Err(format!("schematic exceeds the {MAX_ITEMS} wire limit"));
        }
        let uuid = required_atom(values, "uuid")?.to_string();
        if !wire_uuids.insert(uuid.clone()) {
            return Err(format!("duplicate schematic wire UUID {uuid}"));
        }
        let points = point_list(values)?;
        if points.len() < 2 {
            return Err(format!(
                "schematic wire {uuid} must contain at least two points"
            ));
        }
        if points.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(format!(
                "schematic wire {uuid} contains a zero-length segment"
            ));
        }
        wires.push(SchematicWire { uuid, points });
    }
    wires.sort_by(|left, right| left.uuid.cmp(&right.uuid));

    let mut junctions = direct_lists(top, "junction")
        .map(import_marker)
        .collect::<Result<Vec<_>, _>>()?;
    let mut no_connects = direct_lists(top, "no_connect")
        .map(import_marker)
        .collect::<Result<Vec<_>, _>>()?;
    if junctions.len() > MAX_ITEMS || no_connects.len() > MAX_ITEMS {
        return Err(format!("schematic exceeds the {MAX_ITEMS} marker limit"));
    }
    junctions.sort_by(|left, right| {
        point_key(left.position)
            .cmp(&point_key(right.position))
            .then_with(|| left.uuid.cmp(&right.uuid))
    });
    no_connects.sort_by(|left, right| {
        point_key(left.position)
            .cmp(&point_key(right.position))
            .then_with(|| left.uuid.cmp(&right.uuid))
    });

    let mut labels = Vec::new();
    for (token, kind) in [
        ("label", SchematicLabelKind::Local),
        ("global_label", SchematicLabelKind::Global),
    ] {
        for values in direct_lists(top, token) {
            labels.push(import_label(values, kind)?);
        }
    }
    for symbol in &symbols {
        if let Some(scope) = libraries
            .get(&symbol.lib_id)
            .and_then(|library| library.power)
        {
            for pin in &symbol.pins {
                if pin.name.trim().is_empty() {
                    return Err(format!(
                        "power symbol {} pin {} has a blank net name",
                        symbol.reference, pin.number
                    ));
                }
                labels.push(SchematicLabel {
                    uuid: None,
                    name: pin.name.clone(),
                    kind: match scope {
                        PowerScope::Global => SchematicLabelKind::PowerGlobal,
                        PowerScope::Local => SchematicLabelKind::PowerLocal,
                    },
                    position: pin.position,
                    net_id: 0,
                });
            }
        }
    }
    if labels.len() > MAX_ITEMS {
        return Err(format!("schematic exceeds the {MAX_ITEMS} label limit"));
    }
    labels.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| point_key(left.position).cmp(&point_key(right.position)))
            .then_with(|| left.uuid.cmp(&right.uuid))
    });

    validate_unique_uuids(&uuid, &symbols, &wires, &junctions, &no_connects, &labels)?;
    let nets = connect(&mut symbols, &wires, &junctions, &no_connects, &mut labels)?;
    let unsupported_features = unsupported
        .into_iter()
        .map(|(kind, count)| SchematicUnsupportedFeature { kind, count })
        .collect::<Vec<_>>();
    Ok(SchematicDocument {
        schema_version: 1,
        source_version,
        generator,
        generator_version,
        uuid,
        symbols,
        wires,
        junctions,
        no_connects,
        labels,
        nets,
        coverage: SchematicCoverage {
            complete: unsupported_features.is_empty(),
            unsupported_features,
        },
    })
}

fn library_symbols(top: &[Sexp]) -> Result<HashMap<String, LibrarySymbol<'_>>, String> {
    let values = unique_child_values(top, "lib_symbols")?
        .ok_or_else(|| "KiCad schematic is missing lib_symbols".to_string())?;
    let mut libraries = HashMap::new();
    for symbol in direct_lists(values, "symbol") {
        let id = atom(symbol.get(1))
            .ok_or_else(|| "library symbol is missing its identifier".to_string())?;
        if id.trim().is_empty() {
            return Err("library symbol identifier must not be blank".into());
        }
        let definition = LibrarySymbol {
            values: symbol,
            power: power_scope(symbol)?,
            extends: optional_atom(symbol, "extends")?.is_some(),
        };
        if libraries.insert(id.to_string(), definition).is_some() {
            return Err(format!("duplicate library symbol identifier {id}"));
        }
    }
    Ok(libraries)
}

fn import_symbol(
    values: &[Sexp],
    lib_id: &str,
    library: &LibrarySymbol<'_>,
) -> Result<SchematicSymbol, String> {
    let uuid = required_atom(values, "uuid")?.to_string();
    let unit = optional_u32(values, "unit")?.unwrap_or(1);
    let convert = optional_u32(values, "convert")?.unwrap_or(1);
    if unit == 0 {
        return Err(format!("schematic symbol {uuid} has invalid unit 0"));
    }
    let (position, rotation_deg) = required_point_with_rotation(
        values,
        "at",
        PointArity::OptionalRotation,
        &format!("schematic symbol {uuid}"),
    )?;
    let mirror = optional_atom(values, "mirror")?;
    if mirror.is_some_and(|value| value != "x" && value != "y") {
        return Err(format!("schematic symbol {uuid} has invalid mirror axis"));
    }
    let mirror_x = mirror == Some("x");
    let mirror_y = mirror == Some("y");
    let properties = properties(values)?;
    let reference = properties
        .get("Reference")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("schematic symbol {uuid} is missing Reference"))?
        .clone();
    let value = properties
        .get("Value")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("schematic symbol {reference} is missing Value"))?
        .clone();
    let footprint = properties
        .get("Footprint")
        .filter(|value| !value.trim().is_empty())
        .cloned();

    let definitions = library_pins(library.values, unit, convert)?;
    let instance_uuids = instance_pin_uuids(values)?;
    for number in instance_uuids.keys() {
        if !definitions.iter().any(|pin| &pin.number == number) {
            return Err(format!(
                "schematic symbol {reference} maps unknown library pin {number}"
            ));
        }
    }
    let mut pins = definitions
        .into_iter()
        .map(|pin| {
            let relative = transform(pin.position, rotation_deg, mirror_x, mirror_y)?;
            Ok(SchematicPin {
                uuid: instance_uuids.get(&pin.number).cloned(),
                number: pin.number,
                name: pin.name,
                electrical_type: pin.electrical_type,
                position: add_points(position, relative)?,
                hidden: pin.hidden,
                net_id: 0,
                no_connect: false,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    pins.sort_by(|left, right| natural_pin_cmp(&left.number, &right.number));
    Ok(SchematicSymbol {
        uuid,
        lib_id: lib_id.to_string(),
        reference,
        value,
        footprint,
        unit,
        convert,
        in_bom: yes_no(values, "in_bom", true)?,
        on_board: yes_no(values, "on_board", true)?,
        dnp: yes_no(values, "dnp", false)?,
        position,
        rotation_deg,
        mirror_x,
        mirror_y,
        properties,
        pins,
    })
}

fn library_pins(values: &[Sexp], unit: u32, convert: u32) -> Result<Vec<LibraryPin>, String> {
    let mut pins = Vec::new();
    collect_library_pins(values, unit, convert, None, &mut pins)?;
    let mut numbers = BTreeSet::new();
    for pin in &pins {
        if !numbers.insert(pin.number.clone()) {
            return Err(format!(
                "library symbol unit {unit} contains duplicate pin number {}",
                pin.number
            ));
        }
    }
    Ok(pins)
}

fn collect_library_pins(
    values: &[Sexp],
    target_unit: u32,
    target_convert: u32,
    container: Option<(u32, u32)>,
    out: &mut Vec<LibraryPin>,
) -> Result<(), String> {
    let include = container.is_none_or(|(unit, convert)| {
        (unit == 0 || unit == target_unit) && (convert == 0 || convert == target_convert)
    });
    if include {
        for pin in direct_lists(values, "pin") {
            out.push(import_library_pin(pin)?);
        }
    }
    for symbol in direct_lists(values, "symbol") {
        let name = atom(symbol.get(1)).unwrap_or_default();
        let container = symbol_container(name);
        collect_library_pins(symbol, target_unit, target_convert, container, out)?;
    }
    Ok(())
}

fn symbol_container(name: &str) -> Option<(u32, u32)> {
    let mut parts = name.rsplit('_');
    let convert = parts.next()?.parse::<u32>().ok()?;
    let unit = parts.next()?.parse().ok()?;
    Some((unit, convert))
}

fn import_library_pin(values: &[Sexp]) -> Result<LibraryPin, String> {
    let electrical_type = match atom(values.get(1)).unwrap_or_default() {
        "input" => ElectricalPinType::Input,
        "output" => ElectricalPinType::Output,
        "bidirectional" => ElectricalPinType::Bidirectional,
        "tri_state" => ElectricalPinType::TriState,
        "passive" => ElectricalPinType::Passive,
        "free" => ElectricalPinType::Free,
        "unspecified" => ElectricalPinType::Unspecified,
        "power_in" => ElectricalPinType::PowerInput,
        "power_out" => ElectricalPinType::PowerOutput,
        "open_collector" => ElectricalPinType::OpenCollector,
        "open_emitter" => ElectricalPinType::OpenEmitter,
        "no_connect" => ElectricalPinType::NoConnect,
        value => return Err(format!("unknown symbol pin electrical type {value}")),
    };
    let position = required_point(values, "at", PointArity::RequiredRotation, "library pin")?;
    let name = unique_child_values(values, "name")?
        .and_then(|child| atom(child.get(1)))
        .ok_or_else(|| "library pin is missing a name".to_string())?
        .to_string();
    let number = unique_child_values(values, "number")?
        .and_then(|child| atom(child.get(1)))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "library pin is missing a non-blank number".to_string())?
        .to_string();
    Ok(LibraryPin {
        number,
        name,
        electrical_type,
        position,
        hidden: yes_no(values, "hide", false)?,
    })
}

fn instance_pin_uuids(values: &[Sexp]) -> Result<BTreeMap<String, String>, String> {
    let mut pins = BTreeMap::new();
    for pin in direct_lists(values, "pin") {
        let number = atom(pin.get(1))
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "symbol pin instance is missing its number".to_string())?;
        let uuid = required_atom(pin, "uuid")?.to_string();
        if pins.insert(number.to_string(), uuid).is_some() {
            return Err(format!("symbol contains duplicate pin instance {number}"));
        }
    }
    Ok(pins)
}

fn import_label(values: &[Sexp], kind: SchematicLabelKind) -> Result<SchematicLabel, String> {
    let name = atom(values.get(1))
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| "schematic label must have a non-blank name".to_string())?;
    Ok(SchematicLabel {
        uuid: Some(required_atom(values, "uuid")?.to_string()),
        name: name.to_string(),
        kind,
        position: required_point(
            values,
            "at",
            PointArity::OptionalRotation,
            "schematic label",
        )?,
        net_id: 0,
    })
}

fn import_marker(values: &[Sexp]) -> Result<SchematicMarker, String> {
    Ok(SchematicMarker {
        uuid: required_atom(values, "uuid")?.to_string(),
        position: required_point(values, "at", PointArity::Plain, "schematic marker")?,
    })
}

fn validate_unique_uuids(
    root_uuid: &str,
    symbols: &[SchematicSymbol],
    wires: &[SchematicWire],
    junctions: &[SchematicMarker],
    no_connects: &[SchematicMarker],
    labels: &[SchematicLabel],
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    let mut insert = |uuid: &str| {
        if uuid.trim().is_empty() {
            return Err("schematic UUID must not be blank".into());
        }
        if !seen.insert(uuid.to_string()) {
            return Err(format!("duplicate schematic UUID {uuid}"));
        }
        Ok(())
    };
    insert(root_uuid)?;
    for symbol in symbols {
        insert(&symbol.uuid)?;
        for pin in &symbol.pins {
            if let Some(uuid) = &pin.uuid {
                insert(uuid)?;
            }
        }
    }
    for wire in wires {
        insert(&wire.uuid)?;
    }
    for marker in junctions.iter().chain(no_connects) {
        insert(&marker.uuid)?;
    }
    for label in labels {
        if let Some(uuid) = &label.uuid {
            insert(uuid)?;
        }
    }
    Ok(())
}

fn connect(
    symbols: &mut [SchematicSymbol],
    wires: &[SchematicWire],
    junctions: &[SchematicMarker],
    no_connects: &[SchematicMarker],
    labels: &mut [SchematicLabel],
) -> Result<Vec<SchematicNet>, String> {
    let mut indices = BTreeMap::<(i64, i64), usize>::new();
    let mut points = Vec::<Point>::new();
    let insert =
        |point: Point, indices: &mut BTreeMap<(i64, i64), usize>, points: &mut Vec<Point>| {
            let next = points.len();
            *indices.entry(point_key(point)).or_insert_with(|| {
                points.push(point);
                next
            })
        };
    for wire in wires {
        for &point in &wire.points {
            insert(point, &mut indices, &mut points);
        }
    }
    for marker in junctions.iter().chain(no_connects) {
        insert(marker.position, &mut indices, &mut points);
    }
    for label in labels.iter() {
        insert(label.position, &mut indices, &mut points);
    }
    for symbol in symbols.iter() {
        for pin in &symbol.pins {
            insert(pin.position, &mut indices, &mut points);
        }
    }
    if points.len() > MAX_ITEMS {
        return Err(format!(
            "schematic exceeds the {MAX_ITEMS} electrical-point limit"
        ));
    }
    let segment_count = wires
        .iter()
        .map(|wire| wire.points.len().saturating_sub(1))
        .sum::<usize>();
    if segment_count.saturating_mul(points.len()) > MAX_CONNECTIVITY_TESTS {
        return Err(format!(
            "schematic connectivity exceeds the {MAX_CONNECTIVITY_TESTS} geometric-test limit"
        ));
    }

    let mut sets = DisjointSet::new(points.len());
    for wire in wires {
        for segment in wire.points.windows(2) {
            let mut on_segment = points
                .iter()
                .enumerate()
                .filter(|(_, point)| point_on_segment(**point, segment[0], segment[1]))
                .map(|(index, point)| (segment_parameter(*point, segment[0]), index))
                .collect::<Vec<_>>();
            on_segment.sort_unstable();
            for pair in on_segment.windows(2) {
                sets.union(pair[0].1, pair[1].1);
            }
        }
    }
    let mut labels_by_name = BTreeMap::<String, usize>::new();
    for label in labels.iter() {
        let index = indices[&point_key(label.position)];
        if let Some(&existing) = labels_by_name.get(&label.name) {
            sets.union(existing, index);
        } else {
            labels_by_name.insert(label.name.clone(), index);
        }
    }

    let no_connect_keys = no_connects
        .iter()
        .map(|marker| point_key(marker.position))
        .collect::<BTreeSet<_>>();
    let mut component_points = BTreeMap::<usize, Vec<Point>>::new();
    for (index, &point) in points.iter().enumerate() {
        component_points
            .entry(sets.find(index))
            .or_default()
            .push(point);
    }
    let mut component_labels = BTreeMap::<usize, BTreeSet<String>>::new();
    for label in labels.iter() {
        let root = sets.find(indices[&point_key(label.position)]);
        component_labels
            .entry(root)
            .or_default()
            .insert(label.name.clone());
    }
    let mut component_pins = BTreeMap::<usize, Vec<SchematicPinRef>>::new();
    for symbol in symbols.iter() {
        for pin in &symbol.pins {
            let root = sets.find(indices[&point_key(pin.position)]);
            component_pins
                .entry(root)
                .or_default()
                .push(SchematicPinRef {
                    symbol_uuid: symbol.uuid.clone(),
                    reference: symbol.reference.clone(),
                    unit: symbol.unit,
                    number: pin.number.clone(),
                });
        }
    }

    let mut roots = component_points.keys().copied().collect::<Vec<_>>();
    roots.sort_by_key(|root| {
        component_points[root]
            .iter()
            .map(|point| point_key(*point))
            .min()
            .unwrap_or_default()
    });
    let root_to_id = roots
        .iter()
        .enumerate()
        .map(|(index, root)| (*root, index as u32 + 1))
        .collect::<HashMap<_, _>>();
    let mut nets = Vec::with_capacity(roots.len());
    for root in roots {
        let id = root_to_id[&root];
        let labels = component_labels
            .remove(&root)
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        let mut pins = component_pins.remove(&root).unwrap_or_default();
        pins.sort();
        let mut net_points = component_points.remove(&root).unwrap_or_default();
        sort_points(&mut net_points);
        nets.push(SchematicNet {
            id,
            name: labels.first().cloned().unwrap_or_else(|| format!("N${id}")),
            labels,
            pins,
            points: net_points,
        });
    }
    for label in labels {
        label.net_id = root_to_id[&sets.find(indices[&point_key(label.position)])];
    }
    for symbol in symbols {
        for pin in &mut symbol.pins {
            pin.net_id = root_to_id[&sets.find(indices[&point_key(pin.position)])];
            pin.no_connect = no_connect_keys.contains(&point_key(pin.position));
        }
    }
    Ok(nets)
}

fn point_on_segment(point: Point, start: Point, end: Point) -> bool {
    let px = i128::from(point.x_nm);
    let py = i128::from(point.y_nm);
    let ax = i128::from(start.x_nm);
    let ay = i128::from(start.y_nm);
    let bx = i128::from(end.x_nm);
    let by = i128::from(end.y_nm);
    (bx - ax) * (py - ay) == (by - ay) * (px - ax)
        && px >= ax.min(bx)
        && px <= ax.max(bx)
        && py >= ay.min(by)
        && py <= ay.max(by)
}

fn segment_parameter(point: Point, start: Point) -> i128 {
    let dx = i128::from(point.x_nm) - i128::from(start.x_nm);
    let dy = i128::from(point.y_nm) - i128::from(start.y_nm);
    dx * dx + dy * dy
}

fn transform(point: Point, rotation: u16, mirror_x: bool, mirror_y: bool) -> Result<Point, String> {
    let mut x = i128::from(point.x_nm);
    let mut y = i128::from(point.y_nm);
    if mirror_x {
        y = -y;
    }
    if mirror_y {
        x = -x;
    }
    let (x, y) = match rotation {
        0 => (x, y),
        90 => (-y, x),
        180 => (-x, -y),
        270 => (y, -x),
        _ => unreachable!(),
    };
    Ok(Point {
        x_nm: checked_i64(x, "transformed schematic X coordinate")?,
        y_nm: checked_i64(y, "transformed schematic Y coordinate")?,
    })
}

fn add_points(left: Point, right: Point) -> Result<Point, String> {
    Ok(Point {
        x_nm: checked_i64(
            i128::from(left.x_nm) + i128::from(right.x_nm),
            "schematic X coordinate",
        )?,
        y_nm: checked_i64(
            i128::from(left.y_nm) + i128::from(right.y_nm),
            "schematic Y coordinate",
        )?,
    })
}

fn checked_i64(value: i128, description: &str) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| format!("{description} is outside the supported range"))
}

#[derive(Clone, Copy)]
enum PointArity {
    Plain,
    OptionalRotation,
    RequiredRotation,
}

fn required_point(
    values: &[Sexp],
    name: &str,
    arity: PointArity,
    context: &str,
) -> Result<Point, String> {
    required_point_with_rotation(values, name, arity, context).map(|(point, _)| point)
}

fn required_point_with_rotation(
    values: &[Sexp],
    name: &str,
    arity: PointArity,
    context: &str,
) -> Result<(Point, u16), String> {
    let child =
        unique_child_values(values, name)?.ok_or_else(|| format!("missing {name} coordinate"))?;
    let valid_arity = match arity {
        PointArity::Plain => child.len() == 3,
        PointArity::OptionalRotation => matches!(child.len(), 3 | 4),
        PointArity::RequiredRotation => child.len() == 4,
    };
    if !valid_arity {
        return Err(match arity {
            PointArity::Plain | PointArity::RequiredRotation => {
                format!("{context} {name} coordinate must contain exactly X and Y")
            }
            PointArity::OptionalRotation => {
                format!("{context} {name} coordinate must contain X, Y, and optional rotation")
            }
        });
    }
    let rotation = if matches!(
        arity,
        PointArity::OptionalRotation | PointArity::RequiredRotation
    ) {
        child
            .get(3)
            .map(|value| parse_rotation(value, context))
            .transpose()?
            .unwrap_or(0)
    } else {
        0
    };
    Ok((
        Point {
            x_nm: coordinate_nm(child.get(1), name)?,
            y_nm: coordinate_nm(child.get(2), name)?,
        },
        rotation,
    ))
}

fn parse_rotation(value: &Sexp, context: &str) -> Result<u16, String> {
    let value = atom(Some(value)).ok_or_else(|| format!("{context} rotation must be scalar"))?;
    let rotation = value
        .parse::<u16>()
        .map_err(|_| format!("{context} rotation must be a numeric scalar"))?;
    if !matches!(rotation, 0 | 90 | 180 | 270) {
        return Err(format!(
            "{context} rotation must be 0, 90, 180, or 270 degrees"
        ));
    }
    Ok(rotation)
}

fn point_list(values: &[Sexp]) -> Result<Vec<Point>, String> {
    let points = unique_child_values(values, "pts")?
        .ok_or_else(|| "schematic wire is missing its point list".to_string())?;
    let mut result = Vec::new();
    for value in points.iter().skip(1) {
        let point = value
            .as_list()
            .ok_or_else(|| "schematic wire point must be an xy coordinate".to_string())?;
        if atom(point.first()) != Some("xy") || point.len() != 3 {
            return Err("schematic wire point must contain exactly X and Y".into());
        }
        result.push(Point {
            x_nm: coordinate_nm(point.get(1), "wire")?,
            y_nm: coordinate_nm(point.get(2), "wire")?,
        });
    }
    Ok(result)
}

fn coordinate_nm(value: Option<&Sexp>, description: &str) -> Result<i64, String> {
    let value = atom(value)
        .ok_or_else(|| format!("{description} coordinate is missing"))?
        .parse::<f64>()
        .map_err(|_| format!("{description} coordinate is not numeric"))?;
    let nanometers = value * NM_PER_MM;
    // `i64::MAX as f64` rounds to 2^63, so comparing against it with an
    // inclusive upper bound accidentally accepts values which cannot be
    // represented by an i64.  The mathematical interval is
    // [i64::MIN, 2^63), with 2^63 intentionally exclusive.
    let rounded = nanometers.round();
    let upper_exclusive = -(i64::MIN as f64); // exactly 2^63
    if !value.is_finite()
        || !nanometers.is_finite()
        || rounded < i64::MIN as f64
        || rounded >= upper_exclusive
    {
        return Err(format!(
            "{description} coordinate is outside the supported range"
        ));
    }
    Ok(rounded as i64)
}

fn properties(values: &[Sexp]) -> Result<BTreeMap<String, String>, String> {
    let mut properties = BTreeMap::new();
    for property in direct_lists(values, "property") {
        let name = atom(property.get(1))
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| "symbol property is missing its name".to_string())?;
        let value = atom(property.get(2))
            .ok_or_else(|| format!("symbol property {name} is missing its value"))?;
        if properties
            .insert(name.to_string(), value.to_string())
            .is_some()
        {
            return Err(format!("symbol contains duplicate property {name}"));
        }
    }
    Ok(properties)
}

fn yes_no(values: &[Sexp], name: &str, default: bool) -> Result<bool, String> {
    let Some(child) = unique_child_values(values, name)? else {
        return Ok(default);
    };
    match atom(child.get(1)) {
        Some("yes") => Ok(true),
        Some("no") => Ok(false),
        None if child.len() == 1 => Ok(true),
        _ => Err(format!("{name} must be yes or no")),
    }
}

fn power_scope(values: &[Sexp]) -> Result<Option<PowerScope>, String> {
    let Some(power) = unique_child_values(values, "power")? else {
        return Ok(None);
    };
    match atom(power.get(1)) {
        None if power.len() == 1 => Ok(Some(PowerScope::Global)),
        Some("yes" | "global") => Ok(Some(PowerScope::Global)),
        Some("local") => Ok(Some(PowerScope::Local)),
        Some("no") => Ok(None),
        _ => Err("library symbol power scope must be global, local, yes, or no".into()),
    }
}

fn unique_child_values<'a>(values: &'a [Sexp], name: &str) -> Result<Option<&'a [Sexp]>, String> {
    let mut matches = values.iter().filter_map(|value| {
        let child = value.as_list()?;
        (atom(child.first()) == Some(name)).then_some(child)
    });
    let first = matches.next();
    if matches.next().is_some() {
        return Err(format!("schematic field {name} must not be repeated"));
    }
    Ok(first)
}

fn direct_lists<'a>(values: &'a [Sexp], name: &'a str) -> impl Iterator<Item = &'a [Sexp]> + 'a {
    values.iter().filter_map(move |value| {
        let child = value.as_list()?;
        (atom(child.first()) == Some(name)).then_some(child)
    })
}

fn optional_atom<'a>(values: &'a [Sexp], name: &str) -> Result<Option<&'a str>, String> {
    let Some(child) = unique_child_values(values, name)? else {
        return Ok(None);
    };
    if child.len() != 2 {
        return Err(format!(
            "schematic field {name} must contain exactly one scalar value"
        ));
    }
    atom(child.get(1))
        .map(Some)
        .ok_or_else(|| format!("schematic field {name} must contain a scalar value"))
}

fn required_atom<'a>(values: &'a [Sexp], name: &str) -> Result<&'a str, String> {
    optional_atom(values, name)?.ok_or_else(|| format!("KiCad schematic is missing {name}"))
}

fn optional_u32(values: &[Sexp], name: &str) -> Result<Option<u32>, String> {
    optional_atom(values, name)?
        .map(|value| {
            value
                .parse()
                .map_err(|_| format!("schematic field {name} must be an unsigned integer"))
        })
        .transpose()
}

fn required_u32(values: &[Sexp], name: &str) -> Result<u32, String> {
    required_atom(values, name)?
        .parse()
        .map_err(|_| format!("KiCad schematic {name} must be an unsigned integer"))
}

fn point_key(point: Point) -> (i64, i64) {
    (point.x_nm, point.y_nm)
}

fn sort_points(points: &mut [Point]) {
    points.sort_by_key(|point| point_key(*point));
}

fn natural_pin_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.parse::<u64>(), right.parse::<u64>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

struct DisjointSet {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl DisjointSet {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
            rank: vec![0; size],
        }
    }

    fn find(&mut self, value: usize) -> usize {
        if self.parent[value] != value {
            self.parent[value] = self.find(self.parent[value]);
        }
        self.parent[value]
    }

    fn union(&mut self, left: usize, right: usize) {
        let left = self.find(left);
        let right = self.find(right);
        if left == right {
            return;
        }
        if self.rank[left] < self.rank[right] {
            self.parent[left] = right;
        } else {
            self.parent[right] = left;
            if self.rank[left] == self.rank[right] {
                self.rank[left] += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = r#"(kicad_sch
      (version 20231120)
      (generator eeschema)
      (generator_version "8.0")
      (uuid root-uuid)
      (lib_symbols
        (symbol "Device:R"
          (symbol "R_1_1"
            (pin passive line (at -2.54 0 0) (length 2.54)
              (name "~") (number "1"))
            (pin passive line (at 2.54 0 180) (length 2.54)
              (name "~") (number "2"))))
        (symbol "MCU:Chip"
          (symbol "Chip_1_1"
            (pin output line (at -2.54 0 0) (length 2.54)
              (name "OUT") (number "1"))
            (pin power_in line (at 0 2.54 270) (length 2.54)
              (name "VCC") (number "2")))))
      (junction (at 30 20) (diameter 0) (uuid junction-1))
      (wire (pts (xy 10 20) (xy 30 20)) (uuid wire-1))
      (wire (pts (xy 30 20) (xy 40 20)) (uuid wire-2))
      (label "SIGNAL" (at 30 20 0) (uuid label-1))
      (global_label "VCC" (shape input) (at 20 32.54 0) (uuid label-2))
      (no_connect (at 42.54 20) (uuid nc-1))
      (symbol (lib_id "MCU:Chip") (at 12.54 20 0) (unit 1)
        (in_bom yes) (on_board yes) (uuid symbol-u1)
        (property "Reference" "U1") (property "Value" "Chip")
        (property "Footprint" "Package:QFN")
        (pin "1" (uuid pin-u1-1)) (pin "2" (uuid pin-u1-2)))
      (symbol (lib_id "Device:R") (at 40 20 0) (unit 1)
        (in_bom yes) (on_board yes) (uuid symbol-r1)
        (property "Reference" "R1") (property "Value" "10k")
        (property "Footprint" "Resistor_SMD:R_0603")
        (pin "1" (uuid pin-r1-1)) (pin "2" (uuid pin-r1-2)))
      (sheet_instances (path "/" (page "1")))
    )"#;

    #[test]
    fn imports_symbols_connectivity_labels_and_no_connects() {
        let schematic = import_schematic(SIMPLE).unwrap();
        assert_eq!(schematic.schema_version, 1);
        assert!(schematic.coverage.complete);
        assert_eq!(schematic.symbols.len(), 2);
        assert_eq!(schematic.wires.len(), 2);
        let signal = schematic
            .nets
            .iter()
            .find(|net| net.name == "SIGNAL")
            .unwrap();
        assert_eq!(
            signal
                .pins
                .iter()
                .map(|pin| format!("{}.{}", pin.reference, pin.number))
                .collect::<Vec<_>>(),
            ["R1.1", "U1.1"]
        );
        let resistor = schematic
            .symbols
            .iter()
            .find(|symbol| symbol.reference == "R1")
            .unwrap();
        assert!(
            resistor
                .pins
                .iter()
                .find(|pin| pin.number == "2")
                .unwrap()
                .no_connect
        );
        assert_eq!(
            schematic
                .symbols
                .iter()
                .find(|symbol| symbol.reference == "U1")
                .unwrap()
                .pins
                .iter()
                .find(|pin| pin.number == "2")
                .unwrap()
                .position,
            Point {
                x_nm: 12_540_000,
                y_nm: 22_540_000
            }
        );
    }

    #[test]
    fn rejects_malformed_at_rotation_and_wire_points() {
        let malformed_symbol = SIMPLE.replace(
            "(symbol (lib_id \"MCU:Chip\") (at 12.54 20 0)",
            "(symbol (lib_id \"MCU:Chip\") (at 12.54 20 (bad))",
        );
        let error = import_schematic(&malformed_symbol).unwrap_err();
        assert!(error.contains("rotation must be scalar"), "{error}");

        let malformed_label = SIMPLE.replace(
            "(label \"SIGNAL\" (at 30 20 0)",
            "(label \"SIGNAL\" (at 30 20 45)",
        );
        let error = import_schematic(&malformed_label).unwrap_err();
        assert!(
            error.contains("rotation must be 0, 90, 180, or 270"),
            "{error}"
        );

        let malformed_wire = SIMPLE.replace(
            "(wire (pts (xy 10 20) (xy 30 20)) (uuid wire-1))",
            "(wire (pts (xy 10 20) stray (xy 30 20)) (uuid wire-1))",
        );
        let error = import_schematic(&malformed_wire).unwrap_err();
        assert!(
            error.contains("wire point must be an xy coordinate"),
            "{error}"
        );

        let malformed_marker = SIMPLE.replace(
            "(junction (at 30 20) (diameter 0) (uuid junction-1))",
            "(junction (at 30 20 0) (diameter 0) (uuid junction-1))",
        );
        let error = import_schematic(&malformed_marker).unwrap_err();
        assert!(
            error.contains("schematic marker at coordinate must contain exactly X and Y"),
            "{error}"
        );
    }

    #[test]
    fn connects_crossings_only_when_a_junction_exists() {
        let source = SIMPLE
            .replace("(junction (at 30 20) (diameter 0) (uuid junction-1))", "")
            .replace(
                "(wire (pts (xy 10 20) (xy 30 20)) (uuid wire-1))",
                "(wire (pts (xy 10 20) (xy 40 20)) (uuid wire-1))",
            )
            .replace(
                "(wire (pts (xy 30 20) (xy 40 20)) (uuid wire-2))",
                "(wire (pts (xy 30 10) (xy 30 30)) (uuid wire-2))",
            )
            .replace(
                "(label \"SIGNAL\" (at 30 20 0) (uuid label-1))",
                "(label \"SIGNAL\" (at 10 20 0) (uuid label-1))",
            );
        let schematic = import_schematic(&source).unwrap();
        assert!(!schematic.nets.iter().any(|net| {
            net.points.contains(&Point {
                x_nm: 10_000_000,
                y_nm: 20_000_000,
            }) && net.points.contains(&Point {
                x_nm: 30_000_000,
                y_nm: 10_000_000,
            })
        }));

        let source = source.replace(
            "(label \"SIGNAL\" (at 10 20 0) (uuid label-1))",
            "(junction (at 30 20) (diameter 0) (uuid junction-1))\n\
             (label \"SIGNAL\" (at 10 20 0) (uuid label-1))",
        );
        let schematic = import_schematic(&source).unwrap();
        assert!(schematic.nets.iter().any(|net| {
            net.points.contains(&Point {
                x_nm: 10_000_000,
                y_nm: 20_000_000,
            }) && net.points.contains(&Point {
                x_nm: 30_000_000,
                y_nm: 10_000_000,
            })
        }));
    }

    #[test]
    fn reports_unsupported_hierarchy_and_rejects_future_formats() {
        let hierarchical = SIMPLE.replace(
            "(sheet_instances",
            "(sheet (at 1 1) (size 10 10) (uuid sheet-1))\n(sheet_instances",
        );
        let schematic = import_schematic(&hierarchical).unwrap();
        assert!(!schematic.coverage.complete);
        assert_eq!(schematic.coverage.unsupported_features[0].kind, "sheet");

        let future = SIMPLE.replace("(version 20231120)", "(version 20990101)");
        assert!(
            import_schematic(&future)
                .unwrap_err()
                .contains("newer than supported")
        );

        let duplicate = SIMPLE.replace(
            "(version 20231120)",
            "(version 20231120) (version 20230121)",
        );
        assert!(
            import_schematic(&duplicate)
                .unwrap_err()
                .contains("must not be repeated")
        );

        let duplicate_uuid = SIMPLE.replace("(uuid wire-1)", "(uuid root-uuid)");
        assert!(
            import_schematic(&duplicate_uuid)
                .unwrap_err()
                .contains("duplicate schematic UUID")
        );
    }

    #[test]
    fn rotates_and_mirrors_library_pin_positions() {
        let source = SIMPLE.replace("(at 40 20 0) (unit 1)", "(at 40 20 90) (mirror x) (unit 1)");
        let schematic = import_schematic(&source).unwrap();
        let resistor = schematic
            .symbols
            .iter()
            .find(|symbol| symbol.reference == "R1")
            .unwrap();
        assert_eq!(
            resistor
                .pins
                .iter()
                .find(|pin| pin.number == "1")
                .unwrap()
                .position,
            Point {
                x_nm: 40_000_000,
                y_nm: 17_460_000
            }
        );
    }

    #[test]
    fn retains_duplicate_unannotated_references_with_uuid_identity() {
        let source = SIMPLE.replace("\"U1\"", "\"R1\"");
        let schematic = import_schematic(&source).unwrap();
        let signal = schematic
            .nets
            .iter()
            .find(|net| net.name == "SIGNAL")
            .unwrap();
        assert_eq!(signal.pins.len(), 2);
        assert_ne!(signal.pins[0].symbol_uuid, signal.pins[1].symbol_uuid);
    }

    #[test]
    fn schematic_schema_closes_every_declared_object() {
        fn assert_closed(value: &Value) {
            if value.get("type").and_then(Value::as_str) == Some("object")
                && value.get("properties").is_some()
            {
                assert!(
                    value.get("additionalProperties").is_some(),
                    "object schema is not closed: {value}"
                );
            }
            match value {
                Value::Array(values) => values.iter().for_each(assert_closed),
                Value::Object(values) => values.values().for_each(assert_closed),
                _ => {}
            }
        }

        let schema = schematic_json_schema();
        assert_eq!(
            schema["$id"],
            "https://github.com/penguin425/pcbex/schemas/schematic-ir-v1.json"
        );
        assert_closed(&schema);
    }

    #[test]
    fn preserves_kicad_ten_local_power_scope_and_boolean_hide() {
        let source = SIMPLE
            .replace(
                "(symbol \"MCU:Chip\"",
                "(symbol \"MCU:Chip\"\n          (power local)",
            )
            .replace(
                "(pin output line (at -2.54 0 0)",
                "(pin output line (at -2.54 0 0) (hide no)",
            )
            .replace(
                "(pin power_in line (at 0 2.54 270)",
                "(pin power_in line (at 0 2.54 270) (hide yes)",
            );
        let schematic = import_schematic(&source).unwrap();
        assert_eq!(
            schematic
                .labels
                .iter()
                .filter(|label| label.kind == SchematicLabelKind::PowerLocal)
                .count(),
            2
        );
        let chip = schematic
            .symbols
            .iter()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        assert!(
            !chip
                .pins
                .iter()
                .find(|pin| pin.number == "1")
                .unwrap()
                .hidden
        );
        assert!(
            chip.pins
                .iter()
                .find(|pin| pin.number == "2")
                .unwrap()
                .hidden
        );
    }

    #[test]
    fn schematic_ir_round_trips_and_rejects_unknown_fields() {
        let schematic = import_schematic(SIMPLE).unwrap();
        let mut value = serde_json::to_value(&schematic).unwrap();
        assert_eq!(
            serde_json::from_value::<SchematicDocument>(value.clone()).unwrap(),
            schematic
        );
        value
            .as_object_mut()
            .unwrap()
            .insert("silent_future_field".into(), Value::Bool(true));
        assert!(
            serde_json::from_value::<SchematicDocument>(value)
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }

    #[test]
    fn coordinate_conversion_rejects_the_mathematical_i64_upper_endpoint() {
        let lower = Sexp::Atom((i64::MIN as f64 / NM_PER_MM).to_string());
        assert_eq!(coordinate_nm(Some(&lower), "coordinate").unwrap(), i64::MIN);

        // `i64::MAX as f64` is 2^63.  It must remain exclusive even though a
        // naïve `<= i64::MAX as f64` comparison would accept it.
        let upper = Sexp::Atom((-(i64::MIN as f64) / NM_PER_MM).to_string());
        assert!(coordinate_nm(Some(&upper), "coordinate").is_err());
    }
}

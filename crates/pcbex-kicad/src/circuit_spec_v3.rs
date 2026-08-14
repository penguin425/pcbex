//! Closed multi-unit circuit-spec v3 validation and electrical review.
//!
//! Version 3 keeps one physical part per reference and nests one or more
//! explicit symbol units beneath it. Connections bind `(reference, unit,
//! pin)`, while board-facing consumers collapse those units back to one
//! physical footprint after proving that package pin numbers are unique.

use super::circuit_spec::{
    canonical_json, deserialize_required_option, digest_hex, format_voltage_uv, identifier, lib_id,
    parse_json_value_without_duplicate_keys, prefix_refs, stable_id, text, validate_power,
    validate_voltage,
};
use super::{
    CircuitConnectionV2, CircuitNetV2, CircuitPartV2, CircuitPinV2, CircuitPowerV2, CircuitSpecV2,
    ElectricalPinType, ElectricalPolicy, ElectricalReview, SchematicCoverage, SchematicDocument,
    SchematicLabel, SchematicLabelKind, SchematicNet, SchematicPin, SchematicPinRef,
    SchematicSymbol, check_schematic, electrical_review_json_schema,
};
use pcbex_core::Point;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const CIRCUIT_SPEC_V3_SCHEMA_VERSION: u32 = 3;
pub const CIRCUIT_SPEC_V3_CHECK_SCHEMA_VERSION: u32 = 2;
pub const CIRCUIT_SPEC_V3_MAX_BYTES: u64 = super::CIRCUIT_SPEC_V2_MAX_BYTES;
pub const CIRCUIT_SPEC_V3_MAX_PARTS: usize = super::CIRCUIT_SPEC_V2_MAX_PARTS;
pub const CIRCUIT_SPEC_V3_MAX_NETS: usize = super::CIRCUIT_SPEC_V2_MAX_NETS;
pub const CIRCUIT_SPEC_V3_MAX_UNITS_PER_PART: usize = 32;
pub const CIRCUIT_SPEC_V3_MAX_TOTAL_UNITS: usize = 4096;
pub const CIRCUIT_SPEC_V3_MAX_UNIT_NUMBER: u32 = 255;
pub const CIRCUIT_SPEC_V3_MAX_PINS_PER_UNIT: usize = super::CIRCUIT_SPEC_V2_MAX_PINS_PER_PART;
pub const CIRCUIT_SPEC_V3_MAX_PHYSICAL_PINS_PER_PART: usize =
    super::CIRCUIT_SPEC_V2_MAX_PINS_PER_PART;
pub const CIRCUIT_SPEC_V3_MAX_TOTAL_PINS: usize = super::CIRCUIT_SPEC_V2_MAX_TOTAL_PINS;
pub const CIRCUIT_SPEC_V3_MAX_CONNECTIONS_PER_NET: usize =
    super::CIRCUIT_SPEC_V2_MAX_CONNECTIONS_PER_NET;
pub const CIRCUIT_SPEC_V3_MAX_TOTAL_CONNECTIONS: usize =
    super::CIRCUIT_SPEC_V2_MAX_TOTAL_CONNECTIONS;

const DOCUMENT_DOMAIN: &[u8] = b"pcbex:circuit-spec-v3:schematic\0";
const SYMBOL_DOMAIN: &[u8] = b"pcbex:circuit-spec-v3:symbol\0";
const PIN_DOMAIN: &[u8] = b"pcbex:circuit-spec-v3:pin\0";
const LABEL_DOMAIN: &[u8] = b"pcbex:circuit-spec-v3:label\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitSpecV3 {
    pub schema_version: u32,
    pub parts: Vec<CircuitPartV3>,
    pub nets: Vec<CircuitNetV3>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitPartV3 {
    pub reference: String,
    pub lib_id: String,
    pub value: String,
    pub footprint: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub mpn: Option<String>,
    pub power: CircuitPowerV2,
    pub units: Vec<CircuitUnitV3>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitUnitV3 {
    pub unit: u32,
    pub pins: Vec<CircuitPinV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitNetV3 {
    pub name: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub voltage_uv: Option<i64>,
    pub connections: Vec<CircuitConnectionV3>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitConnectionV3 {
    pub reference: String,
    pub unit: u32,
    pub pin: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitSpecCheckV3 {
    pub schema_version: u32,
    pub circuit_spec_sha256: String,
    pub electrical_review_sha256: String,
    pub normalized_spec: CircuitSpecV3,
    pub electrical_review: ElectricalReview,
}

pub fn parse_circuit_spec_v3(source: &str) -> Result<CircuitSpecV3, String> {
    if source.is_empty() {
        return Err("circuit spec source must not be empty".into());
    }
    if source.len() as u64 > CIRCUIT_SPEC_V3_MAX_BYTES {
        return Err(format!(
            "circuit spec source exceeds {CIRCUIT_SPEC_V3_MAX_BYTES} bytes"
        ));
    }
    let value = parse_json_value_without_duplicate_keys(source, "circuit-spec v3")?;
    let parsed = serde_json::from_value(value)
        .map_err(|error| format!("invalid circuit-spec v3 JSON: {error}"))?;
    normalize_circuit_spec_v3(&parsed)
}

/// Read the top-level wire version used to select the closed v2 or v3
/// parser. The selected parser still rejects duplicate keys and performs the
/// complete semantic validation; this function is not a validation bypass.
pub fn circuit_spec_source_schema_version(source: &str) -> Result<u32, String> {
    if source.is_empty() {
        return Err("circuit spec source must not be empty".into());
    }
    if source.len() as u64 > CIRCUIT_SPEC_V3_MAX_BYTES {
        return Err(format!(
            "circuit spec source exceeds {CIRCUIT_SPEC_V3_MAX_BYTES} bytes"
        ));
    }
    let value: Value = serde_json::from_str(source)
        .map_err(|error| format!("invalid circuit-spec JSON: {error}"))?;
    let version = value
        .as_object()
        .and_then(|object| object.get("schema_version"))
        .and_then(Value::as_u64)
        .ok_or_else(|| "circuit spec schema_version must be an unsigned integer".to_string())?;
    u32::try_from(version).map_err(|_| "circuit spec schema_version is out of range".to_string())
}

/// Parse either supported wire version and return the physical v2-shaped
/// inventory consumed by board, BOM, CPL, and manufacturing boundaries.
pub fn circuit_spec_source_to_physical_v2(source: &str) -> Result<CircuitSpecV2, String> {
    match circuit_spec_source_schema_version(source)? {
        super::CIRCUIT_SPEC_V2_SCHEMA_VERSION => super::parse_circuit_spec_v2(source),
        CIRCUIT_SPEC_V3_SCHEMA_VERSION => {
            circuit_spec_v3_to_physical_v2(&parse_circuit_spec_v3(source)?)
        }
        version => Err(format!(
            "unsupported circuit-spec schema version {version} (expected {} or {})",
            super::CIRCUIT_SPEC_V2_SCHEMA_VERSION,
            CIRCUIT_SPEC_V3_SCHEMA_VERSION
        )),
    }
}

pub fn normalize_circuit_spec_v3(spec: &CircuitSpecV3) -> Result<CircuitSpecV3, String> {
    let mut normalized = spec.clone();
    if normalized.schema_version != CIRCUIT_SPEC_V3_SCHEMA_VERSION {
        return Err(format!(
            "unsupported circuit-spec schema version {} (expected {})",
            normalized.schema_version, CIRCUIT_SPEC_V3_SCHEMA_VERSION
        ));
    }
    if normalized.parts.is_empty() {
        return Err("circuit spec must contain at least one part".into());
    }
    if normalized.parts.len() > CIRCUIT_SPEC_V3_MAX_PARTS {
        return Err(format!(
            "circuit spec contains too many parts (maximum {CIRCUIT_SPEC_V3_MAX_PARTS})"
        ));
    }
    if normalized.nets.is_empty() {
        return Err("circuit spec must contain at least one net".into());
    }
    if normalized.nets.len() > CIRCUIT_SPEC_V3_MAX_NETS {
        return Err(format!(
            "circuit spec contains too many nets (maximum {CIRCUIT_SPEC_V3_MAX_NETS})"
        ));
    }

    let mut references = BTreeSet::new();
    let mut total_units = 0usize;
    let mut total_pins = 0usize;
    let mut known_pins =
        BTreeMap::<(String, u32, String), (Option<String>, ElectricalPinType)>::new();
    let mut physical_pin_numbers = BTreeMap::<String, BTreeSet<String>>::new();
    let mut power_output_nets = BTreeMap::<String, BTreeSet<String>>::new();
    let mut has_power_input = BTreeSet::<String>::new();

    for part in &mut normalized.parts {
        part.reference = identifier(
            &part.reference,
            "part reference",
            super::CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES,
            true,
        )?;
        if !references.insert(part.reference.clone()) {
            return Err(format!("duplicate part reference {}", part.reference));
        }
        part.lib_id = lib_id(&part.lib_id)?;
        part.value = text(
            &part.value,
            "part value",
            super::CIRCUIT_SPEC_V2_MAX_VALUE_BYTES,
        )?;
        part.footprint = text(
            &part.footprint,
            "part footprint",
            super::CIRCUIT_SPEC_V2_MAX_FOOTPRINT_BYTES,
        )?;
        part.mpn = part
            .mpn
            .take()
            .map(|value| text(&value, "part MPN", super::CIRCUIT_SPEC_V2_MAX_MPN_BYTES))
            .transpose()?;
        validate_power(&part.power, &part.reference)?;
        if part.units.is_empty() {
            return Err(format!("{} must contain at least one unit", part.reference));
        }
        if part.units.len() > CIRCUIT_SPEC_V3_MAX_UNITS_PER_PART {
            return Err(format!(
                "{} contains too many units (maximum {CIRCUIT_SPEC_V3_MAX_UNITS_PER_PART})",
                part.reference
            ));
        }
        total_units = total_units
            .checked_add(part.units.len())
            .ok_or_else(|| "circuit spec unit count overflow".to_string())?;
        if total_units > CIRCUIT_SPEC_V3_MAX_TOTAL_UNITS {
            return Err(format!(
                "circuit spec contains too many units (maximum {CIRCUIT_SPEC_V3_MAX_TOTAL_UNITS})"
            ));
        }
        let mut units = BTreeSet::new();
        let mut physical_pin_count = 0usize;
        let physical_pins = physical_pin_numbers
            .entry(part.reference.clone())
            .or_default();
        for unit in &mut part.units {
            if !(1..=CIRCUIT_SPEC_V3_MAX_UNIT_NUMBER).contains(&unit.unit) {
                return Err(format!(
                    "{} unit must be between 1 and {CIRCUIT_SPEC_V3_MAX_UNIT_NUMBER}",
                    part.reference
                ));
            }
            if !units.insert(unit.unit) {
                return Err(format!(
                    "{} contains duplicate unit {}",
                    part.reference, unit.unit
                ));
            }
            if unit.pins.is_empty() {
                return Err(format!(
                    "{} unit {} must contain at least one pin",
                    part.reference, unit.unit
                ));
            }
            if unit.pins.len() > CIRCUIT_SPEC_V3_MAX_PINS_PER_UNIT {
                return Err(format!(
                    "{} unit {} contains too many pins (maximum {CIRCUIT_SPEC_V3_MAX_PINS_PER_UNIT})",
                    part.reference, unit.unit
                ));
            }
            physical_pin_count = physical_pin_count
                .checked_add(unit.pins.len())
                .ok_or_else(|| "physical package pin count overflow".to_string())?;
            if physical_pin_count > CIRCUIT_SPEC_V3_MAX_PHYSICAL_PINS_PER_PART {
                return Err(format!(
                    "{} contains too many physical package pins (maximum {CIRCUIT_SPEC_V3_MAX_PHYSICAL_PINS_PER_PART})",
                    part.reference
                ));
            }
            let mut unit_pins = BTreeSet::new();
            let mut has_non_no_connect = false;
            for pin in &mut unit.pins {
                pin.number = identifier(
                    &pin.number,
                    &format!("{}.unit{}.pin number", part.reference, unit.unit),
                    super::CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES,
                    false,
                )?;
                if !unit_pins.insert(pin.number.clone()) {
                    return Err(format!(
                        "{} unit {} contains duplicate pin {}",
                        part.reference, unit.unit, pin.number
                    ));
                }
                if !physical_pins.insert(pin.number.clone()) {
                    return Err(format!(
                        "{} reuses physical package pin {} across multiple units",
                        part.reference, pin.number
                    ));
                }
                pin.name = text(
                    &pin.name,
                    &format!(
                        "{}.unit{}.{} pin name",
                        part.reference, unit.unit, pin.number
                    ),
                    super::CIRCUIT_SPEC_V2_MAX_PIN_NAME_BYTES,
                )?;
                match &mut pin.net {
                    Some(net) => {
                        *net = identifier(
                            net,
                            &format!("{}.unit{}.{} net", part.reference, unit.unit, pin.number),
                            super::CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES,
                            false,
                        )?;
                        if pin.electrical_type == ElectricalPinType::NoConnect {
                            return Err(format!(
                                "{} unit {} pin {} is no-connect but declares net {}",
                                part.reference, unit.unit, pin.number, net
                            ));
                        }
                        has_non_no_connect = true;
                    }
                    None if pin.electrical_type != ElectricalPinType::NoConnect => {
                        return Err(format!(
                            "{} unit {} pin {} has a null net but is not no-connect",
                            part.reference, unit.unit, pin.number
                        ));
                    }
                    None => {}
                }
                if pin.electrical_type == ElectricalPinType::Unspecified {
                    return Err(format!(
                        "{} unit {} pin {} has unsupported unspecified electrical type",
                        part.reference, unit.unit, pin.number
                    ));
                }
                if pin.electrical_type == ElectricalPinType::PowerInput {
                    has_power_input.insert(part.reference.clone());
                }
                if pin.electrical_type == ElectricalPinType::PowerOutput
                    && let Some(net) = &pin.net
                {
                    power_output_nets
                        .entry(part.reference.clone())
                        .or_default()
                        .insert(net.clone());
                }
                known_pins.insert(
                    (part.reference.clone(), unit.unit, pin.number.clone()),
                    (pin.net.clone(), pin.electrical_type),
                );
            }
            if !has_non_no_connect {
                return Err(format!(
                    "{} unit {} must contain at least one non-no-connect pin",
                    part.reference, unit.unit
                ));
            }
            total_pins = total_pins
                .checked_add(unit.pins.len())
                .ok_or_else(|| "circuit spec pin count overflow".to_string())?;
            if total_pins > CIRCUIT_SPEC_V3_MAX_TOTAL_PINS {
                return Err(format!(
                    "circuit spec contains too many pins (maximum {CIRCUIT_SPEC_V3_MAX_TOTAL_PINS})"
                ));
            }
            unit.pins
                .sort_by(|left, right| left.number.cmp(&right.number));
        }
        part.units.sort_by_key(|unit| unit.unit);
    }
    normalized
        .parts
        .sort_by(|left, right| left.reference.cmp(&right.reference));

    let mut net_names = BTreeSet::new();
    let mut total_connections = 0usize;
    for net in &mut normalized.nets {
        net.name = identifier(
            &net.name,
            "net name",
            super::CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES,
            false,
        )?;
        if !net_names.insert(net.name.clone()) {
            return Err(format!("duplicate net name {}", net.name));
        }
        validate_voltage(net.voltage_uv, &format!("net {} voltage", net.name))?;
        if net.connections.len() < 2 {
            return Err(format!(
                "net {} must contain at least two connections",
                net.name
            ));
        }
        if net.connections.len() > CIRCUIT_SPEC_V3_MAX_CONNECTIONS_PER_NET {
            return Err(format!(
                "net {} contains too many connections (maximum {CIRCUIT_SPEC_V3_MAX_CONNECTIONS_PER_NET})",
                net.name
            ));
        }
        total_connections = total_connections
            .checked_add(net.connections.len())
            .ok_or_else(|| "circuit spec connection count overflow".to_string())?;
        if total_connections > CIRCUIT_SPEC_V3_MAX_TOTAL_CONNECTIONS {
            return Err(format!(
                "circuit spec contains too many connections (maximum {CIRCUIT_SPEC_V3_MAX_TOTAL_CONNECTIONS})"
            ));
        }
        let mut seen_on_net = BTreeSet::new();
        for connection in &mut net.connections {
            connection.reference = identifier(
                &connection.reference,
                "connection reference",
                super::CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES,
                true,
            )?;
            if !(1..=CIRCUIT_SPEC_V3_MAX_UNIT_NUMBER).contains(&connection.unit) {
                return Err(format!(
                    "net {} connection unit must be between 1 and {CIRCUIT_SPEC_V3_MAX_UNIT_NUMBER}",
                    net.name
                ));
            }
            connection.pin = identifier(
                &connection.pin,
                "connection pin",
                super::CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES,
                false,
            )?;
            let key = (
                connection.reference.clone(),
                connection.unit,
                connection.pin.clone(),
            );
            if !seen_on_net.insert(key.clone()) {
                return Err(format!(
                    "net {} contains duplicate connection {}.unit{}.{}",
                    net.name, connection.reference, connection.unit, connection.pin
                ));
            }
            let Some((declared_net, electrical_type)) = known_pins.get(&key) else {
                return Err(format!(
                    "net {} references unknown {}.unit{}.{}",
                    net.name, connection.reference, connection.unit, connection.pin
                ));
            };
            if *electrical_type == ElectricalPinType::NoConnect {
                return Err(format!(
                    "net {} connects no-connect pin {}.unit{}.{}",
                    net.name, connection.reference, connection.unit, connection.pin
                ));
            }
            if declared_net.as_deref() != Some(net.name.as_str()) {
                return Err(format!(
                    "{}.unit{}.{}, declared net {:?}, is connected to {}",
                    connection.reference, connection.unit, connection.pin, declared_net, net.name
                ));
            }
        }
        net.connections.sort_by(|left, right| {
            left.reference
                .cmp(&right.reference)
                .then_with(|| left.unit.cmp(&right.unit))
                .then_with(|| left.pin.cmp(&right.pin))
        });
    }
    normalized
        .nets
        .sort_by(|left, right| left.name.cmp(&right.name));

    let connected = normalized
        .nets
        .iter()
        .flat_map(|net| {
            net.connections.iter().map(|connection| {
                (
                    connection.reference.clone(),
                    connection.unit,
                    connection.pin.clone(),
                )
            })
        })
        .collect::<BTreeSet<_>>();
    if connected.len() != total_connections {
        return Err("one or more circuit pins are connected to multiple nets".into());
    }
    for ((reference, unit, pin), (declared_net, electrical_type)) in &known_pins {
        match declared_net {
            Some(_) if !connected.contains(&(reference.clone(), *unit, pin.clone())) => {
                return Err(format!(
                    "{reference}.unit{unit}.{pin} is not connected to its declared net"
                ));
            }
            None if *electrical_type != ElectricalPinType::NoConnect => {
                return Err(format!(
                    "{reference}.unit{unit}.{pin} has a non-no-connect null net"
                ));
            }
            _ => {}
        }
    }
    for (reference, output_nets) in &power_output_nets {
        let power = &normalized
            .parts
            .iter()
            .find(|part| &part.reference == reference)
            .expect("power output part exists")
            .power;
        if power.rail_voltage_uv.is_some() && output_nets.len() != 1 {
            return Err(format!(
                "{reference} applies one rail voltage across {} output nets",
                output_nets.len()
            ));
        }
    }
    for part in &normalized.parts {
        if part.power.rail_voltage_uv.is_some() && !power_output_nets.contains_key(&part.reference)
        {
            return Err(format!(
                "{} declares a rail voltage without a power-output pin",
                part.reference
            ));
        }
        if (part.power.max_voltage_uv.is_some() || part.power.requires_decoupling)
            && !has_power_input.contains(&part.reference)
        {
            return Err(format!(
                "{} declares input voltage/decoupling requirements without a power-input pin",
                part.reference
            ));
        }
    }
    Ok(normalized)
}

pub fn check_circuit_spec_v3(spec: &CircuitSpecV3) -> Result<CircuitSpecCheckV3, String> {
    let normalized = normalize_circuit_spec_v3(spec)?;
    let spec_bytes = canonical_json(&normalized)?;
    let schematic = circuit_spec_v3_to_schematic(&normalized)?;
    let electrical_review = check_schematic(&schematic, &ElectricalPolicy::default())?;
    let review_bytes = canonical_json(&electrical_review)?;
    Ok(CircuitSpecCheckV3 {
        schema_version: CIRCUIT_SPEC_V3_CHECK_SCHEMA_VERSION,
        circuit_spec_sha256: digest_hex(&spec_bytes),
        electrical_review_sha256: digest_hex(&review_bytes),
        normalized_spec: normalized,
        electrical_review,
    })
}

pub fn parse_and_check_circuit_spec_v3(source: &str) -> Result<CircuitSpecCheckV3, String> {
    check_circuit_spec_v3(&parse_circuit_spec_v3(source)?)
}

pub fn circuit_spec_v3_to_schematic(spec: &CircuitSpecV3) -> Result<SchematicDocument, String> {
    let normalized = normalize_circuit_spec_v3(spec)?;
    let spec_bytes = canonical_json(&normalized)?;
    let document_uuid = stable_id(DOCUMENT_DOMAIN, &spec_bytes);
    let net_ids = normalized
        .nets
        .iter()
        .enumerate()
        .map(|(index, net)| {
            u32::try_from(index + 1)
                .map(|id| (net.name.clone(), id))
                .map_err(|_| "net id overflow".to_string())
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let no_connects = normalized
        .parts
        .iter()
        .flat_map(|part| {
            part.units.iter().flat_map(move |unit| {
                unit.pins
                    .iter()
                    .filter(|pin| pin.electrical_type == ElectricalPinType::NoConnect)
                    .map(move |pin| (part.reference.clone(), unit.unit, pin.number.clone()))
            })
        })
        .collect::<Vec<_>>();
    let first_no_connect_id = net_ids.len() as u32 + 1;
    let no_connect_net_ids = no_connects
        .iter()
        .enumerate()
        .map(|(offset, key)| {
            first_no_connect_id
                .checked_add(u32::try_from(offset).map_err(|_| "no-connect net id overflow")?)
                .map(|id| (key.clone(), id))
                .ok_or("no-connect net id overflow")
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let mut labels = Vec::new();
    let mut schematic_nets = Vec::with_capacity(normalized.nets.len() + no_connects.len());
    for net in &normalized.nets {
        let id = net_ids[&net.name];
        let label_names = net
            .voltage_uv
            .map(|voltage| format_voltage_uv(voltage).to_string())
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(label_name) = label_names.first() {
            labels.push(SchematicLabel {
                uuid: Some(stable_id(
                    LABEL_DOMAIN,
                    format!("{}\0{}", net.name, label_name).as_bytes(),
                )),
                name: label_name.clone(),
                kind: SchematicLabelKind::PowerLocal,
                position: Point::default(),
                net_id: id,
            });
        }
        schematic_nets.push(SchematicNet {
            id,
            name: net.name.clone(),
            labels: label_names,
            pins: net
                .connections
                .iter()
                .map(|connection| SchematicPinRef {
                    symbol_uuid: stable_id(
                        SYMBOL_DOMAIN,
                        format!("{}\0{}", connection.reference, connection.unit).as_bytes(),
                    ),
                    reference: connection.reference.clone(),
                    unit: connection.unit,
                    number: connection.pin.clone(),
                })
                .collect(),
            points: Vec::new(),
        });
    }
    for (reference, unit, pin) in &no_connects {
        let id = no_connect_net_ids[&(reference.clone(), *unit, pin.clone())];
        schematic_nets.push(SchematicNet {
            id,
            name: format!("~NC:{reference}:{unit}:{pin}"),
            labels: Vec::new(),
            pins: vec![SchematicPinRef {
                symbol_uuid: stable_id(SYMBOL_DOMAIN, format!("{reference}\0{unit}").as_bytes()),
                reference: reference.clone(),
                unit: *unit,
                number: pin.clone(),
            }],
            points: Vec::new(),
        });
    }

    let mut symbols = Vec::new();
    for part in &normalized.parts {
        let mut properties = BTreeMap::new();
        if let Some(voltage) = part.power.rail_voltage_uv {
            properties.insert("pcbex:rail_voltage".into(), format_voltage_uv(voltage));
        }
        if let Some(voltage) = part.power.max_voltage_uv {
            properties.insert("pcbex:max_voltage".into(), format_voltage_uv(voltage));
        }
        if let Some(mpn) = &part.mpn {
            properties.insert("pcbex:mpn".into(), mpn.clone());
        }
        properties.insert(
            "pcbex:requires_decoupling".into(),
            part.power.requires_decoupling.to_string(),
        );
        properties.insert("pcbex:decoupling".into(), part.power.decoupling.to_string());
        for unit in &part.units {
            let symbol_uuid = stable_id(
                SYMBOL_DOMAIN,
                format!("{}\0{}", part.reference, unit.unit).as_bytes(),
            );
            let pins = unit
                .pins
                .iter()
                .map(|pin| {
                    let net_id = match &pin.net {
                        Some(net) => net_ids[net],
                        None => {
                            no_connect_net_ids
                                [&(part.reference.clone(), unit.unit, pin.number.clone())]
                        }
                    };
                    SchematicPin {
                        uuid: Some(stable_id(
                            PIN_DOMAIN,
                            format!("{}\0{}\0{}", part.reference, unit.unit, pin.number).as_bytes(),
                        )),
                        number: pin.number.clone(),
                        name: pin.name.clone(),
                        electrical_type: pin.electrical_type,
                        position: Point::default(),
                        hidden: false,
                        net_id,
                        no_connect: pin.electrical_type == ElectricalPinType::NoConnect,
                    }
                })
                .collect();
            symbols.push(SchematicSymbol {
                uuid: symbol_uuid,
                lib_id: part.lib_id.clone(),
                reference: part.reference.clone(),
                value: part.value.clone(),
                footprint: Some(part.footprint.clone()),
                unit: unit.unit,
                convert: 1,
                in_bom: true,
                on_board: true,
                dnp: false,
                position: Point::default(),
                rotation_deg: 0,
                mirror_x: false,
                mirror_y: false,
                properties: properties.clone(),
                pins,
            });
        }
    }
    Ok(SchematicDocument {
        schema_version: 1,
        source_version: 1,
        generator: "pcbex-circuit-spec-v3".into(),
        generator_version: Some(env!("CARGO_PKG_VERSION").into()),
        uuid: document_uuid,
        symbols,
        wires: Vec::new(),
        junctions: Vec::new(),
        no_connects: Vec::new(),
        labels,
        nets: schematic_nets,
        coverage: SchematicCoverage {
            complete: true,
            unsupported_features: Vec::new(),
        },
    })
}

/// Collapse explicit symbol units into one physical v2-shaped part inventory.
/// The v3 validator's global package-pin uniqueness makes this conversion
/// lossless for board, BOM, CPL, and manufacturing consumers.
pub fn circuit_spec_v3_to_physical_v2(spec: &CircuitSpecV3) -> Result<CircuitSpecV2, String> {
    let normalized = normalize_circuit_spec_v3(spec)?;
    let parts = normalized
        .parts
        .iter()
        .map(|part| CircuitPartV2 {
            reference: part.reference.clone(),
            lib_id: part.lib_id.clone(),
            value: part.value.clone(),
            footprint: part.footprint.clone(),
            mpn: part.mpn.clone(),
            power: part.power.clone(),
            pins: part
                .units
                .iter()
                .flat_map(|unit| unit.pins.iter().cloned())
                .collect(),
        })
        .collect();
    let nets = normalized
        .nets
        .iter()
        .map(|net| CircuitNetV2 {
            name: net.name.clone(),
            voltage_uv: net.voltage_uv,
            connections: net
                .connections
                .iter()
                .map(|connection| CircuitConnectionV2 {
                    reference: connection.reference.clone(),
                    pin: connection.pin.clone(),
                })
                .collect(),
        })
        .collect();
    super::normalize_circuit_spec_v2(&CircuitSpecV2 {
        schema_version: super::CIRCUIT_SPEC_V2_SCHEMA_VERSION,
        parts,
        nets,
    })
}

pub fn circuit_spec_v3_sha256(spec: &CircuitSpecV3) -> Result<String, String> {
    Ok(digest_hex(&canonical_json(&normalize_circuit_spec_v3(
        spec,
    )?)?))
}

pub fn circuit_spec_v3_json_schema() -> Value {
    let v2 = super::circuit_spec_v2_json_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/circuit-spec-v3.json",
        "title": "pcbex closed multi-unit circuit specification v3",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "parts", "nets"],
        "properties": {
            "schema_version": {"const": CIRCUIT_SPEC_V3_SCHEMA_VERSION},
            "parts": {"type": "array", "minItems": 1, "maxItems": CIRCUIT_SPEC_V3_MAX_PARTS, "items": {"$ref": "#/$defs/part"}},
            "nets": {"type": "array", "minItems": 1, "maxItems": CIRCUIT_SPEC_V3_MAX_NETS, "items": {"$ref": "#/$defs/net"}}
        },
        "$defs": {
            "part": {
                "type": "object", "additionalProperties": false,
                "required": ["reference", "lib_id", "value", "footprint", "mpn", "power", "units"],
                "properties": {
                    "reference": v2["$defs"]["part"]["properties"]["reference"].clone(),
                    "lib_id": v2["$defs"]["part"]["properties"]["lib_id"].clone(),
                    "value": v2["$defs"]["part"]["properties"]["value"].clone(),
                    "footprint": v2["$defs"]["part"]["properties"]["footprint"].clone(),
                    "mpn": v2["$defs"]["part"]["properties"]["mpn"].clone(),
                    "power": {"$ref": "#/$defs/power"},
                    "units": {"type": "array", "minItems": 1, "maxItems": CIRCUIT_SPEC_V3_MAX_UNITS_PER_PART, "items": {"$ref": "#/$defs/unit"}}
                }
            },
            "unit": {
                "type": "object", "additionalProperties": false,
                "required": ["unit", "pins"],
                "properties": {
                    "unit": {"type": "integer", "minimum": 1, "maximum": CIRCUIT_SPEC_V3_MAX_UNIT_NUMBER},
                    "pins": {"type": "array", "minItems": 1, "maxItems": CIRCUIT_SPEC_V3_MAX_PINS_PER_UNIT, "items": {"$ref": "#/$defs/pin"}}
                }
            },
            "power": v2["$defs"]["power"].clone(),
            "pin": v2["$defs"]["pin"].clone(),
            "net": {
                "type": "object", "additionalProperties": false,
                "required": ["name", "voltage_uv", "connections"],
                "properties": {
                    "name": v2["$defs"]["net"]["properties"]["name"].clone(),
                    "voltage_uv": v2["$defs"]["net"]["properties"]["voltage_uv"].clone(),
                    "connections": {"type": "array", "minItems": 2, "maxItems": CIRCUIT_SPEC_V3_MAX_CONNECTIONS_PER_NET, "items": {"$ref": "#/$defs/connection"}}
                }
            },
            "connection": {
                "type": "object", "additionalProperties": false,
                "required": ["reference", "unit", "pin"],
                "properties": {
                    "reference": v2["$defs"]["connection"]["properties"]["reference"].clone(),
                    "unit": {"type": "integer", "minimum": 1, "maximum": CIRCUIT_SPEC_V3_MAX_UNIT_NUMBER},
                    "pin": v2["$defs"]["connection"]["properties"]["pin"].clone()
                }
            }
        }
    })
}

pub fn circuit_spec_v3_check_json_schema() -> Value {
    let spec_schema = circuit_spec_v3_json_schema();
    let review_schema = electrical_review_json_schema();
    let mut definitions = Map::new();
    for (name, definition) in spec_schema["$defs"].as_object().expect("v3 schema defs") {
        definitions.insert(
            format!("circuit_{name}"),
            prefix_refs(definition.clone(), "circuit_"),
        );
    }
    for (name, definition) in review_schema["$defs"]
        .as_object()
        .expect("review schema defs")
    {
        definitions.insert(
            format!("electrical_{name}"),
            prefix_refs(definition.clone(), "electrical_"),
        );
    }
    definitions.insert(
        "circuit_spec".into(),
        json!({
            "type": "object", "additionalProperties": false,
            "required": spec_schema["required"].clone(),
            "properties": prefix_refs(spec_schema["properties"].clone(), "circuit_")
        }),
    );
    definitions.insert(
        "electrical_review".into(),
        json!({
            "type": "object", "additionalProperties": false,
            "required": review_schema["required"].clone(),
            "properties": prefix_refs(review_schema["properties"].clone(), "electrical_")
        }),
    );
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/circuit-spec-v3-check-v2.json",
        "title": "pcbex multi-unit circuit-spec immutable ERC check",
        "type": "object", "additionalProperties": false,
        "required": ["schema_version", "circuit_spec_sha256", "electrical_review_sha256", "normalized_spec", "electrical_review"],
        "properties": {
            "schema_version": {"const": CIRCUIT_SPEC_V3_CHECK_SCHEMA_VERSION},
            "circuit_spec_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "electrical_review_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "normalized_spec": {"$ref": "#/$defs/circuit_spec"},
            "electrical_review": {"$ref": "#/$defs/electrical_review"}
        },
        "$defs": {}
    });
    schema["$defs"] = Value::Object(definitions);
    schema
}

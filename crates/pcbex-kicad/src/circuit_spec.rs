//! Closed, deterministic circuit-spec v2 validation and electrical review.
//!
//! This module is intentionally a small bridge between the text-to-circuit
//! contract and the existing schematic electrical checker.  It does not
//! duplicate ERC rules: a normalized circuit spec is converted into a
//! deterministic schematic IR and passed to [`check_schematic`], which keeps
//! the immutable electrical safety floor in one place.

use super::{
    ElectricalPinType, ElectricalPolicy, ElectricalReview, SchematicCoverage, SchematicDocument,
    SchematicLabel, SchematicLabelKind, SchematicNet, SchematicPin, SchematicPinRef,
    SchematicSymbol, check_schematic, electrical_review_json_schema,
};
use pcbex_core::Point;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const CIRCUIT_SPEC_V2_SCHEMA_VERSION: u32 = 2;
pub const CIRCUIT_SPEC_CHECK_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted source size for the JSON circuit-spec contract.
pub const CIRCUIT_SPEC_V2_MAX_BYTES: u64 = 16 * 1024 * 1024;
pub const CIRCUIT_SPEC_V2_MAX_PARTS: usize = 256;
pub const CIRCUIT_SPEC_V2_MAX_NETS: usize = 512;
pub const CIRCUIT_SPEC_V2_MAX_PINS_PER_PART: usize = 256;
pub const CIRCUIT_SPEC_V2_MAX_CONNECTIONS_PER_NET: usize = 4096;
pub const CIRCUIT_SPEC_V2_MAX_TOTAL_PINS: usize = 4096;
pub const CIRCUIT_SPEC_V2_MAX_TOTAL_CONNECTIONS: usize = 8192;
pub const CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES: usize = 64;
pub const CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES: usize = 64;
pub const CIRCUIT_SPEC_V2_MAX_PIN_NAME_BYTES: usize = 256;
pub const CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES: usize = 128;
pub const CIRCUIT_SPEC_V2_MAX_LIB_ID_BYTES: usize = 256;
pub const CIRCUIT_SPEC_V2_MAX_VALUE_BYTES: usize = 512;
pub const CIRCUIT_SPEC_V2_MAX_FOOTPRINT_BYTES: usize = 512;
pub const CIRCUIT_SPEC_V2_MAX_MPN_BYTES: usize = 256;

const DOCUMENT_DOMAIN: &[u8] = b"pcbex:circuit-spec-v2:schematic\0";
const SYMBOL_DOMAIN: &[u8] = b"pcbex:circuit-spec-v2:symbol\0";
const PIN_DOMAIN: &[u8] = b"pcbex:circuit-spec-v2:pin\0";
const LABEL_DOMAIN: &[u8] = b"pcbex:circuit-spec-v2:label\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitSpecV2 {
    pub schema_version: u32,
    pub parts: Vec<CircuitPartV2>,
    pub nets: Vec<CircuitNetV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitPartV2 {
    pub reference: String,
    pub lib_id: String,
    pub value: String,
    pub footprint: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub mpn: Option<String>,
    pub power: CircuitPowerV2,
    pub pins: Vec<CircuitPinV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitPowerV2 {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub rail_voltage_uv: Option<i64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub max_voltage_uv: Option<i64>,
    pub requires_decoupling: bool,
    pub decoupling: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitPinV2 {
    pub number: String,
    pub name: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub net: Option<String>,
    pub electrical_type: ElectricalPinType,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitNetV2 {
    pub name: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub voltage_uv: Option<i64>,
    pub connections: Vec<CircuitConnectionV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitConnectionV2 {
    pub reference: String,
    pub pin: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitSpecCheck {
    pub schema_version: u32,
    pub circuit_spec_sha256: String,
    pub electrical_review_sha256: String,
    pub normalized_spec: CircuitSpecV2,
    pub electrical_review: ElectricalReview,
}

/// Parse, normalize, and validate a bounded JSON circuit-spec v2 document.
pub fn parse_circuit_spec_v2(source: &str) -> Result<CircuitSpecV2, String> {
    if source.is_empty() {
        return Err("circuit spec source must not be empty".into());
    }
    if source.len() as u64 > CIRCUIT_SPEC_V2_MAX_BYTES {
        return Err(format!(
            "circuit spec source exceeds {CIRCUIT_SPEC_V2_MAX_BYTES} bytes"
        ));
    }
    let value: CircuitSpecV2 = parse_json_without_duplicate_keys(source)?;
    normalize_circuit_spec_v2(&value)
}

fn parse_json_without_duplicate_keys(source: &str) -> Result<CircuitSpecV2, String> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let value = deserializer
        .deserialize_any(DuplicateValue)
        .map_err(|error| format!("invalid circuit-spec v2 JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("invalid circuit-spec v2 JSON: {error}"))?;
    serde_json::from_value(value).map_err(|error| format!("invalid circuit-spec v2 JSON: {error}"))
}

/// Deserialize a nullable value while requiring the containing JSON key to
/// be present.  Serde normally treats a missing `Option<T>` field as `None`,
/// but the v2 wire contract distinguishes an explicit `null` from an omitted
/// key, so nullable fields opt into this helper and intentionally do not use
/// `#[serde(default)]`.
fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

struct DuplicateValue;

impl<'de> DeserializeSeed<'de> for DuplicateValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateValue {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(DuplicateValue)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map_access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map_access.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let value = map_access.next_value_seed(DuplicateValue)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

/// Normalize and validate an in-memory circuit spec.
pub fn normalize_circuit_spec_v2(spec: &CircuitSpecV2) -> Result<CircuitSpecV2, String> {
    let mut normalized = spec.clone();
    if normalized.schema_version != CIRCUIT_SPEC_V2_SCHEMA_VERSION {
        return Err(format!(
            "unsupported circuit-spec schema version {} (expected {})",
            normalized.schema_version, CIRCUIT_SPEC_V2_SCHEMA_VERSION
        ));
    }
    if normalized.parts.is_empty() {
        return Err("circuit spec must contain at least one part".into());
    }
    if normalized.parts.len() > CIRCUIT_SPEC_V2_MAX_PARTS {
        return Err(format!(
            "circuit spec contains too many parts (maximum {})",
            CIRCUIT_SPEC_V2_MAX_PARTS
        ));
    }
    if normalized.nets.is_empty() {
        return Err("circuit spec must contain at least one net".into());
    }
    if normalized.nets.len() > CIRCUIT_SPEC_V2_MAX_NETS {
        return Err(format!(
            "circuit spec contains too many nets (maximum {})",
            CIRCUIT_SPEC_V2_MAX_NETS
        ));
    }

    let mut references = BTreeSet::new();
    let mut total_pins = 0usize;
    for part in &mut normalized.parts {
        part.reference = identifier(
            &part.reference,
            "part reference",
            CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES,
            true,
        )?;
        if !references.insert(part.reference.clone()) {
            return Err(format!("duplicate part reference {}", part.reference));
        }
        part.lib_id = lib_id(&part.lib_id)?;
        part.value = text(&part.value, "part value", CIRCUIT_SPEC_V2_MAX_VALUE_BYTES)?;
        part.footprint = text(
            &part.footprint,
            "part footprint",
            CIRCUIT_SPEC_V2_MAX_FOOTPRINT_BYTES,
        )?;
        part.mpn = part
            .mpn
            .take()
            .map(|mpn| text(&mpn, "part MPN", CIRCUIT_SPEC_V2_MAX_MPN_BYTES))
            .transpose()?;
        validate_power(&part.power, &part.reference)?;
        if part.pins.is_empty() {
            return Err(format!("{} must contain at least one pin", part.reference));
        }
        if part.pins.len() > CIRCUIT_SPEC_V2_MAX_PINS_PER_PART {
            return Err(format!(
                "{} contains too many pins (maximum {})",
                part.reference, CIRCUIT_SPEC_V2_MAX_PINS_PER_PART
            ));
        }
        let mut pin_numbers = BTreeSet::new();
        let mut has_non_no_connect = false;
        for pin in &mut part.pins {
            pin.number = identifier(
                &pin.number,
                &format!("{}.pin number", part.reference),
                CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES,
                false,
            )?;
            if !pin_numbers.insert(pin.number.clone()) {
                return Err(format!(
                    "{} contains duplicate pin {}",
                    part.reference, pin.number
                ));
            }
            pin.name = text(
                &pin.name,
                &format!("{}.{} pin name", part.reference, pin.number),
                CIRCUIT_SPEC_V2_MAX_PIN_NAME_BYTES,
            )?;
            match &mut pin.net {
                Some(net) => {
                    *net = identifier(
                        net,
                        &format!("{}.{} net", part.reference, pin.number),
                        CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES,
                        false,
                    )?;
                    if pin.electrical_type == ElectricalPinType::NoConnect {
                        return Err(format!(
                            "{} pin {} is no-connect but declares net {}",
                            part.reference, pin.number, net
                        ));
                    }
                    has_non_no_connect = true;
                }
                None if pin.electrical_type != ElectricalPinType::NoConnect => {
                    return Err(format!(
                        "{} pin {} has a null net but is not no-connect",
                        part.reference, pin.number
                    ));
                }
                None => {}
            }
            if pin.electrical_type == ElectricalPinType::Unspecified {
                return Err(format!(
                    "{} pin {} has unsupported unspecified electrical type",
                    part.reference, pin.number
                ));
            }
        }
        if !has_non_no_connect {
            return Err(format!(
                "{} must contain at least one non-no-connect pin",
                part.reference
            ));
        }
        total_pins = total_pins
            .checked_add(part.pins.len())
            .ok_or_else(|| "circuit spec pin count overflow".to_string())?;
        if total_pins > CIRCUIT_SPEC_V2_MAX_TOTAL_PINS {
            return Err(format!(
                "circuit spec contains too many pins (maximum {})",
                CIRCUIT_SPEC_V2_MAX_TOTAL_PINS
            ));
        }
        part.pins
            .sort_by(|left, right| left.number.cmp(&right.number));
    }
    normalized
        .parts
        .sort_by(|left, right| left.reference.cmp(&right.reference));

    let mut net_names = BTreeSet::new();
    let mut total_connections = 0usize;
    let mut known_pins = BTreeMap::<(String, String), (Option<String>, ElectricalPinType)>::new();
    let mut power_output_nets = BTreeMap::<String, BTreeSet<String>>::new();
    let mut has_power_input = BTreeSet::<String>::new();
    for part in &normalized.parts {
        for pin in &part.pins {
            known_pins.insert(
                (part.reference.clone(), pin.number.clone()),
                (pin.net.clone(), pin.electrical_type),
            );
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
        }
    }

    for net in &mut normalized.nets {
        net.name = identifier(
            &net.name,
            "net name",
            CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES,
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
        if net.connections.len() > CIRCUIT_SPEC_V2_MAX_CONNECTIONS_PER_NET {
            return Err(format!(
                "net {} contains too many connections (maximum {})",
                net.name, CIRCUIT_SPEC_V2_MAX_CONNECTIONS_PER_NET
            ));
        }
        total_connections = total_connections
            .checked_add(net.connections.len())
            .ok_or_else(|| "circuit spec connection count overflow".to_string())?;
        if total_connections > CIRCUIT_SPEC_V2_MAX_TOTAL_CONNECTIONS {
            return Err(format!(
                "circuit spec contains too many connections (maximum {})",
                CIRCUIT_SPEC_V2_MAX_TOTAL_CONNECTIONS
            ));
        }
        let mut seen_on_net = BTreeSet::new();
        for connection in &mut net.connections {
            connection.reference = identifier(
                &connection.reference,
                "connection reference",
                CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES,
                true,
            )?;
            connection.pin = identifier(
                &connection.pin,
                "connection pin",
                CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES,
                false,
            )?;
            let key = (connection.reference.clone(), connection.pin.clone());
            if !seen_on_net.insert(key.clone()) {
                return Err(format!(
                    "net {} contains duplicate connection {}.{}",
                    net.name, connection.reference, connection.pin
                ));
            }
            let Some((declared_net, electrical_type)) = known_pins.get(&key) else {
                return Err(format!(
                    "net {} references unknown {}.{}",
                    net.name, connection.reference, connection.pin
                ));
            };
            if *electrical_type == ElectricalPinType::NoConnect {
                return Err(format!(
                    "net {} connects no-connect pin {}.{}",
                    net.name, connection.reference, connection.pin
                ));
            }
            if declared_net.as_deref() != Some(net.name.as_str()) {
                return Err(format!(
                    "{}.{}, declared net {:?}, is connected to {}",
                    connection.reference, connection.pin, declared_net, net.name
                ));
            }
        }
        net.connections.sort_by(|left, right| {
            left.reference
                .cmp(&right.reference)
                .then_with(|| left.pin.cmp(&right.pin))
        });
    }
    normalized
        .nets
        .sort_by(|left, right| left.name.cmp(&right.name));

    let mut connected = BTreeSet::new();
    for net in &normalized.nets {
        for connection in &net.connections {
            let key = (connection.reference.clone(), connection.pin.clone());
            if !connected.insert(key.clone()) {
                return Err(format!(
                    "{}.{}, is connected to multiple nets",
                    connection.reference, connection.pin
                ));
            }
        }
    }
    for ((reference, pin), (declared_net, electrical_type)) in &known_pins {
        match declared_net {
            Some(_) if !connected.contains(&(reference.clone(), pin.clone())) => {
                return Err(format!(
                    "{}.{} is not connected to its declared net",
                    reference, pin
                ));
            }
            None if *electrical_type != ElectricalPinType::NoConnect => {
                return Err(format!(
                    "{}.{} has a non-no-connect null net",
                    reference, pin
                ));
            }
            _ => {}
        }
    }
    for (reference, power_output_nets) in &power_output_nets {
        let power = &normalized
            .parts
            .iter()
            .find(|part| &part.reference == reference)
            .expect("power output part exists")
            .power;
        if power.rail_voltage_uv.is_some() {
            if power_output_nets.is_empty() {
                return Err(format!(
                    "{} declares a rail voltage without a power-output pin",
                    reference
                ));
            }
            if power_output_nets.len() > 1 {
                return Err(format!(
                    "{} applies one rail voltage across multiple output nets",
                    reference
                ));
            }
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

/// Run the immutable electrical ERC against a normalized circuit spec.
pub fn check_circuit_spec(spec: &CircuitSpecV2) -> Result<CircuitSpecCheck, String> {
    let normalized = normalize_circuit_spec_v2(spec)?;
    let spec_bytes = canonical_json(&normalized)?;
    let circuit_spec_sha256 = digest_hex(&spec_bytes);
    let schematic = circuit_spec_v2_to_schematic(&normalized)?;
    let review = check_schematic(&schematic, &ElectricalPolicy::default())?;
    let review_bytes = canonical_json(&review)?;
    Ok(CircuitSpecCheck {
        schema_version: CIRCUIT_SPEC_CHECK_SCHEMA_VERSION,
        circuit_spec_sha256,
        electrical_review_sha256: digest_hex(&review_bytes),
        normalized_spec: normalized,
        electrical_review: review,
    })
}

/// Parse and run the immutable electrical ERC against a JSON circuit spec.
pub fn parse_and_check_circuit_spec_v2(source: &str) -> Result<CircuitSpecCheck, String> {
    let spec = parse_circuit_spec_v2(source)?;
    check_circuit_spec(&spec)
}

/// Convert a normalized v2 circuit specification into a deterministic
/// schematic IR consumed by the existing electrical checker.
pub fn circuit_spec_v2_to_schematic(spec: &CircuitSpecV2) -> Result<SchematicDocument, String> {
    let normalized = normalize_circuit_spec_v2(spec)?;
    let spec_bytes = canonical_json(&normalized)?;
    let document_uuid = stable_id(DOCUMENT_DOMAIN, &spec_bytes);

    let mut net_ids = BTreeMap::<String, u32>::new();
    for (index, net) in normalized.nets.iter().enumerate() {
        let id = u32::try_from(index + 1).map_err(|_| "net id overflow".to_string())?;
        net_ids.insert(net.name.clone(), id);
    }
    let mut no_connects = Vec::<(String, String)>::new();
    for part in &normalized.parts {
        for pin in &part.pins {
            if pin.electrical_type == ElectricalPinType::NoConnect {
                no_connects.push((part.reference.clone(), pin.number.clone()));
            }
        }
    }
    no_connects.sort();
    let first_no_connect_id = net_ids.len() as u32 + 1;
    let mut no_connect_net_ids = BTreeMap::<(String, String), u32>::new();
    for (offset, key) in no_connects.iter().enumerate() {
        let id = first_no_connect_id
            .checked_add(
                u32::try_from(offset).map_err(|_| "no-connect net id overflow".to_string())?,
            )
            .ok_or_else(|| "no-connect net id overflow".to_string())?;
        no_connect_net_ids.insert(key.clone(), id);
    }

    let mut labels = Vec::new();
    let mut schematic_nets = Vec::with_capacity(normalized.nets.len() + no_connects.len());
    for net in &normalized.nets {
        let id = *net_ids.get(&net.name).expect("normalized net id exists");
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
                    symbol_uuid: stable_id(SYMBOL_DOMAIN, connection.reference.as_bytes()),
                    reference: connection.reference.clone(),
                    unit: 1,
                    number: connection.pin.clone(),
                })
                .collect(),
            points: Vec::new(),
        });
    }
    for (reference, pin) in &no_connects {
        let id = *no_connect_net_ids
            .get(&(reference.clone(), pin.clone()))
            .expect("no-connect net id exists");
        schematic_nets.push(SchematicNet {
            id,
            name: format!("~NC:{reference}:{pin}"),
            labels: Vec::new(),
            pins: vec![SchematicPinRef {
                symbol_uuid: stable_id(SYMBOL_DOMAIN, reference.as_bytes()),
                reference: reference.clone(),
                unit: 1,
                number: pin.clone(),
            }],
            points: Vec::new(),
        });
    }

    let mut symbols = Vec::with_capacity(normalized.parts.len());
    for part in &normalized.parts {
        let symbol_uuid = stable_id(SYMBOL_DOMAIN, part.reference.as_bytes());
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
        // Always materialize the boolean power metadata.  The existing
        // schematic-side decoupling helper treats an absent
        // `pcbex:decoupling` property as true for `C*` references, so
        // omitting an explicit false here would silently change the input
        // contract during conversion.
        properties.insert(
            "pcbex:requires_decoupling".into(),
            if part.power.requires_decoupling {
                "true".into()
            } else {
                "false".into()
            },
        );
        properties.insert(
            "pcbex:decoupling".into(),
            if part.power.decoupling {
                "true".into()
            } else {
                "false".into()
            },
        );
        let pins = part
            .pins
            .iter()
            .map(|pin| {
                let net_id = match &pin.net {
                    Some(net) => *net_ids.get(net).expect("normalized declared net exists"),
                    None => *no_connect_net_ids
                        .get(&(part.reference.clone(), pin.number.clone()))
                        .expect("normalized no-connect net exists"),
                };
                SchematicPin {
                    uuid: Some(stable_id(
                        PIN_DOMAIN,
                        format!("{}\0{}", part.reference, pin.number).as_bytes(),
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
            unit: 1,
            convert: 1,
            in_bom: true,
            on_board: true,
            dnp: false,
            position: Point::default(),
            rotation_deg: 0,
            mirror_x: false,
            mirror_y: false,
            properties,
            pins,
        });
    }

    Ok(SchematicDocument {
        schema_version: 1,
        source_version: 1,
        generator: "pcbex-circuit-spec-v2".into(),
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

pub fn circuit_spec_v2_sha256(spec: &CircuitSpecV2) -> Result<String, String> {
    let normalized = normalize_circuit_spec_v2(spec)?;
    Ok(digest_hex(&canonical_json(&normalized)?))
}

pub fn circuit_spec_check_json_schema() -> Value {
    let spec_schema = circuit_spec_v2_json_schema();
    let review_schema = electrical_review_json_schema();
    let spec_properties = prefix_refs(spec_schema["properties"].clone(), "circuit_");
    let review_properties = prefix_refs(review_schema["properties"].clone(), "electrical_");
    let mut definitions = Map::new();
    if let Some(spec_definitions) = spec_schema["$defs"].as_object() {
        for (name, definition) in spec_definitions {
            definitions.insert(
                format!("circuit_{name}"),
                prefix_refs(definition.clone(), "circuit_"),
            );
        }
    }
    if let Some(review_definitions) = review_schema["$defs"].as_object() {
        for (name, definition) in review_definitions {
            definitions.insert(
                format!("electrical_{name}"),
                prefix_refs(definition.clone(), "electrical_"),
            );
        }
    }
    definitions.insert(
        "circuit_spec".into(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": spec_schema["required"].clone(),
            "properties": spec_properties,
        }),
    );
    definitions.insert(
        "electrical_review".into(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": review_schema["required"].clone(),
            "properties": review_properties,
        }),
    );
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/circuit-spec-check-v1.json",
        "title": "pcbex circuit-spec immutable ERC check",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "circuit_spec_sha256", "electrical_review_sha256",
            "normalized_spec", "electrical_review"
        ],
        "properties": {
            "schema_version": {"const": CIRCUIT_SPEC_CHECK_SCHEMA_VERSION},
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

pub fn circuit_spec_v2_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/circuit-spec-v2.json",
        "title": "pcbex closed circuit specification v2",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "parts", "nets"],
        "properties": {
            "schema_version": {"const": CIRCUIT_SPEC_V2_SCHEMA_VERSION},
            "parts": {
                "type": "array",
                "minItems": 1,
                "maxItems": CIRCUIT_SPEC_V2_MAX_PARTS,
                "items": {"$ref": "#/$defs/part"}
            },
            "nets": {
                "type": "array",
                "minItems": 1,
                "maxItems": CIRCUIT_SPEC_V2_MAX_NETS,
                "items": {"$ref": "#/$defs/net"}
            }
        },
        "$defs": {
            "part": {
                "type": "object",
                "additionalProperties": false,
                "required": ["reference", "lib_id", "value", "footprint", "mpn", "power", "pins"],
                "properties": {
                    "reference": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES,
                        "pattern": "^[A-Za-z][A-Za-z0-9_]*$"
                    },
                    "lib_id": {
                        "type": "string",
                        "minLength": 3,
                        "maxLength": CIRCUIT_SPEC_V2_MAX_LIB_ID_BYTES,
                        "pattern": "^[^:\\u0000-\\u001F\\u007F-\\u009F]*[^\\s:\\u0000-\\u001F\\u007F-\\u009F][^:\\u0000-\\u001F\\u007F-\\u009F]*:[^:\\u0000-\\u001F\\u007F-\\u009F]*[^\\s:\\u0000-\\u001F\\u007F-\\u009F][^:\\u0000-\\u001F\\u007F-\\u009F]*$"
                    },
                    "value": {"type": "string", "minLength": 1, "maxLength": CIRCUIT_SPEC_V2_MAX_VALUE_BYTES},
                    "footprint": {"type": "string", "minLength": 1, "maxLength": CIRCUIT_SPEC_V2_MAX_FOOTPRINT_BYTES},
                    "mpn": {
                        "anyOf": [
                            {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": CIRCUIT_SPEC_V2_MAX_MPN_BYTES
                            },
                            {"type": "null"}
                        ]
                    },
                    "power": {"$ref": "#/$defs/power"},
                    "pins": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": CIRCUIT_SPEC_V2_MAX_PINS_PER_PART,
                        "items": {"$ref": "#/$defs/pin"}
                    }
                }
            },
            "power": {
                "type": "object",
                "additionalProperties": false,
                "required": ["rail_voltage_uv", "max_voltage_uv", "requires_decoupling", "decoupling"],
                "properties": {
                    "rail_voltage_uv": {"type": ["integer", "null"], "minimum": 0, "maximum": 1000000000},
                    "max_voltage_uv": {"type": ["integer", "null"], "minimum": 0, "maximum": 1000000000},
                    "requires_decoupling": {"type": "boolean"},
                    "decoupling": {"type": "boolean"}
                }
            },
            "pin": {
                "type": "object",
                "additionalProperties": false,
                "required": ["number", "name", "net", "electrical_type"],
                "properties": {
                    "number": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES,
                        "pattern": "^[A-Za-z0-9_+./-]+$"
                    },
                    "name": {"type": "string", "minLength": 1, "maxLength": CIRCUIT_SPEC_V2_MAX_PIN_NAME_BYTES},
                    "net": {
                        "anyOf": [
                            {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES,
                                "pattern": "^[A-Za-z0-9_+./-]+$"
                            },
                            {"type": "null"}
                        ]
                    },
                    "electrical_type": {"enum": electrical_type_names()}
                }
            },
            "net": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "voltage_uv", "connections"],
                "properties": {
                    "name": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES,
                        "pattern": "^[A-Za-z0-9_+./-]+$"
                    },
                    "voltage_uv": {"type": ["integer", "null"], "minimum": 0, "maximum": 1000000000},
                    "connections": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": CIRCUIT_SPEC_V2_MAX_CONNECTIONS_PER_NET,
                        "items": {"$ref": "#/$defs/connection"}
                    }
                }
            },
            "connection": {
                "type": "object",
                "additionalProperties": false,
                "required": ["reference", "pin"],
                "properties": {
                    "reference": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES,
                        "pattern": "^[A-Za-z][A-Za-z0-9_]*$"
                    },
                    "pin": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES,
                        "pattern": "^[A-Za-z0-9_+./-]+$"
                    }
                }
            }
        }
    })
}

fn validate_power(power: &CircuitPowerV2, reference: &str) -> Result<(), String> {
    validate_voltage(power.rail_voltage_uv, &format!("{reference} rail voltage"))?;
    validate_voltage(
        power.max_voltage_uv,
        &format!("{reference} maximum voltage"),
    )
}

fn validate_voltage(value: Option<i64>, label: &str) -> Result<(), String> {
    if let Some(value) = value
        && !(0..=1_000_000_000).contains(&value)
    {
        return Err(format!(
            "{label} must be between 0 and 1000000000 microvolts"
        ));
    }
    Ok(())
}

fn text(value: &str, label: &str, max_bytes: usize) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    if trimmed.len() > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(format!("{label} must not contain control characters"));
    }
    Ok(trimmed.to_string())
}

fn identifier(
    value: &str,
    label: &str,
    max_bytes: usize,
    reference: bool,
) -> Result<String, String> {
    let value = text(value, label, max_bytes)?;
    let mut characters = value.chars();
    if reference {
        if !characters
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic())
            || !characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return Err(format!("{label} is not a valid reference"));
        }
    } else if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '+' | '.' | '/' | '-')
    }) {
        return Err(format!(
            "{label} contains unsupported identifier characters"
        ));
    }
    Ok(value)
}

fn lib_id(value: &str) -> Result<String, String> {
    let value = text(value, "part lib_id", CIRCUIT_SPEC_V2_MAX_LIB_ID_BYTES)?;
    if value.matches(':').count() != 1 {
        return Err("part lib_id must contain exactly one ':'".into());
    }
    let (library, symbol) = value.split_once(':').expect("lib_id contains one colon");
    if library.is_empty() || symbol.is_empty() {
        return Err("part lib_id library and symbol must be non-empty".into());
    }
    Ok(value)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| format!("serializing canonical JSON: {error}"))
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

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn stable_id(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    format!("pcbex-{}", hex::encode(hasher.finalize()))
}

fn format_voltage_uv(value: i64) -> String {
    if value % 1_000_000 == 0 {
        format!("{}V", value / 1_000_000)
    } else {
        let whole = value / 1_000_000;
        let fraction = format!("{:06}", value % 1_000_000)
            .trim_end_matches('0')
            .to_string();
        format!("{whole}.{fraction}V")
    }
}

fn electrical_type_names() -> [&'static str; 11] {
    [
        "input",
        "output",
        "bidirectional",
        "tri_state",
        "passive",
        "free",
        "power_input",
        "power_output",
        "open_collector",
        "open_emitter",
        "no_connect",
    ]
}

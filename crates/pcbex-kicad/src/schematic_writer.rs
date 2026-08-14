//! Deterministic KiCad schematic writers for circuit-spec v2 and v3.
//!
//! The writer intentionally emits a small, self-contained KiCad document.  It
//! does not resolve a project/library path: every referenced symbol is
//! embedded in `lib_symbols`, and every symbol is unit 1/convert 1.  This
//! keeps the text-to-circuit handoff reproducible and makes the generated
//! file safe to validate in a headless pipeline.

use super::circuit_spec::format_voltage_uv;
use super::{
    CIRCUIT_SPEC_V2_SCHEMA_VERSION, CIRCUIT_SPEC_V3_SCHEMA_VERSION, CircuitSpecV2, CircuitSpecV3,
    ElectricalPinType, ElectricalPolicy, circuit_spec_source_schema_version, import_schematic,
    normalize_circuit_spec_v2, normalize_circuit_spec_v3, parse_circuit_spec_v2,
    parse_circuit_spec_v3, verify_circuit_kicad_handoff,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as FmtWrite};

/// Fixed KiCad file version emitted by [`circuit_spec_v2_to_kicad_sch`].
pub const CIRCUIT_KICAD_SCHEMATIC_VERSION: u32 = 20231120;
/// Maximum generated KiCad schematic size.
pub const CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

const UUID_DOCUMENT_DOMAIN: &[u8] = b"pcbex:circuit-spec-v2:kicad-sch:document\0";
const UUID_SYMBOL_DOMAIN: &[u8] = b"pcbex:circuit-spec-v2:kicad-sch:symbol\0";
const UUID_PIN_DOMAIN: &[u8] = b"pcbex:circuit-spec-v2:kicad-sch:pin\0";
const UUID_LABEL_DOMAIN: &[u8] = b"pcbex:circuit-spec-v2:kicad-sch:label\0";
const UUID_NO_CONNECT_DOMAIN: &[u8] = b"pcbex:circuit-spec-v2:kicad-sch:no-connect\0";
const UUID_V3_DOCUMENT_DOMAIN: &[u8] = b"pcbex:circuit-spec-v3:kicad-sch:document\0";
const UUID_V3_SYMBOL_DOMAIN: &[u8] = b"pcbex:circuit-spec-v3:kicad-sch:symbol\0";
const UUID_V3_PIN_DOMAIN: &[u8] = b"pcbex:circuit-spec-v3:kicad-sch:pin\0";
const UUID_V3_LABEL_DOMAIN: &[u8] = b"pcbex:circuit-spec-v3:kicad-sch:label\0";
const UUID_V3_NO_CONNECT_DOMAIN: &[u8] = b"pcbex:circuit-spec-v3:kicad-sch:no-connect\0";

/// Generate a deterministic flat/single-unit KiCad schematic from a
/// normalized circuit-spec v2 document.
///
/// The input is normalized and passed through the immutable circuit ERC
/// before any output is published.  The generated text is then imported and
/// checked through the existing handoff verifier; a failed re-import or
/// semantic mismatch is returned as an error rather than returning a partial
/// document.
pub fn circuit_spec_v2_to_kicad_sch(spec: &CircuitSpecV2) -> Result<String, String> {
    let normalized = normalize_circuit_spec_v2(spec)?;
    let check = super::check_circuit_spec(&normalized)?;
    if !check.electrical_review.approved {
        return Err(format!(
            "circuit-spec electrical review is not approved ({} errors, {} warnings)",
            check.electrical_review.counts.errors, check.electrical_review.counts.warnings
        ));
    }

    let source_spec = serde_json::to_string(&normalized)
        .map_err(|error| format!("serializing normalized circuit spec: {error}"))?;
    let mut writer = LimitedWriter::new(CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES);
    write_document(&mut writer, &normalized).map_err(|error| error.to_string())?;
    let output = writer.into_string();

    let imported = import_schematic(&output)
        .map_err(|error| format!("generated KiCad schematic failed re-import: {error}"))?;
    if !imported.coverage.complete {
        return Err("generated KiCad schematic has incomplete parser coverage".into());
    }
    let handoff =
        verify_circuit_kicad_handoff(&source_spec, &output, &ElectricalPolicy::default())?;
    if !handoff.approved {
        let codes = handoff
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "generated KiCad schematic failed handoff self-check: {codes}"
        ));
    }
    Ok(output)
}

/// Generate a deterministic multi-unit KiCad schematic from circuit-spec v3.
/// Each `(reference, unit)` becomes one KiCad symbol instance, while all
/// instances retain the same physical reference and footprint identity.
pub fn circuit_spec_v3_to_kicad_sch(spec: &CircuitSpecV3) -> Result<String, String> {
    let normalized = normalize_circuit_spec_v3(spec)?;
    let check = super::check_circuit_spec_v3(&normalized)?;
    if !check.electrical_review.approved {
        return Err(format!(
            "circuit-spec electrical review is not approved ({} errors, {} warnings)",
            check.electrical_review.counts.errors, check.electrical_review.counts.warnings
        ));
    }

    let source_spec = serde_json::to_string(&normalized)
        .map_err(|error| format!("serializing normalized circuit spec: {error}"))?;
    let mut writer = LimitedWriter::new(CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES);
    write_document_v3(&mut writer, &normalized).map_err(|error| error.to_string())?;
    let output = writer.into_string();

    let imported = import_schematic(&output)
        .map_err(|error| format!("generated KiCad schematic failed re-import: {error}"))?;
    if !imported.coverage.complete {
        return Err("generated KiCad schematic has incomplete parser coverage".into());
    }
    let handoff =
        verify_circuit_kicad_handoff(&source_spec, &output, &ElectricalPolicy::default())?;
    if !handoff.approved {
        let codes = handoff
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "generated KiCad schematic failed handoff self-check: {codes}"
        ));
    }
    Ok(output)
}

/// Auto-select the deterministic writer for a closed v2 or v3 source.
pub fn circuit_spec_source_to_kicad_sch(source: &str) -> Result<String, String> {
    match circuit_spec_source_schema_version(source)? {
        CIRCUIT_SPEC_V2_SCHEMA_VERSION => {
            circuit_spec_v2_to_kicad_sch(&parse_circuit_spec_v2(source)?)
        }
        CIRCUIT_SPEC_V3_SCHEMA_VERSION => {
            circuit_spec_v3_to_kicad_sch(&parse_circuit_spec_v3(source)?)
        }
        version => Err(format!(
            "unsupported circuit-spec schema version {version} (expected {CIRCUIT_SPEC_V2_SCHEMA_VERSION} or {CIRCUIT_SPEC_V3_SCHEMA_VERSION})"
        )),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SymbolSignature {
    pins: Vec<(String, String, ElectricalPinType)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PinLocation {
    x: i64,
    y: i64,
}

fn write_document(writer: &mut LimitedWriter, spec: &CircuitSpecV2) -> Result<(), WriterError> {
    let mut uuids = BTreeSet::new();
    let document_key = serde_json::to_vec(spec)
        .map_err(|error| format!("serializing normalized circuit spec: {error}"))?;
    let document_uuid = unique_uuid(&mut uuids, UUID_DOCUMENT_DOMAIN, &document_key, "document")?;

    let symbols = collect_symbol_signatures(spec)?;
    let label_names = collect_label_names(spec)?;
    let (locations, part_y_stride) = pin_locations(spec);
    let part_indices = spec
        .parts
        .iter()
        .enumerate()
        .map(|(index, part)| (part.reference.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let pin_indices = spec
        .parts
        .iter()
        .enumerate()
        .flat_map(|(part_index, part)| {
            part.pins.iter().enumerate().map(move |(pin_index, pin)| {
                (
                    (part.reference.as_str(), pin.number.as_str()),
                    (part_index, pin_index),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();

    writeln!(writer, "(kicad_sch")?;
    writeln!(writer, "  (version {CIRCUIT_KICAD_SCHEMATIC_VERSION})")?;
    writeln!(writer, "  (generator pcbex)")?;
    writeln!(
        writer,
        "  (generator_version {})",
        quote(env!("CARGO_PKG_VERSION"))
    )?;
    writeln!(writer, "  (uuid {document_uuid})")?;
    writeln!(writer, "  (paper \"A4\")")?;
    write_library_symbols(writer, &symbols)?;

    for net in &spec.nets {
        let labels = label_names
            .get(net.name.as_str())
            .ok_or_else(|| format!("missing generated labels for net {}", net.name))?;
        for (connection_index, connection) in net.connections.iter().enumerate() {
            let key = (connection.reference.as_str(), connection.pin.as_str());
            let (part_index, pin_index) = *pin_indices
                .get(&key)
                .ok_or_else(|| format!("missing normalized connection {}.{}", key.0, key.1))?;
            let location = locations[&(part_index, pin_index)];
            for label in labels {
                if label != &net.name && connection_index != 0 {
                    continue;
                }
                let label_key = format!("{}\0{}\0{}\0{label}", net.name, key.0, key.1);
                let label_uuid =
                    unique_uuid(&mut uuids, UUID_LABEL_DOMAIN, label_key.as_bytes(), "label")?;
                writeln!(
                    writer,
                    "  (label {} (at {} {} 0) (effects (font (size 1.27 1.27)) (justify left bottom)) (uuid {label_uuid}))",
                    quote(label),
                    coord(location.x),
                    coord(location.y)
                )?;
            }
        }
    }

    for part in &spec.parts {
        for pin in &part.pins {
            if pin.electrical_type != ElectricalPinType::NoConnect {
                continue;
            }
            let part_index = *part_indices
                .get(part.reference.as_str())
                .ok_or_else(|| format!("missing part index for {}", part.reference))?;
            let pin_index = part
                .pins
                .iter()
                .position(|candidate| candidate.number == pin.number)
                .ok_or_else(|| {
                    format!("missing pin index for {}.{}", part.reference, pin.number)
                })?;
            let location = locations[&(part_index, pin_index)];
            let marker_key = format!("{}\0{}", part.reference, pin.number);
            let marker_uuid = unique_uuid(
                &mut uuids,
                UUID_NO_CONNECT_DOMAIN,
                marker_key.as_bytes(),
                "no-connect marker",
            )?;
            writeln!(
                writer,
                "  (no_connect (at {} {}) (uuid {marker_uuid}))",
                coord(location.x),
                coord(location.y)
            )?;
        }
    }

    for (part_index, part) in spec.parts.iter().enumerate() {
        let origin_x = part_origin_x(part_index);
        let origin_y = part_origin_y(part_index, part_y_stride);
        let symbol_uuid = unique_uuid(
            &mut uuids,
            UUID_SYMBOL_DOMAIN,
            part.reference.as_bytes(),
            "symbol",
        )?;
        writeln!(
            writer,
            "  (symbol (lib_id {}) (at {} {} 0) (unit 1) (exclude_from_sim no) (in_bom yes) (on_board yes) (dnp no) (uuid {symbol_uuid})",
            quote(&part.lib_id),
            coord(origin_x),
            coord(origin_y)
        )?;
        write_property(
            writer,
            "Reference",
            &part.reference,
            origin_x,
            origin_y - 2,
            false,
        )?;
        write_property(writer, "Value", &part.value, origin_x, origin_y - 1, false)?;
        write_property(
            writer,
            "Footprint",
            &part.footprint,
            origin_x,
            origin_y,
            true,
        )?;
        if let Some(mpn) = &part.mpn {
            write_property(writer, "pcbex:mpn", mpn, origin_x, origin_y, true)?;
        }
        if let Some(voltage) = part.power.rail_voltage_uv {
            write_property(
                writer,
                "pcbex:rail_voltage",
                &format_voltage_uv(voltage),
                origin_x,
                origin_y,
                true,
            )?;
        }
        if let Some(voltage) = part.power.max_voltage_uv {
            write_property(
                writer,
                "pcbex:max_voltage",
                &format_voltage_uv(voltage),
                origin_x,
                origin_y,
                true,
            )?;
        }
        write_property(
            writer,
            "pcbex:requires_decoupling",
            if part.power.requires_decoupling {
                "true"
            } else {
                "false"
            },
            origin_x,
            origin_y,
            true,
        )?;
        write_property(
            writer,
            "pcbex:decoupling",
            if part.power.decoupling {
                "true"
            } else {
                "false"
            },
            origin_x,
            origin_y,
            true,
        )?;
        for pin in &part.pins {
            let pin_index = part
                .pins
                .iter()
                .position(|candidate| candidate.number == pin.number)
                .ok_or_else(|| {
                    format!("missing pin index for {}.{}", part.reference, pin.number)
                })?;
            let pin_uuid_key = format!("{}\0{}", part.reference, pin.number);
            let pin_uuid =
                unique_uuid(&mut uuids, UUID_PIN_DOMAIN, pin_uuid_key.as_bytes(), "pin")?;
            writeln!(writer, "    (pin {} (uuid {pin_uuid}))", quote(&pin.number))?;
            debug_assert_eq!(
                locations[&(part_index, pin_index)],
                PinLocation {
                    x: origin_x + pin_index as i64,
                    y: origin_y,
                }
            );
        }
        writeln!(writer, "    (instances")?;
        writeln!(writer, "      (project \"pcbex-generated\"")?;
        writeln!(
            writer,
            "        (path {} (reference {}) (unit 1))",
            quote(&format!("/{document_uuid}")),
            quote(&part.reference)
        )?;
        writeln!(writer, "      )")?;
        writeln!(writer, "    )")?;
        writeln!(writer, "  )")?;
    }
    writeln!(writer, "  (sheet_instances (path \"/\" (page \"1\")))")?;
    writeln!(writer, ")")?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MultiUnitSymbolSignature {
    units: BTreeMap<u32, SymbolSignature>,
}

fn write_document_v3(writer: &mut LimitedWriter, spec: &CircuitSpecV3) -> Result<(), WriterError> {
    let mut uuids = BTreeSet::new();
    let document_key = serde_json::to_vec(spec)
        .map_err(|error| format!("serializing normalized circuit spec: {error}"))?;
    let document_uuid = unique_uuid(
        &mut uuids,
        UUID_V3_DOCUMENT_DOMAIN,
        &document_key,
        "document",
    )?;
    let signatures = collect_v3_symbol_signatures(spec)?;
    let labels_by_net = collect_v3_label_names(spec)?;
    let max_pins = spec
        .parts
        .iter()
        .flat_map(|part| part.units.iter())
        .map(|unit| unit.pins.len())
        .max()
        .unwrap_or(1) as i64;
    let stride = max_pins + 2;
    let mut placements = BTreeMap::<(String, u32), (usize, usize)>::new();
    let mut locations = BTreeMap::<(String, u32, String), PinLocation>::new();
    let mut symbol_index = 0usize;
    for (part_index, part) in spec.parts.iter().enumerate() {
        for unit in &part.units {
            placements.insert(
                (part.reference.clone(), unit.unit),
                (part_index, symbol_index),
            );
            let origin_x = part_origin_x(part_index);
            let origin_y = part_origin_y(symbol_index, stride);
            for (pin_index, pin) in unit.pins.iter().enumerate() {
                locations.insert(
                    (part.reference.clone(), unit.unit, pin.number.clone()),
                    PinLocation {
                        x: origin_x + pin_index as i64,
                        y: origin_y,
                    },
                );
            }
            symbol_index = symbol_index
                .checked_add(1)
                .ok_or_else(|| "multi-unit symbol index overflow".to_string())?;
        }
    }

    writeln!(writer, "(kicad_sch")?;
    writeln!(writer, "  (version {CIRCUIT_KICAD_SCHEMATIC_VERSION})")?;
    writeln!(writer, "  (generator pcbex)")?;
    writeln!(
        writer,
        "  (generator_version {})",
        quote(env!("CARGO_PKG_VERSION"))
    )?;
    writeln!(writer, "  (uuid {document_uuid})")?;
    writeln!(writer, "  (paper \"A4\")")?;
    write_v3_library_symbols(writer, &signatures)?;

    for net in &spec.nets {
        let labels = labels_by_net
            .get(net.name.as_str())
            .ok_or_else(|| format!("missing generated labels for net {}", net.name))?;
        for (connection_index, connection) in net.connections.iter().enumerate() {
            let key = (
                connection.reference.clone(),
                connection.unit,
                connection.pin.clone(),
            );
            let location = locations.get(&key).ok_or_else(|| {
                format!(
                    "missing normalized connection {}.unit{}.{}",
                    connection.reference, connection.unit, connection.pin
                )
            })?;
            for label in labels {
                if label != &net.name && connection_index != 0 {
                    continue;
                }
                let label_key = format!(
                    "{}\0{}\0{}\0{}\0{label}",
                    net.name, connection.reference, connection.unit, connection.pin
                );
                let label_uuid = unique_uuid(
                    &mut uuids,
                    UUID_V3_LABEL_DOMAIN,
                    label_key.as_bytes(),
                    "label",
                )?;
                writeln!(
                    writer,
                    "  (label {} (at {} {} 0) (effects (font (size 1.27 1.27)) (justify left bottom)) (uuid {label_uuid}))",
                    quote(label),
                    coord(location.x),
                    coord(location.y)
                )?;
            }
        }
    }

    for part in &spec.parts {
        for unit in &part.units {
            for pin in &unit.pins {
                if pin.electrical_type != ElectricalPinType::NoConnect {
                    continue;
                }
                let location = locations
                    .get(&(part.reference.clone(), unit.unit, pin.number.clone()))
                    .ok_or_else(|| {
                        format!(
                            "missing pin location for {}.unit{}.{}",
                            part.reference, unit.unit, pin.number
                        )
                    })?;
                let marker_key = format!("{}\0{}\0{}", part.reference, unit.unit, pin.number);
                let marker_uuid = unique_uuid(
                    &mut uuids,
                    UUID_V3_NO_CONNECT_DOMAIN,
                    marker_key.as_bytes(),
                    "no-connect marker",
                )?;
                writeln!(
                    writer,
                    "  (no_connect (at {} {}) (uuid {marker_uuid}))",
                    coord(location.x),
                    coord(location.y)
                )?;
            }
        }
    }

    for part in &spec.parts {
        for unit in &part.units {
            let (part_index, symbol_index) = placements
                .get(&(part.reference.clone(), unit.unit))
                .copied()
                .ok_or_else(|| {
                    format!(
                        "missing symbol placement for {} unit {}",
                        part.reference, unit.unit
                    )
                })?;
            let origin_x = part_origin_x(part_index);
            let origin_y = part_origin_y(symbol_index, stride);
            let symbol_key = format!("{}\0{}", part.reference, unit.unit);
            let symbol_uuid = unique_uuid(
                &mut uuids,
                UUID_V3_SYMBOL_DOMAIN,
                symbol_key.as_bytes(),
                "symbol",
            )?;
            writeln!(
                writer,
                "  (symbol (lib_id {}) (at {} {} 0) (unit {}) (exclude_from_sim no) (in_bom yes) (on_board yes) (dnp no) (uuid {symbol_uuid})",
                quote(&part.lib_id),
                coord(origin_x),
                coord(origin_y),
                unit.unit
            )?;
            write_property(
                writer,
                "Reference",
                &part.reference,
                origin_x,
                origin_y - 2,
                false,
            )?;
            write_property(writer, "Value", &part.value, origin_x, origin_y - 1, false)?;
            write_property(
                writer,
                "Footprint",
                &part.footprint,
                origin_x,
                origin_y,
                true,
            )?;
            if let Some(mpn) = &part.mpn {
                write_property(writer, "pcbex:mpn", mpn, origin_x, origin_y, true)?;
            }
            if let Some(voltage) = part.power.rail_voltage_uv {
                write_property(
                    writer,
                    "pcbex:rail_voltage",
                    &format_voltage_uv(voltage),
                    origin_x,
                    origin_y,
                    true,
                )?;
            }
            if let Some(voltage) = part.power.max_voltage_uv {
                write_property(
                    writer,
                    "pcbex:max_voltage",
                    &format_voltage_uv(voltage),
                    origin_x,
                    origin_y,
                    true,
                )?;
            }
            write_property(
                writer,
                "pcbex:requires_decoupling",
                if part.power.requires_decoupling {
                    "true"
                } else {
                    "false"
                },
                origin_x,
                origin_y,
                true,
            )?;
            write_property(
                writer,
                "pcbex:decoupling",
                if part.power.decoupling {
                    "true"
                } else {
                    "false"
                },
                origin_x,
                origin_y,
                true,
            )?;
            for pin in &unit.pins {
                let pin_key = format!("{}\0{}\0{}", part.reference, unit.unit, pin.number);
                let pin_uuid =
                    unique_uuid(&mut uuids, UUID_V3_PIN_DOMAIN, pin_key.as_bytes(), "pin")?;
                writeln!(writer, "    (pin {} (uuid {pin_uuid}))", quote(&pin.number))?;
            }
            writeln!(writer, "    (instances")?;
            writeln!(writer, "      (project \"pcbex-generated\"")?;
            writeln!(
                writer,
                "        (path {} (reference {}) (unit {}))",
                quote(&format!("/{document_uuid}")),
                quote(&part.reference),
                unit.unit
            )?;
            writeln!(writer, "      )")?;
            writeln!(writer, "    )")?;
            writeln!(writer, "  )")?;
        }
    }
    writeln!(writer, "  (sheet_instances (path \"/\" (page \"1\")))")?;
    writeln!(writer, ")")?;
    Ok(())
}

fn collect_v3_symbol_signatures(
    spec: &CircuitSpecV3,
) -> Result<BTreeMap<String, MultiUnitSymbolSignature>, String> {
    let mut signatures = BTreeMap::<String, MultiUnitSymbolSignature>::new();
    for part in &spec.parts {
        validate_embedded_library_id(&part.lib_id)?;
        let entry =
            signatures
                .entry(part.lib_id.clone())
                .or_insert_with(|| MultiUnitSymbolSignature {
                    units: BTreeMap::new(),
                });
        for unit in &part.units {
            let signature = SymbolSignature {
                pins: unit
                    .pins
                    .iter()
                    .map(|pin| (pin.number.clone(), pin.name.clone(), pin.electrical_type))
                    .collect(),
            };
            if let Some(existing) = entry.units.get(&unit.unit)
                && existing != &signature
            {
                return Err(format!(
                    "incompatible embedded symbol signature for library id {} unit {}",
                    part.lib_id, unit.unit
                ));
            }
            entry.units.entry(unit.unit).or_insert(signature);
        }
    }
    Ok(signatures)
}

fn collect_v3_label_names(spec: &CircuitSpecV3) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut owners = BTreeMap::<String, String>::new();
    let mut labels_by_net = BTreeMap::new();
    for net in &spec.nets {
        let mut labels = BTreeSet::new();
        labels.insert(net.name.clone());
        if let Some(voltage) = net.voltage_uv {
            labels.insert(format_voltage_uv(voltage));
        }
        for label in &labels {
            if let Some(existing) = owners.insert(label.clone(), net.name.clone())
                && existing != net.name
            {
                return Err(format!(
                    "label collision: {label} would merge nets {existing} and {}",
                    net.name
                ));
            }
        }
        labels_by_net.insert(net.name.clone(), labels.into_iter().collect());
    }
    Ok(labels_by_net)
}

fn write_v3_library_symbols(
    writer: &mut LimitedWriter,
    signatures: &BTreeMap<String, MultiUnitSymbolSignature>,
) -> Result<(), WriterError> {
    writeln!(writer, "  (lib_symbols")?;
    for (lib_id, signature) in signatures {
        let base_name = lib_id
            .rsplit_once(':')
            .map_or(lib_id.as_str(), |(_, name)| name);
        writeln!(writer, "    (symbol {}", quote(lib_id))?;
        writeln!(writer, "      (pin_names (offset 0))")?;
        writeln!(writer, "      (in_bom yes)")?;
        writeln!(writer, "      (on_board yes)")?;
        for (unit, unit_signature) in &signature.units {
            writeln!(
                writer,
                "      (symbol {}",
                quote(&format!("{base_name}_{unit}_1"))
            )?;
            for (pin_index, (number, name, electrical_type)) in
                unit_signature.pins.iter().enumerate()
            {
                writeln!(
                    writer,
                    "        (pin {} line (at {} 0 0) (length 2.54) (name {} (effects (font (size 1.27 1.27)))) (number {} (effects (font (size 1.27 1.27)))))",
                    electrical_type_token(*electrical_type),
                    coord(pin_index as i64),
                    quote(name),
                    quote(number)
                )?;
            }
            writeln!(writer, "      )")?;
        }
        writeln!(writer, "    )")?;
    }
    writeln!(writer, "  )")?;
    Ok(())
}

fn collect_symbol_signatures(
    spec: &CircuitSpecV2,
) -> Result<BTreeMap<String, SymbolSignature>, String> {
    let mut signatures = BTreeMap::new();
    for part in &spec.parts {
        validate_embedded_library_id(&part.lib_id)?;
        let signature = SymbolSignature {
            pins: part
                .pins
                .iter()
                .map(|pin| (pin.number.clone(), pin.name.clone(), pin.electrical_type))
                .collect(),
        };
        if let Some(existing) = signatures.get(&part.lib_id)
            && existing != &signature
        {
            return Err(format!(
                "incompatible embedded symbol signature for library id {}",
                part.lib_id
            ));
        }
        signatures.entry(part.lib_id.clone()).or_insert(signature);
    }
    Ok(signatures)
}

fn validate_embedded_library_id(lib_id: &str) -> Result<(), String> {
    if let Some(character) = lib_id
        .chars()
        .find(|character| matches!(character, '\\' | '"'))
    {
        return Err(format!(
            "part library id {lib_id:?} contains KiCad-incompatible character {character:?}"
        ));
    }
    Ok(())
}

fn collect_label_names(spec: &CircuitSpecV2) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut owners = BTreeMap::<String, String>::new();
    let mut labels_by_net = BTreeMap::new();
    for net in &spec.nets {
        let mut labels = BTreeSet::new();
        labels.insert(net.name.clone());
        if let Some(voltage) = net.voltage_uv {
            labels.insert(format_voltage_uv(voltage));
        }
        for label in &labels {
            if let Some(existing) = owners.insert(label.clone(), net.name.clone())
                && existing != net.name
            {
                return Err(format!(
                    "label collision: {label} would merge nets {existing} and {}",
                    net.name
                ));
            }
        }
        labels_by_net.insert(net.name.clone(), labels.into_iter().collect());
    }
    Ok(labels_by_net)
}

fn pin_locations(spec: &CircuitSpecV2) -> (BTreeMap<(usize, usize), PinLocation>, i64) {
    let max_pins = spec
        .parts
        .iter()
        .map(|part| part.pins.len())
        .max()
        .unwrap_or(1) as i64;
    let stride = max_pins + 2;
    let mut locations = BTreeMap::new();
    for (part_index, part) in spec.parts.iter().enumerate() {
        let x = part_origin_x(part_index);
        let origin_y = part_origin_y(part_index, stride);
        for pin_index in 0..part.pins.len() {
            // Keep synthetic pins on the local X axis. KiCad's schematic
            // coordinate transform reverses the symbol-local Y axis, while
            // the bounded pcbex importer represents file-space coordinates
            // directly. X-axis placement therefore gives both engines the
            // same connection point; the native-netlist E2E guards it.
            locations.insert(
                (part_index, pin_index),
                PinLocation {
                    x: x + pin_index as i64,
                    y: origin_y,
                },
            );
        }
    }
    (locations, stride)
}

fn write_library_symbols(
    writer: &mut LimitedWriter,
    signatures: &BTreeMap<String, SymbolSignature>,
) -> Result<(), WriterError> {
    writeln!(writer, "  (lib_symbols")?;
    for (lib_id, signature) in signatures {
        let nested_name = format!(
            "{}_1_1",
            lib_id
                .rsplit_once(':')
                .map_or(lib_id.as_str(), |(_, name)| name)
        );
        writeln!(writer, "    (symbol {}", quote(lib_id))?;
        writeln!(writer, "      (pin_names (offset 0))")?;
        writeln!(writer, "      (in_bom yes)")?;
        writeln!(writer, "      (on_board yes)")?;
        writeln!(writer, "      (symbol {}", quote(&nested_name))?;
        for (pin_index, (number, name, electrical_type)) in signature.pins.iter().enumerate() {
            writeln!(
                writer,
                "        (pin {} line (at {} 0 0) (length 2.54) (name {} (effects (font (size 1.27 1.27)))) (number {} (effects (font (size 1.27 1.27)))))",
                electrical_type_token(*electrical_type),
                coord(pin_index as i64),
                quote(name),
                quote(number)
            )?;
        }
        writeln!(writer, "      )")?;
        writeln!(writer, "    )")?;
    }
    writeln!(writer, "  )")?;
    Ok(())
}

fn electrical_type_token(electrical_type: ElectricalPinType) -> &'static str {
    match electrical_type {
        ElectricalPinType::Input => "input",
        ElectricalPinType::Output => "output",
        ElectricalPinType::Bidirectional => "bidirectional",
        ElectricalPinType::TriState => "tri_state",
        ElectricalPinType::Passive => "passive",
        ElectricalPinType::Free => "free",
        ElectricalPinType::Unspecified => "unspecified",
        ElectricalPinType::PowerInput => "power_in",
        ElectricalPinType::PowerOutput => "power_out",
        ElectricalPinType::OpenCollector => "open_collector",
        ElectricalPinType::OpenEmitter => "open_emitter",
        ElectricalPinType::NoConnect => "no_connect",
    }
}

fn part_origin_x(part_index: usize) -> i64 {
    8 + part_index as i64 * 16
}

fn part_origin_y(part_index: usize, stride: i64) -> i64 {
    8 + part_index as i64 * stride
}

fn coord(grid_units: i64) -> String {
    let hundredths = i128::from(grid_units) * 254;
    let negative = hundredths < 0;
    let absolute = hundredths.unsigned_abs();
    let whole = absolute / 100;
    let fraction = absolute % 100;
    if negative {
        format!("-{whole}.{fraction:02}")
    } else {
        format!("{whole}.{fraction:02}")
    }
}

fn write_property(
    writer: &mut LimitedWriter,
    name: &str,
    value: &str,
    x: i64,
    y: i64,
    hidden: bool,
) -> Result<(), WriterError> {
    writeln!(
        writer,
        "    (property {} {} (at {} {} 0) (effects (font (size 1.27 1.27)){}))",
        quote(name),
        quote(value),
        coord(x),
        coord(y),
        if hidden { " hide" } else { "" }
    )?;
    Ok(())
}

fn quote(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for character in value.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            _ => result.push(character),
        }
    }
    result.push('"');
    result
}

fn stable_uuid(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    // KiCad requires the version-4 UUID layout. The payload remains a
    // domain-separated SHA-256 prefix so generation is reproducible.
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15]
    )
}

fn unique_uuid(
    uuids: &mut BTreeSet<String>,
    domain: &[u8],
    bytes: &[u8],
    kind: &str,
) -> Result<String, String> {
    let uuid = stable_uuid(domain, bytes);
    if !uuids.insert(uuid.clone()) {
        return Err(format!("deterministic {kind} UUID collision: {uuid}"));
    }
    Ok(uuid)
}

struct LimitedWriter {
    text: String,
    max_bytes: usize,
}

impl LimitedWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            text: String::new(),
            max_bytes,
        }
    }

    fn into_string(self) -> String {
        self.text
    }
}

impl FmtWrite for LimitedWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let next = self.text.len().checked_add(value.len()).ok_or(fmt::Error)?;
        if next > self.max_bytes {
            return Err(fmt::Error);
        }
        self.text.try_reserve(value.len()).map_err(|_| fmt::Error)?;
        self.text.push_str(value);
        Ok(())
    }
}

#[derive(Debug)]
enum WriterError {
    Message(String),
    Limit,
}

impl fmt::Display for WriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => formatter.write_str(message),
            Self::Limit => {
                formatter.write_str("generated KiCad schematic exceeds output or allocation limit")
            }
        }
    }
}

impl From<String> for WriterError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<fmt::Error> for WriterError {
    fn from(_: fmt::Error) -> Self {
        Self::Limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CircuitConnectionV2, CircuitNetV2, CircuitPartV2, CircuitPinV2, CircuitPowerV2};

    fn spec() -> CircuitSpecV2 {
        CircuitSpecV2 {
            schema_version: 2,
            parts: vec![
                CircuitPartV2 {
                    reference: "R1".into(),
                    lib_id: "Device:R".into(),
                    value: "10k".into(),
                    footprint: "Resistor_SMD:R_0603".into(),
                    mpn: Some("RC0603FR-0710KL".into()),
                    power: CircuitPowerV2 {
                        rail_voltage_uv: None,
                        max_voltage_uv: None,
                        requires_decoupling: false,
                        decoupling: false,
                    },
                    pins: vec![
                        CircuitPinV2 {
                            number: "1".into(),
                            name: "A".into(),
                            net: Some("A".into()),
                            electrical_type: ElectricalPinType::Passive,
                        },
                        CircuitPinV2 {
                            number: "2".into(),
                            name: "B".into(),
                            net: Some("B".into()),
                            electrical_type: ElectricalPinType::Passive,
                        },
                    ],
                },
                CircuitPartV2 {
                    reference: "R2".into(),
                    lib_id: "Device:R".into(),
                    value: "10k".into(),
                    footprint: "Resistor_SMD:R_0603".into(),
                    mpn: None,
                    power: CircuitPowerV2 {
                        rail_voltage_uv: None,
                        max_voltage_uv: None,
                        requires_decoupling: false,
                        decoupling: false,
                    },
                    pins: vec![
                        CircuitPinV2 {
                            number: "1".into(),
                            name: "A".into(),
                            net: Some("A".into()),
                            electrical_type: ElectricalPinType::Passive,
                        },
                        CircuitPinV2 {
                            number: "2".into(),
                            name: "B".into(),
                            net: Some("B".into()),
                            electrical_type: ElectricalPinType::Passive,
                        },
                    ],
                },
            ],
            nets: vec![
                CircuitNetV2 {
                    name: "A".into(),
                    voltage_uv: None,
                    connections: vec![
                        CircuitConnectionV2 {
                            reference: "R1".into(),
                            pin: "1".into(),
                        },
                        CircuitConnectionV2 {
                            reference: "R2".into(),
                            pin: "1".into(),
                        },
                    ],
                },
                CircuitNetV2 {
                    name: "B".into(),
                    voltage_uv: Some(5_000_000),
                    connections: vec![
                        CircuitConnectionV2 {
                            reference: "R1".into(),
                            pin: "2".into(),
                        },
                        CircuitConnectionV2 {
                            reference: "R2".into(),
                            pin: "2".into(),
                        },
                    ],
                },
            ],
        }
    }

    #[test]
    fn writes_deterministic_flat_schematic_and_handoff_approves() {
        let spec = spec();
        let first = circuit_spec_v2_to_kicad_sch(&spec).unwrap();
        let second = circuit_spec_v2_to_kicad_sch(&spec).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("(lib_symbols"));
        assert!(first.contains("pcbex:mpn"));
        let imported = import_schematic(&first).unwrap();
        assert!(imported.coverage.complete);
        assert_eq!(imported.symbols.len(), 2);
        assert!(imported.labels.iter().any(|label| label.name == "5V"));
    }

    #[test]
    fn rejects_incompatible_embedded_symbol_signatures() {
        let mut spec = spec();
        spec.parts[1].pins[1].number = "3".into();
        spec.nets[1].connections[1].pin = "3".into();
        assert!(
            circuit_spec_v2_to_kicad_sch(&spec)
                .unwrap_err()
                .contains("incompatible embedded symbol signature")
        );
    }

    #[test]
    fn rejects_cross_net_label_collisions() {
        let mut spec = spec();
        spec.nets[0].name = "5V".into();
        spec.parts[0].pins[0].net = Some("5V".into());
        spec.parts[1].pins[0].net = Some("5V".into());
        assert!(
            circuit_spec_v2_to_kicad_sch(&spec)
                .unwrap_err()
                .contains("label collision")
        );
    }

    #[test]
    fn rejects_library_ids_that_native_kicad_cannot_load() {
        for invalid in ["Device:Foo\\Bar", "Device:Foo\"Bar"] {
            let mut spec = spec();
            for part in &mut spec.parts {
                part.lib_id = invalid.into();
            }
            let error = circuit_spec_v2_to_kicad_sch(&spec).unwrap_err();
            assert!(error.contains("KiCad-incompatible character"), "{error}");
        }
    }

    #[test]
    fn escapes_metadata_and_preserves_unicode_through_reimport() {
        let mut spec = spec();
        spec.parts[0].value = "10\"kΩ\\trim".into();
        spec.parts[0].footprint = "Custom:抵抗\"A\\B".into();
        spec.parts[0].mpn = Some("品番\"42\\rev".into());

        let output = circuit_spec_v2_to_kicad_sch(&spec).unwrap();
        assert!(output.contains("10\\\"kΩ\\\\trim"));
        assert!(output.contains("Custom:抵抗\\\"A\\\\B"));
        let imported = import_schematic(&output).unwrap();
        let resistor = imported
            .symbols
            .iter()
            .find(|symbol| symbol.reference == "R1")
            .unwrap();
        assert_eq!(resistor.value, "10\"kΩ\\trim");
        assert_eq!(resistor.footprint.as_deref(), Some("Custom:抵抗\"A\\B"));
        assert_eq!(
            resistor.properties.get("pcbex:mpn").map(String::as_str),
            Some("品番\"42\\rev")
        );
    }

    #[test]
    fn refuses_to_write_when_immutable_erc_rejects() {
        let mut spec = spec();
        for part in &mut spec.parts {
            part.pins[0].electrical_type = ElectricalPinType::Output;
        }
        let error = circuit_spec_v2_to_kicad_sch(&spec).unwrap_err();
        assert!(error.contains("electrical review is not approved"));
    }

    #[test]
    fn coordinate_format_handles_full_integer_domain() {
        assert_eq!(coord(i64::MAX), "23427364973611130549.78");
        assert_eq!(coord(i64::MIN), "-23427364973611130552.32");
    }

    #[test]
    fn output_limit_accepts_exact_bytes_and_rejects_one_over_without_mutation() {
        let mut writer = LimitedWriter::new(4);
        assert!(writer.write_str("é").is_ok());
        assert!(writer.write_str("ab").is_ok());
        assert_eq!(writer.text, "éab");
        assert!(writer.write_str("c").is_err());
        assert_eq!(writer.text, "éab");
    }

    #[test]
    fn deterministic_uuids_use_canonical_version_four_layout() {
        let uuid = stable_uuid(UUID_DOCUMENT_DOMAIN, b"fixture");
        assert_eq!(uuid, stable_uuid(UUID_DOCUMENT_DOMAIN, b"fixture"));
        assert_eq!(uuid.len(), 36);
        assert_eq!(&uuid[8..9], "-");
        assert_eq!(&uuid[13..14], "-");
        assert_eq!(&uuid[18..19], "-");
        assert_eq!(&uuid[23..24], "-");
        assert_eq!(&uuid[14..15], "4");
        assert!(matches!(&uuid[19..20], "8" | "9" | "a" | "b"));
        assert!(uuid.chars().enumerate().all(|(index, character)| matches!(
            index,
            8 | 13 | 18 | 23
        )
            || character.is_ascii_hexdigit()));
    }

    #[test]
    fn writes_and_reimports_explicit_multi_unit_symbols() {
        let source = r#"{
          "schema_version":3,
          "parts":[
            {"reference":"U1","lib_id":"Amplifier_Operational:DUAL","value":"DUAL","footprint":"Package_SO:SOIC-8","mpn":null,
             "power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},
             "units":[
               {"unit":1,"pins":[
                 {"number":"1","name":"OUTA","net":"A","electrical_type":"passive"},
                 {"number":"2","name":"INA","net":null,"electrical_type":"no_connect"}]},
               {"unit":2,"pins":[
                 {"number":"3","name":"OUTB","net":"B","electrical_type":"passive"},
                 {"number":"4","name":"INB","net":null,"electrical_type":"no_connect"}]}
             ]},
            {"reference":"R1","lib_id":"Device:R","value":"10k","footprint":"Resistor_SMD:R_0603","mpn":null,
             "power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},
             "units":[{"unit":1,"pins":[
               {"number":"1","name":"A","net":"A","electrical_type":"passive"},
               {"number":"2","name":"B","net":"B","electrical_type":"passive"}]}]}
          ],
          "nets":[
            {"name":"A","voltage_uv":null,"connections":[{"reference":"U1","unit":1,"pin":"1"},{"reference":"R1","unit":1,"pin":"1"}]},
            {"name":"B","voltage_uv":null,"connections":[{"reference":"U1","unit":2,"pin":"3"},{"reference":"R1","unit":1,"pin":"2"}]}
          ]
        }"#;
        let spec = parse_circuit_spec_v3(source).unwrap();
        let first = circuit_spec_v3_to_kicad_sch(&spec).unwrap();
        assert_eq!(first, circuit_spec_source_to_kicad_sch(source).unwrap());
        let imported = import_schematic(&first).unwrap();
        assert!(imported.coverage.complete);
        assert!(imported.symbols.iter().any(|symbol| {
            symbol.reference == "U1" && symbol.unit == 1 && symbol.pins[0].number == "1"
        }));
        assert!(imported.symbols.iter().any(|symbol| {
            symbol.reference == "U1" && symbol.unit == 2 && symbol.pins[0].number == "3"
        }));
        let report =
            verify_circuit_kicad_handoff(source, &first, &ElectricalPolicy::default()).unwrap();
        assert!(report.approved, "{:?}", report.findings);
    }
}

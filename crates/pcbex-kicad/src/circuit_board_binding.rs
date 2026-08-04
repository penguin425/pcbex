//! Digest-bound verification of a circuit-spec v2, a real KiCad schematic,
//! and the KiCad board intended to implement that schematic.
//!
//! The existing circuit-to-schematic handoff remains authoritative for the
//! logical circuit and ERC decision.  This module always recomputes that
//! handoff from the raw sources, then compares the approved schematic's actual
//! canonical net names with top-level board footprints, pads, and net
//! declarations.  Placement, copper geometry, routing, DRC, and DFM are
//! deliberately outside this identity boundary.

use super::{
    CIRCUIT_SPEC_V2_MAX_FOOTPRINT_BYTES, CIRCUIT_SPEC_V2_MAX_MPN_BYTES,
    CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES, CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES,
    CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES, CIRCUIT_SPEC_V2_MAX_VALUE_BYTES,
    CircuitKicadHandoffReport, CircuitPartV2, ElectricalPolicy, Layer, Point, SchematicDocument,
    SchematicSymbol, Sexp, atom, board_copper_layers, check_circuit_spec, checked_mm_to_nm,
    circuit_kicad_handoff_report_json_schema, custom_pad_polygon, import_schematic, number_u32,
    optional_offset_pair, pad_layers, parse, parse_circuit_spec_v2, required_dimension_pair,
    scalar_f64, verify_circuit_kicad_handoff,
};
use crate::manufacturing::{ManufacturingPart, parse_footprint};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Schema version of [`CircuitKicadBoardBindingReport`].
pub const CIRCUIT_KICAD_BOARD_BINDING_SCHEMA_VERSION: u32 = 1;
/// Compatibility alias used by clients that name report schemas explicitly.
pub const CIRCUIT_KICAD_BOARD_BINDING_REPORT_SCHEMA_VERSION: u32 =
    CIRCUIT_KICAD_BOARD_BINDING_SCHEMA_VERSION;
/// Engine version embedded in board-binding reports.
pub const CIRCUIT_KICAD_BOARD_BINDING_ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Maximum KiCad board source accepted by the board-binding API.
pub const CIRCUIT_KICAD_BOARD_BINDING_MAX_BOARD_BYTES: u64 = 128 * 1024 * 1024;
/// Maximum compact JSON size of a returned board-binding report.
pub const CIRCUIT_KICAD_BOARD_BINDING_MAX_REPORT_BYTES: usize = 12 * 1024 * 1024;

const MAX_BINDING_NETS: usize = 100_000;
const MAX_BINDING_FOOTPRINTS: usize = 4_096;
const MAX_BINDING_PADS: usize = 100_000;
const MAX_BINDING_FINDINGS: usize = 250_000;
const MAX_BINDING_PAD_LAYER_NAMES: usize = 60;
const BOARD_ELECTRICAL_DOMAIN: &[u8] = b"pcbex:circuit-kicad-board-electrical-v1\0";
const HANDOFF_REPORT_DOMAIN: &[u8] = b"pcbex:circuit-kicad-handoff-report-v1\0";
const BOARD_BINDING_DOMAIN: &[u8] = b"pcbex:circuit-kicad-board-binding-v1\0";

const BOARD_BINDING_FINDING_CODES: [&str; 18] = [
    "missing_reserved_net_zero",
    "missing_footprint",
    "extra_footprint",
    "duplicate_footprint_reference",
    "footprint_id_mismatch",
    "value_mismatch",
    "mpn_mismatch",
    "assembly_metadata_mismatch",
    "missing_pad",
    "extra_pad",
    "duplicate_pad_number",
    "pad_type_mismatch",
    "connected_unnumbered_pad",
    "unnumbered_pad_unsupported",
    "pad_net_mismatch",
    "no_connect_mismatch",
    "missing_net",
    "extra_net",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitKicadBoardBindingFinding {
    pub code: String,
    pub message: String,
    pub reference: Option<String>,
    pub pin: Option<String>,
    pub net: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitKicadBoardBindingFindingCounts {
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
}

/// A closed, deterministic three-way circuit/schematic/board identity report.
///
/// The nested handoff contains the circuit and schematic raw/canonical
/// identities and both ERC reviews.  Top-level board fields avoid duplicating
/// those identities while binding the exact board bytes and a geometry-free
/// electrical projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitKicadBoardBindingReport {
    pub schema_version: u32,
    pub engine_version: String,
    pub board_source_bytes: u64,
    pub board_source_sha256: String,
    pub board_electrical_sha256: String,
    pub circuit_kicad_handoff_sha256: String,
    pub binding_sha256: String,
    pub circuit_kicad_handoff: CircuitKicadHandoffReport,
    pub findings: Vec<CircuitKicadBoardBindingFinding>,
    pub counts: CircuitKicadBoardBindingFindingCounts,
    pub approved: bool,
}

#[derive(Clone, Debug)]
struct BoardBindingDocument {
    has_reserved_net_zero: bool,
    nets: BTreeMap<u32, String>,
    footprints: Vec<BoardBindingFootprint>,
}

#[derive(Clone, Debug)]
struct BoardBindingFootprint {
    part: ManufacturingPart,
    pads: Vec<BoardBindingPad>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
struct BoardBindingPad {
    number: String,
    kind: String,
    net: Option<String>,
}

#[derive(Serialize)]
struct BoardElectricalProjection<'a> {
    has_reserved_net_zero: bool,
    nets: Vec<&'a str>,
    footprints: Vec<BoardElectricalFootprintProjection<'a>>,
}

#[derive(Serialize)]
struct BoardElectricalFootprintProjection<'a> {
    reference: &'a str,
    footprint: &'a str,
    value: &'a str,
    mpn: &'a Option<String>,
    in_bom: bool,
    dnp: bool,
    pads: Vec<&'a BoardBindingPad>,
}

#[derive(Serialize)]
struct BindingIdentity<'a> {
    schema_version: u32,
    engine_version: &'a str,
    board_source_bytes: u64,
    circuit_kicad_handoff_sha256: &'a str,
    board_source_sha256: &'a str,
    board_electrical_sha256: &'a str,
    findings: &'a [CircuitKicadBoardBindingFinding],
    counts: &'a CircuitKicadBoardBindingFindingCounts,
    approved: bool,
}

/// Verify raw circuit-spec v2, KiCad schematic, and KiCad board sources.
///
/// Parsing and resource-contract failures return `Err`.  Once the three raw
/// documents are imported, ERC and semantic differences are retained as a
/// report with `approved: false` so CI and MCP callers can publish evidence.
pub fn verify_circuit_kicad_board_binding(
    circuit_source: &str,
    schematic_source: &str,
    board_source: &str,
    policy: &ElectricalPolicy,
) -> Result<CircuitKicadBoardBindingReport, String> {
    if board_source.len() as u64 > CIRCUIT_KICAD_BOARD_BINDING_MAX_BOARD_BYTES {
        return Err(format!(
            "KiCad board exceeds the {CIRCUIT_KICAD_BOARD_BINDING_MAX_BOARD_BYTES}-byte board-binding limit"
        ));
    }

    // Never accept a producer-supplied handoff report.  Recompute it from the
    // same raw inputs used for this three-way gate.
    let handoff = verify_circuit_kicad_handoff(circuit_source, schematic_source, policy)?;
    let checked_spec = check_circuit_spec(&parse_circuit_spec_v2(circuit_source)?)?;
    let schematic = import_schematic(schematic_source)?;
    let board = parse_board_binding_document(board_source)?;

    let mut findings =
        compare_board_binding(&checked_spec.normalized_spec.parts, &schematic, &board)?;
    sort_findings(&mut findings);

    let board_projection = board_electrical_projection(&board);
    let board_projection_bytes = canonical_json(&board_projection)?;
    let handoff_bytes = canonical_json(&handoff)?;
    let board_source_sha256 = digest_hex(board_source.as_bytes());
    let board_electrical_sha256 = domain_digest(BOARD_ELECTRICAL_DOMAIN, &board_projection_bytes);
    let circuit_kicad_handoff_sha256 = domain_digest(HANDOFF_REPORT_DOMAIN, &handoff_bytes);
    let counts = CircuitKicadBoardBindingFindingCounts {
        errors: handoff.counts.errors.saturating_add(findings.len()),
        warnings: handoff.counts.warnings,
        info: handoff.counts.info,
    };
    let approved = handoff.approved && findings.is_empty();
    let binding_bytes = canonical_json(&BindingIdentity {
        schema_version: CIRCUIT_KICAD_BOARD_BINDING_SCHEMA_VERSION,
        engine_version: CIRCUIT_KICAD_BOARD_BINDING_ENGINE_VERSION,
        board_source_bytes: board_source.len() as u64,
        circuit_kicad_handoff_sha256: &circuit_kicad_handoff_sha256,
        board_source_sha256: &board_source_sha256,
        board_electrical_sha256: &board_electrical_sha256,
        findings: &findings,
        counts: &counts,
        approved,
    })?;
    let binding_sha256 = domain_digest(BOARD_BINDING_DOMAIN, &binding_bytes);

    let report = CircuitKicadBoardBindingReport {
        schema_version: CIRCUIT_KICAD_BOARD_BINDING_SCHEMA_VERSION,
        engine_version: CIRCUIT_KICAD_BOARD_BINDING_ENGINE_VERSION.to_string(),
        board_source_bytes: board_source.len() as u64,
        board_source_sha256,
        board_electrical_sha256,
        circuit_kicad_handoff_sha256,
        binding_sha256,
        circuit_kicad_handoff: handoff,
        findings,
        counts,
        approved,
    };
    if canonical_json(&report)?.len() > CIRCUIT_KICAD_BOARD_BINDING_MAX_REPORT_BYTES {
        return Err(format!(
            "circuit-to-KiCad board-binding report exceeds {CIRCUIT_KICAD_BOARD_BINDING_MAX_REPORT_BYTES} bytes"
        ));
    }
    Ok(report)
}

fn parse_board_binding_document(source: &str) -> Result<BoardBindingDocument, String> {
    let root = parse(source)?;
    let top = root
        .as_list()
        .ok_or_else(|| "KiCad document is not an s-expression".to_string())?;
    if atom(top.first()) != Some("kicad_pcb") {
        return Err("expected a kicad_pcb document".into());
    }
    let copper_layers = board_copper_layers(top)?;

    let mut nets = BTreeMap::<u32, String>::new();
    let mut names = BTreeMap::<String, u32>::new();
    for item in top {
        let Some(values) = item.as_list() else {
            continue;
        };
        if atom(values.first()) != Some("net") {
            continue;
        }
        if nets.len() >= MAX_BINDING_NETS {
            return Err(format!(
                "KiCad board contains more than {MAX_BINDING_NETS} net declarations"
            ));
        }
        if values.len() != 3 {
            return Err("KiCad board net declaration must contain exactly one ID and name".into());
        }
        let id = number_u32(values.get(1))
            .ok_or_else(|| "KiCad board net is missing a valid numeric ID".to_string())?;
        let name = atom(values.get(2))
            .ok_or_else(|| format!("KiCad board net {id} is missing a scalar name"))?
            .to_string();
        if id == 0 && !name.is_empty() {
            return Err("KiCad board net 0 name must be empty".into());
        }
        if id != 0 && name.trim().is_empty() {
            return Err(format!("KiCad board net {id} name must not be blank"));
        }
        validate_board_text(
            &name,
            &format!("KiCad board net {id} name"),
            CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES,
            id == 0,
        )?;
        if let Some(existing) = nets.insert(id, name.clone()) {
            return Err(format!(
                "KiCad board contains duplicate net ID {id}: {existing} and {name}"
            ));
        }
        if let Some(existing) = names.insert(name.clone(), id) {
            return Err(format!(
                "KiCad board contains duplicate net name {name}: IDs {existing} and {id}"
            ));
        }
    }

    let mut footprints = Vec::new();
    let mut total_pads = 0usize;
    for item in top {
        let Some(values) = item.as_list() else {
            continue;
        };
        if atom(values.first()) != Some("footprint") {
            continue;
        }
        if footprints.len() >= MAX_BINDING_FOOTPRINTS {
            return Err(format!(
                "KiCad board contains more than {MAX_BINDING_FOOTPRINTS} footprints for board binding"
            ));
        }
        let part = parse_footprint(values)?;
        validate_board_text(
            &part.reference,
            "KiCad board footprint reference",
            CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES,
            false,
        )?;
        validate_board_text(
            &part.footprint,
            &format!("KiCad board footprint {} identifier", part.reference),
            CIRCUIT_SPEC_V2_MAX_FOOTPRINT_BYTES,
            false,
        )?;
        validate_board_text(
            &part.value,
            &format!("KiCad board footprint {} value", part.reference),
            CIRCUIT_SPEC_V2_MAX_VALUE_BYTES,
            !part.in_bom,
        )?;
        if let Some(mpn) = &part.mpn {
            validate_board_text(
                mpn,
                &format!("KiCad board footprint {} MPN", part.reference),
                CIRCUIT_SPEC_V2_MAX_MPN_BYTES,
                false,
            )?;
        }
        let mut pads = Vec::new();
        for child in values {
            let Some(pad_values) = child.as_list() else {
                continue;
            };
            if atom(pad_values.first()) != Some("pad") {
                continue;
            }
            total_pads = total_pads
                .checked_add(1)
                .ok_or_else(|| "KiCad board pad count overflow".to_string())?;
            if total_pads > MAX_BINDING_PADS {
                return Err(format!(
                    "KiCad board contains more than {MAX_BINDING_PADS} pads for board binding"
                ));
            }
            pads.push(parse_binding_pad(pad_values, &nets, &copper_layers)?);
        }
        pads.sort();
        footprints.push(BoardBindingFootprint { part, pads });
    }
    footprints.sort_by(|left, right| {
        left.part
            .reference
            .cmp(&right.part.reference)
            .then_with(|| left.part.footprint.cmp(&right.part.footprint))
            .then_with(|| left.part.value.cmp(&right.part.value))
            .then_with(|| left.part.mpn.cmp(&right.part.mpn))
            .then_with(|| left.part.in_bom.cmp(&right.part.in_bom))
            .then_with(|| left.part.dnp.cmp(&right.part.dnp))
            .then_with(|| left.pads.cmp(&right.pads))
    });

    Ok(BoardBindingDocument {
        has_reserved_net_zero: nets.get(&0).is_some_and(String::is_empty),
        nets,
        footprints,
    })
}

fn parse_binding_pad(
    values: &[Sexp],
    nets: &BTreeMap<u32, String>,
    copper_layers: &[Layer],
) -> Result<BoardBindingPad, String> {
    if values.len() < 4 {
        return Err("KiCad pad header must contain number, type, and shape".into());
    }
    let number = atom(values.get(1))
        .ok_or_else(|| "KiCad pad is missing a scalar number".to_string())?
        .to_string();
    validate_board_text(
        &number,
        "KiCad board pad number",
        CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES,
        true,
    )?;
    let kind = atom(values.get(2))
        .ok_or_else(|| format!("KiCad pad {number:?} is missing a scalar kind"))?
        .to_string();
    validate_board_text(&kind, "KiCad board pad kind", 64, false)?;
    if !matches!(
        kind.as_str(),
        "smd" | "thru_hole" | "np_thru_hole" | "connect"
    ) {
        return Err(format!("KiCad pad {number:?} type {kind:?} is unsupported"));
    }
    let shape = atom(values.get(3))
        .ok_or_else(|| format!("KiCad pad {number:?} is missing a scalar shape"))?;
    if !matches!(
        shape,
        "circle" | "oval" | "rect" | "roundrect" | "trapezoid" | "custom"
    ) {
        return Err(format!(
            "KiCad pad {number:?} shape {shape:?} is unsupported"
        ));
    }
    validate_binding_pad_size(values, &number)?;
    validate_binding_pad_layers(values, &number, copper_layers)?;
    if shape == "custom" {
        custom_pad_polygon(values, Point { x_nm: 0, y_nm: 0 }, 0.0)
            .and_then(|polygon| {
                polygon.ok_or_else(|| {
                    format!("KiCad custom pad {number:?} requires one supported gr_poly primitive")
                })
            })
            .map_err(|error| format!("KiCad custom pad {number:?} is invalid: {error}"))?;
    }
    if matches!(kind.as_str(), "thru_hole" | "np_thru_hole") {
        validate_binding_pad_drill(values, &number)?;
    } else if !binding_children(values, "drill").is_empty() {
        return Err(format!(
            "KiCad pad {number:?} of type {kind:?} must not contain a drill field"
        ));
    }
    let net_fields = values
        .iter()
        .filter_map(|item| {
            let child = item.as_list()?;
            (atom(child.first()) == Some("net")).then_some(child)
        })
        .collect::<Vec<_>>();
    if net_fields.len() > 1 {
        return Err(format!(
            "KiCad pad {number:?} net fields must not be repeated"
        ));
    }
    let net = match net_fields.first() {
        None => None,
        Some(field) => {
            if field.len() != 3 {
                return Err(format!(
                    "KiCad pad {number:?} net field must contain exactly one ID and name"
                ));
            }
            let id = number_u32(field.get(1))
                .ok_or_else(|| format!("KiCad pad {number:?} is missing a valid numeric net ID"))?;
            let declared = nets
                .get(&id)
                .ok_or_else(|| format!("KiCad pad {number:?} references undeclared net ID {id}"))?;
            let name = atom(field.get(2))
                .ok_or_else(|| format!("KiCad pad {number:?} net {id} is missing a scalar name"))?;
            if name != declared {
                return Err(format!(
                    "KiCad pad {number:?} net {id} name {name:?} does not match declared name {declared:?}"
                ));
            }
            (id != 0).then(|| declared.clone())
        }
    };
    Ok(BoardBindingPad { number, kind, net })
}

fn binding_children<'a>(values: &'a [Sexp], name: &str) -> Vec<&'a [Sexp]> {
    values
        .iter()
        .filter_map(|item| {
            let child = item.as_list()?;
            (atom(child.first()) == Some(name)).then_some(child)
        })
        .collect()
}

fn validate_binding_pad_size(values: &[Sexp], number: &str) -> Result<(), String> {
    required_dimension_pair(values, "size", &format!("KiCad pad {number:?} size")).map(|_| ())
}

fn validate_binding_pad_layers(
    values: &[Sexp],
    number: &str,
    copper_layers: &[Layer],
) -> Result<(), String> {
    let layers = binding_children(values, "layers");
    let [layers] = layers.as_slice() else {
        return Err(format!(
            "KiCad pad {number:?} must contain exactly one layers field"
        ));
    };
    if layers.len() < 2 || layers.len() - 1 > MAX_BINDING_PAD_LAYER_NAMES {
        return Err(format!("KiCad pad {number:?} has an invalid layers field"));
    }
    let mut seen = BTreeSet::new();
    for layer in layers.iter().skip(1) {
        let layer = atom(Some(layer))
            .filter(|layer| !layer.is_empty())
            .ok_or_else(|| format!("KiCad pad {number:?} has an invalid layers field"))?;
        if !seen.insert(layer) {
            return Err(format!(
                "KiCad pad {number:?} layers field contains duplicate layer {layer:?}"
            ));
        }
    }
    pad_layers(values, copper_layers)
        .map_err(|error| format!("KiCad pad {number:?} has invalid layers: {error}"))?;
    Ok(())
}

fn validate_binding_pad_drill(values: &[Sexp], number: &str) -> Result<(), String> {
    let drills = binding_children(values, "drill");
    let [drill] = drills.as_slice() else {
        return Err(format!(
            "KiCad pad {number:?} must contain exactly one drill field"
        ));
    };
    for value in drill.iter().skip(1) {
        if let Some(child) = value.as_list()
            && atom(child.first()) != Some("offset")
        {
            return Err(format!(
                "KiCad pad {number:?} drill contains an unsupported child"
            ));
        }
    }
    let scalars = drill
        .iter()
        .skip(1)
        .filter(|value| atom(Some(value)).is_some())
        .collect::<Vec<_>>();
    let (width, height) = if scalars.first().and_then(|value| atom(Some(value))) == Some("oval") {
        if scalars.len() != 3 {
            return Err(format!(
                "KiCad pad {number:?} oval drill must contain two dimensions"
            ));
        }
        (
            scalar_f64(scalars.get(1).copied(), "KiCad pad drill width")?,
            scalar_f64(scalars.get(2).copied(), "KiCad pad drill height")?,
        )
    } else {
        if scalars.is_empty() || scalars.len() > 2 {
            return Err(format!(
                "KiCad pad {number:?} drill must contain one or two dimensions"
            ));
        }
        let width = scalar_f64(scalars.first().copied(), "KiCad pad drill width")?;
        let height = scalars
            .get(1)
            .map(|value| scalar_f64(Some(*value), "KiCad pad drill height"))
            .transpose()?
            .unwrap_or(width);
        (width, height)
    };
    checked_mm_to_nm(width, "KiCad pad drill width", false, true)?;
    checked_mm_to_nm(height, "KiCad pad drill height", false, true)?;
    optional_offset_pair(drill, "offset", "KiCad pad drill offset")?;
    Ok(())
}

fn validate_board_text(
    value: &str,
    label: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), String> {
    if value.is_empty() && allow_empty {
        return Ok(());
    }
    if value.trim().is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    if value.len() > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{label} must not contain control characters"));
    }
    Ok(())
}

fn compare_board_binding(
    parts: &[CircuitPartV2],
    schematic: &SchematicDocument,
    board: &BoardBindingDocument,
) -> Result<Vec<CircuitKicadBoardBindingFinding>, String> {
    let mut findings = Vec::new();
    if !board.has_reserved_net_zero {
        push_finding(
            &mut findings,
            "missing_reserved_net_zero",
            "KiCad board must declare reserved net 0 with an empty name".into(),
            None,
            None,
            None,
        )?;
    }

    let expected_references = parts
        .iter()
        .map(|part| part.reference.as_str())
        .collect::<BTreeSet<_>>();
    let mut board_by_reference = BTreeMap::<&str, Vec<&BoardBindingFootprint>>::new();
    for footprint in &board.footprints {
        board_by_reference
            .entry(&footprint.part.reference)
            .or_default()
            .push(footprint);
    }
    let mut schematic_by_reference = BTreeMap::<&str, Vec<&SchematicSymbol>>::new();
    for symbol in &schematic.symbols {
        schematic_by_reference
            .entry(&symbol.reference)
            .or_default()
            .push(symbol);
    }
    let schematic_net_names = schematic
        .nets
        .iter()
        .map(|net| (net.id, net.name.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut expected_net_names = BTreeSet::<String>::new();
    for part in parts {
        let symbols = schematic_by_reference
            .get(part.reference.as_str())
            .cloned()
            .unwrap_or_default();
        let symbol = (symbols.len() == 1).then_some(symbols[0]);
        for pin in &part.pins {
            if let Some(net) = expected_pin_net(
                pin.net.as_deref(),
                symbol,
                &pin.number,
                &schematic_net_names,
            ) {
                expected_net_names.insert(net.to_string());
            }
        }
    }

    for (reference, footprints) in &board_by_reference {
        if footprints.len() > 1 {
            push_finding(
                &mut findings,
                "duplicate_footprint_reference",
                format!(
                    "KiCad board contains {} footprints with reference {reference}",
                    footprints.len()
                ),
                Some((*reference).to_string()),
                None,
                None,
            )?;
        }
        if !expected_references.contains(reference) {
            push_finding(
                &mut findings,
                "extra_footprint",
                format!("KiCad board contains unexpected footprint {reference}"),
                Some((*reference).to_string()),
                None,
                None,
            )?;
        }
    }

    for part in parts {
        let reference = part.reference.as_str();
        let board_footprints = board_by_reference
            .get(reference)
            .cloned()
            .unwrap_or_default();
        if board_footprints.is_empty() {
            push_finding(
                &mut findings,
                "missing_footprint",
                format!("KiCad board is missing footprint {reference}"),
                Some(reference.to_string()),
                None,
                None,
            )?;
            continue;
        }
        if board_footprints.len() != 1 {
            continue;
        }
        let footprint = board_footprints[0];
        let schematic_symbols = schematic_by_reference
            .get(reference)
            .cloned()
            .unwrap_or_default();
        let symbol = (schematic_symbols.len() == 1).then_some(schematic_symbols[0]);
        compare_footprint_metadata(part, symbol, footprint, &mut findings)?;
        compare_pads(part, symbol, footprint, &schematic_net_names, &mut findings)?;
    }

    let board_net_names = board
        .nets
        .iter()
        .filter(|(id, _)| **id != 0)
        .map(|(_, name)| name.clone())
        .collect::<BTreeSet<_>>();
    for name in expected_net_names.difference(&board_net_names) {
        push_finding(
            &mut findings,
            "missing_net",
            format!("KiCad board is missing schematic net {name}"),
            None,
            None,
            Some(name.clone()),
        )?;
    }
    for name in board_net_names.difference(&expected_net_names) {
        push_finding(
            &mut findings,
            "extra_net",
            format!("KiCad board declares unexpected net {name}"),
            None,
            None,
            Some(name.clone()),
        )?;
    }
    Ok(findings)
}

fn compare_footprint_metadata(
    part: &CircuitPartV2,
    symbol: Option<&SchematicSymbol>,
    footprint: &BoardBindingFootprint,
    findings: &mut Vec<CircuitKicadBoardBindingFinding>,
) -> Result<(), String> {
    let expected_footprint = symbol
        .and_then(|symbol| symbol.footprint.as_deref())
        .unwrap_or(&part.footprint);
    let expected_value = symbol.map_or(part.value.as_str(), |symbol| symbol.value.as_str());
    let expected_mpn = symbol
        .and_then(|symbol| symbol.properties.get("pcbex:mpn"))
        .map(String::as_str)
        .or(part.mpn.as_deref());
    if footprint.part.footprint != expected_footprint {
        push_finding(
            findings,
            "footprint_id_mismatch",
            format!(
                "footprint {} uses {:?}; expected {:?}",
                part.reference, footprint.part.footprint, expected_footprint
            ),
            Some(part.reference.clone()),
            None,
            None,
        )?;
    }
    if footprint.part.value != expected_value {
        push_finding(
            findings,
            "value_mismatch",
            format!(
                "footprint {} value is {:?}; expected {:?}",
                part.reference, footprint.part.value, expected_value
            ),
            Some(part.reference.clone()),
            None,
            None,
        )?;
    }
    if footprint.part.mpn.as_deref() != expected_mpn {
        push_finding(
            findings,
            "mpn_mismatch",
            format!(
                "footprint {} MPN is {:?}; expected {:?}",
                part.reference, footprint.part.mpn, expected_mpn
            ),
            Some(part.reference.clone()),
            None,
            None,
        )?;
    }
    let expected_in_bom = symbol.is_none_or(|symbol| symbol.in_bom);
    let expected_dnp = symbol.is_some_and(|symbol| symbol.dnp);
    let expected_on_board = symbol.is_none_or(|symbol| symbol.on_board);
    if footprint.part.in_bom != expected_in_bom
        || footprint.part.dnp != expected_dnp
        || !expected_on_board
    {
        push_finding(
            findings,
            "assembly_metadata_mismatch",
            format!(
                "footprint {} assembly metadata is in_bom={}, dnp={}; schematic expects in_bom={}, on_board={}, dnp={}",
                part.reference,
                footprint.part.in_bom,
                footprint.part.dnp,
                expected_in_bom,
                expected_on_board,
                expected_dnp
            ),
            Some(part.reference.clone()),
            None,
            None,
        )?;
    }
    Ok(())
}

fn compare_pads(
    part: &CircuitPartV2,
    symbol: Option<&SchematicSymbol>,
    footprint: &BoardBindingFootprint,
    schematic_net_names: &BTreeMap<u32, &str>,
    findings: &mut Vec<CircuitKicadBoardBindingFinding>,
) -> Result<(), String> {
    let expected_numbers = part
        .pins
        .iter()
        .map(|pin| pin.number.as_str())
        .collect::<BTreeSet<_>>();
    let mut pads_by_number = BTreeMap::<&str, Vec<&BoardBindingPad>>::new();
    for pad in &footprint.pads {
        if pad.number.is_empty() {
            if pad.net.is_some() {
                push_finding(
                    findings,
                    "connected_unnumbered_pad",
                    format!(
                        "footprint {} has an unnumbered pad connected to {:?}",
                        part.reference, pad.net
                    ),
                    Some(part.reference.clone()),
                    None,
                    pad.net.clone(),
                )?;
            } else if pad.kind != "np_thru_hole" {
                push_finding(
                    findings,
                    "unnumbered_pad_unsupported",
                    format!(
                        "footprint {} has an unnumbered non-NPTH pad of kind {:?}",
                        part.reference, pad.kind
                    ),
                    Some(part.reference.clone()),
                    None,
                    None,
                )?;
            }
            continue;
        }
        if pad.kind == "np_thru_hole" {
            push_finding(
                findings,
                "pad_type_mismatch",
                format!(
                    "footprint {} pad {} is non-plated mechanical and cannot implement a circuit pin",
                    part.reference, pad.number
                ),
                Some(part.reference.clone()),
                Some(pad.number.clone()),
                pad.net.clone(),
            )?;
        }
        pads_by_number.entry(&pad.number).or_default().push(pad);
    }
    for (number, pads) in &pads_by_number {
        if pads.len() > 1 {
            push_finding(
                findings,
                "duplicate_pad_number",
                format!(
                    "footprint {} contains {} pads numbered {number}",
                    part.reference,
                    pads.len()
                ),
                Some(part.reference.clone()),
                Some((*number).to_string()),
                None,
            )?;
        }
        if !expected_numbers.contains(number) {
            push_finding(
                findings,
                "extra_pad",
                format!(
                    "footprint {} contains unexpected pad {number}",
                    part.reference
                ),
                Some(part.reference.clone()),
                Some((*number).to_string()),
                None,
            )?;
        }
    }

    for expected_pin in &part.pins {
        let pads = pads_by_number
            .get(expected_pin.number.as_str())
            .cloned()
            .unwrap_or_default();
        if pads.is_empty() {
            push_finding(
                findings,
                "missing_pad",
                format!(
                    "footprint {} is missing pad {}",
                    part.reference, expected_pin.number
                ),
                Some(part.reference.clone()),
                Some(expected_pin.number.clone()),
                None,
            )?;
            continue;
        }
        if pads.len() != 1 {
            continue;
        }
        let actual_pad = pads[0];
        let expected_net = expected_pin_net(
            expected_pin.net.as_deref(),
            symbol,
            &expected_pin.number,
            schematic_net_names,
        );
        match (expected_net, actual_pad.net.as_deref()) {
            (None, None) => {}
            (None, Some(actual)) => push_finding(
                findings,
                "no_connect_mismatch",
                format!(
                    "footprint {} pad {} is connected to {actual}; schematic pin is no-connect",
                    part.reference, expected_pin.number
                ),
                Some(part.reference.clone()),
                Some(expected_pin.number.clone()),
                Some(actual.to_string()),
            )?,
            (Some(expected), None) => push_finding(
                findings,
                "no_connect_mismatch",
                format!(
                    "footprint {} pad {} is unconnected; schematic pin expects {expected}",
                    part.reference, expected_pin.number
                ),
                Some(part.reference.clone()),
                Some(expected_pin.number.clone()),
                Some(expected.to_string()),
            )?,
            (Some(expected), Some(actual)) if expected != actual => push_finding(
                findings,
                "pad_net_mismatch",
                format!(
                    "footprint {} pad {} is on net {actual}; schematic pin expects {expected}",
                    part.reference, expected_pin.number
                ),
                Some(part.reference.clone()),
                Some(expected_pin.number.clone()),
                Some(expected.to_string()),
            )?,
            (Some(_), Some(_)) => {}
        }
    }
    Ok(())
}

fn expected_pin_net<'a>(
    fallback: Option<&'a str>,
    symbol: Option<&'a SchematicSymbol>,
    pin_number: &str,
    schematic_net_names: &BTreeMap<u32, &'a str>,
) -> Option<&'a str> {
    let Some(symbol) = symbol else {
        return fallback;
    };
    let mut matches = symbol.pins.iter().filter(|pin| pin.number == pin_number);
    let Some(pin) = matches.next() else {
        return fallback;
    };
    if matches.next().is_some() {
        return fallback;
    }
    if pin.no_connect {
        None
    } else {
        schematic_net_names.get(&pin.net_id).copied().or(fallback)
    }
}

fn board_electrical_projection(board: &BoardBindingDocument) -> BoardElectricalProjection<'_> {
    let mut nets = board
        .nets
        .iter()
        .filter(|(id, _)| **id != 0)
        .map(|(_, name)| name.as_str())
        .collect::<Vec<_>>();
    nets.sort_unstable();
    let footprints = board
        .footprints
        .iter()
        .map(|footprint| BoardElectricalFootprintProjection {
            reference: &footprint.part.reference,
            footprint: &footprint.part.footprint,
            value: &footprint.part.value,
            mpn: &footprint.part.mpn,
            in_bom: footprint.part.in_bom,
            dnp: footprint.part.dnp,
            pads: footprint.pads.iter().collect(),
        })
        .collect();
    BoardElectricalProjection {
        has_reserved_net_zero: board.has_reserved_net_zero,
        nets,
        footprints,
    }
}

fn push_finding(
    findings: &mut Vec<CircuitKicadBoardBindingFinding>,
    code: &str,
    message: String,
    reference: Option<String>,
    pin: Option<String>,
    net: Option<String>,
) -> Result<(), String> {
    if !BOARD_BINDING_FINDING_CODES.contains(&code) {
        return Err(format!(
            "internal board-binding finding code is not closed: {code}"
        ));
    }
    if findings.len() >= MAX_BINDING_FINDINGS {
        return Err(format!(
            "board-binding finding count exceeds {MAX_BINDING_FINDINGS}"
        ));
    }
    findings.push(CircuitKicadBoardBindingFinding {
        code: code.to_string(),
        message,
        reference,
        pin,
        net,
    });
    Ok(())
}

fn sort_findings(findings: &mut [CircuitKicadBoardBindingFinding]) {
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
        .map_err(|error| format!("unable to serialize canonical JSON: {error}"))
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Return the manually closed JSON schema for
/// [`CircuitKicadBoardBindingReport`].
pub fn circuit_kicad_board_binding_report_json_schema() -> Value {
    let handoff_schema = circuit_kicad_handoff_report_json_schema();
    let mut definitions = Map::new();
    if let Some(handoff_defs) = handoff_schema["$defs"].as_object() {
        for (name, definition) in handoff_defs {
            definitions.insert(
                format!("handoff_{name}"),
                prefix_refs(definition.clone(), "handoff_"),
            );
        }
    }
    definitions.insert(
        "handoff_report".into(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": handoff_schema["required"].clone(),
            "properties": prefix_refs(handoff_schema["properties"].clone(), "handoff_")
        }),
    );
    definitions.insert(
        "binding_finding".into(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["code", "message", "reference", "pin", "net"],
            "properties": {
                "code": {"enum": BOARD_BINDING_FINDING_CODES},
                "message": {"type": "string", "minLength": 1},
                "reference": {"type": ["string", "null"], "minLength": 1},
                "pin": {"type": ["string", "null"], "minLength": 1},
                "net": {"type": ["string", "null"], "minLength": 1}
            }
        }),
    );
    definitions.insert(
        "binding_counts".into(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["errors", "warnings", "info"],
            "properties": {
                "errors": {"type": "integer", "minimum": 0},
                "warnings": {"type": "integer", "minimum": 0},
                "info": {"type": "integer", "minimum": 0}
            }
        }),
    );
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/circuit-kicad-board-binding-v1.json",
        "title": "pcbex circuit-spec v2 to KiCad schematic and board binding",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "engine_version", "board_source_bytes",
            "board_source_sha256", "board_electrical_sha256",
            "circuit_kicad_handoff_sha256", "binding_sha256",
            "circuit_kicad_handoff", "findings", "counts", "approved"
        ],
        "properties": {
            "schema_version": {"const": CIRCUIT_KICAD_BOARD_BINDING_SCHEMA_VERSION},
            "engine_version": {"const": CIRCUIT_KICAD_BOARD_BINDING_ENGINE_VERSION},
            "board_source_bytes": {"type": "integer", "minimum": 1},
            "board_source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "board_electrical_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "circuit_kicad_handoff_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "binding_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "circuit_kicad_handoff": {"$ref": "#/$defs/handoff_report"},
            "findings": {
                "type": "array",
                "maxItems": MAX_BINDING_FINDINGS,
                "items": {"$ref": "#/$defs/binding_finding"}
            },
            "counts": {"$ref": "#/$defs/binding_counts"},
            "approved": {"type": "boolean"}
        },
        "$defs": definitions
    })
}

fn prefix_refs(value: Value, prefix: &str) -> Value {
    match value {
        Value::String(reference) if reference.starts_with("#/$defs/") => Value::String(format!(
            "#/$defs/{prefix}{}",
            reference.trim_start_matches("#/$defs/")
        )),
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

#[cfg(test)]
mod tests {
    use super::*;

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

    const BOARD: &str = r#"(kicad_pcb
      (version 20250114) (generator pcbex-test)
      (net 0 "") (net 1 "SIG")
      (footprint "Package:R_0603" (layer "F.Cu") (at 10 10) (attr smd)
        (fp_text reference "R1" (at 0 0) (layer "F.Fab"))
        (fp_text value "10k" (at 0 1) (layer "F.Fab"))
        (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu") (net 1 "SIG"))
        (pad "2" smd rect (at 1 0) (size 1 1) (layers "F.Cu")))
      (footprint "Package:R_0603" (layer "F.Cu") (at 20 10) (attr smd)
        (fp_text reference "R2" (at 0 0) (layer "F.Fab"))
        (fp_text value "10k" (at 0 1) (layer "F.Fab"))
        (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu") (net 1 "SIG"))
        (pad "2" smd rect (at 1 0) (size 1 1) (layers "F.Cu"))))"#;

    fn verify(board: &str) -> CircuitKicadBoardBindingReport {
        verify_circuit_kicad_board_binding(SPEC, SCHEMATIC, board, &ElectricalPolicy::default())
            .unwrap()
    }

    #[test]
    fn exact_binding_is_deterministic_and_schema_is_closed() {
        let first = verify(BOARD);
        let second = verify(BOARD);
        assert_eq!(first, second);
        assert!(first.approved, "{:?}", first.findings);
        assert_eq!(first.counts.errors, 0);
        assert_eq!(first.board_source_sha256.len(), 64);
        assert_eq!(first.board_electrical_sha256.len(), 64);
        assert_eq!(first.binding_sha256.len(), 64);
        assert!(first.circuit_kicad_handoff.approved);

        let schema = circuit_kicad_board_binding_report_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["engine_version"]["const"],
            CIRCUIT_KICAD_BOARD_BINDING_ENGINE_VERSION
        );
        assert_eq!(
            schema["$defs"]["binding_finding"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["$defs"]["handoff_report"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn detects_swapped_pad_nets_missing_and_extra_records() {
        let swapped = BOARD.replace(
            "(pad \"2\" smd rect (at 1 0) (size 1 1) (layers \"F.Cu\"))",
            "(pad \"2\" smd rect (at 1 0) (size 1 1) (layers \"F.Cu\") (net 1 \"SIG\"))",
        );
        let report = verify(&swapped);
        assert!(!report.approved);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "no_connect_mismatch")
        );

        let missing = BOARD.replacen(
            "(pad \"2\" smd rect (at 1 0) (size 1 1) (layers \"F.Cu\"))",
            "",
            1,
        );
        assert!(
            verify(&missing)
                .findings
                .iter()
                .any(|finding| finding.code == "missing_pad")
        );

        let extra_net = BOARD.replacen("(net 1 \"SIG\")", "(net 1 \"SIG\") (net 2 \"UNUSED\")", 1);
        assert!(
            verify(&extra_net)
                .findings
                .iter()
                .any(|finding| finding.code == "extra_net")
        );
    }

    #[test]
    fn validates_duplicate_pads_and_mechanical_pad_exception() {
        let duplicate = BOARD.replace(
            "(pad \"2\" smd rect (at 1 0) (size 1 1) (layers \"F.Cu\"))",
            "(pad \"2\" smd rect (at 1 0) (size 1 1) (layers \"F.Cu\"))\n        (pad \"2\" smd rect (at 2 0) (size 1 1) (layers \"F.Cu\"))",
        );
        assert!(
            verify(&duplicate)
                .findings
                .iter()
                .any(|finding| finding.code == "duplicate_pad_number")
        );

        let mechanical = BOARD.replace(
            "(pad \"2\" smd rect (at 1 0) (size 1 1) (layers \"F.Cu\"))",
            "(pad \"2\" smd rect (at 1 0) (size 1 1) (layers \"F.Cu\"))\n        (pad \"\" np_thru_hole circle (at 2 0) (size 1 1) (drill 1) (layers \"*.Cu\" \"*.Mask\"))",
        );
        assert!(verify(&mechanical).approved);

        let unsupported = mechanical
            .replace("np_thru_hole circle", "smd circle")
            .replace("(drill 1) ", "");
        assert!(
            verify(&unsupported)
                .findings
                .iter()
                .any(|finding| finding.code == "unnumbered_pad_unsupported")
        );

        let connected = mechanical.replace(
            "(pad \"\" np_thru_hole circle (at 2 0) (size 1 1) (drill 1) (layers \"*.Cu\" \"*.Mask\"))",
            "(pad \"\" np_thru_hole circle (at 2 0) (size 1 1) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"SIG\"))",
        );
        assert!(
            verify(&connected)
                .findings
                .iter()
                .any(|finding| finding.code == "connected_unnumbered_pad")
        );

        let numbered_mechanical = BOARD.replacen(
            "(pad \"1\" smd rect (at 0 0) (size 1 1) (layers \"F.Cu\") (net 1 \"SIG\"))",
            "(pad \"1\" np_thru_hole rect (at 0 0) (size 1 1) (drill 0.5) (layers \"*.Cu\" \"*.Mask\") (net 1 \"SIG\"))",
            1,
        );
        assert!(
            verify(&numbered_mechanical)
                .findings
                .iter()
                .any(|finding| finding.code == "pad_type_mismatch")
        );
    }

    #[test]
    fn validates_binding_relevant_pad_structure_and_ranges() {
        let non_copper = BOARD.replacen("(layers \"F.Cu\")", "(layers \"F.SilkS\")", 1);
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &non_copper,
                &ElectricalPolicy::default(),
            )
            .unwrap_err()
            .contains("must include at least one copper layer")
        );

        let unknown_layer = BOARD.replacen("(layers \"F.Cu\")", "(layers \"bogus\")", 1);
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &unknown_layer,
                &ElectricalPolicy::default(),
            )
            .unwrap_err()
            .contains("unknown layer")
        );

        let duplicate_layer = BOARD.replacen("(layers \"F.Cu\")", "(layers \"F.Cu\" \"F.Cu\")", 1);
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &duplicate_layer,
                &ElectricalPolicy::default(),
            )
            .unwrap_err()
            .contains("duplicate layer")
        );

        let mut copper_names = vec!["F.Cu".to_string()];
        copper_names.extend((1..=30).map(|index| format!("In{index}.Cu")));
        copper_names.push("B.Cu".to_string());
        let layer_table = copper_names
            .iter()
            .enumerate()
            .map(|(ordinal, name)| format!("({ordinal} \"{name}\" signal)"))
            .collect::<Vec<_>>()
            .join(" ");
        let pad_layer_names = copper_names
            .iter()
            .map(|name| format!("\"{name}\""))
            .chain(["\"F.Mask\"".to_string(), "\"B.Mask\"".to_string()])
            .collect::<Vec<_>>()
            .join(" ");
        let maximum_copper_layers = BOARD
            .replacen(
                "(generator pcbex-test)",
                &format!("(generator pcbex-test) (layers {layer_table})"),
                1,
            )
            .replacen(
                "(layers \"F.Cu\")",
                &format!("(layers {pad_layer_names})"),
                1,
            );
        assert!(verify(&maximum_copper_layers).approved);

        let huge_size = BOARD.replacen("(size 1 1)", "(size 1e300 1)", 1);
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &huge_size,
                &ElectricalPolicy::default(),
            )
            .unwrap_err()
            .contains("outside the supported range")
        );

        let valid_oval_drill = BOARD.replacen(
            "smd rect (at 0 0) (size 1 1) (layers \"F.Cu\")",
            "thru_hole rect (at 0 0) (size 1 1) (drill oval 0.4 0.7 (offset 0.1 0)) (layers \"*.Cu\" \"*.Mask\")",
            1,
        );
        assert!(verify(&valid_oval_drill).approved);

        let malformed_drill = valid_oval_drill.replace(
            "(drill oval 0.4 0.7 (offset 0.1 0))",
            "(drill oval 0.4 (unknown 0.1 0))",
        );
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &malformed_drill,
                &ElectricalPolicy::default(),
            )
            .unwrap_err()
            .contains("unsupported child")
        );

        let valid_custom = BOARD.replacen(
            "smd rect (at 0 0) (size 1 1) (layers \"F.Cu\")",
            "smd custom (at 0 0) (size 1 1) (layers \"F.Cu\") (primitives (gr_poly (pts (xy -0.5 -0.5) (xy 0.5 -0.5) (xy 0 0.5))))",
            1,
        );
        assert!(verify(&valid_custom).approved);

        let malformed_custom = valid_custom.replace("gr_poly", "gr_fake");
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &malformed_custom,
                &ElectricalPolicy::default(),
            )
            .unwrap_err()
            .contains("unsupported custom pad primitive")
        );
    }

    #[test]
    fn detects_reference_metadata_and_reserved_net_mismatches() {
        let no_net_zero = BOARD.replace("(net 0 \"\") ", "");
        assert!(
            verify(&no_net_zero)
                .findings
                .iter()
                .any(|finding| finding.code == "missing_reserved_net_zero")
        );

        let wrong_reference =
            BOARD.replace("(fp_text reference \"R2\"", "(fp_text reference \"R3\"");
        let report = verify(&wrong_reference);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "missing_footprint")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "extra_footprint")
        );

        let duplicate_reference =
            BOARD.replace("(fp_text reference \"R2\"", "(fp_text reference \"R1\"");
        assert!(
            verify(&duplicate_reference)
                .findings
                .iter()
                .any(|finding| finding.code == "duplicate_footprint_reference")
        );

        let wrong_id = BOARD.replacen(
            "(footprint \"Package:R_0603\"",
            "(footprint \"Package:R_0805\"",
            1,
        );
        assert!(
            verify(&wrong_id)
                .findings
                .iter()
                .any(|finding| finding.code == "footprint_id_mismatch")
        );

        let wrong_value = BOARD.replacen("(fp_text value \"10k\"", "(fp_text value \"9k\"", 1);
        assert!(
            verify(&wrong_value)
                .findings
                .iter()
                .any(|finding| finding.code == "value_mismatch")
        );

        let extra_mpn = BOARD.replacen(
            "(fp_text value \"10k\" (at 0 1) (layer \"F.Fab\"))",
            "(fp_text value \"10k\" (at 0 1) (layer \"F.Fab\"))\n        (property \"pcbex:mpn\" \"MPN-1\")",
            1,
        );
        assert!(
            verify(&extra_mpn)
                .findings
                .iter()
                .any(|finding| finding.code == "mpn_mismatch")
        );

        let excluded = BOARD.replacen("(attr smd)", "(attr smd exclude_from_bom)", 1);
        assert!(
            verify(&excluded)
                .findings
                .iter()
                .any(|finding| finding.code == "assembly_metadata_mismatch")
        );
    }

    #[test]
    fn nested_handoff_rejection_remains_authoritative() {
        let schematic = SCHEMATIC.replacen(
            "(property \"Value\" \"10k\")",
            "(property \"Value\" \"9k\")",
            1,
        );
        let board = BOARD.replacen("(fp_text value \"10k\"", "(fp_text value \"9k\"", 1);
        let report = verify_circuit_kicad_board_binding(
            SPEC,
            &schematic,
            &board,
            &ElectricalPolicy::default(),
        )
        .unwrap();
        assert!(!report.circuit_kicad_handoff.approved);
        assert!(report.findings.is_empty());
        assert!(!report.approved);
        assert_eq!(
            report.counts.errors,
            report.circuit_kicad_handoff.counts.errors
        );
        assert!(report.counts.errors > 0);
    }

    #[test]
    fn electrical_digest_ignores_geometry_but_source_binding_does_not() {
        let moved = BOARD.replace("(at 20 10)", "(at 25 12)");
        let original = verify(BOARD);
        let moved = verify(&moved);
        assert_eq!(
            original.board_electrical_sha256,
            moved.board_electrical_sha256
        );
        assert_ne!(original.board_source_sha256, moved.board_source_sha256);
        assert_ne!(original.binding_sha256, moved.binding_sha256);

        let net_order_a = BOARD.replacen(
            "(net 1 \"SIG\")",
            "(net 1 \"SIG\") (net 2 \"Z_UNUSED\") (net 3 \"A_UNUSED\")",
            1,
        );
        let net_order_b = BOARD.replacen(
            "(net 1 \"SIG\")",
            "(net 1 \"SIG\") (net 2 \"A_UNUSED\") (net 3 \"Z_UNUSED\")",
            1,
        );
        assert_eq!(
            verify(&net_order_a).board_electrical_sha256,
            verify(&net_order_b).board_electrical_sha256
        );
    }

    #[test]
    fn malformed_and_oversized_boards_are_contract_errors() {
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                "not a board",
                &ElectricalPolicy::default(),
            )
            .is_err()
        );
        let long_name = "N".repeat(CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES + 1);
        let oversized_name = BOARD.replace("(net 1 \"SIG\")", &format!("(net 1 \"{long_name}\")"));
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &oversized_name,
                &ElectricalPolicy::default(),
            )
            .unwrap_err()
            .contains("net 1 name exceeds")
        );
        let spoofed_kind = BOARD.replacen("(pad \"1\" smd rect", "(pad \"1\" spoof rect", 1);
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &spoofed_kind,
                &ElectricalPolicy::default(),
            )
            .unwrap_err()
            .contains("type \"spoof\" is unsupported")
        );
        let missing_size = BOARD.replacen("(size 1 1)", "(clearance 0.1)", 1);
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &missing_size,
                &ElectricalPolicy::default(),
            )
            .unwrap_err()
            .contains("size is missing")
        );
        let oversized = " ".repeat(CIRCUIT_KICAD_BOARD_BINDING_MAX_BOARD_BYTES as usize + 1);
        assert!(
            verify_circuit_kicad_board_binding(
                SPEC,
                SCHEMATIC,
                &oversized,
                &ElectricalPolicy::default(),
            )
            .is_err()
        );
    }
}

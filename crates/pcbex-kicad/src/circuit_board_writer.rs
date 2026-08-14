//! Deterministic construction of a fresh, placed-but-unrouted KiCad board.
//!
//! The producer is deliberately a closed transformation.  It consumes exact
//! source bytes, an embedded footprint closure, and closed construction and
//! physical profiles.  It performs no library lookup, routing, DRC, DFM, or
//! fabrication inference.

use super::{
    BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS, BOARD_CONSTRUCTION_PROFILE_V1_MAX_SOURCE_BYTES,
    BoardConstructionProfileV1, BoardConstructionStackupLayerV1,
    CIRCUIT_KICAD_BOARD_BINDING_MAX_RENDERED_REPORT_BYTES,
    CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES, CIRCUIT_SPEC_V2_MAX_BYTES,
    CircuitKicadBoardBindingReport, CircuitPartV2, CircuitSpecV2, ElectricalPolicy,
    FOOTPRINT_CLOSURE_V1_MAX_SOURCE_BYTES, FootprintClosureEntryV1, FootprintClosureV1,
    ImportedBoard, Sexp, board_construction_copper_layers, board_construction_profile_v1_sha256,
    board_construction_routing_rules, circuit_spec_source_to_physical_v2,
    footprint_closure::FOOTPRINT_CLOSURE_V1_MAX_KICAD_VERSION, footprint_closure::digest_hex,
    footprint_closure::parse_footprint_root, footprint_closure::scalar,
    footprint_closure::validate_footprint_closure_layers, footprint_closure_v1_sha256, import,
    parse_board_construction_profile_v1, parse_footprint_closure_v1,
    render_circuit_kicad_board_binding_report, validate_footprint_closure_v1,
    verify_circuit_kicad_board_binding, verify_circuit_kicad_handoff,
};
use pcbex_core::{
    Keepout, Layer, PhysicalConstraintProfile, Point, ProfileKeepout, Rules,
    apply_physical_profile, apply_physical_profile_to_placement, parse_physical_profile,
    placement::{BoardSide, Component, PlacementOptions, PlacementResult, place},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

/// Stable numeric-net board date code accepted by KiCad 10 and pcbex routing.
pub const CIRCUIT_KICAD_BOARD_VERSION: u32 = FOOTPRINT_CLOSURE_V1_MAX_KICAD_VERSION;
pub const CIRCUIT_KICAD_BOARD_MANIFEST_V1_SCHEMA_VERSION: u32 = 1;
pub const CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES: usize = 128 * 1024 * 1024;
pub const CIRCUIT_KICAD_BOARD_MANIFEST_V1_MAX_RENDERED_BYTES: usize = 1024 * 1024;
pub const CIRCUIT_KICAD_BOARD_MAX_PHYSICAL_PROFILE_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
pub const CIRCUIT_KICAD_BOARD_PRODUCER_ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
const PHYSICAL_PROFILE_DIGEST_DOMAIN: &[u8] = b"pcbex-physical-profile-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitKicadBoardStateV1 {
    PlacedButUnrouted,
}

/// Closed evidence for one deterministic board-production result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitKicadBoardManifestV1 {
    pub schema_version: u32,
    pub engine_version: String,

    pub circuit_source_bytes: u64,
    pub circuit_source_sha256: String,
    pub circuit_spec_sha256: String,
    pub circuit_check_sha256: String,

    pub schematic_source_bytes: u64,
    pub schematic_source_sha256: String,
    pub schematic_sha256: String,
    pub policy_sha256: String,

    pub footprint_closure_source_bytes: u64,
    pub footprint_closure_source_sha256: String,
    pub footprint_closure_sha256: String,

    pub construction_profile_source_bytes: u64,
    pub construction_profile_source_sha256: String,
    pub construction_profile_sha256: String,

    pub physical_profile_source_bytes: u64,
    pub physical_profile_source_sha256: String,
    pub physical_profile_sha256: String,

    pub board_source_bytes: u64,
    pub board_source_sha256: String,
    pub board_binding_report_bytes: u64,
    pub board_binding_report_sha256: String,
    pub board_binding_sha256: String,

    pub placement_seed: u64,
    pub placement_iterations: u64,
    pub placement_result_sha256: String,
    pub component_count: usize,
    pub fixed_component_count: usize,

    pub board_state: CircuitKicadBoardStateV1,
    pub routing_performed: bool,
    pub drc_claimed: bool,
    pub dfm_claimed: bool,
    pub approved: bool,
}

/// In-process result.  Each retained text artifact ends in exactly one LF.
#[derive(Clone, Debug)]
pub struct CircuitKicadBoardProduction {
    pub board_source: String,
    pub board_binding_report: CircuitKicadBoardBindingReport,
    pub board_binding_report_json: String,
    pub manifest: CircuitKicadBoardManifestV1,
    pub manifest_json: String,
}

/// Produce a new KiCad 10 board from exact closed inputs.
///
/// The exact circuit and schematic sources are independently reparsed by the
/// handoff and final board-binding gates.  A rejected report is never returned
/// as a successful production result.
pub fn write_circuit_spec_kicad_board(
    circuit_source: &str,
    schematic_source: &str,
    footprint_closure_source: &str,
    construction_profile_source: &str,
    physical_profile_source: &str,
    policy: &ElectricalPolicy,
) -> Result<CircuitKicadBoardProduction, String> {
    let physical_spec = circuit_spec_source_to_physical_v2(circuit_source)?;
    let handoff = verify_circuit_kicad_handoff(circuit_source, schematic_source, policy)?;
    if !handoff.approved {
        return Err(format!(
            "circuit-to-KiCad schematic handoff is not approved ({} errors, {} warnings)",
            handoff.counts.errors, handoff.counts.warnings
        ));
    }

    let closure = parse_footprint_closure_v1(footprint_closure_source)?;
    validate_footprint_closure_v1(&closure, &physical_spec)?;
    let construction = parse_board_construction_profile_v1(construction_profile_source)?;
    let copper_layers = board_construction_copper_layers(&construction)?;
    validate_footprint_closure_layers(&closure, &copper_layers)?;
    let physical = parse_physical_profile(physical_profile_source)?;
    validate_profiles_for_production(&construction, &physical)?;

    let rules = board_construction_routing_rules(&construction)?;
    let initial_board = render_board(&physical_spec, &closure, &construction, &physical, None)?;
    let imported = import(&initial_board, rules.clone())?;
    validate_imported_construction(&imported, &construction, &rules)?;

    let mut problem = imported.placement_problem(construction.placement_defaults.grid_nm)?;
    problem.width_nm = physical.board_width_nm;
    problem.height_nm = physical.board_height_nm;
    for component in &mut problem.components {
        component.position = None;
        component.fixed = false;
        component.side = BoardSide::Front;
        component.allow_side_flip = false;
        component.courtyard.clear();
        let added = construction
            .placement_defaults
            .component_clearance_nm
            .checked_mul(2)
            .ok_or_else(|| "placement component clearance overflow".to_string())?;
        component.width_nm = component
            .width_nm
            .checked_add(added)
            .ok_or_else(|| format!("component {} width overflow", component.reference))?;
        component.height_nm = component
            .height_nm
            .checked_add(added)
            .ok_or_else(|| format!("component {} height overflow", component.reference))?;
    }
    apply_physical_profile_to_placement(&mut problem, &physical)?;

    let iterations = usize::try_from(construction.placement_defaults.iterations)
        .map_err(|_| "placement iteration count does not fit this platform".to_string())?;
    let placement_options = PlacementOptions {
        iterations,
        seed: construction.placement_defaults.seed,
        ..PlacementOptions::default()
    };
    let placement = place(&problem, &placement_options)?;
    validate_placement_result(&placement)?;
    let placements = placement
        .components
        .iter()
        .map(|component| (component.reference.as_str(), component))
        .collect::<BTreeMap<_, _>>();

    let board_source = render_board(
        &physical_spec,
        &closure,
        &construction,
        &physical,
        Some(&placements),
    )?;
    if board_source.len() > CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES {
        return Err(format!(
            "KiCad board output exceeds {CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES} bytes"
        ));
    }

    // Reimport the exact public board through the general board/routing model.
    let mut imported_placed = import(&board_source, rules.clone())?;
    validate_imported_construction(&imported_placed, &construction, &rules)?;
    validate_imported_physical(&mut imported_placed, &physical)?;
    if !imported_placed.board.routes.is_empty() {
        return Err("newly constructed board unexpectedly contains routed copper".into());
    }

    let board_binding_report = verify_circuit_kicad_board_binding(
        circuit_source,
        schematic_source,
        &board_source,
        policy,
    )?;
    if !board_binding_report.approved {
        return Err(format!(
            "generated circuit-to-KiCad board binding is not approved ({} errors, {} warnings)",
            board_binding_report.counts.errors, board_binding_report.counts.warnings
        ));
    }
    let report_bytes = render_circuit_kicad_board_binding_report(&board_binding_report)?;
    let board_binding_report_json = String::from_utf8(report_bytes.clone())
        .map_err(|_| "board-binding report renderer returned non-UTF-8 JSON".to_string())?;

    let placement_bytes = serde_json::to_vec(&placement)
        .map_err(|error| format!("unable to serialize placement result: {error}"))?;
    let physical_bytes = serde_json::to_vec(&physical)
        .map_err(|error| format!("unable to serialize physical profile: {error}"))?;
    let mut physical_identity = Vec::with_capacity(
        PHYSICAL_PROFILE_DIGEST_DOMAIN
            .len()
            .saturating_add(physical_bytes.len()),
    );
    physical_identity.extend_from_slice(PHYSICAL_PROFILE_DIGEST_DOMAIN);
    physical_identity.extend_from_slice(&physical_bytes);
    let placement_iterations = u64::try_from(placement.iterations)
        .map_err(|_| "placement result iteration count overflow".to_string())?;
    let manifest = CircuitKicadBoardManifestV1 {
        schema_version: CIRCUIT_KICAD_BOARD_MANIFEST_V1_SCHEMA_VERSION,
        engine_version: CIRCUIT_KICAD_BOARD_PRODUCER_ENGINE_VERSION.to_string(),
        circuit_source_bytes: circuit_source.len() as u64,
        circuit_source_sha256: digest_hex(circuit_source.as_bytes()),
        circuit_spec_sha256: handoff.circuit_spec_sha256.clone(),
        circuit_check_sha256: handoff.circuit_check_sha256.clone(),
        schematic_source_bytes: schematic_source.len() as u64,
        schematic_source_sha256: digest_hex(schematic_source.as_bytes()),
        schematic_sha256: handoff.schematic_sha256.clone(),
        policy_sha256: handoff.policy_sha256.clone(),
        footprint_closure_source_bytes: footprint_closure_source.len() as u64,
        footprint_closure_source_sha256: digest_hex(footprint_closure_source.as_bytes()),
        footprint_closure_sha256: footprint_closure_v1_sha256(&closure)?,
        construction_profile_source_bytes: construction_profile_source.len() as u64,
        construction_profile_source_sha256: digest_hex(construction_profile_source.as_bytes()),
        construction_profile_sha256: board_construction_profile_v1_sha256(&construction)?,
        physical_profile_source_bytes: physical_profile_source.len() as u64,
        physical_profile_source_sha256: digest_hex(physical_profile_source.as_bytes()),
        physical_profile_sha256: digest_hex(&physical_identity),
        board_source_bytes: board_source.len() as u64,
        board_source_sha256: digest_hex(board_source.as_bytes()),
        board_binding_report_bytes: report_bytes.len() as u64,
        board_binding_report_sha256: digest_hex(&report_bytes),
        board_binding_sha256: board_binding_report.binding_sha256.clone(),
        placement_seed: construction.placement_defaults.seed,
        placement_iterations,
        placement_result_sha256: digest_hex(&placement_bytes),
        component_count: placement.components.len(),
        fixed_component_count: placement
            .components
            .iter()
            .filter(|component| component.fixed)
            .count(),
        board_state: CircuitKicadBoardStateV1::PlacedButUnrouted,
        routing_performed: false,
        drc_claimed: false,
        dfm_claimed: false,
        approved: true,
    };
    let manifest_json = String::from_utf8(render_circuit_kicad_board_manifest_v1(&manifest)?)
        .map_err(|_| "board manifest renderer returned non-UTF-8 JSON".to_string())?;

    Ok(CircuitKicadBoardProduction {
        board_source,
        board_binding_report,
        board_binding_report_json,
        manifest,
        manifest_json,
    })
}

pub fn validate_circuit_kicad_board_manifest_v1(
    manifest: &CircuitKicadBoardManifestV1,
) -> Result<(), String> {
    if manifest.schema_version != CIRCUIT_KICAD_BOARD_MANIFEST_V1_SCHEMA_VERSION {
        return Err(format!(
            "unsupported circuit KiCad board manifest schema_version {}; expected {}",
            manifest.schema_version, CIRCUIT_KICAD_BOARD_MANIFEST_V1_SCHEMA_VERSION
        ));
    }
    if manifest.engine_version.trim().is_empty()
        || manifest.engine_version.len() > 128
        || manifest.engine_version.chars().any(char::is_control)
    {
        return Err("circuit KiCad board manifest engine_version is invalid".into());
    }
    for (bytes, maximum, label) in [
        (
            manifest.circuit_source_bytes,
            CIRCUIT_SPEC_V2_MAX_BYTES,
            "circuit_source_bytes",
        ),
        (
            manifest.schematic_source_bytes,
            CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES,
            "schematic_source_bytes",
        ),
        (
            manifest.footprint_closure_source_bytes,
            FOOTPRINT_CLOSURE_V1_MAX_SOURCE_BYTES,
            "footprint_closure_source_bytes",
        ),
        (
            manifest.construction_profile_source_bytes,
            BOARD_CONSTRUCTION_PROFILE_V1_MAX_SOURCE_BYTES,
            "construction_profile_source_bytes",
        ),
        (
            manifest.physical_profile_source_bytes,
            CIRCUIT_KICAD_BOARD_MAX_PHYSICAL_PROFILE_SOURCE_BYTES,
            "physical_profile_source_bytes",
        ),
        (
            manifest.board_source_bytes,
            CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES as u64,
            "board_source_bytes",
        ),
        (
            manifest.board_binding_report_bytes,
            CIRCUIT_KICAD_BOARD_BINDING_MAX_RENDERED_REPORT_BYTES as u64,
            "board_binding_report_bytes",
        ),
    ] {
        if bytes == 0 || bytes > maximum {
            return Err(format!(
                "circuit KiCad board manifest {label} must be between 1 and {maximum}"
            ));
        }
    }
    for (sha256, label) in [
        (&manifest.circuit_source_sha256, "circuit_source_sha256"),
        (&manifest.circuit_spec_sha256, "circuit_spec_sha256"),
        (&manifest.circuit_check_sha256, "circuit_check_sha256"),
        (&manifest.schematic_source_sha256, "schematic_source_sha256"),
        (&manifest.schematic_sha256, "schematic_sha256"),
        (&manifest.policy_sha256, "policy_sha256"),
        (
            &manifest.footprint_closure_source_sha256,
            "footprint_closure_source_sha256",
        ),
        (
            &manifest.footprint_closure_sha256,
            "footprint_closure_sha256",
        ),
        (
            &manifest.construction_profile_source_sha256,
            "construction_profile_source_sha256",
        ),
        (
            &manifest.construction_profile_sha256,
            "construction_profile_sha256",
        ),
        (
            &manifest.physical_profile_source_sha256,
            "physical_profile_source_sha256",
        ),
        (&manifest.physical_profile_sha256, "physical_profile_sha256"),
        (&manifest.board_source_sha256, "board_source_sha256"),
        (
            &manifest.board_binding_report_sha256,
            "board_binding_report_sha256",
        ),
        (&manifest.board_binding_sha256, "board_binding_sha256"),
        (&manifest.placement_result_sha256, "placement_result_sha256"),
    ] {
        validate_sha256(sha256, label)?;
    }
    if manifest.component_count == 0
        || manifest.component_count > 256
        || manifest.fixed_component_count > manifest.component_count
    {
        return Err("circuit KiCad board manifest component counts are invalid".into());
    }
    if manifest.placement_iterations > u64::from(BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS) {
        return Err(format!(
            "circuit KiCad board manifest placement_iterations exceeds {BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS}"
        ));
    }
    if manifest.board_state != CircuitKicadBoardStateV1::PlacedButUnrouted
        || manifest.routing_performed
        || manifest.drc_claimed
        || manifest.dfm_claimed
        || !manifest.approved
    {
        return Err(
            "circuit KiCad board manifest must describe an approved placed-but-unrouted result without routing/DRC/DFM claims"
                .into(),
        );
    }
    Ok(())
}

pub fn render_circuit_kicad_board_manifest_v1(
    manifest: &CircuitKicadBoardManifestV1,
) -> Result<Vec<u8>, String> {
    validate_circuit_kicad_board_manifest_v1(manifest)?;
    let mut rendered = serde_json::to_vec(manifest)
        .map_err(|error| format!("unable to serialize circuit KiCad board manifest: {error}"))?;
    rendered.push(b'\n');
    if rendered.len() > CIRCUIT_KICAD_BOARD_MANIFEST_V1_MAX_RENDERED_BYTES {
        return Err(format!(
            "circuit KiCad board manifest exceeds {CIRCUIT_KICAD_BOARD_MANIFEST_V1_MAX_RENDERED_BYTES} rendered bytes"
        ));
    }
    Ok(rendered)
}

pub fn circuit_kicad_board_manifest_v1_sha256(
    manifest: &CircuitKicadBoardManifestV1,
) -> Result<String, String> {
    Ok(digest_hex(&render_circuit_kicad_board_manifest_v1(
        manifest,
    )?))
}

pub fn circuit_kicad_board_manifest_v1_json_schema() -> Value {
    let sha = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pcbex.dev/schemas/circuit-kicad-board-manifest-v1.schema.json",
        "title": "pcbex circuit KiCad board production manifest v1",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "engine_version",
            "circuit_source_bytes", "circuit_source_sha256", "circuit_spec_sha256", "circuit_check_sha256",
            "schematic_source_bytes", "schematic_source_sha256", "schematic_sha256", "policy_sha256",
            "footprint_closure_source_bytes", "footprint_closure_source_sha256", "footprint_closure_sha256",
            "construction_profile_source_bytes", "construction_profile_source_sha256", "construction_profile_sha256",
            "physical_profile_source_bytes", "physical_profile_source_sha256", "physical_profile_sha256",
            "board_source_bytes", "board_source_sha256", "board_binding_report_bytes",
            "board_binding_report_sha256", "board_binding_sha256", "placement_seed",
            "placement_iterations", "placement_result_sha256", "component_count",
            "fixed_component_count", "board_state", "routing_performed", "drc_claimed",
            "dfm_claimed", "approved"
        ],
        "properties": {
            "schema_version": {"const": CIRCUIT_KICAD_BOARD_MANIFEST_V1_SCHEMA_VERSION},
            "engine_version": {"type": "string", "minLength": 1, "maxLength": 128},
            "circuit_source_bytes": {"type": "integer", "minimum": 1, "maximum": CIRCUIT_SPEC_V2_MAX_BYTES},
            "circuit_source_sha256": sha.clone(),
            "circuit_spec_sha256": sha.clone(),
            "circuit_check_sha256": sha.clone(),
            "schematic_source_bytes": {"type": "integer", "minimum": 1, "maximum": CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES},
            "schematic_source_sha256": sha.clone(),
            "schematic_sha256": sha.clone(),
            "policy_sha256": sha.clone(),
            "footprint_closure_source_bytes": {"type": "integer", "minimum": 1, "maximum": FOOTPRINT_CLOSURE_V1_MAX_SOURCE_BYTES},
            "footprint_closure_source_sha256": sha.clone(),
            "footprint_closure_sha256": sha.clone(),
            "construction_profile_source_bytes": {"type": "integer", "minimum": 1, "maximum": BOARD_CONSTRUCTION_PROFILE_V1_MAX_SOURCE_BYTES},
            "construction_profile_source_sha256": sha.clone(),
            "construction_profile_sha256": sha.clone(),
            "physical_profile_source_bytes": {"type": "integer", "minimum": 1, "maximum": CIRCUIT_KICAD_BOARD_MAX_PHYSICAL_PROFILE_SOURCE_BYTES},
            "physical_profile_source_sha256": sha.clone(),
            "physical_profile_sha256": sha.clone(),
            "board_source_bytes": {"type": "integer", "minimum": 1, "maximum": CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES},
            "board_source_sha256": sha.clone(),
            "board_binding_report_bytes": {"type": "integer", "minimum": 1, "maximum": CIRCUIT_KICAD_BOARD_BINDING_MAX_RENDERED_REPORT_BYTES},
            "board_binding_report_sha256": sha.clone(),
            "board_binding_sha256": sha.clone(),
            "placement_seed": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
            "placement_iterations": {"type": "integer", "minimum": 0, "maximum": BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS},
            "placement_result_sha256": sha,
            "component_count": {"type": "integer", "minimum": 1, "maximum": 256},
            "fixed_component_count": {"type": "integer", "minimum": 0, "maximum": 256},
            "board_state": {"const": "placed_but_unrouted"},
            "routing_performed": {"const": false},
            "drc_claimed": {"const": false},
            "dfm_claimed": {"const": false},
            "approved": {"const": true}
        }
    })
}

fn validate_profiles_for_production(
    construction: &BoardConstructionProfileV1,
    physical: &PhysicalConstraintProfile,
) -> Result<(), String> {
    if !physical.outline.is_empty() && !is_full_board_rectangle(physical) {
        return Err(
            "board producer v1 supports only an empty outline or a four-corner full-board rectangular physical outline"
                .into(),
        );
    }
    if let Some(keepout) = physical
        .keepouts
        .iter()
        .find(|keepout| keepout.footprints_not_allowed)
    {
        return Err(format!(
            "board producer v1 cannot safely place against footprint-forbidden keepout {}",
            keepout.id
        ));
    }
    if let Some(component) = physical
        .fixed_components
        .iter()
        .find(|component| component.keepout_width_nm != 0 || component.keepout_height_nm != 0)
    {
        return Err(format!(
            "board producer v1 cannot render the fixed-component keepout dimensions for {}",
            component.reference
        ));
    }
    if let Some(keepout) = physical.keepouts.iter().find(|keepout| {
        keepout.minimum_track_width_nm.is_some() || keepout.minimum_clearance_nm.is_some()
    }) {
        return Err(format!(
            "board producer v1 cannot render per-keepout routing minima for {}",
            keepout.id
        ));
    }
    let copper = board_construction_copper_layers(construction)?;
    for keepout in &physical.keepouts {
        if let Some(layer) = keepout.layers.iter().find(|layer| !copper.contains(layer)) {
            return Err(format!(
                "physical keepout {} references undeclared construction layer {}",
                keepout.id,
                layer.name()
            ));
        }
    }
    if let Some(manufacturing) = &physical.manufacturing_rules {
        if manufacturing.board_thickness_nm != construction.board_thickness_nm {
            return Err(format!(
                "construction board_thickness_nm {} does not match physical manufacturing board_thickness_nm {}",
                construction.board_thickness_nm, manufacturing.board_thickness_nm
            ));
        }
        let routing = &construction.routing_defaults;
        if routing.track_width_nm < manufacturing.minimum_track_width_nm {
            return Err(
                "construction track width is below the physical manufacturing minimum".into(),
            );
        }
        if routing.clearance_nm < manufacturing.minimum_clearance_nm {
            return Err(
                "construction clearance is below the physical manufacturing minimum".into(),
            );
        }
        if routing.via_drill_nm < manufacturing.minimum_drill_nm {
            return Err(
                "construction via drill is below the physical manufacturing minimum".into(),
            );
        }
        let annular = routing
            .via_diameter_nm
            .checked_sub(routing.via_drill_nm)
            .and_then(|difference| difference.checked_div(2))
            .ok_or_else(|| "construction via annular-ring calculation failed".to_string())?;
        if annular < manufacturing.minimum_annular_ring_nm {
            return Err(
                "construction via annular ring is below the physical manufacturing minimum".into(),
            );
        }
        let permitted_thickness = routing
            .via_drill_nm
            .checked_mul(i64::from(manufacturing.maximum_via_aspect_ratio))
            .ok_or_else(|| "construction via aspect-ratio calculation overflow".to_string())?;
        if construction.board_thickness_nm > permitted_thickness {
            return Err(
                "construction via drill violates the physical maximum via aspect ratio".into(),
            );
        }
    }
    Ok(())
}

fn is_full_board_rectangle(profile: &PhysicalConstraintProfile) -> bool {
    if profile.outline.len() != 4 {
        return false;
    }
    let expected = HashSet::from([
        Point { x_nm: 0, y_nm: 0 },
        Point {
            x_nm: profile.board_width_nm,
            y_nm: 0,
        },
        Point {
            x_nm: profile.board_width_nm,
            y_nm: profile.board_height_nm,
        },
        Point {
            x_nm: 0,
            y_nm: profile.board_height_nm,
        },
    ]);
    profile.outline.iter().copied().collect::<HashSet<_>>() == expected
}

fn validate_placement_result(result: &PlacementResult) -> Result<(), String> {
    if result
        .components
        .iter()
        .any(|component| component.position.is_none())
    {
        return Err("placement engine returned an unplaced component".into());
    }
    if result.final_score.overlap != 0.0
        || result.final_score.boundary != 0.0
        || result.final_score.constraint_violation != 0.0
    {
        return Err(format!(
            "placement is not legal: overlap={}, boundary={}, constraint_violation={}",
            result.final_score.overlap,
            result.final_score.boundary,
            result.final_score.constraint_violation
        ));
    }
    Ok(())
}

fn validate_imported_construction(
    imported: &ImportedBoard,
    construction: &BoardConstructionProfileV1,
    rules: &Rules,
) -> Result<(), String> {
    if imported.board.rules != *rules {
        return Err("reimported board did not retain construction routing defaults".into());
    }
    let expected_copper = board_construction_copper_layers(construction)?;
    if imported.board.copper_layers != expected_copper {
        return Err(
            "reimported board copper layer inventory does not match construction stackup".into(),
        );
    }
    if imported.board.stackup.len() != expected_copper.len() {
        return Err(
            "reimported board stackup does not cover every construction copper layer".into(),
        );
    }
    for entry in &construction.stackup {
        let BoardConstructionStackupLayerV1::Copper {
            layer,
            thickness_nm,
        } = entry
        else {
            continue;
        };
        let imported_entry = imported
            .board
            .stackup
            .iter()
            .find(|entry| entry.layer == *layer)
            .ok_or_else(|| format!("reimported board stackup is missing {}", layer.name()))?;
        if imported_entry.copper_thickness_nm != *thickness_nm {
            return Err(format!(
                "reimported board stackup {} copper thickness does not match construction profile",
                layer.name()
            ));
        }
        let stackup_index = construction
            .stackup
            .iter()
            .position(|candidate| {
                matches!(candidate, BoardConstructionStackupLayerV1::Copper { layer: candidate, .. } if candidate == layer)
            })
            .expect("validated construction contains each copper layer once");
        let expected = expected_adjacent_dielectrics(construction, stackup_index)?;
        let Some((height, dielectric_constant, reference_layer)) = expected.first().copied() else {
            return Err(format!(
                "construction stackup {} lacks adjacent dielectric data",
                layer.name()
            ));
        };
        let secondary = expected
            .iter()
            .copied()
            .find(|candidate| candidate.2 != reference_layer);
        if imported_entry.dielectric_height_nm != height
            || imported_entry.dielectric_constant != dielectric_constant
            || imported_entry.reference_layer != Some(reference_layer)
            || imported_entry.secondary_dielectric_height_nm
                != secondary.map(|candidate| candidate.0)
            || imported_entry.secondary_dielectric_constant
                != secondary.map(|candidate| candidate.1)
            || imported_entry.secondary_reference_layer != secondary.map(|candidate| candidate.2)
        {
            return Err(format!(
                "reimported board stackup {} dielectric thickness, epsilon, or reference layer does not match construction profile",
                layer.name()
            ));
        }
    }
    Ok(())
}

fn expected_adjacent_dielectrics(
    construction: &BoardConstructionProfileV1,
    copper_index: usize,
) -> Result<Vec<(i64, f64, Layer)>, String> {
    let mut expected = Vec::with_capacity(2);
    for direction in [-1_isize, 1] {
        let dielectric_index = copper_index as isize + direction;
        let reference_index = copper_index as isize + direction * 2;
        if dielectric_index < 0 || reference_index < 0 {
            continue;
        }
        let Some(BoardConstructionStackupLayerV1::Dielectric {
            thickness_nm,
            dielectric_constant_millionths,
            ..
        }) = construction.stackup.get(dielectric_index as usize)
        else {
            continue;
        };
        let Some(BoardConstructionStackupLayerV1::Copper {
            layer: reference_layer,
            ..
        }) = construction.stackup.get(reference_index as usize)
        else {
            continue;
        };
        let dielectric_constant = millionths(*dielectric_constant_millionths)
            .parse::<f64>()
            .map_err(|_| "unable to represent construction dielectric constant".to_string())?;
        expected.push((*thickness_nm, dielectric_constant, *reference_layer));
    }
    expected.sort_by_key(|candidate| candidate.0);
    Ok(expected)
}

fn validate_imported_physical(
    imported: &mut ImportedBoard,
    physical: &PhysicalConstraintProfile,
) -> Result<(), String> {
    if imported.board.width_nm != physical.board_width_nm
        || imported.board.height_nm != physical.board_height_nm
    {
        return Err(format!(
            "reimported board dimensions {}x{} nm do not match physical profile {}x{} nm",
            imported.board.width_nm,
            imported.board.height_nm,
            physical.board_width_nm,
            physical.board_height_nm
        ));
    }

    let expected_outline = HashSet::from([
        Point { x_nm: 0, y_nm: 0 },
        Point {
            x_nm: physical.board_width_nm,
            y_nm: 0,
        },
        Point {
            x_nm: physical.board_width_nm,
            y_nm: physical.board_height_nm,
        },
        Point {
            x_nm: 0,
            y_nm: physical.board_height_nm,
        },
    ]);
    if imported.board.outline.len() != expected_outline.len()
        || imported
            .board
            .outline
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            != expected_outline
    {
        return Err("reimported board outline does not match the rendered physical outline".into());
    }
    if !imported.board.cutouts.is_empty() {
        return Err("reimported board unexpectedly contains physical cutouts".into());
    }

    let expected_fixed = physical
        .fixed_components
        .iter()
        .map(|component| component.reference.as_str())
        .collect::<HashSet<_>>();
    let placement = imported.placement_problem(1)?;
    let actual_fixed = placement
        .components
        .iter()
        .filter(|component| component.fixed)
        .map(|component| component.reference.as_str())
        .collect::<HashSet<_>>();
    if actual_fixed != expected_fixed {
        return Err(
            "reimported board fixed-component set does not match the physical profile".into(),
        );
    }
    for expected in &physical.fixed_components {
        let footprint = imported
            .board
            .footprints
            .iter()
            .find(|footprint| footprint.reference == expected.reference)
            .ok_or_else(|| {
                format!(
                    "reimported board is missing fixed component {}",
                    expected.reference
                )
            })?;
        let expected_rotation = (expected.rotation_mdeg.rem_euclid(360_000) / 1000) as f64;
        if footprint.position
            != (Point {
                x_nm: expected.x_nm,
                y_nm: expected.y_nm,
            })
            || footprint.rotation_deg != expected_rotation
        {
            return Err(format!(
                "reimported board fixed component {} does not match the physical position and rotation",
                expected.reference
            ));
        }
    }

    let mut expected_keepouts = physical
        .keepouts
        .iter()
        .map(profile_keepout_identity)
        .collect::<Vec<_>>();
    expected_keepouts.sort();
    let mut actual_keepouts = imported
        .board
        .keepouts
        .iter()
        .map(imported_keepout_identity)
        .collect::<Vec<_>>();
    actual_keepouts.sort();
    if actual_keepouts != expected_keepouts {
        return Err("reimported board keepout set does not match the physical profile".into());
    }

    // Geometry has already been compared without mutation.  Apply only the
    // manufacturing portion so the existing non-relaxation checks still run
    // without duplicating or replacing public outline/keepout evidence.
    if physical.manufacturing_rules.is_some() {
        let mut manufacturing_only = physical.clone();
        manufacturing_only.outline.clear();
        manufacturing_only.fixed_components.clear();
        manufacturing_only.keepouts.clear();
        apply_physical_profile(&mut imported.board, &manufacturing_only)?;
    }
    Ok(())
}

type KeepoutIdentity = (
    Vec<(i64, i64)>,
    Vec<u8>,
    Option<u32>,
    bool,
    bool,
    bool,
    bool,
    Option<i64>,
    Option<i64>,
);

fn profile_keepout_identity(keepout: &ProfileKeepout) -> KeepoutIdentity {
    let mut layers = keepout
        .layers
        .iter()
        .map(|layer| layer.index())
        .collect::<Vec<_>>();
    layers.sort_unstable();
    (
        keepout
            .polygon
            .iter()
            .map(|point| (point.x_nm, point.y_nm))
            .collect(),
        layers,
        None,
        keepout.tracks_not_allowed,
        keepout.vias_not_allowed,
        keepout.zones_not_allowed,
        keepout.footprints_not_allowed,
        keepout.minimum_track_width_nm,
        keepout.minimum_clearance_nm,
    )
}

fn imported_keepout_identity(keepout: &Keepout) -> KeepoutIdentity {
    let mut layers = keepout
        .layers
        .iter()
        .map(|layer| layer.index())
        .collect::<Vec<_>>();
    layers.sort_unstable();
    (
        keepout
            .polygon
            .iter()
            .map(|point| (point.x_nm, point.y_nm))
            .collect(),
        layers,
        keepout.net_id,
        keepout.tracks_not_allowed,
        keepout.vias_not_allowed,
        keepout.zones_not_allowed,
        keepout.footprints_not_allowed,
        keepout.minimum_track_width_nm,
        keepout.minimum_clearance_nm,
    )
}

fn render_board(
    spec: &CircuitSpecV2,
    closure: &FootprintClosureV1,
    construction: &BoardConstructionProfileV1,
    physical: &PhysicalConstraintProfile,
    placements: Option<&BTreeMap<&str, &Component>>,
) -> Result<String, String> {
    let mut writer = LimitedWriter::new(CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES);
    writer.push("(kicad_pcb\n")?;
    writer.push(&format!("  (version {CIRCUIT_KICAD_BOARD_VERSION})\n"))?;
    writer.push("  (generator pcbex)\n")?;
    writer.push(&format!(
        "  (generator_version {})\n",
        quote(CIRCUIT_KICAD_BOARD_PRODUCER_ENGINE_VERSION)
    ))?;
    writer.push(&format!(
        "  (general (thickness {}))\n",
        mm(construction.board_thickness_nm)
    ))?;
    write_layer_table(&mut writer, construction)?;
    write_setup(&mut writer, construction)?;

    let net_ids = spec
        .nets
        .iter()
        .enumerate()
        .map(|(index, net)| {
            let id = u32::try_from(index + 1)
                .map_err(|_| "generated board net ID overflow".to_string())?;
            Ok((net.name.as_str(), id))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    writer.push("  (net 0 \"\")\n")?;
    for net in &spec.nets {
        writer.push(&format!(
            "  (net {} {})\n",
            net_ids[net.name.as_str()],
            quote(&net.name)
        ))?;
    }
    write_legacy_net_class(&mut writer, spec, construction)?;

    let closure_by_id = closure
        .footprints
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let fixed = physical
        .fixed_components
        .iter()
        .map(|component| component.reference.as_str())
        .collect::<HashSet<_>>();
    for part in &spec.parts {
        let entry = closure_by_id
            .get(part.footprint.as_str())
            .copied()
            .ok_or_else(|| format!("missing footprint closure entry {}", part.footprint))?;
        let (position, rotation, side) = match placements {
            Some(placements) => {
                let component = placements
                    .get(part.reference.as_str())
                    .ok_or_else(|| format!("placement is missing component {}", part.reference))?;
                let position = component.position.ok_or_else(|| {
                    format!("placement component {} has no position", part.reference)
                })?;
                (position, component.rotation_deg, component.side)
            }
            None => (
                Point {
                    x_nm: physical.board_width_nm / 2,
                    y_nm: physical.board_height_nm / 2,
                },
                0,
                BoardSide::Front,
            ),
        };
        write_footprint(
            &mut writer,
            part,
            entry,
            position,
            rotation,
            side,
            fixed.contains(part.reference.as_str()),
            &net_ids,
        )?;
    }
    write_keepouts(&mut writer, physical)?;
    write_outline(&mut writer, physical)?;
    writer.push(")\n")?;
    writer.finish()
}

fn write_layer_table(
    writer: &mut LimitedWriter,
    construction: &BoardConstructionProfileV1,
) -> Result<(), String> {
    writer.push("  (layers\n")?;
    let copper_layers = board_construction_copper_layers(construction)?;
    for layer in &copper_layers {
        writer.push(&format!(
            "    ({} {} signal)\n",
            legacy_kicad_copper_layer_ordinal(*layer, copper_layers.len())?,
            quote(&layer.name())
        ))?;
    }
    for (ordinal, name, alias) in [
        (34, "B.Paste", Some("b.paste")),
        (35, "F.Paste", Some("f.paste")),
        (36, "B.SilkS", Some("b.silkscreen")),
        (37, "F.SilkS", Some("f.silkscreen")),
        (38, "B.Mask", Some("b.mask")),
        (39, "F.Mask", Some("f.mask")),
        (44, "Edge.Cuts", None),
        (46, "B.CrtYd", None),
        (47, "F.CrtYd", None),
        (48, "B.Fab", None),
        (49, "F.Fab", None),
    ] {
        match alias {
            Some(alias) => writer.push(&format!(
                "    ({ordinal} {} user {})\n",
                quote(name),
                quote(alias)
            ))?,
            None => writer.push(&format!("    ({ordinal} {} user)\n", quote(name)))?,
        }
    }
    writer.push("  )\n")
}

/// Return the layer-table ordinal used by the numeric v20250114 dialect.
///
/// KiCad leaves gaps between inner-layer ordinals on boards with at most 16
/// copper layers so additional layers can be inserted without renumbering.
/// Boards with more copper layers must use the complete legacy 0..31 copper
/// range to keep every layer ordinal unique.
fn legacy_kicad_copper_layer_ordinal(layer: Layer, copper_count: usize) -> Result<u8, String> {
    match layer {
        Layer::Front => Ok(0),
        Layer::Back => Ok(31),
        Layer::Inner(index) if copper_count <= 16 => index
            .checked_mul(2)
            .ok_or_else(|| format!("KiCad copper layer ordinal overflow for {}", layer.name())),
        Layer::Inner(index) => Ok(index),
    }
}

fn write_setup(
    writer: &mut LimitedWriter,
    construction: &BoardConstructionProfileV1,
) -> Result<(), String> {
    writer.push("  (setup\n")?;
    writer.push("    (pad_to_mask_clearance 0)\n")?;
    writer.push("    (stackup\n")?;
    let mut dielectric_index = 0usize;
    for entry in &construction.stackup {
        match entry {
            BoardConstructionStackupLayerV1::Copper {
                layer,
                thickness_nm,
            } => writer.push(&format!(
                "      (layer {} (type \"copper\") (thickness {}))\n",
                quote(&layer.name()),
                mm(*thickness_nm)
            ))?,
            BoardConstructionStackupLayerV1::Dielectric {
                material,
                thickness_nm,
                dielectric_constant_millionths,
            } => {
                dielectric_index += 1;
                writer.push(&format!(
                    "      (layer {} (type \"core\") (thickness {}) (material {}) (epsilon_r {}))\n",
                    quote(&format!("dielectric {dielectric_index}")),
                    mm(*thickness_nm),
                    quote(material),
                    millionths(*dielectric_constant_millionths)
                ))?;
            }
        }
    }
    writer.push("      (copper_finish \"None\")\n")?;
    writer.push("      (dielectric_constraints yes)\n")?;
    writer.push("    )\n")?;
    writer.push("  )\n")
}

/// Emit routing defaults in the legacy top-level location accepted by the
/// v20250114 board dialect.  A `net_class` nested in `setup` is not valid
/// KiCad syntax.
fn write_legacy_net_class(
    writer: &mut LimitedWriter,
    spec: &CircuitSpecV2,
    construction: &BoardConstructionProfileV1,
) -> Result<(), String> {
    let defaults = &construction.routing_defaults;
    writer.push(&format!(
        "  (net_class \"Default\" \"pcbex construction defaults\" (clearance {}) (trace_width {}) (via_dia {}) (via_drill {})",
        mm(defaults.clearance_nm),
        mm(defaults.track_width_nm),
        mm(defaults.via_diameter_nm),
        mm(defaults.via_drill_nm)
    ))?;
    for net in &spec.nets {
        writer.push(&format!(" (add_net {})", quote(&net.name)))?;
    }
    writer.push(")\n")
}

#[allow(clippy::too_many_arguments)]
fn write_footprint(
    writer: &mut LimitedWriter,
    part: &CircuitPartV2,
    entry: &FootprintClosureEntryV1,
    position: Point,
    rotation: u16,
    side: BoardSide,
    fixed: bool,
    net_ids: &BTreeMap<&str, u32>,
) -> Result<(), String> {
    if side != BoardSide::Front {
        return Err(format!(
            "board producer v1 does not permit a generated back-side placement for {}",
            part.reference
        ));
    }
    let root = parse_footprint_root(entry)?;
    let values = root.as_list().expect("validated footprint root is a list");
    writer.push(&format!("  (footprint {}\n", quote(&part.footprint)))?;
    writer.push("    (layer \"F.Cu\")\n")?;
    writer.push(&format!(
        "    (at {} {} {rotation})\n",
        mm(position.x_nm),
        mm(position.y_nm)
    ))?;
    if fixed {
        writer.push("    locked\n")?;
    }
    write_generated_text(writer, "reference", &part.reference, -1_500_000, false)?;
    write_generated_text(writer, "value", &part.value, 1_500_000, true)?;
    if let Some(mpn) = &part.mpn {
        writer.push(&format!(
            "    (property \"MPN\" {} (at 0 0 0) (layer \"F.Fab\") hide (effects (font (size 1 1) (thickness 0.15))))\n",
            quote(mpn)
        ))?;
    }
    let attr = footprint_mount_attribute(values);
    if let Some(attr) = attr {
        writer.push(&format!("    (attr {attr})\n"))?;
    }
    for child in values.iter().skip(2) {
        if skip_root_child(child) {
            continue;
        }
        let Some(child_values) = child.as_list() else {
            continue;
        };
        if unquoted_atom(child_values.first()) == Some("pad") {
            write_pad(writer, child_values, part, net_ids)?;
        } else {
            writer.push("    ")?;
            write_sanitized_sexp(writer, child, 0)?;
            writer.push("\n")?;
        }
    }
    writer.push("  )\n")
}

fn write_generated_text(
    writer: &mut LimitedWriter,
    kind: &str,
    value: &str,
    y_nm: i64,
    hide: bool,
) -> Result<(), String> {
    writer.push(&format!(
        "    (fp_text {kind} {} (at 0 {}) (layer \"F.Fab\")",
        quote(value),
        mm(y_nm)
    ))?;
    if hide {
        writer.push(" hide")?;
    }
    writer.push(" (effects (font (size 1 1) (thickness 0.15))))\n")
}

fn footprint_mount_attribute(values: &[Sexp]) -> Option<&'static str> {
    let mut has_smd = false;
    let mut has_through_hole = false;
    for child in values {
        let Some(pad) = child.as_list() else {
            continue;
        };
        if unquoted_atom(pad.first()) != Some("pad") {
            continue;
        }
        match unquoted_atom(pad.get(2)) {
            Some("smd") => has_smd = true,
            Some("thru_hole") => has_through_hole = true,
            _ => {}
        }
    }
    match (has_smd, has_through_hole) {
        (true, false) => Some("smd"),
        (false, true) => Some("through_hole"),
        _ => None,
    }
}

fn skip_root_child(value: &Sexp) -> bool {
    if matches!(value, Sexp::Atom(value) | Sexp::QuotedAtom(value) if matches!(value.as_str(), "locked" | "placed"))
    {
        return true;
    }
    let Some(values) = value.as_list() else {
        return false;
    };
    let keyword = scalar(values.first()).unwrap_or("");
    if matches!(
        keyword,
        "version"
            | "generator"
            | "generator_version"
            | "layer"
            | "at"
            | "property"
            | "model"
            | "uuid"
            | "tstamp"
            | "path"
            | "sheetfile"
            | "sheetname"
            | "attr"
            | "descr"
            | "tags"
            | "fp_text"
            | "fp_text_box"
            | "fp_line"
            | "fp_rect"
            | "fp_circle"
            | "fp_arc"
            | "fp_poly"
            | "fp_curve"
            | "zone"
            | "group"
    ) {
        return true;
    }
    keyword == "fp_text"
        && matches!(
            scalar(values.get(1))
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("reference" | "value")
        )
}

fn write_pad(
    writer: &mut LimitedWriter,
    pad: &[Sexp],
    part: &CircuitPartV2,
    net_ids: &BTreeMap<&str, u32>,
) -> Result<(), String> {
    let number = scalar(pad.get(1)).ok_or_else(|| {
        format!(
            "footprint {} contains a non-scalar pad number",
            part.reference
        )
    })?;
    writer.push("    (")?;
    for (index, value) in pad.iter().enumerate() {
        if index > 0 {
            writer.push(" ")?;
        }
        write_sanitized_sexp(writer, value, 0)?;
    }
    if !number.is_empty() {
        let pin = part
            .pins
            .iter()
            .find(|pin| pin.number == number)
            .expect("footprint closure pad inventory was checked");
        if let Some(net) = pin.net.as_deref() {
            writer.push(&format!(" (net {} {})", net_ids[net], quote(net)))?;
        }
    }
    writer.push(")\n")
}

fn write_sanitized_sexp(
    writer: &mut LimitedWriter,
    value: &Sexp,
    depth: usize,
) -> Result<(), String> {
    if depth > 128 {
        return Err("footprint s-expression exceeds writer nesting limit".into());
    }
    match value {
        Sexp::Atom(value) => writer.push(value),
        Sexp::QuotedAtom(value) => writer.push(&quote(value)),
        Sexp::List(values) => {
            let keyword = scalar(values.first()).unwrap_or("");
            if matches!(
                keyword,
                "net"
                    | "net_name"
                    | "net_tie_pad_groups"
                    | "property"
                    | "model"
                    | "uuid"
                    | "tstamp"
            ) {
                return Ok(());
            }
            writer.push("(")?;
            let mut wrote = false;
            for value in values {
                if let Some(child) = value.as_list()
                    && matches!(
                        scalar(child.first()).unwrap_or(""),
                        "net"
                            | "net_name"
                            | "net_tie_pad_groups"
                            | "property"
                            | "model"
                            | "uuid"
                            | "tstamp"
                    )
                {
                    continue;
                }
                if wrote {
                    writer.push(" ")?;
                }
                write_sanitized_sexp(writer, value, depth + 1)?;
                wrote = true;
            }
            writer.push(")")
        }
    }
}

fn write_keepouts(
    writer: &mut LimitedWriter,
    physical: &PhysicalConstraintProfile,
) -> Result<(), String> {
    let mut keepouts = physical.keepouts.iter().collect::<Vec<_>>();
    keepouts.sort_by(|left, right| left.id.cmp(&right.id));
    for keepout in keepouts {
        writer.push("  (zone\n")?;
        writer.push("    (layers")?;
        let mut layers = keepout.layers.clone();
        layers.sort_by_key(|layer| layer.index());
        for layer in layers {
            writer.push(&format!(" {}", quote(&layer.name())))?;
        }
        writer.push(")\n")?;
        writer.push("    (hatch edge 0.5)\n")?;
        writer.push(&format!(
            "    (keepout (tracks {}) (vias {}) (pads allowed) (copperpour {}) (footprints {}))\n",
            allowed_token(keepout.tracks_not_allowed),
            allowed_token(keepout.vias_not_allowed),
            allowed_token(keepout.zones_not_allowed),
            allowed_token(keepout.footprints_not_allowed)
        ))?;
        writer.push("    (polygon (pts")?;
        for point in &keepout.polygon {
            writer.push(&format!(" (xy {} {})", mm(point.x_nm), mm(point.y_nm)))?;
        }
        writer.push("))\n")?;
        writer.push("  )\n")?;
    }
    Ok(())
}

fn write_outline(
    writer: &mut LimitedWriter,
    physical: &PhysicalConstraintProfile,
) -> Result<(), String> {
    writer.push(&format!(
        "  (gr_rect (start 0 0) (end {} {}) (stroke (width 0.05) (type default)) (fill none) (layer \"Edge.Cuts\"))\n",
        mm(physical.board_width_nm),
        mm(physical.board_height_nm)
    ))
}

fn allowed_token(prohibited: bool) -> &'static str {
    if prohibited { "not_allowed" } else { "allowed" }
}

fn mm(nanometres: i64) -> String {
    let negative = nanometres < 0;
    let magnitude = i128::from(nanometres).abs();
    let whole = magnitude / 1_000_000;
    let fraction = magnitude % 1_000_000;
    if fraction == 0 {
        format!("{}{whole}", if negative { "-" } else { "" })
    } else {
        let mut fraction = format!("{fraction:06}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        format!("{}{whole}.{fraction}", if negative { "-" } else { "" })
    }
}

fn millionths(value: u32) -> String {
    let whole = value / 1_000_000;
    let fraction = value % 1_000_000;
    if fraction == 0 {
        whole.to_string()
    } else {
        let mut fraction = format!("{fraction:06}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        format!("{whole}.{fraction}")
    }
}

fn quote(value: &str) -> String {
    let mut output = String::with_capacity(value.len().saturating_add(2));
    output.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            output.push('\\');
        }
        output.push(character);
    }
    output.push('"');
    output
}

fn unquoted_atom(value: Option<&Sexp>) -> Option<&str> {
    match value? {
        Sexp::Atom(value) => Some(value),
        Sexp::QuotedAtom(_) | Sexp::List(_) => None,
    }
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be 64 lower-case hex characters"));
    }
    Ok(())
}

struct LimitedWriter {
    output: String,
    limit: usize,
}

impl LimitedWriter {
    fn new(limit: usize) -> Self {
        Self {
            output: String::new(),
            limit,
        }
    }

    fn push(&mut self, value: &str) -> Result<(), String> {
        let length = self
            .output
            .len()
            .checked_add(value.len())
            .ok_or_else(|| "KiCad board output length overflow".to_string())?;
        if length > self.limit {
            return Err(format!("KiCad board output exceeds {} bytes", self.limit));
        }
        self.output
            .try_reserve(value.len())
            .map_err(|_| "unable to allocate bounded KiCad board output".to_string())?;
        self.output.push_str(value);
        Ok(())
    }

    fn finish(self) -> Result<String, String> {
        if !self.output.ends_with("\n") {
            return Err("KiCad board output must end in one LF".into());
        }
        Ok(self.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BoardPlacementDefaultsV1, BoardRoutingDefaultsV1, CircuitConnectionV2, CircuitNetV2,
        CircuitPinV2, CircuitPowerV2, ElectricalPinType, FootprintClosureEntryV1,
        circuit_spec_v2_to_kicad_sch,
    };
    use pcbex_core::{FixedComponent, Layer, ManufacturingRules, ProfileKeepout};

    fn spec() -> CircuitSpecV2 {
        CircuitSpecV2 {
            schema_version: 2,
            parts: vec![
                CircuitPartV2 {
                    reference: "U1".into(),
                    lib_id: "MCU:Chip".into(),
                    value: "Chip".into(),
                    footprint: "Package:QFN".into(),
                    mpn: Some("CHIP-1".into()),
                    power: power(),
                    pins: vec![
                        pin("1", "OUT", "SIGNAL", ElectricalPinType::Output),
                        pin("2", "VCC", "VCC", ElectricalPinType::Passive),
                    ],
                },
                CircuitPartV2 {
                    reference: "R1".into(),
                    lib_id: "Device:R".into(),
                    value: "10k".into(),
                    footprint: "Resistor_SMD:R_0603".into(),
                    mpn: None,
                    power: power(),
                    pins: vec![
                        pin("1", "~", "SIGNAL", ElectricalPinType::Passive),
                        pin("2", "~", "VCC", ElectricalPinType::Passive),
                    ],
                },
            ],
            nets: vec![
                CircuitNetV2 {
                    name: "SIGNAL".into(),
                    voltage_uv: None,
                    connections: vec![connection("U1", "1"), connection("R1", "1")],
                },
                CircuitNetV2 {
                    name: "VCC".into(),
                    voltage_uv: None,
                    connections: vec![connection("U1", "2"), connection("R1", "2")],
                },
            ],
        }
    }

    fn power() -> CircuitPowerV2 {
        CircuitPowerV2 {
            rail_voltage_uv: None,
            max_voltage_uv: None,
            requires_decoupling: false,
            decoupling: false,
        }
    }

    fn pin(
        number: &str,
        name: &str,
        net: &str,
        electrical_type: ElectricalPinType,
    ) -> CircuitPinV2 {
        CircuitPinV2 {
            number: number.into(),
            name: name.into(),
            net: Some(net.into()),
            electrical_type,
        }
    }

    fn connection(reference: &str, pin: &str) -> CircuitConnectionV2 {
        CircuitConnectionV2 {
            reference: reference.into(),
            pin: pin.into(),
        }
    }

    fn closure() -> FootprintClosureV1 {
        let qfn = r#"(footprint "QFN" (version 20240108) (generator pcbnew)
  (layer "F.Cu")
  (property "Reference" "REF**")
  (property "Value" "QFN")
  (model "${KICAD9_3DMODEL_DIR}/Package.step")
  (fp_rect (start -2 -2) (end 2 2) (stroke (width 0.05) (type default)) (fill none) (layer "F.CrtYd"))
  (pad "1" thru_hole circle (at -1 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask"))
  (pad "2" thru_hole circle (at 1 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask")))
"#;
        let resistor = r#"(footprint "R_0603" (version 20240108) (generator pcbnew)
  (layer "F.Cu")
  (attr smd exclude_from_bom)
  (fp_rect (start -1.5 -0.8) (end 1.5 0.8) (stroke (width 0.05) (type default)) (fill none) (layer "F.CrtYd"))
  (pad "1" smd roundrect (at -0.8 0) (size 0.9 0.9) (layers "F.Cu" "F.Paste" "F.Mask") (roundrect_rratio 0.2))
  (pad "2" smd roundrect (at 0.8 0) (size 0.9 0.9) (layers "F.Cu" "F.Paste" "F.Mask") (roundrect_rratio 0.2)))
"#;
        FootprintClosureV1 {
            schema_version: 1,
            footprints: vec![
                entry("Package:QFN", qfn),
                entry("Resistor_SMD:R_0603", resistor),
            ],
        }
    }

    fn entry(id: &str, source: &str) -> FootprintClosureEntryV1 {
        FootprintClosureEntryV1 {
            id: id.into(),
            source_bytes: source.len() as u64,
            source_sha256: digest_hex(source.as_bytes()),
            source: source.into(),
        }
    }

    fn construction(four_layer: bool) -> BoardConstructionProfileV1 {
        let stackup = if four_layer {
            vec![
                copper(Layer::Front, 35_000),
                dielectric("prepreg", 200_000, 4_200_000),
                copper(Layer::Inner(1), 18_000),
                dielectric("core", 1_094_000, 4_400_000),
                copper(Layer::Inner(2), 18_000),
                dielectric("prepreg", 200_000, 4_200_000),
                copper(Layer::Back, 35_000),
            ]
        } else {
            vec![
                copper(Layer::Front, 35_000),
                dielectric("FR4", 1_530_000, 4_100_000),
                copper(Layer::Back, 35_000),
            ]
        };
        BoardConstructionProfileV1 {
            schema_version: 1,
            id: if four_layer {
                "four-layer"
            } else {
                "two-layer"
            }
            .into(),
            revision: 1,
            board_thickness_nm: 1_600_000,
            stackup,
            routing_defaults: BoardRoutingDefaultsV1 {
                grid_nm: 100_000,
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                bend_cost: 5,
                via_cost: 50,
            },
            placement_defaults: BoardPlacementDefaultsV1 {
                grid_nm: 500_000,
                component_clearance_nm: 250_000,
                iterations: 100,
                seed: 42,
            },
        }
    }

    fn copper(layer: Layer, thickness_nm: i64) -> BoardConstructionStackupLayerV1 {
        BoardConstructionStackupLayerV1::Copper {
            layer,
            thickness_nm,
        }
    }

    fn dielectric(
        material: &str,
        thickness_nm: i64,
        dielectric_constant_millionths: u32,
    ) -> BoardConstructionStackupLayerV1 {
        BoardConstructionStackupLayerV1::Dielectric {
            material: material.into(),
            thickness_nm,
            dielectric_constant_millionths,
        }
    }

    fn physical(four_layer: bool) -> PhysicalConstraintProfile {
        let mut layers = vec![Layer::Front, Layer::Back];
        if four_layer {
            layers = vec![Layer::Front, Layer::Inner(1), Layer::Inner(2), Layer::Back];
        }
        PhysicalConstraintProfile {
            schema_version: 1,
            id: "board-40x30".into(),
            revision: 1,
            description: "Rectangular deterministic test board".into(),
            board_width_nm: 40_000_000,
            board_height_nm: 30_000_000,
            outline: vec![],
            fixed_components: vec![
                FixedComponent {
                    reference: "U1".into(),
                    x_nm: 10_000_000,
                    y_nm: 10_000_000,
                    rotation_mdeg: 0,
                    tolerance_nm: 0,
                    keepout_width_nm: 0,
                    keepout_height_nm: 0,
                },
                FixedComponent {
                    reference: "R1".into(),
                    x_nm: 20_000_000,
                    y_nm: 20_000_000,
                    rotation_mdeg: 90_000,
                    tolerance_nm: 0,
                    keepout_width_nm: 0,
                    keepout_height_nm: 0,
                },
            ],
            keepouts: vec![ProfileKeepout {
                id: "routing-only".into(),
                polygon: vec![
                    Point {
                        x_nm: 1_000_000,
                        y_nm: 20_000_000,
                    },
                    Point {
                        x_nm: 5_000_000,
                        y_nm: 20_000_000,
                    },
                    Point {
                        x_nm: 5_000_000,
                        y_nm: 25_000_000,
                    },
                    Point {
                        x_nm: 1_000_000,
                        y_nm: 25_000_000,
                    },
                ],
                layers,
                tracks_not_allowed: true,
                vias_not_allowed: true,
                zones_not_allowed: true,
                footprints_not_allowed: false,
                minimum_track_width_nm: None,
                minimum_clearance_nm: None,
            }],
            manufacturing_rules: Some(ManufacturingRules {
                minimum_track_width_nm: 200_000,
                minimum_clearance_nm: 150_000,
                minimum_drill_nm: 250_000,
                minimum_annular_ring_nm: 100_000,
                minimum_copper_to_edge_nm: 250_000,
                board_thickness_nm: 1_600_000,
                maximum_via_aspect_ratio: 10,
                minimum_drill_to_drill_nm: 200_000,
                allow_via_in_pad: false,
                minimum_trace_angle_deg: 45,
            }),
        }
    }

    fn sources(four_layer: bool) -> (String, String, String, String, String) {
        let spec = spec();
        let circuit = serde_json::to_string(&spec).unwrap();
        let schematic = circuit_spec_v2_to_kicad_sch(&spec).unwrap();
        let closure = serde_json::to_string(&closure()).unwrap();
        let construction = serde_json::to_string(&construction(four_layer)).unwrap();
        let physical = serde_json::to_string(&physical(four_layer)).unwrap();
        (circuit, schematic, closure, construction, physical)
    }

    #[test]
    fn produces_deterministic_approved_placed_but_unrouted_board() {
        let (circuit, schematic, closure, construction, physical) = sources(false);
        let first = write_circuit_spec_kicad_board(
            &circuit,
            &schematic,
            &closure,
            &construction,
            &physical,
            &ElectricalPolicy::default(),
        )
        .unwrap();
        let second = write_circuit_spec_kicad_board(
            &circuit,
            &schematic,
            &closure,
            &construction,
            &physical,
            &ElectricalPolicy::default(),
        )
        .unwrap();
        assert_eq!(first.board_source, second.board_source);
        assert_eq!(first.manifest_json, second.manifest_json);
        assert!(first.board_binding_report.approved);
        assert!(
            first
                .board_source
                .starts_with("(kicad_pcb\n  (version 20250114)")
        );
        assert!(first.board_source.contains("  (net 0 \"\")"));
        assert!(!first.board_source.contains("(segment "));
        assert!(!first.board_source.contains("(via "));
        assert!(first.board_source.contains("(at 10 10 0)"));
        assert!(first.board_source.contains("(at 20 20 90)"));
        assert!(first.board_source.contains("(net 1 \"SIGNAL\")"));
        assert!(first.board_source.contains("\n  (net_class \"Default\""));
        assert!(!first.board_source.contains("\n    (net_class "));
        assert!(first.board_source.contains("(property \"MPN\" \"CHIP-1\""));
        assert!(!first.board_source.contains("KICAD9_3DMODEL_DIR"));
        assert!(!first.board_source.contains("exclude_from_bom"));
        assert!(first.board_source.ends_with('\n'));
        assert!(first.board_binding_report_json.ends_with('\n'));
        assert!(first.manifest_json.ends_with('\n'));
        assert_eq!(
            first.manifest.board_source_bytes,
            first.board_source.len() as u64
        );
        assert_eq!(
            first.manifest.board_source_sha256,
            digest_hex(first.board_source.as_bytes())
        );
        let parsed_physical = parse_physical_profile(&physical).unwrap();
        let mut physical_identity = PHYSICAL_PROFILE_DIGEST_DOMAIN.to_vec();
        physical_identity.extend(serde_json::to_vec(&parsed_physical).unwrap());
        assert_eq!(
            first.manifest.physical_profile_sha256,
            digest_hex(&physical_identity)
        );
        assert!(!first.manifest.routing_performed);
        assert!(!first.manifest.drc_claimed);
        assert!(!first.manifest.dfm_claimed);
        validate_circuit_kicad_board_manifest_v1(&first.manifest).unwrap();

        let mut oversized = first.manifest.clone();
        oversized.board_source_bytes = CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES as u64 + 1;
        assert!(
            validate_circuit_kicad_board_manifest_v1(&oversized)
                .unwrap_err()
                .contains("board_source_bytes")
        );
        let mut excessive_iterations = first.manifest.clone();
        excessive_iterations.placement_iterations =
            u64::from(BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS) + 1;
        assert!(
            validate_circuit_kicad_board_manifest_v1(&excessive_iterations)
                .unwrap_err()
                .contains("placement_iterations")
        );
    }

    #[test]
    fn carries_and_round_trips_four_layer_stackup() {
        let (circuit, schematic, closure, construction, physical) = sources(true);
        let output = write_circuit_spec_kicad_board(
            &circuit,
            &schematic,
            &closure,
            &construction,
            &physical,
            &ElectricalPolicy::default(),
        )
        .unwrap();
        assert!(output.board_source.contains("(2 \"In1.Cu\" signal)"));
        assert!(output.board_source.contains("(4 \"In2.Cu\" signal)"));
        assert!(output.board_source.contains("(material \"core\")"));
        assert!(output.board_source.contains("(epsilon_r 4.4)"));
        assert!(output.board_binding_report.approved);

        let parsed_construction = parse_board_construction_profile_v1(&construction).unwrap();
        let rules = board_construction_routing_rules(&parsed_construction).unwrap();
        let altered = output
            .board_source
            .replacen("(epsilon_r 4.4)", "(epsilon_r 4.5)", 1);
        let altered = import(&altered, rules).unwrap();
        assert!(
            validate_imported_construction(
                &altered,
                &parsed_construction,
                &board_construction_routing_rules(&parsed_construction).unwrap(),
            )
            .unwrap_err()
            .contains("dielectric thickness, epsilon, or reference layer")
        );
    }

    #[test]
    fn fails_closed_for_unsupported_physical_placement_geometry() {
        let mut profile = physical(false);
        profile.keepouts[0].footprints_not_allowed = true;
        let error = validate_profiles_for_production(&construction(false), &profile).unwrap_err();
        assert!(error.contains("footprint-forbidden"));

        let mut profile = physical(false);
        profile.outline = vec![
            Point { x_nm: 0, y_nm: 0 },
            Point {
                x_nm: 40_000_000,
                y_nm: 0,
            },
            Point {
                x_nm: 20_000_000,
                y_nm: 15_000_000,
            },
            Point {
                x_nm: 0,
                y_nm: 30_000_000,
            },
        ];
        let error = validate_profiles_for_production(&construction(false), &profile).unwrap_err();
        assert!(error.contains("rectangular"));

        let mut profile = physical(false);
        profile.fixed_components[0].keepout_width_nm = 2_000_000;
        profile.fixed_components[0].keepout_height_nm = 2_000_000;
        let error = validate_profiles_for_production(&construction(false), &profile).unwrap_err();
        assert!(error.contains("fixed-component keepout"));

        let mut profile = physical(false);
        profile.keepouts[0].minimum_track_width_nm = Some(300_000);
        let error = validate_profiles_for_production(&construction(false), &profile).unwrap_err();
        assert!(error.contains("per-keepout routing minima"));
    }

    #[test]
    fn reimport_gate_does_not_mask_physical_output_mismatches() {
        let (circuit, schematic, closure, construction_source, physical_source) = sources(false);
        let output = write_circuit_spec_kicad_board(
            &circuit,
            &schematic,
            &closure,
            &construction_source,
            &physical_source,
            &ElectricalPolicy::default(),
        )
        .unwrap();
        let construction = parse_board_construction_profile_v1(&construction_source).unwrap();
        let physical = parse_physical_profile(&physical_source).unwrap();
        let rules = board_construction_routing_rules(&construction).unwrap();
        let imported = import(&output.board_source, rules).unwrap();

        let mut exact = imported.clone();
        validate_imported_physical(&mut exact, &physical).unwrap();

        let mut wrong_dimensions = imported.clone();
        wrong_dimensions.board.width_nm += 1;
        assert!(
            validate_imported_physical(&mut wrong_dimensions, &physical)
                .unwrap_err()
                .contains("dimensions")
        );

        let mut missing_outline = imported.clone();
        missing_outline.board.outline.clear();
        assert!(
            validate_imported_physical(&mut missing_outline, &physical)
                .unwrap_err()
                .contains("outline")
        );

        let mut missing_keepout = imported.clone();
        missing_keepout.board.keepouts.clear();
        assert!(
            validate_imported_physical(&mut missing_keepout, &physical)
                .unwrap_err()
                .contains("keepout set")
        );

        let mut unexpected_cutout = imported.clone();
        unexpected_cutout.board.cutouts.push(vec![
            Point { x_nm: 1, y_nm: 1 },
            Point { x_nm: 2, y_nm: 1 },
            Point { x_nm: 1, y_nm: 2 },
        ]);
        assert!(
            validate_imported_physical(&mut unexpected_cutout, &physical)
                .unwrap_err()
                .contains("cutouts")
        );

        let mut moved_fixed = imported;
        moved_fixed
            .board
            .footprints
            .iter_mut()
            .find(|footprint| footprint.reference == "U1")
            .unwrap()
            .position
            .x_nm += 1;
        assert!(
            validate_imported_physical(&mut moved_fixed, &physical)
                .unwrap_err()
                .contains("position and rotation")
        );
    }

    #[test]
    fn legacy_copper_ordinals_are_unique_at_the_32_layer_limit() {
        let mut ordinals = vec![legacy_kicad_copper_layer_ordinal(Layer::Front, 32).unwrap()];
        ordinals.extend(
            (1..=30)
                .map(|index| legacy_kicad_copper_layer_ordinal(Layer::Inner(index), 32).unwrap()),
        );
        ordinals.push(legacy_kicad_copper_layer_ordinal(Layer::Back, 32).unwrap());
        assert_eq!(ordinals.iter().copied().collect::<HashSet<_>>().len(), 32);
        assert_eq!(ordinals, (0..=31).collect::<Vec<_>>());
    }

    #[test]
    fn cross_checks_physical_manufacturing_rules() {
        let construction = construction(false);
        let mut profile = physical(false);
        profile
            .manufacturing_rules
            .as_mut()
            .unwrap()
            .minimum_track_width_nm = 300_000;
        assert!(
            validate_profiles_for_production(&construction, &profile)
                .unwrap_err()
                .contains("track width")
        );

        let mut profile = physical(false);
        profile
            .manufacturing_rules
            .as_mut()
            .unwrap()
            .board_thickness_nm = 1_500_000;
        assert!(
            validate_profiles_for_production(&construction, &profile)
                .unwrap_err()
                .contains("board_thickness_nm")
        );
    }

    #[test]
    fn manifest_schema_is_closed_and_claims_are_constants() {
        let schema = circuit_kicad_board_manifest_v1_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["routing_performed"]["const"], false);
        assert_eq!(schema["properties"]["drc_claimed"]["const"], false);
        assert_eq!(schema["properties"]["dfm_claimed"]["const"], false);
    }
}

//! Native, closed circuit-spec to routed-KiCad workflow.
//!
//! This module intentionally owns no command-line parsing.  `main.rs` wires the
//! public(crate) `generate` entry point into the command while retaining the
//! existing pinned-input and no-replace publication boundary.

use anyhow::{Result, bail};
use pcbex_core::{
    RoutingConvergenceOptions, Rules, apply_physical_profile, route_board_with_convergence,
};
use pcbex_kicad::{
    BOARD_CONSTRUCTION_PROFILE_V1_MAX_SOURCE_BYTES,
    CIRCUIT_KICAD_BOARD_BINDING_MAX_RENDERED_REPORT_BYTES, CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES,
    CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES, ElectricalPolicy,
    FOOTPRINT_CLOSURE_V1_MAX_SOURCE_BYTES, board_construction_routing_rules,
    circuit_spec_source_to_kicad_sch, import as import_kicad, parse_board_construction_profile_v1,
    verify_circuit_kicad_board_binding, verify_circuit_kicad_handoff,
    write_circuit_spec_kicad_board,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::physical_profile::MAX_PHYSICAL_PROFILE_BYTES;
use crate::routing_convergence_verification::{
    KicadRoutingVerificationSources, render_routing_convergence_verification_report,
    verify_kicad_routing_convergence,
};

pub const WORKFLOW_SCOPE: &str = "circuit_kicad_routed_board_workflow";
pub const WORKFLOW_STATUS: &str = "verified_complete";
pub const WORKFLOW_SCHEMA_VERSION: u32 = 1;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitRoutedBoardWorkflowManifest {
    pub schema_version: u32,
    pub scope: String,
    pub status: String,
    pub engine_version: String,
    pub circuit_spec: ArtifactIdentity,
    pub footprint_closure: ArtifactIdentity,
    pub construction_profile: ArtifactIdentity,
    pub physical_profile: ArtifactIdentity,
    pub circuit_spec_sha256: String,
    pub circuit_check_sha256: String,
    pub footprint_closure_sha256: String,
    pub construction_profile_sha256: String,
    pub physical_profile_sha256: String,
    pub schematic_sha256: String,
    pub board_placed_sha256: String,
    pub board_routed: ArtifactIdentity,
    pub outputs: [NamedArtifactIdentity; 9],
    pub effective_rules: Rules,
    pub convergence_options: RoutingConvergenceOptions,
    pub routed_board_binding_sha256: String,
    pub routing_verification_binding_sha256: String,
    pub source_authenticity_verified: bool,
    pub internal_rule_check_verified: bool,
    pub native_kicad_drc_verified: bool,
    pub manufacturability_verified: bool,
    pub release_authorized: bool,
    pub human_approval_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedArtifactIdentity {
    pub name: String,
    pub identity: ArtifactIdentity,
}

fn identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

/// Return the closed manifest schema used by the workflow command.
pub fn manifest_json_schema() -> Value {
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "additionalProperties": false,
        "required": ["schema_version","scope","status","engine_version","circuit_spec","footprint_closure","construction_profile","physical_profile","circuit_spec_sha256","circuit_check_sha256","footprint_closure_sha256","construction_profile_sha256","physical_profile_sha256","schematic_sha256","board_placed_sha256","board_routed","outputs","effective_rules","convergence_options","routed_board_binding_sha256","routing_verification_binding_sha256","source_authenticity_verified","internal_rule_check_verified","native_kicad_drc_verified","manufacturability_verified","release_authorized","human_approval_verified"],
        "properties": {
            "schema_version":{"const":1}, "scope":{"const":WORKFLOW_SCOPE}, "status":{"const":WORKFLOW_STATUS}, "engine_version":{"type":"string"},
            "circuit_spec":{"$ref":"#/$defs/identity"}, "footprint_closure":{"$ref":"#/$defs/identity"}, "construction_profile":{"$ref":"#/$defs/identity"}, "physical_profile":{"$ref":"#/$defs/identity"},
            "circuit_spec_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}, "circuit_check_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}, "footprint_closure_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}, "construction_profile_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}, "physical_profile_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}, "schematic_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}, "board_placed_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "board_routed":{"$ref":"#/$defs/identity"}, "outputs":{"type":"array","prefixItems":[{"$ref":"#/$defs/named_circuit_sch"},{"$ref":"#/$defs/named_placed_board"},{"$ref":"#/$defs/named_placed_binding"},{"$ref":"#/$defs/named_placed_manifest"},{"$ref":"#/$defs/named_routed_board"},{"$ref":"#/$defs/named_handoff"},{"$ref":"#/$defs/named_binding"},{"$ref":"#/$defs/named_convergence"},{"$ref":"#/$defs/named_verification"}],"items":false,"minItems":9,"maxItems":9},
            "effective_rules":{"$ref":"#/$defs/rules"}, "convergence_options":{"$ref":"#/$defs/options"},
            "routed_board_binding_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}, "routing_verification_binding_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "source_authenticity_verified":{"const":false}, "internal_rule_check_verified":{"const":true}, "native_kicad_drc_verified":{"const":false}, "manufacturability_verified":{"const":false}, "release_authorized":{"const":false}, "human_approval_verified":{"const":false}
        },
        "$defs": {
            "identity":{"type":"object","additionalProperties":false,"required":["bytes","sha256"],"properties":{"bytes":{"type":"integer","minimum":1},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}}},
            "named":{"type":"object","additionalProperties":false,"required":["name","identity"],"properties":{"name":{"type":"string"},"identity":{"$ref":"#/$defs/identity"}}},
            "named_circuit_sch":{"allOf":[{"$ref":"#/$defs/named"},{"properties":{"name":{"const":"circuit.kicad_sch"}}}]},"named_placed_board":{"allOf":[{"$ref":"#/$defs/named"},{"properties":{"name":{"const":"board.placed.kicad_pcb"}}}]},"named_placed_binding":{"allOf":[{"$ref":"#/$defs/named"},{"properties":{"name":{"const":"board.placed-binding.json"}}}]},"named_placed_manifest":{"allOf":[{"$ref":"#/$defs/named"},{"properties":{"name":{"const":"board.placed-manifest.json"}}}]},"named_routed_board":{"allOf":[{"$ref":"#/$defs/named"},{"properties":{"name":{"const":"board.kicad_pcb"}}}]},"named_handoff":{"allOf":[{"$ref":"#/$defs/named"},{"properties":{"name":{"const":"circuit-handoff.json"}}}]},"named_binding":{"allOf":[{"$ref":"#/$defs/named"},{"properties":{"name":{"const":"board-binding.json"}}}]},"named_convergence":{"allOf":[{"$ref":"#/$defs/named"},{"properties":{"name":{"const":"routing-convergence.json"}}}]},"named_verification":{"allOf":[{"$ref":"#/$defs/named"},{"properties":{"name":{"const":"routing-verification.json"}}}]}
        }
    });
    // Use the same structural bounds as the authoritative input contracts.
    // Runtime checks additionally enforce via drill/diameter relationships,
    // worker products, and the aggregate candidate allocation floor.
    let construction = pcbex_kicad::board_construction_profile_v1_json_schema();
    schema["$defs"]["rules"] = construction["$defs"]["routing_defaults"].clone();
    schema["$defs"]["positive_dimension"] = construction["$defs"]["positive_dimension"].clone();
    schema["$defs"]["options"] =
        pcbex_core::routing_convergence_report_json_schema()["$defs"]["options"].clone();
    schema
}

/// Generate and publish a new fourteen-file routed board bundle.
pub(crate) fn generate(
    circuit_spec: &Path,
    footprint_closure: &Path,
    construction_profile: &Path,
    physical_profile: &Path,
    output_dir: &Path,
    options: &RoutingConvergenceOptions,
) -> Result<()> {
    let prepared = crate::prepare_circuit_kicad_board_output(output_dir)?;
    let inputs = [
        crate::freeze_circuit_kicad_board_input(
            circuit_spec,
            "circuit specification",
            pcbex_kicad::CIRCUIT_SPEC_V2_MAX_BYTES,
        )?,
        crate::freeze_circuit_kicad_board_input(
            footprint_closure,
            "footprint closure",
            FOOTPRINT_CLOSURE_V1_MAX_SOURCE_BYTES,
        )?,
        crate::freeze_circuit_kicad_board_input(
            construction_profile,
            "board construction profile",
            BOARD_CONSTRUCTION_PROFILE_V1_MAX_SOURCE_BYTES,
        )?,
        crate::freeze_circuit_kicad_board_input(
            physical_profile,
            "physical profile",
            MAX_PHYSICAL_PROFILE_BYTES,
        )?,
    ];
    crate::reject_circuit_kicad_board_input_aliases(&inputs, &prepared.output_dir)?;
    let schematic =
        circuit_spec_source_to_kicad_sch(&inputs[0].source).map_err(anyhow::Error::msg)?;
    if schematic.len() as u64 > CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES {
        bail!("generated schematic exceeds bound");
    }
    let policy = ElectricalPolicy::default();
    let production = write_circuit_spec_kicad_board(
        &inputs[0].source,
        &schematic,
        &inputs[1].source,
        &inputs[2].source,
        &inputs[3].source,
        &policy,
    )
    .map_err(anyhow::Error::msg)?;
    let handoff = verify_circuit_kicad_handoff(&inputs[0].source, &schematic, &policy)
        .map_err(anyhow::Error::msg)?;
    if !handoff.approved {
        bail!("generated circuit handoff is not approved");
    }
    let construction =
        parse_board_construction_profile_v1(&inputs[2].source).map_err(anyhow::Error::msg)?;
    let rules = board_construction_routing_rules(&construction).map_err(anyhow::Error::msg)?;
    let physical =
        pcbex_core::parse_physical_profile(&inputs[3].source).map_err(anyhow::Error::msg)?;
    let mut imported =
        import_kicad(&production.board_source, rules.clone()).map_err(anyhow::Error::msg)?;
    apply_physical_profile(&mut imported.board, &physical).map_err(anyhow::Error::msg)?;
    let routed =
        route_board_with_convergence(&imported.board, options).map_err(anyhow::Error::msg)?;
    if !routed.report.converged
        || routed.report.status != pcbex_core::RoutingConvergenceStatus::Converged
        || routed.report.final_metrics.unrouted_nets != 0
        || routed.report.final_drc_violation_count != 0
        || !routed.report.design_rules_unchanged
    {
        bail!("routing convergence did not complete cleanly");
    }
    let routed_board = imported
        .write_routes(&routed.board.routes)
        .map_err(anyhow::Error::msg)?;
    let convergence = pcbex_core::render_routing_convergence_report(&routed.report)
        .map_err(anyhow::Error::msg)?;
    let routed_binding =
        verify_circuit_kicad_board_binding(&inputs[0].source, &schematic, &routed_board, &policy)
            .map_err(anyhow::Error::msg)?;
    if !routed_binding.approved {
        bail!("routed board binding is not approved");
    }
    let routed_binding_json =
        pcbex_kicad::render_circuit_kicad_board_binding_report(&routed_binding)
            .map_err(anyhow::Error::msg)?;
    let verification = verify_kicad_routing_convergence(
        KicadRoutingVerificationSources {
            input: production.board_source.as_bytes(),
            routed_output: routed_board.as_bytes(),
            retained_report: convergence.as_bytes(),
            project: None,
            rules_file: None,
            fab_profile: None,
            policy_pack: None,
            physical_profile: Some(inputs[3].source.as_bytes()),
        },
        rules.clone(),
        None,
    )?;
    if verification.status
        != crate::routing_convergence_verification::RoutingConvergenceVerificationStatus::Complete
        || !verification.routing_complete
        || !verification.validation.source_closure_captured
        || !verification.validation.retained_report_canonical
        || !verification.validation.fresh_convergence_replayed
        || !verification.validation.retained_report_exact
        || !verification.validation.routed_output_exact
        || !verification.validation.caller_inputs_unchanged
    {
        bail!("fresh routing verification did not complete cleanly");
    }
    let verification_json = render_routing_convergence_verification_report(&verification)?;
    let placed_binding = production.board_binding_report_json.as_bytes();
    let placed_manifest = production.manifest_json.as_bytes();
    let mut outputs: Vec<(&str, Vec<u8>, u64)> = vec![
        ("circuit.kicad_sch", schematic.as_bytes().to_vec(), CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES),
        ("board.placed.kicad_pcb", production.board_source.as_bytes().to_vec(), CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES as u64),
        ("board.placed-binding.json", placed_binding.to_vec(), CIRCUIT_KICAD_BOARD_BINDING_MAX_RENDERED_REPORT_BYTES as u64),
        ("board.placed-manifest.json", placed_manifest.to_vec(), pcbex_kicad::CIRCUIT_KICAD_BOARD_MANIFEST_V1_MAX_RENDERED_BYTES as u64),
        ("board.kicad_pcb", routed_board.as_bytes().to_vec(), CIRCUIT_KICAD_BOARD_MAX_OUTPUT_BYTES as u64),
        ("circuit-handoff.json", serde_json::to_vec_pretty(&handoff)?.into_iter().chain(*b"\n").collect(), CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES),
        ("board-binding.json", routed_binding_json.clone(), CIRCUIT_KICAD_BOARD_BINDING_MAX_RENDERED_REPORT_BYTES as u64),
        ("routing-convergence.json", convergence.as_bytes().to_vec(), pcbex_core::MAX_ROUTING_CONVERGENCE_REPORT_BYTES),
        ("routing-verification.json", verification_json.clone(), crate::routing_convergence_verification::MAX_ROUTING_CONVERGENCE_VERIFICATION_REPORT_BYTES),
    ];
    let mut manifest_outputs = Vec::new();
    for (name, bytes, _) in &outputs {
        manifest_outputs.push(NamedArtifactIdentity {
            name: (*name).into(),
            identity: identity(bytes),
        });
    }
    let manifest = CircuitRoutedBoardWorkflowManifest {
        schema_version: WORKFLOW_SCHEMA_VERSION,
        scope: WORKFLOW_SCOPE.into(),
        status: WORKFLOW_STATUS.into(),
        engine_version: env!("CARGO_PKG_VERSION").into(),
        circuit_spec: identity(inputs[0].source.as_bytes()),
        footprint_closure: identity(inputs[1].source.as_bytes()),
        construction_profile: identity(inputs[2].source.as_bytes()),
        physical_profile: identity(inputs[3].source.as_bytes()),
        circuit_spec_sha256: production.manifest.circuit_spec_sha256.clone(),
        circuit_check_sha256: production.manifest.circuit_check_sha256.clone(),
        footprint_closure_sha256: production.manifest.footprint_closure_sha256.clone(),
        construction_profile_sha256: production.manifest.construction_profile_sha256.clone(),
        physical_profile_sha256: production.manifest.physical_profile_sha256.clone(),
        schematic_sha256: production.manifest.schematic_sha256.clone(),
        board_placed_sha256: production.manifest.board_source_sha256.clone(),
        board_routed: identity(routed_board.as_bytes()),
        outputs: manifest_outputs.try_into().map_err(|_| {
            anyhow::anyhow!("workflow output inventory must contain exactly nine artifacts")
        })?,
        effective_rules: rules,
        convergence_options: options.clone(),
        routed_board_binding_sha256: routed_binding.binding_sha256.clone(),
        routing_verification_binding_sha256: verification.binding_sha256.clone(),
        source_authenticity_verified: false,
        internal_rule_check_verified: true,
        native_kicad_drc_verified: false,
        manufacturability_verified: false,
        release_authorized: false,
        human_approval_verified: false,
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest)?
        .into_iter()
        .chain(*b"\n")
        .collect::<Vec<_>>();
    outputs.extend([
        (
            "circuit-spec.json",
            inputs[0].source.as_bytes().to_vec(),
            pcbex_kicad::CIRCUIT_SPEC_V2_MAX_BYTES,
        ),
        (
            "footprint-closure.json",
            inputs[1].source.as_bytes().to_vec(),
            FOOTPRINT_CLOSURE_V1_MAX_SOURCE_BYTES,
        ),
        (
            "construction-profile.json",
            inputs[2].source.as_bytes().to_vec(),
            BOARD_CONSTRUCTION_PROFILE_V1_MAX_SOURCE_BYTES,
        ),
        (
            "physical-profile.json",
            inputs[3].source.as_bytes().to_vec(),
            MAX_PHYSICAL_PROFILE_BYTES,
        ),
    ]);
    outputs.push(("manifest.json", manifest_json, 1024 * 1024));
    for (name, bytes, limit) in &outputs {
        crate::stage_circuit_kicad_board_file(prepared.staging.path(), name, bytes, *limit)?;
    }
    let expected: Vec<(&str, &[u8], u64)> = outputs
        .iter()
        .map(|(n, b, l)| (*n, b.as_slice(), *l))
        .collect();
    crate::validate_circuit_kicad_board_stage(prepared.staging.path(), &expected)?;
    for input in &inputs {
        crate::recheck_frozen_circuit_kicad_board_input(input)?;
    }
    crate::validate_circuit_kicad_board_stage(prepared.staging.path(), &expected)?;
    crate::publish_circuit_kicad_board_output(prepared)
}

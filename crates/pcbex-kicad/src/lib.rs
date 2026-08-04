#![recursion_limit = "256"]

use pcbex_core::{
    Board, CapsuleObstacle, CopperZone, DifferentialPair, Footprint, Keepout, Layer, Net,
    NetClassRules, Obstacle, Pad, PadShape, Point, PolygonObstacle, RoundObstacle, Route, RouteArc,
    Rules, Segment, StackupLayer, Terminal, Via, ViaKind,
    checking::check_board,
    placement::{BoardSide, Component, Connection, PinRef, PlacementProblem},
};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

mod sexp;
pub(crate) use sexp::{Sexp, list_spans, parse_document as parse, parse_sequence};

mod anchor;
pub use anchor::{
    ApprovalLogAnchorProof, ApprovalLogAnchorVerificationReport, ApprovalLogConsistencyProof,
    ApprovalLogConsistencyVerificationReport, SignedApprovalPublicLogTreeHead,
    approval_log_anchor_proof_json_schema, approval_log_anchor_verification_report_json_schema,
    approval_log_consistency_proof_json_schema,
    approval_log_consistency_verification_report_json_schema, approval_public_log_tree_head_sha256,
    create_approval_log_anchor_proof, create_approval_log_consistency_proof,
    validate_approval_log_anchor_proof, verify_approval_log_anchor_proof,
    verify_approval_log_consistency_proof, verify_approval_log_tree_head_consistency,
    verify_approval_public_log_tree_head,
};
mod approval_gossip;
pub use approval_gossip::{
    ApprovalLogGossipVerificationReport, SignedApprovalLogGossipReceipt,
    approval_log_gossip_verification_report_json_schema, sign_approval_log_gossip_receipt,
    signed_approval_log_gossip_receipt_json_schema, validate_approval_log_gossip_receipt,
    verify_approval_log_gossip_receipt,
};
mod approval_gossip_quorum;
pub use approval_gossip_quorum::{
    ApprovalLogGossipObservation, ApprovalLogGossipQuorumMember, ApprovalLogGossipQuorumReport,
    approval_log_gossip_observation_json_schema, approval_log_gossip_quorum_report_json_schema,
    validate_approval_log_gossip_observation, validate_approval_log_gossip_quorum_report,
    verify_approval_log_gossip_quorum,
};
mod approval_gossip_registry;
pub use approval_gossip_registry::{
    ApprovalLogGossipObserverAdmission, ApprovalLogGossipOrganizationRegistry,
    ApprovalLogGossipOrganizationRegistryAction, ApprovalLogGossipOrganizationRegistryEntry,
    ApprovalLogGossipOrganizationRegistryHistory,
    ApprovalLogGossipOrganizationRegistryHistoryAuditEntry,
    ApprovalLogGossipOrganizationRegistryHistoryAuditReport,
    ApprovalLogGossipOrganizationRegistryHistoryEvent,
    ApprovalLogGossipOrganizationRegistryHistoryEventKind, ApprovalLogGossipOrganizationStatus,
    ApprovalLogGossipRegistryBoundQuorumReport, ApprovalLogGossipRegistryGovernanceAuthority,
    ApprovalLogGossipRegistryThresholdApproval,
    SignedApprovalLogGossipOrganizationRegistryAuthorityKeyRotation,
    SignedApprovalLogGossipOrganizationRegistryGovernance,
    SignedApprovalLogGossipOrganizationRegistryGovernanceRotation,
    SignedApprovalLogGossipOrganizationRegistryGovernedAuthorityKeyRotation,
    SignedApprovalLogGossipOrganizationRegistryThresholdTransition,
    SignedApprovalLogGossipOrganizationRegistryTransition,
    apply_approval_log_gossip_organization_registry_authority_key_rotation,
    apply_approval_log_gossip_organization_registry_governance_rotation,
    apply_approval_log_gossip_organization_registry_governed_authority_key_rotation,
    apply_approval_log_gossip_organization_registry_threshold_transition,
    apply_approval_log_gossip_organization_registry_transition,
    approval_log_gossip_organization_registry_history_audit_report_json_schema,
    approval_log_gossip_organization_registry_history_audit_report_sha256,
    approval_log_gossip_organization_registry_history_json_schema,
    approval_log_gossip_organization_registry_json_schema,
    approval_log_gossip_organization_registry_sha256,
    approval_log_gossip_registry_bound_quorum_report_json_schema,
    audit_approval_log_gossip_organization_registry_history,
    new_approval_log_gossip_organization_registry,
    sign_approval_log_gossip_organization_registry_authority_key_rotation,
    sign_approval_log_gossip_organization_registry_governance,
    sign_approval_log_gossip_organization_registry_governance_rotation,
    sign_approval_log_gossip_organization_registry_governed_authority_key_rotation,
    sign_approval_log_gossip_organization_registry_successor_governance,
    sign_approval_log_gossip_organization_registry_threshold_transition,
    sign_approval_log_gossip_organization_registry_transition,
    signed_approval_log_gossip_organization_registry_authority_key_rotation_json_schema,
    signed_approval_log_gossip_organization_registry_authority_key_rotation_sha256,
    signed_approval_log_gossip_organization_registry_governance_json_schema,
    signed_approval_log_gossip_organization_registry_governance_rotation_json_schema,
    signed_approval_log_gossip_organization_registry_governance_rotation_sha256,
    signed_approval_log_gossip_organization_registry_governance_sha256,
    signed_approval_log_gossip_organization_registry_governed_authority_key_rotation_json_schema,
    signed_approval_log_gossip_organization_registry_governed_authority_key_rotation_sha256,
    signed_approval_log_gossip_organization_registry_threshold_transition_json_schema,
    signed_approval_log_gossip_organization_registry_threshold_transition_sha256,
    signed_approval_log_gossip_organization_registry_transition_json_schema,
    signed_approval_log_gossip_organization_registry_transition_sha256,
    validate_approval_log_gossip_organization_registry,
    validate_approval_log_gossip_organization_registry_history,
    validate_approval_log_gossip_organization_registry_history_audit_report,
    validate_approval_log_gossip_registry_bound_quorum_report,
    validate_signed_approval_log_gossip_organization_registry_authority_key_rotation,
    validate_signed_approval_log_gossip_organization_registry_governance,
    validate_signed_approval_log_gossip_organization_registry_governance_rotation,
    validate_signed_approval_log_gossip_organization_registry_governed_authority_key_rotation,
    validate_signed_approval_log_gossip_organization_registry_threshold_transition,
    validate_signed_approval_log_gossip_organization_registry_transition,
    verify_approval_log_gossip_quorum_with_organization_registry,
};
mod approval_gossip_registry_checkpoint;
pub use approval_gossip_registry_checkpoint::{
    ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    ApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessMember,
    ApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport,
    ApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    SignedApprovalLogGossipOrganizationRegistryHistoryCheckpoint,
    SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness,
    SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessKeyRotation,
    accept_approval_log_gossip_organization_registry_history_checkpoint,
    apply_approval_log_gossip_organization_registry_history_checkpoint_witness_key_rotation,
    approval_log_gossip_organization_registry_history_checkpoint_trust_state_json_schema,
    approval_log_gossip_organization_registry_history_checkpoint_witness_quorum_report_json_schema,
    approval_log_gossip_organization_registry_history_checkpoint_witness_trust_state_json_schema,
    approval_log_gossip_organization_registry_history_checkpoint_witness_trusted_public_key,
    new_approval_log_gossip_organization_registry_history_checkpoint_witness_trust_state,
    sign_approval_log_gossip_organization_registry_history_checkpoint,
    sign_approval_log_gossip_organization_registry_history_checkpoint_witness,
    sign_approval_log_gossip_organization_registry_history_checkpoint_witness_key_rotation,
    signed_approval_log_gossip_organization_registry_history_checkpoint_json_schema,
    signed_approval_log_gossip_organization_registry_history_checkpoint_sha256,
    signed_approval_log_gossip_organization_registry_history_checkpoint_witness_json_schema,
    signed_approval_log_gossip_organization_registry_history_checkpoint_witness_key_rotation_json_schema,
    signed_approval_log_gossip_organization_registry_history_checkpoint_witness_sha256,
    validate_approval_log_gossip_organization_registry_history_checkpoint_trust_state,
    validate_approval_log_gossip_organization_registry_history_checkpoint_witness_quorum_report,
    validate_approval_log_gossip_organization_registry_history_checkpoint_witness_trust_state,
    validate_signed_approval_log_gossip_organization_registry_history_checkpoint,
    validate_signed_approval_log_gossip_organization_registry_history_checkpoint_witness,
    validate_signed_approval_log_gossip_organization_registry_history_checkpoint_witness_key_rotation,
    verify_approval_log_gossip_organization_registry_history_checkpoint_witness_for_trust_state,
    verify_approval_log_gossip_organization_registry_history_checkpoint_witnesses,
    verify_approval_log_gossip_organization_registry_history_checkpoint_witnesses_with_trust_states,
};
mod approval_gossip_trust;
pub use approval_gossip_trust::{
    ApprovalLogGossipObserverTrustReference, ApprovalLogGossipObserverTrustState,
    ApprovalLogGossipTrustBoundQuorumReport, SignedApprovalLogGossipObserverKeyRotation,
    apply_approval_log_gossip_observer_key_rotation,
    approval_log_gossip_observer_trust_state_json_schema,
    approval_log_gossip_observer_trust_state_sha256,
    approval_log_gossip_observer_trusted_public_key,
    approval_log_gossip_trust_bound_quorum_report_json_schema,
    new_approval_log_gossip_observer_trust_state, sign_approval_log_gossip_observer_key_rotation,
    signed_approval_log_gossip_observer_key_rotation_json_schema,
    signed_approval_log_gossip_observer_key_rotation_sha256,
    validate_approval_log_gossip_observer_trust_state,
    validate_approval_log_gossip_trust_bound_quorum_report,
    validate_signed_approval_log_gossip_observer_key_rotation,
    verify_approval_log_gossip_quorum_with_observer_trust_states,
};
mod approval;
pub use approval::{
    AiApprovalPolicy, AiModelIdentity, AiRequirement, AiRequirementAssessment, AiRequirementStatus,
    AiReviewArtifactBinding, AiReviewDecision, AiReviewRequest, AiReviewResponse, AiRisk,
    AiRiskSeverity, DeterministicPipelineIdentity, ExactArtifactIdentity, NativeKicadErcIdentity,
    SignedAiApproval, ai_review_request_json_schema, ai_review_request_sha256,
    ai_review_response_json_schema, approval_public_key, bind_ai_review_request,
    bind_native_kicad_erc_to_ai_review_request, build_ai_review_request, parse_ai_review_response,
    sign_ai_review, sign_ai_review_for_session, signed_ai_approval_json_schema,
    verify_session_signed_ai_approval, verify_signed_ai_approval,
};
mod approval_quorum;
pub use approval_quorum::{
    AiApprovalQuorumCandidate, AiApprovalQuorumCounts, AiApprovalQuorumMember,
    AiApprovalQuorumPolicy, AiApprovalQuorumReport, SessionAiApprovalQuorumReport,
    ai_approval_quorum_report_json_schema, render_ai_approval_quorum_summary,
    render_session_ai_approval_quorum_summary, session_ai_approval_quorum_report_json_schema,
    verify_ai_approval_quorum, verify_session_ai_approval_quorum,
};
mod human_escalation;
pub use human_escalation::{
    HumanEscalationCandidate, HumanEscalationDecision, HumanEscalationMember,
    HumanEscalationPolicy, HumanEscalationReport, SessionAiQuorumEvidence, SignedHumanEscalation,
    ai_quorum_evidence_sha256, human_escalation_report_json_schema,
    render_human_escalation_summary, sign_human_escalation, signed_human_escalation_json_schema,
    verify_human_escalation,
};
mod transparency;
pub use transparency::{
    ApprovalArtifactKind, ApprovalEventDescriptor, ApprovalLogVerificationReport,
    ApprovalLogWitnessQuorumReport, ApprovalLogWitnessTrustState, ApprovalTransparencyEntry,
    ApprovalTransparencyLog, SignedApprovalLogCheckpoint, SignedApprovalLogWitness,
    SignedApprovalLogWitnessKeyRotation, append_approval_transparency_event,
    apply_approval_log_witness_key_rotation, approval_log_verification_report_json_schema,
    approval_log_witness_quorum_report_json_schema, approval_log_witness_trust_state_json_schema,
    approval_log_witness_trusted_public_key, approval_transparency_log_json_schema,
    approval_transparency_log_sha256, new_approval_log_witness_trust_state,
    new_approval_transparency_log, sign_approval_log_checkpoint, sign_approval_log_witness,
    sign_approval_log_witness_key_rotation, signed_approval_log_checkpoint_json_schema,
    signed_approval_log_checkpoint_sha256, signed_approval_log_witness_json_schema,
    signed_approval_log_witness_key_rotation_json_schema,
    signed_approval_log_witness_key_rotation_sha256, verify_approval_log_checkpoint,
    verify_approval_log_witness_quorum, verify_signed_approval_log_witness,
};
mod electrical;
pub use electrical::{
    ELECTRICAL_SAFETY_FLOOR_RULES, ElectricalExplanationReport, ElectricalFinding,
    ElectricalFindingCounts, ElectricalPolicy, ElectricalReview, ElectricalRuleExplanation,
    ElectricalRulePolicy, ElectricalSeverity, ElectricalSymbolRef, check_schematic,
    electrical_explanation_json_schema, electrical_policy_json_schema,
    electrical_review_json_schema, electrical_review_to_junit, electrical_review_to_sarif,
    explain_electrical_review, is_electrical_safety_floor_rule, parse_electrical_policy,
};
mod circuit_spec;
pub use circuit_spec::{
    CIRCUIT_SPEC_CHECK_SCHEMA_VERSION, CIRCUIT_SPEC_V2_MAX_BYTES,
    CIRCUIT_SPEC_V2_MAX_CONNECTIONS_PER_NET, CIRCUIT_SPEC_V2_MAX_FOOTPRINT_BYTES,
    CIRCUIT_SPEC_V2_MAX_LIB_ID_BYTES, CIRCUIT_SPEC_V2_MAX_MPN_BYTES,
    CIRCUIT_SPEC_V2_MAX_NET_NAME_BYTES, CIRCUIT_SPEC_V2_MAX_NETS, CIRCUIT_SPEC_V2_MAX_PARTS,
    CIRCUIT_SPEC_V2_MAX_PIN_NAME_BYTES, CIRCUIT_SPEC_V2_MAX_PIN_NUMBER_BYTES,
    CIRCUIT_SPEC_V2_MAX_PINS_PER_PART, CIRCUIT_SPEC_V2_MAX_REFERENCE_BYTES,
    CIRCUIT_SPEC_V2_MAX_TOTAL_CONNECTIONS, CIRCUIT_SPEC_V2_MAX_TOTAL_PINS,
    CIRCUIT_SPEC_V2_MAX_VALUE_BYTES, CIRCUIT_SPEC_V2_SCHEMA_VERSION, CircuitConnectionV2,
    CircuitNetV2, CircuitPartV2, CircuitPinV2, CircuitPowerV2, CircuitSpecCheck, CircuitSpecV2,
    check_circuit_spec, circuit_spec_check_json_schema, circuit_spec_v2_json_schema,
    circuit_spec_v2_sha256, circuit_spec_v2_to_schematic, normalize_circuit_spec_v2,
    parse_and_check_circuit_spec_v2, parse_circuit_spec_v2,
};
mod circuit_handoff;
pub use circuit_handoff::{
    CIRCUIT_KICAD_HANDOFF_ENGINE_VERSION, CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES,
    CIRCUIT_KICAD_HANDOFF_REPORT_SCHEMA_VERSION, CIRCUIT_KICAD_HANDOFF_SCHEMA_VERSION,
    CircuitKicadHandoffFinding, CircuitKicadHandoffFindingCounts, CircuitKicadHandoffReport,
    circuit_kicad_handoff_report_json_schema, verify_circuit_kicad_handoff,
};
mod circuit_board_binding;
pub use circuit_board_binding::{
    CIRCUIT_KICAD_BOARD_BINDING_ENGINE_VERSION, CIRCUIT_KICAD_BOARD_BINDING_MAX_BOARD_BYTES,
    CIRCUIT_KICAD_BOARD_BINDING_MAX_REPORT_BYTES,
    CIRCUIT_KICAD_BOARD_BINDING_REPORT_SCHEMA_VERSION, CIRCUIT_KICAD_BOARD_BINDING_SCHEMA_VERSION,
    CircuitKicadBoardBindingFinding, CircuitKicadBoardBindingFindingCounts,
    CircuitKicadBoardBindingReport, circuit_kicad_board_binding_report_json_schema,
    verify_circuit_kicad_board_binding,
};
mod manufacturing;
pub use manufacturing::{
    MAX_MANUFACTURING_PARTS, ManufacturingPart, manufacturing_gerber_layers, manufacturing_parts,
};
mod electrical_comparison;
pub use electrical_comparison::{
    ElectricalComparisonCounts, ElectricalFindingSummary, ElectricalReviewComparison,
    ElectricalReviewIdentity, ElectricalSeverityChange, compare_electrical_reviews,
    electrical_review_comparison_json_schema,
};
mod evidence;
pub use evidence::{
    SimulationAnalysisKind, SimulationArtifact, SimulationAssertion, SimulationAssertionResult,
    SimulationDeclaration, SimulationEngine, SimulationEvidence, SimulationEvidenceCounts,
    parse_simulation_declaration, record_simulation_evidence, simulation_declaration_json_schema,
    simulation_evidence_json_schema, validate_simulation_evidence,
};
mod schematic;
pub use schematic::{
    ElectricalPinType, SchematicCoverage, SchematicDocument, SchematicLabel, SchematicLabelKind,
    SchematicMarker, SchematicNet, SchematicPin, SchematicPinRef, SchematicSymbol,
    SchematicUnsupportedFeature, SchematicWire, import_schematic, schematic_json_schema,
};
mod schematic_writer;
pub use schematic_writer::{
    CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES, CIRCUIT_KICAD_SCHEMATIC_VERSION,
    circuit_spec_v2_to_kicad_sch,
};
mod schematic_diff;
pub use schematic_diff::{
    SchematicDiffCounts, SchematicDiffIdentity, SchematicNetChange, SchematicNetSummary,
    SchematicPinChange, SchematicPinSummary, SchematicSemanticDiff, SchematicSymbolChange,
    SchematicSymbolSummary, compare_schematics, render_schematic_diff_summary,
    schematic_diff_json_schema, schematic_diff_to_sarif,
};
mod reviewer_routing;
pub use reviewer_routing::{
    SchematicReviewChange, SchematicReviewChangeKind, SchematicReviewSelector,
    SchematicReviewerProfile, SchematicReviewerRoute, SchematicReviewerRoutingPlan,
    SchematicReviewerRoutingPolicy, parse_schematic_reviewer_routing_policy,
    render_schematic_reviewer_routing_summary, route_schematic_review,
    schematic_reviewer_routing_plan_json_schema, schematic_reviewer_routing_policy_json_schema,
};
mod routed_quorum;
pub use routed_quorum::{
    RoutedAiApprovalProfile, RoutedAiApprovalQuorumReport, SessionRoutedAiApprovalQuorumReport,
    render_routed_ai_approval_quorum_summary, render_session_routed_ai_approval_quorum_summary,
    routed_ai_approval_quorum_report_json_schema,
    session_routed_ai_approval_quorum_report_json_schema, verify_routed_ai_approval_quorum,
    verify_session_routed_ai_approval_quorum,
};
mod review_session;
pub use review_session::{
    AiReviewSession, MAX_AI_REVIEW_SESSION_SECONDS, ai_review_session_json_schema,
    ai_review_session_sha256, build_ai_review_session, validate_ai_review_session,
};
mod waiver;
pub use waiver::{
    ElectricalFindingDisposition, ElectricalWaiver, ElectricalWaiverCounts,
    ElectricalWaiverDecision, ElectricalWaiverReport, ElectricalWaiverSet,
    apply_electrical_waivers, electrical_waiver_report_json_schema,
    electrical_waiver_set_json_schema,
};

const NM_PER_MM: f64 = 1_000_000.0;
const ARC_CHORD_TOLERANCE_NM: f64 = 10_000.0;
const MAX_EDGE_ARC_SEGMENTS: usize = 16_384;
const MAX_EDGE_CIRCLE_SEGMENTS: usize = 16_384;
const MAX_EDGE_CURVE_SEGMENTS: usize = 16_384;
const MAX_EDGE_POLYGON_POINTS: usize = 16_384;
const MAX_EDGE_SEGMENTS: usize = 65_536;

#[derive(Clone, Debug)]
pub struct ImportedBoard {
    pub board: Board,
    source: String,
    origin: Point,
    existing_route_net_ids: HashSet<u32>,
}

struct BoardGeometry {
    min: Point,
    max: Point,
    outline: Vec<Point>,
    cutouts: Vec<Vec<Point>>,
}

#[derive(Default)]
struct FootprintGeometry {
    round_obstacles: Vec<RoundObstacle>,
    capsule_obstacles: Vec<CapsuleObstacle>,
    polygon_obstacles: Vec<PolygonObstacle>,
    footprints: Vec<Footprint>,
}

pub fn import(source: &str, rules: Rules) -> Result<ImportedBoard, String> {
    let root = parse(source)?;
    let top = root
        .as_list()
        .ok_or_else(|| "KiCad document is not an s-expression".to_string())?;
    if atom(top.first()) != Some("kicad_pcb") {
        return Err("expected a kicad_pcb document".into());
    }
    let copper_layers = board_copper_layers(top)?;
    let stackup = import_stackup(top, &copper_layers)?;

    let BoardGeometry {
        min,
        max,
        outline,
        cutouts,
    } = board_bounds(top)?;
    let mut nets = HashMap::<u32, Net>::new();
    for item in top {
        let Some(xs) = item.as_list() else { continue };
        if atom(xs.first()) == Some("net") {
            let Some(id) = number_u32(xs.get(1)) else {
                return Err("KiCad board net is missing a valid numeric ID".into());
            };
            let Some(name) = atom(xs.get(2)) else {
                return Err(format!("KiCad board net {id} is missing a scalar name"));
            };
            if xs.len() > 3 {
                return Err(format!(
                    "KiCad board net {id} declaration must contain exactly one ID and name"
                ));
            }
            if id == 0 && !name.is_empty() {
                return Err("KiCad board net 0 name must be empty".into());
            }
            if id != 0 && name.trim().is_empty() {
                return Err(format!("KiCad board net {id} name must not be blank"));
            }
            if let Some(existing) = nets.get(&id) {
                return Err(format!(
                    "KiCad board contains duplicate net ID {id}: {} and {name}",
                    existing.name
                ));
            }
            if let Some(existing) = nets.values().find(|net| net.name == name) {
                return Err(format!(
                    "KiCad board contains duplicate net name {name}: IDs {} and {id}",
                    existing.id
                ));
            }
            nets.insert(
                id,
                Net {
                    id,
                    name: name.to_string(),
                    terminals: Vec::new(),
                    class: None,
                    priority: 0,
                },
            );
        }
    }

    let net_classes = import_net_classes(top, &rules, &mut nets)?;
    let mut obstacles = Vec::new();
    let mut footprint_geometry = FootprintGeometry::default();
    let mut keepouts = Vec::new();
    let mut route_candidates = HashMap::new();
    let mut footprint_references = HashSet::new();
    for item in top {
        let Some(xs) = item.as_list() else { continue };
        match atom(xs.first()) {
            Some("footprint") => {
                let reference = footprint_reference(xs);
                if !reference.trim().is_empty() && !footprint_references.insert(reference.clone()) {
                    return Err(format!("duplicate footprint reference: {reference}"));
                }
                import_footprint(xs, min, &mut nets, &mut footprint_geometry, &copper_layers)?
            }
            Some("segment") => {
                validate_declared_copper_net(xs, "segment", &nets)?;
                import_segment(
                    xs,
                    min,
                    &rules,
                    &copper_layers,
                    &mut obstacles,
                    &mut route_candidates,
                )?
            }
            Some("arc") => {
                validate_declared_copper_net(xs, "route arc", &nets)?;
                import_route_arc(
                    xs,
                    min,
                    &rules,
                    &copper_layers,
                    &mut obstacles,
                    &mut route_candidates,
                )?
            }
            Some("via") => {
                validate_declared_copper_net(xs, "via", &nets)?;
                import_via(
                    xs,
                    min,
                    &rules,
                    &mut obstacles,
                    &mut route_candidates,
                    &copper_layers,
                )?
            }
            Some("zone") => {
                if child_values(xs, "keepout").is_none()
                    && child_values(xs, "attr")
                        .and_then(|attr| child_values(attr, "teardrop"))
                        .is_none()
                {
                    validate_declared_copper_net(xs, "copper zone", &nets)?;
                    validate_copper_zone_net_name(xs, &nets)?;
                }
                import_keepout(xs, min, &mut keepouts, &copper_layers)?;
                import_copper_zone(
                    xs,
                    min,
                    &copper_layers,
                    &mut footprint_geometry.polygon_obstacles,
                    &mut route_candidates,
                )?;
            }
            _ => {}
        }
    }
    let mut nets: Vec<_> = nets
        .into_values()
        .filter(|n| !n.terminals.is_empty())
        .collect();
    nets.sort_by_key(|n| n.id);
    let differential_pairs = infer_differential_pairs(&nets, &net_classes);
    let mut routes: Vec<_> = route_candidates.into_values().collect();
    routes.sort_by_key(|route| route.net_id);
    let mut board = Board {
        schema_version: pcbex_core::CURRENT_SCHEMA_VERSION,
        width_nm: coordinate_span(max.x_nm, min.x_nm),
        height_nm: coordinate_span(max.y_nm, min.y_nm),
        outline: outline
            .into_iter()
            .map(|point| relative(point, min))
            .collect(),
        cutouts: cutouts
            .into_iter()
            .map(|cutout| {
                cutout
                    .into_iter()
                    .map(|point| relative(point, min))
                    .collect()
            })
            .collect(),
        copper_layers,
        rules,
        obstacles,
        round_obstacles: footprint_geometry.round_obstacles,
        capsule_obstacles: footprint_geometry.capsule_obstacles,
        polygon_obstacles: footprint_geometry.polygon_obstacles,
        keepouts,
        footprints: footprint_geometry.footprints,
        net_classes,
        differential_pairs,
        length_groups: vec![],
        escape_groups: vec![],
        manufacturing_rules: None,
        return_path_rules: vec![],
        power_net_rules: vec![],
        stackup,
        via_strategy: pcbex_core::ViaStrategy::ThroughOnly,
        nets,
        routes,
    };
    let incomplete: HashSet<u32> = check_board(&board)
        .violations
        .iter()
        .filter(|violation| {
            matches!(
                violation.rule.as_str(),
                "unconnected" | "disconnected_route" | "orphan_copper"
            )
        })
        .flat_map(|violation| violation.net_ids.iter().copied())
        .collect();
    board
        .routes
        .retain(|route| !incomplete.contains(&route.net_id) || !route.zones.is_empty());
    let existing_route_net_ids = board.routes.iter().map(|route| route.net_id).collect();
    Ok(ImportedBoard {
        board,
        source: source.to_string(),
        origin: min,
        existing_route_net_ids,
    })
}

/// Apply net-class definitions and assignments from a modern `.kicad_pro`
/// project document. Values in KiCad project files are expressed in mm.
pub fn apply_project_net_settings(board: &mut Board, source: &str) -> Result<(), String> {
    let project: serde_json::Value = serde_json::from_str(source)
        .map_err(|error| format!("invalid KiCad project JSON: {error}"))?;
    let settings = project
        .get("net_settings")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "KiCad project does not contain net_settings".to_string())?;
    let classes = settings
        .get("classes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "KiCad project net_settings.classes is not an array".to_string())?;
    let mut net_classes = board.net_classes.clone();
    let mut nets = board.nets.clone();
    let mut project_class_names = HashSet::with_capacity(classes.len());

    for class in classes {
        let Some(class) = class.as_object() else {
            return Err("KiCad project contains a non-object net class".into());
        };
        let Some(name) = class.get("name").and_then(serde_json::Value::as_str) else {
            return Err("KiCad project net class is missing its name".into());
        };
        if name.trim().is_empty() {
            return Err("KiCad project net class name must not be blank".into());
        }
        if !project_class_names.insert(name) {
            return Err(format!("KiCad project contains duplicate net class {name}"));
        }
        let dimension = |key: &str, fallback: i64| -> Result<i64, String> {
            match class.get(key) {
                None | Some(serde_json::Value::Null) => Ok(fallback),
                Some(value) => value
                    .as_f64()
                    .and_then(checked_nonnegative_nm)
                    .ok_or_else(|| format!("net class {name} has invalid {key}")),
            }
        };
        let optional_dimension = |key: &str| -> Result<Option<i64>, String> {
            match class.get(key) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(value) => value
                    .as_f64()
                    .and_then(checked_nonnegative_nm)
                    .map(Some)
                    .ok_or_else(|| format!("net class {name} has invalid {key}")),
            }
        };
        let class_rules = NetClassRules {
            track_width_nm: dimension("track_width", board.rules.track_width_nm)?,
            clearance_nm: dimension("clearance", board.rules.clearance_nm)?,
            via_diameter_nm: dimension("via_diameter", board.rules.via_diameter_nm)?,
            via_drill_nm: dimension("via_drill", board.rules.via_drill_nm)?,
            layers: None,
            differential_width_nm: optional_dimension("diff_pair_width")?,
            differential_gap_nm: optional_dimension("diff_pair_gap")?,
            minimum_length_nm: optional_dimension("min_track_length")?,
            maximum_length_nm: optional_dimension("max_track_length")?,
            target_impedance_ohms: None,
            impedance_tolerance_ohms: None,
            maximum_impedance_step_ohms: None,
        };
        for (key, value) in [
            ("track_width", class_rules.track_width_nm),
            ("via_drill", class_rules.via_drill_nm),
        ] {
            if value <= 0 {
                return Err(format!("net class {name} has invalid {key}"));
            }
        }
        if class_rules.via_diameter_nm <= class_rules.via_drill_nm {
            return Err(format!(
                "net class {name} via_diameter must be greater than via_drill"
            ));
        }
        if class_rules
            .differential_width_nm
            .is_some_and(|width| width <= 0)
        {
            return Err(format!("net class {name} has invalid diff_pair_width"));
        }
        for (key, value) in [
            ("min_track_length", class_rules.minimum_length_nm),
            ("max_track_length", class_rules.maximum_length_nm),
        ] {
            if value.is_some_and(|length| length <= 0) {
                return Err(format!("net class {name} has invalid {key}"));
            }
        }
        if matches!(
            (
                class_rules.minimum_length_nm,
                class_rules.maximum_length_nm
            ),
            (Some(minimum), Some(maximum)) if minimum > maximum
        ) {
            return Err(format!(
                "net class {name} min_track_length must not exceed max_track_length"
            ));
        }
        net_classes.insert(name.to_string(), class_rules);
    }

    if let Some(patterns) = settings.get("netclass_patterns") {
        let patterns = patterns
            .as_array()
            .ok_or_else(|| "KiCad project netclass_patterns is not an array".to_string())?;
        let mut project_patterns = HashSet::with_capacity(patterns.len());
        for assignment in patterns.iter().rev() {
            let assignment = assignment.as_object().ok_or_else(|| {
                "KiCad project contains a non-object net-class pattern".to_string()
            })?;
            let pattern = assignment
                .get("pattern")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "net-class pattern is missing pattern".to_string())?;
            if pattern.trim().is_empty() {
                return Err("net-class pattern is blank".to_string());
            }
            if !project_patterns.insert(pattern) {
                return Err(format!(
                    "KiCad project contains duplicate net-class pattern {pattern}"
                ));
            }
            let class = assignment
                .get("netclass")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "net-class pattern is missing netclass".to_string())?;
            if class.trim().is_empty() {
                return Err(format!("net-class pattern {pattern} has blank netclass"));
            }
            if !net_classes.contains_key(class) {
                return Err(format!(
                    "net-class pattern {pattern} references unknown class {class}"
                ));
            }
            let matcher = compile_net_pattern(pattern)?;
            for net in &mut nets {
                if matcher.is_match(&net.name) {
                    net.class = Some(class.to_string());
                }
            }
        }
    }

    if let Some(assignments) = settings.get("netclass_assignments") {
        let assignments = assignments
            .as_object()
            .ok_or_else(|| "KiCad project netclass_assignments is not an object".to_string())?;
        for (net_name, class) in assignments {
            if net_name.trim().is_empty() {
                return Err("net-class assignment net name must not be blank".to_string());
            }
            let Some(class) = class.as_str() else {
                return Err(format!(
                    "net-class assignment for {net_name} is not a string"
                ));
            };
            if class.trim().is_empty() {
                return Err(format!(
                    "net-class assignment for {net_name} has blank netclass"
                ));
            }
            if !net_classes.contains_key(class) {
                return Err(format!(
                    "net-class assignment for {net_name} references unknown class {class}"
                ));
            }
            let Some(net) = nets.iter_mut().find(|net| net.name == *net_name) else {
                return Err(format!(
                    "net-class assignment references unknown net {net_name}"
                ));
            };
            net.class = Some(class.to_string());
        }
    }
    board.differential_pairs = infer_differential_pairs(&nets, &net_classes);
    board.net_classes = net_classes;
    board.nets = nets;
    Ok(())
}

fn compile_net_pattern(pattern: &str) -> Result<regex::Regex, String> {
    let looks_like_regex = pattern.starts_with('^')
        || pattern.ends_with('$')
        || pattern.contains('[')
        || pattern.contains('(')
        || pattern.contains('|')
        || pattern.contains('\\');
    let expression = if looks_like_regex {
        pattern.to_string()
    } else {
        let mut expression = String::from("^");
        for character in pattern.chars() {
            match character {
                '*' => expression.push_str(".*"),
                '?' => expression.push('.'),
                other => expression.push_str(&regex::escape(&other.to_string())),
            }
        }
        expression.push('$');
        expression
    };
    regex::Regex::new(&expression)
        .map_err(|error| format!("invalid KiCad net-class pattern {pattern}: {error}"))
}

/// Apply the routing-relevant subset of KiCad custom design rules whose
/// condition selects one NetClass. Unsupported rules remain KiCad's authority.
pub fn apply_custom_design_rules(board: &mut Board, source: &str) -> Result<usize, String> {
    let top = parse_sequence(source)?;
    let mut net_classes = board.net_classes.clone();
    let mut applied = 0;
    let mut via_modified_classes = Vec::new();
    for item in top {
        let Some(rule) = item.as_list() else { continue };
        if atom(rule.first()) != Some("rule") {
            continue;
        }
        let rule_name = atom(rule.get(1))
            .ok_or_else(|| "custom rule must contain one scalar name".to_string())?;
        if rule_name.trim().is_empty() {
            return Err("custom rule name must not be blank".to_string());
        }
        if rule.iter().skip(2).any(|value| value.as_list().is_none()) {
            return Err("custom rule must not contain extra scalar values".to_string());
        }
        let Some(condition) = custom_rule_condition(rule)? else {
            continue;
        };
        let Some(class_name) = condition_net_class(condition)? else {
            continue;
        };
        let Some(class) = net_classes.get_mut(&class_name) else {
            return Err(format!(
                "custom rule references unknown net class {class_name}"
            ));
        };
        let mut applied_kinds = HashSet::new();
        for item in rule {
            let Some(constraint) = item.as_list() else {
                continue;
            };
            if atom(constraint.first()) != Some("constraint") {
                continue;
            }
            let kind = atom(constraint.get(1))
                .ok_or_else(|| "custom constraint must contain one scalar type".to_string())?;
            if kind.trim().is_empty() {
                return Err("custom constraint type must not be blank".to_string());
            }
            if constraint
                .iter()
                .skip(2)
                .any(|value| value.as_list().is_none())
            {
                return Err("custom constraint must not contain extra scalar values".to_string());
            }
            if matches!(
                kind,
                "clearance"
                    | "track_width"
                    | "via_diameter"
                    | "hole_size"
                    | "diff_pair_gap"
                    | "length"
            ) && !applied_kinds.insert(kind)
            {
                return Err(format!("custom rule repeats {kind} constraint"));
            }
            match kind {
                "clearance" => class.clearance_nm = constraint_value(constraint, &["min"])?,
                "track_width" => {
                    let value = constraint_value(constraint, &["opt", "min"])?;
                    if value <= 0 {
                        return Err("custom rule track_width must be positive".into());
                    }
                    class.track_width_nm = value;
                }
                "via_diameter" => {
                    class.via_diameter_nm = constraint_value(constraint, &["opt", "min"])?;
                    if !via_modified_classes.contains(&class_name) {
                        via_modified_classes.push(class_name.clone());
                    }
                }
                "hole_size" => {
                    let value = constraint_value(constraint, &["opt", "min"])?;
                    if value <= 0 {
                        return Err("custom rule hole_size must be positive".into());
                    }
                    class.via_drill_nm = value;
                    if !via_modified_classes.contains(&class_name) {
                        via_modified_classes.push(class_name.clone());
                    }
                }
                "diff_pair_gap" => {
                    class.differential_gap_nm = Some(constraint_value(constraint, &["opt", "min"])?)
                }
                "length" => {
                    let minimum = constraint_optional_value(constraint, "min")?;
                    let maximum = constraint_optional_value(constraint, "max")?;
                    if minimum.is_none() && maximum.is_none() {
                        return Err("custom constraint length has no supported value".to_string());
                    }
                    for (name, value) in [("min", minimum), ("max", maximum)] {
                        if value.is_some_and(|length| length <= 0) {
                            return Err(format!("custom rule length {name} must be positive"));
                        }
                    }
                    if matches!(
                        (minimum, maximum),
                        (Some(minimum), Some(maximum)) if minimum > maximum
                    ) {
                        return Err("custom rule length min must not exceed max".to_string());
                    }
                    class.minimum_length_nm = minimum;
                    class.maximum_length_nm = maximum;
                }
                _ => continue,
            }
            applied += 1;
        }
    }
    for class_name in via_modified_classes {
        let class = &net_classes[&class_name];
        if class.via_diameter_nm <= class.via_drill_nm {
            return Err(format!(
                "custom rules leave net class {class_name} via_diameter not greater than hole_size"
            ));
        }
    }
    board.differential_pairs = infer_differential_pairs(&board.nets, &net_classes);
    board.net_classes = net_classes;
    Ok(applied)
}

fn custom_rule_condition(rule: &[Sexp]) -> Result<Option<&str>, String> {
    let mut matches = rule.iter().filter_map(|value| {
        let values = value.as_list()?;
        (atom(values.first()) == Some("condition")).then_some(values)
    });
    let Some(values) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err("custom rule condition must not be repeated".to_string());
    }
    if values.len() > 2 {
        return Err("custom rule condition must not contain extra expressions".to_string());
    }
    let condition = atom(values.get(1))
        .ok_or_else(|| "custom rule condition must contain one scalar expression".to_string())?;
    if condition.trim().is_empty() {
        return Err("custom rule condition must not be blank".to_string());
    }
    Ok(Some(condition))
}

fn condition_net_class(condition: &str) -> Result<Option<String>, String> {
    let condition = condition.trim_start();
    let Some(rest) = condition
        .strip_prefix("A.NetClass")
        .or_else(|| condition.strip_prefix("B.NetClass"))
    else {
        return Ok(None);
    };
    let rest = rest.trim_start();
    let rest = rest
        .strip_prefix("==")
        .ok_or_else(|| "custom rule NetClass condition must use the == operator".to_string())?;
    let rest = rest.trim_start();
    let quote = rest.chars().next().ok_or_else(|| {
        "custom rule NetClass condition must contain one quoted class name".to_string()
    })?;
    if quote != '\'' && quote != '"' {
        return Err(
            "custom rule NetClass condition must contain one quoted class name".to_string(),
        );
    }
    let quoted = &rest[quote.len_utf8()..];
    let Some(closing_quote) = quoted.find(quote) else {
        return Err("custom rule NetClass condition has an unterminated class name".to_string());
    };
    let trailing = &quoted[closing_quote + quote.len_utf8()..];
    if !trailing.trim().is_empty() {
        return Err(
            "custom rule NetClass condition must end after its quoted class name".to_string(),
        );
    }
    let class_name = &quoted[..closing_quote];
    if class_name.trim().is_empty() {
        return Err("custom rule NetClass condition class name must not be blank".to_string());
    }
    Ok(Some(class_name.to_string()))
}

fn constraint_value(constraint: &[Sexp], preferences: &[&str]) -> Result<i64, String> {
    let mut selected = None;
    for preference in preferences {
        let value = constraint_optional_value(constraint, preference)?;
        if selected.is_none() {
            selected = value;
        }
    }
    selected.ok_or_else(|| {
        format!(
            "custom constraint {} has no supported value",
            atom(constraint.get(1)).unwrap_or("unknown")
        )
    })
}

fn constraint_optional_value(constraint: &[Sexp], name: &str) -> Result<Option<i64>, String> {
    let mut matches = constraint.iter().filter_map(|value| {
        let values = value.as_list()?;
        (atom(values.first()) == Some(name)).then_some(values)
    });
    let Some(values) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(format!(
            "custom constraint {name} value must not be repeated"
        ));
    }
    if values.len() > 2 {
        return Err(format!(
            "custom constraint {name} value must contain exactly one dimension"
        ));
    }
    let token =
        atom(values.get(1)).ok_or_else(|| format!("custom constraint {name} value is missing"))?;
    let millimetres = if let Some(value) = token.strip_suffix("mm") {
        value.parse::<f64>()
    } else if let Some(value) = token.strip_suffix("mil") {
        value.parse::<f64>().map(|value| value * 0.0254)
    } else {
        token.parse::<f64>()
    }
    .map_err(|_| format!("invalid custom-rule dimension {token}"))?;
    checked_nonnegative_nm(millimetres)
        .map(Some)
        .ok_or_else(|| format!("invalid custom-rule dimension {token}"))
}

fn import_net_classes(
    top: &[Sexp],
    defaults: &Rules,
    nets: &mut HashMap<u32, Net>,
) -> Result<HashMap<String, NetClassRules>, String> {
    let mut classes = HashMap::new();
    let net_ids_by_name: HashMap<_, _> = nets
        .iter()
        .map(|(id, net)| (net.name.clone(), *id))
        .collect();
    let mut class_by_net_id = HashMap::<u32, String>::new();
    for item in top {
        let Some(setup) = item.as_list() else {
            continue;
        };
        if atom(setup.first()) != Some("setup") {
            continue;
        }
        for item in setup {
            let Some(values) = item.as_list() else {
                continue;
            };
            if atom(values.first()) != Some("net_class") {
                continue;
            }
            let Some(name) = atom(values.get(1)) else {
                return Err("KiCad board net class is missing its name".into());
            };
            if name.trim().is_empty() {
                return Err("KiCad board net class name must not be blank".into());
            }
            if atom(values.get(2)).is_none() {
                return Err(format!(
                    "KiCad board net class {name} is missing a scalar description"
                ));
            }
            if values.iter().skip(3).any(|value| value.as_list().is_none()) {
                return Err(format!(
                    "KiCad board net class {name} contains an unexpected scalar value"
                ));
            }
            if classes.contains_key(name) {
                return Err(format!("KiCad board contains duplicate net class {name}"));
            }
            for key in [
                "trace_width",
                "clearance",
                "via_dia",
                "via_drill",
                "diff_pair_width",
                "diff_pair_gap",
            ] {
                let count = values
                    .iter()
                    .filter_map(Sexp::as_list)
                    .filter(|value| atom(value.first()) == Some(key))
                    .count();
                if count > 1 {
                    return Err(format!("net class {name} contains duplicate {key}"));
                }
            }
            let dimension = |key: &str, fallback: i64| -> Result<i64, String> {
                let Some(value) = child_values(values, key) else {
                    return Ok(fallback);
                };
                if value.len() != 2 {
                    return Err(format!("net class {name} has invalid {key}"));
                }
                number(value.get(1))
                    .and_then(checked_nonnegative_nm)
                    .ok_or_else(|| format!("net class {name} has invalid {key}"))
            };
            let optional_dimension = |key: &str| -> Result<Option<i64>, String> {
                let Some(value) = child_values(values, key) else {
                    return Ok(None);
                };
                if value.len() != 2 {
                    return Err(format!("net class {name} has invalid {key}"));
                }
                number(value.get(1))
                    .and_then(checked_nonnegative_nm)
                    .map(Some)
                    .ok_or_else(|| format!("net class {name} has invalid {key}"))
            };
            let class_rules = NetClassRules {
                track_width_nm: dimension("trace_width", defaults.track_width_nm)?,
                clearance_nm: dimension("clearance", defaults.clearance_nm)?,
                via_diameter_nm: dimension("via_dia", defaults.via_diameter_nm)?,
                via_drill_nm: dimension("via_drill", defaults.via_drill_nm)?,
                layers: None,
                differential_width_nm: optional_dimension("diff_pair_width")?,
                differential_gap_nm: optional_dimension("diff_pair_gap")?,
                minimum_length_nm: None,
                maximum_length_nm: None,
                target_impedance_ohms: None,
                impedance_tolerance_ohms: None,
                maximum_impedance_step_ohms: None,
            };
            for (key, value) in [
                ("trace_width", class_rules.track_width_nm),
                ("via_drill", class_rules.via_drill_nm),
            ] {
                if value <= 0 {
                    return Err(format!("net class {name} has invalid {key}"));
                }
            }
            if class_rules.via_diameter_nm <= class_rules.via_drill_nm {
                return Err(format!(
                    "net class {name} via_dia must be greater than via_drill"
                ));
            }
            if class_rules
                .differential_width_nm
                .is_some_and(|width| width <= 0)
            {
                return Err(format!("net class {name} has invalid diff_pair_width"));
            }
            classes.insert(name.to_string(), class_rules);
            for child in values {
                let Some(assignment) = child.as_list() else {
                    continue;
                };
                if atom(assignment.first()) != Some("add_net") {
                    continue;
                }
                let Some(net_name) = atom(assignment.get(1)) else {
                    return Err(format!(
                        "net class {name} contains add_net without a scalar net name"
                    ));
                };
                if assignment.len() > 2 {
                    return Err(format!(
                        "net class {name} add_net must contain exactly one net name"
                    ));
                }
                if net_name.trim().is_empty() {
                    return Err(format!("net class {name} add_net name must not be blank"));
                }
                let Some(net_id) = net_ids_by_name.get(net_name) else {
                    return Err(format!(
                        "net class {name} references unknown net {net_name}"
                    ));
                };
                if let Some(previous) = class_by_net_id.get(net_id) {
                    if previous == name {
                        return Err(format!(
                            "net class {name} contains duplicate add_net assignment for {net_name}"
                        ));
                    }
                    return Err(format!(
                        "net {net_name} is assigned to multiple legacy net classes: \
                         {previous} and {name}"
                    ));
                }
                class_by_net_id.insert(*net_id, name.to_string());
                if let Some(net) = nets.get_mut(net_id) {
                    net.class = Some(name.to_string());
                }
            }
        }
    }
    Ok(classes)
}

fn infer_differential_pairs(
    nets: &[Net],
    classes: &HashMap<String, NetClassRules>,
) -> Vec<DifferentialPair> {
    let mut candidates = HashMap::<(String, String), (Option<u32>, Option<u32>)>::new();
    for net in nets {
        let Some(class_name) = net.class.as_ref() else {
            continue;
        };
        let Some(class) = classes.get(class_name) else {
            continue;
        };
        if class.differential_gap_nm.is_none() || class.differential_width_nm.is_none() {
            continue;
        }
        let polarity = [("_P", true), ("_N", false), ("+", true), ("-", false)]
            .into_iter()
            .find_map(|(suffix, positive)| {
                net.name
                    .strip_suffix(suffix)
                    .map(|base| (base.to_string(), positive))
            });
        let Some((base, positive)) = polarity else {
            continue;
        };
        let entry = candidates
            .entry((class_name.clone(), base))
            .or_insert((None, None));
        if positive {
            entry.0 = Some(net.id);
        } else {
            entry.1 = Some(net.id);
        }
    }
    let mut pairs: Vec<_> = candidates
        .into_iter()
        .filter_map(|((class_name, base), (positive, negative))| {
            let class = classes.get(&class_name)?;
            Some(DifferentialPair {
                name: base,
                positive_net_id: positive?,
                negative_net_id: negative?,
                gap_nm: class.differential_gap_nm?,
                gap_tolerance_nm: 100_000,
                max_skew_nm: 500_000,
                min_coupled_percent: 80,
                target_differential_impedance_ohms: None,
                differential_impedance_tolerance_ohms: None,
                maximum_differential_impedance_step_ohms: None,
                minimum_length_nm: None,
                tuning_amplitude_nm: None,
                tuning_pitch_nm: None,
                max_tuning_sections: 1,
            })
        })
        .collect();
    pairs.sort_by(|left, right| left.name.cmp(&right.name));
    pairs
}

impl ImportedBoard {
    pub fn origin(&self) -> Point {
        self.origin
    }

    pub fn placement_problem(&self, grid_nm: i64) -> Result<PlacementProblem, String> {
        if grid_nm <= 0 {
            return Err("placement grid must be positive".into());
        }
        let root = parse(&self.source)?;
        let top = root.as_list().ok_or("invalid KiCad document")?;
        let fixed: HashSet<String> = top
            .iter()
            .filter_map(|item| {
                let values = item.as_list()?;
                (atom(values.first()) == Some("footprint") && footprint_is_locked(values))
                    .then(|| footprint_reference(values))
            })
            .collect();
        let mut courtyards = HashMap::<String, Vec<Point>>::new();
        for item in top {
            let Some(values) = item.as_list() else {
                continue;
            };
            if atom(values.first()) != Some("footprint") {
                continue;
            }
            if let Some(polygon) = courtyard_polygon_local(values)? {
                courtyards.insert(footprint_reference(values), polygon);
            }
        }
        let mut sides = Vec::new();
        let mut side_references = HashSet::new();
        for item in top {
            let Some(values) = item.as_list() else {
                continue;
            };
            if atom(values.first()) != Some("footprint") {
                continue;
            }
            let reference = footprint_reference(values);
            let side = footprint_side(values)?;
            if !reference.trim().is_empty() && !side_references.insert(reference.clone()) {
                return Err(format!("duplicate footprint reference: {reference}"));
            }
            sides.push(side);
        }
        let mut components = Vec::with_capacity(self.board.footprints.len());
        let mut net_pins = HashMap::<u32, Vec<PinRef>>::new();
        for (footprint_index, footprint) in self.board.footprints.iter().enumerate() {
            if footprint.reference.is_empty() {
                return Err("every footprint requires a Reference property for placement".into());
            }
            let mut min_x = 0;
            let mut min_y = 0;
            let mut max_x = 0;
            let mut max_y = 0;
            for pad in &footprint.pads {
                let dx = mm(relative_coordinate(
                    pad.position.x_nm,
                    footprint.position.x_nm,
                ));
                let dy = mm(relative_coordinate(
                    pad.position.y_nm,
                    footprint.position.y_nm,
                ));
                let (local_x, local_y) = rotate(dx, dy, -footprint.rotation_deg);
                let local = point_mm_checked(local_x, local_y)?;
                min_x = min_x.min(local.x_nm.saturating_sub(pad.width_nm / 2));
                min_y = min_y.min(local.y_nm.saturating_sub(pad.height_nm / 2));
                max_x = max_x.max(local.x_nm.saturating_add(pad.width_nm / 2));
                max_y = max_y.max(local.y_nm.saturating_add(pad.height_nm / 2));
                if let Some(net_id) = pad.net_id {
                    net_pins.entry(net_id).or_default().push(PinRef {
                        component: footprint.reference.clone(),
                        offset: local,
                    });
                }
            }
            let courtyard = courtyards
                .get(&footprint.reference)
                .cloned()
                .unwrap_or_default();
            let (width_nm, height_nm) = polygon_size(&courtyard).unwrap_or((
                coordinate_span(max_x, min_x).max(1_000_000),
                coordinate_span(max_y, min_y).max(1_000_000),
            ));
            components.push(Component {
                reference: footprint.reference.clone(),
                width_nm,
                height_nm,
                position: Some(footprint.position),
                rotation_deg: footprint.rotation_deg.round().rem_euclid(360.0) as u16,
                fixed: fixed.contains(&footprint.reference),
                side: *sides.get(footprint_index).ok_or_else(|| {
                    format!("footprint {} has no valid layer", footprint.reference)
                })?,
                allowed_rotations: vec![0, 90, 180, 270],
                allow_side_flip: true,
                courtyard,
                anchors: HashMap::new(),
            });
        }
        let mut connections = Vec::new();
        for pins in net_pins.into_values() {
            if let Some(first) = pins.first() {
                connections.extend(pins.iter().skip(1).map(|pin| Connection {
                    from: first.clone(),
                    to: pin.clone(),
                    weight: 1.0,
                }));
            }
        }
        Ok(PlacementProblem {
            width_nm: self.board.width_nm,
            height_nm: self.board.height_nm,
            grid_nm,
            components,
            connections,
            constraints: vec![],
        })
    }

    pub fn write_placements(&self, components: &[Component]) -> Result<String, String> {
        let by_reference: HashMap<_, _> = components
            .iter()
            .map(|component| (component.reference.as_str(), component))
            .collect();
        if by_reference.len() != components.len() {
            return Err("placement component references must be unique".into());
        }
        let mut replacements = Vec::new();
        let mut replaced = HashSet::new();
        for (start, end) in top_level_list_spans(&self.source, "footprint")? {
            let footprint = parse(&self.source[start..end])?;
            let values = footprint.as_list().ok_or("invalid footprint")?;
            let reference = footprint_reference(values);
            let Some(component) = by_reference.get(reference.as_str()) else {
                continue;
            };
            if !replaced.insert(reference.clone()) {
                return Err(format!("duplicate footprint reference: {reference}"));
            }
            let position = component
                .position
                .ok_or_else(|| format!("component {reference} has no position"))?;
            let absolute = self.absolute(position);
            let (at_start, at_end) = direct_child_list_span(&self.source[start..end], "at")?
                .ok_or_else(|| format!("footprint {reference} has no at field"))?;
            let mut replacement = self.source[start..end].to_string();
            replacement.replace_range(
                at_start..at_end,
                &format!(
                    "(at {:.6} {:.6} {})",
                    mm(absolute.x_nm),
                    mm(absolute.y_nm),
                    component.rotation_deg
                ),
            );
            let source_side = footprint_side(values)?;
            if source_side != component.side {
                replacement = swap_front_back_layers(&replacement);
            }
            replacements.push((start, end, replacement));
        }
        if replaced.len() != components.len() {
            let missing = by_reference
                .keys()
                .find(|reference| !replaced.contains(**reference))
                .copied()
                .unwrap_or("");
            return Err(format!("placement references unknown footprint: {missing}"));
        }
        let mut output = self.source.clone();
        replacements.sort_by_key(|replacement| std::cmp::Reverse(replacement.0));
        for (start, end, replacement) in replacements {
            output.replace_range(start..end, &replacement);
        }
        Ok(output)
    }

    pub fn write_routes(&self, routes: &[Route]) -> Result<String, String> {
        let closing = self.source.rfind(')').ok_or("invalid KiCad document")?;
        let mut generated = String::new();
        for route in routes {
            if self.existing_route_net_ids.contains(&route.net_id) {
                continue;
            }
            for segment in &route.segments {
                let start = self.absolute(segment.start);
                let end = self.absolute(segment.end);
                writeln!(
                    generated,
                    "  (segment (start {:.6} {:.6}) (end {:.6} {:.6}) (width {:.6}) (layer \"{}\") (net {}))",
                    mm(start.x_nm), mm(start.y_nm), mm(end.x_nm), mm(end.y_nm),
                    mm(segment.width_nm), layer_name(segment.layer), route.net_id
                ).map_err(|e| e.to_string())?;
            }
            for arc in &route.arcs {
                let start = self.absolute(arc.start);
                let mid = self.absolute(arc.mid);
                let end = self.absolute(arc.end);
                writeln!(
                    generated,
                    "  (arc (start {:.6} {:.6}) (mid {:.6} {:.6}) (end {:.6} {:.6}) (width {:.6}) (layer \"{}\") (net {}))",
                    mm(start.x_nm), mm(start.y_nm), mm(mid.x_nm), mm(mid.y_nm),
                    mm(end.x_nm), mm(end.y_nm), mm(arc.width_nm), layer_name(arc.layer),
                    route.net_id
                ).map_err(|e| e.to_string())?;
            }
            for via in &route.vias {
                let at = self.absolute(via.position);
                let kind = match via.kind {
                    ViaKind::Through => "",
                    ViaKind::BlindBuried => " blind",
                    ViaKind::Micro => " micro",
                };
                writeln!(
                    generated,
                    "  (via{kind} (at {:.6} {:.6}) (size {:.6}) (drill {:.6}) (layers \"{}\" \"{}\") (net {}))",
                    mm(at.x_nm), mm(at.y_nm), mm(via.diameter_nm), mm(via.drill_nm),
                    layer_name(via.start_layer), layer_name(via.end_layer), route.net_id
                ).map_err(|e| e.to_string())?;
            }
            for teardrop in &route.teardrops {
                if teardrop.polygon.len() < 3 {
                    return Err("teardrop polygon must contain at least three points".into());
                }
                write!(
                    generated,
                    "  (zone (net {}) (net_name \"\") (layer \"{}\") (hatch edge 0.5) (attr (teardrop (type padvia))) (polygon (pts",
                    route.net_id,
                    layer_name(teardrop.layer)
                )
                .map_err(|e| e.to_string())?;
                for point in &teardrop.polygon {
                    let point = self.absolute(*point);
                    write!(
                        generated,
                        " (xy {:.6} {:.6})",
                        mm(point.x_nm),
                        mm(point.y_nm)
                    )
                    .map_err(|e| e.to_string())?;
                }
                writeln!(
                    generated,
                    ")) (fill yes (thermal_gap 0.3) (thermal_bridge_width 0.3)))"
                )
                .map_err(|e| e.to_string())?;
            }
            for zone in &route.zones {
                if zone.polygon.len() < 3 || zone.clearance_nm < 0 || zone.minimum_thickness_nm <= 0
                {
                    return Err("copper zone has invalid geometry or dimensions".into());
                }
                let net_name = self
                    .board
                    .nets
                    .iter()
                    .find(|net| net.id == route.net_id)
                    .map(|net| net.name.as_str())
                    .unwrap_or("");
                write!(
                    generated,
                    "  (zone (net {}) (net_name \"{}\") (layer \"{}\") (hatch edge 0.5) (connect_pads (clearance {:.6})) (min_thickness {:.6}) (polygon (pts",
                    route.net_id,
                    net_name,
                    layer_name(zone.layer),
                    mm(zone.clearance_nm),
                    mm(zone.minimum_thickness_nm)
                )
                .map_err(|e| e.to_string())?;
                for point in &zone.polygon {
                    let point = self.absolute(*point);
                    write!(
                        generated,
                        " (xy {:.6} {:.6})",
                        mm(point.x_nm),
                        mm(point.y_nm)
                    )
                    .map_err(|e| e.to_string())?;
                }
                write!(
                    generated,
                    ")) (fill yes (thermal_gap {:.6}) (thermal_bridge_width {:.6}))",
                    mm(zone.thermal_gap_nm),
                    mm(zone.thermal_spoke_width_nm)
                )
                .map_err(|e| e.to_string())?;
                for polygon in &zone.filled_polygons {
                    write!(
                        generated,
                        " (filled_polygon (layer \"{}\") (pts",
                        layer_name(zone.layer)
                    )
                    .map_err(|e| e.to_string())?;
                    for point in polygon {
                        let point = self.absolute(*point);
                        write!(
                            generated,
                            " (xy {:.6} {:.6})",
                            mm(point.x_nm),
                            mm(point.y_nm)
                        )
                        .map_err(|e| e.to_string())?;
                    }
                    write!(generated, "))").map_err(|e| e.to_string())?;
                }
                writeln!(generated, ")").map_err(|e| e.to_string())?;
            }
        }
        if generated.is_empty() {
            return Ok(self.source.clone());
        }
        if !self.source[..closing].ends_with('\n') {
            generated.insert(0, '\n');
        }
        let mut output = self.source.clone();
        output.insert_str(closing, &generated);
        Ok(output)
    }

    fn absolute(&self, point: Point) -> Point {
        Point {
            x_nm: point.x_nm.saturating_add(self.origin.x_nm),
            y_nm: point.y_nm.saturating_add(self.origin.y_nm),
        }
    }
}

fn swap_front_back_layers(source: &str) -> String {
    source
        .replace("\"F.", "\"__PCBEX_SIDE__.")
        .replace("\"B.", "\"F.")
        .replace("\"__PCBEX_SIDE__.", "\"B.")
}

fn courtyard_polygon_local(footprint: &[Sexp]) -> Result<Option<Vec<Point>>, String> {
    for item in footprint {
        let Some(values) = item.as_list() else {
            continue;
        };
        if atom(values.first()) != Some("fp_poly")
            || !matches!(
                child_atom(values, "layer"),
                Some("F.CrtYd") | Some("B.CrtYd")
            )
        {
            continue;
        }
        let Some(points) =
            unique_physical_child_values(values, "pts", "courtyard polygon point list")?
        else {
            return Err("courtyard polygon is missing its point list".into());
        };
        let mut polygon = Vec::new();
        for point in points.iter().skip(1) {
            let Some(xy) = point.as_list() else {
                return Err("courtyard polygon points must be xy coordinates".into());
            };
            if atom(xy.first()) != Some("xy") || xy.len() != 3 {
                return Err("courtyard polygon points must be xy coordinates".into());
            }
            let x = scalar_f64(xy.get(1), "courtyard polygon X coordinate")?;
            let y = scalar_f64(xy.get(2), "courtyard polygon Y coordinate")?;
            polygon.push(Point {
                x_nm: checked_mm_to_nm(x, "courtyard polygon X coordinate", true, false)?,
                y_nm: checked_mm_to_nm(y, "courtyard polygon Y coordinate", true, false)?,
            });
        }
        if polygon.len() >= 3 {
            return Ok(Some(polygon));
        }
        return Err("courtyard polygon must contain at least three points".into());
    }
    let mut min_x = f64::INFINITY;
    let mut min_y = f64::INFINITY;
    let mut max_x = f64::NEG_INFINITY;
    let mut max_y = f64::NEG_INFINITY;
    for item in footprint {
        let Some(values) = item.as_list() else {
            continue;
        };
        if !matches!(atom(values.first()), Some("fp_rect") | Some("fp_line"))
            || !matches!(
                child_atom(values, "layer"),
                Some("F.CrtYd") | Some("B.CrtYd")
            )
        {
            continue;
        }
        for key in ["start", "end"] {
            let Some(point) =
                unique_physical_child_values(values, key, &format!("courtyard {key} point"))?
            else {
                return Err(format!("courtyard {key} point is missing"));
            };
            if point.len() != 3 {
                return Err(format!("courtyard {key} point is missing coordinates"));
            }
            let x = scalar_f64(point.get(1), &format!("courtyard {key} X coordinate"))?;
            let y = scalar_f64(point.get(2), &format!("courtyard {key} Y coordinate"))?;
            checked_mm_to_nm(x, &format!("courtyard {key} X coordinate"), true, false)?;
            checked_mm_to_nm(y, &format!("courtyard {key} Y coordinate"), true, false)?;
            min_x = min_x.min(x);
            min_y = min_y.min(y);
            max_x = max_x.max(x);
            max_y = max_y.max(y);
        }
    }
    if !min_x.is_finite() {
        return Ok(None);
    }
    Ok(Some(vec![
        Point {
            x_nm: checked_mm_to_nm(min_x, "courtyard X coordinate", true, false)?,
            y_nm: checked_mm_to_nm(min_y, "courtyard Y coordinate", true, false)?,
        },
        Point {
            x_nm: checked_mm_to_nm(max_x, "courtyard X coordinate", true, false)?,
            y_nm: checked_mm_to_nm(min_y, "courtyard Y coordinate", true, false)?,
        },
        Point {
            x_nm: checked_mm_to_nm(max_x, "courtyard X coordinate", true, false)?,
            y_nm: checked_mm_to_nm(max_y, "courtyard Y coordinate", true, false)?,
        },
        Point {
            x_nm: checked_mm_to_nm(min_x, "courtyard X coordinate", true, false)?,
            y_nm: checked_mm_to_nm(max_y, "courtyard Y coordinate", true, false)?,
        },
    ]))
}

fn polygon_size(polygon: &[Point]) -> Option<(i64, i64)> {
    let minimum_x = polygon.iter().map(|point| point.x_nm).min()?;
    let maximum_x = polygon.iter().map(|point| point.x_nm).max()?;
    let minimum_y = polygon.iter().map(|point| point.y_nm).min()?;
    let maximum_y = polygon.iter().map(|point| point.y_nm).max()?;
    Some((
        coordinate_span(maximum_x, minimum_x),
        coordinate_span(maximum_y, minimum_y),
    ))
}

fn footprint_is_locked(values: &[Sexp]) -> bool {
    values.iter().any(|item| match item {
        Sexp::Atom(value) => value == "locked",
        Sexp::List(child) => {
            atom(child.first()) == Some("locked")
                && !matches!(atom(child.get(1)), Some("no") | Some("false"))
        }
    })
}

fn top_level_list_spans(source: &str, name: &str) -> Result<Vec<(usize, usize)>, String> {
    list_spans(source, name, 2)
}

fn direct_child_list_span(source: &str, name: &str) -> Result<Option<(usize, usize)>, String> {
    Ok(list_spans(source, name, 2)?.into_iter().next())
}

fn board_bounds(top: &[Sexp]) -> Result<BoardGeometry, String> {
    let mut lines = Vec::new();
    let mut unique_edges = HashSet::new();
    for item in top {
        let Some(xs) = item.as_list() else { continue };
        if !is_edge_cuts_primitive(xs)? {
            continue;
        }
        match atom(xs.first()) {
            Some("gr_line") => {
                let (Some(start), Some(end)) =
                    (edge_child_point(xs, "start")?, edge_child_point(xs, "end")?)
                else {
                    return Err("Edge.Cuts line requires start and end points".into());
                };
                if start == end {
                    return Err("Edge.Cuts line must have distinct endpoints".into());
                }
                push_unique_edge(&mut lines, &mut unique_edges, start, end)?;
            }
            Some("gr_arc") => {
                let (Some(start), Some(mid), Some(end)) = (
                    edge_child_point(xs, "start")?,
                    edge_child_point(xs, "mid")?,
                    edge_child_point(xs, "end")?,
                ) else {
                    return Err("Edge.Cuts arc requires start, mid, and end points".into());
                };
                if start == mid || mid == end || start == end {
                    return Err("Edge.Cuts arc points must be distinct".into());
                }
                for pair in sample_arc(start, mid, end)?.windows(2) {
                    push_unique_edge(&mut lines, &mut unique_edges, pair[0], pair[1])?;
                }
            }
            Some("gr_circle") => {
                let (Some(center), Some(end)) = (
                    edge_child_point(xs, "center")?,
                    edge_child_point(xs, "end")?,
                ) else {
                    return Err("Edge.Cuts circle requires center and end points".into());
                };
                let points = sample_circle(center, end)?;
                for index in 0..points.len() {
                    push_unique_edge(
                        &mut lines,
                        &mut unique_edges,
                        points[index],
                        points[(index + 1) % points.len()],
                    )?;
                }
            }
            Some("gr_curve") => {
                let points = sample_curve(xs)?;
                for pair in points.windows(2) {
                    push_unique_edge(&mut lines, &mut unique_edges, pair[0], pair[1])?;
                }
            }
            Some("gr_rect") => {
                let (Some(start), Some(end)) =
                    (edge_child_point(xs, "start")?, edge_child_point(xs, "end")?)
                else {
                    return Err("Edge.Cuts rectangle requires start and end points".into());
                };
                if start.x_nm == end.x_nm || start.y_nm == end.y_nm {
                    return Err("Edge.Cuts rectangle must have nonzero width and height".into());
                }
                let top_right = Point {
                    x_nm: end.x_nm,
                    y_nm: start.y_nm,
                };
                let bottom_left = Point {
                    x_nm: start.x_nm,
                    y_nm: end.y_nm,
                };
                for (edge_start, edge_end) in [
                    (start, top_right),
                    (top_right, end),
                    (end, bottom_left),
                    (bottom_left, start),
                ] {
                    push_unique_edge(&mut lines, &mut unique_edges, edge_start, edge_end)?;
                }
            }
            Some("gr_poly") => {
                let points = edge_polygon_points(xs)?;
                for index in 0..points.len() {
                    push_unique_edge(
                        &mut lines,
                        &mut unique_edges,
                        points[index],
                        points[(index + 1) % points.len()],
                    )?;
                }
            }
            _ => {}
        }
    }
    let mut contours = if lines.is_empty() {
        let mut rectangles = Vec::new();
        for item in top {
            let Some(xs) = item.as_list() else { continue };
            if atom(xs.first()) == Some("gr_rect") && child_atom(xs, "layer") == Some("Edge.Cuts") {
                let start = edge_child_point(xs, "start")?.ok_or_else(|| {
                    "Edge.Cuts rectangle requires start and end points".to_string()
                })?;
                let end = edge_child_point(xs, "end")?.ok_or_else(|| {
                    "Edge.Cuts rectangle requires start and end points".to_string()
                })?;
                rectangles.push((start, end));
            }
        }
        if rectangles.is_empty() {
            return Err("at least one closed Edge.Cuts outline is required".into());
        }
        rectangles
            .into_iter()
            .map(|(start, end)| {
                vec![
                    start,
                    Point {
                        x_nm: end.x_nm,
                        y_nm: start.y_nm,
                    },
                    end,
                    Point {
                        x_nm: start.x_nm,
                        y_nm: end.y_nm,
                    },
                ]
            })
            .collect()
    } else {
        assemble_contours(lines)?
    };
    contours
        .sort_by_key(|contour| std::cmp::Reverse(polygon_twice_area(contour).unsigned_magnitude()));
    if contours
        .iter()
        .any(|contour| contour_self_intersects(contour))
    {
        return Err("Edge.Cuts contours must not self-intersect".into());
    }
    let outline = contours.remove(0);
    let cutouts = contours;
    let min = Point {
        x_nm: outline.iter().map(|p| p.x_nm).min().unwrap(),
        y_nm: outline.iter().map(|p| p.y_nm).min().unwrap(),
    };
    let max = Point {
        x_nm: outline.iter().map(|p| p.x_nm).max().unwrap(),
        y_nm: outline.iter().map(|p| p.y_nm).max().unwrap(),
    };
    let twice_area = polygon_twice_area(&outline);
    if min == max || twice_area.is_zero() {
        return Err("Edge.Cuts outline has zero area".into());
    }
    if cutouts.iter().any(|cutout| {
        polygon_twice_area(cutout).is_zero()
            || cutout
                .iter()
                .any(|point| !point_in_polygon(*point, &outline))
            || contours_intersect(cutout, &outline)
    }) {
        return Err("Edge.Cuts cutouts must be inside the outer outline".into());
    }
    if cutouts_conflict(&cutouts) {
        return Err("Edge.Cuts cutouts must not overlap or nest".into());
    }
    Ok(BoardGeometry {
        min,
        max,
        outline,
        cutouts,
    })
}

fn edge_polygon_points(values: &[Sexp]) -> Result<Vec<Point>, String> {
    let Some(points) = unique_edge_child_values(values, "pts")? else {
        return Err("Edge.Cuts polygon requires a pts list".into());
    };
    if points.len().saturating_sub(1) > MAX_EDGE_POLYGON_POINTS {
        return Err("Edge.Cuts polygon contains too many points".into());
    }
    let mut polygon = points
        .iter()
        .skip(1)
        .map(|value| {
            let Some(xy) = value.as_list() else {
                return Err("Edge.Cuts polygon points must be xy coordinates".into());
            };
            if atom(xy.first()) != Some("xy") || xy.len() != 3 {
                return Err("Edge.Cuts polygon points must be xy coordinates".into());
            }
            let (Some(x), Some(y)) = (number(xy.get(1)), number(xy.get(2))) else {
                return Err("Edge.Cuts polygon points must be xy coordinates".into());
            };
            if !x.is_finite() || !y.is_finite() {
                return Err("Edge.Cuts polygon coordinates must be finite".into());
            }
            edge_point_mm(x, y)
        })
        .collect::<Result<Vec<_>, String>>()?;
    if polygon.first() == polygon.last() {
        polygon.pop();
    }
    if polygon.len() < 3 {
        return Err("Edge.Cuts polygon must contain at least three distinct points".into());
    }
    if polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
        .any(|(start, end)| start == end)
    {
        return Err("Edge.Cuts polygon must contain distinct adjacent points".into());
    }
    if polygon.iter().collect::<HashSet<_>>().len() != polygon.len() {
        return Err("Edge.Cuts polygon vertices must be distinct".into());
    }
    if contour_self_intersects(&polygon) {
        return Err("Edge.Cuts polygon must not self-intersect".into());
    }
    if polygon_twice_area(&polygon).is_zero() {
        return Err("Edge.Cuts polygon must have nonzero area".into());
    }
    Ok(polygon)
}

fn push_unique_edge(
    lines: &mut Vec<(Point, Point)>,
    unique_edges: &mut HashSet<(Point, Point)>,
    start: Point,
    end: Point,
) -> Result<(), String> {
    if start == end {
        return Err("Edge.Cuts edges must have distinct endpoints".into());
    }
    if lines.len() >= MAX_EDGE_SEGMENTS {
        return Err("Edge.Cuts contains too many segments".into());
    }
    let key = if (start.x_nm, start.y_nm) <= (end.x_nm, end.y_nm) {
        (start, end)
    } else {
        (end, start)
    };
    if !unique_edges.insert(key) {
        return Err("Edge.Cuts contains a duplicate edge".into());
    }
    lines.push((start, end));
    Ok(())
}

fn assemble_contours(lines: Vec<(Point, Point)>) -> Result<Vec<Vec<Point>>, String> {
    let mut incident = HashMap::<Point, Vec<usize>>::new();
    for (index, (start, end)) in lines.iter().enumerate() {
        incident.entry(*start).or_default().push(index);
        incident.entry(*end).or_default().push(index);
    }
    if incident.values().any(|edges| edges.len() != 2) {
        return Err("each Edge.Cuts contour vertex must join exactly two primitives".into());
    }

    let mut used = vec![false; lines.len()];
    let mut contours = Vec::new();
    for seed in 0..lines.len() {
        if used[seed] {
            continue;
        }
        used[seed] = true;
        let (start, mut current) = lines[seed];
        let mut ordered = vec![start];
        while current != start {
            ordered.push(current);
            let Some(index) = incident.get_mut(&current).and_then(|edges| {
                while let Some(index) = edges.pop() {
                    if !used[index] {
                        return Some(index);
                    }
                }
                None
            }) else {
                return Err("Edge.Cuts primitives do not form closed contours".into());
            };
            used[index] = true;
            let (edge_start, edge_end) = lines[index];
            current = if edge_start == current {
                edge_end
            } else {
                edge_start
            };
        }
        if ordered.len() < 3 {
            return Err("Edge.Cuts contour requires at least three points".into());
        }
        contours.push(ordered);
    }
    Ok(contours)
}

#[derive(Clone, Copy)]
struct WideArea {
    high: u128,
    low: u128,
}

impl WideArea {
    fn add_i128(self, value: i128) -> Self {
        let (low, carry) = self.low.overflowing_add(value as u128);
        let sign_extension = if value < 0 { u128::MAX } else { 0 };
        Self {
            high: self
                .high
                .wrapping_add(sign_extension)
                .wrapping_add(carry as u128),
            low,
        }
    }

    fn is_zero(self) -> bool {
        self.high == 0 && self.low == 0
    }

    fn is_positive(self) -> bool {
        self.high >> 127 == 0 && !self.is_zero()
    }

    fn is_negative(self) -> bool {
        self.high >> 127 != 0
    }

    fn unsigned_magnitude(self) -> (u128, u128) {
        if self.high >> 127 == 0 {
            (self.high, self.low)
        } else {
            let (low, carry) = (!self.low).overflowing_add(1);
            ((!self.high).wrapping_add(carry as u128), low)
        }
    }
}

fn polygon_twice_area(polygon: &[Point]) -> WideArea {
    polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
        .fold(WideArea { high: 0, low: 0 }, |area, (start, end)| {
            area.add_i128(start.x_nm as i128 * end.y_nm as i128)
                .add_i128(-(end.x_nm as i128 * start.y_nm as i128))
        })
}

fn point_in_polygon(point: Point, polygon: &[Point]) -> bool {
    let mut inside = false;
    for (start, end) in polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
    {
        let crosses_y = (start.y_nm > point.y_nm) != (end.y_nm > point.y_nm);
        let orientation = triangle_orientation(*start, *end, point);
        let crosses_right = if end.y_nm > start.y_nm {
            orientation.is_positive()
        } else {
            orientation.is_negative()
        };
        let crosses = crosses_y && crosses_right;
        if crosses {
            inside = !inside;
        }
    }
    inside
}

fn triangle_orientation(a: Point, b: Point, c: Point) -> WideArea {
    WideArea { high: 0, low: 0 }
        .add_i128(i128::from(a.x_nm) * i128::from(b.y_nm))
        .add_i128(i128::from(b.x_nm) * i128::from(c.y_nm))
        .add_i128(i128::from(c.x_nm) * i128::from(a.y_nm))
        .add_i128(-(i128::from(a.y_nm) * i128::from(b.x_nm)))
        .add_i128(-(i128::from(b.y_nm) * i128::from(c.x_nm)))
        .add_i128(-(i128::from(c.y_nm) * i128::from(a.x_nm)))
}

fn contours_intersect(left: &[Point], right: &[Point]) -> bool {
    left.iter()
        .zip(left.iter().cycle().skip(1))
        .take(left.len())
        .any(|(left_start, left_end)| {
            right
                .iter()
                .zip(right.iter().cycle().skip(1))
                .take(right.len())
                .any(|(right_start, right_end)| {
                    segments_intersect(*left_start, *left_end, *right_start, *right_end)
                })
        })
}

fn cutouts_conflict(cutouts: &[Vec<Point>]) -> bool {
    for first in 0..cutouts.len() {
        for second in first + 1..cutouts.len() {
            if contours_intersect(&cutouts[first], &cutouts[second])
                || point_in_polygon(cutouts[first][0], &cutouts[second])
                || point_in_polygon(cutouts[second][0], &cutouts[first])
            {
                return true;
            }
        }
    }
    false
}

fn contour_self_intersects(contour: &[Point]) -> bool {
    for first in 0..contour.len() {
        let first_end = (first + 1) % contour.len();
        for second in first + 1..contour.len() {
            let second_end = (second + 1) % contour.len();
            if first_end == second || second_end == first {
                continue;
            }
            if segments_intersect(
                contour[first],
                contour[first_end],
                contour[second],
                contour[second_end],
            ) {
                return true;
            }
        }
    }
    false
}

fn segments_intersect(a: Point, b: Point, c: Point, d: Point) -> bool {
    let abc = triangle_orientation(a, b, c);
    let abd = triangle_orientation(a, b, d);
    let cda = triangle_orientation(c, d, a);
    let cdb = triangle_orientation(c, d, b);

    (abc.is_zero() && point_between(c, a, b))
        || (abd.is_zero() && point_between(d, a, b))
        || (cda.is_zero() && point_between(a, c, d))
        || (cdb.is_zero() && point_between(b, c, d))
        || (((abc.is_positive() && abd.is_negative()) || (abc.is_negative() && abd.is_positive()))
            && ((cda.is_positive() && cdb.is_negative())
                || (cda.is_negative() && cdb.is_positive())))
}

fn point_between(point: Point, start: Point, end: Point) -> bool {
    point.x_nm >= start.x_nm.min(end.x_nm)
        && point.x_nm <= start.x_nm.max(end.x_nm)
        && point.y_nm >= start.y_nm.min(end.y_nm)
        && point.y_nm <= start.y_nm.max(end.y_nm)
}

fn sample_arc(start: Point, mid: Point, end: Point) -> Result<Vec<Point>, String> {
    if triangle_orientation(start, mid, end).is_zero() {
        return Err("Edge.Cuts arc points must not be collinear".into());
    }
    let (x1, y1) = (0.0, 0.0);
    let (x2, y2) = (
        (i128::from(mid.x_nm) - i128::from(start.x_nm)) as f64,
        (i128::from(mid.y_nm) - i128::from(start.y_nm)) as f64,
    );
    let (x3, y3) = (
        (i128::from(end.x_nm) - i128::from(start.x_nm)) as f64,
        (i128::from(end.y_nm) - i128::from(start.y_nm)) as f64,
    );
    let determinant = 2.0 * (x1 * (y2 - y3) + x2 * (y3 - y1) + x3 * (y1 - y2));
    if !determinant.is_finite() || determinant == 0.0 {
        return Err("Edge.Cuts arc geometry exceeds numerical precision".into());
    }
    let q1 = x1 * x1 + y1 * y1;
    let q2 = x2 * x2 + y2 * y2;
    let q3 = x3 * x3 + y3 * y3;
    let center_x = (q1 * (y2 - y3) + q2 * (y3 - y1) + q3 * (y1 - y2)) / determinant;
    let center_y = (q1 * (x3 - x2) + q2 * (x1 - x3) + q3 * (x2 - x1)) / determinant;
    let radius = (x1 - center_x).hypot(y1 - center_y);
    let start_angle = (y1 - center_y).atan2(x1 - center_x);
    let mid_angle = (y2 - center_y).atan2(x2 - center_x);
    let end_angle = (y3 - center_y).atan2(x3 - center_x);
    let positive = |angle: f64| angle.rem_euclid(std::f64::consts::TAU);
    let ccw_sweep = positive(end_angle - start_angle);
    let sweep = if positive(mid_angle - start_angle) <= ccw_sweep {
        ccw_sweep
    } else {
        ccw_sweep - std::f64::consts::TAU
    };
    let mid_sweep = if sweep >= 0.0 {
        positive(mid_angle - start_angle)
    } else {
        -positive(start_angle - mid_angle)
    };
    let max_step = 2.0 * (1.0 - (ARC_CHORD_TOLERANCE_NM / radius).min(1.0)).acos();
    let interval_steps =
        |interval: f64| (interval.abs() / max_step.max(1e-6)).ceil().max(1.0) as usize;
    let start_steps = interval_steps(mid_sweep);
    let end_sweep = sweep - mid_sweep;
    let end_steps = interval_steps(end_sweep);
    let segments = start_steps
        .checked_add(end_steps)
        .ok_or("Edge.Cuts arc requires too many segments")?;
    if segments > MAX_EDGE_ARC_SEGMENTS {
        return Err("Edge.Cuts arc requires too many segments".into());
    }
    let sample_point = |angle: f64| {
        let x = center_x + radius * angle.cos();
        let y = center_y + radius * angle.sin();
        let (Some(x_nm), Some(y_nm)) = (
            checked_arc_coordinate(start.x_nm, x),
            checked_arc_coordinate(start.y_nm, y),
        ) else {
            return Err("Edge.Cuts arc exceeds nanometer range".to_string());
        };
        Ok(Point { x_nm, y_nm })
    };
    let mut points = Vec::with_capacity(segments + 1);
    for index in 0..=start_steps {
        let angle = start_angle + mid_sweep * index as f64 / start_steps as f64;
        points.push(if index == 0 {
            start
        } else if index == start_steps {
            mid
        } else {
            sample_point(angle)?
        });
    }
    for index in 1..=end_steps {
        let angle = mid_angle + end_sweep * index as f64 / end_steps as f64;
        points.push(if index == end_steps {
            end
        } else {
            sample_point(angle)?
        });
    }
    Ok(points)
}

fn sample_circle(center: Point, end: Point) -> Result<Vec<Point>, String> {
    let exact_offset_x = i128::from(end.x_nm) - i128::from(center.x_nm);
    let exact_offset_y = i128::from(end.y_nm) - i128::from(center.y_nm);
    let radius_squared = exact_offset_x
        .unsigned_abs()
        .pow(2)
        .checked_add(exact_offset_y.unsigned_abs().pow(2))
        .ok_or("Edge.Cuts circle exceeds nanometer range")?;
    if radius_squared == 0 {
        return Err("Edge.Cuts circle must have a positive radius".into());
    }
    let coordinate_margin = [
        i128::from(center.x_nm) - i128::from(i64::MIN),
        i128::from(i64::MAX) - i128::from(center.x_nm),
        i128::from(center.y_nm) - i128::from(i64::MIN),
        i128::from(i64::MAX) - i128::from(center.y_nm),
    ]
    .into_iter()
    .min()
    .unwrap() as u128;
    if radius_squared > coordinate_margin.pow(2) {
        return Err("Edge.Cuts circle exceeds nanometer range".into());
    }

    let offset_x = exact_offset_x as f64;
    let offset_y = exact_offset_y as f64;
    let radius = offset_x.hypot(offset_y);
    let start_angle = offset_y.atan2(offset_x);
    let max_step = 2.0 * (1.0 - (ARC_CHORD_TOLERANCE_NM / radius).min(1.0)).acos();
    let required = (std::f64::consts::TAU / max_step.max(1e-6))
        .ceil()
        .max(12.0) as usize;
    let segments = required.div_ceil(4) * 4;
    if segments > MAX_EDGE_CIRCLE_SEGMENTS {
        return Err("Edge.Cuts circle requires too many segments".into());
    }

    let mut points = Vec::with_capacity(segments);
    for index in 0..segments {
        let angle = start_angle + std::f64::consts::TAU * index as f64 / segments as f64;
        points.push(Point {
            x_nm: translate_arc_coordinate(center.x_nm, radius * angle.cos()),
            y_nm: translate_arc_coordinate(center.y_nm, radius * angle.sin()),
        });
    }
    points[0] = end;
    points.dedup();
    if points.last() == points.first() {
        points.pop();
    }
    if points.len() < 3 {
        return Err("Edge.Cuts circle is too small to represent".into());
    }
    Ok(points)
}

fn sample_curve(values: &[Sexp]) -> Result<Vec<Point>, String> {
    let Some(values) = unique_edge_child_values(values, "pts")? else {
        return Err("Edge.Cuts curve requires four points".into());
    };
    if values.len() != 5 {
        return Err("Edge.Cuts curve requires four points".into());
    }
    let [start, control_1, control_2, end] = [
        edge_curve_point(&values[1])?,
        edge_curve_point(&values[2])?,
        edge_curve_point(&values[3])?,
        edge_curve_point(&values[4])?,
    ];

    let relative = |point: Point| {
        (
            (i128::from(point.x_nm) - i128::from(start.x_nm)) as f64,
            (i128::from(point.y_nm) - i128::from(start.y_nm)) as f64,
        )
    };
    let mut stack = vec![[
        relative(start),
        relative(control_1),
        relative(control_2),
        relative(end),
    ]];
    let mut sampled = vec![(0.0, 0.0)];
    while let Some(curve) = stack.pop() {
        if curve_is_flat(curve) {
            sampled.push(curve[3]);
            if sampled.len() > MAX_EDGE_CURVE_SEGMENTS + 1 {
                return Err("Edge.Cuts curve requires too many segments".into());
            }
            continue;
        }
        let [left, right] = split_curve(curve);
        stack.push(right);
        stack.push(left);
    }

    let mut points = sampled
        .into_iter()
        .map(|(x, y)| Point {
            x_nm: translate_arc_coordinate(start.x_nm, x),
            y_nm: translate_arc_coordinate(start.y_nm, y),
        })
        .collect::<Vec<_>>();
    points[0] = start;
    *points.last_mut().unwrap() = end;
    points.dedup();
    if points.len() < 2 {
        return Err("Edge.Cuts curve must have distinct endpoints or control points".into());
    }
    Ok(points)
}

fn edge_curve_point(value: &Sexp) -> Result<Point, String> {
    let Some(xy) = value.as_list() else {
        return Err("Edge.Cuts curve requires four xy points".into());
    };
    if atom(xy.first()) != Some("xy") || xy.len() != 3 {
        return Err("Edge.Cuts curve requires four xy points".into());
    }
    let (Some(x), Some(y)) = (number(xy.get(1)), number(xy.get(2))) else {
        return Err("Edge.Cuts curve requires four xy points".into());
    };
    if !x.is_finite() || !y.is_finite() {
        return Err("Edge.Cuts curve coordinates must be finite".into());
    }
    edge_point_mm(x, y)
}

fn curve_is_flat(curve: [(f64, f64); 4]) -> bool {
    point_segment_distance(curve[1], curve[0], curve[3]) <= ARC_CHORD_TOLERANCE_NM
        && point_segment_distance(curve[2], curve[0], curve[3]) <= ARC_CHORD_TOLERANCE_NM
}

fn point_segment_distance(point: (f64, f64), start: (f64, f64), end: (f64, f64)) -> f64 {
    let delta = (end.0 - start.0, end.1 - start.1);
    let length_squared = delta.0 * delta.0 + delta.1 * delta.1;
    if length_squared == 0.0 {
        return (point.0 - start.0).hypot(point.1 - start.1);
    }
    let projection =
        ((point.0 - start.0) * delta.0 + (point.1 - start.1) * delta.1) / length_squared;
    let projection = projection.clamp(0.0, 1.0);
    (point.0 - (start.0 + projection * delta.0)).hypot(point.1 - (start.1 + projection * delta.1))
}

fn split_curve(curve: [(f64, f64); 4]) -> [[(f64, f64); 4]; 2] {
    let midpoint =
        |left: (f64, f64), right: (f64, f64)| ((left.0 + right.0) / 2.0, (left.1 + right.1) / 2.0);
    let first = midpoint(curve[0], curve[1]);
    let second = midpoint(curve[1], curve[2]);
    let third = midpoint(curve[2], curve[3]);
    let fourth = midpoint(first, second);
    let fifth = midpoint(second, third);
    let center = midpoint(fourth, fifth);
    [
        [curve[0], first, fourth, center],
        [center, fifth, third, curve[3]],
    ]
}

fn translate_arc_coordinate(origin: i64, offset: f64) -> i64 {
    i128::from(origin)
        .saturating_add(offset.round() as i128)
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn checked_arc_coordinate(origin: i64, offset: f64) -> Option<i64> {
    if !offset.is_finite() {
        return None;
    }
    i128::from(origin)
        .checked_add(offset.round() as i128)
        .and_then(|coordinate| coordinate.try_into().ok())
}

fn import_footprint(
    xs: &[Sexp],
    origin: Point,
    nets: &mut HashMap<u32, Net>,
    geometry: &mut FootprintGeometry,
    copper_layers: &[Layer],
) -> Result<(), String> {
    let (fx, fy, angle) =
        optional_position_angle(xs, "at", "footprint at")?.unwrap_or((0.0, 0.0, 0.0));
    if !angle.is_finite() {
        return Err("footprint rotation must be finite".into());
    }
    let mut model = Footprint {
        reference: footprint_reference(xs),
        position: relative(
            Point {
                x_nm: checked_mm_to_nm(fx, "footprint X coordinate", true, false)?,
                y_nm: checked_mm_to_nm(fy, "footprint Y coordinate", true, false)?,
            },
            origin,
        ),
        rotation_deg: angle,
        pads: Vec::new(),
    };
    for child in xs {
        let Some(pad) = child.as_list() else { continue };
        if atom(pad.first()) != Some("pad") {
            continue;
        }
        if pad.len() < 4 {
            return Err("KiCad pad header must contain number, type, and shape".into());
        }
        if atom(pad.get(1)).is_none() {
            return Err("KiCad pad number must be scalar".into());
        }
        if !matches!(
            atom(pad.get(2)),
            Some("smd") | Some("thru_hole") | Some("np_thru_hole") | Some("connect")
        ) {
            return Err("KiCad pad type is unsupported".into());
        }
        let (px, py, pad_angle) =
            optional_position_angle(pad, "at", "pad at")?.unwrap_or((0.0, 0.0, 0.0));
        let total_rotation = angle + pad_angle;
        if !total_rotation.is_finite() {
            return Err("pad rotation must be finite".into());
        }
        let (rx, ry) = rotate(px, py, angle);
        let position = relative(
            Point {
                x_nm: checked_mm_to_nm(fx + rx, "pad X coordinate", true, false)?,
                y_nm: checked_mm_to_nm(fy + ry, "pad Y coordinate", true, false)?,
            },
            origin,
        );
        let layers = pad_layers(pad, copper_layers)?;
        let (width, height) = required_dimension_pair(pad, "size", "pad size")?;
        let shape = match atom(pad.get(3)) {
            Some("circle") => PadShape::Circle,
            Some("oval") => PadShape::Oval,
            Some("rect") => PadShape::Rect,
            Some("roundrect") => PadShape::RoundRect,
            Some("trapezoid") => PadShape::Trapezoid,
            Some("custom") => PadShape::Custom,
            _ => return Err("KiCad pad shape is missing or unsupported".into()),
        };
        let roundrect_ratio =
            match unique_physical_child_values(pad, "roundrect_rratio", "pad roundrect ratio")? {
                None => 0.25,
                Some(values) if values.len() == 2 => {
                    let ratio = scalar_f64(values.get(1), "pad roundrect ratio")?;
                    if !ratio.is_finite() || !(0.0..=0.5).contains(&ratio) {
                        return Err("pad roundrect ratio is outside the supported range".into());
                    }
                    ratio
                }
                Some(_) => return Err("pad roundrect ratio must contain one numeric value".into()),
            };
        let rect_delta =
            optional_offset_pair(pad, "rect_delta", "pad trapezoid delta")?.unwrap_or((0.0, 0.0));
        let custom_polygon = custom_pad_polygon(pad, position, total_rotation)?;
        if shape == PadShape::Custom && custom_polygon.is_none() {
            return Err("custom pad requires one supported gr_poly primitive".into());
        }
        let custom_polygon = custom_polygon.unwrap_or_default();
        let (bbox_width, bbox_height) = rotated_size(width, height, total_rotation);
        let mut net_fields = pad.iter().filter_map(|value| {
            let values = value.as_list()?;
            (atom(values.first()) == Some("net")).then_some(values)
        });
        let net_values = net_fields.next();
        if net_fields.next().is_some() {
            let number = atom(pad.get(1)).unwrap_or("");
            return Err(format!(
                "KiCad pad {number} net fields must not be repeated"
            ));
        }
        let net_id = net_values
            .map(|values| {
                number_u32(values.get(1)).ok_or_else(|| {
                    let number = atom(pad.get(1)).unwrap_or("");
                    format!("KiCad pad {number} is missing a valid numeric net ID")
                })
            })
            .transpose()?;
        if let (Some(values), Some(id)) = (net_values, net_id)
            && atom(values.get(2)).is_none()
        {
            let number = atom(pad.get(1)).unwrap_or("");
            return Err(format!(
                "KiCad pad {number} net {id} is missing a scalar name"
            ));
        }
        if let Some(values) = net_values
            && values.len() > 3
        {
            let number = atom(pad.get(1)).unwrap_or("");
            return Err(format!(
                "KiCad pad {number} net field must contain exactly one ID and name"
            ));
        }
        if let Some(id) = net_id.filter(|id| *id != 0)
            && !nets.contains_key(&id)
        {
            let number = atom(pad.get(1)).unwrap_or("");
            return Err(format!(
                "KiCad pad {number} references undeclared net ID {id}"
            ));
        }
        if let (Some(values), Some(id)) = (net_values, net_id)
            && let Some(declared) = nets.get(&id)
        {
            let name = atom(values.get(2)).expect("pad net name was validated");
            if name != declared.name {
                let number = atom(pad.get(1)).unwrap_or("");
                return Err(format!(
                    "KiCad pad {number} net {id} name {name:?} does not match declared name {:?}",
                    declared.name
                ));
            }
        }
        let drill = unique_physical_child_values(pad, "drill", "pad drill")?
            .map(|values| -> Result<(f64, f64, f64, f64), String> {
                // KiCad permits child lists such as `(offset ...)` after the
                // scalar drill dimensions.  Validate every child explicitly
                // so an unknown child or an extra scalar cannot be ignored.
                for value in values.iter().skip(1) {
                    if let Some(child) = value.as_list()
                        && atom(child.first()) != Some("offset")
                    {
                        return Err("pad drill contains an unsupported child".into());
                    }
                }
                let scalars: Vec<_> = values
                    .iter()
                    .skip(1)
                    .filter(|value| atom(Some(value)).is_some())
                    .collect();
                let (width, height) =
                    if scalars.first().and_then(|value| atom(Some(value))) == Some("oval") {
                        if scalars.len() != 3 {
                            return Err("pad drill oval must contain two dimensions".into());
                        }
                        (
                            scalar_f64(scalars.get(1).copied(), "pad drill width")?,
                            scalar_f64(scalars.get(2).copied(), "pad drill height")?,
                        )
                    } else {
                        if scalars.is_empty() || scalars.len() > 2 {
                            return Err("pad drill must contain one or two dimensions".into());
                        }
                        let width = scalar_f64(scalars.first().copied(), "pad drill width")?;
                        let height = scalars
                            .get(1)
                            .map(|value| scalar_f64(Some(*value), "pad drill height"))
                            .transpose()?
                            .unwrap_or(width);
                        (width, height)
                    };
                checked_mm_to_nm(width, "pad drill width", false, true)?;
                checked_mm_to_nm(height, "pad drill height", false, true)?;
                let offset = optional_offset_pair(values, "offset", "pad drill offset")?
                    .unwrap_or((0.0, 0.0));
                Ok((width, height, offset.0, offset.1))
            })
            .transpose()?;
        model.pads.push(Pad {
            number: atom(pad.get(1)).unwrap_or("").to_string(),
            position,
            width_nm: checked_mm_to_nm(bbox_width, "pad bounding-box width", false, true)?,
            height_nm: checked_mm_to_nm(bbox_height, "pad bounding-box height", false, true)?,
            source_width_nm: checked_mm_to_nm(width, "pad width", false, true)?,
            source_height_nm: checked_mm_to_nm(height, "pad height", false, true)?,
            rotation_deg: total_rotation,
            shape,
            custom_polygon: custom_polygon.clone(),
            roundrect_radius_nm: if shape == PadShape::RoundRect {
                checked_mm_to_nm(
                    width.min(height) * roundrect_ratio,
                    "pad roundrect radius",
                    false,
                    false,
                )?
            } else {
                0
            },
            trapezoid_delta_x_nm: if shape == PadShape::Trapezoid {
                checked_mm_to_nm(rect_delta.0, "pad trapezoid X delta", true, false)?
            } else {
                0
            },
            trapezoid_delta_y_nm: if shape == PadShape::Trapezoid {
                checked_mm_to_nm(rect_delta.1, "pad trapezoid Y delta", true, false)?
            } else {
                0
            },
            drill_width_nm: drill
                .map(|(width, _, _, _)| checked_mm_to_nm(width, "pad drill width", false, true))
                .transpose()?,
            drill_height_nm: drill
                .map(|(_, height, _, _)| checked_mm_to_nm(height, "pad drill height", false, true))
                .transpose()?,
            drill_offset_x_nm: drill
                .map(|(_, _, x, _)| checked_mm_to_nm(x, "pad drill X offset", true, false))
                .transpose()?
                .unwrap_or(0),
            drill_offset_y_nm: drill
                .map(|(_, _, _, y)| checked_mm_to_nm(y, "pad drill Y offset", true, false))
                .transpose()?
                .unwrap_or(0),
            plated: atom(pad.get(2)) != Some("np_thru_hole"),
            layers: layers.clone(),
            net_id,
        });
        if let Some(net_values) = net_values
            && let Some(id) = number_u32(net_values.get(1))
            && let Some(net) = nets.get_mut(&id)
        {
            net.terminals.push(Terminal {
                position,
                layers: layers.clone(),
            });
            add_pad_obstacle(
                shape,
                roundrect_ratio,
                rect_delta,
                &custom_polygon,
                position,
                width,
                height,
                total_rotation,
                layers,
                Some(id),
                &mut geometry.round_obstacles,
                &mut geometry.capsule_obstacles,
                &mut geometry.polygon_obstacles,
            )?;
            continue;
        }
        add_pad_obstacle(
            shape,
            roundrect_ratio,
            rect_delta,
            &custom_polygon,
            position,
            width,
            height,
            total_rotation,
            layers,
            None,
            &mut geometry.round_obstacles,
            &mut geometry.capsule_obstacles,
            &mut geometry.polygon_obstacles,
        )?;
    }
    geometry.footprints.push(model);
    Ok(())
}

fn footprint_reference(xs: &[Sexp]) -> String {
    for item in xs {
        let Some(values) = item.as_list() else {
            continue;
        };
        if atom(values.first()) == Some("property") && atom(values.get(1)) == Some("Reference") {
            return atom(values.get(2)).unwrap_or("").to_string();
        }
        if atom(values.first()) == Some("fp_text") && atom(values.get(1)) == Some("reference") {
            return atom(values.get(2)).unwrap_or("").to_string();
        }
    }
    String::new()
}

fn footprint_side(xs: &[Sexp]) -> Result<BoardSide, String> {
    let values = unique_physical_child_values(xs, "layer", "footprint layer")?
        .ok_or_else(|| "footprint is missing its layer".to_string())?;
    if values.len() != 2 {
        return Err("footprint layer must contain one layer name".into());
    }
    match atom(values.get(1)) {
        Some("F.Cu") => Ok(BoardSide::Front),
        Some("B.Cu") => Ok(BoardSide::Back),
        Some(layer) => Err(format!("footprint layer {layer} is not F.Cu or B.Cu")),
        None => Err("footprint layer must contain a scalar layer name".into()),
    }
}

fn validate_declared_copper_net(
    xs: &[Sexp],
    kind: &str,
    nets: &HashMap<u32, Net>,
) -> Result<(), String> {
    let mut net_fields = xs.iter().filter_map(|value| {
        let values = value.as_list()?;
        (atom(values.first()) == Some("net")).then_some(values)
    });
    let Some(values) = net_fields.next() else {
        return Ok(());
    };
    if net_fields.next().is_some() {
        return Err(format!("KiCad {kind} net fields must not be repeated"));
    }
    if values.len() > 2 {
        return Err(format!(
            "KiCad {kind} net field must contain exactly one ID"
        ));
    }
    let id = number_u32(values.get(1))
        .ok_or_else(|| format!("KiCad {kind} is missing a valid numeric net ID"))?;
    if id != 0 && !nets.contains_key(&id) {
        return Err(format!("KiCad {kind} references undeclared net ID {id}"));
    }
    Ok(())
}

fn validate_copper_zone_net_name(xs: &[Sexp], nets: &HashMap<u32, Net>) -> Result<(), String> {
    let Some(id) = child_values(xs, "net").and_then(|values| number_u32(values.get(1))) else {
        return Ok(());
    };
    let mut net_name_fields = xs.iter().filter_map(|value| {
        let values = value.as_list()?;
        (atom(values.first()) == Some("net_name")).then_some(values)
    });
    let Some(values) = net_name_fields.next() else {
        return Err(format!(
            "KiCad copper zone net {id} is missing a scalar name"
        ));
    };
    if net_name_fields.next().is_some() {
        return Err(format!(
            "KiCad copper zone net {id} net_name fields must not be repeated"
        ));
    }
    if values.len() > 2 {
        return Err(format!(
            "KiCad copper zone net {id} net_name field must contain exactly one name"
        ));
    }
    let Some(name) = atom(values.get(1)) else {
        return Err(format!(
            "KiCad copper zone net {id} is missing a scalar name"
        ));
    };
    let declared = if id == 0 {
        ""
    } else {
        nets.get(&id)
            .expect("copper zone net ID was validated")
            .name
            .as_str()
    };
    if name != declared {
        return Err(format!(
            "KiCad copper zone net {id} name \"{name}\" does not match declared name \"{declared}\""
        ));
    }
    Ok(())
}

fn import_segment(
    xs: &[Sexp],
    origin: Point,
    rules: &Rules,
    copper_layers: &[Layer],
    obstacles: &mut Vec<Obstacle>,
    routes: &mut HashMap<u32, Route>,
) -> Result<(), String> {
    let start = required_point_mm(xs, "start", "segment start")?;
    let end = required_point_mm(xs, "end", "segment end")?;
    let layer = declared_copper_layer(xs, "layer", "segment layer", copper_layers)?
        .ok_or_else(|| "segment requires a valid copper layer".to_string())?;
    let a = relative(start, origin);
    let b = relative(end, origin);
    let width = optional_mm_field(xs, "width", "segment width", false, true)?
        .unwrap_or(rules.track_width_nm);
    let net_id = child_values(xs, "net").and_then(|v| number_u32(v.get(1)));
    obstacles.push(Obstacle {
        min: Point {
            x_nm: a.x_nm.min(b.x_nm).saturating_sub(width / 2),
            y_nm: a.y_nm.min(b.y_nm).saturating_sub(width / 2),
        },
        max: Point {
            x_nm: a.x_nm.max(b.x_nm).saturating_add(width / 2),
            y_nm: a.y_nm.max(b.y_nm).saturating_add(width / 2),
        },
        layers: vec![layer],
        net_id,
    });
    if let Some(net_id) = net_id.filter(|id| *id != 0) {
        routes
            .entry(net_id)
            .or_insert_with(|| Route {
                net_id,
                segments: Vec::new(),
                arcs: Vec::new(),
                vias: Vec::new(),
                teardrops: Vec::new(),
                zones: Vec::new(),
            })
            .segments
            .push(Segment {
                start: a,
                end: b,
                layer,
                width_nm: width,
            });
    }
    Ok(())
}

fn import_route_arc(
    xs: &[Sexp],
    origin: Point,
    rules: &Rules,
    copper_layers: &[Layer],
    obstacles: &mut Vec<Obstacle>,
    routes: &mut HashMap<u32, Route>,
) -> Result<(), String> {
    let start = required_point_mm(xs, "start", "route arc start")?;
    let mid = required_point_mm(xs, "mid", "route arc midpoint")?;
    let end = required_point_mm(xs, "end", "route arc end")?;
    let layer = declared_copper_layer(xs, "layer", "route arc layer", copper_layers)?
        .ok_or_else(|| "route arc requires a valid copper layer".to_string())?;
    let start = relative(start, origin);
    let mid = relative(mid, origin);
    let end = relative(end, origin);
    let width = optional_mm_field(xs, "width", "route arc width", false, true)?
        .unwrap_or(rules.track_width_nm);
    let net_id = child_values(xs, "net").and_then(|values| number_u32(values.get(1)));
    obstacles.push(Obstacle {
        min: Point {
            x_nm: start
                .x_nm
                .min(mid.x_nm)
                .min(end.x_nm)
                .saturating_sub(width / 2),
            y_nm: start
                .y_nm
                .min(mid.y_nm)
                .min(end.y_nm)
                .saturating_sub(width / 2),
        },
        max: Point {
            x_nm: start
                .x_nm
                .max(mid.x_nm)
                .max(end.x_nm)
                .saturating_add(width / 2),
            y_nm: start
                .y_nm
                .max(mid.y_nm)
                .max(end.y_nm)
                .saturating_add(width / 2),
        },
        layers: vec![layer],
        net_id,
    });
    if let Some(net_id) = net_id.filter(|id| *id != 0) {
        routes
            .entry(net_id)
            .or_insert_with(|| Route {
                net_id,
                segments: Vec::new(),
                arcs: Vec::new(),
                vias: Vec::new(),
                teardrops: Vec::new(),
                zones: Vec::new(),
            })
            .arcs
            .push(RouteArc {
                start,
                mid,
                end,
                layer,
                width_nm: width,
            });
    }
    Ok(())
}

fn import_via(
    xs: &[Sexp],
    origin: Point,
    rules: &Rules,
    obstacles: &mut Vec<Obstacle>,
    routes: &mut HashMap<u32, Route>,
    copper_layers: &[Layer],
) -> Result<(), String> {
    let at = required_point_mm(xs, "at", "via position")?;
    let at = relative(at, origin);
    let size = optional_mm_field(xs, "size", "via diameter", false, true)?
        .unwrap_or(rules.via_diameter_nm);
    let drill =
        optional_mm_field(xs, "drill", "via drill", false, true)?.unwrap_or(rules.via_drill_nm);
    if drill >= size {
        return Err("via drill must be smaller than via diameter".into());
    }
    let net_id = child_values(xs, "net").and_then(|v| number_u32(v.get(1)));
    let kind = if xs.iter().any(|value| atom(Some(value)) == Some("micro")) {
        ViaKind::Micro
    } else if xs.iter().any(|value| atom(Some(value)) == Some("blind")) {
        ViaKind::BlindBuried
    } else {
        ViaKind::Through
    };
    let (start_layer, end_layer) = match unique_physical_child_values(xs, "layers", "via layers")? {
        None => (Layer::Front, Layer::Back),
        Some(values) => {
            if values.len() != 3 {
                return Err("via layers must contain exactly two copper layers".into());
            }
            let mut declared = Vec::with_capacity(2);
            for value in values.iter().skip(1) {
                let name = atom(Some(value))
                    .ok_or_else(|| "via layers must contain scalar layer names".to_string())?;
                let layer = parse_layer(name)
                    .ok_or_else(|| "via layers contain an invalid copper layer".to_string())?;
                if !copper_layers.contains(&layer) {
                    return Err("via layers reference an undeclared copper layer".into());
                }
                if declared.contains(&layer) {
                    return Err("via layers contain a duplicate copper layer".into());
                }
                declared.push(layer);
            }
            (declared[0], declared[1])
        }
    };
    let via_layers: Vec<_> = copper_layers
        .iter()
        .copied()
        .filter(|layer| {
            let index = layer.index();
            let first = start_layer.index().min(end_layer.index());
            let last = start_layer.index().max(end_layer.index());
            (first..=last).contains(&index)
        })
        .collect();
    obstacles.push(rect_obstacle(at, size, size, via_layers, net_id));
    if let Some(net_id) = net_id.filter(|id| *id != 0) {
        routes
            .entry(net_id)
            .or_insert_with(|| Route {
                net_id,
                segments: Vec::new(),
                arcs: Vec::new(),
                vias: Vec::new(),
                teardrops: Vec::new(),
                zones: Vec::new(),
            })
            .vias
            .push(Via {
                position: at,
                diameter_nm: size,
                drill_nm: drill,
                kind,
                start_layer,
                end_layer,
            });
    }
    Ok(())
}

fn import_keepout(
    xs: &[Sexp],
    origin: Point,
    keepouts: &mut Vec<Keepout>,
    copper_layers: &[Layer],
) -> Result<(), String> {
    let Some(restrictions) = unique_physical_child_values(xs, "keepout", "keepout field")? else {
        return Ok(());
    };
    let singular = unique_physical_child_values(xs, "layer", "keepout layer")?;
    let plural = unique_physical_child_values(xs, "layers", "keepout layers")?;
    if singular.is_some() && plural.is_some() {
        return Err("keepout layer and layers must not both be present".into());
    }
    let layers = if let Some(values) = singular {
        if values.len() != 2 {
            return Err("keepout layer must contain one layer name".into());
        }
        let name = atom(values.get(1))
            .ok_or_else(|| "keepout layer must contain a scalar layer name".to_string())?;
        if matches!(name, "*.Cu" | "F&B.Cu") {
            copper_layers.to_vec()
        } else {
            let layer = parse_layer(name)
                .ok_or_else(|| "keepout layer contains an invalid copper layer".to_string())?;
            if !copper_layers.contains(&layer) {
                return Err("keepout layer references an undeclared copper layer".into());
            }
            vec![layer]
        }
    } else if let Some(values) = plural {
        if values.len() < 2 {
            return Err("keepout layers must contain at least one layer".into());
        }
        let mut layers = Vec::new();
        for value in values.iter().skip(1) {
            let value = atom(Some(value))
                .ok_or_else(|| "keepout layers must contain scalar layer names".to_string())?;
            if matches!(value, "*.Cu" | "F&B.Cu") {
                for layer in copper_layers {
                    if layers.contains(layer) {
                        return Err("keepout layers contain a duplicate copper layer".into());
                    }
                    layers.push(*layer);
                }
            } else {
                let layer = parse_layer(value)
                    .ok_or_else(|| "keepout layers contain an invalid copper layer".to_string())?;
                if !copper_layers.contains(&layer) {
                    return Err("keepout layers reference an undeclared copper layer".into());
                }
                if layers.contains(&layer) {
                    return Err("keepout layers contain a duplicate copper layer".into());
                }
                layers.push(layer);
            }
        }
        if layers.is_empty() {
            return Err("keepout layers must include at least one copper layer".into());
        }
        layers.sort_by_key(|layer| layer.index());
        layers
    } else {
        copper_layers.to_vec()
    };
    let Some(polygon) = unique_physical_child_values(xs, "polygon", "keepout polygon")? else {
        return Err("keepout is missing its polygon".into());
    };
    let Some(values) = unique_physical_child_values(polygon, "pts", "keepout point list")? else {
        return Err("keepout polygon is missing its point list".into());
    };
    let points = import_polygon_points(values, origin, "keepout polygon")?;
    if points.len() < 3 || layers.is_empty() {
        return Err("keepout polygon must contain at least three points and a layer".into());
    }
    let restrictions = parse_keepout_restrictions(restrictions)?;
    keepouts.push(Keepout {
        polygon: points,
        layers,
        net_id: None,
        tracks_not_allowed: restrictions.tracks,
        vias_not_allowed: restrictions.vias,
        zones_not_allowed: restrictions.copperpour,
        footprints_not_allowed: restrictions.footprints,
        minimum_track_width_nm: None,
        minimum_clearance_nm: None,
    });
    Ok(())
}

#[derive(Default)]
struct KeepoutRestrictions {
    tracks: bool,
    vias: bool,
    copperpour: bool,
    footprints: bool,
}

fn parse_keepout_restrictions(values: &[Sexp]) -> Result<KeepoutRestrictions, String> {
    let mut seen = HashSet::new();
    let mut restrictions = KeepoutRestrictions::default();
    for value in values.iter().skip(1) {
        let child = value
            .as_list()
            .ok_or_else(|| "keepout restriction must be a list".to_string())?;
        let name = atom(child.first())
            .ok_or_else(|| "keepout restriction must have a scalar name".to_string())?;
        if !matches!(
            name,
            "tracks" | "vias" | "copperpour" | "footprints" | "pads"
        ) {
            return Err(format!("keepout contains unknown restriction {name}"));
        }
        if !seen.insert(name) {
            return Err(format!("keepout restriction {name} must not be repeated"));
        }
        if child.len() != 2 {
            return Err(format!("keepout restriction {name} must contain one value"));
        }
        let value = atom(child.get(1))
            .ok_or_else(|| format!("keepout restriction {name} must be scalar"))?;
        if !matches!(value, "allowed" | "not_allowed") {
            return Err(format!(
                "keepout restriction {name} must be allowed or not_allowed"
            ));
        }
        let not_allowed = value == "not_allowed";
        match name {
            "tracks" => restrictions.tracks = not_allowed,
            "vias" => restrictions.vias = not_allowed,
            "copperpour" => restrictions.copperpour = not_allowed,
            "footprints" => restrictions.footprints = not_allowed,
            "pads" if not_allowed => {
                return Err("keepout pads restriction is unsupported".into());
            }
            "pads" => {}
            _ => unreachable!(),
        }
    }
    Ok(restrictions)
}

fn import_copper_zone(
    xs: &[Sexp],
    origin: Point,
    copper_layers: &[Layer],
    polygon_obstacles: &mut Vec<PolygonObstacle>,
    routes: &mut HashMap<u32, Route>,
) -> Result<(), String> {
    if child_values(xs, "keepout").is_some()
        || child_values(xs, "attr")
            .and_then(|attr| child_values(attr, "teardrop"))
            .is_some()
    {
        return Ok(());
    }
    let Some(net_id) = child_values(xs, "net").and_then(|values| number_u32(values.get(1))) else {
        return Err("copper zone is missing a valid net ID".into());
    };
    let layer = declared_copper_layer(xs, "layer", "copper zone layer", copper_layers)?
        .ok_or_else(|| "copper zone requires a valid copper layer".to_string())?;
    if net_id == 0 {
        return Ok(());
    }
    let outline = unique_physical_child_values(xs, "polygon", "copper zone polygon")?
        .ok_or_else(|| "copper zone is missing its polygon".to_string())?;
    let outline_values = unique_physical_child_values(outline, "pts", "copper zone point list")?
        .ok_or_else(|| "copper zone polygon is missing its point list".to_string())?;
    let outline = import_polygon_points(outline_values, origin, "copper zone polygon")?;
    if outline.len() < 3 {
        return Err("copper zone polygon must contain at least three points".into());
    }
    {
        polygon_obstacles.push(PolygonObstacle {
            polygon: outline.clone(),
            layers: vec![layer],
            net_id: Some(net_id),
        });
        let clearance_nm = unique_physical_child_values(xs, "connect_pads", "zone connect_pads")?
            .map(|connect| optional_mm_field(connect, "clearance", "zone clearance", false, false))
            .transpose()?
            .flatten()
            .unwrap_or(0);
        let minimum_thickness_nm =
            optional_mm_field(xs, "min_thickness", "zone minimum thickness", false, true)?
                .unwrap_or(250_000);
        let fill = unique_physical_child_values(xs, "fill", "zone fill")?;
        let thermal_gap_nm = fill
            .map(|values| {
                optional_mm_field(values, "thermal_gap", "zone thermal gap", false, false)
            })
            .transpose()?
            .flatten()
            .unwrap_or(200_000);
        let thermal_spoke_width_nm = fill
            .map(|values| {
                optional_mm_field(
                    values,
                    "thermal_bridge_width",
                    "zone thermal spoke width",
                    false,
                    true,
                )
            })
            .transpose()?
            .flatten()
            .unwrap_or(250_000);
        routes
            .entry(net_id)
            .or_insert_with(|| Route {
                net_id,
                segments: Vec::new(),
                arcs: Vec::new(),
                vias: Vec::new(),
                teardrops: Vec::new(),
                zones: Vec::new(),
            })
            .zones
            .push(CopperZone {
                polygon: outline,
                layer,
                clearance_nm,
                minimum_thickness_nm,
                thermal_relief: true,
                thermal_gap_nm,
                thermal_spoke_width_nm,
                filled_polygons: Vec::new(),
            });
    }
    for child in xs {
        let Some(filled) = child.as_list() else {
            continue;
        };
        if atom(filled.first()) != Some("filled_polygon") {
            continue;
        }
        let layer = match unique_physical_child_values(filled, "layer", "filled polygon layer")? {
            None => layer,
            Some(_values) => {
                declared_copper_layer(filled, "layer", "filled polygon layer", copper_layers)?
                    .ok_or_else(|| {
                        "filled copper polygon requires a valid copper layer".to_string()
                    })?
            }
        };
        let Some(values) =
            unique_physical_child_values(filled, "pts", "filled polygon point list")?
        else {
            return Err("filled copper polygon is missing its point list".into());
        };
        let polygon = import_polygon_points(values, origin, "filled copper polygon")?;
        if polygon.len() < 3 {
            return Err("filled copper polygon must contain at least three points".into());
        }
        if let Some(route) = routes.get_mut(&net_id)
            && let Some(zone) = route.zones.iter_mut().find(|zone| zone.layer == layer)
        {
            zone.filled_polygons.push(polygon.clone());
        }
        polygon_obstacles.push(PolygonObstacle {
            polygon,
            layers: vec![layer],
            net_id: Some(net_id),
        });
    }
    Ok(())
}

fn import_polygon_points(
    values: &[Sexp],
    origin: Point,
    field: &str,
) -> Result<Vec<Point>, String> {
    let mut points = Vec::new();
    for value in values.iter().skip(1) {
        let Some(xy) = value.as_list() else {
            return Err(format!("{field} points must be xy coordinates"));
        };
        if atom(xy.first()) != Some("xy") || xy.len() != 3 {
            return Err(format!("{field} points must be xy coordinates"));
        }
        let x = scalar_f64(xy.get(1), &format!("{field} X coordinate"))?;
        let y = scalar_f64(xy.get(2), &format!("{field} Y coordinate"))?;
        points.push(relative(
            Point {
                x_nm: checked_mm_to_nm(x, &format!("{field} X coordinate"), true, false)?,
                y_nm: checked_mm_to_nm(y, &format!("{field} Y coordinate"), true, false)?,
            },
            origin,
        ));
    }
    Ok(points)
}

fn rect_obstacle(
    center: Point,
    width: i64,
    height: i64,
    layers: Vec<Layer>,
    net_id: Option<u32>,
) -> Obstacle {
    Obstacle {
        min: Point {
            x_nm: center.x_nm.saturating_sub(width / 2),
            y_nm: center.y_nm.saturating_sub(height / 2),
        },
        max: Point {
            x_nm: center.x_nm.saturating_add(width / 2),
            y_nm: center.y_nm.saturating_add(height / 2),
        },
        layers,
        net_id,
    }
}

#[allow(clippy::too_many_arguments)]
fn add_pad_obstacle(
    shape: PadShape,
    roundrect_ratio: f64,
    rect_delta: (f64, f64),
    custom_polygon: &[Point],
    center: Point,
    width_mm: f64,
    height_mm: f64,
    rotation_deg: f64,
    layers: Vec<Layer>,
    net_id: Option<u32>,
    round_obstacles: &mut Vec<RoundObstacle>,
    capsule_obstacles: &mut Vec<CapsuleObstacle>,
    polygon_obstacles: &mut Vec<PolygonObstacle>,
) -> Result<(), String> {
    match shape {
        PadShape::Circle => round_obstacles.push(RoundObstacle {
            center,
            diameter_nm: checked_mm_to_nm(width_mm.max(height_mm), "pad diameter", false, true)?,
            layers,
            net_id,
        }),
        PadShape::Oval => {
            let (major, minor, angle) = if width_mm >= height_mm {
                (width_mm, height_mm, rotation_deg)
            } else {
                (height_mm, width_mm, rotation_deg + 90.0)
            };
            let half_line = (major - minor) / 2.0;
            let (dx, dy) = rotate(half_line, 0.0, angle);
            capsule_obstacles.push(CapsuleObstacle {
                start: Point {
                    x_nm: center.x_nm.saturating_sub(checked_mm_to_nm(
                        dx,
                        "pad oval X offset",
                        true,
                        false,
                    )?),
                    y_nm: center.y_nm.saturating_sub(checked_mm_to_nm(
                        dy,
                        "pad oval Y offset",
                        true,
                        false,
                    )?),
                },
                end: Point {
                    x_nm: center.x_nm.saturating_add(checked_mm_to_nm(
                        dx,
                        "pad oval X offset",
                        true,
                        false,
                    )?),
                    y_nm: center.y_nm.saturating_add(checked_mm_to_nm(
                        dy,
                        "pad oval Y offset",
                        true,
                        false,
                    )?),
                },
                diameter_nm: checked_mm_to_nm(minor, "pad oval diameter", false, true)?,
                layers,
                net_id,
            });
        }
        PadShape::Rect | PadShape::RoundRect | PadShape::Trapezoid | PadShape::Custom => {
            let half_width = width_mm / 2.0;
            let half_height = height_mm / 2.0;
            let local_polygon = match shape {
                PadShape::RoundRect => {
                    let radius = width_mm.min(height_mm) * roundrect_ratio;
                    let mut points = Vec::with_capacity(16);
                    for (cx, cy, start) in [
                        (half_width - radius, half_height - radius, 0.0),
                        (-half_width + radius, half_height - radius, 90.0),
                        (-half_width + radius, -half_height + radius, 180.0),
                        (half_width - radius, -half_height + radius, 270.0),
                    ] {
                        for step in 0..4 {
                            let angle = (start + step as f64 * 30.0_f64).to_radians();
                            points.push((cx + radius * angle.cos(), cy + radius * angle.sin()));
                        }
                    }
                    points
                }
                PadShape::Trapezoid => vec![
                    (
                        -half_width - rect_delta.0 / 2.0,
                        -half_height - rect_delta.1 / 2.0,
                    ),
                    (
                        half_width + rect_delta.0 / 2.0,
                        -half_height + rect_delta.1 / 2.0,
                    ),
                    (
                        half_width - rect_delta.0 / 2.0,
                        half_height + rect_delta.1 / 2.0,
                    ),
                    (
                        -half_width + rect_delta.0 / 2.0,
                        half_height - rect_delta.1 / 2.0,
                    ),
                ],
                PadShape::Custom if custom_polygon.len() >= 3 => {
                    polygon_obstacles.push(PolygonObstacle {
                        polygon: custom_polygon.to_vec(),
                        layers,
                        net_id,
                    });
                    return Ok(());
                }
                _ => vec![
                    (-half_width, -half_height),
                    (half_width, -half_height),
                    (half_width, half_height),
                    (-half_width, half_height),
                ],
            };
            let polygon = local_polygon
                .into_iter()
                .map(|(x, y)| -> Result<Point, String> {
                    let (x, y) = rotate(x, y, rotation_deg);
                    Ok(Point {
                        x_nm: center.x_nm.saturating_add(checked_mm_to_nm(
                            x,
                            "pad polygon X offset",
                            true,
                            false,
                        )?),
                        y_nm: center.y_nm.saturating_add(checked_mm_to_nm(
                            y,
                            "pad polygon Y offset",
                            true,
                            false,
                        )?),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            polygon_obstacles.push(PolygonObstacle {
                polygon,
                layers,
                net_id,
            });
        }
    }
    Ok(())
}

fn custom_pad_polygon(
    pad: &[Sexp],
    center: Point,
    rotation_deg: f64,
) -> Result<Option<Vec<Point>>, String> {
    let Some(primitives) =
        unique_physical_child_values(pad, "primitives", "custom pad primitives")?
    else {
        return Ok(None);
    };
    let mut polygons = 0;
    let mut valid_polygon = None;
    for primitive in primitives.iter().skip(1) {
        let Some(values) = primitive.as_list() else {
            return Err("unsupported custom pad primitive".into());
        };
        if atom(values.first()) != Some("gr_poly") {
            return Err("unsupported custom pad primitive".into());
        }
        polygons += 1;
        if polygons > 1 {
            return Err("unsupported custom pad primitive".into());
        }
        let Some(points) =
            unique_physical_child_values(values, "pts", "custom pad polygon point list")?
        else {
            return Err("custom pad polygon is missing its point list".into());
        };
        let mut polygon = Vec::new();
        for point in points.iter().skip(1) {
            let Some(xy) = point.as_list() else {
                return Err("custom pad polygon points must be xy coordinates".into());
            };
            if atom(xy.first()) != Some("xy") || xy.len() != 3 {
                return Err("custom pad polygon points must be xy coordinates".into());
            }
            let x = scalar_f64(xy.get(1), "custom pad polygon X coordinate")?;
            let y = scalar_f64(xy.get(2), "custom pad polygon Y coordinate")?;
            if !x.is_finite() || !y.is_finite() {
                return Err("custom pad polygon coordinates must be finite".into());
            }
            let (x, y) = rotate(x, y, rotation_deg);
            let dx = checked_mm_to_nm(x, "custom pad polygon X offset", true, false)?;
            let dy = checked_mm_to_nm(y, "custom pad polygon Y offset", true, false)?;
            polygon.push(Point {
                x_nm: center.x_nm.saturating_add(dx),
                y_nm: center.y_nm.saturating_add(dy),
            });
        }
        if polygon.len() >= 3 {
            valid_polygon = Some(polygon);
            continue;
        }
        return Err("custom pad polygon must contain at least three points".into());
    }
    if polygons == 0 {
        return Err("unsupported custom pad primitive".into());
    }
    Ok(valid_polygon)
}

fn rotate(x: f64, y: f64, degrees: f64) -> (f64, f64) {
    let r = degrees.to_radians();
    (x * r.cos() - y * r.sin(), x * r.sin() + y * r.cos())
}
fn rotated_size(width: f64, height: f64, degrees: f64) -> (f64, f64) {
    let r = degrees.to_radians();
    (
        width * r.cos().abs() + height * r.sin().abs(),
        width * r.sin().abs() + height * r.cos().abs(),
    )
}
fn pad_layers(pad: &[Sexp], copper_layers: &[Layer]) -> Result<Vec<Layer>, String> {
    let Some(v) = unique_physical_child_values(pad, "layers", "pad layers")? else {
        return Ok(copper_layers.to_vec());
    };
    if v.len() < 2 {
        return Err("pad layers must contain at least one layer".into());
    }
    let mut layers = Vec::new();
    for value in v.iter().skip(1) {
        let value = atom(Some(value))
            .ok_or_else(|| "pad layers must contain scalar layer names".to_string())?;
        if matches!(value, "*.Cu" | "F&B.Cu") {
            for layer in copper_layers {
                if layers.contains(layer) {
                    return Err("pad layers contain a duplicate copper layer".into());
                }
                layers.push(*layer);
            }
        } else if let Some(layer) = parse_layer(value) {
            if !copper_layers.contains(&layer) {
                return Err("pad layers reference an undeclared copper layer".into());
            }
            if layers.contains(&layer) {
                return Err("pad layers contain a duplicate copper layer".into());
            }
            layers.push(layer);
        } else if !is_known_non_copper_pad_layer(value) {
            return Err("pad layers contain an unknown layer".into());
        }
    }
    if layers.is_empty() {
        return Err("pad layers must include at least one copper layer".into());
    }
    layers.sort_by_key(|layer| layer.index());
    Ok(layers)
}

fn is_known_non_copper_pad_layer(value: &str) -> bool {
    matches!(
        value,
        "F.Mask"
            | "B.Mask"
            | "*.Mask"
            | "F&B.Mask"
            | "F.Paste"
            | "B.Paste"
            | "*.Paste"
            | "F&B.Paste"
            | "F.SilkS"
            | "B.SilkS"
            | "*.SilkS"
            | "F&B.SilkS"
            | "F.CrtYd"
            | "B.CrtYd"
            | "*.CrtYd"
            | "F&B.CrtYd"
            | "F.Fab"
            | "B.Fab"
            | "*.Fab"
            | "F&B.Fab"
            | "F.Adhes"
            | "B.Adhes"
            | "*.Adhes"
            | "F&B.Adhes"
    )
}
fn parse_layer(value: &str) -> Option<Layer> {
    match value {
        "F.Cu" => Some(Layer::Front),
        "B.Cu" => Some(Layer::Back),
        _ if value.starts_with("In") && value.ends_with(".Cu") => value[2..value.len() - 3]
            .parse::<u8>()
            .ok()
            .and_then(Layer::from_index)
            .filter(|layer| matches!(layer, Layer::Inner(_))),
        _ => None,
    }
}

fn declared_copper_layer(
    values: &[Sexp],
    name: &str,
    field: &str,
    copper_layers: &[Layer],
) -> Result<Option<Layer>, String> {
    let Some(layer_values) = unique_physical_child_values(values, name, field)? else {
        return Ok(None);
    };
    if layer_values.len() != 2 {
        return Err(format!("{field} must contain one layer name"));
    }
    let layer_name = atom(layer_values.get(1))
        .ok_or_else(|| format!("{field} must contain a scalar layer name"))?;
    let layer =
        parse_layer(layer_name).ok_or_else(|| format!("{field} requires a valid copper layer"))?;
    if !copper_layers.contains(&layer) {
        return Err(format!("{field} references an undeclared copper layer"));
    }
    Ok(Some(layer))
}

fn layer_name(layer: Layer) -> String {
    layer.name()
}

fn board_copper_layers(top: &[Sexp]) -> Result<Vec<Layer>, String> {
    let Some(values) = unique_physical_child_values(top, "layers", "board layers")? else {
        return Ok(vec![Layer::Front, Layer::Back]);
    };
    let mut layers = Vec::new();
    let mut seen_names = HashSet::new();
    let mut seen_ordinals = HashSet::new();
    for item in values.iter().skip(1) {
        let entry = item
            .as_list()
            .ok_or_else(|| "KiCad board layer entry must be a list".to_string())?;
        if entry.len() < 2 {
            return Err("KiCad board layer entry is missing its name".into());
        }
        let ordinal = atom(entry.first())
            .ok_or_else(|| "KiCad board layer entry has an invalid ordinal".to_string())?
            .parse::<u16>()
            .map_err(|_| "KiCad board layer entry has an invalid ordinal".to_string())?;
        if !seen_ordinals.insert(ordinal) {
            return Err("KiCad board layer table contains a duplicate ordinal".into());
        }
        let name = atom(entry.get(1))
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| "KiCad board layer entry must contain a scalar name".to_string())?;
        if !seen_names.insert(name) {
            return Err("KiCad board layer table contains a duplicate layer".into());
        }
        if let Some(layer) = parse_layer(name) {
            layers.push(layer);
        } else if is_copper_like_layer_name(name) {
            return Err("KiCad board layer table contains an invalid copper layer".into());
        } else if !is_known_non_copper_board_layer(name) {
            return Err("KiCad board layer table contains an unknown layer".into());
        }
    }
    layers.sort_by_key(|layer| layer.index());
    if layers.is_empty() {
        return Err("KiCad board has no copper layers".into());
    }
    Ok(layers)
}

fn is_copper_like_layer_name(name: &str) -> bool {
    name == "*.Cu" || name.ends_with(".Cu")
}

fn is_known_non_copper_board_layer(name: &str) -> bool {
    matches!(
        name,
        "B.Adhes"
            | "F.Adhes"
            | "B.Paste"
            | "F.Paste"
            | "B.SilkS"
            | "F.SilkS"
            | "B.Mask"
            | "F.Mask"
            | "B.CrtYd"
            | "F.CrtYd"
            | "B.Fab"
            | "F.Fab"
            | "Dwgs.User"
            | "Cmts.User"
            | "Eco1.User"
            | "Eco2.User"
            | "Edge.Cuts"
            | "Margin"
            | "User.Drawings"
            | "User.Comments"
            | "User.Eco1"
            | "User.Eco2"
    ) || name.starts_with("User.")
}

#[derive(Clone, Copy)]
struct ImportedStackEntry {
    copper: Option<Layer>,
    thickness_nm: i64,
    dielectric_constant: Option<f64>,
}

fn import_stackup(top: &[Sexp], copper_layers: &[Layer]) -> Result<Vec<StackupLayer>, String> {
    let Some(setup) = unique_physical_child_values(top, "setup", "KiCad setup")? else {
        return Ok(vec![]);
    };
    let Some(stackup) = unique_physical_child_values(setup, "stackup", "KiCad setup stackup")?
    else {
        return Ok(vec![]);
    };
    let mut entries = Vec::new();
    let mut layer_names = HashSet::new();
    let mut metadata_names = HashSet::new();
    for item in stackup.iter().skip(1) {
        let values = item
            .as_list()
            .ok_or_else(|| "KiCad stackup entry must be a list".to_string())?;
        let entry_name = atom(values.first())
            .ok_or_else(|| "KiCad stackup entry must have a scalar name".to_string())?;
        if !matches!(
            entry_name,
            "layer"
                | "copper_finish"
                | "dielectric_constraints"
                | "edge_connector"
                | "castellated_pads"
                | "edge_plating"
        ) {
            return Err(format!("KiCad stackup contains unknown entry {entry_name}"));
        }
        if entry_name != "layer" {
            if !metadata_names.insert(entry_name) {
                return Err(format!(
                    "KiCad stackup metadata {entry_name} must not be repeated"
                ));
            }
            if values.len() != 2 {
                return Err(format!(
                    "KiCad stackup metadata {entry_name} must contain one value"
                ));
            }
            let value = atom(values.get(1)).ok_or_else(|| {
                format!("KiCad stackup metadata {entry_name} must contain a scalar value")
            })?;
            match entry_name {
                "copper_finish" if value.trim().is_empty() => {
                    return Err("KiCad stackup copper_finish must not be blank".into());
                }
                "dielectric_constraints" if !matches!(value, "yes" | "no") => {
                    return Err("KiCad stackup dielectric_constraints must be yes or no".into());
                }
                "edge_connector" if !matches!(value, "yes" | "bevelled") => {
                    return Err("KiCad stackup edge_connector must be yes or bevelled".into());
                }
                "castellated_pads" | "edge_plating" if value != "yes" => {
                    return Err(format!(
                        "KiCad stackup {entry_name} must be yes when present"
                    ));
                }
                _ => {}
            }
            continue;
        }
        if values.len() < 2 {
            return Err("KiCad stackup layer is missing its name".into());
        }
        let Some(name) = atom(values.get(1)) else {
            return Err("KiCad stackup layer is missing its name".into());
        };
        if !layer_names.insert(name) {
            return Err(format!("KiCad stackup contains duplicate layer {name}"));
        }
        let copper = parse_layer(name).filter(|layer| copper_layers.contains(layer));
        let layer_type = match unique_physical_child_values(
            values,
            "type",
            &format!("KiCad stackup layer {name} type"),
        )? {
            None => "",
            Some(layer_type) => {
                if layer_type.len() != 2 {
                    return Err(format!(
                        "KiCad stackup layer {name} type must contain one value"
                    ));
                }
                atom(layer_type.get(1)).ok_or_else(|| {
                    format!("KiCad stackup layer {name} type must contain a scalar value")
                })?
            }
        };
        let is_dielectric = copper.is_none()
            && (name.starts_with("dielectric")
                || matches!(layer_type, "core" | "prepreg" | "dielectric"));
        if copper.is_none() && !is_dielectric && !is_known_non_copper_board_layer(name) {
            return Err(format!("KiCad stackup contains unknown layer {name}"));
        }
        let thickness_nm = optional_mm_field(
            values,
            "thickness",
            &format!("KiCad stackup layer {name} thickness"),
            false,
            false,
        )?
        .unwrap_or(0);
        let dielectric_constant = match unique_physical_child_values(
            values,
            "epsilon_r",
            &format!("KiCad stackup layer {name} dielectric constant"),
        )? {
            None => None,
            Some(epsilon) => {
                if epsilon.len() != 2 {
                    return Err(format!(
                        "KiCad stackup layer {name} has invalid dielectric constant"
                    ));
                }
                let epsilon = scalar_f64(
                    epsilon.get(1),
                    &format!("KiCad stackup layer {name} dielectric constant"),
                )?;
                if !epsilon.is_finite() || epsilon <= 1.0 {
                    return Err(format!(
                        "KiCad stackup layer {name} has invalid dielectric constant"
                    ));
                }
                Some(epsilon)
            }
        };
        entries.push(ImportedStackEntry {
            copper,
            thickness_nm,
            dielectric_constant,
        });
    }

    let mut imported = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(layer) = entry.copper else {
            continue;
        };
        let mut candidates = Vec::new();
        for direction in [-1_i32, 1] {
            let dielectric_index = index as i32 + direction;
            if dielectric_index < 0 {
                continue;
            }
            let Some(dielectric) = entries.get(dielectric_index as usize) else {
                continue;
            };
            if dielectric.copper.is_some()
                || dielectric.thickness_nm <= 0
                || dielectric.dielectric_constant.is_none()
            {
                continue;
            }
            let reference_index = dielectric_index + direction;
            if reference_index < 0 {
                continue;
            }
            let Some(reference) = entries.get(reference_index as usize) else {
                continue;
            };
            let Some(reference_layer) = reference.copper else {
                continue;
            };
            candidates.push((
                dielectric.thickness_nm,
                dielectric.dielectric_constant.unwrap(),
                reference_layer,
            ));
        }
        candidates.sort_by_key(|candidate| candidate.0);
        let Some((height, dielectric_constant, reference_layer)) = candidates.first().copied()
        else {
            continue;
        };
        let secondary = candidates
            .iter()
            .copied()
            .find(|candidate| candidate.2 != reference_layer);
        imported.push(StackupLayer {
            layer,
            dielectric_height_nm: height,
            dielectric_constant,
            copper_thickness_nm: entry.thickness_nm,
            reference_layer: Some(reference_layer),
            secondary_reference_layer: secondary.map(|candidate| candidate.2),
            secondary_dielectric_height_nm: secondary.map(|candidate| candidate.0),
            secondary_dielectric_constant: secondary.map(|candidate| candidate.1),
        });
    }
    imported.sort_by_key(|entry| entry.layer.index());
    Ok(imported)
}

#[cfg(test)]
fn point_mm(x: f64, y: f64) -> Point {
    point_mm_checked(x, y).expect("point_mm is only used with validated internal coordinates")
}
fn point_mm_checked(x: f64, y: f64) -> Result<Point, String> {
    Ok(Point {
        x_nm: checked_mm_to_nm(x, "point X coordinate", true, false)?,
        y_nm: checked_mm_to_nm(y, "point Y coordinate", true, false)?,
    })
}
fn edge_point_mm(x: f64, y: f64) -> Result<Point, String> {
    let convert = |value: f64, field: &str| {
        checked_mm_to_nm(value, field, true, false).map_err(|error| {
            if error.ends_with("must be finite") {
                "Edge.Cuts coordinates must be finite".to_string()
            } else {
                "Edge.Cuts coordinates exceed nanometer range".to_string()
            }
        })
    };
    Ok(Point {
        x_nm: convert(x, "Edge.Cuts X coordinate")?,
        y_nm: convert(y, "Edge.Cuts Y coordinate")?,
    })
}
fn relative(p: Point, origin: Point) -> Point {
    Point {
        x_nm: relative_coordinate(p.x_nm, origin.x_nm),
        y_nm: relative_coordinate(p.y_nm, origin.y_nm),
    }
}
fn coordinate_span(maximum: i64, minimum: i64) -> i64 {
    (i128::from(maximum) - i128::from(minimum)).clamp(0, i128::from(i64::MAX)) as i64
}
fn relative_coordinate(value: i64, origin: i64) -> i64 {
    (i128::from(value) - i128::from(origin)).clamp(i128::from(i64::MIN), i128::from(i64::MAX))
        as i64
}

/// Convert an untrusted KiCad millimetre value to nanometres without relying
/// on Rust's saturating float-to-integer cast semantics.
///
/// The representable interval is mathematically inclusive at `i64::MIN` and
/// exclusive at `2^63`; `i64::MAX as f64` is itself rounded to `2^63`, so an
/// inclusive comparison against that value would accept an unrepresentable
/// endpoint.  `allow_negative` is used for coordinates and offsets, while
/// dimensions pass `false`; `require_positive` additionally rejects zero.
fn checked_mm_to_nm(
    value: f64,
    field: &str,
    allow_negative: bool,
    require_positive: bool,
) -> Result<i64, String> {
    if !value.is_finite() {
        return Err(format!("{field} must be finite"));
    }
    if !allow_negative && value < 0.0 {
        return Err(format!("{field} must be nonnegative"));
    }
    if require_positive && value <= 0.0 {
        return Err(format!("{field} must be positive"));
    }
    let nanometers = value * NM_PER_MM;
    if !nanometers.is_finite() {
        return Err(format!("{field} is outside the supported range"));
    }
    let rounded = nanometers.round();
    let upper_exclusive = -(i64::MIN as f64); // exactly 2^63
    if rounded < i64::MIN as f64 || rounded >= upper_exclusive {
        return Err(format!("{field} is outside the supported range"));
    }
    if !allow_negative && rounded < 0.0 {
        return Err(format!("{field} must be nonnegative"));
    }
    if require_positive && rounded <= 0.0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(rounded as i64)
}

fn scalar_f64(value: Option<&Sexp>, field: &str) -> Result<f64, String> {
    atom(value)
        .ok_or_else(|| format!("{field} must contain one numeric value"))?
        .parse::<f64>()
        .map_err(|_| format!("{field} must contain one numeric value"))
}

fn unique_physical_child_values<'a>(
    list: &'a [Sexp],
    name: &str,
    field: &str,
) -> Result<Option<&'a [Sexp]>, String> {
    let mut matches = list.iter().filter_map(|value| {
        let values = value.as_list()?;
        (atom(values.first()) == Some(name)).then_some(values)
    });
    let first = matches.next();
    if matches.next().is_some() {
        return Err(format!("{field} must not be repeated"));
    }
    Ok(first)
}

fn optional_mm_field(
    list: &[Sexp],
    name: &str,
    field: &str,
    allow_negative: bool,
    require_positive: bool,
) -> Result<Option<i64>, String> {
    let Some(values) = unique_physical_child_values(list, name, field)? else {
        return Ok(None);
    };
    if values.len() != 2 {
        return Err(format!("{field} must contain one numeric value"));
    }
    Ok(Some(checked_mm_to_nm(
        scalar_f64(values.get(1), field)?,
        field,
        allow_negative,
        require_positive,
    )?))
}

fn optional_point_mm(list: &[Sexp], name: &str, field: &str) -> Result<Option<Point>, String> {
    let Some(values) = unique_physical_child_values(list, name, field)? else {
        return Ok(None);
    };
    if values.len() != 3 {
        return Err(format!("{field} must contain X and Y coordinates"));
    }
    Ok(Some(Point {
        x_nm: checked_mm_to_nm(
            scalar_f64(values.get(1), &format!("{field} X coordinate"))?,
            &format!("{field} X coordinate"),
            true,
            false,
        )?,
        y_nm: checked_mm_to_nm(
            scalar_f64(values.get(2), &format!("{field} Y coordinate"))?,
            &format!("{field} Y coordinate"),
            true,
            false,
        )?,
    }))
}

fn required_point_mm(list: &[Sexp], name: &str, field: &str) -> Result<Point, String> {
    optional_point_mm(list, name, field)?.ok_or_else(|| format!("{field} is missing"))
}

fn required_dimension_pair(list: &[Sexp], name: &str, field: &str) -> Result<(f64, f64), String> {
    let Some(values) = unique_physical_child_values(list, name, field)? else {
        return Err(format!("{field} is missing"));
    };
    if values.len() != 3 {
        return Err(format!("{field} must contain exactly two numeric values"));
    }
    let width = scalar_f64(values.get(1), &format!("{field} width"))?;
    let height = scalar_f64(values.get(2), &format!("{field} height"))?;
    checked_mm_to_nm(width, &format!("{field} width"), false, true)?;
    checked_mm_to_nm(height, &format!("{field} height"), false, true)?;
    Ok((width, height))
}

fn optional_offset_pair(
    list: &[Sexp],
    name: &str,
    field: &str,
) -> Result<Option<(f64, f64)>, String> {
    let Some(values) = unique_physical_child_values(list, name, field)? else {
        return Ok(None);
    };
    if values.len() != 3 {
        return Err(format!("{field} must contain exactly two numeric values"));
    }
    let x = scalar_f64(values.get(1), &format!("{field} X offset"))?;
    let y = scalar_f64(values.get(2), &format!("{field} Y offset"))?;
    checked_mm_to_nm(x, &format!("{field} X offset"), true, false)?;
    checked_mm_to_nm(y, &format!("{field} Y offset"), true, false)?;
    Ok(Some((x, y)))
}

fn optional_position_angle(
    list: &[Sexp],
    name: &str,
    field: &str,
) -> Result<Option<(f64, f64, f64)>, String> {
    let Some(values) = unique_physical_child_values(list, name, field)? else {
        return Ok(None);
    };
    if !matches!(values.len(), 3 | 4) {
        return Err(format!("{field} must contain X, Y, and optional rotation"));
    }
    let x = scalar_f64(values.get(1), &format!("{field} X coordinate"))?;
    let y = scalar_f64(values.get(2), &format!("{field} Y coordinate"))?;
    checked_mm_to_nm(x, &format!("{field} X coordinate"), true, false)?;
    checked_mm_to_nm(y, &format!("{field} Y coordinate"), true, false)?;
    let angle = values
        .get(3)
        .map(|value| scalar_f64(Some(value), &format!("{field} rotation")))
        .transpose()?
        .unwrap_or(0.0);
    if !angle.is_finite() {
        return Err(format!("{field} rotation must be finite"));
    }
    Ok(Some((x, y, angle)))
}

fn checked_nonnegative_nm(value: f64) -> Option<i64> {
    checked_mm_to_nm(value, "dimension", false, false).ok()
}
fn mm(value: i64) -> f64 {
    value as f64 / NM_PER_MM
}

fn child_values<'a>(list: &'a [Sexp], name: &str) -> Option<&'a [Sexp]> {
    list.iter().find_map(|x| {
        let xs = x.as_list()?;
        (atom(xs.first()) == Some(name)).then_some(xs)
    })
}
fn unique_edge_child_values<'a>(
    list: &'a [Sexp],
    name: &str,
) -> Result<Option<&'a [Sexp]>, String> {
    let mut matches = list.iter().filter_map(|value| {
        let values = value.as_list()?;
        (atom(values.first()) == Some(name)).then_some(values)
    });
    let first = matches.next();
    if matches.next().is_some() {
        return Err("Edge.Cuts point lists must not be repeated".into());
    }
    Ok(first)
}
fn is_edge_cuts_primitive(list: &[Sexp]) -> Result<bool, String> {
    let mut layer_count = 0;
    let mut has_edge_cuts = false;
    let mut has_invalid_edge_cuts_arity = false;
    for value in list {
        let Some(values) = value.as_list() else {
            continue;
        };
        if atom(values.first()) == Some("layer") {
            layer_count += 1;
            if atom(values.get(1)) == Some("Edge.Cuts") {
                has_edge_cuts = true;
                has_invalid_edge_cuts_arity |= values.len() != 2;
            }
        }
    }
    if has_edge_cuts && layer_count > 1 {
        return Err("Edge.Cuts layer fields must not be repeated".into());
    }
    if has_invalid_edge_cuts_arity {
        return Err("Edge.Cuts layer fields must contain exactly one value".into());
    }
    Ok(has_edge_cuts)
}
fn child_atom<'a>(list: &'a [Sexp], name: &str) -> Option<&'a str> {
    atom(child_values(list, name)?.get(1))
}
fn edge_child_point(list: &[Sexp], name: &str) -> Result<Option<Point>, String> {
    let mut matches = list.iter().filter_map(|value| {
        let values = value.as_list()?;
        (atom(values.first()) == Some(name)).then_some(values)
    });
    let Some(xs) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err("Edge.Cuts point fields must not be repeated".into());
    }
    if xs.len() != 3 {
        return Err("Edge.Cuts points must contain exactly two coordinates".into());
    }
    let x = scalar_f64(xs.get(1), "Edge.Cuts X coordinate")?;
    let y = scalar_f64(xs.get(2), "Edge.Cuts Y coordinate")?;
    Ok(Some(edge_point_mm(x, y)?))
}
fn atom(value: Option<&Sexp>) -> Option<&str> {
    match value? {
        Sexp::Atom(x) => Some(x),
        _ => None,
    }
}
fn number(value: Option<&Sexp>) -> Option<f64> {
    atom(value)?.parse().ok()
}
fn number_u32(value: Option<&Sexp>) -> Option<u32> {
    atom(value)?.parse().ok()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn rules() -> Rules {
        Rules {
            grid_nm: 250_000,
            track_width_nm: 250_000,
            clearance_nm: 200_000,
            via_diameter_nm: 600_000,
            via_drill_nm: 300_000,
            bend_cost: 5,
            via_cost: 20,
        }
    }
    const PCB: &str = r#"(kicad_pcb (version 20250114) (generator pcbnew)
      (net 0 "") (net 1 "VCC")
      (setup
        (net_class "Power" "power nets"
          (clearance 0.4) (trace_width 0.8) (via_dia 1.0) (via_drill 0.5)
          (add_net "VCC")))
      (gr_rect (start 10 20) (end 40 50) (stroke (width 0.05) (type default)) (fill none) (layer "Edge.Cuts"))
      (footprint "A" (layer "F.Cu") (at 15 25 90)
        (pad "1" thru_hole oval (at 1 0) (size 2 1) (drill 0.5) (layers "*.Cu" "*.Mask") (net 1 "VCC")))
      (footprint "B" (layer "F.Cu") (at 35 45)
        (pad "1" smd rect (at 0 0 30) (size 1 1) (layers "F.Cu") (net 1 "VCC")))
    )"#;

    #[test]
    fn rejects_duplicate_kicad_net_ids() {
        let pcb = r#"(kicad_pcb
          (net 1 "FIRST")
          (net 1 "SECOND")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "KiCad board contains duplicate net ID 1: FIRST and SECOND"
        );
    }

    #[test]
    fn rejects_duplicate_kicad_net_names() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (net 2 "SIG")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "KiCad board contains duplicate net name SIG: IDs 1 and 2"
        );
    }

    #[test]
    fn rejects_missing_and_invalid_kicad_net_ids() {
        for declaration in [r#"(net)"#, r#"(net -1 "SIG")"#, r#"(net invalid "SIG")"#] {
            let pcb = format!(
                r#"(kicad_pcb
                  {declaration}
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad board net is missing a valid numeric ID"
            );
        }
    }

    #[test]
    fn rejects_missing_and_non_scalar_kicad_net_names() {
        for declaration in [r#"(net 1)"#, r#"(net 1 (name "SIG"))"#] {
            let pcb = format!(
                r#"(kicad_pcb
                  {declaration}
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad board net 1 is missing a scalar name"
            );
        }
    }

    #[test]
    fn rejects_extra_values_in_kicad_net_declarations() {
        for declaration in [
            r#"(net 1 "SIGNAL" extra)"#,
            r#"(net 1 "SIGNAL" (alias "OTHER"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  {declaration}
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad board net 1 declaration must contain exactly one ID and name"
            );
        }
    }

    #[test]
    fn rejects_blank_nonzero_kicad_net_names() {
        let unconnected = r#"(kicad_pcb
          (net 0 "")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        assert!(import(unconnected, rules()).is_ok());

        for (declaration, id) in [(r#"(net 1 "")"#, 1), (r#"(net 2 "   ")"#, 2)] {
            let pcb = format!(
                r#"(kicad_pcb
                  {declaration}
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                format!("KiCad board net {id} name must not be blank")
            );
        }
    }

    #[test]
    fn rejects_named_kicad_net_zero() {
        for declaration in [r#"(net 0 "SIG")"#, r#"(net 0 " ")"#] {
            let pcb = format!(
                r#"(kicad_pcb
                  {declaration}
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad board net 0 name must be empty"
            );
        }
    }

    #[test]
    fn rejects_pads_referencing_undeclared_kicad_nets() {
        let pcb = r#"(kicad_pcb
          (net 1 "KNOWN")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "A1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
              (net 2 "MISSING")))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "KiCad pad A1 references undeclared net ID 2"
        );
    }

    #[test]
    fn rejects_missing_and_invalid_kicad_pad_net_ids() {
        for net in [
            r#"(net)"#,
            r#"(net -1 "INVALID")"#,
            r#"(net invalid "INVALID")"#,
            r#"(net (id 1) "INVALID")"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (footprint "P" (layer "F.Cu") (at 2 2)
                    (pad "A1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
                      {net}))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad pad A1 is missing a valid numeric net ID"
            );
        }
    }

    #[test]
    fn rejects_missing_and_non_scalar_kicad_pad_net_names() {
        let unconnected = r#"(kicad_pcb
          (net 0 "")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "A1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
              (net 0 "")))
        )"#;
        assert!(import(unconnected, rules()).is_ok());

        for net in [r#"(net 1)"#, r#"(net 1 (name "SIGNAL"))"#] {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 1 "SIGNAL")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (footprint "P" (layer "F.Cu") (at 2 2)
                    (pad "A1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
                      {net}))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad pad A1 net 1 is missing a scalar name"
            );
        }
    }

    #[test]
    fn rejects_kicad_pad_net_names_that_mismatch_the_declaration() {
        for (declaration, net, error) in [
            (
                r#"(net 1 "SIGNAL")"#,
                r#"(net 1 "OTHER")"#,
                r#"KiCad pad A1 net 1 name "OTHER" does not match declared name "SIGNAL""#,
            ),
            (
                r#"(net 0 "")"#,
                r#"(net 0 "SIGNAL")"#,
                r#"KiCad pad A1 net 0 name "SIGNAL" does not match declared name """#,
            ),
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  {declaration}
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (footprint "P" (layer "F.Cu") (at 2 2)
                    (pad "A1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
                      {net}))
                )"#
            );

            assert_eq!(import(&pcb, rules()).unwrap_err(), error);
        }
    }

    #[test]
    fn rejects_repeated_kicad_pad_net_fields() {
        for net_fields in [
            r#"(net 1 "SIGNAL") (net 1 "SIGNAL")"#,
            r#"(net 1 "SIGNAL") (net 2 "OTHER")"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 1 "SIGNAL")
                  (net 2 "OTHER")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (footprint "P" (layer "F.Cu") (at 2 2)
                    (pad "A1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
                      {net_fields}))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad pad A1 net fields must not be repeated"
            );
        }
    }

    #[test]
    fn rejects_extra_values_in_kicad_pad_net_fields() {
        for net in [
            r#"(net 1 "SIGNAL" extra)"#,
            r#"(net 1 "SIGNAL" (alias "OTHER"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 1 "SIGNAL")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (footprint "P" (layer "F.Cu") (at 2 2)
                    (pad "A1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
                      {net}))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad pad A1 net field must contain exactly one ID and name"
            );
        }
    }

    #[test]
    fn rejects_segments_referencing_undeclared_kicad_nets() {
        let pcb = r#"(kicad_pcb
          (net 1 "KNOWN")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (segment (start 1 1) (end 5 1) (width 0.25) (layer "F.Cu") (net 2))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "KiCad segment references undeclared net ID 2"
        );
    }

    #[test]
    fn rejects_route_arcs_referencing_undeclared_kicad_nets() {
        let pcb = r#"(kicad_pcb
          (net 1 "KNOWN")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (arc (start 1 1) (mid 3 3) (end 5 1)
            (width 0.25) (layer "F.Cu") (net 2))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "KiCad route arc references undeclared net ID 2"
        );
    }

    #[test]
    fn rejects_vias_referencing_undeclared_kicad_nets() {
        let pcb = r#"(kicad_pcb
          (net 1 "KNOWN")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (via (at 3 3) (size 0.6) (drill 0.3)
            (layers "F.Cu" "B.Cu") (net 2))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "KiCad via references undeclared net ID 2"
        );
    }

    #[test]
    fn rejects_copper_zones_referencing_undeclared_kicad_nets() {
        let pcb = r#"(kicad_pcb
          (net 1 "KNOWN")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (zone (net 2) (net_name "UNKNOWN") (layer "F.Cu")
            (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5) (xy 1 5))))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "KiCad copper zone references undeclared net ID 2"
        );
    }

    #[test]
    fn rejects_invalid_routed_copper_net_ids() {
        let primitives = [
            (
                "segment",
                r#"(segment (start 1 1) (end 5 1) (width 0.25)
                  (layer "F.Cu") {net})"#,
            ),
            (
                "route arc",
                r#"(arc (start 1 1) (mid 3 3) (end 5 1) (width 0.25)
                  (layer "F.Cu") {net})"#,
            ),
            (
                "via",
                r#"(via (at 3 3) (size 0.6) (drill 0.3)
                  (layers "F.Cu" "B.Cu") {net})"#,
            ),
            (
                "copper zone",
                r#"(zone {net} (net_name "") (layer "F.Cu")
                  (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5) (xy 1 5))))"#,
            ),
        ];

        for (kind, primitive) in primitives {
            for net in ["(net)", "(net -1)", "(net invalid)", "(net (id 1))"] {
                let pcb = format!(
                    r#"(kicad_pcb
                      (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                      {}
                    )"#,
                    primitive.replace("{net}", net)
                );

                assert_eq!(
                    import(&pcb, rules()).unwrap_err(),
                    format!("KiCad {kind} is missing a valid numeric net ID")
                );
            }
        }
    }

    #[test]
    fn rejects_repeated_routed_copper_net_fields() {
        let primitives = [
            (
                "segment",
                r#"(segment (start 1 1) (end 5 1) (width 0.25)
                  (layer "F.Cu") {nets})"#,
            ),
            (
                "route arc",
                r#"(arc (start 1 1) (mid 3 3) (end 5 1) (width 0.25)
                  (layer "F.Cu") {nets})"#,
            ),
            (
                "via",
                r#"(via (at 3 3) (size 0.6) (drill 0.3)
                  (layers "F.Cu" "B.Cu") {nets})"#,
            ),
            (
                "copper zone",
                r#"(zone {nets} (net_name "SIGNAL") (layer "F.Cu")
                  (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5) (xy 1 5))))"#,
            ),
        ];

        for (kind, primitive) in primitives {
            for nets in ["(net 1) (net 1)", "(net 1) (net 2)"] {
                let pcb = format!(
                    r#"(kicad_pcb
                      (net 1 "SIGNAL")
                      (net 2 "OTHER")
                      (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                      {}
                    )"#,
                    primitive.replace("{nets}", nets)
                );

                assert_eq!(
                    import(&pcb, rules()).unwrap_err(),
                    format!("KiCad {kind} net fields must not be repeated")
                );
            }
        }
    }

    #[test]
    fn rejects_extra_values_in_routed_copper_net_fields() {
        let primitives = [
            (
                "segment",
                r#"(segment (start 1 1) (end 5 1) (width 0.25)
                  (layer "F.Cu") (net 1 extra))"#,
            ),
            (
                "route arc",
                r#"(arc (start 1 1) (mid 3 3) (end 5 1) (width 0.25)
                  (layer "F.Cu") (net 1 extra))"#,
            ),
            (
                "via",
                r#"(via (at 3 3) (size 0.6) (drill 0.3)
                  (layers "F.Cu" "B.Cu") (net 1 extra))"#,
            ),
            (
                "copper zone",
                r#"(zone (net 1 extra) (net_name "SIGNAL") (layer "F.Cu")
                  (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5) (xy 1 5))))"#,
            ),
        ];

        for (kind, primitive) in primitives {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 1 "SIGNAL")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  {primitive}
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                format!("KiCad {kind} net field must contain exactly one ID")
            );
        }
    }

    #[test]
    fn rejects_missing_and_non_scalar_copper_zone_net_names() {
        for net_name in ["", "(net_name)", r#"(net_name (name "SIGNAL"))"#] {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 1 "SIGNAL")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (zone (net 1) {net_name} (layer "F.Cu")
                    (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5) (xy 1 5))))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad copper zone net 1 is missing a scalar name"
            );
        }

        let unconnected = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (zone (net 0) (net_name "") (layer "F.Cu")
            (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5) (xy 1 5))))
        )"#;
        assert!(import(unconnected, rules()).is_ok());
    }

    #[test]
    fn rejects_copper_zone_net_names_that_mismatch_the_declaration() {
        for (declaration, net, net_name, error) in [
            (
                r#"(net 1 "SIGNAL")"#,
                1,
                "OTHER",
                r#"KiCad copper zone net 1 name "OTHER" does not match declared name "SIGNAL""#,
            ),
            (
                r#"(net 0 "")"#,
                0,
                "SIGNAL",
                r#"KiCad copper zone net 0 name "SIGNAL" does not match declared name """#,
            ),
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  {declaration}
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (zone (net {net}) (net_name "{net_name}") (layer "F.Cu")
                    (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5) (xy 1 5))))
                )"#
            );

            assert_eq!(import(&pcb, rules()).unwrap_err(), error);
        }
    }

    #[test]
    fn rejects_repeated_copper_zone_net_name_fields() {
        for net_names in [
            r#"(net_name "SIGNAL") (net_name "SIGNAL")"#,
            r#"(net_name "SIGNAL") (net_name "OTHER")"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 1 "SIGNAL")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (zone (net 1) {net_names} (layer "F.Cu")
                    (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5) (xy 1 5))))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad copper zone net 1 net_name fields must not be repeated"
            );
        }
    }

    #[test]
    fn rejects_extra_values_in_copper_zone_net_name_fields() {
        for net_name in [
            r#"(net_name "SIGNAL" extra)"#,
            r#"(net_name "SIGNAL" (alias "OTHER"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 1 "SIGNAL")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (zone (net 1) {net_name} (layer "F.Cu")
                    (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5) (xy 1 5))))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad copper zone net 1 net_name field must contain exactly one name"
            );
        }
    }

    #[test]
    fn imports_outline_and_rotated_pads() {
        let b = import(PCB, rules()).unwrap();
        assert_eq!(
            (b.board.width_nm, b.board.height_nm),
            (30_000_000, 30_000_000)
        );
        assert_eq!(b.board.outline.len(), 4);
        assert_eq!(
            b.board.nets[0].terminals[0].position,
            Point {
                x_nm: 5_000_000,
                y_nm: 6_000_000
            }
        );
        let pad = &b.board.capsule_obstacles[0];
        assert_eq!(
            pad.start,
            Point {
                x_nm: 5_000_000,
                y_nm: 5_500_000
            }
        );
        assert_eq!(
            pad.end,
            Point {
                x_nm: 5_000_000,
                y_nm: 6_500_000
            }
        );
        assert_eq!(pad.diameter_nm, 1_000_000);
        assert_eq!(
            b.board.polygon_obstacles[0].polygon[0],
            Point {
                x_nm: 24_816_987,
                y_nm: 24_316_987
            }
        );
        assert_eq!(b.board.nets[0].class.as_deref(), Some("Power"));
        let power = &b.board.net_classes["Power"];
        assert_eq!(power.track_width_nm, 800_000);
        assert_eq!(power.clearance_nm, 400_000);
        let through_hole = &b.board.footprints[0].pads[0];
        assert_eq!(through_hole.drill_width_nm, Some(500_000));
        assert_eq!(through_hole.drill_height_nm, Some(500_000));
        assert!(through_hole.plated);
    }

    #[test]
    fn coordinate_normalization_handles_full_signed_range() {
        assert_eq!(coordinate_span(i64::MAX, i64::MIN), i64::MAX);
        assert_eq!(coordinate_span(10, -20), 30);
        assert_eq!(
            relative(
                Point {
                    x_nm: i64::MAX,
                    y_nm: i64::MIN,
                },
                Point {
                    x_nm: i64::MIN,
                    y_nm: i64::MAX,
                },
            ),
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MIN,
            }
        );
        assert_eq!(
            relative(Point { x_nm: 10, y_nm: 20 }, Point { x_nm: 3, y_nm: 5 }),
            Point { x_nm: 7, y_nm: 15 }
        );
    }

    #[test]
    fn checked_mm_conversion_rejects_nonfinite_and_exclusive_upper_bound() {
        assert_eq!(
            checked_mm_to_nm(i64::MIN as f64 / NM_PER_MM, "coordinate", true, false).unwrap(),
            i64::MIN
        );
        assert!(
            checked_mm_to_nm(-(i64::MIN as f64) / NM_PER_MM, "coordinate", true, false).is_err()
        );
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e30] {
            assert!(checked_mm_to_nm(value, "coordinate", true, false).is_err());
        }
        assert!(checked_mm_to_nm(-0.001, "dimension", false, false).is_err());
        assert!(checked_mm_to_nm(0.0, "dimension", false, true).is_err());
    }

    #[test]
    fn absolute_coordinate_translation_saturates_at_signed_limits() {
        let positive_origin = import(PCB, rules()).unwrap();
        assert_eq!(
            positive_origin.absolute(Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }),
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }
        );
        assert_eq!(
            positive_origin.absolute(Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            }),
            Point {
                x_nm: 15_000_000,
                y_nm: 25_000_000,
            }
        );

        let negative_origin = import(
            r#"(kicad_pcb
              (gr_rect (start -20 -30) (end -10 -5) (layer "Edge.Cuts"))
            )"#,
            rules(),
        )
        .unwrap();
        assert_eq!(
            negative_origin.absolute(Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            }),
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            }
        );
    }

    #[test]
    fn courtyard_size_handles_full_signed_coordinate_spans() {
        assert_eq!(
            polygon_size(&[
                Point {
                    x_nm: i64::MIN,
                    y_nm: i64::MAX,
                },
                Point {
                    x_nm: i64::MAX,
                    y_nm: i64::MIN,
                },
            ]),
            Some((i64::MAX, i64::MAX))
        );
        assert_eq!(
            polygon_size(&[Point { x_nm: -20, y_nm: 5 }, Point { x_nm: 10, y_nm: 25 }]),
            Some((30, 20))
        );
        assert_eq!(polygon_size(&[]), None);
    }

    #[test]
    fn placement_pad_bounds_saturate_full_signed_coordinate_offsets() {
        let mut imported = import(PCB, rules()).unwrap();
        imported.board.footprints[0].reference = "U1".into();
        imported.board.footprints[1].reference = "U2".into();
        let footprint = &mut imported.board.footprints[0];
        footprint.position = Point {
            x_nm: i64::MAX,
            y_nm: i64::MAX,
        };
        footprint.rotation_deg = 0.0;
        footprint.pads[0].position = Point {
            x_nm: i64::MIN,
            y_nm: i64::MIN,
        };
        footprint.pads[0].width_nm = i64::MAX;
        footprint.pads[0].height_nm = i64::MAX;

        let problem = imported.placement_problem(1).unwrap();
        assert_eq!(problem.components[0].width_nm, i64::MAX);
        assert_eq!(problem.components[0].height_nm, i64::MAX);
        assert_eq!(
            problem.connections[0].from.offset,
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            }
        );
    }

    #[test]
    fn placement_pad_bounds_reject_rotated_out_of_range_coordinate() {
        let mut imported = import(PCB, rules()).unwrap();
        imported.board.footprints[0].reference = "U1".into();
        imported.board.footprints[1].reference = "U2".into();
        let footprint = &mut imported.board.footprints[0];
        footprint.position = Point {
            x_nm: i64::MAX,
            y_nm: i64::MAX,
        };
        footprint.rotation_deg = 45.0;
        footprint.pads[0].position = Point {
            x_nm: i64::MIN,
            y_nm: i64::MIN,
        };

        let error = imported
            .placement_problem(1)
            .expect_err("rotating a full-range coordinate must return an error");
        assert!(error.contains("point X coordinate is outside the supported range"));
    }

    #[test]
    fn imports_non_plated_oval_drill_dimensions() {
        let source = r#"(kicad_pcb
          (net 0 "")
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (footprint "MountingHole" (layer "F.Cu") (at 10 10 90)
            (pad "" np_thru_hole oval (at 0 0 30) (size 3 2)
              (drill oval 1.2 0.8 (offset 0.3 -0.2))
              (layers "*.Cu" "*.Mask"))))"#;

        let imported = import(source, rules()).unwrap();
        let pad = &imported.board.footprints[0].pads[0];
        assert_eq!(pad.drill_width_nm, Some(1_200_000));
        assert_eq!(pad.drill_height_nm, Some(800_000));
        assert_eq!(pad.drill_offset_x_nm, 300_000);
        assert_eq!(pad.drill_offset_y_nm, -200_000);
        assert!(!pad.plated);
        assert_eq!(pad.rotation_deg, 120.0);
    }

    #[test]
    fn rejects_malformed_or_extra_pad_drill_values() {
        for drill in [
            "oval 1.2 0.8 0.1",
            "0.5 0.4 0.3",
            "oval 1.2 0.8 (unknown 1)",
            "0.5 (offset 0 0) (unknown 1)",
        ] {
            let source = format!(
                r#"(kicad_pcb
                  (net 0 "")
                  (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
                  (footprint "MountingHole" (layer "F.Cu") (at 10 10)
                    (pad "" np_thru_hole oval (at 0 0) (size 3 2)
                      (drill {drill})
                      (layers "*.Cu" "*.Mask"))))"#
            );
            assert!(import(&source, rules()).unwrap_err().contains("pad drill"));
        }
    }

    #[test]
    fn imports_circle_pads_as_exact_round_obstacles() {
        let source = r#"(kicad_pcb
          (net 0 "") (net 1 "SIGNAL")
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (footprint "A" (layer "F.Cu") (at 5 5)
            (pad "1" smd circle (at 0 0) (size 2 2)
              (layers "F.Cu") (net 1 "SIGNAL")))
          (footprint "B" (layer "F.Cu") (at 15 15)
            (pad "1" smd rect (at 0 0) (size 2 2)
              (layers "F.Cu") (net 1 "SIGNAL"))))"#;

        let imported = import(source, rules()).unwrap();
        assert_eq!(imported.board.round_obstacles.len(), 1);
        assert_eq!(imported.board.polygon_obstacles.len(), 1);
        assert_eq!(imported.board.footprints[0].pads[0].shape, PadShape::Circle);
        assert_eq!(imported.board.round_obstacles[0].diameter_nm, 2_000_000);
    }
    #[test]
    fn writes_generated_routes_at_board_level() {
        let b = import(PCB, rules()).unwrap();
        let output = b
            .write_routes(&[Route {
                net_id: 1,
                arcs: vec![],
                teardrops: vec![],
                zones: vec![],
                segments: vec![pcbex_core::Segment {
                    start: Point { x_nm: 0, y_nm: 0 },
                    end: Point {
                        x_nm: 1_000_000,
                        y_nm: 0,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                }],
                vias: vec![],
            }])
            .unwrap();
        let root = parse(&output).unwrap();
        let top = root.as_list().unwrap();
        assert!(top.iter().any(|item| {
            item.as_list()
                .is_some_and(|xs| atom(xs.first()) == Some("segment"))
        }));
        assert!(parse(&output).is_ok());
    }

    #[test]
    fn round_trips_route_arcs_and_writes_native_teardrops() {
        let imported = import(PCB, rules()).unwrap();
        let output = imported
            .write_routes(&[Route {
                net_id: 1,
                segments: vec![],
                arcs: vec![RouteArc {
                    start: Point {
                        x_nm: 5_000_000,
                        y_nm: 6_000_000,
                    },
                    mid: Point {
                        x_nm: 15_000_000,
                        y_nm: 18_000_000,
                    },
                    end: Point {
                        x_nm: 25_000_000,
                        y_nm: 25_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 800_000,
                }],
                vias: vec![],
                teardrops: vec![pcbex_core::Teardrop {
                    polygon: vec![
                        Point {
                            x_nm: 4_500_000,
                            y_nm: 5_500_000,
                        },
                        Point {
                            x_nm: 6_500_000,
                            y_nm: 6_000_000,
                        },
                        Point {
                            x_nm: 4_500_000,
                            y_nm: 6_500_000,
                        },
                    ],
                    layer: Layer::Front,
                }],
                zones: vec![],
            }])
            .unwrap();

        assert!(output.contains("(arc (start 15.000000 26.000000)"));
        assert!(output.contains("(attr (teardrop (type padvia)))"));
        let round_trip = import(&output, rules()).unwrap();
        assert_eq!(round_trip.board.routes[0].arcs.len(), 1);
        assert_eq!(
            round_trip.board.routes[0].arcs[0].mid,
            Point {
                x_nm: 15_000_000,
                y_nm: 18_000_000
            }
        );
    }

    #[test]
    fn writes_and_reimports_native_copper_zones() {
        let imported = import(PCB, rules()).unwrap();
        let polygon = vec![
            Point {
                x_nm: 2_000_000,
                y_nm: 2_000_000,
            },
            Point {
                x_nm: 28_000_000,
                y_nm: 2_000_000,
            },
            Point {
                x_nm: 28_000_000,
                y_nm: 28_000_000,
            },
            Point {
                x_nm: 2_000_000,
                y_nm: 28_000_000,
            },
        ];
        let output = imported
            .write_routes(&[Route {
                net_id: 1,
                segments: vec![],
                arcs: vec![],
                vias: vec![],
                teardrops: vec![],
                zones: vec![CopperZone {
                    polygon: polygon.clone(),
                    layer: Layer::Front,
                    clearance_nm: 400_000,
                    minimum_thickness_nm: 250_000,
                    thermal_relief: true,
                    thermal_gap_nm: 200_000,
                    thermal_spoke_width_nm: 250_000,
                    filled_polygons: vec![polygon.clone()],
                }],
            }])
            .unwrap();

        assert!(output.contains("(net_name \"VCC\")"));
        assert!(output.contains("(connect_pads (clearance 0.400000))"));
        assert!(output.contains("(min_thickness 0.250000)"));
        let round_trip = import(&output, rules()).unwrap();
        let zone = &round_trip.board.routes[0].zones[0];
        assert_eq!(zone.polygon, polygon);
        assert_eq!(zone.clearance_nm, 400_000);
        assert_eq!(zone.minimum_thickness_nm, 250_000);
        assert_eq!(zone.filled_polygons.len(), 1);
        assert_eq!(zone.filled_polygons[0], polygon);
        assert!(round_trip.board.polygon_obstacles.iter().any(|obstacle| {
            obstacle.net_id == Some(1)
                && obstacle.layers == [Layer::Front]
                && obstacle.polygon == polygon
        }));
    }

    #[test]
    fn imports_complete_existing_route_without_writing_it_twice() {
        let pcb = PCB.replace(
            "\n    )",
            "\n      (segment (start 15 26) (end 35 45) (width 0.8) (layer \"F.Cu\") (net 1))\n    )",
        );
        let imported = import(&pcb, rules()).unwrap();
        assert_eq!(imported.board.routes.len(), 1);

        let output = imported.write_routes(&imported.board.routes).unwrap();
        assert_eq!(output, pcb);
        let root = parse(&output).unwrap();
        let segment_count = root
            .as_list()
            .unwrap()
            .iter()
            .filter(|item| {
                item.as_list()
                    .is_some_and(|xs| atom(xs.first()) == Some("segment"))
            })
            .count();
        assert_eq!(segment_count, 1);
    }

    #[test]
    fn leaves_incomplete_existing_copper_as_an_obstacle() {
        let pcb = PCB.replace(
            "\n    )",
            "\n      (segment (start 15 26) (end 20 26) (width 0.8) (layer \"F.Cu\") (net 1))\n    )",
        );
        let imported = import(&pcb, rules()).unwrap();
        assert!(imported.board.routes.is_empty());
        assert!(imported
            .board
            .obstacles
            .iter()
            .any(|obstacle| obstacle.net_id == Some(1)
                && obstacle.layers == vec![Layer::Front]));
    }

    #[test]
    fn imports_non_rectangular_outline() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIGNAL")
          (gr_line (start 0 0) (end 20 0) (layer "Edge.Cuts"))
          (gr_line (start 20 0) (end 20 20) (layer "Edge.Cuts"))
          (gr_line (start 20 20) (end 10 20) (layer "Edge.Cuts"))
          (gr_line (start 10 20) (end 0 10) (layer "Edge.Cuts"))
          (gr_line (start 0 10) (end 0 0) (layer "Edge.Cuts"))
          (footprint "A" (layer "F.Cu") (at 2 2)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu") (net 1 "SIGNAL")))
          (footprint "B" (layer "F.Cu") (at 18 18)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu") (net 1 "SIGNAL")))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        assert_eq!(imported.board.outline.len(), 5);
        assert_eq!(imported.board.width_nm, 20_000_000);
        assert_eq!(imported.board.height_nm, 20_000_000);
        let (routed, report) = pcbex_core::route_board(&imported.board).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(pcbex_core::checking::check_board(&routed).is_clean());
    }

    #[test]
    fn assembles_large_unordered_outline_from_mixed_edge_directions() {
        const SIDE: i64 = 1_024;
        let mut points = Vec::new();
        points.extend((0..SIDE).map(|x_nm| Point { x_nm, y_nm: 0 }));
        points.extend((0..SIDE).map(|y_nm| Point { x_nm: SIDE, y_nm }));
        points.extend((1..=SIDE).rev().map(|x_nm| Point { x_nm, y_nm: SIDE }));
        points.extend((1..=SIDE).rev().map(|y_nm| Point { x_nm: 0, y_nm }));

        let ordered = points
            .iter()
            .copied()
            .zip(points.iter().copied().cycle().skip(1))
            .take(points.len())
            .collect::<Vec<_>>();
        let mut lines = (0..ordered.len())
            .step_by(2)
            .chain((1..ordered.len()).step_by(2))
            .map(|index| {
                let (start, end) = ordered[index];
                if index % 3 == 0 {
                    (end, start)
                } else {
                    (start, end)
                }
            })
            .collect::<Vec<_>>();
        lines.rotate_left(1_337);

        let contours = assemble_contours(lines).unwrap();
        assert_eq!(contours.len(), 1);
        assert_eq!(contours[0].len(), points.len());
        assert!(!polygon_twice_area(&contours[0]).is_zero());
    }

    #[test]
    fn edge_segment_limit_is_enforced_before_insertion() {
        let mut lines = Vec::new();
        let mut unique_edges = HashSet::new();
        for index in 0..MAX_EDGE_SEGMENTS {
            push_unique_edge(
                &mut lines,
                &mut unique_edges,
                Point {
                    x_nm: index as i64,
                    y_nm: 0,
                },
                Point {
                    x_nm: index as i64,
                    y_nm: 1,
                },
            )
            .unwrap();
        }

        assert_eq!(
            push_unique_edge(
                &mut lines,
                &mut unique_edges,
                Point {
                    x_nm: MAX_EDGE_SEGMENTS as i64,
                    y_nm: 0,
                },
                Point {
                    x_nm: MAX_EDGE_SEGMENTS as i64,
                    y_nm: 1,
                },
            )
            .unwrap_err(),
            "Edge.Cuts contains too many segments"
        );
        assert_eq!(lines.len(), MAX_EDGE_SEGMENTS);
        assert_eq!(unique_edges.len(), MAX_EDGE_SEGMENTS);
    }

    #[test]
    fn zero_length_edge_is_rejected_before_insertion() {
        let mut lines = vec![(Point { x_nm: 0, y_nm: 0 }, Point { x_nm: 1, y_nm: 0 })];
        let mut unique_edges =
            HashSet::from([(Point { x_nm: 0, y_nm: 0 }, Point { x_nm: 1, y_nm: 0 })]);
        let point = Point { x_nm: 2, y_nm: 3 };

        assert_eq!(
            push_unique_edge(&mut lines, &mut unique_edges, point, point).unwrap_err(),
            "Edge.Cuts edges must have distinct endpoints"
        );
        assert_eq!(
            lines,
            vec![(Point { x_nm: 0, y_nm: 0 }, Point { x_nm: 1, y_nm: 0 },)]
        );
        assert_eq!(unique_edges.len(), 1);
    }

    #[test]
    fn rejects_edge_cuts_contours_that_branch_at_a_shared_vertex() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (gr_rect (start 20 20) (end 30 30) (layer "Edge.Cuts"))
        )"#;

        assert!(
            import(pcb, rules())
                .unwrap_err()
                .contains("must join exactly two primitives")
        );
    }

    #[test]
    fn rejects_nonzero_area_self_intersecting_edge_cuts_contour() {
        let pcb = r#"(kicad_pcb
          (gr_line (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (gr_line (start 10 10) (end 0 10) (layer "Edge.Cuts"))
          (gr_line (start 0 10) (end 8 0) (layer "Edge.Cuts"))
          (gr_line (start 8 0) (end 0 0) (layer "Edge.Cuts"))
        )"#;

        assert!(
            import(pcb, rules())
                .unwrap_err()
                .contains("must not self-intersect")
        );
    }

    #[test]
    fn imports_outline_with_three_point_arc() {
        let pcb = r#"(kicad_pcb
          (gr_line (start 0 0) (end 20 0) (layer "Edge.Cuts"))
          (gr_line (start 20 0) (end 20 10) (layer "Edge.Cuts"))
          (gr_arc (start 20 10) (mid 10 20) (end 0 10) (layer "Edge.Cuts"))
          (gr_line (start 0 10) (end 0 0) (layer "Edge.Cuts"))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        assert!(imported.board.outline.len() > 30);
        assert_eq!(imported.board.width_nm, 20_000_000);
        assert_eq!(imported.board.height_nm, 20_000_000);
        assert!(imported.board.outline.contains(&Point {
            x_nm: 10_000_000,
            y_nm: 20_000_000,
        }));
    }

    #[test]
    fn imports_edge_cuts_circles_as_outline_and_cutout() {
        let pcb = r#"(kicad_pcb
          (gr_circle (center 20 20) (end 40 20) (layer "Edge.Cuts"))
          (gr_circle (center 20 20) (end 25 20) (layer "Edge.Cuts"))
        )"#;

        let imported = import(pcb, rules()).unwrap();
        assert_eq!(
            (imported.board.width_nm, imported.board.height_nm),
            (40_000_000, 40_000_000)
        );
        assert!(imported.board.outline.len() >= 12);
        assert_eq!(imported.board.cutouts.len(), 1);
        assert!(imported.board.cutouts[0].len() >= 12);
    }

    #[test]
    fn imports_edge_cuts_polygons_as_outline_and_cutout() {
        let pcb = r#"(kicad_pcb
          (gr_poly
            (pts (xy 0 0) (xy 30 0) (xy 40 10) (xy 30 30) (xy 0 20))
            (layer "Edge.Cuts"))
          (gr_poly
            (pts (xy 10 8) (xy 20 8) (xy 18 15) (xy 10 14))
            (layer "Edge.Cuts"))
        )"#;

        let imported = import(pcb, rules()).unwrap();
        assert_eq!(
            (imported.board.width_nm, imported.board.height_nm),
            (40_000_000, 30_000_000)
        );
        assert_eq!(imported.board.outline.len(), 5);
        assert_eq!(imported.board.cutouts.len(), 1);
        assert_eq!(imported.board.cutouts[0].len(), 4);
        assert!(imported.board.outline.contains(&point_mm(40.0, 10.0)));
        assert!(imported.board.cutouts[0].contains(&point_mm(18.0, 15.0)));
    }

    #[test]
    fn rejects_edge_cuts_polygon_above_point_limit() {
        let points = (0..=MAX_EDGE_POLYGON_POINTS)
            .map(|index| format!("(xy {index} 0)"))
            .collect::<Vec<_>>()
            .join(" ");
        let pcb = format!(
            r#"(kicad_pcb
              (gr_poly (pts {points}) (layer "Edge.Cuts"))
            )"#
        );

        assert_eq!(
            import(&pcb, rules()).unwrap_err(),
            "Edge.Cuts polygon contains too many points"
        );
    }

    #[test]
    fn rejects_extra_edge_cuts_xy_values() {
        let polygon = r#"(kicad_pcb
          (gr_poly
            (pts (xy 0 0) (xy 20 0 extra) (xy 20 20) (xy 0 20))
            (layer "Edge.Cuts"))
        )"#;
        let curve = r#"(kicad_pcb
          (gr_curve
            (pts (xy 0 0) (xy 5 5 trailing) (xy 10 5) (xy 20 0))
            (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(polygon, rules()).unwrap_err(),
            "Edge.Cuts polygon points must be xy coordinates"
        );
        assert_eq!(
            import(curve, rules()).unwrap_err(),
            "Edge.Cuts curve requires four xy points"
        );
    }

    #[test]
    fn rejects_repeated_nonclosing_edge_cuts_polygon_vertices() {
        let pcb = r#"(kicad_pcb
          (gr_poly
            (pts
              (xy 0 0)
              (xy 20 0)
              (xy 20 20)
              (xy 10 10)
              (xy 0 20)
              (xy 10 10))
            (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "Edge.Cuts polygon vertices must be distinct"
        );
    }

    #[test]
    fn rejects_self_intersecting_edge_cuts_polygon_during_parsing() {
        let pcb = r#"(kicad_pcb
          (gr_poly
            (pts (xy 0 0) (xy 10 10) (xy 0 10) (xy 8 0))
            (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "Edge.Cuts polygon must not self-intersect"
        );
    }

    #[test]
    fn rejects_zero_area_edge_cuts_polygon_during_parsing() {
        let pcb = r#"(kicad_pcb
          (gr_poly
            (pts (xy 0 0) (xy 10 10) (xy 20 20))
            (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "Edge.Cuts polygon must have nonzero area"
        );
    }

    #[test]
    fn rejects_repeated_edge_cuts_point_lists() {
        let polygon = r#"(kicad_pcb
          (gr_poly
            (pts (xy 0 0) (xy 20 0) (xy 20 20) (xy 0 20))
            (pts (xy 0 0) (xy 10 0) (xy 10 10) (xy 0 10))
            (layer "Edge.Cuts"))
        )"#;
        let curve = r#"(kicad_pcb
          (gr_curve
            (pts (xy 0 0) (xy 5 5) (xy 10 5) (xy 20 0))
            (pts (xy 0 0) (xy 4 4) (xy 8 4) (xy 16 0))
            (layer "Edge.Cuts"))
        )"#;

        for pcb in [polygon, curve] {
            assert_eq!(
                import(pcb, rules()).unwrap_err(),
                "Edge.Cuts point lists must not be repeated"
            );
        }
    }

    #[test]
    fn imports_cubic_edge_cuts_curve_with_bounded_chords() {
        let pcb = r#"(kicad_pcb
          (gr_curve
            (pts (xy 0 10) (xy 0 4.477) (xy 4.477 0) (xy 10 0))
            (layer "Edge.Cuts"))
          (gr_line (start 10 0) (end 20 0) (layer "Edge.Cuts"))
          (gr_line (start 20 0) (end 20 20) (layer "Edge.Cuts"))
          (gr_line (start 20 20) (end 0 20) (layer "Edge.Cuts"))
          (gr_line (start 0 20) (end 0 10) (layer "Edge.Cuts"))
        )"#;

        let imported = import(pcb, rules()).unwrap();
        assert_eq!(
            (imported.board.width_nm, imported.board.height_nm),
            (20_000_000, 20_000_000)
        );
        assert!(imported.board.outline.len() > 12);
        assert!(imported.board.outline.contains(&point_mm(0.0, 10.0)));
        assert!(imported.board.outline.contains(&point_mm(10.0, 0.0)));
        assert!(imported.board.outline.iter().any(
            |point| (point.x_nm - 2_928_875).abs() <= 1 && (point.y_nm - 2_928_875).abs() <= 1
        ));
    }

    #[test]
    fn cubic_edge_curve_sampling_respects_chord_tolerance() {
        let curve = parse(
            r#"(gr_curve
              (pts (xy 0 10) (xy -5 -10) (xy 25 30) (xy 20 0))
              (layer "Edge.Cuts"))"#,
        )
        .unwrap();
        let sampled = sample_curve(curve.as_list().unwrap()).unwrap();

        for step in 0..=1_024 {
            let t = step as f64 / 1_024.0;
            let one_minus_t = 1.0 - t;
            let point = (
                3.0 * one_minus_t.powi(2) * t * -5_000_000.0
                    + 3.0 * one_minus_t * t.powi(2) * 25_000_000.0
                    + t.powi(3) * 20_000_000.0,
                one_minus_t.powi(3) * 10_000_000.0
                    + 3.0 * one_minus_t.powi(2) * t * -10_000_000.0
                    + 3.0 * one_minus_t * t.powi(2) * 30_000_000.0,
            );
            let distance = sampled
                .windows(2)
                .map(|pair| {
                    point_segment_distance(
                        point,
                        (pair[0].x_nm as f64, pair[0].y_nm as f64),
                        (pair[1].x_nm as f64, pair[1].y_nm as f64),
                    )
                })
                .fold(f64::INFINITY, f64::min);
            assert!(distance <= ARC_CHORD_TOLERANCE_NM + 1.0);
        }
    }

    #[test]
    fn rejects_malformed_cubic_edge_cuts_curves() {
        let cases = [
            (
                r#"(kicad_pcb
                  (gr_curve (layer "Edge.Cuts"))
                )"#,
                "Edge.Cuts curve requires four points",
            ),
            (
                r#"(kicad_pcb
                  (gr_curve
                    (pts (xy 0 0) (xy 1 1) (xy 2 2))
                    (layer "Edge.Cuts"))
                )"#,
                "Edge.Cuts curve requires four points",
            ),
            (
                r#"(kicad_pcb
                  (gr_curve
                    (pts (xy 0 0) (xy 1 1) (xy 2 2) (xy 3 3) (xy 4 4))
                    (layer "Edge.Cuts"))
                )"#,
                "Edge.Cuts curve requires four points",
            ),
            (
                r#"(kicad_pcb
                  (gr_curve
                    (pts (xy 0 0) (control 1 1) (xy 2 2) (xy 3 3))
                    (layer "Edge.Cuts"))
                )"#,
                "Edge.Cuts curve requires four xy points",
            ),
            (
                r#"(kicad_pcb
                  (gr_curve
                    (pts (xy 0 0) (xy 1 inf) (xy 2 2) (xy 3 3))
                    (layer "Edge.Cuts"))
                )"#,
                "Edge.Cuts curve coordinates must be finite",
            ),
            (
                r#"(kicad_pcb
                  (gr_curve
                    (pts (xy 1 1) (xy 1 1) (xy 1 1) (xy 1 1))
                    (layer "Edge.Cuts"))
                )"#,
                "Edge.Cuts curve must have distinct endpoints or control points",
            ),
        ];

        for (pcb, expected) in cases {
            assert_eq!(import(pcb, rules()).unwrap_err(), expected);
        }
    }

    #[test]
    fn rejects_malformed_and_zero_radius_edge_cuts_circles() {
        let missing_end = r#"(kicad_pcb
          (gr_circle (center 20 20) (layer "Edge.Cuts"))
        )"#;
        let zero_radius = r#"(kicad_pcb
          (gr_circle (center 20 20) (end 20 20) (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(missing_end, rules()).unwrap_err(),
            "Edge.Cuts circle requires center and end points"
        );
        assert_eq!(
            import(zero_radius, rules()).unwrap_err(),
            "Edge.Cuts circle must have a positive radius"
        );
    }

    #[test]
    fn rejects_edge_cuts_circle_extending_beyond_coordinate_range() {
        let center = Point {
            x_nm: i64::MAX - 100,
            y_nm: 0,
        };
        let end = Point {
            x_nm: i64::MAX - 300,
            y_nm: 0,
        };

        assert_eq!(
            sample_circle(center, end).unwrap_err(),
            "Edge.Cuts circle exceeds nanometer range"
        );

        let boundary_center = Point {
            x_nm: i64::MAX - 200,
            y_nm: 0,
        };
        let boundary_end = Point {
            x_nm: i64::MAX - 400,
            y_nm: 0,
        };
        assert!(
            sample_circle(boundary_center, boundary_end)
                .unwrap()
                .contains(&Point {
                    x_nm: i64::MAX,
                    y_nm: 0,
                })
        );
    }

    #[test]
    fn samples_small_arc_near_coordinate_limit() {
        let center = i64::MAX - 512;
        let start = Point {
            x_nm: center - 256,
            y_nm: center,
        };
        let mid = Point {
            x_nm: center,
            y_nm: center - 256,
        };
        let end = Point {
            x_nm: center + 256,
            y_nm: center,
        };

        let points = sample_arc(start, mid, end).unwrap();
        assert_eq!(points.first(), Some(&start));
        assert_eq!(points.last(), Some(&end));
    }

    #[test]
    fn rejects_edge_cuts_arc_extending_beyond_coordinate_range() {
        let center_x = i64::MAX - 1_000_000;
        let start = Point {
            x_nm: center_x - 1_000_000,
            y_nm: -1_732_051,
        };
        let mid = Point {
            x_nm: i64::MAX,
            y_nm: -1_732_051,
        };
        let end = Point {
            x_nm: i64::MAX,
            y_nm: 1_732_051,
        };

        assert_eq!(
            sample_arc(start, mid, end).unwrap_err(),
            "Edge.Cuts arc exceeds nanometer range"
        );
    }

    #[test]
    fn short_semicircle_keeps_intermediate_sample() {
        let start = Point {
            x_nm: -1_000,
            y_nm: 0,
        };
        let mid = Point {
            x_nm: 0,
            y_nm: -1_000,
        };
        let end = Point {
            x_nm: 1_000,
            y_nm: 0,
        };

        let points = sample_arc(start, mid, end).unwrap();
        assert_eq!(points, vec![start, mid, end]);
    }

    #[test]
    fn asymmetric_arc_keeps_declared_midpoint() {
        let start = Point {
            x_nm: 5_000,
            y_nm: 0,
        };
        let mid = Point {
            x_nm: 3_000,
            y_nm: 4_000,
        };
        let end = Point {
            x_nm: -5_000,
            y_nm: 0,
        };

        let points = sample_arc(start, mid, end).unwrap();
        assert_eq!(points, vec![start, mid, end]);
    }

    #[test]
    fn rejects_edge_cuts_arc_above_segment_limit() {
        let radius_nm = 3_000_000_000_000;
        let start = Point {
            x_nm: -radius_nm,
            y_nm: 0,
        };
        let mid = Point {
            x_nm: 0,
            y_nm: -radius_nm,
        };
        let end = Point {
            x_nm: radius_nm,
            y_nm: 0,
        };

        assert_eq!(
            sample_arc(start, mid, end).unwrap_err(),
            "Edge.Cuts arc requires too many segments"
        );
    }

    #[test]
    fn rejects_collinear_edge_cuts_arc() {
        let pcb = r#"(kicad_pcb
          (gr_arc (start 0 0) (mid 10 0) (end 20 0) (layer "Edge.Cuts"))
        )"#;
        assert!(import(pcb, rules()).unwrap_err().contains("collinear"));
    }

    #[test]
    fn distinguishes_extreme_near_collinear_edge_cuts_arc() {
        let start = Point {
            x_nm: i64::MIN,
            y_nm: i64::MIN,
        };
        let mid = Point { x_nm: 0, y_nm: -1 };
        let end = Point { x_nm: -1, y_nm: -2 };

        assert!(triangle_orientation(start, mid, end).is_negative());
        assert_eq!(
            sample_arc(start, mid, end).unwrap_err(),
            "Edge.Cuts arc geometry exceeds numerical precision"
        );
    }

    #[test]
    fn rejects_repeated_edge_cuts_arc_points() {
        for primitive in [
            r#"(gr_arc (start 0 0) (mid 0 0) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_arc (start 0 0) (mid 10 10) (end 10 10) (layer "Edge.Cuts"))"#,
            r#"(gr_arc (start 0 0) (mid 10 10) (end 0 0) (layer "Edge.Cuts"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  {primitive}
                  (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "Edge.Cuts arc points must be distinct"
            );
        }
    }

    #[test]
    fn rejects_edge_cuts_lines_missing_an_endpoint() {
        let missing_start = r#"(kicad_pcb
          (gr_line (end 20 0) (layer "Edge.Cuts"))
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
        )"#;
        let missing_end = r#"(kicad_pcb
          (gr_line (start 0 0) (layer "Edge.Cuts"))
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
        )"#;

        for pcb in [missing_start, missing_end] {
            assert_eq!(
                import(pcb, rules()).unwrap_err(),
                "Edge.Cuts line requires start and end points"
            );
        }
    }

    #[test]
    fn rejects_nonfinite_edge_cuts_primitive_coordinates() {
        for primitive in [
            r#"(gr_line (start 1e400 0) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_arc (start 0 0) (mid NaN 10) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_circle (center 0 0) (end -1e400 0) (layer "Edge.Cuts"))"#,
            r#"(gr_rect (start 0 0) (end 20 NaN) (layer "Edge.Cuts"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  {primitive}
                  (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "Edge.Cuts coordinates must be finite"
            );
        }
    }

    #[test]
    fn rejects_edge_cuts_coordinates_outside_nanometer_range() {
        for primitive in [
            r#"(gr_line (start 1e20 0) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_arc (start 0 0) (mid -1e20 10) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_circle (center 0 0) (end 1e20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_rect (start 0 0) (end 20 -1e20) (layer "Edge.Cuts"))"#,
            r#"(gr_poly (pts (xy 0 0) (xy 1e20 0) (xy 0 20)) (layer "Edge.Cuts"))"#,
            r#"(gr_curve (pts (xy 0 0) (xy 5 5) (xy 10 5) (xy 1e20 0)) (layer "Edge.Cuts"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  {primitive}
                  (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "Edge.Cuts coordinates exceed nanometer range"
            );
        }
    }

    #[test]
    fn rejects_extra_edge_cuts_point_values() {
        for primitive in [
            r#"(gr_line (start 0 0 1) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_arc (start 0 0) (mid 10 10 extra) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_circle (center 0 0) (end 20 0 90) (layer "Edge.Cuts"))"#,
            r#"(gr_rect (start 0 0 ignored) (end 20 20) (layer "Edge.Cuts"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  {primitive}
                  (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "Edge.Cuts points must contain exactly two coordinates"
            );
        }
    }

    #[test]
    fn rejects_repeated_edge_cuts_point_fields() {
        for primitive in [
            r#"(gr_line (start 0 0) (start 1 1) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_arc (start 0 0) (mid 10 10) (mid 10 9) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_circle (center 0 0) (center 1 1) (end 20 0) (layer "Edge.Cuts"))"#,
            r#"(gr_rect (start 0 0) (end 20 20) (end 19 19) (layer "Edge.Cuts"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  {primitive}
                  (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "Edge.Cuts point fields must not be repeated"
            );
        }
    }

    #[test]
    fn rejects_repeated_edge_cuts_layer_fields() {
        for primitive in [
            r#"(gr_line (start 0 0) (end 20 0) (layer "Edge.Cuts") (layer "F.SilkS"))"#,
            r#"(gr_line (start 0 0) (end 20 0) (layer "F.SilkS") (layer "Edge.Cuts"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  {primitive}
                  (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "Edge.Cuts layer fields must not be repeated"
            );
        }
    }

    #[test]
    fn rejects_extra_edge_cuts_layer_values() {
        let pcb = r#"(kicad_pcb
          (gr_rect
            (start 0 0)
            (end 20 20)
            (layer "Edge.Cuts" "F.SilkS"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "Edge.Cuts layer fields must contain exactly one value"
        );
    }

    #[test]
    fn rejects_zero_length_edge_cuts_line() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (gr_line (start 5 5) (end 5 5) (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "Edge.Cuts line must have distinct endpoints"
        );
    }

    #[test]
    fn rejects_duplicate_edge_cuts_edges_in_either_direction() {
        let same_direction = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (gr_line (start 0 0) (end 20 0) (layer "Edge.Cuts"))
        )"#;
        let reverse_direction = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (gr_line (start 20 0) (end 0 0) (layer "Edge.Cuts"))
        )"#;

        for pcb in [same_direction, reverse_direction] {
            assert_eq!(
                import(pcb, rules()).unwrap_err(),
                "Edge.Cuts contains a duplicate edge"
            );
        }
    }

    #[test]
    fn rejects_edge_cuts_rectangles_missing_a_corner() {
        let missing_start = r#"(kicad_pcb
          (gr_rect (end 20 20) (layer "Edge.Cuts"))
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
        )"#;
        let missing_end = r#"(kicad_pcb
          (gr_rect (start 0 0) (layer "Edge.Cuts"))
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
        )"#;

        for pcb in [missing_start, missing_end] {
            assert_eq!(
                import(pcb, rules()).unwrap_err(),
                "Edge.Cuts rectangle requires start and end points"
            );
        }
    }

    #[test]
    fn rejects_degenerate_edge_cuts_rectangles() {
        let zero_width = r#"(kicad_pcb
          (gr_rect (start 5 0) (end 5 20) (layer "Edge.Cuts"))
        )"#;
        let zero_height = r#"(kicad_pcb
          (gr_rect (start 0 5) (end 20 5) (layer "Edge.Cuts"))
        )"#;

        for pcb in [zero_width, zero_height] {
            assert_eq!(
                import(pcb, rules()).unwrap_err(),
                "Edge.Cuts rectangle must have nonzero width and height"
            );
        }
    }

    #[test]
    fn imports_inner_edge_cuts_as_board_cutouts() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (gr_rect (start 8 8) (end 12 12) (layer "Edge.Cuts"))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        assert_eq!(imported.board.outline.len(), 4);
        assert_eq!(imported.board.cutouts.len(), 1);
        assert_eq!(
            imported.board.cutouts[0][0],
            Point {
                x_nm: 8_000_000,
                y_nm: 8_000_000,
            }
        );
    }

    #[test]
    fn rejects_cutout_edges_that_leave_a_concave_outline() {
        let pcb = r#"(kicad_pcb
          (gr_line (start 0 0) (end 10 0) (layer "Edge.Cuts"))
          (gr_line (start 10 0) (end 10 10) (layer "Edge.Cuts"))
          (gr_line (start 10 10) (end 7 10) (layer "Edge.Cuts"))
          (gr_line (start 7 10) (end 7 3) (layer "Edge.Cuts"))
          (gr_line (start 7 3) (end 3 3) (layer "Edge.Cuts"))
          (gr_line (start 3 3) (end 3 10) (layer "Edge.Cuts"))
          (gr_line (start 3 10) (end 0 10) (layer "Edge.Cuts"))
          (gr_line (start 0 10) (end 0 0) (layer "Edge.Cuts"))
          (gr_line (start 2 8) (end 8 8) (layer "Edge.Cuts"))
          (gr_line (start 8 8) (end 5 1) (layer "Edge.Cuts"))
          (gr_line (start 5 1) (end 2 8) (layer "Edge.Cuts"))
        )"#;

        assert!(
            import(pcb, rules())
                .unwrap_err()
                .contains("cutouts must be inside")
        );
    }

    #[test]
    fn rejects_overlapping_and_nested_edge_cuts_cutouts() {
        let overlapping = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 40 40) (layer "Edge.Cuts"))
          (gr_rect (start 5 5) (end 20 20) (layer "Edge.Cuts"))
          (gr_rect (start 15 15) (end 30 30) (layer "Edge.Cuts"))
        )"#;
        let nested = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 40 40) (layer "Edge.Cuts"))
          (gr_rect (start 5 5) (end 30 30) (layer "Edge.Cuts"))
          (gr_rect (start 10 10) (end 20 20) (layer "Edge.Cuts"))
        )"#;

        for pcb in [overlapping, nested] {
            assert!(
                import(pcb, rules())
                    .unwrap_err()
                    .contains("must not overlap or nest")
            );
        }
    }

    #[test]
    fn point_in_polygon_handles_coordinate_extremes() {
        let polygon = [
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MAX,
            },
        ];

        assert!(point_in_polygon(Point { x_nm: 0, y_nm: 0 }, &polygon));
    }

    #[test]
    fn point_in_polygon_distinguishes_adjacent_extreme_coordinates() {
        let polygon = [
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MAX,
            },
        ];

        assert!(point_in_polygon(
            Point {
                x_nm: i64::MAX - 1,
                y_nm: 0,
            },
            &polygon
        ));
    }

    #[test]
    fn polygon_area_handles_coordinate_extremes() {
        let polygon = [
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MAX,
            },
        ];
        let reversed = polygon.iter().copied().rev().collect::<Vec<_>>();

        let area = polygon_twice_area(&polygon);
        let reversed_area = polygon_twice_area(&reversed);
        let squared_width = (u64::MAX as u128) * (u64::MAX as u128);
        let expected_magnitude = (squared_width >> 127, squared_width << 1);
        assert!(!area.is_zero());
        assert_eq!(area.unsigned_magnitude(), expected_magnitude);
        assert_eq!(reversed_area.unsigned_magnitude(), expected_magnitude);
    }

    #[test]
    fn round_trips_kicad_footprint_placements() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIGNAL")
          (gr_rect (start 10 20) (end 50 40) (layer "Edge.Cuts"))
          (footprint "A" (layer "F.Cu") (at 15 25 90) (locked yes)
            (property "Reference" "U1")
            (pad "1" smd rect (at 1 0) (size 2 1) (layers "F.Cu") (net 1 "SIGNAL")))
          (footprint "B" (layer "F.Cu") (at 45 35)
            (property "Reference" "U2")
            (pad "1" smd rect (at -1 0) (size 2 1) (layers "F.Cu") (net 1 "SIGNAL")))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        let problem = imported.placement_problem(500_000).unwrap();
        assert_eq!(problem.components.len(), 2);
        assert!(problem.components[0].fixed);
        assert_eq!(problem.components[0].position, Some(point_mm(5.0, 5.0)));
        assert_eq!(problem.components[0].rotation_deg, 90);
        assert_eq!(problem.connections.len(), 1);

        let mut placed = problem.components;
        placed[1].position = Some(point_mm(20.0, 10.0));
        placed[1].rotation_deg = 180;
        placed[1].side = BoardSide::Back;
        let output = imported.write_placements(&placed).unwrap();
        assert!(output.contains("(at 30.000000 30.000000 180)"));
        assert!(output.contains("(layer \"B.Cu\")"));
        assert!(output.contains("(at 15.000000 25.000000 90)"));
        let round_trip = import(&output, rules()).unwrap();
        assert_eq!(
            round_trip.board.footprints[1].position,
            point_mm(20.0, 10.0)
        );
        assert_eq!(round_trip.board.footprints[1].rotation_deg, 180.0);
        assert_eq!(
            round_trip.placement_problem(500_000).unwrap().components[1].side,
            BoardSide::Back
        );
    }

    #[test]
    fn imports_inner_copper_layers_and_tracks() {
        let pcb = r#"(kicad_pcb
          (layers
            (0 "F.Cu" signal)
            (2 "In1.Cu" signal)
            (4 "In2.Cu" signal)
            (31 "B.Cu" signal)
            (44 "Edge.Cuts" user))
          (net 1 "SIGNAL")
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (segment (start 2 2) (end 10 2) (width 0.25) (layer "In1.Cu") (net 1))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        assert_eq!(
            imported.board.copper_layers,
            vec![Layer::Front, Layer::Inner(1), Layer::Inner(2), Layer::Back]
        );
        assert!(
            imported.board.obstacles[0]
                .layers
                .contains(&Layer::Inner(1))
        );
    }

    #[test]
    fn segment_rejects_out_of_range_coordinates() {
        let segment = parse(
            r#"(segment
              (start -1e30 -1e30)
              (end 1e30 1e30)
              (width 1e30)
              (layer "F.Cu")
              (net 0))"#,
        )
        .unwrap();
        let mut obstacles = Vec::new();
        let mut routes = HashMap::new();
        assert!(
            import_segment(
                segment.as_list().unwrap(),
                Point { x_nm: 0, y_nm: 0 },
                &rules(),
                &[Layer::Front, Layer::Back],
                &mut obstacles,
                &mut routes,
            )
            .is_err()
        );
        assert!(obstacles.is_empty());
        assert!(routes.is_empty());
    }

    #[test]
    fn route_arc_rejects_out_of_range_coordinates() {
        let arc = parse(
            r#"(arc
              (start -1e30 -1e30)
              (mid 0 1e30)
              (end 1e30 -1e30)
              (width 1e30)
              (layer "F.Cu")
              (net 0))"#,
        )
        .unwrap();
        let mut obstacles = Vec::new();
        let mut routes = HashMap::new();
        assert!(
            import_route_arc(
                arc.as_list().unwrap(),
                Point { x_nm: 0, y_nm: 0 },
                &rules(),
                &[Layer::Front, Layer::Back],
                &mut obstacles,
                &mut routes,
            )
            .is_err()
        );
        assert!(obstacles.is_empty());
        assert!(routes.is_empty());
    }

    #[test]
    fn via_rejects_out_of_range_coordinates() {
        let minimum_via = parse(
            r#"(via
              (at -1e30 -1e30)
              (size 1e30)
              (drill 0.3)
              (layers "F.Cu" "B.Cu")
              (net 0))"#,
        )
        .unwrap();
        let maximum_via = parse(
            r#"(via
              (at 1e30 1e30)
              (size 1e30)
              (drill 0.3)
              (layers "F.Cu" "B.Cu")
              (net 0))"#,
        )
        .unwrap();
        let mut obstacles = Vec::new();
        let mut routes = HashMap::new();
        for via in [&minimum_via, &maximum_via] {
            assert!(
                import_via(
                    via.as_list().unwrap(),
                    Point { x_nm: 0, y_nm: 0 },
                    &rules(),
                    &mut obstacles,
                    &mut routes,
                    &[Layer::Front, Layer::Back],
                )
                .is_err()
            );
        }
        assert!(obstacles.is_empty());
        assert!(routes.is_empty());
    }

    #[test]
    fn oval_pad_rejects_out_of_range_dimensions() {
        let mut round_obstacles = Vec::new();
        let mut capsule_obstacles = Vec::new();
        let mut polygon_obstacles = Vec::new();
        for center in [
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
        ] {
            assert!(
                add_pad_obstacle(
                    PadShape::Oval,
                    0.0,
                    (0.0, 0.0),
                    &[],
                    center,
                    1e30,
                    1.0,
                    45.0,
                    vec![Layer::Front],
                    None,
                    &mut round_obstacles,
                    &mut capsule_obstacles,
                    &mut polygon_obstacles,
                )
                .is_err()
            );
        }

        assert!(round_obstacles.is_empty());
        assert!(polygon_obstacles.is_empty());
        assert!(capsule_obstacles.is_empty());
    }

    #[test]
    fn rectangular_pad_rejects_out_of_range_dimensions() {
        let mut round_obstacles = Vec::new();
        let mut capsule_obstacles = Vec::new();
        let mut polygon_obstacles = Vec::new();
        for center in [
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
        ] {
            assert!(
                add_pad_obstacle(
                    PadShape::Rect,
                    0.0,
                    (0.0, 0.0),
                    &[],
                    center,
                    1e30,
                    1e30,
                    0.0,
                    vec![Layer::Front],
                    None,
                    &mut round_obstacles,
                    &mut capsule_obstacles,
                    &mut polygon_obstacles,
                )
                .is_err()
            );
        }

        assert!(round_obstacles.is_empty());
        assert!(capsule_obstacles.is_empty());
        assert!(polygon_obstacles.is_empty());
    }

    #[test]
    fn custom_pad_polygon_vertices_reject_out_of_range_coordinates() {
        let pad = parse(
            r#"(pad "1" smd custom
              (at 0 0)
              (size 1 1)
              (layers "F.Cu")
              (primitives
                (gr_poly
                  (pts
                    (xy -1e30 -1e30)
                    (xy 1e30 -1e30)
                    (xy 1e30 1e30))
                  (width 0)
                  (fill yes))))"#,
        )
        .unwrap();
        let values = pad.as_list().unwrap();
        let minimum = custom_pad_polygon(
            values,
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            0.0,
        );
        let maximum = custom_pad_polygon(
            values,
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
            0.0,
        );
        assert!(minimum.is_err());
        assert!(maximum.is_err());
    }

    #[test]
    fn imports_stackup_geometry_and_reference_layers() {
        let pcb = r#"(kicad_pcb
          (layers
            (0 "F.Cu" signal)
            (2 "In1.Cu" power)
            (4 "In2.Cu" power)
            (31 "B.Cu" signal)
            (44 "Edge.Cuts" user))
          (setup
            (stackup
              (layer "F.Cu" (type "copper") (thickness 0.035))
              (layer "dielectric 1" (type "prepreg") (thickness 0.20) (epsilon_r 4.2))
              (layer "In1.Cu" (type "copper") (thickness 0.018))
              (layer "dielectric 2" (type "core") (thickness 0.80) (epsilon_r 4.4))
              (layer "In2.Cu" (type "copper") (thickness 0.018))
              (layer "dielectric 3" (type "prepreg") (thickness 0.25) (epsilon_r 4.1))
              (layer "B.Cu" (type "copper") (thickness 0.035))))
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
        )"#;

        let imported = import(pcb, rules()).unwrap();

        assert_eq!(imported.board.stackup.len(), 4);
        assert_eq!(imported.board.stackup[0].layer, Layer::Front);
        assert_eq!(imported.board.stackup[0].dielectric_height_nm, 200_000);
        assert_eq!(imported.board.stackup[0].dielectric_constant, 4.2);
        assert_eq!(imported.board.stackup[0].copper_thickness_nm, 35_000);
        assert_eq!(
            imported.board.stackup[0].reference_layer,
            Some(Layer::Inner(1))
        );
        assert_eq!(
            imported
                .board
                .stackup
                .iter()
                .find(|entry| entry.layer == Layer::Inner(2))
                .unwrap()
                .reference_layer,
            Some(Layer::Back)
        );
        let inner = imported
            .board
            .stackup
            .iter()
            .find(|entry| entry.layer == Layer::Inner(1))
            .unwrap();
        assert_eq!(inner.reference_layer, Some(Layer::Front));
        assert_eq!(inner.secondary_reference_layer, Some(Layer::Inner(2)));
        assert_eq!(inner.secondary_dielectric_height_nm, Some(800_000));
        assert_eq!(inner.secondary_dielectric_constant, Some(4.4));
    }

    #[test]
    fn rejects_duplicate_and_unknown_stackup_entries() {
        let duplicate_setup = r#"(kicad_pcb
          (setup (stackup (layer "F.Cu" (type "copper"))))
          (setup (stackup (layer "B.Cu" (type "copper"))))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts")))"#;
        assert!(
            import(duplicate_setup, rules())
                .unwrap_err()
                .contains("KiCad setup must not be repeated")
        );

        let duplicate_layer = r#"(kicad_pcb
          (setup
            (stackup
              (layer "F.Cu" (type "copper"))
              (layer "F.Cu" (type "copper"))))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts")))"#;
        assert!(
            import(duplicate_layer, rules())
                .unwrap_err()
                .contains("stackup contains duplicate layer")
        );

        let unknown_entry = r#"(kicad_pcb
          (setup (stackup (unknown_physical_entry yes)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts")))"#;
        assert!(
            import(unknown_entry, rules())
                .unwrap_err()
                .contains("stackup contains unknown entry")
        );
    }

    #[test]
    fn accepts_edge_plating_and_validates_stackup_metadata() {
        let valid = r#"(kicad_pcb
          (layers
            (0 "F.Cu" signal)
            (31 "B.Cu" signal)
            (44 "Edge.Cuts" user))
          (setup
            (stackup
              (layer "F.Cu" (type "copper") (thickness 0.035))
              (layer "dielectric 1" (type "core") (thickness 0.8) (epsilon_r 4.2))
              (layer "B.Cu" (type "copper") (thickness 0.035))
              (copper_finish "None")
              (dielectric_constraints no)
              (edge_connector bevelled)
              (castellated_pads yes)
              (edge_plating yes)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts")))"#;
        assert!(import(valid, rules()).is_ok());

        for metadata in [
            "(edge_plating yes) (edge_plating yes)",
            "(edge_plating yes extra)",
            "(edge_plating (yes))",
            "(edge_plating no)",
            "(castellated_pads no)",
            "(edge_connector no)",
            "(dielectric_constraints maybe)",
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (layers
                    (0 "F.Cu" signal)
                    (31 "B.Cu" signal)
                    (44 "Edge.Cuts" user))
                  (setup
                    (stackup
                      (layer "F.Cu" (type "copper"))
                      (layer "dielectric 1" (type "core") (thickness 0.8) (epsilon_r 4.2))
                      (layer "B.Cu" (type "copper"))
                      {metadata}))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts")))"#
            );
            assert!(import(&pcb, rules()).is_err(), "metadata: {metadata}");
        }
    }

    #[test]
    fn infers_differential_pair_from_kicad_net_class() {
        let pcb = r#"(kicad_pcb
          (net 1 "USB_P")
          (net 2 "USB_N")
          (setup
            (net_class "USB" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)
              (diff_pair_width 0.18)
              (diff_pair_gap 0.22)
              (add_net "USB_P")
              (add_net "USB_N")))
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (property "Reference" "J1")
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu") (net 1 "USB_P")))
          (footprint "N" (layer "F.Cu") (at 2 3)
            (property "Reference" "J2")
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu") (net 2 "USB_N")))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        assert_eq!(imported.board.differential_pairs.len(), 1);
        let pair = &imported.board.differential_pairs[0];
        assert_eq!(pair.name, "USB");
        assert_eq!(pair.gap_nm, 220_000);
        assert_eq!(imported.board.rules_for_net(1).track_width_nm, 180_000);
    }

    #[test]
    fn rejects_invalid_legacy_net_class_dimensions() {
        for (key, value) in [
            ("trace_width", "1e20"),
            ("diff_pair_gap", "-0.1"),
            ("via_dia", "nan"),
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (setup
                    (net_class "Invalid" ""
                      ({key} {value})))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                format!("net class Invalid has invalid {key}")
            );
        }
    }

    #[test]
    fn rejects_zero_legacy_track_widths_and_via_drills() {
        for key in ["trace_width", "via_drill"] {
            let pcb = format!(
                r#"(kicad_pcb
                  (setup
                    (net_class "Invalid" ""
                      ({key} 0)))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                format!("net class Invalid has invalid {key}")
            );
        }

        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Valid" ""
              (clearance 0)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        assert_eq!(imported.board.net_classes["Valid"].clearance_nm, 0);
    }

    #[test]
    fn rejects_legacy_via_diameters_not_larger_than_drills() {
        for (via_diameter, via_drill) in [(0.3, 0.3), (0.2, 0.3)] {
            let pcb = format!(
                r#"(kicad_pcb
                  (setup
                    (net_class "Invalid" ""
                      (via_dia {via_diameter})
                      (via_drill {via_drill})))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "net class Invalid via_dia must be greater than via_drill"
            );
        }

        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Valid" ""
              (via_dia 0.301)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        let class = &imported.board.net_classes["Valid"];
        assert_eq!(class.via_diameter_nm, 301_000);
        assert_eq!(class.via_drill_nm, 300_000);
    }

    #[test]
    fn rejects_zero_legacy_differential_widths() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Invalid" ""
              (diff_pair_width 0)
              (diff_pair_gap 0.2)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "net class Invalid has invalid diff_pair_width"
        );

        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Valid" ""
              (diff_pair_width 0.2)
              (diff_pair_gap 0)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        let class = &imported.board.net_classes["Valid"];
        assert_eq!(class.differential_width_nm, Some(200_000));
        assert_eq!(class.differential_gap_nm, Some(0));
    }

    #[test]
    fn rejects_extra_legacy_net_class_dimension_values() {
        for key in [
            "trace_width",
            "clearance",
            "via_dia",
            "via_drill",
            "diff_pair_width",
            "diff_pair_gap",
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (setup
                    (net_class "Invalid" ""
                      ({key} 0.25 extra)))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                format!("net class Invalid has invalid {key}")
            );
        }
    }

    #[test]
    fn rejects_duplicate_legacy_net_class_dimensions() {
        for key in [
            "trace_width",
            "clearance",
            "via_dia",
            "via_drill",
            "diff_pair_width",
            "diff_pair_gap",
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (setup
                    (net_class "Invalid" ""
                      ({key} 0.20)
                      ({key} 0.25)))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                format!("net class Invalid contains duplicate {key}")
            );
        }
    }

    #[test]
    fn rejects_duplicate_legacy_net_class_definitions() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25))
            (net_class "Signal" ""
              (clearance 0.3)
              (trace_width 0.4)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "KiCad board contains duplicate net class Signal"
        );
    }

    #[test]
    fn rejects_blank_legacy_net_class_names() {
        for name in ["", " \t"] {
            let pcb = format!(
                r#"(kicad_pcb
                  (setup
                    (net_class "{name}" ""
                      (clearance 0.2)
                      (trace_width 0.25)))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad board net class name must not be blank"
            );
        }
    }

    #[test]
    fn rejects_legacy_net_classes_without_a_scalar_name() {
        for definition in [
            "(net_class)",
            r#"(net_class (name "Signal") "" (trace_width 0.25))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (setup {definition})
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad board net class is missing its name"
            );
        }
    }

    #[test]
    fn rejects_legacy_net_classes_without_a_scalar_description() {
        for definition in [
            r#"(net_class "Signal")"#,
            r#"(net_class "Signal" (description "signals") (trace_width 0.25))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (setup {definition})
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad board net class Signal is missing a scalar description"
            );
        }

        let empty_description = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        assert!(import(empty_description, rules()).is_ok());
    }

    #[test]
    fn rejects_unexpected_scalar_values_in_legacy_net_classes() {
        for definition in [
            r#"(net_class "Signal" "" extra (trace_width 0.25))"#,
            r#"(net_class "Signal" "signals" first second (clearance 0.2))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (setup {definition})
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "KiCad board net class Signal contains an unexpected scalar value"
            );
        }
    }

    #[test]
    fn rejects_unknown_legacy_net_class_assignments() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (add_net "SIG")
              (add_net "MISSING")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "net class Signal references unknown net MISSING"
        );
    }

    #[test]
    fn rejects_legacy_add_net_without_a_scalar_name() {
        for assignment in ["(add_net)", r#"(add_net (name "SIG"))"#] {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 1 "SIG")
                  (setup
                    (net_class "Signal" ""
                      (clearance 0.2)
                      (trace_width 0.25)
                      {assignment}))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "net class Signal contains add_net without a scalar net name"
            );
        }
    }

    #[test]
    fn rejects_extra_values_in_legacy_add_net_assignments() {
        for assignment in [
            r#"(add_net "SIG" extra)"#,
            r#"(add_net "SIG" (alias "OTHER"))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 1 "SIG")
                  (setup
                    (net_class "Signal" ""
                      (clearance 0.2)
                      (trace_width 0.25)
                      {assignment}))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "net class Signal add_net must contain exactly one net name"
            );
        }
    }

    #[test]
    fn rejects_blank_legacy_add_net_names() {
        for net_name in ["", "   "] {
            let pcb = format!(
                r#"(kicad_pcb
                  (net 0 "")
                  (setup
                    (net_class "Signal" ""
                      (clearance 0.2)
                      (trace_width 0.25)
                      (add_net "{net_name}")))
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                )"#
            );

            assert_eq!(
                import(&pcb, rules()).unwrap_err(),
                "net class Signal add_net name must not be blank"
            );
        }
    }

    #[test]
    fn rejects_duplicate_legacy_add_net_assignments() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (add_net "SIG")
              (add_net "SIG")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "net class Signal contains duplicate add_net assignment for SIG"
        );
    }

    #[test]
    fn rejects_conflicting_legacy_net_class_assignments() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (add_net "SIG"))
            (net_class "Power" ""
              (clearance 0.3)
              (trace_width 0.5)
              (add_net "SIG")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        assert_eq!(
            import(pcb, rules()).unwrap_err(),
            "net SIG is assigned to multiple legacy net classes: Signal and Power"
        );
    }

    #[test]
    fn imports_modern_project_net_classes_and_assignments() {
        let pcb = r#"(kicad_pcb
          (version 20250114)
          (general (thickness 1.6))
          (paper "A4")
          (layers (0 "F.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))
          (net 1 "USB_P") (net 2 "USB_N")
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "1" thru_hole circle (at 0 0) (size 1 1) (drill 0.5) (layers "*.Cu") (net 1 "USB_P")))
          (footprint "N" (layer "F.Cu") (at 2 4)
            (pad "1" thru_hole circle (at 0 0) (size 1 1) (drill 0.5) (layers "*.Cu") (net 2 "USB_N")))
          (gr_rect (start 0 0) (end 10 10) (stroke (width 0.05) (type default)) (fill none) (layer "Edge.Cuts"))
        )"#;
        let mut imported = import(pcb, rules()).unwrap();
        let project = r#"{
          "net_settings": {
            "classes": [{
                "name": "USB", "clearance": 0.18, "track_width": 0.16,
                "via_diameter": 0.5, "via_drill": 0.25,
                "diff_pair_width": 0.16, "diff_pair_gap": 0.20
              }, {
                "name": "Slow", "clearance": 0.20, "track_width": 0.25,
                "via_diameter": 0.6, "via_drill": 0.3
            }],
            "netclass_patterns": [
              {"pattern": "USB_*", "netclass": "USB"},
              {"pattern": "USB_N", "netclass": "Slow"}
            ],
            "netclass_assignments": {"USB_N": "USB"}
          }
        }"#;
        apply_project_net_settings(&mut imported.board, project).unwrap();

        let class = &imported.board.net_classes["USB"];
        assert_eq!(class.track_width_nm, 160_000);
        assert_eq!(class.clearance_nm, 180_000);
        assert_eq!(class.via_diameter_nm, 500_000);
        assert_eq!(class.via_drill_nm, 250_000);
        assert!(
            imported
                .board
                .nets
                .iter()
                .all(|net| net.class.as_deref() == Some("USB"))
        );
        assert_eq!(imported.board.differential_pairs.len(), 1);
        assert_eq!(imported.board.differential_pairs[0].gap_nm, 200_000);

        let applied = apply_custom_design_rules(
            &mut imported.board,
            r#"
              (version 1)
              (rule "USB routing"
                (condition "A.NetClass == 'USB'")
                (constraint clearance (min 0.22mm))
                (constraint track_width (min 0.18mm) (opt 0.19mm))
                (constraint via_diameter (min 0.55mm))
                (constraint hole_size (min 10mil))
                (constraint diff_pair_gap (min 0.21mm))
                (constraint length (min 20mm) (max 25mm)))
            "#,
        )
        .unwrap();
        let class = &imported.board.net_classes["USB"];
        assert_eq!(applied, 6);
        assert_eq!(class.clearance_nm, 220_000);
        assert_eq!(class.track_width_nm, 190_000);
        assert_eq!(class.via_diameter_nm, 550_000);
        assert_eq!(class.via_drill_nm, 254_000);
        assert_eq!(class.differential_gap_nm, Some(210_000));
        assert_eq!(class.minimum_length_nm, Some(20_000_000));
        assert_eq!(class.maximum_length_nm, Some(25_000_000));
        assert!(
            compile_net_pattern("^/sheet/D[0-9]+$")
                .unwrap()
                .is_match("/sheet/D12")
        );
    }

    #[test]
    fn rejects_custom_rule_dimensions_outside_nanometer_range() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for token in ["1e20mm", "1e30mil", "inf"] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (version 1)
                  (rule "Oversized"
                    (condition "A.NetClass == 'Signal'")
                    (constraint track_width (min {token})))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                format!("invalid custom-rule dimension {token}")
            );
        }
    }

    #[test]
    fn rejects_zero_custom_rule_track_widths_and_hole_sizes_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for kind in ["track_width", "hole_size"] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Invalid"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm))
                    (constraint {kind} (min 0mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                format!("custom rule {kind} must be positive")
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
            assert_eq!(class.via_drill_nm, 300_000);
        }

        let mut imported = import(pcb, rules()).unwrap();
        let applied = apply_custom_design_rules(
            &mut imported.board,
            r#"
              (rule "Zero nonnegative dimensions"
                (condition "A.NetClass == 'Signal'")
                (constraint clearance (min 0mm))
                (constraint diff_pair_gap (min 0mm)))
            "#,
        )
        .unwrap();
        assert_eq!(applied, 2);
        let class = &imported.board.net_classes["Signal"];
        assert_eq!(class.clearance_nm, 0);
        assert_eq!(class.differential_gap_nm, Some(0));
    }

    #[test]
    fn rejects_inconsistent_custom_rule_via_dimensions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for (via_diameter, hole_size) in [(0.3, 0.3), (0.2, 0.3)] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Invalid"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm))
                    (constraint via_diameter (min {via_diameter}mm))
                    (constraint hole_size (min {hole_size}mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rules leave net class Signal via_diameter not greater than hole_size"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.via_diameter_nm, 600_000);
            assert_eq!(class.via_drill_nm, 300_000);
        }

        let mut imported = import(pcb, rules()).unwrap();
        let applied = apply_custom_design_rules(
            &mut imported.board,
            r#"
              (rule "Diameter first"
                (condition "A.NetClass == 'Signal'")
                (constraint via_diameter (min 0.2mm)))
              (rule "Smaller hole later"
                (condition "A.NetClass == 'Signal'")
                (constraint hole_size (min 0.1mm)))
            "#,
        )
        .unwrap();
        assert_eq!(applied, 2);
        let class = &imported.board.net_classes["Signal"];
        assert_eq!(class.via_diameter_nm, 200_000);
        assert_eq!(class.via_drill_nm, 100_000);
    }

    #[test]
    fn rejects_zero_custom_rule_length_limits_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for bound in ["min", "max"] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Invalid"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm))
                    (constraint length ({bound} 0mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                format!("custom rule length {bound} must be positive")
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.minimum_length_nm, None);
            assert_eq!(class.maximum_length_nm, None);
        }

        let mut imported = import(pcb, rules()).unwrap();
        let applied = apply_custom_design_rules(
            &mut imported.board,
            r#"
              (rule "Exact positive length"
                (condition "A.NetClass == 'Signal'")
                (constraint length (min 1mm) (max 1mm)))
            "#,
        )
        .unwrap();
        assert_eq!(applied, 1);
        let class = &imported.board.net_classes["Signal"];
        assert_eq!(class.minimum_length_nm, Some(1_000_000));
        assert_eq!(class.maximum_length_nm, Some(1_000_000));
    }

    #[test]
    fn rejects_reversed_custom_rule_length_limits_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let mut imported = import(pcb, rules()).unwrap();
        let custom_rules = r#"
          (rule "Reversed"
            (condition "A.NetClass == 'Signal'")
            (constraint clearance (min 0.4mm))
            (constraint length (min 2mm) (max 1mm)))
        "#;

        assert_eq!(
            apply_custom_design_rules(&mut imported.board, custom_rules).unwrap_err(),
            "custom rule length min must not exceed max"
        );
        let class = &imported.board.net_classes["Signal"];
        assert_eq!(class.clearance_nm, 200_000);
        assert_eq!(class.minimum_length_nm, None);
        assert_eq!(class.maximum_length_nm, None);
    }

    #[test]
    fn rejects_custom_rule_lengths_without_supported_bounds_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for length_constraint in ["(constraint length)", "(constraint length (opt 1mm))"] {
            let mut imported = import(pcb, rules()).unwrap();
            let class = imported.board.net_classes.get_mut("Signal").unwrap();
            class.minimum_length_nm = Some(1_000_000);
            class.maximum_length_nm = Some(2_000_000);
            let custom_rules = format!(
                r#"
                  (rule "Missing bounds"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm))
                    {length_constraint})
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom constraint length has no supported value"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.minimum_length_nm, Some(1_000_000));
            assert_eq!(class.maximum_length_nm, Some(2_000_000));
        }
    }

    #[test]
    fn rejects_repeated_custom_constraint_values_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let cases = [
            ("(constraint clearance (min 0.3mm) (min 0.4mm))", "min"),
            ("(constraint track_width (opt 0.3mm) (opt 0.4mm))", "opt"),
            (
                "(constraint track_width (opt 0.3mm) (min 0.2mm) (min 0.25mm))",
                "min",
            ),
            ("(constraint length (max 2mm) (max 3mm))", "max"),
        ];

        for (constraint, repeated_name) in cases {
            let mut imported = import(pcb, rules()).unwrap();
            let preceding_constraint = if constraint.starts_with("(constraint clearance") {
                "(constraint track_width (min 0.4mm))"
            } else {
                "(constraint clearance (min 0.4mm))"
            };
            let custom_rules = format!(
                r#"
                  (rule "Repeated value"
                    (condition "A.NetClass == 'Signal'")
                    {preceding_constraint}
                    {constraint})
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                format!("custom constraint {repeated_name} value must not be repeated")
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
            assert_eq!(class.minimum_length_nm, None);
            assert_eq!(class.maximum_length_nm, None);
        }
    }

    #[test]
    fn rejects_extra_custom_constraint_dimensions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let cases = [
            ("(constraint clearance (min 0.3mm 0.4mm))", "min"),
            ("(constraint track_width (opt 0.3mm 0.4mm))", "opt"),
            (
                "(constraint track_width (opt 0.3mm) (min 0.2mm 0.25mm))",
                "min",
            ),
            ("(constraint length (max 2mm 3mm))", "max"),
        ];

        for (constraint, malformed_name) in cases {
            let mut imported = import(pcb, rules()).unwrap();
            let preceding_constraint = if constraint.starts_with("(constraint clearance") {
                "(constraint track_width (min 0.4mm))"
            } else {
                "(constraint clearance (min 0.4mm))"
            };
            let custom_rules = format!(
                r#"
                  (rule "Extra dimension"
                    (condition "A.NetClass == 'Signal'")
                    {preceding_constraint}
                    {constraint})
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                format!(
                    "custom constraint {malformed_name} value must contain exactly one dimension"
                )
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
            assert_eq!(class.minimum_length_nm, None);
            assert_eq!(class.maximum_length_nm, None);
        }
    }

    #[test]
    fn rejects_repeated_custom_constraints_within_one_rule_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let cases = [
            (
                "clearance",
                "(constraint clearance (min 0.3mm))
                 (constraint clearance (min 0.4mm))",
            ),
            (
                "track_width",
                "(constraint track_width (min 0.3mm))
                 (constraint track_width (min 0.4mm))",
            ),
            (
                "via_diameter",
                "(constraint via_diameter (min 0.7mm))
                 (constraint via_diameter (min 0.8mm))",
            ),
            (
                "hole_size",
                "(constraint hole_size (min 0.2mm))
                 (constraint hole_size (min 0.25mm))",
            ),
            (
                "diff_pair_gap",
                "(constraint diff_pair_gap (min 0.3mm))
                 (constraint diff_pair_gap (min 0.4mm))",
            ),
            (
                "length",
                "(constraint length (min 1mm) (max 2mm))
                 (constraint length (min 3mm) (max 4mm))",
            ),
        ];

        for (kind, constraints) in cases {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Repeated constraint"
                    (condition "A.NetClass == 'Signal'")
                    {constraints})
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                format!("custom rule repeats {kind} constraint")
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
            assert_eq!(class.via_diameter_nm, 600_000);
            assert_eq!(class.via_drill_nm, 300_000);
            assert_eq!(class.differential_gap_nm, None);
            assert_eq!(class.minimum_length_nm, None);
            assert_eq!(class.maximum_length_nm, None);
        }

        let mut imported = import(pcb, rules()).unwrap();
        let applied = apply_custom_design_rules(
            &mut imported.board,
            r#"
              (rule "First"
                (condition "A.NetClass == 'Signal'")
                (constraint clearance (min 0.3mm)))
              (rule "Second"
                (condition "A.NetClass == 'Signal'")
                (constraint clearance (min 0.4mm)))
            "#,
        )
        .unwrap();
        assert_eq!(applied, 2);
        assert_eq!(imported.board.net_classes["Signal"].clearance_nm, 400_000);
    }

    #[test]
    fn rejects_missing_and_non_scalar_custom_rule_names_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for invalid_rule in [
            r#"(rule
                  (condition "A.NetClass == 'Signal'")
                  (constraint track_width (min 0.4mm)))"#,
            r#"(rule (name "Structured")
                  (condition "A.NetClass == 'Signal'")
                  (constraint track_width (min 0.4mm)))"#,
        ] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  {invalid_rule}
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule must contain one scalar name"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_blank_custom_rule_names_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for rule_name in ["", "   "] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "{rule_name}"
                    (condition "A.NetClass == 'Signal'")
                    (constraint track_width (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule name must not be blank"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_extra_custom_rule_scalar_values_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for invalid_rule in [
            r#"(rule "Extra before" unexpected
                  (condition "A.NetClass == 'Signal'")
                  (constraint track_width (min 0.4mm)))"#,
            r#"(rule "Extra after"
                  (condition "A.NetClass == 'Signal'")
                  (constraint track_width (min 0.4mm))
                  unexpected)"#,
        ] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  {invalid_rule}
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule must not contain extra scalar values"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_repeated_custom_rule_conditions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for second_condition in ["A.NetClass == 'Signal'", "A.NetClass == 'Missing'"] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Ambiguous"
                    (condition "A.NetClass == 'Signal'")
                    (condition "{second_condition}")
                    (constraint track_width (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule condition must not be repeated"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_extra_custom_rule_condition_expressions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for condition in [
            r#"(condition "A.NetClass == 'Signal'" "A.NetClass == 'Missing'")"#,
            r#"(condition "A.NetClass == 'Signal'" (comment "ignored"))"#,
        ] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Extra expression"
                    {condition}
                    (constraint track_width (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule condition must not contain extra expressions"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_missing_and_non_scalar_custom_rule_conditions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for condition in [
            "(condition)",
            r#"(condition (expression "A.NetClass == 'Signal'"))"#,
        ] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Invalid condition"
                    {condition}
                    (constraint track_width (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule condition must contain one scalar expression"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_blank_custom_rule_conditions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for condition in ["", "   "] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Blank condition"
                    (condition "{condition}")
                    (constraint track_width (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule condition must not be blank"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_unterminated_and_trailing_net_class_conditions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let cases = [
            (
                "A.NetClass == 'Signal",
                "custom rule NetClass condition has an unterminated class name",
            ),
            (
                "A.NetClass == 'Signal' || A.NetClass == 'Missing'",
                "custom rule NetClass condition must end after its quoted class name",
            ),
        ];

        for (condition, expected) in cases {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Malformed condition"
                    (condition "{condition}")
                    (constraint track_width (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                expected
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_blank_net_class_conditions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for class_name in ["", "   "] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Blank class"
                    (condition "A.NetClass == '{class_name}'")
                    (constraint track_width (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule NetClass condition class name must not be blank"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_non_equality_net_class_conditions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for condition in [
            "A.NetClass = 'Signal'",
            "A.NetClass != 'Signal'",
            "B.NetClass 'Signal'",
        ] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Invalid operator"
                    (condition "{condition}")
                    (constraint track_width (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule NetClass condition must use the == operator"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_missing_and_unquoted_net_class_names_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for condition in ["A.NetClass ==", "B.NetClass == Signal"] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Invalid class name"
                    (condition "{condition}")
                    (constraint track_width (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom rule NetClass condition must contain one quoted class name"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_missing_and_non_scalar_custom_constraint_types_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for constraint in [
            "(constraint)",
            "(constraint (type track_width) (min 0.4mm))",
        ] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Malformed constraint"
                    (condition "A.NetClass == 'Signal'")
                    {constraint})
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom constraint must contain one scalar type"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_extra_custom_constraint_scalar_values_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for constraint in [
            "(constraint track_width ignored (min 0.4mm))",
            "(constraint track_width (min 0.4mm) ignored)",
        ] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Extra scalar"
                    (condition "A.NetClass == 'Signal'")
                    {constraint})
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom constraint must not contain extra scalar values"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn rejects_blank_custom_constraint_types_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for kind in ["", "   "] {
            let mut imported = import(pcb, rules()).unwrap();
            let custom_rules = format!(
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Blank type"
                    (condition "A.NetClass == 'Signal'")
                    (constraint "{kind}" (min 0.4mm)))
                "#
            );

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, &custom_rules).unwrap_err(),
                "custom constraint type must not be blank"
            );
            let class = &imported.board.net_classes["Signal"];
            assert_eq!(class.clearance_nm, 200_000);
            assert_eq!(class.track_width_nm, 250_000);
        }
    }

    #[test]
    fn only_applies_direct_a_or_b_net_class_conditions() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let mut imported = import(pcb, rules()).unwrap();
        let applied = apply_custom_design_rules(
            &mut imported.board,
            r#"
              (rule "Direct A selector"
                (condition "A.NetClass == 'Signal'")
                (constraint clearance (min 0.4mm)))
              (rule "Direct B selector"
                (condition "B.NetClass == 'Signal'")
                (constraint track_width (min 0.35mm)))
              (rule "Unsupported compound selector"
                (condition "A.Layer == 'F.Cu' && A.NetClass == 'Signal'")
                (constraint via_diameter (min 0.8mm)))
            "#,
        )
        .unwrap();

        assert_eq!(applied, 2);
        let class = &imported.board.net_classes["Signal"];
        assert_eq!(class.clearance_nm, 400_000);
        assert_eq!(class.track_width_nm, 350_000);
        assert_eq!(class.via_diameter_nm, 600_000);
    }

    #[test]
    fn custom_rule_errors_leave_net_classes_unchanged() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Signal" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let cases = [
            (
                r#"
                  (rule "Invalid dimension"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm))
                    (constraint track_width (min 1e20mm)))
                "#,
                "invalid custom-rule dimension 1e20mm",
            ),
            (
                r#"
                  (rule "Valid first"
                    (condition "A.NetClass == 'Signal'")
                    (constraint clearance (min 0.4mm)))
                  (rule "Unknown second"
                    (condition "A.NetClass == 'Missing'")
                    (constraint clearance (min 0.5mm)))
                "#,
                "custom rule references unknown net class Missing",
            ),
        ];

        for (custom_rules, expected) in cases {
            let mut imported = import(pcb, rules()).unwrap();
            let original_clearance = imported.board.net_classes["Signal"].clearance_nm;

            assert_eq!(
                apply_custom_design_rules(&mut imported.board, custom_rules).unwrap_err(),
                expected
            );
            assert_eq!(
                imported.board.net_classes["Signal"].clearance_nm,
                original_clearance
            );
        }
    }

    #[test]
    fn rejects_unknown_project_net_class_assignment() {
        let pcb = r#"(kicad_pcb
          (version 20250114)
          (general (thickness 1.6))
          (paper "A4")
          (layers (0 "F.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))
          (net 1 "SIG")
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "1" thru_hole circle (at 0 0) (size 1 1) (drill 0.5) (layers "*.Cu") (net 1 "SIG")))
          (gr_rect (start 0 0) (end 10 10) (stroke (width 0.05) (type default)) (fill none) (layer "Edge.Cuts"))
        )"#;
        let mut imported = import(pcb, rules()).unwrap();
        let error = apply_project_net_settings(
            &mut imported.board,
            r#"{"net_settings":{"classes":[],"netclass_assignments":{"SIG":"Missing"}}}"#,
        )
        .unwrap_err();
        assert!(error.contains("unknown class Missing"));
    }

    #[test]
    fn rejects_unknown_project_assignment_nets_atomically() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)
              (add_net "SIG")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
              (net 1 "SIG")))
        )"#;
        let mut imported = import(pcb, rules()).unwrap();
        let project = r#"{
          "net_settings": {
            "classes": [{"name": "New", "track_width": 0.3}],
            "netclass_assignments": {"MISSING": "New"}
          }
        }"#;

        assert_eq!(
            apply_project_net_settings(&mut imported.board, project).unwrap_err(),
            "net-class assignment references unknown net MISSING"
        );
        assert!(!imported.board.net_classes.contains_key("New"));
        assert_eq!(imported.board.nets[0].class.as_deref(), Some("Existing"));
    }

    #[test]
    fn rejects_blank_project_assignment_net_names_atomically() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)
              (add_net "SIG")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
              (net 1 "SIG")))
        )"#;

        for net_name in ["", "   "] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = serde_json::json!({
                "net_settings": {
                    "classes": [{"name": "New", "track_width": 0.3}],
                    "netclass_assignments": {net_name: "New"}
                }
            });

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
                "net-class assignment net name must not be blank"
            );
            assert!(!imported.board.net_classes.contains_key("New"));
            assert_eq!(imported.board.nets[0].class.as_deref(), Some("Existing"));
        }
    }

    #[test]
    fn rejects_blank_project_assignment_net_classes_atomically() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)
              (add_net "SIG")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
              (net 1 "SIG")))
        )"#;

        for class in ["", "   "] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = serde_json::json!({
                "net_settings": {
                    "classes": [{"name": "New", "track_width": 0.3}],
                    "netclass_assignments": {"SIG": class}
                }
            });

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
                "net-class assignment for SIG has blank netclass"
            );
            assert!(!imported.board.net_classes.contains_key("New"));
            assert_eq!(imported.board.nets[0].class.as_deref(), Some("Existing"));
        }
    }

    #[test]
    fn rejects_blank_project_net_class_patterns_atomically() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)
              (add_net "SIG")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
              (net 1 "SIG")))
        )"#;

        for pattern in ["", "   "] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = format!(
                r#"{{
                  "net_settings": {{
                    "classes": [{{"name": "New", "track_width": 0.3}}],
                    "netclass_patterns": [{{"pattern": "{pattern}", "netclass": "New"}}]
                  }}
                }}"#
            );

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project).unwrap_err(),
                "net-class pattern is blank"
            );
            assert!(!imported.board.net_classes.contains_key("New"));
            assert_eq!(imported.board.nets[0].class.as_deref(), Some("Existing"));
        }
    }

    #[test]
    fn rejects_blank_project_pattern_net_classes_atomically() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)
              (add_net "SIG")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
              (net 1 "SIG")))
        )"#;

        for class in ["", "   "] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = serde_json::json!({
                "net_settings": {
                    "classes": [{"name": "New", "track_width": 0.3}],
                    "netclass_patterns": [{"pattern": "SIG", "netclass": class}]
                }
            });

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
                "net-class pattern SIG has blank netclass"
            );
            assert!(!imported.board.net_classes.contains_key("New"));
            assert_eq!(imported.board.nets[0].class.as_deref(), Some("Existing"));
        }
    }

    #[test]
    fn rejects_duplicate_project_net_class_patterns_atomically() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)
              (add_net "SIG")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
              (net 1 "SIG")))
        )"#;

        for second_class in ["First", "Second"] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = serde_json::json!({
                "net_settings": {
                    "classes": [
                        {"name": "First", "track_width": 0.2},
                        {"name": "Second", "track_width": 0.3}
                    ],
                    "netclass_patterns": [
                        {"pattern": "SIG", "netclass": "First"},
                        {"pattern": "SIG", "netclass": second_class}
                    ]
                }
            });

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
                "KiCad project contains duplicate net-class pattern SIG"
            );
            assert!(!imported.board.net_classes.contains_key("First"));
            assert!(!imported.board.net_classes.contains_key("Second"));
            assert_eq!(imported.board.nets[0].class.as_deref(), Some("Existing"));
        }
    }

    #[test]
    fn project_setting_errors_leave_classes_and_assignments_unchanged() {
        let pcb = r#"(kicad_pcb
          (net 1 "SIG")
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)
              (via_dia 0.6)
              (via_drill 0.3)
              (add_net "SIG")))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "P" (layer "F.Cu") (at 2 2)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")
              (net 1 "SIG")))
        )"#;
        let mut imported = import(pcb, rules()).unwrap();
        let project = r#"{
          "net_settings": {
            "classes": [{
              "name": "New", "clearance": 0.3, "track_width": 0.4,
              "via_diameter": 0.7, "via_drill": 0.35
            }],
            "netclass_patterns": [
              {"pattern": "SIG", "netclass": "New"}
            ],
            "netclass_assignments": {"SIG": "Missing"}
          }
        }"#;

        assert_eq!(
            apply_project_net_settings(&mut imported.board, project).unwrap_err(),
            "net-class assignment for SIG references unknown class Missing"
        );
        assert!(!imported.board.net_classes.contains_key("New"));
        assert_eq!(imported.board.nets[0].class.as_deref(), Some("Existing"));
    }

    #[test]
    fn rejects_duplicate_project_net_class_definitions() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let mut imported = import(pcb, rules()).unwrap();
        let project = r#"{
          "net_settings": {
            "classes": [
              {"name": "Signal", "track_width": 0.2},
              {"name": "Signal", "track_width": 0.3}
            ]
          }
        }"#;

        assert_eq!(
            apply_project_net_settings(&mut imported.board, project).unwrap_err(),
            "KiCad project contains duplicate net class Signal"
        );
        assert!(!imported.board.net_classes.contains_key("Signal"));
    }

    #[test]
    fn rejects_blank_project_net_class_names_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for name in ["", " \t"] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = serde_json::json!({
                "net_settings": {
                    "classes": [
                        {"name": "New", "track_width": 0.2},
                        {"name": name, "track_width": 0.3}
                    ]
                }
            });

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
                "KiCad project net class name must not be blank"
            );
            assert_eq!(imported.board.net_classes.len(), 1);
            assert!(imported.board.net_classes.contains_key("Existing"));
        }
    }

    #[test]
    fn rejects_project_net_class_dimensions_outside_nanometer_range() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for key in ["track_width", "diff_pair_gap"] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = format!(
                r#"{{
                  "net_settings": {{
                    "classes": [{{"name": "Huge", "{key}": 1e20}}]
                  }}
                }}"#
            );

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project).unwrap_err(),
                format!("net class Huge has invalid {key}")
            );
        }
    }

    #[test]
    fn rejects_zero_project_net_class_positive_dimensions_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for key in ["track_width", "via_drill"] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = serde_json::json!({
                "net_settings": {
                    "classes": [
                        {"name": "Valid", "track_width": 0.3},
                        {"name": "Zero", key: 0.0}
                    ]
                }
            });

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
                format!("net class Zero has invalid {key}")
            );
            assert_eq!(imported.board.net_classes.len(), 1);
            assert!(imported.board.net_classes.contains_key("Existing"));
        }
    }

    #[test]
    fn rejects_project_via_diameters_not_larger_than_drills_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for (via_diameter, via_drill) in [(0.3, 0.3), (0.2, 0.3)] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = serde_json::json!({
                "net_settings": {
                    "classes": [
                        {"name": "Valid", "track_width": 0.3},
                        {
                            "name": "Invalid",
                            "via_diameter": via_diameter,
                            "via_drill": via_drill
                        }
                    ]
                }
            });

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
                "net class Invalid via_diameter must be greater than via_drill"
            );
            assert_eq!(imported.board.net_classes.len(), 1);
            assert!(imported.board.net_classes.contains_key("Existing"));
        }
    }

    #[test]
    fn rejects_zero_project_differential_widths_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let mut imported = import(pcb, rules()).unwrap();
        let project = serde_json::json!({
            "net_settings": {
                "classes": [
                    {"name": "Valid", "diff_pair_width": 0.2},
                    {"name": "Zero", "diff_pair_width": 0.0}
                ]
            }
        });

        assert_eq!(
            apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
            "net class Zero has invalid diff_pair_width"
        );
        assert_eq!(imported.board.net_classes.len(), 1);
        assert!(imported.board.net_classes.contains_key("Existing"));

        let mut imported = import(pcb, rules()).unwrap();
        apply_project_net_settings(
            &mut imported.board,
            r#"{"net_settings":{"classes":[{"name":"Touching","diff_pair_gap":0.0}]}}"#,
        )
        .unwrap();
        assert_eq!(
            imported.board.net_classes["Touching"].differential_gap_nm,
            Some(0)
        );
    }

    #[test]
    fn rejects_zero_project_net_class_length_limits_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;

        for key in ["min_track_length", "max_track_length"] {
            let mut imported = import(pcb, rules()).unwrap();
            let project = serde_json::json!({
                "net_settings": {
                    "classes": [
                        {"name": "Valid", "min_track_length": 1.0},
                        {"name": "Zero", key: 0.0}
                    ]
                }
            });

            assert_eq!(
                apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
                format!("net class Zero has invalid {key}")
            );
            assert_eq!(imported.board.net_classes.len(), 1);
            assert!(imported.board.net_classes.contains_key("Existing"));
        }
    }

    #[test]
    fn rejects_reversed_project_net_class_length_limits_atomically() {
        let pcb = r#"(kicad_pcb
          (setup
            (net_class "Existing" ""
              (clearance 0.2)
              (trace_width 0.25)))
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
        )"#;
        let mut imported = import(pcb, rules()).unwrap();
        let project = serde_json::json!({
            "net_settings": {
                "classes": [
                    {"name": "Valid", "min_track_length": 1.0},
                    {
                        "name": "Reversed",
                        "min_track_length": 2.0,
                        "max_track_length": 1.0
                    }
                ]
            }
        });

        assert_eq!(
            apply_project_net_settings(&mut imported.board, &project.to_string()).unwrap_err(),
            "net class Reversed min_track_length must not exceed max_track_length"
        );
        assert_eq!(imported.board.net_classes.len(), 1);
        assert!(imported.board.net_classes.contains_key("Existing"));

        let mut imported = import(pcb, rules()).unwrap();
        apply_project_net_settings(
            &mut imported.board,
            r#"{"net_settings":{"classes":[{
              "name":"Exact","min_track_length":1.0,"max_track_length":1.0
            }]}}"#,
        )
        .unwrap();
        let exact = &imported.board.net_classes["Exact"];
        assert_eq!(exact.minimum_length_nm, exact.maximum_length_nm);
    }

    #[test]
    fn imports_copper_keepout() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (zone (net 0) (net_name "") (layer "F.Cu")
            (keepout (tracks not_allowed) (vias not_allowed) (copperpour not_allowed))
            (polygon (pts (xy 4 5) (xy 9 5) (xy 9 11) (xy 4 11))))
        )"#;
        let imported = import(pcb, rules()).unwrap();
        assert_eq!(imported.board.keepouts.len(), 1);
        assert_eq!(imported.board.keepouts[0].layers, vec![Layer::Front]);
        assert!(imported.board.keepouts[0].tracks_not_allowed);
        assert!(imported.board.keepouts[0].vias_not_allowed);
        assert!(imported.board.keepouts[0].zones_not_allowed);
        assert_eq!(
            imported.board.keepouts[0].polygon[0],
            Point {
                x_nm: 4_000_000,
                y_nm: 5_000_000
            }
        );
    }

    #[test]
    fn preserves_selective_rule_area_restrictions() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (zone (net 0) (net_name "") (layer "F.Cu")
            (keepout (tracks allowed) (vias not_allowed) (copperpour allowed) (footprints not_allowed))
            (polygon (pts (xy 4 5) (xy 9 5) (xy 9 11) (xy 4 11))))
        )"#;

        let imported = import(pcb, rules()).unwrap();
        let rule_area = &imported.board.keepouts[0];

        assert!(!rule_area.tracks_not_allowed);
        assert!(rule_area.vias_not_allowed);
        assert!(!rule_area.zones_not_allowed);
        assert!(rule_area.footprints_not_allowed);
    }

    #[test]
    fn rejects_malformed_keepout_restrictions() {
        for restriction in [
            "(tracks allowed) (tracks not_allowed)",
            "(unknown not_allowed)",
            "(tracks (not_allowed))",
            "(pads not_allowed)",
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
                  (zone (net 0) (net_name "") (layer "F.Cu")
                    (keepout {restriction})
                    (polygon (pts (xy 4 5) (xy 9 5) (xy 9 11) (xy 4 11))))
                )"#
            );
            assert!(import(&pcb, rules()).is_err(), "restriction: {restriction}");
        }
    }

    #[test]
    fn imports_filled_copper_zone_as_net_owned_geometry() {
        let pcb = r#"(kicad_pcb
          (layers (0 "F.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))
          (net 1 "GND")
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (footprint "TP" (layer "F.Cu") (at 2 2)
            (pad "1" smd circle (at 0 0) (size 1 1) (layers "F.Cu") (net 1 "GND")))
          (zone (net 1) (net_name "GND") (layer "F.Cu")
            (polygon (pts (xy 1 1) (xy 10 1) (xy 10 10) (xy 1 10)))
            (filled_polygon (layer "F.Cu")
              (pts (xy 1 1) (xy 10 1) (xy 10 10) (xy 1 10))))
        )"#;

        let imported = import(pcb, rules()).unwrap();
        let zone = imported
            .board
            .polygon_obstacles
            .iter()
            .find(|obstacle| obstacle.net_id == Some(1))
            .unwrap();
        assert_eq!(zone.layers, vec![Layer::Front]);
        assert_eq!(zone.polygon.len(), 4);
        assert_eq!(zone.polygon[0], point_mm(1.0, 1.0));
    }

    #[test]
    fn round_trips_blind_and_micro_via_layer_ranges() {
        let pcb = r#"(kicad_pcb
          (layers
            (0 "F.Cu" signal) (2 "In1.Cu" signal)
            (4 "In2.Cu" signal) (31 "B.Cu" signal)
            (44 "Edge.Cuts" user))
          (net 1 "SIGNAL")
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (via blind (at 4 4) (size 0.6) (drill 0.3)
            (layers "F.Cu" "In2.Cu") (net 1))
          (via micro (at 6 4) (size 0.3) (drill 0.1)
            (layers "F.Cu" "In1.Cu") (net 1))
        )"#;

        let imported = import(pcb, rules()).unwrap();
        let vias = &imported.board.routes[0].vias;
        assert_eq!(vias[0].kind, ViaKind::BlindBuried);
        assert_eq!(vias[0].start_layer, Layer::Front);
        assert_eq!(vias[0].end_layer, Layer::Inner(2));
        assert_eq!(vias[1].kind, ViaKind::Micro);
        assert_eq!(vias[1].end_layer, Layer::Inner(1));

        let mut generated = imported.board.routes[0].clone();
        generated.net_id = 2;
        let output = imported.write_routes(&[generated]).unwrap();
        assert!(output.contains("(via blind"));
        assert!(output.contains("(layers \"F.Cu\" \"In2.Cu\")"));
        assert!(output.contains("(via micro"));
    }

    #[test]
    fn imports_roundrect_trapezoid_and_custom_pad_geometry() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (footprint "U1" (layer "F.Cu") (at 10 10)
            (pad "1" smd roundrect (at -4 0) (size 2 1) (layers "F.Cu")
              (roundrect_rratio 0.25))
            (pad "2" smd trapezoid (at 0 0) (size 2 1) (rect_delta 0.4 0)
              (layers "F.Cu"))
            (pad "3" smd custom (at 4 0) (size 1 1) (layers "F.Cu")
              (primitives
                (gr_poly (pts (xy -1 -0.5) (xy 1 -0.5) (xy 0 1))
                  (width 0) (fill yes)))))
        )"#;

        let imported = import(pcb, rules()).unwrap();
        let pads = &imported.board.footprints[0].pads;
        assert_eq!(pads[0].shape, PadShape::RoundRect);
        assert_eq!(pads[0].roundrect_radius_nm, 250_000);
        assert_eq!(pads[1].shape, PadShape::Trapezoid);
        assert_eq!(pads[1].trapezoid_delta_x_nm, 400_000);
        assert_eq!(pads[1].trapezoid_delta_y_nm, 0);
        assert_eq!(pads[2].shape, PadShape::Custom);
        assert_eq!(pads[2].custom_polygon.len(), 3);
        assert_eq!(imported.board.polygon_obstacles.len(), 3);
        assert_eq!(imported.board.polygon_obstacles[0].polygon.len(), 16);
    }

    #[test]
    fn rejects_malformed_pad_layers_and_unknown_shapes() {
        for layers in [
            r#"(layers "F.Unknown")"#,
            r#"(layers "F.Mask")"#,
            r#"(layers "F.Cu" (structured yes))"#,
            r#"(layers "F.Cu") (layers "B.Cu")"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (layers (0 "F.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))
                  (net 0 "")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (footprint "U1" (layer "F.Cu") (at 2 2)
                    (pad "1" smd rect (at 0 0) (size 1 1) {layers}))
                )"#
            );
            assert!(import(&pcb, rules()).is_err(), "layers: {layers}");
        }

        let unknown_shape = r#"(kicad_pcb
          (layers (0 "F.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))
          (net 0 "")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "U1" (layer "F.Cu") (at 2 2)
            (pad "1" smd hexagon (at 0 0) (size 1 1) (layers "F.Cu"))))"#;
        assert!(import(unknown_shape, rules()).is_err());
    }

    #[test]
    fn rejects_undeclared_layers_for_copper_primitives_and_fills() {
        let segment = r#"(kicad_pcb
          (net 0 "")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (segment (start 1 1) (end 5 1) (layer "In1.Cu") (width 0.2) (net 0)))"#;
        assert!(
            import(segment, rules())
                .unwrap_err()
                .contains("segment layer references an undeclared copper layer")
        );

        let arc = r#"(kicad_pcb
          (net 0 "")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (arc (start 1 1) (mid 3 3) (end 5 1) (layer "In1.Cu") (width 0.2) (net 0)))"#;
        assert!(
            import(arc, rules())
                .unwrap_err()
                .contains("route arc layer references an undeclared copper layer")
        );

        let zone = r#"(kicad_pcb
          (net 0 "")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (zone (net 0) (net_name "") (layer "In1.Cu")
            (polygon (pts (xy 1 1) (xy 8 1) (xy 8 8))))
        )"#;
        assert!(
            import(zone, rules())
                .unwrap_err()
                .contains("copper zone layer references an undeclared copper layer")
        );

        let filled = r#"(kicad_pcb
          (net 1 "GND")
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (zone (net 1) (net_name "GND") (layer "F.Cu")
            (polygon (pts (xy 1 1) (xy 8 1) (xy 8 8)))
            (filled_polygon (layer "In1.Cu")
              (pts (xy 1 1) (xy 8 1) (xy 8 8))))
        )"#;
        assert!(
            import(filled, rules())
                .unwrap_err()
                .contains("filled polygon layer references an undeclared copper layer")
        );
    }

    #[test]
    fn rejects_pads_with_missing_size() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
          (footprint "U1" (layer "F.Cu") (at 2 2)
            (property "Reference" "U1")
            (pad "1" smd rect (at 0 0) (layers "F.Cu"))))"#;
        assert!(
            import(pcb, rules())
                .unwrap_err()
                .contains("pad size is missing")
        );
    }

    #[test]
    fn rejects_malformed_via_layer_endpoints_and_keepout_layer_selection() {
        for layers in [
            r#"(layers "F.Cu")"#,
            r#"(layers "F.Cu" "F.Cu")"#,
            r#"(layers "F.Cu" "Unknown.Cu")"#,
            r#"(layers "F.Cu" (invalid yes))"#,
            r#"(layers "F.Cu" "B.Cu") (layers "F.Cu" "B.Cu")"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (layers (0 "F.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))
                  (net 0 "")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (via (at 2 2) (size 0.6) (drill 0.3) {layers}))"#
            );
            assert!(import(&pcb, rules()).is_err(), "layers: {layers}");
        }

        for selection in [
            r#"(layer "F.Cu") (layers "B.Cu")"#,
            r#"(layer "Unknown.Cu")"#,
            r#"(layers "F.Cu" "F.Cu")"#,
            r#"(layers (invalid yes))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (layers (0 "F.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))
                  (net 0 "")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (zone (net 0) (net_name "") {selection}
                    (keepout (tracks not_allowed))
                    (polygon (pts (xy 1 1) (xy 5 1) (xy 5 5))))"#
            );
            assert!(import(&pcb, rules()).is_err(), "selection: {selection}");
        }
    }

    #[test]
    fn rejects_malformed_board_layer_tables_and_custom_primitives() {
        for layers in [
            r#"(layers (0 "F.Cu" signal) (2 "In0.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))"#,
            r#"(layers (0 "F.Cu" signal) (2 "Unknown.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))"#,
            r#"(layers (0 "F.Cu" signal) (bad) (31 "B.Cu" signal) (44 "Edge.Cuts" user))"#,
            r#"(layers (0 "F.Cu" signal) (31 "B.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))"#,
        ] {
            let pcb = format!(
                r#"(kicad_pcb {layers}
                  (net 0 "")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts")))"#
            );
            assert!(import(&pcb, rules()).is_err(), "layers: {layers}");
        }

        for primitive in [
            r#"(gr_poly (pts (xy -1 -1) (xy 1 -1) (xy 0 1))) (gr_line (start 0 0) (end 1 1))"#,
            r#"(gr_poly (pts (xy -1 -1) (xy 1 -1) (xy 0 1))) (gr_poly (pts (xy -1 -1) (xy 1 -1) (xy 0 1)))"#,
            "",
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (layers (0 "F.Cu" signal) (31 "B.Cu" signal) (44 "Edge.Cuts" user))
                  (net 0 "")
                  (gr_rect (start 0 0) (end 10 10) (layer "Edge.Cuts"))
                  (footprint "U1" (layer "F.Cu") (at 2 2)
                    (pad "1" smd custom (at 0 0) (size 1 1) (layers "F.Cu")
                      (primitives {primitive}))))"#
            );
            assert!(import(&pcb, rules()).is_err(), "primitive: {primitive}");
        }
    }

    #[test]
    fn placement_uses_courtyard_and_board_side() {
        let pcb = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 30 30) (layer "Edge.Cuts"))
          (footprint "U1" (layer "B.Cu") (at 10 10)
            (property "Reference" "U1")
            (fp_rect (start -3 -2) (end 3 2)
              (stroke (width 0.05) (type default)) (fill none) (layer "B.CrtYd"))
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "B.Cu")))
        )"#;

        let imported = import(pcb, rules()).unwrap();
        let problem = imported.placement_problem(500_000).unwrap();
        let component = &problem.components[0];
        assert_eq!(component.width_nm, 6_000_000);
        assert_eq!(component.height_nm, 4_000_000);
        assert_eq!(component.side, BoardSide::Back);
        assert_eq!(component.allowed_rotations, vec![0, 90, 180, 270]);
        assert_eq!(component.courtyard.len(), 4);
    }

    #[test]
    fn rejects_duplicate_references_and_invalid_placement_layers() {
        let duplicate = r#"(kicad_pcb
          (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
          (footprint "A" (layer "F.Cu") (at 2 2)
            (property "Reference" "U1")
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")))
          (footprint "B" (layer "B.Cu") (at 8 8)
            (property "Reference" "U1")
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "B.Cu"))))"#;
        assert!(
            import(duplicate, rules())
                .unwrap_err()
                .contains("duplicate footprint reference")
        );

        for layer in [
            r#"(layer "F.Cu") (layer "B.Cu")"#,
            r#"(layer "Unknown")"#,
            "",
        ] {
            let pcb = format!(
                r#"(kicad_pcb
                  (gr_rect (start 0 0) (end 20 20) (layer "Edge.Cuts"))
                  (footprint "A" {layer} (at 2 2)
                    (property "Reference" "U1")
                    (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu"))))
                "#
            );
            let imported = import(&pcb, rules()).unwrap();
            assert!(
                imported.placement_problem(500_000).is_err(),
                "layer: {layer}"
            );
        }
    }
}

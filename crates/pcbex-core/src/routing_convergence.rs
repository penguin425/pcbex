use crate::checking::check_board;
use crate::routing_candidates::{objective, objective_costs, selection_cost};
use crate::{
    Board, DEFAULT_ASTAR_WORK_BUDGET, MAX_ASTAR_WORK_BUDGET, RouteReport,
    RoutingCandidateObjective, RoutingQuality, route_board_with_variant_and_work_budget,
    routing_quality, validate_routing_resource_bounds,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    sync::{
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        mpsc,
    },
    thread,
};

pub const ROUTING_CONVERGENCE_REPORT_SCHEMA_VERSION: u32 = 1;
pub const MAX_ROUTING_CONVERGENCE_ROUNDS: usize = 8;
pub const MAX_ROUTING_CONVERGENCE_CANDIDATES_PER_ROUND: usize = 32;
/// Maximum retained or freshly rendered routing-convergence report size.
pub const MAX_ROUTING_CONVERGENCE_REPORT_BYTES: u64 = 16 * 1024 * 1024;

const DEFAULT_ROUNDS: usize = 3;
const DEFAULT_CANDIDATES_PER_ROUND: usize = 5;
const DEFAULT_CANDIDATE_WORKERS: usize = 4;
const DEFAULT_ROUTER_WORKERS: usize = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConvergenceOptions {
    pub max_rounds: usize,
    pub candidates_per_round: usize,
    pub candidate_workers: usize,
    pub router_workers: usize,
    pub maximum_work_units: usize,
}

impl Default for RoutingConvergenceOptions {
    fn default() -> Self {
        Self {
            max_rounds: DEFAULT_ROUNDS,
            candidates_per_round: DEFAULT_CANDIDATES_PER_ROUND,
            candidate_workers: DEFAULT_CANDIDATE_WORKERS,
            router_workers: DEFAULT_ROUTER_WORKERS,
            maximum_work_units: DEFAULT_ASTAR_WORK_BUDGET,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingConvergenceCandidateStatus {
    Admissible,
    RejectedDrcViolations,
    RoutingFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingConvergenceSelectionReason {
    AcceptedConverged,
    AcceptedImprovement,
    BestWithoutImprovement,
    LowerRanked,
    Duplicate,
    DrcViolations,
    RoutingFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingConvergenceTerminationReason {
    Continued,
    Converged,
    Stagnated,
    NoAdmissibleCandidate,
    MaximumRounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingConvergenceStatus {
    Converged,
    Partial,
    NoAdmissibleCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConvergenceMetrics {
    pub routed_nets: usize,
    pub unrouted_nets: usize,
    pub total_length_nm: i64,
    pub total_vias: usize,
    pub total_bends: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConvergenceArtifactIdentity {
    pub bytes: usize,
    pub sha256: String,
}

impl From<&RoutingQuality> for RoutingConvergenceMetrics {
    fn from(quality: &RoutingQuality) -> Self {
        Self {
            routed_nets: quality.routed_nets,
            unrouted_nets: quality.unrouted_nets,
            total_length_nm: quality.total_length_nm,
            total_vias: quality.total_vias,
            total_bends: quality.total_bends,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConvergenceCandidate {
    pub id: String,
    pub objective: RoutingCandidateObjective,
    pub search_variant: u8,
    pub bend_cost: u32,
    pub via_cost: u32,
    pub allocated_work_units: usize,
    pub status: RoutingConvergenceCandidateStatus,
    pub metrics: Option<RoutingConvergenceMetrics>,
    pub drc_violation_count: Option<usize>,
    pub expanded_states: Option<usize>,
    pub selection_cost: Option<u64>,
    pub duplicate_of: Option<String>,
    pub selected_as_round_best: bool,
    pub accepted_for_next_round: bool,
    pub selection_reason: RoutingConvergenceSelectionReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConvergenceRound {
    pub round: usize,
    pub input_metrics: RoutingConvergenceMetrics,
    pub candidates: Vec<RoutingConvergenceCandidate>,
    pub selected_candidate_id: Option<String>,
    pub accepted_candidate_id: Option<String>,
    pub termination_reason: RoutingConvergenceTerminationReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConvergenceReport {
    pub schema_version: u32,
    pub scope: String,
    pub engine_version: String,
    pub status: RoutingConvergenceStatus,
    pub converged: bool,
    pub design_rules_unchanged: bool,
    pub options: RoutingConvergenceOptions,
    pub input_board_canonical: RoutingConvergenceArtifactIdentity,
    pub final_board_canonical: RoutingConvergenceArtifactIdentity,
    pub input_metrics: RoutingConvergenceMetrics,
    pub final_metrics: RoutingConvergenceMetrics,
    pub final_drc_violation_count: usize,
    pub selected_candidate_id: Option<String>,
    pub selected_round: Option<usize>,
    pub total_candidates_evaluated: usize,
    pub allocated_work_units: usize,
    pub termination_reason: RoutingConvergenceTerminationReason,
    pub rounds: Vec<RoutingConvergenceRound>,
}

#[derive(Clone, Debug)]
pub struct RoutingConvergenceResult {
    pub board: Board,
    pub report: RoutingConvergenceReport,
    pub selected_route_report: Option<RouteReport>,
}

struct GeneratedCandidate {
    record: RoutingConvergenceCandidate,
    board: Option<Board>,
    route_report: Option<RouteReport>,
}

pub fn route_board_with_convergence(
    board: &Board,
    options: &RoutingConvergenceOptions,
) -> Result<RoutingConvergenceResult, String> {
    route_board_with_convergence_for_engine(board, options, env!("CARGO_PKG_VERSION"))
}

fn route_board_with_convergence_for_engine(
    board: &Board,
    options: &RoutingConvergenceOptions,
    engine_version: &str,
) -> Result<RoutingConvergenceResult, String> {
    validate_engine_version(engine_version)?;
    validate_options(options)?;
    validate_routing_resource_bounds(board)?;
    let input_check = check_board(board);
    let input_drc_violations = blocking_violation_count(&input_check);
    if input_drc_violations != 0 {
        return Err(format!(
            "routing convergence requires a DRC-clean input board ({} violation(s))",
            input_drc_violations
        ));
    }

    let total_slots = options
        .max_rounds
        .checked_mul(options.candidates_per_round)
        .ok_or_else(|| "routing convergence candidate allocation overflow".to_string())?;
    let input_quality = routing_quality(board);
    let input_metrics = RoutingConvergenceMetrics::from(&input_quality);
    let input_board_canonical = board_identity(board)?;
    let mut seed = board.clone();
    let mut rounds = Vec::with_capacity(options.max_rounds);
    let mut selected_candidate_id = None;
    let mut selected_round = None;
    let mut selected_route_report = None;
    let mut allocated_work_units = 0_usize;
    let mut termination_reason = RoutingConvergenceTerminationReason::MaximumRounds;

    if input_metrics.unrouted_nets == 0 {
        return Ok(RoutingConvergenceResult {
            board: seed,
            selected_route_report,
            report: RoutingConvergenceReport {
                schema_version: ROUTING_CONVERGENCE_REPORT_SCHEMA_VERSION,
                scope: "bounded_deterministic_routing_convergence".into(),
                engine_version: engine_version.into(),
                status: RoutingConvergenceStatus::Converged,
                converged: true,
                design_rules_unchanged: true,
                options: options.clone(),
                input_board_canonical: input_board_canonical.clone(),
                final_board_canonical: input_board_canonical,
                input_metrics: input_metrics.clone(),
                final_metrics: input_metrics,
                final_drc_violation_count: 0,
                selected_candidate_id,
                selected_round,
                total_candidates_evaluated: 0,
                allocated_work_units,
                termination_reason: RoutingConvergenceTerminationReason::Converged,
                rounds,
            },
        });
    }

    for round_index in 0..options.max_rounds {
        let round_number = round_index + 1;
        let seed_quality = routing_quality(&seed);
        let round_input_metrics = RoutingConvergenceMetrics::from(&seed_quality);
        let mut generated = generate_round(
            &seed,
            options,
            round_index,
            total_slots,
            &mut allocated_work_units,
        );
        let winner = select_round_winner(
            &generated
                .iter()
                .map(|candidate| candidate.record.clone())
                .collect::<Vec<_>>(),
        );
        let mut accepted_candidate_id = None;
        let mut round_termination = RoutingConvergenceTerminationReason::NoAdmissibleCandidate;

        if let Some(winner_index) = winner {
            let winner_score = candidate_score(&generated[winner_index].record)
                .expect("an admissible routing candidate has metrics");
            let seed_score = quality_score(board, &seed_quality);
            let improved = winner_score < seed_score;
            let converged = generated[winner_index]
                .record
                .metrics
                .as_ref()
                .is_some_and(|metrics| metrics.unrouted_nets == 0);

            for (index, candidate) in generated.iter_mut().enumerate() {
                if index == winner_index {
                    candidate.record.selected_as_round_best = true;
                    if improved {
                        candidate.record.accepted_for_next_round = true;
                        candidate.record.selection_reason = if converged {
                            RoutingConvergenceSelectionReason::AcceptedConverged
                        } else {
                            RoutingConvergenceSelectionReason::AcceptedImprovement
                        };
                    } else {
                        candidate.record.selection_reason =
                            RoutingConvergenceSelectionReason::BestWithoutImprovement;
                    }
                }
            }

            let winner_id = generated[winner_index].record.id.clone();
            if improved {
                seed = generated[winner_index]
                    .board
                    .take()
                    .expect("an admissible routing candidate retains its board");
                selected_route_report = generated[winner_index].route_report.take();
                accepted_candidate_id = Some(winner_id.clone());
                selected_candidate_id = Some(winner_id.clone());
                selected_round = Some(round_number);
                round_termination = if converged {
                    RoutingConvergenceTerminationReason::Converged
                } else if round_number == options.max_rounds {
                    RoutingConvergenceTerminationReason::MaximumRounds
                } else {
                    RoutingConvergenceTerminationReason::Continued
                };
            } else {
                round_termination = RoutingConvergenceTerminationReason::Stagnated;
            }

            rounds.push(RoutingConvergenceRound {
                round: round_number,
                input_metrics: round_input_metrics,
                candidates: generated
                    .into_iter()
                    .map(|candidate| candidate.record)
                    .collect(),
                selected_candidate_id: Some(winner_id),
                accepted_candidate_id,
                termination_reason: round_termination,
            });
        } else {
            rounds.push(RoutingConvergenceRound {
                round: round_number,
                input_metrics: round_input_metrics,
                candidates: generated
                    .into_iter()
                    .map(|candidate| candidate.record)
                    .collect(),
                selected_candidate_id: None,
                accepted_candidate_id: None,
                termination_reason: round_termination,
            });
        }

        termination_reason = round_termination;
        if round_termination != RoutingConvergenceTerminationReason::Continued {
            break;
        }
    }

    if seed.rules != board.rules {
        return Err("routing convergence changed the selected board design rules".into());
    }
    let final_check = check_board(&seed);
    let final_drc_violation_count = blocking_violation_count(&final_check);
    if final_drc_violation_count != 0 {
        return Err("routing convergence selected a board with DRC violations".into());
    }
    let final_quality = routing_quality(&seed);
    let final_metrics = RoutingConvergenceMetrics::from(&final_quality);
    let final_board_canonical = board_identity(&seed)?;
    let converged = final_metrics.unrouted_nets == 0;
    let status = if converged {
        RoutingConvergenceStatus::Converged
    } else if termination_reason == RoutingConvergenceTerminationReason::NoAdmissibleCandidate
        && selected_candidate_id.is_none()
    {
        RoutingConvergenceStatus::NoAdmissibleCandidate
    } else {
        RoutingConvergenceStatus::Partial
    };
    let total_candidates_evaluated = rounds.iter().map(|round| round.candidates.len()).sum();
    Ok(RoutingConvergenceResult {
        board: seed,
        selected_route_report,
        report: RoutingConvergenceReport {
            schema_version: ROUTING_CONVERGENCE_REPORT_SCHEMA_VERSION,
            scope: "bounded_deterministic_routing_convergence".into(),
            engine_version: engine_version.into(),
            status,
            converged,
            design_rules_unchanged: true,
            options: options.clone(),
            input_board_canonical,
            final_board_canonical,
            input_metrics,
            final_metrics,
            final_drc_violation_count,
            selected_candidate_id,
            selected_round,
            total_candidates_evaluated,
            allocated_work_units,
            termination_reason,
            rounds,
        },
    })
}

/// Freshly reproduce one retained convergence report from the exact effective
/// input Board. The retained producer version is preserved only as report
/// metadata; schema-v1 behavior is always recomputed by the current verifier.
/// Every other field must match the fresh deterministic result exactly.
pub fn verify_routing_convergence_report(
    board: &Board,
    retained: &RoutingConvergenceReport,
) -> Result<RoutingConvergenceResult, String> {
    if retained.schema_version != ROUTING_CONVERGENCE_REPORT_SCHEMA_VERSION {
        return Err("unsupported routing convergence report schema version".into());
    }
    if retained.scope != "bounded_deterministic_routing_convergence" {
        return Err("routing convergence report scope is invalid".into());
    }
    validate_engine_version(&retained.engine_version)?;
    let fresh = route_board_with_convergence_for_engine(
        board,
        &retained.options,
        &retained.engine_version,
    )?;
    if fresh.report != *retained {
        return Err(
            "retained routing convergence report does not match a fresh deterministic replay"
                .into(),
        );
    }
    Ok(fresh)
}

fn validate_engine_version(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 32 {
        return Err("routing convergence engine version is not bounded semantic version".into());
    }
    let mut components = value.split('.');
    for _ in 0..3 {
        let Some(component) = components.next() else {
            return Err(
                "routing convergence engine version is not bounded semantic version".into(),
            );
        };
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(
                "routing convergence engine version is not bounded semantic version".into(),
            );
        }
    }
    if components.next().is_some() {
        return Err("routing convergence engine version is not bounded semantic version".into());
    }
    Ok(())
}

fn validate_options(options: &RoutingConvergenceOptions) -> Result<(), String> {
    if !(1..=MAX_ROUTING_CONVERGENCE_ROUNDS).contains(&options.max_rounds) {
        return Err(format!(
            "routing convergence rounds must be between 1 and {MAX_ROUTING_CONVERGENCE_ROUNDS}"
        ));
    }
    if !(1..=MAX_ROUTING_CONVERGENCE_CANDIDATES_PER_ROUND).contains(&options.candidates_per_round) {
        return Err(format!(
            "routing convergence candidates per round must be between 1 and {MAX_ROUTING_CONVERGENCE_CANDIDATES_PER_ROUND}"
        ));
    }
    if !(1..=8).contains(&options.candidate_workers) {
        return Err("routing convergence candidate workers must be between 1 and 8".into());
    }
    if !(1..=8).contains(&options.router_workers) {
        return Err("routing convergence router workers must be between 1 and 8".into());
    }
    if options
        .candidate_workers
        .saturating_mul(options.router_workers)
        > 16
    {
        return Err("routing convergence may use at most 16 routing threads".into());
    }
    if options.maximum_work_units > MAX_ASTAR_WORK_BUDGET {
        return Err(format!(
            "routing convergence work budget must be at most {MAX_ASTAR_WORK_BUDGET} units"
        ));
    }
    let slots = options
        .max_rounds
        .checked_mul(options.candidates_per_round)
        .ok_or_else(|| "routing convergence candidate allocation overflow".to_string())?;
    if options.maximum_work_units < slots {
        return Err(format!(
            "routing convergence work budget must provide at least one unit for each of {slots} candidate slots"
        ));
    }
    Ok(())
}

fn generate_round(
    board: &Board,
    options: &RoutingConvergenceOptions,
    round_index: usize,
    total_slots: usize,
    allocated_work_units: &mut usize,
) -> Vec<GeneratedCandidate> {
    type Routed = Result<(Board, RouteReport), String>;
    type Generated = (usize, RoutingCandidateObjective, u32, u32, usize, Routed);

    let next = AtomicUsize::new(0);
    let worker_count = options.candidate_workers.min(options.candidates_per_round);
    let (sender, receiver) = mpsc::channel::<Generated>();
    thread::scope(|scope| {
        for _ in 0..worker_count {
            let sender = sender.clone();
            let next = &next;
            scope.spawn(move || {
                loop {
                    let candidate_index = next.fetch_add(1, AtomicOrdering::Relaxed);
                    if candidate_index >= options.candidates_per_round {
                        break;
                    }
                    let global_index = round_index * options.candidates_per_round + candidate_index;
                    let objective = objective(global_index);
                    let (bend_cost, via_cost) = objective_costs(board, objective);
                    let budget =
                        allocated_budget(options.maximum_work_units, total_slots, global_index);
                    let mut input = board.clone();
                    input.rules.bend_cost = bend_cost;
                    input.rules.via_cost = via_cost;
                    let result = route_board_with_variant_and_work_budget(
                        &input,
                        options.router_workers,
                        global_index as u8,
                        budget,
                    );
                    if sender
                        .send((
                            candidate_index,
                            objective,
                            bend_cost,
                            via_cost,
                            budget,
                            result,
                        ))
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    drop(sender);

    let mut routed = receiver.into_iter().collect::<Vec<_>>();
    routed.sort_by_key(|candidate| candidate.0);
    let mut generated = Vec::<GeneratedCandidate>::with_capacity(routed.len());
    for (candidate_index, objective, bend_cost, via_cost, budget, result) in routed {
        *allocated_work_units = allocated_work_units.saturating_add(budget);
        let id = format!(
            "round-{:03}-candidate-{:03}",
            round_index + 1,
            candidate_index + 1
        );
        match result {
            Ok((mut candidate_board, route_report)) => {
                candidate_board.rules = board.rules.clone();
                let check = check_board(&candidate_board);
                let quality = routing_quality(&candidate_board);
                let duplicate_of = generated
                    .iter()
                    .find(|candidate| {
                        candidate
                            .board
                            .as_ref()
                            .is_some_and(|existing| existing.routes == candidate_board.routes)
                    })
                    .map(|candidate| candidate.record.id.clone());
                let drc_violation_count = blocking_violation_count(&check);
                let status = if drc_violation_count == 0 {
                    RoutingConvergenceCandidateStatus::Admissible
                } else {
                    RoutingConvergenceCandidateStatus::RejectedDrcViolations
                };
                let selection_reason =
                    if status == RoutingConvergenceCandidateStatus::RejectedDrcViolations {
                        RoutingConvergenceSelectionReason::DrcViolations
                    } else if duplicate_of.is_some() {
                        RoutingConvergenceSelectionReason::Duplicate
                    } else {
                        RoutingConvergenceSelectionReason::LowerRanked
                    };
                generated.push(GeneratedCandidate {
                    record: RoutingConvergenceCandidate {
                        id,
                        objective,
                        search_variant: (round_index * options.candidates_per_round
                            + candidate_index) as u8,
                        bend_cost,
                        via_cost,
                        allocated_work_units: budget,
                        status,
                        metrics: Some(RoutingConvergenceMetrics::from(&quality)),
                        drc_violation_count: Some(drc_violation_count),
                        expanded_states: Some(route_report.expanded_states),
                        selection_cost: Some(selection_cost(board, &quality)),
                        duplicate_of,
                        selected_as_round_best: false,
                        accepted_for_next_round: false,
                        selection_reason,
                    },
                    board: Some(candidate_board),
                    route_report: Some(route_report),
                });
            }
            Err(_) => generated.push(GeneratedCandidate {
                record: RoutingConvergenceCandidate {
                    id,
                    objective,
                    search_variant: (round_index * options.candidates_per_round + candidate_index)
                        as u8,
                    bend_cost,
                    via_cost,
                    allocated_work_units: budget,
                    status: RoutingConvergenceCandidateStatus::RoutingFailed,
                    metrics: None,
                    drc_violation_count: None,
                    expanded_states: None,
                    selection_cost: None,
                    duplicate_of: None,
                    selected_as_round_best: false,
                    accepted_for_next_round: false,
                    selection_reason: RoutingConvergenceSelectionReason::RoutingFailed,
                },
                board: None,
                route_report: None,
            }),
        }
    }
    generated
}

fn allocated_budget(maximum: usize, slots: usize, index: usize) -> usize {
    maximum / slots + usize::from(index < maximum % slots)
}

fn blocking_violation_count(report: &crate::checking::CheckReport) -> usize {
    report
        .violations
        .iter()
        .filter(|violation| violation.rule != "unrouted")
        .count()
}

fn board_identity(board: &Board) -> Result<RoutingConvergenceArtifactIdentity, String> {
    let rendered = serde_json::to_vec(board)
        .map_err(|error| format!("rendering routing convergence board identity: {error}"))?;
    Ok(RoutingConvergenceArtifactIdentity {
        bytes: rendered.len(),
        sha256: hex::encode(Sha256::digest(&rendered)),
    })
}

fn select_round_winner(candidates: &[RoutingConvergenceCandidate]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.status == RoutingConvergenceCandidateStatus::Admissible)
        .min_by(|(_, left), (_, right)| compare_candidates(left, right))
        .map(|(index, _)| index)
}

fn compare_candidates(
    left: &RoutingConvergenceCandidate,
    right: &RoutingConvergenceCandidate,
) -> Ordering {
    candidate_score(left)
        .expect("an admissible routing candidate has a score")
        .cmp(&candidate_score(right).expect("an admissible routing candidate has a score"))
        .then_with(|| left.id.cmp(&right.id))
}

fn candidate_score(
    candidate: &RoutingConvergenceCandidate,
) -> Option<(usize, u64, i64, usize, usize)> {
    let metrics = candidate.metrics.as_ref()?;
    Some((
        metrics.unrouted_nets,
        candidate.selection_cost?,
        metrics.total_length_nm,
        metrics.total_vias,
        metrics.total_bends,
    ))
}

fn quality_score(board: &Board, quality: &RoutingQuality) -> (usize, u64, i64, usize, usize) {
    (
        quality.unrouted_nets,
        selection_cost(board, quality),
        quality.total_length_nm,
        quality.total_vias,
        quality.total_bends,
    )
}

pub fn render_routing_convergence_report(
    report: &RoutingConvergenceReport,
) -> Result<String, String> {
    let rendered = serde_json::to_string_pretty(report)
        .map(|rendered| format!("{rendered}\n"))
        .map_err(|error| format!("rendering routing convergence report: {error}"))?;
    if rendered.len() as u64 > MAX_ROUTING_CONVERGENCE_REPORT_BYTES {
        return Err(format!(
            "routing convergence report exceeds {MAX_ROUTING_CONVERGENCE_REPORT_BYTES} bytes"
        ));
    }
    Ok(rendered)
}

pub fn routing_convergence_report_json_schema() -> Value {
    let nullable_id = json!({
        "anyOf": [
            {"type": "null"},
            {"type": "string", "pattern": "^round-[0-9]{3}-candidate-[0-9]{3}$"}
        ]
    });
    let nullable_usize = json!({
        "anyOf": [
            {"type": "null"},
            {"type": "integer", "minimum": 0, "maximum": u64::MAX}
        ]
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/routing-convergence-report-v1.json",
        "title": "pcbex bounded deterministic routing convergence report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "scope", "engine_version", "status", "converged", "design_rules_unchanged",
            "options", "input_board_canonical", "final_board_canonical", "input_metrics", "final_metrics", "final_drc_violation_count",
            "selected_candidate_id", "selected_round", "total_candidates_evaluated",
            "allocated_work_units", "termination_reason", "rounds"
        ],
        "properties": {
            "schema_version": {"const": ROUTING_CONVERGENCE_REPORT_SCHEMA_VERSION},
            "scope": {"const": "bounded_deterministic_routing_convergence"},
            "engine_version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$", "maxLength": 32},
            "status": {"enum": ["converged", "partial", "no_admissible_candidate"]},
            "converged": {"type": "boolean"},
            "design_rules_unchanged": {"const": true},
            "options": {"$ref": "#/$defs/options"},
            "input_board_canonical": {"$ref": "#/$defs/artifact_identity"},
            "final_board_canonical": {"$ref": "#/$defs/artifact_identity"},
            "input_metrics": {"$ref": "#/$defs/metrics"},
            "final_metrics": {"$ref": "#/$defs/metrics"},
            "final_drc_violation_count": {"type": "integer", "minimum": 0},
            "selected_candidate_id": nullable_id,
            "selected_round": {
                "anyOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 1, "maximum": MAX_ROUTING_CONVERGENCE_ROUNDS}
                ]
            },
            "total_candidates_evaluated": {"type": "integer", "minimum": 0, "maximum": MAX_ROUTING_CONVERGENCE_ROUNDS * MAX_ROUTING_CONVERGENCE_CANDIDATES_PER_ROUND},
            "allocated_work_units": {"type": "integer", "minimum": 0, "maximum": MAX_ASTAR_WORK_BUDGET},
            "termination_reason": {"$ref": "#/$defs/termination_reason"},
            "rounds": {
                "type": "array", "maxItems": MAX_ROUTING_CONVERGENCE_ROUNDS,
                "items": {"$ref": "#/$defs/round"}
            }
        },
        "$defs": {
            "artifact_identity": {
                "type": "object", "additionalProperties": false,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {"type": "integer", "minimum": 1, "maximum": u64::MAX},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            },
            "options": {
                "type": "object", "additionalProperties": false,
                "required": ["max_rounds", "candidates_per_round", "candidate_workers", "router_workers", "maximum_work_units"],
                "properties": {
                    "max_rounds": {"type": "integer", "minimum": 1, "maximum": MAX_ROUTING_CONVERGENCE_ROUNDS},
                    "candidates_per_round": {"type": "integer", "minimum": 1, "maximum": MAX_ROUTING_CONVERGENCE_CANDIDATES_PER_ROUND},
                    "candidate_workers": {"type": "integer", "minimum": 1, "maximum": 8},
                    "router_workers": {"type": "integer", "minimum": 1, "maximum": 8},
                    "maximum_work_units": {"type": "integer", "minimum": 1, "maximum": MAX_ASTAR_WORK_BUDGET}
                }
            },
            "metrics": {
                "type": "object", "additionalProperties": false,
                "required": ["routed_nets", "unrouted_nets", "total_length_nm", "total_vias", "total_bends"],
                "properties": {
                    "routed_nets": {"type": "integer", "minimum": 0},
                    "unrouted_nets": {"type": "integer", "minimum": 0},
                    "total_length_nm": {"type": "integer", "minimum": 0, "maximum": 9_223_372_036_854_775_807_i64},
                    "total_vias": {"type": "integer", "minimum": 0},
                    "total_bends": {"type": "integer", "minimum": 0}
                }
            },
            "termination_reason": {
                "enum": ["continued", "converged", "stagnated", "no_admissible_candidate", "maximum_rounds"]
            },
            "candidate": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "id", "objective", "search_variant", "bend_cost", "via_cost",
                    "allocated_work_units", "status", "metrics", "drc_violation_count",
                    "expanded_states", "selection_cost", "duplicate_of",
                    "selected_as_round_best", "accepted_for_next_round", "selection_reason"
                ],
                "properties": {
                    "id": {"type": "string", "pattern": "^round-[0-9]{3}-candidate-[0-9]{3}$"},
                    "objective": {"enum": ["balanced", "shortest", "via_minimized", "bend_minimized", "alternate_order"]},
                    "search_variant": {"type": "integer", "minimum": 0, "maximum": 255},
                    "bend_cost": {"type": "integer", "minimum": 0, "maximum": 4_294_967_295_u64},
                    "via_cost": {"type": "integer", "minimum": 0, "maximum": 4_294_967_295_u64},
                    "allocated_work_units": {"type": "integer", "minimum": 1, "maximum": MAX_ASTAR_WORK_BUDGET},
                    "status": {"enum": ["admissible", "rejected_drc_violations", "routing_failed"]},
                    "metrics": {"anyOf": [{"type": "null"}, {"$ref": "#/$defs/metrics"}]},
                    "drc_violation_count": nullable_usize,
                    "expanded_states": nullable_usize,
                    "selection_cost": nullable_usize,
                    "duplicate_of": nullable_id,
                    "selected_as_round_best": {"type": "boolean"},
                    "accepted_for_next_round": {"type": "boolean"},
                    "selection_reason": {"enum": [
                        "accepted_converged", "accepted_improvement", "best_without_improvement",
                        "lower_ranked", "duplicate", "drc_violations", "routing_failed"
                    ]}
                }
            },
            "round": {
                "type": "object", "additionalProperties": false,
                "required": ["round", "input_metrics", "candidates", "selected_candidate_id", "accepted_candidate_id", "termination_reason"],
                "properties": {
                    "round": {"type": "integer", "minimum": 1, "maximum": MAX_ROUTING_CONVERGENCE_ROUNDS},
                    "input_metrics": {"$ref": "#/$defs/metrics"},
                    "candidates": {
                        "type": "array", "minItems": 1, "maxItems": MAX_ROUTING_CONVERGENCE_CANDIDATES_PER_ROUND,
                        "items": {"$ref": "#/$defs/candidate"}
                    },
                    "selected_candidate_id": nullable_id,
                    "accepted_candidate_id": nullable_id,
                    "termination_reason": {"$ref": "#/$defs/termination_reason"}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_board_json;

    fn candidate(
        id: &str,
        status: RoutingConvergenceCandidateStatus,
        unrouted_nets: usize,
        cost: u64,
    ) -> RoutingConvergenceCandidate {
        RoutingConvergenceCandidate {
            id: id.into(),
            objective: RoutingCandidateObjective::Balanced,
            search_variant: 0,
            bend_cost: 5,
            via_cost: 20,
            allocated_work_units: 1,
            status,
            metrics: Some(RoutingConvergenceMetrics {
                routed_nets: 1,
                unrouted_nets,
                total_length_nm: 100,
                total_vias: 0,
                total_bends: 0,
            }),
            drc_violation_count: Some(usize::from(
                status == RoutingConvergenceCandidateStatus::RejectedDrcViolations,
            )),
            expanded_states: Some(1),
            selection_cost: Some(cost),
            duplicate_of: None,
            selected_as_round_best: false,
            accepted_for_next_round: false,
            selection_reason: RoutingConvergenceSelectionReason::LowerRanked,
        }
    }

    #[test]
    fn drc_rejected_candidate_is_never_selected() {
        let candidates = vec![
            candidate(
                "round-001-candidate-001",
                RoutingConvergenceCandidateStatus::RejectedDrcViolations,
                0,
                0,
            ),
            candidate(
                "round-001-candidate-002",
                RoutingConvergenceCandidateStatus::Admissible,
                1,
                100,
            ),
        ];
        assert_eq!(select_round_winner(&candidates), Some(1));
    }

    #[test]
    fn budget_allocation_is_exact_and_bounded() {
        let allocations = (0..15)
            .map(|index| allocated_budget(2_000_000, 15, index))
            .collect::<Vec<_>>();
        assert_eq!(allocations.iter().sum::<usize>(), 2_000_000);
        assert_eq!(allocations[0], 133_334);
        assert_eq!(allocations[14], 133_333);
    }

    #[test]
    fn convergence_is_deterministic_and_preserves_rules() {
        let board = parse_board_json(include_str!("../../../examples/simple.json")).unwrap();
        let options = RoutingConvergenceOptions {
            max_rounds: 2,
            candidates_per_round: 3,
            candidate_workers: 3,
            router_workers: 1,
            maximum_work_units: MAX_ASTAR_WORK_BUDGET,
        };
        let first = route_board_with_convergence(&board, &options).unwrap();
        let second = route_board_with_convergence(&board, &options).unwrap();
        assert_eq!(first.board.rules, board.rules);
        assert_eq!(first.board.routes, second.board.routes);
        assert_eq!(
            render_routing_convergence_report(&first.report).unwrap(),
            render_routing_convergence_report(&second.report).unwrap()
        );
        assert!(first.report.allocated_work_units <= options.maximum_work_units);
        assert_eq!(blocking_violation_count(&check_board(&first.board)), 0);
        assert!(
            first
                .report
                .rounds
                .iter()
                .flat_map(|round| &round.candidates)
                .filter(|candidate| candidate.selected_as_round_best)
                .all(|candidate| {
                    candidate.status == RoutingConvergenceCandidateStatus::Admissible
                })
        );
    }

    #[test]
    fn fresh_verifier_reproduces_retained_producer_version_and_rejects_tampering() {
        let board = parse_board_json(include_str!("../../../examples/simple.json")).unwrap();
        let options = RoutingConvergenceOptions {
            max_rounds: 1,
            candidates_per_round: 2,
            candidate_workers: 2,
            router_workers: 1,
            maximum_work_units: MAX_ASTAR_WORK_BUDGET,
        };
        let retained = route_board_with_convergence_for_engine(&board, &options, "1.474.0")
            .unwrap()
            .report;
        let verified = verify_routing_convergence_report(&board, &retained).unwrap();
        assert_eq!(verified.report, retained);

        let mut tampered = retained.clone();
        tampered.final_metrics.total_length_nm += 1;
        assert!(verify_routing_convergence_report(&board, &tampered).is_err());

        let mut malformed = retained;
        malformed.engine_version = "v1".into();
        assert!(verify_routing_convergence_report(&board, &malformed).is_err());
    }

    #[test]
    fn fresh_verifier_retains_exact_partial_outcome() {
        let board = parse_board_json(include_str!("../../../examples/simple.json")).unwrap();
        let options = RoutingConvergenceOptions {
            max_rounds: 1,
            candidates_per_round: 1,
            candidate_workers: 1,
            router_workers: 1,
            maximum_work_units: 1,
        };
        let retained = route_board_with_convergence(&board, &options)
            .unwrap()
            .report;
        assert!(!retained.converged);
        let verified = verify_routing_convergence_report(&board, &retained).unwrap();
        assert_eq!(verified.report, retained);
        assert_eq!(
            board_identity(&verified.board).unwrap(),
            board_identity(&board).unwrap()
        );
    }

    #[test]
    fn options_reject_unbounded_budget_and_threads() {
        let board = parse_board_json(include_str!("../../../examples/simple.json")).unwrap();
        let options = RoutingConvergenceOptions {
            maximum_work_units: MAX_ASTAR_WORK_BUDGET + 1,
            ..RoutingConvergenceOptions::default()
        };
        assert!(route_board_with_convergence(&board, &options).is_err());
        let options = RoutingConvergenceOptions {
            candidate_workers: 8,
            router_workers: 8,
            ..RoutingConvergenceOptions::default()
        };
        assert!(route_board_with_convergence(&board, &options).is_err());
    }

    #[test]
    fn already_routed_input_converges_without_candidate_work() {
        let board = parse_board_json(include_str!("../../../examples/simple.json")).unwrap();
        let routed = crate::route_board_with_workers(&board, 1).unwrap().0;
        let result =
            route_board_with_convergence(&routed, &RoutingConvergenceOptions::default()).unwrap();
        assert_eq!(result.board.routes, routed.routes);
        assert!(result.report.converged);
        assert!(result.report.rounds.is_empty());
        assert_eq!(result.report.total_candidates_evaluated, 0);
        assert_eq!(result.report.allocated_work_units, 0);
        assert_eq!(
            result.report.termination_reason,
            RoutingConvergenceTerminationReason::Converged
        );
    }

    #[test]
    fn non_unrouted_input_violation_fails_before_candidate_work() {
        let mut board = parse_board_json(include_str!("../../../examples/simple.json")).unwrap();
        board.rules.track_width_nm = 0;
        let error = route_board_with_convergence(&board, &RoutingConvergenceOptions::default())
            .unwrap_err();
        assert!(error.contains("DRC-clean input board"));
    }

    #[test]
    fn schema_is_recursively_closed_and_arrays_are_bounded() {
        fn audit(value: &Value) {
            if value.get("type") == Some(&Value::String("object".into())) {
                assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
            }
            if value.get("type") == Some(&Value::String("array".into())) {
                assert!(value.get("maxItems").is_some());
            }
            match value {
                Value::Array(values) => values.iter().for_each(audit),
                Value::Object(values) => values.values().for_each(audit),
                _ => {}
            }
        }
        let schema = routing_convergence_report_json_schema();
        audit(&schema);
        assert_eq!(schema["additionalProperties"], false);
    }
}

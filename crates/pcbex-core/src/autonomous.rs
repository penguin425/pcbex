//! Deterministic multi-strategy routing convergence.
//!
//! This is deliberately a policy layer around the existing router.  It never
//! accepts a candidate solely because the router returned it: every candidate
//! is scored with the internal checker, and the best checked candidate is kept
//! in a reproducible order.  When progress stalls, the next round changes a
//! routing strategy (via/layer transitions or spacing) before trying again.

use crate::{
    Board, RoutingCandidateOptions, RoutingQuality, ViaStrategy, checking::CheckReport,
    route_candidates, routing_quality,
};
use serde::{Deserialize, Serialize};

pub const AUTONOMOUS_ROUTING_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousRoutingOptions {
    #[serde(default = "default_rounds")]
    pub max_rounds: usize,
    #[serde(default = "default_candidates")]
    pub candidates: usize,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default = "default_router_workers")]
    pub router_workers: usize,
    #[serde(default = "default_spacing_step")]
    pub spacing_step_nm: i64,
    #[serde(default = "default_max_copper_layers")]
    pub max_copper_layers: usize,
}

impl Default for AutonomousRoutingOptions {
    fn default() -> Self {
        Self {
            max_rounds: default_rounds(),
            candidates: default_candidates(),
            workers: default_workers(),
            router_workers: default_router_workers(),
            spacing_step_nm: default_spacing_step(),
            max_copper_layers: default_max_copper_layers(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousRoutingRound {
    pub round: usize,
    pub strategy: String,
    pub via_strategy: ViaStrategy,
    pub clearance_nm: i64,
    pub quality: Option<RoutingQuality>,
    pub violations: Option<usize>,
    pub error: Option<String>,
    pub improved: bool,
    pub stalled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousRoutingResult {
    pub schema_version: u32,
    pub board: Board,
    pub rounds: Vec<AutonomousRoutingRound>,
    pub selected_round: usize,
    pub converged: bool,
    pub stalled: bool,
}

/// Run bounded deterministic routing rounds and return the best checked board.
pub fn autonomous_route(
    board: &Board,
    options: &AutonomousRoutingOptions,
) -> Result<AutonomousRoutingResult, String> {
    validate_options(options)?;
    let mut best_board = board.clone();
    let initial_quality = routing_quality(&best_board);
    let initial_check = crate::checking::check_board(&best_board);
    let mut best_score = score(&initial_quality, &initial_check);
    let mut selected_round = 0;
    let mut rounds = Vec::with_capacity(options.max_rounds);
    let mut previous_score = None;
    let mut stalled_rounds = 0;
    let mut converged = false;

    for round in 0..options.max_rounds {
        let (input, strategy) = strategy_board(
            board,
            round,
            options.spacing_step_nm,
            options.max_copper_layers,
        );
        let route_options = RoutingCandidateOptions {
            candidates: options.candidates,
            workers: options.workers,
            router_workers: options.router_workers,
        };
        let result = route_candidates(&input, &route_options);
        let (candidate_board, quality, check, error) = match result {
            Ok(candidates) => {
                let Some(candidate) = candidates.candidates.iter().min_by(|left, right| {
                    score(&left.quality, &crate::checking::check_board(&left.board))
                        .cmp(&score(
                            &right.quality,
                            &crate::checking::check_board(&right.board),
                        ))
                        .then_with(|| left.id.cmp(&right.id))
                }) else {
                    return Err("autonomous routing produced no candidates".into());
                };
                let check = crate::checking::check_board(&candidate.board);
                (
                    Some(candidate.board.clone()),
                    Some(candidate.quality.clone()),
                    Some(check),
                    None,
                )
            }
            Err(error) => (None, None, None, Some(error)),
        };
        let candidate_score = quality
            .as_ref()
            .zip(check.as_ref())
            .map(|(quality, check)| score(quality, check));
        let improved = candidate_score.is_some_and(|candidate_score| candidate_score < best_score);
        if improved {
            best_score = candidate_score.expect("candidate score exists when improved");
            best_board = candidate_board
                .clone()
                .expect("candidate board exists when improved");
            selected_round = round;
        }
        let stalled = candidate_score.is_some_and(|candidate_score| {
            previous_score.is_some_and(|previous| previous == candidate_score)
        });
        if stalled {
            stalled_rounds += 1;
        } else {
            stalled_rounds = 0;
        }
        previous_score = candidate_score;
        let round_quality = quality.clone();
        converged = quality
            .as_ref()
            .zip(check.as_ref())
            .is_some_and(|(quality, check)| quality.unrouted_nets == 0 && check.is_clean());
        rounds.push(AutonomousRoutingRound {
            round,
            strategy,
            via_strategy: input.via_strategy,
            clearance_nm: input.rules.clearance_nm,
            quality: round_quality,
            violations: check.as_ref().map(|check| check.violations.len()),
            error,
            improved,
            stalled,
        });
        if converged {
            break;
        }
    }

    Ok(AutonomousRoutingResult {
        schema_version: AUTONOMOUS_ROUTING_SCHEMA_VERSION,
        board: best_board,
        rounds,
        selected_round,
        converged,
        stalled: stalled_rounds >= 2,
    })
}

fn strategy_board(
    board: &Board,
    round: usize,
    spacing_step_nm: i64,
    max_copper_layers: usize,
) -> (Board, String) {
    let mut input = board.clone();
    let mut expanded_layers = false;
    if round % 2 == 1 {
        input.via_strategy = ViaStrategy::Auto;
        if input.copper_layers.len() < max_copper_layers {
            let desired = max_copper_layers.min(input.copper_layers.len().saturating_add(2));
            let inner_count = desired.saturating_sub(2);
            input.copper_layers = std::iter::once(crate::Layer::Front)
                .chain((1..=inner_count as u8).map(crate::Layer::Inner))
                .chain(std::iter::once(crate::Layer::Back))
                .collect();
            expanded_layers = true;
        }
    } else {
        input.via_strategy = board.via_strategy;
    }
    let spacing_round = (round / 2) as i64;
    let spacing = spacing_step_nm.saturating_mul(spacing_round);
    input.rules.clearance_nm = board.rules.clearance_nm.saturating_add(spacing);
    for rules in input.net_classes.values_mut() {
        rules.clearance_nm = rules.clearance_nm.saturating_add(spacing);
    }
    let strategy = match (round % 2, spacing_round > 0, expanded_layers) {
        (1, true, true) => "expanded-layers+auto-transitions+tightened-spacing",
        (1, false, true) => "expanded-layers+auto-transitions",
        (1, true, false) => "auto-layer-transitions+tightened-spacing",
        (1, false, false) => "auto-layer-transitions",
        (0, true, _) => "through-layer-transitions+tightened-spacing",
        _ => "baseline",
    };
    (input, strategy.to_string())
}

fn score(quality: &RoutingQuality, check: &CheckReport) -> (usize, usize, i64, usize, usize) {
    (
        quality.unrouted_nets,
        check.violations.len(),
        quality.total_length_nm,
        quality.total_vias,
        quality.total_bends,
    )
}

fn validate_options(options: &AutonomousRoutingOptions) -> Result<(), String> {
    if !(1..=8).contains(&options.max_rounds) {
        return Err("autonomous routing max_rounds must be between 1 and 8".into());
    }
    if !(1..=32).contains(&options.candidates) {
        return Err("autonomous routing candidates must be between 1 and 32".into());
    }
    if !(1..=8).contains(&options.workers) {
        return Err("autonomous routing workers must be between 1 and 8".into());
    }
    if !(1..=8).contains(&options.router_workers) {
        return Err("autonomous routing router_workers must be between 1 and 8".into());
    }
    if options.workers.saturating_mul(options.router_workers) > 16 {
        return Err("autonomous routing workers may use at most 16 threads".into());
    }
    if options.spacing_step_nm < 0 {
        return Err("autonomous routing spacing_step_nm must not be negative".into());
    }
    if !(2..=32).contains(&options.max_copper_layers) {
        return Err("autonomous routing max_copper_layers must be between 2 and 32".into());
    }
    Ok(())
}

fn default_rounds() -> usize {
    4
}
fn default_candidates() -> usize {
    3
}
fn default_workers() -> usize {
    2
}
fn default_router_workers() -> usize {
    2
}
fn default_spacing_step() -> i64 {
    50_000
}

fn default_max_copper_layers() -> usize {
    4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CURRENT_SCHEMA_VERSION, Layer, Net, Point, Rules, Terminal};

    fn board() -> Board {
        Board {
            schema_version: CURRENT_SCHEMA_VERSION,
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            outline: vec![],
            cutouts: vec![],
            copper_layers: vec![Layer::Front, Layer::Inner(1), Layer::Back],
            rules: Rules {
                grid_nm: 500_000,
                track_width_nm: 200_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                bend_cost: 5,
                via_cost: 20,
            },
            obstacles: vec![],
            round_obstacles: vec![],
            capsule_obstacles: vec![],
            polygon_obstacles: vec![],
            keepouts: vec![],
            footprints: vec![],
            net_classes: Default::default(),
            differential_pairs: vec![],
            length_groups: vec![],
            escape_groups: vec![],
            manufacturing_rules: None,
            return_path_rules: vec![],
            power_net_rules: vec![],
            stackup: vec![],
            via_strategy: ViaStrategy::ThroughOnly,
            nets: vec![Net {
                id: 1,
                name: "SIG".into(),
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 1_000_000,
                            y_nm: 1_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: Point {
                            x_nm: 8_000_000,
                            y_nm: 8_000_000,
                        },
                        layers: vec![Layer::Back],
                    },
                ],
                class: None,
                priority: 0,
            }],
            routes: vec![],
        }
    }

    #[test]
    fn converges_and_records_strategy_rounds() {
        let result = autonomous_route(
            &board(),
            &AutonomousRoutingOptions {
                max_rounds: 4,
                candidates: 1,
                workers: 1,
                router_workers: 1,
                spacing_step_nm: 50_000,
                max_copper_layers: 4,
            },
        )
        .unwrap();
        assert!(result.converged);
        assert!(!result.rounds.is_empty());
        assert_eq!(result.board.routes.len(), 1);
    }

    #[test]
    fn expands_a_two_layer_board_when_strategy_stalls() {
        let mut input = board();
        input.copper_layers = vec![Layer::Front, Layer::Back];
        let (expanded, strategy) = strategy_board(&input, 1, 50_000, 4);
        assert_eq!(expanded.copper_layers.len(), 4);
        assert!(strategy.starts_with("expanded-layers"));
    }
}

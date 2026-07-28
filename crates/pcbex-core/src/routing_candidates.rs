use crate::{Board, RouteReport, RoutingQuality, route_board_with_variant, routing_quality};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingCandidateObjective {
    Balanced,
    Shortest,
    ViaMinimized,
    BendMinimized,
    AlternateOrder,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingCandidateOptions {
    #[serde(default = "candidate_count")]
    pub candidates: usize,
    #[serde(default = "candidate_workers")]
    pub workers: usize,
    #[serde(default = "router_workers")]
    pub router_workers: usize,
}

impl Default for RoutingCandidateOptions {
    fn default() -> Self {
        Self {
            candidates: candidate_count(),
            workers: candidate_workers(),
            router_workers: router_workers(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingCandidate {
    pub id: String,
    pub objective: RoutingCandidateObjective,
    pub search_variant: u8,
    pub bend_cost: u32,
    pub via_cost: u32,
    pub board: Board,
    pub report: RouteReport,
    pub quality: RoutingQuality,
    pub selection_cost: u64,
    pub duplicate_of: Option<String>,
    pub pareto_optimal: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingCandidateSet {
    pub schema_version: u32,
    pub options: RoutingCandidateOptions,
    pub candidates: Vec<RoutingCandidate>,
    pub pareto_front: Vec<String>,
    pub selected_candidate_id: String,
}

impl RoutingCandidateSet {
    pub fn selected(&self) -> &RoutingCandidate {
        self.candidates
            .iter()
            .find(|candidate| candidate.id == self.selected_candidate_id)
            .expect("selected routing candidate is present")
    }
}

pub fn route_candidates(
    board: &Board,
    options: &RoutingCandidateOptions,
) -> Result<RoutingCandidateSet, String> {
    if !(1..=32).contains(&options.candidates) {
        return Err("routing candidate count must be between 1 and 32".into());
    }
    if !(1..=8).contains(&options.workers) {
        return Err("routing candidate workers must be between 1 and 8".into());
    }
    if !(1..=8).contains(&options.router_workers) {
        return Err("per-candidate router workers must be between 1 and 8".into());
    }
    if options.workers.saturating_mul(options.router_workers) > 16 {
        return Err("routing candidate and router workers may use at most 16 threads".into());
    }

    let next = AtomicUsize::new(0);
    let worker_count = options.workers.min(options.candidates);
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..worker_count {
            let sender = sender.clone();
            let next = &next;
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= options.candidates {
                        break;
                    }
                    let objective = objective(index);
                    let (bend_cost, via_cost) = objective_costs(board, objective);
                    let mut input = board.clone();
                    input.rules.bend_cost = bend_cost;
                    input.rules.via_cost = via_cost;
                    let result =
                        route_board_with_variant(&input, options.router_workers, index as u8);
                    if sender
                        .send((index, objective, bend_cost, via_cost, result))
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    drop(sender);

    let mut generated = receiver.into_iter().collect::<Vec<_>>();
    generated.sort_by_key(|candidate| candidate.0);
    let mut candidates = Vec::with_capacity(generated.len());
    for (index, objective, bend_cost, via_cost, result) in generated {
        let (mut routed, report) = result?;
        routed.rules = board.rules.clone();
        let quality = routing_quality(&routed);
        let duplicate_of = candidates
            .iter()
            .find(|candidate: &&RoutingCandidate| candidate.board.routes == routed.routes)
            .map(|candidate| candidate.id.clone());
        candidates.push(RoutingCandidate {
            id: format!("candidate-{:03}", index + 1),
            objective,
            search_variant: index as u8,
            bend_cost,
            via_cost,
            selection_cost: selection_cost(board, &quality),
            board: routed,
            report,
            quality,
            duplicate_of,
            pareto_optimal: false,
        });
    }

    let front = pareto_indices(&candidates);
    for &index in &front {
        candidates[index].pareto_optimal = true;
    }
    let selected_index = front
        .iter()
        .copied()
        .min_by(|left, right| {
            candidates[*left]
                .quality
                .unrouted_nets
                .cmp(&candidates[*right].quality.unrouted_nets)
                .then_with(|| {
                    candidates[*left]
                        .selection_cost
                        .cmp(&candidates[*right].selection_cost)
                })
                .then_with(|| candidates[*left].id.cmp(&candidates[*right].id))
        })
        .expect("at least one unique routing candidate");
    Ok(RoutingCandidateSet {
        schema_version: 1,
        options: options.clone(),
        pareto_front: front
            .iter()
            .map(|index| candidates[*index].id.clone())
            .collect(),
        selected_candidate_id: candidates[selected_index].id.clone(),
        candidates,
    })
}

fn candidate_count() -> usize {
    5
}

fn candidate_workers() -> usize {
    4
}

fn router_workers() -> usize {
    2
}

fn objective(index: usize) -> RoutingCandidateObjective {
    match index % 5 {
        0 => RoutingCandidateObjective::Balanced,
        1 => RoutingCandidateObjective::Shortest,
        2 => RoutingCandidateObjective::ViaMinimized,
        3 => RoutingCandidateObjective::BendMinimized,
        _ => RoutingCandidateObjective::AlternateOrder,
    }
}

fn objective_costs(board: &Board, objective: RoutingCandidateObjective) -> (u32, u32) {
    let bend = board.rules.bend_cost;
    let via = board.rules.via_cost;
    match objective {
        RoutingCandidateObjective::Balanced | RoutingCandidateObjective::AlternateOrder => {
            (bend, via)
        }
        RoutingCandidateObjective::Shortest => (0, (via / 4).max(1)),
        RoutingCandidateObjective::ViaMinimized => (bend, via.saturating_mul(8).max(100)),
        RoutingCandidateObjective::BendMinimized => (bend.saturating_mul(8).max(50), via),
    }
}

fn selection_cost(board: &Board, quality: &RoutingQuality) -> u64 {
    let grid = board.rules.grid_nm.max(1) as u64;
    let length = quality.total_length_nm.max(0) as u64 / grid;
    length
        .saturating_mul(10)
        .saturating_add((quality.total_vias as u64).saturating_mul(board.rules.via_cost.into()))
        .saturating_add((quality.total_bends as u64).saturating_mul(board.rules.bend_cost.into()))
}

fn pareto_indices(candidates: &[RoutingCandidate]) -> Vec<usize> {
    (0..candidates.len())
        .filter(|&candidate| {
            candidates[candidate].duplicate_of.is_none()
                && !(0..candidates.len()).any(|other| {
                    other != candidate
                        && candidates[other].duplicate_of.is_none()
                        && dominates(&candidates[other].quality, &candidates[candidate].quality)
                })
        })
        .collect()
}

fn dominates(left: &RoutingQuality, right: &RoutingQuality) -> bool {
    let left = [
        left.unrouted_nets as u128,
        left.total_length_nm.max(0) as u128,
        left.total_vias as u128,
        left.total_bends as u128,
    ];
    let right = [
        right.unrouted_nets as u128,
        right.total_length_nm.max(0) as u128,
        right.total_vias as u128,
        right.total_bends as u128,
    ];
    left.iter().zip(&right).all(|(left, right)| left <= right)
        && left.iter().zip(&right).any(|(left, right)| left < right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_board_json;

    #[test]
    fn parallel_candidate_generation_is_deterministic() {
        let board = parse_board_json(include_str!("../../../examples/simple.json")).unwrap();
        let mut options = RoutingCandidateOptions {
            candidates: 7,
            workers: 1,
            router_workers: 1,
        };
        let sequential = route_candidates(&board, &options).unwrap();
        options.workers = 4;
        let parallel = route_candidates(&board, &options).unwrap();
        assert_eq!(
            serde_json::to_value(&sequential.candidates).unwrap(),
            serde_json::to_value(&parallel.candidates).unwrap()
        );
        assert_eq!(sequential.pareto_front, parallel.pareto_front);
        assert_eq!(
            sequential.selected_candidate_id,
            parallel.selected_candidate_id
        );
        assert_eq!(parallel.candidates.len(), 7);
        assert!(
            parallel
                .candidates
                .iter()
                .any(|candidate| candidate.duplicate_of.is_some())
        );
        assert!(
            parallel
                .candidates
                .iter()
                .filter(|candidate| candidate.duplicate_of.is_some())
                .all(|candidate| !candidate.pareto_optimal)
        );
        assert!(parallel.selected().pareto_optimal);
    }

    #[test]
    fn pareto_dominance_requires_no_worse_and_one_better_metric() {
        fn quality(
            length: crate::Nm,
            vias: usize,
            bends: usize,
            unrouted: usize,
        ) -> RoutingQuality {
            RoutingQuality {
                total_length_nm: length,
                total_vias: vias,
                total_bends: bends,
                routed_nets: 0,
                unrouted_nets: unrouted,
                nets: vec![],
                differential_pairs: vec![],
            }
        }

        let baseline = quality(100, 2, 3, 0);
        assert!(dominates(&quality(90, 2, 3, 0), &baseline));
        assert!(!dominates(&quality(90, 3, 3, 0), &baseline));
        assert!(!dominates(&baseline, &baseline));
        assert!(!dominates(&quality(90, 1, 1, 1), &baseline));
    }

    #[test]
    fn rejects_unbounded_thread_combinations() {
        let board = parse_board_json(include_str!("../../../examples/simple.json")).unwrap();
        let error = route_candidates(
            &board,
            &RoutingCandidateOptions {
                candidates: 8,
                workers: 8,
                router_workers: 8,
            },
        )
        .unwrap_err();
        assert!(error.contains("at most 16 threads"));
    }
}

use crate::{Nm, Point, geometry};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementProblem {
    pub width_nm: Nm,
    pub height_nm: Nm,
    pub grid_nm: Nm,
    pub components: Vec<Component>,
    #[serde(default)]
    pub connections: Vec<Connection>,
    #[serde(default)]
    pub constraints: Vec<PlacementConstraint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Component {
    pub reference: String,
    pub width_nm: Nm,
    pub height_nm: Nm,
    #[serde(default)]
    pub position: Option<Point>,
    #[serde(default)]
    pub rotation_deg: u16,
    #[serde(default)]
    pub fixed: bool,
    #[serde(default)]
    pub side: BoardSide,
    #[serde(default)]
    pub allowed_rotations: Vec<u16>,
    #[serde(default)]
    pub allow_side_flip: bool,
    /// Local, unrotated courtyard polygon. Empty uses width/height.
    #[serde(default)]
    pub courtyard: Vec<Point>,
    /// Named pin/anchor offsets from the component origin.
    #[serde(default)]
    pub anchors: HashMap<String, Point>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardSide {
    #[default]
    Front,
    Back,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub from: PinRef,
    pub to: PinRef,
    #[serde(default = "one")]
    pub weight: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PinRef {
    pub component: String,
    #[serde(default)]
    pub offset: Point,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlacementConstraint {
    Near {
        subject: String,
        target: String,
        max_distance_nm: Nm,
    },
    Decoupling {
        capacitor_anchor: String,
        power_pin: String,
        max_distance_nm: Nm,
        #[serde(default = "same_side_required")]
        require_same_side: bool,
    },
    BoardEdge {
        subject: String,
        edge: Edge,
        #[serde(default)]
        max_distance_nm: Nm,
    },
    KeepTogether {
        components: Vec<String>,
        max_span_nm: Nm,
    },
    Region {
        subject: String,
        min: Point,
        max: Point,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Edge {
    Left,
    Right,
    Top,
    Bottom,
}

fn same_side_required() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementOptions {
    #[serde(default = "iterations")]
    pub iterations: usize,
    #[serde(default = "initial_temperature")]
    pub initial_temperature: f64,
    #[serde(default = "cooling")]
    pub cooling: f64,
    #[serde(default = "default_seed")]
    pub seed: u64,
    #[serde(default)]
    pub weights: ScoreWeights,
}

impl Default for PlacementOptions {
    fn default() -> Self {
        Self {
            iterations: iterations(),
            initial_temperature: initial_temperature(),
            cooling: cooling(),
            seed: default_seed(),
            weights: ScoreWeights::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreWeights {
    #[serde(default = "one")]
    pub hpwl: f64,
    #[serde(default = "overlap_weight")]
    pub overlap: f64,
    #[serde(default = "boundary_weight")]
    pub boundary: f64,
    #[serde(default = "congestion_weight")]
    pub congestion: f64,
    #[serde(default = "constraint_weight")]
    pub constraint_violation: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            hpwl: one(),
            overlap: overlap_weight(),
            boundary: boundary_weight(),
            congestion: congestion_weight(),
            constraint_violation: constraint_weight(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Score {
    pub total: f64,
    pub hpwl: f64,
    pub overlap: f64,
    pub boundary: f64,
    pub congestion: f64,
    pub constraint_violation: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementResult {
    pub components: Vec<Component>,
    pub initial_score: Score,
    pub final_score: Score,
    pub accepted_moves: usize,
    pub iterations: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateObjective {
    Balanced,
    Wirelength,
    Routability,
    Constraints,
    Legalization,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementCandidateOptions {
    #[serde(default = "candidate_count")]
    pub candidates: usize,
    #[serde(default = "candidate_workers")]
    pub workers: usize,
    #[serde(default)]
    pub placement: PlacementOptions,
}

impl Default for PlacementCandidateOptions {
    fn default() -> Self {
        Self {
            candidates: candidate_count(),
            workers: candidate_workers(),
            placement: PlacementOptions::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementCandidate {
    pub id: String,
    pub objective: CandidateObjective,
    pub seed: u64,
    pub weights: ScoreWeights,
    pub result: PlacementResult,
    /// Score under the caller's base weights, used for deterministic selection.
    pub comparison_score: Score,
    pub pareto_optimal: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementCandidateSet {
    pub schema_version: u32,
    pub options: PlacementCandidateOptions,
    pub candidates: Vec<PlacementCandidate>,
    pub pareto_front: Vec<String>,
    pub selected_candidate_id: String,
}

impl PlacementCandidateSet {
    pub fn selected(&self) -> &PlacementCandidate {
        self.candidates
            .iter()
            .find(|candidate| candidate.id == self.selected_candidate_id)
            .expect("selected placement candidate is present")
    }
}

pub fn place_candidates(
    problem: &PlacementProblem,
    options: &PlacementCandidateOptions,
) -> Result<PlacementCandidateSet, String> {
    if !(1..=32).contains(&options.candidates) {
        return Err("placement candidate count must be between 1 and 32".into());
    }
    if !(1..=8).contains(&options.workers) {
        return Err("placement candidate workers must be between 1 and 8".into());
    }
    validate(problem, &options.placement)?;

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
                    let objective = candidate_objective(index);
                    let mut placement = options.placement.clone();
                    placement.seed = candidate_seed(options.placement.seed, index);
                    placement.weights = objective_weights(&options.placement.weights, objective);
                    let result = place(problem, &placement);
                    if sender
                        .send((index, objective, placement.seed, placement.weights, result))
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
    for (index, objective, seed, weights, result) in generated {
        let result = result?;
        let comparison_score = evaluate(problem, &result.components, &options.placement.weights)?;
        candidates.push(PlacementCandidate {
            id: format!("candidate-{:03}", index + 1),
            objective,
            seed,
            weights,
            result,
            comparison_score,
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
                .comparison_score
                .total
                .total_cmp(&candidates[*right].comparison_score.total)
                .then_with(|| candidates[*left].id.cmp(&candidates[*right].id))
        })
        .expect("at least one placement candidate");
    Ok(PlacementCandidateSet {
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

pub fn place(
    problem: &PlacementProblem,
    options: &PlacementOptions,
) -> Result<PlacementResult, String> {
    validate(problem, options)?;
    let index: HashMap<_, _> = problem
        .components
        .iter()
        .enumerate()
        .map(|(i, c)| (c.reference.as_str(), i))
        .collect();
    validate_references(problem, &index)?;
    let mut current = initial_placement(problem, &index);
    let initial_score = score(problem, &current, &index, &options.weights);
    let mut current_score = initial_score.clone();
    let mut best = current.clone();
    let mut best_score = current_score.clone();
    let movable: Vec<_> = current
        .iter()
        .enumerate()
        .filter_map(|(i, c)| (!c.fixed).then_some(i))
        .collect();
    if movable.is_empty() {
        return Ok(PlacementResult {
            components: current,
            initial_score: initial_score.clone(),
            final_score: initial_score,
            accepted_moves: 0,
            iterations: 0,
        });
    }
    let mut rng = Rng::new(options.seed);
    let mut accepted = 0;
    let mut temperature = options.initial_temperature;
    for _ in 0..options.iterations {
        let mut candidate = current.clone();
        mutate(
            &mut candidate,
            &movable,
            problem.grid_nm,
            problem.width_nm,
            problem.height_nm,
            &mut rng,
        );
        let candidate_score = score(problem, &candidate, &index, &options.weights);
        let delta = candidate_score.total - current_score.total;
        if delta <= 0.0 || rng.unit() < (-delta / temperature.max(1e-9)).exp() {
            current = candidate;
            current_score = candidate_score;
            accepted += 1;
            if current_score.total < best_score.total {
                best = current.clone();
                best_score = current_score.clone();
            }
        }
        temperature *= options.cooling;
    }
    for c in &mut best {
        if let Some(p) = &mut c.position {
            p.x_nm = snap(p.x_nm, problem.grid_nm);
            p.y_nm = snap(p.y_nm, problem.grid_nm);
        }
    }
    let best_score = score(problem, &best, &index, &options.weights);
    Ok(PlacementResult {
        components: best,
        initial_score,
        final_score: best_score,
        accepted_moves: accepted,
        iterations: options.iterations,
    })
}

fn candidate_count() -> usize {
    5
}

fn candidate_workers() -> usize {
    4
}

fn candidate_objective(index: usize) -> CandidateObjective {
    match index % 5 {
        0 => CandidateObjective::Balanced,
        1 => CandidateObjective::Wirelength,
        2 => CandidateObjective::Routability,
        3 => CandidateObjective::Constraints,
        _ => CandidateObjective::Legalization,
    }
}

fn candidate_seed(base: u64, index: usize) -> u64 {
    base.wrapping_add((index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

fn objective_weights(base: &ScoreWeights, objective: CandidateObjective) -> ScoreWeights {
    let mut weights = base.clone();
    match objective {
        CandidateObjective::Balanced => {}
        CandidateObjective::Wirelength => weights.hpwl *= 3.0,
        CandidateObjective::Routability => weights.congestion *= 4.0,
        CandidateObjective::Constraints => weights.constraint_violation *= 4.0,
        CandidateObjective::Legalization => {
            weights.overlap *= 4.0;
            weights.boundary *= 4.0;
        }
    }
    weights
}

fn pareto_indices(candidates: &[PlacementCandidate]) -> Vec<usize> {
    (0..candidates.len())
        .filter(|&candidate| {
            !(0..candidates.len()).any(|other| {
                other != candidate
                    && dominates(
                        &candidates[other].comparison_score,
                        &candidates[candidate].comparison_score,
                    )
            })
        })
        .collect()
}

fn dominates(left: &Score, right: &Score) -> bool {
    let left = [
        left.hpwl,
        left.overlap,
        left.boundary,
        left.congestion,
        left.constraint_violation,
    ];
    let right = [
        right.hpwl,
        right.overlap,
        right.boundary,
        right.congestion,
        right.constraint_violation,
    ];
    left.iter().zip(&right).all(|(left, right)| left <= right)
        && left.iter().zip(&right).any(|(left, right)| left < right)
}

pub fn evaluate(
    problem: &PlacementProblem,
    components: &[Component],
    weights: &ScoreWeights,
) -> Result<Score, String> {
    let index: HashMap<_, _> = components
        .iter()
        .enumerate()
        .map(|(i, c)| (c.reference.as_str(), i))
        .collect();
    validate_references(problem, &index)?;
    Ok(score(problem, components, &index, weights))
}

fn validate(problem: &PlacementProblem, options: &PlacementOptions) -> Result<(), String> {
    if problem.width_nm <= 0 || problem.height_nm <= 0 || problem.grid_nm <= 0 {
        return Err("board dimensions and placement grid must be positive".into());
    }
    if problem.components.is_empty() {
        return Err("placement requires at least one component".into());
    }
    if problem.components.iter().any(|c| {
        c.width_nm <= 0
            || c.height_nm <= 0
            || c.allowed_rotations
                .iter()
                .any(|rotation| *rotation >= 360 || !rotation.is_multiple_of(90))
    }) {
        return Err("component dimensions or allowed rotations are invalid".into());
    }
    let mut refs: Vec<_> = problem
        .components
        .iter()
        .map(|c| c.reference.as_str())
        .collect();
    refs.sort_unstable();
    if refs.windows(2).any(|x| x[0] == x[1]) {
        return Err("component references must be unique".into());
    }
    if options.iterations > 0
        && (!options.initial_temperature.is_finite()
            || options.initial_temperature <= 0.0
            || !(0.0..=1.0).contains(&options.cooling)
            || options.cooling == 0.0)
    {
        return Err("invalid annealing temperature or cooling rate".into());
    }
    let weights = [
        options.weights.hpwl,
        options.weights.overlap,
        options.weights.boundary,
        options.weights.congestion,
        options.weights.constraint_violation,
    ];
    if weights
        .iter()
        .any(|weight| !weight.is_finite() || *weight < 0.0)
        || weights.iter().all(|weight| *weight == 0.0)
    {
        return Err(
            "placement score weights must be finite, non-negative, and not all zero".into(),
        );
    }
    Ok(())
}

fn validate_references(
    problem: &PlacementProblem,
    index: &HashMap<&str, usize>,
) -> Result<(), String> {
    for connection in &problem.connections {
        for name in [&connection.from.component, &connection.to.component] {
            if !index.contains_key(name.as_str()) {
                return Err(format!("unknown component in connection: {name}"));
            }
        }
    }
    for constraint in &problem.constraints {
        let names: Vec<&str> = match constraint {
            PlacementConstraint::Near {
                subject, target, ..
            } => vec![subject, target],
            PlacementConstraint::Decoupling {
                capacitor_anchor,
                power_pin,
                ..
            } => vec![capacitor_anchor, power_pin],
            PlacementConstraint::BoardEdge { subject, .. } => vec![subject],
            PlacementConstraint::KeepTogether { components, .. } => {
                components.iter().map(String::as_str).collect()
            }
            PlacementConstraint::Region { subject, .. } => vec![subject],
        };
        for name in names {
            if !index.contains_key(component_name(name)) {
                return Err(format!("unknown component in constraint: {name}"));
            }
            if let Some((component, anchor)) = name.split_once('.')
                && !problem.components[index[component]]
                    .anchors
                    .contains_key(anchor)
            {
                return Err(format!("unknown anchor in constraint: {name}"));
            }
        }
    }
    Ok(())
}

fn initial_placement(problem: &PlacementProblem, index: &HashMap<&str, usize>) -> Vec<Component> {
    let mut components = problem.components.clone();
    let mut adjacency = vec![Vec::new(); components.len()];
    for connection in &problem.connections {
        let a = index[connection.from.component.as_str()];
        let b = index[connection.to.component.as_str()];
        adjacency[a].push(b);
        adjacency[b].push(a);
    }
    let mut order: Vec<_> = (0..components.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(adjacency[i].len()));
    let mut queue: VecDeque<_> = order.into();
    let mut placed = vec![false; components.len()];
    let mut cursor = Point {
        x_nm: problem.grid_nm,
        y_nm: problem.grid_nm,
    };
    while let Some(root) = queue.pop_front() {
        if placed[root] {
            continue;
        }
        let mut cluster = VecDeque::from([root]);
        while let Some(i) = cluster.pop_front() {
            if placed[i] {
                continue;
            }
            placed[i] = true;
            if components[i].position.is_none() {
                components[i].position = Some(cursor);
                let step = placement_spacing_step(components[i].width_nm, problem.grid_nm);
                cursor.x_nm = cursor.x_nm.saturating_add(step);
                if cursor.x_nm.saturating_add(step) > problem.width_nm {
                    cursor.x_nm = problem.grid_nm;
                    cursor.y_nm = cursor.y_nm.saturating_add(placement_spacing_step(
                        components[i].height_nm,
                        problem.grid_nm,
                    ));
                }
            }
            let mut neighbors = adjacency[i].clone();
            neighbors.sort_by_key(|&n| std::cmp::Reverse(adjacency[n].len()));
            cluster.extend(neighbors);
        }
    }
    components
}

fn placement_spacing_step(component_extent_nm: Nm, grid_nm: Nm) -> Nm {
    component_extent_nm.saturating_add(grid_nm.saturating_mul(2))
}

fn mutate(
    components: &mut [Component],
    movable: &[usize],
    grid: Nm,
    board_width: Nm,
    board_height: Nm,
    rng: &mut Rng,
) {
    let i = movable[rng.index(movable.len())];
    match rng.next() % 5 {
        0 => {
            let allowed = &components[i].allowed_rotations;
            components[i].rotation_deg = if allowed.is_empty() {
                (components[i].rotation_deg + 90) % 360
            } else {
                let current = allowed
                    .iter()
                    .position(|rotation| *rotation == components[i].rotation_deg)
                    .unwrap_or(0);
                allowed[(current + 1) % allowed.len()] % 360
            };
        }
        1 if movable.len() > 1 => {
            let mut j = movable[rng.index(movable.len())];
            if j == i {
                j = movable[(rng.index(movable.len() - 1) + 1) % movable.len()];
            }
            let a = components[i].position;
            components[i].position = components[j].position;
            components[j].position = a;
        }
        2 if components[i].allow_side_flip => {
            components[i].side = match components[i].side {
                BoardSide::Front => BoardSide::Back,
                BoardSide::Back => BoardSide::Front,
            };
        }
        _ => {
            let radius = 1 + (rng.next() % 8) as i64;
            let dx = (rng.next() % (radius as u64 * 2 + 1)) as i64 - radius;
            let dy = (rng.next() % (radius as u64 * 2 + 1)) as i64 - radius;
            if let Some(p) = &mut components[i].position {
                p.x_nm = bounded_grid_move(p.x_nm, dx, grid, board_width);
                p.y_nm = bounded_grid_move(p.y_nm, dy, grid, board_height);
            }
        }
    }
}

fn bounded_grid_move(position_nm: Nm, grid_steps: Nm, grid_nm: Nm, extent_nm: Nm) -> Nm {
    position_nm
        .saturating_add(grid_steps.saturating_mul(grid_nm))
        .clamp(0, extent_nm)
}

fn manhattan_distance_nm(a: Point, b: Point) -> f64 {
    let dx = (i128::from(a.x_nm) - i128::from(b.x_nm)).abs();
    let dy = (i128::from(a.y_nm) - i128::from(b.y_nm)).abs();
    (dx + dy) as f64
}

fn manhattan_excess_nm(a: Point, b: Point, allowed_nm: Nm) -> f64 {
    let dx = (i128::from(a.x_nm) - i128::from(b.x_nm)).abs();
    let dy = (i128::from(a.y_nm) - i128::from(b.y_nm)).abs();
    (dx + dy - i128::from(allowed_nm)).max(0) as f64
}

fn decoupling_distance_excess_nm(capacitor: Point, power: Point, allowed_nm: Nm) -> f64 {
    manhattan_excess_nm(capacitor, power, allowed_nm)
}

fn board_edge_excess_nm(
    point: Point,
    edge: Edge,
    width_nm: Nm,
    height_nm: Nm,
    allowed_nm: Nm,
) -> f64 {
    let distance = match edge {
        Edge::Left => i128::from(point.x_nm),
        Edge::Right => i128::from(width_nm) - i128::from(point.x_nm),
        Edge::Top => i128::from(point.y_nm),
        Edge::Bottom => i128::from(height_nm) - i128::from(point.y_nm),
    };
    (distance - i128::from(allowed_nm)).max(0) as f64
}

fn point_cloud_span_excess_nm(points: &[Point], allowed_nm: Nm) -> f64 {
    let Some(first) = points.first() else {
        return 0.0;
    };
    let (mut min_x, mut max_x) = (first.x_nm, first.x_nm);
    let (mut min_y, mut max_y) = (first.y_nm, first.y_nm);
    for point in &points[1..] {
        min_x = min_x.min(point.x_nm);
        max_x = max_x.max(point.x_nm);
        min_y = min_y.min(point.y_nm);
        max_y = max_y.max(point.y_nm);
    }
    let x_span = i128::from(max_x) - i128::from(min_x);
    let y_span = i128::from(max_y) - i128::from(min_y);
    (x_span + y_span - i128::from(allowed_nm)).max(0) as f64
}

fn region_overflow_nm(bounds: Rect, min: Point, max: Point) -> f64 {
    let left = (i128::from(min.x_nm) - i128::from(bounds.min_x)).max(0);
    let top = (i128::from(min.y_nm) - i128::from(bounds.min_y)).max(0);
    let right = (i128::from(bounds.max_x) - i128::from(max.x_nm)).max(0);
    let bottom = (i128::from(bounds.max_y) - i128::from(max.y_nm)).max(0);
    (left + top + right + bottom) as f64
}

fn point_boundary_overflow_nm(point: Point, width_nm: Nm, height_nm: Nm) -> f64 {
    let x = i128::from(point.x_nm);
    let y = i128::from(point.y_nm);
    let left = (-x).max(0);
    let top = (-y).max(0);
    let right = (x - i128::from(width_nm)).max(0);
    let bottom = (y - i128::from(height_nm)).max(0);
    (left + top + right + bottom) as f64
}

fn score(
    problem: &PlacementProblem,
    components: &[Component],
    index: &HashMap<&str, usize>,
    weights: &ScoreWeights,
) -> Score {
    let unit = problem.grid_nm as f64;
    let mut out = Score::default();
    for connection in &problem.connections {
        let a = pin_position(
            &components[index[connection.from.component.as_str()]],
            connection.from.offset,
        );
        let b = pin_position(
            &components[index[connection.to.component.as_str()]],
            connection.to.offset,
        );
        out.hpwl += manhattan_distance_nm(a, b) / unit * connection.weight;
    }
    for (i, a) in components.iter().enumerate() {
        let ar = bounds(a);
        let polygon = courtyard_polygon(a);
        out.boundary += polygon
            .iter()
            .map(|point| point_boundary_overflow_nm(*point, problem.width_nm, problem.height_nm))
            .sum::<f64>()
            / unit;
        for b in &components[i + 1..] {
            let bbox_overlap = intersection(ar, bounds(b));
            if a.side == b.side
                && bbox_overlap > 0.0
                && polygons_intersect(&polygon, &courtyard_polygon(b))
            {
                out.overlap += bbox_overlap / (unit * unit);
            }
        }
    }
    out.congestion = congestion(problem, components, index);
    out.constraint_violation = constraint_penalty(problem, components, index, unit);
    out.total = out.hpwl * weights.hpwl
        + out.overlap * weights.overlap
        + out.boundary * weights.boundary
        + out.congestion * weights.congestion
        + out.constraint_violation * weights.constraint_violation;
    out
}

fn congestion(
    problem: &PlacementProblem,
    components: &[Component],
    index: &HashMap<&str, usize>,
) -> f64 {
    const BINS: usize = 8;
    let mut bins = [[0u16; BINS]; BINS];
    for connection in &problem.connections {
        let a = center(&components[index[connection.from.component.as_str()]]);
        let b = center(&components[index[connection.to.component.as_str()]]);
        let min_x = bin(a.x_nm.min(b.x_nm), problem.width_nm, BINS);
        let max_x = bin(a.x_nm.max(b.x_nm), problem.width_nm, BINS);
        let min_y = bin(a.y_nm.min(b.y_nm), problem.height_nm, BINS);
        let max_y = bin(a.y_nm.max(b.y_nm), problem.height_nm, BINS);
        for row in bins.iter_mut().take(max_y + 1).skip(min_y) {
            for value in row.iter_mut().take(max_x + 1).skip(min_x) {
                *value = value.saturating_add(1);
            }
        }
    }
    bins.iter()
        .flatten()
        .map(|&x| u32::from(x.saturating_sub(2)).pow(2) as f64)
        .sum()
}

fn constraint_penalty(
    problem: &PlacementProblem,
    components: &[Component],
    index: &HashMap<&str, usize>,
    unit: f64,
) -> f64 {
    problem
        .constraints
        .iter()
        .map(|constraint| match constraint {
            PlacementConstraint::Near {
                subject,
                target,
                max_distance_nm,
            } => {
                let a = named_position(subject, components, index);
                let b = named_position(target, components, index);
                manhattan_excess_nm(a, b, *max_distance_nm) / unit
            }
            PlacementConstraint::Decoupling {
                capacitor_anchor,
                power_pin,
                max_distance_nm,
                require_same_side,
            } => {
                let capacitor = named_position(capacitor_anchor, components, index);
                let power = named_position(power_pin, components, index);
                let distance_penalty =
                    decoupling_distance_excess_nm(capacitor, power, *max_distance_nm) / unit;
                let capacitor_component = &components[index[component_name(capacitor_anchor)]];
                let power_component = &components[index[component_name(power_pin)]];
                distance_penalty
                    + if *require_same_side && capacitor_component.side != power_component.side {
                        2.0 * problem.width_nm.max(problem.height_nm) as f64 / unit
                    } else {
                        0.0
                    }
            }
            PlacementConstraint::BoardEdge {
                subject,
                edge,
                max_distance_nm,
            } => {
                let p = center(&components[index[subject.as_str()]]);
                board_edge_excess_nm(
                    p,
                    *edge,
                    problem.width_nm,
                    problem.height_nm,
                    *max_distance_nm,
                ) / unit
            }
            PlacementConstraint::KeepTogether {
                components: names,
                max_span_nm,
            } => {
                let points: Vec<_> = names
                    .iter()
                    .map(|name| center(&components[index[name.as_str()]]))
                    .collect();
                if points.is_empty() {
                    0.0
                } else {
                    point_cloud_span_excess_nm(&points, *max_span_nm) / unit
                }
            }
            PlacementConstraint::Region { subject, min, max } => {
                let bounds = bounds(&components[index[subject.as_str()]]);
                region_overflow_nm(bounds, *min, *max) / unit
            }
        })
        .sum()
}

#[derive(Clone, Copy)]
struct Rect {
    min_x: Nm,
    min_y: Nm,
    max_x: Nm,
    max_y: Nm,
}
fn bounds(c: &Component) -> Rect {
    if !c.courtyard.is_empty() {
        let polygon = courtyard_polygon(c);
        return Rect {
            min_x: polygon.iter().map(|point| point.x_nm).min().unwrap_or(0),
            min_y: polygon.iter().map(|point| point.y_nm).min().unwrap_or(0),
            max_x: polygon.iter().map(|point| point.x_nm).max().unwrap_or(0),
            max_y: polygon.iter().map(|point| point.y_nm).max().unwrap_or(0),
        };
    }
    let p = c.position.unwrap_or_default();
    let (w, h) = if c.rotation_deg.is_multiple_of(180) {
        (c.width_nm, c.height_nm)
    } else {
        (c.height_nm, c.width_nm)
    };
    Rect {
        min_x: p.x_nm.saturating_sub(w / 2),
        min_y: p.y_nm.saturating_sub(h / 2),
        max_x: p.x_nm.saturating_add(w / 2),
        max_y: p.y_nm.saturating_add(h / 2),
    }
}

fn courtyard_polygon(component: &Component) -> Vec<Point> {
    let local = if component.courtyard.len() >= 3 {
        component.courtyard.clone()
    } else {
        let half_width = component.width_nm / 2;
        let half_height = component.height_nm / 2;
        vec![
            Point {
                x_nm: -half_width,
                y_nm: -half_height,
            },
            Point {
                x_nm: half_width,
                y_nm: -half_height,
            },
            Point {
                x_nm: half_width,
                y_nm: half_height,
            },
            Point {
                x_nm: -half_width,
                y_nm: half_height,
            },
        ]
    };
    let center = center(component);
    local
        .into_iter()
        .map(|point| {
            transform_courtyard_point(point, center, component.rotation_deg, component.side)
        })
        .collect()
}

fn transform_courtyard_point(
    mut point: Point,
    center: Point,
    rotation_deg: u16,
    side: BoardSide,
) -> Point {
    if side == BoardSide::Back {
        point.x_nm = point.x_nm.saturating_neg();
    }
    let rotated = rotate_point(point, rotation_deg);
    Point {
        x_nm: center.x_nm.saturating_add(rotated.x_nm),
        y_nm: center.y_nm.saturating_add(rotated.y_nm),
    }
}

fn polygons_intersect(left: &[Point], right: &[Point]) -> bool {
    left.iter()
        .zip(left.iter().cycle().skip(1))
        .take(left.len())
        .any(|(a, b)| {
            right
                .iter()
                .zip(right.iter().cycle().skip(1))
                .take(right.len())
                .any(|(c, d)| geometry::segments_within(*a, *b, *c, *d, 0))
        })
        || left
            .first()
            .is_some_and(|point| geometry::point_in_polygon(*point, right))
        || right
            .first()
            .is_some_and(|point| geometry::point_in_polygon(*point, left))
}

fn rotate_point(point: Point, rotation_deg: u16) -> Point {
    match rotation_deg % 360 {
        90 => Point {
            x_nm: point.y_nm.saturating_neg(),
            y_nm: point.x_nm,
        },
        180 => Point {
            x_nm: point.x_nm.saturating_neg(),
            y_nm: point.y_nm.saturating_neg(),
        },
        270 => Point {
            x_nm: point.y_nm,
            y_nm: point.x_nm.saturating_neg(),
        },
        _ => point,
    }
}
fn center(c: &Component) -> Point {
    c.position.unwrap_or_default()
}
fn pin_position(c: &Component, offset: Point) -> Point {
    let mut offset = offset;
    if c.side == BoardSide::Back {
        offset.x_nm = offset.x_nm.saturating_neg();
    }
    let offset = rotate_point(offset, c.rotation_deg);
    let p = center(c);
    Point {
        x_nm: p.x_nm.saturating_add(offset.x_nm),
        y_nm: p.y_nm.saturating_add(offset.y_nm),
    }
}
fn component_name(reference: &str) -> &str {
    reference
        .split_once('.')
        .map_or(reference, |(name, _)| name)
}
fn named_position(
    reference: &str,
    components: &[Component],
    index: &HashMap<&str, usize>,
) -> Point {
    let (component_name, anchor_name) = reference
        .split_once('.')
        .map_or((reference, None), |(a, b)| (a, Some(b)));
    let component = &components[index[component_name]];
    let offset = anchor_name
        .and_then(|name| component.anchors.get(name))
        .copied()
        .unwrap_or_default();
    pin_position(component, offset)
}
fn intersection(a: Rect, b: Rect) -> f64 {
    let w = overlap_extent_nm(a.min_x, a.max_x, b.min_x, b.max_x);
    let h = overlap_extent_nm(a.min_y, a.max_y, b.min_y, b.max_y);
    w * h
}

fn overlap_extent_nm(first_min: Nm, first_max: Nm, second_min: Nm, second_max: Nm) -> f64 {
    let lower = first_min.max(second_min);
    let upper = first_max.min(second_max);
    (i128::from(upper) - i128::from(lower)).max(0) as f64
}

fn bin(value: Nm, extent: Nm, count: usize) -> usize {
    ((value.clamp(0, extent) as i128 * count as i128 / extent as i128) as usize).min(count - 1)
}
fn snap(value: Nm, grid: Nm) -> Nm {
    let value = i128::from(value);
    let grid = i128::from(grid);
    let quotient = (value + grid / 2).div_euclid(grid);
    let minimum_quotient = -(-i128::from(Nm::MIN)).div_euclid(grid);
    let maximum_quotient = i128::from(Nm::MAX).div_euclid(grid);
    (quotient.clamp(minimum_quotient, maximum_quotient) * grid) as Nm
}

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { default_seed() } else { seed })
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn unit(&mut self) -> f64 {
        self.next() as f64 / u64::MAX as f64
    }
    fn index(&mut self, length: usize) -> usize {
        self.next() as usize % length
    }
}
fn one() -> f64 {
    1.0
}
fn iterations() -> usize {
    20_000
}
fn initial_temperature() -> f64 {
    100.0
}
fn cooling() -> f64 {
    0.9995
}
fn default_seed() -> u64 {
    0x0050_4342_4558
}
fn overlap_weight() -> f64 {
    1_000.0
}
fn boundary_weight() -> f64 {
    2_000.0
}
fn congestion_weight() -> f64 {
    2.0
}
fn constraint_weight() -> f64 {
    100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_spacing_step_saturates_extreme_dimensions() {
        assert_eq!(placement_spacing_step(i64::MAX, i64::MAX), i64::MAX);
        assert_eq!(placement_spacing_step(2_000_000, 500_000), 3_000_000);
    }

    #[test]
    fn bounded_grid_move_saturates_extreme_displacements() {
        assert_eq!(bounded_grid_move(1, i64::MAX, i64::MAX, 100), 100);
        assert_eq!(bounded_grid_move(99, i64::MIN, i64::MAX, 100), 0);
        assert_eq!(bounded_grid_move(50, 2, 10, 100), 70);
    }

    #[test]
    fn manhattan_distance_handles_full_signed_coordinates() {
        let distance = manhattan_distance_nm(
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
        );
        assert!(distance.is_finite());
        assert!(distance > i64::MAX as f64);
        assert_eq!(
            manhattan_distance_nm(Point { x_nm: 10, y_nm: 20 }, Point { x_nm: 15, y_nm: 30 }),
            15.0
        );
    }

    #[test]
    fn manhattan_excess_handles_full_signed_coordinates() {
        let excess = manhattan_excess_nm(
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
            i64::MAX,
        );
        assert!(excess.is_finite());
        assert!(excess > 0.0);
        assert_eq!(
            manhattan_excess_nm(
                Point { x_nm: 10, y_nm: 20 },
                Point { x_nm: 15, y_nm: 30 },
                20
            ),
            0.0
        );
    }

    #[test]
    fn decoupling_distance_handles_full_signed_coordinates() {
        let excess = decoupling_distance_excess_nm(
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
            i64::MAX,
        );
        assert!(excess.is_finite());
        assert!(excess > 0.0);
        assert_eq!(
            decoupling_distance_excess_nm(
                Point { x_nm: 10, y_nm: 20 },
                Point { x_nm: 15, y_nm: 30 },
                20
            ),
            0.0
        );
    }

    #[test]
    fn board_edge_distance_handles_full_signed_coordinates() {
        let right = board_edge_excess_nm(
            Point {
                x_nm: i64::MIN,
                y_nm: 0,
            },
            Edge::Right,
            i64::MAX,
            100,
            0,
        );
        let bottom = board_edge_excess_nm(
            Point {
                x_nm: 0,
                y_nm: i64::MIN,
            },
            Edge::Bottom,
            100,
            i64::MAX,
            0,
        );
        assert!(right.is_finite());
        assert!(bottom.is_finite());
        assert!(right > i64::MAX as f64);
        assert_eq!(
            board_edge_excess_nm(Point { x_nm: 90, y_nm: 50 }, Edge::Right, 100, 100, 10),
            0.0
        );
    }

    #[test]
    fn keep_together_span_handles_full_signed_coordinates() {
        let points = [
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
        ];
        let excess = point_cloud_span_excess_nm(&points, i64::MAX);
        assert!(excess.is_finite());
        assert!(excess > 0.0);
        assert_eq!(
            point_cloud_span_excess_nm(
                &[Point { x_nm: 10, y_nm: 20 }, Point { x_nm: 15, y_nm: 30 }],
                20
            ),
            0.0
        );
        assert_eq!(point_cloud_span_excess_nm(&[], 0), 0.0);
    }

    #[test]
    fn component_bounds_saturate_at_coordinate_limits() {
        let mut upper = component(
            "U1",
            Some(Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }),
        );
        upper.width_nm = i64::MAX;
        upper.height_nm = i64::MAX;
        let upper_bounds = bounds(&upper);
        assert_eq!(upper_bounds.max_x, i64::MAX);
        assert_eq!(upper_bounds.max_y, i64::MAX);

        let mut lower = upper;
        lower.position = Some(Point {
            x_nm: i64::MIN,
            y_nm: i64::MIN,
        });
        let lower_bounds = bounds(&lower);
        assert_eq!(lower_bounds.min_x, i64::MIN);
        assert_eq!(lower_bounds.min_y, i64::MIN);
    }

    #[test]
    fn courtyard_transform_saturates_at_coordinate_limits() {
        assert_eq!(
            transform_courtyard_point(
                Point {
                    x_nm: i64::MIN,
                    y_nm: i64::MAX,
                },
                Point {
                    x_nm: i64::MAX,
                    y_nm: i64::MAX,
                },
                0,
                BoardSide::Back,
            ),
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }
        );
        assert_eq!(
            transform_courtyard_point(
                Point { x_nm: 10, y_nm: 20 },
                Point {
                    x_nm: 100,
                    y_nm: 200
                },
                0,
                BoardSide::Front,
            ),
            Point {
                x_nm: 110,
                y_nm: 220,
            }
        );
    }

    #[test]
    fn pin_position_saturates_rotation_mirroring_and_offsets() {
        let mut part = component(
            "U1",
            Some(Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }),
        );
        part.side = BoardSide::Back;
        part.rotation_deg = 180;
        assert_eq!(
            pin_position(
                &part,
                Point {
                    x_nm: i64::MIN,
                    y_nm: i64::MIN,
                },
            ),
            Point {
                x_nm: 0,
                y_nm: i64::MAX,
            }
        );
        assert_eq!(
            pin_position(&part, Point { x_nm: 10, y_nm: 20 }),
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX - 20,
            }
        );
    }

    #[test]
    fn region_overflow_handles_full_signed_coordinates() {
        let overflow = region_overflow_nm(
            Rect {
                min_x: i64::MIN,
                min_y: i64::MIN,
                max_x: i64::MAX,
                max_y: i64::MAX,
            },
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
        );
        assert!(overflow.is_finite());
        assert!(overflow > i64::MAX as f64);
        assert_eq!(
            region_overflow_nm(
                Rect {
                    min_x: 20,
                    min_y: 30,
                    max_x: 80,
                    max_y: 90,
                },
                Point { x_nm: 10, y_nm: 20 },
                Point {
                    x_nm: 100,
                    y_nm: 100,
                },
            ),
            0.0
        );
    }

    #[test]
    fn rectangle_intersection_handles_full_signed_coordinates() {
        let full = Rect {
            min_x: i64::MIN,
            min_y: i64::MIN,
            max_x: i64::MAX,
            max_y: i64::MAX,
        };
        let area = intersection(full, full);
        assert!(area.is_finite());
        assert!(area > (i64::MAX as f64).powi(2));
        assert_eq!(
            intersection(
                Rect {
                    min_x: 0,
                    min_y: 0,
                    max_x: 10,
                    max_y: 20,
                },
                Rect {
                    min_x: 5,
                    min_y: 10,
                    max_x: 15,
                    max_y: 30,
                },
            ),
            50.0
        );
    }

    #[test]
    fn grid_snap_handles_full_signed_coordinates() {
        assert_eq!(snap(i64::MAX, 2), i64::MAX - 1);
        assert_eq!(snap(i64::MIN, 3), i64::MIN + 2);
        assert_eq!(snap(-6, 10), -10);
        assert_eq!(snap(-5, 10), 0);
        assert_eq!(snap(14, 10), 10);
        assert_eq!(snap(15, 10), 20);
    }

    #[test]
    fn boundary_overflow_handles_full_signed_coordinates() {
        let negative = point_boundary_overflow_nm(
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            },
            100,
            100,
        );
        let positive = point_boundary_overflow_nm(
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
            100,
            100,
        );
        assert!(negative.is_finite());
        assert!(positive.is_finite());
        assert_eq!(
            point_boundary_overflow_nm(Point { x_nm: 20, y_nm: 30 }, 100, 100),
            0.0
        );
    }

    fn component(reference: &str, position: Option<Point>) -> Component {
        Component {
            reference: reference.into(),
            width_nm: 2_000_000,
            height_nm: 2_000_000,
            position,
            rotation_deg: 0,
            fixed: false,
            side: BoardSide::Front,
            allowed_rotations: vec![],
            allow_side_flip: false,
            courtyard: vec![],
            anchors: HashMap::new(),
        }
    }

    fn connection(from: &str, to: &str) -> Connection {
        Connection {
            from: PinRef {
                component: from.to_string(),
                offset: Point::default(),
            },
            to: PinRef {
                component: to.to_string(),
                offset: Point::default(),
            },
            weight: 1.0,
        }
    }

    #[test]
    fn annealing_improves_overlapping_placement() {
        let p = PlacementProblem {
            width_nm: 20_000_000,
            height_nm: 20_000_000,
            grid_nm: 500_000,
            components: vec![
                component(
                    "U1",
                    Some(Point {
                        x_nm: 10_000_000,
                        y_nm: 10_000_000,
                    }),
                ),
                component(
                    "C1",
                    Some(Point {
                        x_nm: 10_000_000,
                        y_nm: 10_000_000,
                    }),
                ),
            ],
            connections: vec![Connection {
                from: PinRef {
                    component: "U1".into(),
                    offset: Point::default(),
                },
                to: PinRef {
                    component: "C1".into(),
                    offset: Point::default(),
                },
                weight: 1.0,
            }],
            constraints: vec![PlacementConstraint::Near {
                subject: "C1".into(),
                target: "U1".into(),
                max_distance_nm: 4_000_000,
            }],
        };
        let result = place(
            &p,
            &PlacementOptions {
                iterations: 5_000,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.final_score.total < result.initial_score.total);
        assert_eq!(result.final_score.overlap, 0.0);
    }
    #[test]
    fn fixed_component_does_not_move() {
        let mut c = component(
            "J1",
            Some(Point {
                x_nm: 1_000_000,
                y_nm: 2_000_000,
            }),
        );
        c.fixed = true;
        let p = PlacementProblem {
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            grid_nm: 500_000,
            components: vec![c],
            connections: vec![],
            constraints: vec![],
        };
        let r = place(&p, &PlacementOptions::default()).unwrap();
        assert_eq!(r.components[0].position, p.components[0].position);
    }

    #[test]
    fn near_constraint_supports_rotated_named_anchor() {
        let mut u1 = component(
            "U1",
            Some(Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            }),
        );
        u1.rotation_deg = 90;
        u1.anchors.insert(
            "VDD".into(),
            Point {
                x_nm: 1_000_000,
                y_nm: 0,
            },
        );
        u1.fixed = true;
        let mut c1 = component(
            "C1",
            Some(Point {
                x_nm: 5_000_000,
                y_nm: 6_000_000,
            }),
        );
        c1.fixed = true;
        let p = PlacementProblem {
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            grid_nm: 500_000,
            components: vec![u1, c1],
            connections: vec![],
            constraints: vec![PlacementConstraint::Near {
                subject: "C1".into(),
                target: "U1.VDD".into(),
                max_distance_nm: 0,
            }],
        };
        let result = place(&p, &PlacementOptions::default()).unwrap();
        assert_eq!(result.final_score.constraint_violation, 0.0);
    }

    #[test]
    fn decoupling_constraint_uses_pin_anchors_and_board_side() {
        let mut u1 = component(
            "U1",
            Some(Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            }),
        );
        u1.anchors.insert(
            "VDD".into(),
            Point {
                x_nm: 1_000_000,
                y_nm: 0,
            },
        );
        let mut c1 = component(
            "C1",
            Some(Point {
                x_nm: 6_000_000,
                y_nm: 5_000_000,
            }),
        );
        c1.anchors.insert("1".into(), Point::default());
        c1.side = BoardSide::Back;
        let problem = PlacementProblem {
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            grid_nm: 500_000,
            components: vec![u1, c1],
            connections: vec![],
            constraints: vec![PlacementConstraint::Decoupling {
                capacitor_anchor: "C1.1".into(),
                power_pin: "U1.VDD".into(),
                max_distance_nm: 500_000,
                require_same_side: true,
            }],
        };

        let opposite_side =
            evaluate(&problem, &problem.components, &ScoreWeights::default()).unwrap();
        let mut same_side = problem.components.clone();
        same_side[1].side = BoardSide::Front;
        let colocated = evaluate(&problem, &same_side, &ScoreWeights::default()).unwrap();

        assert!(opposite_side.constraint_violation > 0.0);
        assert_eq!(colocated.constraint_violation, 0.0);
    }

    #[test]
    fn region_and_allowed_rotations_are_enforced() {
        let mut part = component(
            "U1",
            Some(Point {
                x_nm: 1_000_000,
                y_nm: 1_000_000,
            }),
        );
        part.allowed_rotations = vec![90, 270];
        part.rotation_deg = 90;
        let problem = PlacementProblem {
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            grid_nm: 500_000,
            components: vec![part],
            connections: vec![],
            constraints: vec![PlacementConstraint::Region {
                subject: "U1".into(),
                min: Point {
                    x_nm: 4_000_000,
                    y_nm: 4_000_000,
                },
                max: Point {
                    x_nm: 8_000_000,
                    y_nm: 8_000_000,
                },
            }],
        };
        let result = place(&problem, &PlacementOptions::default()).unwrap();
        assert!(
            result.components[0]
                .allowed_rotations
                .contains(&result.components[0].rotation_deg)
        );
        assert!(
            result.final_score.constraint_violation < result.initial_score.constraint_violation
        );
    }

    #[test]
    fn polygon_courtyards_avoid_bbox_false_overlap_and_respect_side() {
        let mut left = component(
            "U1",
            Some(Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            }),
        );
        left.courtyard = vec![
            Point { x_nm: 0, y_nm: 0 },
            Point {
                x_nm: 4_000_000,
                y_nm: 0,
            },
            Point {
                x_nm: 0,
                y_nm: 4_000_000,
            },
        ];
        let mut right = component(
            "U2",
            Some(Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            }),
        );
        right.courtyard = vec![
            Point {
                x_nm: 4_000_000,
                y_nm: 4_000_000,
            },
            Point {
                x_nm: 4_000_000,
                y_nm: 1_000_000,
            },
            Point {
                x_nm: 1_000_000,
                y_nm: 4_000_000,
            },
        ];
        let mut problem = PlacementProblem {
            width_nm: 20_000_000,
            height_nm: 20_000_000,
            grid_nm: 500_000,
            components: vec![left, right],
            connections: vec![],
            constraints: vec![],
        };

        assert_eq!(
            evaluate(&problem, &problem.components, &ScoreWeights::default())
                .unwrap()
                .overlap,
            0.0
        );
        problem.components[1].courtyard[2] = Point {
            x_nm: 500_000,
            y_nm: 500_000,
        };
        assert!(
            evaluate(&problem, &problem.components, &ScoreWeights::default())
                .unwrap()
                .overlap
                > 0.0
        );
        problem.components[1].side = BoardSide::Back;
        assert_eq!(
            evaluate(&problem, &problem.components, &ScoreWeights::default())
                .unwrap()
                .overlap,
            0.0
        );
    }

    #[test]
    fn parallel_candidate_generation_is_deterministic_and_selects_pareto_result() {
        let problem = PlacementProblem {
            width_nm: 30_000_000,
            height_nm: 20_000_000,
            grid_nm: 500_000,
            components: vec![
                component("U1", None),
                component("U2", None),
                component("U3", None),
                component("U4", None),
            ],
            connections: vec![
                connection("U1", "U2"),
                connection("U1", "U3"),
                connection("U2", "U4"),
                connection("U3", "U4"),
            ],
            constraints: vec![],
        };
        let mut options = PlacementCandidateOptions {
            candidates: 7,
            workers: 1,
            placement: PlacementOptions {
                iterations: 300,
                ..PlacementOptions::default()
            },
        };
        let sequential = place_candidates(&problem, &options).unwrap();
        options.workers = 4;
        let parallel = place_candidates(&problem, &options).unwrap();
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
        assert!(parallel.selected().pareto_optimal);
        assert!(
            parallel
                .pareto_front
                .contains(&parallel.selected_candidate_id)
        );
        assert_eq!(
            parallel.candidates[0].objective,
            CandidateObjective::Balanced
        );
        assert_eq!(
            parallel.candidates[1].objective,
            CandidateObjective::Wirelength
        );
    }

    #[test]
    fn pareto_dominance_requires_no_worse_and_one_better_metric() {
        let baseline = Score {
            hpwl: 10.0,
            overlap: 0.0,
            boundary: 0.0,
            congestion: 5.0,
            constraint_violation: 0.0,
            total: 15.0,
        };
        let better = Score {
            hpwl: 9.0,
            ..baseline.clone()
        };
        let tradeoff = Score {
            hpwl: 8.0,
            congestion: 6.0,
            ..baseline.clone()
        };
        assert!(dominates(&better, &baseline));
        assert!(!dominates(&baseline, &better));
        assert!(!dominates(&tradeoff, &baseline));
        assert!(!dominates(&baseline, &tradeoff));
    }
}

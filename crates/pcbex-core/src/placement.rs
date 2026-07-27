use crate::{Nm, Point, geometry};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

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
        out.hpwl +=
            ((a.x_nm - b.x_nm).abs() + (a.y_nm - b.y_nm).abs()) as f64 / unit * connection.weight;
    }
    for (i, a) in components.iter().enumerate() {
        let ar = bounds(a);
        let polygon = courtyard_polygon(a);
        out.boundary += polygon
            .iter()
            .map(|point| {
                (-point.x_nm).max(0)
                    + (-point.y_nm).max(0)
                    + (point.x_nm - problem.width_nm).max(0)
                    + (point.y_nm - problem.height_nm).max(0)
            })
            .sum::<i64>() as f64
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
                (((a.x_nm - b.x_nm).abs() + (a.y_nm - b.y_nm).abs() - max_distance_nm).max(0))
                    as f64
                    / unit
            }
            PlacementConstraint::Decoupling {
                capacitor_anchor,
                power_pin,
                max_distance_nm,
                require_same_side,
            } => {
                let capacitor = named_position(capacitor_anchor, components, index);
                let power = named_position(power_pin, components, index);
                let distance_penalty = ((capacitor.x_nm - power.x_nm).abs()
                    + (capacitor.y_nm - power.y_nm).abs()
                    - max_distance_nm)
                    .max(0) as f64
                    / unit;
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
                let distance = match edge {
                    Edge::Left => p.x_nm,
                    Edge::Right => problem.width_nm - p.x_nm,
                    Edge::Top => p.y_nm,
                    Edge::Bottom => problem.height_nm - p.y_nm,
                };
                (distance - max_distance_nm).max(0) as f64 / unit
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
                    let span = points.iter().map(|p| p.x_nm).max().unwrap()
                        - points.iter().map(|p| p.x_nm).min().unwrap()
                        + points.iter().map(|p| p.y_nm).max().unwrap()
                        - points.iter().map(|p| p.y_nm).min().unwrap();
                    (span - max_span_nm).max(0) as f64 / unit
                }
            }
            PlacementConstraint::Region { subject, min, max } => {
                let bounds = bounds(&components[index[subject.as_str()]]);
                (min.x_nm - bounds.min_x).max(0) as f64 / unit
                    + (min.y_nm - bounds.min_y).max(0) as f64 / unit
                    + (bounds.max_x - max.x_nm).max(0) as f64 / unit
                    + (bounds.max_y - max.y_nm).max(0) as f64 / unit
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
        min_x: p.x_nm - w / 2,
        min_y: p.y_nm - h / 2,
        max_x: p.x_nm + w / 2,
        max_y: p.y_nm + h / 2,
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
        .map(|mut point| {
            if component.side == BoardSide::Back {
                point.x_nm = -point.x_nm;
            }
            let rotated = rotate_point(point, component.rotation_deg);
            Point {
                x_nm: center.x_nm + rotated.x_nm,
                y_nm: center.y_nm + rotated.y_nm,
            }
        })
        .collect()
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
            x_nm: -point.y_nm,
            y_nm: point.x_nm,
        },
        180 => Point {
            x_nm: -point.x_nm,
            y_nm: -point.y_nm,
        },
        270 => Point {
            x_nm: point.y_nm,
            y_nm: -point.x_nm,
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
        offset.x_nm = -offset.x_nm;
    }
    let offset = rotate_point(offset, c.rotation_deg);
    let p = center(c);
    Point {
        x_nm: p.x_nm + offset.x_nm,
        y_nm: p.y_nm + offset.y_nm,
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
    let w = (a.max_x.min(b.max_x) - a.min_x.max(b.min_x)).max(0) as f64;
    let h = (a.max_y.min(b.max_y) - a.min_y.max(b.min_y)).max(0) as f64;
    w * h
}
fn bin(value: Nm, extent: Nm, count: usize) -> usize {
    ((value.clamp(0, extent) as i128 * count as i128 / extent as i128) as usize).min(count - 1)
}
fn snap(value: Nm, grid: Nm) -> Nm {
    ((value + grid / 2) / grid) * grid
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
}

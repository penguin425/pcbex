use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

pub mod checking;
mod geometry;
pub mod placement;

pub type Nm = i64;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x_nm: Nm,
    pub y_nm: Nm,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Layer {
    Front,
    Inner(u8),
    Back,
}

impl Layer {
    pub fn index(self) -> u8 {
        match self {
            Self::Front => 0,
            Self::Inner(index) => index,
            Self::Back => 31,
        }
    }

    pub fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Front),
            1..=30 => Some(Self::Inner(index)),
            31 => Some(Self::Back),
            _ => None,
        }
    }

    pub fn name(self) -> String {
        match self {
            Self::Front => "F.Cu".into(),
            Self::Inner(index) => format!("In{index}.Cu"),
            Self::Back => "B.Cu".into(),
        }
    }
}

impl Serialize for Layer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.name())
    }
}

impl<'de> Deserialize<'de> for Layer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "F.Cu" => Ok(Self::Front),
            "B.Cu" => Ok(Self::Back),
            _ if value.starts_with("In") && value.ends_with(".Cu") => value[2..value.len() - 3]
                .parse::<u8>()
                .ok()
                .and_then(Self::from_index)
                .filter(|layer| matches!(layer, Self::Inner(_)))
                .ok_or_else(|| de::Error::custom(format!("invalid copper layer: {value}"))),
            _ => Err(de::Error::custom(format!("invalid copper layer: {value}"))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Terminal {
    pub position: Point,
    #[serde(default = "both_layers")]
    pub layers: Vec<Layer>,
}
fn both_layers() -> Vec<Layer> {
    vec![Layer::Front, Layer::Back]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Net {
    pub id: u32,
    pub name: String,
    pub terminals: Vec<Terminal>,
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Obstacle {
    pub min: Point,
    pub max: Point,
    #[serde(default = "both_layers")]
    pub layers: Vec<Layer>,
    #[serde(default)]
    pub net_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundObstacle {
    pub center: Point,
    pub diameter_nm: Nm,
    #[serde(default = "both_layers")]
    pub layers: Vec<Layer>,
    #[serde(default)]
    pub net_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapsuleObstacle {
    pub start: Point,
    pub end: Point,
    pub diameter_nm: Nm,
    #[serde(default = "both_layers")]
    pub layers: Vec<Layer>,
    #[serde(default)]
    pub net_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolygonObstacle {
    pub polygon: Vec<Point>,
    #[serde(default = "both_layers")]
    pub layers: Vec<Layer>,
    #[serde(default)]
    pub net_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keepout {
    pub polygon: Vec<Point>,
    #[serde(default = "both_layers")]
    pub layers: Vec<Layer>,
    #[serde(default)]
    pub net_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Footprint {
    pub reference: String,
    pub position: Point,
    pub rotation_deg: f64,
    pub pads: Vec<Pad>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pad {
    pub number: String,
    pub position: Point,
    pub width_nm: Nm,
    pub height_nm: Nm,
    #[serde(default)]
    pub source_width_nm: Nm,
    #[serde(default)]
    pub source_height_nm: Nm,
    #[serde(default)]
    pub rotation_deg: f64,
    #[serde(default)]
    pub shape: PadShape,
    #[serde(default)]
    pub custom_polygon: Vec<Point>,
    pub layers: Vec<Layer>,
    pub net_id: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PadShape {
    #[default]
    Rect,
    Circle,
    Oval,
    RoundRect,
    Trapezoid,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rules {
    pub grid_nm: Nm,
    pub track_width_nm: Nm,
    pub clearance_nm: Nm,
    pub via_diameter_nm: Nm,
    pub via_drill_nm: Nm,
    #[serde(default = "bend_cost")]
    pub bend_cost: u32,
    #[serde(default = "via_cost")]
    pub via_cost: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetClassRules {
    pub track_width_nm: Nm,
    pub clearance_nm: Nm,
    pub via_diameter_nm: Nm,
    pub via_drill_nm: Nm,
    #[serde(default)]
    pub layers: Option<Vec<Layer>>,
    #[serde(default)]
    pub differential_width_nm: Option<Nm>,
    #[serde(default)]
    pub differential_gap_nm: Option<Nm>,
    #[serde(default)]
    pub minimum_length_nm: Option<Nm>,
    #[serde(default)]
    pub maximum_length_nm: Option<Nm>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DifferentialPair {
    pub name: String,
    pub positive_net_id: u32,
    pub negative_net_id: u32,
    pub gap_nm: Nm,
    #[serde(default = "differential_gap_tolerance")]
    pub gap_tolerance_nm: Nm,
    #[serde(default = "differential_max_skew")]
    pub max_skew_nm: Nm,
    #[serde(default = "differential_min_coupled_percent")]
    pub min_coupled_percent: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManufacturingRules {
    pub minimum_track_width_nm: Nm,
    pub minimum_clearance_nm: Nm,
    pub minimum_drill_nm: Nm,
    pub minimum_annular_ring_nm: Nm,
    pub minimum_copper_to_edge_nm: Nm,
    pub board_thickness_nm: Nm,
    #[serde(default = "default_maximum_via_aspect_ratio")]
    pub maximum_via_aspect_ratio: u16,
    #[serde(default)]
    pub minimum_drill_to_drill_nm: Nm,
    #[serde(default = "allow_via_in_pad")]
    pub allow_via_in_pad: bool,
    #[serde(default)]
    pub minimum_trace_angle_deg: u16,
}

fn default_maximum_via_aspect_ratio() -> u16 {
    10
}

fn allow_via_in_pad() -> bool {
    true
}

fn differential_gap_tolerance() -> Nm {
    100_000
}
fn differential_max_skew() -> Nm {
    500_000
}
fn differential_min_coupled_percent() -> u8 {
    80
}

impl NetClassRules {
    fn merged_with(&self, defaults: &Rules) -> Rules {
        Rules {
            grid_nm: defaults.grid_nm,
            track_width_nm: self.track_width_nm,
            clearance_nm: self.clearance_nm,
            via_diameter_nm: self.via_diameter_nm,
            via_drill_nm: self.via_drill_nm,
            bend_cost: defaults.bend_cost,
            via_cost: defaults.via_cost,
        }
    }
}
fn bend_cost() -> u32 {
    5
}
fn via_cost() -> u32 {
    20
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Board {
    pub width_nm: Nm,
    pub height_nm: Nm,
    #[serde(default)]
    pub outline: Vec<Point>,
    #[serde(default)]
    pub cutouts: Vec<Vec<Point>>,
    #[serde(default = "both_layers")]
    pub copper_layers: Vec<Layer>,
    pub rules: Rules,
    #[serde(default)]
    pub obstacles: Vec<Obstacle>,
    #[serde(default)]
    pub round_obstacles: Vec<RoundObstacle>,
    #[serde(default)]
    pub capsule_obstacles: Vec<CapsuleObstacle>,
    #[serde(default)]
    pub polygon_obstacles: Vec<PolygonObstacle>,
    #[serde(default)]
    pub keepouts: Vec<Keepout>,
    #[serde(default)]
    pub footprints: Vec<Footprint>,
    #[serde(default)]
    pub net_classes: HashMap<String, NetClassRules>,
    #[serde(default)]
    pub differential_pairs: Vec<DifferentialPair>,
    #[serde(default)]
    pub manufacturing_rules: Option<ManufacturingRules>,
    #[serde(default)]
    pub via_strategy: ViaStrategy,
    #[serde(default)]
    pub nets: Vec<Net>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

impl Board {
    fn effective_outline(&self) -> Vec<Point> {
        if self.outline.len() >= 3 {
            return self.outline.clone();
        }
        vec![
            Point { x_nm: 0, y_nm: 0 },
            Point {
                x_nm: self.width_nm,
                y_nm: 0,
            },
            Point {
                x_nm: self.width_nm,
                y_nm: self.height_nm,
            },
            Point {
                x_nm: 0,
                y_nm: self.height_nm,
            },
        ]
    }

    fn point_inside_board(&self, point: Point, diameter_nm: Nm) -> bool {
        let outline = self.effective_outline();
        geometry::point_in_polygon(point, &outline)
            && !geometry::point_polygon_closer_than(point, &outline, diameter_nm)
            && self.cutouts.iter().all(|cutout| {
                !geometry::point_in_polygon(point, cutout)
                    && !geometry::point_polygon_closer_than(point, cutout, diameter_nm)
            })
    }

    pub fn rules_for_net(&self, net_id: u32) -> Rules {
        let class = self
            .nets
            .iter()
            .find(|net| net.id == net_id)
            .and_then(|net| net.class.as_ref())
            .and_then(|class| self.net_classes.get(class));
        let Some(class) = class else {
            return self.rules.clone();
        };
        let mut rules = class.merged_with(&self.rules);
        if self
            .differential_pairs
            .iter()
            .any(|pair| pair.positive_net_id == net_id || pair.negative_net_id == net_id)
            && let Some(width) = class.differential_width_nm
        {
            rules.track_width_nm = width;
        }
        rules
    }

    pub fn layers_for_net(&self, net_id: u32) -> Option<&[Layer]> {
        self.nets
            .iter()
            .find(|net| net.id == net_id)
            .and_then(|net| net.class.as_ref())
            .and_then(|class| self.net_classes.get(class))
            .and_then(|rules| rules.layers.as_deref())
    }

    pub fn length_limits_for_net(&self, net_id: u32) -> (Option<Nm>, Option<Nm>) {
        self.nets
            .iter()
            .find(|net| net.id == net_id)
            .and_then(|net| net.class.as_ref())
            .and_then(|class| self.net_classes.get(class))
            .map(|rules| (rules.minimum_length_nm, rules.maximum_length_nm))
            .unwrap_or((None, None))
    }

    fn via_for_transition(&self, from: Layer, to: Layer) -> (ViaKind, Layer, Layer, u64) {
        if self.via_strategy == ViaStrategy::ThroughOnly {
            return (ViaKind::Through, Layer::Front, Layer::Back, 1);
        }
        let from_position = self
            .copper_layers
            .iter()
            .position(|layer| *layer == from)
            .expect("router transitions only declared layers");
        let to_position = self
            .copper_layers
            .iter()
            .position(|layer| *layer == to)
            .expect("router transitions only declared layers");
        if from_position.abs_diff(to_position) == 1 {
            (ViaKind::Micro, from, to, 1)
        } else if from_position.min(to_position) == 0
            && from_position.max(to_position) + 1 == self.copper_layers.len()
        {
            (ViaKind::Through, Layer::Front, Layer::Back, 1)
        } else {
            (ViaKind::BlindBuried, from, to, 2)
        }
    }

    fn maximum_routing_envelope(&self) -> (Nm, Nm) {
        self.net_classes.values().fold(
            (
                self.rules.track_width_nm.max(self.rules.via_diameter_nm),
                self.rules.clearance_nm,
            ),
            |(diameter, clearance), rules| {
                (
                    diameter
                        .max(rules.track_width_nm)
                        .max(rules.via_diameter_nm),
                    clearance.max(rules.clearance_nm),
                )
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Segment {
    pub start: Point,
    pub end: Point,
    pub layer: Layer,
    pub width_nm: Nm,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouteArc {
    pub start: Point,
    pub mid: Point,
    pub end: Point,
    pub layer: Layer,
    pub width_nm: Nm,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Teardrop {
    pub polygon: Vec<Point>,
    pub layer: Layer,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CopperZone {
    pub polygon: Vec<Point>,
    pub layer: Layer,
    #[serde(default)]
    pub clearance_nm: Nm,
    #[serde(default = "zone_minimum_thickness")]
    pub minimum_thickness_nm: Nm,
}

fn zone_minimum_thickness() -> Nm {
    250_000
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Via {
    pub position: Point,
    pub diameter_nm: Nm,
    pub drill_nm: Nm,
    #[serde(default)]
    pub kind: ViaKind,
    #[serde(default = "front_layer")]
    pub start_layer: Layer,
    #[serde(default = "back_layer")]
    pub end_layer: Layer,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViaKind {
    #[default]
    Through,
    BlindBuried,
    Micro,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViaStrategy {
    #[default]
    ThroughOnly,
    Auto,
}

fn front_layer() -> Layer {
    Layer::Front
}

fn back_layer() -> Layer {
    Layer::Back
}

impl Via {
    pub fn spans_layer(&self, layer: Layer) -> bool {
        let first = self.start_layer.index().min(self.end_layer.index());
        let last = self.start_layer.index().max(self.end_layer.index());
        (first..=last).contains(&layer.index())
    }

    pub fn shares_layer_with(&self, other: &Self) -> bool {
        self.spans_layer(other.start_layer)
            || self.spans_layer(other.end_layer)
            || other.spans_layer(self.start_layer)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Route {
    pub net_id: u32,
    pub segments: Vec<Segment>,
    #[serde(default)]
    pub arcs: Vec<RouteArc>,
    pub vias: Vec<Via>,
    #[serde(default)]
    pub teardrops: Vec<Teardrop>,
    #[serde(default)]
    pub zones: Vec<CopperZone>,
}

impl Route {
    pub fn linearized_arcs(&self) -> Self {
        let mut route = self.clone();
        for arc in &self.arcs {
            route.segments.extend([
                Segment {
                    start: arc.start,
                    end: arc.mid,
                    layer: arc.layer,
                    width_nm: arc.width_nm,
                },
                Segment {
                    start: arc.mid,
                    end: arc.end,
                    layer: arc.layer,
                    width_nm: arc.width_nm,
                },
            ]);
        }
        route.arcs.clear();
        route
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteReport {
    pub preserved: Vec<String>,
    pub routed: Vec<String>,
    pub rerouted: Vec<String>,
    pub unrouted: Vec<String>,
    pub expanded_states: usize,
    #[serde(default)]
    pub rasterized_candidate_cells: usize,
    pub reroute_passes: usize,
    pub ripup_events: usize,
    #[serde(default)]
    pub coupled_differential_pairs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Node {
    x: i32,
    y: i32,
    layer: u8,
    dir: u8,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct QueueItem {
    score: u64,
    cost: u64,
    node: Node,
}
impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .cmp(&self.score)
            .then_with(|| other.cost.cmp(&self.cost))
    }
}
impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct Router<'a> {
    board: &'a Board,
    blocked: HashSet<(i32, i32, u8)>,
    owned: HashMap<(i32, i32, u8), u32>,
    occupied: HashSet<(i32, i32, u8)>,
    occupied_by: HashMap<(i32, i32, u8), u32>,
    congestion: HashMap<(i32, i32, u8), u16>,
    rasterized_candidate_cells: usize,
}

struct RouteFailure {
    expanded: usize,
    blockers: HashSet<u32>,
}

struct SearchFailure {
    expanded: usize,
    blockers: HashSet<u32>,
}

impl<'a> Router<'a> {
    pub fn new(board: &'a Board) -> Result<Self, String> {
        if board.rules.grid_nm <= 0 {
            return Err("grid_nm must be positive".into());
        }
        if board.width_nm <= 0 || board.height_nm <= 0 {
            return Err("board dimensions must be positive".into());
        }
        if board.copper_layers.is_empty()
            || board
                .copper_layers
                .iter()
                .any(|layer| !matches!(layer, Layer::Front | Layer::Back | Layer::Inner(1..=30)))
            || board
                .copper_layers
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                .len()
                != board.copper_layers.len()
        {
            return Err("board copper layers must be unique supported layers".into());
        }
        let known_layers = |layers: &[Layer]| {
            !layers.is_empty()
                && layers
                    .iter()
                    .all(|layer| board.copper_layers.contains(layer))
        };
        if board
            .nets
            .iter()
            .flat_map(|net| &net.terminals)
            .any(|terminal| !known_layers(&terminal.layers))
            || board
                .obstacles
                .iter()
                .any(|obstacle| !known_layers(&obstacle.layers))
            || board
                .round_obstacles
                .iter()
                .any(|obstacle| !known_layers(&obstacle.layers))
            || board
                .capsule_obstacles
                .iter()
                .any(|obstacle| !known_layers(&obstacle.layers))
            || board
                .polygon_obstacles
                .iter()
                .any(|obstacle| !known_layers(&obstacle.layers))
            || board
                .keepouts
                .iter()
                .any(|keepout| !known_layers(&keepout.layers))
            || board
                .routes
                .iter()
                .flat_map(|route| &route.segments)
                .any(|segment| !board.copper_layers.contains(&segment.layer))
        {
            return Err("board items reference undeclared copper layers".into());
        }
        if !board.outline.is_empty()
            && (!geometry::polygon_is_simple(&board.outline)
                || board.outline.iter().any(|point| {
                    point.x_nm < 0
                        || point.y_nm < 0
                        || point.x_nm > board.width_nm
                        || point.y_nm > board.height_nm
                }))
        {
            return Err("board outline must be a simple polygon inside its bounds".into());
        }
        let outline = board.effective_outline();
        if board.cutouts.iter().any(|cutout| {
            !geometry::polygon_is_simple(cutout)
                || cutout
                    .iter()
                    .any(|point| !geometry::point_in_polygon(*point, &outline))
        }) {
            return Err("board cutouts must be simple polygons inside the outline".into());
        }
        if board
            .keepouts
            .iter()
            .any(|keepout| !geometry::polygon_is_simple(&keepout.polygon))
        {
            return Err("keepout must be a simple polygon".into());
        }
        if board
            .polygon_obstacles
            .iter()
            .any(|obstacle| !geometry::polygon_is_simple(&obstacle.polygon))
        {
            return Err("polygon obstacle must be a simple polygon".into());
        }
        if board
            .round_obstacles
            .iter()
            .any(|obstacle| obstacle.diameter_nm <= 0)
        {
            return Err("round obstacle diameter must be positive".into());
        }
        if board
            .capsule_obstacles
            .iter()
            .any(|obstacle| obstacle.diameter_nm <= 0)
        {
            return Err("capsule obstacle diameter must be positive".into());
        }
        for (name, rules) in &board.net_classes {
            if rules.track_width_nm <= 0
                || rules.clearance_nm < 0
                || rules.via_drill_nm <= 0
                || rules.via_diameter_nm <= rules.via_drill_nm
            {
                return Err(format!("net class {name} has invalid dimensions"));
            }
            if rules.layers.as_ref().is_some_and(Vec::is_empty) {
                return Err(format!("net class {name} must allow at least one layer"));
            }
            if rules.minimum_length_nm.is_some_and(|value| value <= 0)
                || rules.maximum_length_nm.is_some_and(|value| value <= 0)
                || matches!(
                    (rules.minimum_length_nm, rules.maximum_length_nm),
                    (Some(minimum), Some(maximum)) if minimum > maximum
                )
            {
                return Err(format!("net class {name} has invalid length limits"));
            }
            if rules
                .layers
                .as_ref()
                .is_some_and(|layers| !known_layers(layers))
            {
                return Err(format!("net class {name} references undeclared layers"));
            }
        }
        let net_ids: HashSet<_> = board.nets.iter().map(|net| net.id).collect();
        let mut paired_net_ids = HashSet::new();
        for pair in &board.differential_pairs {
            if pair.positive_net_id == pair.negative_net_id
                || !net_ids.contains(&pair.positive_net_id)
                || !net_ids.contains(&pair.negative_net_id)
                || pair.gap_nm < 0
                || pair.gap_tolerance_nm < 0
                || pair.max_skew_nm < 0
                || pair.min_coupled_percent > 100
                || !paired_net_ids.insert(pair.positive_net_id)
                || !paired_net_ids.insert(pair.negative_net_id)
            {
                return Err(format!("differential pair {} is invalid", pair.name));
            }
        }
        let mut route_net_ids = HashSet::new();
        for route in &board.routes {
            if !route_net_ids.insert(route.net_id) {
                return Err(format!(
                    "net {} has more than one existing route",
                    route.net_id
                ));
            }
        }
        let mut router = Self {
            board,
            blocked: HashSet::new(),
            owned: HashMap::new(),
            occupied: HashSet::new(),
            occupied_by: HashMap::new(),
            congestion: HashMap::new(),
            rasterized_candidate_cells: 0,
        };
        router.rasterize_obstacles();
        Ok(router)
    }

    fn rasterize_obstacles(&mut self) {
        let g = self.board.rules.grid_nm;
        let (maximum_diameter, maximum_clearance) = self.board.maximum_routing_envelope();
        let edge_envelope = maximum_diameter + 2 * maximum_clearance;
        let max_x = self.board.width_nm / g;
        let max_y = self.board.height_nm / g;
        for y in 0..=max_y {
            for x in 0..=max_x {
                self.rasterized_candidate_cells += 1;
                let point = Point {
                    x_nm: x as Nm * g,
                    y_nm: y as Nm * g,
                };
                if !self.board.point_inside_board(point, edge_envelope) {
                    self.blocked.extend(
                        self.board
                            .copper_layers
                            .iter()
                            .map(|layer| (x as i32, y as i32, layer_index(*layer))),
                    );
                }
            }
        }
        let inflate = maximum_diameter / 2 + maximum_clearance;
        for o in &self.board.obstacles {
            let min_x = ((o.min.x_nm - inflate).max(0) / g) as i32;
            let min_y = ((o.min.y_nm - inflate).max(0) / g) as i32;
            let max_x = ((o.max.x_nm + inflate).min(self.board.width_nm) / g) as i32;
            let max_y = ((o.max.y_nm + inflate).min(self.board.height_nm) / g) as i32;
            for layer in &o.layers {
                let l = layer_index(*layer);
                for y in min_y..=max_y {
                    for x in min_x..=max_x {
                        self.rasterized_candidate_cells += 1;
                        let cell = (x, y, l);
                        if let Some(net_id) = o.net_id {
                            if self
                                .owned
                                .insert(cell, net_id)
                                .is_some_and(|previous| previous != net_id)
                            {
                                self.blocked.insert(cell);
                            }
                        } else {
                            self.blocked.insert(cell);
                        }
                    }
                }
            }
        }
        for obstacle in &self.board.round_obstacles {
            let distance_twice = obstacle.diameter_nm + maximum_diameter + 2 * maximum_clearance;
            let radius = (distance_twice + 1) / 2;
            let (min_x, max_x, min_y, max_y) = cell_window(
                obstacle.center.x_nm - radius,
                obstacle.center.x_nm + radius,
                obstacle.center.y_nm - radius,
                obstacle.center.y_nm + radius,
                g,
                self.board.width_nm,
                self.board.height_nm,
            );
            for layer in &obstacle.layers {
                let layer = layer_index(*layer);
                for y in min_y..=max_y {
                    for x in min_x..=max_x {
                        self.rasterized_candidate_cells += 1;
                        let point = Point {
                            x_nm: x as Nm * g,
                            y_nm: y as Nm * g,
                        };
                        if !geometry::points_within(point, obstacle.center, distance_twice) {
                            continue;
                        }
                        let cell = (x, y, layer);
                        if let Some(net_id) = obstacle.net_id {
                            if self
                                .owned
                                .insert(cell, net_id)
                                .is_some_and(|previous| previous != net_id)
                            {
                                self.blocked.insert(cell);
                            }
                        } else {
                            self.blocked.insert(cell);
                        }
                    }
                }
            }
        }
        for obstacle in &self.board.capsule_obstacles {
            let distance_twice = obstacle.diameter_nm + maximum_diameter + 2 * maximum_clearance;
            let radius = (distance_twice + 1) / 2;
            let (min_x, max_x, min_y, max_y) = cell_window(
                obstacle.start.x_nm.min(obstacle.end.x_nm) - radius,
                obstacle.start.x_nm.max(obstacle.end.x_nm) + radius,
                obstacle.start.y_nm.min(obstacle.end.y_nm) - radius,
                obstacle.start.y_nm.max(obstacle.end.y_nm) + radius,
                g,
                self.board.width_nm,
                self.board.height_nm,
            );
            for layer in &obstacle.layers {
                let layer = layer_index(*layer);
                for y in min_y..=max_y {
                    for x in min_x..=max_x {
                        self.rasterized_candidate_cells += 1;
                        let point = Point {
                            x_nm: x as Nm * g,
                            y_nm: y as Nm * g,
                        };
                        if !geometry::point_segment_within(
                            point,
                            obstacle.start,
                            obstacle.end,
                            distance_twice,
                        ) {
                            continue;
                        }
                        let cell = (x, y, layer);
                        if let Some(net_id) = obstacle.net_id {
                            if self
                                .owned
                                .insert(cell, net_id)
                                .is_some_and(|previous| previous != net_id)
                            {
                                self.blocked.insert(cell);
                            }
                        } else {
                            self.blocked.insert(cell);
                        }
                    }
                }
            }
        }
        let keepout_distance_twice = maximum_diameter + 2 * maximum_clearance;
        for obstacle in &self.board.polygon_obstacles {
            let Some((min_x_nm, max_x_nm, min_y_nm, max_y_nm)) = polygon_bounds(&obstacle.polygon)
            else {
                continue;
            };
            let radius = (keepout_distance_twice + 1) / 2;
            let (min_x, max_x, min_y, max_y) = cell_window(
                min_x_nm - radius,
                max_x_nm + radius,
                min_y_nm - radius,
                max_y_nm + radius,
                g,
                self.board.width_nm,
                self.board.height_nm,
            );
            for layer in &obstacle.layers {
                let layer = layer_index(*layer);
                for y in min_y..=max_y {
                    for x in min_x..=max_x {
                        self.rasterized_candidate_cells += 1;
                        let point = Point {
                            x_nm: x as Nm * g,
                            y_nm: y as Nm * g,
                        };
                        if geometry::point_in_polygon(point, &obstacle.polygon)
                            || geometry::point_polygon_closer_than(
                                point,
                                &obstacle.polygon,
                                keepout_distance_twice,
                            )
                        {
                            let cell = (x, y, layer);
                            if let Some(net_id) = obstacle.net_id {
                                if self
                                    .owned
                                    .insert(cell, net_id)
                                    .is_some_and(|previous| previous != net_id)
                                {
                                    self.blocked.insert(cell);
                                }
                            } else {
                                self.blocked.insert(cell);
                            }
                        }
                    }
                }
            }
        }
        for keepout in &self.board.keepouts {
            let Some((min_x_nm, max_x_nm, min_y_nm, max_y_nm)) = polygon_bounds(&keepout.polygon)
            else {
                continue;
            };
            let radius = (keepout_distance_twice + 1) / 2;
            let (min_x, max_x, min_y, max_y) = cell_window(
                min_x_nm - radius,
                max_x_nm + radius,
                min_y_nm - radius,
                max_y_nm + radius,
                g,
                self.board.width_nm,
                self.board.height_nm,
            );
            for layer in &keepout.layers {
                let layer = layer_index(*layer);
                for y in min_y..=max_y {
                    for x in min_x..=max_x {
                        self.rasterized_candidate_cells += 1;
                        let point = Point {
                            x_nm: x as Nm * g,
                            y_nm: y as Nm * g,
                        };
                        if geometry::point_in_polygon(point, &keepout.polygon)
                            || geometry::point_polygon_closer_than(
                                point,
                                &keepout.polygon,
                                keepout_distance_twice,
                            )
                        {
                            let cell = (x, y, layer);
                            if let Some(net_id) = keepout.net_id {
                                if self
                                    .owned
                                    .insert(cell, net_id)
                                    .is_some_and(|previous| previous != net_id)
                                {
                                    self.blocked.insert(cell);
                                }
                            } else {
                                self.blocked.insert(cell);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn route_all(mut self) -> (Vec<Route>, RouteReport) {
        let fixed_net_ids: HashSet<u32> =
            self.board.routes.iter().map(|route| route.net_id).collect();
        let preserved: Vec<String> = self
            .board
            .nets
            .iter()
            .filter(|net| fixed_net_ids.contains(&net.id))
            .map(|net| net.name.clone())
            .collect();
        let mut nets: Vec<_> = self
            .board
            .nets
            .iter()
            .filter(|net| !fixed_net_ids.contains(&net.id))
            .collect();
        nets.sort_by_key(|n| {
            (
                std::cmp::Reverse(n.priority),
                std::cmp::Reverse(n.terminals.len()),
                std::cmp::Reverse(net_span(n)),
            )
        });
        let mut pending: HashSet<u32> = nets.iter().map(|net| net.id).collect();
        let mut previously_failed = HashSet::new();
        let mut accepted = Vec::<Route>::new();
        let mut ripped_ids = HashSet::<u32>::new();
        let mut ripup_events = 0;
        let mut best_routes = self.board.routes.clone();
        let mut best_report = RouteReport {
            preserved: preserved.clone(),
            unrouted: nets.iter().map(|n| n.name.clone()).collect(),
            rasterized_candidate_cells: self.rasterized_candidate_cells,
            ..RouteReport::default()
        };
        let mut total_expanded = 0;
        for attempt in 0..4 {
            self.occupied.clear();
            self.occupied_by.clear();
            for route in &self.board.routes {
                self.commit(route);
            }
            for route in &accepted {
                self.commit(route);
            }
            let mut attempt_nets: Vec<_> = nets
                .iter()
                .copied()
                .filter(|net| pending.contains(&net.id))
                .collect();
            attempt_nets.sort_by_key(|net| {
                (
                    !previously_failed.contains(&net.id),
                    std::cmp::Reverse(net.priority),
                    std::cmp::Reverse(net.terminals.len()),
                    std::cmp::Reverse(net_span(net)),
                )
            });
            let mut blockers = HashSet::new();
            let mut failed_ids = HashSet::new();
            for net in attempt_nets {
                match self.route_net(net) {
                    Ok((route, expanded)) => {
                        total_expanded += expanded;
                        self.commit(&route);
                        accepted.push(route);
                    }
                    Err(failure) => {
                        total_expanded += failure.expanded;
                        blockers.extend(failure.blockers);
                        failed_ids.insert(net.id);
                    }
                }
            }
            let mut routes = self.board.routes.clone();
            routes.extend(accepted.iter().cloned());
            let mut report = RouteReport {
                preserved: preserved.clone(),
                routed: nets
                    .iter()
                    .filter(|net| accepted.iter().any(|route| route.net_id == net.id))
                    .map(|net| net.name.clone())
                    .collect(),
                rerouted: nets
                    .iter()
                    .filter(|net| ripped_ids.contains(&net.id))
                    .map(|net| net.name.clone())
                    .collect(),
                unrouted: nets
                    .iter()
                    .filter(|net| !accepted.iter().any(|route| route.net_id == net.id))
                    .map(|net| net.name.clone())
                    .collect(),
                ripup_events,
                ..RouteReport::default()
            };
            if report.unrouted.len() < best_report.unrouted.len() {
                best_routes = routes.clone();
                best_report = report.clone();
            }
            if report.unrouted.is_empty() {
                report.expanded_states = total_expanded;
                report.rasterized_candidate_cells = self.rasterized_candidate_cells;
                report.reroute_passes = attempt + 1;
                return (routes, report);
            }
            let rip_ids: HashSet<u32> = blockers
                .into_iter()
                .filter(|id| accepted.iter().any(|route| route.net_id == *id))
                .collect();
            if rip_ids.is_empty() {
                best_report.expanded_states = total_expanded;
                best_report.rasterized_candidate_cells = self.rasterized_candidate_cells;
                best_report.reroute_passes = attempt + 1;
                best_report.rerouted = nets
                    .iter()
                    .filter(|net| ripped_ids.contains(&net.id))
                    .map(|net| net.name.clone())
                    .collect();
                best_report.ripup_events = ripup_events;
                return (best_routes, best_report);
            }
            for (&cell, owner) in &self.occupied_by {
                if !rip_ids.contains(owner) {
                    continue;
                }
                let value = self.congestion.entry(cell).or_default();
                *value = value.saturating_add(8);
            }
            accepted.retain(|route| !rip_ids.contains(&route.net_id));
            ripup_events += rip_ids.len();
            ripped_ids.extend(rip_ids.iter().copied());
            previously_failed = failed_ids.clone();
            pending = failed_ids;
            pending.extend(rip_ids);
        }
        best_report.expanded_states = total_expanded;
        best_report.rasterized_candidate_cells = self.rasterized_candidate_cells;
        best_report.reroute_passes = 4;
        best_report.rerouted = nets
            .iter()
            .filter(|net| ripped_ids.contains(&net.id))
            .map(|net| net.name.clone())
            .collect();
        best_report.ripup_events = ripup_events;
        (best_routes, best_report)
    }

    fn route_net(&self, net: &Net) -> Result<(Route, usize), RouteFailure> {
        if net.terminals.len() < 2 {
            return Ok((
                Route {
                    net_id: net.id,
                    segments: vec![],
                    arcs: vec![],
                    vias: vec![],
                    teardrops: vec![],
                    zones: vec![],
                },
                0,
            ));
        }
        let mut route = Route {
            net_id: net.id,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        };
        let rules = self.board.rules_for_net(net.id);
        let mut expanded = 0;
        let root_index = steiner_root_index(net, &rules);
        let root = &net.terminals[root_index];
        let mut tree: HashSet<(i32, i32, u8)> = self
            .terminal_nodes(net.id, root, &rules)
            .into_iter()
            .map(|node| (node.x, node.y, node.layer))
            .collect();
        if tree.is_empty() {
            return Err(RouteFailure {
                expanded: 0,
                blockers: HashSet::new(),
            });
        }
        let mut remaining: Vec<usize> = (0..net.terminals.len())
            .filter(|index| *index != root_index)
            .collect();
        let mut root_access_added = false;
        while !remaining.is_empty() {
            let mut best: Option<(u64, Nm, Nm, usize, Vec<Node>)> = None;
            let mut search_blockers = HashSet::new();
            for &terminal_index in &remaining {
                let (path, count, cost) =
                    match self.astar_to_tree(net.id, &net.terminals[terminal_index], &tree, &rules)
                    {
                        Ok(result) => result,
                        Err(failure) => {
                            expanded += failure.expanded;
                            search_blockers.extend(failure.blockers);
                            continue;
                        }
                    };
                expanded += count;
                let terminal = &net.terminals[terminal_index];
                let candidate = (
                    cost,
                    terminal.position.x_nm,
                    terminal.position.y_nm,
                    terminal_index,
                    path,
                );
                if best.as_ref().is_none_or(|current| {
                    (candidate.0, candidate.1, candidate.2, candidate.3)
                        < (current.0, current.1, current.2, current.3)
                }) {
                    best = Some(candidate);
                }
            }
            let Some((_, _, _, terminal_index, nodes)) = best else {
                return Err(RouteFailure {
                    expanded,
                    blockers: search_blockers,
                });
            };
            let terminal = &net.terminals[terminal_index];
            append_terminal_access(&mut route, terminal.position, nodes[0], &rules, true);
            append_path(&mut route, &nodes, &rules, self.board);
            if !root_access_added {
                append_terminal_access(
                    &mut route,
                    root.position,
                    *nodes.last().unwrap(),
                    &rules,
                    false,
                );
                root_access_added = true;
            }
            tree.extend(nodes.iter().map(|node| (node.x, node.y, node.layer)));
            tree.extend(
                self.terminal_nodes(net.id, terminal, &rules)
                    .into_iter()
                    .map(|node| (node.x, node.y, node.layer)),
            );
            remaining.retain(|index| *index != terminal_index);
        }
        Ok((route, expanded))
    }

    fn terminal_nodes(&self, net_id: u32, terminal: &Terminal, rules: &Rules) -> Vec<Node> {
        let allowed_layers = self.board.layers_for_net(net_id);
        let x = nearest_grid(terminal.position.x_nm, rules.grid_nm) as i32;
        let y = nearest_grid(terminal.position.y_nm, rules.grid_nm) as i32;
        terminal
            .layers
            .iter()
            .copied()
            .filter(|layer| allowed_layers.is_none_or(|allowed| allowed.contains(layer)))
            .map(|layer| Node {
                x,
                y,
                layer: layer_index(layer),
                dir: 8,
            })
            .collect()
    }

    fn astar_to_tree(
        &self,
        net_id: u32,
        start: &Terminal,
        goals: &HashSet<(i32, i32, u8)>,
        rules: &Rules,
    ) -> Result<(Vec<Node>, usize, u64), SearchFailure> {
        const DIRS: [(i32, i32); 8] = [
            (1, 0),
            (1, 1),
            (0, 1),
            (-1, 1),
            (-1, 0),
            (-1, -1),
            (0, -1),
            (1, -1),
        ];
        let g = rules.grid_nm;
        let sx = nearest_grid(start.position.x_nm, g) as i32;
        let sy = nearest_grid(start.position.y_nm, g) as i32;
        let track_radius = rules.track_width_nm / 2;
        let min_track_cell = ((track_radius + g - 1) / g) as i32;
        let max_x = ((self.board.width_nm - track_radius) / g) as i32;
        let max_y = ((self.board.height_nm - track_radius) / g) as i32;
        let allowed_layers = self.board.layers_for_net(net_id);
        let mut open = BinaryHeap::new();
        let mut costs = HashMap::new();
        let mut prev = HashMap::new();
        let mut blockers = HashSet::new();
        for n in self.terminal_nodes(net_id, start, rules) {
            costs.insert(n, 0u64);
            open.push(QueueItem {
                score: heuristic_to_tree(sx, sy, n.layer, goals),
                cost: 0,
                node: n,
            });
        }
        let mut expanded = 0;
        while let Some(item) = open.pop() {
            if item.cost != *costs.get(&item.node).unwrap_or(&u64::MAX) {
                continue;
            }
            expanded += 1;
            if goals.contains(&(item.node.x, item.node.y, item.node.layer)) {
                let mut path = vec![item.node];
                let mut cur = item.node;
                while let Some(p) = prev.get(&cur) {
                    cur = *p;
                    path.push(cur);
                }
                path.reverse();
                return Ok((path, expanded, item.cost));
            }
            for (dir, (dx, dy)) in DIRS.iter().enumerate() {
                let nx = item.node.x + dx;
                let ny = item.node.y + dy;
                if nx < min_track_cell || ny < min_track_cell || nx > max_x || ny > max_y {
                    continue;
                }
                let cell = (nx, ny, item.node.layer);
                let endpoint = goals.contains(&cell) || (nx == sx && ny == sy);
                if !endpoint
                    && (self.blocked.contains(&cell) || self.foreign_obstacle(cell, net_id))
                {
                    continue;
                }
                if !endpoint && self.occupied.contains(&cell) {
                    if let Some(owner) = self.occupied_by.get(&cell) {
                        blockers.insert(*owner);
                    }
                    continue;
                }
                if *dx != 0
                    && *dy != 0
                    && [
                        (item.node.x + dx, item.node.y, item.node.layer),
                        (item.node.x, item.node.y + dy, item.node.layer),
                    ]
                    .iter()
                    .any(|cell| self.blocked.contains(cell) || self.foreign_obstacle(*cell, net_id))
                {
                    continue;
                }
                let step = if *dx != 0 && *dy != 0 { 14 } else { 10 };
                let bend = if item.node.dir < 8 && item.node.dir != dir as u8 {
                    rules.bend_cost as u64
                } else {
                    0
                };
                let proximity = self.proximity(nx, ny, item.node.layer) as u64;
                self.relax(
                    item.node,
                    Node {
                        x: nx,
                        y: ny,
                        layer: item.node.layer,
                        dir: dir as u8,
                    },
                    item.cost + step + bend + proximity,
                    goals,
                    &mut costs,
                    &mut prev,
                    &mut open,
                );
            }
            let via_radius = rules.via_diameter_nm / 2;
            let via_inside_board = item.node.x as Nm * g >= via_radius
                && item.node.y as Nm * g >= via_radius
                && item.node.x as Nm * g + via_radius <= self.board.width_nm
                && item.node.y as Nm * g + via_radius <= self.board.height_nm;
            if via_inside_board {
                for other_layer in &self.board.copper_layers {
                    let other = layer_index(*other_layer);
                    if other == item.node.layer
                        || allowed_layers.is_some_and(|allowed| !allowed.contains(other_layer))
                    {
                        continue;
                    }
                    let (kind, start_layer, end_layer, cost_multiplier) = self
                        .board
                        .via_for_transition(index_layer(item.node.layer), *other_layer);
                    let candidate = Via {
                        position: Point {
                            x_nm: item.node.x as Nm * g,
                            y_nm: item.node.y as Nm * g,
                        },
                        diameter_nm: rules.via_diameter_nm,
                        drill_nm: rules.via_drill_nm,
                        kind,
                        start_layer,
                        end_layer,
                    };
                    let cells: Vec<_> = self
                        .board
                        .copper_layers
                        .iter()
                        .filter(|layer| candidate.spans_layer(**layer))
                        .map(|layer| (item.node.x, item.node.y, layer_index(*layer)))
                        .collect();
                    if cells.iter().any(|cell| {
                        self.blocked.contains(cell) || self.foreign_obstacle(*cell, net_id)
                    }) {
                        continue;
                    }
                    let owners: HashSet<_> = cells
                        .iter()
                        .filter_map(|cell| self.occupied_by.get(cell).copied())
                        .collect();
                    if !owners.is_empty() {
                        blockers.extend(owners);
                    } else {
                        let n = Node {
                            x: item.node.x,
                            y: item.node.y,
                            layer: other,
                            dir: item.node.dir,
                        };
                        self.relax(
                            item.node,
                            n,
                            item.cost + rules.via_cost as u64 * cost_multiplier,
                            goals,
                            &mut costs,
                            &mut prev,
                            &mut open,
                        );
                    }
                }
            }
        }
        Err(SearchFailure { expanded, blockers })
    }

    fn foreign_obstacle(&self, cell: (i32, i32, u8), net_id: u32) -> bool {
        self.owned.get(&cell).is_some_and(|owner| *owner != net_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn relax(
        &self,
        from: Node,
        to: Node,
        cost: u64,
        goals: &HashSet<(i32, i32, u8)>,
        costs: &mut HashMap<Node, u64>,
        prev: &mut HashMap<Node, Node>,
        open: &mut BinaryHeap<QueueItem>,
    ) {
        if cost < *costs.get(&to).unwrap_or(&u64::MAX) {
            costs.insert(to, cost);
            prev.insert(to, from);
            open.push(QueueItem {
                score: cost + heuristic_to_tree(to.x, to.y, to.layer, goals),
                cost,
                node: to,
            });
        }
    }
    fn proximity(&self, x: i32, y: i32, l: u8) -> u16 {
        let mut p = *self.congestion.get(&(x, y, l)).unwrap_or(&0);
        for dy in -1..=1 {
            for dx in -1..=1 {
                if self.occupied.contains(&(x + dx, y + dy, l)) {
                    p = p.saturating_add(3)
                }
            }
        }
        p
    }
    fn commit(&mut self, route: &Route) {
        let g = self.board.rules.grid_nm;
        let (maximum_diameter, maximum_clearance) = self.board.maximum_routing_envelope();
        for s in &route.segments {
            let clearance_radius =
                (s.width_nm / 2 + maximum_diameter / 2 + maximum_clearance + g - 1) / g;
            for (x, y) in raster_line_cells(
                s.start.x_nm / g,
                s.start.y_nm / g,
                s.end.x_nm / g,
                s.end.y_nm / g,
            ) {
                for oy in -clearance_radius..=clearance_radius {
                    for ox in -clearance_radius..=clearance_radius {
                        if ox * ox + oy * oy <= clearance_radius * clearance_radius {
                            let cell = ((x + ox) as i32, (y + oy) as i32, layer_index(s.layer));
                            self.occupied.insert(cell);
                            self.occupied_by.insert(cell, route.net_id);
                        }
                    }
                }
            }
        }
        for via in &route.vias {
            let clearance_radius =
                (via.diameter_nm / 2 + maximum_diameter / 2 + maximum_clearance + g - 1) / g;
            let center_x = via.position.x_nm / g;
            let center_y = via.position.y_nm / g;
            for layer in self
                .board
                .copper_layers
                .iter()
                .filter(|layer| via.spans_layer(**layer))
            {
                for offset_y in -clearance_radius..=clearance_radius {
                    for offset_x in -clearance_radius..=clearance_radius {
                        if offset_x * offset_x + offset_y * offset_y
                            > clearance_radius * clearance_radius
                        {
                            continue;
                        }
                        let cell = (
                            (center_x + offset_x) as i32,
                            (center_y + offset_y) as i32,
                            layer_index(*layer),
                        );
                        self.occupied.insert(cell);
                        self.occupied_by.insert(cell, route.net_id);
                    }
                }
            }
        }
        for &(x, y, l) in &self.occupied {
            for dy in -2..=2 {
                for dx in -2..=2 {
                    *self.congestion.entry((x + dx, y + dy, l)).or_default() += 1;
                }
            }
        }
    }
}

fn raster_line_cells(mut x: Nm, mut y: Nm, end_x: Nm, end_y: Nm) -> Vec<(Nm, Nm)> {
    let dx = (end_x - x).abs();
    let step_x = (end_x - x).signum();
    let dy = -(end_y - y).abs();
    let step_y = (end_y - y).signum();
    let mut error = dx + dy;
    let mut cells = Vec::new();
    loop {
        cells.push((x, y));
        if x == end_x && y == end_y {
            break;
        }
        let twice_error = 2 * error;
        if twice_error >= dy {
            error += dy;
            x += step_x;
        }
        if twice_error <= dx {
            error += dx;
            y += step_y;
        }
    }
    cells
}

fn polygon_bounds(polygon: &[Point]) -> Option<(Nm, Nm, Nm, Nm)> {
    Some((
        polygon.iter().map(|point| point.x_nm).min()?,
        polygon.iter().map(|point| point.x_nm).max()?,
        polygon.iter().map(|point| point.y_nm).min()?,
        polygon.iter().map(|point| point.y_nm).max()?,
    ))
}

fn cell_window(
    min_x_nm: Nm,
    max_x_nm: Nm,
    min_y_nm: Nm,
    max_y_nm: Nm,
    grid_nm: Nm,
    board_width_nm: Nm,
    board_height_nm: Nm,
) -> (i32, i32, i32, i32) {
    (
        (min_x_nm.max(0) / grid_nm) as i32,
        (max_x_nm.min(board_width_nm) / grid_nm) as i32,
        (min_y_nm.max(0) / grid_nm) as i32,
        (max_y_nm.min(board_height_nm) / grid_nm) as i32,
    )
}

fn heuristic(x: i32, y: i32, gx: i32, gy: i32) -> u64 {
    let dx = (x - gx).unsigned_abs() as u64;
    let dy = (y - gy).unsigned_abs() as u64;
    14 * dx.min(dy) + 10 * (dx.max(dy) - dx.min(dy))
}
fn heuristic_to_tree(x: i32, y: i32, _layer: u8, goals: &HashSet<(i32, i32, u8)>) -> u64 {
    goals
        .iter()
        .map(|(goal_x, goal_y, _)| heuristic(x, y, *goal_x, *goal_y))
        .min()
        .unwrap_or(0)
}
fn layer_index(l: Layer) -> u8 {
    l.index()
}
fn index_layer(l: u8) -> Layer {
    Layer::from_index(l).expect("router only stores supported copper layers")
}
fn net_span(n: &Net) -> Nm {
    n.terminals
        .windows(2)
        .map(|p| {
            (p[0].position.x_nm - p[1].position.x_nm).abs()
                + (p[0].position.y_nm - p[1].position.y_nm).abs()
        })
        .sum()
}
fn steiner_root_index(net: &Net, rules: &Rules) -> usize {
    let grid_positions: Vec<(i32, i32)> = net
        .terminals
        .iter()
        .map(|terminal| {
            (
                nearest_grid(terminal.position.x_nm, rules.grid_nm) as i32,
                nearest_grid(terminal.position.y_nm, rules.grid_nm) as i32,
            )
        })
        .collect();
    grid_positions
        .iter()
        .enumerate()
        .min_by_key(|(index, (x, y))| {
            (
                grid_positions
                    .iter()
                    .map(|(other_x, other_y)| heuristic(*x, *y, *other_x, *other_y))
                    .sum::<u64>(),
                net.terminals[*index].position.x_nm,
                net.terminals[*index].position.y_nm,
                *index,
            )
        })
        .map(|(index, _)| index)
        .unwrap_or(0)
}
fn append_path(route: &mut Route, nodes: &[Node], rules: &Rules, board: &Board) {
    if nodes.len() < 2 {
        return;
    }
    let g = rules.grid_nm;
    let mut start = nodes[0];
    let mut last = nodes[0];
    for pair in nodes.windows(2) {
        if pair[0].layer != pair[1].layer {
            if start != pair[0] {
                push_segment(route, start, pair[0], g, rules.track_width_nm);
            }
            let (kind, start_layer, end_layer, _) =
                board.via_for_transition(index_layer(pair[0].layer), index_layer(pair[1].layer));
            route.vias.push(Via {
                position: Point {
                    x_nm: pair[0].x as Nm * g,
                    y_nm: pair[0].y as Nm * g,
                },
                diameter_nm: rules.via_diameter_nm,
                drill_nm: rules.via_drill_nm,
                kind,
                start_layer,
                end_layer,
            });
            start = pair[1];
            last = pair[1];
            continue;
        }
        let old_dir = (last.x - start.x).signum();
        let old_dy = (last.y - start.y).signum();
        let new_dir = (pair[1].x - pair[0].x).signum();
        let new_dy = (pair[1].y - pair[0].y).signum();
        if last != start && (old_dir != new_dir || old_dy != new_dy) {
            push_segment(route, start, pair[0], g, rules.track_width_nm);
            start = pair[0];
        }
        last = pair[1];
    }
    if start != *nodes.last().unwrap() {
        push_segment(
            route,
            start,
            *nodes.last().unwrap(),
            g,
            rules.track_width_nm,
        )
    }
}
fn append_terminal_access(
    route: &mut Route,
    terminal: Point,
    node: Node,
    rules: &Rules,
    terminal_first: bool,
) {
    let grid = Point {
        x_nm: node.x as Nm * rules.grid_nm,
        y_nm: node.y as Nm * rules.grid_nm,
    };
    if terminal == grid {
        return;
    }
    let corner = Point {
        x_nm: grid.x_nm,
        y_nm: terminal.y_nm,
    };
    let points = if terminal_first {
        [terminal, corner, grid]
    } else {
        [grid, corner, terminal]
    };
    for pair in points.windows(2) {
        if pair[0] != pair[1] {
            route.segments.push(Segment {
                start: pair[0],
                end: pair[1],
                layer: index_layer(node.layer),
                width_nm: rules.track_width_nm,
            });
        }
    }
}
fn nearest_grid(value: Nm, grid: Nm) -> Nm {
    (value + grid / 2) / grid
}
fn push_segment(route: &mut Route, a: Node, b: Node, g: Nm, w: Nm) {
    route.segments.push(Segment {
        start: Point {
            x_nm: a.x as Nm * g,
            y_nm: a.y as Nm * g,
        },
        end: Point {
            x_nm: b.x as Nm * g,
            y_nm: b.y as Nm * g,
        },
        layer: index_layer(a.layer),
        width_nm: w,
    });
}

pub fn route_board(board: &Board) -> Result<(Board, RouteReport), String> {
    let (routes, mut report) = Router::new(board)?.route_all();
    let mut out = board.clone();
    out.routes = routes;
    tune_route_lengths(&mut out)?;
    couple_differential_pairs(&mut out, &mut report);
    Ok((out, report))
}

fn couple_differential_pairs(board: &mut Board, report: &mut RouteReport) {
    for pair in board.differential_pairs.clone() {
        let (Some(positive_net), Some(negative_net)) = (
            board.nets.iter().find(|net| net.id == pair.positive_net_id),
            board.nets.iter().find(|net| net.id == pair.negative_net_id),
        ) else {
            continue;
        };
        if positive_net.terminals.len() != negative_net.terminals.len()
            || positive_net.terminals.is_empty()
        {
            continue;
        }
        let offset = Point {
            x_nm: negative_net.terminals[0].position.x_nm - positive_net.terminals[0].position.x_nm,
            y_nm: negative_net.terminals[0].position.y_nm - positive_net.terminals[0].position.y_nm,
        };
        if !positive_net
            .terminals
            .iter()
            .zip(&negative_net.terminals)
            .all(|(positive, negative)| {
                translate_point(positive.position, offset) == negative.position
                    && positive.layers == negative.layers
            })
        {
            continue;
        }
        let (Some(positive_index), Some(negative_index)) = (
            board
                .routes
                .iter()
                .position(|route| route.net_id == pair.positive_net_id),
            board
                .routes
                .iter()
                .position(|route| route.net_id == pair.negative_net_id),
        ) else {
            continue;
        };
        let mut translated = translate_route(&board.routes[positive_index], offset);
        translated.net_id = pair.negative_net_id;
        let original = std::mem::replace(&mut board.routes[negative_index], translated);
        let invalid = checking::check_board(board)
            .violations
            .iter()
            .any(|violation| {
                violation.net_ids.contains(&pair.positive_net_id)
                    || violation.net_ids.contains(&pair.negative_net_id)
            });
        if invalid {
            board.routes[negative_index] = original;
        } else {
            report.coupled_differential_pairs.push(pair.name);
        }
    }
}

fn translate_route(route: &Route, offset: Point) -> Route {
    let mut translated = route.clone();
    for segment in &mut translated.segments {
        segment.start = translate_point(segment.start, offset);
        segment.end = translate_point(segment.end, offset);
    }
    for arc in &mut translated.arcs {
        arc.start = translate_point(arc.start, offset);
        arc.mid = translate_point(arc.mid, offset);
        arc.end = translate_point(arc.end, offset);
    }
    for via in &mut translated.vias {
        via.position = translate_point(via.position, offset);
    }
    for teardrop in &mut translated.teardrops {
        for point in &mut teardrop.polygon {
            *point = translate_point(*point, offset);
        }
    }
    for zone in &mut translated.zones {
        for point in &mut zone.polygon {
            *point = translate_point(*point, offset);
        }
    }
    translated
}

fn translate_point(point: Point, offset: Point) -> Point {
    Point {
        x_nm: point.x_nm + offset.x_nm,
        y_nm: point.y_nm + offset.y_nm,
    }
}

pub fn tune_route_lengths(board: &mut Board) -> Result<(), String> {
    for route_index in 0..board.routes.len() {
        let net_id = board.routes[route_index].net_id;
        let (minimum, maximum) = board.length_limits_for_net(net_id);
        let Some(minimum) = minimum else { continue };
        let current = route_length_nm(&board.routes[route_index]);
        if current >= minimum {
            continue;
        }
        let grid = board.rules_for_net(net_id).grid_nm;
        let amplitude = ((minimum - current + 2 * grid - 1) / (2 * grid)) * grid;
        let original = board.routes[route_index].clone();
        let mut tuned = None;
        for segment_index in (0..original.segments.len()).rev() {
            let segment = &original.segments[segment_index];
            let dx = segment.end.x_nm - segment.start.x_nm;
            let dy = segment.end.y_nm - segment.start.y_nm;
            if dx != 0 && dy != 0 {
                continue;
            }
            let span = dx.abs().max(dy.abs());
            if span < 4 * grid {
                continue;
            }
            for direction in [1, -1] {
                let mut candidate = original.clone();
                let one = Point {
                    x_nm: segment.start.x_nm + dx / 3,
                    y_nm: segment.start.y_nm + dy / 3,
                };
                let two = Point {
                    x_nm: segment.start.x_nm + 2 * dx / 3,
                    y_nm: segment.start.y_nm + 2 * dy / 3,
                };
                let offset = if dx == 0 {
                    Point {
                        x_nm: direction * amplitude,
                        y_nm: 0,
                    }
                } else {
                    Point {
                        x_nm: 0,
                        y_nm: direction * amplitude,
                    }
                };
                let points = [
                    segment.start,
                    one,
                    Point {
                        x_nm: one.x_nm + offset.x_nm,
                        y_nm: one.y_nm + offset.y_nm,
                    },
                    Point {
                        x_nm: two.x_nm + offset.x_nm,
                        y_nm: two.y_nm + offset.y_nm,
                    },
                    two,
                    segment.end,
                ];
                let replacement = points
                    .windows(2)
                    .map(|points| Segment {
                        start: points[0],
                        end: points[1],
                        layer: segment.layer,
                        width_nm: segment.width_nm,
                    })
                    .collect::<Vec<_>>();
                candidate
                    .segments
                    .splice(segment_index..=segment_index, replacement);
                board.routes[route_index] = candidate.clone();
                let check = crate::checking::check_board(board);
                if check.violations.iter().all(|violation| {
                    violation.rule == "trace_length" && !violation.net_ids.contains(&net_id)
                }) && maximum.is_none_or(|limit| route_length_nm(&candidate) <= limit)
                {
                    tuned = Some(candidate);
                    break;
                }
            }
            if tuned.is_some() {
                break;
            }
        }
        board.routes[route_index] = tuned.ok_or_else(|| {
            format!("unable to satisfy minimum length for net {net_id} with a legal meander")
        })?;
    }
    Ok(())
}

pub fn route_length_nm(route: &Route) -> Nm {
    route
        .segments
        .iter()
        .map(|segment| {
            let dx = (segment.end.x_nm - segment.start.x_nm) as f64;
            let dy = (segment.end.y_nm - segment.start.y_nm) as f64;
            dx.hypot(dy).round() as Nm
        })
        .sum()
}

pub fn render_svg(board: &Board) -> String {
    let scale = 1_000_000.0;
    let w = board.width_nm as f64 / scale;
    let h = board.height_nm as f64 / scale;
    let outline = board
        .effective_outline()
        .iter()
        .map(|point| {
            format!(
                "{},{}",
                point.x_nm as f64 / scale,
                point.y_nm as f64 / scale
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut s = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}"><polygon points="{outline}" fill="#152019" stroke="#ccc" stroke-width=".2"/>"##
    );
    for cutout in &board.cutouts {
        let points = cutout
            .iter()
            .map(|point| {
                format!(
                    "{},{}",
                    point.x_nm as f64 / scale,
                    point.y_nm as f64 / scale
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        s.push_str(&format!(
            r##"<polygon points="{points}" fill="white" stroke="#ccc" stroke-width=".2"/>"##
        ));
    }
    for o in &board.obstacles {
        s.push_str(&format!(
            r##"<rect x="{}" y="{}" width="{}" height="{}" fill="#555"/>"##,
            o.min.x_nm as f64 / scale,
            o.min.y_nm as f64 / scale,
            (o.max.x_nm - o.min.x_nm) as f64 / scale,
            (o.max.y_nm - o.min.y_nm) as f64 / scale
        ));
    }
    for obstacle in &board.round_obstacles {
        s.push_str(&format!(
            r##"<circle cx="{}" cy="{}" r="{}" fill="#555"/>"##,
            obstacle.center.x_nm as f64 / scale,
            obstacle.center.y_nm as f64 / scale,
            obstacle.diameter_nm as f64 / scale / 2.0
        ));
    }
    for obstacle in &board.capsule_obstacles {
        s.push_str(&format!(
            r##"<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#555" stroke-width="{}" stroke-linecap="round"/>"##,
            obstacle.start.x_nm as f64 / scale,
            obstacle.start.y_nm as f64 / scale,
            obstacle.end.x_nm as f64 / scale,
            obstacle.end.y_nm as f64 / scale,
            obstacle.diameter_nm as f64 / scale
        ));
    }
    for obstacle in &board.polygon_obstacles {
        let points = obstacle
            .polygon
            .iter()
            .map(|point| {
                format!(
                    "{},{}",
                    point.x_nm as f64 / scale,
                    point.y_nm as f64 / scale
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        s.push_str(&format!(r##"<polygon points="{points}" fill="#555"/>"##));
    }
    for keepout in &board.keepouts {
        let points = keepout
            .polygon
            .iter()
            .map(|point| {
                format!(
                    "{},{}",
                    point.x_nm as f64 / scale,
                    point.y_nm as f64 / scale
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        s.push_str(&format!(
            r##"<polygon points="{points}" fill="#733" fill-opacity=".65"/>"##
        ));
    }
    for r in &board.routes {
        for x in &r.segments {
            let color = if x.layer == Layer::Front {
                "#e44"
            } else {
                "#48e"
            };
            s.push_str(&format!(r##"<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{color}" stroke-width="{}" stroke-linecap="round"/>"##,x.start.x_nm as f64/scale,x.start.y_nm as f64/scale,x.end.x_nm as f64/scale,x.end.y_nm as f64/scale,x.width_nm as f64/scale));
        }
        for v in &r.vias {
            s.push_str(&format!(
                r##"<circle cx="{}" cy="{}" r="{}" fill="#dc4" stroke="#111" stroke-width=".1"/>"##,
                v.position.x_nm as f64 / scale,
                v.position.y_nm as f64 / scale,
                v.diameter_nm as f64 / scale / 2.0
            ));
        }
    }
    s.push_str("</svg>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    fn board() -> Board {
        Board {
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            outline: vec![],
            cutouts: vec![],
            copper_layers: both_layers(),
            rules: Rules {
                grid_nm: 500_000,
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                bend_cost: 5,
                via_cost: 20,
            },
            obstacles: vec![Obstacle {
                min: Point {
                    x_nm: 4_000_000,
                    y_nm: 0,
                },
                max: Point {
                    x_nm: 6_000_000,
                    y_nm: 8_000_000,
                },
                layers: both_layers(),
                net_id: None,
            }],
            round_obstacles: vec![],
            capsule_obstacles: vec![],
            polygon_obstacles: vec![],
            keepouts: vec![],
            footprints: vec![],
            net_classes: HashMap::new(),
            differential_pairs: vec![],
            manufacturing_rules: None,
            via_strategy: ViaStrategy::ThroughOnly,
            nets: vec![Net {
                id: 1,
                name: "N1".into(),
                class: None,
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 1_000_000,
                            y_nm: 1_000_000,
                        },
                        layers: both_layers(),
                    },
                    Terminal {
                        position: Point {
                            x_nm: 9_000_000,
                            y_nm: 1_000_000,
                        },
                        layers: both_layers(),
                    },
                ],
            }],
            routes: vec![],
        }
    }

    #[test]
    fn spatial_window_clamps_to_the_board() {
        assert_eq!(
            cell_window(
                -1_000_000, 2_100_000, 8_000_000, 12_000_000, 500_000, 10_000_000, 10_000_000,
            ),
            (0, 4, 16, 20)
        );
    }

    #[test]
    fn automatic_via_strategy_classifies_stackup_transitions() {
        let mut board = board();
        board.copper_layers = vec![Layer::Front, Layer::Inner(1), Layer::Inner(2), Layer::Back];
        board.via_strategy = ViaStrategy::Auto;
        assert_eq!(
            board.via_for_transition(Layer::Front, Layer::Inner(1)).0,
            ViaKind::Micro
        );
        assert_eq!(
            board.via_for_transition(Layer::Front, Layer::Inner(2)).0,
            ViaKind::BlindBuried
        );
        assert_eq!(
            board.via_for_transition(Layer::Front, Layer::Back).0,
            ViaKind::Through
        );
    }

    #[test]
    fn inner_copper_layer_json_is_kicad_compatible() {
        assert_eq!(
            serde_json::to_string(&Layer::Inner(30)).unwrap(),
            r#""In30.Cu""#
        );
        assert_eq!(
            serde_json::from_str::<Layer>(r#""In1.Cu""#).unwrap(),
            Layer::Inner(1)
        );
        assert!(serde_json::from_str::<Layer>(r#""In31.Cu""#).is_err());
    }
    #[test]
    fn routes_around_obstacle() {
        let (b, r) = route_board(&board()).unwrap();
        assert!(r.unrouted.is_empty());
        assert!(!b.routes[0].segments.is_empty());
    }
    #[test]
    fn svg_is_produced() {
        let (b, _) = route_board(&board()).unwrap();
        assert!(render_svg(&b).contains("<line"));
    }

    #[test]
    fn separate_nets_keep_clearance() {
        let mut b = board();
        b.obstacles.clear();
        b.nets = vec![
            Net {
                id: 1,
                name: "A".into(),
                class: None,
                priority: 10,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 1_000_000,
                            y_nm: 4_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: Point {
                            x_nm: 9_000_000,
                            y_nm: 4_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                ],
            },
            Net {
                id: 2,
                name: "B".into(),
                class: None,
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 1_000_000,
                            y_nm: 4_500_000,
                        },
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: Point {
                            x_nm: 9_000_000,
                            y_nm: 4_500_000,
                        },
                        layers: vec![Layer::Front],
                    },
                ],
            },
        ];
        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert_ne!(
            routed.routes[0].segments, routed.routes[1].segments,
            "second net must not overlap the first"
        );
    }

    #[test]
    fn routes_ten_signal_nets() {
        let mut b = board();
        b.width_nm = 20_000_000;
        b.height_nm = 20_000_000;
        b.obstacles.clear();
        b.nets = (0..10)
            .map(|i| {
                let y = 1_000_000 + i * 1_500_000;
                Net {
                    id: i as u32 + 1,
                    name: format!("N{}", i + 1),
                    class: None,
                    priority: 0,
                    terminals: vec![
                        Terminal {
                            position: Point {
                                x_nm: 1_000_000,
                                y_nm: y,
                            },
                            layers: vec![Layer::Front],
                        },
                        Terminal {
                            position: Point {
                                x_nm: 19_000_000,
                                y_nm: y,
                            },
                            layers: vec![Layer::Front],
                        },
                    ],
                }
            })
            .collect();
        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty(), "{:?}", report.unrouted);
        assert!(
            report.expanded_states < 100_000,
            "parallel-net search budget regressed: {} states",
            report.expanded_states
        );
        assert_eq!(routed.routes.len(), 10);
        let check = crate::checking::check_board(&routed);
        assert!(check.is_clean(), "{:?}", check.violations);
    }

    #[test]
    fn foreign_net_pad_blocks_but_own_pad_is_enterable() {
        let mut b = board();
        b.obstacles = vec![
            Obstacle {
                min: Point {
                    x_nm: 500_000,
                    y_nm: 500_000,
                },
                max: Point {
                    x_nm: 1_500_000,
                    y_nm: 1_500_000,
                },
                layers: vec![Layer::Front],
                net_id: Some(1),
            },
            Obstacle {
                min: Point {
                    x_nm: 4_000_000,
                    y_nm: 500_000,
                },
                max: Point {
                    x_nm: 6_000_000,
                    y_nm: 1_500_000,
                },
                layers: vec![Layer::Front],
                net_id: Some(2),
            },
        ];
        b.nets[0].terminals[0].layers = vec![Layer::Front];
        b.nets[0].terminals[1].layers = vec![Layer::Front];
        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(
            routed.routes[0]
                .segments
                .iter()
                .any(|s| s.start.y_nm != 1_000_000 || s.end.y_nm != 1_000_000),
            "route must detour around the foreign-net pad"
        );
        assert!(crate::checking::check_board(&routed).is_clean());
    }

    #[test]
    fn connects_off_grid_terminals_exactly() {
        let mut b = board();
        b.obstacles.clear();
        b.nets[0].terminals[0].position = Point {
            x_nm: 1_123_000,
            y_nm: 1_234_000,
        };
        b.nets[0].terminals[1].position = Point {
            x_nm: 8_876_000,
            y_nm: 7_654_000,
        };
        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(crate::checking::check_board(&routed).is_clean());
    }

    #[test]
    fn changes_layers_with_through_vias_when_front_is_blocked() {
        let mut b = board();
        b.obstacles = vec![Obstacle {
            min: Point {
                x_nm: 4_000_000,
                y_nm: 0,
            },
            max: Point {
                x_nm: 6_000_000,
                y_nm: 10_000_000,
            },
            layers: vec![Layer::Front],
            net_id: None,
        }];
        b.nets[0].terminals[0].layers = vec![Layer::Front];
        b.nets[0].terminals[1].layers = vec![Layer::Front];
        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert_eq!(routed.routes[0].vias.len(), 2);
        assert!(
            routed.routes[0]
                .segments
                .iter()
                .any(|segment| segment.layer == Layer::Back)
        );
        assert!(crate::checking::check_board(&routed).is_clean());
    }

    #[test]
    fn routes_through_an_inner_copper_layer() {
        let mut b = board();
        b.copper_layers = vec![Layer::Front, Layer::Inner(1), Layer::Back];
        b.via_strategy = ViaStrategy::Auto;
        b.obstacles = vec![Obstacle {
            min: Point {
                x_nm: 4_000_000,
                y_nm: 0,
            },
            max: Point {
                x_nm: 6_000_000,
                y_nm: 10_000_000,
            },
            layers: vec![Layer::Front, Layer::Back],
            net_id: None,
        }];
        b.nets[0].terminals[0].layers = vec![Layer::Front];
        b.nets[0].terminals[1].layers = vec![Layer::Front];

        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(
            routed.routes[0]
                .segments
                .iter()
                .any(|segment| segment.layer == Layer::Inner(1))
        );
        assert!(routed.routes[0].vias.len() >= 2);
        assert!(
            routed.routes[0]
                .vias
                .iter()
                .all(|via| via.kind == ViaKind::Micro)
        );
        assert!(checking::check_board(&routed).is_clean());
    }

    #[test]
    fn stops_without_futile_reroutes_when_no_route_is_blocking() {
        let mut b = board();
        b.obstacles = vec![Obstacle {
            min: Point {
                x_nm: 4_000_000,
                y_nm: 0,
            },
            max: Point {
                x_nm: 6_000_000,
                y_nm: 10_000_000,
            },
            layers: both_layers(),
            net_id: None,
        }];
        let (routed, report) = route_board(&b).unwrap();
        assert!(routed.routes.is_empty());
        assert_eq!(report.unrouted, vec!["N1"]);
        assert_eq!(report.reroute_passes, 1);
        assert_eq!(report.ripup_events, 0);
    }

    #[test]
    fn applies_net_class_dimensions_and_layer_constraint() {
        let mut b = board();
        b.obstacles.clear();
        b.nets[0].class = Some("Power".into());
        b.net_classes.insert(
            "Power".into(),
            NetClassRules {
                track_width_nm: 800_000,
                clearance_nm: 400_000,
                via_diameter_nm: 1_000_000,
                via_drill_nm: 500_000,
                layers: Some(vec![Layer::Back]),
                differential_width_nm: None,
                differential_gap_nm: None,
                minimum_length_nm: None,
                maximum_length_nm: None,
            },
        );
        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(
            routed.routes[0]
                .segments
                .iter()
                .all(|segment| segment.width_nm == 800_000 && segment.layer == Layer::Back)
        );
        assert!(crate::checking::check_board(&routed).is_clean());
    }

    #[test]
    fn preserves_existing_routes_and_only_routes_missing_nets() {
        let mut b = board();
        b.obstacles.clear();
        let existing = Route {
            net_id: 1,
            arcs: vec![],
            teardrops: vec![],
            zones: vec![],
            segments: vec![Segment {
                start: b.nets[0].terminals[0].position,
                end: b.nets[0].terminals[1].position,
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            vias: vec![],
        };
        b.routes.push(existing.clone());
        b.nets.push(Net {
            id: 2,
            name: "N2".into(),
            class: None,
            priority: 0,
            terminals: vec![
                Terminal {
                    position: Point {
                        x_nm: 1_000_000,
                        y_nm: 2_000_000,
                    },
                    layers: vec![Layer::Front],
                },
                Terminal {
                    position: Point {
                        x_nm: 9_000_000,
                        y_nm: 2_000_000,
                    },
                    layers: vec![Layer::Front],
                },
            ],
        });

        let (routed, report) = route_board(&b).unwrap();
        assert_eq!(routed.routes.len(), 2);
        assert_eq!(routed.routes[0], existing);
        assert_eq!(report.preserved, vec!["N1"]);
        assert_eq!(report.routed, vec!["N2"]);
        assert!(report.unrouted.is_empty());
        assert!(crate::checking::check_board(&routed).is_clean());
    }

    #[test]
    fn routing_an_already_routed_board_is_idempotent() {
        let (routed, initial_report) = route_board(&board()).unwrap();
        assert_eq!(initial_report.routed, vec!["N1"]);

        let (rerouted, report) = route_board(&routed).unwrap();
        assert_eq!(rerouted.routes, routed.routes);
        assert_eq!(report.preserved, vec!["N1"]);
        assert!(report.routed.is_empty());
        assert!(report.unrouted.is_empty());
        assert_eq!(report.expanded_states, 0);
    }

    #[test]
    fn rejects_multiple_existing_routes_for_one_net() {
        let mut b = board();
        b.routes = vec![
            Route {
                net_id: 1,
                arcs: vec![],
                teardrops: vec![],
                zones: vec![],
                segments: vec![],
                vias: vec![],
            },
            Route {
                net_id: 1,
                arcs: vec![],
                teardrops: vec![],
                zones: vec![],
                segments: vec![],
                vias: vec![],
            },
        ];

        assert_eq!(
            route_board(&b).unwrap_err(),
            "net 1 has more than one existing route"
        );
    }

    #[test]
    fn multi_terminal_net_branches_into_the_existing_tree() {
        let mut b = board();
        b.obstacles.clear();
        b.nets[0].terminals = [
            (5_000_000, 5_000_000),
            (1_000_000, 5_000_000),
            (9_000_000, 5_000_000),
            (5_000_000, 1_000_000),
            (5_000_000, 9_000_000),
        ]
        .into_iter()
        .map(|(x_nm, y_nm)| Terminal {
            position: Point { x_nm, y_nm },
            layers: vec![Layer::Front],
        })
        .collect();

        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(crate::checking::check_board(&routed).is_clean());

        let route_cost: u64 = routed.routes[0]
            .segments
            .iter()
            .map(|segment| {
                let dx = ((segment.end.x_nm - segment.start.x_nm).abs() / b.rules.grid_nm) as u64;
                let dy = ((segment.end.y_nm - segment.start.y_nm).abs() / b.rules.grid_nm) as u64;
                14 * dx.min(dy) + 10 * (dx.max(dy) - dx.min(dy))
            })
            .sum();
        let input_order_chain_cost = 512;
        assert_eq!(route_cost, 320);
        assert!(route_cost < input_order_chain_cost);
    }

    #[test]
    fn selectively_rips_only_routes_that_block_a_failed_net() {
        let mut b = board();
        b.obstacles.clear();
        b.net_classes.insert(
            "FrontOnly".into(),
            NetClassRules {
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                layers: Some(vec![Layer::Front]),
                differential_width_nm: None,
                differential_gap_nm: None,
                minimum_length_nm: None,
                maximum_length_nm: None,
            },
        );
        b.nets = vec![
            Net {
                id: 1,
                name: "horizontal".into(),
                class: Some("FrontOnly".into()),
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 500_000,
                            y_nm: 5_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: Point {
                            x_nm: 9_500_000,
                            y_nm: 5_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                ],
            },
            Net {
                id: 2,
                name: "vertical".into(),
                class: Some("FrontOnly".into()),
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 5_000_000,
                            y_nm: 2_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: Point {
                            x_nm: 5_000_000,
                            y_nm: 8_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                ],
            },
        ];

        let (routed, report) = route_board(&b).unwrap();
        assert!(report.reroute_passes > 1);
        assert!(report.ripup_events > 0);
        assert_eq!(report.rerouted, vec!["horizontal".to_string()]);
        assert!(report.unrouted.is_empty());
        let check = crate::checking::check_board(&routed);
        assert!(check.is_clean(), "{:?}", check.violations);
    }

    #[test]
    fn routes_inside_a_concave_board_outline() {
        let mut b = board();
        b.obstacles.clear();
        b.outline = vec![
            Point { x_nm: 0, y_nm: 0 },
            Point {
                x_nm: 10_000_000,
                y_nm: 0,
            },
            Point {
                x_nm: 10_000_000,
                y_nm: 4_000_000,
            },
            Point {
                x_nm: 4_000_000,
                y_nm: 4_000_000,
            },
            Point {
                x_nm: 4_000_000,
                y_nm: 10_000_000,
            },
            Point {
                x_nm: 0,
                y_nm: 10_000_000,
            },
        ];
        b.nets[0].terminals = vec![
            Terminal {
                position: Point {
                    x_nm: 1_000_000,
                    y_nm: 9_000_000,
                },
                layers: vec![Layer::Front],
            },
            Terminal {
                position: Point {
                    x_nm: 9_000_000,
                    y_nm: 1_000_000,
                },
                layers: vec![Layer::Front],
            },
        ];

        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(crate::checking::check_board(&routed).is_clean());
        assert!(routed.routes[0].segments.iter().all(|segment| {
            !geometry::point_in_polygon(
                segment.start,
                &[
                    Point {
                        x_nm: 4_000_001,
                        y_nm: 4_000_001,
                    },
                    Point {
                        x_nm: 10_000_000,
                        y_nm: 4_000_001,
                    },
                    Point {
                        x_nm: 10_000_000,
                        y_nm: 10_000_000,
                    },
                    Point {
                        x_nm: 4_000_001,
                        y_nm: 10_000_000,
                    },
                ],
            )
        }));
    }

    #[test]
    fn routes_around_a_board_cutout() {
        let mut b = board();
        b.obstacles.clear();
        b.cutouts = vec![vec![
            Point {
                x_nm: 4_000_000,
                y_nm: 4_000_000,
            },
            Point {
                x_nm: 6_000_000,
                y_nm: 4_000_000,
            },
            Point {
                x_nm: 6_000_000,
                y_nm: 6_000_000,
            },
            Point {
                x_nm: 4_000_000,
                y_nm: 6_000_000,
            },
        ]];
        b.nets[0].terminals[0].position = Point {
            x_nm: 1_000_000,
            y_nm: 5_000_000,
        };
        b.nets[0].terminals[1].position = Point {
            x_nm: 9_000_000,
            y_nm: 5_000_000,
        };

        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(
            report.expanded_states < 50_000,
            "cutout search budget regressed: {} states",
            report.expanded_states
        );
        assert!(checking::check_board(&routed).is_clean());
        assert!(render_svg(&routed).contains(r#"fill="white""#));
    }

    #[test]
    fn polygon_keepout_does_not_block_its_bounding_box() {
        let mut b = board();
        b.obstacles.clear();
        b.keepouts.push(Keepout {
            polygon: vec![
                Point {
                    x_nm: 4_000_000,
                    y_nm: 4_000_000,
                },
                Point {
                    x_nm: 8_000_000,
                    y_nm: 4_000_000,
                },
                Point {
                    x_nm: 8_000_000,
                    y_nm: 8_000_000,
                },
            ],
            layers: vec![Layer::Front],
            net_id: None,
        });
        b.nets[0].class = Some("FrontOnly".into());
        b.net_classes.insert(
            "FrontOnly".into(),
            NetClassRules {
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                layers: Some(vec![Layer::Front]),
                differential_width_nm: None,
                differential_gap_nm: None,
                minimum_length_nm: None,
                maximum_length_nm: None,
            },
        );
        b.nets[0].terminals = vec![
            Terminal {
                position: Point {
                    x_nm: 4_500_000,
                    y_nm: 7_500_000,
                },
                layers: vec![Layer::Front],
            },
            Terminal {
                position: Point {
                    x_nm: 6_500_000,
                    y_nm: 7_500_000,
                },
                layers: vec![Layer::Front],
            },
        ];

        let (routed, report) = route_board(&b).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(crate::checking::check_board(&routed).is_clean());
        assert!(
            routed.routes[0].segments.iter().all(|segment| {
                segment.start.y_nm == 7_500_000 && segment.end.y_nm == 7_500_000
            })
        );
    }

    #[test]
    fn round_obstacle_does_not_block_its_bounding_box_corner() {
        let mut board = board();
        board.obstacles.clear();
        board.round_obstacles.push(RoundObstacle {
            center: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            diameter_nm: 4_000_000,
            layers: vec![Layer::Front],
            net_id: None,
        });
        board.nets[0].class = Some("FrontOnly".into());
        board.net_classes.insert(
            "FrontOnly".into(),
            NetClassRules {
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                layers: Some(vec![Layer::Front]),
                differential_width_nm: None,
                differential_gap_nm: None,
                minimum_length_nm: None,
                maximum_length_nm: None,
            },
        );
        board.nets[0].terminals = vec![
            Terminal {
                position: Point {
                    x_nm: 2_000_000,
                    y_nm: 4_000_000,
                },
                layers: vec![Layer::Front],
            },
            Terminal {
                position: Point {
                    x_nm: 4_000_000,
                    y_nm: 2_000_000,
                },
                layers: vec![Layer::Front],
            },
        ];

        let (routed, report) = route_board(&board).unwrap();
        assert!(report.unrouted.is_empty());
        assert!(crate::checking::check_board(&routed).is_clean());
        assert!(!routed.routes[0].segments.is_empty());
        assert!(routed.routes[0].vias.is_empty());
    }

    #[test]
    fn tunes_a_short_route_with_a_legal_meander() {
        let mut board = board();
        board.obstacles.clear();
        board.nets[0].class = Some("Matched".into());
        board.nets[0].terminals[0].position = Point {
            x_nm: 1_000_000,
            y_nm: 5_000_000,
        };
        board.nets[0].terminals[1].position = Point {
            x_nm: 9_000_000,
            y_nm: 5_000_000,
        };
        board.net_classes.insert(
            "Matched".into(),
            NetClassRules {
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                layers: Some(vec![Layer::Front]),
                differential_width_nm: None,
                differential_gap_nm: None,
                minimum_length_nm: Some(10_000_000),
                maximum_length_nm: Some(11_000_000),
            },
        );

        let (routed, report) = route_board(&board).unwrap();

        assert!(report.unrouted.is_empty());
        assert!(crate::checking::check_board(&routed).is_clean());
        assert!((10_000_000..=11_000_000).contains(&route_length_nm(&routed.routes[0])));
        assert!(routed.routes[0].segments.len() >= 5);
    }

    #[test]
    fn autoroutes_a_coupled_differential_pair() {
        let mut board = board();
        board.obstacles.clear();
        let terminals = |y_nm| {
            vec![
                Terminal {
                    position: Point {
                        x_nm: 1_000_000,
                        y_nm,
                    },
                    layers: vec![Layer::Front],
                },
                Terminal {
                    position: Point {
                        x_nm: 9_000_000,
                        y_nm,
                    },
                    layers: vec![Layer::Front],
                },
            ]
        };
        board.nets = vec![
            Net {
                id: 1,
                name: "USB_D+".into(),
                class: None,
                priority: 0,
                terminals: terminals(4_000_000),
            },
            Net {
                id: 2,
                name: "USB_D-".into(),
                class: None,
                priority: 0,
                terminals: terminals(5_000_000),
            },
        ];
        board.differential_pairs = vec![DifferentialPair {
            name: "USB_D".into(),
            positive_net_id: 1,
            negative_net_id: 2,
            gap_nm: 750_000,
            gap_tolerance_nm: 50_000,
            max_skew_nm: 0,
            min_coupled_percent: 100,
        }];

        let (routed, report) = route_board(&board).unwrap();

        assert!(report.unrouted.is_empty());
        assert_eq!(report.coupled_differential_pairs, ["USB_D"]);
        assert!(crate::checking::check_board(&routed).is_clean());
        let positive = routed
            .routes
            .iter()
            .find(|route| route.net_id == 1)
            .unwrap();
        let negative = routed
            .routes
            .iter()
            .find(|route| route.net_id == 2)
            .unwrap();
        assert_eq!(positive.segments.len(), negative.segments.len());
        assert!(
            positive
                .segments
                .iter()
                .zip(&negative.segments)
                .all(|(positive, negative)| {
                    negative.start.y_nm - positive.start.y_nm == 1_000_000
                        && negative.end.y_nm - positive.end.y_nm == 1_000_000
                        && negative.start.x_nm == positive.start.x_nm
                        && negative.end.x_nm == positive.end.x_nm
                })
        );
    }
}

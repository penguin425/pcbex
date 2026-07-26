use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};

pub mod checking;
mod geometry;
pub mod placement;
pub mod quality;
pub mod schema;

pub use quality::{DifferentialQuality, NetQuality, RoutingQuality, routing_quality};
pub use schema::{board_json_schema, migrate_board_json, parse_board_json};

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
    #[serde(default = "prohibited")]
    pub tracks_not_allowed: bool,
    #[serde(default = "prohibited")]
    pub vias_not_allowed: bool,
    #[serde(default = "prohibited")]
    pub zones_not_allowed: bool,
    #[serde(default)]
    pub footprints_not_allowed: bool,
    #[serde(default)]
    pub minimum_track_width_nm: Option<Nm>,
    #[serde(default)]
    pub minimum_clearance_nm: Option<Nm>,
}

fn prohibited() -> bool {
    true
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub target_impedance_ohms: Option<f64>,
    #[serde(default)]
    pub impedance_tolerance_ohms: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackupLayer {
    pub layer: Layer,
    pub dielectric_height_nm: Nm,
    pub dielectric_constant: f64,
    #[serde(default)]
    pub copper_thickness_nm: Nm,
    #[serde(default)]
    pub reference_layer: Option<Layer>,
    #[serde(default)]
    pub secondary_reference_layer: Option<Layer>,
    #[serde(default)]
    pub secondary_dielectric_height_nm: Option<Nm>,
    #[serde(default)]
    pub secondary_dielectric_constant: Option<f64>,
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
    #[serde(default)]
    pub target_differential_impedance_ohms: Option<f64>,
    #[serde(default)]
    pub differential_impedance_tolerance_ohms: Option<f64>,
    #[serde(default)]
    pub minimum_length_nm: Option<Nm>,
    #[serde(default)]
    pub tuning_amplitude_nm: Option<Nm>,
    #[serde(default)]
    pub tuning_pitch_nm: Option<Nm>,
    #[serde(default = "default_tuning_sections")]
    pub max_tuning_sections: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LengthGroup {
    pub name: String,
    pub net_ids: Vec<u32>,
    pub max_skew_nm: Nm,
    #[serde(default)]
    pub tuning_amplitude_nm: Option<Nm>,
    #[serde(default)]
    pub tuning_pitch_nm: Option<Nm>,
    #[serde(default = "default_tuning_sections")]
    pub max_tuning_sections: u8,
}

fn default_tuning_sections() -> u8 {
    4
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscapeGroup {
    pub name: String,
    pub net_ids: Vec<u32>,
    pub fanout_distance_nm: Nm,
    pub target_layer: Layer,
    #[serde(default)]
    pub direction: EscapeDirection,
    #[serde(default)]
    pub via_grid_nm: Option<Nm>,
    #[serde(default = "default_escape_rings")]
    pub max_rings: u8,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeDirection {
    Radial,
    Rows,
    Columns,
    #[default]
    FourWay,
}

fn default_escape_rings() -> u8 {
    3
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnPathRule {
    pub name: String,
    pub signal_net_ids: Vec<u32>,
    pub reference_net_id: u32,
    pub max_via_distance_nm: Nm,
    #[serde(default)]
    pub auto_stitch: bool,
    #[serde(default)]
    pub require_continuous_plane: bool,
    #[serde(default)]
    pub plane_sample_spacing_nm: Option<Nm>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowerNetRule {
    pub net_id: u32,
    pub current_ma: f64,
    pub maximum_voltage_drop_mv: f64,
    #[serde(default)]
    pub minimum_parallel_vias: usize,
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
#[serde(deny_unknown_fields)]
pub struct Board {
    #[serde(default = "legacy_schema_version")]
    pub schema_version: u32,
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
    #[serde(serialize_with = "serialize_net_classes")]
    pub net_classes: HashMap<String, NetClassRules>,
    #[serde(default)]
    pub differential_pairs: Vec<DifferentialPair>,
    #[serde(default)]
    pub length_groups: Vec<LengthGroup>,
    #[serde(default)]
    pub escape_groups: Vec<EscapeGroup>,
    #[serde(default)]
    pub manufacturing_rules: Option<ManufacturingRules>,
    #[serde(default)]
    pub return_path_rules: Vec<ReturnPathRule>,
    #[serde(default)]
    pub power_net_rules: Vec<PowerNetRule>,
    #[serde(default)]
    pub stackup: Vec<StackupLayer>,
    #[serde(default)]
    pub via_strategy: ViaStrategy,
    #[serde(default)]
    pub nets: Vec<Net>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

pub const CURRENT_SCHEMA_VERSION: u32 = 2;
fn legacy_schema_version() -> u32 {
    1
}

fn serialize_net_classes<S>(
    classes: &HashMap<String, NetClassRules>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    classes
        .iter()
        .collect::<BTreeMap<_, _>>()
        .serialize(serializer)
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
    #[serde(default = "zone_thermal_relief")]
    pub thermal_relief: bool,
    #[serde(default = "zone_thermal_gap")]
    pub thermal_gap_nm: Nm,
    #[serde(default = "zone_thermal_spoke_width")]
    pub thermal_spoke_width_nm: Nm,
    #[serde(default)]
    pub filled_polygons: Vec<Vec<Point>>,
}

fn zone_minimum_thickness() -> Nm {
    250_000
}
fn zone_thermal_relief() -> bool {
    true
}
fn zone_thermal_gap() -> Nm {
    200_000
}
fn zone_thermal_spoke_width() -> Nm {
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
        const ARC_DRC_DEVIATION_NM: Nm = 1_000;
        let mut route = self.clone();
        for arc in &self.arcs {
            route
                .segments
                .extend(
                    arc_polyline(arc, ARC_DRC_DEVIATION_NM)
                        .windows(2)
                        .map(|points| Segment {
                            start: points[0],
                            end: points[1],
                            layer: arc.layer,
                            width_nm: arc.width_nm + 2 * ARC_DRC_DEVIATION_NM,
                        }),
                );
        }
        route.arcs.clear();
        route
    }
}

fn arc_geometry(arc: &RouteArc) -> Option<(f64, f64, f64, f64)> {
    let (ax, ay) = (arc.start.x_nm as f64, arc.start.y_nm as f64);
    let (bx, by) = (arc.mid.x_nm as f64, arc.mid.y_nm as f64);
    let (cx, cy) = (arc.end.x_nm as f64, arc.end.y_nm as f64);
    let determinant = 2.0 * (ax * (by - cy) + bx * (cy - ay) + cx * (ay - by));
    if determinant.abs() < 1.0 {
        return None;
    }
    let a2 = ax * ax + ay * ay;
    let b2 = bx * bx + by * by;
    let c2 = cx * cx + cy * cy;
    let center_x = (a2 * (by - cy) + b2 * (cy - ay) + c2 * (ay - by)) / determinant;
    let center_y = (a2 * (cx - bx) + b2 * (ax - cx) + c2 * (bx - ax)) / determinant;
    let start = (ay - center_y).atan2(ax - center_x);
    let middle = (by - center_y).atan2(bx - center_x);
    let end = (cy - center_y).atan2(cx - center_x);
    let ccw = (end - start).rem_euclid(std::f64::consts::TAU);
    let middle_ccw = (middle - start).rem_euclid(std::f64::consts::TAU);
    let sweep = if middle_ccw <= ccw {
        ccw
    } else {
        ccw - std::f64::consts::TAU
    };
    Some((
        center_x,
        center_y,
        (ax - center_x).hypot(ay - center_y),
        sweep,
    ))
}

pub fn arc_is_valid(arc: &RouteArc) -> bool {
    arc_geometry(arc).is_some()
}

pub fn arc_length_nm(arc: &RouteArc) -> Nm {
    arc_geometry(arc)
        .map(|(_, _, radius, sweep)| (radius * sweep.abs()).round() as Nm)
        .unwrap_or_else(|| {
            let first = (arc.mid.x_nm - arc.start.x_nm) as f64;
            let first_y = (arc.mid.y_nm - arc.start.y_nm) as f64;
            let second = (arc.end.x_nm - arc.mid.x_nm) as f64;
            let second_y = (arc.end.y_nm - arc.mid.y_nm) as f64;
            (first.hypot(first_y) + second.hypot(second_y)).round() as Nm
        })
}

/// Estimate single-ended microstrip impedance with the IPC-2141 equation.
pub fn estimated_impedance_ohms(
    width_nm: Nm,
    dielectric_height_nm: Nm,
    dielectric_constant: f64,
) -> Option<f64> {
    estimated_impedance_with_copper_ohms(width_nm, dielectric_height_nm, 0, dielectric_constant)
}

/// Estimate single-ended microstrip impedance including conductor thickness.
pub fn estimated_impedance_with_copper_ohms(
    width_nm: Nm,
    dielectric_height_nm: Nm,
    copper_thickness_nm: Nm,
    dielectric_constant: f64,
) -> Option<f64> {
    if width_nm <= 0
        || dielectric_height_nm <= 0
        || copper_thickness_nm < 0
        || dielectric_constant <= 1.0
    {
        return None;
    }
    let width = width_nm as f64;
    let height = dielectric_height_nm as f64;
    let thickness = copper_thickness_nm as f64;
    let argument = 5.98 * height / (0.8 * width + thickness);
    if argument <= 1.0 {
        return None;
    }
    Some(87.0 / (dielectric_constant + 1.41).sqrt() * argument.ln())
}

/// Estimate impedance for a trace embedded between two reference planes.
///
/// The symmetric case is stripline. Unequal dielectric heights or constants
/// model an asymmetric embedded microstrip using a height-weighted effective
/// dielectric constant.
pub fn estimated_embedded_impedance_ohms(
    width_nm: Nm,
    first_dielectric_height_nm: Nm,
    second_dielectric_height_nm: Nm,
    copper_thickness_nm: Nm,
    first_dielectric_constant: f64,
    second_dielectric_constant: f64,
) -> Option<f64> {
    if width_nm <= 0
        || first_dielectric_height_nm <= 0
        || second_dielectric_height_nm <= 0
        || copper_thickness_nm < 0
        || first_dielectric_constant <= 1.0
        || second_dielectric_constant <= 1.0
        || !first_dielectric_constant.is_finite()
        || !second_dielectric_constant.is_finite()
    {
        return None;
    }
    let width = width_nm as f64;
    let thickness = copper_thickness_nm as f64;
    let first_height = first_dielectric_height_nm as f64;
    let second_height = second_dielectric_height_nm as f64;
    let plane_separation = first_height + thickness + second_height;
    let dielectric_constant = (first_dielectric_constant * first_height
        + second_dielectric_constant * second_height)
        / (first_height + second_height);
    let argument =
        4.0 * plane_separation / (0.67 * std::f64::consts::PI * (0.8 * width + thickness));
    if argument <= 1.0 {
        return None;
    }
    Some(60.0 / dielectric_constant.sqrt() * argument.ln())
}

/// Estimate impedance using the geometry encoded by a stackup entry.
pub fn estimated_stackup_impedance_ohms(width_nm: Nm, stackup: &StackupLayer) -> Option<f64> {
    match (
        stackup.secondary_dielectric_height_nm,
        stackup.secondary_dielectric_constant,
    ) {
        (Some(height), Some(dielectric_constant)) => estimated_embedded_impedance_ohms(
            width_nm,
            stackup.dielectric_height_nm,
            height,
            stackup.copper_thickness_nm,
            stackup.dielectric_constant,
            dielectric_constant,
        ),
        (None, None) => estimated_impedance_with_copper_ohms(
            width_nm,
            stackup.dielectric_height_nm,
            stackup.copper_thickness_nm,
            stackup.dielectric_constant,
        ),
        _ => None,
    }
}

/// Estimate edge-coupled differential microstrip impedance.
///
/// Uses the IPC-2141 single-ended estimate and the common exponential
/// odd-mode coupling correction as an early layout constraint.
pub fn estimated_differential_impedance_ohms(
    width_nm: Nm,
    gap_nm: Nm,
    dielectric_height_nm: Nm,
    copper_thickness_nm: Nm,
    dielectric_constant: f64,
) -> Option<f64> {
    if gap_nm < 0 {
        return None;
    }
    let single = estimated_impedance_with_copper_ohms(
        width_nm,
        dielectric_height_nm,
        copper_thickness_nm,
        dielectric_constant,
    )?;
    let normalized_gap = gap_nm as f64 / dielectric_height_nm as f64;
    Some(2.0 * single * (1.0 - 0.48 * (-0.96 * normalized_gap).exp()))
}

/// Estimate edge-coupled differential impedance using a stackup entry.
pub fn estimated_stackup_differential_impedance_ohms(
    width_nm: Nm,
    gap_nm: Nm,
    stackup: &StackupLayer,
) -> Option<f64> {
    if gap_nm < 0 {
        return None;
    }
    let single = estimated_stackup_impedance_ohms(width_nm, stackup)?;
    let coupling_height = stackup
        .secondary_dielectric_height_nm
        .map_or(stackup.dielectric_height_nm, |height| {
            height.min(stackup.dielectric_height_nm)
        });
    let normalized_gap = gap_nm as f64 / coupling_height as f64;
    Some(2.0 * single * (1.0 - 0.48 * (-0.96 * normalized_gap).exp()))
}

pub fn arc_polyline(arc: &RouteArc, maximum_deviation_nm: Nm) -> Vec<Point> {
    let Some((center_x, center_y, radius, sweep)) = arc_geometry(arc) else {
        return vec![arc.start, arc.mid, arc.end];
    };
    let deviation = maximum_deviation_nm.max(1) as f64;
    let maximum_step = if deviation >= radius {
        std::f64::consts::PI
    } else {
        2.0 * (1.0 - deviation / radius).clamp(-1.0, 1.0).acos()
    };
    let steps = (sweep.abs() / maximum_step).ceil().clamp(1.0, 65_536.0) as usize;
    let start_angle = (arc.start.y_nm as f64 - center_y).atan2(arc.start.x_nm as f64 - center_x);
    let mut points = Vec::with_capacity(steps + 1);
    for index in 0..=steps {
        let angle = start_angle + sweep * index as f64 / steps as f64;
        points.push(Point {
            x_nm: (center_x + radius * angle.cos()).round() as Nm,
            y_nm: (center_y + radius * angle.sin()).round() as Nm,
        });
    }
    points[0] = arc.start;
    points[steps] = arc.end;
    points
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
    pub shove_events: usize,
    #[serde(default)]
    pub coupled_differential_pairs: Vec<String>,
    #[serde(default)]
    pub generated_teardrops: usize,
    #[serde(default)]
    pub optimized_segments: usize,
    #[serde(default)]
    pub rounded_corners: usize,
    #[serde(default)]
    pub escaped_nets: usize,
    #[serde(default)]
    pub parallel_candidates: usize,
    #[serde(default)]
    pub parallel_fallbacks: usize,
    #[serde(default)]
    pub parallel_workers: usize,
    #[serde(default)]
    pub generated_return_vias: usize,
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
        if board.keepouts.iter().any(|keepout| {
            !geometry::polygon_is_simple(&keepout.polygon)
                || !(keepout.tracks_not_allowed
                    || keepout.vias_not_allowed
                    || keepout.zones_not_allowed
                    || keepout.footprints_not_allowed
                    || keepout.minimum_track_width_nm.is_some()
                    || keepout.minimum_clearance_nm.is_some())
                || keepout
                    .minimum_track_width_nm
                    .is_some_and(|value| value <= 0)
                || keepout.minimum_clearance_nm.is_some_and(|value| value < 0)
        }) {
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
            if rules.target_impedance_ohms.is_some() != rules.impedance_tolerance_ohms.is_some()
                || rules
                    .target_impedance_ohms
                    .is_some_and(|value| !value.is_finite() || value <= 0.0)
                || rules
                    .impedance_tolerance_ohms
                    .is_some_and(|value| !value.is_finite() || value < 0.0)
            {
                return Err(format!("net class {name} has invalid impedance limits"));
            }
        }
        let mut stackup_layers = HashSet::new();
        if board.stackup.iter().any(|entry| {
            !stackup_layers.insert(entry.layer)
                || !board.copper_layers.contains(&entry.layer)
                || entry.dielectric_height_nm <= 0
                || entry.copper_thickness_nm < 0
                || !entry.dielectric_constant.is_finite()
                || entry.dielectric_constant <= 1.0
                || entry.reference_layer.is_some_and(|layer| {
                    !board.copper_layers.contains(&layer) || layer == entry.layer
                })
                || entry.secondary_reference_layer.is_some()
                    != entry.secondary_dielectric_height_nm.is_some()
                || entry.secondary_reference_layer.is_some()
                    != entry.secondary_dielectric_constant.is_some()
                || entry.secondary_reference_layer.is_some() && entry.reference_layer.is_none()
                || entry.secondary_reference_layer.is_some_and(|layer| {
                    !board.copper_layers.contains(&layer)
                        || layer == entry.layer
                        || Some(layer) == entry.reference_layer
                })
                || entry
                    .secondary_dielectric_height_nm
                    .is_some_and(|height| height <= 0)
                || entry
                    .secondary_dielectric_constant
                    .is_some_and(|value| !value.is_finite() || value <= 1.0)
        }) {
            return Err("stackup has invalid or duplicate layer entries".into());
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
                || pair
                    .target_differential_impedance_ohms
                    .is_some_and(|value| !value.is_finite() || value <= 0.0)
                || pair
                    .differential_impedance_tolerance_ohms
                    .is_some_and(|value| !value.is_finite() || value < 0.0)
                || pair.target_differential_impedance_ohms.is_some()
                    != pair.differential_impedance_tolerance_ohms.is_some()
                || pair.minimum_length_nm.is_some_and(|value| value <= 0)
                || pair.tuning_amplitude_nm.is_some_and(|value| value <= 0)
                || pair.tuning_pitch_nm.is_some_and(|value| value <= 0)
                || !(1..=16).contains(&pair.max_tuning_sections)
                || !paired_net_ids.insert(pair.positive_net_id)
                || !paired_net_ids.insert(pair.negative_net_id)
            {
                return Err(format!("differential pair {} is invalid", pair.name));
            }
        }
        let mut length_group_names = HashSet::new();
        for group in &board.length_groups {
            let members: HashSet<_> = group.net_ids.iter().copied().collect();
            if group.name.is_empty()
                || !length_group_names.insert(group.name.as_str())
                || group.max_skew_nm < 0
                || group.tuning_amplitude_nm.is_some_and(|value| value <= 0)
                || group.tuning_pitch_nm.is_some_and(|value| value <= 0)
                || !(1..=16).contains(&group.max_tuning_sections)
                || members.len() < 2
                || members.len() != group.net_ids.len()
                || !members.iter().all(|net_id| net_ids.contains(net_id))
            {
                return Err(format!("length group {} is invalid", group.name));
            }
        }
        let mut escaped_net_ids = HashSet::new();
        for group in &board.escape_groups {
            if group.name.is_empty()
                || group.net_ids.is_empty()
                || group.fanout_distance_nm <= 0
                || group.via_grid_nm.is_some_and(|grid| grid <= 0)
                || !(1..=8).contains(&group.max_rings)
                || group.target_layer == Layer::Front
                || !board.copper_layers.contains(&group.target_layer)
                || group.net_ids.iter().any(|net_id| {
                    !net_ids.contains(net_id)
                        || !escaped_net_ids.insert(*net_id)
                        || board
                            .nets
                            .iter()
                            .find(|net| net.id == *net_id)
                            .is_none_or(|net| {
                                net.terminals.is_empty()
                                    || !net.terminals[0].layers.contains(&Layer::Front)
                            })
                        || board.routes.iter().any(|route| route.net_id == *net_id)
                })
            {
                return Err(format!("escape group {} is invalid", group.name));
            }
        }
        let mut return_path_names = HashSet::new();
        for rule in &board.return_path_rules {
            if rule.name.is_empty()
                || !return_path_names.insert(rule.name.as_str())
                || rule.max_via_distance_nm <= 0
                || rule
                    .plane_sample_spacing_nm
                    .is_some_and(|spacing| spacing <= 0)
                || !net_ids.contains(&rule.reference_net_id)
                || rule.signal_net_ids.is_empty()
                || rule
                    .signal_net_ids
                    .iter()
                    .any(|net_id| *net_id == rule.reference_net_id || !net_ids.contains(net_id))
            {
                return Err(format!("return path rule {} is invalid", rule.name));
            }
        }
        let mut power_net_ids = HashSet::new();
        for rule in &board.power_net_rules {
            if !power_net_ids.insert(rule.net_id)
                || !net_ids.contains(&rule.net_id)
                || !rule.current_ma.is_finite()
                || rule.current_ma <= 0.0
                || !rule.maximum_voltage_drop_mv.is_finite()
                || rule.maximum_voltage_drop_mv <= 0.0
            {
                return Err(format!("power-net rule for net {} is invalid", rule.net_id));
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
            if !keepout.tracks_not_allowed {
                continue;
            }
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

    pub fn route_all(self) -> (Vec<Route>, RouteReport) {
        let worker_limit = std::thread::available_parallelism().map_or(2, usize::from);
        self.route_all_with_workers(worker_limit)
    }

    pub fn route_all_with_workers(mut self, worker_limit: usize) -> (Vec<Route>, RouteReport) {
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
        let mut shove_events = 0;
        let mut best_routes = self.board.routes.clone();
        let mut best_report = RouteReport {
            preserved: preserved.clone(),
            unrouted: nets.iter().map(|n| n.name.clone()).collect(),
            rasterized_candidate_cells: self.rasterized_candidate_cells,
            ..RouteReport::default()
        };
        let mut total_expanded = 0;
        let mut parallel_candidates = 0;
        let mut parallel_fallbacks = 0;
        let mut parallel_workers = 0;
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
            let mut failed_blockers = HashMap::<u32, HashSet<u32>>::new();
            let initial_results = if attempt == 0 && attempt_nets.len() > 1 {
                parallel_candidates += attempt_nets.len();
                let worker_count = worker_limit.max(1).min(attempt_nets.len()).min(8);
                parallel_workers = worker_count;
                let next = std::sync::atomic::AtomicUsize::new(0);
                let results = std::sync::Mutex::new(
                    (0..attempt_nets.len())
                        .map(|_| None)
                        .collect::<Vec<Option<Result<(Route, usize), RouteFailure>>>>(),
                );
                std::thread::scope(|scope| {
                    for _ in 0..worker_count {
                        scope.spawn(|| {
                            loop {
                                let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let Some(net) = attempt_nets.get(index) else {
                                    break;
                                };
                                results.lock().expect("result lock poisoned")[index] =
                                    Some(self.route_net(net));
                            }
                        });
                    }
                });
                results
                    .into_inner()
                    .expect("result lock poisoned")
                    .into_iter()
                    .map(|result| result.expect("parallel worker skipped a net"))
                    .map(Some)
                    .collect::<Vec<_>>()
            } else {
                (0..attempt_nets.len()).map(|_| None).collect()
            };
            let mut validation = self.board.clone();
            validation.routes.extend(accepted.iter().cloned());
            for (net, initial_result) in attempt_nets.iter().copied().zip(initial_results) {
                let mut result = initial_result.unwrap_or_else(|| self.route_net(net));
                if attempt == 0
                    && let Ok((candidate, _)) = &result
                {
                    validation.routes.push(candidate.clone());
                    let invalid = checking::check_board(&validation)
                        .violations
                        .iter()
                        .any(|violation| violation.net_ids.contains(&net.id));
                    validation.routes.pop();
                    if invalid {
                        parallel_fallbacks += 1;
                        result = self.route_net(net);
                    }
                }
                match result {
                    Ok((route, expanded)) => {
                        total_expanded += expanded;
                        self.commit(&route);
                        validation.routes.push(route.clone());
                        accepted.push(route);
                    }
                    Err(failure) => {
                        total_expanded += failure.expanded;
                        blockers.extend(failure.blockers.iter().copied());
                        failed_blockers.insert(net.id, failure.blockers);
                        failed_ids.insert(net.id);
                    }
                }
            }
            for net in &attempt_nets {
                if !failed_ids.contains(&net.id) {
                    continue;
                }
                let Some(net_blockers) = failed_blockers.get(&net.id) else {
                    continue;
                };
                if let Some((blocker_id, shoved, routed, expanded)) =
                    try_automatic_shove(self.board, &accepted, net, net_blockers)
                {
                    total_expanded += expanded;
                    if let Some(route) =
                        accepted.iter_mut().find(|route| route.net_id == blocker_id)
                    {
                        *route = shoved;
                    }
                    accepted.push(routed);
                    failed_ids.remove(&net.id);
                    shove_events += 1;
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
                shove_events,
                parallel_candidates,
                parallel_fallbacks,
                parallel_workers,
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
                best_report.shove_events = shove_events;
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
        best_report.shove_events = shove_events;
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

    fn route_coupled_pair(&self, positive: &Net, negative: &Net) -> Option<(Route, Route, usize)> {
        if positive.terminals.len() != 2 || negative.terminals.len() != 2 {
            return None;
        }
        let rules = self.board.rules_for_net(positive.id);
        if rules != self.board.rules_for_net(negative.id) {
            return None;
        }
        let g = rules.grid_nm;
        let start_offset = (
            nearest_grid(negative.terminals[0].position.x_nm, g)
                - nearest_grid(positive.terminals[0].position.x_nm, g),
            nearest_grid(negative.terminals[0].position.y_nm, g)
                - nearest_grid(positive.terminals[0].position.y_nm, g),
        );
        let end_offset = (
            nearest_grid(negative.terminals[1].position.x_nm, g)
                - nearest_grid(positive.terminals[1].position.x_nm, g),
            nearest_grid(negative.terminals[1].position.y_nm, g)
                - nearest_grid(positive.terminals[1].position.y_nm, g),
        );
        if start_offset != end_offset || (start_offset.0 != 0 && start_offset.1 != 0) {
            return None;
        }
        let starts = self.terminal_nodes(positive.id, &positive.terminals[0], &rules);
        let goals: HashSet<_> = self
            .terminal_nodes(positive.id, &positive.terminals[1], &rules)
            .into_iter()
            .map(|node| (node.x, node.y, node.layer))
            .collect();
        let mut open = BinaryHeap::new();
        let mut costs = HashMap::new();
        let mut prev = HashMap::new();
        for node in starts {
            costs.insert(node, 0);
            open.push(QueueItem {
                score: heuristic_to_tree(node.x, node.y, node.layer, &goals),
                cost: 0,
                node,
            });
        }
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
        let max_x = (self.board.width_nm / g) as i32;
        let max_y = (self.board.height_nm / g) as i32;
        let mut expanded = 0;
        while let Some(item) = open.pop() {
            if item.cost != *costs.get(&item.node).unwrap_or(&u64::MAX) {
                continue;
            }
            expanded += 1;
            if goals.contains(&(item.node.x, item.node.y, item.node.layer)) {
                let mut path = vec![item.node];
                let mut cursor = item.node;
                while let Some(previous) = prev.get(&cursor) {
                    cursor = *previous;
                    path.push(cursor);
                }
                path.reverse();
                let paired_path: Vec<_> = path
                    .iter()
                    .map(|node| Node {
                        x: node.x + start_offset.0 as i32,
                        y: node.y + start_offset.1 as i32,
                        ..*node
                    })
                    .collect();
                let mut positive_route = empty_route(positive.id);
                let mut negative_route = empty_route(negative.id);
                append_terminal_access(
                    &mut positive_route,
                    positive.terminals[0].position,
                    path[0],
                    &rules,
                    true,
                );
                append_path(&mut positive_route, &path, &rules, self.board);
                append_terminal_access(
                    &mut positive_route,
                    positive.terminals[1].position,
                    *path.last().unwrap(),
                    &rules,
                    false,
                );
                append_terminal_access(
                    &mut negative_route,
                    negative.terminals[0].position,
                    paired_path[0],
                    &rules,
                    true,
                );
                append_path(&mut negative_route, &paired_path, &rules, self.board);
                append_terminal_access(
                    &mut negative_route,
                    negative.terminals[1].position,
                    *paired_path.last().unwrap(),
                    &rules,
                    false,
                );
                return Some((positive_route, negative_route, expanded));
            }
            for (direction, (dx, dy)) in DIRS.iter().enumerate() {
                let next = Node {
                    x: item.node.x + dx,
                    y: item.node.y + dy,
                    layer: item.node.layer,
                    dir: direction as u8,
                };
                let paired = (
                    next.x + start_offset.0 as i32,
                    next.y + start_offset.1 as i32,
                    next.layer,
                );
                if next.x < 0
                    || next.y < 0
                    || next.x > max_x
                    || next.y > max_y
                    || paired.0 < 0
                    || paired.1 < 0
                    || paired.0 > max_x
                    || paired.1 > max_y
                {
                    continue;
                }
                let positive_cell = (next.x, next.y, next.layer);
                let endpoint = goals.contains(&positive_cell);
                if !endpoint
                    && (self.blocked.contains(&positive_cell)
                        || self.foreign_obstacle(positive_cell, positive.id)
                        || self.blocked.contains(&paired)
                        || self.foreign_obstacle(paired, negative.id))
                {
                    continue;
                }
                let step = if *dx != 0 && *dy != 0 { 14 } else { 10 };
                let bend = u64::from(item.node.dir < 8 && item.node.dir != direction as u8)
                    * rules.bend_cost as u64;
                self.relax(
                    item.node,
                    next,
                    item.cost + step + bend,
                    &goals,
                    &mut costs,
                    &mut prev,
                    &mut open,
                );
            }
        }
        None
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
        if self.owned.get(&cell).is_some_and(|owner| *owner != net_id) {
            return true;
        }
        let layer = index_layer(cell.2);
        let point = Point {
            x_nm: cell.0 as Nm * self.board.rules_for_net(net_id).grid_nm,
            y_nm: cell.1 as Nm * self.board.rules_for_net(net_id).grid_nm,
        };
        let rules = self.board.rules_for_net(net_id);
        self.board.keepouts.iter().any(|area| {
            area.net_id != Some(net_id)
                && area.layers.contains(&layer)
                && geometry::point_in_polygon(point, &area.polygon)
                && (area
                    .minimum_track_width_nm
                    .is_some_and(|minimum| rules.track_width_nm < minimum)
                    || area
                        .minimum_clearance_nm
                        .is_some_and(|minimum| rules.clearance_nm < minimum))
        })
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
fn try_automatic_shove(
    board: &Board,
    accepted: &[Route],
    failed_net: &Net,
    blockers: &HashSet<u32>,
) -> Option<(u32, Route, Route, usize)> {
    let grid = board.rules_for_net(failed_net.id).grid_nm;
    for distance in 1..=2 {
        for offset in [
            Point {
                x_nm: distance * grid,
                y_nm: 0,
            },
            Point {
                x_nm: -distance * grid,
                y_nm: 0,
            },
            Point {
                x_nm: 0,
                y_nm: distance * grid,
            },
            Point {
                x_nm: 0,
                y_nm: -distance * grid,
            },
        ] {
            for blocker_id in blockers {
                let Some(blocker_index) = accepted
                    .iter()
                    .position(|route| route.net_id == *blocker_id)
                else {
                    continue;
                };
                let Ok(shoved) = shoved_route_candidate(board, &accepted[blocker_index], offset)
                else {
                    continue;
                };
                let mut candidate = board.clone();
                candidate.routes.extend(accepted.iter().cloned());
                let Some(route_index) = candidate
                    .routes
                    .iter()
                    .position(|route| route.net_id == *blocker_id)
                else {
                    continue;
                };
                candidate.routes[route_index] = shoved.clone();
                let Ok(router) = Router::new(&candidate) else {
                    continue;
                };
                let Ok((routed, expanded)) = router.route_net(failed_net) else {
                    continue;
                };
                candidate.routes.push(routed.clone());
                let invalid =
                    checking::check_board(&candidate)
                        .violations
                        .iter()
                        .any(|violation| {
                            violation.net_ids.contains(&failed_net.id)
                                || violation.net_ids.contains(blocker_id)
                        });
                if !invalid {
                    return Some((*blocker_id, shoved, routed, expanded));
                }
            }
        }
    }
    None
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

fn empty_route(net_id: u32) -> Route {
    Route {
        net_id,
        segments: vec![],
        arcs: vec![],
        vias: vec![],
        teardrops: vec![],
        zones: vec![],
    }
}

pub fn route_board(board: &Board) -> Result<(Board, RouteReport), String> {
    let workers = std::thread::available_parallelism().map_or(2, usize::from);
    route_board_with_workers(board, workers)
}

/// Route a board with a deterministic upper bound on first-pass search workers.
///
/// The limit is clamped to 1..=8 and is primarily useful for repeatable
/// performance measurements and resource-constrained integrations.
pub fn route_board_with_workers(
    board: &Board,
    worker_limit: usize,
) -> Result<(Board, RouteReport), String> {
    if worker_limit == 0 {
        return Err("worker limit must be at least 1".into());
    }
    let (mut seeded, escape_stubs) = prepare_escape_routing(board)?;
    let mut coupled = Vec::new();
    let mut paired_expanded = 0;
    for pair in &board.differential_pairs {
        if seeded.routes.iter().any(|route| {
            route.net_id == pair.positive_net_id || route.net_id == pair.negative_net_id
        }) {
            continue;
        }
        let (Some(positive), Some(negative)) = (
            board.nets.iter().find(|net| net.id == pair.positive_net_id),
            board.nets.iter().find(|net| net.id == pair.negative_net_id),
        ) else {
            continue;
        };
        let Some((positive_route, negative_route, expanded)) =
            Router::new(&seeded)?.route_coupled_pair(positive, negative)
        else {
            continue;
        };
        seeded.routes.push(positive_route);
        seeded.routes.push(negative_route);
        let invalid = checking::check_board(&seeded)
            .violations
            .iter()
            .any(|violation| {
                violation.net_ids.contains(&pair.positive_net_id)
                    || violation.net_ids.contains(&pair.negative_net_id)
            });
        if invalid {
            seeded.routes.retain(|route| {
                route.net_id != pair.positive_net_id && route.net_id != pair.negative_net_id
            });
        } else {
            coupled.push(pair.name.clone());
            paired_expanded += expanded;
        }
    }
    let (routes, mut report) = Router::new(&seeded)?.route_all_with_workers(worker_limit);
    let mut out = seeded;
    out.routes = routes;
    couple_differential_pairs(&mut out, &mut report);
    tune_differential_pairs_synchronously(&mut out)?;
    tune_route_lengths(&mut out)?;
    for stub in escape_stubs {
        let route = out
            .routes
            .iter_mut()
            .find(|route| route.net_id == stub.net_id)
            .ok_or_else(|| format!("escaped net {} was not routed", stub.net_id))?;
        route.segments.extend(stub.segments);
        route.vias.extend(stub.vias);
        report.escaped_nets += 1;
    }
    out.nets = board.nets.clone();
    report.generated_return_vias = stitch_return_paths(&mut out);
    let mutable_net_ids: HashSet<u32> = report
        .routed
        .iter()
        .chain(&report.rerouted)
        .filter_map(|name| {
            out.nets
                .iter()
                .find(|net| net.name == *name)
                .map(|net| net.id)
        })
        .collect();
    report.optimized_segments = optimize_routes(&mut out, &mutable_net_ids);
    report.rounded_corners = round_route_corners(&mut out, &mutable_net_ids, board.rules.grid_nm);
    report.generated_teardrops = generate_route_teardrops(&mut out);
    fill_copper_zones(&mut out);
    report.expanded_states += paired_expanded;
    report.coupled_differential_pairs.extend(coupled);
    report.coupled_differential_pairs.sort();
    report.coupled_differential_pairs.dedup();
    let final_check = checking::check_board(&out);
    if report.unrouted.is_empty() && !final_check.is_clean() {
        return Err(format!(
            "post-routing checks failed: {}",
            final_check
                .violations
                .iter()
                .map(|violation| violation.rule.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok((out, report))
}

/// Add checked reference-net vias beside signal-layer transitions for rules
/// that opt into automatic stitching.
pub fn stitch_return_paths(board: &mut Board) -> usize {
    let mut generated = 0;
    for rule in board
        .return_path_rules
        .clone()
        .into_iter()
        .filter(|rule| rule.auto_stitch && rule.max_via_distance_nm > 0)
    {
        let Some(reference_index) = board
            .routes
            .iter()
            .position(|route| route.net_id == rule.reference_net_id)
        else {
            continue;
        };
        let signal_vias: Vec<_> = board
            .routes
            .iter()
            .filter(|route| rule.signal_net_ids.contains(&route.net_id))
            .flat_map(|route| route.vias.iter().cloned().map(|via| (route.net_id, via)))
            .collect();
        for (signal_net_id, signal_via) in signal_vias {
            if board.routes[reference_index]
                .vias
                .iter()
                .any(|reference_via| {
                    signal_via.shares_layer_with(reference_via)
                        && point_distance_nm(signal_via.position, reference_via.position)
                            <= rule.max_via_distance_nm
                })
            {
                continue;
            }
            let anchors: Vec<_> = board.routes[reference_index]
                .segments
                .iter()
                .filter(|segment| signal_via.spans_layer(segment.layer))
                .flat_map(|segment| [segment.start, segment.end])
                .chain(
                    board
                        .nets
                        .iter()
                        .find(|net| net.id == rule.reference_net_id)
                        .into_iter()
                        .flat_map(|net| &net.terminals)
                        .filter(|terminal| {
                            terminal
                                .layers
                                .iter()
                                .any(|layer| signal_via.spans_layer(*layer))
                        })
                        .map(|terminal| terminal.position),
                )
                .collect();
            let anchor = anchors
                .into_iter()
                .min_by_key(|point| point_distance_nm(*point, signal_via.position));
            let reference_rules = board.rules_for_net(rule.reference_net_id);
            let distance = rule.max_via_distance_nm;
            let baseline_non_return = checking::check_board(board)
                .violations
                .iter()
                .filter(|violation| violation.rule != "return_path")
                .count();
            for (dx, dy) in [(distance, 0), (-distance, 0), (0, distance), (0, -distance)] {
                let position = Point {
                    x_nm: signal_via.position.x_nm + dx,
                    y_nm: signal_via.position.y_nm + dy,
                };
                if !board.point_inside_board(position, reference_rules.via_diameter_nm) {
                    continue;
                }
                let layer = signal_via.start_layer;
                let touches_zone = board.routes[reference_index].zones.iter().any(|zone| {
                    signal_via.spans_layer(zone.layer) && zone_contains_point(zone, position)
                });
                let points = if touches_zone {
                    vec![position]
                } else if let Some(anchor) = anchor {
                    if anchor.x_nm == position.x_nm
                        || anchor.y_nm == position.y_nm
                        || (anchor.x_nm - position.x_nm).abs()
                            == (anchor.y_nm - position.y_nm).abs()
                    {
                        vec![anchor, position]
                    } else {
                        vec![
                            anchor,
                            Point {
                                x_nm: position.x_nm,
                                y_nm: anchor.y_nm,
                            },
                            position,
                        ]
                    }
                } else {
                    continue;
                };
                let segments = points
                    .windows(2)
                    .map(|points| Segment {
                        start: points[0],
                        end: points[1],
                        layer,
                        width_nm: reference_rules.track_width_nm,
                    })
                    .collect::<Vec<_>>();
                let via = Via {
                    position,
                    diameter_nm: reference_rules.via_diameter_nm,
                    drill_nm: reference_rules.via_drill_nm,
                    kind: signal_via.kind,
                    start_layer: signal_via.start_layer,
                    end_layer: signal_via.end_layer,
                };
                let mut candidate = board.clone();
                candidate.routes[reference_index]
                    .segments
                    .extend(segments.iter().cloned());
                candidate.routes[reference_index].vias.push(via.clone());
                let report = checking::check_board(&candidate);
                let non_return = report
                    .violations
                    .iter()
                    .filter(|violation| violation.rule != "return_path")
                    .count();
                let still_missing = report.violations.iter().any(|violation| {
                    violation.rule == "return_path"
                        && violation.net_ids.contains(&rule.reference_net_id)
                        && violation.net_ids.contains(&signal_net_id)
                });
                if non_return == baseline_non_return && !still_missing {
                    board.routes[reference_index].segments.extend(segments);
                    board.routes[reference_index].vias.push(via);
                    generated += 1;
                    break;
                }
            }
        }
    }
    generated
}

fn zone_contains_point(zone: &CopperZone, point: Point) -> bool {
    if zone.filled_polygons.is_empty() {
        geometry::point_in_polygon(point, &zone.polygon)
    } else {
        zone.filled_polygons
            .iter()
            .any(|polygon| geometry::point_in_polygon(point, polygon))
    }
}

fn point_distance_nm(left: Point, right: Point) -> Nm {
    let dx = (left.x_nm - right.x_nm) as f64;
    let dy = (left.y_nm - right.y_nm) as f64;
    dx.hypot(dy).round() as Nm
}

/// Rip up and reroute only the selected nets. Every unselected route remains
/// locked and is compared byte-for-byte before the result is returned.
pub fn repair_routes(
    board: &Board,
    requested_net_ids: &HashSet<u32>,
) -> Result<(Board, RouteReport), String> {
    let known_net_ids: HashSet<_> = board.nets.iter().map(|net| net.id).collect();
    if requested_net_ids.is_empty() {
        return Err("local repair requires at least one net".into());
    }
    if let Some(unknown) = requested_net_ids
        .iter()
        .find(|net_id| !known_net_ids.contains(net_id))
    {
        return Err(format!("cannot repair unknown net {unknown}"));
    }
    let locked: HashMap<_, _> = board
        .routes
        .iter()
        .filter(|route| !requested_net_ids.contains(&route.net_id))
        .map(|route| (route.net_id, route.clone()))
        .collect();
    let zones: HashMap<_, _> = board
        .routes
        .iter()
        .filter(|route| requested_net_ids.contains(&route.net_id) && !route.zones.is_empty())
        .map(|route| (route.net_id, route.zones.clone()))
        .collect();
    let mut candidate = board.clone();
    candidate
        .routes
        .retain(|route| !requested_net_ids.contains(&route.net_id));
    let (mut repaired, mut report) = route_board(&candidate)?;
    for route in &mut repaired.routes {
        if let Some(saved) = zones.get(&route.net_id) {
            route.zones = saved.clone();
        }
    }
    fill_copper_zones(&mut repaired);
    for (net_id, original) in locked {
        if repaired.routes.iter().find(|route| route.net_id == net_id) != Some(&original) {
            return Err(format!("local repair changed locked net {net_id}"));
        }
    }
    let check = checking::check_board(&repaired);
    if !report.unrouted.is_empty() || !check.is_clean() {
        return Err(format!(
            "local repair did not produce a clean board: {}",
            check
                .violations
                .iter()
                .map(|violation| violation.rule.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    report.rerouted = board
        .nets
        .iter()
        .filter(|net| requested_net_ids.contains(&net.id))
        .map(|net| net.name.clone())
        .collect();
    report.routed.clear();
    Ok((repaired, report))
}

pub fn repairable_net_ids(board: &Board) -> HashSet<u32> {
    checking::check_board(board)
        .violations
        .into_iter()
        .flat_map(|violation| violation.net_ids)
        .collect()
}

fn prepare_escape_routing(board: &Board) -> Result<(Board, Vec<Route>), String> {
    let mut adjusted = board.clone();
    let mut stubs = Vec::new();
    for group in &board.escape_groups {
        let terminals: Vec<_> = group
            .net_ids
            .iter()
            .filter_map(|net_id| {
                board
                    .nets
                    .iter()
                    .find(|net| net.id == *net_id)
                    .and_then(|net| net.terminals.first())
                    .map(|terminal| terminal.position)
            })
            .collect();
        if terminals.is_empty() {
            continue;
        }
        let centroid = Point {
            x_nm: terminals.iter().map(|point| point.x_nm).sum::<Nm>() / terminals.len() as Nm,
            y_nm: terminals.iter().map(|point| point.y_nm).sum::<Nm>() / terminals.len() as Nm,
        };
        for net_id in &group.net_ids {
            let net_index = adjusted
                .nets
                .iter()
                .position(|net| net.id == *net_id)
                .ok_or_else(|| format!("unknown escaped net {net_id}"))?;
            let original = adjusted.nets[net_index].terminals[0].position;
            let rules = adjusted.rules_for_net(*net_id);
            let kind = if group.target_layer.index() == 1 {
                ViaKind::Micro
            } else if group.target_layer == Layer::Back {
                ViaKind::Through
            } else {
                ViaKind::BlindBuried
            };
            let primary = escape_primary_direction(original, centroid, group.direction, *net_id);
            let directions = escape_direction_candidates(primary);
            let mut selected = None;
            'rings: for ring in 1..=group.max_rings {
                for (dx, dy) in &directions {
                    let distance = group.fanout_distance_nm * Nm::from(ring);
                    let mut escape = Point {
                        x_nm: original.x_nm + dx * distance,
                        y_nm: original.y_nm + dy * distance,
                    };
                    if let Some(grid) = group.via_grid_nm {
                        escape.x_nm = snap_to_grid(escape.x_nm, grid);
                        escape.y_nm = snap_to_grid(escape.y_nm, grid);
                    }
                    if escape == original
                        || !adjusted.point_inside_board(escape, rules.via_diameter_nm)
                    {
                        continue;
                    }
                    let candidate = Route {
                        net_id: *net_id,
                        segments: escape_stub_segments(original, escape, rules.track_width_nm),
                        arcs: vec![],
                        vias: vec![Via {
                            position: escape,
                            diameter_nm: rules.via_diameter_nm,
                            drill_nm: rules.via_drill_nm,
                            kind,
                            start_layer: Layer::Front,
                            end_layer: group.target_layer,
                        }],
                        teardrops: vec![],
                        zones: vec![],
                    };
                    if escape_candidate_is_legal(&adjusted, &stubs, &candidate) {
                        selected = Some((escape, candidate));
                        break 'rings;
                    }
                }
            }
            let Some((escape, stub)) = selected else {
                return Err(format!(
                    "unable to place a legal BGA escape via for net {net_id} in {} rings",
                    group.max_rings
                ));
            };
            stubs.push(stub);
            let terminal = &mut adjusted.nets[net_index].terminals[0];
            terminal.position = escape;
            terminal.layers = vec![group.target_layer];
        }
    }
    adjusted.escape_groups.clear();
    Ok((adjusted, stubs))
}

fn escape_primary_direction(
    point: Point,
    centroid: Point,
    strategy: EscapeDirection,
    net_id: u32,
) -> (Nm, Nm) {
    let mut dx = (point.x_nm - centroid.x_nm).signum();
    let dy = (point.y_nm - centroid.y_nm).signum();
    if dx == 0 && dy == 0 {
        dx = if net_id.is_multiple_of(2) { -1 } else { 1 };
    }
    match strategy {
        EscapeDirection::Radial => (dx, dy),
        EscapeDirection::Rows => (if dx == 0 { 1 } else { dx }, 0),
        EscapeDirection::Columns => (0, if dy == 0 { 1 } else { dy }),
        EscapeDirection::FourWay => {
            if (point.x_nm - centroid.x_nm).abs() >= (point.y_nm - centroid.y_nm).abs() {
                (if dx == 0 { 1 } else { dx }, 0)
            } else {
                (0, if dy == 0 { 1 } else { dy })
            }
        }
    }
}

fn escape_direction_candidates(primary: (Nm, Nm)) -> Vec<(Nm, Nm)> {
    let axes = [(1, 0), (0, 1), (-1, 0), (0, -1)];
    let mut directions = vec![primary];
    directions.extend(axes.into_iter().filter(|direction| *direction != primary));
    directions
}

fn snap_to_grid(value: Nm, grid: Nm) -> Nm {
    ((value as f64 / grid as f64).round() as Nm) * grid
}

fn escape_stub_segments(start: Point, end: Point, width_nm: Nm) -> Vec<Segment> {
    let dx = (end.x_nm - start.x_nm).abs();
    let dy = (end.y_nm - start.y_nm).abs();
    let points = if dx == 0 || dy == 0 || dx == dy {
        vec![start, end]
    } else {
        vec![
            start,
            Point {
                x_nm: end.x_nm,
                y_nm: start.y_nm,
            },
            end,
        ]
    };
    points
        .windows(2)
        .map(|points| Segment {
            start: points[0],
            end: points[1],
            layer: Layer::Front,
            width_nm,
        })
        .collect()
}

fn escape_candidate_is_legal(board: &Board, stubs: &[Route], candidate: &Route) -> bool {
    let mut validation = board.clone();
    validation.routes.extend_from_slice(stubs);
    validation.routes.push(candidate.clone());
    checking::check_board(&validation)
        .violations
        .iter()
        .all(|violation| {
            !violation.net_ids.contains(&candidate.net_id)
                || matches!(
                    violation.rule.as_str(),
                    "unconnected" | "disconnected_route" | "orphan_copper"
                )
        })
}

/// Replace legal orthogonal track corners with tangent quarter-circle arcs.
/// Every replacement is accepted only when the complete board remains clean.
pub fn round_route_corners(
    board: &mut Board,
    net_ids: &HashSet<u32>,
    requested_radius_nm: Nm,
) -> usize {
    if requested_radius_nm <= 0 {
        return 0;
    }
    let mut rounded = 0;
    for route_index in 0..board.routes.len() {
        if !net_ids.contains(&board.routes[route_index].net_id) {
            continue;
        }
        let mut segment_index = 0;
        while segment_index + 1 < board.routes[route_index].segments.len() {
            let first = &board.routes[route_index].segments[segment_index];
            let second = &board.routes[route_index].segments[segment_index + 1];
            let Some((arc, first_end, second_start)) =
                rounded_corner(first, second, requested_radius_nm)
            else {
                segment_index += 1;
                continue;
            };
            let mut candidate = board.clone();
            candidate.routes[route_index].segments[segment_index].end = first_end;
            candidate.routes[route_index].segments[segment_index + 1].start = second_start;
            candidate.routes[route_index].arcs.push(arc);
            if checking::check_board(&candidate).is_clean() {
                *board = candidate;
                rounded += 1;
                segment_index += 2;
            } else {
                segment_index += 1;
            }
        }
    }
    rounded
}

fn rounded_corner(
    first: &Segment,
    second: &Segment,
    requested_radius_nm: Nm,
) -> Option<(RouteArc, Point, Point)> {
    if first.layer != second.layer || first.width_nm != second.width_nm || first.end != second.start
    {
        return None;
    }
    let corner = first.end;
    let incoming = (
        corner.x_nm - first.start.x_nm,
        corner.y_nm - first.start.y_nm,
    );
    let outgoing = (second.end.x_nm - corner.x_nm, second.end.y_nm - corner.y_nm);
    let incoming_axis = (incoming.0 == 0) != (incoming.1 == 0);
    let outgoing_axis = (outgoing.0 == 0) != (outgoing.1 == 0);
    if !incoming_axis
        || !outgoing_axis
        || i128::from(incoming.0) * i128::from(outgoing.0)
            + i128::from(incoming.1) * i128::from(outgoing.1)
            != 0
    {
        return None;
    }
    let first_length = incoming.0.abs() + incoming.1.abs();
    let second_length = outgoing.0.abs() + outgoing.1.abs();
    let radius = requested_radius_nm
        .min(first_length / 2)
        .min(second_length / 2);
    if radius <= 0 {
        return None;
    }
    let incoming_unit = (incoming.0.signum(), incoming.1.signum());
    let outgoing_unit = (outgoing.0.signum(), outgoing.1.signum());
    let start = Point {
        x_nm: corner.x_nm - incoming_unit.0 * radius,
        y_nm: corner.y_nm - incoming_unit.1 * radius,
    };
    let end = Point {
        x_nm: corner.x_nm + outgoing_unit.0 * radius,
        y_nm: corner.y_nm + outgoing_unit.1 * radius,
    };
    let center = Point {
        x_nm: start.x_nm + outgoing_unit.0 * radius,
        y_nm: start.y_nm + outgoing_unit.1 * radius,
    };
    let diagonal = radius as f64 / 2.0_f64.sqrt();
    let mid = Point {
        x_nm: (center.x_nm as f64
            + f64::from((incoming_unit.0 - outgoing_unit.0) as i32) * diagonal)
            .round() as Nm,
        y_nm: (center.y_nm as f64
            + f64::from((incoming_unit.1 - outgoing_unit.1) as i32) * diagonal)
            .round() as Nm,
    };
    Some((
        RouteArc {
            start,
            mid,
            end,
            layer: first.layer,
            width_nm: first.width_nm,
        },
        start,
        end,
    ))
}

/// Deterministically replace legal contiguous track detours with shorter direct
/// H/V/45-degree segments. Each candidate is accepted only after a complete
/// board check, so connectivity, clearance, length, and differential-pair
/// constraints remain authoritative.
pub fn optimize_routes(board: &mut Board, net_ids: &HashSet<u32>) -> usize {
    let mut removed = 0;
    for route_index in 0..board.routes.len() {
        if !net_ids.contains(&board.routes[route_index].net_id) {
            continue;
        }
        let mut changed = true;
        while changed {
            changed = false;
            let segment_count = board.routes[route_index].segments.len();
            'candidate: for start in 0..segment_count {
                for end in ((start + 1)..segment_count).rev() {
                    let chain = &board.routes[route_index].segments[start..=end];
                    if !chain.windows(2).all(|pair| pair[0].end == pair[1].start)
                        || !chain.iter().all(|segment| {
                            segment.layer == chain[0].layer && segment.width_nm == chain[0].width_nm
                        })
                    {
                        continue;
                    }
                    let direct = Segment {
                        start: chain[0].start,
                        end: chain[chain.len() - 1].end,
                        layer: chain[0].layer,
                        width_nm: chain[0].width_nm,
                    };
                    let dx = (direct.end.x_nm - direct.start.x_nm).abs();
                    let dy = (direct.end.y_nm - direct.start.y_nm).abs();
                    if direct.start == direct.end || (dx != 0 && dy != 0 && dx != dy) {
                        continue;
                    }
                    let old_length: Nm = chain
                        .iter()
                        .map(|segment| {
                            let dx = (segment.end.x_nm - segment.start.x_nm) as f64;
                            let dy = (segment.end.y_nm - segment.start.y_nm) as f64;
                            dx.hypot(dy).round() as Nm
                        })
                        .sum();
                    let direct_length = {
                        let dx = (direct.end.x_nm - direct.start.x_nm) as f64;
                        let dy = (direct.end.y_nm - direct.start.y_nm) as f64;
                        dx.hypot(dy).round() as Nm
                    };
                    if direct_length > old_length {
                        continue;
                    }
                    let mut candidate = board.clone();
                    candidate.routes[route_index]
                        .segments
                        .splice(start..=end, [direct]);
                    if checking::check_board(&candidate).is_clean() {
                        let count = end - start;
                        *board = candidate;
                        removed += count;
                        changed = true;
                        break 'candidate;
                    }
                }
            }
        }
    }
    removed
}

pub fn fill_copper_zones(board: &mut Board) -> usize {
    let snapshot = board.clone();
    let grid = board.rules.grid_nm;
    let mut total_cells = 0;
    for route in &mut board.routes {
        for zone in &mut route.zones {
            zone.filled_polygons.clear();
            let Some((min_x, max_x, min_y, max_y)) = polygon_bounds(&zone.polygon) else {
                continue;
            };
            let mut cells = HashSet::new();
            for y in (min_y / grid)..=(max_y / grid) {
                for x in (min_x / grid)..=(max_x / grid) {
                    let center = Point {
                        x_nm: x * grid,
                        y_nm: y * grid,
                    };
                    let half = grid / 2;
                    let corners = [
                        Point {
                            x_nm: center.x_nm - half,
                            y_nm: center.y_nm - half,
                        },
                        Point {
                            x_nm: center.x_nm + half,
                            y_nm: center.y_nm - half,
                        },
                        Point {
                            x_nm: center.x_nm + half,
                            y_nm: center.y_nm + half,
                        },
                        Point {
                            x_nm: center.x_nm - half,
                            y_nm: center.y_nm + half,
                        },
                    ];
                    if corners
                        .iter()
                        .all(|point| geometry::point_in_polygon(*point, &zone.polygon))
                        && !zone_cell_blocked(&snapshot, route.net_id, zone, center, &corners)
                    {
                        cells.insert((x, y));
                    }
                }
            }
            cells = connected_zone_cells(&snapshot, route.net_id, cells, grid);
            total_cells += cells.len();
            zone.filled_polygons = cells
                .into_iter()
                .map(|(x, y)| {
                    let center_x = x * grid;
                    let center_y = y * grid;
                    let half = grid / 2;
                    vec![
                        Point {
                            x_nm: center_x - half,
                            y_nm: center_y - half,
                        },
                        Point {
                            x_nm: center_x + half,
                            y_nm: center_y - half,
                        },
                        Point {
                            x_nm: center_x + half,
                            y_nm: center_y + half,
                        },
                        Point {
                            x_nm: center_x - half,
                            y_nm: center_y + half,
                        },
                    ]
                })
                .collect();
        }
    }
    total_cells
}

fn zone_cell_blocked(
    board: &Board,
    net_id: u32,
    zone: &CopperZone,
    center: Point,
    corners: &[Point; 4],
) -> bool {
    if corners
        .iter()
        .any(|point| !board.point_inside_board(*point, 0))
    {
        return true;
    }
    let clearance_twice = 2 * zone.clearance_nm;
    if board.keepouts.iter().any(|keepout| {
        keepout.zones_not_allowed
            && keepout.layers.contains(&zone.layer)
            && keepout.net_id != Some(net_id)
            && corners.iter().any(|point| {
                geometry::point_in_polygon(*point, &keepout.polygon)
                    || geometry::point_polygon_closer_than(
                        *point,
                        &keepout.polygon,
                        clearance_twice,
                    )
            })
    }) {
        return true;
    }
    if board.obstacles.iter().any(|obstacle| {
        obstacle.layers.contains(&zone.layer)
            && obstacle.net_id != Some(net_id)
            && corners.iter().any(|point| {
                geometry::point_rect_closer_than(
                    *point,
                    obstacle.min,
                    obstacle.max,
                    clearance_twice,
                )
            })
    }) {
        return true;
    }
    if board.round_obstacles.iter().any(|obstacle| {
        obstacle.layers.contains(&zone.layer)
            && obstacle.net_id != Some(net_id)
            && corners.iter().any(|point| {
                geometry::points_closer_than(
                    *point,
                    obstacle.center,
                    obstacle.diameter_nm + clearance_twice,
                )
            })
    }) {
        return true;
    }
    if board.routes.iter().any(|route| {
        route.net_id != net_id
            && route.segments.iter().any(|segment| {
                segment.layer == zone.layer
                    && corners.iter().any(|point| {
                        geometry::point_segment_closer_than(
                            *point,
                            segment.start,
                            segment.end,
                            segment.width_nm + clearance_twice,
                        )
                    })
            })
    }) {
        return true;
    }
    if zone.thermal_relief {
        for pad in board
            .footprints
            .iter()
            .flat_map(|footprint| &footprint.pads)
            .filter(|pad| pad.net_id == Some(net_id) && pad.layers.contains(&zone.layer))
        {
            let half_width = pad.width_nm / 2 + zone.thermal_gap_nm;
            let half_height = pad.height_nm / 2 + zone.thermal_gap_nm;
            let dx = (center.x_nm - pad.position.x_nm).abs();
            let dy = (center.y_nm - pad.position.y_nm).abs();
            if dx <= half_width
                && dy <= half_height
                && dx > zone.thermal_spoke_width_nm / 2
                && dy > zone.thermal_spoke_width_nm / 2
            {
                return true;
            }
        }
    }
    false
}

fn connected_zone_cells(
    board: &Board,
    net_id: u32,
    cells: HashSet<(Nm, Nm)>,
    grid: Nm,
) -> HashSet<(Nm, Nm)> {
    if cells.is_empty() {
        return cells;
    }
    let seeds: Vec<_> = board
        .nets
        .iter()
        .find(|net| net.id == net_id)
        .into_iter()
        .flat_map(|net| &net.terminals)
        .map(|terminal| {
            (
                nearest_grid(terminal.position.x_nm, grid),
                nearest_grid(terminal.position.y_nm, grid),
            )
        })
        .filter(|cell| cells.contains(cell))
        .collect();
    let start = seeds
        .first()
        .copied()
        .unwrap_or_else(|| *cells.iter().next().unwrap());
    let mut connected = HashSet::new();
    let mut queue = VecDeque::from([start]);
    while let Some(cell) = queue.pop_front() {
        if !cells.contains(&cell) || !connected.insert(cell) {
            continue;
        }
        for neighbor in [
            (cell.0 + 1, cell.1),
            (cell.0 - 1, cell.1),
            (cell.0, cell.1 + 1),
            (cell.0, cell.1 - 1),
        ] {
            queue.push_back(neighbor);
        }
    }
    connected
}

pub fn generate_route_teardrops(board: &mut Board) -> usize {
    let mut generated = 0;
    for route_index in 0..board.routes.len() {
        let net_id = board.routes[route_index].net_id;
        let vias = board.routes[route_index].vias.clone();
        let segments = board.routes[route_index].segments.clone();
        for via in vias {
            for segment in &segments {
                if !via.spans_layer(segment.layer) {
                    continue;
                }
                let other = if segment.start == via.position {
                    segment.end
                } else if segment.end == via.position {
                    segment.start
                } else {
                    continue;
                };
                let dx = (other.x_nm - via.position.x_nm) as f64;
                let dy = (other.y_nm - via.position.y_nm) as f64;
                let span = dx.hypot(dy);
                let length = via.diameter_nm.max(3 * segment.width_nm) as f64;
                if span < length || span == 0.0 {
                    continue;
                }
                let (ux, uy) = (dx / span, dy / span);
                let (px, py) = (-uy, ux);
                let base_half = via.diameter_nm as f64 * 0.45;
                let tip_half = segment.width_nm as f64 / 2.0;
                let tip_x = via.position.x_nm as f64 + ux * length;
                let tip_y = via.position.y_nm as f64 + uy * length;
                let polygon = vec![
                    Point {
                        x_nm: (via.position.x_nm as f64 + px * base_half).round() as Nm,
                        y_nm: (via.position.y_nm as f64 + py * base_half).round() as Nm,
                    },
                    Point {
                        x_nm: (tip_x + px * tip_half).round() as Nm,
                        y_nm: (tip_y + py * tip_half).round() as Nm,
                    },
                    Point {
                        x_nm: (tip_x - px * tip_half).round() as Nm,
                        y_nm: (tip_y - py * tip_half).round() as Nm,
                    },
                    Point {
                        x_nm: (via.position.x_nm as f64 - px * base_half).round() as Nm,
                        y_nm: (via.position.y_nm as f64 - py * base_half).round() as Nm,
                    },
                ];
                if polygon
                    .iter()
                    .any(|point| !board.point_inside_board(*point, 0))
                    || board.routes[route_index].teardrops.iter().any(|teardrop| {
                        teardrop.layer == segment.layer && teardrop.polygon == polygon
                    })
                {
                    continue;
                }
                board.routes[route_index].teardrops.push(Teardrop {
                    polygon,
                    layer: segment.layer,
                });
                let invalid = checking::check_board(board)
                    .violations
                    .iter()
                    .any(|violation| violation.net_ids.contains(&net_id));
                if invalid {
                    board.routes[route_index].teardrops.pop();
                } else {
                    generated += 1;
                }
            }
        }
    }
    generated
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

/// Pushes the movable interior geometry of one route by a local offset.
///
/// Net terminals remain fixed, shared interior vertices move together, and
/// the edit is committed only when the complete board passes checking.
pub fn shove_route(board: &mut Board, net_id: u32, offset: Point) -> Result<(), String> {
    let grid = board.rules_for_net(net_id).grid_nm;
    if offset == Point::default() || offset.x_nm % grid != 0 || offset.y_nm % grid != 0 {
        return Err("shove offset must be a non-zero grid multiple".into());
    }
    let route_index = board
        .routes
        .iter()
        .position(|route| route.net_id == net_id)
        .ok_or_else(|| format!("net {net_id} has no route"))?;
    let candidate = shoved_route_candidate(board, &board.routes[route_index], offset)?;
    let original = std::mem::replace(&mut board.routes[route_index], candidate);
    let report = checking::check_board(board);
    if report.is_clean() {
        Ok(())
    } else {
        board.routes[route_index] = original;
        Err(format!(
            "shove for net {net_id} rejected by board rules: {}",
            report
                .violations
                .iter()
                .map(|violation| violation.rule.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

fn shoved_route_candidate(board: &Board, route: &Route, offset: Point) -> Result<Route, String> {
    let terminals: HashSet<Point> = board
        .nets
        .iter()
        .find(|net| net.id == route.net_id)
        .ok_or_else(|| format!("unknown net {}", route.net_id))?
        .terminals
        .iter()
        .map(|terminal| terminal.position)
        .collect();
    let mut candidate = route.clone();
    let move_point = |point| {
        if terminals.contains(&point) {
            point
        } else {
            translate_point(point, offset)
        }
    };
    for segment in &mut candidate.segments {
        segment.start = move_point(segment.start);
        segment.end = move_point(segment.end);
    }
    for arc in &mut candidate.arcs {
        arc.start = move_point(arc.start);
        arc.mid = move_point(arc.mid);
        arc.end = move_point(arc.end);
    }
    for via in &mut candidate.vias {
        via.position = move_point(via.position);
    }
    for teardrop in &mut candidate.teardrops {
        for point in &mut teardrop.polygon {
            *point = move_point(*point);
        }
    }
    for zone in &mut candidate.zones {
        for point in &mut zone.polygon {
            *point = move_point(*point);
        }
    }
    if candidate == *route && route.segments.len() == 1 {
        let segment = &route.segments[0];
        let dx = segment.end.x_nm - segment.start.x_nm;
        let dy = segment.end.y_nm - segment.start.y_nm;
        let perpendicular = (dx == 0 && offset.y_nm == 0) || (dy == 0 && offset.x_nm == 0);
        let shoulder = offset.x_nm.abs().max(offset.y_nm.abs());
        let span = dx.abs().max(dy.abs());
        if perpendicular && shoulder > 0 && span > 2 * shoulder {
            let one = Point {
                x_nm: segment.start.x_nm + dx.signum() * shoulder + offset.x_nm,
                y_nm: segment.start.y_nm + dy.signum() * shoulder + offset.y_nm,
            };
            let two = Point {
                x_nm: segment.end.x_nm - dx.signum() * shoulder + offset.x_nm,
                y_nm: segment.end.y_nm - dy.signum() * shoulder + offset.y_nm,
            };
            candidate.segments = [segment.start, one, two, segment.end]
                .windows(2)
                .map(|points| Segment {
                    start: points[0],
                    end: points[1],
                    layer: segment.layer,
                    width_nm: segment.width_nm,
                })
                .collect();
        }
    }
    if candidate == *route {
        Err(format!(
            "route for net {} has no movable interior geometry",
            route.net_id
        ))
    } else {
        Ok(candidate)
    }
}

pub fn tune_differential_pairs_synchronously(board: &mut Board) -> Result<(), String> {
    for pair in board.differential_pairs.clone() {
        let Some(minimum) = pair.minimum_length_nm else {
            continue;
        };
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
        let (Some(positive_net), Some(negative_net)) = (
            board.nets.iter().find(|net| net.id == pair.positive_net_id),
            board.nets.iter().find(|net| net.id == pair.negative_net_id),
        ) else {
            continue;
        };
        let (Some(positive_terminal), Some(negative_terminal)) = (
            positive_net.terminals.first(),
            negative_net.terminals.first(),
        ) else {
            continue;
        };
        let offset = Point {
            x_nm: negative_terminal.position.x_nm - positive_terminal.position.x_nm,
            y_nm: negative_terminal.position.y_nm - positive_terminal.position.y_nm,
        };
        let grid = board.rules_for_net(pair.positive_net_id).grid_nm;
        let pitch = pair.tuning_pitch_nm.unwrap_or(2 * grid).max(grid);
        for section in 0..pair.max_tuning_sections {
            let current = route_length_nm(&board.routes[positive_index]);
            if current >= minimum {
                break;
            }
            let remaining = Nm::from(pair.max_tuning_sections - section);
            let distributed = (minimum - current + 2 * remaining - 1) / (2 * remaining);
            let amplitude = pair
                .tuning_amplitude_nm
                .unwrap_or(distributed)
                .min((minimum - current + 1) / 2)
                .max(grid);
            let amplitude = ((amplitude + grid - 1) / grid) * grid;
            let original_positive = board.routes[positive_index].clone();
            let original_negative = board.routes[negative_index].clone();
            let mut accepted = false;
            for segment_index in (0..original_positive.segments.len()).rev() {
                let segment = &original_positive.segments[segment_index];
                let dx = segment.end.x_nm - segment.start.x_nm;
                let dy = segment.end.y_nm - segment.start.y_nm;
                if (dx != 0 && dy != 0) || dx.abs().max(dy.abs()) < 2 * pitch {
                    continue;
                }
                for direction in [1, -1] {
                    let one = Point {
                        x_nm: segment.start.x_nm + dx / 2 - dx.signum() * pitch / 2,
                        y_nm: segment.start.y_nm + dy / 2 - dy.signum() * pitch / 2,
                    };
                    let two = Point {
                        x_nm: segment.start.x_nm + dx / 2 + dx.signum() * pitch / 2,
                        y_nm: segment.start.y_nm + dy / 2 + dy.signum() * pitch / 2,
                    };
                    let meander_offset = if dx == 0 {
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
                        translate_point(one, meander_offset),
                        translate_point(two, meander_offset),
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
                    let mut candidate = original_positive.clone();
                    candidate
                        .segments
                        .splice(segment_index..=segment_index, replacement);
                    let mut translated = translate_route(&candidate, offset);
                    translated.net_id = pair.negative_net_id;
                    board.routes[positive_index] = candidate;
                    board.routes[negative_index] = translated;
                    let check = crate::checking::check_board(board);
                    if check.violations.iter().all(|violation| {
                        violation.rule == "trace_length" || violation.rule == "length_group_skew"
                    }) {
                        accepted = true;
                        break;
                    }
                }
                if accepted {
                    break;
                }
            }
            if !accepted {
                board.routes[positive_index] = original_positive;
                board.routes[negative_index] = original_negative;
                break;
            }
        }
        if route_length_nm(&board.routes[positive_index]) < minimum
            || route_length_nm(&board.routes[negative_index]) < minimum
        {
            return Err(format!(
                "unable to synchronously tune differential pair {} to {minimum} nm",
                pair.name
            ));
        }
    }
    Ok(())
}

pub fn tune_route_lengths(board: &mut Board) -> Result<(), String> {
    let defaults = TuningProfile {
        amplitude_nm: None,
        pitch_nm: None,
        max_sections: 1,
    };
    for route_index in 0..board.routes.len() {
        let net_id = board.routes[route_index].net_id;
        let (minimum, maximum) = board.length_limits_for_net(net_id);
        let Some(minimum) = minimum else { continue };
        tune_route_to_minimum(board, route_index, minimum, maximum, defaults)?;
    }
    for group in board.length_groups.clone() {
        let target = board
            .routes
            .iter()
            .filter(|route| group.net_ids.contains(&route.net_id))
            .map(route_length_nm)
            .max();
        let Some(target) = target else { continue };
        for net_id in group.net_ids {
            let Some(route_index) = board.routes.iter().position(|route| route.net_id == net_id)
            else {
                continue;
            };
            if route_length_nm(&board.routes[route_index]) + group.max_skew_nm < target {
                tune_route_to_minimum(
                    board,
                    route_index,
                    target - group.max_skew_nm,
                    board.length_limits_for_net(net_id).1,
                    TuningProfile {
                        amplitude_nm: group.tuning_amplitude_nm,
                        pitch_nm: group.tuning_pitch_nm,
                        max_sections: group.max_tuning_sections,
                    },
                )?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct TuningProfile {
    amplitude_nm: Option<Nm>,
    pitch_nm: Option<Nm>,
    max_sections: u8,
}

fn tune_route_to_minimum(
    board: &mut Board,
    route_index: usize,
    minimum: Nm,
    maximum: Option<Nm>,
    profile: TuningProfile,
) -> Result<(), String> {
    let net_id = board.routes[route_index].net_id;
    let current = route_length_nm(&board.routes[route_index]);
    if current >= minimum {
        return Ok(());
    }
    let grid = board.rules_for_net(net_id).grid_nm;
    let pitch = profile.pitch_nm.unwrap_or(2 * grid).max(grid);
    for section in 0..profile.max_sections {
        let current = route_length_nm(&board.routes[route_index]);
        if current >= minimum {
            break;
        }
        let remaining_sections = Nm::from(profile.max_sections - section);
        let distributed =
            (minimum - current + 2 * remaining_sections - 1) / (2 * remaining_sections);
        let amplitude = profile
            .amplitude_nm
            .unwrap_or(distributed)
            .min((minimum - current + 1) / 2)
            .max(grid);
        let amplitude = ((amplitude + grid - 1) / grid) * grid;
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
            if span < 2 * pitch {
                continue;
            }
            for direction in [1, -1] {
                let mut candidate = original.clone();
                let one = Point {
                    x_nm: segment.start.x_nm + dx / 2 - dx.signum() * pitch / 2,
                    y_nm: segment.start.y_nm + dy / 2 - dy.signum() * pitch / 2,
                };
                let two = Point {
                    x_nm: segment.start.x_nm + dx / 2 + dx.signum() * pitch / 2,
                    y_nm: segment.start.y_nm + dy / 2 + dy.signum() * pitch / 2,
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
                    violation.rule == "trace_length" || violation.rule == "length_group_skew"
                }) && maximum.is_none_or(|limit| route_length_nm(&candidate) <= limit)
                {
                    tuned = Some(candidate);
                    break;
                }
            }
            if tuned.is_some() {
                board.routes[route_index] = tuned.clone().unwrap();
                break;
            }
        }
        if tuned.is_none() {
            board.routes[route_index] = original;
            break;
        }
    }
    if route_length_nm(&board.routes[route_index]) >= minimum {
        Ok(())
    } else {
        Err(format!(
            "unable to satisfy minimum length for net {net_id} with {} legal meander sections",
            profile.max_sections
        ))
    }
}

pub fn route_length_nm(route: &Route) -> Nm {
    let segment_length: Nm = route
        .segments
        .iter()
        .map(|segment| {
            let dx = (segment.end.x_nm - segment.start.x_nm) as f64;
            let dy = (segment.end.y_nm - segment.start.y_nm) as f64;
            dx.hypot(dy).round() as Nm
        })
        .sum();
    segment_length + route.arcs.iter().map(arc_length_nm).sum::<Nm>()
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
        for arc in &r.arcs {
            let color = if arc.layer == Layer::Front {
                "#e44"
            } else {
                "#48e"
            };
            let points = arc_polyline(arc, 10_000)
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
                r##"<polyline points="{points}" fill="none" stroke="{color}" stroke-width="{}" stroke-linecap="round" stroke-linejoin="round"/>"##,
                arc.width_nm as f64 / scale
            ));
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
            schema_version: CURRENT_SCHEMA_VERSION,
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
            length_groups: vec![],
            escape_groups: vec![],
            manufacturing_rules: None,
            return_path_rules: vec![],
            power_net_rules: vec![],
            stackup: vec![],
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
    fn locally_shoves_only_route_interior_and_rolls_back_invalid_edits() {
        let mut board = board();
        board.obstacles.clear();
        board.routes.push(Route {
            net_id: 1,
            segments: vec![
                Segment {
                    start: Point {
                        x_nm: 1_000_000,
                        y_nm: 1_000_000,
                    },
                    end: Point {
                        x_nm: 4_000_000,
                        y_nm: 3_500_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
                Segment {
                    start: Point {
                        x_nm: 4_000_000,
                        y_nm: 3_500_000,
                    },
                    end: Point {
                        x_nm: 6_000_000,
                        y_nm: 3_500_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
                Segment {
                    start: Point {
                        x_nm: 6_000_000,
                        y_nm: 3_500_000,
                    },
                    end: Point {
                        x_nm: 9_000_000,
                        y_nm: 1_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
            ],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });

        shove_route(
            &mut board,
            1,
            Point {
                x_nm: 0,
                y_nm: 500_000,
            },
        )
        .unwrap();

        assert_eq!(
            board.routes[0].segments[0].start,
            board.nets[0].terminals[0].position
        );
        assert_eq!(board.routes[0].segments[0].end.y_nm, 4_000_000);
        assert!(checking::check_board(&board).is_clean());
        let accepted = board.routes[0].clone();
        assert!(
            shove_route(
                &mut board,
                1,
                Point {
                    x_nm: 0,
                    y_nm: 7_000_000,
                },
            )
            .is_err()
        );
        assert_eq!(board.routes[0], accepted);
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
    fn checks_and_stitches_signal_return_vias() {
        let mut board = board();
        board.obstacles.clear();
        board.nets[0].terminals = vec![
            Terminal {
                position: Point {
                    x_nm: 1_000_000,
                    y_nm: 1_000_000,
                },
                layers: vec![Layer::Front],
            },
            Terminal {
                position: Point {
                    x_nm: 9_000_000,
                    y_nm: 1_000_000,
                },
                layers: vec![Layer::Back],
            },
        ];
        board.nets.push(Net {
            id: 2,
            name: "GND".into(),
            class: None,
            priority: 0,
            terminals: vec![
                Terminal {
                    position: Point {
                        x_nm: 1_000_000,
                        y_nm: 3_000_000,
                    },
                    layers: vec![Layer::Front],
                },
                Terminal {
                    position: Point {
                        x_nm: 9_000_000,
                        y_nm: 3_000_000,
                    },
                    layers: vec![Layer::Front],
                },
            ],
        });
        board.routes = vec![
            Route {
                net_id: 1,
                segments: vec![
                    Segment {
                        start: Point {
                            x_nm: 1_000_000,
                            y_nm: 1_000_000,
                        },
                        end: Point {
                            x_nm: 5_000_000,
                            y_nm: 1_000_000,
                        },
                        layer: Layer::Front,
                        width_nm: 250_000,
                    },
                    Segment {
                        start: Point {
                            x_nm: 5_000_000,
                            y_nm: 1_000_000,
                        },
                        end: Point {
                            x_nm: 9_000_000,
                            y_nm: 1_000_000,
                        },
                        layer: Layer::Back,
                        width_nm: 250_000,
                    },
                ],
                arcs: vec![],
                vias: vec![Via {
                    position: Point {
                        x_nm: 5_000_000,
                        y_nm: 1_000_000,
                    },
                    diameter_nm: 600_000,
                    drill_nm: 300_000,
                    kind: ViaKind::Through,
                    start_layer: Layer::Front,
                    end_layer: Layer::Back,
                }],
                teardrops: vec![],
                zones: vec![],
            },
            Route {
                net_id: 2,
                segments: vec![Segment {
                    start: Point {
                        x_nm: 1_000_000,
                        y_nm: 3_000_000,
                    },
                    end: Point {
                        x_nm: 9_000_000,
                        y_nm: 3_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                }],
                arcs: vec![],
                vias: vec![],
                teardrops: vec![],
                zones: vec![],
            },
        ];
        board.return_path_rules.push(ReturnPathRule {
            name: "high-speed reference".into(),
            signal_net_ids: vec![1],
            reference_net_id: 2,
            max_via_distance_nm: 1_000_000,
            auto_stitch: true,
            require_continuous_plane: false,
            plane_sample_spacing_nm: None,
        });

        assert!(
            checking::check_board(&board)
                .violations
                .iter()
                .any(|violation| violation.rule == "return_path")
        );
        assert_eq!(stitch_return_paths(&mut board), 1);
        assert!(checking::check_board(&board).is_clean());
        assert_eq!(board.routes[1].vias.len(), 1);
    }

    #[test]
    fn detects_reference_plane_gaps_and_stitches_directly_to_zones() {
        let mut board = board();
        board.obstacles.clear();
        board.nets[0].terminals[0].layers = vec![Layer::Front];
        board.nets[0].terminals[1].layers = vec![Layer::Front];
        board.nets.push(Net {
            id: 2,
            name: "GND".into(),
            class: None,
            priority: 0,
            terminals: vec![Terminal {
                position: Point {
                    x_nm: 1_000_000,
                    y_nm: 2_000_000,
                },
                layers: vec![Layer::Back],
            }],
        });
        board.stackup.push(StackupLayer {
            layer: Layer::Front,
            dielectric_height_nm: 200_000,
            dielectric_constant: 4.2,
            copper_thickness_nm: 35_000,
            reference_layer: Some(Layer::Back),
            secondary_reference_layer: None,
            secondary_dielectric_height_nm: None,
            secondary_dielectric_constant: None,
        });
        let plane = CopperZone {
            polygon: vec![
                Point { x_nm: 0, y_nm: 0 },
                Point {
                    x_nm: 10_000_000,
                    y_nm: 0,
                },
                Point {
                    x_nm: 10_000_000,
                    y_nm: 10_000_000,
                },
                Point {
                    x_nm: 0,
                    y_nm: 10_000_000,
                },
            ],
            layer: Layer::Back,
            clearance_nm: 200_000,
            minimum_thickness_nm: 250_000,
            thermal_relief: false,
            thermal_gap_nm: 0,
            thermal_spoke_width_nm: 0,
            filled_polygons: vec![
                vec![
                    Point { x_nm: 0, y_nm: 0 },
                    Point {
                        x_nm: 4_000_000,
                        y_nm: 0,
                    },
                    Point {
                        x_nm: 4_000_000,
                        y_nm: 10_000_000,
                    },
                    Point {
                        x_nm: 0,
                        y_nm: 10_000_000,
                    },
                ],
                vec![
                    Point {
                        x_nm: 6_000_000,
                        y_nm: 0,
                    },
                    Point {
                        x_nm: 10_000_000,
                        y_nm: 0,
                    },
                    Point {
                        x_nm: 10_000_000,
                        y_nm: 10_000_000,
                    },
                    Point {
                        x_nm: 6_000_000,
                        y_nm: 10_000_000,
                    },
                ],
            ],
        };
        board.routes = vec![
            Route {
                net_id: 1,
                segments: vec![Segment {
                    start: board.nets[0].terminals[0].position,
                    end: board.nets[0].terminals[1].position,
                    layer: Layer::Front,
                    width_nm: 250_000,
                }],
                arcs: vec![],
                vias: vec![],
                teardrops: vec![],
                zones: vec![],
            },
            Route {
                net_id: 2,
                segments: vec![],
                arcs: vec![],
                vias: vec![],
                teardrops: vec![],
                zones: vec![plane],
            },
        ];
        board.return_path_rules.push(ReturnPathRule {
            name: "plane".into(),
            signal_net_ids: vec![1],
            reference_net_id: 2,
            max_via_distance_nm: 1_000_000,
            auto_stitch: true,
            require_continuous_plane: true,
            plane_sample_spacing_nm: Some(250_000),
        });

        assert!(
            checking::check_board(&board)
                .violations
                .iter()
                .any(|violation| violation.rule == "return_path_plane")
        );

        board.routes[1].zones[0].filled_polygons.clear();
        board.return_path_rules[0].require_continuous_plane = false;
        board.routes[0].segments = vec![
            Segment {
                start: board.nets[0].terminals[0].position,
                end: Point {
                    x_nm: 5_000_000,
                    y_nm: 1_000_000,
                },
                layer: Layer::Front,
                width_nm: 250_000,
            },
            Segment {
                start: Point {
                    x_nm: 5_000_000,
                    y_nm: 1_000_000,
                },
                end: board.nets[0].terminals[1].position,
                layer: Layer::Back,
                width_nm: 250_000,
            },
        ];
        board.nets[0].terminals[1].layers = vec![Layer::Back];
        board.routes[0].vias.push(Via {
            position: Point {
                x_nm: 5_000_000,
                y_nm: 1_000_000,
            },
            diameter_nm: 600_000,
            drill_nm: 300_000,
            kind: ViaKind::Through,
            start_layer: Layer::Front,
            end_layer: Layer::Back,
        });

        assert_eq!(stitch_return_paths(&mut board), 1);
        assert!(board.routes[1].segments.is_empty());
        assert_eq!(board.routes[1].vias.len(), 1);
        assert!(checking::check_board(&board).is_clean());
    }

    #[test]
    fn automatically_rounds_a_checked_right_angle() {
        let mut board = board();
        board.obstacles.clear();
        board.nets[0].terminals[1].position = Point {
            x_nm: 5_000_000,
            y_nm: 5_000_000,
        };
        board.routes.push(Route {
            net_id: 1,
            segments: vec![
                Segment {
                    start: Point {
                        x_nm: 1_000_000,
                        y_nm: 1_000_000,
                    },
                    end: Point {
                        x_nm: 5_000_000,
                        y_nm: 1_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
                Segment {
                    start: Point {
                        x_nm: 5_000_000,
                        y_nm: 1_000_000,
                    },
                    end: Point {
                        x_nm: 5_000_000,
                        y_nm: 5_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
            ],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });

        assert_eq!(
            round_route_corners(&mut board, &HashSet::from([1]), 500_000),
            1
        );
        assert_eq!(board.routes[0].arcs.len(), 1);
        assert!(arc_is_valid(&board.routes[0].arcs[0]));
        assert!(checking::check_board(&board).is_clean());
    }

    #[test]
    fn checks_stackup_impedance_against_net_class_target() {
        let mut board = board();
        board.obstacles.clear();
        board.nets[0].class = Some("Controlled".into());
        let estimated = estimated_impedance_ohms(250_000, 200_000, 4.0).unwrap();
        board.net_classes.insert(
            "Controlled".into(),
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
                target_impedance_ohms: Some(estimated),
                impedance_tolerance_ohms: Some(1.0),
            },
        );
        board.stackup.push(StackupLayer {
            layer: Layer::Front,
            dielectric_height_nm: 200_000,
            dielectric_constant: 4.0,
            copper_thickness_nm: 0,
            reference_layer: Some(Layer::Back),
            secondary_reference_layer: None,
            secondary_dielectric_height_nm: None,
            secondary_dielectric_constant: None,
        });
        board.routes.push(Route {
            net_id: 1,
            segments: vec![Segment {
                start: board.nets[0].terminals[0].position,
                end: board.nets[0].terminals[1].position,
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });

        assert!(checking::check_board(&board).is_clean());
        board
            .net_classes
            .get_mut("Controlled")
            .unwrap()
            .target_impedance_ohms = Some(50.0);
        assert!(
            checking::check_board(&board)
                .violations
                .iter()
                .any(|violation| violation.rule == "impedance")
        );
    }

    #[test]
    fn estimates_symmetric_and_asymmetric_embedded_impedance() {
        let symmetric =
            estimated_embedded_impedance_ohms(150_000, 200_000, 200_000, 35_000, 4.2, 4.2).unwrap();
        let asymmetric =
            estimated_embedded_impedance_ohms(150_000, 100_000, 300_000, 35_000, 3.5, 4.5).unwrap();

        assert!(symmetric > 0.0);
        assert!(asymmetric > 0.0);
        assert!((symmetric - asymmetric).abs() > 0.1);
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
    fn migrates_legacy_board_json_and_rejects_unknown_versions_and_fields() {
        let legacy = r#"{
            "board_width_nm": 10000000,
            "board_height_nm": 8000000,
            "rules": {
                "grid_nm": 250000,
                "track_width_nm": 250000,
                "clearance_nm": 200000,
                "via_diameter_nm": 600000,
                "via_drill_nm": 300000,
                "bend_cost": 5,
                "via_cost": 20
            },
            "signals": []
        }"#;
        let board = parse_board_json(legacy).unwrap();
        assert_eq!(board.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(board.width_nm, 10_000_000);
        assert!(board.nets.is_empty());
        let migrated = migrate_board_json(legacy).unwrap();
        assert_eq!(
            migrated["schema_version"],
            serde_json::json!(CURRENT_SCHEMA_VERSION)
        );
        assert!(migrated.get("board_width_nm").is_none());
        let reparsed = parse_board_json(&migrated.to_string()).unwrap();
        assert_eq!(
            serde_json::to_value(&board).unwrap(),
            serde_json::to_value(&reparsed).unwrap(),
            "v1 migration and native v2 parsing must be semantically identical"
        );
        assert!(
            parse_board_json(r#"{"schema_version":99}"#)
                .unwrap_err()
                .contains("unsupported board schema version")
        );
        let unknown = legacy.replace("\"signals\": []", "\"signals\": [], \"typo\": true");
        assert!(
            parse_board_json(&unknown)
                .unwrap_err()
                .contains("unknown field")
        );
        assert_eq!(
            board_json_schema()["properties"]["schema_version"]["const"],
            serde_json::json!(CURRENT_SCHEMA_VERSION)
        );
        let schema = board_json_schema();
        for property in [
            "rules",
            "net_classes",
            "length_groups",
            "escape_groups",
            "return_path_rules",
            "stackup",
        ] {
            assert!(schema["properties"].get(property).is_some());
        }
        for definition in [
            "rules",
            "net_class",
            "length_group",
            "escape_group",
            "return_path_rule",
            "stackup_layer",
        ] {
            assert_eq!(
                schema["$defs"][definition]["additionalProperties"],
                serde_json::json!(false)
            );
        }
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
        let (routed, report) = route_board_with_workers(&b, 1).unwrap();
        let (routed_again, repeated_report) = route_board_with_workers(&b, 8).unwrap();
        assert!(report.unrouted.is_empty(), "{:?}", report.unrouted);
        assert_eq!(report.parallel_candidates, 10);
        assert_eq!(repeated_report.parallel_candidates, 10);
        assert_eq!(report.parallel_workers, 1);
        assert_eq!(repeated_report.parallel_workers, 8);
        assert_eq!(
            serde_json::to_vec(&routed).unwrap(),
            serde_json::to_vec(&routed_again).unwrap()
        );
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
                target_impedance_ohms: None,
                impedance_tolerance_ohms: None,
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
                target_impedance_ohms: None,
                impedance_tolerance_ohms: None,
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
    fn automatic_shove_moves_a_blocker_before_routing_the_failed_net() {
        let mut b = board();
        b.obstacles.clear();
        b.copper_layers = vec![Layer::Front];
        let terminals = |start_x, end_x, y_nm| {
            vec![
                Terminal {
                    position: Point {
                        x_nm: start_x,
                        y_nm,
                    },
                    layers: vec![Layer::Front],
                },
                Terminal {
                    position: Point { x_nm: end_x, y_nm },
                    layers: vec![Layer::Front],
                },
            ]
        };
        b.nets = vec![
            Net {
                id: 1,
                name: "blocker".into(),
                class: None,
                priority: 1,
                terminals: terminals(3_000_000, 7_000_000, 5_000_000),
            },
            Net {
                id: 2,
                name: "target".into(),
                class: None,
                priority: 0,
                terminals: terminals(1_000_000, 9_000_000, 6_000_000),
            },
        ];
        let accepted = vec![Route {
            net_id: 1,
            segments: vec![Segment {
                start: b.nets[0].terminals[0].position,
                end: b.nets[0].terminals[1].position,
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        }];

        let (blocker_id, shoved, routed, _) =
            try_automatic_shove(&b, &accepted, &b.nets[1], &HashSet::from([1]))
                .expect("a legal shove should make room for the target");

        assert_eq!(blocker_id, 1);
        assert!(shoved.segments.len() > accepted[0].segments.len());
        let mut checked = b;
        checked.routes = vec![shoved, routed];
        assert!(checking::check_board(&checked).is_clean());
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
            tracks_not_allowed: true,
            vias_not_allowed: true,
            zones_not_allowed: true,
            footprints_not_allowed: false,
            minimum_track_width_nm: None,
            minimum_clearance_nm: None,
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
                target_impedance_ohms: None,
                impedance_tolerance_ohms: None,
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
    fn routes_around_unsatisfied_local_rule_area_constraints() {
        let mut b = board();
        b.obstacles.clear();
        b.copper_layers = vec![Layer::Front];
        b.nets[0].terminals.iter_mut().for_each(|terminal| {
            terminal.layers = vec![Layer::Front];
            terminal.position.y_nm = 5_000_000;
        });
        b.keepouts.push(Keepout {
            polygon: vec![
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
            ],
            layers: vec![Layer::Front],
            net_id: None,
            tracks_not_allowed: false,
            vias_not_allowed: false,
            zones_not_allowed: false,
            footprints_not_allowed: false,
            minimum_track_width_nm: Some(500_000),
            minimum_clearance_nm: Some(400_000),
        });

        let (routed, report) = route_board(&b).unwrap();

        assert!(report.unrouted.is_empty());
        assert!(checking::check_board(&routed).is_clean());
        assert!(routed.routes[0].segments.iter().all(|segment| {
            let midpoint = Point {
                x_nm: segment.start.x_nm + (segment.end.x_nm - segment.start.x_nm) / 2,
                y_nm: segment.start.y_nm + (segment.end.y_nm - segment.start.y_nm) / 2,
            };
            !geometry::point_in_polygon(midpoint, &b.keepouts[0].polygon)
        }));
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
                target_impedance_ohms: None,
                impedance_tolerance_ohms: None,
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
                target_impedance_ohms: None,
                impedance_tolerance_ohms: None,
            },
        );

        let (routed, report) = route_board(&board).unwrap();

        assert!(report.unrouted.is_empty());
        assert!(crate::checking::check_board(&routed).is_clean());
        assert!((10_000_000..=11_000_000).contains(&route_length_nm(&routed.routes[0])));
        assert!(routed.routes[0].segments.len() >= 5);
    }

    #[test]
    fn distributes_length_tuning_across_multiple_sections() {
        let mut board = board();
        board.obstacles.clear();
        board.nets[0].terminals[0].position = Point {
            x_nm: 1_000_000,
            y_nm: 5_000_000,
        };
        board.nets[0].terminals[1].position = Point {
            x_nm: 9_000_000,
            y_nm: 5_000_000,
        };
        board.routes.push(Route {
            net_id: 1,
            segments: vec![Segment {
                start: board.nets[0].terminals[0].position,
                end: board.nets[0].terminals[1].position,
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });

        tune_route_to_minimum(
            &mut board,
            0,
            11_000_000,
            Some(12_000_000),
            TuningProfile {
                amplitude_nm: Some(500_000),
                pitch_nm: Some(1_000_000),
                max_sections: 3,
            },
        )
        .unwrap();

        assert_eq!(route_length_nm(&board.routes[0]), 11_000_000);
        assert_eq!(board.routes[0].segments.len(), 13);
        assert!(checking::check_board(&board).is_clean());
    }

    #[test]
    fn tunes_parallel_bus_members_to_the_group_skew() {
        let mut board = board();
        board.obstacles.clear();
        board.nets = vec![
            Net {
                id: 1,
                name: "D0".into(),
                class: None,
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 1_000_000,
                            y_nm: 3_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: Point {
                            x_nm: 5_000_000,
                            y_nm: 3_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                ],
            },
            Net {
                id: 2,
                name: "D1".into(),
                class: None,
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 1_000_000,
                            y_nm: 7_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: Point {
                            x_nm: 9_000_000,
                            y_nm: 7_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                ],
            },
        ];
        board.length_groups.push(LengthGroup {
            name: "DATA".into(),
            net_ids: vec![1, 2],
            max_skew_nm: 500_000,
            tuning_amplitude_nm: None,
            tuning_pitch_nm: None,
            max_tuning_sections: 1,
        });

        let (routed, report) = route_board(&board).unwrap();
        let lengths: Vec<_> = routed.routes.iter().map(route_length_nm).collect();

        assert!(report.unrouted.is_empty());
        assert!(crate::checking::check_board(&routed).is_clean());
        assert!(lengths.iter().max().unwrap() - lengths.iter().min().unwrap() <= 500_000);
        assert!(
            routed
                .routes
                .iter()
                .find(|route| route.net_id == 1)
                .unwrap()
                .segments
                .len()
                >= 5
        );
    }

    #[test]
    fn generates_bga_dogbones_before_global_inner_layer_routing() {
        let mut board = board();
        board.obstacles.clear();
        board.copper_layers = vec![Layer::Front, Layer::Inner(1), Layer::Back];
        board.round_obstacles = [
            (3_000_000, 3_000_000),
            (4_000_000, 4_000_000),
            (5_000_000, 3_000_000),
            (4_000_000, 2_000_000),
            (7_000_000, 3_000_000),
            (6_000_000, 4_000_000),
            (6_000_000, 2_000_000),
        ]
        .into_iter()
        .map(|(x_nm, y_nm)| RoundObstacle {
            center: Point { x_nm, y_nm },
            diameter_nm: 200_000,
            layers: vec![Layer::Inner(1)],
            net_id: None,
        })
        .collect();
        board.nets = vec![
            Net {
                id: 1,
                name: "BGA1".into(),
                class: None,
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 4_000_000,
                            y_nm: 3_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: Point {
                            x_nm: 3_000_000,
                            y_nm: 9_000_000,
                        },
                        layers: vec![Layer::Inner(1)],
                    },
                ],
            },
            Net {
                id: 2,
                name: "BGA2".into(),
                class: None,
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 6_000_000,
                            y_nm: 3_000_000,
                        },
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: Point {
                            x_nm: 7_000_000,
                            y_nm: 9_000_000,
                        },
                        layers: vec![Layer::Inner(1)],
                    },
                ],
            },
        ];
        board.escape_groups.push(EscapeGroup {
            name: "U1".into(),
            net_ids: vec![1, 2],
            fanout_distance_nm: 1_000_000,
            target_layer: Layer::Inner(1),
            direction: EscapeDirection::FourWay,
            via_grid_nm: Some(500_000),
            max_rings: 3,
        });

        let (routed, report) = route_board(&board).unwrap();

        assert!(report.unrouted.is_empty());
        assert_eq!(report.escaped_nets, 2);
        assert!(checking::check_board(&routed).is_clean());
        for route in &routed.routes {
            assert!(route.vias.iter().any(|via| via.kind == ViaKind::Micro));
            assert!(route.segments.iter().any(|segment| {
                segment.layer == Layer::Front
                    && segment.start
                        == board
                            .nets
                            .iter()
                            .find(|net| net.id == route.net_id)
                            .unwrap()
                            .terminals[0]
                            .position
            }));
            assert!(
                route
                    .segments
                    .iter()
                    .any(|segment| segment.layer == Layer::Inner(1))
            );
            let via = route
                .vias
                .iter()
                .find(|via| via.kind == ViaKind::Micro)
                .unwrap();
            assert!(
                (via.position.x_nm - 5_000_000).abs() >= 3_000_000,
                "ring-one candidates should be blocked: {:?}",
                via.position
            );
        }
    }

    #[test]
    fn local_repair_reroutes_only_the_violating_net() {
        let mut board = board();
        board.obstacles = vec![Obstacle {
            min: Point {
                x_nm: 4_000_000,
                y_nm: 2_000_000,
            },
            max: Point {
                x_nm: 6_000_000,
                y_nm: 4_000_000,
            },
            layers: both_layers(),
            net_id: None,
        }];
        board.nets = vec![
            Net {
                id: 1,
                name: "broken".into(),
                class: None,
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 1_000_000,
                            y_nm: 3_000_000,
                        },
                        layers: both_layers(),
                    },
                    Terminal {
                        position: Point {
                            x_nm: 9_000_000,
                            y_nm: 3_000_000,
                        },
                        layers: both_layers(),
                    },
                ],
            },
            Net {
                id: 2,
                name: "locked".into(),
                class: None,
                priority: 0,
                terminals: vec![
                    Terminal {
                        position: Point {
                            x_nm: 1_000_000,
                            y_nm: 8_000_000,
                        },
                        layers: both_layers(),
                    },
                    Terminal {
                        position: Point {
                            x_nm: 9_000_000,
                            y_nm: 8_000_000,
                        },
                        layers: both_layers(),
                    },
                ],
            },
        ];
        let direct = |net_id, y_nm| Route {
            net_id,
            segments: vec![Segment {
                start: Point {
                    x_nm: 1_000_000,
                    y_nm,
                },
                end: Point {
                    x_nm: 9_000_000,
                    y_nm,
                },
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        };
        board.routes = vec![direct(1, 3_000_000), direct(2, 8_000_000)];
        let locked = board.routes[1].clone();

        assert!(repairable_net_ids(&board).contains(&1));
        let (repaired, report) = repair_routes(&board, &HashSet::from([1])).unwrap();

        assert_eq!(report.rerouted, vec!["broken"]);
        assert_eq!(
            repaired.routes.iter().find(|route| route.net_id == 2),
            Some(&locked)
        );
        assert_ne!(
            repaired.routes.iter().find(|route| route.net_id == 1),
            Some(&board.routes[0])
        );
        assert!(checking::check_board(&repaired).is_clean());
    }

    #[test]
    fn quality_report_counts_geometry_and_detects_regressions() {
        let mut board = board();
        board.obstacles.clear();
        board.routes = vec![Route {
            net_id: 1,
            segments: vec![
                Segment {
                    start: Point {
                        x_nm: 1_000_000,
                        y_nm: 1_000_000,
                    },
                    end: Point {
                        x_nm: 5_000_000,
                        y_nm: 1_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
                Segment {
                    start: Point {
                        x_nm: 5_000_000,
                        y_nm: 1_000_000,
                    },
                    end: Point {
                        x_nm: 9_000_000,
                        y_nm: 1_000_000,
                    },
                    layer: Layer::Back,
                    width_nm: 250_000,
                },
            ],
            arcs: vec![],
            vias: vec![Via {
                position: Point {
                    x_nm: 5_000_000,
                    y_nm: 1_000_000,
                },
                diameter_nm: 600_000,
                drill_nm: 300_000,
                kind: ViaKind::Through,
                start_layer: Layer::Front,
                end_layer: Layer::Back,
            }],
            teardrops: vec![],
            zones: vec![],
        }];
        let quality = routing_quality(&board);

        assert_eq!(quality.total_length_nm, 8_000_000);
        assert_eq!(quality.total_vias, 1);
        assert_eq!(quality.nets[0].layers_used, 2);
        assert_eq!(quality.routed_nets, 1);
        assert_eq!(quality.unrouted_nets, 0);
        let mut baseline = quality.clone();
        baseline.total_length_nm -= 1;
        baseline.total_vias = 0;
        assert_eq!(quality.regressions_against(&baseline).len(), 2);
        assert!(
            serde_json::to_string(&quality)
                .unwrap()
                .contains("total_length_nm")
        );
    }

    #[test]
    fn autoroutes_a_coupled_differential_pair() {
        let mut board = board();
        board.obstacles.clear();
        board.round_obstacles.push(RoundObstacle {
            center: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            diameter_nm: 500_000,
            layers: vec![Layer::Front],
            net_id: None,
        });
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
            target_differential_impedance_ohms: None,
            differential_impedance_tolerance_ohms: None,
            minimum_length_nm: None,
            tuning_amplitude_nm: None,
            tuning_pitch_nm: None,
            max_tuning_sections: 1,
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
        assert!(positive.segments.len() > 1);
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

    #[test]
    fn tunes_differential_pair_with_synchronous_meanders() {
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
                name: "CLK+".into(),
                class: None,
                priority: 0,
                terminals: terminals(3_000_000),
            },
            Net {
                id: 2,
                name: "CLK-".into(),
                class: None,
                priority: 0,
                terminals: terminals(4_000_000),
            },
        ];
        board.routes = vec![
            Route {
                net_id: 1,
                segments: vec![Segment {
                    start: Point {
                        x_nm: 1_000_000,
                        y_nm: 3_000_000,
                    },
                    end: Point {
                        x_nm: 9_000_000,
                        y_nm: 3_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                }],
                arcs: vec![],
                vias: vec![],
                teardrops: vec![],
                zones: vec![],
            },
            Route {
                net_id: 2,
                segments: vec![Segment {
                    start: Point {
                        x_nm: 1_000_000,
                        y_nm: 4_000_000,
                    },
                    end: Point {
                        x_nm: 9_000_000,
                        y_nm: 4_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                }],
                arcs: vec![],
                vias: vec![],
                teardrops: vec![],
                zones: vec![],
            },
        ];
        board.differential_pairs = vec![DifferentialPair {
            name: "CLK".into(),
            positive_net_id: 1,
            negative_net_id: 2,
            gap_nm: 750_000,
            gap_tolerance_nm: 100_000,
            max_skew_nm: 0,
            min_coupled_percent: 70,
            target_differential_impedance_ohms: None,
            differential_impedance_tolerance_ohms: None,
            minimum_length_nm: Some(9_000_000),
            tuning_amplitude_nm: Some(500_000),
            tuning_pitch_nm: Some(1_000_000),
            max_tuning_sections: 1,
        }];

        tune_differential_pairs_synchronously(&mut board).unwrap();

        assert_eq!(route_length_nm(&board.routes[0]), 9_000_000);
        assert_eq!(
            route_length_nm(&board.routes[0]),
            route_length_nm(&board.routes[1])
        );
        assert_eq!(board.routes[0].segments.len(), 5);
        assert!(
            board.routes[0]
                .segments
                .iter()
                .zip(&board.routes[1].segments)
                .all(|(positive, negative)| {
                    translate_point(
                        positive.start,
                        Point {
                            x_nm: 0,
                            y_nm: 1_000_000,
                        },
                    ) == negative.start
                        && translate_point(
                            positive.end,
                            Point {
                                x_nm: 0,
                                y_nm: 1_000_000,
                            },
                        ) == negative.end
                })
        );
        assert!(crate::checking::check_board(&board).is_clean());
    }

    #[test]
    fn route_arcs_use_true_length_and_curved_drc_geometry() {
        let arc = RouteArc {
            start: Point {
                x_nm: 1_000_000,
                y_nm: 5_000_000,
            },
            mid: Point {
                x_nm: 5_000_000,
                y_nm: 1_000_000,
            },
            end: Point {
                x_nm: 9_000_000,
                y_nm: 5_000_000,
            },
            layer: Layer::Front,
            width_nm: 250_000,
        };
        let route = Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![arc],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        };
        assert!((route_length_nm(&route) - 12_566_371).abs() <= 1);

        let mut board = board();
        board.obstacles.clear();
        board.nets[0].terminals[0].position = route.arcs[0].start;
        board.nets[0].terminals[1].position = route.arcs[0].end;
        board.routes = vec![route];
        board.round_obstacles.push(RoundObstacle {
            center: Point {
                x_nm: 5_000_000,
                y_nm: 1_000_000,
            },
            diameter_nm: 500_000,
            layers: vec![Layer::Front],
            net_id: None,
        });
        let report = crate::checking::check_board(&board);
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.rule == "clearance")
        );
    }

    #[test]
    fn automatically_generates_checked_via_teardrops() {
        let mut board = board();
        board.obstacles.clear();
        let start = Point {
            x_nm: 2_000_000,
            y_nm: 5_000_000,
        };
        let end = Point {
            x_nm: 8_000_000,
            y_nm: 5_000_000,
        };
        board.nets[0].terminals[0].position = start;
        board.nets[0].terminals[1].position = end;
        board.routes = vec![Route {
            net_id: 1,
            segments: vec![Segment {
                start,
                end,
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            arcs: vec![],
            vias: vec![Via {
                position: start,
                diameter_nm: 600_000,
                drill_nm: 300_000,
                kind: ViaKind::Through,
                start_layer: Layer::Front,
                end_layer: Layer::Back,
            }],
            teardrops: vec![],
            zones: vec![],
        }];

        assert_eq!(generate_route_teardrops(&mut board), 1);
        assert_eq!(board.routes[0].teardrops[0].polygon.len(), 4);
        assert_eq!(board.routes[0].teardrops[0].layer, Layer::Front);
        assert!(checking::check_board(&board).is_clean());
        assert_eq!(generate_route_teardrops(&mut board), 0);
    }

    #[test]
    fn fills_zones_with_clearance_thermals_and_island_removal() {
        let mut board = board();
        board.obstacles.clear();
        board.keepouts.push(Keepout {
            polygon: vec![
                Point {
                    x_nm: 4_500_000,
                    y_nm: 1_000_000,
                },
                Point {
                    x_nm: 5_500_000,
                    y_nm: 1_000_000,
                },
                Point {
                    x_nm: 5_500_000,
                    y_nm: 9_000_000,
                },
                Point {
                    x_nm: 4_500_000,
                    y_nm: 9_000_000,
                },
            ],
            layers: vec![Layer::Front],
            net_id: None,
            tracks_not_allowed: true,
            vias_not_allowed: true,
            zones_not_allowed: true,
            footprints_not_allowed: false,
            minimum_track_width_nm: None,
            minimum_clearance_nm: None,
        });
        board.nets[0].terminals[0].position = Point {
            x_nm: 2_000_000,
            y_nm: 5_000_000,
        };
        board.footprints.push(Footprint {
            reference: "U1".into(),
            position: board.nets[0].terminals[0].position,
            rotation_deg: 0.0,
            pads: vec![Pad {
                number: "1".into(),
                position: board.nets[0].terminals[0].position,
                width_nm: 1_000_000,
                height_nm: 1_000_000,
                source_width_nm: 1_000_000,
                source_height_nm: 1_000_000,
                rotation_deg: 0.0,
                shape: PadShape::Rect,
                custom_polygon: vec![],
                layers: vec![Layer::Front],
                net_id: Some(1),
            }],
        });
        board.routes = vec![Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![CopperZone {
                polygon: vec![
                    Point {
                        x_nm: 1_000_000,
                        y_nm: 1_000_000,
                    },
                    Point {
                        x_nm: 9_000_000,
                        y_nm: 1_000_000,
                    },
                    Point {
                        x_nm: 9_000_000,
                        y_nm: 9_000_000,
                    },
                    Point {
                        x_nm: 1_000_000,
                        y_nm: 9_000_000,
                    },
                ],
                layer: Layer::Front,
                clearance_nm: 250_000,
                minimum_thickness_nm: 250_000,
                thermal_relief: true,
                thermal_gap_nm: 250_000,
                thermal_spoke_width_nm: 250_000,
                filled_polygons: vec![],
            }],
        }];

        let count = fill_copper_zones(&mut board);
        assert!(count > 50, "filled cells: {count}");
        let fills = &board.routes[0].zones[0].filled_polygons;
        assert!(fills.iter().all(|polygon| {
            polygon.iter().map(|point| point.x_nm).sum::<Nm>() / (polygon.len() as Nm) < 4_500_000
        }));
        let centers: HashSet<_> = fills
            .iter()
            .map(|polygon| {
                (
                    polygon.iter().map(|point| point.x_nm).sum::<Nm>() / 4,
                    polygon.iter().map(|point| point.y_nm).sum::<Nm>() / 4,
                )
            })
            .collect();
        assert!(centers.contains(&(2_000_000, 5_000_000)));
        assert!(!centers.contains(&(2_500_000, 5_500_000)));
    }

    #[test]
    fn post_optimizer_shortens_only_checked_mutable_routes() {
        let mut board = board();
        board.obstacles.clear();
        board.nets[0].terminals[1].position = Point {
            x_nm: 5_000_000,
            y_nm: 5_000_000,
        };
        board.routes.push(Route {
            net_id: 1,
            segments: vec![
                Segment {
                    start: Point {
                        x_nm: 1_000_000,
                        y_nm: 1_000_000,
                    },
                    end: Point {
                        x_nm: 1_000_000,
                        y_nm: 3_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
                Segment {
                    start: Point {
                        x_nm: 1_000_000,
                        y_nm: 3_000_000,
                    },
                    end: Point {
                        x_nm: 3_000_000,
                        y_nm: 5_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
                Segment {
                    start: Point {
                        x_nm: 3_000_000,
                        y_nm: 5_000_000,
                    },
                    end: Point {
                        x_nm: 5_000_000,
                        y_nm: 5_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
            ],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });
        let original = board.clone();

        assert_eq!(optimize_routes(&mut board, &HashSet::new()), 0);
        assert_eq!(board.routes[0].segments, original.routes[0].segments);
        assert_eq!(optimize_routes(&mut board, &HashSet::from([1])), 2);
        assert_eq!(board.routes[0].segments.len(), 1);
        assert_eq!(
            board.routes[0].segments[0].end,
            board.nets[0].terminals[1].position
        );
        assert!(checking::check_board(&board).is_clean());
    }
}

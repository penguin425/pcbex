use pcbex_core::{
    Board, CapsuleObstacle, CopperZone, DifferentialPair, Footprint, Keepout, Layer, Net,
    NetClassRules, Obstacle, Pad, PadShape, Point, PolygonObstacle, RoundObstacle, Route, RouteArc,
    Rules, Segment, StackupLayer, Terminal, Via, ViaKind,
    checking::check_board,
    placement::{BoardSide, Component, Connection, PinRef, PlacementProblem},
};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

const NM_PER_MM: f64 = 1_000_000.0;
const ARC_CHORD_TOLERANCE_NM: f64 = 10_000.0;
const MAX_EDGE_ARC_SEGMENTS: usize = 16_384;
const MAX_EDGE_CIRCLE_SEGMENTS: usize = 16_384;
const MAX_EDGE_CURVE_SEGMENTS: usize = 16_384;
const MAX_EDGE_POLYGON_POINTS: usize = 16_384;
const MAX_EDGE_SEGMENTS: usize = 65_536;

#[derive(Clone, Debug, PartialEq)]
enum Sexp {
    Atom(String),
    List(Vec<Sexp>),
}

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
        if atom(xs.first()) == Some("net")
            && let (Some(id), Some(name)) = (number_u32(xs.get(1)), atom(xs.get(2)))
        {
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
    for item in top {
        let Some(xs) = item.as_list() else { continue };
        match atom(xs.first()) {
            Some("footprint") => {
                import_footprint(xs, min, &mut nets, &mut footprint_geometry, &copper_layers)
            }
            Some("segment") => {
                import_segment(xs, min, &rules, &mut obstacles, &mut route_candidates)
            }
            Some("arc") => import_route_arc(xs, min, &rules, &mut obstacles, &mut route_candidates),
            Some("via") => import_via(
                xs,
                min,
                &rules,
                &mut obstacles,
                &mut route_candidates,
                &copper_layers,
            ),
            Some("zone") => {
                import_keepout(xs, min, &mut keepouts, &copper_layers);
                import_copper_zone(
                    xs,
                    min,
                    &mut footprint_geometry.polygon_obstacles,
                    &mut route_candidates,
                );
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
        net_classes.insert(
            name.to_string(),
            NetClassRules {
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
            },
        );
    }

    if let Some(patterns) = settings.get("netclass_patterns") {
        let patterns = patterns
            .as_array()
            .ok_or_else(|| "KiCad project netclass_patterns is not an array".to_string())?;
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
            let class = assignment
                .get("netclass")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "net-class pattern is missing netclass".to_string())?;
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
            let Some(class) = class.as_str() else {
                return Err(format!(
                    "net-class assignment for {net_name} is not a string"
                ));
            };
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
    let root = parse(&format!("({source})"))?;
    let top = root
        .as_list()
        .ok_or_else(|| "KiCad custom rules are not an s-expression".to_string())?;
    let mut net_classes = board.net_classes.clone();
    let mut applied = 0;
    for item in top {
        let Some(rule) = item.as_list() else { continue };
        if atom(rule.first()) != Some("rule") {
            continue;
        }
        let Some(condition) = child_atom(rule, "condition") else {
            continue;
        };
        let Some(class_name) = condition_net_class(condition) else {
            continue;
        };
        let Some(class) = net_classes.get_mut(&class_name) else {
            return Err(format!(
                "custom rule references unknown net class {class_name}"
            ));
        };
        for item in rule {
            let Some(constraint) = item.as_list() else {
                continue;
            };
            if atom(constraint.first()) != Some("constraint") {
                continue;
            }
            let Some(kind) = atom(constraint.get(1)) else {
                continue;
            };
            match kind {
                "clearance" => class.clearance_nm = constraint_value(constraint, &["min"])?,
                "track_width" => {
                    class.track_width_nm = constraint_value(constraint, &["opt", "min"])?
                }
                "via_diameter" => {
                    class.via_diameter_nm = constraint_value(constraint, &["opt", "min"])?
                }
                "hole_size" => class.via_drill_nm = constraint_value(constraint, &["opt", "min"])?,
                "diff_pair_gap" => {
                    class.differential_gap_nm = Some(constraint_value(constraint, &["opt", "min"])?)
                }
                "length" => {
                    class.minimum_length_nm = constraint_optional_value(constraint, "min")?;
                    class.maximum_length_nm = constraint_optional_value(constraint, "max")?;
                }
                _ => continue,
            }
            applied += 1;
        }
    }
    board.differential_pairs = infer_differential_pairs(&board.nets, &net_classes);
    board.net_classes = net_classes;
    Ok(applied)
}

fn condition_net_class(condition: &str) -> Option<String> {
    let marker = "NetClass";
    let rest = &condition[condition.find(marker)? + marker.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("==")?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    Some(rest[1..].split(quote).next()?.to_string())
}

fn constraint_value(constraint: &[Sexp], preferences: &[&str]) -> Result<i64, String> {
    for preference in preferences {
        if let Some(value) = constraint_optional_value(constraint, preference)? {
            return Ok(value);
        }
    }
    Err(format!(
        "custom constraint {} has no supported value",
        atom(constraint.get(1)).unwrap_or("unknown")
    ))
}

fn constraint_optional_value(constraint: &[Sexp], name: &str) -> Result<Option<i64>, String> {
    let Some(values) = child_values(constraint, name) else {
        return Ok(None);
    };
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
            if classes.contains_key(name) {
                return Err(format!("KiCad board contains duplicate net class {name}"));
            }
            let dimension = |key: &str, fallback: i64| -> Result<i64, String> {
                let Some(value) = child_values(values, key) else {
                    return Ok(fallback);
                };
                number(value.get(1))
                    .and_then(checked_nonnegative_nm)
                    .ok_or_else(|| format!("net class {name} has invalid {key}"))
            };
            let optional_dimension = |key: &str| -> Result<Option<i64>, String> {
                let Some(value) = child_values(values, key) else {
                    return Ok(None);
                };
                number(value.get(1))
                    .and_then(checked_nonnegative_nm)
                    .map(Some)
                    .ok_or_else(|| format!("net class {name} has invalid {key}"))
            };
            classes.insert(
                name.to_string(),
                NetClassRules {
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
                },
            );
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
                let Some(net_id) = net_ids_by_name.get(net_name) else {
                    return Err(format!(
                        "net class {name} references unknown net {net_name}"
                    ));
                };
                if let Some(previous) = class_by_net_id.get(net_id)
                    && previous != name
                {
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
        let courtyards: HashMap<String, Vec<Point>> = top
            .iter()
            .filter_map(|item| {
                let values = item.as_list()?;
                if atom(values.first()) != Some("footprint") {
                    return None;
                }
                courtyard_polygon_local(values)
                    .map(|polygon| (footprint_reference(values), polygon))
            })
            .collect();
        let sides: HashMap<String, BoardSide> = top
            .iter()
            .filter_map(|item| {
                let values = item.as_list()?;
                if atom(values.first()) != Some("footprint") {
                    return None;
                }
                Some((
                    footprint_reference(values),
                    if child_atom(values, "layer").is_some_and(|layer| layer.starts_with("B.")) {
                        BoardSide::Back
                    } else {
                        BoardSide::Front
                    },
                ))
            })
            .collect();
        let mut components = Vec::with_capacity(self.board.footprints.len());
        let mut net_pins = HashMap::<u32, Vec<PinRef>>::new();
        for footprint in &self.board.footprints {
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
                let local = point_mm(local_x, local_y);
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
                side: sides
                    .get(&footprint.reference)
                    .copied()
                    .unwrap_or(BoardSide::Front),
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
            let source_side =
                if child_atom(values, "layer").is_some_and(|layer| layer.starts_with("B.")) {
                    BoardSide::Back
                } else {
                    BoardSide::Front
                };
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

fn courtyard_polygon_local(footprint: &[Sexp]) -> Option<Vec<Point>> {
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
        let Some(points) = child_values(values, "pts") else {
            continue;
        };
        let polygon: Vec<_> = points
            .iter()
            .skip(1)
            .filter_map(|point| {
                let xy = point.as_list()?;
                if atom(xy.first()) != Some("xy") {
                    return None;
                }
                Some(point_mm(number(xy.get(1))?, number(xy.get(2))?))
            })
            .collect();
        if polygon.len() >= 3 {
            return Some(polygon);
        }
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
            let Some(point) = child_values(values, key) else {
                continue;
            };
            let (Some(x), Some(y)) = (number(point.get(1)), number(point.get(2))) else {
                continue;
            };
            min_x = min_x.min(x);
            min_y = min_y.min(y);
            max_x = max_x.max(x);
            max_y = max_y.max(y);
        }
    }
    min_x.is_finite().then(|| {
        vec![
            point_mm(min_x, min_y),
            point_mm(max_x, min_y),
            point_mm(max_x, max_y),
            point_mm(min_x, max_y),
        ]
    })
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

fn list_spans(
    source: &str,
    name: &str,
    target_depth: usize,
) -> Result<Vec<(usize, usize)>, String> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut stack = Vec::new();
    let mut spans = Vec::new();
    let mut index = 0usize;
    let mut quoted = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if quoted => index += 1,
            b'"' => quoted = !quoted,
            b'(' if !quoted => {
                depth += 1;
                let mut atom_start = index + 1;
                while atom_start < bytes.len() && bytes[atom_start].is_ascii_whitespace() {
                    atom_start += 1;
                }
                let mut atom_end = atom_start;
                while atom_end < bytes.len()
                    && !bytes[atom_end].is_ascii_whitespace()
                    && !matches!(bytes[atom_end], b'(' | b')')
                {
                    atom_end += 1;
                }
                stack.push((
                    index,
                    depth,
                    source.get(atom_start..atom_end).unwrap_or_default() == name,
                ));
            }
            b')' if !quoted => {
                let Some((start, list_depth, matches)) = stack.pop() else {
                    return Err("unbalanced KiCad document".into());
                };
                if matches && list_depth == target_depth {
                    spans.push((start, index + 1));
                }
                depth = depth.checked_sub(1).ok_or("unbalanced KiCad document")?;
            }
            _ => {}
        }
        index += 1;
    }
    if quoted || depth != 0 {
        return Err("unterminated KiCad document".into());
    }
    Ok(spans)
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
            if atom(xs.first()) == Some("gr_rect")
                && child_atom(xs, "layer") == Some("Edge.Cuts")
                && let (Some(start), Some(end)) = (child_point(xs, "start"), child_point(xs, "end"))
            {
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
) {
    let footprint_at = child_values(xs, "at");
    let fx = footprint_at.and_then(|v| number(v.get(1))).unwrap_or(0.0);
    let fy = footprint_at.and_then(|v| number(v.get(2))).unwrap_or(0.0);
    let angle = footprint_at.and_then(|v| number(v.get(3))).unwrap_or(0.0);
    let mut model = Footprint {
        reference: footprint_reference(xs),
        position: relative(point_mm(fx, fy), origin),
        rotation_deg: angle,
        pads: Vec::new(),
    };
    for child in xs {
        let Some(pad) = child.as_list() else { continue };
        if atom(pad.first()) != Some("pad") {
            continue;
        }
        let at = child_values(pad, "at");
        let px = at.and_then(|v| number(v.get(1))).unwrap_or(0.0);
        let py = at.and_then(|v| number(v.get(2))).unwrap_or(0.0);
        let (rx, ry) = rotate(px, py, angle);
        let position = relative(point_mm(fx + rx, fy + ry), origin);
        let layers = pad_layers(pad, copper_layers);
        let size = child_values(pad, "size");
        let width = size.and_then(|v| number(v.get(1))).unwrap_or(1.0);
        let height = size.and_then(|v| number(v.get(2))).unwrap_or(width);
        let pad_angle = at.and_then(|v| number(v.get(3))).unwrap_or(0.0);
        let shape = match atom(pad.get(3)) {
            Some("circle") => PadShape::Circle,
            Some("oval") => PadShape::Oval,
            Some("roundrect") => PadShape::RoundRect,
            Some("trapezoid") => PadShape::Trapezoid,
            Some("custom") => PadShape::Custom,
            _ => PadShape::Rect,
        };
        let roundrect_ratio = child_values(pad, "roundrect_rratio")
            .and_then(|values| number(values.get(1)))
            .unwrap_or(0.25)
            .clamp(0.0, 0.5);
        let rect_delta = child_values(pad, "rect_delta")
            .map(|values| {
                (
                    number(values.get(1)).unwrap_or(0.0),
                    number(values.get(2)).unwrap_or(0.0),
                )
            })
            .unwrap_or((0.0, 0.0));
        let custom_polygon =
            custom_pad_polygon(pad, position, angle + pad_angle).unwrap_or_default();
        let (bbox_width, bbox_height) = rotated_size(width, height, angle + pad_angle);
        let net_id = child_values(pad, "net").and_then(|values| number_u32(values.get(1)));
        let drill = child_values(pad, "drill").and_then(|values| {
            let (width, height) = if atom(values.get(1)) == Some("oval") {
                (
                    number(values.get(2))?,
                    number(values.get(3)).or_else(|| number(values.get(2)))?,
                )
            } else {
                let width = number(values.get(1))?;
                (width, number(values.get(2)).unwrap_or(width))
            };
            let offset = child_values(values, "offset")
                .map(|offset| {
                    (
                        number(offset.get(1)).unwrap_or(0.0),
                        number(offset.get(2)).unwrap_or(0.0),
                    )
                })
                .unwrap_or((0.0, 0.0));
            Some((width, height, offset.0, offset.1))
        });
        model.pads.push(Pad {
            number: atom(pad.get(1)).unwrap_or("").to_string(),
            position,
            width_nm: nm(bbox_width),
            height_nm: nm(bbox_height),
            source_width_nm: nm(width),
            source_height_nm: nm(height),
            rotation_deg: angle + pad_angle,
            shape,
            custom_polygon: custom_polygon.clone(),
            roundrect_radius_nm: if shape == PadShape::RoundRect {
                nm(width.min(height) * roundrect_ratio)
            } else {
                0
            },
            trapezoid_delta_x_nm: if shape == PadShape::Trapezoid {
                nm(rect_delta.0)
            } else {
                0
            },
            trapezoid_delta_y_nm: if shape == PadShape::Trapezoid {
                nm(rect_delta.1)
            } else {
                0
            },
            drill_width_nm: drill.map(|(width, _, _, _)| nm(width)),
            drill_height_nm: drill.map(|(_, height, _, _)| nm(height)),
            drill_offset_x_nm: drill.map(|(_, _, x, _)| nm(x)).unwrap_or(0),
            drill_offset_y_nm: drill.map(|(_, _, _, y)| nm(y)).unwrap_or(0),
            plated: atom(pad.get(2)) != Some("np_thru_hole"),
            layers: layers.clone(),
            net_id,
        });
        if let Some(net_values) = child_values(pad, "net")
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
                angle + pad_angle,
                layers,
                Some(id),
                &mut geometry.round_obstacles,
                &mut geometry.capsule_obstacles,
                &mut geometry.polygon_obstacles,
            );
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
            angle + pad_angle,
            layers,
            None,
            &mut geometry.round_obstacles,
            &mut geometry.capsule_obstacles,
            &mut geometry.polygon_obstacles,
        );
    }
    geometry.footprints.push(model);
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

fn import_segment(
    xs: &[Sexp],
    origin: Point,
    rules: &Rules,
    obstacles: &mut Vec<Obstacle>,
    routes: &mut HashMap<u32, Route>,
) {
    let (Some(start), Some(end), Some(layer)) = (
        child_point(xs, "start"),
        child_point(xs, "end"),
        child_atom(xs, "layer").and_then(parse_layer),
    ) else {
        return;
    };
    let a = relative(start, origin);
    let b = relative(end, origin);
    let width = child_values(xs, "width")
        .and_then(|v| number(v.get(1)))
        .map(nm)
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
}

fn import_route_arc(
    xs: &[Sexp],
    origin: Point,
    rules: &Rules,
    obstacles: &mut Vec<Obstacle>,
    routes: &mut HashMap<u32, Route>,
) {
    let (Some(start), Some(mid), Some(end), Some(layer)) = (
        child_point(xs, "start"),
        child_point(xs, "mid"),
        child_point(xs, "end"),
        child_atom(xs, "layer").and_then(parse_layer),
    ) else {
        return;
    };
    let start = relative(start, origin);
    let mid = relative(mid, origin);
    let end = relative(end, origin);
    let width = child_values(xs, "width")
        .and_then(|values| number(values.get(1)))
        .map(nm)
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
}

fn import_via(
    xs: &[Sexp],
    origin: Point,
    rules: &Rules,
    obstacles: &mut Vec<Obstacle>,
    routes: &mut HashMap<u32, Route>,
    copper_layers: &[Layer],
) {
    let Some(at) = child_point(xs, "at") else {
        return;
    };
    let at = relative(at, origin);
    let size = child_values(xs, "size")
        .and_then(|v| number(v.get(1)))
        .map(nm)
        .unwrap_or(rules.via_diameter_nm);
    let drill = child_values(xs, "drill")
        .and_then(|v| number(v.get(1)))
        .map(nm)
        .unwrap_or(rules.via_drill_nm);
    let net_id = child_values(xs, "net").and_then(|v| number_u32(v.get(1)));
    let kind = if xs.iter().any(|value| atom(Some(value)) == Some("micro")) {
        ViaKind::Micro
    } else if xs.iter().any(|value| atom(Some(value)) == Some("blind")) {
        ViaKind::BlindBuried
    } else {
        ViaKind::Through
    };
    let declared_layers: Vec<_> = child_values(xs, "layers")
        .into_iter()
        .flat_map(|values| values.iter().skip(1))
        .filter_map(|value| atom(Some(value)).and_then(parse_layer))
        .collect();
    let start_layer = declared_layers.first().copied().unwrap_or(Layer::Front);
    let end_layer = declared_layers.last().copied().unwrap_or(Layer::Back);
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
}

fn import_keepout(
    xs: &[Sexp],
    origin: Point,
    keepouts: &mut Vec<Keepout>,
    copper_layers: &[Layer],
) {
    let Some(restrictions) = child_values(xs, "keepout") else {
        return;
    };
    let layers = if let Some(layer) = child_atom(xs, "layer").and_then(parse_layer) {
        vec![layer]
    } else if matches!(child_atom(xs, "layer"), Some("*.Cu") | Some("F&B.Cu")) {
        copper_layers.to_vec()
    } else if let Some(values) = child_values(xs, "layers") {
        let mut layers = Vec::new();
        for value in values.iter().skip(1).filter_map(|value| atom(Some(value))) {
            if matches!(value, "*.Cu" | "F&B.Cu") {
                layers.extend_from_slice(copper_layers);
            } else if let Some(layer) = parse_layer(value) {
                layers.push(layer);
            }
        }
        layers.sort_by_key(|layer| layer.index());
        layers.dedup();
        layers
    } else {
        copper_layers.to_vec()
    };
    let Some(polygon) = child_values(xs, "polygon") else {
        return;
    };
    let Some(values) = child_values(polygon, "pts") else {
        return;
    };
    let points: Vec<_> = values
        .iter()
        .skip(1)
        .filter_map(|value| {
            let xy = value.as_list()?;
            if atom(xy.first()) != Some("xy") {
                return None;
            }
            Some(relative(
                point_mm(number(xy.get(1))?, number(xy.get(2))?),
                origin,
            ))
        })
        .collect();
    if points.len() < 3 || layers.is_empty() {
        return;
    }
    keepouts.push(Keepout {
        polygon: points,
        layers,
        net_id: None,
        tracks_not_allowed: child_atom(restrictions, "tracks") == Some("not_allowed"),
        vias_not_allowed: child_atom(restrictions, "vias") == Some("not_allowed"),
        zones_not_allowed: child_atom(restrictions, "copperpour") == Some("not_allowed"),
        footprints_not_allowed: child_atom(restrictions, "footprints") == Some("not_allowed"),
        minimum_track_width_nm: None,
        minimum_clearance_nm: None,
    });
}

fn import_copper_zone(
    xs: &[Sexp],
    origin: Point,
    polygon_obstacles: &mut Vec<PolygonObstacle>,
    routes: &mut HashMap<u32, Route>,
) {
    if child_values(xs, "keepout").is_some()
        || child_values(xs, "attr")
            .and_then(|attr| child_values(attr, "teardrop"))
            .is_some()
    {
        return;
    }
    let Some(net_id) = child_values(xs, "net").and_then(|values| number_u32(values.get(1))) else {
        return;
    };
    if net_id == 0 {
        return;
    }
    let zone_layer = child_atom(xs, "layer").and_then(parse_layer);
    let outline = child_values(xs, "polygon")
        .and_then(|polygon| child_values(polygon, "pts"))
        .map(|values| import_polygon_points(values, origin))
        .unwrap_or_default();
    if let Some(layer) = zone_layer
        && outline.len() >= 3
    {
        polygon_obstacles.push(PolygonObstacle {
            polygon: outline.clone(),
            layers: vec![layer],
            net_id: Some(net_id),
        });
        let clearance_nm = child_values(xs, "connect_pads")
            .and_then(|connect| child_values(connect, "clearance"))
            .and_then(|values| number(values.get(1)))
            .map(nm)
            .unwrap_or(0);
        let minimum_thickness_nm = child_values(xs, "min_thickness")
            .and_then(|values| number(values.get(1)))
            .map(nm)
            .unwrap_or(250_000);
        let fill = child_values(xs, "fill");
        let thermal_gap_nm = fill
            .and_then(|values| child_values(values, "thermal_gap"))
            .and_then(|values| number(values.get(1)))
            .map(nm)
            .unwrap_or(200_000);
        let thermal_spoke_width_nm = fill
            .and_then(|values| child_values(values, "thermal_bridge_width"))
            .and_then(|values| number(values.get(1)))
            .map(nm)
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
        let Some(layer) = child_atom(filled, "layer")
            .and_then(parse_layer)
            .or(zone_layer)
        else {
            continue;
        };
        let Some(values) = child_values(filled, "pts") else {
            continue;
        };
        let polygon = import_polygon_points(values, origin);
        if polygon.len() >= 3 {
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
    }
}

fn import_polygon_points(values: &[Sexp], origin: Point) -> Vec<Point> {
    values
        .iter()
        .skip(1)
        .filter_map(|value| {
            let xy = value.as_list()?;
            if atom(xy.first()) != Some("xy") {
                return None;
            }
            Some(relative(
                point_mm(number(xy.get(1))?, number(xy.get(2))?),
                origin,
            ))
        })
        .collect()
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
) {
    match shape {
        PadShape::Circle => round_obstacles.push(RoundObstacle {
            center,
            diameter_nm: nm(width_mm.max(height_mm)),
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
                    x_nm: center.x_nm.saturating_sub(nm(dx)),
                    y_nm: center.y_nm.saturating_sub(nm(dy)),
                },
                end: Point {
                    x_nm: center.x_nm.saturating_add(nm(dx)),
                    y_nm: center.y_nm.saturating_add(nm(dy)),
                },
                diameter_nm: nm(minor),
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
                    return;
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
                .map(|(x, y)| {
                    let (x, y) = rotate(x, y, rotation_deg);
                    Point {
                        x_nm: center.x_nm.saturating_add(nm(x)),
                        y_nm: center.y_nm.saturating_add(nm(y)),
                    }
                })
                .collect();
            polygon_obstacles.push(PolygonObstacle {
                polygon,
                layers,
                net_id,
            });
        }
    }
}

fn custom_pad_polygon(pad: &[Sexp], center: Point, rotation_deg: f64) -> Option<Vec<Point>> {
    let primitives = child_values(pad, "primitives")?;
    for primitive in primitives.iter().skip(1) {
        let values = primitive.as_list()?;
        if atom(values.first()) != Some("gr_poly") {
            continue;
        }
        let points = child_values(values, "pts")?;
        let polygon: Vec<_> = points
            .iter()
            .skip(1)
            .filter_map(|point| {
                let xy = point.as_list()?;
                if atom(xy.first()) != Some("xy") {
                    return None;
                }
                let (x, y) = rotate(number(xy.get(1))?, number(xy.get(2))?, rotation_deg);
                Some(Point {
                    x_nm: center.x_nm.saturating_add(nm(x)),
                    y_nm: center.y_nm.saturating_add(nm(y)),
                })
            })
            .collect();
        if polygon.len() >= 3 {
            return Some(polygon);
        }
    }
    None
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
fn pad_layers(pad: &[Sexp], copper_layers: &[Layer]) -> Vec<Layer> {
    let Some(v) = child_values(pad, "layers") else {
        return copper_layers.to_vec();
    };
    let mut layers = Vec::new();
    for value in v.iter().skip(1).filter_map(|value| atom(Some(value))) {
        if value == "*.Cu" {
            layers.extend_from_slice(copper_layers);
        } else if let Some(layer) = parse_layer(value) {
            layers.push(layer);
        }
    }
    layers.sort_by_key(|layer| layer.index());
    layers.dedup();
    if layers.is_empty() {
        layers.push(Layer::Front);
    }
    layers
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
fn layer_name(layer: Layer) -> String {
    layer.name()
}

fn board_copper_layers(top: &[Sexp]) -> Result<Vec<Layer>, String> {
    let Some(values) = child_values(top, "layers") else {
        return Ok(vec![Layer::Front, Layer::Back]);
    };
    let mut layers: Vec<_> = values
        .iter()
        .skip(1)
        .filter_map(|item| {
            let values = item.as_list()?;
            parse_layer(atom(values.get(1))?)
        })
        .collect();
    layers.sort_by_key(|layer| layer.index());
    layers.dedup();
    if layers.is_empty() {
        return Err("KiCad board has no copper layers".into());
    }
    Ok(layers)
}

#[derive(Clone, Copy)]
struct ImportedStackEntry {
    copper: Option<Layer>,
    thickness_nm: i64,
    dielectric_constant: Option<f64>,
}

fn import_stackup(top: &[Sexp], copper_layers: &[Layer]) -> Result<Vec<StackupLayer>, String> {
    let Some(setup) = child_values(top, "setup") else {
        return Ok(vec![]);
    };
    let Some(stackup) = child_values(setup, "stackup") else {
        return Ok(vec![]);
    };
    let mut entries = Vec::new();
    for item in stackup.iter().skip(1) {
        let Some(values) = item.as_list() else {
            continue;
        };
        if atom(values.first()) != Some("layer") {
            continue;
        }
        let Some(name) = atom(values.get(1)) else {
            return Err("KiCad stackup layer is missing its name".into());
        };
        let copper = parse_layer(name).filter(|layer| copper_layers.contains(layer));
        let layer_type = child_atom(values, "type").unwrap_or_default();
        let is_dielectric = copper.is_none()
            && (name.starts_with("dielectric")
                || matches!(layer_type, "core" | "prepreg" | "dielectric"));
        if copper.is_none() && !is_dielectric {
            continue;
        }
        let thickness = child_values(values, "thickness")
            .and_then(|values| number(values.get(1)))
            .unwrap_or(0.0);
        if !thickness.is_finite() || thickness < 0.0 {
            return Err(format!("KiCad stackup layer {name} has invalid thickness"));
        }
        let dielectric_constant =
            child_values(values, "epsilon_r").and_then(|values| number(values.get(1)));
        if dielectric_constant.is_some_and(|value| !value.is_finite() || value <= 1.0) {
            return Err(format!(
                "KiCad stackup layer {name} has invalid dielectric constant"
            ));
        }
        entries.push(ImportedStackEntry {
            copper,
            thickness_nm: nm(thickness),
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

fn point_mm(x: f64, y: f64) -> Point {
    Point {
        x_nm: nm(x),
        y_nm: nm(y),
    }
}
fn edge_point_mm(x: f64, y: f64) -> Result<Point, String> {
    let convert = |value: f64| -> Result<i64, String> {
        let nanometers = (value * NM_PER_MM).round();
        if (i64::MIN as f64..-(i64::MIN as f64)).contains(&nanometers) {
            Ok(nanometers as i64)
        } else {
            Err("Edge.Cuts coordinates exceed nanometer range".into())
        }
    };
    Ok(Point {
        x_nm: convert(x)?,
        y_nm: convert(y)?,
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
fn nm(value: f64) -> i64 {
    (value * NM_PER_MM).round() as i64
}
fn checked_nonnegative_nm(value: f64) -> Option<i64> {
    let nanometers = (value * NM_PER_MM).round();
    (nanometers.is_finite() && (0.0..-(i64::MIN as f64)).contains(&nanometers))
        .then_some(nanometers as i64)
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
fn child_point(list: &[Sexp], name: &str) -> Option<Point> {
    let xs = child_values(list, name)?;
    Some(point_mm(number(xs.get(1))?, number(xs.get(2))?))
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
    if xs.len() > 3 {
        return Err("Edge.Cuts points must contain exactly two coordinates".into());
    }
    let (Some(x), Some(y)) = (number(xs.get(1)), number(xs.get(2))) else {
        return Ok(None);
    };
    if !x.is_finite() || !y.is_finite() {
        return Err("Edge.Cuts coordinates must be finite".into());
    }
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
impl Sexp {
    fn as_list(&self) -> Option<&[Sexp]> {
        match self {
            Sexp::List(x) => Some(x),
            _ => None,
        }
    }
}

fn parse(input: &str) -> Result<Sexp, String> {
    let tokens = tokenize(input)?;
    let mut position = 0;
    let value = parse_one(&tokens, &mut position)?;
    if position != tokens.len() {
        return Err("trailing tokens in KiCad document".into());
    }
    Ok(value)
}
fn tokenize(input: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '(' | ')' => out.push(c.to_string()),
            '"' => {
                let mut value = String::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => value.push(chars.next().ok_or("unterminated escape")?),
                        _ => value.push(c),
                    }
                }
                if !closed {
                    return Err("unterminated string".into());
                }
                out.push(value);
            }
            c if c.is_whitespace() => {}
            _ => {
                let mut value = String::from(c);
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == '(' || c == ')' {
                        break;
                    }
                    value.push(c);
                    chars.next();
                }
                out.push(value);
            }
        }
    }
    Ok(out)
}
fn parse_one(tokens: &[String], position: &mut usize) -> Result<Sexp, String> {
    let token = tokens.get(*position).ok_or("unexpected end of document")?;
    *position += 1;
    if token == "(" {
        let mut values = Vec::new();
        while tokens.get(*position).map(String::as_str) != Some(")") {
            values.push(parse_one(tokens, position)?);
        }
        *position += 1;
        Ok(Sexp::List(values))
    } else if token == ")" {
        Err("unexpected ')'".into())
    } else {
        Ok(Sexp::Atom(token.clone()))
    }
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
    fn segment_obstacle_envelope_saturates_at_coordinate_limits() {
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
        import_segment(
            segment.as_list().unwrap(),
            Point { x_nm: 0, y_nm: 0 },
            &rules(),
            &mut obstacles,
            &mut routes,
        );

        assert_eq!(obstacles.len(), 1);
        assert_eq!(
            obstacles[0].min,
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            }
        );
        assert_eq!(
            obstacles[0].max,
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }
        );
        assert!(routes.is_empty());
    }

    #[test]
    fn route_arc_obstacle_envelope_saturates_at_coordinate_limits() {
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
        import_route_arc(
            arc.as_list().unwrap(),
            Point { x_nm: 0, y_nm: 0 },
            &rules(),
            &mut obstacles,
            &mut routes,
        );

        assert_eq!(obstacles.len(), 1);
        assert_eq!(
            obstacles[0].min,
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            }
        );
        assert_eq!(
            obstacles[0].max,
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }
        );
        assert!(routes.is_empty());
    }

    #[test]
    fn via_obstacle_envelope_saturates_at_coordinate_limits() {
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
            import_via(
                via.as_list().unwrap(),
                Point { x_nm: 0, y_nm: 0 },
                &rules(),
                &mut obstacles,
                &mut routes,
                &[Layer::Front, Layer::Back],
            );
        }

        assert_eq!(obstacles.len(), 2);
        assert_eq!(
            obstacles[0].min,
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            }
        );
        assert_eq!(
            obstacles[1].max,
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }
        );
        assert!(routes.is_empty());
    }

    #[test]
    fn oval_pad_capsule_endpoints_saturate_at_coordinate_limits() {
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
            );
        }

        assert!(round_obstacles.is_empty());
        assert!(polygon_obstacles.is_empty());
        assert_eq!(capsule_obstacles.len(), 2);
        assert_eq!(
            capsule_obstacles[0].start,
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            }
        );
        assert_eq!(
            capsule_obstacles[1].end,
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }
        );
    }

    #[test]
    fn rectangular_pad_polygon_vertices_saturate_at_coordinate_limits() {
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
            );
        }

        assert!(round_obstacles.is_empty());
        assert!(capsule_obstacles.is_empty());
        assert_eq!(polygon_obstacles.len(), 2);
        assert_eq!(
            polygon_obstacles[0].polygon[0],
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            }
        );
        assert_eq!(
            polygon_obstacles[1].polygon[2],
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }
        );
    }

    #[test]
    fn custom_pad_polygon_vertices_saturate_at_coordinate_limits() {
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
        )
        .unwrap();
        let maximum = custom_pad_polygon(
            values,
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            },
            0.0,
        )
        .unwrap();

        assert_eq!(minimum.len(), 3);
        assert_eq!(
            minimum[0],
            Point {
                x_nm: i64::MIN,
                y_nm: i64::MIN,
            }
        );
        assert_eq!(
            maximum[2],
            Point {
                x_nm: i64::MAX,
                y_nm: i64::MAX,
            }
        );
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
}

use pcbex_core::{
    Board, CapsuleObstacle, DifferentialPair, Footprint, Keepout, Layer, Net, NetClassRules,
    Obstacle, Pad, PadShape, Point, PolygonObstacle, RoundObstacle, Route, RouteArc, Rules,
    Segment, Terminal, Via, ViaKind,
    checking::check_board,
    placement::{BoardSide, Component, Connection, PinRef, PlacementProblem},
};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

const NM_PER_MM: f64 = 1_000_000.0;
const ARC_CHORD_TOLERANCE_NM: f64 = 10_000.0;

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

    let net_classes = import_net_classes(top, &rules, &mut nets);
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
                import_copper_zone(xs, min, &mut footprint_geometry.polygon_obstacles);
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
        width_nm: max.x_nm - min.x_nm,
        height_nm: max.y_nm - min.y_nm,
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
        manufacturing_rules: None,
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
        .retain(|route| !incomplete.contains(&route.net_id));
    let existing_route_net_ids = board.routes.iter().map(|route| route.net_id).collect();
    Ok(ImportedBoard {
        board,
        source: source.to_string(),
        origin: min,
        existing_route_net_ids,
    })
}

fn import_net_classes(
    top: &[Sexp],
    defaults: &Rules,
    nets: &mut HashMap<u32, Net>,
) -> HashMap<String, NetClassRules> {
    let mut classes = HashMap::new();
    let net_ids_by_name: HashMap<_, _> = nets
        .iter()
        .map(|(id, net)| (net.name.clone(), *id))
        .collect();
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
                continue;
            };
            let dimension = |key: &str, fallback: i64| {
                child_values(values, key)
                    .and_then(|value| number(value.get(1)))
                    .map(nm)
                    .unwrap_or(fallback)
            };
            let optional_dimension = |key: &str| {
                child_values(values, key)
                    .and_then(|value| number(value.get(1)))
                    .map(nm)
            };
            classes.insert(
                name.to_string(),
                NetClassRules {
                    track_width_nm: dimension("trace_width", defaults.track_width_nm),
                    clearance_nm: dimension("clearance", defaults.clearance_nm),
                    via_diameter_nm: dimension("via_dia", defaults.via_diameter_nm),
                    via_drill_nm: dimension("via_drill", defaults.via_drill_nm),
                    layers: None,
                    differential_width_nm: optional_dimension("diff_pair_width"),
                    differential_gap_nm: optional_dimension("diff_pair_gap"),
                    minimum_length_nm: None,
                    maximum_length_nm: None,
                },
            );
            for child in values {
                let Some(assignment) = child.as_list() else {
                    continue;
                };
                if atom(assignment.first()) == Some("add_net")
                    && let Some(net_name) = atom(assignment.get(1))
                    && let Some(net_id) = net_ids_by_name.get(net_name)
                    && let Some(net) = nets.get_mut(net_id)
                {
                    net.class = Some(name.to_string());
                }
            }
        }
    }
    classes
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
                let dx = mm(pad.position.x_nm - footprint.position.x_nm);
                let dy = mm(pad.position.y_nm - footprint.position.y_nm);
                let (local_x, local_y) = rotate(dx, dy, -footprint.rotation_deg);
                let local = point_mm(local_x, local_y);
                min_x = min_x.min(local.x_nm - pad.width_nm / 2);
                min_y = min_y.min(local.y_nm - pad.height_nm / 2);
                max_x = max_x.max(local.x_nm + pad.width_nm / 2);
                max_y = max_y.max(local.y_nm + pad.height_nm / 2);
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
                (max_x - min_x).max(1_000_000),
                (max_y - min_y).max(1_000_000),
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
                    "  (zone (net {}) (net_name \"\") (layer \"{}\") (hatch edge 0.5) (teardrop (type padvia)) (polygon (pts",
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
            x_nm: point.x_nm + self.origin.x_nm,
            y_nm: point.y_nm + self.origin.y_nm,
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
    Some((
        polygon.iter().map(|point| point.x_nm).max()?
            - polygon.iter().map(|point| point.x_nm).min()?,
        polygon.iter().map(|point| point.y_nm).max()?
            - polygon.iter().map(|point| point.y_nm).min()?,
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
    for item in top {
        let Some(xs) = item.as_list() else { continue };
        if child_atom(xs, "layer") != Some("Edge.Cuts") {
            continue;
        }
        match atom(xs.first()) {
            Some("gr_line") => {
                if let (Some(start), Some(end)) = (child_point(xs, "start"), child_point(xs, "end"))
                {
                    lines.push((start, end));
                }
            }
            Some("gr_arc") => {
                let (Some(start), Some(mid), Some(end)) = (
                    child_point(xs, "start"),
                    child_point(xs, "mid"),
                    child_point(xs, "end"),
                ) else {
                    return Err("Edge.Cuts arc requires start, mid, and end points".into());
                };
                for pair in sample_arc(start, mid, end)?.windows(2) {
                    lines.push((pair[0], pair[1]));
                }
            }
            Some("gr_rect") => {
                if let (Some(start), Some(end)) = (child_point(xs, "start"), child_point(xs, "end"))
                {
                    let top_right = Point {
                        x_nm: end.x_nm,
                        y_nm: start.y_nm,
                    };
                    let bottom_left = Point {
                        x_nm: start.x_nm,
                        y_nm: end.y_nm,
                    };
                    lines.extend([
                        (start, top_right),
                        (top_right, end),
                        (end, bottom_left),
                        (bottom_left, start),
                    ]);
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
        let mut unused = lines;
        let mut contours = Vec::new();
        while !unused.is_empty() {
            let (start, mut current) = unused.remove(0);
            let mut ordered = vec![start];
            while current != start {
                ordered.push(current);
                let Some((index, next)) =
                    unused
                        .iter()
                        .enumerate()
                        .find_map(|(index, (edge_start, edge_end))| {
                            if *edge_start == current {
                                Some((index, *edge_end))
                            } else if *edge_end == current {
                                Some((index, *edge_start))
                            } else {
                                None
                            }
                        })
                else {
                    return Err("Edge.Cuts primitives do not form closed contours".into());
                };
                unused.remove(index);
                current = next;
            }
            if ordered.len() < 3 {
                return Err("Edge.Cuts contour requires at least three points".into());
            }
            contours.push(ordered);
        }
        contours
    };
    contours.sort_by_key(|contour| std::cmp::Reverse(polygon_twice_area(contour).abs()));
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
    if min == max || twice_area == 0 {
        return Err("Edge.Cuts outline has zero area".into());
    }
    if cutouts.iter().any(|cutout| {
        polygon_twice_area(cutout) == 0
            || cutout
                .iter()
                .any(|point| !point_in_polygon(*point, &outline))
    }) {
        return Err("Edge.Cuts cutouts must be inside the outer outline".into());
    }
    Ok(BoardGeometry {
        min,
        max,
        outline,
        cutouts,
    })
}

fn polygon_twice_area(polygon: &[Point]) -> i128 {
    polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
        .map(|(a, b)| a.x_nm as i128 * b.y_nm as i128 - b.x_nm as i128 * a.y_nm as i128)
        .sum()
}

fn point_in_polygon(point: Point, polygon: &[Point]) -> bool {
    let mut inside = false;
    for (start, end) in polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
    {
        let crosses = (start.y_nm > point.y_nm) != (end.y_nm > point.y_nm)
            && (point.x_nm as f64)
                < (end.x_nm - start.x_nm) as f64 * (point.y_nm - start.y_nm) as f64
                    / (end.y_nm - start.y_nm) as f64
                    + start.x_nm as f64;
        if crosses {
            inside = !inside;
        }
    }
    inside
}

fn sample_arc(start: Point, mid: Point, end: Point) -> Result<Vec<Point>, String> {
    let (x1, y1) = (start.x_nm as f64, start.y_nm as f64);
    let (x2, y2) = (mid.x_nm as f64, mid.y_nm as f64);
    let (x3, y3) = (end.x_nm as f64, end.y_nm as f64);
    let determinant = 2.0 * (x1 * (y2 - y3) + x2 * (y3 - y1) + x3 * (y1 - y2));
    if determinant.abs() < 1.0 {
        return Err("Edge.Cuts arc points must not be collinear".into());
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
    let max_step = 2.0 * (1.0 - (ARC_CHORD_TOLERANCE_NM / radius).min(1.0)).acos();
    let steps = (sweep.abs() / max_step.max(1e-6)).ceil().max(1.0) as usize;
    let mut points = Vec::with_capacity(steps + 1);
    for index in 0..=steps {
        let angle = start_angle + sweep * index as f64 / steps as f64;
        points.push(Point {
            x_nm: (center_x + radius * angle.cos()).round() as i64,
            y_nm: (center_y + radius * angle.sin()).round() as i64,
        });
    }
    points[0] = start;
    points[steps] = end;
    Ok(points)
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
            x_nm: a.x_nm.min(b.x_nm) - width / 2,
            y_nm: a.y_nm.min(b.y_nm) - width / 2,
        },
        max: Point {
            x_nm: a.x_nm.max(b.x_nm) + width / 2,
            y_nm: a.y_nm.max(b.y_nm) + width / 2,
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
            x_nm: start.x_nm.min(mid.x_nm).min(end.x_nm) - width / 2,
            y_nm: start.y_nm.min(mid.y_nm).min(end.y_nm) - width / 2,
        },
        max: Point {
            x_nm: start.x_nm.max(mid.x_nm).max(end.x_nm) + width / 2,
            y_nm: start.y_nm.max(mid.y_nm).max(end.y_nm) + width / 2,
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
    if child_values(xs, "keepout").is_none() {
        return;
    }
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
    });
}

fn import_copper_zone(xs: &[Sexp], origin: Point, polygon_obstacles: &mut Vec<PolygonObstacle>) {
    if child_values(xs, "keepout").is_some() {
        return;
    }
    let Some(net_id) = child_values(xs, "net").and_then(|values| number_u32(values.get(1))) else {
        return;
    };
    if net_id == 0 {
        return;
    }
    let zone_layer = child_atom(xs, "layer").and_then(parse_layer);
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
        let polygon: Vec<_> = values
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
        if polygon.len() >= 3 {
            polygon_obstacles.push(PolygonObstacle {
                polygon,
                layers: vec![layer],
                net_id: Some(net_id),
            });
        }
    }
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
            x_nm: center.x_nm - width / 2,
            y_nm: center.y_nm - height / 2,
        },
        max: Point {
            x_nm: center.x_nm + width / 2,
            y_nm: center.y_nm + height / 2,
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
                    x_nm: center.x_nm - nm(dx),
                    y_nm: center.y_nm - nm(dy),
                },
                end: Point {
                    x_nm: center.x_nm + nm(dx),
                    y_nm: center.y_nm + nm(dy),
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
                        x_nm: center.x_nm + nm(x),
                        y_nm: center.y_nm + nm(y),
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
                    x_nm: center.x_nm + nm(x),
                    y_nm: center.y_nm + nm(y),
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
fn point_mm(x: f64, y: f64) -> Point {
    Point {
        x_nm: nm(x),
        y_nm: nm(y),
    }
}
fn relative(p: Point, origin: Point) -> Point {
    Point {
        x_nm: p.x_nm - origin.x_nm,
        y_nm: p.y_nm - origin.y_nm,
    }
}
fn nm(value: f64) -> i64 {
    (value * NM_PER_MM).round() as i64
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
fn child_atom<'a>(list: &'a [Sexp], name: &str) -> Option<&'a str> {
    atom(child_values(list, name)?.get(1))
}
fn child_point(list: &[Sexp], name: &str) -> Option<Point> {
    let xs = child_values(list, name)?;
    Some(point_mm(number(xs.get(1))?, number(xs.get(2))?))
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
            }])
            .unwrap();

        assert!(output.contains("(arc (start 15.000000 26.000000)"));
        assert!(output.contains("(teardrop (type padvia))"));
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
    fn rejects_collinear_edge_cuts_arc() {
        let pcb = r#"(kicad_pcb
          (gr_arc (start 0 0) (mid 10 0) (end 20 0) (layer "Edge.Cuts"))
        )"#;
        assert!(import(pcb, rules()).unwrap_err().contains("collinear"));
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
        assert_eq!(
            imported.board.keepouts[0].polygon[0],
            Point {
                x_nm: 4_000_000,
                y_nm: 5_000_000
            }
        );
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
        assert_eq!(pads[1].shape, PadShape::Trapezoid);
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

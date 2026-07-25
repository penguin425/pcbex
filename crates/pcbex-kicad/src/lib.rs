use pcbex_core::{
    Board, CapsuleObstacle, Footprint, Keepout, Layer, Net, NetClassRules, Obstacle, Pad, PadShape,
    Point, PolygonObstacle, RoundObstacle, Route, Rules, Segment, Terminal, Via,
    checking::check_board,
};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

const NM_PER_MM: f64 = 1_000_000.0;

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

pub fn import(source: &str, rules: Rules) -> Result<ImportedBoard, String> {
    let root = parse(source)?;
    let top = root
        .as_list()
        .ok_or_else(|| "KiCad document is not an s-expression".to_string())?;
    if atom(top.first()) != Some("kicad_pcb") {
        return Err("expected a kicad_pcb document".into());
    }

    let (min, max, outline) = board_bounds(top)?;
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
    let mut round_obstacles = Vec::new();
    let mut capsule_obstacles = Vec::new();
    let mut polygon_obstacles = Vec::new();
    let mut keepouts = Vec::new();
    let mut footprints = Vec::new();
    let mut route_candidates = HashMap::new();
    for item in top {
        let Some(xs) = item.as_list() else { continue };
        match atom(xs.first()) {
            Some("footprint") => import_footprint(
                xs,
                min,
                &mut nets,
                &mut round_obstacles,
                &mut capsule_obstacles,
                &mut polygon_obstacles,
                &mut footprints,
            ),
            Some("segment") => {
                import_segment(xs, min, &rules, &mut obstacles, &mut route_candidates)
            }
            Some("via") => import_via(xs, min, &rules, &mut obstacles, &mut route_candidates),
            Some("zone") => import_keepout(xs, min, &mut keepouts),
            _ => {}
        }
    }
    let mut nets: Vec<_> = nets
        .into_values()
        .filter(|n| !n.terminals.is_empty())
        .collect();
    nets.sort_by_key(|n| n.id);
    let mut routes: Vec<_> = route_candidates.into_values().collect();
    routes.sort_by_key(|route| route.net_id);
    let mut board = Board {
        width_nm: max.x_nm - min.x_nm,
        height_nm: max.y_nm - min.y_nm,
        outline: outline
            .into_iter()
            .map(|point| relative(point, min))
            .collect(),
        rules,
        obstacles,
        round_obstacles,
        capsule_obstacles,
        polygon_obstacles,
        keepouts,
        footprints,
        net_classes,
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
            classes.insert(
                name.to_string(),
                NetClassRules {
                    track_width_nm: dimension("trace_width", defaults.track_width_nm),
                    clearance_nm: dimension("clearance", defaults.clearance_nm),
                    via_diameter_nm: dimension("via_dia", defaults.via_diameter_nm),
                    via_drill_nm: dimension("via_drill", defaults.via_drill_nm),
                    layers: None,
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

impl ImportedBoard {
    pub fn origin(&self) -> Point {
        self.origin
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
            for via in &route.vias {
                let at = self.absolute(via.position);
                writeln!(
                    generated,
                    "  (via (at {:.6} {:.6}) (size {:.6}) (drill {:.6}) (layers \"F.Cu\" \"B.Cu\") (net {}))",
                    mm(at.x_nm), mm(at.y_nm), mm(via.diameter_nm), mm(via.drill_nm), route.net_id
                ).map_err(|e| e.to_string())?;
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

fn board_bounds(top: &[Sexp]) -> Result<(Point, Point, Vec<Point>), String> {
    let mut lines = Vec::new();
    for item in top {
        let Some(xs) = item.as_list() else { continue };
        if atom(xs.first()) != Some("gr_line") || child_atom(xs, "layer") != Some("Edge.Cuts") {
            continue;
        }
        if let (Some(start), Some(end)) = (child_point(xs, "start"), child_point(xs, "end")) {
            lines.push((start, end));
        }
    }
    let outline = if lines.is_empty() {
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
        if rectangles.len() != 1 {
            return Err("exactly one closed Edge.Cuts outline is required".into());
        }
        let (start, end) = rectangles[0];
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
    } else {
        let mut unused = lines;
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
                return Err("Edge.Cuts lines do not form a closed outline".into());
            };
            unused.remove(index);
            current = next;
        }
        if !unused.is_empty() || ordered.len() < 3 {
            return Err("Edge.Cuts must form one closed outline".into());
        }
        ordered
    };
    let min = Point {
        x_nm: outline.iter().map(|p| p.x_nm).min().unwrap(),
        y_nm: outline.iter().map(|p| p.y_nm).min().unwrap(),
    };
    let max = Point {
        x_nm: outline.iter().map(|p| p.x_nm).max().unwrap(),
        y_nm: outline.iter().map(|p| p.y_nm).max().unwrap(),
    };
    let twice_area: i128 = outline
        .iter()
        .zip(outline.iter().cycle().skip(1))
        .take(outline.len())
        .map(|(a, b)| a.x_nm as i128 * b.y_nm as i128 - b.x_nm as i128 * a.y_nm as i128)
        .sum();
    if min == max || twice_area == 0 {
        return Err("Edge.Cuts outline has zero area".into());
    }
    Ok((min, max, outline))
}

fn import_footprint(
    xs: &[Sexp],
    origin: Point,
    nets: &mut HashMap<u32, Net>,
    round_obstacles: &mut Vec<RoundObstacle>,
    capsule_obstacles: &mut Vec<CapsuleObstacle>,
    polygon_obstacles: &mut Vec<PolygonObstacle>,
    footprints: &mut Vec<Footprint>,
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
        let layers = pad_layers(pad);
        let size = child_values(pad, "size");
        let width = size.and_then(|v| number(v.get(1))).unwrap_or(1.0);
        let height = size.and_then(|v| number(v.get(2))).unwrap_or(width);
        let pad_angle = at.and_then(|v| number(v.get(3))).unwrap_or(0.0);
        let shape = match atom(pad.get(3)) {
            Some("circle") => PadShape::Circle,
            Some("oval") => PadShape::Oval,
            _ => PadShape::Rect,
        };
        let (bbox_width, bbox_height) = rotated_size(width, height, angle + pad_angle);
        let net_id = child_values(pad, "net").and_then(|values| number_u32(values.get(1)));
        model.pads.push(Pad {
            number: atom(pad.get(1)).unwrap_or("").to_string(),
            position,
            width_nm: nm(bbox_width),
            height_nm: nm(bbox_height),
            shape,
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
                position,
                width,
                height,
                angle + pad_angle,
                layers,
                Some(id),
                round_obstacles,
                capsule_obstacles,
                polygon_obstacles,
            );
            continue;
        }
        add_pad_obstacle(
            shape,
            position,
            width,
            height,
            angle + pad_angle,
            layers,
            None,
            round_obstacles,
            capsule_obstacles,
            polygon_obstacles,
        );
    }
    footprints.push(model);
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
                vias: Vec::new(),
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

fn import_via(
    xs: &[Sexp],
    origin: Point,
    rules: &Rules,
    obstacles: &mut Vec<Obstacle>,
    routes: &mut HashMap<u32, Route>,
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
    obstacles.push(rect_obstacle(
        at,
        size,
        size,
        vec![Layer::Front, Layer::Back],
        net_id,
    ));
    if let Some(net_id) = net_id.filter(|id| *id != 0) {
        routes
            .entry(net_id)
            .or_insert_with(|| Route {
                net_id,
                segments: Vec::new(),
                vias: Vec::new(),
            })
            .vias
            .push(Via {
                position: at,
                diameter_nm: size,
                drill_nm: drill,
            });
    }
}

fn import_keepout(xs: &[Sexp], origin: Point, keepouts: &mut Vec<Keepout>) {
    if child_values(xs, "keepout").is_none() {
        return;
    }
    let layers = if let Some(layer) = child_atom(xs, "layer").and_then(parse_layer) {
        vec![layer]
    } else if matches!(child_atom(xs, "layer"), Some("*.Cu") | Some("F&B.Cu")) {
        vec![Layer::Front, Layer::Back]
    } else if let Some(values) = child_values(xs, "layers") {
        let mut layers = Vec::new();
        for value in values.iter().skip(1).filter_map(|value| atom(Some(value))) {
            if matches!(value, "*.Cu" | "F&B.Cu") {
                layers.extend([Layer::Front, Layer::Back]);
            } else if let Some(layer) = parse_layer(value) {
                layers.push(layer);
            }
        }
        layers.sort_by_key(|layer| if *layer == Layer::Front { 0 } else { 1 });
        layers.dedup();
        layers
    } else {
        vec![Layer::Front, Layer::Back]
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
        PadShape::Rect => {
            let half_width = width_mm / 2.0;
            let half_height = height_mm / 2.0;
            let polygon = [
                (-half_width, -half_height),
                (half_width, -half_height),
                (half_width, half_height),
                (-half_width, half_height),
            ]
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
fn pad_layers(pad: &[Sexp]) -> Vec<Layer> {
    let Some(v) = child_values(pad, "layers") else {
        return vec![Layer::Front, Layer::Back];
    };
    let front = v
        .iter()
        .skip(1)
        .any(|x| matches!(atom(Some(x)), Some("F.Cu") | Some("*.Cu")));
    let back = v
        .iter()
        .skip(1)
        .any(|x| matches!(atom(Some(x)), Some("B.Cu") | Some("*.Cu")));
    let mut layers = Vec::new();
    if front {
        layers.push(Layer::Front);
    }
    if back {
        layers.push(Layer::Back);
    }
    if layers.is_empty() {
        layers.push(Layer::Front);
    }
    layers
}
fn parse_layer(value: &str) -> Option<Layer> {
    match value {
        "F.Cu" => Some(Layer::Front),
        "B.Cu" => Some(Layer::Back),
        _ => None,
    }
}
fn layer_name(layer: Layer) -> &'static str {
    match layer {
        Layer::Front => "F.Cu",
        Layer::Back => "B.Cu",
    }
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
}

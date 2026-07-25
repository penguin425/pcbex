use serde::{Deserialize, Serialize};
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Layer {
    #[serde(rename = "F.Cu")]
    Front,
    #[serde(rename = "B.Cu")]
    Back,
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
    pub layers: Vec<Layer>,
    pub net_id: Option<u32>,
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
    pub rules: Rules,
    #[serde(default)]
    pub obstacles: Vec<Obstacle>,
    #[serde(default)]
    pub footprints: Vec<Footprint>,
    #[serde(default)]
    pub net_classes: HashMap<String, NetClassRules>,
    #[serde(default)]
    pub nets: Vec<Net>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

impl Board {
    pub fn rules_for_net(&self, net_id: u32) -> Rules {
        self.nets
            .iter()
            .find(|net| net.id == net_id)
            .and_then(|net| net.class.as_ref())
            .and_then(|class| self.net_classes.get(class))
            .map_or_else(
                || self.rules.clone(),
                |rules| rules.merged_with(&self.rules),
            )
    }

    pub fn layers_for_net(&self, net_id: u32) -> Option<&[Layer]> {
        self.nets
            .iter()
            .find(|net| net.id == net_id)
            .and_then(|net| net.class.as_ref())
            .and_then(|class| self.net_classes.get(class))
            .and_then(|rules| rules.layers.as_deref())
    }

    fn maximum_routing_envelope(&self) -> (Nm, Nm) {
        self.net_classes.values().fold(
            (self.rules.track_width_nm, self.rules.clearance_nm),
            |(width, clearance), rules| {
                (
                    width.max(rules.track_width_nm),
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
pub struct Via {
    pub position: Point,
    pub diameter_nm: Nm,
    pub drill_nm: Nm,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Route {
    pub net_id: u32,
    pub segments: Vec<Segment>,
    pub vias: Vec<Via>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteReport {
    pub preserved: Vec<String>,
    pub routed: Vec<String>,
    pub unrouted: Vec<String>,
    pub expanded_states: usize,
    pub reroute_passes: usize,
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
    congestion: HashMap<(i32, i32, u8), u16>,
}

impl<'a> Router<'a> {
    pub fn new(board: &'a Board) -> Result<Self, String> {
        if board.rules.grid_nm <= 0 {
            return Err("grid_nm must be positive".into());
        }
        if board.width_nm <= 0 || board.height_nm <= 0 {
            return Err("board dimensions must be positive".into());
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
            congestion: HashMap::new(),
        };
        router.rasterize_obstacles();
        Ok(router)
    }

    fn rasterize_obstacles(&mut self) {
        let g = self.board.rules.grid_nm;
        let (maximum_width, maximum_clearance) = self.board.maximum_routing_envelope();
        let inflate = maximum_width / 2 + maximum_clearance;
        for o in &self.board.obstacles {
            let min_x = ((o.min.x_nm - inflate).max(0) / g) as i32;
            let min_y = ((o.min.y_nm - inflate).max(0) / g) as i32;
            let max_x = ((o.max.x_nm + inflate).min(self.board.width_nm) / g) as i32;
            let max_y = ((o.max.y_nm + inflate).min(self.board.height_nm) / g) as i32;
            for layer in &o.layers {
                let l = layer_index(*layer);
                for y in min_y..=max_y {
                    for x in min_x..=max_x {
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
        let mut failed_ids = HashSet::new();
        let mut best_routes = self.board.routes.clone();
        let mut best_report = RouteReport {
            preserved: preserved.clone(),
            unrouted: nets.iter().map(|n| n.name.clone()).collect(),
            ..RouteReport::default()
        };
        let mut total_expanded = 0;
        for attempt in 0..4 {
            self.occupied.clear();
            for route in &self.board.routes {
                self.commit(route);
            }
            if !failed_ids.is_empty() {
                nets.sort_by_key(|n| {
                    (
                        !failed_ids.contains(&n.id),
                        std::cmp::Reverse(n.priority),
                        std::cmp::Reverse(net_span(n)),
                    )
                });
            }
            let mut routes = self.board.routes.clone();
            let mut report = RouteReport {
                preserved: preserved.clone(),
                ..RouteReport::default()
            };
            failed_ids.clear();
            for net in &nets {
                match self.route_net(net) {
                    Some((route, expanded)) => {
                        total_expanded += expanded;
                        self.commit(&route);
                        report.routed.push(net.name.clone());
                        routes.push(route);
                    }
                    None => {
                        report.unrouted.push(net.name.clone());
                        failed_ids.insert(net.id);
                    }
                }
            }
            if report.unrouted.len() < best_report.unrouted.len() {
                best_routes = routes.clone();
                best_report = report.clone();
            }
            if report.unrouted.is_empty() {
                report.expanded_states = total_expanded;
                report.reroute_passes = attempt + 1;
                return (routes, report);
            }
            // History cost makes the next full rip-up pass avoid the same channels.
            for &cell in &self.occupied {
                let value = self.congestion.entry(cell).or_default();
                *value = value.saturating_add(8);
            }
        }
        best_report.expanded_states = total_expanded;
        best_report.reroute_passes = 4;
        (best_routes, best_report)
    }

    fn route_net(&self, net: &Net) -> Option<(Route, usize)> {
        if net.terminals.len() < 2 {
            return Some((
                Route {
                    net_id: net.id,
                    segments: vec![],
                    vias: vec![],
                },
                0,
            ));
        }
        let mut route = Route {
            net_id: net.id,
            segments: vec![],
            vias: vec![],
        };
        let rules = self.board.rules_for_net(net.id);
        let mut expanded = 0;
        for (pair_index, pair) in net.terminals.windows(2).enumerate() {
            let (nodes, count) = self.astar(net.id, &pair[0], &pair[1], &rules)?;
            expanded += count;
            if pair_index == 0 {
                append_terminal_access(&mut route, pair[0].position, nodes[0], &rules, true);
            }
            append_path(&mut route, &nodes, &rules);
            append_terminal_access(
                &mut route,
                pair[1].position,
                *nodes.last().unwrap(),
                &rules,
                false,
            );
        }
        Some((route, expanded))
    }

    fn astar(
        &self,
        net_id: u32,
        start: &Terminal,
        goal: &Terminal,
        rules: &Rules,
    ) -> Option<(Vec<Node>, usize)> {
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
        let gx = nearest_grid(goal.position.x_nm, g) as i32;
        let gy = nearest_grid(goal.position.y_nm, g) as i32;
        let max_x = (self.board.width_nm / g) as i32;
        let max_y = (self.board.height_nm / g) as i32;
        let allowed_layers = self.board.layers_for_net(net_id);
        let terminal_layers = |terminal: &Terminal| {
            terminal
                .layers
                .iter()
                .copied()
                .filter(|layer| allowed_layers.is_none_or(|allowed| allowed.contains(layer)))
                .collect::<Vec<_>>()
        };
        let goals: HashSet<u8> = terminal_layers(goal).into_iter().map(layer_index).collect();
        let mut open = BinaryHeap::new();
        let mut costs = HashMap::new();
        let mut prev = HashMap::new();
        for layer in terminal_layers(start) {
            let n = Node {
                x: sx,
                y: sy,
                layer: layer_index(layer),
                dir: 8,
            };
            costs.insert(n, 0u64);
            open.push(QueueItem {
                score: heuristic(sx, sy, gx, gy),
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
            if item.node.x == gx && item.node.y == gy && goals.contains(&item.node.layer) {
                let mut path = vec![item.node];
                let mut cur = item.node;
                while let Some(p) = prev.get(&cur) {
                    cur = *p;
                    path.push(cur);
                }
                path.reverse();
                return Some((path, expanded));
            }
            for (dir, (dx, dy)) in DIRS.iter().enumerate() {
                let nx = item.node.x + dx;
                let ny = item.node.y + dy;
                if nx < 0 || ny < 0 || nx > max_x || ny > max_y {
                    continue;
                }
                let cell = (nx, ny, item.node.layer);
                let endpoint = (nx == gx && ny == gy) || (nx == sx && ny == sy);
                if !endpoint
                    && (self.blocked.contains(&cell)
                        || self.foreign_obstacle(cell, net_id)
                        || self.occupied.contains(&cell))
                {
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
                    gx,
                    gy,
                    &mut costs,
                    &mut prev,
                    &mut open,
                );
            }
            let other = 1 - item.node.layer;
            let cell = (item.node.x, item.node.y, other);
            if allowed_layers.is_none_or(|allowed| allowed.contains(&index_layer(other)))
                && !self.blocked.contains(&cell)
                && !self.foreign_obstacle(cell, net_id)
                && !self.occupied.contains(&cell)
            {
                let n = Node {
                    x: item.node.x,
                    y: item.node.y,
                    layer: other,
                    dir: item.node.dir,
                };
                self.relax(
                    item.node,
                    n,
                    item.cost + rules.via_cost as u64,
                    gx,
                    gy,
                    &mut costs,
                    &mut prev,
                    &mut open,
                );
            }
        }
        None
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
        gx: i32,
        gy: i32,
        costs: &mut HashMap<Node, u64>,
        prev: &mut HashMap<Node, Node>,
        open: &mut BinaryHeap<QueueItem>,
    ) {
        if cost < *costs.get(&to).unwrap_or(&u64::MAX) {
            costs.insert(to, cost);
            prev.insert(to, from);
            open.push(QueueItem {
                score: cost + heuristic(to.x, to.y, gx, gy),
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
        let (maximum_width, maximum_clearance) = self.board.maximum_routing_envelope();
        for s in &route.segments {
            let clearance_radius =
                (s.width_nm / 2 + maximum_width / 2 + maximum_clearance + g - 1) / g;
            for (x, y) in raster_line_cells(
                s.start.x_nm / g,
                s.start.y_nm / g,
                s.end.x_nm / g,
                s.end.y_nm / g,
            ) {
                for oy in -clearance_radius..=clearance_radius {
                    for ox in -clearance_radius..=clearance_radius {
                        if ox * ox + oy * oy <= clearance_radius * clearance_radius {
                            self.occupied.insert((
                                (x + ox) as i32,
                                (y + oy) as i32,
                                layer_index(s.layer),
                            ));
                        }
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

fn heuristic(x: i32, y: i32, gx: i32, gy: i32) -> u64 {
    let dx = (x - gx).unsigned_abs() as u64;
    let dy = (y - gy).unsigned_abs() as u64;
    14 * dx.min(dy) + 10 * (dx.max(dy) - dx.min(dy))
}
fn layer_index(l: Layer) -> u8 {
    if l == Layer::Front { 0 } else { 1 }
}
fn index_layer(l: u8) -> Layer {
    if l == 0 { Layer::Front } else { Layer::Back }
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
fn append_path(route: &mut Route, nodes: &[Node], rules: &Rules) {
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
            route.vias.push(Via {
                position: Point {
                    x_nm: pair[0].x as Nm * g,
                    y_nm: pair[0].y as Nm * g,
                },
                diameter_nm: rules.via_diameter_nm,
                drill_nm: rules.via_drill_nm,
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
    let (routes, report) = Router::new(board)?.route_all();
    let mut out = board.clone();
    out.routes = routes;
    Ok((out, report))
}

pub fn render_svg(board: &Board) -> String {
    let scale = 1_000_000.0;
    let w = board.width_nm as f64 / scale;
    let h = board.height_nm as f64 / scale;
    let mut s = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}"><rect width="{w}" height="{h}" fill="#152019" stroke="#ccc" stroke-width=".2"/>"##
    );
    for o in &board.obstacles {
        s.push_str(&format!(
            r##"<rect x="{}" y="{}" width="{}" height="{}" fill="#555"/>"##,
            o.min.x_nm as f64 / scale,
            o.min.y_nm as f64 / scale,
            (o.max.x_nm - o.min.x_nm) as f64 / scale,
            (o.max.y_nm - o.min.y_nm) as f64 / scale
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
            footprints: vec![],
            net_classes: HashMap::new(),
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
        assert_eq!(routed.routes.len(), 10);
        assert!(crate::checking::check_board(&routed).is_clean());
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
    fn reports_unrouted_after_bounded_reroute_passes() {
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
        assert_eq!(report.reroute_passes, 4);
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
                segments: vec![],
                vias: vec![],
            },
            Route {
                net_id: 1,
                segments: vec![],
                vias: vec![],
            },
        ];

        assert_eq!(
            route_board(&b).unwrap_err(),
            "net 1 has more than one existing route"
        );
    }
}

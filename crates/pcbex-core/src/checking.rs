use crate::{Board, Layer, Nm, Point, Route, Segment};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Violation {
    pub rule: String,
    pub message: String,
    pub net_ids: Vec<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CheckReport {
    pub violations: Vec<Violation>,
}

impl CheckReport {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

pub fn check_board(board: &Board) -> CheckReport {
    let mut report = CheckReport::default();
    let routes: HashMap<u32, &Route> = board.routes.iter().map(|r| (r.net_id, r)).collect();
    for net in &board.nets {
        let Some(route) = routes.get(&net.id) else {
            report.push(
                "unrouted",
                format!("net {} has no route", net.name),
                vec![net.id],
            );
            continue;
        };
        for terminal in &net.terminals {
            if !route_touches(
                route,
                terminal.position,
                &terminal.layers,
                board.rules.track_width_nm,
            ) {
                report.push(
                    "unconnected",
                    format!(
                        "net {} does not reach terminal at {},{}",
                        net.name, terminal.position.x_nm, terminal.position.y_nm
                    ),
                    vec![net.id],
                );
            }
        }
    }
    for route in &board.routes {
        for segment in &route.segments {
            check_segment(board, route.net_id, segment, &mut report);
        }
        for via in &route.vias {
            if via.diameter_nm <= via.drill_nm || via.drill_nm <= 0 {
                report.push(
                    "via_size",
                    "via diameter must exceed its positive drill".into(),
                    vec![route.net_id],
                );
            }
            let radius = via.diameter_nm / 2;
            if via.position.x_nm - radius < 0
                || via.position.y_nm - radius < 0
                || via.position.x_nm + radius > board.width_nm
                || via.position.y_nm + radius > board.height_nm
            {
                report.push(
                    "board_edge",
                    "via crosses the board boundary".into(),
                    vec![route.net_id],
                );
            }
            for obstacle in &board.obstacles {
                if obstacle.net_id == Some(route.net_id) {
                    continue;
                }
                let required = radius + board.rules.clearance_nm;
                if point_rect_distance(via.position, obstacle.min, obstacle.max) < required as f64 {
                    report.push(
                        "clearance",
                        "via is too close to an obstacle".into(),
                        vec![route.net_id],
                    );
                    break;
                }
            }
        }
    }
    for (i, a) in board.routes.iter().enumerate() {
        for b in &board.routes[i + 1..] {
            check_route_clearance(board, a, b, &mut report);
        }
    }
    report
}

impl CheckReport {
    fn push(&mut self, rule: &str, message: String, net_ids: Vec<u32>) {
        self.violations.push(Violation {
            rule: rule.into(),
            message,
            net_ids,
        });
    }
}

fn check_segment(board: &Board, net_id: u32, segment: &Segment, report: &mut CheckReport) {
    let dx = (segment.end.x_nm - segment.start.x_nm).abs();
    let dy = (segment.end.y_nm - segment.start.y_nm).abs();
    if dx != 0 && dy != 0 && dx != dy {
        report.push(
            "track_angle",
            "track is not horizontal, vertical, or 45 degrees".into(),
            vec![net_id],
        );
    }
    if segment.width_nm < board.rules.track_width_nm {
        report.push(
            "track_width",
            "track is narrower than the configured minimum".into(),
            vec![net_id],
        );
    }
    let radius = segment.width_nm / 2;
    if [segment.start, segment.end].iter().any(|p| {
        p.x_nm - radius < 0
            || p.y_nm - radius < 0
            || p.x_nm + radius > board.width_nm
            || p.y_nm + radius > board.height_nm
    }) {
        report.push(
            "board_edge",
            "track crosses the board boundary".into(),
            vec![net_id],
        );
    }
    for obstacle in &board.obstacles {
        if obstacle.net_id == Some(net_id) {
            continue;
        }
        if !obstacle.layers.contains(&segment.layer) {
            continue;
        }
        let required = segment.width_nm / 2 + board.rules.clearance_nm;
        if segment_rect_distance(segment, obstacle.min, obstacle.max) < required as f64 {
            report.push(
                "clearance",
                "track is too close to an obstacle".into(),
                vec![net_id],
            );
            break;
        }
    }
}

fn check_route_clearance(board: &Board, a: &Route, b: &Route, report: &mut CheckReport) {
    for sa in &a.segments {
        for sb in &b.segments {
            if sa.layer != sb.layer {
                continue;
            }
            let required =
                (sa.width_nm + sb.width_nm) as f64 / 2.0 + board.rules.clearance_nm as f64;
            if segment_distance(sa.start, sa.end, sb.start, sb.end) < required {
                report.push(
                    "clearance",
                    "tracks from different nets violate clearance".into(),
                    vec![a.net_id, b.net_id],
                );
                return;
            }
        }
        for via in &b.vias {
            let required = sa.width_nm as f64 / 2.0
                + via.diameter_nm as f64 / 2.0
                + board.rules.clearance_nm as f64;
            if point_segment_distance(via.position, sa.start, sa.end) < required {
                report.push(
                    "clearance",
                    "track and via from different nets violate clearance".into(),
                    vec![a.net_id, b.net_id],
                );
                return;
            }
        }
    }
    for via in &a.vias {
        for sb in &b.segments {
            let required = sb.width_nm as f64 / 2.0
                + via.diameter_nm as f64 / 2.0
                + board.rules.clearance_nm as f64;
            if point_segment_distance(via.position, sb.start, sb.end) < required {
                report.push(
                    "clearance",
                    "via and track from different nets violate clearance".into(),
                    vec![a.net_id, b.net_id],
                );
                return;
            }
        }
        for other in &b.vias {
            let required = (via.diameter_nm + other.diameter_nm) as f64 / 2.0
                + board.rules.clearance_nm as f64;
            if distance(via.position, other.position) < required {
                report.push(
                    "clearance",
                    "vias from different nets violate clearance".into(),
                    vec![a.net_id, b.net_id],
                );
                return;
            }
        }
    }
}

fn route_touches(route: &Route, point: Point, layers: &[Layer], width: Nm) -> bool {
    route.segments.iter().any(|s| {
        layers.contains(&s.layer)
            && point_segment_distance(point, s.start, s.end) <= width as f64 / 2.0
    }) || route
        .vias
        .iter()
        .any(|v| distance(v.position, point) <= v.diameter_nm as f64 / 2.0)
}

fn segment_rect_distance(segment: &Segment, min: Point, max: Point) -> f64 {
    if point_in_rect(segment.start, min, max) || point_in_rect(segment.end, min, max) {
        return 0.0;
    }
    let corners = [
        min,
        Point {
            x_nm: max.x_nm,
            y_nm: min.y_nm,
        },
        max,
        Point {
            x_nm: min.x_nm,
            y_nm: max.y_nm,
        },
    ];
    (0..4)
        .map(|i| segment_distance(segment.start, segment.end, corners[i], corners[(i + 1) % 4]))
        .fold(f64::INFINITY, f64::min)
}
fn point_in_rect(p: Point, min: Point, max: Point) -> bool {
    p.x_nm >= min.x_nm && p.x_nm <= max.x_nm && p.y_nm >= min.y_nm && p.y_nm <= max.y_nm
}
fn point_rect_distance(p: Point, min: Point, max: Point) -> f64 {
    let dx = if p.x_nm < min.x_nm {
        min.x_nm - p.x_nm
    } else if p.x_nm > max.x_nm {
        p.x_nm - max.x_nm
    } else {
        0
    };
    let dy = if p.y_nm < min.y_nm {
        min.y_nm - p.y_nm
    } else if p.y_nm > max.y_nm {
        p.y_nm - max.y_nm
    } else {
        0
    };
    (dx as f64).hypot(dy as f64)
}
fn segment_distance(a: Point, b: Point, c: Point, d: Point) -> f64 {
    if intersects(a, b, c, d) {
        return 0.0;
    }
    [
        point_segment_distance(a, c, d),
        point_segment_distance(b, c, d),
        point_segment_distance(c, a, b),
        point_segment_distance(d, a, b),
    ]
    .into_iter()
    .fold(f64::INFINITY, f64::min)
}
fn intersects(a: Point, b: Point, c: Point, d: Point) -> bool {
    let o1 = orientation(a, b, c);
    let o2 = orientation(a, b, d);
    let o3 = orientation(c, d, a);
    let o4 = orientation(c, d, b);
    o1.signum() != o2.signum() && o3.signum() != o4.signum()
}
fn orientation(a: Point, b: Point, c: Point) -> i128 {
    (b.x_nm - a.x_nm) as i128 * (c.y_nm - a.y_nm) as i128
        - (b.y_nm - a.y_nm) as i128 * (c.x_nm - a.x_nm) as i128
}
fn point_segment_distance(p: Point, a: Point, b: Point) -> f64 {
    let dx = (b.x_nm - a.x_nm) as f64;
    let dy = (b.y_nm - a.y_nm) as f64;
    if dx == 0.0 && dy == 0.0 {
        return distance(p, a);
    }
    let t = (((p.x_nm - a.x_nm) as f64 * dx + (p.y_nm - a.y_nm) as f64 * dy) / (dx * dx + dy * dy))
        .clamp(0.0, 1.0);
    let x = a.x_nm as f64 + t * dx;
    let y = a.y_nm as f64 + t * dy;
    ((p.x_nm as f64 - x).powi(2) + (p.y_nm as f64 - y).powi(2)).sqrt()
}
fn distance(a: Point, b: Point) -> f64 {
    ((a.x_nm - b.x_nm) as f64).hypot((a.y_nm - b.y_nm) as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Net, Rules, Terminal};
    fn base() -> Board {
        Board {
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            rules: Rules {
                grid_nm: 250_000,
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                bend_cost: 5,
                via_cost: 20,
            },
            obstacles: vec![],
            footprints: vec![],
            nets: vec![],
            routes: vec![],
        }
    }
    #[test]
    fn detects_cross_net_short() {
        let mut b = base();
        for (id, a, z) in [
            (
                1,
                Point {
                    x_nm: 1_000_000,
                    y_nm: 1_000_000,
                },
                Point {
                    x_nm: 9_000_000,
                    y_nm: 9_000_000,
                },
            ),
            (
                2,
                Point {
                    x_nm: 1_000_000,
                    y_nm: 9_000_000,
                },
                Point {
                    x_nm: 9_000_000,
                    y_nm: 1_000_000,
                },
            ),
        ] {
            b.nets.push(Net {
                id,
                name: id.to_string(),
                terminals: vec![
                    Terminal {
                        position: a,
                        layers: vec![Layer::Front],
                    },
                    Terminal {
                        position: z,
                        layers: vec![Layer::Front],
                    },
                ],
                priority: 0,
            });
            b.routes.push(Route {
                net_id: id,
                segments: vec![Segment {
                    start: a,
                    end: z,
                    layer: Layer::Front,
                    width_nm: 250_000,
                }],
                vias: vec![],
            });
        }
        assert!(
            check_board(&b)
                .violations
                .iter()
                .any(|v| v.rule == "clearance")
        );
    }
}

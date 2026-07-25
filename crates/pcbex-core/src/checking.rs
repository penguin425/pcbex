use crate::geometry::{
    point_in_polygon, point_polygon_closer_than, point_rect_closer_than, point_segment_closer_than,
    point_segment_within, points_closer_than, points_within, segment_polygon_closer_than,
    segment_rect_closer_than, segments_closer_than, segments_within,
};
use crate::{Board, Net, Route, Segment};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
        check_route_connectivity(net, route, &mut report);
    }
    for route in &board.routes {
        for segment in &route.segments {
            check_segment(board, route.net_id, segment, &mut report);
        }
        for via in &route.vias {
            let rules = board.rules_for_net(route.net_id);
            if via.diameter_nm <= via.drill_nm || via.drill_nm <= 0 {
                report.push(
                    "via_size",
                    "via diameter must exceed its positive drill".into(),
                    vec![route.net_id],
                );
            }
            if via.diameter_nm < rules.via_diameter_nm || via.drill_nm < rules.via_drill_nm {
                report.push(
                    "via_size",
                    "via is smaller than its net class minimum".into(),
                    vec![route.net_id],
                );
            }
            if !board.point_inside_board(via.position, via.diameter_nm + 2 * rules.clearance_nm) {
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
                let required_twice = via.diameter_nm + 2 * rules.clearance_nm;
                if point_rect_closer_than(via.position, obstacle.min, obstacle.max, required_twice)
                {
                    report.push(
                        "clearance",
                        "via is too close to an obstacle".into(),
                        vec![route.net_id],
                    );
                    break;
                }
            }
            for obstacle in &board.round_obstacles {
                if obstacle.net_id == Some(route.net_id) {
                    continue;
                }
                let required_twice =
                    via.diameter_nm + obstacle.diameter_nm + 2 * rules.clearance_nm;
                if points_closer_than(via.position, obstacle.center, required_twice) {
                    report.push(
                        "clearance",
                        "via is too close to a round obstacle".into(),
                        vec![route.net_id],
                    );
                    break;
                }
            }
            for obstacle in &board.capsule_obstacles {
                if obstacle.net_id == Some(route.net_id) {
                    continue;
                }
                let required_twice =
                    via.diameter_nm + obstacle.diameter_nm + 2 * rules.clearance_nm;
                if point_segment_closer_than(
                    via.position,
                    obstacle.start,
                    obstacle.end,
                    required_twice,
                ) {
                    report.push(
                        "clearance",
                        "via is too close to a capsule obstacle".into(),
                        vec![route.net_id],
                    );
                    break;
                }
            }
            for obstacle in &board.polygon_obstacles {
                if obstacle.net_id == Some(route.net_id) {
                    continue;
                }
                let required_twice = via.diameter_nm + 2 * rules.clearance_nm;
                if point_in_polygon(via.position, &obstacle.polygon)
                    || point_polygon_closer_than(via.position, &obstacle.polygon, required_twice)
                {
                    report.push(
                        "clearance",
                        "via is too close to a polygon obstacle".into(),
                        vec![route.net_id],
                    );
                    break;
                }
            }
            for keepout in &board.keepouts {
                if keepout.net_id == Some(route.net_id) {
                    continue;
                }
                let required_twice = via.diameter_nm + 2 * rules.clearance_nm;
                if point_in_polygon(via.position, &keepout.polygon)
                    || point_polygon_closer_than(via.position, &keepout.polygon, required_twice)
                {
                    report.push(
                        "clearance",
                        "via is too close to a polygon keepout".into(),
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
    let rules = board.rules_for_net(net_id);
    let dx = (segment.end.x_nm - segment.start.x_nm).abs();
    let dy = (segment.end.y_nm - segment.start.y_nm).abs();
    if dx != 0 && dy != 0 && dx != dy {
        report.push(
            "track_angle",
            "track is not horizontal, vertical, or 45 degrees".into(),
            vec![net_id],
        );
    }
    if segment.width_nm < rules.track_width_nm {
        report.push(
            "track_width",
            "track is narrower than the configured minimum".into(),
            vec![net_id],
        );
    }
    let outline = board.effective_outline();
    if !point_in_polygon(segment.start, &outline)
        || !point_in_polygon(segment.end, &outline)
        || segment_polygon_closer_than(
            segment.start,
            segment.end,
            &outline,
            segment.width_nm + 2 * rules.clearance_nm,
        )
        || board.cutouts.iter().any(|cutout| {
            point_in_polygon(segment.start, cutout)
                || point_in_polygon(segment.end, cutout)
                || segment_polygon_closer_than(
                    segment.start,
                    segment.end,
                    cutout,
                    segment.width_nm + 2 * rules.clearance_nm,
                )
        })
    {
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
        let required_twice = segment.width_nm + 2 * rules.clearance_nm;
        if segment_rect_closer_than(
            segment.start,
            segment.end,
            obstacle.min,
            obstacle.max,
            required_twice,
        ) {
            report.push(
                "clearance",
                "track is too close to an obstacle".into(),
                vec![net_id],
            );
            break;
        }
    }
    for obstacle in &board.round_obstacles {
        if obstacle.net_id == Some(net_id) || !obstacle.layers.contains(&segment.layer) {
            continue;
        }
        let required_twice = segment.width_nm + obstacle.diameter_nm + 2 * rules.clearance_nm;
        if point_segment_closer_than(obstacle.center, segment.start, segment.end, required_twice) {
            report.push(
                "clearance",
                "track is too close to a round obstacle".into(),
                vec![net_id],
            );
            break;
        }
    }
    for obstacle in &board.capsule_obstacles {
        if obstacle.net_id == Some(net_id) || !obstacle.layers.contains(&segment.layer) {
            continue;
        }
        let required_twice = segment.width_nm + obstacle.diameter_nm + 2 * rules.clearance_nm;
        if segments_closer_than(
            segment.start,
            segment.end,
            obstacle.start,
            obstacle.end,
            required_twice,
        ) {
            report.push(
                "clearance",
                "track is too close to a capsule obstacle".into(),
                vec![net_id],
            );
            break;
        }
    }
    for obstacle in &board.polygon_obstacles {
        if obstacle.net_id == Some(net_id) || !obstacle.layers.contains(&segment.layer) {
            continue;
        }
        let required_twice = segment.width_nm + 2 * rules.clearance_nm;
        if point_in_polygon(segment.start, &obstacle.polygon)
            || point_in_polygon(segment.end, &obstacle.polygon)
            || segment_polygon_closer_than(
                segment.start,
                segment.end,
                &obstacle.polygon,
                required_twice,
            )
        {
            report.push(
                "clearance",
                "track is too close to a polygon obstacle".into(),
                vec![net_id],
            );
            break;
        }
    }
    for keepout in &board.keepouts {
        if keepout.net_id == Some(net_id) || !keepout.layers.contains(&segment.layer) {
            continue;
        }
        let required_twice = segment.width_nm + 2 * rules.clearance_nm;
        if point_in_polygon(segment.start, &keepout.polygon)
            || point_in_polygon(segment.end, &keepout.polygon)
            || segment_polygon_closer_than(
                segment.start,
                segment.end,
                &keepout.polygon,
                required_twice,
            )
        {
            report.push(
                "clearance",
                "track is too close to a polygon keepout".into(),
                vec![net_id],
            );
            break;
        }
    }
}

fn check_route_clearance(board: &Board, a: &Route, b: &Route, report: &mut CheckReport) {
    let clearance = board
        .rules_for_net(a.net_id)
        .clearance_nm
        .max(board.rules_for_net(b.net_id).clearance_nm);
    for sa in &a.segments {
        for sb in &b.segments {
            if sa.layer != sb.layer {
                continue;
            }
            let required_twice = sa.width_nm + sb.width_nm + 2 * clearance;
            if segments_closer_than(sa.start, sa.end, sb.start, sb.end, required_twice) {
                report.push(
                    "clearance",
                    "tracks from different nets violate clearance".into(),
                    vec![a.net_id, b.net_id],
                );
                return;
            }
        }
        for via in &b.vias {
            let required_twice = sa.width_nm + via.diameter_nm + 2 * clearance;
            if point_segment_closer_than(via.position, sa.start, sa.end, required_twice) {
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
            let required_twice = sb.width_nm + via.diameter_nm + 2 * clearance;
            if point_segment_closer_than(via.position, sb.start, sb.end, required_twice) {
                report.push(
                    "clearance",
                    "via and track from different nets violate clearance".into(),
                    vec![a.net_id, b.net_id],
                );
                return;
            }
        }
        for other in &b.vias {
            let required_twice = via.diameter_nm + other.diameter_nm + 2 * clearance;
            if points_closer_than(via.position, other.position, required_twice) {
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

fn check_route_connectivity(net: &Net, route: &Route, report: &mut CheckReport) {
    let segment_count = route.segments.len();
    let node_count = segment_count + route.vias.len();
    let mut components = DisjointSet::new(node_count);

    for (index, segment) in route.segments.iter().enumerate() {
        for (other_index, other) in route.segments[..index].iter().enumerate() {
            if segment.layer == other.layer
                && segments_within(
                    segment.start,
                    segment.end,
                    other.start,
                    other.end,
                    segment.width_nm + other.width_nm,
                )
            {
                components.union(index, other_index);
            }
        }
        for (via_index, via) in route.vias.iter().enumerate() {
            if point_segment_within(
                via.position,
                segment.start,
                segment.end,
                segment.width_nm + via.diameter_nm,
            ) {
                components.union(index, segment_count + via_index);
            }
        }
    }
    for (index, via) in route.vias.iter().enumerate() {
        for (other_index, other) in route.vias[..index].iter().enumerate() {
            if points_within(
                via.position,
                other.position,
                via.diameter_nm + other.diameter_nm,
            ) {
                components.union(segment_count + index, segment_count + other_index);
            }
        }
    }

    let mut terminal_nodes = Vec::with_capacity(net.terminals.len());
    for terminal in &net.terminals {
        let touched: Vec<usize> = route
            .segments
            .iter()
            .enumerate()
            .filter(|(_, segment)| {
                terminal.layers.contains(&segment.layer)
                    && point_segment_within(
                        terminal.position,
                        segment.start,
                        segment.end,
                        segment.width_nm,
                    )
            })
            .map(|(index, _)| index)
            .chain(
                route
                    .vias
                    .iter()
                    .enumerate()
                    .filter(|(_, via)| {
                        points_within(via.position, terminal.position, via.diameter_nm)
                    })
                    .map(|(index, _)| segment_count + index),
            )
            .collect();

        if let Some((&first, rest)) = touched.split_first() {
            for &node in rest {
                components.union(first, node);
            }
            terminal_nodes.push(Some(first));
        } else {
            terminal_nodes.push(None);
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

    let terminal_roots: HashSet<usize> = terminal_nodes
        .into_iter()
        .flatten()
        .map(|node| components.find(node))
        .collect();
    if terminal_roots.len() > 1 {
        report.push(
            "disconnected_route",
            format!(
                "net {} is split into disconnected copper components",
                net.name
            ),
            vec![net.id],
        );
    }

    let all_roots: HashSet<usize> = (0..node_count).map(|node| components.find(node)).collect();
    for _ in all_roots.difference(&terminal_roots) {
        report.push(
            "orphan_copper",
            format!(
                "net {} contains copper not connected to a terminal",
                net.name
            ),
            vec![net.id],
        );
    }
}

struct DisjointSet {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl DisjointSet {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            rank: vec![0; len],
        }
    }

    fn find(&mut self, node: usize) -> usize {
        if self.parent[node] != node {
            self.parent[node] = self.find(self.parent[node]);
        }
        self.parent[node]
    }

    fn union(&mut self, left: usize, right: usize) {
        let left_root = self.find(left);
        let right_root = self.find(right);
        if left_root == right_root {
            return;
        }
        match self.rank[left_root].cmp(&self.rank[right_root]) {
            std::cmp::Ordering::Less => self.parent[left_root] = right_root,
            std::cmp::Ordering::Greater => self.parent[right_root] = left_root,
            std::cmp::Ordering::Equal => {
                self.parent[right_root] = left_root;
                self.rank[left_root] += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapsuleObstacle, Layer, Point, RoundObstacle, Rules, Terminal, Via};
    fn base() -> Board {
        Board {
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            outline: vec![],
            cutouts: vec![],
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
            round_obstacles: vec![],
            capsule_obstacles: vec![],
            polygon_obstacles: vec![],
            keepouts: vec![],
            footprints: vec![],
            net_classes: HashMap::new(),
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
                class: None,
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

    #[test]
    fn checks_round_obstacles_without_using_their_bounding_box() {
        let mut board = base();
        let start = Point {
            x_nm: 2_000_000,
            y_nm: 4_000_000,
        };
        let end = Point {
            x_nm: 4_000_000,
            y_nm: 2_000_000,
        };
        board.round_obstacles.push(RoundObstacle {
            center: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            diameter_nm: 4_000_000,
            layers: vec![Layer::Front],
            net_id: None,
        });
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![
                Terminal {
                    position: start,
                    layers: vec![Layer::Front],
                },
                Terminal {
                    position: end,
                    layers: vec![Layer::Front],
                },
            ],
            class: None,
            priority: 0,
        });
        board.routes.push(Route {
            net_id: 1,
            segments: vec![Segment {
                start,
                end,
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            vias: vec![],
        });

        assert!(check_board(&board).is_clean());

        let closer_start = Point {
            x_nm: 2_000_000,
            y_nm: 5_000_000,
        };
        let closer_end = Point {
            x_nm: 5_000_000,
            y_nm: 2_000_000,
        };
        board.nets[0].terminals[0].position = closer_start;
        board.nets[0].terminals[1].position = closer_end;
        board.routes[0].segments[0].start = closer_start;
        board.routes[0].segments[0].end = closer_end;
        assert!(
            check_board(&board)
                .violations
                .iter()
                .any(|violation| violation.rule == "clearance")
        );
    }

    #[test]
    fn checks_capsules_without_using_their_bounding_box() {
        let mut board = base();
        let start = Point {
            x_nm: 2_000_000,
            y_nm: 5_000_000,
        };
        let end = Point {
            x_nm: 4_000_000,
            y_nm: 3_000_000,
        };
        board.capsule_obstacles.push(CapsuleObstacle {
            start: Point {
                x_nm: 4_000_000,
                y_nm: 5_000_000,
            },
            end: Point {
                x_nm: 6_000_000,
                y_nm: 5_000_000,
            },
            diameter_nm: 2_000_000,
            layers: vec![Layer::Front],
            net_id: None,
        });
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![
                Terminal {
                    position: start,
                    layers: vec![Layer::Front],
                },
                Terminal {
                    position: end,
                    layers: vec![Layer::Front],
                },
            ],
            class: None,
            priority: 0,
        });
        board.routes.push(Route {
            net_id: 1,
            segments: vec![Segment {
                start,
                end,
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            vias: vec![],
        });

        assert!(check_board(&board).is_clean());

        let closer_start = Point {
            x_nm: 2_000_000,
            y_nm: 6_000_000,
        };
        let closer_end = Point {
            x_nm: 5_000_000,
            y_nm: 3_000_000,
        };
        board.nets[0].terminals[0].position = closer_start;
        board.nets[0].terminals[1].position = closer_end;
        board.routes[0].segments[0].start = closer_start;
        board.routes[0].segments[0].end = closer_end;
        assert!(
            check_board(&board)
                .violations
                .iter()
                .any(|violation| violation.rule == "clearance")
        );
    }

    #[test]
    fn detects_route_split_between_terminals() {
        let mut board = base();
        let start = Point {
            x_nm: 1_000_000,
            y_nm: 1_000_000,
        };
        let end = Point {
            x_nm: 9_000_000,
            y_nm: 1_000_000,
        };
        board.nets.push(Net {
            id: 1,
            name: "split".into(),
            terminals: vec![
                Terminal {
                    position: start,
                    layers: vec![Layer::Front],
                },
                Terminal {
                    position: end,
                    layers: vec![Layer::Front],
                },
            ],
            class: None,
            priority: 0,
        });
        board.routes.push(Route {
            net_id: 1,
            segments: vec![
                Segment {
                    start,
                    end: Point {
                        x_nm: 3_000_000,
                        y_nm: 1_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
                Segment {
                    start: Point {
                        x_nm: 7_000_000,
                        y_nm: 1_000_000,
                    },
                    end,
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
            ],
            vias: vec![],
        });

        let report = check_board(&board);
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.rule == "disconnected_route")
        );
        assert!(
            !report
                .violations
                .iter()
                .any(|violation| violation.rule == "unconnected")
        );
    }

    #[test]
    fn detects_copper_without_a_terminal() {
        let mut board = base();
        let start = Point {
            x_nm: 1_000_000,
            y_nm: 1_000_000,
        };
        let end = Point {
            x_nm: 9_000_000,
            y_nm: 1_000_000,
        };
        board.nets.push(Net {
            id: 1,
            name: "orphan".into(),
            terminals: vec![
                Terminal {
                    position: start,
                    layers: vec![Layer::Front],
                },
                Terminal {
                    position: end,
                    layers: vec![Layer::Front],
                },
            ],
            class: None,
            priority: 0,
        });
        board.routes.push(Route {
            net_id: 1,
            segments: vec![
                Segment {
                    start,
                    end,
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
                Segment {
                    start: Point {
                        x_nm: 3_000_000,
                        y_nm: 5_000_000,
                    },
                    end: Point {
                        x_nm: 7_000_000,
                        y_nm: 5_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
            ],
            vias: vec![],
        });

        assert!(
            check_board(&board)
                .violations
                .iter()
                .any(|violation| violation.rule == "orphan_copper")
        );
    }

    #[test]
    fn via_connects_segments_on_opposite_layers() {
        let mut board = base();
        let start = Point {
            x_nm: 1_000_000,
            y_nm: 1_000_000,
        };
        let middle = Point {
            x_nm: 5_000_000,
            y_nm: 1_000_000,
        };
        let end = Point {
            x_nm: 9_000_000,
            y_nm: 1_000_000,
        };
        board.nets.push(Net {
            id: 1,
            name: "through-via".into(),
            terminals: vec![
                Terminal {
                    position: start,
                    layers: vec![Layer::Front],
                },
                Terminal {
                    position: end,
                    layers: vec![Layer::Back],
                },
            ],
            class: None,
            priority: 0,
        });
        board.routes.push(Route {
            net_id: 1,
            segments: vec![
                Segment {
                    start,
                    end: middle,
                    layer: Layer::Front,
                    width_nm: 250_000,
                },
                Segment {
                    start: middle,
                    end,
                    layer: Layer::Back,
                    width_nm: 250_000,
                },
            ],
            vias: vec![Via {
                position: middle,
                diameter_nm: 600_000,
                drill_nm: 300_000,
            }],
        });

        let report = check_board(&board);
        assert!(!report.violations.iter().any(|violation| matches!(
            violation.rule.as_str(),
            "unconnected" | "disconnected_route" | "orphan_copper"
        )));
    }
}

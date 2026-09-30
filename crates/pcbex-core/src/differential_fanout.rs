//! Bounded, single-layer fanouts for two-terminal differential pairs.
//!
//! Equal axial terminal offsets retain the legacy search. Other pairs try at
//! most 32 deterministic port/layer choices, each with a coupled A* trunk and
//! four local A* connectors. All searches debit the caller's one work budget.

use super::{
    ASTAR_WORK_BUDGET_ERROR, Board, Layer, Net, NetClassRules, Nm, Point, Route, Router, Rules,
    Terminal, WorkBudget, nearest_grid, route_length_nm,
};

const MAX_PORT_CANDIDATES: usize = 32;

pub(super) fn legacy_geometry_supported(positive: &Net, negative: &Net, rules: &Rules) -> bool {
    if positive.terminals.len() != 2 || negative.terminals.len() != 2 {
        return false;
    }
    let offset = |index: usize| {
        (
            nearest_grid(negative.terminals[index].position.x_nm, rules.grid_nm)
                - nearest_grid(positive.terminals[index].position.x_nm, rules.grid_nm),
            nearest_grid(negative.terminals[index].position.y_nm, rules.grid_nm)
                - nearest_grid(positive.terminals[index].position.y_nm, rules.grid_nm),
        )
    };
    let start = offset(0);
    start == offset(1) && (start.0 == 0 || start.1 == 0)
}

pub(super) fn route_differential_fanout_coupled(
    router: &Router<'_>,
    positive: &Net,
    negative: &Net,
    budget: &mut WorkBudget,
    expanded: &mut usize,
) -> Result<Option<(Route, Route)>, String> {
    let board = router.board;
    let rules = board.rules_for_net(positive.id);
    if positive.terminals.len() != 2
        || negative.terminals.len() != 2
        || rules != board.rules_for_net(negative.id)
        || legacy_geometry_supported(positive, negative, &rules)
        || board
            .routes
            .iter()
            .any(|route| route.net_id == positive.id || route.net_id == negative.id)
    {
        return Ok(None);
    }
    // Router::commit reserves segments and vias. Until the new fanout search
    // has reservations for these other copper forms, do not ignore them.
    if board.routes.iter().any(|route| {
        !route.arcs.is_empty() || !route.zones.is_empty() || !route.teardrops.is_empty()
    }) {
        return Ok(None);
    }
    let Some(pair) = board
        .differential_pairs
        .iter()
        .find(|pair| pair.positive_net_id == positive.id && pair.negative_net_id == negative.id)
    else {
        return Ok(None);
    };
    let grid = i128::from(rules.grid_nm);
    let width = i128::from(rules.track_width_nm);
    let pitch =
        ((width + i128::from(pair.gap_nm.max(rules.clearance_nm)) + grid - 1) / grid) * grid;
    // Quantization may not enlarge the requested pitch beyond the coupling
    // tolerance. The checker includes equality at the nanometre boundary.
    if pitch > width + i128::from(pair.gap_nm) + i128::from(pair.gap_tolerance_nm) {
        return Ok(None);
    }
    let layers: Vec<_> = board
        .copper_layers
        .iter()
        .copied()
        .filter(|layer| {
            [positive, negative].iter().all(|net| {
                net.terminals
                    .iter()
                    .all(|terminal| terminal.layers.contains(layer))
                    && board
                        .layers_for_net(net.id)
                        .is_none_or(|allowed| allowed.contains(layer))
            })
        })
        .collect();
    if layers.is_empty() {
        return Ok(None);
    }
    let (diameter, clearance) = board.maximum_routing_envelope();
    let edge_envelope = Nm::try_from(i128::from(diameter) + 2 * i128::from(clearance))
        .map_err(|_| "resource limit exceeded: inflate_radius_cells".to_string())?;
    let mut candidates = 0;
    // Interleave layers with port choices so a multilayer board still has one
    // global candidate cap. No budget charge is invented for enumeration.
    for geometry in 0..MAX_PORT_CANDIDATES {
        for &layer in &layers {
            if candidates == MAX_PORT_CANDIDATES {
                return Ok(None);
            }
            candidates += 1;
            let Some(ports) = trunk_ports(positive, negative, grid, pitch, geometry) else {
                continue;
            };
            if ports
                .iter()
                .any(|point| !board.point_inside_board(*point, edge_envelope))
            {
                continue;
            }
            let local_board = single_layer_board(board, positive.id, negative.id, layer, &rules);
            let mut base = Router::new_with_variant(&local_board, router.search_variant)?;
            for route in &board.routes {
                base.commit(route)?;
            }
            let mut trunk_router = base.clone();
            // The legacy coupled search consults blocked/owned, not occupied.
            trunk_router
                .blocked
                .extend(trunk_router.occupied.iter().copied());
            let trunk_positive = local_net(positive, ports[0], ports[1], layer);
            let trunk_negative = local_net(negative, ports[2], ports[3], layer);
            let Some((mut positive_route, mut negative_route, _)) = trunk_router
                .route_coupled_pair_tracked(&trunk_positive, &trunk_negative, budget, expanded)
                .map_err(|_| ASTAR_WORK_BUDGET_ERROR.to_string())?
            else {
                continue;
            };
            // Never reserve this net's own trunk: the general A* treats all
            // occupied cells as foreign, including same-net copper.
            let positive_connectors = [
                (positive.terminals[0].position, ports[0]),
                (ports[1], positive.terminals[1].position),
            ];
            let negative_connectors = [
                (negative.terminals[0].position, ports[2]),
                (ports[3], negative.terminals[1].position),
            ];
            let mut connected = true;
            for endpoints in positive_connectors {
                let Some(connector) = route_connector(
                    &base,
                    positive,
                    endpoints,
                    layer,
                    &negative_route,
                    budget,
                    expanded,
                )?
                else {
                    connected = false;
                    break;
                };
                append_route(&mut positive_route, connector);
            }
            if !connected {
                continue;
            }
            for endpoints in negative_connectors {
                let Some(connector) = route_connector(
                    &base,
                    negative,
                    endpoints,
                    layer,
                    &positive_route,
                    budget,
                    expanded,
                )?
                else {
                    connected = false;
                    break;
                };
                append_route(&mut negative_route, connector);
            }
            if !connected {
                continue;
            }
            if pair.minimum_length_nm.is_some_and(|minimum| {
                route_length_nm(&positive_route) < minimum
                    || route_length_nm(&negative_route) < minimum
            }) {
                continue;
            }
            let mut candidate = board.clone();
            candidate.routes.push(positive_route.clone());
            candidate.routes.push(negative_route.clone());
            super::validate_routing_resource_bounds(&candidate)?;
            // Retain the original classes, IDs, pad ownership and constraints.
            // Unrelated unrouted nets must not reject an otherwise valid pair.
            let invalid = super::checking::check_board(&candidate)
                .violations
                .iter()
                .any(|violation| {
                    violation.net_ids.contains(&positive.id)
                        || violation.net_ids.contains(&negative.id)
                });
            if !invalid {
                return Ok(Some((positive_route, negative_route)));
            }
        }
    }
    Ok(None)
}

fn local_net(net: &Net, start: Point, end: Point, layer: Layer) -> Net {
    Net {
        terminals: vec![
            Terminal {
                position: start,
                layers: vec![layer],
            },
            Terminal {
                position: end,
                layers: vec![layer],
            },
        ],
        ..net.clone()
    }
}

fn route_connector(
    base: &Router<'_>,
    net: &Net,
    endpoints: (Point, Point),
    layer: Layer,
    opposite: &Route,
    budget: &mut WorkBudget,
    expanded: &mut usize,
) -> Result<Option<Route>, String> {
    let mut router = base.clone();
    router.commit(opposite)?;
    match router.route_net(&local_net(net, endpoints.0, endpoints.1, layer), budget) {
        Ok((route, count)) => {
            *expanded += count;
            Ok(Some(route))
        }
        Err(failure) => {
            *expanded += failure.expanded;
            if failure.budget_exhausted {
                Err(ASTAR_WORK_BUDGET_ERROR.to_string())
            } else {
                Ok(None)
            }
        }
    }
}

fn append_route(route: &mut Route, connector: Route) {
    route.segments.extend(connector.segments);
    route.vias.extend(connector.vias);
}

fn single_layer_board(
    board: &Board,
    positive_id: u32,
    negative_id: u32,
    layer: Layer,
    rules: &Rules,
) -> Board {
    let mut local = board.clone();
    let mut name = format!("__pcbex_fanout_{positive_id}_{negative_id}");
    while local.net_classes.contains_key(&name) {
        name.push('_');
    }
    local.net_classes.insert(
        name.clone(),
        NetClassRules {
            track_width_nm: rules.track_width_nm,
            clearance_nm: rules.clearance_nm,
            via_diameter_nm: rules.via_diameter_nm,
            via_drill_nm: rules.via_drill_nm,
            layers: Some(vec![layer]),
            differential_width_nm: Some(rules.track_width_nm),
            differential_gap_nm: None,
            minimum_length_nm: None,
            maximum_length_nm: None,
            target_impedance_ohms: None,
            impedance_tolerance_ohms: None,
            maximum_impedance_step_ohms: None,
        },
    );
    for net in &mut local.nets {
        if net.id == positive_id || net.id == negative_id {
            net.class = Some(name.clone());
        }
    }
    local
}

fn trunk_ports(
    positive: &Net,
    negative: &Net,
    grid: i128,
    pitch: i128,
    choice: usize,
) -> Option<[Point; 4]> {
    let p = [
        positive.terminals[0].position,
        positive.terminals[1].position,
    ];
    let n = [
        negative.terminals[0].position,
        negative.terminals[1].position,
    ];
    let dx = i128::from(p[1].x_nm) + i128::from(n[1].x_nm)
        - i128::from(p[0].x_nm)
        - i128::from(n[0].x_nm);
    let dy = i128::from(p[1].y_nm) + i128::from(n[1].y_nm)
        - i128::from(p[0].y_nm)
        - i128::from(n[0].y_nm);
    let horizontal = (dx.abs() >= dy.abs()) != (choice / 16 != 0);
    let axial = |point: Point| i128::from(if horizontal { point.x_nm } else { point.y_nm });
    let normal = |point: Point| i128::from(if horizontal { point.y_nm } else { point.x_nm });
    let forward = if horizontal { dx } else { dy } >= 0;
    let natural = if normal(n[0]) < normal(p[0]) { -1 } else { 1 };
    let polarity = if choice % 16 / 8 == 0 {
        natural
    } else {
        -natural
    };
    let inset = (2 * grid).max(2 * pitch) * (1 + (choice % 8 / 4) as i128);
    let shift = [0, 1, -1, 2][choice % 4] * pitch;
    let floor = |value: i128| value.div_euclid(grid) * grid;
    let ceil = |value: i128| -(-value).div_euclid(grid) * grid;
    let snap = |value: i128| (value + grid / 2).div_euclid(grid) * grid;
    let start_axis = if forward {
        ceil(axial(p[0]).max(axial(n[0]))) + inset
    } else {
        floor(axial(p[0]).min(axial(n[0]))) - inset
    };
    let end_axis = if forward {
        floor(axial(p[1]).min(axial(n[1]))) - inset
    } else {
        ceil(axial(p[1]).max(axial(n[1]))) + inset
    };
    if (end_axis - start_axis) * if forward { 1 } else { -1 } <= grid {
        return None;
    }
    let start_normal = snap(normal(p[0])) + shift;
    let end_normal = snap(normal(p[1])) + shift;
    let point = |axis: i128, normal: i128| -> Option<Point> {
        let (x, y) = if horizontal {
            (axis, normal)
        } else {
            (normal, axis)
        };
        Some(Point {
            x_nm: Nm::try_from(x).ok()?,
            y_nm: Nm::try_from(y).ok()?,
        })
    };
    Some([
        point(start_axis, start_normal)?,
        point(end_axis, end_normal)?,
        point(start_axis, start_normal + polarity * pitch)?,
        point(end_axis, end_normal + polarity * pitch)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RoundObstacle, Segment, empty_route, route_board_with_work_budget, route_board_with_workers,
    };
    use serde_json::json;

    fn board() -> Board {
        serde_json::from_value(json!({
            "width_nm": 80_000_000, "height_nm": 20_000_000,
            "copper_layers": ["F.Cu"],
            "rules": {"grid_nm": 250_000, "track_width_nm": 250_000,
                "clearance_nm": 200_000, "via_diameter_nm": 600_000, "via_drill_nm": 300_000},
            "nets": [
                {"id": 1, "name": "P", "terminals": [
                    {"position": {"x_nm": 5_000_000, "y_nm": 8_000_000}, "layers": ["F.Cu"]},
                    {"position": {"x_nm": 75_000_000, "y_nm": 8_000_000}, "layers": ["F.Cu"]}]},
                {"id": 2, "name": "N", "terminals": [
                    {"position": {"x_nm": 5_000_000, "y_nm": 9_000_000}, "layers": ["F.Cu"]},
                    {"position": {"x_nm": 75_000_000, "y_nm": 10_000_000}, "layers": ["F.Cu"]}]}],
            "differential_pairs": [{"name": "LINK", "positive_net_id": 1,
                "negative_net_id": 2, "gap_nm": 750_000, "gap_tolerance_nm": 50_000,
                "max_skew_nm": 2_000_000, "min_coupled_percent": 85}]
        }))
        .unwrap()
    }

    fn candidate(
        board: &Board,
        budget: &mut WorkBudget,
        expanded: &mut usize,
    ) -> Option<(Route, Route)> {
        route_differential_fanout_coupled(
            &Router::new(board).unwrap(),
            &board.nets[0],
            &board.nets[1],
            budget,
            expanded,
        )
        .unwrap()
    }

    fn assert_clean_pair(board: &Board) {
        assert!(
            super::super::checking::check_board(board)
                .violations
                .is_empty(),
            "{:?}",
            super::super::checking::check_board(board).violations
        );
        assert!(board.routes.iter().all(|route| route.vias.is_empty()));
    }

    #[test]
    fn unequal_endpoint_pitch_routes_and_is_worker_deterministic() {
        let input = board();
        let (one, report) = route_board_with_workers(&input, 1).unwrap();
        let (four, other) = route_board_with_workers(&input, 4).unwrap();
        assert_clean_pair(&one);
        assert_eq!(report.coupled_differential_pairs, vec!["LINK"]);
        assert!(report.expanded_states > 0);
        assert_eq!(
            serde_json::to_vec(&one).unwrap(),
            serde_json::to_vec(&four).unwrap()
        );
        assert_eq!(report.expanded_states, other.expanded_states);
    }

    #[test]
    fn rotated_endpoint_routes_with_original_terminal_order() {
        let mut input = board();
        input.nets[1].terminals[1].position = Point {
            x_nm: 76_000_000,
            y_nm: 8_000_000,
        };
        input.differential_pairs[0].max_skew_nm = 3_000_000;
        input.differential_pairs[0].min_coupled_percent = 80;
        let (out, report) = route_board_with_workers(&input, 1).unwrap();
        assert_clean_pair(&out);
        assert_eq!(report.coupled_differential_pairs, vec!["LINK"]);
        assert_eq!(
            serde_json::to_vec(&out.nets).unwrap(),
            serde_json::to_vec(&input.nets).unwrap()
        );
    }

    #[test]
    fn unrelated_unrouted_net_does_not_reject_candidate() {
        let mut input = board();
        input.nets.push(local_net(
            &input.nets[0],
            Point {
                x_nm: 5_000_000,
                y_nm: 15_000_000,
            },
            Point {
                x_nm: 75_000_000,
                y_nm: 15_000_000,
            },
            Layer::Front,
        ));
        input.nets[2].id = 3;
        input.nets[2].name = "OTHER".into();
        let mut expanded = 0;
        assert!(candidate(&input, &mut WorkBudget::new(1_000_000), &mut expanded).is_some());
        assert!(expanded > 0);
    }

    #[test]
    fn off_grid_owned_pads_keep_original_ids_and_differential_width() {
        let mut input = board();
        let class: NetClassRules = serde_json::from_value(json!({
            "track_width_nm": 500_000, "clearance_nm": 200_000,
            "via_diameter_nm": 600_000, "via_drill_nm": 300_000,
            "layers": ["F.Cu"], "differential_width_nm": 250_000
        }))
        .unwrap();
        input
            .net_classes
            .insert("positive_class".into(), class.clone());
        input.net_classes.insert("negative_class".into(), class);
        for (index, net) in input.nets.iter_mut().enumerate() {
            net.class = Some(
                if index == 0 {
                    "positive_class"
                } else {
                    "negative_class"
                }
                .into(),
            );
            for terminal in &mut net.terminals {
                terminal.position.x_nm += 70_000;
                terminal.position.y_nm += 90_000;
                input.round_obstacles.push(RoundObstacle {
                    center: terminal.position,
                    diameter_nm: 700_000,
                    layers: vec![Layer::Front],
                    net_id: Some(net.id),
                });
            }
        }
        let (out, report) = route_board_with_workers(&input, 1).unwrap();
        assert_clean_pair(&out);
        assert_eq!(report.coupled_differential_pairs, vec!["LINK"]);
        assert!(
            out.routes
                .iter()
                .flat_map(|route| &route.segments)
                .all(|segment| segment.width_nm == 250_000)
        );
        assert_eq!(
            serde_json::to_vec(&input.nets).unwrap(),
            serde_json::to_vec(&out.nets).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&input.net_classes).unwrap(),
            serde_json::to_vec(&out.net_classes).unwrap()
        );
    }

    #[test]
    fn reversed_terminal_order_and_negative_normal_polarity_route() {
        let mut input = board();
        for net in &mut input.nets {
            for terminal in &mut net.terminals {
                terminal.position.y_nm = input.height_nm - terminal.position.y_nm;
            }
            net.terminals.reverse();
        }
        let (out, report) = route_board_with_workers(&input, 1).unwrap();
        assert_clean_pair(&out);
        assert_eq!(report.coupled_differential_pairs, vec!["LINK"]);
        assert_eq!(
            serde_json::to_vec(&input.nets).unwrap(),
            serde_json::to_vec(&out.nets).unwrap()
        );
    }

    #[test]
    fn unmet_pair_minimum_length_is_not_admitted_for_later_translation() {
        let mut input = board();
        input.differential_pairs[0].minimum_length_nm = Some(1_000_000_000);
        let mut expanded = 0;
        assert!(candidate(&input, &mut WorkBudget::new(2_000_000), &mut expanded).is_none());
        assert!(expanded > 0);
    }

    #[test]
    fn escaped_nonlegacy_pair_keeps_the_ordinary_shared_budget_path() {
        let mut input = board();
        input.copper_layers.push(Layer::Back);
        input.differential_pairs[0].min_coupled_percent = 0;
        input.differential_pairs[0].max_skew_nm = 10_000_000;
        input.escape_groups.push(
            serde_json::from_value(json!({
                "name": "ESCAPE", "net_ids": [1, 2], "fanout_distance_nm": 2_000_000,
                "target_layer": "B.Cu", "direction": "rows", "max_rings": 2
            }))
            .unwrap(),
        );
        let (out, report) = route_board_with_work_budget(&input, 1, 100_000).unwrap();
        assert_eq!(report.escaped_nets, 2);
        assert!(
            super::super::checking::check_board(&out)
                .violations
                .is_empty()
        );
    }

    #[test]
    fn failed_candidates_spend_shared_budget_and_report_expansions() {
        let mut input = board();
        input.differential_pairs[0].min_coupled_percent = 100;
        input.differential_pairs[0].max_skew_nm = 0;
        let mut budget = WorkBudget::new(2_000_000);
        let mut expanded = 0;
        assert!(candidate(&input, &mut budget, &mut expanded).is_none());
        assert!(budget.remaining() < 2_000_000);
        assert!(expanded > 0);
        let spent = budget.used(2_000_000);
        assert_eq!(
            route_board_with_work_budget(&input, 1, spent).unwrap_err(),
            ASTAR_WORK_BUDGET_ERROR
        );
        assert_eq!(
            route_board_with_work_budget(&input, 1, 1).unwrap_err(),
            ASTAR_WORK_BUDGET_ERROR
        );
    }

    #[test]
    fn unsupported_inputs_do_not_start_searches() {
        let input = board();
        let mut cases = vec![];
        let mut multi = input.clone();
        let terminal = multi.nets[0].terminals[0].clone();
        multi.nets[0].terminals.push(terminal);
        cases.push(multi);
        let mut layers = input.clone();
        layers.copper_layers.push(Layer::Back);
        layers.nets[1].terminals[1].layers = vec![Layer::Back];
        cases.push(layers);
        let mut coarse = input.clone();
        coarse.rules.grid_nm = 1_250_000;
        cases.push(coarse);
        let mut preserved = input.clone();
        preserved.routes.push(empty_route(1));
        cases.push(preserved);
        let mut different_rules = input.clone();
        let class = single_layer_board(&input, 1, 2, Layer::Front, &input.rules)
            .net_classes
            .into_values()
            .next()
            .unwrap();
        different_rules.net_classes.insert(
            "different".into(),
            NetClassRules {
                clearance_nm: 250_000,
                ..class
            },
        );
        different_rules.nets[1].class = Some("different".into());
        cases.push(different_rules);
        for case in cases {
            let mut budget = WorkBudget::new(100);
            let mut expanded = 0;
            assert!(candidate(&case, &mut budget, &mut expanded).is_none());
            assert_eq!(budget.remaining(), 100);
            assert_eq!(expanded, 0);
        }
    }

    #[test]
    fn existing_third_net_segment_is_preserved_and_avoided() {
        let mut input = board();
        let mut net = local_net(
            &input.nets[0],
            Point {
                x_nm: 40_000_000,
                y_nm: 5_000_000,
            },
            Point {
                x_nm: 40_000_000,
                y_nm: 12_000_000,
            },
            Layer::Front,
        );
        net.id = 3;
        net.name = "EXISTING".into();
        let mut route = empty_route(3);
        route.segments.push(Segment {
            start: net.terminals[0].position,
            end: net.terminals[1].position,
            layer: Layer::Front,
            width_nm: 250_000,
        });
        let bytes = serde_json::to_vec(&route).unwrap();
        input.nets.push(net);
        input.routes.push(route);
        input.differential_pairs[0].min_coupled_percent = 80;
        input.differential_pairs[0].max_skew_nm = 3_000_000;
        let (out, report) = route_board_with_workers(&input, 1).unwrap();
        assert_clean_pair(&out);
        assert_eq!(report.coupled_differential_pairs, vec!["LINK"]);
        assert_eq!(
            serde_json::to_vec(out.routes.iter().find(|route| route.net_id == 3).unwrap()).unwrap(),
            bytes
        );
    }
}

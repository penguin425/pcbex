use crate::geometry::{
    point_in_polygon, point_polygon_closer_than, point_rect_closer_than, point_segment_closer_than,
    point_segment_within, points_closer_than, points_within, segment_polygon_closer_than,
    segment_rect_closer_than, segments_closer_than, segments_within,
};
use crate::{Board, Net, Pad, PadShape, Point, Route, Segment, route_length_nm};
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
    if board.routes.iter().any(|route| {
        !route.arcs.is_empty()
            || !route.teardrops.is_empty()
            || route
                .zones
                .iter()
                .any(|zone| !zone.filled_polygons.is_empty())
    }) {
        let arc_net_ids: HashSet<_> = board
            .routes
            .iter()
            .filter(|route| !route.arcs.is_empty())
            .map(|route| route.net_id)
            .collect();
        let mut linearized = board.clone();
        linearized.routes = board.routes.iter().map(Route::linearized_arcs).collect();
        let mut teardrop_obstacles = Vec::new();
        for route in &mut linearized.routes {
            for teardrop in route.teardrops.drain(..) {
                teardrop_obstacles.push(crate::PolygonObstacle {
                    polygon: teardrop.polygon,
                    layers: vec![teardrop.layer],
                    net_id: Some(route.net_id),
                });
            }
            for zone in &mut route.zones {
                for polygon in zone.filled_polygons.drain(..) {
                    teardrop_obstacles.push(crate::PolygonObstacle {
                        polygon,
                        layers: vec![zone.layer],
                        net_id: Some(route.net_id),
                    });
                }
            }
        }
        linearized.polygon_obstacles.extend(teardrop_obstacles);
        let mut report = check_board(&linearized);
        report.violations.retain(|violation| {
            violation.rule != "track_angle"
                || !violation.net_ids.iter().any(|id| arc_net_ids.contains(id))
        });
        for route in board
            .routes
            .iter()
            .filter(|route| arc_net_ids.contains(&route.net_id))
        {
            let rules = board.rules_for_net(route.net_id);
            for segment in &route.segments {
                let dx = (segment.end.x_nm - segment.start.x_nm).abs();
                let dy = (segment.end.y_nm - segment.start.y_nm).abs();
                if dx != 0 && dy != 0 && dx != dy {
                    report.push(
                        "track_angle",
                        "track is not horizontal, vertical, or 45 degrees".into(),
                        vec![route.net_id],
                    );
                }
            }
            for arc in &route.arcs {
                if arc.width_nm < rules.track_width_nm {
                    report.push(
                        "track_width",
                        "arc is narrower than the configured minimum".into(),
                        vec![route.net_id],
                    );
                }
                if !crate::arc_is_valid(arc) {
                    report.push(
                        "arc_geometry",
                        "arc start, midpoint, and end must define a curve".into(),
                        vec![route.net_id],
                    );
                }
            }
        }
        report
            .violations
            .retain(|violation| violation.rule != "return_path_plane");
        check_return_plane_continuity(board, &mut report);
        return report;
    }
    let mut report = CheckReport::default();
    for footprint in &board.footprints {
        for pad in &footprint.pads {
            match (pad.drill_width_nm, pad.drill_height_nm) {
                (None, None) => {
                    if pad.drill_offset_x_nm != 0 || pad.drill_offset_y_nm != 0 {
                        report.push(
                            "component_hole",
                            format!(
                                "{} pad {} has a drill offset without a drill",
                                footprint.reference, pad.number
                            ),
                            pad.net_id.into_iter().collect(),
                        );
                    }
                }
                (Some(width_nm), Some(height_nm)) if width_nm > 0 && height_nm > 0 => {
                    if pad.plated && !drill_fits_pad(pad, width_nm, height_nm) {
                        report.push(
                            "component_hole",
                            format!(
                                "{} pad {} plated drill must fit inside the pad",
                                footprint.reference, pad.number
                            ),
                            pad.net_id.into_iter().collect(),
                        );
                    }
                }
                _ => report.push(
                    "component_hole",
                    format!(
                        "{} pad {} drill must have two positive dimensions",
                        footprint.reference, pad.number
                    ),
                    pad.net_id.into_iter().collect(),
                ),
            }
        }
    }
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
        let length = route_length_nm(route);
        let (minimum, maximum) = board.length_limits_for_net(route.net_id);
        if minimum.is_some_and(|limit| length < limit)
            || maximum.is_some_and(|limit| length > limit)
        {
            report.push(
                "trace_length",
                format!("route length {length} nm is outside its net-class limits"),
                vec![route.net_id],
            );
        }
        for segment in &route.segments {
            check_segment(board, route.net_id, segment, &mut report);
        }
        for via in &route.vias {
            let rules = board.rules_for_net(route.net_id);
            let start = board
                .copper_layers
                .iter()
                .position(|layer| *layer == via.start_layer);
            let end = board
                .copper_layers
                .iter()
                .position(|layer| *layer == via.end_layer);
            if start.is_none()
                || end.is_none()
                || start == end
                || (via.kind == crate::ViaKind::Micro
                    && start.zip(end).is_some_and(|(a, b)| a.abs_diff(b) != 1))
            {
                report.push(
                    "via_layers",
                    "via has an invalid layer range for its type".into(),
                    vec![route.net_id],
                );
            }
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
                if !obstacle.layers.iter().any(|layer| via.spans_layer(*layer)) {
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
                if !obstacle.layers.iter().any(|layer| via.spans_layer(*layer)) {
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
                if !obstacle.layers.iter().any(|layer| via.spans_layer(*layer)) {
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
                if !obstacle.layers.iter().any(|layer| via.spans_layer(*layer)) {
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
                if !keepout.vias_not_allowed || keepout.net_id == Some(route.net_id) {
                    continue;
                }
                if !keepout.layers.iter().any(|layer| via.spans_layer(*layer)) {
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
    check_footprint_rule_areas(board, &mut report);
    check_differential_pairs(board, &routes, &mut report);
    check_length_groups(board, &routes, &mut report);
    check_return_paths(board, &routes, &mut report);
    check_power_nets(board, &routes, &mut report);
    check_impedance(board, &routes, &mut report);
    report
        .violations
        .extend(check_manufacturability(board).violations);
    report
}

fn check_footprint_rule_areas(board: &Board, report: &mut CheckReport) {
    for footprint in &board.footprints {
        for area in &board.keepouts {
            if !area.footprints_not_allowed {
                continue;
            }
            let intersects = point_in_polygon(footprint.position, &area.polygon)
                || footprint
                    .pads
                    .iter()
                    .any(|pad| point_in_polygon(pad.position, &area.polygon));
            if intersects {
                report.push(
                    "rule_area_footprint",
                    format!(
                        "footprint {} intersects a footprint-prohibited Rule Area",
                        footprint.reference
                    ),
                    footprint.pads.iter().filter_map(|pad| pad.net_id).collect(),
                );
                break;
            }
        }
    }
}

fn check_power_nets(board: &Board, routes: &HashMap<u32, &Route>, report: &mut CheckReport) {
    const COPPER_RESISTIVITY_OHM_M: f64 = 1.724e-8;
    for rule in &board.power_net_rules {
        let Some(route) = routes.get(&rule.net_id) else {
            continue;
        };
        let resistance_ohms = route
            .segments
            .iter()
            .map(|segment| {
                let length_m = (((segment.end.x_nm - segment.start.x_nm) as f64)
                    .hypot((segment.end.y_nm - segment.start.y_nm) as f64))
                    * 1e-9;
                let copper_thickness_m = board
                    .stackup
                    .iter()
                    .find(|entry| entry.layer == segment.layer)
                    .map_or(35_000, |entry| entry.copper_thickness_nm.max(1))
                    as f64
                    * 1e-9;
                let cross_section_m2 = segment.width_nm as f64 * 1e-9 * copper_thickness_m;
                COPPER_RESISTIVITY_OHM_M * length_m / cross_section_m2
            })
            .sum::<f64>();
        let voltage_drop_mv = rule.current_ma * resistance_ohms;
        if voltage_drop_mv > rule.maximum_voltage_drop_mv {
            report.push(
                "pdn_voltage_drop",
                format!(
                    "estimated {:.3} mV drop exceeds {:.3} mV at {:.3} mA",
                    voltage_drop_mv, rule.maximum_voltage_drop_mv, rule.current_ma
                ),
                vec![rule.net_id],
            );
        }
        if route.vias.len() < rule.minimum_parallel_vias {
            report.push(
                "pdn_via_count",
                format!(
                    "power route has {} vias but requires at least {}",
                    route.vias.len(),
                    rule.minimum_parallel_vias
                ),
                vec![rule.net_id],
            );
        }
    }
}

fn check_impedance(board: &Board, routes: &HashMap<u32, &Route>, report: &mut CheckReport) {
    for net in &board.nets {
        let Some(class) = net
            .class
            .as_ref()
            .and_then(|class| board.net_classes.get(class))
        else {
            continue;
        };
        let Some(route) = routes.get(&net.id) else {
            continue;
        };
        if class.target_impedance_ohms.is_none() && class.maximum_impedance_step_ohms.is_none() {
            continue;
        }
        let mut estimates = Vec::new();
        for segment in &route.segments {
            let Some(stackup) = board
                .stackup
                .iter()
                .find(|entry| entry.layer == segment.layer)
            else {
                report.push(
                    "impedance_stackup",
                    format!(
                        "net {} has no stackup entry for {:?}",
                        net.name, segment.layer
                    ),
                    vec![net.id],
                );
                break;
            };
            let Some(estimated) =
                crate::estimated_stackup_impedance_ohms(segment.width_nm, stackup)
            else {
                report.push(
                    "impedance_stackup",
                    format!("net {} has an invalid impedance geometry", net.name),
                    vec![net.id],
                );
                break;
            };
            estimates.push((segment, estimated));
            if let (Some(target), Some(tolerance)) =
                (class.target_impedance_ohms, class.impedance_tolerance_ohms)
                && (estimated - target).abs() > tolerance
            {
                report.push(
                    "impedance",
                    format!(
                        "net {} estimates {:.2} Ω, outside {:.2} ± {:.2} Ω",
                        net.name, estimated, target, tolerance
                    ),
                    vec![net.id],
                );
                break;
            }
        }
        let Some(maximum_step) = class.maximum_impedance_step_ohms else {
            continue;
        };
        for via in &route.vias {
            let connected = estimates
                .iter()
                .filter(|(segment, _)| {
                    (segment.start == via.position || segment.end == via.position)
                        && via.spans_layer(segment.layer)
                })
                .map(|(_, impedance)| *impedance)
                .collect::<Vec<_>>();
            if connected.len() < 2 {
                continue;
            }
            let minimum = connected.iter().copied().fold(f64::INFINITY, f64::min);
            let maximum = connected.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            if maximum - minimum > maximum_step {
                report.push(
                    "impedance_transition",
                    format!(
                        "net {} changes impedance by {:.2} Ω at a layer transition, exceeding {:.2} Ω",
                        net.name,
                        maximum - minimum,
                        maximum_step
                    ),
                    vec![net.id],
                );
                break;
            }
        }
    }
}

fn check_return_paths(board: &Board, routes: &HashMap<u32, &Route>, report: &mut CheckReport) {
    for rule in &board.return_path_rules {
        let reference_vias = routes
            .get(&rule.reference_net_id)
            .map_or(&[][..], |route| route.vias.as_slice());
        for signal_net_id in &rule.signal_net_ids {
            let Some(signal_route) = routes.get(signal_net_id) else {
                continue;
            };
            for signal_via in &signal_route.vias {
                let has_return = reference_vias.iter().any(|reference_via| {
                    if !signal_via.shares_layer_with(reference_via) {
                        return false;
                    }
                    let dx = i128::from(signal_via.position.x_nm - reference_via.position.x_nm);
                    let dy = i128::from(signal_via.position.y_nm - reference_via.position.y_nm);
                    let limit = i128::from(rule.max_via_distance_nm);
                    dx * dx + dy * dy <= limit * limit
                });
                if !has_return {
                    report.push(
                        "return_path",
                        format!(
                            "{} requires a reference-net via within {} nm of the signal transition",
                            rule.name, rule.max_via_distance_nm
                        ),
                        vec![*signal_net_id, rule.reference_net_id],
                    );
                }
            }
        }
    }
    check_return_plane_continuity(board, report);
}

fn check_return_plane_continuity(board: &Board, report: &mut CheckReport) {
    for rule in board
        .return_path_rules
        .iter()
        .filter(|rule| rule.require_continuous_plane)
    {
        let Some(reference_route) = board
            .routes
            .iter()
            .find(|route| route.net_id == rule.reference_net_id)
        else {
            continue;
        };
        for signal_net_id in &rule.signal_net_ids {
            let Some(signal_route) = board
                .routes
                .iter()
                .find(|route| route.net_id == *signal_net_id)
            else {
                continue;
            };
            for segment in &signal_route.segments {
                let Some(reference_layer) = board
                    .stackup
                    .iter()
                    .find(|entry| entry.layer == segment.layer)
                    .and_then(|entry| entry.reference_layer)
                else {
                    report.push(
                        "return_path_plane",
                        format!(
                            "{} has no reference-layer stackup entry for {:?}",
                            rule.name, segment.layer
                        ),
                        vec![*signal_net_id, rule.reference_net_id],
                    );
                    break;
                };
                let spacing = rule
                    .plane_sample_spacing_nm
                    .unwrap_or(board.rules.grid_nm)
                    .max(1);
                let dx = segment.end.x_nm - segment.start.x_nm;
                let dy = segment.end.y_nm - segment.start.y_nm;
                let length = ((dx as f64).hypot(dy as f64)).round() as i64;
                let steps = ((length + spacing - 1) / spacing).max(1);
                let continuous = (0..=steps).all(|step| {
                    let point = Point {
                        x_nm: segment.start.x_nm + dx * step / steps,
                        y_nm: segment.start.y_nm + dy * step / steps,
                    };
                    reference_route.zones.iter().any(|zone| {
                        zone.layer == reference_layer
                            && if zone.filled_polygons.is_empty() {
                                point_in_polygon(point, &zone.polygon)
                            } else {
                                zone.filled_polygons
                                    .iter()
                                    .any(|polygon| point_in_polygon(point, polygon))
                            }
                    })
                });
                if !continuous {
                    report.push(
                        "return_path_plane",
                        format!(
                            "{} crosses a gap in the {:?} reference plane",
                            rule.name, reference_layer
                        ),
                        vec![*signal_net_id, rule.reference_net_id],
                    );
                    break;
                }
            }
        }
    }
}

pub fn check_manufacturability(board: &Board) -> CheckReport {
    let mut report = CheckReport::default();
    let Some(rules) = &board.manufacturing_rules else {
        return report;
    };
    if rules.minimum_track_width_nm <= 0
        || rules.minimum_clearance_nm < 0
        || rules.minimum_drill_nm <= 0
        || rules.minimum_annular_ring_nm < 0
        || rules.minimum_copper_to_edge_nm < 0
        || rules.board_thickness_nm <= 0
        || rules.maximum_via_aspect_ratio == 0
        || rules.minimum_drill_to_drill_nm < 0
        || rules.minimum_trace_angle_deg > 180
    {
        report.push(
            "dfm_rules",
            "manufacturing rules contain invalid dimensions".into(),
            vec![],
        );
        return report;
    }
    for route in &board.routes {
        for segment in &route.segments {
            if segment.width_nm < rules.minimum_track_width_nm {
                report.push(
                    "dfm_track_width",
                    "track is narrower than the manufacturing minimum".into(),
                    vec![route.net_id],
                );
            }
            let edge_envelope = segment.width_nm + 2 * rules.minimum_copper_to_edge_nm;
            if !board.point_inside_board(segment.start, edge_envelope)
                || !board.point_inside_board(segment.end, edge_envelope)
            {
                report.push(
                    "dfm_copper_to_edge",
                    "track is too close to the routed board edge".into(),
                    vec![route.net_id],
                );
            }
        }
        for via in &route.vias {
            if via.drill_nm < rules.minimum_drill_nm {
                report.push(
                    "dfm_drill",
                    "via drill is smaller than the manufacturing minimum".into(),
                    vec![route.net_id],
                );
            }
            if via.diameter_nm - via.drill_nm < 2 * rules.minimum_annular_ring_nm {
                report.push(
                    "dfm_annular_ring",
                    "via annular ring is smaller than the manufacturing minimum".into(),
                    vec![route.net_id],
                );
            }
            if rules.board_thickness_nm > via.drill_nm * i64::from(rules.maximum_via_aspect_ratio) {
                report.push(
                    "dfm_aspect_ratio",
                    "via exceeds the manufacturing aspect-ratio limit".into(),
                    vec![route.net_id],
                );
            }
            if !board.point_inside_board(
                via.position,
                via.diameter_nm + 2 * rules.minimum_copper_to_edge_nm,
            ) {
                report.push(
                    "dfm_copper_to_edge",
                    "via is too close to the routed board edge".into(),
                    vec![route.net_id],
                );
            }
            if !rules.allow_via_in_pad
                && board
                    .footprints
                    .iter()
                    .flat_map(|footprint| &footprint.pads)
                    .any(|pad| {
                        pad.layers.iter().any(|layer| via.spans_layer(*layer))
                            && point_in_pad(via.position, pad)
                    })
            {
                report.push(
                    "dfm_via_in_pad",
                    "via is located inside a component pad".into(),
                    vec![route.net_id],
                );
            }
        }
        check_trace_angles(route, rules.minimum_trace_angle_deg, &mut report);
    }
    for (index, route) in board.routes.iter().enumerate() {
        for other in &board.routes[index + 1..] {
            check_manufacturing_clearance(route, other, rules.minimum_clearance_nm, &mut report);
        }
    }

    let mut drilled_holes: Vec<_> = board
        .routes
        .iter()
        .flat_map(|route| {
            route.vias.iter().map(move |via| DrilledHole {
                start: via.position,
                end: via.position,
                diameter_nm: via.drill_nm,
                net_id: Some(route.net_id),
            })
        })
        .collect();
    for footprint in &board.footprints {
        for pad in &footprint.pads {
            let (Some(drill_width_nm), Some(drill_height_nm)) =
                (pad.drill_width_nm, pad.drill_height_nm)
            else {
                if pad.drill_width_nm.is_some() || pad.drill_height_nm.is_some() {
                    report.push(
                        "dfm_component_drill",
                        format!(
                            "{} pad {} has incomplete drill dimensions",
                            footprint.reference, pad.number
                        ),
                        pad.net_id.into_iter().collect(),
                    );
                }
                continue;
            };
            if drill_width_nm <= 0 || drill_height_nm <= 0 {
                report.push(
                    "dfm_component_drill",
                    format!(
                        "{} pad {} has invalid drill dimensions",
                        footprint.reference, pad.number
                    ),
                    pad.net_id.into_iter().collect(),
                );
                continue;
            }
            let drill_nm = drill_width_nm.min(drill_height_nm);
            if drill_nm < rules.minimum_drill_nm {
                report.push(
                    "dfm_component_drill",
                    format!(
                        "{} pad {} drill is smaller than the manufacturing minimum",
                        footprint.reference, pad.number
                    ),
                    pad.net_id.into_iter().collect(),
                );
            }
            let pad_width_nm = if pad.source_width_nm > 0 {
                pad.source_width_nm
            } else {
                pad.width_nm
            };
            let pad_height_nm = if pad.source_height_nm > 0 {
                pad.source_height_nm
            } else {
                pad.height_nm
            };
            if pad.plated
                && (pad_width_nm - drill_width_nm < 2 * rules.minimum_annular_ring_nm
                    || pad_height_nm - drill_height_nm < 2 * rules.minimum_annular_ring_nm)
            {
                report.push(
                    "dfm_component_annular_ring",
                    format!(
                        "{} pad {} annular ring is smaller than the manufacturing minimum",
                        footprint.reference, pad.number
                    ),
                    pad.net_id.into_iter().collect(),
                );
            }
            if rules.board_thickness_nm > drill_nm * i64::from(rules.maximum_via_aspect_ratio) {
                report.push(
                    "dfm_component_aspect_ratio",
                    format!(
                        "{} pad {} exceeds the manufacturing aspect-ratio limit",
                        footprint.reference, pad.number
                    ),
                    pad.net_id.into_iter().collect(),
                );
            }
            let hole = drilled_pad_hole(pad, drill_width_nm, drill_height_nm);
            let edge_envelope = hole.diameter_nm + 2 * rules.minimum_copper_to_edge_nm;
            if !board.point_inside_board(hole.start, edge_envelope)
                || !board.point_inside_board(hole.end, edge_envelope)
            {
                report.push(
                    "dfm_hole_to_edge",
                    format!(
                        "{} pad {} hole is too close to the routed board edge",
                        footprint.reference, pad.number
                    ),
                    pad.net_id.into_iter().collect(),
                );
            }
            drilled_holes.push(hole);
        }
    }
    for (index, hole) in drilled_holes.iter().enumerate() {
        for other in &drilled_holes[index + 1..] {
            let required_twice =
                hole.diameter_nm + other.diameter_nm + 2 * rules.minimum_drill_to_drill_nm;
            if segments_closer_than(hole.start, hole.end, other.start, other.end, required_twice) {
                let mut net_ids: Vec<_> =
                    [hole.net_id, other.net_id].into_iter().flatten().collect();
                net_ids.sort_unstable();
                net_ids.dedup();
                report.push(
                    "dfm_drill_spacing",
                    "drilled holes are below the manufacturing spacing minimum".into(),
                    net_ids,
                );
            }
        }
    }
    report
}

#[derive(Clone, Copy)]
struct DrilledHole {
    start: Point,
    end: Point,
    diameter_nm: i64,
    net_id: Option<u32>,
}

fn drill_fits_pad(pad: &Pad, width_nm: i64, height_nm: i64) -> bool {
    let pad_width_nm = if pad.source_width_nm > 0 {
        pad.source_width_nm
    } else {
        pad.width_nm
    } as f64;
    let pad_height_nm = if pad.source_height_nm > 0 {
        pad.source_height_nm
    } else {
        pad.height_nm
    } as f64;
    if pad_width_nm <= 0.0 || pad_height_nm <= 0.0 {
        return false;
    }

    let radius = width_nm.min(height_nm) as f64 / 2.0;
    let centerline = (width_nm.max(height_nm) - width_nm.min(height_nm)) as f64;
    let offset_x = pad.drill_offset_x_nm as f64;
    let offset_y = pad.drill_offset_y_nm as f64;
    let endpoints = if width_nm >= height_nm {
        [
            (offset_x - centerline / 2.0, offset_y),
            (offset_x + centerline / 2.0, offset_y),
        ]
    } else {
        [
            (offset_x, offset_y - centerline / 2.0),
            (offset_x, offset_y + centerline / 2.0),
        ]
    };

    match pad.shape {
        PadShape::Circle => {
            let pad_radius = pad_width_nm.min(pad_height_nm) / 2.0;
            endpoints
                .iter()
                .all(|(x, y)| x.hypot(*y) + radius < pad_radius)
        }
        PadShape::Oval => {
            let pad_radius = pad_width_nm.min(pad_height_nm) / 2.0;
            let pad_centerline = pad_width_nm.max(pad_height_nm) - 2.0 * pad_radius;
            endpoints.iter().all(|(x, y)| {
                let distance = if pad_width_nm >= pad_height_nm {
                    let nearest_x = x.clamp(-pad_centerline / 2.0, pad_centerline / 2.0);
                    (x - nearest_x).hypot(*y)
                } else {
                    let nearest_y = y.clamp(-pad_centerline / 2.0, pad_centerline / 2.0);
                    x.hypot(y - nearest_y)
                };
                distance + radius < pad_radius
            })
        }
        PadShape::RoundRect => {
            let corner_radius = pad.roundrect_radius_nm as f64;
            let half_width = pad_width_nm / 2.0 - radius;
            let half_height = pad_height_nm / 2.0 - radius;
            if corner_radius < 0.0
                || corner_radius > pad_width_nm.min(pad_height_nm) / 2.0
                || half_width <= 0.0
                || half_height <= 0.0
            {
                return false;
            }
            let eroded_corner = (corner_radius - radius).max(0.0);
            endpoints.iter().all(|(x, y)| {
                point_inside_roundrect(*x, *y, half_width, half_height, eroded_corner)
            })
        }
        PadShape::Trapezoid => {
            let half_width = pad_width_nm / 2.0;
            let half_height = pad_height_nm / 2.0;
            let delta_x = pad.trapezoid_delta_x_nm as f64;
            let delta_y = pad.trapezoid_delta_y_nm as f64;
            let polygon = [
                (-half_width - delta_x / 2.0, -half_height - delta_y / 2.0),
                (half_width + delta_x / 2.0, -half_height + delta_y / 2.0),
                (half_width - delta_x / 2.0, half_height + delta_y / 2.0),
                (-half_width + delta_x / 2.0, half_height - delta_y / 2.0),
            ];
            endpoints
                .iter()
                .all(|point| disk_inside_convex_polygon(*point, radius, &polygon))
        }
        _ => endpoints.iter().all(|(x, y)| {
            x.abs() + radius < pad_width_nm / 2.0 && y.abs() + radius < pad_height_nm / 2.0
        }),
    }
}

fn point_inside_roundrect(
    x: f64,
    y: f64,
    half_width: f64,
    half_height: f64,
    corner_radius: f64,
) -> bool {
    let x = x.abs();
    let y = y.abs();
    if x >= half_width || y >= half_height {
        return false;
    }
    let inner_x = half_width - corner_radius;
    let inner_y = half_height - corner_radius;
    if x <= inner_x || y <= inner_y {
        return true;
    }
    (x - inner_x).hypot(y - inner_y) < corner_radius
}

fn disk_inside_convex_polygon(point: (f64, f64), radius: f64, polygon: &[(f64, f64)]) -> bool {
    let signed_area_twice: f64 = polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
        .map(|(&(ax, ay), &(bx, by))| ax * by - bx * ay)
        .sum();
    if signed_area_twice == 0.0 {
        return false;
    }
    let orientation = signed_area_twice.signum();
    polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
        .all(|(&(ax, ay), &(bx, by))| {
            let edge_x = bx - ax;
            let edge_y = by - ay;
            let edge_length = edge_x.hypot(edge_y);
            edge_length > 0.0
                && orientation * (edge_x * (point.1 - ay) - edge_y * (point.0 - ax)) / edge_length
                    > radius
        })
}

fn drilled_pad_hole(pad: &Pad, width_nm: i64, height_nm: i64) -> DrilledHole {
    let diameter_nm = width_nm.min(height_nm);
    let centerline_nm = width_nm.max(height_nm) - diameter_nm;
    let angle_deg = if width_nm >= height_nm {
        pad.rotation_deg
    } else {
        pad.rotation_deg + 90.0
    };
    let radians = angle_deg.to_radians();
    let pad_radians = pad.rotation_deg.to_radians();
    let center = Point {
        x_nm: pad.position.x_nm
            + (pad_radians.cos() * pad.drill_offset_x_nm as f64
                - pad_radians.sin() * pad.drill_offset_y_nm as f64)
                .round() as i64,
        y_nm: pad.position.y_nm
            + (pad_radians.sin() * pad.drill_offset_x_nm as f64
                + pad_radians.cos() * pad.drill_offset_y_nm as f64)
                .round() as i64,
    };
    let half_dx = (radians.cos() * centerline_nm as f64 / 2.0).round() as i64;
    let half_dy = (radians.sin() * centerline_nm as f64 / 2.0).round() as i64;
    DrilledHole {
        start: Point {
            x_nm: center.x_nm - half_dx,
            y_nm: center.y_nm - half_dy,
        },
        end: Point {
            x_nm: center.x_nm + half_dx,
            y_nm: center.y_nm + half_dy,
        },
        diameter_nm,
        net_id: pad.net_id,
    }
}

fn check_trace_angles(route: &Route, minimum_angle_deg: u16, report: &mut CheckReport) {
    if minimum_angle_deg == 0 {
        return;
    }
    for (index, segment) in route.segments.iter().enumerate() {
        for other in &route.segments[index + 1..] {
            if segment.layer != other.layer {
                continue;
            }
            let Some((junction, first_end, second_end)) = shared_endpoint(segment, other) else {
                continue;
            };
            let ax = (first_end.x_nm - junction.x_nm) as f64;
            let ay = (first_end.y_nm - junction.y_nm) as f64;
            let bx = (second_end.x_nm - junction.x_nm) as f64;
            let by = (second_end.y_nm - junction.y_nm) as f64;
            let denominator = ax.hypot(ay) * bx.hypot(by);
            if denominator == 0.0 {
                continue;
            }
            let angle = ((ax * bx + ay * by) / denominator)
                .clamp(-1.0, 1.0)
                .acos()
                .to_degrees();
            if angle + f64::EPSILON < f64::from(minimum_angle_deg) {
                report.push(
                    "dfm_trace_angle",
                    format!("trace junction angle {angle:.1}° is below the manufacturing minimum"),
                    vec![route.net_id],
                );
            }
        }
    }
}

fn shared_endpoint(left: &Segment, right: &Segment) -> Option<(Point, Point, Point)> {
    for (junction, first_end) in [(left.start, left.end), (left.end, left.start)] {
        if right.start == junction {
            return Some((junction, first_end, right.end));
        }
        if right.end == junction {
            return Some((junction, first_end, right.start));
        }
    }
    None
}

fn point_in_pad(point: Point, pad: &Pad) -> bool {
    if pad.shape == PadShape::Custom && pad.custom_polygon.len() >= 3 {
        return point_in_polygon(point, &pad.custom_polygon);
    }
    let width = if pad.source_width_nm > 0 {
        pad.source_width_nm
    } else {
        pad.width_nm
    };
    let height = if pad.source_height_nm > 0 {
        pad.source_height_nm
    } else {
        pad.height_nm
    };
    let radians = (-pad.rotation_deg).to_radians();
    let dx = (point.x_nm - pad.position.x_nm) as f64;
    let dy = (point.y_nm - pad.position.y_nm) as f64;
    let x = dx * radians.cos() - dy * radians.sin();
    let y = dx * radians.sin() + dy * radians.cos();
    match pad.shape {
        PadShape::Circle => x.hypot(y) <= width.max(height) as f64 / 2.0,
        PadShape::Oval => {
            let (major, minor, along, across) = if width >= height {
                (width, height, x.abs(), y.abs())
            } else {
                (height, width, y.abs(), x.abs())
            };
            let half_line = (major - minor) as f64 / 2.0;
            let radius = minor as f64 / 2.0;
            across <= radius && (along <= half_line || (along - half_line).hypot(across) <= radius)
        }
        _ => x.abs() <= width as f64 / 2.0 && y.abs() <= height as f64 / 2.0,
    }
}

pub fn check_report_to_sarif(report: &CheckReport) -> serde_json::Value {
    let mut rule_ids: Vec<_> = report
        .violations
        .iter()
        .map(|violation| violation.rule.as_str())
        .collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pcbex",
                    "informationUri": "https://github.com/penguin425/pcbex",
                    "rules": rule_ids.iter().map(|rule| serde_json::json!({
                        "id": rule,
                        "shortDescription": {"text": rule.replace('_', " ")}
                    })).collect::<Vec<_>>()
                }
            },
            "results": report.violations.iter().map(|violation| serde_json::json!({
                "ruleId": violation.rule,
                "level": "error",
                "message": {"text": violation.message},
                "properties": {"netIds": violation.net_ids}
            })).collect::<Vec<_>>()
        }]
    })
}

fn check_manufacturing_clearance(
    route: &Route,
    other: &Route,
    clearance_nm: i64,
    report: &mut CheckReport,
) {
    for segment in &route.segments {
        for candidate in &other.segments {
            if segment.layer == candidate.layer
                && segments_closer_than(
                    segment.start,
                    segment.end,
                    candidate.start,
                    candidate.end,
                    segment.width_nm + candidate.width_nm + 2 * clearance_nm,
                )
            {
                report.push(
                    "dfm_clearance",
                    "copper spacing is below the manufacturing minimum".into(),
                    vec![route.net_id, other.net_id],
                );
                return;
            }
        }
        for via in &other.vias {
            if via.spans_layer(segment.layer)
                && point_segment_closer_than(
                    via.position,
                    segment.start,
                    segment.end,
                    via.diameter_nm + segment.width_nm + 2 * clearance_nm,
                )
            {
                report.push(
                    "dfm_clearance",
                    "copper spacing is below the manufacturing minimum".into(),
                    vec![route.net_id, other.net_id],
                );
                return;
            }
        }
    }
    for via in &route.vias {
        for segment in &other.segments {
            if via.spans_layer(segment.layer)
                && point_segment_closer_than(
                    via.position,
                    segment.start,
                    segment.end,
                    via.diameter_nm + segment.width_nm + 2 * clearance_nm,
                )
            {
                report.push(
                    "dfm_clearance",
                    "copper spacing is below the manufacturing minimum".into(),
                    vec![route.net_id, other.net_id],
                );
                return;
            }
        }
        for candidate in &other.vias {
            if via.shares_layer_with(candidate)
                && points_closer_than(
                    via.position,
                    candidate.position,
                    via.diameter_nm + candidate.diameter_nm + 2 * clearance_nm,
                )
            {
                report.push(
                    "dfm_clearance",
                    "copper spacing is below the manufacturing minimum".into(),
                    vec![route.net_id, other.net_id],
                );
                return;
            }
        }
    }
}

fn check_differential_pairs(
    board: &Board,
    routes: &HashMap<u32, &Route>,
    report: &mut CheckReport,
) {
    for pair in &board.differential_pairs {
        let (Some(positive), Some(negative)) = (
            routes.get(&pair.positive_net_id),
            routes.get(&pair.negative_net_id),
        ) else {
            continue;
        };
        let positive_length = route_length(positive);
        let negative_length = route_length(negative);
        if (positive_length - negative_length).abs() > pair.max_skew_nm {
            report.push(
                "differential_skew",
                format!("differential pair {} exceeds maximum skew", pair.name),
                vec![pair.positive_net_id, pair.negative_net_id],
            );
        }
        let positive_layers: HashSet<_> = positive
            .segments
            .iter()
            .map(|segment| segment.layer)
            .collect();
        let negative_layers: HashSet<_> = negative
            .segments
            .iter()
            .map(|segment| segment.layer)
            .collect();
        if positive_layers != negative_layers || positive.vias.len() != negative.vias.len() {
            report.push(
                "differential_symmetry",
                format!(
                    "differential pair {} uses asymmetric layers or vias",
                    pair.name
                ),
                vec![pair.positive_net_id, pair.negative_net_id],
            );
        }
        let positive_coupling = coupled_percent(positive, negative, pair);
        let negative_coupling = coupled_percent(negative, positive, pair);
        if positive_coupling.min(negative_coupling) < pair.min_coupled_percent {
            report.push(
                "differential_coupling",
                format!(
                    "differential pair {} is coupled for less than {}%",
                    pair.name, pair.min_coupled_percent
                ),
                vec![pair.positive_net_id, pair.negative_net_id],
            );
        }
        if let (Some(target), Some(tolerance)) = (
            pair.target_differential_impedance_ohms,
            pair.differential_impedance_tolerance_ohms,
        ) {
            for segment in &positive.segments {
                let Some(stackup) = board
                    .stackup
                    .iter()
                    .find(|entry| entry.layer == segment.layer)
                else {
                    report.push(
                        "differential_impedance_stackup",
                        format!(
                            "differential pair {} has no stackup entry for {:?}",
                            pair.name, segment.layer
                        ),
                        vec![pair.positive_net_id, pair.negative_net_id],
                    );
                    break;
                };
                let Some(estimated) = crate::estimated_stackup_differential_impedance_ohms(
                    segment.width_nm,
                    pair.gap_nm,
                    stackup,
                ) else {
                    report.push(
                        "differential_impedance_stackup",
                        format!(
                            "differential pair {} has invalid impedance geometry",
                            pair.name
                        ),
                        vec![pair.positive_net_id, pair.negative_net_id],
                    );
                    break;
                };
                if (estimated - target).abs() > tolerance {
                    report.push(
                        "differential_impedance",
                        format!(
                            "differential pair {} estimates {:.2} Ω, outside {:.2} ± {:.2} Ω",
                            pair.name, estimated, target, tolerance
                        ),
                        vec![pair.positive_net_id, pair.negative_net_id],
                    );
                    break;
                }
            }
        }
        let Some(maximum_step) = pair.maximum_differential_impedance_step_ohms else {
            continue;
        };
        let steps = [positive, negative]
            .into_iter()
            .map(|route| differential_impedance_transition_step(board, route, pair))
            .collect::<Result<Vec<_>, _>>();
        let Ok(steps) = steps else {
            report.push(
                "differential_impedance_stackup",
                format!(
                    "differential pair {} has invalid transition stackup geometry",
                    pair.name
                ),
                vec![pair.positive_net_id, pair.negative_net_id],
            );
            continue;
        };
        let step = steps.into_iter().flatten().fold(0.0_f64, f64::max);
        if step > maximum_step {
            report.push(
                "differential_impedance_transition",
                format!(
                    "differential pair {} changes impedance by {:.2} Ω at a layer transition, exceeding {:.2} Ω",
                    pair.name, step, maximum_step
                ),
                vec![pair.positive_net_id, pair.negative_net_id],
            );
        }
    }
}

fn differential_impedance_transition_step(
    board: &Board,
    route: &Route,
    pair: &crate::DifferentialPair,
) -> Result<Option<f64>, ()> {
    let mut maximum_step = None::<f64>;
    for via in &route.vias {
        let connected = route
            .segments
            .iter()
            .filter(|segment| {
                (segment.start == via.position || segment.end == via.position)
                    && via.spans_layer(segment.layer)
            })
            .map(|segment| {
                let stackup = board
                    .stackup
                    .iter()
                    .find(|entry| entry.layer == segment.layer)
                    .ok_or(())?;
                crate::estimated_stackup_differential_impedance_ohms(
                    segment.width_nm,
                    pair.gap_nm,
                    stackup,
                )
                .ok_or(())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if connected.len() < 2 {
            continue;
        }
        let minimum = connected.iter().copied().fold(f64::INFINITY, f64::min);
        let maximum = connected.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        maximum_step =
            Some(maximum_step.map_or(maximum - minimum, |current| current.max(maximum - minimum)));
    }
    Ok(maximum_step)
}

fn check_length_groups(board: &Board, routes: &HashMap<u32, &Route>, report: &mut CheckReport) {
    for group in &board.length_groups {
        let lengths: Vec<_> = group
            .net_ids
            .iter()
            .filter_map(|net_id| {
                routes
                    .get(net_id)
                    .map(|route| (*net_id, route_length(route)))
            })
            .collect();
        let (Some(minimum), Some(maximum)) = (
            lengths.iter().min_by_key(|(_, length)| length),
            lengths.iter().max_by_key(|(_, length)| length),
        ) else {
            continue;
        };
        if maximum.1 - minimum.1 > group.max_skew_nm {
            report.push(
                "length_group_skew",
                format!(
                    "length group {} has {} nm skew, exceeding {} nm",
                    group.name,
                    maximum.1 - minimum.1,
                    group.max_skew_nm
                ),
                group.net_ids.clone(),
            );
        }
    }
}

fn route_length(route: &Route) -> i64 {
    route_length_nm(route)
}

pub fn coupled_percent(route: &Route, partner: &Route, pair: &crate::DifferentialPair) -> u8 {
    let total = route_length(route);
    if total == 0 {
        return 0;
    }
    let coupled: i64 = route
        .segments
        .iter()
        .filter(|segment| {
            partner.segments.iter().any(|other| {
                if segment.layer != other.layer {
                    return false;
                }
                let maximum_twice = segment.width_nm
                    + other.width_nm
                    + 2 * (pair.gap_nm + pair.gap_tolerance_nm)
                    + 1;
                point_segment_closer_than(segment.start, other.start, other.end, maximum_twice)
                    && point_segment_closer_than(segment.end, other.start, other.end, maximum_twice)
            })
        })
        .map(|segment| {
            let dx = (segment.end.x_nm - segment.start.x_nm) as f64;
            let dy = (segment.end.y_nm - segment.start.y_nm) as f64;
            dx.hypot(dy).round() as i64
        })
        .sum();
    ((coupled as i128 * 100 / total as i128).clamp(0, 100)) as u8
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
        let midpoint = Point {
            x_nm: segment.start.x_nm + (segment.end.x_nm - segment.start.x_nm) / 2,
            y_nm: segment.start.y_nm + (segment.end.y_nm - segment.start.y_nm) / 2,
        };
        if keepout.net_id != Some(net_id)
            && keepout.layers.contains(&segment.layer)
            && point_in_polygon(midpoint, &keepout.polygon)
        {
            if keepout
                .minimum_track_width_nm
                .is_some_and(|minimum| segment.width_nm < minimum)
            {
                report.push(
                    "rule_area_track_width",
                    "track is narrower than the local Rule Area minimum".into(),
                    vec![net_id],
                );
            }
            if keepout
                .minimum_clearance_nm
                .is_some_and(|minimum| rules.clearance_nm < minimum)
            {
                report.push(
                    "rule_area_clearance",
                    "net clearance is below the local Rule Area minimum".into(),
                    vec![net_id],
                );
            }
        }
        if !keepout.tracks_not_allowed
            || keepout.net_id == Some(net_id)
            || !keepout.layers.contains(&segment.layer)
        {
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
            if via.spans_layer(sa.layer)
                && point_segment_closer_than(via.position, sa.start, sa.end, required_twice)
            {
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
            if via.spans_layer(sb.layer)
                && point_segment_closer_than(via.position, sb.start, sb.end, required_twice)
            {
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
            if via.shares_layer_with(other)
                && points_closer_than(via.position, other.position, required_twice)
            {
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
    let via_count = route.vias.len();
    let zone_offset = segment_count + via_count;
    let node_count = zone_offset + route.zones.len();
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
            if via.spans_layer(segment.layer)
                && point_segment_within(
                    via.position,
                    segment.start,
                    segment.end,
                    segment.width_nm + via.diameter_nm,
                )
            {
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
    for (zone_index, zone) in route.zones.iter().enumerate() {
        let node = zone_offset + zone_index;
        for (segment_index, segment) in route.segments.iter().enumerate() {
            if segment.layer == zone.layer
                && (point_in_polygon(segment.start, &zone.polygon)
                    || point_in_polygon(segment.end, &zone.polygon)
                    || segment_polygon_closer_than(
                        segment.start,
                        segment.end,
                        &zone.polygon,
                        segment.width_nm,
                    ))
            {
                components.union(node, segment_index);
            }
        }
        for (via_index, via) in route.vias.iter().enumerate() {
            if via.spans_layer(zone.layer)
                && (point_in_polygon(via.position, &zone.polygon)
                    || point_polygon_closer_than(via.position, &zone.polygon, via.diameter_nm))
            {
                components.union(node, segment_count + via_index);
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
                        terminal.layers.iter().any(|layer| via.spans_layer(*layer))
                            && points_within(via.position, terminal.position, via.diameter_nm)
                    })
                    .map(|(index, _)| segment_count + index),
            )
            .chain(
                route
                    .zones
                    .iter()
                    .enumerate()
                    .filter(|(_, zone)| {
                        terminal.layers.contains(&zone.layer)
                            && point_in_polygon(terminal.position, &zone.polygon)
                    })
                    .map(|(index, _)| zone_offset + index),
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
    use crate::{
        CapsuleObstacle, DifferentialPair, Layer, Point, RoundObstacle, Rules, Terminal, Via,
    };
    fn base() -> Board {
        Board {
            schema_version: crate::CURRENT_SCHEMA_VERSION,
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            outline: vec![],
            cutouts: vec![],
            copper_layers: vec![Layer::Front, Layer::Back],
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
            differential_pairs: vec![],
            length_groups: vec![],
            escape_groups: vec![],
            manufacturing_rules: None,
            return_path_rules: vec![],
            power_net_rules: vec![],
            stackup: vec![],
            via_strategy: crate::ViaStrategy::ThroughOnly,
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
                arcs: vec![],
                teardrops: vec![],
                zones: vec![],
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
    fn checks_power_net_voltage_drop_and_parallel_vias() {
        let mut board = base();
        board.routes.push(Route {
            net_id: 1,
            segments: vec![Segment {
                start: Point {
                    x_nm: 1_000_000,
                    y_nm: 1_000_000,
                },
                end: Point {
                    x_nm: 9_000_000,
                    y_nm: 1_000_000,
                },
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });
        board.power_net_rules.push(crate::PowerNetRule {
            net_id: 1,
            current_ma: 1_000.0,
            maximum_voltage_drop_mv: 10.0,
            minimum_parallel_vias: 2,
        });

        let report = check_board(&board);

        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.rule == "pdn_voltage_drop")
        );
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.rule == "pdn_via_count")
        );
    }

    #[test]
    fn checks_footprint_and_local_rule_area_constraints() {
        let mut board = base();
        board.keepouts.push(crate::Keepout {
            polygon: vec![
                Point {
                    x_nm: 3_000_000,
                    y_nm: 3_000_000,
                },
                Point {
                    x_nm: 7_000_000,
                    y_nm: 3_000_000,
                },
                Point {
                    x_nm: 7_000_000,
                    y_nm: 7_000_000,
                },
                Point {
                    x_nm: 3_000_000,
                    y_nm: 7_000_000,
                },
            ],
            layers: vec![Layer::Front],
            net_id: None,
            tracks_not_allowed: false,
            vias_not_allowed: false,
            zones_not_allowed: false,
            footprints_not_allowed: true,
            minimum_track_width_nm: Some(500_000),
            minimum_clearance_nm: Some(400_000),
        });
        board.footprints.push(crate::Footprint {
            reference: "U1".into(),
            position: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            rotation_deg: 0.0,
            pads: vec![],
        });
        board.routes.push(Route {
            net_id: 1,
            segments: vec![Segment {
                start: Point {
                    x_nm: 4_000_000,
                    y_nm: 5_000_000,
                },
                end: Point {
                    x_nm: 6_000_000,
                    y_nm: 5_000_000,
                },
                layer: Layer::Front,
                width_nm: 250_000,
            }],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });

        let report = check_board(&board);

        for rule in [
            "rule_area_footprint",
            "rule_area_track_width",
            "rule_area_clearance",
        ] {
            assert!(
                report
                    .violations
                    .iter()
                    .any(|violation| violation.rule == rule)
            );
        }
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
            arcs: vec![],
            teardrops: vec![],
            zones: vec![],
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
            arcs: vec![],
            teardrops: vec![],
            zones: vec![],
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
            arcs: vec![],
            teardrops: vec![],
            zones: vec![],
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
            arcs: vec![],
            teardrops: vec![],
            zones: vec![],
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
            arcs: vec![],
            teardrops: vec![],
            zones: vec![],
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
                kind: crate::ViaKind::Through,
                start_layer: Layer::Front,
                end_layer: Layer::Back,
            }],
        });

        let report = check_board(&board);
        assert!(!report.violations.iter().any(|violation| matches!(
            violation.rule.as_str(),
            "unconnected" | "disconnected_route" | "orphan_copper"
        )));
    }

    #[test]
    fn checks_differential_pair_coupling_and_skew() {
        let mut board = base();
        for (id, name, y_nm, end_x) in [
            (1, "USB_P", 4_000_000, 9_000_000),
            (2, "USB_N", 4_600_000, 9_000_000),
        ] {
            let start = Point {
                x_nm: 1_000_000,
                y_nm,
            };
            let end = Point { x_nm: end_x, y_nm };
            board.nets.push(Net {
                id,
                name: name.into(),
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
                net_id: id,
                arcs: vec![],
                teardrops: vec![],
                zones: vec![],
                segments: vec![Segment {
                    start,
                    end,
                    layer: Layer::Front,
                    width_nm: 250_000,
                }],
                vias: vec![],
            });
        }
        board.stackup.push(crate::StackupLayer {
            layer: Layer::Front,
            dielectric_height_nm: 200_000,
            dielectric_constant: 4.2,
            copper_thickness_nm: 35_000,
            reference_layer: Some(Layer::Back),
            secondary_reference_layer: None,
            secondary_dielectric_height_nm: None,
            secondary_dielectric_constant: None,
        });
        let target =
            crate::estimated_differential_impedance_ohms(250_000, 350_000, 200_000, 35_000, 4.2)
                .unwrap();
        board.differential_pairs.push(DifferentialPair {
            name: "USB".into(),
            positive_net_id: 1,
            negative_net_id: 2,
            gap_nm: 350_000,
            gap_tolerance_nm: 50_000,
            max_skew_nm: 100_000,
            min_coupled_percent: 90,
            target_differential_impedance_ohms: Some(target),
            differential_impedance_tolerance_ohms: Some(0.01),
            maximum_differential_impedance_step_ohms: None,
            minimum_length_nm: None,
            tuning_amplitude_nm: None,
            tuning_pitch_nm: None,
            max_tuning_sections: 1,
        });
        assert!(check_board(&board).is_clean());

        board.differential_pairs[0].target_differential_impedance_ohms = Some(target + 20.0);
        let impedance_report = check_board(&board);
        assert!(
            impedance_report
                .violations
                .iter()
                .any(|violation| violation.rule == "differential_impedance")
        );
        board.differential_pairs[0].target_differential_impedance_ohms = Some(target);
        board.routes[1].segments[0].end.x_nm = 8_000_000;
        board.nets[1].terminals[1].position.x_nm = 8_000_000;
        let report = check_board(&board);
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.rule == "differential_skew")
        );
    }

    #[test]
    fn checks_differential_impedance_at_layer_transitions() {
        let mut board = base();
        for (id, name, y_nm) in [(1, "USB_P", 4_000_000), (2, "USB_N", 4_350_000)] {
            let start = Point {
                x_nm: 1_000_000,
                y_nm,
            };
            let transition = Point {
                x_nm: 5_000_000,
                y_nm,
            };
            let end = Point {
                x_nm: 9_000_000,
                y_nm,
            };
            board.nets.push(Net {
                id,
                name: name.into(),
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
                net_id: id,
                arcs: vec![],
                teardrops: vec![],
                zones: vec![],
                segments: vec![
                    Segment {
                        start,
                        end: transition,
                        layer: Layer::Front,
                        width_nm: 150_000,
                    },
                    Segment {
                        start: transition,
                        end,
                        layer: Layer::Back,
                        width_nm: 400_000,
                    },
                ],
                vias: vec![Via {
                    position: transition,
                    diameter_nm: 600_000,
                    drill_nm: 300_000,
                    kind: crate::ViaKind::Through,
                    start_layer: Layer::Front,
                    end_layer: Layer::Back,
                }],
            });
        }
        for (layer, reference) in [(Layer::Front, Layer::Back), (Layer::Back, Layer::Front)] {
            board.stackup.push(crate::StackupLayer {
                layer,
                dielectric_height_nm: 200_000,
                dielectric_constant: 4.2,
                copper_thickness_nm: 35_000,
                reference_layer: Some(reference),
                secondary_reference_layer: None,
                secondary_dielectric_height_nm: None,
                secondary_dielectric_constant: None,
            });
        }
        board.differential_pairs.push(DifferentialPair {
            name: "USB".into(),
            positive_net_id: 1,
            negative_net_id: 2,
            gap_nm: 350_000,
            gap_tolerance_nm: 50_000,
            max_skew_nm: 100_000,
            min_coupled_percent: 90,
            target_differential_impedance_ohms: None,
            differential_impedance_tolerance_ohms: None,
            maximum_differential_impedance_step_ohms: Some(2.0),
            minimum_length_nm: None,
            tuning_amplitude_nm: None,
            tuning_pitch_nm: None,
            max_tuning_sections: 1,
        });

        assert!(
            check_board(&board)
                .violations
                .iter()
                .any(|violation| violation.rule == "differential_impedance_transition")
        );
    }

    #[test]
    fn reports_manufacturing_width_drill_ring_aspect_and_edge_rules() {
        let mut board = base();
        board.manufacturing_rules = Some(crate::ManufacturingRules {
            minimum_track_width_nm: 300_000,
            minimum_clearance_nm: 250_000,
            minimum_drill_nm: 350_000,
            minimum_annular_ring_nm: 200_000,
            minimum_copper_to_edge_nm: 500_000,
            board_thickness_nm: 1_600_000,
            maximum_via_aspect_ratio: 4,
            minimum_drill_to_drill_nm: 300_000,
            allow_via_in_pad: false,
            minimum_trace_angle_deg: 90,
        });
        board.footprints.push(crate::Footprint {
            reference: "U1".into(),
            position: Point {
                x_nm: 5_000_000,
                y_nm: 1_000_000,
            },
            rotation_deg: 0.0,
            pads: vec![Pad {
                number: "1".into(),
                position: Point {
                    x_nm: 5_000_000,
                    y_nm: 1_000_000,
                },
                width_nm: 1_000_000,
                height_nm: 1_000_000,
                source_width_nm: 1_000_000,
                source_height_nm: 1_000_000,
                rotation_deg: 0.0,
                shape: PadShape::Circle,
                custom_polygon: vec![],
                roundrect_radius_nm: 0,
                trapezoid_delta_x_nm: 0,
                trapezoid_delta_y_nm: 0,
                drill_width_nm: Some(200_000),
                drill_height_nm: Some(200_000),
                drill_offset_x_nm: 0,
                drill_offset_y_nm: 0,
                plated: true,
                layers: vec![Layer::Front],
                net_id: Some(1),
            }],
        });
        board.routes.push(Route {
            net_id: 1,
            arcs: vec![],
            teardrops: vec![],
            zones: vec![],
            segments: vec![
                Segment {
                    start: Point {
                        x_nm: 100_000,
                        y_nm: 1_000_000,
                    },
                    end: Point {
                        x_nm: 5_000_000,
                        y_nm: 1_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 200_000,
                },
                Segment {
                    start: Point {
                        x_nm: 5_000_000,
                        y_nm: 1_000_000,
                    },
                    end: Point {
                        x_nm: 4_000_000,
                        y_nm: 2_000_000,
                    },
                    layer: Layer::Front,
                    width_nm: 200_000,
                },
            ],
            vias: vec![Via {
                position: Point {
                    x_nm: 5_000_000,
                    y_nm: 1_000_000,
                },
                diameter_nm: 600_000,
                drill_nm: 300_000,
                kind: crate::ViaKind::Through,
                start_layer: Layer::Front,
                end_layer: Layer::Back,
            }],
        });
        board.routes.push(Route {
            net_id: 2,
            arcs: vec![],
            teardrops: vec![],
            zones: vec![],
            segments: vec![],
            vias: vec![Via {
                position: Point {
                    x_nm: 5_500_000,
                    y_nm: 1_000_000,
                },
                diameter_nm: 600_000,
                drill_nm: 300_000,
                kind: crate::ViaKind::Through,
                start_layer: Layer::Front,
                end_layer: Layer::Back,
            }],
        });

        let report = check_manufacturability(&board);
        for rule in [
            "dfm_track_width",
            "dfm_drill",
            "dfm_annular_ring",
            "dfm_aspect_ratio",
            "dfm_copper_to_edge",
            "dfm_via_in_pad",
            "dfm_drill_spacing",
            "dfm_trace_angle",
        ] {
            assert!(
                report
                    .violations
                    .iter()
                    .any(|violation| violation.rule == rule),
                "missing {rule}"
            );
        }
        let sarif = check_report_to_sarif(&report);
        assert_eq!(sarif["version"], "2.1.0");
        assert!(
            sarif["runs"][0]["results"]
                .as_array()
                .is_some_and(|results| results.len() == report.violations.len())
        );
    }

    #[test]
    fn reports_plated_and_non_plated_component_hole_dfm() {
        let mut board = base();
        board.manufacturing_rules = Some(crate::ManufacturingRules {
            minimum_track_width_nm: 200_000,
            minimum_clearance_nm: 200_000,
            minimum_drill_nm: 400_000,
            minimum_annular_ring_nm: 200_000,
            minimum_copper_to_edge_nm: 300_000,
            board_thickness_nm: 1_600_000,
            maximum_via_aspect_ratio: 3,
            minimum_drill_to_drill_nm: 300_000,
            allow_via_in_pad: true,
            minimum_trace_angle_deg: 0,
        });
        board.footprints.push(crate::Footprint {
            reference: "J1".into(),
            position: Point {
                x_nm: 300_000,
                y_nm: 1_000_000,
            },
            rotation_deg: 0.0,
            pads: vec![
                Pad {
                    number: "1".into(),
                    position: Point {
                        x_nm: 300_000,
                        y_nm: 1_000_000,
                    },
                    width_nm: 600_000,
                    height_nm: 600_000,
                    source_width_nm: 600_000,
                    source_height_nm: 600_000,
                    rotation_deg: 0.0,
                    shape: PadShape::Circle,
                    custom_polygon: vec![],
                    roundrect_radius_nm: 0,
                    trapezoid_delta_x_nm: 0,
                    trapezoid_delta_y_nm: 0,
                    drill_width_nm: Some(300_000),
                    drill_height_nm: Some(300_000),
                    drill_offset_x_nm: 0,
                    drill_offset_y_nm: 0,
                    plated: true,
                    layers: vec![Layer::Front, Layer::Back],
                    net_id: Some(1),
                },
                Pad {
                    number: String::new(),
                    position: Point {
                        x_nm: 800_000,
                        y_nm: 1_000_000,
                    },
                    width_nm: 1_200_000,
                    height_nm: 800_000,
                    source_width_nm: 1_200_000,
                    source_height_nm: 800_000,
                    rotation_deg: 0.0,
                    shape: PadShape::Oval,
                    custom_polygon: vec![],
                    roundrect_radius_nm: 0,
                    trapezoid_delta_x_nm: 0,
                    trapezoid_delta_y_nm: 0,
                    drill_width_nm: Some(700_000),
                    drill_height_nm: Some(300_000),
                    drill_offset_x_nm: 0,
                    drill_offset_y_nm: 0,
                    plated: false,
                    layers: vec![Layer::Front, Layer::Back],
                    net_id: None,
                },
            ],
        });

        let report = check_manufacturability(&board);
        for rule in [
            "dfm_component_drill",
            "dfm_component_annular_ring",
            "dfm_component_aspect_ratio",
            "dfm_hole_to_edge",
            "dfm_drill_spacing",
        ] {
            assert!(
                report
                    .violations
                    .iter()
                    .any(|violation| violation.rule == rule),
                "missing {rule}"
            );
        }
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "dfm_component_annular_ring")
                .count(),
            1,
            "NPTH pads must not require an annular ring"
        );
    }

    #[test]
    fn normal_check_rejects_invalid_component_hole_models_without_dfm_rules() {
        let mut board = base();
        board.footprints.push(crate::Footprint {
            reference: "J1".into(),
            position: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            rotation_deg: 0.0,
            pads: vec![
                Pad {
                    number: "1".into(),
                    position: Point {
                        x_nm: 5_000_000,
                        y_nm: 5_000_000,
                    },
                    width_nm: 600_000,
                    height_nm: 600_000,
                    source_width_nm: 600_000,
                    source_height_nm: 600_000,
                    rotation_deg: 0.0,
                    shape: PadShape::Circle,
                    custom_polygon: vec![],
                    roundrect_radius_nm: 0,
                    trapezoid_delta_x_nm: 0,
                    trapezoid_delta_y_nm: 0,
                    drill_width_nm: Some(600_000),
                    drill_height_nm: Some(300_000),
                    drill_offset_x_nm: 0,
                    drill_offset_y_nm: 0,
                    plated: true,
                    layers: vec![Layer::Front, Layer::Back],
                    net_id: Some(1),
                },
                Pad {
                    number: "2".into(),
                    position: Point {
                        x_nm: 7_000_000,
                        y_nm: 5_000_000,
                    },
                    width_nm: 800_000,
                    height_nm: 800_000,
                    source_width_nm: 800_000,
                    source_height_nm: 800_000,
                    rotation_deg: 0.0,
                    shape: PadShape::Circle,
                    custom_polygon: vec![],
                    roundrect_radius_nm: 0,
                    trapezoid_delta_x_nm: 0,
                    trapezoid_delta_y_nm: 0,
                    drill_width_nm: Some(300_000),
                    drill_height_nm: None,
                    drill_offset_x_nm: 0,
                    drill_offset_y_nm: 0,
                    plated: false,
                    layers: vec![Layer::Front, Layer::Back],
                    net_id: None,
                },
            ],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "component_hole")
                .count(),
            2
        );
    }

    #[test]
    fn rotated_drill_offsets_move_the_exact_hole_capsule() {
        let pad = Pad {
            number: "1".into(),
            position: Point {
                x_nm: 2_000_000,
                y_nm: 3_000_000,
            },
            width_nm: 2_000_000,
            height_nm: 2_000_000,
            source_width_nm: 2_000_000,
            source_height_nm: 2_000_000,
            rotation_deg: 90.0,
            shape: PadShape::Oval,
            custom_polygon: vec![],
            roundrect_radius_nm: 0,
            trapezoid_delta_x_nm: 0,
            trapezoid_delta_y_nm: 0,
            drill_width_nm: Some(800_000),
            drill_height_nm: Some(400_000),
            drill_offset_x_nm: 300_000,
            drill_offset_y_nm: -100_000,
            plated: true,
            layers: vec![Layer::Front, Layer::Back],
            net_id: Some(1),
        };

        let hole = drilled_pad_hole(&pad, 800_000, 400_000);
        assert_eq!(
            hole.start,
            Point {
                x_nm: 2_100_000,
                y_nm: 3_100_000
            }
        );
        assert_eq!(
            hole.end,
            Point {
                x_nm: 2_100_000,
                y_nm: 3_500_000
            }
        );
        assert_eq!(hole.diameter_nm, 400_000);
        assert!(drill_fits_pad(&pad, 800_000, 400_000));
    }

    #[test]
    fn normal_check_rejects_diagonal_offset_hole_outside_circle_pad() {
        let mut board = base();
        board.footprints.push(crate::Footprint {
            reference: "J2".into(),
            position: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            rotation_deg: 0.0,
            pads: vec![Pad {
                number: "1".into(),
                position: Point {
                    x_nm: 5_000_000,
                    y_nm: 5_000_000,
                },
                width_nm: 1_000_000,
                height_nm: 1_000_000,
                source_width_nm: 1_000_000,
                source_height_nm: 1_000_000,
                rotation_deg: 0.0,
                shape: PadShape::Circle,
                custom_polygon: vec![],
                roundrect_radius_nm: 0,
                trapezoid_delta_x_nm: 0,
                trapezoid_delta_y_nm: 0,
                drill_width_nm: Some(200_000),
                drill_height_nm: Some(200_000),
                drill_offset_x_nm: 350_000,
                drill_offset_y_nm: 350_000,
                plated: true,
                layers: vec![Layer::Front, Layer::Back],
                net_id: Some(1),
            }],
        });

        let report = check_board(&board);
        assert!(report.violations.iter().any(|violation| {
            violation.rule == "component_hole"
                && violation.message.contains("plated drill must fit")
        }));
    }

    #[test]
    fn roundrect_hole_containment_respects_curved_corners() {
        let pad = Pad {
            number: "1".into(),
            position: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            width_nm: 2_000_000,
            height_nm: 1_000_000,
            source_width_nm: 2_000_000,
            source_height_nm: 1_000_000,
            rotation_deg: 0.0,
            shape: PadShape::RoundRect,
            custom_polygon: vec![],
            roundrect_radius_nm: 250_000,
            trapezoid_delta_x_nm: 0,
            trapezoid_delta_y_nm: 0,
            drill_width_nm: Some(200_000),
            drill_height_nm: Some(200_000),
            drill_offset_x_nm: 875_000,
            drill_offset_y_nm: 375_000,
            plated: true,
            layers: vec![Layer::Front, Layer::Back],
            net_id: Some(1),
        };

        assert!(!drill_fits_pad(&pad, 200_000, 200_000));
    }

    #[test]
    fn trapezoid_hole_containment_respects_sloped_edges() {
        let pad = Pad {
            number: "1".into(),
            position: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            width_nm: 2_000_000,
            height_nm: 1_000_000,
            source_width_nm: 2_000_000,
            source_height_nm: 1_000_000,
            rotation_deg: 0.0,
            shape: PadShape::Trapezoid,
            custom_polygon: vec![],
            roundrect_radius_nm: 0,
            trapezoid_delta_x_nm: 400_000,
            trapezoid_delta_y_nm: 0,
            drill_width_nm: Some(200_000),
            drill_height_nm: Some(200_000),
            drill_offset_x_nm: 800_000,
            drill_offset_y_nm: 350_000,
            plated: true,
            layers: vec![Layer::Front, Layer::Back],
            net_id: Some(1),
        };

        assert!(!drill_fits_pad(&pad, 200_000, 200_000));
    }
}

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
        linearized.routes = board
            .routes
            .iter()
            .map(|route| {
                let mut valid_arcs = route.clone();
                valid_arcs
                    .arcs
                    .retain(|arc| route_arc_geometry_is_valid(board, arc));
                valid_arcs.linearized_arcs()
            })
            .collect();
        let mut teardrop_obstacles = Vec::new();
        let mut invalid_teardrop_net_ids = Vec::new();
        let mut invalid_zone_fill_net_ids = Vec::new();
        for route in &mut linearized.routes {
            for teardrop in route.teardrops.drain(..) {
                if teardrop_geometry_is_valid(board, &teardrop) {
                    teardrop_obstacles.push(crate::PolygonObstacle {
                        polygon: teardrop.polygon,
                        layers: vec![teardrop.layer],
                        net_id: Some(route.net_id),
                    });
                } else {
                    invalid_teardrop_net_ids.push(route.net_id);
                }
            }
            for zone in &mut route.zones {
                for polygon in zone.filled_polygons.drain(..) {
                    if zone_fill_geometry_is_valid(board, zone.layer, &polygon) {
                        teardrop_obstacles.push(crate::PolygonObstacle {
                            polygon,
                            layers: vec![zone.layer],
                            net_id: Some(route.net_id),
                        });
                    } else {
                        invalid_zone_fill_net_ids.push(route.net_id);
                    }
                }
            }
        }
        linearized.polygon_obstacles.extend(teardrop_obstacles);
        let mut report = check_board(&linearized);
        for net_id in invalid_teardrop_net_ids {
            report.push(
                "teardrop_geometry",
                "teardrop must be a simple non-degenerate polygon on a declared copper layer"
                    .into(),
                vec![net_id],
            );
        }
        for net_id in invalid_zone_fill_net_ids {
            report.push(
                "zone_fill_geometry",
                "filled zone must be a simple non-degenerate polygon on a declared copper layer"
                    .into(),
                vec![net_id],
            );
        }
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
                if !route_arc_geometry_is_valid(board, arc) {
                    report.push(
                        "arc_geometry",
                        "arc must have positive width, a declared copper layer, and three points defining a curve"
                            .into(),
                        vec![route.net_id],
                    );
                    continue;
                }
                if arc.width_nm < rules.track_width_nm {
                    report.push(
                        "track_width",
                        "arc is narrower than the configured minimum".into(),
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
    if board.width_nm <= 0 || board.height_nm <= 0 {
        report.push(
            "board_dimensions",
            "board width and height must be positive".into(),
            vec![],
        );
    }
    if board.rules.grid_nm <= 0 {
        report.push(
            "routing_grid",
            "routing grid must be positive".into(),
            vec![],
        );
    }
    if board.rules.track_width_nm <= 0
        || board.rules.clearance_nm < 0
        || board.rules.via_drill_nm <= 0
        || board.rules.via_diameter_nm <= board.rules.via_drill_nm
    {
        report.push(
            "routing_rules",
            "base routing rules require a positive track width and via drill, non-negative clearance, and a via diameter larger than its drill"
                .into(),
            vec![],
        );
    }
    for (name, rules) in &board.net_classes {
        if name.trim().is_empty() {
            report.push(
                "net_class_name",
                "net class names must contain at least one non-whitespace character".into(),
                vec![],
            );
        }
        if rules.track_width_nm <= 0
            || rules.clearance_nm < 0
            || rules.via_drill_nm <= 0
            || rules.via_diameter_nm <= rules.via_drill_nm
        {
            report.push(
                "net_class_dimensions",
                format!(
                    "net class {name} requires a positive track width and via drill, non-negative clearance, and a via diameter larger than its drill"
                ),
                vec![],
            );
        }
        if rules
            .layers
            .as_ref()
            .is_some_and(|layers| !layer_membership_is_valid(board, layers))
        {
            report.push(
                "net_class_layers",
                format!(
                    "net class {name} must allow a unique non-empty subset of the board copper stackup"
                ),
                vec![],
            );
        }
        if rules.minimum_length_nm.is_some_and(|value| value <= 0)
            || rules.maximum_length_nm.is_some_and(|value| value <= 0)
            || matches!(
                (rules.minimum_length_nm, rules.maximum_length_nm),
                (Some(minimum), Some(maximum)) if minimum > maximum
            )
        {
            report.push(
                "net_class_length_limits",
                format!(
                    "net class {name} length limits must be positive and minimum must not exceed maximum"
                ),
                vec![],
            );
        }
        if rules.target_impedance_ohms.is_some() != rules.impedance_tolerance_ohms.is_some()
            || rules
                .target_impedance_ohms
                .is_some_and(|value| !value.is_finite() || value <= 0.0)
            || rules
                .impedance_tolerance_ohms
                .is_some_and(|value| !value.is_finite() || value < 0.0)
            || rules
                .maximum_impedance_step_ohms
                .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            report.push(
                "net_class_impedance_limits",
                format!(
                    "net class {name} impedance target and tolerance must be paired finite values with a positive target and non-negative limits"
                ),
                vec![],
            );
        }
        if rules.differential_width_nm.is_some_and(|value| value <= 0)
            || rules.differential_gap_nm.is_some_and(|value| value < 0)
        {
            report.push(
                "net_class_differential_dimensions",
                format!(
                    "net class {name} differential width must be positive and differential gap must be non-negative"
                ),
                vec![],
            );
        }
    }
    if !copper_layer_table_is_valid(board) {
        report.push(
            "copper_layers",
            "board copper layers must be non-empty, unique, and supported".into(),
            vec![],
        );
    }
    for obstacle in &board.obstacles {
        if obstacle.min.x_nm >= obstacle.max.x_nm || obstacle.min.y_nm >= obstacle.max.y_nm {
            report.push(
                "obstacle_geometry",
                "rectangular obstacle minimum coordinates must be strictly below its maximum coordinates"
                    .into(),
                obstacle.net_id.into_iter().collect(),
            );
        }
    }
    for (kind, diameter_nm, net_id) in board
        .round_obstacles
        .iter()
        .map(|obstacle| ("round", obstacle.diameter_nm, obstacle.net_id))
        .chain(
            board
                .capsule_obstacles
                .iter()
                .map(|obstacle| ("capsule", obstacle.diameter_nm, obstacle.net_id)),
        )
    {
        if diameter_nm <= 0 {
            report.push(
                "obstacle_diameter",
                format!("{kind} obstacle diameter must be positive"),
                net_id.into_iter().collect(),
            );
        }
    }
    for obstacle in &board.polygon_obstacles {
        if !custom_pad_polygon_is_valid(&obstacle.polygon) {
            report.push(
                "polygon_obstacle",
                "polygon obstacle must be a simple non-degenerate polygon".into(),
                obstacle.net_id.into_iter().collect(),
            );
        }
    }
    for keepout in &board.keepouts {
        if !keepout_definition_is_valid(keepout) {
            report.push(
                "keepout_definition",
                "keepout must have a simple non-degenerate polygon, at least one prohibition or local rule, positive minimum width, and non-negative minimum clearance"
                    .into(),
                keepout.net_id.into_iter().collect(),
            );
        }
    }
    for layers in board
        .obstacles
        .iter()
        .map(|obstacle| obstacle.layers.as_slice())
        .chain(
            board
                .round_obstacles
                .iter()
                .map(|obstacle| obstacle.layers.as_slice()),
        )
        .chain(
            board
                .capsule_obstacles
                .iter()
                .map(|obstacle| obstacle.layers.as_slice()),
        )
        .chain(
            board
                .polygon_obstacles
                .iter()
                .map(|obstacle| obstacle.layers.as_slice()),
        )
        .chain(
            board
                .keepouts
                .iter()
                .map(|keepout| keepout.layers.as_slice()),
        )
    {
        if !layer_membership_is_valid(board, layers) {
            report.push(
                "obstacle_layers",
                "obstacles and keepouts must use unique layers from the board copper stackup"
                    .into(),
                vec![],
            );
        }
    }
    let explicit_outline_is_valid =
        board.outline.is_empty() || custom_pad_polygon_is_valid(&board.outline);
    if !explicit_outline_is_valid {
        report.push(
            "board_outline",
            "explicit board outline must be a simple non-degenerate polygon".into(),
            vec![],
        );
    }
    if explicit_outline_is_valid
        && !board.outline.is_empty()
        && board.width_nm > 0
        && board.height_nm > 0
        && board.outline.iter().any(|point| {
            point.x_nm < 0
                || point.y_nm < 0
                || point.x_nm > board.width_nm
                || point.y_nm > board.height_nm
        })
    {
        report.push(
            "board_outline_bounds",
            "explicit board outline must remain inside the declared board dimensions".into(),
            vec![],
        );
    }
    let effective_outline = explicit_outline_is_valid.then(|| board.effective_outline());
    for cutout in &board.cutouts {
        let topology_is_valid = custom_pad_polygon_is_valid(cutout);
        if !topology_is_valid {
            report.push(
                "board_cutout",
                "board cutout must be a simple non-degenerate polygon".into(),
                vec![],
            );
        }
        if topology_is_valid
            && effective_outline.as_ref().is_some_and(|outline| {
                cutout
                    .iter()
                    .any(|point| !point_in_polygon(*point, outline))
            })
        {
            report.push(
                "board_cutout_bounds",
                "board cutout must remain inside the effective board outline".into(),
                vec![],
            );
        }
    }
    let known_net_ids: HashSet<_> = board.nets.iter().map(|net| net.id).collect();
    for net_id in board
        .obstacles
        .iter()
        .filter_map(|obstacle| obstacle.net_id)
        .chain(
            board
                .round_obstacles
                .iter()
                .filter_map(|obstacle| obstacle.net_id),
        )
        .chain(
            board
                .capsule_obstacles
                .iter()
                .filter_map(|obstacle| obstacle.net_id),
        )
        .chain(
            board
                .polygon_obstacles
                .iter()
                .filter_map(|obstacle| obstacle.net_id),
        )
        .chain(board.keepouts.iter().filter_map(|keepout| keepout.net_id))
    {
        if !known_net_ids.contains(&net_id) {
            report.push(
                "obstacle_net",
                format!("obstacle references undeclared net {net_id}"),
                vec![net_id],
            );
        }
    }
    let mut seen_net_ids = HashSet::new();
    let mut seen_net_names = HashSet::new();
    for net in &board.nets {
        let id_is_unique = seen_net_ids.insert(net.id);
        let name_is_unique = seen_net_names.insert(net.name.as_str());
        if net.id == 0 || net.name.trim().is_empty() || !id_is_unique || !name_is_unique {
            report.push(
                "net_table",
                format!(
                    "net {} must have a unique non-zero ID and unique non-empty name",
                    net.id
                ),
                vec![net.id],
            );
        }
        if net
            .class
            .as_ref()
            .is_some_and(|class| !board.net_classes.contains_key(class))
        {
            report.push(
                "net_class",
                format!("net {} references an undeclared net class", net.id),
                vec![net.id],
            );
        }
        for terminal in &net.terminals {
            if !layer_membership_is_valid(board, &terminal.layers) {
                report.push(
                    "terminal_layers",
                    format!(
                        "net {} terminal must use unique layers from the board copper stackup",
                        net.id
                    ),
                    vec![net.id],
                );
            }
        }
    }
    for footprint in &board.footprints {
        for pad in &footprint.pads {
            if !pad_geometry_is_valid(pad) {
                report.push(
                    "pad_geometry",
                    format!(
                        "{} pad {} must have valid dimensions, rotation, and shape parameters",
                        footprint.reference, pad.number
                    ),
                    pad.net_id.into_iter().collect(),
                );
            }
            let pad_layers: HashSet<_> = pad.layers.iter().copied().collect();
            if pad.layers.is_empty()
                || pad_layers.len() != pad.layers.len()
                || pad_layers
                    .iter()
                    .any(|layer| !board.copper_layers.contains(layer))
            {
                report.push(
                    "pad_layers",
                    format!(
                        "{} pad {} must use unique layers from the board copper stackup",
                        footprint.reference, pad.number
                    ),
                    pad.net_id.into_iter().collect(),
                );
            }
            if pad
                .net_id
                .is_some_and(|net_id| !known_net_ids.contains(&net_id))
            {
                report.push(
                    "pad_net",
                    format!(
                        "{} pad {} references an undeclared net",
                        footprint.reference, pad.number
                    ),
                    pad.net_id.into_iter().collect(),
                );
            }
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
    let mut seen_route_net_ids = HashSet::new();
    for route in &board.routes {
        if !known_net_ids.contains(&route.net_id) {
            report.push(
                "route_net",
                format!("route {} references an undeclared net", route.net_id),
                vec![route.net_id],
            );
        }
        if !seen_route_net_ids.insert(route.net_id) {
            report.push(
                "duplicate_route",
                format!("net {} has more than one route", route.net_id),
                vec![route.net_id],
            );
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
            if segment.start == segment.end
                || segment.width_nm <= 0
                || !board.copper_layers.contains(&segment.layer)
            {
                report.push(
                    "segment_geometry",
                    "track segment must have distinct endpoints, positive width, and a declared copper layer"
                        .into(),
                    vec![route.net_id],
                );
                continue;
            }
            check_segment(board, route.net_id, segment, &mut report);
        }
        for via in &route.vias {
            let rules = board.rules_for_net(route.net_id);
            if !via_geometry_is_valid(via) {
                report.push(
                    "via_geometry",
                    "via diameter must exceed its positive drill".into(),
                    vec![route.net_id],
                );
                continue;
            }
            let start = board
                .copper_layers
                .iter()
                .position(|layer| *layer == via.start_layer);
            let end = board
                .copper_layers
                .iter()
                .position(|layer| *layer == via.end_layer);
            if !via_layer_range_is_valid(via, start, end) {
                report.push(
                    "via_layers",
                    "via has an invalid layer range for its type".into(),
                    vec![route.net_id],
                );
                continue;
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
        for zone in &route.zones {
            if !zone_geometry_is_valid(board, zone) {
                report.push(
                    "zone_geometry",
                    "zone outline must be a simple non-degenerate polygon on a declared copper layer"
                        .into(),
                    vec![route.net_id],
                );
            }
            if !zone_rule_dimensions_are_valid(zone) {
                report.push(
                    "zone_rules",
                    "zone clearance, thickness, and thermal dimensions must be physically valid"
                        .into(),
                    vec![route.net_id],
                );
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
        PadShape::Custom => custom_pad_contains_hole(pad, width_nm, height_nm),
        _ => endpoints.iter().all(|(x, y)| {
            x.abs() + radius < pad_width_nm / 2.0 && y.abs() + radius < pad_height_nm / 2.0
        }),
    }
}

fn custom_pad_contains_hole(pad: &Pad, width_nm: i64, height_nm: i64) -> bool {
    if pad.custom_polygon.len() < 3 {
        return false;
    }
    let hole = drilled_pad_hole(pad, width_nm, height_nm);
    if !point_in_polygon(hole.start, &pad.custom_polygon)
        || !point_in_polygon(hole.end, &pad.custom_polygon)
    {
        return false;
    }
    pad.custom_polygon
        .iter()
        .copied()
        .zip(pad.custom_polygon.iter().copied().cycle().skip(1))
        .take(pad.custom_polygon.len())
        .all(|(start, end)| !segments_within(hole.start, hole.end, start, end, hole.diameter_nm))
}

fn route_arc_geometry_is_valid(board: &Board, arc: &crate::RouteArc) -> bool {
    arc.width_nm > 0 && board.copper_layers.contains(&arc.layer) && crate::arc_is_valid(arc)
}

fn copper_layer_table_is_valid(board: &Board) -> bool {
    !board.copper_layers.is_empty()
        && board.copper_layers.iter().all(|layer| {
            matches!(
                layer,
                crate::Layer::Front | crate::Layer::Back | crate::Layer::Inner(1..=30)
            )
        })
        && board
            .copper_layers
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            == board.copper_layers.len()
}

fn layer_membership_is_valid(board: &Board, layers: &[crate::Layer]) -> bool {
    !layers.is_empty()
        && layers
            .iter()
            .all(|layer| board.copper_layers.contains(layer))
        && layers.iter().copied().collect::<HashSet<_>>().len() == layers.len()
}

fn keepout_definition_is_valid(keepout: &crate::Keepout) -> bool {
    custom_pad_polygon_is_valid(&keepout.polygon)
        && (keepout.tracks_not_allowed
            || keepout.vias_not_allowed
            || keepout.zones_not_allowed
            || keepout.footprints_not_allowed
            || keepout.minimum_track_width_nm.is_some()
            || keepout.minimum_clearance_nm.is_some())
        && keepout.minimum_track_width_nm.is_none_or(|value| value > 0)
        && keepout.minimum_clearance_nm.is_none_or(|value| value >= 0)
}

fn via_geometry_is_valid(via: &crate::Via) -> bool {
    via.drill_nm > 0 && via.diameter_nm > via.drill_nm
}

fn via_layer_range_is_valid(via: &crate::Via, start: Option<usize>, end: Option<usize>) -> bool {
    start.is_some()
        && end.is_some()
        && start != end
        && (via.kind != crate::ViaKind::Micro
            || start.zip(end).is_some_and(|(a, b)| a.abs_diff(b) == 1))
}

fn teardrop_geometry_is_valid(board: &Board, teardrop: &crate::Teardrop) -> bool {
    board.copper_layers.contains(&teardrop.layer) && custom_pad_polygon_is_valid(&teardrop.polygon)
}

fn zone_fill_geometry_is_valid(board: &Board, layer: crate::Layer, polygon: &[Point]) -> bool {
    board.copper_layers.contains(&layer) && custom_pad_polygon_is_valid(polygon)
}

fn zone_geometry_is_valid(board: &Board, zone: &crate::CopperZone) -> bool {
    board.copper_layers.contains(&zone.layer) && custom_pad_polygon_is_valid(&zone.polygon)
}

fn zone_rule_dimensions_are_valid(zone: &crate::CopperZone) -> bool {
    zone.clearance_nm >= 0
        && zone.minimum_thickness_nm > 0
        && zone.thermal_gap_nm >= 0
        && zone.thermal_spoke_width_nm >= 0
        && (!zone.thermal_relief || zone.thermal_spoke_width_nm > 0)
}

fn custom_pad_polygon_is_valid(polygon: &[Point]) -> bool {
    if polygon.len() < 3 {
        return false;
    }
    let edges: Vec<_> = polygon
        .iter()
        .copied()
        .zip(polygon.iter().copied().cycle().skip(1))
        .take(polygon.len())
        .collect();
    if edges.iter().any(|(start, end)| start == end) {
        return false;
    }

    let mut signed_area_twice = 0_i128;
    for (start, end) in &edges {
        let cross = i128::from(start.x_nm) * i128::from(end.y_nm)
            - i128::from(end.x_nm) * i128::from(start.y_nm);
        let Some(area) = signed_area_twice.checked_add(cross) else {
            return false;
        };
        signed_area_twice = area;
    }
    if signed_area_twice == 0 {
        return false;
    }

    for first in 0..edges.len() {
        for second in (first + 1)..edges.len() {
            if second == first + 1 || (first == 0 && second == edges.len() - 1) {
                continue;
            }
            let (first_start, first_end) = edges[first];
            let (second_start, second_end) = edges[second];
            if segments_within(first_start, first_end, second_start, second_end, 0) {
                return false;
            }
        }
    }
    true
}

fn pad_geometry_is_valid(pad: &Pad) -> bool {
    if pad.width_nm <= 0 || pad.height_nm <= 0 || !pad.rotation_deg.is_finite() {
        return false;
    }
    match pad.shape {
        PadShape::RoundRect => {
            let width_nm = if pad.source_width_nm > 0 {
                pad.source_width_nm
            } else {
                pad.width_nm
            };
            let height_nm = if pad.source_height_nm > 0 {
                pad.source_height_nm
            } else {
                pad.height_nm
            };
            pad.roundrect_radius_nm >= 0
                && i128::from(pad.roundrect_radius_nm) * 2 <= i128::from(width_nm.min(height_nm))
        }
        PadShape::Trapezoid => {
            pad.source_width_nm > 0
                && pad.source_height_nm > 0
                && i128::from(pad.trapezoid_delta_x_nm).abs() < i128::from(pad.source_width_nm)
                && i128::from(pad.trapezoid_delta_y_nm).abs() < i128::from(pad.source_height_nm)
        }
        PadShape::Custom => custom_pad_polygon_is_valid(&pad.custom_polygon),
        _ => true,
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

    #[test]
    fn custom_pad_hole_containment_respects_polygon_edges() {
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
            shape: PadShape::Custom,
            custom_polygon: vec![
                Point {
                    x_nm: 4_000_000,
                    y_nm: 4_500_000,
                },
                Point {
                    x_nm: 6_000_000,
                    y_nm: 4_500_000,
                },
                Point {
                    x_nm: 5_000_000,
                    y_nm: 5_500_000,
                },
            ],
            roundrect_radius_nm: 0,
            trapezoid_delta_x_nm: 0,
            trapezoid_delta_y_nm: 0,
            drill_width_nm: Some(200_000),
            drill_height_nm: Some(200_000),
            drill_offset_x_nm: 700_000,
            drill_offset_y_nm: 200_000,
            plated: true,
            layers: vec![Layer::Front, Layer::Back],
            net_id: Some(1),
        };

        assert!(!drill_fits_pad(&pad, 200_000, 200_000));
    }

    #[test]
    fn normal_check_rejects_invalid_custom_pad_topology() {
        let mut board = base();
        let pad = |number: &str, custom_polygon: Vec<Point>| Pad {
            number: number.into(),
            position: Point { x_nm: 0, y_nm: 0 },
            width_nm: 2_000_000,
            height_nm: 2_000_000,
            source_width_nm: 2_000_000,
            source_height_nm: 2_000_000,
            rotation_deg: 0.0,
            shape: PadShape::Custom,
            custom_polygon,
            roundrect_radius_nm: 0,
            trapezoid_delta_x_nm: 0,
            trapezoid_delta_y_nm: 0,
            drill_width_nm: None,
            drill_height_nm: None,
            drill_offset_x_nm: 0,
            drill_offset_y_nm: 0,
            plated: false,
            layers: vec![Layer::Front],
            net_id: None,
        };
        board.footprints.push(crate::Footprint {
            reference: "U1".into(),
            position: Point { x_nm: 0, y_nm: 0 },
            rotation_deg: 0.0,
            pads: vec![
                pad(
                    "1",
                    vec![
                        Point { x_nm: 0, y_nm: 0 },
                        Point {
                            x_nm: 1_000_000,
                            y_nm: 0,
                        },
                    ],
                ),
                pad(
                    "2",
                    vec![
                        Point { x_nm: 0, y_nm: 0 },
                        Point {
                            x_nm: 1_000_000,
                            y_nm: 0,
                        },
                        Point {
                            x_nm: 2_000_000,
                            y_nm: 0,
                        },
                    ],
                ),
                pad(
                    "3",
                    vec![
                        Point { x_nm: 0, y_nm: 0 },
                        Point {
                            x_nm: 1_000_000,
                            y_nm: 1_000_000,
                        },
                        Point {
                            x_nm: 0,
                            y_nm: 1_000_000,
                        },
                        Point {
                            x_nm: 1_000_000,
                            y_nm: 0,
                        },
                    ],
                ),
            ],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "pad_geometry")
                .count(),
            3
        );
    }

    #[test]
    fn normal_check_rejects_invalid_base_pad_geometry() {
        let mut board = base();
        let pad = |number: &str, shape: PadShape| Pad {
            number: number.into(),
            position: Point { x_nm: 0, y_nm: 0 },
            width_nm: 1_000_000,
            height_nm: 1_000_000,
            source_width_nm: 1_000_000,
            source_height_nm: 1_000_000,
            rotation_deg: 0.0,
            shape,
            custom_polygon: vec![],
            roundrect_radius_nm: 0,
            trapezoid_delta_x_nm: 0,
            trapezoid_delta_y_nm: 0,
            drill_width_nm: None,
            drill_height_nm: None,
            drill_offset_x_nm: 0,
            drill_offset_y_nm: 0,
            plated: false,
            layers: vec![Layer::Front],
            net_id: None,
        };
        let mut zero_width = pad("1", PadShape::Rect);
        zero_width.width_nm = 0;
        let mut non_finite_rotation = pad("2", PadShape::Oval);
        non_finite_rotation.rotation_deg = f64::INFINITY;
        let mut invalid_roundrect = pad("3", PadShape::RoundRect);
        invalid_roundrect.roundrect_radius_nm = 600_000;
        let mut invalid_trapezoid = pad("4", PadShape::Trapezoid);
        invalid_trapezoid.trapezoid_delta_x_nm = 1_000_000;
        board.footprints.push(crate::Footprint {
            reference: "U2".into(),
            position: Point { x_nm: 0, y_nm: 0 },
            rotation_deg: 0.0,
            pads: vec![
                zero_width,
                non_finite_rotation,
                invalid_roundrect,
                invalid_trapezoid,
            ],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "pad_geometry")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_invalid_pad_layer_membership() {
        let mut board = base();
        let pad = |number: &str, layers: Vec<Layer>| Pad {
            number: number.into(),
            position: Point { x_nm: 0, y_nm: 0 },
            width_nm: 1_000_000,
            height_nm: 1_000_000,
            source_width_nm: 1_000_000,
            source_height_nm: 1_000_000,
            rotation_deg: 0.0,
            shape: PadShape::Rect,
            custom_polygon: vec![],
            roundrect_radius_nm: 0,
            trapezoid_delta_x_nm: 0,
            trapezoid_delta_y_nm: 0,
            drill_width_nm: None,
            drill_height_nm: None,
            drill_offset_x_nm: 0,
            drill_offset_y_nm: 0,
            plated: false,
            layers,
            net_id: None,
        };
        board.footprints.push(crate::Footprint {
            reference: "U3".into(),
            position: Point { x_nm: 0, y_nm: 0 },
            rotation_deg: 0.0,
            pads: vec![
                pad("1", vec![]),
                pad("2", vec![Layer::Front, Layer::Front]),
                pad("3", vec![Layer::Inner(1)]),
                pad("4", vec![Layer::Front, Layer::Back]),
            ],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "pad_layers")
                .count(),
            3
        );
    }

    #[test]
    fn normal_check_rejects_invalid_obstacle_layer_membership() {
        let mut board = base();
        let point = Point { x_nm: 1, y_nm: 1 };
        board.obstacles.push(crate::Obstacle {
            min: point,
            max: Point { x_nm: 2, y_nm: 2 },
            layers: vec![],
            net_id: None,
        });
        board.round_obstacles.push(RoundObstacle {
            center: point,
            diameter_nm: 1,
            layers: vec![Layer::Front, Layer::Front],
            net_id: None,
        });
        board.capsule_obstacles.push(CapsuleObstacle {
            start: point,
            end: Point { x_nm: 2, y_nm: 2 },
            diameter_nm: 1,
            layers: vec![Layer::Inner(1)],
            net_id: None,
        });
        board.polygon_obstacles.push(crate::PolygonObstacle {
            polygon: vec![
                point,
                Point { x_nm: 2, y_nm: 1 },
                Point { x_nm: 1, y_nm: 2 },
            ],
            layers: vec![Layer::Back],
            net_id: None,
        });
        board.keepouts.push(crate::Keepout {
            polygon: vec![
                point,
                Point { x_nm: 2, y_nm: 1 },
                Point { x_nm: 1, y_nm: 2 },
            ],
            layers: vec![Layer::Inner(2)],
            net_id: None,
            tracks_not_allowed: true,
            vias_not_allowed: true,
            zones_not_allowed: true,
            footprints_not_allowed: false,
            minimum_track_width_nm: None,
            minimum_clearance_nm: None,
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "obstacle_layers")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_invalid_rectangular_obstacle_geometry() {
        let mut board = base();
        let obstacle = |min: Point, max: Point| crate::Obstacle {
            min,
            max,
            layers: vec![Layer::Front],
            net_id: None,
        };
        board.obstacles = vec![
            obstacle(Point { x_nm: 2, y_nm: 1 }, Point { x_nm: 1, y_nm: 2 }),
            obstacle(Point { x_nm: 1, y_nm: 2 }, Point { x_nm: 2, y_nm: 2 }),
            obstacle(Point { x_nm: 1, y_nm: 1 }, Point { x_nm: 2, y_nm: 2 }),
        ];

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "obstacle_geometry")
                .count(),
            2
        );
    }

    #[test]
    fn normal_check_rejects_non_positive_curved_obstacle_diameters() {
        let mut board = base();
        let point = Point { x_nm: 1, y_nm: 1 };
        board.round_obstacles = vec![
            RoundObstacle {
                center: point,
                diameter_nm: 0,
                layers: vec![Layer::Front],
                net_id: None,
            },
            RoundObstacle {
                center: point,
                diameter_nm: 1,
                layers: vec![Layer::Front],
                net_id: None,
            },
        ];
        board.capsule_obstacles = vec![
            CapsuleObstacle {
                start: point,
                end: Point { x_nm: 2, y_nm: 2 },
                diameter_nm: -1,
                layers: vec![Layer::Front],
                net_id: None,
            },
            CapsuleObstacle {
                start: point,
                end: Point { x_nm: 2, y_nm: 2 },
                diameter_nm: 1,
                layers: vec![Layer::Front],
                net_id: None,
            },
        ];

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "obstacle_diameter")
                .count(),
            2
        );
    }

    #[test]
    fn normal_check_rejects_invalid_polygon_obstacle_topology() {
        let mut board = base();
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        let polygon = |points| crate::PolygonObstacle {
            polygon: points,
            layers: vec![Layer::Front],
            net_id: None,
        };
        board.polygon_obstacles = vec![
            polygon(vec![point(1, 1), point(2, 1)]),
            polygon(vec![point(1, 1), point(1, 1), point(2, 2)]),
            polygon(vec![point(1, 1), point(2, 1), point(3, 1)]),
            polygon(vec![point(1, 1), point(3, 3), point(1, 3), point(3, 1)]),
            polygon(vec![point(1, 1), point(3, 1), point(2, 3)]),
        ];

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "polygon_obstacle")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_invalid_keepout_definitions() {
        let mut board = base();
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        let valid_polygon = vec![point(1, 1), point(3, 1), point(2, 3)];
        let keepout = |polygon,
                       tracks_not_allowed,
                       minimum_track_width_nm,
                       minimum_clearance_nm| crate::Keepout {
            polygon,
            layers: vec![Layer::Front],
            net_id: None,
            tracks_not_allowed,
            vias_not_allowed: false,
            zones_not_allowed: false,
            footprints_not_allowed: false,
            minimum_track_width_nm,
            minimum_clearance_nm,
        };
        board.keepouts = vec![
            keepout(valid_polygon[..2].to_vec(), true, None, None),
            keepout(valid_polygon.clone(), false, None, None),
            keepout(valid_polygon.clone(), false, Some(0), None),
            keepout(valid_polygon.clone(), false, None, Some(-1)),
            keepout(valid_polygon, false, Some(1), Some(0)),
        ];

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "keepout_definition")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_unknown_obstacle_net_references() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "declared".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let point = Point { x_nm: 1, y_nm: 1 };
        board.obstacles.extend([
            crate::Obstacle {
                min: point,
                max: Point { x_nm: 2, y_nm: 2 },
                layers: vec![Layer::Front],
                net_id: Some(99),
            },
            crate::Obstacle {
                min: point,
                max: Point { x_nm: 2, y_nm: 2 },
                layers: vec![Layer::Front],
                net_id: Some(1),
            },
        ]);
        board.round_obstacles.push(RoundObstacle {
            center: point,
            diameter_nm: 1,
            layers: vec![Layer::Front],
            net_id: Some(98),
        });
        board.capsule_obstacles.push(CapsuleObstacle {
            start: point,
            end: Point { x_nm: 2, y_nm: 2 },
            diameter_nm: 1,
            layers: vec![Layer::Front],
            net_id: Some(97),
        });
        let polygon = vec![
            point,
            Point { x_nm: 2, y_nm: 1 },
            Point { x_nm: 1, y_nm: 2 },
        ];
        board.polygon_obstacles.push(crate::PolygonObstacle {
            polygon: polygon.clone(),
            layers: vec![Layer::Front],
            net_id: Some(96),
        });
        board.keepouts.push(crate::Keepout {
            polygon,
            layers: vec![Layer::Front],
            net_id: Some(95),
            tracks_not_allowed: true,
            vias_not_allowed: true,
            zones_not_allowed: true,
            footprints_not_allowed: false,
            minimum_track_width_nm: None,
            minimum_clearance_nm: None,
        });

        let report = check_board(&board);
        let invalid_ids: HashSet<_> = report
            .violations
            .iter()
            .filter(|violation| violation.rule == "obstacle_net")
            .flat_map(|violation| violation.net_ids.iter().copied())
            .collect();
        assert_eq!(invalid_ids, HashSet::from([95, 96, 97, 98, 99]));
    }

    #[test]
    fn normal_check_rejects_unknown_pad_net_references() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let pad = |number: &str, net_id: Option<u32>| Pad {
            number: number.into(),
            position: Point { x_nm: 0, y_nm: 0 },
            width_nm: 1_000_000,
            height_nm: 1_000_000,
            source_width_nm: 1_000_000,
            source_height_nm: 1_000_000,
            rotation_deg: 0.0,
            shape: PadShape::Rect,
            custom_polygon: vec![],
            roundrect_radius_nm: 0,
            trapezoid_delta_x_nm: 0,
            trapezoid_delta_y_nm: 0,
            drill_width_nm: None,
            drill_height_nm: None,
            drill_offset_x_nm: 0,
            drill_offset_y_nm: 0,
            plated: false,
            layers: vec![Layer::Front],
            net_id,
        };
        board.footprints.push(crate::Footprint {
            reference: "U4".into(),
            position: Point { x_nm: 0, y_nm: 0 },
            rotation_deg: 0.0,
            pads: vec![pad("1", None), pad("2", Some(1)), pad("3", Some(99))],
        });

        let report = check_board(&board);
        let violations: Vec<_> = report
            .violations
            .iter()
            .filter(|violation| violation.rule == "pad_net")
            .collect();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].net_ids, vec![99]);
    }

    #[test]
    fn normal_check_rejects_invalid_net_table_identities() {
        let mut board = base();
        let net = |id, name: &str| Net {
            id,
            name: name.into(),
            terminals: vec![],
            class: None,
            priority: 0,
        };
        board.nets = vec![
            net(1, "signal"),
            net(0, "ground"),
            net(2, " "),
            net(1, "other"),
            net(3, "signal"),
        ];

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "net_table")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_invalid_terminal_layer_membership() {
        let mut board = base();
        let terminal = |layers| Terminal {
            position: Point { x_nm: 1, y_nm: 1 },
            layers,
        };
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![
                terminal(vec![]),
                terminal(vec![Layer::Front, Layer::Front]),
                terminal(vec![Layer::Inner(1)]),
                terminal(vec![Layer::Front, Layer::Back]),
            ],
            class: None,
            priority: 0,
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "terminal_layers")
                .count(),
            3
        );
    }

    #[test]
    fn normal_check_rejects_unknown_net_class_references() {
        let mut board = base();
        board.net_classes.insert(
            "declared".into(),
            crate::NetClassRules {
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                layers: None,
                differential_width_nm: None,
                differential_gap_nm: None,
                minimum_length_nm: None,
                maximum_length_nm: None,
                target_impedance_ohms: None,
                impedance_tolerance_ohms: None,
                maximum_impedance_step_ohms: None,
            },
        );
        let net = |id, class: Option<&str>| Net {
            id,
            name: format!("N{id}"),
            terminals: vec![],
            class: class.map(str::to_owned),
            priority: 0,
        };
        board.nets = vec![
            net(1, None),
            net(2, Some("declared")),
            net(3, Some("missing")),
        ];

        let report = check_board(&board);
        let violations = report
            .violations
            .iter()
            .filter(|violation| violation.rule == "net_class")
            .collect::<Vec<_>>();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].net_ids, vec![3]);
    }

    #[test]
    fn normal_check_rejects_unknown_route_net_references() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let route = |net_id| Route {
            net_id,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        };
        board.routes = vec![route(1), route(99)];

        let report = check_board(&board);
        let violations: Vec<_> = report
            .violations
            .iter()
            .filter(|violation| violation.rule == "route_net")
            .collect();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].net_ids, vec![99]);
    }

    #[test]
    fn normal_check_rejects_duplicate_routes_for_one_net() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let route = || Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        };
        board.routes = vec![route(), route()];

        let report = check_board(&board);
        let violations: Vec<_> = report
            .violations
            .iter()
            .filter(|violation| violation.rule == "duplicate_route")
            .collect();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].net_ids, vec![1]);
    }

    #[test]
    fn normal_check_rejects_invalid_segment_geometry() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let segment = |start: Point, end: Point, layer: Layer, width_nm| Segment {
            start,
            end,
            layer,
            width_nm,
        };
        let start = Point {
            x_nm: 1_000_000,
            y_nm: 1_000_000,
        };
        let end = Point {
            x_nm: 2_000_000,
            y_nm: 1_000_000,
        };
        board.routes.push(Route {
            net_id: 1,
            segments: vec![
                segment(start, start, Layer::Front, 250_000),
                segment(start, end, Layer::Front, 0),
                segment(start, end, Layer::Inner(1), 250_000),
                segment(start, end, Layer::Front, 250_000),
            ],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "segment_geometry")
                .count(),
            3
        );
    }

    #[test]
    fn normal_check_rejects_invalid_arc_geometry_before_linearization() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        let arc = |start, mid, end, layer, width_nm| crate::RouteArc {
            start,
            mid,
            end,
            layer,
            width_nm,
        };
        let start = point(1_000_000, 2_000_000);
        let mid = point(2_000_000, 1_000_000);
        let end = point(3_000_000, 2_000_000);
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![
                arc(start, mid, end, Layer::Front, 0),
                arc(start, mid, end, Layer::Inner(1), 250_000),
                arc(start, start, end, Layer::Front, 250_000),
                arc(
                    start,
                    point(2_000_000, 2_000_000),
                    end,
                    Layer::Front,
                    250_000,
                ),
                arc(start, mid, end, Layer::Front, 250_000),
            ],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "arc_geometry")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_invalid_via_geometry_before_derived_checks() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let via = |diameter_nm, drill_nm| Via {
            position: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            diameter_nm,
            drill_nm,
            kind: crate::ViaKind::Through,
            start_layer: Layer::Front,
            end_layer: Layer::Back,
        };
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![
                via(0, 0),
                via(600_000, 0),
                via(300_000, 300_000),
                via(300_000, 400_000),
                via(600_000, 300_000),
            ],
            teardrops: vec![],
            zones: vec![],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "via_geometry")
                .count(),
            4
        );
        assert!(
            !report
                .violations
                .iter()
                .any(|violation| violation.rule == "via_size")
        );
    }

    #[test]
    fn normal_check_rejects_invalid_via_layer_ranges_before_derived_checks() {
        let mut board = base();
        board.copper_layers = vec![Layer::Front, Layer::Inner(1), Layer::Back];
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let via = |kind, start_layer, end_layer| Via {
            position: Point {
                x_nm: 5_000_000,
                y_nm: 5_000_000,
            },
            diameter_nm: 600_000,
            drill_nm: 300_000,
            kind,
            start_layer,
            end_layer,
        };
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![
                via(crate::ViaKind::Through, Layer::Inner(2), Layer::Back),
                via(crate::ViaKind::Through, Layer::Front, Layer::Front),
                via(crate::ViaKind::Micro, Layer::Front, Layer::Back),
                via(crate::ViaKind::Micro, Layer::Front, Layer::Inner(1)),
                via(crate::ViaKind::Through, Layer::Front, Layer::Back),
            ],
            teardrops: vec![],
            zones: vec![],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "via_layers")
                .count(),
            3
        );
    }

    #[test]
    fn normal_check_rejects_invalid_teardrop_geometry_before_obstacle_conversion() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "signal".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        let teardrop = |polygon, layer| crate::Teardrop { polygon, layer };
        let valid = vec![
            point(1_000_000, 1_000_000),
            point(2_000_000, 1_000_000),
            point(1_500_000, 2_000_000),
        ];
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![
                teardrop(valid[..2].to_vec(), Layer::Front),
                teardrop(vec![valid[0], valid[0], valid[2]], Layer::Front),
                teardrop(
                    vec![
                        point(1_000_000, 1_000_000),
                        point(2_000_000, 1_000_000),
                        point(3_000_000, 1_000_000),
                    ],
                    Layer::Front,
                ),
                teardrop(valid.clone(), Layer::Inner(1)),
                teardrop(valid, Layer::Front),
            ],
            zones: vec![],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "teardrop_geometry")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_invalid_zone_fill_geometry_before_obstacle_conversion() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "ground".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        let valid = vec![
            point(1_000_000, 1_000_000),
            point(2_000_000, 1_000_000),
            point(1_500_000, 2_000_000),
        ];
        let zone = |layer, filled_polygons| crate::CopperZone {
            polygon: valid.clone(),
            layer,
            clearance_nm: 200_000,
            minimum_thickness_nm: 250_000,
            thermal_relief: true,
            thermal_gap_nm: 200_000,
            thermal_spoke_width_nm: 250_000,
            filled_polygons,
        };
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![
                zone(
                    Layer::Front,
                    vec![
                        valid[..2].to_vec(),
                        vec![valid[0], valid[0], valid[2]],
                        vec![
                            point(1_000_000, 1_000_000),
                            point(2_000_000, 1_000_000),
                            point(3_000_000, 1_000_000),
                        ],
                        valid.clone(),
                    ],
                ),
                zone(Layer::Inner(1), vec![valid.clone()]),
            ],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "zone_fill_geometry")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_invalid_zone_outlines() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "ground".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        let valid = vec![
            point(1_000_000, 1_000_000),
            point(2_000_000, 1_000_000),
            point(1_500_000, 2_000_000),
        ];
        let zone = |polygon, layer| crate::CopperZone {
            polygon,
            layer,
            clearance_nm: 200_000,
            minimum_thickness_nm: 250_000,
            thermal_relief: true,
            thermal_gap_nm: 200_000,
            thermal_spoke_width_nm: 250_000,
            filled_polygons: vec![],
        };
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![
                zone(valid[..2].to_vec(), Layer::Front),
                zone(vec![valid[0], valid[0], valid[2]], Layer::Front),
                zone(
                    vec![
                        point(1_000_000, 1_000_000),
                        point(2_000_000, 1_000_000),
                        point(3_000_000, 1_000_000),
                    ],
                    Layer::Front,
                ),
                zone(valid.clone(), Layer::Inner(1)),
                zone(valid, Layer::Front),
            ],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "zone_geometry")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_invalid_zone_rule_dimensions() {
        let mut board = base();
        board.nets.push(Net {
            id: 1,
            name: "ground".into(),
            terminals: vec![],
            class: None,
            priority: 0,
        });
        let polygon = vec![
            Point {
                x_nm: 1_000_000,
                y_nm: 1_000_000,
            },
            Point {
                x_nm: 2_000_000,
                y_nm: 1_000_000,
            },
            Point {
                x_nm: 1_500_000,
                y_nm: 2_000_000,
            },
        ];
        let zone = |clearance_nm,
                    minimum_thickness_nm,
                    thermal_relief,
                    thermal_gap_nm,
                    thermal_spoke_width_nm| crate::CopperZone {
            polygon: polygon.clone(),
            layer: Layer::Front,
            clearance_nm,
            minimum_thickness_nm,
            thermal_relief,
            thermal_gap_nm,
            thermal_spoke_width_nm,
            filled_polygons: vec![],
        };
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![
                zone(-1, 250_000, true, 200_000, 250_000),
                zone(200_000, 0, true, 200_000, 250_000),
                zone(200_000, 250_000, true, -1, 250_000),
                zone(200_000, 250_000, true, 200_000, 0),
                zone(200_000, 250_000, false, 0, 0),
                zone(200_000, 250_000, true, 200_000, 250_000),
            ],
        });

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "zone_rules")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_non_positive_board_dimensions() {
        let mut zero_width = base();
        zero_width.width_nm = 0;
        let mut negative_height = base();
        negative_height.height_nm = -1;
        let valid = base();

        for board in [&zero_width, &negative_height] {
            let report = check_board(board);
            assert_eq!(
                report
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "board_dimensions")
                    .count(),
                1
            );
        }
        assert!(
            !check_board(&valid)
                .violations
                .iter()
                .any(|violation| violation.rule == "board_dimensions")
        );
    }

    #[test]
    fn normal_check_rejects_non_positive_routing_grids() {
        let mut zero = base();
        zero.rules.grid_nm = 0;
        let mut negative = base();
        negative.rules.grid_nm = -1;
        let valid = base();

        for board in [&zero, &negative] {
            let report = check_board(board);
            assert_eq!(
                report
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "routing_grid")
                    .count(),
                1
            );
        }
        assert!(
            !check_board(&valid)
                .violations
                .iter()
                .any(|violation| violation.rule == "routing_grid")
        );
    }

    #[test]
    fn normal_check_rejects_invalid_base_routing_rules() {
        let mut zero_width = base();
        zero_width.rules.track_width_nm = 0;
        let mut negative_clearance = base();
        negative_clearance.rules.clearance_nm = -1;
        let mut zero_drill = base();
        zero_drill.rules.via_drill_nm = 0;
        let mut equal_via_dimensions = base();
        equal_via_dimensions.rules.via_diameter_nm = equal_via_dimensions.rules.via_drill_nm;
        let valid = base();

        for board in [
            &zero_width,
            &negative_clearance,
            &zero_drill,
            &equal_via_dimensions,
        ] {
            let report = check_board(board);
            assert_eq!(
                report
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "routing_rules")
                    .count(),
                1
            );
        }
        assert!(
            !check_board(&valid)
                .violations
                .iter()
                .any(|violation| violation.rule == "routing_rules")
        );
    }

    #[test]
    fn normal_check_rejects_invalid_net_class_dimensions() {
        let class = || crate::NetClassRules {
            track_width_nm: 250_000,
            clearance_nm: 200_000,
            via_diameter_nm: 600_000,
            via_drill_nm: 300_000,
            layers: None,
            differential_width_nm: None,
            differential_gap_nm: None,
            minimum_length_nm: None,
            maximum_length_nm: None,
            target_impedance_ohms: None,
            impedance_tolerance_ohms: None,
            maximum_impedance_step_ohms: None,
        };
        let with_class = |name: &str, rules| {
            let mut board = base();
            board.net_classes.insert(name.into(), rules);
            board
        };
        let mut zero_width = class();
        zero_width.track_width_nm = 0;
        let mut negative_clearance = class();
        negative_clearance.clearance_nm = -1;
        let mut zero_drill = class();
        zero_drill.via_drill_nm = 0;
        let mut equal_via_dimensions = class();
        equal_via_dimensions.via_diameter_nm = equal_via_dimensions.via_drill_nm;

        for board in [
            with_class("zero-width", zero_width),
            with_class("negative-clearance", negative_clearance),
            with_class("zero-drill", zero_drill),
            with_class("equal-via-dimensions", equal_via_dimensions),
        ] {
            assert_eq!(
                check_board(&board)
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "net_class_dimensions")
                    .count(),
                1
            );
        }
        assert!(
            !check_board(&with_class("valid", class()))
                .violations
                .iter()
                .any(|violation| violation.rule == "net_class_dimensions")
        );
    }

    #[test]
    fn normal_check_rejects_invalid_net_class_layer_membership() {
        let with_layers = |name: &str, layers| {
            let mut board = base();
            board.net_classes.insert(
                name.into(),
                crate::NetClassRules {
                    track_width_nm: 250_000,
                    clearance_nm: 200_000,
                    via_diameter_nm: 600_000,
                    via_drill_nm: 300_000,
                    layers,
                    differential_width_nm: None,
                    differential_gap_nm: None,
                    minimum_length_nm: None,
                    maximum_length_nm: None,
                    target_impedance_ohms: None,
                    impedance_tolerance_ohms: None,
                    maximum_impedance_step_ohms: None,
                },
            );
            board
        };

        for board in [
            with_layers("empty", Some(vec![])),
            with_layers("duplicate", Some(vec![Layer::Front, Layer::Front])),
            with_layers("unknown", Some(vec![Layer::Inner(1)])),
        ] {
            assert_eq!(
                check_board(&board)
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "net_class_layers")
                    .count(),
                1
            );
        }
        for board in [
            with_layers("unrestricted", None),
            with_layers("multilayer", Some(vec![Layer::Front, Layer::Back])),
        ] {
            assert!(
                !check_board(&board)
                    .violations
                    .iter()
                    .any(|violation| violation.rule == "net_class_layers")
            );
        }
    }

    #[test]
    fn normal_check_rejects_invalid_net_class_length_limits() {
        let with_limits = |name: &str, minimum_length_nm, maximum_length_nm| {
            let mut board = base();
            board.net_classes.insert(
                name.into(),
                crate::NetClassRules {
                    track_width_nm: 250_000,
                    clearance_nm: 200_000,
                    via_diameter_nm: 600_000,
                    via_drill_nm: 300_000,
                    layers: None,
                    differential_width_nm: None,
                    differential_gap_nm: None,
                    minimum_length_nm,
                    maximum_length_nm,
                    target_impedance_ohms: None,
                    impedance_tolerance_ohms: None,
                    maximum_impedance_step_ohms: None,
                },
            );
            board
        };

        for board in [
            with_limits("zero-minimum", Some(0), None),
            with_limits("negative-maximum", None, Some(-1)),
            with_limits("reversed", Some(2_000_000), Some(1_000_000)),
        ] {
            assert_eq!(
                check_board(&board)
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "net_class_length_limits")
                    .count(),
                1
            );
        }
        for board in [
            with_limits("unbounded", None, None),
            with_limits("minimum-only", Some(1), None),
            with_limits("maximum-only", None, Some(1)),
            with_limits("bounded", Some(1), Some(2)),
        ] {
            assert!(
                !check_board(&board)
                    .violations
                    .iter()
                    .any(|violation| violation.rule == "net_class_length_limits")
            );
        }
    }

    #[test]
    fn normal_check_rejects_invalid_net_class_impedance_limits() {
        let with_impedance = |name: &str, target, tolerance, maximum_step| {
            let mut board = base();
            board.net_classes.insert(
                name.into(),
                crate::NetClassRules {
                    track_width_nm: 250_000,
                    clearance_nm: 200_000,
                    via_diameter_nm: 600_000,
                    via_drill_nm: 300_000,
                    layers: None,
                    differential_width_nm: None,
                    differential_gap_nm: None,
                    minimum_length_nm: None,
                    maximum_length_nm: None,
                    target_impedance_ohms: target,
                    impedance_tolerance_ohms: tolerance,
                    maximum_impedance_step_ohms: maximum_step,
                },
            );
            board
        };

        for board in [
            with_impedance("target-only", Some(50.0), None, None),
            with_impedance("tolerance-only", None, Some(5.0), None),
            with_impedance("zero-target", Some(0.0), Some(5.0), None),
            with_impedance("nan-target", Some(f64::NAN), Some(5.0), None),
            with_impedance("infinite-tolerance", Some(50.0), Some(f64::INFINITY), None),
            with_impedance("negative-tolerance", Some(50.0), Some(-1.0), None),
            with_impedance("negative-step", None, None, Some(-1.0)),
            with_impedance("nan-step", None, None, Some(f64::NAN)),
        ] {
            assert_eq!(
                check_board(&board)
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "net_class_impedance_limits")
                    .count(),
                1
            );
        }
        for board in [
            with_impedance("unrestricted", None, None, None),
            with_impedance("target", Some(50.0), Some(0.0), None),
            with_impedance("step", None, None, Some(0.0)),
            with_impedance("all", Some(90.0), Some(9.0), Some(4.0)),
        ] {
            assert!(
                !check_board(&board)
                    .violations
                    .iter()
                    .any(|violation| violation.rule == "net_class_impedance_limits")
            );
        }
    }

    #[test]
    fn normal_check_rejects_invalid_net_class_differential_dimensions() {
        let with_dimensions = |name: &str, differential_width_nm, differential_gap_nm| {
            let mut board = base();
            board.net_classes.insert(
                name.into(),
                crate::NetClassRules {
                    track_width_nm: 250_000,
                    clearance_nm: 200_000,
                    via_diameter_nm: 600_000,
                    via_drill_nm: 300_000,
                    layers: None,
                    differential_width_nm,
                    differential_gap_nm,
                    minimum_length_nm: None,
                    maximum_length_nm: None,
                    target_impedance_ohms: None,
                    impedance_tolerance_ohms: None,
                    maximum_impedance_step_ohms: None,
                },
            );
            board
        };

        for board in [
            with_dimensions("zero-width", Some(0), None),
            with_dimensions("negative-width", Some(-1), None),
            with_dimensions("negative-gap", None, Some(-1)),
        ] {
            assert_eq!(
                check_board(&board)
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "net_class_differential_dimensions")
                    .count(),
                1
            );
        }
        for board in [
            with_dimensions("unset", None, None),
            with_dimensions("zero-gap", None, Some(0)),
            with_dimensions("configured", Some(200_000), Some(150_000)),
        ] {
            assert!(
                !check_board(&board)
                    .violations
                    .iter()
                    .any(|violation| violation.rule == "net_class_differential_dimensions")
            );
        }
    }

    #[test]
    fn normal_check_rejects_blank_net_class_names() {
        let with_name = |name: &str| {
            let mut board = base();
            board.net_classes.insert(
                name.into(),
                crate::NetClassRules {
                    track_width_nm: 250_000,
                    clearance_nm: 200_000,
                    via_diameter_nm: 600_000,
                    via_drill_nm: 300_000,
                    layers: None,
                    differential_width_nm: None,
                    differential_gap_nm: None,
                    minimum_length_nm: None,
                    maximum_length_nm: None,
                    target_impedance_ohms: None,
                    impedance_tolerance_ohms: None,
                    maximum_impedance_step_ohms: None,
                },
            );
            board
        };

        for board in [with_name(""), with_name(" \t")] {
            assert_eq!(
                check_board(&board)
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "net_class_name")
                    .count(),
                1
            );
        }
        assert!(
            !check_board(&with_name("signals"))
                .violations
                .iter()
                .any(|violation| violation.rule == "net_class_name")
        );
    }

    #[test]
    fn normal_check_rejects_invalid_copper_layer_tables() {
        let mut empty = base();
        empty.copper_layers.clear();
        let mut duplicate = base();
        duplicate.copper_layers.push(Layer::Front);
        let mut unsupported = base();
        unsupported.copper_layers = vec![Layer::Front, Layer::Inner(31), Layer::Back];
        let valid = base();

        for board in [&empty, &duplicate, &unsupported] {
            let report = check_board(board);
            assert_eq!(
                report
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "copper_layers")
                    .count(),
                1
            );
        }
        assert!(
            !check_board(&valid)
                .violations
                .iter()
                .any(|violation| violation.rule == "copper_layers")
        );
    }

    #[test]
    fn normal_check_rejects_invalid_explicit_board_outlines() {
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        let valid_outline = vec![
            point(0, 0),
            point(10_000_000, 0),
            point(10_000_000, 10_000_000),
            point(0, 10_000_000),
        ];
        let outlines = vec![
            valid_outline[..2].to_vec(),
            vec![valid_outline[0], valid_outline[0], valid_outline[2]],
            vec![point(0, 0), point(1_000_000, 0), point(2_000_000, 0)],
            vec![
                point(0, 0),
                point(10_000_000, 10_000_000),
                point(0, 10_000_000),
                point(10_000_000, 0),
            ],
        ];

        for outline in outlines {
            let mut board = base();
            board.outline = outline;
            let report = check_board(&board);
            assert_eq!(
                report
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "board_outline")
                    .count(),
                1
            );
        }
        let mut explicit = base();
        explicit.outline = valid_outline;
        for board in [base(), explicit] {
            assert!(
                !check_board(&board)
                    .violations
                    .iter()
                    .any(|violation| violation.rule == "board_outline")
            );
        }
    }

    #[test]
    fn normal_check_rejects_invalid_board_cutout_topology() {
        let mut board = base();
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        let valid = vec![
            point(2_000_000, 2_000_000),
            point(4_000_000, 2_000_000),
            point(4_000_000, 4_000_000),
            point(2_000_000, 4_000_000),
        ];
        board.cutouts = vec![
            valid[..2].to_vec(),
            vec![valid[0], valid[0], valid[2]],
            vec![
                point(2_000_000, 2_000_000),
                point(3_000_000, 2_000_000),
                point(4_000_000, 2_000_000),
            ],
            vec![
                point(2_000_000, 2_000_000),
                point(4_000_000, 4_000_000),
                point(2_000_000, 4_000_000),
                point(4_000_000, 2_000_000),
            ],
            valid,
        ];

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "board_cutout")
                .count(),
            4
        );
    }

    #[test]
    fn normal_check_rejects_board_cutouts_outside_the_outline() {
        let mut board = base();
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        board.cutouts = vec![
            vec![
                point(2_000_000, 2_000_000),
                point(4_000_000, 2_000_000),
                point(4_000_000, 4_000_000),
                point(2_000_000, 4_000_000),
            ],
            vec![
                point(9_000_000, 2_000_000),
                point(11_000_000, 2_000_000),
                point(11_000_000, 4_000_000),
                point(9_000_000, 4_000_000),
            ],
        ];

        let report = check_board(&board);
        assert_eq!(
            report
                .violations
                .iter()
                .filter(|violation| violation.rule == "board_cutout_bounds")
                .count(),
            1
        );
    }

    #[test]
    fn normal_check_rejects_explicit_board_outlines_outside_dimensions() {
        let point = |x_nm, y_nm| Point { x_nm, y_nm };
        let outline = |minimum, maximum| {
            vec![
                point(minimum, minimum),
                point(maximum, minimum),
                point(maximum, maximum),
                point(minimum, maximum),
            ]
        };
        let mut negative = base();
        negative.outline = outline(-1, 9_000_000);
        let mut oversized = base();
        oversized.outline = outline(1_000_000, 10_000_001);
        let mut valid = base();
        valid.outline = outline(0, 10_000_000);

        for board in [&negative, &oversized] {
            let report = check_board(board);
            assert_eq!(
                report
                    .violations
                    .iter()
                    .filter(|violation| violation.rule == "board_outline_bounds")
                    .count(),
                1
            );
        }
        assert!(
            !check_board(&valid)
                .violations
                .iter()
                .any(|violation| violation.rule == "board_outline_bounds")
        );
    }
}

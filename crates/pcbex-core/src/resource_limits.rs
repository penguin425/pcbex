//! Fail-closed resource limits for routing and geometric validation.
//!
//! The router performs a number of raster and polygon operations whose cost is
//! proportional to the board dimensions or to the number of polygon edges.  A
//! malformed board must be rejected before any of those operations can allocate
//! or enter an unbounded loop.  This module intentionally does not try to
//! validate electrical or geometric semantics; those remain the responsibility
//! of the normal router/checker validation paths.

use crate::{Board, CopperZone, Nm, Point};

/// Maximum supported board dimension and absolute board-space coordinate.
pub const MAX_BOARD_EXTENT_NM: Nm = 1_000_000_000;
/// Alias for callers that want to state the coordinate part of the bound.
pub const MAX_BOARD_ABSOLUTE_COORDINATE_NM: Nm = MAX_BOARD_EXTENT_NM;
/// Maximum number of cells in one board plane.
pub const MAX_PLANE_GRID_CELLS: usize = 1_000_000;
/// Maximum number of plane-cell/layer slots.
pub const MAX_CELL_LAYER_SLOTS: usize = 2_000_000;
/// Maximum cumulative number of raster candidate visits.
pub const MAX_RASTER_CANDIDATE_VISITS: usize = 10_000_000;
/// Maximum clearance/inflation radius measured in grid cells.
pub const MAX_INFLATE_RADIUS_CELLS: usize = 128;
/// Maximum number of vertices in one polygon.
pub const MAX_POLYGON_VERTICES: usize = 4_096;
/// Maximum number of polygon vertices in a board.
pub const MAX_TOTAL_POLYGON_VERTICES: usize = 65_536;
/// Maximum candidate cells considered while filling all copper zones.
pub const MAX_ZONE_CANDIDATE_CELLS: usize = 524_288;
/// Maximum cells returned by one rasterized line.
pub const MAX_RASTER_LINE_CELLS: usize = 1_000_000;
/// Maximum pairwise edge work allowed by topology checks.
pub const MAX_TOPOLOGY_EDGE_PAIR_WORK: usize = 8_500_000;
/// Maximum cumulative polygon-edge predicate work during rasterization.
///
/// The unit is one edge visit (one candidate point tested against one polygon
/// edge).  It covers board-boundary/cutout checks and polygon obstacle/track
/// keepout checks; constant-cost rectangle/round/capsule predicates remain in
/// [`MAX_RASTER_CANDIDATE_VISITS`].
pub const MAX_RASTER_GEOMETRY_EDGE_WORK: usize = 50_000_000;
/// Maximum cumulative per-cell blocker work while filling copper zones.
///
/// The unit is one conservative blocker/predicate operation.  Polygon edge
/// tests are expanded to their individual edge visits, while constant-cost
/// blocker checks contribute one operation per inspected item/corner.
pub const MAX_ZONE_BLOCKER_WORK: usize = 50_000_000;

/// Injectable limits used by [`validate_routing_resource_bounds_with_limits`].
///
/// Keeping the limits in a plain copyable value makes exact and +1 boundary
/// tests cheap without weakening the production ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingResourceLimits {
    pub max_board_extent_nm: Nm,
    pub max_plane_grid_cells: usize,
    pub max_cell_layer_slots: usize,
    pub max_raster_candidate_visits: usize,
    pub max_inflate_radius_cells: usize,
    pub max_polygon_vertices: usize,
    pub max_total_polygon_vertices: usize,
    pub max_zone_candidate_cells: usize,
    pub max_raster_line_cells: usize,
    pub max_topology_edge_pair_work: usize,
    pub max_raster_geometry_edge_work: usize,
    pub max_zone_blocker_work: usize,
}

impl RoutingResourceLimits {
    pub const PRODUCTION: Self = Self {
        max_board_extent_nm: MAX_BOARD_EXTENT_NM,
        max_plane_grid_cells: MAX_PLANE_GRID_CELLS,
        max_cell_layer_slots: MAX_CELL_LAYER_SLOTS,
        max_raster_candidate_visits: MAX_RASTER_CANDIDATE_VISITS,
        max_inflate_radius_cells: MAX_INFLATE_RADIUS_CELLS,
        max_polygon_vertices: MAX_POLYGON_VERTICES,
        max_total_polygon_vertices: MAX_TOTAL_POLYGON_VERTICES,
        max_zone_candidate_cells: MAX_ZONE_CANDIDATE_CELLS,
        max_raster_line_cells: MAX_RASTER_LINE_CELLS,
        max_topology_edge_pair_work: MAX_TOPOLOGY_EDGE_PAIR_WORK,
        max_raster_geometry_edge_work: MAX_RASTER_GEOMETRY_EDGE_WORK,
        max_zone_blocker_work: MAX_ZONE_BLOCKER_WORK,
    };
}

impl Default for RoutingResourceLimits {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// Validate a board against the production routing resource ceilings.
pub fn validate_routing_resource_bounds(board: &Board) -> Result<(), String> {
    validate_routing_resource_bounds_with_limits(board, RoutingResourceLimits::PRODUCTION)
}

/// Validate a board against caller-provided resource ceilings.
pub fn validate_routing_resource_bounds_with_limits(
    board: &Board,
    limits: RoutingResourceLimits,
) -> Result<(), String> {
    validate_limit_configuration(&limits)?;

    if board.width_nm > limits.max_board_extent_nm || board.height_nm > limits.max_board_extent_nm {
        return Err(resource_error(
            "board_extent_nm",
            limits.max_board_extent_nm,
            "nm",
        ));
    }

    // Check coordinates before any subtraction or absolute-value operation.
    for point in board_points(board) {
        validate_coordinate(point, limits.max_board_extent_nm)?;
    }

    // Every physical length is bounded as well.  Negative semantic values are
    // left for the normal validation path, but extreme values are rejected here
    // so checked arithmetic never has to consume i64::MIN.
    for value in board_dimensions(board) {
        validate_magnitude(value, limits.max_board_extent_nm)?;
    }

    let mut polygons = PolygonAccounting::default();
    if board.outline.len() < 3 && board.width_nm > 0 && board.height_nm > 0 {
        let effective_outline = [
            Point { x_nm: 0, y_nm: 0 },
            Point {
                x_nm: board.width_nm,
                y_nm: 0,
            },
            Point {
                x_nm: board.width_nm,
                y_nm: board.height_nm,
            },
            Point {
                x_nm: 0,
                y_nm: board.height_nm,
            },
        ];
        polygons.add(&effective_outline, &limits)?;
    }
    for polygon in board_polygons(board) {
        polygons.add(polygon, &limits)?;
    }
    check_topology_work(board, &mut polygons, &limits)?;

    let grid = board.rules.grid_nm;
    if grid > 0 && board.width_nm > 0 && board.height_nm > 0 {
        let plane_x = axis_cells(board.width_nm, grid)?;
        let plane_y = axis_cells(board.height_nm, grid)?;
        let plane_cells = plane_x.checked_mul(plane_y).ok_or_else(|| {
            resource_error("plane_grid_cells", limits.max_plane_grid_cells, "cells")
        })?;
        check_limit(
            plane_cells,
            limits.max_plane_grid_cells,
            "plane_grid_cells",
            "cells",
        )?;
        let layer_slots = plane_cells
            .checked_mul(board.copper_layers.len() as u128)
            .ok_or_else(|| {
                resource_error("cell_layer_slots", limits.max_cell_layer_slots, "slots")
            })?;
        check_limit(
            layer_slots,
            limits.max_cell_layer_slots,
            "cell_layer_slots",
            "slots",
        )?;

        let (maximum_diameter, maximum_clearance) = maximum_routing_envelope(board);
        check_radius(
            maximum_diameter / 2 + maximum_clearance,
            i128::from(grid),
            limits.max_inflate_radius_cells,
        )?;
        let raster_visits = check_raster_windows(
            board,
            grid,
            maximum_diameter,
            maximum_clearance,
            plane_cells,
            &limits,
        )?;
        check_existing_routes(
            board,
            grid,
            maximum_diameter,
            maximum_clearance,
            raster_visits,
            &limits,
        )?;
        check_zone_windows(board, grid, &limits)?;
    }

    Ok(())
}

fn validate_limit_configuration(limits: &RoutingResourceLimits) -> Result<(), String> {
    if limits.max_board_extent_nm <= 0 || limits.max_board_extent_nm > MAX_BOARD_EXTENT_NM {
        return Err(format!(
            "resource limit configuration: max_board_extent_nm must be in 1..={MAX_BOARD_EXTENT_NM} nm"
        ));
    }
    let limits_to_check = [
        (
            "max_plane_grid_cells",
            limits.max_plane_grid_cells,
            MAX_PLANE_GRID_CELLS,
        ),
        (
            "max_cell_layer_slots",
            limits.max_cell_layer_slots,
            MAX_CELL_LAYER_SLOTS,
        ),
        (
            "max_raster_candidate_visits",
            limits.max_raster_candidate_visits,
            MAX_RASTER_CANDIDATE_VISITS,
        ),
        (
            "max_inflate_radius_cells",
            limits.max_inflate_radius_cells,
            MAX_INFLATE_RADIUS_CELLS,
        ),
        (
            "max_polygon_vertices",
            limits.max_polygon_vertices,
            MAX_POLYGON_VERTICES,
        ),
        (
            "max_total_polygon_vertices",
            limits.max_total_polygon_vertices,
            MAX_TOTAL_POLYGON_VERTICES,
        ),
        (
            "max_zone_candidate_cells",
            limits.max_zone_candidate_cells,
            MAX_ZONE_CANDIDATE_CELLS,
        ),
        (
            "max_raster_line_cells",
            limits.max_raster_line_cells,
            MAX_RASTER_LINE_CELLS,
        ),
        (
            "max_topology_edge_pair_work",
            limits.max_topology_edge_pair_work,
            MAX_TOPOLOGY_EDGE_PAIR_WORK,
        ),
        (
            "max_raster_geometry_edge_work",
            limits.max_raster_geometry_edge_work,
            MAX_RASTER_GEOMETRY_EDGE_WORK,
        ),
        (
            "max_zone_blocker_work",
            limits.max_zone_blocker_work,
            MAX_ZONE_BLOCKER_WORK,
        ),
    ];
    for (name, value, production) in limits_to_check {
        if value > production {
            return Err(format!(
                "resource limit configuration: {name} must not exceed {production}"
            ));
        }
    }
    Ok(())
}

#[derive(Default)]
struct PolygonAccounting {
    total_vertices: u128,
    pair_work: u128,
}

impl PolygonAccounting {
    fn add(&mut self, polygon: &[Point], limits: &RoutingResourceLimits) -> Result<(), String> {
        let vertices = polygon.len() as u128;
        check_limit(
            vertices,
            limits.max_polygon_vertices,
            "polygon_vertices",
            "vertices",
        )?;
        self.total_vertices = self.total_vertices.checked_add(vertices).ok_or_else(|| {
            resource_error(
                "total_polygon_vertices",
                limits.max_total_polygon_vertices,
                "vertices",
            )
        })?;
        check_limit(
            self.total_vertices,
            limits.max_total_polygon_vertices,
            "total_polygon_vertices",
            "vertices",
        )?;
        let pairs = vertices
            .checked_mul(vertices.saturating_sub(1))
            .and_then(|value| value.checked_div(2))
            .ok_or_else(|| {
                resource_error(
                    "topology_edge_pair_work",
                    limits.max_topology_edge_pair_work,
                    "pairs",
                )
            })?;
        self.pair_work = self.pair_work.checked_add(pairs).ok_or_else(|| {
            resource_error(
                "topology_edge_pair_work",
                limits.max_topology_edge_pair_work,
                "pairs",
            )
        })?;
        check_limit(
            self.pair_work,
            limits.max_topology_edge_pair_work,
            "topology_edge_pair_work",
            "pairs",
        )
    }

    fn add_pair_work(&mut self, work: u128, limits: &RoutingResourceLimits) -> Result<(), String> {
        self.pair_work = self.pair_work.checked_add(work).ok_or_else(|| {
            resource_error(
                "topology_edge_pair_work",
                limits.max_topology_edge_pair_work,
                "pairs",
            )
        })?;
        check_limit(
            self.pair_work,
            limits.max_topology_edge_pair_work,
            "topology_edge_pair_work",
            "pairs",
        )
    }
}

fn choose_two(count: usize, limits: &RoutingResourceLimits) -> Result<u128, String> {
    choose_two_u128(count as u128, limits)
}

fn choose_two_u128(count: u128, limits: &RoutingResourceLimits) -> Result<u128, String> {
    count
        .checked_mul(count.saturating_sub(1))
        .and_then(|value| value.checked_div(2))
        .ok_or_else(|| {
            resource_error(
                "topology_edge_pair_work",
                limits.max_topology_edge_pair_work,
                "pairs",
            )
        })
}

fn checked_product(
    left: u128,
    right: u128,
    limits: &RoutingResourceLimits,
) -> Result<u128, String> {
    left.checked_mul(right).ok_or_else(|| {
        resource_error(
            "topology_edge_pair_work",
            limits.max_topology_edge_pair_work,
            "pairs",
        )
    })
}

fn checked_sum(left: u128, right: u128, limits: &RoutingResourceLimits) -> Result<u128, String> {
    left.checked_add(right).ok_or_else(|| {
        resource_error(
            "topology_edge_pair_work",
            limits.max_topology_edge_pair_work,
            "pairs",
        )
    })
}

/// Account for the bounded quadratic loops used by the checker.
///
/// This deliberately mirrors the nested collections instead of charging one
/// large choose(total geometry, 2) value.  The generic route-clearance pass,
/// optional manufacturing-clearance pass, route-local connectivity/angle
/// checks, drilled-hole spacing, and zone-to-route connectivity are included.
fn check_topology_work(
    board: &Board,
    polygons: &mut PolygonAccounting,
    limits: &RoutingResourceLimits,
) -> Result<(), String> {
    for (index, route) in board.routes.iter().enumerate() {
        let segments = route.segments.len() as u128;
        let vias = route.vias.len() as u128;
        let zones = route.zones.len() as u128;
        let segment_pairs = choose_two(route.segments.len(), limits)?;
        let via_pairs = choose_two(route.vias.len(), limits)?;
        // check_route_connectivity's segment/segment, segment/via, and
        // via/via nested loops.
        let self_work = checked_sum(
            checked_sum(
                segment_pairs,
                checked_product(segments, vias, limits)?,
                limits,
            )?,
            via_pairs,
            limits,
        )?;
        polygons.add_pair_work(self_work, limits)?;
        // Manufacturing trace-angle checks repeat the segment-pair loop when
        // that optional rule is enabled.
        if board
            .manufacturing_rules
            .as_ref()
            .is_some_and(|rules| rules.minimum_trace_angle_deg > 0)
        {
            polygons.add_pair_work(segment_pairs, limits)?;
        }
        // Zone-to-segment/via connectivity checks.
        polygons.add_pair_work(
            checked_product(zones, checked_sum(segments, vias, limits)?, limits)?,
            limits,
        )?;

        for other in &board.routes[index + 1..] {
            let other_segments = other.segments.len() as u128;
            let other_vias = other.vias.len() as u128;
            let cross = checked_sum(
                checked_sum(
                    checked_product(segments, other_segments, limits)?,
                    checked_product(segments, other_vias, limits)?,
                    limits,
                )?,
                checked_sum(
                    checked_product(vias, other_segments, limits)?,
                    checked_product(vias, other_vias, limits)?,
                    limits,
                )?,
                limits,
            )?;
            // Generic route clearance always runs; manufacturability repeats
            // the same segment/via cross-products when configured.
            polygons.add_pair_work(cross, limits)?;
            if board.manufacturing_rules.is_some() {
                polygons.add_pair_work(cross, limits)?;
            }
        }
    }

    if board.manufacturing_rules.is_some() {
        let via_count = board.routes.iter().try_fold(0_u128, |total, route| {
            total.checked_add(route.vias.len() as u128).ok_or_else(|| {
                resource_error(
                    "topology_edge_pair_work",
                    limits.max_topology_edge_pair_work,
                    "pairs",
                )
            })
        })?;
        let pad_count = board
            .footprints
            .iter()
            .flat_map(|footprint| &footprint.pads)
            .filter(|pad| {
                pad.drill_width_nm.is_some_and(|value| value > 0)
                    && pad.drill_height_nm.is_some_and(|value| value > 0)
            })
            .count() as u128;
        let drilled_holes = checked_sum(via_count, pad_count, limits)?;
        polygons.add_pair_work(choose_two_u128(drilled_holes, limits)?, limits)?;
    }
    Ok(())
}

fn resource_error(resource: &str, limit: impl std::fmt::Display, unit: &str) -> String {
    format!("resource limit exceeded: {resource} (limit {limit} {unit})")
}

fn check_limit(actual: u128, limit: usize, resource: &str, unit: &str) -> Result<(), String> {
    if actual > limit as u128 {
        Err(resource_error(resource, limit, unit))
    } else {
        Ok(())
    }
}

fn validate_coordinate(point: Point, max_extent_nm: Nm) -> Result<(), String> {
    let limit = i128::from(max_extent_nm);
    if i128::from(point.x_nm).abs() > limit || i128::from(point.y_nm).abs() > limit {
        return Err(resource_error(
            "absolute_board_coordinate_nm",
            max_extent_nm,
            "nm",
        ));
    }
    Ok(())
}

fn validate_magnitude(value: Nm, max_extent_nm: Nm) -> Result<(), String> {
    if i128::from(value).abs() > i128::from(max_extent_nm) {
        return Err(resource_error("numeric_nm_domain", max_extent_nm, "nm"));
    }
    Ok(())
}

fn axis_cells(dimension: Nm, grid: Nm) -> Result<u128, String> {
    (i128::from(dimension) / i128::from(grid) + 1)
        .try_into()
        .map_err(|_| resource_error("plane_grid_cells", MAX_PLANE_GRID_CELLS, "cells"))
}

fn ceil_div(value: i128, divisor: i128) -> Result<u128, String> {
    if value < 0 || divisor <= 0 {
        return Err(resource_error(
            "inflate_radius_cells",
            MAX_INFLATE_RADIUS_CELLS,
            "cells",
        ));
    }
    ((value + divisor - 1) / divisor)
        .try_into()
        .map_err(|_| resource_error("inflate_radius_cells", MAX_INFLATE_RADIUS_CELLS, "cells"))
}

fn check_radius(value: i128, grid: i128, limit: usize) -> Result<(), String> {
    if value < 0 || grid <= 0 {
        return Ok(());
    }
    check_limit(
        ceil_div(value, grid)?,
        limit,
        "inflate_radius_cells",
        "cells",
    )
}

fn maximum_routing_envelope(board: &Board) -> (i128, i128) {
    let mut diameter = 0_i128;
    let mut clearance = 0_i128;
    for value in [board.rules.track_width_nm, board.rules.via_diameter_nm] {
        if value > 0 {
            diameter = diameter.max(i128::from(value));
        }
    }
    if board.rules.clearance_nm >= 0 {
        clearance = i128::from(board.rules.clearance_nm);
    }
    for rules in board.net_classes.values() {
        for value in [rules.track_width_nm, rules.via_diameter_nm] {
            if value > 0 {
                diameter = diameter.max(i128::from(value));
            }
        }
        if rules.clearance_nm >= 0 {
            clearance = clearance.max(i128::from(rules.clearance_nm));
        }
    }
    (diameter, clearance)
}

fn checked_add(left: i128, right: i128, resource: &str) -> Result<i128, String> {
    left.checked_add(right).ok_or_else(|| {
        format!("resource limit exceeded: {resource} (checked coordinate arithmetic)")
    })
}

#[allow(clippy::too_many_arguments)]
fn window_cells(
    min_x: i128,
    max_x: i128,
    min_y: i128,
    max_y: i128,
    grid: Nm,
    board_width: Nm,
    board_height: Nm,
    window_limit: usize,
) -> Result<u128, String> {
    if grid <= 0 || board_width <= 0 || board_height <= 0 {
        return Ok(0);
    }
    let width = i128::from(board_width);
    let height = i128::from(board_height);
    let min_x = min_x.max(0);
    let max_x = max_x.min(width);
    let min_y = min_y.max(0);
    let max_y = max_y.min(height);
    if min_x > max_x || min_y > max_y {
        return Ok(0);
    }
    let x_cells = (max_x / i128::from(grid))
        .checked_sub(min_x / i128::from(grid))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| resource_error("raster_window_cells", window_limit, "cells"))?;
    let y_cells = (max_y / i128::from(grid))
        .checked_sub(min_y / i128::from(grid))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| resource_error("raster_window_cells", window_limit, "cells"))?;
    let x_cells: u128 = x_cells
        .try_into()
        .map_err(|_| resource_error("raster_window_cells", window_limit, "cells"))?;
    let y_cells: u128 = y_cells
        .try_into()
        .map_err(|_| resource_error("raster_window_cells", window_limit, "cells"))?;
    x_cells
        .checked_mul(y_cells)
        .ok_or_else(|| resource_error("raster_window_cells", window_limit, "cells"))
}

fn add_raster_visits(
    total: &mut u128,
    cells: u128,
    layers: usize,
    limits: &RoutingResourceLimits,
) -> Result<(), String> {
    let visits = cells.checked_mul(layers as u128).ok_or_else(|| {
        resource_error(
            "raster_candidate_visits",
            limits.max_raster_candidate_visits,
            "visits",
        )
    })?;
    add_raster_work(total, visits, limits)
}

fn add_raster_work(
    total: &mut u128,
    visits: u128,
    limits: &RoutingResourceLimits,
) -> Result<(), String> {
    *total = total.checked_add(visits).ok_or_else(|| {
        resource_error(
            "raster_candidate_visits",
            limits.max_raster_candidate_visits,
            "visits",
        )
    })?;
    check_limit(
        *total,
        limits.max_raster_candidate_visits,
        "raster_candidate_visits",
        "visits",
    )
}

fn add_geometry_edge_work(
    total: &mut u128,
    work: u128,
    limits: &RoutingResourceLimits,
) -> Result<(), String> {
    *total = total.checked_add(work).ok_or_else(|| {
        resource_error(
            "raster_geometry_edge_work",
            limits.max_raster_geometry_edge_work,
            "edge-visits",
        )
    })?;
    check_limit(
        *total,
        limits.max_raster_geometry_edge_work,
        "raster_geometry_edge_work",
        "edge-visits",
    )
}

fn effective_outline_vertices(board: &Board) -> u128 {
    if board.outline.len() >= 3 {
        board.outline.len() as u128
    } else {
        4
    }
}

fn checked_work_product(
    values: impl IntoIterator<Item = u128>,
    resource: &str,
    limit: usize,
    unit: &str,
) -> Result<u128, String> {
    values.into_iter().try_fold(1_u128, |total, value| {
        total
            .checked_mul(value)
            .ok_or_else(|| resource_error(resource, limit, unit))
    })
}

fn check_raster_windows(
    board: &Board,
    grid: Nm,
    maximum_diameter: i128,
    maximum_clearance: i128,
    plane_cells: u128,
    limits: &RoutingResourceLimits,
) -> Result<u128, String> {
    let mut total = plane_cells;
    check_limit(
        total,
        limits.max_raster_candidate_visits,
        "raster_candidate_visits",
        "visits",
    )?;
    let outline_and_cutout_edges = checked_work_product(
        [
            plane_cells,
            2,
            effective_outline_vertices(board)
                .checked_add(
                    board
                        .cutouts
                        .iter()
                        .map(|cutout| cutout.len() as u128)
                        .try_fold(0_u128, |total, vertices| total.checked_add(vertices))
                        .ok_or_else(|| {
                            resource_error(
                                "raster_geometry_edge_work",
                                limits.max_raster_geometry_edge_work,
                                "edge-visits",
                            )
                        })?,
                )
                .ok_or_else(|| {
                    resource_error(
                        "raster_geometry_edge_work",
                        limits.max_raster_geometry_edge_work,
                        "edge-visits",
                    )
                })?,
        ],
        "raster_geometry_edge_work",
        limits.max_raster_geometry_edge_work,
        "edge-visits",
    )?;
    let mut geometry_edge_work = 0_u128;
    add_geometry_edge_work(&mut geometry_edge_work, outline_and_cutout_edges, limits)?;
    let inflate = maximum_diameter / 2 + maximum_clearance;
    let keepout_distance_twice = maximum_diameter + 2 * maximum_clearance;
    check_radius(
        keepout_distance_twice.max(0) / 2,
        i128::from(grid),
        limits.max_inflate_radius_cells,
    )?;

    for obstacle in &board.obstacles {
        let min_x = checked_add(i128::from(obstacle.min.x_nm), -inflate, "raster_window")?;
        let max_x = checked_add(i128::from(obstacle.max.x_nm), inflate, "raster_window")?;
        let min_y = checked_add(i128::from(obstacle.min.y_nm), -inflate, "raster_window")?;
        let max_y = checked_add(i128::from(obstacle.max.y_nm), inflate, "raster_window")?;
        let cells = window_cells(
            min_x,
            max_x,
            min_y,
            max_y,
            grid,
            board.width_nm,
            board.height_nm,
            limits.max_raster_candidate_visits,
        )?;
        add_raster_visits(&mut total, cells, obstacle.layers.len(), limits)?;
    }
    for obstacle in &board.round_obstacles {
        let distance_twice = i128::from(obstacle.diameter_nm)
            .checked_add(maximum_diameter)
            .and_then(|value| value.checked_add(2 * maximum_clearance))
            .ok_or_else(|| {
                resource_error(
                    "inflate_radius_cells",
                    limits.max_inflate_radius_cells,
                    "cells",
                )
            })?;
        let radius = (distance_twice.max(0) + 1) / 2;
        check_radius(radius, i128::from(grid), limits.max_inflate_radius_cells)?;
        let min_x = checked_add(i128::from(obstacle.center.x_nm), -radius, "raster_window")?;
        let max_x = checked_add(i128::from(obstacle.center.x_nm), radius, "raster_window")?;
        let min_y = checked_add(i128::from(obstacle.center.y_nm), -radius, "raster_window")?;
        let max_y = checked_add(i128::from(obstacle.center.y_nm), radius, "raster_window")?;
        let cells = window_cells(
            min_x,
            max_x,
            min_y,
            max_y,
            grid,
            board.width_nm,
            board.height_nm,
            limits.max_raster_candidate_visits,
        )?;
        add_raster_visits(&mut total, cells, obstacle.layers.len(), limits)?;
    }
    for obstacle in &board.capsule_obstacles {
        let distance_twice = i128::from(obstacle.diameter_nm)
            .checked_add(maximum_diameter)
            .and_then(|value| value.checked_add(2 * maximum_clearance))
            .ok_or_else(|| {
                resource_error(
                    "inflate_radius_cells",
                    limits.max_inflate_radius_cells,
                    "cells",
                )
            })?;
        let radius = (distance_twice.max(0) + 1) / 2;
        check_radius(radius, i128::from(grid), limits.max_inflate_radius_cells)?;
        let min_x = checked_add(
            i128::from(obstacle.start.x_nm.min(obstacle.end.x_nm)),
            -radius,
            "raster_window",
        )?;
        let max_x = checked_add(
            i128::from(obstacle.start.x_nm.max(obstacle.end.x_nm)),
            radius,
            "raster_window",
        )?;
        let min_y = checked_add(
            i128::from(obstacle.start.y_nm.min(obstacle.end.y_nm)),
            -radius,
            "raster_window",
        )?;
        let max_y = checked_add(
            i128::from(obstacle.start.y_nm.max(obstacle.end.y_nm)),
            radius,
            "raster_window",
        )?;
        let cells = window_cells(
            min_x,
            max_x,
            min_y,
            max_y,
            grid,
            board.width_nm,
            board.height_nm,
            limits.max_raster_candidate_visits,
        )?;
        add_raster_visits(&mut total, cells, obstacle.layers.len(), limits)?;
    }
    for polygon in board
        .polygon_obstacles
        .iter()
        .map(|obstacle| (&obstacle.polygon, obstacle.layers.len()))
        .chain(
            board
                .keepouts
                .iter()
                .filter(|keepout| keepout.tracks_not_allowed)
                .map(|keepout| (&keepout.polygon, keepout.layers.len())),
        )
    {
        let Some((min_x, max_x, min_y, max_y)) = polygon_bounds(polygon.0) else {
            continue;
        };
        let radius = (keepout_distance_twice.max(0) + 1) / 2;
        check_radius(radius, i128::from(grid), limits.max_inflate_radius_cells)?;
        let min_x = checked_add(i128::from(min_x), -radius, "raster_window")?;
        let max_x = checked_add(i128::from(max_x), radius, "raster_window")?;
        let min_y = checked_add(i128::from(min_y), -radius, "raster_window")?;
        let max_y = checked_add(i128::from(max_y), radius, "raster_window")?;
        let cells = window_cells(
            min_x,
            max_x,
            min_y,
            max_y,
            grid,
            board.width_nm,
            board.height_nm,
            limits.max_raster_candidate_visits,
        )?;
        add_raster_visits(&mut total, cells, polygon.1, limits)?;
        let edge_work = checked_work_product(
            [cells, polygon.1 as u128, 2, polygon.0.len() as u128],
            "raster_geometry_edge_work",
            limits.max_raster_geometry_edge_work,
            "edge-visits",
        )?;
        add_geometry_edge_work(&mut geometry_edge_work, edge_work, limits)?;
    }
    Ok(total)
}

fn check_existing_routes(
    board: &Board,
    grid: Nm,
    maximum_diameter: i128,
    maximum_clearance: i128,
    mut total: u128,
    limits: &RoutingResourceLimits,
) -> Result<(), String> {
    let grid = i128::from(grid);
    for route in &board.routes {
        for segment in &route.segments {
            let start_x = i128::from(segment.start.x_nm) / grid;
            let end_x = i128::from(segment.end.x_nm) / grid;
            let start_y = i128::from(segment.start.y_nm) / grid;
            let end_y = i128::from(segment.end.y_nm) / grid;
            let dx = (end_x - start_x).abs();
            let dy = (end_y - start_y).abs();
            let cells = dx.max(dy).checked_add(1).ok_or_else(|| {
                resource_error("raster_line_cells", limits.max_raster_line_cells, "cells")
            })?;
            let cells: u128 = cells.try_into().map_err(|_| {
                resource_error("raster_line_cells", limits.max_raster_line_cells, "cells")
            })?;
            check_limit(
                cells,
                limits.max_raster_line_cells,
                "raster_line_cells",
                "cells",
            )?;
            let radius =
                i128::from(segment.width_nm) / 2 + maximum_diameter / 2 + maximum_clearance;
            let radius_cells = ceil_div(radius.max(0), grid)?;
            check_limit(
                radius_cells,
                limits.max_inflate_radius_cells,
                "inflate_radius_cells",
                "cells",
            )?;
            let side = radius_cells
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    resource_error(
                        "raster_candidate_visits",
                        limits.max_raster_candidate_visits,
                        "visits",
                    )
                })?;
            let visits = cells
                .checked_mul(side.checked_mul(side).ok_or_else(|| {
                    resource_error(
                        "raster_candidate_visits",
                        limits.max_raster_candidate_visits,
                        "visits",
                    )
                })?)
                .ok_or_else(|| {
                    resource_error(
                        "raster_candidate_visits",
                        limits.max_raster_candidate_visits,
                        "visits",
                    )
                })?;
            add_raster_work(&mut total, visits, limits)?;
        }
        for via in &route.vias {
            let radius = i128::from(via.diameter_nm) / 2 + maximum_diameter / 2 + maximum_clearance;
            let radius_cells = ceil_div(radius.max(0), grid)?;
            check_limit(
                radius_cells,
                limits.max_inflate_radius_cells,
                "inflate_radius_cells",
                "cells",
            )?;
            let side = radius_cells
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    resource_error(
                        "raster_candidate_visits",
                        limits.max_raster_candidate_visits,
                        "visits",
                    )
                })?;
            let layer_count = board
                .copper_layers
                .iter()
                .filter(|layer| via.spans_layer(**layer))
                .count() as u128;
            let visits = layer_count
                .checked_mul(side.checked_mul(side).ok_or_else(|| {
                    resource_error(
                        "raster_candidate_visits",
                        limits.max_raster_candidate_visits,
                        "visits",
                    )
                })?)
                .ok_or_else(|| {
                    resource_error(
                        "raster_candidate_visits",
                        limits.max_raster_candidate_visits,
                        "visits",
                    )
                })?;
            add_raster_work(&mut total, visits, limits)?;
        }
    }
    Ok(())
}

fn check_zone_windows(
    board: &Board,
    grid: Nm,
    limits: &RoutingResourceLimits,
) -> Result<(), String> {
    let mut total_cells = 0_u128;
    let mut total_work = 0_u128;
    for route in &board.routes {
        for zone in &route.zones {
            let Some((min_x, max_x, min_y, max_y)) = polygon_bounds(&zone.polygon) else {
                continue;
            };
            let cells = window_cells(
                i128::from(min_x),
                i128::from(max_x),
                i128::from(min_y),
                i128::from(max_y),
                grid,
                board.width_nm,
                board.height_nm,
                limits.max_zone_candidate_cells,
            )?;
            total_cells = total_cells.checked_add(cells).ok_or_else(|| {
                resource_error(
                    "zone_candidate_cells",
                    limits.max_zone_candidate_cells,
                    "cells",
                )
            })?;
            check_limit(
                total_cells,
                limits.max_zone_candidate_cells,
                "zone_candidate_cells",
                "cells",
            )?;

            let per_cell_work = zone_blocker_work_per_cell(board, route.net_id, zone, limits)?;
            let zone_work = checked_work_product(
                [cells, per_cell_work],
                "zone_blocker_work",
                limits.max_zone_blocker_work,
                "operations",
            )?;
            total_work = total_work.checked_add(zone_work).ok_or_else(|| {
                resource_error(
                    "zone_blocker_work",
                    limits.max_zone_blocker_work,
                    "operations",
                )
            })?;
            check_limit(
                total_work,
                limits.max_zone_blocker_work,
                "zone_blocker_work",
                "operations",
            )?;
        }
    }
    Ok(())
}

fn zone_blocker_work_per_cell(
    board: &Board,
    net_id: u32,
    zone: &CopperZone,
    limits: &RoutingResourceLimits,
) -> Result<u128, String> {
    // Four corners are checked against the zone outline itself.
    let mut work = checked_work_product(
        [4, zone.polygon.len() as u128],
        "zone_blocker_work",
        limits.max_zone_blocker_work,
        "operations",
    )?;
    // board.point_inside_board() checks the effective outline and every
    // cutout with both point-in-polygon and edge-distance predicates.
    let board_edges = effective_outline_vertices(board)
        .checked_add(
            board
                .cutouts
                .iter()
                .map(|cutout| cutout.len() as u128)
                .try_fold(0_u128, |total, vertices| total.checked_add(vertices))
                .ok_or_else(|| {
                    resource_error(
                        "zone_blocker_work",
                        limits.max_zone_blocker_work,
                        "operations",
                    )
                })?,
        )
        .ok_or_else(|| {
            resource_error(
                "zone_blocker_work",
                limits.max_zone_blocker_work,
                "operations",
            )
        })?;
    work = work
        .checked_add(checked_work_product(
            [4, 2, board_edges],
            "zone_blocker_work",
            limits.max_zone_blocker_work,
            "operations",
        )?)
        .ok_or_else(|| {
            resource_error(
                "zone_blocker_work",
                limits.max_zone_blocker_work,
                "operations",
            )
        })?;

    // Keepouts are inspected even when layer/net eligibility rejects their
    // geometry.  An eligible polygon then contributes four corners times the
    // two polygon edge predicates.
    for keepout in &board.keepouts {
        work = work.checked_add(1).ok_or_else(|| {
            resource_error(
                "zone_blocker_work",
                limits.max_zone_blocker_work,
                "operations",
            )
        })?;
        if keepout.zones_not_allowed
            && keepout.layers.contains(&zone.layer)
            && keepout.net_id != Some(net_id)
        {
            work = work
                .checked_add(checked_work_product(
                    [4, 2, keepout.polygon.len() as u128],
                    "zone_blocker_work",
                    limits.max_zone_blocker_work,
                    "operations",
                )?)
                .ok_or_else(|| {
                    resource_error(
                        "zone_blocker_work",
                        limits.max_zone_blocker_work,
                        "operations",
                    )
                })?;
        }
    }

    // Rectangular and round blockers are constant-cost per corner, but every
    // item still contributes one outer predicate inspection (including layer
    // mismatches) so large ineligible collections cannot evade the bound.
    for obstacle in &board.obstacles {
        work = work.checked_add(1).ok_or_else(|| {
            resource_error(
                "zone_blocker_work",
                limits.max_zone_blocker_work,
                "operations",
            )
        })?;
        if obstacle.layers.contains(&zone.layer) && obstacle.net_id != Some(net_id) {
            work = work.checked_add(4).ok_or_else(|| {
                resource_error(
                    "zone_blocker_work",
                    limits.max_zone_blocker_work,
                    "operations",
                )
            })?;
        }
    }
    for obstacle in &board.round_obstacles {
        work = work.checked_add(1).ok_or_else(|| {
            resource_error(
                "zone_blocker_work",
                limits.max_zone_blocker_work,
                "operations",
            )
        })?;
        if obstacle.layers.contains(&zone.layer) && obstacle.net_id != Some(net_id) {
            work = work.checked_add(4).ok_or_else(|| {
                resource_error(
                    "zone_blocker_work",
                    limits.max_zone_blocker_work,
                    "operations",
                )
            })?;
        }
    }
    for route in &board.routes {
        // `board.routes.iter().any` performs this outer net-id inspection for
        // every route before it can inspect any of that route's segments.
        work = work.checked_add(1).ok_or_else(|| {
            resource_error(
                "zone_blocker_work",
                limits.max_zone_blocker_work,
                "operations",
            )
        })?;
        if route.net_id == net_id {
            continue;
        }
        for segment in &route.segments {
            // Include the layer predicate even for a mismatch, then charge
            // four corner geometry checks for an eligible foreign segment.
            work = work.checked_add(1).ok_or_else(|| {
                resource_error(
                    "zone_blocker_work",
                    limits.max_zone_blocker_work,
                    "operations",
                )
            })?;
            if segment.layer == zone.layer {
                work = work.checked_add(4).ok_or_else(|| {
                    resource_error(
                        "zone_blocker_work",
                        limits.max_zone_blocker_work,
                        "operations",
                    )
                })?;
            }
        }
    }

    // The thermal-relief iterator filters every pad and performs one
    // constant-cost distance check for each eligible own-net pad.  Counting
    // all pads is conservative and captures filter inspection too.
    if zone.thermal_relief {
        let pad_count = board
            .footprints
            .iter()
            .map(|footprint| footprint.pads.len() as u128)
            .try_fold(0_u128, |total, count| total.checked_add(count))
            .ok_or_else(|| {
                resource_error(
                    "zone_blocker_work",
                    limits.max_zone_blocker_work,
                    "operations",
                )
            })?;
        work = work.checked_add(pad_count).ok_or_else(|| {
            resource_error(
                "zone_blocker_work",
                limits.max_zone_blocker_work,
                "operations",
            )
        })?;
    }
    Ok(work)
}

fn polygon_bounds(polygon: &[Point]) -> Option<(Nm, Nm, Nm, Nm)> {
    Some((
        polygon.iter().map(|point| point.x_nm).min()?,
        polygon.iter().map(|point| point.x_nm).max()?,
        polygon.iter().map(|point| point.y_nm).min()?,
        polygon.iter().map(|point| point.y_nm).max()?,
    ))
}

fn board_points(board: &Board) -> impl Iterator<Item = Point> + '_ {
    board
        .outline
        .iter()
        .chain(board.cutouts.iter().flatten())
        .copied()
        .chain(
            board
                .obstacles
                .iter()
                .flat_map(|obstacle| [obstacle.min, obstacle.max]),
        )
        .chain(board.round_obstacles.iter().map(|obstacle| obstacle.center))
        .chain(
            board
                .capsule_obstacles
                .iter()
                .flat_map(|obstacle| [obstacle.start, obstacle.end]),
        )
        .chain(
            board
                .polygon_obstacles
                .iter()
                .flat_map(|obstacle| obstacle.polygon.iter().copied()),
        )
        .chain(
            board
                .keepouts
                .iter()
                .flat_map(|keepout| keepout.polygon.iter().copied()),
        )
        .chain(board.footprints.iter().flat_map(|footprint| {
            std::iter::once(footprint.position).chain(footprint.pads.iter().flat_map(|pad| {
                std::iter::once(pad.position).chain(pad.custom_polygon.iter().copied())
            }))
        }))
        .chain(
            board
                .nets
                .iter()
                .flat_map(|net| net.terminals.iter().map(|terminal| terminal.position)),
        )
        .chain(board.routes.iter().flat_map(|route| {
            route
                .segments
                .iter()
                .flat_map(|segment| [segment.start, segment.end])
                .chain(
                    route
                        .arcs
                        .iter()
                        .flat_map(|arc| [arc.start, arc.mid, arc.end]),
                )
                .chain(route.vias.iter().map(|via| via.position))
                .chain(
                    route
                        .teardrops
                        .iter()
                        .flat_map(|teardrop| teardrop.polygon.iter().copied()),
                )
                .chain(route.zones.iter().flat_map(|zone| {
                    zone.polygon
                        .iter()
                        .chain(zone.filled_polygons.iter().flatten())
                        .copied()
                }))
        }))
}

fn board_polygons(board: &Board) -> impl Iterator<Item = &[Point]> + '_ {
    std::iter::once(board.outline.as_slice())
        .chain(board.cutouts.iter().map(Vec::as_slice))
        .chain(
            board
                .polygon_obstacles
                .iter()
                .map(|obstacle| obstacle.polygon.as_slice()),
        )
        .chain(
            board
                .keepouts
                .iter()
                .map(|keepout| keepout.polygon.as_slice()),
        )
        .chain(board.footprints.iter().flat_map(|footprint| {
            footprint
                .pads
                .iter()
                .map(|pad| pad.custom_polygon.as_slice())
        }))
        .chain(board.routes.iter().flat_map(|route| {
            route
                .teardrops
                .iter()
                .map(|teardrop| teardrop.polygon.as_slice())
                .chain(route.zones.iter().flat_map(|zone| {
                    std::iter::once(zone.polygon.as_slice())
                        .chain(zone.filled_polygons.iter().map(Vec::as_slice))
                }))
        }))
}

fn board_dimensions(board: &Board) -> impl Iterator<Item = Nm> + '_ {
    let rules = &board.rules;
    let base = [
        board.width_nm,
        board.height_nm,
        rules.grid_nm,
        rules.track_width_nm,
        rules.clearance_nm,
        rules.via_diameter_nm,
        rules.via_drill_nm,
    ];
    base.into_iter()
        .chain(board.net_classes.values().flat_map(|rules| {
            [
                rules.track_width_nm,
                rules.clearance_nm,
                rules.via_diameter_nm,
                rules.via_drill_nm,
                rules.differential_width_nm.unwrap_or(0),
                rules.differential_gap_nm.unwrap_or(0),
                rules.minimum_length_nm.unwrap_or(0),
                rules.maximum_length_nm.unwrap_or(0),
            ]
        }))
        .chain(
            board
                .round_obstacles
                .iter()
                .map(|obstacle| obstacle.diameter_nm),
        )
        .chain(
            board
                .capsule_obstacles
                .iter()
                .map(|obstacle| obstacle.diameter_nm),
        )
        .chain(board.keepouts.iter().flat_map(|keepout| {
            [
                keepout.minimum_track_width_nm.unwrap_or(0),
                keepout.minimum_clearance_nm.unwrap_or(0),
            ]
        }))
        .chain(board.footprints.iter().flat_map(|footprint| {
            footprint.pads.iter().flat_map(|pad| {
                [
                    pad.width_nm,
                    pad.height_nm,
                    pad.source_width_nm,
                    pad.source_height_nm,
                    pad.roundrect_radius_nm,
                    pad.trapezoid_delta_x_nm,
                    pad.trapezoid_delta_y_nm,
                    pad.drill_width_nm.unwrap_or(0),
                    pad.drill_height_nm.unwrap_or(0),
                    pad.drill_offset_x_nm,
                    pad.drill_offset_y_nm,
                ]
            })
        }))
        .chain(board.routes.iter().flat_map(|route| {
            route
                .segments
                .iter()
                .map(|segment| segment.width_nm)
                .chain(route.arcs.iter().map(|arc| arc.width_nm))
                .chain(
                    route
                        .vias
                        .iter()
                        .flat_map(|via| [via.diameter_nm, via.drill_nm]),
                )
                .chain(route.zones.iter().flat_map(|zone| {
                    [
                        zone.clearance_nm,
                        zone.minimum_thickness_nm,
                        zone.thermal_gap_nm,
                        zone.thermal_spoke_width_nm,
                    ]
                }))
        }))
        .chain(
            board.escape_groups.iter().flat_map(|group| {
                std::iter::once(group.fanout_distance_nm).chain(group.via_grid_nm)
            }),
        )
        .chain(board.return_path_rules.iter().flat_map(|rule| {
            std::iter::once(rule.max_via_distance_nm).chain(rule.plane_sample_spacing_nm)
        }))
        .chain(board.stackup.iter().flat_map(|layer| {
            std::iter::once(layer.dielectric_height_nm)
                .chain(std::iter::once(layer.copper_thickness_nm))
                .chain(layer.secondary_dielectric_height_nm)
        }))
        .chain(board.manufacturing_rules.iter().flat_map(|rules| {
            [
                rules.minimum_track_width_nm,
                rules.minimum_clearance_nm,
                rules.minimum_drill_nm,
                rules.minimum_annular_ring_nm,
                rules.minimum_copper_to_edge_nm,
                rules.board_thickness_nm,
                rules.minimum_drill_to_drill_nm,
            ]
        }))
        .chain(board.differential_pairs.iter().flat_map(|pair| {
            [
                pair.gap_nm,
                pair.gap_tolerance_nm,
                pair.max_skew_nm,
                pair.minimum_length_nm.unwrap_or(0),
                pair.tuning_amplitude_nm.unwrap_or(0),
                pair.tuning_pitch_nm.unwrap_or(0),
            ]
        }))
        .chain(board.length_groups.iter().flat_map(|group| {
            [
                group.max_skew_nm,
                group.tuning_amplitude_nm.unwrap_or(0),
                group.tuning_pitch_nm.unwrap_or(0),
            ]
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Board, CopperZone, Layer, Obstacle, Point, Route, Rules, Segment};

    fn board(width_nm: Nm, height_nm: Nm, grid_nm: Nm) -> Board {
        Board {
            schema_version: crate::CURRENT_SCHEMA_VERSION,
            width_nm,
            height_nm,
            outline: vec![],
            cutouts: vec![],
            copper_layers: vec![Layer::Front, Layer::Back],
            rules: Rules {
                grid_nm,
                track_width_nm: 1,
                clearance_nm: 0,
                via_diameter_nm: 2,
                via_drill_nm: 1,
                bend_cost: 5,
                via_cost: 20,
            },
            obstacles: vec![],
            round_obstacles: vec![],
            capsule_obstacles: vec![],
            polygon_obstacles: vec![],
            keepouts: vec![],
            footprints: vec![],
            net_classes: Default::default(),
            differential_pairs: vec![],
            length_groups: vec![],
            escape_groups: vec![],
            manufacturing_rules: None,
            return_path_rules: vec![],
            power_net_rules: vec![],
            stackup: vec![],
            via_strategy: Default::default(),
            nets: vec![],
            routes: vec![],
        }
    }

    #[test]
    fn injectable_plane_limit_accepts_exact_and_rejects_plus_one() {
        let board = board(4, 4, 1);
        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_plane_grid_cells = 25;
        assert!(validate_routing_resource_bounds_with_limits(&board, limits).is_ok());
        limits.max_plane_grid_cells = 24;
        let error = validate_routing_resource_bounds_with_limits(&board, limits).unwrap_err();
        assert!(error.contains("plane_grid_cells"));
        assert!(error.contains("limit 24"));
    }

    #[test]
    fn injectable_raster_geometry_edge_work_has_exact_and_plus_one_boundaries() {
        let base = board(4, 4, 1);
        // 25 plane cells × 2 predicates × four effective rectangle edges.
        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_raster_geometry_edge_work = 200;
        assert!(validate_routing_resource_bounds_with_limits(&base, limits).is_ok());
        limits.max_raster_geometry_edge_work = 199;
        let error = validate_routing_resource_bounds_with_limits(&base, limits).unwrap_err();
        assert!(error.contains("raster_geometry_edge_work"));
        assert!(error.contains("limit 199"));

        let mut polygon_board = base;
        polygon_board
            .polygon_obstacles
            .push(crate::PolygonObstacle {
                polygon: vec![
                    Point { x_nm: 0, y_nm: 0 },
                    Point { x_nm: 4, y_nm: 0 },
                    Point { x_nm: 4, y_nm: 4 },
                    Point { x_nm: 0, y_nm: 4 },
                ],
                layers: vec![Layer::Front],
                net_id: None,
            });
        // The polygon window covers the same 25 cells: +25 × 1 layer ×
        // two predicates × four edges.
        limits.max_raster_geometry_edge_work = 400;
        assert!(validate_routing_resource_bounds_with_limits(&polygon_board, limits).is_ok());
        limits.max_raster_geometry_edge_work = 399;
        let error =
            validate_routing_resource_bounds_with_limits(&polygon_board, limits).unwrap_err();
        assert!(error.contains("raster_geometry_edge_work"));
    }

    #[test]
    fn injectable_zone_blocker_work_counts_outer_inspections() {
        let mut board = board(4, 4, 1);
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![CopperZone {
                polygon: vec![
                    Point { x_nm: 0, y_nm: 0 },
                    Point { x_nm: 4, y_nm: 0 },
                    Point { x_nm: 4, y_nm: 4 },
                ],
                layer: Layer::Front,
                clearance_nm: 0,
                minimum_thickness_nm: 1,
                thermal_relief: false,
                thermal_gap_nm: 0,
                thermal_spoke_width_nm: 0,
                filled_polygons: vec![],
            }],
        });
        // 25 cells × (4×3 zone edges + 4×2×4 board edges + one route
        // outer inspection) = 1,125 conservative operations.
        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_zone_blocker_work = 1_125;
        assert!(validate_routing_resource_bounds_with_limits(&board, limits).is_ok());
        limits.max_zone_blocker_work = 1_124;
        let error = validate_routing_resource_bounds_with_limits(&board, limits).unwrap_err();
        assert!(error.contains("zone_blocker_work"));

        // A layer-mismatched rectangular blocker still executes the outer
        // iterator predicate, so its inspection must be charged.
        board.obstacles = (0..3)
            .map(|offset| Obstacle {
                min: Point {
                    x_nm: offset,
                    y_nm: 0,
                },
                max: Point {
                    x_nm: offset + 1,
                    y_nm: 1,
                },
                layers: vec![Layer::Back],
                net_id: None,
            })
            .collect();
        limits.max_zone_blocker_work = 1_200;
        assert!(validate_routing_resource_bounds_with_limits(&board, limits).is_ok());
        limits.max_zone_blocker_work = 1_199;
        let error = validate_routing_resource_bounds_with_limits(&board, limits).unwrap_err();
        assert!(error.contains("zone_blocker_work"));
    }

    #[test]
    fn large_injectable_polygon_edge_work_analog_is_bounded() {
        let mut board = board(1, 1, 1);
        board.polygon_obstacles.push(crate::PolygonObstacle {
            polygon: vec![Point { x_nm: 0, y_nm: 0 }; MAX_POLYGON_VERTICES],
            layers: vec![Layer::Front],
            net_id: None,
        });
        // Four plane cells and a 4,096-edge polygon window are enough to
        // exercise the same multiplication as a 1M-cell/large-polygon board
        // without allocating the production-sized raster.
        let expected = 4 * 2 * 4 + 4 * 2 * MAX_POLYGON_VERTICES;
        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_raster_geometry_edge_work = expected;
        assert!(validate_routing_resource_bounds_with_limits(&board, limits).is_ok());
        limits.max_raster_geometry_edge_work = expected - 1;
        let error = validate_routing_resource_bounds_with_limits(&board, limits).unwrap_err();
        assert!(error.contains("raster_geometry_edge_work"));
    }

    #[test]
    fn topology_pair_work_includes_route_self_pairs() {
        let mut board = board(4, 4, 1);
        board.routes.push(Route {
            net_id: 1,
            segments: vec![
                Segment {
                    start: Point { x_nm: 0, y_nm: 0 },
                    end: Point { x_nm: 1, y_nm: 0 },
                    layer: Layer::Front,
                    width_nm: 1,
                },
                Segment {
                    start: Point { x_nm: 1, y_nm: 0 },
                    end: Point { x_nm: 2, y_nm: 0 },
                    layer: Layer::Front,
                    width_nm: 1,
                },
            ],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });
        // Effective outline contributes six pairs; connectivity contributes
        // one segment pair.
        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_topology_edge_pair_work = 7;
        assert!(validate_routing_resource_bounds_with_limits(&board, limits).is_ok());
        limits.max_topology_edge_pair_work = 6;
        let error = validate_routing_resource_bounds_with_limits(&board, limits).unwrap_err();
        assert!(error.contains("topology_edge_pair_work"));
    }

    #[test]
    fn injectable_limits_cover_slots_raster_radius_polygon_zone_and_line() {
        let base = board(4, 4, 1);

        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_plane_grid_cells = 25;
        limits.max_cell_layer_slots = 50;
        assert!(validate_routing_resource_bounds_with_limits(&base, limits).is_ok());
        limits.max_cell_layer_slots = 49;
        assert!(
            validate_routing_resource_bounds_with_limits(&base, limits)
                .unwrap_err()
                .contains("cell_layer_slots")
        );

        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_raster_candidate_visits = 25;
        assert!(validate_routing_resource_bounds_with_limits(&base, limits).is_ok());
        limits.max_raster_candidate_visits = 24;
        assert!(
            validate_routing_resource_bounds_with_limits(&base, limits)
                .unwrap_err()
                .contains("raster_candidate_visits")
        );

        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_inflate_radius_cells = 1;
        assert!(validate_routing_resource_bounds_with_limits(&base, limits).is_ok());
        limits.max_inflate_radius_cells = 0;
        assert!(
            validate_routing_resource_bounds_with_limits(&base, limits)
                .unwrap_err()
                .contains("inflate_radius_cells")
        );

        let mut polygon_board = base.clone();
        polygon_board
            .polygon_obstacles
            .push(crate::PolygonObstacle {
                polygon: vec![
                    Point { x_nm: 0, y_nm: 0 },
                    Point { x_nm: 3, y_nm: 0 },
                    Point { x_nm: 3, y_nm: 3 },
                    Point { x_nm: 0, y_nm: 3 },
                ],
                layers: vec![Layer::Front],
                net_id: None,
            });
        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_total_polygon_vertices = 8;
        limits.max_topology_edge_pair_work = 12;
        assert!(validate_routing_resource_bounds_with_limits(&polygon_board, limits).is_ok());
        limits.max_total_polygon_vertices = 7;
        assert!(
            validate_routing_resource_bounds_with_limits(&polygon_board, limits)
                .unwrap_err()
                .contains("total_polygon_vertices")
        );
        limits.max_total_polygon_vertices = 8;
        limits.max_topology_edge_pair_work = 11;
        assert!(
            validate_routing_resource_bounds_with_limits(&polygon_board, limits)
                .unwrap_err()
                .contains("topology_edge_pair_work")
        );

        let mut line_board = base.clone();
        line_board.routes.push(Route {
            net_id: 1,
            segments: vec![Segment {
                start: Point { x_nm: 0, y_nm: 0 },
                end: Point { x_nm: 4, y_nm: 4 },
                layer: Layer::Front,
                width_nm: 1,
            }],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });
        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_raster_line_cells = 5;
        assert!(validate_routing_resource_bounds_with_limits(&line_board, limits).is_ok());
        limits.max_raster_line_cells = 4;
        assert!(
            validate_routing_resource_bounds_with_limits(&line_board, limits)
                .unwrap_err()
                .contains("raster_line_cells")
        );
        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_raster_candidate_visits = 70;
        assert!(validate_routing_resource_bounds_with_limits(&line_board, limits).is_ok());
        limits.max_raster_candidate_visits = 69;
        assert!(
            validate_routing_resource_bounds_with_limits(&line_board, limits)
                .unwrap_err()
                .contains("raster_candidate_visits")
        );

        let mut zone_board = base;
        zone_board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![CopperZone {
                polygon: vec![
                    Point { x_nm: 0, y_nm: 0 },
                    Point { x_nm: 4, y_nm: 0 },
                    Point { x_nm: 4, y_nm: 4 },
                ],
                layer: Layer::Front,
                clearance_nm: 0,
                minimum_thickness_nm: 1,
                thermal_relief: false,
                thermal_gap_nm: 0,
                thermal_spoke_width_nm: 0,
                filled_polygons: vec![],
            }],
        });
        let mut limits = RoutingResourceLimits::PRODUCTION;
        limits.max_zone_candidate_cells = 25;
        assert!(validate_routing_resource_bounds_with_limits(&zone_board, limits).is_ok());
        limits.max_zone_candidate_cells = 24;
        assert!(
            validate_routing_resource_bounds_with_limits(&zone_board, limits)
                .unwrap_err()
                .contains("zone_candidate_cells")
        );
    }

    #[test]
    fn extreme_coordinate_is_rejected_before_checker_geometry() {
        let mut board = board(4, 4, 1);
        board.routes.push(Route {
            net_id: 1,
            segments: vec![Segment {
                start: Point {
                    x_nm: i64::MIN,
                    y_nm: 0,
                },
                end: Point { x_nm: 0, y_nm: 0 },
                layer: Layer::Front,
                width_nm: 1,
            }],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });
        let report = crate::checking::check_board(&board);
        assert_eq!(report.violations[0].rule, "resource_limits");
        assert!(
            matches!(crate::Router::new(&board), Err(error) if error.contains("absolute_board_coordinate_nm"))
        );
    }

    #[test]
    fn huge_board_and_tiny_grid_are_rejected_before_rasterization() {
        let board = board(MAX_BOARD_EXTENT_NM, MAX_BOARD_EXTENT_NM, 1);
        let error = validate_routing_resource_bounds(&board).unwrap_err();
        assert!(error.contains("plane_grid_cells"));
        assert!(
            matches!(crate::Router::new(&board), Err(error) if error.contains("plane_grid_cells"))
        );
    }

    #[test]
    fn overlong_existing_segment_is_rejected_before_line_allocation() {
        let mut board = board(999, 999, 1);
        board.routes.push(Route {
            net_id: 1,
            segments: vec![Segment {
                start: Point {
                    x_nm: -MAX_BOARD_EXTENT_NM,
                    y_nm: -MAX_BOARD_EXTENT_NM,
                },
                end: Point {
                    x_nm: MAX_BOARD_EXTENT_NM,
                    y_nm: MAX_BOARD_EXTENT_NM,
                },
                layer: Layer::Front,
                width_nm: 1,
            }],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![],
        });
        let error = validate_routing_resource_bounds(&board).unwrap_err();
        assert!(error.contains("raster_line_cells"));
    }

    #[test]
    fn oversized_polygon_is_rejected_before_topology() {
        let mut board = board(10, 10, 1);
        board.polygon_obstacles.push(crate::PolygonObstacle {
            polygon: vec![Point { x_nm: 1, y_nm: 1 }; MAX_POLYGON_VERTICES + 1],
            layers: vec![Layer::Front],
            net_id: None,
        });
        let error = validate_routing_resource_bounds(&board).unwrap_err();
        assert!(error.contains("polygon_vertices"));
        assert!(matches!(
            crate::route_board_with_workers(&board, 1),
            Err(error) if error.contains("polygon_vertices")
        ));
    }

    #[test]
    fn off_board_zone_is_clamped_without_candidate_scan() {
        let mut board = board(10, 10, 1);
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![CopperZone {
                polygon: vec![
                    Point {
                        x_nm: -MAX_BOARD_EXTENT_NM,
                        y_nm: -MAX_BOARD_EXTENT_NM,
                    },
                    Point {
                        x_nm: -MAX_BOARD_EXTENT_NM + 1,
                        y_nm: -MAX_BOARD_EXTENT_NM,
                    },
                    Point {
                        x_nm: -MAX_BOARD_EXTENT_NM + 1,
                        y_nm: -MAX_BOARD_EXTENT_NM + 1,
                    },
                ],
                layer: Layer::Front,
                clearance_nm: 0,
                minimum_thickness_nm: 1,
                thermal_relief: false,
                thermal_gap_nm: 0,
                thermal_spoke_width_nm: 0,
                filled_polygons: vec![vec![
                    Point { x_nm: 1, y_nm: 1 },
                    Point { x_nm: 2, y_nm: 1 },
                    Point { x_nm: 2, y_nm: 2 },
                ]],
            }],
        });
        assert_eq!(crate::try_fill_copper_zones(&mut board).unwrap(), 0);
    }

    #[test]
    fn zone_fill_failure_is_atomic_and_zero_grid_is_rejected() {
        let mut board = board(999, 999, 1);
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![CopperZone {
                polygon: vec![
                    Point { x_nm: 0, y_nm: 0 },
                    Point { x_nm: 999, y_nm: 0 },
                    Point {
                        x_nm: 999,
                        y_nm: 999,
                    },
                ],
                layer: Layer::Front,
                clearance_nm: 0,
                minimum_thickness_nm: 1,
                thermal_relief: false,
                thermal_gap_nm: 0,
                thermal_spoke_width_nm: 0,
                filled_polygons: vec![vec![
                    Point { x_nm: 1, y_nm: 1 },
                    Point { x_nm: 2, y_nm: 1 },
                    Point { x_nm: 2, y_nm: 2 },
                ]],
            }],
        });
        let before = board.routes[0].zones[0].filled_polygons.clone();
        let error = crate::try_fill_copper_zones(&mut board).unwrap_err();
        assert!(error.contains("zone_candidate_cells"));
        assert_eq!(board.routes[0].zones[0].filled_polygons, before);

        let mut compatibility = board.clone();
        assert_eq!(crate::fill_copper_zones(&mut compatibility), 0);
        assert_eq!(compatibility.routes[0].zones[0].filled_polygons, before);

        board.rules.grid_nm = 0;
        let error = crate::try_fill_copper_zones(&mut board).unwrap_err();
        assert!(error.contains("zone_grid_nm"));
        assert_eq!(board.routes[0].zones[0].filled_polygons, before);
    }

    #[test]
    fn zone_fill_rejects_non_positive_board_dimensions_atomically() {
        let mut board = board(0, 4, 1);
        board.routes.push(Route {
            net_id: 1,
            segments: vec![],
            arcs: vec![],
            vias: vec![],
            teardrops: vec![],
            zones: vec![CopperZone {
                polygon: vec![
                    Point { x_nm: 0, y_nm: 0 },
                    Point { x_nm: 1, y_nm: 0 },
                    Point { x_nm: 0, y_nm: 1 },
                ],
                layer: Layer::Front,
                clearance_nm: 0,
                minimum_thickness_nm: 1,
                thermal_relief: false,
                thermal_gap_nm: 0,
                thermal_spoke_width_nm: 0,
                filled_polygons: vec![vec![
                    Point { x_nm: 0, y_nm: 0 },
                    Point { x_nm: 1, y_nm: 0 },
                    Point { x_nm: 0, y_nm: 1 },
                ]],
            }],
        });
        let before = board.routes[0].zones[0].filled_polygons.clone();
        let error = crate::try_fill_copper_zones(&mut board).unwrap_err();
        assert!(error.contains("zone_board_extent_nm"));
        assert_eq!(board.routes[0].zones[0].filled_polygons, before);
        assert_eq!(crate::fill_copper_zones(&mut board), 0);
        assert_eq!(board.routes[0].zones[0].filled_polygons, before);
    }
}

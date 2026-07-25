use crate::Point;
use std::cmp::Ordering;

pub(crate) fn points_within(a: Point, b: Point, distance_twice: i64) -> bool {
    compare_ratio(
        squared_difference(a.x_nm, b.x_nm) + squared_difference(a.y_nm, b.y_nm),
        1,
        distance_twice,
        true,
    )
}

pub(crate) fn points_closer_than(a: Point, b: Point, distance_twice: i64) -> bool {
    compare_ratio(
        squared_difference(a.x_nm, b.x_nm) + squared_difference(a.y_nm, b.y_nm),
        1,
        distance_twice,
        false,
    )
}

pub(crate) fn point_segment_within(
    point: Point,
    start: Point,
    end: Point,
    distance_twice: i64,
) -> bool {
    point_segment_compare(point, start, end, distance_twice, true)
}

pub(crate) fn point_segment_closer_than(
    point: Point,
    start: Point,
    end: Point,
    distance_twice: i64,
) -> bool {
    point_segment_compare(point, start, end, distance_twice, false)
}

pub(crate) fn segments_within(a: Point, b: Point, c: Point, d: Point, distance_twice: i64) -> bool {
    segment_compare(a, b, c, d, distance_twice, true)
}

pub(crate) fn segments_closer_than(
    a: Point,
    b: Point,
    c: Point,
    d: Point,
    distance_twice: i64,
) -> bool {
    segment_compare(a, b, c, d, distance_twice, false)
}

pub(crate) fn point_rect_closer_than(
    point: Point,
    min: Point,
    max: Point,
    distance_twice: i64,
) -> bool {
    let dx = if point.x_nm < min.x_nm {
        min.x_nm as i128 - point.x_nm as i128
    } else if point.x_nm > max.x_nm {
        point.x_nm as i128 - max.x_nm as i128
    } else {
        0
    };
    let dy = if point.y_nm < min.y_nm {
        min.y_nm as i128 - point.y_nm as i128
    } else if point.y_nm > max.y_nm {
        point.y_nm as i128 - max.y_nm as i128
    } else {
        0
    };
    compare_ratio(dx * dx + dy * dy, 1, distance_twice, false)
}

pub(crate) fn segment_rect_closer_than(
    start: Point,
    end: Point,
    min: Point,
    max: Point,
    distance_twice: i64,
) -> bool {
    if point_in_rect(start, min, max) || point_in_rect(end, min, max) {
        return distance_twice > 0;
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
    (0..4).any(|index| {
        segments_closer_than(
            start,
            end,
            corners[index],
            corners[(index + 1) % 4],
            distance_twice,
        )
    })
}

pub(crate) fn point_in_polygon(point: Point, polygon: &[Point]) -> bool {
    if polygon.len() < 3 {
        return false;
    }
    let mut winding = 0i32;
    for index in 0..polygon.len() {
        let start = polygon[index];
        let end = polygon[(index + 1) % polygon.len()];
        if orientation(start, end, point) == 0 && point_on_segment(point, start, end) {
            return true;
        }
        if start.y_nm <= point.y_nm {
            if end.y_nm > point.y_nm && orientation(start, end, point) > 0 {
                winding += 1;
            }
        } else if end.y_nm <= point.y_nm && orientation(start, end, point) < 0 {
            winding -= 1;
        }
    }
    winding != 0
}

pub(crate) fn polygon_is_simple(polygon: &[Point]) -> bool {
    if polygon.len() < 3
        || polygon
            .iter()
            .zip(polygon.iter().cycle().skip(1))
            .take(polygon.len())
            .any(|(start, end)| start == end)
    {
        return false;
    }
    for left in 0..polygon.len() {
        for right in left + 1..polygon.len() {
            let adjacent = right == left + 1 || (left == 0 && right == polygon.len() - 1);
            if adjacent {
                continue;
            }
            if segments_intersect(
                polygon[left],
                polygon[(left + 1) % polygon.len()],
                polygon[right],
                polygon[(right + 1) % polygon.len()],
            ) {
                return false;
            }
        }
    }
    polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
        .map(|(a, b)| a.x_nm as i128 * b.y_nm as i128 - b.x_nm as i128 * a.y_nm as i128)
        .sum::<i128>()
        != 0
}

pub(crate) fn point_polygon_closer_than(
    point: Point,
    polygon: &[Point],
    distance_twice: i64,
) -> bool {
    polygon_edges(polygon)
        .any(|(start, end)| point_segment_closer_than(point, start, end, distance_twice))
}

pub(crate) fn segment_polygon_closer_than(
    start: Point,
    end: Point,
    polygon: &[Point],
    distance_twice: i64,
) -> bool {
    polygon_edges(polygon).any(|(edge_start, edge_end)| {
        segments_closer_than(start, end, edge_start, edge_end, distance_twice)
    })
}

fn polygon_edges(polygon: &[Point]) -> impl Iterator<Item = (Point, Point)> + '_ {
    polygon
        .iter()
        .copied()
        .zip(polygon.iter().copied().cycle().skip(1))
        .take(polygon.len())
}

fn point_segment_compare(
    point: Point,
    start: Point,
    end: Point,
    distance_twice: i64,
    inclusive: bool,
) -> bool {
    let dx = end.x_nm as i128 - start.x_nm as i128;
    let dy = end.y_nm as i128 - start.y_nm as i128;
    let px = point.x_nm as i128 - start.x_nm as i128;
    let py = point.y_nm as i128 - start.y_nm as i128;
    let length_squared = dx * dx + dy * dy;
    if length_squared == 0 {
        return compare_ratio(px * px + py * py, 1, distance_twice, inclusive);
    }
    let projection = px * dx + py * dy;
    if projection <= 0 {
        compare_ratio(px * px + py * py, 1, distance_twice, inclusive)
    } else if projection >= length_squared {
        let ex = point.x_nm as i128 - end.x_nm as i128;
        let ey = point.y_nm as i128 - end.y_nm as i128;
        compare_ratio(ex * ex + ey * ey, 1, distance_twice, inclusive)
    } else {
        let cross = px * dy - py * dx;
        compare_ratio(cross * cross, length_squared, distance_twice, inclusive)
    }
}

fn segment_compare(
    a: Point,
    b: Point,
    c: Point,
    d: Point,
    distance_twice: i64,
    inclusive: bool,
) -> bool {
    if segments_intersect(a, b, c, d) {
        return inclusive || distance_twice > 0;
    }
    [
        point_segment_compare(a, c, d, distance_twice, inclusive),
        point_segment_compare(b, c, d, distance_twice, inclusive),
        point_segment_compare(c, a, b, distance_twice, inclusive),
        point_segment_compare(d, a, b, distance_twice, inclusive),
    ]
    .into_iter()
    .any(|matches| matches)
}

fn compare_ratio(numerator: i128, denominator: i128, distance_twice: i64, inclusive: bool) -> bool {
    if distance_twice < 0 {
        return false;
    }
    let threshold = distance_twice as i128;
    let ordering = (4 * numerator).cmp(&(threshold * threshold * denominator));
    if inclusive {
        ordering != Ordering::Greater
    } else {
        ordering == Ordering::Less
    }
}

fn segments_intersect(a: Point, b: Point, c: Point, d: Point) -> bool {
    let ab_c = orientation(a, b, c);
    let ab_d = orientation(a, b, d);
    let cd_a = orientation(c, d, a);
    let cd_b = orientation(c, d, b);
    if ab_c == 0 && point_on_segment(c, a, b)
        || ab_d == 0 && point_on_segment(d, a, b)
        || cd_a == 0 && point_on_segment(a, c, d)
        || cd_b == 0 && point_on_segment(b, c, d)
    {
        return true;
    }
    (ab_c > 0) != (ab_d > 0) && (cd_a > 0) != (cd_b > 0)
}

fn orientation(a: Point, b: Point, c: Point) -> i128 {
    (b.x_nm as i128 - a.x_nm as i128) * (c.y_nm as i128 - a.y_nm as i128)
        - (b.y_nm as i128 - a.y_nm as i128) * (c.x_nm as i128 - a.x_nm as i128)
}

fn point_on_segment(point: Point, start: Point, end: Point) -> bool {
    point.x_nm >= start.x_nm.min(end.x_nm)
        && point.x_nm <= start.x_nm.max(end.x_nm)
        && point.y_nm >= start.y_nm.min(end.y_nm)
        && point.y_nm <= start.y_nm.max(end.y_nm)
}

fn point_in_rect(point: Point, min: Point, max: Point) -> bool {
    point.x_nm >= min.x_nm
        && point.x_nm <= max.x_nm
        && point.y_nm >= min.y_nm
        && point.y_nm <= max.y_nm
}

fn squared_difference(left: i64, right: i64) -> i128 {
    let difference = left as i128 - right as i128;
    difference * difference
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(x: i64, y: i64) -> Point {
        Point { x_nm: x, y_nm: y }
    }

    #[test]
    fn detects_collinear_overlap_and_endpoint_contact() {
        assert!(segments_within(
            point(0, 0),
            point(10, 0),
            point(5, 0),
            point(15, 0),
            0
        ));
        assert!(segments_within(
            point(0, 0),
            point(10, 0),
            point(10, 0),
            point(10, 10),
            0
        ));
    }

    #[test]
    fn distinguishes_exact_clearance_from_a_violation() {
        assert!(!segments_closer_than(
            point(0, 0),
            point(10, 0),
            point(0, 5),
            point(10, 5),
            10
        ));
        assert!(segments_closer_than(
            point(0, 0),
            point(10, 0),
            point(0, 4),
            point(10, 4),
            10
        ));
    }

    #[test]
    fn compares_half_unit_thresholds_without_rounding() {
        assert!(points_within(point(0, 0), point(3, 4), 10));
        assert!(!points_closer_than(point(0, 0), point(3, 4), 10));
        assert!(points_closer_than(point(0, 0), point(3, 4), 11));
    }

    #[test]
    fn classifies_concave_polygon_and_boundary_exactly() {
        let polygon = [
            point(0, 0),
            point(10, 0),
            point(10, 4),
            point(4, 4),
            point(4, 10),
            point(0, 10),
        ];
        assert!(point_in_polygon(point(2, 8), &polygon));
        assert!(point_in_polygon(point(4, 7), &polygon));
        assert!(!point_in_polygon(point(8, 8), &polygon));
        assert!(polygon_is_simple(&polygon));
        assert!(!polygon_is_simple(&[
            point(0, 0),
            point(10, 10),
            point(0, 10),
            point(10, 0),
        ]));
    }
}

//! Bounded physical constraints for board and placement orchestration.
//!
//! A physical profile is a closed, versioned contract.  It is validated in
//! full before it is applied, and both board and placement application stage a
//! complete candidate so an error cannot leave a partially modified value.

use crate::{
    Board, Footprint, Keepout, Layer, MAX_BOARD_EXTENT_NM, ManufacturingRules, Nm, Point,
    placement::PlacementProblem,
};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fmt;

pub const PHYSICAL_PROFILE_SCHEMA_VERSION: u32 = 1;

/// Bounds are intentionally finite even though the wire representation uses
/// signed 64-bit integers. They keep geometry predicates and allocations well
/// inside the routing resource contract.
pub const MAX_PHYSICAL_PROFILE_COORDINATE_NM: Nm = MAX_BOARD_EXTENT_NM;
pub const MAX_PHYSICAL_PROFILE_TEXT_BYTES: usize = 1024;
pub const MAX_PHYSICAL_PROFILE_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PHYSICAL_PROFILE_ITEMS: usize = 4096;
pub const MAX_PHYSICAL_PROFILE_POLYGON_POINTS: usize = 4096;
pub const MAX_PHYSICAL_PROFILE_TOTAL_POINTS: usize = 65_536;
pub const MAX_PHYSICAL_PROFILE_ROTATION_MDEG: i64 = 360_000;
const MAX_POLYGON_EDGE_PAIR_WORK: usize = 8_500_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalConstraintProfile {
    pub schema_version: u32,
    pub id: String,
    pub revision: u32,
    pub description: String,
    pub board_width_nm: Nm,
    pub board_height_nm: Nm,
    #[serde(default)]
    pub outline: Vec<Point>,
    #[serde(default)]
    pub fixed_components: Vec<FixedComponent>,
    #[serde(default)]
    pub keepouts: Vec<ProfileKeepout>,
    #[serde(default)]
    pub manufacturing_rules: Option<ManufacturingRules>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedComponent {
    pub reference: String,
    pub x_nm: Nm,
    pub y_nm: Nm,
    #[serde(default)]
    pub rotation_mdeg: i64,
    #[serde(default)]
    pub tolerance_nm: Nm,
    #[serde(default)]
    pub keepout_width_nm: Nm,
    #[serde(default)]
    pub keepout_height_nm: Nm,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileKeepout {
    pub id: String,
    pub polygon: Vec<Point>,
    #[serde(default = "default_layers")]
    pub layers: Vec<Layer>,
    #[serde(default = "true_value")]
    pub tracks_not_allowed: bool,
    #[serde(default = "true_value")]
    pub vias_not_allowed: bool,
    #[serde(default = "true_value")]
    pub zones_not_allowed: bool,
    #[serde(default)]
    pub footprints_not_allowed: bool,
    #[serde(default)]
    pub minimum_track_width_nm: Option<Nm>,
    #[serde(default)]
    pub minimum_clearance_nm: Option<Nm>,
}

fn default_layers() -> Vec<Layer> {
    vec![Layer::Front, Layer::Back]
}

fn true_value() -> bool {
    true
}

/// Parse and fully validate one closed physical-profile document.
pub fn parse_physical_profile(source: &str) -> Result<PhysicalConstraintProfile, String> {
    const MAX_INPUT_BYTES: usize = MAX_PHYSICAL_PROFILE_TEXT_BYTES * 4096;
    if source.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "physical profile JSON exceeds the {MAX_INPUT_BYTES}-byte input limit"
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let value = deserializer
        .deserialize_any(NoDuplicateValueVisitor)
        .map_err(|error| format!("invalid physical constraint profile JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("invalid physical constraint profile JSON: {error}"))?;
    validate_json_counts(&value)?;
    let profile: PhysicalConstraintProfile = serde_json::from_value(value)
        .map_err(|error| format!("invalid physical constraint profile JSON: {error}"))?;
    validate_physical_profile(&profile)?;
    Ok(profile)
}

struct NoDuplicateValueVisitor;

struct NoDuplicateValueSeed;

impl<'de> de::DeserializeSeed<'de> for NoDuplicateValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateValueVisitor)
    }
}

impl<'de> de::Visitor<'de> for NoDuplicateValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(NoDuplicateValueSeed)? {
            values.push(value);
            if values.len() > MAX_PHYSICAL_PROFILE_ITEMS {
                return Err(de::Error::custom(
                    "physical profile JSON array exceeds item limit",
                ));
            }
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let value = map.next_value_seed(NoDuplicateValueSeed)?;
            object.insert(key, value);
            if object.len() > MAX_PHYSICAL_PROFILE_ITEMS {
                return Err(de::Error::custom(
                    "physical profile JSON object exceeds key limit",
                ));
            }
        }
        Ok(Value::Object(object))
    }
}

fn validate_json_counts(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "physical profile JSON root must be an object".to_string())?;
    if let Some(outline) = object.get("outline").and_then(Value::as_array)
        && outline.len() > MAX_PHYSICAL_PROFILE_POLYGON_POINTS
    {
        return Err("physical profile outline exceeds the point limit".into());
    }
    if let Some(fixed) = object.get("fixed_components").and_then(Value::as_array)
        && fixed.len() > MAX_PHYSICAL_PROFILE_ITEMS
    {
        return Err("physical profile fixed_components exceeds the item limit".into());
    }
    if let Some(keepouts) = object.get("keepouts").and_then(Value::as_array) {
        if keepouts.len() > MAX_PHYSICAL_PROFILE_ITEMS {
            return Err("physical profile keepouts exceeds the item limit".into());
        }
        for keepout in keepouts {
            if let Some(points) = keepout.get("polygon").and_then(Value::as_array)
                && points.len() > MAX_PHYSICAL_PROFILE_POLYGON_POINTS
            {
                return Err("physical profile keepout polygon exceeds the point limit".into());
            }
        }
    }
    Ok(())
}

pub fn validate_physical_profile(profile: &PhysicalConstraintProfile) -> Result<(), String> {
    if profile.schema_version != PHYSICAL_PROFILE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported physical profile schema_version {}; expected {}",
            profile.schema_version, PHYSICAL_PROFILE_SCHEMA_VERSION
        ));
    }
    validate_identifier(&profile.id, "profile id")?;
    if profile.revision == 0 {
        return Err("physical profile revision must be greater than zero".into());
    }
    validate_text(&profile.description, "physical profile description")?;
    validate_dimension(profile.board_width_nm, "board_width_nm", false)?;
    validate_dimension(profile.board_height_nm, "board_height_nm", false)?;

    let mut polygon_work = 0_usize;
    let mut total_points = 0_usize;
    if !profile.outline.is_empty() {
        add_point_count(&mut total_points, profile.outline.len(), "profile polygons")?;
        validate_polygon(
            &profile.outline,
            profile.board_width_nm,
            profile.board_height_nm,
            "outline",
            &mut polygon_work,
        )?;
    }

    if profile.fixed_components.len() > MAX_PHYSICAL_PROFILE_ITEMS {
        return Err("physical profile fixed_components exceeds the item limit".into());
    }
    let mut references = HashSet::<String>::with_capacity(profile.fixed_components.len());
    for component in &profile.fixed_components {
        validate_fixed_component_definition(
            component,
            profile.board_width_nm,
            profile.board_height_nm,
            &profile.outline,
            &mut references,
            &mut polygon_work,
        )?;
    }

    if profile.keepouts.len() > MAX_PHYSICAL_PROFILE_ITEMS {
        return Err("physical profile keepouts exceeds the item limit".into());
    }
    let mut keepout_ids = HashSet::with_capacity(profile.keepouts.len());
    for keepout in &profile.keepouts {
        validate_identifier(&keepout.id, "keepout id")?;
        if !keepout_ids.insert(&keepout.id) {
            return Err(format!("duplicate physical profile keepout {}", keepout.id));
        }
        add_point_count(&mut total_points, keepout.polygon.len(), "profile polygons")?;
        validate_polygon(
            &keepout.polygon,
            profile.board_width_nm,
            profile.board_height_nm,
            &format!("keepout {}", keepout.id),
            &mut polygon_work,
        )?;
        if !profile.outline.is_empty() {
            validate_geometry_inside_outline(
                &keepout.polygon,
                &profile.outline,
                &format!("keepout {}", keepout.id),
                &mut polygon_work,
            )?;
        }
        validate_keepout(keepout)?;
    }
    if let Some(rules) = &profile.manufacturing_rules {
        validate_manufacturing_rules(rules)?;
    }
    Ok(())
}

fn add_point_count(total: &mut usize, count: usize, label: &str) -> Result<(), String> {
    *total = total
        .checked_add(count)
        .ok_or_else(|| format!("{label} point count overflow"))?;
    if *total > MAX_PHYSICAL_PROFILE_TOTAL_POINTS {
        return Err(format!(
            "{label} exceed the {}-point total limit",
            MAX_PHYSICAL_PROFILE_TOTAL_POINTS
        ));
    }
    Ok(())
}

fn validate_fixed_component_definition(
    component: &FixedComponent,
    width: Nm,
    height: Nm,
    outline: &[Point],
    references: &mut HashSet<String>,
    polygon_work: &mut usize,
) -> Result<(), String> {
    validate_identifier(&component.reference, "fixed component reference")?;
    if !references.insert(component.reference.clone()) {
        return Err(format!("duplicate fixed component {}", component.reference));
    }
    if !in_bounds(component.x_nm, width) || !in_bounds(component.y_nm, height) {
        return Err(format!(
            "fixed component {} position is outside the board",
            component.reference
        ));
    }
    if !outline.is_empty() && !point_in_polygon(component_point(component), outline) {
        return Err(format!(
            "fixed component {} position is outside profile outline",
            component.reference
        ));
    }
    if component.rotation_mdeg.unsigned_abs() > MAX_PHYSICAL_PROFILE_ROTATION_MDEG as u64 {
        return Err(format!(
            "fixed component {} rotation is outside +/-360 degrees",
            component.reference
        ));
    }
    validate_nonnegative_bounded(component.tolerance_nm, "fixed component tolerance")?;
    let width_zero = component.keepout_width_nm == 0;
    let height_zero = component.keepout_height_nm == 0;
    if width_zero != height_zero {
        return Err(format!(
            "fixed component {} keepout width and height must both be zero or both be positive",
            component.reference
        ));
    }
    if component.keepout_width_nm < 0 || component.keepout_height_nm < 0 {
        return Err(format!(
            "fixed component {} keepout dimensions must not be negative",
            component.reference
        ));
    }
    validate_nonnegative_bounded(component.keepout_width_nm, "fixed component keepout width")?;
    validate_nonnegative_bounded(
        component.keepout_height_nm,
        "fixed component keepout height",
    )?;
    if component.keepout_width_nm > width || component.keepout_height_nm > height {
        return Err(format!(
            "fixed component {} keepout dimensions exceed the board",
            component.reference
        ));
    }
    let half_width = i128::from(component.keepout_width_nm) / 2;
    let half_height = i128::from(component.keepout_height_nm) / 2;
    let upper_width = i128::from(component.keepout_width_nm) - half_width;
    let upper_height = i128::from(component.keepout_height_nm) - half_height;
    if i128::from(component.x_nm) - half_width < 0
        || i128::from(component.x_nm) + upper_width > i128::from(width)
        || i128::from(component.y_nm) - half_height < 0
        || i128::from(component.y_nm) + upper_height > i128::from(height)
    {
        return Err(format!(
            "fixed component {} keepout exceeds board bounds",
            component.reference
        ));
    }
    if !outline.is_empty() {
        let keepout = fixed_component_keepout(component);
        validate_geometry_inside_outline(
            &keepout,
            outline,
            &format!("fixed component {} keepout", component.reference),
            polygon_work,
        )?;
    }
    Ok(())
}

fn validate_keepout(keepout: &ProfileKeepout) -> Result<(), String> {
    if keepout.layers.is_empty() || keepout.layers.len() > 32 {
        return Err(format!(
            "keepout {} must declare one to 32 copper layers",
            keepout.id
        ));
    }
    let mut layers = HashSet::with_capacity(keepout.layers.len());
    for layer in &keepout.layers {
        if !layers.insert(*layer) {
            return Err(format!(
                "keepout {} must declare unique copper layers",
                keepout.id
            ));
        }
    }
    if !(keepout.tracks_not_allowed
        || keepout.vias_not_allowed
        || keepout.zones_not_allowed
        || keepout.footprints_not_allowed
        || keepout.minimum_track_width_nm.is_some()
        || keepout.minimum_clearance_nm.is_some())
    {
        return Err(format!("keepout {} has no active restriction", keepout.id));
    }
    if let Some(value) = keepout.minimum_track_width_nm {
        validate_dimension(value, "keepout minimum_track_width_nm", false)?;
    }
    if let Some(value) = keepout.minimum_clearance_nm {
        validate_nonnegative_bounded(value, "keepout minimum_clearance_nm")?;
    }
    Ok(())
}

fn validate_polygon(
    polygon: &[Point],
    width: Nm,
    height: Nm,
    label: &str,
    work: &mut usize,
) -> Result<(), String> {
    if polygon.len() < 3 {
        return Err(format!("{label} must contain at least three points"));
    }
    if polygon.len() > MAX_PHYSICAL_PROFILE_POLYGON_POINTS {
        return Err(format!(
            "{label} exceeds the {}-point limit",
            MAX_PHYSICAL_PROFILE_POLYGON_POINTS
        ));
    }
    let mut points = HashSet::with_capacity(polygon.len());
    for point in polygon {
        if !in_bounds(point.x_nm, width) || !in_bounds(point.y_nm, height) {
            return Err(format!("{label} must remain inside board dimensions"));
        }
        if !points.insert(*point) {
            return Err(format!("{label} contains a repeated point"));
        }
    }
    let mut area = 0_i128;
    for index in 0..polygon.len() {
        let next = (index + 1) % polygon.len();
        area = area
            .checked_add(
                i128::from(polygon[index].x_nm) * i128::from(polygon[next].y_nm)
                    - i128::from(polygon[next].x_nm) * i128::from(polygon[index].y_nm),
            )
            .ok_or_else(|| format!("{label} area calculation overflow"))?;
    }
    if area == 0 {
        return Err(format!("{label} must have non-zero area"));
    }
    for left in 0..polygon.len() {
        let left_next = (left + 1) % polygon.len();
        for right in left + 1..polygon.len() {
            let right_next = (right + 1) % polygon.len();
            if left == right || left_next == right || right_next == left {
                continue;
            }
            *work = work
                .checked_add(1)
                .ok_or_else(|| format!("{label} topology work overflow"))?;
            if *work > MAX_POLYGON_EDGE_PAIR_WORK {
                return Err(format!("{label} exceeds polygon topology work limit"));
            }
            if segments_intersect(
                polygon[left],
                polygon[left_next],
                polygon[right],
                polygon[right_next],
            ) {
                return Err(format!("{label} is self-intersecting"));
            }
        }
    }
    Ok(())
}

fn orientation(a: Point, b: Point, c: Point) -> i128 {
    (i128::from(b.x_nm) - i128::from(a.x_nm)) * (i128::from(c.y_nm) - i128::from(a.y_nm))
        - (i128::from(b.y_nm) - i128::from(a.y_nm)) * (i128::from(c.x_nm) - i128::from(a.x_nm))
}

fn on_segment(a: Point, b: Point, p: Point) -> bool {
    p.x_nm >= a.x_nm.min(b.x_nm)
        && p.x_nm <= a.x_nm.max(b.x_nm)
        && p.y_nm >= a.y_nm.min(b.y_nm)
        && p.y_nm <= a.y_nm.max(b.y_nm)
}

fn segments_intersect(a: Point, b: Point, c: Point, d: Point) -> bool {
    let ab_c = orientation(a, b, c);
    let ab_d = orientation(a, b, d);
    let cd_a = orientation(c, d, a);
    let cd_b = orientation(c, d, b);
    if ab_c == 0 && on_segment(a, b, c)
        || ab_d == 0 && on_segment(a, b, d)
        || cd_a == 0 && on_segment(c, d, a)
        || cd_b == 0 && on_segment(c, d, b)
    {
        return true;
    }
    (ab_c > 0) != (ab_d > 0) && (cd_a > 0) != (cd_b > 0)
}

fn point_in_polygon(point: Point, polygon: &[Point]) -> bool {
    if polygon.len() < 3 {
        return false;
    }
    let mut winding = 0_i32;
    for index in 0..polygon.len() {
        let start = polygon[index];
        let end = polygon[(index + 1) % polygon.len()];
        if orientation(start, end, point) == 0 && on_segment(start, end, point) {
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

fn component_point(component: &FixedComponent) -> Point {
    Point {
        x_nm: component.x_nm,
        y_nm: component.y_nm,
    }
}

fn fixed_component_keepout(component: &FixedComponent) -> Vec<Point> {
    let half_width = component.keepout_width_nm / 2;
    let half_height = component.keepout_height_nm / 2;
    rectangle(
        component.x_nm - half_width,
        component.y_nm - half_height,
        component.x_nm + (component.keepout_width_nm - half_width),
        component.y_nm + (component.keepout_height_nm - half_height),
    )
}

/// Validate profile geometry against the effective outline and cutouts of the
/// board being modified.  A profile with no declared outline inherits the
/// board's existing outline (or the board rectangle when it has none).
fn validate_profile_geometry_against_board(
    board: &Board,
    profile: &PhysicalConstraintProfile,
) -> Result<(), String> {
    let outline = if profile.outline.len() >= 3 {
        profile.outline.clone()
    } else if !board.outline.is_empty() {
        board.outline.clone()
    } else {
        rectangle(0, 0, profile.board_width_nm, profile.board_height_nm)
    };
    let mut work = 0_usize;
    validate_polygon(
        &outline,
        profile.board_width_nm,
        profile.board_height_nm,
        "board effective outline",
        &mut work,
    )?;
    for (index, cutout) in board.cutouts.iter().enumerate() {
        validate_polygon(
            cutout,
            profile.board_width_nm,
            profile.board_height_nm,
            &format!("board cutout {index}"),
            &mut work,
        )?;
        validate_geometry_inside_outline(
            cutout,
            &outline,
            &format!("board cutout {index}"),
            &mut work,
        )?;
    }
    for component in &profile.fixed_components {
        let point = component_point(component);
        validate_shape_against_board(
            std::slice::from_ref(&point),
            &outline,
            &board.cutouts,
            &format!("fixed component {} position", component.reference),
            &mut work,
        )?;
        if let Some(footprint) = board
            .footprints
            .iter()
            .find(|footprint| footprint.reference == component.reference)
        {
            validate_shape_against_board(
                std::slice::from_ref(&footprint.position),
                &outline,
                &board.cutouts,
                &format!("fixed component {} board position", component.reference),
                &mut work,
            )?;
        }
        if component.keepout_width_nm != 0 {
            let keepout = fixed_component_keepout(component);
            validate_shape_against_board(
                &keepout,
                &outline,
                &board.cutouts,
                &format!("fixed component {} keepout", component.reference),
                &mut work,
            )?;
        }
    }
    for keepout in &profile.keepouts {
        validate_shape_against_board(
            &keepout.polygon,
            &outline,
            &board.cutouts,
            &format!("keepout {}", keepout.id),
            &mut work,
        )?;
    }
    Ok(())
}

fn validate_shape_against_board(
    shape: &[Point],
    outline: &[Point],
    cutouts: &[Vec<Point>],
    label: &str,
    work: &mut usize,
) -> Result<(), String> {
    if shape.len() > 1 {
        validate_geometry_inside_outline(shape, outline, label, work)?;
    } else if shape
        .first()
        .is_none_or(|point| !point_in_polygon(*point, outline))
    {
        return Err(format!("{label} must remain inside board outline"));
    }
    for cutout in cutouts {
        validate_geometry_outside_cutout(shape, cutout, label, work)?;
    }
    Ok(())
}

fn validate_geometry_inside_outline(
    shape: &[Point],
    outline: &[Point],
    label: &str,
    work: &mut usize,
) -> Result<(), String> {
    for point in shape {
        if !point_in_polygon(*point, outline) {
            return Err(format!("{label} must remain inside profile outline"));
        }
    }
    for index in 0..shape.len() {
        let next = (index + 1) % shape.len();
        validate_segment_inside_outline(shape[index], shape[next], outline, label, work)?;
    }
    Ok(())
}

fn validate_geometry_outside_cutout(
    shape: &[Point],
    cutout: &[Point],
    label: &str,
    work: &mut usize,
) -> Result<(), String> {
    if shape.iter().any(|point| point_in_polygon(*point, cutout)) {
        return Err(format!("{label} intersects a board cutout"));
    }
    if shape.len() >= 3 && cutout.iter().any(|point| point_in_polygon(*point, shape)) {
        return Err(format!("{label} intersects a board cutout"));
    }
    for index in 0..shape.len() {
        let next = (index + 1) % shape.len();
        for edge in 0..cutout.len() {
            let edge_next = (edge + 1) % cutout.len();
            charge_polygon_work(work, label)?;
            if segments_intersect(shape[index], shape[next], cutout[edge], cutout[edge_next]) {
                return Err(format!("{label} intersects a board cutout"));
            }
        }
    }
    Ok(())
}

fn charge_polygon_work(work: &mut usize, label: &str) -> Result<(), String> {
    *work = work
        .checked_add(1)
        .ok_or_else(|| format!("{label} topology work overflow"))?;
    if *work > MAX_POLYGON_EDGE_PAIR_WORK {
        return Err(format!("{label} exceeds polygon topology work limit"));
    }
    Ok(())
}

fn validate_segment_inside_outline(
    start: Point,
    end: Point,
    outline: &[Point],
    label: &str,
    work: &mut usize,
) -> Result<(), String> {
    if !point_in_polygon(start, outline) || !point_in_polygon(end, outline) {
        return Err(format!("{label} must remain inside profile outline"));
    }
    let mut events = vec![Rational::integer(0), Rational::integer(1)];
    for index in 0..outline.len() {
        let next = (index + 1) % outline.len();
        charge_polygon_work(work, label)?;
        append_segment_intersection_events(start, end, outline[index], outline[next], &mut events)?;
    }
    // Winding-rule ray crossings can change when the segment passes an
    // outline vertex's horizontal level. Include those parameters so every
    // open interval has a stable classification.
    for vertex in outline {
        charge_polygon_work(work, label)?;
        append_horizontal_intersection_event(start, end, vertex.y_nm, &mut events)?;
    }
    events.sort_unstable_by(Rational::cmp);
    events.dedup_by(|left, right| left.cmp(right).is_eq());
    for pair in events.windows(2) {
        if pair[0].cmp(&pair[1]).is_eq() {
            continue;
        }
        if !point_in_polygon_on_interval(start, end, pair[0], outline)? {
            return Err(format!("{label} crosses outside profile outline"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Rational {
    num: i128,
    den: i128,
}

impl Rational {
    fn integer(value: i128) -> Self {
        Self { num: value, den: 1 }
    }

    fn new(mut num: i128, mut den: i128) -> Result<Self, String> {
        if den == 0 {
            return Err("profile outline geometry has a zero intersection denominator".into());
        }
        if den < 0 {
            num = num
                .checked_neg()
                .ok_or_else(|| "profile outline geometry arithmetic overflow".to_string())?;
            den = den
                .checked_neg()
                .ok_or_else(|| "profile outline geometry arithmetic overflow".to_string())?;
        }
        let divisor = gcd_u128(num.unsigned_abs(), den as u128);
        Ok(Self {
            num: num
                / i128::try_from(divisor)
                    .map_err(|_| "profile outline geometry arithmetic overflow")?,
            den: den
                / i128::try_from(divisor)
                    .map_err(|_| "profile outline geometry arithmetic overflow")?,
        })
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Intersection parameters are formed from coordinate cross products
        // bounded by +/-2e18; their pairwise products remain within i128.
        (self.num * other.den).cmp(&(other.num * self.den))
    }
}

fn gcd_u128(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

fn cross_vectors(a: Point, b: Point) -> i128 {
    i128::from(a.x_nm) * i128::from(b.y_nm) - i128::from(a.y_nm) * i128::from(b.x_nm)
}

fn vector_between(start: Point, end: Point) -> Point {
    Point {
        x_nm: end.x_nm - start.x_nm,
        y_nm: end.y_nm - start.y_nm,
    }
}

fn append_segment_intersection_events(
    start: Point,
    end: Point,
    edge_start: Point,
    edge_end: Point,
    events: &mut Vec<Rational>,
) -> Result<(), String> {
    let segment = vector_between(start, end);
    let edge = vector_between(edge_start, edge_end);
    let offset = vector_between(start, edge_start);
    let denominator = cross_vectors(segment, edge);
    if denominator != 0 {
        let mut segment_num = cross_vectors(offset, edge);
        let mut edge_num = cross_vectors(offset, segment);
        let mut denominator = denominator;
        if denominator < 0 {
            denominator = denominator
                .checked_neg()
                .ok_or_else(|| "profile outline geometry arithmetic overflow".to_string())?;
            segment_num = segment_num
                .checked_neg()
                .ok_or_else(|| "profile outline geometry arithmetic overflow".to_string())?;
            edge_num = edge_num
                .checked_neg()
                .ok_or_else(|| "profile outline geometry arithmetic overflow".to_string())?;
        }
        if (0..=denominator).contains(&segment_num) && (0..=denominator).contains(&edge_num) {
            events.push(Rational::new(segment_num, denominator)?);
        }
        return Ok(());
    }
    if cross_vectors(offset, segment) != 0 {
        return Ok(());
    }
    for point in [edge_start, edge_end] {
        if on_segment(start, end, point) {
            let (delta, distance) = if segment.x_nm != 0 {
                (
                    i128::from(segment.x_nm),
                    i128::from(point.x_nm - start.x_nm),
                )
            } else {
                (
                    i128::from(segment.y_nm),
                    i128::from(point.y_nm - start.y_nm),
                )
            };
            events.push(Rational::new(distance, delta)?);
        }
    }
    Ok(())
}

fn append_horizontal_intersection_event(
    start: Point,
    end: Point,
    y_nm: Nm,
    events: &mut Vec<Rational>,
) -> Result<(), String> {
    let delta = i128::from(end.y_nm - start.y_nm);
    if delta == 0 {
        return Ok(());
    }
    let distance = i128::from(y_nm - start.y_nm);
    if (0..=delta).contains(&distance) || (delta..=0).contains(&distance) {
        events.push(Rational::new(distance, delta)?);
    }
    Ok(())
}

fn point_in_polygon_on_interval(
    start: Point,
    end: Point,
    left: Rational,
    polygon: &[Point],
) -> Result<bool, String> {
    let segment = vector_between(start, end);
    let mut winding = 0_i32;
    for index in 0..polygon.len() {
        let edge_start = polygon[index];
        let edge_end = polygon[(index + 1) % polygon.len()];
        let edge_dx = i128::from(edge_end.x_nm - edge_start.x_nm);
        let edge_dy = i128::from(edge_end.y_nm - edge_start.y_nm);
        let base_orientation = orientation(edge_start, edge_end, start);
        let slope_orientation = edge_dx
            .checked_mul(i128::from(segment.y_nm))
            .and_then(|value| {
                edge_dy
                    .checked_mul(i128::from(segment.x_nm))
                    .and_then(|other| value.checked_sub(other))
            })
            .ok_or_else(|| "profile outline geometry arithmetic overflow".to_string())?;
        if base_orientation == 0
            && slope_orientation == 0
            && linear_segment_on_edge_interval(start, segment, edge_start, edge_end, left)?
        {
            return Ok(true);
        }
        let orientation_sign = linear_sign(base_orientation, slope_orientation, left)?;
        let start_y_sign = linear_sign(
            i128::from(start.y_nm - edge_start.y_nm),
            i128::from(segment.y_nm),
            left,
        )?;
        let end_y_sign = linear_sign(
            i128::from(start.y_nm - edge_end.y_nm),
            i128::from(segment.y_nm),
            left,
        )?;
        if start_y_sign >= 0 && end_y_sign < 0 && orientation_sign > 0 {
            winding += 1;
        } else if start_y_sign < 0 && end_y_sign >= 0 && orientation_sign < 0 {
            winding -= 1;
        }
    }
    Ok(winding != 0)
}

fn linear_sign(base: i128, slope: i128, left: Rational) -> Result<i8, String> {
    let value = base
        .checked_mul(left.den)
        .and_then(|value| {
            slope
                .checked_mul(left.num)
                .and_then(|other| value.checked_add(other))
        })
        .ok_or_else(|| "profile outline geometry arithmetic overflow".to_string())?;
    if value > 0 {
        Ok(1)
    } else if value < 0 {
        Ok(-1)
    } else if slope > 0 {
        // The open interval lies immediately to the right of `left`.
        Ok(1)
    } else if slope < 0 {
        Ok(-1)
    } else {
        Ok(0)
    }
}

fn linear_segment_on_edge_interval(
    start: Point,
    segment: Point,
    edge_start: Point,
    edge_end: Point,
    left: Rational,
) -> Result<bool, String> {
    let min_x = edge_start.x_nm.min(edge_end.x_nm);
    let max_x = edge_start.x_nm.max(edge_end.x_nm);
    let min_y = edge_start.y_nm.min(edge_end.y_nm);
    let max_y = edge_start.y_nm.max(edge_end.y_nm);
    let x_lower = linear_sign(
        i128::from(start.x_nm - min_x),
        i128::from(segment.x_nm),
        left,
    )?;
    let x_upper = linear_sign(
        i128::from(start.x_nm - max_x),
        i128::from(segment.x_nm),
        left,
    )?;
    let y_lower = linear_sign(
        i128::from(start.y_nm - min_y),
        i128::from(segment.y_nm),
        left,
    )?;
    let y_upper = linear_sign(
        i128::from(start.y_nm - max_y),
        i128::from(segment.y_nm),
        left,
    )?;
    Ok(x_lower >= 0 && x_upper <= 0 && y_lower >= 0 && y_upper <= 0)
}

fn validate_manufacturing_rules(rules: &ManufacturingRules) -> Result<(), String> {
    for (name, value) in [
        ("minimum_track_width_nm", rules.minimum_track_width_nm),
        ("minimum_drill_nm", rules.minimum_drill_nm),
        ("minimum_annular_ring_nm", rules.minimum_annular_ring_nm),
        ("board_thickness_nm", rules.board_thickness_nm),
    ] {
        validate_dimension(value, name, false)?;
    }
    for (name, value) in [
        ("minimum_clearance_nm", rules.minimum_clearance_nm),
        ("minimum_copper_to_edge_nm", rules.minimum_copper_to_edge_nm),
        ("minimum_drill_to_drill_nm", rules.minimum_drill_to_drill_nm),
    ] {
        validate_nonnegative_bounded(value, name)?;
    }
    if !(1..=100).contains(&rules.maximum_via_aspect_ratio) {
        return Err("maximum_via_aspect_ratio must be between 1 and 100".into());
    }
    if rules.minimum_trace_angle_deg > 180 {
        return Err("minimum_trace_angle_deg must be between 0 and 180".into());
    }
    Ok(())
}

fn validate_dimension(value: Nm, name: &str, allow_zero: bool) -> Result<(), String> {
    if (!allow_zero && value <= 0) || (allow_zero && value < 0) {
        return Err(format!("{name} must not be negative or zero"));
    }
    if value > MAX_PHYSICAL_PROFILE_COORDINATE_NM {
        return Err(format!(
            "{name} must not exceed {MAX_PHYSICAL_PROFILE_COORDINATE_NM}"
        ));
    }
    Ok(())
}

fn validate_nonnegative_bounded(value: Nm, name: &str) -> Result<(), String> {
    if value < 0 {
        return Err(format!("{name} must not be negative"));
    }
    if value > MAX_PHYSICAL_PROFILE_COORDINATE_NM {
        return Err(format!(
            "{name} must not exceed {MAX_PHYSICAL_PROFILE_COORDINATE_NM}"
        ));
    }
    Ok(())
}

fn in_bounds(value: Nm, upper: Nm) -> bool {
    (0..=upper).contains(&value)
}

fn validate_identifier(value: &str, label: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(format!("{label} must be a non-empty safe identifier"));
    };
    if value.len() > MAX_PHYSICAL_PROFILE_IDENTIFIER_BYTES
        || !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("{label} must be a non-empty safe identifier"));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > MAX_PHYSICAL_PROFILE_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must contain 1 to {MAX_PHYSICAL_PROFILE_TEXT_BYTES} non-control bytes"
        ));
    }
    Ok(())
}

/// Validate and atomically inject a profile into a board.
pub fn apply_physical_profile(
    board: &mut Board,
    profile: &PhysicalConstraintProfile,
) -> Result<(), String> {
    validate_physical_profile(profile)?;
    if board.width_nm != profile.board_width_nm || board.height_nm != profile.board_height_nm {
        return Err(format!(
            "board dimensions {}x{} nm do not match physical profile {}x{} nm",
            board.width_nm, board.height_nm, profile.board_width_nm, profile.board_height_nm
        ));
    }
    if !profile.outline.is_empty() && !board.outline.is_empty() && board.outline != profile.outline
    {
        return Err("board outline does not match physical constraint profile".into());
    }
    let mut footprint_indices = HashMap::<&str, usize>::with_capacity(board.footprints.len());
    for (index, footprint) in board.footprints.iter().enumerate() {
        if footprint_indices
            .insert(footprint.reference.as_str(), index)
            .is_some()
        {
            return Err(format!(
                "board contains duplicate footprint {}",
                footprint.reference
            ));
        }
    }
    for component in &profile.fixed_components {
        let index = footprint_indices
            .get(component.reference.as_str())
            .copied()
            .ok_or_else(|| {
                format!(
                    "fixed component {} is missing from board",
                    component.reference
                )
            })?;
        validate_fixed_component(&board.footprints[index], component)?;
    }
    for keepout in &profile.keepouts {
        if keepout
            .layers
            .iter()
            .any(|layer| !board.copper_layers.contains(layer))
        {
            return Err(format!(
                "physical profile keepout {} references an undeclared board layer",
                keepout.id
            ));
        }
    }
    validate_profile_geometry_against_board(board, profile)?;
    if let Some(rules) = &profile.manufacturing_rules
        && let Some(existing) = &board.manufacturing_rules
    {
        validate_manufacturing_non_relaxation(existing, rules)?;
    }

    let mut candidate = board.clone();
    if !profile.outline.is_empty() {
        candidate.outline = profile.outline.clone();
    }
    for component in &profile.fixed_components {
        if component.keepout_width_nm == 0 {
            continue;
        }
        candidate.keepouts.push(Keepout {
            polygon: fixed_component_keepout(component),
            layers: candidate.copper_layers.clone(),
            net_id: None,
            tracks_not_allowed: true,
            vias_not_allowed: true,
            zones_not_allowed: true,
            footprints_not_allowed: false,
            minimum_track_width_nm: None,
            minimum_clearance_nm: None,
        });
    }
    candidate
        .keepouts
        .extend(profile.keepouts.iter().map(|keepout| Keepout {
            polygon: keepout.polygon.clone(),
            layers: keepout.layers.clone(),
            net_id: None,
            tracks_not_allowed: keepout.tracks_not_allowed,
            vias_not_allowed: keepout.vias_not_allowed,
            zones_not_allowed: keepout.zones_not_allowed,
            footprints_not_allowed: keepout.footprints_not_allowed,
            minimum_track_width_nm: keepout.minimum_track_width_nm,
            minimum_clearance_nm: keepout.minimum_clearance_nm,
        }));
    if let Some(rules) = &profile.manufacturing_rules {
        apply_manufacturing_rules(&mut candidate, rules)?;
    }
    *board = candidate;
    Ok(())
}

/// Apply fixed profile coordinates to a placement problem atomically.
pub fn apply_physical_profile_to_placement(
    problem: &mut PlacementProblem,
    profile: &PhysicalConstraintProfile,
) -> Result<(), String> {
    validate_physical_profile(profile)?;
    if problem.width_nm != profile.board_width_nm || problem.height_nm != profile.board_height_nm {
        return Err(format!(
            "placement dimensions {}x{} nm do not match physical profile {}x{} nm",
            problem.width_nm, problem.height_nm, profile.board_width_nm, profile.board_height_nm
        ));
    }
    let mut indices = HashMap::<&str, usize>::with_capacity(problem.components.len());
    for (index, component) in problem.components.iter().enumerate() {
        if indices
            .insert(component.reference.as_str(), index)
            .is_some()
        {
            return Err(format!(
                "placement problem contains duplicate component {}",
                component.reference
            ));
        }
    }
    let mut rotations = Vec::with_capacity(profile.fixed_components.len());
    for component in &profile.fixed_components {
        let index = indices
            .get(component.reference.as_str())
            .copied()
            .ok_or_else(|| {
                format!(
                    "fixed component {} is missing from placement",
                    component.reference
                )
            })?;
        if component.rotation_mdeg % 1000 != 0 {
            return Err(format!(
                "fixed component {} rotation must be a whole degree for placement",
                component.reference
            ));
        }
        let rotation_deg = component.rotation_mdeg.rem_euclid(360_000) / 1000;
        let rotation_deg = u16::try_from(rotation_deg).map_err(|_| {
            format!(
                "fixed component {} rotation is not placement-compatible",
                component.reference
            )
        })?;
        if !problem.components[index].allowed_rotations.is_empty()
            && !problem.components[index]
                .allowed_rotations
                .contains(&rotation_deg)
        {
            return Err(format!(
                "fixed component {} rotation is not in the placement allowed rotations",
                component.reference
            ));
        }
        rotations.push((index, rotation_deg));
    }
    let mut candidate = problem.clone();
    for (component, (index, rotation_deg)) in profile.fixed_components.iter().zip(rotations) {
        candidate.components[index].position = Some(Point {
            x_nm: component.x_nm,
            y_nm: component.y_nm,
        });
        candidate.components[index].rotation_deg = rotation_deg;
        candidate.components[index].fixed = true;
    }
    *problem = candidate;
    Ok(())
}

fn validate_fixed_component(
    footprint: &Footprint,
    component: &FixedComponent,
) -> Result<(), String> {
    let x_distance =
        (i128::from(footprint.position.x_nm) - i128::from(component.x_nm)).unsigned_abs();
    let y_distance =
        (i128::from(footprint.position.y_nm) - i128::from(component.y_nm)).unsigned_abs();
    if x_distance > component.tolerance_nm as u128 || y_distance > component.tolerance_nm as u128 {
        return Err(format!(
            "fixed component {} position differs from profile beyond {} nm",
            component.reference, component.tolerance_nm
        ));
    }
    if !footprint.rotation_deg.is_finite() {
        return Err(format!(
            "fixed component {} board rotation is not finite",
            component.reference
        ));
    }
    let actual = footprint.rotation_deg.rem_euclid(360.0);
    let expected = (component.rotation_mdeg as f64).rem_euclid(360_000.0) / 1000.0;
    let raw_difference = (actual - expected).abs();
    let difference = raw_difference.min(360.0 - raw_difference);
    if difference > 0.0015 {
        return Err(format!(
            "fixed component {} rotation differs from profile",
            component.reference
        ));
    }
    Ok(())
}

fn rectangle(min_x: Nm, min_y: Nm, max_x: Nm, max_y: Nm) -> Vec<Point> {
    vec![
        Point {
            x_nm: min_x,
            y_nm: min_y,
        },
        Point {
            x_nm: max_x,
            y_nm: min_y,
        },
        Point {
            x_nm: max_x,
            y_nm: max_y,
        },
        Point {
            x_nm: min_x,
            y_nm: max_y,
        },
    ]
}

fn apply_manufacturing_rules(board: &mut Board, rules: &ManufacturingRules) -> Result<(), String> {
    board.rules.track_width_nm = board.rules.track_width_nm.max(rules.minimum_track_width_nm);
    board.rules.clearance_nm = board.rules.clearance_nm.max(rules.minimum_clearance_nm);
    board.rules.via_drill_nm = board.rules.via_drill_nm.max(rules.minimum_drill_nm);
    board.rules.via_diameter_nm = board.rules.via_diameter_nm.max(minimum_via_diameter(
        board.rules.via_drill_nm,
        rules.minimum_annular_ring_nm,
    )?);
    for net_class in board.net_classes.values_mut() {
        net_class.track_width_nm = net_class.track_width_nm.max(rules.minimum_track_width_nm);
        net_class.clearance_nm = net_class.clearance_nm.max(rules.minimum_clearance_nm);
        net_class.via_drill_nm = net_class.via_drill_nm.max(rules.minimum_drill_nm);
        net_class.via_diameter_nm = net_class.via_diameter_nm.max(minimum_via_diameter(
            net_class.via_drill_nm,
            rules.minimum_annular_ring_nm,
        )?);
    }
    board.manufacturing_rules = Some(rules.clone());
    Ok(())
}

fn minimum_via_diameter(drill_nm: Nm, annular_ring_nm: Nm) -> Result<Nm, String> {
    drill_nm
        .checked_add(
            annular_ring_nm
                .checked_mul(2)
                .ok_or_else(|| "manufacturing via diameter overflows".to_string())?,
        )
        .ok_or_else(|| "manufacturing via diameter overflows".to_string())
}

fn validate_manufacturing_non_relaxation(
    existing: &ManufacturingRules,
    proposed: &ManufacturingRules,
) -> Result<(), String> {
    for (name, old, new) in [
        (
            "minimum_track_width_nm",
            existing.minimum_track_width_nm,
            proposed.minimum_track_width_nm,
        ),
        (
            "minimum_clearance_nm",
            existing.minimum_clearance_nm,
            proposed.minimum_clearance_nm,
        ),
        (
            "minimum_drill_nm",
            existing.minimum_drill_nm,
            proposed.minimum_drill_nm,
        ),
        (
            "minimum_annular_ring_nm",
            existing.minimum_annular_ring_nm,
            proposed.minimum_annular_ring_nm,
        ),
        (
            "minimum_copper_to_edge_nm",
            existing.minimum_copper_to_edge_nm,
            proposed.minimum_copper_to_edge_nm,
        ),
        (
            "board_thickness_nm",
            existing.board_thickness_nm,
            proposed.board_thickness_nm,
        ),
        (
            "minimum_drill_to_drill_nm",
            existing.minimum_drill_to_drill_nm,
            proposed.minimum_drill_to_drill_nm,
        ),
        (
            "minimum_trace_angle_deg",
            i64::from(existing.minimum_trace_angle_deg),
            i64::from(proposed.minimum_trace_angle_deg),
        ),
    ] {
        if new < old {
            return Err(format!("manufacturing profile would relax existing {name}"));
        }
    }
    if proposed.maximum_via_aspect_ratio > existing.maximum_via_aspect_ratio {
        return Err("manufacturing profile would relax maximum_via_aspect_ratio".into());
    }
    if !existing.allow_via_in_pad && proposed.allow_via_in_pad {
        return Err("manufacturing profile would relax allow_via_in_pad".into());
    }
    Ok(())
}

pub fn physical_profile_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/physical-constraint-profile-v1.json",
        "title": "pcbex physical constraint profile",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "id", "revision", "description", "board_width_nm", "board_height_nm"],
        "properties": {
            "schema_version": {"const": PHYSICAL_PROFILE_SCHEMA_VERSION},
            "id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"},
            "revision": {"type": "integer", "minimum": 1, "maximum": 4294967295_u64},
            "description": {"type": "string", "minLength": 1, "maxLength": MAX_PHYSICAL_PROFILE_TEXT_BYTES, "pattern": "^\\S(?:[\\s\\S]*\\S)?$"},
            "board_width_nm": {"type": "integer", "minimum": 1, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
            "board_height_nm": {"type": "integer", "minimum": 1, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
            "outline": {"type": "array", "maxItems": MAX_PHYSICAL_PROFILE_POLYGON_POINTS, "items": {"$ref": "#/$defs/point"}, "oneOf": [
                {"maxItems": 0}, {"minItems": 3}
            ]},
            "fixed_components": {"type": "array", "maxItems": MAX_PHYSICAL_PROFILE_ITEMS, "items": {"$ref": "#/$defs/fixed_component"}},
            "keepouts": {"type": "array", "maxItems": MAX_PHYSICAL_PROFILE_ITEMS, "items": {"$ref": "#/$defs/keepout"}},
            "manufacturing_rules": {"anyOf": [{"type": "null"}, {"$ref": "#/$defs/manufacturing_rules"}]}
        },
        "$defs": {
            "point": {"type": "object", "additionalProperties": false, "required": ["x_nm", "y_nm"], "properties": {
                "x_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "y_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM}
            }},
            "fixed_component": {"type": "object", "additionalProperties": false, "required": ["reference", "x_nm", "y_nm"], "properties": {
                "reference": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"},
                "x_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "y_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "rotation_mdeg": {"type": "integer", "minimum": -360000, "maximum": 360000},
                "tolerance_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "keepout_width_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "keepout_height_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM}
            }, "oneOf": [
                {"properties": {"keepout_width_nm": {"const": 0}, "keepout_height_nm": {"const": 0}}},
                {"required": ["keepout_width_nm", "keepout_height_nm"], "properties": {"keepout_width_nm": {"minimum": 1}, "keepout_height_nm": {"minimum": 1}}}
            ]},
            "keepout": {"type": "object", "additionalProperties": false, "required": ["id", "polygon"], "properties": {
                "id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"},
                "polygon": {"type": "array", "minItems": 3, "maxItems": MAX_PHYSICAL_PROFILE_POLYGON_POINTS, "items": {"$ref": "#/$defs/point"}},
                "layers": {"type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": true, "items": {
                    "type": "string", "pattern": "^(?:F\\.Cu|B\\.Cu|In(?:[1-9]|[12][0-9]|30)\\.Cu)$"
                }},
                "tracks_not_allowed": {"type": "boolean"}, "vias_not_allowed": {"type": "boolean"},
                "zones_not_allowed": {"type": "boolean"}, "footprints_not_allowed": {"type": "boolean"},
                "minimum_track_width_nm": {"type": ["integer", "null"], "minimum": 1, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "minimum_clearance_nm": {"type": ["integer", "null"], "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM}
            }},
            "manufacturing_rules": {"type": "object", "additionalProperties": false, "required": [
                "minimum_track_width_nm", "minimum_clearance_nm", "minimum_drill_nm", "minimum_annular_ring_nm", "minimum_copper_to_edge_nm", "board_thickness_nm"
            ], "properties": {
                "minimum_track_width_nm": {"type": "integer", "minimum": 1, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "minimum_clearance_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "minimum_drill_nm": {"type": "integer", "minimum": 1, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "minimum_annular_ring_nm": {"type": "integer", "minimum": 1, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "minimum_copper_to_edge_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "board_thickness_nm": {"type": "integer", "minimum": 1, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "maximum_via_aspect_ratio": {"type": "integer", "minimum": 1, "maximum": 100},
                "minimum_drill_to_drill_nm": {"type": "integer", "minimum": 0, "maximum": MAX_PHYSICAL_PROFILE_COORDINATE_NM},
                "allow_via_in_pad": {"type": "boolean"}, "minimum_trace_angle_deg": {"type": "integer", "minimum": 0, "maximum": 180}
            }}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Board, CURRENT_SCHEMA_VERSION, Rules, ViaStrategy,
        placement::{BoardSide, Component, PlacementProblem},
    };

    fn rules() -> ManufacturingRules {
        ManufacturingRules {
            minimum_track_width_nm: 100_000,
            minimum_clearance_nm: 100_000,
            minimum_drill_nm: 150_000,
            minimum_annular_ring_nm: 180_000,
            minimum_copper_to_edge_nm: 200_000,
            board_thickness_nm: 1_600_000,
            maximum_via_aspect_ratio: 10,
            minimum_drill_to_drill_nm: 200_000,
            allow_via_in_pad: false,
            minimum_trace_angle_deg: 45,
        }
    }

    fn profile() -> PhysicalConstraintProfile {
        PhysicalConstraintProfile {
            schema_version: PHYSICAL_PROFILE_SCHEMA_VERSION,
            id: "profile-1".into(),
            revision: 1,
            description: "bounded board profile".into(),
            board_width_nm: 60_000_000,
            board_height_nm: 40_000_000,
            outline: vec![],
            fixed_components: vec![FixedComponent {
                reference: "J1".into(),
                x_nm: 5_000_000,
                y_nm: 20_000_000,
                rotation_mdeg: 90_000,
                tolerance_nm: 1_000,
                keepout_width_nm: 4_000_000,
                keepout_height_nm: 2_000_000,
            }],
            keepouts: vec![],
            manufacturing_rules: Some(rules()),
        }
    }

    fn board() -> Board {
        Board {
            schema_version: CURRENT_SCHEMA_VERSION,
            width_nm: 60_000_000,
            height_nm: 40_000_000,
            outline: vec![],
            cutouts: vec![],
            copper_layers: vec![Layer::Front, Layer::Back],
            rules: Rules {
                grid_nm: 500_000,
                track_width_nm: 80_000,
                clearance_nm: 80_000,
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
            footprints: vec![Footprint {
                reference: "J1".into(),
                position: Point {
                    x_nm: 5_000_500,
                    y_nm: 20_000_000,
                },
                rotation_deg: 90.0,
                pads: vec![],
            }],
            net_classes: Default::default(),
            differential_pairs: vec![],
            length_groups: vec![],
            escape_groups: vec![],
            manufacturing_rules: None,
            return_path_rules: vec![],
            power_net_rules: vec![],
            stackup: vec![],
            via_strategy: ViaStrategy::ThroughOnly,
            nets: vec![],
            routes: vec![],
        }
    }

    fn placement() -> PlacementProblem {
        PlacementProblem {
            width_nm: 60_000_000,
            height_nm: 40_000_000,
            grid_nm: 500_000,
            components: vec![Component {
                reference: "J1".into(),
                width_nm: 4_000_000,
                height_nm: 2_000_000,
                position: None,
                rotation_deg: 0,
                fixed: false,
                side: BoardSide::Front,
                allowed_rotations: vec![],
                allow_side_flip: false,
                courtyard: vec![],
                anchors: Default::default(),
            }],
            connections: vec![],
            constraints: vec![],
        }
    }

    fn concave_outline() -> Vec<Point> {
        vec![
            Point { x_nm: 0, y_nm: 0 },
            Point {
                x_nm: 60_000_000,
                y_nm: 0,
            },
            Point {
                x_nm: 60_000_000,
                y_nm: 40_000_000,
            },
            Point {
                x_nm: 30_000_000,
                y_nm: 40_000_000,
            },
            Point {
                x_nm: 30_000_000,
                y_nm: 20_000_000,
            },
            Point {
                x_nm: 0,
                y_nm: 20_000_000,
            },
        ]
    }

    #[test]
    fn validates_and_applies_happy_path_atomically() {
        let mut board = board();
        apply_physical_profile(&mut board, &profile()).unwrap();
        assert_eq!(board.keepouts.len(), 1);
        assert_eq!(board.rules.track_width_nm, 100_000);
        assert_eq!(board.rules.via_diameter_nm, 660_000);
        assert_eq!(board.manufacturing_rules, Some(rules()));
    }

    #[test]
    fn rejects_self_intersecting_polygon() {
        let mut candidate = profile();
        candidate.keepouts.push(ProfileKeepout {
            id: "cross".into(),
            polygon: vec![
                Point { x_nm: 1, y_nm: 1 },
                Point { x_nm: 10, y_nm: 10 },
                Point { x_nm: 1, y_nm: 10 },
                Point { x_nm: 10, y_nm: 1 },
            ],
            layers: vec![Layer::Front],
            tracks_not_allowed: true,
            vias_not_allowed: false,
            zones_not_allowed: false,
            footprints_not_allowed: false,
            minimum_track_width_nm: None,
            minimum_clearance_nm: None,
        });
        assert!(validate_physical_profile(&candidate).is_err());
    }

    #[test]
    fn rejects_fixed_component_outside_concave_profile_outline() {
        let mut candidate = profile();
        candidate.outline = concave_outline();
        candidate.fixed_components[0].x_nm = 10_000_000;
        candidate.fixed_components[0].y_nm = 30_000_000;
        candidate.fixed_components[0].keepout_width_nm = 0;
        candidate.fixed_components[0].keepout_height_nm = 0;
        let error = validate_physical_profile(&candidate).unwrap_err();
        assert!(error.contains("outside profile outline"));
    }

    #[test]
    fn rejects_keepout_edge_crossing_concave_profile_notch() {
        let mut candidate = profile();
        candidate.outline = concave_outline();
        candidate.fixed_components[0].x_nm = 10_000_000;
        candidate.fixed_components[0].y_nm = 10_000_000;
        candidate.fixed_components[0].keepout_width_nm = 0;
        candidate.fixed_components[0].keepout_height_nm = 0;
        candidate.keepouts.push(ProfileKeepout {
            id: "notch-crossing".into(),
            polygon: vec![
                Point {
                    x_nm: 10_000_000,
                    y_nm: 10_000_000,
                },
                Point {
                    x_nm: 35_000_000,
                    y_nm: 30_000_000,
                },
                Point {
                    x_nm: 50_000_000,
                    y_nm: 10_000_000,
                },
            ],
            layers: vec![Layer::Front],
            tracks_not_allowed: true,
            vias_not_allowed: false,
            zones_not_allowed: false,
            footprints_not_allowed: false,
            minimum_track_width_nm: None,
            minimum_clearance_nm: None,
        });
        let error = validate_physical_profile(&candidate).unwrap_err();
        assert!(error.contains("crosses outside profile outline"));
    }

    #[test]
    fn accepts_geometry_inside_and_on_concave_profile_outline() {
        let mut candidate = profile();
        candidate.outline = concave_outline();
        candidate.fixed_components[0].x_nm = 10_000_000;
        candidate.fixed_components[0].y_nm = 10_000_000;
        candidate.fixed_components[0].keepout_width_nm = 0;
        candidate.fixed_components[0].keepout_height_nm = 0;
        candidate.keepouts.push(ProfileKeepout {
            id: "boundary-edge".into(),
            polygon: vec![
                Point {
                    x_nm: 0,
                    y_nm: 10_000_000,
                },
                Point {
                    x_nm: 10_000_000,
                    y_nm: 10_000_000,
                },
                Point {
                    x_nm: 10_000_000,
                    y_nm: 20_000_000,
                },
                Point {
                    x_nm: 0,
                    y_nm: 20_000_000,
                },
            ],
            layers: vec![Layer::Front],
            tracks_not_allowed: true,
            vias_not_allowed: false,
            zones_not_allowed: false,
            footprints_not_allowed: false,
            minimum_track_width_nm: None,
            minimum_clearance_nm: None,
        });
        assert!(validate_physical_profile(&candidate).is_ok());
    }

    #[test]
    fn board_application_checks_existing_outline_and_cutouts() {
        let mut board_value = board();
        board_value.outline = concave_outline();
        board_value.footprints[0].position = Point {
            x_nm: 10_000_000,
            y_nm: 30_000_000,
        };
        let mut candidate = profile();
        candidate.fixed_components[0].x_nm = 10_000_000;
        candidate.fixed_components[0].y_nm = 30_000_000;
        candidate.fixed_components[0].keepout_width_nm = 0;
        candidate.fixed_components[0].keepout_height_nm = 0;
        let before = serde_json::to_value(&board_value).unwrap();
        let error = apply_physical_profile(&mut board_value, &candidate).unwrap_err();
        assert!(error.contains("board outline"));
        assert_eq!(serde_json::to_value(&board_value).unwrap(), before);

        let mut board_value = board();
        board_value.footprints[0].position = Point {
            x_nm: 10_000_000,
            y_nm: 30_000_000,
        };
        let mut candidate = profile();
        candidate.outline = concave_outline();
        candidate.fixed_components[0].x_nm = 10_000_000;
        candidate.fixed_components[0].y_nm = 10_000_000;
        candidate.fixed_components[0].tolerance_nm = 25_000_000;
        candidate.fixed_components[0].keepout_width_nm = 0;
        candidate.fixed_components[0].keepout_height_nm = 0;
        let before = serde_json::to_value(&board_value).unwrap();
        let error = apply_physical_profile(&mut board_value, &candidate).unwrap_err();
        assert!(error.contains("board position"));
        assert_eq!(serde_json::to_value(&board_value).unwrap(), before);

        let mut board_value = board();
        board_value.outline = vec![Point { x_nm: 0, y_nm: 0 }];
        let before = serde_json::to_value(&board_value).unwrap();
        let error = apply_physical_profile(&mut board_value, &profile()).unwrap_err();
        assert!(error.contains("effective outline"));
        assert_eq!(serde_json::to_value(&board_value).unwrap(), before);

        let mut board_value = board();
        board_value.cutouts.push(vec![
            Point {
                x_nm: 4_000_000,
                y_nm: 19_000_000,
            },
            Point {
                x_nm: 6_000_000,
                y_nm: 19_000_000,
            },
            Point {
                x_nm: 6_000_000,
                y_nm: 21_000_000,
            },
            Point {
                x_nm: 4_000_000,
                y_nm: 21_000_000,
            },
        ]);
        let before = serde_json::to_value(&board_value).unwrap();
        let error = apply_physical_profile(&mut board_value, &profile()).unwrap_err();
        assert!(error.contains("cutout"));
        assert_eq!(serde_json::to_value(&board_value).unwrap(), before);
    }

    #[test]
    fn rejects_partial_component_keepout() {
        let mut candidate = profile();
        candidate.fixed_components[0].keepout_height_nm = 0;
        assert!(
            validate_physical_profile(&candidate)
                .unwrap_err()
                .contains("both be zero")
        );
    }

    #[test]
    fn preserves_odd_fixed_component_keepout_dimensions() {
        let mut candidate = profile();
        candidate.fixed_components[0].keepout_width_nm = 1;
        candidate.fixed_components[0].keepout_height_nm = 1;
        assert!(validate_physical_profile(&candidate).is_ok());
        let mut board_value = board();
        apply_physical_profile(&mut board_value, &candidate).unwrap();
        assert_eq!(
            board_value.keepouts[0].polygon,
            vec![
                Point {
                    x_nm: 5_000_000,
                    y_nm: 20_000_000,
                },
                Point {
                    x_nm: 5_000_001,
                    y_nm: 20_000_000,
                },
                Point {
                    x_nm: 5_000_001,
                    y_nm: 20_000_001,
                },
                Point {
                    x_nm: 5_000_000,
                    y_nm: 20_000_001,
                },
            ]
        );
    }

    #[test]
    fn rejects_duplicate_layers_and_invalid_manufacturing_values() {
        let mut candidate = profile();
        candidate.keepouts.push(ProfileKeepout {
            id: "k".into(),
            polygon: vec![
                Point { x_nm: 1, y_nm: 1 },
                Point { x_nm: 10, y_nm: 1 },
                Point { x_nm: 10, y_nm: 10 },
            ],
            layers: vec![Layer::Front, Layer::Front],
            tracks_not_allowed: true,
            vias_not_allowed: false,
            zones_not_allowed: false,
            footprints_not_allowed: false,
            minimum_track_width_nm: None,
            minimum_clearance_nm: None,
        });
        assert!(
            validate_physical_profile(&candidate)
                .unwrap_err()
                .contains("unique")
        );
        let mut invalid_rules = rules();
        invalid_rules.minimum_clearance_nm = -1;
        candidate.keepouts.clear();
        candidate.manufacturing_rules = Some(invalid_rules);
        assert!(validate_physical_profile(&candidate).is_err());
    }

    #[test]
    fn rejects_duplicate_json_keys_and_bounds() {
        let duplicate = r#"{"schema_version":1,"schema_version":1,"id":"p","revision":1,"description":"x","board_width_nm":1,"board_height_nm":1}"#;
        assert!(
            parse_physical_profile(duplicate)
                .unwrap_err()
                .contains("duplicate JSON object key")
        );
        let mut candidate = profile();
        candidate.board_width_nm = MAX_PHYSICAL_PROFILE_COORDINATE_NM + 1;
        assert!(validate_physical_profile(&candidate).is_err());
    }

    #[test]
    fn board_application_is_atomic_on_missing_component_and_relaxation() {
        let mut board_value = board();
        let before = serde_json::to_value(&board_value).unwrap();
        let mut missing = profile();
        missing.fixed_components[0].reference = "J2".into();
        assert!(apply_physical_profile(&mut board_value, &missing).is_err());
        assert_eq!(serde_json::to_value(&board_value).unwrap(), before);

        let mut board_value = board();
        let mut existing = rules();
        existing.minimum_track_width_nm = 200_000;
        board_value.manufacturing_rules = Some(existing);
        let before = serde_json::to_value(&board_value).unwrap();
        assert!(apply_physical_profile(&mut board_value, &profile()).is_err());
        assert_eq!(serde_json::to_value(&board_value).unwrap(), before);
    }

    #[test]
    fn placement_application_locks_exact_position_and_rotation() {
        let mut problem = placement();
        apply_physical_profile_to_placement(&mut problem, &profile()).unwrap();
        let component = &problem.components[0];
        assert_eq!(
            component.position,
            Some(Point {
                x_nm: 5_000_000,
                y_nm: 20_000_000
            })
        );
        assert_eq!(component.rotation_deg, 90);
        assert!(component.fixed);
    }

    #[test]
    fn placement_application_rejects_fractional_rotation_atomically() {
        let mut problem = placement();
        let before = serde_json::to_value(&problem).unwrap();
        let mut candidate = profile();
        candidate.fixed_components[0].rotation_mdeg = 90_001;
        assert!(apply_physical_profile_to_placement(&mut problem, &candidate).is_err());
        assert_eq!(serde_json::to_value(&problem).unwrap(), before);
    }

    #[test]
    fn schema_exposes_closed_bounds() {
        let schema = physical_profile_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["board_width_nm"]["maximum"],
            MAX_PHYSICAL_PROFILE_COORDINATE_NM
        );
        assert_eq!(
            schema["properties"]["fixed_components"]["maxItems"],
            MAX_PHYSICAL_PROFILE_ITEMS
        );
    }
}

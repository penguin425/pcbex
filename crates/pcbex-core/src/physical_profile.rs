//! Versioned physical constraints for the headless orchestration boundary.
//!
//! A profile binds board dimensions, fixed component coordinates, explicit
//! routing keepouts, and manufacturing minimums in one reviewable JSON
//! document.  Applying a profile is fail-closed: an existing footprint must
//! already be within its declared fixed position tolerance and all injected
//! geometry must remain inside the board.

use crate::{
    Board, Footprint, Keepout, Layer, ManufacturingRules, Nm, Point, apply_manufacturing_rules,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;

pub const PHYSICAL_PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

pub fn parse_physical_profile(source: &str) -> Result<PhysicalConstraintProfile, String> {
    let profile: PhysicalConstraintProfile = serde_json::from_str(source)
        .map_err(|error| format!("invalid physical constraint profile JSON: {error}"))?;
    validate_physical_profile(&profile)?;
    Ok(profile)
}

pub fn validate_physical_profile(profile: &PhysicalConstraintProfile) -> Result<(), String> {
    if profile.schema_version != PHYSICAL_PROFILE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported physical profile schema_version {}; expected {}",
            profile.schema_version, PHYSICAL_PROFILE_SCHEMA_VERSION
        ));
    }
    validate_name(&profile.id, "profile id")?;
    if profile.revision == 0 {
        return Err("physical profile revision must be greater than zero".into());
    }
    if profile.description.trim().is_empty() || profile.description.len() > 1024 {
        return Err("physical profile description must contain 1 to 1024 bytes".into());
    }
    if profile.board_width_nm <= 0 || profile.board_height_nm <= 0 {
        return Err("physical profile board dimensions must be positive".into());
    }
    if !profile.outline.is_empty() {
        validate_polygon(
            &profile.outline,
            profile.board_width_nm,
            profile.board_height_nm,
            "outline",
        )?;
    }
    let mut references = HashSet::new();
    for component in &profile.fixed_components {
        validate_name(&component.reference, "fixed component reference")?;
        if !references.insert(&component.reference) {
            return Err(format!("duplicate fixed component {}", component.reference));
        }
        if component.x_nm < 0
            || component.y_nm < 0
            || component.x_nm > profile.board_width_nm
            || component.y_nm > profile.board_height_nm
        {
            return Err(format!(
                "fixed component {} position is outside the board",
                component.reference
            ));
        }
        if component.rotation_mdeg.unsigned_abs() > 360_000 {
            return Err(format!(
                "fixed component {} rotation is outside +/-360 degrees",
                component.reference
            ));
        }
        if component.tolerance_nm < 0
            || component.keepout_width_nm < 0
            || component.keepout_height_nm < 0
        {
            return Err(format!(
                "fixed component {} dimensions and tolerance must not be negative",
                component.reference
            ));
        }
        let half_width = component.keepout_width_nm / 2;
        let half_height = component.keepout_height_nm / 2;
        if component.keepout_width_nm > 0
            && (component.x_nm < half_width
                || component.x_nm.saturating_add(half_width) > profile.board_width_nm)
            || component.keepout_height_nm > 0
                && (component.y_nm < half_height
                    || component.y_nm.saturating_add(half_height) > profile.board_height_nm)
        {
            return Err(format!(
                "fixed component {} keepout exceeds board bounds",
                component.reference
            ));
        }
    }
    let mut keepout_ids = HashSet::new();
    for keepout in &profile.keepouts {
        validate_name(&keepout.id, "keepout id")?;
        if !keepout_ids.insert(&keepout.id) {
            return Err(format!("duplicate physical profile keepout {}", keepout.id));
        }
        validate_polygon(
            &keepout.polygon,
            profile.board_width_nm,
            profile.board_height_nm,
            &format!("keepout {}", keepout.id),
        )?;
        if keepout.layers.is_empty()
            || keepout.layers.iter().copied().collect::<HashSet<_>>().len() != keepout.layers.len()
        {
            return Err(format!(
                "keepout {} must declare unique copper layers",
                keepout.id
            ));
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
        if keepout
            .minimum_track_width_nm
            .is_some_and(|value| value <= 0)
            || keepout.minimum_clearance_nm.is_some_and(|value| value < 0)
        {
            return Err(format!("keepout {} has invalid minimum rule", keepout.id));
        }
    }
    if let Some(rules) = &profile.manufacturing_rules {
        validate_manufacturing_rules(rules)?;
    }
    Ok(())
}

/// Validate and inject a profile into a board used by the router.
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
    if !profile.outline.is_empty() {
        if !board.outline.is_empty() && board.outline != profile.outline {
            return Err("board outline does not match physical constraint profile".into());
        }
        board.outline = profile.outline.clone();
    }
    for component in &profile.fixed_components {
        let footprint = board
            .footprints
            .iter()
            .find(|footprint| footprint.reference == component.reference)
            .ok_or_else(|| {
                format!(
                    "fixed component {} is missing from board",
                    component.reference
                )
            })?;
        validate_fixed_component(footprint, component)?;
        if component.keepout_width_nm > 0 && component.keepout_height_nm > 0 {
            let half_width = component.keepout_width_nm / 2;
            let half_height = component.keepout_height_nm / 2;
            board.keepouts.push(Keepout {
                polygon: rectangle(
                    component.x_nm.saturating_sub(half_width),
                    component.y_nm.saturating_sub(half_height),
                    component.x_nm.saturating_add(half_width),
                    component.y_nm.saturating_add(half_height),
                ),
                layers: board.copper_layers.clone(),
                net_id: None,
                tracks_not_allowed: true,
                vias_not_allowed: true,
                zones_not_allowed: true,
                footprints_not_allowed: false,
                minimum_track_width_nm: None,
                minimum_clearance_nm: None,
            });
        }
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
    board
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
        apply_manufacturing_rules(board, rules);
    }
    Ok(())
}

fn validate_fixed_component(
    footprint: &Footprint,
    component: &FixedComponent,
) -> Result<(), String> {
    let tolerance = component.tolerance_nm;
    let x_distance = (footprint.position.x_nm as i128 - component.x_nm as i128).unsigned_abs();
    let y_distance = (footprint.position.y_nm as i128 - component.y_nm as i128).unsigned_abs();
    if x_distance > tolerance as u128 || y_distance > tolerance as u128 {
        return Err(format!(
            "fixed component {} position differs from profile beyond {} nm",
            component.reference, tolerance
        ));
    }
    let actual_mdeg = (footprint.rotation_deg * 1000.0).round() as i64;
    if (actual_mdeg - component.rotation_mdeg).unsigned_abs() > 1 {
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

fn validate_polygon(polygon: &[Point], width: Nm, height: Nm, label: &str) -> Result<(), String> {
    if polygon.len() < 3 {
        return Err(format!("{label} must contain at least three points"));
    }
    if polygon
        .iter()
        .any(|point| point.x_nm < 0 || point.y_nm < 0 || point.x_nm > width || point.y_nm > height)
    {
        return Err(format!("{label} must remain inside board dimensions"));
    }
    if polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
        .any(|(left, right)| left == right)
    {
        return Err(format!("{label} contains a zero-length edge"));
    }
    let area = polygon
        .iter()
        .zip(polygon.iter().cycle().skip(1))
        .take(polygon.len())
        .map(|(left, right)| {
            left.x_nm as i128 * right.y_nm as i128 - right.x_nm as i128 * left.y_nm as i128
        })
        .sum::<i128>();
    if area == 0 {
        return Err(format!("{label} must have non-zero area"));
    }
    Ok(())
}

fn validate_manufacturing_rules(rules: &ManufacturingRules) -> Result<(), String> {
    if rules.minimum_track_width_nm <= 0
        || rules.minimum_clearance_nm < 0
        || rules.minimum_drill_nm <= 0
        || rules.minimum_annular_ring_nm <= 0
        || rules.board_thickness_nm <= 0
        || rules.maximum_via_aspect_ratio == 0
        || rules.minimum_drill_to_drill_nm < 0
        || rules.minimum_trace_angle_deg > 180
    {
        return Err("physical profile manufacturing rules are invalid".into());
    }
    Ok(())
}

fn validate_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("{label} must be a non-empty safe identifier"));
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
            "revision": {"type": "integer", "minimum": 1},
            "description": {"type": "string", "minLength": 1, "maxLength": 1024},
            "board_width_nm": {"type": "integer", "exclusiveMinimum": 0},
            "board_height_nm": {"type": "integer", "exclusiveMinimum": 0},
            "outline": {"type": "array", "items": {"$ref": "#/$defs/point"}},
            "fixed_components": {"type": "array", "items": {"$ref": "#/$defs/fixed_component"}},
            "keepouts": {"type": "array", "items": {"$ref": "#/$defs/keepout"}},
            "manufacturing_rules": {"type": ["object", "null"]}
        },
        "$defs": {
            "point": {"type": "object", "additionalProperties": false, "required": ["x_nm", "y_nm"], "properties": {"x_nm": {"type": "integer"}, "y_nm": {"type": "integer"}}},
            "fixed_component": {"type": "object", "additionalProperties": false, "required": ["reference", "x_nm", "y_nm"], "properties": {"reference": {"type": "string", "minLength": 1}, "x_nm": {"type": "integer", "minimum": 0}, "y_nm": {"type": "integer", "minimum": 0}, "rotation_mdeg": {"type": "integer"}, "tolerance_nm": {"type": "integer", "minimum": 0}, "keepout_width_nm": {"type": "integer", "minimum": 0}, "keepout_height_nm": {"type": "integer", "minimum": 0}}},
            "keepout": {"type": "object", "additionalProperties": false, "required": ["id", "polygon"], "properties": {"id": {"type": "string", "minLength": 1}, "polygon": {"type": "array", "minItems": 3, "items": {"$ref": "#/$defs/point"}}, "layers": {"type": "array", "minItems": 1, "items": {"type": "string"}}, "tracks_not_allowed": {"type": "boolean"}, "vias_not_allowed": {"type": "boolean"}, "zones_not_allowed": {"type": "boolean"}, "footprints_not_allowed": {"type": "boolean"}, "minimum_track_width_nm": {"type": ["integer", "null"], "exclusiveMinimum": 0}, "minimum_clearance_nm": {"type": ["integer", "null"], "minimum": 0}}}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CURRENT_SCHEMA_VERSION, Rules, ViaStrategy};

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
                    x_nm: 5_000_000,
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

    #[test]
    fn injects_fixed_connector_keepout_and_dfm_rules() {
        let profile = PhysicalConstraintProfile {
            schema_version: 1,
            id: "nes-60pin".into(),
            revision: 1,
            description: "NES board".into(),
            board_width_nm: 60_000_000,
            board_height_nm: 40_000_000,
            outline: vec![],
            fixed_components: vec![FixedComponent {
                reference: "J1".into(),
                x_nm: 5_000_000,
                y_nm: 20_000_000,
                rotation_mdeg: 90_000,
                tolerance_nm: 0,
                keepout_width_nm: 4_000_000,
                keepout_height_nm: 2_000_000,
            }],
            keepouts: vec![],
            manufacturing_rules: Some(ManufacturingRules {
                minimum_track_width_nm: 100_000,
                minimum_clearance_nm: 100_000,
                minimum_drill_nm: 150_000,
                minimum_annular_ring_nm: 180_000,
                minimum_copper_to_edge_nm: 200_000,
                board_thickness_nm: 1_600_000,
                maximum_via_aspect_ratio: 10,
                minimum_drill_to_drill_nm: 200_000,
                allow_via_in_pad: false,
                minimum_trace_angle_deg: 0,
            }),
        };
        let mut board = board();
        apply_physical_profile(&mut board, &profile).unwrap();
        assert_eq!(board.keepouts.len(), 1);
        assert_eq!(board.rules.track_width_nm, 100_000);
        assert!(board.manufacturing_rules.is_some());
    }

    #[test]
    fn rejects_fixed_component_drift() {
        let profile = PhysicalConstraintProfile {
            schema_version: 1,
            id: "p".into(),
            revision: 1,
            description: "p".into(),
            board_width_nm: 60_000_000,
            board_height_nm: 40_000_000,
            outline: vec![],
            fixed_components: vec![FixedComponent {
                reference: "J1".into(),
                x_nm: 5_100_000,
                y_nm: 20_000_000,
                rotation_mdeg: 90_000,
                tolerance_nm: 0,
                keepout_width_nm: 0,
                keepout_height_nm: 0,
            }],
            keepouts: vec![],
            manufacturing_rules: None,
        };
        assert!(apply_physical_profile(&mut board(), &profile).is_err());
    }
}

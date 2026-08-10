//! Closed deterministic board-construction defaults.
//!
//! This profile is intentionally narrower than a fabrication capability or
//! DFM profile.  It describes only the stackup and deterministic defaults
//! needed to create a placed, unrouted KiCad board.

use super::footprint_closure::{digest_hex, parse_json_value_without_duplicate_keys};
use pcbex_core::{Layer, MAX_BOARD_EXTENT_NM, Nm, Rules};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const BOARD_CONSTRUCTION_PROFILE_V1_SCHEMA_VERSION: u32 = 1;
pub const BOARD_CONSTRUCTION_PROFILE_V1_MAX_SOURCE_BYTES: u64 = 1024 * 1024;
pub const BOARD_CONSTRUCTION_PROFILE_V1_MIN_COPPER_LAYERS: usize = 2;
pub const BOARD_CONSTRUCTION_PROFILE_V1_MAX_COPPER_LAYERS: usize = 32;
pub const BOARD_CONSTRUCTION_PROFILE_V1_MAX_TEXT_BYTES: usize = 128;
pub const BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS: u32 = 1_000_000;
pub const BOARD_CONSTRUCTION_PROFILE_V1_MAX_COST: u32 = 1_000_000;
pub const BOARD_CONSTRUCTION_PROFILE_V1_MAX_DIELECTRIC_CONSTANT_MILLIONTHS: u32 = 100_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardConstructionProfileV1 {
    pub schema_version: u32,
    pub id: String,
    pub revision: u32,
    pub board_thickness_nm: Nm,
    pub stackup: Vec<BoardConstructionStackupLayerV1>,
    pub routing_defaults: BoardRoutingDefaultsV1,
    pub placement_defaults: BoardPlacementDefaultsV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BoardConstructionStackupLayerV1 {
    Copper {
        layer: Layer,
        thickness_nm: Nm,
    },
    Dielectric {
        material: String,
        thickness_nm: Nm,
        /// Relative permittivity multiplied by 1,000,000.
        dielectric_constant_millionths: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardRoutingDefaultsV1 {
    pub grid_nm: Nm,
    pub track_width_nm: Nm,
    pub clearance_nm: Nm,
    pub via_diameter_nm: Nm,
    pub via_drill_nm: Nm,
    pub bend_cost: u32,
    pub via_cost: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardPlacementDefaultsV1 {
    pub grid_nm: Nm,
    pub component_clearance_nm: Nm,
    pub iterations: u32,
    pub seed: u64,
}

pub fn parse_board_construction_profile_v1(
    source: &str,
) -> Result<BoardConstructionProfileV1, String> {
    if source.is_empty() {
        return Err("board construction profile source must not be empty".into());
    }
    if source.len() as u64 > BOARD_CONSTRUCTION_PROFILE_V1_MAX_SOURCE_BYTES {
        return Err(format!(
            "board construction profile source exceeds {BOARD_CONSTRUCTION_PROFILE_V1_MAX_SOURCE_BYTES} bytes"
        ));
    }
    let value = parse_json_value_without_duplicate_keys(source, "board construction profile")?;
    validate_canonical_copper_layer_spellings(&value)?;
    let profile: BoardConstructionProfileV1 = serde_json::from_value(value)
        .map_err(|error| format!("invalid board construction profile JSON: {error}"))?;
    validate_board_construction_profile_v1(&profile)?;
    Ok(profile)
}

fn validate_canonical_copper_layer_spellings(value: &Value) -> Result<(), String> {
    let Some(stackup) = value.get("stackup").and_then(Value::as_array) else {
        return Ok(());
    };
    for entry in stackup {
        let Some(object) = entry.as_object() else {
            continue;
        };
        if object.get("kind").and_then(Value::as_str) != Some("copper") {
            continue;
        }
        let Some(layer) = object.get("layer").and_then(Value::as_str) else {
            continue;
        };
        let canonical = match layer {
            "F.Cu" | "B.Cu" => true,
            _ => layer
                .strip_prefix("In")
                .and_then(|value| value.strip_suffix(".Cu"))
                .and_then(|value| value.parse::<u8>().ok())
                .filter(|index| (1..=30).contains(index))
                .is_some_and(|index| layer == format!("In{index}.Cu")),
        };
        if !canonical {
            return Err(format!(
                "board construction copper layer {layer:?} is not canonically spelled"
            ));
        }
    }
    Ok(())
}

pub fn validate_board_construction_profile_v1(
    profile: &BoardConstructionProfileV1,
) -> Result<(), String> {
    if profile.schema_version != BOARD_CONSTRUCTION_PROFILE_V1_SCHEMA_VERSION {
        return Err(format!(
            "unsupported board construction profile schema_version {}; expected {}",
            profile.schema_version, BOARD_CONSTRUCTION_PROFILE_V1_SCHEMA_VERSION
        ));
    }
    validate_text(&profile.id, "board construction profile id")?;
    if profile.revision == 0 {
        return Err("board construction profile revision must be greater than zero".into());
    }
    validate_dimension(profile.board_thickness_nm, "board_thickness_nm", false)?;

    let expected_max_stackup_items = BOARD_CONSTRUCTION_PROFILE_V1_MAX_COPPER_LAYERS
        .checked_mul(2)
        .and_then(|value| value.checked_sub(1))
        .expect("constant stackup limit fits usize");
    if profile.stackup.len() < 3 || profile.stackup.len() > expected_max_stackup_items {
        return Err(format!(
            "board construction stackup must contain 3 to {expected_max_stackup_items} alternating layers"
        ));
    }

    let copper_count = profile
        .stackup
        .iter()
        .filter(|layer| matches!(layer, BoardConstructionStackupLayerV1::Copper { .. }))
        .count();
    if !(BOARD_CONSTRUCTION_PROFILE_V1_MIN_COPPER_LAYERS
        ..=BOARD_CONSTRUCTION_PROFILE_V1_MAX_COPPER_LAYERS)
        .contains(&copper_count)
    {
        return Err(format!(
            "board construction stackup must contain {} to {} copper layers",
            BOARD_CONSTRUCTION_PROFILE_V1_MIN_COPPER_LAYERS,
            BOARD_CONSTRUCTION_PROFILE_V1_MAX_COPPER_LAYERS
        ));
    }
    if profile.stackup.len() != copper_count.saturating_mul(2).saturating_sub(1) {
        return Err(
            "board construction stackup must alternate copper and dielectric layers".into(),
        );
    }

    let mut copper_index = 0usize;
    let mut thickness_sum = 0i128;
    for (index, entry) in profile.stackup.iter().enumerate() {
        match entry {
            BoardConstructionStackupLayerV1::Copper {
                layer,
                thickness_nm,
            } => {
                if !index.is_multiple_of(2) {
                    return Err(
                        "board construction stackup must alternate copper and dielectric layers"
                            .into(),
                    );
                }
                let expected = expected_copper_layer(copper_index, copper_count)?;
                if *layer != expected {
                    return Err(format!(
                        "board construction copper layer {} is {}; expected {}",
                        copper_index + 1,
                        layer.name(),
                        expected.name()
                    ));
                }
                validate_dimension(*thickness_nm, "copper thickness_nm", false)?;
                thickness_sum += i128::from(*thickness_nm);
                copper_index += 1;
            }
            BoardConstructionStackupLayerV1::Dielectric {
                material,
                thickness_nm,
                dielectric_constant_millionths,
            } => {
                if index.is_multiple_of(2) {
                    return Err(
                        "board construction stackup must alternate copper and dielectric layers"
                            .into(),
                    );
                }
                validate_text(material, "dielectric material")?;
                validate_dimension(*thickness_nm, "dielectric thickness_nm", false)?;
                if !(1_000_001..=BOARD_CONSTRUCTION_PROFILE_V1_MAX_DIELECTRIC_CONSTANT_MILLIONTHS)
                    .contains(dielectric_constant_millionths)
                {
                    return Err(format!(
                        "dielectric_constant_millionths must be between 1000001 and {BOARD_CONSTRUCTION_PROFILE_V1_MAX_DIELECTRIC_CONSTANT_MILLIONTHS}"
                    ));
                }
                thickness_sum += i128::from(*thickness_nm);
            }
        }
        if thickness_sum > i128::from(MAX_BOARD_EXTENT_NM) {
            return Err(
                "board construction stackup thickness exceeds the board extent limit".into(),
            );
        }
    }
    if thickness_sum != i128::from(profile.board_thickness_nm) {
        return Err(format!(
            "board construction stackup thickness sum {thickness_sum} nm does not equal board_thickness_nm {}",
            profile.board_thickness_nm
        ));
    }

    validate_routing_defaults(&profile.routing_defaults)?;
    validate_placement_defaults(&profile.placement_defaults)?;
    Ok(())
}

pub fn board_construction_profile_v1_sha256(
    profile: &BoardConstructionProfileV1,
) -> Result<String, String> {
    validate_board_construction_profile_v1(profile)?;
    let bytes = serde_json::to_vec(profile)
        .map_err(|error| format!("unable to serialize board construction profile: {error}"))?;
    Ok(digest_hex(&bytes))
}

pub fn board_construction_routing_rules(
    profile: &BoardConstructionProfileV1,
) -> Result<Rules, String> {
    validate_board_construction_profile_v1(profile)?;
    let defaults = &profile.routing_defaults;
    Ok(Rules {
        grid_nm: defaults.grid_nm,
        track_width_nm: defaults.track_width_nm,
        clearance_nm: defaults.clearance_nm,
        via_diameter_nm: defaults.via_diameter_nm,
        via_drill_nm: defaults.via_drill_nm,
        bend_cost: defaults.bend_cost,
        via_cost: defaults.via_cost,
    })
}

pub fn board_construction_copper_layers(
    profile: &BoardConstructionProfileV1,
) -> Result<Vec<Layer>, String> {
    validate_board_construction_profile_v1(profile)?;
    Ok(profile
        .stackup
        .iter()
        .filter_map(|entry| match entry {
            BoardConstructionStackupLayerV1::Copper { layer, .. } => Some(*layer),
            BoardConstructionStackupLayerV1::Dielectric { .. } => None,
        })
        .collect())
}

pub fn board_construction_profile_v1_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pcbex.dev/schemas/board-construction-profile-v1.schema.json",
        "title": "pcbex board construction profile v1",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "id", "revision", "board_thickness_nm", "stackup",
            "routing_defaults", "placement_defaults"
        ],
        "properties": {
            "schema_version": {"const": BOARD_CONSTRUCTION_PROFILE_V1_SCHEMA_VERSION},
            "id": {"$ref": "#/$defs/text"},
            "revision": {"type": "integer", "minimum": 1, "maximum": u32::MAX},
            "board_thickness_nm": {"$ref": "#/$defs/positive_dimension"},
            "stackup": {
                "type": "array",
                "minItems": 3,
                "maxItems": BOARD_CONSTRUCTION_PROFILE_V1_MAX_COPPER_LAYERS * 2 - 1,
                "items": {"oneOf": [
                    {"$ref": "#/$defs/copper"},
                    {"$ref": "#/$defs/dielectric"}
                ]}
            },
            "routing_defaults": {"$ref": "#/$defs/routing_defaults"},
            "placement_defaults": {"$ref": "#/$defs/placement_defaults"}
        },
        "$defs": {
            "text": {
                "type": "string",
                "minLength": 1,
                "maxLength": BOARD_CONSTRUCTION_PROFILE_V1_MAX_TEXT_BYTES,
                "pattern": "^\\S(?:[\\s\\S]*\\S)?$"
            },
            "positive_dimension": {
                "type": "integer", "minimum": 1, "maximum": MAX_BOARD_EXTENT_NM
            },
            "nonnegative_dimension": {
                "type": "integer", "minimum": 0, "maximum": MAX_BOARD_EXTENT_NM
            },
            "copper": {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "layer", "thickness_nm"],
                "properties": {
                    "kind": {"const": "copper"},
                    "layer": {
                        "type": "string",
                        "pattern": "^(F\\.Cu|B\\.Cu|In([1-9]|[12][0-9]|30)\\.Cu)$"
                    },
                    "thickness_nm": {"$ref": "#/$defs/positive_dimension"}
                }
            },
            "dielectric": {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "material", "thickness_nm", "dielectric_constant_millionths"],
                "properties": {
                    "kind": {"const": "dielectric"},
                    "material": {"$ref": "#/$defs/text"},
                    "thickness_nm": {"$ref": "#/$defs/positive_dimension"},
                    "dielectric_constant_millionths": {
                        "type": "integer",
                        "minimum": 1000001,
                        "maximum": BOARD_CONSTRUCTION_PROFILE_V1_MAX_DIELECTRIC_CONSTANT_MILLIONTHS
                    }
                }
            },
            "routing_defaults": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "grid_nm", "track_width_nm", "clearance_nm", "via_diameter_nm",
                    "via_drill_nm", "bend_cost", "via_cost"
                ],
                "properties": {
                    "grid_nm": {"$ref": "#/$defs/positive_dimension"},
                    "track_width_nm": {"$ref": "#/$defs/positive_dimension"},
                    "clearance_nm": {"$ref": "#/$defs/positive_dimension"},
                    "via_diameter_nm": {"$ref": "#/$defs/positive_dimension"},
                    "via_drill_nm": {"$ref": "#/$defs/positive_dimension"},
                    "bend_cost": {"type": "integer", "minimum": 0, "maximum": BOARD_CONSTRUCTION_PROFILE_V1_MAX_COST},
                    "via_cost": {"type": "integer", "minimum": 0, "maximum": BOARD_CONSTRUCTION_PROFILE_V1_MAX_COST}
                }
            },
            "placement_defaults": {
                "type": "object",
                "additionalProperties": false,
                "required": ["grid_nm", "component_clearance_nm", "iterations", "seed"],
                "properties": {
                    "grid_nm": {"$ref": "#/$defs/positive_dimension"},
                    "component_clearance_nm": {"$ref": "#/$defs/nonnegative_dimension"},
                    "iterations": {"type": "integer", "minimum": 0, "maximum": BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS},
                    "seed": {"type": "integer", "minimum": 0, "maximum": u64::MAX}
                }
            }
        }
    })
}

fn expected_copper_layer(index: usize, count: usize) -> Result<Layer, String> {
    if index == 0 {
        return Ok(Layer::Front);
    }
    if index + 1 == count {
        return Ok(Layer::Back);
    }
    let inner = u8::try_from(index)
        .map_err(|_| "board construction internal copper layer index overflow".to_string())?;
    Layer::from_index(inner)
        .filter(|layer| matches!(layer, Layer::Inner(_)))
        .ok_or_else(|| "board construction internal copper layer index is invalid".to_string())
}

fn validate_routing_defaults(defaults: &BoardRoutingDefaultsV1) -> Result<(), String> {
    for (value, label) in [
        (defaults.grid_nm, "routing_defaults.grid_nm"),
        (defaults.track_width_nm, "routing_defaults.track_width_nm"),
        (defaults.clearance_nm, "routing_defaults.clearance_nm"),
        (defaults.via_diameter_nm, "routing_defaults.via_diameter_nm"),
        (defaults.via_drill_nm, "routing_defaults.via_drill_nm"),
    ] {
        validate_dimension(value, label, false)?;
    }
    if defaults.via_drill_nm >= defaults.via_diameter_nm {
        return Err("routing_defaults.via_drill_nm must be smaller than via_diameter_nm".into());
    }
    if defaults.bend_cost > BOARD_CONSTRUCTION_PROFILE_V1_MAX_COST
        || defaults.via_cost > BOARD_CONSTRUCTION_PROFILE_V1_MAX_COST
    {
        return Err(format!(
            "routing default costs must not exceed {BOARD_CONSTRUCTION_PROFILE_V1_MAX_COST}"
        ));
    }
    Ok(())
}

fn validate_placement_defaults(defaults: &BoardPlacementDefaultsV1) -> Result<(), String> {
    validate_dimension(defaults.grid_nm, "placement_defaults.grid_nm", false)?;
    validate_dimension(
        defaults.component_clearance_nm,
        "placement_defaults.component_clearance_nm",
        true,
    )?;
    if defaults.iterations > BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS {
        return Err(format!(
            "placement_defaults.iterations exceeds {BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS}"
        ));
    }
    Ok(())
}

fn validate_dimension(value: Nm, label: &str, allow_zero: bool) -> Result<(), String> {
    if value < i64::from(!allow_zero) || value > MAX_BOARD_EXTENT_NM {
        let lower = i64::from(!allow_zero);
        return Err(format!(
            "{label} must be between {lower} and {MAX_BOARD_EXTENT_NM} nm"
        ));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > BOARD_CONSTRUCTION_PROFILE_V1_MAX_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must contain 1 to {BOARD_CONSTRUCTION_PROFILE_V1_MAX_TEXT_BYTES} trimmed non-control bytes"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> BoardConstructionProfileV1 {
        BoardConstructionProfileV1 {
            schema_version: 1,
            id: "two-layer-fr4".into(),
            revision: 1,
            board_thickness_nm: 1_600_000,
            stackup: vec![
                BoardConstructionStackupLayerV1::Copper {
                    layer: Layer::Front,
                    thickness_nm: 35_000,
                },
                BoardConstructionStackupLayerV1::Dielectric {
                    material: "FR4".into(),
                    thickness_nm: 1_530_000,
                    dielectric_constant_millionths: 4_100_000,
                },
                BoardConstructionStackupLayerV1::Copper {
                    layer: Layer::Back,
                    thickness_nm: 35_000,
                },
            ],
            routing_defaults: BoardRoutingDefaultsV1 {
                grid_nm: 100_000,
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                bend_cost: 5,
                via_cost: 50,
            },
            placement_defaults: BoardPlacementDefaultsV1 {
                grid_nm: 500_000,
                component_clearance_nm: 250_000,
                iterations: 100,
                seed: 7,
            },
        }
    }

    #[test]
    fn validates_closed_two_layer_profile_and_digest() {
        let profile = profile();
        validate_board_construction_profile_v1(&profile).unwrap();
        assert_eq!(
            board_construction_copper_layers(&profile).unwrap(),
            vec![Layer::Front, Layer::Back]
        );
        assert_eq!(
            board_construction_profile_v1_sha256(&profile)
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn rejects_duplicate_keys_and_unknown_fields() {
        let source = serde_json::to_string(&profile()).unwrap();
        let duplicate = source.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(
            parse_board_construction_profile_v1(&duplicate)
                .unwrap_err()
                .contains("duplicate JSON object key")
        );
        let unknown = source.replacen("\"revision\":1", "\"revision\":1,\"unknown\":true", 1);
        assert!(
            parse_board_construction_profile_v1(&unknown)
                .unwrap_err()
                .contains("unknown field")
        );
    }

    #[test]
    fn rejects_non_alternating_or_misordered_copper_and_bad_sum() {
        let mut bad = profile();
        bad.stackup[2] = BoardConstructionStackupLayerV1::Copper {
            layer: Layer::Inner(1),
            thickness_nm: 35_000,
        };
        assert!(
            validate_board_construction_profile_v1(&bad)
                .unwrap_err()
                .contains("expected B.Cu")
        );

        let mut bad = profile();
        bad.board_thickness_nm += 1;
        assert!(
            validate_board_construction_profile_v1(&bad)
                .unwrap_err()
                .contains("thickness sum")
        );

        let mut bad = profile();
        bad.stackup.swap(0, 1);
        assert!(
            validate_board_construction_profile_v1(&bad)
                .unwrap_err()
                .contains("alternate")
        );
    }

    #[test]
    fn rejects_invalid_routing_and_placement_defaults() {
        let mut bad = profile();
        bad.routing_defaults.via_drill_nm = bad.routing_defaults.via_diameter_nm;
        assert!(
            validate_board_construction_profile_v1(&bad)
                .unwrap_err()
                .contains("smaller")
        );

        let mut bad = profile();
        bad.placement_defaults.iterations = BOARD_CONSTRUCTION_PROFILE_V1_MAX_ITERATIONS + 1;
        assert!(
            validate_board_construction_profile_v1(&bad)
                .unwrap_err()
                .contains("iterations")
        );
    }

    #[test]
    fn parser_rejects_noncanonical_inner_copper_layer_spelling() {
        let mut value = serde_json::to_value(profile()).unwrap();
        value["stackup"] = json!([
            {"kind": "copper", "layer": "F.Cu", "thickness_nm": 35_000},
            {"kind": "dielectric", "material": "prepreg", "thickness_nm": 500_000, "dielectric_constant_millionths": 4_200_000},
            {"kind": "copper", "layer": "In01.Cu", "thickness_nm": 30_000},
            {"kind": "dielectric", "material": "core", "thickness_nm": 1_000_000, "dielectric_constant_millionths": 4_400_000},
            {"kind": "copper", "layer": "B.Cu", "thickness_nm": 35_000}
        ]);
        let source = serde_json::to_string(&value).unwrap();
        assert!(
            parse_board_construction_profile_v1(&source)
                .unwrap_err()
                .contains("not canonically spelled")
        );
    }
}

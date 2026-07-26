use crate::{Board, CURRENT_SCHEMA_VERSION};

pub fn migrate_board_json(source: &str) -> Result<serde_json::Value, String> {
    let mut value: serde_json::Value =
        serde_json::from_str(source).map_err(|error| error.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or("board JSON root must be an object")?;
    let mut version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1) as u32;
    if version == 0 || version > CURRENT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported board schema version {version}; latest is {CURRENT_SCHEMA_VERSION}"
        ));
    }
    while version < CURRENT_SCHEMA_VERSION {
        match version {
            1 => {
                for (legacy, current) in [
                    ("board_width_nm", "width_nm"),
                    ("board_height_nm", "height_nm"),
                    ("signals", "nets"),
                ] {
                    if !object.contains_key(current)
                        && let Some(value) = object.remove(legacy)
                    {
                        object.insert(current.into(), value);
                    }
                }
                version = 2;
                object.insert("schema_version".into(), serde_json::json!(version));
            }
            _ => return Err(format!("no migration path from schema version {version}")),
        }
    }
    Ok(value)
}

pub fn parse_board_json(source: &str) -> Result<Board, String> {
    let value = migrate_board_json(source)?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

pub fn board_json_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/board-v2.json",
        "title": "pcbex board",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "width_nm", "height_nm", "rules"],
        "properties": {
            "schema_version": {"const": CURRENT_SCHEMA_VERSION},
            "width_nm": {"type": "integer", "exclusiveMinimum": 0},
            "height_nm": {"type": "integer", "exclusiveMinimum": 0},
            "outline": {"type": "array", "items": {"$ref": "#/$defs/point"}},
            "cutouts": {"type": "array", "items": {"type": "array", "items": {"$ref": "#/$defs/point"}}},
            "copper_layers": {"type": "array", "items": {"type": "string"}},
            "rules": {"$ref": "#/$defs/rules"},
            "obstacles": {"type": "array"},
            "round_obstacles": {"type": "array"},
            "capsule_obstacles": {"type": "array"},
            "polygon_obstacles": {"type": "array"},
            "keepouts": {"type": "array"},
            "footprints": {"type": "array"},
            "net_classes": {
                "type": "object",
                "additionalProperties": {"$ref": "#/$defs/net_class"}
            },
            "differential_pairs": {"type": "array"},
            "length_groups": {"type": "array", "items": {"$ref": "#/$defs/length_group"}},
            "escape_groups": {"type": "array", "items": {"$ref": "#/$defs/escape_group"}},
            "manufacturing_rules": {"type": ["object", "null"]},
            "return_path_rules": {"type": "array", "items": {"$ref": "#/$defs/return_path_rule"}},
            "stackup": {"type": "array", "items": {"$ref": "#/$defs/stackup_layer"}},
            "via_strategy": {"enum": ["through_only", "auto"]},
            "nets": {"type": "array"},
            "routes": {"type": "array"}
        },
        "$defs": {
            "point": {
                "type": "object",
                "additionalProperties": false,
                "required": ["x_nm", "y_nm"],
                "properties": {
                    "x_nm": {"type": "integer"},
                    "y_nm": {"type": "integer"}
                }
            },
            "rules": {
                "type": "object",
                "additionalProperties": false,
                "required": ["grid_nm", "track_width_nm", "clearance_nm", "via_diameter_nm", "via_drill_nm"],
                "properties": {
                    "grid_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "track_width_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "clearance_nm": {"type": "integer", "minimum": 0},
                    "via_diameter_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "via_drill_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "bend_cost": {"type": "integer", "minimum": 0},
                    "via_cost": {"type": "integer", "minimum": 0}
                }
            },
            "net_class": {
                "type": "object",
                "additionalProperties": false,
                "required": ["track_width_nm", "clearance_nm", "via_diameter_nm", "via_drill_nm"],
                "properties": {
                    "track_width_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "clearance_nm": {"type": "integer", "minimum": 0},
                    "via_diameter_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "via_drill_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "layers": {"type": ["array", "null"], "items": {"type": "string"}},
                    "differential_width_nm": {"type": ["integer", "null"]},
                    "differential_gap_nm": {"type": ["integer", "null"]},
                    "minimum_length_nm": {"type": ["integer", "null"]},
                    "maximum_length_nm": {"type": ["integer", "null"]},
                    "target_impedance_ohms": {"type": ["number", "null"], "exclusiveMinimum": 0},
                    "impedance_tolerance_ohms": {"type": ["number", "null"], "minimum": 0}
                }
            },
            "length_group": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "net_ids", "max_skew_nm"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "net_ids": {"type": "array", "minItems": 2, "uniqueItems": true, "items": {"type": "integer", "minimum": 0}},
                    "max_skew_nm": {"type": "integer", "minimum": 0},
                    "tuning_amplitude_nm": {"type": ["integer", "null"], "exclusiveMinimum": 0},
                    "tuning_pitch_nm": {"type": ["integer", "null"], "exclusiveMinimum": 0},
                    "max_tuning_sections": {"type": "integer", "minimum": 1, "maximum": 16}
                }
            },
            "escape_group": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "net_ids", "fanout_distance_nm", "target_layer"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "net_ids": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "integer", "minimum": 0}},
                    "fanout_distance_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "target_layer": {"type": "string"},
                    "direction": {"enum": ["radial", "rows", "columns", "four_way"]},
                    "via_grid_nm": {"type": ["integer", "null"], "exclusiveMinimum": 0},
                    "max_rings": {"type": "integer", "minimum": 1, "maximum": 8}
                }
            },
            "return_path_rule": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "signal_net_ids", "reference_net_id", "max_via_distance_nm"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "signal_net_ids": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "integer", "minimum": 0}},
                    "reference_net_id": {"type": "integer", "minimum": 0},
                    "max_via_distance_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "auto_stitch": {"type": "boolean"}
                }
            },
            "stackup_layer": {
                "type": "object",
                "additionalProperties": false,
                "required": ["layer", "dielectric_height_nm", "dielectric_constant"],
                "properties": {
                    "layer": {"type": "string"},
                    "dielectric_height_nm": {"type": "integer", "exclusiveMinimum": 0},
                    "dielectric_constant": {"type": "number", "exclusiveMinimum": 1},
                    "copper_thickness_nm": {"type": "integer", "minimum": 0},
                    "reference_layer": {"type": ["string", "null"]}
                }
            }
        }
    })
}

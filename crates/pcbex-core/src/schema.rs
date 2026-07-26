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
            "rules": {"type": "object"},
            "obstacles": {"type": "array"},
            "round_obstacles": {"type": "array"},
            "capsule_obstacles": {"type": "array"},
            "polygon_obstacles": {"type": "array"},
            "keepouts": {"type": "array"},
            "footprints": {"type": "array"},
            "net_classes": {"type": "object"},
            "differential_pairs": {"type": "array"},
            "length_groups": {"type": "array"},
            "escape_groups": {"type": "array"},
            "manufacturing_rules": {"type": ["object", "null"]},
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
            }
        }
    })
}

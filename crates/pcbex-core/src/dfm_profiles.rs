use crate::{Board, ManufacturingRules, NetClassRules, Rules};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;

pub const DFM_PROFILE_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_PROFILE_DIMENSION_NM: i64 = 1_000_000_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DfmProfile {
    pub schema_version: u32,
    pub id: String,
    pub aliases: Vec<String>,
    pub revision: u32,
    pub verified_on: String,
    pub description: String,
    pub source_urls: Vec<String>,
    pub rules: ManufacturingRules,
}

pub fn dfm_profiles() -> Vec<DfmProfile> {
    vec![
        DfmProfile {
            schema_version: DFM_PROFILE_SCHEMA_VERSION,
            id: "jlcpcb-standard-2layer-1oz-v1".into(),
            aliases: vec!["jlcpcb-2layer".into()],
            revision: 1,
            verified_on: "2026-07-28".into(),
            description: "JLCPCB standard 2-layer FR-4, 1 oz copper, 1.6 mm thickness".into(),
            source_urls: vec!["https://jlcpcb.com/capabilities/pcb-capabilities/".into()],
            rules: ManufacturingRules {
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
            },
        },
        DfmProfile {
            schema_version: DFM_PROFILE_SCHEMA_VERSION,
            id: "pcbway-standard-2layer-1oz-v1".into(),
            aliases: vec!["pcbway-2layer".into()],
            revision: 1,
            verified_on: "2026-07-28".into(),
            description: "PCBWay standard 2-layer FR-4, 1 oz copper, 1.6 mm thickness".into(),
            source_urls: vec![
                "https://www.pcbway.com/capabilities.html".into(),
                "https://www.pcbway.com/helpcenter/board_outline_issues/The_distance_between_the_trace_and_board_outline_is_less_than_0_20mm.html".into(),
            ],
            rules: ManufacturingRules {
                minimum_track_width_nm: 100_000,
                minimum_clearance_nm: 100_000,
                minimum_drill_nm: 150_000,
                minimum_annular_ring_nm: 150_000,
                minimum_copper_to_edge_nm: 200_000,
                board_thickness_nm: 1_600_000,
                maximum_via_aspect_ratio: 10,
                minimum_drill_to_drill_nm: 0,
                allow_via_in_pad: false,
                minimum_trace_angle_deg: 0,
            },
        },
    ]
}

pub fn dfm_profile(name: &str) -> Option<DfmProfile> {
    dfm_profiles()
        .into_iter()
        .find(|profile| profile.id == name || profile.aliases.iter().any(|alias| alias == name))
}

pub fn parse_external_dfm_profile(source: &str) -> Result<DfmProfile, String> {
    let profile: DfmProfile = serde_json::from_str(source)
        .map_err(|error| format!("invalid DFM profile JSON: {error}"))?;
    validate_dfm_profile(&profile)?;

    let reserved = dfm_profiles()
        .into_iter()
        .flat_map(|profile| std::iter::once(profile.id).chain(profile.aliases))
        .collect::<HashSet<_>>();
    for name in std::iter::once(&profile.id).chain(&profile.aliases) {
        if reserved.contains(name) {
            return Err(format!(
                "external DFM profile name {name:?} collides with a built-in ID or alias"
            ));
        }
    }
    Ok(profile)
}

pub fn validate_dfm_profile(profile: &DfmProfile) -> Result<(), String> {
    if profile.schema_version != DFM_PROFILE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported DFM profile schema_version {}; expected {}",
            profile.schema_version, DFM_PROFILE_SCHEMA_VERSION
        ));
    }
    validate_name("id", &profile.id)?;
    if profile.aliases.len() > 64 {
        return Err("aliases must contain at most 64 entries".into());
    }
    let mut names = HashSet::from([profile.id.as_str()]);
    for alias in &profile.aliases {
        validate_name("alias", alias)?;
        if !names.insert(alias) {
            return Err(format!("duplicate DFM profile name {alias:?}"));
        }
    }
    if profile.revision == 0 {
        return Err("revision must be greater than zero".into());
    }
    validate_date(&profile.verified_on)?;
    let description = profile.description.trim();
    if description.is_empty() || description.len() > 1024 {
        return Err("description must contain 1 to 1024 bytes after trimming".into());
    }
    if profile.source_urls.is_empty() || profile.source_urls.len() > 32 {
        return Err("source_urls must contain 1 to 32 entries".into());
    }
    let mut urls = HashSet::new();
    for url in &profile.source_urls {
        let authority = url
            .strip_prefix("https://")
            .and_then(|rest| rest.split(['/', '?', '#']).next());
        if url.len() > 2048
            || url.bytes().any(|byte| byte.is_ascii_whitespace())
            || authority.is_none_or(str::is_empty)
        {
            return Err(format!(
                "source URL {url:?} must be a non-empty HTTPS URL of at most 2048 bytes"
            ));
        }
        if !urls.insert(url) {
            return Err(format!("duplicate source URL {url:?}"));
        }
    }
    validate_rules(&profile.rules)
}

pub fn dfm_profile_json_schema() -> Value {
    let nonnegative_nm =
        json!({"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROFILE_DIMENSION_NM});
    let positive_nm =
        json!({"type": "integer", "minimum": 1, "maximum": MAXIMUM_PROFILE_DIMENSION_NM});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/dfm-profile-v1.json",
        "title": "pcbex external DFM profile",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "id", "aliases", "revision", "verified_on",
            "description", "source_urls", "rules"
        ],
        "properties": {
            "schema_version": {"const": DFM_PROFILE_SCHEMA_VERSION},
            "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "aliases": {
                "type": "array", "maxItems": 64, "uniqueItems": true,
                "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"}
            },
            "revision": {"type": "integer", "minimum": 1, "maximum": 4294967295_u64},
            "verified_on": {"type": "string", "format": "date"},
            "description": {"type": "string", "minLength": 1, "maxLength": 1024},
            "source_urls": {
                "type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": true,
                "items": {"type": "string", "format": "uri", "pattern": "^https://", "maxLength": 2048}
            },
            "rules": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "minimum_track_width_nm", "minimum_clearance_nm", "minimum_drill_nm",
                    "minimum_annular_ring_nm", "minimum_copper_to_edge_nm",
                    "board_thickness_nm", "maximum_via_aspect_ratio",
                    "minimum_drill_to_drill_nm", "allow_via_in_pad",
                    "minimum_trace_angle_deg"
                ],
                "properties": {
                    "minimum_track_width_nm": positive_nm,
                    "minimum_clearance_nm": nonnegative_nm,
                    "minimum_drill_nm": positive_nm,
                    "minimum_annular_ring_nm": positive_nm,
                    "minimum_copper_to_edge_nm": nonnegative_nm,
                    "board_thickness_nm": positive_nm,
                    "maximum_via_aspect_ratio": {"type": "integer", "minimum": 1, "maximum": 100},
                    "minimum_drill_to_drill_nm": nonnegative_nm,
                    "allow_via_in_pad": {"type": "boolean"},
                    "minimum_trace_angle_deg": {"type": "integer", "minimum": 0, "maximum": 180}
                }
            }
        }
    })
}

fn validate_name(label: &str, name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && (name.as_bytes()[0].is_ascii_lowercase() || name.as_bytes()[0].is_ascii_digit());
    let valid_tail = name.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    });
    if !valid || !valid_tail {
        return Err(format!(
            "{label} {name:?} must match [a-z0-9][a-z0-9.-]{{0,127}}"
        ));
    }
    Ok(())
}

fn validate_date(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let shape_is_valid = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit());
    if !shape_is_valid {
        return Err(format!(
            "verified_on {value:?} must be a valid YYYY-MM-DD date"
        ));
    }
    let components = value
        .split('-')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>();
    let Ok(components) = components else {
        return Err(format!(
            "verified_on {value:?} must be a valid YYYY-MM-DD date"
        ));
    };
    if components.len() != 3 {
        return Err(format!(
            "verified_on {value:?} must be a valid YYYY-MM-DD date"
        ));
    }
    let (year, month, day) = (components[0], components[1], components[2]);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days {
        return Err(format!(
            "verified_on {value:?} must be a valid YYYY-MM-DD date"
        ));
    }
    Ok(())
}

fn validate_rules(rules: &ManufacturingRules) -> Result<(), String> {
    for (name, value) in [
        ("minimum_track_width_nm", rules.minimum_track_width_nm),
        ("minimum_drill_nm", rules.minimum_drill_nm),
        ("minimum_annular_ring_nm", rules.minimum_annular_ring_nm),
        ("board_thickness_nm", rules.board_thickness_nm),
    ] {
        if value <= 0 {
            return Err(format!("{name} must be greater than zero"));
        }
        if value > MAXIMUM_PROFILE_DIMENSION_NM {
            return Err(format!(
                "{name} must not exceed {MAXIMUM_PROFILE_DIMENSION_NM}"
            ));
        }
    }
    for (name, value) in [
        ("minimum_clearance_nm", rules.minimum_clearance_nm),
        ("minimum_copper_to_edge_nm", rules.minimum_copper_to_edge_nm),
        ("minimum_drill_to_drill_nm", rules.minimum_drill_to_drill_nm),
    ] {
        if value < 0 {
            return Err(format!("{name} must not be negative"));
        }
        if value > MAXIMUM_PROFILE_DIMENSION_NM {
            return Err(format!(
                "{name} must not exceed {MAXIMUM_PROFILE_DIMENSION_NM}"
            ));
        }
    }
    if !(1..=100).contains(&rules.maximum_via_aspect_ratio) {
        return Err("maximum_via_aspect_ratio must be between 1 and 100".into());
    }
    if rules.minimum_trace_angle_deg > 180 {
        return Err("minimum_trace_angle_deg must be between 0 and 180".into());
    }
    Ok(())
}

pub fn apply_dfm_profile(board: &mut Board, profile: &DfmProfile) {
    apply_manufacturing_rules(board, &profile.rules);
}

/// Apply verified manufacturing minimums without requiring a named profile.
///
/// This is used by higher-level orchestration profiles that carry one
/// self-contained, reviewable set of constraints alongside physical geometry.
pub fn apply_manufacturing_rules(board: &mut Board, rules: &ManufacturingRules) {
    apply_routing_minimums(&mut board.rules, rules);
    for net_class in board.net_classes.values_mut() {
        apply_net_class_minimums(net_class, rules);
    }
    board.manufacturing_rules = Some(rules.clone());
}

fn apply_routing_minimums(rules: &mut Rules, manufacturing: &ManufacturingRules) {
    rules.track_width_nm = rules
        .track_width_nm
        .max(manufacturing.minimum_track_width_nm);
    rules.clearance_nm = rules.clearance_nm.max(manufacturing.minimum_clearance_nm);
    rules.via_drill_nm = rules.via_drill_nm.max(manufacturing.minimum_drill_nm);
    rules.via_diameter_nm = rules.via_diameter_nm.max(minimum_via_diameter(
        rules.via_drill_nm,
        manufacturing.minimum_annular_ring_nm,
    ));
}

fn apply_net_class_minimums(rules: &mut NetClassRules, manufacturing: &ManufacturingRules) {
    rules.track_width_nm = rules
        .track_width_nm
        .max(manufacturing.minimum_track_width_nm);
    rules.clearance_nm = rules.clearance_nm.max(manufacturing.minimum_clearance_nm);
    rules.via_drill_nm = rules.via_drill_nm.max(manufacturing.minimum_drill_nm);
    rules.via_diameter_nm = rules.via_diameter_nm.max(minimum_via_diameter(
        rules.via_drill_nm,
        manufacturing.minimum_annular_ring_nm,
    ));
}

fn minimum_via_diameter(drill_nm: i64, annular_ring_nm: i64) -> i64 {
    drill_nm.saturating_add(annular_ring_nm.saturating_mul(2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CURRENT_SCHEMA_VERSION, NetClassRules};
    use std::collections::HashMap;

    fn board() -> Board {
        Board {
            schema_version: CURRENT_SCHEMA_VERSION,
            width_nm: 10_000_000,
            height_nm: 10_000_000,
            outline: vec![],
            cutouts: vec![],
            copper_layers: vec![],
            rules: Rules {
                grid_nm: 100_000,
                track_width_nm: 80_000,
                clearance_nm: 80_000,
                via_diameter_nm: 300_000,
                via_drill_nm: 100_000,
                bend_cost: 5,
                via_cost: 20,
            },
            obstacles: vec![],
            round_obstacles: vec![],
            capsule_obstacles: vec![],
            polygon_obstacles: vec![],
            keepouts: vec![],
            footprints: vec![],
            net_classes: HashMap::from([(
                "fine".into(),
                NetClassRules {
                    track_width_nm: 90_000,
                    clearance_nm: 90_000,
                    via_diameter_nm: 300_000,
                    via_drill_nm: 100_000,
                    layers: None,
                    differential_width_nm: None,
                    differential_gap_nm: None,
                    minimum_length_nm: None,
                    maximum_length_nm: None,
                    target_impedance_ohms: None,
                    impedance_tolerance_ohms: None,
                    maximum_impedance_step_ohms: None,
                },
            )]),
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
    fn resolves_versioned_ids_and_stable_aliases() {
        let versioned = dfm_profile("jlcpcb-standard-2layer-1oz-v1").unwrap();
        let alias = dfm_profile("jlcpcb-2layer").unwrap();
        assert_eq!(versioned, alias);
        assert_eq!(versioned.revision, 1);
        assert!(dfm_profile("unknown").is_none());
    }

    #[test]
    fn parses_strict_external_profiles() {
        let mut value = serde_json::to_value(dfm_profile("jlcpcb-2layer").unwrap()).unwrap();
        value["id"] = "acme-hdi-4layer-v3".into();
        value["aliases"] = serde_json::json!(["acme-hdi"]);
        value["revision"] = 3.into();
        let profile = parse_external_dfm_profile(&value.to_string()).unwrap();
        assert_eq!(profile.id, "acme-hdi-4layer-v3");
        assert_eq!(profile.aliases, ["acme-hdi"]);

        value["unexpected"] = true.into();
        assert!(
            parse_external_dfm_profile(&value.to_string())
                .unwrap_err()
                .contains("unknown field")
        );
    }

    #[test]
    fn rejects_invalid_or_reserved_external_profiles() {
        let mut value = serde_json::to_value(dfm_profile("jlcpcb-2layer").unwrap()).unwrap();
        value["id"] = "acme-profile-v1".into();
        value["aliases"] = serde_json::json!(["jlcpcb-2layer"]);
        assert!(
            parse_external_dfm_profile(&value.to_string())
                .unwrap_err()
                .contains("collides")
        );

        value["aliases"] = serde_json::json!(["acme-profile"]);
        value["verified_on"] = "2026-02-30".into();
        assert!(
            parse_external_dfm_profile(&value.to_string())
                .unwrap_err()
                .contains("valid YYYY-MM-DD")
        );
        value["verified_on"] = "2026-07-29".into();
        value["rules"]["minimum_track_width_nm"] = 0.into();
        assert!(
            parse_external_dfm_profile(&value.to_string())
                .unwrap_err()
                .contains("minimum_track_width_nm")
        );
    }

    #[test]
    fn profile_schema_is_closed_and_versioned() {
        let schema = dfm_profile_json_schema();
        assert_eq!(schema["properties"]["schema_version"]["const"], 1);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["rules"]["additionalProperties"], false);
    }

    #[test]
    fn applies_manufacturing_and_routing_minimums() {
        let profile = dfm_profile("jlcpcb-2layer").unwrap();
        let mut board = board();
        board.rules.track_width_nm = 250_000;
        board.net_classes.get_mut("fine").unwrap().clearance_nm = 250_000;
        apply_dfm_profile(&mut board, &profile);

        assert_eq!(board.manufacturing_rules, Some(profile.rules.clone()));
        assert_eq!(board.rules.track_width_nm, 250_000);
        assert_eq!(board.rules.clearance_nm, 100_000);
        assert_eq!(board.rules.via_drill_nm, 150_000);
        assert_eq!(board.rules.via_diameter_nm, 510_000);
        assert_eq!(board.net_classes["fine"].track_width_nm, 100_000);
        assert_eq!(board.net_classes["fine"].clearance_nm, 250_000);
        assert_eq!(board.net_classes["fine"].via_diameter_nm, 510_000);
    }
}

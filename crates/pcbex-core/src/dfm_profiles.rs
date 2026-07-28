use crate::{Board, ManufacturingRules, NetClassRules, Rules};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DfmProfile {
    pub id: &'static str,
    pub aliases: &'static [&'static str],
    pub revision: u32,
    pub verified_on: &'static str,
    pub description: &'static str,
    pub source_urls: &'static [&'static str],
    pub rules: ManufacturingRules,
}

pub fn dfm_profiles() -> Vec<DfmProfile> {
    vec![
        DfmProfile {
            id: "jlcpcb-standard-2layer-1oz-v1",
            aliases: &["jlcpcb-2layer"],
            revision: 1,
            verified_on: "2026-07-28",
            description: "JLCPCB standard 2-layer FR-4, 1 oz copper, 1.6 mm thickness",
            source_urls: &["https://jlcpcb.com/capabilities/pcb-capabilities/"],
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
            id: "pcbway-standard-2layer-1oz-v1",
            aliases: &["pcbway-2layer"],
            revision: 1,
            verified_on: "2026-07-28",
            description: "PCBWay standard 2-layer FR-4, 1 oz copper, 1.6 mm thickness",
            source_urls: &[
                "https://www.pcbway.com/capabilities.html",
                "https://www.pcbway.com/helpcenter/board_outline_issues/The_distance_between_the_trace_and_board_outline_is_less_than_0_20mm.html",
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
        .find(|profile| profile.id == name || profile.aliases.contains(&name))
}

pub fn apply_dfm_profile(board: &mut Board, profile: &DfmProfile) {
    apply_routing_minimums(&mut board.rules, &profile.rules);
    for rules in board.net_classes.values_mut() {
        apply_net_class_minimums(rules, &profile.rules);
    }
    board.manufacturing_rules = Some(profile.rules.clone());
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

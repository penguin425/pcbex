#![no_main]

use libfuzzer_sys::fuzz_target;
use pcbex_core::{parse_board_json, route_board};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let directions = ["radial", "rows", "columns", "four_way"];
    let direction = directions[usize::from(data[0] % 4)];
    let rings = 1 + data[1] % 8;
    let distance = 250_000 + i64::from(data[2] % 8) * 250_000;
    let source = serde_json::json!({
        "schema_version": 2,
        "width_nm": 12_000_000,
        "height_nm": 12_000_000,
        "copper_layers": ["F.Cu", "In1.Cu", "B.Cu"],
        "rules": {
            "grid_nm": 250_000,
            "track_width_nm": 200_000,
            "clearance_nm": 150_000,
            "via_diameter_nm": 500_000,
            "via_drill_nm": 250_000
        },
        "escape_groups": [{
            "name": "U1",
            "net_ids": [1],
            "fanout_distance_nm": distance,
            "target_layer": "In1.Cu",
            "direction": direction,
            "via_grid_nm": 250_000,
            "max_rings": rings
        }],
        "nets": [{
            "id": 1,
            "name": "BGA",
            "priority": 0,
            "terminals": [
                {"position": {"x_nm": 6_000_000, "y_nm": 6_000_000}, "layers": ["F.Cu"]},
                {"position": {"x_nm": 10_000_000, "y_nm": 10_000_000}, "layers": ["In1.Cu"]}
            ]
        }]
    });
    if let Ok(board) = parse_board_json(&source.to_string()) {
        let _ = route_board(&board);
    }
});

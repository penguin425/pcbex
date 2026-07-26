#![no_main]

use libfuzzer_sys::fuzz_target;
use pcbex_core::{parse_board_json, route_board};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let amplitude = 250_000 + i64::from(data[0] % 8) * 250_000;
    let pitch = 500_000 + i64::from(data[1] % 8) * 250_000;
    let sections = 1 + data[2] % 16;
    let minimum = 16_000_000 + 2 * amplitude * i64::from(sections.min(4));
    let source = serde_json::json!({
        "schema_version": 2,
        "width_nm": 20_000_000,
        "height_nm": 20_000_000,
        "rules": {
            "grid_nm": 250_000,
            "track_width_nm": 250_000,
            "clearance_nm": 200_000,
            "via_diameter_nm": 600_000,
            "via_drill_nm": 300_000
        },
        "net_classes": {
            "Tuned": {
                "track_width_nm": 250_000,
                "clearance_nm": 200_000,
                "via_diameter_nm": 600_000,
                "via_drill_nm": 300_000,
                "minimum_length_nm": minimum
            }
        },
        "length_groups": [{
            "name": "fuzz",
            "net_ids": [1, 2],
            "max_skew_nm": 250_000,
            "tuning_amplitude_nm": amplitude,
            "tuning_pitch_nm": pitch,
            "max_tuning_sections": sections
        }],
        "nets": [
            {"id": 1, "name": "A", "class": "Tuned", "priority": 0, "terminals": [
                {"position": {"x_nm": 2_000_000, "y_nm": 5_000_000}, "layers": ["F.Cu"]},
                {"position": {"x_nm": 18_000_000, "y_nm": 5_000_000}, "layers": ["F.Cu"]}
            ]},
            {"id": 2, "name": "B", "priority": 0, "terminals": [
                {"position": {"x_nm": 2_000_000, "y_nm": 12_000_000}, "layers": ["F.Cu"]},
                {"position": {"x_nm": 18_000_000, "y_nm": 12_000_000}, "layers": ["F.Cu"]}
            ]}
        ]
    });
    if let Ok(board) = parse_board_json(&source.to_string()) {
        let _ = route_board(&board);
    }
});

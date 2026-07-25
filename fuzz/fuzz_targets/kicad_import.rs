#![no_main]

use libfuzzer_sys::fuzz_target;
use pcbex_core::Rules;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    if let Ok(source) = std::str::from_utf8(data) {
        let _ = pcbex_kicad::import(
            source,
            Rules {
                grid_nm: 250_000,
                track_width_nm: 250_000,
                clearance_nm: 200_000,
                via_diameter_nm: 600_000,
                via_drill_nm: 300_000,
                bend_cost: 5,
                via_cost: 20,
            },
        );
    }
});

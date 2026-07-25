#![no_main]

use libfuzzer_sys::fuzz_target;
use pcbex_core::{Board, Router, checking::check_board};

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    if let Ok(board) = serde_json::from_slice::<Board>(data) {
        if board.width_nm > 100_000_000
            || board.height_nm > 100_000_000
            || board.rules.grid_nm < 100_000
            || board.nets.len() > 100
            || board.routes.len() > 100
        {
            return;
        }
        let _ = Router::new(&board);
        let _ = check_board(&board);
    }
});

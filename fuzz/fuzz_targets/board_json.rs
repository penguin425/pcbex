#![no_main]

use libfuzzer_sys::fuzz_target;
use pcbex_core::{Router, checking::check_board, parse_board_json, route_board};

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    if let Ok(source) = std::str::from_utf8(data)
        && let Ok(board) = parse_board_json(source)
    {
        if board.width_nm > 20_000_000
            || board.height_nm > 20_000_000
            || board.rules.grid_nm < 250_000
            || board.nets.len() > 20
            || board.routes.len() > 20
        {
            return;
        }
        let _ = Router::new(&board);
        let _ = check_board(&board);
        let _ = route_board(&board);
    }
});

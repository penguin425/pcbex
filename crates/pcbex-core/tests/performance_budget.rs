use pcbex_core::{
    Board, Layer, Net, Point, RoundObstacle, Rules, Terminal, ViaStrategy, route_board,
};
use std::collections::HashMap;

fn rules() -> Rules {
    Rules {
        grid_nm: 250_000,
        track_width_nm: 250_000,
        clearance_nm: 200_000,
        via_diameter_nm: 600_000,
        via_drill_nm: 300_000,
        bend_cost: 5,
        via_cost: 20,
    }
}

fn board_with_nets(net_count: usize) -> Board {
    Board {
        schema_version: pcbex_core::CURRENT_SCHEMA_VERSION,
        width_nm: 20_000_000,
        height_nm: 20_000_000,
        outline: vec![],
        cutouts: vec![],
        copper_layers: vec![Layer::Front, Layer::Back],
        rules: rules(),
        obstacles: vec![],
        round_obstacles: vec![],
        capsule_obstacles: vec![],
        polygon_obstacles: vec![],
        keepouts: vec![],
        footprints: vec![],
        net_classes: HashMap::new(),
        differential_pairs: vec![],
        length_groups: vec![],
        escape_groups: vec![],
        manufacturing_rules: None,
        return_path_rules: vec![],
        via_strategy: ViaStrategy::ThroughOnly,
        nets: (0..net_count)
            .map(|index| {
                let y_nm = 1_000_000 + index as i64 * 1_500_000;
                Net {
                    id: index as u32 + 1,
                    name: format!("N{}", index + 1),
                    class: None,
                    priority: 0,
                    terminals: vec![
                        Terminal {
                            position: Point {
                                x_nm: 1_000_000,
                                y_nm,
                            },
                            layers: vec![Layer::Front],
                        },
                        Terminal {
                            position: Point {
                                x_nm: 19_000_000,
                                y_nm,
                            },
                            layers: vec![Layer::Front],
                        },
                    ],
                }
            })
            .collect(),
        routes: vec![],
    }
}

fn assert_budget(
    name: &str,
    board: &Board,
    maximum_expanded_states: usize,
    maximum_rasterized_candidate_cells: usize,
) {
    let (_, report) = route_board(board).expect("performance fixture must route");
    println!(
        "{name}: expanded_states={}/{maximum_expanded_states}, rasterized_candidates={}/{}",
        report.expanded_states,
        report.rasterized_candidate_cells,
        maximum_rasterized_candidate_cells
    );
    assert!(
        report.unrouted.is_empty(),
        "{name} left nets unrouted: {:?}",
        report.unrouted
    );
    assert!(
        report.expanded_states <= maximum_expanded_states,
        "{name} exceeded its deterministic search budget: {} > {}",
        report.expanded_states,
        maximum_expanded_states
    );
    assert!(
        report.rasterized_candidate_cells <= maximum_rasterized_candidate_cells,
        "{name} exceeded its rasterization budget: {} > {}",
        report.rasterized_candidate_cells,
        maximum_rasterized_candidate_cells
    );
}

#[test]
fn parallel_net_search_stays_within_budget() {
    assert_budget("parallel_10_nets", &board_with_nets(10), 1_000, 20_000);
}

#[test]
fn large_obstacle_rasterization_stays_within_budget() {
    let mut board = board_with_nets(1);
    board.width_nm = 100_000_000;
    board.height_nm = 100_000_000;
    board.nets[0].terminals[1].position.x_nm = 99_000_000;
    for index in 0..200 {
        board.round_obstacles.push(RoundObstacle {
            center: Point {
                x_nm: 5_000_000 + (index % 20) as i64 * 4_500_000,
                y_nm: 10_000_000 + (index / 20) as i64 * 8_000_000,
            },
            diameter_nm: 1_000_000,
            layers: vec![Layer::Front, Layer::Back],
            net_id: None,
        });
    }

    assert_budget("large_board_200_obstacles", &board, 500, 250_000);
}

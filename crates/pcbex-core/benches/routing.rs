use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pcbex_core::{Board, Layer, Net, Obstacle, Point, Rules, Terminal, route_board};
use std::collections::HashMap;
use std::hint::black_box;

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
        width_nm: 20_000_000,
        height_nm: 20_000_000,
        outline: vec![],
        cutouts: vec![],
        rules: rules(),
        obstacles: vec![],
        round_obstacles: vec![],
        capsule_obstacles: vec![],
        polygon_obstacles: vec![],
        keepouts: vec![],
        footprints: vec![],
        net_classes: HashMap::new(),
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

fn routing_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("routing");

    let mut obstacle = board_with_nets(1);
    obstacle.obstacles.push(Obstacle {
        min: Point {
            x_nm: 8_000_000,
            y_nm: 0,
        },
        max: Point {
            x_nm: 12_000_000,
            y_nm: 12_000_000,
        },
        layers: vec![Layer::Front, Layer::Back],
        net_id: None,
    });
    group.bench_function("single_net_obstacle", |bencher| {
        bencher.iter(|| route_board(black_box(&obstacle)).unwrap())
    });

    for net_count in [5, 10] {
        let board = board_with_nets(net_count);
        group.bench_with_input(
            BenchmarkId::new("parallel_nets", net_count),
            &board,
            |bencher, board| bencher.iter(|| route_board(black_box(board)).unwrap()),
        );
    }

    let mut cutout = board_with_nets(1);
    cutout.nets[0].terminals[0].position.y_nm = 10_000_000;
    cutout.nets[0].terminals[1].position.y_nm = 10_000_000;
    cutout.cutouts.push(vec![
        Point {
            x_nm: 8_000_000,
            y_nm: 7_000_000,
        },
        Point {
            x_nm: 12_000_000,
            y_nm: 7_000_000,
        },
        Point {
            x_nm: 12_000_000,
            y_nm: 13_000_000,
        },
        Point {
            x_nm: 8_000_000,
            y_nm: 13_000_000,
        },
    ]);
    group.bench_function("single_net_cutout", |bencher| {
        bencher.iter(|| route_board(black_box(&cutout)).unwrap())
    });
    group.finish();
}

criterion_group!(benches, routing_benchmarks);
criterion_main!(benches);

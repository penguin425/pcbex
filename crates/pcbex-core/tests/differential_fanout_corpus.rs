use pcbex_core::{Board, checking, route_board_with_workers};

fn fixture(name: &str) -> Board {
    let source = match name {
        "pitch" => include_str!("../../../corpus/differential_endpoint_pitch.json"),
        "rotated" => include_str!("../../../corpus/differential_endpoint_rotated.json"),
        _ => panic!("unknown fixture: {name}"),
    };
    serde_json::from_str(source).expect("differential endpoint corpus must parse")
}

fn assert_fixture(name: &str) {
    let input = fixture(name);
    let (one, report_one) = route_board_with_workers(&input, 1).expect("fixture must route");
    let (four, report_four) = route_board_with_workers(&input, 4).expect("fixture must route");

    assert!(checking::check_board(&one).violations.is_empty());
    assert!(checking::check_board(&four).violations.is_empty());
    assert_eq!(report_one.coupled_differential_pairs, vec!["LINK"]);
    assert_eq!(
        report_one.coupled_differential_pairs,
        report_four.coupled_differential_pairs
    );
    assert!(one.routes.iter().all(|route| route.vias.is_empty()));
    assert!(four.routes.iter().all(|route| route.vias.is_empty()));
    assert_eq!(
        serde_json::to_vec(&one).unwrap(),
        serde_json::to_vec(&four).unwrap()
    );
    assert_eq!(report_one.expanded_states, report_four.expanded_states);

    let (rerouted, _) = route_board_with_workers(&one, 1).expect("reroute must succeed");
    assert_eq!(
        serde_json::to_vec(&one).unwrap(),
        serde_json::to_vec(&rerouted).unwrap()
    );
}

#[test]
fn differential_endpoint_pitch_corpus_is_deterministic_and_clean() {
    assert_fixture("pitch");
}

#[test]
fn differential_endpoint_rotated_corpus_is_deterministic_and_clean() {
    assert_fixture("rotated");
}

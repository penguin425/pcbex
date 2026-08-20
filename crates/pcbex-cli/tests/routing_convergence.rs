use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn pcbex(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .args(arguments)
        .output()
        .unwrap()
}

fn audit_closed_schema(value: &Value) {
    if value.get("type") == Some(&Value::String("object".into())) {
        assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
    }
    if value.get("type") == Some(&Value::String("array".into())) {
        assert!(value.get("maxItems").is_some());
    }
    match value {
        Value::Array(values) => values.iter().for_each(audit_closed_schema),
        Value::Object(values) => values.values().for_each(audit_closed_schema),
        _ => {}
    }
}

#[test]
fn route_convergence_is_deterministic_and_schema_is_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let temporary_root = fs::canonicalize(temporary.path()).unwrap();
    let input = root().join("examples/simple.json");
    let first_board = temporary_root.join("first.board.json");
    let first_report = temporary_root.join("first.report.json");
    let second_board = temporary_root.join("second.board.json");
    let second_report = temporary_root.join("second.report.json");

    for (board, report) in [
        (&first_board, &first_report),
        (&second_board, &second_report),
    ] {
        let output = pcbex(&[
            "route",
            input.to_str().unwrap(),
            "--output",
            board.to_str().unwrap(),
            "--convergence-report",
            report.to_str().unwrap(),
            "--convergence-rounds",
            "2",
            "--convergence-candidates",
            "3",
            "--convergence-workers",
            "3",
            "--convergence-router-workers",
            "1",
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert_eq!(
        fs::read(&first_board).unwrap(),
        fs::read(&second_board).unwrap()
    );
    assert_eq!(
        fs::read(&first_report).unwrap(),
        fs::read(&second_report).unwrap()
    );
    let report: Value = serde_json::from_slice(&fs::read(&first_report).unwrap()).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["engine_version"], "1.474.0");
    assert_eq!(report["scope"], "bounded_deterministic_routing_convergence");
    assert_eq!(report["status"], "converged");
    assert_eq!(report["converged"], true);
    assert_eq!(report["design_rules_unchanged"], true);
    assert_eq!(report["final_drc_violation_count"], 0);
    assert_eq!(report["final_metrics"]["unrouted_nets"], 0);
    for identity in [
        &report["input_board_canonical"],
        &report["final_board_canonical"],
    ] {
        assert!(identity["bytes"].as_u64().unwrap() > 0);
        assert_eq!(identity["sha256"].as_str().unwrap().len(), 64);
    }
    assert!(report["allocated_work_units"].as_u64().unwrap() <= 2_000_000);
    assert!(report["rounds"].as_array().unwrap().iter().all(|round| {
        round["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|candidate| {
                !candidate["selected_as_round_best"]
                    .as_bool()
                    .unwrap_or(false)
                    || candidate["status"] == "admissible"
            })
    }));

    let schema_path = temporary_root.join("schema.json");
    let output = pcbex(&[
        "routing-convergence-report-schema",
        "--output",
        schema_path.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let schema: Value = serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
    audit_closed_schema(&schema);
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["$defs"]["round"]["additionalProperties"], false);
}

#[test]
fn negative_report_is_retained_before_unrouted_gate() {
    let temporary = tempfile::tempdir().unwrap();
    let temporary_root = fs::canonicalize(temporary.path()).unwrap();
    let input = root().join("examples/simple.json");
    let board = temporary_root.join("partial.board.json");
    let report = temporary_root.join("partial.report.json");
    let output = pcbex(&[
        "route",
        input.to_str().unwrap(),
        "--output",
        board.to_str().unwrap(),
        "--convergence-report",
        report.to_str().unwrap(),
        "--convergence-rounds",
        "1",
        "--convergence-candidates",
        "1",
        "--convergence-workers",
        "1",
        "--convergence-router-workers",
        "1",
        "--convergence-work-budget",
        "1",
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("routing convergence retained 1 unrouted net(s)")
    );
    assert!(board.is_file());
    assert!(report.is_file());
    let retained: Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    assert_eq!(retained["status"], "no_admissible_candidate");
    assert_eq!(retained["converged"], false);
    assert_eq!(retained["final_drc_violation_count"], 0);
    assert_eq!(retained["final_metrics"]["unrouted_nets"], 1);

    let allowed_board = temporary_root.join("allowed.board.json");
    let allowed_report = temporary_root.join("allowed.report.json");
    let output = pcbex(&[
        "route",
        input.to_str().unwrap(),
        "--output",
        allowed_board.to_str().unwrap(),
        "--convergence-report",
        allowed_report.to_str().unwrap(),
        "--convergence-rounds",
        "1",
        "--convergence-candidates",
        "1",
        "--convergence-workers",
        "1",
        "--convergence-router-workers",
        "1",
        "--convergence-work-budget",
        "1",
        "--allow-unrouted",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn report_preflight_rejects_overwrite_alias_and_unbound_options() {
    let temporary = tempfile::tempdir().unwrap();
    let temporary_root = fs::canonicalize(temporary.path()).unwrap();
    let input = root().join("examples/simple.json");
    let board = temporary_root.join("board.json");
    let report = temporary_root.join("report.json");
    fs::write(&report, b"retained\n").unwrap();
    let output = pcbex(&[
        "route",
        input.to_str().unwrap(),
        "--output",
        board.to_str().unwrap(),
        "--convergence-report",
        report.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert_eq!(fs::read(&report).unwrap(), b"retained\n");
    assert!(!board.exists());

    let alias = temporary_root.join("alias.json");
    let output = pcbex(&[
        "route",
        input.to_str().unwrap(),
        "--output",
        alias.to_str().unwrap(),
        "--convergence-report",
        alias.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(!alias.exists());

    let output = pcbex(&[
        "route",
        input.to_str().unwrap(),
        "--output",
        board.to_str().unwrap(),
        "--convergence-rounds",
        "1",
    ]);
    assert!(!output.status.success());
    assert!(!board.exists());
}

#[test]
fn route_kicad_supports_the_same_convergence_boundary() {
    let temporary = tempfile::tempdir().unwrap();
    let temporary_root = fs::canonicalize(temporary.path()).unwrap();
    let input = root().join("examples/simple.kicad_pcb");
    let board = temporary_root.join("routed.kicad_pcb");
    let report = temporary_root.join("routing.report.json");
    let output = pcbex(&[
        "route-kicad",
        input.to_str().unwrap(),
        "--output",
        board.to_str().unwrap(),
        "--convergence-report",
        report.to_str().unwrap(),
        "--convergence-rounds",
        "2",
        "--convergence-candidates",
        "3",
        "--convergence-workers",
        "2",
        "--convergence-router-workers",
        "1",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(board.is_file());
    let retained: Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    assert_eq!(retained["status"], "converged");
    assert_eq!(retained["final_drc_violation_count"], 0);
}

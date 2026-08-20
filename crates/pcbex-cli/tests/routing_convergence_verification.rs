use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, path::PathBuf, process::Command};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn pcbex(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .args(arguments)
        .output()
        .unwrap()
}

fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}

fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
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

fn route_json(input: &Path, board: &Path, report: &Path, partial: bool) {
    let mut arguments = vec![
        "route",
        path(input),
        "--output",
        path(board),
        "--convergence-report",
        path(report),
        "--convergence-rounds",
        if partial { "1" } else { "2" },
        "--convergence-candidates",
        if partial { "1" } else { "3" },
        "--convergence-workers",
        if partial { "1" } else { "2" },
        "--convergence-router-workers",
        "1",
    ];
    if partial {
        arguments.extend(["--convergence-work-budget", "1", "--allow-unrouted"]);
    }
    let output = pcbex(&arguments);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn board_json_verification_replays_exact_sources_and_emits_closed_evidence() {
    let temporary = tempfile::tempdir().unwrap();
    let temporary_root = fs::canonicalize(temporary.path()).unwrap();
    let input = temporary_root.join("input.board.json");
    fs::copy(root().join("examples/simple.json"), &input).unwrap();
    let routed = temporary_root.join("routed.board.json");
    let convergence = temporary_root.join("convergence.json");
    let verification = temporary_root.join("verification.json");
    route_json(&input, &routed, &convergence, false);

    let output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&routed),
        "--report",
        path(&convergence),
        "--output",
        path(&verification),
        "--require-complete",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let retained_raw = fs::read(&verification).unwrap();
    assert_eq!(retained_raw.last(), Some(&b'\n'));
    let retained: Value = serde_json::from_slice(&retained_raw).unwrap();
    assert_eq!(retained["schema_version"], 1);
    assert_eq!(
        retained["scope"],
        "fresh_exact_routing_convergence_verification"
    );
    assert_eq!(retained["engine_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(retained["input_kind"], "board_json");
    assert_eq!(retained["status"], "verified_complete");
    assert_eq!(retained["routing_complete"], true);
    for claim in [
        "source_authenticity_verified",
        "native_kicad_drc_verified",
        "manufacturability_verified",
        "release_authorized",
    ] {
        assert_eq!(retained[claim], false);
    }
    assert_eq!(retained["validation"]["fresh_convergence_replayed"], true);
    assert_eq!(retained["validation"]["retained_report_exact"], true);
    assert_eq!(retained["validation"]["routed_output_exact"], true);
    assert_eq!(retained["binding_sha256"].as_str().unwrap().len(), 64);

    for (name, source) in [
        ("input", fs::read(&input).unwrap()),
        ("routed_output", fs::read(&routed).unwrap()),
        ("retained_report", fs::read(&convergence).unwrap()),
    ] {
        assert_eq!(retained["sources"][name]["bytes"], source.len() as u64);
        assert_eq!(retained["sources"][name]["sha256"], sha256(&source));
    }

    let schema_path = temporary_root.join("verification.schema.json");
    let output = pcbex(&[
        "routing-convergence-verification-report-schema",
        "--output",
        path(&schema_path),
    ]);
    assert!(output.status.success());
    let schema: Value = serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
    audit_closed_schema(&schema);
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["convergence"]["$ref"],
        "#/$defs/convergence_report"
    );
}

#[test]
fn partial_verification_is_retained_before_optional_gate() {
    let temporary = tempfile::tempdir().unwrap();
    let temporary_root = fs::canonicalize(temporary.path()).unwrap();
    let input = root().join("examples/simple.json");
    let routed = temporary_root.join("partial.board.json");
    let convergence = temporary_root.join("partial.convergence.json");
    route_json(&input, &routed, &convergence, true);

    let gated = temporary_root.join("gated.verification.json");
    let output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&routed),
        "--report",
        path(&convergence),
        "--output",
        path(&gated),
        "--require-complete",
    ]);
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .last()
            .unwrap(),
        "Error: fresh routing convergence verification retained an incomplete routing result"
    );
    let gated_raw = fs::read(&gated).unwrap();
    let retained: Value = serde_json::from_slice(&gated_raw).unwrap();
    assert_eq!(retained["status"], "verified_no_admissible_candidate");
    assert_eq!(retained["routing_complete"], false);
    assert_eq!(retained["convergence"]["converged"], false);

    let allowed = temporary_root.join("allowed.verification.json");
    let output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&routed),
        "--report",
        path(&convergence),
        "--output",
        path(&allowed),
    ]);
    assert!(output.status.success());
    assert_eq!(gated_raw, fs::read(allowed).unwrap());
}

#[test]
fn tampering_aliases_and_no_clobber_fail_without_verification_output() {
    let temporary = tempfile::tempdir().unwrap();
    let temporary_root = fs::canonicalize(temporary.path()).unwrap();
    let input = temporary_root.join("input.board.json");
    fs::copy(root().join("examples/simple.json"), &input).unwrap();
    let routed = temporary_root.join("routed.board.json");
    let convergence = temporary_root.join("convergence.json");
    route_json(&input, &routed, &convergence, false);

    let tampered_routed = temporary_root.join("tampered.board.json");
    let mut routed_raw = fs::read(&routed).unwrap();
    routed_raw.push(b'\n');
    fs::write(&tampered_routed, routed_raw).unwrap();
    let output_path = temporary_root.join("tampered-output.verification.json");
    let output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&tampered_routed),
        "--report",
        path(&convergence),
        "--output",
        path(&output_path),
    ]);
    assert!(!output.status.success());
    assert!(!output_path.exists());

    let tampered_report = temporary_root.join("tampered.convergence.json");
    let mut report: Value = serde_json::from_slice(&fs::read(&convergence).unwrap()).unwrap();
    let length = report["final_metrics"]["total_length_nm"].as_i64().unwrap();
    report["final_metrics"]["total_length_nm"] = json!(length + 1);
    fs::write(
        &tampered_report,
        format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
    )
    .unwrap();
    let report_output = temporary_root.join("report-tamper.verification.json");
    let output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&routed),
        "--report",
        path(&tampered_report),
        "--output",
        path(&report_output),
    ]);
    assert!(!output.status.success());
    assert!(!report_output.exists());

    let duplicate_report = temporary_root.join("duplicate.convergence.json");
    let report_text = String::from_utf8(fs::read(&convergence).unwrap()).unwrap();
    fs::write(
        &duplicate_report,
        report_text.replacen(
            '{',
            "{\n  \"scope\": \"bounded_deterministic_routing_convergence\",",
            1,
        ),
    )
    .unwrap();
    let duplicate_output = temporary_root.join("duplicate.verification.json");
    let output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&routed),
        "--report",
        path(&duplicate_report),
        "--output",
        path(&duplicate_output),
    ]);
    assert!(!output.status.success());
    assert!(!duplicate_output.exists());

    let noncanonical_report = temporary_root.join("noncanonical.convergence.json");
    let mut report_raw = fs::read(&convergence).unwrap();
    assert_eq!(report_raw.pop(), Some(b'\n'));
    fs::write(&noncanonical_report, report_raw).unwrap();
    let noncanonical_output = temporary_root.join("noncanonical.verification.json");
    let output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&routed),
        "--report",
        path(&noncanonical_report),
        "--output",
        path(&noncanonical_output),
    ]);
    assert!(!output.status.success());
    assert!(!noncanonical_output.exists());

    let preserved = temporary_root.join("preserved.verification.json");
    fs::write(&preserved, b"preserve\n").unwrap();
    let output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&routed),
        "--report",
        path(&convergence),
        "--output",
        path(&preserved),
    ]);
    assert!(!output.status.success());
    assert_eq!(fs::read(&preserved).unwrap(), b"preserve\n");

    let alias_output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&routed),
        "--report",
        path(&convergence),
        "--output",
        path(&input),
    ]);
    assert!(!alias_output.status.success());
    assert!(input.is_file());

    let hardlink = temporary_root.join("input-hardlink.board.json");
    fs::hard_link(&input, &hardlink).unwrap();
    let hardlink_output = temporary_root.join("hardlink.verification.json");
    let output = pcbex(&[
        "verify-routing-convergence",
        path(&input),
        "--routed",
        path(&hardlink),
        "--report",
        path(&convergence),
        "--output",
        path(&hardlink_output),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must not alias"));
    assert!(!hardlink_output.exists());
}

#[test]
fn kicad_verification_replays_the_same_effective_board_and_output_writer() {
    let temporary = tempfile::tempdir().unwrap();
    let temporary_root = fs::canonicalize(temporary.path()).unwrap();
    let input = root().join("examples/simple.kicad_pcb");
    let routed = temporary_root.join("routed.kicad_pcb");
    let convergence = temporary_root.join("convergence.json");
    let output = pcbex(&[
        "route-kicad",
        path(&input),
        "--output",
        path(&routed),
        "--convergence-report",
        path(&convergence),
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

    let verification = temporary_root.join("verification.json");
    let output = pcbex(&[
        "verify-kicad-routing-convergence",
        path(&input),
        "--routed",
        path(&routed),
        "--report",
        path(&convergence),
        "--output",
        path(&verification),
        "--require-complete",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let retained: Value = serde_json::from_slice(&fs::read(verification).unwrap()).unwrap();
    assert_eq!(retained["input_kind"], "kicad_pcb");
    assert_eq!(retained["status"], "verified_complete");
    assert_eq!(retained["routing_complete"], true);
    assert_eq!(retained["sources"]["project"], Value::Null);
    assert_eq!(retained["sources"]["rules_file"], Value::Null);
}

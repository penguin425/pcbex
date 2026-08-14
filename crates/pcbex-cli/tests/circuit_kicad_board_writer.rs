use pcbex_kicad::{
    circuit_spec_v2_sha256, circuit_spec_v3_sha256, circuit_spec_v3_to_physical_v2,
    parse_circuit_spec_v3,
};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(directory.path()).unwrap();
    (directory, canonical)
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn example(name: &str) -> PathBuf {
    repository_root().join("examples").join(name)
}

fn path(value: &Path) -> &str {
    value.to_str().expect("test path is UTF-8")
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_schematic(directory: &Path) -> PathBuf {
    write_schematic_for(directory, &example("circuit-board-spec-v2.json"))
}

fn write_schematic_for(directory: &Path, spec: &Path) -> PathBuf {
    let schematic = directory.join("generated.kicad_sch");
    assert_success(
        Command::new(binary())
            .args([
                "write-circuit-spec-kicad-schematic",
                path(spec),
                "--output",
                path(&schematic),
            ])
            .output()
            .unwrap(),
    );
    schematic
}

fn generate(schematic: &Path, output_dir: &Path, closure: &Path) -> Output {
    generate_for(
        &example("circuit-board-spec-v2.json"),
        schematic,
        output_dir,
        closure,
    )
}

fn generate_for(spec: &Path, schematic: &Path, output_dir: &Path, closure: &Path) -> Output {
    Command::new(binary())
        .args([
            "generate-circuit-kicad-board",
            path(spec),
            path(schematic),
            "--footprint-closure",
            path(closure),
            "--construction-profile",
            path(&example("circuit-board-construction-profile-v1.json")),
            "--physical-profile",
            path(&example("circuit-board-physical-profile-v1.json")),
            "--output-dir",
            path(output_dir),
        ])
        .output()
        .unwrap()
}

#[test]
fn multi_unit_v3_collapses_to_one_physical_footprint_and_retains_exact_binding() {
    let (_workspace_guard, workspace) = canonical_tempdir();
    let spec = example("circuit-board-spec-v3.json");
    let closure = example("circuit-board-footprint-closure-v1.json");
    let schematic = write_schematic_for(&workspace, &spec);
    let output_dir = workspace.join("v3-board");
    assert_success(generate_for(&spec, &schematic, &output_dir, &closure));

    let board = fs::read_to_string(output_dir.join("board.kicad_pcb")).unwrap();
    assert_eq!(board.matches("(footprint \"Package:QFN\"").count(), 1);
    assert_eq!(board.matches("(fp_text reference \"U1\"").count(), 1);
    let binding: Value =
        serde_json::from_slice(&fs::read(output_dir.join("board-binding.json")).unwrap()).unwrap();
    assert_eq!(binding["approved"], true);
    assert_eq!(binding["findings"].as_array().unwrap().len(), 0);
    let manifest: Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json")).unwrap()).unwrap();
    let source = fs::read_to_string(&spec).unwrap();
    let parsed = parse_circuit_spec_v3(&source).unwrap();
    let expected_v3_digest = circuit_spec_v3_sha256(&parsed).unwrap();
    let projected_v2_digest =
        circuit_spec_v2_sha256(&circuit_spec_v3_to_physical_v2(&parsed).unwrap()).unwrap();
    assert_eq!(
        manifest["circuit_spec_sha256"],
        binding["circuit_kicad_handoff"]["circuit_spec_sha256"]
    );
    assert_eq!(manifest["circuit_spec_sha256"], expected_v3_digest);
    assert_ne!(expected_v3_digest, projected_v2_digest);
    assert_eq!(manifest["component_count"], 2);
}

#[test]
fn generates_deterministic_exact_board_bundle_and_downstream_consumers_accept_it() {
    let (_workspace_guard, workspace) = canonical_tempdir();
    let schematic = write_schematic(&workspace);
    let first = workspace.join("first");
    let second = workspace.join("second");
    let closure = example("circuit-board-footprint-closure-v1.json");
    assert_success(generate(&schematic, &first, &closure));
    assert_success(generate(&schematic, &second, &closure));

    let mut names = fs::read_dir(&first)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["board-binding.json", "board.kicad_pcb", "manifest.json"]
    );
    for name in &names {
        assert_eq!(
            fs::read(first.join(name)).unwrap(),
            fs::read(second.join(name)).unwrap()
        );
    }

    let binding: Value =
        serde_json::from_slice(&fs::read(first.join("board-binding.json")).unwrap()).unwrap();
    assert_eq!(binding["approved"], true);
    assert_eq!(binding["counts"]["errors"], 0);
    let manifest: Value =
        serde_json::from_slice(&fs::read(first.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["approved"], true);
    assert_eq!(manifest["board_state"], "placed_but_unrouted");
    assert_eq!(manifest["routing_performed"], false);
    assert_eq!(manifest["drc_claimed"], false);
    assert_eq!(manifest["dfm_claimed"], false);

    let replay = workspace.join("fresh-binding.json");
    assert_success(
        Command::new(binary())
            .args([
                "verify-circuit-kicad-board-binding",
                path(&example("circuit-board-spec-v2.json")),
                path(&schematic),
                path(&first.join("board.kicad_pcb")),
                "--output",
                path(&replay),
                "--require-approved",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(
        fs::read(replay).unwrap(),
        fs::read(first.join("board-binding.json")).unwrap()
    );

    let routed = workspace.join("routed.kicad_pcb");
    assert_success(
        Command::new(binary())
            .args([
                "route-kicad",
                path(&first.join("board.kicad_pcb")),
                "--physical-profile",
                path(&example("circuit-board-physical-profile-v1.json")),
                "--grid-mm",
                "0.1",
                "--width-mm",
                "0.25",
                "--clearance-mm",
                "0.2",
                "--via-diameter-mm",
                "0.66",
                "--via-drill-mm",
                "0.3",
                "--bend-cost",
                "5",
                "--via-cost",
                "50",
                "--output",
                path(&routed),
                "--allow-unrouted",
            ])
            .output()
            .unwrap(),
    );
    assert!(fs::metadata(routed).unwrap().len() > 0);
}

#[test]
fn rejects_tampered_closure_before_publishing_a_directory() {
    let (_workspace_guard, workspace) = canonical_tempdir();
    let schematic = write_schematic(&workspace);
    let mut closure: Value = serde_json::from_slice(
        &fs::read(example("circuit-board-footprint-closure-v1.json")).unwrap(),
    )
    .unwrap();
    closure["footprints"][0]["source_sha256"] = Value::String("0".repeat(64));
    let tampered = workspace.join("tampered-closure.json");
    fs::write(&tampered, serde_json::to_vec(&closure).unwrap()).unwrap();
    let output_dir = workspace.join("rejected");
    let output = generate(&schematic, &output_dir, &tampered);
    assert!(!output.status.success());
    assert!(!output_dir.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(path(&workspace)),
        "error leaked caller path: {stderr}"
    );
}

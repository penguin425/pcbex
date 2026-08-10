use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
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
    let schematic = directory.join("generated.kicad_sch");
    assert_success(
        Command::new(binary())
            .args([
                "write-circuit-spec-kicad-schematic",
                path(&example("circuit-board-spec-v2.json")),
                "--output",
                path(&schematic),
            ])
            .output()
            .unwrap(),
    );
    schematic
}

fn generate(schematic: &Path, output_dir: &Path, closure: &Path) -> Output {
    Command::new(binary())
        .args([
            "generate-circuit-kicad-board",
            path(&example("circuit-board-spec-v2.json")),
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
fn generates_deterministic_exact_board_bundle_and_downstream_consumers_accept_it() {
    let workspace = tempfile::tempdir().unwrap();
    let schematic = write_schematic(workspace.path());
    let first = workspace.path().join("first");
    let second = workspace.path().join("second");
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

    let replay = workspace.path().join("fresh-binding.json");
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

    let routed = workspace.path().join("routed.kicad_pcb");
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
    let workspace = tempfile::tempdir().unwrap();
    let schematic = write_schematic(workspace.path());
    let mut closure: Value = serde_json::from_slice(
        &fs::read(example("circuit-board-footprint-closure-v1.json")).unwrap(),
    )
    .unwrap();
    closure["footprints"][0]["source_sha256"] = Value::String("0".repeat(64));
    let tampered = workspace.path().join("tampered-closure.json");
    fs::write(&tampered, serde_json::to_vec(&closure).unwrap()).unwrap();
    let output_dir = workspace.path().join("rejected");
    let output = generate(&schematic, &output_dir, &tampered);
    assert!(!output.status.success());
    assert!(!output_dir.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(path(workspace.path())),
        "error leaked caller path: {stderr}"
    );
}

use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_directory(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pcbex-{name}-{}-{unique}", std::process::id()))
}

fn run(arguments: &[&Path]) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pcbex"));
    for argument in arguments {
        command.arg(argument);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "pcbex failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_failure(arguments: &[&Path]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pcbex"));
    for argument in arguments {
        command.arg(argument);
    }
    let output = command.output().unwrap();
    assert!(
        !output.status.success(),
        "pcbex unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    output
}

#[test]
fn writes_deterministic_json_and_kicad_candidate_bundles() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let placement = root.join("examples/placement.json");
    let sequential = temporary_directory("placement-candidates-sequential");
    let parallel = temporary_directory("placement-candidates-parallel");
    let sequential_args = [
        Path::new("place-candidates"),
        &placement,
        Path::new("--output-dir"),
        &sequential,
        Path::new("--candidates"),
        Path::new("5"),
        Path::new("--workers"),
        Path::new("1"),
        Path::new("--iterations"),
        Path::new("200"),
    ];
    run(&sequential_args);
    let parallel_args = [
        Path::new("place-candidates"),
        &placement,
        Path::new("--output-dir"),
        &parallel,
        Path::new("--candidates"),
        Path::new("5"),
        Path::new("--workers"),
        Path::new("4"),
        Path::new("--iterations"),
        Path::new("200"),
    ];
    run(&parallel_args);
    let sequential_manifest: Value =
        serde_json::from_slice(&fs::read(sequential.join("candidates.json")).unwrap()).unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(parallel.join("candidates.json")).unwrap()).unwrap();
    assert_eq!(sequential_manifest["candidates"], manifest["candidates"]);
    assert_eq!(
        sequential_manifest["pareto_front"],
        manifest["pareto_front"]
    );
    assert_eq!(
        sequential_manifest["selected_candidate_id"],
        manifest["selected_candidate_id"]
    );
    assert_eq!(manifest["candidates"].as_array().unwrap().len(), 5);
    let selected = manifest["selected_candidate_id"].as_str().unwrap();
    assert!(
        manifest["pareto_front"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate == selected)
    );
    assert!(parallel.join("selected.json").is_file());

    let kicad = temporary_directory("placement-candidates-kicad");
    let board = root.join("examples/simple.kicad_pcb");
    let kicad_args = [
        Path::new("place-kicad-candidates"),
        &board,
        Path::new("--output-dir"),
        &kicad,
        Path::new("--candidates"),
        Path::new("3"),
        Path::new("--workers"),
        Path::new("2"),
        Path::new("--iterations"),
        Path::new("50"),
    ];
    run(&kicad_args);
    assert!(kicad.join("selected.kicad_pcb").is_file());
    assert!(kicad.join("candidate-001-balanced.kicad_pcb").is_file());
    assert!(kicad.join("candidate-002-wirelength.kicad_pcb").is_file());
    assert!(kicad.join("candidate-003-routability.kicad_pcb").is_file());

    fs::remove_dir_all(sequential).unwrap();
    fs::remove_dir_all(parallel).unwrap();
    fs::remove_dir_all(kicad).unwrap();
}

#[test]
fn rejects_physical_profile_outline_drift_before_publishing_placement() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temporary = temporary_directory("placement-profile-outline");
    fs::create_dir_all(&temporary).unwrap();
    let profile_path = temporary.join("profile.json");
    let output_path = temporary.join("placed.kicad_pcb");
    let mut profile: Value = serde_json::from_slice(
        &fs::read(repository.join("examples/multilayer-physical-profile.json")).unwrap(),
    )
    .unwrap();
    profile["outline"] = serde_json::json!([
        {"x_nm": 0, "y_nm": 0},
        {"x_nm": 40_000_000, "y_nm": 0},
        {"x_nm": 0, "y_nm": 20_000_000}
    ]);
    fs::write(&profile_path, serde_json::to_vec_pretty(&profile).unwrap()).unwrap();

    let output = run_failure(&[
        Path::new("place-kicad"),
        &repository.join("examples/simple.kicad_pcb"),
        Path::new("--output"),
        &output_path,
        Path::new("--physical-profile"),
        &profile_path,
        Path::new("--iterations"),
        Path::new("1"),
    ]);

    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("board outline does not match physical constraint profile")
    );
    assert!(!output_path.exists());
    fs::remove_dir_all(temporary).unwrap();
}

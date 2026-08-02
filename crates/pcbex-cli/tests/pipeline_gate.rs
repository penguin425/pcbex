use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

const FIRMWARE_FILES: [&str; 5] = [
    "pinout.h",
    "firmware.h",
    "firmware.c",
    "firmware_smoke_test.c",
    "host.py",
];

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> String {
    sha256(&fs::read(path).unwrap())
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn write_json(path: &Path, value: &Value) {
    let mut rendered = serde_json::to_vec_pretty(value).unwrap();
    rendered.push(b'\n');
    fs::write(path, rendered).unwrap();
}

fn assert_success(output: &Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[derive(Clone, Debug)]
struct PipelineInputs {
    schematic: PathBuf,
    electrical_policy: Option<PathBuf>,
    electrical_review: PathBuf,
    board: PathBuf,
    analysis_manifest: PathBuf,
    analysis_checks: PathBuf,
    quality: PathBuf,
    analysis_project: Option<PathBuf>,
    analysis_rules: Option<PathBuf>,
    analysis_dfm_profile: Option<PathBuf>,
    analysis_policy_pack: Option<PathBuf>,
    manufacturing_package: PathBuf,
    firmware_manifest: PathBuf,
}

impl PipelineInputs {
    fn command(&self, output: &Path) -> Command {
        let mut command = Command::new(binary());
        command
            .arg("pipeline-verify")
            .arg("--schematic")
            .arg(&self.schematic);
        if let Some(policy) = &self.electrical_policy {
            command.arg("--electrical-policy").arg(policy);
        }
        for (flag, path) in [
            ("--analysis-project", self.analysis_project.as_ref()),
            ("--analysis-rules", self.analysis_rules.as_ref()),
            ("--analysis-dfm-profile", self.analysis_dfm_profile.as_ref()),
            ("--analysis-policy-pack", self.analysis_policy_pack.as_ref()),
        ] {
            if let Some(path) = path {
                command.arg(flag).arg(path);
            }
        }
        command
            .arg("--electrical-review")
            .arg(&self.electrical_review)
            .arg("--board")
            .arg(&self.board)
            .arg("--analysis-manifest")
            .arg(&self.analysis_manifest)
            .arg("--analysis-checks")
            .arg(&self.analysis_checks)
            .arg("--quality")
            .arg(&self.quality)
            .arg("--manufacturing-package")
            .arg(&self.manufacturing_package)
            .arg("--firmware-manifest")
            .arg(&self.firmware_manifest)
            .arg("--output")
            .arg(output);
        command
    }
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("examples")
        .join(name)
}

fn make_approved_electrical_review(
    directory: &Path,
    schematic: &Path,
) -> (PathBuf, PathBuf, String) {
    let policy_path = directory.join("electrical-policy.json");
    let policy_output = Command::new(binary())
        .arg("electrical-policy")
        .arg("--output")
        .arg(&policy_path)
        .output()
        .unwrap();
    assert_success(&policy_output, "electrical-policy");

    let mut policy = read_json(&policy_path);
    for rule in policy["rules"].as_object_mut().unwrap().values_mut() {
        if rule["severity"] == "error" {
            rule["enabled"] = Value::Bool(false);
        }
    }
    write_json(&policy_path, &policy);

    let review_path = directory.join("electrical-review.json");
    let review_output = Command::new(binary())
        .arg("check-schematic")
        .arg(schematic)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--output")
        .arg(&review_path)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert_success(&review_output, "check-schematic");
    let review = read_json(&review_path);
    assert_eq!(review["approved"], true);
    assert_eq!(review["counts"]["errors"], 0);
    let schematic_sha256 = review["schematic_sha256"].as_str().unwrap().to_string();
    (policy_path, review_path, schematic_sha256)
}

fn make_routed_board(directory: &Path, input: &Path) -> PathBuf {
    let output_path = directory.join("simple.routed.kicad_pcb");
    let output = Command::new(binary())
        .arg("route-kicad")
        .arg(input)
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert_success(&output, "route-kicad");
    output_path
}

fn make_clean_analysis(directory: &Path, board: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let output = Command::new(binary())
        .arg("analyze-kicad")
        .arg(board)
        .arg("--output-dir")
        .arg(directory)
        .arg("--fail-on-violations")
        .output()
        .unwrap();
    assert_success(&output, "analyze-kicad");

    let checks_path = directory.join("checks.json");
    let quality_path = directory.join("quality.json");
    let manifest_path = directory.join("run.json");
    let checks = read_json(&checks_path);
    assert!(checks["violations"].as_array().unwrap().is_empty());
    let quality = read_json(&quality_path);
    assert_eq!(quality["routed_nets"], 1);
    assert_eq!(quality["unrouted_nets"], 0);
    let manifest = read_json(&manifest_path);
    assert_eq!(manifest["command"], "analyze-kicad");
    assert_eq!(manifest["input"]["sha256"], sha256_file(board));
    assert_eq!(manifest["result"]["clean"], true);
    assert_eq!(manifest["result"]["violations"], 0);
    assert_eq!(manifest["result"]["routed_nets"], 1);
    assert_eq!(manifest["result"]["unrouted_nets"], 0);
    (manifest_path, checks_path, quality_path)
}

fn write_manufacturing_package(path: &Path, board: &Path) {
    let board_bytes = fs::read(board).unwrap();
    let board_name = board.file_name().unwrap().to_str().unwrap();
    let gerber_job = serde_json::to_vec(&json!({
        "GeneralSpecs": {"LayerNumber": 2},
        "FilesAttributes": [
            {"Path": "board-F_Cu.gtl", "FileFunction": "Copper,L1,Top"},
            {"Path": "board-B_Cu.gbl", "FileFunction": "Copper,L2,Bot"},
            {"Path": "board-f_mask.gts", "FileFunction": "SolderMask,Top"},
            {"Path": "board-b_mask.gbs", "FileFunction": "SolderMask,Bot"},
            {"Path": "board-f_silkscreen.gto", "FileFunction": "Legend,Top"},
            {"Path": "board-b_silkscreen.gbo", "FileFunction": "Legend,Bot"},
            {"Path": "board-Edge_Cuts.gm1", "FileFunction": "Profile"}
        ]
    }))
    .unwrap();
    let artifacts = vec![
        ("board-F_Cu.gtl", b"front-copper".to_vec()),
        ("board-B_Cu.gbl", b"back-copper".to_vec()),
        ("board-f_mask.gts", b"front-mask".to_vec()),
        ("board-b_mask.gbs", b"back-mask".to_vec()),
        ("board-f_silkscreen.gto", b"front-legend".to_vec()),
        ("board-b_silkscreen.gbo", b"back-legend".to_vec()),
        ("board-Edge_Cuts.gm1", b"profile".to_vec()),
        ("board-job.gbrjob", gerber_job),
        ("board.drl", b"drill".to_vec()),
        ("drc.rpt", b"DRC clean\n".to_vec()),
        ("bom.csv", b"Comment,Designator\n".to_vec()),
        ("cpl.csv", b"Designator,Mid X (mm)\n".to_vec()),
    ];
    let manifest = json!({
        "schema_version": 1,
        "engine": "pcbex",
        "engine_version": env!("CARGO_PKG_VERSION"),
        "tools": {
            "kicad_cli": "10.0.5",
            "kicad_cli_about_sha256": "a".repeat(64)
        },
        "input": {
            "path": board_name,
            "bytes": board_bytes.len(),
            "sha256": sha256(&board_bytes)
        },
        "project_inputs": [],
        "parts": {"total": 0, "bom": 0, "placement": 0, "dnp": 0},
        "artifacts": artifacts.iter().map(|(artifact_path, bytes)| json!({
            "path": artifact_path,
            "bytes": bytes.len(),
            "sha256": sha256(bytes)
        })).collect::<Vec<_>>(),
        "archive": "manufacturing.zip"
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (artifact_path, bytes) in artifacts {
        writer.start_file(artifact_path, options).unwrap();
        writer.write_all(&bytes).unwrap();
    }
    writer.start_file("manifest.json", options).unwrap();
    writer.write_all(&manifest_bytes).unwrap();
    fs::write(path, writer.finish().unwrap().into_inner()).unwrap();
}

fn write_firmware_manifest(directory: &Path, schematic_sha256: &str) -> PathBuf {
    let contents: [&[u8]; 5] = [
        b"#define STATUS_LED_PIN 1\n",
        b"void firmware_tick(void);\n",
        b"void firmware_tick(void) {}\n",
        b"int main(void) { firmware_tick(); return 0; }\n",
        b"print('firmware smoke check')\n",
    ];
    let artifacts = FIRMWARE_FILES
        .iter()
        .zip(contents)
        .map(|(name, bytes)| {
            fs::write(directory.join(name), bytes).unwrap();
            json!({"path": name, "bytes": bytes.len(), "sha256": sha256(bytes)})
        })
        .collect::<Vec<_>>();
    let manifest = json!({
        "schema_version": 1,
        "engine": "pcbex",
        "engine_version": env!("CARGO_PKG_VERSION"),
        "schematic_sha256": schematic_sha256,
        "artifacts": artifacts,
        "c_build": {
            "attempted": true,
            "passed": true,
            "command": ["cc", "firmware.c", "firmware_smoke_test.c"]
        },
        "python_check": {
            "attempted": true,
            "passed": true,
            "command": ["python3", "-m", "py_compile", "host.py"]
        }
    });
    let path = directory.join("firmware-manifest.json");
    write_json(&path, &manifest);
    path
}

fn passing_inputs(directory: &Path) -> (PipelineInputs, String, String) {
    let schematic = example("simple.kicad_sch");
    let board_input = example("simple.kicad_pcb");
    let (electrical_policy, electrical_review, schematic_sha256) =
        make_approved_electrical_review(directory, &schematic);
    let board = make_routed_board(directory, &board_input);
    let analysis_directory = directory.join("analysis");
    let (analysis_manifest, analysis_checks, quality) =
        make_clean_analysis(&analysis_directory, &board);
    let manufacturing_package = directory.join("manufacturing.zip");
    write_manufacturing_package(&manufacturing_package, &board);
    let firmware_manifest = write_firmware_manifest(directory, &schematic_sha256);
    let board_sha256 = sha256_file(&board);
    (
        PipelineInputs {
            schematic,
            electrical_policy: Some(electrical_policy),
            electrical_review,
            board,
            analysis_manifest,
            analysis_checks,
            quality,
            analysis_project: None,
            analysis_rules: None,
            analysis_dfm_profile: None,
            analysis_policy_pack: None,
            manufacturing_package,
            firmware_manifest,
        },
        schematic_sha256,
        board_sha256,
    )
}

fn missing_inputs(directory: &Path) -> PipelineInputs {
    PipelineInputs {
        schematic: directory.join("missing.kicad_sch"),
        electrical_policy: Some(directory.join("missing-policy.json")),
        electrical_review: directory.join("missing-review.json"),
        board: directory.join("missing.kicad_pcb"),
        analysis_manifest: directory.join("missing-run.json"),
        analysis_checks: directory.join("missing-checks.json"),
        quality: directory.join("missing-quality.json"),
        analysis_project: None,
        analysis_rules: None,
        analysis_dfm_profile: None,
        analysis_policy_pack: None,
        manufacturing_package: directory.join("missing-manufacturing.zip"),
        firmware_manifest: directory.join("missing-firmware.json"),
    }
}

fn one_dummy_input(path: &Path) -> PipelineInputs {
    PipelineInputs {
        schematic: path.to_path_buf(),
        electrical_policy: None,
        electrical_review: path.to_path_buf(),
        board: path.to_path_buf(),
        analysis_manifest: path.to_path_buf(),
        analysis_checks: path.to_path_buf(),
        quality: path.to_path_buf(),
        analysis_project: None,
        analysis_rules: None,
        analysis_dfm_profile: None,
        analysis_policy_pack: None,
        manufacturing_package: path.to_path_buf(),
        firmware_manifest: path.to_path_buf(),
    }
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn assert_evidence_descriptors(report: &Value) {
    for phase in report["phases"].as_array().unwrap() {
        let evidence = phase["evidence"].as_array().unwrap();
        assert!(!evidence.is_empty());
        for descriptor in evidence {
            assert_eq!(
                keys(descriptor),
                BTreeSet::from(["bytes", "role", "sha256"])
            );
            assert!(!descriptor["role"].as_str().unwrap().is_empty());
            assert!(descriptor["bytes"].as_u64().unwrap() > 0);
            let digest = descriptor["sha256"].as_str().unwrap();
            assert_eq!(digest.len(), 64);
            assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }
}

fn phase<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["phases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|phase| phase["name"] == name)
        .unwrap()
}

fn tamper_zip_entry(path: &Path, entry_name: &str) {
    let mut bytes = fs::read(path).unwrap();
    let offset = {
        let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
        archive.by_name(entry_name).unwrap().data_start().unwrap() as usize
    };
    bytes[offset] ^= 1;
    fs::write(path, bytes).unwrap();
}

#[test]
fn pipeline_verify_accepts_a_digest_bound_end_to_end_pipeline() {
    let temporary = tempfile::tempdir().unwrap();
    let (inputs, schematic_sha256, board_sha256) = passing_inputs(temporary.path());
    let report_path = temporary.path().join("pipeline-report.json");
    let output = inputs.command(&report_path).output().unwrap();
    assert_success(&output, "pipeline-verify");

    let report = read_json(&report_path);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["pipeline"], "pcbex-hardware-v1");
    assert_eq!(report["passed"], true);
    assert_eq!(report["failures"], json!([]));
    assert_eq!(
        report["phases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|phase| phase["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "electrical-erc",
            "analysis-drc",
            "routing-quality",
            "manufacturing-package",
            "firmware-build",
        ]
    );
    assert!(
        report["phases"]
            .as_array()
            .unwrap()
            .iter()
            .all(|phase| phase["passed"] == true && phase["failures"] == json!([]))
    );
    assert_eq!(report["identities"]["schematic_sha256"], schematic_sha256);
    assert_eq!(report["identities"]["board_sha256"], board_sha256);
    assert_evidence_descriptors(&report);
}

#[test]
fn pipeline_verify_requires_explicit_analysis_sources_and_ignores_descriptor_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut inputs, _, _) = passing_inputs(temporary.path());
    let project = temporary.path().join("explicit-project.kicad_pro");
    write_json(&project, &json!({"net_settings": {"classes": []}}));
    let rules = temporary.path().join("explicit-rules.kicad_dru");
    fs::write(&rules, b"(version 1)\n").unwrap();
    let dfm_profile = example("acme-dfm-profile.json");
    let analysis = temporary.path().join("analysis-with-project");
    let analyze = Command::new(binary())
        .arg("analyze-kicad")
        .arg(&inputs.board)
        .arg("--project")
        .arg(&project)
        .arg("--rules-file")
        .arg(&rules)
        .arg("--fab-profile")
        .arg(&dfm_profile)
        .arg("--output-dir")
        .arg(&analysis)
        .arg("--fail-on-violations")
        .output()
        .unwrap();
    assert_success(&analyze, "analyze-kicad with explicit project");
    inputs.analysis_manifest = analysis.join("run.json");
    inputs.analysis_checks = analysis.join("checks.json");
    inputs.quality = analysis.join("quality.json");

    let mut manifest = read_json(&inputs.analysis_manifest);
    manifest["project"]["path"] = Value::String("/untrusted/host/secret".into());
    manifest["rules_file"]["path"] = Value::String("../../untrusted-rules".into());
    manifest["dfm_profile_file"]["path"] = Value::String("/untrusted/dfm-profile".into());
    write_json(&inputs.analysis_manifest, &manifest);

    let missing_report = temporary.path().join("missing-explicit-project.json");
    let output = inputs.command(&missing_report).output().unwrap();
    assert!(!output.status.success());
    let report = read_json(&missing_report);
    assert!(
        phase(&report, "analysis-drc")["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure.as_str().unwrap().contains("no explicit CLI path"))
    );
    assert!(
        phase(&report, "analysis-drc")["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .all(|evidence| evidence["role"] != "analysis-project")
    );

    inputs.analysis_project = Some(project.clone());
    inputs.analysis_rules = Some(rules.clone());
    inputs.analysis_dfm_profile = Some(dfm_profile.clone());
    let accepted_report = temporary.path().join("explicit-project.json");
    let output = inputs.command(&accepted_report).output().unwrap();
    assert_success(&output, "pipeline-verify with explicit project");
    let report = read_json(&accepted_report);
    assert_eq!(report["passed"], true);
    let evidence = phase(&report, "analysis-drc")["evidence"]
        .as_array()
        .unwrap();
    for (role, path) in [
        ("analysis-project", project.as_path()),
        ("analysis-rules", rules.as_path()),
        ("analysis-dfm-profile", dfm_profile.as_path()),
    ] {
        let descriptor = evidence
            .iter()
            .find(|evidence| evidence["role"] == role)
            .unwrap();
        assert_eq!(descriptor["sha256"], sha256_file(path));
    }
}

#[test]
fn pipeline_verify_recomputes_an_explicit_policy_pack() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut inputs, _, _) = passing_inputs(temporary.path());
    let policy_pack = example("acme-policy-pack.json");
    let analysis = temporary.path().join("analysis-with-policy-pack");
    let analyze = Command::new(binary())
        .arg("analyze-kicad")
        .arg(&inputs.board)
        .arg("--policy-pack")
        .arg(&policy_pack)
        .arg("--output-dir")
        .arg(&analysis)
        .arg("--fail-on-violations")
        .output()
        .unwrap();
    assert_success(&analyze, "analyze-kicad with policy pack");
    inputs.analysis_manifest = analysis.join("run.json");
    inputs.analysis_checks = analysis.join("checks.json");
    inputs.quality = analysis.join("quality.json");
    inputs.analysis_policy_pack = Some(policy_pack.clone());

    let mut manifest = read_json(&inputs.analysis_manifest);
    manifest["policy_pack_file"]["path"] = Value::String("/untrusted/policy-pack".into());
    write_json(&inputs.analysis_manifest, &manifest);

    let report_path = temporary.path().join("explicit-policy-pack.json");
    let output = inputs.command(&report_path).output().unwrap();
    assert_success(&output, "pipeline-verify with policy pack");
    let report = read_json(&report_path);
    assert_eq!(report["passed"], true);
    let evidence = phase(&report, "analysis-drc")["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|evidence| evidence["role"] == "analysis-policy-pack")
        .unwrap();
    assert_eq!(evidence["sha256"], sha256_file(&policy_pack));
}

#[test]
fn pipeline_verify_rejects_exact_board_package_and_firmware_tampering() {
    let temporary = tempfile::tempdir().unwrap();
    let (inputs, schematic_sha256, _) = passing_inputs(temporary.path());

    fs::write(
        temporary.path().join("firmware.c"),
        b"void firmware_tick(void) { /* tampered */ }\n",
    )
    .unwrap();
    let firmware_report = temporary.path().join("firmware-tamper.json");
    let output = inputs.command(&firmware_report).output().unwrap();
    assert!(!output.status.success());
    let report = read_json(&firmware_report);
    assert_eq!(phase(&report, "firmware-build")["passed"], false);
    assert!(
        phase(&report, "firmware-build")["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure.as_str().unwrap().contains("does not match"))
    );

    let _ = write_firmware_manifest(temporary.path(), &schematic_sha256);
    tamper_zip_entry(&inputs.manufacturing_package, "board-F_Cu.gtl");
    let package_report = temporary.path().join("package-tamper.json");
    let output = inputs.command(&package_report).output().unwrap();
    assert!(!output.status.success());
    let report = read_json(&package_report);
    assert_eq!(phase(&report, "manufacturing-package")["passed"], false);
    assert!(
        phase(&report, "manufacturing-package")["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure
                .as_str()
                .unwrap()
                .contains("invalid manufacturing package"))
    );

    write_manufacturing_package(&inputs.manufacturing_package, &inputs.board);
    let mut board = fs::read(&inputs.board).unwrap();
    board.extend_from_slice(b"\n");
    fs::write(&inputs.board, board).unwrap();
    let board_report = temporary.path().join("board-tamper.json");
    let output = inputs.command(&board_report).output().unwrap();
    assert!(!output.status.success());
    let report = read_json(&board_report);
    assert_eq!(phase(&report, "analysis-drc")["passed"], false);
    assert_eq!(phase(&report, "manufacturing-package")["passed"], false);
}

#[test]
fn pipeline_verify_retains_a_closed_five_phase_rejection_report() {
    let temporary = tempfile::tempdir().unwrap();
    let inputs = missing_inputs(temporary.path());
    let report_path = temporary.path().join("rejected.json");
    let output = inputs.command(&report_path).output().unwrap();
    assert!(!output.status.success());
    assert!(report_path.is_file());
    assert!(fs::read(&report_path).unwrap().ends_with(b"\n"));

    let report = read_json(&report_path);
    assert_eq!(
        keys(&report),
        BTreeSet::from([
            "failures",
            "identities",
            "passed",
            "phases",
            "pipeline",
            "schema_version",
        ])
    );
    assert_eq!(
        keys(&report["identities"]),
        BTreeSet::from(["board_sha256", "schematic_sha256"])
    );
    assert!(report["identities"]["schematic_sha256"].is_null());
    assert!(report["identities"]["board_sha256"].is_null());
    assert_eq!(report["passed"], false);
    assert!(!report["failures"].as_array().unwrap().is_empty());
    let phases = report["phases"].as_array().unwrap();
    assert_eq!(phases.len(), 5);
    for phase in phases {
        assert_eq!(
            keys(phase),
            BTreeSet::from(["checks", "evidence", "failures", "name", "passed"])
        );
        assert_eq!(phase["passed"], false);
        assert!(!phase["failures"].as_array().unwrap().is_empty());
        for evidence in phase["evidence"].as_array().unwrap() {
            assert_eq!(keys(evidence), BTreeSet::from(["bytes", "role", "sha256"]));
        }
    }
}

#[test]
fn pipeline_verify_refuses_unsafe_or_aliased_outputs_without_modification() {
    let temporary = tempfile::tempdir().unwrap();
    let input_path = temporary.path().join("input.json");
    let sentinel = b"preserve input and output\n";
    fs::write(&input_path, sentinel).unwrap();
    let inputs = one_dummy_input(&input_path);

    let existing = temporary.path().join("existing.json");
    fs::write(&existing, sentinel).unwrap();
    let existing_output = inputs.command(&existing).output().unwrap();
    assert!(!existing_output.status.success());
    assert!(
        String::from_utf8_lossy(&existing_output.stderr)
            .contains("refusing to overwrite existing output")
    );
    assert_eq!(fs::read(&existing).unwrap(), sentinel);

    let aliased_output = inputs.command(&input_path).output().unwrap();
    assert!(!aliased_output.status.success());
    assert!(
        String::from_utf8_lossy(&aliased_output.stderr)
            .contains("pipeline output must not alias an input")
    );
    assert_eq!(fs::read(&input_path).unwrap(), sentinel);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let target = temporary.path().join("symlink-target.json");
        let output_link = temporary.path().join("output-link.json");
        fs::write(&target, sentinel).unwrap();
        symlink(&target, &output_link).unwrap();
        let symlink_output = inputs.command(&output_link).output().unwrap();
        assert!(!symlink_output.status.success());
        assert!(String::from_utf8_lossy(&symlink_output.stderr).contains("symlink component"));
        assert_eq!(fs::read(&target).unwrap(), sentinel);

        let real_parent = temporary.path().join("real-parent");
        let linked_parent = temporary.path().join("linked-parent");
        fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();
        let parent_link_output = linked_parent.join("report.json");
        let output = inputs.command(&parent_link_output).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("symlink component"));
        assert!(!real_parent.join("report.json").exists());
    }
}

fn assert_schema_objects_are_closed(value: &Value) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".into()))
                && object.contains_key("properties")
            {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "object schema is not closed: {value}"
                );
            }
            for nested in object.values() {
                assert_schema_objects_are_closed(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                assert_schema_objects_are_closed(nested);
            }
        }
        _ => {}
    }
}

#[test]
fn pipeline_schema_is_closed_and_never_clobbers_output() {
    let temporary = tempfile::tempdir().unwrap();
    let schema_path = temporary.path().join("pipeline.schema.json");
    let first = Command::new(binary())
        .arg("pipeline-schema")
        .arg("--output")
        .arg(&schema_path)
        .output()
        .unwrap();
    assert_success(&first, "pipeline-schema");
    let schema = read_json(&schema_path);
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_schema_objects_are_closed(&schema);

    let sentinel = b"preserve existing schema\n";
    fs::write(&schema_path, sentinel).unwrap();
    let overwrite = Command::new(binary())
        .arg("pipeline-schema")
        .arg("--output")
        .arg(&schema_path)
        .output()
        .unwrap();
    assert!(!overwrite.status.success());
    assert!(
        String::from_utf8_lossy(&overwrite.stderr)
            .contains("refusing to overwrite existing output")
    );
    assert_eq!(fs::read(&schema_path).unwrap(), sentinel);
}

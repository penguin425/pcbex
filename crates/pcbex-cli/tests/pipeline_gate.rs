use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{ChildStdin, ChildStdout, Command, Output, Stdio},
};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

const FIRMWARE_FILES: [&str; 7] = [
    "pinout.h",
    "firmware.h",
    "firmware.c",
    "firmware_smoke_test.c",
    "firmware.cpp",
    "firmware_cpp_smoke_test.cpp",
    "host.py",
];

const RUNNER_CIRCUIT_SPEC: &str = r#"{
  "schema_version": 2,
  "parts": [
    {"reference":"U1","lib_id":"MCU:Chip","value":"Chip","footprint":"Package:QFN","mpn":null,"power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},"pins":[{"number":"1","name":"OUT","net":"SIGNAL","electrical_type":"output"},{"number":"2","name":"VCC","net":"VCC","electrical_type":"passive"}]},
    {"reference":"R1","lib_id":"Device:R","value":"10k","footprint":"Resistor_SMD:R_0603","mpn":null,"power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},"pins":[{"number":"1","name":"~","net":"SIGNAL","electrical_type":"passive"},{"number":"2","name":"~","net":"VCC","electrical_type":"passive"}]}
  ],
  "nets": [
    {"name":"SIGNAL","voltage_uv":null,"connections":[{"reference":"U1","pin":"1"},{"reference":"R1","pin":"1"}]},
    {"name":"VCC","voltage_uv":null,"connections":[{"reference":"U1","pin":"2"},{"reference":"R1","pin":"2"}]}
  ]
}"#;

const RUNNER_BOARD: &str = r#"(kicad_pcb
  (version 20250114)
  (generator pcbex-test)
  (general (thickness 1.6))
  (paper "A4")
  (layers
    (0 "F.Cu" signal)
    (31 "B.Cu" signal)
    (34 "B.Mask" user "b.mask")
    (35 "F.Mask" user "f.mask")
    (36 "B.SilkS" user "b.silkscreen")
    (37 "F.SilkS" user "f.silkscreen")
    (44 "Edge.Cuts" user))
  (setup (pad_to_mask_clearance 0))
  (net 0 "")
  (net 1 "SIGNAL")
  (net 2 "VCC")
  (footprint "Package:QFN"
    (layer "F.Cu")
    (at 10 10)
    (fp_text reference "U1" (at 0 0) (layer "F.Fab") hide)
    (fp_text value "Chip" (at 0 1) (layer "F.Fab") hide)
    (pad "1" thru_hole circle (at 0 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 1 "SIGNAL"))
    (pad "2" thru_hole circle (at 2 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 2 "VCC")))
  (footprint "Resistor_SMD:R_0603"
    (layer "F.Cu")
    (at 20 20)
    (fp_text reference "R1" (at 0 0) (layer "F.Fab") hide)
    (fp_text value "10k" (at 0 1) (layer "F.Fab") hide)
    (pad "1" thru_hole circle (at 0 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 1 "SIGNAL"))
    (pad "2" thru_hole circle (at 2 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 2 "VCC")))
  (segment (start 10 10) (end 20 20) (width 0.25) (layer "F.Cu") (net 1))
  (segment (start 12 10) (end 22 20) (width 0.25) (layer "B.Cu") (net 2))
  (gr_rect (start 0 0) (end 40 30) (stroke (width 0.05) (type default)) (fill none) (layer "Edge.Cuts")))"#;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn send_mcp(stdin: &mut ChildStdin, message: Value) {
    serde_json::to_writer(&mut *stdin, &message).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

fn receive_mcp(stdout: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(!line.is_empty(), "MCP server closed stdout unexpectedly");
    serde_json::from_str(&line).unwrap()
}

fn initialize_mcp(stdin: &mut ChildStdin, stdout: &mut BufReader<ChildStdout>) {
    send_mcp(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "pipeline-gate-test", "version": "1"}
            }
        }),
    );
    let initialized = receive_mcp(stdout);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    send_mcp(
        stdin,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
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
    analysis_physical_profile: Option<PathBuf>,
    manufacturing_package: PathBuf,
    firmware_manifest: PathBuf,
    factory_receipt: Option<PathBuf>,
    require_factory: bool,
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
            (
                "--analysis-physical-profile",
                self.analysis_physical_profile.as_ref(),
            ),
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
        if let Some(receipt) = &self.factory_receipt {
            command.arg("--factory-receipt").arg(receipt);
        }
        if self.require_factory {
            command.arg("--require-factory");
        }
        command
    }
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("examples")
        .join(name)
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn runner_schematic() -> String {
    let mut source = include_str!("../../../examples/simple.kicad_sch").to_string();
    source = source.replace("(pin power_in line", "(pin passive line");
    source = source.replace(
        r##"  (no_connect
    (at 42.54 20)
    (uuid 00000000-0000-0000-0000-000000000015))"##,
        r##"  (global_label "VCC"
    (shape input)
    (at 42.54 20 0)
    (effects (font (size 1.27 1.27)) (justify left))
    (uuid 00000000-0000-0000-0000-000000000015)
    (property "Intersheetrefs" "${INTERSHEET_REFS}"
      (at 42.54 20 0)
      (effects (font (size 1.27 1.27)) hide)))"##,
    );
    for (footprint, property) in [
        (
            "Package:QFN",
            "    (property \"pcbex:requires_decoupling\" \"false\")\n    (property \"pcbex:decoupling\" \"false\")",
        ),
        (
            "Resistor_SMD:R_0603",
            "    (property \"pcbex:requires_decoupling\" \"false\")\n    (property \"pcbex:decoupling\" \"false\")",
        ),
    ] {
        let needle = format!(
            "    (property \"Footprint\" \"{footprint}\"\n      (at {} 20 0)\n      (effects (font (size 1.27 1.27)) hide))",
            if footprint == "Package:QFN" {
                "12.54"
            } else {
                "40"
            }
        );
        let replacement = format!("{needle}\n{property}");
        source = source.replace(&needle, &replacement);
    }
    source
}

fn plan_descriptor(root: &Path, path: &Path) -> Value {
    let bytes = fs::read(path).unwrap();
    let relative = path
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    json!({
        "path": relative,
        "bytes": bytes.len(),
        "sha256": sha256(&bytes),
    })
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

fn make_runner_clean_analysis(directory: &Path, board: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let output = Command::new(binary())
        .arg("analyze-kicad")
        .arg(board)
        .arg("--output-dir")
        .arg(directory)
        .arg("--fail-on-violations")
        .output()
        .unwrap();
    assert_success(&output, "runner analyze-kicad");
    let manifest_path = directory.join("run.json");
    let checks_path = directory.join("checks.json");
    let quality_path = directory.join("quality.json");
    let manifest = read_json(&manifest_path);
    assert_eq!(manifest["input"]["sha256"], sha256_file(board));
    assert_eq!(manifest["result"]["clean"], true);
    assert_eq!(manifest["result"]["violations"], 0);
    assert_eq!(manifest["result"]["unrouted_nets"], 0);
    (manifest_path, checks_path, quality_path)
}

fn write_manufacturing_package(path: &Path, board: &Path) {
    write_manufacturing_package_with_profile(path, board, None);
}

fn write_manufacturing_package_with_profile(
    path: &Path,
    board: &Path,
    physical_profile: Option<&Value>,
) {
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
    let mut manifest = json!({
        "schema_version": if physical_profile.is_some() { 2 } else { 1 },
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
    if let Some(binding) = physical_profile {
        manifest["physical_profile"] = binding.clone();
    }
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

fn factory_receipt_value(package: &[u8]) -> Value {
    let response = json!({
        "status": "accepted",
        "accepted": true,
        "dfm_passed": true,
        "quote": {"currency": "USD", "total": 1.0},
        "findings": []
    });
    let response_bytes = serde_json::to_vec(&response).unwrap();
    let package_sha256 = sha256(package);
    json!({
        "schema_version": 1,
        "adapter": "generic-factory-http-v1",
        "provider": "generic",
        "endpoint": "https://factory.example/quote",
        "package_sha256": package_sha256,
        "package_bytes": package.len(),
        "request_sha256": sha256(package),
        "response_sha256": sha256(&response_bytes),
        "response_bytes": response_bytes.len(),
        "http_status": 200,
        "status": "accepted",
        "accepted": true,
        "dfm_passed": true,
        "quote": {"currency": "USD", "total": 1.0},
        "findings": [],
        "response": response
    })
}

fn write_factory_receipt(path: &Path, package: &Path) {
    write_json(path, &factory_receipt_value(&fs::read(package).unwrap()));
}

fn write_firmware_manifest(directory: &Path, schematic_sha256: &str) -> PathBuf {
    let bundle = directory.join("firmware");
    fs::create_dir_all(&bundle).unwrap();
    let contents: [&[u8]; 7] = [
        b"#define STATUS_LED_PIN 1\n",
        b"void firmware_tick(void);\n",
        b"void firmware_tick(void) {}\n",
        b"int main(void) { firmware_tick(); return 0; }\n",
        b"extern \"C\" void firmware_tick(void) {}\n",
        b"int main() { firmware_tick(); return 0; }\n",
        b"print('firmware smoke check')\n",
    ];
    let artifacts = FIRMWARE_FILES
        .iter()
        .zip(contents)
        .map(|(name, bytes)| {
            fs::write(bundle.join(name), bytes).unwrap();
            json!({"path": name, "bytes": bytes.len(), "sha256": sha256(bytes)})
        })
        .collect::<Vec<_>>();
    let manifest = json!({
        "schema_version": 2,
        "engine": "pcbex",
        "engine_version": env!("CARGO_PKG_VERSION"),
        "schematic_sha256": schematic_sha256,
        "artifacts": artifacts,
        "c_build": {
            "attempted": true,
            "passed": true,
            "command": ["cc", "firmware.c", "firmware_smoke_test.c"],
            "exit_code": 0,
            "smoke": {
                "attempted": true,
                "passed": true,
                "command": ["firmware-c-smoke"],
                "exit_code": 0
            }
        },
        "cpp_build": {
            "attempted": true,
            "passed": true,
            "command": ["c++", "firmware.cpp", "firmware_cpp_smoke_test.cpp"],
            "exit_code": 0,
            "smoke": {
                "attempted": true,
                "passed": true,
                "command": ["firmware-cpp-smoke"],
                "exit_code": 0
            }
        },
        "python_check": {
            "attempted": true,
            "passed": true,
            "command": ["python3", "-m", "py_compile", "host.py"],
            "exit_code": 0,
            "smoke": {
                "attempted": true,
                "passed": true,
                "command": ["python3", "host.py"],
                "exit_code": 0
            }
        }
    });
    let path = bundle.join("manifest.json");
    write_json(&path, &manifest);
    path
}

fn passing_inputs(directory: &Path) -> (PipelineInputs, String, String) {
    let schematic = fixture("approved-mcu.kicad_sch");
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
            analysis_physical_profile: None,
            manufacturing_package,
            firmware_manifest,
            factory_receipt: None,
            require_factory: false,
        },
        schematic_sha256,
        board_sha256,
    )
}

fn passing_runner_plan(directory: &Path) -> PathBuf {
    let circuit_spec = directory.join("circuit-spec-v2.json");
    let schematic = directory.join("design.kicad_sch");
    let board = directory.join("design.routed.kicad_pcb");
    fs::write(&circuit_spec, RUNNER_CIRCUIT_SPEC).unwrap();
    fs::write(&schematic, runner_schematic()).unwrap();
    fs::write(&board, RUNNER_BOARD).unwrap();

    let (electrical_policy, electrical_review, schematic_sha256) =
        make_approved_electrical_review(directory, &schematic);
    let analysis_directory = directory.join("runner-analysis");
    let (analysis_manifest, analysis_checks, quality) =
        make_runner_clean_analysis(&analysis_directory, &board);
    let manufacturing_package = directory.join("runner-manufacturing.zip");
    write_manufacturing_package(&manufacturing_package, &board);
    let firmware_manifest = write_firmware_manifest(directory, &schematic_sha256);

    let plan = json!({
        "schema_version": 1,
        "circuit_spec": plan_descriptor(directory, &circuit_spec),
        "schematic": plan_descriptor(directory, &schematic),
        "electrical_policy": plan_descriptor(directory, &electrical_policy),
        "electrical_review": plan_descriptor(directory, &electrical_review),
        "board": plan_descriptor(directory, &board),
        "analysis_manifest": plan_descriptor(directory, &analysis_manifest),
        "analysis_checks": plan_descriptor(directory, &analysis_checks),
        "quality": plan_descriptor(directory, &quality),
        "analysis_project": null,
        "analysis_rules": null,
        "analysis_dfm_profile": null,
        "analysis_policy_pack": null,
        "analysis_physical_profile": null,
        "manufacturing_package": plan_descriptor(directory, &manufacturing_package),
        "firmware_manifest": plan_descriptor(directory, &firmware_manifest),
        "factory_receipt": null,
        "require_factory": false,
    });
    let path = directory.join("deterministic-pipeline-plan.json");
    write_json(&path, &plan);
    path
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
        analysis_physical_profile: None,
        manufacturing_package: directory.join("missing-manufacturing.zip"),
        firmware_manifest: directory.join("missing-firmware.json"),
        factory_receipt: None,
        require_factory: false,
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
        analysis_physical_profile: None,
        manufacturing_package: path.to_path_buf(),
        firmware_manifest: path.to_path_buf(),
        factory_receipt: None,
        require_factory: false,
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

fn assert_firmware_rejected(
    inputs: &PipelineInputs,
    manifest_path: &Path,
    manifest: Value,
    report_path: &Path,
) -> Value {
    write_json(manifest_path, &manifest);
    let output = inputs.command(report_path).output().unwrap();
    assert!(!output.status.success());
    assert!(
        report_path.is_file(),
        "failed firmware validation must retain a report"
    );
    let report = read_json(report_path);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["pipeline"], "pcbex-hardware-v1");
    assert_eq!(phase(&report, "firmware-build")["passed"], false);
    assert!(
        !phase(&report, "firmware-build")["failures"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    report
}

fn assert_firmware_manifest_contract(path: &Path, schematic_sha256: &str) {
    let manifest = read_json(path);
    assert_eq!(
        keys(&manifest),
        BTreeSet::from([
            "artifacts",
            "c_build",
            "cpp_build",
            "engine",
            "engine_version",
            "python_check",
            "schema_version",
            "schematic_sha256",
        ])
    );
    assert_eq!(manifest["schema_version"], 2);
    assert_eq!(manifest["engine"], "pcbex");
    assert_eq!(manifest["engine_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["schematic_sha256"], schematic_sha256);
    let artifacts = manifest["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), FIRMWARE_FILES.len());
    assert_eq!(
        artifacts
            .iter()
            .map(|artifact| artifact["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        FIRMWARE_FILES
    );
    for artifact in artifacts {
        assert_eq!(keys(artifact), BTreeSet::from(["bytes", "path", "sha256"]));
        assert!(artifact["bytes"].as_u64().unwrap() > 0);
        assert_eq!(artifact["sha256"].as_str().unwrap().len(), 64);
    }
    for build_name in ["c_build", "cpp_build", "python_check"] {
        let build = &manifest[build_name];
        assert_eq!(
            keys(build),
            BTreeSet::from(["attempted", "command", "exit_code", "passed", "smoke"])
        );
        assert_eq!(build["attempted"], true);
        assert_eq!(build["passed"], true);
        assert_eq!(build["exit_code"], 0);
        assert!(!build["command"].as_array().unwrap().is_empty());
        let smoke = &build["smoke"];
        assert_eq!(
            keys(smoke),
            BTreeSet::from(["attempted", "command", "exit_code", "passed"])
        );
        assert_eq!(smoke["attempted"], true);
        assert_eq!(smoke["passed"], true);
        assert_eq!(smoke["exit_code"], 0);
        assert!(!smoke["command"].as_array().unwrap().is_empty());
    }
}

fn assert_factory_rejected(
    inputs: &PipelineInputs,
    receipt_path: &Path,
    report_path: &Path,
    receipt: Value,
) -> Value {
    write_json(receipt_path, &receipt);
    let output = inputs.command(report_path).output().unwrap();
    assert!(!output.status.success());
    assert!(report_path.is_file());
    let report = read_json(report_path);
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["pipeline"], "pcbex-hardware-v2");
    assert_eq!(phase(&report, "factory-dfm")["passed"], false);
    assert!(
        !phase(&report, "factory-dfm")["failures"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    report
}

fn replace_factory_response(receipt: &mut Value, response: Value) {
    let response_bytes = serde_json::to_vec(&response).unwrap();
    receipt["response_sha256"] = Value::String(sha256(&response_bytes));
    receipt["response_bytes"] = Value::Number((response_bytes.len() as u64).into());
    receipt["response"] = response;
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
    assert_firmware_manifest_contract(&inputs.firmware_manifest, &schematic_sha256);
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
fn pipeline_verify_binds_one_physical_profile_through_analysis_and_manufacturing() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut inputs, _, _) = passing_inputs(temporary.path());
    let imported_board = read_json(&temporary.path().join("analysis/board.json"));
    let profile_path = temporary.path().join("physical-profile.json");
    write_json(
        &profile_path,
        &json!({
            "schema_version": 1,
            "id": "pipeline-fixture-v1",
            "revision": 1,
            "description": "pipeline physical profile fixture",
            "board_width_nm": imported_board["width_nm"],
            "board_height_nm": imported_board["height_nm"],
            "outline": [],
            "fixed_components": [],
            "keepouts": [],
            "manufacturing_rules": null
        }),
    );
    let analysis = temporary.path().join("analysis-physical");
    let output = Command::new(binary())
        .arg("analyze-kicad")
        .arg(&inputs.board)
        .arg("--physical-profile")
        .arg(&profile_path)
        .arg("--output-dir")
        .arg(&analysis)
        .arg("--fail-on-violations")
        .output()
        .unwrap();
    assert_success(&output, "profile-aware analyze-kicad");
    inputs.analysis_manifest = analysis.join("run.json");
    inputs.analysis_checks = analysis.join("checks.json");
    inputs.quality = analysis.join("quality.json");
    inputs.analysis_physical_profile = Some(profile_path.clone());
    let run = read_json(&inputs.analysis_manifest);
    assert_eq!(run["schema_version"], 2);
    let binding = run["physical_profile"].clone();
    write_manufacturing_package_with_profile(
        &inputs.manufacturing_package,
        &inputs.board,
        Some(&binding),
    );

    let report_path = temporary.path().join("pipeline-physical.json");
    let output = inputs.command(&report_path).output().unwrap();
    assert_success(&output, "profile-bound pipeline-verify");
    let report = read_json(&report_path);
    assert_eq!(report["passed"], true);
    assert_eq!(
        report["identities"]["physical_profile_sha256"],
        binding["canonical_sha256"]
    );
    assert_eq!(phase(&report, "analysis-drc")["passed"], true);
    assert_eq!(phase(&report, "manufacturing-package")["passed"], true);

    let mut substituted = binding;
    substituted["canonical_sha256"] = Value::String("d".repeat(64));
    write_manufacturing_package_with_profile(
        &inputs.manufacturing_package,
        &inputs.board,
        Some(&substituted),
    );
    let rejection_path = temporary.path().join("pipeline-physical-substitution.json");
    let output = inputs.command(&rejection_path).output().unwrap();
    assert!(!output.status.success());
    let rejection = read_json(&rejection_path);
    assert_eq!(phase(&rejection, "analysis-drc")["passed"], true);
    assert_eq!(phase(&rejection, "manufacturing-package")["passed"], false);
    assert!(
        phase(&rejection, "manufacturing-package")["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure.as_str().unwrap().contains("does not match"))
    );
}

#[test]
fn pipeline_verify_accepts_a_valid_factory_receipt_with_a_six_phase_v2_report() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut inputs, schematic_sha256, board_sha256) = passing_inputs(temporary.path());
    assert_firmware_manifest_contract(&inputs.firmware_manifest, &schematic_sha256);
    let receipt_path = temporary.path().join("factory-receipt.json");
    write_factory_receipt(&receipt_path, &inputs.manufacturing_package);
    inputs.factory_receipt = Some(receipt_path.clone());
    let report_path = temporary.path().join("pipeline-v2-report.json");

    let output = inputs.command(&report_path).output().unwrap();
    assert_success(&output, "pipeline-verify with factory receipt");

    let report = read_json(&report_path);
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["pipeline"], "pcbex-hardware-v2");
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
            "factory-dfm",
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
    let factory = phase(&report, "factory-dfm");
    let evidence = factory["evidence"].as_array().unwrap();
    let receipt_evidence = evidence
        .iter()
        .find(|descriptor| descriptor["role"] == "factory-receipt")
        .unwrap();
    assert_eq!(
        receipt_evidence["bytes"],
        fs::metadata(&receipt_path).unwrap().len()
    );
    assert_eq!(receipt_evidence["sha256"], sha256_file(&receipt_path));
    assert_evidence_descriptors(&report);
}

#[test]
fn pipeline_verify_retains_a_v2_rejection_when_factory_is_required_but_missing() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut inputs, _, _) = passing_inputs(temporary.path());
    inputs.require_factory = true;
    let report_path = temporary.path().join("factory-required-missing.json");
    let output = inputs.command(&report_path).output().unwrap();
    assert!(!output.status.success());
    assert!(report_path.is_file());

    let report = read_json(&report_path);
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["pipeline"], "pcbex-hardware-v2");
    assert_eq!(report["passed"], false);
    assert_eq!(report["phases"].as_array().unwrap().len(), 6);
    assert_eq!(phase(&report, "factory-dfm")["passed"], false);
    assert!(
        !phase(&report, "factory-dfm")["failures"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(fs::read(&report_path).unwrap().ends_with(b"\n"));
}

#[test]
fn pipeline_verify_rejects_factory_receipts_with_package_or_request_identity_mismatches() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut inputs, _, _) = passing_inputs(temporary.path());
    let receipt_path = temporary.path().join("factory-receipt.json");
    inputs.factory_receipt = Some(receipt_path.clone());
    let package = fs::read(&inputs.manufacturing_package).unwrap();
    let valid = factory_receipt_value(&package);

    for (label, field) in [
        ("package-digest", "package_sha256"),
        ("request-digest", "request_sha256"),
    ] {
        let mut receipt = valid.clone();
        receipt[field] = Value::String("0".repeat(64));
        let report_path = temporary.path().join(format!("{label}.json"));
        let report = assert_factory_rejected(&inputs, &receipt_path, &report_path, receipt);
        assert_eq!(phase(&report, "factory-dfm")["passed"], false);
    }

    let mut receipt = valid;
    receipt["package_bytes"] = json!(package.len() + 1);
    let report_path = temporary.path().join("package-size.json");
    let report = assert_factory_rejected(&inputs, &receipt_path, &report_path, receipt);
    assert_eq!(phase(&report, "factory-dfm")["passed"], false);
}

#[test]
fn pipeline_verify_rejects_factory_receipts_with_failed_or_ambiguous_feedback() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut inputs, _, _) = passing_inputs(temporary.path());
    let receipt_path = temporary.path().join("factory-receipt.json");
    inputs.factory_receipt = Some(receipt_path.clone());
    let package = fs::read(&inputs.manufacturing_package).unwrap();
    let valid = factory_receipt_value(&package);

    let mut accepted_false = valid.clone();
    accepted_false["accepted"] = json!(false);
    let mut response = accepted_false["response"].clone();
    response["accepted"] = json!(false);
    replace_factory_response(&mut accepted_false, response);
    let report_path = temporary.path().join("accepted-false.json");
    assert_factory_rejected(&inputs, &receipt_path, &report_path, accepted_false);

    let mut dfm_false = valid.clone();
    dfm_false["dfm_passed"] = json!(false);
    let mut response = dfm_false["response"].clone();
    response["dfm_passed"] = json!(false);
    replace_factory_response(&mut dfm_false, response);
    let report_path = temporary.path().join("dfm-false.json");
    assert_factory_rejected(&inputs, &receipt_path, &report_path, dfm_false);

    let mut unknown_severity = valid.clone();
    let finding = json!({"code": "X-1", "severity": "mystery", "message": "unknown"});
    unknown_severity["findings"] = json!([finding.clone()]);
    let mut response = unknown_severity["response"].clone();
    response["findings"] = json!([finding]);
    replace_factory_response(&mut unknown_severity, response);
    let report_path = temporary.path().join("unknown-severity.json");
    assert_factory_rejected(&inputs, &receipt_path, &report_path, unknown_severity);

    let mut bad_http_status = valid.clone();
    bad_http_status["http_status"] = json!(500);
    let report_path = temporary.path().join("http-status.json");
    assert_factory_rejected(&inputs, &receipt_path, &report_path, bad_http_status);

    let mut bad_endpoint = valid.clone();
    bad_endpoint["endpoint"] = json!("http://factory.example/quote");
    let report_path = temporary.path().join("endpoint.json");
    assert_factory_rejected(&inputs, &receipt_path, &report_path, bad_endpoint);

    let mut unknown_field = valid;
    unknown_field["unexpected"] = json!(true);
    let report_path = temporary.path().join("unknown-field.json");
    assert_factory_rejected(&inputs, &receipt_path, &report_path, unknown_field);
}

#[test]
fn pipeline_verify_rejects_unsafe_factory_receipts_and_preserves_an_aliased_output() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut inputs, _, _) = passing_inputs(temporary.path());
    let receipt_path = temporary.path().join("factory-receipt.json");
    write_factory_receipt(&receipt_path, &inputs.manufacturing_package);
    inputs.factory_receipt = Some(receipt_path.clone());

    let original_receipt = fs::read(&receipt_path).unwrap();
    let alias_output = inputs.command(&receipt_path).output().unwrap();
    assert!(!alias_output.status.success());
    let alias_stderr = String::from_utf8_lossy(&alias_output.stderr);
    assert!(
        alias_stderr.contains("pipeline output must not alias an input")
            || alias_stderr.contains("refusing to overwrite existing output")
    );
    assert_eq!(fs::read(&receipt_path).unwrap(), original_receipt);

    let empty_receipt = temporary.path().join("empty-receipt.json");
    fs::write(&empty_receipt, []).unwrap();
    inputs.factory_receipt = Some(empty_receipt.clone());
    let empty_report = temporary.path().join("empty-receipt-report.json");
    let output = inputs.command(&empty_report).output().unwrap();
    assert!(!output.status.success());
    assert!(empty_report.is_file());

    let oversize_receipt = temporary.path().join("oversize-receipt.json");
    // The pipeline's receipt snapshot limit is 64 MiB; this is one byte beyond
    // that bound and is rejected before JSON parsing.
    fs::File::create(&oversize_receipt)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    inputs.factory_receipt = Some(oversize_receipt.clone());
    let oversize_report = temporary.path().join("oversize-receipt-report.json");
    let output = inputs.command(&oversize_report).output().unwrap();
    assert!(!output.status.success());
    assert!(oversize_report.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let valid_receipt = temporary.path().join("valid-receipt.json");
        write_factory_receipt(&valid_receipt, &inputs.manufacturing_package);
        let receipt_link = temporary.path().join("receipt-link.json");
        symlink(&valid_receipt, &receipt_link).unwrap();
        inputs.factory_receipt = Some(receipt_link);
        let report_path = temporary.path().join("receipt-link-report.json");
        let output = inputs.command(&report_path).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("symlink"));

        let real_parent = temporary.path().join("receipt-parent");
        let linked_parent = temporary.path().join("receipt-parent-link");
        fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();
        let parent_receipt = real_parent.join("factory-receipt.json");
        write_factory_receipt(&parent_receipt, &inputs.manufacturing_package);
        inputs.factory_receipt = Some(linked_parent.join("factory-receipt.json"));
        let report_path = temporary.path().join("receipt-parent-link-report.json");
        let output = inputs.command(&report_path).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("symlink"));
    }
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
    let firmware_directory = inputs.firmware_manifest.parent().unwrap();

    fs::write(
        firmware_directory.join("firmware.c"),
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
    fs::write(
        firmware_directory.join("firmware.cpp"),
        b"extern \"C\" void firmware_tick(void) { /* tampered */ }\n",
    )
    .unwrap();
    let cpp_report = temporary.path().join("firmware-cpp-tamper.json");
    let output = inputs.command(&cpp_report).output().unwrap();
    assert!(!output.status.success());
    let report = read_json(&cpp_report);
    assert_eq!(phase(&report, "firmware-build")["passed"], false);
    assert!(
        phase(&report, "firmware-build")["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure.as_str().unwrap().contains("firmware.cpp"))
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
fn pipeline_verify_rejects_cpp_artifact_descriptor_hash_or_byte_tampering() {
    let temporary = tempfile::tempdir().unwrap();
    let (inputs, _, _) = passing_inputs(temporary.path());
    let manifest_path = inputs.firmware_manifest.clone();
    let baseline = read_json(&manifest_path);

    for (label, field, value) in [
        ("sha256", "sha256", Value::String("0".repeat(64))),
        (
            "bytes",
            "bytes",
            json!(baseline["artifacts"][4]["bytes"].as_u64().unwrap() + 1),
        ),
    ] {
        let mut manifest = baseline.clone();
        manifest["artifacts"][4][field] = value;
        let report_path = temporary
            .path()
            .join(format!("cpp-descriptor-{label}.json"));
        let report = assert_firmware_rejected(&inputs, &manifest_path, manifest, &report_path);
        assert!(
            phase(&report, "firmware-build")["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|failure| failure.as_str().unwrap().contains("firmware.cpp"))
        );
    }
}

#[test]
fn pipeline_verify_rejects_missing_reordered_or_extra_firmware_artifacts() {
    let temporary = tempfile::tempdir().unwrap();
    let (inputs, _, _) = passing_inputs(temporary.path());
    let manifest_path = inputs.firmware_manifest.clone();
    let baseline = read_json(&manifest_path);

    let mut missing = baseline.clone();
    let mut artifacts = missing["artifacts"].as_array().unwrap().to_vec();
    artifacts.remove(4);
    missing["artifacts"] = Value::Array(artifacts);
    let missing_report = temporary.path().join("cpp-artifact-missing.json");
    assert_firmware_rejected(&inputs, &manifest_path, missing, &missing_report);

    let mut reordered = baseline.clone();
    reordered["artifacts"].as_array_mut().unwrap().swap(4, 5);
    let reordered_report = temporary.path().join("cpp-artifact-reordered.json");
    assert_firmware_rejected(&inputs, &manifest_path, reordered, &reordered_report);

    let mut extra = baseline;
    let extra_artifact = extra["artifacts"][4].clone();
    extra["artifacts"]
        .as_array_mut()
        .unwrap()
        .push(extra_artifact);
    let extra_report = temporary.path().join("cpp-artifact-extra.json");
    assert_firmware_rejected(&inputs, &manifest_path, extra, &extra_report);
}

#[test]
fn pipeline_verify_rejects_an_extra_adjacent_firmware_bundle_file() {
    let temporary = tempfile::tempdir().unwrap();
    let (inputs, _, _) = passing_inputs(temporary.path());
    let manifest_path = inputs.firmware_manifest.clone();
    let bundle = manifest_path.parent().unwrap();
    fs::write(bundle.join("unexpected.txt"), b"adjacent regular file\n").unwrap();

    let report_path = temporary.path().join("firmware-extra-adjacent.json");
    let report = assert_firmware_rejected(
        &inputs,
        &manifest_path,
        read_json(&manifest_path),
        &report_path,
    );
    assert!(
        phase(&report, "firmware-build")["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure.as_str().unwrap().contains("exact v2 artifact set"))
    );
    assert_eq!(
        fs::read(bundle.join("unexpected.txt")).unwrap(),
        b"adjacent regular file\n"
    );
}

#[test]
fn pipeline_verify_accepts_a_generated_firmware_bundle_end_to_end() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut inputs, schematic_sha256, board_sha256) = passing_inputs(temporary.path());
    let generated = temporary.path().join("generated-firmware");
    let generated_output = Command::new(binary())
        .arg("generate-firmware")
        .arg(&inputs.schematic)
        .arg("--mcu-reference")
        .arg("U1")
        .arg("--output-dir")
        .arg(&generated)
        .output()
        .unwrap();
    assert_success(&generated_output, "generate-firmware");
    let generated_manifest = generated.join("manifest.json");
    assert!(generated_manifest.is_file());
    assert_firmware_manifest_contract(&generated_manifest, &schematic_sha256);

    inputs.firmware_manifest = generated_manifest;
    let report_path = temporary.path().join("generated-firmware-pipeline.json");
    let output = inputs.command(&report_path).output().unwrap();
    assert_success(&output, "pipeline-verify with generated firmware bundle");
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
    assert_eq!(report["identities"]["schematic_sha256"], schematic_sha256);
    assert_eq!(report["identities"]["board_sha256"], board_sha256);
    assert_evidence_descriptors(&report);
}

#[test]
fn pipeline_verify_rejects_cpp_build_and_smoke_failures() {
    let temporary = tempfile::tempdir().unwrap();
    let (inputs, _, _) = passing_inputs(temporary.path());
    let manifest_path = inputs.firmware_manifest.clone();
    let baseline = read_json(&manifest_path);

    for (label, path, value) in [
        ("attempted", vec!["cpp_build", "attempted"], json!(false)),
        ("passed", vec!["cpp_build", "passed"], json!(false)),
        ("exit-code", vec!["cpp_build", "exit_code"], json!(1)),
        (
            "smoke-attempted",
            vec!["cpp_build", "smoke", "attempted"],
            json!(false),
        ),
        (
            "smoke-passed",
            vec!["cpp_build", "smoke", "passed"],
            json!(false),
        ),
        (
            "smoke-exit-code",
            vec!["cpp_build", "smoke", "exit_code"],
            json!(1),
        ),
    ] {
        let mut manifest = baseline.clone();
        let mut cursor = &mut manifest;
        for key in &path[..path.len() - 1] {
            cursor = &mut cursor[*key];
        }
        cursor[path[path.len() - 1]] = value;
        let report_path = temporary.path().join(format!("cpp-build-{label}.json"));
        assert_firmware_rejected(&inputs, &manifest_path, manifest, &report_path);
    }

    let sentinel = b"preserve existing report\n";
    let no_clobber_report = temporary.path().join("cpp-build-no-clobber.json");
    fs::write(&no_clobber_report, sentinel).unwrap();
    let mut failed = baseline;
    failed["cpp_build"]["passed"] = json!(false);
    write_json(&manifest_path, &failed);
    let output = inputs.command(&no_clobber_report).output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite existing output")
    );
    assert_eq!(fs::read(&no_clobber_report).unwrap(), sentinel);
}

#[test]
fn pipeline_verify_rejects_legacy_unknown_and_malformed_firmware_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let (inputs, _, _) = passing_inputs(temporary.path());
    let manifest_path = inputs.firmware_manifest.clone();
    let baseline = read_json(&manifest_path);

    let mut unknown = baseline.clone();
    unknown["cpp_build"]["smoke"]["unexpected"] = json!(true);
    let unknown_report = temporary.path().join("cpp-unknown-nested.json");
    assert_firmware_rejected(&inputs, &manifest_path, unknown, &unknown_report);

    let mut legacy = baseline.clone();
    legacy["schema_version"] = json!(1);
    let legacy_report = temporary.path().join("firmware-v1.json");
    let report = assert_firmware_rejected(&inputs, &manifest_path, legacy, &legacy_report);
    assert!(
        phase(&report, "firmware-build")["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure.as_str().unwrap().contains("schema_version"))
    );

    let mut malformed = baseline;
    malformed["engine_version"] = json!("not-semver");
    let malformed_report = temporary.path().join("cpp-engine-version.json");
    let report = assert_firmware_rejected(&inputs, &manifest_path, malformed, &malformed_report);
    assert!(
        phase(&report, "firmware-build")["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure.as_str().unwrap().contains("engine version"))
    );
}

#[test]
fn pipeline_verify_rejects_cpp_unsafe_paths_and_symlinks() {
    let temporary = tempfile::tempdir().unwrap();
    let (inputs, _, _) = passing_inputs(temporary.path());
    let manifest_path = inputs.firmware_manifest.clone();
    let baseline = read_json(&manifest_path);

    let mut unsafe_path = baseline.clone();
    unsafe_path["artifacts"][4]["path"] = json!("../firmware.cpp");
    let unsafe_report = temporary.path().join("cpp-unsafe-path.json");
    assert_firmware_rejected(&inputs, &manifest_path, unsafe_path, &unsafe_report);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let target = temporary.path().join("firmware-cpp-target");
        fs::write(&target, b"extern \"C\" void firmware_tick(void) {}\n").unwrap();
        let cpp_path = manifest_path.parent().unwrap().join("firmware.cpp");
        let _ = write_firmware_manifest(
            temporary.path(),
            baseline["schematic_sha256"].as_str().unwrap(),
        );
        fs::remove_file(&cpp_path).unwrap();
        symlink(&target, &cpp_path).unwrap();

        let valid_manifest = read_json(&manifest_path);
        let symlink_report = temporary.path().join("cpp-symlink.json");
        let report =
            assert_firmware_rejected(&inputs, &manifest_path, valid_manifest, &symlink_report);
        assert!(
            phase(&report, "firmware-build")["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|failure| failure.as_str().unwrap().contains("symlink"))
        );
        assert_eq!(
            fs::read(&target).unwrap(),
            b"extern \"C\" void firmware_tick(void) {}\n"
        );
    }
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
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(
        schema["properties"]["pipeline"]["const"],
        "pcbex-hardware-v1"
    );
    assert_eq!(schema["properties"]["phases"]["minItems"], 5);
    assert_eq!(schema["properties"]["phases"]["maxItems"], 5);
    assert_eq!(schema["properties"]["phases"]["items"], false);
    assert_eq!(
        schema["properties"]["phases"]["prefixItems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|phase| phase["properties"]["name"]["const"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "electrical-erc",
            "analysis-drc",
            "routing-quality",
            "manufacturing-package",
            "firmware-build",
        ]
    );
    assert_schema_objects_are_closed(&schema);

    let factory_schema_path = temporary.path().join("pipeline-factory.schema.json");
    let factory = Command::new(binary())
        .arg("pipeline-schema")
        .arg("--factory")
        .arg("--output")
        .arg(&factory_schema_path)
        .output()
        .unwrap();
    assert_success(&factory, "pipeline-schema --factory");
    let factory_schema = read_json(&factory_schema_path);
    assert_eq!(factory_schema["$schema"], schema["$schema"]);
    assert_eq!(factory_schema["additionalProperties"], false);
    assert_eq!(factory_schema["properties"]["schema_version"]["const"], 2);
    assert_eq!(
        factory_schema["properties"]["pipeline"]["const"],
        "pcbex-hardware-v2"
    );
    assert_eq!(factory_schema["properties"]["phases"]["minItems"], 6);
    assert_eq!(factory_schema["properties"]["phases"]["maxItems"], 6);
    assert_eq!(factory_schema["properties"]["phases"]["items"], false);
    assert_eq!(
        factory_schema["properties"]["phases"]["prefixItems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|phase| phase["properties"]["name"]["const"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "electrical-erc",
            "analysis-drc",
            "routing-quality",
            "manufacturing-package",
            "firmware-build",
            "factory-dfm",
        ]
    );
    assert_schema_objects_are_closed(&factory_schema);

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

#[test]
fn deterministic_pipeline_runner_approves_and_reproduces_the_complete_chain() {
    let temporary = tempfile::tempdir().unwrap();
    let plan = passing_runner_plan(temporary.path());
    let first_report = temporary.path().join("runner-report-1.json");
    let first = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&plan)
        .arg("--output")
        .arg(&first_report)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert_success(&first, "run-deterministic-pipeline");
    let report = read_json(&first_report);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["approved"], true);
    assert_eq!(report["failures"], json!([]));
    assert_eq!(report["binding"]["approved"], true);
    assert_eq!(report["pipeline"]["passed"], true);
    assert_eq!(report["run_sha256"].as_str().unwrap().len(), 64);
    assert!(
        report["input_evidence"]
            .as_array()
            .unwrap()
            .windows(2)
            .all(|pair| pair[0]["role"].as_str().unwrap() < pair[1]["role"].as_str().unwrap())
    );

    let second_report = temporary.path().join("runner-report-2.json");
    let second = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&plan)
        .arg("--output")
        .arg(&second_report)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert_success(&second, "repeated run-deterministic-pipeline");
    assert_eq!(
        fs::read(first_report).unwrap(),
        fs::read(second_report).unwrap()
    );
}

#[test]
fn ai_review_artifact_binding_revalidates_the_exact_pipeline_and_schematic() {
    let temporary = tempfile::tempdir().unwrap();
    let plan = passing_runner_plan(temporary.path());
    let schematic = temporary.path().join("design.kicad_sch");
    let policy = temporary.path().join("electrical-policy.json");
    let review = temporary.path().join("electrical-review.json");
    let report = temporary.path().join("deterministic-pipeline-report.json");

    let runner = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&plan)
        .arg("--output")
        .arg(&report)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert_success(&runner, "run-deterministic-pipeline for AI review binding");
    let report_value = read_json(&report);
    assert_eq!(report_value["approved"], true);

    // The structured review may parse identically after harmless whitespace,
    // but its raw artifact must still be the exact review named by the plan.
    let alternate_review = temporary.path().join("alternate-electrical-review.json");
    let mut alternate_review_bytes = fs::read(&review).unwrap();
    alternate_review_bytes.push(b'\n');
    fs::write(&alternate_review, alternate_review_bytes).unwrap();
    let mismatched_review_request = temporary.path().join("mismatched-review-request.json");
    let mismatched_review = Command::new(binary())
        .arg("prepare-ai-review")
        .arg(&schematic)
        .arg("--electrical-review")
        .arg(&alternate_review)
        .arg("--policy")
        .arg(&policy)
        .arg("--requirement")
        .arg("power=Power input treatment is intentional")
        .arg("--allow-no-simulation")
        .arg("--deterministic-pipeline-plan")
        .arg(&plan)
        .arg("--deterministic-pipeline-report")
        .arg(&report)
        .arg("--output")
        .arg(&mismatched_review_request)
        .output()
        .unwrap();
    assert!(!mismatched_review.status.success());
    assert!(
        String::from_utf8_lossy(&mismatched_review.stderr).contains("electrical-review identity")
    );
    assert!(!mismatched_review_request.exists());

    let request = temporary.path().join("bound-request.json");
    let prepared = Command::new(binary())
        .arg("prepare-ai-review")
        .arg(&schematic)
        .arg("--electrical-review")
        .arg(&review)
        .arg("--policy")
        .arg(&policy)
        .arg("--requirement")
        .arg("power=Power input treatment is intentional")
        .arg("--allow-no-simulation")
        .arg("--deterministic-pipeline-plan")
        .arg(&plan)
        .arg("--deterministic-pipeline-report")
        .arg(&report)
        .arg("--output")
        .arg(&request)
        .output()
        .unwrap();
    assert_success(&prepared, "prepare-ai-review with deterministic artifacts");

    let request_value = read_json(&request);
    assert_eq!(request_value["schema_version"], 2);
    assert_eq!(request_value["request_sha256"].as_str().unwrap().len(), 64);
    let binding = &request_value["artifact_binding"];
    assert_eq!(binding["schema_version"], 1);
    let schematic_bytes = fs::read(&schematic).unwrap();
    assert_eq!(
        binding["generated_schematic"]["bytes"],
        schematic_bytes.len()
    );
    assert_eq!(
        binding["generated_schematic"]["sha256"],
        sha256(&schematic_bytes)
    );
    let plan_bytes = fs::read(&plan).unwrap();
    let report_bytes = fs::read(&report).unwrap();
    let pipeline_binding = &binding["pipeline"];
    assert_eq!(pipeline_binding["plan_source"]["bytes"], plan_bytes.len());
    assert_eq!(
        pipeline_binding["plan_source"]["sha256"],
        sha256(&plan_bytes)
    );
    assert_eq!(pipeline_binding["plan_sha256"], report_value["plan_sha256"]);
    assert_eq!(pipeline_binding["report"]["bytes"], report_bytes.len());
    assert_eq!(pipeline_binding["report"]["sha256"], sha256(&report_bytes));
    assert_eq!(pipeline_binding["run_sha256"], report_value["run_sha256"]);

    let response = temporary.path().join("bound-response.json");
    write_json(
        &response,
        &json!({
            "schema_version": 1,
            "request_sha256": request_value["request_sha256"],
            "model": {"provider": "test-provider", "model": "schematic-reviewer", "version": "1"},
            "decision": "approve",
            "summary": "The deterministic review supports the supplied requirement.",
            "requirements": [{
                "id": "power",
                "status": "pass",
                "rationale": "The bound electrical review is approved.",
                "evidence_refs": ["electrical-review"]
            }],
            "risks": []
        }),
    );
    let private_key = temporary.path().join("approval.key");
    let public_key = temporary.path().join("approval.pub");
    let keygen = Command::new(binary())
        .arg("approval-keygen")
        .arg("--private-key")
        .arg(&private_key)
        .arg("--public-key")
        .arg(&public_key)
        .output()
        .unwrap();
    assert_success(&keygen, "approval-keygen for AI review binding");

    // The path itself is deliberately not signed: an identical copy at a
    // different path must still satisfy the byte/digest binding.
    let copied_schematic = temporary.path().join("copied-design.kicad_sch");
    fs::copy(&schematic, &copied_schematic).unwrap();
    let approval = temporary.path().join("bound-approval.json");
    let signed = Command::new(binary())
        .arg("sign-ai-review")
        .arg(&request)
        .arg(&response)
        .arg("--generated-schematic")
        .arg(&copied_schematic)
        .arg("--deterministic-pipeline-plan")
        .arg(&plan)
        .arg("--deterministic-pipeline-report")
        .arg(&report)
        .arg("--private-key")
        .arg(&private_key)
        .arg("--signer-id")
        .arg("binding-test")
        .arg("--output")
        .arg(&approval)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert_success(&signed, "sign-ai-review with copied generated schematic");

    let verified = Command::new(binary())
        .arg("verify-ai-approval")
        .arg(&approval)
        .arg(&request)
        .arg(&response)
        .arg("--generated-schematic")
        .arg(&copied_schematic)
        .arg("--deterministic-pipeline-plan")
        .arg(&plan)
        .arg("--deterministic-pipeline-report")
        .arg(&report)
        .arg("--public-key")
        .arg(&public_key)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert_success(
        &verified,
        "verify-ai-approval with copied generated schematic",
    );

    let missing_live_artifacts = Command::new(binary())
        .arg("verify-ai-approval")
        .arg(&approval)
        .arg(&request)
        .arg(&response)
        .arg("--public-key")
        .arg(&public_key)
        .output()
        .unwrap();
    assert!(!missing_live_artifacts.status.success());
    assert!(
        String::from_utf8_lossy(&missing_live_artifacts.stderr)
            .contains("schema version 2 requires --generated-schematic")
    );

    // A one-byte change to the generated schematic is rejected before any
    // signature can be accepted.
    let original_schematic = fs::read(&copied_schematic).unwrap();
    let mut mutated_schematic = original_schematic.clone();
    let last = mutated_schematic.len() - 1;
    mutated_schematic[last] ^= 1;
    fs::write(&copied_schematic, &mutated_schematic).unwrap();
    let rejected_schematic = Command::new(binary())
        .arg("verify-ai-approval")
        .arg(&approval)
        .arg(&request)
        .arg(&response)
        .arg("--generated-schematic")
        .arg(&copied_schematic)
        .arg("--deterministic-pipeline-plan")
        .arg(&plan)
        .arg("--deterministic-pipeline-report")
        .arg(&report)
        .arg("--public-key")
        .arg(&public_key)
        .output()
        .unwrap();
    assert!(!rejected_schematic.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_schematic.stderr)
            .contains("generated schematic identity")
    );
    fs::write(&copied_schematic, &original_schematic).unwrap();

    // Retaining a report with one changed byte cannot bypass the fresh-run
    // comparison, even though the signed request and approval are intact.
    let original_report = fs::read(&report).unwrap();
    let mut mutated_report = original_report.clone();
    mutated_report[0] = if mutated_report[0] == b'{' {
        b'['
    } else {
        b'{'
    };
    fs::write(&report, &mutated_report).unwrap();
    let rejected_report = Command::new(binary())
        .arg("verify-ai-approval")
        .arg(&approval)
        .arg(&request)
        .arg(&response)
        .arg("--generated-schematic")
        .arg(&copied_schematic)
        .arg("--deterministic-pipeline-plan")
        .arg(&plan)
        .arg("--deterministic-pipeline-report")
        .arg(&report)
        .arg("--public-key")
        .arg(&public_key)
        .output()
        .unwrap();
    assert!(!rejected_report.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_report.stderr)
            .contains("retained deterministic pipeline report")
    );
    fs::write(&report, &original_report).unwrap();

    // Clap must reject an incomplete artifact tuple before trying to read any
    // of the approval files.
    let partial = Command::new(binary())
        .arg("verify-ai-approval")
        .arg(&approval)
        .arg(&request)
        .arg(&response)
        .arg("--generated-schematic")
        .arg(&copied_schematic)
        .arg("--public-key")
        .arg(&public_key)
        .output()
        .unwrap();
    assert!(!partial.status.success());
    assert!(String::from_utf8_lossy(&partial.stderr).contains("deterministic-pipeline-plan"));

    // A separately valid plan/report pair with a different source-byte
    // identity must not be mixed into this request's signed binding.
    let alternate_plan = temporary.path().join("alternate-plan.json");
    let mut alternate_plan_bytes = fs::read(&plan).unwrap();
    alternate_plan_bytes.push(b'\n');
    fs::write(&alternate_plan, &alternate_plan_bytes).unwrap();
    let alternate_report = temporary.path().join("alternate-report.json");
    let alternate_runner = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&alternate_plan)
        .arg("--output")
        .arg(&alternate_report)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert_success(
        &alternate_runner,
        "independently valid alternate deterministic pipeline run",
    );
    let mixed = Command::new(binary())
        .arg("verify-ai-approval")
        .arg(&approval)
        .arg(&request)
        .arg(&response)
        .arg("--generated-schematic")
        .arg(&copied_schematic)
        .arg("--deterministic-pipeline-plan")
        .arg(&alternate_plan)
        .arg("--deterministic-pipeline-report")
        .arg(&alternate_report)
        .arg("--public-key")
        .arg(&public_key)
        .output()
        .unwrap();
    assert!(!mixed.status.success());
    assert!(
        String::from_utf8_lossy(&mixed.stderr)
            .contains("do not match the AI review request binding")
    );
}

#[test]
fn deterministic_pipeline_runner_retains_digest_rejection_and_preflights_output() {
    let temporary = tempfile::tempdir().unwrap();
    let plan = passing_runner_plan(temporary.path());
    let mut value = read_json(&plan);
    value["board"]["sha256"] = Value::String("0".repeat(64));
    write_json(&plan, &value);

    let report_path = temporary.path().join("rejected-runner-report.json");
    let rejected = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&plan)
        .arg("--output")
        .arg(&report_path)
        .arg("--require-approved")
        .arg("--mcp-echo-report-summary")
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let report = read_json(&report_path);
    let summary = serde_json::from_slice::<Value>(&rejected.stdout).unwrap();
    let retained = fs::read(&report_path).unwrap();
    assert_eq!(summary["schema_version"], report["schema_version"]);
    assert_eq!(summary["approved"], report["approved"]);
    assert_eq!(summary["plan_sha256"], report["plan_sha256"]);
    assert_eq!(summary["run_sha256"], report["run_sha256"]);
    assert_eq!(
        summary["failure_count"],
        report["failures"].as_array().unwrap().len()
    );
    assert_eq!(summary["report_bytes"], retained.len());
    assert_eq!(summary["report_sha256"], sha256(&retained));
    assert_eq!(report["approved"], false);
    assert!(!report["failures"].as_array().unwrap().is_empty());
    assert_eq!(report["binding"], Value::Null);
    assert_eq!(report["pipeline"], Value::Null);

    let occupied = temporary.path().join("occupied-runner-report.json");
    let sentinel = b"preserve runner output\n";
    fs::write(&occupied, sentinel).unwrap();
    fs::write(&plan, b"not valid JSON").unwrap();
    let preflight = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&plan)
        .arg("--output")
        .arg(&occupied)
        .output()
        .unwrap();
    assert!(!preflight.status.success());
    assert!(
        String::from_utf8_lossy(&preflight.stderr)
            .contains("refusing to overwrite existing output")
    );
    assert_eq!(fs::read(occupied).unwrap(), sentinel);
}

#[test]
fn deterministic_pipeline_runner_rejects_non_exact_firmware_and_symlink_inputs() {
    let temporary = tempfile::tempdir().unwrap();
    let plan = passing_runner_plan(temporary.path());
    fs::write(
        temporary.path().join("firmware/unexpected.txt"),
        b"not authorized by the firmware bundle contract",
    )
    .unwrap();
    let report_path = temporary.path().join("extra-firmware-report.json");
    let extra = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&plan)
        .arg("--output")
        .arg(&report_path)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert!(!extra.status.success());
    let report = read_json(&report_path);
    assert_eq!(report["approved"], false);
    assert_eq!(report["binding"]["approved"], true);
    assert_eq!(report["pipeline"], Value::Null);
    assert!(
        report["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure.as_str().unwrap().contains("firmware bundle"))
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let linked_temporary = tempfile::tempdir().unwrap();
        let linked_plan = passing_runner_plan(linked_temporary.path());
        let mut value = read_json(&linked_plan);
        let board_relative = value["board"]["path"].as_str().unwrap();
        let board = linked_temporary.path().join(board_relative);
        let link = linked_temporary.path().join("board-link.kicad_pcb");
        symlink(&board, &link).unwrap();
        value["board"]["path"] = Value::String("board-link.kicad_pcb".into());
        write_json(&linked_plan, &value);
        let linked_report = linked_temporary.path().join("symlink-report.json");
        let linked = Command::new(binary())
            .arg("run-deterministic-pipeline")
            .arg(&linked_plan)
            .arg("--output")
            .arg(&linked_report)
            .arg("--require-approved")
            .output()
            .unwrap();
        assert!(!linked.status.success());
        let report = read_json(&linked_report);
        assert_eq!(report["approved"], false);
        assert_eq!(report["binding"], Value::Null);
        assert_eq!(report["pipeline"], Value::Null);
        assert!(
            report["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|failure| failure.as_str().unwrap().contains("symlink component"))
        );
    }
}

#[test]
fn deterministic_pipeline_runner_retains_each_independently_runnable_gate() {
    let pipeline_only = tempfile::tempdir().unwrap();
    let plan = passing_runner_plan(pipeline_only.path());
    let mut value = read_json(&plan);
    value["circuit_spec"]["sha256"] = Value::String("0".repeat(64));
    write_json(&plan, &value);
    let report_path = pipeline_only.path().join("pipeline-only-report.json");
    let output = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&plan)
        .arg("--output")
        .arg(&report_path)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report = read_json(&report_path);
    assert_eq!(report["approved"], false);
    assert_eq!(report["binding"], Value::Null);
    assert_eq!(report["pipeline"]["passed"], true);
    assert!(
        report["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| {
                failure
                    .as_str()
                    .unwrap()
                    .contains("circuit_spec: input SHA-256")
            })
    );

    let binding_only = tempfile::tempdir().unwrap();
    let plan = passing_runner_plan(binding_only.path());
    let mut value = read_json(&plan);
    value["analysis_checks"]["sha256"] = Value::String("0".repeat(64));
    write_json(&plan, &value);
    let report_path = binding_only.path().join("binding-only-report.json");
    let output = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&plan)
        .arg("--output")
        .arg(&report_path)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report = read_json(&report_path);
    assert_eq!(report["approved"], false);
    assert_eq!(report["binding"]["approved"], true);
    assert_eq!(report["pipeline"], Value::Null);
    assert!(
        report["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| {
                failure
                    .as_str()
                    .unwrap()
                    .contains("analysis_checks: input SHA-256")
            })
    );
}

#[test]
fn deterministic_pipeline_runner_keeps_output_outside_the_exact_firmware_bundle() {
    let temporary = tempfile::tempdir().unwrap();
    let plan = passing_runner_plan(temporary.path());
    let firmware = temporary.path().join("firmware");
    let report_path = firmware.join("report.json");
    let output = Command::new(binary())
        .arg("run-deterministic-pipeline")
        .arg(&plan)
        .arg("--output")
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("must be outside the exact firmware bundle directory")
    );
    assert!(!report_path.exists());
    let mut names = fs::read_dir(&firmware)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    let mut expected = FIRMWARE_FILES
        .iter()
        .map(ToString::to_string)
        .chain(std::iter::once("manifest.json".to_string()))
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(names, expected);
}

#[test]
fn deterministic_pipeline_runner_mcp_retains_rejected_sync_and_task_reports() {
    let temporary = tempfile::tempdir().unwrap();
    let plan = passing_runner_plan(temporary.path());
    let mut plan_value = read_json(&plan);
    plan_value["board"]["sha256"] = Value::String("0".repeat(64));
    write_json(&plan, &plan_value);

    let mut child = Command::new(binary())
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    initialize_mcp(&mut stdin, &mut stdout);

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "method": "tools/list"
        }),
    );
    let tools = receive_mcp(&mut stdout);
    let tool = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "run_deterministic_pipeline")
        .expect("deterministic pipeline MCP tool");
    assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    assert_eq!(tool["inputSchema"]["required"], json!(["plan", "output"]));
    assert_eq!(
        tool["inputSchema"]["properties"]["require_approved"]["default"],
        false
    );
    assert_eq!(tool["execution"]["taskSupport"], "optional");

    let sync_output = temporary.path().join("mcp-sync-report.json");
    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "sync",
            "method": "tools/call",
            "params": {
                "name": "run_deterministic_pipeline",
                "arguments": {
                    "plan": plan,
                    "output": sync_output,
                    "require_approved": true
                }
            }
        }),
    );
    let sync = receive_mcp(&mut stdout);
    assert_eq!(sync["result"]["isError"], true);
    let sync_report = read_json(&sync_output);
    let sync_summary = &sync["result"]["structuredContent"]["report_summary"];
    assert_eq!(sync_summary["approved"], false);
    assert_eq!(sync_summary["plan_sha256"], sync_report["plan_sha256"]);
    assert_eq!(sync_summary["run_sha256"], sync_report["run_sha256"]);
    assert_eq!(
        sync_summary["report_bytes"],
        fs::metadata(&sync_output).unwrap().len()
    );
    assert_eq!(sync_summary["report_sha256"], sha256_file(&sync_output));

    let task_output = temporary.path().join("mcp-task-report.json");
    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "create-task",
            "method": "tools/call",
            "params": {
                "name": "run_deterministic_pipeline",
                "arguments": {
                    "plan": plan,
                    "output": task_output,
                    "require_approved": true
                },
                "task": {"ttl": 60_000}
            }
        }),
    );
    let created = receive_mcp(&mut stdout);
    assert_eq!(created["result"]["task"]["status"], "working");
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();
    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "task-result",
            "method": "tasks/result",
            "params": {"taskId": task_id}
        }),
    );
    let task = receive_mcp(&mut stdout);
    assert_eq!(task["result"]["isError"], true);
    let task_report = read_json(&task_output);
    let task_summary = &task["result"]["structuredContent"]["report_summary"];
    assert_eq!(task_summary["approved"], false);
    assert_eq!(task_summary["plan_sha256"], task_report["plan_sha256"]);
    assert_eq!(task_summary["run_sha256"], task_report["run_sha256"]);
    assert_eq!(
        task_summary["report_bytes"],
        fs::metadata(&task_output).unwrap().len()
    );
    assert_eq!(task_summary["report_sha256"], sha256_file(&task_output));
    assert_eq!(
        task["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        task_id
    );

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
}

#[test]
fn deterministic_pipeline_schemas_are_closed_and_no_clobber() {
    let temporary = tempfile::tempdir().unwrap();
    for (command, name) in [
        ("deterministic-pipeline-plan-schema", "plan.schema.json"),
        ("deterministic-pipeline-report-schema", "report.schema.json"),
    ] {
        let path = temporary.path().join(name);
        let output = Command::new(binary())
            .arg(command)
            .arg("--output")
            .arg(&path)
            .output()
            .unwrap();
        assert_success(&output, command);
        let schema = read_json(&path);
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["additionalProperties"], false);
        assert_schema_objects_are_closed(&schema);

        let collision = Command::new(binary())
            .arg(command)
            .arg("--output")
            .arg(&path)
            .output()
            .unwrap();
        assert!(!collision.status.success());
    }
}

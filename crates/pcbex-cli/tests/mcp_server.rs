use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn send(stdin: &mut ChildStdin, message: Value) {
    serde_json::to_writer(&mut *stdin, &message).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

fn receive(stdout: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(!line.is_empty(), "MCP server closed stdout unexpectedly");
    serde_json::from_str(&line).unwrap()
}

fn initialize(stdin: &mut ChildStdin, stdout: &mut BufReader<ChildStdout>, id: Value) -> Value {
    send(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "integration-test", "version": "1"}
            }
        }),
    );
    send(
        stdin,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    receive(stdout)
}

fn temporary_directory(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pcbex-{name}-{}-{unique}", std::process::id()))
}

const DETERMINISTIC_FIRMWARE_ARTIFACTS: [&str; 7] = [
    "pinout.h",
    "firmware.h",
    "firmware.c",
    "firmware_smoke_test.c",
    "firmware.cpp",
    "firmware_cpp_smoke_test.cpp",
    "host.py",
];

fn skipped_firmware_build(command: &str) -> Value {
    json!({
        "attempted": false,
        "passed": false,
        "command": [command],
        "exit_code": null,
        "smoke": {
            "attempted": false,
            "passed": false,
            "command": ["smoke"],
            "exit_code": null
        }
    })
}

/// Build the same closed fixture used by the successful deterministic intent
/// MCP test.  Invalid-bundle tests mutate only the firmware manifest after
/// this helper returns, keeping all non-firmware inputs identical.
fn write_deterministic_pipeline_fixture(output: &Path) -> PathBuf {
    fs::create_dir_all(output.join("intent")).unwrap();
    for (relative, bytes) in [
        ("circuit.json", b"circuit".as_slice()),
        ("design.kicad_sch", b"schematic".as_slice()),
        ("review.json", b"review".as_slice()),
        ("design.kicad_pcb", b"board".as_slice()),
        ("analysis/run.json", b"manifest".as_slice()),
        ("analysis/checks.json", b"checks".as_slice()),
        ("analysis/quality.json", b"quality".as_slice()),
        ("manufacturing.zip", b"package".as_slice()),
    ] {
        let path = output.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    let firmware = output.join("firmware");
    fs::create_dir_all(&firmware).unwrap();
    let artifacts = DETERMINISTIC_FIRMWARE_ARTIFACTS
        .iter()
        .map(|name| {
            let bytes = name.as_bytes();
            fs::write(firmware.join(name), bytes).unwrap();
            json!({
                "path": name,
                "bytes": bytes.len(),
                "sha256": hex::encode(Sha256::digest(bytes))
            })
        })
        .collect::<Vec<_>>();
    fs::write(
        firmware.join("manifest.json"),
        serde_json::to_vec(&json!({
            "schema_version": 2,
            "engine": "pcbex",
            "engine_version": env!("CARGO_PKG_VERSION"),
            "schematic_sha256": "a".repeat(64),
            "artifacts": artifacts,
            "c_build": skipped_firmware_build("cc"),
            "cpp_build": skipped_firmware_build("c++"),
            "python_check": skipped_firmware_build("python3")
        }))
        .unwrap(),
    )
    .unwrap();

    let intent = output.join("intent/pipeline-intent.json");
    fs::write(
        &intent,
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "circuit_spec": "circuit.json",
            "schematic": "design.kicad_sch",
            "electrical_policy": null,
            "electrical_review": "review.json",
            "board": "design.kicad_pcb",
            "analysis_manifest": "analysis/run.json",
            "analysis_checks": "analysis/checks.json",
            "quality": "analysis/quality.json",
            "analysis_project": null,
            "analysis_rules": null,
            "analysis_dfm_profile": null,
            "analysis_policy_pack": null,
            "analysis_physical_profile": null,
            "manufacturing_package": "manufacturing.zip",
            "firmware_manifest": "firmware/manifest.json",
            "factory_receipt": null,
            "require_factory": false
        }))
        .unwrap(),
    )
    .unwrap();
    intent
}

fn mutate_firmware_manifest(root: &Path, mutate: impl FnOnce(&mut Value)) {
    let path = root.join("firmware/manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    mutate(&mut manifest);
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

fn assert_compile_bundle_rejected(response: &Value, output: &Path, context: &str) {
    assert_eq!(response["result"]["isError"], true, "{context}: {response}");
    let structured = &response["result"]["structuredContent"];
    assert_eq!(structured["ok"], false, "{context}: {response}");
    assert!(structured["plan"].is_null(), "{context}: {response}");
    let message = structured["message"].as_str().unwrap_or_default();
    assert!(message.len() <= 4 * 1024, "{context}: unbounded message");
    assert!(
        response.to_string().len() < 16 * 1024 * 1024,
        "{context}: unbounded response"
    );
    assert!(
        !output.exists(),
        "{context}: rejected compile published output"
    );
}

#[cfg(unix)]
fn fake_native_kicad_drc_cli(directory: &Path, name: &str, with_finding: bool) -> PathBuf {
    const DRC_SCHEMA: &str = "https://schemas.kicad.org/drc.v1.json";
    let path = directory.join(name);
    let status = if with_finding { 5 } else { 0 };
    let violations = if with_finding {
        r#"[{"description":"bad","items":[{"description":"pad","pos":{"x":1.0,"y":2.0},"uuid":"00000000-0000-0000-0000-000000000001"}],"severity":"error","type":"clearance"}]"#
    } else {
        "[]"
    };
    let report = format!(
        r#"{{"$schema":"{DRC_SCHEMA}","coordinate_units":"mm","date":"now","included_severities":["error","warning"],"kicad_version":"10.0.5","schematic_parity":[],"source":"input.kicad_pcb","unconnected_items":[],"violations":{violations}}}"#
    );
    let script = format!(
        "#!/bin/sh\nout=''\ninput=''\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then out=$2; shift 2; else input=$1; shift; fi\ndone\nprintf '%s' '{report}' > \"$out\"\nexit {status}\n"
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[cfg(unix)]
fn fake_malformed_native_kicad_drc_cli(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(
        &path,
        "#!/bin/sh\nout=''\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then out=$2; shift 2; else shift; fi\ndone\nprintf '%s' 'not-json' > \"$out\"\nexit 0\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[cfg(unix)]
fn fake_native_kicad_erc_cli(directory: &Path, name: &str, with_error: bool) -> PathBuf {
    let path = directory.join(name);
    let status = if with_error { 5 } else { 0 };
    let violations = if with_error {
        r#"[{"description":"Pin not connected","items":[{"description":"Symbol U1 Pin 1","pos":{"x":1.0,"y":2.0},"uuid":"00000000-0000-0000-0000-000000000001"}],"severity":"error","type":"pin_not_connected"}]"#
    } else {
        "[]"
    };
    let report = format!(
        r#"{{"$schema":"https://schemas.kicad.org/erc.v1.json","coordinate_units":"mm","date":"now","ignored_checks":[{{"description":"ignored","key":"ignored"}}],"included_severities":["error"],"kicad_version":"10.0.5","sheets":[{{"path":"/","uuid_path":"/root","violations":{violations}}}],"source":"input.kicad_sch"}}"#
    );
    let script = format!(
        "#!/bin/sh\nout=''\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then out=$2; shift 2; else shift; fi\ndone\nprintf '%s' '{report}' > \"$out\"\nexit {status}\n"
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[cfg(unix)]
fn fake_native_kicad_erc_warning_cli(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    let report = r#"{"$schema":"https://schemas.kicad.org/erc.v1.json","coordinate_units":"mm","date":"now","ignored_checks":[{"description":"ignored","key":"ignored"}],"included_severities":["error","warning"],"kicad_version":"10.0.5","sheets":[{"path":"/","uuid_path":"/root","violations":[{"description":"Warning","items":[{"description":"Symbol U1 Pin 2","pos":{"x":3.0,"y":4.0},"uuid":"00000000-0000-0000-0000-000000000002"}],"severity":"warning","type":"warning_type"}]}],"source":"input.kicad_sch"}"#;
    let script = format!(
        "#!/bin/sh\nout=''\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then out=$2; shift 2; else shift; fi\ndone\nprintf '%s' '{report}' > \"$out\"\nexit 5\n"
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[cfg(unix)]
fn fake_sleeping_native_kicad_cli(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(
        &path,
        "#!/bin/sh\nsleep 600 &\nsleep_pid=$!\nprintf '%s %s\\n' \"$$\" \"$sleep_pid\" > \"$PCBEX_TEST_KICAD_PID_FILE\"\nwait \"$sleep_pid\"\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[cfg(unix)]
fn unix_process_group(pid: i32) -> Option<i32> {
    unsafe extern "C" {
        fn getpgid(pid: i32) -> i32;
    }
    if pid <= 0 {
        return None;
    }
    let group = unsafe { getpgid(pid) };
    (group > 0).then_some(group)
}

#[cfg(all(unix, target_os = "linux"))]
fn unix_process_exists(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let stat_path = format!("/proc/{pid}/stat");
    match fs::read_to_string(stat_path) {
        Ok(stat) => stat
            .rfind(") ")
            .and_then(|close| stat.as_bytes().get(close + 2).copied())
            .is_some_and(|state| state != b'Z'),
        Err(_) => false,
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn unix_process_exists(pid: i32) -> bool {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    pid > 0 && unsafe { kill(pid, 0) == 0 }
}

#[cfg(unix)]
fn kill_unix_process_group(pgid: i32) {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    if pgid > 0 {
        let _ = unsafe { kill(-pgid, SIGKILL) };
    }
}

#[cfg(unix)]
fn read_recorded_kicad_pids(pid_file: &Path) -> Vec<i32> {
    fs::read_to_string(pid_file)
        .ok()
        .map(|source| {
            source
                .split_whitespace()
                .filter_map(|value| value.parse::<i32>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[cfg(unix)]
struct KicadProcessCleanup {
    pid_file: PathBuf,
    pids: Vec<i32>,
    process_group: Option<i32>,
}

#[cfg(unix)]
impl KicadProcessCleanup {
    fn new(pid_file: &Path) -> Self {
        Self {
            pid_file: pid_file.to_path_buf(),
            pids: Vec::new(),
            process_group: None,
        }
    }

    fn validated_process_group(pids: &[i32]) -> Option<i32> {
        let (&shell, &sleep) = (pids.first()?, pids.get(1)?);
        let shell_group = unix_process_group(shell)?;
        let sleep_group = unix_process_group(sleep)?;
        (shell_group == shell && sleep_group == shell_group).then_some(shell_group)
    }

    fn wait_for_start(&mut self) -> Vec<i32> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let pids = read_recorded_kicad_pids(&self.pid_file);
            if pids.len() == 2 {
                self.pids = pids.clone();
                if let Some(process_group) = Self::validated_process_group(&pids) {
                    self.process_group = Some(process_group);
                    return pids;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.pids = read_recorded_kicad_pids(&self.pid_file);
        self.process_group = Self::validated_process_group(&self.pids);
        if self.process_group.is_some() {
            self.pids.clone()
        } else {
            Vec::new()
        }
    }

    fn wait_for_exit(&self) -> Vec<i32> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.pids.iter().any(|pid| unix_process_exists(*pid)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.pids
            .iter()
            .copied()
            .filter(|pid| unix_process_exists(*pid))
            .collect()
    }
}

#[cfg(unix)]
impl Drop for KicadProcessCleanup {
    fn drop(&mut self) {
        if self.pids.is_empty() {
            let deadline = Instant::now() + Duration::from_secs(1);
            while self.process_group.is_none() && Instant::now() < deadline {
                let pids = read_recorded_kicad_pids(&self.pid_file);
                if !pids.is_empty() {
                    self.pids = pids;
                    self.process_group = Self::validated_process_group(&self.pids);
                }
                if self.process_group.is_none() {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        let Some(process_group) = self.process_group else {
            return;
        };
        let descendant_is_running_in_group = self.pids.get(1).is_some_and(|pid| {
            unix_process_exists(*pid) && unix_process_group(*pid) == Some(process_group)
        });
        if descendant_is_running_in_group {
            kill_unix_process_group(process_group);
        }
    }
}

const HANDOFF_CIRCUIT_SPEC: &str = r#"{
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

fn handoff_schematic() -> String {
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
    source = source.replace(
        r##"    (property "Footprint" "Package:QFN"
      (at 12.54 20 0)
      (effects (font (size 1.27 1.27)) hide))"##,
        r##"    (property "Footprint" "Package:QFN"
      (at 12.54 20 0)
      (effects (font (size 1.27 1.27)) hide))
    (property "pcbex:requires_decoupling" "false")
    (property "pcbex:decoupling" "false")"##,
    );
    source = source.replace(
        r##"    (property "Footprint" "Resistor_SMD:R_0603"
      (at 40 20 0)
      (effects (font (size 1.27 1.27)) hide))"##,
        r##"    (property "Footprint" "Resistor_SMD:R_0603"
      (at 40 20 0)
      (effects (font (size 1.27 1.27)) hide))
    (property "pcbex:requires_decoupling" "false")
    (property "pcbex:decoupling" "false")"##,
    );
    source
}

fn board_binding_board() -> &'static str {
    r#"(kicad_pcb
  (version 20250114)
  (generator pcbex-test)
  (general (thickness 1.6))
  (paper "A4")
  (layers
    (0 "F.Cu" signal)
    (31 "B.Cu" signal)
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
    (at 20 10)
    (fp_text reference "R1" (at 0 0) (layer "F.Fab") hide)
    (fp_text value "10k" (at 0 1) (layer "F.Fab") hide)
    (pad "1" thru_hole circle (at 0 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 1 "SIGNAL"))
    (pad "2" thru_hole circle (at 2 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 2 "VCC")))
  (gr_rect (start 0 0) (end 40 20) (stroke (width 0.05) (type default)) (fill none) (layer "Edge.Cuts")))"#
}

#[test]
fn stdio_server_negotiates_and_returns_failed_gate_artifacts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("examples/simple.kicad_pcb");
    let output = temporary_directory("mcp-analysis");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "integration-test", "version": "1"}
            }
        }),
    );
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    let initialized = receive(&mut stdout);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        initialized["result"]["capabilities"]["tasks"],
        json!({
            "list": {},
            "cancel": {},
            "requests": {"tools": {"call": {}}}
        })
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "analysis",
            "method": "tools/call",
            "params": {
                "name": "analyze_kicad",
                "arguments": {
                    "input": input,
                    "output_dir": output,
                    "fab": "jlcpcb-2layer",
                    "fail_on_violations": true
                },
                "task": {"ttl": 60_000}
            }
        }),
    );
    let created = receive(&mut stdout);
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(created["result"]["task"]["status"], "working");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "status",
            "method": "tasks/get",
            "params": {"taskId": task_id}
        }),
    );
    let status = receive(&mut stdout);
    assert!(matches!(
        status["result"]["status"].as_str(),
        Some("working" | "failed")
    ));
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "result",
            "method": "tasks/result",
            "params": {"taskId": task_id}
        }),
    );
    let result = receive(&mut stdout);
    drop(stdin);
    let process_status = child.wait().unwrap();
    assert!(process_status.success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert_eq!(result["id"], "result");
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(
        result["result"]["structuredContent"]["manifest"]["configuration"]["dfm_profile"]["id"],
        "jlcpcb-standard-2layer-1oz-v1"
    );
    assert_eq!(
        result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        task_id
    );
    assert!(output.join("run.json").is_file());
    assert!(output.join("report.sarif").is_file());

    fs::remove_dir_all(output).unwrap();
}

#[test]
fn stdio_server_advertises_native_kicad_drc_contract_and_rejects_bad_arguments() {
    let output = temporary_directory("mcp-native-drc-contract");
    fs::create_dir_all(&output).unwrap();
    let stale = output.join("stale.json");
    fs::write(&stale, br#"{"old":true}"#).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(&mut stdin, &mut stdout, json!("native-drc-init"));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "method": "tools/list",
            "params": {}
        }),
    );
    let tools = receive(&mut stdout);
    let drc = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "run_native_kicad_drc")
        .expect("native DRC MCP tool is advertised");
    assert_eq!(drc["inputSchema"]["additionalProperties"], false);
    assert_eq!(drc["inputSchema"]["required"], json!(["input", "output"]));
    assert_eq!(
        drc["inputSchema"]["properties"]["project"]["type"],
        "string"
    );

    let verifier = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "verify_native_kicad_drc_report")
        .expect("native DRC replay MCP tool is advertised");
    assert_eq!(verifier["inputSchema"]["additionalProperties"], false);
    assert_eq!(
        verifier["inputSchema"]["required"],
        json!(["input", "report"])
    );
    assert_eq!(
        verifier["inputSchema"]["properties"]["report"]["minLength"],
        1
    );
    assert_eq!(verifier["execution"]["taskSupport"], "optional");
    assert_eq!(verifier["annotations"]["readOnlyHint"], true);
    assert_eq!(verifier["annotations"]["destructiveHint"], false);

    let erc_verifier = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "verify_native_kicad_erc_report")
        .expect("native ERC replay MCP tool is advertised");
    assert_eq!(erc_verifier["inputSchema"]["additionalProperties"], false);
    assert_eq!(
        erc_verifier["inputSchema"]["required"],
        json!(["input", "retained_report"])
    );
    assert_eq!(
        erc_verifier["inputSchema"]["properties"]["retained_report"]["minLength"],
        1
    );
    assert_eq!(erc_verifier["execution"]["taskSupport"], "optional");
    assert_eq!(erc_verifier["annotations"]["readOnlyHint"], true);
    assert_eq!(erc_verifier["annotations"]["destructiveHint"], false);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "wrong-type",
            "method": "tools/call",
            "params": {
                "name": "run_native_kicad_drc",
                "arguments": {"input": "board.kicad_pcb", "output": "new.json", "project": 4}
            }
        }),
    );
    let wrong_type = receive(&mut stdout);
    assert_eq!(wrong_type["error"]["code"], -32602);
    assert!(
        wrong_type["error"]["data"]["detail"]
            .as_str()
            .unwrap()
            .contains("project")
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "replay-wrong-type",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_drc_report",
                "arguments": {"input": "board.kicad_pcb", "report": 4}
            }
        }),
    );
    let replay_wrong_type = receive(&mut stdout);
    assert_eq!(replay_wrong_type["error"]["code"], -32602);
    assert!(
        replay_wrong_type["error"]["data"]["detail"]
            .as_str()
            .unwrap()
            .contains("report")
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "erc-replay-wrong-type",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_erc_report",
                "arguments": {"input": "schematic.kicad_sch", "retained_report": 4}
            }
        }),
    );
    let erc_replay_wrong_type = receive(&mut stdout);
    assert_eq!(erc_replay_wrong_type["error"]["code"], -32602);
    assert!(
        erc_replay_wrong_type["error"]["data"]["detail"]
            .as_str()
            .unwrap()
            .contains("retained_report")
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "stale",
            "method": "tools/call",
            "params": {
                "name": "run_native_kicad_drc",
                "arguments": {"input": "board.kicad_pcb", "output": stale}
            }
        }),
    );
    let stale_response = receive(&mut stdout);
    assert_eq!(stale_response["error"]["code"], -32602);
    assert!(
        stale_response["error"]["data"]["detail"]
            .as_str()
            .unwrap()
            .contains("stale MCP evidence")
    );
    assert_eq!(fs::read(&stale).unwrap(), br#"{"old":true}"#);

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    fs::remove_dir_all(output).unwrap();
}

#[cfg(unix)]
#[test]
fn stdio_server_verifies_native_drc_replay_and_preserves_rejected_summary() {
    let output = temporary_directory("mcp-native-drc-replay");
    fs::create_dir_all(&output).unwrap();
    let rejected_cli = fake_native_kicad_drc_cli(&output, "fake-drc-rejected", true);
    let approved_cli = fake_native_kicad_drc_cli(&output, "fake-drc-approved", false);
    let board = output.join("-board.kicad_pcb");
    let report = output.join("-retained.json");
    fs::write(&board, b"board").unwrap();

    // Seed a canonical rejected report directly through the public CLI.  The
    // MCP replay below must verify this retained report without replacing it.
    let generated = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .current_dir(&output)
        .args([
            "run-native-kicad-drc",
            "--output=-retained.json",
            "--kicad-cli=./fake-drc-rejected",
            "--",
            "-board.kicad_pcb",
        ])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "native DRC seed failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let retained = fs::read(&report).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .current_dir(&output)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(
        &mut stdin,
        &mut stdout,
        json!("initialize-native-drc-replay"),
    );
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "replay-rejected",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_drc_report",
                "arguments": {
                    "input": "-board.kicad_pcb",
                    "report": "-retained.json",
                    "kicad_cli": "./fake-drc-rejected",
                    "require_approved": true
                }
            }
        }),
    );
    let rejected = receive(&mut stdout);
    assert_eq!(rejected["id"], "replay-rejected");
    assert_eq!(rejected["result"]["isError"], true);
    assert_eq!(rejected["result"]["structuredContent"]["ok"], false);
    let summary = &rejected["result"]["structuredContent"]["report_summary"];
    const SUMMARY_FIELDS: [&str; 17] = [
        "schema_version",
        "approved",
        "violation_count",
        "unconnected_item_count",
        "schematic_parity_count",
        "error_count",
        "warning_count",
        "ignored_check_count",
        "board_bytes",
        "board_sha256",
        "project_bytes",
        "project_sha256",
        "rules_file_bytes",
        "rules_file_sha256",
        "run_sha256",
        "report_bytes",
        "report_sha256",
    ];
    assert!(summary.is_object());
    assert_eq!(summary.as_object().unwrap().len(), SUMMARY_FIELDS.len());
    for field in SUMMARY_FIELDS {
        assert!(
            summary.get(field).is_some(),
            "missing summary field {field}"
        );
    }
    assert_eq!(summary["approved"], false);
    assert_eq!(summary["error_count"], 1);
    assert_eq!(summary["report_bytes"], retained.len());
    let mut retained_hasher = Sha256::new();
    retained_hasher.update(&retained);
    assert_eq!(
        summary["report_sha256"],
        hex::encode(retained_hasher.finalize())
    );
    assert_eq!(fs::read(&report).unwrap(), retained);

    // A fresh run with a different native result must fail closed: no summary
    // is trusted, and the retained rejected report remains byte-for-byte
    // unchanged.
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "replay-mismatch",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_drc_report",
                "arguments": {
                    "input": "-board.kicad_pcb",
                    "report": "-retained.json",
                    "kicad_cli": "./fake-drc-approved"
                }
            }
        }),
    );
    let mismatch = receive(&mut stdout);
    assert_eq!(mismatch["id"], "replay-mismatch");
    assert_eq!(mismatch["result"]["isError"], true);
    assert_eq!(mismatch["result"]["structuredContent"]["ok"], false);
    assert!(mismatch["result"]["structuredContent"]["report_summary"].is_null());
    assert_eq!(fs::read(&report).unwrap(), retained);

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert!(rejected_cli.is_file());
    assert!(approved_cli.is_file());
    fs::remove_dir_all(output).unwrap();
}

#[cfg(unix)]
#[test]
fn stdio_server_direct_native_drc_bridge_retains_rejected_report_and_structured_failures() {
    const SUMMARY_FIELDS: [&str; 17] = [
        "schema_version",
        "approved",
        "violation_count",
        "unconnected_item_count",
        "schematic_parity_count",
        "error_count",
        "warning_count",
        "ignored_check_count",
        "board_bytes",
        "board_sha256",
        "project_bytes",
        "project_sha256",
        "rules_file_bytes",
        "rules_file_sha256",
        "run_sha256",
        "report_bytes",
        "report_sha256",
    ];
    let output = temporary_directory("mcp-native-drc-direct-bridge");
    fs::create_dir_all(&output).unwrap();
    let rejected_cli = fake_native_kicad_drc_cli(&output, "fake-drc-direct-rejected", true);
    let malformed_cli = fake_malformed_native_kicad_drc_cli(&output, "fake-drc-direct-malformed");
    let board = output.join("board.kicad_pcb");
    let report = output.join("rejected.json");
    let malformed_report = output.join("malformed.json");
    fs::write(&board, b"board").unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .current_dir(&output)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    initialize(
        &mut stdin,
        &mut stdout,
        json!("initialize-native-drc-direct-bridge"),
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "direct-rejected",
            "method": "tools/call",
            "params": {
                "name": "run_native_kicad_drc",
                "arguments": {
                    "input": "board.kicad_pcb",
                    "output": "rejected.json",
                    "kicad_cli": "./fake-drc-direct-rejected",
                    "require_approved": true
                }
            }
        }),
    );
    let rejected = receive(&mut stdout);
    assert_eq!(rejected["jsonrpc"], "2.0");
    assert_eq!(rejected["id"], "direct-rejected");
    assert!(rejected.get("error").is_none());
    assert_eq!(rejected["result"]["isError"], true);
    let rejected_result = &rejected["result"]["structuredContent"];
    assert_eq!(rejected_result["ok"], false);
    assert_eq!(rejected_result["exit_code"], 1);
    let summary = &rejected_result["report_summary"];
    assert!(summary.is_object());
    assert_eq!(summary.as_object().unwrap().len(), SUMMARY_FIELDS.len());
    for field in SUMMARY_FIELDS {
        assert!(
            summary.get(field).is_some(),
            "missing summary field {field}"
        );
    }
    assert_eq!(summary["schema_version"], 1);
    assert_eq!(summary["approved"], false);
    assert_eq!(summary["error_count"], 1);
    let retained = fs::read(&report).unwrap();
    assert_eq!(summary["report_bytes"], retained.len());
    assert_eq!(
        summary["report_sha256"],
        hex::encode(Sha256::digest(&retained))
    );
    let retained_json: Value = serde_json::from_slice(&retained).unwrap();
    assert_eq!(retained_json["schema_version"], 1);
    assert_eq!(retained_json["approved"], false);
    assert_eq!(retained_json["error_count"], 1);
    assert!(retained.ends_with(b"\n"));

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "direct-malformed",
            "method": "tools/call",
            "params": {
                "name": "run_native_kicad_drc",
                "arguments": {
                    "input": "board.kicad_pcb",
                    "output": "malformed.json",
                    "kicad_cli": "./fake-drc-direct-malformed"
                }
            }
        }),
    );
    let malformed = receive(&mut stdout);
    assert_eq!(malformed["jsonrpc"], "2.0");
    assert_eq!(malformed["id"], "direct-malformed");
    assert!(malformed.get("error").is_none());
    assert_eq!(malformed["result"]["isError"], true);
    let malformed_result = &malformed["result"]["structuredContent"];
    assert_eq!(malformed_result["ok"], false);
    assert_eq!(malformed_result["exit_code"], 1);
    assert!(malformed_result["report_summary"].is_null());
    assert!(!malformed_report.exists());

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert!(rejected_cli.is_file());
    assert!(malformed_cli.is_file());
    fs::remove_dir_all(output).unwrap();
}

#[cfg(unix)]
#[test]
fn stdio_server_verifies_native_erc_replay_and_preserves_report_bytes() {
    let output = temporary_directory("mcp-native-erc-replay");
    fs::create_dir_all(&output).unwrap();
    let rejected_cli = fake_native_kicad_erc_cli(&output, "fake-erc-rejected", true);
    let approved_cli = fake_native_kicad_erc_cli(&output, "fake-erc-approved", false);
    let warning_cli = fake_native_kicad_erc_warning_cli(&output, "fake-erc-warning");
    let schematic = output.join("schematic.kicad_sch");
    let rejected_report = output.join("rejected.json");
    let warning_report = output.join("warning.json");
    let warning_policy = output.join("warning-policy.json");
    let warning_policy_source = br#"{"schema_version":1,"id":"test-warning-policy","maximum_total_warnings":1,"warning_limits":[{"finding_type":"warning_type","maximum_count":1}],"allowed_ignored_checks":["ignored"]}"#;
    fs::write(&schematic, b"schematic").unwrap();
    fs::write(&warning_policy, warning_policy_source).unwrap();

    let generated = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .current_dir(&output)
        .args([
            "run-native-kicad-erc",
            "schematic.kicad_sch",
            "--output",
            "rejected.json",
            "--kicad-cli",
        ])
        .arg(&rejected_cli)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "native ERC seed failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let retained_rejected = fs::read(&rejected_report).unwrap();

    let generated_warning = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .current_dir(&output)
        .args([
            "run-native-kicad-erc",
            "schematic.kicad_sch",
            "--output",
            "warning.json",
            "--kicad-cli",
        ])
        .arg(&warning_cli)
        .arg("--warning-policy")
        .arg(&warning_policy)
        .output()
        .unwrap();
    assert!(
        generated_warning.status.success(),
        "native ERC warning seed failed: {}",
        String::from_utf8_lossy(&generated_warning.stderr)
    );
    let retained_warning = fs::read(&warning_report).unwrap();

    let malformed = output.join("malformed.json");
    fs::write(&malformed, b"not-json").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .current_dir(&output)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    initialize(
        &mut stdin,
        &mut stdout,
        json!("initialize-native-erc-replay"),
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "replay-rejected-evidence",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_erc_report",
                "arguments": {
                    "input": "schematic.kicad_sch",
                    "retained_report": "rejected.json",
                    "kicad_cli": rejected_cli.display().to_string()
                }
            }
        }),
    );
    let rejected = receive(&mut stdout);
    assert_eq!(rejected["id"], "replay-rejected-evidence");
    assert_eq!(rejected["result"]["isError"], false);
    let rejected_result = &rejected["result"]["structuredContent"];
    assert_eq!(rejected_result["ok"], true);
    let rejected_summary = &rejected_result["report_summary"];
    assert_eq!(rejected_summary.as_object().unwrap().len(), 6);
    assert_eq!(rejected_summary["schema_version"], 1);
    assert_eq!(rejected_summary["approved"], false);
    assert_eq!(rejected_summary["error_count"], 1);
    assert_eq!(rejected_summary["report_bytes"], retained_rejected.len());
    assert_eq!(
        rejected_summary["report_sha256"],
        hex::encode(Sha256::digest(&retained_rejected))
    );
    assert_eq!(fs::read(&rejected_report).unwrap(), retained_rejected);

    // A fresh run with different findings is stale evidence, not a new
    // retained report.  Replay must reject it without touching the original.
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "replay-stale",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_erc_report",
                "arguments": {
                    "input": "schematic.kicad_sch",
                    "retained_report": "rejected.json",
                    "kicad_cli": approved_cli.display().to_string()
                }
            }
        }),
    );
    let stale = receive(&mut stdout);
    assert_eq!(stale["id"], "replay-stale");
    assert_eq!(stale["result"]["isError"], true);
    assert_eq!(stale["result"]["structuredContent"]["ok"], false);
    assert!(stale["result"]["structuredContent"]["report_summary"].is_null());
    assert_eq!(fs::read(&rejected_report).unwrap(), retained_rejected);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "replay-rejected-gate",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_erc_report",
                "arguments": {
                    "input": "schematic.kicad_sch",
                    "retained_report": "rejected.json",
                    "kicad_cli": rejected_cli.display().to_string(),
                    "require_approved": true
                }
            }
        }),
    );
    let rejected_gate = receive(&mut stdout);
    assert_eq!(rejected_gate["id"], "replay-rejected-gate");
    assert_eq!(rejected_gate["result"]["isError"], true);
    assert_eq!(rejected_gate["result"]["structuredContent"]["ok"], false);
    assert_eq!(
        rejected_gate["result"]["structuredContent"]["report_summary"],
        rejected_summary.clone()
    );
    assert_eq!(fs::read(&rejected_report).unwrap(), retained_rejected);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "replay-warning",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_erc_report",
                "arguments": {
                    "input": "schematic.kicad_sch",
                    "retained_report": "warning.json",
                    "warning_policy": warning_policy.display().to_string(),
                    "kicad_cli": warning_cli.display().to_string(),
                    "require_approved": true
                }
            }
        }),
    );
    let warning = receive(&mut stdout);
    assert_eq!(warning["id"], "replay-warning");
    assert_eq!(warning["result"]["isError"], false);
    let warning_summary = &warning["result"]["structuredContent"]["report_summary"];
    let expected_warning_fields = [
        "schema_version",
        "approved",
        "error_count",
        "warning_count",
        "policy_failure_count",
        "run_sha256",
        "report_bytes",
        "report_sha256",
        "warning_policy_sha256",
        "warning_policy_source_bytes",
        "warning_policy_source_sha256",
    ];
    assert_eq!(
        warning_summary.as_object().unwrap().len(),
        expected_warning_fields.len()
    );
    for field in expected_warning_fields {
        assert!(warning_summary.get(field).is_some(), "missing {field}");
    }
    assert_eq!(warning_summary["schema_version"], 2);
    assert_eq!(warning_summary["approved"], true);
    assert_eq!(warning_summary["warning_count"], 1);
    assert_eq!(warning_summary["policy_failure_count"], 0);
    assert_eq!(warning_summary["report_bytes"], retained_warning.len());
    assert_eq!(
        warning_summary["report_sha256"],
        hex::encode(Sha256::digest(&retained_warning))
    );
    assert_eq!(fs::read(&warning_report).unwrap(), retained_warning);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "replay-malformed",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_erc_report",
                "arguments": {
                    "input": "schematic.kicad_sch",
                    "retained_report": "malformed.json",
                    "kicad_cli": rejected_cli.display().to_string()
                }
            }
        }),
    );
    let malformed_response = receive(&mut stdout);
    assert_eq!(malformed_response["id"], "replay-malformed");
    assert_eq!(malformed_response["result"]["isError"], true);
    assert_eq!(
        malformed_response["result"]["structuredContent"]["ok"],
        false
    );
    assert!(malformed_response["result"]["structuredContent"]["report_summary"].is_null());
    assert_eq!(fs::read(&malformed).unwrap(), b"not-json");

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert!(rejected_cli.is_file());
    assert!(approved_cli.is_file());
    assert!(warning_cli.is_file());
    fs::remove_dir_all(output).unwrap();
}

#[cfg(unix)]
#[test]
fn stdio_server_direct_native_erc_bridge_retains_rejected_report_and_trusted_summary() {
    let output = temporary_directory("mcp-native-erc-direct-bridge");
    fs::create_dir_all(&output).unwrap();
    let rejected_cli = fake_native_kicad_erc_cli(&output, "fake-erc-direct-rejected", true);
    let warning_cli = fake_native_kicad_erc_warning_cli(&output, "fake-erc-direct-warning");
    let schematic = output.join("schematic.kicad_sch");
    let report = output.join("rejected-erc.json");
    let warning_report = output.join("warning-erc.json");
    let warning_policy = output.join("warning-policy.json");
    let warning_policy_source = br#"{"schema_version":1,"id":"test-warning-policy","maximum_total_warnings":1,"warning_limits":[{"finding_type":"warning_type","maximum_count":1}],"allowed_ignored_checks":["ignored"]}"#;
    fs::write(&warning_policy, warning_policy_source).unwrap();
    fs::write(&schematic, b"schematic").unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .current_dir(&output)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    initialize(
        &mut stdin,
        &mut stdout,
        json!("initialize-native-erc-direct-bridge"),
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "direct-erc-rejected",
            "method": "tools/call",
            "params": {
                "name": "run_native_kicad_erc",
                "arguments": {
                    "input": "schematic.kicad_sch",
                    "output": "rejected-erc.json",
                    "kicad_cli": rejected_cli,
                    "require_approved": true
                }
            }
        }),
    );
    let rejected = receive(&mut stdout);
    assert_eq!(rejected["jsonrpc"], "2.0");
    assert_eq!(rejected["id"], "direct-erc-rejected");
    assert!(rejected.get("error").is_none());
    assert_eq!(rejected["result"]["isError"], true);
    let rejected_result = &rejected["result"]["structuredContent"];
    assert_eq!(rejected_result["ok"], false);
    assert_eq!(rejected_result["exit_code"], 1);
    let summary = &rejected_result["report_summary"];
    assert!(summary.is_object());
    assert_eq!(summary.as_object().unwrap().len(), 6);
    assert_eq!(summary["schema_version"], 1);
    assert_eq!(summary["approved"], false);
    assert_eq!(summary["error_count"], 1);
    assert_eq!(summary["run_sha256"].as_str().unwrap().len(), 64);
    let retained = fs::read(&report).unwrap();
    assert_eq!(summary["report_bytes"], retained.len());
    assert_eq!(
        summary["report_sha256"],
        hex::encode(Sha256::digest(&retained))
    );
    let retained_json: Value = serde_json::from_slice(&retained).unwrap();
    assert_eq!(retained_json["schema_version"], 1);
    assert_eq!(retained_json["approved"], false);
    assert_eq!(retained_json["error_count"], 1);
    assert!(retained.ends_with(b"\n"));

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "direct-erc-warning",
            "method": "tools/call",
            "params": {
                "name": "run_native_kicad_erc",
                "arguments": {
                    "input": "schematic.kicad_sch",
                    "output": "warning-erc.json",
                    "kicad_cli": warning_cli,
                    "warning_policy": warning_policy,
                    "require_approved": true
                }
            }
        }),
    );
    let warning = receive(&mut stdout);
    assert_eq!(warning["jsonrpc"], "2.0");
    assert_eq!(warning["id"], "direct-erc-warning");
    assert!(warning.get("error").is_none());
    assert_eq!(warning["result"]["isError"], false);
    let warning_result = &warning["result"]["structuredContent"];
    assert_eq!(warning_result["ok"], true);
    assert_eq!(warning_result["exit_code"], 0);
    let warning_summary = &warning_result["report_summary"];
    let expected_fields = [
        "schema_version",
        "approved",
        "error_count",
        "warning_count",
        "policy_failure_count",
        "run_sha256",
        "report_bytes",
        "report_sha256",
        "warning_policy_sha256",
        "warning_policy_source_bytes",
        "warning_policy_source_sha256",
    ];
    let warning_summary_object = warning_summary.as_object().unwrap();
    assert_eq!(warning_summary_object.len(), expected_fields.len());
    for field in expected_fields {
        assert!(
            warning_summary_object.contains_key(field),
            "missing {field}"
        );
    }
    assert_eq!(warning_summary["schema_version"], 2);
    assert_eq!(warning_summary["approved"], true);
    assert_eq!(warning_summary["error_count"], 0);
    assert_eq!(warning_summary["warning_count"], 1);
    assert_eq!(warning_summary["policy_failure_count"], 0);
    assert_eq!(
        warning_summary["warning_policy_source_bytes"],
        warning_policy_source.len()
    );
    let warning_policy_source_sha256 = hex::encode(Sha256::digest(warning_policy_source));
    assert_eq!(
        warning_summary["warning_policy_source_sha256"],
        warning_policy_source_sha256
    );
    let mut policy_hasher = Sha256::new();
    policy_hasher.update(b"pcbex/native-kicad-erc-warning-policy/v1\0");
    policy_hasher.update(warning_policy_source);
    let warning_policy_sha256 = hex::encode(policy_hasher.finalize());
    assert_eq!(
        warning_summary["warning_policy_sha256"],
        warning_policy_sha256
    );
    assert_eq!(warning_summary["run_sha256"].as_str().unwrap().len(), 64);
    let warning_retained = fs::read(&warning_report).unwrap();
    assert_eq!(warning_summary["report_bytes"], warning_retained.len());
    assert_eq!(
        warning_summary["report_sha256"],
        hex::encode(Sha256::digest(&warning_retained))
    );
    let warning_retained_json: Value = serde_json::from_slice(&warning_retained).unwrap();
    assert_eq!(warning_retained_json["schema_version"], 2);
    assert_eq!(warning_retained_json["approved"], true);
    assert_eq!(warning_retained_json["error_count"], 0);
    assert_eq!(warning_retained_json["warning_count"], 1);
    assert!(
        warning_retained_json["policy_failures"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        warning_retained_json["warning_policy"]["policy_sha256"],
        warning_policy_sha256
    );
    assert_eq!(
        warning_retained_json["warning_policy"]["source"]["bytes"],
        warning_policy_source.len()
    );
    assert_eq!(
        warning_retained_json["warning_policy"]["source"]["sha256"],
        warning_policy_source_sha256
    );
    assert_eq!(
        warning_retained_json["run_sha256"],
        warning_summary["run_sha256"]
    );
    assert!(warning_retained.ends_with(b"\n"));

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert!(rejected_cli.is_file());
    assert!(warning_cli.is_file());
    fs::remove_dir_all(output).unwrap();
}

#[cfg(unix)]
#[test]
fn stdio_server_cancels_native_drc_replay_without_orphaning_kicad() {
    let output = temporary_directory("mcp-native-drc-replay-cancel");
    fs::create_dir_all(&output).unwrap();
    let approved_cli = fake_native_kicad_drc_cli(&output, "fake-drc-approved", false);
    let sleeping_cli = fake_sleeping_native_kicad_cli(&output, "fake-drc-sleeping");
    let board = output.join("board.kicad_pcb");
    let report = output.join("retained.json");
    let pid_file = output.join("kicad.pid");
    let mut process_cleanup = KicadProcessCleanup::new(&pid_file);
    fs::write(&board, b"board").unwrap();

    let generated = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .current_dir(&output)
        .args([
            "run-native-kicad-drc",
            "--output=retained.json",
            "--kicad-cli=./fake-drc-approved",
            "--",
            "board.kicad_pcb",
        ])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "native DRC seed failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let retained = fs::read(&report).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .current_dir(&output)
        .env("PCBEX_TEST_KICAD_PID_FILE", &pid_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    initialize(&mut stdin, &mut stdout, json!("initialize-replay-cancel"));

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "create-replay-task",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_drc_report",
                "arguments": {
                    "input": "board.kicad_pcb",
                    "report": "retained.json",
                    "kicad_cli": "./fake-drc-sleeping"
                },
                "task": {"ttl": 60_000}
            }
        }),
    );
    let created = receive(&mut stdout);
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("replay task id")
        .to_string();
    assert_eq!(created["result"]["task"]["status"], "working");

    let pids = process_cleanup.wait_for_start();
    assert!(pid_file.is_file(), "sleeping KiCad child did not start");
    assert_eq!(pids.len(), 2, "fixture must record shell and sleep PIDs");
    assert!(
        process_cleanup.process_group.is_some(),
        "fixture process group was not validated"
    );
    assert!(pids.iter().all(|pid| unix_process_exists(*pid)));

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "cancel-replay-task",
            "method": "tasks/cancel",
            "params": {"taskId": task_id}
        }),
    );
    let cancelled = receive(&mut stdout);
    assert_eq!(cancelled["result"]["status"], "cancelled");

    let orphaned = process_cleanup.wait_for_exit();
    assert!(
        orphaned.is_empty(),
        "cancelled replay left KiCad processes {orphaned:?} running"
    );
    assert_eq!(fs::read(&report).unwrap(), retained);

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert!(approved_cli.is_file());
    assert!(sleeping_cli.is_file());
    fs::remove_dir_all(output).unwrap();
}

#[cfg(unix)]
#[test]
fn stdio_server_cancels_native_erc_replay_without_orphaning_kicad() {
    let output = temporary_directory("mcp-native-erc-replay-cancel");
    fs::create_dir_all(&output).unwrap();
    let approved_cli = fake_native_kicad_erc_cli(&output, "fake-erc-approved", false);
    let sleeping_cli = fake_sleeping_native_kicad_cli(&output, "fake-erc-sleeping");
    let schematic = output.join("schematic.kicad_sch");
    let report = output.join("retained.json");
    let pid_file = output.join("kicad.pid");
    let mut process_cleanup = KicadProcessCleanup::new(&pid_file);
    fs::write(&schematic, b"schematic").unwrap();

    let generated = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .current_dir(&output)
        .args([
            "run-native-kicad-erc",
            "schematic.kicad_sch",
            "--output",
            "retained.json",
            "--kicad-cli",
        ])
        .arg(&approved_cli)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "native ERC seed failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let retained = fs::read(&report).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .current_dir(&output)
        .env("PCBEX_TEST_KICAD_PID_FILE", &pid_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    initialize(
        &mut stdin,
        &mut stdout,
        json!("initialize-native-erc-replay-cancel"),
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "create-erc-replay-task",
            "method": "tools/call",
            "params": {
                "name": "verify_native_kicad_erc_report",
                "arguments": {
                    "input": "schematic.kicad_sch",
                    "retained_report": "retained.json",
                    "kicad_cli": sleeping_cli.display().to_string()
                },
                "task": {"ttl": 60_000}
            }
        }),
    );
    let created = receive(&mut stdout);
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("ERC replay task id")
        .to_string();
    assert_eq!(created["result"]["task"]["status"], "working");

    let pids = process_cleanup.wait_for_start();
    assert!(pid_file.is_file(), "sleeping KiCad child did not start");
    assert_eq!(pids.len(), 2, "fixture must record shell and sleep PIDs");
    assert!(
        process_cleanup.process_group.is_some(),
        "fixture process group was not validated"
    );
    assert!(pids.iter().all(|pid| unix_process_exists(*pid)));

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "cancel-erc-replay-task",
            "method": "tasks/cancel",
            "params": {"taskId": task_id}
        }),
    );
    let cancelled = receive(&mut stdout);
    assert_eq!(cancelled["result"]["status"], "cancelled");

    let orphaned = process_cleanup.wait_for_exit();
    assert!(
        orphaned.is_empty(),
        "cancelled ERC replay left KiCad processes {orphaned:?} running"
    );
    assert_eq!(fs::read(&report).unwrap(), retained);

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert!(approved_cli.is_file());
    assert!(sleeping_cli.is_file());
    fs::remove_dir_all(output).unwrap();
}

#[cfg(unix)]
#[test]
fn stdio_server_cancels_native_drc_task_without_orphaning_kicad() {
    let output = temporary_directory("mcp-native-drc-run-cancel");
    fs::create_dir_all(&output).unwrap();
    let sleeping_cli = fake_sleeping_native_kicad_cli(&output, "fake-drc-run-sleeping");
    let board = output.join("board.kicad_pcb");
    let report = output.join("drc.json");
    let pid_file = output.join("drc-run.kicad.pid");
    let mut process_cleanup = KicadProcessCleanup::new(&pid_file);
    fs::write(&board, b"board").unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .current_dir(&output)
        .env("PCBEX_TEST_KICAD_PID_FILE", &pid_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    initialize(
        &mut stdin,
        &mut stdout,
        json!("initialize-native-drc-run-cancel"),
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "create-drc-run-task",
            "method": "tools/call",
            "params": {
                "name": "run_native_kicad_drc",
                "arguments": {
                    "input": "board.kicad_pcb",
                    "output": "drc.json",
                    "kicad_cli": "./fake-drc-run-sleeping"
                },
                "task": {"ttl": 60_000}
            }
        }),
    );
    let created = receive(&mut stdout);
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("DRC task id")
        .to_string();
    assert_eq!(created["result"]["task"]["status"], "working");

    let pids = process_cleanup.wait_for_start();
    assert_eq!(pids.len(), 2, "fixture must record shell and sleep PIDs");
    assert!(
        process_cleanup.process_group.is_some(),
        "fixture process group was not validated"
    );
    assert!(pids.iter().all(|pid| unix_process_exists(*pid)));

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "cancel-drc-run-task",
            "method": "tasks/cancel",
            "params": {"taskId": task_id}
        }),
    );
    let cancelled = receive(&mut stdout);
    assert_eq!(cancelled["result"]["status"], "cancelled");

    let orphaned = process_cleanup.wait_for_exit();
    assert!(
        orphaned.is_empty(),
        "cancelled native DRC run left KiCad processes {orphaned:?} running"
    );

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert!(sleeping_cli.is_file());
    assert!(!report.exists(), "cancelled DRC must not publish a report");
    fs::remove_dir_all(output).unwrap();
}

#[cfg(unix)]
#[test]
fn stdio_server_cancels_native_erc_task_without_orphaning_kicad() {
    let output = temporary_directory("mcp-native-erc-run-cancel");
    fs::create_dir_all(&output).unwrap();
    let sleeping_cli = fake_sleeping_native_kicad_cli(&output, "fake-erc-run-sleeping");
    let schematic = output.join("schematic.kicad_sch");
    let report = output.join("erc.json");
    let pid_file = output.join("erc-run.kicad.pid");
    let mut process_cleanup = KicadProcessCleanup::new(&pid_file);
    fs::write(&schematic, b"schematic").unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .current_dir(&output)
        .env("PCBEX_TEST_KICAD_PID_FILE", &pid_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    initialize(
        &mut stdin,
        &mut stdout,
        json!("initialize-native-erc-run-cancel"),
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "create-erc-run-task",
            "method": "tools/call",
            "params": {
                "name": "run_native_kicad_erc",
                "arguments": {
                    "input": "schematic.kicad_sch",
                    "output": "erc.json",
                    "kicad_cli": sleeping_cli
                },
                "task": {"ttl": 60_000}
            }
        }),
    );
    let created = receive(&mut stdout);
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("ERC task id")
        .to_string();
    assert_eq!(created["result"]["task"]["status"], "working");

    let pids = process_cleanup.wait_for_start();
    assert_eq!(pids.len(), 2, "fixture must record shell and sleep PIDs");
    assert!(
        process_cleanup.process_group.is_some(),
        "fixture process group was not validated"
    );
    assert!(pids.iter().all(|pid| unix_process_exists(*pid)));

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "cancel-erc-run-task",
            "method": "tasks/cancel",
            "params": {"taskId": task_id}
        }),
    );
    let cancelled = receive(&mut stdout);
    assert_eq!(cancelled["result"]["status"], "cancelled");

    let orphaned = process_cleanup.wait_for_exit();
    assert!(
        orphaned.is_empty(),
        "cancelled native ERC run left KiCad processes {orphaned:?} running"
    );

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert!(sleeping_cli.is_file());
    assert!(!report.exists(), "cancelled ERC must not publish a report");
    fs::remove_dir_all(output).unwrap();
}

#[test]
fn physical_profile_is_forwarded_and_cli_rejects_conflicting_fabrication_profile() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("examples/simple.kicad_pcb");
    let output = temporary_directory("mcp-physical-profile-conflict");
    fs::create_dir_all(&output).unwrap();
    let profile = output.join("physical-profile.json");
    fs::write(&profile, b"{}").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "physical-profile-test", "version": "1"}
            }
        }),
    );
    send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    let initialized = receive(&mut stdout);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "conflict",
            "method": "tools/call",
            "params": {
                "name": "analyze_kicad",
                "arguments": {
                    "input": input,
                    "output_dir": output.join("artifacts"),
                    "fab": "jlcpcb-2layer",
                    "physical_profile": profile
                }
            }
        }),
    );
    let response = receive(&mut stdout);
    drop(stdin);
    assert_eq!(response["id"], "conflict");
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(response["result"]["structuredContent"]["ok"], false);
    assert!(
        response["result"]["structuredContent"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("cannot be used with"))
    );
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );

    fs::remove_dir_all(output).unwrap();
}

#[test]
fn stdio_server_check_schematic_success_retains_all_requested_artifacts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("crates/pcbex-cli/tests/fixtures/approved-empty.kicad_sch");
    let output = temporary_directory("mcp-check-schematic");
    fs::create_dir_all(&output).unwrap();
    let review = output.join("review.json");
    let explanation = output.join("explanation.json");
    let junit = output.join("review.xml");
    let sarif = output.join("review.sarif");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(&mut stdin, &mut stdout, json!("initialize-check-schematic"));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "check-schematic",
            "method": "tools/call",
            "params": {
                "name": "check_schematic",
                "arguments": {
                    "input": input,
                    "output": review,
                    "explain": explanation,
                    "junit_output": junit,
                    "sarif_output": sarif,
                    "require_approved": true
                }
            }
        }),
    );
    let response = receive(&mut stdout);
    assert_eq!(response["id"], "check-schematic");
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(response["result"]["structuredContent"]["ok"], true);
    assert_eq!(
        response["result"]["structuredContent"]["review"]["approved"],
        true
    );
    assert!(response["result"]["structuredContent"]["explanation"].is_object());
    assert!(response["result"]["structuredContent"]["sarif"].is_object());
    assert!(review.is_file());
    assert!(explanation.is_file());
    assert!(junit.is_file());
    assert!(sarif.is_file());

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    fs::remove_dir_all(output).unwrap();
}

#[test]
fn stdio_server_check_circuit_spec_success_requires_and_retains_output() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("examples/circuit-spec-v2.json");
    let output = temporary_directory("mcp-check-circuit-spec");
    fs::create_dir_all(&output).unwrap();
    let check = output.join("check.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(&mut stdin, &mut stdout, json!("initialize-circuit-spec"));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "check-circuit-spec",
            "method": "tools/call",
            "params": {
                "name": "check_circuit_spec",
                "arguments": {
                    "input": input,
                    "output": check,
                    "require_approved": true
                }
            }
        }),
    );
    let response = receive(&mut stdout);
    assert_eq!(response["id"], "check-circuit-spec");
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(response["result"]["structuredContent"]["ok"], true);
    assert_eq!(
        response["result"]["structuredContent"]["check"]["electrical_review"]["approved"],
        true
    );
    assert!(check.is_file());

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    fs::remove_dir_all(output).unwrap();
}

#[test]
fn stdio_server_write_circuit_spec_kicad_schematic_returns_only_digest_summary() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("examples/circuit-spec-v2.json");
    let output = temporary_directory("mcp-write-circuit-spec");
    fs::create_dir_all(&output).unwrap();
    let schematic = output.join("generated.kicad_sch");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(
        &mut stdin,
        &mut stdout,
        json!("initialize-write-circuit-spec"),
    );
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "write-circuit-spec",
            "method": "tools/call",
            "params": {
                "name": "write_circuit_spec_kicad_schematic",
                "arguments": {
                    "input": input,
                    "output": schematic
                }
            }
        }),
    );
    let response = receive(&mut stdout);
    assert_eq!(response["id"], "write-circuit-spec");
    assert_eq!(response["result"]["isError"], false);
    let structured = &response["result"]["structuredContent"];
    assert_eq!(structured["ok"], true);
    assert_eq!(
        structured["schematic"]["path"],
        schematic.display().to_string()
    );
    let bytes = fs::read(&schematic).unwrap();
    assert_eq!(structured["schematic"]["bytes"], bytes.len() as u64);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    assert_eq!(
        structured["schematic"]["sha256"],
        hex::encode(hasher.finalize())
    );
    assert!(structured["schematic"].get("content").is_none());
    assert!(response.to_string().len() < 16 * 1024 * 1024);

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    fs::remove_dir_all(output).unwrap();
}

#[test]
fn stdio_server_pipeline_verify_retains_rejected_report() {
    let output = temporary_directory("mcp-pipeline-rejected");
    fs::create_dir_all(&output).unwrap();
    let report = output.join("pipeline.json");
    let path = |name: &str| output.join(name);
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(&mut stdin, &mut stdout, json!("initialize-pipeline"));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "pipeline",
            "method": "tools/call",
            "params": {
                "name": "pipeline_verify",
                "arguments": {
                    "schematic": path("schematic.kicad_sch"),
                    "electrical_policy": path("electrical-policy.json"),
                    "electrical_review": path("electrical-review.json"),
                    "board": path("board.kicad_pcb"),
                    "analysis_manifest": path("run.json"),
                    "analysis_checks": path("checks.json"),
                    "quality": path("quality.json"),
                    "analysis_project": path("project.kicad_pro"),
                    "analysis_rules": path("rules.kicad_dru"),
                    "analysis_dfm_profile": path("dfm-profile.json"),
                    "analysis_policy_pack": path("policy-pack.json"),
                    "analysis_physical_profile": path("physical-profile.json"),
                    "manufacturing_package": path("manufacturing.zip"),
                    "firmware_manifest": path("firmware.json"),
                    "require_factory": true,
                    "output": report
                }
            }
        }),
    );
    let response = receive(&mut stdout);
    assert_eq!(response["id"], "pipeline");
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(response["result"]["structuredContent"]["ok"], false);
    assert_eq!(
        response["result"]["structuredContent"]["report"]["passed"],
        false
    );
    assert_eq!(
        response["result"]["structuredContent"]["report"]["schema_version"],
        2
    );
    assert!(report.is_file());

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    fs::remove_dir_all(output).unwrap();
}

#[test]
fn stdio_server_compiles_deterministic_pipeline_intent_sync_and_as_task() {
    let output = temporary_directory("mcp-compile-deterministic-intent");
    let intent = write_deterministic_pipeline_fixture(&output);
    let plan = output.join("pipeline-plan.json");
    let task_plan = output.join("pipeline-plan-task.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(&mut stdin, &mut stdout, json!("initialize-compile-intent"));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "compile-sync",
            "method": "tools/call",
            "params": {
                "name": "compile_deterministic_pipeline_plan",
                "arguments": {"intent": intent, "output": plan}
            }
        }),
    );
    let response = receive(&mut stdout);
    assert_eq!(response["id"], "compile-sync");
    assert_eq!(response["result"]["isError"], false);
    let structured = &response["result"]["structuredContent"];
    assert_eq!(structured["ok"], true);
    assert_eq!(structured["schema_version"], 1);
    assert_eq!(structured["intent"]["path"], intent.display().to_string());
    assert_eq!(structured["plan"]["path"], plan.display().to_string());
    let intent_bytes = fs::read(&intent).unwrap();
    assert_eq!(structured["intent"]["bytes"], intent_bytes.len() as u64);
    assert_eq!(
        structured["intent"]["sha256"],
        hex::encode(Sha256::digest(&intent_bytes))
    );
    let plan_bytes = fs::read(&plan).unwrap();
    assert_eq!(structured["plan"]["bytes"], plan_bytes.len() as u64);
    assert_eq!(
        structured["plan"]["sha256"],
        hex::encode(Sha256::digest(&plan_bytes))
    );
    assert_eq!(plan_bytes.last(), Some(&b'\n'));
    assert!(structured["plan"].get("content").is_none());
    assert!(response.to_string().len() < 16 * 1024 * 1024);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "compile-task",
            "method": "tools/call",
            "params": {
                "name": "compile_deterministic_pipeline_plan",
                "arguments": {"intent": intent, "output": task_plan},
                "task": {"ttl": 60_000}
            }
        }),
    );
    let created = receive(&mut stdout);
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(created["result"]["task"]["status"], "working");
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "compile-task-result",
            "method": "tasks/result",
            "params": {"taskId": task_id}
        }),
    );
    let task_result = receive(&mut stdout);
    assert_eq!(task_result["id"], "compile-task-result");
    assert_eq!(task_result["result"]["isError"], false);
    assert_eq!(
        task_result["result"]["structuredContent"]["plan"]["path"],
        task_plan.display().to_string()
    );
    assert_eq!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        task_id
    );
    assert!(task_plan.is_file());

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    fs::remove_dir_all(output).unwrap();
}

#[test]
fn stdio_server_rejects_invalid_deterministic_firmware_bundle_sync_and_as_task() {
    for case in ["extra-entry", "hash-mismatch"] {
        let output = temporary_directory(&format!("mcp-compile-invalid-{case}"));
        let intent = write_deterministic_pipeline_fixture(&output);
        if case == "extra-entry" {
            let extra = b"unexpected-extra-artifact";
            fs::write(output.join("firmware/extra.bin"), extra).unwrap();
            mutate_firmware_manifest(&output, |manifest| {
                manifest["artifacts"].as_array_mut().unwrap().push(json!({
                    "path": "extra.bin",
                    "bytes": extra.len(),
                    "sha256": hex::encode(Sha256::digest(extra))
                }));
            });
        } else {
            mutate_firmware_manifest(&output, |manifest| {
                manifest["artifacts"].as_array_mut().unwrap()[0]["sha256"] =
                    Value::String("0".repeat(64));
            });
        }

        let sync_plan = output.join("invalid-sync-plan.json");
        let task_plan = output.join("invalid-task-plan.json");
        let stale_plan = output.join("stale-sync-plan.json");
        let stale_contents = br#"{"stale":true}"#;
        fs::write(&stale_plan, stale_contents).unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("mcp-server")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut stderr = child.stderr.take().unwrap();
        let initialized = initialize(
            &mut stdin,
            &mut stdout,
            json!(format!("initialize-invalid-{case}")),
        );
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": "compile-invalid-sync",
                "method": "tools/call",
                "params": {
                    "name": "compile_deterministic_pipeline_plan",
                    "arguments": {"intent": intent, "output": sync_plan}
                }
            }),
        );
        let sync_response = receive(&mut stdout);
        assert_eq!(sync_response["id"], "compile-invalid-sync");
        assert_compile_bundle_rejected(&sync_response, &sync_plan, case);

        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": "compile-invalid-task",
                "method": "tools/call",
                "params": {
                    "name": "compile_deterministic_pipeline_plan",
                    "arguments": {"intent": intent, "output": task_plan},
                    "task": {"ttl": 60_000}
                }
            }),
        );
        let created = receive(&mut stdout);
        let task_id = created["result"]["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(created["result"]["task"]["status"], "working");
        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": "compile-invalid-task-result",
                "method": "tasks/result",
                "params": {"taskId": task_id}
            }),
        );
        let task_response = receive(&mut stdout);
        assert_eq!(task_response["id"], "compile-invalid-task-result");
        assert_eq!(
            task_response["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
            task_id
        );
        assert_compile_bundle_rejected(&task_response, &task_plan, case);

        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": "compile-stale-sync",
                "method": "tools/call",
                "params": {
                    "name": "compile_deterministic_pipeline_plan",
                    "arguments": {"intent": intent, "output": stale_plan}
                }
            }),
        );
        let stale_response = receive(&mut stdout);
        assert_eq!(stale_response["id"], "compile-stale-sync");
        assert_eq!(stale_response["error"]["code"], -32602);
        assert!(
            stale_response["error"]["data"]["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(fs::read(&stale_plan).unwrap(), stale_contents);

        let stale_task_plan = output.join("stale-task-plan.json");
        fs::write(&stale_task_plan, stale_contents).unwrap();
        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": "compile-stale-task",
                "method": "tools/call",
                "params": {
                    "name": "compile_deterministic_pipeline_plan",
                    "arguments": {"intent": intent, "output": stale_task_plan},
                    "task": {"ttl": 60_000}
                }
            }),
        );
        let stale_task_created = receive(&mut stdout);
        let stale_task_id = stale_task_created["result"]["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();
        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": "compile-stale-task-result",
                "method": "tasks/result",
                "params": {"taskId": stale_task_id}
            }),
        );
        let stale_task_response = receive(&mut stdout);
        assert_eq!(stale_task_response["id"], "compile-stale-task-result");
        assert_eq!(stale_task_response["error"]["code"], -32602);
        assert!(
            stale_task_response["error"]["data"]["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(fs::read(&stale_task_plan).unwrap(), stale_contents);

        drop(stdin);
        assert!(child.wait().unwrap().success());
        let mut stderr_bytes = Vec::new();
        stderr.read_to_end(&mut stderr_bytes).unwrap();
        assert!(
            stderr_bytes.is_empty(),
            "MCP server stderr: {}",
            String::from_utf8_lossy(&stderr_bytes)
        );
        fs::remove_dir_all(output).unwrap();
    }
}

#[test]
fn stdio_server_handoff_retains_success_and_rejected_reports() {
    let output = temporary_directory("mcp-handoff");
    fs::create_dir_all(&output).unwrap();
    let spec = output.join("circuit.json");
    let schematic = output.join("design.kicad_sch");
    fs::write(&spec, HANDOFF_CIRCUIT_SPEC).unwrap();
    fs::write(&schematic, handoff_schematic()).unwrap();
    let approved_report = output.join("approved.json");
    let rejected_report = output.join("rejected.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(&mut stdin, &mut stdout, json!("initialize-handoff"));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "handoff-success",
            "method": "tools/call",
            "params": {
                "name": "verify_circuit_kicad_handoff",
                "arguments": {
                    "circuit_spec": spec,
                    "schematic": schematic,
                    "output": approved_report,
                    "require_approved": true
                }
            }
        }),
    );
    let success = receive(&mut stdout);
    assert_eq!(success["id"], "handoff-success");
    assert_eq!(success["result"]["isError"], false);
    assert_eq!(success["result"]["structuredContent"]["ok"], true);
    assert_eq!(
        success["result"]["structuredContent"]["report"]["approved"],
        true
    );
    assert!(approved_report.is_file());

    let mut changed = fs::read_to_string(&schematic).unwrap();
    changed = changed.replace("(property \"Value\" \"10k\"", "(property \"Value\" \"9k\"");
    fs::write(&schematic, changed).unwrap();
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "handoff-rejected",
            "method": "tools/call",
            "params": {
                "name": "verify_circuit_kicad_handoff",
                "arguments": {
                    "circuit_spec": spec,
                    "schematic": schematic,
                    "output": rejected_report,
                    "require_approved": true
                }
            }
        }),
    );
    let rejected = receive(&mut stdout);
    assert_eq!(rejected["id"], "handoff-rejected");
    assert_eq!(rejected["result"]["isError"], true);
    assert_eq!(rejected["result"]["structuredContent"]["ok"], false);
    assert_eq!(
        rejected["result"]["structuredContent"]["report"]["approved"],
        false
    );
    assert!(
        rejected["result"]["structuredContent"]["report"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "symbol_mismatch")
    );
    assert!(rejected_report.is_file());

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    fs::remove_dir_all(output).unwrap();
}

#[test]
fn stdio_server_board_binding_retains_rejected_report() {
    let output = temporary_directory("mcp-board-binding");
    fs::create_dir_all(&output).unwrap();
    let spec = output.join("circuit.json");
    let schematic = output.join("design.kicad_sch");
    let board = output.join("design.kicad_pcb");
    fs::write(&spec, HANDOFF_CIRCUIT_SPEC).unwrap();
    fs::write(&schematic, handoff_schematic()).unwrap();
    fs::write(&board, board_binding_board()).unwrap();
    let approved_report = output.join("approved.json");
    let rejected_report = output.join("rejected.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(&mut stdin, &mut stdout, json!("initialize-board-binding"));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "board-binding-success",
            "method": "tools/call",
            "params": {
                "name": "verify_circuit_kicad_board_binding",
                "arguments": {
                    "circuit_spec": spec,
                    "schematic": schematic,
                    "board": board,
                    "output": approved_report,
                    "require_approved": true
                }
            }
        }),
    );
    let success = receive(&mut stdout);
    assert_eq!(success["id"], "board-binding-success");
    assert_eq!(success["result"]["isError"], false);
    assert_eq!(
        success["result"]["structuredContent"]["report"]["approved"],
        true
    );
    let success_text = success["result"]["content"][0]["text"].as_str().unwrap();
    assert!(success_text.contains("board binding approved"));
    assert!(!success_text.contains("binding_sha256"));
    assert!(approved_report.is_file());

    let changed = fs::read_to_string(&board).unwrap().replace(
        "(fp_text value \"10k\" (at 0 1) (layer \"F.Fab\") hide)",
        "(fp_text value \"9k\" (at 0 1) (layer \"F.Fab\") hide)",
    );
    fs::write(&board, changed).unwrap();
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "board-binding-rejected",
            "method": "tools/call",
            "params": {
                "name": "verify_circuit_kicad_board_binding",
                "arguments": {
                    "circuit_spec": spec,
                    "schematic": schematic,
                    "board": board,
                    "output": rejected_report,
                    "require_approved": true
                }
            }
        }),
    );
    let rejected = receive(&mut stdout);
    assert_eq!(rejected["id"], "board-binding-rejected");
    assert_eq!(rejected["result"]["isError"], true);
    assert_eq!(
        rejected["result"]["structuredContent"]["report"]["approved"],
        false
    );
    let rejected_text = rejected["result"]["content"][0]["text"].as_str().unwrap();
    assert!(rejected_text.contains("board binding rejected"));
    assert!(!rejected_text.contains("binding_sha256"));
    assert!(rejected_report.is_file());

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    fs::remove_dir_all(output).unwrap();
}

#[test]
fn stdio_server_verifies_live_ai_schematic_approval_and_quorum() {
    let output = temporary_directory("mcp-live-ai-approval");
    fs::create_dir_all(&output).unwrap();
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/approved-empty.kicad_sch");
    let run_cli = |arguments: &[String]| {
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .args(arguments)
            .output()
            .unwrap()
    };
    let path = |value: &Path| value.display().to_string();

    // Build the schema-v1 request and response through the public CLI.  The
    // only files touched are inside this test's private temporary directory.
    let policy = output.join("electrical-policy.json");
    assert!(
        run_cli(&["electrical-policy".into(), "--output".into(), path(&policy),])
            .status
            .success()
    );
    let policy_value: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();

    let review = output.join("electrical-review.json");
    assert!(
        run_cli(&[
            "check-schematic".into(),
            path(&fixture),
            "--policy".into(),
            path(&policy),
            "--output".into(),
            path(&review),
            "--require-approved".into(),
        ])
        .status
        .success()
    );

    let private_key = output.join("approval.key");
    let public_key = output.join("approval.pub");
    assert!(
        run_cli(&[
            "approval-keygen".into(),
            "--private-key".into(),
            path(&private_key),
            "--public-key".into(),
            path(&public_key),
        ])
        .status
        .success()
    );

    let sample_pack =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/acme-policy-pack.json");
    let mut pack: Value = serde_json::from_slice(&fs::read(sample_pack).unwrap()).unwrap();
    pack["electrical_policy"] = policy_value;
    pack["ai_requirements"] = json!([{
        "id": "power",
        "text": "Power input treatment is intentional"
    }]);
    pack["require_simulation_evidence"] = false.into();
    pack["trusted_approval_keys"] = json!([{
        "signer_id": "ci-production",
        "public_key": fs::read_to_string(&public_key).unwrap().trim()
    }]);
    let policy_pack = output.join("policy-pack.json");
    fs::write(&policy_pack, serde_json::to_vec_pretty(&pack).unwrap()).unwrap();
    assert!(
        run_cli(&["validate-policy-pack".into(), path(&policy_pack),])
            .status
            .success()
    );

    let request = output.join("request.json");
    assert!(
        run_cli(&[
            "prepare-ai-review".into(),
            path(&fixture),
            "--electrical-review".into(),
            path(&review),
            "--policy-pack".into(),
            path(&policy_pack),
            "--output".into(),
            path(&request),
        ])
        .status
        .success()
    );
    let request_value: Value = serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
    assert_eq!(request_value["schema_version"], 1);

    let response = output.join("response.json");
    fs::write(
        &response,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "request_sha256": request_value["request_sha256"],
            "model": {
                "provider": "test-provider",
                "model": "schematic-reviewer",
                "version": "1"
            },
            "decision": "approve",
            "summary": "The deterministic review supports approval.",
            "requirements": [{
                "id": "power",
                "status": "pass",
                "rationale": "The electrical review is approved.",
                "evidence_refs": ["electrical-review"]
            }],
            "risks": []
        }))
        .unwrap(),
    )
    .unwrap();

    let equivalent_schematic = output.join("equivalent-live.kicad_sch");
    fs::write(
        &equivalent_schematic,
        format!("{}\n\n", fs::read_to_string(&fixture).unwrap()),
    )
    .unwrap();
    let mutated_schematic = output.join("mutated-live.kicad_sch");
    let mutated_source = fs::read_to_string(&fixture).unwrap().replace(
        "00000000-0000-0000-0000-000000000100",
        "00000000-0000-0000-0000-000000000101",
    );
    assert_ne!(mutated_source, fs::read_to_string(&fixture).unwrap());
    fs::write(&mutated_schematic, mutated_source).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("mcp-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let initialized = initialize(&mut stdin, &mut stdout, json!("live-ai-approval-init"));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    let approval = output.join("approval.json");
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "live-ai-approval-sign-success",
            "method": "tools/call",
            "params": {
                "name": "sign_schematic_approval",
                "arguments": {
                    "request": path(&request),
                    "response": path(&response),
                    "private_key": path(&private_key),
                    "signer_id": "ci-production",
                    "schematic": path(&equivalent_schematic),
                    "output": path(&approval),
                    "require_approved": true
                }
            }
        }),
    );
    let signed = receive(&mut stdout);
    assert_eq!(signed["id"], "live-ai-approval-sign-success");
    assert_eq!(signed["result"]["isError"], false);
    assert_eq!(signed["result"]["structuredContent"]["ok"], true);
    assert_eq!(
        signed["result"]["structuredContent"]["approval"]["approved"],
        true
    );
    assert!(approval.is_file());

    let failed_approval = output.join("failed-approval.json");
    let missing_private_key = output.join("missing-approval.key");
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "live-ai-approval-sign-mutated",
            "method": "tools/call",
            "params": {
                "name": "sign_schematic_approval",
                "arguments": {
                    "request": path(&request),
                    "response": path(&response),
                    "private_key": path(&missing_private_key),
                    "signer_id": "ci-production",
                    "schematic": path(&mutated_schematic),
                    "output": path(&failed_approval),
                    "require_approved": true
                }
            }
        }),
    );
    let sign_rejected = receive(&mut stdout);
    assert_eq!(sign_rejected["id"], "live-ai-approval-sign-mutated");
    assert_eq!(sign_rejected["result"]["isError"], true);
    assert_eq!(sign_rejected["result"]["structuredContent"]["ok"], false);
    assert_eq!(
        sign_rejected["result"]["structuredContent"]["approval"],
        Value::Null
    );
    assert!(!failed_approval.exists());
    assert!(
        sign_rejected["result"]["structuredContent"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("live schematic semantic document does not match")
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "live-ai-approval-success",
            "method": "tools/call",
            "params": {
                "name": "verify_schematic_approval",
                "arguments": {
                    "approval": path(&approval),
                    "request": path(&request),
                    "response": path(&response),
                    "policy_pack": path(&policy_pack),
                    "schematic": path(&equivalent_schematic),
                    "require_approved": true
                }
            }
        }),
    );
    let verified = receive(&mut stdout);
    assert_eq!(verified["id"], "live-ai-approval-success");
    assert_eq!(verified["result"]["isError"], false);
    assert_eq!(verified["result"]["structuredContent"]["ok"], true);
    assert_eq!(verified["result"]["structuredContent"]["verified"], true);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "live-ai-approval-mutated",
            "method": "tools/call",
            "params": {
                "name": "verify_schematic_approval",
                "arguments": {
                    "approval": path(&approval),
                    "request": path(&request),
                    "response": path(&response),
                    "policy_pack": path(&policy_pack),
                    "schematic": path(&mutated_schematic),
                    "require_approved": true
                }
            }
        }),
    );
    let rejected = receive(&mut stdout);
    assert_eq!(rejected["id"], "live-ai-approval-mutated");
    assert_eq!(rejected["result"]["isError"], true);
    assert_eq!(rejected["result"]["structuredContent"]["ok"], false);
    assert_eq!(rejected["result"]["structuredContent"]["verified"], false);
    assert!(
        rejected["result"]["structuredContent"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("live schematic semantic document does not match")
    );

    let quorum_report = output.join("quorum.json");
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": "live-ai-approval-quorum",
            "method": "tools/call",
            "params": {
                "name": "verify_schematic_approval_quorum",
                "arguments": {
                    "request": path(&request),
                    "approvals": [path(&approval)],
                    "responses": [path(&response)],
                    "policy_pack": path(&policy_pack),
                    "minimum_approvals": 1,
                    "minimum_distinct_providers": 1,
                    "minimum_distinct_models": 1,
                    "schematic": path(&equivalent_schematic),
                    "output": path(&quorum_report),
                    "require_quorum": true
                }
            }
        }),
    );
    let quorum = receive(&mut stdout);
    assert_eq!(quorum["id"], "live-ai-approval-quorum");
    assert_eq!(quorum["result"]["isError"], false);
    assert_eq!(quorum["result"]["structuredContent"]["ok"], true);
    assert_eq!(
        quorum["result"]["structuredContent"]["report"]["quorum_met"],
        true
    );
    assert!(quorum_report.is_file());
    let retained: Value = serde_json::from_slice(&fs::read(&quorum_report).unwrap()).unwrap();
    assert_eq!(retained["quorum_met"], true);

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();
    assert!(
        stderr_bytes.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    fs::remove_dir_all(output).unwrap();
}

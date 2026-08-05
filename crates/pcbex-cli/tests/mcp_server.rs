use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{ChildStdin, ChildStdout, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
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
fn fake_sleeping_native_kicad_drc_cli(directory: &Path) -> PathBuf {
    let path = directory.join("fake-drc-sleeping");
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
fn unix_process_exists(pid: i32) -> bool {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    unsafe { kill(pid, 0) == 0 }
}

#[cfg(unix)]
fn kill_unix_process_group(pid: i32) {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    let _ = unsafe { kill(-pid, SIGKILL) };
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
fn stdio_server_cancels_native_drc_replay_without_orphaning_kicad() {
    let output = temporary_directory("mcp-native-drc-replay-cancel");
    fs::create_dir_all(&output).unwrap();
    let approved_cli = fake_native_kicad_drc_cli(&output, "fake-drc-approved", false);
    let sleeping_cli = fake_sleeping_native_kicad_drc_cli(&output);
    let board = output.join("board.kicad_pcb");
    let report = output.join("retained.json");
    let pid_file = output.join("kicad.pid");
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

    let pid_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !pid_file.is_file() && std::time::Instant::now() < pid_deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(pid_file.is_file(), "sleeping KiCad child did not start");
    let pids = fs::read_to_string(&pid_file)
        .unwrap()
        .split_whitespace()
        .map(|value| value.parse::<i32>().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(pids.len(), 2, "fixture must record shell and sleep PIDs");
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

    let exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pids.iter().any(|pid| unix_process_exists(*pid))
        && std::time::Instant::now() < exit_deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let orphaned = pids
        .iter()
        .copied()
        .filter(|pid| unix_process_exists(*pid))
        .collect::<Vec<_>>();
    if !orphaned.is_empty() {
        // Keep a failing regression from leaking the deliberately long-lived
        // fixture into the test host.
        kill_unix_process_group(pids[0]);
    }
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

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{ChildStdin, ChildStdout, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

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

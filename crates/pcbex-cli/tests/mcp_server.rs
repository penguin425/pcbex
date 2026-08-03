use serde_json::{Value, json};
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

fn temporary_directory(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pcbex-{name}-{}-{unique}", std::process::id()))
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

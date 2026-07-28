use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

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

    let messages = [
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
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
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
                }
            }
        }),
    ];
    {
        let stdin = child.stdin.as_mut().unwrap();
        for message in messages {
            serde_json::to_writer(&mut *stdin, &message).unwrap();
            stdin.write_all(b"\n").unwrap();
        }
    }
    drop(child.stdin.take());
    let process = child.wait_with_output().unwrap();
    assert!(process.status.success());
    assert!(
        process.stderr.is_empty(),
        "MCP server stderr: {}",
        String::from_utf8_lossy(&process.stderr)
    );

    let responses = String::from_utf8(process.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 2, "notifications must not get responses");
    assert_eq!(responses[0]["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        responses[0]["result"]["capabilities"]["tools"],
        json!({
            "listChanged": false
        })
    );
    assert_eq!(responses[1]["id"], "analysis");
    assert_eq!(responses[1]["result"]["isError"], true);
    assert_eq!(
        responses[1]["result"]["structuredContent"]["manifest"]["configuration"]["dfm_profile"]["id"],
        "jlcpcb-standard-2layer-1oz-v1"
    );
    assert!(output.join("run.json").is_file());
    assert!(output.join("report.sarif").is_file());

    fs::remove_dir_all(output).unwrap();
}

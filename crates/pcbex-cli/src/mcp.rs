use anyhow::{Context, Result};
use pcbex_core::dfm_profiles;
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeSet,
    env,
    io::{self, BufRead, Write},
    path::Path,
    process::Command,
};

const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Lifecycle {
    #[default]
    Uninitialized,
    Initializing,
    Ready,
}

pub fn serve_stdio() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut server = McpServer::default();
    for line in stdin.lock().lines() {
        let line = line.context("reading MCP stdio request")?;
        if line.is_empty() {
            continue;
        }
        if let Some(response) = server.handle_line(&line) {
            serde_json::to_writer(&mut stdout, &response)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct McpServer {
    lifecycle: Lifecycle,
}

impl McpServer {
    fn handle_line(&mut self, line: &str) -> Option<Value> {
        let message = match serde_json::from_str::<Value>(line) {
            Ok(message) => message,
            Err(error) => {
                return Some(error_response(
                    Value::Null,
                    -32700,
                    "Parse error",
                    Some(json!({"detail": error.to_string()})),
                ));
            }
        };
        self.handle_message(message)
    }

    fn handle_message(&mut self, message: Value) -> Option<Value> {
        let Some(object) = message.as_object() else {
            return Some(error_response(Value::Null, -32600, "Invalid Request", None));
        };
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(error_response(
                request_id(object),
                -32600,
                "Invalid Request",
                Some(json!({"detail": "jsonrpc must be \"2.0\""})),
            ));
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Some(error_response(
                request_id(object),
                -32600,
                "Invalid Request",
                Some(json!({"detail": "method must be a string"})),
            ));
        };
        let id = object.get("id").cloned();
        if id
            .as_ref()
            .is_some_and(|id| !(id.is_string() || id.is_i64() || id.is_u64()) || id.is_null())
        {
            return Some(error_response(
                Value::Null,
                -32600,
                "Invalid Request",
                Some(json!({"detail": "request id must be a string or integer"})),
            ));
        }

        if id.is_none() {
            self.handle_notification(method);
            return None;
        }
        let id = id.unwrap();
        match method {
            "initialize" => Some(self.initialize(id, object.get("params"))),
            "ping" => Some(success_response(id, json!({}))),
            _ if self.lifecycle != Lifecycle::Ready => {
                Some(error_response(id, -32002, "Server not initialized", None))
            }
            "tools/list" => Some(success_response(id, json!({"tools": tool_definitions()}))),
            "tools/call" => Some(match call_tool(object.get("params")) {
                Ok(result) => success_response(id, result),
                Err(error) => error_response(id, -32602, "Invalid tool request", Some(error)),
            }),
            _ => Some(error_response(id, -32601, "Method not found", None)),
        }
    }

    fn initialize(&mut self, id: Value, params: Option<&Value>) -> Value {
        if self.lifecycle != Lifecycle::Uninitialized {
            return error_response(id, -32600, "Server already initialized", None);
        }
        let requested = params
            .and_then(Value::as_object)
            .and_then(|params| params.get("protocolVersion"))
            .and_then(Value::as_str);
        let Some(requested) = requested else {
            return error_response(
                id,
                -32602,
                "Invalid initialize parameters",
                Some(json!({"detail": "protocolVersion must be a string"})),
            );
        };
        let negotiated = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
            requested
        } else {
            LATEST_PROTOCOL_VERSION
        };
        self.lifecycle = Lifecycle::Initializing;
        success_response(
            id,
            json!({
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {
                    "name": "pcbex",
                    "title": "pcbex hardware design engine",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Deterministic KiCad analysis, routing, DFM, and comparison tools",
                    "websiteUrl": "https://github.com/penguin425/pcbex"
                },
                "instructions": "Use explicit input and output paths. Analyze before routing, retain generated bundles for review, and ask the user before overwriting hardware files."
            }),
        )
    }

    fn handle_notification(&mut self, method: &str) {
        if method == "notifications/initialized" && self.lifecycle == Lifecycle::Initializing {
            self.lifecycle = Lifecycle::Ready;
        }
    }
}

fn request_id(object: &Map<String, Value>) -> Value {
    object.get("id").cloned().unwrap_or(Value::Null)
}

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_response(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({"code": code, "message": message});
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}

fn tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "list_dfm_profiles",
            "List fabrication profiles",
            "List revisioned built-in fabrication profiles and their exact rules.",
            json!({"type": "object", "additionalProperties": false}),
            true,
            false,
        ),
        tool(
            "analyze_kicad",
            "Analyze KiCad board",
            "Analyze a .kicad_pcb file and write a complete JSON, SVG, SARIF, Markdown, and provenance bundle.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "output_dir"],
                "properties": {
                    "input": {"type": "string"},
                    "output_dir": {"type": "string"},
                    "project": {"type": "string"},
                    "rules_file": {"type": "string"},
                    "fab": {"type": "string"},
                    "fail_on_violations": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
        ),
        tool(
            "compare_analysis",
            "Compare analysis bundles",
            "Compare baseline and current analysis bundles, write deltas and SARIF, and optionally gate regressions.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["baseline_dir", "current_dir", "output_dir"],
                "properties": {
                    "baseline_dir": {"type": "string"},
                    "current_dir": {"type": "string"},
                    "output_dir": {"type": "string"},
                    "fail_on_regressions": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
        ),
        tool(
            "route_kicad",
            "Route KiCad board",
            "Route a placed .kicad_pcb file and write a separate routed board.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "output"],
                "properties": {
                    "input": {"type": "string"},
                    "output": {"type": "string"},
                    "project": {"type": "string"},
                    "rules_file": {"type": "string"},
                    "fab": {"type": "string"},
                    "svg": {"type": "string"},
                    "json_output": {"type": "string"},
                    "allow_unrouted": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
        ),
    ]
}

fn tool(
    name: &str,
    title: &str,
    description: &str,
    input_schema: Value,
    read_only: bool,
    destructive: bool,
) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": input_schema,
        "outputSchema": {
            "type": "object",
            "required": ["ok"],
            "properties": {"ok": {"type": "boolean"}}
        },
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

fn call_tool(params: Option<&Value>) -> std::result::Result<Value, Value> {
    let params = params
        .and_then(Value::as_object)
        .ok_or_else(|| json!({"detail": "params must be an object"}))?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| json!({"detail": "tool name must be a string"}))?;
    let arguments = params
        .get("arguments")
        .map(|arguments| {
            arguments
                .as_object()
                .ok_or_else(|| json!({"detail": "arguments must be an object"}))
        })
        .transpose()?
        .cloned()
        .unwrap_or_default();

    let structured = match name {
        "list_dfm_profiles" => {
            reject_unknown(&arguments, &[])?;
            json!({"ok": true, "profiles": dfm_profiles()})
        }
        "analyze_kicad" => analyze_kicad(arguments)?,
        "compare_analysis" => compare_analysis(arguments)?,
        "route_kicad" => route_kicad(arguments)?,
        _ => return Err(json!({"detail": format!("unknown tool {name:?}")})),
    };
    let is_error = structured.get("ok").and_then(Value::as_bool) == Some(false);
    let text =
        serde_json::to_string_pretty(&structured).expect("structured tool result serializes");
    Ok(json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": is_error
    }))
}

fn analyze_kicad(arguments: Map<String, Value>) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "output_dir",
            "project",
            "rules_file",
            "fab",
            "fail_on_violations",
        ],
    )?;
    let input = required_string(&arguments, "input")?;
    let output_dir = required_string(&arguments, "output_dir")?;
    let mut command = vec![
        "analyze-kicad".to_string(),
        input,
        "--output-dir".to_string(),
        output_dir.clone(),
    ];
    optional_option(&arguments, "project", "--project", &mut command)?;
    optional_option(&arguments, "rules_file", "--rules-file", &mut command)?;
    optional_option(&arguments, "fab", "--fab", &mut command)?;
    optional_flag(
        &arguments,
        "fail_on_violations",
        "--fail-on-violations",
        &mut command,
    )?;
    let execution = execute(&command)?;
    let manifest = read_json_if_present(&Path::new(&output_dir).join("run.json"));
    Ok(execution_result(
        execution,
        json!({"artifact_dir": output_dir, "manifest": manifest}),
    ))
}

fn compare_analysis(arguments: Map<String, Value>) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "baseline_dir",
            "current_dir",
            "output_dir",
            "fail_on_regressions",
        ],
    )?;
    let baseline = required_string(&arguments, "baseline_dir")?;
    let current = required_string(&arguments, "current_dir")?;
    let output_dir = required_string(&arguments, "output_dir")?;
    let mut command = vec![
        "compare-analysis".to_string(),
        baseline,
        current,
        "--output-dir".to_string(),
        output_dir.clone(),
    ];
    optional_flag(
        &arguments,
        "fail_on_regressions",
        "--fail-on-regressions",
        &mut command,
    )?;
    let execution = execute(&command)?;
    let manifest = read_json_if_present(&Path::new(&output_dir).join("run.json"));
    Ok(execution_result(
        execution,
        json!({"artifact_dir": output_dir, "manifest": manifest}),
    ))
}

fn route_kicad(arguments: Map<String, Value>) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "output",
            "project",
            "rules_file",
            "fab",
            "svg",
            "json_output",
            "allow_unrouted",
        ],
    )?;
    let input = required_string(&arguments, "input")?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "route-kicad".to_string(),
        input,
        "--output".to_string(),
        output.clone(),
    ];
    optional_option(&arguments, "project", "--project", &mut command)?;
    optional_option(&arguments, "rules_file", "--rules-file", &mut command)?;
    optional_option(&arguments, "fab", "--fab", &mut command)?;
    optional_option(&arguments, "svg", "--svg", &mut command)?;
    optional_option(&arguments, "json_output", "--json-output", &mut command)?;
    optional_flag(
        &arguments,
        "allow_unrouted",
        "--allow-unrouted",
        &mut command,
    )?;
    let execution = execute(&command)?;
    Ok(execution_result(execution, json!({"output": output})))
}

struct Execution {
    success: bool,
    exit_code: Option<i32>,
    stderr: String,
}

fn execute(arguments: &[String]) -> std::result::Result<Execution, Value> {
    let executable = env::current_exe()
        .map_err(|error| json!({"detail": format!("locating pcbex executable: {error}")}))?;
    let output = Command::new(executable)
        .args(arguments)
        .output()
        .map_err(|error| json!({"detail": format!("starting pcbex tool process: {error}")}))?;
    Ok(Execution {
        success: output.status.success(),
        exit_code: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn execution_result(execution: Execution, fields: Value) -> Value {
    let mut result = fields.as_object().cloned().unwrap_or_default();
    result.insert("ok".into(), Value::Bool(execution.success));
    result.insert(
        "exit_code".into(),
        execution.exit_code.map_or(Value::Null, Value::from),
    );
    if !execution.stderr.is_empty() {
        result.insert("message".into(), Value::String(execution.stderr));
    }
    Value::Object(result)
}

fn read_json_if_present(path: &Path) -> Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|source| serde_json::from_str(&source).ok())
        .unwrap_or(Value::Null)
}

fn required_string(
    arguments: &Map<String, Value>,
    name: &str,
) -> std::result::Result<String, Value> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| json!({"detail": format!("{name} must be a non-empty string")}))
}

fn optional_option(
    arguments: &Map<String, Value>,
    name: &str,
    option: &str,
    command: &mut Vec<String>,
) -> std::result::Result<(), Value> {
    if let Some(value) = arguments.get(name) {
        let value = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| json!({"detail": format!("{name} must be a non-empty string")}))?;
        command.push(option.to_string());
        command.push(value.to_string());
    }
    Ok(())
}

fn optional_flag(
    arguments: &Map<String, Value>,
    name: &str,
    option: &str,
    command: &mut Vec<String>,
) -> std::result::Result<(), Value> {
    if let Some(value) = arguments.get(name) {
        let enabled = value
            .as_bool()
            .ok_or_else(|| json!({"detail": format!("{name} must be a boolean")}))?;
        if enabled {
            command.push(option.to_string());
        }
    }
    Ok(())
}

fn reject_unknown(
    arguments: &Map<String, Value>,
    allowed: &[&str],
) -> std::result::Result<(), Value> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    let unknown = arguments
        .keys()
        .filter(|key| !allowed.contains(key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(json!({"detail": format!("unknown argument(s): {}", unknown.join(", "))}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: i64, method: &str, params: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    }

    fn ready_server() -> McpServer {
        let mut server = McpServer::default();
        let initialized = server.handle_message(request(
            1,
            "initialize",
            json!({
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"}
            }),
        ));
        assert_eq!(
            initialized.unwrap()["result"]["protocolVersion"],
            LATEST_PROTOCOL_VERSION
        );
        assert!(
            server
                .handle_message(json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized"
                }))
                .is_none()
        );
        server
    }

    #[test]
    fn negotiates_lifecycle_and_lists_tools() {
        let mut server = McpServer::default();
        let premature = server.handle_message(request(1, "tools/list", json!({})));
        assert_eq!(premature.unwrap()["error"]["code"], -32002);

        let mut server = ready_server();
        let response = server
            .handle_message(request(2, "tools/list", json!({})))
            .unwrap();
        assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 4);
        assert_eq!(
            response["result"]["tools"][0]["annotations"]["readOnlyHint"],
            true
        );
    }

    #[test]
    fn returns_structured_profiles_and_tool_errors() {
        let mut server = ready_server();
        let response = server
            .handle_message(request(
                2,
                "tools/call",
                json!({"name": "list_dfm_profiles", "arguments": {}}),
            ))
            .unwrap();
        assert_eq!(
            response["result"]["structuredContent"]["profiles"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let invalid = server
            .handle_message(request(
                3,
                "tools/call",
                json!({"name": "analyze_kicad", "arguments": {"input": 3}}),
            ))
            .unwrap();
        assert_eq!(invalid["error"]["code"], -32602);
    }

    #[test]
    fn rejects_batches_and_never_responds_to_notifications() {
        let mut server = ready_server();
        assert_eq!(
            server.handle_message(json!([])).unwrap()["error"]["code"],
            -32600
        );
        assert!(
            server
                .handle_message(json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": 1}
                }))
                .is_none()
        );
    }
}

use anyhow::{Context, Result};
use pcbex_core::dfm_profiles;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    io::{self, BufRead, Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_TASK_TTL_MS: u64 = 10 * 60 * 1_000;
const MAX_TASK_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const TASK_POLL_INTERVAL_MS: u64 = 250;
const MAX_TASKS: usize = 32;
const MAX_CONCURRENT_TASKS: usize = 4;
static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

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

struct McpServer {
    lifecycle: Lifecycle,
    protocol_version: String,
    tasks: BTreeMap<String, Arc<TaskRecord>>,
    active_tasks: Arc<AtomicUsize>,
}

impl Default for McpServer {
    fn default() -> Self {
        Self {
            lifecycle: Lifecycle::default(),
            protocol_version: String::new(),
            tasks: BTreeMap::new(),
            active_tasks: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        for task in self.tasks.values() {
            task.cancellation.store(true, Ordering::SeqCst);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.active_tasks.load(Ordering::SeqCst) != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

struct TaskRecord {
    task_id: String,
    created_at: String,
    created: Instant,
    ttl_ms: u64,
    cancellation: Arc<AtomicBool>,
    state: Mutex<TaskState>,
    changed: Condvar,
}

struct TaskState {
    status: TaskStatus,
    status_message: String,
    last_updated_at: String,
    result: Option<TaskOutcome>,
}

#[derive(Clone)]
enum TaskOutcome {
    Result(Value),
    InvalidRequest(Value),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn is_terminal(self) -> bool {
        self != Self::Working
    }
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
            "tools/list" => Some(success_response(
                id,
                json!({"tools": tool_definitions(self.tasks_supported())}),
            )),
            "tools/call" => Some(self.call_tool_request(id, object.get("params"))),
            "tasks/get" if self.tasks_supported() => Some(self.get_task(id, object.get("params"))),
            "tasks/result" if self.tasks_supported() => {
                Some(self.get_task_result(id, object.get("params")))
            }
            "tasks/list" if self.tasks_supported() => {
                Some(self.list_tasks(id, object.get("params")))
            }
            "tasks/cancel" if self.tasks_supported() => {
                Some(self.cancel_task(id, object.get("params")))
            }
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
        self.protocol_version = negotiated.to_string();
        let capabilities = if negotiated == LATEST_PROTOCOL_VERSION {
            json!({
                "tools": {"listChanged": false},
                "tasks": {
                    "list": {},
                    "cancel": {},
                    "requests": {"tools": {"call": {}}}
                }
            })
        } else {
            json!({"tools": {"listChanged": false}})
        };
        success_response(
            id,
            json!({
                "protocolVersion": negotiated,
                "capabilities": capabilities,
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

    fn tasks_supported(&self) -> bool {
        self.protocol_version == LATEST_PROTOCOL_VERSION
    }

    fn call_tool_request(&mut self, id: Value, params: Option<&Value>) -> Value {
        let wants_task = params
            .and_then(Value::as_object)
            .is_some_and(|params| params.contains_key("task"));
        if wants_task && self.tasks_supported() {
            return self.create_task(id, params);
        }
        match call_tool(params, None) {
            Ok(result) => success_response(id, result),
            Err(error) => error_response(id, -32602, "Invalid tool request", Some(error)),
        }
    }

    fn create_task(&mut self, id: Value, params: Option<&Value>) -> Value {
        self.remove_expired_tasks();
        let Some(params) = params.and_then(Value::as_object) else {
            return error_response(id, -32602, "Invalid tool request", None);
        };
        let name = params.get("name").and_then(Value::as_str);
        if !matches!(
            name,
            Some(
                "analyze_kicad"
                    | "compare_analysis"
                    | "record_manufacturing_feedback"
                    | "compare_manufacturing_feedback"
                    | "compare_schematics"
                    | "route_schematic_reviewers"
                    | "route_kicad"
            )
        ) {
            return error_response(
                id,
                -32601,
                "Tool does not support task execution",
                name.map(|name| json!({"tool": name})),
            );
        }
        let task_options = match params.get("task").and_then(Value::as_object) {
            Some(task) => task,
            None => {
                return error_response(
                    id,
                    -32602,
                    "Invalid task parameters",
                    Some(json!({"detail": "task must be an object"})),
                );
            }
        };
        if task_options.keys().any(|key| key != "ttl") {
            return error_response(
                id,
                -32602,
                "Invalid task parameters",
                Some(json!({"detail": "task only accepts ttl"})),
            );
        }
        let ttl_ms = match task_options.get("ttl") {
            None | Some(Value::Null) => DEFAULT_TASK_TTL_MS,
            Some(value) => match value.as_u64().filter(|ttl| *ttl > 0) {
                Some(ttl) if ttl <= MAX_TASK_TTL_MS => ttl,
                _ => {
                    return error_response(
                        id,
                        -32602,
                        "Invalid task parameters",
                        Some(json!({
                            "detail": format!("ttl must be between 1 and {MAX_TASK_TTL_MS} milliseconds")
                        })),
                    );
                }
            },
        };
        if self.tasks.len() >= MAX_TASKS {
            return error_response(
                id,
                -32000,
                "Task capacity reached",
                Some(json!({"maximumTasks": MAX_TASKS})),
            );
        }
        if self
            .active_tasks
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                (active < MAX_CONCURRENT_TASKS).then_some(active + 1)
            })
            .is_err()
        {
            return error_response(
                id,
                -32000,
                "Concurrent task capacity reached",
                Some(json!({"maximumConcurrentTasks": MAX_CONCURRENT_TASKS})),
            );
        }

        let sequence = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
        let task_id = format!("pcbex-{}-{sequence}", std::process::id());
        let created_at = iso8601_now();
        let record = Arc::new(TaskRecord {
            task_id: task_id.clone(),
            created_at: created_at.clone(),
            created: Instant::now(),
            ttl_ms,
            cancellation: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(TaskState {
                status: TaskStatus::Working,
                status_message: "pcbex tool process is running".to_string(),
                last_updated_at: created_at,
                result: None,
            }),
            changed: Condvar::new(),
        });
        // CreateTaskResult must describe the initial state even when a very
        // short operation reaches a terminal state before this method returns.
        let create_result = success_response(id, json!({"task": task_json(&record)}));
        self.tasks.insert(task_id, Arc::clone(&record));
        let params = Value::Object(params.clone());
        let active_tasks = Arc::clone(&self.active_tasks);
        thread::spawn(move || {
            let outcome = call_tool(Some(&params), Some(&record.cancellation));
            let mut state = record.state.lock().expect("task state lock");
            if state.status == TaskStatus::Working {
                match outcome {
                    Ok(result) => {
                        state.status =
                            if result.get("isError").and_then(Value::as_bool) == Some(true) {
                                TaskStatus::Failed
                            } else {
                                TaskStatus::Completed
                            };
                        state.status_message = if state.status == TaskStatus::Completed {
                            "pcbex tool process completed".to_string()
                        } else {
                            "pcbex tool process reported an error".to_string()
                        };
                        state.result = Some(TaskOutcome::Result(result));
                    }
                    Err(error) => {
                        state.status = TaskStatus::Failed;
                        state.status_message = "invalid pcbex tool request".to_string();
                        state.result = Some(TaskOutcome::InvalidRequest(error));
                    }
                }
                state.last_updated_at = iso8601_now();
            }
            record.changed.notify_all();
            active_tasks.fetch_sub(1, Ordering::SeqCst);
        });
        create_result
    }

    fn get_task(&mut self, id: Value, params: Option<&Value>) -> Value {
        let Some(record) = self.find_task(id.clone(), params) else {
            return invalid_task_response(id);
        };
        success_response(id, task_json(&record))
    }

    fn get_task_result(&mut self, id: Value, params: Option<&Value>) -> Value {
        let Some(record) = self.find_task(id.clone(), params) else {
            return invalid_task_response(id);
        };
        let mut state = record.state.lock().expect("task state lock");
        while !state.status.is_terminal() {
            state = record.changed.wait(state).expect("task state wait");
        }
        let outcome = state.result.clone().unwrap_or_else(|| {
            TaskOutcome::Result(tool_error_result(
                json!({"detail": "task was cancelled before producing a result"}),
            ))
        });
        let mut result = match outcome {
            TaskOutcome::Result(result) => result,
            TaskOutcome::InvalidRequest(error) => {
                return error_response(id, -32602, "Invalid tool request", Some(error));
            }
        };
        let object = result
            .as_object_mut()
            .expect("tool results are always JSON objects");
        object.insert(
            "_meta".to_string(),
            json!({"io.modelcontextprotocol/related-task": {"taskId": record.task_id}}),
        );
        success_response(id, result)
    }

    fn list_tasks(&mut self, id: Value, params: Option<&Value>) -> Value {
        self.remove_expired_tasks();
        let valid = params.and_then(Value::as_object).is_none_or(|params| {
            params.is_empty() || (params.len() == 1 && params.contains_key("_meta"))
        });
        if !valid {
            return error_response(
                id,
                -32602,
                "Invalid task list parameters",
                Some(
                    json!({"detail": "pagination cursors are not needed for the bounded task list"}),
                ),
            );
        }
        let tasks = self
            .tasks
            .values()
            .map(|task| task_json(task))
            .collect::<Vec<_>>();
        success_response(id, json!({"tasks": tasks}))
    }

    fn cancel_task(&mut self, id: Value, params: Option<&Value>) -> Value {
        let Some(record) = self.find_task(id.clone(), params) else {
            return invalid_task_response(id);
        };
        let mut state = record.state.lock().expect("task state lock");
        if state.status != TaskStatus::Working {
            return error_response(
                id,
                -32602,
                "Task cannot be cancelled",
                Some(json!({"taskId": record.task_id, "status": state.status.as_str()})),
            );
        }
        record.cancellation.store(true, Ordering::SeqCst);
        state.status = TaskStatus::Cancelled;
        state.status_message = "task cancelled by client".to_string();
        state.last_updated_at = iso8601_now();
        state.result = Some(TaskOutcome::Result(tool_error_result(
            json!({"detail": "task cancelled by client"}),
        )));
        record.changed.notify_all();
        drop(state);
        success_response(id, task_json(&record))
    }

    fn find_task(&mut self, _id: Value, params: Option<&Value>) -> Option<Arc<TaskRecord>> {
        self.remove_expired_tasks();
        let task_id = params
            .and_then(Value::as_object)
            .filter(|params| {
                params
                    .keys()
                    .all(|key| matches!(key.as_str(), "taskId" | "_meta"))
            })
            .and_then(|params| params.get("taskId"))
            .and_then(Value::as_str)?;
        self.tasks.get(task_id).cloned()
    }

    fn remove_expired_tasks(&mut self) {
        self.tasks
            .retain(|_, record| record.created.elapsed() < Duration::from_millis(record.ttl_ms));
    }
}

fn task_json(record: &TaskRecord) -> Value {
    let state = record.state.lock().expect("task state lock");
    json!({
        "taskId": record.task_id,
        "status": state.status.as_str(),
        "statusMessage": state.status_message,
        "createdAt": record.created_at,
        "lastUpdatedAt": state.last_updated_at,
        "ttl": record.ttl_ms,
        "pollInterval": TASK_POLL_INTERVAL_MS
    })
}

fn invalid_task_response(id: Value) -> Value {
    error_response(
        id,
        -32602,
        "Invalid task",
        Some(json!({"detail": "taskId must identify a retained task"})),
    )
}

fn tool_error_result(error: Value) -> Value {
    let structured = json!({"ok": false, "error": error});
    let text = serde_json::to_string_pretty(&structured).expect("structured tool error serializes");
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": true
    })
}

fn iso8601_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let shifted_days = days + 719_468;
    let era = shifted_days.div_euclid(146_097);
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
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

fn tool_definitions(tasks_supported: bool) -> Vec<Value> {
    vec![
        tool(
            "list_dfm_profiles",
            "List fabrication profiles",
            "List revisioned built-in fabrication profiles and their exact rules.",
            json!({"type": "object", "additionalProperties": false}),
            true,
            false,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_policy_pack",
            "Verify organization policy pack",
            "Verify a signed organization policy pack against a separately trusted Ed25519 public key and extract the authenticated pack.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "public_key", "output"],
                "properties": {
                    "input": {"type": "string"},
                    "public_key": {"type": "string"},
                    "baseline_state": {"type": "string"},
                    "state_output": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
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
                    "fab_profile": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "fail_on_violations": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
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
            tasks_supported.then_some("optional"),
        ),
        tool(
            "record_manufacturing_feedback",
            "Record manufacturing feedback",
            "Bind fabrication findings and raw inspection artifacts to the exact board and analyze-kicad manifest.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["declaration", "analysis_dir", "board", "artifacts", "output"],
                "properties": {
                    "declaration": {"type": "string"},
                    "analysis_dir": {"type": "string"},
                    "board": {"type": "string"},
                    "artifacts": {
                        "type": "array", "minItems": 1,
                        "items": {"type": "string"}
                    },
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "sarif_output": {"type": "string"},
                    "require_passed": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "compare_manufacturing_feedback",
            "Compare manufacturing feedback",
            "Compare accepted and current bound fabrication feedback and gate new or escalated findings.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["baseline", "current", "output"],
                "properties": {
                    "baseline": {"type": "string"},
                    "current": {"type": "string"},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "sarif_output": {"type": "string"},
                    "fail_on_regressions": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "compare_schematics",
            "Compare KiCad schematics",
            "Compare two .kicad_sch files by symbols, pins, attributes, and electrical connectivity while ignoring drawing-only changes.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["baseline", "current", "output"],
                "properties": {
                    "baseline": {"type": "string"},
                    "current": {"type": "string"},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "sarif_output": {"type": "string"},
                    "require_no_review": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "route_schematic_reviewers",
            "Route AI schematic reviewers",
            "Recompute semantic schematic changes and deterministically assign every change to policy-selected specialist or fallback AI reviewer profiles.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["baseline", "current", "routing_policy", "output"],
                "properties": {
                    "baseline": {"type": "string"},
                    "current": {"type": "string"},
                    "routing_policy": {"type": "string"},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_routed": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
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
                    "fab_profile": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "svg": {"type": "string"},
                    "json_output": {"type": "string"},
                    "allow_unrouted": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "prepare_schematic_review",
            "Prepare AI schematic review",
            "Recompute and bind schematic, electrical, simulation, and requirement evidence into a review request.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "electrical_review", "output"],
                "oneOf": [
                    {"required": ["requirements"]},
                    {"required": ["policy_pack"]}
                ],
                "properties": {
                    "input": {"type": "string"},
                    "electrical_review": {"type": "string"},
                    "policy": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "simulation_evidence": {
                        "type": "array", "items": {"type": "string"}
                    },
                    "requirements": {
                        "type": "array", "minItems": 1, "items": {"type": "string"}
                    },
                    "allow_no_simulation": {"type": "boolean", "default": false},
                    "output": {"type": "string"},
                    "session_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_schematic_approval",
            "Sign AI schematic approval",
            "Evaluate a bound AI response and create an Ed25519-signed approval or rejection. Requires an explicit private-key path.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "request", "response", "private_key", "signer_id", "output"
                ],
                "properties": {
                    "request": {"type": "string"},
                    "response": {"type": "string"},
                    "private_key": {"type": "string"},
                    "signer_id": {"type": "string"},
                    "session": {"type": "string"},
                    "output": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_schematic_approval",
            "Verify AI schematic approval",
            "Strictly verify an Ed25519 approval against its exact request and AI response.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["approval", "request", "response"],
                "oneOf": [
                    {"required": ["public_key"]},
                    {"required": ["policy_pack"]}
                ],
                "properties": {
                    "approval": {"type": "string"},
                    "request": {"type": "string"},
                    "response": {"type": "string"},
                    "public_key": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "session": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            true,
            false,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_schematic_approval_quorum",
            "Verify AI schematic approval quorum",
            "Verify independent signed reviews against one bound request and enforce approval, provider, and model thresholds.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "request", "approvals", "responses", "policy_pack", "output"
                ],
                "properties": {
                    "request": {"type": "string"},
                    "approvals": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "responses": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "policy_pack": {"type": "string"},
                    "minimum_approvals": {
                        "type": "integer", "minimum": 1, "maximum": 100, "default": 2
                    },
                    "minimum_distinct_providers": {
                        "type": "integer", "minimum": 1, "maximum": 100, "default": 2
                    },
                    "minimum_distinct_models": {
                        "type": "integer", "minimum": 1, "maximum": 100, "default": 2
                    },
                    "baseline_schematic": {"type": "string"},
                    "current_schematic": {"type": "string"},
                    "reviewer_routing_policy": {"type": "string"},
                    "session": {"type": "string"},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_quorum": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_human_schematic_escalation",
            "Sign human schematic escalation",
            "Sign an explicit human approve/reject decision bound to eligible time-bound AI needs-human evidence.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "request", "session", "ai_quorum", "private_key", "signer_id",
                    "decision", "reason", "ticket", "output"
                ],
                "properties": {
                    "request": {"type": "string"},
                    "session": {"type": "string"},
                    "ai_quorum": {"type": "string"},
                    "private_key": {"type": "string"},
                    "signer_id": {"type": "string"},
                    "decision": {"enum": ["approve", "reject"]},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "ticket": {"type": "string", "minLength": 1, "maxLength": 256},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_human_schematic_escalation",
            "Verify human schematic escalation",
            "Verify trusted, distinct human decisions and require dual control for eligible AI needs-human evidence.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "request", "session", "ai_quorum", "escalations", "policy_pack",
                    "output"
                ],
                "properties": {
                    "request": {"type": "string"},
                    "session": {"type": "string"},
                    "ai_quorum": {"type": "string"},
                    "escalations": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "policy_pack": {"type": "string"},
                    "minimum_approvals": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "init_approval_transparency_log",
            "Initialize approval transparency log",
            "Create an empty append-only approval evidence log.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["log_id", "output"],
                "properties": {
                    "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "append_approval_transparency_log",
            "Append approval transparency event",
            "Normalize one supported approval artifact and append it to a new hash-chained log snapshot.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["log", "artifact", "kind", "output"],
                "properties": {
                    "log": {"type": "string"},
                    "artifact": {"type": "string"},
                    "kind": {"enum": [
                        "signed-ai-approval", "ai-quorum-report",
                        "signed-human-escalation", "human-escalation-report",
                        "signed-policy-pack"
                    ]},
                    "recorded_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_log",
            "Sign approval-log checkpoint",
            "Create an Ed25519 checkpoint for the exact approval log head and complete log digest.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["log", "private_key", "signer_id", "output"],
                "properties": {
                    "log": {"type": "string"},
                    "private_key": {"type": "string"},
                    "signer_id": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_approval_transparency_log",
            "Verify approval transparency log",
            "Verify the complete hash chain and a trusted Ed25519 checkpoint.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["log", "checkpoint", "public_key", "output"],
                "properties": {
                    "log": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "witness_approval_transparency_log",
            "Witness approval-log checkpoint",
            "Independently sign the exact normalized checkpoint observed by a witness.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["checkpoint", "private_key", "witness_id", "output"],
                "properties": {
                    "checkpoint": {"type": "string"},
                    "private_key": {"type": "string"},
                    "witness_id": {"type": "string"},
                    "observed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_approval_transparency_witnesses",
            "Verify approval-log witness quorum",
            "Verify distinct trusted witness signatures over one exact checkpoint and enforce a threshold.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["checkpoint", "witnesses", "public_keys", "output"],
                "properties": {
                    "checkpoint": {"type": "string"},
                    "witnesses": {"type": "array", "minItems": 1, "maxItems": 64, "items": {"type": "string"}},
                    "public_keys": {"type": "array", "minItems": 1, "maxItems": 64, "items": {"type": "string"}},
                    "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": 64, "default": 2},
                    "output": {"type": "string"},
                    "require_quorum": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "request_remote_approval_transparency_witness",
            "Request remote approval-log witness",
            "POST one checkpoint to a bounded HTTPS witness service and verify its response against a trusted key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["checkpoint", "endpoint", "public_key", "output", "receipt_output"],
                "properties": {
                    "checkpoint": {"type": "string"},
                    "endpoint": {"type": "string", "pattern": "^https://"},
                    "public_key": {"type": "string"},
                    "bearer_token_env": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600, "default": 30},
                    "output": {"type": "string"},
                    "receipt_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
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
    task_support: Option<&str>,
) -> Value {
    let mut definition = json!({
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
    });
    if let Some(task_support) = task_support {
        definition["execution"] = json!({"taskSupport": task_support});
    }
    definition
}

fn call_tool(
    params: Option<&Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
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
        "verify_policy_pack" => verify_policy_pack(arguments, cancellation)?,
        "analyze_kicad" => analyze_kicad(arguments, cancellation)?,
        "compare_analysis" => compare_analysis(arguments, cancellation)?,
        "record_manufacturing_feedback" => record_manufacturing_feedback(arguments, cancellation)?,
        "compare_manufacturing_feedback" => {
            compare_manufacturing_feedback(arguments, cancellation)?
        }
        "compare_schematics" => compare_schematics(arguments, cancellation)?,
        "route_schematic_reviewers" => route_schematic_reviewers(arguments, cancellation)?,
        "route_kicad" => route_kicad(arguments, cancellation)?,
        "prepare_schematic_review" => prepare_schematic_review(arguments, cancellation)?,
        "sign_schematic_approval" => sign_schematic_approval(arguments, cancellation)?,
        "verify_schematic_approval" => verify_schematic_approval(arguments, cancellation)?,
        "verify_schematic_approval_quorum" => {
            verify_schematic_approval_quorum(arguments, cancellation)?
        }
        "sign_human_schematic_escalation" => {
            sign_human_schematic_escalation(arguments, cancellation)?
        }
        "verify_human_schematic_escalation" => {
            verify_human_schematic_escalation(arguments, cancellation)?
        }
        "init_approval_transparency_log" => {
            init_approval_transparency_log(arguments, cancellation)?
        }
        "append_approval_transparency_log" => {
            append_approval_transparency_log(arguments, cancellation)?
        }
        "sign_approval_transparency_log" => {
            sign_approval_transparency_log(arguments, cancellation)?
        }
        "verify_approval_transparency_log" => {
            verify_approval_transparency_log(arguments, cancellation)?
        }
        "witness_approval_transparency_log" => {
            witness_approval_transparency_log(arguments, cancellation)?
        }
        "verify_approval_transparency_witnesses" => {
            verify_approval_transparency_witnesses(arguments, cancellation)?
        }
        "request_remote_approval_transparency_witness" => {
            request_remote_approval_transparency_witness(arguments, cancellation)?
        }
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

fn verify_policy_pack(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "public_key",
            "baseline_state",
            "state_output",
            "output",
        ],
    )?;
    let input = required_string(&arguments, "input")?;
    let public_key = required_string(&arguments, "public_key")?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-policy-pack".into(),
        input,
        "--public-key".into(),
        public_key,
        "--output".into(),
        output.clone(),
    ];
    optional_option(
        &arguments,
        "baseline_state",
        "--baseline-state",
        &mut command,
    )?;
    optional_option(&arguments, "state_output", "--state-output", &mut command)?;
    let execution = execute(&command, cancellation)?;
    let policy_pack = read_json_if_present(Path::new(&output));
    let trust_state = arguments
        .get("state_output")
        .and_then(Value::as_str)
        .map(Path::new)
        .map(read_json_if_present)
        .unwrap_or(Value::Null);
    Ok(execution_result(
        execution,
        json!({"output": output, "policy_pack": policy_pack, "trust_state": trust_state}),
    ))
}

fn analyze_kicad(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "output_dir",
            "project",
            "rules_file",
            "fab",
            "fab_profile",
            "policy_pack",
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
    optional_option(&arguments, "fab_profile", "--fab-profile", &mut command)?;
    optional_option(&arguments, "policy_pack", "--policy-pack", &mut command)?;
    optional_flag(
        &arguments,
        "fail_on_violations",
        "--fail-on-violations",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let manifest = read_json_if_present(&Path::new(&output_dir).join("run.json"));
    Ok(execution_result(
        execution,
        json!({"artifact_dir": output_dir, "manifest": manifest}),
    ))
}

fn compare_analysis(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
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
    let execution = execute(&command, cancellation)?;
    let manifest = read_json_if_present(&Path::new(&output_dir).join("run.json"));
    Ok(execution_result(
        execution,
        json!({"artifact_dir": output_dir, "manifest": manifest}),
    ))
}

fn record_manufacturing_feedback(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "declaration",
            "analysis_dir",
            "board",
            "artifacts",
            "output",
            "summary_output",
            "sarif_output",
            "require_passed",
        ],
    )?;
    let declaration = required_string(&arguments, "declaration")?;
    let analysis_dir = required_string(&arguments, "analysis_dir")?;
    let board = required_string(&arguments, "board")?;
    let artifacts = required_string_array(&arguments, "artifacts", false)?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "record-manufacturing-feedback".into(),
        declaration,
        "--analysis-dir".into(),
        analysis_dir,
        "--board".into(),
        board,
    ];
    for artifact in artifacts {
        command.extend(["--artifact".into(), artifact]);
    }
    command.extend(["--output".into(), output.clone()]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_option(&arguments, "sarif_output", "--sarif-output", &mut command)?;
    optional_flag(
        &arguments,
        "require_passed",
        "--require-passed",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let feedback = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "feedback": feedback}),
    ))
}

fn compare_manufacturing_feedback(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "baseline",
            "current",
            "output",
            "summary_output",
            "sarif_output",
            "fail_on_regressions",
        ],
    )?;
    let baseline = required_string(&arguments, "baseline")?;
    let current = required_string(&arguments, "current")?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "compare-manufacturing-feedback".into(),
        baseline,
        current,
        "--output".into(),
        output.clone(),
    ];
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_option(&arguments, "sarif_output", "--sarif-output", &mut command)?;
    optional_flag(
        &arguments,
        "fail_on_regressions",
        "--fail-on-regressions",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let comparison = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "comparison": comparison}),
    ))
}

fn compare_schematics(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "baseline",
            "current",
            "output",
            "summary_output",
            "sarif_output",
            "require_no_review",
        ],
    )?;
    let baseline = required_string(&arguments, "baseline")?;
    let current = required_string(&arguments, "current")?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "compare-schematics".into(),
        baseline,
        current,
        "--output".into(),
        output.clone(),
    ];
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_option(&arguments, "sarif_output", "--sarif-output", &mut command)?;
    optional_flag(
        &arguments,
        "require_no_review",
        "--require-no-review",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let diff = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "diff": diff}),
    ))
}

fn route_schematic_reviewers(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "baseline",
            "current",
            "routing_policy",
            "output",
            "summary_output",
            "require_routed",
        ],
    )?;
    let baseline = required_string(&arguments, "baseline")?;
    let current = required_string(&arguments, "current")?;
    let routing_policy = required_string(&arguments, "routing_policy")?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "route-schematic-review".into(),
        baseline,
        current,
        "--routing-policy".into(),
        routing_policy,
        "--output".into(),
        output.clone(),
    ];
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_routed",
        "--require-routed",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let plan = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "plan": plan}),
    ))
}

fn route_kicad(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "output",
            "project",
            "rules_file",
            "fab",
            "fab_profile",
            "policy_pack",
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
    optional_option(&arguments, "fab_profile", "--fab-profile", &mut command)?;
    optional_option(&arguments, "policy_pack", "--policy-pack", &mut command)?;
    optional_option(&arguments, "svg", "--svg", &mut command)?;
    optional_option(&arguments, "json_output", "--json-output", &mut command)?;
    optional_flag(
        &arguments,
        "allow_unrouted",
        "--allow-unrouted",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(execution, json!({"output": output})))
}

fn prepare_schematic_review(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "electrical_review",
            "policy",
            "policy_pack",
            "simulation_evidence",
            "requirements",
            "allow_no_simulation",
            "output",
            "session_output",
        ],
    )?;
    let input = required_string(&arguments, "input")?;
    let review = required_string(&arguments, "electrical_review")?;
    let output = required_string(&arguments, "output")?;
    let requirements = required_string_array(
        &arguments,
        "requirements",
        arguments.contains_key("policy_pack"),
    )?;
    let simulations = required_string_array(&arguments, "simulation_evidence", true)?;
    let mut command = vec![
        "prepare-ai-review".into(),
        input,
        "--electrical-review".into(),
        review,
    ];
    optional_option(&arguments, "policy", "--policy", &mut command)?;
    optional_option(&arguments, "policy_pack", "--policy-pack", &mut command)?;
    for value in simulations {
        command.push("--simulation-evidence".into());
        command.push(value);
    }
    for value in requirements {
        command.push("--requirement".into());
        command.push(value);
    }
    optional_flag(
        &arguments,
        "allow_no_simulation",
        "--allow-no-simulation",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    optional_option(
        &arguments,
        "session_output",
        "--session-output",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let request = read_json_if_present(Path::new(&output));
    let session_output = arguments
        .get("session_output")
        .and_then(Value::as_str)
        .map(str::to_string);
    let session = session_output
        .as_deref()
        .map(|path| read_json_if_present(Path::new(path)));
    Ok(execution_result(
        execution,
        json!({
            "output": output, "request": request,
            "session_output": session_output, "session": session
        }),
    ))
}

fn sign_schematic_approval(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "request",
            "response",
            "private_key",
            "signer_id",
            "session",
            "output",
            "require_approved",
        ],
    )?;
    let request = required_string(&arguments, "request")?;
    let response = required_string(&arguments, "response")?;
    let private_key = required_string(&arguments, "private_key")?;
    let signer_id = required_string(&arguments, "signer_id")?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-ai-review".into(),
        request,
        response,
        "--private-key".into(),
        private_key,
        "--signer-id".into(),
        signer_id,
        "--output".into(),
        output.clone(),
    ];
    optional_option(&arguments, "session", "--session", &mut command)?;
    optional_flag(
        &arguments,
        "require_approved",
        "--require-approved",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let approval = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "approval": approval}),
    ))
}

fn verify_schematic_approval(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "approval",
            "request",
            "response",
            "public_key",
            "policy_pack",
            "session",
            "require_approved",
        ],
    )?;
    let approval = required_string(&arguments, "approval")?;
    let request = required_string(&arguments, "request")?;
    let response = required_string(&arguments, "response")?;
    let has_public_key = arguments.contains_key("public_key");
    let has_policy_pack = arguments.contains_key("policy_pack");
    if has_public_key == has_policy_pack {
        return Err(json!({
            "detail": "exactly one of public_key or policy_pack is required"
        }));
    }
    let mut command = vec!["verify-ai-approval".into(), approval, request, response];
    optional_option(&arguments, "public_key", "--public-key", &mut command)?;
    optional_option(&arguments, "policy_pack", "--policy-pack", &mut command)?;
    optional_option(&arguments, "session", "--session", &mut command)?;
    optional_flag(
        &arguments,
        "require_approved",
        "--require-approved",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let verified = execution.success;
    Ok(execution_result(execution, json!({"verified": verified})))
}

fn verify_schematic_approval_quorum(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "request",
            "approvals",
            "responses",
            "policy_pack",
            "minimum_approvals",
            "minimum_distinct_providers",
            "minimum_distinct_models",
            "baseline_schematic",
            "current_schematic",
            "reviewer_routing_policy",
            "session",
            "output",
            "summary_output",
            "require_quorum",
        ],
    )?;
    let request = required_string(&arguments, "request")?;
    let approvals = required_string_array(&arguments, "approvals", false)?;
    let responses = required_string_array(&arguments, "responses", false)?;
    if approvals.len() != responses.len() {
        return Err(json!({
            "detail": "approvals and responses must contain the same number of paths"
        }));
    }
    let policy_pack = required_string(&arguments, "policy_pack")?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec!["verify-ai-quorum".into(), request];
    for approval in approvals {
        command.extend(["--approval".into(), approval]);
    }
    for response in responses {
        command.extend(["--response".into(), response]);
    }
    command.extend(["--policy-pack".into(), policy_pack]);
    optional_positive_integer(
        &arguments,
        "minimum_approvals",
        "--minimum-approvals",
        &mut command,
    )?;
    optional_positive_integer(
        &arguments,
        "minimum_distinct_providers",
        "--minimum-distinct-providers",
        &mut command,
    )?;
    optional_positive_integer(
        &arguments,
        "minimum_distinct_models",
        "--minimum-distinct-models",
        &mut command,
    )?;
    let routed_inputs = [
        "baseline_schematic",
        "current_schematic",
        "reviewer_routing_policy",
    ]
    .iter()
    .filter(|name| arguments.contains_key(**name))
    .count();
    if routed_inputs != 0 && routed_inputs != 3 {
        return Err(json!({
            "detail": "baseline_schematic, current_schematic, and reviewer_routing_policy must be supplied together"
        }));
    }
    optional_option(
        &arguments,
        "baseline_schematic",
        "--baseline-schematic",
        &mut command,
    )?;
    optional_option(&arguments, "session", "--session", &mut command)?;
    optional_option(
        &arguments,
        "current_schematic",
        "--current-schematic",
        &mut command,
    )?;
    optional_option(
        &arguments,
        "reviewer_routing_policy",
        "--reviewer-routing-policy",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_quorum",
        "--require-quorum",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn sign_human_schematic_escalation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "request",
            "session",
            "ai_quorum",
            "private_key",
            "signer_id",
            "decision",
            "reason",
            "ticket",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-human-escalation".into(),
        required_string(&arguments, "request")?,
        "--session".into(),
        required_string(&arguments, "session")?,
        "--ai-quorum".into(),
        required_string(&arguments, "ai_quorum")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--signer-id".into(),
        required_string(&arguments, "signer_id")?,
        "--decision".into(),
        required_string(&arguments, "decision")?,
        "--reason".into(),
        required_string(&arguments, "reason")?,
        "--ticket".into(),
        required_string(&arguments, "ticket")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let escalation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "escalation": escalation}),
    ))
}

fn verify_human_schematic_escalation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "request",
            "session",
            "ai_quorum",
            "escalations",
            "policy_pack",
            "minimum_approvals",
            "output",
            "summary_output",
            "require_approved",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-human-escalation".into(),
        required_string(&arguments, "request")?,
        "--session".into(),
        required_string(&arguments, "session")?,
        "--ai-quorum".into(),
        required_string(&arguments, "ai_quorum")?,
    ];
    for escalation in required_string_array(&arguments, "escalations", false)? {
        command.extend(["--escalation".into(), escalation]);
    }
    command.extend([
        "--policy-pack".into(),
        required_string(&arguments, "policy_pack")?,
    ]);
    optional_positive_integer(
        &arguments,
        "minimum_approvals",
        "--minimum-approvals",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_approved",
        "--require-approved",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn init_approval_transparency_log(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["log_id", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-approval-log".into(),
        "--log-id".into(),
        required_string(&arguments, "log_id")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let log = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "log": log}),
    ))
}

fn append_approval_transparency_log(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "artifact", "kind", "recorded_at_unix", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "append-approval-log".into(),
        required_string(&arguments, "log")?,
        "--artifact".into(),
        required_string(&arguments, "artifact")?,
        "--kind".into(),
        required_string(&arguments, "kind")?,
    ];
    optional_nonnegative_integer(
        &arguments,
        "recorded_at_unix",
        "--recorded-at-unix",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let log = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "log": log}),
    ))
}

fn sign_approval_transparency_log(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["log", "private_key", "signer_id", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-approval-log".into(),
        required_string(&arguments, "log")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--signer-id".into(),
        required_string(&arguments, "signer_id")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let checkpoint = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "checkpoint": checkpoint}),
    ))
}

fn verify_approval_transparency_log(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["log", "checkpoint", "public_key", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "verify-approval-log".into(),
        required_string(&arguments, "log")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn witness_approval_transparency_log(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "checkpoint",
            "private_key",
            "witness_id",
            "observed_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "witness-approval-log".into(),
        required_string(&arguments, "checkpoint")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
    ];
    optional_nonnegative_integer(
        &arguments,
        "observed_at_unix",
        "--observed-at-unix",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let witness = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "witness": witness}),
    ))
}

fn verify_approval_transparency_witnesses(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "checkpoint",
            "witnesses",
            "public_keys",
            "minimum_witnesses",
            "output",
            "require_quorum",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-approval-log-witnesses".into(),
        required_string(&arguments, "checkpoint")?,
    ];
    for witness in required_string_array(&arguments, "witnesses", false)? {
        command.extend(["--witness".into(), witness]);
    }
    for public_key in required_string_array(&arguments, "public_keys", false)? {
        command.extend(["--public-key".into(), public_key]);
    }
    optional_positive_integer(
        &arguments,
        "minimum_witnesses",
        "--minimum-witnesses",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    optional_flag(
        &arguments,
        "require_quorum",
        "--require-quorum",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn request_remote_approval_transparency_witness(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "checkpoint",
            "endpoint",
            "public_key",
            "bearer_token_env",
            "timeout_seconds",
            "output",
            "receipt_output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let receipt_output = required_string(&arguments, "receipt_output")?;
    let mut command = vec![
        "request-approval-log-witness".into(),
        required_string(&arguments, "checkpoint")?,
        "--endpoint".into(),
        required_string(&arguments, "endpoint")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
    ];
    optional_option(
        &arguments,
        "bearer_token_env",
        "--bearer-token-env",
        &mut command,
    )?;
    optional_positive_integer(
        &arguments,
        "timeout_seconds",
        "--timeout-seconds",
        &mut command,
    )?;
    command.extend([
        "--output".into(),
        output.clone(),
        "--receipt-output".into(),
        receipt_output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let witness = read_json_if_present(Path::new(&output));
    let receipt = read_json_if_present(Path::new(&receipt_output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "receipt_output": receipt_output,
            "witness": witness,
            "receipt": receipt
        }),
    ))
}

struct Execution {
    success: bool,
    exit_code: Option<i32>,
    stderr: String,
}

fn execute(
    arguments: &[String],
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Execution, Value> {
    let executable = env::current_exe()
        .map_err(|error| json!({"detail": format!("locating pcbex executable: {error}")}))?;
    let mut child = Command::new(executable)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| json!({"detail": format!("starting pcbex tool process: {error}")}))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = io::BufReader::new(stdout).read_to_end(&mut bytes);
        bytes
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = io::BufReader::new(stderr).read_to_end(&mut bytes);
        bytes
    });
    let status = loop {
        if cancellation.is_some_and(|cancelled| cancelled.load(Ordering::SeqCst)) {
            let _ = child.kill();
            break child.wait().map_err(|error| {
                json!({"detail": format!("waiting for cancelled pcbex tool process: {error}")})
            })?;
        }
        match child.try_wait().map_err(
            |error| json!({"detail": format!("waiting for pcbex tool process: {error}")}),
        )? {
            Some(status) => break status,
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    let _stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    Ok(Execution {
        success: status.success(),
        exit_code: status.code(),
        stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
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

fn optional_positive_integer(
    arguments: &Map<String, Value>,
    name: &str,
    option: &str,
    command: &mut Vec<String>,
) -> std::result::Result<(), Value> {
    if let Some(value) = arguments.get(name) {
        let value = value
            .as_u64()
            .filter(|value| (1..=100).contains(value))
            .ok_or_else(|| json!({"detail": format!("{name} must be an integer from 1 to 100")}))?;
        command.push(option.into());
        command.push(value.to_string());
    }
    Ok(())
}

fn optional_nonnegative_integer(
    arguments: &Map<String, Value>,
    name: &str,
    option: &str,
    command: &mut Vec<String>,
) -> std::result::Result<(), Value> {
    if let Some(value) = arguments.get(name) {
        let value = value
            .as_u64()
            .ok_or_else(|| json!({"detail": format!("{name} must be a non-negative integer")}))?;
        command.push(option.into());
        command.push(value.to_string());
    }
    Ok(())
}

fn required_string_array(
    arguments: &Map<String, Value>,
    name: &str,
    allow_missing: bool,
) -> std::result::Result<Vec<String>, Value> {
    let Some(value) = arguments.get(name) else {
        return if allow_missing {
            Ok(Vec::new())
        } else {
            Err(json!({"detail": format!("{name} must be a non-empty string array")}))
        };
    };
    let values = value
        .as_array()
        .ok_or_else(|| json!({"detail": format!("{name} must be a string array")}))?;
    if !allow_missing && values.is_empty() {
        return Err(json!({"detail": format!("{name} must not be empty")}));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(
                    || json!({"detail": format!("{name} entries must be non-empty strings")}),
                )
        })
        .collect()
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
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 22);
        let named = |name: &str| {
            tools
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("missing MCP tool {name}"))
        };
        assert_eq!(
            named("list_dfm_profiles")["annotations"]["readOnlyHint"],
            true
        );
        assert_eq!(
            named("verify_policy_pack")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("analyze_kicad")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("record_manufacturing_feedback")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("record_manufacturing_feedback")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("record_manufacturing_feedback")["inputSchema"]["properties"]["artifacts"]["type"],
            "array"
        );
        assert_eq!(
            named("compare_schematics")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("route_schematic_reviewers")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("route_schematic_reviewers")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("sign_schematic_approval")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("prepare_schematic_review")["inputSchema"]["properties"]["session_output"]["type"],
            "string"
        );
        assert_eq!(
            named("sign_schematic_approval")["inputSchema"]["properties"]["session"]["type"],
            "string"
        );
        assert_eq!(
            named("verify_schematic_approval")["annotations"]["readOnlyHint"],
            true
        );
        assert_eq!(
            named("verify_schematic_approval_quorum")["inputSchema"]["properties"]["approvals"]["type"],
            "array"
        );
        assert_eq!(
            named("verify_schematic_approval_quorum")["inputSchema"]["properties"]["reviewer_routing_policy"]
                ["type"],
            "string"
        );
        assert_eq!(
            named("verify_schematic_approval_quorum")["inputSchema"]["properties"]["session"]["type"],
            "string"
        );
        assert_eq!(
            named("verify_schematic_approval_quorum")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("sign_human_schematic_escalation")["inputSchema"]["properties"]["decision"]["enum"]
                [0],
            "approve"
        );
        assert_eq!(
            named("verify_human_schematic_escalation")["inputSchema"]["properties"]["escalations"]
                ["type"],
            "array"
        );
        assert_eq!(
            named("append_approval_transparency_log")["inputSchema"]["properties"]["kind"]["enum"]
                [0],
            "signed-ai-approval"
        );
        assert_eq!(
            named("verify_approval_transparency_log")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("verify_approval_transparency_witnesses")["inputSchema"]["properties"]["minimum_witnesses"]
                ["minimum"],
            2
        );
        assert_eq!(
            named("request_remote_approval_transparency_witness")["inputSchema"]["properties"]["endpoint"]
                ["pattern"],
            "^https://"
        );
        let verify_policy = tools
            .iter()
            .find(|tool| tool["name"] == "verify_policy_pack")
            .unwrap();
        assert_eq!(
            verify_policy["inputSchema"]["properties"]["baseline_state"]["type"],
            "string"
        );
        assert_eq!(
            verify_policy["inputSchema"]["properties"]["state_output"]["type"],
            "string"
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

    #[test]
    fn runs_task_augmented_calls_and_returns_original_errors() {
        let mut server = ready_server();
        let forbidden = server
            .handle_message(request(
                1,
                "tools/call",
                json!({
                    "name": "list_dfm_profiles",
                    "arguments": {},
                    "task": {"ttl": 60_000}
                }),
            ))
            .unwrap();
        assert_eq!(forbidden["error"]["code"], -32601);
        let invalid_ttl = server
            .handle_message(request(
                1,
                "tools/call",
                json!({
                    "name": "analyze_kicad",
                    "arguments": {},
                    "task": {"ttl": MAX_TASK_TTL_MS + 1}
                }),
            ))
            .unwrap();
        assert_eq!(invalid_ttl["error"]["code"], -32602);
        let created = server
            .handle_message(request(
                2,
                "tools/call",
                json!({
                    "name": "analyze_kicad",
                    "arguments": {},
                    "task": {"ttl": 60_000}
                }),
            ))
            .unwrap();
        let task_id = created["result"]["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(created["result"]["task"]["status"], "working");
        let result = server
            .handle_message(request(3, "tasks/result", json!({"taskId": task_id})))
            .unwrap();
        assert_eq!(result["error"]["code"], -32602);
        let status = server
            .handle_message(request(
                4,
                "tasks/get",
                json!({
                    "taskId": task_id,
                    "_meta": {"io.modelcontextprotocol/related-task": {"taskId": "ignored"}}
                }),
            ))
            .unwrap();
        assert_eq!(status["result"]["status"], "failed");
        assert_eq!(
            server
                .handle_message(request(5, "tasks/list", json!({})))
                .unwrap()["result"]["tasks"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn cancels_working_tasks_and_preserves_terminal_state() {
        let mut server = ready_server();
        let task_id = "test-cancellable".to_string();
        let created_at = iso8601_now();
        server.tasks.insert(
            task_id.clone(),
            Arc::new(TaskRecord {
                task_id: task_id.clone(),
                created_at: created_at.clone(),
                created: Instant::now(),
                ttl_ms: DEFAULT_TASK_TTL_MS,
                cancellation: Arc::new(AtomicBool::new(false)),
                state: Mutex::new(TaskState {
                    status: TaskStatus::Working,
                    status_message: "working".to_string(),
                    last_updated_at: created_at,
                    result: None,
                }),
                changed: Condvar::new(),
            }),
        );
        let cancelled = server
            .handle_message(request(2, "tasks/cancel", json!({"taskId": task_id})))
            .unwrap();
        assert_eq!(cancelled["result"]["status"], "cancelled");
        let repeated = server
            .handle_message(request(3, "tasks/cancel", json!({"taskId": task_id})))
            .unwrap();
        assert_eq!(repeated["error"]["code"], -32602);
        let result = server
            .handle_message(request(4, "tasks/result", json!({"taskId": task_id})))
            .unwrap();
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(
            result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
            task_id
        );
    }

    #[test]
    fn older_protocol_ignores_task_augmentation() {
        let mut server = McpServer::default();
        let initialized = server
            .handle_message(request(
                1,
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}
                }),
            ))
            .unwrap();
        assert!(initialized["result"]["capabilities"]["tasks"].is_null());
        server.handle_message(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }));
        let response = server
            .handle_message(request(
                2,
                "tools/call",
                json!({
                    "name": "list_dfm_profiles",
                    "arguments": {},
                    "task": {"ttl": 1}
                }),
            ))
            .unwrap();
        assert_eq!(response["result"]["isError"], false);
    }
}

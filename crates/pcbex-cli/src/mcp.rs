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
                    | "recommend_policy"
                    | "policy_rollout_profile"
                    | "simulate_policy_rollout"
                    | "sign_rollout_approval"
                    | "verify_rollout_approvals"
                    | "record_canary_monitoring"
                    | "sign_canary_completion"
                    | "verify_canary_completion"
                    | "advance_policy_deployment"
                    | "verify_policy_deployment"
                    | "apply_policy_deployment_rollback"
                    | "verify_policy_rollback_recovery"
                    | "close_rollback_incident"
                    | "append_policy_incident_ledger"
                    | "apply_policy_suspension_decision"
                    | "apply_policy_remediation"
                    | "append_policy_lifecycle_event"
                    | "snapshot_policy_lifecycle"
                    | "verify_policy_lifecycle_checkpoint"
                    | "verify_policy_lifecycle_checkpoint_witnesses"
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
        open_world_tool(
            "fetch_policy_pack",
            "Fetch organization policy pack",
            "Fetch a signed policy pack from a bounded HTTPS registry, verify its Ed25519 signature, and reject rollback or equivocation.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "endpoint", "public_key", "signed_output", "output",
                    "state_output", "receipt_output"
                ],
                "properties": {
                    "endpoint": {"type": "string", "pattern": "^https://"},
                    "public_key": {"type": "string"},
                    "baseline_state": {"type": "string"},
                    "bearer_token_env": {
                        "type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"
                    },
                    "timeout_seconds": {
                        "type": "integer", "minimum": 1, "maximum": 600, "default": 30
                    },
                    "signed_output": {"type": "string"},
                    "output": {"type": "string"},
                    "state_output": {"type": "string"},
                    "receipt_output": {"type": "string"}
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
            "recommend_policy",
            "Recommend manufacturing policy tightening",
            "Generate a proposal-only, human-gated DFM tightening report from independently bound fabrication feedback and exact analyze-kicad manifests.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "policy_pack", "feedback", "analysis_manifests",
                    "generated_on", "output"
                ],
                "properties": {
                    "policy_pack": {"type": "string"},
                    "feedback": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "analysis_manifests": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "generated_on": {"type": "string", "format": "date"},
                    "minimum_occurrences": {
                        "type": "integer", "minimum": 2, "maximum": 100,
                        "default": 2
                    },
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "policy_rollout_profile",
            "Create policy rollout simulation profile",
            "Materialize a deterministic simulation-only DFM profile from a governed recommendation without approving or deploying it.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["policy_pack", "recommendation", "generated_on", "output"],
                "properties": {
                    "policy_pack": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "generated_on": {"type": "string", "format": "date"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "simulate_policy_rollout",
            "Simulate policy rollout across projects",
            "Bind baseline and candidate pcbex analyses across projects into a non-deployable, human-gated rollout impact report.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "policy_pack", "recommendation", "project_ids",
                    "boards", "baseline_analyses", "candidate_analyses",
                    "generated_on", "output"
                ],
                "properties": {
                    "policy_pack": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "project_ids": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "boards": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "baseline_analyses": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "candidate_analyses": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "generated_on": {"type": "string", "format": "date"},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "sign_rollout_approval",
            "Sign canary rollout decision",
            "Sign one human approve/reject decision over an exact rollout, bounded canary scope, and maximum seven-day window.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollout", "canary_projects", "valid_from_unix",
                    "expires_at_unix", "private_key", "signer_id",
                    "decision", "reason", "ticket", "output"
                ],
                "properties": {
                    "rollout": {"type": "string"},
                    "canary_projects": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "valid_from_unix": {"type": "integer", "minimum": 0},
                    "expires_at_unix": {"type": "integer", "minimum": 1},
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
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_rollout_approvals",
            "Authorize bounded canary rollout",
            "Verify trusted dual-control human signatures and emit a canary-only authorization with mandatory rollback and no automatic promotion.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollout", "policy_pack", "approvals",
                    "evaluated_at_unix", "output"
                ],
                "properties": {
                    "rollout": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "approvals": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "minimum_approvals": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_authorized": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "record_canary_monitoring",
            "Record bound canary monitoring",
            "Compare exact observed canary analyses with their authorized simulated baselines; regressions require rollback and clean evidence still requires a human promotion decision.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollout", "authorization", "project_ids", "boards",
                    "baseline_analyses", "observed_analyses",
                    "observed_at_unix", "output"
                ],
                "properties": {
                    "rollout": {"type": "string"},
                    "authorization": {"type": "string"},
                    "project_ids": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "boards": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "baseline_analyses": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "observed_analyses": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "observed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_passed": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "sign_canary_completion",
            "Sign canary completion decision",
            "Sign one explicit promote or rollback decision over exact bound canary monitoring evidence.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollout", "monitoring", "authorization", "decision",
                    "decided_at_unix", "private_key", "signer_id",
                    "reason", "ticket", "output"
                ],
                "properties": {
                    "rollout": {"type": "string"},
                    "monitoring": {"type": "string"},
                    "authorization": {"type": "string"},
                    "decision": {"enum": ["promote", "rollback"]},
                    "decided_at_unix": {"type": "integer", "minimum": 0},
                    "private_key": {"type": "string"},
                    "signer_id": {"type": "string"},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "ticket": {"type": "string", "minLength": 1, "maxLength": 256},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_canary_completion",
            "Finalize canary completion",
            "Verify a unanimous trusted human quorum over promotion or rollback; monitoring failures permit rollback only.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollout", "monitoring", "authorization", "policy_pack",
                    "decisions", "output"
                ],
                "properties": {
                    "rollout": {"type": "string"},
                    "monitoring": {"type": "string"},
                    "authorization": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "decisions": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "minimum_decisions": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_finalized": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "advance_policy_deployment",
            "Advance monotonic policy deployment",
            "Re-verify the exact human completion quorum and append a hash-chained deployment state that prevents revision replay while retaining the rollback target.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollout", "monitoring", "authorization", "policy_pack",
                    "candidate_policy_pack", "source_policy_trust_state",
                    "candidate_policy_trust_state", "decisions", "recorded_at_unix",
                    "output"
                ],
                "properties": {
                    "rollout": {"type": "string"},
                    "monitoring": {"type": "string"},
                    "authorization": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "candidate_policy_pack": {"type": "string"},
                    "source_policy_trust_state": {"type": "string"},
                    "candidate_policy_trust_state": {"type": "string"},
                    "decisions": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "minimum_decisions": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "baseline_state": {"type": "string"},
                    "suspension_states": {
                        "type": "array", "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "remediation_states": {
                        "type": "array", "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "policy_lifecycle_ledgers": {
                        "type": "array", "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "recorded_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_promotion": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_policy_deployment",
            "Verify deployed policy fleet",
            "Compare every deployed project with its exact simulated candidate evidence; any regression requires a separately approved rollback and never triggers automatic rollback.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "deployment", "rollout", "candidate_policy_pack",
                    "project_ids", "boards", "expected_analyses",
                    "observed_analyses", "verified_at_unix", "output"
                ],
                "properties": {
                    "deployment": {"type": "string"},
                    "rollout": {"type": "string"},
                    "candidate_policy_pack": {"type": "string"},
                    "project_ids": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "boards": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "expected_analyses": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "observed_analyses": {
                        "type": "array", "minItems": 1, "maxItems": 1000,
                        "items": {"type": "string"}
                    },
                    "verified_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_passed": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "sign_policy_deployment_rollback",
            "Sign production rollback approval",
            "Sign an explicit human rollback approval bound to the exact failed production verification, failed revision, and retained restore target.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "deployment", "verification", "approved_at_unix",
                    "private_key", "signer_id", "reason", "ticket", "output"
                ],
                "properties": {
                    "deployment": {"type": "string"},
                    "verification": {"type": "string"},
                    "approved_at_unix": {"type": "integer", "minimum": 0},
                    "private_key": {"type": "string"},
                    "signer_id": {"type": "string"},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "ticket": {"type": "string", "minLength": 1, "maxLength": 256},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            Some("forbidden"),
        ),
        tool(
            "apply_policy_deployment_rollback",
            "Apply dual-control production rollback",
            "Re-verify distinct trusted human approvals over failed production evidence and retain a hash-bound state restoring only the recorded prior revision.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "deployment", "verification", "active_policy_pack",
                    "approvals", "recorded_at_unix", "output"
                ],
                "properties": {
                    "deployment": {"type": "string"},
                    "verification": {"type": "string"},
                    "active_policy_pack": {"type": "string"},
                    "approvals": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "minimum_approvals": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "recorded_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_applied": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_policy_rollback_recovery",
            "Verify rollback recovery",
            "Compare the complete restored fleet with exact retained pre-promotion production evidence; incomplete coverage or regression keeps the incident open.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollback", "rollout", "deployment", "failed_verification",
                    "previous_deployment", "baseline_verification",
                    "restored_policy_pack", "project_ids",
                    "boards", "expected_analyses", "observed_analyses",
                    "verified_at_unix", "output"
                ],
                "properties": {
                    "rollback": {"type": "string"},
                    "rollout": {"type": "string"},
                    "deployment": {"type": "string"},
                    "failed_verification": {"type": "string"},
                    "previous_deployment": {"type": "string"},
                    "baseline_verification": {"type": "string"},
                    "restored_policy_pack": {"type": "string"},
                    "project_ids": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "string"}},
                    "boards": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "string"}},
                    "expected_analyses": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "string"}},
                    "observed_analyses": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "string"}},
                    "verified_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_passed": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "sign_rollback_incident_acknowledgment",
            "Sign rollback incident acknowledgment",
            "Sign an operator acknowledgment bound to exact complete and clean post-rollback recovery evidence.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollback", "recovery", "acknowledged_at_unix", "private_key",
                    "operator_id", "reason", "ticket", "output"
                ],
                "properties": {
                    "rollback": {"type": "string"},
                    "recovery": {"type": "string"},
                    "acknowledged_at_unix": {"type": "integer", "minimum": 0},
                    "private_key": {"type": "string"},
                    "operator_id": {"type": "string"},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "ticket": {"type": "string", "minLength": 1, "maxLength": 256},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            Some("forbidden"),
        ),
        tool(
            "close_rollback_incident",
            "Close rollback incident",
            "Verify clean recovery and a trusted operator signature independent of rollback approvers before retaining a closed incident state.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollback", "recovery", "restored_policy_pack",
                    "acknowledgment", "closed_at_unix", "output"
                ],
                "properties": {
                    "rollback": {"type": "string"},
                    "recovery": {"type": "string"},
                    "restored_policy_pack": {"type": "string"},
                    "acknowledgment": {"type": "string"},
                    "closed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_closed": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "append_policy_incident_ledger",
            "Append policy incident ledger",
            "Append one closed rollback incident to a hash chain, recompute recovery metrics, and flag repeated failed revisions for human suspension review without automatic suspension.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "rollback", "failed_verification", "recovery", "closure", "output"
                ],
                "properties": {
                    "rollback": {"type": "string"},
                    "failed_verification": {"type": "string"},
                    "recovery": {"type": "string"},
                    "closure": {"type": "string"},
                    "baseline_ledger": {"type": "string"},
                    "suspension_threshold": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_no_suspension_review": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "sign_policy_suspension_decision",
            "Sign policy suspension decision",
            "Sign an explicit human suspend or continue decision bound to one repeated-incident candidate and the exact incident-ledger head.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "ledger", "failed_revision", "failed_policy_pack_sha256",
                    "decision", "decided_at_unix", "private_key", "signer_id",
                    "reason", "ticket", "output"
                ],
                "properties": {
                    "ledger": {"type": "string"},
                    "failed_revision": {"type": "integer", "minimum": 1},
                    "failed_policy_pack_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "decision": {"enum": ["suspend", "continue"]},
                    "decided_at_unix": {"type": "integer", "minimum": 0},
                    "private_key": {"type": "string"},
                    "signer_id": {"type": "string"},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "ticket": {"type": "string", "minLength": 1, "maxLength": 256},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            Some("forbidden"),
        ),
        tool(
            "apply_policy_suspension_decision",
            "Apply policy suspension decision",
            "Verify a unanimous dual-control human quorum over repeated incident evidence and retain an exact-digest promotion deny decision.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "ledger", "policy_pack", "failed_revision",
                    "failed_policy_pack_sha256", "decisions",
                    "recorded_at_unix", "output"
                ],
                "properties": {
                    "ledger": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "failed_revision": {"type": "integer", "minimum": 1},
                    "failed_policy_pack_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "decisions": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "minimum_decisions": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "recorded_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_suspended": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "sign_policy_remediation_approval",
            "Sign policy remediation approval",
            "Sign an independent human approval bound to a suspended policy, accepted successor digest, and complete clean canary evidence.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "suspension", "candidate_policy_pack",
                    "candidate_policy_trust_state", "rollout", "monitoring",
                    "approved_at_unix", "private_key", "signer_id",
                    "reason", "ticket", "output"
                ],
                "properties": {
                    "suspension": {"type": "string"},
                    "candidate_policy_pack": {"type": "string"},
                    "candidate_policy_trust_state": {"type": "string"},
                    "rollout": {"type": "string"},
                    "monitoring": {"type": "string"},
                    "approved_at_unix": {"type": "integer", "minimum": 0},
                    "private_key": {"type": "string"},
                    "signer_id": {"type": "string"},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "ticket": {"type": "string", "minLength": 1, "maxLength": 256},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            Some("forbidden"),
        ),
        tool(
            "apply_policy_remediation",
            "Apply policy remediation",
            "Verify an independent dual-control quorum over a clean accepted successor and lift one suspension only for that exact remediation digest.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "suspension", "policy_pack", "candidate_policy_pack",
                    "candidate_policy_trust_state", "rollout", "monitoring",
                    "approvals", "recorded_at_unix", "output"
                ],
                "properties": {
                    "suspension": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "candidate_policy_pack": {"type": "string"},
                    "candidate_policy_trust_state": {"type": "string"},
                    "rollout": {"type": "string"},
                    "monitoring": {"type": "string"},
                    "approvals": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "minimum_approvals": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "recorded_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_verified": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "append_policy_lifecycle_event",
            "Append policy lifecycle event",
            "Retain one complete suspension decision or independently verified remediation in an immutable hash-chained lifecycle ledger.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["output"],
                "properties": {
                    "baseline_ledger": {"type": "string"},
                    "suspension": {"type": "string"},
                    "remediation": {"type": "string"},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_no_pending_suspensions": {
                        "type": "boolean", "default": false
                    }
                },
                "oneOf": [
                    {"required": ["suspension"], "not": {"required": ["remediation"]}},
                    {"required": ["remediation"], "not": {"required": ["suspension"]}}
                ]
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "snapshot_policy_lifecycle",
            "Snapshot historical policy lifecycle",
            "Recompute blocked, released, superseded, and continued policy decisions at one retained historical generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["ledger", "generation", "output"],
                "properties": {
                    "ledger": {"type": "string"},
                    "generation": {"type": "integer", "minimum": 1},
                    "output": {"type": "string"}
                }
            }),
            false,
            false,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "sign_policy_lifecycle_checkpoint",
            "Sign policy lifecycle checkpoint",
            "Bind an Ed25519 signature to the exact generation, hash-chain head, and normalized digest of an append-only policy lifecycle ledger.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "ledger", "issued_at_unix", "private_key", "signer_id", "output"
                ],
                "properties": {
                    "ledger": {"type": "string"},
                    "issued_at_unix": {"type": "integer", "minimum": 0},
                    "private_key": {"type": "string"},
                    "signer_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                    },
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_policy_lifecycle_checkpoint",
            "Verify policy lifecycle checkpoint",
            "Authenticate one lifecycle ledger and monotonically advance retained trust while rejecting rollback, same-generation equivocation, and history forks.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "ledger", "checkpoint", "public_key", "accepted_at_unix", "output"
                ],
                "properties": {
                    "ledger": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "public_key": {"type": "string"},
                    "baseline_state": {"type": "string"},
                    "key_rotation": {"type": "string"},
                    "accepted_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "require_accepted": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "sign_policy_lifecycle_key_rotation",
            "Sign policy lifecycle key rotation",
            "Authorize one signing-root transition with dual Ed25519 signatures from both the currently trusted and successor private keys.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "baseline_state", "old_private_key", "new_private_key",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "baseline_state": {"type": "string"},
                    "old_private_key": {"type": "string"},
                    "new_private_key": {"type": "string"},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "witness_policy_lifecycle_checkpoint",
            "Witness policy lifecycle checkpoint",
            "Independently sign one exact accepted lifecycle checkpoint, generation, and hash-chain head.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "private_key", "witness_id",
                    "observed_at_unix", "output"
                ],
                "properties": {
                    "trust_state": {"type": "string"},
                    "private_key": {"type": "string"},
                    "witness_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                    },
                    "observed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "init_policy_lifecycle_witness_trust",
            "Initialize lifecycle witness key trust",
            "Create generation-zero trust state binding one lifecycle-checkpoint witness identity to its current Ed25519 key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["witness_id", "public_key", "output"],
                "properties": {
                    "witness_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                    },
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_witness_key_rotation",
            "Sign lifecycle witness key rotation",
            "Create old-key authorization and new-key possession proof for exactly one identity-bound witness-key generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "old_private_key", "new_private_key",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "trust_state": {"type": "string"},
                    "old_private_key": {"type": "string"},
                    "new_private_key": {"type": "string"},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_policy_lifecycle_witness_key_rotation",
            "Apply lifecycle witness key rotation",
            "Verify both signatures and advance one digest-chained lifecycle-witness trust state by exactly one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "rotation", "output", "public_key_output"
                ],
                "properties": {
                    "trust_state": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "export_policy_lifecycle_witness_public_key",
            "Export lifecycle witness key",
            "Strictly validate retained lifecycle-witness trust and export its current key for legacy consumers.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_policy_lifecycle_checkpoint_witnesses",
            "Verify policy lifecycle witnesses",
            "Require a bounded quorum of distinct independently trusted keys over one exact accepted lifecycle checkpoint.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "witnesses", "evaluated_at_unix", "output"],
                "oneOf": [
                    {"required": ["public_keys"]},
                    {"required": ["witness_key_trust_states"]}
                ],
                "properties": {
                    "trust_state": {"type": "string"},
                    "witnesses": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "public_keys": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "witness_key_trust_states": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "minimum_witnesses": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "require_quorum": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        open_world_tool(
            "request_remote_policy_lifecycle_checkpoint_witness",
            "Request remote policy lifecycle witness",
            "POST one accepted lifecycle checkpoint identity to bounded HTTPS and immediately verify the signed response against a separately trusted key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "endpoint", "evaluated_at_unix",
                    "output", "receipt_output"
                ],
                "oneOf": [
                    {"required": ["public_key"]},
                    {"required": ["witness_key_trust_state"]}
                ],
                "properties": {
                    "trust_state": {"type": "string"},
                    "endpoint": {"type": "string", "pattern": "^https://"},
                    "public_key": {"type": "string"},
                    "witness_key_trust_state": {"type": "string"},
                    "bearer_token_env": {
                        "type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"
                    },
                    "timeout_seconds": {
                        "type": "integer", "minimum": 1, "maximum": 600, "default": 30
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "receipt_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "create_policy_lifecycle_public_anchor",
            "Create policy lifecycle public-log anchor",
            "Build and sign an RFC 6962-style Merkle inclusion proof over an ordered lifecycle-checkpoint snapshot.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "checkpoint", "log_checkpoints", "leaf_index", "log_id",
                    "private_key", "output"
                ],
                "properties": {
                    "checkpoint": {"type": "string"},
                    "log_checkpoints": {
                        "type": "array", "minItems": 1, "maxItems": 100000,
                        "items": {"type": "string"}
                    },
                    "leaf_index": {"type": "integer", "minimum": 0},
                    "log_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                    },
                    "private_key": {"type": "string"},
                    "observed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_policy_lifecycle_public_anchor",
            "Verify policy lifecycle public-log anchor",
            "Verify exact lifecycle-checkpoint inclusion, the reconstructed Merkle root, and a separately trusted signed tree head.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["checkpoint", "proof", "log_id", "public_key", "output"],
                "properties": {
                    "checkpoint": {"type": "string"},
                    "proof": {"type": "string"},
                    "log_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                    },
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "create_policy_lifecycle_public_log_consistency",
            "Create policy lifecycle public-log consistency proof",
            "Build an RFC 6962-style logarithmic proof that a retained signed lifecycle-log tree is an exact prefix of the current tree.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "previous_anchor", "current_anchor", "log_checkpoints", "output"
                ],
                "properties": {
                    "previous_anchor": {"type": "string"},
                    "current_anchor": {"type": "string"},
                    "log_checkpoints": {
                        "type": "array", "minItems": 1, "maxItems": 100000,
                        "items": {"type": "string"}
                    },
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_policy_lifecycle_public_log_consistency",
            "Verify policy lifecycle public-log consistency",
            "Bind retained and current anchors to trusted signed tree heads and reject rollback, equivocation, or a non-prefix split view.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "previous_anchor", "current_anchor", "proof",
                    "log_id", "public_key", "output"
                ],
                "properties": {
                    "previous_anchor": {"type": "string"},
                    "current_anchor": {"type": "string"},
                    "proof": {"type": "string"},
                    "log_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                    },
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_receipt",
            "Sign policy lifecycle public-log gossip receipt",
            "Verify a trusted signed lifecycle-log tree head and re-sign the exact observation with an independent, time-bounded observer identity.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "anchor", "log_id", "log_public_key", "observer_id",
                    "private_key", "expires_at_unix", "output"
                ],
                "properties": {
                    "anchor": {"type": "string"},
                    "log_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                    },
                    "log_public_key": {"type": "string"},
                    "observer_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                    },
                    "private_key": {"type": "string"},
                    "received_at_unix": {"type": "integer", "minimum": 0},
                    "expires_at_unix": {"type": "integer", "minimum": 1},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_policy_lifecycle_public_log_gossip_receipt",
            "Verify policy lifecycle public-log gossip receipt",
            "Compare one independently signed observation with the local anchor and require append-only consistency whenever their tree sizes differ.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "local_anchor", "receipt", "log_id", "log_public_key",
                    "observer_id", "observer_public_key", "evaluated_at_unix", "output"
                ],
                "properties": {
                    "local_anchor": {"type": "string"},
                    "receipt": {"type": "string"},
                    "consistency_proof": {"type": "string"},
                    "log_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                    },
                    "log_public_key": {"type": "string"},
                    "observer_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                    },
                    "observer_public_key": {"type": "string"},
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "init_policy_lifecycle_public_log_gossip_observer_trust",
            "Initialize lifecycle public-log gossip observer trust",
            "Create generation-zero trust binding one organization and observer identity to its current Ed25519 key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["organization_id", "observer_id", "public_key", "output"],
                "properties": {
                    "organization_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                    },
                    "observer_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                    },
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_observer_key_rotation",
            "Sign lifecycle public-log gossip observer key rotation",
            "Create old-key authorization and new-key possession proof for exactly one organization-bound observer generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "old_private_key", "new_private_key",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "trust_state": {"type": "string"},
                    "old_private_key": {"type": "string"},
                    "new_private_key": {"type": "string"},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_policy_lifecycle_public_log_gossip_observer_key_rotation",
            "Apply lifecycle public-log gossip observer key rotation",
            "Verify both signatures and advance one organization-bound digest-chained observer trust state by exactly one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "rotation", "output", "public_key_output"
                ],
                "properties": {
                    "trust_state": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "export_policy_lifecycle_public_log_gossip_observer_key",
            "Export lifecycle public-log gossip observer key",
            "Strictly validate retained organization-bound observer trust and export its current key for legacy consumers.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "init_policy_lifecycle_public_log_gossip_organization_registry",
            "Initialize lifecycle gossip organization registry",
            "Create an empty generation-zero registry bound to one separately retained Ed25519 authority key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["registry_id", "authority_public_key", "output"],
                "properties": {
                    "registry_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                    },
                    "authority_public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_transition",
            "Sign lifecycle gossip organization registry transition",
            "Authority-sign exactly one observer admission, organization suspension, or permanent revocation over the retained registry generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "authority_private_key", "action",
                    "organization_id", "reason_sha256", "effective_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "authority_private_key": {"type": "string"},
                    "action": {"enum": [
                        "admit-observer", "suspend-organization", "revoke-organization"
                    ]},
                    "organization_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                    },
                    "observer_trust_state": {"type": "string"},
                    "reason_sha256": {
                        "type": "string", "pattern": "^[0-9a-f]{64}$"
                    },
                    "effective_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_policy_lifecycle_public_log_gossip_organization_registry_transition",
            "Apply lifecycle gossip organization registry transition",
            "Verify authority signature and digest-chain continuity before advancing the registry by exactly one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["registry", "transition", "output"],
                "properties": {
                    "registry": {"type": "string"},
                    "transition": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation",
            "Sign lifecycle gossip registry authority key rotation",
            "Create old-key authorization and new-key possession proof for exactly one registry generation without resetting organization history.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "old_private_key", "new_private_key",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "old_private_key": {"type": "string"},
                    "new_private_key": {"type": "string"},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation",
            "Apply lifecycle gossip registry authority key rotation",
            "Verify both signatures and advance the same registry transition chain by exactly one generation while retaining all organization decisions.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "rotation", "output", "public_key_output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_governance",
            "Sign lifecycle gossip registry threshold governance",
            "Root-sign a configurable threshold policy over distinct registry authority identities and Ed25519 keys.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "registry_authority_private_key", "minimum_approvals",
                    "authority_ids", "authority_public_keys", "issued_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "registry_authority_private_key": {"type": "string"},
                    "minimum_approvals": {"type": "integer", "minimum": 2, "maximum": 100},
                    "authority_ids": {
                        "type": "array", "minItems": 2, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "authority_public_keys": {
                        "type": "array", "minItems": 2, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "issued_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_successor_governance",
            "Sign successor lifecycle gossip registry governance",
            "Use a distinct prospective registry-root private key to sign the exact successor threshold policy required for governed root rotation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "successor_registry_authority_private_key",
                    "minimum_approvals", "authority_ids", "authority_public_keys",
                    "issued_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "successor_registry_authority_private_key": {"type": "string"},
                    "minimum_approvals": {"type": "integer", "minimum": 2, "maximum": 100},
                    "authority_ids": {
                        "type": "array", "minItems": 2, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "authority_public_keys": {
                        "type": "array", "minItems": 2, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "issued_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition",
            "Sign lifecycle gossip registry threshold transition",
            "Create one admission, suspension, or revocation carrying a quorum of distinct governance-authority signatures.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "governance", "authority_ids", "authority_private_keys",
                    "action", "organization_id", "reason_sha256",
                    "effective_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "governance": {"type": "string"},
                    "authority_ids": {
                        "type": "array", "minItems": 2, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "authority_private_keys": {
                        "type": "array", "minItems": 2, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "action": {"enum": [
                        "admit-observer", "suspend-organization", "revoke-organization"
                    ]},
                    "organization_id": {"type": "string"},
                    "observer_trust_state": {"type": "string"},
                    "reason_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "effective_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition",
            "Apply lifecycle gossip registry threshold transition",
            "Verify root governance, distinct-authority quorum, signatures, and chain continuity before atomically advancing the registry.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["registry", "governance", "transition", "output"],
                "properties": {
                    "registry": {"type": "string"},
                    "governance": {"type": "string"},
                    "transition": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation",
            "Sign lifecycle gossip registry governance rotation",
            "Require valid retained and successor authority quorums over one exact governance change and registry generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "old_governance", "new_governance",
                    "old_authority_ids", "old_authority_private_keys",
                    "new_authority_ids", "new_authority_private_keys",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "old_governance": {"type": "string"},
                    "new_governance": {"type": "string"},
                    "old_authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "old_authority_private_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "new_authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "new_authority_private_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation",
            "Apply lifecycle gossip registry governance rotation",
            "Verify both root-signed policies, both distinct authority quorums, and registry chain continuity before advancing one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["registry", "old_governance", "new_governance", "rotation", "output"],
                "properties": {
                    "registry": {"type": "string"},
                    "old_governance": {"type": "string"},
                    "new_governance": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation",
            "Sign governed lifecycle gossip registry root rotation",
            "Require retained and successor governance quorums over one exact registry-root, governance-digest, generation, and chain transition.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "old_governance", "new_governance",
                    "old_authority_ids", "old_authority_private_keys",
                    "new_authority_ids", "new_authority_private_keys",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "old_governance": {"type": "string"},
                    "new_governance": {"type": "string"},
                    "old_authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "old_authority_private_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "new_authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "new_authority_private_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation",
            "Apply governed lifecycle gossip registry root rotation",
            "Verify both root-signed policies, both authority quorums, new-root possession, and chain continuity before atomically replacing the root and active governance digest.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "old_governance", "new_governance", "rotation",
                    "output", "public_key_output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "old_governance": {"type": "string"},
                    "new_governance": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "audit_policy_lifecycle_public_log_gossip_organization_registry_history",
            "Audit complete lifecycle gossip registry history",
            "Replay every typed event from genesis, verify signatures, quorums, generations, time, and digest continuity, then atomically emit the audit and computed final registry.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["history", "output", "final_registry_output"],
                "properties": {
                    "history": {"type": "string"},
                    "output": {"type": "string"},
                    "final_registry_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint",
            "Sign lifecycle gossip registry history checkpoint",
            "Replay the complete registry history and root-sign its exact audit and final-state digests.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["history", "authority_private_key", "issued_at_unix", "output"],
                "properties": {
                    "history": {"type": "string"},
                    "authority_private_key": {"type": "string"},
                    "issued_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "accept_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint",
            "Accept lifecycle gossip registry history checkpoint",
            "Replay from genesis, verify the retained-root signature, reject equivocation or rollback, and pin the accepted checkpoint.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["history", "checkpoint", "accepted_at_unix", "output"],
                "properties": {
                    "history": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "baseline": {"type": "string"},
                    "accepted_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness",
            "Witness lifecycle gossip registry history checkpoint",
            "Independently replay and verify one exact registry-history checkpoint before signing an observer witness.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "history", "checkpoint", "witness_id",
                    "witness_private_key", "witnessed_at_unix", "output"
                ],
                "properties": {
                    "history": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "witness_id": {"type": "string"},
                    "witness_private_key": {"type": "string"},
                    "witnessed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witnesses",
            "Verify lifecycle gossip registry history checkpoint witnesses",
            "Verify fresh signatures from distinct trusted witnesses over one exact audited checkpoint and optionally require quorum.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "history", "checkpoint", "witnesses", "evaluated_at_unix", "output"
                ],
                "oneOf": [
                    {"required": ["trusted_witness_ids", "trusted_witness_public_keys"]},
                    {"required": ["witness_trust_states"]}
                ],
                "properties": {
                    "history": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "witnesses": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "trusted_witness_ids": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "trusted_witness_public_keys": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "witness_trust_states": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "minimum_witnesses": {
                        "type": "integer", "minimum": 2, "maximum": 100,
                        "default": 2
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "require_quorum": {"type": "boolean", "default": false},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        open_world_tool(
            "request_remote_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness",
            "Request remote registry history checkpoint witness",
            "POST one accepted complete registry-history checkpoint to bounded HTTPS and immediately verify the response against a direct or rotatable witness key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "checkpoint_trust_state", "endpoint", "evaluated_at_unix",
                    "output", "receipt_output"
                ],
                "oneOf": [
                    {"required": ["public_key"]},
                    {"required": ["witness_key_trust_state"]}
                ],
                "properties": {
                    "checkpoint_trust_state": {"type": "string"},
                    "endpoint": {"type": "string", "pattern": "^https://"},
                    "public_key": {"type": "string"},
                    "witness_key_trust_state": {"type": "string"},
                    "bearer_token_env": {
                        "type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"
                    },
                    "timeout_seconds": {
                        "type": "integer", "minimum": 1, "maximum": 600, "default": 30
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "receipt_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "init_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_trust",
            "Initialize registry history witness trust",
            "Pin one witness identity to its initial Ed25519 public key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["witness_id", "public_key", "output"],
                "properties": {
                    "witness_id": {"type": "string"},
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation",
            "Sign registry history witness key rotation",
            "Require both current-key authorization and successor-key possession for one exact next generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "old_private_key", "new_private_key",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "trust_state": {"type": "string"},
                    "old_private_key": {"type": "string"},
                    "new_private_key": {"type": "string"},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation",
            "Apply registry history witness key rotation",
            "Verify both signatures and chain continuity before atomically advancing trust and exporting the key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "rotation", "output", "public_key_output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "export_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key",
            "Export registry history witness key",
            "Validate a witness trust state and export its current public key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_policy_lifecycle_public_log_gossip_quorum",
            "Verify policy lifecycle public-log gossip quorum",
            "Freshly verify paired observations from distinct trusted organizations and retain deterministic evidence even when the required organization quorum is not met.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "local_anchor", "observations", "log_id",
                    "log_public_key", "evaluated_at_unix", "output"
                ],
                "oneOf": [
                    {
                        "required": [
                            "organization_ids", "observer_ids", "observer_public_keys"
                        ]
                    },
                    {"required": ["observer_trust_states"]}
                ],
                "properties": {
                    "local_anchor": {"type": "string"},
                    "observations": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "organization_ids": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {
                            "type": "string", "minLength": 1, "maxLength": 128,
                            "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                        }
                    },
                    "observer_ids": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {
                            "type": "string", "minLength": 1, "maxLength": 128,
                            "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                        }
                    },
                    "observer_public_keys": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "observer_trust_states": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "organization_trust_registry": {"type": "string"},
                    "minimum_organizations": {
                        "type": "integer", "minimum": 2, "maximum": 100
                    },
                    "log_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                    },
                    "log_public_key": {"type": "string"},
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "require_quorum": {"type": "boolean"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        open_world_tool(
            "request_remote_policy_lifecycle_public_log_gossip",
            "Request remote policy lifecycle public-log gossip",
            "Acquire one observation from bounded HTTPS, immediately verify its log and observer signatures plus consistency proof, and retain a hash-bound transport receipt.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "local_anchor", "endpoint", "log_id", "log_public_key",
                    "evaluated_at_unix", "output", "receipt_output"
                ],
                "oneOf": [
                    {
                        "required": [
                            "organization_id", "observer_id", "observer_public_key"
                        ]
                    },
                    {"required": ["observer_trust_state"]}
                ],
                "properties": {
                    "local_anchor": {"type": "string"},
                    "endpoint": {"type": "string", "pattern": "^https://"},
                    "log_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                    },
                    "log_public_key": {"type": "string"},
                    "organization_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                    },
                    "observer_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
                    },
                    "observer_public_key": {"type": "string"},
                    "observer_trust_state": {"type": "string"},
                    "bearer_token_env": {"type": "string"},
                    "timeout_seconds": {
                        "type": "integer", "minimum": 1, "maximum": 600
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "receipt_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
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
                        "signed-policy-pack",
                        "remote-registry-history-checkpoint-witness-receipt",
                        "remote-approval-registry-history-checkpoint-witness-receipt"
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
            "append_verified_remote_approval_registry_history_witness_receipt",
            "Verify and append approval registry witness receipt",
            "Rebind a transport receipt to retained checkpoint, witness trust, exact response bytes, and an Ed25519 signature before appending it.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "receipt", "checkpoint_trust_state", "response", "output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "receipt": {"type": "string"},
                    "checkpoint_trust_state": {"type": "string"},
                    "response": {"type": "string"},
                    "public_key": {"type": "string"},
                    "witness_key_trust_state": {"type": "string"},
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "recorded_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                },
                "oneOf": [
                    {"required": ["public_key"], "not": {"required": ["witness_key_trust_state"]}},
                    {"required": ["witness_key_trust_state"], "not": {"required": ["public_key"]}}
                ]
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "append_verified_remote_approval_registry_history_witness_receipt_quorum",
            "Verify and append approval registry witness receipt quorum",
            "Atomically append only after distinct trusted witnesses, keys, exact responses, freshness, and signatures meet the configured quorum.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "receipts", "checkpoint_trust_state", "responses",
                    "output", "report_output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "receipts": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "checkpoint_trust_state": {"type": "string"},
                    "responses": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "trusted_witness_ids": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "trusted_witness_public_keys": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "witness_key_trust_states": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "minimum_witnesses": {
                        "type": "integer", "minimum": 2, "maximum": 100, "default": 2
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "recorded_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "report_output": {"type": "string"}
                },
                "oneOf": [
                    {
                        "required": [
                            "trusted_witness_ids", "trusted_witness_public_keys"
                        ],
                        "not": {"required": ["witness_key_trust_states"]}
                    },
                    {
                        "required": ["witness_key_trust_states"],
                        "not": {
                            "anyOf": [
                                {"required": ["trusted_witness_ids"]},
                                {"required": ["trusted_witness_public_keys"]}
                            ]
                        }
                    }
                ]
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_quorum_bound_approval_transparency_log",
            "Sign quorum-bound approval-log checkpoint",
            "Create an Ed25519 checkpoint only when the exact log suffix matches a successful verifier-bound remote receipt quorum report.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["log", "quorum_report", "private_key", "signer_id", "output"],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
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
            "init_approval_transparency_witness_trust",
            "Initialize witness key trust",
            "Create generation-zero trust state for one approval-log witness identity and public key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["witness_id", "public_key", "output"],
                "properties": {
                    "witness_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_witness_key_rotation",
            "Sign witness key rotation",
            "Create an old-key authorization plus new-key possession proof for exactly one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "old_private_key", "new_private_key", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "old_private_key": {"type": "string"},
                    "new_private_key": {"type": "string"},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_approval_transparency_witness_key_rotation",
            "Apply witness key rotation",
            "Verify both signatures and advance a hash-chained witness trust state by one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "rotation", "output", "public_key_output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "export_approval_transparency_witness_public_key",
            "Export current witness key",
            "Strictly validate a witness trust state and export its current public key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "create_approval_transparency_public_anchor",
            "Create approval public-log anchor",
            "Build and sign an RFC 6962-style Merkle inclusion proof over an ordered checkpoint snapshot.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "checkpoint", "log_checkpoints", "leaf_index", "log_id",
                    "private_key", "output"
                ],
                "properties": {
                    "checkpoint": {"type": "string"},
                    "log_checkpoints": {
                        "type": "array", "minItems": 1, "maxItems": 100000,
                        "items": {"type": "string"}
                    },
                    "leaf_index": {"type": "integer", "minimum": 0},
                    "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "private_key": {"type": "string"},
                    "observed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_approval_transparency_public_anchor",
            "Verify approval public-log anchor",
            "Verify checkpoint inclusion, the exact Merkle root, and a separately trusted signed tree head.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["checkpoint", "proof", "public_key", "output"],
                "properties": {
                    "checkpoint": {"type": "string"},
                    "proof": {"type": "string"},
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "create_approval_transparency_public_log_consistency",
            "Create approval public-log consistency proof",
            "Build an RFC 6962-style proof that a newer signed tree head extends a previously accepted anchor.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["old_anchor", "new_anchor", "log_checkpoints", "output"],
                "properties": {
                    "old_anchor": {"type": "string"},
                    "new_anchor": {"type": "string"},
                    "log_checkpoints": {
                        "type": "array", "minItems": 1, "maxItems": 100000,
                        "items": {"type": "string"}
                    },
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_approval_transparency_public_log_consistency",
            "Verify approval public-log consistency",
            "Verify both accepted anchors, signed tree heads, and the minimal path proving append-only prefix extension.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["old_anchor", "new_anchor", "proof", "public_key", "output"],
                "properties": {
                    "old_anchor": {"type": "string"},
                    "new_anchor": {"type": "string"},
                    "proof": {"type": "string"},
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_receipt",
            "Sign approval public-log gossip receipt",
            "Independently re-sign one trusted signed tree head with a bounded observation lifetime.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "anchor", "log_public_key", "observer_id", "observer_private_key",
                    "received_at_unix", "expires_at_unix", "output"
                ],
                "properties": {
                    "anchor": {"type": "string"},
                    "log_public_key": {"type": "string"},
                    "observer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "observer_private_key": {"type": "string"},
                    "received_at_unix": {"type": "integer", "minimum": 0},
                    "expires_at_unix": {"type": "integer", "minimum": 1},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_approval_transparency_public_log_gossip_receipt",
            "Verify approval public-log gossip receipt",
            "Compare an independently signed tree-head observation with a local anchor and require consistency for different sizes.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "local_anchor", "receipt", "log_public_key", "observer_id",
                    "observer_public_key", "evaluated_at_unix", "output"
                ],
                "properties": {
                    "local_anchor": {"type": "string"},
                    "receipt": {"type": "string"},
                    "consistency_proof": {"type": "string"},
                    "log_public_key": {"type": "string"},
                    "observer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "observer_public_key": {"type": "string"},
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_approval_transparency_public_log_gossip_quorum",
            "Verify approval public-log gossip quorum",
            "Freshly verify paired observations from distinct trusted organizations and enforce a bounded organization threshold.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "local_anchor", "observations", "log_public_key",
                    "evaluated_at_unix", "output"
                ],
                "oneOf": [
                    {"required": ["organization_ids", "observer_ids", "observer_public_keys"]},
                    {"required": ["observer_trust_states"]}
                ],
                "properties": {
                    "local_anchor": {"type": "string"},
                    "observations": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "organization_ids": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"}
                    },
                    "observer_ids": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"}
                    },
                    "observer_public_keys": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "observer_trust_states": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string"}
                    },
                    "organization_registry": {"type": "string"},
                    "minimum_organizations": {"type": "integer", "minimum": 2, "maximum": 100},
                    "log_public_key": {"type": "string"},
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "require_quorum": {"type": "boolean"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        open_world_tool(
            "request_remote_approval_transparency_public_log_gossip",
            "Request remote approval public-log gossip",
            "Acquire one bounded HTTPS observation, verify both signatures and append-only consistency, and retain hash-bound transport evidence.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "local_anchor", "endpoint", "log_public_key", "evaluated_at_unix",
                    "output", "receipt_output"
                ],
                "oneOf": [
                    {"required": ["organization_id", "observer_id", "observer_public_key"]},
                    {"required": ["observer_trust_state"]}
                ],
                "properties": {
                    "local_anchor": {"type": "string"},
                    "endpoint": {"type": "string", "pattern": "^https://"},
                    "log_public_key": {"type": "string"},
                    "organization_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "observer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "observer_public_key": {"type": "string"},
                    "observer_trust_state": {"type": "string"},
                    "bearer_token_env": {"type": "string"},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600},
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "receipt_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "init_approval_transparency_public_log_gossip_observer_trust",
            "Initialize approval gossip observer trust",
            "Create generation-zero trust binding one organization and observer identity to its current Ed25519 key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["organization_id", "observer_id", "public_key", "output"],
                "properties": {
                    "organization_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
                    "observer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_observer_key_rotation",
            "Sign approval gossip observer key rotation",
            "Create old-key authorization and new-key possession proof for one exact observer generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "old_private_key", "new_private_key",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "trust_state": {"type": "string"},
                    "old_private_key": {"type": "string"},
                    "new_private_key": {"type": "string"},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_approval_transparency_public_log_gossip_observer_key_rotation",
            "Apply approval gossip observer key rotation",
            "Verify both signatures and advance one digest-chained observer trust state by exactly one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "rotation", "output", "public_key_output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "export_approval_transparency_public_log_gossip_observer_key",
            "Export approval gossip observer key",
            "Validate an observer trust state and export its current public key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "init_approval_transparency_public_log_gossip_organization_registry",
            "Initialize approval gossip organization registry",
            "Create an empty generation-zero registry bound to one Ed25519 authority key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["registry_id", "authority_public_key", "output"],
                "properties": {
                    "registry_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
                    "authority_public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_transition",
            "Sign approval gossip organization registry transition",
            "Authority-sign one observer admission, organization suspension, or permanent revocation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "authority_private_key", "action", "organization_id",
                    "reason_sha256", "effective_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "authority_private_key": {"type": "string"},
                    "action": {"enum": [
                        "admit-observer", "suspend-organization", "revoke-organization"
                    ]},
                    "organization_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
                    "observer_trust_state": {"type": "string"},
                    "reason_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "effective_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_approval_transparency_public_log_gossip_organization_registry_transition",
            "Apply approval gossip organization registry transition",
            "Verify authority signature and chain continuity, then advance registry state by exactly one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["registry", "transition", "output"],
                "properties": {
                    "registry": {"type": "string"},
                    "transition": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_authority_key_rotation",
            "Sign approval gossip registry authority rotation",
            "Require the retained authority and successor authority to dual-sign one exact generation- and digest-chained trust-root transition.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "old_private_key", "new_private_key",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "old_private_key": {"type": "string"},
                    "new_private_key": {"type": "string"},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_approval_transparency_public_log_gossip_organization_registry_authority_key_rotation",
            "Apply approval gossip registry authority rotation",
            "Verify old-key authorization, new-key possession, and exact chain continuity while preserving every organization admission and status.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["registry", "rotation", "output", "public_key_output"],
                "properties": {
                    "registry": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_governance",
            "Sign approval gossip registry governance",
            "Root-sign an exact threshold over ordered distinct approval registry authority identities and keys.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "registry_authority_private_key", "minimum_approvals",
                    "authority_ids", "authority_public_keys", "issued_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "registry_authority_private_key": {"type": "string"},
                    "minimum_approvals": {"type": "integer", "minimum": 2, "maximum": 100},
                    "authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "authority_public_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "issued_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_successor_governance",
            "Sign successor approval gossip registry governance",
            "Use a distinct prospective registry-root private key to sign the successor threshold policy required for governed root rotation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "successor_registry_authority_private_key",
                    "minimum_approvals", "authority_ids", "authority_public_keys",
                    "issued_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "successor_registry_authority_private_key": {"type": "string"},
                    "minimum_approvals": {"type": "integer", "minimum": 2, "maximum": 100},
                    "authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "authority_public_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "issued_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_threshold_transition",
            "Sign governed approval gossip registry transition",
            "Create a generation- and digest-chained registry operation approved by a distinct-key authority quorum.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "governance", "authority_ids", "authority_private_keys",
                    "action", "organization_id", "reason_sha256", "effective_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "governance": {"type": "string"},
                    "authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "authority_private_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "action": {"enum": ["admit-observer", "suspend-organization", "revoke-organization"]},
                    "organization_id": {"type": "string"},
                    "observer_trust_state": {"type": "string"},
                    "reason_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "effective_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_approval_transparency_public_log_gossip_organization_registry_threshold_transition",
            "Apply governed approval gossip registry transition",
            "Verify root governance, distinct trusted quorum signatures, and retained chain continuity before atomically advancing registry state.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["registry", "governance", "transition", "output"],
                "properties": {
                    "registry": {"type": "string"},
                    "governance": {"type": "string"},
                    "transition": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_governance_rotation",
            "Sign approval gossip governance rotation",
            "Require retained and successor governance quorums to approve one exact policy replacement.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "old_governance", "new_governance",
                    "old_authority_ids", "old_authority_private_keys",
                    "new_authority_ids", "new_authority_private_keys",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "old_governance": {"type": "string"},
                    "new_governance": {"type": "string"},
                    "old_authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "old_authority_private_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "new_authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "new_authority_private_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_approval_transparency_public_log_gossip_organization_registry_governance_rotation",
            "Apply approval gossip governance rotation",
            "Verify both distinct-key quorums and atomically replace retained governance while preserving organization state.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "old_governance", "new_governance", "rotation", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "old_governance": {"type": "string"},
                    "new_governance": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_governed_authority_key_rotation",
            "Sign governed approval gossip registry root rotation",
            "Require retained and successor governance quorums over one exact root, governance, generation, and chain transition.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "old_governance", "new_governance",
                    "old_authority_ids", "old_authority_private_keys",
                    "new_authority_ids", "new_authority_private_keys",
                    "rotated_at_unix", "output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "old_governance": {"type": "string"},
                    "new_governance": {"type": "string"},
                    "old_authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "old_authority_private_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "new_authority_ids": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "new_authority_private_keys": {"type": "array", "minItems": 2, "maxItems": 100, "items": {"type": "string"}},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_approval_transparency_public_log_gossip_organization_registry_governed_authority_key_rotation",
            "Apply governed approval gossip registry root rotation",
            "Verify both root-signed policies, both quorums, new-root possession, and chain continuity before atomically replacing the root and active governance.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "registry", "old_governance", "new_governance", "rotation",
                    "output", "public_key_output"
                ],
                "properties": {
                    "registry": {"type": "string"},
                    "old_governance": {"type": "string"},
                    "new_governance": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "audit_approval_transparency_public_log_gossip_organization_registry_history",
            "Audit complete approval gossip registry history",
            "Replay every typed event from genesis, verify signatures, quorums, generations, time, and digest continuity, then atomically emit the audit and computed final registry.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["history", "output", "registry_output"],
                "properties": {
                    "history": {"type": "string"},
                    "output": {"type": "string"},
                    "registry_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint",
            "Sign approval gossip registry history checkpoint",
            "Replay a complete history and sign its exact final state with the retained registry root.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["history", "authority_private_key", "issued_at_unix", "output"],
                "properties": {
                    "history": {"type": "string"},
                    "authority_private_key": {"type": "string"},
                    "issued_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "accept_approval_transparency_public_log_gossip_organization_registry_history_checkpoint",
            "Accept approval gossip registry history checkpoint",
            "Verify from genesis and pin or monotonically advance local checkpoint trust.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["history", "checkpoint", "accepted_at_unix", "output"],
                "properties": {
                    "history": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "baseline": {"type": "string"},
                    "accepted_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness",
            "Witness approval gossip registry history checkpoint",
            "Independently replay the history and sign one exact retained-root checkpoint.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["history", "checkpoint", "witness_id", "witness_private_key", "witnessed_at_unix", "output"],
                "properties": {
                    "history": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "witness_id": {"type": "string"},
                    "witness_private_key": {"type": "string"},
                    "witnessed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "init_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_trust",
            "Initialize approval history witness trust",
            "Pin generation-zero identity-bound public-key trust for one checkpoint witness.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["witness_id", "public_key", "output"],
                "properties": {
                    "witness_id": {"type": "string"},
                    "public_key": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation",
            "Sign approval history witness key rotation",
            "Require retained-key authorization and successor-key possession for one exact generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "old_private_key", "new_private_key", "rotated_at_unix", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "old_private_key": {"type": "string"},
                    "new_private_key": {"type": "string"},
                    "rotated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "apply_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation",
            "Apply approval history witness key rotation",
            "Verify both signatures and atomically advance the identity-bound witness trust state.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "rotation", "output", "public_key_output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"},
                    "public_key_output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "export_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key",
            "Export approval history witness key",
            "Validate a witness trust state and export its current trusted public key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            true,
            false,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witnesses",
            "Verify approval gossip registry history checkpoint witnesses",
            "Verify fresh, distinct witnesses using either direct keys or rotatable trust states.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "history", "checkpoint", "witnesses", "evaluated_at_unix", "output"
                ],
                "oneOf": [
                    {"required": ["trusted_witness_ids", "trusted_witness_public_keys"]},
                    {"required": ["witness_trust_states"]}
                ],
                "properties": {
                    "history": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "witnesses": {"type": "array", "minItems": 1, "maxItems": 100, "items": {"type": "string"}},
                    "trusted_witness_ids": {"type": "array", "minItems": 1, "maxItems": 100, "items": {"type": "string"}},
                    "trusted_witness_public_keys": {"type": "array", "minItems": 1, "maxItems": 100, "items": {"type": "string"}},
                    "witness_trust_states": {"type": "array", "minItems": 1, "maxItems": 100, "items": {"type": "string"}},
                    "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": 100, "default": 2},
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "require_quorum": {"type": "boolean", "default": false},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        open_world_tool(
            "request_remote_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness",
            "Request remote approval registry history witness",
            "POST one accepted history checkpoint to bounded HTTPS and immediately verify the response against a direct or rotatable witness key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "checkpoint_trust_state", "endpoint", "evaluated_at_unix",
                    "output", "receipt_output"
                ],
                "oneOf": [
                    {"required": ["public_key"]},
                    {"required": ["witness_key_trust_state"]}
                ],
                "properties": {
                    "checkpoint_trust_state": {"type": "string"},
                    "endpoint": {"type": "string", "pattern": "^https://"},
                    "public_key": {"type": "string"},
                    "witness_key_trust_state": {"type": "string"},
                    "bearer_token_env": {
                        "type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"
                    },
                    "timeout_seconds": {
                        "type": "integer", "minimum": 1, "maximum": 600, "default": 30
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"},
                    "receipt_output": {"type": "string"}
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
        open_world_tool(
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

fn open_world_tool(
    name: &str,
    title: &str,
    description: &str,
    input_schema: Value,
    read_only: bool,
    destructive: bool,
    task_support: Option<&str>,
) -> Value {
    let mut definition = tool(
        name,
        title,
        description,
        input_schema,
        read_only,
        destructive,
        task_support,
    );
    definition["annotations"]["openWorldHint"] = Value::Bool(true);
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
        "fetch_policy_pack" => fetch_policy_pack(arguments, cancellation)?,
        "analyze_kicad" => analyze_kicad(arguments, cancellation)?,
        "compare_analysis" => compare_analysis(arguments, cancellation)?,
        "record_manufacturing_feedback" => record_manufacturing_feedback(arguments, cancellation)?,
        "compare_manufacturing_feedback" => {
            compare_manufacturing_feedback(arguments, cancellation)?
        }
        "recommend_policy" => recommend_policy(arguments, cancellation)?,
        "policy_rollout_profile" => policy_rollout_profile(arguments, cancellation)?,
        "simulate_policy_rollout" => simulate_policy_rollout(arguments, cancellation)?,
        "sign_rollout_approval" => sign_rollout_approval(arguments, cancellation)?,
        "verify_rollout_approvals" => verify_rollout_approvals(arguments, cancellation)?,
        "record_canary_monitoring" => record_canary_monitoring(arguments, cancellation)?,
        "sign_canary_completion" => sign_canary_completion(arguments, cancellation)?,
        "verify_canary_completion" => verify_canary_completion(arguments, cancellation)?,
        "advance_policy_deployment" => advance_policy_deployment(arguments, cancellation)?,
        "verify_policy_deployment" => verify_policy_deployment(arguments, cancellation)?,
        "sign_policy_deployment_rollback" => {
            sign_policy_deployment_rollback(arguments, cancellation)?
        }
        "apply_policy_deployment_rollback" => {
            apply_policy_deployment_rollback(arguments, cancellation)?
        }
        "verify_policy_rollback_recovery" => {
            verify_policy_rollback_recovery(arguments, cancellation)?
        }
        "sign_rollback_incident_acknowledgment" => {
            sign_rollback_incident_acknowledgment(arguments, cancellation)?
        }
        "close_rollback_incident" => close_rollback_incident(arguments, cancellation)?,
        "append_policy_incident_ledger" => append_policy_incident_ledger(arguments, cancellation)?,
        "sign_policy_suspension_decision" => {
            sign_policy_suspension_decision(arguments, cancellation)?
        }
        "apply_policy_suspension_decision" => {
            apply_policy_suspension_decision(arguments, cancellation)?
        }
        "sign_policy_remediation_approval" => {
            sign_policy_remediation_approval(arguments, cancellation)?
        }
        "apply_policy_remediation" => apply_policy_remediation(arguments, cancellation)?,
        "append_policy_lifecycle_event" => append_policy_lifecycle_event(arguments, cancellation)?,
        "snapshot_policy_lifecycle" => snapshot_policy_lifecycle(arguments, cancellation)?,
        "sign_policy_lifecycle_checkpoint" => {
            sign_policy_lifecycle_checkpoint(arguments, cancellation)?
        }
        "verify_policy_lifecycle_checkpoint" => {
            verify_policy_lifecycle_checkpoint(arguments, cancellation)?
        }
        "sign_policy_lifecycle_key_rotation" => {
            sign_policy_lifecycle_key_rotation(arguments, cancellation)?
        }
        "witness_policy_lifecycle_checkpoint" => {
            witness_policy_lifecycle_checkpoint(arguments, cancellation)?
        }
        "init_policy_lifecycle_witness_trust" => {
            init_policy_lifecycle_witness_trust(arguments, cancellation)?
        }
        "sign_policy_lifecycle_witness_key_rotation" => {
            sign_policy_lifecycle_witness_key_rotation(arguments, cancellation)?
        }
        "apply_policy_lifecycle_witness_key_rotation" => {
            apply_policy_lifecycle_witness_key_rotation(arguments, cancellation)?
        }
        "export_policy_lifecycle_witness_public_key" => {
            export_policy_lifecycle_witness_public_key(arguments, cancellation)?
        }
        "verify_policy_lifecycle_checkpoint_witnesses" => {
            verify_policy_lifecycle_checkpoint_witnesses(arguments, cancellation)?
        }
        "request_remote_policy_lifecycle_checkpoint_witness" => {
            request_remote_policy_lifecycle_checkpoint_witness(arguments, cancellation)?
        }
        "create_policy_lifecycle_public_anchor" => {
            create_policy_lifecycle_public_anchor(arguments, cancellation)?
        }
        "verify_policy_lifecycle_public_anchor" => {
            verify_policy_lifecycle_public_anchor(arguments, cancellation)?
        }
        "create_policy_lifecycle_public_log_consistency" => {
            create_policy_lifecycle_public_log_consistency(arguments, cancellation)?
        }
        "verify_policy_lifecycle_public_log_consistency" => {
            verify_policy_lifecycle_public_log_consistency(arguments, cancellation)?
        }
        "sign_policy_lifecycle_public_log_gossip_receipt" => {
            sign_policy_lifecycle_public_log_gossip_receipt(arguments, cancellation)?
        }
        "verify_policy_lifecycle_public_log_gossip_receipt" => {
            verify_policy_lifecycle_public_log_gossip_receipt(arguments, cancellation)?
        }
        "init_policy_lifecycle_public_log_gossip_observer_trust" => {
            init_policy_lifecycle_public_log_gossip_observer_trust(arguments, cancellation)?
        }
        "sign_policy_lifecycle_public_log_gossip_observer_key_rotation" => {
            sign_policy_lifecycle_public_log_gossip_observer_key_rotation(arguments, cancellation)?
        }
        "apply_policy_lifecycle_public_log_gossip_observer_key_rotation" => {
            apply_policy_lifecycle_public_log_gossip_observer_key_rotation(arguments, cancellation)?
        }
        "export_policy_lifecycle_public_log_gossip_observer_key" => {
            export_policy_lifecycle_public_log_gossip_observer_key(arguments, cancellation)?
        }
        "init_policy_lifecycle_public_log_gossip_organization_registry" => {
            init_policy_lifecycle_public_log_gossip_organization_registry(arguments, cancellation)?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_transition" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_transition(
                arguments,
                cancellation,
            )?
        }
        "apply_policy_lifecycle_public_log_gossip_organization_registry_transition" => {
            apply_policy_lifecycle_public_log_gossip_organization_registry_transition(
                arguments,
                cancellation,
            )?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation" => {
            apply_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_governance" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_governance(
                arguments,
                cancellation,
            )?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_successor_governance" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_successor_governance(
                arguments,
                cancellation,
            )?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition(
                arguments,
                cancellation,
            )?
        }
        "apply_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition" => {
            apply_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition(
                arguments,
                cancellation,
            )?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation" => {
            apply_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation(
                arguments,
                cancellation,
            )?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation" => {
            apply_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "audit_policy_lifecycle_public_log_gossip_organization_registry_history" => {
            audit_policy_lifecycle_public_log_gossip_organization_registry_history(
                arguments,
                cancellation,
            )?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "accept_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint" => {
            accept_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness(
                arguments,
                cancellation,
            )?
        }
        "verify_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witnesses" => {
            verify_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witnesses(
                arguments,
                cancellation,
            )?
        }
        "request_remote_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness" => {
            request_remote_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness(
                arguments,
                cancellation,
            )?
        }
        "init_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_trust" => {
            init_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_trust(
                arguments, cancellation,
            )?
        }
        "sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation" => {
            sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
                arguments, cancellation,
            )?
        }
        "apply_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation" => {
            apply_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
                arguments, cancellation,
            )?
        }
        "export_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key" => {
            export_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key(
                arguments, cancellation,
            )?
        }
        "verify_policy_lifecycle_public_log_gossip_quorum" => {
            verify_policy_lifecycle_public_log_gossip_quorum(arguments, cancellation)?
        }
        "request_remote_policy_lifecycle_public_log_gossip" => {
            request_remote_policy_lifecycle_public_log_gossip(arguments, cancellation)?
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
        "append_verified_remote_approval_registry_history_witness_receipt" => {
            append_verified_remote_approval_registry_history_witness_receipt(
                arguments,
                cancellation,
            )?
        }
        "append_verified_remote_approval_registry_history_witness_receipt_quorum" => {
            append_verified_remote_approval_registry_history_witness_receipt_quorum(
                arguments,
                cancellation,
            )?
        }
        "sign_quorum_bound_approval_transparency_log" => {
            sign_quorum_bound_approval_transparency_log(arguments, cancellation)?
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
        "init_approval_transparency_witness_trust" => {
            init_approval_transparency_witness_trust(arguments, cancellation)?
        }
        "sign_approval_transparency_witness_key_rotation" => {
            sign_approval_transparency_witness_key_rotation(arguments, cancellation)?
        }
        "apply_approval_transparency_witness_key_rotation" => {
            apply_approval_transparency_witness_key_rotation(arguments, cancellation)?
        }
        "export_approval_transparency_witness_public_key" => {
            export_approval_transparency_witness_public_key(arguments, cancellation)?
        }
        "create_approval_transparency_public_anchor" => {
            create_approval_transparency_public_anchor(arguments, cancellation)?
        }
        "verify_approval_transparency_public_anchor" => {
            verify_approval_transparency_public_anchor(arguments, cancellation)?
        }
        "create_approval_transparency_public_log_consistency" => {
            create_approval_transparency_public_log_consistency(arguments, cancellation)?
        }
        "verify_approval_transparency_public_log_consistency" => {
            verify_approval_transparency_public_log_consistency(arguments, cancellation)?
        }
        "sign_approval_transparency_public_log_gossip_receipt" => {
            sign_approval_transparency_public_log_gossip_receipt(arguments, cancellation)?
        }
        "verify_approval_transparency_public_log_gossip_receipt" => {
            verify_approval_transparency_public_log_gossip_receipt(arguments, cancellation)?
        }
        "verify_approval_transparency_public_log_gossip_quorum" => {
            verify_approval_transparency_public_log_gossip_quorum(arguments, cancellation)?
        }
        "request_remote_approval_transparency_public_log_gossip" => {
            request_remote_approval_transparency_public_log_gossip(arguments, cancellation)?
        }
        "init_approval_transparency_public_log_gossip_observer_trust" => {
            init_approval_transparency_public_log_gossip_observer_trust(arguments, cancellation)?
        }
        "sign_approval_transparency_public_log_gossip_observer_key_rotation" => {
            sign_approval_transparency_public_log_gossip_observer_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_approval_transparency_public_log_gossip_observer_key_rotation" => {
            apply_approval_transparency_public_log_gossip_observer_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "export_approval_transparency_public_log_gossip_observer_key" => {
            export_approval_transparency_public_log_gossip_observer_key(arguments, cancellation)?
        }
        "init_approval_transparency_public_log_gossip_organization_registry" => {
            init_approval_transparency_public_log_gossip_organization_registry(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_transition" => {
            sign_approval_transparency_public_log_gossip_organization_registry_transition(
                arguments,
                cancellation,
            )?
        }
        "apply_approval_transparency_public_log_gossip_organization_registry_transition" => {
            apply_approval_transparency_public_log_gossip_organization_registry_transition(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_authority_key_rotation" => {
            sign_approval_transparency_public_log_gossip_organization_registry_authority_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_approval_transparency_public_log_gossip_organization_registry_authority_key_rotation" => {
            apply_approval_transparency_public_log_gossip_organization_registry_authority_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_governance" => {
            sign_approval_transparency_public_log_gossip_organization_registry_governance(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_successor_governance" => {
            sign_approval_transparency_public_log_gossip_organization_registry_successor_governance(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_threshold_transition" => {
            sign_approval_transparency_public_log_gossip_organization_registry_threshold_transition(
                arguments,
                cancellation,
            )?
        }
        "apply_approval_transparency_public_log_gossip_organization_registry_threshold_transition" => {
            apply_approval_transparency_public_log_gossip_organization_registry_threshold_transition(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_governance_rotation" => {
            sign_approval_transparency_public_log_gossip_organization_registry_governance_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_approval_transparency_public_log_gossip_organization_registry_governance_rotation" => {
            apply_approval_transparency_public_log_gossip_organization_registry_governance_rotation(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_governed_authority_key_rotation" => {
            sign_approval_transparency_public_log_gossip_organization_registry_governed_authority_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_approval_transparency_public_log_gossip_organization_registry_governed_authority_key_rotation" => {
            apply_approval_transparency_public_log_gossip_organization_registry_governed_authority_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "audit_approval_transparency_public_log_gossip_organization_registry_history" => {
            audit_approval_transparency_public_log_gossip_organization_registry_history(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint" => {
            sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "accept_approval_transparency_public_log_gossip_organization_registry_history_checkpoint" => {
            accept_approval_transparency_public_log_gossip_organization_registry_history_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness" => {
            sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness(
                arguments,
                cancellation,
            )?
        }
        "init_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_trust" => {
            init_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_trust(
                arguments,
                cancellation,
            )?
        }
        "sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation" => {
            sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation" => {
            apply_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "export_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key" => {
            export_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key(
                arguments,
                cancellation,
            )?
        }
        "verify_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witnesses" => {
            verify_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witnesses(
                arguments,
                cancellation,
            )?
        }
        "request_remote_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness" => {
            request_remote_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness(
                arguments,
                cancellation,
            )?
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

fn fetch_policy_pack(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "endpoint",
            "public_key",
            "baseline_state",
            "bearer_token_env",
            "timeout_seconds",
            "signed_output",
            "output",
            "state_output",
            "receipt_output",
        ],
    )?;
    let signed_output = required_string(&arguments, "signed_output")?;
    let output = required_string(&arguments, "output")?;
    let state_output = required_string(&arguments, "state_output")?;
    let receipt_output = required_string(&arguments, "receipt_output")?;
    let mut command = vec![
        "fetch-policy-pack".into(),
        "--endpoint".into(),
        required_string(&arguments, "endpoint")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--signed-output".into(),
        signed_output.clone(),
        "--output".into(),
        output.clone(),
        "--state-output".into(),
        state_output.clone(),
        "--receipt-output".into(),
        receipt_output.clone(),
    ];
    optional_option(
        &arguments,
        "baseline_state",
        "--baseline-state",
        &mut command,
    )?;
    optional_option(
        &arguments,
        "bearer_token_env",
        "--bearer-token-env",
        &mut command,
    )?;
    if let Some(timeout) = arguments.get("timeout_seconds") {
        let timeout = timeout
            .as_u64()
            .filter(|timeout| (1..=600).contains(timeout))
            .ok_or_else(|| json!({"detail": "timeout_seconds must be an integer from 1 to 600"}))?;
        command.extend(["--timeout-seconds".into(), timeout.to_string()]);
    }
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(
        execution,
        json!({
            "signed_output": signed_output,
            "output": output,
            "state_output": state_output,
            "receipt_output": receipt_output,
            "signed_policy_pack": read_json_if_present(Path::new(&signed_output)),
            "policy_pack": read_json_if_present(Path::new(&output)),
            "trust_state": read_json_if_present(Path::new(&state_output)),
            "receipt": read_json_if_present(Path::new(&receipt_output))
        }),
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

fn recommend_policy(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "policy_pack",
            "feedback",
            "analysis_manifests",
            "generated_on",
            "minimum_occurrences",
            "output",
            "summary_output",
        ],
    )?;
    let feedback = required_string_array(&arguments, "feedback", false)?;
    let manifests = required_string_array(&arguments, "analysis_manifests", false)?;
    if feedback.len() != manifests.len() {
        return Err(json!({
            "detail": "feedback and analysis_manifests must contain the same number of paths"
        }));
    }
    if feedback.len() > 1_000 {
        return Err(json!({"detail": "feedback cannot exceed 1000 entries"}));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "recommend-policy".into(),
        required_string(&arguments, "policy_pack")?,
    ];
    for path in feedback {
        command.extend(["--feedback".into(), path]);
    }
    for path in manifests {
        command.extend(["--analysis-manifest".into(), path]);
    }
    command.extend([
        "--generated-on".into(),
        required_string(&arguments, "generated_on")?,
    ]);
    if let Some(value) = arguments.get("minimum_occurrences") {
        let value = value
            .as_u64()
            .filter(|value| (2..=100).contains(value))
            .ok_or_else(
                || json!({"detail": "minimum_occurrences must be an integer from 2 to 100"}),
            )?;
        command.extend(["--minimum-occurrences".into(), value.to_string()]);
    }
    command.extend(["--output".into(), output.clone()]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let recommendation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "recommendation": recommendation}),
    ))
}

fn policy_rollout_profile(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["policy_pack", "recommendation", "generated_on", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "policy-rollout-profile".into(),
        required_string(&arguments, "policy_pack")?,
        required_string(&arguments, "recommendation")?,
        "--generated-on".into(),
        required_string(&arguments, "generated_on")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let profile = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "profile": profile}),
    ))
}

fn simulate_policy_rollout(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "policy_pack",
            "recommendation",
            "project_ids",
            "boards",
            "baseline_analyses",
            "candidate_analyses",
            "generated_on",
            "output",
            "summary_output",
        ],
    )?;
    let project_ids = required_string_array(&arguments, "project_ids", false)?;
    let boards = required_string_array(&arguments, "boards", false)?;
    let baselines = required_string_array(&arguments, "baseline_analyses", false)?;
    let candidates = required_string_array(&arguments, "candidate_analyses", false)?;
    if project_ids.len() != boards.len()
        || project_ids.len() != baselines.len()
        || project_ids.len() != candidates.len()
    {
        return Err(json!({
            "detail": "project_ids, boards, baseline_analyses, and candidate_analyses must have equal lengths"
        }));
    }
    if project_ids.len() > 1_000 {
        return Err(json!({"detail": "policy rollout cannot exceed 1000 projects"}));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "simulate-policy-rollout".into(),
        required_string(&arguments, "policy_pack")?,
        required_string(&arguments, "recommendation")?,
    ];
    for project_id in project_ids {
        command.extend(["--project-id".into(), project_id]);
    }
    for board in boards {
        command.extend(["--board".into(), board]);
    }
    for baseline in baselines {
        command.extend(["--baseline-analysis".into(), baseline]);
    }
    for candidate in candidates {
        command.extend(["--candidate-analysis".into(), candidate]);
    }
    command.extend([
        "--generated-on".into(),
        required_string(&arguments, "generated_on")?,
        "--output".into(),
        output.clone(),
    ]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let rollout = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rollout": rollout}),
    ))
}

fn sign_rollout_approval(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollout",
            "canary_projects",
            "valid_from_unix",
            "expires_at_unix",
            "private_key",
            "signer_id",
            "decision",
            "reason",
            "ticket",
            "output",
        ],
    )?;
    let projects = required_string_array(&arguments, "canary_projects", false)?;
    if projects.len() > 100 {
        return Err(json!({"detail": "canary_projects cannot exceed 100 entries"}));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-rollout-approval".into(),
        required_string(&arguments, "rollout")?,
    ];
    for project in projects {
        command.extend(["--canary-project".into(), project]);
    }
    for (name, option) in [
        ("valid_from_unix", "--valid-from-unix"),
        ("expires_at_unix", "--expires-at-unix"),
    ] {
        let value = arguments
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| json!({"detail": format!("{name} must be an unsigned integer")}))?;
        command.extend([option.into(), value.to_string()]);
    }
    for (name, option) in [
        ("private_key", "--private-key"),
        ("signer_id", "--signer-id"),
        ("decision", "--decision"),
        ("reason", "--reason"),
        ("ticket", "--ticket"),
    ] {
        command.extend([option.into(), required_string(&arguments, name)?]);
    }
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let approval = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "approval": approval}),
    ))
}

fn verify_rollout_approvals(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollout",
            "policy_pack",
            "approvals",
            "evaluated_at_unix",
            "minimum_approvals",
            "output",
            "summary_output",
            "require_authorized",
        ],
    )?;
    let approvals = required_string_array(&arguments, "approvals", false)?;
    if approvals.len() > 100 {
        return Err(json!({"detail": "approvals cannot exceed 100 entries"}));
    }
    let evaluated = arguments
        .get("evaluated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "evaluated_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-rollout-approvals".into(),
        required_string(&arguments, "rollout")?,
        "--policy-pack".into(),
        required_string(&arguments, "policy_pack")?,
    ];
    for approval in approvals {
        command.extend(["--approval".into(), approval]);
    }
    command.extend(["--evaluated-at-unix".into(), evaluated.to_string()]);
    if let Some(value) = arguments.get("minimum_approvals") {
        let value = value
            .as_u64()
            .filter(|value| (2..=100).contains(value))
            .ok_or_else(
                || json!({"detail": "minimum_approvals must be an integer from 2 to 100"}),
            )?;
        command.extend(["--minimum-approvals".into(), value.to_string()]);
    }
    command.extend(["--output".into(), output.clone()]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_authorized",
        "--require-authorized",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let authorization = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "authorization": authorization}),
    ))
}

fn record_canary_monitoring(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollout",
            "authorization",
            "project_ids",
            "boards",
            "baseline_analyses",
            "observed_analyses",
            "observed_at_unix",
            "output",
            "summary_output",
            "require_passed",
        ],
    )?;
    let project_ids = required_string_array(&arguments, "project_ids", false)?;
    let boards = required_string_array(&arguments, "boards", false)?;
    let baselines = required_string_array(&arguments, "baseline_analyses", false)?;
    let observed = required_string_array(&arguments, "observed_analyses", false)?;
    if project_ids.len() > 100
        || project_ids.len() != boards.len()
        || project_ids.len() != baselines.len()
        || project_ids.len() != observed.len()
    {
        return Err(json!({"detail": "canary monitoring arrays must pair 1 to 100 entries"}));
    }
    let observed_at = arguments
        .get("observed_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "observed_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "record-canary-monitoring".into(),
        required_string(&arguments, "rollout")?,
        required_string(&arguments, "authorization")?,
    ];
    for value in project_ids {
        command.extend(["--project-id".into(), value]);
    }
    for value in boards {
        command.extend(["--board".into(), value]);
    }
    for value in baselines {
        command.extend(["--baseline-analysis".into(), value]);
    }
    for value in observed {
        command.extend(["--observed-analysis".into(), value]);
    }
    command.extend([
        "--observed-at-unix".into(),
        observed_at.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_passed",
        "--require-passed",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let monitoring = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "monitoring": monitoring}),
    ))
}

fn sign_canary_completion(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollout",
            "monitoring",
            "authorization",
            "decision",
            "decided_at_unix",
            "private_key",
            "signer_id",
            "reason",
            "ticket",
            "output",
        ],
    )?;
    let decision = required_string(&arguments, "decision")?;
    if !matches!(decision.as_str(), "promote" | "rollback") {
        return Err(json!({"detail": "decision must be promote or rollback"}));
    }
    let decided_at = arguments
        .get("decided_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "decided_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-canary-completion".into(),
        required_string(&arguments, "rollout")?,
        required_string(&arguments, "monitoring")?,
        required_string(&arguments, "authorization")?,
        "--decision".into(),
        decision,
        "--decided-at-unix".into(),
        decided_at.to_string(),
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--signer-id".into(),
        required_string(&arguments, "signer_id")?,
        "--reason".into(),
        required_string(&arguments, "reason")?,
        "--ticket".into(),
        required_string(&arguments, "ticket")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let decision = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "decision": decision}),
    ))
}

fn verify_canary_completion(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollout",
            "monitoring",
            "authorization",
            "policy_pack",
            "decisions",
            "minimum_decisions",
            "output",
            "summary_output",
            "require_finalized",
        ],
    )?;
    let decisions = required_string_array(&arguments, "decisions", false)?;
    if decisions.len() > 100 {
        return Err(json!({"detail": "decisions cannot exceed 100 entries"}));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-canary-completion".into(),
        required_string(&arguments, "rollout")?,
        required_string(&arguments, "monitoring")?,
        required_string(&arguments, "authorization")?,
        "--policy-pack".into(),
        required_string(&arguments, "policy_pack")?,
    ];
    for decision in decisions {
        command.extend(["--decision".into(), decision]);
    }
    if let Some(value) = arguments.get("minimum_decisions") {
        let value = value
            .as_u64()
            .filter(|value| (2..=100).contains(value))
            .ok_or_else(|| json!({"detail": "minimum_decisions must be 2 to 100"}))?;
        command.extend(["--minimum-decisions".into(), value.to_string()]);
    }
    command.extend(["--output".into(), output.clone()]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_finalized",
        "--require-finalized",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let completion = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "completion": completion}),
    ))
}

fn advance_policy_deployment(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollout",
            "monitoring",
            "authorization",
            "policy_pack",
            "candidate_policy_pack",
            "source_policy_trust_state",
            "candidate_policy_trust_state",
            "decisions",
            "minimum_decisions",
            "baseline_state",
            "suspension_states",
            "remediation_states",
            "policy_lifecycle_ledgers",
            "recorded_at_unix",
            "output",
            "summary_output",
            "require_promotion",
        ],
    )?;
    let decisions = required_string_array(&arguments, "decisions", false)?;
    if decisions.len() > 100 {
        return Err(json!({"detail": "decisions cannot exceed 100 entries"}));
    }
    let recorded_at = arguments
        .get("recorded_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "recorded_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "advance-policy-deployment".into(),
        required_string(&arguments, "rollout")?,
        required_string(&arguments, "monitoring")?,
        required_string(&arguments, "authorization")?,
        "--policy-pack".into(),
        required_string(&arguments, "policy_pack")?,
        "--candidate-policy-pack".into(),
        required_string(&arguments, "candidate_policy_pack")?,
        "--source-policy-trust-state".into(),
        required_string(&arguments, "source_policy_trust_state")?,
        "--candidate-policy-trust-state".into(),
        required_string(&arguments, "candidate_policy_trust_state")?,
    ];
    for decision in decisions {
        command.extend(["--decision".into(), decision]);
    }
    if let Some(value) = arguments.get("minimum_decisions") {
        let value = value
            .as_u64()
            .filter(|value| (2..=100).contains(value))
            .ok_or_else(|| json!({"detail": "minimum_decisions must be 2 to 100"}))?;
        command.extend(["--minimum-decisions".into(), value.to_string()]);
    }
    optional_option(
        &arguments,
        "baseline_state",
        "--baseline-state",
        &mut command,
    )?;
    if let Some(states) = arguments.get("suspension_states") {
        let states = states
            .as_array()
            .ok_or_else(|| json!({"detail": "suspension_states must be an array"}))?;
        if states.len() > 100 {
            return Err(json!({"detail": "suspension_states cannot exceed 100 entries"}));
        }
        for state in states {
            let state = state
                .as_str()
                .filter(|state| !state.is_empty())
                .ok_or_else(|| json!({"detail": "suspension_states entries must be strings"}))?;
            command.extend(["--suspension-state".into(), state.into()]);
        }
    }
    if let Some(states) = arguments.get("remediation_states") {
        let states = states
            .as_array()
            .ok_or_else(|| json!({"detail": "remediation_states must be an array"}))?;
        if states.len() > 100 {
            return Err(json!({"detail": "remediation_states cannot exceed 100 entries"}));
        }
        for state in states {
            let state = state
                .as_str()
                .filter(|state| !state.is_empty())
                .ok_or_else(|| json!({"detail": "remediation_states entries must be strings"}))?;
            command.extend(["--remediation-state".into(), state.into()]);
        }
    }
    if let Some(ledgers) = arguments.get("policy_lifecycle_ledgers") {
        let ledgers = ledgers
            .as_array()
            .ok_or_else(|| json!({"detail": "policy_lifecycle_ledgers must be an array"}))?;
        if ledgers.len() > 100 {
            return Err(json!({"detail": "policy_lifecycle_ledgers cannot exceed 100 entries"}));
        }
        for ledger in ledgers {
            let ledger = ledger
                .as_str()
                .filter(|ledger| !ledger.is_empty())
                .ok_or_else(
                    || json!({"detail": "policy_lifecycle_ledgers entries must be strings"}),
                )?;
            command.extend(["--policy-lifecycle-ledger".into(), ledger.into()]);
        }
    }
    command.extend([
        "--recorded-at-unix".into(),
        recorded_at.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_promotion",
        "--require-promotion",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let deployment = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "deployment": deployment}),
    ))
}

fn verify_policy_deployment(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "deployment",
            "rollout",
            "candidate_policy_pack",
            "project_ids",
            "boards",
            "expected_analyses",
            "observed_analyses",
            "verified_at_unix",
            "output",
            "summary_output",
            "require_passed",
        ],
    )?;
    let project_ids = required_string_array(&arguments, "project_ids", false)?;
    let boards = required_string_array(&arguments, "boards", false)?;
    let expected = required_string_array(&arguments, "expected_analyses", false)?;
    let observed = required_string_array(&arguments, "observed_analyses", false)?;
    if project_ids.len() > 1_000
        || project_ids.len() != boards.len()
        || project_ids.len() != expected.len()
        || project_ids.len() != observed.len()
    {
        return Err(json!({
            "detail": "post-deployment verification arrays must pair 1 to 1000 entries"
        }));
    }
    let verified_at = arguments
        .get("verified_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "verified_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-policy-deployment".into(),
        required_string(&arguments, "deployment")?,
        required_string(&arguments, "rollout")?,
        "--candidate-policy-pack".into(),
        required_string(&arguments, "candidate_policy_pack")?,
    ];
    for value in project_ids {
        command.extend(["--project-id".into(), value]);
    }
    for value in boards {
        command.extend(["--board".into(), value]);
    }
    for value in expected {
        command.extend(["--expected-analysis".into(), value]);
    }
    for value in observed {
        command.extend(["--observed-analysis".into(), value]);
    }
    command.extend([
        "--verified-at-unix".into(),
        verified_at.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_passed",
        "--require-passed",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let verification = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "verification": verification}),
    ))
}

fn sign_policy_deployment_rollback(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "deployment",
            "verification",
            "approved_at_unix",
            "private_key",
            "signer_id",
            "reason",
            "ticket",
            "output",
        ],
    )?;
    let approved_at = arguments
        .get("approved_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "approved_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-deployment-rollback".into(),
        required_string(&arguments, "deployment")?,
        required_string(&arguments, "verification")?,
        "--approved-at-unix".into(),
        approved_at.to_string(),
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--signer-id".into(),
        required_string(&arguments, "signer_id")?,
        "--reason".into(),
        required_string(&arguments, "reason")?,
        "--ticket".into(),
        required_string(&arguments, "ticket")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let approval = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "approval": approval}),
    ))
}

fn apply_policy_deployment_rollback(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "deployment",
            "verification",
            "active_policy_pack",
            "approvals",
            "minimum_approvals",
            "recorded_at_unix",
            "output",
            "summary_output",
            "require_applied",
        ],
    )?;
    let approvals = required_string_array(&arguments, "approvals", false)?;
    if approvals.len() > 100 {
        return Err(json!({"detail": "approvals cannot exceed 100 entries"}));
    }
    let recorded_at = arguments
        .get("recorded_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "recorded_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "apply-policy-deployment-rollback".into(),
        required_string(&arguments, "deployment")?,
        required_string(&arguments, "verification")?,
        "--active-policy-pack".into(),
        required_string(&arguments, "active_policy_pack")?,
    ];
    for approval in approvals {
        command.extend(["--approval".into(), approval]);
    }
    if let Some(value) = arguments.get("minimum_approvals") {
        let value = value
            .as_u64()
            .filter(|value| (2..=100).contains(value))
            .ok_or_else(|| json!({"detail": "minimum_approvals must be 2 to 100"}))?;
        command.extend(["--minimum-approvals".into(), value.to_string()]);
    }
    command.extend([
        "--recorded-at-unix".into(),
        recorded_at.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_applied",
        "--require-applied",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rollback": state}),
    ))
}

fn verify_policy_rollback_recovery(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollback",
            "rollout",
            "deployment",
            "failed_verification",
            "previous_deployment",
            "baseline_verification",
            "restored_policy_pack",
            "project_ids",
            "boards",
            "expected_analyses",
            "observed_analyses",
            "verified_at_unix",
            "output",
            "summary_output",
            "require_passed",
        ],
    )?;
    let project_ids = required_string_array(&arguments, "project_ids", false)?;
    let boards = required_string_array(&arguments, "boards", false)?;
    let expected = required_string_array(&arguments, "expected_analyses", false)?;
    let observed = required_string_array(&arguments, "observed_analyses", false)?;
    if project_ids.len() > 1_000
        || project_ids.len() != boards.len()
        || project_ids.len() != expected.len()
        || project_ids.len() != observed.len()
    {
        return Err(
            json!({"detail": "recovery project arrays must have equal lengths of at most 1000"}),
        );
    }
    let verified_at = arguments
        .get("verified_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "verified_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-policy-rollback-recovery".into(),
        required_string(&arguments, "rollback")?,
        required_string(&arguments, "rollout")?,
        "--deployment".into(),
        required_string(&arguments, "deployment")?,
        "--failed-verification".into(),
        required_string(&arguments, "failed_verification")?,
        "--previous-deployment".into(),
        required_string(&arguments, "previous_deployment")?,
        "--baseline-verification".into(),
        required_string(&arguments, "baseline_verification")?,
        "--restored-policy-pack".into(),
        required_string(&arguments, "restored_policy_pack")?,
    ];
    for value in project_ids {
        command.extend(["--project-id".into(), value]);
    }
    for value in boards {
        command.extend(["--board".into(), value]);
    }
    for value in expected {
        command.extend(["--expected-analysis".into(), value]);
    }
    for value in observed {
        command.extend(["--observed-analysis".into(), value]);
    }
    command.extend([
        "--verified-at-unix".into(),
        verified_at.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_passed",
        "--require-passed",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let recovery = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "recovery": recovery}),
    ))
}

fn sign_rollback_incident_acknowledgment(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollback",
            "recovery",
            "acknowledged_at_unix",
            "private_key",
            "operator_id",
            "reason",
            "ticket",
            "output",
        ],
    )?;
    let acknowledged_at = arguments
        .get("acknowledged_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "acknowledged_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-rollback-incident-acknowledgment".into(),
        required_string(&arguments, "rollback")?,
        required_string(&arguments, "recovery")?,
        "--acknowledged-at-unix".into(),
        acknowledged_at.to_string(),
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--operator-id".into(),
        required_string(&arguments, "operator_id")?,
        "--reason".into(),
        required_string(&arguments, "reason")?,
        "--ticket".into(),
        required_string(&arguments, "ticket")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let acknowledgment = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "acknowledgment": acknowledgment}),
    ))
}

fn close_rollback_incident(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollback",
            "recovery",
            "restored_policy_pack",
            "acknowledgment",
            "closed_at_unix",
            "output",
            "summary_output",
            "require_closed",
        ],
    )?;
    let closed_at = arguments
        .get("closed_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "closed_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "close-rollback-incident".into(),
        required_string(&arguments, "rollback")?,
        required_string(&arguments, "recovery")?,
        "--restored-policy-pack".into(),
        required_string(&arguments, "restored_policy_pack")?,
        "--acknowledgment".into(),
        required_string(&arguments, "acknowledgment")?,
        "--closed-at-unix".into(),
        closed_at.to_string(),
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
        "require_closed",
        "--require-closed",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let closure = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "closure": closure}),
    ))
}

fn append_policy_incident_ledger(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "rollback",
            "failed_verification",
            "recovery",
            "closure",
            "baseline_ledger",
            "suspension_threshold",
            "output",
            "summary_output",
            "require_no_suspension_review",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "append-policy-incident-ledger".into(),
        required_string(&arguments, "rollback")?,
        "--failed-verification".into(),
        required_string(&arguments, "failed_verification")?,
        "--recovery".into(),
        required_string(&arguments, "recovery")?,
        "--closure".into(),
        required_string(&arguments, "closure")?,
        "--output".into(),
        output.clone(),
    ];
    optional_option(
        &arguments,
        "baseline_ledger",
        "--baseline-ledger",
        &mut command,
    )?;
    if let Some(value) = arguments.get("suspension_threshold") {
        let value = value
            .as_u64()
            .filter(|value| (2..=100).contains(value))
            .ok_or_else(|| json!({"detail": "suspension_threshold must be 2 to 100"}))?;
        command.extend(["--suspension-threshold".into(), value.to_string()]);
    }
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_no_suspension_review",
        "--require-no-suspension-review",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let ledger = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "ledger": ledger}),
    ))
}

fn sign_policy_suspension_decision(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "ledger",
            "failed_revision",
            "failed_policy_pack_sha256",
            "decision",
            "decided_at_unix",
            "private_key",
            "signer_id",
            "reason",
            "ticket",
            "output",
        ],
    )?;
    let revision = arguments
        .get("failed_revision")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= u32::MAX as u64)
        .ok_or_else(|| json!({"detail": "failed_revision must be a positive u32"}))?;
    let decided_at = arguments
        .get("decided_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "decided_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-suspension-decision".into(),
        required_string(&arguments, "ledger")?,
        "--failed-revision".into(),
        revision.to_string(),
        "--failed-policy-pack-sha256".into(),
        required_string(&arguments, "failed_policy_pack_sha256")?,
        "--decision".into(),
        required_string(&arguments, "decision")?,
        "--decided-at-unix".into(),
        decided_at.to_string(),
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--signer-id".into(),
        required_string(&arguments, "signer_id")?,
        "--reason".into(),
        required_string(&arguments, "reason")?,
        "--ticket".into(),
        required_string(&arguments, "ticket")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let decision = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "decision": decision}),
    ))
}

fn apply_policy_suspension_decision(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "ledger",
            "policy_pack",
            "failed_revision",
            "failed_policy_pack_sha256",
            "decisions",
            "minimum_decisions",
            "recorded_at_unix",
            "output",
            "summary_output",
            "require_suspended",
        ],
    )?;
    let decisions = required_string_array(&arguments, "decisions", false)?;
    if decisions.len() > 100 {
        return Err(json!({"detail": "decisions cannot exceed 100 entries"}));
    }
    let revision = arguments
        .get("failed_revision")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= u32::MAX as u64)
        .ok_or_else(|| json!({"detail": "failed_revision must be a positive u32"}))?;
    let recorded_at = arguments
        .get("recorded_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "recorded_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "apply-policy-suspension-decision".into(),
        required_string(&arguments, "ledger")?,
        "--policy-pack".into(),
        required_string(&arguments, "policy_pack")?,
        "--failed-revision".into(),
        revision.to_string(),
        "--failed-policy-pack-sha256".into(),
        required_string(&arguments, "failed_policy_pack_sha256")?,
    ];
    for decision in decisions {
        command.extend(["--decision".into(), decision]);
    }
    if let Some(value) = arguments.get("minimum_decisions") {
        let value = value
            .as_u64()
            .filter(|value| (2..=100).contains(value))
            .ok_or_else(|| json!({"detail": "minimum_decisions must be 2 to 100"}))?;
        command.extend(["--minimum-decisions".into(), value.to_string()]);
    }
    command.extend([
        "--recorded-at-unix".into(),
        recorded_at.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_suspended",
        "--require-suspended",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "suspension": state}),
    ))
}

fn sign_policy_remediation_approval(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "suspension",
            "candidate_policy_pack",
            "candidate_policy_trust_state",
            "rollout",
            "monitoring",
            "approved_at_unix",
            "private_key",
            "signer_id",
            "reason",
            "ticket",
            "output",
        ],
    )?;
    let approved_at = arguments
        .get("approved_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "approved_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-remediation-approval".into(),
        required_string(&arguments, "suspension")?,
        required_string(&arguments, "candidate_policy_pack")?,
        required_string(&arguments, "candidate_policy_trust_state")?,
        required_string(&arguments, "rollout")?,
        required_string(&arguments, "monitoring")?,
        "--approved-at-unix".into(),
        approved_at.to_string(),
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--signer-id".into(),
        required_string(&arguments, "signer_id")?,
        "--reason".into(),
        required_string(&arguments, "reason")?,
        "--ticket".into(),
        required_string(&arguments, "ticket")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let approval = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "approval": approval}),
    ))
}

fn apply_policy_remediation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "suspension",
            "policy_pack",
            "candidate_policy_pack",
            "candidate_policy_trust_state",
            "rollout",
            "monitoring",
            "approvals",
            "minimum_approvals",
            "recorded_at_unix",
            "output",
            "summary_output",
            "require_verified",
        ],
    )?;
    let approvals = required_string_array(&arguments, "approvals", false)?;
    if approvals.len() > 100 {
        return Err(json!({"detail": "approvals cannot exceed 100 entries"}));
    }
    let recorded_at = arguments
        .get("recorded_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "recorded_at_unix must be an unsigned integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "apply-policy-remediation".into(),
        required_string(&arguments, "suspension")?,
        "--policy-pack".into(),
        required_string(&arguments, "policy_pack")?,
        "--candidate-policy-pack".into(),
        required_string(&arguments, "candidate_policy_pack")?,
        "--candidate-policy-trust-state".into(),
        required_string(&arguments, "candidate_policy_trust_state")?,
        "--rollout".into(),
        required_string(&arguments, "rollout")?,
        "--monitoring".into(),
        required_string(&arguments, "monitoring")?,
    ];
    for approval in approvals {
        command.extend(["--approval".into(), approval]);
    }
    if let Some(value) = arguments.get("minimum_approvals") {
        let value = value
            .as_u64()
            .filter(|value| (2..=100).contains(value))
            .ok_or_else(|| json!({"detail": "minimum_approvals must be 2 to 100"}))?;
        command.extend(["--minimum-approvals".into(), value.to_string()]);
    }
    command.extend([
        "--recorded-at-unix".into(),
        recorded_at.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_verified",
        "--require-verified",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "remediation": state}),
    ))
}

fn append_policy_lifecycle_event(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "baseline_ledger",
            "suspension",
            "remediation",
            "output",
            "summary_output",
            "require_no_pending_suspensions",
        ],
    )?;
    let suspension = optional_string(&arguments, "suspension")?;
    let remediation = optional_string(&arguments, "remediation")?;
    if suspension.is_some() == remediation.is_some() {
        return Err(json!({
            "detail": "exactly one of suspension or remediation must be supplied"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec!["append-policy-lifecycle-event".into()];
    optional_option(
        &arguments,
        "baseline_ledger",
        "--baseline-ledger",
        &mut command,
    )?;
    if let Some(suspension) = suspension {
        command.extend(["--suspension".into(), suspension]);
    }
    if let Some(remediation) = remediation {
        command.extend(["--remediation".into(), remediation]);
    }
    command.extend(["--output".into(), output.clone()]);
    optional_option(
        &arguments,
        "summary_output",
        "--summary-output",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_no_pending_suspensions",
        "--require-no-pending-suspensions",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let ledger = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "ledger": ledger}),
    ))
}

fn snapshot_policy_lifecycle(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["ledger", "generation", "output"])?;
    let generation = arguments
        .get("generation")
        .and_then(Value::as_u64)
        .filter(|generation| *generation > 0)
        .ok_or_else(|| json!({"detail": "generation must be a positive integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "snapshot-policy-lifecycle".into(),
        required_string(&arguments, "ledger")?,
        "--generation".into(),
        generation.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let snapshot = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "snapshot": snapshot}),
    ))
}

fn sign_policy_lifecycle_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "ledger",
            "issued_at_unix",
            "private_key",
            "signer_id",
            "output",
        ],
    )?;
    let issued_at_unix = arguments
        .get("issued_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "issued_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-lifecycle-checkpoint".into(),
        required_string(&arguments, "ledger")?,
        "--issued-at-unix".into(),
        issued_at_unix.to_string(),
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

fn verify_policy_lifecycle_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "ledger",
            "checkpoint",
            "public_key",
            "baseline_state",
            "key_rotation",
            "accepted_at_unix",
            "output",
            "require_accepted",
        ],
    )?;
    let accepted_at_unix = arguments
        .get("accepted_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "accepted_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-policy-lifecycle-checkpoint".into(),
        required_string(&arguments, "ledger")?,
        required_string(&arguments, "checkpoint")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--accepted-at-unix".into(),
        accepted_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ];
    optional_option(
        &arguments,
        "baseline_state",
        "--baseline-state",
        &mut command,
    )?;
    optional_option(&arguments, "key_rotation", "--key-rotation", &mut command)?;
    optional_flag(
        &arguments,
        "require_accepted",
        "--require-accepted",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "trust_state": state}),
    ))
}

fn sign_policy_lifecycle_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "baseline_state",
            "old_private_key",
            "new_private_key",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let rotated_at_unix = arguments
        .get("rotated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "rotated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-lifecycle-key-rotation".into(),
        required_string(&arguments, "baseline_state")?,
        "--old-private-key".into(),
        required_string(&arguments, "old_private_key")?,
        "--new-private-key".into(),
        required_string(&arguments, "new_private_key")?,
        "--rotated-at-unix".into(),
        rotated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "key_rotation": rotation}),
    ))
}

fn witness_policy_lifecycle_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "trust_state",
            "private_key",
            "witness_id",
            "observed_at_unix",
            "output",
        ],
    )?;
    let observed_at_unix = arguments
        .get("observed_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "observed_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "witness-policy-lifecycle-checkpoint".into(),
        required_string(&arguments, "trust_state")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
        "--observed-at-unix".into(),
        observed_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let witness = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "witness": witness}),
    ))
}

fn init_policy_lifecycle_witness_trust(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["witness_id", "public_key", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-policy-lifecycle-witness-trust".into(),
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "trust_state": trust_state}),
    ))
}

fn sign_policy_lifecycle_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "trust_state",
            "old_private_key",
            "new_private_key",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let rotated_at_unix = arguments
        .get("rotated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "rotated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-lifecycle-witness-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        "--old-private-key".into(),
        required_string(&arguments, "old_private_key")?,
        "--new-private-key".into(),
        required_string(&arguments, "new_private_key")?,
        "--rotated-at-unix".into(),
        rotated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "key_rotation": rotation}),
    ))
}

fn apply_policy_lifecycle_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["trust_state", "rotation", "output", "public_key_output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let public_key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-policy-lifecycle-witness-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        public_key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": public_key_output,
            "trust_state": trust_state
        }),
    ))
}

fn export_policy_lifecycle_witness_public_key(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "export-policy-lifecycle-witness-public-key".into(),
        required_string(&arguments, "trust_state")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(execution, json!({"output": output})))
}

fn verify_policy_lifecycle_checkpoint_witnesses(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "trust_state",
            "witnesses",
            "public_keys",
            "witness_key_trust_states",
            "minimum_witnesses",
            "evaluated_at_unix",
            "output",
            "require_quorum",
        ],
    )?;
    let witnesses = required_string_array(&arguments, "witnesses", false)?;
    let public_keys = arguments
        .contains_key("public_keys")
        .then(|| required_string_array(&arguments, "public_keys", false))
        .transpose()?;
    let witness_key_trust_states = arguments
        .contains_key("witness_key_trust_states")
        .then(|| required_string_array(&arguments, "witness_key_trust_states", false))
        .transpose()?;
    if public_keys.is_some() == witness_key_trust_states.is_some() {
        return Err(json!({
            "detail": "exactly one of public_keys or witness_key_trust_states is required"
        }));
    }
    let key_evidence_count = public_keys
        .as_ref()
        .map(Vec::len)
        .or_else(|| witness_key_trust_states.as_ref().map(Vec::len))
        .unwrap_or_default();
    if witnesses.len() != key_evidence_count || witnesses.len() > 100 {
        return Err(json!({
            "detail": "witnesses and trusted key evidence must be paired and cannot exceed 100"
        }));
    }
    let minimum_witnesses = arguments
        .get("minimum_witnesses")
        .map_or(Some(2), Value::as_u64)
        .filter(|value| (2..=100).contains(value))
        .ok_or_else(|| json!({"detail": "minimum_witnesses must be 2 to 100"}))?;
    let evaluated_at_unix = arguments
        .get("evaluated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "evaluated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-policy-lifecycle-checkpoint-witnesses".into(),
        required_string(&arguments, "trust_state")?,
    ];
    for witness in witnesses {
        command.extend(["--witness".into(), witness]);
    }
    if let Some(public_keys) = public_keys {
        for public_key in public_keys {
            command.extend(["--public-key".into(), public_key]);
        }
    }
    if let Some(trust_states) = witness_key_trust_states {
        for trust_state in trust_states {
            command.extend(["--witness-key-trust-state".into(), trust_state]);
        }
    }
    command.extend([
        "--minimum-witnesses".into(),
        minimum_witnesses.to_string(),
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
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
        json!({"output": output, "quorum": report}),
    ))
}

fn request_remote_policy_lifecycle_checkpoint_witness(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "trust_state",
            "endpoint",
            "public_key",
            "witness_key_trust_state",
            "bearer_token_env",
            "timeout_seconds",
            "evaluated_at_unix",
            "output",
            "receipt_output",
        ],
    )?;
    let evaluated_at_unix = arguments
        .get("evaluated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "evaluated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let receipt_output = required_string(&arguments, "receipt_output")?;
    let public_key = arguments.get("public_key").and_then(Value::as_str);
    let witness_key_trust_state = arguments
        .get("witness_key_trust_state")
        .and_then(Value::as_str);
    if public_key.is_some() == witness_key_trust_state.is_some() {
        return Err(json!({
            "detail": "exactly one of public_key or witness_key_trust_state is required"
        }));
    }
    let mut command = vec![
        "request-policy-lifecycle-checkpoint-witness".into(),
        required_string(&arguments, "trust_state")?,
        "--endpoint".into(),
        required_string(&arguments, "endpoint")?,
    ];
    if let Some(public_key) = public_key {
        command.extend(["--public-key".into(), public_key.into()]);
    }
    if let Some(trust_state) = witness_key_trust_state {
        command.extend(["--witness-key-trust-state".into(), trust_state.into()]);
    }
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
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
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

fn create_policy_lifecycle_public_anchor(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "checkpoint",
            "log_checkpoints",
            "leaf_index",
            "log_id",
            "private_key",
            "observed_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let leaf_index = arguments
        .get("leaf_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "leaf_index must be a non-negative integer"}))?;
    let mut command = vec![
        "create-policy-lifecycle-log-anchor".into(),
        required_string(&arguments, "checkpoint")?,
    ];
    let log_checkpoints = required_string_array(&arguments, "log_checkpoints", false)?;
    if log_checkpoints.len() > 100_000 {
        return Err(json!({
            "detail": "log_checkpoints cannot exceed 100000 entries"
        }));
    }
    for checkpoint in log_checkpoints {
        command.extend(["--log-checkpoint".into(), checkpoint]);
    }
    command.extend([
        "--leaf-index".into(),
        leaf_index.to_string(),
        "--log-id".into(),
        required_string(&arguments, "log_id")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
    ]);
    optional_nonnegative_integer(
        &arguments,
        "observed_at_unix",
        "--observed-at-unix",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let proof = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "proof": proof}),
    ))
}

fn verify_policy_lifecycle_public_anchor(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["checkpoint", "proof", "log_id", "public_key", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "verify-policy-lifecycle-log-anchor".into(),
        required_string(&arguments, "checkpoint")?,
        "--proof".into(),
        required_string(&arguments, "proof")?,
        "--log-id".into(),
        required_string(&arguments, "log_id")?,
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

fn create_policy_lifecycle_public_log_consistency(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "previous_anchor",
            "current_anchor",
            "log_checkpoints",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "create-policy-lifecycle-log-consistency".into(),
        "--previous-anchor".into(),
        required_string(&arguments, "previous_anchor")?,
        "--current-anchor".into(),
        required_string(&arguments, "current_anchor")?,
    ];
    let log_checkpoints = required_string_array(&arguments, "log_checkpoints", false)?;
    if log_checkpoints.len() > 100_000 {
        return Err(json!({
            "detail": "log_checkpoints cannot exceed 100000 entries"
        }));
    }
    for checkpoint in log_checkpoints {
        command.extend(["--log-checkpoint".into(), checkpoint]);
    }
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let proof = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "proof": proof}),
    ))
}

fn verify_policy_lifecycle_public_log_consistency(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "previous_anchor",
            "current_anchor",
            "proof",
            "log_id",
            "public_key",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "verify-policy-lifecycle-log-consistency".into(),
        "--previous-anchor".into(),
        required_string(&arguments, "previous_anchor")?,
        "--current-anchor".into(),
        required_string(&arguments, "current_anchor")?,
        "--proof".into(),
        required_string(&arguments, "proof")?,
        "--log-id".into(),
        required_string(&arguments, "log_id")?,
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

fn sign_policy_lifecycle_public_log_gossip_receipt(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "anchor",
            "log_id",
            "log_public_key",
            "observer_id",
            "private_key",
            "received_at_unix",
            "expires_at_unix",
            "output",
        ],
    )?;
    let expires_at_unix = arguments
        .get("expires_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "expires_at_unix must be a positive integer"}))?;
    if expires_at_unix == 0 {
        return Err(json!({"detail": "expires_at_unix must be a positive integer"}));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-policy-lifecycle-log-gossip-receipt".into(),
        "--anchor".into(),
        required_string(&arguments, "anchor")?,
        "--log-id".into(),
        required_string(&arguments, "log_id")?,
        "--log-public-key".into(),
        required_string(&arguments, "log_public_key")?,
        "--observer-id".into(),
        required_string(&arguments, "observer_id")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
    ];
    optional_nonnegative_integer(
        &arguments,
        "received_at_unix",
        "--received-at-unix",
        &mut command,
    )?;
    command.extend([
        "--expires-at-unix".into(),
        expires_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let receipt = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "receipt": receipt}),
    ))
}

fn verify_policy_lifecycle_public_log_gossip_receipt(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "local_anchor",
            "receipt",
            "consistency_proof",
            "log_id",
            "log_public_key",
            "observer_id",
            "observer_public_key",
            "evaluated_at_unix",
            "output",
        ],
    )?;
    let evaluated_at_unix = arguments
        .get("evaluated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "evaluated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-policy-lifecycle-log-gossip-receipt".into(),
        "--local-anchor".into(),
        required_string(&arguments, "local_anchor")?,
        "--receipt".into(),
        required_string(&arguments, "receipt")?,
    ];
    optional_option(
        &arguments,
        "consistency_proof",
        "--consistency-proof",
        &mut command,
    )?;
    command.extend([
        "--log-id".into(),
        required_string(&arguments, "log_id")?,
        "--log-public-key".into(),
        required_string(&arguments, "log_public_key")?,
        "--observer-id".into(),
        required_string(&arguments, "observer_id")?,
        "--observer-public-key".into(),
        required_string(&arguments, "observer_public_key")?,
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn init_policy_lifecycle_public_log_gossip_observer_trust(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["organization_id", "observer_id", "public_key", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-policy-lifecycle-log-gossip-observer-trust".into(),
        "--organization-id".into(),
        required_string(&arguments, "organization_id")?,
        "--observer-id".into(),
        required_string(&arguments, "observer_id")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "trust_state": state}),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_observer_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "trust_state",
            "old_private_key",
            "new_private_key",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let rotated_at_unix = arguments
        .get("rotated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "rotated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-lifecycle-log-gossip-observer-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        "--old-private-key".into(),
        required_string(&arguments, "old_private_key")?,
        "--new-private-key".into(),
        required_string(&arguments, "new_private_key")?,
        "--rotated-at-unix".into(),
        rotated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_policy_lifecycle_public_log_gossip_observer_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["trust_state", "rotation", "output", "public_key_output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let public_key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-policy-lifecycle-log-gossip-observer-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        public_key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": public_key_output,
            "trust_state": state
        }),
    ))
}

fn export_policy_lifecycle_public_log_gossip_observer_key(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "export-policy-lifecycle-log-gossip-observer-public-key".into(),
        required_string(&arguments, "trust_state")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(execution, json!({"output": output})))
}

fn init_policy_lifecycle_public_log_gossip_organization_registry(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["registry_id", "authority_public_key", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-policy-lifecycle-log-gossip-organization-registry".into(),
        "--registry-id".into(),
        required_string(&arguments, "registry_id")?,
        "--authority-public-key".into(),
        required_string(&arguments, "authority_public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "registry": registry}),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_transition(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "authority_private_key",
            "action",
            "organization_id",
            "observer_trust_state",
            "reason_sha256",
            "effective_at_unix",
            "output",
        ],
    )?;
    let action = required_string(&arguments, "action")?;
    if !matches!(
        action.as_str(),
        "admit-observer" | "suspend-organization" | "revoke-organization"
    ) {
        return Err(json!({
            "detail": "action must be admit-observer, suspend-organization, or revoke-organization"
        }));
    }
    let observer_trust_state = optional_string(&arguments, "observer_trust_state")?;
    if (action == "admit-observer") != observer_trust_state.is_some() {
        return Err(json!({
            "detail": "observer_trust_state is required only for admit-observer"
        }));
    }
    let reason_sha256 = required_string(&arguments, "reason_sha256")?;
    if reason_sha256.len() != 64
        || !reason_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(json!({"detail": "reason_sha256 must be lowercase SHA-256 hex"}));
    }
    let effective_at_unix = arguments
        .get("effective_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "effective_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-transition".into(),
        required_string(&arguments, "registry")?,
        "--authority-private-key".into(),
        required_string(&arguments, "authority_private_key")?,
        "--action".into(),
        action,
        "--organization-id".into(),
        required_string(&arguments, "organization_id")?,
    ];
    if let Some(path) = observer_trust_state {
        command.extend(["--observer-trust-state".into(), path]);
    }
    command.extend([
        "--reason-sha256".into(),
        reason_sha256,
        "--effective-at-unix".into(),
        effective_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let transition = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "transition": transition}),
    ))
}

fn apply_policy_lifecycle_public_log_gossip_organization_registry_transition(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["registry", "transition", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "apply-policy-lifecycle-log-gossip-organization-registry-transition".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "transition")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "registry": registry}),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "old_private_key",
            "new_private_key",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let rotated_at_unix = arguments
        .get("rotated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "rotated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation".into(),
        required_string(&arguments, "registry")?,
        "--old-private-key".into(),
        required_string(&arguments, "old_private_key")?,
        "--new-private-key".into(),
        required_string(&arguments, "new_private_key")?,
        "--rotated-at-unix".into(),
        rotated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["registry", "rotation", "output", "public_key_output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let public_key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        public_key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": public_key_output,
            "registry": registry
        }),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_governance(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "registry_authority_private_key",
            "minimum_approvals",
            "authority_ids",
            "authority_public_keys",
            "issued_at_unix",
            "output",
        ],
    )?;
    let minimum_approvals = arguments
        .get("minimum_approvals")
        .and_then(Value::as_u64)
        .filter(|value| (2..=100).contains(value))
        .ok_or_else(|| json!({"detail": "minimum_approvals must be an integer from 2 to 100"}))?;
    let issued_at_unix = arguments
        .get("issued_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "issued_at_unix must be a non-negative integer"}))?;
    let authority_ids = required_string_array(&arguments, "authority_ids", false)?;
    let authority_public_keys = required_string_array(&arguments, "authority_public_keys", false)?;
    if authority_ids.len() != authority_public_keys.len() {
        return Err(json!({"detail": "authority_ids and authority_public_keys counts must match"}));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-governance".into(),
        required_string(&arguments, "registry")?,
        "--registry-authority-private-key".into(),
        required_string(&arguments, "registry_authority_private_key")?,
        "--minimum-approvals".into(),
        minimum_approvals.to_string(),
    ];
    for (authority_id, public_key) in authority_ids.iter().zip(&authority_public_keys) {
        command.extend(["--authority-id".into(), authority_id.clone()]);
        command.extend(["--authority-public-key".into(), public_key.clone()]);
    }
    command.extend([
        "--issued-at-unix".into(),
        issued_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let governance = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "governance": governance}),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_successor_governance(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "successor_registry_authority_private_key",
            "minimum_approvals",
            "authority_ids",
            "authority_public_keys",
            "issued_at_unix",
            "output",
        ],
    )?;
    let minimum_approvals = arguments
        .get("minimum_approvals")
        .and_then(Value::as_u64)
        .filter(|value| (2..=100).contains(value))
        .ok_or_else(|| json!({"detail": "minimum_approvals must be an integer from 2 to 100"}))?;
    let issued_at_unix = arguments
        .get("issued_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "issued_at_unix must be a non-negative integer"}))?;
    let authority_ids = required_string_array(&arguments, "authority_ids", false)?;
    let authority_public_keys = required_string_array(&arguments, "authority_public_keys", false)?;
    if authority_ids.len() != authority_public_keys.len() {
        return Err(json!({"detail": "authority_ids and authority_public_keys counts must match"}));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-successor-governance".into(),
        required_string(&arguments, "registry")?,
        "--successor-registry-authority-private-key".into(),
        required_string(&arguments, "successor_registry_authority_private_key")?,
        "--minimum-approvals".into(),
        minimum_approvals.to_string(),
    ];
    for (authority_id, public_key) in authority_ids.iter().zip(&authority_public_keys) {
        command.extend(["--authority-id".into(), authority_id.clone()]);
        command.extend(["--authority-public-key".into(), public_key.clone()]);
    }
    command.extend([
        "--issued-at-unix".into(),
        issued_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let governance = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "governance": governance}),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "governance",
            "authority_ids",
            "authority_private_keys",
            "action",
            "organization_id",
            "observer_trust_state",
            "reason_sha256",
            "effective_at_unix",
            "output",
        ],
    )?;
    let authority_ids = required_string_array(&arguments, "authority_ids", false)?;
    let authority_private_keys =
        required_string_array(&arguments, "authority_private_keys", false)?;
    if authority_ids.len() != authority_private_keys.len() {
        return Err(
            json!({"detail": "authority_ids and authority_private_keys counts must match"}),
        );
    }
    let action = required_string(&arguments, "action")?;
    if !matches!(
        action.as_str(),
        "admit-observer" | "suspend-organization" | "revoke-organization"
    ) {
        return Err(json!({"detail": "action is invalid"}));
    }
    let effective_at_unix = arguments
        .get("effective_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "effective_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-threshold-transition".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "governance")?,
    ];
    for (authority_id, private_key) in authority_ids.iter().zip(&authority_private_keys) {
        command.extend(["--authority-id".into(), authority_id.clone()]);
        command.extend(["--authority-private-key".into(), private_key.clone()]);
    }
    command.extend([
        "--action".into(),
        action,
        "--organization-id".into(),
        required_string(&arguments, "organization_id")?,
    ]);
    if let Some(observer) = optional_string(&arguments, "observer_trust_state")? {
        command.extend(["--observer-trust-state".into(), observer]);
    }
    command.extend([
        "--reason-sha256".into(),
        required_string(&arguments, "reason_sha256")?,
        "--effective-at-unix".into(),
        effective_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let transition = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "transition": transition}),
    ))
}

fn apply_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["registry", "governance", "transition", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "apply-policy-lifecycle-log-gossip-organization-registry-threshold-transition".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "governance")?,
        required_string(&arguments, "transition")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "registry": registry}),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    let names = [
        "registry",
        "old_governance",
        "new_governance",
        "old_authority_ids",
        "old_authority_private_keys",
        "new_authority_ids",
        "new_authority_private_keys",
        "rotated_at_unix",
        "output",
    ];
    reject_unknown(&arguments, &names)?;
    let old_ids = required_string_array(&arguments, "old_authority_ids", false)?;
    let old_keys = required_string_array(&arguments, "old_authority_private_keys", false)?;
    let new_ids = required_string_array(&arguments, "new_authority_ids", false)?;
    let new_keys = required_string_array(&arguments, "new_authority_private_keys", false)?;
    if old_ids.len() != old_keys.len() || new_ids.len() != new_keys.len() {
        return Err(
            json!({"detail": "governance rotation authority identity and key counts must match"}),
        );
    }
    let rotated_at = arguments
        .get("rotated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "rotated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-governance-rotation".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "old_governance")?,
        required_string(&arguments, "new_governance")?,
    ];
    for (id, key) in old_ids.iter().zip(&old_keys) {
        command.extend(["--old-authority-id".into(), id.clone()]);
        command.extend(["--old-authority-private-key".into(), key.clone()]);
    }
    for (id, key) in new_ids.iter().zip(&new_keys) {
        command.extend(["--new-authority-id".into(), id.clone()]);
        command.extend(["--new-authority-private-key".into(), key.clone()]);
    }
    command.extend([
        "--rotated-at-unix".into(),
        rotated_at.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "old_governance",
            "new_governance",
            "rotation",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "apply-policy-lifecycle-log-gossip-organization-registry-governance-rotation".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "old_governance")?,
        required_string(&arguments, "new_governance")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "registry": registry}),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    let names = [
        "registry",
        "old_governance",
        "new_governance",
        "old_authority_ids",
        "old_authority_private_keys",
        "new_authority_ids",
        "new_authority_private_keys",
        "rotated_at_unix",
        "output",
    ];
    reject_unknown(&arguments, &names)?;
    let old_ids = required_string_array(&arguments, "old_authority_ids", false)?;
    let old_keys = required_string_array(&arguments, "old_authority_private_keys", false)?;
    let new_ids = required_string_array(&arguments, "new_authority_ids", false)?;
    let new_keys = required_string_array(&arguments, "new_authority_private_keys", false)?;
    if old_ids.len() != old_keys.len() || new_ids.len() != new_keys.len() {
        return Err(
            json!({"detail": "governed authority rotation identity and key counts must match"}),
        );
    }
    let rotated_at = arguments
        .get("rotated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "rotated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation"
            .into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "old_governance")?,
        required_string(&arguments, "new_governance")?,
    ];
    for (id, key) in old_ids.iter().zip(&old_keys) {
        command.extend(["--old-authority-id".into(), id.clone()]);
        command.extend(["--old-authority-private-key".into(), key.clone()]);
    }
    for (id, key) in new_ids.iter().zip(&new_keys) {
        command.extend(["--new-authority-id".into(), id.clone()]);
        command.extend(["--new-authority-private-key".into(), key.clone()]);
    }
    command.extend([
        "--rotated-at-unix".into(),
        rotated_at.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "old_governance",
            "new_governance",
            "rotation",
            "output",
            "public_key_output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let public_key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation"
            .into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "old_governance")?,
        required_string(&arguments, "new_governance")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        public_key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": public_key_output,
            "registry": registry
        }),
    ))
}

fn audit_policy_lifecycle_public_log_gossip_organization_registry_history(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["history", "output", "final_registry_output"])?;
    let output = required_string(&arguments, "output")?;
    let final_registry_output = required_string(&arguments, "final_registry_output")?;
    let command = vec![
        "audit-policy-lifecycle-log-gossip-organization-registry-history".into(),
        required_string(&arguments, "history")?,
        "--output".into(),
        output.clone(),
        "--final-registry-output".into(),
        final_registry_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let audit = read_json_if_present(Path::new(&output));
    let final_registry = read_json_if_present(Path::new(&final_registry_output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "final_registry_output": final_registry_output,
            "audit": audit,
            "final_registry": final_registry
        }),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "history",
            "authority_private_key",
            "issued_at_unix",
            "output",
        ],
    )?;
    let issued_at_unix = arguments
        .get("issued_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "issued_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-history-checkpoint".into(),
        required_string(&arguments, "history")?,
        "--authority-private-key".into(),
        required_string(&arguments, "authority_private_key")?,
        "--issued-at-unix".into(),
        issued_at_unix.to_string(),
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

fn accept_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "history",
            "checkpoint",
            "baseline",
            "accepted_at_unix",
            "output",
        ],
    )?;
    let accepted_at_unix = arguments
        .get("accepted_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "accepted_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "accept-policy-lifecycle-log-gossip-organization-registry-history-checkpoint".into(),
        required_string(&arguments, "history")?,
        required_string(&arguments, "checkpoint")?,
    ];
    optional_option(&arguments, "baseline", "--baseline", &mut command)?;
    command.extend([
        "--accepted-at-unix".into(),
        accepted_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "trust_state": trust_state}),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "history",
            "checkpoint",
            "witness_id",
            "witness_private_key",
            "witnessed_at_unix",
            "output",
        ],
    )?;
    let witnessed_at_unix = arguments
        .get("witnessed_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "witnessed_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness".into(),
        required_string(&arguments, "history")?,
        required_string(&arguments, "checkpoint")?,
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
        "--witness-private-key".into(),
        required_string(&arguments, "witness_private_key")?,
        "--witnessed-at-unix".into(),
        witnessed_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let witness = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "witness": witness}),
    ))
}

fn verify_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witnesses(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "history",
            "checkpoint",
            "witnesses",
            "trusted_witness_ids",
            "trusted_witness_public_keys",
            "witness_trust_states",
            "witness_trust_states",
            "minimum_witnesses",
            "evaluated_at_unix",
            "require_quorum",
            "output",
        ],
    )?;
    let witnesses = required_string_array(&arguments, "witnesses", false)?;
    let trusted_ids = required_string_array(&arguments, "trusted_witness_ids", true)?;
    let trusted_keys = required_string_array(&arguments, "trusted_witness_public_keys", true)?;
    let trust_states = required_string_array(&arguments, "witness_trust_states", true)?;
    let direct = !trusted_ids.is_empty() || !trusted_keys.is_empty();
    if direct == !trust_states.is_empty() || (direct && trusted_ids.len() != trusted_keys.len()) {
        return Err(json!({
            "detail": "supply exactly one paired direct or witness-trust-state key source"
        }));
    }
    let evaluated_at_unix = arguments
        .get("evaluated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "evaluated_at_unix must be a non-negative integer"}))?;
    let minimum_witnesses = match arguments.get("minimum_witnesses") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| json!({"detail": "minimum_witnesses must be an integer"}))?,
        None => 2,
    };
    if !(2..=100).contains(&minimum_witnesses) {
        return Err(json!({
            "detail": "minimum_witnesses must be an integer from 2 to 100"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witnesses"
            .into(),
        required_string(&arguments, "history")?,
        required_string(&arguments, "checkpoint")?,
    ];
    for witness in witnesses {
        command.extend(["--witness".into(), witness]);
    }
    if direct {
        for id in trusted_ids {
            command.extend(["--trusted-witness-id".into(), id]);
        }
        for key in trusted_keys {
            command.extend(["--trusted-witness-public-key".into(), key]);
        }
    } else {
        for state in trust_states {
            command.extend(["--witness-trust-state".into(), state]);
        }
    }
    command.extend([
        "--minimum-witnesses".into(),
        minimum_witnesses.to_string(),
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
    ]);
    optional_flag(
        &arguments,
        "require_quorum",
        "--require-quorum",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let quorum = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "quorum": quorum}),
    ))
}

fn request_remote_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "checkpoint_trust_state",
            "endpoint",
            "public_key",
            "witness_key_trust_state",
            "bearer_token_env",
            "timeout_seconds",
            "evaluated_at_unix",
            "output",
            "receipt_output",
        ],
    )?;
    let evaluated_at_unix = arguments
        .get("evaluated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "evaluated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let receipt_output = required_string(&arguments, "receipt_output")?;
    let public_key = arguments.get("public_key").and_then(Value::as_str);
    let witness_key_trust_state = arguments
        .get("witness_key_trust_state")
        .and_then(Value::as_str);
    if public_key.is_some() == witness_key_trust_state.is_some() {
        return Err(json!({
            "detail": "exactly one of public_key or witness_key_trust_state is required"
        }));
    }
    let mut command = vec![
        "request-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness"
            .into(),
        required_string(&arguments, "checkpoint_trust_state")?,
        "--endpoint".into(),
        required_string(&arguments, "endpoint")?,
    ];
    if let Some(public_key) = public_key {
        command.extend(["--public-key".into(), public_key.into()]);
    }
    if let Some(trust_state) = witness_key_trust_state {
        command.extend(["--witness-key-trust-state".into(), trust_state.into()]);
    }
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
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
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

fn init_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_trust(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["witness_id", "public_key", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-trust"
            .into(),
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "trust_state": trust_state}),
    ))
}

fn sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "trust_state",
            "old_private_key",
            "new_private_key",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let rotated_at = arguments
        .get("rotated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "rotated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        "--old-private-key".into(),
        required_string(&arguments, "old_private_key")?,
        "--new-private-key".into(),
        required_string(&arguments, "new_private_key")?,
        "--rotated-at-unix".into(),
        rotated_at.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["trust_state", "rotation", "output", "public_key_output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": key_output,
            "trust_state": trust_state
        }),
    ))
}

fn export_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "export-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-key"
            .into(),
        required_string(&arguments, "trust_state")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(execution, json!({"output": output})))
}

fn verify_policy_lifecycle_public_log_gossip_quorum(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "local_anchor",
            "observations",
            "organization_ids",
            "observer_ids",
            "observer_public_keys",
            "observer_trust_states",
            "organization_registry",
            "observer_trust_states",
            "observer_trust_states",
            "organization_trust_registry",
            "minimum_organizations",
            "log_id",
            "log_public_key",
            "evaluated_at_unix",
            "output",
            "require_quorum",
        ],
    )?;
    let observations = required_string_array(&arguments, "observations", false)?;
    let organization_ids = required_string_array(&arguments, "organization_ids", true)?;
    let observer_ids = required_string_array(&arguments, "observer_ids", true)?;
    let observer_public_keys = required_string_array(&arguments, "observer_public_keys", true)?;
    let observer_trust_states = required_string_array(&arguments, "observer_trust_states", true)?;
    let organization_trust_registry = optional_string(&arguments, "organization_trust_registry")?;
    let direct = !organization_ids.is_empty()
        || !observer_ids.is_empty()
        || !observer_public_keys.is_empty();
    if observations.len() > 100
        || direct == !observer_trust_states.is_empty()
        || (direct
            && (observations.len() != organization_ids.len()
                || observations.len() != observer_ids.len()
                || observations.len() != observer_public_keys.len()))
        || (!observer_trust_states.is_empty() && observations.len() != observer_trust_states.len())
        || (direct && organization_trust_registry.is_some())
    {
        return Err(json!({
            "detail": "observations require exactly one paired direct-trust or observer-trust-state array mode with at most 100 entries"
        }));
    }
    let minimum = match arguments.get("minimum_organizations") {
        Some(value) => value.as_u64().ok_or_else(
            || json!({"detail": "minimum_organizations must be an integer from 2 to 100"}),
        )?,
        None => 2,
    };
    if !(2..=100).contains(&minimum) {
        return Err(json!({"detail": "minimum_organizations must be an integer from 2 to 100"}));
    }
    let evaluated_at_unix = arguments
        .get("evaluated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "evaluated_at_unix must be a non-negative integer"}))?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-policy-lifecycle-log-gossip-quorum".into(),
        "--local-anchor".into(),
        required_string(&arguments, "local_anchor")?,
    ];
    for observation in observations {
        command.extend(["--observation".into(), observation]);
    }
    if direct {
        for organization_id in organization_ids {
            command.extend(["--organization-id".into(), organization_id]);
        }
        for observer_id in observer_ids {
            command.extend(["--observer-id".into(), observer_id]);
        }
        for key in observer_public_keys {
            command.extend(["--observer-public-key".into(), key]);
        }
    } else {
        for state in observer_trust_states {
            command.extend(["--observer-trust-state".into(), state]);
        }
        if let Some(registry) = organization_trust_registry {
            command.extend(["--organization-trust-registry".into(), registry]);
        }
    }
    command.extend([
        "--minimum-organizations".into(),
        minimum.to_string(),
        "--log-id".into(),
        required_string(&arguments, "log_id")?,
        "--log-public-key".into(),
        required_string(&arguments, "log_public_key")?,
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
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

fn request_remote_policy_lifecycle_public_log_gossip(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "local_anchor",
            "endpoint",
            "log_id",
            "log_public_key",
            "organization_id",
            "observer_id",
            "observer_public_key",
            "observer_trust_state",
            "bearer_token_env",
            "timeout_seconds",
            "evaluated_at_unix",
            "output",
            "receipt_output",
        ],
    )?;
    let evaluated_at_unix = arguments
        .get("evaluated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "evaluated_at_unix must be a non-negative integer"}))?;
    let timeout = match arguments.get("timeout_seconds") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| json!({"detail": "timeout_seconds must be an integer from 1 to 600"}))?,
        None => 30,
    };
    if !(1..=600).contains(&timeout) {
        return Err(json!({"detail": "timeout_seconds must be an integer from 1 to 600"}));
    }
    let output = required_string(&arguments, "output")?;
    let receipt_output = required_string(&arguments, "receipt_output")?;
    let direct_trust = [
        arguments.contains_key("organization_id"),
        arguments.contains_key("observer_id"),
        arguments.contains_key("observer_public_key"),
    ];
    let trust_state = arguments.contains_key("observer_trust_state");
    if trust_state == direct_trust.iter().all(|value| *value)
        || (direct_trust.iter().any(|value| *value) && !direct_trust.iter().all(|value| *value))
    {
        return Err(json!({
            "detail": "supply exactly one complete direct observer trust tuple or observer_trust_state"
        }));
    }
    let mut command = vec![
        "request-policy-lifecycle-log-gossip-observation".into(),
        "--local-anchor".into(),
        required_string(&arguments, "local_anchor")?,
        "--endpoint".into(),
        required_string(&arguments, "endpoint")?,
        "--log-id".into(),
        required_string(&arguments, "log_id")?,
        "--log-public-key".into(),
        required_string(&arguments, "log_public_key")?,
    ];
    if trust_state {
        command.extend([
            "--observer-trust-state".into(),
            required_string(&arguments, "observer_trust_state")?,
        ]);
    } else {
        command.extend([
            "--organization-id".into(),
            required_string(&arguments, "organization_id")?,
            "--observer-id".into(),
            required_string(&arguments, "observer_id")?,
            "--observer-public-key".into(),
            required_string(&arguments, "observer_public_key")?,
        ]);
    }
    command.extend([
        "--timeout-seconds".into(),
        timeout.to_string(),
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
        "--receipt-output".into(),
        receipt_output.clone(),
    ]);
    optional_option(
        &arguments,
        "bearer_token_env",
        "--bearer-token-env",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let observation = read_json_if_present(Path::new(&output));
    let receipt = read_json_if_present(Path::new(&receipt_output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "receipt_output": receipt_output,
            "observation": observation,
            "transport_receipt": receipt
        }),
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

fn append_verified_remote_approval_registry_history_witness_receipt(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "receipt",
            "checkpoint_trust_state",
            "response",
            "public_key",
            "witness_key_trust_state",
            "evaluated_at_unix",
            "recorded_at_unix",
            "output",
        ],
    )?;
    let public_key = optional_string(&arguments, "public_key")?;
    let witness_trust_state = optional_string(&arguments, "witness_key_trust_state")?;
    if public_key.is_some() == witness_trust_state.is_some() {
        return Err(json!({
            "detail": "exactly one of public_key or witness_key_trust_state is required"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "append-verified-remote-approval-registry-history-checkpoint-witness-receipt".into(),
        required_string(&arguments, "log")?,
        "--receipt".into(),
        required_string(&arguments, "receipt")?,
        "--checkpoint-trust-state".into(),
        required_string(&arguments, "checkpoint_trust_state")?,
        "--response".into(),
        required_string(&arguments, "response")?,
    ];
    if let Some(path) = public_key {
        command.extend(["--public-key".into(), path]);
    }
    if let Some(path) = witness_trust_state {
        command.extend(["--witness-key-trust-state".into(), path]);
    }
    optional_nonnegative_integer(
        &arguments,
        "evaluated_at_unix",
        "--evaluated-at-unix",
        &mut command,
    )?;
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

fn append_verified_remote_approval_registry_history_witness_receipt_quorum(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "receipts",
            "checkpoint_trust_state",
            "responses",
            "trusted_witness_ids",
            "trusted_witness_public_keys",
            "witness_key_trust_states",
            "minimum_witnesses",
            "evaluated_at_unix",
            "recorded_at_unix",
            "output",
            "report_output",
        ],
    )?;
    let receipts = required_string_array(&arguments, "receipts", false)?;
    let responses = required_string_array(&arguments, "responses", false)?;
    let trusted_ids = required_string_array(&arguments, "trusted_witness_ids", true)?;
    let trusted_keys = required_string_array(&arguments, "trusted_witness_public_keys", true)?;
    let trust_states = required_string_array(&arguments, "witness_key_trust_states", true)?;
    if receipts.len() != responses.len() {
        return Err(json!({"detail": "receipt and response counts must match"}));
    }
    let direct_mode = !trusted_ids.is_empty() || !trusted_keys.is_empty();
    if direct_mode == !trust_states.is_empty()
        || (direct_mode && trusted_ids.len() != trusted_keys.len())
    {
        return Err(json!({
            "detail": "use either paired trusted witness identities/keys or witness trust states"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let report_output = required_string(&arguments, "report_output")?;
    let mut command = vec![
        "append-verified-remote-approval-registry-history-checkpoint-witness-receipt-quorum".into(),
        required_string(&arguments, "log")?,
    ];
    for receipt in receipts {
        command.extend(["--receipt".into(), receipt]);
    }
    command.extend([
        "--checkpoint-trust-state".into(),
        required_string(&arguments, "checkpoint_trust_state")?,
    ]);
    for response in responses {
        command.extend(["--response".into(), response]);
    }
    for (id, key) in trusted_ids.into_iter().zip(trusted_keys) {
        command.extend(["--trusted-witness-id".into(), id]);
        command.extend(["--trusted-witness-public-key".into(), key]);
    }
    for state in trust_states {
        command.extend(["--witness-key-trust-state".into(), state]);
    }
    optional_positive_integer(
        &arguments,
        "minimum_witnesses",
        "--minimum-witnesses",
        &mut command,
    )?;
    optional_nonnegative_integer(
        &arguments,
        "evaluated_at_unix",
        "--evaluated-at-unix",
        &mut command,
    )?;
    optional_nonnegative_integer(
        &arguments,
        "recorded_at_unix",
        "--recorded-at-unix",
        &mut command,
    )?;
    command.extend([
        "--output".into(),
        output.clone(),
        "--report-output".into(),
        report_output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let log = read_json_if_present(Path::new(&output));
    let report = read_json_if_present(Path::new(&report_output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "log": log,
            "report_output": report_output,
            "report": report
        }),
    ))
}

fn sign_quorum_bound_approval_transparency_log(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "quorum_report", "private_key", "signer_id", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-approval-log-with-remote-approval-registry-history-checkpoint-witness-receipt-quorum"
            .into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
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

fn init_approval_transparency_witness_trust(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["witness_id", "public_key", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-approval-log-witness-trust".into(),
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "trust_state": trust_state}),
    ))
}

fn sign_approval_transparency_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "trust_state",
            "old_private_key",
            "new_private_key",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-approval-log-witness-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        "--old-private-key".into(),
        required_string(&arguments, "old_private_key")?,
        "--new-private-key".into(),
        required_string(&arguments, "new_private_key")?,
    ];
    optional_nonnegative_integer(
        &arguments,
        "rotated_at_unix",
        "--rotated-at-unix",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_approval_transparency_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["trust_state", "rotation", "output", "public_key_output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let public_key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-approval-log-witness-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        public_key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": public_key_output,
            "trust_state": trust_state
        }),
    ))
}

fn export_approval_transparency_witness_public_key(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "export-approval-log-witness-public-key".into(),
        required_string(&arguments, "trust_state")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(execution, json!({"output": output})))
}

fn create_approval_transparency_public_anchor(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "checkpoint",
            "log_checkpoints",
            "leaf_index",
            "log_id",
            "private_key",
            "observed_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let leaf_index = arguments
        .get("leaf_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": "leaf_index must be a non-negative integer"}))?;
    let mut command = vec![
        "create-approval-log-anchor".into(),
        required_string(&arguments, "checkpoint")?,
    ];
    for checkpoint in required_string_array(&arguments, "log_checkpoints", false)? {
        command.extend(["--log-checkpoint".into(), checkpoint]);
    }
    command.extend([
        "--leaf-index".into(),
        leaf_index.to_string(),
        "--log-id".into(),
        required_string(&arguments, "log_id")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
    ]);
    optional_nonnegative_integer(
        &arguments,
        "observed_at_unix",
        "--observed-at-unix",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let proof = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "proof": proof}),
    ))
}

fn verify_approval_transparency_public_anchor(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["checkpoint", "proof", "public_key", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "verify-approval-log-anchor".into(),
        required_string(&arguments, "checkpoint")?,
        "--proof".into(),
        required_string(&arguments, "proof")?,
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

fn create_approval_transparency_public_log_consistency(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["old_anchor", "new_anchor", "log_checkpoints", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "create-approval-log-consistency".into(),
        "--old-anchor".into(),
        required_string(&arguments, "old_anchor")?,
        "--new-anchor".into(),
        required_string(&arguments, "new_anchor")?,
    ];
    for checkpoint in required_string_array(&arguments, "log_checkpoints", false)? {
        command.extend(["--log-checkpoint".into(), checkpoint]);
    }
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let proof = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "proof": proof}),
    ))
}

fn verify_approval_transparency_public_log_consistency(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["old_anchor", "new_anchor", "proof", "public_key", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "verify-approval-log-consistency".into(),
        "--old-anchor".into(),
        required_string(&arguments, "old_anchor")?,
        "--new-anchor".into(),
        required_string(&arguments, "new_anchor")?,
        "--proof".into(),
        required_string(&arguments, "proof")?,
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

fn sign_approval_transparency_public_log_gossip_receipt(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "anchor",
            "log_public_key",
            "observer_id",
            "observer_private_key",
            "received_at_unix",
            "expires_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let received_at_unix = required_nonnegative_integer(&arguments, "received_at_unix")?;
    let expires_at_unix = required_nonnegative_integer(&arguments, "expires_at_unix")?;
    let command = vec![
        "sign-approval-log-gossip-receipt".into(),
        "--anchor".into(),
        required_string(&arguments, "anchor")?,
        "--log-public-key".into(),
        required_string(&arguments, "log_public_key")?,
        "--observer-id".into(),
        required_string(&arguments, "observer_id")?,
        "--observer-private-key".into(),
        required_string(&arguments, "observer_private_key")?,
        "--received-at-unix".into(),
        received_at_unix.to_string(),
        "--expires-at-unix".into(),
        expires_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let receipt = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "receipt": receipt}),
    ))
}

fn verify_approval_transparency_public_log_gossip_receipt(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "local_anchor",
            "receipt",
            "consistency_proof",
            "log_public_key",
            "observer_id",
            "observer_public_key",
            "evaluated_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let evaluated_at_unix = required_nonnegative_integer(&arguments, "evaluated_at_unix")?;
    let mut command = vec![
        "verify-approval-log-gossip-receipt".into(),
        "--local-anchor".into(),
        required_string(&arguments, "local_anchor")?,
        "--receipt".into(),
        required_string(&arguments, "receipt")?,
    ];
    if let Some(proof) = optional_string(&arguments, "consistency_proof")? {
        command.extend(["--consistency-proof".into(), proof]);
    }
    command.extend([
        "--log-public-key".into(),
        required_string(&arguments, "log_public_key")?,
        "--observer-id".into(),
        required_string(&arguments, "observer_id")?,
        "--observer-public-key".into(),
        required_string(&arguments, "observer_public_key")?,
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn verify_approval_transparency_public_log_gossip_quorum(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "local_anchor",
            "observations",
            "organization_ids",
            "observer_ids",
            "observer_public_keys",
            "minimum_organizations",
            "log_public_key",
            "evaluated_at_unix",
            "output",
            "require_quorum",
        ],
    )?;
    let observations = required_string_array(&arguments, "observations", false)?;
    let organization_ids = required_string_array(&arguments, "organization_ids", false)?;
    let observer_ids = required_string_array(&arguments, "observer_ids", false)?;
    let observer_keys = required_string_array(&arguments, "observer_public_keys", false)?;
    let trust_states = required_string_array(&arguments, "observer_trust_states", true)?;
    let direct =
        !organization_ids.is_empty() || !observer_ids.is_empty() || !observer_keys.is_empty();
    if observations.len() > 100
        || direct == !trust_states.is_empty()
        || (direct
            && (observations.len() != organization_ids.len()
                || observations.len() != observer_ids.len()
                || observations.len() != observer_keys.len()))
        || (!trust_states.is_empty() && observations.len() != trust_states.len())
    {
        return Err(json!({
            "detail": "observations require exactly one paired direct-trust or observer-trust-state mode with at most 100 entries"
        }));
    }
    if arguments.contains_key("organization_registry") && trust_states.is_empty() {
        return Err(json!({
            "detail": "organization_registry requires observer_trust_states mode"
        }));
    }
    let minimum = match arguments.get("minimum_organizations") {
        Some(value) => value.as_u64().ok_or_else(
            || json!({"detail": "minimum_organizations must be an integer from 2 to 100"}),
        )?,
        None => 2,
    };
    if !(2..=100).contains(&minimum) {
        return Err(json!({"detail": "minimum_organizations must be an integer from 2 to 100"}));
    }
    let evaluated_at_unix = required_nonnegative_integer(&arguments, "evaluated_at_unix")?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-approval-log-gossip-quorum".into(),
        "--local-anchor".into(),
        required_string(&arguments, "local_anchor")?,
    ];
    for observation in observations {
        command.extend(["--observation".into(), observation]);
    }
    if direct {
        for organization in organization_ids {
            command.extend(["--organization-id".into(), organization]);
        }
        for observer in observer_ids {
            command.extend(["--observer-id".into(), observer]);
        }
        for key in observer_keys {
            command.extend(["--observer-public-key".into(), key]);
        }
    } else {
        for state in trust_states {
            command.extend(["--observer-trust-state".into(), state]);
        }
        optional_option(
            &arguments,
            "organization_registry",
            "--organization-registry",
            &mut command,
        )?;
    }
    command.extend([
        "--minimum-organizations".into(),
        minimum.to_string(),
        "--log-public-key".into(),
        required_string(&arguments, "log_public_key")?,
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
    ]);
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

fn request_remote_approval_transparency_public_log_gossip(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "local_anchor",
            "endpoint",
            "log_public_key",
            "organization_id",
            "observer_id",
            "observer_public_key",
            "observer_trust_state",
            "bearer_token_env",
            "timeout_seconds",
            "evaluated_at_unix",
            "output",
            "receipt_output",
        ],
    )?;
    let timeout = match arguments.get("timeout_seconds") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| json!({"detail": "timeout_seconds must be an integer from 1 to 600"}))?,
        None => 30,
    };
    if !(1..=600).contains(&timeout) {
        return Err(json!({"detail": "timeout_seconds must be an integer from 1 to 600"}));
    }
    let evaluated_at_unix = required_nonnegative_integer(&arguments, "evaluated_at_unix")?;
    let output = required_string(&arguments, "output")?;
    let receipt_output = required_string(&arguments, "receipt_output")?;
    let direct = [
        arguments.contains_key("organization_id"),
        arguments.contains_key("observer_id"),
        arguments.contains_key("observer_public_key"),
    ];
    let trust_state = arguments.contains_key("observer_trust_state");
    if trust_state == direct.iter().all(|value| *value)
        || (direct.iter().any(|value| *value) && !direct.iter().all(|value| *value))
    {
        return Err(json!({
            "detail": "supply exactly one complete direct observer trust tuple or observer_trust_state"
        }));
    }
    let mut command = vec![
        "request-approval-log-gossip-observation".into(),
        "--local-anchor".into(),
        required_string(&arguments, "local_anchor")?,
        "--endpoint".into(),
        required_string(&arguments, "endpoint")?,
        "--log-public-key".into(),
        required_string(&arguments, "log_public_key")?,
    ];
    if trust_state {
        command.extend([
            "--observer-trust-state".into(),
            required_string(&arguments, "observer_trust_state")?,
        ]);
    } else {
        command.extend([
            "--organization-id".into(),
            required_string(&arguments, "organization_id")?,
            "--observer-id".into(),
            required_string(&arguments, "observer_id")?,
            "--observer-public-key".into(),
            required_string(&arguments, "observer_public_key")?,
        ]);
    }
    optional_option(
        &arguments,
        "bearer_token_env",
        "--bearer-token-env",
        &mut command,
    )?;
    command.extend([
        "--timeout-seconds".into(),
        timeout.to_string(),
        "--evaluated-at-unix".into(),
        evaluated_at_unix.to_string(),
        "--output".into(),
        output.clone(),
        "--receipt-output".into(),
        receipt_output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let observation = read_json_if_present(Path::new(&output));
    let receipt = read_json_if_present(Path::new(&receipt_output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "receipt_output": receipt_output,
            "observation": observation,
            "receipt": receipt
        }),
    ))
}

fn init_approval_transparency_public_log_gossip_observer_trust(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["organization_id", "observer_id", "public_key", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-approval-log-gossip-observer-trust".into(),
        "--organization-id".into(),
        required_string(&arguments, "organization_id")?,
        "--observer-id".into(),
        required_string(&arguments, "observer_id")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "trust_state": trust_state}),
    ))
}

fn sign_approval_transparency_public_log_gossip_observer_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "trust_state",
            "old_private_key",
            "new_private_key",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-approval-log-gossip-observer-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        "--old-private-key".into(),
        required_string(&arguments, "old_private_key")?,
        "--new-private-key".into(),
        required_string(&arguments, "new_private_key")?,
        "--rotated-at-unix".into(),
        required_nonnegative_integer(&arguments, "rotated_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_approval_transparency_public_log_gossip_observer_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["trust_state", "rotation", "output", "public_key_output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let public_key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-approval-log-gossip-observer-key-rotation".into(),
        required_string(&arguments, "trust_state")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        public_key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": public_key_output,
            "trust_state": trust_state
        }),
    ))
}

fn export_approval_transparency_public_log_gossip_observer_key(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "export-approval-log-gossip-observer-public-key".into(),
        required_string(&arguments, "trust_state")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(execution, json!({"output": output})))
}

fn init_approval_transparency_public_log_gossip_organization_registry(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["registry_id", "authority_public_key", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-approval-log-gossip-organization-registry".into(),
        "--registry-id".into(),
        required_string(&arguments, "registry_id")?,
        "--authority-public-key".into(),
        required_string(&arguments, "authority_public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "registry": registry}),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_transition(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "authority_private_key",
            "action",
            "organization_id",
            "observer_trust_state",
            "reason_sha256",
            "effective_at_unix",
            "output",
        ],
    )?;
    let action = required_string(&arguments, "action")?;
    if !matches!(
        action.as_str(),
        "admit-observer" | "suspend-organization" | "revoke-organization"
    ) {
        return Err(json!({"detail": "unsupported approval gossip registry action"}));
    }
    if (action == "admit-observer") != arguments.contains_key("observer_trust_state") {
        return Err(json!({
            "detail": "observer_trust_state is required only for admit-observer"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-approval-log-gossip-organization-registry-transition".into(),
        required_string(&arguments, "registry")?,
        "--authority-private-key".into(),
        required_string(&arguments, "authority_private_key")?,
        "--action".into(),
        action,
        "--organization-id".into(),
        required_string(&arguments, "organization_id")?,
    ];
    optional_option(
        &arguments,
        "observer_trust_state",
        "--observer-trust-state",
        &mut command,
    )?;
    command.extend([
        "--reason-sha256".into(),
        required_string(&arguments, "reason_sha256")?,
        "--effective-at-unix".into(),
        required_nonnegative_integer(&arguments, "effective_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let transition = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "transition": transition}),
    ))
}

fn apply_approval_transparency_public_log_gossip_organization_registry_transition(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["registry", "transition", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "apply-approval-log-gossip-organization-registry-transition".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "transition")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "registry": registry}),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_authority_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "old_private_key",
            "new_private_key",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-approval-log-gossip-organization-registry-authority-key-rotation".into(),
        required_string(&arguments, "registry")?,
        "--old-private-key".into(),
        required_string(&arguments, "old_private_key")?,
        "--new-private-key".into(),
        required_string(&arguments, "new_private_key")?,
        "--rotated-at-unix".into(),
        required_nonnegative_integer(&arguments, "rotated_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_approval_transparency_public_log_gossip_organization_registry_authority_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["registry", "rotation", "output", "public_key_output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let public_key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-approval-log-gossip-organization-registry-authority-key-rotation".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        public_key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": public_key_output,
            "registry": registry
        }),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_governance(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "registry_authority_private_key",
            "minimum_approvals",
            "authority_ids",
            "authority_public_keys",
            "issued_at_unix",
            "output",
        ],
    )?;
    let authority_ids = required_string_array(&arguments, "authority_ids", false)?;
    let authority_keys = required_string_array(&arguments, "authority_public_keys", false)?;
    if authority_ids.len() != authority_keys.len() {
        return Err(json!({"detail": "authority_ids and authority_public_keys counts must match"}));
    }
    let minimum_approvals = required_nonnegative_integer(&arguments, "minimum_approvals")?;
    if !(2..=100).contains(&minimum_approvals) {
        return Err(json!({"detail": "minimum_approvals must be an integer from 2 to 100"}));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-approval-log-gossip-organization-registry-governance".into(),
        required_string(&arguments, "registry")?,
        "--registry-authority-private-key".into(),
        required_string(&arguments, "registry_authority_private_key")?,
        "--minimum-approvals".into(),
        minimum_approvals.to_string(),
    ];
    for (authority_id, key) in authority_ids.into_iter().zip(authority_keys) {
        command.extend([
            "--authority-id".into(),
            authority_id,
            "--authority-public-key".into(),
            key,
        ]);
    }
    command.extend([
        "--issued-at-unix".into(),
        required_nonnegative_integer(&arguments, "issued_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let governance = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "governance": governance}),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_successor_governance(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "successor_registry_authority_private_key",
            "minimum_approvals",
            "authority_ids",
            "authority_public_keys",
            "issued_at_unix",
            "output",
        ],
    )?;
    let authority_ids = required_string_array(&arguments, "authority_ids", false)?;
    let authority_keys = required_string_array(&arguments, "authority_public_keys", false)?;
    if authority_ids.len() != authority_keys.len() {
        return Err(json!({"detail": "authority_ids and authority_public_keys counts must match"}));
    }
    let minimum_approvals = required_nonnegative_integer(&arguments, "minimum_approvals")?;
    if !(2..=100).contains(&minimum_approvals) {
        return Err(json!({"detail": "minimum_approvals must be an integer from 2 to 100"}));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-approval-log-gossip-organization-registry-successor-governance".into(),
        required_string(&arguments, "registry")?,
        "--successor-registry-authority-private-key".into(),
        required_string(&arguments, "successor_registry_authority_private_key")?,
        "--minimum-approvals".into(),
        minimum_approvals.to_string(),
    ];
    for (authority_id, key) in authority_ids.into_iter().zip(authority_keys) {
        command.extend([
            "--authority-id".into(),
            authority_id,
            "--authority-public-key".into(),
            key,
        ]);
    }
    command.extend([
        "--issued-at-unix".into(),
        required_nonnegative_integer(&arguments, "issued_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let governance = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "governance": governance}),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_threshold_transition(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "governance",
            "authority_ids",
            "authority_private_keys",
            "action",
            "organization_id",
            "observer_trust_state",
            "reason_sha256",
            "effective_at_unix",
            "output",
        ],
    )?;
    let authority_ids = required_string_array(&arguments, "authority_ids", false)?;
    let authority_keys = required_string_array(&arguments, "authority_private_keys", false)?;
    if authority_ids.len() != authority_keys.len() {
        return Err(
            json!({"detail": "authority_ids and authority_private_keys counts must match"}),
        );
    }
    let action = required_string(&arguments, "action")?;
    if !matches!(
        action.as_str(),
        "admit-observer" | "suspend-organization" | "revoke-organization"
    ) {
        return Err(json!({"detail": "unsupported approval gossip registry action"}));
    }
    if (action == "admit-observer") != arguments.contains_key("observer_trust_state") {
        return Err(json!({
            "detail": "observer_trust_state is required only for admit-observer"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-approval-log-gossip-organization-registry-threshold-transition".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "governance")?,
    ];
    for (authority_id, key) in authority_ids.into_iter().zip(authority_keys) {
        command.extend([
            "--authority-id".into(),
            authority_id,
            "--authority-private-key".into(),
            key,
        ]);
    }
    command.extend([
        "--action".into(),
        action,
        "--organization-id".into(),
        required_string(&arguments, "organization_id")?,
    ]);
    optional_option(
        &arguments,
        "observer_trust_state",
        "--observer-trust-state",
        &mut command,
    )?;
    command.extend([
        "--reason-sha256".into(),
        required_string(&arguments, "reason_sha256")?,
        "--effective-at-unix".into(),
        required_nonnegative_integer(&arguments, "effective_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let transition = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "transition": transition}),
    ))
}

fn apply_approval_transparency_public_log_gossip_organization_registry_threshold_transition(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["registry", "governance", "transition", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "apply-approval-log-gossip-organization-registry-threshold-transition".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "governance")?,
        required_string(&arguments, "transition")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "registry": registry}),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_governance_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "old_governance",
            "new_governance",
            "old_authority_ids",
            "old_authority_private_keys",
            "new_authority_ids",
            "new_authority_private_keys",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let old_ids = required_string_array(&arguments, "old_authority_ids", false)?;
    let old_keys = required_string_array(&arguments, "old_authority_private_keys", false)?;
    let new_ids = required_string_array(&arguments, "new_authority_ids", false)?;
    let new_keys = required_string_array(&arguments, "new_authority_private_keys", false)?;
    if old_ids.len() != old_keys.len() || new_ids.len() != new_keys.len() {
        return Err(json!({
            "detail": "each old/new authority id requires one paired private key"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-approval-log-gossip-organization-registry-governance-rotation".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "old_governance")?,
        required_string(&arguments, "new_governance")?,
    ];
    for (authority_id, key) in old_ids.into_iter().zip(old_keys) {
        command.extend([
            "--old-authority-id".into(),
            authority_id,
            "--old-authority-private-key".into(),
            key,
        ]);
    }
    for (authority_id, key) in new_ids.into_iter().zip(new_keys) {
        command.extend([
            "--new-authority-id".into(),
            authority_id,
            "--new-authority-private-key".into(),
            key,
        ]);
    }
    command.extend([
        "--rotated-at-unix".into(),
        required_nonnegative_integer(&arguments, "rotated_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_approval_transparency_public_log_gossip_organization_registry_governance_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "old_governance",
            "new_governance",
            "rotation",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "apply-approval-log-gossip-organization-registry-governance-rotation".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "old_governance")?,
        required_string(&arguments, "new_governance")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "registry": registry}),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_governed_authority_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "old_governance",
            "new_governance",
            "old_authority_ids",
            "old_authority_private_keys",
            "new_authority_ids",
            "new_authority_private_keys",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let old_ids = required_string_array(&arguments, "old_authority_ids", false)?;
    let old_keys = required_string_array(&arguments, "old_authority_private_keys", false)?;
    let new_ids = required_string_array(&arguments, "new_authority_ids", false)?;
    let new_keys = required_string_array(&arguments, "new_authority_private_keys", false)?;
    if old_ids.len() != old_keys.len() || new_ids.len() != new_keys.len() {
        return Err(json!({
            "detail": "each old/new authority id requires one paired private key"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "sign-approval-log-gossip-organization-registry-governed-authority-key-rotation".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "old_governance")?,
        required_string(&arguments, "new_governance")?,
    ];
    for (authority_id, key) in old_ids.into_iter().zip(old_keys) {
        command.extend([
            "--old-authority-id".into(),
            authority_id,
            "--old-authority-private-key".into(),
            key,
        ]);
    }
    for (authority_id, key) in new_ids.into_iter().zip(new_keys) {
        command.extend([
            "--new-authority-id".into(),
            authority_id,
            "--new-authority-private-key".into(),
            key,
        ]);
    }
    command.extend([
        "--rotated-at-unix".into(),
        required_nonnegative_integer(&arguments, "rotated_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ]);
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_approval_transparency_public_log_gossip_organization_registry_governed_authority_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "registry",
            "old_governance",
            "new_governance",
            "rotation",
            "output",
            "public_key_output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let public_key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-approval-log-gossip-organization-registry-governed-authority-key-rotation".into(),
        required_string(&arguments, "registry")?,
        required_string(&arguments, "old_governance")?,
        required_string(&arguments, "new_governance")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        public_key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let registry = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": public_key_output,
            "registry": registry
        }),
    ))
}

fn audit_approval_transparency_public_log_gossip_organization_registry_history(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["history", "output", "registry_output"])?;
    let output = required_string(&arguments, "output")?;
    let registry_output = required_string(&arguments, "registry_output")?;
    let command = vec![
        "audit-approval-log-gossip-organization-registry-history".into(),
        required_string(&arguments, "history")?,
        "--output".into(),
        output.clone(),
        "--registry-output".into(),
        registry_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let audit = read_json_if_present(Path::new(&output));
    let registry = read_json_if_present(Path::new(&registry_output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "registry_output": registry_output,
            "audit": audit,
            "registry": registry
        }),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "history",
            "authority_private_key",
            "issued_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-approval-log-gossip-organization-registry-history-checkpoint".into(),
        required_string(&arguments, "history")?,
        "--authority-private-key".into(),
        required_string(&arguments, "authority_private_key")?,
        "--issued-at-unix".into(),
        required_nonnegative_integer(&arguments, "issued_at_unix")?.to_string(),
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

fn accept_approval_transparency_public_log_gossip_organization_registry_history_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "history",
            "checkpoint",
            "baseline",
            "accepted_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "accept-approval-log-gossip-organization-registry-history-checkpoint".into(),
        required_string(&arguments, "history")?,
        required_string(&arguments, "checkpoint")?,
        "--accepted-at-unix".into(),
        required_nonnegative_integer(&arguments, "accepted_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ];
    optional_option(&arguments, "baseline", "--baseline", &mut command)?;
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "trust_state": trust_state}),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "history",
            "checkpoint",
            "witness_id",
            "witness_private_key",
            "witnessed_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-approval-log-gossip-organization-registry-history-checkpoint-witness".into(),
        required_string(&arguments, "history")?,
        required_string(&arguments, "checkpoint")?,
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
        "--witness-private-key".into(),
        required_string(&arguments, "witness_private_key")?,
        "--witnessed-at-unix".into(),
        required_nonnegative_integer(&arguments, "witnessed_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let witness = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "witness": witness}),
    ))
}

fn init_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_trust(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["witness_id", "public_key", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-approval-log-gossip-organization-registry-history-checkpoint-witness-trust".into(),
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "trust_state": trust_state}),
    ))
}

fn sign_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "trust_state",
            "old_private_key",
            "new_private_key",
            "rotated_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-approval-log-gossip-organization-registry-history-checkpoint-witness-key-rotation"
            .into(),
        required_string(&arguments, "trust_state")?,
        "--old-private-key".into(),
        required_string(&arguments, "old_private_key")?,
        "--new-private-key".into(),
        required_string(&arguments, "new_private_key")?,
        "--rotated-at-unix".into(),
        required_nonnegative_integer(&arguments, "rotated_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let rotation = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "rotation": rotation}),
    ))
}

fn apply_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["trust_state", "rotation", "output", "public_key_output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let public_key_output = required_string(&arguments, "public_key_output")?;
    let command = vec![
        "apply-approval-log-gossip-organization-registry-history-checkpoint-witness-key-rotation"
            .into(),
        required_string(&arguments, "trust_state")?,
        required_string(&arguments, "rotation")?,
        "--output".into(),
        output.clone(),
        "--public-key-output".into(),
        public_key_output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let trust_state = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "public_key_output": public_key_output,
            "trust_state": trust_state
        }),
    ))
}

fn export_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness_key(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "export-approval-log-gossip-organization-registry-history-checkpoint-witness-key".into(),
        required_string(&arguments, "trust_state")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(execution, json!({"output": output})))
}

fn verify_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witnesses(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "history",
            "checkpoint",
            "witnesses",
            "trusted_witness_ids",
            "trusted_witness_public_keys",
            "minimum_witnesses",
            "evaluated_at_unix",
            "require_quorum",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let witnesses = required_string_array(&arguments, "witnesses", false)?;
    let ids = required_string_array(&arguments, "trusted_witness_ids", true)?;
    let keys = required_string_array(&arguments, "trusted_witness_public_keys", true)?;
    let trust_states = required_string_array(&arguments, "witness_trust_states", true)?;
    let direct_trust = !ids.is_empty() || !keys.is_empty();
    if direct_trust == !trust_states.is_empty() {
        return Err(
            json!({"detail": "supply exactly one direct or trust-state witness key source"}),
        );
    }
    if ids.len() != keys.len() {
        return Err(json!({"detail": "trusted witness id and public key counts must match"}));
    }
    let mut command = vec![
        "verify-approval-log-gossip-organization-registry-history-checkpoint-witnesses".into(),
        required_string(&arguments, "history")?,
        required_string(&arguments, "checkpoint")?,
    ];
    for witness in witnesses {
        command.extend(["--witness".into(), witness]);
    }
    for id in ids {
        command.extend(["--trusted-witness-id".into(), id]);
    }
    for key in keys {
        command.extend(["--trusted-witness-public-key".into(), key]);
    }
    for trust_state in trust_states {
        command.extend(["--witness-trust-state".into(), trust_state]);
    }
    optional_positive_integer(
        &arguments,
        "minimum_witnesses",
        "--minimum-witnesses",
        &mut command,
    )?;
    command.extend([
        "--evaluated-at-unix".into(),
        required_nonnegative_integer(&arguments, "evaluated_at_unix")?.to_string(),
        "--output".into(),
        output.clone(),
    ]);
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

fn request_remote_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "checkpoint_trust_state",
            "endpoint",
            "public_key",
            "witness_key_trust_state",
            "bearer_token_env",
            "timeout_seconds",
            "evaluated_at_unix",
            "output",
            "receipt_output",
        ],
    )?;
    let public_key = optional_string(&arguments, "public_key")?;
    let trust_state = optional_string(&arguments, "witness_key_trust_state")?;
    if public_key.is_some() == trust_state.is_some() {
        return Err(json!({
            "detail": "exactly one of public_key or witness_key_trust_state is required"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let receipt_output = required_string(&arguments, "receipt_output")?;
    let mut command = vec![
        "request-approval-log-gossip-organization-registry-history-checkpoint-witness".into(),
        required_string(&arguments, "checkpoint_trust_state")?,
        "--endpoint".into(),
        required_string(&arguments, "endpoint")?,
    ];
    if let Some(key) = public_key {
        command.extend(["--public-key".into(), key]);
    }
    if let Some(state) = trust_state {
        command.extend(["--witness-key-trust-state".into(), state]);
    }
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
        "--evaluated-at-unix".into(),
        required_nonnegative_integer(&arguments, "evaluated_at_unix")?.to_string(),
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

fn optional_string(
    arguments: &Map<String, Value>,
    name: &str,
) -> std::result::Result<Option<String>, Value> {
    arguments
        .get(name)
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| json!({"detail": format!("{name} must be a non-empty string")}))
        })
        .transpose()
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

fn required_nonnegative_integer(
    arguments: &Map<String, Value>,
    name: &str,
) -> std::result::Result<u64, Value> {
    arguments
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"detail": format!("{name} must be a non-negative integer")}))
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
        assert_eq!(tools.len(), 132);
        let named = |name: &str| {
            tools
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("missing MCP tool {name}"))
        };
        assert_eq!(
            named(
                "verify_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witnesses"
            )["inputSchema"]["properties"]["minimum_witnesses"]["minimum"],
            2
        );
        assert_eq!(
            named(
                "request_remote_approval_transparency_public_log_gossip_organization_registry_history_checkpoint_witness"
            )["execution"]["taskSupport"],
            "forbidden"
        );
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
            named("recommend_policy")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("recommend_policy")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("recommend_policy")["inputSchema"]["properties"]["minimum_occurrences"]["minimum"],
            2
        );
        assert_eq!(
            named("policy_rollout_profile")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("simulate_policy_rollout")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("simulate_policy_rollout")["inputSchema"]["properties"]["project_ids"]["maxItems"],
            1000
        );
        assert_eq!(
            named("sign_rollout_approval")["inputSchema"]["properties"]["decision"]["enum"][0],
            "approve"
        );
        assert_eq!(
            named("verify_rollout_approvals")["inputSchema"]["properties"]["minimum_approvals"]["default"],
            2
        );
        assert_eq!(
            named("verify_rollout_approvals")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("record_canary_monitoring")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("record_canary_monitoring")["inputSchema"]["properties"]["project_ids"]["maxItems"],
            100
        );
        assert_eq!(
            named("sign_canary_completion")["inputSchema"]["properties"]["decision"]["enum"][0],
            "promote"
        );
        assert_eq!(
            named("verify_canary_completion")["inputSchema"]["properties"]["minimum_decisions"]["default"],
            2
        );
        assert_eq!(
            named("advance_policy_deployment")["inputSchema"]["properties"]["require_promotion"]["default"],
            false
        );
        assert_eq!(
            named("advance_policy_deployment")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("verify_policy_deployment")["inputSchema"]["properties"]["project_ids"]["maxItems"],
            1000
        );
        assert_eq!(
            named("verify_policy_deployment")["inputSchema"]["properties"]["require_passed"]["default"],
            false
        );
        assert_eq!(
            named("verify_policy_deployment")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("sign_policy_deployment_rollback")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("apply_policy_deployment_rollback")["inputSchema"]["properties"]["minimum_approvals"]
                ["default"],
            2
        );
        assert_eq!(
            named("apply_policy_deployment_rollback")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("verify_policy_rollback_recovery")["inputSchema"]["properties"]["project_ids"]["maxItems"],
            1000
        );
        assert_eq!(
            named("verify_policy_rollback_recovery")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("sign_rollback_incident_acknowledgment")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("close_rollback_incident")["inputSchema"]["properties"]["require_closed"]["default"],
            false
        );
        assert_eq!(
            named("append_policy_incident_ledger")["inputSchema"]["properties"]["suspension_threshold"]
                ["default"],
            2
        );
        assert_eq!(
            named("append_policy_incident_ledger")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("sign_policy_suspension_decision")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("apply_policy_suspension_decision")["inputSchema"]["properties"]["minimum_decisions"]
                ["default"],
            2
        );
        assert_eq!(
            named("apply_policy_suspension_decision")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("sign_policy_remediation_approval")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("apply_policy_remediation")["inputSchema"]["properties"]["minimum_approvals"]["default"],
            2
        );
        assert_eq!(
            named("apply_policy_remediation")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("append_policy_lifecycle_event")["inputSchema"]["oneOf"][0]["required"][0],
            "suspension"
        );
        assert_eq!(
            named("append_policy_lifecycle_event")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("snapshot_policy_lifecycle")["inputSchema"]["properties"]["generation"]["minimum"],
            1
        );
        assert_eq!(
            named("snapshot_policy_lifecycle")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("sign_policy_lifecycle_checkpoint")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("verify_policy_lifecycle_checkpoint")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("sign_policy_lifecycle_key_rotation")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("witness_policy_lifecycle_checkpoint")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("init_policy_lifecycle_witness_trust")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("sign_policy_lifecycle_witness_key_rotation")["inputSchema"]["properties"]["rotated_at_unix"]
                ["minimum"],
            0
        );
        assert_eq!(
            named("apply_policy_lifecycle_witness_key_rotation")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("export_policy_lifecycle_witness_public_key")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("verify_policy_lifecycle_checkpoint_witnesses")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("verify_policy_lifecycle_checkpoint_witnesses")["inputSchema"]["properties"]["minimum_witnesses"]
                ["default"],
            2
        );
        assert_eq!(
            named("request_remote_policy_lifecycle_checkpoint_witness")["inputSchema"]["properties"]
                ["endpoint"]["pattern"],
            "^https://"
        );
        assert_eq!(
            named("request_remote_policy_lifecycle_checkpoint_witness")["annotations"]["openWorldHint"],
            true
        );
        assert_eq!(
            named("request_remote_policy_lifecycle_checkpoint_witness")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("create_policy_lifecycle_public_anchor")["inputSchema"]["properties"]["log_checkpoints"]
                ["maxItems"],
            100000
        );
        assert_eq!(
            named("create_policy_lifecycle_public_anchor")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("verify_policy_lifecycle_public_anchor")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("create_policy_lifecycle_public_log_consistency")["inputSchema"]["properties"]["log_checkpoints"]
                ["maxItems"],
            100000
        );
        assert_eq!(
            named("create_policy_lifecycle_public_log_consistency")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("verify_policy_lifecycle_public_log_consistency")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("sign_policy_lifecycle_public_log_gossip_receipt")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("verify_policy_lifecycle_public_log_gossip_receipt")["inputSchema"]["properties"]
                ["evaluated_at_unix"]["minimum"],
            0
        );
        assert_eq!(
            named("verify_policy_lifecycle_public_log_gossip_receipt")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("verify_policy_lifecycle_public_log_gossip_quorum")["inputSchema"]["properties"]
                ["observations"]["maxItems"],
            100
        );
        assert_eq!(
            named("verify_policy_lifecycle_public_log_gossip_quorum")["inputSchema"]["oneOf"][1]["required"]
                [0],
            "observer_trust_states"
        );
        assert_eq!(
            named("verify_policy_lifecycle_public_log_gossip_quorum")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("request_remote_policy_lifecycle_public_log_gossip")["inputSchema"]["properties"]
                ["endpoint"]["pattern"],
            "^https://"
        );
        assert_eq!(
            named("request_remote_policy_lifecycle_public_log_gossip")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("init_policy_lifecycle_public_log_gossip_observer_trust")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("sign_policy_lifecycle_public_log_gossip_observer_key_rotation")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("init_policy_lifecycle_public_log_gossip_organization_registry")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("sign_policy_lifecycle_public_log_gossip_organization_registry_transition")["inputSchema"]
                ["properties"]["action"]["enum"][2],
            "revoke-organization"
        );
        assert_eq!(
            named("apply_policy_lifecycle_public_log_gossip_organization_registry_transition")["execution"]
                ["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "sign_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "apply_policy_lifecycle_public_log_gossip_organization_registry_authority_key_rotation"
            )["inputSchema"]["properties"]["public_key_output"]["type"],
            "string"
        );
        assert_eq!(
            named("sign_policy_lifecycle_public_log_gossip_organization_registry_governance")["inputSchema"]
                ["properties"]["minimum_approvals"]["minimum"],
            2
        );
        assert_eq!(
            named(
                "sign_policy_lifecycle_public_log_gossip_organization_registry_successor_governance"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "sign_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition"
            )["inputSchema"]["properties"]["authority_private_keys"]["minItems"],
            2
        );
        assert_eq!(
            named(
                "apply_policy_lifecycle_public_log_gossip_organization_registry_threshold_transition"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "sign_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation"
            )["inputSchema"]["properties"]["old_authority_ids"]["minItems"],
            2
        );
        assert_eq!(
            named(
                "apply_policy_lifecycle_public_log_gossip_organization_registry_governance_rotation"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "sign_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation"
            )["inputSchema"]["properties"]["new_authority_ids"]["minItems"],
            2
        );
        assert_eq!(
            named(
                "apply_policy_lifecycle_public_log_gossip_organization_registry_governed_authority_key_rotation"
            )["inputSchema"]["properties"]["public_key_output"]["type"],
            "string"
        );
        assert_eq!(
            named("audit_policy_lifecycle_public_log_gossip_organization_registry_history")["execution"]
                ["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint"
            )["inputSchema"]["properties"]["issued_at_unix"]["minimum"],
            0
        );
        assert_eq!(
            named(
                "accept_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "verify_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witnesses"
            )["inputSchema"]["properties"]["minimum_witnesses"]["minimum"],
            2
        );
        assert_eq!(
            named(
                "request_remote_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness"
            )["inputSchema"]["properties"]["endpoint"]["pattern"],
            "^https://"
        );
        assert_eq!(
            named(
                "request_remote_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness"
            )["annotations"]["openWorldHint"],
            true
        );
        assert_eq!(
            named(
                "request_remote_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "sign_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation"
            )["inputSchema"]["properties"]["rotated_at_unix"]["minimum"],
            0
        );
        assert_eq!(
            named(
                "apply_policy_lifecycle_public_log_gossip_organization_registry_history_checkpoint_witness_key_rotation"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("request_remote_policy_lifecycle_public_log_gossip")["annotations"]["openWorldHint"],
            true
        );
        assert_eq!(
            named("verify_policy_lifecycle_checkpoint")["inputSchema"]["properties"]["accepted_at_unix"]
                ["minimum"],
            0
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
            named("append_approval_transparency_log")["inputSchema"]["properties"]["kind"]["enum"]
                [5],
            "remote-registry-history-checkpoint-witness-receipt"
        );
        assert_eq!(
            named("append_approval_transparency_log")["inputSchema"]["properties"]["kind"]["enum"]
                [6],
            "remote-approval-registry-history-checkpoint-witness-receipt"
        );
        assert_eq!(
            named("append_verified_remote_approval_registry_history_witness_receipt")["inputSchema"]
                ["oneOf"][1]["required"][0],
            "witness_key_trust_state"
        );
        assert_eq!(
            named("append_verified_remote_approval_registry_history_witness_receipt")["annotations"]
                ["destructiveHint"],
            true
        );
        assert_eq!(
            named("append_verified_remote_approval_registry_history_witness_receipt_quorum")["inputSchema"]
                ["properties"]["minimum_witnesses"]["minimum"],
            2
        );
        assert_eq!(
            named("append_verified_remote_approval_registry_history_witness_receipt_quorum")["inputSchema"]
                ["oneOf"][1]["required"][0],
            "witness_key_trust_states"
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
        assert_eq!(
            named("apply_approval_transparency_witness_key_rotation")["inputSchema"]["required"][3],
            "public_key_output"
        );
        assert_eq!(
            named("create_approval_transparency_public_anchor")["inputSchema"]["properties"]["log_checkpoints"]
                ["maxItems"],
            100000
        );
        assert_eq!(
            named("create_approval_transparency_public_log_consistency")["inputSchema"]["properties"]
                ["log_checkpoints"]["maxItems"],
            100000
        );
        assert_eq!(
            named("verify_approval_transparency_public_log_consistency")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("sign_approval_transparency_public_log_gossip_receipt")["inputSchema"]["properties"]
                ["expires_at_unix"]["minimum"],
            1
        );
        assert_eq!(
            named("verify_approval_transparency_public_log_gossip_receipt")["inputSchema"]["properties"]
                ["consistency_proof"]["type"],
            "string"
        );
        assert_eq!(
            named("verify_approval_transparency_public_log_gossip_quorum")["inputSchema"]["properties"]
                ["observations"]["maxItems"],
            100
        );
        assert_eq!(
            named("request_remote_approval_transparency_public_log_gossip")["inputSchema"]["properties"]
                ["endpoint"]["pattern"],
            "^https://"
        );
        assert_eq!(
            named("request_remote_approval_transparency_public_log_gossip")["annotations"]["openWorldHint"],
            true
        );
        assert_eq!(
            named("verify_approval_transparency_public_log_gossip_quorum")["inputSchema"]["oneOf"]
                [1]["required"][0],
            "observer_trust_states"
        );
        assert_eq!(
            named("apply_approval_transparency_public_log_gossip_observer_key_rotation")["inputSchema"]
                ["required"][3],
            "public_key_output"
        );
        assert_eq!(
            named("verify_approval_transparency_public_log_gossip_quorum")["inputSchema"]["properties"]
                ["organization_registry"]["type"],
            "string"
        );
        assert_eq!(
            named("sign_approval_transparency_public_log_gossip_organization_registry_transition")
                ["inputSchema"]["properties"]["action"]["enum"][2],
            "revoke-organization"
        );
        assert_eq!(
            named(
                "apply_approval_transparency_public_log_gossip_organization_registry_authority_key_rotation"
            )["inputSchema"]["required"][3],
            "public_key_output"
        );
        assert_eq!(
            named("sign_approval_transparency_public_log_gossip_organization_registry_governance")
                ["inputSchema"]["properties"]["minimum_approvals"]["minimum"],
            2
        );
        assert_eq!(
            named(
                "apply_approval_transparency_public_log_gossip_organization_registry_governance_rotation"
            )["inputSchema"]["required"][4],
            "output"
        );
        assert_eq!(
            named(
                "sign_approval_transparency_public_log_gossip_organization_registry_successor_governance"
            )["inputSchema"]["properties"]["minimum_approvals"]["minimum"],
            2
        );
        assert_eq!(
            named(
                "apply_approval_transparency_public_log_gossip_organization_registry_governed_authority_key_rotation"
            )["inputSchema"]["required"][5],
            "public_key_output"
        );
        assert_eq!(
            named("audit_approval_transparency_public_log_gossip_organization_registry_history")["inputSchema"]
                ["required"][2],
            "registry_output"
        );
        assert_eq!(
            named("fetch_policy_pack")["inputSchema"]["properties"]["timeout_seconds"]["maximum"],
            600
        );
        assert_eq!(
            named("fetch_policy_pack")["annotations"]["openWorldHint"],
            true
        );
        assert_eq!(
            named("request_remote_approval_transparency_witness")["annotations"]["openWorldHint"],
            true
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

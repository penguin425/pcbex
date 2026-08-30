use anyhow::{Context, Result};
use pcbex_core::dfm_profiles;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    io::{self, BufRead, Write},
    path::Path,
    process::Command,
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
const MAX_MCP_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_MCP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MCP_PROCESS_MESSAGE_BYTES: usize = 4 * 1024;
// The writer emits a KiCad document that may be larger than the generic MCP
// response/file-reader ceiling.  Keep this command-specific bound tied to the
// writer's own limit, while returning only an authenticated summary over MCP.
const MAX_CIRCUIT_KICAD_SCHEMATIC_BYTES: u64 =
    pcbex_kicad::CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES as u64;
static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
thread_local! {
    static AFTER_FABRICATION_REPORT_READ_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static AFTER_FABRICATION_SUMMARY_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_after_fabrication_report_read_hook(hook: impl FnOnce() + 'static) {
    AFTER_FABRICATION_REPORT_READ_HOOK.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}

#[cfg(test)]
fn invoke_after_fabrication_report_read_hook() {
    let hook = AFTER_FABRICATION_REPORT_READ_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn set_after_fabrication_summary_hook(hook: impl FnOnce() + 'static) {
    AFTER_FABRICATION_SUMMARY_HOOK.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}

#[cfg(test)]
fn invoke_after_fabrication_summary_hook() {
    let hook = AFTER_FABRICATION_SUMMARY_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Lifecycle {
    #[default]
    Uninitialized,
    Initializing,
    Ready,
}

pub fn serve_stdio() -> Result<()> {
    let stdin = io::stdin();
    let mut stdin = io::BufReader::new(stdin.lock());
    let mut stdout = io::stdout().lock();
    let mut server = McpServer::default();
    loop {
        let line = read_bounded_line(&mut stdin).context("reading MCP stdio request")?;
        let Some(line) = line else { break };
        let response = match line {
            BoundedLine::Line(line) if line.is_empty() => None,
            BoundedLine::Line(line) => server.handle_line(&line),
            BoundedLine::Oversized => Some(error_response(
                Value::Null,
                -32600,
                "Invalid Request",
                Some(json!({
                    "detail": format!(
                        "MCP request exceeds {MAX_MCP_REQUEST_BYTES} bytes"
                    )
                })),
            )),
        };
        if let Some(response) = response {
            write_bounded_response(&mut stdout, &response).context("writing MCP stdio response")?;
        }
    }
    Ok(())
}

enum BoundedLine {
    Line(String),
    Oversized,
}

/// Read one newline-delimited request while keeping both allocation and
/// protocol framing bounded.  Once a line exceeds the limit, all remaining
/// bytes through its newline (or EOF) are drained before returning so the
/// next request starts at a known frame boundary.
fn read_bounded_line<R: BufRead>(reader: &mut R) -> io::Result<Option<BoundedLine>> {
    let mut bytes = Vec::new();
    let mut oversized = false;

    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            if oversized {
                return Ok(Some(BoundedLine::Oversized));
            }
            if bytes.is_empty() {
                return Ok(None);
            }
            return decode_bounded_line(bytes).map(BoundedLine::Line).map(Some);
        }

        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let content_len = newline.unwrap_or(chunk.len());
        if !oversized {
            if content_len > MAX_MCP_REQUEST_BYTES.saturating_sub(bytes.len()) {
                oversized = true;
                bytes.clear();
            } else {
                bytes.extend_from_slice(&chunk[..content_len]);
            }
        }
        let consumed = newline.map_or(chunk.len(), |index| index + 1);
        reader.consume(consumed);

        if newline.is_some() {
            if oversized {
                return Ok(Some(BoundedLine::Oversized));
            }
            return decode_bounded_line(bytes).map(BoundedLine::Line).map(Some);
        }
    }
}

fn decode_bounded_line(mut bytes: Vec<u8>) -> io::Result<String> {
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("MCP request is not valid UTF-8: {error}"),
        )
    })
}

struct BoundedResponseWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedResponseWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}

impl Write for BoundedResponseWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP response exceeds the byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json_line(value: &Value) -> Option<Vec<u8>> {
    // Reserve one byte for the protocol newline so the complete frame remains
    // within MAX_MCP_RESPONSE_BYTES.
    let mut output = BoundedResponseWriter::new(MAX_MCP_RESPONSE_BYTES.saturating_sub(1));
    serde_json::to_writer(&mut output, value).ok()?;
    output.bytes.push(b'\n');
    Some(output.bytes)
}

fn response_bytes(value: &Value) -> Vec<u8> {
    bounded_json_line(value).unwrap_or_else(|| {
        let fallback = error_response(
            Value::Null,
            -32603,
            "Internal error",
            Some(json!({"detail": "MCP response exceeds 16 MiB"})),
        );
        bounded_json_line(&fallback).expect("bounded MCP internal-error response serializes")
    })
}

fn write_bounded_response<W: Write>(writer: &mut W, value: &Value) -> io::Result<()> {
    writer.write_all(&response_bytes(value))?;
    writer.flush()
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
                    | "check_schematic"
                    | "check_circuit_spec"
                    | "write_circuit_spec_kicad_schematic"
                    | "verify_circuit_kicad_handoff"
                    | "verify_circuit_kicad_board_binding"
                    | "pipeline_verify"
                    | "run_deterministic_pipeline"
                    | "verify_fabrication_authorization"
                    | "compile_deterministic_pipeline_plan"
                    | "run_native_kicad_erc"
                    | "run_native_kicad_drc"
                    | "verify_native_kicad_erc_report"
                    | "verify_native_kicad_drc_report"
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
        let create_result = success_response(id.clone(), json!({"task": task_json(&record)}));
        self.tasks.insert(task_id, Arc::clone(&record));
        if let Err(error) = arm_task_expiration(&record) {
            self.tasks.remove(&record.task_id);
            self.active_tasks.fetch_sub(1, Ordering::SeqCst);
            return error_response(
                id,
                -32000,
                "Task execution unavailable",
                Some(json!({"detail": format!("starting task TTL monitor: {error}")})),
            );
        }
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
        self.tasks.retain(|_, record| {
            if record.created.elapsed() < Duration::from_millis(record.ttl_ms) {
                return true;
            }
            expire_working_task(record);
            false
        });
    }
}

fn arm_task_expiration(record: &Arc<TaskRecord>) -> io::Result<()> {
    let ttl = Duration::from_millis(record.ttl_ms);
    let record = Arc::downgrade(record);
    thread::Builder::new()
        .name("pcbex-mcp-task-ttl".to_string())
        .spawn(move || {
            thread::sleep(ttl);
            if let Some(record) = record.upgrade() {
                expire_working_task(&record);
            }
        })?;
    Ok(())
}

fn expire_working_task(record: &TaskRecord) {
    let mut state = record.state.lock().expect("task state lock");
    if state.status != TaskStatus::Working {
        return;
    }
    record.cancellation.store(true, Ordering::SeqCst);
    state.status = TaskStatus::Cancelled;
    state.status_message = "task TTL expired".to_string();
    state.last_updated_at = iso8601_now();
    state.result = Some(TaskOutcome::Result(tool_error_result(
        json!({"detail": "task TTL expired"}),
    )));
    record.changed.notify_all();
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
                    "physical_profile": {"type": "string"},
                    "fail_on_violations": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "check_schematic",
            "Check KiCad schematic",
            "Run deterministic electrical checks on a KiCad schematic and retain the closed review and optional explanation, JUnit, and SARIF artifacts.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "output"],
                "properties": {
                    "input": {"type": "string"},
                    "output": {"type": "string"},
                    "explain": {"type": "string"},
                    "junit_output": {"type": "string"},
                    "sarif_output": {"type": "string"},
                    "policy": {"type": "string"},
                    "policy_pack": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                },
                "not": {"required": ["policy", "policy_pack"]}
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "check_circuit_spec",
            "Check circuit specification",
            "Normalize a circuit-spec v2 JSON document, run its immutable electrical ERC floor, and retain the closed check report.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "output"],
                "properties": {
                    "input": {"type": "string"},
                    "output": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "write_circuit_spec_kicad_schematic",
            "Write circuit-spec KiCad schematic",
            "Write an immutable-ERC-approved circuit-spec v2 as a deterministic flat KiCad schematic and return only its bounded digest summary.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "output"],
                "properties": {
                    "input": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_circuit_kicad_handoff",
            "Verify circuit-to-KiCad handoff",
            "Verify that a circuit-spec v2 and KiCad schematic represent the same normalized electrical design, retaining the closed handoff report on rejection.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["circuit_spec", "schematic", "output"],
                "properties": {
                    "circuit_spec": {"type": "string"},
                    "schematic": {"type": "string"},
                    "policy": {"type": "string"},
                    "output": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_circuit_kicad_board_binding",
            "Verify circuit-to-KiCad board binding",
            "Verify that a circuit-spec v2, KiCad schematic, and KiCad board represent the same bound design, retaining the closed board-binding report on rejection.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["circuit_spec", "schematic", "board", "output"],
                "properties": {
                    "circuit_spec": {"type": "string"},
                    "schematic": {"type": "string"},
                    "board": {"type": "string"},
                    "policy": {"type": "string"},
                    "output": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "pipeline_verify",
            "Verify hardware pipeline",
            "Verify the complete deterministic hardware pipeline and retain its closed multi-phase gate report, including rejected reports.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "schematic", "electrical_review", "board", "analysis_manifest",
                    "analysis_checks", "quality", "manufacturing_package",
                    "firmware_manifest", "output"
                ],
                "properties": {
                    "schematic": {"type": "string"},
                    "electrical_policy": {"type": "string"},
                    "electrical_review": {"type": "string"},
                    "board": {"type": "string"},
                    "analysis_manifest": {"type": "string"},
                    "analysis_checks": {"type": "string"},
                    "quality": {"type": "string"},
                    "analysis_project": {"type": "string"},
                    "analysis_rules": {"type": "string"},
                    "analysis_dfm_profile": {"type": "string"},
                    "analysis_policy_pack": {"type": "string"},
                    "analysis_physical_profile": {"type": "string"},
                    "manufacturing_package": {"type": "string"},
                    "firmware_manifest": {"type": "string"},
                    "factory_receipt": {"type": "string"},
                    "require_factory": {"type": "boolean", "default": false},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "run_deterministic_pipeline",
            "Run deterministic hardware pipeline",
            "Run a closed, digest-bound deterministic pipeline plan and retain its aggregate report, including rejected reports before an optional approval gate fails.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["plan", "output"],
                "properties": {
                    "plan": {"type": "string"},
                    "output": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_fabrication_authorization",
            "Verify fabrication authorization",
            "Verification-only: freshly replay exact fabrication evidence and verify a dedicated human authorization quorum, retaining truthful not-authorized reports before an optional gate fails; never sign approvals or place factory orders.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "plan", "retained_report", "manufacturing_package",
                    "factory_receipt", "policy_pack", "approvals", "output"
                ],
                "properties": {
                    "plan": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "retained_report": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "manufacturing_package": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "factory_receipt": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "policy_pack": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "approvals": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1, "maxLength": 4096}
                    },
                    "output": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "require_authorized": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "compile_deterministic_pipeline_plan",
            "Compile deterministic pipeline intent",
            "Compile a closed deterministic pipeline intent into a canonical digest-bound plan and return only authenticated intent/plan metadata.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["intent", "output"],
                "properties": {
                    "intent": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "run_native_kicad_erc",
            "Run native KiCad ERC",
            "Run KiCad's native electrical rules checker against a schematic and retain its closed, digest-bound report, including rejected reports before an optional approval gate fails.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "output"],
                "properties": {
                    "input": {"type": "string"},
                    "output": {"type": "string"},
                    "kicad_cli": {"type": "string"},
                    "warning_policy": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "run_native_kicad_drc",
            "Run native KiCad PCB DRC",
            "Run KiCad's native PCB design-rules checker against a board and retain its closed, digest-bound report, including rejected reports before an optional approval gate fails.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "output"],
                "properties": {
                    "input": {"type": "string", "minLength": 1},
                    "output": {"type": "string", "minLength": 1},
                    "project": {"type": "string", "minLength": 1},
                    "rules_file": {"type": "string", "minLength": 1},
                    "kicad_cli": {"type": "string", "minLength": 1},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            false,
            true,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_native_kicad_drc_report",
            "Verify native KiCad PCB DRC report",
            "Re-run KiCad's native PCB design-rules checker and verify a retained, digest-bound report without modifying it; rejected evidence remains valid unless approval is required.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "report"],
                "properties": {
                    "input": {"type": "string", "minLength": 1},
                    "report": {"type": "string", "minLength": 1},
                    "project": {"type": "string", "minLength": 1},
                    "rules_file": {"type": "string", "minLength": 1},
                    "kicad_cli": {"type": "string", "minLength": 1},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            true,
            false,
            tasks_supported.then_some("optional"),
        ),
        tool(
            "verify_native_kicad_erc_report",
            "Verify native KiCad ERC report",
            "Re-run KiCad's native electrical rules checker and verify a retained, digest-bound schematic ERC report without modifying it; rejected evidence remains valid unless approval is required.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["input", "retained_report"],
                "properties": {
                    "input": {"type": "string", "minLength": 1},
                    "retained_report": {"type": "string", "minLength": 1},
                    "warning_policy": {"type": "string", "minLength": 1},
                    "kicad_cli": {"type": "string", "minLength": 1},
                    "require_approved": {"type": "boolean", "default": false}
                }
            }),
            true,
            false,
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
                    "physical_profile": {"type": "string"},
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
            "Recompute and bind schematic, electrical, simulation, and requirement evidence into a review request; a deterministic plan/report pair creates a live-verified schema-v2 artifact-bound request, while native KiCad ERC evidence creates schema-v3 (error-only) or schema-v4 (warning-policy) evidence.",
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
                    "deterministic_pipeline_plan": {"type": "string"},
                    "deterministic_pipeline_report": {"type": "string"},
                    "native_kicad_erc_report": {"type": "string"},
                    "native_kicad_erc_warning_policy": {"type": "string"},
                    "kicad_cli": {"type": "string"},
                    "output": {"type": "string"},
                    "session_output": {"type": "string"}
                },
                "allOf": [{
                    "oneOf": [
                        {
                            "required": ["deterministic_pipeline_plan", "deterministic_pipeline_report"],
                            "not": {"anyOf": [
                                {"required": ["native_kicad_erc_report"]},
                                {"required": ["native_kicad_erc_warning_policy"]}
                            ]}
                        },
                        {"not": {"anyOf": [
                            {"required": ["deterministic_pipeline_plan"]},
                            {"required": ["deterministic_pipeline_report"]},
                            {"required": ["native_kicad_erc_report"]},
                            {"required": ["native_kicad_erc_warning_policy"]}
                        ]}},
                        {"required": [
                            "deterministic_pipeline_plan",
                            "deterministic_pipeline_report",
                            "native_kicad_erc_report"
                        ]}
                    ]
                }, {
                    "if": {"required": ["kicad_cli"]},
                    "then": {"required": ["native_kicad_erc_report"]}
                }, {
                    "if": {"required": ["native_kicad_erc_warning_policy"]},
                    "then": {"required": ["native_kicad_erc_report"]}
                }]
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_schematic_approval",
            "Sign AI schematic approval",
            "Evaluate a bound AI response and create an Ed25519-signed approval or rejection. Either a live schema-v1 KiCad schematic is revalidated, or request-schema-v2/v3/v4 artifacts are rerun and revalidated, including native KiCad ERC evidence, before the private key is read.",
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
                    "schematic": {"type": "string"},
                    "generated_schematic": {"type": "string"},
                    "deterministic_pipeline_plan": {"type": "string"},
                    "deterministic_pipeline_report": {"type": "string"},
                    "native_kicad_erc_report": {"type": "string"},
                    "native_kicad_erc_warning_policy": {"type": "string"},
                    "kicad_cli": {"type": "string"},
                    "output": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                },
                "allOf": [{
                    "oneOf": [
                        {
                            "required": [
                                "generated_schematic",
                                "deterministic_pipeline_plan",
                                "deterministic_pipeline_report"
                            ],
                            "not": {"anyOf": [
                                {"required": ["native_kicad_erc_report"]},
                                {"required": ["native_kicad_erc_warning_policy"]},
                                {"required": ["schematic"]}
                            ]}
                        },
                        {"not": {"anyOf": [
                            {"required": ["schematic"]},
                            {"required": ["generated_schematic"]},
                            {"required": ["deterministic_pipeline_plan"]},
                            {"required": ["deterministic_pipeline_report"]},
                            {"required": ["native_kicad_erc_report"]},
                            {"required": ["native_kicad_erc_warning_policy"]}
                        ]}},
                        {"required": [
                            "generated_schematic",
                            "deterministic_pipeline_plan",
                            "deterministic_pipeline_report",
                            "native_kicad_erc_report"
                        ], "not": {"required": ["schematic"]}},
                        {
                            "required": ["schematic"],
                            "not": {"anyOf": [
                                {"required": ["generated_schematic"]},
                                {"required": ["deterministic_pipeline_plan"]},
                                {"required": ["deterministic_pipeline_report"]},
                                {"required": ["native_kicad_erc_report"]},
                                {"required": ["native_kicad_erc_warning_policy"]},
                                {"required": ["kicad_cli"]}
                            ]}
                        }
                    ]
                }, {
                    "if": {"required": ["kicad_cli"]},
                    "then": {"required": ["native_kicad_erc_report"]}
                }, {
                    "if": {"required": ["native_kicad_erc_warning_policy"]},
                    "then": {"required": ["native_kicad_erc_report"]}
                }]
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_schematic_approval",
            "Verify AI schematic approval",
            "Strictly verify an Ed25519 approval against its exact request, AI response, and either a live schema-v1 KiCad schematic or request-schema-v2/v3/v4 artifacts, including native KiCad ERC evidence.",
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
                    "schematic": {"type": "string"},
                    "generated_schematic": {"type": "string"},
                    "deterministic_pipeline_plan": {"type": "string"},
                    "deterministic_pipeline_report": {"type": "string"},
                    "native_kicad_erc_report": {"type": "string"},
                    "native_kicad_erc_warning_policy": {"type": "string"},
                    "kicad_cli": {"type": "string"},
                    "require_approved": {"type": "boolean", "default": false}
                },
                "allOf": [{
                    "oneOf": [
                        {
                            "required": [
                                "generated_schematic",
                                "deterministic_pipeline_plan",
                                "deterministic_pipeline_report"
                            ],
                            "not": {"anyOf": [
                                {"required": ["native_kicad_erc_report"]},
                                {"required": ["native_kicad_erc_warning_policy"]},
                                {"required": ["schematic"]}
                            ]}
                        },
                        {"not": {"anyOf": [
                            {"required": ["schematic"]},
                            {"required": ["generated_schematic"]},
                            {"required": ["deterministic_pipeline_plan"]},
                            {"required": ["deterministic_pipeline_report"]},
                            {"required": ["native_kicad_erc_report"]},
                            {"required": ["native_kicad_erc_warning_policy"]}
                        ]}},
                        {"required": [
                            "generated_schematic",
                            "deterministic_pipeline_plan",
                            "deterministic_pipeline_report",
                            "native_kicad_erc_report"
                        ], "not": {"required": ["schematic"]}},
                        {
                            "required": ["schematic"],
                            "not": {"anyOf": [
                                {"required": ["generated_schematic"]},
                                {"required": ["deterministic_pipeline_plan"]},
                                {"required": ["deterministic_pipeline_report"]},
                                {"required": ["native_kicad_erc_report"]},
                                {"required": ["native_kicad_erc_warning_policy"]},
                                {"required": ["kicad_cli"]}
                            ]}
                        }
                    ]
                }, {
                    "if": {"required": ["kicad_cli"]},
                    "then": {"required": ["native_kicad_erc_report"]}
                }, {
                    "if": {"required": ["native_kicad_erc_warning_policy"]},
                    "then": {"required": ["native_kicad_erc_report"]}
                }]
            }),
            true,
            false,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_schematic_approval_quorum",
            "Verify AI schematic approval quorum",
            "Verify independent signed reviews and either a live schema-v1 KiCad schematic or request-schema-v2/v3/v4 artifacts, including native KiCad ERC evidence, against one bound request, then enforce approval, provider, and model thresholds.",
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
                    "schematic": {"type": "string"},
                    "generated_schematic": {"type": "string"},
                    "deterministic_pipeline_plan": {"type": "string"},
                    "deterministic_pipeline_report": {"type": "string"},
                    "native_kicad_erc_report": {"type": "string"},
                    "native_kicad_erc_warning_policy": {"type": "string"},
                    "kicad_cli": {"type": "string"},
                    "output": {"type": "string"},
                    "summary_output": {"type": "string"},
                    "require_quorum": {"type": "boolean", "default": false}
                },
                "allOf": [{
                    "oneOf": [
                        {
                            "required": [
                                "generated_schematic",
                                "deterministic_pipeline_plan",
                                "deterministic_pipeline_report"
                            ],
                            "not": {"anyOf": [
                                {"required": ["native_kicad_erc_report"]},
                                {"required": ["native_kicad_erc_warning_policy"]},
                                {"required": ["schematic"]}
                            ]}
                        },
                        {"not": {"anyOf": [
                            {"required": ["schematic"]},
                            {"required": ["generated_schematic"]},
                            {"required": ["deterministic_pipeline_plan"]},
                            {"required": ["deterministic_pipeline_report"]},
                            {"required": ["native_kicad_erc_report"]},
                            {"required": ["native_kicad_erc_warning_policy"]}
                        ]}},
                        {"required": [
                            "generated_schematic",
                            "deterministic_pipeline_plan",
                            "deterministic_pipeline_report",
                            "native_kicad_erc_report"
                        ], "not": {"required": ["schematic"]}},
                        {
                            "required": ["schematic"],
                            "not": {"anyOf": [
                                {"required": ["generated_schematic"]},
                                {"required": ["deterministic_pipeline_plan"]},
                                {"required": ["deterministic_pipeline_report"]},
                                {"required": ["native_kicad_erc_report"]},
                                {"required": ["native_kicad_erc_warning_policy"]},
                                {"required": ["kicad_cli"]}
                            ]}
                        }
                    ]
                }, {
                    "if": {"required": ["kicad_cli"]},
                    "then": {"required": ["native_kicad_erc_report"]}
                }, {
                    "if": {"required": ["native_kicad_erc_warning_policy"]},
                    "then": {"required": ["native_kicad_erc_report"]}
                }]
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
                        "remote-approval-registry-history-checkpoint-witness-receipt",
                        "remote-factory-release-registry-history-checkpoint-witness-receipt",
                        "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt"
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
            "append_verified_remote_factory_release_registry_history_witness_receipt",
            "Verify and append factory registry witness receipt",
            "Replay complete factory registry history, retained checkpoint trust, exact response bytes, witness trust, freshness, and the Ed25519 signature before appending one receipt.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "receipt", "history", "checkpoint_trust_state",
                    "response", "output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "receipt": {"type": "string"},
                    "history": {"type": "string"},
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
            "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt",
            "Verify and append factory receipt-quorum checkpoint witness receipt",
            "Replay the exact quorum report, complete approval log, signed checkpoint, raw witness response, checkpoint trust, witness trust, freshness, and Ed25519 signatures before appending one receipt.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "receipt", "quorum_report", "approval_log", "checkpoint",
                    "checkpoint_public_key", "response", "output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "receipt": {"type": "string"},
                    "quorum_report": {"type": "string"},
                    "approval_log": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "checkpoint_public_key": {"type": "string"},
                    "response": {"type": "string"},
                    "witness_public_key": {"type": "string"},
                    "witness_trust_state": {"type": "string"},
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "recorded_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                },
                "oneOf": [
                    {"required": ["witness_public_key"], "not": {"required": ["witness_trust_state"]}},
                    {"required": ["witness_trust_state"], "not": {"required": ["witness_public_key"]}}
                ]
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum",
            "Verify and append factory checkpoint-witness receipt quorum",
            "Replay one exact quorum report, complete approval log, signed checkpoint, raw witness responses, checkpoint trust, per-witness trust, freshness, and Ed25519 signatures before no-clobber publication of the admitted receipt quorum and report.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "receipts", "quorum_report", "approval_log",
                    "checkpoint", "checkpoint_public_key", "responses",
                    "output", "report_output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "receipts": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "quorum_report": {"type": "string"},
                    "approval_log": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "checkpoint_public_key": {"type": "string"},
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
                    "witness_trust_states": {
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
                        "not": {"required": ["witness_trust_states"]}
                    },
                    {
                        "required": ["witness_trust_states"],
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
            "append_verified_remote_factory_release_registry_history_witness_receipt_quorum",
            "Verify and append factory registry witness receipt quorum",
            "Replay one complete factory registry history and atomically append only after distinct trusted witnesses, keys, exact responses, freshness, and signatures meet the configured quorum.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "receipts", "history", "checkpoint_trust_state",
                    "responses", "output", "report_output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "receipts": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "history": {"type": "string"},
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
            "sign_quorum_bound_factory_release_receipt_transparency_log",
            "Sign quorum-bound factory receipt-log checkpoint",
            "Create an Ed25519 checkpoint only when the exact log and its factory receipt suffix match a successful verifier-bound receipt quorum report.",
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
            "sign_quorum_bound_factory_checkpoint_witness_receipt_transparency_log",
            "Sign quorum-bound factory checkpoint-witness receipt log",
            "Create an Ed25519 checkpoint only when the exact log and its factory checkpoint-witness receipt suffix match a successful verifier-bound receipt quorum report.",
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
            "sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint",
            "Sign dedicated factory checkpoint-witness receipt-quorum checkpoint",
            "Domain-separate and sign the exact verifier-bound factory checkpoint-witness receipt-quorum report digest and admission-log state.",
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
            "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint",
            "Verify dedicated factory checkpoint-witness receipt-quorum checkpoint",
            "Verify the factory checkpoint-witness receipt-quorum signature against the exact report, admission log, and trusted public key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["log", "quorum_report", "checkpoint", "public_key", "output"],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
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
            "witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint",
            "Witness dedicated factory checkpoint-witness receipt-quorum checkpoint",
            "Re-verify the exact admission report, admission log, dedicated checkpoint, and trusted checkpoint signature before independently signing its digest.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "quorum_report", "checkpoint", "checkpoint_public_key",
                    "private_key", "witness_id", "output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "checkpoint_public_key": {"type": "string"},
                    "private_key": {"type": "string"},
                    "witness_id": {"type": "string"},
                    "witnessed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses",
            "Verify factory checkpoint-witness receipt-quorum checkpoint witnesses",
            "Re-verify the exact dedicated checkpoint evidence and require a fresh quorum of distinct trusted witness identities and keys.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "quorum_report", "checkpoint", "checkpoint_public_key",
                    "witnesses", "witness_public_keys", "minimum_witnesses", "output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "checkpoint_public_key": {"type": "string"},
                    "witnesses": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "witness_public_keys": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "minimum_witnesses": {
                        "type": "integer", "minimum": 2, "maximum": 100
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint",
            "Sign dedicated factory receipt-quorum checkpoint",
            "Domain-separate and sign the exact verifier-bound factory receipt-quorum report digest and approval-log state.",
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
            "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint",
            "Verify dedicated factory receipt-quorum checkpoint",
            "Verify the factory-specific signature against the exact quorum report, approval log, and trusted public key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["log", "quorum_report", "checkpoint", "public_key", "output"],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
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
            "witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint",
            "Witness dedicated factory receipt-quorum checkpoint",
            "Re-verify the exact factory quorum report, approval log, and trusted checkpoint signature before independently signing its digest.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "quorum_report", "checkpoint", "checkpoint_public_key",
                    "private_key", "witness_id", "output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "checkpoint_public_key": {"type": "string"},
                    "private_key": {"type": "string"},
                    "witness_id": {"type": "string"},
                    "witnessed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses",
            "Verify factory receipt-quorum checkpoint witnesses",
            "Re-verify the exact factory checkpoint evidence and require a fresh quorum of distinct trusted witness identities and keys.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "quorum_report", "checkpoint", "checkpoint_public_key",
                    "witnesses", "minimum_witnesses", "output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "checkpoint_public_key": {"type": "string"},
                    "witnesses": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "witness_public_keys": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "witness_trust_states": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "minimum_witnesses": {
                        "type": "integer", "minimum": 2, "maximum": 100
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                },
                "oneOf": [
                    {
                        "required": ["witness_public_keys"],
                        "not": {"required": ["witness_trust_states"]}
                    },
                    {
                        "required": ["witness_trust_states"],
                        "not": {"required": ["witness_public_keys"]}
                    }
                ]
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "init_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust",
            "Initialize factory checkpoint witness trust",
            "Pin generation-zero trust for one factory receipt-quorum checkpoint witness identity and Ed25519 public key.",
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
            "sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation",
            "Sign factory checkpoint witness key rotation",
            "Require old-key authorization and new-key possession for one generation-chained factory witness trust transition.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "old_private_key", "new_private_key", "output"
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
            "apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation",
            "Apply factory checkpoint witness key rotation",
            "Verify and atomically advance retained factory receipt-quorum checkpoint witness trust by exactly one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "rotation", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "export_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_public_key",
            "Export factory checkpoint witness public key",
            "Validate retained factory witness trust and export its currently trusted Ed25519 public key.",
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
            "sign_remote_approval_registry_history_receipt_quorum_log_checkpoint",
            "Sign dedicated receipt-quorum log checkpoint",
            "Domain-separate and sign the exact verifier-bound quorum report digest and approval log state.",
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
            "verify_remote_approval_registry_history_receipt_quorum_log_checkpoint",
            "Verify dedicated receipt-quorum log checkpoint",
            "Verify the dedicated signature against the exact quorum report, approval log, and trusted public key.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["log", "quorum_report", "checkpoint", "public_key", "output"],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
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
            "witness_remote_approval_registry_history_receipt_quorum_log_checkpoint",
            "Witness dedicated receipt-quorum checkpoint",
            "Re-verify the exact quorum report, approval log, and trusted checkpoint signature before independently signing its digest.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "quorum_report", "checkpoint", "checkpoint_public_key",
                    "private_key", "witness_id", "output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "checkpoint_public_key": {"type": "string"},
                    "private_key": {"type": "string"},
                    "witness_id": {"type": "string"},
                    "witnessed_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "verify_remote_approval_registry_history_receipt_quorum_log_checkpoint_witnesses",
            "Verify receipt-quorum checkpoint witnesses",
            "Re-verify the exact checkpoint evidence and require a fresh quorum of distinct trusted witness identities and keys.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "log", "quorum_report", "checkpoint", "checkpoint_public_key",
                    "witnesses", "minimum_witnesses", "output"
                ],
                "properties": {
                    "log": {"type": "string"},
                    "quorum_report": {"type": "string"},
                    "checkpoint": {"type": "string"},
                    "checkpoint_public_key": {"type": "string"},
                    "witnesses": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "witness_public_keys": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "witness_trust_states": {
                        "type": "array", "minItems": 1, "maxItems": 100,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "minimum_witnesses": {
                        "type": "integer", "minimum": 2, "maximum": 100
                    },
                    "evaluated_at_unix": {"type": "integer", "minimum": 0},
                    "output": {"type": "string"}
                },
                "oneOf": [
                    {
                        "required": ["witness_public_keys"],
                        "not": {"required": ["witness_trust_states"]}
                    },
                    {
                        "required": ["witness_trust_states"],
                        "not": {"required": ["witness_public_keys"]}
                    }
                ]
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "init_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_trust",
            "Initialize checkpoint witness trust",
            "Pin generation-zero trust for one receipt-quorum checkpoint witness identity and Ed25519 public key.",
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
            "sign_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation",
            "Sign checkpoint witness key rotation",
            "Require old-key authorization and new-key possession for one generation-chained witness trust transition.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": [
                    "trust_state", "old_private_key", "new_private_key", "output"
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
            "apply_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation",
            "Apply checkpoint witness key rotation",
            "Verify and atomically advance retained receipt-quorum checkpoint witness trust by exactly one generation.",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["trust_state", "rotation", "output"],
                "properties": {
                    "trust_state": {"type": "string"},
                    "rotation": {"type": "string"},
                    "output": {"type": "string"}
                }
            }),
            false,
            true,
            tasks_supported.then_some("forbidden"),
        ),
        tool(
            "export_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_public_key",
            "Export checkpoint witness public key",
            "Validate retained witness trust and export its currently trusted Ed25519 public key.",
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
    if cancellation.is_some_and(|cancelled| cancelled.load(Ordering::SeqCst)) {
        return Ok(tool_error_result(
            json!({"detail": "task execution cancelled"}),
        ));
    }
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
        "check_schematic" => check_schematic(arguments, cancellation)?,
        "check_circuit_spec" => check_circuit_spec(arguments, cancellation)?,
        "write_circuit_spec_kicad_schematic" => {
            write_circuit_spec_kicad_schematic(arguments, cancellation)?
        }
        "verify_circuit_kicad_handoff" => {
            verify_circuit_kicad_handoff(arguments, cancellation)?
        }
        "verify_circuit_kicad_board_binding" => {
            verify_circuit_kicad_board_binding(arguments, cancellation)?
        }
        "pipeline_verify" => pipeline_verify(arguments, cancellation)?,
        "run_deterministic_pipeline" => {
            run_deterministic_pipeline_tool(arguments, cancellation)?
        }
        "verify_fabrication_authorization" => {
            verify_fabrication_authorization_tool(arguments, cancellation)?
        }
        "compile_deterministic_pipeline_plan" => {
            compile_deterministic_pipeline_plan_tool(arguments, cancellation)?
        }
        "run_native_kicad_erc" => run_native_kicad_erc_tool(arguments, cancellation)?,
        "run_native_kicad_drc" => run_native_kicad_drc_tool(arguments, cancellation)?,
        "verify_native_kicad_erc_report" => {
            verify_native_kicad_erc_report_tool(arguments, cancellation)?
        }
        "verify_native_kicad_drc_report" => {
            verify_native_kicad_drc_report_tool(arguments, cancellation)?
        }
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
        "append_verified_remote_factory_release_registry_history_witness_receipt" => {
            append_verified_remote_factory_release_registry_history_witness_receipt(
                arguments,
                cancellation,
            )?
        }
        "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt" => {
            append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
                arguments,
                cancellation,
            )?
        }
        "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum" => {
            append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum(
                arguments,
                cancellation,
            )?
        }
        "append_verified_remote_factory_release_registry_history_witness_receipt_quorum" => {
            append_verified_remote_factory_release_registry_history_witness_receipt_quorum(
                arguments,
                cancellation,
            )?
        }
        "sign_quorum_bound_factory_release_receipt_transparency_log" => {
            sign_quorum_bound_factory_release_receipt_transparency_log(arguments, cancellation)?
        }
        "sign_quorum_bound_factory_checkpoint_witness_receipt_transparency_log" => {
            sign_quorum_bound_factory_checkpoint_witness_receipt_transparency_log(
                arguments,
                cancellation,
            )?
        }
        "sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint" => {
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint" => {
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint" => {
            witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses" => {
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses(
                arguments,
                cancellation,
            )?
        }
        "sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint" => {
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint" => {
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint" => {
            witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses" => {
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
                arguments,
                cancellation,
            )?
        }
        "init_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust" => {
            init_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust(
                arguments,
                cancellation,
            )?
        }
        "sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation" => {
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation" => {
            apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "export_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_public_key" => {
            export_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_public_key(
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
        "sign_remote_approval_registry_history_receipt_quorum_log_checkpoint" => {
            sign_remote_approval_registry_history_receipt_quorum_log_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "verify_remote_approval_registry_history_receipt_quorum_log_checkpoint" => {
            verify_remote_approval_registry_history_receipt_quorum_log_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "witness_remote_approval_registry_history_receipt_quorum_log_checkpoint" => {
            witness_remote_approval_registry_history_receipt_quorum_log_checkpoint(
                arguments,
                cancellation,
            )?
        }
        "verify_remote_approval_registry_history_receipt_quorum_log_checkpoint_witnesses" => {
            verify_remote_approval_registry_history_receipt_quorum_log_checkpoint_witnesses(
                arguments,
                cancellation,
            )?
        }
        "init_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_trust" => {
            init_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_trust(
                arguments,
                cancellation,
            )?
        }
        "sign_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation" => {
            sign_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "apply_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation" => {
            apply_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                arguments,
                cancellation,
            )?
        }
        "export_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_public_key" => {
            export_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_public_key(
                arguments,
                cancellation,
            )?
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
    let text = tool_result_text(name, &structured);
    Ok(json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": is_error
    }))
}

fn tool_result_text(name: &str, structured: &Value) -> String {
    if name != "verify_circuit_kicad_board_binding" {
        return serde_json::to_string_pretty(structured)
            .expect("structured tool result serializes");
    }

    // This report can legitimately be several MiB. Repeating it as escaped
    // human-readable text would more than double the JSON-RPC frame and could
    // make a valid structured result exceed the 16 MiB transport ceiling.
    let command_ok = structured.get("ok").and_then(Value::as_bool) == Some(true);
    let approved = structured
        .pointer("/report/approved")
        .and_then(Value::as_bool);
    let status = match (command_ok, approved) {
        (true, Some(true)) => "approved",
        (_, Some(false)) => "rejected",
        _ => "failed",
    };
    let output = structured
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    format!(
        "Circuit-to-KiCad board binding {status}; retained report: {output}; command_ok={command_ok}"
    )
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
            "physical_profile",
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
    optional_option(
        &arguments,
        "physical_profile",
        "--physical-profile",
        &mut command,
    )?;
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

fn check_schematic(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "output",
            "explain",
            "junit_output",
            "sarif_output",
            "policy",
            "policy_pack",
            "require_approved",
        ],
    )?;
    let input = required_string(&arguments, "input")?;
    let output = required_string(&arguments, "output")?;
    if arguments.contains_key("policy") && arguments.contains_key("policy_pack") {
        return Err(json!({
            "detail": "policy and policy_pack cannot be used together"
        }));
    }
    let explain = optional_string(&arguments, "explain")?;
    let junit_output = optional_string(&arguments, "junit_output")?;
    let sarif_output = optional_string(&arguments, "sarif_output")?;
    require_absent_outputs([
        Some(output.as_str()),
        explain.as_deref(),
        junit_output.as_deref(),
        sarif_output.as_deref(),
    ])?;
    let mut command = vec![
        "check-schematic".into(),
        input,
        "--output".into(),
        output.clone(),
    ];
    optional_option(&arguments, "explain", "--explain", &mut command)?;
    optional_option(&arguments, "junit_output", "--junit-output", &mut command)?;
    optional_option(&arguments, "sarif_output", "--sarif-output", &mut command)?;
    optional_option(&arguments, "policy", "--policy", &mut command)?;
    optional_option(&arguments, "policy_pack", "--policy-pack", &mut command)?;
    optional_flag(
        &arguments,
        "require_approved",
        "--require-approved",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let review = read_json_if_present(Path::new(&output));
    let execution = require_retained_json(execution, &review, "check-schematic output");
    let explanation = explain
        .as_deref()
        .map(|path| read_json_if_present(Path::new(path)));
    let execution = if let Some(explanation) = explanation.as_ref() {
        require_retained_json(execution, explanation, "check-schematic explanation")
    } else {
        execution
    };
    let execution = if let Some(path) = junit_output.as_deref() {
        require_retained_file(execution, Path::new(path), "check-schematic JUnit output")
    } else {
        execution
    };
    let sarif = sarif_output
        .as_deref()
        .map(|path| read_json_if_present(Path::new(path)));
    let execution = if let Some(sarif) = sarif.as_ref() {
        require_retained_json(execution, sarif, "check-schematic SARIF output")
    } else {
        execution
    };
    Ok(execution_result(
        execution,
        json!({
            "output": output,
            "review": review,
            "explain": explain,
            "explanation": explanation,
            "junit_output": junit_output,
            "sarif_output": sarif_output,
            "sarif": sarif
        }),
    ))
}

fn check_circuit_spec(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["input", "output", "require_approved"])?;
    let input = required_string(&arguments, "input")?;
    let output = required_string(&arguments, "output")?;
    require_absent_outputs([Some(output.as_str())])?;
    let command = vec![
        "check-circuit-spec".into(),
        input,
        "--output".into(),
        output.clone(),
    ];
    let mut command = command;
    optional_flag(
        &arguments,
        "require_approved",
        "--require-approved",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let check = read_json_if_present(Path::new(&output));
    let execution = require_retained_json(execution, &check, "check-circuit-spec output");
    Ok(execution_result(
        execution,
        json!({"output": output, "check": check}),
    ))
}

fn write_circuit_spec_kicad_schematic(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["input", "output"])?;
    let input = required_string(&arguments, "input")?;
    let output = required_string(&arguments, "output")?;
    // The CLI bridge performs the authoritative symlink/alias checks.  This
    // preflight prevents a stale artifact from being mistaken for a result
    // when the child rejects or is cancelled before publishing its output.
    require_absent_outputs([Some(output.as_str())])?;
    let command = vec![
        "write-circuit-spec-kicad-schematic".into(),
        input.clone(),
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let (execution, schematic) =
        require_retained_circuit_kicad_schematic(execution, Path::new(&output));
    Ok(execution_result(
        execution,
        json!({
            "input": input,
            "output": output,
            "schematic": schematic
        }),
    ))
}

fn verify_circuit_kicad_handoff(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "circuit_spec",
            "schematic",
            "policy",
            "output",
            "require_approved",
        ],
    )?;
    let circuit_spec = required_string(&arguments, "circuit_spec")?;
    let schematic = required_string(&arguments, "schematic")?;
    optional_string(&arguments, "policy")?;
    let output = required_string(&arguments, "output")?;
    require_absent_outputs([Some(output.as_str())])?;
    let mut command = vec![
        "verify-circuit-kicad-handoff".into(),
        circuit_spec,
        schematic,
        "--output".into(),
        output.clone(),
        "--mcp-echo-report".into(),
    ];
    optional_option(&arguments, "policy", "--policy", &mut command)?;
    optional_flag(
        &arguments,
        "require_approved",
        "--require-approved",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    // Trust a retained handoff report only when the child itself echoed the
    // exact JSON after its atomic no-clobber publish and the retained file
    // still matches.  This prevents a concurrent creator from injecting a
    // stale report into a failed MCP call between preflight and readback.
    let report = trusted_echoed_json(&execution, Path::new(&output));
    let execution = require_retained_json(execution, &report, "handoff output");
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn verify_circuit_kicad_board_binding(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "circuit_spec",
            "schematic",
            "board",
            "policy",
            "output",
            "require_approved",
        ],
    )?;
    let circuit_spec = required_string(&arguments, "circuit_spec")?;
    let schematic = required_string(&arguments, "schematic")?;
    let board = required_string(&arguments, "board")?;
    optional_string(&arguments, "policy")?;
    let output = required_string(&arguments, "output")?;
    require_absent_outputs([Some(output.as_str())])?;
    let mut command = vec![
        "verify-circuit-kicad-board-binding".into(),
        circuit_spec,
        schematic,
        board,
        "--output".into(),
        output.clone(),
        "--mcp-echo-report".into(),
    ];
    optional_option(&arguments, "policy", "--policy", &mut command)?;
    optional_flag(
        &arguments,
        "require_approved",
        "--require-approved",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    // Trust a retained board-binding report only when the child echoed the
    // exact JSON after atomic no-clobber publish and the retained file still
    // matches. This protects failed/rejected calls from stale or concurrent
    // output injection between execution and readback.
    let report = trusted_echoed_json(&execution, Path::new(&output));
    let execution = require_retained_json(execution, &report, "board binding output");
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn pipeline_verify(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "schematic",
            "electrical_policy",
            "electrical_review",
            "board",
            "analysis_manifest",
            "analysis_checks",
            "quality",
            "analysis_project",
            "analysis_rules",
            "analysis_dfm_profile",
            "analysis_policy_pack",
            "analysis_physical_profile",
            "manufacturing_package",
            "firmware_manifest",
            "factory_receipt",
            "require_factory",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    require_absent_outputs([Some(output.as_str())])?;
    let mut command = vec!["pipeline-verify".into()];
    for (name, option) in [
        ("schematic", "--schematic"),
        ("electrical_review", "--electrical-review"),
        ("board", "--board"),
        ("analysis_manifest", "--analysis-manifest"),
        ("analysis_checks", "--analysis-checks"),
        ("quality", "--quality"),
        ("manufacturing_package", "--manufacturing-package"),
        ("firmware_manifest", "--firmware-manifest"),
    ] {
        command.extend([option.into(), required_string(&arguments, name)?]);
    }
    for (name, option) in [
        ("electrical_policy", "--electrical-policy"),
        ("analysis_project", "--analysis-project"),
        ("analysis_rules", "--analysis-rules"),
        ("analysis_dfm_profile", "--analysis-dfm-profile"),
        ("analysis_policy_pack", "--analysis-policy-pack"),
        ("analysis_physical_profile", "--analysis-physical-profile"),
        ("factory_receipt", "--factory-receipt"),
    ] {
        optional_option(&arguments, name, option, &mut command)?;
    }
    optional_flag(
        &arguments,
        "require_factory",
        "--require-factory",
        &mut command,
    )?;
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    let execution = require_retained_json(execution, &report, "pipeline-verify output");
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn run_deterministic_pipeline_tool(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["plan", "output", "require_approved"])?;
    let plan = required_string(&arguments, "plan")?;
    let output = required_string(&arguments, "output")?;
    // Refuse stale evidence before starting the child.  The runner performs
    // the stronger path-component, alias, and atomic-publish checks after it
    // has parsed the closed plan.
    require_absent_outputs([Some(output.as_str())])?;
    let mut command = vec![
        "run-deterministic-pipeline".to_string(),
        plan.clone(),
        "--output".to_string(),
        output.clone(),
        // The child emits a compact digest-bound summary on stdout when this
        // hidden MCP-only switch is present.  Comparing that summary with a
        // stable read of the retained file prevents a concurrent writer from
        // replacing evidence while keeping the MCP frame below 16 MiB even
        // when the CLI report is near its 128 MiB bound.
        "--mcp-echo-report-summary".to_string(),
    ];
    optional_flag(
        &arguments,
        "require_approved",
        "--require-approved",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let report_summary = trusted_deterministic_pipeline_summary(&execution, Path::new(&output));
    let execution = require_retained_json(
        execution,
        &report_summary,
        "deterministic pipeline output summary",
    );
    Ok(execution_result(
        execution,
        json!({"plan": plan, "output": output, "report_summary": report_summary}),
    ))
}

fn verify_fabrication_authorization_tool(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "plan",
            "retained_report",
            "manufacturing_package",
            "factory_receipt",
            "policy_pack",
            "approvals",
            "output",
            "require_authorized",
        ],
    )?;
    let plan = required_fabrication_path(&arguments, "plan")?;
    let retained_report = required_fabrication_path(&arguments, "retained_report")?;
    let manufacturing_package = required_fabrication_path(&arguments, "manufacturing_package")?;
    let factory_receipt = required_fabrication_path(&arguments, "factory_receipt")?;
    let policy_pack = required_fabrication_path(&arguments, "policy_pack")?;
    let approvals = required_string_array(&arguments, "approvals", false)?;
    if approvals.len() > 100 {
        return Err(json!({"detail": "approvals must contain 1 to 100 entries"}));
    }
    for approval in &approvals {
        validate_fabrication_path(approval, "approvals entries")?;
    }
    let output = required_fabrication_path(&arguments, "output")?;

    // Use attached option values and terminate option parsing before the
    // positional plan so literal paths beginning with '-' cannot be treated
    // as CLI switches.
    let mut command = vec![
        "verify-fabrication-authorization".to_string(),
        format!("--report={retained_report}"),
        format!("--manufacturing-package={manufacturing_package}"),
        format!("--factory-receipt={factory_receipt}"),
        format!("--policy-pack={policy_pack}"),
    ];
    command.extend(
        approvals
            .iter()
            .map(|approval| format!("--approval={approval}")),
    );
    command.extend([
        format!("--output={output}"),
        // The child emits this compact summary after atomically retaining the
        // full report and before applying the optional authorization gate.
        "--mcp-echo-report-summary".to_string(),
    ]);
    optional_flag(
        &arguments,
        "require_authorized",
        "--require-authorized",
        &mut command,
    )?;
    command.extend(["--".to_string(), plan]);

    // Never let a report from an earlier call masquerade as current evidence.
    require_absent_outputs([Some(output.as_str())])?;
    let execution = execute(&command, cancellation)?;
    authenticated_fabrication_authorization_result(execution, output, cancellation)
}

fn authenticated_fabrication_authorization_result(
    execution: Execution,
    output: String,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    ensure_task_not_cancelled(cancellation)?;
    let report_summary =
        trusted_fabrication_authorization_summary(&execution, Path::new(&output), cancellation);
    #[cfg(test)]
    invoke_after_fabrication_summary_hook();
    ensure_task_not_cancelled(cancellation)?;
    let execution = require_retained_json(
        execution,
        &report_summary,
        "fabrication authorization report summary",
    );
    Ok(execution_result(
        execution,
        json!({"output": output, "report_summary": report_summary}),
    ))
}

fn compile_deterministic_pipeline_plan_tool(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["intent", "output"])?;
    let intent = required_string(&arguments, "intent")?;
    let output = required_string(&arguments, "output")?;
    // Refuse stale evidence before starting the child.  The compiler performs
    // the stronger output-parent, symlink, alias, and no-clobber checks after
    // it has parsed the closed intent and stable-read every source.
    require_absent_outputs([Some(output.as_str())])?;
    let command = vec![
        "compile-deterministic-pipeline-plan".to_string(),
        intent.clone(),
        "--output".to_string(),
        output.clone(),
        // The child emits only a compact, strict metadata summary.  MCP
        // authenticates that echo against stable reads of both the intent and
        // the atomically retained plan, without embedding plan contents.
        "--mcp-echo-plan-summary".to_string(),
    ];
    let execution = execute(&command, cancellation)?;
    let summary = trusted_deterministic_pipeline_plan_summary(
        &execution,
        Path::new(&intent),
        Path::new(&output),
    );
    let execution = require_retained_json(execution, &summary, "deterministic pipeline plan");
    let schema_version = summary
        .as_object()
        .map(|summary| summary["schema_version"].clone())
        .unwrap_or(Value::Null);
    let intent_metadata = summary
        .as_object()
        .map(|summary| {
            json!({
                "path": intent.clone(),
                "bytes": summary["intent_source_bytes"],
                "sha256": summary["intent_source_sha256"]
            })
        })
        .unwrap_or(Value::Null);
    let plan_metadata = summary
        .as_object()
        .map(|summary| {
            json!({
                "path": output.clone(),
                "bytes": summary["plan_source_bytes"],
                "sha256": summary["plan_source_sha256"]
            })
        })
        .unwrap_or(Value::Null);
    Ok(execution_result(
        execution,
        json!({
            "schema_version": schema_version,
            "intent": intent_metadata,
            "plan": plan_metadata
        }),
    ))
}

fn run_native_kicad_erc_tool(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "output",
            "kicad_cli",
            "warning_policy",
            "require_approved",
        ],
    )?;
    let input = required_string(&arguments, "input")?;
    let output = required_string(&arguments, "output")?;
    // Refuse stale evidence before starting native KiCad so a rejected or
    // cancelled native run can never be mistaken for a fresh report.
    require_absent_outputs([Some(output.as_str())])?;
    let kicad_cli = optional_string(&arguments, "kicad_cli")?;
    let warning_policy = optional_string(&arguments, "warning_policy")?;
    let require_approved = optional_bool(&arguments, "require_approved")?;
    let output_path = Path::new(&output);
    let input_path = Path::new(&input);
    let policy_path = warning_policy.as_deref().map(Path::new);
    let authorized_inputs =
        policy_path.map_or_else(|| vec![input_path], |policy| vec![input_path, policy]);
    let prepared = match crate::prepare_pipeline_output(output_path, &authorized_inputs) {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(native_kicad_execution_failure(
                error,
                json!({"output": output, "report_summary": Value::Null}),
            ));
        }
    };
    let kicad_cli = std::ffi::OsStr::new(kicad_cli.as_deref().unwrap_or("kicad-cli"));
    let (report_summary, approved, error_count, warning_count, policy_failure_count) =
        if let Some(policy) = policy_path {
            let report = match crate::native_kicad_erc::run_native_kicad_erc_with_warning_policy(
                input_path,
                policy,
                kicad_cli,
                cancellation,
            ) {
                Ok(report) => report,
                Err(error) => {
                    ensure_task_not_cancelled(cancellation)?;
                    return Ok(native_kicad_execution_failure(
                        error,
                        json!({"output": output, "report_summary": Value::Null}),
                    ));
                }
            };
            ensure_task_not_cancelled(cancellation)?;
            let rendered =
                match crate::native_kicad_erc::render_native_kicad_erc_warning_report(&report) {
                    Ok(rendered) => rendered,
                    Err(error) => {
                        return Ok(native_kicad_execution_failure(
                            error,
                            json!({"output": output, "report_summary": Value::Null}),
                        ));
                    }
                };
            ensure_task_not_cancelled(cancellation)?;
            if let Err(error) =
                crate::persist_atomic_new_file_bytes(prepared, output_path, &rendered)
            {
                return Ok(native_kicad_execution_failure(
                    error,
                    json!({"output": output, "report_summary": Value::Null}),
                ));
            }
            let summary = json!({
                "schema_version": report.schema_version,
                "approved": report.approved,
                "error_count": report.error_count,
                "warning_count": report.warning_count,
                "policy_failure_count": report.policy_failures.len(),
                "warning_policy_sha256": report.warning_policy.policy_sha256,
                "warning_policy_source_bytes": report.warning_policy.source.bytes,
                "warning_policy_source_sha256": report.warning_policy.source.sha256,
                "run_sha256": report.run_sha256,
                "report_bytes": rendered.len(),
                "report_sha256": hex::encode(Sha256::digest(&rendered)),
            });
            (
                summary,
                report.approved,
                report.error_count,
                report.warning_count,
                report.policy_failures.len(),
            )
        } else {
            let report = match crate::native_kicad_erc::run_native_kicad_erc(
                input_path,
                kicad_cli,
                cancellation,
            ) {
                Ok(report) => report,
                Err(error) => {
                    ensure_task_not_cancelled(cancellation)?;
                    return Ok(native_kicad_execution_failure(
                        error,
                        json!({"output": output, "report_summary": Value::Null}),
                    ));
                }
            };
            ensure_task_not_cancelled(cancellation)?;
            let rendered = match crate::native_kicad_erc::render_native_kicad_erc_report(&report) {
                Ok(rendered) => rendered,
                Err(error) => {
                    return Ok(native_kicad_execution_failure(
                        error,
                        json!({"output": output, "report_summary": Value::Null}),
                    ));
                }
            };
            ensure_task_not_cancelled(cancellation)?;
            if let Err(error) =
                crate::persist_atomic_new_file_bytes(prepared, output_path, &rendered)
            {
                return Ok(native_kicad_execution_failure(
                    error,
                    json!({"output": output, "report_summary": Value::Null}),
                ));
            }
            let summary = json!({
                "schema_version": report.schema_version,
                "approved": report.approved,
                "error_count": report.error_count,
                "run_sha256": report.run_sha256,
                "report_bytes": rendered.len(),
                "report_sha256": hex::encode(Sha256::digest(&rendered)),
            });
            (summary, report.approved, report.error_count, 0, 0)
        };
    let mut stdout =
        serde_json::to_vec(&report_summary).expect("native KiCad ERC summary always serializes");
    stdout.push(b'\n');
    let success = !require_approved || approved;
    let mut stderr = if warning_policy.is_some() {
        format!(
            "native KiCad ERC warning policy: {}; {} error(s), {} warning(s), {} policy failure(s); report={}",
            if approved { "approved" } else { "rejected" },
            error_count,
            warning_count,
            policy_failure_count,
            output_path.display()
        )
    } else {
        format!(
            "native KiCad ERC: {}; {} error(s); report={}",
            if approved { "approved" } else { "rejected" },
            error_count,
            output_path.display()
        )
    };
    if require_approved && !approved {
        stderr.push_str(if warning_policy.is_some() {
            "\nError: native KiCad schematic ERC warning policy rejected"
        } else {
            "\nError: native KiCad schematic ERC rejected"
        });
    }
    let execution = Execution {
        success,
        exit_code: Some(if success { 0 } else { 1 }),
        stdout,
        stderr: bounded_process_message(stderr.as_bytes()),
    };
    let report_summary = trusted_native_kicad_erc_summary(&execution, Path::new(&output));
    let execution = require_retained_json(
        execution,
        &report_summary,
        "native KiCad ERC output summary",
    );
    Ok(execution_result(
        execution,
        json!({"output": output, "report_summary": report_summary}),
    ))
}

fn run_native_kicad_drc_tool(
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
            "kicad_cli",
            "require_approved",
        ],
    )?;
    let input = required_string(&arguments, "input")?;
    let output = required_string(&arguments, "output")?;
    // Refuse stale evidence before starting native KiCad so a rejected or
    // cancelled native run can never be mistaken for a fresh report.
    require_absent_outputs([Some(output.as_str())])?;
    let project = optional_string(&arguments, "project")?;
    let rules_file = optional_string(&arguments, "rules_file")?;
    let kicad_cli = optional_string(&arguments, "kicad_cli")?;
    let require_approved = optional_bool(&arguments, "require_approved")?;
    let input_path = Path::new(&input);
    let output_path = Path::new(&output);
    let project_path = project.as_deref().map(Path::new);
    let rules_path = rules_file.as_deref().map(Path::new);
    let kicad_cli = std::ffi::OsStr::new(kicad_cli.as_deref().unwrap_or("kicad-cli"));
    let auto_project = input_path.with_extension("kicad_pro");
    let auto_rules = input_path.with_extension("kicad_dru");
    let mut authorized_inputs = vec![input_path, auto_project.as_path(), auto_rules.as_path()];
    if let Some(project) = project_path {
        authorized_inputs.push(project);
    }
    if let Some(rules_file) = rules_path {
        authorized_inputs.push(rules_file);
    }
    let prepared = match crate::prepare_pipeline_output(output_path, &authorized_inputs) {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(native_kicad_execution_failure(
                error,
                json!({"input": input, "output": output, "report_summary": Value::Null}),
            ));
        }
    };
    let report = match crate::native_kicad_drc::run_native_kicad_drc(
        input_path,
        project_path,
        rules_path,
        kicad_cli,
        cancellation,
    ) {
        Ok(report) => report,
        Err(error) => {
            ensure_task_not_cancelled(cancellation)?;
            return Ok(native_kicad_execution_failure(
                error,
                json!({"input": input, "output": output, "report_summary": Value::Null}),
            ));
        }
    };
    ensure_task_not_cancelled(cancellation)?;
    let rendered = match crate::native_kicad_drc::render_native_kicad_drc_report(&report) {
        Ok(rendered) => rendered,
        Err(error) => {
            return Ok(native_kicad_execution_failure(
                error,
                json!({"input": input, "output": output, "report_summary": Value::Null}),
            ));
        }
    };
    ensure_task_not_cancelled(cancellation)?;
    if let Err(error) = crate::persist_atomic_new_file_bytes(prepared, output_path, &rendered) {
        return Ok(native_kicad_execution_failure(
            error,
            json!({"input": input, "output": output, "report_summary": Value::Null}),
        ));
    }
    let summary = crate::native_kicad_drc::native_kicad_drc_report_summary(&report, &rendered);
    let mut stdout =
        serde_json::to_vec(&summary).expect("native KiCad DRC summary always serializes");
    stdout.push(b'\n');
    let success = !require_approved || report.approved;
    let mut stderr = format!(
        "native KiCad DRC: {}; {} finding(s) ({} violation(s), {} unconnected item(s)), {} error(s), {} warning(s); report={}",
        if report.approved {
            "approved"
        } else {
            "rejected"
        },
        report.findings.len(),
        report.violation_count,
        report.unconnected_item_count,
        report.error_count,
        report.warning_count,
        output_path.display()
    );
    if require_approved && !report.approved {
        stderr.push_str("\nError: native KiCad PCB DRC rejected");
    }
    let execution = Execution {
        success,
        exit_code: Some(if success { 0 } else { 1 }),
        stdout,
        stderr: bounded_process_message(stderr.as_bytes()),
    };
    let report_summary = trusted_native_kicad_drc_summary(
        &execution,
        output_path,
        input_path,
        project_path,
        rules_path,
    );
    let execution = require_retained_json(
        execution,
        &report_summary,
        "native KiCad DRC output summary",
    );
    Ok(execution_result(
        execution,
        json!({"input": input, "output": output, "report_summary": report_summary}),
    ))
}

fn optional_bool(arguments: &Map<String, Value>, name: &str) -> std::result::Result<bool, Value> {
    match arguments.get(name) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(json!({"detail": format!("{name} must be a boolean")})),
    }
}

fn native_kicad_execution_failure(error: anyhow::Error, fields: Value) -> Value {
    execution_result(
        Execution {
            success: false,
            exit_code: Some(1),
            stdout: Vec::new(),
            stderr: bounded_process_message(format!("Error: {error:#}").as_bytes()),
        },
        fields,
    )
}

fn ensure_task_not_cancelled(cancellation: Option<&AtomicBool>) -> std::result::Result<(), Value> {
    if task_is_cancelled(cancellation) {
        Err(json!({"detail": "task execution cancelled"}))
    } else {
        Ok(())
    }
}

fn task_is_cancelled(cancellation: Option<&AtomicBool>) -> bool {
    cancellation.is_some_and(|cancelled| cancelled.load(Ordering::SeqCst))
}

fn verify_native_kicad_erc_report_tool(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "retained_report",
            "warning_policy",
            "kicad_cli",
            "require_approved",
        ],
    )?;
    let input = required_string(&arguments, "input")?;
    let retained_report = required_string(&arguments, "retained_report")?;
    let warning_policy = optional_string(&arguments, "warning_policy")?;
    let kicad_cli = optional_string(&arguments, "kicad_cli")?;
    let require_approved = optional_bool(&arguments, "require_approved")?;
    let input_path = Path::new(&input);
    let retained_report_path = Path::new(&retained_report);
    let kicad_cli = std::ffi::OsStr::new(kicad_cli.as_deref().unwrap_or("kicad-cli"));

    // Replay is intentionally performed in this worker rather than by
    // spawning another pcbex bridge.  The native replay API receives the MCP
    // cancellation token directly, so cancelling a Task terminates KiCad's
    // process group and cannot leave a nested child behind.
    let replay = if let Some(warning_policy) = warning_policy.as_deref() {
        crate::native_kicad_erc::replay_native_kicad_erc_report_with_warning_policy(
            input_path,
            retained_report_path,
            Path::new(warning_policy),
            kicad_cli,
            cancellation,
        )
        .map(|report| {
            let rendered =
                crate::native_kicad_erc::render_native_kicad_erc_warning_report(&report)?;
            let summary = crate::native_kicad_erc::native_kicad_erc_warning_report_summary(
                &report, &rendered,
            );
            Ok::<_, anyhow::Error>((summary, report.approved))
        })
    } else {
        crate::native_kicad_erc::replay_native_kicad_erc_report(
            input_path,
            retained_report_path,
            kicad_cli,
            cancellation,
        )
        .map(|report| {
            let rendered = crate::native_kicad_erc::render_native_kicad_erc_report(&report)?;
            let summary =
                crate::native_kicad_erc::native_kicad_erc_report_summary(&report, &rendered);
            Ok::<_, anyhow::Error>((summary, report.approved))
        })
    };

    let (execution, report_summary) = match replay {
        Ok(Ok((summary, approved))) => {
            ensure_task_not_cancelled(cancellation)?;
            let mut stdout = serde_json::to_vec(&summary)
                .expect("native KiCad ERC replay summary always serializes");
            stdout.push(b'\n');
            let success = !require_approved || approved;
            let mut stderr = if warning_policy.is_some() {
                format!(
                    "native KiCad ERC replay with warning policy: {}; report={}",
                    if approved { "approved" } else { "rejected" },
                    retained_report_path.display()
                )
            } else {
                format!(
                    "native KiCad ERC replay: {}; report={}",
                    if approved { "approved" } else { "rejected" },
                    retained_report_path.display()
                )
            };
            if require_approved && !approved {
                stderr.push_str(if warning_policy.is_some() {
                    "\nError: native KiCad ERC warning policy rejected"
                } else {
                    "\nError: native KiCad ERC rejected"
                });
            }
            let execution = Execution {
                success,
                exit_code: Some(if success { 0 } else { 1 }),
                stdout,
                stderr: bounded_process_message(stderr.as_bytes()),
            };
            ensure_task_not_cancelled(cancellation)?;
            let report_summary = trusted_native_kicad_erc_summary(&execution, retained_report_path);
            let execution = require_retained_json(
                execution,
                &report_summary,
                "native KiCad ERC verification report summary",
            );
            (execution, report_summary)
        }
        Ok(Err(error)) | Err(error) => {
            ensure_task_not_cancelled(cancellation)?;
            (
                Execution {
                    success: false,
                    exit_code: Some(1),
                    stdout: Vec::new(),
                    stderr: bounded_process_message(error.to_string().as_bytes()),
                },
                Value::Null,
            )
        }
    };

    Ok(execution_result(
        execution,
        json!({
            "input": input,
            "retained_report": retained_report,
            "report_summary": report_summary
        }),
    ))
}

fn verify_native_kicad_drc_report_tool(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "input",
            "report",
            "project",
            "rules_file",
            "kicad_cli",
            "require_approved",
        ],
    )?;
    let input = required_string(&arguments, "input")?;
    let report = required_string(&arguments, "report")?;
    let project = optional_string(&arguments, "project")?;
    let rules_file = optional_string(&arguments, "rules_file")?;
    let kicad_cli = optional_string(&arguments, "kicad_cli")?;
    let require_approved = match arguments.get("require_approved") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(json!({"detail": "require_approved must be a boolean"})),
    };

    // Run replay in the MCP worker itself so the task cancellation token is
    // passed directly to the bounded KiCad child.  Spawning another pcbex
    // bridge here would put KiCad in a nested Unix process group, allowing it
    // to outlive cancellation of the outer bridge process.
    let verified = crate::native_kicad_drc::verify_native_kicad_drc_report(
        Path::new(&input),
        Path::new(&report),
        project.as_deref().map(Path::new),
        rules_file.as_deref().map(Path::new),
        std::ffi::OsStr::new(kicad_cli.as_deref().unwrap_or("kicad-cli")),
        cancellation,
    );
    let (execution, report_summary) = match verified {
        Ok(verified) => {
            let rendered = crate::native_kicad_drc::render_native_kicad_drc_report(&verified)
                .expect("a verified native KiCad DRC report remains renderable");
            let summary =
                crate::native_kicad_drc::native_kicad_drc_report_summary(&verified, &rendered);
            let mut stdout =
                serde_json::to_vec(&summary).expect("native KiCad DRC summary always serializes");
            stdout.push(b'\n');
            let success = !require_approved || verified.approved;
            let execution = Execution {
                success,
                exit_code: Some(if success { 0 } else { 1 }),
                stdout,
                stderr: if success {
                    String::new()
                } else {
                    "native KiCad PCB DRC rejected".to_string()
                },
            };
            // Re-authenticate the retained bytes and current source identities
            // after replay before exposing the compact summary.
            let report_summary = trusted_native_kicad_drc_summary(
                &execution,
                Path::new(&report),
                Path::new(&input),
                project.as_deref().map(Path::new),
                rules_file.as_deref().map(Path::new),
            );
            let execution = require_retained_json(
                execution,
                &report_summary,
                "native KiCad DRC verification report summary",
            );
            (execution, report_summary)
        }
        Err(error) => {
            let message = error.to_string();
            (
                Execution {
                    success: false,
                    exit_code: Some(1),
                    stdout: Vec::new(),
                    stderr: bounded_process_message(message.as_bytes()),
                },
                Value::Null,
            )
        }
    };
    Ok(execution_result(
        execution,
        json!({
            "input": input,
            "report": report,
            "report_summary": report_summary
        }),
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
            "physical_profile",
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
    optional_option(
        &arguments,
        "physical_profile",
        "--physical-profile",
        &mut command,
    )?;
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
            "deterministic_pipeline_plan",
            "deterministic_pipeline_report",
            "native_kicad_erc_report",
            "native_kicad_erc_warning_policy",
            "kicad_cli",
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
    let session_output = arguments
        .get("session_output")
        .and_then(Value::as_str)
        .map(str::to_string);
    // Treat request/session artifacts as no-clobber at the MCP boundary.  Do
    // this check before dispatch so a failed or cancelled invocation cannot
    // cause MCP to echo a pre-existing stale request as fresh evidence.
    require_absent_outputs([Some(output.as_str()), session_output.as_deref()])?;
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
    append_native_ai_review_options(
        &arguments,
        &[
            (
                "deterministic_pipeline_plan",
                "--deterministic-pipeline-plan",
            ),
            (
                "deterministic_pipeline_report",
                "--deterministic-pipeline-report",
            ),
        ],
        "deterministic_pipeline_plan and deterministic_pipeline_report",
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
    // Do not expose any retained artifact after a failed child process.  A
    // successful child must still leave valid JSON at every requested output
    // path; otherwise the MCP result fails closed instead of returning null
    // or an unrelated file.
    let request = if execution.success {
        read_json_if_present(Path::new(&output))
    } else {
        Value::Null
    };
    let mut execution = require_retained_json(execution, &request, "prepare-ai-review output");
    let session = if execution.success {
        session_output
            .as_deref()
            .map(|path| read_json_if_present(Path::new(path)))
    } else {
        None
    };
    if let Some(session) = session.as_ref() {
        execution = require_retained_json(execution, session, "prepare-ai-review session output");
    }
    let (request, session) = if execution.success {
        (request, session)
    } else {
        (Value::Null, None)
    };
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
            "schematic",
            "generated_schematic",
            "deterministic_pipeline_plan",
            "deterministic_pipeline_report",
            "native_kicad_erc_report",
            "native_kicad_erc_warning_policy",
            "kicad_cli",
            "output",
            "require_approved",
        ],
    )?;
    let request = required_string(&arguments, "request")?;
    let response = required_string(&arguments, "response")?;
    let private_key = required_string(&arguments, "private_key")?;
    let signer_id = required_string(&arguments, "signer_id")?;
    let output = required_string(&arguments, "output")?;
    require_absent_outputs([Some(output.as_str())])?;
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
    append_live_schematic_option(&arguments, &mut command)?;
    append_native_ai_review_options(
        &arguments,
        &[
            ("generated_schematic", "--generated-schematic"),
            (
                "deterministic_pipeline_plan",
                "--deterministic-pipeline-plan",
            ),
            (
                "deterministic_pipeline_report",
                "--deterministic-pipeline-report",
            ),
        ],
        "generated_schematic, deterministic_pipeline_plan, and deterministic_pipeline_report",
        &mut command,
    )?;
    optional_flag(
        &arguments,
        "require_approved",
        "--require-approved",
        &mut command,
    )?;
    let execution = execute(&command, cancellation)?;
    let approval = if execution.success {
        read_json_if_present(Path::new(&output))
    } else {
        Value::Null
    };
    let execution = require_retained_json(execution, &approval, "sign-ai-review output");
    let approval = if execution.success {
        approval
    } else {
        Value::Null
    };
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
            "schematic",
            "generated_schematic",
            "deterministic_pipeline_plan",
            "deterministic_pipeline_report",
            "native_kicad_erc_report",
            "native_kicad_erc_warning_policy",
            "kicad_cli",
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
    append_live_schematic_option(&arguments, &mut command)?;
    append_native_ai_review_options(
        &arguments,
        &[
            ("generated_schematic", "--generated-schematic"),
            (
                "deterministic_pipeline_plan",
                "--deterministic-pipeline-plan",
            ),
            (
                "deterministic_pipeline_report",
                "--deterministic-pipeline-report",
            ),
        ],
        "generated_schematic, deterministic_pipeline_plan, and deterministic_pipeline_report",
        &mut command,
    )?;
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
            "schematic",
            "generated_schematic",
            "deterministic_pipeline_plan",
            "deterministic_pipeline_report",
            "native_kicad_erc_report",
            "native_kicad_erc_warning_policy",
            "kicad_cli",
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
    let summary_output = arguments
        .get("summary_output")
        .and_then(Value::as_str)
        .map(str::to_string);
    require_absent_outputs([Some(output.as_str()), summary_output.as_deref()])?;
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
    append_live_schematic_option(&arguments, &mut command)?;
    append_native_ai_review_options(
        &arguments,
        &[
            ("generated_schematic", "--generated-schematic"),
            (
                "deterministic_pipeline_plan",
                "--deterministic-pipeline-plan",
            ),
            (
                "deterministic_pipeline_report",
                "--deterministic-pipeline-report",
            ),
        ],
        "generated_schematic, deterministic_pipeline_plan, and deterministic_pipeline_report",
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
    let report = if execution.success {
        read_json_if_present(Path::new(&output))
    } else {
        Value::Null
    };
    let execution = require_retained_json(execution, &report, "verify-ai-quorum output");
    // The CLI writes the optional Markdown summary in every successful
    // quorum branch before returning.  Confirm that contract at the MCP
    // boundary so a successful process cannot produce an incomplete result
    // when the requested summary was missing or replaced.
    let execution = if let Some(path) = summary_output.as_deref() {
        require_retained_file(
            execution,
            Path::new(path),
            "verify-ai-quorum summary output",
        )
    } else {
        execution
    };
    let report = if execution.success {
        report
    } else {
        Value::Null
    };
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

fn append_verified_remote_factory_release_registry_history_witness_receipt(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "receipt",
            "history",
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
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt".into(),
        required_string(&arguments, "log")?,
        "--receipt".into(),
        required_string(&arguments, "receipt")?,
        "--history".into(),
        required_string(&arguments, "history")?,
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

fn append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "receipt",
            "quorum_report",
            "approval_log",
            "checkpoint",
            "checkpoint_public_key",
            "response",
            "witness_public_key",
            "witness_trust_state",
            "evaluated_at_unix",
            "recorded_at_unix",
            "output",
        ],
    )?;
    let witness_public_key = optional_string(&arguments, "witness_public_key")?;
    let witness_trust_state = optional_string(&arguments, "witness_trust_state")?;
    if witness_public_key.is_some() == witness_trust_state.is_some() {
        return Err(json!({
            "detail": "exactly one of witness_public_key or witness_trust_state is required"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "append-verified-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt"
            .into(),
        required_string(&arguments, "log")?,
        "--receipt".into(),
        required_string(&arguments, "receipt")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--approval-log".into(),
        required_string(&arguments, "approval_log")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--checkpoint-public-key".into(),
        required_string(&arguments, "checkpoint_public_key")?,
        "--response".into(),
        required_string(&arguments, "response")?,
    ];
    if let Some(path) = witness_public_key {
        command.extend(["--witness-public-key".into(), path]);
    }
    if let Some(path) = witness_trust_state {
        command.extend(["--witness-trust-state".into(), path]);
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

fn append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "receipts",
            "quorum_report",
            "approval_log",
            "checkpoint",
            "checkpoint_public_key",
            "responses",
            "trusted_witness_ids",
            "trusted_witness_public_keys",
            "witness_trust_states",
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
    let trust_states = required_string_array(&arguments, "witness_trust_states", true)?;
    let direct_mode = !trusted_ids.is_empty() || !trusted_keys.is_empty();
    if receipts.len() != responses.len()
        || (direct_mode && receipts.len() != trusted_ids.len())
        || (!direct_mode && receipts.len() != trust_states.len())
    {
        return Err(json!({
            "detail": "receipt, response, and witness trust counts must match"
        }));
    }
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
        "append-verified-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum"
            .into(),
        required_string(&arguments, "log")?,
    ];
    for receipt in receipts {
        command.extend(["--receipt".into(), receipt]);
    }
    command.extend([
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--approval-log".into(),
        required_string(&arguments, "approval_log")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--checkpoint-public-key".into(),
        required_string(&arguments, "checkpoint_public_key")?,
    ]);
    for response in responses {
        command.extend(["--response".into(), response]);
    }
    for (id, key) in trusted_ids.into_iter().zip(trusted_keys) {
        command.extend(["--trusted-witness-id".into(), id]);
        command.extend(["--trusted-witness-public-key".into(), key]);
    }
    for state in trust_states {
        command.extend(["--witness-trust-state".into(), state]);
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

fn append_verified_remote_factory_release_registry_history_witness_receipt_quorum(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "receipts",
            "history",
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
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum"
            .into(),
        required_string(&arguments, "log")?,
    ];
    for receipt in receipts {
        command.extend(["--receipt".into(), receipt]);
    }
    command.extend([
        "--history".into(),
        required_string(&arguments, "history")?,
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

fn sign_quorum_bound_factory_release_receipt_transparency_log(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "quorum_report", "private_key", "signer_id", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-approval-log-with-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum"
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

fn sign_quorum_bound_factory_checkpoint_witness_receipt_transparency_log(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "quorum_report", "private_key", "signer_id", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-approval-log-with-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum"
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

fn sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "quorum_report", "private_key", "signer_id", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint"
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

fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "quorum_report", "checkpoint", "public_key", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint"
            .into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let verification = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "verification": verification}),
    ))
}

fn witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "quorum_report",
            "checkpoint",
            "checkpoint_public_key",
            "private_key",
            "witness_id",
            "witnessed_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint"
            .into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--checkpoint-public-key".into(),
        required_string(&arguments, "checkpoint_public_key")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
    ];
    optional_nonnegative_integer(
        &arguments,
        "witnessed_at_unix",
        "--witnessed-at-unix",
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

fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "quorum_report",
            "checkpoint",
            "checkpoint_public_key",
            "witnesses",
            "witness_public_keys",
            "minimum_witnesses",
            "evaluated_at_unix",
            "output",
        ],
    )?;
    let witnesses = required_string_array(&arguments, "witnesses", false)?;
    let public_keys = required_string_array(&arguments, "witness_public_keys", false)?;
    if witnesses.len() != public_keys.len() {
        return Err(json!({
            "detail": "factory checkpoint-witness receipt quorum checkpoint witnesses and public keys must be paired"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witnesses"
            .into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--checkpoint-public-key".into(),
        required_string(&arguments, "checkpoint_public_key")?,
    ];
    for witness in witnesses {
        command.extend(["--witnesses".into(), witness]);
    }
    for public_key in public_keys {
        command.extend(["--witness-public-keys".into(), public_key]);
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
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "quorum_report", "private_key", "signer_id", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint".into(),
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

fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "quorum_report", "checkpoint", "public_key", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint".into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let verification = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "verification": verification}),
    ))
}

fn witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "quorum_report",
            "checkpoint",
            "checkpoint_public_key",
            "private_key",
            "witness_id",
            "witnessed_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint".into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--checkpoint-public-key".into(),
        required_string(&arguments, "checkpoint_public_key")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
    ];
    optional_nonnegative_integer(
        &arguments,
        "witnessed_at_unix",
        "--witnessed-at-unix",
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

fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "quorum_report",
            "checkpoint",
            "checkpoint_public_key",
            "witnesses",
            "witness_public_keys",
            "witness_trust_states",
            "minimum_witnesses",
            "evaluated_at_unix",
            "output",
        ],
    )?;
    let witnesses = required_string_array(&arguments, "witnesses", false)?;
    let public_keys = arguments
        .contains_key("witness_public_keys")
        .then(|| required_string_array(&arguments, "witness_public_keys", false))
        .transpose()?
        .unwrap_or_default();
    let trust_states = arguments
        .contains_key("witness_trust_states")
        .then(|| required_string_array(&arguments, "witness_trust_states", false))
        .transpose()?
        .unwrap_or_default();
    if (!public_keys.is_empty() && !trust_states.is_empty())
        || (public_keys.is_empty() && trust_states.is_empty())
    {
        return Err(json!({
            "detail": "use either factory receipt quorum checkpoint witness public keys or trust states"
        }));
    }
    let trust_count = if trust_states.is_empty() {
        public_keys.len()
    } else {
        trust_states.len()
    };
    if witnesses.len() != trust_count {
        return Err(json!({
            "detail": "factory receipt quorum checkpoint witnesses and trust inputs must be paired"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses"
            .into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--checkpoint-public-key".into(),
        required_string(&arguments, "checkpoint_public_key")?,
    ];
    for witness in witnesses {
        command.extend(["--witnesses".into(), witness]);
    }
    for public_key in public_keys {
        command.extend(["--witness-public-keys".into(), public_key]);
    }
    for trust_state in trust_states {
        command.extend(["--witness-trust-states".into(), trust_state]);
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
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn init_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["witness_id", "public_key", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-trust"
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

fn sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
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
        "sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation"
            .into(),
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

fn apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "rotation", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "apply-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation"
            .into(),
        required_string(&arguments, "trust_state")?,
        "--rotation".into(),
        required_string(&arguments, "rotation")?,
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

fn export_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_public_key(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "export-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-public-key"
            .into(),
        required_string(&arguments, "trust_state")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(execution, json!({"output": output})))
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

fn sign_remote_approval_registry_history_receipt_quorum_log_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "quorum_report", "private_key", "signer_id", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "sign-remote-approval-registry-history-receipt-quorum-log-checkpoint".into(),
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

fn verify_remote_approval_registry_history_receipt_quorum_log_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &["log", "quorum_report", "checkpoint", "public_key", "output"],
    )?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "verify-remote-approval-registry-history-receipt-quorum-log-checkpoint".into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--public-key".into(),
        required_string(&arguments, "public_key")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    let verification = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "verification": verification}),
    ))
}

fn witness_remote_approval_registry_history_receipt_quorum_log_checkpoint(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "quorum_report",
            "checkpoint",
            "checkpoint_public_key",
            "private_key",
            "witness_id",
            "witnessed_at_unix",
            "output",
        ],
    )?;
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "witness-remote-approval-registry-history-receipt-quorum-log-checkpoint".into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--checkpoint-public-key".into(),
        required_string(&arguments, "checkpoint_public_key")?,
        "--private-key".into(),
        required_string(&arguments, "private_key")?,
        "--witness-id".into(),
        required_string(&arguments, "witness_id")?,
    ];
    optional_nonnegative_integer(
        &arguments,
        "witnessed_at_unix",
        "--witnessed-at-unix",
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

fn verify_remote_approval_registry_history_receipt_quorum_log_checkpoint_witnesses(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(
        &arguments,
        &[
            "log",
            "quorum_report",
            "checkpoint",
            "checkpoint_public_key",
            "witnesses",
            "witness_public_keys",
            "witness_trust_states",
            "minimum_witnesses",
            "evaluated_at_unix",
            "output",
        ],
    )?;
    let witnesses = required_string_array(&arguments, "witnesses", false)?;
    let public_keys = arguments
        .contains_key("witness_public_keys")
        .then(|| required_string_array(&arguments, "witness_public_keys", false))
        .transpose()?
        .unwrap_or_default();
    let trust_states = arguments
        .contains_key("witness_trust_states")
        .then(|| required_string_array(&arguments, "witness_trust_states", false))
        .transpose()?
        .unwrap_or_default();
    if (!public_keys.is_empty() && !trust_states.is_empty())
        || (public_keys.is_empty() && trust_states.is_empty())
    {
        return Err(json!({
            "detail": "use either receipt quorum checkpoint witness public keys or trust states"
        }));
    }
    let trust_count = if trust_states.is_empty() {
        public_keys.len()
    } else {
        trust_states.len()
    };
    if witnesses.len() != trust_count {
        return Err(json!({
            "detail": "receipt quorum checkpoint witnesses and trust inputs must be paired"
        }));
    }
    let output = required_string(&arguments, "output")?;
    let mut command = vec![
        "verify-remote-approval-registry-history-receipt-quorum-log-checkpoint-witnesses".into(),
        required_string(&arguments, "log")?,
        "--quorum-report".into(),
        required_string(&arguments, "quorum_report")?,
        "--checkpoint".into(),
        required_string(&arguments, "checkpoint")?,
        "--checkpoint-public-key".into(),
        required_string(&arguments, "checkpoint_public_key")?,
    ];
    for witness in witnesses {
        command.extend(["--witnesses".into(), witness]);
    }
    for public_key in public_keys {
        command.extend(["--witness-public-keys".into(), public_key]);
    }
    for trust_state in trust_states {
        command.extend(["--witness-trust-states".into(), trust_state]);
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
    command.extend(["--output".into(), output.clone()]);
    let execution = execute(&command, cancellation)?;
    let report = read_json_if_present(Path::new(&output));
    Ok(execution_result(
        execution,
        json!({"output": output, "report": report}),
    ))
}

fn init_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_trust(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["witness_id", "public_key", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "init-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-trust".into(),
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

fn sign_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
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
        "sign-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation"
            .into(),
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

fn apply_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "rotation", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "apply-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation"
            .into(),
        required_string(&arguments, "trust_state")?,
        "--rotation".into(),
        required_string(&arguments, "rotation")?,
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

fn export_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_public_key(
    arguments: Map<String, Value>,
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Value, Value> {
    reject_unknown(&arguments, &["trust_state", "output"])?;
    let output = required_string(&arguments, "output")?;
    let command = vec![
        "export-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-public-key"
            .into(),
        required_string(&arguments, "trust_state")?,
        "--output".into(),
        output.clone(),
    ];
    let execution = execute(&command, cancellation)?;
    Ok(execution_result(execution, json!({"output": output})))
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
    stdout: Vec<u8>,
    stderr: String,
}

fn execute(
    arguments: &[String],
    cancellation: Option<&AtomicBool>,
) -> std::result::Result<Execution, Value> {
    let executable = env::current_exe()
        .map_err(|error| json!({"detail": format!("locating pcbex executable: {error}")}))?;
    let mut command = Command::new(executable);
    command.args(arguments);
    let output = crate::bounded_process::run_bounded(
        &mut command,
        crate::bounded_process::ProcessLimits {
            timeout: Duration::from_secs(600),
            stdout_bytes: MAX_MCP_RESPONSE_BYTES,
            stderr_bytes: 1024 * 1024,
        },
        cancellation,
    )
    .map_err(|error| json!({"detail": format!("running pcbex tool process: {error}")}))?;
    Ok(Execution {
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: output.stdout,
        stderr: bounded_process_message(&output.stderr),
    })
}

fn bounded_process_message(bytes: &[u8]) -> String {
    const SUFFIX: &str = "\n[stderr truncated]";

    let prefix = &bytes[..bytes.len().min(MAX_MCP_PROCESS_MESSAGE_BYTES)];
    let decoded = String::from_utf8_lossy(prefix);
    let message = decoded.trim();
    let truncated = bytes.len() > prefix.len() || message.len() > MAX_MCP_PROCESS_MESSAGE_BYTES;
    if !truncated {
        return message.to_string();
    }

    let budget = MAX_MCP_PROCESS_MESSAGE_BYTES.saturating_sub(SUFFIX.len());
    let mut end = message.len().min(budget);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = message[..end].trim_end().to_string();
    bounded.push_str(SUFFIX);
    bounded
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

fn require_retained_json(mut execution: Execution, value: &Value, label: &str) -> Execution {
    if execution.success && !value.is_object() {
        execution.success = false;
        if execution.stderr.is_empty() {
            execution.stderr = format!("{label} was not retained as valid JSON");
        }
    }
    execution
}

/// Read the generated schematic without ever placing its body in an MCP
/// response.  The generic retained-file helper is intentionally capped at the
/// 16 MiB transport limit; this writer has its own 64 MiB bound and therefore
/// needs a dedicated identity-checked reader.
fn require_retained_circuit_kicad_schematic(
    mut execution: Execution,
    path: &Path,
) -> (Execution, Value) {
    if !execution.success {
        return (execution, Value::Null);
    }

    let summary = match read_circuit_kicad_schematic(path) {
        Ok(bytes) => json!({
            "path": path.display().to_string(),
            "bytes": bytes.len() as u64,
            "sha256": sha256_hex(&bytes)
        }),
        Err(error) => {
            execution.success = false;
            if execution.stderr.is_empty() {
                execution.stderr = format!(
                    "generated KiCad schematic was not retained as a stable regular file: {error}"
                );
            }
            Value::Null
        }
    };
    (execution, summary)
}

/// Read and authenticate one writer output.  `read_with_limit` performs
/// descriptor/path identity checks and a second content pass; the surrounding
/// metadata checks close the post-child replacement window at the helper
/// boundary as well.  A replacement, in-place mutation, symlink, directory,
/// disappearance, or oversized document all fail closed.
fn read_circuit_kicad_schematic(path: &Path) -> io::Result<Vec<u8>> {
    let before = crate::bounded_io::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "output is not a regular non-symlink file: {}",
                path.display()
            ),
        ));
    }
    let bytes = crate::bounded_io::read_with_limit(path, MAX_CIRCUIT_KICAD_SCHEMATIC_BYTES)?;
    let after = crate::bounded_io::symlink_metadata(path)?;
    if !after.file_type().is_file()
        || !crate::bounded_io::same_file(&before, &after)
        || before.len() != after.len()
        || after.len() != bytes.len() as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "output identity changed while being retained: {}",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

fn trusted_echoed_json(execution: &Execution, path: &Path) -> Value {
    let echoed = serde_json::from_slice(&execution.stdout).unwrap_or(Value::Null);
    let retained = read_json_if_present(path);
    if echoed.is_object() && echoed == retained {
        echoed
    } else {
        Value::Null
    }
}

/// Verify the compact stdout bridge emitted by the deterministic pipeline
/// child against a stable, bounded read of the atomically retained report.
///
/// The runner report is allowed to be larger than the MCP 16 MiB frame limit,
/// so MCP returns only this authenticated summary.  Every field is checked,
/// unknown fields are rejected, and the report's own top-level identity fields
/// are compared before the summary is trusted.
fn trusted_deterministic_pipeline_summary(execution: &Execution, path: &Path) -> Value {
    const SUMMARY_FIELDS: [&str; 7] = [
        "schema_version",
        "approved",
        "plan_sha256",
        "run_sha256",
        "failure_count",
        "report_bytes",
        "report_sha256",
    ];

    if execution.stdout.len() > MAX_MCP_PROCESS_MESSAGE_BYTES {
        return Value::Null;
    }
    let summary = serde_json::from_slice::<Value>(&execution.stdout).unwrap_or(Value::Null);
    let Some(object) = summary.as_object() else {
        return Value::Null;
    };
    if object.len() != SUMMARY_FIELDS.len()
        || SUMMARY_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Value::Null;
    }

    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .filter(|value| {
            *value == u64::from(crate::deterministic_pipeline_runner::PLAN_SCHEMA_VERSION)
        });
    let approved = object.get("approved").and_then(Value::as_bool);
    let plan_sha256 = object
        .get("plan_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let run_sha256 = object
        .get("run_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let failure_count = object.get("failure_count").and_then(Value::as_u64);
    let report_bytes = object
        .get("report_bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0);
    let report_sha256 = object
        .get("report_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let (
        Some(schema_version),
        Some(approved),
        Some(plan_sha256),
        Some(run_sha256),
        Some(failure_count),
        Some(report_bytes),
        Some(report_sha256),
    ) = (
        schema_version,
        approved,
        plan_sha256,
        run_sha256,
        failure_count,
        report_bytes,
        report_sha256,
    )
    else {
        return Value::Null;
    };

    let max_report_bytes =
        (crate::deterministic_pipeline_runner::MAX_REPORT_BYTES as u64).saturating_add(1);
    if report_bytes > max_report_bytes || failure_count > 128 {
        return Value::Null;
    }
    let Ok(retained) = crate::bounded_io::read_with_limit(path, max_report_bytes) else {
        return Value::Null;
    };
    if retained.len() as u64 != report_bytes || sha256_hex(&retained) != report_sha256 {
        return Value::Null;
    }
    let Ok(report) = serde_json::from_slice::<Value>(&retained) else {
        return Value::Null;
    };
    let Some(report_object) = report.as_object() else {
        return Value::Null;
    };
    if report_object.get("schema_version").and_then(Value::as_u64) != Some(schema_version)
        || report_object.get("approved").and_then(Value::as_bool) != Some(approved)
        || report_object.get("plan_sha256").and_then(Value::as_str) != Some(plan_sha256)
        || report_object.get("run_sha256").and_then(Value::as_str) != Some(run_sha256)
        || report_object
            .get("failures")
            .and_then(Value::as_array)
            .is_none_or(|failures| failures.len() as u64 != failure_count)
        || approved != (failure_count == 0)
    {
        return Value::Null;
    }

    summary
}

/// Authenticate the fabrication verifier's compact stdout bridge against the
/// exact retained report bytes and a full semantic replay of that report.
///
/// The report may contain up to 100 signed approvals and can reach the shared
/// 128 MiB file ceiling, so it must never cross MCP.  Only the closed summary
/// below is returned after every field, digest, count, constant, nested
/// evidence binding, and retained signature has been independently checked.
fn trusted_fabrication_authorization_summary(
    execution: &Execution,
    path: &Path,
    cancellation: Option<&AtomicBool>,
) -> Value {
    const SUMMARY_FIELDS: [&str; 23] = [
        "schema_version",
        "status",
        "fabrication_authorized",
        "authorization_id",
        "challenge",
        "quantity",
        "currency",
        "maximum_total_minor_units",
        "valid_from_unix",
        "expires_at_unix",
        "evaluated_at_unix",
        "approvals",
        "rejections",
        "gate_failure_count",
        "plan_sha256",
        "run_sha256",
        "manufacturing_package_sha256",
        "factory_receipt_sha256",
        "policy_pack_sha256",
        "quote_authenticity_verified",
        "challenge_one_time_use_enforced",
        "report_bytes",
        "report_sha256",
    ];
    const MAXIMUM_QUANTITY: u64 = 1_000_000;
    const MAXIMUM_TOTAL_MINOR_UNITS: u64 = 9_007_199_254_740_991;
    const MAXIMUM_VALIDITY_SECONDS: u64 = 604_800;
    const MAXIMUM_APPROVALS: u64 = 100;
    const MAXIMUM_GATE_FAILURES: u64 = 4;

    if task_is_cancelled(cancellation)
        || execution.stdout.len() > MAX_MCP_PROCESS_MESSAGE_BYTES
        || has_duplicate_json_keys(&execution.stdout)
    {
        return Value::Null;
    }
    let summary = serde_json::from_slice::<Value>(&execution.stdout).unwrap_or(Value::Null);
    let Some(object) = summary.as_object() else {
        return Value::Null;
    };
    if object.len() != SUMMARY_FIELDS.len()
        || SUMMARY_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Value::Null;
    }

    let Some(schema_version) = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .filter(|value| {
            *value
                == u64::from(
                    crate::fabrication_authorization::FABRICATION_AUTHORIZATION_REPORT_SCHEMA_VERSION,
                )
        })
    else {
        return Value::Null;
    };
    let Some(status) = object
        .get("status")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "fabrication_authorized" | "not_authorized"))
    else {
        return Value::Null;
    };
    let Some(fabrication_authorized) = object
        .get("fabrication_authorized")
        .and_then(Value::as_bool)
    else {
        return Value::Null;
    };
    let Some(authorization_id) = object
        .get("authorization_id")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && (value.as_bytes()[0].is_ascii_lowercase()
                    || value.as_bytes()[0].is_ascii_digit())
                && value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'-')
                })
        })
    else {
        return Value::Null;
    };
    let Some(challenge) = object
        .get("challenge")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value))
    else {
        return Value::Null;
    };
    let Some(quantity) = object
        .get("quantity")
        .and_then(Value::as_u64)
        .filter(|value| (1..=MAXIMUM_QUANTITY).contains(value))
    else {
        return Value::Null;
    };
    let Some(currency) = object
        .get("currency")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()))
    else {
        return Value::Null;
    };
    let Some(maximum_total_minor_units) = object
        .get("maximum_total_minor_units")
        .and_then(Value::as_u64)
        .filter(|value| (1..=MAXIMUM_TOTAL_MINOR_UNITS).contains(value))
    else {
        return Value::Null;
    };
    let Some(valid_from_unix) = object.get("valid_from_unix").and_then(Value::as_u64) else {
        return Value::Null;
    };
    let Some(expires_at_unix) = object
        .get("expires_at_unix")
        .and_then(Value::as_u64)
        .filter(|expires| {
            expires
                .checked_sub(valid_from_unix)
                .is_some_and(|duration| (1..=MAXIMUM_VALIDITY_SECONDS).contains(&duration))
        })
    else {
        return Value::Null;
    };
    let Some(evaluated_at_unix) = object.get("evaluated_at_unix").and_then(Value::as_u64) else {
        return Value::Null;
    };
    let Some(approvals) = object
        .get("approvals")
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAXIMUM_APPROVALS)
    else {
        return Value::Null;
    };
    let Some(rejections) = object
        .get("rejections")
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAXIMUM_APPROVALS)
    else {
        return Value::Null;
    };
    let Some(approval_count) = approvals
        .checked_add(rejections)
        .filter(|value| (1..=MAXIMUM_APPROVALS).contains(value))
    else {
        return Value::Null;
    };
    let Some(gate_failure_count) = object
        .get("gate_failure_count")
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAXIMUM_GATE_FAILURES)
    else {
        return Value::Null;
    };
    let Some(plan_sha256) = object
        .get("plan_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value))
    else {
        return Value::Null;
    };
    let Some(run_sha256) = object
        .get("run_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value))
    else {
        return Value::Null;
    };
    let Some(manufacturing_package_sha256) = object
        .get("manufacturing_package_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value))
    else {
        return Value::Null;
    };
    let Some(factory_receipt_sha256) = object
        .get("factory_receipt_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value))
    else {
        return Value::Null;
    };
    let Some(policy_pack_sha256) = object
        .get("policy_pack_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value))
    else {
        return Value::Null;
    };
    let Some(quote_authenticity_verified) = object
        .get("quote_authenticity_verified")
        .and_then(Value::as_bool)
        .filter(|value| !*value)
    else {
        return Value::Null;
    };
    let Some(challenge_one_time_use_enforced) = object
        .get("challenge_one_time_use_enforced")
        .and_then(Value::as_bool)
        .filter(|value| !*value)
    else {
        return Value::Null;
    };
    let Some(report_bytes) = object
        .get("report_bytes")
        .and_then(Value::as_u64)
        .filter(|value| (1..=crate::bounded_io::MAX_FILE_BYTES).contains(value))
    else {
        return Value::Null;
    };
    let Some(report_sha256) = object
        .get("report_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value))
    else {
        return Value::Null;
    };

    let expected_status = if fabrication_authorized {
        "fabrication_authorized"
    } else {
        "not_authorized"
    };
    if status != expected_status
        || fabrication_authorized != (gate_failure_count == 0)
        || (fabrication_authorized && rejections != 0)
    {
        return Value::Null;
    }

    if task_is_cancelled(cancellation) {
        return Value::Null;
    }
    let Ok(retained) = crate::bounded_io::read_with_limit(path, crate::bounded_io::MAX_FILE_BYTES)
    else {
        return Value::Null;
    };
    #[cfg(test)]
    invoke_after_fabrication_report_read_hook();
    if task_is_cancelled(cancellation) || retained.len() as u64 != report_bytes {
        return Value::Null;
    }
    if sha256_hex(&retained) != report_sha256 || task_is_cancelled(cancellation) {
        return Value::Null;
    }
    if has_duplicate_json_keys(&retained) || task_is_cancelled(cancellation) {
        return Value::Null;
    }
    let Ok(report) = serde_json::from_slice::<
        crate::fabrication_authorization::FabricationAuthorizationReport,
    >(&retained) else {
        return Value::Null;
    };
    if task_is_cancelled(cancellation) {
        return Value::Null;
    }

    // Re-run the retained policy and signature verification at the report's
    // recorded evaluation instant.  Exact equality checks every non-summary
    // semantic field too, without returning policy contents, approvals,
    // reasons, tickets, or any other sensitive report body over MCP.
    let Ok(reverified) = crate::fabrication_authorization::verify_fabrication_authorization(
        &report.evidence,
        &report.policy_pack,
        &report.signed_approvals,
        report.evaluated_at_unix,
    ) else {
        return Value::Null;
    };
    if task_is_cancelled(cancellation)
        || reverified != report
        || u64::from(report.schema_version) != schema_version
        || report.status != status
        || report.fabrication_authorized != fabrication_authorized
        || report.scope.authorization_id != authorization_id
        || report.scope.challenge != challenge
        || u64::from(report.scope.quantity) != quantity
        || report.scope.currency != currency
        || report.scope.maximum_total_minor_units != maximum_total_minor_units
        || report.scope.valid_from_unix != valid_from_unix
        || report.scope.expires_at_unix != expires_at_unix
        || report.evaluated_at_unix != evaluated_at_unix
        || u64::from(report.approvals) != approvals
        || u64::from(report.rejections) != rejections
        || report.signed_approvals.len() as u64 != approval_count
        || report.gate_failures.len() as u64 != gate_failure_count
        || report.evidence.pipeline.plan_sha256 != plan_sha256
        || report.evidence.pipeline.run_sha256 != run_sha256
        || report.evidence.manufacturing_package.sha256 != manufacturing_package_sha256
        || report.evidence.factory_receipt.receipt.sha256 != factory_receipt_sha256
        || report.evidence.policy_pack.source.sha256 != policy_pack_sha256
        || report.evidence.factory_receipt.quote_authenticity_verified
            != quote_authenticity_verified
        || report.challenge_one_time_use_enforced != challenge_one_time_use_enforced
    {
        return Value::Null;
    }

    summary
}

/// Verify the compact stdout bridge emitted by the deterministic pipeline
/// intent compiler against stable, bounded reads of the current intent and
/// atomically retained plan.  The compiler has no rejected report to return;
/// a malformed echo, changed source, or changed plan therefore fails closed.
fn trusted_deterministic_pipeline_plan_summary(
    execution: &Execution,
    intent_path: &Path,
    plan_path: &Path,
) -> Value {
    const SUMMARY_FIELDS: [&str; 5] = [
        "schema_version",
        "intent_source_bytes",
        "intent_source_sha256",
        "plan_source_bytes",
        "plan_source_sha256",
    ];

    if execution.stdout.len() > MAX_MCP_PROCESS_MESSAGE_BYTES {
        return Value::Null;
    }
    let summary = serde_json::from_slice::<Value>(&execution.stdout).unwrap_or(Value::Null);
    let Some(object) = summary.as_object() else {
        return Value::Null;
    };
    if object.len() != SUMMARY_FIELDS.len()
        || SUMMARY_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Value::Null;
    }

    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .filter(|value| {
            *value == u64::from(crate::deterministic_pipeline_runner::PLAN_SCHEMA_VERSION)
        });
    let intent_source_bytes = object
        .get("intent_source_bytes")
        .and_then(Value::as_u64)
        .filter(|value| {
            *value > 0 && *value <= crate::deterministic_pipeline_compiler::MAX_INTENT_BYTES
        });
    let intent_source_sha256 = object
        .get("intent_source_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let plan_source_bytes = object
        .get("plan_source_bytes")
        .and_then(Value::as_u64)
        .filter(|value| {
            *value > 0 && *value <= crate::deterministic_pipeline_runner::MAX_PLAN_BYTES
        });
    let plan_source_sha256 = object
        .get("plan_source_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let (
        Some(_schema_version),
        Some(intent_source_bytes),
        Some(intent_source_sha256),
        Some(plan_source_bytes),
        Some(plan_source_sha256),
    ) = (
        schema_version,
        intent_source_bytes,
        intent_source_sha256,
        plan_source_bytes,
        plan_source_sha256,
    )
    else {
        return Value::Null;
    };

    let Ok(intent) = crate::bounded_io::read_with_limit(
        intent_path,
        crate::deterministic_pipeline_compiler::MAX_INTENT_BYTES,
    ) else {
        return Value::Null;
    };
    if intent.len() as u64 != intent_source_bytes || sha256_hex(&intent) != intent_source_sha256 {
        return Value::Null;
    }

    let Ok(plan) = crate::bounded_io::read_with_limit(
        plan_path,
        crate::deterministic_pipeline_runner::MAX_PLAN_BYTES,
    ) else {
        return Value::Null;
    };
    if plan.len() as u64 != plan_source_bytes || sha256_hex(&plan) != plan_source_sha256 {
        return Value::Null;
    }
    let Ok(plan_document) = serde_json::from_slice::<Value>(&plan) else {
        return Value::Null;
    };
    if plan.last() != Some(&b'\n')
        || plan_document
            .as_object()
            .and_then(|plan| plan.get("schema_version"))
            .and_then(Value::as_u64)
            != Some(crate::deterministic_pipeline_runner::PLAN_SCHEMA_VERSION.into())
    {
        return Value::Null;
    }

    summary
}

/// Verify the compact stdout bridge emitted by the native KiCad ERC child
/// against a stable bounded read of its retained normalized report.  Native
/// reports have a 32 MiB ceiling, so returning the complete document could
/// exceed the 16 MiB MCP frame limit.
fn trusted_native_kicad_erc_summary(execution: &Execution, path: &Path) -> Value {
    if execution.stdout.len() > MAX_MCP_PROCESS_MESSAGE_BYTES {
        return Value::Null;
    }
    let summary = serde_json::from_slice::<Value>(&execution.stdout).unwrap_or(Value::Null);
    let Some(object) = summary.as_object() else {
        return Value::Null;
    };
    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .filter(|value| matches!(*value, 1 | 2));
    let Some(schema_version) = schema_version else {
        return Value::Null;
    };
    let expected_fields_v1 = [
        "schema_version",
        "approved",
        "error_count",
        "run_sha256",
        "report_bytes",
        "report_sha256",
    ];
    let expected_fields_v2 = [
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
    let expected_fields: &[&str] = if schema_version == 1 {
        &expected_fields_v1
    } else {
        &expected_fields_v2
    };
    if object.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Value::Null;
    }
    let approved = object.get("approved").and_then(Value::as_bool);
    let error_count = object.get("error_count").and_then(Value::as_u64);
    let run_sha256 = object
        .get("run_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let report_bytes = object
        .get("report_bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0);
    let report_sha256 = object
        .get("report_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let warning_count = object.get("warning_count").and_then(Value::as_u64);
    let policy_failure_count = object.get("policy_failure_count").and_then(Value::as_u64);
    let warning_policy_sha256 = object
        .get("warning_policy_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let warning_policy_source_bytes = object
        .get("warning_policy_source_bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0);
    let warning_policy_source_sha256 = object
        .get("warning_policy_source_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let (
        Some(approved),
        Some(error_count),
        Some(run_sha256),
        Some(report_bytes),
        Some(report_sha256),
    ) = (
        approved,
        error_count,
        run_sha256,
        report_bytes,
        report_sha256,
    )
    else {
        return Value::Null;
    };
    if schema_version == 2
        && (warning_count.is_none()
            || policy_failure_count.is_none()
            || warning_policy_sha256.is_none()
            || warning_policy_source_bytes.is_none()
            || warning_policy_source_sha256.is_none())
    {
        return Value::Null;
    }

    if report_bytes > crate::native_kicad_erc::MAX_REPORT_BYTES {
        return Value::Null;
    }
    let Ok(retained) =
        crate::bounded_io::read_with_limit(path, crate::native_kicad_erc::MAX_REPORT_BYTES)
    else {
        return Value::Null;
    };
    if retained.len() as u64 != report_bytes || sha256_hex(&retained) != report_sha256 {
        return Value::Null;
    }
    let Ok(report) = serde_json::from_slice::<Value>(&retained) else {
        return Value::Null;
    };
    let Some(report_object) = report.as_object() else {
        return Value::Null;
    };
    if report_object.get("schema_version").and_then(Value::as_u64) != Some(schema_version)
        || report_object.get("approved").and_then(Value::as_bool) != Some(approved)
        || report_object.get("error_count").and_then(Value::as_u64) != Some(error_count)
        || report_object.get("run_sha256").and_then(Value::as_str) != Some(run_sha256)
    {
        return Value::Null;
    }
    let Some(findings) = report_object.get("findings").and_then(Value::as_array) else {
        return Value::Null;
    };
    let actual_error_count = findings
        .iter()
        .filter(|finding| finding.get("severity").and_then(Value::as_str) == Some("error"))
        .count() as u64;
    let actual_warning_count = findings
        .iter()
        .filter(|finding| finding.get("severity").and_then(Value::as_str) == Some("warning"))
        .count() as u64;
    if actual_error_count != error_count {
        return Value::Null;
    }
    if schema_version == 1 {
        if findings.len() as u64 != error_count || approved != (error_count == 0) {
            return Value::Null;
        }
    } else {
        let warning_count = warning_count.expect("validated above");
        let policy_failure_count = policy_failure_count.expect("validated above");
        if findings.len() as u64 != error_count.saturating_add(warning_count)
            || actual_warning_count != warning_count
            || report_object.get("warning_count").and_then(Value::as_u64) != Some(warning_count)
            || report_object
                .get("policy_failures")
                .and_then(Value::as_array)
                .is_none_or(|failures| failures.len() as u64 != policy_failure_count)
            || approved != (error_count == 0 && policy_failure_count == 0)
        {
            return Value::Null;
        }
        let Some(policy) = report_object
            .get("warning_policy")
            .and_then(Value::as_object)
        else {
            return Value::Null;
        };
        if policy.get("policy").and_then(Value::as_object).is_none() {
            return Value::Null;
        }
        if policy.get("policy_sha256").and_then(Value::as_str) != warning_policy_sha256 {
            return Value::Null;
        }
        let Some(source) = policy.get("source").and_then(Value::as_object) else {
            return Value::Null;
        };
        if source.get("bytes").and_then(Value::as_u64) != warning_policy_source_bytes
            || source.get("sha256").and_then(Value::as_str) != warning_policy_source_sha256
        {
            return Value::Null;
        }
    }

    summary
}

/// Verify the compact stdout bridge emitted by the native KiCad PCB DRC
/// child.  The complete report remains on disk; MCP exposes only this
/// digest-bound summary after checking the retained report's closed top-level
/// shape and every summary count.
fn trusted_native_kicad_drc_summary(
    execution: &Execution,
    path: &Path,
    input: &Path,
    project: Option<&Path>,
    rules_file: Option<&Path>,
) -> Value {
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
    if execution.stdout.len() > MAX_MCP_PROCESS_MESSAGE_BYTES
        || has_duplicate_json_keys(&execution.stdout)
    {
        return Value::Null;
    }
    let summary = serde_json::from_slice::<Value>(&execution.stdout).unwrap_or(Value::Null);
    let Some(object) = summary.as_object() else {
        return Value::Null;
    };
    if object.len() != SUMMARY_FIELDS.len()
        || SUMMARY_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Value::Null;
    }

    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .filter(|value| *value == 1);
    let approved = object.get("approved").and_then(Value::as_bool);
    let violation_count = object.get("violation_count").and_then(Value::as_u64);
    let unconnected_item_count = object.get("unconnected_item_count").and_then(Value::as_u64);
    let schematic_parity_count = object.get("schematic_parity_count").and_then(Value::as_u64);
    let error_count = object.get("error_count").and_then(Value::as_u64);
    let warning_count = object.get("warning_count").and_then(Value::as_u64);
    let ignored_check_count = object.get("ignored_check_count").and_then(Value::as_u64);
    let board_bytes = object.get("board_bytes").and_then(Value::as_u64);
    let board_sha256 = object
        .get("board_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let project_bytes = object.get("project_bytes");
    let project_sha256 = object.get("project_sha256");
    let rules_file_bytes = object.get("rules_file_bytes");
    let rules_file_sha256 = object.get("rules_file_sha256");
    let run_sha256 = object
        .get("run_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let report_bytes = object
        .get("report_bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= crate::native_kicad_drc::MAX_REPORT_BYTES);
    let report_sha256 = object
        .get("report_sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value));
    let (
        Some(schema_version),
        Some(approved),
        Some(violation_count),
        Some(unconnected_item_count),
        Some(schematic_parity_count),
        Some(error_count),
        Some(warning_count),
        Some(ignored_check_count),
        Some(board_bytes),
        Some(board_sha256),
        Some(run_sha256),
        Some(report_bytes),
        Some(report_sha256),
    ) = (
        schema_version,
        approved,
        violation_count,
        unconnected_item_count,
        schematic_parity_count,
        error_count,
        warning_count,
        ignored_check_count,
        board_bytes,
        board_sha256,
        run_sha256,
        report_bytes,
        report_sha256,
    )
    else {
        return Value::Null;
    };
    let Ok(retained) =
        crate::bounded_io::read_with_limit(path, crate::native_kicad_drc::MAX_REPORT_BYTES)
    else {
        return Value::Null;
    };
    if retained.len() as u64 != report_bytes || sha256_hex(&retained) != report_sha256 {
        return Value::Null;
    }
    if has_duplicate_json_keys(&retained) {
        return Value::Null;
    }
    let Ok(report) = crate::native_kicad_drc::decode_native_kicad_drc_report(&retained) else {
        return Value::Null;
    };
    if report.schema_version as u64 != schema_version
        || report.approved != approved
        || report.violation_count as u64 != violation_count
        || report.unconnected_item_count as u64 != unconnected_item_count
        || report.schematic_parity_count as u64 != schematic_parity_count
        || report.error_count as u64 != error_count
        || report.warning_count as u64 != warning_count
        || report.ignored_checks.len() as u64 != ignored_check_count
        || report.run_sha256 != run_sha256
    {
        return Value::Null;
    }
    let Ok((resolved_project, resolved_rules)) =
        crate::native_kicad_drc::resolve_native_kicad_drc_companions(input, project, rules_file)
    else {
        return Value::Null;
    };
    let Some(source_identity) = native_drc_file_identity(input) else {
        return Value::Null;
    };
    if report.source != source_identity {
        return Value::Null;
    }
    let project_identity = resolved_project
        .as_deref()
        .and_then(native_drc_file_identity);
    let rules_identity = resolved_rules.as_deref().and_then(native_drc_file_identity);
    if report.project != project_identity || report.rules_file != rules_identity {
        return Value::Null;
    }
    let expected_project_bytes = report.project.as_ref().map_or_else(
        || Value::String(String::new()),
        |identity| json!(identity.bytes),
    );
    let expected_project_sha256 = report.project.as_ref().map_or_else(
        || Value::String(String::new()),
        |identity| Value::String(identity.sha256.clone()),
    );
    let expected_rules_file_bytes = report.rules_file.as_ref().map_or_else(
        || Value::String(String::new()),
        |identity| json!(identity.bytes),
    );
    let expected_rules_file_sha256 = report.rules_file.as_ref().map_or_else(
        || Value::String(String::new()),
        |identity| Value::String(identity.sha256.clone()),
    );
    if board_bytes != report.source.bytes
        || board_sha256 != report.source.sha256.as_str()
        || project_bytes != Some(&expected_project_bytes)
        || project_sha256 != Some(&expected_project_sha256)
        || rules_file_bytes != Some(&expected_rules_file_bytes)
        || rules_file_sha256 != Some(&expected_rules_file_sha256)
    {
        return Value::Null;
    }
    summary
}

fn native_drc_file_identity(
    path: &Path,
) -> Option<crate::native_kicad_drc::NativeKicadDrcSourceIdentity> {
    const MAX_INPUT_BYTES: u64 = 128 * 1024 * 1024;
    let bytes = crate::bounded_io::read_with_limit(path, MAX_INPUT_BYTES).ok()?;
    (!bytes.is_empty()).then(|| crate::native_kicad_drc::NativeKicadDrcSourceIdentity {
        bytes: bytes.len() as u64,
        sha256: sha256_hex(&bytes),
    })
}

struct DuplicateKeySeed;

impl<'de> DeserializeSeed<'de> for DuplicateKeySeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}

struct DuplicateKeyVisitor;

impl<'de> Visitor<'de> for DuplicateKeyVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = access.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            access.next_value_seed(DuplicateKeySeed)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while access.next_element_seed(DuplicateKeySeed)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_bytes<E>(self, _value: &'de [u8]) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
}

fn has_duplicate_json_keys(bytes: &[u8]) -> bool {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    if deserializer.deserialize_any(DuplicateKeyVisitor).is_err() {
        return true;
    }
    deserializer.end().is_err()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn require_retained_file(mut execution: Execution, path: &Path, label: &str) -> Execution {
    if execution.success
        && !matches!(
            crate::bounded_io::read_with_limit(path, MAX_MCP_RESPONSE_BYTES as u64),
            Ok(bytes) if !bytes.is_empty()
        )
    {
        execution.success = false;
        if execution.stderr.is_empty() {
            execution.stderr = format!("{label} was not retained as a non-empty regular file");
        }
    }
    execution
}

fn require_absent_outputs<'a>(
    paths: impl IntoIterator<Item = Option<&'a str>>,
) -> std::result::Result<(), Value> {
    for path in paths.into_iter().flatten() {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(json!({
                    "detail": "output path already exists; refusing stale MCP evidence"
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(json!({
                    "detail": "output path could not be safely inspected"
                }));
            }
        }
    }
    Ok(())
}

fn read_json_if_present(path: &Path) -> Value {
    crate::bounded_io::read_with_limit(path, MAX_MCP_RESPONSE_BYTES as u64)
        .ok()
        .and_then(|source| serde_json::from_slice(&source).ok())
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

fn required_fabrication_path(
    arguments: &Map<String, Value>,
    name: &str,
) -> std::result::Result<String, Value> {
    let value = required_string(arguments, name)?;
    validate_fabrication_path(&value, name)?;
    Ok(value)
}

fn validate_fabrication_path(value: &str, name: &str) -> std::result::Result<(), Value> {
    if value.chars().count() > 4096 {
        Err(json!({
            "detail": format!("{name} must contain at most 4096 characters")
        }))
    } else if value.bytes().any(|byte| byte <= 0x1f || byte == 0x7f) {
        Err(json!({
            "detail": format!("{name} must not contain NUL or ASCII control characters")
        }))
    } else {
        Ok(())
    }
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

/// Require an optional group of related path arguments to be either entirely
/// absent or entirely present.  The CLI performs the authoritative artifact
/// binding and digest validation; MCP rejects partial groups before spawning
/// a child so a caller cannot accidentally create a request that omits one
/// side of the binding handoff.
fn require_complete_option_set(
    arguments: &Map<String, Value>,
    names: &[&str],
    label: &str,
) -> std::result::Result<(), Value> {
    let supplied = names
        .iter()
        .filter(|name| arguments.contains_key(**name))
        .count();
    if supplied == 0 || supplied == names.len() {
        Ok(())
    } else {
        Err(json!({
            "detail": format!("{label} must be supplied together")
        }))
    }
}

fn append_complete_options(
    arguments: &Map<String, Value>,
    options: &[(&str, &str)],
    label: &str,
    command: &mut Vec<String>,
) -> std::result::Result<(), Value> {
    let names = options.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    require_complete_option_set(arguments, &names, label)?;
    for (name, option) in options {
        optional_option(arguments, name, option, command)?;
    }
    Ok(())
}

/// Append the schema-v1 live schematic binding while rejecting every
/// generated/native artifact field.  The CLI performs the authoritative
/// semantic binding; MCP still fails closed before spawning a child when a
/// caller mixes mutually exclusive binding modes.
fn append_live_schematic_option(
    arguments: &Map<String, Value>,
    command: &mut Vec<String>,
) -> std::result::Result<(), Value> {
    if arguments.contains_key("schematic") {
        let artifact_fields = [
            "generated_schematic",
            "deterministic_pipeline_plan",
            "deterministic_pipeline_report",
            "native_kicad_erc_report",
            "native_kicad_erc_warning_policy",
            "kicad_cli",
        ];
        if artifact_fields
            .iter()
            .any(|field| arguments.contains_key(*field))
        {
            return Err(json!({
                "detail": "schematic cannot be combined with generated/native AI review artifacts"
            }));
        }
    }
    optional_option(arguments, "schematic", "--schematic", command)
}

/// Append the optional AI-review artifact identity flags while enforcing the
/// schema-version groups shared by prepare/sign/verify/quorum.  Error-only
/// native ERC evidence upgrades a complete deterministic artifact set to
/// schema v3; a warning policy upgrades it to schema v4.  A KiCad executable
/// is meaningful only for that native evidence path.
fn append_native_ai_review_options(
    arguments: &Map<String, Value>,
    options: &[(&str, &str)],
    label: &str,
    command: &mut Vec<String>,
) -> std::result::Result<(), Value> {
    let native_supplied = arguments.contains_key("native_kicad_erc_report");
    let warning_policy_supplied = arguments.contains_key("native_kicad_erc_warning_policy");
    let supplied = options
        .iter()
        .filter(|(name, _)| arguments.contains_key(*name))
        .count();
    if native_supplied && supplied != options.len() {
        return Err(json!({
            "detail": format!("{label} and native_kicad_erc_report must be supplied together")
        }));
    }
    append_complete_options(arguments, options, label, command)?;
    if arguments.contains_key("kicad_cli") && !native_supplied {
        return Err(json!({
            "detail": "kicad_cli requires native_kicad_erc_report"
        }));
    }
    if warning_policy_supplied && !native_supplied {
        return Err(json!({
            "detail": "native_kicad_erc_warning_policy requires native_kicad_erc_report"
        }));
    }
    if native_supplied {
        optional_option(
            arguments,
            "native_kicad_erc_report",
            "--native-kicad-erc-report",
            command,
        )?;
        optional_option(
            arguments,
            "native_kicad_erc_warning_policy",
            "--native-kicad-erc-warning-policy",
            command,
        )?;
        optional_option(arguments, "kicad_cli", "--kicad-cli", command)?;
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

    #[test]
    fn bounded_line_accepts_exact_limit_and_drains_oversized_frames() {
        let mut exact = vec![b'a'; MAX_MCP_REQUEST_BYTES];
        exact.extend_from_slice(b"\n{\"next\":true}\n");
        let mut reader = std::io::Cursor::new(exact);
        let line = read_bounded_line(&mut reader).unwrap().unwrap();
        match line {
            BoundedLine::Line(line) => assert_eq!(line.len(), MAX_MCP_REQUEST_BYTES),
            BoundedLine::Oversized => panic!("exactly bounded request was rejected"),
        }
        assert!(matches!(
            read_bounded_line(&mut reader).unwrap().unwrap(),
            BoundedLine::Line(line) if line == "{\"next\":true}"
        ));

        let mut oversized = vec![b'b'; MAX_MCP_REQUEST_BYTES + 1];
        oversized.extend_from_slice(b"\n{\"after\":true}\n");
        let mut reader = std::io::Cursor::new(oversized);
        assert!(matches!(
            read_bounded_line(&mut reader).unwrap().unwrap(),
            BoundedLine::Oversized
        ));
        assert!(matches!(
            read_bounded_line(&mut reader).unwrap().unwrap(),
            BoundedLine::Line(line) if line == "{\"after\":true}"
        ));
    }

    #[test]
    fn oversized_response_becomes_small_internal_error_without_partial_output() {
        let base = serde_json::to_vec(&json!({"payload": ""})).unwrap().len();
        let exact_payload = "a".repeat(MAX_MCP_RESPONSE_BYTES - 1 - base);
        let exact = bounded_json_line(&json!({"payload": exact_payload})).unwrap();
        assert_eq!(exact.len(), MAX_MCP_RESPONSE_BYTES);

        let oversized = json!({
            "payload": "a".repeat(MAX_MCP_RESPONSE_BYTES - base)
        });
        assert!(bounded_json_line(&oversized).is_none());
        let fallback: Value = serde_json::from_slice(&response_bytes(&oversized)).unwrap();
        assert_eq!(fallback["error"]["code"], -32603);
        assert!(response_bytes(&oversized).len() < 1024);
    }

    #[test]
    fn expired_working_tasks_are_cancelled_before_removal() {
        let mut server = McpServer::default();
        let cancellation = Arc::new(AtomicBool::new(false));
        let created_at = iso8601_now();
        let task_id = "expired-task".to_string();
        server.tasks.insert(
            task_id.clone(),
            Arc::new(TaskRecord {
                task_id,
                created_at: created_at.clone(),
                created: Instant::now() - Duration::from_secs(1),
                ttl_ms: 1,
                cancellation: Arc::clone(&cancellation),
                state: Mutex::new(TaskState {
                    status: TaskStatus::Working,
                    status_message: "working".to_string(),
                    last_updated_at: created_at,
                    result: None,
                }),
                changed: Condvar::new(),
            }),
        );

        server.remove_expired_tasks();
        assert!(cancellation.load(Ordering::SeqCst));
        assert!(server.tasks.is_empty());
    }

    #[test]
    fn task_ttl_watchdog_actively_cancels_working_task() {
        let created_at = iso8601_now();
        let record = Arc::new(TaskRecord {
            task_id: "watchdog-task".to_string(),
            created_at: created_at.clone(),
            created: Instant::now(),
            ttl_ms: 10,
            cancellation: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(TaskState {
                status: TaskStatus::Working,
                status_message: "working".to_string(),
                last_updated_at: created_at,
                result: None,
            }),
            changed: Condvar::new(),
        });
        arm_task_expiration(&record).unwrap();

        let state = record.state.lock().unwrap();
        let (state, timeout) = record
            .changed
            .wait_timeout_while(state, Duration::from_secs(1), |state| {
                !state.status.is_terminal()
            })
            .unwrap();
        assert!(!timeout.timed_out(), "TTL watchdog did not fire");
        assert!(matches!(state.status, TaskStatus::Cancelled));
        assert!(record.cancellation.load(Ordering::SeqCst));
    }

    #[test]
    fn pre_cancelled_tool_call_returns_tool_error_without_dispatch() {
        let cancelled = AtomicBool::new(true);
        let params = json!({"name": "list_dfm_profiles", "arguments": {}});
        let result = call_tool(Some(&params), Some(&cancelled)).unwrap();
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["structuredContent"]["error"]["detail"],
            "task execution cancelled"
        );
    }

    #[test]
    fn process_diagnostics_are_trimmed_and_bounded() {
        assert_eq!(
            bounded_process_message(b"  concise error \n"),
            "concise error"
        );

        let oversized = vec![b'x'; MAX_MCP_PROCESS_MESSAGE_BYTES + 1];
        let message = bounded_process_message(&oversized);
        assert!(message.len() <= MAX_MCP_PROCESS_MESSAGE_BYTES);
        assert!(message.ends_with("[stderr truncated]"));

        let invalid = vec![0xff; MAX_MCP_PROCESS_MESSAGE_BYTES];
        assert!(bounded_process_message(&invalid).len() <= MAX_MCP_PROCESS_MESSAGE_BYTES);
    }

    #[test]
    fn bounded_json_file_reader_rejects_symlink_and_oversized_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("valid.json");
        std::fs::write(&valid, br#"{"ok":true}"#).unwrap();
        assert_eq!(read_json_if_present(&valid), json!({"ok": true}));

        let oversized = directory.path().join("oversized.json");
        let file = std::fs::File::create(&oversized).unwrap();
        file.set_len(MAX_MCP_RESPONSE_BYTES as u64 + 1).unwrap();
        assert_eq!(read_json_if_present(&oversized), Value::Null);

        #[cfg(unix)]
        {
            let link = directory.path().join("link.json");
            std::os::unix::fs::symlink(&valid, &link).unwrap();
            assert_eq!(read_json_if_present(&link), Value::Null);
        }
    }

    #[test]
    fn ai_review_artifact_options_forward_exact_cli_flags() {
        let arguments = json!({
            "generated_schematic": "generated.kicad_sch",
            "deterministic_pipeline_plan": "plan.json",
            "deterministic_pipeline_report": "report.json"
        });
        let arguments = arguments.as_object().unwrap();
        let mut command = vec!["verify-ai-quorum".to_string()];
        append_complete_options(
            arguments,
            &[
                ("generated_schematic", "--generated-schematic"),
                (
                    "deterministic_pipeline_plan",
                    "--deterministic-pipeline-plan",
                ),
                (
                    "deterministic_pipeline_report",
                    "--deterministic-pipeline-report",
                ),
            ],
            "generated_schematic, deterministic_pipeline_plan, and deterministic_pipeline_report",
            &mut command,
        )
        .unwrap();
        assert_eq!(
            command,
            vec![
                "verify-ai-quorum",
                "--generated-schematic",
                "generated.kicad_sch",
                "--deterministic-pipeline-plan",
                "plan.json",
                "--deterministic-pipeline-report",
                "report.json"
            ]
        );

        let partial = json!({"generated_schematic": "generated.kicad_sch"});
        let error = append_complete_options(
            partial.as_object().unwrap(),
            &[
                ("generated_schematic", "--generated-schematic"),
                (
                    "deterministic_pipeline_plan",
                    "--deterministic-pipeline-plan",
                ),
                (
                    "deterministic_pipeline_report",
                    "--deterministic-pipeline-report",
                ),
            ],
            "generated_schematic, deterministic_pipeline_plan, and deterministic_pipeline_report",
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("must be supplied together")
        );

        let partial_pair = json!({"deterministic_pipeline_report": "report.json"});
        let error = append_complete_options(
            partial_pair.as_object().unwrap(),
            &[
                (
                    "deterministic_pipeline_plan",
                    "--deterministic-pipeline-plan",
                ),
                (
                    "deterministic_pipeline_report",
                    "--deterministic-pipeline-report",
                ),
            ],
            "deterministic_pipeline_plan and deterministic_pipeline_report",
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("must be supplied together")
        );
    }

    #[test]
    fn native_ai_review_artifact_options_forward_and_require_complete_groups() {
        let complete = json!({
            "generated_schematic": "generated.kicad_sch",
            "deterministic_pipeline_plan": "plan.json",
            "deterministic_pipeline_report": "report.json",
            "native_kicad_erc_report": "native-erc.json",
            "native_kicad_erc_warning_policy": "warning-policy.json",
            "kicad_cli": "kicad-cli"
        });
        let mut command = vec!["verify-ai-quorum".to_string()];
        append_native_ai_review_options(
            complete.as_object().unwrap(),
            &[
                ("generated_schematic", "--generated-schematic"),
                (
                    "deterministic_pipeline_plan",
                    "--deterministic-pipeline-plan",
                ),
                (
                    "deterministic_pipeline_report",
                    "--deterministic-pipeline-report",
                ),
            ],
            "generated_schematic, deterministic_pipeline_plan, and deterministic_pipeline_report",
            &mut command,
        )
        .unwrap();
        assert_eq!(
            command,
            vec![
                "verify-ai-quorum",
                "--generated-schematic",
                "generated.kicad_sch",
                "--deterministic-pipeline-plan",
                "plan.json",
                "--deterministic-pipeline-report",
                "report.json",
                "--native-kicad-erc-report",
                "native-erc.json",
                "--native-kicad-erc-warning-policy",
                "warning-policy.json",
                "--kicad-cli",
                "kicad-cli"
            ]
        );

        let partial_native = json!({
            "generated_schematic": "generated.kicad_sch",
            "deterministic_pipeline_plan": "plan.json",
            "native_kicad_erc_report": "native-erc.json"
        });
        let error = append_native_ai_review_options(
            partial_native.as_object().unwrap(),
            &[
                ("generated_schematic", "--generated-schematic"),
                (
                    "deterministic_pipeline_plan",
                    "--deterministic-pipeline-plan",
                ),
                (
                    "deterministic_pipeline_report",
                    "--deterministic-pipeline-report",
                ),
            ],
            "generated_schematic, deterministic_pipeline_plan, and deterministic_pipeline_report",
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("must be supplied together")
        );

        let cli_without_native = json!({"kicad_cli": "kicad-cli"});
        let error = append_native_ai_review_options(
            cli_without_native.as_object().unwrap(),
            &[
                (
                    "deterministic_pipeline_plan",
                    "--deterministic-pipeline-plan",
                ),
                (
                    "deterministic_pipeline_report",
                    "--deterministic-pipeline-report",
                ),
            ],
            "deterministic_pipeline_plan and deterministic_pipeline_report",
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            error["detail"],
            "kicad_cli requires native_kicad_erc_report"
        );

        let policy_without_native = json!({
            "generated_schematic": "generated.kicad_sch",
            "deterministic_pipeline_plan": "plan.json",
            "deterministic_pipeline_report": "report.json",
            "native_kicad_erc_warning_policy": "warning-policy.json"
        });
        let error = append_native_ai_review_options(
            policy_without_native.as_object().unwrap(),
            &[
                ("generated_schematic", "--generated-schematic"),
                (
                    "deterministic_pipeline_plan",
                    "--deterministic-pipeline-plan",
                ),
                (
                    "deterministic_pipeline_report",
                    "--deterministic-pipeline-report",
                ),
            ],
            "generated_schematic, deterministic_pipeline_plan, and deterministic_pipeline_report",
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            error["detail"],
            "native_kicad_erc_warning_policy requires native_kicad_erc_report"
        );
    }

    #[test]
    fn live_schematic_binding_forwards_exact_cli_flag_and_rejects_artifacts() {
        let arguments = json!({"schematic": "live.kicad_sch"});
        let mut command = vec!["sign-ai-review".to_string()];
        append_live_schematic_option(arguments.as_object().unwrap(), &mut command).unwrap();
        assert_eq!(
            command,
            vec!["sign-ai-review", "--schematic", "live.kicad_sch"]
        );

        let mut verify_command = vec!["verify-ai-approval".to_string()];
        append_live_schematic_option(arguments.as_object().unwrap(), &mut verify_command).unwrap();
        assert_eq!(
            verify_command,
            vec!["verify-ai-approval", "--schematic", "live.kicad_sch"]
        );

        let conflicting = json!({
            "schematic": "live.kicad_sch",
            "generated_schematic": "generated.kicad_sch",
            "deterministic_pipeline_plan": "plan.json",
            "deterministic_pipeline_report": "report.json"
        });
        let error = append_live_schematic_option(conflicting.as_object().unwrap(), &mut Vec::new())
            .unwrap_err();
        assert_eq!(
            error["detail"],
            "schematic cannot be combined with generated/native AI review artifacts"
        );
    }

    #[test]
    fn ai_review_handlers_reject_partial_artifact_binding_before_dispatch() {
        let prepare = prepare_schematic_review(
            json!({
                "input": "generated.kicad_sch",
                "electrical_review": "electrical.json",
                "requirements": ["power"],
                "deterministic_pipeline_plan": "plan.json",
                "output": "request.json"
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            prepare["detail"]
                .as_str()
                .unwrap()
                .contains("must be supplied together")
        );

        let warning_policy_without_native = prepare_schematic_review(
            json!({
                "input": "generated.kicad_sch",
                "electrical_review": "electrical.json",
                "requirements": ["power"],
                "deterministic_pipeline_plan": "plan.json",
                "deterministic_pipeline_report": "report.json",
                "native_kicad_erc_warning_policy": "warning-policy.json",
                "output": "request.json"
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert_eq!(
            warning_policy_without_native["detail"],
            "native_kicad_erc_warning_policy requires native_kicad_erc_report"
        );

        let sign = sign_schematic_approval(
            json!({
                "request": "request.json",
                "response": "response.json",
                "private_key": "private.key",
                "signer_id": "reviewer",
                "generated_schematic": "generated.kicad_sch",
                "output": "approval.json"
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            sign["detail"]
                .as_str()
                .unwrap()
                .contains("must be supplied together")
        );

        let sign_live_conflict = sign_schematic_approval(
            json!({
                "request": "request.json",
                "response": "response.json",
                "private_key": "private.key",
                "signer_id": "reviewer",
                "output": "approval.json",
                "schematic": "live.kicad_sch",
                "generated_schematic": "generated.kicad_sch"
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert_eq!(
            sign_live_conflict["detail"],
            "schematic cannot be combined with generated/native AI review artifacts"
        );

        let verify = verify_schematic_approval(
            json!({
                "approval": "approval.json",
                "request": "request.json",
                "response": "response.json",
                "public_key": "public.key",
                "deterministic_pipeline_report": "report.json"
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            verify["detail"]
                .as_str()
                .unwrap()
                .contains("must be supplied together")
        );

        let quorum = verify_schematic_approval_quorum(
            json!({
                "request": "request.json",
                "approvals": ["approval.json"],
                "responses": ["response.json"],
                "policy_pack": "policy-pack.json",
                "output": "quorum.json",
                "deterministic_pipeline_plan": "plan.json",
                "deterministic_pipeline_report": "report.json"
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            quorum["detail"]
                .as_str()
                .unwrap()
                .contains("must be supplied together")
        );

        let verify_live_conflict = verify_schematic_approval(
            json!({
                "approval": "approval.json",
                "request": "request.json",
                "response": "response.json",
                "public_key": "public.key",
                "schematic": "live.kicad_sch",
                "generated_schematic": "generated.kicad_sch"
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert_eq!(
            verify_live_conflict["detail"],
            "schematic cannot be combined with generated/native AI review artifacts"
        );

        let quorum_live_conflict = verify_schematic_approval_quorum(
            json!({
                "request": "request.json",
                "approvals": ["approval.json"],
                "responses": ["response.json"],
                "policy_pack": "policy-pack.json",
                "output": "quorum-live-conflict.json",
                "schematic": "live.kicad_sch",
                "native_kicad_erc_report": "native-erc.json"
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert_eq!(
            quorum_live_conflict["detail"],
            "schematic cannot be combined with generated/native AI review artifacts"
        );
    }

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
        assert_eq!(tools.len(), 171);
        let named = |name: &str| {
            tools
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("missing MCP tool {name}"))
        };
        assert_eq!(
            named("run_native_kicad_drc")["inputSchema"]["required"],
            json!(["input", "output"])
        );
        assert_eq!(
            named("run_native_kicad_drc")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("verify_native_kicad_drc_report")["inputSchema"]["required"],
            json!(["input", "report"])
        );
        assert_eq!(
            named("verify_native_kicad_drc_report")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("verify_native_kicad_drc_report")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("verify_native_kicad_drc_report")["annotations"]["readOnlyHint"],
            true
        );
        assert_eq!(
            named("verify_native_kicad_drc_report")["annotations"]["destructiveHint"],
            false
        );
        assert_eq!(
            named("verify_native_kicad_erc_report")["inputSchema"]["required"],
            json!(["input", "retained_report"])
        );
        assert_eq!(
            named("verify_native_kicad_erc_report")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("verify_native_kicad_erc_report")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("verify_native_kicad_erc_report")["annotations"]["readOnlyHint"],
            true
        );
        assert_eq!(
            named("verify_native_kicad_erc_report")["annotations"]["destructiveHint"],
            false
        );
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
            named(
                "verify_remote_approval_registry_history_receipt_quorum_log_checkpoint_witnesses"
            )["inputSchema"]["properties"]["minimum_witnesses"]["minimum"],
            2
        );
        assert_eq!(
            named("witness_remote_approval_registry_history_receipt_quorum_log_checkpoint")["execution"]
                ["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "verify_remote_approval_registry_history_receipt_quorum_log_checkpoint_witnesses"
            )["inputSchema"]["oneOf"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            named(
                "export_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_public_key"
            )["annotations"]["readOnlyHint"],
            true
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
            named("analyze_kicad")["inputSchema"]["properties"]["physical_profile"]["type"],
            "string"
        );
        assert_eq!(
            named("check_schematic")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("check_schematic")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("check_schematic")["inputSchema"]["properties"]["junit_output"]["type"],
            "string"
        );
        assert_eq!(
            named("check_schematic")["inputSchema"]["not"]["required"],
            json!(["policy", "policy_pack"])
        );
        assert_eq!(
            named("check_circuit_spec")["inputSchema"]["required"],
            json!(["input", "output"])
        );
        assert_eq!(
            named("check_circuit_spec")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("write_circuit_spec_kicad_schematic")["inputSchema"]["required"],
            json!(["input", "output"])
        );
        assert_eq!(
            named("write_circuit_spec_kicad_schematic")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("write_circuit_spec_kicad_schematic")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("write_circuit_spec_kicad_schematic")["annotations"]["readOnlyHint"],
            false
        );
        assert_eq!(
            named("write_circuit_spec_kicad_schematic")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("write_circuit_spec_kicad_schematic")["annotations"]["openWorldHint"],
            false
        );
        assert_eq!(
            named("verify_circuit_kicad_handoff")["inputSchema"]["required"],
            json!(["circuit_spec", "schematic", "output"])
        );
        assert_eq!(
            named("verify_circuit_kicad_handoff")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("verify_circuit_kicad_handoff")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("verify_circuit_kicad_board_binding")["inputSchema"]["required"],
            json!(["circuit_spec", "schematic", "board", "output"])
        );
        assert_eq!(
            named("verify_circuit_kicad_board_binding")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("verify_circuit_kicad_board_binding")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("pipeline_verify")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("pipeline_verify")["inputSchema"]["properties"]["factory_receipt"]["type"],
            "string"
        );
        assert_eq!(
            named("pipeline_verify")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("run_deterministic_pipeline")["inputSchema"]["required"],
            json!(["plan", "output"])
        );
        assert_eq!(
            named("run_deterministic_pipeline")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("run_deterministic_pipeline")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("run_deterministic_pipeline")["annotations"]["readOnlyHint"],
            false
        );
        assert_eq!(
            named("run_deterministic_pipeline")["annotations"]["destructiveHint"],
            true
        );
        let fabrication = named("verify_fabrication_authorization");
        assert_eq!(
            fabrication["inputSchema"]["required"],
            json!([
                "plan",
                "retained_report",
                "manufacturing_package",
                "factory_receipt",
                "policy_pack",
                "approvals",
                "output"
            ])
        );
        assert_eq!(fabrication["inputSchema"]["additionalProperties"], false);
        assert_eq!(
            fabrication["inputSchema"]["properties"]["approvals"]["minItems"],
            1
        );
        assert_eq!(
            fabrication["inputSchema"]["properties"]["approvals"]["maxItems"],
            100
        );
        assert_eq!(
            fabrication["inputSchema"]["properties"]["approvals"]["items"]["minLength"],
            1
        );
        assert_eq!(
            fabrication["inputSchema"]["properties"]["approvals"]["items"]["maxLength"],
            4096
        );
        assert_eq!(
            fabrication["inputSchema"]["properties"]["require_authorized"]["default"],
            false
        );
        assert_eq!(fabrication["execution"]["taskSupport"], "optional");
        assert_eq!(fabrication["annotations"]["readOnlyHint"], false);
        assert_eq!(fabrication["annotations"]["destructiveHint"], true);
        assert_eq!(fabrication["annotations"]["idempotentHint"], true);
        assert_eq!(fabrication["annotations"]["openWorldHint"], false);
        let fabrication_properties = fabrication["inputSchema"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            fabrication_properties,
            BTreeSet::from([
                "plan",
                "retained_report",
                "manufacturing_package",
                "factory_receipt",
                "policy_pack",
                "approvals",
                "output",
                "require_authorized",
            ])
        );
        assert!(
            tools
                .iter()
                .all(|tool| tool["name"] != "sign_fabrication_approval")
        );
        assert_eq!(
            named("compile_deterministic_pipeline_plan")["inputSchema"]["required"],
            json!(["intent", "output"])
        );
        assert_eq!(
            named("compile_deterministic_pipeline_plan")["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            named("compile_deterministic_pipeline_plan")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("compile_deterministic_pipeline_plan")["annotations"]["readOnlyHint"],
            false
        );
        assert_eq!(
            named("compile_deterministic_pipeline_plan")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("compile_deterministic_pipeline_plan")["annotations"]["openWorldHint"],
            false
        );
        assert_eq!(
            named("run_native_kicad_erc")["inputSchema"]["properties"]["kicad_cli"]["type"],
            "string"
        );
        assert_eq!(
            named("run_native_kicad_erc")["inputSchema"]["properties"]["warning_policy"]["type"],
            "string"
        );
        assert_eq!(
            named("run_native_kicad_erc")["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            named("run_native_kicad_erc")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("route_kicad")["inputSchema"]["properties"]["physical_profile"]["type"],
            "string"
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
            named("prepare_schematic_review")["inputSchema"]["properties"]["deterministic_pipeline_plan"]
                ["type"],
            "string"
        );
        assert_eq!(
            named("prepare_schematic_review")["inputSchema"]["properties"]["native_kicad_erc_warning_policy"]
                ["type"],
            "string"
        );
        assert_eq!(
            named("prepare_schematic_review")["inputSchema"]["allOf"][0]["oneOf"][0]["required"][1],
            "deterministic_pipeline_report"
        );
        assert_eq!(
            named("sign_schematic_approval")["inputSchema"]["properties"]["session"]["type"],
            "string"
        );
        assert_eq!(
            named("sign_schematic_approval")["inputSchema"]["properties"]["generated_schematic"]["type"],
            "string"
        );
        assert_eq!(
            named("sign_schematic_approval")["inputSchema"]["properties"]["schematic"]["type"],
            "string"
        );
        assert_eq!(
            named("sign_schematic_approval")["inputSchema"]["allOf"][0]["oneOf"][3]["required"][0],
            "schematic"
        );
        assert_eq!(
            named("sign_schematic_approval")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("verify_schematic_approval")["inputSchema"]["allOf"][0]["oneOf"][0]["required"]
                [2],
            "deterministic_pipeline_report"
        );
        assert_eq!(
            named("verify_schematic_approval")["inputSchema"]["properties"]["schematic"]["type"],
            "string"
        );
        assert_eq!(
            named("verify_schematic_approval")["inputSchema"]["allOf"][0]["oneOf"][3]["required"]
                [0],
            "schematic"
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
            named("verify_schematic_approval_quorum")["inputSchema"]["properties"]["deterministic_pipeline_report"]
                ["type"],
            "string"
        );
        assert_eq!(
            named("verify_schematic_approval_quorum")["inputSchema"]["allOf"][0]["oneOf"][0]["required"]
                [0],
            "generated_schematic"
        );
        assert_eq!(
            named("verify_schematic_approval_quorum")["inputSchema"]["properties"]["schematic"]["type"],
            "string"
        );
        assert_eq!(
            named("verify_schematic_approval_quorum")["inputSchema"]["allOf"][0]["oneOf"][3]["required"]
                [0],
            "schematic"
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
            named("append_approval_transparency_log")["inputSchema"]["properties"]["kind"]["enum"]
                [7],
            "remote-factory-release-registry-history-checkpoint-witness-receipt"
        );
        assert_eq!(
            named("append_approval_transparency_log")["inputSchema"]["properties"]["kind"]["enum"]
                [8],
            "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt"
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
            named("append_verified_remote_factory_release_registry_history_witness_receipt")["inputSchema"]
                ["required"][2],
            "history"
        );
        assert_eq!(
            named("append_verified_remote_factory_release_registry_history_witness_receipt")["inputSchema"]
                ["oneOf"][1]["required"][0],
            "witness_key_trust_state"
        );
        assert_eq!(
            named("append_verified_remote_factory_release_registry_history_witness_receipt")["annotations"]
                ["destructiveHint"],
            true
        );
        assert_eq!(
            named(
                "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt"
            )["inputSchema"]["required"][2],
            "quorum_report"
        );
        assert_eq!(
            named(
                "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt"
            )["inputSchema"]["oneOf"][1]["required"][0],
            "witness_trust_state"
        );
        assert_eq!(
            named(
                "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum"
            )["inputSchema"]["properties"]["minimum_witnesses"]["minimum"],
            2
        );
        assert_eq!(
            named(
                "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum"
            )["inputSchema"]["required"][2],
            "quorum_report"
        );
        assert_eq!(
            named(
                "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum"
            )["inputSchema"]["oneOf"][1]["required"][0],
            "witness_trust_states"
        );
        assert_eq!(
            named(
                "append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("append_verified_remote_factory_release_registry_history_witness_receipt_quorum")
                ["inputSchema"]["properties"]["minimum_witnesses"]["minimum"],
            2
        );
        assert_eq!(
            named("append_verified_remote_factory_release_registry_history_witness_receipt_quorum")
                ["inputSchema"]["required"][2],
            "history"
        );
        assert_eq!(
            named("append_verified_remote_factory_release_registry_history_witness_receipt_quorum")
                ["inputSchema"]["oneOf"][1]["required"][0],
            "witness_key_trust_states"
        );
        assert_eq!(
            named("append_verified_remote_factory_release_registry_history_witness_receipt_quorum")
                ["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("sign_quorum_bound_factory_release_receipt_transparency_log")["inputSchema"]["required"],
            json!(["log", "quorum_report", "private_key", "signer_id", "output"])
        );
        assert_eq!(
            named("sign_quorum_bound_factory_release_receipt_transparency_log")["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("sign_quorum_bound_factory_release_receipt_transparency_log")["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("sign_quorum_bound_factory_checkpoint_witness_receipt_transparency_log")["inputSchema"]
                ["required"],
            json!(["log", "quorum_report", "private_key", "signer_id", "output"])
        );
        assert_eq!(
            named("sign_quorum_bound_factory_checkpoint_witness_receipt_transparency_log")["execution"]
                ["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("sign_quorum_bound_factory_checkpoint_witness_receipt_transparency_log")["annotations"]
                ["destructiveHint"],
            true
        );
        assert_eq!(
            named(
                "sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint"
            )["inputSchema"]["required"],
            json!(["log", "quorum_report", "private_key", "signer_id", "output"])
        );
        assert_eq!(
            named(
                "sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint"
            )["inputSchema"]["required"],
            json!(["log", "quorum_report", "checkpoint", "public_key", "output"])
        );
        assert_eq!(
            named(
                "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint"
            )["inputSchema"]["required"],
            json!([
                "log",
                "quorum_report",
                "checkpoint",
                "checkpoint_public_key",
                "private_key",
                "witness_id",
                "output"
            ])
        );
        assert_eq!(
            named(
                "witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses"
            )["inputSchema"]["required"],
            json!([
                "log",
                "quorum_report",
                "checkpoint",
                "checkpoint_public_key",
                "witnesses",
                "witness_public_keys",
                "minimum_witnesses",
                "output"
            ])
        );
        assert_eq!(
            named(
                "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses"
            )["inputSchema"]["properties"]["minimum_witnesses"]["minimum"],
            2
        );
        assert_eq!(
            named(
                "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses"
            )["annotations"]["destructiveHint"],
            true
        );
        assert_eq!(
            named("sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint")["inputSchema"]
                ["required"],
            json!(["log", "quorum_report", "private_key", "signer_id", "output"])
        );
        assert_eq!(
            named("sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint")["execution"]
                ["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named("verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint")["inputSchema"]
                ["required"],
            json!(["log", "quorum_report", "checkpoint", "public_key", "output"])
        );
        assert_eq!(
            named("verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint")["annotations"]
                ["destructiveHint"],
            true
        );
        assert_eq!(
            named("witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint")
                ["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses"
            )["inputSchema"]["properties"]["minimum_witnesses"]["minimum"],
            2
        );
        assert_eq!(
            named(
                "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses"
            )["inputSchema"]["required"],
            json!([
                "log",
                "quorum_report",
                "checkpoint",
                "checkpoint_public_key",
                "witnesses",
                "minimum_witnesses",
                "output"
            ])
        );
        assert_eq!(
            named(
                "verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses"
            )["inputSchema"]["oneOf"][1]["required"][0],
            "witness_trust_states"
        );
        assert_eq!(
            named(
                "sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation"
            )["inputSchema"]["properties"]["rotated_at_unix"]["minimum"],
            0
        );
        assert_eq!(
            named(
                "apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation"
            )["execution"]["taskSupport"],
            "forbidden"
        );
        assert_eq!(
            named(
                "export_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_public_key"
            )["annotations"]["readOnlyHint"],
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
    fn new_pipeline_tools_reject_unknown_empty_and_wrong_typed_arguments() {
        let mut server = ready_server();
        for (id, name, arguments) in [
            (
                10,
                "check_schematic",
                json!({"input": "input.kicad_sch", "output": "review.json", "extra": true}),
            ),
            (
                11,
                "check_circuit_spec",
                json!({"input": "", "output": "check.json"}),
            ),
            (
                17,
                "write_circuit_spec_kicad_schematic",
                json!({"input": "input.json", "output": "design.kicad_sch", "extra": true}),
            ),
            (
                18,
                "write_circuit_spec_kicad_schematic",
                json!({"input": "", "output": "design.kicad_sch"}),
            ),
            (
                13,
                "check_schematic",
                json!({
                    "input": "input.kicad_sch",
                    "output": "review.json",
                    "policy": "policy.json",
                    "policy_pack": "policy-pack.json"
                }),
            ),
            (
                12,
                "pipeline_verify",
                json!({
                    "schematic": "schematic.kicad_sch",
                    "electrical_review": "review.json",
                    "board": "board.kicad_pcb",
                    "analysis_manifest": "run.json",
                    "analysis_checks": "checks.json",
                    "quality": "quality.json",
                    "manufacturing_package": "manufacturing.zip",
                    "firmware_manifest": "firmware.json",
                    "output": "pipeline.json",
                    "require_factory": "yes"
                }),
            ),
            (
                16,
                "run_deterministic_pipeline",
                json!({
                    "plan": "pipeline-plan.json",
                    "output": "pipeline-report.json",
                    "require_approved": "yes"
                }),
            ),
            (
                19,
                "compile_deterministic_pipeline_plan",
                json!({
                    "intent": "pipeline-intent.json",
                    "output": "pipeline-plan.json",
                    "extra": true
                }),
            ),
            (
                20,
                "compile_deterministic_pipeline_plan",
                json!({"intent": "", "output": "pipeline-plan.json"}),
            ),
            (
                14,
                "verify_circuit_kicad_handoff",
                json!({
                    "circuit_spec": "circuit.json",
                    "schematic": "design.kicad_sch",
                    "output": "handoff.json",
                    "require_approved": "yes"
                }),
            ),
            (
                15,
                "verify_circuit_kicad_board_binding",
                json!({
                    "circuit_spec": "circuit.json",
                    "schematic": "design.kicad_sch",
                    "board": "design.kicad_pcb",
                    "output": "binding.json",
                    "require_approved": "yes"
                }),
            ),
        ] {
            let response = server
                .handle_message(request(
                    id,
                    "tools/call",
                    json!({"name": name, "arguments": arguments}),
                ))
                .unwrap();
            assert_eq!(response["error"]["code"], -32602, "{name}: {response}");
        }
    }

    #[test]
    fn fabrication_authorization_rejects_closed_argument_and_path_violations() {
        fn valid_arguments() -> Map<String, Value> {
            json!({
                "plan": "plan.json",
                "retained_report": "pipeline-report.json",
                "manufacturing_package": "manufacturing.zip",
                "factory_receipt": "factory-receipt.json",
                "policy_pack": "policy-pack.json",
                "approvals": ["approval-a.json", "approval-b.json"],
                "output": "authorization.json"
            })
            .as_object()
            .unwrap()
            .clone()
        }

        let mut unknown = valid_arguments();
        unknown.insert("private_key".into(), json!("private.key"));
        unknown.insert("scope".into(), json!({"quantity": 10}));
        unknown.insert("evaluated_at_unix".into(), json!(1));
        unknown.insert("timeout_seconds".into(), json!(30));
        unknown.insert("approval_data".into(), json!({}));

        let mut wrong_plan_type = valid_arguments();
        wrong_plan_type.insert("plan".into(), json!(7));
        let mut empty_plan = valid_arguments();
        empty_plan.insert("plan".into(), json!(""));
        let mut long_plan = valid_arguments();
        long_plan.insert("plan".into(), json!("x".repeat(4097)));
        let mut controlled_plan = valid_arguments();
        controlled_plan.insert("plan".into(), json!("plan\n.json"));
        let mut wrong_approvals_type = valid_arguments();
        wrong_approvals_type.insert("approvals".into(), json!("approval.json"));
        let mut empty_approvals = valid_arguments();
        empty_approvals.insert("approvals".into(), json!([]));
        let mut excessive_approvals = valid_arguments();
        excessive_approvals.insert("approvals".into(), json!(vec!["approval.json"; 101]));
        let mut empty_approval = valid_arguments();
        empty_approval.insert("approvals".into(), json!([""]));
        let mut long_approval = valid_arguments();
        long_approval.insert("approvals".into(), json!(["x".repeat(4097)]));
        let mut nul_approval = valid_arguments();
        nul_approval.insert("approvals".into(), json!(["approval\0.json"]));
        let mut wrong_gate_type = valid_arguments();
        wrong_gate_type.insert("require_authorized".into(), json!("yes"));
        let mut missing_output = valid_arguments();
        missing_output.remove("output");

        for (label, arguments) in [
            ("unknown", unknown),
            ("wrong plan type", wrong_plan_type),
            ("empty plan", empty_plan),
            ("long plan", long_plan),
            ("controlled plan", controlled_plan),
            ("wrong approvals type", wrong_approvals_type),
            ("empty approvals", empty_approvals),
            ("excessive approvals", excessive_approvals),
            ("empty approval", empty_approval),
            ("long approval", long_approval),
            ("NUL approval", nul_approval),
            ("wrong require gate type", wrong_gate_type),
            ("missing output", missing_output),
        ] {
            assert!(
                verify_fabrication_authorization_tool(arguments, None).is_err(),
                "{label} was accepted"
            );
        }
    }

    #[test]
    fn successful_tool_process_requires_a_retained_json_artifact() {
        let execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: String::new(),
        };
        let failed = require_retained_json(execution, &Value::Null, "review");
        assert!(!failed.success);
        assert_eq!(failed.exit_code, Some(0));
        assert!(failed.stderr.contains("review"));

        let execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: String::new(),
        };
        let retained = require_retained_json(execution, &json!({"approved": true}), "review");
        assert!(retained.success);
        assert!(retained.stderr.is_empty());

        let directory = tempfile::tempdir().unwrap();
        let empty = directory.path().join("empty.xml");
        std::fs::write(&empty, []).unwrap();
        let execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: String::new(),
        };
        let failed = require_retained_file(execution, &empty, "JUnit");
        assert!(!failed.success);
        assert!(failed.stderr.contains("JUnit"));

        let present = directory.path().join("present.xml");
        std::fs::write(&present, b"<testsuite/>").unwrap();
        let execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: String::new(),
        };
        let retained = require_retained_file(execution, &present, "JUnit");
        assert!(retained.success);
        assert!(retained.stderr.is_empty());

        let report = directory.path().join("handoff.json");
        std::fs::write(&report, br#"{"approved":true}"#).unwrap();
        let untrusted = Execution {
            success: false,
            exit_code: Some(1),
            stdout: Vec::new(),
            stderr: "child failed before retaining a report".into(),
        };
        assert_eq!(trusted_echoed_json(&untrusted, &report), Value::Null);
        let trusted = Execution {
            success: false,
            exit_code: Some(1),
            stdout: br#"{"approved":true}"#.to_vec(),
            stderr: "required approval rejected after retaining a report".into(),
        };
        assert_eq!(
            trusted_echoed_json(&trusted, &report),
            json!({"approved": true})
        );
        std::fs::write(&report, br#"{"approved":false}"#).unwrap();
        assert_eq!(trusted_echoed_json(&trusted, &report), Value::Null);
    }

    #[test]
    fn writer_summary_is_bounded_and_identity_checked() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("generated.kicad_sch");
        let contents = b"(kicad_sch\n  (version 20231120)\n)\n";
        std::fs::write(&output, contents).unwrap();
        let execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: String::new(),
        };
        let (retained, summary) = require_retained_circuit_kicad_schematic(execution, &output);
        assert!(retained.success);
        assert_eq!(summary["path"], output.display().to_string());
        assert_eq!(summary["bytes"], contents.len() as u64);
        assert_eq!(summary["sha256"], sha256_hex(contents));
        assert!(summary.get("content").is_none());

        let oversized = directory.path().join("oversized.kicad_sch");
        std::fs::File::create(&oversized)
            .unwrap()
            .set_len(MAX_CIRCUIT_KICAD_SCHEMATIC_BYTES + 1)
            .unwrap();
        let execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: String::new(),
        };
        let (failed, summary) = require_retained_circuit_kicad_schematic(execution, &oversized);
        assert!(!failed.success);
        assert!(failed.stderr.contains("not retained"));
        assert_eq!(summary, Value::Null);

        #[cfg(unix)]
        {
            let link = directory.path().join("linked.kicad_sch");
            std::os::unix::fs::symlink(&output, &link).unwrap();
            let execution = Execution {
                success: true,
                exit_code: Some(0),
                stdout: Vec::new(),
                stderr: String::new(),
            };
            let (failed, summary) = require_retained_circuit_kicad_schematic(execution, &link);
            assert!(!failed.success);
            assert_eq!(summary, Value::Null);
        }
    }

    #[test]
    fn deterministic_pipeline_summary_is_digest_bound_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let report_path = directory.path().join("pipeline-report.json");
        let report = json!({
            "schema_version": 1,
            "approved": false,
            "plan_sha256": "a".repeat(64),
            "run_sha256": "b".repeat(64),
            "failures": ["pipeline rejected"]
        });
        let rendered = format!("{}\n", serde_json::to_string(&report).unwrap());
        std::fs::write(&report_path, rendered.as_bytes()).unwrap();
        let summary = json!({
            "schema_version": 1,
            "approved": false,
            "plan_sha256": "a".repeat(64),
            "run_sha256": "b".repeat(64),
            "failure_count": 1,
            "report_bytes": rendered.len(),
            "report_sha256": sha256_hex(rendered.as_bytes())
        });
        let execution = Execution {
            success: false,
            exit_code: Some(1),
            stdout: serde_json::to_vec(&summary).unwrap(),
            stderr: "required approval rejected after retaining a report".into(),
        };
        assert_eq!(
            trusted_deterministic_pipeline_summary(&execution, &report_path),
            summary
        );

        std::fs::write(&report_path, b"{}\n").unwrap();
        assert_eq!(
            trusted_deterministic_pipeline_summary(&execution, &report_path),
            Value::Null
        );
    }

    fn fabrication_authorization_report_fixture() -> (
        crate::fabrication_authorization::FabricationAuthorizationReport,
        Vec<u8>,
        Value,
    ) {
        use crate::fabrication_authorization::{
            FabricationApprovalDecision, FabricationAuthorizationEvidence,
            FabricationAuthorizationScope, FabricationFactoryReceiptEvidence,
            FabricationPipelineEvidence, FabricationPolicyPackEvidence, sign_fabrication_approval,
            verify_fabrication_authorization,
        };
        use crate::policy_pack::{FabricationAuthorizationPolicy, TrustedApprovalKey};
        use pcbex_kicad::ExactArtifactIdentity;

        fn identity(seed: char, bytes: u64) -> ExactArtifactIdentity {
            ExactArtifactIdentity {
                bytes,
                sha256: seed.to_string().repeat(64),
            }
        }

        let mut policy = crate::policy_pack::parse_policy_pack(include_str!(
            "../../../examples/acme-policy-pack.json"
        ))
        .unwrap();
        policy.fabrication_authorization_policy = Some(FabricationAuthorizationPolicy {
            minimum_approvals: 2,
            maximum_validity_seconds: 3_600,
            trusted_keys: vec![
                TrustedApprovalKey {
                    signer_id: "fabrication-a".into(),
                    public_key: hex::encode(
                        ed25519_dalek::SigningKey::from_bytes(&[41; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                },
                TrustedApprovalKey {
                    signer_id: "fabrication-b".into(),
                    public_key: hex::encode(
                        ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                },
            ],
        });
        crate::policy_pack::validate_policy_pack(&policy).unwrap();
        let evidence = FabricationAuthorizationEvidence {
            pipeline: FabricationPipelineEvidence {
                plan_source: identity('1', 100),
                plan_sha256: "2".repeat(64),
                retained_report: identity('3', 200),
                run_sha256: "4".repeat(64),
            },
            manufacturing_package: identity('5', 300),
            factory_receipt: FabricationFactoryReceiptEvidence {
                receipt: identity('6', 400),
                provider: crate::factory::FactoryProvider::Generic,
                endpoint: "https://factory.example/quote".into(),
                quote_sha256: "7".repeat(64),
                quote_authenticity_verified: false,
            },
            policy_pack: FabricationPolicyPackEvidence {
                source: identity('8', 500),
                canonical_sha256: crate::policy_pack::policy_pack_sha256(&policy).unwrap(),
                id: policy.id.clone(),
                revision: policy.revision,
            },
        };
        let scope = FabricationAuthorizationScope {
            authorization_id: "fab-2026-001".into(),
            challenge: "9".repeat(64),
            quantity: 25,
            currency: "USD".into(),
            maximum_total_minor_units: 125_000,
            valid_from_unix: 1_000,
            expires_at_unix: 1_600,
        };
        let signed = [
            ("fabrication-a", [41; 32], "FAB-41"),
            ("fabrication-b", [42; 32], "FAB-42"),
        ]
        .into_iter()
        .map(|(signer_id, key, ticket)| {
            sign_fabrication_approval(
                &evidence,
                &policy,
                &scope,
                FabricationApprovalDecision::Approve,
                "Approved within the exact fabrication scope.",
                ticket,
                signer_id,
                &key,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
        let report = verify_fabrication_authorization(&evidence, &policy, &signed, 1_200).unwrap();
        let rendered = format!("{}\n", serde_json::to_string_pretty(&report).unwrap()).into_bytes();
        let summary = json!({
            "schema_version": report.schema_version,
            "status": report.status,
            "fabrication_authorized": report.fabrication_authorized,
            "authorization_id": report.scope.authorization_id,
            "challenge": report.scope.challenge,
            "quantity": report.scope.quantity,
            "currency": report.scope.currency,
            "maximum_total_minor_units": report.scope.maximum_total_minor_units,
            "valid_from_unix": report.scope.valid_from_unix,
            "expires_at_unix": report.scope.expires_at_unix,
            "evaluated_at_unix": report.evaluated_at_unix,
            "approvals": report.approvals,
            "rejections": report.rejections,
            "gate_failure_count": report.gate_failures.len(),
            "plan_sha256": report.evidence.pipeline.plan_sha256,
            "run_sha256": report.evidence.pipeline.run_sha256,
            "manufacturing_package_sha256": report.evidence.manufacturing_package.sha256,
            "factory_receipt_sha256": report.evidence.factory_receipt.receipt.sha256,
            "policy_pack_sha256": report.evidence.policy_pack.source.sha256,
            "quote_authenticity_verified": report.evidence.factory_receipt.quote_authenticity_verified,
            "challenge_one_time_use_enforced": report.challenge_one_time_use_enforced,
            "report_bytes": rendered.len(),
            "report_sha256": sha256_hex(&rendered)
        });
        (report, rendered, summary)
    }

    #[test]
    fn fabrication_authorization_summary_is_strict_and_semantically_authenticated() {
        fn execution(summary: &Value, success: bool) -> Execution {
            Execution {
                success,
                exit_code: Some(if success { 0 } else { 1 }),
                stdout: serde_json::to_vec(summary).unwrap(),
                stderr: if success {
                    String::new()
                } else {
                    "fabrication authorization quorum did not authorize the exact scope".into()
                },
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let report_path = directory.path().join("fabrication-authorization.json");
        let (report, rendered, summary) = fabrication_authorization_report_fixture();
        std::fs::write(&report_path, &rendered).unwrap();

        assert_eq!(
            trusted_fabrication_authorization_summary(
                &execution(&summary, true),
                &report_path,
                None,
            ),
            summary
        );
        // The child emits and retains the summary before require_authorized
        // turns a truthful not-authorized outcome into a nonzero exit.
        assert_eq!(
            trusted_fabrication_authorization_summary(
                &execution(&summary, false),
                &report_path,
                None,
            ),
            summary
        );

        let mut mutations = Vec::new();
        let mut unknown = summary.clone();
        unknown["unexpected"] = json!(true);
        mutations.push(("unknown field", unknown));
        let mut missing = summary.clone();
        missing.as_object_mut().unwrap().remove("challenge");
        mutations.push(("missing field", missing));
        let mut wrong_type = summary.clone();
        wrong_type["quantity"] = json!("25");
        mutations.push(("wrong type", wrong_type));
        let mut out_of_range = summary.clone();
        out_of_range["quantity"] = json!(0);
        mutations.push(("range", out_of_range));
        let mut digest = summary.clone();
        digest["plan_sha256"] = json!("A".repeat(64));
        mutations.push(("digest", digest));
        let mut status = summary.clone();
        status["status"] = json!("not_authorized");
        mutations.push(("status", status));
        let mut count = summary.clone();
        count["approvals"] = json!(1);
        mutations.push(("count", count));
        let mut gate_count = summary.clone();
        gate_count["gate_failure_count"] = json!(1);
        mutations.push(("gate count", gate_count));
        let mut quote_constant = summary.clone();
        quote_constant["quote_authenticity_verified"] = json!(true);
        mutations.push(("quote constant", quote_constant));
        let mut challenge_constant = summary.clone();
        challenge_constant["challenge_one_time_use_enforced"] = json!(true);
        mutations.push(("challenge constant", challenge_constant));
        let mut bytes = summary.clone();
        bytes["report_bytes"] = json!(rendered.len() + 1);
        mutations.push(("report bytes", bytes));
        let mut report_digest = summary.clone();
        report_digest["report_sha256"] = json!("f".repeat(64));
        mutations.push(("report digest", report_digest));
        let mut nested_digest = summary.clone();
        nested_digest["factory_receipt_sha256"] = json!("e".repeat(64));
        mutations.push(("nested evidence", nested_digest));

        for (label, mutation) in mutations {
            assert_eq!(
                trusted_fabrication_authorization_summary(
                    &execution(&mutation, true),
                    &report_path,
                    None,
                ),
                Value::Null,
                "{label} mutation was trusted"
            );
        }

        let compact = serde_json::to_string(&summary).unwrap();
        let duplicate = format!("{{\"status\":\"fabrication_authorized\",{}", &compact[1..]);
        let duplicate_execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: duplicate.into_bytes(),
            stderr: String::new(),
        };
        assert_eq!(
            trusted_fabrication_authorization_summary(&duplicate_execution, &report_path, None,),
            Value::Null
        );
        let oversized_execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: vec![b' '; MAX_MCP_PROCESS_MESSAGE_BYTES + 1],
            stderr: String::new(),
        };
        assert_eq!(
            trusted_fabrication_authorization_summary(&oversized_execution, &report_path, None,),
            Value::Null
        );

        let mut forged = serde_json::to_value(&report).unwrap();
        forged["evidence"]["manufacturing_package"]["sha256"] = json!("e".repeat(64));
        let forged_rendered =
            format!("{}\n", serde_json::to_string_pretty(&forged).unwrap()).into_bytes();
        std::fs::write(&report_path, &forged_rendered).unwrap();
        let mut forged_summary = summary.clone();
        forged_summary["manufacturing_package_sha256"] = json!("e".repeat(64));
        forged_summary["report_bytes"] = json!(forged_rendered.len());
        forged_summary["report_sha256"] = json!(sha256_hex(&forged_rendered));
        assert_eq!(
            trusted_fabrication_authorization_summary(
                &execution(&forged_summary, true),
                &report_path,
                None,
            ),
            Value::Null
        );

        std::fs::remove_file(&report_path).unwrap();
        assert_eq!(
            trusted_fabrication_authorization_summary(
                &execution(&summary, true),
                &report_path,
                None,
            ),
            Value::Null
        );
    }

    #[test]
    fn fabrication_authorization_authentication_observes_cancellation_boundaries() {
        fn execution(summary: &Value) -> Execution {
            Execution {
                success: true,
                exit_code: Some(0),
                stdout: serde_json::to_vec(summary).unwrap(),
                stderr: String::new(),
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let report_path = directory.path().join("fabrication-authorization.json");
        let (_, rendered, summary) = fabrication_authorization_report_fixture();
        std::fs::write(&report_path, &rendered).unwrap();
        let output = report_path.display().to_string();

        let sync = authenticated_fabrication_authorization_result(
            execution(&summary),
            output.clone(),
            None,
        )
        .unwrap();
        assert_eq!(sync["ok"], true);
        assert_eq!(sync["report_summary"], summary);

        let pre_cancelled = AtomicBool::new(true);
        let error = authenticated_fabrication_authorization_result(
            execution(&summary),
            output.clone(),
            Some(&pre_cancelled),
        )
        .unwrap_err();
        assert_eq!(error["detail"], "task execution cancelled");

        let during_read = Arc::new(AtomicBool::new(false));
        let cancel_during_read = Arc::clone(&during_read);
        set_after_fabrication_report_read_hook(move || {
            cancel_during_read.store(true, Ordering::SeqCst);
        });
        let error = authenticated_fabrication_authorization_result(
            execution(&summary),
            output.clone(),
            Some(&during_read),
        )
        .unwrap_err();
        assert_eq!(error["detail"], "task execution cancelled");

        let after_summary = Arc::new(AtomicBool::new(false));
        let cancel_after_summary = Arc::clone(&after_summary);
        set_after_fabrication_summary_hook(move || {
            cancel_after_summary.store(true, Ordering::SeqCst);
        });
        let error = authenticated_fabrication_authorization_result(
            execution(&summary),
            output,
            Some(&after_summary),
        )
        .unwrap_err();
        assert_eq!(error["detail"], "task execution cancelled");
        assert_eq!(std::fs::read(&report_path).unwrap(), rendered);
    }

    #[test]
    fn deterministic_pipeline_plan_summary_authenticates_intent_and_plan() {
        let directory = tempfile::tempdir().unwrap();
        let intent_path = directory.path().join("pipeline-intent.json");
        let plan_path = directory.path().join("pipeline-plan.json");
        let intent = b"{\"schema_version\":1}\n";
        let plan = b"{\"schema_version\":1}\n";
        std::fs::write(&intent_path, intent).unwrap();
        std::fs::write(&plan_path, plan).unwrap();
        let summary = json!({
            "schema_version": 1,
            "intent_source_bytes": intent.len(),
            "intent_source_sha256": sha256_hex(intent),
            "plan_source_bytes": plan.len(),
            "plan_source_sha256": sha256_hex(plan)
        });
        let execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: serde_json::to_vec(&summary).unwrap(),
            stderr: String::new(),
        };
        assert_eq!(
            trusted_deterministic_pipeline_plan_summary(&execution, &intent_path, &plan_path),
            summary
        );

        std::fs::write(&intent_path, b"{\"schema_version\":2}\n").unwrap();
        assert_eq!(
            trusted_deterministic_pipeline_plan_summary(&execution, &intent_path, &plan_path),
            Value::Null
        );
        std::fs::write(&intent_path, intent).unwrap();
        let invalid_plan = b"not-json\n";
        std::fs::write(&plan_path, invalid_plan).unwrap();
        let mut invalid_plan_summary = summary.clone();
        invalid_plan_summary["plan_source_bytes"] = Value::from(invalid_plan.len());
        invalid_plan_summary["plan_source_sha256"] = Value::from(sha256_hex(invalid_plan));
        let invalid_plan_execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: serde_json::to_vec(&invalid_plan_summary).unwrap(),
            stderr: String::new(),
        };
        assert_eq!(
            trusted_deterministic_pipeline_plan_summary(
                &invalid_plan_execution,
                &intent_path,
                &plan_path,
            ),
            Value::Null
        );

        let wrong_schema_plan = b"{\"schema_version\":2}\n";
        std::fs::write(&plan_path, wrong_schema_plan).unwrap();
        let mut wrong_schema_summary = summary.clone();
        wrong_schema_summary["plan_source_bytes"] = Value::from(wrong_schema_plan.len());
        wrong_schema_summary["plan_source_sha256"] = Value::from(sha256_hex(wrong_schema_plan));
        let wrong_schema_execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: serde_json::to_vec(&wrong_schema_summary).unwrap(),
            stderr: String::new(),
        };
        assert_eq!(
            trusted_deterministic_pipeline_plan_summary(
                &wrong_schema_execution,
                &intent_path,
                &plan_path,
            ),
            Value::Null
        );

        let mut malformed = summary;
        malformed["unexpected"] = Value::Bool(true);
        let execution = Execution {
            stdout: serde_json::to_vec(&malformed).unwrap(),
            ..execution
        };
        std::fs::write(&plan_path, plan).unwrap();
        assert_eq!(
            trusted_deterministic_pipeline_plan_summary(&execution, &intent_path, &plan_path),
            Value::Null
        );
    }

    #[test]
    fn native_kicad_erc_summary_is_digest_bound_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let report_path = directory.path().join("native-erc.json");
        let report = json!({
            "schema_version": 1,
            "engine": "pcbex",
            "engine_version": "1.424.0",
            "kicad_version": "9.0.0",
            "source": {"bytes": 1, "sha256": "a".repeat(64)},
            "invocation": {
                "command": "sch erc",
                "format": "json",
                "units": "mm",
                "severity": "error",
                "exit_code_violations": true
            },
            "ignored_checks": [],
            "findings": [],
            "error_count": 0,
            "approved": true,
            "run_sha256": "b".repeat(64)
        });
        let rendered = format!("{}\n", serde_json::to_string(&report).unwrap());
        std::fs::write(&report_path, rendered.as_bytes()).unwrap();
        let summary = json!({
            "schema_version": 1,
            "approved": true,
            "error_count": 0,
            "run_sha256": "b".repeat(64),
            "report_bytes": rendered.len(),
            "report_sha256": sha256_hex(rendered.as_bytes())
        });
        let execution = Execution {
            success: true,
            exit_code: Some(0),
            stdout: serde_json::to_vec(&summary).unwrap(),
            stderr: String::new(),
        };
        assert_eq!(
            trusted_native_kicad_erc_summary(&execution, &report_path),
            summary
        );

        std::fs::write(&report_path, b"{}\n").unwrap();
        assert_eq!(
            trusted_native_kicad_erc_summary(&execution, &report_path),
            Value::Null
        );
    }

    #[test]
    fn native_kicad_erc_warning_summary_is_strictly_policy_bound() {
        let directory = tempfile::tempdir().unwrap();
        let report_path = directory.path().join("native-erc-warning.json");
        let policy_source = br#"{"schema_version":1,"maximum_total_warnings":1}"#;
        let policy_sha256 = sha256_hex(policy_source);
        let policy_source_sha256 = sha256_hex(policy_source);
        let report = json!({
            "schema_version": 2,
            "engine": "pcbex",
            "engine_version": "1.426.0",
            "kicad_version": "10.0.5",
            "source": {"bytes": 1, "sha256": "a".repeat(64)},
            "invocation": {
                "command": "sch erc",
                "format": "json",
                "units": "mm",
                "severity": "error,warning",
                "exit_code_violations": true
            },
            "ignored_checks": [],
            "findings": [{"severity": "warning"}],
            "error_count": 0,
            "warning_count": 1,
            "policy_failures": [],
            "approved": true,
            "run_sha256": "b".repeat(64),
            "warning_policy": {
                "source": {
                    "bytes": policy_source.len(),
                    "sha256": policy_source_sha256
                },
                "policy_sha256": policy_sha256,
                "policy": {"schema_version": 1}
            }
        });
        let rendered = format!("{}\n", serde_json::to_string(&report).unwrap());
        std::fs::write(&report_path, rendered.as_bytes()).unwrap();
        let summary = json!({
            "schema_version": 2,
            "approved": true,
            "error_count": 0,
            "warning_count": 1,
            "policy_failure_count": 0,
            "run_sha256": "b".repeat(64),
            "report_bytes": rendered.len(),
            "report_sha256": sha256_hex(rendered.as_bytes()),
            "warning_policy_sha256": policy_sha256,
            "warning_policy_source_bytes": policy_source.len(),
            "warning_policy_source_sha256": policy_source_sha256
        });
        let execution = Execution {
            success: true,
            exit_code: Some(5),
            stdout: serde_json::to_vec(&summary).unwrap(),
            stderr: String::new(),
        };
        assert_eq!(
            trusted_native_kicad_erc_summary(&execution, &report_path),
            summary
        );

        let mut tampered = summary.clone();
        tampered["warning_count"] = json!(0);
        let tampered_execution = Execution {
            stdout: serde_json::to_vec(&tampered).unwrap(),
            ..execution
        };
        assert_eq!(
            trusted_native_kicad_erc_summary(&tampered_execution, &report_path),
            Value::Null
        );
    }

    #[test]
    fn native_kicad_drc_summary_is_digest_bound_and_identity_checked() {
        #[derive(serde::Serialize)]
        struct RunIdentity<'a> {
            schema_version: u32,
            engine: &'a str,
            engine_version: &'a str,
            kicad_version: &'a str,
            source: &'a crate::native_kicad_drc::NativeKicadDrcSourceIdentity,
            project: &'a Option<crate::native_kicad_drc::NativeKicadDrcSourceIdentity>,
            rules_file: &'a Option<crate::native_kicad_drc::NativeKicadDrcSourceIdentity>,
            invocation: &'a crate::native_kicad_drc::NativeKicadDrcInvocation,
            ignored_checks: &'a [crate::native_kicad_drc::NativeKicadDrcIgnoredCheck],
            findings: &'a [crate::native_kicad_drc::NativeKicadDrcFinding],
            violation_count: usize,
            unconnected_item_count: usize,
            schematic_parity_count: usize,
            error_count: usize,
            warning_count: usize,
            approved: bool,
        }

        let directory = tempfile::tempdir().unwrap();
        let board_path = directory.path().join("board.kicad_pcb");
        let board = b"board";
        std::fs::write(&board_path, board).unwrap();
        let source = crate::native_kicad_drc::NativeKicadDrcSourceIdentity {
            bytes: board.len() as u64,
            sha256: sha256_hex(board),
        };
        let invocation = crate::native_kicad_drc::NativeKicadDrcInvocation {
            command: "pcb drc".into(),
            format: "json".into(),
            units: "mm".into(),
            severities: vec!["error".into(), "warning".into()],
            exit_code_violations: true,
            all_track_errors: false,
            schematic_parity: false,
            refill_zones: false,
            save_board: false,
        };
        let mut report = crate::native_kicad_drc::NativeKicadDrcReport {
            schema_version: 1,
            engine: "pcbex".into(),
            engine_version: env!("CARGO_PKG_VERSION").into(),
            kicad_version: "10.0.5".into(),
            source,
            project: None,
            rules_file: None,
            invocation,
            ignored_checks: Vec::new(),
            findings: Vec::new(),
            violation_count: 0,
            unconnected_item_count: 0,
            schematic_parity_count: 0,
            error_count: 0,
            warning_count: 0,
            approved: true,
            run_sha256: String::new(),
        };
        let identity = RunIdentity {
            schema_version: report.schema_version,
            engine: &report.engine,
            engine_version: &report.engine_version,
            kicad_version: &report.kicad_version,
            source: &report.source,
            project: &report.project,
            rules_file: &report.rules_file,
            invocation: &report.invocation,
            ignored_checks: &report.ignored_checks,
            findings: &report.findings,
            violation_count: report.violation_count,
            unconnected_item_count: report.unconnected_item_count,
            schematic_parity_count: report.schematic_parity_count,
            error_count: report.error_count,
            warning_count: report.warning_count,
            approved: report.approved,
        };
        let canonical = serde_json::to_vec(&identity).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"pcbex/native-kicad-pcb-drc/v1\0");
        hasher.update(canonical);
        report.run_sha256 = hex::encode(hasher.finalize());
        let rendered = crate::native_kicad_drc::render_native_kicad_drc_report(&report).unwrap();
        let report_path = directory.path().join("drc.json");
        std::fs::write(&report_path, &rendered).unwrap();
        let summary = json!({
            "schema_version": 1,
            "approved": true,
            "violation_count": 0,
            "unconnected_item_count": 0,
            "schematic_parity_count": 0,
            "error_count": 0,
            "warning_count": 0,
            "ignored_check_count": 0,
            "board_bytes": board.len(),
            "board_sha256": sha256_hex(board),
            "project_bytes": "",
            "project_sha256": "",
            "rules_file_bytes": "",
            "rules_file_sha256": "",
            "run_sha256": report.run_sha256,
            "report_bytes": rendered.len(),
            "report_sha256": sha256_hex(&rendered)
        });
        let execution = || Execution {
            success: false,
            exit_code: Some(5),
            stdout: serde_json::to_vec(&summary).unwrap(),
            stderr: "required approval rejected after retaining a report".into(),
        };
        assert_eq!(
            trusted_native_kicad_drc_summary(&execution(), &report_path, &board_path, None, None),
            summary
        );

        let mut tampered = summary.clone();
        tampered["error_count"] = json!(1);
        let tampered_execution = Execution {
            stdout: serde_json::to_vec(&tampered).unwrap(),
            ..execution()
        };
        assert_eq!(
            trusted_native_kicad_drc_summary(
                &tampered_execution,
                &report_path,
                &board_path,
                None,
                None
            ),
            Value::Null
        );
        let oversized = Execution {
            stdout: vec![b'x'; MAX_MCP_PROCESS_MESSAGE_BYTES + 1],
            ..execution()
        };
        assert_eq!(
            trusted_native_kicad_drc_summary(&oversized, &report_path, &board_path, None, None),
            Value::Null
        );
        std::fs::write(&board_path, b"changed").unwrap();
        assert_eq!(
            trusted_native_kicad_drc_summary(&execution(), &report_path, &board_path, None, None),
            Value::Null
        );
        std::fs::remove_file(&report_path).unwrap();
        assert_eq!(
            trusted_native_kicad_drc_summary(&execution(), &report_path, &board_path, None, None),
            Value::Null
        );
    }

    #[test]
    fn new_pipeline_tools_reject_preexisting_outputs_as_stale_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("old-check.json");
        std::fs::write(&output, br#"{"approved":true}"#).unwrap();
        let mut server = ready_server();
        let response = server
            .handle_message(request(
                30,
                "tools/call",
                json!({
                    "name": "check_circuit_spec",
                    "arguments": {
                        "input": "missing-spec.json",
                        "output": output
                    }
                }),
            ))
            .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(
            response["error"]["data"]["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(std::fs::read(&output).unwrap(), br#"{"approved":true}"#);

        let schematic_output = directory.path().join("old-generated.kicad_sch");
        std::fs::write(&schematic_output, b"old schematic").unwrap();
        let response = server
            .handle_message(request(
                34,
                "tools/call",
                json!({
                    "name": "write_circuit_spec_kicad_schematic",
                    "arguments": {
                        "input": "missing-spec.json",
                        "output": schematic_output
                    }
                }),
            ))
            .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(
            response["error"]["data"]["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(std::fs::read(&schematic_output).unwrap(), b"old schematic");

        let handoff_output = directory.path().join("old-handoff.json");
        std::fs::write(&handoff_output, br#"{"approved":true}"#).unwrap();
        let response = server
            .handle_message(request(
                31,
                "tools/call",
                json!({
                    "name": "verify_circuit_kicad_handoff",
                    "arguments": {
                        "circuit_spec": "missing-spec.json",
                        "schematic": "missing-schematic.kicad_sch",
                        "output": handoff_output
                    }
                }),
            ))
            .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(
            response["error"]["data"]["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&handoff_output).unwrap(),
            br#"{"approved":true}"#
        );

        let board_binding_output = directory.path().join("old-board-binding.json");
        std::fs::write(&board_binding_output, br#"{"approved":true}"#).unwrap();
        let response = server
            .handle_message(request(
                32,
                "tools/call",
                json!({
                    "name": "verify_circuit_kicad_board_binding",
                    "arguments": {
                        "circuit_spec": "missing-spec.json",
                        "schematic": "missing-schematic.kicad_sch",
                        "board": "missing-board.kicad_pcb",
                        "output": board_binding_output
                    }
                }),
            ))
            .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(
            response["error"]["data"]["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&board_binding_output).unwrap(),
            br#"{"approved":true}"#
        );

        let deterministic_output = directory.path().join("old-deterministic.json");
        std::fs::write(&deterministic_output, br#"{"approved":true}"#).unwrap();
        let response = server
            .handle_message(request(
                33,
                "tools/call",
                json!({
                    "name": "run_deterministic_pipeline",
                    "arguments": {
                        "plan": "missing-plan.json",
                        "output": deterministic_output
                    }
                }),
            ))
            .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(
            response["error"]["data"]["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&deterministic_output).unwrap(),
            br#"{"approved":true}"#
        );

        let compiler_output = directory.path().join("old-compiled-plan.json");
        std::fs::write(&compiler_output, br#"{"schema_version":1}"#).unwrap();
        let response = server
            .handle_message(request(
                34,
                "tools/call",
                json!({
                    "name": "compile_deterministic_pipeline_plan",
                    "arguments": {
                        "intent": "missing-intent.json",
                        "output": compiler_output
                    }
                }),
            ))
            .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(
            response["error"]["data"]["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&compiler_output).unwrap(),
            br#"{"schema_version":1}"#
        );

        let authorization_output = directory.path().join("old-authorization.json");
        std::fs::write(&authorization_output, br#"{"status":"stale"}"#).unwrap();
        let error = verify_fabrication_authorization_tool(
            json!({
                "plan": "missing-plan.json",
                "retained_report": "missing-pipeline-report.json",
                "manufacturing_package": "missing-manufacturing.zip",
                "factory_receipt": "missing-factory-receipt.json",
                "policy_pack": "missing-policy-pack.json",
                "approvals": ["missing-approval.json"],
                "output": authorization_output
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&authorization_output).unwrap(),
            br#"{"status":"stale"}"#
        );
    }

    #[test]
    fn ai_review_tools_reject_preexisting_outputs_as_stale_evidence() {
        let directory = tempfile::tempdir().unwrap();

        let request_output = directory.path().join("old-request.json");
        std::fs::write(&request_output, br#"{"approved":true}"#).unwrap();
        let error = prepare_schematic_review(
            json!({
                "input": "missing-schematic.kicad_sch",
                "electrical_review": "missing-review.json",
                "requirements": ["intent=works"],
                "output": request_output,
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&request_output).unwrap(),
            br#"{"approved":true}"#
        );

        let session_output = directory.path().join("old-session.json");
        std::fs::write(&session_output, br#"{"request_sha256":"stale"}"#).unwrap();
        let request_without_session = directory.path().join("new-request.json");
        let error = prepare_schematic_review(
            json!({
                "input": "missing-schematic.kicad_sch",
                "electrical_review": "missing-review.json",
                "requirements": ["intent=works"],
                "output": request_without_session,
                "session_output": session_output,
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&session_output).unwrap(),
            br#"{"request_sha256":"stale"}"#
        );

        let approval_output = directory.path().join("old-approval.json");
        std::fs::write(&approval_output, br#"{"approved":true}"#).unwrap();
        let error = sign_schematic_approval(
            json!({
                "request": "missing-request.json",
                "response": "missing-response.json",
                "private_key": "missing-private.key",
                "signer_id": "reviewer",
                "output": approval_output,
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&approval_output).unwrap(),
            br#"{"approved":true}"#
        );

        let quorum_output = directory.path().join("old-quorum.json");
        std::fs::write(&quorum_output, br#"{"approved":true}"#).unwrap();
        let error = verify_schematic_approval_quorum(
            json!({
                "request": "missing-request.json",
                "approvals": ["missing-approval.json"],
                "responses": ["missing-response.json"],
                "policy_pack": "missing-policy-pack.json",
                "output": quorum_output,
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&quorum_output).unwrap(),
            br#"{"approved":true}"#
        );

        let summary_output = directory.path().join("old-quorum-summary.md");
        std::fs::write(&summary_output, b"stale quorum summary\n").unwrap();
        let quorum_without_summary = directory.path().join("new-quorum.json");
        let error = verify_schematic_approval_quorum(
            json!({
                "request": "missing-request.json",
                "approvals": ["missing-approval.json"],
                "responses": ["missing-response.json"],
                "policy_pack": "missing-policy-pack.json",
                "output": quorum_without_summary,
                "summary_output": summary_output,
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap_err();
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("stale MCP evidence")
        );
        assert_eq!(
            std::fs::read(&summary_output).unwrap(),
            b"stale quorum summary\n"
        );
    }

    #[test]
    fn ai_review_tools_never_return_retained_json_after_child_failure() {
        let directory = tempfile::tempdir().unwrap();

        let request_output = directory.path().join("request.json");
        let result = prepare_schematic_review(
            json!({
                "input": "missing-schematic.kicad_sch",
                "electrical_review": "missing-review.json",
                "requirements": ["intent=works"],
                "output": request_output,
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(result["request"], Value::Null);
        assert!(!request_output.exists());

        let approval_output = directory.path().join("approval.json");
        let result = sign_schematic_approval(
            json!({
                "request": "missing-request.json",
                "response": "missing-response.json",
                "private_key": "missing-private.key",
                "signer_id": "reviewer",
                "output": approval_output,
            })
            .as_object()
            .unwrap()
            .clone(),
            None,
        )
        .unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(result["approval"], Value::Null);
        assert!(!approval_output.exists());
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
        let signing_forbidden = server
            .handle_message(request(
                6,
                "tools/call",
                json!({
                    "name": "sign_schematic_approval",
                    "arguments": {},
                    "task": {"ttl": 60_000}
                }),
            ))
            .unwrap();
        assert_eq!(signing_forbidden["error"]["code"], -32601);
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
    fn new_pipeline_tools_accept_task_augmented_calls() {
        for (index, name) in [
            "check_schematic",
            "check_circuit_spec",
            "write_circuit_spec_kicad_schematic",
            "verify_circuit_kicad_handoff",
            "verify_circuit_kicad_board_binding",
            "pipeline_verify",
            "run_deterministic_pipeline",
            "verify_fabrication_authorization",
            "compile_deterministic_pipeline_plan",
        ]
        .into_iter()
        .enumerate()
        {
            let mut server = ready_server();
            let created = server
                .handle_message(request(
                    10 + index as i64,
                    "tools/call",
                    json!({
                        "name": name,
                        "arguments": {},
                        "task": {"ttl": 60_000}
                    }),
                ))
                .unwrap();
            let task_id = created["result"]["task"]["taskId"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(created["result"]["task"]["status"], "working", "{name}");
            let result = server
                .handle_message(request(
                    20 + index as i64,
                    "tasks/result",
                    json!({"taskId": task_id}),
                ))
                .unwrap();
            assert_eq!(result["error"]["code"], -32602, "{name}: {result}");
        }
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

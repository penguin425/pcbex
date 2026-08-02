use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn manufacturing_package() -> Vec<u8> {
    let board = b"board-bytes";
    let job = serde_json::to_vec(&json!({
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
        ("board-job.gbrjob", job),
        ("board.drl", b"drill".to_vec()),
        ("drc.rpt", b"DRC clean".to_vec()),
        ("bom.csv", b"Comment,Designator\n".to_vec()),
        ("cpl.csv", b"Designator,Mid X (mm)\n".to_vec()),
    ];
    let manifest = json!({
        "schema_version": 1,
        "engine": "pcbex",
        "engine_version": env!("CARGO_PKG_VERSION"),
        "tools": {"kicad_cli": "10.0.5", "kicad_cli_about_sha256": "a".repeat(64)},
        "input": {
            "path": "board.kicad_pcb",
            "bytes": board.len(),
            "sha256": sha256(board)
        },
        "project_inputs": [],
        "parts": {"total": 0, "bom": 0, "placement": 0, "dnp": 0},
        "artifacts": artifacts.iter().map(|(path, bytes)| json!({
            "path": path,
            "bytes": bytes.len(),
            "sha256": sha256(bytes)
        })).collect::<Vec<_>>(),
        "archive": "manufacturing.zip"
    });
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (path, bytes) in artifacts {
        writer.start_file(path, options).unwrap();
        writer.write_all(&bytes).unwrap();
    }
    writer.start_file("manifest.json", options).unwrap();
    writer.write_all(&manifest).unwrap();
    writer.finish().unwrap().into_inner()
}

fn write_package(path: &Path) -> Vec<u8> {
    let package = manufacturing_package();
    fs::write(path, &package).unwrap();
    package
}

fn passing_response() -> Value {
    json!({
        "status": "quoted",
        "accepted": true,
        "dfm_passed": true,
        "findings": []
    })
}

fn failing_response() -> Value {
    json!({
        "status": "dfm-failed",
        "accepted": true,
        "dfm_passed": false,
        "findings": [{
            "code": "clearance",
            "severity": "error",
            "message": "copper clearance is too small"
        }]
    })
}

struct CollisionSideEffect {
    response_index: usize,
    path: PathBuf,
    contents: Vec<u8>,
}

struct HttpFixture {
    endpoint: String,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    handle: JoinHandle<()>,
}

impl HttpFixture {
    fn finish(self) -> Vec<Vec<u8>> {
        self.handle.join().unwrap();
        self.requests.lock().unwrap().clone()
    }
}

fn spawn_http_fixture(responses: Vec<Value>) -> HttpFixture {
    spawn_http_fixture_with_side_effect(responses, None)
}

fn spawn_http_fixture_with_side_effect(
    responses: Vec<Value>,
    side_effect: Option<CollisionSideEffect>,
) -> HttpFixture {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/quote", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_requests = Arc::clone(&requests);
    let handle = thread::spawn(move || {
        for (index, response) in responses.into_iter().enumerate() {
            let mut stream = accept_before_deadline(&listener);
            let request = read_http_request(&mut stream);
            server_requests.lock().unwrap().push(request);
            if let Some(effect) = side_effect.as_ref()
                && effect.response_index == index
            {
                fs::write(&effect.path, &effect.contents).unwrap();
            }
            let body = serde_json::to_vec(&response).unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    HttpFixture {
        endpoint,
        requests,
        handle,
    }
}

fn accept_before_deadline(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "factory client did not connect within five seconds"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accepting factory request: {error}"),
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "factory client closed before sending headers");
        request.extend_from_slice(&buffer[..read]);
        if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break index;
        }
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
        })
        .unwrap_or(0);
    let request_length = header_end + 4 + content_length;
    while request.len() < request_length {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "factory client closed before sending its body");
        request.extend_from_slice(&buffer[..read]);
    }
    request.truncate(request_length);
    request
}

fn request_body(request: &[u8]) -> &[u8] {
    let body = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    &request[body..]
}

fn feedback_command(package: &Path, endpoint: &str, report: &Path) -> Command {
    let mut command = Command::new(binary());
    command
        .arg("factory-feedback-loop")
        .arg(package)
        .args(["--endpoint", endpoint])
        .args(["--timeout-seconds", "1"])
        .arg("--allow-http-loopback")
        .arg("--output")
        .arg(report);
    command
}

fn run_with_final_outputs(
    package: &Path,
    endpoint: &str,
    report: &Path,
    receipt: &Path,
    final_package: &Path,
) -> Output {
    feedback_command(package, endpoint, report)
        .arg("--final-receipt")
        .arg(receipt)
        .arg("--final-package")
        .arg(final_package)
        .output()
        .unwrap()
}

fn unused_loopback_endpoint() -> (TcpListener, String) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let endpoint = format!("http://{}/quote", listener.local_addr().unwrap());
    (listener, endpoint)
}

fn assert_no_connection(listener: &TcpListener) {
    listener.set_nonblocking(true).unwrap();
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("factory CLI contacted the network before output preflight failed"),
        Err(error) => panic!("checking for an unexpected factory connection: {error}"),
    }
}

fn assert_no_prepared_outputs(directory: &Path) {
    let prepared = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".pcbex-output-"))
        .collect::<Vec<_>>();
    assert!(
        prepared.is_empty(),
        "orphaned prepared outputs: {prepared:?}"
    );
}

#[test]
fn feedback_loop_schema_is_closed_and_never_overwrites() {
    let temporary = tempfile::tempdir().unwrap();
    let schema_path = temporary.path().join("factory-loop.schema.json");
    let first = Command::new(binary())
        .args(["factory-feedback-loop-schema", "--output"])
        .arg(&schema_path)
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let schema: Value = serde_json::from_slice(&fs::read(&schema_path).unwrap()).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(
        schema["properties"]["attempts"]["items"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["$defs"]["factory_submission_receipt"]["additionalProperties"],
        false
    );

    let existing = temporary.path().join("existing.schema.json");
    let sentinel = b"preserve-existing-schema\n";
    fs::write(&existing, sentinel).unwrap();
    let overwrite = Command::new(binary())
        .args(["factory-feedback-loop-schema", "--output"])
        .arg(&existing)
        .output()
        .unwrap();
    assert!(!overwrite.status.success());
    assert_eq!(fs::read(&existing).unwrap(), sentinel);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let target = temporary.path().join("schema-target.json");
        let link = temporary.path().join("schema-link.json");
        fs::write(&target, sentinel).unwrap();
        symlink(&target, &link).unwrap();
        let through_link = Command::new(binary())
            .args(["factory-feedback-loop-schema", "--output"])
            .arg(&link)
            .output()
            .unwrap();
        assert!(!through_link.status.success());
        assert_eq!(fs::read(&target).unwrap(), sentinel);
    }
    assert_no_prepared_outputs(temporary.path());
}

#[test]
fn all_existing_loop_outputs_fail_before_network_access() {
    for existing_label in ["report", "receipt", "package"] {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("manufacturing.zip");
        fs::write(&input, b"must-not-be-read-before-output-preflight").unwrap();
        let report = temporary.path().join("loop.json");
        let receipt = temporary.path().join("receipt.json");
        let final_package = temporary.path().join("final.zip");
        let existing = match existing_label {
            "report" => &report,
            "receipt" => &receipt,
            "package" => &final_package,
            _ => unreachable!(),
        };
        let sentinel = format!("preserve-{existing_label}\n");
        fs::write(existing, sentinel.as_bytes()).unwrap();
        let (listener, endpoint) = unused_loopback_endpoint();

        let result = run_with_final_outputs(&input, &endpoint, &report, &receipt, &final_package);
        assert!(
            !result.status.success(),
            "existing {existing_label} was overwritten"
        );
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("refusing to overwrite existing output")
        );
        assert_eq!(fs::read(existing).unwrap(), sentinel.as_bytes());
        assert_no_connection(&listener);
        assert_no_prepared_outputs(temporary.path());
    }
}

#[cfg(unix)]
#[test]
fn symlink_output_fails_before_network_access() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    write_package(&input);
    let report = temporary.path().join("loop.json");
    let receipt_target = temporary.path().join("receipt-target.json");
    let receipt_link = temporary.path().join("receipt-link.json");
    let final_package = temporary.path().join("final.zip");
    let sentinel = b"preserve-symlink-target\n";
    fs::write(&receipt_target, sentinel).unwrap();
    symlink(&receipt_target, &receipt_link).unwrap();
    let (listener, endpoint) = unused_loopback_endpoint();

    let result = run_with_final_outputs(&input, &endpoint, &report, &receipt_link, &final_package);
    assert!(!result.status.success());
    assert_eq!(fs::read(&receipt_target).unwrap(), sentinel);
    assert_no_connection(&listener);
    assert!(!report.exists());
    assert!(!final_package.exists());
    assert_no_prepared_outputs(temporary.path());
}

#[test]
fn collisions_and_input_aliases_fail_before_network_access() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    write_package(&input);
    let outputs = temporary.path().join("outputs");
    fs::create_dir(&outputs).unwrap();
    let report = outputs.join("loop.json");
    let lexical_alias = outputs.join(".").join("loop.json");
    let final_package = outputs.join("final.zip");
    let (listener, endpoint) = unused_loopback_endpoint();

    let collision =
        run_with_final_outputs(&input, &endpoint, &report, &lexical_alias, &final_package);
    assert!(!collision.status.success());
    assert!(String::from_utf8_lossy(&collision.stderr).contains("same destination"));
    assert_no_connection(&listener);

    let (listener, endpoint) = unused_loopback_endpoint();
    let input_alias = feedback_command(&input, &endpoint, &input)
        .output()
        .unwrap();
    assert!(!input_alias.status.success());
    assert!(String::from_utf8_lossy(&input_alias.stderr).contains("must not alias input package"));
    assert_no_connection(&listener);
    assert_no_prepared_outputs(outputs.as_path());
}

#[cfg(unix)]
#[test]
fn symlinked_parent_output_alias_fails_before_network_access() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    write_package(&input);
    let real = temporary.path().join("real");
    let alias = temporary.path().join("alias");
    fs::create_dir(&real).unwrap();
    symlink(&real, &alias).unwrap();
    let report = alias.join("loop.json");
    let (listener, endpoint) = unused_loopback_endpoint();

    let result = feedback_command(&input, &endpoint, &report)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("symlink component"));
    assert_no_connection(&listener);
    assert_no_prepared_outputs(&real);
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn case_folded_output_alias_fails_before_network_access() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    write_package(&input);
    let report = temporary.path().join("loop.json");
    let receipt = temporary.path().join("LOOP.JSON");
    let (listener, endpoint) = unused_loopback_endpoint();
    let result = feedback_command(&input, &endpoint, &report)
        .arg("--final-receipt")
        .arg(&receipt)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("same destination"));
    assert_no_connection(&listener);
}

#[test]
fn one_attempt_pass_publishes_report_receipt_and_package_hashes() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    let package = write_package(&input);
    let report_path = temporary.path().join("loop.json");
    let receipt_path = temporary.path().join("receipt.json");
    let final_package_path = temporary.path().join("final.zip");
    let fixture = spawn_http_fixture(vec![passing_response()]);

    let result = run_with_final_outputs(
        &input,
        &fixture.endpoint,
        &report_path,
        &receipt_path,
        &final_package_path,
    );
    let requests = fixture.finish();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(requests.len(), 1);
    assert_eq!(request_body(&requests[0]), package);

    let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    let receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    let package_hash = sha256(&package);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["passed"], true);
    assert_eq!(report["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(report["attempts"][0]["package_sha256"], package_hash);
    assert!(report["attempts"][0]["receipt"].is_object());
    assert!(report["attempts"][0]["error"].is_null());
    assert_eq!(report["final_package_sha256"], package_hash);
    assert_eq!(report["final_package_bytes"], package.len());
    assert_eq!(receipt["package_sha256"], package_hash);
    assert_eq!(fs::read(&final_package_path).unwrap(), package);
    #[cfg(unix)]
    for path in [&report_path, &receipt_path, &final_package_path] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
    assert_no_prepared_outputs(temporary.path());
}

#[test]
fn failed_dfm_without_repair_still_publishes_evidence_and_exits_nonzero() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    let package = write_package(&input);
    let report_path = temporary.path().join("loop.json");
    let receipt_path = temporary.path().join("receipt.json");
    let final_package_path = temporary.path().join("final.zip");
    let fixture = spawn_http_fixture(vec![failing_response()]);

    let result = run_with_final_outputs(
        &input,
        &fixture.endpoint,
        &report_path,
        &receipt_path,
        &final_package_path,
    );
    let requests = fixture.finish();
    assert!(!result.status.success());
    assert_eq!(requests.len(), 1);
    let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["passed"], false);
    assert_eq!(report["attempts"].as_array().unwrap().len(), 1);
    assert!(
        report["failure"]
            .as_str()
            .unwrap()
            .contains("no repair command")
    );
    assert!(receipt_path.exists());
    assert_eq!(fs::read(&final_package_path).unwrap(), package);
    assert_no_prepared_outputs(temporary.path());
}

#[cfg(unix)]
#[test]
fn executable_non_utf8_repair_wrapper_can_reach_a_passing_attempt() {
    use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};

    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    let package = write_package(&input);
    let report_path = temporary.path().join("loop.json");
    let receipt_path = temporary.path().join("receipt.json");
    let final_package_path = temporary.path().join("final.zip");
    let repair = temporary
        .path()
        .join(std::ffi::OsString::from_vec(b"repair-\xff.sh".to_vec()));
    fs::write(
        &repair,
        b"#!/bin/sh\nset -eu\ncp -- \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\" \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"\n",
    )
    .unwrap();
    fs::set_permissions(&repair, fs::Permissions::from_mode(0o755)).unwrap();
    let fixture = spawn_http_fixture(vec![failing_response(), passing_response()]);

    let result = feedback_command(&input, &fixture.endpoint, &report_path)
        .args(["--max-attempts", "2"])
        .arg("--repair-command")
        .arg(&repair)
        .arg("--final-receipt")
        .arg(&receipt_path)
        .arg("--final-package")
        .arg(&final_package_path)
        .output()
        .unwrap();
    let requests = fixture.finish();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request_body(request) == package)
    );
    let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["passed"], true);
    assert_eq!(report["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(report["attempts"][0]["repair_command_ran"], true);
    assert_eq!(report["attempts"][1]["repair_command_ran"], false);
    assert_eq!(fs::read(&final_package_path).unwrap(), package);
    assert_no_prepared_outputs(temporary.path());
}

#[test]
fn reflected_bearer_token_never_reaches_loop_artifacts() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    let package = write_package(&input);
    let report_path = temporary.path().join("loop.json");
    let receipt_path = temporary.path().join("receipt.json");
    let final_package_path = temporary.path().join("final.zip");
    let token = "secret-token-\"\\value";
    let variable = "PCBEX_FACTORY_REFLECTED_TOKEN_INTEGRATION";
    let fixture = spawn_http_fixture(vec![json!({
        "status": "quoted",
        "accepted": true,
        "dfm_passed": true,
        "echo": format!("authorization was Bearer {token}")
    })]);

    let result = feedback_command(&input, &fixture.endpoint, &report_path)
        .arg("--bearer-token-env")
        .arg(variable)
        .arg("--final-receipt")
        .arg(&receipt_path)
        .arg("--final-package")
        .arg(&final_package_path)
        .env(variable, token)
        .output()
        .unwrap();
    let requests = fixture.finish();

    assert!(!result.status.success());
    assert_eq!(requests.len(), 1);
    assert!(String::from_utf8_lossy(&requests[0]).contains(token));
    let report = fs::read_to_string(&report_path).unwrap();
    assert!(!report.contains(token));
    let report: Value = serde_json::from_str(&report).unwrap();
    assert!(report["attempts"][0]["receipt"].is_null());
    assert!(
        report["attempts"][0]["error"]
            .as_str()
            .unwrap()
            .contains("reflected bearer credentials")
    );
    assert!(!receipt_path.exists());
    assert_eq!(fs::read(&final_package_path).unwrap(), package);
    assert_no_prepared_outputs(temporary.path());
}

#[test]
fn transport_error_publishes_nullable_receipt_report_and_known_good_package() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    let package = write_package(&input);
    let report_path = temporary.path().join("loop.json");
    let receipt_path = temporary.path().join("receipt.json");
    let final_package_path = temporary.path().join("final.zip");
    let (listener, endpoint) = unused_loopback_endpoint();
    drop(listener);

    let result = run_with_final_outputs(
        &input,
        &endpoint,
        &report_path,
        &receipt_path,
        &final_package_path,
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("no final receipt"));
    let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["passed"], false);
    assert_eq!(report["attempts"].as_array().unwrap().len(), 1);
    assert!(report["attempts"][0]["receipt"].is_null());
    assert!(report["attempts"][0]["error"].is_string());
    assert!(!receipt_path.exists());
    assert_eq!(fs::read(&final_package_path).unwrap(), package);
    assert_no_prepared_outputs(temporary.path());
}

#[cfg(unix)]
#[test]
fn invalid_or_mutating_repair_retains_the_known_good_package() {
    use std::os::unix::fs::PermissionsExt;

    let cases: [(&str, &[u8], &str); 2] = [
        (
            "invalid",
            b"#!/bin/sh\nset -eu\nprintf 'not-a-zip' > \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"\n",
            "valid ZIP",
        ),
        (
            "mutating",
            b"#!/bin/sh\nset -eu\nprintf 'mutation' >> \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\"\ncp -- \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\" \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"\n",
            "modified its input",
        ),
    ];
    for (name, script, failure_fragment) in cases {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("manufacturing.zip");
        let package = write_package(&input);
        let report_path = temporary.path().join("loop.json");
        let receipt_path = temporary.path().join("receipt.json");
        let final_package_path = temporary.path().join("final.zip");
        let repair = temporary.path().join(format!("repair-{name}.sh"));
        fs::write(&repair, script).unwrap();
        fs::set_permissions(&repair, fs::Permissions::from_mode(0o755)).unwrap();
        let fixture = spawn_http_fixture(vec![failing_response()]);

        let result = feedback_command(&input, &fixture.endpoint, &report_path)
            .args(["--max-attempts", "2"])
            .arg("--repair-command")
            .arg(&repair)
            .arg("--final-receipt")
            .arg(&receipt_path)
            .arg("--final-package")
            .arg(&final_package_path)
            .output()
            .unwrap();
        let requests = fixture.finish();
        assert!(
            !result.status.success(),
            "{name} repair unexpectedly passed"
        );
        assert_eq!(requests.len(), 1);
        let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
        assert_eq!(report["passed"], false);
        assert!(
            report["failure"]
                .as_str()
                .unwrap()
                .contains(failure_fragment),
            "{}",
            report["failure"]
        );
        assert_eq!(fs::read(&input).unwrap(), package);
        assert_eq!(fs::read(&final_package_path).unwrap(), package);
        assert!(receipt_path.exists());
        assert_no_prepared_outputs(temporary.path());
    }
}

#[test]
fn report_survives_optional_artifact_publication_race() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("manufacturing.zip");
    write_package(&input);
    let report_path = temporary.path().join("loop.json");
    let receipt_path = temporary.path().join("receipt.json");
    let final_package_path = temporary.path().join("final.zip");
    let sentinel = b"racing-writer-won\n".to_vec();
    let fixture = spawn_http_fixture_with_side_effect(
        vec![passing_response()],
        Some(CollisionSideEffect {
            response_index: 0,
            path: final_package_path.clone(),
            contents: sentinel.clone(),
        }),
    );

    let result = run_with_final_outputs(
        &input,
        &fixture.endpoint,
        &report_path,
        &receipt_path,
        &final_package_path,
    );
    fixture.finish();
    assert!(!result.status.success());
    assert_eq!(fs::read(&final_package_path).unwrap(), sentinel);
    assert!(receipt_path.exists());
    let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["passed"], true);
    assert_no_prepared_outputs(temporary.path());
}

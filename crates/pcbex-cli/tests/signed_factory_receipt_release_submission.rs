use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    io::{Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NONCE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const RECONCILIATION_ID: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const TOKEN: &str = "test-factory-release-token-1482";
const TOKEN_ENV: &str = "PCBEX_TEST_FACTORY_RELEASE_TOKEN_1482";
const RESERVATION_SCOPE: &str =
    "pinned-local-signed-factory-receipt-release-ledger-at-most-once-v1";
const ACKNOWLEDGEMENT_SCOPE: &str = "pcbex-signed-factory-release-adapter-acknowledgement-v1";

#[derive(Serialize)]
struct Marker<'a> {
    schema_version: u32,
    reservation_scope: &'a str,
    status: &'a str,
    local_challenge_reserved: bool,
    adapter_network_performed: bool,
    global_challenge_one_time_use_enforced: bool,
    external_submission_performed: bool,
    capacity_reserved: bool,
    order_placed: bool,
    payment_performed: bool,
    ledger_id: &'a str,
    release_report_summary: Summary<'a>,
}

#[derive(Serialize)]
struct Summary<'a> {
    schema_version: u32,
    status: &'a str,
    release_authenticated: bool,
    executable_pinned_fabrication_release_authorized: bool,
    factory_receipt_attestation_verified: bool,
    factory_receipt_authenticity_verified: bool,
    attestation_id: &'a str,
    challenge: &'a str,
    issued_at_unix: u64,
    expires_at_unix: u64,
    evaluated_at_unix: u64,
    fabrication_authorization_id: &'a str,
    fabrication_authorization_challenge: &'a str,
    fabrication_valid_from_unix: u64,
    fabrication_expires_at_unix: u64,
    factory_id: &'a str,
    provider: &'a str,
    manufacturing_package_sha256: &'a str,
    factory_receipt_sha256: &'a str,
    policy_pack_sha256: &'a str,
    policy_pack_canonical_sha256: &'a str,
    signed_attestation_sha256: &'a str,
    attestation_verifier_sha256: &'a str,
    retained_report_bytes: u64,
    retained_report_sha256: &'a str,
    retained_report_binding_sha256: &'a str,
    fresh_report_bytes: u64,
    fresh_report_sha256: &'a str,
    fresh_report_binding_sha256: &'a str,
    release_subject_sha256: &'a str,
    gate_failure_count: u32,
    trusted_time_verified: bool,
    factory_legal_identity_verified: bool,
    endpoint_transport_authenticity_verified: bool,
    raw_response_authenticity_verified: bool,
    source_authenticity_verified: bool,
    executable_origin_authenticity_verified: bool,
    toolchain_authenticity_verified: bool,
    policy_pack_authenticity_verified: bool,
    manufacturability_verified: bool,
    external_submission_performed: bool,
    capacity_reserved: bool,
    order_placed: bool,
    payment_performed: bool,
    challenge_one_time_use_enforced: bool,
}

fn pcbex() -> &'static str {
    env!("CARGO_BIN_EXE_pcbex")
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn canonical_json(value: &impl Serialize) -> Vec<u8> {
    let mut raw = serde_json::to_vec_pretty(value).unwrap();
    raw.push(b'\n');
    raw
}

fn marker(current: u64, package_sha256: &str) -> Vec<u8> {
    canonical_json(&Marker {
        schema_version: 1,
        reservation_scope: RESERVATION_SCOPE,
        status: "local_reservation_committed",
        local_challenge_reserved: true,
        adapter_network_performed: false,
        global_challenge_one_time_use_enforced: false,
        external_submission_performed: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        ledger_id: DIGEST,
        release_report_summary: Summary {
            schema_version: 1,
            status: "release_authenticated",
            release_authenticated: true,
            executable_pinned_fabrication_release_authorized: true,
            factory_receipt_attestation_verified: true,
            factory_receipt_authenticity_verified: true,
            attestation_id: "receipt-1482",
            challenge: DIGEST,
            issued_at_unix: current - 60,
            expires_at_unix: current + 600,
            evaluated_at_unix: current,
            fabrication_authorization_id: "fabrication-1482",
            fabrication_authorization_challenge: DIGEST,
            fabrication_valid_from_unix: current - 120,
            fabrication_expires_at_unix: current + 900,
            factory_id: "factory-a",
            provider: "generic",
            manufacturing_package_sha256: package_sha256,
            factory_receipt_sha256: DIGEST,
            policy_pack_sha256: DIGEST,
            policy_pack_canonical_sha256: DIGEST,
            signed_attestation_sha256: DIGEST,
            attestation_verifier_sha256: DIGEST,
            retained_report_bytes: 4_096,
            retained_report_sha256: DIGEST,
            retained_report_binding_sha256: DIGEST,
            fresh_report_bytes: 4_097,
            fresh_report_sha256: DIGEST,
            fresh_report_binding_sha256: DIGEST,
            release_subject_sha256: DIGEST,
            gate_failure_count: 0,
            trusted_time_verified: false,
            factory_legal_identity_verified: false,
            endpoint_transport_authenticity_verified: false,
            raw_response_authenticity_verified: false,
            source_authenticity_verified: false,
            executable_origin_authenticity_verified: false,
            toolchain_authenticity_verified: false,
            policy_pack_authenticity_verified: false,
            manufacturability_verified: false,
            external_submission_performed: false,
            capacity_reserved: false,
            order_placed: false,
            payment_performed: false,
            challenge_one_time_use_enforced: false,
        },
    })
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
    let artifacts: Vec<(&str, Vec<u8>)> = vec![
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
        (
            "bom.csv",
            b"Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n".to_vec(),
        ),
        (
            "cpl.csv",
            b"Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n".to_vec(),
        ),
    ];
    let manifest = json!({
        "schema_version": 1,
        "engine": "pcbex",
        "engine_version": env!("CARGO_PKG_VERSION"),
        "tools": {
            "kicad_cli": "10.0.5",
            "kicad_cli_about_sha256": "a".repeat(64)
        },
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
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (path, bytes) in artifacts {
        writer.start_file(path, options).unwrap();
        writer.write_all(&bytes).unwrap();
    }
    writer.start_file("manifest.json", options).unwrap();
    writer
        .write_all(&serde_json::to_vec(&manifest).unwrap())
        .unwrap();
    writer.finish().unwrap().into_inner()
}

#[cfg(unix)]
fn create_ledger(root: &Path, package_sha256: &str) -> PathBuf {
    let ledger = root.join("ledger");
    fs::create_dir(&ledger).unwrap();
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        ledger.join(".pcbex-signed-factory-receipt-release-reservation-ledger-v1.json"),
        format!(
            "{{\"schema_version\":1,\"ledger_scope\":\"{RESERVATION_SCOPE}\",\"ledger_id\":\"{DIGEST}\"}}"
        ),
    )
    .unwrap();
    let marker_path = ledger.join(format!(
        "signed-factory-receipt-release-reservation-v1-{DIGEST}.json"
    ));
    fs::write(&marker_path, marker(now(), package_sha256)).unwrap();
    fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o600)).unwrap();
    ledger
}

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "client closed before request headers completed");
        request.extend_from_slice(&buffer[..read]);
        if let Some(offset) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break offset + 4;
        }
    };
    let content_length = header_value(&request[..header_end], "content-length")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(0);
    while request.len() < header_end + content_length {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "client closed before request body completed");
        request.extend_from_slice(&buffer[..read]);
    }
    request.truncate(header_end + content_length);
    request
}

fn header_value(headers: &[u8], expected: &str) -> Option<String> {
    String::from_utf8_lossy(headers).lines().find_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case(expected)
                .then(|| value.trim().to_string())
        })
    })
}

fn spawn_acknowledgement_server(
    operation: &'static str,
    status: &'static str,
    reconciliation_id: Option<&'static str>,
) -> (String, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        let header_end = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let idempotency_key = header_value(&request[..header_end], "idempotency-key").unwrap();
        let request_nonce = header_value(&request[..header_end], "x-pcbex-request-nonce").unwrap();
        let release_subject =
            header_value(&request[..header_end], "x-pcbex-release-subject-sha256").unwrap();
        let package_sha256 =
            header_value(&request[..header_end], "x-pcbex-package-sha256").unwrap();
        let body = serde_json::to_vec(&json!({
            "schema_version": 1,
            "acknowledgement_scope": ACKNOWLEDGEMENT_SCOPE,
            "operation": operation,
            "idempotency_key": idempotency_key,
            "request_nonce": request_nonce,
            "reconciliation_id": reconciliation_id,
            "release_subject_sha256": release_subject,
            "manufacturing_package_sha256": package_sha256,
            "factory_id": "factory-a",
            "provider": "generic",
            "status": status,
            "submission_id": "factory-submission-1482"
        }))
        .unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        request
    });
    (endpoint, handle)
}

#[cfg(unix)]
fn submit(
    package: &Path,
    ledger: &Path,
    endpoint: &str,
    output: &Path,
    require_accepted: bool,
) -> Output {
    submit_with_nonce(package, ledger, endpoint, NONCE, output, require_accepted)
}

#[cfg(unix)]
fn submit_with_nonce(
    package: &Path,
    ledger: &Path,
    endpoint: &str,
    request_nonce: &str,
    output: &Path,
    require_accepted: bool,
) -> Output {
    let mut command = Command::new(pcbex());
    command
        .arg("submit-signed-factory-receipt-release")
        .arg(package)
        .arg("--reservation-ledger")
        .arg(ledger)
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--challenge")
        .arg(DIGEST)
        .arg("--endpoint")
        .arg(endpoint)
        .arg("--request-nonce")
        .arg(request_nonce)
        .arg("--bearer-token-env")
        .arg(TOKEN_ENV)
        .arg("--timeout-seconds")
        .arg("5")
        .arg("--output")
        .arg(output)
        .arg("--allow-http-loopback")
        .env(TOKEN_ENV, TOKEN);
    if require_accepted {
        command.arg("--require-accepted");
    }
    command.output().unwrap()
}

#[cfg(unix)]
fn reconcile(
    ledger: &Path,
    idempotency_key: &str,
    endpoint: &str,
    output: &Path,
    require_accepted: bool,
) -> Output {
    let mut command = Command::new(pcbex());
    command
        .arg("reconcile-signed-factory-receipt-release")
        .arg("--reservation-ledger")
        .arg(ledger)
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--idempotency-key")
        .arg(idempotency_key)
        .arg("--endpoint")
        .arg(endpoint)
        .arg("--reconciliation-id")
        .arg(RECONCILIATION_ID)
        .arg("--bearer-token-env")
        .arg(TOKEN_ENV)
        .arg("--timeout-seconds")
        .arg("5")
        .arg("--output")
        .arg(output)
        .arg("--allow-http-loopback")
        .env(TOKEN_ENV, TOKEN);
    if require_accepted {
        command.arg("--require-accepted");
    }
    command.output().unwrap()
}

#[test]
fn schemas_and_public_commands_are_visible() {
    let help = Command::new(pcbex()).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    for command in [
        "signed-factory-release-submission-intent-schema",
        "signed-factory-release-adapter-acknowledgement-schema",
        "signed-factory-release-adapter-receipt-schema",
        "submit-signed-factory-receipt-release",
        "reconcile-signed-factory-receipt-release",
    ] {
        assert!(help.contains(command), "missing {command}");
    }
    for command in [
        "signed-factory-release-submission-intent-schema",
        "signed-factory-release-adapter-acknowledgement-schema",
        "signed-factory-release-adapter-receipt-schema",
    ] {
        let output = Command::new(pcbex()).arg(command).output().unwrap();
        assert!(output.status.success());
        let schema: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
    }
}

#[test]
#[cfg(unix)]
fn durable_submit_and_reconcile_never_retransmit_the_package() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().canonicalize().unwrap();
    let package = manufacturing_package();
    let package_path = root.join("manufacturing.zip");
    fs::write(&package_path, &package).unwrap();
    let ledger = create_ledger(&root, &sha256(&package));

    let (submit_endpoint, submit_server) =
        spawn_acknowledgement_server("submit", "adapter_pending", None);
    let first_path = root.join("submit.json");
    let first = submit(&package_path, &ledger, &submit_endpoint, &first_path, false);
    assert!(
        first.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    let submitted_request = submit_server.join().unwrap();
    assert!(String::from_utf8_lossy(&submitted_request).starts_with("POST /release HTTP/1.1"));
    assert!(submitted_request.ends_with(&package));
    let first_raw = fs::read(&first_path).unwrap();
    let first_receipt: Value = serde_json::from_slice(&first_raw).unwrap();
    assert_eq!(first_receipt["status"], "adapter_pending");
    assert_eq!(
        first_receipt["manufacturing_package_transmission_attempted"],
        true
    );
    assert_eq!(first_receipt["server_side_idempotency_enforced"], false);
    assert_eq!(first_receipt["trusted_time_verified"], false);
    assert!(first_receipt["attempted_at_unix"].as_u64().is_some());
    let idempotency_key = first_receipt["idempotency_key"].as_str().unwrap();

    // A caller cannot mint another idempotency key for the same reservation
    // by changing either the nonce or the endpoint. Both variations collide
    // with the committed intent and fail before another adapter call.
    let changed_nonce_path = root.join("changed-nonce.json");
    let changed_nonce = submit_with_nonce(
        &package_path,
        &ledger,
        &submit_endpoint,
        &"3".repeat(64),
        &changed_nonce_path,
        false,
    );
    assert!(!changed_nonce.status.success());
    assert!(
        String::from_utf8_lossy(&changed_nonce.stderr)
            .contains("existing durable submission intent does not match")
    );
    assert!(!changed_nonce_path.exists());

    let unused_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let changed_endpoint = format!("http://{}/release", unused_listener.local_addr().unwrap());
    drop(unused_listener);
    let changed_endpoint_path = root.join("changed-endpoint.json");
    let changed_endpoint_result = submit(
        &package_path,
        &ledger,
        &changed_endpoint,
        &changed_endpoint_path,
        false,
    );
    assert!(!changed_endpoint_result.status.success());
    assert!(
        String::from_utf8_lossy(&changed_endpoint_result.stderr)
            .contains("existing durable submission intent does not match")
    );
    assert!(!changed_endpoint_path.exists());

    // The listener is gone. A second submit must replay the durable result,
    // retain it, and apply the final acceptance gate without opening a socket.
    let replay_path = root.join("submit-replay.json");
    let replay = submit(&package_path, &ledger, &submit_endpoint, &replay_path, true);
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("did not acknowledge acceptance"));
    assert_eq!(fs::read(&replay_path).unwrap(), first_raw);

    let (reconcile_endpoint, reconcile_server) =
        spawn_acknowledgement_server("reconcile", "adapter_accepted", Some(RECONCILIATION_ID));
    let reconciled_path = root.join("reconciled.json");
    let reconciled = reconcile(
        &ledger,
        idempotency_key,
        &reconcile_endpoint,
        &reconciled_path,
        true,
    );
    assert!(
        reconciled.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&reconciled.stderr)
    );
    let reconciliation_request = reconcile_server.join().unwrap();
    assert!(String::from_utf8_lossy(&reconciliation_request).starts_with("GET /release HTTP/1.1"));
    let header_end = reconciliation_request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(reconciliation_request.len(), header_end);
    assert!(
        !reconciliation_request
            .windows(package.len())
            .any(|bytes| bytes == package)
    );
    let reconciled_raw = fs::read(&reconciled_path).unwrap();
    let reconciled_receipt: Value = serde_json::from_slice(&reconciled_raw).unwrap();
    assert_eq!(reconciled_receipt["status"], "adapter_accepted");
    assert_eq!(reconciled_receipt["operation"], "reconcile");
    assert_eq!(
        reconciled_receipt["manufacturing_package_transmission_attempted"],
        false
    );
    assert_eq!(reconciled_receipt["trusted_time_verified"], false);
    assert!(reconciled_receipt["attempted_at_unix"].as_u64().is_some());

    // Reusing the same reconciliation id is also a pure durable replay.
    let reconciliation_replay_path = root.join("reconciled-replay.json");
    let reconciliation_replay = reconcile(
        &ledger,
        idempotency_key,
        &reconcile_endpoint,
        &reconciliation_replay_path,
        true,
    );
    assert!(reconciliation_replay.status.success());
    assert_eq!(
        fs::read(reconciliation_replay_path).unwrap(),
        reconciled_raw
    );

    for entry in fs::read_dir(&ledger).unwrap() {
        let raw = fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !raw.windows(TOKEN.len())
                .any(|bytes| bytes == TOKEN.as_bytes())
        );
    }
}

#[test]
#[cfg(unix)]
fn unknown_submit_outcome_is_retained_then_replayed_without_network() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().canonicalize().unwrap();
    let package = manufacturing_package();
    let package_path = root.join("manufacturing.zip");
    fs::write(&package_path, &package).unwrap();
    let ledger = create_ledger(&root, &sha256(&package));

    // Reserve a loopback address, then close it so the single POST attempt
    // deterministically fails at the transport boundary.
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
    drop(listener);

    let first_path = root.join("unknown.json");
    let first = submit(&package_path, &ledger, &endpoint, &first_path, false);
    assert!(!first.status.success());
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert!(
        first_stderr.contains("outcome is unknown"),
        "{first_stderr}"
    );
    assert!(!first_stderr.contains(TOKEN));
    let first_raw = fs::read(&first_path).unwrap();
    let receipt: Value = serde_json::from_slice(&first_raw).unwrap();
    assert_eq!(receipt["status"], "outcome_unknown");
    assert_eq!(receipt["failure"], "transport_error");
    assert_eq!(
        receipt["manufacturing_package_transmission_attempted"],
        true
    );
    assert!(
        !first_raw
            .windows(TOKEN.len())
            .any(|bytes| bytes == TOKEN.as_bytes())
    );

    // A retained unknown result is evidence of the first attempt. Repeating
    // the public submit publishes those exact bytes and never sends again.
    let replay_path = root.join("unknown-replay.json");
    let replay = submit(&package_path, &ledger, &endpoint, &replay_path, false);
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("outcome is unknown"));
    assert_eq!(fs::read(replay_path).unwrap(), first_raw);

    // Model a crash after the intent commit but before result retention. The
    // surviving intent is a hard retransmission barrier.
    let result_path = fs::read_dir(&ledger)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("signed-factory-release-submission-result-v1-")
                })
        })
        .unwrap();
    fs::remove_file(result_path).unwrap();
    let blocked_path = root.join("blocked-retransmission.json");
    let blocked = submit(&package_path, &ledger, &endpoint, &blocked_path, false);
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("intent already exists without a result")
    );
    assert!(!blocked_path.exists());
}

#[test]
#[cfg(not(unix))]
fn durable_commands_fail_closed_off_unix() {
    let output = Command::new(pcbex())
        .arg("submit-signed-factory-receipt-release")
        .arg("package.zip")
        .arg("--reservation-ledger")
        .arg("ledger")
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--challenge")
        .arg(DIGEST)
        .arg("--endpoint")
        .arg("https://factory.example/release")
        .arg("--request-nonce")
        .arg(NONCE)
        .arg("--bearer-token-env")
        .arg(TOKEN_ENV)
        .arg("--output")
        .arg("receipt.json")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("supported only on Unix"));
}

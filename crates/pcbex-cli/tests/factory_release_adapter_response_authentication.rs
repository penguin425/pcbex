use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
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
const TOKEN: &str = "test-authenticated-factory-release-token-1483";
const TOKEN_ENV: &str = "PCBEX_TEST_AUTHENTICATED_FACTORY_RELEASE_TOKEN_1483";
const RESERVATION_SCOPE: &str =
    "pinned-local-signed-factory-receipt-release-ledger-at-most-once-v1";
const ACKNOWLEDGEMENT_SCOPE: &str = "pcbex-signed-factory-release-adapter-acknowledgement-v1";
const SIGNATURE_PROFILE: &str = "pcbex-signed-factory-release-response-v1";
const RESPONSE_PROFILE_HEADER: &str = "rfc9421-ed25519-content-digest-v1";
const MONOTONIC_SIGNATURE_PROFILE: &str =
    "pcbex-signed-factory-release-monotonic-state-response-v1";
const MONOTONIC_RESPONSE_PROFILE_HEADER: &str = "rfc9421-ed25519-content-digest-monotonic-state-v1";
const MONOTONIC_STATE_SCOPE: &str = "authenticated-monotonic-factory-release-adapter-state-v1";
const RESPONSE_KEY_ID: &str = "factory-response-key-a";
const RESPONSE_SECRET: [u8; 32] = [37; 32];
const POLICY_SECRET: [u8; 32] = [41; 32];

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

#[derive(Serialize)]
struct MonotonicStateMaterial<'a> {
    schema_version: u32,
    state_scope: &'a str,
    sequence: u64,
    previous_state_sha256: Option<&'a str>,
    idempotency_key: &'a str,
    submission_id: &'a str,
    factory_id: &'a str,
    provider: &'a str,
    release_subject_sha256: &'a str,
    manufacturing_package_sha256: &'a str,
    status: &'a str,
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
            attestation_id: "receipt-1483",
            challenge: DIGEST,
            issued_at_unix: current - 60,
            expires_at_unix: current + 600,
            evaluated_at_unix: current,
            fabrication_authorization_id: "fabrication-1483",
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
        "tools": {"kicad_cli": "10.0.5", "kicad_cli_about_sha256": "a".repeat(64)},
        "input": {"path": "board.kicad_pcb", "bytes": board.len(), "sha256": sha256(board)},
        "project_inputs": [],
        "parts": {"total": 0, "bom": 0, "placement": 0, "dnp": 0},
        "artifacts": artifacts.iter().map(|(path, bytes)| json!({
            "path": path, "bytes": bytes.len(), "sha256": sha256(bytes)
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
fn create_ledger(root: &Path, package_sha256: &str, suffix: &str) -> PathBuf {
    let ledger = root.join(format!("ledger-{suffix}"));
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

#[cfg(unix)]
fn create_policy(root: &Path) -> (PathBuf, String) {
    let policy_path = root.join("adapter-response-policy.json");
    let private_key_path = root.join("policy-signing.key");
    let signed_path = root.join("signed-policy.json");
    let response_public = hex::encode(
        SigningKey::from_bytes(&RESPONSE_SECRET)
            .verifying_key()
            .to_bytes(),
    );
    let policy_public = hex::encode(
        SigningKey::from_bytes(&POLICY_SECRET)
            .verifying_key()
            .to_bytes(),
    );
    let mut policy: Value =
        serde_json::from_str(include_str!("../../../examples/acme-policy-pack.json")).unwrap();
    policy["trusted_approval_keys"] = json!([{
        "signer_id": "integration-policy-key",
        "public_key": policy_public
    }]);
    policy["factory_adapter_response_authentication_policy"] = json!({
        "maximum_validity_seconds": 300,
        "trusted_keys": [{
            "key_id": RESPONSE_KEY_ID,
            "factory_id": "factory-a",
            "provider": "generic",
            "public_key": response_public
        }]
    });
    fs::write(&policy_path, canonical_json(&policy)).unwrap();
    fs::write(
        &private_key_path,
        format!("{}\n", hex::encode(POLICY_SECRET)),
    )
    .unwrap();
    fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600)).unwrap();
    let signed = Command::new(pcbex())
        .arg("sign-policy-pack")
        .arg(&policy_path)
        .arg("--private-key")
        .arg(&private_key_path)
        .arg("--signer-id")
        .arg("integration-policy-key")
        .arg("--output")
        .arg(&signed_path)
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let envelope: Value = serde_json::from_slice(&fs::read(signed_path).unwrap()).unwrap();
    (
        policy_path,
        envelope["policy_pack_sha256"].as_str().unwrap().into(),
    )
}

fn header_value(headers: &[u8], expected: &str) -> Option<String> {
    String::from_utf8_lossy(headers).lines().find_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case(expected)
                .then(|| value.trim().to_string())
        })
    })
}

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0);
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
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
    }
    request.truncate(header_end + content_length);
    request
}

fn signature_components(operation: &str) -> &'static str {
    if operation == "submit" {
        "(\"@status\" \"content-digest\" \"content-type\" \"x-pcbex-adapter\";req \"x-pcbex-schema-version\";req \"x-pcbex-response-signature-profile\";req \"idempotency-key\";req \"x-pcbex-request-nonce\";req \"x-pcbex-release-subject-sha256\";req \"x-pcbex-package-sha256\";req \"x-pcbex-factory-id\";req \"@method\";req \"@target-uri\";req)"
    } else {
        "(\"@status\" \"content-digest\" \"content-type\" \"x-pcbex-adapter\";req \"x-pcbex-schema-version\";req \"x-pcbex-response-signature-profile\";req \"idempotency-key\";req \"x-pcbex-request-nonce\";req \"x-pcbex-reconciliation-id\";req \"x-pcbex-release-subject-sha256\";req \"x-pcbex-package-sha256\";req \"x-pcbex-factory-id\";req \"@method\";req \"@target-uri\";req)"
    }
}

fn spawn_adapter(
    operation: &'static str,
    status: &'static str,
    reconciliation_id: Option<&'static str>,
    sign_response: bool,
) -> (String, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
    let signed_endpoint = endpoint.clone();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        let header_end = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = &request[..header_end];
        let idempotency_key = header_value(headers, "idempotency-key").unwrap();
        let request_nonce = header_value(headers, "x-pcbex-request-nonce").unwrap();
        let release_subject = header_value(headers, "x-pcbex-release-subject-sha256").unwrap();
        let package_sha256 = header_value(headers, "x-pcbex-package-sha256").unwrap();
        let factory_id = header_value(headers, "x-pcbex-factory-id").unwrap();
        let body = serde_json::to_vec(&json!({
            "schema_version": 1,
            "acknowledgement_scope": ACKNOWLEDGEMENT_SCOPE,
            "operation": operation,
            "idempotency_key": idempotency_key,
            "request_nonce": request_nonce,
            "reconciliation_id": reconciliation_id,
            "release_subject_sha256": release_subject,
            "manufacturing_package_sha256": package_sha256,
            "factory_id": factory_id,
            "provider": "generic",
            "status": status,
            "submission_id": "factory-submission-1483"
        }))
        .unwrap();
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if sign_response {
            let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body)));
            let created = now();
            let expires = created + 120;
            let parameters = format!(
                "{};created={created};expires={expires};keyid=\"{RESPONSE_KEY_ID}\";alg=\"ed25519\";tag=\"{SIGNATURE_PROFILE}\"",
                signature_components(operation)
            );
            let signature_input = format!("pcbex={parameters}");
            let mut base = vec![
                "\"@status\": 200".to_string(),
                format!("\"content-digest\": {content_digest}"),
                "\"content-type\": application/json".into(),
                "\"x-pcbex-adapter\";req: signed-factory-release-http-v1".into(),
                "\"x-pcbex-schema-version\";req: 1".into(),
                format!("\"x-pcbex-response-signature-profile\";req: {RESPONSE_PROFILE_HEADER}"),
                format!("\"idempotency-key\";req: {idempotency_key}"),
                format!("\"x-pcbex-request-nonce\";req: {request_nonce}"),
            ];
            if let Some(id) = reconciliation_id {
                base.push(format!("\"x-pcbex-reconciliation-id\";req: {id}"));
            }
            base.extend([
                format!("\"x-pcbex-release-subject-sha256\";req: {release_subject}"),
                format!("\"x-pcbex-package-sha256\";req: {package_sha256}"),
                format!("\"x-pcbex-factory-id\";req: {factory_id}"),
                format!(
                    "\"@method\";req: {}",
                    if operation == "submit" { "POST" } else { "GET" }
                ),
                format!("\"@target-uri\";req: {signed_endpoint}"),
                format!("\"@signature-params\": {parameters}"),
            ]);
            let signature = SigningKey::from_bytes(&RESPONSE_SECRET)
                .sign(base.join("\n").as_bytes())
                .to_bytes();
            response.push_str(&format!("Content-Digest: {content_digest}\r\n"));
            response.push_str(&format!("Signature-Input: {signature_input}\r\n"));
            response.push_str(&format!(
                "Signature: pcbex=:{}:\r\n",
                STANDARD.encode(signature)
            ));
        }
        response.push_str("\r\n");
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        request
    });
    (endpoint, handle)
}

fn monotonic_signature_components(operation: &str) -> &'static str {
    if operation == "submit" {
        "(\"@status\" \"content-digest\" \"content-type\" \"x-pcbex-state-sequence\" \"x-pcbex-state-previous-sha256\" \"x-pcbex-state-sha256\" \"x-pcbex-adapter\";req \"x-pcbex-schema-version\";req \"x-pcbex-response-signature-profile\";req \"x-pcbex-accepted-state-sequence\";req \"x-pcbex-accepted-state-sha256\";req \"idempotency-key\";req \"x-pcbex-request-nonce\";req \"x-pcbex-release-subject-sha256\";req \"x-pcbex-package-sha256\";req \"x-pcbex-factory-id\";req \"@method\";req \"@target-uri\";req)"
    } else {
        "(\"@status\" \"content-digest\" \"content-type\" \"x-pcbex-state-sequence\" \"x-pcbex-state-previous-sha256\" \"x-pcbex-state-sha256\" \"x-pcbex-adapter\";req \"x-pcbex-schema-version\";req \"x-pcbex-response-signature-profile\";req \"x-pcbex-accepted-state-sequence\";req \"x-pcbex-accepted-state-sha256\";req \"idempotency-key\";req \"x-pcbex-request-nonce\";req \"x-pcbex-reconciliation-id\";req \"x-pcbex-release-subject-sha256\";req \"x-pcbex-package-sha256\";req \"x-pcbex-factory-id\";req \"@method\";req \"@target-uri\";req)"
    }
}

fn monotonic_state_sha256(
    sequence: u64,
    previous_state_sha256: Option<&str>,
    idempotency_key: &str,
    factory_id: &str,
    release_subject_sha256: &str,
    manufacturing_package_sha256: &str,
    status: &str,
) -> String {
    let source = serde_json::to_vec(&MonotonicStateMaterial {
        schema_version: 1,
        state_scope: MONOTONIC_STATE_SCOPE,
        sequence,
        previous_state_sha256,
        idempotency_key,
        submission_id: "factory-submission-1484",
        factory_id,
        provider: "generic",
        release_subject_sha256,
        manufacturing_package_sha256,
        status,
    })
    .unwrap();
    let mut hash = Sha256::new();
    hash.update(b"pcbex:factory-release-adapter-monotonic-state:v1\0");
    hash.update(source);
    hex::encode(hash.finalize())
}

fn spawn_monotonic_adapter(
    operation: &'static str,
    status: &'static str,
    reconciliation_id: Option<&'static str>,
    sequence: u64,
) -> (String, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
    let signed_endpoint = endpoint.clone();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        let header_end = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = &request[..header_end];
        let idempotency_key = header_value(headers, "idempotency-key").unwrap();
        let request_nonce = header_value(headers, "x-pcbex-request-nonce").unwrap();
        let release_subject = header_value(headers, "x-pcbex-release-subject-sha256").unwrap();
        let package_sha256 = header_value(headers, "x-pcbex-package-sha256").unwrap();
        let factory_id = header_value(headers, "x-pcbex-factory-id").unwrap();
        let accepted_sequence = header_value(headers, "x-pcbex-accepted-state-sequence").unwrap();
        let accepted_sha256 = header_value(headers, "x-pcbex-accepted-state-sha256").unwrap();
        assert_eq!(
            header_value(headers, "x-pcbex-response-signature-profile").as_deref(),
            Some(MONOTONIC_RESPONSE_PROFILE_HEADER)
        );
        let previous = if sequence == 0 {
            assert_eq!(accepted_sequence, "none");
            assert_eq!(accepted_sha256, "none");
            None
        } else {
            assert_eq!(accepted_sequence, (sequence - 1).to_string());
            Some(accepted_sha256.as_str())
        };
        let state_sha256 = monotonic_state_sha256(
            sequence,
            previous,
            &idempotency_key,
            &factory_id,
            &release_subject,
            &package_sha256,
            status,
        );
        let previous_header = previous.unwrap_or("none");
        let body = serde_json::to_vec(&json!({
            "schema_version": 1,
            "acknowledgement_scope": ACKNOWLEDGEMENT_SCOPE,
            "operation": operation,
            "idempotency_key": idempotency_key,
            "request_nonce": request_nonce,
            "reconciliation_id": reconciliation_id,
            "release_subject_sha256": release_subject,
            "manufacturing_package_sha256": package_sha256,
            "factory_id": factory_id,
            "provider": "generic",
            "status": status,
            "submission_id": "factory-submission-1484"
        }))
        .unwrap();
        let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body)));
        let created = now();
        let expires = created + 120;
        let parameters = format!(
            "{};created={created};expires={expires};keyid=\"{RESPONSE_KEY_ID}\";alg=\"ed25519\";tag=\"{MONOTONIC_SIGNATURE_PROFILE}\"",
            monotonic_signature_components(operation)
        );
        let signature_input = format!("pcbex-state={parameters}");
        let mut base = vec![
            "\"@status\": 200".to_string(),
            format!("\"content-digest\": {content_digest}"),
            "\"content-type\": application/json".into(),
            format!("\"x-pcbex-state-sequence\": {sequence}"),
            format!("\"x-pcbex-state-previous-sha256\": {previous_header}"),
            format!("\"x-pcbex-state-sha256\": {state_sha256}"),
            "\"x-pcbex-adapter\";req: signed-factory-release-http-v1".into(),
            "\"x-pcbex-schema-version\";req: 1".into(),
            format!(
                "\"x-pcbex-response-signature-profile\";req: {MONOTONIC_RESPONSE_PROFILE_HEADER}"
            ),
            format!("\"x-pcbex-accepted-state-sequence\";req: {accepted_sequence}"),
            format!("\"x-pcbex-accepted-state-sha256\";req: {accepted_sha256}"),
            format!("\"idempotency-key\";req: {idempotency_key}"),
            format!("\"x-pcbex-request-nonce\";req: {request_nonce}"),
        ];
        if let Some(id) = reconciliation_id {
            base.push(format!("\"x-pcbex-reconciliation-id\";req: {id}"));
        }
        base.extend([
            format!("\"x-pcbex-release-subject-sha256\";req: {release_subject}"),
            format!("\"x-pcbex-package-sha256\";req: {package_sha256}"),
            format!("\"x-pcbex-factory-id\";req: {factory_id}"),
            format!(
                "\"@method\";req: {}",
                if operation == "submit" { "POST" } else { "GET" }
            ),
            format!("\"@target-uri\";req: {signed_endpoint}"),
            format!("\"@signature-params\": {parameters}"),
        ]);
        let signature = SigningKey::from_bytes(&RESPONSE_SECRET)
            .sign(base.join("\n").as_bytes())
            .to_bytes();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nContent-Digest: {content_digest}\r\nX-PCBEX-State-Sequence: {sequence}\r\nX-PCBEX-State-Previous-SHA256: {previous_header}\r\nX-PCBEX-State-SHA256: {state_sha256}\r\nSignature-Input: {signature_input}\r\nSignature: pcbex-state=:{}:\r\n\r\n",
            body.len(),
            STANDARD.encode(signature)
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        request
    });
    (endpoint, handle)
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn submit(
    package: &Path,
    ledger: &Path,
    policy: &Path,
    policy_sha256: &str,
    endpoint: &str,
    output: &Path,
    require_accepted: bool,
) -> Output {
    let mut command = Command::new(pcbex());
    command
        .arg("submit-authenticated-signed-factory-receipt-release")
        .arg(package)
        .arg("--reservation-ledger")
        .arg(ledger)
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--challenge")
        .arg(DIGEST)
        .arg("--policy-pack")
        .arg(policy)
        .arg("--expected-policy-sha256")
        .arg(policy_sha256)
        .arg("--endpoint")
        .arg(endpoint)
        .arg("--request-nonce")
        .arg(NONCE)
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
#[allow(clippy::too_many_arguments)]
fn reconcile(
    ledger: &Path,
    idempotency_key: &str,
    policy: &Path,
    policy_sha256: &str,
    endpoint: &str,
    reconciliation_id: &str,
    output: &Path,
) -> Output {
    Command::new(pcbex())
        .arg("reconcile-authenticated-signed-factory-receipt-release")
        .arg("--reservation-ledger")
        .arg(ledger)
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--idempotency-key")
        .arg(idempotency_key)
        .arg("--policy-pack")
        .arg(policy)
        .arg("--expected-policy-sha256")
        .arg(policy_sha256)
        .arg("--endpoint")
        .arg(endpoint)
        .arg("--reconciliation-id")
        .arg(reconciliation_id)
        .arg("--bearer-token-env")
        .arg(TOKEN_ENV)
        .arg("--timeout-seconds")
        .arg("5")
        .arg("--output")
        .arg(output)
        .arg("--allow-http-loopback")
        .arg("--require-accepted")
        .env(TOKEN_ENV, TOKEN)
        .output()
        .unwrap()
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn submit_monotonic(
    package: &Path,
    ledger: &Path,
    policy: &Path,
    policy_sha256: &str,
    endpoint: &str,
    output: &Path,
    require_accepted: bool,
) -> Output {
    let mut command = Command::new(pcbex());
    command
        .arg("submit-monotonic-authenticated-signed-factory-receipt-release")
        .arg(package)
        .arg("--reservation-ledger")
        .arg(ledger)
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--challenge")
        .arg(DIGEST)
        .arg("--policy-pack")
        .arg(policy)
        .arg("--expected-policy-sha256")
        .arg(policy_sha256)
        .arg("--endpoint")
        .arg(endpoint)
        .arg("--request-nonce")
        .arg(NONCE)
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
#[allow(clippy::too_many_arguments)]
fn reconcile_monotonic(
    ledger: &Path,
    idempotency_key: &str,
    policy: &Path,
    policy_sha256: &str,
    endpoint: &str,
    reconciliation_id: &str,
    output: &Path,
    require_accepted: bool,
) -> Output {
    let mut command = Command::new(pcbex());
    command
        .arg("reconcile-monotonic-authenticated-signed-factory-receipt-release")
        .arg("--reservation-ledger")
        .arg(ledger)
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--idempotency-key")
        .arg(idempotency_key)
        .arg("--policy-pack")
        .arg(policy)
        .arg("--expected-policy-sha256")
        .arg(policy_sha256)
        .arg("--endpoint")
        .arg(endpoint)
        .arg("--reconciliation-id")
        .arg(reconciliation_id)
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
fn schemas_and_authenticated_commands_are_public() {
    let help = Command::new(pcbex()).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    for command in [
        "factory-release-adapter-http-message-signature-schema",
        "factory-release-adapter-response-authentication-report-schema",
        "submit-authenticated-signed-factory-receipt-release",
        "reconcile-authenticated-signed-factory-receipt-release",
        "factory-release-adapter-monotonic-state-schema",
        "factory-release-adapter-monotonic-http-message-signature-schema",
        "factory-release-adapter-monotonic-state-entry-schema",
        "factory-release-adapter-monotonic-observation-report-schema",
        "submit-monotonic-authenticated-signed-factory-receipt-release",
        "reconcile-monotonic-authenticated-signed-factory-receipt-release",
    ] {
        assert!(help.contains(command), "missing {command}");
    }
    for command in [
        "factory-release-adapter-http-message-signature-schema",
        "factory-release-adapter-response-authentication-report-schema",
        "factory-release-adapter-monotonic-state-schema",
        "factory-release-adapter-monotonic-http-message-signature-schema",
        "factory-release-adapter-monotonic-state-entry-schema",
        "factory-release-adapter-monotonic-observation-report-schema",
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
fn durable_authenticated_submit_reconcile_and_replay_use_one_network_attempt_each() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().canonicalize().unwrap();
    let package = manufacturing_package();
    let package_path = root.join("manufacturing.zip");
    fs::write(&package_path, &package).unwrap();
    let ledger = create_ledger(&root, &sha256(&package), "signed");
    let (policy, policy_sha256) = create_policy(&root);

    let (submit_endpoint, submit_server) = spawn_adapter("submit", "adapter_pending", None, true);
    let submit_path = root.join("authenticated-submit.json");
    let first = submit(
        &package_path,
        &ledger,
        &policy,
        &policy_sha256,
        &submit_endpoint,
        &submit_path,
        false,
    );
    assert!(
        first.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    let request = submit_server.join().unwrap();
    assert!(String::from_utf8_lossy(&request).starts_with("POST /release HTTP/1.1"));
    assert!(request.ends_with(&package));
    let submit_raw = fs::read(&submit_path).unwrap();
    let submit_report: Value = serde_json::from_slice(&submit_raw).unwrap();
    assert_eq!(submit_report["response_authenticated"], true);
    assert_eq!(submit_report["raw_response_authenticity_verified"], true);
    assert_eq!(
        submit_report["adapter_receipt"]["raw_response_authenticity_verified"],
        false
    );
    assert_eq!(
        submit_report["adapter_receipt"]["status"],
        "adapter_pending"
    );
    assert_eq!(submit_report["trusted_time_verified"], false);
    assert_eq!(submit_report["order_placed"], false);
    let idempotency_key = submit_report["adapter_receipt"]["idempotency_key"]
        .as_str()
        .unwrap();

    let replay_path = root.join("authenticated-submit-replay.json");
    let replay = submit(
        &package_path,
        &ledger,
        &policy,
        &policy_sha256,
        &submit_endpoint,
        &replay_path,
        false,
    );
    assert!(replay.status.success());
    assert_eq!(fs::read(replay_path).unwrap(), submit_raw);

    let (reconcile_endpoint, reconcile_server) = spawn_adapter(
        "reconcile",
        "adapter_accepted",
        Some(RECONCILIATION_ID),
        true,
    );
    let reconcile_path = root.join("authenticated-reconcile.json");
    let reconciled = reconcile(
        &ledger,
        idempotency_key,
        &policy,
        &policy_sha256,
        &reconcile_endpoint,
        RECONCILIATION_ID,
        &reconcile_path,
    );
    assert!(
        reconciled.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&reconciled.stderr)
    );
    let request = reconcile_server.join().unwrap();
    assert!(String::from_utf8_lossy(&request).starts_with("GET /release HTTP/1.1"));
    let header_end = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(request.len(), header_end);
    let reconcile_raw = fs::read(&reconcile_path).unwrap();
    let report: Value = serde_json::from_slice(&reconcile_raw).unwrap();
    assert_eq!(report["response_authenticated"], true);
    assert_eq!(report["accepted"], true);
    assert_eq!(report["adapter_receipt"]["operation"], "reconcile");
    assert_eq!(
        report["adapter_receipt"]["manufacturing_package_transmission_attempted"],
        false
    );

    let reconcile_replay_path = root.join("authenticated-reconcile-replay.json");
    let reconcile_replay = reconcile(
        &ledger,
        idempotency_key,
        &policy,
        &policy_sha256,
        &reconcile_endpoint,
        RECONCILIATION_ID,
        &reconcile_replay_path,
    );
    assert!(reconcile_replay.status.success());
    assert_eq!(fs::read(reconcile_replay_path).unwrap(), reconcile_raw);

    let names = fs::read_dir(&ledger)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        names
            .iter()
            .any(|name| name.starts_with("authenticated-factory-release-submission-v1-"))
    );
    assert!(
        names
            .iter()
            .any(|name| name.starts_with("authenticated-factory-release-reconciliation-v1-"))
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
fn durable_monotonic_submit_repairs_then_advances_once_and_stops_at_terminal_state() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().canonicalize().unwrap();
    let package = manufacturing_package();
    let package_path = root.join("manufacturing-monotonic.zip");
    fs::write(&package_path, &package).unwrap();
    let ledger = create_ledger(&root, &sha256(&package), "monotonic");
    let (policy, policy_sha256) = create_policy(&root);

    let (submit_endpoint, submit_server) =
        spawn_monotonic_adapter("submit", "adapter_pending", None, 0);
    let submit_path = root.join("monotonic-submit.json");
    let submitted = submit_monotonic(
        &package_path,
        &ledger,
        &policy,
        &policy_sha256,
        &submit_endpoint,
        &submit_path,
        false,
    );
    assert!(
        submitted.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&submitted.stderr)
    );
    let submit_request = submit_server.join().unwrap();
    assert!(String::from_utf8_lossy(&submit_request).starts_with("POST /release HTTP/1.1"));
    assert!(submit_request.ends_with(&package));
    let submit_raw = fs::read(&submit_path).unwrap();
    let submit_report: Value = serde_json::from_slice(&submit_raw).unwrap();
    assert_eq!(submit_report["response_authenticated"], true);
    assert_eq!(submit_report["state_continuity_verified"], true);
    assert_eq!(submit_report["requested_head_continuity_verified"], true);
    assert_eq!(submit_report["selected_ledger_state_committed"], false);
    assert_eq!(submit_report["observed_state"]["sequence"], 0);
    assert_eq!(submit_report["observed_state"]["status"], "adapter_pending");
    assert_eq!(submit_report["requested_state"], Value::Null);
    assert_eq!(submit_report["accepted"], false);
    assert_eq!(submit_report["global_non_equivocation_verified"], false);
    assert_eq!(submit_report["trusted_time_verified"], false);
    assert_eq!(submit_report["order_placed"], false);
    let idempotency_key = submit_report["adapter_receipt"]["idempotency_key"]
        .as_str()
        .unwrap();
    let state_zero = ledger.join(format!(
        "monotonic-factory-release-state-v1-{idempotency_key}-0000.json"
    ));
    let compatible_submit = ledger.join(format!(
        "signed-factory-release-submission-result-v1-{idempotency_key}.json"
    ));
    assert!(state_zero.is_file());
    assert!(compatible_submit.is_file());

    // Simulate process loss after the durable observation but before each later
    // publication barrier. Replaying the submit command must repair locally.
    fs::remove_file(&state_zero).unwrap();
    fs::remove_file(&compatible_submit).unwrap();
    let repaired_path = root.join("monotonic-submit-repaired.json");
    let repaired = submit_monotonic(
        &package_path,
        &ledger,
        &policy,
        &policy_sha256,
        &submit_endpoint,
        &repaired_path,
        false,
    );
    assert!(
        repaired.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&repaired.stderr)
    );
    assert_eq!(fs::read(repaired_path).unwrap(), submit_raw);
    assert!(state_zero.is_file());
    assert!(compatible_submit.is_file());

    let (reconcile_endpoint, reconcile_server) =
        spawn_monotonic_adapter("reconcile", "adapter_accepted", Some(RECONCILIATION_ID), 1);
    let reconcile_path = root.join("monotonic-reconcile.json");
    let reconciled = reconcile_monotonic(
        &ledger,
        idempotency_key,
        &policy,
        &policy_sha256,
        &reconcile_endpoint,
        RECONCILIATION_ID,
        &reconcile_path,
        true,
    );
    assert!(
        reconciled.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&reconciled.stderr)
    );
    let reconcile_request = reconcile_server.join().unwrap();
    assert!(String::from_utf8_lossy(&reconcile_request).starts_with("GET /release HTTP/1.1"));
    let request_head = header_value(&reconcile_request, "x-pcbex-accepted-state-sha256").unwrap();
    assert_eq!(
        request_head,
        submit_report["observed_state"]["state_sha256"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        header_value(&reconcile_request, "x-pcbex-accepted-state-sequence").as_deref(),
        Some("0")
    );
    let header_end = reconcile_request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(reconcile_request.len(), header_end);
    let reconcile_raw = fs::read(&reconcile_path).unwrap();
    let reconcile_report: Value = serde_json::from_slice(&reconcile_raw).unwrap();
    assert_eq!(reconcile_report["response_authenticated"], true);
    assert_eq!(reconcile_report["state_continuity_verified"], true);
    assert_eq!(reconcile_report["observed_state"]["sequence"], 1);
    assert_eq!(
        reconcile_report["observed_state"]["status"],
        "adapter_accepted"
    );
    assert_eq!(reconcile_report["accepted"], true);
    assert_eq!(
        reconcile_report["requested_state"]["state_sha256"],
        submit_report["observed_state"]["state_sha256"]
    );
    assert!(
        ledger
            .join(format!(
                "monotonic-factory-release-state-v1-{idempotency_key}-0001.json"
            ))
            .is_file()
    );

    // A terminal state is returned locally even with a fresh observation ID and
    // the now-closed endpoint. No third network request is possible.
    let terminal_replay_path = root.join("monotonic-terminal-replay.json");
    let terminal_replay = reconcile_monotonic(
        &ledger,
        idempotency_key,
        &policy,
        &policy_sha256,
        &reconcile_endpoint,
        &"33".repeat(32),
        &terminal_replay_path,
        true,
    );
    assert!(
        terminal_replay.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&terminal_replay.stderr)
    );
    assert_eq!(fs::read(terminal_replay_path).unwrap(), reconcile_raw);

    let names = fs::read_dir(&ledger)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        names
            .iter()
            .any(|name| name.starts_with("monotonic-factory-release-submission-v1-"))
    );
    assert!(
        names
            .iter()
            .any(|name| name.starts_with("monotonic-factory-release-reconciliation-v1-"))
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
fn unauthenticated_response_is_retained_and_replayed_without_a_second_post() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().canonicalize().unwrap();
    let package = manufacturing_package();
    let package_path = root.join("manufacturing.zip");
    fs::write(&package_path, &package).unwrap();
    let ledger = create_ledger(&root, &sha256(&package), "unsigned");
    let (policy, policy_sha256) = create_policy(&root);
    let (endpoint, server) = spawn_adapter("submit", "adapter_accepted", None, false);
    let report_path = root.join("negative.json");
    let first = submit(
        &package_path,
        &ledger,
        &policy,
        &policy_sha256,
        &endpoint,
        &report_path,
        true,
    );
    assert!(!first.status.success());
    assert!(String::from_utf8_lossy(&first.stderr).contains("response was not authenticated"));
    server.join().unwrap();
    let first_raw = fs::read(&report_path).unwrap();
    let report: Value = serde_json::from_slice(&first_raw).unwrap();
    assert_eq!(report["response_authenticated"], false);
    assert_eq!(
        report["authentication_failure"],
        "response_signature_headers_missing"
    );
    assert_eq!(report["signer"], Value::Null);
    assert_eq!(report["response_signature"], Value::Null);
    assert_eq!(report["accepted"], false);

    let replay_path = root.join("negative-replay.json");
    let replay = submit(
        &package_path,
        &ledger,
        &policy,
        &policy_sha256,
        &endpoint,
        &replay_path,
        false,
    );
    assert!(!replay.status.success());
    assert_eq!(fs::read(replay_path).unwrap(), first_raw);
}

#[test]
#[cfg(not(unix))]
fn authenticated_durable_commands_fail_closed_off_unix() {
    let output = Command::new(pcbex())
        .arg("submit-authenticated-signed-factory-receipt-release")
        .arg("package.zip")
        .arg("--reservation-ledger")
        .arg("ledger")
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--challenge")
        .arg(DIGEST)
        .arg("--policy-pack")
        .arg("policy.json")
        .arg("--expected-policy-sha256")
        .arg(DIGEST)
        .arg("--endpoint")
        .arg("https://factory.example/release")
        .arg("--request-nonce")
        .arg(NONCE)
        .arg("--bearer-token-env")
        .arg(TOKEN_ENV)
        .arg("--output")
        .arg("report.json")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("supported only on Unix"));

    let monotonic = Command::new(pcbex())
        .arg("submit-monotonic-authenticated-signed-factory-receipt-release")
        .arg("package.zip")
        .arg("--reservation-ledger")
        .arg("ledger")
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--challenge")
        .arg(DIGEST)
        .arg("--policy-pack")
        .arg("policy.json")
        .arg("--expected-policy-sha256")
        .arg(DIGEST)
        .arg("--endpoint")
        .arg("https://factory.example/release")
        .arg("--request-nonce")
        .arg(NONCE)
        .arg("--bearer-token-env")
        .arg(TOKEN_ENV)
        .arg("--output")
        .arg("monotonic-report.json")
        .output()
        .unwrap();
    assert!(!monotonic.status.success());
    assert!(String::from_utf8_lossy(&monotonic.stderr).contains("supported only on Unix"));
}

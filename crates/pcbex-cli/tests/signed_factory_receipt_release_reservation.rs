use serde::Serialize;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SCOPE: &str = "pinned-local-signed-factory-receipt-release-ledger-at-most-once-v1";

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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn marker(current: u64) -> Vec<u8> {
    let value = Marker {
        schema_version: 1,
        reservation_scope: SCOPE,
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
            attestation_id: "receipt-1481",
            challenge: DIGEST,
            issued_at_unix: current - 60,
            expires_at_unix: current + 600,
            evaluated_at_unix: current,
            fabrication_authorization_id: "fabrication-1481",
            fabrication_authorization_challenge: DIGEST,
            fabrication_valid_from_unix: current - 120,
            fabrication_expires_at_unix: current + 900,
            factory_id: "factory-a",
            provider: "generic",
            manufacturing_package_sha256: DIGEST,
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
    };
    let mut raw = serde_json::to_vec_pretty(&value).unwrap();
    raw.push(b'\n');
    raw
}

fn manifest() -> String {
    format!("{{\"schema_version\":1,\"ledger_scope\":\"{SCOPE}\",\"ledger_id\":\"{DIGEST}\"}}")
}

fn run(marker: &Path, ledger: &Path, protected: &Path) -> Output {
    Command::new(pcbex())
        .arg("internal-reserve-signed-factory-receipt-release")
        .arg(marker)
        .arg("--reservation-ledger")
        .arg(ledger)
        .arg("--expected-ledger-id")
        .arg(DIGEST)
        .arg("--protected-input")
        .arg(protected)
        .output()
        .unwrap()
}

#[cfg(unix)]
fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().canonicalize().unwrap();
    (workspace, root)
}

#[cfg(unix)]
fn create_ledger(root: &Path) -> PathBuf {
    let ledger = root.join("ledger");
    fs::create_dir(&ledger).unwrap();
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        ledger.join(".pcbex-signed-factory-receipt-release-reservation-ledger-v1.json"),
        manifest(),
    )
    .unwrap();
    ledger
}

#[test]
#[cfg(unix)]
fn helper_commits_once_and_rejects_an_insecure_or_overlapping_ledger() {
    let (_workspace, root) = canonical_tempdir();
    let marker_path = root.join("marker.json");
    let marker_raw = marker(now());
    fs::write(&marker_path, &marker_raw).unwrap();
    let protected = root.join("source.json");
    fs::write(&protected, "source").unwrap();
    let ledger = create_ledger(&root);
    let final_path = ledger.join(format!(
        "signed-factory-receipt-release-reservation-v1-{DIGEST}.json"
    ));

    let first = run(&marker_path, &ledger, &protected);
    assert!(
        first.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stdout.is_empty());
    assert!(first.stderr.is_empty());
    assert_eq!(fs::read(&final_path).unwrap(), marker_raw);
    assert_eq!(
        fs::metadata(&final_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let second = run(&marker_path, &ledger, &protected);
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("challenge is already reserved"));
    assert_eq!(fs::read(&final_path).unwrap(), marker_raw);

    let (_burned_workspace, burned_root) = canonical_tempdir();
    let burned_marker = burned_root.join("marker.json");
    fs::write(&burned_marker, marker(now())).unwrap();
    let burned_protected = burned_root.join("source.json");
    fs::write(&burned_protected, "source").unwrap();
    let burned_ledger = create_ledger(&burned_root);
    let corrupt = burned_ledger.join(format!(
        "signed-factory-receipt-release-reservation-v1-{DIGEST}.json"
    ));
    fs::write(&corrupt, b"corrupt-but-burned\n").unwrap();
    let burned = run(&burned_marker, &burned_ledger, &burned_protected);
    assert!(!burned.status.success());
    assert!(String::from_utf8_lossy(&burned.stderr).contains("challenge is already reserved"));
    assert_eq!(fs::read(corrupt).unwrap(), b"corrupt-but-burned\n");

    let (_other_workspace, other_root) = canonical_tempdir();
    let other_marker = other_root.join("marker.json");
    fs::write(&other_marker, marker(now())).unwrap();
    let other_ledger = create_ledger(&other_root);
    fs::set_permissions(&other_ledger, fs::Permissions::from_mode(0o755)).unwrap();
    let insecure = run(&other_marker, &other_ledger, &protected);
    assert!(!insecure.status.success());
    assert!(String::from_utf8_lossy(&insecure.stderr).contains("exactly 0700"));

    fs::set_permissions(&other_ledger, fs::Permissions::from_mode(0o700)).unwrap();
    let inside = other_ledger.join("source.json");
    fs::write(&inside, "source").unwrap();
    let overlap = run(&other_marker, &other_ledger, &inside);
    assert!(!overlap.status.success());
    assert!(String::from_utf8_lossy(&overlap.stderr).contains("must not contain or alias input"));

    let outside = other_root.join("outside.json");
    fs::write(&outside, "outside").unwrap();
    let outward_link = other_ledger.join("outward-source.json");
    symlink(&outside, &outward_link).unwrap();
    let lexical_overlap = run(&other_marker, &other_ledger, &outward_link);
    assert!(!lexical_overlap.status.success());
    assert!(
        String::from_utf8_lossy(&lexical_overlap.stderr)
            .contains("must not contain or alias input")
    );
}

#[test]
fn schemas_are_public_but_helper_is_hidden() {
    let help = Command::new(pcbex()).arg("--help").output().unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("signed-factory-receipt-release-reservation-schema"));
    assert!(text.contains("signed-factory-receipt-release-reservation-ledger-schema"));
    assert!(!text.contains("internal-reserve-signed-factory-receipt-release"));
    for command in [
        "signed-factory-receipt-release-reservation-schema",
        "signed-factory-receipt-release-reservation-ledger-schema",
    ] {
        let output = Command::new(pcbex()).arg(command).output().unwrap();
        assert!(output.status.success());
        let schema: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }
}

#[test]
#[cfg(not(unix))]
fn helper_fails_closed_off_unix() {
    let workspace = tempfile::tempdir().unwrap();
    let marker_path = workspace.path().join("marker.json");
    fs::write(&marker_path, marker(now())).unwrap();
    let ledger = workspace.path().join("ledger");
    fs::create_dir(&ledger).unwrap();
    let protected = workspace.path().join("source.json");
    fs::write(&protected, "source").unwrap();
    let output = run(&marker_path, &ledger, &protected);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("supported only on Unix"));
}

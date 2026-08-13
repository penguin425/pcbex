use serde::Serialize;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SCOPE: &str = "pinned-local-procurement-authorization-ledger-at-most-once-v1";

#[derive(Serialize)]
struct Marker<'a> {
    schema_version: u32,
    reservation_scope: &'a str,
    status: &'a str,
    local_challenge_reserved: bool,
    adapter_network_performed: bool,
    global_challenge_one_time_use_enforced: bool,
    inventory_reserved: bool,
    order_placed: bool,
    payment_performed: bool,
    ledger_id: &'a str,
    authorization_report_summary: Summary<'a>,
}

#[derive(Serialize)]
struct Summary<'a> {
    schema_version: u32,
    status: &'a str,
    procurement_authorized: bool,
    authorization_id: &'a str,
    challenge: &'a str,
    supplier: &'a str,
    offer_id: &'a str,
    requested_boards: u32,
    currency: &'a str,
    component_subtotal_micros: u64,
    maximum_component_subtotal_micros: u64,
    offer_valid_from_unix: u64,
    offer_valid_until_unix: u64,
    receipt_fetched_at_unix: u64,
    maximum_receipt_observation_age_seconds: u64,
    valid_from_unix: u64,
    expires_at_unix: u64,
    evaluated_at_unix: u64,
    approvals: u32,
    rejections: u32,
    gate_failure_count: u32,
    current_availability_verified: bool,
    supplier_authenticity_verified: bool,
    offer_authenticity_verified: bool,
    price_authenticity_verified: bool,
    receipt_observation_authenticity_verified: bool,
    policy_pack_authenticity_verified: bool,
    trusted_time_verified: bool,
    challenge_one_time_use_enforced: bool,
    report_bytes: u64,
    report_sha256: &'a str,
    report_binding_sha256: &'a str,
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
        inventory_reserved: false,
        order_placed: false,
        payment_performed: false,
        ledger_id: DIGEST,
        authorization_report_summary: Summary {
            schema_version: 1,
            status: "procurement_authorized",
            procurement_authorized: true,
            authorization_id: "release-1472",
            challenge: DIGEST,
            supplier: "supplier-a",
            offer_id: "offer-1",
            requested_boards: 25,
            currency: "USD",
            component_subtotal_micros: 10_000_000,
            maximum_component_subtotal_micros: 11_000_000,
            offer_valid_from_unix: current - 60,
            offer_valid_until_unix: current + 600,
            receipt_fetched_at_unix: current - 10,
            maximum_receipt_observation_age_seconds: 300,
            valid_from_unix: current - 30,
            expires_at_unix: current + 300,
            evaluated_at_unix: current,
            approvals: 2,
            rejections: 0,
            gate_failure_count: 0,
            current_availability_verified: false,
            supplier_authenticity_verified: false,
            offer_authenticity_verified: false,
            price_authenticity_verified: false,
            receipt_observation_authenticity_verified: false,
            policy_pack_authenticity_verified: false,
            trusted_time_verified: false,
            challenge_one_time_use_enforced: false,
            report_bytes: 4_096,
            report_sha256: DIGEST,
            report_binding_sha256: DIGEST,
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
        .arg("internal-reserve-procurement-authorization")
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
fn create_ledger(root: &Path) -> std::path::PathBuf {
    let ledger = root.join("ledger");
    fs::create_dir(&ledger).unwrap();
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        ledger.join(".pcbex-procurement-authorization-reservation-ledger-v1.json"),
        manifest(),
    )
    .unwrap();
    ledger
}

#[test]
#[cfg(unix)]
fn helper_commits_once_and_existing_corrupt_marker_burns_challenge() {
    let workspace = tempfile::tempdir().unwrap();
    let marker_path = workspace.path().join("marker.json");
    let marker_raw = marker(now());
    fs::write(&marker_path, &marker_raw).unwrap();
    let protected = workspace.path().join("source.json");
    fs::write(&protected, "source").unwrap();
    let ledger = create_ledger(workspace.path());
    let final_path = ledger.join(format!(
        "procurement-authorization-reservation-v1-{DIGEST}.json"
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

    let second_workspace = tempfile::tempdir().unwrap();
    let second_marker = second_workspace.path().join("marker.json");
    fs::write(&second_marker, marker(now())).unwrap();
    let second_protected = second_workspace.path().join("source.json");
    fs::write(&second_protected, "source").unwrap();
    let second_ledger = create_ledger(second_workspace.path());
    let corrupt = second_ledger.join(format!(
        "procurement-authorization-reservation-v1-{DIGEST}.json"
    ));
    fs::write(&corrupt, b"corrupt-but-burned\n").unwrap();
    let output = run(&second_marker, &second_ledger, &second_protected);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("challenge is already reserved"));
    assert_eq!(fs::read(corrupt).unwrap(), b"corrupt-but-burned\n");
}

#[test]
#[cfg(unix)]
fn helper_rejects_insecure_ledger_and_input_overlap() {
    let workspace = tempfile::tempdir().unwrap();
    let marker_path = workspace.path().join("marker.json");
    fs::write(&marker_path, marker(now())).unwrap();
    let protected = workspace.path().join("source.json");
    fs::write(&protected, "source").unwrap();
    let ledger = create_ledger(workspace.path());
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o755)).unwrap();
    let insecure = run(&marker_path, &ledger, &protected);
    assert!(!insecure.status.success());
    assert!(String::from_utf8_lossy(&insecure.stderr).contains("exactly 0700"));

    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).unwrap();
    let inside = ledger.join("source.json");
    fs::write(&inside, "source").unwrap();
    let overlap = run(&marker_path, &ledger, &inside);
    assert!(!overlap.status.success());
    assert!(String::from_utf8_lossy(&overlap.stderr).contains("must not contain or alias input"));

    let outside = workspace.path().join("outside.json");
    fs::write(&outside, "outside").unwrap();
    let outward_link = ledger.join("outward-source.json");
    symlink(&outside, &outward_link).unwrap();
    let lexical_overlap = run(&marker_path, &ledger, &outward_link);
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
    assert!(text.contains("procurement-authorization-reservation-schema"));
    assert!(text.contains("procurement-authorization-reservation-ledger-schema"));
    assert!(!text.contains("internal-reserve-procurement-authorization"));

    for command in [
        "procurement-authorization-reservation-schema",
        "procurement-authorization-reservation-ledger-schema",
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

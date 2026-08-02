use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

#[test]
fn factory_schema_is_closed_and_never_overwrites_output() {
    let temporary = tempfile::tempdir().unwrap();
    let output_path = temporary.path().join("factory-receipt.schema.json");
    let first = Command::new(binary())
        .args(["factory-schema", "--output"])
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let schema: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(
        schema["properties"]["findings"]["items"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["properties"]["endpoint"]["anyOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let sentinel = b"preserve-existing-receipt\n";
    fs::write(&output_path, sentinel).unwrap();
    let overwrite = Command::new(binary())
        .args(["factory-schema", "--output"])
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!overwrite.status.success());
    assert_eq!(fs::read(&output_path).unwrap(), sentinel);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let target = temporary.path().join("target.json");
        let link = temporary.path().join("receipt-link.json");
        fs::write(&target, sentinel).unwrap();
        symlink(&target, &link).unwrap();
        let symlink_output = Command::new(binary())
            .args(["factory-schema", "--output"])
            .arg(&link)
            .output()
            .unwrap();
        assert!(!symlink_output.status.success());
        assert_eq!(fs::read(&target).unwrap(), sentinel);
    }
}

#[test]
fn factory_submit_rejects_an_existing_receipt_before_network_access() {
    let temporary = tempfile::tempdir().unwrap();
    let package = temporary.path().join("manufacturing.zip");
    let receipt = temporary.path().join("receipt.json");
    fs::write(&package, b"not-read-before-output-preflight").unwrap();
    fs::write(&receipt, b"preserve-existing-receipt\n").unwrap();

    let output = Command::new(binary())
        .arg("factory-submit")
        .arg(&package)
        .args([
            "--endpoint",
            "http://127.0.0.1:9/quote",
            "--allow-http-loopback",
            "--output",
        ])
        .arg(&receipt)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite existing output")
    );
    assert_eq!(fs::read(&receipt).unwrap(), b"preserve-existing-receipt\n");
}

#[test]
fn failed_factory_submission_removes_the_prepared_output() {
    let temporary = tempfile::tempdir().unwrap();
    let package = temporary.path().join("manufacturing.zip");
    let receipt = temporary.path().join("receipt.json");
    fs::write(&package, b"not-a-zip").unwrap();

    let output = Command::new(binary())
        .arg("factory-submit")
        .arg(&package)
        .args([
            "--endpoint",
            "http://127.0.0.1:9/quote",
            "--allow-http-loopback",
            "--output",
        ])
        .arg(&receipt)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a valid ZIP archive"));
    assert!(!receipt.exists());
    let names = fs::read_dir(temporary.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(names, vec![package.file_name().unwrap().to_os_string()]);
}

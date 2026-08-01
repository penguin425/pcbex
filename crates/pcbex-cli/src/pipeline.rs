//! Final deterministic gate for the hardware development pipeline.

use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
pub struct PipelinePhase {
    pub name: String,
    pub input: String,
    pub passed: bool,
    pub checks: Vec<String>,
    pub failures: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PipelineGateReport {
    pub schema_version: u32,
    pub pipeline: &'static str,
    pub phases: Vec<PipelinePhase>,
    pub passed: bool,
    pub failures: Vec<String>,
}

/// Validate every phase artifact and return a report suitable for CI retention.
/// Verify the complete pipeline, optionally including a factory DFM receipt.
///
/// The legacy five-phase entry point remains available for existing CI.  New
/// production pipelines should pass a receipt and `require_factory=true` so a
/// quote/DFM response is a mandatory, package-digest-bound phase.
pub fn verify_pipeline_with_factory(
    electrical_review: &Path,
    analysis_manifest: &Path,
    quality: &Path,
    manufacturing_manifest: &Path,
    firmware_manifest: &Path,
    factory_receipt: Option<&Path>,
    require_factory: bool,
) -> PipelineGateReport {
    let phases = vec![
        electrical_phase(electrical_review),
        analysis_phase(analysis_manifest),
        quality_phase(quality),
        manufacturing_phase(manufacturing_manifest),
        firmware_phase(firmware_manifest),
    ]
    .into_iter()
    .chain(match (factory_receipt, require_factory) {
        (Some(path), _) => Some(factory_phase(path, manufacturing_manifest)),
        (None, true) => Some(required_factory_phase()),
        (None, false) => None,
    })
    .collect::<Vec<_>>();
    let failures = phases
        .iter()
        .flat_map(|phase| {
            phase
                .failures
                .iter()
                .map(|failure| format!("{}: {failure}", phase.name))
        })
        .collect::<Vec<_>>();
    PipelineGateReport {
        schema_version: 1,
        pipeline: "pcbex-hardware-v1",
        passed: failures.is_empty(),
        phases,
        failures,
    }
}

pub fn pipeline_gate_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/pipeline-gate-v1.json",
        "title": "pcbex deterministic hardware pipeline gate",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "pipeline", "phases", "passed", "failures"],
        "properties": {
            "schema_version": {"const": 1},
            "pipeline": {"const": "pcbex-hardware-v1"},
            "phases": {"type": "array", "items": {"$ref": "#/$defs/phase"}},
            "passed": {"type": "boolean"},
            "failures": {"type": "array", "items": {"type": "string"}}
        },
        "$defs": {
            "phase": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "input", "passed", "checks", "failures"],
                "properties": {
                    "name": {"type": "string"},
                    "input": {"type": "string"},
                    "passed": {"type": "boolean"},
                    "checks": {"type": "array", "items": {"type": "string"}},
                    "failures": {"type": "array", "items": {"type": "string"}}
                }
            }
        }
    })
}

fn electrical_phase(path: &Path) -> PipelinePhase {
    let mut phase = phase("electrical-erc", path);
    let value = match read_json(path) {
        Ok(value) => value,
        Err(error) => {
            phase.failures.push(error);
            return finish(phase);
        }
    };
    let approved = value.get("approved").and_then(Value::as_bool);
    let errors = value
        .get("counts")
        .and_then(|counts| counts.get("errors"))
        .and_then(Value::as_u64);
    phase.checks.push(format!("approved={approved:?}"));
    phase.checks.push(format!("errors={errors:?}"));
    if approved != Some(true) {
        phase
            .failures
            .push("electrical review is not approved".into());
    }
    if errors != Some(0) {
        phase
            .failures
            .push("electrical review contains error findings".into());
    }
    finish(phase)
}

fn analysis_phase(path: &Path) -> PipelinePhase {
    let mut phase = phase("analysis-drc", path);
    let value = match read_json(path) {
        Ok(value) => value,
        Err(error) => {
            phase.failures.push(error);
            return finish(phase);
        }
    };
    let clean = value
        .get("result")
        .and_then(|result| result.get("clean"))
        .and_then(Value::as_bool);
    let violations = value
        .get("result")
        .and_then(|result| result.get("violations"))
        .and_then(Value::as_u64);
    phase.checks.push(format!("clean={clean:?}"));
    phase.checks.push(format!("violations={violations:?}"));
    if clean != Some(true) || violations != Some(0) {
        phase
            .failures
            .push("analysis/DRC result is not clean".into());
    }
    finish(phase)
}

fn quality_phase(path: &Path) -> PipelinePhase {
    let mut phase = phase("routing-quality", path);
    let value = match read_json(path) {
        Ok(value) => value,
        Err(error) => {
            phase.failures.push(error);
            return finish(phase);
        }
    };
    let unrouted = value.get("unrouted_nets").and_then(Value::as_u64);
    phase.checks.push(format!("unrouted_nets={unrouted:?}"));
    if unrouted != Some(0) {
        phase
            .failures
            .push("routing quality has unrouted nets".into());
    }
    finish(phase)
}

fn manufacturing_phase(path: &Path) -> PipelinePhase {
    let mut phase = phase("manufacturing-package", path);
    let value = match read_json(path) {
        Ok(value) => value,
        Err(error) => {
            phase.failures.push(error);
            return finish(phase);
        }
    };
    if value.get("schema_version").and_then(Value::as_u64) != Some(1) {
        phase
            .failures
            .push("manufacturing manifest schema_version is not 1".into());
    }
    let Some(directory) = path.parent() else {
        phase
            .failures
            .push("manufacturing manifest has no parent directory".into());
        return finish(phase);
    };
    let archive = value.get("archive").and_then(Value::as_str);
    if let Some(archive) = archive {
        phase.checks.push(format!("archive={archive}"));
        if !safe_relative_path(archive) || !directory.join(archive).is_file() {
            phase
                .failures
                .push("manufacturing archive is missing or unsafe".into());
        }
    } else {
        phase
            .failures
            .push("manufacturing manifest has no archive".into());
    }
    for required in ["bom.csv", "cpl.csv", "drc.rpt"] {
        if directory.join(required).is_file() {
            phase.checks.push(format!("present={required}"));
        } else {
            phase.failures.push(format!(
                "required manufacturing artifact {required} is missing"
            ));
        }
    }
    let mut seen = BTreeSet::new();
    let Some(artifacts) = value.get("artifacts").and_then(Value::as_array) else {
        phase
            .failures
            .push("manufacturing manifest artifacts is not an array".into());
        return finish(phase);
    };
    for artifact in artifacts {
        let Some(artifact_path) = artifact.get("path").and_then(Value::as_str) else {
            phase
                .failures
                .push("manufacturing artifact path is missing".into());
            continue;
        };
        let Some(expected) = artifact.get("sha256").and_then(Value::as_str) else {
            phase
                .failures
                .push(format!("{artifact_path}: SHA-256 is missing"));
            continue;
        };
        let expected_bytes = artifact.get("bytes").and_then(Value::as_u64);
        if !safe_relative_path(artifact_path) || !seen.insert(artifact_path.to_string()) {
            phase.failures.push(format!(
                "{artifact_path}: unsafe or duplicate artifact path"
            ));
            continue;
        }
        let artifact_path = directory.join(artifact_path);
        if let Some(expected_bytes) = expected_bytes {
            match fs::metadata(&artifact_path) {
                Ok(metadata) if metadata.len() == expected_bytes => {}
                Ok(metadata) => phase.failures.push(format!(
                    "{}: byte count mismatch (expected {expected_bytes}, got {})",
                    artifact_path.display(),
                    metadata.len()
                )),
                Err(error) => phase.failures.push(format!(
                    "{}: cannot read artifact metadata: {error}",
                    artifact_path.display()
                )),
            }
        } else {
            phase.failures.push(format!(
                "{}: byte count is missing",
                artifact_path.display()
            ));
        }
        match sha256_file(&artifact_path) {
            Ok(actual) if actual == expected => phase.checks.push(format!(
                "hash-ok={}",
                artifact_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            )),
            Ok(actual) => phase.failures.push(format!(
                "{}: SHA-256 mismatch (expected {expected}, got {actual})",
                artifact_path.display()
            )),
            Err(error) => phase.failures.push(error),
        }
    }
    finish(phase)
}

fn firmware_phase(path: &Path) -> PipelinePhase {
    let mut phase = phase("firmware-build", path);
    let value = match read_json(path) {
        Ok(value) => value,
        Err(error) => {
            phase.failures.push(error);
            return finish(phase);
        }
    };
    if value.get("schema_version").and_then(Value::as_u64) != Some(1) {
        phase
            .failures
            .push("firmware manifest schema_version is not 1".into());
    }
    for (name, key) in [
        ("C build", "c_build"),
        ("C++ build", "cpp_build"),
        ("Python check", "python_check"),
    ] {
        let passed = value
            .get(key)
            .and_then(|build| build.get("passed"))
            .and_then(Value::as_bool);
        phase.checks.push(format!("{key}.passed={passed:?}"));
        if passed != Some(true) {
            phase.failures.push(format!("{name} gate did not pass"));
        }
    }
    let Some(directory) = path.parent() else {
        phase
            .failures
            .push("firmware manifest has no parent directory".into());
        return finish(phase);
    };
    let Some(files) = value.get("files").and_then(Value::as_array) else {
        phase
            .failures
            .push("firmware manifest files is not an array".into());
        return finish(phase);
    };
    for file in files.iter().filter_map(Value::as_str) {
        if !safe_relative_path(file) || !directory.join(file).is_file() {
            phase
                .failures
                .push(format!("firmware artifact {file} is missing or unsafe"));
        } else {
            phase.checks.push(format!("present={file}"));
        }
    }
    finish(phase)
}

fn required_factory_phase() -> PipelinePhase {
    let phase = PipelinePhase {
        name: "factory-dfm".into(),
        input: "<missing>".into(),
        passed: false,
        checks: Vec::new(),
        failures: vec!["factory receipt is required for the full pipeline".into()],
    };
    finish(phase)
}

fn factory_phase(receipt_path: &Path, manufacturing_manifest: &Path) -> PipelinePhase {
    let mut phase = phase("factory-dfm", receipt_path);
    let value = match read_json(receipt_path) {
        Ok(value) => value,
        Err(error) => {
            phase.failures.push(error);
            return finish(phase);
        }
    };
    if value.get("schema_version").and_then(Value::as_u64) != Some(1) {
        phase
            .failures
            .push("factory receipt schema_version is not 1".into());
    }
    if value
        .get("provider")
        .and_then(Value::as_str)
        .is_none_or(|provider| !matches!(provider, "jlcpcb" | "pcbway" | "generic"))
    {
        phase
            .failures
            .push("factory receipt has an unsupported provider".into());
    }
    let endpoint = value.get("endpoint").and_then(Value::as_str);
    if endpoint.is_none_or(|endpoint| !endpoint.starts_with("https://")) {
        phase
            .failures
            .push("factory receipt endpoint is not HTTPS".into());
    }
    let accepted = value.get("accepted").and_then(Value::as_bool);
    let dfm_passed = value.get("dfm_passed").and_then(Value::as_bool);
    phase.checks.push(format!("accepted={accepted:?}"));
    phase.checks.push(format!("dfm_passed={dfm_passed:?}"));
    if accepted != Some(true) {
        phase
            .failures
            .push("factory submission was not accepted".into());
    }
    if dfm_passed != Some(true) {
        phase
            .failures
            .push("factory DFM feedback did not pass".into());
    }
    let status = value.get("http_status").and_then(Value::as_u64);
    if status.is_none_or(|status| !(200..=299).contains(&status)) {
        phase
            .failures
            .push("factory receipt HTTP status is not successful".into());
    }
    let package_digest = value.get("package_sha256").and_then(Value::as_str);
    if package_digest.is_none_or(|digest| !is_sha256(digest)) {
        phase
            .failures
            .push("factory receipt package_sha256 is invalid".into());
    }
    let package_bytes = value.get("package_bytes").and_then(Value::as_u64);
    if package_bytes.is_none_or(|bytes| bytes == 0) {
        phase
            .failures
            .push("factory receipt package_bytes is invalid".into());
    }
    let findings = value.get("findings").and_then(Value::as_array);
    if let Some(findings) = findings {
        let severe = findings
            .iter()
            .filter(|finding| {
                finding
                    .get("severity")
                    .and_then(Value::as_str)
                    .is_some_and(|severity| {
                        matches!(
                            severity.to_ascii_lowercase().as_str(),
                            "error" | "critical" | "fatal"
                        )
                    })
            })
            .count();
        phase.checks.push(format!("severe_findings={severe}"));
        if severe != 0 {
            phase.failures.push(format!(
                "factory receipt contains {severe} severe finding(s)"
            ));
        }
    } else {
        phase
            .failures
            .push("factory receipt findings is not an array".into());
    }
    if let (Some(expected), Some(bytes), Some(archive)) = (
        package_digest,
        package_bytes,
        archive_from_manifest(manufacturing_manifest),
    ) {
        match fs::read(&archive) {
            Ok(contents) => {
                let actual = hex::encode(Sha256::digest(&contents));
                phase
                    .checks
                    .push(format!("package_bytes={}", contents.len()));
                if bytes != contents.len() as u64 || expected != actual {
                    phase.failures.push(format!(
                        "factory package digest/size does not match {}",
                        archive.display()
                    ));
                }
            }
            Err(error) => phase.failures.push(format!(
                "cannot read factory package {}: {error}",
                archive.display()
            )),
        }
    }
    finish(phase)
}

fn archive_from_manifest(manifest: &Path) -> Option<std::path::PathBuf> {
    let value = read_json(manifest).ok()?;
    let archive = value.get("archive").and_then(Value::as_str)?;
    if !safe_relative_path(archive) {
        return None;
    }
    Some(manifest.parent()?.join(archive))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn phase(name: &str, path: &Path) -> PipelinePhase {
    PipelinePhase {
        name: name.into(),
        input: path.display().to_string(),
        passed: false,
        checks: Vec::new(),
        failures: Vec::new(),
    }
}

fn finish(mut phase: PipelinePhase) -> PipelinePhase {
    phase.passed = phase.failures.is_empty();
    phase
}

fn read_json(path: &Path) -> Result<Value, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("{}: cannot read JSON: {error}", path.display()))?;
    serde_json::from_str(&source)
        .map_err(|error| format!("{}: invalid JSON: {error}", path.display()))
}

fn safe_relative_path(path: &str) -> bool {
    let candidate = Path::new(path);
    !candidate.is_absolute()
        && !candidate.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        })
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("{}: cannot read artifact: {error}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn rejects_missing_and_tampered_phase_outputs() {
        let path = PathBuf::from("/tmp/pcbex-missing-phase.json");
        let report = verify_pipeline_with_factory(&path, &path, &path, &path, &path, None, false);
        assert!(!report.passed);
        assert_eq!(report.phases.len(), 5);
        assert!(
            report
                .failures
                .iter()
                .all(|failure| failure.contains("cannot read JSON"))
        );
    }

    #[test]
    fn validates_safe_relative_paths() {
        assert!(safe_relative_path("bom.csv"));
        assert!(safe_relative_path("nested/bom.csv"));
        assert!(!safe_relative_path("../bom.csv"));
        assert!(!safe_relative_path("/tmp/bom.csv"));
    }

    #[test]
    fn accepts_a_complete_hash_bound_pipeline() {
        let root = std::env::temp_dir().join(format!("pcbex-pipeline-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let electrical = root.join("electrical.json");
        let analysis = root.join("run.json");
        let quality = root.join("quality.json");
        let manufacturing = root.join("manifest.json");
        let firmware = root.join("firmware-manifest.json");
        fs::write(&electrical, r#"{"approved":true,"counts":{"errors":0}}"#).unwrap();
        fs::write(&analysis, r#"{"result":{"clean":true,"violations":0}}"#).unwrap();
        fs::write(&quality, r#"{"unrouted_nets":0}"#).unwrap();
        for file in ["bom.csv", "cpl.csv", "drc.rpt", "manufacturing.zip"] {
            fs::write(root.join(file), file).unwrap();
        }
        let artifacts = ["bom.csv", "cpl.csv", "drc.rpt"]
            .iter()
            .map(|file| {
                let bytes = fs::read(root.join(file)).unwrap();
                json!({"path": file, "bytes": bytes.len(), "sha256": hex::encode(Sha256::digest(bytes))})
            })
            .collect::<Vec<_>>();
        fs::write(
            &manufacturing,
            serde_json::to_vec(
                &json!({"schema_version":1,"archive":"manufacturing.zip","artifacts":artifacts}),
            )
            .unwrap(),
        )
        .unwrap();
        for file in ["pinout.h", "firmware.h", "firmware.c", "host.py"] {
            fs::write(root.join(file), file).unwrap();
        }
        fs::write(
            &firmware,
            br#"{"schema_version":1,"files":["pinout.h","firmware.h","firmware.c","host.py"],"c_build":{"passed":true},"cpp_build":{"passed":true},"python_check":{"passed":true}}"#,
        )
        .unwrap();
        let report = verify_pipeline_with_factory(
            &electrical,
            &analysis,
            &quality,
            &manufacturing,
            &firmware,
            None,
            false,
        );
        assert!(report.passed, "{}", report.failures.join("; "));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_factory_dfm_receipt_bound_to_manufacturing_archive() {
        let root =
            std::env::temp_dir().join(format!("pcbex-pipeline-factory-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let electrical = root.join("electrical.json");
        let analysis = root.join("run.json");
        let quality = root.join("quality.json");
        let manufacturing = root.join("manifest.json");
        let firmware = root.join("firmware-manifest.json");
        let receipt = root.join("factory-receipt.json");
        fs::write(&electrical, r#"{"approved":true,"counts":{"errors":0}}"#).unwrap();
        fs::write(&analysis, r#"{"result":{"clean":true,"violations":0}}"#).unwrap();
        fs::write(&quality, r#"{"unrouted_nets":0}"#).unwrap();
        for file in ["bom.csv", "cpl.csv", "drc.rpt"] {
            fs::write(root.join(file), file).unwrap();
        }
        let archive_bytes = b"factory archive";
        fs::write(root.join("manufacturing.zip"), archive_bytes).unwrap();
        fs::write(
            &manufacturing,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "archive": "manufacturing.zip",
                "artifacts": []
            }))
            .unwrap(),
        )
        .unwrap();
        for file in ["pinout.h", "firmware.h", "firmware.c", "host.py"] {
            fs::write(root.join(file), file).unwrap();
        }
        fs::write(
            &firmware,
            br#"{"schema_version":1,"files":["pinout.h","firmware.h","firmware.c","host.py"],"c_build":{"passed":true},"cpp_build":{"passed":true},"python_check":{"passed":true}}"#,
        )
        .unwrap();
        fs::write(
            &receipt,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "provider": "generic",
                "endpoint": "https://factory.example/quote",
                "package_sha256": hex::encode(Sha256::digest(archive_bytes)),
                "package_bytes": archive_bytes.len(),
                "accepted": true,
                "dfm_passed": true,
                "http_status": 200,
                "findings": []
            }))
            .unwrap(),
        )
        .unwrap();
        let report = verify_pipeline_with_factory(
            &electrical,
            &analysis,
            &quality,
            &manufacturing,
            &firmware,
            Some(&receipt),
            true,
        );
        assert!(report.passed, "{}", report.failures.join("; "));
        assert_eq!(report.phases.len(), 6);
        fs::remove_dir_all(root).unwrap();
    }
}

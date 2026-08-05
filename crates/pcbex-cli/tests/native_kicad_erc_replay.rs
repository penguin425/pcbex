#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    const ERC_SCHEMA: &str = "https://schemas.kicad.org/erc.v1.json";

    fn binary() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
    }

    fn fake_cli(directory: &Path, raw_report: &str, status: i32) -> PathBuf {
        let path = directory.join(format!("fake-kicad-erc-{status}.sh"));
        let script = format!(
            concat!(
                "#!/bin/sh\n",
                "set -eu\n",
                "report=''\n",
                "input=''\n",
                "while [ \"$#\" -gt 0 ]; do\n",
                "  if [ \"$1\" = '--output' ]; then report=\"$2\"; shift 2; else input=\"$1\"; shift; fi\n",
                "done\n",
                "if [ -n \"${{PCBEX_MUTATE_SCHEMATIC:-}}\" ]; then printf '%s' mutation >> \"$PCBEX_MUTATE_SCHEMATIC\"; fi\n",
                "cat > \"$report\" <<'PCBEX_NATIVE_ERC_REPORT'\n",
                "{}\n",
                "PCBEX_NATIVE_ERC_REPORT\n",
                "exit {}\n"
            ),
            raw_report, status
        );
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn run<I, S>(args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        Command::new(binary()).args(args).output().unwrap()
    }

    fn run_with_env<I, S>(args: I, key: &str, value: &Path) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        Command::new(binary())
            .args(args)
            .env(key, value)
            .output()
            .unwrap()
    }

    fn approved_report() -> String {
        format!(
            concat!(
                "{{\"$schema\":\"{}\",\"coordinate_units\":\"mm\",",
                "\"date\":\"now\",\"ignored_checks\":[],",
                "\"included_severities\":[\"error\"],\"kicad_version\":\"10.0.5\",",
                "\"sheets\":[{{\"path\":\"/\",\"uuid_path\":\"/root\",\"violations\":[]}}],",
                "\"source\":\"input.kicad_sch\"}}"
            ),
            ERC_SCHEMA
        )
    }

    fn rejected_report() -> String {
        format!(
            concat!(
                "{{\"$schema\":\"{}\",\"coordinate_units\":\"mm\",",
                "\"date\":\"now\",\"ignored_checks\":[],",
                "\"included_severities\":[\"error\"],\"kicad_version\":\"10.0.5\",",
                "\"sheets\":[{{\"path\":\"/\",\"uuid_path\":\"/root\",\"violations\":[",
                "{{\"description\":\"unconnected\",\"items\":[",
                "{{\"description\":\"U1 pin 1\",\"pos\":{{\"x\":1.0,\"y\":2.0}},",
                "\"uuid\":\"00000000-0000-0000-0000-000000000001\"}}],",
                "\"severity\":\"error\",\"type\":\"pin_not_connected\"}}]}}],",
                "\"source\":\"input.kicad_sch\"}}"
            ),
            ERC_SCHEMA
        )
    }

    fn warning_report() -> String {
        format!(
            concat!(
                "{{\"$schema\":\"{}\",\"coordinate_units\":\"mm\",",
                "\"date\":\"now\",\"ignored_checks\":[],",
                "\"included_severities\":[\"error\",\"warning\"],",
                "\"kicad_version\":\"10.0.5\",\"sheets\":[{{\"path\":\"/\",",
                "\"uuid_path\":\"/root\",\"violations\":[{{\"description\":\"warning\",",
                "\"items\":[{{\"description\":\"U1 pin 1\",\"pos\":{{\"x\":1.0,\"y\":2.0}},",
                "\"uuid\":\"00000000-0000-0000-0000-000000000002\"}}],",
                "\"severity\":\"warning\",\"type\":\"warning_type\"}}]}}],",
                "\"source\":\"input.kicad_sch\"}}"
            ),
            ERC_SCHEMA
        )
    }

    fn warning_policy(path: &Path) {
        fs::write(
            path,
            br#"{"schema_version":1,"id":"test-policy","maximum_total_warnings":0,"warning_limits":[{"finding_type":"warning_type","maximum_count":0}],"allowed_ignored_checks":[]}"#,
        )
        .unwrap();
    }

    #[test]
    fn verify_replays_approved_erc_without_writing_a_report() {
        let directory = tempfile::tempdir().unwrap();
        let schematic = directory.path().join("design.kicad_sch");
        let report = directory.path().join("erc.json");
        let cli = fake_cli(directory.path(), &approved_report(), 0);
        fs::write(&schematic, b"schematic").unwrap();

        let generated = run([
            "run-native-kicad-erc",
            schematic.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let retained = fs::read(&report).unwrap();

        let verified = run([
            "verify-native-kicad-erc-report",
            schematic.to_str().unwrap(),
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        assert!(verified.stdout.is_empty());
        assert_eq!(fs::read(&report).unwrap(), retained);
        assert!(String::from_utf8_lossy(&verified.stderr).contains("verification: approved"));
    }

    #[test]
    fn verify_replays_rejected_erc_unless_approval_is_required() {
        let directory = tempfile::tempdir().unwrap();
        let schematic = directory.path().join("design.kicad_sch");
        let report = directory.path().join("erc-rejected.json");
        let cli = fake_cli(directory.path(), &rejected_report(), 5);
        fs::write(&schematic, b"schematic").unwrap();

        let generated = run([
            "run-native-kicad-erc",
            schematic.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();

        let verified = run([
            "verify-native-kicad-erc-report",
            schematic.to_str().unwrap(),
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        assert!(String::from_utf8_lossy(&verified.stderr).contains("verification: rejected"));

        let required = run([
            "verify-native-kicad-erc-report",
            schematic.to_str().unwrap(),
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
            "--require-approved",
        ]);
        assert!(!required.status.success());
        assert!(
            String::from_utf8_lossy(&required.stderr)
                .contains("native KiCad schematic ERC rejected")
        );
        assert_eq!(fs::read(&report).unwrap(), retained);
    }

    #[test]
    fn warning_policy_replay_preserves_rejected_evidence_contract() {
        let directory = tempfile::tempdir().unwrap();
        let schematic = directory.path().join("design.kicad_sch");
        let policy = directory.path().join("warning-policy.json");
        let report = directory.path().join("erc-warning.json");
        let cli = fake_cli(directory.path(), &warning_report(), 5);
        fs::write(&schematic, b"schematic").unwrap();
        warning_policy(&policy);

        let generated = run([
            "run-native-kicad-erc",
            schematic.to_str().unwrap(),
            "--warning-policy",
            policy.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let retained = fs::read(&report).unwrap();

        let verified = run([
            "verify-native-kicad-erc-report",
            schematic.to_str().unwrap(),
            report.to_str().unwrap(),
            "--warning-policy",
            policy.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
            "--mcp-echo-report-summary",
        ]);
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        let summary: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
        assert_eq!(summary["schema_version"], 2);
        assert_eq!(summary["approved"], false);
        assert_eq!(summary["warning_count"], 1);
        assert_eq!(summary["policy_failure_count"], 2);

        let required = run([
            "verify-native-kicad-erc-report",
            schematic.to_str().unwrap(),
            report.to_str().unwrap(),
            "--warning-policy",
            policy.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
            "--require-approved",
        ]);
        assert!(!required.status.success());
        assert!(
            String::from_utf8_lossy(&required.stderr)
                .contains("native KiCad schematic ERC warning policy rejected")
        );
        assert_eq!(fs::read(&report).unwrap(), retained);
    }

    #[test]
    fn fresh_replay_mismatch_preserves_retained_report() {
        let directory = tempfile::tempdir().unwrap();
        let schematic = directory.path().join("design.kicad_sch");
        let report = directory.path().join("erc.json");
        let approved = fake_cli(directory.path(), &approved_report(), 0);
        let rejected = fake_cli(directory.path(), &rejected_report(), 5);
        fs::write(&schematic, b"schematic").unwrap();

        let generated = run([
            "run-native-kicad-erc",
            schematic.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            approved.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();

        let verified = run([
            "verify-native-kicad-erc-report",
            schematic.to_str().unwrap(),
            report.to_str().unwrap(),
            "--kicad-cli",
            rejected.to_str().unwrap(),
        ]);
        assert!(!verified.status.success());
        assert!(
            String::from_utf8_lossy(&verified.stderr)
                .contains("does not match a fresh native KiCad ERC run")
        );
        assert_eq!(fs::read(&report).unwrap(), retained);
    }

    #[test]
    fn run_rejects_schematic_mutation_before_publishing_report() {
        let directory = tempfile::tempdir().unwrap();
        let schematic = directory.path().join("design.kicad_sch");
        let report = directory.path().join("erc.json");
        let cli = fake_cli(directory.path(), &approved_report(), 0);
        fs::write(&schematic, b"schematic").unwrap();

        let result = run_with_env(
            [
                "run-native-kicad-erc",
                schematic.to_str().unwrap(),
                "--output",
                report.to_str().unwrap(),
                "--kicad-cli",
                cli.to_str().unwrap(),
            ],
            "PCBEX_MUTATE_SCHEMATIC",
            &schematic,
        );
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("KiCad schematic changed during native ERC")
        );
        assert!(!report.exists());
    }
}

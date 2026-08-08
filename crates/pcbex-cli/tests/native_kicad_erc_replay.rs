#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::thread;
    use std::time::{Duration, Instant};

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

    fn sleeping_cli(directory: &Path) -> PathBuf {
        let path = directory.join("sleeping-kicad-erc.sh");
        let script = concat!(
            "#!/bin/sh\n",
            "set -eu\n",
            "printf '%s\\n' \"$$\" > \"$PCBEX_FAKE_KICAD_PID\"\n",
            "sh -c 'printf started > \"$PCBEX_FAKE_KICAD_DESCENDANT_STARTED\"; sleep 0.6; printf survived > \"$PCBEX_FAKE_KICAD_SURVIVOR\"' &\n",
            "while [ ! -s \"$PCBEX_FAKE_KICAD_DESCENDANT_STARTED\" ]; do sleep 0.01; done\n",
            "sleep 30\n",
        );
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn process_is_alive(pid: &str) -> bool {
        Command::new("sh")
            .args(["-c", "kill -0 \"$1\" 2>/dev/null", "pcbex-test", pid])
            .status()
            .unwrap()
            .success()
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
            "--timeout-seconds",
            "1.5",
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
    fn explicit_timeout_terminates_and_reaps_fake_kicad_process_tree() {
        let directory = tempfile::tempdir().unwrap();
        let schematic = directory.path().join("design.kicad_sch");
        let report = directory.path().join("erc.json");
        let normal_cli = fake_cli(directory.path(), &approved_report(), 0);
        let sleeping_cli = sleeping_cli(directory.path());
        let pid_file = directory.path().join("sleeping-kicad.pid");
        let descendant_started = directory.path().join("sleeping-kicad-descendant-started");
        let survivor = directory.path().join("sleeping-kicad-survivor");
        fs::write(&schematic, b"schematic").unwrap();

        let generated = run([
            "run-native-kicad-erc",
            schematic.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            normal_cli.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();

        let started = Instant::now();
        let timed_out = Command::new(binary())
            .args([
                "verify-native-kicad-erc-report",
                schematic.to_str().unwrap(),
                report.to_str().unwrap(),
                "--kicad-cli",
                sleeping_cli.to_str().unwrap(),
                "--timeout-seconds",
                "0.25",
            ])
            .env("PCBEX_FAKE_KICAD_PID", &pid_file)
            .env("PCBEX_FAKE_KICAD_DESCENDANT_STARTED", &descendant_started)
            .env("PCBEX_FAKE_KICAD_SURVIVOR", &survivor)
            .output()
            .unwrap();
        assert!(!timed_out.status.success());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "explicit timeout was not applied promptly"
        );
        assert!(
            String::from_utf8_lossy(&timed_out.stderr)
                .contains("subprocess exceeded timeout of 250ms"),
            "{}",
            String::from_utf8_lossy(&timed_out.stderr)
        );
        assert_eq!(fs::read(&report).unwrap(), retained);
        assert!(
            descendant_started.exists(),
            "fake KiCad descendant did not start before the timeout"
        );

        let pid = fs::read_to_string(&pid_file).unwrap();
        assert!(
            !process_is_alive(pid.trim()),
            "timed-out fake KiCad child was not reaped"
        );
        thread::sleep(Duration::from_millis(900));
        assert!(
            !survivor.exists(),
            "timed-out fake KiCad descendant survived process-tree cleanup"
        );
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

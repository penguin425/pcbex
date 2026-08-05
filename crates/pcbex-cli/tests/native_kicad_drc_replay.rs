#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    const DRC_SCHEMA: &str = "https://schemas.kicad.org/drc.v1.json";

    fn binary() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
    }

    fn fake_cli(directory: &Path, with_finding: bool) -> PathBuf {
        let path = directory.join(if with_finding {
            "fake-kicad-rejected.sh"
        } else {
            "fake-kicad-approved.sh"
        });
        let status = if with_finding { 5 } else { 0 };
        let violations = if with_finding {
            "[{\"description\":\"bad\",\"items\":[{\"description\":\"pad\",\"pos\":{\"x\":1.0,\"y\":2.0},\"uuid\":\"00000000-0000-0000-0000-000000000001\"}],\"severity\":\"error\",\"type\":\"clearance\"}]"
        } else {
            "[]"
        };
        let report = format!(
            "{{\"$schema\":\"{DRC_SCHEMA}\",\"coordinate_units\":\"mm\",\"date\":\"now\",\"included_severities\":[\"error\",\"warning\"],\"kicad_version\":\"10.0.5\",\"schematic_parity\":[],\"source\":\"input.kicad_pcb\",\"unconnected_items\":[],\"violations\":{violations}}}"
        );
        let script = format!(
            "#!/bin/sh\nout=''\ninput=''\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then out=$2; shift 2; else input=$1; shift; fi\ndone\nif [ -n \"$PCBEX_MUTATE_REPORT\" ]; then printf '%s' mutation >> \"$PCBEX_MUTATE_REPORT\"; fi\nif [ -n \"$PCBEX_MUTATE_BOARD\" ]; then printf '%s' mutation >> \"$input\"; fi\nif [ -n \"$PCBEX_MUTATE_PROJECT\" ]; then printf '%s' mutation >> \"$PCBEX_MUTATE_PROJECT\"; fi\nif [ -n \"$PCBEX_MUTATE_RULES\" ]; then printf '%s' mutation >> \"$PCBEX_MUTATE_RULES\"; fi\nprintf '%s' '{}' > \"$out\"\nexit {}\n",
            report, status
        );
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
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

    #[test]
    fn verify_replays_fresh_drc_without_writing_a_report() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("board.kicad_pcb");
        let project = directory.path().join("project.kicad_pro");
        let rules = directory.path().join("rules.kicad_dru");
        let report = directory.path().join("drc.json");
        let cli = fake_cli(directory.path(), false);
        fs::write(&board, b"board").unwrap();
        fs::write(&project, b"{}").unwrap();
        fs::write(&rules, b"(version 1)").unwrap();

        let generated = run([
            "run-native-kicad-drc",
            board.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
            "--project",
            project.to_str().unwrap(),
            "--rules-file",
            rules.to_str().unwrap(),
        ]);
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let retained = fs::read(&report).unwrap();

        let verified = run([
            "verify-native-kicad-drc-report",
            board.to_str().unwrap(),
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
            "--project",
            project.to_str().unwrap(),
            "--rules-file",
            rules.to_str().unwrap(),
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
    fn verify_rejects_fresh_report_mismatch_and_preserves_retained_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("board.kicad_pcb");
        let report = directory.path().join("drc.json");
        let approved_cli = fake_cli(directory.path(), false);
        let rejected_cli = fake_cli(directory.path(), true);
        fs::write(&board, b"board").unwrap();
        let generated = run([
            "run-native-kicad-drc",
            board.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            approved_cli.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();

        let verified = run([
            "verify-native-kicad-drc-report",
            board.to_str().unwrap(),
            report.to_str().unwrap(),
            "--kicad-cli",
            rejected_cli.to_str().unwrap(),
        ]);
        assert!(!verified.status.success());
        assert!(
            String::from_utf8_lossy(&verified.stderr)
                .contains("does not match a fresh native KiCad PCB DRC run")
        );
        assert_eq!(fs::read(&report).unwrap(), retained);
    }

    #[test]
    fn verify_detects_board_mutation_during_fresh_replay() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("board.kicad_pcb");
        let report = directory.path().join("drc.json");
        let cli = fake_cli(directory.path(), false);
        fs::write(&board, b"board").unwrap();
        let generated = run([
            "run-native-kicad-drc",
            board.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();
        let verified = run_with_env(
            [
                "verify-native-kicad-drc-report",
                board.to_str().unwrap(),
                report.to_str().unwrap(),
                "--kicad-cli",
                cli.to_str().unwrap(),
            ],
            "PCBEX_MUTATE_BOARD",
            &board,
        );
        assert!(!verified.status.success());
        assert!(
            String::from_utf8_lossy(&verified.stderr)
                .contains("staged KiCad PCB board changed during native DRC")
                || String::from_utf8_lossy(&verified.stderr)
                    .contains("KiCad PCB board changed during native DRC")
        );
        assert_eq!(fs::read(&report).unwrap(), retained);
    }

    #[test]
    fn verify_detects_project_mutation_during_fresh_replay() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("board.kicad_pcb");
        let project = directory.path().join("project.kicad_pro");
        let rules = directory.path().join("rules.kicad_dru");
        let report = directory.path().join("drc.json");
        let cli = fake_cli(directory.path(), false);
        fs::write(&board, b"board").unwrap();
        fs::write(&project, b"{}").unwrap();
        fs::write(&rules, b"(version 1)").unwrap();
        let generated = run([
            "run-native-kicad-drc",
            board.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--project",
            project.to_str().unwrap(),
            "--rules-file",
            rules.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();
        let verified = run_with_env(
            [
                "verify-native-kicad-drc-report",
                board.to_str().unwrap(),
                report.to_str().unwrap(),
                "--project",
                project.to_str().unwrap(),
                "--rules-file",
                rules.to_str().unwrap(),
                "--kicad-cli",
                cli.to_str().unwrap(),
            ],
            "PCBEX_MUTATE_PROJECT",
            &project,
        );
        assert!(!verified.status.success());
        let stderr = String::from_utf8_lossy(&verified.stderr);
        assert!(
            stderr.contains("KiCad PCB project changed during native DRC")
                || stderr.contains("KiCad PCB project changed during native DRC verification")
        );
        assert_eq!(fs::read(&report).unwrap(), retained);
    }

    #[test]
    fn verify_detects_rules_mutation_during_fresh_replay() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("board.kicad_pcb");
        let project = directory.path().join("project.kicad_pro");
        let rules = directory.path().join("rules.kicad_dru");
        let report = directory.path().join("drc.json");
        let cli = fake_cli(directory.path(), false);
        fs::write(&board, b"board").unwrap();
        fs::write(&project, b"{}").unwrap();
        fs::write(&rules, b"(version 1)").unwrap();
        let generated = run([
            "run-native-kicad-drc",
            board.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--project",
            project.to_str().unwrap(),
            "--rules-file",
            rules.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();
        let verified = run_with_env(
            [
                "verify-native-kicad-drc-report",
                board.to_str().unwrap(),
                report.to_str().unwrap(),
                "--project",
                project.to_str().unwrap(),
                "--rules-file",
                rules.to_str().unwrap(),
                "--kicad-cli",
                cli.to_str().unwrap(),
            ],
            "PCBEX_MUTATE_RULES",
            &rules,
        );
        assert!(!verified.status.success());
        let stderr = String::from_utf8_lossy(&verified.stderr);
        assert!(
            stderr.contains("KiCad PCB rules file changed during native DRC")
                || stderr.contains("KiCad PCB rules file changed during native DRC verification")
        );
        assert_eq!(fs::read(&report).unwrap(), retained);
    }

    #[test]
    fn verify_detects_retained_report_mutation_without_clobbering_it() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("board.kicad_pcb");
        let report = directory.path().join("drc.json");
        let cli = fake_cli(directory.path(), false);
        fs::write(&board, b"board").unwrap();
        let generated = run([
            "run-native-kicad-drc",
            board.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();
        let verified = run_with_env(
            [
                "verify-native-kicad-drc-report",
                board.to_str().unwrap(),
                report.to_str().unwrap(),
                "--kicad-cli",
                cli.to_str().unwrap(),
            ],
            "PCBEX_MUTATE_REPORT",
            &report,
        );
        assert!(!verified.status.success());
        assert!(
            String::from_utf8_lossy(&verified.stderr)
                .contains("retained native KiCad PCB DRC report changed during verification")
        );
        assert!(fs::read(&report).unwrap().starts_with(&retained));
    }

    #[test]
    fn verify_rejects_linked_and_noncanonical_retained_reports() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("board.kicad_pcb");
        let report = directory.path().join("drc.json");
        let cli = fake_cli(directory.path(), false);
        fs::write(&board, b"board").unwrap();
        let generated = run([
            "run-native-kicad-drc",
            board.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();

        let linked = directory.path().join("linked.json");
        std::os::unix::fs::symlink(&report, &linked).unwrap();
        let linked_result = run([
            "verify-native-kicad-drc-report",
            board.to_str().unwrap(),
            linked.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(!linked_result.status.success());
        assert_eq!(fs::read(&report).unwrap(), retained);

        let noncanonical = directory.path().join("noncanonical.json");
        let value: serde_json::Value = serde_json::from_slice(&retained).unwrap();
        let mut pretty = serde_json::to_vec_pretty(&value).unwrap();
        pretty.push(b'\n');
        fs::write(&noncanonical, &pretty).unwrap();
        let noncanonical_result = run([
            "verify-native-kicad-drc-report",
            board.to_str().unwrap(),
            noncanonical.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(!noncanonical_result.status.success());
        assert!(String::from_utf8_lossy(&noncanonical_result.stderr).contains("not canonical"));
        assert_eq!(fs::read(&noncanonical).unwrap(), pretty);
        assert_eq!(fs::read(&report).unwrap(), retained);
    }

    #[test]
    fn rejected_evidence_is_valid_unless_approval_is_required_and_mcp_summary_is_stable() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("board.kicad_pcb");
        let report = directory.path().join("drc.json");
        let cli = fake_cli(directory.path(), true);
        fs::write(&board, b"board").unwrap();
        let generated = run([
            "run-native-kicad-drc",
            board.to_str().unwrap(),
            "--output",
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
        ]);
        assert!(generated.status.success());
        let retained = fs::read(&report).unwrap();

        let verified = run([
            "verify-native-kicad-drc-report",
            board.to_str().unwrap(),
            report.to_str().unwrap(),
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
        for key in [
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
        ] {
            assert!(summary.get(key).is_some(), "missing summary key {key}");
        }
        assert_eq!(summary["approved"], false);
        assert_eq!(summary["error_count"], 1);
        assert_eq!(fs::read(&report).unwrap(), retained);

        let required = run([
            "verify-native-kicad-drc-report",
            board.to_str().unwrap(),
            report.to_str().unwrap(),
            "--kicad-cli",
            cli.to_str().unwrap(),
            "--require-approved",
        ]);
        assert!(!required.status.success());
        assert!(
            String::from_utf8_lossy(&required.stderr).contains("native KiCad PCB DRC rejected")
        );
        assert_eq!(fs::read(&report).unwrap(), retained);
    }
}

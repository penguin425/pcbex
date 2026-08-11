import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from pcbex_agent import cli


class AssemblyEvidenceCliV1467Tests(unittest.TestCase):
    @staticmethod
    def _required_arguments(root: Path, output: Path) -> list[str]:
        return [
            "pcbex-agent",
            "build-assembly-evidence",
            str(root / "handoff.zip"),
            str(root / "board.kicad_pcb"),
            str(root / "manufacturing.zip"),
            "--board-binding-report",
            str(root / "board-binding.json"),
            "--procurement-intent",
            str(root / "procurement-intent.json"),
            "--catalog-snapshot",
            str(root / "catalog-snapshot.json"),
            "--final-cpl-report",
            str(root / "final-cpl.json"),
            "--output",
            str(output),
        ]

    def test_help_exposes_the_closed_command_surface(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", "build-assembly-evidence", "--help"],
            ),
            redirect_stdout(stdout),
            self.assertRaises(SystemExit) as stopped,
        ):
            cli.main()
        self.assertEqual(stopped.exception.code, 0)
        help_text = stdout.getvalue()
        for value in (
            "HANDOFF_ZIP",
            "BOARD",
            "MANUFACTURING_ZIP",
            "--board-binding-report REPORT",
            "--procurement-intent INTENT",
            "--catalog-snapshot SNAPSHOT",
            "--final-cpl-report REPORT",
            "--output REPORT",
            "--board-binding-policy POLICY",
            "--manufacturing-kicad-cli CMD",
            "--manufacturing-kicad-project PATH",
            "--manufacturing-kicad-rules PATH",
            "--manufacturing-fab ID",
            "--manufacturing-fab-profile PATH",
            "--manufacturing-physical-profile PATH",
            "--expected-handoff-archive-sha256 HEX",
            "--expected-handoff-bundle-sha256 HEX",
            "--pcbex CMD",
            "--timeout-seconds SECONDS",
            "--require-complete",
        ):
            with self.subTest(value=value):
                self.assertIn(value, help_text)

    def test_parser_routes_every_option_and_writes_one_lf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "assembly-evidence.json"
            result = {
                "schema_version": 1,
                "status": "complete",
                "complete": True,
                "note": "完全",
            }
            rendered = b'{"rendered-by-core":true}\n'
            argv = [
                *self._required_arguments(root, output),
                "--board-binding-policy",
                str(root / "board-policy.json"),
                "--manufacturing-kicad-cli",
                "trusted-kicad-cli",
                "--manufacturing-kicad-project",
                str(root / "project.kicad_pro"),
                "--manufacturing-kicad-rules",
                str(root / "rules.json"),
                "--manufacturing-fab-profile",
                str(root / "fab.json"),
                "--expected-handoff-archive-sha256",
                "a" * 64,
                "--expected-handoff-bundle-sha256",
                "b" * 64,
                "--pcbex",
                "trusted-pcbex",
                "--timeout-seconds",
                "17.5",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli, "evaluate_assembly_evidence", return_value=result
                ) as evaluate,
                mock.patch.object(
                    cli, "render_assembly_evidence", return_value=rendered
                ) as render,
            ):
                cli.main()

            evaluate.assert_called_once_with(
                root / "handoff.zip",
                root / "board.kicad_pcb",
                root / "manufacturing.zip",
                root / "board-binding.json",
                root / "procurement-intent.json",
                root / "catalog-snapshot.json",
                root / "final-cpl.json",
                "trusted-pcbex",
                board_binding_policy=root / "board-policy.json",
                kicad_cli="trusted-kicad-cli",
                manufacturing_kicad_project=root / "project.kicad_pro",
                manufacturing_kicad_rules=root / "rules.json",
                manufacturing_fab=None,
                manufacturing_fab_profile=root / "fab.json",
                manufacturing_physical_profile=None,
                expected_archive_sha256="a" * 64,
                expected_bundle_sha256="b" * 64,
                timeout_seconds=17.5,
            )
            render.assert_called_once_with(result)
            self.assertEqual(output.read_bytes(), rendered)
            self.assertNotIn(b"\r", rendered)
            self.assertFalse(rendered.endswith(b"\n\n"))

    def test_profile_options_are_mutually_exclusive_before_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "assembly-evidence.json"
            argv = [
                *self._required_arguments(root, output),
                "--manufacturing-fab",
                "fab-id",
                "--manufacturing-physical-profile",
                str(root / "physical.json"),
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(cli, "evaluate_assembly_evidence") as evaluate,
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                cli.main()
            evaluate.assert_not_called()
            self.assertFalse(output.exists())

    def test_existing_output_fails_before_evaluation_and_is_not_clobbered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "assembly-evidence.json"
            retained = b"do not replace\n"
            output.write_bytes(retained)
            argv = self._required_arguments(root, output)
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(cli, "evaluate_assembly_evidence") as evaluate,
                mock.patch.object(cli, "render_assembly_evidence") as render,
                self.assertRaisesRegex(SystemExit, "already exists"),
            ):
                cli.main()
            evaluate.assert_not_called()
            render.assert_not_called()
            self.assertEqual(output.read_bytes(), retained)

    def test_incomplete_report_is_retained_before_require_complete_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "assembly-evidence.json"
            result = {
                "schema_version": 1,
                "status": "incomplete",
                "complete": False,
            }
            rendered = b'{"complete":false}\n'
            argv = [
                *self._required_arguments(root, output),
                "--require-complete",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli, "evaluate_assembly_evidence", return_value=result
                ) as evaluate,
                mock.patch.object(
                    cli, "render_assembly_evidence", return_value=rendered
                ) as render,
                self.assertRaisesRegex(SystemExit, "assembly evidence is incomplete"),
            ):
                cli.main()
            evaluate.assert_called_once_with(
                root / "handoff.zip",
                root / "board.kicad_pcb",
                root / "manufacturing.zip",
                root / "board-binding.json",
                root / "procurement-intent.json",
                root / "catalog-snapshot.json",
                root / "final-cpl.json",
                "pcbex",
                board_binding_policy=None,
                kicad_cli="kicad-cli",
                manufacturing_kicad_project=None,
                manufacturing_kicad_rules=None,
                manufacturing_fab=None,
                manufacturing_fab_profile=None,
                manufacturing_physical_profile=None,
                expected_archive_sha256=None,
                expected_bundle_sha256=None,
                timeout_seconds=120.0,
            )
            render.assert_called_once_with(result)
            self.assertEqual(output.read_bytes(), rendered)

    def test_schema_stdout_output_and_no_clobber_are_exact(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys, "argv", ["pcbex-agent", "assembly-evidence-schema"]
            ),
            redirect_stdout(stdout),
        ):
            cli.main()
        rendered = stdout.getvalue()
        self.assertTrue(rendered.endswith("\n"))
        self.assertFalse(rendered.endswith("\n\n"))
        self.assertNotIn("\r", rendered)
        schema = json.loads(rendered)
        self.assertFalse(schema["additionalProperties"])

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "assembly-evidence.schema.json"
            argv = [
                "pcbex-agent",
                "assembly-evidence-schema",
                "--output",
                str(output),
            ]
            with mock.patch.object(sys, "argv", argv):
                cli.main()
            retained = output.read_bytes()
            self.assertEqual(retained, rendered.encode("utf-8"))
            with (
                mock.patch.object(sys, "argv", argv),
                self.assertRaisesRegex(SystemExit, "already exists"),
            ):
                cli.main()
            self.assertEqual(output.read_bytes(), retained)


if __name__ == "__main__":
    unittest.main()

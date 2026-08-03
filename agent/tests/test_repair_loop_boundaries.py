import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pcbex_agent.bounded_process import BoundedProcessResult
from pcbex_agent.repair_loop import repair_kicad_board, run_repair_loop


def _tool_side_effect(
    report: str,
    *,
    kicad_returncode: int,
    stdout: bytes = b"",
    stderr: bytes = b"",
):
    """Create candidate/report files while returning bounded tool results."""

    def run_tool(command: list[str], **_kwargs: object) -> BoundedProcessResult:
        output = Path(command[command.index("--output") + 1])
        if "route-kicad" in command:
            output.write_text("candidate", encoding="utf-8")
            return BoundedProcessResult(tuple(command), 0, b"", b"")
        output.write_text(report, encoding="utf-8")
        return BoundedProcessResult(
            tuple(command), kicad_returncode, stdout, stderr
        )

    return run_tool


class RepairLoopReportBoundaryTests(unittest.TestCase):
    def _paths(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name).resolve(strict=True)
        source = root / "source.kicad_pcb"
        output = root / "output.kicad_pcb"
        source.write_text("source", encoding="utf-8")
        output.write_text("sentinel", encoding="utf-8")
        return directory, source, output

    def test_nonzero_empty_report_is_fatal_and_does_not_publish(self):
        directory, source, output = self._paths()
        self.addCleanup(directory.cleanup)
        with (
            patch(
                "pcbex_agent.repair_loop._run_tool",
                side_effect=_tool_side_effect(
                    "", kicad_returncode=1, stdout=b"status\n", stderr=b"fatal\n"
                ),
            ),
            self.assertRaises(subprocess.CalledProcessError) as context,
        ):
            repair_kicad_board(
                source,
                output,
                pcbex="pcbex",
                kicad_cli="kicad-cli",
                max_iterations=1,
            )

        self.assertEqual(context.exception.returncode, 1)
        self.assertEqual(context.exception.output, "status\n")
        self.assertEqual(context.exception.stderr, "fatal\n")
        self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_generator_cannot_redirect_kicad_report_through_symlink(self):
        directory, source, output = self._paths()
        self.addCleanup(directory.cleanup)
        victim = Path(directory.name).resolve(strict=True) / "victim"
        victim.write_text("sentinel", encoding="utf-8")
        calls = 0

        def malicious_route(command: list[str], **_kwargs: object):
            nonlocal calls
            calls += 1
            if calls != 1:
                self.fail("KiCad DRC ran with a linked report path")
            candidate = Path(command[command.index("--output") + 1])
            candidate.write_text("candidate", encoding="utf-8")
            try:
                os.symlink(victim, candidate.with_suffix(".drc.rpt"))
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symbolic links are unavailable: {error}")
            return BoundedProcessResult(tuple(command), 0, b"", b"")

        with (
            patch(
                "pcbex_agent.repair_loop._run_tool",
                side_effect=malicious_route,
            ),
            self.assertRaisesRegex(OSError, "symbolic link"),
        ):
            repair_kicad_board(
                source,
                output,
                pcbex="pcbex",
                kicad_cli="kicad-cli",
                max_iterations=1,
            )

        self.assertEqual(calls, 1)
        self.assertEqual(victim.read_text(encoding="utf-8"), "sentinel")
        self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_returnzero_empty_report_is_not_clean(self):
        directory, source, output = self._paths()
        self.addCleanup(directory.cleanup)
        with (
            patch(
                "pcbex_agent.repair_loop._run_tool",
                side_effect=_tool_side_effect("", kicad_returncode=0),
            ),
            self.assertRaisesRegex(RuntimeError, "empty report"),
        ):
            repair_kicad_board(
                source,
                output,
                pcbex="pcbex",
                kicad_cli="kicad-cli",
                max_iterations=1,
            )

        self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_returnzero_invalid_report_is_not_clean(self):
        directory, source, output = self._paths()
        self.addCleanup(directory.cleanup)
        with (
            patch(
                "pcbex_agent.repair_loop._run_tool",
                side_effect=_tool_side_effect(
                    "not a KiCad report", kicad_returncode=0
                ),
            ),
            self.assertRaisesRegex(RuntimeError, "invalid report"),
        ):
            repair_kicad_board(
                source,
                output,
                pcbex="pcbex",
                kicad_cli="kicad-cli",
                max_iterations=1,
            )

        self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_returnzero_complete_clean_report_is_accepted(self):
        report = (
            "** Drc report for candidate.kicad_pcb **\n"
            "** Found 0 DRC violations **\n"
            "** Found 0 unconnected pads **\n"
            "** Found 0 Footprint errors **\n"
            "** End of Report **\n"
        )
        directory, source, output = self._paths()
        self.addCleanup(directory.cleanup)
        with patch(
            "pcbex_agent.repair_loop._run_tool",
            side_effect=_tool_side_effect(report, kicad_returncode=0),
        ):
            result = repair_kicad_board(
                source,
                output,
                pcbex="pcbex",
                kicad_cli="kicad-cli",
                max_iterations=1,
            )

        self.assertTrue(result.success)
        self.assertEqual(result.stop_reason, "clean")
        self.assertEqual(output.read_text(encoding="utf-8"), "candidate")

    def test_returnzero_nonzero_summary_without_sections_is_not_clean(self):
        report = (
            "** Drc report for candidate.kicad_pcb **\n"
            "** Found 1 DRC violations **\n"
            "** Found 0 unconnected pads **\n"
            "** Found 0 Footprint errors **\n"
            "** End of Report **\n"
        )
        directory, source, output = self._paths()
        self.addCleanup(directory.cleanup)
        with (
            patch(
                "pcbex_agent.repair_loop._run_tool",
                side_effect=_tool_side_effect(report, kicad_returncode=0),
            ),
            self.assertRaisesRegex(RuntimeError, "count does not match"),
        ):
            repair_kicad_board(
                source,
                output,
                pcbex="pcbex",
                kicad_cli="kicad-cli",
                max_iterations=1,
            )

        self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_returnzero_warning_without_envelope_is_not_clean(self):
        report = "[warning-rule]: warning text\n    Severity: warning\n"
        directory, source, output = self._paths()
        self.addCleanup(directory.cleanup)
        with (
            patch(
                "pcbex_agent.repair_loop._run_tool",
                side_effect=_tool_side_effect(report, kicad_returncode=0),
            ),
            self.assertRaisesRegex(RuntimeError, "invalid report"),
        ):
            repair_kicad_board(
                source,
                output,
                pcbex="pcbex",
                kicad_cli="kicad-cli",
                max_iterations=1,
            )

        self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_returnzero_zero_summary_with_warning_section_is_not_clean(self):
        report = (
            "** Drc report for candidate.kicad_pcb **\n"
            "** Found 0 DRC violations **\n"
            "** Found 0 unconnected pads **\n"
            "** Found 0 Footprint errors **\n"
            "[warning-rule]: warning text\n"
            "    Severity: warning\n"
            "** End of Report **\n"
        )
        directory, source, output = self._paths()
        self.addCleanup(directory.cleanup)
        with (
            patch(
                "pcbex_agent.repair_loop._run_tool",
                side_effect=_tool_side_effect(report, kicad_returncode=0),
            ),
            self.assertRaisesRegex(RuntimeError, "count does not match"),
        ):
            repair_kicad_board(
                source,
                output,
                pcbex="pcbex",
                kicad_cli="kicad-cli",
                max_iterations=1,
            )

        self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_nonzero_report_with_violation_continues_existing_repair_loop(self):
        report = (
            "** Drc report for candidate.kicad_pcb **\n"
            "** Found 1 DRC violations **\n"
            "[clearance]: Clearance violation\n"
            "    Severity: error\n"
            "    @(1.0000 mm, 2.0000 mm): Track\n"
            "** End of Report **\n"
        )
        directory, source, output = self._paths()
        self.addCleanup(directory.cleanup)
        with patch(
            "pcbex_agent.repair_loop._run_tool",
            side_effect=_tool_side_effect(report, kicad_returncode=1),
        ):
            result = repair_kicad_board(
                source,
                output,
                pcbex="pcbex",
                kicad_cli="kicad-cli",
                max_iterations=2,
            )

        self.assertFalse(result.success)
        self.assertEqual(result.stop_reason, "repeated_candidate")
        self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_same_source_and_output_path_is_rejected_before_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            board = Path(directory).resolve(strict=True) / "board.kicad_pcb"
            board.write_text("source", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different paths"):
                run_repair_loop(
                    board,
                    board,
                    max_iterations=1,
                    generate_candidate=lambda *_args: self.fail("generator ran"),
                    inspect_drc=lambda *_args: [],
                )

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_private_workspace_canonicalizes_trusted_temporary_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            temporary_root = root / "real-temporary-root"
            temporary_root.mkdir()
            temporary_alias = root / "temporary-alias"
            try:
                os.symlink(temporary_root, temporary_alias, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symbolic links are unavailable: {error}")

            source = root / "source.kicad_pcb"
            output = root / "output.kicad_pcb"
            source.write_text("source", encoding="utf-8")
            candidate_parents: list[Path] = []

            def generate(_source, candidate, _iteration, _actions):
                candidate_parents.append(candidate.parent)
                candidate.write_text("candidate", encoding="utf-8")

            with patch(
                "pcbex_agent.repair_loop.tempfile.gettempdir",
                return_value=str(temporary_alias),
            ):
                result = run_repair_loop(
                    source,
                    output,
                    max_iterations=1,
                    generate_candidate=generate,
                    inspect_drc=lambda *_args: [],
                )

            self.assertTrue(result.success)
            self.assertEqual(candidate_parents[0].parent, temporary_root)
            self.assertEqual(output.read_text(encoding="utf-8"), "candidate")


if __name__ == "__main__":
    unittest.main()

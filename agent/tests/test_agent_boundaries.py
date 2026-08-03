import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pcbex_agent.cli as agent_cli
from pcbex_agent.bounded_io import BoundedIOError
from pcbex_agent.bounded_process import ProcessOutputLimitExceeded
from pcbex_agent.executor import run_pcbex
from pcbex_agent.managed_provider import review_schematic_with_managed_provider
from pcbex_agent.provider import ProviderError, review_schematic_with_command
from pcbex_agent.repair_loop import run_repair_loop


def _review_request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "request_sha256": "a" * 64,
        "requirements": [],
        "evidence_ids": [],
    }


def _symlink_or_skip(case: unittest.TestCase, target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as error:
        case.skipTest(f"symbolic links are unavailable: {error}")


@unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
class AgentBoundaryTests(unittest.TestCase):
    def test_command_provider_rejects_symlink_request_without_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_request = root / "real-request.json"
            linked_request = root / "request.json"
            response = root / "response.json"
            receipt = root / "receipt.json"
            real_request.write_text(json.dumps(_review_request()), encoding="utf-8")
            _symlink_or_skip(self, real_request, linked_request)

            with self.assertRaisesRegex(ProviderError, "symbolic link"):
                review_schematic_with_command(
                    linked_request,
                    response,
                    receipt,
                    [sys.executable, "-c", "raise SystemExit('must not run')"],
                )

            self.assertFalse(response.exists())
            self.assertFalse(receipt.exists())

    def test_managed_provider_rejects_symlink_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_request = root / "real-request.json"
            linked_request = root / "request.json"
            real_request.write_text(json.dumps(_review_request()), encoding="utf-8")
            _symlink_or_skip(self, real_request, linked_request)

            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": "secret"}),
                self.assertRaisesRegex(ProviderError, "symbolic link"),
            ):
                review_schematic_with_managed_provider(
                    linked_request,
                    root / "response.json",
                    root / "receipt.json",
                    provider="openai",
                    model="reviewer",
                )

    def test_repair_loop_rejects_symlink_source_and_preserves_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_source = root / "real.kicad_pcb"
            linked_source = root / "source.kicad_pcb"
            output = root / "output.kicad_pcb"
            real_source.write_text("board", encoding="utf-8")
            output.write_text("sentinel", encoding="utf-8")
            _symlink_or_skip(self, real_source, linked_source)

            with self.assertRaises(BoundedIOError):
                run_repair_loop(
                    linked_source,
                    output,
                    max_iterations=1,
                    generate_candidate=lambda *_args: self.fail("generator ran"),
                    inspect_drc=lambda *_args: [],
                )

            self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_repair_loop_rejects_symlink_candidate_before_drc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.kicad_pcb"
            output = root / "output.kicad_pcb"
            source.write_text("board", encoding="utf-8")
            output.write_text("sentinel", encoding="utf-8")

            def generate(_source, candidate, _iteration, _actions):
                _symlink_or_skip(self, source, candidate)

            with self.assertRaisesRegex(BoundedIOError, "symbolic link"):
                run_repair_loop(
                    source,
                    output,
                    max_iterations=1,
                    generate_candidate=generate,
                    inspect_drc=lambda *_args: self.fail("DRC inspector ran"),
                )

            self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")


class AgentProcessIntegrationTests(unittest.TestCase):
    def test_repair_cli_rejects_board_report_aliases_before_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.kicad_pcb"
            output = root / "output.kicad_pcb"
            source.write_text("source", encoding="utf-8")
            for report in (source, output):
                with (
                    self.subTest(report=report),
                    patch(
                        "sys.argv",
                        [
                            "pcbex-agent",
                            "repair-kicad",
                            str(source),
                            "--output",
                            str(output),
                            "--report",
                            str(report),
                        ],
                    ),
                    patch.object(agent_cli, "repair_kicad_board") as repair,
                    patch.object(agent_cli, "write_repair_report") as write_report,
                    self.assertRaisesRegex(SystemExit, "paths must differ"),
                ):
                    agent_cli.main()
                repair.assert_not_called()
                write_report.assert_not_called()

    def test_generic_agent_output_limit_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output.json"
            output.write_text("sentinel", encoding="utf-8")
            with (
                patch.object(agent_cli, "MAXIMUM_AGENT_FILE_BYTES", 4),
                self.assertRaises(BoundedIOError),
            ):
                agent_cli._write_text(output, "12345")
            self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_command_provider_requires_utf8_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "request.json"
            response = root / "response.json"
            receipt = root / "receipt.json"
            request.write_bytes(json.dumps(_review_request()).encode("utf-16"))

            with self.assertRaisesRegex(ProviderError, "invalid AI review request JSON"):
                review_schematic_with_command(
                    request,
                    response,
                    receipt,
                    [sys.executable, "-c", "raise SystemExit('must not run')"],
                )

            self.assertFalse(response.exists())
            self.assertFalse(receipt.exists())

    def test_run_pcbex_preserves_check_true_failure_contract(self):
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            run_pcbex(
                Path(sys.executable),
                ["-c", "import sys; print('failed'); sys.exit(7)"],
                timeout_seconds=5,
            )
        self.assertEqual(raised.exception.returncode, 7)
        self.assertEqual(raised.exception.output, "failed\n")

    def test_run_pcbex_enforces_shared_output_limit(self):
        with (
            patch("pcbex_agent.executor.MAXIMUM_PCBEX_STDOUT_BYTES", 4),
            self.assertRaises(ProcessOutputLimitExceeded),
        ):
            run_pcbex(
                Path(sys.executable),
                ["-c", "import sys; sys.stdout.write('12345')"],
                timeout_seconds=5,
            )

    def test_run_pcbex_preserves_non_utf8_bounded_diagnostics(self):
        completed = run_pcbex(
            Path(sys.executable),
            ["-c", "import os; os.write(1, b'\\xff')"],
            timeout_seconds=5,
        )
        self.assertEqual(completed.stdout, "\ufffd")

    def test_oversized_repair_candidate_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.kicad_pcb"
            output = root / "output.kicad_pcb"
            source.write_bytes(b"src")
            output.write_bytes(b"sentinel")

            def generate(_source, candidate, _iteration, _actions):
                candidate.write_bytes(b"12345")

            def inspect(*_args):
                self.fail("oversized candidate reached DRC inspector")

            with (
                patch("pcbex_agent.repair_loop.MAXIMUM_KICAD_BOARD_BYTES", 4),
                self.assertRaises(BoundedIOError),
            ):
                run_repair_loop(
                    source,
                    output,
                    max_iterations=1,
                    generate_candidate=generate,
                    inspect_drc=inspect,
                )

            self.assertEqual(output.read_bytes(), b"sentinel")


if __name__ == "__main__":
    unittest.main()

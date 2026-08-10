"""Unit tests for the deterministic-pipeline fixture boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import deterministic_pipeline_ci as fixture  # noqa: E402


class DeterministicPipelineCiTests(unittest.TestCase):
    def test_windows_fixture_selects_installed_gcc_compatible_clang_names(self):
        self.assertEqual(
            fixture._firmware_compiler_arguments("nt"),
            ["--cc", "clang", "--cxx", "clang++"],
        )
        self.assertEqual(fixture._firmware_compiler_arguments("posix"), [])

    def test_resolves_relative_executable_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            executable = workspace / "pcbex"
            executable.write_bytes(b"binary")
            executable.chmod(0o755)
            previous = Path.cwd()
            os.chdir(workspace)
            try:
                resolved, identity = fixture._resolve_pcbex("pcbex")
                self.assertEqual(resolved, executable.resolve())
                self.assertEqual(
                    identity[:2], (executable.stat().st_dev, executable.stat().st_ino)
                )
                self.assertEqual(identity[2], len(b"binary"))
                self.assertEqual(identity[3], hashlib.sha256(b"binary").hexdigest())
                if hasattr(os, "symlink"):
                    link = workspace / "pcbex-link"
                    link.symlink_to(executable)
                    with self.assertRaises(fixture.FixtureError):
                        fixture._resolve_pcbex("pcbex-link")
            finally:
                os.chdir(previous)

    def test_executable_identity_rejects_in_place_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "pcbex"
            executable.write_bytes(b"before")
            _, identity = fixture._resolve_pcbex(str(executable))
            with executable.open("r+b") as stream:
                stream.write(b"change")
                stream.flush()
                os.fsync(stream.fileno())
            self.assertEqual(
                executable.stat().st_ino,
                identity[1],
                "the test must preserve the inode to exercise digest checking",
            )
            with self.assertRaises(fixture.FixtureError):
                fixture._assert_executable_identity(executable, identity)

    def test_summary_schema_is_closed(self):
        digest = hashlib.sha256(b"fixture").hexdigest()
        accepted = {
            "approved": True,
            "binding_approved": True,
            "pipeline_passed": True,
            "failure_count": 0,
            "intent_source_bytes": 1,
            "intent_source_sha256": digest,
            "plan_source_bytes": 1,
            "plan_source_sha256": digest,
            "plan_sha256": digest,
            "run_sha256": digest,
            "report_bytes": 1,
            "report_sha256": digest,
        }
        rejected = copy.deepcopy(accepted)
        rejected.update(
            {
                "approved": False,
                "pipeline_passed": False,
                "failure_count": 1,
                "required_exit_code": 1,
                "required_report_bytes": 1,
                "required_report_sha256": digest,
            }
        )
        summary = {"schema_version": 1, "accepted": accepted, "rejected": rejected}
        fixture._validate_summary(summary)
        mutated = copy.deepcopy(summary)
        mutated["accepted"].pop("run_sha256")
        with self.assertRaises(fixture.FixtureError):
            fixture._validate_summary(mutated)
        for mutation in (
            {"schema_version": True},
            {"accepted": {"failure_count": False}},
            {"rejected": {"failure_count": True}},
        ):
            candidate = copy.deepcopy(summary)
            if "schema_version" in mutation:
                candidate["schema_version"] = mutation["schema_version"]
            else:
                case = "accepted" if "accepted" in mutation else "rejected"
                candidate[case]["failure_count"] = mutation[case]["failure_count"]
            with self.assertRaises(fixture.FixtureError):
                fixture._validate_summary(candidate)

    def test_tamper_changes_exactly_one_drc_entry_and_preserves_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.zip"
            destination = root / "rejected.zip"
            manifest = b'{"sha256":"stable"}'
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("manifest.json", manifest)
                archive.writestr("drc.rpt", b"clean\n")
                archive.writestr("other.txt", b"other")
            fixture._tamper_manufacturing_entry(source, destination)
            with zipfile.ZipFile(destination) as archive:
                self.assertEqual(archive.read("manifest.json"), manifest)
                self.assertEqual(
                    archive.read("drc.rpt"),
                    b"DRC content changed without manifest update\n",
                )
            missing = root / "missing-drc.zip"
            with zipfile.ZipFile(missing, "w") as archive:
                archive.writestr("manifest.json", manifest)
            missing_destination = root / "missing-out.zip"
            with self.assertRaises(fixture.FixtureError):
                fixture._tamper_manufacturing_entry(missing, missing_destination)
            self.assertFalse(missing_destination.exists())
            duplicate = root / "duplicate-drc.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate, "w") as archive:
                    archive.writestr("drc.rpt", b"one")
                    archive.writestr("drc.rpt", b"two")
            duplicate_destination = root / "duplicate-out.zip"
            with self.assertRaises(fixture.FixtureError):
                fixture._tamper_manufacturing_entry(duplicate, duplicate_destination)
            self.assertFalse(duplicate_destination.exists())

    def test_manufacturing_package_failure_leaves_no_partial_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            board = root / "design.kicad_pcb"
            board.write_bytes(b"(kicad_pcb)")
            destination = root / "manufacturing.zip"
            with mock.patch.object(
                zipfile.ZipFile,
                "writestr",
                side_effect=OSError("forced archive failure"),
            ):
                with self.assertRaises(fixture.FixtureError):
                    fixture._write_manufacturing_package(
                        destination,
                        board,
                        engine_version="1.438.0",
                    )
            self.assertFalse(destination.exists())

    def test_manufacturing_package_uses_production_csv_headers_and_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            board = root / "design.kicad_pcb"
            board.write_bytes(b"(kicad_pcb)")
            destination = root / "manufacturing.zip"
            fixture._write_manufacturing_package(
                destination,
                board,
                engine_version="1.439.0",
            )
            with zipfile.ZipFile(destination) as archive:
                self.assertEqual(
                    archive.read("bom.csv"),
                    b"Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n",
                )
                self.assertEqual(
                    archive.read("cpl.csv"),
                    b"Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n",
                )
                manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(
                manifest["parts"],
                {"total": 0, "bom": 0, "placement": 0, "dnp": 0},
            )

    def test_rejected_case_is_manufacturing_only(self):
        detail = (
            "invalid manufacturing package: factory package ZIP entry drc.rpt "
            "does not match manifest bytes/hash"
        )
        report = {
            "failures": ["pipeline: hardware pipeline gate rejected with 1 failure(s)"],
            "pipeline": {
                "phases": [
                    {"name": "electrical-erc", "passed": True, "failures": []},
                    {"name": "analysis-drc", "passed": True, "failures": []},
                    {"name": "routing-quality", "passed": True, "failures": []},
                    {
                        "name": "manufacturing-package",
                        "passed": False,
                        "failures": [detail],
                    },
                    {"name": "firmware-build", "passed": True, "failures": []},
                ],
                "failures": [f"manufacturing-package: {detail}"],
            },
        }
        fixture._validate_manufacturing_rejection(report)
        for mutate in ("wrong-phase", "wrong-detail", "wrong-top-level"):
            candidate = copy.deepcopy(report)
            if mutate == "wrong-phase":
                candidate["pipeline"]["phases"][1]["passed"] = False
            elif mutate == "wrong-detail":
                candidate["pipeline"]["phases"][3]["failures"] = ["other"]
            else:
                candidate["failures"] = ["other"]
            with self.assertRaises(fixture.FixtureError):
                fixture._validate_manufacturing_rejection(candidate)

    def test_fresh_output_and_no_clobber_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            fixture._prepare_fresh_output(output)
            with self.assertRaises(fixture.FixtureError):
                fixture._prepare_fresh_output(output)
            intent = root / "intent.json"
            intent.write_bytes(b"{}")
            with self.assertRaises(fixture.FixtureError):
                fixture._write_intent(root, "package.zip")

    @unittest.skipIf(os.name == "nt", "POSIX FIFO is not available")
    def test_scanner_rejects_special_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.mkfifo(root / "unexpected.fifo")
            with self.assertRaises(fixture.FixtureError):
                fixture._scan_output_tree(root)

    def test_child_output_is_bounded_by_the_shared_supervisor(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(fixture.FixtureError):
                fixture._run_command(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stdout.buffer.write(b'x' * 65537)",
                    ],
                    cwd=Path(temporary),
                    timeout_seconds=5,
                )

    def test_child_timeout_is_bounded_by_the_shared_supervisor(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(fixture.FixtureError):
                fixture._run_command(
                    [sys.executable, "-c", "import time; time.sleep(2)"],
                    cwd=Path(temporary),
                    timeout_seconds=1,
                )

    def test_unexpected_runner_detail_is_bounded_and_names_failed_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            report.write_text(
                json.dumps(
                    {
                        "approved": False,
                        "failures": [
                            "pipeline: hardware pipeline gate rejected with 1 failure(s)"
                        ],
                        "pipeline": {
                            "phases": [
                                {
                                    "name": "firmware-build",
                                    "passed": False,
                                    "failures": ["firmware smoke failed"],
                                }
                            ]
                        },
                    },
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            detail = fixture._unexpected_runner_detail(
                report,
                b"deterministic hardware pipeline rejected\n",
            )
            self.assertLessEqual(len(detail), 2048)
            parsed = json.loads(detail)
            self.assertEqual(parsed["approved"], False)
            self.assertEqual(parsed["failed_phases"][0]["name"], "firmware-build")
            self.assertEqual(
                parsed["failed_phases"][0]["failures"],
                ["firmware smoke failed"],
            )
            self.assertIn("pipeline rejected", parsed["stderr"])


if __name__ == "__main__":
    unittest.main()

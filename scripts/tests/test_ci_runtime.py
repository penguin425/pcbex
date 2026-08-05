from __future__ import annotations

import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import ci_runtime


class _Response(io.BytesIO):
    def __init__(self, payload: bytes, content_length: str | None = None) -> None:
        super().__init__(payload)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length


class CiRuntimeTests(unittest.TestCase):
    def test_process_accepts_exact_output_and_preserves_nonzero_status(self):
        result = ci_runtime.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 8); sys.exit(7)",
            ],
            timeout_seconds=5,
            max_stdout_bytes=8,
            max_stderr_bytes=8,
        )
        self.assertEqual(result.stdout, b"x" * 8)
        self.assertEqual(result.returncode, 7)

    def test_process_rejects_one_byte_over_and_timeout(self):
        with self.assertRaises(ci_runtime.ExecutionBoundaryError):
            ci_runtime.run(
                [sys.executable, "-c", "print('12345678', end='')"],
                timeout_seconds=5,
                max_stdout_bytes=7,
                max_stderr_bytes=8,
            )
        with self.assertRaises(ci_runtime.ExecutionBoundaryError):
            ci_runtime.run(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout_seconds=0.05,
                max_stdout_bytes=8,
                max_stderr_bytes=8,
            )

    def test_aggregate_deadline_is_shared_across_calls(self):
        with mock.patch.object(
            ci_runtime.time, "monotonic", side_effect=[100.0, 105.0, 111.0]
        ):
            deadline = ci_runtime.Deadline.start(10)
            self.assertEqual(deadline.remaining(), 5)
            with self.assertRaisesRegex(
                ci_runtime.ExecutionBoundaryError, "aggregate execution deadline"
            ):
                ci_runtime.run(
                    [sys.executable, "-c", "pass"],
                    timeout_seconds=5,
                    deadline=deadline,
                )

    def test_http_response_accepts_exact_limit_and_rejects_overflow(self):
        self.assertEqual(
            ci_runtime.read_response_bytes(_Response(b"1234", "4"), max_bytes=4),
            b"1234",
        )
        for response in (_Response(b"12345"), _Response(b"", "5")):
            with self.subTest(headers=response.headers):
                with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                    ci_runtime.read_response_bytes(response, max_bytes=4)

    def test_append_text_accepts_exact_limit_and_rejects_overflow(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "github-output"
            output.write_bytes(b"a=1\n")
            ci_runtime.append_text(output, "b=2\n", max_bytes=8)
            self.assertEqual(output.read_bytes(), b"a=1\nb=2\n")
            with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                ci_runtime.append_text(output, "x", max_bytes=8)
            self.assertEqual(output.read_bytes(), b"a=1\nb=2\n")

    def test_append_text_creates_missing_file_and_uses_binary_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "github-output"
            ci_runtime.append_text(output, "value\n", max_bytes=6)
            self.assertEqual(output.read_bytes(), b"value\n")
        with mock.patch.object(ci_runtime.os, "O_BINARY", 1 << 29, create=True):
            self.assertTrue(ci_runtime._append_open_flags() & (1 << 29))

    def test_append_text_requires_a_positive_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "github-output"
            with self.assertRaisesRegex(
                ci_runtime.ExecutionBoundaryError, "positive integer"
            ):
                ci_runtime.append_text(output, "", max_bytes=0)

    def test_relative_output_root_rejects_escape_and_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            for value in (
                "",
                ".",
                "..",
                "../escape",
                "/absolute",
                "a\\b",
                "C:tmp",
                "a/./b",
                "a//b",
                "a/",
                "a\nb",
                "a\rb",
                "a\tb",
            ):
                with self.subTest(value=value):
                    with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                        ci_runtime.validate_relative_output_root(value, base=workspace)

            if hasattr(os, "symlink"):
                outside = workspace / "outside"
                outside.mkdir()
                link = workspace / "linked"
                try:
                    link.symlink_to(outside, target_is_directory=True)
                except OSError:
                    pass
                else:
                    with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                        ci_runtime.validate_relative_output_root(
                            "linked/result", base=workspace
                        )

    def test_literal_relative_output_root_rejects_artifact_globs(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            self.assertEqual(
                ci_runtime.validate_relative_output_root(
                    "build/result name", base=workspace
                ),
                workspace / "build/result name",
            )
            self.assertEqual(
                ci_runtime.validate_literal_relative_output_root(
                    "build/result-name_1.0", base=workspace
                ),
                workspace / "build/result-name_1.0",
            )
            for value in (
                "build/*",
                "build/result?",
                "build/[result]",
                "build/{one,two}",
                "build/result!",
                "build/result name",
            ):
                with self.subTest(value=value):
                    with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                        ci_runtime.validate_literal_relative_output_root(
                            value, base=workspace
                        )

    def test_artifact_relative_output_root_preserves_spaces_but_rejects_globs(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            for value in (
                "build/result name",
                "build/result+name@example.com",
                "build/(draft)",
            ):
                with self.subTest(value=value):
                    self.assertEqual(
                        ci_runtime.validate_artifact_relative_output_root(
                            value, base=workspace
                        ),
                        workspace / value,
                    )
            for value in (
                "build/*",
                "build/result?",
                "build/[result]",
                "build/{one,two}",
                "!build/result",
                "build/@(one|two)",
            ):
                with self.subTest(value=value):
                    with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                        ci_runtime.validate_artifact_relative_output_root(
                            value, base=workspace
                        )

    def test_relative_input_file_rejects_escape_absolute_links_and_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            nested = workspace / "nested path"
            nested.mkdir()
            source = nested / "-design.kicad_sch"
            source.write_text("(kicad_sch)\n", encoding="utf-8")
            self.assertEqual(
                ci_runtime.validate_relative_input_file(
                    "nested path/-design.kicad_sch", base=workspace
                ),
                source,
            )
            for value in (
                "",
                ".",
                "..",
                "../escape.kicad_sch",
                str(source),
                "a\\b",
                "C:design.kicad_sch",
                "nested path",
            ):
                with self.subTest(value=value):
                    with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                        ci_runtime.validate_relative_input_file(value, base=workspace)

            if hasattr(os, "symlink"):
                linked = workspace / "linked.kicad_sch"
                try:
                    linked.symlink_to(source)
                except OSError:
                    pass
                else:
                    with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                        ci_runtime.validate_relative_input_file(
                            "linked.kicad_sch", base=workspace
                        )

    def test_tree_scan_accepts_exact_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            nested = root / "nested"
            nested.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            (nested / "b.txt").write_bytes(b"de")
            usage = ci_runtime.scan_tree(
                root,
                max_entries=3,
                max_depth=2,
                max_file_bytes=3,
                max_total_bytes=5,
            )
            self.assertEqual(usage.entries, 3)
            self.assertEqual(usage.files, 2)
            self.assertEqual(usage.bytes, 5)
            self.assertEqual(usage.maximum_depth, 2)

    def test_tree_scan_rejects_each_quota_and_symlink(self):
        cases = {
            "entries": dict(max_entries=1, max_depth=4, max_file_bytes=8, max_total_bytes=16),
            "depth": dict(max_entries=4, max_depth=1, max_file_bytes=8, max_total_bytes=16),
            "file": dict(max_entries=4, max_depth=4, max_file_bytes=2, max_total_bytes=16),
            "total": dict(max_entries=4, max_depth=4, max_file_bytes=8, max_total_bytes=2),
        }
        for name, limits in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                nested = root / "nested"
                nested.mkdir()
                (nested / "value.txt").write_bytes(b"abc")
                with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                    ci_runtime.scan_tree(root, **limits)

        if hasattr(os, "symlink"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                target = root / "target.txt"
                target.write_text("value")
                link = root / "link.txt"
                try:
                    link.symlink_to(target)
                except OSError:
                    return
                with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                    ci_runtime.scan_tree(root)
            with tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary).resolve()
                target = parent / "target"
                target.mkdir()
                dangling = parent / "output"
                try:
                    dangling.symlink_to(parent / "missing", target_is_directory=True)
                except OSError:
                    return
                with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                    ci_runtime.scan_tree(dangling)

    def test_direct_tree_scan_rejects_parent_traversal_and_linked_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            outside = workspace / "outside"
            outside.mkdir()
            previous = Path.cwd()
            try:
                os.chdir(workspace)
                with self.assertRaisesRegex(
                    ci_runtime.ExecutionBoundaryError, "parent traversal"
                ):
                    ci_runtime.scan_tree("../outside")
            finally:
                os.chdir(previous)

            if hasattr(os, "symlink"):
                linked_base = workspace / "linked-base"
                try:
                    linked_base.symlink_to(outside, target_is_directory=True)
                except OSError:
                    return
                with self.assertRaises(ci_runtime.ExecutionBoundaryError):
                    ci_runtime.validate_relative_output_root(
                        "result", base=linked_base
                    )

    def test_exec_cli_requires_declared_output_tree_to_exist(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            previous = Path.cwd()
            try:
                os.chdir(workspace)
                with (
                    mock.patch(
                        "sys.argv",
                        [
                            "ci_runtime.py",
                            "exec",
                            "--timeout-seconds",
                            "5",
                            "--output-root",
                            "missing",
                            "--",
                            sys.executable,
                            "-c",
                            "pass",
                        ],
                    ),
                ):
                    self.assertEqual(ci_runtime.main(), 2)
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()

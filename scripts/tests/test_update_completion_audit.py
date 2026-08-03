from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "update-completion-audit.py"
SPEC = importlib.util.spec_from_file_location("update_completion_audit", SCRIPT)
assert SPEC and SPEC.loader
update_completion_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(update_completion_audit)


class UpdateCompletionAuditTests(unittest.TestCase):
    def test_rust_test_list_is_time_and_output_bounded(self):
        result = SimpleNamespace(
            returncode=0,
            stdout=b"alpha: test\nnoise\nbeta: test\n",
            stderr=b"",
        )
        with mock.patch.object(
            update_completion_audit, "run", return_value=result
        ) as command:
            self.assertEqual(update_completion_audit.rust_test_count(), 2)
        options = command.call_args.kwargs
        self.assertEqual(
            options["timeout_seconds"],
            update_completion_audit.CARGO_LIST_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            options["max_stdout_bytes"],
            update_completion_audit.MAX_CARGO_STDOUT_BYTES,
        )
        self.assertEqual(
            options["max_stderr_bytes"],
            update_completion_audit.MAX_CARGO_STDERR_BYTES,
        )

    def test_rust_test_list_rejects_nonzero_and_invalid_utf8(self):
        for result in (
            SimpleNamespace(returncode=2, stdout=b"", stderr=b"failed"),
            SimpleNamespace(returncode=0, stdout=b"\xff", stderr=b""),
        ):
            with self.subTest(returncode=result.returncode), mock.patch.object(
                update_completion_audit, "run", return_value=result
            ):
                with self.assertRaises(RuntimeError):
                    update_completion_audit.rust_test_count()

    def test_document_replacement_requires_markers(self):
        with self.assertRaises(update_completion_audit.CompletionAuditError):
            update_completion_audit.updated_document("no markers")
        original = (
            "before\n"
            f"{update_completion_audit.START}\nstale\n"
            f"{update_completion_audit.END}\n"
            "after\n"
        )
        with mock.patch.object(
            update_completion_audit, "generated_block", return_value="generated"
        ):
            self.assertEqual(
                update_completion_audit.updated_document(original),
                "before\ngenerated\nafter\n",
            )

    def test_main_atomically_updates_and_check_detects_staleness(self):
        with tempfile.TemporaryDirectory() as temporary:
            audit = Path(temporary).resolve() / "audit.md"
            original = (
                "before\n"
                f"{update_completion_audit.START}\nstale\n"
                f"{update_completion_audit.END}\n"
            )
            audit.write_text(original)
            generated = (
                f"{update_completion_audit.START}\nfresh\n"
                f"{update_completion_audit.END}"
            )
            with (
                mock.patch.object(update_completion_audit, "AUDIT", audit),
                mock.patch.object(update_completion_audit, "ROOT", audit.parent),
                mock.patch.object(
                    update_completion_audit, "generated_block", return_value=generated
                ),
                mock.patch("sys.argv", [str(SCRIPT), "--check"]),
                mock.patch("sys.stderr", new_callable=io.StringIO),
            ):
                self.assertEqual(update_completion_audit.main(), 1)
                self.assertEqual(audit.read_text(), original)

            with (
                mock.patch.object(update_completion_audit, "AUDIT", audit),
                mock.patch.object(update_completion_audit, "ROOT", audit.parent),
                mock.patch.object(
                    update_completion_audit, "generated_block", return_value=generated
                ),
                mock.patch("sys.argv", [str(SCRIPT)]),
            ):
                self.assertEqual(update_completion_audit.main(), 0)
            self.assertIn("fresh", audit.read_text())

    def test_main_rejects_oversized_audit_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            audit = Path(temporary).resolve() / "audit.md"
            with audit.open("wb") as stream:
                stream.truncate(update_completion_audit.MAX_AUDIT_BYTES + 1)
            before = audit.stat().st_size
            with (
                mock.patch.object(update_completion_audit, "AUDIT", audit),
                mock.patch("sys.argv", [str(SCRIPT)]),
                mock.patch("sys.stderr", new_callable=io.StringIO),
            ):
                self.assertEqual(update_completion_audit.main(), 2)
            self.assertEqual(audit.stat().st_size, before)


if __name__ == "__main__":
    unittest.main()

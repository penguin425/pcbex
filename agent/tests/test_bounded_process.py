import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import pcbex_agent.bounded_process as bounded_process
from pcbex_agent.bounded_process import (
    BoundedProcessResult,
    InvalidInputLimit,
    InvalidOutputLimit,
    InvalidProcessArguments,
    InvalidTimeout,
    ProcessCleanupError,
    ProcessInputLimitExceeded,
    ProcessOutputLimitExceeded,
    ProcessTimeout,
    run_bounded,
)


def _python(script: str, *args: str) -> list[str]:
    """Build a shell-free child command for the test cases."""

    return [sys.executable, "-c", script, *args]


class BoundedProcessTests(unittest.TestCase):
    def test_success_argv_environment_cwd_and_closed_stdin(self):
        script = (
            "import os, sys; "
            "data = sys.stdin.buffer.read(); "
            "text = '\\n'.join((repr(sys.argv[1:]), str(len(data)), "
            "os.environ['PCBEX_BOUNDED_TEST'], os.getcwd())) + '\\n'; "
            "sys.stdout.buffer.write(text.encode('utf-8'))"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            result = run_bounded(
                _python(script, "literal; echo should-not-run", "日本語"),
                timeout_seconds=5,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                env={**os.environ, "PCBEX_BOUNDED_TEST": "ok"},
                cwd=root,
            )
        self.assertIsInstance(result, BoundedProcessResult)
        self.assertEqual(result.returncode, 0)
        lines = result.stdout.decode().splitlines()
        self.assertEqual(lines[0], repr(["literal; echo should-not-run", "日本語"]))
        self.assertEqual(lines[1], "0")
        self.assertEqual(lines[2], "ok")
        self.assertEqual(lines[3], str(root))
        self.assertEqual(result.stderr, b"")

    def test_exact_output_limits_are_allowed(self):
        result = run_bounded(
            _python(
                "import sys; "
                "sys.stdout.buffer.write(b'o' * 7); "
                "sys.stderr.buffer.write(b'e' * 5)"
            ),
            timeout_seconds=5,
            max_stdout_bytes=7,
            max_stderr_bytes=5,
        )
        self.assertEqual(result.stdout, b"o" * 7)
        self.assertEqual(result.stderr, b"e" * 5)

    def test_exact_input_limit_is_allowed(self):
        result = run_bounded(
            _python(
                "import sys; "
                "sys.stdout.buffer.write(sys.stdin.buffer.read())"
            ),
            input_bytes=b"i" * 7,
            timeout_seconds=5,
            max_stdin_bytes=7,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"i" * 7)

    def test_input_one_over_limit_is_typed_before_process_spawn(self):
        with self.assertRaises(ProcessInputLimitExceeded) as context:
            run_bounded(
                _python("raise SystemExit('must not spawn')"),
                input_bytes=bytearray(b"i" * 8),
                timeout_seconds=5,
                max_stdin_bytes=7,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        self.assertEqual(context.exception.size, 8)
        self.assertEqual(context.exception.limit, 7)

    def test_invalid_input_limit_is_typed(self):
        with self.assertRaises(InvalidInputLimit):
            run_bounded(_python("pass"), max_stdin_bytes=-1)

    def test_released_memoryview_and_huge_timeout_are_typed(self):
        released = memoryview(b"input")
        released.release()
        with self.assertRaises(InvalidProcessArguments):
            run_bounded(_python("pass"), input_bytes=released)
        with self.assertRaises(InvalidTimeout):
            run_bounded(_python("pass"), timeout_seconds=10**309)

    def test_stdout_one_over_limit_is_typed(self):
        with self.assertRaises(ProcessOutputLimitExceeded) as context:
            run_bounded(
                _python("import sys; sys.stdout.buffer.write(b'x' * 8)"),
                timeout_seconds=5,
                max_stdout_bytes=7,
                max_stderr_bytes=1024,
            )
        self.assertEqual(context.exception.stream, "stdout")
        self.assertEqual(context.exception.limit, 7)

    def test_stderr_one_over_limit_is_typed_independently(self):
        with self.assertRaises(ProcessOutputLimitExceeded) as context:
            run_bounded(
                _python("import sys; sys.stderr.buffer.write(b'x' * 8)"),
                timeout_seconds=5,
                max_stdout_bytes=1024,
                max_stderr_bytes=7,
            )
        self.assertEqual(context.exception.stream, "stderr")
        self.assertEqual(context.exception.limit, 7)

    def test_simultaneous_stdout_stderr_flood_does_not_deadlock(self):
        script = (
            "import os; "
            "os.write(1, b'o' * 2000000); "
            "os.write(2, b'e' * 2000000)"
        )
        result = run_bounded(
            _python(script),
            timeout_seconds=10,
            max_stdout_bytes=2_000_000,
            max_stderr_bytes=2_000_000,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout), 2_000_000)
        self.assertEqual(len(result.stderr), 2_000_000)

    def test_timeout_kills_sleeping_process(self):
        started = time.monotonic()
        with self.assertRaises(ProcessTimeout):
            run_bounded(
                _python("import time; time.sleep(2)"),
                timeout_seconds=0.15,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        self.assertLess(time.monotonic() - started, 1.5)

    def test_timeout_includes_blocked_stdin_delivery(self):
        started = time.monotonic()
        with self.assertRaises(ProcessTimeout):
            run_bounded(
                _python("import time; time.sleep(2)"),
                input_bytes=b"x" * (8 * 1024 * 1024),
                timeout_seconds=0.2,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        self.assertLess(time.monotonic() - started, 1.5)

    def test_cleanup_failure_supersedes_timeout_and_chains_primary(self):
        real_cleanup = bounded_process._cleanup_process
        cleanup_calls = []

        def cleanup_then_fail(*args, **kwargs):
            # Let the production cleanup path terminate and reap the real
            # process before returning a simulated cleanup failure.
            result = real_cleanup(*args, **kwargs)
            cleanup_calls.append(result)
            return ProcessCleanupError("simulated cleanup failure")

        with patch.object(
            bounded_process, "_cleanup_process", side_effect=cleanup_then_fail
        ):
            with self.assertRaises(ProcessCleanupError) as context:
                run_bounded(
                    _python("import time; time.sleep(2)"),
                    timeout_seconds=0.1,
                    max_stdout_bytes=1024,
                    max_stderr_bytes=1024,
                )

        self.assertEqual(len(cleanup_calls), 1)
        self.assertIsInstance(context.exception.__cause__, ProcessTimeout)

    def test_process_tree_termination_failure_is_reported_after_real_cleanup(self):
        real_kill = bounded_process._kill_process_tree

        def kill_then_report(*args, **kwargs):
            real_kill(*args, **kwargs)
            return ["simulated process-tree termination failure"]

        with (
            patch.object(
                bounded_process,
                "_kill_process_tree",
                side_effect=kill_then_report,
            ),
            self.assertRaisesRegex(
                ProcessCleanupError,
                "simulated process-tree termination failure",
            ),
        ):
            run_bounded(
                _python("pass"),
                timeout_seconds=5,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )

    def test_process_tree_is_terminated_only_once(self):
        real_kill = bounded_process._kill_process_tree
        with patch.object(
            bounded_process,
            "_kill_process_tree",
            wraps=real_kill,
        ) as kill:
            result = run_bounded(
                _python("pass"),
                timeout_seconds=5,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(kill.call_count, 1)

    def test_cleanup_failure_chains_unexpected_primary_exception(self):
        real_cleanup = bounded_process._cleanup_process
        primary = ValueError("unexpected supervisor failure")

        def cleanup_then_fail(*args, **kwargs):
            real_cleanup(*args, **kwargs)
            return ProcessCleanupError("simulated cleanup failure")

        with (
            patch.object(
                bounded_process, "_cleanup_process", side_effect=cleanup_then_fail
            ),
            patch.object(bounded_process, "_first_failure", side_effect=primary),
        ):
            with self.assertRaises(ProcessCleanupError) as context:
                run_bounded(
                    _python("import time; time.sleep(2)"),
                    timeout_seconds=5,
                    max_stdout_bytes=1024,
                    max_stderr_bytes=1024,
                )

        self.assertIs(context.exception.__cause__, primary)

    def test_nonzero_exit_is_returned_not_hidden(self):
        result = run_bounded(
            _python(
                "import sys; "
                "sys.stderr.buffer.write(b'expected failure'); "
                "sys.exit(7)"
            ),
            timeout_seconds=5,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stderr, b"expected failure")

    @unittest.skipUnless(
        os.name in {"posix", "nt"},
        "process-tree cleanup is supported on POSIX and Windows",
    )
    def test_descendant_is_killed_with_process_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory).resolve(strict=True) / "descendant-ran"
            descendant_script = (
                "import pathlib, sys, time; "
                "time.sleep(0.6); "
                "pathlib.Path(sys.argv[1]).write_text('leaked')"
            )
            parent_script = (
                "import subprocess, sys, time; "
                "time.sleep(0.2); "
                "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]])"
            )
            result = run_bounded(
                _python(parent_script, descendant_script, str(marker)),
                timeout_seconds=5,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
            self.assertEqual(result.returncode, 0)
            time.sleep(0.9)
            self.assertFalse(marker.exists())

    def test_invalid_limits_and_timeout_are_typed(self):
        command = _python("pass")
        with self.assertRaises(InvalidTimeout):
            run_bounded(command, timeout_seconds=0)
        with self.assertRaises(InvalidOutputLimit):
            run_bounded(command, max_stdout_bytes=-1)


if __name__ == "__main__":
    unittest.main()

"""Shell-free subprocess execution with bounded, concurrent output capture.

The runner in this module is deliberately small and dependency-free so it can
be used by providers, executors, and repair loops without each caller having
to reimplement process supervision.  ``run_bounded`` starts the command in a
dedicated process group (POSIX) or Job Object (Windows), closes standard input
when no input is supplied, and enforces one monotonic deadline that includes
delivery of ``input_bytes``. Callers that compose this runner into a larger
deadline can also cap the termination/reap phase independently with
``cleanup_timeout_seconds``.

On Windows a Job Object is created and assigned immediately after spawn.  The
assignment is necessarily post-spawn, so a process which exits in that small
window may not be attached; in that case no descendants can be recovered by
this runner.  A live process for which assignment fails is rejected and
cleaned up rather than silently falling back to direct-process termination.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import math
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any


DEFAULT_TIMEOUT_SECONDS = 300.0
DEFAULT_MAX_INPUT_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_CLEANUP_WAIT_SECONDS = 5.0
_THREAD_JOIN_SECONDS = 1.0
_DARWIN_EXIT_RACE_SECONDS = 1.0
_DARWIN_EXIT_RACE_POLL_SECONDS = 0.01


class BoundedProcessError(RuntimeError):
    """Base class for deterministic failures raised by :func:`run_bounded`."""

    def __init__(self, message: str, *, argv: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.argv = argv


class InvalidProcessArguments(BoundedProcessError):
    """The argv, environment, or input arguments are not valid."""


class InvalidTimeout(BoundedProcessError):
    """The timeout is not a finite, positive number."""

    def __init__(self, timeout_seconds: Any, *, argv: tuple[str, ...] = ()) -> None:
        self.timeout_seconds = timeout_seconds
        super().__init__(
            "timeout_seconds must be a finite number greater than zero",
            argv=argv,
        )


class InvalidOutputLimit(BoundedProcessError):
    """An output limit is not a non-negative integer."""

    def __init__(
        self,
        stream: str,
        limit: Any,
        *,
        argv: tuple[str, ...] = (),
    ) -> None:
        self.stream = stream
        self.limit = limit
        super().__init__(
            f"{stream} output limit must be a non-negative integer",
            argv=argv,
        )


class InvalidInputLimit(BoundedProcessError):
    """The stdin input limit is not a non-negative integer."""

    def __init__(
        self,
        limit: Any,
        *,
        argv: tuple[str, ...] = (),
    ) -> None:
        self.limit = limit
        super().__init__(
            "stdin input limit must be a non-negative integer",
            argv=argv,
        )


class ProcessSpawnError(BoundedProcessError):
    """The child process could not be started or attached to its job."""

    def __init__(
        self,
        message: str,
        *,
        argv: tuple[str, ...] = (),
        cause: BaseException | None = None,
    ) -> None:
        self.cause = cause
        super().__init__(message, argv=argv)


class ProcessTimeout(BoundedProcessError):
    """The process or input delivery crossed the monotonic deadline."""

    def __init__(
        self,
        timeout_seconds: float,
        *,
        argv: tuple[str, ...] = (),
    ) -> None:
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"process exceeded timeout of {timeout_seconds:g} seconds",
            argv=argv,
        )


class ProcessOutputLimitExceeded(BoundedProcessError):
    """The selected output stream produced more than its independent limit."""

    def __init__(
        self,
        stream: str,
        limit: int,
        *,
        argv: tuple[str, ...] = (),
    ) -> None:
        self.stream = stream
        self.limit = limit
        super().__init__(
            f"{stream} output exceeded limit of {limit} bytes",
            argv=argv,
        )


class ProcessInputLimitExceeded(BoundedProcessError):
    """The supplied stdin payload exceeds its independent byte limit."""

    def __init__(
        self,
        size: int,
        limit: int,
        *,
        argv: tuple[str, ...] = (),
    ) -> None:
        self.size = size
        self.limit = limit
        super().__init__(
            f"stdin input exceeded limit of {limit} bytes (got {size})",
            argv=argv,
        )


class ProcessIOError(BoundedProcessError):
    """An operating-system error occurred while reading or writing a pipe."""

    def __init__(
        self,
        stream: str,
        operation: str,
        cause: BaseException,
        *,
        argv: tuple[str, ...] = (),
    ) -> None:
        self.stream = stream
        self.operation = operation
        self.cause = cause
        super().__init__(
            f"{operation} {stream} pipe failed: {cause}",
            argv=argv,
        )


class ProcessCleanupError(BoundedProcessError):
    """The direct child could not be reaped after termination was requested."""


@dataclass(frozen=True)
class BoundedProcessResult:
    """Completed process status and the bounded bytes captured from each pipe."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass
class _PipeState:
    name: str
    limit: int
    buffer: bytearray
    done: threading.Event
    error: BoundedProcessError | None = None


@dataclass
class _WriterState:
    done: threading.Event
    error: BoundedProcessError | None = None


def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes, bytearray)):
        raise InvalidProcessArguments("argv must be a non-empty sequence of strings")
    try:
        values = tuple(argv)
    except Exception as exc:
        raise InvalidProcessArguments(
            "argv must be a non-empty sequence of strings"
        ) from exc
    if not values:
        raise InvalidProcessArguments("argv must not be empty")
    if any(not isinstance(value, str) for value in values):
        raise InvalidProcessArguments("argv entries must be strings", argv=values)
    if any("\x00" in value for value in values):
        raise InvalidProcessArguments("argv entries must not contain NUL", argv=values)
    return values


def _validate_limit(value: Any, stream: str, argv: tuple[str, ...]) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidOutputLimit(stream, value, argv=argv)
    return value


def _validate_env(
    env: Mapping[str, str] | None,
    argv: tuple[str, ...],
) -> dict[str, str] | None:
    if env is None:
        return None
    if not isinstance(env, Mapping):
        raise InvalidProcessArguments("env must be a string-to-string mapping", argv=argv)
    try:
        copied = dict(env)
    except Exception as exc:
        raise InvalidProcessArguments("env must be a string-to-string mapping", argv=argv) from exc
    if any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or "\x00" in key
        or "\x00" in value
        for key, value in copied.items()
    ):
        raise InvalidProcessArguments("env must contain only NUL-free strings", argv=argv)
    return copied


def _validate_input_limit(value: Any, argv: tuple[str, ...]) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidInputLimit(value, argv=argv)
    return value


def _validate_input(
    input_bytes: bytes | bytearray | memoryview | None,
    max_stdin_bytes: int,
    argv: tuple[str, ...],
) -> bytes | None:
    if input_bytes is None:
        return None
    if not isinstance(input_bytes, (bytes, bytearray, memoryview)):
        raise InvalidProcessArguments("input_bytes must be bytes-like or None", argv=argv)
    try:
        view = memoryview(input_bytes)
    except (TypeError, ValueError) as exc:
        raise InvalidProcessArguments(
            "input_bytes must reference a live bytes-like buffer",
            argv=argv,
        ) from exc
    try:
        size = view.nbytes
        # Inspect the buffer before making a private bytes copy.  This keeps
        # an oversized caller-controlled payload from causing an allocation
        # beyond the configured input budget.
        if size > max_stdin_bytes:
            raise ProcessInputLimitExceeded(size, max_stdin_bytes, argv=argv)
        return bytes(view)
    finally:
        view.release()


def _notify(events: queue.Queue[tuple[str, str]], event: tuple[str, str]) -> None:
    # The queue contains only bounded status events (never output bytes), so a
    # full queue indicates an internal bug rather than untrusted data growth.
    try:
        events.put_nowait(event)
    except queue.Full:  # pragma: no cover - defensive; the queue is unbounded
        pass


def _read_pipe(
    stream: Any,
    state: _PipeState,
    events: queue.Queue[tuple[str, str]],
    stop_event: threading.Event,
    argv: tuple[str, ...],
) -> None:
    try:
        while not stop_event.is_set():
            remaining = state.limit - len(state.buffer)
            # Request one byte beyond the remaining allowance.  This accepts
            # exactly the limit and reports the first byte over it without
            # retaining unbounded output.
            read_size = _READ_CHUNK_BYTES if remaining >= _READ_CHUNK_BYTES else remaining + 1
            chunk = stream.read(read_size)
            if not chunk:
                return
            if len(chunk) > remaining:
                if remaining:
                    state.buffer.extend(chunk[:remaining])
                state.error = ProcessOutputLimitExceeded(
                    state.name,
                    state.limit,
                    argv=argv,
                )
                return
            state.buffer.extend(chunk)
    except Exception as exc:
        if not stop_event.is_set():
            state.error = ProcessIOError(state.name, "reading", exc, argv=argv)
    finally:
        state.done.set()
        _notify(events, ("pipe", state.name))
        try:
            stream.close()
        except Exception:
            pass


def _write_pipe(
    stream: Any,
    input_bytes: bytes,
    deadline: float,
    state: _WriterState,
    events: queue.Queue[tuple[str, str]],
    stop_event: threading.Event,
    argv: tuple[str, ...],
) -> None:
    try:
        offset = 0
        while offset < len(input_bytes) and not stop_event.is_set():
            # A blocking write is interrupted by process cleanup when the
            # supervisor reaches the same deadline.  Chunking keeps delivery
            # observable and prevents a single giant write from hiding that
            # deadline in user-space buffering.
            if time.monotonic() >= deadline:
                return
            chunk = input_bytes[offset : offset + _READ_CHUNK_BYTES]
            written = stream.write(chunk)
            if written is None:
                written = len(chunk)
            if written <= 0:
                raise OSError("stdin pipe write returned no progress")
            offset += written
            stream.flush()
    except (BrokenPipeError, ConnectionResetError):
        # A child is allowed to exit without consuming all optional input.
        pass
    except Exception as exc:
        if not stop_event.is_set():
            state.error = ProcessIOError("stdin", "writing", exc, argv=argv)
    finally:
        try:
            stream.close()
        except Exception:
            pass
        state.done.set()
        _notify(events, ("pipe", "stdin"))


def _first_failure(
    stdout_state: _PipeState,
    stderr_state: _PipeState,
    writer_state: _WriterState,
) -> BoundedProcessError | None:
    # Fixed ordering makes simultaneous failures deterministic.
    return stdout_state.error or stderr_state.error or writer_state.error


def _darwin_exited_process_group_is_gone(
    process: subprocess.Popen[bytes],
    error: OSError,
    *,
    proof_deadline: float | None = None,
) -> bool:
    """Return whether a Darwin ``killpg`` EPERM is an exited-group race.

    Darwin can report EPERM while the direct child is exiting.  Give that
    kernel transition a small bounded window, but treat the result as benign
    only after ``poll`` has reaped the direct child and a signal-zero probe
    proves that the process group no longer exists.  A live child, an existing
    group, or an ambiguous probe at the deadline remains a cleanup failure.
    """

    if sys.platform != "darwin" or error.errno != errno.EPERM:
        return False
    race_deadline = time.monotonic() + _DARWIN_EXIT_RACE_SECONDS
    if proof_deadline is None:
        proof_deadline = race_deadline
    else:
        proof_deadline = min(proof_deadline, race_deadline)
    while True:
        try:
            exited = process.poll() is not None
        except OSError:
            return False
        if exited:
            try:
                os.killpg(process.pid, 0)
            except OSError as probe_error:
                if probe_error.errno == errno.ESRCH:
                    return True
                if probe_error.errno != errno.EPERM:
                    return False
            else:
                return False
        now = time.monotonic()
        if now >= proof_deadline:
            return False
        time.sleep(
            min(_DARWIN_EXIT_RACE_POLL_SECONDS, proof_deadline - now)
        )


def _kill_process_tree(
    process: subprocess.Popen[bytes],
    job: Any,
    *,
    deadline: float | None = None,
) -> list[str]:
    failures: list[str] = []
    posix_group_error: OSError | None = None
    direct_child_error: OSError | None = None
    if job is not None:
        try:
            job.terminate()
        except Exception as exc:
            failures.append(f"could not terminate Windows Job Object: {exc}")
    if os.name == "posix":
        # start_new_session=True gives the child a process group whose id is
        # its pid.  killpg also handles a leader that has already exited while
        # descendants remain in the group.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            posix_group_error = exc
    try:
        process.kill()
    except ProcessLookupError:
        pass
    except OSError as exc:
        direct_child_error = exc
    if posix_group_error is not None and not _darwin_exited_process_group_is_gone(
        process,
        posix_group_error,
        proof_deadline=deadline,
    ):
        failures.append(
            f"could not terminate POSIX process group: {posix_group_error}"
        )
    if direct_child_error is not None:
        failures.append(f"could not terminate direct child: {direct_child_error}")
    return failures


def _close_stream(stream: Any) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except Exception:
        pass


def _cleanup_process(
    process: subprocess.Popen[bytes] | None,
    job: Any,
    stop_event: threading.Event,
    streams: Sequence[Any],
    threads: Sequence[threading.Thread],
    argv: tuple[str, ...],
    *,
    terminate_tree: bool = True,
    prior_termination_failures: Sequence[str] = (),
    cleanup_deadline: float | None = None,
) -> ProcessCleanupError | None:
    if process is None:
        return None
    stop_event.set()
    termination_failures = list(prior_termination_failures)
    if terminate_tree:
        termination_failures.extend(
            _kill_process_tree(
                process,
                job,
                deadline=cleanup_deadline,
            )
        )
    cleanup_error = (
        ProcessCleanupError("; ".join(termination_failures), argv=argv)
        if termination_failures
        else None
    )

    def wait_budget(maximum: float) -> float:
        if cleanup_deadline is None:
            return maximum
        return min(maximum, max(0.0, cleanup_deadline - time.monotonic()))

    try:
        first_wait = wait_budget(_CLEANUP_WAIT_SECONDS)
        if first_wait <= 0 and process.poll() is None:
            raise subprocess.TimeoutExpired(argv, 0)
        process.wait(timeout=first_wait)
    except subprocess.TimeoutExpired as exc:
        try:
            process.kill()
        except Exception:
            pass
        try:
            second_wait = wait_budget(_CLEANUP_WAIT_SECONDS)
            if second_wait <= 0 and process.poll() is None:
                raise subprocess.TimeoutExpired(argv, 0)
            process.wait(timeout=second_wait)
        except Exception as wait_exc:
            cleanup_error = ProcessCleanupError(
                f"could not reap child process: {wait_exc}",
                argv=argv,
            )
    except Exception as exc:
        cleanup_error = ProcessCleanupError(
            f"could not reap child process: {exc}",
            argv=argv,
        )
    for thread in threads:
        thread.join(timeout=wait_budget(_THREAD_JOIN_SECONDS))
    workers_alive = any(thread.is_alive() for thread in threads)
    if cleanup_error is None and workers_alive:
        cleanup_error = ProcessCleanupError(
            "a process pipe worker did not terminate", argv=argv
        )
    if not workers_alive:
        # Workers close their own streams. This also covers partially-started
        # supervision where no worker took ownership. Never call close while
        # a worker may hold a buffered stream lock: a failed tree kill could
        # otherwise turn cleanup itself into an unbounded wait.
        for stream in streams:
            _close_stream(stream)
    return cleanup_error


if os.name == "nt":  # pragma: no cover - exercised on Windows CI
    import ctypes
    from ctypes import wintypes

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _WindowsJobError(RuntimeError):
        pass

    class _WindowsJob:
        def __init__(self, process: subprocess.Popen[bytes]) -> None:
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._handle: Any = None
            create = self._kernel32.CreateJobObjectW
            create.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            create.restype = wintypes.HANDLE
            self._close = self._kernel32.CloseHandle
            self._close.argtypes = [wintypes.HANDLE]
            self._close.restype = wintypes.BOOL
            self._terminate = self._kernel32.TerminateJobObject
            self._terminate.argtypes = [wintypes.HANDLE, wintypes.UINT]
            self._terminate.restype = wintypes.BOOL
            self._set_info = self._kernel32.SetInformationJobObject
            self._set_info.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                wintypes.LPVOID,
                wintypes.DWORD,
            ]
            self._set_info.restype = wintypes.BOOL
            self._assign = self._kernel32.AssignProcessToJobObject
            self._assign.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            self._assign.restype = wintypes.BOOL

            self._handle = create(None, None)
            if not self._handle:
                raise _WindowsJobError(
                    f"CreateJobObjectW failed with WinError {ctypes.get_last_error()}"
                )
            info = _ExtendedLimitInformation()
            info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self._set_info(
                self._handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info),
                ctypes.sizeof(info),
            ):
                error = ctypes.get_last_error()
                self.close()
                raise _WindowsJobError(
                    f"SetInformationJobObject failed with WinError {error}"
                )
            process_handle = getattr(process, "_handle", None)
            if process_handle is None:
                self.close()
                raise _WindowsJobError("Popen did not expose a process handle")
            if not self._assign(self._handle, wintypes.HANDLE(process_handle)):
                error = ctypes.get_last_error()
                self.close()
                raise _WindowsJobError(
                    f"AssignProcessToJobObject failed with WinError {error}"
                )

        def terminate(self) -> None:
            if self._handle and not self._terminate(self._handle, 1):
                raise _WindowsJobError(
                    f"TerminateJobObject failed with WinError {ctypes.get_last_error()}"
                )

        def close(self) -> None:
            if self._handle:
                if not self._close(self._handle):
                    raise _WindowsJobError(
                        "CloseHandle failed with WinError "
                        f"{ctypes.get_last_error()}"
                    )
                self._handle = None


else:

    class _WindowsJob:  # pragma: no cover - only selected on Windows
        def __init__(self, process: subprocess.Popen[bytes]) -> None:
            raise RuntimeError("Windows Job Objects are unavailable on this platform")

        def terminate(self) -> None:
            return None

        def close(self) -> None:
            return None


def run_bounded(
    argv: Sequence[str],
    *,
    input_bytes: bytes | bytearray | memoryview | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    cleanup_timeout_seconds: float | None = None,
    max_stdin_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_stdout_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> BoundedProcessResult:
    """Run ``argv`` without a shell and return bounded captured output.

    ``input_bytes=None`` connects standard input to ``DEVNULL``; consequently
    the child observes EOF immediately.  When bytes are supplied, they are
    delivered by a dedicated writer thread and the same monotonic deadline
    covers both delivery and child execution.  The input payload is checked
    against ``max_stdin_bytes`` before it is copied or delivered.
    ``cleanup_timeout_seconds`` optionally caps the separate process-tree
    termination, direct-child reap, and pipe-worker join phase. A non-zero
    child exit is a normal result; malformed arguments, input/output overflow,
    timeout, pipe errors, and unreaped children are represented by typed
    ``BoundedProcessError`` subclasses.
    """

    normalized_argv = _validate_argv(argv)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise InvalidTimeout(timeout_seconds, argv=normalized_argv)
    try:
        normalized_timeout = float(timeout_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise InvalidTimeout(timeout_seconds, argv=normalized_argv) from exc
    if not math.isfinite(normalized_timeout) or normalized_timeout <= 0:
        raise InvalidTimeout(timeout_seconds, argv=normalized_argv)
    timeout_seconds = normalized_timeout
    if cleanup_timeout_seconds is not None:
        if isinstance(cleanup_timeout_seconds, bool) or not isinstance(
            cleanup_timeout_seconds, (int, float)
        ):
            raise InvalidTimeout(cleanup_timeout_seconds, argv=normalized_argv)
        try:
            normalized_cleanup_timeout = float(cleanup_timeout_seconds)
        except (TypeError, ValueError, OverflowError) as exc:
            raise InvalidTimeout(
                cleanup_timeout_seconds, argv=normalized_argv
            ) from exc
        if (
            not math.isfinite(normalized_cleanup_timeout)
            or normalized_cleanup_timeout <= 0
        ):
            raise InvalidTimeout(cleanup_timeout_seconds, argv=normalized_argv)
        cleanup_timeout_seconds = normalized_cleanup_timeout
    stdin_limit = _validate_input_limit(max_stdin_bytes, normalized_argv)
    stdout_limit = _validate_limit(max_stdout_bytes, "stdout", normalized_argv)
    stderr_limit = _validate_limit(max_stderr_bytes, "stderr", normalized_argv)
    normalized_input = _validate_input(input_bytes, stdin_limit, normalized_argv)
    normalized_env = _validate_env(env, normalized_argv)

    # The deadline starts before Popen so process creation and all input
    # delivery are included in the single hard budget.
    deadline = time.monotonic() + timeout_seconds
    process: subprocess.Popen[bytes] | None = None
    job: Any = None
    stop_event = threading.Event()
    events: queue.Queue[tuple[str, str]] = queue.Queue()
    stdout_state = _PipeState("stdout", stdout_limit, bytearray(), threading.Event())
    stderr_state = _PipeState("stderr", stderr_limit, bytearray(), threading.Event())
    writer_state = _WriterState(threading.Event())
    threads: list[threading.Thread] = []
    tree_terminated = False
    tree_termination_failures: list[str] = []
    primary_error: BaseException | None = None
    cleanup_error: ProcessCleanupError | None = None

    try:
        try:
            process = subprocess.Popen(
                normalized_argv,
                stdin=subprocess.PIPE if normalized_input is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=normalized_env,
                cwd=cwd,
                start_new_session=(os.name == "posix"),
            )
        except Exception as exc:
            raise ProcessSpawnError(
                f"could not start process: {exc}",
                argv=normalized_argv,
                cause=exc,
            ) from exc

        if os.name == "nt":
            try:
                job = _WindowsJob(process)
            except Exception as exc:
                # If the process is already gone, this is the documented
                # post-spawn assignment race; descendants cannot be recovered,
                # but the completed direct process can still be reported.
                if process.poll() is None:
                    raise ProcessSpawnError(
                        f"could not attach process to a Windows Job Object: {exc}",
                        argv=normalized_argv,
                        cause=exc,
                    ) from exc
                job = None

        assert process.stdout is not None
        assert process.stderr is not None
        reader_specs = (
            (process.stdout, stdout_state),
            (process.stderr, stderr_state),
        )
        for stream, state in reader_specs:
            thread = threading.Thread(
                target=_read_pipe,
                args=(stream, state, events, stop_event, normalized_argv),
                name=f"pcbex-bounded-{state.name}",
                daemon=True,
            )
            thread.start()
            threads.append(thread)

        if normalized_input is None:
            writer_state.done.set()
        else:
            assert process.stdin is not None
            writer = threading.Thread(
                target=_write_pipe,
                args=(
                    process.stdin,
                    normalized_input,
                    deadline,
                    writer_state,
                    events,
                    stop_event,
                    normalized_argv,
                ),
                name="pcbex-bounded-stdin",
                daemon=True,
            )
            writer.start()
            threads.append(writer)

        while True:
            now = time.monotonic()
            if now >= deadline:
                raise ProcessTimeout(timeout_seconds, argv=normalized_argv)
            failure = _first_failure(stdout_state, stderr_state, writer_state)
            if failure is not None:
                raise failure

            returncode = process.poll()
            if returncode is not None:
                if not tree_terminated:
                    # Terminate any descendants that inherited the completed
                    # leader's pipes.  Retain failures for the single cleanup
                    # pass below instead of sending a second kill to a process
                    # group whose numeric id may already have been reused.
                    tree_termination_failures.extend(
                        _kill_process_tree(process, job, deadline=deadline)
                    )
                    tree_terminated = True
                if (
                    stdout_state.done.is_set()
                    and stderr_state.done.is_set()
                    and writer_state.done.is_set()
                ):
                    break

            wait_seconds = min(0.05, max(0.0, deadline - now))
            try:
                events.get(timeout=wait_seconds)
            except queue.Empty:
                pass

        assert process.returncode is not None
        # A pipe worker can record an error after the loop's first check but
        # before setting its done event. Recheck after all workers are done so
        # that this narrow completion race cannot turn overflow/I/O failure
        # into an apparently successful result.
        failure = _first_failure(stdout_state, stderr_state, writer_state)
        if failure is not None:
            raise failure
        result = BoundedProcessResult(
            argv=normalized_argv,
            returncode=process.returncode,
            stdout=bytes(stdout_state.buffer),
            stderr=bytes(stderr_state.buffer),
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if process is not None:
            cleanup_deadline = (
                None
                if cleanup_timeout_seconds is None
                else time.monotonic() + cleanup_timeout_seconds
            )
            cleanup_error = _cleanup_process(
                process,
                job,
                stop_event,
                (
                    process.stdin,
                    process.stdout,
                    process.stderr,
                ),
                threads,
                normalized_argv,
                terminate_tree=not tree_terminated,
                prior_termination_failures=tree_termination_failures,
                cleanup_deadline=cleanup_deadline,
            )
            if job is not None:
                try:
                    job.close()
                except Exception as exc:
                    close_error = ProcessCleanupError(
                        f"could not close Windows Job Object: {exc}",
                        argv=normalized_argv,
                    )
                    if cleanup_error is None:
                        cleanup_error = close_error
                    else:
                        cleanup_error = ProcessCleanupError(
                            f"{cleanup_error}; {close_error}",
                            argv=normalized_argv,
                        )
        if cleanup_error is not None:
            if primary_error is not None:
                raise cleanup_error from primary_error
            raise cleanup_error

    return result


__all__ = [
    "BoundedProcessError",
    "BoundedProcessResult",
    "DEFAULT_MAX_INPUT_BYTES",
    "InvalidInputLimit",
    "InvalidOutputLimit",
    "InvalidProcessArguments",
    "InvalidTimeout",
    "ProcessCleanupError",
    "ProcessInputLimitExceeded",
    "ProcessIOError",
    "ProcessOutputLimitExceeded",
    "ProcessSpawnError",
    "ProcessTimeout",
    "run_bounded",
]

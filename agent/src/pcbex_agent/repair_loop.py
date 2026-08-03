from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .bounded_io import (
    BoundedIOError,
    atomic_write,
    read_bytes,
    read_text,
    validate_no_clobber_path,
)
from .bounded_process import (
    ProcessSpawnError,
    ProcessTimeout,
    run_bounded as run_bounded_process,
)
from .drc import normalize_kicad_report
from .models import DrcViolation, RepairAction
from .repair import propose_repairs

CandidateGenerator = Callable[[Path, Path, int, list[RepairAction]], None]
DrcInspector = Callable[[Path, Path], list[DrcViolation]]

MAXIMUM_KICAD_BOARD_BYTES = 128 * 1024 * 1024
MAXIMUM_DRC_REPORT_BYTES = 32 * 1024 * 1024
MAXIMUM_TOOL_STDOUT_BYTES = 8 * 1024 * 1024
MAXIMUM_TOOL_STDERR_BYTES = 1024 * 1024
TOOL_TIMEOUT_SECONDS = 300

_KICAD_DRC_SUMMARY = re.compile(
    r"^\*\*\s+Found\s+\d+\s+DRC\s+violations\s+\*\*\s*$",
    re.IGNORECASE,
)
_KICAD_DRC_HEADER = re.compile(
    r"^\*\*\s+Drc\s+report\s+for\s+.+\s+\*\*\s*$",
    re.IGNORECASE,
)
_KICAD_DRC_FOOTER = re.compile(
    r"^\*\*\s+End\s+of\s+Report\s+\*\*\s*$",
    re.IGNORECASE,
)
_KICAD_FOUND_SUMMARY = re.compile(
    r"^\*\*\s+Found\s+(\d+)\s+.+\s+\*\*\s*$",
    re.IGNORECASE,
)


def _decode_tool_stream(stream: bytes | str) -> str:
    """Decode bounded tool output for diagnostics without masking failures."""

    if isinstance(stream, str):
        return stream
    # Preserve trailing text while matching ``subprocess.run(text=True)``
    # universal-newline behavior used by the previous implementation.
    return (
        stream.decode("utf-8", errors="replace")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )


def _is_kicad_drc_report(report: str) -> bool:
    """Return whether ``report`` contains KiCad's stable DRC summary marker.

    KiCad's report envelope includes a header, a ``Found N DRC violations``
    summary, and a footer even for clean boards. Keeping this check
    intentionally narrow prevents a truncated or arbitrary tool response from
    being interpreted as a clean board.
    """

    lines = report.splitlines()
    return (
        any(_KICAD_DRC_HEADER.match(line) for line in lines)
        and any(_KICAD_DRC_SUMMARY.match(line) for line in lines)
        and any(_KICAD_DRC_FOOTER.match(line) for line in lines)
    )


def _parse_kicad_drc_report(
    report: str,
    *,
    completed: object,
    command: list[str],
) -> list[DrcViolation]:
    """Parse a bounded KiCad report and reject ambiguous clean results."""

    returncode = getattr(completed, "returncode", 0)

    def raise_nonzero() -> None:
        stdout = _decode_tool_stream(getattr(completed, "stdout", b""))
        stderr = _decode_tool_stream(getattr(completed, "stderr", b""))
        raise subprocess.CalledProcessError(
            returncode,
            command,
            output=stdout,
            stderr=stderr,
        )

    if not report.strip():
        if returncode != 0:
            raise_nonzero()
        raise RuntimeError("KiCad DRC produced an empty report")

    if not _is_kicad_drc_report(report):
        if returncode != 0:
            raise_nonzero()
        raise RuntimeError("KiCad DRC produced an invalid report")

    violations = normalize_kicad_report(report)
    reported_count = sum(
        int(match.group(1))
        for line in report.splitlines()
        if (match := _KICAD_FOUND_SUMMARY.match(line)) is not None
    )
    if reported_count != len(violations):
        if returncode != 0:
            raise_nonzero()
        raise RuntimeError(
            "KiCad DRC report finding count does not match parsed violations"
        )

    if returncode != 0 and not violations:
        raise_nonzero()
    return violations


@dataclass(frozen=True)
class RepairIteration:
    iteration: int
    error_count: int
    warning_count: int
    actions: tuple[str, ...]


@dataclass(frozen=True)
class RepairLoopResult:
    success: bool
    stop_reason: str
    iterations: tuple[RepairIteration, ...]
    best_error_count: int
    output: str | None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def run_repair_loop(
    source: Path,
    output: Path,
    *,
    max_iterations: int,
    generate_candidate: CandidateGenerator,
    inspect_drc: DrcInspector,
    supported_actions: frozenset[str] | None = None,
) -> RepairLoopResult:
    """Generate, inspect, and atomically accept a clean repaired board."""
    if not 1 <= max_iterations <= 20:
        raise ValueError("max_iterations must be in 1..20")
    # Validate the caller-owned source before any external tool is allowed to
    # consume its path. The tool reopens it, so this is a bounded validation
    # boundary rather than a filesystem sandbox against a local administrator.
    read_bytes(source, max_bytes=MAXIMUM_KICAD_BOARD_BYTES)
    if os.path.normcase(os.path.abspath(source)) == os.path.normcase(
        os.path.abspath(output)
    ):
        raise ValueError("source and output must be different paths")

    history: list[RepairIteration] = []
    actions: list[RepairAction] = []
    best_error_count = 2**31 - 1
    seen: set[tuple[str, tuple[tuple[str, str, str], ...]]] = set()
    # macOS exposes its default temporary area through the system-managed
    # ``/var`` symlink. Canonicalize this trusted process-selected root once so
    # strict descendant symlink checks remain useful without rejecting our own
    # private workspace.
    trusted_temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="pcbex-repair-", dir=trusted_temporary_root
    ) as directory:
        workspace = Path(directory)
        for iteration in range(max_iterations):
            candidate = workspace / f"candidate-{iteration}.kicad_pcb"
            report = workspace / f"candidate-{iteration}.drc.rpt"
            generate_candidate(source, candidate, iteration, actions)
            # Do not hand a symlink, special file, or oversized candidate from
            # one external tool to the next. The later reads repeat the check
            # after DRC before hashing or publication.
            read_bytes(candidate, max_bytes=MAXIMUM_KICAD_BOARD_BYTES)
            violations = inspect_drc(candidate, report)
            errors = [value for value in violations if value.severity != "warning"]
            warnings = [value for value in violations if value.severity == "warning"]
            proposed_actions = propose_repairs(violations)
            next_actions = [
                action
                for action in proposed_actions
                if supported_actions is None or action.kind in supported_actions
            ]
            history.append(
                RepairIteration(
                    iteration=iteration + 1,
                    error_count=len(errors),
                    warning_count=len(warnings),
                    actions=tuple(action.kind for action in next_actions),
                )
            )
            best_error_count = min(best_error_count, len(errors))
            if not errors:
                candidate_bytes = read_bytes(
                    candidate,
                    max_bytes=MAXIMUM_KICAD_BOARD_BYTES,
                )
                atomic_write(
                    output,
                    candidate_bytes,
                    max_bytes=MAXIMUM_KICAD_BOARD_BYTES,
                )
                return RepairLoopResult(
                    True,
                    "clean",
                    tuple(history),
                    0,
                    str(output),
                )

            fingerprint = (
                hashlib.sha256(
                    read_bytes(candidate, max_bytes=MAXIMUM_KICAD_BOARD_BYTES)
                ).hexdigest(),
                tuple(
                    sorted(
                        (value.rule, value.severity, value.message)
                        for value in violations
                    )
                ),
            )
            if fingerprint in seen:
                return RepairLoopResult(
                    False,
                    "repeated_candidate",
                    tuple(history),
                    best_error_count,
                    None,
                )
            seen.add(fingerprint)
            if not next_actions:
                return RepairLoopResult(
                    False,
                    "no_supported_repair",
                    tuple(history),
                    best_error_count,
                    None,
                )
            actions = next_actions

    return RepairLoopResult(
        False,
        "iteration_limit",
        tuple(history),
        best_error_count,
        None,
    )


def repair_kicad_board(
    source: Path,
    output: Path,
    *,
    pcbex: str = "pcbex",
    kicad_cli: str = "kicad-cli",
    max_iterations: int = 4,
) -> RepairLoopResult:
    schedules = ((5, 20), (12, 35), (2, 60), (20, 10))

    def generate(
        original: Path,
        candidate: Path,
        iteration: int,
        _actions: list[RepairAction],
    ) -> None:
        bend_cost, via_cost = schedules[iteration % len(schedules)]
        command = [
            pcbex,
            "route-kicad",
            str(original),
            "--output",
            str(candidate),
            "--bend-cost",
            str(bend_cost),
            "--via-cost",
            str(via_cost),
        ]
        completed = _run_tool(
            command,
            timeout_seconds=TOOL_TIMEOUT_SECONDS,
        )
        if completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode,
                command,
                output=_decode_tool_stream(completed.stdout),
                stderr=_decode_tool_stream(completed.stderr),
            )

    def inspect(candidate: Path, report: Path) -> list[DrcViolation]:
        # The routing executable receives the private workspace path and could
        # otherwise precreate the predictable DRC report as a symlink. Reject
        # every existing/link-like target before giving it to KiCad; the
        # bounded read below remains the post-process authority.
        validate_no_clobber_path(report)
        environment = os.environ.copy()
        state = report.parent / "kicad-state"
        environment.update(
            {
                "XDG_CONFIG_HOME": str(state / "config"),
                "XDG_CACHE_HOME": str(state / "cache"),
                "XDG_DATA_HOME": str(state / "data"),
            }
        )
        command = [
            kicad_cli,
            "pcb",
            "drc",
            "--exit-code-violations",
            "--output",
            str(report),
            str(candidate),
        ]
        completed = _run_tool(
            command,
            timeout_seconds=TOOL_TIMEOUT_SECONDS,
            env=environment,
        )
        try:
            report_text = read_text(report, max_bytes=MAXIMUM_DRC_REPORT_BYTES)
        except BoundedIOError as error:
            raise RuntimeError(
                "KiCad DRC did not produce a readable bounded report: "
                + _decode_tool_stream(completed.stderr).strip()
            ) from error
        return _parse_kicad_drc_report(
            report_text,
            completed=completed,
            command=command,
        )

    return run_repair_loop(
        source,
        output,
        max_iterations=max_iterations,
        generate_candidate=generate,
        inspect_drc=inspect,
        supported_actions=frozenset({"reroute", "route_unconnected"}),
    )


def write_repair_report(result: RepairLoopResult, path: Path) -> None:
    atomic_write(
        path,
        json.dumps(result.as_dict(), indent=2, ensure_ascii=False) + "\n",
        max_bytes=MAXIMUM_DRC_REPORT_BYTES,
    )


def _run_tool(
    command: list[str],
    *,
    timeout_seconds: int,
    env: dict[str, str] | None = None,
):
    try:
        return run_bounded_process(
            command,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=MAXIMUM_TOOL_STDOUT_BYTES,
            max_stderr_bytes=MAXIMUM_TOOL_STDERR_BYTES,
            env=env,
        )
    except ProcessTimeout as error:
        raise subprocess.TimeoutExpired(command, timeout_seconds) from error
    except ProcessSpawnError as error:
        raise OSError(str(error)) from error

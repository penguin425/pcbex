from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .bounded_io import atomic_write, read_text
from .bounded_process import (
    BoundedProcessError,
    ProcessSpawnError,
    ProcessTimeout,
    run_bounded as run_bounded_process,
)
from .models import ExecutionPlan

MAXIMUM_AGENT_FILE_BYTES = 32 * 1024 * 1024
MAXIMUM_PCBEX_STDOUT_BYTES = 8 * 1024 * 1024
MAXIMUM_PCBEX_STDERR_BYTES = 1024 * 1024


def _decode_process_text(stream: bytes) -> str:
    """Match ``subprocess.run(text=True)`` universal-newline decoding."""

    return (
        stream.decode("utf-8", errors="replace")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )


@dataclass(frozen=True)
class ScoreComparison:
    before: float
    after: float
    changed_components: int

    @property
    def improvement(self) -> float:
        return self.before - self.after


def accept_change(comparison: ScoreComparison, plan: ExecutionPlan) -> bool:
    return (
        comparison.changed_components <= plan.limits.max_changed_components
        and comparison.improvement >= plan.limits.min_score_improvement
        and comparison.after <= comparison.before
    )


def run_bounded(
    plan: ExecutionPlan,
    attempt: Callable[[int], ScoreComparison],
) -> ScoreComparison | None:
    """Run repair attempts with hard plan limits and retain only improvements."""
    best: ScoreComparison | None = None
    for iteration in range(plan.limits.max_iterations):
        result = attempt(iteration)
        if accept_change(result, plan) and (best is None or result.after < best.after):
            best = result
    return best


def run_pcbex(
    executable: Path,
    arguments: list[str],
    *,
    timeout_seconds: int = 300,
) -> subprocess.CompletedProcess[str]:
    command = [str(executable), *arguments]
    try:
        completed = run_bounded_process(
            command,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=MAXIMUM_PCBEX_STDOUT_BYTES,
            max_stderr_bytes=MAXIMUM_PCBEX_STDERR_BYTES,
        )
    except ProcessTimeout as error:
        raise subprocess.TimeoutExpired(command, timeout_seconds) from error
    except ProcessSpawnError as error:
        raise OSError(str(error)) from error
    except BoundedProcessError:
        raise

    # pcbex itself emits UTF-8, but platform tools and localized diagnostics
    # may not. Preserve the bounded diagnostic contract instead of leaking a
    # decode failure after the child has already completed.
    stdout = _decode_process_text(completed.stdout)
    stderr = _decode_process_text(completed.stderr)
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=stdout,
            stderr=stderr,
        )
    return subprocess.CompletedProcess(command, completed.returncode, stdout, stderr)


def apply_constraints(problem_path: Path, plan: ExecutionPlan, output: Path) -> None:
    problem = json.loads(read_text(problem_path, max_bytes=MAXIMUM_AGENT_FILE_BYTES))
    generated = [
        value
        for constraint in plan.constraints
        if (value := constraint.to_placement_json()) is not None
    ]
    problem["constraints"] = [*problem.get("constraints", []), *generated]
    atomic_write(
        output,
        json.dumps(problem, indent=2, ensure_ascii=False) + "\n",
        max_bytes=MAXIMUM_AGENT_FILE_BYTES,
    )

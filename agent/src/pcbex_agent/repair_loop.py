from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .drc import normalize_kicad_report
from .models import DrcViolation, RepairAction
from .repair import propose_repairs

CandidateGenerator = Callable[[Path, Path, int, list[RepairAction]], None]
DrcInspector = Callable[[Path, Path], list[DrcViolation]]


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
    if not source.is_file():
        raise FileNotFoundError(source)

    history: list[RepairIteration] = []
    actions: list[RepairAction] = []
    best_error_count = 2**31 - 1
    seen: set[tuple[str, tuple[tuple[str, str, str], ...]]] = set()
    with tempfile.TemporaryDirectory(prefix="pcbex-repair-") as directory:
        workspace = Path(directory)
        for iteration in range(max_iterations):
            candidate = workspace / f"candidate-{iteration}.kicad_pcb"
            report = workspace / f"candidate-{iteration}.drc.rpt"
            generate_candidate(source, candidate, iteration, actions)
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
                output.parent.mkdir(parents=True, exist_ok=True)
                temporary_output = output.with_name(f".{output.name}.pcbex-tmp")
                shutil.copy2(candidate, temporary_output)
                os.replace(temporary_output, output)
                return RepairLoopResult(
                    True,
                    "clean",
                    tuple(history),
                    0,
                    str(output),
                )

            fingerprint = (
                hashlib.sha256(candidate.read_bytes()).hexdigest(),
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
        subprocess.run(
            [
                pcbex,
                "route-kicad",
                str(original),
                "--output",
                str(candidate),
                "--bend-cost",
                str(bend_cost),
                "--via-cost",
                str(via_cost),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def inspect(candidate: Path, report: Path) -> list[DrcViolation]:
        environment = os.environ.copy()
        state = report.parent / "kicad-state"
        environment.update(
            {
                "XDG_CONFIG_HOME": str(state / "config"),
                "XDG_CACHE_HOME": str(state / "cache"),
                "XDG_DATA_HOME": str(state / "data"),
            }
        )
        completed = subprocess.run(
            [
                kicad_cli,
                "pcb",
                "drc",
                "--exit-code-violations",
                "--output",
                str(report),
                str(candidate),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
            env=environment,
        )
        if not report.exists():
            raise RuntimeError(
                f"KiCad DRC did not produce a report: {completed.stderr.strip()}"
            )
        return normalize_kicad_report(report.read_text(encoding="utf-8"))

    return run_repair_loop(
        source,
        output,
        max_iterations=max_iterations,
        generate_candidate=generate,
        inspect_drc=inspect,
        supported_actions=frozenset({"reroute", "route_unconnected"}),
    )


def write_repair_report(result: RepairLoopResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result.as_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

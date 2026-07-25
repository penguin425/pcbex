from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .models import ExecutionPlan


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
    return subprocess.run(
        [str(executable), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def apply_constraints(problem_path: Path, plan: ExecutionPlan, output: Path) -> None:
    problem = json.loads(problem_path.read_text(encoding="utf-8"))
    generated = [
        value
        for constraint in plan.constraints
        if (value := constraint.to_placement_json()) is not None
    ]
    problem["constraints"] = [*problem.get("constraints", []), *generated]
    output.write_text(json.dumps(problem, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

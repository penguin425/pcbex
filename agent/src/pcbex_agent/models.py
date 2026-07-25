from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Constraint:
    type: str
    parameters: dict[str, Any]
    source: str

    def to_placement_json(self) -> dict[str, Any] | None:
        if self.type == "near":
            return {
                "type": "near",
                "subject": self.parameters["subject"],
                "target": self.parameters["target"],
                "max_distance_nm": self.parameters["max_distance_nm"],
            }
        if self.type == "board_edge":
            return {
                "type": "board_edge",
                "subject": self.parameters["subject"],
                "edge": self.parameters["edge"],
                "max_distance_nm": self.parameters["max_distance_nm"],
            }
        if self.type == "keep_together":
            return {
                "type": "keep_together",
                "components": self.parameters["components"],
                "max_span_nm": self.parameters["max_span_nm"],
            }
        return None


@dataclass(frozen=True)
class PlanLimits:
    max_iterations: int = 3
    max_changed_components: int = 12
    min_score_improvement: float = 0.0

    def validate(self) -> None:
        if not 1 <= self.max_iterations <= 20:
            raise ValueError("max_iterations must be in 1..20")
        if not 1 <= self.max_changed_components <= 100:
            raise ValueError("max_changed_components must be in 1..100")
        if self.min_score_improvement < 0:
            raise ValueError("min_score_improvement must be non-negative")


@dataclass
class ExecutionPlan:
    requirements: str
    constraints: list[Constraint]
    limits: PlanLimits
    steps: list[str] = field(
        default_factory=lambda: [
            "validate_input",
            "place",
            "route",
            "rule_check",
            "repair_if_needed",
            "compare_scores",
            "write_output",
        ]
    )
    unsupported_requirements: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["placement_constraints"] = [
            value
            for constraint in self.constraints
            if (value := constraint.to_placement_json()) is not None
        ]
        return data


@dataclass(frozen=True)
class DrcViolation:
    rule: str
    severity: str
    message: str
    items: tuple[str, ...] = ()


@dataclass(frozen=True)
class RepairAction:
    kind: str
    reason: str
    parameters: dict[str, Any]

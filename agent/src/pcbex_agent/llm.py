from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .models import Constraint, ExecutionPlan, PlanLimits
from .planner import PlanningError

Transport = Callable[[str], str]


def build_plan_with_llm(
    requirements: str,
    transport: Transport,
    *,
    limits: PlanLimits | None = None,
) -> ExecutionPlan:
    """Use an injected LLM transport and validate its structured-only output.

    The transport receives a schema-constrained prompt and returns JSON. It has
    no filesystem or engine access, so coordinate changes remain impossible.
    """
    limits = limits or PlanLimits()
    limits.validate()
    prompt = (
        "Convert PCB placement requirements to JSON only. "
        'Schema: {"constraints":[{"type":"near|board_edge|keep_together|'
        'differential_pair","parameters":{},"source":""}],'
        '"unsupported_requirements":["..."]}. '
        "Never emit coordinates or commands.\nRequirements:\n"
        + requirements
    )
    try:
        raw: Any = json.loads(transport(prompt))
    except (TypeError, json.JSONDecodeError) as error:
        raise PlanningError(f"LLM did not return valid JSON: {error}") from error
    if not isinstance(raw, dict) or not isinstance(raw.get("constraints"), list):
        raise PlanningError("LLM response does not match the planning schema")
    constraints = []
    allowed = {"near", "board_edge", "keep_together", "differential_pair"}
    for item in raw["constraints"]:
        if (
            not isinstance(item, dict)
            or item.get("type") not in allowed
            or not isinstance(item.get("parameters"), dict)
            or not isinstance(item.get("source", ""), str)
        ):
            raise PlanningError("LLM returned an invalid constraint")
        if any(key in item["parameters"] for key in ("x", "y", "x_nm", "y_nm")):
            raise PlanningError("LLM constraints may not contain coordinates")
        constraints.append(
            Constraint(item["type"], item["parameters"], item.get("source", ""))
        )
    unsupported = raw.get("unsupported_requirements", [])
    if not isinstance(unsupported, list) or not all(
        isinstance(value, str) for value in unsupported
    ):
        raise PlanningError("invalid unsupported_requirements")
    return ExecutionPlan(
        requirements,
        constraints,
        limits,
        unsupported_requirements=unsupported,
    )

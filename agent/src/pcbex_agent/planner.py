from __future__ import annotations

import re

from .models import Constraint, ExecutionPlan, PlanLimits

REF = r"[A-Za-z][A-Za-z0-9_.+-]*"
NUMBER = r"\d+(?:\.\d+)?"


class PlanningError(ValueError):
    pass


def _nm(value: str) -> int:
    return round(float(value) * 1_000_000)


def build_plan(
    requirements: str,
    *,
    limits: PlanLimits | None = None,
) -> ExecutionPlan:
    """Convert a constrained natural-language request into an auditable plan.

    Ambiguous text is retained under ``unsupported_requirements`` rather than
    guessed. This function is deterministic; an LLM may produce the same schema
    upstream, but never controls coordinates or edits directly.
    """
    if not requirements.strip():
        raise PlanningError("requirements must not be empty")
    limits = limits or PlanLimits()
    limits.validate()
    constraints: list[Constraint] = []
    matched: list[tuple[int, int]] = []

    near_patterns = [
        rf"(?P<subject>{REF})\s+(?:near|close to)\s+(?P<target>{REF})(?:\s+within)?\s+(?P<distance>{NUMBER})\s*mm",
        rf"(?P<subject>{REF})を(?P<target>{REF})(?:の)?(?:近く|付近)に(?:、|,|\s)*(?P<distance>{NUMBER})\s*mm以内",
    ]
    for pattern in near_patterns:
        for match in re.finditer(pattern, requirements, re.IGNORECASE):
            constraints.append(
                Constraint(
                    "near",
                    {
                        "subject": match["subject"],
                        "target": match["target"],
                        "max_distance_nm": _nm(match["distance"]),
                    },
                    match.group(0),
                )
            )
            matched.append(match.span())

    edge_names = {
        "left": "left", "right": "right", "top": "top", "bottom": "bottom",
        "左": "left", "右": "right", "上": "top", "下": "bottom",
    }
    edge_patterns = [
        rf"(?P<subject>{REF})\s+(?:on|near|at)\s+(?:the\s+)?(?P<edge>left|right|top|bottom)\s+edge(?:\s+within\s+(?P<distance>{NUMBER})\s*mm)?",
        rf"(?P<subject>{REF})を基板の(?P<edge>左|右|上|下)端(?:から(?P<distance>{NUMBER})\s*mm以内)?",
    ]
    for pattern in edge_patterns:
        for match in re.finditer(pattern, requirements, re.IGNORECASE):
            constraints.append(
                Constraint(
                    "board_edge",
                    {
                        "subject": match["subject"],
                        "edge": edge_names[match["edge"].lower()],
                        "max_distance_nm": _nm(match["distance"] or "2"),
                    },
                    match.group(0),
                )
            )
            matched.append(match.span())

    keep_patterns = [
        rf"keep\s+(?P<refs>{REF}(?:\s*,\s*{REF})+)\s+together(?:\s+within\s+(?P<distance>{NUMBER})\s*mm)?",
        rf"(?P<refs>{REF}(?:\s*[、,]\s*{REF})+)をまとめて(?:\s*(?P<distance>{NUMBER})\s*mm以内)?",
    ]
    for pattern in keep_patterns:
        for match in re.finditer(pattern, requirements, re.IGNORECASE):
            refs = re.findall(REF, match["refs"])
            constraints.append(
                Constraint(
                    "keep_together",
                    {
                        "components": refs,
                        "max_span_nm": _nm(match["distance"] or "10"),
                    },
                    match.group(0),
                )
            )
            matched.append(match.span())

    differential = re.compile(
        rf"(?:differential\s+pair|差動(?:ペア|配線))\s*[:：]?\s*(?P<positive>{REF})\s*[,、/]\s*(?P<negative>{REF})",
        re.IGNORECASE,
    )
    for match in differential.finditer(requirements):
        constraints.append(
            Constraint(
                "differential_pair",
                {"positive": match["positive"], "negative": match["negative"]},
                match.group(0),
            )
        )
        matched.append(match.span())

    unsupported = []
    for sentence in re.split(r"[\n。;]+", requirements):
        sentence = sentence.strip()
        if not sentence:
            continue
        start = requirements.find(sentence)
        end = start + len(sentence)
        if not any(a < end and start < b for a, b in matched):
            unsupported.append(sentence)
    return ExecutionPlan(requirements, constraints, limits, unsupported_requirements=unsupported)

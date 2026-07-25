from __future__ import annotations

import re

from .models import DrcViolation

HEADER = re.compile(r"^\[(?P<rule>[^\]]+)\]:\s*(?P<message>.*)$")
SEVERITY = re.compile(
    r"^\s*(?:(?:Severity:\s*(?P<label>\w+))|(?:.+;\s*(?P<suffix>error|warning)))\s*$",
    re.IGNORECASE,
)
ITEM = re.compile(
    r"^\s*@?\((?P<location>[^)]+)\)(?::\s*(?P<description>.+))?\s*$"
)


def normalize_kicad_report(report: str) -> list[DrcViolation]:
    """Normalize KiCad's text DRC report without depending on localized prose."""
    violations: list[DrcViolation] = []
    rule: str | None = None
    message = ""
    severity = "error"
    items: list[str] = []

    def flush() -> None:
        nonlocal rule, message, severity, items
        if rule is not None:
            violations.append(DrcViolation(rule, severity.lower(), message, tuple(items)))
        rule, message, severity, items = None, "", "error", []

    for line in report.splitlines():
        if match := HEADER.match(line):
            flush()
            rule = match["rule"].strip()
            message = match["message"].strip()
        elif rule is not None and (match := SEVERITY.match(line)):
            severity = match["label"] or match["suffix"]
        elif rule is not None and (match := ITEM.match(line)):
            description = match["description"]
            items.append(
                f"{match['location'].strip()}: {description.strip()}"
                if description
                else match["location"].strip()
            )
    flush()
    return violations

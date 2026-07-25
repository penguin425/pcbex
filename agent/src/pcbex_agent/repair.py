from __future__ import annotations

from .models import DrcViolation, RepairAction


def propose_repairs(violations: list[DrcViolation]) -> list[RepairAction]:
    actions: list[RepairAction] = []
    rules = {v.rule.lower() for v in violations if v.severity != "warning"}
    if any("clearance" in rule or "short" in rule for rule in rules):
        actions.append(
            RepairAction(
                "reroute",
                "copper clearance or short-circuit violation",
                {"increase_congestion": 4, "ripup_conflicts": True},
            )
        )
    if any("unconnected" in rule for rule in rules):
        actions.append(
            RepairAction(
                "route_unconnected",
                "unconnected items remain",
                {"prioritize_failed_nets": True},
            )
        )
    if any("courtyard" in rule or "overlap" in rule for rule in rules):
        actions.append(
            RepairAction(
                "replace",
                "component overlap violation",
                {"increase_overlap_weight": 2.0},
            )
        )
    if any("board_edge" in rule or "edge_clearance" in rule for rule in rules):
        actions.append(
            RepairAction(
                "replace",
                "board-edge clearance violation",
                {"increase_boundary_weight": 2.0},
            )
        )
    return actions

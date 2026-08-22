"""Freshly bind routing/manufacturing replay to native KiCad DRC evidence.

The Python layer composes two existing authorities without reimplementing
their algorithms.  It first reproduces one retained v1.476
routing/manufacturing handoff, then asks the Rust CLI to freshly verify one
retained normalized native KiCad PCB DRC report against the exact same routed
board and companion files.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .bounded_process import BoundedProcessError, run_bounded
from . import manufacturing_replay as _manufacturing
from . import routing_manufacturing_handoff as _handoff


ROUTING_DRC_MANUFACTURING_HANDOFF_SCHEMA_VERSION = 1
ROUTING_DRC_MANUFACTURING_HANDOFF_SCOPE = (
    "fresh-exact-routing-native-drc-manufacturing-handoff-v1"
)

MAXIMUM_NATIVE_KICAD_DRC_REPORT_BYTES = 32 * 1024 * 1024
MAXIMUM_ROUTING_DRC_MANUFACTURING_HANDOFF_REPORT_BYTES = 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = 724 * 1024 * 1024
MAXIMUM_CHILD_STDOUT_BYTES = 64 * 1024
MAXIMUM_CHILD_STDERR_BYTES = 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600.0
DEFAULT_TIMEOUT_SECONDS = 300.0

_REPORT_BINDING_DOMAIN = (
    b"pcbex:fresh-exact-routing-native-drc-manufacturing-handoff:v1\0"
)
_NATIVE_DRC_BINDING_DOMAIN = b"pcbex/native-kicad-pcb-drc/v1\0"
_HEX = frozenset("0123456789abcdef")

_REPORT_KEYS = (
    "schema_version",
    "verification_scope",
    "status",
    "ready",
    "source_authenticity_verified",
    "native_kicad_drc_verified",
    "manufacturability_verified",
    "fabrication_authorized",
    "release_authorized",
    "sources",
    "routing_manufacturing_handoff",
    "native_kicad_drc",
    "gate_failures",
    "validation",
    "binding_sha256",
)
_SOURCE_KEYS = (
    "input_board",
    "routed_board",
    "convergence_report",
    "routing_verification_report",
    "manufacturing_package",
    "routing_manufacturing_handoff_report",
    "native_kicad_drc_report",
    "project",
    "rules_file",
    "fab_profile",
    "physical_profile",
)
_HANDOFF_PROJECTION_KEYS = (
    "retained_report",
    "schema_version",
    "verification_scope",
    "status",
    "ready",
    "built_in_dfm_profile",
    "sources",
    "binding_sha256",
)
_NATIVE_DRC_PROJECTION_KEYS = (
    "retained_report",
    "schema_version",
    "engine_version",
    "kicad_version",
    "approved",
    "source",
    "project",
    "rules_file",
    "violation_count",
    "unconnected_item_count",
    "schematic_parity_count",
    "error_count",
    "warning_count",
    "ignored_check_count",
    "run_sha256",
)
_VALIDATION_KEYS = (
    "source_closure_captured",
    "routing_manufacturing_handoff_replayed",
    "retained_routing_manufacturing_handoff_exact",
    "routed_board_identity_matched",
    "shared_sidecars_matched",
    "native_kicad_drc_replayed",
    "retained_native_kicad_drc_exact",
    "caller_inputs_unchanged",
)
_NATIVE_DRC_REPORT_KEYS = (
    "schema_version",
    "engine",
    "engine_version",
    "kicad_version",
    "source",
    "project",
    "rules_file",
    "invocation",
    "ignored_checks",
    "findings",
    "violation_count",
    "unconnected_item_count",
    "schematic_parity_count",
    "error_count",
    "warning_count",
    "approved",
    "run_sha256",
)
_NATIVE_DRC_SUMMARY_KEYS = (
    "schema_version",
    "approved",
    "violation_count",
    "unconnected_item_count",
    "schematic_parity_count",
    "error_count",
    "warning_count",
    "ignored_check_count",
    "board_bytes",
    "board_sha256",
    "project_bytes",
    "project_sha256",
    "rules_file_bytes",
    "rules_file_sha256",
    "run_sha256",
    "report_bytes",
    "report_sha256",
)


class RoutingDrcManufacturingHandoffError(ValueError):
    """Stable, path-free routing/DRC/manufacturing composition failure."""


def _fail(message: str) -> RoutingDrcManufacturingHandoffError:
    return RoutingDrcManufacturingHandoffError(message)


def _public_root() -> str:
    try:
        root = os.getcwd()
    except Exception:
        raise _fail("caller working directory is invalid") from None
    if type(root) is not str or not os.path.isabs(root):
        raise _fail("caller working directory is invalid")
    return root


def _guard_cwd(
    root: str, operation: Callable[..., Any], *args: Any, **kwargs: Any
) -> Any:
    try:
        result = operation(*args, **kwargs)
    finally:
        try:
            observed = os.getcwd()
        except Exception:
            try:
                os.chdir(root)
            except Exception:
                raise _fail(
                    "caller working directory became invalid and could not be restored"
                ) from None
            raise _fail("caller working directory became invalid and was restored") from None
        if observed != root:
            try:
                os.chdir(root)
            except Exception:
                raise _fail(
                    "caller working directory changed and could not be restored"
                ) from None
            raise _fail("caller-controlled hook changed the working directory")
    return result


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha256(raw)}


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _bounded_text(value: Any, maximum: int) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise _fail("native KiCad DRC text is invalid")
    try:
        if len(value.encode("utf-8")) > maximum:
            raise _fail("native KiCad DRC text exceeds its byte bound")
    except UnicodeError:
        raise _fail("native KiCad DRC text is invalid") from None
    return value


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    class DuplicateKey(ValueError):
        pass

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateKey
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise ValueError

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (
        UnicodeError,
        json.JSONDecodeError,
        DuplicateKey,
        ValueError,
        RecursionError,
    ):
        raise _fail(f"{label} is not strict JSON") from None
    if not isinstance(value, dict):
        raise _fail(f"{label} must be a JSON object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: Sequence[str], label: str) -> None:
    try:
        observed = set(value)
    except Exception:
        raise _fail(f"{label} shape is invalid") from None
    if observed != set(expected):
        raise _fail(f"{label} shape is invalid")


def _normalize_identity(value: Any, maximum: int, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail(f"{label} identity is invalid")
    _exact_keys(value, ("bytes", "sha256"), f"{label} identity")
    count = value.get("bytes")
    digest = value.get("sha256")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 1
        or count > maximum
        or not _is_digest(digest)
    ):
        raise _fail(f"{label} identity is invalid")
    return {"bytes": count, "sha256": digest}


def _nullable_identity(value: Any, maximum: int, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    return _normalize_identity(value, maximum, label)


def _bounded_count(value: Any, maximum: int, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > maximum
    ):
        raise _fail(f"{label} is invalid")
    return value


def _freeze_path(value: str | os.PathLike[str], label: str, root: str) -> str:
    try:
        rendered = _guard_cwd(root, os.fspath, value)
        if type(rendered) is not str or not rendered:
            raise TypeError
        drive, _tail = os.path.splitdrive(rendered)
        if drive and not os.path.isabs(rendered):
            raise ValueError
        return os.path.abspath(os.path.join(root, rendered))
    except RoutingDrcManufacturingHandoffError:
        raise
    except Exception:
        raise _fail(f"{label} path is invalid") from None


def _read_source(path: str, maximum: int, label: str) -> bytes:
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} source is invalid") from None
    if not raw:
        raise _fail(f"{label} source is empty")
    return raw


def _same_path(left: str, right: str) -> bool:
    try:
        if os.path.samefile(left, right):
            return True
    except OSError:
        pass
    try:
        left_key = os.path.normcase(os.path.realpath(left)).casefold()
        right_key = os.path.normcase(os.path.realpath(right)).casefold()
    except (OSError, TypeError, ValueError):
        raise _fail("routing/DRC/manufacturing path identity is invalid") from None
    return left_key == right_key


def _reject_aliases(paths: Sequence[tuple[str, str]]) -> None:
    for index, (left_label, left) in enumerate(paths):
        for right_label, right in paths[index + 1 :]:
            if _same_path(left, right):
                raise _fail(f"{left_label} and {right_label} must not alias")


def _reread(paths: Sequence[tuple[str, bytes, int, str]]) -> None:
    for path, expected, maximum, label in paths:
        if _read_source(path, maximum, label) != expected:
            raise _fail(f"{label} source changed during replay")


def _verify_staged(paths: Sequence[tuple[Path, bytes, int, str]]) -> None:
    for path, expected, maximum, label in paths:
        if _read_source(str(path), maximum, label) != expected:
            raise _fail("trusted replay workspace input changed")


def _deadline(timeout_seconds: float, clock: Callable[[], float]) -> float:
    if type(timeout_seconds) not in {int, float}:
        raise _fail("aggregate timeout is invalid")
    try:
        timeout = float(timeout_seconds)
        start = float(clock())
    except RoutingDrcManufacturingHandoffError:
        raise
    except Exception:
        raise _fail("aggregate timeout is invalid") from None
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > MAXIMUM_TIMEOUT_SECONDS
        or not math.isfinite(start)
    ):
        raise _fail("aggregate timeout is invalid")
    result = start + timeout
    if not math.isfinite(result):
        raise _fail("aggregate timeout is invalid")
    return result


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    try:
        remaining = deadline - float(clock())
    except RoutingDrcManufacturingHandoffError:
        raise
    except Exception:
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("routing/DRC/manufacturing replay exceeded its aggregate deadline")
    return min(remaining, MAXIMUM_TIMEOUT_SECONDS)


def _normalize_native_drc_report(raw: bytes) -> dict[str, Any]:
    value = _strict_object(raw, "retained native KiCad DRC report")
    _exact_keys(value, _NATIVE_DRC_REPORT_KEYS, "native KiCad DRC report")
    if value.get("schema_version") != 1 or value.get("engine") != "pcbex":
        raise _fail("native KiCad DRC report header is invalid")
    engine_version = _bounded_text(value.get("engine_version"), 256)
    kicad_version = _bounded_text(value.get("kicad_version"), 256)
    source = _normalize_identity(
        value.get("source"), _handoff.MAXIMUM_ROUTED_BOARD_BYTES, "DRC board"
    )
    project = _nullable_identity(
        value.get("project"), _manufacturing.MAXIMUM_PROJECT_BYTES, "DRC project"
    )
    rules = _nullable_identity(
        value.get("rules_file"), _manufacturing.MAXIMUM_RULES_BYTES, "DRC rules"
    )

    invocation_value = value.get("invocation")
    invocation_keys = (
        "command",
        "format",
        "units",
        "severities",
        "exit_code_violations",
        "all_track_errors",
        "schematic_parity",
        "refill_zones",
        "save_board",
    )
    if not isinstance(invocation_value, Mapping):
        raise _fail("native KiCad DRC invocation is invalid")
    _exact_keys(invocation_value, invocation_keys, "native KiCad DRC invocation")
    invocation = {
        "command": invocation_value.get("command"),
        "format": invocation_value.get("format"),
        "units": invocation_value.get("units"),
        "severities": invocation_value.get("severities"),
        "exit_code_violations": invocation_value.get("exit_code_violations"),
        "all_track_errors": invocation_value.get("all_track_errors"),
        "schematic_parity": invocation_value.get("schematic_parity"),
        "refill_zones": invocation_value.get("refill_zones"),
        "save_board": invocation_value.get("save_board"),
    }
    if invocation != {
        "command": "pcb drc",
        "format": "json",
        "units": "mm",
        "severities": ["error", "warning"],
        "exit_code_violations": True,
        "all_track_errors": False,
        "schematic_parity": False,
        "refill_zones": False,
        "save_board": False,
    }:
        raise _fail("native KiCad DRC invocation is not fixed")

    ignored_value = value.get("ignored_checks")
    if not isinstance(ignored_value, list) or len(ignored_value) > 1024:
        raise _fail("native KiCad DRC ignored checks are invalid")
    ignored: list[dict[str, str]] = []
    ignored_keys: set[str] = set()
    for item in ignored_value:
        if not isinstance(item, Mapping):
            raise _fail("native KiCad DRC ignored check is invalid")
        _exact_keys(item, ("description", "key"), "native KiCad DRC ignored check")
        check = {
            "description": _bounded_text(item.get("description"), 4096),
            "key": _bounded_text(item.get("key"), 4096),
        }
        if check["key"] in ignored_keys:
            raise _fail("native KiCad DRC ignored check keys are not unique")
        ignored_keys.add(check["key"])
        ignored.append(check)
    if ignored != sorted(ignored, key=lambda item: (item["key"], item["description"])):
        raise _fail("native KiCad DRC ignored checks are not canonically sorted")

    findings_value = value.get("findings")
    if not isinstance(findings_value, list) or len(findings_value) > 100_000:
        raise _fail("native KiCad DRC findings are invalid")
    findings: list[dict[str, Any]] = []
    violation_count = 0
    unconnected_count = 0
    error_count = 0
    warning_count = 0
    for finding_value in findings_value:
        if not isinstance(finding_value, Mapping):
            raise _fail("native KiCad DRC finding is invalid")
        _exact_keys(
            finding_value,
            ("category", "description", "items", "severity", "type"),
            "native KiCad DRC finding",
        )
        category = finding_value.get("category")
        severity = finding_value.get("severity")
        if type(category) is not str or category not in {
            "violation",
            "unconnected-item",
        }:
            raise _fail("native KiCad DRC finding category is invalid")
        if type(severity) is not str or severity not in {"error", "warning"}:
            raise _fail("native KiCad DRC finding severity is invalid")
        items_value = finding_value.get("items")
        if not isinstance(items_value, list) or len(items_value) > 1024:
            raise _fail("native KiCad DRC finding items are invalid")
        items: list[dict[str, Any]] = []
        for item_value in items_value:
            if not isinstance(item_value, Mapping):
                raise _fail("native KiCad DRC finding item is invalid")
            _exact_keys(
                item_value,
                ("description", "position_nm"),
                "native KiCad DRC finding item",
            )
            position_value = item_value.get("position_nm")
            if not isinstance(position_value, Mapping):
                raise _fail("native KiCad DRC finding position is invalid")
            _exact_keys(position_value, ("x", "y"), "native KiCad DRC position")
            x = position_value.get("x")
            y = position_value.get("y")
            if any(
                isinstance(coordinate, bool)
                or not isinstance(coordinate, int)
                or not -1_000_000_000_000_000 <= coordinate <= 1_000_000_000_000_000
                for coordinate in (x, y)
            ):
                raise _fail("native KiCad DRC finding position is invalid")
            items.append(
                {
                    "description": _bounded_text(item_value.get("description"), 4096),
                    "position_nm": {"x": x, "y": y},
                }
            )
        item_key = lambda item: (
            item["description"],
            item["position_nm"]["x"],
            item["position_nm"]["y"],
        )
        if items != sorted(items, key=item_key):
            raise _fail("native KiCad DRC finding items are not canonically sorted")
        finding = {
            "category": category,
            "description": _bounded_text(finding_value.get("description"), 4096),
            "items": items,
            "severity": severity,
            "type": _bounded_text(finding_value.get("type"), 4096),
        }
        findings.append(finding)
        violation_count += category == "violation"
        unconnected_count += category == "unconnected-item"
        error_count += severity == "error"
        warning_count += severity == "warning"

    def finding_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
        item_key_value = tuple(
            (
                nested["description"],
                nested["position_nm"]["x"],
                nested["position_nm"]["y"],
            )
            for nested in item["items"]
        )
        return (
            item["category"],
            item["severity"],
            item["type"],
            item["description"],
            item_key_value,
        )

    if findings != sorted(findings, key=finding_key):
        raise _fail("native KiCad DRC findings are not canonically sorted")

    counts = {
        "violation_count": _bounded_count(
            value.get("violation_count"), 100_000, "native DRC violation count"
        ),
        "unconnected_item_count": _bounded_count(
            value.get("unconnected_item_count"),
            100_000,
            "native DRC unconnected count",
        ),
        "schematic_parity_count": _bounded_count(
            value.get("schematic_parity_count"),
            100_000,
            "native DRC schematic-parity count",
        ),
        "error_count": _bounded_count(
            value.get("error_count"), 100_000, "native DRC error count"
        ),
        "warning_count": _bounded_count(
            value.get("warning_count"), 100_000, "native DRC warning count"
        ),
    }
    expected_counts = {
        "violation_count": violation_count,
        "unconnected_item_count": unconnected_count,
        "schematic_parity_count": 0,
        "error_count": error_count,
        "warning_count": warning_count,
    }
    if counts != expected_counts:
        raise _fail("native KiCad DRC report counts do not match findings")
    approved = value.get("approved")
    if type(approved) is not bool or approved != (error_count == 0 and warning_count == 0):
        raise _fail("native KiCad DRC approval is inconsistent")

    run_identity: dict[str, Any] = {
        "schema_version": 1,
        "engine": "pcbex",
        "engine_version": engine_version,
        "kicad_version": kicad_version,
        "source": source,
        "project": project,
        "rules_file": rules,
        "invocation": invocation,
        "ignored_checks": ignored,
        "findings": findings,
        **counts,
        "approved": approved,
    }
    run_sha256 = value.get("run_sha256")
    expected_run_sha256 = _sha256(
        _NATIVE_DRC_BINDING_DOMAIN
        + json.dumps(
            run_identity, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )
    if not _is_digest(run_sha256) or run_sha256 != expected_run_sha256:
        raise _fail("native KiCad DRC run binding is invalid")
    normalized = {**run_identity, "run_sha256": run_sha256}
    canonical = (
        json.dumps(normalized, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if canonical != raw:
        raise _fail("retained native KiCad DRC report is not canonical")
    return normalized


def _normalize_native_drc_summary(
    raw: bytes,
    report: Mapping[str, Any],
    report_raw: bytes,
) -> dict[str, Any]:
    value = _strict_object(raw, "native KiCad DRC child summary")
    _exact_keys(value, _NATIVE_DRC_SUMMARY_KEYS, "native KiCad DRC child summary")
    count_fields = (
        "violation_count",
        "unconnected_item_count",
        "schematic_parity_count",
        "error_count",
        "warning_count",
    )
    for field in count_fields:
        observed = value.get(field)
        if type(observed) is not int or observed != report.get(field):
            raise _fail("native KiCad DRC child summary counts are inconsistent")
    approved = value.get("approved")
    ignored_count = value.get("ignored_check_count")
    board_bytes = value.get("board_bytes")
    report_bytes = value.get("report_bytes")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or type(approved) is not bool
        or approved != report.get("approved")
        or type(ignored_count) is not int
        or ignored_count != len(report["ignored_checks"])
        or type(board_bytes) is not int
        or board_bytes != report["source"]["bytes"]
        or value.get("board_sha256") != report["source"]["sha256"]
        or value.get("run_sha256") != report.get("run_sha256")
        or type(report_bytes) is not int
        or report_bytes != len(report_raw)
        or value.get("report_sha256") != _sha256(report_raw)
    ):
        raise _fail("native KiCad DRC child summary is inconsistent")
    for prefix, identity in (
        ("project", report.get("project")),
        ("rules_file", report.get("rules_file")),
    ):
        expected_bytes: Any = "" if identity is None else identity["bytes"]
        expected_sha = "" if identity is None else identity["sha256"]
        observed_bytes = value.get(f"{prefix}_bytes")
        observed_sha = value.get(f"{prefix}_sha256")
        if (
            type(observed_bytes) is not type(expected_bytes)
            or observed_bytes != expected_bytes
            or type(observed_sha) is not str
            or observed_sha != expected_sha
        ):
            raise _fail("native KiCad DRC child summary companions are inconsistent")
    canonical = (
        json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if canonical != raw:
        raise _fail("native KiCad DRC child summary is not canonical")
    return dict(value)


def _handoff_projection(
    report: Mapping[str, Any], retained_raw: bytes
) -> dict[str, Any]:
    routing = report.get("routing_verification")
    if not isinstance(routing, Mapping):
        raise _fail("routing/manufacturing handoff projection is invalid")
    return {
        "retained_report": _identity(retained_raw),
        "schema_version": report["schema_version"],
        "verification_scope": report["verification_scope"],
        "status": report["status"],
        "ready": report["ready"],
        "built_in_dfm_profile": routing.get("built_in_dfm_profile"),
        "sources": deepcopy(report["sources"]),
        "binding_sha256": report["binding_sha256"],
    }


def _native_drc_projection(
    report: Mapping[str, Any], retained_raw: bytes
) -> dict[str, Any]:
    return {
        "retained_report": _identity(retained_raw),
        "schema_version": report["schema_version"],
        "engine_version": report["engine_version"],
        "kicad_version": report["kicad_version"],
        "approved": report["approved"],
        "source": deepcopy(report["source"]),
        "project": deepcopy(report["project"]),
        "rules_file": deepcopy(report["rules_file"]),
        "violation_count": report["violation_count"],
        "unconnected_item_count": report["unconnected_item_count"],
        "schematic_parity_count": report["schematic_parity_count"],
        "error_count": report["error_count"],
        "warning_count": report["warning_count"],
        "ignored_check_count": len(report["ignored_checks"]),
        "run_sha256": report["run_sha256"],
    }


def _binding(report: Mapping[str, Any]) -> str:
    payload = {key: report[key] for key in _REPORT_KEYS if key != "binding_sha256"}
    canonical = json.dumps(
        payload, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _sha256(_REPORT_BINDING_DOMAIN + canonical)


def _evaluate_impl(
    input_board: str | os.PathLike[str],
    routed_board: str | os.PathLike[str],
    convergence_report: str | os.PathLike[str],
    routing_verification_report: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    routing_manufacturing_handoff_report: str | os.PathLike[str],
    native_kicad_drc_report: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    kicad_cli: str | os.PathLike[str] = "kicad-cli",
    kicad_project: str | os.PathLike[str] | None = None,
    kicad_rules: str | os.PathLike[str] | None = None,
    grid_mm: float = 0.25,
    width_mm: float = 0.25,
    clearance_mm: float = 0.20,
    via_diameter_mm: float = 0.60,
    via_drill_mm: float = 0.30,
    bend_cost: int = 5,
    via_cost: int = 20,
    fab: str | None = None,
    fab_profile: str | os.PathLike[str] | None = None,
    physical_profile: str | os.PathLike[str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    _clock: Callable[[], float] = time.monotonic,
    _root: str,
) -> dict[str, Any]:
    selections = sum(source is not None for source in (fab, fab_profile, physical_profile))
    if selections > 1:
        raise _fail("manufacturing profile selections are mutually exclusive")

    caller_sources: list[tuple[str, bytes, int, str]] = []

    def capture(
        value: str | os.PathLike[str], maximum: int, label: str
    ) -> tuple[str, bytes]:
        path = _freeze_path(value, label, _root)
        raw = _read_source(path, maximum, label)
        caller_sources.append((path, raw, maximum, label))
        return path, raw

    input_source, input_raw = capture(
        input_board, _handoff.MAXIMUM_ROUTING_INPUT_BYTES, "routing input board"
    )
    routed_source, routed_raw = capture(
        routed_board, _handoff.MAXIMUM_ROUTED_BOARD_BYTES, "routed board"
    )
    convergence_source, convergence_raw = capture(
        convergence_report,
        _handoff.MAXIMUM_CONVERGENCE_REPORT_BYTES,
        "routing convergence report",
    )
    verification_source, verification_raw = capture(
        routing_verification_report,
        _handoff.MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES,
        "routing verification report",
    )
    package_source, package_raw = capture(
        manufacturing_package,
        _handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
        "manufacturing package",
    )
    handoff_source, handoff_raw = capture(
        routing_manufacturing_handoff_report,
        _handoff.MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES,
        "routing/manufacturing handoff report",
    )
    native_drc_source, native_drc_raw = capture(
        native_kicad_drc_report,
        MAXIMUM_NATIVE_KICAD_DRC_REPORT_BYTES,
        "native KiCad DRC report",
    )

    def capture_optional(
        value: str | os.PathLike[str] | None, maximum: int, label: str
    ) -> tuple[str | None, bytes | None]:
        if value is None:
            return None, None
        return capture(value, maximum, label)

    project_source, project_raw = capture_optional(
        kicad_project, _manufacturing.MAXIMUM_PROJECT_BYTES, "KiCad project"
    )
    rules_source, rules_raw = capture_optional(
        kicad_rules, _manufacturing.MAXIMUM_RULES_BYTES, "KiCad rules"
    )
    fab_profile_source, fab_profile_raw = capture_optional(
        fab_profile, _manufacturing.MAXIMUM_PROFILE_BYTES, "DFM profile"
    )
    physical_profile_source, physical_profile_raw = capture_optional(
        physical_profile,
        _manufacturing.MAXIMUM_PROFILE_BYTES,
        "physical profile",
    )
    _reject_aliases(
        [(label, path) for path, _raw, _maximum, label in caller_sources]
    )
    if sum(len(raw) for _path, raw, _maximum, _label in caller_sources) > MAXIMUM_TOTAL_INPUT_BYTES:
        raise _fail("routing/DRC/manufacturing inputs exceed their aggregate bound")

    try:
        normalized_handoff = _handoff._normalize_report(
            _strict_object(handoff_raw, "retained routing/manufacturing handoff report")
        )
        if _handoff.render_routing_manufacturing_handoff_report(normalized_handoff) != handoff_raw:
            raise _fail("retained routing/manufacturing handoff report is not canonical")
    except RoutingDrcManufacturingHandoffError:
        raise
    except Exception:
        raise _fail("retained routing/manufacturing handoff report is invalid") from None
    normalized_native_drc = _normalize_native_drc_report(native_drc_raw)
    _reread(caller_sources)

    try:
        command = _guard_cwd(_root, _manufacturing._normalize_command, pcbex)
        _reread(caller_sources)
        kicad_cli_argument = _guard_cwd(
            _root, _manufacturing._argument, kicad_cli, "kicad-cli argument"
        )
        _reread(caller_sources)
    except RoutingDrcManufacturingHandoffError:
        raise
    except Exception:
        raise _fail("routing/DRC/manufacturing command is invalid") from None

    last_clock: list[float | None] = [None]

    def guarded_clock() -> float:
        try:
            raw = _guard_cwd(_root, _clock)
        except RoutingDrcManufacturingHandoffError:
            raise
        except Exception:
            raise _fail("aggregate deadline clock is invalid") from None
        if isinstance(raw, bool) or type(raw) not in {int, float}:
            raise _fail("aggregate deadline clock is invalid")
        numeric = float(raw)
        if not math.isfinite(numeric):
            raise _fail("aggregate deadline clock is invalid")
        previous = last_clock[0]
        if previous is not None and numeric < previous:
            raise _fail("aggregate deadline clock moved backwards")
        last_clock[0] = numeric
        return numeric

    deadline = _deadline(timeout_seconds, guarded_clock)
    _reread(caller_sources)

    staged: list[tuple[Path, bytes, int, str]] = []
    native_projection: dict[str, Any] | None = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-routing-drc-manufacturing-handoff-",
            dir=_manufacturing._trusted_temporary_root(),
        ) as directory:
            root = Path(directory)

            def stage(
                role: str,
                basename: str,
                raw: bytes,
                maximum: int,
                label: str,
            ) -> Path:
                target = root / role / basename
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                atomic_write_no_clobber(target, raw, max_bytes=maximum)
                staged.append((target, raw, maximum, label))
                return target

            staged_input = stage(
                "input",
                Path(input_source).name,
                input_raw,
                _handoff.MAXIMUM_ROUTING_INPUT_BYTES,
                "staged routing input board",
            )
            staged_routed = stage(
                "routed",
                Path(routed_source).name,
                routed_raw,
                _handoff.MAXIMUM_ROUTED_BOARD_BYTES,
                "staged routed board",
            )
            staged_convergence = stage(
                "reports",
                "routing-convergence.json",
                convergence_raw,
                _handoff.MAXIMUM_CONVERGENCE_REPORT_BYTES,
                "staged convergence report",
            )
            staged_verification = stage(
                "reports",
                "routing-verification.json",
                verification_raw,
                _handoff.MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES,
                "staged routing verification report",
            )
            staged_package = stage(
                "package",
                "manufacturing.zip",
                package_raw,
                _handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
                "staged manufacturing package",
            )
            staged_handoff = stage(
                "reports",
                "routing-manufacturing-handoff.json",
                handoff_raw,
                _handoff.MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES,
                "staged routing/manufacturing handoff report",
            )
            staged_native_drc = stage(
                "reports",
                "native-kicad-drc.json",
                native_drc_raw,
                MAXIMUM_NATIVE_KICAD_DRC_REPORT_BYTES,
                "staged native KiCad DRC report",
            )
            staged_project = (
                None
                if project_raw is None
                else stage(
                    "routed",
                    Path(project_source or "input.kicad_pro").name,
                    project_raw,
                    _manufacturing.MAXIMUM_PROJECT_BYTES,
                    "staged KiCad project",
                )
            )
            staged_rules = (
                None
                if rules_raw is None
                else stage(
                    "routed",
                    Path(rules_source or "input.kicad_dru").name,
                    rules_raw,
                    _manufacturing.MAXIMUM_RULES_BYTES,
                    "staged KiCad rules",
                )
            )
            staged_fab_profile = (
                None
                if fab_profile_raw is None
                else stage(
                    "profile",
                    Path(fab_profile_source or "dfm-profile.json").name,
                    fab_profile_raw,
                    _manufacturing.MAXIMUM_PROFILE_BYTES,
                    "staged DFM profile",
                )
            )
            staged_physical_profile = (
                None
                if physical_profile_raw is None
                else stage(
                    "profile",
                    Path(physical_profile_source or "physical-profile.json").name,
                    physical_profile_raw,
                    _manufacturing.MAXIMUM_PROFILE_BYTES,
                    "staged physical profile",
                )
            )
            _verify_staged(staged)

            outer_remaining = _remaining(deadline, guarded_clock)
            handoff_timeout = outer_remaining / 2.0
            if not math.isfinite(handoff_timeout) or handoff_timeout <= 0:
                raise _fail("routing/manufacturing replay has no execution budget")
            try:
                fresh_handoff = _handoff.evaluate_routing_manufacturing_handoff(
                    staged_input,
                    staged_routed,
                    staged_convergence,
                    staged_verification,
                    staged_package,
                    command,
                    kicad_cli=kicad_cli_argument,
                    kicad_project=staged_project,
                    kicad_rules=staged_rules,
                    grid_mm=grid_mm,
                    width_mm=width_mm,
                    clearance_mm=clearance_mm,
                    via_diameter_mm=via_diameter_mm,
                    via_drill_mm=via_drill_mm,
                    bend_cost=bend_cost,
                    via_cost=via_cost,
                    fab=fab,
                    fab_profile=staged_fab_profile,
                    physical_profile=staged_physical_profile,
                    timeout_seconds=handoff_timeout,
                    _clock=guarded_clock,
                )
                fresh_handoff_raw = _handoff.render_routing_manufacturing_handoff_report(
                    fresh_handoff
                )
            except Exception:
                raise _fail("routing/manufacturing handoff replay failed") from None
            if fresh_handoff_raw != handoff_raw:
                raise _fail(
                    "fresh routing/manufacturing handoff did not reproduce the retained report"
                )
            if _read_source(
                str(staged_handoff),
                _handoff.MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES,
                "staged routing/manufacturing handoff report",
            ) != handoff_raw:
                raise _fail("trusted replay workspace input changed")
            _remaining(deadline, guarded_clock)
            _verify_staged(staged)
            _reread(caller_sources)

            handoff_ready = fresh_handoff.get("ready") is True
            if handoff_ready:
                drc_remaining = _remaining(deadline, guarded_clock)
                reserve = min(15.0, drc_remaining / 2.0)
                drc_timeout = drc_remaining - reserve
                if not math.isfinite(drc_timeout) or drc_timeout <= 0:
                    raise _fail("native KiCad DRC replay has no execution budget")
                argv = [
                    *command,
                    "verify-native-kicad-drc-report",
                    str(staged_routed),
                    str(staged_native_drc),
                    f"--kicad-cli={kicad_cli_argument}",
                    "--mcp-echo-report-summary",
                ]
                if staged_project is not None:
                    argv.append(f"--project={staged_project}")
                if staged_rules is not None:
                    argv.append(f"--rules-file={staged_rules}")
                try:
                    argv = _manufacturing._validate_final_argv(argv)
                    _verify_staged(staged)
                    completed = run_bounded(
                        argv,
                        timeout_seconds=drc_timeout,
                        max_stdout_bytes=MAXIMUM_CHILD_STDOUT_BYTES,
                        max_stderr_bytes=MAXIMUM_CHILD_STDERR_BYTES,
                    )
                except RoutingDrcManufacturingHandoffError:
                    raise
                except (
                    BoundedProcessError,
                    _manufacturing.ManufacturingReplayError,
                    OSError,
                    TypeError,
                    ValueError,
                ):
                    raise _fail("native KiCad DRC replay child failed") from None
                if completed.returncode != 0:
                    raise _fail("native KiCad DRC replay child rejected the evidence")
                _normalize_native_drc_summary(
                    completed.stdout, normalized_native_drc, native_drc_raw
                )
                _remaining(deadline, guarded_clock)
                _verify_staged(staged)
                _reread(caller_sources)
                native_projection = _native_drc_projection(
                    normalized_native_drc, native_drc_raw
                )
    except RoutingDrcManufacturingHandoffError:
        raise
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail("routing/DRC/manufacturing private workspace failed") from None

    _remaining(deadline, guarded_clock)
    _reread(caller_sources)
    handoff_sources = normalized_handoff["sources"]
    expected_handoff_sources = {
        "input_board": _identity(input_raw),
        "routed_board": _identity(routed_raw),
        "convergence_report": _identity(convergence_raw),
        "routing_verification_report": _identity(verification_raw),
        "manufacturing_package": _identity(package_raw),
        "project": None if project_raw is None else _identity(project_raw),
        "rules_file": None if rules_raw is None else _identity(rules_raw),
        "fab_profile": None if fab_profile_raw is None else _identity(fab_profile_raw),
        "physical_profile": (
            None if physical_profile_raw is None else _identity(physical_profile_raw)
        ),
    }
    if handoff_sources != expected_handoff_sources:
        raise _fail("routing/manufacturing handoff sources do not match the outer closure")
    if normalized_native_drc["source"] != _identity(routed_raw):
        raise _fail("native KiCad DRC does not use the routed board")
    if normalized_native_drc["project"] != expected_handoff_sources["project"]:
        raise _fail("native KiCad DRC project does not match the handoff")
    if normalized_native_drc["rules_file"] != expected_handoff_sources["rules_file"]:
        raise _fail("native KiCad DRC rules do not match the handoff")

    handoff_ready = normalized_handoff["ready"] is True
    drc_approved = native_projection is not None and native_projection["approved"] is True
    ready = handoff_ready and drc_approved
    if not handoff_ready:
        gate_failures = ["routing_incomplete"]
    elif not drc_approved:
        gate_failures = ["native_drc_rejected"]
    else:
        gate_failures = []

    sources = {
        "input_board": expected_handoff_sources["input_board"],
        "routed_board": expected_handoff_sources["routed_board"],
        "convergence_report": expected_handoff_sources["convergence_report"],
        "routing_verification_report": expected_handoff_sources[
            "routing_verification_report"
        ],
        "manufacturing_package": expected_handoff_sources[
            "manufacturing_package"
        ],
        "routing_manufacturing_handoff_report": _identity(handoff_raw),
        "native_kicad_drc_report": _identity(native_drc_raw),
        "project": expected_handoff_sources["project"],
        "rules_file": expected_handoff_sources["rules_file"],
        "fab_profile": expected_handoff_sources["fab_profile"],
        "physical_profile": expected_handoff_sources["physical_profile"],
    }
    result: dict[str, Any] = {
        "schema_version": ROUTING_DRC_MANUFACTURING_HANDOFF_SCHEMA_VERSION,
        "verification_scope": ROUTING_DRC_MANUFACTURING_HANDOFF_SCOPE,
        "status": "verified_ready" if ready else "not_ready",
        "ready": ready,
        "source_authenticity_verified": False,
        "native_kicad_drc_verified": ready,
        "manufacturability_verified": False,
        "fabrication_authorized": False,
        "release_authorized": False,
        "sources": sources,
        "routing_manufacturing_handoff": _handoff_projection(
            normalized_handoff, handoff_raw
        ),
        "native_kicad_drc": native_projection,
        "gate_failures": gate_failures,
        "validation": {
            "source_closure_captured": True,
            "routing_manufacturing_handoff_replayed": True,
            "retained_routing_manufacturing_handoff_exact": True,
            "routed_board_identity_matched": True,
            "shared_sidecars_matched": True,
            "native_kicad_drc_replayed": native_projection is not None,
            "retained_native_kicad_drc_exact": native_projection is not None,
            "caller_inputs_unchanged": True,
        },
        "binding_sha256": "",
    }
    result["binding_sha256"] = _binding(result)
    return _normalize_report(result)


def evaluate_routing_drc_manufacturing_handoff(
    input_board: str | os.PathLike[str],
    routed_board: str | os.PathLike[str],
    convergence_report: str | os.PathLike[str],
    routing_verification_report: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    routing_manufacturing_handoff_report: str | os.PathLike[str],
    native_kicad_drc_report: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    kicad_cli: str | os.PathLike[str] = "kicad-cli",
    kicad_project: str | os.PathLike[str] | None = None,
    kicad_rules: str | os.PathLike[str] | None = None,
    grid_mm: float = 0.25,
    width_mm: float = 0.25,
    clearance_mm: float = 0.20,
    via_diameter_mm: float = 0.60,
    via_drill_mm: float = 0.30,
    bend_cost: int = 5,
    via_cost: int = 20,
    fab: str | None = None,
    fab_profile: str | os.PathLike[str] | None = None,
    physical_profile: str | os.PathLike[str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly verify routing, exact manufacturing output, and native DRC."""

    root = _public_root()
    try:
        return _guard_cwd(
            root,
            _evaluate_impl,
            input_board,
            routed_board,
            convergence_report,
            routing_verification_report,
            manufacturing_package,
            routing_manufacturing_handoff_report,
            native_kicad_drc_report,
            pcbex,
            kicad_cli=kicad_cli,
            kicad_project=kicad_project,
            kicad_rules=kicad_rules,
            grid_mm=grid_mm,
            width_mm=width_mm,
            clearance_mm=clearance_mm,
            via_diameter_mm=via_diameter_mm,
            via_drill_mm=via_drill_mm,
            bend_cost=bend_cost,
            via_cost=via_cost,
            fab=fab,
            fab_profile=fab_profile,
            physical_profile=physical_profile,
            timeout_seconds=timeout_seconds,
            _clock=_clock,
            _root=root,
        )
    except RoutingDrcManufacturingHandoffError:
        raise
    except Exception:
        raise _fail("routing/DRC/manufacturing inputs are invalid") from None


def _normalize_handoff_projection(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("routing/manufacturing handoff projection is invalid")
    _exact_keys(value, _HANDOFF_PROJECTION_KEYS, "routing/manufacturing projection")
    retained = _normalize_identity(
        value.get("retained_report"),
        _handoff.MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES,
        "retained routing/manufacturing report",
    )
    if (
        value.get("schema_version") != 1
        or value.get("verification_scope") != _handoff.ROUTING_MANUFACTURING_HANDOFF_SCOPE
        or type(value.get("status")) is not str
        or value.get("status") not in {"verified_ready", "not_ready"}
        or type(value.get("ready")) is not bool
        or value.get("ready") != (value.get("status") == "verified_ready")
        or not _is_digest(value.get("binding_sha256"))
    ):
        raise _fail("routing/manufacturing handoff projection is inconsistent")
    built_in = value.get("built_in_dfm_profile")
    if built_in is not None and (
        not isinstance(built_in, str)
        or not built_in
        or len(built_in.encode("utf-8")) > 256
    ):
        raise _fail("routing/manufacturing built-in profile is invalid")
    sources_value = value.get("sources")
    if not isinstance(sources_value, Mapping):
        raise _fail("routing/manufacturing projected sources are invalid")
    _exact_keys(sources_value, _handoff._SOURCE_KEYS, "projected handoff sources")
    sources = {
        "input_board": _normalize_identity(
            sources_value.get("input_board"),
            _handoff.MAXIMUM_ROUTING_INPUT_BYTES,
            "projected input board",
        ),
        "routed_board": _normalize_identity(
            sources_value.get("routed_board"),
            _handoff.MAXIMUM_ROUTED_BOARD_BYTES,
            "projected routed board",
        ),
        "convergence_report": _normalize_identity(
            sources_value.get("convergence_report"),
            _handoff.MAXIMUM_CONVERGENCE_REPORT_BYTES,
            "projected convergence report",
        ),
        "routing_verification_report": _normalize_identity(
            sources_value.get("routing_verification_report"),
            _handoff.MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES,
            "projected routing verification",
        ),
        "manufacturing_package": _normalize_identity(
            sources_value.get("manufacturing_package"),
            _handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
            "projected manufacturing package",
        ),
        "project": _nullable_identity(
            sources_value.get("project"),
            _manufacturing.MAXIMUM_PROJECT_BYTES,
            "projected project",
        ),
        "rules_file": _nullable_identity(
            sources_value.get("rules_file"),
            _manufacturing.MAXIMUM_RULES_BYTES,
            "projected rules",
        ),
        "fab_profile": _nullable_identity(
            sources_value.get("fab_profile"),
            _manufacturing.MAXIMUM_PROFILE_BYTES,
            "projected DFM profile",
        ),
        "physical_profile": _nullable_identity(
            sources_value.get("physical_profile"),
            _manufacturing.MAXIMUM_PROFILE_BYTES,
            "projected physical profile",
        ),
    }
    return {
        "retained_report": retained,
        "schema_version": 1,
        "verification_scope": _handoff.ROUTING_MANUFACTURING_HANDOFF_SCOPE,
        "status": value["status"],
        "ready": value["ready"],
        "built_in_dfm_profile": built_in,
        "sources": sources,
        "binding_sha256": value["binding_sha256"],
    }


def _normalize_native_projection(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("native KiCad DRC projection is invalid")
    _exact_keys(value, _NATIVE_DRC_PROJECTION_KEYS, "native KiCad DRC projection")
    counts = {
        name: _bounded_count(value.get(name), 100_000, f"native DRC {name}")
        for name in (
            "violation_count",
            "unconnected_item_count",
            "schematic_parity_count",
            "error_count",
            "warning_count",
        )
    }
    ignored_count = _bounded_count(
        value.get("ignored_check_count"), 1024, "native DRC ignored check count"
    )
    approved = value.get("approved")
    if (
        value.get("schema_version") != 1
        or type(approved) is not bool
        or approved != (counts["error_count"] == 0 and counts["warning_count"] == 0)
        or not _is_digest(value.get("run_sha256"))
    ):
        raise _fail("native KiCad DRC projection is inconsistent")
    return {
        "retained_report": _normalize_identity(
            value.get("retained_report"),
            MAXIMUM_NATIVE_KICAD_DRC_REPORT_BYTES,
            "retained native DRC report",
        ),
        "schema_version": 1,
        "engine_version": _bounded_text(value.get("engine_version"), 256),
        "kicad_version": _bounded_text(value.get("kicad_version"), 256),
        "approved": approved,
        "source": _normalize_identity(
            value.get("source"), _handoff.MAXIMUM_ROUTED_BOARD_BYTES, "native DRC board"
        ),
        "project": _nullable_identity(
            value.get("project"), _manufacturing.MAXIMUM_PROJECT_BYTES, "native DRC project"
        ),
        "rules_file": _nullable_identity(
            value.get("rules_file"), _manufacturing.MAXIMUM_RULES_BYTES, "native DRC rules"
        ),
        **counts,
        "ignored_check_count": ignored_count,
        "run_sha256": value["run_sha256"],
    }


def _normalize_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("routing/DRC/manufacturing report is invalid")
    _exact_keys(value, _REPORT_KEYS, "routing/DRC/manufacturing report")
    status = value.get("status")
    ready = value.get("ready")
    if (
        value.get("schema_version") != ROUTING_DRC_MANUFACTURING_HANDOFF_SCHEMA_VERSION
        or value.get("verification_scope") != ROUTING_DRC_MANUFACTURING_HANDOFF_SCOPE
        or type(status) is not str
        or status not in {"verified_ready", "not_ready"}
        or type(ready) is not bool
        or ready != (status == "verified_ready")
    ):
        raise _fail("routing/DRC/manufacturing report header is invalid")
    for claim in (
        "source_authenticity_verified",
        "manufacturability_verified",
        "fabrication_authorized",
        "release_authorized",
    ):
        if value.get(claim) is not False:
            raise _fail("routing/DRC/manufacturing report contains unsupported claims")
    if value.get("native_kicad_drc_verified") is not ready:
        raise _fail("native KiCad DRC verification claim is inconsistent")

    sources_value = value.get("sources")
    if not isinstance(sources_value, Mapping):
        raise _fail("routing/DRC/manufacturing sources are invalid")
    _exact_keys(sources_value, _SOURCE_KEYS, "routing/DRC/manufacturing sources")
    sources = {
        "input_board": _normalize_identity(
            sources_value.get("input_board"),
            _handoff.MAXIMUM_ROUTING_INPUT_BYTES,
            "input board",
        ),
        "routed_board": _normalize_identity(
            sources_value.get("routed_board"),
            _handoff.MAXIMUM_ROUTED_BOARD_BYTES,
            "routed board",
        ),
        "convergence_report": _normalize_identity(
            sources_value.get("convergence_report"),
            _handoff.MAXIMUM_CONVERGENCE_REPORT_BYTES,
            "convergence report",
        ),
        "routing_verification_report": _normalize_identity(
            sources_value.get("routing_verification_report"),
            _handoff.MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES,
            "routing verification report",
        ),
        "manufacturing_package": _normalize_identity(
            sources_value.get("manufacturing_package"),
            _handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
            "manufacturing package",
        ),
        "routing_manufacturing_handoff_report": _normalize_identity(
            sources_value.get("routing_manufacturing_handoff_report"),
            _handoff.MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES,
            "routing/manufacturing handoff report",
        ),
        "native_kicad_drc_report": _normalize_identity(
            sources_value.get("native_kicad_drc_report"),
            MAXIMUM_NATIVE_KICAD_DRC_REPORT_BYTES,
            "native KiCad DRC report",
        ),
        "project": _nullable_identity(
            sources_value.get("project"), _manufacturing.MAXIMUM_PROJECT_BYTES, "project"
        ),
        "rules_file": _nullable_identity(
            sources_value.get("rules_file"), _manufacturing.MAXIMUM_RULES_BYTES, "rules"
        ),
        "fab_profile": _nullable_identity(
            sources_value.get("fab_profile"),
            _manufacturing.MAXIMUM_PROFILE_BYTES,
            "DFM profile",
        ),
        "physical_profile": _nullable_identity(
            sources_value.get("physical_profile"),
            _manufacturing.MAXIMUM_PROFILE_BYTES,
            "physical profile",
        ),
    }
    handoff = _normalize_handoff_projection(value.get("routing_manufacturing_handoff"))
    native_value = value.get("native_kicad_drc")
    native = None if native_value is None else _normalize_native_projection(native_value)
    if handoff["retained_report"] != sources["routing_manufacturing_handoff_report"]:
        raise _fail("routing/manufacturing retained-report identity is inconsistent")
    if handoff["sources"] != {
        key: sources[key]
        for key in _handoff._SOURCE_KEYS
    }:
        raise _fail("routing/manufacturing projected sources are inconsistent")
    if native is not None:
        if (
            native["retained_report"] != sources["native_kicad_drc_report"]
            or native["source"] != sources["routed_board"]
            or native["project"] != sources["project"]
            or native["rules_file"] != sources["rules_file"]
        ):
            raise _fail("native KiCad DRC projection is not cross-bound")

    gate_value = value.get("gate_failures")
    if not isinstance(gate_value, list) or len(gate_value) > 1:
        raise _fail("routing/DRC/manufacturing gate failures are invalid")
    gates = list(gate_value)
    validation_value = value.get("validation")
    if not isinstance(validation_value, Mapping):
        raise _fail("routing/DRC/manufacturing validation is invalid")
    _exact_keys(validation_value, _VALIDATION_KEYS, "routing/DRC/manufacturing validation")
    if any(type(validation_value.get(key)) is not bool for key in _VALIDATION_KEYS):
        raise _fail("routing/DRC/manufacturing validation is invalid")
    validation = {key: validation_value[key] for key in _VALIDATION_KEYS}
    if any(
        validation[key] is not True
        for key in _VALIDATION_KEYS
        if key not in {"native_kicad_drc_replayed", "retained_native_kicad_drc_exact"}
    ):
        raise _fail("routing/DRC/manufacturing validation is incomplete")

    if ready:
        if (
            gates
            or not handoff["ready"]
            or native is None
            or not native["approved"]
            or not validation["native_kicad_drc_replayed"]
            or not validation["retained_native_kicad_drc_exact"]
        ):
            raise _fail("ready routing/DRC/manufacturing decision is inconsistent")
    elif not handoff["ready"]:
        if (
            gates != ["routing_incomplete"]
            or native is not None
            or validation["native_kicad_drc_replayed"]
            or validation["retained_native_kicad_drc_exact"]
        ):
            raise _fail("incomplete routing/DRC/manufacturing decision is inconsistent")
    else:
        if (
            gates != ["native_drc_rejected"]
            or native is None
            or native["approved"]
            or not validation["native_kicad_drc_replayed"]
            or not validation["retained_native_kicad_drc_exact"]
        ):
            raise _fail("rejected native DRC decision is inconsistent")

    normalized = {
        "schema_version": ROUTING_DRC_MANUFACTURING_HANDOFF_SCHEMA_VERSION,
        "verification_scope": ROUTING_DRC_MANUFACTURING_HANDOFF_SCOPE,
        "status": status,
        "ready": ready,
        "source_authenticity_verified": False,
        "native_kicad_drc_verified": ready,
        "manufacturability_verified": False,
        "fabrication_authorized": False,
        "release_authorized": False,
        "sources": sources,
        "routing_manufacturing_handoff": handoff,
        "native_kicad_drc": native,
        "gate_failures": gates,
        "validation": validation,
        "binding_sha256": value.get("binding_sha256"),
    }
    if not _is_digest(normalized["binding_sha256"]) or normalized["binding_sha256"] != _binding(normalized):
        raise _fail("routing/DRC/manufacturing binding is invalid")
    return normalized


def render_routing_drc_manufacturing_handoff_report(
    report: Mapping[str, Any]
) -> bytes:
    root = _public_root()

    def render() -> bytes:
        normalized = _normalize_report(deepcopy(report))
        try:
            raw = (
                json.dumps(normalized, indent=2, ensure_ascii=False) + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise _fail("routing/DRC/manufacturing report cannot be rendered") from None
        if len(raw) > MAXIMUM_ROUTING_DRC_MANUFACTURING_HANDOFF_REPORT_BYTES:
            raise _fail("routing/DRC/manufacturing report exceeds its byte limit")
        return raw

    try:
        return _guard_cwd(root, render)
    except RoutingDrcManufacturingHandoffError:
        raise
    except Exception:
        raise _fail("routing/DRC/manufacturing report is invalid") from None


def routing_drc_manufacturing_handoff_report_json_schema() -> dict[str, Any]:
    def identity(maximum: int) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": maximum,
                },
                "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            },
        }

    def nullable_identity(maximum: int) -> dict[str, Any]:
        return {"anyOf": [identity(maximum), {"type": "null"}]}

    handoff_source_limits = {
        "input_board": _handoff.MAXIMUM_ROUTING_INPUT_BYTES,
        "routed_board": _handoff.MAXIMUM_ROUTED_BOARD_BYTES,
        "convergence_report": _handoff.MAXIMUM_CONVERGENCE_REPORT_BYTES,
        "routing_verification_report": (
            _handoff.MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES
        ),
        "manufacturing_package": _handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
        "project": _manufacturing.MAXIMUM_PROJECT_BYTES,
        "rules_file": _manufacturing.MAXIMUM_RULES_BYTES,
        "fab_profile": _manufacturing.MAXIMUM_PROFILE_BYTES,
        "physical_profile": _manufacturing.MAXIMUM_PROFILE_BYTES,
    }
    optional_source_keys = {
        "project",
        "rules_file",
        "fab_profile",
        "physical_profile",
    }
    handoff_source_properties = {
        key: (
            nullable_identity(handoff_source_limits[key])
            if key in optional_source_keys
            else identity(handoff_source_limits[key])
        )
        for key in _handoff._SOURCE_KEYS
    }
    outer_source_limits = {
        **handoff_source_limits,
        "routing_manufacturing_handoff_report": (
            _handoff.MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES
        ),
        "native_kicad_drc_report": MAXIMUM_NATIVE_KICAD_DRC_REPORT_BYTES,
    }
    source_properties = {
        key: (
            nullable_identity(outer_source_limits[key])
            if key in optional_source_keys
            else identity(outer_source_limits[key])
        )
        for key in _SOURCE_KEYS
    }
    handoff_projection = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_HANDOFF_PROJECTION_KEYS),
        "properties": {
            "retained_report": identity(
                _handoff.MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES
            ),
            "schema_version": {"const": 1},
            "verification_scope": {"const": _handoff.ROUTING_MANUFACTURING_HANDOFF_SCOPE},
            "status": {"enum": ["verified_ready", "not_ready"]},
            "ready": {"type": "boolean"},
            "built_in_dfm_profile": {
                "anyOf": [
                    {"type": "string", "minLength": 1, "maxLength": 256},
                    {"type": "null"},
                ]
            },
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": list(_handoff._SOURCE_KEYS),
                "properties": handoff_source_properties,
            },
            "binding_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "allOf": [
            {
                "if": {"properties": {"ready": {"const": True}}},
                "then": {"properties": {"status": {"const": "verified_ready"}}},
                "else": {"properties": {"status": {"const": "not_ready"}}},
            }
        ],
    }
    native_projection = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_NATIVE_DRC_PROJECTION_KEYS),
        "properties": {
            "retained_report": identity(MAXIMUM_NATIVE_KICAD_DRC_REPORT_BYTES),
            "schema_version": {"const": 1},
            "engine_version": {"type": "string", "minLength": 1, "maxLength": 256},
            "kicad_version": {"type": "string", "minLength": 1, "maxLength": 256},
            "approved": {"type": "boolean"},
            "source": identity(_handoff.MAXIMUM_ROUTED_BOARD_BYTES),
            "project": nullable_identity(_manufacturing.MAXIMUM_PROJECT_BYTES),
            "rules_file": nullable_identity(_manufacturing.MAXIMUM_RULES_BYTES),
            "violation_count": {"type": "integer", "minimum": 0, "maximum": 100000},
            "unconnected_item_count": {"type": "integer", "minimum": 0, "maximum": 100000},
            "schematic_parity_count": {"type": "integer", "minimum": 0, "maximum": 100000},
            "error_count": {"type": "integer", "minimum": 0, "maximum": 100000},
            "warning_count": {"type": "integer", "minimum": 0, "maximum": 100000},
            "ignored_check_count": {"type": "integer", "minimum": 0, "maximum": 1024},
            "run_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "allOf": [
            {
                "if": {"properties": {"approved": {"const": True}}},
                "then": {
                    "properties": {
                        "error_count": {"const": 0},
                        "warning_count": {"const": 0},
                    }
                },
                "else": {
                    "anyOf": [
                        {"properties": {"error_count": {"minimum": 1}}},
                        {"properties": {"warning_count": {"minimum": 1}}},
                    ]
                },
            }
        ],
    }
    validation = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_VALIDATION_KEYS),
        "properties": {
            key: (
                {"type": "boolean"}
                if key
                in {"native_kicad_drc_replayed", "retained_native_kicad_drc_exact"}
                else {"const": True}
            )
            for key in _VALIDATION_KEYS
        },
    }
    schema: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "routing-native-drc-manufacturing-handoff-v1.json"
        ),
        "title": "pcbex fresh routing/native-DRC/manufacturing handoff",
        "type": "object",
        "additionalProperties": False,
        "required": list(_REPORT_KEYS),
        "properties": {
            "schema_version": {"const": 1},
            "verification_scope": {"const": ROUTING_DRC_MANUFACTURING_HANDOFF_SCOPE},
            "status": {"enum": ["verified_ready", "not_ready"]},
            "ready": {"type": "boolean"},
            "source_authenticity_verified": {"const": False},
            "native_kicad_drc_verified": {"type": "boolean"},
            "manufacturability_verified": {"const": False},
            "fabrication_authorized": {"const": False},
            "release_authorized": {"const": False},
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": list(_SOURCE_KEYS),
                "properties": source_properties,
            },
            "routing_manufacturing_handoff": {"$ref": "#/$defs/handoff_projection"},
            "native_kicad_drc": {
                "anyOf": [
                    {"$ref": "#/$defs/native_projection"},
                    {"type": "null"},
                ]
            },
            "gate_failures": {
                "type": "array",
                "maxItems": 1,
                "items": {"enum": ["routing_incomplete", "native_drc_rejected"]},
            },
            "validation": {"$ref": "#/$defs/validation"},
            "binding_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "$defs": {
            "handoff_projection": handoff_projection,
            "native_projection": native_projection,
            "validation": validation,
        },
        "allOf": [
            {
                "if": {"properties": {"ready": {"const": True}}},
                "then": {
                    "properties": {
                        "status": {"const": "verified_ready"},
                        "native_kicad_drc_verified": {"const": True},
                        "native_kicad_drc": {
                            "allOf": [
                                {"$ref": "#/$defs/native_projection"},
                                {"properties": {"approved": {"const": True}}},
                            ]
                        },
                        "gate_failures": {"maxItems": 0},
                        "routing_manufacturing_handoff": {
                            "allOf": [
                                {"$ref": "#/$defs/handoff_projection"},
                                {
                                    "properties": {
                                        "status": {"const": "verified_ready"},
                                        "ready": {"const": True},
                                    }
                                },
                            ]
                        },
                        "validation": {
                            "allOf": [
                                {"$ref": "#/$defs/validation"},
                                {
                                    "properties": {
                                        "native_kicad_drc_replayed": {"const": True},
                                        "retained_native_kicad_drc_exact": {
                                            "const": True
                                        },
                                    }
                                },
                            ]
                        },
                    }
                },
                "else": {
                    "properties": {
                        "status": {"const": "not_ready"},
                        "native_kicad_drc_verified": {"const": False},
                        "gate_failures": {"minItems": 1, "maxItems": 1},
                    },
                    "oneOf": [
                        {
                            "properties": {
                                "routing_manufacturing_handoff": {
                                    "allOf": [
                                        {"$ref": "#/$defs/handoff_projection"},
                                        {
                                            "properties": {
                                                "status": {"const": "not_ready"},
                                                "ready": {"const": False},
                                            }
                                        },
                                    ]
                                },
                                "native_kicad_drc": {"type": "null"},
                                "gate_failures": {
                                    "prefixItems": [{"const": "routing_incomplete"}],
                                    "items": False,
                                    "minItems": 1,
                                    "maxItems": 1,
                                },
                                "validation": {
                                    "allOf": [
                                        {"$ref": "#/$defs/validation"},
                                        {
                                            "properties": {
                                                "native_kicad_drc_replayed": {
                                                    "const": False
                                                },
                                                "retained_native_kicad_drc_exact": {
                                                    "const": False
                                                },
                                            }
                                        },
                                    ]
                                },
                            }
                        },
                        {
                            "properties": {
                                "routing_manufacturing_handoff": {
                                    "allOf": [
                                        {"$ref": "#/$defs/handoff_projection"},
                                        {
                                            "properties": {
                                                "status": {"const": "verified_ready"},
                                                "ready": {"const": True},
                                            }
                                        },
                                    ]
                                },
                                "native_kicad_drc": {
                                    "allOf": [
                                        {"$ref": "#/$defs/native_projection"},
                                        {"properties": {"approved": {"const": False}}},
                                    ]
                                },
                                "gate_failures": {
                                    "prefixItems": [{"const": "native_drc_rejected"}],
                                    "items": False,
                                    "minItems": 1,
                                    "maxItems": 1,
                                },
                                "validation": {
                                    "allOf": [
                                        {"$ref": "#/$defs/validation"},
                                        {
                                            "properties": {
                                                "native_kicad_drc_replayed": {
                                                    "const": True
                                                },
                                                "retained_native_kicad_drc_exact": {
                                                    "const": True
                                                },
                                            }
                                        },
                                    ]
                                },
                            }
                        },
                    ],
                },
            }
        ],
    }
    return schema


__all__ = [
    "MAXIMUM_ROUTING_DRC_MANUFACTURING_HANDOFF_REPORT_BYTES",
    "RoutingDrcManufacturingHandoffError",
    "evaluate_routing_drc_manufacturing_handoff",
    "render_routing_drc_manufacturing_handoff_report",
    "routing_drc_manufacturing_handoff_report_json_schema",
]

"""Freshly cross-bind routing convergence to manufacturing-package replay.

This module owns the Python composition boundary only.  Rust remains the
authority for routing convergence and manufacturing rules; the existing
``pcbex`` verifier and ``fabricate`` producer are invoked in private staging.
The one routed KiCad board captured here is reused by both stages.
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


ROUTING_MANUFACTURING_HANDOFF_SCHEMA_VERSION = 1
ROUTING_MANUFACTURING_HANDOFF_SCOPE = (
    "fresh-exact-routing-to-manufacturing-handoff-v1"
)

MAXIMUM_ROUTING_INPUT_BYTES = 128 * 1024 * 1024
MAXIMUM_ROUTED_BOARD_BYTES = 128 * 1024 * 1024
MAXIMUM_CONVERGENCE_REPORT_BYTES = 16 * 1024 * 1024
MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES = 32 * 1024 * 1024
MAXIMUM_MANUFACTURING_PACKAGE_BYTES = 128 * 1024 * 1024
MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES = 4 * 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = 688 * 1024 * 1024
MAXIMUM_CHILD_STDOUT_BYTES = 64 * 1024
MAXIMUM_CHILD_STDERR_BYTES = 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600.0
DEFAULT_TIMEOUT_SECONDS = 300.0

_ROUTING_BINDING_DOMAIN = (
    b"pcbex/fresh-exact-routing-convergence-verification/v1\0"
)
_HANDOFF_BINDING_DOMAIN = (
    b"pcbex:fresh-exact-routing-to-manufacturing-handoff:v1\0"
)
_HEX = frozenset("0123456789abcdef")
_ROUTING_STATUSES = frozenset(
    {
        "verified_complete",
        "verified_partial",
        "verified_no_admissible_candidate",
    }
)
_ROUTING_SOURCE_KEYS = (
    "input",
    "routed_output",
    "retained_report",
    "project",
    "rules_file",
    "fab_profile",
    "policy_pack",
    "physical_profile",
)
_ROUTING_VALIDATION_KEYS = (
    "source_closure_captured",
    "retained_report_canonical",
    "fresh_convergence_replayed",
    "retained_report_exact",
    "routed_output_exact",
    "caller_inputs_unchanged",
)
_ROUTING_REPORT_KEYS = (
    "schema_version",
    "scope",
    "engine_version",
    "input_kind",
    "status",
    "routing_complete",
    "source_authenticity_verified",
    "native_kicad_drc_verified",
    "manufacturability_verified",
    "release_authorized",
    "built_in_dfm_profile",
    "sources",
    "convergence",
    "validation",
    "binding_sha256",
)
_REPORT_KEYS = (
    "schema_version",
    "verification_scope",
    "status",
    "ready",
    "source_authenticity_verified",
    "native_kicad_drc_verified",
    "manufacturability_verified",
    "release_authorized",
    "sources",
    "routing_verification",
    "manufacturing_replay",
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
    "project",
    "rules_file",
    "fab_profile",
    "physical_profile",
)
_VALIDATION_KEYS = (
    "source_closure_captured",
    "routing_verification_replayed",
    "retained_routing_verification_exact",
    "routed_board_identity_matched",
    "shared_sidecars_matched",
    "manufacturing_package_replayed",
    "caller_inputs_unchanged",
)
_ROUTING_PROJECTION_KEYS = (
    "source",
    "engine_version",
    "status",
    "routing_complete",
    "built_in_dfm_profile",
    "binding_sha256",
    "sources",
)


class RoutingManufacturingHandoffError(ValueError):
    """Stable, path-free routing/manufacturing composition failure."""


def _fail(message: str) -> RoutingManufacturingHandoffError:
    return RoutingManufacturingHandoffError(message)


def _public_root() -> str:
    """Capture the caller's working directory before touching public values."""

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
    """Restore and reject any caller-controlled working-directory mutation."""

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


def _is_bounded_utf8(value: Any, maximum: int) -> bool:
    """Return whether *value* is non-empty UTF-8 text within *maximum* bytes."""

    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        return False


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
    if set(value) != set(expected):
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


def _optional_identity(value: Any, maximum: int, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    return _normalize_identity(value, maximum, label)


def _compact(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise _fail("report binding material is invalid") from None


def _routing_binding(report: Mapping[str, Any]) -> str:
    material = {key: report[key] for key in _ROUTING_REPORT_KEYS[:-1]}
    return _sha256(_ROUTING_BINDING_DOMAIN + _compact(material))


def _handoff_binding(report: Mapping[str, Any]) -> str:
    material = {key: report[key] for key in _REPORT_KEYS[:-1]}
    return _sha256(_HANDOFF_BINDING_DOMAIN + _compact(material))


def _normalize_routing_verification(
    value: Any,
    *,
    retained_source: dict[str, Any],
    input_identity: dict[str, Any],
    routed_identity: dict[str, Any],
    convergence_identity: dict[str, Any],
    project_identity: dict[str, Any] | None,
    rules_identity: dict[str, Any] | None,
    fab: str | None,
    fab_profile_identity: dict[str, Any] | None,
    physical_profile_identity: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise _fail("routing verification report is invalid")
    _exact_keys(value, _ROUTING_REPORT_KEYS, "routing verification report")
    if (
        value.get("schema_version") != 1
        or value.get("scope") != "fresh_exact_routing_convergence_verification"
        or value.get("input_kind") != "kicad_pcb"
        or not _is_bounded_utf8(value.get("engine_version"), 128)
        or value.get("status") not in _ROUTING_STATUSES
        or type(value.get("routing_complete")) is not bool
    ):
        raise _fail("routing verification report header is invalid")
    for claim in (
        "source_authenticity_verified",
        "native_kicad_drc_verified",
        "manufacturability_verified",
        "release_authorized",
    ):
        if value.get(claim) is not False:
            raise _fail("routing verification report contains unsupported claims")

    builtin = value.get("built_in_dfm_profile")
    if builtin is not None:
        try:
            builtin = _manufacturing._builtin_profile_id(builtin)
        except _manufacturing.ManufacturingReplayError:
            raise _fail("routing verification built-in profile is invalid") from None
    if (fab is None) != (builtin is None) or (fab is not None and builtin != fab):
        raise _fail("routing and manufacturing built-in profiles do not match")

    sources_value = value.get("sources")
    if not isinstance(sources_value, Mapping):
        raise _fail("routing verification sources are invalid")
    _exact_keys(sources_value, _ROUTING_SOURCE_KEYS, "routing verification sources")
    sources = {
        "input": _normalize_identity(
            sources_value["input"], MAXIMUM_ROUTING_INPUT_BYTES, "routing input"
        ),
        "routed_output": _normalize_identity(
            sources_value["routed_output"],
            MAXIMUM_ROUTED_BOARD_BYTES,
            "routed output",
        ),
        "retained_report": _normalize_identity(
            sources_value["retained_report"],
            MAXIMUM_CONVERGENCE_REPORT_BYTES,
            "convergence report",
        ),
        "project": _optional_identity(
            sources_value["project"],
            _manufacturing.MAXIMUM_PROJECT_BYTES,
            "KiCad project",
        ),
        "rules_file": _optional_identity(
            sources_value["rules_file"],
            _manufacturing.MAXIMUM_RULES_BYTES,
            "KiCad rules",
        ),
        "fab_profile": _optional_identity(
            sources_value["fab_profile"],
            _manufacturing.MAXIMUM_PROFILE_BYTES,
            "DFM profile",
        ),
        "policy_pack": _optional_identity(
            sources_value["policy_pack"], 64 * 1024 * 1024, "policy pack"
        ),
        "physical_profile": _optional_identity(
            sources_value["physical_profile"],
            _manufacturing.MAXIMUM_PROFILE_BYTES,
            "physical profile",
        ),
    }
    expected_sources = {
        "input": input_identity,
        "routed_output": routed_identity,
        "retained_report": convergence_identity,
        "project": project_identity,
        "rules_file": rules_identity,
        "fab_profile": fab_profile_identity,
        "policy_pack": None,
        "physical_profile": physical_profile_identity,
    }
    if sources != expected_sources:
        raise _fail("routing verification does not retain the exact captured closure")

    validation_value = value.get("validation")
    if not isinstance(validation_value, Mapping):
        raise _fail("routing verification validation is invalid")
    _exact_keys(
        validation_value, _ROUTING_VALIDATION_KEYS, "routing verification validation"
    )
    if any(validation_value[key] is not True for key in _ROUTING_VALIDATION_KEYS):
        raise _fail("routing verification checks are incomplete")

    convergence = value.get("convergence")
    if not isinstance(convergence, Mapping):
        raise _fail("routing verification convergence evidence is invalid")
    converged = convergence.get("converged")
    convergence_status = convergence.get("status")
    final_metrics = convergence.get("final_metrics")
    final_drc = convergence.get("final_drc_violation_count")
    if (
        type(converged) is not bool
        or convergence_status
        not in {"converged", "partial", "no_admissible_candidate"}
        or not isinstance(final_metrics, Mapping)
        or isinstance(final_metrics.get("unrouted_nets"), bool)
        or not isinstance(final_metrics.get("unrouted_nets"), int)
        or final_metrics["unrouted_nets"] < 0
        or isinstance(final_drc, bool)
        or not isinstance(final_drc, int)
        or final_drc < 0
    ):
        raise _fail("routing verification convergence decision is invalid")
    expected_status = {
        "converged": "verified_complete",
        "partial": "verified_partial",
        "no_admissible_candidate": "verified_no_admissible_candidate",
    }[convergence_status]
    complete = final_metrics["unrouted_nets"] == 0 and final_drc == 0
    if (
        value["status"] != expected_status
        or value["routing_complete"] is not converged
        or value["routing_complete"] is not complete
    ):
        raise _fail("routing verification decision is inconsistent")
    binding = value.get("binding_sha256")
    if not _is_digest(binding) or binding != _routing_binding(value):
        raise _fail("routing verification binding is invalid")

    projection = {
        "source": retained_source,
        "engine_version": value["engine_version"],
        "status": value["status"],
        "routing_complete": value["routing_complete"],
        "built_in_dfm_profile": builtin,
        "binding_sha256": binding,
        "sources": sources,
    }
    return projection, dict(value)


def _normalize_manufacturing_replay(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("manufacturing replay result is invalid")
    expected = (
        "schema_version",
        "verification_scope",
        "verified",
        "board",
        "project",
        "rules",
        "profile",
        "package",
        "validation",
    )
    _exact_keys(value, expected, "manufacturing replay result")
    if (
        value.get("schema_version") != 1
        or value.get("verification_scope")
        != _manufacturing.MANUFACTURING_REPLAY_SCOPE
        or value.get("verified") is not True
    ):
        raise _fail("manufacturing replay result header is invalid")
    board_value = value.get("board")
    if not isinstance(board_value, Mapping):
        raise _fail("manufacturing replay board is invalid")
    _exact_keys(board_value, ("name", "bytes", "sha256"), "manufacturing board")
    name = board_value.get("name")
    if (
        not isinstance(name, str)
        or not name.endswith(".kicad_pcb")
        or not _manufacturing._portable_leaf(name)
    ):
        raise _fail("manufacturing replay board is invalid")
    board_identity = _normalize_identity(
        {"bytes": board_value.get("bytes"), "sha256": board_value.get("sha256")},
        _manufacturing.MAXIMUM_BOARD_BYTES,
        "manufacturing board",
    )
    project = _optional_identity(
        value.get("project"), _manufacturing.MAXIMUM_PROJECT_BYTES, "manufacturing project"
    )
    rules = _optional_identity(
        value.get("rules"), _manufacturing.MAXIMUM_RULES_BYTES, "manufacturing rules"
    )
    profile_value = value.get("profile")
    if not isinstance(profile_value, Mapping):
        raise _fail("manufacturing replay profile is invalid")
    kind = profile_value.get("kind")
    if kind == "none":
        _exact_keys(profile_value, ("kind",), "manufacturing replay profile")
        profile: dict[str, Any] = {"kind": "none"}
    elif kind == "builtin":
        _exact_keys(profile_value, ("kind", "id"), "manufacturing replay profile")
        profile_id = profile_value.get("id")
        try:
            profile_id = _manufacturing._builtin_profile_id(profile_id)
        except _manufacturing.ManufacturingReplayError:
            raise _fail("manufacturing replay profile is invalid") from None
        profile = {"kind": "builtin", "id": profile_id}
    elif kind in {"dfm-file", "physical-file"}:
        _exact_keys(profile_value, ("kind", "source"), "manufacturing replay profile")
        source_value = profile_value.get("source")
        if not isinstance(source_value, Mapping):
            raise _fail("manufacturing replay profile is invalid")
        _exact_keys(source_value, ("name", "bytes", "sha256"), "manufacturing profile source")
        source_name = source_value.get("name")
        if not isinstance(source_name, str) or not _manufacturing._portable_leaf(source_name):
            raise _fail("manufacturing replay profile is invalid")
        source_identity = _normalize_identity(
            {"bytes": source_value.get("bytes"), "sha256": source_value.get("sha256")},
            _manufacturing.MAXIMUM_PROFILE_BYTES,
            "manufacturing profile",
        )
        profile = {"kind": kind, "source": {"name": source_name, **source_identity}}
    else:
        raise _fail("manufacturing replay profile is invalid")

    package_value = value.get("package")
    if not isinstance(package_value, Mapping):
        raise _fail("manufacturing replay package is invalid")
    _exact_keys(
        package_value, ("retained", "fresh", "identical"), "manufacturing replay package"
    )
    retained = _normalize_identity(
        package_value.get("retained"),
        _manufacturing.MAXIMUM_PACKAGE_BYTES,
        "retained manufacturing package",
    )
    fresh = _normalize_identity(
        package_value.get("fresh"),
        _manufacturing.MAXIMUM_PACKAGE_BYTES,
        "fresh manufacturing package",
    )
    if package_value.get("identical") is not True or retained != fresh:
        raise _fail("manufacturing replay package is inconsistent")

    validation_value = value.get("validation")
    validation_keys = (
        "inputs_captured",
        "package_reproduced",
        "staged_inputs_unchanged",
        "caller_inputs_unchanged",
    )
    if not isinstance(validation_value, Mapping):
        raise _fail("manufacturing replay validation is invalid")
    _exact_keys(validation_value, validation_keys, "manufacturing replay validation")
    if any(validation_value.get(key) is not True for key in validation_keys):
        raise _fail("manufacturing replay validation is incomplete")
    return {
        "schema_version": 1,
        "verification_scope": _manufacturing.MANUFACTURING_REPLAY_SCOPE,
        "verified": True,
        "board": {"name": name, **board_identity},
        "project": project,
        "rules": rules,
        "profile": profile,
        "package": {"retained": retained, "fresh": fresh, "identical": True},
        "validation": {key: True for key in validation_keys},
    }


def _freeze_path(
    value: str | os.PathLike[str], label: str, root: str
) -> str:
    try:
        rendered = _guard_cwd(
            root, _manufacturing._freeze_path, value, label
        )
        drive, _tail = os.path.splitdrive(rendered)
        if drive and not os.path.isabs(rendered):
            raise _fail(f"{label} is invalid")
        return os.path.abspath(os.path.join(root, rendered))
    except RoutingManufacturingHandoffError:
        raise
    except Exception:
        raise _fail(f"{label} is invalid") from None


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
        raise _fail("routing/manufacturing input path is invalid") from None
    return left_key == right_key


def _reject_aliases(paths: Sequence[tuple[str, str]]) -> None:
    for index, (left_label, left) in enumerate(paths):
        for right_label, right in paths[index + 1 :]:
            if _same_path(left, right):
                raise _fail(f"{left_label} and {right_label} must not alias")


def _deadline(timeout_seconds: float, clock: Callable[[], float]) -> float:
    if type(timeout_seconds) not in {int, float}:
        raise _fail("aggregate timeout is invalid")
    try:
        timeout = float(timeout_seconds)
        start = float(clock())
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
    except Exception:
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("routing/manufacturing handoff exceeded its aggregate deadline")
    return min(remaining, MAXIMUM_TIMEOUT_SECONDS)


def _numeric_options(
    *,
    grid_mm: float,
    width_mm: float,
    clearance_mm: float,
    via_diameter_mm: float,
    via_drill_mm: float,
    bend_cost: int,
    via_cost: int,
) -> list[str]:
    numbers: list[tuple[str, float, bool]] = [
        ("grid-mm", grid_mm, True),
        ("width-mm", width_mm, True),
        ("clearance-mm", clearance_mm, False),
        ("via-diameter-mm", via_diameter_mm, True),
        ("via-drill-mm", via_drill_mm, True),
    ]
    normalized: dict[str, float] = {}
    for name, value, positive in numbers:
        if type(value) not in {int, float}:
            raise _fail("routing numeric options are invalid")
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            raise _fail("routing numeric options are invalid") from None
        if (
            isinstance(value, bool)
            or not math.isfinite(number)
            or (number <= 0 if positive else number < 0)
        ):
            raise _fail("routing numeric options are invalid")
        normalized[name] = number
    if normalized["via-drill-mm"] >= normalized["via-diameter-mm"]:
        raise _fail("routing via drill must be smaller than via diameter")
    costs: dict[str, int] = {}
    for name, value in (("bend-cost", bend_cost), ("via-cost", via_cost)):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**32 - 1:
            raise _fail("routing cost options are invalid")
        costs[name] = value
    return [
        *(f"--{name}={value:.17g}" for name, value in normalized.items()),
        *(f"--{name}={value}" for name, value in costs.items()),
    ]


def _profile_arguments(
    *,
    fab: str | None,
    fab_profile: Path | None,
    physical_profile: Path | None,
) -> list[str]:
    if fab is not None:
        return [f"--fab={fab}"]
    if fab_profile is not None:
        return [f"--fab-profile={fab_profile}"]
    if physical_profile is not None:
        return [f"--physical-profile={physical_profile}"]
    return []


def _reread(paths: Sequence[tuple[str, bytes, int, str]]) -> None:
    for path, expected, maximum, label in paths:
        observed = _read_source(path, maximum, label)
        if observed != expected:
            raise _fail(f"{label} source changed during handoff replay")


def _verify_staged(
    paths: Sequence[tuple[Path, bytes, int, str]], label: str
) -> None:
    """Reread child inputs without invoking another caller-controlled hook."""

    for path, expected, maximum, _source_label in paths:
        observed = _read_source(str(path), maximum, label)
        if observed != expected:
            raise _fail(f"{label} changed before child execution")


def _evaluate_routing_manufacturing_handoff_impl(
    input_board: str | os.PathLike[str],
    routed_board: str | os.PathLike[str],
    convergence_report: str | os.PathLike[str],
    routing_verification_report: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
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
    """Freshly replay routing and, when complete, its exact manufacturing ZIP."""

    selections = sum(
        source is not None for source in (fab, fab_profile, physical_profile)
    )
    if selections > 1:
        raise _fail("manufacturing profile selections are mutually exclusive")
    normalized_fab: str | None = None
    if fab is not None:
        if type(fab) is not str:
            raise _fail("built-in fabrication profile is invalid")
        normalized_fab = str.__add__("", fab)

    caller_sources: list[tuple[str, bytes, int, str]] = []

    def capture(
        value: str | os.PathLike[str], maximum: int, label: str
    ) -> tuple[str, bytes]:
        path = _freeze_path(value, label, _root)
        raw = _read_source(path, maximum, label)
        caller_sources.append((path, raw, maximum, label))
        return path, raw

    input_source, input_raw = capture(
        input_board, MAXIMUM_ROUTING_INPUT_BYTES, "routing input board"
    )
    routed_source, routed_raw = capture(
        routed_board, MAXIMUM_ROUTED_BOARD_BYTES, "routed board"
    )
    convergence_source, convergence_raw = capture(
        convergence_report,
        MAXIMUM_CONVERGENCE_REPORT_BYTES,
        "routing convergence report",
    )
    verification_source, verification_raw = capture(
        routing_verification_report,
        MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES,
        "routing verification report",
    )
    package_source, package_raw = capture(
        manufacturing_package,
        MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
        "manufacturing package",
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
    aliases = [
        (label, path) for path, _raw, _maximum, label in caller_sources
    ]
    _reject_aliases(aliases)
    _reread(caller_sources)

    try:
        command = _guard_cwd(
            _root, _manufacturing._normalize_command, pcbex
        )
        _reread(caller_sources)
        kicad_cli_argument = _guard_cwd(
            _root,
            _manufacturing._argument,
            kicad_cli,
            "kicad-cli argument",
        )
        _reread(caller_sources)
        options = _numeric_options(
            grid_mm=grid_mm,
            width_mm=width_mm,
            clearance_mm=clearance_mm,
            via_diameter_mm=via_diameter_mm,
            via_drill_mm=via_drill_mm,
            bend_cost=bend_cost,
            via_cost=via_cost,
        )
    except RoutingManufacturingHandoffError:
        raise
    except Exception:
        raise _fail("routing/manufacturing command is invalid") from None

    last_clock: list[float | None] = [None]

    def guarded_clock() -> float:
        try:
            raw = _guard_cwd(_root, _clock)
        except RoutingManufacturingHandoffError:
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

    try:
        manufacturing_capture = _manufacturing._capture_manufacturing_replay_inputs(
            routed_source,
            package_source,
            kicad_project=project_source,
            kicad_rules=rules_source,
            fab=normalized_fab,
            fab_profile=fab_profile_source,
            physical_profile=physical_profile_source,
            deadline=deadline,
            clock=guarded_clock,
            board_raw=routed_raw,
        )
    except _manufacturing.ManufacturingReplayError as error:
        raise _fail(f"manufacturing replay inputs are invalid: {error}") from None
    if (
        manufacturing_capture.board_raw != routed_raw
        or manufacturing_capture.retained_raw != package_raw
        or manufacturing_capture.project_raw != project_raw
        or manufacturing_capture.rules_raw != rules_raw
        or manufacturing_capture.fab_profile_raw != fab_profile_raw
        or manufacturing_capture.physical_profile_raw != physical_profile_raw
    ):
        raise _fail("manufacturing replay did not preserve the captured closure")
    _reread(caller_sources)

    if not verification_raw.endswith(b"\n") or verification_raw[:-1].endswith(b"\n"):
        raise _fail("routing verification report is not canonical rendered JSON")
    _remaining(deadline, guarded_clock)

    aggregate = sum(len(raw) for _path, raw, _maximum, _label in caller_sources)
    if aggregate > MAXIMUM_TOTAL_INPUT_BYTES:
        raise _fail("routing/manufacturing inputs exceed their aggregate bound")

    fresh_verification_raw: bytes
    staged: list[tuple[Path, bytes, int, str]] = []
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-routing-manufacturing-handoff-",
            dir=_manufacturing._trusted_temporary_root(),
        ) as directory:
            root = Path(directory)
            staged_input = root / "routing-input.kicad_pcb"
            staged_routed = root / "routing-output.kicad_pcb"
            staged_convergence = root / "routing-convergence.json"
            staged_verification = root / "fresh-routing-verification.json"
            for path, raw, maximum, label in (
                (
                    staged_input,
                    input_raw,
                    MAXIMUM_ROUTING_INPUT_BYTES,
                    "staged routing input",
                ),
                (
                    staged_routed,
                    manufacturing_capture.board_raw,
                    MAXIMUM_ROUTED_BOARD_BYTES,
                    "staged routed board",
                ),
                (
                    staged_convergence,
                    convergence_raw,
                    MAXIMUM_CONVERGENCE_REPORT_BYTES,
                    "staged convergence report",
                ),
            ):
                atomic_write_no_clobber(path, raw, max_bytes=maximum)
                staged.append((path, raw, maximum, label))

            staged_project: Path | None = None
            staged_rules: Path | None = None
            staged_fab_profile: Path | None = None
            staged_physical_profile: Path | None = None
            optional_staging = (
                (
                    "routing-project.kicad_pro",
                    manufacturing_capture.project_raw,
                    _manufacturing.MAXIMUM_PROJECT_BYTES,
                    "staged KiCad project",
                ),
                (
                    "routing-rules.kicad_dru",
                    manufacturing_capture.rules_raw,
                    _manufacturing.MAXIMUM_RULES_BYTES,
                    "staged KiCad rules",
                ),
                (
                    "routing-fab-profile.json",
                    manufacturing_capture.fab_profile_raw,
                    _manufacturing.MAXIMUM_PROFILE_BYTES,
                    "staged DFM profile",
                ),
                (
                    "routing-physical-profile.json",
                    manufacturing_capture.physical_profile_raw,
                    _manufacturing.MAXIMUM_PROFILE_BYTES,
                    "staged physical profile",
                ),
            )
            staged_optionals: list[Path | None] = []
            for name, raw, maximum, label in optional_staging:
                if raw is None:
                    staged_optionals.append(None)
                    continue
                path = root / name
                atomic_write_no_clobber(path, raw, max_bytes=maximum)
                staged.append((path, raw, maximum, label))
                staged_optionals.append(path)
            (
                staged_project,
                staged_rules,
                staged_fab_profile,
                staged_physical_profile,
            ) = staged_optionals

            outer_remaining = _remaining(deadline, guarded_clock)
            routing_timeout = outer_remaining / 2.0
            if not math.isfinite(routing_timeout) or routing_timeout <= 0:
                raise _fail("routing verification child has no execution budget")
            argv = [
                *command,
                "verify-kicad-routing-convergence",
                str(staged_input),
                f"--routed={staged_routed}",
                f"--report={staged_convergence}",
                f"--output={staged_verification}",
                *options,
            ]
            if staged_project is not None:
                argv.append(f"--project={staged_project}")
            if staged_rules is not None:
                argv.append(f"--rules-file={staged_rules}")
            argv.extend(
                _profile_arguments(
                    fab=manufacturing_capture.fab,
                    fab_profile=staged_fab_profile,
                    physical_profile=staged_physical_profile,
                )
            )
            try:
                argv = _manufacturing._validate_final_argv(argv)
                _verify_staged(staged, "staged routing input")
                completed = run_bounded(
                    argv,
                    timeout_seconds=routing_timeout,
                    max_stdout_bytes=MAXIMUM_CHILD_STDOUT_BYTES,
                    max_stderr_bytes=MAXIMUM_CHILD_STDERR_BYTES,
                )
            except (
                _manufacturing.ManufacturingReplayError,
                BoundedProcessError,
            ):
                raise _fail("routing verification child process failed") from None
            if completed.returncode != 0:
                raise _fail("routing verification child rejected the replay")
            fresh_verification_raw = _read_source(
                str(staged_verification),
                MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES,
                "fresh routing verification",
            )
            if fresh_verification_raw != verification_raw:
                raise _fail(
                    "fresh routing verification did not reproduce the retained report"
                )
            _remaining(deadline, guarded_clock)
            _verify_staged(staged, "staged routing input")
    except RoutingManufacturingHandoffError:
        raise
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail("routing verification workspace failed") from None

    routing_value = _strict_object(
        fresh_verification_raw, "fresh routing verification report"
    )
    routing_projection, _normalized_routing = _normalize_routing_verification(
        routing_value,
        retained_source=_identity(verification_raw),
        input_identity=_identity(input_raw),
        routed_identity=manufacturing_capture.board_identity,
        convergence_identity=_identity(convergence_raw),
        project_identity=manufacturing_capture.project_identity,
        rules_identity=manufacturing_capture.rules_identity,
        fab=manufacturing_capture.fab,
        fab_profile_identity=manufacturing_capture.fab_profile_identity,
        physical_profile_identity=manufacturing_capture.physical_profile_identity,
    )
    _remaining(deadline, guarded_clock)
    _reread(caller_sources)

    manufacturing_result: dict[str, Any] | None = None
    ready = routing_projection["routing_complete"] is True
    if ready:
        try:
            manufacturing_result = _normalize_manufacturing_replay(
                _manufacturing._replay_captured_manufacturing_package(
                    manufacturing_capture,
                    command,
                    kicad_cli_argument,
                    deadline=deadline,
                    clock=guarded_clock,
                )
            )
        except _manufacturing.ManufacturingReplayError as error:
            raise _fail(f"manufacturing package replay failed: {error}") from None
        board = manufacturing_result.get("board")
        if not isinstance(board, Mapping):
            raise _fail("manufacturing replay board identity is invalid")
        board_identity = {
            "bytes": board.get("bytes"),
            "sha256": board.get("sha256"),
        }
        if board_identity != manufacturing_capture.board_identity:
            raise _fail("manufacturing replay does not use the routed board")
        if manufacturing_result.get("project") != manufacturing_capture.project_identity:
            raise _fail("manufacturing replay project identity is inconsistent")
        if manufacturing_result.get("rules") != manufacturing_capture.rules_identity:
            raise _fail("manufacturing replay rules identity is inconsistent")
        expected_profile = _manufacturing._profile_result(
            fab=manufacturing_capture.fab,
            fab_profile_identity=manufacturing_capture.fab_profile_identity,
            fab_profile_name=manufacturing_capture.fab_profile_name,
            physical_profile_identity=manufacturing_capture.physical_profile_identity,
            physical_profile_name=manufacturing_capture.physical_profile_name,
        )
        if manufacturing_result.get("profile") != expected_profile:
            raise _fail("manufacturing replay profile identity is inconsistent")
        package = manufacturing_result.get("package")
        if (
            not isinstance(package, Mapping)
            or package.get("retained") != manufacturing_capture.retained_identity
            or package.get("fresh") != manufacturing_capture.retained_identity
            or package.get("identical") is not True
        ):
            raise _fail("manufacturing replay package identity is inconsistent")

    _remaining(deadline, guarded_clock)
    _reread(caller_sources)
    sources = {
        "input_board": _identity(input_raw),
        "routed_board": manufacturing_capture.board_identity,
        "convergence_report": _identity(convergence_raw),
        "routing_verification_report": _identity(verification_raw),
        "manufacturing_package": manufacturing_capture.retained_identity,
        "project": manufacturing_capture.project_identity,
        "rules_file": manufacturing_capture.rules_identity,
        "fab_profile": manufacturing_capture.fab_profile_identity,
        "physical_profile": manufacturing_capture.physical_profile_identity,
    }
    result: dict[str, Any] = {
        "schema_version": ROUTING_MANUFACTURING_HANDOFF_SCHEMA_VERSION,
        "verification_scope": ROUTING_MANUFACTURING_HANDOFF_SCOPE,
        "status": "verified_ready" if ready else "not_ready",
        "ready": ready,
        "source_authenticity_verified": False,
        "native_kicad_drc_verified": False,
        "manufacturability_verified": False,
        "release_authorized": False,
        "sources": sources,
        "routing_verification": routing_projection,
        "manufacturing_replay": manufacturing_result,
        "gate_failures": [] if ready else ["routing_incomplete"],
        "validation": {
            "source_closure_captured": True,
            "routing_verification_replayed": True,
            "retained_routing_verification_exact": True,
            "routed_board_identity_matched": True,
            "shared_sidecars_matched": True,
            "manufacturing_package_replayed": ready,
            "caller_inputs_unchanged": True,
        },
        "binding_sha256": "",
    }
    result["binding_sha256"] = _handoff_binding(result)
    normalized = _normalize_report(result)
    return normalized


def evaluate_routing_manufacturing_handoff(
    input_board: str | os.PathLike[str],
    routed_board: str | os.PathLike[str],
    convergence_report: str | os.PathLike[str],
    routing_verification_report: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
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
    """Freshly replay routing and, when complete, its exact manufacturing ZIP."""

    root = _public_root()
    return _guard_cwd(
        root,
        _evaluate_routing_manufacturing_handoff_impl,
        input_board,
        routed_board,
        convergence_report,
        routing_verification_report,
        manufacturing_package,
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


def _normalize_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("routing/manufacturing handoff report is invalid")
    _exact_keys(value, _REPORT_KEYS, "routing/manufacturing handoff report")
    if (
        value.get("schema_version") != ROUTING_MANUFACTURING_HANDOFF_SCHEMA_VERSION
        or value.get("verification_scope") != ROUTING_MANUFACTURING_HANDOFF_SCOPE
        or value.get("status") not in {"verified_ready", "not_ready"}
        or type(value.get("ready")) is not bool
    ):
        raise _fail("routing/manufacturing handoff report header is invalid")
    for claim in (
        "source_authenticity_verified",
        "native_kicad_drc_verified",
        "manufacturability_verified",
        "release_authorized",
    ):
        if value.get(claim) is not False:
            raise _fail("routing/manufacturing handoff contains unsupported claims")

    sources_value = value.get("sources")
    if not isinstance(sources_value, Mapping):
        raise _fail("routing/manufacturing handoff sources are invalid")
    _exact_keys(sources_value, _SOURCE_KEYS, "routing/manufacturing handoff sources")
    sources = {
        "input_board": _normalize_identity(
            sources_value["input_board"], MAXIMUM_ROUTING_INPUT_BYTES, "input board"
        ),
        "routed_board": _normalize_identity(
            sources_value["routed_board"], MAXIMUM_ROUTED_BOARD_BYTES, "routed board"
        ),
        "convergence_report": _normalize_identity(
            sources_value["convergence_report"],
            MAXIMUM_CONVERGENCE_REPORT_BYTES,
            "convergence report",
        ),
        "routing_verification_report": _normalize_identity(
            sources_value["routing_verification_report"],
            MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES,
            "routing verification report",
        ),
        "manufacturing_package": _normalize_identity(
            sources_value["manufacturing_package"],
            MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
            "manufacturing package",
        ),
        "project": _optional_identity(
            sources_value["project"], _manufacturing.MAXIMUM_PROJECT_BYTES, "project"
        ),
        "rules_file": _optional_identity(
            sources_value["rules_file"], _manufacturing.MAXIMUM_RULES_BYTES, "rules"
        ),
        "fab_profile": _optional_identity(
            sources_value["fab_profile"], _manufacturing.MAXIMUM_PROFILE_BYTES, "DFM profile"
        ),
        "physical_profile": _optional_identity(
            sources_value["physical_profile"],
            _manufacturing.MAXIMUM_PROFILE_BYTES,
            "physical profile",
        ),
    }

    routing = value.get("routing_verification")
    if not isinstance(routing, Mapping):
        raise _fail("routing verification projection is invalid")
    _exact_keys(
        routing, _ROUTING_PROJECTION_KEYS, "routing verification projection"
    )
    built_in_profile = routing.get("built_in_dfm_profile")
    if built_in_profile is not None:
        try:
            built_in_profile = _manufacturing._builtin_profile_id(
                built_in_profile
            )
        except _manufacturing.ManufacturingReplayError:
            raise _fail("routing verification projection is invalid") from None
    if (
        routing.get("source") != sources["routing_verification_report"]
        or not _is_bounded_utf8(routing.get("engine_version"), 128)
        or routing.get("status") not in _ROUTING_STATUSES
        or type(routing.get("routing_complete")) is not bool
        or not _is_digest(routing.get("binding_sha256"))
        or not isinstance(routing.get("sources"), Mapping)
    ):
        raise _fail("routing verification projection is invalid")
    if (routing["status"] == "verified_complete") is not routing["routing_complete"]:
        raise _fail("routing verification projection decision is inconsistent")
    routing_sources = routing["sources"]
    _exact_keys(routing_sources, _ROUTING_SOURCE_KEYS, "routing verification sources")
    expected_routing_sources = {
        "input": sources["input_board"],
        "routed_output": sources["routed_board"],
        "retained_report": sources["convergence_report"],
        "project": sources["project"],
        "rules_file": sources["rules_file"],
        "fab_profile": sources["fab_profile"],
        "policy_pack": None,
        "physical_profile": sources["physical_profile"],
    }
    if dict(routing_sources) != expected_routing_sources:
        raise _fail("routing verification projection is not cross-bound")

    validation = value.get("validation")
    if not isinstance(validation, Mapping):
        raise _fail("routing/manufacturing validation is invalid")
    _exact_keys(validation, _VALIDATION_KEYS, "routing/manufacturing validation")
    for key in _VALIDATION_KEYS[:-2]:
        if validation.get(key) is not True:
            raise _fail("routing/manufacturing validation is incomplete")
    if validation.get("caller_inputs_unchanged") is not True:
        raise _fail("routing/manufacturing validation is incomplete")

    ready = value["ready"]
    failures = value.get("gate_failures")
    if not isinstance(failures, list):
        raise _fail("routing/manufacturing gate failures are invalid")
    manufacturing = value.get("manufacturing_replay")
    if ready:
        if (
            value["status"] != "verified_ready"
            or routing["routing_complete"] is not True
            or failures != []
            or validation.get("manufacturing_package_replayed") is not True
            or manufacturing is None
        ):
            raise _fail("routing/manufacturing ready decision is inconsistent")
        manufacturing = _normalize_manufacturing_replay(manufacturing)
        board = manufacturing.get("board")
        if not isinstance(board, Mapping) or {
            "bytes": board.get("bytes"),
            "sha256": board.get("sha256"),
        } != sources["routed_board"]:
            raise _fail("manufacturing replay routed-board binding is invalid")
        if (
            manufacturing.get("project") != sources["project"]
            or manufacturing.get("rules") != sources["rules_file"]
            or manufacturing["package"]["retained"]
            != sources["manufacturing_package"]
        ):
            raise _fail("manufacturing replay source binding is invalid")
        if built_in_profile is not None:
            expected_profile: dict[str, Any] = {
                "kind": "builtin",
                "id": built_in_profile,
            }
        elif sources["fab_profile"] is not None:
            expected_profile = {
                "kind": "dfm-file",
                "source": {
                    "name": manufacturing["profile"].get("source", {}).get("name"),
                    **sources["fab_profile"],
                },
            }
        elif sources["physical_profile"] is not None:
            expected_profile = {
                "kind": "physical-file",
                "source": {
                    "name": manufacturing["profile"].get("source", {}).get("name"),
                    **sources["physical_profile"],
                },
            }
        else:
            expected_profile = {"kind": "none"}
        if manufacturing.get("profile") != expected_profile:
            raise _fail("manufacturing replay profile binding is invalid")
    else:
        if (
            value["status"] != "not_ready"
            or routing["routing_complete"] is not False
            or failures != ["routing_incomplete"]
            or validation.get("manufacturing_package_replayed") is not False
            or manufacturing is not None
        ):
            raise _fail("routing/manufacturing negative decision is inconsistent")

    binding = value.get("binding_sha256")
    if not _is_digest(binding) or binding != _handoff_binding(value):
        raise _fail("routing/manufacturing handoff binding is invalid")
    normalized = {key: deepcopy(value[key]) for key in _REPORT_KEYS}
    normalized["sources"] = sources
    normalized["manufacturing_replay"] = manufacturing
    return normalized


def _render_routing_manufacturing_handoff_report_impl(
    report: Mapping[str, Any],
) -> bytes:
    """Validate and render one canonical pretty JSON report with one LF."""

    normalized = _normalize_report(report)
    try:
        raw = (
            json.dumps(normalized, indent=2, ensure_ascii=False, allow_nan=False)
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise _fail("routing/manufacturing handoff report cannot be rendered") from None
    if len(raw) > MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES:
        raise _fail("routing/manufacturing handoff report exceeds its byte limit")
    return raw


def render_routing_manufacturing_handoff_report(report: Mapping[str, Any]) -> bytes:
    """Validate and render one canonical pretty JSON report with one LF."""

    root = _public_root()
    return _guard_cwd(
        root, _render_routing_manufacturing_handoff_report_impl, report
    )


def routing_manufacturing_handoff_report_json_schema() -> dict[str, Any]:
    """Return the closed Draft 2020-12 schema for the v1 composition."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def identity(maximum: int) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
                "sha256": deepcopy(digest),
            },
        }

    optional_project = {
        "anyOf": [identity(_manufacturing.MAXIMUM_PROJECT_BYTES), {"type": "null"}]
    }
    optional_rules = {
        "anyOf": [identity(_manufacturing.MAXIMUM_RULES_BYTES), {"type": "null"}]
    }
    optional_profile = {
        "anyOf": [identity(_manufacturing.MAXIMUM_PROFILE_BYTES), {"type": "null"}]
    }
    routing_sources = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_ROUTING_SOURCE_KEYS),
        "properties": {
            "input": identity(MAXIMUM_ROUTING_INPUT_BYTES),
            "routed_output": identity(MAXIMUM_ROUTED_BOARD_BYTES),
            "retained_report": identity(MAXIMUM_CONVERGENCE_REPORT_BYTES),
            "project": deepcopy(optional_project),
            "rules_file": deepcopy(optional_rules),
            "fab_profile": deepcopy(optional_profile),
            "policy_pack": {"type": "null"},
            "physical_profile": deepcopy(optional_profile),
        },
    }
    manufacturing_schema = deepcopy(
        _manufacturing.manufacturing_package_replay_result_json_schema()
    )
    for key in ("$schema", "$id", "title"):
        manufacturing_schema.pop(key, None)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "routing-manufacturing-handoff-report-v1.json"
        ),
        "title": "pcbex fresh exact routing-to-manufacturing handoff report",
        "type": "object",
        "additionalProperties": False,
        "required": list(_REPORT_KEYS),
        "properties": {
            "schema_version": {"const": 1},
            "verification_scope": {"const": ROUTING_MANUFACTURING_HANDOFF_SCOPE},
            "status": {"enum": ["verified_ready", "not_ready"]},
            "ready": {"type": "boolean"},
            "source_authenticity_verified": {"const": False},
            "native_kicad_drc_verified": {"const": False},
            "manufacturability_verified": {"const": False},
            "release_authorized": {"const": False},
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": list(_SOURCE_KEYS),
                "properties": {
                    "input_board": identity(MAXIMUM_ROUTING_INPUT_BYTES),
                    "routed_board": identity(MAXIMUM_ROUTED_BOARD_BYTES),
                    "convergence_report": identity(MAXIMUM_CONVERGENCE_REPORT_BYTES),
                    "routing_verification_report": identity(
                        MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES
                    ),
                    "manufacturing_package": identity(
                        MAXIMUM_MANUFACTURING_PACKAGE_BYTES
                    ),
                    "project": deepcopy(optional_project),
                    "rules_file": deepcopy(optional_rules),
                    "fab_profile": deepcopy(optional_profile),
                    "physical_profile": deepcopy(optional_profile),
                },
            },
            "routing_verification": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source",
                    "engine_version",
                    "status",
                    "routing_complete",
                    "built_in_dfm_profile",
                    "binding_sha256",
                    "sources",
                ],
                "properties": {
                    "source": identity(MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES),
                    "engine_version": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                    },
                    "status": {"enum": sorted(_ROUTING_STATUSES)},
                    "routing_complete": {"type": "boolean"},
                    "built_in_dfm_profile": {
                        "anyOf": [
                            {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 128,
                                "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$",
                            },
                            {"type": "null"},
                        ]
                    },
                    "binding_sha256": deepcopy(digest),
                    "sources": routing_sources,
                },
            },
            "manufacturing_replay": {
                "anyOf": [manufacturing_schema, {"type": "null"}]
            },
            "gate_failures": {
                "type": "array",
                "maxItems": 1,
                "items": {"const": "routing_incomplete"},
            },
            "validation": {
                "type": "object",
                "additionalProperties": False,
                "required": list(_VALIDATION_KEYS),
                "properties": {
                    **{key: {"const": True} for key in _VALIDATION_KEYS[:-2]},
                    "manufacturing_package_replayed": {"type": "boolean"},
                    "caller_inputs_unchanged": {"const": True},
                },
            },
            "binding_sha256": deepcopy(digest),
        },
        "allOf": [
            {
                "if": {
                    "properties": {
                        "routing_verification": {
                            "properties": {
                                "routing_complete": {"const": True}
                            }
                        }
                    }
                },
                "then": {
                    "properties": {
                        "routing_verification": {
                            "properties": {
                                "status": {"const": "verified_complete"}
                            }
                        }
                    }
                },
                "else": {
                    "properties": {
                        "routing_verification": {
                            "properties": {
                                "status": {
                                    "enum": [
                                        "verified_no_admissible_candidate",
                                        "verified_partial",
                                    ]
                                }
                            }
                        }
                    }
                },
            },
            {
                "if": {"properties": {"ready": {"const": True}}},
                "then": {
                    "properties": {
                        "status": {"const": "verified_ready"},
                        "manufacturing_replay": manufacturing_schema,
                        "gate_failures": {"maxItems": 0},
                        "validation": {
                            "properties": {
                                "manufacturing_package_replayed": {"const": True}
                            }
                        },
                    }
                },
                "else": {
                    "properties": {
                        "status": {"const": "not_ready"},
                        "manufacturing_replay": {"type": "null"},
                        "gate_failures": {
                            "minItems": 1,
                            "maxItems": 1,
                            "prefixItems": [{"const": "routing_incomplete"}],
                        },
                        "validation": {
                            "properties": {
                                "manufacturing_package_replayed": {"const": False}
                            }
                        },
                    }
                },
            }
        ],
    }


__all__ = [
    "MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES",
    "RoutingManufacturingHandoffError",
    "evaluate_routing_manufacturing_handoff",
    "render_routing_manufacturing_handoff_report",
    "routing_manufacturing_handoff_report_json_schema",
]

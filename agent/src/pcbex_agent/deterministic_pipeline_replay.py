"""Fresh, byte-exact replay of one retained deterministic-pipeline report.

The adapter captures the closed runner plan, every authorized source, and the
retained report before invoking a caller-selected ``pcbex`` binary in a
private workspace.  The fresh report must equal the retained bytes exactly.
Only path-free identities are returned; the fresh report and staged inputs are
removed with the private workspace.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
import tempfile
import time
from typing import Any
import unicodedata

from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .bounded_process import BoundedProcessError, run_bounded


DETERMINISTIC_PIPELINE_REPLAY_RESULT_SCHEMA_VERSION = 1
DETERMINISTIC_PIPELINE_REPLAY_SCOPE = "deterministic-pipeline-fresh-replay-v1"

MAXIMUM_PLAN_BYTES = 4 * 1024 * 1024
MAXIMUM_REPORT_BYTES = 128 * 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = 512 * 1024 * 1024
MAXIMUM_CHILD_STDOUT_BYTES = 64 * 1024
MAXIMUM_CHILD_STDERR_BYTES = 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600.0
MAXIMUM_PATH_CHARACTERS = 4096
MAXIMUM_PORTABLE_COMPONENT_BYTES = 255
MAXIMUM_ARGUMENT_BYTES = 32_768
MAXIMUM_COMMAND_ARGUMENTS = 256
MAXIMUM_WINDOWS_COMMAND_LINE_UTF16_UNITS = 32_767
MAXIMUM_INPUT_EVIDENCE = 64
MAXIMUM_FAILURES = 128
MAXIMUM_FAILURE_CHARACTERS = 4096
MAXIMUM_WINDOWS_PATH_UTF16_UNITS = 260
# ``atomic_write_no_clobber`` uses a 15-character prefix plus a runtime-chosen
# suffix. Reserve a conservative leaf length instead of relying on tempfile's
# private suffix length.
MAXIMUM_WINDOWS_TEMPORARY_NAME_UTF16_UNITS = 32

_MIB = 1024 * 1024
_ROLE_LIMITS = {
    "circuit_spec": 16 * _MIB,
    "schematic": 64 * _MIB,
    "electrical_policy": 4 * _MIB,
    "electrical_review": 64 * _MIB,
    "board": 128 * _MIB,
    "analysis_manifest": 64 * _MIB,
    "analysis_checks": 64 * _MIB,
    "quality": 64 * _MIB,
    "analysis_project": 64 * _MIB,
    "analysis_rules": 64 * _MIB,
    "analysis_dfm_profile": 4 * _MIB,
    "analysis_policy_pack": 64 * _MIB,
    "analysis_physical_profile": 4 * _MIB,
    "manufacturing_package": 128 * _MIB,
    "firmware_manifest": 4 * _MIB,
    "factory_receipt": 64 * _MIB,
}
_REQUIRED_ROLES = (
    "circuit_spec",
    "schematic",
    "electrical_review",
    "board",
    "analysis_manifest",
    "analysis_checks",
    "quality",
    "manufacturing_package",
    "firmware_manifest",
)
_OPTIONAL_ROLES = (
    "electrical_policy",
    "analysis_project",
    "analysis_rules",
    "analysis_dfm_profile",
    "analysis_policy_pack",
    "analysis_physical_profile",
    "factory_receipt",
)
_PLAN_KEYS = frozenset(
    {"schema_version", "require_factory", *_REQUIRED_ROLES, *_OPTIONAL_ROLES}
)
_FIRMWARE_ARTIFACTS = (
    "pinout.h",
    "firmware.h",
    "firmware.c",
    "firmware_smoke_test.c",
    "firmware.cpp",
    "firmware_cpp_smoke_test.cpp",
    "host.py",
)
_FIRMWARE_ENTRIES = frozenset({"manifest.json", *_FIRMWARE_ARTIFACTS})
_FIRMWARE_ARTIFACT_LIMIT = 16 * _MIB
_INPUT_SET_DOMAIN = b"pcbex:deterministic-pipeline-replay-input-set:v1\0"
_PLAN_HASH_DOMAIN = b"pcbex:deterministic-pipeline-plan:v1\0"
_RUN_HASH_DOMAIN = b"pcbex:deterministic-pipeline-runner:v1\0"
_HEX_DIGEST_LENGTH = 64
_SEMVER_PATTERN = (
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_SEMVER_RE = re.compile(_SEMVER_PATTERN)
_PIPELINE_ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]*$")
_ELECTRICAL_FINDING_ID_RE = re.compile(r"^pcbex-er-[0-9a-f]{16}$")
_PLAN_WIRE_ORDER = (
    "schema_version",
    "circuit_spec",
    "schematic",
    "electrical_policy",
    "electrical_review",
    "board",
    "analysis_manifest",
    "analysis_checks",
    "quality",
    "analysis_project",
    "analysis_rules",
    "analysis_dfm_profile",
    "analysis_policy_pack",
    "analysis_physical_profile",
    "manufacturing_package",
    "firmware_manifest",
    "factory_receipt",
    "require_factory",
)

_WINDOWS_RESERVED_NUMERIC_SUFFIXES = "123456789"
_WINDOWS_RESERVED_LEAF_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {
        f"COM{suffix}"
        for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES
    }
    | {
        f"LPT{suffix}"
        for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES
    }
)

_MAXIMUM_FILE_BYTES = 128 * _MIB
_MAXIMUM_CIRCUIT_SOURCE_BYTES = 16 * _MIB
_MAXIMUM_SCHEMATIC_SOURCE_BYTES = 64 * _MIB
_MAXIMUM_BINDING_FINDINGS = 250_000
_MAXIMUM_PHASE_CHECKS = 128
_MAXIMUM_PHASE_FAILURES = 128
_MAXIMUM_PIPELINE_FAILURES = 512
_ELECTRICAL_RULES = frozenset(
    {
        "coverage_incomplete",
        "duplicate_reference_unit",
        "unannotated_reference",
        "missing_footprint",
        "no_connect_connected",
        "pin_type_no_connect_connected",
        "unconnected_pin",
        "multiple_output_drivers",
        "multiple_power_outputs",
        "power_input_not_driven",
        "input_not_driven",
        "multiple_net_names",
        "invalid_power_metadata",
        "power_rail_voltage_conflict",
        "power_input_voltage_exceeded",
        "missing_decoupling_capacitor",
    }
)
_ELECTRICAL_SEVERITIES = frozenset({"info", "warning", "error"})
_HANDOFF_FINDING_CODES = frozenset(
    {
        "coverage_incomplete",
        "missing_symbol",
        "duplicate_symbol_reference",
        "extra_power_symbol",
        "extra_symbol",
        "missing_net",
        "duplicate_net_name",
        "extra_net",
        "net_voltage_mismatch",
        "net_label_mismatch",
        "merged_expected_nets",
        "net_mismatch",
        "net_pin_reference_invalid",
        "multi_unit_symbol",
        "symbol_mismatch",
        "metadata_missing",
        "metadata_mismatch",
        "metadata_extra",
        "duplicate_pin_number",
        "missing_pin",
        "extra_pin",
        "pin_mismatch",
        "no_connect_mismatch",
    }
)
_BOARD_BINDING_FINDING_CODES = frozenset(
    {
        "missing_reserved_net_zero",
        "missing_footprint",
        "extra_footprint",
        "duplicate_footprint_reference",
        "footprint_id_mismatch",
        "value_mismatch",
        "mpn_mismatch",
        "assembly_metadata_mismatch",
        "missing_pad",
        "extra_pad",
        "duplicate_pad_number",
        "pad_type_mismatch",
        "connected_unnumbered_pad",
        "unnumbered_pad_unsupported",
        "pad_net_mismatch",
        "no_connect_mismatch",
        "missing_net",
        "extra_net",
    }
)
_PIPELINE_PHASE_NAMES = {
    1: (
        "electrical-erc",
        "analysis-drc",
        "routing-quality",
        "manufacturing-package",
        "firmware-build",
    ),
    2: (
        "electrical-erc",
        "analysis-drc",
        "routing-quality",
        "manufacturing-package",
        "firmware-build",
        "factory-dfm",
    ),
}


class DeterministicPipelineReplayError(ValueError):
    """A stable, path-free deterministic-pipeline replay failure."""


class _DuplicateJSONKey(ValueError):
    pass


def _fail(message: str) -> DeterministicPipelineReplayError:
    return DeterministicPipelineReplayError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha256(raw)}


def _compact_json(value: Any, *, sort_keys: bool = False) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=sort_keys,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        raise _fail("deterministic pipeline digest input is invalid") from None


def _digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _HEX_DIGEST_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _fail(f"{label} is not a lowercase SHA-256")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value}")


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJSONKey,
        ValueError,
        RecursionError,
    ):
        raise _fail(f"{label} is not strict JSON") from None
    if not isinstance(value, dict):
        raise _fail(f"{label} must be a JSON object")
    return value


def _freeze_path(value: str | os.PathLike[str], label: str) -> str:
    try:
        rendered = os.fspath(value)
    except (TypeError, ValueError, OSError):
        raise _fail(f"{label} is invalid") from None
    if not isinstance(rendered, str) or not rendered or "\x00" in rendered:
        raise _fail(f"{label} is invalid")
    return str.__add__("", rendered)


def _normalize_command(value: str | Sequence[str]) -> list[str]:
    if isinstance(value, str):
        items: list[Any] = [value]
    elif isinstance(value, (bytes, bytearray)):
        raise _fail("pcbex command is invalid")
    else:
        try:
            iterator = iter(value)
        except (TypeError, ValueError, OverflowError):
            raise _fail("pcbex command is invalid") from None
        items = []
        try:
            for item in iterator:
                if len(items) == MAXIMUM_COMMAND_ARGUMENTS:
                    raise _fail("pcbex command is invalid")
                items.append(item)
        except DeterministicPipelineReplayError:
            raise
        except (TypeError, ValueError, OverflowError, RuntimeError):
            raise _fail("pcbex command is invalid") from None
    if not items:
        raise _fail("pcbex command is invalid")
    normalized: list[str] = []
    total = 0
    for item in items:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise _fail("pcbex command is invalid")
        try:
            encoded = item.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise _fail("pcbex command is invalid") from None
        total += len(encoded)
        if total > MAXIMUM_ARGUMENT_BYTES:
            raise _fail("pcbex command is invalid")
        normalized.append(item)
    return normalized


def _validate_final_argv(argv: Sequence[str]) -> list[str]:
    if not argv or len(argv) > MAXIMUM_COMMAND_ARGUMENTS:
        raise _fail("deterministic pipeline child argv is invalid")
    total = 0
    for item in argv:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise _fail("deterministic pipeline child argv is invalid")
        try:
            total += len(item.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            raise _fail("deterministic pipeline child argv is invalid") from None
        if total > MAXIMUM_ARGUMENT_BYTES:
            raise _fail("deterministic pipeline child argv is invalid")
    try:
        rendered = subprocess.list2cmdline(list(argv))
        windows_units = len(rendered.encode("utf-16-le", errors="strict")) // 2 + 1
    except (TypeError, ValueError, UnicodeEncodeError):
        raise _fail("deterministic pipeline child argv is invalid") from None
    if windows_units > MAXIMUM_WINDOWS_COMMAND_LINE_UTF16_UNITS:
        raise _fail("deterministic pipeline child argv is invalid")
    return list(argv)


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    try:
        remaining = deadline - float(clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("deterministic pipeline replay exceeded its aggregate deadline")
    return min(remaining, MAXIMUM_TIMEOUT_SECONDS)


def _portable_component(component: str) -> bool:
    if (
        not component
        or component in {".", ".."}
        or component[-1] in {" ", "."}
        or any(unicodedata.category(character) == "Cc" for character in component)
        or any(character in '<>:"/\\|?*' for character in component)
    ):
        return False
    try:
        encoded = component.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    windows = PureWindowsPath(component)
    stem = component.partition(".")[0].rstrip(" ").upper()
    return (
        len(encoded) <= MAXIMUM_PORTABLE_COMPONENT_BYTES
        and not windows.drive
        and not windows.root
        and windows.parts == (component,)
        and windows.name == component
        and stem not in _WINDOWS_RESERVED_LEAF_STEMS
    )


def _portable_relative_path(value: Any, role: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAXIMUM_PATH_CHARACTERS
        or "\\" in value
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
    ):
        raise _fail(f"{role} descriptor path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(
        not _portable_component(component) for component in path.parts
    ):
        raise _fail(f"{role} descriptor path is invalid")
    return value


def _positive_integer(value: Any, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > maximum
    ):
        raise _fail(f"{label} is invalid")
    return value


def _descriptor(value: Any, role: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"path", "bytes", "sha256"}:
        raise _fail(f"{role} descriptor is invalid")
    return {
        "path": _portable_relative_path(value["path"], role),
        "bytes": _positive_integer(
            value["bytes"], f"{role} descriptor byte count", _ROLE_LIMITS[role]
        ),
        "sha256": _digest(value["sha256"], f"{role} descriptor digest"),
    }


def _parse_plan(raw: bytes) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]]]:
    plan = _strict_object(raw, "deterministic pipeline plan")
    if set(plan) != _PLAN_KEYS:
        raise _fail("deterministic pipeline plan has an invalid closed shape")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise _fail("deterministic pipeline plan schema version is invalid")
    if not isinstance(plan["require_factory"], bool):
        raise _fail("deterministic pipeline require_factory decision is invalid")
    descriptors: list[tuple[str, dict[str, Any]]] = []
    for role in (*_REQUIRED_ROLES, *_OPTIONAL_ROLES):
        value = plan[role]
        if role in _OPTIONAL_ROLES and value is None:
            continue
        descriptors.append((role, _descriptor(value, role)))
    return plan, descriptors


def _semantic_plan_digest(plan: dict[str, Any]) -> str:
    wire: dict[str, Any] = {}
    roles = frozenset((*_REQUIRED_ROLES, *_OPTIONAL_ROLES))
    for key in _PLAN_WIRE_ORDER:
        value = plan[key]
        if key in roles and value is not None:
            wire[key] = {
                "path": value["path"],
                "bytes": value["bytes"],
                "sha256": value["sha256"],
            }
        else:
            wire[key] = value
    return _sha256(_PLAN_HASH_DOMAIN + _compact_json(wire))


def _semantic_run_digest(report: dict[str, Any]) -> str:
    value = dict(report)
    value.pop("run_sha256", None)
    return _sha256(_RUN_HASH_DOMAIN + _compact_json(value, sort_keys=True))


def _source_path(root: Path, relative: str) -> Path:
    return root.joinpath(*PurePosixPath(relative).parts)


def _read_nonempty(path: Path | str, maximum: int, label: str) -> bytes:
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} source is invalid") from None
    if not raw:
        raise _fail(f"{label} source is empty")
    return raw


def _same_file(left: str, right: str) -> bool:
    try:
        return os.path.samefile(left, right)
    except (FileNotFoundError, OSError, TypeError, ValueError):
        return False


def _firmware_entry_names(directory: Path) -> frozenset[str]:
    try:
        names: set[str] = set()
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(names) == len(_FIRMWARE_ENTRIES):
                    raise _fail("firmware bundle has too many entries")
                if entry.name in names or not entry.is_file(follow_symlinks=False):
                    raise _fail("firmware bundle contains an invalid entry")
                names.add(entry.name)
    except DeterministicPipelineReplayError:
        raise
    except (OSError, TypeError, ValueError):
        raise _fail("firmware bundle directory is invalid") from None
    if frozenset(names) != _FIRMWARE_ENTRIES:
        raise _fail("firmware bundle must contain exactly eight fixed files")
    return frozenset(names)


def _capture_identity(raw: bytes, role: str, relative: str) -> dict[str, Any]:
    return {
        "role": role,
        "path": relative,
        "bytes": len(raw),
        "sha256": _sha256(raw),
    }


def _input_set_identity(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(evidence, key=lambda item: (item["role"], item["path"]))
    try:
        encoded = json.dumps(
            ordered, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        raise _fail("deterministic pipeline input identity is invalid") from None
    total = sum(item["bytes"] for item in ordered)
    if total > MAXIMUM_TOTAL_INPUT_BYTES or len(ordered) > MAXIMUM_INPUT_EVIDENCE:
        raise _fail("deterministic pipeline inputs exceed their aggregate bound")
    return {
        "count": len(ordered),
        "bytes": total,
        "sha256": _sha256(_INPUT_SET_DOMAIN + encoded),
    }


def _verify_capture(
    path: Path | str,
    expected: dict[str, Any],
    maximum: int,
    label: str,
) -> None:
    raw = _read_nonempty(path, maximum, label)
    if len(raw) != expected["bytes"] or _sha256(raw) != expected["sha256"]:
        raise _fail(f"{label} changed during replay")


def _trusted_temporary_root() -> Path:
    try:
        return Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _fail("trusted temporary root is invalid") from None


def _stage_name(relative_paths: set[str]) -> str:
    first_components = {
        PurePosixPath(relative).parts[0].lower() for relative in relative_paths
    }
    index = 0
    while True:
        candidate = f"__pcbex_replay_plan_{index}.json"
        if candidate.lower() not in first_components:
            return candidate
        index += 1
        if index > len(relative_paths):
            raise _fail("could not reserve a private deterministic pipeline plan name")


def _validate_private_staging_paths(paths: Sequence[Path]) -> None:
    """Reject private paths beyond the portable Windows MAX_PATH boundary."""

    if os.name != "nt":
        return
    for path in paths:
        try:
            absolute = os.path.abspath(os.fspath(path))
            units = len(absolute.encode("utf-16-le", errors="strict")) // 2
            parent = os.path.dirname(absolute)
            temporary = os.path.join(
                parent,
                ".pcbex-bounded-"
                + ("x" * (MAXIMUM_WINDOWS_TEMPORARY_NAME_UTF16_UNITS - 15)),
            )
            temporary_units = len(
                temporary.encode("utf-16-le", errors="strict")
            ) // 2
        except (OSError, TypeError, UnicodeError, ValueError):
            raise _fail("deterministic pipeline private staging path is invalid") from None
        if (
            units >= MAXIMUM_WINDOWS_PATH_UTF16_UNITS
            or temporary_units >= MAXIMUM_WINDOWS_PATH_UTF16_UNITS
        ):
            raise _fail("deterministic pipeline private staging path is too long")


def _parse_child_summary(raw: bytes) -> dict[str, Any]:
    if not raw.endswith(b"\n") or b"\n" in raw[:-1] or b"\r" in raw:
        raise _fail("deterministic pipeline child summary is invalid")
    summary = _strict_object(raw[:-1], "deterministic pipeline child summary")
    required = {
        "schema_version",
        "approved",
        "plan_sha256",
        "run_sha256",
        "failure_count",
        "report_bytes",
        "report_sha256",
    }
    if set(summary) != required:
        raise _fail("deterministic pipeline child summary is invalid")
    if type(summary["schema_version"]) is not int or summary["schema_version"] != 1:
        raise _fail("deterministic pipeline child summary is invalid")
    if not isinstance(summary["approved"], bool):
        raise _fail("deterministic pipeline child summary is invalid")
    for field in ("plan_sha256", "run_sha256", "report_sha256"):
        _digest(summary[field], f"child summary {field}")
    _positive_integer(
        summary["report_bytes"], "child summary report byte count", MAXIMUM_REPORT_BYTES
    )
    if (
        isinstance(summary["failure_count"], bool)
        or not isinstance(summary["failure_count"], int)
        or not 0 <= summary["failure_count"] <= MAXIMUM_FAILURES
    ):
        raise _fail("deterministic pipeline child summary is invalid")
    return summary


def _closed_object(
    value: Any,
    label: str,
    required: set[str] | frozenset[str],
    optional: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(f"{label} must be an object")
    allowed = set(required) | set(optional)
    if set(value) - allowed or not set(required).issubset(value):
        raise _fail(f"{label} has an invalid closed shape")
    return value


def _strict_integer(
    value: Any,
    label: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise _fail(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        raise _fail(f"{label} is below its minimum")
    if maximum is not None and value > maximum:
        raise _fail(f"{label} exceeds its maximum")
    return value


def _strict_string(
    value: Any,
    label: str,
    minimum: int = 1,
    maximum: int | None = None,
) -> str:
    if not isinstance(value, str) or len(value) < minimum:
        raise _fail(f"{label} is invalid")
    if maximum is not None and len(value) > maximum:
        raise _fail(f"{label} exceeds its maximum")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise _fail(f"{label} must be a boolean")
    return value


def _strict_array(
    value: Any,
    label: str,
    maximum: int | None = None,
    minimum: int | None = None,
) -> list[Any]:
    if not isinstance(value, list):
        raise _fail(f"{label} must be an array")
    if maximum is not None and len(value) > maximum:
        raise _fail(f"{label} exceeds its maximum")
    if minimum is not None and len(value) < minimum:
        raise _fail(f"{label} is below its minimum")
    return value


def _optional_string(value: Any, label: str) -> None | str:
    if value is not None:
        _strict_string(value, label)
    return value


def _validate_counts(value: Any, label: str) -> None:
    counts = _closed_object(value, label, {"errors", "warnings", "info"})
    for field in ("errors", "warnings", "info"):
        _strict_integer(counts[field], f"{label} {field}", 0)


def _validate_electrical_finding(value: Any, label: str) -> None:
    finding = _closed_object(
        value,
        label,
        {"id", "rule", "severity", "message", "net_id", "symbols", "pins"},
    )
    identifier = _strict_string(finding["id"], f"{label} id")
    if _ELECTRICAL_FINDING_ID_RE.fullmatch(identifier) is None:
        raise _fail(f"{label} id is invalid")
    if finding["rule"] not in _ELECTRICAL_RULES:
        raise _fail(f"{label} rule is invalid")
    if finding["severity"] not in _ELECTRICAL_SEVERITIES:
        raise _fail(f"{label} severity is invalid")
    _strict_string(finding["message"], f"{label} message")
    if finding["net_id"] is not None:
        _strict_integer(finding["net_id"], f"{label} net id", 1)
    symbols = _strict_array(finding["symbols"], f"{label} symbols")
    for symbol in symbols:
        symbol_value = _closed_object(symbol, f"{label} symbol", {"uuid", "reference"})
        _strict_string(symbol_value["uuid"], f"{label} symbol uuid")
        _strict_string(symbol_value["reference"], f"{label} symbol reference")
    pins = _strict_array(finding["pins"], f"{label} pins")
    for pin in pins:
        pin_value = _closed_object(
            pin,
            f"{label} pin",
            {"symbol_uuid", "reference", "unit", "number"},
        )
        _strict_string(pin_value["symbol_uuid"], f"{label} pin symbol uuid")
        _strict_string(pin_value["reference"], f"{label} pin reference")
        _strict_integer(pin_value["unit"], f"{label} pin unit", 1)
        _strict_string(pin_value["number"], f"{label} pin number")


def _validate_electrical_review(value: Any, label: str, engine: str) -> None:
    review = _closed_object(
        value,
        label,
        {
            "schema_version",
            "schematic_sha256",
            "policy_sha256",
            "policy_id",
            "approved",
            "counts",
            "findings",
        },
    )
    _strict_integer(review["schema_version"], f"{label} schema version", 1, 1)
    _digest(review["schematic_sha256"], f"{label} schematic digest")
    _digest(review["policy_sha256"], f"{label} policy digest")
    _strict_string(review["policy_id"], f"{label} policy id")
    _strict_bool(review["approved"], f"{label} approval")
    _validate_counts(review["counts"], f"{label} counts")
    findings = _strict_array(review["findings"], f"{label} findings")
    for index, finding in enumerate(findings):
        _validate_electrical_finding(finding, f"{label} finding {index}")


def _validate_handoff_finding(value: Any, label: str) -> None:
    finding = _closed_object(
        value,
        label,
        {"code", "message", "reference", "pin", "net"},
    )
    if finding["code"] not in _HANDOFF_FINDING_CODES:
        raise _fail(f"{label} code is invalid")
    _strict_string(finding["message"], f"{label} message")
    _optional_string(finding["reference"], f"{label} reference")
    _optional_string(finding["pin"], f"{label} pin")
    _optional_string(finding["net"], f"{label} net")


def _validate_handoff(value: Any, label: str, engine: str) -> None:
    handoff = _closed_object(
        value,
        label,
        {
            "schema_version",
            "engine_version",
            "circuit_source_bytes",
            "circuit_source_sha256",
            "schematic_source_bytes",
            "schematic_source_sha256",
            "circuit_spec_sha256",
            "circuit_check_sha256",
            "circuit_review",
            "schematic_sha256",
            "schematic_review",
            "policy_sha256",
            "findings",
            "counts",
            "approved",
        },
    )
    _strict_integer(handoff["schema_version"], f"{label} schema version", 1, 1)
    if _strict_string(handoff["engine_version"], f"{label} engine version") != engine:
        raise _fail(f"{label} engine version does not match the runner")
    _strict_integer(
        handoff["circuit_source_bytes"],
        f"{label} circuit source bytes",
        1,
        _MAXIMUM_CIRCUIT_SOURCE_BYTES,
    )
    _digest(handoff["circuit_source_sha256"], f"{label} circuit source digest")
    _strict_integer(
        handoff["schematic_source_bytes"],
        f"{label} schematic source bytes",
        1,
        _MAXIMUM_SCHEMATIC_SOURCE_BYTES,
    )
    _digest(handoff["schematic_source_sha256"], f"{label} schematic source digest")
    _digest(handoff["circuit_spec_sha256"], f"{label} circuit spec digest")
    _digest(handoff["circuit_check_sha256"], f"{label} circuit check digest")
    _validate_electrical_review(handoff["circuit_review"], f"{label} circuit review", engine)
    _digest(handoff["schematic_sha256"], f"{label} schematic digest")
    _validate_electrical_review(
        handoff["schematic_review"], f"{label} schematic review", engine
    )
    _digest(handoff["policy_sha256"], f"{label} policy digest")
    findings = _strict_array(handoff["findings"], f"{label} findings")
    for index, finding in enumerate(findings):
        _validate_handoff_finding(finding, f"{label} finding {index}")
    _validate_counts(handoff["counts"], f"{label} counts")
    _strict_bool(handoff["approved"], f"{label} approval")


def _validate_binding_finding(value: Any, label: str) -> None:
    finding = _closed_object(
        value,
        label,
        {"code", "message", "reference", "pin", "net"},
    )
    if finding["code"] not in _BOARD_BINDING_FINDING_CODES:
        raise _fail(f"{label} code is invalid")
    _strict_string(finding["message"], f"{label} message")
    _optional_string(finding["reference"], f"{label} reference")
    _optional_string(finding["pin"], f"{label} pin")
    _optional_string(finding["net"], f"{label} net")


def _validate_binding(value: Any, label: str, engine: str) -> None:
    binding = _closed_object(
        value,
        label,
        {
            "schema_version",
            "engine_version",
            "board_source_bytes",
            "board_source_sha256",
            "board_electrical_sha256",
            "circuit_kicad_handoff_sha256",
            "binding_sha256",
            "circuit_kicad_handoff",
            "findings",
            "counts",
            "approved",
        },
    )
    _strict_integer(binding["schema_version"], f"{label} schema version", 1, 1)
    if _strict_string(binding["engine_version"], f"{label} engine version") != engine:
        raise _fail(f"{label} engine version does not match the runner")
    _strict_integer(
        binding["board_source_bytes"],
        f"{label} board source bytes",
        1,
        _MAXIMUM_FILE_BYTES,
    )
    _digest(binding["board_source_sha256"], f"{label} board source digest")
    _digest(binding["board_electrical_sha256"], f"{label} board electrical digest")
    _digest(binding["circuit_kicad_handoff_sha256"], f"{label} handoff digest")
    _digest(binding["binding_sha256"], f"{label} binding digest")
    _validate_handoff(binding["circuit_kicad_handoff"], f"{label} handoff", engine)
    findings = _strict_array(
        binding["findings"], f"{label} findings", _MAXIMUM_BINDING_FINDINGS
    )
    for index, finding in enumerate(findings):
        _validate_binding_finding(finding, f"{label} finding {index}")
    _validate_counts(binding["counts"], f"{label} counts")
    _strict_bool(binding["approved"], f"{label} approval")


def _validate_pipeline_evidence(value: Any, label: str) -> None:
    evidence = _closed_object(value, label, {"role", "bytes", "sha256"})
    role = _strict_string(evidence["role"], f"{label} role", 1, 128)
    if _PIPELINE_ROLE_RE.fullmatch(role) is None:
        raise _fail(f"{label} role is invalid")
    _strict_integer(evidence["bytes"], f"{label} bytes", 1, _MAXIMUM_FILE_BYTES)
    _digest(evidence["sha256"], f"{label} digest")


def _validate_pipeline_phase(value: Any, label: str, expected_name: str) -> None:
    phase = _closed_object(
        value, label, {"name", "evidence", "passed", "checks", "failures"}
    )
    if phase["name"] != expected_name:
        raise _fail(f"{label} name is invalid")
    evidence = _strict_array(phase["evidence"], f"{label} evidence", 16)
    for index, item in enumerate(evidence):
        _validate_pipeline_evidence(item, f"{label} evidence {index}")
    passed = _strict_bool(phase["passed"], f"{label} decision")
    checks = _strict_array(phase["checks"], f"{label} checks", _MAXIMUM_PHASE_CHECKS)
    for item in checks:
        _strict_string(item, f"{label} check", 1, MAXIMUM_FAILURE_CHARACTERS)
    failures = _strict_array(
        phase["failures"], f"{label} failures", _MAXIMUM_PHASE_FAILURES
    )
    for item in failures:
        _strict_string(item, f"{label} failure", 1, MAXIMUM_FAILURE_CHARACTERS)
    if passed and failures:
        raise _fail(f"{label} passed phase has failures")
    if not passed and not failures:
        raise _fail(f"{label} rejected phase has no failure")


def _validate_pipeline(value: Any, label: str) -> None:
    pipeline = _closed_object(
        value,
        label,
        {"schema_version", "pipeline", "identities", "phases", "passed", "failures"},
    )
    schema_version = _strict_integer(
        pipeline["schema_version"], f"{label} schema version", 1, 2
    )
    expected_pipeline = f"pcbex-hardware-v{schema_version}"
    if pipeline["pipeline"] != expected_pipeline:
        raise _fail(f"{label} pipeline name is invalid")
    identities = _closed_object(
        pipeline["identities"],
        f"{label} identities",
        {"schematic_sha256", "board_sha256"},
        {"physical_profile_sha256"},
    )
    for field in ("schematic_sha256", "board_sha256"):
        if identities[field] is not None:
            _digest(identities[field], f"{label} {field}")
    if "physical_profile_sha256" in identities:
        _digest(identities["physical_profile_sha256"], f"{label} physical profile digest")
    phases = _strict_array(
        pipeline["phases"], f"{label} phases", len(_PIPELINE_PHASE_NAMES[schema_version]),
        len(_PIPELINE_PHASE_NAMES[schema_version]),
    )
    for index, (phase, expected_name) in enumerate(
        zip(phases, _PIPELINE_PHASE_NAMES[schema_version])
    ):
        _validate_pipeline_phase(phase, f"{label} phase {index}", expected_name)
    passed = _strict_bool(pipeline["passed"], f"{label} decision")
    failures = _strict_array(
        pipeline["failures"], f"{label} failures", _MAXIMUM_PIPELINE_FAILURES
    )
    for item in failures:
        _strict_string(item, f"{label} failure", 1, MAXIMUM_FAILURE_CHARACTERS)
    if passed:
        if failures or any(phase["passed"] is False for phase in phases):
            raise _fail(f"{label} passed pipeline is inconsistent")
    elif not failures or not any(phase["passed"] is False for phase in phases):
        raise _fail(f"{label} rejected pipeline is inconsistent")


def _validate_input_evidence(value: Any, label: str) -> dict[str, Any]:
    evidence = _closed_object(value, label, {"role", "path", "bytes", "sha256"})
    _strict_string(evidence["role"], f"{label} role", 1, 128)
    _strict_string(evidence["path"], f"{label} path", 1, MAXIMUM_PATH_CHARACTERS)
    _strict_integer(evidence["bytes"], f"{label} bytes", 1, _MAXIMUM_FILE_BYTES)
    _digest(evidence["sha256"], f"{label} digest")
    return evidence


def _parse_fresh_report(
    raw: bytes,
    plan_identity: dict[str, Any],
    plan_digest: str,
    expected_evidence: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    if not raw.endswith(b"\n") or b"\n" in raw[:-1] or b"\r" in raw:
        raise _fail("fresh deterministic pipeline report is not canonical")
    report = _strict_object(raw[:-1], "fresh deterministic pipeline report")
    required = {
        "schema_version",
        "engine_version",
        "plan_source_bytes",
        "plan_source_sha256",
        "plan_sha256",
        "input_evidence",
        "binding",
        "pipeline",
        "failures",
        "approved",
        "run_sha256",
    }
    if set(report) != required:
        raise _fail("fresh deterministic pipeline report has an invalid closed shape")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise _fail("fresh deterministic pipeline report schema version is invalid")
    engine = report["engine_version"]
    if (
        not isinstance(engine, str)
        or not 1 <= len(engine) <= 256
        or _SEMVER_RE.fullmatch(engine) is None
    ):
        raise _fail("fresh deterministic pipeline engine version is invalid")
    _strict_integer(
        report["plan_source_bytes"],
        "fresh report plan source bytes",
        1,
        MAXIMUM_PLAN_BYTES,
    )
    _digest(report["plan_source_sha256"], "fresh report plan source digest")
    if (
        report["plan_source_bytes"] != plan_identity["bytes"]
        or report["plan_source_sha256"] != plan_identity["sha256"]
    ):
        raise _fail("fresh deterministic pipeline report does not bind the plan source")
    plan_sha = _digest(report["plan_sha256"], "fresh report plan digest")
    run_sha = _digest(report["run_sha256"], "fresh report run digest")
    if plan_sha != plan_digest:
        raise _fail("fresh deterministic pipeline plan digest is invalid")
    if run_sha != _semantic_run_digest(report):
        raise _fail("fresh deterministic pipeline run digest is invalid")
    if not isinstance(report["approved"], bool):
        raise _fail("fresh deterministic pipeline approval decision is invalid")
    failures = report["failures"]
    if not isinstance(failures, list) or len(failures) > MAXIMUM_FAILURES:
        raise _fail("fresh deterministic pipeline failures are invalid")
    if any(
        not isinstance(item, str)
        or not 1 <= len(item) <= MAXIMUM_FAILURE_CHARACTERS
        for item in failures
    ):
        raise _fail("fresh deterministic pipeline failures are invalid")
    if failures != sorted(set(failures)):
        raise _fail("fresh deterministic pipeline failures are not canonical")
    binding = report["binding"]
    pipeline = report["pipeline"]
    if binding is not None and not isinstance(binding, dict):
        raise _fail("fresh deterministic pipeline binding is invalid")
    if pipeline is not None and not isinstance(pipeline, dict):
        raise _fail("fresh deterministic pipeline gate is invalid")
    if binding is not None:
        _validate_binding(binding, "fresh deterministic pipeline binding", engine)
    if pipeline is not None:
        _validate_pipeline(pipeline, "fresh deterministic pipeline gate")
    if report["approved"]:
        if (
            failures
            or not isinstance(binding, dict)
            or binding.get("approved") is not True
            or not isinstance(pipeline, dict)
            or pipeline.get("passed") is not True
        ):
            raise _fail("fresh deterministic pipeline approval is inconsistent")
    elif not failures:
        raise _fail("fresh deterministic pipeline rejection has no failure")
    evidence = _strict_array(
        report["input_evidence"],
        "fresh deterministic pipeline input evidence",
        MAXIMUM_INPUT_EVIDENCE,
    )
    evidence = [
        _validate_input_evidence(item, f"fresh input evidence {index}")
        for index, item in enumerate(evidence)
    ]
    ordered_expected = sorted(
        expected_evidence, key=lambda item: (item["role"], item["path"])
    )
    if evidence != ordered_expected:
        raise _fail("fresh deterministic pipeline input evidence does not match captures")
    report_identity = _identity(raw)
    if (
        summary["approved"] != report["approved"]
        or summary["plan_sha256"] != plan_sha
        or summary["run_sha256"] != run_sha
        or summary["failure_count"] != len(failures)
        or summary["report_bytes"] != report_identity["bytes"]
        or summary["report_sha256"] != report_identity["sha256"]
    ):
        raise _fail("deterministic pipeline child summary does not match its report")
    return report


def deterministic_pipeline_replay_result_json_schema() -> dict[str, Any]:
    """Return the closed path-free exact replay result schema."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def identity(maximum: int) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
                "sha256": dict(digest),
            },
        }

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "deterministic-pipeline-fresh-replay-result-v1.json"
        ),
        "title": "pcbex deterministic-pipeline fresh replay result",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "verification_scope",
            "verified",
            "engine_version",
            "plan",
            "report",
            "inputs",
            "validation",
        ],
        "properties": {
            "schema_version": {
                "const": DETERMINISTIC_PIPELINE_REPLAY_RESULT_SCHEMA_VERSION
            },
            "verification_scope": {"const": DETERMINISTIC_PIPELINE_REPLAY_SCOPE},
            "verified": {"const": True},
            "engine_version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": _SEMVER_PATTERN,
            },
            "plan": {
                "type": "object",
                "additionalProperties": False,
                "required": ["source", "plan_sha256", "factory_required"],
                "properties": {
                    "source": identity(MAXIMUM_PLAN_BYTES),
                    "plan_sha256": dict(digest),
                    "factory_required": {"type": "boolean"},
                },
            },
            "report": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "retained",
                    "fresh",
                    "run_sha256",
                    "approved",
                    "failure_count",
                    "identical",
                ],
                "properties": {
                    "retained": identity(MAXIMUM_REPORT_BYTES),
                    "fresh": identity(MAXIMUM_REPORT_BYTES),
                    "run_sha256": dict(digest),
                    "approved": {"type": "boolean"},
                    "failure_count": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAXIMUM_FAILURES,
                    },
                    "identical": {"const": True},
                },
            },
            "inputs": {
                "type": "object",
                "additionalProperties": False,
                "required": ["count", "bytes", "sha256"],
                "properties": {
                    "count": {
                        "type": "integer",
                        "minimum": len(_REQUIRED_ROLES) + len(_FIRMWARE_ARTIFACTS),
                        "maximum": (
                            len(_REQUIRED_ROLES)
                            + len(_OPTIONAL_ROLES)
                            + len(_FIRMWARE_ARTIFACTS)
                        ),
                    },
                    "bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAXIMUM_TOTAL_INPUT_BYTES,
                    },
                    "sha256": dict(digest),
                },
            },
            "validation": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "plan_captured_before_replay",
                    "inputs_captured_before_replay",
                    "fresh_report_reproduced",
                    "retained_report_identical",
                    "staged_inputs_unchanged",
                    "caller_inputs_unchanged",
                ],
                "properties": {
                    "plan_captured_before_replay": {"const": True},
                    "inputs_captured_before_replay": {"const": True},
                    "fresh_report_reproduced": {"const": True},
                    "retained_report_identical": {"const": True},
                    "staged_inputs_unchanged": {"const": True},
                    "caller_inputs_unchanged": {"const": True},
                },
            },
        },
    }


def replay_deterministic_pipeline(
    plan: str | os.PathLike[str],
    retained_report: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly run one closed plan and exactly compare its retained report."""

    try:
        timeout = float(timeout_seconds)
        start = float(_clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate timeout is invalid") from None
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > MAXIMUM_TIMEOUT_SECONDS
        or not math.isfinite(start)
    ):
        raise _fail("aggregate timeout is invalid")
    deadline = start + timeout
    if not math.isfinite(deadline):
        raise _fail("aggregate timeout is invalid")

    plan_source = _freeze_path(plan, "deterministic pipeline plan")
    report_source = _freeze_path(retained_report, "retained pipeline report")
    if _same_file(plan_source, report_source):
        raise _fail("deterministic pipeline plan and report must be distinct")
    command = _normalize_command(pcbex)
    plan_raw = _read_nonempty(plan_source, MAXIMUM_PLAN_BYTES, "plan")
    plan_identity = _identity(plan_raw)
    plan_value, descriptors = _parse_plan(plan_raw)
    plan_digest = _semantic_plan_digest(plan_value)
    if sum(descriptor["bytes"] for _role, descriptor in descriptors) > (
        MAXIMUM_TOTAL_INPUT_BYTES
    ):
        raise _fail("deterministic pipeline inputs exceed their aggregate bound")
    _remaining(deadline, _clock)
    retained_raw = _read_nonempty(
        report_source, MAXIMUM_REPORT_BYTES, "retained report"
    )
    retained_identity = _identity(retained_raw)
    _remaining(deadline, _clock)

    caller_root = Path(plan_source).parent
    firmware_descriptor = dict(descriptors)["firmware_manifest"]
    firmware_manifest_source = _source_path(
        caller_root, firmware_descriptor["path"]
    )
    if firmware_manifest_source.name != "manifest.json":
        raise _fail("firmware manifest basename must be manifest.json")
    firmware_source_directory = firmware_manifest_source.parent
    _firmware_entry_names(firmware_source_directory)

    relative_keys = {descriptor["path"].casefold() for _role, descriptor in descriptors}
    plan_stage_name = _stage_name(relative_keys)
    captures: list[tuple[Path, Path, int, str, dict[str, Any]]] = []
    evidence: list[dict[str, Any]] = []

    trusted_root = _trusted_temporary_root()
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-deterministic-pipeline-replay-", dir=trusted_root
        ) as temporary:
            workspace = Path(temporary)
            input_root = workspace / "inputs"
            fresh_directory = workspace / "result"
            staged_plan = input_root / plan_stage_name
            fresh_report = fresh_directory / "fresh-report.json"
            firmware_relative_parent = PurePosixPath(
                firmware_descriptor["path"]
            ).parent
            planned_staging_paths = [
                workspace,
                input_root,
                fresh_directory,
                staged_plan,
                fresh_report,
            ]
            planned_staging_paths.extend(
                _source_path(input_root, descriptor["path"])
                for _role, descriptor in descriptors
            )
            planned_staging_paths.extend(
                _source_path(
                    input_root,
                    name
                    if str(firmware_relative_parent) == "."
                    else f"{firmware_relative_parent.as_posix()}/{name}",
                )
                for name in _FIRMWARE_ARTIFACTS
            )
            _validate_private_staging_paths(planned_staging_paths)
            input_root.mkdir(mode=0o700)
            fresh_directory.mkdir(mode=0o700)
            atomic_write_no_clobber(
                staged_plan, plan_raw, max_bytes=MAXIMUM_PLAN_BYTES
            )

            total_input_bytes = 0
            for role, descriptor in descriptors:
                caller_path = _source_path(caller_root, descriptor["path"])
                raw = _read_nonempty(caller_path, _ROLE_LIMITS[role], role)
                observed = _identity(raw)
                if (
                    observed["bytes"] != descriptor["bytes"]
                    or observed["sha256"] != descriptor["sha256"]
                ):
                    raise _fail(f"{role} source does not match its plan descriptor")
                staged_path = _source_path(input_root, descriptor["path"])
                staged_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                atomic_write_no_clobber(
                    staged_path, raw, max_bytes=_ROLE_LIMITS[role]
                )
                total_input_bytes += len(raw)
                if total_input_bytes > MAXIMUM_TOTAL_INPUT_BYTES:
                    raise _fail("deterministic pipeline inputs exceed their aggregate bound")
                captured = _capture_identity(raw, role, descriptor["path"])
                evidence.append(captured)
                captures.append(
                    (caller_path, staged_path, _ROLE_LIMITS[role], role, observed)
                )
                _remaining(deadline, _clock)

            for name in _FIRMWARE_ARTIFACTS:
                caller_path = firmware_source_directory / name
                raw = _read_nonempty(
                    caller_path, _FIRMWARE_ARTIFACT_LIMIT, f"firmware artifact {name}"
                )
                relative = (
                    name
                    if str(firmware_relative_parent) == "."
                    else f"{firmware_relative_parent.as_posix()}/{name}"
                )
                staged_path = _source_path(input_root, relative)
                staged_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                atomic_write_no_clobber(
                    staged_path, raw, max_bytes=_FIRMWARE_ARTIFACT_LIMIT
                )
                total_input_bytes += len(raw)
                if total_input_bytes > MAXIMUM_TOTAL_INPUT_BYTES:
                    raise _fail("deterministic pipeline inputs exceed their aggregate bound")
                observed = _identity(raw)
                evidence.append(
                    _capture_identity(raw, f"firmware_artifact:{name}", relative)
                )
                captures.append(
                    (
                        caller_path,
                        staged_path,
                        _FIRMWARE_ARTIFACT_LIMIT,
                        f"firmware artifact {name}",
                        observed,
                    )
                )
                _remaining(deadline, _clock)

            input_identity = _input_set_identity(evidence)
            _firmware_entry_names(firmware_source_directory)
            _firmware_entry_names(
                _source_path(input_root, firmware_descriptor["path"]).parent
            )
            for caller_path, staged_path, maximum, label, expected in captures:
                _verify_capture(caller_path, expected, maximum, label)
                _verify_capture(staged_path, expected, maximum, f"staged {label}")
                _remaining(deadline, _clock)
            _verify_capture(
                plan_source, plan_identity, MAXIMUM_PLAN_BYTES, "plan source"
            )
            _verify_capture(
                report_source,
                retained_identity,
                MAXIMUM_REPORT_BYTES,
                "retained report source",
            )

            argv = _validate_final_argv(
                [
                    *command,
                    "run-deterministic-pipeline",
                    str(staged_plan),
                    "--output",
                    str(fresh_report),
                    "--mcp-echo-report-summary",
                ]
            )
            outer_remaining = _remaining(deadline, _clock)
            cleanup_and_reread_reserve = min(30.0, outer_remaining / 2.0)
            process_cleanup_timeout = cleanup_and_reread_reserve / 2.0
            process_timeout = outer_remaining - cleanup_and_reread_reserve
            if (
                not math.isfinite(process_timeout)
                or process_timeout <= 0
                or not math.isfinite(process_cleanup_timeout)
                or process_cleanup_timeout <= 0
            ):
                raise _fail("deterministic pipeline child has no execution budget")
            try:
                completed = run_bounded(
                    argv,
                    timeout_seconds=process_timeout,
                    cleanup_timeout_seconds=process_cleanup_timeout,
                    max_stdout_bytes=MAXIMUM_CHILD_STDOUT_BYTES,
                    max_stderr_bytes=MAXIMUM_CHILD_STDERR_BYTES,
                )
            except BoundedProcessError:
                raise _fail("deterministic pipeline child process failed") from None
            if completed.returncode != 0:
                raise _fail("deterministic pipeline child rejected the replay")
            summary = _parse_child_summary(completed.stdout)
            _remaining(deadline, _clock)

            fresh_raw = _read_nonempty(
                fresh_report, MAXIMUM_REPORT_BYTES, "fresh report"
            )
            fresh_identity = _identity(fresh_raw)
            if fresh_raw != retained_raw:
                raise _fail(
                    "fresh deterministic pipeline replay did not reproduce the retained report"
                )
            report_value = _parse_fresh_report(
                fresh_raw, plan_identity, plan_digest, evidence, summary
            )
            _remaining(deadline, _clock)

            for caller_path, staged_path, maximum, label, expected in captures:
                _verify_capture(staged_path, expected, maximum, f"staged {label}")
                _verify_capture(caller_path, expected, maximum, label)
                _remaining(deadline, _clock)
            _firmware_entry_names(firmware_source_directory)
            _firmware_entry_names(
                _source_path(input_root, firmware_descriptor["path"]).parent
            )
            _verify_capture(
                plan_source, plan_identity, MAXIMUM_PLAN_BYTES, "plan source"
            )
            _verify_capture(
                staged_plan, plan_identity, MAXIMUM_PLAN_BYTES, "staged plan source"
            )
            _verify_capture(
                report_source,
                retained_identity,
                MAXIMUM_REPORT_BYTES,
                "retained report source",
            )
            _verify_capture(
                fresh_report, fresh_identity, MAXIMUM_REPORT_BYTES, "fresh report source"
            )
            _remaining(deadline, _clock)
    except DeterministicPipelineReplayError:
        raise
    except (BoundedIOError, BoundedProcessError, OSError, TypeError, ValueError):
        raise _fail("deterministic pipeline replay workspace failed") from None

    result = {
        "schema_version": DETERMINISTIC_PIPELINE_REPLAY_RESULT_SCHEMA_VERSION,
        "verification_scope": DETERMINISTIC_PIPELINE_REPLAY_SCOPE,
        "verified": True,
        "engine_version": report_value["engine_version"],
        "plan": {
            "source": plan_identity,
            "plan_sha256": report_value["plan_sha256"],
            "factory_required": plan_value["require_factory"],
        },
        "report": {
            "retained": retained_identity,
            "fresh": fresh_identity,
            "run_sha256": report_value["run_sha256"],
            "approved": report_value["approved"],
            "failure_count": len(report_value["failures"]),
            "identical": True,
        },
        "inputs": input_identity,
        "validation": {
            "plan_captured_before_replay": True,
            "inputs_captured_before_replay": True,
            "fresh_report_reproduced": True,
            "retained_report_identical": True,
            "staged_inputs_unchanged": True,
            "caller_inputs_unchanged": True,
        },
    }
    _remaining(deadline, _clock)
    return result


__all__ = [
    "DETERMINISTIC_PIPELINE_REPLAY_RESULT_SCHEMA_VERSION",
    "DETERMINISTIC_PIPELINE_REPLAY_SCOPE",
    "DeterministicPipelineReplayError",
    "deterministic_pipeline_replay_result_json_schema",
    "replay_deterministic_pipeline",
]

"""Freshly replay one v1.478 release with externally pinned entrypoint bytes.

This boundary observes three native command entrypoints after the complete
v1.478 evidence closure has been captured and before selected tools run.  It
requires their bytes to match caller-supplied SHA-256 pins, supplies the
resolved absolute entrypoints to the existing v1.478 authority, and requires
that authority to freshly reassess the time-invariant subject of one retained
v1.478 report.

The digest pins authenticate neither executable origin nor the surrounding
loader, libraries, plugins, environment, operating system, or toolchain.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any

from .bounded_io import BoundedIOError
from . import routing_drc_fabrication_release as _v1478


EXECUTABLE_PINNED_FABRICATION_RELEASE_SCHEMA_VERSION = 1
EXECUTABLE_PINNED_FABRICATION_RELEASE_SCOPE = (
    "fresh-exact-executable-pinned-fabrication-release-v1"
)

MAXIMUM_EXECUTABLE_PINNED_FABRICATION_RELEASE_REPORT_BYTES = 8 * 1024 * 1024
MAXIMUM_PINNED_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAXIMUM_PINNED_EXECUTABLE_AGGREGATE_BYTES = 384 * 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = (
    _v1478.MAXIMUM_TOTAL_INPUT_BYTES
    + _v1478.MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES
    + MAXIMUM_PINNED_EXECUTABLE_AGGREGATE_BYTES
)
DEFAULT_TIMEOUT_SECONDS = _v1478.DEFAULT_TIMEOUT_SECONDS
MAXIMUM_TIMEOUT_SECONDS = _v1478.MAXIMUM_TIMEOUT_SECONDS

_REPORT_BINDING_DOMAIN = (
    b"pcbex:fresh-exact-executable-pinned-fabrication-release:v1\0"
)
_HEX = frozenset("0123456789abcdef")
_ROLES = ("routing_pcbex", "authorization_pcbex", "kicad_cli")
_REPORT_KEYS = (
    "schema_version",
    "verification_scope",
    "status",
    "routing_drc_fabrication_release_authorized",
    "executable_digest_pins_verified",
    "release_authorized",
    "source_authenticity_verified",
    "executable_origin_authenticity_verified",
    "toolchain_authenticity_verified",
    "policy_pack_authenticity_verified",
    "factory_receipt_authenticity_verified",
    "manufacturability_verified",
    "external_submission_performed",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "challenge_one_time_use_enforced",
    "sources",
    "routing_drc_fabrication_release",
    "executable_pins",
    "gate_failures",
    "validation",
    "binding_sha256",
)
_PIN_KEYS = ("format", "bytes", "sha256", "expected_sha256", "matched")
_VALIDATION_KEYS = (
    "routing_drc_fabrication_release_replayed",
    "retained_routing_drc_fabrication_release_subject_matched",
    "native_entrypoints_resolved",
    "native_entrypoint_formats_checked",
    "executable_digest_pins_matched",
    "executed_commands_bound",
    "executable_sources_unchanged",
    "caller_inputs_unchanged",
)
_FALSE_KEYS = (
    "source_authenticity_verified",
    "executable_origin_authenticity_verified",
    "toolchain_authenticity_verified",
    "policy_pack_authenticity_verified",
    "factory_receipt_authenticity_verified",
    "manufacturability_verified",
    "external_submission_performed",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "challenge_one_time_use_enforced",
)


class ExecutablePinnedFabricationReleaseError(ValueError):
    """Stable, path-free failure from the executable-pin release boundary."""


def _fail(message: str) -> ExecutablePinnedFabricationReleaseError:
    return ExecutablePinnedFabricationReleaseError(message)


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
            raise _fail("caller-controlled hook changed the working directory") from None
    return result


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_digest(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _digest(value: Any, label: str) -> str:
    if not _is_digest(value):
        raise _fail(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha256(raw)}


def _normalize_identity(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail(f"{label} identity must be an object")
    try:
        snapshot = dict(value.items())
    except Exception:
        raise _fail(f"{label} identity is invalid") from None
    if set(snapshot) != {"bytes", "sha256"}:
        raise _fail(f"{label} identity has an unexpected shape")
    byte_count = snapshot.get("bytes")
    if type(byte_count) is not int or not 1 <= byte_count <= _v1478.MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES:
        raise _fail(f"{label} byte count is invalid")
    return {
        "bytes": byte_count,
        "sha256": _digest(snapshot.get("sha256"), f"{label} digest"),
    }


def _normalize_retained_source(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("retained routing/DRC/fabrication release source is invalid")
    try:
        snapshot = dict(value.items())
    except Exception:
        raise _fail(
            "retained routing/DRC/fabrication release source is invalid"
        ) from None
    if set(snapshot) != {"bytes", "sha256", "replay_subject_sha256"}:
        raise _fail(
            "retained routing/DRC/fabrication release source has an unexpected shape"
        )
    identity = _normalize_identity(
        {"bytes": snapshot["bytes"], "sha256": snapshot["sha256"]},
        "routing/DRC/fabrication release report",
    )
    return {
        **identity,
        "replay_subject_sha256": _digest(
            snapshot["replay_subject_sha256"],
            "routing/DRC/fabrication release replay subject digest",
        ),
    }


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    class DuplicateKey(ValueError):
        pass

    def build(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateKey
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=build)
    except (DuplicateKey, UnicodeError, json.JSONDecodeError, RecursionError):
        raise _fail(f"{label} is not strict JSON") from None
    if type(value) is not dict:
        raise _fail(f"{label} must be a JSON object")
    return value


def _compact(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _fail("executable-pinned release report cannot be encoded") from None


def _binding(value: Mapping[str, Any]) -> str:
    body = {key: value[key] for key in _REPORT_KEYS[:-1]}
    return _sha256(_REPORT_BINDING_DOMAIN + _compact(body))


def _native_format(raw: bytes) -> str:
    if sys.platform == "win32":
        if raw.startswith(b"MZ"):
            return "pe"
    elif sys.platform == "darwin":
        if raw[:4] in {
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        }:
            return "mach-o"
    elif sys.platform.startswith("linux"):
        if raw.startswith(b"\x7fELF"):
            return "elf"
    raise _fail("selected release entrypoint is not a native executable for this host")


def _resolve_entrypoint(command: tuple[str, ...], root: str, label: str) -> str:
    if type(command) is not tuple or len(command) != 1 or type(command[0]) is not str:
        raise _fail(f"{label} command must contain exactly one native executable")
    token = command[0]
    if not token or "\x00" in token:
        raise _fail(f"{label} command is invalid")
    if os.path.isabs(token):
        candidate = token
    elif os.sep in token or (os.altsep is not None and os.altsep in token):
        candidate = os.path.join(root, token)
    else:
        try:
            selected = shutil.which(token)
        except Exception:
            raise _fail(f"{label} executable could not be resolved") from None
        if selected is None:
            raise _fail(f"{label} executable could not be resolved")
        candidate = selected
    try:
        resolved = os.path.realpath(os.path.abspath(candidate))
    except Exception:
        raise _fail(f"{label} executable could not be resolved") from None
    if type(resolved) is not str or not os.path.isabs(resolved):
        raise _fail(f"{label} executable could not be resolved")
    try:
        if not os.access(resolved, os.X_OK):
            raise _fail(f"{label} executable is not executable")
    except ExecutablePinnedFabricationReleaseError:
        raise
    except Exception:
        raise _fail(f"{label} executable is not executable") from None
    return resolved


def _normalize_pin(value: Any, role: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail(f"{role} executable pin must be an object")
    try:
        snapshot = dict(value.items())
    except Exception:
        raise _fail(f"{role} executable pin is invalid") from None
    if tuple(snapshot) != _PIN_KEYS and set(snapshot) != set(_PIN_KEYS):
        raise _fail(f"{role} executable pin has an unexpected shape")
    executable_format = snapshot.get("format")
    if type(executable_format) is not str or executable_format not in {
        "elf",
        "mach-o",
        "pe",
    }:
        raise _fail(f"{role} executable format is invalid")
    byte_count = snapshot.get("bytes")
    if type(byte_count) is not int or not 1 <= byte_count <= MAXIMUM_PINNED_EXECUTABLE_BYTES:
        raise _fail(f"{role} executable byte count is invalid")
    observed = _digest(snapshot.get("sha256"), f"{role} executable digest")
    expected = _digest(
        snapshot.get("expected_sha256"), f"expected {role} executable digest"
    )
    if observed != expected or snapshot.get("matched") is not True:
        raise _fail(f"{role} executable digest pin is not matched")
    return {
        "format": executable_format,
        "bytes": byte_count,
        "sha256": observed,
        "expected_sha256": expected,
        "matched": True,
    }


def _normalize_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("executable-pinned release report must be an object")
    try:
        snapshot = dict(value.items())
    except Exception:
        raise _fail("executable-pinned release report is invalid") from None
    if tuple(snapshot) != _REPORT_KEYS and set(snapshot) != set(_REPORT_KEYS):
        raise _fail("executable-pinned release report has an unexpected shape")
    if snapshot.get("schema_version") != EXECUTABLE_PINNED_FABRICATION_RELEASE_SCHEMA_VERSION:
        raise _fail("executable-pinned release schema version is invalid")
    if snapshot.get("verification_scope") != EXECUTABLE_PINNED_FABRICATION_RELEASE_SCOPE:
        raise _fail("executable-pinned release verification scope is invalid")

    try:
        nested = _v1478._normalize_report(
            deepcopy(snapshot.get("routing_drc_fabrication_release"))
        )
        nested_raw = _v1478.render_routing_drc_fabrication_release_report(nested)
    except Exception:
        raise _fail("nested routing/DRC/fabrication release report is invalid") from None

    sources = snapshot.get("sources")
    if not isinstance(sources, Mapping):
        raise _fail("executable-pinned release sources must be an object")
    try:
        source_snapshot = dict(sources.items())
    except Exception:
        raise _fail("executable-pinned release sources are invalid") from None
    if set(source_snapshot) != {"routing_drc_fabrication_release_report"}:
        raise _fail("executable-pinned release sources have an unexpected shape")
    retained_identity = _normalize_retained_source(
        source_snapshot["routing_drc_fabrication_release_report"],
    )
    if retained_identity["replay_subject_sha256"] != (
        _v1478._retained_replay_subject_sha256(nested)
    ):
        raise _fail("nested routing/DRC/fabrication release subject is invalid")

    pins = snapshot.get("executable_pins")
    if not isinstance(pins, Mapping):
        raise _fail("executable pins must be an object")
    try:
        pin_snapshot = dict(pins.items())
    except Exception:
        raise _fail("executable pins are invalid") from None
    if set(pin_snapshot) != set(_ROLES):
        raise _fail("executable pins have an unexpected shape")
    normalized_pins = {
        role: _normalize_pin(pin_snapshot[role], role) for role in _ROLES
    }

    nested_authorized = nested["release_authorized"] is True
    expected_status = "release_authorized" if nested_authorized else "not_authorized"
    if snapshot.get("status") != expected_status:
        raise _fail("executable-pinned release status is invalid")
    if snapshot.get("routing_drc_fabrication_release_authorized") is not nested_authorized:
        raise _fail("nested release authorization decision is invalid")
    if snapshot.get("executable_digest_pins_verified") is not True:
        raise _fail("executable digest pin decision is invalid")
    if snapshot.get("release_authorized") is not nested_authorized:
        raise _fail("executable-pinned release decision is invalid")
    for key in _FALSE_KEYS:
        if snapshot.get(key) is not False:
            raise _fail(f"{key} must remain false")

    expected_gates = (
        [] if nested_authorized else ["routing_drc_fabrication_release_not_authorized"]
    )
    gates = snapshot.get("gate_failures")
    if type(gates) is not list or gates != expected_gates:
        raise _fail("executable-pinned release gate failures are invalid")
    validation = snapshot.get("validation")
    if not isinstance(validation, Mapping):
        raise _fail("executable-pinned release validation must be an object")
    try:
        validation_snapshot = dict(validation.items())
    except Exception:
        raise _fail("executable-pinned release validation is invalid") from None
    if set(validation_snapshot) != set(_VALIDATION_KEYS) or any(
        validation_snapshot[key] is not True for key in _VALIDATION_KEYS
    ):
        raise _fail("executable-pinned release validation flags are invalid")

    normalized: dict[str, Any] = {
        "schema_version": EXECUTABLE_PINNED_FABRICATION_RELEASE_SCHEMA_VERSION,
        "verification_scope": EXECUTABLE_PINNED_FABRICATION_RELEASE_SCOPE,
        "status": expected_status,
        "routing_drc_fabrication_release_authorized": nested_authorized,
        "executable_digest_pins_verified": True,
        "release_authorized": nested_authorized,
        **{key: False for key in _FALSE_KEYS},
        "sources": {
            "routing_drc_fabrication_release_report": retained_identity,
        },
        "routing_drc_fabrication_release": nested,
        "executable_pins": normalized_pins,
        "gate_failures": expected_gates,
        "validation": {key: True for key in _VALIDATION_KEYS},
        "binding_sha256": snapshot.get("binding_sha256"),
    }
    if (
        not _is_digest(normalized["binding_sha256"])
        or normalized["binding_sha256"] != _binding(normalized)
    ):
        raise _fail("executable-pinned release binding is invalid")
    return normalized


def _evaluate_impl(
    input_board: str | os.PathLike[str],
    routed_board: str | os.PathLike[str],
    convergence_report: str | os.PathLike[str],
    routing_verification_report: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    routing_manufacturing_handoff_report: str | os.PathLike[str],
    native_kicad_drc_report: str | os.PathLike[str],
    routing_drc_manufacturing_handoff_report: str | os.PathLike[str],
    deterministic_pipeline_plan: str | os.PathLike[str],
    deterministic_pipeline_report: str | os.PathLike[str],
    signed_approvals: Sequence[str | os.PathLike[str]],
    routing_drc_fabrication_release_report: str | os.PathLike[str],
    expected_policy_pack_canonical_sha256: str,
    expected_routing_pcbex_sha256: str,
    expected_authorization_pcbex_sha256: str,
    expected_kicad_cli_sha256: str,
    pcbex: str | Sequence[str],
    authorization_pcbex: str | Sequence[str],
    *,
    kicad_cli: str | os.PathLike[str],
    kicad_project: str | os.PathLike[str] | None,
    kicad_rules: str | os.PathLike[str] | None,
    grid_mm: float,
    width_mm: float,
    clearance_mm: float,
    via_diameter_mm: float,
    via_drill_mm: float,
    bend_cost: int,
    via_cost: int,
    fab: str | None,
    fab_profile: str | os.PathLike[str] | None,
    physical_profile: str | os.PathLike[str] | None,
    timeout_seconds: float,
    _clock: Callable[[], float],
    _root: str,
) -> dict[str, Any]:
    expected = {
        "routing_pcbex": _digest(
            expected_routing_pcbex_sha256, "expected routing pcbex digest"
        ),
        "authorization_pcbex": _digest(
            expected_authorization_pcbex_sha256,
            "expected authorization pcbex digest",
        ),
        "kicad_cli": _digest(
            expected_kicad_cli_sha256, "expected KiCad CLI digest"
        ),
    }
    observations: tuple[tuple[str, str, int, str, str, bool], ...] = ()
    captured: tuple[tuple[str, str, bytes], ...] = ()
    retained_capture: list[tuple[str, bytes]] = []

    def observe(
        routing_command: tuple[str, ...],
        authorization_command: tuple[str, ...],
        kicad_argument: str,
    ) -> tuple[tuple[str, ...], tuple[str, ...], str]:
        nonlocal observations, captured
        if observations or captured:
            raise _fail("release entrypoints were observed more than once")
        commands = {
            "routing_pcbex": routing_command,
            "authorization_pcbex": authorization_command,
            "kicad_cli": (kicad_argument,),
        }
        aggregate = 0
        resolved_commands: dict[str, str] = {}
        observed_rows: list[tuple[str, str, int, str, str, bool]] = []
        captured_rows: list[tuple[str, str, bytes]] = []
        for role in _ROLES:
            path = _resolve_entrypoint(commands[role], _root, role)
            try:
                raw = _v1478._read_source(
                    path, MAXIMUM_PINNED_EXECUTABLE_BYTES, f"{role} executable"
                )
            except Exception:
                raise _fail(f"{role} executable could not be captured") from None
            aggregate += len(raw)
            if aggregate > MAXIMUM_PINNED_EXECUTABLE_AGGREGATE_BYTES:
                raise _fail("selected release executables exceed their aggregate bound")
            observed_digest = _sha256(raw)
            if observed_digest != expected[role]:
                raise _fail(f"{role} executable does not match its expected digest")
            observed_rows.append(
                (
                    role,
                    _native_format(raw),
                    len(raw),
                    observed_digest,
                    expected[role],
                    True,
                )
            )
            captured_rows.append((role, path, raw))
            resolved_commands[role] = path
        observations = tuple(observed_rows)
        captured = tuple(captured_rows)
        return (
            (resolved_commands["routing_pcbex"],),
            (resolved_commands["authorization_pcbex"],),
            resolved_commands["kicad_cli"],
        )

    def verify_executables() -> None:
        if tuple(row[0] for row in captured) != _ROLES:
            raise _fail("selected release executables were not captured")
        for role, path, expected_raw in captured:
            try:
                observed_raw = _v1478._read_source(
                    path, MAXIMUM_PINNED_EXECUTABLE_BYTES, f"{role} executable"
                )
            except Exception:
                raise _fail(f"{role} executable could not be reread") from None
            if observed_raw != expected_raw:
                raise _fail(f"{role} executable changed during release replay")

    if _clock is time.monotonic:
        replay_clock = _clock
    else:

        def replay_clock() -> float:
            value = _clock()
            if captured:
                verify_executables()
            return value

    try:
        nested = _v1478._evaluate_impl(
            input_board,
            routed_board,
            convergence_report,
            routing_verification_report,
            manufacturing_package,
            routing_manufacturing_handoff_report,
            native_kicad_drc_report,
            routing_drc_manufacturing_handoff_report,
            deterministic_pipeline_plan,
            deterministic_pipeline_report,
            signed_approvals,
            expected_policy_pack_canonical_sha256,
            pcbex,
            authorization_pcbex,
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
            _clock=replay_clock,
            _root=_root,
            _retained_outer=routing_drc_fabrication_release_report,
            _command_observer=observe,
            _retained_outer_subject_only=True,
            _retained_outer_capture=retained_capture,
        )
    except ExecutablePinnedFabricationReleaseError:
        raise
    except Exception:
        raise _fail("routing/DRC/fabrication release replay failed") from None

    verify_executables()
    if len(retained_capture) != 1:
        raise _fail(
            "retained routing/DRC/fabrication release report was not captured"
        )
    retained_path, retained_raw = retained_capture[0]
    try:
        retained_value = _v1478._normalize_report(
            _strict_object(
                retained_raw, "retained routing/DRC/fabrication release report"
            )
        )
        retained_subject_sha256 = _v1478._retained_replay_subject_sha256(
            retained_value
        )
    except Exception:
        raise _fail(
            "retained routing/DRC/fabrication release report is invalid"
        ) from None
    try:
        final_retained_raw = _v1478._read_source(
            retained_path,
            _v1478.MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES,
            "retained routing/DRC/fabrication release report",
        )
    except Exception:
        raise _fail(
            "retained routing/DRC/fabrication release report could not be reread"
        ) from None
    if final_retained_raw != retained_raw:
        raise _fail(
            "retained routing/DRC/fabrication release report changed during replay"
        )
    if tuple(row[0] for row in observations) != _ROLES:
        raise _fail("selected release executable evidence is incomplete")
    try:
        nested = _v1478._normalize_report(nested)
        nested_raw = _v1478.render_routing_drc_fabrication_release_report(nested)
    except Exception:
        raise _fail("routing/DRC/fabrication release replay returned invalid evidence") from None

    authorized = nested["release_authorized"] is True
    result: dict[str, Any] = {
        "schema_version": EXECUTABLE_PINNED_FABRICATION_RELEASE_SCHEMA_VERSION,
        "verification_scope": EXECUTABLE_PINNED_FABRICATION_RELEASE_SCOPE,
        "status": "release_authorized" if authorized else "not_authorized",
        "routing_drc_fabrication_release_authorized": authorized,
        "executable_digest_pins_verified": True,
        "release_authorized": authorized,
        **{key: False for key in _FALSE_KEYS},
        "sources": {
            "routing_drc_fabrication_release_report": {
                **_identity(retained_raw),
                "replay_subject_sha256": retained_subject_sha256,
            },
        },
        "routing_drc_fabrication_release": nested,
        "executable_pins": {
            role: {
                "format": native_format,
                "bytes": byte_count,
                "sha256": observed_sha256,
                "expected_sha256": expected_sha256,
                "matched": matched,
            }
            for (
                role,
                native_format,
                byte_count,
                observed_sha256,
                expected_sha256,
                matched,
            ) in observations
        },
        "gate_failures": (
            [] if authorized else ["routing_drc_fabrication_release_not_authorized"]
        ),
        "validation": {key: True for key in _VALIDATION_KEYS},
        "binding_sha256": "",
    }
    result["binding_sha256"] = _binding(result)
    return _normalize_report(result)


def evaluate_executable_pinned_fabrication_release(
    input_board: str | os.PathLike[str],
    routed_board: str | os.PathLike[str],
    convergence_report: str | os.PathLike[str],
    routing_verification_report: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    routing_manufacturing_handoff_report: str | os.PathLike[str],
    native_kicad_drc_report: str | os.PathLike[str],
    routing_drc_manufacturing_handoff_report: str | os.PathLike[str],
    deterministic_pipeline_plan: str | os.PathLike[str],
    deterministic_pipeline_report: str | os.PathLike[str],
    signed_approvals: Sequence[str | os.PathLike[str]],
    routing_drc_fabrication_release_report: str | os.PathLike[str],
    expected_policy_pack_canonical_sha256: str,
    expected_routing_pcbex_sha256: str,
    expected_authorization_pcbex_sha256: str,
    expected_kicad_cli_sha256: str,
    pcbex: str | Sequence[str] = "pcbex",
    authorization_pcbex: str | Sequence[str] = "pcbex",
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
    """Freshly reassess a v1.478 subject using three digest-pinned binaries."""

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
            routing_drc_manufacturing_handoff_report,
            deterministic_pipeline_plan,
            deterministic_pipeline_report,
            signed_approvals,
            routing_drc_fabrication_release_report,
            expected_policy_pack_canonical_sha256,
            expected_routing_pcbex_sha256,
            expected_authorization_pcbex_sha256,
            expected_kicad_cli_sha256,
            pcbex,
            authorization_pcbex,
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
    except ExecutablePinnedFabricationReleaseError:
        raise
    except Exception:
        raise _fail("executable-pinned fabrication release inputs are invalid") from None


def render_executable_pinned_fabrication_release_report(
    report: Mapping[str, Any],
) -> bytes:
    root = _public_root()

    def render() -> bytes:
        normalized = _normalize_report(deepcopy(report))
        try:
            raw = (
                json.dumps(normalized, indent=2, ensure_ascii=False, allow_nan=False)
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise _fail("executable-pinned release report cannot be rendered") from None
        if len(raw) > MAXIMUM_EXECUTABLE_PINNED_FABRICATION_RELEASE_REPORT_BYTES:
            raise _fail("executable-pinned release report exceeds its byte limit")
        return raw

    try:
        return _guard_cwd(root, render)
    except ExecutablePinnedFabricationReleaseError:
        raise
    except Exception:
        raise _fail("executable-pinned release report is invalid") from None


def executable_pinned_fabrication_release_report_json_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    identity = {
        "type": "object",
        "additionalProperties": False,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": _v1478.MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES,
            },
            "sha256": dict(digest),
        },
    }
    retained_source = deepcopy(identity)
    retained_source["required"] = [
        "bytes",
        "sha256",
        "replay_subject_sha256",
    ]
    retained_source["properties"]["replay_subject_sha256"] = dict(digest)
    pin = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_PIN_KEYS),
        "properties": {
            "format": {"enum": ["elf", "mach-o", "pe"]},
            "bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_PINNED_EXECUTABLE_BYTES,
            },
            "sha256": dict(digest),
            "expected_sha256": dict(digest),
            "matched": {"const": True},
        },
    }
    nested_schema = deepcopy(
        _v1478.routing_drc_fabrication_release_report_json_schema()
    )
    validation = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_VALIDATION_KEYS),
        "properties": {key: {"const": True} for key in _VALIDATION_KEYS},
    }
    properties: dict[str, Any] = {
        "schema_version": {
            "const": EXECUTABLE_PINNED_FABRICATION_RELEASE_SCHEMA_VERSION
        },
        "verification_scope": {"const": EXECUTABLE_PINNED_FABRICATION_RELEASE_SCOPE},
        "status": {"enum": ["release_authorized", "not_authorized"]},
        "routing_drc_fabrication_release_authorized": {"type": "boolean"},
        "executable_digest_pins_verified": {"const": True},
        "release_authorized": {"type": "boolean"},
        **{key: {"const": False} for key in _FALSE_KEYS},
        "sources": {
            "type": "object",
            "additionalProperties": False,
            "required": ["routing_drc_fabrication_release_report"],
            "properties": {
                "routing_drc_fabrication_release_report": retained_source,
            },
        },
        "routing_drc_fabrication_release": nested_schema,
        "executable_pins": {
            "type": "object",
            "additionalProperties": False,
            "required": list(_ROLES),
            "properties": {role: deepcopy(pin) for role in _ROLES},
        },
        "gate_failures": {
            "type": "array",
            "maxItems": 1,
            "items": {"const": "routing_drc_fabrication_release_not_authorized"},
        },
        "validation": validation,
        "binding_sha256": dict(digest),
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "executable-pinned-fabrication-release-v1.json"
        ),
        "title": "pcbex executable-pinned fabrication release report",
        "type": "object",
        "additionalProperties": False,
        "required": list(_REPORT_KEYS),
        "properties": properties,
        "allOf": [
            {
                "if": {"properties": {"status": {"const": "release_authorized"}}},
                "then": {
                    "properties": {
                        "routing_drc_fabrication_release_authorized": {"const": True},
                        "release_authorized": {"const": True},
                        "gate_failures": {"maxItems": 0},
                    }
                },
                "else": {
                    "properties": {
                        "routing_drc_fabrication_release_authorized": {"const": False},
                        "release_authorized": {"const": False},
                        "gate_failures": {"minItems": 1, "maxItems": 1},
                    }
                },
            }
        ],
    }


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "EXECUTABLE_PINNED_FABRICATION_RELEASE_SCHEMA_VERSION",
    "EXECUTABLE_PINNED_FABRICATION_RELEASE_SCOPE",
    "ExecutablePinnedFabricationReleaseError",
    "MAXIMUM_EXECUTABLE_PINNED_FABRICATION_RELEASE_REPORT_BYTES",
    "MAXIMUM_PINNED_EXECUTABLE_AGGREGATE_BYTES",
    "MAXIMUM_PINNED_EXECUTABLE_BYTES",
    "MAXIMUM_TIMEOUT_SECONDS",
    "MAXIMUM_TOTAL_INPUT_BYTES",
    "evaluate_executable_pinned_fabrication_release",
    "executable_pinned_fabrication_release_report_json_schema",
    "render_executable_pinned_fabrication_release_report",
]

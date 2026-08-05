#!/usr/bin/env python3
"""Build and authenticate a small end-to-end deterministic-pipeline fixture.

The CI workflow invokes this helper through ``ci_runtime.py exec``.  The
helper deliberately captures every pcbex child stream and emits exactly one
compact JSON summary on success; no plan, report, schematic, or manufacturing
package body is written to stdout.  The same bounded child timeout and output
limits are enforced locally so a direct invocation has the same failure
contract as the supervisor-wrapped invocation.

Only three small KiCad/circuit source fixtures are checked in.  Electrical
review, analysis, firmware, and the manufacturing archive are generated in a
fresh output tree.  The rejected case is derived from the accepted archive by
changing one ZIP entry without updating its manifest, so the archive remains a
valid ZIP while the manufacturing gate rejects its content identity.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import zipfile
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
SUMMARY_VALIDATOR = SCRIPT_DIR / "deterministic_pipeline_summary.py"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ci_runtime import (  # noqa: E402
    ExecutionBoundaryError,
    atomic_write_no_clobber,
    run as run_bounded,
)

SCHEMA_VERSION = 1
MAX_CHILD_STDOUT_BYTES = 64 * 1024
MAX_CHILD_STDERR_BYTES = 256 * 1024
MAX_CHILD_TIMEOUT_SECONDS = 600
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024 * 1024 - 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FIXTURE_FILES = ("circuit-spec-v2.json", "design.kicad_pcb", "design.kicad_sch")
FIRMWARE_FILES = (
    "pinout.h",
    "firmware.h",
    "firmware.c",
    "firmware_smoke_test.c",
    "firmware.cpp",
    "firmware_cpp_smoke_test.cpp",
    "host.py",
)


class FixtureError(RuntimeError):
    """A bounded fixture-generation or evidence-authentication failure."""


@dataclass(frozen=True)
class ChildResult:
    returncode: int
    stdout: bytes
    stderr: bytes


# The inode/device pair prevents replacement, while the bounded byte count and
# digest also detect an in-place rewrite that preserves the same inode.
ExecutableIdentity = tuple[int, int, int, str]


def _reject_constant(value: str) -> Any:
    raise FixtureError(f"non-standard JSON number {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json(payload: bytes, *, role: str) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except FixtureError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixtureError(f"{role} is not valid JSON: {error}") from error


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_stable(path: Path, *, maximum: int, role: str) -> bytes:
    """Read one regular file twice, rejecting links and concurrent changes."""

    first = _read_regular(path, maximum=maximum, role=role)
    second = _read_regular(path, maximum=maximum, role=role)
    if first != second:
        raise FixtureError(f"{role} changed between bounded reads")
    return first


def _read_regular(path: Path, *, maximum: int, role: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FixtureError(f"could not inspect {role}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise FixtureError(f"{role} must be a regular non-link file: {path}")
    if metadata.st_size > maximum:
        raise FixtureError(f"{role} exceeds its {maximum}-byte limit")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise FixtureError(f"could not read {role}: {error}") from error
    if len(payload) > maximum:
        raise FixtureError(f"{role} exceeds its {maximum}-byte limit")
    return payload


def _reject_symlink_components(path: Path, role: str) -> None:
    """Reject links in an existing path prefix before creating output files."""

    absolute = path.absolute()
    components = [absolute.anchor]
    components.extend(absolute.parts[1:])
    current = Path(components[0])
    for component in components[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError as error:
            raise FixtureError(f"could not inspect {role} component {current}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise FixtureError(f"{role} contains a symlink component: {current}")


def _require_regular_directory(path: Path, role: str) -> None:
    _reject_symlink_components(path, role)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FixtureError(f"could not inspect {role}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise FixtureError(f"{role} must be a regular directory: {path}")


def _executable_identity(path: Path) -> ExecutableIdentity:
    """Capture a bounded, stable identity for the selected pcbex binary."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise FixtureError(f"could not inspect pcbex executable: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise FixtureError("pcbex executable changed to a non-regular file")
    payload = _read_stable(
        path,
        maximum=MAX_EXECUTABLE_BYTES,
        role="pcbex executable",
    )
    try:
        final_metadata = path.lstat()
    except OSError as error:
        raise FixtureError(f"could not inspect pcbex executable after reading: {error}") from error
    if stat.S_ISLNK(final_metadata.st_mode) or not stat.S_ISREG(final_metadata.st_mode):
        raise FixtureError("pcbex executable changed to a non-regular file")
    identity = (metadata.st_dev, metadata.st_ino)
    final_identity = (final_metadata.st_dev, final_metadata.st_ino)
    if identity != final_identity or final_metadata.st_size != len(payload):
        raise FixtureError("pcbex executable changed while being read")
    return (*identity, len(payload), _sha256(payload))


def _assert_executable_identity(path: Path, expected: ExecutableIdentity) -> None:
    """Reject replacement or in-place mutation of the selected pcbex binary."""

    actual = _executable_identity(path)
    if actual != expected:
        raise FixtureError("pcbex executable changed while the fixture was running")


def _prepare_fresh_output(path: Path) -> None:
    _reject_symlink_components(path, "fixture output")
    if path.exists() or path.is_symlink():
        raise FixtureError(f"fixture output must be new and empty: {path}")
    try:
        path.mkdir(parents=True)
    except OSError as error:
        raise FixtureError(f"could not create fixture output: {error}") from error


def _copy_fixture(fixture_dir: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in FIXTURE_FILES:
        source = fixture_dir / name
        payload = _read_stable(source, maximum=MAX_SOURCE_BYTES, role=f"fixture {name}")
        target = destination / name
        if target.exists() or target.is_symlink():
            raise FixtureError(f"refusing to overwrite fixture output {target}")
        target.write_bytes(payload)


def _run_command(
    argv: list[str],
    *,
    cwd: Path,
    input_bytes: bytes = b"",
    timeout_seconds: int,
    executable_identity: ExecutableIdentity | None = None,
) -> ChildResult:
    """Run one bounded child; the CI supervisor applies an outer bound too."""

    if timeout_seconds < 1 or timeout_seconds > MAX_CHILD_TIMEOUT_SECONDS:
        raise FixtureError("child timeout must be between 1 and 600 seconds")
    if executable_identity is not None:
        _assert_executable_identity(Path(argv[0]), executable_identity)
    try:
        result = run_bounded(
            argv,
            cwd=cwd,
            input_bytes=input_bytes,
            max_stdin_bytes=MAX_SOURCE_BYTES,
            max_stdout_bytes=MAX_CHILD_STDOUT_BYTES,
            max_stderr_bytes=MAX_CHILD_STDERR_BYTES,
            timeout_seconds=timeout_seconds,
        )
    except ExecutionBoundaryError as error:
        raise FixtureError(f"bounded child failed: {error}") from error
    if executable_identity is not None:
        _assert_executable_identity(Path(argv[0]), executable_identity)
    return ChildResult(result.returncode, result.stdout, result.stderr)


def _run_checked(
    pcbex: Path,
    arguments: Iterable[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    executable_identity: ExecutableIdentity | None = None,
) -> ChildResult:
    result = _run_command(
        [str(pcbex), *arguments],
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        if len(detail) > 1024:
            detail = detail[:1024] + "..."
        suffix = f": {detail}" if detail else ""
        raise FixtureError(
            f"pcbex {' '.join(arguments[:2])} exited {result.returncode}{suffix}"
        )
    return result


def _write_json(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise FixtureError(f"refusing to overwrite {path}")
    path.write_bytes(_canonical_json(value))


def _descriptor(path: Path, *, archive_name: str | None = None) -> dict[str, Any]:
    payload = _read_stable(path, maximum=MAX_REPORT_BYTES, role=f"artifact {path.name}")
    return {
        "path": archive_name or path.name,
        "bytes": len(payload),
        "sha256": _sha256(payload),
    }


def _write_manufacturing_package(path: Path, board: Path, *, engine_version: str) -> None:
    board_bytes = _read_stable(board, maximum=MAX_SOURCE_BYTES, role="fixture board")
    artifact_data: list[tuple[str, bytes, str]] = [
        ("design-F_Cu.gtl", b"front-copper", "Copper,L1,Top"),
        ("design-B_Cu.gbl", b"back-copper", "Copper,L2,Bot"),
        ("design-f_mask.gts", b"front-mask", "SolderMask,Top"),
        ("design-b_mask.gbs", b"back-mask", "SolderMask,Bot"),
        ("design-f_silkscreen.gto", b"front-legend", "Legend,Top"),
        ("design-b_silkscreen.gbo", b"back-legend", "Legend,Bot"),
        ("design-Edge_Cuts.gm1", b"profile", "Profile"),
    ]
    gerber_job = _canonical_json(
        {
            "GeneralSpecs": {"LayerNumber": 2},
            "FilesAttributes": [
                {"Path": name, "FileFunction": function}
                for name, _, function in artifact_data
            ],
        }
    ).rstrip(b"\n")
    artifact_data.extend(
        [
            ("design-job.gbrjob", gerber_job, ""),
            ("design.drl", b"drill", ""),
            ("drc.rpt", b"DRC clean\n", ""),
            ("bom.csv", b"Comment,Designator\n", ""),
            ("cpl.csv", b"Designator,Mid X (mm)\n", ""),
        ]
    )
    manifest = {
        "schema_version": 1,
        "engine": "pcbex",
        "engine_version": engine_version,
        "tools": {
            "kicad_cli": "10.0.5",
            "kicad_cli_about_sha256": "a" * 64,
        },
        "input": {
            "path": board.name,
            "bytes": len(board_bytes),
            "sha256": _sha256(board_bytes),
        },
        "project_inputs": [],
        "parts": {"total": 0, "bom": 0, "placement": 0, "dnp": 0},
        "artifacts": [
            {"path": name, "bytes": len(payload), "sha256": _sha256(payload)}
            for name, payload, _ in artifact_data
        ],
        "archive": path.name,
    }
    entries = [(name, payload) for name, payload, _ in artifact_data]
    entries.append(("manifest.json", json.dumps(manifest, separators=(",", ":")).encode()))
    if path.exists() or path.is_symlink():
        raise FixtureError(f"refusing to overwrite manufacturing package {path}")
    try:
        rendered = io.BytesIO()
        with zipfile.ZipFile(rendered, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, payload in entries:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, payload)
        atomic_write_no_clobber(
            path,
            rendered.getvalue(),
            max_bytes=MAX_PACKAGE_BYTES,
        )
    except (OSError, zipfile.BadZipFile, ValueError) as error:
        raise FixtureError(f"could not write manufacturing package: {error}") from error


def _tamper_manufacturing_entry(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise FixtureError(f"refusing to overwrite rejected package {destination}")
    try:
        # Validate the exact mutation target before creating any destination
        # bytes.  Otherwise a malformed source (missing or duplicate drc.rpt)
        # would leave a partial ZIP in the evidence tree after raising.
        with zipfile.ZipFile(source) as source_archive:
            source_infos = source_archive.infolist()
            changed_entries = sum(
                source_info.filename == "drc.rpt" for source_info in source_infos
            )
            if changed_entries != 1:
                raise FixtureError(
                    "rejected package tamper expected exactly one drc.rpt entry, "
                    f"got {changed_entries}"
                )
            rendered = io.BytesIO()
            with zipfile.ZipFile(
                rendered, "w", compression=zipfile.ZIP_STORED
            ) as destination_archive:
                for source_info in source_infos:
                    payload = source_archive.read(source_info.filename)
                    if source_info.filename == "drc.rpt":
                        payload = b"DRC content changed without manifest update\n"
                    info = zipfile.ZipInfo(
                        source_info.filename, date_time=(1980, 1, 1, 0, 0, 0)
                    )
                    info.compress_type = zipfile.ZIP_STORED
                    info.create_system = 3
                    info.external_attr = 0o100644 << 16
                    destination_archive.writestr(info, payload)
            atomic_write_no_clobber(
                destination,
                rendered.getvalue(),
                max_bytes=MAX_PACKAGE_BYTES,
            )
    except FixtureError:
        raise
    except (OSError, zipfile.BadZipFile, KeyError, ValueError) as error:
        raise FixtureError(f"could not derive rejected manufacturing package: {error}") from error


def _write_intent(case: Path, manufacturing_name: str = "manufacturing.zip") -> Path:
    intent = {
        "schema_version": 1,
        "circuit_spec": "circuit-spec-v2.json",
        "schematic": "design.kicad_sch",
        "electrical_policy": "electrical-policy.json",
        "electrical_review": "electrical-review.json",
        "board": "design.kicad_pcb",
        "analysis_manifest": "analysis/run.json",
        "analysis_checks": "analysis/checks.json",
        "quality": "analysis/quality.json",
        "analysis_project": None,
        "analysis_rules": None,
        "analysis_dfm_profile": None,
        "analysis_policy_pack": None,
        "analysis_physical_profile": None,
        "manufacturing_package": manufacturing_name,
        "firmware_manifest": "firmware/manifest.json",
        "factory_receipt": None,
        "require_factory": False,
    }
    path = case / "intent.json"
    rendered = _canonical_json(intent)
    if path.exists() or path.is_symlink():
        if _read_stable(path, maximum=MAX_SOURCE_BYTES, role="pipeline intent") != rendered:
            raise FixtureError(f"refusing to replace an existing pipeline intent {path}")
    else:
        path.write_bytes(rendered)
    return path


def _verify_compiler(
    case: Path, intent: Path, plan: Path, compiler_stdout: bytes, *, timeout_seconds: int
) -> dict[str, Any]:
    result = _run_command(
        [
            sys.executable,
            str(SUMMARY_VALIDATOR),
            "--verify-compile",
            "--intent",
            intent.name,
            "--plan",
            plan.name,
        ],
        cwd=case,
        input_bytes=compiler_stdout,
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise FixtureError(f"compiler summary verification failed: {detail[:1024]}")
    summary = _parse_json(result.stdout, role="verified compiler summary")
    expected = {
        "schema_version",
        "intent_source_bytes",
        "intent_source_sha256",
        "plan_source_bytes",
        "plan_source_sha256",
    }
    if not isinstance(summary, dict) or set(summary) != expected:
        raise FixtureError("verified compiler summary fields are not exact")
    _validate_positive_int(summary["schema_version"], "compiler schema_version")
    if summary["schema_version"] != SCHEMA_VERSION:
        raise FixtureError("verified compiler summary schema version is invalid")
    _validate_hash(summary["intent_source_sha256"], "intent source SHA-256")
    _validate_hash(summary["plan_source_sha256"], "plan source SHA-256")
    _validate_positive_int(summary["intent_source_bytes"], "intent source bytes")
    _validate_positive_int(summary["plan_source_bytes"], "plan source bytes")
    return summary


def _verify_runner(
    case: Path,
    intent: Path,
    plan: Path,
    report: Path,
    runner_stdout: bytes,
    compiler_summary: dict[str, Any],
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    result = _run_command(
        [
            sys.executable,
            str(SUMMARY_VALIDATOR),
            "--verify",
            "--intent",
            intent.name,
            "--plan",
            plan.name,
            "--report",
            report.name,
            "--expected-intent-source-bytes",
            str(compiler_summary["intent_source_bytes"]),
            "--expected-intent-source-sha256",
            compiler_summary["intent_source_sha256"],
            "--expected-plan-source-bytes",
            str(compiler_summary["plan_source_bytes"]),
            "--expected-plan-source-sha256",
            compiler_summary["plan_source_sha256"],
        ],
        cwd=case,
        input_bytes=runner_stdout,
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise FixtureError(f"runner summary verification failed: {detail[:1024]}")
    summary = _parse_json(result.stdout, role="verified runner summary")
    expected = {
        "schema_version",
        "approved",
        "plan_sha256",
        "run_sha256",
        "failure_count",
        "report_bytes",
        "report_sha256",
    }
    if not isinstance(summary, dict) or set(summary) != expected:
        raise FixtureError("verified runner summary fields are not exact")
    for field in ("plan_sha256", "run_sha256", "report_sha256"):
        _validate_hash(summary[field], field)
    _validate_positive_int(summary["schema_version"], "schema_version")
    if summary["schema_version"] != SCHEMA_VERSION:
        raise FixtureError("verified runner summary schema version is invalid")
    if type(summary["approved"]) is not bool:
        raise FixtureError("verified runner summary approved must be a boolean")
    _validate_nonnegative_int(summary["failure_count"], "failure_count")
    _validate_positive_int(summary["report_bytes"], "report_bytes")
    _validate_report_shape(case, report, summary)
    return summary


def _validate_report_shape(case: Path, report: Path, summary: dict[str, Any]) -> None:
    payload = _read_stable(report, maximum=MAX_REPORT_BYTES, role="retained report")
    value = _parse_json(payload, role="retained report")
    expected_keys = {
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
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise FixtureError("retained report fields are not the closed schema-v1 shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
        or not isinstance(value["engine_version"], str)
    ):
        raise FixtureError("retained report schema or engine version is invalid")
    if value["plan_sha256"] != summary["plan_sha256"]:
        raise FixtureError("retained report plan identity differs from compact summary")
    if value["run_sha256"] != summary["run_sha256"]:
        raise FixtureError("retained report run identity differs from compact summary")
    if value["approved"] != summary["approved"]:
        raise FixtureError("retained report decision differs from compact summary")
    failures = value["failures"]
    if not isinstance(failures, list) or len(failures) != summary["failure_count"]:
        raise FixtureError("retained report failure count differs from compact summary")
    if value["approved"] != (len(failures) == 0):
        raise FixtureError("retained report approval is inconsistent with failures")
    _validate_hash(value["plan_source_sha256"], "retained plan source SHA-256")
    _validate_hash(value["plan_sha256"], "retained plan SHA-256")
    _validate_hash(value["run_sha256"], "retained run SHA-256")
    if value["approved"]:
        if not isinstance(value["binding"], dict) or value["binding"].get("approved") is not True:
            raise FixtureError("approved report does not contain an approved binding")
        if not isinstance(value["pipeline"], dict) or value["pipeline"].get("passed") is not True:
            raise FixtureError("approved report does not contain a passing pipeline")
    else:
        if not isinstance(value["binding"], dict) or value["binding"].get("approved") is not True:
            raise FixtureError("rejected fixture must preserve an approved binding")
        if not isinstance(value["pipeline"], dict) or value["pipeline"].get("passed") is not False:
            raise FixtureError("rejected fixture must contain a rejected pipeline")
        _validate_manufacturing_rejection(value)
    if len(payload) != summary["report_bytes"] or _sha256(payload) != summary["report_sha256"]:
        raise FixtureError("retained report bytes/SHA differ from compact summary")


def _validate_manufacturing_rejection(report: dict[str, Any]) -> None:
    """Require the negative fixture to fail only at the intended DFM binding."""

    expected_detail = (
        "invalid manufacturing package: factory package ZIP entry drc.rpt "
        "does not match manifest bytes/hash"
    )
    if report.get("failures") != [
        "pipeline: hardware pipeline gate rejected with 1 failure(s)"
    ]:
        raise FixtureError("rejected fixture has an unexpected top-level failure")
    pipeline = report["pipeline"]
    phases = pipeline.get("phases")
    expected_names = (
        "electrical-erc",
        "analysis-drc",
        "routing-quality",
        "manufacturing-package",
        "firmware-build",
    )
    if not isinstance(phases, list) or tuple(
        phase.get("name") if isinstance(phase, dict) else None for phase in phases
    ) != expected_names:
        raise FixtureError("rejected fixture pipeline phases are not exact")
    for phase in phases:
        name = phase["name"]
        if name == "manufacturing-package":
            if phase.get("passed") is not False or phase.get("failures") != [
                expected_detail
            ]:
                raise FixtureError(
                    "rejected fixture did not retain the intended manufacturing failure"
                )
        elif phase.get("passed") is not True or phase.get("failures") != []:
            raise FixtureError(
                f"rejected fixture unexpectedly failed the {name} phase"
            )
    if pipeline.get("failures") != [f"manufacturing-package: {expected_detail}"]:
        raise FixtureError("rejected fixture pipeline failure is not manufacturing-only")


def _validate_hash(value: Any, role: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise FixtureError(f"{role} must be lowercase hexadecimal SHA-256")


def _validate_positive_int(value: Any, role: str) -> None:
    if type(value) is not int or value <= 0:
        raise FixtureError(f"{role} must be a positive integer")


def _validate_nonnegative_int(value: Any, role: str) -> None:
    if type(value) is not int or value < 0:
        raise FixtureError(f"{role} must be a non-negative integer")


def _report_identity(case: Path, report: Path, summary: dict[str, Any]) -> dict[str, Any]:
    payload = _read_stable(report, maximum=MAX_REPORT_BYTES, role="retained report")
    if len(payload) != summary["report_bytes"] or _sha256(payload) != summary["report_sha256"]:
        raise FixtureError("retained report identity changed after verification")
    return {
        "schema_version": summary["schema_version"],
        "approved": summary["approved"],
        "failure_count": summary["failure_count"],
        "plan_sha256": summary["plan_sha256"],
        "run_sha256": summary["run_sha256"],
        "report_bytes": summary["report_bytes"],
        "report_sha256": summary["report_sha256"],
    }


def _run_case(
    pcbex: Path,
    case: Path,
    *,
    manufacturing_name: str,
    require_approved: bool,
    expected_exit: int | None,
    compiler_summary: dict[str, Any] | None = None,
    report_name: str | None = None,
    timeout_seconds: int,
    executable_identity: ExecutableIdentity | None = None,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    # A required-gate rerun must reuse the already authenticated intent/plan
    # and only publish a differently named report.  Recreating either input
    # would turn a valid no-clobber rerun into an accidental mutation.
    if compiler_summary is None:
        intent = _write_intent(case, manufacturing_name)
    else:
        intent = case / "intent.json"
        _read_stable(intent, maximum=MAX_SOURCE_BYTES, role="pipeline intent")
    plan = case / "plan.json"
    if plan.exists() or plan.is_symlink():
        if compiler_summary is None:
            raise FixtureError(f"existing plan requires compiler metadata: {plan}")
        _read_stable(plan, maximum=MAX_SOURCE_BYTES, role="compiled plan")
    else:
        if compiler_summary is not None:
            raise FixtureError(f"reused compiler metadata requires an existing plan: {plan}")
        compile_result = _run_command(
            [
                str(pcbex),
                "compile-deterministic-pipeline-plan",
                intent.name,
                "--output",
                plan.name,
                "--mcp-echo-plan-summary",
            ],
            cwd=case,
            timeout_seconds=timeout_seconds,
            executable_identity=executable_identity,
        )
        if compile_result.returncode != 0:
            raise FixtureError("deterministic pipeline plan compiler failed")
        fresh_compiler_summary = _verify_compiler(
            case, intent, plan, compile_result.stdout, timeout_seconds=timeout_seconds
        )
        if compiler_summary is None:
            compiler_summary = fresh_compiler_summary
        elif compiler_summary != fresh_compiler_summary:
            raise FixtureError("recompiled plan metadata differs from the retained compiler summary")
    report_name = report_name or ("report-required.json" if require_approved else "report.json")
    report = case / report_name
    runner_arguments = [
        str(pcbex),
        "run-deterministic-pipeline",
        plan.name,
        "--output",
        report.name,
        "--mcp-echo-report-summary",
    ]
    if require_approved:
        runner_arguments.append("--require-approved")
    runner_result = _run_command(
        runner_arguments,
        cwd=case,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    if expected_exit is None:
        if not 1 <= runner_result.returncode <= 255:
            raise FixtureError(
                "runner rejection exit code must be a nonzero byte-sized status"
            )
    elif runner_result.returncode != expected_exit:
        raise FixtureError(
            f"runner exit code {runner_result.returncode} did not match {expected_exit}"
        )
    if not report.exists() or report.is_symlink():
        raise FixtureError(f"runner did not retain a regular report: {report}")
    verified = _verify_runner(
        case,
        intent,
        plan,
        report,
        runner_result.stdout,
        compiler_summary,
        timeout_seconds=timeout_seconds,
    )
    return compiler_summary, _report_identity(case, report, verified), runner_result.returncode


def _scan_output_tree(root: Path) -> None:
    entries = 0
    total_bytes = 0
    for path in root.rglob("*"):
        entries += 1
        if entries > 4096:
            raise FixtureError("fixture output contains too many entries")
        relative = path.relative_to(root)
        if len(relative.parts) > 16:
            raise FixtureError("fixture output exceeds the depth limit")
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise FixtureError(f"fixture output contains a symlink: {relative}")
        if stat.S_ISREG(metadata.st_mode):
            total_bytes += metadata.st_size
            if total_bytes > 512 * 1024 * 1024:
                raise FixtureError("fixture output exceeds the aggregate byte limit")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise FixtureError(f"fixture output contains a special file: {relative}")


def _build_fixture(
    pcbex: Path,
    fixture_dir: Path,
    output_dir: Path,
    *,
    executable_identity: ExecutableIdentity,
    timeout_seconds: int,
) -> dict[str, Any]:
    _require_regular_directory(fixture_dir, "fixture directory")
    for name in FIXTURE_FILES:
        _read_stable(fixture_dir / name, maximum=MAX_SOURCE_BYTES, role=f"fixture {name}")
    _prepare_fresh_output(output_dir)
    accepted = output_dir / "accepted"
    rejected = output_dir / "rejected"
    accepted.mkdir()
    rejected.mkdir()
    _copy_fixture(fixture_dir, accepted)
    _copy_fixture(fixture_dir, rejected)

    version_result = _run_checked(
        pcbex,
        ["--version"],
        cwd=accepted,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    match = re.search(r"\b[0-9]+\.[0-9]+\.[0-9]+\b", version_result.stdout.decode("utf-8"))
    if match is None:
        raise FixtureError("pcbex --version did not return a semantic version")
    engine_version = match.group(0)

    _run_checked(
        pcbex,
        ["electrical-policy", "--output", "electrical-policy.json"],
        cwd=accepted,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    _run_checked(
        pcbex,
        [
            "check-schematic",
            "design.kicad_sch",
            "--policy",
            "electrical-policy.json",
            "--output",
            "electrical-review.json",
            "--require-approved",
        ],
        cwd=accepted,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    _run_checked(
        pcbex,
        [
            "analyze-kicad",
            "design.kicad_pcb",
            "--output-dir",
            "analysis",
            "--fail-on-violations",
        ],
        cwd=accepted,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    _run_checked(
        pcbex,
        [
            "generate-firmware",
            "design.kicad_sch",
            "--mcu-reference",
            "U1",
            "--output-dir",
            "firmware",
        ],
        cwd=accepted,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    _write_manufacturing_package(
        accepted / "manufacturing.zip", accepted / "design.kicad_pcb", engine_version=engine_version
    )
    # The rejected case shares the accepted deterministic evidence and differs
    # only in one manifest-bound ZIP entry.  This keeps the scenario small while
    # proving the downstream manufacturing phase, not circuit binding, rejects.
    for relative in ("electrical-policy.json", "electrical-review.json", "analysis", "firmware"):
        source = accepted / relative
        destination = rejected / relative
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            shutil.copyfile(source, destination)
    shutil.copyfile(accepted / "manufacturing.zip", rejected / "manufacturing.zip")
    _tamper_manufacturing_entry(
        rejected / "manufacturing.zip", rejected / "manufacturing-rejected.zip"
    )
    (rejected / "manufacturing.zip").unlink()

    accepted_meta, accepted_report, accepted_exit = _run_case(
        pcbex,
        accepted,
        manufacturing_name="manufacturing.zip",
        require_approved=True,
        expected_exit=0,
        report_name="report.json",
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    rejected_meta, rejected_report, rejected_normal_exit = _run_case(
        pcbex,
        rejected,
        manufacturing_name="manufacturing-rejected.zip",
        require_approved=False,
        expected_exit=0,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    _, required_report, required_exit = _run_case(
        pcbex,
        rejected,
        manufacturing_name="manufacturing-rejected.zip",
        require_approved=True,
        expected_exit=None,
        compiler_summary=rejected_meta,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    if rejected_normal_exit != 0 or not 1 <= required_exit <= 255:
        raise FixtureError("rejected runner exit-code contract was not met")
    if (
        rejected_report["report_bytes"] != required_report["report_bytes"]
        or rejected_report["report_sha256"] != required_report["report_sha256"]
    ):
        raise FixtureError("normal and require-approved rejected reports differ")
    if accepted_exit != 0:
        raise FixtureError("accepted require-approved runner did not exit successfully")

    summary = {
        "schema_version": SCHEMA_VERSION,
        "accepted": {
            "approved": accepted_report["approved"],
            "binding_approved": True,
            "pipeline_passed": True,
            "failure_count": accepted_report["failure_count"],
            "intent_source_bytes": accepted_meta["intent_source_bytes"],
            "intent_source_sha256": accepted_meta["intent_source_sha256"],
            "plan_source_bytes": accepted_meta["plan_source_bytes"],
            "plan_source_sha256": accepted_meta["plan_source_sha256"],
            "plan_sha256": accepted_report["plan_sha256"],
            "run_sha256": accepted_report["run_sha256"],
            "report_bytes": accepted_report["report_bytes"],
            "report_sha256": accepted_report["report_sha256"],
        },
        "rejected": {
            "approved": rejected_report["approved"],
            "binding_approved": True,
            "pipeline_passed": False,
            "failure_count": rejected_report["failure_count"],
            "intent_source_bytes": rejected_meta["intent_source_bytes"],
            "intent_source_sha256": rejected_meta["intent_source_sha256"],
            "plan_source_bytes": rejected_meta["plan_source_bytes"],
            "plan_source_sha256": rejected_meta["plan_source_sha256"],
            "plan_sha256": rejected_report["plan_sha256"],
            "run_sha256": rejected_report["run_sha256"],
            "report_bytes": rejected_report["report_bytes"],
            "report_sha256": rejected_report["report_sha256"],
            "required_exit_code": required_exit,
            "required_report_bytes": required_report["report_bytes"],
            "required_report_sha256": required_report["report_sha256"],
        },
    }
    _validate_summary(summary)
    _scan_output_tree(output_dir)
    summary_bytes = _canonical_json(summary)
    summary_path = output_dir / "summary.json"
    atomic_write_no_clobber(
        summary_path,
        summary_bytes,
        max_bytes=MAX_CHILD_STDOUT_BYTES,
    )
    return summary


def _validate_summary(summary: dict[str, Any]) -> None:
    if not isinstance(summary, dict) or set(summary) != {
        "schema_version",
        "accepted",
        "rejected",
    }:
        raise FixtureError("fixture summary fields are not closed")
    if (
        type(summary["schema_version"]) is not int
        or summary["schema_version"] != SCHEMA_VERSION
    ):
        raise FixtureError("fixture summary schema version is invalid")
    accepted = summary["accepted"]
    rejected = summary["rejected"]
    if not isinstance(accepted, dict) or not isinstance(rejected, dict):
        raise FixtureError("fixture summary case values must be objects")
    accepted_keys = {
        "approved",
        "binding_approved",
        "pipeline_passed",
        "failure_count",
        "intent_source_bytes",
        "intent_source_sha256",
        "plan_source_bytes",
        "plan_source_sha256",
        "plan_sha256",
        "run_sha256",
        "report_bytes",
        "report_sha256",
    }
    rejected_keys = accepted_keys | {
        "required_exit_code",
        "required_report_bytes",
        "required_report_sha256",
    }
    if set(accepted) != accepted_keys or set(rejected) != rejected_keys:
        raise FixtureError("fixture summary case fields are not closed")
    if accepted["approved"] is not True or accepted["binding_approved"] is not True:
        raise FixtureError("accepted summary decision is invalid")
    if (
        accepted["pipeline_passed"] is not True
        or type(accepted["failure_count"]) is not int
        or accepted["failure_count"] != 0
    ):
        raise FixtureError("accepted summary gate result is invalid")
    if rejected["approved"] is not False or rejected["binding_approved"] is not True:
        raise FixtureError("rejected summary decision is invalid")
    if (
        rejected["pipeline_passed"] is not False
        or type(rejected["failure_count"]) is not int
        or rejected["failure_count"] <= 0
    ):
        raise FixtureError("rejected summary gate result is invalid")
    if (
        type(rejected["required_exit_code"]) is not int
        or not 1 <= rejected["required_exit_code"] <= 255
    ):
        raise FixtureError("rejected require-approved exit code is invalid")
    for value in (accepted, rejected):
        for field in (
            "intent_source_bytes",
            "plan_source_bytes",
            "report_bytes",
        ):
            _validate_positive_int(value[field], field)
        for field in (
            "intent_source_sha256",
            "plan_source_sha256",
            "plan_sha256",
            "run_sha256",
            "report_sha256",
        ):
            _validate_hash(value[field], field)
    _validate_positive_int(rejected["required_report_bytes"], "required report bytes")
    _validate_hash(rejected["required_report_sha256"], "required report SHA-256")
    if (
        rejected["report_bytes"] != rejected["required_report_bytes"]
        or rejected["report_sha256"] != rejected["required_report_sha256"]
    ):
        raise FixtureError("rejected report identities are not byte-identical")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcbex", required=True, help="explicit pcbex executable path")
    parser.add_argument("--fixture-dir", required=True, help="checked-in three-file fixture directory")
    parser.add_argument("--output-dir", required=True, help="fresh output directory")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=600,
        help="per-child timeout (the CI supervisor should apply an outer bound too)",
    )
    return parser


def _resolve_pcbex(raw: str) -> tuple[Path, ExecutableIdentity]:
    """Resolve the executable before any case changes cwd and pin its identity."""

    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    _reject_symlink_components(candidate, "--pcbex")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise FixtureError(f"could not inspect --pcbex: {error}") from error
    return resolved, _executable_identity(resolved)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        timeout_seconds = args.timeout_seconds
        if timeout_seconds < 1 or timeout_seconds > MAX_CHILD_TIMEOUT_SECONDS:
            raise FixtureError("--timeout-seconds must be between 1 and 600")
        pcbex, executable_identity = _resolve_pcbex(args.pcbex)
        fixture_dir = Path(args.fixture_dir)
        output_dir = Path(args.output_dir)
        summary = _build_fixture(
            pcbex,
            fixture_dir,
            output_dir,
            executable_identity=executable_identity,
            timeout_seconds=timeout_seconds,
        )
        encoded = _canonical_json(summary)
        if len(encoded) > MAX_CHILD_STDOUT_BYTES:
            raise FixtureError("fixture summary exceeds its stdout bound")
        sys.stdout.buffer.write(encoded)
        return 0
    except (FixtureError, OSError, ValueError) as error:
        print(f"deterministic pipeline CI fixture failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

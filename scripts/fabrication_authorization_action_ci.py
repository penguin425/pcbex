#!/usr/bin/env python3
"""Build one real factory-bound fixture for the focused authorization Action.

The checked-in fixture contributes only a small circuit, schematic, and routed
board.  This helper creates the final policy, analysis, firmware, manufacturing
ZIP, factory receipt, factory-required plan/report, and two signed approvals at
runtime.  Private signing keys exist only in a private temporary directory and
are removed before the closed fixture summary is published.

Every pcbex child runs through the shared bounded CI process supervisor.  The
selected release binary is identity-pinned before and after each invocation by
``deterministic_pipeline_ci``, whose small manufacturing-package constructor is
also shared so this smoke and the deterministic-pipeline portability smoke use
the same validated archive shape.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import deterministic_pipeline_ci as pipeline_fixture  # noqa: E402


SCHEMA_VERSION = 1
MAX_CHILD_TIMEOUT_SECONDS = 600
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_POLICY_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024 * 1024
MAX_APPROVAL_BYTES = 1024 * 1024
AUTHORIZATION_ID = "action-fabrication-release"
CHALLENGE = "ab" * 32
QUANTITY = 25
CURRENCY = "USD"
MAXIMUM_TOTAL_MINOR_UNITS = 125_000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class FixtureError(RuntimeError):
    """A bounded fixture-generation or evidence-validation failure."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read(path: Path, *, maximum: int, role: str) -> bytes:
    try:
        return pipeline_fixture._read_stable(path, maximum=maximum, role=role)
    except pipeline_fixture.FixtureError as error:
        raise FixtureError(str(error)) from error


def _read_json(path: Path, *, maximum: int, role: str) -> Any:
    payload = _read(path, maximum=maximum, role=role)
    try:
        return pipeline_fixture._parse_json(payload, role=role)
    except pipeline_fixture.FixtureError as error:
        raise FixtureError(str(error)) from error


def _write_json(path: Path, value: Any) -> None:
    try:
        pipeline_fixture._write_json(path, value)
    except pipeline_fixture.FixtureError as error:
        raise FixtureError(str(error)) from error


def _run_checked(
    pcbex: Path,
    arguments: Iterable[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    executable_identity: pipeline_fixture.ExecutableIdentity,
) -> pipeline_fixture.ChildResult:
    try:
        return pipeline_fixture._run_checked(
            pcbex,
            arguments,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            executable_identity=executable_identity,
        )
    except pipeline_fixture.FixtureError as error:
        raise FixtureError(str(error)) from error


def _descriptor(root: Path, path: Path) -> dict[str, Any]:
    payload = _read(path, maximum=MAX_REPORT_BYTES, role=f"plan input {path.name}")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise FixtureError(f"plan input is outside the fixture root: {path}") from error
    return {"path": relative, "bytes": len(payload), "sha256": _sha256(payload)}


def _require_hash(value: Any, role: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise FixtureError(f"{role} must be lowercase hexadecimal SHA-256")
    return value


def _require_private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FixtureError(f"could not inspect private signing key: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise FixtureError("private signing key must be a regular non-link file")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise FixtureError("private signing key permissions are not private")


def _generate_keypair(
    pcbex: Path,
    private_directory: Path,
    signer: str,
    *,
    cwd: Path,
    timeout_seconds: int,
    executable_identity: pipeline_fixture.ExecutableIdentity,
) -> tuple[Path, str]:
    private_key = private_directory / f"{signer}.key"
    public_key = private_directory / f"{signer}.pub"
    _run_checked(
        pcbex,
        [
            "approval-keygen",
            "--private-key",
            str(private_key),
            "--public-key",
            str(public_key),
        ],
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    _require_private_file(private_key)
    public_source = _read(
        public_key,
        maximum=MAX_SOURCE_BYTES,
        role=f"{signer} public key",
    )
    try:
        public = public_source.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise FixtureError(f"{signer} public key is not ASCII") from error
    _require_hash(public, f"{signer} public key")
    return private_key, public


def _factory_receipt(package: bytes) -> dict[str, Any]:
    response = {
        "status": "accepted",
        "accepted": True,
        "dfm_passed": True,
        "quote": {"currency": "USD", "total": 1.0},
        "findings": [],
    }
    response_bytes = json.dumps(
        response,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    package_sha256 = _sha256(package)
    return {
        "schema_version": 1,
        "adapter": "generic-factory-http-v1",
        "provider": "generic",
        "endpoint": "https://factory.example/quote",
        "package_sha256": package_sha256,
        "package_bytes": len(package),
        "request_sha256": package_sha256,
        "response_sha256": _sha256(response_bytes),
        "response_bytes": len(response_bytes),
        "http_status": 200,
        "status": "accepted",
        "accepted": True,
        "dfm_passed": True,
        "quote": {"currency": "USD", "total": 1.0},
        "findings": [],
        "response": response,
    }


def _validate_pipeline_report(
    report_path: Path,
    *,
    plan_path: Path,
    package_path: Path,
    receipt_path: Path,
    policy_path: Path,
) -> dict[str, Any]:
    report = _read_json(
        report_path,
        maximum=MAX_REPORT_BYTES,
        role="factory-required deterministic pipeline report",
    )
    if not isinstance(report, dict):
        raise FixtureError("factory-required pipeline report must be an object")
    if report.get("schema_version") != 1 or report.get("approved") is not True:
        raise FixtureError("factory-required pipeline report is not approved schema v1")
    pipeline = report.get("pipeline")
    if (
        not isinstance(pipeline, dict)
        or pipeline.get("schema_version") != 2
        or pipeline.get("passed") is not True
        or pipeline.get("failures") != []
    ):
        raise FixtureError("factory-required pipeline did not retain a passing v2 gate")
    if report.get("failures") != []:
        raise FixtureError("approved factory-required pipeline retained failures")
    _require_hash(report.get("plan_sha256"), "pipeline plan SHA-256")
    _require_hash(report.get("run_sha256"), "pipeline run SHA-256")

    input_evidence = report.get("input_evidence")
    if not isinstance(input_evidence, list):
        raise FixtureError("factory-required pipeline input evidence is missing")
    evidence_by_role = {
        evidence.get("role"): evidence
        for evidence in input_evidence
        if isinstance(evidence, dict) and isinstance(evidence.get("role"), str)
    }
    expected = {
        "manufacturing_package": package_path,
        "factory_receipt": receipt_path,
        "analysis_policy_pack": policy_path,
    }
    for role, path in expected.items():
        evidence = evidence_by_role.get(role)
        payload = _read(path, maximum=MAX_REPORT_BYTES, role=role)
        if (
            not isinstance(evidence, dict)
            or evidence.get("bytes") != len(payload)
            or evidence.get("sha256") != _sha256(payload)
        ):
            raise FixtureError(f"pipeline report does not bind exact {role} bytes")

    plan_source = _read(
        plan_path,
        maximum=MAX_SOURCE_BYTES,
        role="factory-required plan",
    )
    if report.get("plan_source_bytes") != len(plan_source):
        raise FixtureError("pipeline report plan byte count is inconsistent")
    if report.get("plan_source_sha256") != _sha256(plan_source):
        raise FixtureError("pipeline report plan source digest is inconsistent")
    return report


def _sign_approval(
    pcbex: Path,
    root: Path,
    private_key: Path,
    signer: str,
    *,
    valid_from_unix: int,
    expires_at_unix: int,
    timeout_seconds: int,
    executable_identity: pipeline_fixture.ExecutableIdentity,
) -> Path:
    suffix = signer.removeprefix("fabrication-")
    output = root / f"approval-{suffix}.json"
    _run_checked(
        pcbex,
        [
            "sign-fabrication-approval",
            "factory-required-plan.json",
            "--report",
            "factory-required-report.json",
            "--manufacturing-package",
            "manufacturing.zip",
            "--factory-receipt",
            "factory-receipt.json",
            "--policy-pack",
            "final-policy-pack.json",
            "--private-key",
            str(private_key),
            "--signer-id",
            signer,
            "--decision",
            "approve",
            "--authorization-id",
            AUTHORIZATION_ID,
            "--challenge",
            CHALLENGE,
            "--quantity",
            str(QUANTITY),
            "--currency",
            CURRENCY,
            "--maximum-total-minor-units",
            str(MAXIMUM_TOTAL_MINOR_UNITS),
            "--valid-from-unix",
            str(valid_from_unix),
            "--expires-at-unix",
            str(expires_at_unix),
            "--reason",
            f"Independent CI decision by {signer}",
            "--ticket",
            f"PCBEX-ACTION-{suffix.upper()}",
            "--output",
            output.name,
        ],
        cwd=root,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    return output


def _validate_approvals(
    approvals: list[Path],
    *,
    plan_sha256: str,
    run_sha256: str,
    package_sha256: str,
    receipt_sha256: str,
    policy_sha256: str,
    valid_from_unix: int,
    expires_at_unix: int,
) -> None:
    parsed = [
        _read_json(
            path,
            maximum=MAX_APPROVAL_BYTES,
            role=f"signed approval {path.name}",
        )
        for path in approvals
    ]
    if any(not isinstance(approval, dict) for approval in parsed):
        raise FixtureError("signed fabrication approvals must be objects")
    if [approval.get("signer_id") for approval in parsed] != [
        "fabrication-a",
        "fabrication-b",
    ]:
        raise FixtureError("signed fabrication approval identities are not exact")
    if parsed[0].get("scope") != parsed[1].get("scope"):
        raise FixtureError("signed fabrication approvals do not share one scope")
    if parsed[0].get("evidence") != parsed[1].get("evidence"):
        raise FixtureError("signed fabrication approvals do not share one evidence set")
    expected_scope = {
        "authorization_id": AUTHORIZATION_ID,
        "challenge": CHALLENGE,
        "quantity": QUANTITY,
        "currency": CURRENCY,
        "maximum_total_minor_units": MAXIMUM_TOTAL_MINOR_UNITS,
        "valid_from_unix": valid_from_unix,
        "expires_at_unix": expires_at_unix,
    }
    if parsed[0].get("scope") != expected_scope:
        raise FixtureError("signed fabrication approval scope is not exact")
    evidence = parsed[0].get("evidence")
    if not isinstance(evidence, dict):
        raise FixtureError("signed fabrication approval evidence is missing")
    pipeline = evidence.get("pipeline")
    factory_receipt = evidence.get("factory_receipt")
    policy_pack = evidence.get("policy_pack")
    manufacturing_package = evidence.get("manufacturing_package")
    if (
        not isinstance(pipeline, dict)
        or pipeline.get("plan_sha256") != plan_sha256
        or pipeline.get("run_sha256") != run_sha256
        or not isinstance(manufacturing_package, dict)
        or manufacturing_package.get("sha256") != package_sha256
        or not isinstance(factory_receipt, dict)
        or not isinstance(factory_receipt.get("receipt"), dict)
        or factory_receipt["receipt"].get("sha256") != receipt_sha256
        or factory_receipt.get("quote_authenticity_verified") is not False
        or not isinstance(policy_pack, dict)
        or not isinstance(policy_pack.get("source"), dict)
        or policy_pack["source"].get("sha256") != policy_sha256
    ):
        raise FixtureError(
            "signed fabrication approval evidence identities are not exact"
        )
    for approval in parsed:
        if (
            approval.get("schema_version") != 1
            or approval.get("decision") != "approve"
            or approval.get("algorithm") != "ed25519"
            or not isinstance(approval.get("signature"), str)
            or re.fullmatch(r"[0-9a-f]{128}", approval["signature"]) is None
        ):
            raise FixtureError("signed fabrication approval envelope is invalid")


def _validate_summary(summary: dict[str, Any]) -> None:
    expected_fields = {
        "schema_version",
        "pipeline_approved",
        "factory_required",
        "plan",
        "retained_report",
        "manufacturing_package",
        "factory_receipt",
        "policy_pack",
        "approvals",
        "authorization_id",
        "challenge",
        "quantity",
        "currency",
        "maximum_total_minor_units",
        "valid_from_unix",
        "expires_at_unix",
        "plan_sha256",
        "run_sha256",
        "retained_report_bytes",
        "retained_report_sha256",
        "manufacturing_package_sha256",
        "factory_receipt_sha256",
        "policy_pack_sha256",
    }
    if set(summary) != expected_fields:
        raise FixtureError("fabrication authorization fixture summary is not closed")
    if (
        summary["schema_version"] != SCHEMA_VERSION
        or summary["pipeline_approved"] is not True
        or summary["factory_required"] is not True
        or summary["approvals"] != ["approval-a.json", "approval-b.json"]
        or summary["authorization_id"] != AUTHORIZATION_ID
        or summary["challenge"] != CHALLENGE
        or summary["quantity"] != QUANTITY
        or summary["currency"] != CURRENCY
        or summary["maximum_total_minor_units"] != MAXIMUM_TOTAL_MINOR_UNITS
    ):
        raise FixtureError(
            "fabrication authorization fixture summary values are invalid"
        )
    for field in (
        "plan_sha256",
        "run_sha256",
        "retained_report_sha256",
        "manufacturing_package_sha256",
        "factory_receipt_sha256",
        "policy_pack_sha256",
    ):
        _require_hash(summary[field], field)
    for field in (
        "valid_from_unix",
        "expires_at_unix",
        "retained_report_bytes",
    ):
        if type(summary[field]) is not int or summary[field] <= 0:
            raise FixtureError(f"fixture summary {field} must be a positive integer")
    if summary["expires_at_unix"] <= summary["valid_from_unix"]:
        raise FixtureError("fixture summary authorization window is invalid")


def _build_fixture(
    pcbex: Path,
    fixture_dir: Path,
    policy_template: Path,
    output_dir: Path,
    *,
    timeout_seconds: int,
    executable_identity: pipeline_fixture.ExecutableIdentity,
) -> dict[str, Any]:
    try:
        pipeline_fixture._require_regular_directory(fixture_dir, "fixture directory")
        pipeline_fixture._prepare_fresh_output(output_dir)
        pipeline_fixture._copy_fixture(fixture_dir, output_dir)
    except pipeline_fixture.FixtureError as error:
        raise FixtureError(str(error)) from error
    policy_template_value = _read_json(
        policy_template,
        maximum=MAX_POLICY_BYTES,
        role="policy template",
    )
    if not isinstance(policy_template_value, dict):
        raise FixtureError("policy template must be an object")

    version_result = _run_checked(
        pcbex,
        ["--version"],
        cwd=output_dir,
        timeout_seconds=timeout_seconds,
        executable_identity=executable_identity,
    )
    version_match = re.search(
        r"\b[0-9]+\.[0-9]+\.[0-9]+\b",
        version_result.stdout.decode("utf-8", errors="strict"),
    )
    if version_match is None:
        raise FixtureError("pcbex --version did not return a semantic version")
    engine_version = version_match.group(0)

    with tempfile.TemporaryDirectory(
        prefix="pcbex-fabrication-authorization-"
    ) as temporary:
        private_directory = Path(temporary)
        if os.name == "posix":
            private_directory.chmod(0o700)
        private_a, public_a = _generate_keypair(
            pcbex,
            private_directory,
            "fabrication-a",
            cwd=output_dir,
            timeout_seconds=timeout_seconds,
            executable_identity=executable_identity,
        )
        private_b, public_b = _generate_keypair(
            pcbex,
            private_directory,
            "fabrication-b",
            cwd=output_dir,
            timeout_seconds=timeout_seconds,
            executable_identity=executable_identity,
        )

        candidate_policy = dict(policy_template_value)
        candidate_policy["fabrication_authorization_policy"] = {
            "minimum_approvals": 2,
            "maximum_validity_seconds": 7_200,
            "trusted_keys": [
                {"signer_id": "fabrication-a", "public_key": public_a},
                {"signer_id": "fabrication-b", "public_key": public_b},
            ],
        }
        _write_json(output_dir / "policy-candidate.json", candidate_policy)
        _run_checked(
            pcbex,
            [
                "validate-policy-pack",
                "policy-candidate.json",
                "--output",
                "final-policy-pack.json",
            ],
            cwd=output_dir,
            timeout_seconds=timeout_seconds,
            executable_identity=executable_identity,
        )

        _run_checked(
            pcbex,
            ["electrical-policy", "--output", "electrical-policy.json"],
            cwd=output_dir,
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
            cwd=output_dir,
            timeout_seconds=timeout_seconds,
            executable_identity=executable_identity,
        )
        _run_checked(
            pcbex,
            [
                "analyze-kicad",
                "design.kicad_pcb",
                "--policy-pack",
                "final-policy-pack.json",
                "--output-dir",
                "analysis",
                "--fail-on-violations",
            ],
            cwd=output_dir,
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
                *pipeline_fixture._firmware_compiler_arguments(),
                "--output-dir",
                "firmware",
            ],
            cwd=output_dir,
            timeout_seconds=timeout_seconds,
            executable_identity=executable_identity,
        )

        package_path = output_dir / "manufacturing.zip"
        try:
            pipeline_fixture._write_manufacturing_package(
                package_path,
                output_dir / "design.kicad_pcb",
                engine_version=engine_version,
            )
        except pipeline_fixture.FixtureError as error:
            raise FixtureError(str(error)) from error
        package_source = _read(
            package_path,
            maximum=MAX_REPORT_BYTES,
            role="manufacturing package",
        )
        receipt_path = output_dir / "factory-receipt.json"
        _write_json(receipt_path, _factory_receipt(package_source))

        plan_path = output_dir / "factory-required-plan.json"
        plan = {
            "schema_version": 1,
            "circuit_spec": _descriptor(
                output_dir, output_dir / "circuit-spec-v2.json"
            ),
            "schematic": _descriptor(output_dir, output_dir / "design.kicad_sch"),
            "electrical_policy": _descriptor(
                output_dir, output_dir / "electrical-policy.json"
            ),
            "electrical_review": _descriptor(
                output_dir, output_dir / "electrical-review.json"
            ),
            "board": _descriptor(output_dir, output_dir / "design.kicad_pcb"),
            "analysis_manifest": _descriptor(
                output_dir, output_dir / "analysis/run.json"
            ),
            "analysis_checks": _descriptor(
                output_dir, output_dir / "analysis/checks.json"
            ),
            "quality": _descriptor(output_dir, output_dir / "analysis/quality.json"),
            "analysis_project": None,
            "analysis_rules": None,
            "analysis_dfm_profile": None,
            "analysis_policy_pack": _descriptor(
                output_dir, output_dir / "final-policy-pack.json"
            ),
            "analysis_physical_profile": None,
            "manufacturing_package": _descriptor(output_dir, package_path),
            "firmware_manifest": _descriptor(
                output_dir, output_dir / "firmware/manifest.json"
            ),
            "factory_receipt": _descriptor(output_dir, receipt_path),
            "require_factory": True,
        }
        _write_json(plan_path, plan)
        report_path = output_dir / "factory-required-report.json"
        _run_checked(
            pcbex,
            [
                "run-deterministic-pipeline",
                plan_path.name,
                "--output",
                report_path.name,
                "--require-approved",
            ],
            cwd=output_dir,
            timeout_seconds=timeout_seconds,
            executable_identity=executable_identity,
        )
        report = _validate_pipeline_report(
            report_path,
            plan_path=plan_path,
            package_path=package_path,
            receipt_path=receipt_path,
            policy_path=output_dir / "final-policy-pack.json",
        )

        now = int(time.time())
        valid_from_unix = max(1, now - 60)
        expires_at_unix = now + 3_600
        approvals = [
            _sign_approval(
                pcbex,
                output_dir,
                private_a,
                "fabrication-a",
                valid_from_unix=valid_from_unix,
                expires_at_unix=expires_at_unix,
                timeout_seconds=timeout_seconds,
                executable_identity=executable_identity,
            ),
            _sign_approval(
                pcbex,
                output_dir,
                private_b,
                "fabrication-b",
                valid_from_unix=valid_from_unix,
                expires_at_unix=expires_at_unix,
                timeout_seconds=timeout_seconds,
                executable_identity=executable_identity,
            ),
        ]

        report_source = _read(
            report_path,
            maximum=MAX_REPORT_BYTES,
            role="factory-required pipeline report",
        )
        receipt_source = _read(
            receipt_path,
            maximum=MAX_REPORT_BYTES,
            role="factory receipt",
        )
        policy_source = _read(
            output_dir / "final-policy-pack.json",
            maximum=MAX_POLICY_BYTES,
            role="final policy pack",
        )
        plan_sha256 = _require_hash(report.get("plan_sha256"), "plan SHA-256")
        run_sha256 = _require_hash(report.get("run_sha256"), "run SHA-256")
        _validate_approvals(
            approvals,
            plan_sha256=plan_sha256,
            run_sha256=run_sha256,
            package_sha256=_sha256(package_source),
            receipt_sha256=_sha256(receipt_source),
            policy_sha256=_sha256(policy_source),
            valid_from_unix=valid_from_unix,
            expires_at_unix=expires_at_unix,
        )

    # The private temporary directory and both signing keys are gone before
    # any fixture summary is retained or emitted.
    summary = {
        "schema_version": SCHEMA_VERSION,
        "pipeline_approved": True,
        "factory_required": True,
        "plan": "factory-required-plan.json",
        "retained_report": "factory-required-report.json",
        "manufacturing_package": "manufacturing.zip",
        "factory_receipt": "factory-receipt.json",
        "policy_pack": "final-policy-pack.json",
        "approvals": [path.name for path in approvals],
        "authorization_id": AUTHORIZATION_ID,
        "challenge": CHALLENGE,
        "quantity": QUANTITY,
        "currency": CURRENCY,
        "maximum_total_minor_units": MAXIMUM_TOTAL_MINOR_UNITS,
        "valid_from_unix": valid_from_unix,
        "expires_at_unix": expires_at_unix,
        "plan_sha256": plan_sha256,
        "run_sha256": run_sha256,
        "retained_report_bytes": len(report_source),
        "retained_report_sha256": _sha256(report_source),
        "manufacturing_package_sha256": _sha256(package_source),
        "factory_receipt_sha256": _sha256(receipt_source),
        "policy_pack_sha256": _sha256(policy_source),
    }
    _validate_summary(summary)
    _write_json(output_dir / "fixture-summary.json", summary)
    try:
        pipeline_fixture._scan_output_tree(output_dir)
    except pipeline_fixture.FixtureError as error:
        raise FixtureError(str(error)) from error
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcbex", required=True, help="explicit pcbex executable path")
    parser.add_argument(
        "--fixture-dir",
        required=True,
        help="checked-in circuit/schematic/board fixture directory",
    )
    parser.add_argument(
        "--policy-template",
        required=True,
        help="closed organization policy pack used as the runtime template",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="fresh fixture output directory",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="per-child timeout (the CI supervisor applies a longer outer bound)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not 1 <= args.timeout_seconds <= MAX_CHILD_TIMEOUT_SECONDS:
            raise FixtureError("--timeout-seconds must be between 1 and 600")
        try:
            pcbex, executable_identity = pipeline_fixture._resolve_pcbex(args.pcbex)
        except pipeline_fixture.FixtureError as error:
            raise FixtureError(str(error)) from error
        summary = _build_fixture(
            pcbex,
            Path(args.fixture_dir),
            Path(args.policy_template),
            Path(args.output_dir),
            timeout_seconds=args.timeout_seconds,
            executable_identity=executable_identity,
        )
        encoded = pipeline_fixture._canonical_json(summary)
        if len(encoded) > pipeline_fixture.MAX_CHILD_STDOUT_BYTES:
            raise FixtureError("fixture summary exceeds its stdout bound")
        sys.stdout.buffer.write(encoded)
        return 0
    except (FixtureError, OSError, ValueError) as error:
        print(
            f"fabrication authorization Action fixture failed: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

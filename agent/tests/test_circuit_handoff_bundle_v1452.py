from __future__ import annotations

import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent.tests.test_circuit_handoff_bundle_v1448 import (
    _bundle,
    _render,
    _replace_native_check,
    _spec,
)
from agent.tests.test_circuit_handoff_bundle_v1449 import _archive_entries
from agent.tests.test_circuit_handoff_bundle_v1450 import _valid_archive_with_command
from agent.tests.test_circuit_handoff_bundle_v1451 import (
    _retained_report,
    _write_native_wrapper,
)
from pcbex_agent import cli
from pcbex_agent import circuit_handoff_bundle as handoff_module
from pcbex_agent.circuit_handoff_bundle import (
    CircuitHandoffBundleError,
    circuit_handoff_bundle_ai_quorum_replay_result_json_schema,
    circuit_handoff_bundle_native_erc_replay_result_json_schema,
    circuit_handoff_bundle_replay_result_json_schema,
    handoff_circuit_generation,
    replay_circuit_handoff_bundle,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _member(
    index: int,
    *,
    approved: bool = True,
    provider: str | None = None,
    model: str | None = None,
) -> dict[str, object]:
    return {
        "signer_id": f"reviewer-{index}",
        "public_key": f"{index + 10:064x}",
        "response_sha256": f"{index + 100:064x}",
        "provider": provider or f"provider-{index}",
        "model": model or f"model-{index}",
        "version": "1",
        "approved": approved,
        "gate_failures": [] if approved else ["response_decision_not_approve"],
    }


def _quorum_report(
    request_sha256: str,
    members: list[dict[str, object]],
    *,
    minimum_approvals: int = 2,
    minimum_distinct_providers: int = 2,
    minimum_distinct_models: int = 2,
) -> dict[str, object]:
    approved = [member for member in members if member["approved"]]
    providers = {
        str(member["provider"]).strip().lower() for member in approved
    }
    models = {
        f"{str(member['provider']).strip().lower()}/"
        f"{str(member['model']).strip().lower()}@"
        f"{str(member['version']).strip().lower() if member['version'] is not None else '-'}"
        for member in approved
    }
    counts = {
        "members": len(members),
        "approvals": len(approved),
        "rejections": len(members) - len(approved),
        "distinct_providers": len(providers),
        "distinct_models": len(models),
    }
    policy = {
        "minimum_approvals": minimum_approvals,
        "minimum_distinct_providers": minimum_distinct_providers,
        "minimum_distinct_models": minimum_distinct_models,
    }
    failures = []
    for label, required, actual in (
        ("insufficient_approvals", minimum_approvals, counts["approvals"]),
        (
            "insufficient_distinct_providers",
            minimum_distinct_providers,
            counts["distinct_providers"],
        ),
        (
            "insufficient_distinct_models",
            minimum_distinct_models,
            counts["distinct_models"],
        ),
    ):
        if actual < required:
            failures.append(f"{label}:required={required}:actual={actual}")
    return {
        "schema_version": 1,
        "request_sha256": request_sha256,
        "policy": policy,
        "counts": counts,
        "members": members,
        "quorum_met": not failures,
        "quorum_failures": failures,
    }


def _write_ai_wrapper(
    root: Path,
    base_command: list[str],
    report_raw: bytes,
    **configuration: object,
) -> list[str]:
    (root / "ai-base-command.json").write_text(
        json.dumps(base_command),
        encoding="utf-8",
    )
    (root / "ai-configuration.json").write_text(
        json.dumps(configuration),
        encoding="utf-8",
    )
    (root / "ai-emitted-report.bin").write_bytes(report_raw)
    wrapper = root / "fake_pcbex_ai.py"
    wrapper.write_text(
        """from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

root = Path(__file__).parent
base = json.loads((root / "ai-base-command.json").read_text(encoding="utf-8"))
configuration = json.loads(
    (root / "ai-configuration.json").read_text(encoding="utf-8")
)
if sys.argv[1] != "verify-ai-quorum":
    completed = subprocess.run([*base, *sys.argv[1:]], check=False)
    raise SystemExit(completed.returncode)

(root / "ai-invocation.json").write_text(
    json.dumps(sys.argv[1:]),
    encoding="utf-8",
)
time.sleep(float(configuration.get("sleep_seconds", 0)))
arguments = sys.argv[2:]
schematic_path = Path(
    next(value.split("=", 1)[1] for value in arguments if value.startswith("--schematic="))
)
request_path = Path(arguments[-1])
request = json.loads(request_path.read_bytes())
expected_schematic_sha256 = request.get("test_source_sha256")
if expected_schematic_sha256 is not None:
    observed = hashlib.sha256(schematic_path.read_bytes()).hexdigest()
    if observed != expected_schematic_sha256:
        raise SystemExit(7)

def option_path(prefix: str) -> Path:
    return Path(next(value.split("=", 1)[1] for value in arguments if value.startswith(prefix)))

staged_kind = configuration.get("mutate_staged")
if staged_kind:
    staged = {
        "schematic": schematic_path,
        "request": request_path,
        "policy": option_path("--policy-pack="),
        "approval": option_path("--approval="),
        "response": option_path("--response="),
    }[staged_kind]
    staged.write_bytes(b"changed staged input\\n")
caller_path = configuration.get("mutate_caller")
if caller_path:
    Path(caller_path).write_bytes(b"changed caller input\\n")

if configuration.get("write_report", True):
    output_path = option_path("--output=")
    output_path.write_bytes((root / "ai-emitted-report.bin").read_bytes())
stdout = configuration.get("stdout", "")
if stdout:
    print(stdout, end="")
raise SystemExit(int(configuration.get("exit_code", 0)))
""",
        encoding="utf-8",
    )
    return [sys.executable, str(wrapper)]


def _write_ai_inputs(
    root: Path,
    schematic_raw: bytes,
    *,
    members: list[dict[str, object]] | None = None,
    minimum_approvals: int = 2,
    minimum_distinct_providers: int = 2,
    minimum_distinct_models: int = 2,
) -> tuple[dict[str, object], bytes, dict[str, object]]:
    request_sha256 = "1" * 64
    request_raw = _render(
        {
            "schema_version": 1,
            "request_sha256": request_sha256,
            "test_source_sha256": _sha(schematic_raw),
        }
    )
    policy_raw = _render({"schema_version": 1, "id": "test-policy"})
    actual_members = members or [_member(0), _member(1)]
    report_value = _quorum_report(
        request_sha256,
        actual_members,
        minimum_approvals=minimum_approvals,
        minimum_distinct_providers=minimum_distinct_providers,
        minimum_distinct_models=minimum_distinct_models,
    )
    report_raw = json.dumps(report_value, indent=2).encode("utf-8")

    request = root / "ai request.json"
    policy = root / "ai policy.json"
    report = root / "ai quorum.json"
    request.write_bytes(request_raw)
    policy.write_bytes(policy_raw)
    report.write_bytes(report_raw)
    approvals: list[Path] = []
    responses: list[Path] = []
    approval_raws: list[bytes] = []
    response_raws: list[bytes] = []
    for index, member in enumerate(actual_members):
        approval_raw = _render(
            {"schema_version": 1, "signer_id": member["signer_id"]}
        )
        response_raw = _render(
            {
                "schema_version": 1,
                "model": {
                    "provider": member["provider"],
                    "model": member["model"],
                    "version": member["version"],
                },
            }
        )
        approval = root / f"approval {index}.json"
        response = root / f"response {index}.json"
        approval.write_bytes(approval_raw)
        response.write_bytes(response_raw)
        approvals.append(approval)
        responses.append(response)
        approval_raws.append(approval_raw)
        response_raws.append(response_raw)

    options: dict[str, object] = {
        "retained_ai_quorum_report": report,
        "ai_review_request": request,
        "ai_policy_pack": policy,
        "ai_approvals": approvals,
        "ai_responses": responses,
        "minimum_ai_approvals": minimum_approvals,
        "minimum_distinct_ai_providers": minimum_distinct_providers,
        "minimum_distinct_ai_models": minimum_distinct_models,
    }
    raw = {
        "request": request_raw,
        "policy": policy_raw,
        "report": report_raw,
        "approvals": approval_raws,
        "responses": response_raws,
    }
    return options, report_raw, raw


class CircuitHandoffBundleV1452Tests(unittest.TestCase):
    def test_ai_only_replay_returns_closed_path_free_v3_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            options, report_raw, source_raws = _write_ai_inputs(root, schematic_raw)
            command = _write_ai_wrapper(root, base, report_raw)

            result = replay_circuit_handoff_bundle(
                archive,
                command,
                **options,
                require_ai_quorum=True,
                timeout_seconds=30,
                expected_archive_sha256=_sha(archive_raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )
            invocation = json.loads(
                (root / "ai-invocation.json").read_text(encoding="utf-8")
            )
            root_text = str(root)

        self.assertEqual(result["schema_version"], 3)
        self.assertEqual(
            result["verification_scope"],
            handoff_module.CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_SCOPE,
        )
        self.assertTrue(result["validation"]["ai_schematic_quorum_replayed"])
        self.assertFalse(result["validation"]["native_kicad_erc_replayed"])
        self.assertNotIn("native_kicad_erc", result)
        evidence = result["ai_schematic_quorum"]
        self.assertEqual(
            evidence,
            {
                "schema_version": 1,
                "quorum_met": True,
                "quorum_required": True,
                "request_sha256": "1" * 64,
                "policy": {
                    "minimum_approvals": 2,
                    "minimum_distinct_providers": 2,
                    "minimum_distinct_models": 2,
                },
                "counts": {
                    "members": 2,
                    "approvals": 2,
                    "rejections": 0,
                    "distinct_providers": 2,
                    "distinct_models": 2,
                },
                "report": {"bytes": len(report_raw), "sha256": _sha(report_raw)},
                "sources": {
                    "request": {
                        "bytes": len(source_raws["request"]),
                        "sha256": _sha(source_raws["request"]),
                    },
                    "policy_pack": {
                        "bytes": len(source_raws["policy"]),
                        "sha256": _sha(source_raws["policy"]),
                    },
                    "members": [
                        {
                            "approval": {
                                "bytes": len(approval),
                                "sha256": _sha(approval),
                            },
                            "response": {
                                "bytes": len(response),
                                "sha256": _sha(response),
                            },
                        }
                        for approval, response in zip(
                            source_raws["approvals"],
                            source_raws["responses"],
                            strict=True,
                        )
                    ],
                },
            },
        )
        self.assertNotIn(root_text, json.dumps(result))
        self.assertEqual(invocation[0], "verify-ai-quorum")
        self.assertTrue(any(value.startswith("--schematic=") for value in invocation))
        self.assertEqual(sum(value.startswith("--approval=") for value in invocation), 2)
        self.assertEqual(sum(value.startswith("--response=") for value in invocation), 2)
        self.assertNotIn("--require-quorum", invocation)
        self.assertEqual(invocation[-2], "--")

        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        schema = circuit_handoff_bundle_ai_quorum_replay_result_json_schema()
        self.assertTrue(schema["additionalProperties"] is False)
        self.assertEqual(
            schema["$id"],
            "https://github.com/penguin425/pcbex/schemas/"
            "circuit-generation-kicad-handoff-bundle-ai-quorum-replay-result-v3.json",
        )
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(result)), [])
        forged = copy.deepcopy(result)
        forged["caller_path"] = "/tmp/forged"
        self.assertNotEqual(list(Draft202012Validator(schema).iter_errors(forged)), [])

    def test_native_and_ai_replay_returns_one_closed_v3_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            native_report = root / "native-erc.json"
            archive.write_bytes(archive_raw)
            native_report.write_bytes(_retained_report(schematic_raw))
            native_command = _write_native_wrapper(root, base, schema_version=1)
            options, report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
            command = _write_ai_wrapper(root, native_command, report_raw)

            result = replay_circuit_handoff_bundle(
                archive,
                command,
                retained_native_kicad_erc_report=native_report,
                require_native_kicad_erc_approved=True,
                **options,
                require_ai_quorum=True,
                timeout_seconds=30,
            )

        self.assertEqual(result["schema_version"], 3)
        self.assertTrue(result["validation"]["native_kicad_erc_replayed"])
        self.assertTrue(result["validation"]["ai_schematic_quorum_replayed"])
        self.assertTrue(result["native_kicad_erc"]["approved"])
        self.assertTrue(result["ai_schematic_quorum"]["quorum_met"])
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        schema = circuit_handoff_bundle_ai_quorum_replay_result_json_schema()
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(result)), [])

    def test_complete_ai_inputs_without_thresholds_use_exact_two_two_two_defaults(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            options, report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
            for key in (
                "minimum_ai_approvals",
                "minimum_distinct_ai_providers",
                "minimum_distinct_ai_models",
            ):
                options.pop(key)
            command = _write_ai_wrapper(root, base, report_raw)

            result = replay_circuit_handoff_bundle(archive, command, **options)
            invocation = json.loads(
                (root / "ai-invocation.json").read_text(encoding="utf-8")
            )

        self.assertEqual(
            result["ai_schematic_quorum"]["policy"],
            {
                "minimum_approvals": 2,
                "minimum_distinct_providers": 2,
                "minimum_distinct_models": 2,
            },
        )
        self.assertIn("--minimum-approvals=2", invocation)
        self.assertIn("--minimum-distinct-providers=2", invocation)
        self.assertIn("--minimum-distinct-models=2", invocation)

    def test_omitted_ai_inputs_preserve_exact_v1_and_v2_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)

            v1 = replay_circuit_handoff_bundle(archive, base)
            native_report = root / "native.json"
            native_report.write_bytes(_retained_report(schematic_raw))
            native_command = _write_native_wrapper(root, base, schema_version=1)
            v2 = replay_circuit_handoff_bundle(
                archive,
                native_command,
                retained_native_kicad_erc_report=native_report,
            )

        self.assertEqual(v1["schema_version"], 1)
        self.assertNotIn("ai_schematic_quorum_replayed", v1["validation"])
        self.assertNotIn("ai_schematic_quorum", v1)
        self.assertEqual(v2["schema_version"], 2)
        self.assertNotIn("ai_schematic_quorum_replayed", v2["validation"])
        self.assertNotIn("ai_schematic_quorum", v2)
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        self.assertEqual(
            list(
                Draft202012Validator(
                    circuit_handoff_bundle_replay_result_json_schema()
                ).iter_errors(v1)
            ),
            [],
        )
        self.assertEqual(
            list(
                Draft202012Validator(
                    circuit_handoff_bundle_native_erc_replay_result_json_schema()
                ).iter_errors(v2)
            ),
            [],
        )

    def test_incomplete_pair_and_threshold_inputs_fail_before_any_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            options, _report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)

            incomplete = [
                {"retained_ai_quorum_report": options["retained_ai_quorum_report"]},
                {"minimum_ai_approvals": 2},
                {
                    **options,
                    "ai_responses": list(options["ai_responses"])[0:1],
                },
                {**options, "ai_approvals": []},
                {**options, "ai_approvals": "approval.json"},
                {**options, "ai_approvals": range(10**9)},
                {**options, "ai_responses": [*options["ai_responses"]] * 51},
                {**options, "require_ai_quorum": 1},
                {**options, "minimum_ai_approvals": 0},
                {**options, "minimum_ai_approvals": True},
                {**options, "minimum_ai_approvals": 101},
                {
                    **options,
                    "minimum_ai_approvals": 1,
                    "minimum_distinct_ai_providers": 2,
                },
            ]
            with mock.patch.object(handoff_module, "_run_native") as run_native:
                for replay_options in incomplete:
                    with self.subTest(options=replay_options), self.assertRaises(
                        CircuitHandoffBundleError
                    ):
                        replay_circuit_handoff_bundle(
                            archive,
                            base,
                            **replay_options,
                        )
                run_native.assert_not_called()

            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "replay-circuit-handoff-bundle",
                    str(archive),
                    "--minimum-ai-approvals",
                    "2",
                ],
            ), mock.patch.object(
                handoff_module,
                "_run_native",
            ) as run_native, self.assertRaisesRegex(
                SystemExit,
                "AI schematic quorum replay inputs are incomplete",
            ):
                cli.main()
            run_native.assert_not_called()

    def test_individual_and_aggregate_ai_sidecar_bounds_are_preflighted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            options, _report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
            report = Path(options["retained_ai_quorum_report"])
            request = Path(options["ai_review_request"])

            report.write_bytes(b"r" * 257)
            with mock.patch.object(
                handoff_module, "MAX_AI_QUORUM_REPORT_BYTES", 256
            ), mock.patch.object(handoff_module, "_run_native") as run_native:
                with self.assertRaises(CircuitHandoffBundleError):
                    replay_circuit_handoff_bundle(archive, base, **options)
                run_native.assert_not_called()

            options, _report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
            request.write_bytes(b"q" * 257)
            with mock.patch.object(
                handoff_module, "MAX_AI_QUORUM_INPUT_BYTES", 256
            ), mock.patch.object(handoff_module, "_run_native") as run_native:
                with self.assertRaises(CircuitHandoffBundleError):
                    replay_circuit_handoff_bundle(archive, base, **options)
                run_native.assert_not_called()

            options, _report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
            Path(options["ai_policy_pack"]).write_bytes(b"p" * 200)
            for path in [*options["ai_approvals"], *options["ai_responses"]]:
                Path(path).write_bytes(b"x" * 100)
            with mock.patch.object(
                handoff_module, "MAX_AI_QUORUM_INPUT_BYTES", 256
            ), mock.patch.object(
                handoff_module, "MAX_AI_QUORUM_TOTAL_INPUT_BYTES", 512
            ), mock.patch.object(handoff_module, "_run_native") as run_native:
                with self.assertRaisesRegex(
                    CircuitHandoffBundleError,
                    "aggregate bound",
                ):
                    replay_circuit_handoff_bundle(archive, base, **options)
                run_native.assert_not_called()

    def test_retained_report_must_match_fresh_bytes_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            options, report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
            semantically_equal = report_raw + b"\n"
            command = _write_ai_wrapper(root, base, semantically_equal)

            with self.assertRaisesRegex(
                CircuitHandoffBundleError,
                "did not reproduce the retained report",
            ):
                replay_circuit_handoff_bundle(archive, command, **options)

    def test_forged_exact_reports_fail_strict_closed_recomputation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            options, _report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
            report_path = Path(options["retained_ai_quorum_report"])
            baseline = _quorum_report("1" * 64, [_member(0), _member(1)])

            forged_reports: dict[str, dict[str, object]] = {}
            extra = copy.deepcopy(baseline)
            extra["unexpected"] = True
            forged_reports["unknown top-level field"] = extra
            wrong_request = copy.deepcopy(baseline)
            wrong_request["request_sha256"] = "2" * 64
            forged_reports["wrong request"] = wrong_request
            wrong_policy = copy.deepcopy(baseline)
            wrong_policy["policy"]["minimum_approvals"] = 1
            forged_reports["wrong policy"] = wrong_policy
            wrong_counts = copy.deepcopy(baseline)
            wrong_counts["counts"]["approvals"] = 1
            forged_reports["wrong counts"] = wrong_counts
            unordered = copy.deepcopy(baseline)
            unordered["members"].reverse()
            forged_reports["unordered members"] = unordered
            duplicate = copy.deepcopy(baseline)
            duplicate["members"][1]["public_key"] = duplicate["members"][0]["public_key"]
            forged_reports["duplicate identity"] = duplicate
            bad_member = copy.deepcopy(baseline)
            bad_member["members"][0]["gate_failures"] = ["forged"]
            forged_reports["inconsistent member decision"] = bad_member
            bad_decision = copy.deepcopy(baseline)
            bad_decision["quorum_met"] = False
            forged_reports["inconsistent quorum decision"] = bad_decision
            forged_reports["report omits a supplied member"] = _quorum_report(
                "1" * 64,
                [_member(0)],
            )

            for label, report_value in forged_reports.items():
                report_raw = json.dumps(report_value, indent=2).encode("utf-8")
                report_path.write_bytes(report_raw)
                command = _write_ai_wrapper(root, base, report_raw)
                with self.subTest(label=label), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    replay_circuit_handoff_bundle(archive, command, **options)

    def test_rust_unicode_identity_counts_remain_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            # Rust's current Unicode tables fold U+10D50 to U+10D70. Python
            # 3.11's older tables do not, so Python must not independently
            # recalculate the verifier's canonical identity sets.
            members = [
                _member(0, provider="\U00010d50", model="shared-model"),
                _member(1, provider="\U00010d70", model="shared-model"),
            ]
            options, _report_raw, _source_raws = _write_ai_inputs(
                root,
                schematic_raw,
                members=members,
                minimum_approvals=2,
                minimum_distinct_providers=1,
                minimum_distinct_models=1,
            )
            report_path = Path(options["retained_ai_quorum_report"])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["counts"]["distinct_providers"] = 1
            report["counts"]["distinct_models"] = 1
            report_raw = json.dumps(report, indent=2).encode("utf-8")
            report_path.write_bytes(report_raw)
            command = _write_ai_wrapper(root, base, report_raw)

            result = replay_circuit_handoff_bundle(archive, command, **options)

        self.assertEqual(
            result["ai_schematic_quorum"]["counts"]["distinct_providers"],
            1,
        )
        self.assertEqual(
            result["ai_schematic_quorum"]["counts"]["distinct_models"],
            1,
        )

    def test_caller_and_staged_ai_input_mutation_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)

            for label in ("report", "request", "policy", "approval", "response"):
                options, report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
                caller_path = {
                    "report": options["retained_ai_quorum_report"],
                    "request": options["ai_review_request"],
                    "policy": options["ai_policy_pack"],
                    "approval": options["ai_approvals"][0],
                    "response": options["ai_responses"][0],
                }[label]
                command = _write_ai_wrapper(
                    root,
                    base,
                    report_raw,
                    mutate_caller=str(caller_path),
                )
                with self.subTest(caller=label), self.assertRaisesRegex(
                    CircuitHandoffBundleError,
                    "changed during replay",
                ):
                    replay_circuit_handoff_bundle(archive, command, **options)

            for label in ("schematic", "request", "policy", "approval", "response"):
                options, report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
                command = _write_ai_wrapper(
                    root,
                    base,
                    report_raw,
                    mutate_staged=label,
                )
                with self.subTest(staged=label), self.assertRaisesRegex(
                    CircuitHandoffBundleError,
                    "staged AI schematic quorum input changed",
                ):
                    replay_circuit_handoff_bundle(archive, command, **options)

    def test_ai_child_cannot_mutate_retained_native_sidecar_in_combined_v3(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            native_report = root / "native.json"
            archive.write_bytes(archive_raw)
            native_report.write_bytes(_retained_report(schematic_raw))
            native_command = _write_native_wrapper(root, base, schema_version=1)
            options, report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
            command = _write_ai_wrapper(
                root,
                native_command,
                report_raw,
                mutate_caller=str(native_report),
            )

            with self.assertRaisesRegex(
                CircuitHandoffBundleError,
                "native KiCad ERC report changed during replay",
            ):
                replay_circuit_handoff_bundle(
                    archive,
                    command,
                    retained_native_kicad_erc_report=native_report,
                    **options,
                )

    def test_rejected_quorum_is_evidence_unless_optional_gate_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            members = [_member(0), _member(1, approved=False)]
            options, report_raw, _source_raws = _write_ai_inputs(
                root,
                schematic_raw,
                members=members,
            )
            command = _write_ai_wrapper(root, base, report_raw)

            result = replay_circuit_handoff_bundle(archive, command, **options)
            self.assertFalse(result["ai_schematic_quorum"]["quorum_met"])
            self.assertFalse(result["ai_schematic_quorum"]["quorum_required"])
            with self.assertRaisesRegex(
                CircuitHandoffBundleError,
                "did not meet every threshold",
            ):
                replay_circuit_handoff_bundle(
                    archive,
                    command,
                    **options,
                    require_ai_quorum=True,
                )
            self.assertTrue((root / "ai-invocation.json").exists())

    def test_ai_quorum_child_uses_same_aggregate_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive_raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            options, report_raw, _source_raws = _write_ai_inputs(root, schematic_raw)
            command = _write_ai_wrapper(root, base, report_raw, sleep_seconds=5)

            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    archive,
                    command,
                    **options,
                    timeout_seconds=1.5,
                )
            self.assertEqual(archive.read_bytes(), archive_raw)

    def test_cli_routes_all_ai_inputs_and_writes_v3_schema(self) -> None:
        result = {"schema_version": 3, "operation": "replay", "replayed": True}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive = root / "handoff.zip"
            report = root / "quorum.json"
            request = root / "request.json"
            policy = root / "policy.json"
            approval_a = root / "approval-a.json"
            approval_b = root / "approval-b.json"
            response_a = root / "response-a.json"
            response_b = root / "response-b.json"
            schema_path = root / "v3-schema.json"
            stdout = io.StringIO()
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "replay-circuit-handoff-bundle",
                    str(archive),
                    "--pcbex",
                    "native-pcbex",
                    "--ai-quorum-report",
                    str(report),
                    "--ai-review-request",
                    str(request),
                    "--ai-policy-pack",
                    str(policy),
                    "--ai-approval",
                    str(approval_a),
                    "--ai-approval",
                    str(approval_b),
                    "--ai-response",
                    str(response_a),
                    "--ai-response",
                    str(response_b),
                    "--minimum-ai-approvals",
                    "2",
                    "--minimum-distinct-ai-providers",
                    "1",
                    "--minimum-distinct-ai-models",
                    "2",
                    "--require-ai-quorum",
                ],
            ), mock.patch.object(
                cli,
                "replay_circuit_handoff_bundle",
                return_value=result,
            ) as replay, redirect_stdout(stdout):
                cli.main()
            replay.assert_called_once_with(
                Path(archive),
                "native-pcbex",
                retained_ai_quorum_report=Path(report),
                ai_review_request=Path(request),
                ai_policy_pack=Path(policy),
                ai_approvals=[Path(approval_a), Path(approval_b)],
                ai_responses=[Path(response_a), Path(response_b)],
                minimum_ai_approvals=2,
                minimum_distinct_ai_providers=1,
                minimum_distinct_ai_models=2,
                require_ai_quorum=True,
                timeout_seconds=120.0,
                expected_archive_sha256=None,
                expected_bundle_sha256=None,
            )
            self.assertEqual(json.loads(stdout.getvalue()), result)

            stdout = io.StringIO()
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "replay-circuit-handoff-bundle",
                    str(archive),
                    "--ai-quorum-report",
                    str(report),
                    "--ai-review-request",
                    str(request),
                    "--ai-policy-pack",
                    str(policy),
                    "--ai-approval",
                    str(approval_a),
                    "--ai-approval",
                    str(approval_b),
                    "--ai-response",
                    str(response_a),
                    "--ai-response",
                    str(response_b),
                ],
            ), mock.patch.object(
                cli,
                "replay_circuit_handoff_bundle",
                return_value=result,
            ) as replay_defaults, redirect_stdout(stdout):
                cli.main()
            replay_defaults.assert_called_once_with(
                Path(archive),
                "pcbex",
                retained_ai_quorum_report=Path(report),
                ai_review_request=Path(request),
                ai_policy_pack=Path(policy),
                ai_approvals=[Path(approval_a), Path(approval_b)],
                ai_responses=[Path(response_a), Path(response_b)],
                minimum_ai_approvals=None,
                minimum_distinct_ai_providers=None,
                minimum_distinct_ai_models=None,
                require_ai_quorum=False,
                timeout_seconds=120.0,
                expected_archive_sha256=None,
                expected_bundle_sha256=None,
            )

            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "circuit-handoff-bundle-ai-quorum-replay-result-schema",
                    "--output",
                    str(schema_path),
                ],
            ):
                cli.main()
            self.assertEqual(
                json.loads(schema_path.read_text(encoding="utf-8")),
                circuit_handoff_bundle_ai_quorum_replay_result_json_schema(),
            )

    def test_real_rust_kicad_and_two_reviewer_quorum_replay_when_binary_is_supplied(
        self,
    ) -> None:
        binary = os.environ.get("PCBEX_TEST_BINARY")
        if not binary:
            self.skipTest("PCBEX_TEST_BINARY is not set")
        binary_path = Path(binary).resolve()
        if not binary_path.is_file():
            self.fail("PCBEX_TEST_BINARY does not name a regular file")

        def run(*arguments: object, timeout: float = 60) -> None:
            completed = subprocess.run(
                [str(binary_path), *(str(argument) for argument in arguments)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
            if completed.returncode != 0:
                self.fail(completed.stderr.decode("utf-8", errors="replace"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            spec_path = root / "spec.json"
            spec_path.write_bytes(_render(_spec()))
            checked = subprocess.run(
                [str(binary_path), "check-circuit-spec", str(spec_path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            generation = _replace_native_check(_bundle(), json.loads(checked.stdout))
            generation_path = root / "generation.json"
            generation_path.write_bytes(_render(generation))
            archive = root / "handoff.zip"
            handoff_circuit_generation(
                generation_path,
                archive,
                str(binary_path),
                timeout_seconds=30,
            )
            schematic = root / "schematic.kicad_sch"
            schematic.write_bytes(
                _archive_entries(archive.read_bytes())[handoff_module.SCHEMATIC_NAME]
            )
            native_report = root / "native-erc.json"
            run(
                "run-native-kicad-erc",
                schematic,
                "--output",
                native_report,
                "--require-approved",
            )

            electrical_policy = root / "electrical-policy.json"
            run("electrical-policy", "--output", electrical_policy)
            reviewer_material: list[tuple[Path, Path]] = []
            trusted_keys = []
            for index in range(2):
                private_key = root / f"reviewer-{index}.key"
                public_key = root / f"reviewer-{index}.pub"
                run(
                    "approval-keygen",
                    "--private-key",
                    private_key,
                    "--public-key",
                    public_key,
                )
                reviewer_material.append((private_key, public_key))
                trusted_keys.append(
                    {
                        "signer_id": f"reviewer-{index}",
                        "public_key": public_key.read_text(encoding="utf-8").strip(),
                    }
                )
            policy_pack_value = json.loads(
                (Path(__file__).parents[2] / "examples/acme-policy-pack.json").read_text(
                    encoding="utf-8"
                )
            )
            policy_pack_value["electrical_policy"] = json.loads(
                electrical_policy.read_text(encoding="utf-8")
            )
            policy_pack_value["require_simulation_evidence"] = False
            policy_pack_value["ai_requirements"] = [
                {
                    "id": "power",
                    "text": "Power input treatment is intentional",
                }
            ]
            policy_pack_value["trusted_approval_keys"] = trusted_keys
            policy_pack = root / "policy-pack.json"
            policy_pack.write_text(
                json.dumps(policy_pack_value, indent=2),
                encoding="utf-8",
            )
            run("validate-policy-pack", policy_pack)
            electrical_review = root / "electrical-review.json"
            run(
                "check-schematic",
                schematic,
                "--policy-pack",
                policy_pack,
                "--output",
                electrical_review,
                "--require-approved",
            )
            request = root / "request.json"
            run(
                "prepare-ai-review",
                schematic,
                "--electrical-review",
                electrical_review,
                "--policy-pack",
                policy_pack,
                "--output",
                request,
                "--session-output",
                root / "session.json",
            )
            request_value = json.loads(request.read_text(encoding="utf-8"))
            approvals = []
            responses = []
            for index, (private_key, _public_key) in enumerate(reviewer_material):
                response = root / f"response-{index}.json"
                response.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "request_sha256": request_value["request_sha256"],
                            "model": {
                                "provider": f"provider-{index}",
                                "model": f"model-{index}",
                                "version": "1",
                            },
                            "decision": "approve",
                            "summary": "The deterministic evidence supports approval.",
                            "requirements": [
                                {
                                    "id": "power",
                                    "status": "pass",
                                    "rationale": "The electrical review is approved.",
                                    "evidence_refs": ["electrical-review"],
                                }
                            ],
                            "risks": [],
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                approval = root / f"approval-{index}.json"
                run(
                    "sign-ai-review",
                    request,
                    response,
                    "--private-key",
                    private_key,
                    "--signer-id",
                    f"reviewer-{index}",
                    "--output",
                    approval,
                    "--require-approved",
                )
                approvals.append(approval)
                responses.append(response)
            quorum_report = root / "quorum.json"
            approval_arguments = [
                argument
                for approval in approvals
                for argument in ("--approval", approval)
            ]
            response_arguments = [
                argument
                for response in responses
                for argument in ("--response", response)
            ]
            run(
                "verify-ai-quorum",
                request,
                "--schematic",
                schematic,
                *approval_arguments,
                *response_arguments,
                "--policy-pack",
                policy_pack,
                "--minimum-approvals",
                "2",
                "--minimum-distinct-providers",
                "2",
                "--minimum-distinct-models",
                "2",
                "--output",
                quorum_report,
                "--require-quorum",
            )

            result = replay_circuit_handoff_bundle(
                archive,
                str(binary_path),
                retained_native_kicad_erc_report=native_report,
                require_native_kicad_erc_approved=True,
                retained_ai_quorum_report=quorum_report,
                ai_review_request=request,
                ai_policy_pack=policy_pack,
                ai_approvals=approvals,
                ai_responses=responses,
                require_ai_quorum=True,
                timeout_seconds=90,
            )

        self.assertEqual(result["schema_version"], 3)
        self.assertTrue(result["native_kicad_erc"]["approved"])
        self.assertTrue(result["ai_schematic_quorum"]["quorum_met"])
        self.assertEqual(result["ai_schematic_quorum"]["counts"]["approvals"], 2)


if __name__ == "__main__":
    unittest.main()

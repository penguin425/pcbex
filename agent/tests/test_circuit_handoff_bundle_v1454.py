from __future__ import annotations

from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
from pathlib import PureWindowsPath
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent.tests.test_circuit_handoff_bundle_v1448 import (
    _bundle,
    _render,
    _replace_native_check,
)
from agent.tests.test_circuit_handoff_bundle_v1449 import _archive_entries
from agent.tests.test_circuit_handoff_bundle_v1450 import _valid_archive_with_command
from agent.tests.test_circuit_handoff_bundle_v1451 import _retained_report, _write_native_wrapper
from agent.tests.test_circuit_handoff_bundle_v1452 import _write_ai_inputs, _write_ai_wrapper
from agent.tests.test_circuit_handoff_bundle_v1453 import (
    _catalog_artifacts,
    _catalog_kwargs,
)
from pcbex_agent import cli
from pcbex_agent import circuit_handoff_bundle as handoff_module
from pcbex_agent.circuit_handoff_bundle import (
    CircuitHandoffBundleError,
    handoff_circuit_generation,
    replay_circuit_handoff_bundle,
)


BOARD_COMMAND = "verify-circuit-kicad-board-binding"
BOARD_RESULT_SCHEMA_COMMAND = (
    "circuit-handoff-bundle-board-binding-replay-result-schema"
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _compact(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _board_report_raw(
    archive_raw: bytes,
    board_raw: bytes,
    *,
    approved: bool = True,
    electrical_sha256: str = "e" * 64,
) -> bytes:
    """Make a deterministic report plus identities for the fake Rust child."""

    entries = _archive_entries(archive_raw)
    try:
        handoff = json.loads(entries[handoff_module.HANDOFF_REPORT_NAME])
    except (KeyError, json.JSONDecodeError):
        handoff = {}
    findings = [] if approved else [
        {
            "code": "missing_reserved_net_zero",
            "message": "retained test rejection",
            "reference": None,
            "pin": None,
            "net": None,
        }
    ]
    counts = {"errors": len(findings), "warnings": 0, "info": 0}
    handoff_sha256 = _sha(
        b"pcbex:circuit-kicad-handoff-report-v1\0" + _compact(handoff)
    )
    report_identity = {
        "schema_version": 1,
        "engine_version": handoff["engine_version"],
        "board_source_bytes": len(board_raw),
        "circuit_kicad_handoff_sha256": handoff_sha256,
        "board_source_sha256": _sha(board_raw),
        "board_electrical_sha256": electrical_sha256,
        "findings": findings,
        "counts": counts,
        "approved": approved,
    }
    binding_sha256 = _sha(
        b"pcbex:circuit-kicad-board-binding-v1\0" + _compact(report_identity)
    )
    value = {
        "schema_version": report_identity["schema_version"],
        "engine_version": report_identity["engine_version"],
        "board_source_bytes": report_identity["board_source_bytes"],
        "board_source_sha256": report_identity["board_source_sha256"],
        "board_electrical_sha256": report_identity["board_electrical_sha256"],
        "circuit_kicad_handoff_sha256": report_identity[
            "circuit_kicad_handoff_sha256"
        ],
        "binding_sha256": binding_sha256,
        "circuit_kicad_handoff": handoff,
        "findings": findings,
        "counts": counts,
        "approved": approved,
    }
    # Rust's retained report is compact canonical JSON with exactly one LF.
    return _compact(value) + b"\n"


def _write_board_wrapper(
    root: Path,
    base_command: list[str],
    report_raw: bytes,
    summary_template_raw: bytes | None = None,
    **configuration: object,
) -> list[str]:
    """Create a shell-free fake pcbex that models board replay and mutations."""

    (root / "board-base-command.json").write_text(
        json.dumps(base_command), encoding="utf-8"
    )
    (root / "board-configuration.json").write_text(
        json.dumps(configuration), encoding="utf-8"
    )
    (root / "board-emitted-report.bin").write_bytes(report_raw)
    (root / "board-summary-template.bin").write_bytes(
        report_raw if summary_template_raw is None else summary_template_raw
    )
    wrapper = root / "fake_pcbex_board.py"
    wrapper.write_text(
        r'''from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

root = Path(__file__).parent
base = json.loads((root / "board-base-command.json").read_text(encoding="utf-8"))
configuration = json.loads(
    (root / "board-configuration.json").read_text(encoding="utf-8")
)

if sys.argv[1] != "verify-circuit-kicad-board-binding":
    completed = subprocess.run([*base, *sys.argv[1:]], check=False)
    raise SystemExit(completed.returncode)

argv = sys.argv[1:]
(root / "board-invocation.json").write_text(json.dumps(argv), encoding="utf-8")

def option(name: str):
    prefix = "--" + name + "="
    for index, value in enumerate(argv):
        if value.startswith(prefix):
            return Path(value[len(prefix):])
        if value == "--" + name and index + 1 < len(argv):
            return Path(argv[index + 1])
    return None

def positional(suffix: str, excluded=()):
    values = []
    for value in argv[1:]:
        if value.startswith("-"):
            continue
        path = Path(value)
        if path.suffix == suffix and path not in excluded:
            values.append(path)
    return values[0] if values else None

output = option("output")
policy = option("policy") or option("board-binding-policy")
board = option("board") or option("kicad-board") or positional(".kicad_pcb")
if board is None or output is None:
    raise SystemExit(41)

mutation = configuration.get("mutate_staged")
if mutation:
    staged = {
        "board": board,
        "circuit_spec": option("circuit-spec") or positional(
            ".json", excluded=(output, policy)
        ),
        "schematic": option("schematic") or positional(".kicad_sch"),
        "policy": policy,
    }.get(mutation)
    if staged is None:
        raise SystemExit(42)
    original = staged.read_bytes()
    if configuration.get("same_size"):
        staged.write_bytes(bytes((value ^ 0x01) for value in original))
    else:
        staged.write_bytes(b"staged input changed\n")

caller = configuration.get("mutate_caller")
if caller:
    path = Path(caller)
    original = path.read_bytes()
    if configuration.get("same_size"):
        path.write_bytes(bytes((value ^ 0x01) for value in original))
    else:
        path.write_bytes(b"caller input changed\n")

time.sleep(float(configuration.get("sleep_seconds", 0)))
if configuration.get("write_report", True):
    output.write_bytes((root / "board-emitted-report.bin").read_bytes())

report_raw = (root / "board-emitted-report.bin").read_bytes()
board_raw = board.read_bytes()
template = json.loads(
    (root / "board-summary-template.bin").read_bytes()
)
summary = {
    "schema_version": 1,
    "report_schema_version": 1,
    "engine_version": configuration.get("engine_version", template["engine_version"]),
    "approved": bool(configuration.get("approved", True)),
    "counts": template["counts"],
    "board_source_bytes": len(board_raw),
    "board_source_sha256": hashlib.sha256(board_raw).hexdigest(),
    "board_electrical_sha256": configuration.get(
        "board_electrical_sha256", template["board_electrical_sha256"]
    ),
    "circuit_kicad_handoff_sha256": template["circuit_kicad_handoff_sha256"],
    "circuit_kicad_handoff": {
        key: template["circuit_kicad_handoff"][key]
        for key in (
            "schema_version",
            "engine_version",
            "circuit_source_bytes",
            "circuit_source_sha256",
            "schematic_source_bytes",
            "schematic_source_sha256",
            "circuit_spec_sha256",
            "circuit_check_sha256",
            "schematic_sha256",
            "policy_sha256",
        )
    },
    "binding_sha256": template["binding_sha256"],
    "report_bytes": len(report_raw),
    "report_sha256": hashlib.sha256(report_raw).hexdigest(),
}
if configuration.get("forge_summary") == "report_sha256":
    summary["report_sha256"] = "f" * 64
elif configuration.get("forge_summary") == "board_source_sha256":
    summary["board_source_sha256"] = "f" * 64
if configuration.get("extra_summary"):
    summary["unexpected"] = True

stdout_bytes = int(configuration.get("stdout_bytes", 0))
stderr_bytes = int(configuration.get("stderr_bytes", 0))
if stdout_bytes:
    sys.stdout.write("o" * stdout_bytes)
if stderr_bytes:
    sys.stderr.write("e" * stderr_bytes)
if configuration.get("emit_summary", True):
    print(json.dumps(summary, separators=(",", ":")))
raise SystemExit(int(configuration.get("exit_code", 0)))
''',
        encoding="utf-8",
    )
    return [sys.executable, str(wrapper)]


def _board_case_from_archive(
    root: Path,
    archive_raw: bytes,
    manifest: dict[str, object],
    base: list[str],
    *,
    approved: bool = True,
):
    archive = root / "handoff.zip"
    archive.write_bytes(archive_raw)
    board = root / "design.kicad_pcb"
    board_raw = b"(kicad_pcb (version 20250114) (generator pcbex-test))\n"
    board.write_bytes(board_raw)
    report = root / "retained-board-binding.json"
    report_raw = _board_report_raw(archive_raw, board_raw, approved=approved)
    report.write_bytes(report_raw)
    policy = root / "board-policy.json"
    policy_raw = b'{"schema_version":1,"id":"board-policy"}\n'
    policy.write_bytes(policy_raw)
    return {
        "archive": archive,
        "archive_raw": archive_raw,
        "manifest": manifest,
        "base": base,
        "board": board,
        "board_raw": board_raw,
        "report": report,
        "report_raw": report_raw,
        "policy": policy,
        "policy_raw": policy_raw,
    }


def _board_case(root: Path, *, approved: bool = True):
    archive_raw, manifest, base, _initial = _valid_archive_with_command(root)
    return _board_case_from_archive(
        root,
        archive_raw,
        manifest,
        base,
        approved=approved,
    )


def _board_kwargs(case: dict[str, object], **overrides: object) -> dict[str, object]:
    options = {
        "kicad_board": case["board"],
        "retained_board_binding_report": case["report"],
    }
    options.update(overrides)
    return options


def _board_evidence(result: dict[str, object]) -> dict[str, object]:
    value = result.get("board_binding")
    if not isinstance(value, dict):
        raise AssertionError("board binding evidence is missing")
    return value


def _board_replayed_flag(result: dict[str, object]) -> bool:
    validation = result.get("validation")
    if not isinstance(validation, dict):
        raise AssertionError("validation object is missing")
    if "board_binding_replayed" not in validation:
        raise AssertionError("board binding replay flag is missing")
    return bool(validation["board_binding_replayed"])


def _board_schema() -> dict[str, object]:
    return handoff_module.circuit_handoff_bundle_board_binding_replay_result_json_schema()


def _board_limit(name: str) -> int:
    value = getattr(handoff_module, name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise AssertionError(f"{name} is not an integer bound")
    return value


class CircuitHandoffBundleV1454Tests(unittest.TestCase):
    def test_board_replay_is_closed_v5_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            command = _write_board_wrapper(root, case["base"], case["report_raw"])
            result = replay_circuit_handoff_bundle(
                case["archive"],
                command,
                **_board_kwargs(case),
                expected_archive_sha256=_sha(case["archive_raw"]),
                expected_bundle_sha256=case["manifest"]["bundle_sha256"],
            )
            invocation = json.loads(
                (root / "board-invocation.json").read_text(encoding="utf-8")
            )
            expected_policy_sha256 = json.loads(
                _archive_entries(case["archive_raw"])[handoff_module.HANDOFF_REPORT_NAME]
            )["policy_sha256"]
            root_text = str(root)

        self.assertEqual(result["schema_version"], 5)
        self.assertTrue(_board_replayed_flag(result))
        evidence = _board_evidence(result)
        self.assertTrue(evidence["approved"])
        self.assertEqual(
            evidence["report"],
            {"bytes": len(case["report_raw"]), "sha256": _sha(case["report_raw"])},
        )
        self.assertEqual(
            evidence["board"]["bytes"],
            len(case["board_raw"]),
        )
        self.assertEqual(evidence["policy_sha256"], expected_policy_sha256)
        self.assertNotIn(root_text, json.dumps(result))
        self.assertIn("--mcp-echo-report-summary", invocation)
        self.assertIn("verify-circuit-kicad-board-binding", invocation)
        self.assertTrue(any("kicad_pcb" in value for value in invocation))

    def test_custom_policy_keeps_raw_source_and_effective_identity_distinct(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            command = _write_board_wrapper(root, case["base"], case["report_raw"])
            result = replay_circuit_handoff_bundle(
                case["archive"],
                command,
                **_board_kwargs(
                    case,
                    board_binding_policy=case["policy"],
                ),
            )

        evidence = _board_evidence(result)
        self.assertEqual(
            evidence["policy"],
            {
                "bytes": len(case["policy_raw"]),
                "sha256": _sha(case["policy_raw"]),
            },
        )
        self.assertRegex(str(evidence["policy_sha256"]), r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            evidence["policy"]["sha256"],
            evidence["policy_sha256"],
        )

    def test_board_inputs_are_all_or_none_and_preflight_before_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            marker = root / "spawned"
            child = root / "must-not-run.py"
            child.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('spawned', encoding='utf-8')\n",
                encoding="utf-8",
            )
            command = [sys.executable, str(child)]
            incomplete = (
                {"kicad_board": case["board"]},
                {"retained_board_binding_report": case["report"]},
                {"board_binding_policy": case["policy"]},
                {"require_board_binding_approved": True},
                {
                    "kicad_board": case["board"],
                    "board_binding_policy": case["policy"],
                },
            )
            with mock.patch.object(handoff_module, "_run_native") as run_native:
                for options in incomplete:
                    with self.subTest(options=options), self.assertRaises(
                        CircuitHandoffBundleError
                    ):
                        replay_circuit_handoff_bundle(
                            case["archive"], command, **options
                        )
                run_native.assert_not_called()
            self.assertFalse(marker.exists())

            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    case["archive"],
                    command,
                    **_board_kwargs(case),
                    board_binding_policy=case["policy"],
                    require_board_binding_approved=1,
                )
            self.assertFalse(marker.exists())

    def test_board_report_and_policy_caps_fail_before_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            board_limit = _board_limit("MAX_KICAD_BOARD_BINDING_BYTES")
            report_limit = _board_limit(
                "MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES"
            )
            policy_limit = _board_limit("MAX_KICAD_BOARD_BINDING_POLICY_BYTES")
            command = _write_board_wrapper(root, case["base"], case["report_raw"])

            for label, path, limit, options in (
                (
                    "board",
                    case["board"],
                    board_limit,
                    _board_kwargs(case),
                ),
                (
                    "report",
                    case["report"],
                    report_limit,
                    _board_kwargs(case),
                ),
                (
                    "policy",
                    case["policy"],
                    policy_limit,
                    _board_kwargs(
                        case,
                        board_binding_policy=case["policy"],
                    ),
                ),
            ):
                with self.subTest(label=label):
                    path.write_bytes(b"x" * (limit + 1))
                    with mock.patch.object(
                        handoff_module, "_run_native"
                    ) as run_native, self.assertRaises(CircuitHandoffBundleError):
                        replay_circuit_handoff_bundle(
                            case["archive"], command, **options
                        )
                    run_native.assert_not_called()
                    if label == "board":
                        path.write_bytes(case["board_raw"])
                    elif label == "report":
                        path.write_bytes(case["report_raw"])
                    else:
                        path.write_bytes(case["policy_raw"])

    def test_board_aggregate_cap_fails_before_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            command = _write_board_wrapper(root, case["base"], case["report_raw"])
            total = sum(
                len(case[key])
                for key in ("board_raw", "report_raw", "policy_raw")
            )
            with mock.patch.object(
                handoff_module,
                "MAX_KICAD_BOARD_BINDING_TOTAL_INPUT_BYTES",
                total - 1,
            ), mock.patch.object(
                handoff_module, "_run_native"
            ) as run_native, self.assertRaisesRegex(
                CircuitHandoffBundleError, "aggregate bound"
            ):
                replay_circuit_handoff_bundle(
                    case["archive"],
                    command,
                    **_board_kwargs(
                        case,
                        board_binding_policy=case["policy"],
                    ),
                )
            run_native.assert_not_called()

    def test_rendered_report_cap_allows_the_single_protocol_newline(self) -> None:
        """12 MiB of report data plus its required LF is the accepted bound."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            rendered_limit = _board_limit(
                "MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES"
            )
            report_raw = b"r" * (rendered_limit - 1) + b"\n"
            case["report"].write_bytes(report_raw)
            command = _write_board_wrapper(
                root,
                case["base"],
                report_raw,
                summary_template_raw=case["report_raw"],
            )
            result = replay_circuit_handoff_bundle(
                case["archive"],
                command,
                **_board_kwargs(case),
            )

        evidence = _board_evidence(result)
        self.assertEqual(
            evidence["report"],
            {"bytes": rendered_limit, "sha256": _sha(report_raw)},
        )

    def test_forged_summary_and_exact_report_mismatch_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            forged_summary = _write_board_wrapper(
                root,
                case["base"],
                case["report_raw"],
                forge_summary="report_sha256",
            )
            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    case["archive"], forged_summary, **_board_kwargs(case)
                )

            mismatched_report = case["report_raw"] + b"\n"
            case["report"].write_bytes(mismatched_report)
            command = _write_board_wrapper(root, case["base"], case["report_raw"])
            with self.assertRaisesRegex(CircuitHandoffBundleError, "report"):
                replay_circuit_handoff_bundle(
                    case["archive"], command, **_board_kwargs(case)
                )

            case["report"].write_bytes(case["report_raw"])
            extra_summary = _write_board_wrapper(
                root,
                case["base"],
                case["report_raw"],
                extra_summary=True,
            )
            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    case["archive"], extra_summary, **_board_kwargs(case)
                )

    def test_caller_and_staged_mutations_including_same_size_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            for label, caller in (
                ("archive", case["archive"]),
                ("board", case["board"]),
                ("report", case["report"]),
                ("policy", case["policy"]),
            ):
                command = _write_board_wrapper(
                    root,
                    case["base"],
                    case["report_raw"],
                    mutate_caller=str(caller),
                )
                options = _board_kwargs(case)
                if label == "policy":
                    options["board_binding_policy"] = case["policy"]
                with self.subTest(caller=label), self.assertRaisesRegex(
                    CircuitHandoffBundleError, "changed during replay"
                ):
                    replay_circuit_handoff_bundle(
                        case["archive"], command, **options
                    )
                if label == "archive":
                    case["archive"].write_bytes(case["archive_raw"])
                elif label == "board":
                    case["board"].write_bytes(case["board_raw"])
                elif label == "report":
                    case["report"].write_bytes(case["report_raw"])
                else:
                    case["policy"].write_bytes(case["policy_raw"])

            for label in ("board", "circuit_spec", "schematic", "policy"):
                command = _write_board_wrapper(
                    root,
                    case["base"],
                    case["report_raw"],
                    mutate_staged=label,
                    same_size=True,
                )
                options = _board_kwargs(case)
                if label == "policy":
                    options["board_binding_policy"] = case["policy"]
                with self.subTest(staged=label), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    replay_circuit_handoff_bundle(
                        case["archive"], command, **options
                    )

    def test_symlink_and_nonregular_inputs_are_path_free(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX symlink/FIFO checks are covered on Windows-native CI")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            command = _write_board_wrapper(root, case["base"], case["report_raw"])
            for label, path in (
                ("board", case["board"]),
                ("report", case["report"]),
                ("policy", case["policy"]),
            ):
                target = path.with_name(path.name + ".target")
                target.write_bytes(path.read_bytes())
                path.unlink()
                path.symlink_to(target)
                options = _board_kwargs(case)
                if label == "policy":
                    options["board_binding_policy"] = path
                try:
                    with self.subTest(kind="symlink", label=label):
                        with self.assertRaises(CircuitHandoffBundleError) as raised:
                            replay_circuit_handoff_bundle(
                                case["archive"], command, **options
                            )
                        self.assertNotIn(str(root), str(raised.exception))
                finally:
                    path.unlink(missing_ok=True)
                    path.write_bytes(
                        case["board_raw"]
                        if label == "board"
                        else case["report_raw"]
                        if label == "report"
                        else case["policy_raw"]
                    )
                    target.unlink(missing_ok=True)

            fifo = root / "board.fifo"
            os.mkfifo(fifo)
            try:
                with self.assertRaises(CircuitHandoffBundleError) as raised:
                    replay_circuit_handoff_bundle(
                        case["archive"],
                        command,
                        kicad_board=fifo,
                        retained_board_binding_report=case["report"],
                    )
                self.assertNotIn(str(root), str(raised.exception))
            finally:
                fifo.unlink()

    def test_rejected_evidence_is_returned_unless_approval_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root, approved=False)
            command = _write_board_wrapper(
                root,
                case["base"],
                case["report_raw"],
                approved=False,
                error_count=1,
            )
            result = replay_circuit_handoff_bundle(
                case["archive"], command, **_board_kwargs(case)
            )
            evidence = _board_evidence(result)
            self.assertFalse(evidence["approved"])
            self.assertFalse(evidence.get("approval_required", True))

            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    case["archive"],
                    command,
                    **_board_kwargs(
                        case,
                        require_board_binding_approved=True,
                    ),
                )

    def test_timeout_and_child_output_limits_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            for configuration in (
                {"sleep_seconds": 5},
                {"stdout_bytes": 2 * 1024 * 1024},
                {"stderr_bytes": 2 * 1024 * 1024},
            ):
                command = _write_board_wrapper(
                    root, case["base"], case["report_raw"], **configuration
                )
                with self.subTest(configuration=configuration), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    replay_circuit_handoff_bundle(
                        case["archive"],
                        command,
                        **_board_kwargs(case),
                        timeout_seconds=1.0,
                    )
            self.assertEqual(case["archive"].read_bytes(), case["archive_raw"])

    def test_geometry_change_cannot_hide_behind_electrical_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            baseline = _write_board_wrapper(
                root,
                case["base"],
                case["report_raw"],
                board_electrical_sha256="e" * 64,
            )
            first = replay_circuit_handoff_bundle(
                case["archive"], baseline, **_board_kwargs(case)
            )
            first_evidence = _board_evidence(first)

            changed_board = case["board_raw"].replace(
                b"generator pcbex-test", b"generator pcbex-other"
            )
            case["board"].write_bytes(changed_board)
            changed_report_raw = _board_report_raw(
                case["archive_raw"],
                changed_board,
                electrical_sha256="e" * 64,
            )
            case["report"].write_bytes(changed_report_raw)
            changed = _write_board_wrapper(
                root,
                case["base"],
                changed_report_raw,
                board_electrical_sha256="e" * 64,
            )
            second = replay_circuit_handoff_bundle(
                case["archive"], changed, **_board_kwargs(case)
            )
            second_evidence = _board_evidence(second)

        self.assertEqual(
            first_evidence["board_electrical_sha256"],
            second_evidence["board_electrical_sha256"],
        )
        self.assertNotEqual(
            first_evidence["board"]["sha256"],
            second_evidence["board"]["sha256"],
        )

    def test_board_v5_composes_with_native_ai_and_catalog_gates(self) -> None:
        """Every pre-existing gate remains represented when board replay is added."""

        compositions = (
            ("board", False, False, False),
            ("native", True, False, False),
            ("ai", False, True, False),
            ("catalog", False, False, True),
            ("all", True, True, True),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            for label, native, ai, catalog in compositions:
                with self.subTest(composition=label):
                    case_root = root / label
                    case_root.mkdir()
                    catalog_options = {}
                    if catalog:
                        artifacts = _catalog_artifacts(case_root / "catalog")
                        case = _board_case_from_archive(
                            case_root,
                            artifacts["archive_raw"],
                            artifacts["manifest"],
                            artifacts["command"],
                        )
                        catalog_options = _catalog_kwargs(artifacts)
                    else:
                        case = _board_case(case_root)

                    wrapper_base = case["base"]
                    native_options = {}
                    ai_options = {}
                    schematic_raw = _archive_entries(case["archive_raw"])[
                        handoff_module.SCHEMATIC_NAME
                    ]
                    if native:
                        native_report = case_root / "native-erc.json"
                        native_report.write_bytes(_retained_report(schematic_raw))
                        wrapper_base = _write_native_wrapper(
                            case_root, wrapper_base, schema_version=1
                        )
                        native_options = {
                            "retained_native_kicad_erc_report": native_report,
                            "require_native_kicad_erc_approved": True,
                        }
                    if ai:
                        ai_options, ai_report_raw, _source_raws = _write_ai_inputs(
                            case_root, schematic_raw
                        )
                        wrapper_base = _write_ai_wrapper(
                            case_root, wrapper_base, ai_report_raw
                        )
                        ai_options["require_ai_quorum"] = True
                    command = _write_board_wrapper(
                        case_root,
                        wrapper_base,
                        case["report_raw"],
                    )
                    result = replay_circuit_handoff_bundle(
                        case["archive"],
                        command,
                        **_board_kwargs(case),
                        **catalog_options,
                        **native_options,
                        **ai_options,
                    )

                    self.assertEqual(result["schema_version"], 5)
                    self.assertEqual(
                        result["verification_scope"],
                        handoff_module.CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_SCOPE,
                    )
                    self.assertTrue(result["validation"]["board_binding_replayed"])
                    self.assertIn("board_binding", result)
                    self.assertEqual(
                        result["validation"]["native_kicad_erc_replayed"], native
                    )
                    self.assertEqual(
                        result["validation"]["ai_schematic_quorum_replayed"], ai
                    )
                    self.assertEqual(
                        result["validation"]["catalog_generation_provenance_replayed"],
                        catalog,
                    )

    def test_catalog_source_names_are_portable_private_leaves(self) -> None:
        private = PureWindowsPath("C:/pcbex-private")
        self.assertNotEqual((private / "D:catalog.json").parent, private)
        unsafe_names = (
            "D:catalog.json",
            "catalog.json:payload",
            "CON",
            "nul.json",
            "COM1.txt",
            "LPT\N{SUPERSCRIPT ONE}",
            "catalog.json.",
            "catalog.json ",
        )
        for source_name in unsafe_names:
            with self.subTest(source_name=source_name), mock.patch.object(
                handoff_module.tempfile, "TemporaryDirectory"
            ) as temporary_directory, mock.patch.object(
                handoff_module, "atomic_write_no_clobber"
            ) as writer:
                with self.assertRaisesRegex(
                    CircuitHandoffBundleError, "snapshot source is invalid"
                ):
                    handoff_module._catalog_generation_provenance_evidence(
                        b"{}",
                        b"{}",
                        b"{}",
                        b"{}",
                        {
                            "source": {
                                "kind": "file",
                                "name": source_name,
                                "bytes": 2,
                                "sha256": "0" * 64,
                            }
                        },
                        deadline=1.0,
                        clock=lambda: 0.0,
                    )
                temporary_directory.assert_not_called()
                writer.assert_not_called()

    def test_real_rust_board_binding_replay_with_deterministic_pipeline_fixture(
        self,
    ) -> None:
        binary = os.environ.get("PCBEX_TEST_BINARY")
        if not binary:
            self.skipTest("PCBEX_TEST_BINARY is not set")
        binary_path = Path(binary).resolve()
        if not binary_path.is_file():
            self.fail("PCBEX_TEST_BINARY does not name a regular file")

        fixture_dir = (
            Path(__file__).resolve().parents[2]
            / "crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci"
        )
        spec = fixture_dir / "circuit-spec-v2.json"
        schematic = fixture_dir / "design.kicad_sch"
        board = fixture_dir / "design.kicad_pcb"
        for source in (spec, schematic, board):
            if not source.is_file() or source.is_symlink():
                self.fail(f"deterministic-pipeline fixture is not a regular file: {source.name}")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            check = root / "circuit-spec-check.json"
            subprocess.run(
                [
                    str(binary_path),
                    "check-circuit-spec",
                    str(spec),
                    "--output",
                    str(check),
                    "--require-approved",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            generation = _replace_native_check(
                _bundle(), json.loads(check.read_bytes())
            )
            generation_path = root / "generation.json"
            generation_path.write_bytes(_render(generation))
            archive = root / "handoff.zip"
            manifest = handoff_circuit_generation(
                generation_path,
                archive,
                str(binary_path),
                timeout_seconds=90,
            )
            archive_raw = archive.read_bytes()
            archive_spec = root / "archive-circuit-spec-v2.json"
            archive_spec.write_bytes(
                _archive_entries(archive_raw)[handoff_module.CIRCUIT_SPEC_NAME]
            )
            archive_schematic = root / "archive-design.kicad_sch"
            archive_schematic.write_bytes(
                _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            )

            report = root / "board-binding.json"
            subprocess.run(
                [
                    str(binary_path),
                    "verify-circuit-kicad-board-binding",
                    str(archive_spec),
                    str(archive_schematic),
                    str(board),
                    "--output",
                    str(report),
                    "--require-approved",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            result = replay_circuit_handoff_bundle(
                archive,
                str(binary_path),
                kicad_board=board,
                retained_board_binding_report=report,
                require_board_binding_approved=True,
                timeout_seconds=120,
                expected_archive_sha256=_sha(archive_raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )

        self.assertEqual(result["schema_version"], 5)
        self.assertEqual(
            result["verification_scope"],
            handoff_module.CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_SCOPE,
        )
        self.assertTrue(result["validation"]["board_binding_replayed"])
        self.assertTrue(result["board_binding"]["approved"])
        self.assertTrue(result["board_binding"]["approval_required"])

    def test_board_result_schema_couples_presence_and_flag_without_paths(self) -> None:
        schema = _board_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("board_binding", schema["required"])
        self.assertEqual(schema["properties"]["schema_version"], {"const": 5})
        self.assertEqual(
            schema["properties"]["verification_scope"],
            {"const": handoff_module.CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_SCOPE},
        )
        self.assertEqual(
            set(schema["properties"]["validation"]["required"]),
            {
                "internal_consistency",
                "expected_identity_matched",
                "archive_reproduced",
                "native_handoff_replayed",
                "catalog_input_erc_required",
                "catalog_input_erc_replayed",
                "native_kicad_erc_replayed",
                "ai_schematic_quorum_replayed",
                "catalog_generation_provenance_replayed",
                "board_binding_replayed",
            },
        )
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _board_case(root)
            command = _write_board_wrapper(root, case["base"], case["report_raw"])
            result = replay_circuit_handoff_bundle(
                case["archive"], command, **_board_kwargs(case)
            )
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(result)), [])
        for flag in (
            "native_kicad_erc_replayed",
            "ai_schematic_quorum_replayed",
            "catalog_generation_provenance_replayed",
        ):
            self.assertFalse(result["validation"][flag])
        forged = copy.deepcopy(result)
        forged["caller_path"] = "/tmp/secret"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(forged)))
        forged = copy.deepcopy(result)
        forged["validation"]["board_binding_replayed"] = False
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(forged)))
        forged = copy.deepcopy(result)
        del forged["board_binding"]
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(forged)))
        forged = copy.deepcopy(result)
        forged["board_binding"]["approved"] = False
        forged["board_binding"]["approval_required"] = True
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(forged)))
        forged = copy.deepcopy(result)
        del forged["board_binding"]["policy_sha256"]
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(forged)))
        for evidence_key, flag in (
            ("native_kicad_erc", "native_kicad_erc_replayed"),
            ("ai_schematic_quorum", "ai_schematic_quorum_replayed"),
            ("catalog_generation_provenance", "catalog_generation_provenance_replayed"),
        ):
            forged = copy.deepcopy(result)
            forged[evidence_key] = {}
            forged["validation"][flag] = False
            self.assertTrue(
                list(Draft202012Validator(schema).iter_errors(forged)),
                evidence_key,
            )

    def test_omitting_board_options_keeps_previous_result_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, manifest, command, _initial = _valid_archive_with_command(root)
            archive = root / "handoff.zip"
            archive.write_bytes(raw)
            first = replay_circuit_handoff_bundle(archive, command)
            second = replay_circuit_handoff_bundle(archive, command)
            manifest_raw = _archive_entries(raw)[handoff_module.MANIFEST_NAME]

            expected = {
                "schema_version": 1,
                "operation": "replay",
                "verified": True,
                "replayed": True,
                "verification_scope": handoff_module.CIRCUIT_HANDOFF_BUNDLE_REPLAY_SCOPE,
                "archive": {"bytes": len(raw), "sha256": _sha(raw)},
                "manifest": {
                    "name": handoff_module.MANIFEST_NAME,
                    "bytes": len(manifest_raw),
                    "sha256": _sha(manifest_raw),
                },
                "expected": {
                    "archive_sha256": None,
                    "bundle_sha256": None,
                },
                "validation": {
                    "internal_consistency": True,
                    "expected_identity_matched": False,
                    "archive_reproduced": True,
                    "native_handoff_replayed": True,
                    "catalog_input_erc_required": False,
                    "catalog_input_erc_replayed": False,
                    "native_kicad_erc_replayed": False,
                },
                "adapter": manifest["adapter"],
                "engine_version": manifest["engine_version"],
                "bundle_sha256": manifest["bundle_sha256"],
                "artifacts": manifest["artifacts"],
            }
        self.assertEqual(first, second)
        self.assertEqual(first, expected)
        self.assertNotIn("board_binding", first)
        self.assertNotIn("board_binding_replayed", first["validation"])

    def test_cli_routes_board_options_and_schema_no_clobber(self) -> None:
        result = {"schema_version": 5, "operation": "replay", "replayed": True}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive = root / "handoff.zip"
            board = root / "design.kicad_pcb"
            report = root / "binding.json"
            policy = root / "policy.json"
            schema_path = root / "board-replay-schema.json"
            stdout = io.StringIO()
            argv = [
                "pcbex-agent",
                "replay-circuit-handoff-bundle",
                str(archive),
                "--pcbex",
                "native-pcbex",
                "--kicad-board",
                str(board),
                "--board-binding-report",
                str(report),
                "--board-binding-policy",
                str(policy),
                "--require-board-binding-approved",
                "--timeout-seconds",
                "42",
            ]
            with mock.patch.object(
                sys, "argv", argv
            ), mock.patch.object(
                cli, "replay_circuit_handoff_bundle", return_value=result
            ) as replay, redirect_stdout(stdout):
                cli.main()
            replay.assert_called_once()
            kwargs = replay.call_args.kwargs
            self.assertEqual(kwargs["kicad_board"], board)
            self.assertEqual(kwargs["retained_board_binding_report"], report)
            self.assertEqual(kwargs["board_binding_policy"], policy)
            self.assertTrue(kwargs["require_board_binding_approved"])
            self.assertEqual(kwargs["timeout_seconds"], 42.0)
            self.assertEqual(json.loads(stdout.getvalue()), result)

            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    BOARD_RESULT_SCHEMA_COMMAND,
                    "--output",
                    str(schema_path),
                ],
            ):
                cli.main()
            original = schema_path.read_bytes()
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    BOARD_RESULT_SCHEMA_COMMAND,
                    "--output",
                    str(schema_path),
                ],
            ), self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(schema_path.read_bytes(), original)
if __name__ == "__main__":
    unittest.main()

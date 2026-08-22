from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from pcbex_agent import cli
from pcbex_agent import routing_manufacturing_handoff as handoff_module
from pcbex_agent.routing_manufacturing_handoff import (
    RoutingManufacturingHandoffError,
    evaluate_routing_manufacturing_handoff,
    render_routing_manufacturing_handoff_report,
    routing_manufacturing_handoff_report_json_schema,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": _sha(raw)}


def _write_fake_pcbex(
    root: Path,
    *,
    package_raw: bytes,
    fresh_verification_raw: bytes,
    mutation: Path | None = None,
    forbid_fabricate: bool = False,
) -> list[str]:
    package = root / "fake-package.bin"
    verification = root / "fresh-verification.bin"
    config = root / "fake-config.json"
    wrapper = root / "fake-pcbex.py"
    package.write_bytes(package_raw)
    verification.write_bytes(fresh_verification_raw)
    config.write_text(
        json.dumps(
            {
                "mutation": None if mutation is None else str(mutation),
                "forbid_fabricate": forbid_fabricate,
            }
        ),
        encoding="utf-8",
    )
    wrapper.write_text(
        r'''from __future__ import annotations
import json
from pathlib import Path
import sys

root = Path(__file__).parent
config = json.loads((root / "fake-config.json").read_text(encoding="utf-8"))
argv = sys.argv[1:]
calls_path = root / "calls.json"
calls = json.loads(calls_path.read_text(encoding="utf-8")) if calls_path.exists() else []
calls.append(argv)
calls_path.write_text(json.dumps(calls), encoding="utf-8")

def option(name: str) -> str | None:
    prefix = "--" + name + "="
    for index, value in enumerate(argv):
        if value.startswith(prefix):
            return value[len(prefix):]
        if value == "--" + name and index + 1 < len(argv):
            return argv[index + 1]
    return None

if argv and argv[0] == "verify-kicad-routing-convergence":
    output = Path(option("output"))
    output.write_bytes((root / "fresh-verification.bin").read_bytes())
    mutation = config.get("mutation")
    if mutation:
        target = Path(mutation)
        target.write_bytes(target.read_bytes() + b"changed")
    raise SystemExit(0)

if argv and argv[0] == "fabricate":
    if config.get("forbid_fabricate"):
        raise SystemExit(92)
    output = Path(option("output-dir"))
    output.mkdir()
    (output / "manufacturing.zip").write_bytes(
        (root / "fake-package.bin").read_bytes()
    )
    raise SystemExit(0)

raise SystemExit(91)
''',
        encoding="utf-8",
    )
    return [sys.executable, str(wrapper)]


class RoutingManufacturingHandoffTests(unittest.TestCase):
    def _sources(self, root: Path, *, complete: bool = True) -> dict[str, object]:
        input_board = root / "controller.placed.kicad_pcb"
        routed_board = root / "controller.routed.kicad_pcb"
        convergence = root / "routing-convergence.json"
        verification = root / "routing-verification.json"
        package = root / "manufacturing.zip"
        project = root / "controller.kicad_pro"
        rules = root / "controller.kicad_dru"
        profile = root / "factory-profile.json"
        input_raw = b"(kicad_pcb (version 20240108) (generator pcbex-input))\n"
        routed_raw = b"(kicad_pcb (version 20240108) (generator pcbex-routed))\n"
        convergence_raw = b'{"schema_version":1,"fixture":"convergence"}\n'
        package_raw = b"PK\x03\x04exact-manufacturing-package"
        project_raw = b'{"board": {}}\n'
        rules_raw = b"(version 1)\n"
        profile_raw = b'{"schema_version":1,"id":"fixture"}\n'
        for path, raw in (
            (input_board, input_raw),
            (routed_board, routed_raw),
            (convergence, convergence_raw),
            (package, package_raw),
            (project, project_raw),
            (rules, rules_raw),
            (profile, profile_raw),
        ):
            path.write_bytes(raw)

        status = "verified_complete" if complete else "verified_partial"
        convergence_status = "converged" if complete else "partial"
        report: dict[str, object] = {
            "schema_version": 1,
            "scope": "fresh_exact_routing_convergence_verification",
            "engine_version": "1.475.0-test",
            "input_kind": "kicad_pcb",
            "status": status,
            "routing_complete": complete,
            "source_authenticity_verified": False,
            "native_kicad_drc_verified": False,
            "manufacturability_verified": False,
            "release_authorized": False,
            "built_in_dfm_profile": None,
            "sources": {
                "input": _identity(input_raw),
                "routed_output": _identity(routed_raw),
                "retained_report": _identity(convergence_raw),
                "project": _identity(project_raw),
                "rules_file": _identity(rules_raw),
                "fab_profile": _identity(profile_raw),
                "policy_pack": None,
                "physical_profile": None,
            },
            "convergence": {
                "status": convergence_status,
                "converged": complete,
                "final_metrics": {"unrouted_nets": 0 if complete else 1},
                "final_drc_violation_count": 0,
            },
            "validation": {
                "source_closure_captured": True,
                "retained_report_canonical": True,
                "fresh_convergence_replayed": True,
                "retained_report_exact": True,
                "routed_output_exact": True,
                "caller_inputs_unchanged": True,
            },
            "binding_sha256": "",
        }
        report["binding_sha256"] = handoff_module._routing_binding(report)
        verification_raw = (
            json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        ).encode()
        verification.write_bytes(verification_raw)
        return {
            "input": input_board,
            "routed": routed_board,
            "convergence": convergence,
            "verification": verification,
            "package": package,
            "project": project,
            "rules": rules,
            "profile": profile,
            "package_raw": package_raw,
            "verification_raw": verification_raw,
        }

    def _evaluate(self, sources: dict[str, object], command: list[str]):
        return evaluate_routing_manufacturing_handoff(
            sources["input"],
            sources["routed"],
            sources["convergence"],
            sources["verification"],
            sources["package"],
            command,
            kicad_project=sources["project"],
            kicad_rules=sources["rules"],
            fab_profile=sources["profile"],
        )

    def test_complete_routing_cross_binds_one_board_to_exact_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root)
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=sources["verification_raw"],
            )
            result = self._evaluate(sources, command)

            self.assertEqual(result["status"], "verified_ready")
            self.assertTrue(result["ready"])
            self.assertEqual(result["gate_failures"], [])
            self.assertEqual(
                result["routing_verification"]["sources"]["routed_output"],
                result["sources"]["routed_board"],
            )
            self.assertEqual(
                {
                    key: result["manufacturing_replay"]["board"][key]
                    for key in ("bytes", "sha256")
                },
                result["sources"]["routed_board"],
            )
            self.assertEqual(
                result["manufacturing_replay"]["package"]["fresh"],
                result["sources"]["manufacturing_package"],
            )
            for claim in (
                "source_authenticity_verified",
                "native_kicad_drc_verified",
                "manufacturability_verified",
                "release_authorized",
            ):
                self.assertFalse(result[claim])
            rendered = render_routing_manufacturing_handoff_report(result)
            self.assertEqual(rendered[-1:], b"\n")
            self.assertNotIn(str(root).encode(), rendered)
            self.assertEqual(
                json.loads(rendered)["binding_sha256"], result["binding_sha256"]
            )
            calls = json.loads((root / "calls.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [call[0] for call in calls],
                ["verify-kicad-routing-convergence", "fabricate"],
            )
            if Draft202012Validator is not None:
                Draft202012Validator(
                    routing_manufacturing_handoff_report_json_schema()
                ).validate(result)

    def test_partial_routing_retains_truthful_negative_without_fabrication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root, complete=False)
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=sources["verification_raw"],
                forbid_fabricate=True,
            )
            result = self._evaluate(sources, command)
            self.assertEqual(result["status"], "not_ready")
            self.assertFalse(result["ready"])
            self.assertEqual(result["gate_failures"], ["routing_incomplete"])
            self.assertIsNone(result["manufacturing_replay"])
            self.assertFalse(
                result["validation"]["manufacturing_package_replayed"]
            )
            calls = json.loads((root / "calls.json").read_text(encoding="utf-8"))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], "verify-kicad-routing-convergence")
            if Draft202012Validator is not None:
                Draft202012Validator(
                    routing_manufacturing_handoff_report_json_schema()
                ).validate(result)

    def test_retained_or_fresh_verification_substitution_fails_before_fabrication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root)
            alternate = bytearray(sources["verification_raw"])
            alternate[-3] = ord("1") if alternate[-3] != ord("1") else ord("2")
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=bytes(alternate),
            )
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "did not reproduce"
            ):
                self._evaluate(sources, command)
            calls = json.loads((root / "calls.json").read_text(encoding="utf-8"))
            self.assertEqual(len(calls), 1)

    def test_caller_mutation_and_cross_role_alias_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root)
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=sources["verification_raw"],
                mutation=sources["package"],
            )
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "source changed"
            ):
                self._evaluate(sources, command)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root)
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=sources["verification_raw"],
            )
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "must not alias"
            ):
                evaluate_routing_manufacturing_handoff(
                    sources["input"],
                    sources["routed"],
                    sources["convergence"],
                    sources["verification"],
                    sources["package"],
                    command,
                    kicad_project=sources["routed"],
                    kicad_rules=sources["rules"],
                    fab_profile=sources["profile"],
                )

    def test_hardlink_alias_and_cwd_changing_pathlike_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root)
            alias = root / "project-alias.kicad_pro"
            try:
                os.link(sources["routed"], alias)
            except OSError as error:
                self.skipTest(f"hard links unavailable: {error}")
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=sources["verification_raw"],
            )
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "must not alias"
            ):
                evaluate_routing_manufacturing_handoff(
                    sources["input"],
                    sources["routed"],
                    sources["convergence"],
                    sources["verification"],
                    sources["package"],
                    command,
                    kicad_project=alias,
                    kicad_rules=sources["rules"],
                    fab_profile=sources["profile"],
                )

            other = root / "other"
            other.mkdir()
            entry = Path.cwd()

            class ChangingPath:
                def __fspath__(self):
                    os.chdir(other)
                    return str(sources["input"])

            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "working directory"
            ):
                evaluate_routing_manufacturing_handoff(
                    ChangingPath(),
                    sources["routed"],
                    sources["convergence"],
                    sources["verification"],
                    sources["package"],
                    command,
                    kicad_project=sources["project"],
                    kicad_rules=sources["rules"],
                    fab_profile=sources["profile"],
                )
            self.assertEqual(Path.cwd(), entry)

    def test_final_clock_swap_of_each_private_child_input_is_rejected(self):
        for target_glob, expected_error, expected_calls in (
            (
                "pcbex-routing-manufacturing-handoff-*/routing-input.kicad_pcb",
                "staged routing input changed before child execution",
                0,
            ),
            (
                "pcbex-manufacturing-replay-*/controller.routed.kicad_pcb",
                "staged manufacturing input changed before execution",
                1,
            ),
        ):
            with self.subTest(target_glob=target_glob), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                sources = self._sources(root)
                command = _write_fake_pcbex(
                    root,
                    package_raw=sources["package_raw"],
                    fresh_verification_raw=sources["verification_raw"],
                )
                changed = False
                tick = 0.0

                def clock():
                    nonlocal changed, tick
                    tick += 0.01
                    if not changed:
                        candidates = list(Path(tempfile.gettempdir()).glob(target_glob))
                        if candidates:
                            candidates[0].write_bytes(
                                candidates[0].read_bytes() + b"clock-swap"
                            )
                            changed = True
                    return tick

                with self.assertRaisesRegex(
                    RoutingManufacturingHandoffError, expected_error
                ):
                    evaluate_routing_manufacturing_handoff(
                        sources["input"],
                        sources["routed"],
                        sources["convergence"],
                        sources["verification"],
                        sources["package"],
                        command,
                        kicad_project=sources["project"],
                        kicad_rules=sources["rules"],
                        fab_profile=sources["profile"],
                        _clock=clock,
                    )
                self.assertTrue(changed)
                calls_path = root / "calls.json"
                calls = (
                    json.loads(calls_path.read_text(encoding="utf-8"))
                    if calls_path.exists()
                    else []
                )
                self.assertEqual(len(calls), expected_calls)

    def test_backwards_deadline_clock_fails_before_any_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root)
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=sources["verification_raw"],
            )
            readings = iter((10.0, 9.0))
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "deadline clock is invalid"
            ):
                evaluate_routing_manufacturing_handoff(
                    sources["input"],
                    sources["routed"],
                    sources["convergence"],
                    sources["verification"],
                    sources["package"],
                    command,
                    kicad_project=sources["project"],
                    kicad_rules=sources["rules"],
                    fab_profile=sources["profile"],
                    _clock=lambda: next(readings),
                )
            self.assertFalse((root / "calls.json").exists())

    def test_clock_cannot_replace_fresh_package_after_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root)
            command = _write_fake_pcbex(
                root,
                package_raw=b"PK\x03\x04different-package",
                fresh_verification_raw=sources["verification_raw"],
            )
            changed = False
            tick = 0.0

            def clock():
                nonlocal changed, tick
                tick += 0.01
                if not changed:
                    candidates = list(
                        Path(tempfile.gettempdir()).glob(
                            "pcbex-manufacturing-replay-*/"
                            "fresh-manufacturing/manufacturing.zip"
                        )
                    )
                    if candidates:
                        candidates[0].write_bytes(sources["package_raw"])
                        changed = True
                return tick

            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "did not reproduce"
            ):
                evaluate_routing_manufacturing_handoff(
                    sources["input"],
                    sources["routed"],
                    sources["convergence"],
                    sources["verification"],
                    sources["package"],
                    command,
                    kicad_project=sources["project"],
                    kicad_rules=sources["rules"],
                    fab_profile=sources["profile"],
                    _clock=clock,
                )
            self.assertFalse(changed)

    def test_command_and_initial_clock_hooks_cannot_select_the_source_baseline(self):
        for hook_kind in ("command", "clock"):
            with self.subTest(hook_kind=hook_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                sources = self._sources(root)
                command = _write_fake_pcbex(
                    root,
                    package_raw=sources["package_raw"],
                    fresh_verification_raw=sources["verification_raw"],
                )

                class MutatingCommand:
                    def __iter__(self):
                        sources["input"].write_bytes(b"substituted-input")
                        return iter(command)

                tick = 0.0

                def mutating_clock():
                    nonlocal tick
                    tick += 0.01
                    if tick == 0.01:
                        sources["input"].write_bytes(b"substituted-input")
                    return tick

                with self.assertRaisesRegex(
                    RoutingManufacturingHandoffError, "source changed"
                ):
                    evaluate_routing_manufacturing_handoff(
                        sources["input"],
                        sources["routed"],
                        sources["convergence"],
                        sources["verification"],
                        sources["package"],
                        MutatingCommand() if hook_kind == "command" else command,
                        kicad_project=sources["project"],
                        kicad_rules=sources["rules"],
                        fab_profile=sources["profile"],
                        _clock=mutating_clock if hook_kind == "clock" else (lambda: 1.0),
                    )
                self.assertFalse((root / "calls.json").exists())

    def test_forged_manufacturing_board_or_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root)
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=sources["verification_raw"],
            )
            real_replay = handoff_module._manufacturing._replay_captured_manufacturing_package

            def forged(*args, **kwargs):
                result = real_replay(*args, **kwargs)
                result["board"]["sha256"] = "f" * 64
                return result

            with mock.patch.object(
                handoff_module._manufacturing,
                "_replay_captured_manufacturing_package",
                side_effect=forged,
            ), self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "does not use the routed board"
            ):
                self._evaluate(sources, command)

    def test_schema_is_recursively_closed_and_bounded(self):
        schema = routing_manufacturing_handoff_report_json_schema()

        def visit(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertIs(value.get("additionalProperties"), False)
                if value.get("type") == "array":
                    self.assertIn("maxItems", value)
                for nested in value.values():
                    visit(nested)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested)

        visit(schema)
        if Draft202012Validator is not None:
            Draft202012Validator.check_schema(schema)

    def test_renderer_rejects_binding_and_nested_profile_forgery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root)
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=sources["verification_raw"],
            )
            result = self._evaluate(sources, command)
            forged = json.loads(json.dumps(result))
            forged["binding_sha256"] = "0" * 64
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "binding is invalid"
            ):
                render_routing_manufacturing_handoff_report(forged)
            forged = json.loads(json.dumps(result))
            forged["manufacturing_replay"]["profile"]["unexpected"] = True
            forged["binding_sha256"] = handoff_module._handoff_binding(forged)
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "profile shape is invalid"
            ):
                render_routing_manufacturing_handoff_report(forged)
            forged = json.loads(json.dumps(result))
            alternate = _identity(b"different-package")
            forged["manufacturing_replay"]["package"]["retained"] = alternate
            forged["manufacturing_replay"]["package"]["fresh"] = alternate
            forged["binding_sha256"] = handoff_module._handoff_binding(forged)
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "source binding is invalid"
            ):
                render_routing_manufacturing_handoff_report(forged)
            forged = json.loads(json.dumps(result))
            forged["manufacturing_replay"]["profile"]["source"]["sha256"] = (
                "e" * 64
            )
            forged["binding_sha256"] = handoff_module._handoff_binding(forged)
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError, "profile binding is invalid"
            ):
                render_routing_manufacturing_handoff_report(forged)

            partial_root = root / "partial"
            partial_root.mkdir()
            partial_sources = self._sources(partial_root, complete=False)
            partial_command = _write_fake_pcbex(
                partial_root,
                package_raw=partial_sources["package_raw"],
                fresh_verification_raw=partial_sources["verification_raw"],
                forbid_fabricate=True,
            )
            forged = self._evaluate(partial_sources, partial_command)
            forged["routing_verification"]["built_in_dfm_profile"] = (
                "INVALID_PROFILE"
            )
            forged["binding_sha256"] = handoff_module._handoff_binding(forged)
            with self.assertRaisesRegex(
                RoutingManufacturingHandoffError,
                "routing verification projection is invalid",
            ):
                render_routing_manufacturing_handoff_report(forged)

    def test_cli_retains_negative_before_require_ready_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._sources(root, complete=False)
            command = _write_fake_pcbex(
                root,
                package_raw=sources["package_raw"],
                fresh_verification_raw=sources["verification_raw"],
                forbid_fabricate=True,
            )
            output = root / "handoff.json"
            argv = [
                "pcbex-agent",
                "replay-routing-manufacturing-handoff",
                str(sources["input"]),
                str(sources["routed"]),
                "--convergence-report",
                str(sources["convergence"]),
                "--routing-verification-report",
                str(sources["verification"]),
                "--manufacturing-package",
                str(sources["package"]),
                "--kicad-project",
                str(sources["project"]),
                "--kicad-rules",
                str(sources["rules"]),
                "--fab-profile",
                str(sources["profile"]),
                "--pcbex",
                command[0],
                "-o",
                str(output),
                "--require-ready",
            ]
            # argparse's scalar --pcbex cannot carry the wrapper argument, so
            # patch only the public evaluator while exercising publication/gate order.
            negative = self._evaluate(sources, command)
            with mock.patch.object(
                cli,
                "evaluate_routing_manufacturing_handoff",
                return_value=negative,
            ), mock.patch.object(sys, "argv", argv), self.assertRaisesRegex(
                SystemExit, "was retained but is not ready"
            ):
                cli.main()
            self.assertEqual(
                output.read_bytes(),
                render_routing_manufacturing_handoff_report(negative),
            )

    def test_schema_cli_stdout_and_no_clobber(self):
        stdout = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            ["pcbex-agent", "routing-manufacturing-handoff-report-schema"],
        ), redirect_stdout(stdout):
            cli.main()
        self.assertEqual(
            json.loads(stdout.getvalue()),
            routing_manufacturing_handoff_report_json_schema(),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve(strict=True) / "schema.json"
            argv = [
                "pcbex-agent",
                "routing-manufacturing-handoff-report-schema",
                "--output",
                str(output),
            ]
            with mock.patch.object(sys, "argv", argv):
                cli.main()
            before = output.read_bytes()
            with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()

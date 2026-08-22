from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from agent.tests import test_routing_drc_fabrication_release_v1478 as v1478_fixture
from pcbex_agent import cli
from pcbex_agent import executable_pinned_fabrication_release as subject
from pcbex_agent.executable_pinned_fabrication_release import (
    ExecutablePinnedFabricationReleaseError,
    evaluate_executable_pinned_fabrication_release,
    executable_pinned_fabrication_release_report_json_schema,
    render_executable_pinned_fabrication_release_report,
)
from pcbex_agent import routing_drc_fabrication_release as v1478


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class ExecutablePinnedFabricationReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls._temporary.name).resolve(strict=True)
        cls.case = v1478_fixture.RoutingDrcFabricationReleaseTests()

        positive_root = cls.root / "positive"
        positive_root.mkdir()
        cls.positive_sources, cls.routing_command, cls.authorization_command = (
            cls.case._prepare(positive_root)
        )
        cls.positive = cls.case._evaluate(
            cls.positive_sources, cls.routing_command, cls.authorization_command
        )
        cls.positive_retained = positive_root / "routing-drc-fabrication-release.json"
        cls.positive_retained.write_bytes(
            v1478.render_routing_drc_fabrication_release_report(cls.positive)
        )

        negative_root = cls.root / "negative"
        negative_root.mkdir()
        cls.negative_sources, cls.negative_routing, cls.negative_authorization = (
            cls.case._prepare(negative_root, fabrication_authorized=False)
        )
        cls.negative = cls.case._evaluate(
            cls.negative_sources, cls.negative_routing, cls.negative_authorization
        )
        cls.negative_retained = negative_root / "routing-drc-fabrication-release.json"
        cls.negative_retained.write_bytes(
            v1478.render_routing_drc_fabrication_release_report(cls.negative)
        )

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def _native_copy(self, root: Path) -> tuple[Path, str]:
        suffix = ".exe" if sys.platform == "win32" else ""
        target = root / f"pinned-tool{suffix}"
        shutil.copyfile(Path(sys.executable).resolve(strict=True), target)
        target.chmod(0o700)
        return target, _sha(target.read_bytes())

    def _fake_nested(self, nested: dict[str, object], *, invoke_clock: bool = False):
        def evaluate(*args, **kwargs):
            retained_path = os.path.abspath(os.fspath(kwargs["_retained_outer"]))
            retained_raw = v1478._read_source(
                retained_path,
                v1478.MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES,
                "retained routing/DRC/fabrication release report",
            )
            kwargs["_retained_outer_capture"].append(
                (retained_path, retained_raw)
            )
            observer = kwargs["_command_observer"]
            observer(
                tuple(args[12]) if isinstance(args[12], (list, tuple)) else (args[12],),
                tuple(args[13]) if isinstance(args[13], (list, tuple)) else (args[13],),
                os.fspath(kwargs["kicad_cli"]),
            )
            if invoke_clock:
                kwargs["_clock"]()
            return deepcopy(nested)

        return evaluate

    def _evaluate(
        self,
        tool: Path,
        digest: str,
        *,
        nested: dict[str, object] | None = None,
        retained: Path | None = None,
        routing_command=None,
        expected_routing: str | None = None,
        expected_authorization: str | None = None,
        expected_kicad: str | None = None,
        clock=time.monotonic,
        invoke_clock: bool = False,
    ) -> dict[str, object]:
        sources = self.positive_sources
        nested = self.positive if nested is None else nested
        retained = self.positive_retained if retained is None else retained
        command = os.fspath(tool) if routing_command is None else routing_command
        with mock.patch.object(
            subject._v1478,
            "_evaluate_impl",
            side_effect=self._fake_nested(nested, invoke_clock=invoke_clock),
        ):
            return evaluate_executable_pinned_fabrication_release(
                sources["input"],
                sources["routed"],
                sources["convergence"],
                sources["verification"],
                sources["package"],
                sources["handoff"],
                sources["native_drc"],
                sources["release"],
                sources["plan"],
                sources["report"],
                sources["approvals"],
                retained,
                self.case.policy_digest,
                digest if expected_routing is None else expected_routing,
                digest if expected_authorization is None else expected_authorization,
                digest if expected_kicad is None else expected_kicad,
                command,
                os.fspath(tool),
                kicad_cli=tool,
                kicad_project=sources["project"],
                kicad_rules=sources["rules"],
                fab_profile=sources["profile"],
                _clock=clock,
            )

    def test_positive_binds_exact_native_entrypoint_bytes_and_retained_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            tool, digest = self._native_copy(root)
            result = self._evaluate(tool, digest)
            self.assertEqual(result["status"], "release_authorized")
            self.assertTrue(result["executable_digest_pins_verified"])
            self.assertTrue(result["release_authorized"])
            self.assertEqual(result["gate_failures"], [])
            for role in ("routing_pcbex", "authorization_pcbex", "kicad_cli"):
                self.assertEqual(result["executable_pins"][role]["sha256"], digest)
                self.assertEqual(
                    result["executable_pins"][role]["expected_sha256"], digest
                )
                self.assertTrue(result["executable_pins"][role]["matched"])
            for claim in (
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
            ):
                self.assertFalse(result[claim])
            rendered = render_executable_pinned_fabrication_release_report(result)
            self.assertEqual(rendered[-1:], b"\n")
            self.assertNotIn(str(root).encode(), rendered)
            if Draft202012Validator is not None:
                Draft202012Validator(
                    executable_pinned_fabrication_release_report_json_schema()
                ).validate(result)

    def test_retained_subject_ignores_historical_assessment_time_but_binds_raw(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            tool, digest = self._native_copy(root)
            fresh = deepcopy(self.positive)
            fresh["fabrication_authorization"]["evaluated_at_unix"] += 1
            fresh["fabrication_authorization"]["report"]["sha256"] = "a" * 64
            fresh["binding_sha256"] = v1478._binding(fresh)
            self.assertEqual(
                v1478._retained_replay_subject_sha256(self.positive),
                v1478._retained_replay_subject_sha256(fresh),
            )

            result = self._evaluate(tool, digest, nested=fresh)
            retained_raw = self.positive_retained.read_bytes()
            self.assertEqual(
                result["sources"]["routing_drc_fabrication_release_report"],
                {
                    "bytes": len(retained_raw),
                    "sha256": _sha(retained_raw),
                    "replay_subject_sha256": (
                        v1478._retained_replay_subject_sha256(self.positive)
                    ),
                },
            )
            self.assertEqual(
                result["routing_drc_fabrication_release"], fresh
            )

    def test_valid_nested_negative_is_retained_with_one_outer_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            tool, digest = self._native_copy(root)
            result = self._evaluate(
                tool,
                digest,
                nested=self.negative,
                retained=self.negative_retained,
            )
            self.assertEqual(result["status"], "not_authorized")
            self.assertFalse(result["release_authorized"])
            self.assertEqual(
                result["gate_failures"],
                ["routing_drc_fabrication_release_not_authorized"],
            )

    def test_digest_mismatch_and_nonnative_entrypoint_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            tool, digest = self._native_copy(root)
            with self.assertRaisesRegex(
                ExecutablePinnedFabricationReleaseError,
                "routing_pcbex executable does not match",
            ):
                self._evaluate(tool, digest, expected_routing="0" * 64)

            text_tool = root / ("text-tool.exe" if sys.platform == "win32" else "text-tool")
            text_tool.write_bytes(b"not a native executable\n")
            text_tool.chmod(0o700)
            with self.assertRaisesRegex(
                ExecutablePinnedFabricationReleaseError, "not a native executable"
            ):
                self._evaluate(text_tool, _sha(text_tool.read_bytes()))

    def test_command_must_be_one_entrypoint_without_wrapper_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            tool, digest = self._native_copy(root)
            with self.assertRaisesRegex(
                ExecutablePinnedFabricationReleaseError,
                "exactly one native executable",
            ):
                self._evaluate(
                    tool,
                    digest,
                    routing_command=[os.fspath(tool), "--wrapper-argument"],
                )

    def test_injected_clock_cannot_swap_and_restore_entrypoint_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            tool, digest = self._native_copy(root)

            def mutate():
                raw = tool.read_bytes()
                tool.write_bytes(raw[:-1] + bytes((raw[-1] ^ 1,)))
                return 10.0

            with self.assertRaisesRegex(
                ExecutablePinnedFabricationReleaseError,
                "executable changed during release replay",
            ):
                self._evaluate(
                    tool,
                    digest,
                    clock=mutate,
                    invoke_clock=True,
                )

    def test_injected_clock_cannot_rewrite_frozen_executable_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            tool, digest = self._native_copy(root)
            observed_frame = False

            def mutate_evidence():
                nonlocal observed_frame
                frame = inspect.currentframe()
                try:
                    frame = frame.f_back if frame is not None else None
                    while frame is not None:
                        if frame.f_code.co_filename == subject.__file__:
                            local_observations = frame.f_locals.get("observations")
                            if local_observations is not None:
                                observed_frame = True
                            if isinstance(local_observations, dict):
                                for pin in local_observations.values():
                                    pin["sha256"] = "0" * 64
                                    pin["expected_sha256"] = "0" * 64
                        frame = frame.f_back
                finally:
                    del frame
                return 10.0

            result = self._evaluate(
                tool,
                digest,
                clock=mutate_evidence,
                invoke_clock=True,
            )
            self.assertTrue(observed_frame)
            for role in subject._ROLES:
                self.assertEqual(result["executable_pins"][role]["sha256"], digest)
                self.assertEqual(
                    result["executable_pins"][role]["expected_sha256"], digest
                )

    def test_v1478_private_retained_replay_requires_exact_canonical_bytes(self):
        sources = self.positive_sources
        observed_commands = []

        def observe(routing_command, authorization_command, kicad_argument):
            self.assertIs(type(routing_command), tuple)
            self.assertIs(type(authorization_command), tuple)
            self.assertIs(type(kicad_argument), str)
            observed_commands.append(
                (routing_command, authorization_command, kicad_argument)
            )
            return routing_command, authorization_command, kicad_argument

        result = v1478._evaluate_impl(
            sources["input"],
            sources["routed"],
            sources["convergence"],
            sources["verification"],
            sources["package"],
            sources["handoff"],
            sources["native_drc"],
            sources["release"],
            sources["plan"],
            sources["report"],
            sources["approvals"],
            self.case.policy_digest,
            self.routing_command,
            self.authorization_command,
            kicad_cli="kicad-cli",
            kicad_project=sources["project"],
            kicad_rules=sources["rules"],
            grid_mm=0.25,
            width_mm=0.25,
            clearance_mm=0.20,
            via_diameter_mm=0.60,
            via_drill_mm=0.30,
            bend_cost=5,
            via_cost=20,
            fab=None,
            fab_profile=sources["profile"],
            physical_profile=None,
            timeout_seconds=300.0,
            _clock=time.monotonic,
            _root=os.getcwd(),
            _retained_outer=self.positive_retained,
            _command_observer=observe,
        )
        self.assertEqual(len(observed_commands), 1)
        self.assertEqual(
            v1478.render_routing_drc_fabrication_release_report(result),
            self.positive_retained.read_bytes(),
        )
        with self.assertRaisesRegex(
            v1478.RoutingDrcFabricationReleaseError,
            "did not reproduce the retained report",
        ):
            v1478._evaluate_impl(
                sources["input"],
                sources["routed"],
                sources["convergence"],
                sources["verification"],
                sources["package"],
                sources["handoff"],
                sources["native_drc"],
                sources["release"],
                sources["plan"],
                sources["report"],
                sources["approvals"],
                self.case.policy_digest,
                self.routing_command,
                self.authorization_command,
                kicad_cli="kicad-cli",
                kicad_project=sources["project"],
                kicad_rules=sources["rules"],
                grid_mm=0.25,
                width_mm=0.25,
                clearance_mm=0.20,
                via_diameter_mm=0.60,
                via_drill_mm=0.30,
                bend_cost=5,
                via_cost=20,
                fab=None,
                fab_profile=sources["profile"],
                physical_profile=None,
                timeout_seconds=300.0,
                _clock=time.monotonic,
                _root=os.getcwd(),
                _retained_outer=self.negative_retained,
            )

    def test_renderer_rejects_pin_binding_nested_and_false_claim_forgery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            tool, digest = self._native_copy(root)
            result = self._evaluate(tool, digest)
            mutations = (
                lambda value: value["executable_pins"]["kicad_cli"].update(
                    matched=False
                ),
                lambda value: value.update(binding_sha256="0" * 64),
                lambda value: value.update(toolchain_authenticity_verified=True),
                lambda value: value["routing_drc_fabrication_release"].update(
                    order_placed=True
                ),
            )
            for mutate in mutations:
                forged = deepcopy(result)
                mutate(forged)
                with self.assertRaises(ExecutablePinnedFabricationReleaseError):
                    render_executable_pinned_fabrication_release_report(forged)

    def test_schema_is_recursively_closed_and_arrays_are_bounded(self):
        schema = executable_pinned_fabrication_release_report_json_schema()
        objects = arrays = 0
        stack = [schema]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                if value.get("type") == "object":
                    objects += 1
                    self.assertFalse(value.get("additionalProperties", True))
                if value.get("type") == "array":
                    arrays += 1
                    self.assertIn("maxItems", value)
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        self.assertGreaterEqual(objects, 20)
        self.assertGreaterEqual(arrays, 3)

    def test_cli_retains_negative_before_require_authorized(self):
        sources = self.positive_sources
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release.json"
            rendered = b'{"retained":true}\n'
            argv = [
                "pcbex-agent",
                "replay-executable-pinned-fabrication-release",
                str(sources["input"]),
                str(sources["routed"]),
                "--convergence-report",
                str(sources["convergence"]),
                "--routing-verification-report",
                str(sources["verification"]),
                "--manufacturing-package",
                str(sources["package"]),
                "--routing-manufacturing-handoff-report",
                str(sources["handoff"]),
                "--native-drc-report",
                str(sources["native_drc"]),
                "--routing-drc-manufacturing-handoff-report",
                str(sources["release"]),
                "--deterministic-pipeline-plan",
                str(sources["plan"]),
                "--deterministic-pipeline-report",
                str(sources["report"]),
                "--approval",
                str(sources["approvals"][0]),
                "--routing-drc-fabrication-release-report",
                str(self.positive_retained),
                "--expected-policy-pack-canonical-sha256",
                self.case.policy_digest,
                "--expected-routing-pcbex-sha256",
                "a" * 64,
                "--expected-authorization-pcbex-sha256",
                "a" * 64,
                "--expected-kicad-cli-sha256",
                "a" * 64,
                "--output",
                str(output),
                "--require-authorized",
            ]
            with mock.patch.object(
                cli,
                "evaluate_executable_pinned_fabrication_release",
                return_value={"release_authorized": False},
            ), mock.patch.object(
                cli,
                "render_executable_pinned_fabrication_release_report",
                return_value=rendered,
            ), mock.patch.object(sys, "argv", argv), self.assertRaisesRegex(
                SystemExit, "was retained but is not authorized"
            ):
                cli.main()
            self.assertEqual(output.read_bytes(), rendered)

    def test_schema_cli_stdout(self):
        stdout = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            [
                "pcbex-agent",
                "executable-pinned-fabrication-release-report-schema",
            ],
        ), redirect_stdout(stdout):
            cli.main()
        self.assertEqual(
            json.loads(stdout.getvalue()),
            executable_pinned_fabrication_release_report_json_schema(),
        )


if __name__ == "__main__":
    unittest.main()

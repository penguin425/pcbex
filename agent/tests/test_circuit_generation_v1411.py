import ast
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from pcbex_agent.bounded_process import BoundedProcessResult
from pcbex_agent.circuit_generation import (
    CircuitCandidateRejected,
    CircuitGenerationError,
    _compact_json,
    _validate_check_envelope,
    circuit_generation_json_schema,
    generate_circuit_with_llm,
)
from pcbex_agent.provider import run_provider_command


def _compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def _spec(*, hostile=False):
    net = "__builtins__" if hostile else "N1"
    pin = "__class__" if hostile else "1"
    return {
        "schema_version": 2,
        "parts": [
            {
                "reference": "R1",
                "lib_id": "Device:R",
                "value": "1k",
                "footprint": "Resistor_SMD:R_0603",
                "mpn": None,
                "power": {
                    "rail_voltage_uv": None,
                    "max_voltage_uv": None,
                    "requires_decoupling": False,
                    "decoupling": False,
                },
                "pins": [
                    {"number": pin, "name": "~", "net": net, "electrical_type": "passive"},
                    {"number": "2", "name": "~", "net": net, "electrical_type": "passive"},
                ],
            }
        ],
        "nets": [
            {
                "name": net,
                "voltage_uv": None,
                "connections": [
                    {"reference": "R1", "pin": pin},
                    {"reference": "R1", "pin": "2"},
                ],
            }
        ],
    }


def _spec_with_no_connect():
    spec = _spec()
    spec["parts"][0]["pins"].append(
        {
            "number": "3",
            "name": "NC",
            "net": None,
            "electrical_type": "no_connect",
        }
    )
    return spec


def _review(errors=0, *, approved=None):
    if approved is None:
        approved = errors == 0
    return {
        "schema_version": 1,
        "schematic_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "policy_id": "default",
        "approved": approved,
        "counts": {"errors": errors, "warnings": 0, "info": 0},
        "findings": [
            {
                "id": "pcbex-er-" + (format(index, "016x")),
                "rule": "coverage_incomplete",
                "severity": "error",
                "message": f"error {errors}",
                "net_id": None,
                "symbols": [],
                "pins": [],
            }
            for index in range(errors)
        ],
    }


def _check_envelope(spec):
    review = _review()
    return {
        "schema_version": 1,
        "circuit_spec_sha256": hashlib.sha256(_compact_json(spec)).hexdigest(),
        "electrical_review_sha256": hashlib.sha256(_compact_json(review)).hexdigest(),
        "normalized_spec": spec,
        "electrical_review": review,
    }


def _checker_for(spec, errors=(0,), variants=None):
    calls = 0

    def checker(candidate, _remaining):
        nonlocal calls
        review = _review(errors[min(calls, len(errors) - 1)])
        checked_spec = spec
        if variants is not None:
            checked_spec = json.loads(json.dumps(spec))
            checked_spec["parts"][0]["value"] = variants[min(calls, len(variants) - 1)]
        calls += 1
        candidate.read_bytes()
        return {
            "schema_version": 1,
            "circuit_spec_sha256": hashlib.sha256(_compact(checked_spec)).hexdigest(),
            "electrical_review_sha256": hashlib.sha256(_compact(review)).hexdigest(),
            "normalized_spec": checked_spec,
            "electrical_review": review,
        }

    return checker


class CircuitGenerationV1411Tests(unittest.TestCase):
    def test_invalid_json_then_valid_correction(self):
        spec = _spec()
        responses = iter(["not-json", json.dumps({"candidate": True})])
        result = generate_circuit_with_llm(
            "make a resistor",
            {"type": "object"},
            lambda _prompt, _remaining: next(responses),
            _checker_for(spec),
            max_attempts=2,
        )
        self.assertEqual(result["attempts"], 2)
        self.assertTrue(result["repaired"])
        self.assertEqual(
            [item["outcome"] for item in result["attempt_history"]],
            ["invalid_json", "approved"],
        )

    def test_electrical_error_count_must_strictly_decrease(self):
        spec = _spec()
        responses = iter(
            [
                json.dumps({"candidate": 1}),
                json.dumps({"candidate": 2}),
                json.dumps({"candidate": 3}),
            ]
        )
        result = generate_circuit_with_llm(
            "make a resistor",
            {"type": "object"},
            lambda _prompt, _remaining: next(responses),
            _checker_for(spec, errors=(2, 1, 0), variants=("1k", "2k", "3k")),
            max_attempts=3,
        )
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(
            [item["error_count"] for item in result["attempt_history"]],
            [2, 1, 0],
        )

    def test_repeated_and_no_progress_fail_closed(self):
        spec = _spec()
        responses = iter([json.dumps({"candidate": 1}), json.dumps({"candidate": 2})])
        with self.assertRaisesRegex(CircuitGenerationError, "strictly decrease"):
            generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                lambda _prompt, _remaining: next(responses),
                _checker_for(spec, errors=(1, 1), variants=("1k", "2k")),
                max_attempts=3,
            )

        responses = iter([json.dumps({"candidate": 1}), json.dumps({"candidate": 1})])
        with self.assertRaisesRegex(CircuitGenerationError, "repeated a raw"):
            generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                lambda _prompt, _remaining: next(responses),
                _checker_for(spec, errors=(1, 0)),
                max_attempts=3,
            )

        responses = iter([json.dumps({"candidate": 1}), json.dumps({"candidate": 2})])
        with self.assertRaisesRegex(CircuitGenerationError, "repeated a normalized"):
            generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                lambda _prompt, _remaining: next(responses),
                _checker_for(spec, errors=(1, 0)),
                max_attempts=3,
            )

    def test_transport_size_and_utf8_boundaries(self):
        spec = _spec()
        with self.assertRaisesRegex(CircuitGenerationError, "exceeds 4 bytes"):
            generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                lambda _prompt, _remaining: b"12345",
                _checker_for(spec),
                maximum_output_bytes=4,
            )
        with self.assertRaisesRegex(CircuitGenerationError, "not valid UTF-8"):
            generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                lambda _prompt, _remaining: b"\xff",
                _checker_for(spec),
            )

    def test_aggregate_deadline_is_shared_by_callbacks(self):
        spec = _spec()
        ticks = iter([0.0, 1.0, 2.0, 11.0])
        transport_calls = []

        def clock():
            return next(ticks)

        def transport(_prompt, remaining):
            transport_calls.append(remaining)
            return json.dumps({"candidate": True})

        with self.assertRaisesRegex(CircuitGenerationError, "aggregate deadline"):
            generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                transport,
                _checker_for(spec),
                timeout_seconds=10,
                _clock=clock,
            )
        self.assertEqual(len(transport_calls), 1)
        self.assertLessEqual(transport_calls[0], 10)

    def test_forged_native_envelope_digest_is_rejected(self):
        spec = _spec()

        def forged(candidate, _remaining):
            review = _review()
            return {
                "schema_version": 1,
                "circuit_spec_sha256": "0" * 64,
                "electrical_review_sha256": hashlib.sha256(_compact(review)).hexdigest(),
                "normalized_spec": spec,
                "electrical_review": review,
            }

        with self.assertRaisesRegex(CircuitGenerationError, "different normalized candidate"):
            generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                lambda _prompt, _remaining: json.dumps({"candidate": True}),
                forged,
            )

    def test_forged_native_finding_counts_are_rejected(self):
        spec = _spec()

        def forged(candidate, _remaining):
            review = _review(1)
            review["approved"] = True
            review["counts"]["errors"] = 0
            return {
                "schema_version": 1,
                "circuit_spec_sha256": hashlib.sha256(_compact(spec)).hexdigest(),
                "electrical_review_sha256": hashlib.sha256(_compact(review)).hexdigest(),
                "normalized_spec": spec,
                "electrical_review": review,
            }

        with self.assertRaisesRegex(CircuitGenerationError, "counts do not match"):
            generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                lambda _prompt, _remaining: json.dumps({"candidate": True}),
                forged,
            )

    def test_duplicate_candidate_keys_are_rejected_before_checker(self):
        checker = _checker_for(_spec())
        with self.assertRaisesRegex(CircuitGenerationError, "exhausted"):
            generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                lambda _prompt, _remaining: '{"candidate":1,"candidate":2}',
                checker,
                max_attempts=1,
            )

    def test_native_checker_candidate_rejection_is_retryable(self):
        spec = _spec()
        responses = iter([json.dumps({"candidate": 1}), json.dumps({"candidate": 2})])
        calls = 0
        prompts = []
        sensitive_diagnostic = "invalid field SECRET-CANDIDATE-VALUE"

        def checker(candidate, remaining):
            nonlocal calls
            if calls == 0:
                calls += 1
                raise CircuitCandidateRejected(sensitive_diagnostic)
            calls += 1
            return _checker_for(spec)(candidate, remaining)

        def transport(prompt, _remaining):
            prompts.append(prompt)
            return next(responses)

        result = generate_circuit_with_llm(
            "make a resistor",
            {"type": "object"},
            transport,
            checker,
            max_attempts=2,
        )
        self.assertEqual([item["outcome"] for item in result["attempt_history"]], ["candidate_rejected", "approved"])
        self.assertIn(sensitive_diagnostic, prompts[1])
        self.assertNotIn(sensitive_diagnostic, json.dumps(result))
        self.assertEqual(
            result["attempt_history"][0]["error"],
            "native checker rejected candidate",
        )

    def test_generation_schema_closes_recursive_bundle_shapes(self):
        schema = circuit_generation_json_schema()
        self.assertEqual(schema["$id"].rsplit("/", 1)[-1], "circuit-generation-v2.json")
        self.assertFalse(schema["properties"]["attempt_history"]["items"]["additionalProperties"])
        self.assertFalse(schema["properties"]["spec"]["additionalProperties"])
        self.assertFalse(schema["properties"]["check"]["additionalProperties"])
        findings = schema["properties"]["check"]["properties"]["electrical_review"]["properties"]["findings"]
        self.assertFalse(findings["items"]["additionalProperties"])
        receipt = schema["properties"]["catalog_receipt"]["anyOf"][0]
        self.assertFalse(receipt["additionalProperties"])

    def test_schema_cli_preflights_output_before_native_subprocess(self):
        from pcbex_agent import cli

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "schema.json"
            output.write_text("sentinel", encoding="utf-8")
            with patch.object(cli, "fetch_circuit_spec_v2_schema") as spec_fetch, patch.object(
                cli, "fetch_circuit_spec_check_schema"
            ) as check_fetch, patch.object(
                sys,
                "argv",
                ["pcbex-agent", "circuit-generation-schema", "--pcbex", "must-not-run", "-o", str(output)],
            ), self.assertRaises(SystemExit):
                cli.main()
            spec_fetch.assert_not_called()
            check_fetch.assert_not_called()
            self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_command_adapter_rejects_limits_before_schema_spawn(self):
        from pcbex_agent import circuit_generation

        with patch.object(circuit_generation, "_command_json") as command:
            with self.assertRaisesRegex(CircuitGenerationError, "max_attempts"):
                circuit_generation.generate_circuit_with_command(
                    "requirements",
                    "pcbex",
                    ["provider"],
                    max_attempts=5,
                )
            command.assert_not_called()

    def test_native_checker_only_exit_one_is_candidate_rejection(self):
        from pcbex_agent import circuit_generation

        failure = BoundedProcessResult(("pcbex", "check-circuit-spec"), 2, b"", b"bad")
        with patch.object(circuit_generation, "run_bounded", return_value=failure):
            with self.assertRaisesRegex(CircuitGenerationError, "exited with 2"):
                circuit_generation._command_json(
                    ["pcbex", "check-circuit-spec", "candidate.json"],
                    1.0,
                    maximum_output_bytes=1024,
                    check_candidate=True,
                )

    @unittest.skipUnless(Path("target/debug/pcbex").is_file(), "Rust pcbex binary is not built")
    def test_command_adapter_round_trips_real_rust_checker(self):
        from pcbex_agent.circuit_generation import generate_circuit_with_command

        spec = json.loads(Path("examples/circuit-spec-v2.json").read_text(encoding="utf-8"))
        raw = json.dumps(spec, separators=(",", ":"))
        bundle = generate_circuit_with_command(
            "build the example regulator",
            "target/debug/pcbex",
            [sys.executable, "-c", "import sys; sys.stdout.write(sys.argv[1])", raw],
            timeout_seconds=30,
        )
        self.assertTrue(bundle["check"]["electrical_review"]["approved"])
        self.assertEqual(bundle["attempts"], 1)

    def test_bundle_is_deterministic_and_evidence_bound(self):
        spec = _spec(hostile=True)

        def run():
            return generate_circuit_with_llm(
                "make a resistor",
                {"type": "object"},
                lambda _prompt, _remaining: b'{"candidate":true}',
                _checker_for(spec),
            )

        first, second = run(), run()
        self.assertEqual(first, second)
        self.assertIn('_pcbex_parts["R1"]', first["skidl"])
        self.assertIn('_pcbex_nets["__builtins__"]', first["skidl"])
        self.assertIn(first["circuit_spec_sha256"], first["skidl"])
        self.assertIn(first["electrical_review_sha256"], first["skidl"])
        self.assertIn("from skidl import Net, Part, generate_netlist", first["skidl"])
        self.assertNotIn("from skidl import NC,", first["skidl"])

    def test_v2_no_connects_render_as_skidl_nc_before_ordinary_nets(self):
        spec = _spec_with_no_connect()
        result = generate_circuit_with_llm(
            "make a resistor with one intentionally unconnected pin",
            {"type": "object"},
            lambda _prompt, _remaining: b'{"candidate":true}',
            _checker_for(spec),
        )
        source = result["skidl"]
        self.assertIn("from skidl import NC, Net, Part, generate_netlist", source)
        self.assertIn('_pcbex_parts["R1"]["3"] += NC', source)
        self.assertNotIn('_pcbex_nets["NC"]', source)
        self.assertLess(
            source.index('_pcbex_parts["R1"]["3"] += NC'),
            source.index('_pcbex_parts["R1"]["1"] += _pcbex_nets["N1"]'),
        )
        ast.parse(source)
        compiled = compile(source, "generated-circuit.py", "exec")

        class FakeNet:
            def __init__(self, name):
                self.name = name
                self.connections = 0

        class FakePin:
            def __iadd__(self, net):
                net.connections += 1
                return self

        class FakePart:
            def __init__(self, _library, _symbol, *, value, footprint):
                self.value = value
                self.footprint = footprint
                self.pins = {}

            def __getitem__(self, pin):
                return self.pins.setdefault(pin, FakePin())

            def __setitem__(self, pin, value):
                self.pins[pin] = value

        fake_skidl = ModuleType("skidl")
        fake_skidl.NC = FakeNet("NC")
        fake_skidl.Net = FakeNet
        fake_skidl.Part = FakePart
        fake_skidl.generate_netlist = lambda: None
        namespace = {}
        with patch.dict(sys.modules, {"skidl": fake_skidl}):
            exec(compiled, namespace)
        self.assertEqual(fake_skidl.NC.connections, 1)
        self.assertEqual(namespace["_pcbex_nets"]["N1"].connections, 2)

    def test_v2_envelope_rejects_forged_no_connect_relationships(self):
        spec = _spec_with_no_connect()
        cases = []

        bad = copy.deepcopy(spec)
        bad["parts"][0]["pins"][2]["electrical_type"] = "passive"
        cases.append((bad, "null net but is not no-connect"))

        bad = copy.deepcopy(spec)
        bad["parts"][0]["pins"][2]["net"] = "N1"
        cases.append((bad, "is no-connect but declares net"))

        bad = copy.deepcopy(spec)
        bad["nets"][0]["connections"].append({"reference": "R1", "pin": "3"})
        cases.append((bad, "connects no-connect pin"))

        bad = copy.deepcopy(spec)
        bad["parts"][0]["pins"][0]["net"] = "N2"
        cases.append((bad, "declares net"))

        bad = copy.deepcopy(spec)
        bad["parts"][0]["pins"].append(
            {
                "number": "4",
                "name": "UNWIRED",
                "net": "N1",
                "electrical_type": "passive",
            }
        )
        cases.append((bad, "is not connected to its declared net"))

        bad = copy.deepcopy(spec)
        bad["nets"].append(
            {
                "name": "N2",
                "voltage_uv": None,
                "connections": [
                    {"reference": "R1", "pin": "1"},
                    {"reference": "R1", "pin": "2"},
                ],
            }
        )
        cases.append((bad, "is connected to multiple nets"))

        bad = copy.deepcopy(spec)
        bad["nets"][0]["connections"].append({"reference": "R1", "pin": "1"})
        cases.append((bad, "native net N1 has an invalid connection"))

        for bad, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                CircuitGenerationError, message
            ):
                _validate_check_envelope(_check_envelope(bad))

    def test_provider_wrapper_preserves_shell_free_argv_and_remaining_float(self):
        result = BoundedProcessResult(("provider", "--arg"), 0, b"{}", b"")
        with patch("pcbex_agent.provider.run_bounded", return_value=result) as runner:
            self.assertEqual(
                run_provider_command(
                    ["provider", "--arg"],
                    "prompt",
                    timeout_seconds=0.25,
                    max_output_bytes=100,
                ),
                "{}",
            )
        kwargs = runner.call_args.kwargs
        self.assertEqual(kwargs["timeout_seconds"], 0.25)
        self.assertEqual(runner.call_args.args[0], ["provider", "--arg"])

    def test_cli_failure_does_not_publish_artifacts(self):
        from pcbex_agent import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            bundle = root / "bundle.json"
            skidl = root / "generated.py"
            requirements.write_text("make a resistor", encoding="utf-8")
            with patch.object(
                cli,
                "generate_circuit_with_command",
                side_effect=CircuitGenerationError("provider failed"),
            ), patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "generate-circuit",
                    str(requirements),
                    "-o",
                    str(bundle),
                    "--skidl-output",
                    str(skidl),
                    "--provider-command",
                    "provider",
                ],
            ), self.assertRaises(SystemExit):
                cli.main()
            self.assertFalse(bundle.exists())
            self.assertFalse(skidl.exists())


if __name__ == "__main__":
    unittest.main()

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pcbex_agent.catalog import (
    CatalogSelectionError,
    canonical_sha256,
    load_catalog_snapshot,
    select_catalog_parts,
    validate_catalog_receipt,
)
from pcbex_agent.circuit_generation import (
    CircuitCandidateRejected,
    CircuitGenerationError,
    circuit_generation_json_schema,
    generate_circuit_with_command,
    generate_circuit_with_llm,
)

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional validation aid
    Draft202012Validator = None


def _compact(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _spec(*, value="100nF", mpn=None):
    return {
        "schema_version": 2,
        "parts": [
            {
                "reference": "C1",
                "lib_id": "Device:C",
                "value": value,
                "footprint": "Capacitor_SMD:C_0603_1608Metric",
                "mpn": mpn,
                "power": {
                    "rail_voltage_uv": None,
                    "max_voltage_uv": None,
                    "requires_decoupling": False,
                    "decoupling": False,
                },
                "pins": [
                    {
                        "number": "1",
                        "name": "~",
                        "net": "N1",
                        "electrical_type": "passive",
                    },
                    {
                        "number": "2",
                        "name": "~",
                        "net": "N1",
                        "electrical_type": "passive",
                    },
                ],
            }
        ],
        "nets": [
            {
                "name": "N1",
                "voltage_uv": None,
                "connections": [
                    {"reference": "C1", "pin": "1"},
                    {"reference": "C1", "pin": "2"},
                ],
            }
        ],
    }


def _snapshot():
    return load_catalog_snapshot(
        {
            "schema_version": 1,
            "supplier": "jlcpcb",
            "snapshot_id": "test-snapshot",
            "captured_at_unix": 100,
            "expires_at_unix": 200,
            "parts": [
                {
                    "mpn": "C-100N",
                    "supplier_part_number": "C1234",
                    "description": "100nF ceramic capacitor",
                    "footprint": "Capacitor_SMD:C_0603_1608Metric",
                    "tags": ["100nF", "capacitor", "ceramic"],
                    "vendor": "Acme",
                    "stock": 8,
                    "basic": True,
                    "datasheet_url": "https://example.test/c-100n",
                }
            ],
        },
        evaluated_at_unix=150,
    )


def _review(errors=0):
    return {
        "schema_version": 1,
        "schematic_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "policy_id": "default",
        "approved": errors == 0,
        "counts": {"errors": errors, "warnings": 0, "info": 0},
        "findings": [
            {
                "id": f"pcbex-er-{index:016x}",
                "rule": "coverage_incomplete",
                "severity": "error",
                "message": "test error",
                "net_id": None,
                "symbols": [],
                "pins": [],
            }
            for index in range(errors)
        ],
    }


def _envelope(spec, *, errors=0):
    review = _review(errors)
    return {
        "schema_version": 1,
        "circuit_spec_sha256": hashlib.sha256(_compact(spec)).hexdigest(),
        "electrical_review_sha256": hashlib.sha256(_compact(review)).hexdigest(),
        "normalized_spec": spec,
        "electrical_review": review,
    }


class _Checker:
    def __init__(self, initial_specs, *, initial_errors=None, final_transform=None):
        self.initial_specs = list(initial_specs)
        self.initial_errors = list(initial_errors or [0] * len(self.initial_specs))
        self.final_transform = final_transform
        self.initial_calls = 0
        self.final_calls = 0

    def __call__(self, path, _remaining):
        if path.name.startswith("candidate-"):
            index = self.initial_calls
            self.initial_calls += 1
            return _envelope(
                self.initial_specs[index],
                errors=self.initial_errors[index],
            )
        self.final_calls += 1
        spec = json.loads(path.read_text(encoding="utf-8"))
        if self.final_transform is not None:
            spec = self.final_transform(spec)
        return _envelope(spec)


def _selector(snapshot):
    def select(spec, _remaining):
        return select_catalog_parts(spec, snapshot, evaluated_at_unix=150)

    return select


def _validator(snapshot):
    def validate(original, resolved, receipt, _remaining):
        return validate_catalog_receipt(
            receipt,
            original,
            resolved,
            snapshot,
            evaluated_at_unix=150,
        )

    return validate


def _reverse_object_keys(value):
    if isinstance(value, dict):
        return {
            key: _reverse_object_keys(child)
            for key, child in reversed(list(value.items()))
        }
    if isinstance(value, list):
        return [_reverse_object_keys(child) for child in value]
    return value


class CatalogGenerationV1412Tests(unittest.TestCase):
    def test_catalog_success_runs_two_native_gates_and_binds_evidence(self):
        initial = _spec()
        checker = _Checker([initial])
        snapshot = _snapshot()
        bundle = generate_circuit_with_llm(
            "make a capacitor",
            {"type": "object"},
            lambda _prompt, _remaining: '{"candidate":1}',
            checker,
            catalog_selector=_selector(snapshot),
            catalog_receipt_validator=_validator(snapshot),
        )

        self.assertEqual((checker.initial_calls, checker.final_calls), (1, 1))
        self.assertEqual(bundle["schema_version"], 2)
        self.assertEqual(bundle["spec"]["parts"][0]["mpn"], "C-100N")
        self.assertEqual(
            bundle["catalog_receipt_sha256"],
            canonical_sha256(bundle["catalog_receipt"]),
        )
        record = bundle["attempt_history"][0]
        self.assertNotEqual(record["spec_sha256"], record["resolved_spec_sha256"])
        self.assertNotEqual(
            record["circuit_spec_sha256"],
            record["resolved_circuit_spec_sha256"],
        )
        self.assertEqual(
            record["resolved_circuit_spec_sha256"],
            bundle["circuit_spec_sha256"],
        )
        self.assertIn("_PCBEX_MPN_BY_REFERENCE", bundle["skidl"])
        self.assertIn(bundle["catalog_receipt_sha256"], bundle["skidl"])

    def test_catalog_rejection_is_retryable_and_zero_erc_is_progress_floor(self):
        specs = [_spec(value="100nF"), _spec(value="100nF ceramic")]
        checker = _Checker(specs)
        responses = iter(['{"candidate":1}', '{"candidate":2}'])
        prompts = []
        calls = 0
        snapshot = _snapshot()

        def selector(spec, remaining):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise CatalogSelectionError("catalog policy needs another part")
            return _selector(_snapshot())(spec, remaining)

        def transport(prompt, _remaining):
            prompts.append(prompt)
            return next(responses)

        bundle = generate_circuit_with_llm(
            "make a capacitor",
            {"type": "object"},
            transport,
            checker,
            max_attempts=2,
            catalog_selector=selector,
            catalog_receipt_validator=_validator(snapshot),
        )
        self.assertEqual(
            [item["outcome"] for item in bundle["attempt_history"]],
            ["catalog_rejected", "approved"],
        )
        self.assertIn("catalog policy needs another part", prompts[1])
        self.assertNotIn("catalog policy needs another part", json.dumps(bundle))
        self.assertEqual((checker.initial_calls, checker.final_calls), (2, 1))

        checker = _Checker(specs, initial_errors=[0, 1])
        calls = 0
        failing_responses = iter(['{"candidate":1}', '{"candidate":2}'])

        def reject_first(_spec_value, _remaining):
            nonlocal calls
            calls += 1
            raise CatalogSelectionError("no match")

        with self.assertRaisesRegex(CircuitGenerationError, "strictly decrease"):
            generate_circuit_with_llm(
                "make a capacitor",
                {"type": "object"},
                lambda _prompt, _remaining: next(failing_responses),
                checker,
                max_attempts=2,
                catalog_selector=reject_first,
                catalog_receipt_validator=_validator(snapshot),
            )

    def test_catalog_selector_requires_validator_before_native_or_provider(self):
        checker = _Checker([_spec()])
        transport_calls = []

        with self.assertRaisesRegex(
            CircuitGenerationError,
            "catalog_receipt_validator.*is required",
        ):
            generate_circuit_with_llm(
                "make a capacitor",
                {"type": "object"},
                lambda prompt, remaining: transport_calls.append((prompt, remaining)),
                checker,
                catalog_selector=_selector(_snapshot()),
            )

        self.assertEqual(checker.initial_calls, 0)
        self.assertEqual(transport_calls, [])

    def test_forged_receipt_metadata_and_catalog_part_digests_are_hard_failures(self):
        snapshot = _snapshot()
        mutations = {
            "supplier": lambda receipt: receipt.__setitem__("supplier", "other"),
            "source digest": lambda receipt: receipt["source"].__setitem__(
                "sha256", "c" * 64
            ),
            "catalog digest": lambda receipt: receipt["catalog"].__setitem__(
                "sha256", "d" * 64
            ),
            "catalog part digest": lambda receipt: (
                receipt["selections"][0].__setitem__(
                    "catalog_part_sha256", "e" * 64
                ),
                receipt.__setitem__(
                    "selections_sha256", canonical_sha256(receipt["selections"])
                ),
            ),
        }

        for label, mutate in mutations.items():
            with self.subTest(label=label):
                checker = _Checker([_spec()])

                def forge(spec, remaining, mutate=mutate):
                    resolved, receipt = _selector(snapshot)(spec, remaining)
                    forged = copy.deepcopy(receipt)
                    mutate(forged)
                    return resolved, forged

                with self.assertRaisesRegex(
                    CircuitGenerationError,
                    "catalog receipt does not match recomputed selection",
                ):
                    generate_circuit_with_llm(
                        "make a capacitor",
                        {"type": "object"},
                        lambda _prompt, _remaining: "{}",
                        checker,
                        catalog_selector=forge,
                        catalog_receipt_validator=_validator(snapshot),
                    )

                self.assertEqual((checker.initial_calls, checker.final_calls), (1, 0))

    def test_receipt_validator_cannot_mutate_second_gate_artifacts(self):
        snapshot = _snapshot()
        checker = _Checker([_spec()])

        def mutating_validator(original, resolved, receipt, _remaining):
            original["nets"][0]["name"] = "FORGED-NET"
            resolved["parts"][0]["mpn"] = "FORGED-MPN"
            receipt["source"]["sha256"] = "f" * 64

        bundle = generate_circuit_with_llm(
            "make a capacitor",
            {"type": "object"},
            lambda _prompt, _remaining: "{}",
            checker,
            catalog_selector=_selector(snapshot),
            catalog_receipt_validator=mutating_validator,
        )

        self.assertEqual((checker.initial_calls, checker.final_calls), (1, 1))
        self.assertEqual(bundle["spec"]["parts"][0]["mpn"], "C-100N")
        self.assertEqual(bundle["spec"]["nets"][0]["name"], "N1")
        self.assertEqual(
            bundle["catalog_receipt"]["source"]["sha256"],
            snapshot.source_sha256,
        )

    def test_selector_cannot_change_non_mpn_data_or_forge_selections(self):
        checker = _Checker([_spec()])
        snapshot = _snapshot()

        def mutate(spec, _remaining):
            spec["nets"][0]["name"] = "MUTATED"
            return spec, {}

        with self.assertRaisesRegex(CircuitGenerationError, "changed circuit nets"):
            generate_circuit_with_llm(
                "make a capacitor",
                {"type": "object"},
                lambda _prompt, _remaining: "{}",
                checker,
                catalog_selector=mutate,
                catalog_receipt_validator=_validator(snapshot),
            )

        checker = _Checker([_spec()])

        def forge(spec, remaining):
            resolved, receipt = _selector(_snapshot())(spec, remaining)
            receipt = copy.deepcopy(receipt)
            receipt["selections"][0]["mpn"] = "FORGED"
            receipt["selections_sha256"] = canonical_sha256(receipt["selections"])
            return resolved, receipt

        with self.assertRaisesRegex(CircuitGenerationError, "does not match resolved part"):
            generate_circuit_with_llm(
                "make a capacitor",
                {"type": "object"},
                lambda _prompt, _remaining: "{}",
                checker,
                catalog_selector=forge,
                catalog_receipt_validator=_validator(snapshot),
            )

    def test_shared_alias_mutation_isolated_and_reordered_final_keys_are_allowed(self):
        shared = _spec()
        checker = _Checker([shared], final_transform=_reverse_object_keys)
        snapshot = _snapshot()

        def selector(spec, remaining):
            shared["nets"][0]["name"] = "MUTATED-OUTSIDE"
            return _selector(_snapshot())(spec, remaining)

        bundle = generate_circuit_with_llm(
            "make a capacitor",
            {"type": "object"},
            lambda _prompt, _remaining: "{}",
            checker,
            catalog_selector=selector,
            catalog_receipt_validator=_validator(snapshot),
        )
        self.assertEqual(bundle["spec"]["nets"][0]["name"], "N1")
        self.assertEqual(bundle["catalog_receipt"]["input_spec_sha256"], canonical_sha256(_spec()))

    def test_second_gate_rejection_and_post_selector_deadline_fail_closed(self):
        initial = _spec()

        def reject_final(path, _remaining):
            if path.name.startswith("candidate-"):
                return _envelope(initial)
            raise CircuitCandidateRejected("resolved candidate rejected")

        with self.assertRaisesRegex(CircuitCandidateRejected, "resolved candidate"):
            snapshot = _snapshot()
            generate_circuit_with_llm(
                "make a capacitor",
                {"type": "object"},
                lambda _prompt, _remaining: "{}",
                reject_final,
                catalog_selector=_selector(snapshot),
                catalog_receipt_validator=_validator(snapshot),
            )

        expired = False
        checker = _Checker([initial])
        snapshot = _snapshot()

        def clock():
            return 11.0 if expired else 0.0

        def expire_after_selection(spec, remaining):
            nonlocal expired
            result = _selector(_snapshot())(spec, remaining)
            expired = True
            return result

        with self.assertRaisesRegex(CircuitGenerationError, "aggregate deadline"):
            generate_circuit_with_llm(
                "make a capacitor",
                {"type": "object"},
                lambda _prompt, _remaining: "{}",
                checker,
                timeout_seconds=10,
                catalog_selector=expire_after_selection,
                catalog_receipt_validator=_validator(snapshot),
                _clock=clock,
            )
        self.assertEqual((checker.initial_calls, checker.final_calls), (1, 0))

    def test_command_catalog_contract_preflights_before_native_or_provider(self):
        with patch("pcbex_agent.circuit_generation._command_json") as command:
            with self.assertRaisesRegex(CircuitGenerationError, "snapshot validation"):
                generate_circuit_with_command(
                    "requirements",
                    "pcbex",
                    ["provider"],
                    catalog_snapshot=b"not-json",
                    _clock=lambda: 0.0,
                    _wall_clock=lambda: 150.0,
                )
            command.assert_not_called()

        with patch("pcbex_agent.circuit_generation._command_json") as command:
            with self.assertRaisesRegex(CircuitGenerationError, "require a catalog"):
                generate_circuit_with_command(
                    "requirements",
                    "pcbex",
                    ["provider"],
                    require_basic=True,
                    _clock=lambda: 0.0,
                )
            command.assert_not_called()

    def test_catalog_schema_cli_is_closed_and_refuses_clobber(self):
        from pcbex_agent import cli

        commands = (
            ("catalog-snapshot-schema", "schema_version"),
            ("catalog-selection-receipt-schema", "adapter"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for command, required_property in commands:
                with self.subTest(command=command):
                    output = root / f"{command}.json"
                    with patch.object(
                        sys,
                        "argv",
                        ["pcbex-agent", command, "--output", str(output)],
                    ):
                        cli.main()
                    schema = json.loads(output.read_text(encoding="utf-8"))
                    self.assertFalse(schema["additionalProperties"])
                    self.assertIn(required_property, schema["properties"])
                    original = output.read_bytes()
                    with (
                        patch.object(
                            sys,
                            "argv",
                            ["pcbex-agent", command, "--output", str(output)],
                        ),
                        self.assertRaises(SystemExit),
                    ):
                        cli.main()
                    self.assertEqual(output.read_bytes(), original)

    def test_generate_circuit_cli_forwards_catalog_policy_after_preflight(self):
        from pcbex_agent import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            snapshot_path = root / "snapshot.json"
            output = root / "bundle.json"
            requirements.write_text("make a capacitor", encoding="utf-8")
            snapshot_path.write_text("{}", encoding="utf-8")
            sentinel_snapshot = object()
            bundle = {"schema_version": 2, "skidl": "# generated\n"}
            argv = [
                "pcbex-agent",
                "generate-circuit",
                str(requirements),
                "--output",
                str(output),
                "--catalog-snapshot",
                str(snapshot_path),
                "--allow-out-of-stock",
                "--require-basic",
                "--allow-footprint-fallback",
                "--provider-command",
                "provider",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    cli,
                    "load_catalog_snapshot",
                    return_value=sentinel_snapshot,
                ) as load_snapshot,
                patch.object(
                    cli,
                    "generate_circuit_with_command",
                    return_value=bundle,
                ) as generate,
            ):
                cli.main()
            load_snapshot.assert_called_once_with(snapshot_path)
            self.assertIs(generate.call_args.kwargs["catalog_snapshot"], sentinel_snapshot)
            self.assertFalse(generate.call_args.kwargs["require_available"])
            self.assertTrue(generate.call_args.kwargs["require_basic"])
            self.assertTrue(generate.call_args.kwargs["allow_footprint_fallback"])
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), bundle)

            with (
                patch.object(sys, "argv", argv),
                patch.object(cli, "load_catalog_snapshot") as load_snapshot,
                patch.object(cli, "generate_circuit_with_command") as generate,
                self.assertRaises(SystemExit),
            ):
                cli.main()
            load_snapshot.assert_not_called()
            generate.assert_not_called()

    @unittest.skipUnless(Path("target/debug/pcbex").is_file(), "Rust pcbex binary is not built")
    def test_command_adapter_round_trips_catalog_through_real_rust_checker(self):
        raw = json.dumps(_spec(), separators=(",", ":"))
        bundle = generate_circuit_with_command(
            "make a capacitor",
            "target/debug/pcbex",
            [sys.executable, "-c", "import sys;sys.stdout.write(sys.argv[1])", raw],
            catalog_snapshot=_snapshot(),
            evaluated_at_unix=150,
            timeout_seconds=30,
        )
        self.assertTrue(bundle["check"]["electrical_review"]["approved"])
        self.assertEqual(bundle["spec"]["parts"][0]["mpn"], "C-100N")
        self.assertEqual(bundle["attempt_history"][0]["outcome"], "approved")

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_bundle_schema_correlates_catalog_receipt_history_and_mpns(self):
        checker = _Checker([_spec()])
        snapshot = _snapshot()
        bundle = generate_circuit_with_llm(
            "make a capacitor",
            {"type": "object"},
            lambda _prompt, _remaining: "{}",
            checker,
            catalog_selector=_selector(snapshot),
            catalog_receipt_validator=_validator(snapshot),
        )
        validator = Draft202012Validator(circuit_generation_json_schema())
        self.assertEqual(list(validator.iter_errors(bundle)), [])

        mismatches = []
        value = copy.deepcopy(bundle)
        value["catalog_receipt_sha256"] = None
        mismatches.append(value)
        value = copy.deepcopy(bundle)
        value["attempt_history"][0]["resolved_spec_sha256"] = None
        mismatches.append(value)
        value = copy.deepcopy(bundle)
        value["catalog_receipt"] = None
        value["catalog_receipt_sha256"] = None
        mismatches.append(value)
        value = copy.deepcopy(bundle)
        value["spec"]["parts"][0]["mpn"] = None
        mismatches.append(value)
        value = copy.deepcopy(bundle)
        value["attempt_history"].append(copy.deepcopy(value["attempt_history"][0]))
        value["attempt_history"][-1]["outcome"] = "electrical_rejected"
        value["attempts"] = 2
        mismatches.append(value)
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatches.index(mismatch)):
                self.assertTrue(list(validator.iter_errors(mismatch)))


if __name__ == "__main__":
    unittest.main()

import json
import http.server
import sys
import threading
import time
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pcbex_agent.cli import main as agent_main
from pcbex_agent.catalog import CatalogPart, catalog_parts_from_json, search_parts
from pcbex_agent.catalog_remote import CatalogEndpoint, CatalogRemoteError, fetch_catalog
from pcbex_agent.circuit_generation import (
    CircuitGenerationError,
    circuit_generation_json_schema,
    generate_circuit_with_llm,
)
from pcbex_agent.circuit import (
    circuit_spec_to_kicad_pcb,
    circuit_spec_to_netlist,
    circuit_spec_to_placement_problem,
    skidl_to_placement_problem,
)
from pcbex_agent.firmware import firmware_bundle_json_schema, generate_firmware_bundle
from pcbex_agent.pipeline import pipeline_run_json_schema, run_hardware_pipeline
from pcbex_agent.factory import FactoryEndpoint, factory_submission_json_schema, submit_factory_package
from pcbex_agent.drc import normalize_kicad_report
from pcbex_agent.executor import ScoreComparison, run_bounded
from pcbex_agent.models import DrcViolation, PlanLimits
from pcbex_agent.managed_provider import (
    managed_provider_receipt_json_schema,
    review_schematic_with_managed_provider,
)
from pcbex_agent.planner import build_plan
from pcbex_agent.provider import (
    ProviderError,
    provider_receipt_json_schema,
    review_schematic_with_command,
)
from pcbex_agent.repair import propose_repairs
from pcbex_agent.repair_loop import run_repair_loop
from pcbex_agent.llm import build_plan_with_llm
from pcbex_agent.ipc import apply_routes_to_open_board
from pcbex_agent.review import review_schematic_with_llm
from pcbex_agent.skidl import (
    CircuitSpecError,
    assign_catalog_parts,
    check_circuit_electrical,
    circuit_erc_json_schema,
    circuit_spec_json_schema,
    generate_skidl,
)


class PlannerTests(unittest.TestCase):
    def test_builds_structured_constraints_in_english_and_japanese(self):
        plan = build_plan(
            "Place C12 near U1 within 2 mm.\n"
            "J1を基板の左端から3mm以内。\n"
            "keep U1, C10, C11 together within 8 mm"
        )
        self.assertEqual([c.type for c in plan.constraints], [
            "near", "board_edge", "keep_together"
        ])
        self.assertEqual(plan.constraints[0].parameters["max_distance_nm"], 2_000_000)
        self.assertEqual(plan.unsupported_requirements, [])

    def test_ambiguous_requirement_is_reported_not_guessed(self):
        plan = build_plan("Make the board aesthetically pleasing")
        self.assertEqual(len(plan.constraints), 0)
        self.assertEqual(len(plan.unsupported_requirements), 1)


class RepairTests(unittest.TestCase):
    def test_normalizes_drc_and_proposes_reroute(self):
        report = """[clearance]: Track clearance violation
    Severity: error
    @(track A)
    @(pad B)
"""
        violations = normalize_kicad_report(report)
        self.assertEqual(violations[0].rule, "clearance")
        self.assertEqual(violations[0].items, ("track A", "pad B"))
        self.assertEqual(propose_repairs(violations)[0].kind, "reroute")

    def test_normalizes_kicad_10_report_shape(self):
        report = """[clearance]: Clearance violation
    Local override; warning
    @(5.0000 mm, 10.0000 mm): Track [SIGNAL]
"""
        violation = normalize_kicad_report(report)[0]
        self.assertEqual(violation.severity, "warning")
        self.assertEqual(
            violation.items, ("5.0000 mm, 10.0000 mm: Track [SIGNAL]",)
        )

    def test_bounded_executor_rejects_excessive_changes(self):
        plan = build_plan("C1 near U1 within 2 mm", limits=PlanLimits(3, 2))
        values = [
            ScoreComparison(100, 90, 4),
            ScoreComparison(100, 95, 2),
            ScoreComparison(100, 80, 1),
        ]
        result = run_bounded(plan, lambda i: values[i])
        self.assertEqual(result.after, 80)

    def test_repair_loop_atomically_accepts_first_clean_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.kicad_pcb"
            output = root / "output.kicad_pcb"
            source.write_text("source", encoding="utf-8")
            output.write_text("original output", encoding="utf-8")

            def generate(_source, candidate, iteration, _actions):
                candidate.write_text(f"candidate {iteration}", encoding="utf-8")
                self.assertEqual(output.read_text(encoding="utf-8"), "original output")

            def inspect(candidate, _report):
                iteration = int(candidate.read_text(encoding="utf-8").split()[-1])
                if iteration < 2:
                    return [
                        DrcViolation("clearance", "error", f"remaining {2 - iteration}")
                    ]
                return []

            result = run_repair_loop(
                source,
                output,
                max_iterations=4,
                generate_candidate=generate,
                inspect_drc=inspect,
            )
            self.assertTrue(result.success)
            self.assertEqual(len(result.iterations), 3)
            self.assertEqual(output.read_text(encoding="utf-8"), "candidate 2")

    def test_repair_loop_stops_on_repeated_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.kicad_pcb"
            output = root / "output.kicad_pcb"
            source.write_text("source", encoding="utf-8")

            def generate(_source, candidate, _iteration, _actions):
                candidate.write_text("unchanged", encoding="utf-8")

            def inspect(_candidate, _report):
                return [DrcViolation("clearance", "error", "same violation")]

            result = run_repair_loop(
                source,
                output,
                max_iterations=4,
                generate_candidate=generate,
                inspect_drc=inspect,
            )
            self.assertFalse(result.success)
            self.assertEqual(result.stop_reason, "repeated_candidate")
            self.assertEqual(len(result.iterations), 2)
            self.assertFalse(output.exists())


class AdapterTests(unittest.TestCase):
    @staticmethod
    def _managed_review_fixture():
        request = {
            "schema_version": 1,
            "request_sha256": "a" * 64,
            "requirements": [{"id": "power", "text": "Power is valid"}],
            "evidence_ids": ["electrical-review"],
        }
        response = {
            "schema_version": 1,
            "request_sha256": "a" * 64,
            "model": {"provider": "untrusted", "model": "claim", "version": "x"},
            "decision": "approve",
            "summary": "Evidence is complete.",
            "requirements": [{
                "id": "power",
                "status": "pass",
                "rationale": "The deterministic review passed.",
                "evidence_refs": ["electrical-review"],
            }],
            "risks": [],
        }
        return request, response

    @staticmethod
    def _serve_provider(
        envelope,
        *,
        content_type="application/json",
        delay=0,
        status=200,
        location=None,
    ):
        state = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                state["path"] = self.path
                state["headers"] = {
                    name.lower(): value for name, value in self.headers.items()
                }
                state["body"] = self.rfile.read(length)
                time.sleep(delay)
                encoded = json.dumps(envelope).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(encoded)))
                if location is not None:
                    self.send_header("Location", location)
                self.end_headers()
                try:
                    self.wfile.write(encoded)
                except BrokenPipeError:
                    pass

            def log_message(self, _format, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, state

    def test_llm_adapter_rejects_coordinates(self):
        response = (
            '{"constraints":[{"type":"near","parameters":'
            '{"subject":"C1","target":"U1","x_nm":2}, "source":"x"}]}'
        )
        with self.assertRaises(ValueError):
            build_plan_with_llm("place C1", lambda _prompt: response)

    def test_circuit_generation_retries_after_deterministic_validation(self):
        valid = {
            "schema_version": 1,
            "parts": [
                {
                    "reference": "R1",
                    "lib_id": "Device:R",
                    "value": "10k",
                    "footprint": "Resistor_SMD:R_0603",
                    "pins": {"1": "VCC", "2": "GND"},
                }
            ],
            "nets": [
                {
                    "name": "VCC",
                    "connections": [{"reference": "R1", "pin": "1"}, {"reference": "R1", "pin": "2"}],
                }
            ],
        }
        prompts = []

        def transport(prompt):
            prompts.append(prompt)
            return json.dumps({"schema_version": 1, "parts": [], "nets": []}) if len(prompts) == 1 else json.dumps(valid)

        result = generate_circuit_with_llm("Connect a resistor", transport)
        self.assertTrue(result["repaired"])
        self.assertEqual(result["attempts"], 2)
        self.assertIn("Validation error", prompts[1])
        self.assertIn("Part(\"Device\", \"R\"", result["skidl"])

    def test_circuit_generation_rejects_unrepairable_model(self):
        with self.assertRaises(CircuitGenerationError):
            generate_circuit_with_llm(
                "unsafe",
                lambda _prompt: "not json",
                max_attempts=2,
            )

    def test_circuit_generation_schema_is_closed(self):
        schema = circuit_generation_json_schema()
        self.assertTrue(schema["additionalProperties"] is False)
        self.assertIn("skidl", schema["required"])
        self.assertIn("erc", schema["required"])

    def test_circuit_erc_blocks_overvoltage_and_missing_decoupling(self):
        spec = {
            "schema_version": 1,
            "parts": [{
                "reference": "U1",
                "lib_id": "MCU:Example",
                "value": "controller",
                "footprint": "QFN-16",
                "pins": {"1": "5V", "2": "GND"},
                "electrical": {
                    "pin_max_voltage_v": {"1": 3.3},
                    "requires_decoupling": True,
                },
            }],
            "nets": [
                {"name": "5V", "connections": [{"reference": "U1", "pin": "1"}, {"reference": "U1", "pin": "2"}]},
            ],
        }
        report = check_circuit_electrical(spec)
        self.assertFalse(report["passed"])
        self.assertEqual(
            {finding["code"] for finding in report["findings"]},
            {"power_input_voltage_exceeded", "missing_decoupling_capacitor"},
        )
        self.assertFalse(circuit_erc_json_schema()["additionalProperties"])

    def test_circuit_erc_accepts_matching_rail_and_bypass(self):
        spec = {
            "schema_version": 1,
            "parts": [
                {
                    "reference": "U1",
                    "lib_id": "MCU:Example",
                    "value": "controller",
                    "footprint": "QFN-16",
                    "pins": {"1": "3V3", "2": "GND"},
                    "electrical": {
                        "pin_max_voltage_v": {"1": 3.3},
                        "requires_decoupling": True,
                    },
                },
                {
                    "reference": "C1",
                    "lib_id": "Device:C",
                    "value": "100nF",
                    "footprint": "C_0603",
                    "pins": {"1": "3V3", "2": "GND"},
                    "electrical": {"decoupling": True},
                },
            ],
            "nets": [
                {"name": "3V3", "connections": [{"reference": "U1", "pin": "1"}, {"reference": "C1", "pin": "1"}]},
                {"name": "GND", "connections": [{"reference": "U1", "pin": "2"}, {"reference": "C1", "pin": "2"}]},
            ],
        }
        report = check_circuit_electrical(spec)
        self.assertTrue(report["passed"], report)

    def test_circuit_erc_rejects_incompatible_power_drivers(self):
        spec = {
            "schema_version": 1,
            "parts": [
                {
                    "reference": "U1",
                    "lib_id": "Regulator:FiveVolt",
                    "value": "5V regulator",
                    "footprint": "SOT-23",
                    "pins": {"1": "RAIL"},
                    "electrical": {"power_output_v": 5.0},
                },
                {
                    "reference": "U2",
                    "lib_id": "Regulator:ThreeVolt",
                    "value": "3V3 regulator",
                    "footprint": "SOT-23",
                    "pins": {"1": "RAIL"},
                    "electrical": {"power_output_v": 3.3},
                },
            ],
            "nets": [{"name": "RAIL", "connections": [{"reference": "U1", "pin": "1"}, {"reference": "U2", "pin": "1"}]}],
        }
        report = check_circuit_electrical(spec)
        self.assertFalse(report["passed"])
        self.assertIn("multiple_power_outputs", {finding["code"] for finding in report["findings"]})
        self.assertIn("power_rail_voltage_conflict", {finding["code"] for finding in report["findings"]})

    def test_circuit_generation_retries_after_electrical_erc_failure(self):
        invalid = {
            "schema_version": 1,
            "parts": [{
                "reference": "U1",
                "lib_id": "MCU:Example",
                "value": "controller",
                "footprint": "QFN-16",
                "pins": {"1": "5V", "2": "GND"},
                "electrical": {"pin_max_voltage_v": {"1": 3.3}},
            }],
            "nets": [{"name": "5V", "connections": [{"reference": "U1", "pin": "1"}, {"reference": "U1", "pin": "2"}]}],
        }
        valid = {
            **invalid,
            "parts": [{
                **invalid["parts"][0],
                "electrical": {"pin_max_voltage_v": {"1": 5.0}},
            }],
        }
        prompts = []

        def transport(prompt):
            prompts.append(prompt)
            return json.dumps(invalid if len(prompts) == 1 else valid)

        result = generate_circuit_with_llm("Power a controller", transport)
        self.assertTrue(result["repaired"])
        self.assertTrue(result["erc"]["passed"])
        self.assertIn("electrical ERC failed", prompts[1])

    def test_generate_circuit_cli_writes_bundle_and_skidl(self):
        response = {
            "schema_version": 1,
            "parts": [{
                "reference": "C1",
                "lib_id": "Device:C",
                "value": "100nF",
                "footprint": "Capacitor_SMD:C_0603",
                "pins": {"1": "VCC", "2": "GND"},
            }],
            "nets": [
                {"name": "VCC", "connections": [
                    {"reference": "C1", "pin": "1"},
                    {"reference": "C1", "pin": "2"},
                ]}
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            bundle = root / "bundle.json"
            skidl = root / "circuit.py"
            requirements.write_text("Add a 100nF bypass capacitor", encoding="utf-8")
            provider = (
                "import sys; sys.stdin.read(); "
                f"print({json.dumps(json.dumps(response))})"
            )
            with patch.object(
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
                    sys.executable,
                    "-c",
                    provider,
                ],
            ):
                agent_main()
            generated = json.loads(bundle.read_text(encoding="utf-8"))
            self.assertEqual(generated["spec"]["parts"][0]["reference"], "C1")
            self.assertIn("Part(\"Device\", \"C\"", skidl.read_text(encoding="utf-8"))

    def test_schematic_review_adapter_accepts_only_bound_complete_evidence(self):
        request = {
            "schema_version": 1,
            "request_sha256": "a" * 64,
            "requirements": [{"id": "power", "text": "Power is valid"}],
            "evidence_ids": ["electrical-review"],
        }
        response = {
            "schema_version": 1,
            "request_sha256": "a" * 64,
            "model": {"provider": "test", "model": "reviewer", "version": "1"},
            "decision": "approve",
            "summary": "Evidence is complete.",
            "requirements": [{
                "id": "power",
                "status": "pass",
                "rationale": "The deterministic review passed.",
                "evidence_refs": ["electrical-review"],
            }],
            "risks": [],
        }
        result = review_schematic_with_llm(
            request, lambda _prompt: json.dumps(response)
        )
        self.assertEqual(result["decision"], "approve")

    def test_schematic_review_adapter_rejects_invented_evidence(self):
        request = {
            "schema_version": 1,
            "request_sha256": "a" * 64,
            "requirements": [{"id": "power", "text": "Power is valid"}],
            "evidence_ids": ["electrical-review"],
        }
        response = {
            "schema_version": 1,
            "request_sha256": "a" * 64,
            "model": {"provider": "test", "model": "reviewer", "version": None},
            "decision": "approve",
            "summary": "Evidence is complete.",
            "requirements": [{
                "id": "power",
                "status": "pass",
                "rationale": "Claimed evidence.",
                "evidence_refs": ["invented"],
            }],
            "risks": [],
        }
        with self.assertRaises(ValueError):
            review_schematic_with_llm(
                request, lambda _prompt: json.dumps(response)
            )

    def test_command_provider_writes_bound_response_and_receipt(self):
        request = {
            "schema_version": 1,
            "request_sha256": "a" * 64,
            "requirements": [{"id": "power", "text": "Power is valid"}],
            "evidence_ids": ["electrical-review"],
        }
        response = {
            "schema_version": 1,
            "request_sha256": "a" * 64,
            "model": {"provider": "test", "model": "reviewer", "version": "1"},
            "decision": "approve",
            "summary": "Evidence is complete.",
            "requirements": [{
                "id": "power",
                "status": "pass",
                "rationale": "The deterministic review passed.",
                "evidence_refs": ["electrical-review"],
            }],
            "risks": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            output_path = root / "response.json"
            receipt_path = root / "receipt.json"
            request_path.write_text(json.dumps(request), encoding="utf-8")
            provider = (
                "import sys;"
                "sys.stdin.read();"
                f"print({json.dumps(json.dumps(response))})"
            )
            receipt = review_schematic_with_command(
                request_path,
                output_path,
                receipt_path,
                [sys.executable, "-c", provider],
            )
            self.assertEqual(
                json.loads(output_path.read_text())["decision"], "approve"
            )
            self.assertEqual(receipt["adapter"], "provider-command-v1")
            self.assertEqual(len(receipt["request"]["sha256"]), 64)
            self.assertEqual(
                json.loads(receipt_path.read_text())["response"]["sha256"],
                receipt["response"]["sha256"],
            )
            original = output_path.read_bytes()
            with self.assertRaisesRegex(ProviderError, "refuses to overwrite"):
                review_schematic_with_command(
                    request_path,
                    output_path,
                    receipt_path,
                    [sys.executable, "-c", provider],
                )
            self.assertEqual(output_path.read_bytes(), original)

    def test_command_provider_enforces_output_limit_without_writing_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            output_path = root / "response.json"
            receipt_path = root / "receipt.json"
            request_path.write_text(
                json.dumps({
                    "schema_version": 1,
                    "request_sha256": "a" * 64,
                    "requirements": [],
                    "evidence_ids": [],
                }),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ProviderError, "exceeded 100 bytes"):
                review_schematic_with_command(
                    request_path,
                    output_path,
                    receipt_path,
                    [sys.executable, "-c", "print('x' * 1000)"],
                    max_output_bytes=100,
                )
            self.assertFalse(output_path.exists())
            self.assertFalse(receipt_path.exists())

    def test_provider_receipt_schema_is_closed_and_versioned(self):
        schema = provider_receipt_json_schema()
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(
            schema["properties"]["response"]["additionalProperties"]
        )

    def test_command_provider_timeout_includes_blocked_prompt_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps({
                    "schema_version": 1,
                    "request_sha256": "a" * 64,
                    "requirements": [],
                    "evidence_ids": [],
                    "padding": "x" * 1_000_000,
                }),
                encoding="utf-8",
            )
            started = time.monotonic()
            with self.assertRaisesRegex(ProviderError, "exceeded 1 second"):
                review_schematic_with_command(
                    request_path,
                    root / "response.json",
                    root / "receipt.json",
                    [
                        sys.executable,
                        "-c",
                        "import time; time.sleep(10)",
                    ],
                    timeout_seconds=1,
                )
            self.assertLess(time.monotonic() - started, 3)

    def test_command_provider_cli_preserves_adapter_arguments_without_a_shell(self):
        receipt = {
            "request": {"sha256": "a" * 64},
            "response": {"sha256": "b" * 64},
        }
        arguments = [
            "pcbex-agent",
            "review-schematic",
            "request.json",
            "--output",
            "response.json",
            "--receipt",
            "receipt.json",
            "--provider-command",
            "adapter",
            "--model",
            "reviewer",
        ]
        with (
            patch("sys.argv", arguments),
            patch(
                "pcbex_agent.cli.review_schematic_with_command",
                return_value=receipt,
            ) as review,
        ):
            agent_main()
        self.assertEqual(
            review.call_args.args[3], ["adapter", "--model", "reviewer"]
        )

    def test_managed_providers_normalize_three_official_response_envelopes(self):
        request, response = self._managed_review_fixture()
        structured = json.dumps(response)
        envelopes = {
            "openai": {
                "status": "completed",
                "output": [{
                    "type": "message",
                    "content": [{"type": "output_text", "text": structured}],
                }],
            },
            "anthropic": {
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": structured}],
            },
            "gemini": {
                "candidates": [{
                    "finishReason": "STOP",
                    "content": {"parts": [{"text": structured}]},
                }],
            },
        }
        for provider, envelope in envelopes.items():
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as directory:
                server, thread, state = self._serve_provider(envelope)
                try:
                    root = Path(directory)
                    request_path = root / "request.json"
                    output_path = root / "response.json"
                    receipt_path = root / "receipt.json"
                    request_path.write_text(json.dumps(request), encoding="utf-8")
                    with patch.dict("os.environ", {"PCBEX_TEST_KEY": "top-secret"}):
                        receipt = review_schematic_with_managed_provider(
                            request_path,
                            output_path,
                            receipt_path,
                            provider=provider,
                            model="review-model",
                            model_version="2026-07-29",
                            api_key_environment="PCBEX_TEST_KEY",
                            endpoint=(
                                f"http://127.0.0.1:{server.server_port}/review"
                            ),
                            allow_insecure_loopback=True,
                        )
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join()
                normalized = json.loads(output_path.read_text())
                self.assertEqual(normalized["model"], {
                    "provider": provider,
                    "model": "review-model",
                    "version": "2026-07-29",
                })
                self.assertEqual(receipt["adapter"], "managed-provider-http-v1")
                self.assertNotIn("top-secret", receipt_path.read_text())
                sent = json.loads(state["body"])
                if provider == "openai":
                    self.assertEqual(
                        state["headers"]["authorization"], "Bearer top-secret"
                    )
                    self.assertFalse(sent["store"])
                    self.assertTrue(sent["text"]["format"]["strict"])
                elif provider == "anthropic":
                    self.assertEqual(state["headers"]["x-api-key"], "top-secret")
                    self.assertEqual(
                        sent["output_config"]["format"]["type"], "json_schema"
                    )
                else:
                    self.assertEqual(
                        state["headers"]["x-goog-api-key"], "top-secret"
                    )
                    self.assertEqual(
                        sent["generationConfig"]["responseFormat"]["text"]["mimeType"],
                        "application/json",
                    )

    def test_managed_provider_rejects_unsafe_endpoint_before_network_access(self):
        request, _response = self._managed_review_fixture()
        unsafe = (
            "http://api.example/review",
            "https://user:password@api.example/review",
            "https://api.example/review?key=secret",
            "https://api.example/review#fragment",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request), encoding="utf-8")
            for index, endpoint in enumerate(unsafe):
                with (
                    self.subTest(endpoint=endpoint),
                    patch.dict("os.environ", {"PCBEX_TEST_KEY": "secret"}),
                    self.assertRaises(ProviderError),
                ):
                    review_schematic_with_managed_provider(
                        request_path,
                        root / f"response-{index}.json",
                        root / f"receipt-{index}.json",
                        provider="openai",
                        model="review-model",
                        api_key_environment="PCBEX_TEST_KEY",
                        endpoint=endpoint,
                    )

    def test_managed_provider_failure_writes_no_artifacts(self):
        request, _response = self._managed_review_fixture()
        envelope = {"status": "incomplete", "output": []}
        server, thread, _state = self._serve_provider(envelope)
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                request_path = root / "request.json"
                output_path = root / "response.json"
                receipt_path = root / "receipt.json"
                request_path.write_text(json.dumps(request), encoding="utf-8")
                with (
                    patch.dict("os.environ", {"PCBEX_TEST_KEY": "secret"}),
                    self.assertRaisesRegex(ProviderError, "did not complete"),
                ):
                    review_schematic_with_managed_provider(
                        request_path,
                        output_path,
                        receipt_path,
                        provider="openai",
                        model="review-model",
                        api_key_environment="PCBEX_TEST_KEY",
                        endpoint=f"http://127.0.0.1:{server.server_port}/review",
                        allow_insecure_loopback=True,
                    )
                self.assertFalse(output_path.exists())
                self.assertFalse(receipt_path.exists())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_managed_provider_does_not_follow_redirects(self):
        request, _response = self._managed_review_fixture()
        server, thread, state = self._serve_provider(
            {},
            status=307,
            location="https://redirected.example/review",
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                request_path = root / "request.json"
                request_path.write_text(json.dumps(request), encoding="utf-8")
                with (
                    patch.dict("os.environ", {"PCBEX_TEST_KEY": "secret"}),
                    self.assertRaisesRegex(ProviderError, "HTTP 307"),
                ):
                    review_schematic_with_managed_provider(
                        request_path,
                        root / "response.json",
                        root / "receipt.json",
                        provider="openai",
                        model="review-model",
                        api_key_environment="PCBEX_TEST_KEY",
                        endpoint=f"http://127.0.0.1:{server.server_port}/review",
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(state["path"], "/review")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_managed_provider_enforces_response_limit(self):
        request, _response = self._managed_review_fixture()
        server, thread, _state = self._serve_provider({
            "status": "completed",
            "output": [{"type": "message", "content": [{
                "type": "output_text", "text": "x" * 1000,
            }]}],
        })
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                request_path = root / "request.json"
                request_path.write_text(json.dumps(request), encoding="utf-8")
                with (
                    patch.dict("os.environ", {"PCBEX_TEST_KEY": "secret"}),
                    self.assertRaisesRegex(ProviderError, "exceeds 100 bytes"),
                ):
                    review_schematic_with_managed_provider(
                        request_path,
                        root / "response.json",
                        root / "receipt.json",
                        provider="openai",
                        model="review-model",
                        api_key_environment="PCBEX_TEST_KEY",
                        endpoint=f"http://127.0.0.1:{server.server_port}/review",
                        max_response_bytes=100,
                        allow_insecure_loopback=True,
                    )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_managed_provider_enforces_end_to_end_timeout(self):
        request, response = self._managed_review_fixture()
        envelope = {
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{
                    "type": "output_text",
                    "text": json.dumps(response),
                }],
            }],
        }
        server, thread, _state = self._serve_provider(envelope, delay=3)
        started = time.monotonic()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                request_path = root / "request.json"
                request_path.write_text(json.dumps(request), encoding="utf-8")
                with (
                    patch.dict("os.environ", {"PCBEX_TEST_KEY": "secret"}),
                    self.assertRaisesRegex(ProviderError, "exceeded 1 second"),
                ):
                    review_schematic_with_managed_provider(
                        request_path,
                        root / "response.json",
                        root / "receipt.json",
                        provider="openai",
                        model="review-model",
                        api_key_environment="PCBEX_TEST_KEY",
                        endpoint=f"http://127.0.0.1:{server.server_port}/review",
                        timeout_seconds=1,
                        allow_insecure_loopback=True,
                    )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertLess(time.monotonic() - started, 2.5)

    def test_managed_provider_requires_environment_secret(self):
        request, _response = self._managed_review_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request), encoding="utf-8")
            with (
                patch.dict("os.environ", {}, clear=True),
                self.assertRaisesRegex(ProviderError, "OPENAI_API_KEY is not set"),
            ):
                review_schematic_with_managed_provider(
                    request_path,
                    root / "response.json",
                    root / "receipt.json",
                    provider="openai",
                    model="review-model",
                )

    def test_managed_provider_receipt_schema_is_closed_and_secret_free(self):
        schema = managed_provider_receipt_json_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["adapter"]["const"],
            "managed-provider-http-v1",
        )
        self.assertNotIn("api_key", json.dumps(schema))

    def test_managed_provider_action_keeps_secret_out_of_process_arguments(self):
        action = (
            Path(__file__).parents[2]
            / ".github/actions/managed-ai-review/action.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "PCBEX_MANAGED_PROVIDER_API_KEY: ${{ inputs.api-key }}", action
        )
        self.assertIn(
            "--api-key-environment PCBEX_MANAGED_PROVIDER_API_KEY", action
        )
        self.assertNotIn("--api-key \"$PCBEX_MANAGED_PROVIDER_API_KEY\"", action)
        self.assertIn("value: ${{ steps.review.outputs.receipt }}", action)

    def test_catalog_search_is_ranked_and_filtered(self):
        parts = [
            CatalogPart("A", "ceramic capacitor", "0402", ("decoupling",), "JLC", 100, True),
            CatalogPart("B", "resistor", "0402", stock=100, basic=True),
        ]
        self.assertEqual(search_parts(parts, "decoupling", limit=1)[0].mpn, "A")

    def test_catalog_selection_requires_stock_and_basic_parts(self):
        parts = catalog_parts_from_json([
            {"mpn": "C1", "description": "capacitor", "footprint": "0402", "stock": 0},
            {"mpn": "C2", "description": "capacitor", "footprint": "0402", "stock": 20, "basic": True},
        ])
        spec = {
            "schema_version": 1,
            "parts": [{
                "reference": "C1", "lib_id": "Device:C", "value": "100nF",
                "footprint": "0402", "pins": {"1": "VCC", "2": "GND"}, "mpn": None,
            }],
            "nets": [
                {"name": "VCC", "connections": [{"reference": "C1", "pin": "1"}, {"reference": "C1", "pin": "2"}]},
            ],
        }
        selected = assign_catalog_parts(spec, parts, require_basic=True)
        self.assertEqual(selected["parts"][0]["mpn"], "C2")

    def test_live_catalog_adapter_normalizes_inventory_and_headers(self):
        state = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                state["headers"] = {name.lower(): value for name, value in self.headers.items()}
                body = json.dumps({"parts": [{
                    "part_number": "C-LIVE",
                    "comment": "100nF capacitor",
                    "package": "0402",
                    "quantity": 42,
                    "basic": True,
                }]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            catalog = fetch_catalog(CatalogEndpoint(
                provider="jlcpcb",
                endpoint=f"http://127.0.0.1:{server.server_port}/parts",
                allow_http_loopback=True,
            ))
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertEqual(catalog[0].mpn, "C-LIVE")
        self.assertEqual(catalog[0].vendor, "jlcpcb")
        self.assertEqual(catalog[0].stock, 42)
        self.assertEqual(state["headers"]["x-pcbex-catalog-provider"], "jlcpcb")

    def test_live_catalog_rejects_insecure_remote_endpoint(self):
        with self.assertRaises(CatalogRemoteError):
            fetch_catalog(CatalogEndpoint(provider="jlcpcb", endpoint="http://example.com/parts"))

    def test_live_catalog_normalizes_native_digikey_and_lcsc_aliases(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                provider = self.headers["X-PCBEX-Catalog-Provider"]
                if provider == "digikey":
                    payload = {"parts": [{
                        "ProductNumber": "DK-1",
                        "Description": "level shifter",
                        "PackageType": "SOT-23-6",
                        "QuantityAvailable": 7,
                        "isBasic": False,
                    }]}
                else:
                    payload = [{
                        "partNumber": "C-LCSC-1",
                        "productName": "level shifter",
                        "packageType": "SOT-23-6",
                        "stockQty": 11,
                        "jlcpcbBasic": "true",
                    }]
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_port}/parts"
            digikey = fetch_catalog(CatalogEndpoint(
                provider="digikey", endpoint=endpoint, allow_http_loopback=True
            ))
            lcsc = fetch_catalog(CatalogEndpoint(
                provider="lcsc", endpoint=endpoint, allow_http_loopback=True
            ))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual((digikey[0].mpn, digikey[0].stock), ("DK-1", 7))
        self.assertEqual((lcsc[0].mpn, lcsc[0].stock, lcsc[0].basic), ("C-LCSC-1", 11, True))

    def test_native_digikey_catalog_uses_oauth_and_keyword_search(self):
        state = {"token": False, "search": False}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                if self.path.endswith("/oauth2/token"):
                    state["token"] = body == b"client_id=id&client_secret=secret&grant_type=client_credentials"
                    value = {"access_token": "access"}
                else:
                    state["search"] = self.headers.get("Authorization") == "Bearer access"
                    value = {"Products": [{
                        "ManufacturerProductNumber": "DK-MPN",
                        "Description": {"ProductDescription": "level shifter"},
                        "QuantityAvailable": 9,
                        "ProductVariations": [{"PackageType": {"Name": "SOT-23-6"}}],
                        "DatasheetUrl": "https://example.test/datasheet.pdf",
                    }]}
                payload = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, _format, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict("os.environ", {"PCBEX_DK_ID": "id", "PCBEX_DK_SECRET": "secret"}):
                parts = fetch_catalog(CatalogEndpoint(
                    provider="digikey",
                    endpoint=f"http://127.0.0.1:{server.server_port}/products/v4/search/keyword",
                    query="level shifter",
                    client_id_environment="PCBEX_DK_ID",
                    client_secret_environment="PCBEX_DK_SECRET",
                    allow_http_loopback=True,
                ))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertTrue(state["token"] and state["search"])
        self.assertEqual((parts[0].mpn, parts[0].stock, parts[0].footprint), ("DK-MPN", 9, "SOT-23-6"))

    def test_skidl_generator_is_deterministic_and_complete(self):
        spec = {
            "schema_version": 1,
            "parts": [
                {"reference": "R1", "lib_id": "Device:R", "value": "10k", "footprint": "0402",
                 "pins": {"1": "VCC", "2": "GND"}},
                {"reference": "U1", "lib_id": "Connector_Generic:Conn_01x02", "value": "JTAG",
                 "footprint": "PinHeader_1x02_P2.54mm_Vertical", "pins": {"1": "VCC", "2": "GND"}},
            ],
            "nets": [
                {"name": "GND", "connections": [{"reference": "R1", "pin": "2"}, {"reference": "U1", "pin": "2"}]},
                {"name": "VCC", "connections": [{"reference": "R1", "pin": "1"}, {"reference": "U1", "pin": "1"}]},
            ],
        }
        source = generate_skidl(spec)
        self.assertEqual(source, generate_skidl(spec))
        self.assertIn('R1 = Part("Device", "R"', source)
        self.assertIn('R1["1"] += VCC', source)
        self.assertIn("PCBEX_ELECTRICAL_JSON", source)
        self.assertIn("generate_netlist()", source)
        schema = circuit_spec_json_schema()
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)

    def test_skidl_generator_fails_on_unconnected_pin(self):
        spec = {
            "schema_version": 1,
            "parts": [{"reference": "R1", "lib_id": "Device:R", "value": "10k",
                        "footprint": "0402", "pins": {"1": "VCC", "2": "GND"}}],
            "nets": [{"name": "VCC", "connections": [{"reference": "R1", "pin": "1"},
                                                          {"reference": "R1", "pin": "1"}]}],
        }
        with self.assertRaises(CircuitSpecError):
            generate_skidl(spec)

    def test_skidl_shape_converts_to_connection_graph(self):
        u1 = SimpleNamespace(ref="U1", footprint="QFN")
        c1 = SimpleNamespace(ref="C1", footprint="0402")
        net = SimpleNamespace(
            pins=[
                SimpleNamespace(part=u1),
                SimpleNamespace(part=c1),
            ]
        )
        circuit = SimpleNamespace(parts=[u1, c1], nets=[net])
        problem = skidl_to_placement_problem(
            circuit,
            {"QFN": (4_000_000, 4_000_000), "0402": (1_000_000, 500_000)},
            width_nm=20_000_000,
            height_nm=10_000_000,
            grid_nm=250_000,
        )
        self.assertEqual(problem["connections"][0]["from"]["component"], "U1")

    def test_circuit_spec_handoff_is_deterministic_and_bundle_aware(self):
        spec = {
            "schema_version": 1,
            "parts": [
                {
                    "reference": "U1",
                    "lib_id": "MCU:Example",
                    "value": "controller",
                    "footprint": "QFN",
                    "pins": {"1": "A", "2": "GND"},
                },
                {
                    "reference": "J1",
                    "lib_id": "Connector:Conn",
                    "value": "header",
                    "footprint": "HEADER",
                    "pins": {"1": "A", "2": "GND"},
                },
            ],
            "nets": [
                {"name": "A", "connections": [
                    {"reference": "U1", "pin": "1"},
                    {"reference": "J1", "pin": "1"},
                ]},
                {"name": "GND", "connections": [
                    {"reference": "U1", "pin": "2"},
                    {"reference": "J1", "pin": "2"},
                ]},
            ],
        }
        sizes = {
            "QFN": {"width_nm": 4_000_000, "height_nm": 4_000_000},
            "HEADER": {"width_nm": 6_000_000, "height_nm": 2_000_000},
        }
        bundle = {"schema_version": 1, "spec": spec, "skidl": "ignored"}
        problem = circuit_spec_to_placement_problem(
            bundle,
            sizes,
            width_nm=20_000_000,
            height_nm=10_000_000,
            grid_nm=250_000,
        )
        self.assertEqual([item["reference"] for item in problem["components"]], ["J1", "U1"])
        self.assertEqual(
            [(item["net"], item["from"]["component"], item["to"]["component"])
             for item in problem["connections"]],
            [("A", "J1", "U1"), ("GND", "J1", "U1")],
        )
        self.assertEqual(problem, circuit_spec_to_placement_problem(
            spec, sizes, width_nm=20_000_000, height_nm=10_000_000, grid_nm=250_000
        ))

    def test_circuit_spec_handoff_renders_kicad_nets_and_pads(self):
        spec = {
            "schema_version": 1,
            "parts": [{
                "reference": "J1",
                "lib_id": "Connector:Conn",
                "value": "header",
                "footprint": "HEADER",
                "pins": {"1": "A", "2": "GND"},
            }],
            "nets": [
                {"name": "A", "connections": [
                    {"reference": "J1", "pin": "1"},
                    {"reference": "J1", "pin": "2"},
                ]},
            ],
        }
        board = circuit_spec_to_kicad_pcb(
            spec,
            {"HEADER": {"width_nm": 6_000_000, "height_nm": 2_000_000}},
            width_nm=20_000_000,
            height_nm=10_000_000,
        )
        self.assertIn('(net 1 "A")', board)
        self.assertIn('(footprint "HEADER"', board)
        self.assertEqual(board.count("(pad "), 2)
        self.assertTrue(board.endswith("\n") and board.rstrip().endswith(")"))

    def test_circuit_handoff_preserves_fixed_component_position_and_lock(self):
        spec = {
            "schema_version": 1,
            "parts": [{
                "reference": "J1", "lib_id": "Connector:Conn", "value": "header",
                "footprint": "HEADER", "pins": {"1": "A", "2": "GND"},
            }],
            "nets": [{"name": "A", "connections": [
                {"reference": "J1", "pin": "1"}, {"reference": "J1", "pin": "2"},
            ]}],
        }
        board = circuit_spec_to_kicad_pcb(
            spec,
            {"HEADER": {"width_nm": 6_000_000, "height_nm": 2_000_000,
                        "position": {"x_nm": 5_000_000, "y_nm": 20_000_000},
                        "rotation_deg": 90, "fixed": True}},
            width_nm=20_000_000,
            height_nm=30_000_000,
        )
        self.assertIn('(at 5 20 90) (locked yes)', board)

    def test_circuit_netlist_is_canonical_and_digest_bound(self):
        spec = {
            "schema_version": 1,
            "parts": [{
                "reference": "U1", "lib_id": "MCU:Example", "value": "controller",
                "footprint": "QFN", "pins": {"1": "A", "2": "B"},
            }],
            "nets": [
                {"name": "B", "connections": [
                    {"reference": "U1", "pin": "2"}, {"reference": "U1", "pin": "1"},
                ]},
            ],
        }
        netlist = circuit_spec_to_netlist(spec)
        self.assertEqual(netlist["nets"][0]["connections"][0]["pin"], "1")
        self.assertEqual(len(netlist["sha256"]), 64)
        self.assertEqual(netlist["sha256"], circuit_spec_to_netlist(spec)["sha256"])

    def test_circuit_bound_firmware_builds_c_cpp_and_python(self):
        spec = {
            "schema_version": 1,
            "parts": [{
                "reference": "U1",
                "lib_id": "MCU:Example",
                "value": "controller",
                "footprint": "QFN",
                "pins": {"1": "DATA", "2": "GND"},
            }],
            "nets": [
                {"name": "DATA", "connections": [
                    {"reference": "U1", "pin": "1"},
                    {"reference": "U1", "pin": "2"},
                ]},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            manifest = generate_firmware_bundle(
                spec,
                Path(directory),
                mcu_reference="U1",
                gpio_map={"1": "PA0"},
            )
            self.assertTrue(manifest["c_build"]["passed"])
            self.assertTrue(manifest["cpp_build"]["passed"])
            self.assertTrue(manifest["python_check"]["passed"])
            self.assertTrue((Path(directory) / "pinout.h").is_file())
            self.assertTrue((Path(directory) / "firmware_smoke_test").is_file())
            self.assertTrue(firmware_bundle_json_schema()["additionalProperties"] is False)

    def test_pipeline_run_is_fail_closed_and_connects_all_phases(self):
        spec = {
            "schema_version": 1,
            "parts": [{
                "reference": "U1", "lib_id": "MCU:Example", "value": "controller",
                "footprint": "QFN", "pins": {"1": "DATA", "2": "GND"},
            }],
            "nets": [{"name": "DATA", "connections": [
                {"reference": "U1", "pin": "1"}, {"reference": "U1", "pin": "2"},
            ]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            requirements.write_text("Connect the controller", encoding="utf-8")
            sizes = root / "sizes.json"
            sizes.write_text(json.dumps({"QFN": {"width_nm": 4_000_000, "height_nm": 4_000_000}}), encoding="utf-8")
            physical_profile = root / "physical-profile.json"
            physical_profile.write_text(json.dumps({
                "schema_version": 1,
                "id": "fixture-profile",
                "revision": 1,
                "description": "fixture",
                "board_width_nm": 20_000_000,
                "board_height_nm": 10_000_000,
                "fixed_components": [{"reference": "U1", "x_nm": 5_000_000, "y_nm": 5_000_000}],
            }), encoding="utf-8")
            provider = [
                sys.executable, "-c",
                f"import sys; sys.stdin.read(); print({json.dumps(json.dumps(spec))})",
            ]
            fake_pcbex = root / "fake-pcbex"
            fake_pcbex.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, shutil, sys\n"
                "cmd=sys.argv[1]\n"
                "def value(name): return pathlib.Path(sys.argv[sys.argv.index(name)+1])\n"
                "if cmd == 'place-kicad':\n"
                "  shutil.copy2(pathlib.Path(sys.argv[2]), value('--output')); value('--json-output').write_text(json.dumps({'components':[{'reference':'U1','position':{'x_nm':1000000,'y_nm':2000000},'rotation_deg':90,'side':'front'}]}))\n"
                "elif cmd == 'route-kicad':\n"
                "  shutil.copy2(pathlib.Path(sys.argv[2]), value('--output')); value('--json-output').write_text('{}')\n"
                "elif cmd == 'fabricate':\n"
                "  out=value('--output-dir'); out.mkdir(parents=True, exist_ok=True); (out/'F-Cu.gbr').write_text('gerber')\n"
                "else: raise SystemExit('unknown command')\n",
                encoding="utf-8",
            )
            fake_pcbex.chmod(0o755)
            factory_command = root / "factory.json"
            factory_command.write_text(json.dumps([
                sys.executable, "-c",
                "import sys; sys.stdin.buffer.read(); print('{\"accepted\":true,\"dfm_passed\":true}')",
            ]), encoding="utf-8")
            report = run_hardware_pipeline(
                requirements,
                root / "pipeline",
                provider_command=provider,
                footprint_sizes=sizes,
                board_width_nm=20_000_000,
                board_height_nm=10_000_000,
                mcu_reference="U1",
                pcbex=str(fake_pcbex),
                physical_profile=physical_profile,
                factory_command_file=factory_command,
                require_factory=True,
            )
            self.assertTrue(report["passed"], report)
            self.assertEqual(
                [phase["name"] for phase in report["phases"]],
                ["circuit-generation", "circuit-kicad-handoff", "placement",
                 "autonomous-routing-drc", "manufacturing-package", "firmware-build", "factory-dfm"],
            )
            self.assertTrue((root / "pipeline" / "pipeline.json").is_file())
            self.assertIn('(at 5 5 0.0) (locked yes)', (root / "pipeline" / "circuit.kicad_pcb").read_text(encoding="utf-8"))
            cpl = (root / "pipeline" / "manufacturing" / "cpl.csv").read_text(encoding="utf-8")
            self.assertIn("U1,1.000000,2.000000,90,F.Cu", cpl)
            self.assertFalse(pipeline_run_json_schema()["additionalProperties"])

    def test_factory_http_submission_binds_package_and_response_hashes(self):
        state = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                state["body"] = self.rfile.read(int(self.headers["Content-Length"]))
                state["adapter"] = self.headers.get("X-PCBEX-Adapter")
                body = b'{"status":"quoted","accepted":true,"dfm":{"passed":true},"quote":{"total":12.5}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                package = Path(directory) / "manufacturing.zip"
                package.write_bytes(b"zip-fixture")
                receipt = submit_factory_package(
                    package,
                    FactoryEndpoint(
                        provider="jlcpcb",
                        endpoint=f"http://127.0.0.1:{server.server_port}/submit",
                        allow_http_loopback=True,
                    ),
                )
                self.assertTrue(receipt["accepted"])
                self.assertTrue(receipt["dfm_passed"])
                self.assertEqual(state["adapter"], "jlcpcb-http-v1")
                self.assertEqual(receipt["package_bytes"], len(state["body"]))
                self.assertFalse(factory_submission_json_schema()["additionalProperties"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_ipc_adapter_applies_one_atomic_commit(self):
        class Item:
            pass

        class Vector:
            @staticmethod
            def from_xy(x, y):
                return (x, y)

        net = SimpleNamespace(code=1, name="SIGNAL")
        board = SimpleNamespace(
            get_nets=lambda: [net],
            begin_commit=lambda: "commit",
        )
        board.create_items = lambda items: setattr(board, "created", items)
        board.push_commit = lambda commit, message: setattr(
            board, "pushed", (commit, message)
        )
        board.drop_commit = lambda commit: setattr(board, "dropped", commit)
        client = SimpleNamespace(get_board=lambda: board)
        api = SimpleNamespace(
            client_factory=lambda: client,
            Track=Item,
            Via=Item,
            Vector2=Vector,
            layer_from_name=lambda name: name,
        )
        result = apply_routes_to_open_board(
            {
                "routes": [
                    {
                        "net_id": 1,
                        "segments": [
                            {
                                "start": {"x_nm": 1, "y_nm": 2},
                                "end": {"x_nm": 3, "y_nm": 4},
                                "width_nm": 250000,
                                "layer": "F.Cu",
                            }
                        ],
                        "vias": [],
                    }
                ]
            },
            api=api,
        )
        self.assertEqual(result.tracks_created, 1)
        self.assertEqual(board.pushed[0], "commit")


if __name__ == "__main__":
    unittest.main()

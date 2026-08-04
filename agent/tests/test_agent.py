import ast
import json
import http.server
import sys
import threading
import time
import unittest
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from pcbex_agent.cli import main as agent_main
from pcbex_agent.catalog import CatalogPart, catalog_parts_from_json, search_parts
from pcbex_agent.circuit import skidl_to_placement_problem
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
from pcbex_agent.review import ReviewError, review_schematic_with_llm
from pcbex_agent.skidl import (
    CircuitSpecError,
    assign_catalog_parts,
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

    @staticmethod
    def _bound_review_fixture():
        request, response = AdapterTests._managed_review_fixture()
        request = {
            **request,
            "schema_version": 2,
            "artifact_binding": {
                "schema_version": 1,
                "generated_schematic": {
                    "bytes": 64,
                    "sha256": "b" * 64,
                },
                "pipeline": {
                    "plan_source": {"bytes": 128, "sha256": "c" * 64},
                    "plan_sha256": "d" * 64,
                    "report": {"bytes": 256, "sha256": "e" * 64},
                    "run_sha256": "f" * 64,
                },
            },
        }
        return request, response

    def test_schematic_review_adapter_accepts_bound_v2_evidence(self):
        request, response = self._bound_review_fixture()
        prompts: list[str] = []
        result = review_schematic_with_llm(
            request,
            lambda prompt: (prompts.append(prompt), json.dumps(response))[1],
        )
        self.assertEqual(result["schema_version"], 1)
        self.assertIn(
            "Artifact identities in a schema-v2 request are immutable evidence",
            prompts[0],
        )
        self.assertIn("The response schema remains v1", prompts[0])

    @staticmethod
    def _bound_review_v3_fixture():
        request, response = AdapterTests._bound_review_fixture()
        request["schema_version"] = 3
        request["artifact_binding"]["schema_version"] = 2
        request["artifact_binding"]["native_kicad_erc"] = {
            "schema_version": 1,
            "report": {"bytes": 512, "sha256": "1" * 64},
            "run_sha256": "2" * 64,
        }
        return request, response

    def test_schematic_review_adapter_accepts_bound_v3_native_kicad_erc(self):
        request, response = self._bound_review_v3_fixture()
        prompts: list[str] = []
        result = review_schematic_with_llm(
            request,
            lambda prompt: (prompts.append(prompt), json.dumps(response))[1],
        )
        self.assertEqual(result["schema_version"], 1)
        self.assertIn(
            "schema-v3 request, the native KiCad ERC report identity and run digest",
            prompts[0],
        )
        self.assertIn(
            "The response schema remains v1 even when the request is schema v2 or schema v3",
            prompts[0],
        )

    def test_schematic_review_adapter_rejects_v1_artifact_binding_presence(self):
        request, _response = self._managed_review_fixture()
        for binding in (None, {}):
            with self.subTest(binding=binding):
                malformed = {**request, "artifact_binding": binding}
                with self.assertRaises(ReviewError):
                    review_schematic_with_llm(malformed, lambda _prompt: "{}")

    def test_schematic_review_adapter_rejects_malformed_v2_binding(self):
        request, _response = self._bound_review_fixture()
        cases = {
            "missing": {
                key: value
                for key, value in request["artifact_binding"].items()
                if key != "pipeline"
            },
            "unknown binding field": {
                **request["artifact_binding"],
                "unexpected": True,
            },
            "unknown identity field": {
                **request["artifact_binding"],
                "generated_schematic": {
                    **request["artifact_binding"]["generated_schematic"],
                    "path": "design.kicad_sch",
                },
            },
        }
        for name, binding in cases.items():
            with self.subTest(case=name):
                malformed = {**request, "artifact_binding": binding}
                with self.assertRaises(ReviewError):
                    review_schematic_with_llm(malformed, lambda _prompt: "{}")

    def test_schematic_review_adapter_rejects_mixed_artifact_binding_versions(self):
        request, _response = self._bound_review_v3_fixture()
        cases = {
            "v3 request with v1 binding": {
                **request,
                "artifact_binding": {
                    key: value
                    for key, value in request["artifact_binding"].items()
                    if key != "native_kicad_erc"
                },
            },
            "v2 request with v2 binding": {
                **request,
                "schema_version": 2,
            },
        }
        for name, malformed in cases.items():
            with self.subTest(case=name), self.assertRaises(ReviewError):
                review_schematic_with_llm(malformed, lambda _prompt: "{}")

    def test_schematic_review_adapter_rejects_malformed_v3_native_binding(self):
        request, _response = self._bound_review_v3_fixture()
        native = request["artifact_binding"]["native_kicad_erc"]
        cases = {
            "null native binding": None,
            "unknown native field": {**native, "unexpected": True},
            "wrong native schema": {**native, "schema_version": 2},
            "null report": {**native, "report": None},
            "unknown report field": {
                **native,
                "report": {**native["report"], "path": "erc.json"},
            },
            "boolean report bytes": {
                **native,
                "report": {**native["report"], "bytes": False},
            },
            "noncanonical native run digest": {
                **native,
                "run_sha256": "A" * 64,
            },
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                malformed = json.loads(json.dumps(request))
                malformed["artifact_binding"]["native_kicad_erc"] = value
                with self.assertRaises(ReviewError):
                    review_schematic_with_llm(malformed, lambda _prompt: "{}")

    def test_schematic_review_adapter_rejects_oversize_v3_native_report(self):
        request, _response = self._bound_review_v3_fixture()
        malformed = json.loads(json.dumps(request))
        malformed["artifact_binding"]["native_kicad_erc"]["report"]["bytes"] = (
            32 * 1024 * 1024 + 1
        )
        with self.assertRaises(ReviewError):
            review_schematic_with_llm(malformed, lambda _prompt: "{}")

    def test_schematic_review_adapter_rejects_oversize_and_non_boolean_bytes(self):
        request, _response = self._bound_review_fixture()
        cases = {
            "schematic oversize": (
                "generated_schematic",
                {"bytes": 64 * 1024 * 1024 + 1, "sha256": "b" * 64},
            ),
            "plan oversize": (
                "plan_source",
                {"bytes": 4 * 1024 * 1024 + 1, "sha256": "c" * 64},
            ),
            "report oversize": (
                "report",
                {"bytes": 128 * 1024 * 1024 + 1, "sha256": "e" * 64},
            ),
            "boolean bytes": (
                "generated_schematic",
                {"bytes": True, "sha256": "b" * 64},
            ),
        }
        for name, (field, value) in cases.items():
            with self.subTest(case=name):
                malformed = json.loads(json.dumps(request))
                if field == "generated_schematic":
                    malformed["artifact_binding"][field] = value
                else:
                    malformed["artifact_binding"]["pipeline"][field] = value
                with self.assertRaises(ReviewError):
                    review_schematic_with_llm(malformed, lambda _prompt: "{}")

    def test_schematic_review_adapter_rejects_noncanonical_artifact_sha256(self):
        request, _response = self._bound_review_fixture()
        for field, value in (
            ("generated_schematic", "A" * 64),
            ("plan_sha256", "g" * 64),
        ):
            with self.subTest(field=field):
                malformed = json.loads(json.dumps(request))
                if field == "generated_schematic":
                    malformed["artifact_binding"][field]["sha256"] = value
                else:
                    malformed["artifact_binding"]["pipeline"][field] = value
                with self.assertRaises(ReviewError):
                    review_schematic_with_llm(malformed, lambda _prompt: "{}")

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
        with self.assertRaisesRegex(ValueError, "index 0 must be an object"):
            catalog_parts_from_json(["not-an-object"])

    def test_catalog_selection_requires_stock_and_basic_parts(self):
        parts = catalog_parts_from_json([
            {"mpn": "C1", "description": "capacitor", "footprint": "0402", "stock": 0},
            {"mpn": "C2", "description": "capacitor", "footprint": "0402", "stock": 20, "basic": True},
        ])
        spec = {
            "schema_version": 1,
            "parts": [{
                "reference": "C1", "lib_id": "Device:C", "value": "100nF",
                "footprint": "0402", "pins": {"1": "VCC", "2": "VCC"}, "mpn": None,
            }],
            "nets": [
                {"name": "VCC", "connections": [{"reference": "C1", "pin": "1"}, {"reference": "C1", "pin": "2"}]},
            ],
        }
        selected = assign_catalog_parts(
            spec,
            parts,
            require_basic=True,
            allow_footprint_fallback=True,
        )
        self.assertEqual(selected["parts"][0]["mpn"], "C2")

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
        self.assertIn('_pcbex_parts["R1"] = Part("Device", "R"', source)
        self.assertIn('_pcbex_parts["R1"]["1"] += _pcbex_nets["VCC"]', source)
        self.assertIn("generate_netlist()", source)
        schema = circuit_spec_json_schema()
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)

    def test_skidl_generator_isolates_external_names_from_python_namespace(self):
        net_names = [
            "5V",
            "USB+",
            "A.B",
            "Part",
            "Net",
            "generate_netlist",
            "PCBEX_ELECTRICAL_JSON",
            "class",
            "__debug__",
        ]
        pins = {str(index): name for index, name in enumerate(net_names, start=1)}
        spec = {
            "schema_version": 1,
            "parts": [
                {"reference": "Part", "lib_id": "Device:R", "value": "10k",
                 "footprint": "0402", "pins": pins},
                {"reference": "generate_netlist", "lib_id": "Device:R", "value": "1k",
                 "footprint": "0402", "pins": pins},
            ],
            "nets": [
                {"name": name,
                 "connections": [
                     {"reference": "Part", "pin": str(index)},
                     {"reference": "generate_netlist", "pin": str(index)},
                 ]}
                for index, name in enumerate(net_names, start=1)
            ],
        }

        source = generate_skidl(spec)
        ast.parse(source)
        compile(source, "generated-circuit.py", "exec")
        compile(
            generate_skidl(spec, include_netlist=False),
            "generated-circuit-without-netlist.py",
            "exec",
        )
        self.assertIn('_pcbex_nets["5V"] = Net("5V")', source)
        self.assertIn(
            '_pcbex_parts["Part"]["4"] += _pcbex_nets["Part"]', source
        )

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

        generated_netlists = []
        fake_skidl = ModuleType("skidl")
        fake_skidl.Net = FakeNet
        fake_skidl.Part = FakePart
        fake_skidl.generate_netlist = lambda: generated_netlists.append(True)
        namespace = {}
        with patch.dict(sys.modules, {"skidl": fake_skidl}):
            exec(compile(source, "generated-circuit.py", "exec"), namespace)

        self.assertEqual(generated_netlists, [True])
        self.assertEqual(set(namespace["_pcbex_nets"]), set(net_names))
        self.assertTrue(
            all(net.connections == 2 for net in namespace["_pcbex_nets"].values())
        )

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

    def test_skidl_generator_rejects_declared_pin_net_mismatch(self):
        spec = {
            "schema_version": 1,
            "parts": [
                {"reference": "R1", "lib_id": "Device:R", "value": "10k",
                 "footprint": "0402", "pins": {"1": "VCC", "2": "GND"}},
                {"reference": "R2", "lib_id": "Device:R", "value": "1k",
                 "footprint": "0402", "pins": {"1": "VCC", "2": "GND"}},
            ],
            "nets": [
                {"name": "GND", "connections": [
                    {"reference": "R1", "pin": "1"},
                    {"reference": "R2", "pin": "2"},
                ]},
                {"name": "VCC", "connections": [
                    {"reference": "R1", "pin": "2"},
                    {"reference": "R2", "pin": "1"},
                ]},
            ],
        }
        with self.assertRaisesRegex(CircuitSpecError, "declares net"):
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

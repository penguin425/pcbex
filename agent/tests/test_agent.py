import json
import sys
import time
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pcbex_agent.cli import main as agent_main
from pcbex_agent.catalog import CatalogPart, search_parts
from pcbex_agent.circuit import skidl_to_placement_problem
from pcbex_agent.drc import normalize_kicad_report
from pcbex_agent.executor import ScoreComparison, run_bounded
from pcbex_agent.models import DrcViolation, PlanLimits
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

    def test_catalog_search_is_ranked_and_filtered(self):
        parts = [
            CatalogPart("A", "ceramic capacitor", "0402", ("decoupling",)),
            CatalogPart("B", "resistor", "0402"),
        ]
        self.assertEqual(search_parts(parts, "decoupling", limit=1)[0].mpn, "A")

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

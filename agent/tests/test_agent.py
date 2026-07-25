import unittest
from types import SimpleNamespace

from pcbex_agent.catalog import CatalogPart, search_parts
from pcbex_agent.circuit import skidl_to_placement_problem
from pcbex_agent.drc import normalize_kicad_report
from pcbex_agent.executor import ScoreComparison, run_bounded
from pcbex_agent.models import PlanLimits
from pcbex_agent.planner import build_plan
from pcbex_agent.repair import propose_repairs
from pcbex_agent.llm import build_plan_with_llm
from pcbex_agent.ipc import apply_routes_to_open_board


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


class AdapterTests(unittest.TestCase):
    def test_llm_adapter_rejects_coordinates(self):
        response = (
            '{"constraints":[{"type":"near","parameters":'
            '{"subject":"C1","target":"U1","x_nm":2}, "source":"x"}]}'
        )
        with self.assertRaises(ValueError):
            build_plan_with_llm("place C1", lambda _prompt: response)

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

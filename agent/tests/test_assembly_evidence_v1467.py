from __future__ import annotations

from collections.abc import Iterator, Mapping
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional in focused CI environments
    Draft202012Validator = None

from agent.tests.test_circuit_handoff_bundle_v1449 import _archive_entries
from agent.tests.test_circuit_handoff_bundle_v1457 import _case
import pcbex_agent.assembly_evidence as assembly_module
import pcbex_agent.circuit_handoff_bundle as handoff_module
from pcbex_agent.assembly_evidence import (
    AssemblyEvidenceError,
    assembly_evidence_json_schema,
    evaluate_assembly_evidence,
    render_assembly_evidence,
    validate_assembly_evidence,
)


def _identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _rebind(report: dict[str, object]) -> None:
    payload = {key: value for key, value in report.items() if key != "binding_sha256"}
    report["binding_sha256"] = hashlib.sha256(
        assembly_module.ASSEMBLY_EVIDENCE_BINDING_DOMAIN
        + assembly_module._compact_json(payload)
    ).hexdigest()


def _write_outer_wrapper(
    root: Path,
    base: list[str],
    final_cpl_raw: bytes,
    *,
    mutate: Path | None = None,
) -> list[str]:
    (root / "assembly-base-command.json").write_text(
        json.dumps(base), encoding="utf-8"
    )
    (root / "assembly-final-cpl.bin").write_bytes(final_cpl_raw)
    (root / "assembly-mutation.json").write_text(
        json.dumps(None if mutate is None else str(mutate)), encoding="utf-8"
    )
    wrapper = root / "assembly-wrapper.py"
    wrapper.write_text(
        textwrap.dedent(
            """
            import json
            from pathlib import Path
            import subprocess
            import sys

            root = Path(__file__).parent
            base = json.loads((root / "assembly-base-command.json").read_text())
            mutation = json.loads((root / "assembly-mutation.json").read_text())
            argv = sys.argv[1:]
            if argv and argv[0] == "verify-final-cpl":
                output = next(
                    value.split("=", 1)[1]
                    for value in argv
                    if value.startswith("--output=")
                )
                Path(output).write_bytes(
                    (root / "assembly-final-cpl.bin").read_bytes()
                )
                if mutation is not None:
                    path = Path(mutation)
                    path.write_bytes(path.read_bytes() + b"changed")
                raise SystemExit(0)
            raise SystemExit(subprocess.run([*base, *argv]).returncode)
            """
        ),
        encoding="utf-8",
        newline="\n",
    )
    return [sys.executable, str(wrapper)]


def _fixture(
    root: Path,
    *,
    board_approved: bool = True,
    procurement_approved: bool = True,
    final_cpl_approved: bool = True,
    bom_references: tuple[str, ...] = ("R1",),
    cpl_references: tuple[str, ...] = ("R1",),
    mutate: str | None = None,
) -> dict[str, object]:
    case, package, package_raw, base = _case(root, approved=board_approved)
    entries = _archive_entries(case["archive_raw"])
    generation_raw = entries[handoff_module.GENERATION_BUNDLE_NAME]
    engine = json.loads(entries[handoff_module.HANDOFF_REPORT_NAME])["engine_version"]
    procurement_path = root / "procurement-intent.json"
    procurement_raw = b"{}\n"
    procurement_path.write_bytes(procurement_raw)
    catalog_path = root / "catalog.json"
    catalog_raw = b"{}\n"
    catalog_path.write_bytes(catalog_raw)

    board_identity = _identity(case["board_raw"])
    package_identity = _identity(package_raw)
    manifest_identity = _identity(b"manifest")
    bom_identity = _identity(b"bom")
    final_bom = {
        "schema_version": 1,
        "scope": assembly_module.FINAL_BOM_SCOPE,
        "engine_version": engine,
        "board_basename": "design.kicad_pcb",
        "sources": {
            "board": board_identity,
            "manufacturing_package": package_identity,
            "manifest": manifest_identity,
            "bom": bom_identity,
            "canonical_bom": bom_identity,
            "package_board_source": board_identity,
        },
        "counts": {
            "board_parts": len(bom_references),
            "board_in_bom_parts": len(bom_references),
            "package_parts": len(bom_references),
            "package_in_bom_parts": len(bom_references),
            "findings": 0,
        },
        "in_bom_parts": [
            {
                "reference": reference,
                "value": "1k",
                "footprint": "Test:R",
                "mpn": f"MPN-{reference}",
                "layer": "F",
                "type": "SMD",
            }
            for reference in sorted(bom_references)
        ],
        "findings": [],
        "approved": True,
    }
    procurement_findings = []
    procurement_validation = {
        "final_bom_verified": True,
        "catalog_selection_replayed": True,
        "reference_sets_matched": procurement_approved,
        "part_values_matched": procurement_approved,
        "part_footprints_matched": procurement_approved,
        "part_mpns_matched": procurement_approved,
        "supplier_part_numbers_present": procurement_approved,
        "supplier_part_numbers_unambiguous": procurement_approved,
        "caller_inputs_unchanged": True,
    }
    if not procurement_approved:
        procurement_findings = [
            {
                "code": "reference_set_mismatch",
                "message": assembly_module._procurement._PROCUREMENT_FINDING_MESSAGES[
                    "reference_set_mismatch"
                ],
            }
        ]
    procurement = {
        "schema_version": 1,
        "scope": assembly_module._procurement.PROCUREMENT_INTENT_SCOPE,
        "status": "approved" if procurement_approved else "rejected",
        "approved": procurement_approved,
        "procurement_authorized": False,
        "network_performed": False,
        "order_placed": False,
        "current_availability_verified": False,
        "supplier_authenticity_verified": False,
        "quantity_basis": "per_board",
        "sources": {
            "board": {"name": "design.kicad_pcb", **board_identity},
            "manufacturing_package": package_identity,
            "generation_bundle": _identity(generation_raw),
            "catalog_snapshot": _identity(catalog_raw),
            "final_bom_report": _identity(b"final-bom\n"),
            "manifest": manifest_identity,
            "bom": bom_identity,
            "canonical_bom": bom_identity,
            "package_board_source": board_identity,
        },
        "final_bom": final_bom,
        "catalog": {
            "supplier": "test",
            "snapshot_id": "snapshot-1",
            "captured_at_unix": 1,
            "expires_at_unix": 2,
            "evaluated_at_unix": 1,
            "catalog_sha256": "a" * 64,
            "selection_receipt_sha256": "b" * 64,
            "input_spec_sha256": "c" * 64,
            "resolved_spec_sha256": "d" * 64,
            "policy": {
                "require_available": False,
                "require_basic": False,
                "allow_footprint_fallback": False,
            },
        },
        "line_items": (
            [
                {
                    "mpn": f"MPN-{reference}",
                    "supplier_part_number": f"SKU-{reference}",
                    "catalog_part_sha256": hashlib.sha256(
                        reference.encode()
                    ).hexdigest(),
                    "footprint": "Test:R",
                    "quantity": 1,
                    "references": [reference],
                }
                for reference in sorted(bom_references)
            ]
            if procurement_approved
            else []
        ),
        "findings": procurement_findings,
        "validation": procurement_validation,
        "binding_sha256": "e" * 64,
    }

    cpl_raw = b"cpl"
    canonical_cpl_raw = cpl_raw if final_cpl_approved else b"different-cpl"
    cpl_findings = []
    if not final_cpl_approved:
        cpl_findings = [
            {
                "code": "canonical_cpl_mismatch",
                "message": assembly_module._FINAL_CPL_FINDING_MESSAGES[
                    "canonical_cpl_mismatch"
                ],
            }
        ]
    final_cpl = {
        "schema_version": 1,
        "scope": assembly_module.FINAL_CPL_SCOPE,
        "engine_version": engine,
        "board_basename": "design.kicad_pcb",
        "sources": {
            "board": board_identity,
            "manufacturing_package": package_identity,
            "manifest": manifest_identity,
            "cpl": _identity(cpl_raw),
            "canonical_cpl": _identity(canonical_cpl_raw),
            "package_board_source": board_identity,
        },
        "counts": {
            "board_parts": len(bom_references),
            "board_in_pos_parts": len(cpl_references),
            "package_parts": len(bom_references),
            "package_placement_parts": len(cpl_references),
            "findings": len(cpl_findings),
        },
        "in_pos_parts": [
            {
                "reference": reference,
                "x_nm": index,
                "y_nm": -index,
                "rotation_mdeg": 0,
                "layer": "F",
            }
            for index, reference in enumerate(sorted(cpl_references))
        ],
        "findings": cpl_findings,
        "approved": final_cpl_approved,
    }
    final_cpl_path = root / "final-cpl.json"
    final_cpl_raw = (
        json.dumps(final_cpl, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    final_cpl_path.write_bytes(final_cpl_raw)
    mutation_path = None
    if mutate == "procurement":
        mutation_path = procurement_path
    command = _write_outer_wrapper(
        root,
        base,
        final_cpl_raw,
        mutate=mutation_path,
    )
    return {
        "case": case,
        "package": package,
        "procurement_path": procurement_path,
        "catalog_path": catalog_path,
        "final_cpl_path": final_cpl_path,
        "command": command,
        "procurement": procurement,
        "final_cpl": final_cpl,
    }


def _evaluate(fixture: Mapping[str, object], **kwargs: object) -> dict[str, object]:
    case = fixture["case"]
    assert isinstance(case, Mapping)
    with mock.patch.object(
        assembly_module._procurement,
        "validate_procurement_intent",
        return_value=fixture["procurement"],
    ):
        return evaluate_assembly_evidence(
            case["archive"],
            case["board"],
            fixture["package"],
            case["report"],
            fixture["procurement_path"],
            fixture["catalog_path"],
            fixture["final_cpl_path"],
            fixture["command"],
            **kwargs,
        )


class AssemblyEvidenceV1467Tests(unittest.TestCase):
    def test_complete_evidence_is_closed_canonical_and_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve())
            result = _evaluate(fixture)

        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "complete")
        self.assertFalse(result["assembly_ready"])
        self.assertFalse(result["assembly_authorized"])
        self.assertNotIn("in_bom_parts", result["final_bom"])
        self.assertNotIn("final_bom", result["procurement"])
        self.assertNotIn("binding_sha256", result["procurement"])
        self.assertEqual(result["membership"], {"both": ["R1"], "bom_only": [], "cpl_only": []})
        rendered = render_assembly_evidence(result)
        self.assertTrue(rendered.endswith(b"\n"))
        self.assertEqual(rendered, render_assembly_evidence(json.loads(rendered)))
        if Draft202012Validator is not None:
            Draft202012Validator.check_schema(assembly_evidence_json_schema())
            self.assertEqual(
                list(
                    Draft202012Validator(
                        assembly_evidence_json_schema()
                    ).iter_errors(result)
                ),
                [],
            )

    def test_three_child_rejections_are_retained_as_exact_outer_findings(self) -> None:
        scenarios = (
            ({"board_approved": False}, "board_binding_rejected"),
            ({"procurement_approved": False}, "procurement_intent_rejected"),
            ({"final_cpl_approved": False}, "final_cpl_rejected"),
        )
        for options, expected in scenarios:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                result = _evaluate(_fixture(Path(directory).resolve(), **options))
            self.assertFalse(result["complete"])
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual([item["code"] for item in result["findings"]], [expected])

    def test_package_board_source_mismatch_is_incomplete_not_a_hard_bind_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            procurement = fixture["procurement"]
            final_bom = procurement["final_bom"]
            final_cpl = fixture["final_cpl"]
            other_board = _identity(b"different-package-board")
            message = assembly_module._procurement._FINAL_BOM_FINDING_MESSAGES[
                "package_board_source_mismatch"
            ]
            final_bom["sources"]["package_board_source"] = other_board
            final_bom["findings"] = [
                {"code": "package_board_source_mismatch", "message": message}
            ]
            final_bom["counts"]["findings"] = 1
            final_bom["approved"] = False
            procurement["sources"]["package_board_source"] = other_board
            procurement["status"] = "rejected"
            procurement["approved"] = False
            procurement["line_items"] = []
            procurement["findings"] = [
                {
                    "code": "final_bom_rejected",
                    "message": assembly_module._procurement._PROCUREMENT_FINDING_MESSAGES[
                        "final_bom_rejected"
                    ],
                }
            ]
            procurement["validation"]["final_bom_verified"] = False

            cpl_message = assembly_module._FINAL_CPL_FINDING_MESSAGES[
                "package_board_source_mismatch"
            ]
            final_cpl["sources"]["package_board_source"] = other_board
            final_cpl["findings"] = [
                {
                    "code": "package_board_source_mismatch",
                    "message": cpl_message,
                }
            ]
            final_cpl["counts"]["findings"] = 1
            final_cpl["approved"] = False
            final_cpl_raw = json.dumps(final_cpl, indent=2).encode() + b"\n"
            Path(fixture["final_cpl_path"]).write_bytes(final_cpl_raw)
            (root / "assembly-final-cpl.bin").write_bytes(final_cpl_raw)
            result = _evaluate(fixture)

        self.assertFalse(result["complete"])
        self.assertEqual(
            [finding["code"] for finding in result["findings"]],
            ["final_cpl_rejected", "procurement_intent_rejected"],
        )
        self.assertNotEqual(
            result["final_cpl"]["sources"]["package_board_source"]["sha256"],
            result["sources"]["board"]["sha256"],
        )

    def test_membership_differences_are_informational_not_a_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = _evaluate(
                _fixture(
                    Path(directory).resolve(),
                    bom_references=("R1", "R2"),
                    cpl_references=("C1", "R1"),
                )
            )
        self.assertTrue(result["complete"])
        self.assertEqual(
            result["membership"],
            {"both": ["R1"], "bom_only": ["R2"], "cpl_only": ["C1"]},
        )

    def test_cross_binding_mismatch_fails_hard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve())
            forged = copy.deepcopy(fixture["procurement"])
            forged["sources"]["generation_bundle"]["sha256"] = "0" * 64
            fixture["procurement"] = forged
            with self.assertRaisesRegex(AssemblyEvidenceError, "generation_bundle"):
                _evaluate(fixture)

    def test_final_cpl_rust_parity_rejects_bool_coordinate_before_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve())
            value = copy.deepcopy(fixture["final_cpl"])
            value["in_pos_parts"][0]["x_nm"] = True
            Path(fixture["final_cpl_path"]).write_bytes(
                json.dumps(value, indent=2).encode() + b"\n"
            )
            case = fixture["case"]
            with mock.patch.object(
                assembly_module._handoff, "replay_circuit_handoff_bundle"
            ) as replay, mock.patch.object(assembly_module, "run_bounded") as child:
                with self.assertRaisesRegex(AssemblyEvidenceError, "coordinate"):
                    evaluate_assembly_evidence(
                        case["archive"],
                        case["board"],
                        fixture["package"],
                        case["report"],
                        fixture["procurement_path"],
                        fixture["catalog_path"],
                        fixture["final_cpl_path"],
                        fixture["command"],
                    )
                replay.assert_not_called()
                child.assert_not_called()

    def test_outer_deadline_reserves_each_downstream_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve())
            original_replay = assembly_module._handoff.replay_circuit_handoff_bundle
            original_child = assembly_module.run_bounded
            with mock.patch.object(
                assembly_module._handoff,
                "replay_circuit_handoff_bundle",
                wraps=original_replay,
            ) as replay, mock.patch.object(
                assembly_module._procurement,
                "validate_procurement_intent",
                return_value=fixture["procurement"],
            ) as procurement, mock.patch.object(
                assembly_module, "run_bounded", wraps=original_child
            ) as child:
                case = fixture["case"]
                result = evaluate_assembly_evidence(
                    case["archive"],
                    case["board"],
                    fixture["package"],
                    case["report"],
                    fixture["procurement_path"],
                    fixture["catalog_path"],
                    fixture["final_cpl_path"],
                    fixture["command"],
                    timeout_seconds=120,
                    _clock=lambda: 0.0,
                )
        self.assertTrue(result["complete"])
        self.assertEqual(replay.call_args.kwargs["timeout_seconds"], 60.0)
        self.assertEqual(procurement.call_args.kwargs["timeout_seconds"], 60.0)
        self.assertEqual(child.call_args.kwargs["timeout_seconds"], 105.0)
        self.assertEqual(child.call_args.kwargs["cleanup_timeout_seconds"], 7.5)

    def test_mutation_by_last_child_is_detected_by_final_union_reread(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(), mutate="procurement")
            with self.assertRaisesRegex(AssemblyEvidenceError, "changed"):
                _evaluate(fixture)

    def test_retained_validation_accepts_mapping_but_requires_canonical_raw(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = _fixture(root)
            result = _evaluate(fixture)
            case = fixture["case"]
            arguments = (
                case["archive"],
                case["board"],
                fixture["package"],
                case["report"],
                fixture["procurement_path"],
                fixture["catalog_path"],
                fixture["final_cpl_path"],
                fixture["command"],
            )
            canonical = render_assembly_evidence(result)
            retained_path = root / "assembly.json"
            retained_path.write_bytes(canonical)
            with mock.patch.object(
                assembly_module, "_evaluate_capture", return_value=result
            ):
                self.assertEqual(validate_assembly_evidence(result, *arguments), result)
                self.assertEqual(
                    validate_assembly_evidence(retained_path, *arguments), result
                )
                alternate = json.dumps(result, separators=(",", ":")).encode()
                with self.assertRaisesRegex(AssemblyEvidenceError, "canonical"):
                    validate_assembly_evidence(alternate, *arguments)

    def test_retained_path_hook_runs_after_capture_and_mutation_is_observed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = _fixture(root)
            result = _evaluate(fixture)
            retained = root / "assembly.json"
            retained.write_bytes(render_assembly_evidence(result))
            case = fixture["case"]

            class MutatingPath:
                def __fspath__(self) -> str:
                    board = Path(case["board"])
                    board.write_bytes(board.read_bytes() + b"changed")
                    return str(retained)

            with mock.patch.object(
                assembly_module, "_evaluate_capture", return_value=result
            ), self.assertRaisesRegex(AssemblyEvidenceError, "board changed"):
                validate_assembly_evidence(
                    MutatingPath(),
                    case["archive"],
                    case["board"],
                    fixture["package"],
                    case["report"],
                    fixture["procurement_path"],
                    fixture["catalog_path"],
                    fixture["final_cpl_path"],
                    fixture["command"],
                )

    def test_renderer_snapshots_stateful_mapping_once_and_rejects_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = _evaluate(_fixture(Path(directory).resolve()))

        class OneView(Mapping[str, object]):
            def __init__(self, value: dict[str, object]) -> None:
                self.value = value
                self.views = 0

            def __getitem__(self, key: str) -> object:
                return self.value[key]

            def __iter__(self) -> Iterator[str]:
                return iter(self.value)

            def __len__(self) -> int:
                return len(self.value)

            def items(self):
                self.views += 1
                if self.views > 1:
                    raise RuntimeError("second traversal")
                return self.value.items()

        stateful = OneView(result)
        self.assertEqual(json.loads(render_assembly_evidence(stateful)), result)
        self.assertEqual(stateful.views, 1)
        forged = copy.deepcopy(result)
        forged["complete"] = False
        with self.assertRaises(AssemblyEvidenceError):
            render_assembly_evidence(forged)
        forged = copy.deepcopy(result)
        forged["membership"]["both"] = []
        forged["binding_sha256"] = hashlib.sha256(
            assembly_module.ASSEMBLY_EVIDENCE_BINDING_DOMAIN
            + assembly_module._compact_json(
                {key: value for key, value in forged.items() if key != "binding_sha256"}
            )
        ).hexdigest()
        with self.assertRaisesRegex(AssemblyEvidenceError, "membership"):
            render_assembly_evidence(forged)

    def test_command_hooks_cannot_change_the_retained_snapshot(self) -> None:
        for hook in ("pcbex", "kicad"):
            with self.subTest(hook=hook), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                fixture = _fixture(root)
                result = _evaluate(fixture)
                retained = root / "assembly.json"
                retained.write_bytes(render_assembly_evidence(result))
                case = fixture["case"]

                class MutatingCommand:
                    def __iter__(self):
                        retained.write_bytes(retained.read_bytes() + b" ")
                        yield sys.executable
                        yield str(root / "unused.py")

                class MutatingKicad:
                    def __fspath__(self) -> str:
                        retained.write_bytes(retained.read_bytes() + b" ")
                        return "kicad-cli"

                pcbex = MutatingCommand() if hook == "pcbex" else fixture["command"]
                kicad = MutatingKicad() if hook == "kicad" else "kicad-cli"
                with mock.patch.object(
                    assembly_module, "_evaluate_capture", return_value=result
                ), self.assertRaisesRegex(AssemblyEvidenceError, "report changed"):
                    validate_assembly_evidence(
                        retained,
                        case["archive"],
                        case["board"],
                        fixture["package"],
                        case["report"],
                        fixture["procurement_path"],
                        fixture["catalog_path"],
                        fixture["final_cpl_path"],
                        pcbex,
                        kicad_cli=kicad,
                    )

    def test_retained_representations_share_the_aggregate_input_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            result = _evaluate(fixture)
            canonical = render_assembly_evidence(result)
            retained = root / "assembly.json"
            retained.write_bytes(canonical)
            case = fixture["case"]
            arguments = (
                case["archive"],
                case["board"],
                fixture["package"],
                case["report"],
                fixture["procurement_path"],
                fixture["catalog_path"],
                fixture["final_cpl_path"],
                fixture["command"],
            )
            direct_bytes = sum(
                Path(path).stat().st_size
                for path in (
                    case["archive"],
                    case["board"],
                    fixture["package"],
                    case["report"],
                    fixture["procurement_path"],
                    fixture["catalog_path"],
                    fixture["final_cpl_path"],
                )
            )
            representations = (
                retained,
                canonical,
                bytearray(canonical),
                memoryview(canonical),
                result,
            )
            for representation in representations:
                with self.subTest(kind=type(representation).__name__), mock.patch.object(
                    assembly_module,
                    "MAXIMUM_TOTAL_INPUT_BYTES",
                    direct_bytes + len(canonical) - 1,
                ), mock.patch.object(
                    assembly_module, "_evaluate_capture", return_value=result
                ), self.assertRaisesRegex(AssemblyEvidenceError, "aggregate bound"):
                    validate_assembly_evidence(representation, *arguments)

    def test_streaming_renderer_bounds_pretty_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = _evaluate(_fixture(Path(directory).resolve(strict=True)))
        compact = assembly_module._procurement._bounded_injected_json_bytes(
            result,
            maximum=assembly_module.MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
            label="test report",
        )
        pretty = render_assembly_evidence(result)
        self.assertGreater(len(pretty), len(compact))
        with mock.patch.object(
            assembly_module,
            "MAXIMUM_ASSEMBLY_EVIDENCE_BYTES",
            len(pretty) - 1,
        ), self.assertRaisesRegex(AssemblyEvidenceError, "byte bound"):
            render_assembly_evidence(result)

    def test_structural_unique_items_is_linear_hash_based(self) -> None:
        values = list(range(10_000))
        with mock.patch.object(
            assembly_module,
            "_strict_json_equal",
            side_effect=AssertionError("pairwise comparison is forbidden"),
        ):
            assembly_module._validate_structural_schema(
                values,
                {
                    "type": "array",
                    "uniqueItems": True,
                    "items": {"type": "integer"},
                },
            )
        with self.assertRaises(AssemblyEvidenceError):
            assembly_module._validate_structural_schema(
                [*values, values[-1]],
                {
                    "type": "array",
                    "uniqueItems": True,
                    "items": {"type": "integer"},
                },
            )

    def test_runtime_validator_rejects_numeric_and_line_item_coercions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = _evaluate(_fixture(Path(directory).resolve(strict=True)))

        mutations = []
        numeric = copy.deepcopy(result)
        numeric["final_cpl"]["schema_version"] = 1.0
        mutations.append(numeric)
        extra = copy.deepcopy(result)
        extra["procurement"]["line_items"][0]["unexpected"] = None
        mutations.append(extra)
        digest = copy.deepcopy(result)
        digest["procurement"]["line_items"][0]["catalog_part_sha256"] = "A" * 64
        mutations.append(digest)
        quantity = copy.deepcopy(result)
        quantity["procurement"]["line_items"][0]["quantity"] = 1.0
        mutations.append(quantity)
        nested = copy.deepcopy(result)
        nested["circuit_manufacturing"]["manufacturing_package"]["verified"] = False
        mutations.append(nested)
        procurement_scope = copy.deepcopy(result)
        procurement_scope["procurement"]["scope"] = "forged"
        mutations.append(procurement_scope)
        catalog_extra = copy.deepcopy(result)
        catalog_extra["procurement"]["catalog"]["unexpected"] = None
        mutations.append(catalog_extra)
        finding = copy.deepcopy(result)
        finding["procurement"]["findings"] = [
            {"code": "bogus", "message": "bogus"}
        ]
        mutations.append(finding)
        validation_extra = copy.deepcopy(result)
        validation_extra["procurement"]["validation"]["unexpected"] = True
        mutations.append(validation_extra)
        artifact_extra = copy.deepcopy(result)
        artifact_extra["circuit_manufacturing"]["artifacts"]["unexpected"] = {
            "name": "unexpected",
            "bytes": 1,
            "sha256": "a" * 64,
        }
        mutations.append(artifact_extra)
        board_schema = copy.deepcopy(result)
        board_schema["circuit_manufacturing"]["board_binding"][
            "schema_version"
        ] = "bogus"
        mutations.append(board_schema)
        manufacturing_scope = copy.deepcopy(result)
        manufacturing_scope["circuit_manufacturing"]["manufacturing_package"][
            "verification_scope"
        ] = "bogus"
        mutations.append(manufacturing_scope)
        for index, forged in enumerate(mutations):
            payload = {
                key: value
                for key, value in forged.items()
                if key != "binding_sha256"
            }
            forged["binding_sha256"] = hashlib.sha256(
                assembly_module.ASSEMBLY_EVIDENCE_BINDING_DOMAIN
                + assembly_module._compact_json(payload)
            ).hexdigest()
            with self.subTest(mutation=index), self.assertRaises(
                AssemblyEvidenceError
            ):
                render_assembly_evidence(forged)

    def test_runtime_validator_rejects_self_contained_mapping_forges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = _evaluate(_fixture(Path(directory).resolve(strict=True)))

        mutations: list[tuple[str, dict[str, object]]] = []

        expected_flag = copy.deepcopy(result)
        expected_flag["circuit_manufacturing"]["validation"][
            "expected_identity_matched"
        ] = True
        mutations.append(("expected flag without digest", expected_flag))

        expected_digest = copy.deepcopy(result)
        expected_digest["circuit_manufacturing"]["expected"][
            "archive_sha256"
        ] = "0" * 64
        expected_digest["circuit_manufacturing"]["validation"][
            "expected_identity_matched"
        ] = True
        mutations.append(("wrong expected archive digest", expected_digest))

        archive_size = copy.deepcopy(result)
        impossible_archive = {"bytes": 1, "sha256": "0" * 64}
        archive_size["sources"]["circuit_handoff_bundle"] = impossible_archive
        archive_size["circuit_manufacturing"]["archive"] = copy.deepcopy(
            impossible_archive
        )
        mutations.append(("impossible canonical handoff ZIP size", archive_size))

        manifest_size = copy.deepcopy(result)
        manifest_size["circuit_manufacturing"]["manifest"]["bytes"] += 1
        manifest_size["circuit_manufacturing"]["manifest"]["sha256"] = "0" * 64
        forged_archive = copy.deepcopy(
            manifest_size["circuit_manufacturing"]["archive"]
        )
        forged_archive["bytes"] += 1
        forged_archive["sha256"] = "0" * 64
        manifest_size["circuit_manufacturing"]["archive"] = forged_archive
        manifest_size["sources"]["circuit_handoff_bundle"] = copy.deepcopy(
            forged_archive
        )
        mutations.append(("impossible canonical handoff manifest size", manifest_size))

        board_approval = copy.deepcopy(result)
        board_approval["circuit_manufacturing"]["board_binding"]["counts"][
            "errors"
        ] = 1
        mutations.append(("approved board binding with errors", board_approval))

        catalog_time = copy.deepcopy(result)
        catalog_time["procurement"]["catalog"]["evaluated_at_unix"] = 3
        mutations.append(("catalog evaluation after expiry", catalog_time))

        catalog_ttl = copy.deepcopy(result)
        catalog_ttl["procurement"]["catalog"]["expires_at_unix"] = (
            catalog_ttl["procurement"]["catalog"]["captured_at_unix"]
            + assembly_module.MAX_CATALOG_TTL_SECONDS
            + 1
        )
        mutations.append(("catalog TTL overflow", catalog_ttl))

        for field in ("supplier", "snapshot_id"):
            catalog_identity_text = copy.deepcopy(result)
            catalog_identity_text["procurement"]["catalog"][field] += "\n"
            mutations.append(
                (f"catalog {field} terminal newline", catalog_identity_text)
            )

        catalog_digest_lf = copy.deepcopy(result)
        catalog_digest_lf["procurement"]["catalog"]["catalog_sha256"] += "\n"
        mutations.append(("catalog digest terminal newline", catalog_digest_lf))

        findings_order = copy.deepcopy(result)
        findings_order["procurement"]["approved"] = False
        findings_order["procurement"]["status"] = "rejected"
        findings_order["procurement"]["line_items"] = []
        for key in (
            "reference_sets_matched",
            "part_values_matched",
            "part_footprints_matched",
            "part_mpns_matched",
            "supplier_part_numbers_present",
            "supplier_part_numbers_unambiguous",
        ):
            findings_order["procurement"]["validation"][key] = False
        findings_order["procurement"]["findings"] = [
            {
                "code": code,
                "message": assembly_module._procurement._PROCUREMENT_FINDING_MESSAGES[
                    code
                ],
            }
            for code in ("reference_set_mismatch", "part_value_mismatch")
        ]
        findings_order["complete"] = False
        findings_order["status"] = "incomplete"
        findings_order["findings"] = [
            {
                "code": "procurement_intent_rejected",
                "message": assembly_module._ASSEMBLY_FINDING_MESSAGES[
                    "procurement_intent_rejected"
                ],
            }
        ]
        mutations.append(("unsorted procurement findings", findings_order))

        finding_validation = copy.deepcopy(result)
        finding_validation["procurement"]["approved"] = False
        finding_validation["procurement"]["status"] = "rejected"
        finding_validation["procurement"]["line_items"] = []
        finding_validation["procurement"]["findings"] = [
            {
                "code": "reference_set_mismatch",
                "message": assembly_module._procurement._PROCUREMENT_FINDING_MESSAGES[
                    "reference_set_mismatch"
                ],
            }
        ]
        finding_validation["complete"] = False
        finding_validation["status"] = "incomplete"
        finding_validation["findings"] = copy.deepcopy(findings_order["findings"])
        mutations.append(("finding disagrees with validation", finding_validation))

        bom_count = copy.deepcopy(result)
        bom_count["final_bom"]["counts"]["package_in_bom_parts"] = 0
        mutations.append(("equal BOM identity with unequal count", bom_count))

        cpl_count = copy.deepcopy(result)
        cpl_count["final_cpl"]["counts"]["package_placement_parts"] = 0
        mutations.append(("equal CPL identity with unequal count", cpl_count))

        package_part_count = copy.deepcopy(result)
        package_part_count["final_bom"]["counts"]["package_parts"] = 2
        package_part_count["final_cpl"]["counts"]["package_parts"] = 2
        package_part_count["sources"]["final_cpl_report"] = _identity(
            assembly_module._render_normalized_final_cpl_report(
                package_part_count["final_cpl"]
            )
        )
        mutations.append(
            ("same package-board source with unequal part count", package_part_count)
        )

        cpl_content = copy.deepcopy(result)
        cpl_content["final_cpl"]["in_pos_parts"][0]["x_nm"] += 1
        mutations.append(("final CPL content without raw identity", cpl_content))

        profile_name = copy.deepcopy(result)
        profile_name["circuit_manufacturing"]["manufacturing_package"][
            "profile"
        ] = {
            "kind": "dfm-file",
            "source": {"name": "\N{GRINNING FACE}" * 255, **_identity(b"p")},
        }
        mutations.append(("profile basename UTF-8 byte overflow", profile_name))

        builtin_profile = copy.deepcopy(result)
        builtin_profile["circuit_manufacturing"]["manufacturing_package"][
            "profile"
        ] = {"kind": "builtin", "id": "test\n"}
        mutations.append(("built-in profile terminal newline", builtin_profile))

        board_binding_digest = copy.deepcopy(result)
        board_binding_digest["circuit_manufacturing"]["board_binding"][
            "policy_sha256"
        ] += "\n"
        mutations.append(("board-binding digest terminal newline", board_binding_digest))

        for field in ("mpn", "supplier_part_number", "footprint"):
            catalog_text = copy.deepcopy(result)
            catalog_text["procurement"]["line_items"][0][field] += " "
            mutations.append((f"noncanonical line {field}", catalog_text))

        for label, forged in mutations:
            _rebind(forged)
            with self.subTest(mutation=label), self.assertRaises(
                AssemblyEvidenceError
            ):
                render_assembly_evidence(forged)

        with tempfile.TemporaryDirectory() as directory:
            bom_only_result = _evaluate(
                _fixture(
                    Path(directory).resolve(strict=True),
                    bom_references=("R1", "R2"),
                    cpl_references=("R1",),
                )
            )
        sku_ambiguity = copy.deepcopy(bom_only_result)
        sku_ambiguity["procurement"]["line_items"][1][
            "supplier_part_number"
        ] = sku_ambiguity["procurement"]["line_items"][0][
            "supplier_part_number"
        ]
        _rebind(sku_ambiguity)
        with self.assertRaises(AssemblyEvidenceError):
            render_assembly_evidence(sku_ambiguity)

        casefold_mpn = copy.deepcopy(bom_only_result)
        casefold_mpn["procurement"]["line_items"][1]["mpn"] = casefold_mpn[
            "procurement"
        ]["line_items"][0]["mpn"].lower()
        _rebind(casefold_mpn)
        with self.assertRaises(AssemblyEvidenceError):
            render_assembly_evidence(casefold_mpn)

        digest_mapping = copy.deepcopy(bom_only_result)
        digest_mapping["procurement"]["line_items"][1][
            "catalog_part_sha256"
        ] = digest_mapping["procurement"]["line_items"][0][
            "catalog_part_sha256"
        ]
        _rebind(digest_mapping)
        with self.assertRaises(AssemblyEvidenceError):
            render_assembly_evidence(digest_mapping)

        bom_only_result["membership"]["bom_only"] = [" R2"]
        r2_line = next(
            line
            for line in bom_only_result["procurement"]["line_items"]
            if line["references"] == ["R2"]
        )
        r2_line["references"] = [" R2"]
        _rebind(bom_only_result)
        with self.assertRaises(AssemblyEvidenceError):
            render_assembly_evidence(bom_only_result)

    def test_expected_handoff_identities_remain_renderable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            case = fixture["case"]
            entries = _archive_entries(case["archive_raw"])
            manifest = json.loads(entries[handoff_module.MANIFEST_NAME])
            result = _evaluate(
                fixture,
                expected_archive_sha256=hashlib.sha256(
                    case["archive_raw"]
                ).hexdigest(),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )
        self.assertTrue(
            result["circuit_manufacturing"]["validation"][
                "expected_identity_matched"
            ]
        )
        self.assertEqual(json.loads(render_assembly_evidence(result)), result)


if __name__ == "__main__":
    unittest.main()

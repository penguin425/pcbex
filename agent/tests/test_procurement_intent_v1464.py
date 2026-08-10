from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
import zipfile

import pcbex_agent.procurement_intent as procurement_intent_module

from agent.tests.test_circuit_handoff_bundle_v1453 import (
    _catalog_artifacts,
    _catalog_generation_bundle,
    _check_envelope,
    _render,
)
from agent.tests.test_circuit_handoff_bundle_v1448 import _spec
from pcbex_agent import cli
from pcbex_agent.catalog import (
    canonical_sha256,
    load_catalog_snapshot,
    select_catalog_parts,
    validate_catalog_receipt,
)
from pcbex_agent.circuit_generation import generate_circuit_with_llm
from pcbex_agent.procurement_intent import (
    ProcurementIntentError,
    evaluate_procurement_intent,
    procurement_intent_json_schema,
    validate_procurement_intent,
)

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional schema validation aid
    Draft202012Validator = None


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": _sha(raw)}


def _real_board_and_package() -> tuple[bytes, bytes]:
    board = b"""(kicad_pcb
  (version 20250114)
  (generator pcbex-procurement-test)
  (layers (0 \"F.Cu\" signal) (31 \"B.Cu\" signal))
  (footprint \"Resistor_SMD:R_0603_1608Metric\"
    (layer \"F.Cu\") (at 1 2 0)
    (property \"Reference\" \"R1\") (property \"Value\" \"1k\")
    (property \"MPN\" \"R-1K-0603\") (attr smd)
    (pad \"1\" smd rect (at 0 0) (size 1 1) (layers \"F.Cu\")))
  (footprint \"Resistor_SMD:R_0603_1608Metric\"
    (layer \"F.Cu\") (at 2 2 0)
    (property \"Reference\" \"R2\") (property \"Value\" \"1k\")
    (property \"MPN\" \"R-1K-0603\") (attr smd)
    (pad \"1\" smd rect (at 0 0) (size 1 1) (layers \"F.Cu\")))
)\n"""
    job = json.dumps(
        {
            "GeneralSpecs": {"LayerNumber": 2},
            "FilesAttributes": [
                {"Path": "board-F_Cu.gtl", "FileFunction": "Copper,L1,Top"},
                {"Path": "board-B_Cu.gbl", "FileFunction": "Copper,L2,Bot"},
                {"Path": "board-f_mask.gts", "FileFunction": "SolderMask,Top"},
                {"Path": "board-b_mask.gbs", "FileFunction": "SolderMask,Bot"},
                {"Path": "board-f_silkscreen.gto", "FileFunction": "Legend,Top"},
                {"Path": "board-b_silkscreen.gbo", "FileFunction": "Legend,Bot"},
                {"Path": "board-Edge_Cuts.gm1", "FileFunction": "Profile"},
            ],
        },
        separators=(",", ":"),
    ).encode()
    bom = (
        b"Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n"
        b'1k,"R1,R2",Resistor_SMD:R_0603_1608Metric,2,R-1K-0603,F,SMD\n'
    )
    artifacts = [
        ("board-F_Cu.gtl", b"front-copper"),
        ("board-B_Cu.gbl", b"back-copper"),
        ("board-f_mask.gts", b"front-mask"),
        ("board-b_mask.gbs", b"back-mask"),
        ("board-f_silkscreen.gto", b"front-legend"),
        ("board-b_silkscreen.gbo", b"back-legend"),
        ("board-Edge_Cuts.gm1", b"profile"),
        ("board-job.gbrjob", job),
        ("board.drl", b"drill"),
        ("drc.rpt", b"DRC clean"),
        ("bom.csv", bom),
        (
            "cpl.csv",
            b"Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n"
            b"R1,1,2,0,F\nR2,2,2,0,F\n",
        ),
    ]
    manifest = {
        "schema_version": 1,
        "engine": "pcbex",
        "engine_version": "1.464.0",
        "tools": {
            "kicad_cli": "10.0.5",
            "kicad_cli_about_sha256": "a" * 64,
        },
        "input": {
            "path": "renamed-source.kicad_pcb",
            "bytes": len(board),
            "sha256": _sha(board),
        },
        "project_inputs": [],
        "parts": {"total": 2, "bom": 2, "placement": 2, "dnp": 0},
        "artifacts": [
            {"path": name, "bytes": len(raw), "sha256": _sha(raw)}
            for name, raw in artifacts
        ],
        "archive": "manufacturing.zip",
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        entries = [
            *artifacts,
            (
                "manifest.json",
                json.dumps(manifest, separators=(",", ":")).encode(),
            ),
        ]
        for name, raw in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, raw)
    return board, output.getvalue()


def _write_fake_pcbex(
    root: Path, *, mode: str = "approved", mutate_retained: Path | None = None
) -> list[str]:
    script = root / f"fake-final-bom-{mode}.py"
    script.write_text(
        textwrap.dedent(
            f"""
            import hashlib
            import json
            from pathlib import Path
            import sys
            import time

            MODE = {mode!r}
            MUTATE_RETAINED = {str(mutate_retained) if mutate_retained is not None else None!r}

            def identity(raw):
                return {{"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}

            output = next(value.split("=", 1)[1] for value in sys.argv if value.startswith("--output="))
            separator = sys.argv.index("--")
            board_path = Path(sys.argv[separator + 1])
            package_path = Path(sys.argv[separator + 2])
            board = board_path.read_bytes()
            package = package_path.read_bytes()
            if MODE == "timeout":
                time.sleep(2)
            if MODE == "stdout-overflow":
                sys.stdout.buffer.write(b"x" * (1024 * 1024 + 1))
                sys.stdout.buffer.flush()
            if MODE == "oversized-report":
                Path(output).write_bytes(b"x" * (16 * 1024 * 1024 + 1))
                raise SystemExit(0)
            manifest = b"manifest"
            package_bom = b"bom"
            canonical_bom = b"other" if MODE == "rust-rejected" else package_bom
            package_board = b"other-board" if MODE == "rust-rejected" else board
            parts = [
                {{
                    "reference": "R1",
                    "value": (
                        "x" * 513
                        if MODE == "wide-value-mismatch"
                        else ("wrong" if MODE == "value-mismatch" else "1k")
                    ),
                    "footprint": "Resistor_SMD:R_0603_1608Metric",
                    "mpn": "R-1K-0603",
                    "layer": "F",
                    "type": "SMD",
                }},
                {{
                    "reference": "R3" if MODE == "reference-mismatch" else "R2",
                    "value": "1k",
                    "footprint": "Resistor_SMD:R_0603_1608Metric",
                    "mpn": "R-2K-0603" if MODE == "ambiguous-sku" else "R-1K-0603",
                    "layer": "F",
                    "type": "SMD",
                }},
            ]
            if MODE == "reference-subset":
                parts = parts[:1]
            elif MODE == "reference-empty":
                parts = []
            findings = []
            if MODE == "rust-rejected":
                findings = [
                    {{
                        "code": "canonical_bom_mismatch",
                        "message": "manufacturing package bom.csv does not equal the canonical BOM regenerated from the board",
                    }},
                    {{
                        "code": "package_board_source_mismatch",
                        "message": "manufacturing package input identity does not equal the supplied board",
                    }},
                ]
            report = {{
                "schema_version": 1,
                "scope": "final_bom_source_and_canonical_bom_v1",
                "engine_version": "1.464.0",
                "board_basename": board_path.name,
                "sources": {{
                    "board": identity(board),
                    "manufacturing_package": identity(package),
                    "manifest": identity(manifest),
                    "bom": identity(package_bom),
                    "canonical_bom": identity(canonical_bom),
                    "package_board_source": identity(package_board),
                }},
                "counts": {{
                    "board_parts": 2,
                    "board_in_bom_parts": len(parts),
                    "package_parts": 2,
                    "package_in_bom_parts": len(parts),
                    "findings": len(findings),
                }},
                "in_bom_parts": parts,
                "findings": findings,
                "approved": not findings,
            }}
            if MODE == "bad-identity":
                report["sources"]["board"]["sha256"] = "0" * 64
            if MODE == "malformed":
                Path(output).write_bytes(b"not-json")
            else:
                Path(output).write_bytes(json.dumps(report, separators=(",", ":")).encode("utf-8") + b"\\n")
            if MUTATE_RETAINED is not None:
                Path(MUTATE_RETAINED).write_bytes(b"{{}}\\n")
            """
        ),
        encoding="utf-8",
        newline="\n",
    )
    return [sys.executable, str(script)]


class ProcurementIntentV1464Tests(unittest.TestCase):
    def _inputs(
        self,
        root: Path,
        *,
        supplier_part_number: str | None = "C1000",
        snapshot_name: str | None = None,
    ) -> dict[str, object]:
        artifacts = _catalog_artifacts(root / "catalog", source_kind="file")
        board = root / "design.kicad_pcb"
        package = root / "manufacturing.zip"
        bundle = root / "generation-bundle.json"
        board.write_bytes(b"board")
        package.write_bytes(b"package")
        snapshot_value = artifacts["snapshot"].to_mapping()
        snapshot_value["parts"][0]["supplier_part_number"] = supplier_part_number
        snapshot_path = artifacts["snapshot_path"]
        if snapshot_name is not None:
            snapshot_path = root / "renamed-snapshot" / snapshot_name
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_bytes(_render(snapshot_value))
        snapshot = load_catalog_snapshot(snapshot_path, evaluated_at_unix=150)
        bundle_value, _initial = _catalog_generation_bundle(snapshot)
        bundle.write_bytes(_render(bundle_value))
        return {
            "board": board,
            "package": package,
            "bundle": bundle,
            "snapshot": snapshot_path,
        }

    def _ambiguous_sku_inputs(self, root: Path) -> dict[str, object]:
        artifacts = _catalog_artifacts(root / "catalog", source_kind="file")
        snapshot_value = artifacts["snapshot"].to_mapping()
        second = dict(snapshot_value["parts"][0])
        second.update(
            {
                "mpn": "R-2K-0603",
                "supplier_part_number": "C1000",
                "description": "2k resistor",
                "tags": ["2k", "resistor"],
            }
        )
        snapshot_value["parts"].append(second)
        snapshot_path = root / "ambiguous-catalog.json"
        snapshot_path.write_bytes(_render(snapshot_value))
        snapshot = load_catalog_snapshot(snapshot_path, evaluated_at_unix=150)
        initial = _spec()
        initial["parts"][1]["mpn"] = "R-2K-0603"

        def checker(path: Path, _remaining: float) -> dict[str, object]:
            selected = (
                initial
                if path.name.startswith("candidate-")
                else json.loads(path.read_text(encoding="utf-8"))
            )
            return _check_envelope(selected)

        def selector(spec: dict[str, object], _remaining: float):
            return select_catalog_parts(spec, snapshot, evaluated_at_unix=150)

        def receipt_validator(
            original: dict[str, object],
            resolved: dict[str, object],
            receipt: dict[str, object],
            _remaining: float,
        ) -> None:
            validate_catalog_receipt(
                receipt,
                original,
                resolved,
                snapshot,
                evaluated_at_unix=150,
            )

        bundle_value = generate_circuit_with_llm(
            "two resistors",
            {"type": "object"},
            lambda _prompt, _remaining: '{"candidate":1}',
            checker,
            catalog_selector=selector,
            catalog_receipt_validator=receipt_validator,
        )
        board = root / "design.kicad_pcb"
        package = root / "manufacturing.zip"
        bundle = root / "generation-bundle.json"
        board.write_bytes(b"board")
        package.write_bytes(b"package")
        bundle.write_bytes(_render(bundle_value))
        return {
            "board": board,
            "package": package,
            "bundle": bundle,
            "snapshot": snapshot_path,
        }

    def test_exact_per_board_catalog_binding_is_approved_and_closed(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        inputs = self._inputs(root)
        result = evaluate_procurement_intent(
            inputs["board"],
            inputs["package"],
            inputs["bundle"],
            inputs["snapshot"],
            _write_fake_pcbex(root),
        )
        self.assertTrue(result["approved"])
        self.assertEqual(result["status"], "approved")
        self.assertFalse(result["procurement_authorized"])
        self.assertFalse(result["network_performed"])
        self.assertFalse(result["order_placed"])
        self.assertEqual(result["quantity_basis"], "per_board")
        self.assertEqual(
            result["line_items"],
            [
                {
                    "mpn": "R-1K-0603",
                    "supplier_part_number": "C1000",
                    "catalog_part_sha256": result["line_items"][0][
                        "catalog_part_sha256"
                    ],
                    "footprint": "Resistor_SMD:R_0603_1608Metric",
                    "quantity": 2,
                    "references": ["R1", "R2"],
                }
            ],
        )
        self.assertEqual(set(result), set(procurement_intent_json_schema()["required"]))
        self.assertRegex(result["binding_sha256"], r"^[0-9a-f]{64}$")
        if Draft202012Validator is not None:
            Draft202012Validator.check_schema(procurement_intent_json_schema())
            validator = Draft202012Validator(procurement_intent_json_schema())
            validator.validate(result)
            inconsistent = json.loads(json.dumps(result))
            inconsistent["status"] = "rejected"
            self.assertTrue(list(validator.iter_errors(inconsistent)))
            inconsistent = json.loads(json.dumps(result))
            inconsistent["final_bom"]["approved"] = False
            self.assertTrue(list(validator.iter_errors(inconsistent)))

    def test_real_rust_final_bom_bridge_when_binary_is_supplied(self) -> None:
        binary = os.environ.get("PCBEX_TEST_BINARY")
        if not binary:
            self.skipTest("PCBEX_TEST_BINARY is not supplied")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        inputs = self._inputs(root)
        board, package = _real_board_and_package()
        Path(inputs["board"]).write_bytes(board)
        Path(inputs["package"]).write_bytes(package)
        result = evaluate_procurement_intent(
            inputs["board"],
            inputs["package"],
            inputs["bundle"],
            inputs["snapshot"],
            binary,
        )
        self.assertTrue(result["approved"])
        self.assertTrue(result["final_bom"]["approved"])
        self.assertEqual(result["final_bom"]["board_basename"], "design.kicad_pcb")
        self.assertEqual(result["line_items"][0]["quantity"], 2)
        self.assertEqual(result["line_items"][0]["references"], ["R1", "R2"])

    def test_semantic_mismatches_are_retained_without_partial_lines(self) -> None:
        for mode, expected_code in (
            ("value-mismatch", "part_value_mismatch"),
            ("wide-value-mismatch", "part_value_mismatch"),
            ("rust-rejected", "final_bom_rejected"),
        ):
            with self.subTest(mode=mode):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name).resolve()
                inputs = self._inputs(root)
                result = evaluate_procurement_intent(
                    inputs["board"],
                    inputs["package"],
                    inputs["bundle"],
                    inputs["snapshot"],
                    _write_fake_pcbex(root, mode=mode),
                )
                self.assertFalse(result["approved"])
                self.assertEqual(result["status"], "rejected")
                self.assertEqual(result["line_items"], [])
                self.assertIn(expected_code, {item["code"] for item in result["findings"]})
                if Draft202012Validator is not None and mode == "rust-rejected":
                    Draft202012Validator(procurement_intent_json_schema()).validate(result)

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        inputs = self._inputs(root, supplier_part_number=None)
        result = evaluate_procurement_intent(
            inputs["board"],
            inputs["package"],
            inputs["bundle"],
            inputs["snapshot"],
            _write_fake_pcbex(root),
        )
        self.assertFalse(result["approved"])
        self.assertEqual(result["line_items"], [])
        self.assertIn(
            "supplier_part_number_missing",
            {item["code"] for item in result["findings"]},
        )

        for mode in ("reference-subset", "reference-empty"):
            with self.subTest(mode=mode):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name).resolve()
                inputs = self._inputs(root)
                result = evaluate_procurement_intent(
                    inputs["board"],
                    inputs["package"],
                    inputs["bundle"],
                    inputs["snapshot"],
                    _write_fake_pcbex(root, mode=mode),
                )
                self.assertFalse(result["approved"])
                self.assertEqual(result["line_items"], [])
                self.assertEqual(
                    result["validation"],
                    {
                        "final_bom_verified": True,
                        "catalog_selection_replayed": True,
                        "reference_sets_matched": False,
                        "part_values_matched": False,
                        "part_footprints_matched": False,
                        "part_mpns_matched": False,
                        "supplier_part_numbers_present": False,
                        "supplier_part_numbers_unambiguous": False,
                        "caller_inputs_unchanged": True,
                    },
                )
                self.assertEqual(
                    {item["code"] for item in result["findings"]},
                    {"reference_set_mismatch"},
                )

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        inputs = self._ambiguous_sku_inputs(root)
        result = evaluate_procurement_intent(
            inputs["board"],
            inputs["package"],
            inputs["bundle"],
            inputs["snapshot"],
            _write_fake_pcbex(root, mode="ambiguous-sku"),
        )
        self.assertFalse(result["approved"])
        self.assertEqual(result["line_items"], [])
        self.assertTrue(result["validation"]["reference_sets_matched"])
        self.assertTrue(result["validation"]["supplier_part_numbers_present"])
        self.assertFalse(result["validation"]["supplier_part_numbers_unambiguous"])
        self.assertEqual(
            {item["code"] for item in result["findings"]},
            {"supplier_part_number_ambiguous"},
        )

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        inputs = self._inputs(root)
        result = evaluate_procurement_intent(
            inputs["board"],
            inputs["package"],
            inputs["bundle"],
            inputs["snapshot"],
            _write_fake_pcbex(root, mode="reference-mismatch"),
        )
        self.assertFalse(result["approved"])
        self.assertEqual(result["line_items"], [])
        self.assertFalse(result["validation"]["reference_sets_matched"])
        self.assertFalse(result["validation"]["part_values_matched"])
        self.assertFalse(result["validation"]["part_footprints_matched"])
        self.assertFalse(result["validation"]["part_mpns_matched"])
        self.assertFalse(result["validation"]["supplier_part_numbers_present"])
        self.assertIn(
            "supplier_part_number_missing",
            {item["code"] for item in result["findings"]},
        )

    def test_role_staging_is_collision_free_and_board_names_are_portable(self) -> None:
        for snapshot_name in (
            "manufacturing.zip",
            "design.kicad_pcb",
            "final-bom-report.json",
        ):
            with self.subTest(snapshot_name=snapshot_name):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name).resolve()
                inputs = self._inputs(root, snapshot_name=snapshot_name)
                result = evaluate_procurement_intent(
                    inputs["board"],
                    inputs["package"],
                    inputs["bundle"],
                    inputs["snapshot"],
                    _write_fake_pcbex(root),
                )
                self.assertTrue(result["approved"])

        for board_name in ("CON.kicad_pcb", ".kicad_pcb"):
            with self.subTest(board_name=board_name):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name).resolve()
                inputs = self._inputs(root)
                renamed = root / board_name
                Path(inputs["board"]).rename(renamed)
                with self.assertRaisesRegex(
                    ProcurementIntentError, "board basename is invalid"
                ):
                    evaluate_procurement_intent(
                        renamed,
                        inputs["package"],
                        inputs["bundle"],
                        inputs["snapshot"],
                        _write_fake_pcbex(root),
                    )

    def test_retained_validation_replays_exact_evidence_and_freezes_pathlikes(self) -> None:
        class OneShotPath:
            def __init__(self, value: Path) -> None:
                self.value = str(value)
                self.calls = 0

            def __fspath__(self) -> str:
                self.calls += 1
                if self.calls != 1:
                    raise AssertionError("caller PathLike was converted more than once")
                return self.value

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        inputs = self._inputs(root)
        command = _write_fake_pcbex(root)
        result = evaluate_procurement_intent(
            inputs["board"],
            inputs["package"],
            inputs["bundle"],
            inputs["snapshot"],
            command,
        )
        paths = [
            OneShotPath(inputs["board"]),
            OneShotPath(inputs["package"]),
            OneShotPath(inputs["bundle"]),
            OneShotPath(inputs["snapshot"]),
        ]
        replayed = validate_procurement_intent(result, *paths, command)
        self.assertEqual(replayed, result)
        self.assertTrue(all(path.calls == 1 for path in paths))

        forged = json.loads(json.dumps(result))
        forged["approved"] = False
        with self.assertRaisesRegex(
            ProcurementIntentError, "does not match exact replayed evidence"
        ):
            validate_procurement_intent(
                forged,
                inputs["board"],
                inputs["package"],
                inputs["bundle"],
                inputs["snapshot"],
                command,
            )

        for path, forged_value in (
            (("schema_version",), 1.0),
            (("approved",), 1),
            (("network_performed",), 0),
            (("final_bom", "counts", "board_parts"), True),
            (("sources", "board", "bytes"), float(result["sources"]["board"]["bytes"])),
        ):
            with self.subTest(strict_json_path=path):
                forged = json.loads(json.dumps(result))
                target = forged
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = forged_value
                with self.assertRaisesRegex(
                    ProcurementIntentError, "does not match exact replayed evidence"
                ):
                    validate_procurement_intent(
                        forged,
                        inputs["board"],
                        inputs["package"],
                        inputs["bundle"],
                        inputs["snapshot"],
                        command,
                    )

        class StatefulMapping(dict[str, object]):
            def __init__(self, value: dict[str, object]) -> None:
                super().__init__(value)
                self.calls = 0

            def items(self):  # type: ignore[override]
                self.calls += 1
                if self.calls == 1:
                    return super().items()
                return {"overflow": "x" * (17 * 1024 * 1024)}.items()

        stateful = StatefulMapping(json.loads(json.dumps(result)))
        self.assertEqual(
            validate_procurement_intent(
                stateful,
                inputs["board"],
                inputs["package"],
                inputs["bundle"],
                inputs["snapshot"],
                command,
            ),
            result,
        )
        self.assertEqual(stateful.calls, 1)

        retained_path = root / "retained-intent.json"
        retained_path.write_text(
            json.dumps(result, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ProcurementIntentError, "changed during retained replay"
        ):
            validate_procurement_intent(
                retained_path,
                inputs["board"],
                inputs["package"],
                inputs["bundle"],
                inputs["snapshot"],
                _write_fake_pcbex(root, mutate_retained=retained_path),
            )
        self.assertEqual(retained_path.read_bytes(), b"{}\n")

        retained_path.write_bytes(_render(result))
        original_reread_inputs = procurement_intent_module._reread_inputs
        reread_calls = 0

        def mutate_retained_during_outer_final_scan(*args, **kwargs):
            nonlocal reread_calls
            original_reread_inputs(*args, **kwargs)
            reread_calls += 1
            if reread_calls == 3:
                retained_path.write_bytes(b"{}\n")

        with (
            mock.patch.object(
                procurement_intent_module,
                "_reread_inputs",
                side_effect=mutate_retained_during_outer_final_scan,
            ),
            self.assertRaisesRegex(
                ProcurementIntentError, "changed during retained replay"
            ),
        ):
            validate_procurement_intent(
                retained_path,
                inputs["board"],
                inputs["package"],
                inputs["bundle"],
                inputs["snapshot"],
                command,
            )
        self.assertEqual(reread_calls, 3)
        self.assertEqual(retained_path.read_bytes(), b"{}\n")

        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        with self.assertRaisesRegex(ProcurementIntentError, "report is invalid"):
            validate_procurement_intent(
                recursive,
                inputs["board"],
                inputs["package"],
                inputs["bundle"],
                inputs["snapshot"],
                command,
            )

    def test_injected_command_and_report_subclasses_are_bounded_before_copy(self) -> None:
        class LyingCommand(str):
            def __len__(self) -> int:
                return 1

            def __contains__(self, _item: object) -> bool:
                return False

            def encode(self, *_args: object, **_kwargs: object) -> bytes:
                return b"x"

        oversized_command = LyingCommand(
            "x" * (procurement_intent_module.MAXIMUM_ARGUMENT_BYTES + 1)
        )
        with mock.patch.object(
            procurement_intent_module,
            "_exact_command_string",
            side_effect=AssertionError("command copied before its bound was checked"),
        ):
            with self.assertRaisesRegex(ProcurementIntentError, "command is invalid"):
                procurement_intent_module._normalize_command(oversized_command)

        class LyingBytes(bytes):
            def __len__(self) -> int:
                return 1

            def __bytes__(self) -> bytes:
                raise AssertionError("report copied through a dynamic bytes hook")

        with self.assertRaisesRegex(ProcurementIntentError, "report is invalid"):
            procurement_intent_module._bounded_bytes_like(
                LyingBytes(b"x" * 64),
                maximum=32,
                label="procurement intent report",
            )

    def test_shape_valid_receipt_forgery_is_rejected_by_full_replay(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        inputs = self._inputs(root)
        bundle = json.loads(Path(inputs["bundle"]).read_text(encoding="utf-8"))
        receipt = bundle["catalog_receipt"]
        receipt["selections"][0]["supplier_part_number"] = "FORGED"
        receipt["selections_sha256"] = canonical_sha256(receipt["selections"])
        forged_receipt_sha = canonical_sha256(receipt)
        bundle["catalog_receipt_sha256"] = forged_receipt_sha
        for record in bundle["attempt_history"]:
            if record["catalog_receipt_sha256"] is not None:
                record["catalog_receipt_sha256"] = forged_receipt_sha
        Path(inputs["bundle"]).write_bytes(_render(bundle))
        with self.assertRaisesRegex(
            ProcurementIntentError, "catalog selection cannot be fully replayed"
        ):
            evaluate_procurement_intent(
                inputs["board"],
                inputs["package"],
                inputs["bundle"],
                inputs["snapshot"],
                _write_fake_pcbex(root),
            )

    def test_child_report_identity_and_shape_forgery_fail_hard(self) -> None:
        for mode in ("bad-identity", "malformed", "stdout-overflow", "oversized-report"):
            with self.subTest(mode=mode):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name).resolve()
                inputs = self._inputs(root)
                with self.assertRaises(ProcurementIntentError):
                    evaluate_procurement_intent(
                        inputs["board"],
                        inputs["package"],
                        inputs["bundle"],
                        inputs["snapshot"],
                        _write_fake_pcbex(root, mode=mode),
                    )

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        inputs = self._inputs(root)
        with self.assertRaisesRegex(ProcurementIntentError, "child process failed"):
            evaluate_procurement_intent(
                inputs["board"],
                inputs["package"],
                inputs["bundle"],
                inputs["snapshot"],
                _write_fake_pcbex(root, mode="timeout"),
                timeout_seconds=0.5,
            )

    def test_cli_retains_rejection_before_final_gate_and_never_clobbers(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        inputs = self._inputs(root)
        output = root / "intent.json"
        rejected = evaluate_procurement_intent(
            inputs["board"],
            inputs["package"],
            inputs["bundle"],
            inputs["snapshot"],
            _write_fake_pcbex(root, mode="value-mismatch"),
        )
        argv = [
            "pcbex-agent",
            "build-procurement-intent",
            str(inputs["board"]),
            str(inputs["package"]),
            "--circuit-generation",
            str(inputs["bundle"]),
            "--catalog-snapshot",
            str(inputs["snapshot"]),
            "--pcbex",
            "ignored-by-test",
            "--output",
            str(output),
            "--require-approved",
        ]
        # The API tests above cover the real child-vector seam.  Patch only
        # the evaluator here so this CLI retention/no-clobber regression is
        # equally executable on POSIX and Windows.
        with mock.patch.object(cli, "evaluate_procurement_intent", return_value=rejected):
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(SystemExit, "was not technically approved"):
                    cli.main()
        retained = output.read_bytes()
        self.assertFalse(json.loads(retained)["approved"])
        with mock.patch.object(
            cli, "evaluate_procurement_intent", return_value=rejected
        ) as evaluator:
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(SystemExit, "already exists"):
                    cli.main()
        evaluator.assert_not_called()
        self.assertEqual(output.read_bytes(), retained)

    def test_schema_cli_is_closed_and_never_clobbers(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        output = root / "schema.json"
        argv = [
            "pcbex-agent",
            "procurement-intent-schema",
            "--output",
            str(output),
        ]
        with mock.patch.object(sys, "argv", argv):
            cli.main()
        retained = output.read_bytes()
        schema = json.loads(retained)
        self.assertFalse(schema["additionalProperties"])
        if Draft202012Validator is not None:
            Draft202012Validator.check_schema(schema)
        with mock.patch.object(sys, "argv", argv):
            with self.assertRaisesRegex(SystemExit, "already exists"):
                cli.main()
        self.assertEqual(output.read_bytes(), retained)


if __name__ == "__main__":
    unittest.main()

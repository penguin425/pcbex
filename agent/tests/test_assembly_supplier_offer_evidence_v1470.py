from __future__ import annotations

from collections.abc import Iterator, Mapping
import copy
import hashlib
import json
import ntpath
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from agent.tests.test_assembly_evidence_v1467 import (
    _evaluate as _evaluate_assembly,
    _fixture as _assembly_fixture,
)
import pcbex_agent.assembly_evidence as assembly_module
import pcbex_agent.assembly_supplier_offer_evidence as module
import pcbex_agent.circuit_handoff_bundle as handoff_module
import pcbex_agent.supplier_offer as offer_module
import pcbex_agent.supplier_offer_acquisition as acquisition_module
from pcbex_agent.assembly_supplier_offer_evidence import (
    AssemblySupplierOfferEvidenceError,
    assembly_supplier_offer_evidence_json_schema,
    build_assembly_supplier_offer_evidence,
    evaluate_assembly_supplier_offer_evidence,
    render_assembly_supplier_offer_evidence,
    validate_assembly_supplier_offer_evidence,
)


def _render(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode()
        + b"\n"
    )


def _rebind_outer(value: dict[str, object]) -> None:
    payload = {key: item for key, item in value.items() if key != "binding_sha256"}
    value["binding_sha256"] = hashlib.sha256(
        module.ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BINDING_DOMAIN
        + module._compact_json(payload)
    ).hexdigest()


def _identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _rebind_assembly(value: dict[str, object]) -> None:
    payload = {key: item for key, item in value.items() if key != "binding_sha256"}
    value["binding_sha256"] = hashlib.sha256(
        assembly_module.ASSEMBLY_EVIDENCE_BINDING_DOMAIN
        + assembly_module._compact_json(payload)
    ).hexdigest()


def _rebind_coverage(value: dict[str, object]) -> None:
    payload = {key: item for key, item in value.items() if key != "binding_sha256"}
    value["binding_sha256"] = hashlib.sha256(
        offer_module.SUPPLIER_OFFER_COVERAGE_BINDING_DOMAIN
        + offer_module._compact_json(payload)
    ).hexdigest()


def _fixture(
    root: Path,
    *,
    assembly_complete: bool = True,
    shortfall: bool = False,
    supplier_mismatch: bool = False,
) -> dict[str, object]:
    fixture = _assembly_fixture(root, board_approved=assembly_complete)
    procurement = fixture["procurement"]
    assert isinstance(procurement, dict)
    intent_raw = _render(procurement)
    intent_path = fixture["procurement_path"]
    assert isinstance(intent_path, Path)
    intent_path.write_bytes(intent_raw)

    assembly = _evaluate_assembly(fixture)
    assembly_path = root / "assembly-evidence.json"
    assembly_path.write_bytes(assembly_module.render_assembly_evidence(assembly))

    case = fixture["case"]
    assert isinstance(case, Mapping)
    _summary, entries = handoff_module.validate_circuit_handoff_archive(
        case["archive_raw"]
    )
    generation_raw = entries[handoff_module.GENERATION_BUNDLE_NAME]
    generation_path = root / "generation-bundle.json"
    generation_path.write_bytes(generation_raw)

    supplier = "other-supplier" if supplier_mismatch else "test"
    offer = {
        "schema_version": 1,
        "scope": offer_module.SUPPLIER_OFFER_SCOPE,
        "procurement_intent_sha256": hashlib.sha256(intent_raw).hexdigest(),
        "supplier": supplier,
        "offer_id": "offer-v1470",
        "valid_from_unix": 100,
        "valid_until_unix": 200,
        "currency": "USD",
        "lines": [
            {
                "mpn": line["mpn"],
                "supplier_part_number": line["supplier_part_number"],
                "catalog_part_sha256": line["catalog_part_sha256"],
                "quoted_quantity": 2 if shortfall else line["quantity"] * 3,
                "line_subtotal_micros": 100,
            }
            for line in procurement["line_items"]
        ],
    }
    offer_path = root / "supplier-offer.json"
    offer_path.write_bytes(_render(offer))
    coverage_args = (
        case["board"],
        fixture["package"],
        generation_path,
        fixture["catalog_path"],
        intent_path,
        offer_path,
    )
    with mock.patch.object(
        offer_module._procurement,
        "validate_procurement_intent",
        return_value=copy.deepcopy(procurement),
    ):
        coverage = offer_module.evaluate_supplier_offer_coverage(
            *coverage_args, requested_boards=3, evaluated_at_unix=100
        )
    coverage_path = root / "supplier-offer-coverage.json"
    coverage_path.write_bytes(
        offer_module.render_supplier_offer_coverage(coverage)
    )

    offer_raw = offer_path.read_bytes()
    intent_digest = hashlib.sha256(intent_raw).hexdigest()
    endpoint = "https://offers.example.test/quote/v1"
    receipt = {
        "adapter": acquisition_module.SUPPLIER_OFFER_FETCH_ADAPTER,
        "adapter_network_performed": True,
        "current_availability_verified": False,
        "endpoint_id": endpoint,
        "fetched_at_unix": 100,
        "inventory_reserved": False,
        "offer_authenticity_verified": False,
        "offer_bytes": len(offer_raw),
        "offer_sha256": hashlib.sha256(offer_raw).hexdigest(),
        "order_placed": False,
        "order_ready": False,
        "payment_performed": False,
        "price_authenticity_verified": False,
        "procurement_authorized": False,
        "procurement_intent_sha256": intent_digest,
        "request_sha256": acquisition_module._request_sha256(
            endpoint, supplier, intent_digest
        ),
        "response_bytes": len(offer_raw),
        "response_sha256": hashlib.sha256(offer_raw).hexdigest(),
        "schema_version": 1,
        "scope": acquisition_module.SUPPLIER_OFFER_FETCH_RECEIPT_SCOPE,
        "status": 200,
        "supplier": supplier,
        "supplier_authenticity_verified": False,
        "trusted_time_verified": False,
    }
    receipt_path = root / "supplier-offer-fetch-receipt.json"
    receipt_path.write_bytes(_render(receipt))
    return {
        **fixture,
        "assembly": assembly,
        "assembly_path": assembly_path,
        "generation_raw": generation_raw,
        "offer": offer,
        "offer_path": offer_path,
        "receipt": receipt,
        "receipt_path": receipt_path,
        "coverage": coverage,
        "coverage_path": coverage_path,
    }


def _arguments(fixture: Mapping[str, object]) -> tuple[object, ...]:
    case = fixture["case"]
    assert isinstance(case, Mapping)
    return (
        case["archive"],
        case["board"],
        fixture["package"],
        case["report"],
        fixture["procurement_path"],
        fixture["catalog_path"],
        fixture["final_cpl_path"],
        fixture["assembly_path"],
        fixture["offer_path"],
        fixture["receipt_path"],
        fixture["coverage_path"],
        fixture["command"],
    )


def _evaluate(fixture: Mapping[str, object], *args: object, **kwargs: object):
    arguments = args or _arguments(fixture)
    with mock.patch.object(
        assembly_module._procurement,
        "validate_procurement_intent",
        return_value=copy.deepcopy(fixture["procurement"]),
    ) as replay:
        result = evaluate_assembly_supplier_offer_evidence(
            *arguments,
            requested_boards=3,
            evaluated_at_unix=100,
            **kwargs,
        )
    return result, replay.call_count


class _OnePassMapping(Mapping[str, object]):
    def __init__(self, value: Mapping[str, object]) -> None:
        self.value = value
        self.calls = 0

    def __getitem__(self, key: str) -> object:
        raise AssertionError("one-pass snapshot must use items()")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("one-pass snapshot must use items()")

    def __len__(self) -> int:
        return len(self.value)

    def items(self):  # type: ignore[override]
        self.calls += 1
        if self.calls != 1:
            raise AssertionError("Mapping traversed more than once")
        return self.value.items()


class _BytesWithPath(bytes):
    def __fspath__(self) -> str:
        raise AssertionError("bytes must not dispatch as PathLike")


class _OneShotPath(os.PathLike[str]):
    def __init__(self, path: Path, hook=None) -> None:
        self.path = path
        self.hook = hook
        self.calls = 0

    def __fspath__(self) -> str:
        self.calls += 1
        if self.calls != 1:
            raise RuntimeError("PathLike converted more than once")
        if self.hook is not None:
            self.hook()
        return str(self.path)


class AssemblySupplierOfferEvidenceV1470Tests(unittest.TestCase):
    def test_complete_result_is_closed_canonical_bound_and_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            result, replay_count = _evaluate(fixture)
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(set(result), module._RESULT_KEYS)
        self.assertEqual(set(result["sources"]), module._SOURCE_KEYS)
        self.assertEqual(set(result["validation"]), set(module._VALIDATION_KEYS))
        self.assertTrue(all(result["validation"].values()))
        self.assertTrue(all(result[key] is False for key in module._FALSE_CLAIM_KEYS))
        self.assertEqual(replay_count, 2)
        self.assertEqual(result["assembly_evidence"], fixture["assembly"])
        self.assertEqual(result["supplier_offer_coverage"], fixture["coverage"])
        self.assertEqual(result["supplier_offer_fetch_receipt"], fixture["receipt"])
        rendered = render_assembly_supplier_offer_evidence(result)
        self.assertTrue(rendered.endswith(b"\n"))
        self.assertFalse(rendered[:-1].endswith(b"\n"))
        payload = {key: value for key, value in result.items() if key != "binding_sha256"}
        self.assertEqual(
            result["binding_sha256"],
            hashlib.sha256(
                module.ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BINDING_DOMAIN
                + module._compact_json(payload)
            ).hexdigest(),
        )
        self.assertIs(
            build_assembly_supplier_offer_evidence,
            evaluate_assembly_supplier_offer_evidence,
        )
        schema = assembly_supplier_offer_evidence_json_schema()
        self.assertEqual(
            schema["$id"],
            "https://github.com/penguin425/pcbex/schemas/"
            "offline-exact-board-assembly-supplier-offer-evidence-v1.json",
        )
        self.assertNotIn("$id", schema["properties"]["assembly_evidence"])
        if Draft202012Validator is not None:
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(result)

    def test_retained_child_path_bytes_and_one_pass_mapping_are_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            expected, _count = _evaluate(fixture)
            args = list(_arguments(fixture))
            args[7] = _BytesWithPath(Path(fixture["assembly_path"]).read_bytes())
            args[9] = _BytesWithPath(Path(fixture["receipt_path"]).read_bytes())
            args[10] = _BytesWithPath(Path(fixture["coverage_path"]).read_bytes())
            bytes_result, _count = _evaluate(fixture, *args)
            mappings = [
                _OnePassMapping(copy.deepcopy(fixture["assembly"])),
                _OnePassMapping(copy.deepcopy(fixture["receipt"])),
                _OnePassMapping(copy.deepcopy(fixture["coverage"])),
            ]
            args[7], args[9], args[10] = mappings
            mapping_result, _count = _evaluate(fixture, *args)
        self.assertEqual(bytes_result, expected)
        self.assertEqual(mapping_result, expected)
        self.assertEqual([value.calls for value in mappings], [1, 1, 1])

    def test_outer_findings_retain_each_negative_and_sort_both(self) -> None:
        scenarios = (
            (False, False, ["assembly_evidence_incomplete"]),
            (True, True, ["supplier_offer_not_covered"]),
            (
                False,
                True,
                ["assembly_evidence_incomplete", "supplier_offer_not_covered"],
            ),
        )
        for assembly_complete, shortfall, codes in scenarios:
            with self.subTest(codes=codes), tempfile.TemporaryDirectory() as directory:
                fixture = _fixture(
                    Path(directory).resolve(strict=True),
                    assembly_complete=assembly_complete,
                    shortfall=shortfall,
                )
                result, _count = _evaluate(fixture)
            self.assertFalse(result["complete"])
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual([finding["code"] for finding in result["findings"]], codes)

    def test_supplier_mismatch_remains_a_valid_coverage_negative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(
                Path(directory).resolve(strict=True), supplier_mismatch=True
            )
            result, _count = _evaluate(fixture)
        self.assertFalse(result["complete"])
        self.assertIn(
            "supplier_mismatch",
            [item["code"] for item in result["supplier_offer_coverage"]["findings"]],
        )

    def test_receipt_and_selector_mismatches_fail_before_assembly_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            receipt = copy.deepcopy(fixture["receipt"])
            receipt["request_sha256"] = "0" * 64
            Path(fixture["receipt_path"]).write_bytes(_render(receipt))
            with mock.patch.object(module._assembly, "validate_assembly_evidence") as child:
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    _evaluate(fixture)
            child.assert_not_called()

            Path(fixture["receipt_path"]).write_bytes(_render(fixture["receipt"]))
            receipt = copy.deepcopy(fixture["receipt"])
            receipt["fetched_at_unix"] = 101
            Path(fixture["receipt_path"]).write_bytes(_render(receipt))
            with mock.patch.object(module._assembly, "validate_assembly_evidence") as child:
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    _evaluate(fixture)
            child.assert_not_called()

    def test_public_validators_run_receipt_assembly_coverage_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            order: list[str] = []
            receipt = module._acquisition.validate_supplier_offer_fetch_receipt
            assembly = module._assembly.validate_assembly_evidence
            coverage = module._offer.validate_supplier_offer_coverage
            with (
                mock.patch.object(
                    module._acquisition,
                    "validate_supplier_offer_fetch_receipt",
                    side_effect=lambda *a, **k: (order.append("receipt"), receipt(*a, **k))[1],
                ),
                mock.patch.object(
                    module._assembly,
                    "validate_assembly_evidence",
                    side_effect=lambda *a, **k: (order.append("assembly"), assembly(*a, **k))[1],
                ),
                mock.patch.object(
                    module._offer,
                    "validate_supplier_offer_coverage",
                    side_effect=lambda *a, **k: (order.append("coverage"), coverage(*a, **k))[1],
                ),
            ):
                result, replay_count = _evaluate(fixture)
        self.assertTrue(result["complete"])
        self.assertEqual(order, ["receipt", "assembly", "coverage"])
        self.assertEqual(replay_count, 2)

    def test_renderer_rejects_outer_cross_binding_timestamp_and_binding_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            result, _count = _evaluate(fixture)
        for mutation in ("board", "timestamp", "binding"):
            forged = copy.deepcopy(result)
            if mutation == "board":
                forged["sources"]["board"]["sha256"] = "0" * 64
                _rebind_outer(forged)
            elif mutation == "timestamp":
                forged["supplier_offer_fetch_receipt"]["fetched_at_unix"] = 101
                raw = _render(forged["supplier_offer_fetch_receipt"])
                forged["sources"]["supplier_offer_fetch_receipt"] = {
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                _rebind_outer(forged)
            else:
                forged["binding_sha256"] = "0" * 64
            with self.subTest(mutation=mutation):
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    render_assembly_supplier_offer_evidence(forged)

    def test_renderer_rejects_every_shared_identity_and_receipt_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            result, _count = _evaluate(fixture)

        shared = (
            "board",
            "manufacturing_package",
            "handoff_generation_bundle",
            "catalog_snapshot",
            "procurement_intent",
            "supplier_offer",
        )
        for key in shared:
            forged = copy.deepcopy(result)
            forged["sources"][key]["sha256"] = "0" * 64
            _rebind_outer(forged)
            with self.subTest(shared_identity=key):
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    render_assembly_supplier_offer_evidence(forged)

        for mutation in (
            "offer_bytes",
            "offer_sha256",
            "supplier",
            "procurement_intent_sha256",
            "request_sha256",
            "adapter_network_performed",
        ):
            forged = copy.deepcopy(result)
            receipt = forged["supplier_offer_fetch_receipt"]
            if mutation == "offer_bytes":
                receipt[mutation] += 1
            elif mutation == "offer_sha256":
                receipt[mutation] = "0" * 64
            elif mutation == "supplier":
                receipt[mutation] = "other-supplier"
                receipt["request_sha256"] = acquisition_module._request_sha256(
                    receipt["endpoint_id"],
                    receipt["supplier"],
                    receipt["procurement_intent_sha256"],
                )
            elif mutation == "procurement_intent_sha256":
                receipt[mutation] = "0" * 64
                receipt["request_sha256"] = acquisition_module._request_sha256(
                    receipt["endpoint_id"],
                    receipt["supplier"],
                    receipt["procurement_intent_sha256"],
                )
            elif mutation == "request_sha256":
                receipt[mutation] = "0" * 64
            else:
                receipt[mutation] = False
            receipt_raw = _render(receipt)
            forged["sources"]["supplier_offer_fetch_receipt"] = _identity(
                receipt_raw
            )
            _rebind_outer(forged)
            with self.subTest(receipt_binding=mutation):
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    render_assembly_supplier_offer_evidence(forged)

        for child, rebind in (
            ("assembly_evidence", _rebind_assembly),
            ("supplier_offer_coverage", _rebind_coverage),
        ):
            forged = copy.deepcopy(result)
            nested = forged[child]
            nested["adapter_network_performed"] = True
            rebind(nested)
            nested_raw = _render(nested)
            forged["sources"][child] = _identity(nested_raw)
            _rebind_outer(forged)
            with self.subTest(network_child=child):
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    render_assembly_supplier_offer_evidence(forged)

        forged = copy.deepcopy(result)
        nested_assembly = forged["assembly_evidence"]
        nested_assembly["procurement"]["catalog"]["snapshot_id"] = "other"
        _rebind_assembly(nested_assembly)
        assembly_raw = assembly_module.render_assembly_evidence(nested_assembly)
        forged["sources"]["assembly_evidence"] = _identity(assembly_raw)
        _rebind_outer(forged)
        with self.assertRaises(AssemblySupplierOfferEvidenceError):
            render_assembly_supplier_offer_evidence(forged)

    def test_outer_validator_accepts_path_bytes_mapping_and_rejects_none(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            result, _count = _evaluate(fixture)
            raw = render_assembly_supplier_offer_evidence(result)
            path = root / "outer.json"
            path.write_bytes(raw)
            for retained in (path, raw, _OnePassMapping(result)):
                with mock.patch.object(
                    assembly_module._procurement,
                    "validate_procurement_intent",
                    return_value=copy.deepcopy(fixture["procurement"]),
                ):
                    observed = validate_assembly_supplier_offer_evidence(
                        retained,
                        *_arguments(fixture),
                        requested_boards=3,
                        evaluated_at_unix=100,
                    )
                self.assertEqual(observed, result)
            with self.assertRaises(AssemblySupplierOfferEvidenceError):
                validate_assembly_supplier_offer_evidence(
                    None,
                    *_arguments(fixture),
                    requested_boards=3,
                    evaluated_at_unix=100,
                )

    def test_alias_rejected_before_mapping_and_outer_mutation_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            mapping = _OnePassMapping(fixture["assembly"])
            args = list(_arguments(fixture))
            args[8] = args[1]
            with self.assertRaises(AssemblySupplierOfferEvidenceError):
                _evaluate(fixture, *args[:7], mapping, *args[8:])
            self.assertEqual(mapping.calls, 0)

            board = Path(args[1])
            correct_board = board.read_bytes()
            board.write_bytes(b"precall-bogus-board")
            retained_child = _OneShotPath(
                Path(fixture["assembly_path"]),
                hook=lambda: board.write_bytes(correct_board),
            )
            child_args = list(_arguments(fixture))
            child_args[7] = retained_child
            with self.assertRaises(AssemblySupplierOfferEvidenceError):
                _evaluate(fixture, *child_args)
            self.assertEqual(retained_child.calls, 1)

            board.write_bytes(b"precall-bogus-board")
            offer_hook = _OneShotPath(
                Path(fixture["offer_path"]),
                hook=lambda: board.write_bytes(correct_board),
            )
            offer_args = list(_arguments(fixture))
            offer_args[8] = offer_hook
            with self.assertRaises(AssemblySupplierOfferEvidenceError):
                _evaluate(fixture, *offer_args)
            self.assertEqual(offer_hook.calls, 1)

            assembly_path = Path(fixture["assembly_path"])
            correct_assembly = assembly_path.read_bytes()
            assembly_path.write_bytes(b"{}\n")
            receipt_hook = _OneShotPath(
                Path(fixture["receipt_path"]),
                hook=lambda: assembly_path.write_bytes(correct_assembly),
            )
            sibling_args = list(_arguments(fixture))
            sibling_args[9] = receipt_hook
            with self.assertRaises(AssemblySupplierOfferEvidenceError):
                _evaluate(fixture, *sibling_args)
            self.assertEqual(receipt_hook.calls, 1)

            result, _count = _evaluate(fixture)
            outer = root / "outer.json"
            outer.write_bytes(render_assembly_supplier_offer_evidence(result))
            board = Path(args[1])
            retained = _OneShotPath(
                outer, hook=lambda: board.write_bytes(board.read_bytes() + b"changed")
            )
            with mock.patch.object(
                assembly_module._procurement,
                "validate_procurement_intent",
                return_value=copy.deepcopy(fixture["procurement"]),
            ):
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    validate_assembly_supplier_offer_evidence(
                        retained,
                        *_arguments(fixture),
                        requested_boards=3,
                        evaluated_at_unix=100,
                    )
            self.assertEqual(retained.calls, 1)

    def test_generation_extraction_and_staged_and_caller_mutations_are_hard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            result, _count = _evaluate(fixture)
            self.assertEqual(
                result["sources"]["handoff_generation_bundle"],
                _identity(fixture["generation_raw"]),
            )

            original_handoff = module._handoff.validate_circuit_handoff_archive

            def altered_handoff(*args, **kwargs):
                summary, entries = original_handoff(*args, **kwargs)
                changed = dict(entries)
                changed[module._handoff.GENERATION_BUNDLE_NAME] = b"{}\n"
                return summary, changed

            with mock.patch.object(
                module._handoff,
                "validate_circuit_handoff_archive",
                side_effect=altered_handoff,
            ):
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    _evaluate(fixture)

            original_assembly = module._assembly.validate_assembly_evidence

            def mutate_staged(*args, **kwargs):
                observed = original_assembly(*args, **kwargs)
                staged_root = Path(args[0]).parents[1]
                staged_offer = staged_root / "offer" / "supplier-offer.json"
                staged_offer.write_bytes(staged_offer.read_bytes() + b"changed")
                return observed

            with mock.patch.object(
                module._assembly,
                "validate_assembly_evidence",
                side_effect=mutate_staged,
            ):
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    _evaluate(fixture)

            original_coverage = module._offer.validate_supplier_offer_coverage

            def mutate_caller(*args, **kwargs):
                observed = original_coverage(*args, **kwargs)
                catalog = Path(fixture["catalog_path"])
                catalog.write_bytes(catalog.read_bytes() + b"changed")
                return observed

            with mock.patch.object(
                module._offer,
                "validate_supplier_offer_coverage",
                side_effect=mutate_caller,
            ):
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    _evaluate(fixture)

    def test_aggregate_bounds_are_representation_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            path_args = list(_arguments(fixture))
            byte_args = list(path_args)
            byte_args[7] = Path(fixture["assembly_path"]).read_bytes()
            byte_args[9] = Path(fixture["receipt_path"]).read_bytes()
            byte_args[10] = Path(fixture["coverage_path"]).read_bytes()
            mapping_args = list(path_args)
            mapping_args[7] = copy.deepcopy(fixture["assembly"])
            mapping_args[9] = copy.deepcopy(fixture["receipt"])
            mapping_args[10] = copy.deepcopy(fixture["coverage"])
            for label, args in (
                ("path", path_args),
                ("bytes", byte_args),
                ("mapping", mapping_args),
            ):
                with self.subTest(direct=label), mock.patch.object(
                    module, "MAXIMUM_TOTAL_INPUT_BYTES", 1
                ):
                    with self.assertRaises(AssemblySupplierOfferEvidenceError):
                        _evaluate(fixture, *args)

            result, _count = _evaluate(fixture)
            outer_raw = render_assembly_supplier_offer_evidence(result)
            outer_path = root / "outer-bound.json"
            outer_path.write_bytes(outer_raw)
            for label, retained in (
                ("path", outer_path),
                ("bytes", outer_raw),
                ("mapping", copy.deepcopy(result)),
            ):
                with self.subTest(validation=label), mock.patch.object(
                    module, "MAXIMUM_VALIDATION_TOTAL_INPUT_BYTES", 1
                ):
                    with self.assertRaises(AssemblySupplierOfferEvidenceError):
                        validate_assembly_supplier_offer_evidence(
                            retained,
                            *_arguments(fixture),
                            requested_boards=3,
                            evaluated_at_unix=100,
                        )

        self.assertEqual(
            module.MAXIMUM_BOARD_BINDING_REPORT_BYTES,
            assembly_module.MAXIMUM_BOARD_BINDING_REPORT_BYTES,
        )
        self.assertEqual(
            module.MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
            acquisition_module.MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        )

    def test_relative_paths_use_initial_root_and_windows_root_relative_is_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            args = list(_arguments(fixture))
            for index in range(11):
                args[index] = os.path.relpath(args[index], root)
            original = Path.cwd()
            try:
                os.chdir(root)
                result, _count = _evaluate(fixture, *args)
            finally:
                os.chdir(original)
            self.assertTrue(result["complete"])

        with (
            mock.patch.object(module.os, "path", ntpath),
            mock.patch.object(
                module,
                "_guard_cwd",
                side_effect=lambda _root, operation, *args, **kwargs: operation(
                    *args, **kwargs
                ),
            ),
        ):
            self.assertEqual(
                module._freeze_against_root(r"\offer.json", "offer", r"C:\base"),
                r"C:\offer.json",
            )
            with self.assertRaises(AssemblySupplierOfferEvidenceError):
                module._freeze_against_root(r"C:offer.json", "offer", r"C:\base")

    def test_cwd_changing_clock_and_path_hooks_fail_closed_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            original = Path.cwd()
            other = root / "other"
            other.mkdir()

            def bad_clock() -> float:
                os.chdir(other)
                return 0.0

            with self.assertRaises(AssemblySupplierOfferEvidenceError):
                _evaluate(fixture, _clock=bad_clock)
            self.assertEqual(Path.cwd(), original)

            args = list(_arguments(fixture))
            changing = _OneShotPath(Path(args[0]), hook=lambda: os.chdir(other))
            args[0] = changing
            with self.assertRaises(AssemblySupplierOfferEvidenceError):
                _evaluate(fixture, *args)
            self.assertEqual(changing.calls, 1)
            self.assertEqual(Path.cwd(), original)

    def test_subsecond_child_budget_fails_before_assembly_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            calls = 0

            def clock() -> float:
                nonlocal calls
                calls += 1
                return 0.0 if calls == 1 else 0.1

            with mock.patch.object(module._assembly, "validate_assembly_evidence") as child:
                with self.assertRaises(AssemblySupplierOfferEvidenceError):
                    _evaluate(fixture, timeout_seconds=1.0, _clock=clock)
            child.assert_not_called()

            class StatefulTimeout:
                called = False

                def __float__(self) -> float:
                    self.called = True
                    return 300.0

            timeout = StatefulTimeout()
            with self.assertRaises(AssemblySupplierOfferEvidenceError):
                _evaluate(fixture, timeout_seconds=timeout)
            self.assertFalse(timeout.called)

    def test_absolute_deadline_uses_exact_half_then_final_reserve_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            now = [0.0]
            observed: list[tuple[str, float, object]] = []

            def clock() -> float:
                return now[0]

            def assembly_child(*args, **kwargs):
                observed.append(
                    ("assembly", kwargs["timeout_seconds"], kwargs["_clock"])
                )
                now[0] = 150.0
                return copy.deepcopy(fixture["assembly"])

            def coverage_child(*args, **kwargs):
                observed.append(
                    ("coverage", kwargs["timeout_seconds"], kwargs["_clock"])
                )
                return copy.deepcopy(fixture["coverage"])

            with (
                mock.patch.object(
                    module._acquisition,
                    "validate_supplier_offer_fetch_receipt",
                    return_value=copy.deepcopy(fixture["receipt"]),
                ),
                mock.patch.object(
                    module._assembly,
                    "validate_assembly_evidence",
                    side_effect=assembly_child,
                ),
                mock.patch.object(
                    module._offer,
                    "validate_supplier_offer_coverage",
                    side_effect=coverage_child,
                ),
            ):
                result, _count = _evaluate(fixture, _clock=clock)
        self.assertTrue(result["complete"])
        self.assertEqual(
            [(label, budget) for label, budget, _clock in observed],
            [("assembly", 150.0), ("coverage", 135.0)],
        )
        self.assertIs(observed[0][2], observed[1][2])

    def test_mapping_provider_exceptions_are_sanitized(self) -> None:
        class BadMapping(Mapping[str, object]):
            def __getitem__(self, key: str) -> object:
                raise LookupError("secret detail")

            def __iter__(self) -> Iterator[str]:
                raise LookupError("secret detail")

            def __len__(self) -> int:
                return 1

            def items(self):  # type: ignore[override]
                raise LookupError("secret detail")

        with self.assertRaises(AssemblySupplierOfferEvidenceError) as caught:
            render_assembly_supplier_offer_evidence(BadMapping())
        self.assertNotIn("secret", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

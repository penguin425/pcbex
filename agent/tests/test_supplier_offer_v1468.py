from __future__ import annotations

from collections.abc import Iterator, Mapping
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional in focused environments
    Draft202012Validator = None

import pcbex_agent.supplier_offer as supplier_offer_module
from pcbex_agent.supplier_offer import (
    MAXIMUM_SUPPLIER_OFFER_BYTES,
    MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
    SupplierOfferError,
    build_supplier_offer_coverage,
    evaluate_supplier_offer_coverage,
    normalized_supplier_offer_json_schema,
    render_supplier_offer_coverage,
    supplier_offer_coverage_json_schema,
    validate_supplier_offer_coverage,
)


def _identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _render(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


def _rebind(value: dict[str, object]) -> None:
    payload = {key: item for key, item in value.items() if key != "binding_sha256"}
    value["binding_sha256"] = hashlib.sha256(
        supplier_offer_module.SUPPLIER_OFFER_COVERAGE_BINDING_DOMAIN
        + supplier_offer_module._compact_json(payload)
    ).hexdigest()


def _fixture(
    root: Path,
    *,
    approved: bool = True,
    line_count: int = 1,
) -> dict[str, object]:
    direct = {
        "board": (root / "design.kicad_pcb", b"board-v1468"),
        "package": (root / "manufacturing.zip", b"package-v1468"),
        "generation": (root / "generation.json", b"generation-v1468"),
        "catalog": (root / "catalog.json", b"catalog-v1468"),
    }
    for path, raw in direct.values():
        path.write_bytes(raw)
    board_path, board_raw = direct["board"]
    package_path, package_raw = direct["package"]
    generation_path, generation_raw = direct["generation"]
    catalog_path, catalog_raw = direct["catalog"]
    common_identity = _identity(b"common-source")

    procurement_lines = [
        {
            "mpn": f"MPN-{index}",
            "supplier_part_number": f"SKU-{index}",
            "catalog_part_sha256": f"{index + 1:064x}",
            "footprint": "Test:R",
            "quantity": index + 1,
            "references": [f"R{index}-{number}" for number in range(index + 1)],
        }
        for index in range(line_count)
    ]
    if approved:
        procurement_findings: list[dict[str, str]] = []
        validation = {
            "final_bom_verified": True,
            "catalog_selection_replayed": True,
            "reference_sets_matched": True,
            "part_values_matched": True,
            "part_footprints_matched": True,
            "part_mpns_matched": True,
            "supplier_part_numbers_present": True,
            "supplier_part_numbers_unambiguous": True,
            "caller_inputs_unchanged": True,
        }
    else:
        procurement_lines = []
        procurement_findings = [
            {
                "code": "reference_set_mismatch",
                "message": supplier_offer_module._procurement._PROCUREMENT_FINDING_MESSAGES[
                    "reference_set_mismatch"
                ],
            }
        ]
        validation = {
            "final_bom_verified": True,
            "catalog_selection_replayed": True,
            "reference_sets_matched": False,
            "part_values_matched": False,
            "part_footprints_matched": False,
            "part_mpns_matched": False,
            "supplier_part_numbers_present": False,
            "supplier_part_numbers_unambiguous": False,
            "caller_inputs_unchanged": True,
        }
    procurement = {
        "schema_version": 1,
        "scope": supplier_offer_module._procurement.PROCUREMENT_INTENT_SCOPE,
        "status": "approved" if approved else "rejected",
        "approved": approved,
        "procurement_authorized": False,
        "network_performed": False,
        "order_placed": False,
        "current_availability_verified": False,
        "supplier_authenticity_verified": False,
        "quantity_basis": "per_board",
        "sources": {
            "board": {"name": board_path.name, **_identity(board_raw)},
            "manufacturing_package": _identity(package_raw),
            "generation_bundle": _identity(generation_raw),
            "catalog_snapshot": _identity(catalog_raw),
            "final_bom_report": common_identity,
            "manifest": common_identity,
            "bom": common_identity,
            "canonical_bom": common_identity,
            "package_board_source": _identity(board_raw),
        },
        "final_bom": {},
        "catalog": {
            "supplier": "test-supplier",
            "snapshot_id": "snapshot-v1",
            "captured_at_unix": 1,
            "expires_at_unix": 100,
            "evaluated_at_unix": 50,
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
        "line_items": procurement_lines,
        "findings": procurement_findings,
        "validation": validation,
        "binding_sha256": "e" * 64,
    }
    intent_raw = _render(procurement)
    intent_path = root / "procurement-intent.json"
    intent_path.write_bytes(intent_raw)
    offer_lines = [
        {
            "mpn": line["mpn"],
            "supplier_part_number": line["supplier_part_number"],
            "catalog_part_sha256": line["catalog_part_sha256"],
            "quoted_quantity": line["quantity"] * 4,
            "line_subtotal_micros": 100 + index,
        }
        for index, line in enumerate(procurement_lines)
    ]
    offer = {
        "schema_version": 1,
        "scope": supplier_offer_module.SUPPLIER_OFFER_SCOPE,
        "procurement_intent_sha256": hashlib.sha256(intent_raw).hexdigest(),
        "supplier": "test-supplier",
        "offer_id": "offer-v1",
        "valid_from_unix": 10,
        "valid_until_unix": 20,
        "currency": "USD",
        "lines": offer_lines,
    }
    offer_path = root / "supplier-offer.json"
    offer_path.write_bytes(_render(offer))
    return {
        "paths": (
            board_path,
            package_path,
            generation_path,
            catalog_path,
            intent_path,
            offer_path,
        ),
        "procurement": procurement,
        "offer": offer,
    }


def _rewrite_offer(fixture: Mapping[str, object]) -> None:
    paths = fixture["paths"]
    assert isinstance(paths, tuple)
    offer = fixture["offer"]
    assert isinstance(offer, dict)
    paths[5].write_bytes(_render(offer))


def _evaluate(
    fixture: Mapping[str, object],
    *,
    requested_boards: int = 3,
    evaluated_at_unix: int = 10,
    **kwargs: object,
) -> dict[str, object]:
    paths = fixture["paths"]
    assert isinstance(paths, tuple)
    with mock.patch.object(
        supplier_offer_module._procurement,
        "validate_procurement_intent",
        return_value=copy.deepcopy(fixture["procurement"]),
    ):
        return evaluate_supplier_offer_coverage(
            *paths,
            requested_boards=requested_boards,
            evaluated_at_unix=evaluated_at_unix,
            **kwargs,
        )


class _StatefulMapping(Mapping[str, object]):
    def __init__(self, value: Mapping[str, object]) -> None:
        self.value = value
        self.items_calls = 0

    def __getitem__(self, key: str) -> object:
        raise AssertionError("snapshotter must use the single items view")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("snapshotter must use the single items view")

    def __len__(self) -> int:
        return len(self.value)

    def items(self):  # type: ignore[override]
        self.items_calls += 1
        if self.items_calls != 1:
            raise AssertionError("mapping was traversed more than once")
        return self.value.items()


class _LyingBytes(bytes):
    def __len__(self) -> int:
        return 1

    def __bytes__(self) -> bytes:
        return b"forged"

    def __fspath__(self) -> str:
        return "/must-not-be-treated-as-a-path"


class _OneShotPath(os.PathLike[str]):
    def __init__(self, path: Path, hook=None) -> None:
        self.path = path
        self.hook = hook
        self.calls = 0

    def __fspath__(self) -> str:
        self.calls += 1
        if self.calls != 1:
            raise RuntimeError("path was converted more than once")
        if self.hook is not None:
            self.hook()
        return str(self.path)


class SupplierOfferV1468Tests(unittest.TestCase):
    def test_exact_covered_result_is_closed_canonical_and_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            result = _evaluate(fixture)
        self.assertTrue(result["covered"])
        self.assertEqual(result["status"], "covered")
        self.assertEqual(set(result), supplier_offer_module._RESULT_KEYS)
        self.assertTrue(
            all(
                result[key] is False
                for key in supplier_offer_module._FALSE_CLAIM_KEYS
            )
        )
        self.assertTrue(all(result["validation"].values()))
        self.assertEqual(result["component_subtotal_micros"], 100)
        self.assertEqual(
            set(result["coverage_lines"][0]), supplier_offer_module._COVERAGE_LINE_KEYS
        )
        self.assertEqual(result["coverage_lines"][0]["per_board_quantity"], 1)
        self.assertEqual(result["coverage_lines"][0]["requested_boards"], 3)
        self.assertEqual(result["coverage_lines"][0]["required_quantity"], 3)
        self.assertEqual(result["coverage_lines"][0]["surplus_quantity"], 1)
        self.assertNotIn("final_bom", result["procurement"])
        self.assertNotIn("binding_sha256", result["procurement"])
        rendered = render_supplier_offer_coverage(result)
        self.assertTrue(rendered.endswith(b"\n"))
        self.assertFalse(rendered[:-1].endswith(b"\n"))
        self.assertEqual(json.loads(rendered), result)
        self.assertIs(build_supplier_offer_coverage, evaluate_supplier_offer_coverage)
        if Draft202012Validator is not None:
            for schema in (
                normalized_supplier_offer_json_schema(),
                supplier_offer_coverage_json_schema(),
            ):
                Draft202012Validator.check_schema(schema)
            Draft202012Validator(supplier_offer_coverage_json_schema()).validate(result)

    def test_each_retained_finding_and_half_open_window_edges(self) -> None:
        scenarios = (
            ("supplier_mismatch", lambda f: f["offer"].update(supplier="other"), 10),
            ("offer_line_set_mismatch", lambda f: f["offer"].update(lines=[]), 10),
            (
                "offer_line_identity_mismatch",
                lambda f: f["offer"]["lines"][0].update(mpn="different"),
                10,
            ),
            (
                "quoted_quantity_shortfall",
                lambda f: f["offer"]["lines"][0].update(quoted_quantity=2),
                10,
            ),
            ("offer_outside_declared_window", lambda _f: None, 20),
        )
        for expected, mutate, evaluated in scenarios:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                fixture = _fixture(Path(directory).resolve(strict=True))
                mutate(fixture)
                _rewrite_offer(fixture)
                result = _evaluate(fixture, evaluated_at_unix=evaluated)
            self.assertFalse(result["covered"])
            self.assertEqual(result["status"], "not_covered")
            self.assertIn(expected, [item["code"] for item in result["findings"]])
            self.assertEqual(result["coverage_lines"], [])
            self.assertIsNone(result["component_subtotal_micros"])
            self.assertTrue(result["validation"]["component_subtotal_checked"])
            if expected == "offer_line_set_mismatch":
                self.assertTrue(result["validation"]["line_identities_matched"])
                self.assertTrue(result["validation"]["quantities_covered"])
                self.assertEqual(
                    [item["code"] for item in result["findings"]],
                    ["offer_line_set_mismatch"],
                )

        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True), approved=False)
            result = _evaluate(fixture)
        self.assertEqual(
            [item["code"] for item in result["findings"]],
            ["procurement_intent_rejected"],
        )
        self.assertFalse(result["validation"]["procurement_intent_approved"])

        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            at_start = _evaluate(fixture, evaluated_at_unix=10)
            before = _evaluate(fixture, evaluated_at_unix=9)
        self.assertTrue(at_start["covered"])
        self.assertFalse(before["covered"])

    def test_findings_are_lexicographically_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            fixture["offer"].update(supplier="other", lines=[])
            _rewrite_offer(fixture)
            result = _evaluate(fixture, evaluated_at_unix=20)
        codes = [item["code"] for item in result["findings"]]
        self.assertEqual(codes, sorted(codes))
        self.assertEqual(
            codes,
            [
                "offer_line_set_mismatch",
                "offer_outside_declared_window",
                "supplier_mismatch",
            ],
        )

    def test_raw_intent_digest_mismatch_is_hard_before_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            fixture["offer"]["procurement_intent_sha256"] = "0" * 64
            _rewrite_offer(fixture)
            with mock.patch.object(
                supplier_offer_module._procurement, "validate_procurement_intent"
            ) as validator:
                with self.assertRaises(SupplierOfferError):
                    evaluate_supplier_offer_coverage(
                        *fixture["paths"], requested_boards=3, evaluated_at_unix=10
                    )
            validator.assert_not_called()

    def test_replay_return_must_equal_retained_intent_and_cross_bind_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            forged = copy.deepcopy(fixture["procurement"])
            forged["catalog"]["snapshot_id"] = "other"
            with mock.patch.object(
                supplier_offer_module._procurement,
                "validate_procurement_intent",
                return_value=forged,
            ):
                with self.assertRaises(SupplierOfferError):
                    evaluate_supplier_offer_coverage(
                        *fixture["paths"], requested_boards=3, evaluated_at_unix=10
                    )

    def test_strict_argument_and_offer_scalar_bounds(self) -> None:
        bad_arguments = (
            {"requested_boards": True, "evaluated_at_unix": 10},
            {"requested_boards": 0, "evaluated_at_unix": 10},
            {"requested_boards": 1_000_001, "evaluated_at_unix": 10},
            {"requested_boards": 3, "evaluated_at_unix": True},
            {"requested_boards": 3, "evaluated_at_unix": -1},
        )
        for arguments in bad_arguments:
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as directory:
                fixture = _fixture(Path(directory).resolve(strict=True))
                with mock.patch.object(
                    supplier_offer_module._procurement, "validate_procurement_intent"
                ) as validator:
                    with self.assertRaises(SupplierOfferError):
                        evaluate_supplier_offer_coverage(*fixture["paths"], **arguments)
                validator.assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            with mock.patch.object(
                supplier_offer_module._procurement, "validate_procurement_intent"
            ) as validator:
                for timeout in (True, 0.5, 600.0001, float("inf"), float("nan")):
                    with self.subTest(timeout=timeout), self.assertRaises(
                        SupplierOfferError
                    ):
                        evaluate_supplier_offer_coverage(
                            *fixture["paths"],
                            requested_boards=3,
                            evaluated_at_unix=10,
                            timeout_seconds=timeout,
                        )
            validator.assert_not_called()

        mutations = (
            lambda offer: offer["lines"][0].update(quoted_quantity=True),
            lambda offer: offer["lines"][0].update(quoted_quantity=0),
            lambda offer: offer["lines"][0].update(line_subtotal_micros=True),
            lambda offer: offer.update(valid_from_unix=True),
            lambda offer: offer.update(valid_until_unix=offer["valid_from_unix"]),
            lambda offer: offer.update(currency="usd"),
            lambda offer: offer.update(procurement_intent_sha256="f" * 64 + "\n"),
        )
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as directory:
                fixture = _fixture(Path(directory).resolve(strict=True))
                mutate(fixture["offer"])
                _rewrite_offer(fixture)
                with self.assertRaises(SupplierOfferError):
                    _evaluate(fixture)

    def test_offer_is_closed_strictly_sku_sorted_unique_and_has_no_price_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True), line_count=2)
            fixture["offer"]["lines"].reverse()
            _rewrite_offer(fixture)
            with self.assertRaises(SupplierOfferError):
                _evaluate(fixture)
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            fixture["offer"]["lines"][0]["unit_price_micros"] = 1
            _rewrite_offer(fixture)
            with self.assertRaises(SupplierOfferError):
                _evaluate(fixture)
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True), line_count=2)
            fixture["offer"]["lines"][1]["supplier_part_number"] = "SKU-0"
            _rewrite_offer(fixture)
            with self.assertRaises(SupplierOfferError):
                _evaluate(fixture)

    def test_checked_money_sum_and_quantity_multiplication_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True), line_count=2)
            for line in fixture["offer"]["lines"]:
                line["line_subtotal_micros"] = supplier_offer_module.MAXIMUM_MONEY_MICROS
            _rewrite_offer(fixture)
            with self.assertRaises(SupplierOfferError):
                _evaluate(fixture)
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            fixture["offer"]["lines"][0]["quoted_quantity"] = 5
            _rewrite_offer(fixture)
            with mock.patch.object(supplier_offer_module, "MAXIMUM_QUANTITY", 5):
                with self.assertRaises(SupplierOfferError):
                    _evaluate(fixture, requested_boards=6)

    def test_renderer_one_pass_and_rejects_rebound_semantic_forgeries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            result = _evaluate(fixture)
        stateful = _StatefulMapping(result)
        self.assertEqual(json.loads(render_supplier_offer_coverage(stateful)), result)
        self.assertEqual(stateful.items_calls, 1)

        for mutate in (
            lambda value: value.update(procurement_authorized=True),
            lambda value: value["coverage_lines"][0].update(required_quantity=2),
            lambda value: value["validation"].update(quantities_covered=False),
            lambda value: value["sources"]["supplier_offer"].update(
                sha256="0" * 64 + "\n"
            ),
        ):
            forged = copy.deepcopy(result)
            mutate(forged)
            _rebind(forged)
            with self.assertRaises(SupplierOfferError):
                render_supplier_offer_coverage(forged)

    def test_fresh_validator_accepts_mapping_canonical_bytes_and_path_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            result = _evaluate(fixture)
            canonical = render_supplier_offer_coverage(result)
            retained = root / "coverage.json"
            retained.write_bytes(canonical)
            with mock.patch.object(
                supplier_offer_module._procurement,
                "validate_procurement_intent",
                return_value=copy.deepcopy(fixture["procurement"]),
            ):
                self.assertEqual(
                    validate_supplier_offer_coverage(
                        result,
                        *fixture["paths"],
                        requested_boards=3,
                        evaluated_at_unix=10,
                    ),
                    result,
                )
                self.assertEqual(
                    validate_supplier_offer_coverage(
                        _LyingBytes(canonical),
                        *fixture["paths"],
                        requested_boards=3,
                        evaluated_at_unix=10,
                    ),
                    result,
                )
                self.assertEqual(
                    validate_supplier_offer_coverage(
                        retained,
                        *fixture["paths"],
                        requested_boards=3,
                        evaluated_at_unix=10,
                    ),
                    result,
                )
                compact = json.dumps(result, sort_keys=True).encode("utf-8") + b"\n"
                with self.assertRaises(SupplierOfferError):
                    validate_supplier_offer_coverage(
                        compact,
                        *fixture["paths"],
                        requested_boards=3,
                        evaluated_at_unix=10,
                    )

    def test_alias_symlink_mutation_and_retained_path_hook_are_hard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            paths = list(fixture["paths"])
            with self.assertRaises(SupplierOfferError):
                evaluate_supplier_offer_coverage(
                    *paths[:5], paths[4], requested_boards=3, evaluated_at_unix=10
                )
            alias = root / "catalog-alias.json"
            os.link(paths[3], alias)
            aliased = [*paths]
            aliased[3] = alias
            aliased[2] = paths[3]
            with self.assertRaises(SupplierOfferError):
                evaluate_supplier_offer_coverage(
                    *aliased, requested_boards=3, evaluated_at_unix=10
                )
            symlink = root / "offer-link.json"
            try:
                symlink.symlink_to(paths[5])
            except (OSError, NotImplementedError):
                pass
            else:
                linked = [*paths]
                linked[5] = symlink
                with self.assertRaises(SupplierOfferError):
                    evaluate_supplier_offer_coverage(
                        *linked, requested_boards=3, evaluated_at_unix=10
                    )

            def mutate_and_return(*_args: object, **_kwargs: object) -> object:
                paths[5].write_bytes(paths[5].read_bytes() + b"changed")
                return copy.deepcopy(fixture["procurement"])

            with mock.patch.object(
                supplier_offer_module._procurement,
                "validate_procurement_intent",
                side_effect=mutate_and_return,
            ):
                with self.assertRaises(SupplierOfferError):
                    evaluate_supplier_offer_coverage(
                        *paths, requested_boards=3, evaluated_at_unix=10
                    )

    def test_paths_are_frozen_once_and_retained_path_hooks_cannot_mutate_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            fixture = _fixture(root)
            paths = list(fixture["paths"])
            board = _OneShotPath(paths[0])
            wrapped_paths = [board, *paths[1:]]
            with mock.patch.object(
                supplier_offer_module._procurement,
                "validate_procurement_intent",
                return_value=copy.deepcopy(fixture["procurement"]),
            ):
                result = evaluate_supplier_offer_coverage(
                    *wrapped_paths, requested_boards=3, evaluated_at_unix=10
                )
            self.assertTrue(result["covered"])
            self.assertEqual(board.calls, 1)

            retained = root / "coverage.json"
            retained.write_bytes(render_supplier_offer_coverage(result))

            def mutate_offer() -> None:
                paths[5].write_bytes(paths[5].read_bytes() + b"changed")

            retained_hook = _OneShotPath(retained, mutate_offer)
            with mock.patch.object(
                supplier_offer_module._procurement,
                "validate_procurement_intent",
                return_value=copy.deepcopy(fixture["procurement"]),
            ):
                with self.assertRaises(SupplierOfferError):
                    validate_supplier_offer_coverage(
                        retained_hook,
                        *paths,
                        requested_boards=3,
                        evaluated_at_unix=10,
                    )
            self.assertEqual(retained_hook.calls, 1)

    def test_shared_deadline_and_representation_aggregate_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            with mock.patch.object(
                supplier_offer_module._procurement,
                "validate_procurement_intent",
                return_value=copy.deepcopy(fixture["procurement"]),
            ) as validator:
                evaluate_supplier_offer_coverage(
                    *fixture["paths"],
                    requested_boards=3,
                    evaluated_at_unix=10,
                    timeout_seconds=120,
                    _clock=lambda: 0.0,
                )
            self.assertEqual(validator.call_args.kwargs["timeout_seconds"], 60.0)

        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory).resolve(strict=True))
            result = _evaluate(fixture)
            direct_bytes = sum(path.stat().st_size for path in fixture["paths"])
            with mock.patch.object(
                supplier_offer_module,
                "MAXIMUM_TOTAL_INPUT_BYTES",
                direct_bytes + len(render_supplier_offer_coverage(result)) - 1,
            ), mock.patch.object(
                supplier_offer_module._procurement, "validate_procurement_intent"
            ) as validator:
                with self.assertRaises(SupplierOfferError):
                    validate_supplier_offer_coverage(
                        result,
                        *fixture["paths"],
                        requested_boards=3,
                        evaluated_at_unix=10,
                    )
            validator.assert_not_called()

    def test_public_byte_limits_and_schema_ids_are_frozen(self) -> None:
        self.assertEqual(MAXIMUM_SUPPLIER_OFFER_BYTES, 4 * 1024 * 1024)
        self.assertEqual(MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES, 16 * 1024 * 1024)
        self.assertTrue(
            normalized_supplier_offer_json_schema()["$id"].endswith(
                "/offline-normalized-supplier-offer-v1.json"
            )
        )
        self.assertTrue(
            supplier_offer_coverage_json_schema()["$id"].endswith(
                "/offline-procurement-supplier-offer-coverage-v1.json"
            )
        )


if __name__ == "__main__":
    unittest.main()

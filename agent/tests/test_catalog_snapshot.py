import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pcbex_agent.catalog import (
    CatalogError,
    CatalogSelectionError,
    MAX_CATALOG_QUERY_BYTES,
    MAX_CATALOG_QUERY_TOKENS,
    MAX_CATALOG_RECEIPT_BYTES,
    MAX_SPEC_PARTS,
    catalog_receipt_json_schema,
    catalog_snapshot_json_schema,
    canonical_sha256,
    load_catalog_snapshot,
    select_catalog_parts,
    validate_catalog_receipt,
    validate_catalog_receipt_shape,
)

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional validation aid
    Draft202012Validator = None


def _snapshot(**overrides):
    value = {
        "schema_version": 1,
        "supplier": "jlcpcb",
        "snapshot_id": "snap-1",
        "captured_at_unix": 100,
        "expires_at_unix": 200,
        "parts": [
            {
                "mpn": "C-100N",
                "supplier_part_number": "LCSC-C1",
                "description": "100nF ceramic capacitor",
                "footprint": "0402",
                "tags": ["capacitor", "decoupling"],
                "vendor": "jlcpcb",
                "stock": 4,
                "basic": True,
                "datasheet_url": None,
            },
            {
                "mpn": "R-10K",
                "supplier_part_number": None,
                "description": "10k resistor",
                "footprint": "0402",
                "tags": ["resistor"],
                "vendor": "jlcpcb",
                "stock": 4,
                "basic": False,
                "datasheet_url": "https://example.test/r-10k",
            },
        ],
    }
    value.update(overrides)
    return value


def _spec():
    return {
        "schema_version": 2,
        "parts": [
            {
                "reference": "C1",
                "lib_id": "Device:C",
                "value": "100nF",
                "footprint": "0402",
                "mpn": None,
                "power": {
                    "rail_voltage_uv": None,
                    "max_voltage_uv": None,
                    "requires_decoupling": False,
                    "decoupling": False,
                },
                "pins": [
                    {"number": "1", "name": "~", "net": "N1", "electrical_type": "passive"},
                    {"number": "2", "name": "~", "net": "N1", "electrical_type": "passive"},
                ],
            },
            {
                "reference": "R1",
                "lib_id": "Device:R",
                "value": "10k",
                "footprint": "0402",
                "mpn": "R-10K",
                "power": {
                    "rail_voltage_uv": None,
                    "max_voltage_uv": None,
                    "requires_decoupling": False,
                    "decoupling": False,
                },
                "pins": [
                    {"number": "1", "name": "~", "net": "N1", "electrical_type": "passive"},
                    {"number": "2", "name": "~", "net": "N1", "electrical_type": "passive"},
                ],
            },
        ],
        "nets": [
            {
                "name": "N1",
                "voltage_uv": None,
                "connections": [
                    {"reference": "C1", "pin": "1"},
                    {"reference": "C1", "pin": "2"},
                    {"reference": "R1", "pin": "1"},
                    {"reference": "R1", "pin": "2"},
                ],
            }
        ],
    }


class CatalogSnapshotTests(unittest.TestCase):
    def test_normalizes_sorting_and_rejects_recursive_duplicate_keys(self):
        raw = json.dumps(_snapshot(), separators=(",", ":"))
        first = load_catalog_snapshot(raw, evaluated_at_unix=150)
        swapped = _snapshot(parts=list(reversed(_snapshot()["parts"])))
        second = load_catalog_snapshot(json.dumps(swapped), evaluated_at_unix=150)
        self.assertEqual(first.catalog_sha256, second.catalog_sha256)
        with self.assertRaises(CatalogError):
            load_catalog_snapshot(
                b'{"schema_version":1,"supplier":"jlcpcb","snapshot_id":"x",'
                b'"captured_at_unix":1,"expires_at_unix":2,"parts":[{"mpn":"x",'
                b'"supplier_part_number":null,"description":"x","footprint":"x",'
                b'"tags":[],"vendor":"x","stock":1,"basic":false,"datasheet_url":null,'
                b'"nested":{"a":1,"a":2}}]}',
                evaluated_at_unix=1,
            )

    def test_closed_snapshot_bounds_and_https(self):
        with self.assertRaises(CatalogError):
            load_catalog_snapshot(json.dumps(_snapshot(supplier="JLCPCB")), evaluated_at_unix=150)
        with self.assertRaises(CatalogError):
            load_catalog_snapshot(json.dumps(_snapshot(expires_at_unix=100 + 7 * 24 * 60 * 60 + 1)), evaluated_at_unix=150)
        bad = _snapshot()
        bad["parts"][0] = dict(bad["parts"][0], datasheet_url="http://example.test")
        with self.assertRaises(CatalogError):
            load_catalog_snapshot(json.dumps(bad), evaluated_at_unix=150)

    def test_selection_and_full_receipt_recomputation(self):
        snapshot = load_catalog_snapshot(json.dumps(_snapshot()), evaluated_at_unix=150)
        resolved, receipt = select_catalog_parts(_spec(), snapshot)
        self.assertEqual(resolved["parts"][0]["mpn"], "C-100N")
        self.assertEqual(receipt["selections"][0]["status"], "assigned")
        validate_catalog_receipt_shape(receipt)
        validate_catalog_receipt(receipt, _spec(), resolved, snapshot)
        tampered = dict(receipt, selections=list(receipt["selections"]))
        tampered["selections"][0] = dict(tampered["selections"][0], mpn="R-10K")
        with self.assertRaises(CatalogError):
            validate_catalog_receipt_shape(tampered)

    def test_prefilled_and_stock_policy_fail_closed(self):
        snapshot = load_catalog_snapshot(json.dumps(_snapshot()), evaluated_at_unix=150)
        spec = _spec()
        spec["parts"][0]["mpn"] = "missing"
        with self.assertRaises(CatalogSelectionError):
            select_catalog_parts(spec, snapshot)
        stock = _snapshot(parts=[dict(_snapshot()["parts"][0], stock=1)])
        snapshot = load_catalog_snapshot(json.dumps(stock), evaluated_at_unix=150)
        spec = _spec()
        spec["parts"][1] = dict(spec["parts"][0], reference="C2")
        spec["nets"][0]["connections"] = [
            {"reference": "C1", "pin": "1"},
            {"reference": "C1", "pin": "2"},
            {"reference": "C2", "pin": "1"},
            {"reference": "C2", "pin": "2"},
        ]
        with self.assertRaises(CatalogSelectionError):
            select_catalog_parts(spec, snapshot)

    def test_file_source_retains_basename_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(_snapshot()), encoding="utf-8")
            snapshot = load_catalog_snapshot(path, evaluated_at_unix=150)
            _, receipt = select_catalog_parts(_spec(), snapshot)
            self.assertEqual(receipt["source"]["kind"], "file")
            self.assertEqual(receipt["source"]["name"], "catalog.json")
            self.assertNotIn(directory, json.dumps(receipt))

    def test_selection_has_a_deterministic_work_limit(self):
        snapshot = load_catalog_snapshot(json.dumps(_snapshot()), evaluated_at_unix=150)
        with (
            patch("pcbex_agent.catalog.MAX_CATALOG_SELECTION_WORK", 3),
            self.assertRaisesRegex(CatalogError, "work limit"),
        ):
            select_catalog_parts(_spec(), snapshot)

    def test_query_token_and_byte_limits_fail_before_selection(self):
        snapshot = load_catalog_snapshot(json.dumps(_snapshot()), evaluated_at_unix=150)
        too_many_tokens = _spec()
        too_many_tokens["parts"][0]["value"] = " ".join(
            ["x"] * (MAX_CATALOG_QUERY_TOKENS + 1)
        )
        with self.assertRaisesRegex(CatalogError, "query contains more"):
            select_catalog_parts(too_many_tokens, snapshot)
        with patch("pcbex_agent.catalog.MAX_CATALOG_QUERY_BYTES", 4):
            with self.assertRaisesRegex(CatalogError, "query exceeds"):
                select_catalog_parts(_spec(), snapshot)

    def test_receipt_selection_and_canonical_byte_bounds(self):
        snapshot = load_catalog_snapshot(json.dumps(_snapshot()), evaluated_at_unix=150)
        _resolved, receipt = select_catalog_parts(_spec(), snapshot)
        oversized = dict(receipt)
        oversized["selections"] = [
            dict(receipt["selections"][0], reference=f"C{index:03d}")
            for index in range(MAX_SPEC_PARTS + 1)
        ]
        oversized["selections_sha256"] = canonical_sha256(oversized["selections"])
        with self.assertRaisesRegex(CatalogError, "between 1 and"):
            validate_catalog_receipt_shape(oversized)
        encoded_size = len(
            json.dumps(
                receipt,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        with patch("pcbex_agent.catalog.MAX_CATALOG_RECEIPT_BYTES", encoded_size):
            validate_catalog_receipt_shape(receipt)
        with (
            patch("pcbex_agent.catalog.MAX_CATALOG_RECEIPT_BYTES", encoded_size - 1),
            self.assertRaisesRegex(CatalogError, "canonical bytes"),
        ):
            validate_catalog_receipt_shape(receipt)

    def test_injected_mapping_preflight_and_closed_v2_shape(self):
        snapshot = load_catalog_snapshot(_snapshot(), evaluated_at_unix=150)
        malformed = _spec()
        malformed["parts"][0]["unexpected"] = "x"
        with self.assertRaises(CatalogError):
            select_catalog_parts(malformed, snapshot)
        malformed = _spec()
        malformed["parts"][0]["power"]["rail_voltage_uv"] = -1
        with self.assertRaises(CatalogError):
            select_catalog_parts(malformed, snapshot)
        malformed_snapshot = _snapshot()
        malformed_snapshot["parts"][0]["description"] = "x" * 10_000
        with self.assertRaises(CatalogError):
            load_catalog_snapshot(malformed_snapshot, evaluated_at_unix=150)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_exported_schemas_enforce_structural_bounds(self):
        snapshot_schema = catalog_snapshot_json_schema()
        receipt_schema = catalog_receipt_json_schema()
        Draft202012Validator.check_schema(snapshot_schema)
        Draft202012Validator.check_schema(receipt_schema)

        snapshot_value = _snapshot()
        snapshot_validator = Draft202012Validator(snapshot_schema)
        self.assertEqual(list(snapshot_validator.iter_errors(snapshot_value)), [])
        invalid_snapshot = dict(snapshot_value, supplier="jlcpcb-")
        self.assertTrue(list(snapshot_validator.iter_errors(invalid_snapshot)))
        invalid_snapshot = _snapshot()
        invalid_snapshot["parts"][0] = dict(
            invalid_snapshot["parts"][0], supplier_part_number=""
        )
        self.assertTrue(list(snapshot_validator.iter_errors(invalid_snapshot)))

        snapshot = load_catalog_snapshot(snapshot_value, evaluated_at_unix=150)
        _resolved, receipt = select_catalog_parts(_spec(), snapshot)
        receipt_validator = Draft202012Validator(receipt_schema)
        self.assertEqual(list(receipt_validator.iter_errors(receipt)), [])
        invalid_receipt = dict(receipt, selections=[])
        self.assertTrue(list(receipt_validator.iter_errors(invalid_receipt)))
        invalid_receipt = dict(receipt, source=dict(receipt["source"], name="x"))
        self.assertTrue(list(receipt_validator.iter_errors(invalid_receipt)))


if __name__ == "__main__":
    unittest.main()

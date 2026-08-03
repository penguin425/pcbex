import importlib
import unittest
from unittest.mock import patch

from pcbex_agent.catalog import (
    MAX_CATALOG_PARTS,
    MAX_CATALOG_QUERY_BYTES,
    MAX_CATALOG_QUERY_TOKENS,
    MAX_CATALOG_STOCK,
    MAX_CATALOG_TAG_BYTES,
    MAX_CATALOG_TAGS,
    MAX_CATALOG_TEXT_BYTES,
    MAX_SPEC_PARTS,
    CatalogPart,
)
from pcbex_agent.skidl import CircuitSpecError, assign_catalog_parts, generate_skidl


skidl_module = importlib.import_module("pcbex_agent.skidl")


def _spec(*, mpns=(None,), value="100nF", footprint="0402"):
    references = [f"C{index}" for index in range(1, len(mpns) + 1)]
    parts = [
        {
            "reference": reference,
            "lib_id": "Device:C",
            "value": value,
            "footprint": footprint,
            "pins": {"1": "VCC", "2": "VCC"},
            "mpn": mpn,
        }
        for reference, mpn in zip(references, mpns)
    ]
    return {
        "schema_version": 1,
        "parts": parts,
        "nets": [
            {
                "name": "VCC",
                "connections": [
                    {"reference": reference, "pin": pin}
                    for reference in references
                    for pin in ("1", "2")
                ],
            },
        ],
    }


class SkidlCatalogEvidenceTests(unittest.TestCase):
    def test_mpn_mapping_is_sorted_and_part_does_not_receive_mpn_kwarg(self):
        source = generate_skidl(
            _spec(mpns=("MPN-Z", None, "MPN-A")), include_netlist=False
        )
        self.assertIn(
            '_PCBEX_MPN_BY_REFERENCE = {"C1": "MPN-Z", "C3": "MPN-A"}',
            source,
        )
        self.assertNotIn("mpn=", source)
        self.assertLess(
            source.index('"C1": "MPN-Z"'), source.index('"C3": "MPN-A"')
        )

    def test_catalog_receipt_digest_is_optional_but_strictly_validated(self):
        digest = "a" * 64
        source = generate_skidl(
            _spec(mpns=("MPN-1",)),
            catalog_receipt_sha256=digest,
        )
        self.assertIn(f'_PCBEX_CATALOG_RECEIPT_SHA256 = "{digest}"', source)
        for invalid in ("A" * 64, "a" * 63, "a" * 65, 1, "not-a-digest"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    CircuitSpecError, "catalog_receipt_sha256 must be lowercase 64-hex"
                ):
                    generate_skidl(_spec(), catalog_receipt_sha256=invalid)

    def test_prefilled_mpn_is_case_insensitive_but_checks_identity_and_policies(self):
        catalog = [
            CatalogPart(
                "C-100NF", "100nF capacitor", "0402", stock=2, basic=True
            )
        ]
        selected = assign_catalog_parts(
            _spec(mpns=("c-100nf",)), catalog, require_basic=True
        )
        self.assertEqual(selected["parts"][0]["mpn"], "c-100nf")

        with self.assertRaisesRegex(CircuitSpecError, "not in catalog"):
            assign_catalog_parts(_spec(mpns=("missing",)), catalog)
        with self.assertRaisesRegex(CircuitSpecError, "mismatched footprint"):
            assign_catalog_parts(_spec(mpns=("C-100NF",), footprint="0603"), catalog)
        with self.assertRaisesRegex(CircuitSpecError, "not basic"):
            assign_catalog_parts(
                _spec(mpns=("C-100NF",)),
                [CatalogPart("C-100NF", "100nF capacitor", "0402", stock=2)],
                require_basic=True,
            )
        with self.assertRaisesRegex(CircuitSpecError, "unavailable"):
            assign_catalog_parts(
                _spec(mpns=("C-100NF",)),
                [CatalogPart("C-100NF", "100nF capacitor", "0402", stock=0)],
            )

    def test_footprint_fallback_is_opt_in(self):
        catalog = [CatalogPart("X-1", "unrelated text", "0402", stock=4)]
        with self.assertRaisesRegex(CircuitSpecError, "no catalog part satisfies"):
            assign_catalog_parts(_spec(), catalog)
        selected = assign_catalog_parts(
            _spec(), catalog, allow_footprint_fallback=True
        )
        self.assertEqual(selected["parts"][0]["mpn"], "X-1")

    def test_available_stock_covers_each_reference(self):
        catalog = [CatalogPart("C-100NF", "100nF capacitor", "0402", stock=1)]
        with self.assertRaisesRegex(CircuitSpecError, "stock is insufficient"):
            assign_catalog_parts(_spec(mpns=(None, None)), catalog)
        selected = assign_catalog_parts(
            _spec(mpns=(None, None)),
            [CatalogPart("C-100NF", "100nF capacitor", "0402", stock=2)],
        )
        self.assertEqual(
            [part["mpn"] for part in selected["parts"]], ["C-100NF", "C-100NF"]
        )
        # The availability policy is the gate for multiplicity; an explicit
        # out-of-stock policy remains useful for offline catalog snapshots.
        selected = assign_catalog_parts(_spec(mpns=(None, None)), catalog, require_available=False)
        self.assertEqual(len(selected["parts"]), 2)

    def test_allocation_uses_next_ranked_candidate_when_stock_is_consumed(self):
        catalog = [
            CatalogPart("A-100NF", "100nF capacitor", "0402", stock=1),
            CatalogPart("B-100NF", "100nF capacitor", "0402", stock=1),
        ]
        selected = assign_catalog_parts(_spec(mpns=(None, None)), catalog)
        self.assertEqual(
            [part["mpn"] for part in selected["parts"]],
            ["A-100NF", "B-100NF"],
        )

    def test_receipt_evidence_requires_complete_mpns(self):
        with self.assertRaisesRegex(CircuitSpecError, "MPN for every circuit part"):
            generate_skidl(_spec(), catalog_receipt_sha256="a" * 64)

    def test_direct_catalog_part_values_are_revalidated(self):
        with self.assertRaisesRegex(CircuitSpecError, "invalid CatalogPart"):
            assign_catalog_parts(
                _spec(),
                [CatalogPart("X", "part", "0402", stock=-1)],
            )

    def test_direct_catalog_mpns_are_unique_case_insensitively_and_policies_are_booleans(self):
        duplicate = [
            CatalogPart("C-100NF", "100nF capacitor", "0402"),
            CatalogPart("c-100nf", "another capacitor", "0402"),
        ]
        with self.assertRaisesRegex(CircuitSpecError, "duplicate MPNs"):
            assign_catalog_parts(_spec(), duplicate)
        for name in ("require_available", "require_basic", "allow_footprint_fallback"):
            with self.subTest(name=name):
                kwargs = {name: 1}
                with self.assertRaisesRegex(CircuitSpecError, f"{name} must be a boolean"):
                    assign_catalog_parts(_spec(), [], **kwargs)

    def test_catalog_and_spec_collection_bounds_reject_before_ranking(self):
        # Patch the published limit down for a fast exact boundary test while
        # retaining the same one-over behavior used by the production bound.
        candidate = CatalogPart("X", "x", "0402", stock=1)
        with patch.object(skidl_module, "MAX_CATALOG_PARTS", 2):
            self.assertEqual(
                assign_catalog_parts(
                    _spec(value="x"), [candidate, CatalogPart("Y", "x", "0402", stock=1)],
                    allow_footprint_fallback=True,
                )["parts"][0]["mpn"],
                "X",
            )
            with self.assertRaisesRegex(CircuitSpecError, "catalog contains more than 2 parts"):
                assign_catalog_parts(
                    _spec(value="x"),
                    [candidate, CatalogPart("Y", "x", "0402", stock=1),
                     CatalogPart("Z", "x", "0402", stock=1)],
                )

        too_many_parts = _spec(mpns=(None,) * (MAX_SPEC_PARTS + 1))
        with self.assertRaisesRegex(
            CircuitSpecError, f"circuit spec contains more than {MAX_SPEC_PARTS} parts"
        ):
            assign_catalog_parts(too_many_parts, [candidate])

    def test_query_byte_and_token_boundaries_are_exact(self):
        # The query includes the value, one separator, and ``Device:C``.
        suffix_bytes = len(" Device:C".encode("utf-8"))
        value_at_limit = "x" * (MAX_CATALOG_QUERY_BYTES - suffix_bytes)
        self.assertEqual(
            assign_catalog_parts(
                _spec(value=value_at_limit),
                [CatalogPart("X", "x", "0402", stock=1)],
                allow_footprint_fallback=True,
            )["parts"][0]["mpn"],
            "X",
        )
        with self.assertRaisesRegex(
            CircuitSpecError,
            f"catalog query exceeds {MAX_CATALOG_QUERY_BYTES} UTF-8 bytes",
        ):
            assign_catalog_parts(
                _spec(value=value_at_limit + "x"),
                [CatalogPart("X", "x", "0402", stock=1)],
            )

        value_at_token_limit = " ".join(["x"] * (MAX_CATALOG_QUERY_TOKENS - 1))
        self.assertEqual(
            assign_catalog_parts(
                _spec(value=value_at_token_limit),
                [CatalogPart("X", "x", "0402", stock=1)],
            )["parts"][0]["mpn"],
            "X",
        )
        with self.assertRaisesRegex(
            CircuitSpecError,
            f"catalog query contains more than {MAX_CATALOG_QUERY_TOKENS} tokens",
        ):
            assign_catalog_parts(
                _spec(value=" ".join(["x"] * MAX_CATALOG_QUERY_TOKENS)),
                [CatalogPart("X", "x", "0402", stock=1)],
            )

    def test_work_limit_is_checked_before_search_parts(self):
        candidate = CatalogPart("X", "x", "0402", stock=1)
        # The former token-only estimate was exactly two units for this
        # query.  The shared search contract also charges candidate traversal
        # and query bytes, so a two-unit ceiling must reject before ranking.
        with patch.object(skidl_module, "MAX_CATALOG_SELECTION_WORK", 2), patch.object(
            skidl_module, "search_parts", side_effect=AssertionError("ranking started")
        ):
            with self.assertRaisesRegex(
                CircuitSpecError, "catalog selection exceeds its deterministic work limit"
            ):
                assign_catalog_parts(_spec(value="x"), [candidate])

    def test_direct_catalog_fields_use_snapshot_bounds(self):
        # Exact UTF-8 and collection boundaries remain accepted for direct
        # values, while the first over-boundary input fails closed.
        exact_description = "x" * MAX_CATALOG_TEXT_BYTES
        self.assertEqual(
            assign_catalog_parts(
                _spec(value="x"),
                [CatalogPart("X", exact_description, "0402", stock=MAX_CATALOG_STOCK)],
            )["parts"][0]["mpn"],
            "X",
        )
        with self.assertRaisesRegex(CircuitSpecError, "invalid CatalogPart"):
            assign_catalog_parts(
                _spec(value="x"),
                [CatalogPart("X", exact_description + "x", "0402", stock=1)],
            )

        exact_tags = tuple("x" for _ in range(MAX_CATALOG_TAGS))
        self.assertEqual(
            assign_catalog_parts(
                _spec(value="x"),
                [CatalogPart("X", "x", "0402", exact_tags, stock=1)],
            )["parts"][0]["mpn"],
            "X",
        )
        with self.assertRaisesRegex(CircuitSpecError, "invalid CatalogPart"):
            assign_catalog_parts(
                _spec(value="x"),
                [CatalogPart("X", "x", "0402", exact_tags + ("x",), stock=1)],
            )

        with self.assertRaisesRegex(CircuitSpecError, "invalid CatalogPart"):
            assign_catalog_parts(
                _spec(value="x"),
                [CatalogPart("X", "x", "0402", stock=1, datasheet_url="http://example.test")],
            )
        with self.assertRaisesRegex(CircuitSpecError, "invalid CatalogPart"):
            assign_catalog_parts(
                _spec(value="x"),
                [CatalogPart("X", "x", "0402", stock=MAX_CATALOG_STOCK + 1)],
            )
        with self.assertRaisesRegex(CircuitSpecError, "invalid CatalogPart"):
            assign_catalog_parts(
                _spec(value="x"),
                [CatalogPart("X", "x", "0402", ("x" * (MAX_CATALOG_TAG_BYTES + 1),), stock=1)],
            )


if __name__ == "__main__":
    unittest.main()

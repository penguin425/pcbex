import unittest
from unittest.mock import patch

import pcbex_agent.catalog as catalog_module
from pcbex_agent.catalog import (
    CatalogError,
    CatalogPart,
    MAX_CATALOG_PARTS,
    MAX_CATALOG_QUERY_BYTES,
    MAX_CATALOG_QUERY_TOKENS,
    MAX_CATALOG_SELECTION_WORK,
    MAX_CATALOG_STOCK,
    MAX_CATALOG_TAGS,
    MAX_CATALOG_TEXT_BYTES,
    assign_catalog_parts,
    catalog_parts_from_json,
    search_parts,
)


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
            }
        ],
    }


def _part(mpn="C-100N", description="100nF capacitor", *, stock=2, basic=True):
    return CatalogPart(mpn, description, "0402", stock=stock, basic=basic)


class CatalogLegacyBoundsTests(unittest.TestCase):
    def test_search_rejects_invalid_policy_limit_query_and_footprint(self):
        part = _part()
        for name in ("require_available", "require_basic"):
            with self.subTest(name=name), self.assertRaisesRegex(
                CatalogError, f"{name} must be a boolean"
            ):
                search_parts([part], "100nF", **{name: 1})
        for limit in (-1, True, 1.5, MAX_CATALOG_PARTS + 1):
            with self.subTest(limit=limit), self.assertRaises(CatalogError):
                search_parts([part], "100nF", limit=limit)
        with self.assertRaisesRegex(CatalogError, "query must be a string"):
            search_parts([part], None)
        with self.assertRaisesRegex(CatalogError, "query exceeds"):
            search_parts([part], "x" * (MAX_CATALOG_QUERY_BYTES + 1))
        with self.assertRaisesRegex(CatalogError, "query contains more"):
            search_parts([part], " ".join("x" for _ in range(MAX_CATALOG_QUERY_TOKENS + 1)))
        with self.assertRaisesRegex(CatalogError, "footprint must be"):
            search_parts([part], "100nF", footprint=1)
        with self.assertRaisesRegex(CatalogError, "footprint exceeds"):
            search_parts([part], "100nF", footprint="x" * (MAX_CATALOG_TEXT_BYTES + 1))

    def test_search_rejects_invalid_parts_and_consumes_only_one_over_bound(self):
        with self.assertRaisesRegex(CatalogError, "only CatalogPart"):
            search_parts([object()], "x")
        with self.assertRaisesRegex(CatalogError, "invalid CatalogPart"):
            search_parts([CatalogPart("X", "x", "0402", stock=-1)], "x")
        oversized = CatalogPart("X", "x" * (MAX_CATALOG_TEXT_BYTES + 1), "0402")
        with self.assertRaisesRegex(CatalogError, "invalid CatalogPart"):
            search_parts([oversized], "x")

        yielded = 0
        part = _part()

        def bounded_infinite_like():
            nonlocal yielded
            while True:
                yielded += 1
                yield CatalogPart(
                    f"C{yielded}", part.description, part.footprint, stock=part.stock
                )

        with patch.object(catalog_module, "MAX_CATALOG_PARTS", 2):
            with self.assertRaisesRegex(CatalogError, "more than 2 parts"):
                search_parts(bounded_infinite_like(), "100nF", limit=2)
        self.assertEqual(yielded, 3)

    def test_search_work_budget_is_checked_before_ranking(self):
        with patch.object(catalog_module, "MAX_CATALOG_SELECTION_WORK", 1):
            with self.assertRaisesRegex(CatalogError, "selection exceeds"):
                search_parts([_part()], "100nF")

    def test_search_keeps_deterministic_rank_order(self):
        parts = [
            _part("B", "100nF capacitor", stock=4, basic=False),
            _part("A", "100nF capacitor", stock=4, basic=True),
        ]
        self.assertEqual(
            [part.mpn for part in search_parts(parts, "100nF", limit=2)], ["A", "B"]
        )

    def test_legacy_json_count_fields_duplicates_and_empty_defaults_are_bounded(self):
        minimal = {"mpn": "X", "description": "x", "footprint": "0402"}
        self.assertEqual(catalog_parts_from_json([minimal])[0].vendor, "")
        self.assertEqual(catalog_parts_from_json([{**minimal, "datasheet_url": ""}])[0].datasheet_url, "")
        self.assertEqual(CatalogPart.from_mapping(minimal).vendor, "")
        with self.assertRaisesRegex(CatalogError, "bounded field"):
            CatalogPart.from_mapping(
                {**minimal, "description": "x" * (MAX_CATALOG_TEXT_BYTES + 1)}
            )
        with self.assertRaisesRegex(CatalogError, "at most"):
            CatalogPart.from_mapping(
                {**minimal, "tags": ["x"] * (MAX_CATALOG_TAGS + 1)}
            )
        with self.assertRaisesRegex(CatalogError, "bounded"):
            CatalogPart.from_mapping(
                {**minimal, "tags": ["x" * (MAX_CATALOG_TEXT_BYTES + 1)]}
            )
        with patch.object(catalog_module, "MAX_CATALOG_PARTS", 2):
            with self.assertRaisesRegex(CatalogError, "more than 2 parts"):
                catalog_parts_from_json([minimal, {**minimal, "mpn": "Y"}, {**minimal, "mpn": "Z"}])
        with self.assertRaisesRegex(CatalogError, "bounded text"):
            catalog_parts_from_json([{**minimal, "description": "x" * (MAX_CATALOG_TEXT_BYTES + 1)}])
        with self.assertRaisesRegex(CatalogError, "at most"):
            catalog_parts_from_json([{**minimal, "tags": ["x"] * (MAX_CATALOG_TAGS + 1)}])
        with self.assertRaisesRegex(CatalogError, "bounded range"):
            catalog_parts_from_json([{**minimal, "stock": MAX_CATALOG_STOCK + 1}])
        with self.assertRaisesRegex(CatalogError, "duplicate MPNs"):
            catalog_parts_from_json([minimal, {**minimal, "mpn": "x"}])

    def test_legacy_list_path_matches_skidl_validation_reservation_and_policies(self):
        with self.assertRaisesRegex(CatalogError, "stock is insufficient"):
            assign_catalog_parts(
                _spec(mpns=(None, None)), [_part(stock=1)]
            )
        selected = assign_catalog_parts(
            _spec(mpns=(None, None)),
            [_part("A", stock=1), _part("B", stock=1)],
        )
        self.assertEqual([part["mpn"] for part in selected["parts"]], ["A", "B"])

        with self.assertRaisesRegex(CatalogError, "not in catalog"):
            assign_catalog_parts(_spec(mpns=("UNKNOWN",)), [_part()])
        with self.assertRaisesRegex(CatalogError, "duplicate MPNs"):
            assign_catalog_parts(
                _spec(), [_part("X"), _part("x", "other")]
            )
        for name in ("require_available", "require_basic", "allow_footprint_fallback"):
            with self.subTest(name=name), self.assertRaisesRegex(
                CatalogError, f"{name} must be a boolean"
            ):
                assign_catalog_parts(_spec(), [_part()], **{name: 1})

        malformed = {"parts": [{"reference": "C1", "footprint": "0402"}]}
        with self.assertRaisesRegex(CatalogError, "circuit spec"):
            assign_catalog_parts(malformed, [_part()])

    def test_legacy_fallback_remains_opt_in(self):
        unrelated = _part(description="unrelated")
        with self.assertRaisesRegex(CatalogError, "no catalog part satisfies"):
            assign_catalog_parts(_spec(), [unrelated])
        selected = assign_catalog_parts(
            _spec(), [unrelated], allow_footprint_fallback=True
        )
        self.assertEqual(selected["parts"][0]["mpn"], unrelated.mpn)


if __name__ == "__main__":
    unittest.main()

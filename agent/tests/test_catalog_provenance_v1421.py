import copy
import hashlib
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from pcbex_agent.catalog import (
    canonical_sha256,
    load_catalog_snapshot,
    select_catalog_parts,
    validate_catalog_receipt,
)
from pcbex_agent.catalog_provenance import (
    CatalogGenerationProvenanceError,
    build_catalog_generation_provenance,
    catalog_generation_provenance_json_schema,
    validate_catalog_generation_provenance,
)
from pcbex_agent.circuit_generation import generate_circuit_with_llm
from pcbex_agent.supplier_inventory import fetch_catalog_snapshot

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional schema validation aid
    Draft202012Validator = None


def _compact(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _spec(*, mpn=None):
    return {
        "schema_version": 2,
        "parts": [
            {
                "reference": "C1",
                "lib_id": "Device:C",
                "value": "100nF",
                "footprint": "Capacitor_SMD:C_0603_1608Metric",
                "mpn": mpn,
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
            }
        ],
        "nets": [
            {
                "name": "N1",
                "voltage_uv": None,
                "connections": [
                    {"reference": "C1", "pin": "1"},
                    {"reference": "C1", "pin": "2"},
                ],
            }
        ],
    }


def _snapshot():
    return {
        "schema_version": 1,
        "supplier": "jlcpcb",
        "snapshot_id": "provenance-feed",
        "captured_at_unix": 100,
        "expires_at_unix": 200,
        "parts": [
            {
                "mpn": "C-100N",
                "supplier_part_number": "C1",
                "description": "100nF ceramic capacitor",
                "footprint": "Capacitor_SMD:C_0603_1608Metric",
                "tags": ["capacitor"],
                "vendor": "vendor",
                "stock": 8,
                "basic": True,
                "datasheet_url": None,
            }
        ],
    }


def _review():
    return {
        "schema_version": 1,
        "schematic_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "policy_id": "default",
        "approved": True,
        "counts": {"errors": 0, "warnings": 0, "info": 0},
        "findings": [],
    }


def _envelope(spec):
    review = _review()
    return {
        "schema_version": 1,
        "circuit_spec_sha256": hashlib.sha256(_compact(spec)).hexdigest(),
        "electrical_review_sha256": hashlib.sha256(_compact(review)).hexdigest(),
        "normalized_spec": spec,
        "electrical_review": review,
    }


class _FeedHandler(BaseHTTPRequestHandler):
    body = b""

    def do_GET(self):  # noqa: N802 - stdlib handler name
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        try:
            self.wfile.write(type(self).body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args):
        return


class CatalogGenerationProvenanceV1421Tests(unittest.TestCase):
    def _make_artifacts(self, root, server):
        snapshot_path = root / "catalog-snapshot.json"
        fetch_receipt_path = root / "catalog-fetch-receipt.json"
        fetch_catalog_snapshot(
            f"http://127.0.0.1:{server.server_port}/catalog",
            "jlcpcb",
            snapshot_path,
            fetch_receipt_path,
            fetched_at_unix=150,
            allow_insecure_loopback=True,
        )
        snapshot = load_catalog_snapshot(snapshot_path, evaluated_at_unix=150)

        def selector(spec, _remaining):
            return select_catalog_parts(spec, snapshot, evaluated_at_unix=150)

        def receipt_validator(original, resolved, receipt, _remaining):
            return validate_catalog_receipt(
                receipt,
                original,
                resolved,
                snapshot,
                evaluated_at_unix=150,
            )

        class Checker:
            def __call__(self, _path, _remaining):
                return _envelope(_spec(mpn="C-100N"))

        bundle = generate_circuit_with_llm(
            "make a capacitor",
            {"type": "object"},
            lambda _prompt, _remaining: "{}",
            Checker(),
            catalog_selector=selector,
            catalog_receipt_validator=receipt_validator,
        )
        bundle_path = root / "generation-bundle.json"
        bundle_path.write_bytes(
            (json.dumps(bundle, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        )
        skidl_path = root / "generated.py"
        skidl_path.write_bytes(bundle["skidl"].encode("utf-8"))
        return fetch_receipt_path, snapshot_path, bundle_path, skidl_path

    def _server(self):
        handler = type(
            "FeedHandler",
            (_FeedHandler,),
            {"body": json.dumps(_snapshot(), separators=(",", ":")).encode("utf-8")},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    def test_build_validate_and_schema_are_closed(self):
        server = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fetch, snapshot, bundle, skidl = self._make_artifacts(root, server)
                provenance = build_catalog_generation_provenance(
                    fetch,
                    snapshot,
                    bundle,
                    skidl,
                    allow_insecure_loopback=True,
                )
                self.assertEqual(
                    set(provenance),
                    {
                        "schema_version",
                        "adapter",
                        "provider",
                        "endpoint_id",
                        "evaluated_at_unix",
                        "fetch_receipt_sha256",
                        "snapshot_sha256",
                        "catalog_sha256",
                        "selection_receipt_sha256",
                        "input_spec_sha256",
                        "resolved_spec_sha256",
                        "generation_bundle_sha256",
                        "generated_skidl_sha256",
                    },
                )
                self.assertNotIn(str(root), json.dumps(provenance))
                self.assertEqual(
                    validate_catalog_generation_provenance(
                        provenance,
                        fetch,
                        snapshot,
                        bundle,
                        skidl,
                        allow_insecure_loopback=True,
                    ),
                    provenance,
                )
                schema = catalog_generation_provenance_json_schema()
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(set(schema["required"]), set(provenance))
                if Draft202012Validator is not None:
                    Draft202012Validator.check_schema(schema)
                    self.assertEqual(list(Draft202012Validator(schema).iter_errors(provenance)), [])
        finally:
            server.shutdown()
            server.server_close()

    def test_one_byte_artifact_tamper_fails_closed(self):
        server = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fetch, snapshot, bundle, skidl = self._make_artifacts(root, server)
                provenance = build_catalog_generation_provenance(
                    fetch, snapshot, bundle, skidl, allow_insecure_loopback=True
                )
                for path in (fetch, snapshot, bundle, skidl):
                    original = path.read_bytes()
                    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                    try:
                        with self.subTest(path=path.name), self.assertRaises(
                            CatalogGenerationProvenanceError
                        ):
                            validate_catalog_generation_provenance(
                                provenance,
                                fetch,
                                snapshot,
                                bundle,
                                skidl,
                                allow_insecure_loopback=True,
                            )
                    finally:
                        path.write_bytes(original)
        finally:
            server.shutdown()
            server.server_close()

    def test_unknown_and_duplicate_provenance_fields_fail_closed(self):
        server = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fetch, snapshot, bundle, skidl = self._make_artifacts(root, server)
                provenance = build_catalog_generation_provenance(
                    fetch, snapshot, bundle, skidl, allow_insecure_loopback=True
                )
                unknown = dict(provenance, unexpected="x")
                with self.assertRaises(CatalogGenerationProvenanceError):
                    validate_catalog_generation_provenance(
                        unknown, fetch, snapshot, bundle, skidl, allow_insecure_loopback=True
                    )
                duplicate_raw = (
                    json.dumps(provenance, separators=(",", ":"))[:-1]
                    + ',"adapter":"catalog-generation-provenance-v1"}'
                ).encode("utf-8")
                with self.assertRaises(CatalogGenerationProvenanceError):
                    validate_catalog_generation_provenance(
                        duplicate_raw,
                        fetch,
                        snapshot,
                        bundle,
                        skidl,
                        allow_insecure_loopback=True,
                    )
                expired = dict(provenance, evaluated_at_unix=151)
                with self.assertRaises(CatalogGenerationProvenanceError):
                    validate_catalog_generation_provenance(
                        expired, fetch, snapshot, bundle, skidl, allow_insecure_loopback=True
                    )
                with patch(
                    "pcbex_agent.catalog_provenance.MAX_PROVENANCE_BYTES",
                    32,
                ):
                    with self.assertRaises(CatalogGenerationProvenanceError):
                        build_catalog_generation_provenance(
                            fetch,
                            snapshot,
                            bundle,
                            skidl,
                            allow_insecure_loopback=True,
                        )
        finally:
            server.shutdown()
            server.server_close()

    def test_recomputed_provenance_rejects_final_history_digest_forgery(self):
        server = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fetch, snapshot, bundle, skidl = self._make_artifacts(root, server)
                value = json.loads(bundle.read_text(encoding="utf-8"))
                value["attempt_history"][-1]["resolved_spec_sha256"] = "0" * 64
                forged = root / "forged-bundle.json"
                forged.write_text(
                    json.dumps(value, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(CatalogGenerationProvenanceError):
                    build_catalog_generation_provenance(
                        fetch,
                        snapshot,
                        forged,
                        skidl,
                        allow_insecure_loopback=True,
                    )
        finally:
            server.shutdown()
            server.server_close()

    def test_injected_sources_are_bounded_before_copy_or_serialization(self):
        with patch(
            "pcbex_agent.catalog_provenance.MAX_PROVENANCE_BUNDLE_BYTES",
            4,
        ):
            with self.assertRaises(CatalogGenerationProvenanceError):
                build_catalog_generation_provenance(
                    {},
                    b"{}",
                    memoryview(b"12345"),
                )
        with patch(
            "pcbex_agent.catalog_provenance.MAXIMUM_RECEIPT_BYTES",
            8,
        ), patch(
            "pcbex_agent.catalog_provenance.MAX_CATALOG_RECEIPT_BYTES",
            8,
        ):
            with self.assertRaises(CatalogGenerationProvenanceError):
                build_catalog_generation_provenance(
                    {"oversized": "x" * 9},
                    b"{}",
                    b"{}",
                )

        # Shared nested objects must be charged once per serialized reference.
        # This prevents a tiny in-memory DAG from expanding into an unbounded
        # temporary JSON string before the configured limit is enforced.
        chain = "x"
        for _ in range(100):
            chain = [chain]
        expanded = {"shared": [chain] * 10}
        with patch(
            "pcbex_agent.catalog_provenance.MAXIMUM_RECEIPT_BYTES",
            512,
        ), patch(
            "pcbex_agent.catalog_provenance.MAX_CATALOG_RECEIPT_BYTES",
            512,
        ), patch("pcbex_agent.catalog_provenance.json.dumps") as dumps:
            with self.assertRaises(CatalogGenerationProvenanceError):
                build_catalog_generation_provenance(expanded, b"{}", b"{}")
            dumps.assert_not_called()

        # A character count is not a UTF-8 byte count; non-ASCII input is
        # rejected by the preflight before serialization as well.
        with patch(
            "pcbex_agent.catalog_provenance.MAXIMUM_RECEIPT_BYTES",
            8,
        ), patch(
            "pcbex_agent.catalog_provenance.MAX_CATALOG_RECEIPT_BYTES",
            8,
        ), patch("pcbex_agent.catalog_provenance.json.dumps") as dumps:
            with self.assertRaises(CatalogGenerationProvenanceError):
                build_catalog_generation_provenance({"x": "é" * 5}, b"{}", b"{}")
            dumps.assert_not_called()

    def test_history_shape_matches_the_closed_generation_contract(self):
        server = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fetch, snapshot, bundle, skidl = self._make_artifacts(root, server)
                original = json.loads(bundle.read_text(encoding="utf-8"))
                mutations = {
                    "boolean attempt": lambda value: value["attempt_history"][-1].__setitem__(
                        "attempt", True
                    ),
                    "null prompt digest": lambda value: value["attempt_history"][-1].__setitem__(
                        "prompt_sha256", None
                    ),
                    "non-string error": lambda value: value["attempt_history"][-1].__setitem__(
                        "error", 1
                    ),
                }
                for label, mutate in mutations.items():
                    with self.subTest(label=label):
                        value = copy.deepcopy(original)
                        mutate(value)
                        with self.assertRaises(CatalogGenerationProvenanceError):
                            build_catalog_generation_provenance(
                                fetch,
                                snapshot,
                                value,
                                skidl,
                                allow_insecure_loopback=True,
                            )

                value = copy.deepcopy(original)
                first = copy.deepcopy(value["attempt_history"][0])
                first["attempt"] = 1
                first["outcome"] = "invalid_json"
                first["error"] = "retry"
                for key in (
                    "resolved_spec_sha256",
                    "resolved_check_sha256",
                    "resolved_circuit_spec_sha256",
                    "resolved_electrical_review_sha256",
                    "catalog_receipt_sha256",
                ):
                    first[key] = None
                second = value["attempt_history"][0]
                second["attempt"] = 2
                value["attempts"] = 2
                value["repaired"] = True
                value["attempt_history"] = [first, second]
                build_catalog_generation_provenance(
                    fetch,
                    snapshot,
                    value,
                    skidl,
                    allow_insecure_loopback=True,
                )
                value["attempt_history"][0]["resolved_spec_sha256"] = "0" * 64
                with self.assertRaises(CatalogGenerationProvenanceError):
                    build_catalog_generation_provenance(
                        fetch,
                        snapshot,
                        value,
                        skidl,
                        allow_insecure_loopback=True,
                    )
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()

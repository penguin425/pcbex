import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from pcbex_agent.supplier_inventory import (
    SupplierInventoryError,
    catalog_fetch_receipt_json_schema,
    fetch_catalog_snapshot,
    validate_catalog_fetch_receipt,
)
from pcbex_agent import supplier_inventory as supplier_inventory_module

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional schema validation aid
    Draft202012Validator = None


def _snapshot(*, reverse=False):
    parts = [
        {
            "mpn": "R-10K",
            "supplier_part_number": None,
            "description": "10k resistor",
            "footprint": "0402",
            "tags": ["resistor"],
            "vendor": "vendor",
            "stock": 3,
            "basic": True,
            "datasheet_url": None,
        },
        {
            "mpn": "C-100N",
            "supplier_part_number": "C1",
            "description": "100nF capacitor",
            "footprint": "0402",
            "tags": ["decoupling", "capacitor"],
            "vendor": "vendor",
            "stock": 4,
            "basic": False,
            "datasheet_url": "https://example.test/c-100n",
        },
    ]
    if reverse:
        parts.reverse()
    return {
        "schema_version": 1,
        "supplier": "jlcpcb",
        "snapshot_id": "feed-1",
        "captured_at_unix": 100,
        "expires_at_unix": 200,
        "parts": parts,
    }


class _FeedHandler(BaseHTTPRequestHandler):
    body = b""
    status = 200
    content_type = "application/json"
    transfer_encoding = None
    delay = 0.0
    content_length = True
    requests = 0
    methods = []
    headers_seen = []

    def do_GET(self):  # noqa: N802 - stdlib handler name
        type(self).requests += 1
        type(self).methods.append(self.command)
        type(self).headers_seen.append(dict(self.headers))
        if self.delay:
            time.sleep(self.delay)
        self.send_response(type(self).status)
        if type(self).content_type is not None:
            self.send_header("Content-Type", type(self).content_type)
        if type(self).content_length:
            self.send_header("Content-Length", str(len(type(self).body)))
        if type(self).transfer_encoding is not None:
            self.send_header("Transfer-Encoding", type(self).transfer_encoding)
        self.end_headers()
        try:
            if type(self).transfer_encoding == "chunked":
                midpoint = max(1, len(type(self).body) // 2)
                for chunk in (type(self).body[:midpoint], type(self).body[midpoint:]):
                    if chunk:
                        self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii"))
                        self.wfile.write(chunk + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.wfile.write(type(self).body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):  # noqa: N802 - reject accidental method changes
        type(self).methods.append(self.command)
        self.send_response(405)
        self.end_headers()

    def log_message(self, *_args):
        return


class SupplierInventoryV1420Tests(unittest.TestCase):
    def _server(self, **overrides):
        attrs = {
            "body": json.dumps(_snapshot(), separators=(",", ":")).encode("utf-8"),
            "status": 200,
            "content_type": "application/json",
            "transfer_encoding": None,
            "delay": 0.0,
            "content_length": True,
            "requests": 0,
            "methods": [],
            "headers_seen": [],
        }
        attrs.update(overrides)
        handler = type("FeedHandler", (_FeedHandler,), attrs)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, handler

    def _endpoint(self, server):
        return f"http://127.0.0.1:{server.server_port}/catalog"

    def test_success_normalizes_and_replays(self):
        raw = json.dumps(_snapshot(reverse=True), separators=(",", ":")).encode("utf-8")
        server, handler = self._server(body=raw)
        try:
            with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
                first_root, second_root = Path(first), Path(second)
                receipt_a = fetch_catalog_snapshot(
                    self._endpoint(server),
                    "jlcpcb",
                    first_root / "snapshot.json",
                    first_root / "receipt.json",
                    fetched_at_unix=150,
                    allow_insecure_loopback=True,
                )
                receipt_b = fetch_catalog_snapshot(
                    self._endpoint(server),
                    "jlcpcb",
                    second_root / "snapshot.json",
                    second_root / "receipt.json",
                    fetched_at_unix=150,
                    allow_insecure_loopback=True,
                )
                self.assertEqual(
                    (first_root / "snapshot.json").read_bytes(),
                    (second_root / "snapshot.json").read_bytes(),
                )
                self.assertEqual(receipt_a, receipt_b)
                self.assertEqual(
                    validate_catalog_fetch_receipt(
                        receipt_a,
                        first_root / "snapshot.json",
                        allow_insecure_loopback=True,
                    ),
                    receipt_a,
                )
                self.assertEqual(handler.methods, ["GET", "GET"])
                self.assertEqual(handler.requests, 2)
        finally:
            server.shutdown()
            server.server_close()

    def test_status_redirect_content_type_and_oversize_fail(self):
        cases = (
            {"status": 500},
            {"status": 302, "content_type": "text/plain"},
            {"content_type": "application/json; charset=utf-8"},
            {"body": b"{}" * 100, "content_type": "application/octet-stream"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                server, handler = self._server(**overrides)
                try:
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        with self.assertRaises(SupplierInventoryError):
                            fetch_catalog_snapshot(
                                self._endpoint(server),
                                "jlcpcb",
                                root / "snapshot.json",
                                root / "receipt.json",
                                fetched_at_unix=150,
                                allow_insecure_loopback=True,
                                maximum_response_bytes=64,
                            )
                        self.assertEqual(handler.requests, 1)
                finally:
                    server.shutdown()
                    server.server_close()

    def test_invalid_duplicate_and_nan_json_fail_without_body_reflection(self):
        bodies = (
            b"not json",
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":NaN}',
        )
        for body in bodies:
            server, handler = self._server(body=body)
            try:
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    with self.assertRaises(SupplierInventoryError) as raised:
                        fetch_catalog_snapshot(
                            self._endpoint(server),
                            "jlcpcb",
                            root / "snapshot.json",
                            root / "receipt.json",
                            fetched_at_unix=150,
                            allow_insecure_loopback=True,
                        )
                    self.assertNotIn(body.decode("utf-8", "ignore"), str(raised.exception))
            finally:
                server.shutdown()
                server.server_close()

    def test_auth_endpoint_and_token_are_not_retained(self):
        token = "v1-test-bearer-token"
        server, handler = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.dict(os.environ, {"PCBEX_SUPPLIER_TOKEN": token}):
                    receipt = fetch_catalog_snapshot(
                        self._endpoint(server),
                        "jlcpcb",
                        root / "snapshot.json",
                        root / "receipt.json",
                        bearer_token_environment="PCBEX_SUPPLIER_TOKEN",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(handler.headers_seen[0].get("Authorization"), f"Bearer {token}")
                self.assertNotIn(token, json.dumps(receipt))
                self.assertNotIn(token, (root / "snapshot.json").read_text())
                self.assertNotIn(token, (root / "receipt.json").read_text())
        finally:
            server.shutdown()
            server.server_close()

    def test_rejects_invalid_token_and_non_ascii_endpoint_before_network(self):
        server, handler = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.dict(os.environ, {"PCBEX_BAD_TOKEN": "token with spaces"}):
                    with self.assertRaises(SupplierInventoryError):
                        fetch_catalog_snapshot(
                            self._endpoint(server),
                            "jlcpcb",
                            root / "snapshot.json",
                            root / "receipt.json",
                            bearer_token_environment="PCBEX_BAD_TOKEN",
                            fetched_at_unix=150,
                            allow_insecure_loopback=True,
                        )
                with patch.dict(os.environ, {"PCBEX_HUGE_TOKEN": "a" * 8193}):
                    with self.assertRaises(SupplierInventoryError):
                        fetch_catalog_snapshot(
                            self._endpoint(server),
                            "jlcpcb",
                            root / "snapshot-token.json",
                            root / "receipt-token.json",
                            bearer_token_environment="PCBEX_HUGE_TOKEN",
                            fetched_at_unix=150,
                            allow_insecure_loopback=True,
                        )
                with self.assertRaises(SupplierInventoryError):
                    fetch_catalog_snapshot(
                        self._endpoint(server) + "/café",
                        "jlcpcb",
                        root / "snapshot-2.json",
                        root / "receipt-2.json",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                with self.assertRaises(SupplierInventoryError):
                    fetch_catalog_snapshot(
                        self._endpoint(server) + "/" + "a" * 4096,
                        "jlcpcb",
                        root / "snapshot-3.json",
                        root / "receipt-3.json",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                for suffix in ("?", "#", "/raw space"):
                    with self.subTest(suffix=suffix), self.assertRaises(
                        SupplierInventoryError
                    ):
                        fetch_catalog_snapshot(
                            self._endpoint(server) + suffix,
                            "jlcpcb",
                            root / f"snapshot-delimiter-{len(suffix)}.json",
                            root / f"receipt-delimiter-{len(suffix)}.json",
                            fetched_at_unix=150,
                            allow_insecure_loopback=True,
                        )
                self.assertEqual(handler.requests, 0)
        finally:
            server.shutdown()
            server.server_close()

    def test_rejects_content_encoding_and_requires_loopback_flag_for_replay(self):
        server, _handler = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                receipt = fetch_catalog_snapshot(
                    self._endpoint(server),
                    "jlcpcb",
                    root / "snapshot.json",
                    root / "receipt.json",
                    fetched_at_unix=150,
                    allow_insecure_loopback=True,
                )
                with self.assertRaises(SupplierInventoryError):
                    validate_catalog_fetch_receipt(receipt, root / "snapshot.json")
        finally:
            server.shutdown()
            server.server_close()

    def test_transfer_encoding_is_closed_and_chunked_is_supported(self):
        rejected_cases = (
            {"transfer_encoding": "gzip", "content_length": False},
            {"transfer_encoding": "gzip, chunked", "content_length": False},
            {"transfer_encoding": "chunked", "content_length": True},
        )
        for overrides in rejected_cases:
            with self.subTest(overrides=overrides):
                server, handler = self._server(**overrides)
                try:
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        with self.assertRaises(SupplierInventoryError):
                            fetch_catalog_snapshot(
                                self._endpoint(server),
                                "jlcpcb",
                                root / "snapshot.json",
                                root / "receipt.json",
                                fetched_at_unix=150,
                                allow_insecure_loopback=True,
                            )
                        self.assertEqual(handler.requests, 1)
                finally:
                    server.shutdown()
                    server.server_close()

        server, handler = self._server(
            transfer_encoding="chunked",
            content_length=False,
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                receipt = fetch_catalog_snapshot(
                    self._endpoint(server),
                    "jlcpcb",
                    root / "snapshot.json",
                    root / "receipt.json",
                    fetched_at_unix=150,
                    allow_insecure_loopback=True,
                )
                self.assertEqual(receipt["response_bytes"], len(handler.body))
                self.assertEqual(handler.requests, 1)
        finally:
            server.shutdown()
            server.server_close()

        server, handler = self._server(content_encoding="gzip")
        # The handler subclass needs to emit this optional header without
        # changing the normal fixture behavior.
        original_do_get = server.RequestHandlerClass.do_GET

        def encoded_get(instance):
            type(instance).requests += 1
            instance.send_response(200)
            instance.send_header("Content-Type", "application/json")
            instance.send_header("Content-Encoding", "gzip")
            instance.send_header("Content-Length", str(len(type(instance).body)))
            instance.end_headers()
            instance.wfile.write(type(instance).body)

        server.RequestHandlerClass.do_GET = encoded_get
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaises(SupplierInventoryError):
                    fetch_catalog_snapshot(
                        self._endpoint(server),
                        "jlcpcb",
                        root / "snapshot.json",
                        root / "receipt.json",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(handler.requests, 1)
        finally:
            server.RequestHandlerClass.do_GET = original_do_get
            server.shutdown()
            server.server_close()

    def test_timeout_and_preflight_paths_do_not_contact_server(self):
        server, handler = self._server(delay=1.2)
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaises(SupplierInventoryError):
                    fetch_catalog_snapshot(
                        self._endpoint(server),
                        "jlcpcb",
                        root / "snapshot.json",
                        root / "receipt.json",
                        timeout_seconds=1,
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(handler.requests, 1)
                (root / "existing.json").write_text("sentinel", encoding="utf-8")
                with self.assertRaises(SupplierInventoryError):
                    fetch_catalog_snapshot(
                        self._endpoint(server),
                        "jlcpcb",
                        root / "existing.json",
                        root / "receipt-2.json",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(handler.requests, 1)
                with self.assertRaises(SupplierInventoryError):
                    fetch_catalog_snapshot(
                        self._endpoint(server),
                        "jlcpcb",
                        root / "same.json",
                        root / "same.json",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(handler.requests, 1)
        finally:
            server.shutdown()
            server.server_close()

    def test_stream_deadline_is_reported_as_supplier_error(self):
        server, handler = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with (
                    patch(
                        "pcbex_agent.supplier_inventory._set_socket_timeout",
                        side_effect=[None, None, None, TimeoutError],
                    ),
                    self.assertRaisesRegex(
                        SupplierInventoryError,
                        "request exceeded its timeout",
                    ),
                ):
                    fetch_catalog_snapshot(
                        self._endpoint(server),
                        "jlcpcb",
                        root / "snapshot.json",
                        root / "receipt.json",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(handler.requests, 1)
                self.assertFalse((root / "snapshot.json").exists())
                self.assertFalse((root / "receipt.json").exists())
        finally:
            server.shutdown()
            server.server_close()

    def test_dns_tcp_and_tls_connect_are_inside_the_deadline(self):
        server, handler = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                started = time.monotonic()
                workers_before = sum(
                    thread.name == "pcbex-supplier-connect"
                    for thread in threading.enumerate()
                )
                with patch.object(
                    http.client.HTTPConnection,
                    "connect",
                    new=lambda _connection: time.sleep(3),
                ):
                    for index in range(2):
                        with self.assertRaisesRegex(
                            SupplierInventoryError,
                            "request exceeded its timeout",
                        ):
                            fetch_catalog_snapshot(
                                self._endpoint(server),
                                "jlcpcb",
                                root / f"snapshot-{index}.json",
                                root / f"receipt-{index}.json",
                                timeout_seconds=1,
                                fetched_at_unix=150,
                                allow_insecure_loopback=True,
                            )
                        if index == 0:
                            self.assertLess(time.monotonic() - started, 2)
                workers_after = sum(
                    thread.name == "pcbex-supplier-connect"
                    for thread in threading.enumerate()
                )
                self.assertLessEqual(workers_after, workers_before + 1)
                self.assertEqual(handler.requests, 0)
                self.assertFalse((root / "snapshot-0.json").exists())
                self.assertFalse((root / "receipt-0.json").exists())
                self.assertFalse((root / "snapshot-1.json").exists())
                self.assertFalse((root / "receipt-1.json").exists())
        finally:
            server.shutdown()
            server.server_close()

    def test_hostname_resolution_ascii_content_length_and_strict_loopback(self):
        server, handler = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                endpoint = self._endpoint(server).replace("127.0.0.1", "localhost")
                resolved = supplier_inventory_module._resolve_endpoint(
                    "localhost",
                    server.server_port,
                    time.monotonic() + 5,
                )
                self.assertTrue(resolved)
                with self.assertRaises(SupplierInventoryError):
                    fetch_catalog_snapshot(
                        endpoint,
                        "jlcpcb",
                        root / "snapshot.json",
                        root / "receipt.json",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(handler.requests, 0)
        finally:
            server.shutdown()
            server.server_close()

        class NonAsciiLengthResponse:
            headers = Message()

        NonAsciiLengthResponse.headers["Content-Length"] = "١"
        with self.assertRaises(SupplierInventoryError):
            supplier_inventory_module._parse_content_length(NonAsciiLengthResponse())

    def test_receipt_and_snapshot_tamper_are_rejected(self):
        server, _handler = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                receipt = fetch_catalog_snapshot(
                    self._endpoint(server),
                    "jlcpcb",
                    root / "snapshot.json",
                    root / "receipt.json",
                    fetched_at_unix=150,
                    allow_insecure_loopback=True,
                )
                original = (root / "snapshot.json").read_bytes()
                (root / "snapshot.json").write_bytes(original + b" ")
                with self.assertRaises(SupplierInventoryError):
                    validate_catalog_fetch_receipt(
                        receipt,
                        root / "snapshot.json",
                        allow_insecure_loopback=True,
                    )
                (root / "snapshot.json").write_bytes(original)
                tampered = dict(receipt, catalog_sha256="0" * 64)
                with self.assertRaises(SupplierInventoryError):
                    validate_catalog_fetch_receipt(
                        tampered,
                        root / "snapshot.json",
                        allow_insecure_loopback=True,
                    )
                oversized = memoryview(
                    bytearray(supplier_inventory_module.MAX_CATALOG_RAW_BYTES + 1)
                )
                try:
                    with self.assertRaises(SupplierInventoryError):
                        validate_catalog_fetch_receipt(
                            receipt,
                            oversized,
                            allow_insecure_loopback=True,
                        )
                finally:
                    oversized.release()
        finally:
            server.shutdown()
            server.server_close()

    def test_symlink_destination_fails_before_network(self):
        server, handler = self._server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "target.json"
                target.write_text("sentinel", encoding="utf-8")
                linked = root / "snapshot.json"
                try:
                    linked.symlink_to(target)
                except OSError as error:  # pragma: no cover - restricted Windows hosts
                    self.skipTest(f"symlink creation is unavailable: {error}")
                with self.assertRaises(SupplierInventoryError):
                    fetch_catalog_snapshot(
                        self._endpoint(server),
                        "jlcpcb",
                        linked,
                        root / "receipt.json",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(handler.requests, 0)
                self.assertEqual(target.read_text(encoding="utf-8"), "sentinel")
        finally:
            server.shutdown()
            server.server_close()

    def test_reflected_bearer_token_is_not_published_or_reported(self):
        token = "v1-reflected-secret"
        reflected = _snapshot()
        reflected["parts"][0]["description"] = token
        server, handler = self._server(
            body=json.dumps(reflected, separators=(",", ":")).encode("utf-8")
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with (
                    patch.dict(os.environ, {"PCBEX_REFLECTED_TOKEN": token}),
                    self.assertRaises(SupplierInventoryError) as raised,
                ):
                    fetch_catalog_snapshot(
                        self._endpoint(server),
                        "jlcpcb",
                        root / "snapshot.json",
                        root / "receipt.json",
                        bearer_token_environment="PCBEX_REFLECTED_TOKEN",
                        fetched_at_unix=150,
                        allow_insecure_loopback=True,
                    )
                self.assertEqual(handler.requests, 1)
                self.assertNotIn(token, str(raised.exception))
                self.assertFalse((root / "snapshot.json").exists())
                self.assertFalse((root / "receipt.json").exists())
        finally:
            server.shutdown()
            server.server_close()

    def test_schema_is_closed_and_exact(self):
        schema = catalog_fetch_receipt_json_schema()
        expected = {
            "schema_version",
            "adapter",
            "provider",
            "endpoint_id",
            "request_sha256",
            "response_sha256",
            "response_bytes",
            "status",
            "fetched_at_unix",
            "expires_at_unix",
            "snapshot_bytes",
            "snapshot_sha256",
            "catalog_sha256",
        }
        self.assertEqual(set(schema["required"]), expected)
        self.assertFalse(schema["additionalProperties"])
        if Draft202012Validator is not None:
            Draft202012Validator.check_schema(schema)


if __name__ == "__main__":
    unittest.main()

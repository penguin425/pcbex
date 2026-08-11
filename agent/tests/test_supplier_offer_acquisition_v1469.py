from __future__ import annotations

from collections.abc import Iterator, Mapping
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional in focused environments
    Draft202012Validator = None

from pcbex_agent.bounded_io import BoundedIOError
import pcbex_agent.supplier_offer_acquisition as acquisition_module
from pcbex_agent.supplier_offer_acquisition import (
    MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
    SupplierOfferAcquisitionError,
    fetch_supplier_offer,
    supplier_offer_fetch_receipt_json_schema,
    validate_supplier_offer_fetch_receipt,
)


_PROCUREMENT_DIGEST = "0" * 64


def _offer(*, lines: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "scope": "offline-normalized-supplier-offer-v1",
        "procurement_intent_sha256": _PROCUREMENT_DIGEST,
        "supplier": "example-supplier",
        "offer_id": "quote-v1",
        "valid_from_unix": 10,
        "valid_until_unix": 20,
        "currency": "USD",
        "lines": [] if lines is None else lines,
    }


def _raw_offer(value: Mapping[str, object] | None = None) -> bytes:
    return json.dumps(
        _offer() if value is None else value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _raw_http_response(headers: list[tuple[str, str]], body: bytes) -> bytes:
    lines = [b"HTTP/1.1 200 OK\r\n"]
    lines.extend(
        f"{name}: {value}\r\n".encode("latin-1") for name, value in headers
    )
    lines.append(b"\r\n")
    lines.append(body)
    return b"".join(lines)


class _OfferHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    body = _raw_offer()
    status = 200
    content_type: str | None = "application/json"
    content_encoding: str | None = None
    transfer_encoding: str | None = None
    content_length: bool | str = True
    extra_headers: list[tuple[str, str]] = []
    delay_headers = 0.0
    delay_body = 0.0
    malformed_chunk = False
    raw_response_chunks: list[bytes] | None = None
    dribble_interval = 0.0
    body_chunk_count = 0
    requests = 0
    methods: list[str] = []
    paths: list[str] = []
    headers_seen: list[dict[str, str]] = []

    def do_GET(self):  # noqa: N802 - stdlib handler name
        cls = type(self)
        cls.requests += 1
        cls.methods.append(self.command)
        cls.paths.append(self.path)
        cls.headers_seen.append(dict(self.headers))
        if cls.raw_response_chunks is not None:
            try:
                for chunk in cls.raw_response_chunks:
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    if cls.dribble_interval:
                        time.sleep(cls.dribble_interval)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            self.close_connection = True
            return
        if cls.delay_headers:
            time.sleep(cls.delay_headers)
        self.send_response(cls.status)
        if cls.content_type is not None:
            self.send_header("Content-Type", cls.content_type)
        if cls.content_encoding is not None:
            self.send_header("Content-Encoding", cls.content_encoding)
        if cls.transfer_encoding is not None:
            self.send_header("Transfer-Encoding", cls.transfer_encoding)
        if cls.content_length is True:
            self.send_header("Content-Length", str(len(cls.body)))
        elif isinstance(cls.content_length, str):
            self.send_header("Content-Length", cls.content_length)
        for name, value in cls.extra_headers:
            self.send_header(name, value)
        if not cls.content_length and cls.transfer_encoding is None:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        try:
            if cls.body_chunk_count:
                chunk_size = max(1, len(cls.body) // cls.body_chunk_count)
                for start in range(0, len(cls.body), chunk_size):
                    self.wfile.write(cls.body[start : start + chunk_size])
                    self.wfile.flush()
                    if cls.dribble_interval:
                        time.sleep(cls.dribble_interval)
            elif cls.delay_body:
                midpoint = max(1, len(cls.body) // 2)
                self.wfile.write(cls.body[:midpoint])
                self.wfile.flush()
                time.sleep(cls.delay_body)
                self.wfile.write(cls.body[midpoint:])
            elif (
                cls.transfer_encoding is not None
                and cls.transfer_encoding.strip().lower() == "chunked"
            ):
                if cls.malformed_chunk:
                    self.wfile.write(b"not-hex\r\n")
                else:
                    midpoint = max(1, len(cls.body) // 2)
                    for chunk in (cls.body[:midpoint], cls.body[midpoint:]):
                        if chunk:
                            self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii"))
                            self.wfile.write(chunk + b"\r\n")
                    self.wfile.write(b"0\r\n\r\n")
            else:
                self.wfile.write(cls.body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):  # noqa: N802
        type(self).methods.append(self.command)
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    accepted = 0

    def get_request(self):
        request = super().get_request()
        self.accepted += 1
        return request

    def handle_error(self, _request: object, _client_address: object) -> None:
        return


class _LoopbackServer:
    def __init__(self, **overrides: object) -> None:
        attributes = {
            "body": _raw_offer(),
            "status": 200,
            "content_type": "application/json",
            "content_encoding": None,
            "transfer_encoding": None,
            "content_length": True,
            "extra_headers": [],
            "delay_headers": 0.0,
            "delay_body": 0.0,
            "malformed_chunk": False,
            "raw_response_chunks": None,
            "dribble_interval": 0.0,
            "body_chunk_count": 0,
            "requests": 0,
            "methods": [],
            "paths": [],
            "headers_seen": [],
        }
        attributes.update(overrides)
        self.handler = type("OfferHandler", (_OfferHandler,), attributes)
        self.server = _QuietThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.server.accepted = 0
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_LoopbackServer":
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/offers/v1"


def _fetch(server: _LoopbackServer, root: Path, **kwargs: object) -> dict[str, object]:
    return fetch_supplier_offer(
        server.endpoint,
        "example-supplier",
        root / "offer.json",
        root / "receipt.json",
        procurement_intent_sha256=_PROCUREMENT_DIGEST,
        fetched_at_unix=100,
        allow_insecure_loopback=True,
        **kwargs,
    )


class _StatefulMapping(Mapping[str, object]):
    def __init__(self, value: Mapping[str, object]) -> None:
        self.value = value
        self.calls = 0

    def __getitem__(self, _key: str) -> object:
        raise AssertionError("single items snapshot required")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("single items snapshot required")

    def __len__(self) -> int:
        return len(self.value)

    def items(self):  # type: ignore[override]
        self.calls += 1
        if self.calls != 1:
            raise AssertionError("Mapping was traversed more than once")
        return self.value.items()


class _BytesPath(bytes):
    def __len__(self) -> int:
        return 1

    def __bytes__(self) -> bytes:
        return b"forged"

    def __fspath__(self) -> str:
        return "/must-not-be-used-as-a-path"


class _OneShotPath(os.PathLike[str]):
    def __init__(self, path: Path, hook=None) -> None:
        self.path = path
        self.hook = hook
        self.calls = 0

    def __fspath__(self) -> str:
        self.calls += 1
        if self.calls != 1:
            raise RuntimeError("path converted more than once")
        if self.hook is not None:
            self.hook()
        return str(self.path)


class _ExplodingPath(os.PathLike[str]):
    def __fspath__(self) -> str:
        raise LookupError("path-hook-secret")


class _ExplodingMapping(Mapping[str, object]):
    def __getitem__(self, _key: str) -> object:
        raise OSError("mapping-hook-secret")

    def __iter__(self) -> Iterator[str]:
        raise OSError("mapping-hook-secret")

    def __len__(self) -> int:
        return 24

    def items(self):  # type: ignore[override]
        raise OSError("mapping-hook-secret")


class SupplierOfferAcquisitionV1469Tests(unittest.TestCase):
    def test_success_normalizes_offer_and_emits_closed_canonical_receipt(self) -> None:
        body = json.dumps(_offer(), indent=1, ensure_ascii=False).encode("utf-8")
        with _LoopbackServer(
            body=body, content_type="application/json; charset=utf-8"
        ) as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            receipt = _fetch(server, root)
            offer_raw = (root / "offer.json").read_bytes()
            receipt_raw = (root / "receipt.json").read_bytes()
            self.assertEqual(server.handler.methods, ["GET"])
            self.assertEqual(server.handler.paths, ["/offers/v1"])
            self.assertEqual(
                server.handler.headers_seen[0]["Accept"], "application/json"
            )
            self.assertEqual(
                server.handler.headers_seen[0]["Accept-Encoding"], "identity"
            )
            self.assertEqual(offer_raw, acquisition_module._pretty_json(
                _offer(),
                maximum=acquisition_module._supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
                label="test offer",
            ))
            self.assertEqual(
                receipt_raw,
                acquisition_module._pretty_json(
                    receipt,
                    maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
                    label="test receipt",
                ),
            )
            self.assertEqual(tuple(receipt), acquisition_module._RECEIPT_KEYS)
            self.assertTrue(receipt["adapter_network_performed"])
            self.assertTrue(
                all(receipt[key] is False for key in acquisition_module._FALSE_CLAIM_KEYS)
            )
            self.assertEqual(receipt["response_sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(receipt["offer_sha256"], hashlib.sha256(offer_raw).hexdigest())
            self.assertEqual(
                validate_supplier_offer_fetch_receipt(
                    receipt_raw,
                    offer_raw,
                    allow_insecure_loopback=True,
                ),
                receipt,
            )
            self.assertEqual(set(root.iterdir()), {root / "offer.json", root / "receipt.json"})
        for bodyless_status in (204, 205):
            forged_status = copy.deepcopy(receipt)
            forged_status["status"] = bodyless_status
            with self.assertRaises(SupplierOfferAcquisitionError):
                validate_supplier_offer_fetch_receipt(
                    forged_status, offer_raw, allow_insecure_loopback=True
                )
        if Draft202012Validator is not None:
            schema = supplier_offer_fetch_receipt_json_schema()
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(receipt)
            for bodyless_status in (204, 205):
                forged_status = copy.deepcopy(receipt)
                forged_status["status"] = bodyless_status
                self.assertFalse(Draft202012Validator(schema).is_valid(forged_status))

    def test_chunked_and_close_delimited_bodies_are_accepted(self) -> None:
        cases = (
            {"transfer_encoding": "chunked", "content_length": False},
            {"transfer_encoding": " chunked ", "content_length": False},
            {"transfer_encoding": None, "content_length": False},
        )
        for settings in cases:
            with self.subTest(settings=settings), _LoopbackServer(
                **settings
            ) as server, tempfile.TemporaryDirectory() as directory:
                receipt = _fetch(server, Path(directory).resolve(strict=True))
                self.assertEqual(receipt["status"], 200)

    def test_status_content_encoding_framing_header_and_size_fail_closed(self) -> None:
        cases = (
            {"status": 302, "extra_headers": [("Location", "/elsewhere")]},
            {"content_type": "text/plain"},
            {"content_encoding": "gzip"},
            {"transfer_encoding": "gzip", "content_length": False},
            {"transfer_encoding": "chunked", "content_length": True},
            {"content_length": "01x"},
            {"content_length": True, "extra_headers": [("Content-Length", "1")]},
            {"transfer_encoding": "chunked", "content_length": False, "malformed_chunk": True},
            {"extra_headers": [(f"X-Test-{index}", "x") for index in range(65)]},
        )
        for settings in cases:
            with self.subTest(settings=settings), _LoopbackServer(
                **settings
            ) as server, tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                with self.assertRaises(SupplierOfferAcquisitionError):
                    _fetch(server, root)
                self.assertFalse((root / "offer.json").exists())
                self.assertFalse((root / "receipt.json").exists())
                self.assertEqual(server.handler.requests, 1)
        with _LoopbackServer() as server, tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SupplierOfferAcquisitionError):
                _fetch(
                    server,
                    Path(directory).resolve(strict=True),
                    maximum_response_bytes=16,
                )

    def test_malformed_headers_and_exact_combined_header_budget(self) -> None:
        body = _raw_offer()
        malformed = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"THIS IS NOT A HEADER\r\n"
            + b"Ignored-After-Defect: yes\r\n\r\n"
            + body
        )
        with _LoopbackServer(
            raw_response_chunks=[malformed]
        ) as server, tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SupplierOfferAcquisitionError):
                _fetch(server, Path(directory).resolve(strict=True))

        content_length = str(len(body))
        fixed_combined = (
            len("Content-Type")
            + len("application/json")
            + len("Content-Length")
            + len(content_length)
            + len("X-Pad")
        )
        padding = "x" * (
            acquisition_module._transport.MAXIMUM_RESPONSE_HEADER_BYTES
            - fixed_combined
        )
        exact = _raw_http_response(
            [
                ("Content-Type", "application/json"),
                ("Content-Length", content_length),
                ("X-Pad", padding),
            ],
            body,
        )
        with _LoopbackServer(
            raw_response_chunks=[exact]
        ) as server, tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                _fetch(server, Path(directory).resolve(strict=True))["status"], 200
            )
        over = exact.replace(
            ("X-Pad: " + padding).encode("ascii"),
            ("X-Pad: " + padding + "x").encode("ascii"),
            1,
        )
        with _LoopbackServer(
            raw_response_chunks=[over]
        ) as server, tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SupplierOfferAcquisitionError):
                _fetch(server, Path(directory).resolve(strict=True))

    def test_status_and_header_lines_require_crlf_and_no_interim_response(self) -> None:
        body = _raw_offer()
        valid = _raw_http_response(
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
            body,
        )
        chunked_body = (
            f"{len(body):X}\r\n".encode("ascii")
            + body
            + b"\r\n0\r\n\r\n"
        )
        chunked_headers = (
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        cases = (
            valid.replace(b"HTTP/1.1 200 OK\r\n", b"HTTP/1.1 200 OK\n", 1),
            valid.replace(b"HTTP/1.1 200 OK", b"HTTP/1.X 200 OK", 1),
            valid.replace(b"HTTP/1.1 200 OK", b"HTTP/1.9 200 OK", 1),
            valid.replace(b"HTTP/1.1 200 OK", b"HTTP/0.9 200 OK", 1),
            valid.replace(b"HTTP/1.1 200 OK", b"HTTP/1.1\t200\tOK", 1),
            valid.replace(b"HTTP/1.1 200 OK", b"HTTP/1.1 200", 1),
            valid.replace(
                b"HTTP/1.1 200 OK", b"HTTP/1.1\x85200\x85OK", 1
            ),
            valid.replace(
                b"Content-Type: application/json\r\n",
                b"Content-Type: application/json\n",
                1,
            ),
            b"HTTP/1.1 100 Continue\r\nX-Interim: x\r\n\r\n" + valid,
            b"HTTP/1.1 204 No Content\r\n" + chunked_headers + chunked_body,
            valid.replace(b"HTTP/1.1 200 OK", b"HTTP/1.1 205 Reset Content", 1),
            b"HTTP/1.0 200 OK\r\n" + chunked_headers + chunked_body,
        )
        for raw in cases:
            with self.subTest(raw=raw[:40]), _LoopbackServer(
                raw_response_chunks=[raw]
            ) as server, tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(SupplierOfferAcquisitionError):
                    _fetch(server, Path(directory).resolve(strict=True))

    def test_chunk_size_terminator_and_trailers_are_exact(self) -> None:
        body = _raw_offer()
        header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        canonical_size = f"{len(body):X}".encode("ascii")

        def framed(
            size_line: bytes = canonical_size + b"\r\n",
            data_terminator: bytes = b"\r\n",
            trailer: bytes = b"\r\n",
        ) -> bytes:
            return (
                header
                + size_line
                + body
                + data_terminator
                + b"0\r\n"
                + trailer
            )

        with _LoopbackServer(
            raw_response_chunks=[framed()]
        ) as server, tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                _fetch(server, Path(directory).resolve(strict=True))["status"], 200
            )

        trailers = b"".join(
            f"X-T-{index}: x\r\n".encode("ascii") for index in range(65)
        ) + b"\r\n"
        malformed = (
            framed(b"+" + canonical_size + b"\r\n"),
            framed(b"0x" + canonical_size + b"\r\n"),
            framed(b" " + canonical_size + b" \r\n"),
            framed(canonical_size + b";extension=yes\r\n"),
            framed(canonical_size + b";bad\0extension\r\n"),
            framed(canonical_size + b"\n"),
            framed(data_terminator=b"XX"),
            framed(trailer=b"X-Trailer: x\r\n\r\n"),
            framed(trailer=b"NOT A HEADER\r\n\r\n"),
            framed(trailer=trailers),
        )
        for raw in malformed:
            with self.subTest(raw=raw[-80:]), _LoopbackServer(
                raw_response_chunks=[raw]
            ) as server, tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(SupplierOfferAcquisitionError):
                    _fetch(server, Path(directory).resolve(strict=True))

    def test_endpoint_policy_and_exact_get_reject_before_network(self) -> None:
        invalid = (
            "http://example.test/offer",
            "http://localhost/offer",
            "https://user:pass@example.test/offer",
            "https://example.test:/offer",
            "https://[v1.foo]/offer",
            "https://[127.0.0.1]/offer",
            "https://example.test/offer?",
            "https://example.test/offer#",
            "https://example.test\\offer",
            "https://例.example/offer",
            "relative/offer",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            for index, endpoint in enumerate(invalid):
                with self.subTest(endpoint=endpoint), mock.patch.object(
                    acquisition_module._transport, "_http_get"
                ) as transport:
                    with self.assertRaises(SupplierOfferAcquisitionError):
                        fetch_supplier_offer(
                            endpoint,
                            "example-supplier",
                            root / f"offer-{index}.json",
                            root / f"receipt-{index}.json",
                            procurement_intent_sha256=_PROCUREMENT_DIGEST,
                        )
                    transport.assert_not_called()

    def test_hostname_resolver_uses_only_required_windows_environment(self) -> None:
        transport = acquisition_module._transport
        with mock.patch.object(transport.os, "name", "nt"), mock.patch.object(
            os.environ, "get", side_effect=AssertionError("must not read")
        ) as environment_get:
            for reserved_name in ("SystemRoot", "systemroot", "SYSTEMROOT"):
                with self.subTest(reserved_name=reserved_name), self.assertRaises(
                    transport._SupplierOfferTransportError
                ):
                    transport._load_bearer_token(reserved_name)
            environment_get.assert_not_called()
        with mock.patch.object(transport.os, "name", "nt"), mock.patch.dict(
            os.environ, {"SystemRoot": r"C:\Windows", "SECRET": "not-forwarded"}, clear=True
        ):
            self.assertEqual(
                transport._resolver_environment("safe-token"),
                {"SystemRoot": r"C:\Windows"},
            )
            with self.assertRaises(OSError):
                transport._resolver_environment("Windows")
        resolved_output = json.dumps(
            [
                [
                    transport.socket.AF_INET,
                    transport.socket.SOCK_STREAM,
                    transport.socket.IPPROTO_TCP,
                    ["192.0.2.1", 443],
                ]
            ],
            separators=(",", ":"),
        ).encode("ascii")
        completed = mock.Mock(returncode=0, stdout=resolved_output, stderr=b"")
        resolver_env = {"SystemRoot": r"C:\Windows"}
        with mock.patch.object(
            transport, "_resolver_environment", return_value=resolver_env
        ), mock.patch.object(
            transport, "run_bounded", return_value=completed
        ) as run:
            resolved = transport._resolve_endpoint(
                "offers.example.test",
                443,
                time.monotonic() + 2.0,
                cleanup_timeout_seconds=0.25,
                bearer_token="safe-token",
            )
        self.assertEqual(resolved[0][3], ("192.0.2.1", 443))
        self.assertEqual(run.call_args.kwargs["env"], resolver_env)

    def test_strict_offer_supplier_digest_and_unsupported_fields_fail(self) -> None:
        bad_values: list[bytes] = [
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":NaN}',
        ]
        wrong_supplier = _offer()
        wrong_supplier["supplier"] = "other"
        bad_values.append(_raw_offer(wrong_supplier))
        wrong_digest = _offer()
        wrong_digest["procurement_intent_sha256"] = "1" * 64
        bad_values.append(_raw_offer(wrong_digest))
        extra = _offer()
        extra["unit_price_micros"] = 1
        bad_values.append(_raw_offer(extra))
        invalid_window = _offer()
        invalid_window["valid_until_unix"] = invalid_window["valid_from_unix"]
        bad_values.append(_raw_offer(invalid_window))
        for body in bad_values:
            with self.subTest(body=body[:40]), _LoopbackServer(
                body=body
            ) as server, tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                with self.assertRaises(SupplierOfferAcquisitionError) as raised:
                    _fetch(server, root)
                self.assertNotIn(body.decode("utf-8", "ignore"), str(raised.exception))
                self.assertEqual(list(root.iterdir()), [])

    def test_bearer_token_is_environment_only_and_reflection_is_rejected(self) -> None:
        token = "v1469-secret-token"
        with _LoopbackServer() as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            with mock.patch.dict(os.environ, {"PCBEX_OFFER_TOKEN": token}):
                receipt = _fetch(
                    server,
                    root,
                    bearer_token_environment="PCBEX_OFFER_TOKEN",
                )
            self.assertEqual(
                server.handler.headers_seen[0]["Authorization"], f"Bearer {token}"
            )
            retained = (root / "offer.json").read_bytes() + (root / "receipt.json").read_bytes()
            self.assertNotIn(token.encode(), retained)
            self.assertNotIn(token, json.dumps(receipt))

        reflected = _offer()
        reflected["offer_id"] = token
        with _LoopbackServer(body=_raw_offer(reflected)) as server, tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PCBEX_OFFER_TOKEN": token}):
                with self.assertRaises(SupplierOfferAcquisitionError):
                    _fetch(
                        server,
                        Path(directory).resolve(strict=True),
                        bearer_token_environment="PCBEX_OFFER_TOKEN",
                    )

        escaped = _raw_offer().replace(b'"quote-v1"', b'"\\u00761469-secret-token"')
        self.assertNotIn(token.encode(), escaped)
        with _LoopbackServer(body=escaped) as server, tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PCBEX_OFFER_TOKEN": token}):
                with self.assertRaises(SupplierOfferAcquisitionError):
                    _fetch(
                        server,
                        Path(directory).resolve(strict=True),
                        bearer_token_environment="PCBEX_OFFER_TOKEN",
                    )

    def test_invalid_token_and_scalar_arguments_stop_before_transport(self) -> None:
        invalid_kwargs = (
            {"timeout_seconds": True},
            {"timeout_seconds": 0},
            {"timeout_seconds": 61},
            {"maximum_response_bytes": True},
            {"maximum_response_bytes": 0},
            {"maximum_response_bytes": 4 * 1024 * 1024 + 1},
            {"fetched_at_unix": True},
            {"fetched_at_unix": -1},
            {"allow_insecure_loopback": 1},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            for index, kwargs in enumerate(invalid_kwargs):
                with self.subTest(kwargs=kwargs), mock.patch.object(
                    acquisition_module._transport, "_http_get"
                ) as transport:
                    with self.assertRaises(SupplierOfferAcquisitionError):
                        fetch_supplier_offer(
                            "https://example.test/offer",
                            "example-supplier",
                            root / f"offer-{index}.json",
                            root / f"receipt-{index}.json",
                            procurement_intent_sha256=_PROCUREMENT_DIGEST,
                            **kwargs,
                        )
                    transport.assert_not_called()
            with mock.patch.dict(os.environ, {"BAD_TOKEN": "has spaces"}), mock.patch.object(
                acquisition_module._transport, "_http_get"
            ) as transport:
                with self.assertRaises(SupplierOfferAcquisitionError):
                    fetch_supplier_offer(
                        "https://example.test/offer",
                        "example-supplier",
                        root / "offer-token.json",
                        root / "receipt-token.json",
                        procurement_intent_sha256=_PROCUREMENT_DIGEST,
                        bearer_token_environment="BAD_TOKEN",
                    )
                transport.assert_not_called()
            with mock.patch.object(
                os.environ, "get", side_effect=AssertionError("must not read")
            ) as environment_get, mock.patch.object(
                acquisition_module._transport, "_http_get"
            ) as transport:
                with self.assertRaises(SupplierOfferAcquisitionError):
                    fetch_supplier_offer(
                        "https://example.test/offer",
                        "example-supplier",
                        root / "offer-system-root.json",
                        root / "receipt-system-root.json",
                        procurement_intent_sha256=_PROCUREMENT_DIGEST,
                        bearer_token_environment="SystemRoot",
                    )
                environment_get.assert_not_called()
                transport.assert_not_called()

    def test_transport_result_is_rechecked_at_the_public_boundary(self) -> None:
        raw = _raw_offer()
        invalid_results = (
            (raw, True, len(raw)),
            (bytearray(raw), 200, len(raw)),
            (raw, 200, len(raw) - 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            for index, (body, status, limit) in enumerate(invalid_results):
                with self.subTest(index=index), mock.patch.object(
                    acquisition_module._transport,
                    "_http_get",
                    return_value=(body, status),
                ):
                    with self.assertRaises(SupplierOfferAcquisitionError):
                        fetch_supplier_offer(
                            "https://example.test/offer",
                            "example-supplier",
                            root / f"offer-{index}.json",
                            root / f"receipt-{index}.json",
                            procurement_intent_sha256=_PROCUREMENT_DIGEST,
                            maximum_response_bytes=limit,
                            fetched_at_unix=100,
                        )
                    self.assertFalse((root / f"offer-{index}.json").exists())
                    self.assertFalse((root / f"receipt-{index}.json").exists())

    def test_one_second_deadline_bounds_headers_and_streamed_body(self) -> None:
        cases = ({"delay_headers": 1.0}, {"delay_body": 1.0})
        for settings in cases:
            with self.subTest(settings=settings), _LoopbackServer(
                **settings
            ) as server, tempfile.TemporaryDirectory() as directory:
                started = time.monotonic()
                with self.assertRaises(SupplierOfferAcquisitionError):
                    _fetch(
                        server,
                        Path(directory).resolve(strict=True),
                        timeout_seconds=1,
                    )
                self.assertLess(time.monotonic() - started, 2.5)

    def test_absolute_deadline_rejects_header_and_close_body_dribbles(self) -> None:
        body = _raw_offer()
        raw = _raw_http_response(
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
            body,
        )
        split_points = (25, 29, 34, 41, 49, len(raw))
        chunks: list[bytes] = []
        prior = 0
        for point in split_points:
            chunks.append(raw[prior:point])
            prior = point
        cases = (
            {
                "raw_response_chunks": chunks,
                "dribble_interval": 0.25,
            },
            {
                "content_length": False,
                "body_chunk_count": 8,
                "dribble_interval": 0.2,
            },
        )
        for settings in cases:
            with self.subTest(settings=tuple(settings)), _LoopbackServer(
                **settings
            ) as server, tempfile.TemporaryDirectory() as directory:
                started = time.monotonic()
                with self.assertRaises(SupplierOfferAcquisitionError):
                    _fetch(
                        server,
                        Path(directory).resolve(strict=True),
                        timeout_seconds=1,
                    )
                self.assertLess(time.monotonic() - started, 1.5)

    def test_transaction_slot_prevents_pre_request_connection_accumulation(self) -> None:
        with _LoopbackServer(
            content_length=False,
            body_chunk_count=40,
            dribble_interval=0.1,
        ) as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            first_errors: list[SupplierOfferAcquisitionError] = []

            def first_fetch() -> None:
                try:
                    fetch_supplier_offer(
                        server.endpoint,
                        "example-supplier",
                        root / "offer-first.json",
                        root / "receipt-first.json",
                        procurement_intent_sha256=_PROCUREMENT_DIGEST,
                        timeout_seconds=3,
                        allow_insecure_loopback=True,
                    )
                except SupplierOfferAcquisitionError as error:
                    first_errors.append(error)

            worker = threading.Thread(target=first_fetch, daemon=True)
            worker.start()
            observation_deadline = time.monotonic() + 1.0
            while server.handler.requests != 1 and time.monotonic() < observation_deadline:
                time.sleep(0.01)
            self.assertEqual(server.handler.requests, 1)
            with self.assertRaises(SupplierOfferAcquisitionError):
                fetch_supplier_offer(
                    server.endpoint,
                    "example-supplier",
                    root / "offer-second.json",
                    root / "receipt-second.json",
                    procurement_intent_sha256=_PROCUREMENT_DIGEST,
                    timeout_seconds=1,
                    allow_insecure_loopback=True,
                )
            self.assertEqual(server.server.accepted, 1)
            worker.join(timeout=4)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(first_errors), 1)

    def test_preflight_and_publication_race_semantics(self) -> None:
        with _LoopbackServer() as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            occupied = root / "occupied.json"
            occupied.write_bytes(b"owned")
            for output, receipt in (
                (occupied, root / "receipt.json"),
                (root / "same.json", root / "same.json"),
            ):
                with self.subTest(output=output), mock.patch.object(
                    acquisition_module._transport, "_http_get"
                ) as transport:
                    with self.assertRaises(SupplierOfferAcquisitionError):
                        fetch_supplier_offer(
                            server.endpoint,
                            "example-supplier",
                            output,
                            receipt,
                            procurement_intent_sha256=_PROCUREMENT_DIGEST,
                            allow_insecure_loopback=True,
                        )
                    transport.assert_not_called()
            self.assertEqual(occupied.read_bytes(), b"owned")

        with _LoopbackServer() as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            original = acquisition_module.atomic_write_no_clobber
            calls = 0

            def lose_receipt(path: Path, data: bytes, *, max_bytes: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise BoundedIOError("receipt race")
                original(path, data, max_bytes=max_bytes)

            with mock.patch.object(
                acquisition_module, "atomic_write_no_clobber", side_effect=lose_receipt
            ):
                with self.assertRaises(SupplierOfferAcquisitionError):
                    _fetch(server, root)
            self.assertTrue((root / "offer.json").is_file())
            self.assertFalse((root / "receipt.json").exists())

    def test_lexical_and_casefolded_output_aliases_stop_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            same = root / "same.json"
            double_slash = "//" + str(same).lstrip("/")
            cases = (
                (same, double_slash),
                (root / "case.json", root / "CASE.JSON"),
            )
            for index, (output, receipt) in enumerate(cases):
                with self.subTest(index=index), mock.patch.object(
                    acquisition_module._transport, "_http_get"
                ) as transport:
                    with self.assertRaises(SupplierOfferAcquisitionError):
                        fetch_supplier_offer(
                            "https://example.test/offer",
                            "example-supplier",
                            output,
                            receipt,
                            procurement_intent_sha256=_PROCUREMENT_DIGEST,
                        )
                    transport.assert_not_called()

    def test_rejected_close_delimited_responses_do_not_leak_descriptors(self) -> None:
        descriptor_root = Path("/proc/self/fd")
        if not descriptor_root.is_dir():
            self.skipTest("descriptor accounting requires /proc/self/fd")
        with _LoopbackServer(
            status=302, content_length=False
        ) as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            baseline = len(list(descriptor_root.iterdir()))
            retained: list[SupplierOfferAcquisitionError] = []
            for index in range(12):
                try:
                    fetch_supplier_offer(
                        server.endpoint,
                        "example-supplier",
                        root / f"offer-{index}.json",
                        root / f"receipt-{index}.json",
                        procurement_intent_sha256=_PROCUREMENT_DIGEST,
                        allow_insecure_loopback=True,
                    )
                except SupplierOfferAcquisitionError as error:
                    retained.append(error)
            self.assertEqual(len(retained), 12)
            self.assertLessEqual(len(list(descriptor_root.iterdir())), baseline + 2)

    def test_request_digest_vector_and_schema_are_frozen(self) -> None:
        self.assertEqual(
            acquisition_module._request_sha256(
                "https://offers.example.test/quote/v1",
                "example-supplier",
                "0" * 64,
            ),
            "fcc8649f2b182d22ca26a826a774b2cc14ac55b45b68e82489af518c72d96d0c",
        )
        self.assertEqual(MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES, 1024 * 1024)
        schema = supplier_offer_fetch_receipt_json_schema()
        self.assertEqual(
            schema["$id"],
            "https://github.com/penguin425/pcbex/schemas/"
            "supplier-offer-fetch-receipt-v1.json",
        )
        self.assertEqual(schema["required"], list(acquisition_module._RECEIPT_KEYS))
        self.assertEqual(tuple(schema["properties"]), acquisition_module._RECEIPT_KEYS)

    def test_validator_accepts_one_pass_mapping_bytes_and_paths(self) -> None:
        with _LoopbackServer() as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            receipt = _fetch(server, root)
            offer_raw = (root / "offer.json").read_bytes()
            receipt_raw = (root / "receipt.json").read_bytes()
            stateful = _StatefulMapping(receipt)
            self.assertEqual(
                validate_supplier_offer_fetch_receipt(
                    stateful, offer_raw, allow_insecure_loopback=True
                ),
                receipt,
            )
            self.assertEqual(stateful.calls, 1)
            self.assertEqual(
                validate_supplier_offer_fetch_receipt(
                    _BytesPath(receipt_raw),
                    _BytesPath(offer_raw),
                    allow_insecure_loopback=True,
                ),
                receipt,
            )
            receipt_path = _OneShotPath(root / "receipt.json")
            offer_path = _OneShotPath(root / "offer.json")
            self.assertEqual(
                validate_supplier_offer_fetch_receipt(
                    receipt_path, offer_path, allow_insecure_loopback=True
                ),
                receipt,
            )
            self.assertEqual(receipt_path.calls, 1)
            self.assertEqual(offer_path.calls, 1)

    def test_provider_hook_exceptions_are_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            with mock.patch.object(
                acquisition_module._transport, "_http_get"
            ) as transport:
                with self.assertRaises(SupplierOfferAcquisitionError) as raised:
                    fetch_supplier_offer(
                        "https://example.test/offer",
                        "example-supplier",
                        _ExplodingPath(),
                        root / "receipt.json",
                        procurement_intent_sha256=_PROCUREMENT_DIGEST,
                    )
                self.assertNotIn("secret", str(raised.exception))
                transport.assert_not_called()
            with self.assertRaises(SupplierOfferAcquisitionError) as raised:
                validate_supplier_offer_fetch_receipt(
                    _ExplodingMapping(), _raw_offer()
                )
            self.assertNotIn("secret", str(raised.exception))
            with self.assertRaises(SupplierOfferAcquisitionError) as raised:
                validate_supplier_offer_fetch_receipt({}, _ExplodingPath())
            self.assertNotIn("secret", str(raised.exception))

            with mock.patch.object(
                os.environ, "get", side_effect=LookupError("environment-secret")
            ), mock.patch.object(
                acquisition_module._transport, "_http_get"
            ) as transport:
                with self.assertRaises(SupplierOfferAcquisitionError) as raised:
                    fetch_supplier_offer(
                        "https://example.test/offer",
                        "example-supplier",
                        root / "offer-env.json",
                        root / "receipt-env.json",
                        procurement_intent_sha256=_PROCUREMENT_DIGEST,
                        bearer_token_environment="PCBEX_OFFER_TOKEN",
                    )
                self.assertNotIn("secret", str(raised.exception))
                transport.assert_not_called()

    def test_validator_absolutizes_sources_before_a_cwd_change(self) -> None:
        original_cwd = Path.cwd()
        with _LoopbackServer() as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            elsewhere = root / "elsewhere"
            elsewhere.mkdir()
            receipt = _fetch(server, root)
            os.chdir(root)
            try:
                receipt_path = _OneShotPath(
                    root / "receipt.json", lambda: os.chdir(elsewhere)
                )
                self.assertEqual(
                    validate_supplier_offer_fetch_receipt(
                        receipt_path,
                        "offer.json",
                        allow_insecure_loopback=True,
                    ),
                    receipt,
                )
                self.assertEqual(receipt_path.calls, 1)
            finally:
                os.chdir(original_cwd)

    def test_validator_rejects_noncanonical_alias_tamper_and_mutation(self) -> None:
        with _LoopbackServer() as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            receipt = _fetch(server, root)
            offer_path = root / "offer.json"
            receipt_path = root / "receipt.json"
            compact_receipt = json.dumps(receipt, sort_keys=True).encode() + b"\n"
            compact_offer = json.dumps(_offer(), sort_keys=True).encode() + b"\n"
            for retained, offer in (
                (compact_receipt, offer_path),
                (receipt_path, compact_offer),
                (receipt_path, receipt_path),
            ):
                with self.subTest(retained=type(retained)), self.assertRaises(
                    SupplierOfferAcquisitionError
                ):
                    validate_supplier_offer_fetch_receipt(
                        retained, offer, allow_insecure_loopback=True
                    )
            forged = copy.deepcopy(receipt)
            forged["procurement_intent_sha256"] = "1" * 64
            forged["request_sha256"] = acquisition_module._request_sha256(
                forged["endpoint_id"], forged["supplier"], forged["procurement_intent_sha256"]
            )
            with self.assertRaises(SupplierOfferAcquisitionError):
                validate_supplier_offer_fetch_receipt(
                    forged, offer_path, allow_insecure_loopback=True
                )

            def mutate_offer() -> None:
                offer_path.write_bytes(offer_path.read_bytes() + b"changed")

            hooked_receipt = _OneShotPath(receipt_path, mutate_offer)
            with self.assertRaises(SupplierOfferAcquisitionError):
                validate_supplier_offer_fetch_receipt(
                    hooked_receipt, offer_path, allow_insecure_loopback=True
                )
            self.assertEqual(hooked_receipt.calls, 1)

    def test_validator_uses_no_network_time_or_offer_window(self) -> None:
        with _LoopbackServer() as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            receipt = _fetch(server, root)
            # fetched_at=100 deliberately lies outside offer window [10,20).
            with mock.patch.object(
                acquisition_module._transport,
                "_http_get",
                side_effect=AssertionError("network forbidden"),
            ), mock.patch.object(
                acquisition_module.time,
                "time",
                side_effect=AssertionError("clock forbidden"),
            ):
                self.assertEqual(
                    validate_supplier_offer_fetch_receipt(
                        receipt,
                        root / "offer.json",
                        allow_insecure_loopback=True,
                    ),
                    receipt,
                )

    def test_validator_enforces_five_mib_representation_aggregate(self) -> None:
        with _LoopbackServer() as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            receipt = _fetch(server, root)
            offer_raw = (root / "offer.json").read_bytes()
            receipt_raw = (root / "receipt.json").read_bytes()
            with mock.patch.object(
                acquisition_module,
                "_MAXIMUM_VALIDATION_AGGREGATE_BYTES",
                len(offer_raw) + len(receipt_raw) - 1,
            ):
                with self.assertRaises(SupplierOfferAcquisitionError):
                    validate_supplier_offer_fetch_receipt(
                        receipt_raw, offer_raw, allow_insecure_loopback=True
                    )


if __name__ == "__main__":
    unittest.main()

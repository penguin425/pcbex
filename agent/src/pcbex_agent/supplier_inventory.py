"""Bounded, explicit HTTP ingestion for catalog snapshot v1 documents.

This module is deliberately a pre-step to catalog selection.  It performs one
GET, retains no provider response object, and publishes a normalized local
snapshot and a digest-bound fetch receipt.  Selection itself remains entirely
offline (see :mod:`pcbex_agent.catalog`).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import queue
import re
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .bounded_io import (
    BoundedIOError,
    atomic_write_no_clobber,
    read_bytes,
    validate_no_clobber_path,
)
from .bounded_process import BoundedProcessError, ProcessTimeout, run_bounded
from .catalog import (
    MAX_CATALOG_RAW_BYTES,
    MAX_CATALOG_TIMESTAMP,
    MAX_CATALOG_TTL_SECONDS,
    load_catalog_snapshot,
)


CATALOG_FETCH_SCHEMA_VERSION = 1
CATALOG_FETCH_ADAPTER = "supplier-inventory-http-v1"
MAXIMUM_RESPONSE_BYTES = 4 * 1024 * 1024
MAXIMUM_RECEIPT_BYTES = 1 * 1024 * 1024
MAXIMUM_ENDPOINT_BYTES = 4 * 1024
MAXIMUM_BEARER_TOKEN_BYTES = 8 * 1024
MAXIMUM_RESOLVER_OUTPUT_BYTES = 64 * 1024
MAXIMUM_RESOLVED_ADDRESSES = 64

_SUPPLIER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_ENVIRONMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")
_ASCII_DIGITS_RE = re.compile(r"^[0-9]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONNECT_SLOT = threading.BoundedSemaphore(value=1)
_RESOLVER_SCRIPT = """
import json
import socket
import sys

try:
    records = []
    for family, socktype, protocol, _canonname, address in socket.getaddrinfo(
        sys.argv[1], int(sys.argv[2]), type=socket.SOCK_STREAM
    ):
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        if socktype != socket.SOCK_STREAM:
            continue
        records.append([family, socktype, protocol, list(address)])
        if len(records) > 64:
            raise RuntimeError
    if not records:
        raise RuntimeError
    sys.stdout.write(json.dumps(records, separators=(",", ":")))
except BaseException:
    raise SystemExit(2)
""".strip()
_RECEIPT_KEYS = frozenset(
    {
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
)
_RECEIPT_DIGEST_KEYS = (
    "request_sha256",
    "response_sha256",
    "snapshot_sha256",
    "catalog_sha256",
)


class SupplierInventoryError(ValueError):
    """Raised when bounded supplier snapshot ingestion fails."""


def _error(message: str) -> SupplierInventoryError:
    """Create an error without retaining a potentially sensitive exception."""

    return SupplierInventoryError(message)


def _validate_provider(provider: Any) -> str:
    if not isinstance(provider, str) or _SUPPLIER_RE.fullmatch(provider) is None:
        raise _error("supplier provider must be lowercase safe ASCII")
    # The expression is ASCII-only by construction.  Keep the explicit check
    # so a future expression edit cannot silently admit Unicode identifiers.
    try:
        provider.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise _error("supplier provider must be lowercase safe ASCII") from None
    return provider


def _validate_timeout(timeout_seconds: Any) -> int:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= 60
    ):
        raise _error("supplier catalog timeout must be between 1 and 60 seconds")
    return timeout_seconds


def _validate_response_limit(maximum_response_bytes: Any) -> int:
    if (
        isinstance(maximum_response_bytes, bool)
        or not isinstance(maximum_response_bytes, int)
        or not 1 <= maximum_response_bytes <= MAXIMUM_RESPONSE_BYTES
    ):
        raise _error(
            "maximum supplier catalog response must be between 1 and "
            f"{MAXIMUM_RESPONSE_BYTES} bytes"
        )
    return maximum_response_bytes


def _validate_loopback_flag(value: Any) -> bool:
    if not isinstance(value, bool):
        raise _error("allow_insecure_loopback must be a boolean")
    return value


def _validate_timestamp(value: Any, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_CATALOG_TIMESTAMP
    ):
        raise _error(f"{label} must be a bounded integer timestamp")
    return value


def _endpoint_parts(endpoint: Any, *, allow_insecure_loopback: bool) -> tuple[str, SplitResult]:
    if not isinstance(endpoint, str) or not endpoint:
        raise _error("supplier catalog endpoint must be an absolute HTTPS URL")
    if len(endpoint) > MAXIMUM_ENDPOINT_BYTES:
        raise _error("supplier catalog endpoint exceeds its byte bound")
    try:
        endpoint.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise _error("supplier catalog endpoint must be an ASCII URL") from None
    # Raw whitespace/control characters cannot be part of an HTTP request
    # target or header. Empty query/fragment delimiters are also rejected
    # rather than silently normalized out of the retained endpoint identity.
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in endpoint):
        raise _error("supplier catalog endpoint is invalid")
    if "?" in endpoint or "#" in endpoint:
        raise _error(
            "supplier catalog endpoint must omit query and fragment delimiters"
        )
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError):
        raise _error("supplier catalog endpoint is invalid") from None
    hostname = parsed.hostname
    if (
        not parsed.scheme
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        raise _error(
            "supplier catalog endpoint must be absolute and omit userinfo, query, and fragment"
        )
    try:
        hostname.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise _error("supplier catalog endpoint host is invalid") from None

    if parsed.scheme == "https":
        pass
    elif (
        allow_insecure_loopback
        and parsed.scheme == "http"
        and hostname.lower() in {"127.0.0.1", "::1"}
    ):
        pass
    else:
        raise _error("supplier catalog endpoint must use HTTPS")

    # Rebuild the endpoint with a lower-case host and the exact path.  This is
    # the endpoint identity retained in a receipt and the target used for the
    # request; no token or query can enter it because those were rejected.
    host = hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    authority = host if port is None else f"{host}:{port}"
    path = parsed.path or "/"
    canonical = urlunsplit((parsed.scheme, authority, path, "", ""))
    canonical_parts = urlsplit(canonical)
    return canonical, canonical_parts


def _validate_environment_name(name: Any) -> str:
    if not isinstance(name, str) or _ENVIRONMENT_RE.fullmatch(name) is None:
        raise _error("bearer token environment name is invalid")
    return name


def _load_bearer_token(name: Any) -> str | None:
    if name is None:
        return None
    environment_name = _validate_environment_name(name)
    token = os.environ.get(environment_name)
    if token is None or not token.strip():
        raise _error("bearer token environment is not set")
    # RFC 6750's b64token form is safe to place in an HTTP header and in a
    # JSON reflection scan.  Reject controls, quotes, Unicode, and interior
    # padding before constructing the header, without ever echoing the value.
    if len(token) > MAXIMUM_BEARER_TOKEN_BYTES:
        raise _error("bearer token exceeds its byte bound")
    if _BEARER_TOKEN_RE.fullmatch(token) is None:
        raise _error("bearer token contains invalid header characters")
    return token


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _error("supplier catalog receipt is not canonical JSON") from None


def _request_sha256(provider: str, endpoint_id: str) -> str:
    # JSON object ordering is fixed by sort_keys and the material includes no
    # Authorization value.  This gives one stable, secret-free identity for
    # the exact operation performed by this adapter.
    material = {
        "adapter": CATALOG_FETCH_ADAPTER,
        "endpoint": endpoint_id,
        "method": "GET",
        "provider": provider,
    }
    return hashlib.sha256(_canonical_json_bytes(material)).hexdigest()


def _pretty_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                value,
                indent=2,
                ensure_ascii=False,
                sort_keys=False,
                allow_nan=False,
            ).encode("utf-8", errors="strict")
            + b"\n"
        )
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _error("supplier catalog snapshot cannot be encoded") from None


def _preflight_outputs(output_path: Any, receipt_path: Any) -> tuple[Path, Path]:
    try:
        output_raw = os.fspath(output_path)
        receipt_raw = os.fspath(receipt_path)
        if isinstance(output_raw, bytes) or isinstance(receipt_raw, bytes):
            raise TypeError
        output_absolute = os.path.normcase(os.path.abspath(output_raw))
        receipt_absolute = os.path.normcase(os.path.abspath(receipt_raw))
    except (TypeError, ValueError, OSError):
        raise _error("supplier catalog output paths are invalid") from None
    if output_absolute == receipt_absolute:
        raise _error("supplier catalog snapshot and receipt paths must differ")
    paths = (Path(output_raw), Path(receipt_raw))
    # Both checks occur before the HTTP operation.  The bounded helper rejects
    # direct/ancestor links, non-regular existing destinations, and existing
    # regular destinations without creating missing parents.
    for path in paths:
        try:
            validate_no_clobber_path(path)
        except BoundedIOError:
            raise _error("supplier catalog output path is unsafe or already exists") from None
    return paths


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _set_socket_timeout(connection: http.client.HTTPConnection, deadline: float) -> None:
    remaining = _remaining(deadline)
    sock = connection.sock
    if sock is not None:
        sock.settimeout(remaining)


def _literal_address(hostname: str, port: int) -> list[tuple[int, int, int, tuple[Any, ...]]] | None:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, hostname)
        except OSError:
            continue
        address: tuple[Any, ...]
        if family == socket.AF_INET:
            address = (hostname, port)
        else:
            address = (hostname, port, 0, 0)
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, address)]
    return None


def _parse_resolver_output(
    raw: bytes,
    *,
    expected_port: int,
) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    try:
        value = json.loads(raw.decode("ascii", errors="strict"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise OSError("supplier resolver returned invalid output") from None
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAXIMUM_RESOLVED_ADDRESSES
    ):
        raise OSError("supplier resolver returned invalid output")

    resolved: list[tuple[int, int, int, tuple[Any, ...]]] = []
    seen: set[tuple[int, int, int, tuple[Any, ...]]] = set()
    for record in value:
        if not isinstance(record, list) or len(record) != 4:
            raise OSError("supplier resolver returned invalid output")
        family, socktype, protocol, raw_address = record
        if (
            isinstance(family, bool)
            or family not in (socket.AF_INET, socket.AF_INET6)
            or isinstance(socktype, bool)
            or socktype != socket.SOCK_STREAM
            or isinstance(protocol, bool)
            or not isinstance(protocol, int)
            or protocol < 0
            or protocol > 255
            or not isinstance(raw_address, list)
        ):
            raise OSError("supplier resolver returned invalid output")
        expected_items = 2 if family == socket.AF_INET else 4
        if len(raw_address) != expected_items:
            raise OSError("supplier resolver returned invalid output")
        address_text = raw_address[0]
        address_port = raw_address[1]
        if (
            not isinstance(address_text, str)
            or len(address_text) > 64
            or isinstance(address_port, bool)
            or address_port != expected_port
        ):
            raise OSError("supplier resolver returned invalid output")
        try:
            socket.inet_pton(family, address_text)
        except OSError:
            raise OSError("supplier resolver returned invalid output") from None
        if family == socket.AF_INET6:
            flow_info, scope_id = raw_address[2:]
            if any(
                isinstance(number, bool)
                or not isinstance(number, int)
                or number < 0
                or number > 0xFFFFFFFF
                for number in (flow_info, scope_id)
            ):
                raise OSError("supplier resolver returned invalid output")
        address = tuple(raw_address)
        normalized = (family, socktype, protocol, address)
        if normalized not in seen:
            seen.add(normalized)
            resolved.append(normalized)
    if not resolved:
        raise OSError("supplier resolver returned no usable addresses")
    return resolved


def _resolve_endpoint(
    hostname: str,
    port: int,
    deadline: float,
) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    literal = _literal_address(hostname, port)
    if literal is not None:
        return literal
    try:
        result = run_bounded(
            [sys.executable, "-I", "-c", _RESOLVER_SCRIPT, hostname, str(port)],
            timeout_seconds=_remaining(deadline),
            max_stdin_bytes=0,
            max_stdout_bytes=MAXIMUM_RESOLVER_OUTPUT_BYTES,
            max_stderr_bytes=0,
            env={},
        )
    except ProcessTimeout:
        raise TimeoutError from None
    except BoundedProcessError:
        raise OSError("supplier resolver failed") from None
    if result.returncode != 0 or result.stderr:
        raise OSError("supplier resolver failed")
    return _parse_resolver_output(result.stdout, expected_port=port)


def _install_resolved_socket_factory(
    connection: http.client.HTTPConnection,
    resolved: list[tuple[int, int, int, tuple[Any, ...]]],
    deadline: float,
) -> None:
    def create_connection(
        _address: tuple[str, int],
        _timeout: Any = None,
        source_address: tuple[str, int] | None = None,
    ) -> socket.socket:
        for family, socktype, protocol, address in resolved:
            opened: socket.socket | None = None
            try:
                opened = socket.socket(family, socktype, protocol)
                opened.settimeout(_remaining(deadline))
                if source_address is not None:
                    opened.bind(source_address)
                opened.connect(address)
                return opened
            except TimeoutError:
                if opened is not None:
                    opened.close()
                raise
            except OSError:
                if opened is not None:
                    opened.close()
        raise OSError("supplier connection failed") from None

    connection._create_connection = create_connection


def _connect_with_deadline(
    connection: http.client.HTTPConnection,
    deadline: float,
) -> None:
    """Bound TCP/TLS setup and cap any pathological late worker to one."""

    outcome: queue.Queue[bool] = queue.Queue(maxsize=1)
    cancelled = threading.Event()
    try:
        acquired = _CONNECT_SLOT.acquire(timeout=_remaining(deadline))
    except TimeoutError:
        raise TimeoutError from None
    if not acquired:
        raise TimeoutError

    def connect() -> None:
        succeeded = False
        try:
            connection.connect()
            succeeded = True
        except Exception:
            # Never move a provider-controlled exception object or message
            # across the thread boundary into public diagnostics.
            succeeded = False
        finally:
            if cancelled.is_set():
                try:
                    connection.close()
                except (OSError, http.client.HTTPException):
                    pass
            try:
                outcome.put_nowait(succeeded)
            except queue.Full:  # pragma: no cover - one producer, one result
                pass
            _CONNECT_SLOT.release()

    worker = threading.Thread(
        target=connect,
        name="pcbex-supplier-connect",
        daemon=True,
    )
    try:
        worker.start()
    except RuntimeError:
        _CONNECT_SLOT.release()
        raise OSError("supplier connection worker could not start") from None
    try:
        succeeded = outcome.get(timeout=_remaining(deadline))
    except (TimeoutError, queue.Empty):
        cancelled.set()
        try:
            connection.close()
        except (OSError, http.client.HTTPException):
            pass
        raise TimeoutError from None
    if not succeeded:
        raise OSError("supplier connection failed")


def _parse_content_length(response: http.client.HTTPResponse) -> int | None:
    values = response.headers.get_all("Content-Length", [])
    if len(values) > 1:
        raise _error("supplier catalog response has ambiguous Content-Length")
    if not values:
        return None
    value = values[0].strip()
    if not value or _ASCII_DIGITS_RE.fullmatch(value) is None:
        raise _error("supplier catalog response has invalid Content-Length")
    try:
        length = int(value, 10)
    except (TypeError, ValueError):
        raise _error("supplier catalog response has invalid Content-Length") from None
    return length


def _http_get(
    endpoint_id: str,
    *,
    timeout_seconds: int,
    maximum_response_bytes: int,
    bearer_token: str | None,
) -> tuple[bytes, int]:
    parsed = urlsplit(endpoint_id)
    deadline = time.monotonic() + timeout_seconds
    connection_type: type[http.client.HTTPConnection]
    connection_type = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    try:
        connection = connection_type(parsed.hostname, parsed.port, timeout=timeout_seconds)
    except (TypeError, ValueError, OSError):
        raise _error("supplier catalog connection could not be created") from None

    headers = {"Accept": "application/json"}
    if bearer_token is not None:
        headers["Authorization"] = f"Bearer {bearer_token}"
    body = bytearray()
    status: int | None = None
    declared_length: int | None = None
    try:
        try:
            hostname = parsed.hostname
            if hostname is None:
                raise OSError("supplier endpoint host is missing")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            resolved = _resolve_endpoint(hostname, port, deadline)
            _install_resolved_socket_factory(connection, resolved, deadline)
            _connect_with_deadline(connection, deadline)
            _set_socket_timeout(connection, deadline)
            # Explicitly issue only GET.  http.client does not follow redirects.
            connection.request("GET", parsed.path or "/", headers=headers)
            _set_socket_timeout(connection, deadline)
            response = connection.getresponse()
            _set_socket_timeout(connection, deadline)
        except (TimeoutError, socket.timeout):
            raise _error("supplier catalog request exceeded its timeout") from None
        except (OSError, http.client.HTTPException):
            raise _error("supplier catalog request failed") from None

        status = response.status
        if not isinstance(status, int) or isinstance(status, bool) or not 200 <= status < 300:
            raise _error("supplier catalog endpoint returned a non-success status")

        content_types = response.headers.get_all("Content-Type", [])
        if len(content_types) != 1:
            raise _error("supplier catalog response must declare application/json")
        try:
            content_type = response.headers.get_content_type()
        except (AttributeError, ValueError):
            raise _error("supplier catalog response must declare application/json") from None
        if content_type != "application/json":
            raise _error("supplier catalog response must declare application/json")

        content_encodings = response.headers.get_all("Content-Encoding", [])
        if len(content_encodings) > 1:
            raise _error("supplier catalog response has ambiguous Content-Encoding")
        if content_encodings and content_encodings[0].strip().lower() != "identity":
            raise _error("supplier catalog response must not be encoded")

        transfer_encodings = response.headers.get_all("Transfer-Encoding", [])
        if len(transfer_encodings) > 1:
            raise _error("supplier catalog response has ambiguous Transfer-Encoding")
        if transfer_encodings:
            transfer_tokens = [
                token.strip().lower() for token in transfer_encodings[0].split(",")
            ]
            if transfer_tokens != ["chunked"]:
                raise _error("supplier catalog response has unsupported Transfer-Encoding")

        declared_length = _parse_content_length(response)
        if transfer_encodings and declared_length is not None:
            raise _error("supplier catalog response framing is ambiguous")
        if declared_length is not None and declared_length > maximum_response_bytes:
            raise _error("supplier catalog response exceeds its byte bound")

        while len(body) <= maximum_response_bytes:
            read_size = min(64 * 1024, maximum_response_bytes + 1 - len(body))
            try:
                _set_socket_timeout(connection, deadline)
                chunk = response.read(read_size)
            except (TimeoutError, socket.timeout):
                raise _error("supplier catalog request exceeded its timeout") from None
            except (OSError, http.client.HTTPException):
                raise _error("supplier catalog request failed") from None
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > maximum_response_bytes:
                raise _error("supplier catalog response exceeds its byte bound")
        if declared_length is not None and len(body) != declared_length:
            raise _error("supplier catalog response length did not match Content-Length")
    finally:
        try:
            connection.close()
        except (OSError, http.client.HTTPException):
            pass
    assert status is not None
    return bytes(body), status


def _validate_receipt_shape(
    receipt: Any,
    *,
    allow_insecure_loopback: bool = False,
) -> dict[str, Any]:
    allow_loopback = _validate_loopback_flag(allow_insecure_loopback)
    if not isinstance(receipt, Mapping):
        raise _error("supplier catalog fetch receipt must be an object")
    try:
        value = dict(receipt)
        keys = set(value)
    except (TypeError, ValueError, RuntimeError):
        raise _error("supplier catalog fetch receipt must be an object") from None
    if keys != _RECEIPT_KEYS:
        raise _error("supplier catalog fetch receipt has invalid fields")

    if value.get("schema_version") != CATALOG_FETCH_SCHEMA_VERSION or isinstance(
        value.get("schema_version"), bool
    ):
        raise _error("supplier catalog fetch receipt schema version is invalid")
    if value.get("adapter") != CATALOG_FETCH_ADAPTER:
        raise _error("supplier catalog fetch receipt adapter is invalid")
    provider = value.get("provider")
    if not isinstance(provider, str) or _SUPPLIER_RE.fullmatch(provider) is None:
        raise _error("supplier catalog fetch receipt provider is invalid")
    endpoint_id = value.get("endpoint_id")
    if not isinstance(endpoint_id, str) or not endpoint_id or len(endpoint_id) > 4096:
        raise _error("supplier catalog fetch receipt endpoint is invalid")
    # Receipt endpoint identities must be the same safe endpoint form accepted
    # at fetch time.  This also prevents an endpoint token from being smuggled
    # into a recomputation input.
    canonical_endpoint, _parts = _endpoint_parts(
        endpoint_id,
        allow_insecure_loopback=allow_loopback,
    )
    if canonical_endpoint != endpoint_id:
        raise _error("supplier catalog fetch receipt endpoint is not canonical")

    for key in _RECEIPT_DIGEST_KEYS:
        digest = value.get(key)
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise _error("supplier catalog fetch receipt digest is invalid")

    for key, minimum, maximum in (
        ("response_bytes", 1, MAXIMUM_RESPONSE_BYTES),
        ("snapshot_bytes", 1, MAX_CATALOG_RAW_BYTES),
    ):
        number = value.get(key)
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number < minimum
            or number > maximum
        ):
            raise _error("supplier catalog fetch receipt byte count is invalid")
    status = value.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status < 300:
        raise _error("supplier catalog fetch receipt status is invalid")

    fetched = _validate_timestamp(value.get("fetched_at_unix"), "receipt fetched_at_unix")
    expires = _validate_timestamp(value.get("expires_at_unix"), "receipt expires_at_unix")
    if expires < fetched or expires - fetched > MAX_CATALOG_TTL_SECONDS:
        raise _error("supplier catalog fetch receipt expiry is invalid")

    expected_request = _request_sha256(provider, endpoint_id)
    if value.get("request_sha256") != expected_request:
        raise _error("supplier catalog fetch receipt request digest is invalid")

    canonical = _canonical_json_bytes(value)
    if len(canonical) > MAXIMUM_RECEIPT_BYTES:
        raise _error("supplier catalog fetch receipt exceeds its canonical byte bound")
    return value


def catalog_fetch_receipt_json_schema() -> dict[str, Any]:
    """Return the closed JSON Schema for supplier fetch receipts."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/catalog-fetch-receipt-v1.json",
        "$comment": (
            "The runtime validator additionally enforces canonical UTF-8 byte "
            "bounds, endpoint normalization, timestamp/TTL semantics, and all "
            "recomputed snapshot bindings."
        ),
        "title": "pcbex supplier inventory catalog fetch receipt v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
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
        ],
        "properties": {
            "schema_version": {"const": CATALOG_FETCH_SCHEMA_VERSION},
            "adapter": {"const": CATALOG_FETCH_ADAPTER},
            "provider": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$",
            },
            "endpoint_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "format": "uri",
            },
            "request_sha256": digest,
            "response_sha256": digest,
            "response_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_RESPONSE_BYTES,
            },
            "status": {"type": "integer", "minimum": 200, "maximum": 299},
            "fetched_at_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_CATALOG_TIMESTAMP,
            },
            "expires_at_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_CATALOG_TIMESTAMP,
            },
            "snapshot_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_CATALOG_RAW_BYTES,
            },
            "snapshot_sha256": digest,
            "catalog_sha256": digest,
        },
    }


def fetch_catalog_snapshot(
    endpoint: str,
    provider: str,
    output_path: Any,
    receipt_path: Any,
    *,
    timeout_seconds: int = 30,
    maximum_response_bytes: int = MAXIMUM_RESPONSE_BYTES,
    bearer_token_environment: str | None = None,
    fetched_at_unix: int | None = None,
    allow_insecure_loopback: bool = False,
) -> dict[str, Any]:
    """Fetch and no-clobber publish one normalized catalog snapshot.

    The endpoint and output paths are checked before any network operation.
    Redirects are not followed, only ``application/json`` 2xx responses are
    admitted, and the response is bounded under one monotonic deadline.
    """

    # Path preflight is intentionally the first external operation: a caller
    # cannot accidentally contact a supplier when publication targets are
    # already occupied or unsafe.
    output, receipt_output = _preflight_outputs(output_path, receipt_path)
    provider_value = _validate_provider(provider)
    timeout = _validate_timeout(timeout_seconds)
    response_limit = _validate_response_limit(maximum_response_bytes)
    allow_loopback = _validate_loopback_flag(allow_insecure_loopback)
    endpoint_id, _endpoint = _endpoint_parts(
        endpoint,
        allow_insecure_loopback=allow_loopback,
    )
    token = _load_bearer_token(bearer_token_environment)
    if fetched_at_unix is None:
        fetched = _validate_timestamp(int(time.time()), "fetched_at_unix")
    else:
        fetched = _validate_timestamp(fetched_at_unix, "fetched_at_unix")

    raw_response, status = _http_get(
        endpoint_id,
        timeout_seconds=timeout,
        maximum_response_bytes=response_limit,
        bearer_token=token,
    )
    if token is not None:
        try:
            token_bytes = token.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise _error("bearer token contains invalid header characters") from None
        # Do not permit a provider to reflect credentials into retained local
        # evidence.  The normalized representation is checked again below for
        # escaped JSON forms.
        if token_bytes and token_bytes in raw_response:
            raise _error("supplier catalog response reflected the bearer token")

    response_sha = hashlib.sha256(raw_response).hexdigest()
    try:
        snapshot = load_catalog_snapshot(raw_response, evaluated_at_unix=fetched)
    except Exception:
        # The loader's detailed diagnostics may contain untrusted JSON values;
        # retain only a stable, body-free adapter error.
        raise _error("supplier catalog snapshot failed closed validation") from None
    if snapshot.supplier != provider_value:
        raise _error("supplier catalog snapshot supplier does not match provider")
    normalized_snapshot = _pretty_json_bytes(snapshot.to_mapping())
    if len(normalized_snapshot) > MAX_CATALOG_RAW_BYTES:
        raise _error("normalized supplier catalog snapshot exceeds its byte bound")
    if token is not None:
        try:
            if token.encode("utf-8", errors="strict") in normalized_snapshot:
                raise _error("supplier catalog snapshot reflected the bearer token")
        except UnicodeEncodeError:
            raise _error("bearer token contains invalid header characters") from None

    receipt: dict[str, Any] = {
        "schema_version": CATALOG_FETCH_SCHEMA_VERSION,
        "adapter": CATALOG_FETCH_ADAPTER,
        "provider": provider_value,
        "endpoint_id": endpoint_id,
        "request_sha256": _request_sha256(provider_value, endpoint_id),
        "response_sha256": response_sha,
        "response_bytes": len(raw_response),
        "status": status,
        "fetched_at_unix": fetched,
        "expires_at_unix": snapshot.expires_at_unix,
        "snapshot_bytes": len(normalized_snapshot),
        "snapshot_sha256": hashlib.sha256(normalized_snapshot).hexdigest(),
        "catalog_sha256": snapshot.catalog_sha256,
    }
    try:
        _validate_receipt_shape(receipt, allow_insecure_loopback=allow_loopback)
        receipt_bytes = _pretty_json_bytes(receipt)
    except SupplierInventoryError:
        raise
    if len(receipt_bytes) > MAXIMUM_RECEIPT_BYTES:
        raise _error("supplier catalog fetch receipt exceeds its byte bound")
    if token is not None:
        token_bytes = token.encode("ascii", errors="strict")
        if token_bytes and token_bytes in receipt_bytes:
            raise _error("supplier catalog fetch receipt reflected the bearer token")

    try:
        atomic_write_no_clobber(
            output,
            normalized_snapshot,
            max_bytes=MAX_CATALOG_RAW_BYTES,
        )
    except BoundedIOError:
        raise _error("publishing supplier catalog snapshot failed") from None
    try:
        atomic_write_no_clobber(
            receipt_output,
            receipt_bytes,
            max_bytes=MAXIMUM_RECEIPT_BYTES,
        )
    except BoundedIOError:
        # Never unlink the snapshot here.  A receipt race can mean another
        # writer owns either artifact, and deleting it would be a clobber.
        raise _error("publishing supplier catalog fetch receipt failed") from None
    return receipt


def validate_catalog_fetch_receipt(
    receipt: Any,
    snapshot_source: Any,
    *,
    evaluated_at_unix: int | None = None,
    allow_insecure_loopback: bool = False,
) -> dict[str, Any]:
    """Validate a fetch receipt against one stable local snapshot.

    Validation always evaluates the catalog at the receipt's fetch timestamp.
    Callers may pass ``evaluated_at_unix`` only when it is exactly that same
    timestamp; this makes the replay point explicit and deterministic.
    """

    shape = _validate_receipt_shape(
        receipt,
        allow_insecure_loopback=allow_insecure_loopback,
    )
    fetched = shape["fetched_at_unix"]
    if evaluated_at_unix is not None:
        evaluated = _validate_timestamp(evaluated_at_unix, "evaluated_at_unix")
        if evaluated != fetched:
            raise _error("evaluated_at_unix must equal receipt fetched_at_unix")

    if isinstance(snapshot_source, (str, os.PathLike, Path)):
        try:
            snapshot_bytes = read_bytes(snapshot_source, max_bytes=MAX_CATALOG_RAW_BYTES)
        except BoundedIOError:
            raise _error("unable to stably read supplier catalog snapshot") from None
    elif isinstance(snapshot_source, bytes):
        snapshot_bytes = snapshot_source
    elif isinstance(snapshot_source, bytearray):
        if not snapshot_source or len(snapshot_source) > MAX_CATALOG_RAW_BYTES:
            raise _error("supplier catalog snapshot source exceeds its byte bound")
        try:
            snapshot_bytes = bytes(snapshot_source)
        except (TypeError, ValueError):
            raise _error("supplier catalog snapshot source is invalid") from None
    elif isinstance(snapshot_source, memoryview):
        try:
            snapshot_size = snapshot_source.nbytes
        except (TypeError, ValueError):
            raise _error("supplier catalog snapshot source is invalid") from None
        if snapshot_size <= 0 or snapshot_size > MAX_CATALOG_RAW_BYTES:
            raise _error("supplier catalog snapshot source exceeds its byte bound")
        try:
            snapshot_bytes = snapshot_source.tobytes()
        except (TypeError, ValueError):
            raise _error("supplier catalog snapshot source is invalid") from None
    else:
        raise _error("supplier catalog snapshot source must be a path or bytes")
    if not snapshot_bytes or len(snapshot_bytes) > MAX_CATALOG_RAW_BYTES:
        raise _error("supplier catalog snapshot source exceeds its byte bound")
    if len(snapshot_bytes) != shape["snapshot_bytes"]:
        raise _error("supplier catalog snapshot byte count does not match receipt")
    if hashlib.sha256(snapshot_bytes).hexdigest() != shape["snapshot_sha256"]:
        raise _error("supplier catalog snapshot digest does not match receipt")

    try:
        snapshot = load_catalog_snapshot(snapshot_bytes, evaluated_at_unix=fetched)
    except Exception:
        raise _error("supplier catalog snapshot failed closed validation") from None
    if snapshot.supplier != shape["provider"]:
        raise _error("supplier catalog snapshot supplier does not match receipt")
    if snapshot.expires_at_unix != shape["expires_at_unix"]:
        raise _error("supplier catalog snapshot expiry does not match receipt")
    if snapshot.catalog_sha256 != shape["catalog_sha256"]:
        raise _error("supplier catalog catalog digest does not match receipt")
    normalized = _pretty_json_bytes(snapshot.to_mapping())
    if normalized != snapshot_bytes:
        raise _error("supplier catalog snapshot is not the normalized published form")
    expected_request = _request_sha256(shape["provider"], shape["endpoint_id"])
    if shape["request_sha256"] != expected_request:
        raise _error("supplier catalog fetch request digest does not match receipt")
    return shape


__all__ = [
    "SupplierInventoryError",
    "catalog_fetch_receipt_json_schema",
    "fetch_catalog_snapshot",
    "validate_catalog_fetch_receipt",
]

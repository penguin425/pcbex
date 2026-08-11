"""Private bounded HTTP transport for supplier-offer acquisition.

This module is intentionally independent from the frozen v1.420 supplier
inventory adapter.  It performs one GET, follows no redirect, retries nothing,
and returns only the bounded response body and status to the v1.469 boundary.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import queue
import re
import socket
import sys
import threading
import time
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .bounded_process import BoundedProcessError, ProcessTimeout, run_bounded


MAXIMUM_ENDPOINT_BYTES = 4 * 1024
MAXIMUM_BEARER_TOKEN_BYTES = 8 * 1024
MAXIMUM_RESOLVER_OUTPUT_BYTES = 64 * 1024
MAXIMUM_RESOLVED_ADDRESSES = 64
MAXIMUM_RESPONSE_HEADERS = 64
MAXIMUM_RESPONSE_HEADER_BYTES = 64 * 1024

_ENVIRONMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_BEARER_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/-]+=*")
_ASCII_DIGITS_RE = re.compile(r"[0-9]+")
_CHUNK_SIZE_LINE_RE = re.compile(rb"[0-9A-Fa-f]+\r\n")
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_STATUS_LINE_RE = re.compile(
    rb"(HTTP/1\.[01]) ([0-9]{3}) ([\x20-\x7e]*)\r\n"
)
_CONNECT_SLOT = threading.BoundedSemaphore(value=1)
_REQUEST_SLOT = threading.BoundedSemaphore(value=1)
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


class _SupplierOfferTransportError(ValueError):
    """Internal path/body-free transport failure."""


def _fail(message: str) -> _SupplierOfferTransportError:
    return _SupplierOfferTransportError(message)


def _validate_loopback_flag(value: Any) -> bool:
    if type(value) is not bool:
        raise _fail("allow_insecure_loopback must be a boolean")
    return value


def _endpoint_parts(
    endpoint: Any, *, allow_insecure_loopback: bool
) -> tuple[str, SplitResult]:
    allow_loopback = _validate_loopback_flag(allow_insecure_loopback)
    if type(endpoint) is not str or not endpoint:
        raise _fail("supplier-offer endpoint must be an absolute HTTPS URL")
    if str.__len__(endpoint) > MAXIMUM_ENDPOINT_BYTES:
        raise _fail("supplier-offer endpoint exceeds its byte bound")
    try:
        encoded = str.encode(endpoint, "ascii", "strict")
    except UnicodeEncodeError:
        raise _fail("supplier-offer endpoint must be an ASCII URL") from None
    if len(encoded) > MAXIMUM_ENDPOINT_BYTES:
        raise _fail("supplier-offer endpoint exceeds its byte bound")
    if (
        str.__contains__(endpoint, "\\")
        or str.__contains__(endpoint, "?")
        or str.__contains__(endpoint, "#")
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in endpoint)
    ):
        raise _fail(
            "supplier-offer endpoint must omit controls, backslashes, query, and fragment"
        )
    try:
        parsed = urlsplit(str.__str__(endpoint))
        if parsed.netloc.endswith(":"):
            raise ValueError
        port = parsed.port
    except (TypeError, ValueError):
        raise _fail("supplier-offer endpoint is invalid") from None
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
        raise _fail(
            "supplier-offer endpoint must be absolute and omit userinfo, query, and fragment"
        )
    try:
        str.encode(hostname, "ascii", "strict")
    except UnicodeEncodeError:
        raise _fail("supplier-offer endpoint host is invalid") from None
    scheme = parsed.scheme.lower()
    host = hostname.lower()
    if parsed.netloc.startswith("["):
        try:
            socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            raise _fail("supplier-offer endpoint host is invalid") from None
    elif "[" in parsed.netloc or "]" in parsed.netloc:
        raise _fail("supplier-offer endpoint host is invalid")
    if scheme == "https":
        pass
    elif (
        allow_loopback
        and scheme == "http"
        and host in {"127.0.0.1", "::1"}
    ):
        pass
    else:
        raise _fail("supplier-offer endpoint must use HTTPS")
    rendered_host = f"[{host}]" if ":" in host else host
    authority = rendered_host if port is None else f"{rendered_host}:{port}"
    path = parsed.path or "/"
    canonical = urlunsplit((scheme, authority, path, "", ""))
    return canonical, urlsplit(canonical)


def _load_bearer_token(name: Any) -> str | None:
    if name is None:
        return None
    if type(name) is not str or _ENVIRONMENT_RE.fullmatch(name) is None:
        raise _fail("bearer token environment name is invalid")
    # Windows requires SystemRoot in the isolated resolver environment.  It
    # therefore cannot also designate the bearer secret (environment names
    # are case-insensitive on Windows); keep the rule deterministic on every
    # platform and reject it before reading the environment.
    if name.casefold() == "systemroot":
        raise _fail("bearer token environment name is reserved")
    try:
        token = os.environ.get(name)
    except Exception:
        raise _fail("bearer token environment could not be read") from None
    if token is None or type(token) is not str or not token:
        raise _fail("bearer token environment is not set")
    if (
        str.__len__(token) > MAXIMUM_BEARER_TOKEN_BYTES
        or _BEARER_TOKEN_RE.fullmatch(token) is None
    ):
        raise _fail("bearer token contains invalid header characters")
    try:
        encoded = str.encode(token, "ascii", "strict")
    except UnicodeEncodeError:
        raise _fail("bearer token contains invalid header characters") from None
    if len(encoded) > MAXIMUM_BEARER_TOKEN_BYTES:
        raise _fail("bearer token exceeds its byte bound")
    return str.__str__(token)


def _remaining(deadline: float, clock=time.monotonic) -> float:
    try:
        remaining = deadline - float(clock())
    except (TypeError, ValueError, OverflowError):
        raise TimeoutError from None
    if not remaining > 0:
        raise TimeoutError
    return remaining


def _literal_address(
    hostname: str, port: int
) -> list[tuple[int, int, int, tuple[Any, ...]]] | None:
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
    raw: bytes, *, expected_port: int
) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    try:
        value = json.loads(raw.decode("ascii", errors="strict"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise OSError("supplier-offer resolver returned invalid output") from None
    if (
        type(value) is not list
        or not value
        or len(value) > MAXIMUM_RESOLVED_ADDRESSES
    ):
        raise OSError("supplier-offer resolver returned invalid output")
    resolved: list[tuple[int, int, int, tuple[Any, ...]]] = []
    seen: set[tuple[int, int, int, tuple[Any, ...]]] = set()
    for record in value:
        if type(record) is not list or len(record) != 4:
            raise OSError("supplier-offer resolver returned invalid output")
        family, socktype, protocol, raw_address = record
        if (
            type(family) is not int
            or family not in (socket.AF_INET, socket.AF_INET6)
            or type(socktype) is not int
            or socktype != socket.SOCK_STREAM
            or type(protocol) is not int
            or not 0 <= protocol <= 255
            or type(raw_address) is not list
        ):
            raise OSError("supplier-offer resolver returned invalid output")
        expected_items = 2 if family == socket.AF_INET else 4
        if len(raw_address) != expected_items:
            raise OSError("supplier-offer resolver returned invalid output")
        address_text, address_port = raw_address[:2]
        if (
            type(address_text) is not str
            or str.__len__(address_text) > 64
            or type(address_port) is not int
            or address_port != expected_port
        ):
            raise OSError("supplier-offer resolver returned invalid output")
        try:
            socket.inet_pton(family, address_text)
        except OSError:
            raise OSError("supplier-offer resolver returned invalid output") from None
        if family == socket.AF_INET6 and any(
            type(number) is not int or not 0 <= number <= 0xFFFFFFFF
            for number in raw_address[2:]
        ):
            raise OSError("supplier-offer resolver returned invalid output")
        normalized = (family, socktype, protocol, tuple(raw_address))
        if normalized not in seen:
            seen.add(normalized)
            resolved.append(normalized)
    if not resolved:
        raise OSError("supplier-offer resolver returned no usable addresses")
    return resolved


def _resolver_environment(bearer_token: str | None = None) -> dict[str, str]:
    if os.name != "nt":
        return {}
    try:
        system_root = os.environ.get("SystemRoot")
    except Exception:
        raise OSError("supplier-offer resolver environment is invalid") from None
    if type(system_root) is not str or not system_root:
        raise OSError("supplier-offer resolver environment is invalid")
    try:
        encoded = str.encode(system_root, "utf-8", "strict")
    except UnicodeError:
        raise OSError("supplier-offer resolver environment is invalid") from None
    if len(encoded) > MAXIMUM_ENDPOINT_BYTES or b"\0" in encoded:
        raise OSError("supplier-offer resolver environment is invalid")
    if bearer_token is not None:
        if type(bearer_token) is not str:
            raise OSError("supplier-offer resolver environment is invalid")
        try:
            token_bytes = str.encode(bearer_token, "ascii", "strict")
        except UnicodeError:
            raise OSError("supplier-offer resolver environment is invalid") from None
        if not token_bytes or token_bytes in encoded:
            raise OSError("supplier-offer resolver environment is invalid")
    return {"SystemRoot": str.__str__(system_root)}


def _resolve_endpoint(
    hostname: str,
    port: int,
    deadline: float,
    *,
    cleanup_timeout_seconds: float,
    bearer_token: str | None = None,
    clock=time.monotonic,
) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    literal = _literal_address(hostname, port)
    if literal is not None:
        return literal
    try:
        result = run_bounded(
            [sys.executable, "-I", "-c", _RESOLVER_SCRIPT, hostname, str(port)],
            timeout_seconds=_remaining(deadline, clock),
            cleanup_timeout_seconds=cleanup_timeout_seconds,
            max_stdin_bytes=0,
            max_stdout_bytes=MAXIMUM_RESOLVER_OUTPUT_BYTES,
            max_stderr_bytes=0,
            env=_resolver_environment(bearer_token),
        )
    except ProcessTimeout:
        raise TimeoutError from None
    except BoundedProcessError:
        raise OSError("supplier-offer resolver failed") from None
    if result.returncode != 0 or result.stderr:
        raise OSError("supplier-offer resolver failed")
    return _parse_resolver_output(result.stdout, expected_port=port)


def _install_resolved_socket_factory(
    connection: http.client.HTTPConnection,
    resolved: list[tuple[int, int, int, tuple[Any, ...]]],
    deadline: float,
    *,
    clock=time.monotonic,
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
                opened.settimeout(_remaining(deadline, clock))
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
        raise OSError("supplier-offer connection failed") from None

    connection._create_connection = create_connection


def _connect_with_deadline(
    connection: http.client.HTTPConnection,
    deadline: float,
    *,
    clock=time.monotonic,
) -> None:
    outcome: queue.Queue[bool] = queue.Queue(maxsize=1)
    cancelled = threading.Event()
    if not _CONNECT_SLOT.acquire(timeout=_remaining(deadline, clock)):
        raise TimeoutError

    def connect() -> None:
        succeeded = False
        try:
            connection.connect()
            succeeded = True
        except Exception:
            succeeded = False
        finally:
            if cancelled.is_set():
                try:
                    connection.close()
                except (OSError, http.client.HTTPException):
                    pass
            try:
                outcome.put_nowait(succeeded)
            except queue.Full:  # pragma: no cover - one producer
                pass
            _CONNECT_SLOT.release()

    worker = threading.Thread(
        target=connect, name="pcbex-supplier-offer-connect", daemon=True
    )
    try:
        worker.start()
    except RuntimeError:
        _CONNECT_SLOT.release()
        raise OSError("supplier-offer connection worker could not start") from None
    try:
        succeeded = outcome.get(timeout=_remaining(deadline, clock))
    except (TimeoutError, queue.Empty):
        cancelled.set()
        try:
            connection.close()
        except (OSError, http.client.HTTPException):
            pass
        raise TimeoutError from None
    if not succeeded:
        raise OSError("supplier-offer connection failed")


def _set_socket_timeout(
    connection: http.client.HTTPConnection,
    deadline: float,
    *,
    clock=time.monotonic,
) -> None:
    sock = connection.sock
    if sock is not None:
        sock.settimeout(_remaining(deadline, clock))


def _read_bounded_header_block(fp: Any) -> bytes:
    lines: list[bytes] = []
    total = 0
    # The accepted budget counts only field names and values.  Permit the
    # bounded syntax overhead required to parse at most 64 CRLF-terminated
    # fields, then enforce the exact semantic budget in ``_validate_headers``.
    raw_maximum = (
        MAXIMUM_RESPONSE_HEADER_BYTES + (4 * MAXIMUM_RESPONSE_HEADERS) + 2
    )
    while True:
        try:
            line = fp.readline(raw_maximum + 1 - total)
        except Exception:
            raise http.client.HTTPException("invalid supplier-offer headers") from None
        if not isinstance(line, bytes) or not line or not line.endswith(b"\r\n"):
            raise http.client.HTTPException("invalid supplier-offer headers")
        total += len(line)
        if total > raw_maximum:
            raise http.client.HTTPException("supplier-offer headers are too large")
        if line == b"\r\n":
            break
        if len(lines) == MAXIMUM_RESPONSE_HEADERS:
            raise http.client.HTTPException("too many supplier-offer headers")
        lines.append(line)
    return b"".join(lines) + b"\r\n"


class _BoundedHTTPResponse(http.client.HTTPResponse):
    def __init__(
        self,
        sock: socket.socket,
        debuglevel: int = 0,
        method: str | None = None,
        url: str | None = None,
        *,
        maximum_body_bytes: int,
    ) -> None:
        super().__init__(sock, debuglevel=debuglevel, method=method, url=url)
        self._maximum_body_bytes = maximum_body_bytes
        self._declared_chunk_bytes = 0

    def _read_status(self) -> tuple[str, int, str]:
        try:
            raw = self.fp.readline(65_537)
        except Exception:
            raise http.client.BadStatusLine("invalid status line") from None
        if (
            type(raw) is not bytes
            or not raw
            or len(raw) > 65_536
            or not raw.endswith(b"\r\n")
        ):
            self._close_conn()
            raise http.client.BadStatusLine("invalid status line")
        matched = _STATUS_LINE_RE.fullmatch(raw)
        if matched is None:
            self._close_conn()
            raise http.client.BadStatusLine("invalid status line")
        version = matched.group(1).decode("ascii")
        status = int(matched.group(2), 10)
        reason = matched.group(3).decode("ascii")
        if not 100 <= status <= 999:
            self._close_conn()
            raise http.client.BadStatusLine("invalid status line")
        return version, status, reason

    def begin(self) -> None:
        if self.headers is not None:
            return
        version, status, reason = self._read_status()
        header_block = _read_bounded_header_block(self.fp)
        if status == http.client.CONTINUE:
            raise http.client.HTTPException(
                "interim supplier-offer responses are unsupported"
            )
        self.code = self.status = status
        self.reason = reason.strip()
        if version in ("HTTP/1.0", "HTTP/0.9"):
            self.version = 10
        elif version.startswith("HTTP/1."):
            self.version = 11
        else:
            raise http.client.UnknownProtocol(version)
        self.headers = self.msg = http.client.parse_headers(
            io.BytesIO(header_block), _class=http.client.HTTPMessage
        )
        transfer_encoding = self.headers.get("transfer-encoding")
        if transfer_encoding and transfer_encoding.strip().lower() == "chunked":
            self.chunked = True
            self.chunk_left = None
        else:
            self.chunked = False
        self.will_close = self._check_close()
        self.length = None
        length = self.headers.get("content-length")
        if length and not self.chunked:
            try:
                self.length = int(length)
            except ValueError:
                self.length = None
            else:
                if self.length < 0:
                    self.length = None
        if (
            status == http.client.NO_CONTENT
            or status == http.client.NOT_MODIFIED
            or 100 <= status < 200
            or self._method == "HEAD"
        ):
            self.length = 0
        if not self.will_close and not self.chunked and self.length is None:
            self.will_close = True

    def _read_next_chunk_size(self) -> int:
        try:
            line = self.fp.readline(65)
        except Exception:
            self._close_conn()
            raise ValueError from None
        if type(line) is not bytes or _CHUNK_SIZE_LINE_RE.fullmatch(line) is None:
            self._close_conn()
            raise ValueError
        size = int(line[:-2], 16)
        if size > self._maximum_body_bytes - self._declared_chunk_bytes:
            self._close_conn()
            raise ValueError
        self._declared_chunk_bytes += size
        return size

    def _read_and_discard_trailer(self) -> None:
        try:
            line = self.fp.readline(3)
        except Exception:
            self._close_conn()
            raise http.client.IncompleteRead(b"") from None
        if line != b"\r\n":
            self._close_conn()
            raise http.client.IncompleteRead(b"")

    def _get_chunk_left(self) -> int | None:
        chunk_left = self.chunk_left
        if not chunk_left:
            if chunk_left is not None:
                try:
                    terminator = self._safe_read(2)
                except http.client.IncompleteRead:
                    self._close_conn()
                    raise
                if terminator != b"\r\n":
                    self._close_conn()
                    raise http.client.IncompleteRead(b"")
            try:
                chunk_left = self._read_next_chunk_size()
            except ValueError:
                raise http.client.IncompleteRead(b"") from None
            if chunk_left == 0:
                self._read_and_discard_trailer()
                self._close_conn()
                chunk_left = None
            self.chunk_left = chunk_left
        return chunk_left


def _validate_headers(response: http.client.HTTPResponse) -> None:
    try:
        defects = response.headers.defects
        raw_headers = list(response.headers.raw_items())
    except Exception:
        raise _fail("supplier-offer response headers are invalid") from None
    if defects:
        raise _fail("supplier-offer response headers are malformed")
    if len(raw_headers) > MAXIMUM_RESPONSE_HEADERS:
        raise _fail("supplier-offer response has too many headers")
    total = 0
    for name, value in raw_headers:
        if (
            type(name) is not str
            or _HEADER_NAME_RE.fullmatch(name) is None
            or type(value) is not str
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise _fail("supplier-offer response headers are invalid")
        try:
            name_bytes = name.encode("ascii", errors="strict")
            value_bytes = value.encode("latin-1", errors="strict")
        except UnicodeError:
            raise _fail("supplier-offer response headers are invalid") from None
        total += len(name_bytes) + len(value_bytes)
        if total > MAXIMUM_RESPONSE_HEADER_BYTES:
            raise _fail("supplier-offer response headers exceed their byte bound")


def _parse_content_length(response: http.client.HTTPResponse) -> int | None:
    values = response.headers.get_all("Content-Length", [])
    if len(values) > 1:
        raise _fail("supplier-offer response has ambiguous Content-Length")
    if not values:
        return None
    value = values[0].strip()
    if not value or _ASCII_DIGITS_RE.fullmatch(value) is None:
        raise _fail("supplier-offer response has invalid Content-Length")
    try:
        length = int(value, 10)
    except (TypeError, ValueError):
        raise _fail("supplier-offer response has invalid Content-Length") from None
    return length


def _close_connection(connection: http.client.HTTPConnection) -> None:
    try:
        connection.close()
    except Exception:
        pass


def _abort_socket(opened: socket.socket | None) -> None:
    if opened is None:
        return
    try:
        opened.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        opened.close()
    except Exception:
        pass


def _response_owned_socket(
    response: http.client.HTTPResponse | None,
) -> socket.socket | None:
    if response is None:
        return None
    try:
        fp = response.fp
        raw = getattr(fp, "raw", fp)
        candidate = getattr(raw, "_sock", None)
    except Exception:
        return None
    return candidate if isinstance(candidate, socket.socket) else None


def _request_with_absolute_deadline(
    connection: http.client.HTTPConnection,
    path: str,
    headers: dict[str, str],
    *,
    maximum_response_bytes: int,
    operation_deadline: float,
    cleanup_deadline: float,
    clock=time.monotonic,
) -> tuple[bytes, int]:
    try:
        outcome: queue.Queue[tuple[str, bytes, int, str]] = queue.Queue(maxsize=1)
        active_socket = connection.sock
        response_lock = threading.Lock()
        response_holder: list[http.client.HTTPResponse | None] = [None]
    except Exception:
        _REQUEST_SLOT.release()
        raise OSError("supplier-offer request worker could not start") from None

    def request_and_read() -> None:
        result = ("failure", b"", 0, "supplier-offer request failed")
        response: http.client.HTTPResponse | None = None
        body = bytearray()
        try:
            _set_socket_timeout(connection, operation_deadline, clock=clock)
            connection.request("GET", path, headers=headers)
            _set_socket_timeout(connection, operation_deadline, clock=clock)
            response = connection.getresponse()
            with response_lock:
                response_holder[0] = response
            _set_socket_timeout(connection, operation_deadline, clock=clock)
            status = response.status
            if type(status) is not int or not 200 <= status < 300:
                raise _fail("supplier-offer endpoint returned a non-success status")
            if status in {204, 205}:
                raise _fail("supplier-offer endpoint returned a bodyless status")
            _validate_headers(response)
            content_types = response.headers.get_all("Content-Type", [])
            content_type = response.headers.get_content_type()
            if len(content_types) != 1 or content_type != "application/json":
                raise _fail("supplier-offer response must declare application/json")
            content_encodings = response.headers.get_all("Content-Encoding", [])
            if len(content_encodings) > 1 or (
                content_encodings
                and content_encodings[0].strip().lower() != "identity"
            ):
                raise _fail("supplier-offer response must use identity encoding")
            transfer_encodings = response.headers.get_all("Transfer-Encoding", [])
            if len(transfer_encodings) > 1:
                raise _fail("supplier-offer response has ambiguous Transfer-Encoding")
            if transfer_encodings:
                if response.version != 11:
                    raise _fail(
                        "supplier-offer response used chunked framing before HTTP/1.1"
                    )
                tokens = [
                    item.strip().lower()
                    for item in transfer_encodings[0].split(",")
                ]
                if tokens != ["chunked"]:
                    raise _fail(
                        "supplier-offer response has unsupported Transfer-Encoding"
                    )
            declared_length = _parse_content_length(response)
            if transfer_encodings and declared_length is not None:
                raise _fail("supplier-offer response framing is ambiguous")
            if declared_length is not None and not (
                1 <= declared_length <= maximum_response_bytes
            ):
                raise _fail("supplier-offer response exceeds its byte bound")
            while len(body) <= maximum_response_bytes:
                size = min(
                    64 * 1024,
                    maximum_response_bytes + 1 - len(body),
                )
                _set_socket_timeout(connection, operation_deadline, clock=clock)
                chunk = response.read(size)
                if not chunk:
                    break
                if type(chunk) is not bytes:
                    raise _fail("supplier-offer response body is invalid")
                body.extend(chunk)
                if len(body) > maximum_response_bytes:
                    raise _fail("supplier-offer response exceeds its byte bound")
            if not body:
                raise _fail("supplier-offer response body is empty")
            if declared_length is not None and len(body) != declared_length:
                raise _fail(
                    "supplier-offer response length did not match Content-Length"
                )
            result = ("success", bytes(body), status, "")
        except _SupplierOfferTransportError as error:
            result = ("failure", b"", 0, str(error))
        except (TimeoutError, socket.timeout):
            result = (
                "timeout",
                b"",
                0,
                "supplier-offer request exceeded its timeout",
            )
        except Exception:
            result = ("failure", b"", 0, "supplier-offer request failed")
        finally:
            with response_lock:
                response_holder[0] = None
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            _close_connection(connection)
            try:
                outcome.put_nowait(result)
            except queue.Full:  # pragma: no cover - one producer
                pass
            finally:
                _REQUEST_SLOT.release()

    try:
        worker = threading.Thread(
            target=request_and_read,
            name="pcbex-supplier-offer-response",
            daemon=True,
        )
        worker.start()
    except Exception:
        _REQUEST_SLOT.release()
        raise OSError("supplier-offer request worker could not start") from None
    try:
        kind, body, status, message = outcome.get(
            timeout=_remaining(operation_deadline, clock)
        )
    except (TimeoutError, queue.Empty):
        with response_lock:
            owned_socket = _response_owned_socket(response_holder[0])
        if owned_socket is not active_socket:
            _abort_socket(owned_socket)
        _abort_socket(active_socket)
        _close_connection(connection)
        try:
            cleanup_remaining = max(0.0, cleanup_deadline - float(clock()))
        except Exception:
            cleanup_remaining = 0.0
        worker.join(timeout=cleanup_remaining)
        raise TimeoutError from None
    if kind == "timeout":
        raise TimeoutError
    if kind != "success":
        raise _fail(message)
    return body, status


def _http_get(
    endpoint_id: str,
    *,
    timeout_seconds: int,
    maximum_response_bytes: int,
    bearer_token: str | None,
    clock=time.monotonic,
) -> tuple[bytes, int]:
    parsed = urlsplit(endpoint_id)
    try:
        start = float(clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("supplier-offer request clock is invalid") from None
    if not start == start or start in {float("inf"), float("-inf")}:
        raise _fail("supplier-offer request clock is invalid")
    outer_deadline = start + timeout_seconds
    cleanup_reserve = min(1.0, timeout_seconds / 4.0)
    operation_deadline = outer_deadline - cleanup_reserve
    resolver_cleanup = cleanup_reserve / 2.0
    connection_type: type[http.client.HTTPConnection] = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    try:
        connection = connection_type(
            parsed.hostname, parsed.port, timeout=_remaining(operation_deadline, clock)
        )

        def response_factory(
            opened: socket.socket,
            debuglevel: int = 0,
            method: str | None = None,
            url: str | None = None,
        ) -> _BoundedHTTPResponse:
            return _BoundedHTTPResponse(
                opened,
                debuglevel=debuglevel,
                method=method,
                url=url,
                maximum_body_bytes=maximum_response_bytes,
            )

        connection.response_class = response_factory
    except (TypeError, ValueError, OSError, TimeoutError):
        raise _fail("supplier-offer connection could not be created") from None
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    if bearer_token is not None:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request_slot_held = False
    try:
        try:
            if not _REQUEST_SLOT.acquire(
                timeout=_remaining(operation_deadline, clock)
            ):
                raise TimeoutError
            request_slot_held = True
            hostname = parsed.hostname
            if hostname is None:
                raise OSError
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            resolved = _resolve_endpoint(
                hostname,
                port,
                operation_deadline,
                cleanup_timeout_seconds=resolver_cleanup,
                bearer_token=bearer_token,
                clock=clock,
            )
            _install_resolved_socket_factory(
                connection, resolved, operation_deadline, clock=clock
            )
            _connect_with_deadline(connection, operation_deadline, clock=clock)
            # The response worker now owns the transaction slot and releases
            # it only after closing its response/socket, including after a
            # caller-visible timeout.
            request_slot_held = False
            body, status = _request_with_absolute_deadline(
                connection,
                parsed.path or "/",
                headers,
                maximum_response_bytes=maximum_response_bytes,
                operation_deadline=operation_deadline,
                cleanup_deadline=outer_deadline,
                clock=clock,
            )
        except (TimeoutError, socket.timeout):
            raise _fail("supplier-offer request exceeded its timeout") from None
        except (OSError, http.client.HTTPException):
            raise _fail("supplier-offer request failed") from None
    finally:
        if request_slot_held:
            _REQUEST_SLOT.release()
        _close_connection(connection)
    try:
        _remaining(outer_deadline, clock)
    except TimeoutError:
        raise _fail("supplier-offer request exceeded its timeout") from None
    return body, status


__all__: list[str] = []

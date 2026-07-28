from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

from .review import ReviewError, review_schematic_with_llm

MAXIMUM_REQUEST_BYTES = 32 * 1024 * 1024
MAXIMUM_PROVIDER_OUTPUT_BYTES = 16 * 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600


class ProviderError(RuntimeError):
    pass


def provider_receipt_json_schema() -> dict[str, Any]:
    descriptor = {
        "type": "object",
        "additionalProperties": False,
        "required": ["path", "bytes", "sha256"],
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "bytes": {"type": "integer", "minimum": 0},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/"
            "schema/provider-command-receipt-v1.json"
        ),
        "title": "pcbex provider-command receipt",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "adapter",
            "provider_executable",
            "command_argv_sha256",
            "request",
            "response",
            "timeout_seconds",
            "maximum_output_bytes",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": "provider-command-v1"},
            "provider_executable": {"type": "string", "minLength": 1},
            "command_argv_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "request": descriptor,
            "response": descriptor,
            "timeout_seconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_TIMEOUT_SECONDS,
            },
            "maximum_output_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_PROVIDER_OUTPUT_BYTES,
            },
        },
    }


def review_schematic_with_command(
    request_path: Path,
    output_path: Path,
    receipt_path: Path,
    command: list[str],
    *,
    timeout_seconds: int = 120,
    max_output_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    """Run one bounded, shell-free provider adapter and atomically retain evidence."""
    if not command or not command[0].strip():
        raise ProviderError("provider command must not be empty")
    if output_path == receipt_path:
        raise ProviderError("response and receipt paths must differ")
    if output_path.exists() or receipt_path.exists():
        raise ProviderError("provider adapter refuses to overwrite response or receipt")
    if not 1 <= timeout_seconds <= MAXIMUM_TIMEOUT_SECONDS:
        raise ProviderError(
            f"timeout must be between 1 and {MAXIMUM_TIMEOUT_SECONDS} seconds"
        )
    if not 1 <= max_output_bytes <= MAXIMUM_PROVIDER_OUTPUT_BYTES:
        raise ProviderError(
            "maximum output must be between 1 and "
            f"{MAXIMUM_PROVIDER_OUTPUT_BYTES} bytes"
        )
    request_bytes = request_path.read_bytes()
    if len(request_bytes) > MAXIMUM_REQUEST_BYTES:
        raise ProviderError(
            f"AI review request exceeds {MAXIMUM_REQUEST_BYTES} bytes"
        )
    try:
        request = json.loads(request_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProviderError(f"invalid AI review request JSON: {error}") from error
    if not isinstance(request, dict):
        raise ProviderError("AI review request must be a JSON object")

    response = review_schematic_with_llm(
        request,
        lambda prompt: _run_provider(
            command,
            prompt,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        ),
    )
    response_bytes = (
        json.dumps(response, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    receipt = {
        "schema_version": 1,
        "adapter": "provider-command-v1",
        "provider_executable": Path(command[0]).name,
        "command_argv_sha256": _sha256(
            json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
        "request": _descriptor(request_path, request_bytes),
        "response": _descriptor(output_path, response_bytes),
        "timeout_seconds": timeout_seconds,
        "maximum_output_bytes": max_output_bytes,
    }
    receipt_bytes = (
        json.dumps(receipt, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    _atomic_write_new(output_path, response_bytes)
    try:
        _atomic_write_new(receipt_path, receipt_bytes)
    except Exception:
        output_path.unlink(missing_ok=True)
        raise
    return receipt


def _run_provider(
    command: list[str],
    prompt: str,
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> str:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as error:
        raise ProviderError(f"starting provider command: {error}") from error

    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    streams = [
        threading.Thread(
            target=_read_bounded,
            args=(process.stdout, stdout, max_output_bytes, overflow, process),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded,
            args=(process.stderr, stderr, max_output_bytes, overflow, process),
            daemon=True,
        ),
    ]
    for thread in streams:
        thread.start()
    writer = threading.Thread(
        target=_write_prompt,
        args=(process.stdin, prompt.encode("utf-8")),
        daemon=True,
    )
    writer.start()
    try:
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            raise ProviderError(
                f"provider command exceeded {timeout_seconds} second timeout"
            ) from error
    finally:
        writer.join(timeout=2)
        for thread in streams:
            thread.join(timeout=2)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    if overflow.is_set():
        raise ProviderError(
            f"provider stdout or stderr exceeded {max_output_bytes} bytes"
        )
    if return_code != 0:
        detail = stderr[:4096].decode("utf-8", errors="replace").strip()
        if len(stderr) > 4096:
            detail += "…"
        raise ProviderError(
            f"provider command exited with {return_code}"
            + (f": {detail}" if detail else "")
        )
    try:
        return stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProviderError("provider stdout is not valid UTF-8") from error


def _read_bounded(
    stream: Any,
    destination: bytearray,
    limit: int,
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    if stream is None:
        return
    while chunk := stream.read(65536):
        remaining = limit - len(destination)
        destination.extend(chunk[: max(remaining, 0)])
        if len(chunk) > remaining:
            overflow.set()
            process.kill()
            return


def _write_prompt(stream: Any, prompt: bytes) -> None:
    if stream is None:
        return
    try:
        stream.write(prompt)
        stream.flush()
    except BrokenPipeError:
        pass
    finally:
        stream.close()


def _descriptor(path: Path, value: bytes) -> dict[str, Any]:
    return {
        "path": path.as_posix(),
        "bytes": len(value),
        "sha256": _sha256(value),
    }


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_write_new(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        temporary.unlink()
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

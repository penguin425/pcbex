from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .bounded_io import (
    BoundedIOError,
    atomic_write_no_clobber,
    read_bytes,
    validate_no_clobber_path,
)
from .bounded_process import (
    BoundedProcessError,
    InvalidProcessArguments,
    ProcessInputLimitExceeded,
    ProcessOutputLimitExceeded,
    ProcessSpawnError,
    ProcessTimeout,
    run_bounded,
)
from .review import review_schematic_with_llm

MAXIMUM_REQUEST_BYTES = 32 * 1024 * 1024
MAXIMUM_PROVIDER_PROMPT_BYTES = 32 * 1024 * 1024
MAXIMUM_PROVIDER_OUTPUT_BYTES = 16 * 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600
_PROMPT_VALIDATION_CHUNK_CHARACTERS = 64 * 1024


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
    _preflight_new_artifacts(
        output_path,
        receipt_path,
        refusal="provider adapter refuses to overwrite response or receipt",
    )
    if not 1 <= timeout_seconds <= MAXIMUM_TIMEOUT_SECONDS:
        raise ProviderError(
            f"timeout must be between 1 and {MAXIMUM_TIMEOUT_SECONDS} seconds"
        )
    if not 1 <= max_output_bytes <= MAXIMUM_PROVIDER_OUTPUT_BYTES:
        raise ProviderError(
            "maximum output must be between 1 and "
            f"{MAXIMUM_PROVIDER_OUTPUT_BYTES} bytes"
        )
    try:
        request_bytes = read_bytes(request_path, max_bytes=MAXIMUM_REQUEST_BYTES)
    except BoundedIOError as error:
        raise ProviderError(f"reading AI review request: {error}") from error
    try:
        request = json.loads(request_bytes.decode("utf-8", errors="strict"))
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
    # The two artifacts are independently atomic, not a filesystem
    # transaction.  If receipt publication fails, retain the already-published
    # response: deleting it here could race with another path replacement and
    # remove an object that this invocation did not create.
    _atomic_write_new(receipt_path, receipt_bytes)
    return receipt


def _run_provider(
    command: list[str],
    prompt: str,
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> str:
    prompt_bytes = _encode_provider_prompt(prompt)
    try:
        completed = run_bounded(
            command,
            input_bytes=prompt_bytes,
            timeout_seconds=timeout_seconds,
            max_stdin_bytes=MAXIMUM_PROVIDER_PROMPT_BYTES,
            max_stdout_bytes=max_output_bytes,
            max_stderr_bytes=max_output_bytes,
        )
    except (InvalidProcessArguments, ProcessSpawnError) as error:
        raise ProviderError(f"starting provider command: {error}") from error
    except ProcessTimeout as error:
        raise ProviderError(
            f"provider command exceeded {timeout_seconds} second timeout"
        ) from error
    except ProcessInputLimitExceeded as error:
        raise ProviderError(
            "provider prompt exceeded "
            f"{MAXIMUM_PROVIDER_PROMPT_BYTES} bytes"
        ) from error
    except ProcessOutputLimitExceeded as error:
        raise ProviderError(
            f"provider stdout or stderr exceeded {max_output_bytes} bytes"
        ) from error
    except BoundedProcessError as error:
        raise ProviderError(f"running provider command: {error}") from error

    if completed.returncode != 0:
        diagnostic = completed.stderr if completed.stderr else completed.stdout
        detail = diagnostic[:4096].decode("utf-8", errors="replace").strip()
        if len(diagnostic) > 4096:
            detail += "…"
        raise ProviderError(
            f"provider command exited with {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProviderError("provider stdout is not valid UTF-8") from error


def _descriptor(path: Path, value: bytes) -> dict[str, Any]:
    return {
        "path": path.as_posix(),
        "bytes": len(value),
        "sha256": _sha256(value),
    }


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_provider_prompt(prompt: str) -> None:
    """Reject an oversized/invalid UTF-8 prompt before allocating its bytes."""

    total = 0
    try:
        for offset in range(0, len(prompt), _PROMPT_VALIDATION_CHUNK_CHARACTERS):
            chunk = prompt[offset : offset + _PROMPT_VALIDATION_CHUNK_CHARACTERS]
            total += len(chunk.encode("utf-8", errors="strict"))
            if total > MAXIMUM_PROVIDER_PROMPT_BYTES:
                raise ProviderError(
                    "provider prompt exceeded "
                    f"{MAXIMUM_PROVIDER_PROMPT_BYTES} bytes"
                )
    except UnicodeEncodeError as error:
        raise ProviderError("provider prompt is not valid UTF-8") from error


def _encode_provider_prompt(prompt: str) -> bytes:
    _validate_provider_prompt(prompt)
    return prompt.encode("utf-8", errors="strict")


def _preflight_new_artifacts(
    output_path: Path,
    receipt_path: Path,
    *,
    refusal: str,
) -> None:
    """Reject unsafe/existing targets before a provider is contacted."""

    if os.path.normcase(os.path.abspath(output_path)) == os.path.normcase(
        os.path.abspath(receipt_path)
    ):
        raise ProviderError("response and receipt paths must differ")
    for path in (output_path, receipt_path):
        try:
            validate_no_clobber_path(path)
        except BoundedIOError as error:
            if error.errno == errno.EEXIST:
                raise ProviderError(refusal) from error
            raise ProviderError(f"validating provider artifact path: {error}") from error


def _atomic_write_new(path: Path, value: bytes) -> None:
    try:
        atomic_write_no_clobber(
            path,
            value,
            max_bytes=MAXIMUM_PROVIDER_OUTPUT_BYTES,
        )
    except BoundedIOError as error:
        raise ProviderError(f"writing provider artifact: {error}") from error

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import urllib.parse
import time
from pathlib import Path
from typing import Any

from .bounded_io import BoundedIOError, read_bytes
from .provider import (
    MAXIMUM_PROVIDER_OUTPUT_BYTES,
    MAXIMUM_REQUEST_BYTES,
    MAXIMUM_TIMEOUT_SECONDS,
    ProviderError,
    _atomic_write_new,
    _descriptor,
    _preflight_new_artifacts,
    _validate_provider_prompt,
)
from .review import review_schematic_with_llm

DEFAULT_ENDPOINTS = {
    "openai": "https://api.openai.com/v1/responses",
    "anthropic": "https://api.anthropic.com/v1/messages",
}
DEFAULT_KEY_ENVIRONMENTS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
}
PROVIDERS = frozenset(DEFAULT_KEY_ENVIRONMENTS)
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAXIMUM_MANAGED_PROVIDER_REQUEST_BYTES = 64 * 1024 * 1024


def managed_provider_receipt_json_schema() -> dict[str, Any]:
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
    payload_descriptor = {
        "type": "object",
        "additionalProperties": False,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 0},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/"
            "schema/managed-provider-receipt-v1.json"
        ),
        "title": "pcbex managed AI provider receipt",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "adapter",
            "provider",
            "model",
            "model_version",
            "endpoint",
            "request",
            "provider_request",
            "provider_response",
            "response",
            "timeout_seconds",
            "maximum_response_bytes",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": "managed-provider-http-v1"},
            "provider": {"enum": sorted(PROVIDERS)},
            "model": {"type": "string", "minLength": 1},
            "model_version": {
                "type": ["string", "null"],
                "minLength": 1,
            },
            "endpoint": {"type": "string", "format": "uri"},
            "request": descriptor,
            "provider_request": payload_descriptor,
            "provider_response": payload_descriptor,
            "response": descriptor,
            "timeout_seconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_TIMEOUT_SECONDS,
            },
            "maximum_response_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_PROVIDER_OUTPUT_BYTES,
            },
        },
    }


def review_schematic_with_managed_provider(
    request_path: Path,
    output_path: Path,
    receipt_path: Path,
    *,
    provider: str,
    model: str,
    model_version: str | None = None,
    api_key_environment: str | None = None,
    endpoint: str | None = None,
    timeout_seconds: int = 120,
    max_response_bytes: int = 1024 * 1024,
    max_output_tokens: int = 4096,
    allow_insecure_loopback: bool = False,
) -> dict[str, Any]:
    """Call one supported API and retain only normalized output and digests."""
    provider = provider.strip().lower()
    model = model.strip()
    if provider not in PROVIDERS:
        raise ProviderError(f"unsupported managed provider: {provider}")
    if not model:
        raise ProviderError("provider model must not be empty")
    if model_version is not None and not model_version.strip():
        raise ProviderError("provider model version must not be blank")
    if output_path == receipt_path:
        raise ProviderError("response and receipt paths must differ")
    _preflight_new_artifacts(
        output_path,
        receipt_path,
        refusal="managed provider refuses to overwrite response or receipt",
    )
    if not 1 <= timeout_seconds <= MAXIMUM_TIMEOUT_SECONDS:
        raise ProviderError(
            f"timeout must be between 1 and {MAXIMUM_TIMEOUT_SECONDS} seconds"
        )
    if not 1 <= max_response_bytes <= MAXIMUM_PROVIDER_OUTPUT_BYTES:
        raise ProviderError(
            "maximum response must be between 1 and "
            f"{MAXIMUM_PROVIDER_OUTPUT_BYTES} bytes"
        )
    if not 1 <= max_output_tokens <= 1_000_000:
        raise ProviderError("maximum output tokens must be between 1 and 1000000")

    key_environment = api_key_environment or DEFAULT_KEY_ENVIRONMENTS[provider]
    if not _ENVIRONMENT_NAME.fullmatch(key_environment):
        raise ProviderError("API key environment name is invalid")
    api_key = os.environ.get(key_environment)
    if api_key is None or not api_key.strip():
        raise ProviderError(f"API key environment {key_environment} is not set")

    resolved_endpoint = endpoint or _default_endpoint(provider, model)
    _validate_endpoint(
        resolved_endpoint,
        allow_insecure_loopback=allow_insecure_loopback,
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

    exchange: dict[str, bytes] = {}

    def transport(prompt: str) -> str:
        _validate_provider_prompt(prompt)
        provider_request = _provider_request(
            provider,
            model,
            prompt,
            max_output_tokens=max_output_tokens,
        )
        encoded_request = _encode_bounded_provider_request(provider_request)
        raw_response = _post_json(
            resolved_endpoint,
            encoded_request,
            provider=provider,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        exchange["request"] = encoded_request
        exchange["response"] = raw_response
        structured = _extract_structured_response(provider, raw_response)
        try:
            parsed = json.loads(structured)
        except (TypeError, json.JSONDecodeError) as error:
            raise ProviderError(
                f"{provider} did not return valid structured JSON: {error}"
            ) from error
        if not isinstance(parsed, dict):
            raise ProviderError(f"{provider} structured response must be an object")
        parsed["model"] = {
            "provider": provider,
            "model": model,
            "version": model_version,
        }
        return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))

    response = review_schematic_with_llm(request, transport)
    response_bytes = (
        json.dumps(response, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    receipt = {
        "schema_version": 1,
        "adapter": "managed-provider-http-v1",
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "endpoint": resolved_endpoint,
        "request": _descriptor(request_path, request_bytes),
        "provider_request": _payload_descriptor(exchange["request"]),
        "provider_response": _payload_descriptor(exchange["response"]),
        "response": _descriptor(output_path, response_bytes),
        "timeout_seconds": timeout_seconds,
        "maximum_response_bytes": max_response_bytes,
    }
    receipt_bytes = (
        json.dumps(receipt, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    _atomic_write_new(output_path, response_bytes)
    # These are per-file atomic publications rather than a multi-file
    # transaction.  Retain a successfully-published response if the receipt
    # cannot be published; rollback-by-unlink can remove a concurrently
    # replaced object.
    _atomic_write_new(receipt_path, receipt_bytes)
    return receipt


def _encode_bounded_provider_request(request: dict[str, Any]) -> bytes:
    """Encode one managed-provider body without retaining bytes past its cap."""

    encoder = json.JSONEncoder(
        ensure_ascii=False,
        separators=(",", ":"),
    )
    chunks: list[bytes] = []
    total = 0
    try:
        for text in encoder.iterencode(request):
            encoded = text.encode("utf-8", errors="strict")
            total += len(encoded)
            if total > MAXIMUM_MANAGED_PROVIDER_REQUEST_BYTES:
                raise ProviderError(
                    "managed provider request exceeded "
                    f"{MAXIMUM_MANAGED_PROVIDER_REQUEST_BYTES} bytes"
                )
            chunks.append(encoded)
    except UnicodeEncodeError as error:
        raise ProviderError("managed provider request is not valid UTF-8") from error
    return b"".join(chunks)


def _default_endpoint(provider: str, model: str) -> str:
    if provider == "gemini":
        encoded_model = urllib.parse.quote(model, safe="-._")
        return (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{encoded_model}:generateContent"
        )
    return DEFAULT_ENDPOINTS[provider]


def _validate_endpoint(url: str, *, allow_insecure_loopback: bool) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise ProviderError(f"invalid provider endpoint: {error}") from error
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or port == 0
    ):
        raise ProviderError(
            "provider endpoint must be an absolute URL without credentials, "
            "query, or fragment"
        )
    if parsed.scheme == "https":
        return
    if (
        allow_insecure_loopback
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        return
    raise ProviderError("provider endpoint must use HTTPS")


def _provider_request(
    provider: str,
    model: str,
    prompt: str,
    *,
    max_output_tokens: int,
) -> dict[str, Any]:
    schema = _review_response_schema()
    if provider == "openai":
        return {
            "model": model,
            "input": prompt,
            "max_output_tokens": max_output_tokens,
            "store": False,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "pcbex_schematic_review",
                    "strict": True,
                    "schema": schema,
                }
            },
        }
    if provider == "anthropic":
        return {
            "model": model,
            "max_tokens": max_output_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "output_config": {
                "format": {
                    "type": "json_schema",
                    "schema": schema,
                }
            },
        }
    return {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseFormat": {
                "text": {
                    "mimeType": "application/json",
                    "schema": schema,
                }
            },
            "maxOutputTokens": max_output_tokens,
        },
    }


def _review_response_schema() -> dict[str, Any]:
    evidence_refs = {
        "type": "array",
        "minItems": 1,
        "uniqueItems": True,
        "items": {"type": "string"},
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "request_sha256",
            "model",
            "decision",
            "summary",
            "requirements",
            "risks",
        ],
        "properties": {
            "schema_version": {"type": "integer", "enum": [1]},
            "request_sha256": {"type": "string"},
            "model": {
                "type": "object",
                "additionalProperties": False,
                "required": ["provider", "model", "version"],
                "properties": {
                    "provider": {"type": "string"},
                    "model": {"type": "string"},
                    "version": {"type": ["string", "null"]},
                },
            },
            "decision": {
                "type": "string",
                "enum": ["approve", "reject", "needs_human"],
            },
            "summary": {"type": "string"},
            "requirements": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["id", "status", "rationale", "evidence_refs"],
                    "properties": {
                        "id": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": ["pass", "fail", "unknown"],
                        },
                        "rationale": {"type": "string"},
                        "evidence_refs": evidence_refs,
                    },
                },
            },
            "risks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "id",
                        "severity",
                        "title",
                        "rationale",
                        "evidence_refs",
                    ],
                    "properties": {
                        "id": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["info", "warning", "error", "critical"],
                        },
                        "title": {"type": "string"},
                        "rationale": {"type": "string"},
                        "evidence_refs": evidence_refs,
                    },
                },
            },
        },
    }


def _post_json(
    endpoint: str,
    body: bytes,
    *,
    provider: str,
    api_key: str,
    timeout_seconds: int,
    max_response_bytes: int,
) -> bytes:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "pcbex-agent/managed-provider-http-v1",
    }
    if provider == "openai":
        headers["Authorization"] = f"Bearer {api_key}"
    elif provider == "anthropic":
        headers["x-api-key"] = api_key
        headers["anthropic-version"] = "2023-06-01"
    else:
        headers["x-goog-api-key"] = api_key
    parsed = urllib.parse.urlsplit(endpoint)
    connection_type = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    connection = connection_type(
        parsed.hostname,
        parsed.port,
        timeout=timeout_seconds,
    )
    deadline = time.monotonic() + timeout_seconds

    def apply_remaining_timeout() -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        if connection.sock is not None:
            connection.sock.settimeout(remaining)

    try:
        connection.connect()
        apply_remaining_timeout()
        connection.request("POST", parsed.path, body=body, headers=headers)
        apply_remaining_timeout()
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise ProviderError(
                f"{provider} API returned HTTP {response.status}"
            )
        content_type = response.headers.get_content_type()
        if content_type != "application/json":
            raise ProviderError(
                f"{provider} returned unsupported content type {content_type}"
            )
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                if int(declared) > max_response_bytes:
                    raise ProviderError(
                        f"{provider} response exceeds {max_response_bytes} bytes"
                    )
            except ValueError as error:
                raise ProviderError(
                    f"{provider} returned invalid Content-Length"
                ) from error
        chunks = bytearray()
        while len(chunks) <= max_response_bytes:
            apply_remaining_timeout()
            chunk = response.read(min(65536, max_response_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
    except TimeoutError as error:
        raise ProviderError(
            f"{provider} API exceeded {timeout_seconds} second timeout"
        ) from error
    except (OSError, http.client.HTTPException) as error:
        raise ProviderError(f"{provider} API request failed: {error}") from error
    finally:
        connection.close()
    if len(chunks) > max_response_bytes:
        raise ProviderError(f"{provider} response exceeds {max_response_bytes} bytes")
    return bytes(chunks)


def _extract_structured_response(provider: str, raw: bytes) -> str:
    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProviderError(f"{provider} response is not valid JSON: {error}") from error
    if not isinstance(envelope, dict):
        raise ProviderError(f"{provider} response envelope must be an object")
    if provider == "openai":
        if envelope.get("status") != "completed":
            raise ProviderError("openai response did not complete")
        output = envelope.get("output")
        if not isinstance(output, list):
            raise ProviderError("openai response has no output")
        texts = [
            content.get("text")
            for item in output
            if isinstance(item, dict) and item.get("type") == "message"
            for content in item.get("content", [])
            if isinstance(content, dict) and content.get("type") == "output_text"
        ]
    elif provider == "anthropic":
        if envelope.get("stop_reason") != "end_turn":
            raise ProviderError("anthropic response did not end normally")
        content = envelope.get("content")
        if not isinstance(content, list):
            raise ProviderError("anthropic response has no content")
        texts = [
            item.get("text")
            for item in content
            if isinstance(item, dict) and item.get("type") == "text"
        ]
    else:
        candidates = envelope.get("candidates")
        if not isinstance(candidates, list) or len(candidates) != 1:
            raise ProviderError("gemini response must contain exactly one candidate")
        candidate = candidates[0]
        if (
            not isinstance(candidate, dict)
            or candidate.get("finishReason") != "STOP"
            or not isinstance(candidate.get("content"), dict)
        ):
            raise ProviderError("gemini response did not finish normally")
        parts = candidate["content"].get("parts")
        if not isinstance(parts, list):
            raise ProviderError("gemini response has no content parts")
        texts = [
            part.get("text")
            for part in parts
            if isinstance(part, dict) and set(part) == {"text"}
        ]
    if len(texts) != 1 or not isinstance(texts[0], str):
        raise ProviderError(
            f"{provider} response must contain exactly one structured text output"
        )
    return texts[0]


def _payload_descriptor(value: bytes) -> dict[str, Any]:
    return {
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }

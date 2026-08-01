"""Bounded HTTPS factory submission and DFM receipt normalization."""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class FactorySubmissionError(ValueError):
    """Raised when a factory submission cannot be safely normalized."""


@dataclass(frozen=True)
class FactoryEndpoint:
    provider: str
    endpoint: str
    bearer_token_environment: str | None = None
    timeout_seconds: int = 300
    allow_http_loopback: bool = False


def factory_submission_json_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/factory-submission-v1.json",
        "title": "pcbex bounded factory submission receipt",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version", "adapter", "provider", "endpoint", "package_sha256",
            "package_bytes", "request_sha256", "response_sha256", "response_bytes",
            "http_status", "status", "accepted", "dfm_passed", "quote", "findings", "response",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": "factory-http-v1"},
            "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
            "endpoint": {"type": "string", "pattern": "^https://"},
            "package_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "package_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PACKAGE_BYTES},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES},
            "http_status": {"type": "integer", "minimum": 200, "maximum": 299},
            "status": {"type": "string"}, "accepted": {"type": "boolean"},
            "dfm_passed": {"type": ["boolean", "null"]},
            "quote": {"type": ["object", "null"]},
            "findings": {"type": "array", "items": {"$ref": "#/$defs/finding"}},
            "response": {"type": "object"},
        },
        "$defs": {
            "finding": {
                "type": "object", "additionalProperties": False,
                "required": ["code", "severity", "message"],
                "properties": {
                    "code": {"type": ["string", "null"]},
                    "severity": {"type": "string"},
                    "message": {"type": "string"},
                },
            },
        },
    }


def _validate_endpoint(config: FactoryEndpoint) -> None:
    if config.provider.strip().lower() not in {"jlcpcb", "pcbway", "generic"}:
        raise FactorySubmissionError("factory provider must be jlcpcb, pcbway, or generic")
    if not 1 <= config.timeout_seconds <= 600:
        raise FactorySubmissionError("factory timeout must be between 1 and 600 seconds")
    parsed = urlsplit(config.endpoint)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if not (parsed.scheme == "https" or (config.allow_http_loopback and parsed.scheme == "http" and loopback)):
        raise FactorySubmissionError("factory endpoint must use HTTPS")
    if not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise FactorySubmissionError("factory endpoint must not contain userinfo, query, or fragment")


def _normalize_response(value: Mapping[str, Any]) -> tuple[str, bool, bool | None, Any, list[dict[str, Any]]]:
    status = str(value.get("status") or "unknown").strip()
    accepted = value.get("accepted")
    if not isinstance(accepted, bool):
        accepted = status.lower() in {"accepted", "quoted", "success", "ok", "pass", "passed"}
    dfm = value.get("dfm_passed")
    if not isinstance(dfm, bool) and isinstance(value.get("dfm"), Mapping):
        dfm = value["dfm"].get("passed")
    if not isinstance(dfm, bool):
        dfm = None
    raw_findings = value.get("dfm_findings", value.get("findings", []))
    if not isinstance(raw_findings, list):
        raise FactorySubmissionError("factory findings must be an array")
    findings = []
    for item in raw_findings:
        if not isinstance(item, Mapping):
            raise FactorySubmissionError("factory finding must be an object")
        severity = str(item.get("severity") or "warning").lower()
        findings.append({
            "code": item.get("code", item.get("id")),
            "severity": severity,
            "message": str(item.get("message") or "factory DFM finding"),
        })
    findings.sort(key=lambda item: (item["severity"], item["code"] or "", item["message"]))
    quote = value.get("quote")
    if quote is not None and not isinstance(quote, Mapping):
        raise FactorySubmissionError("factory quote must be an object or null")
    return status, accepted, dfm, quote, findings


def submit_factory_package(package: Path, config: FactoryEndpoint) -> dict[str, Any]:
    """Submit a manufacturing ZIP and return a digest-bound normalized receipt."""

    _validate_endpoint(config)
    metadata = package.stat()
    if not package.is_file() or metadata.st_size == 0 or metadata.st_size > MAX_PACKAGE_BYTES:
        raise FactorySubmissionError(f"factory package must contain 1 to {MAX_PACKAGE_BYTES} bytes")
    body = package.read_bytes()
    package_sha = hashlib.sha256(body).hexdigest()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/zip",
        "User-Agent": "pcbex-agent/factory-http-v1",
        "X-PCBEX-Adapter": f"{config.provider.lower()}-http-v1",
        "X-PCBEX-Package-SHA256": package_sha,
    }
    if config.bearer_token_environment:
        token = os.environ.get(config.bearer_token_environment)
        if not token or not token.strip():
            raise FactorySubmissionError(
                f"factory bearer-token environment {config.bearer_token_environment} is unset or empty"
            )
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(config.endpoint, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=config.timeout_seconds) as response:
            if not 200 <= response.status <= 299:
                raise FactorySubmissionError(f"factory returned HTTP {response.status}")
            if response.headers.get_content_type() != "application/json":
                raise FactorySubmissionError("factory response Content-Type must be application/json")
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
    except urllib.error.HTTPError as error:
        raise FactorySubmissionError(f"factory HTTP request failed: {error.code}") from error
    except urllib.error.URLError as error:
        raise FactorySubmissionError(f"factory request failed: {error.reason}") from error
    if not response_body or len(response_body) > MAX_RESPONSE_BYTES:
        raise FactorySubmissionError(f"factory response must contain 1 to {MAX_RESPONSE_BYTES} bytes")
    try:
        value = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FactorySubmissionError(f"factory response is not UTF-8 JSON: {error}") from error
    if not isinstance(value, Mapping):
        raise FactorySubmissionError("factory response must be a JSON object")
    normalized_status, accepted, dfm_passed, quote, findings = _normalize_response(value)
    response_sha = hashlib.sha256(response_body).hexdigest()
    return {
        "schema_version": 1,
        "adapter": "factory-http-v1",
        "provider": config.provider.lower(),
        "endpoint": config.endpoint,
        "package_sha256": package_sha,
        "package_bytes": len(body),
        "request_sha256": package_sha,
        "response_sha256": response_sha,
        "response_bytes": len(response_body),
        "http_status": status,
        "status": normalized_status,
        "accepted": accepted,
        "dfm_passed": dfm_passed,
        "quote": quote,
        "findings": findings,
        "response": dict(value),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise FactorySubmissionError("factory endpoint redirects are not allowed")

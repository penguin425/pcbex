"""Bounded HTTPS catalog adapters for live supplier inventory."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .catalog import CatalogPart, catalog_parts_from_json, search_parts

MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class CatalogRemoteError(ValueError):
    """Raised when a supplier catalog cannot be fetched or normalized."""


@dataclass(frozen=True)
class CatalogEndpoint:
    provider: str
    endpoint: str
    bearer_token_environment: str | None = None
    timeout_seconds: float = 20.0
    allow_http_loopback: bool = False


def fetch_catalog(config: CatalogEndpoint) -> list[CatalogPart]:
    """Fetch and normalize a bounded vendor-neutral supplier response.

    The endpoint contract is intentionally small: either a JSON array of
    catalog parts or an object containing that array under ``parts``. Supplier
    gateways can translate their native API into this contract without tying
    pcbex's deterministic selector to unstable vendor response shapes.
    """
    provider = config.provider.strip().lower()
    if provider not in {"jlcpcb", "digikey", "lcsc", "generic"}:
        raise CatalogRemoteError(
            "catalog provider must be one of: jlcpcb, digikey, lcsc, generic"
        )
    validate_endpoint(config)
    if not 0.1 <= config.timeout_seconds <= 120:
        raise CatalogRemoteError("catalog timeout_seconds must be between 0.1 and 120")
    token = None
    if config.bearer_token_environment:
        _validate_env_name(config.bearer_token_environment)
        token = os.environ.get(config.bearer_token_environment)
        if not token or not token.strip():
            raise CatalogRemoteError(
                f"catalog bearer-token environment {config.bearer_token_environment} is unset or empty"
            )
    request = urllib.request.Request(
        config.endpoint,
        headers={
            "Accept": "application/json",
            "User-Agent": "pcbex-agent/1",
            "X-PCBEX-Catalog-Provider": provider,
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=config.timeout_seconds) as response:
            if response.status != 200:
                raise CatalogRemoteError(
                    f"catalog endpoint returned unexpected HTTP status {response.status}"
                )
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise CatalogRemoteError(
                    f"catalog response Content-Type must be application/json, got {content_type!r}"
                )
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise CatalogRemoteError(f"catalog HTTP request failed: {error.code}") from error
    except urllib.error.URLError as error:
        raise CatalogRemoteError(f"catalog request failed: {error.reason}") from error
    if not body or len(body) > MAX_RESPONSE_BYTES:
        raise CatalogRemoteError(
            f"catalog response must contain 1 to {MAX_RESPONSE_BYTES} bytes"
        )
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogRemoteError(f"catalog response is not UTF-8 JSON: {error}") from error
    if isinstance(value, dict):
        value = value.get("parts")
    if not isinstance(value, list):
        raise CatalogRemoteError("catalog response must be an array or an object with parts")
    normalized = [_normalize_part(item, provider) for item in value]
    return catalog_parts_from_json(normalized)


def search_remote_parts(
    config: CatalogEndpoint,
    query: str,
    *,
    footprint: str | None = None,
    limit: int = 10,
    require_available: bool = False,
    require_basic: bool = False,
) -> list[CatalogPart]:
    return search_parts(
        fetch_catalog(config),
        query,
        footprint=footprint,
        limit=limit,
        require_available=require_available,
        require_basic=require_basic,
    )


def validate_endpoint(config: CatalogEndpoint) -> None:
    parsed = urlsplit(config.endpoint)
    if parsed.scheme == "https":
        pass
    elif config.allow_http_loopback and parsed.scheme == "http" and parsed.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        pass
    else:
        raise CatalogRemoteError("catalog endpoint must use HTTPS")
    if not parsed.netloc or parsed.username or parsed.password:
        raise CatalogRemoteError("catalog endpoint must have authority and no userinfo")
    if parsed.query or parsed.fragment:
        raise CatalogRemoteError("catalog endpoint must not contain query or fragment")


def _normalize_part(value: Any, provider: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogRemoteError("catalog part must be an object")
    provider = provider.strip().lower()
    if provider == "digikey":
        mpn_keys = (
            "mpn", "manufacturer_part_number", "ManufacturerPartNumber",
            "part_number", "DigiKeyPartNumber", "ProductNumber",
        )
        description_keys = ("description", "Description", "comment", "value")
        footprint_keys = ("footprint", "package", "PackageType", "package_type")
        stock_keys = ("stock", "quantity", "inventory", "QuantityAvailable", "quantity_available")
        basic_keys = ("basic", "isBasic", "is_basic")
    elif provider == "lcsc":
        mpn_keys = (
            "mpn", "part_number", "partNumber", "manufacturer_part_number",
            "product_code", "productCode", "lcsc_part",
        )
        description_keys = ("description", "comment", "value", "productName", "product_name")
        footprint_keys = ("footprint", "package", "packageType", "package_type")
        stock_keys = ("stock", "quantity", "inventory", "stockQty", "stock_quantity")
        basic_keys = ("basic", "isBasic", "is_basic", "jlcpcbBasic")
    else:
        mpn_keys = ("mpn", "part_number", "manufacturer_part_number")
        description_keys = ("description", "comment", "value")
        footprint_keys = ("footprint", "package")
        stock_keys = ("stock", "quantity", "inventory")
        basic_keys = ("basic",)
    mpn = _first_string(value, *mpn_keys)
    description = _first_string(value, *description_keys)
    footprint = _first_string(value, *footprint_keys)
    if not mpn or not description or not footprint:
        raise CatalogRemoteError("catalog part requires mpn, description, and footprint")
    stock = _first_value(value, *stock_keys, default=0)
    if isinstance(stock, bool) or not isinstance(stock, int) or stock < 0:
        raise CatalogRemoteError(f"catalog part {mpn} stock must be a non-negative integer")
    tags = value.get("tags", ())
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, (list, tuple)) or not all(isinstance(tag, str) for tag in tags):
        raise CatalogRemoteError(f"catalog part {mpn} tags must be strings")
    return {
        "mpn": mpn,
        "description": description,
        "footprint": footprint,
        "tags": list(tags),
        "vendor": _first_string(value, "vendor", "supplier", "Supplier") or provider,
        "stock": stock,
        "basic": _first_bool(value, *basic_keys),
        "datasheet_url": str(value.get("datasheet_url") or value.get("datasheet") or ""),
    }


def _first_string(value: dict[str, Any], *keys: str) -> str:
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def _first_value(value: dict[str, Any], *keys: str, default: Any) -> Any:
    for key in keys:
        if key in value and value[key] is not None:
            return value[key]
    return default


def _first_bool(value: dict[str, Any], *keys: str) -> bool:
    candidate = _first_value(value, *keys, default=False)
    if isinstance(candidate, bool):
        return candidate
    if isinstance(candidate, str):
        normalized = candidate.strip().lower()
        if normalized in {"true", "yes", "1", "basic"}:
            return True
        if normalized in {"false", "no", "0", "extended", ""}:
            return False
    return False


def _validate_env_name(value: str) -> None:
    if not value or not (value[0].isalpha() or value[0] == "_") or not all(
        character.isalnum() or character == "_" for character in value
    ):
        raise CatalogRemoteError("catalog bearer-token environment name is invalid")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise CatalogRemoteError("catalog endpoint redirects are not allowed")

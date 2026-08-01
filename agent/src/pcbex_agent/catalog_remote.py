"""Bounded HTTPS catalog adapters for live supplier inventory."""

from __future__ import annotations

import json
import os
import urllib.parse
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
    query: str | None = None
    client_id_environment: str | None = None
    client_secret_environment: str | None = None
    token_endpoint: str | None = None
    locale_site: str = "US"
    locale_language: str = "en"
    locale_currency: str = "USD"


def fetch_catalog(config: CatalogEndpoint) -> list[CatalogPart]:
    """Fetch and normalize a bounded vendor-neutral supplier response.

    The deployment-neutral GET contract is intentionally small: either a JSON
    array of catalog parts or an object containing that array under ``parts``.
    When an approved JLCPCB/LCSC endpoint and ``query`` are supplied, the
    bounded provider-native POST adapter accepts common component wrappers
    before applying the same deterministic selector.
    """
    provider = config.provider.strip().lower()
    if provider not in {"jlcpcb", "digikey", "lcsc", "generic"}:
        raise CatalogRemoteError(
            "catalog provider must be one of: jlcpcb, digikey, lcsc, generic"
        )
    validate_endpoint(config)
    if not 0.1 <= config.timeout_seconds <= 120:
        raise CatalogRemoteError("catalog timeout_seconds must be between 0.1 and 120")
    if provider == "digikey" and config.client_id_environment:
        return _fetch_digikey_native(config)
    if provider in {"jlcpcb", "lcsc"} and config.query:
        return _fetch_component_native(config)
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


def _fetch_digikey_native(config: CatalogEndpoint) -> list[CatalogPart]:
    """Call DigiKey Product Information v4 without requiring a gateway."""

    if not config.query or not config.query.strip():
        raise CatalogRemoteError("native DigiKey search requires catalog query")
    if not config.client_secret_environment:
        raise CatalogRemoteError("native DigiKey search requires client secret environment")
    _validate_env_name(config.client_id_environment or "")
    _validate_env_name(config.client_secret_environment)
    client_id = os.environ.get(config.client_id_environment or "")
    client_secret = os.environ.get(config.client_secret_environment)
    if not client_id or not client_secret:
        raise CatalogRemoteError("DigiKey client credentials are unset or empty")
    parsed = urlsplit(config.endpoint)
    token_endpoint = config.token_endpoint or f"{parsed.scheme}://{parsed.netloc}/v1/oauth2/token"
    token_config = CatalogEndpoint(
        provider="digikey",
        endpoint=token_endpoint,
        timeout_seconds=config.timeout_seconds,
        allow_http_loopback=config.allow_http_loopback,
    )
    validate_endpoint(token_config)
    token_body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }).encode("ascii")
    token_request = urllib.request.Request(
        token_endpoint,
        data=token_body,
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    token_value = _native_json_request(token_request, config.timeout_seconds, "DigiKey token")
    access_token = token_value.get("access_token") if isinstance(token_value, dict) else None
    if not isinstance(access_token, str) or not access_token:
        raise CatalogRemoteError("DigiKey token response did not contain access_token")
    limit = 50
    body = json.dumps({"Keywords": config.query[:250], "Limit": limit, "Offset": 0}).encode("utf-8")
    request = urllib.request.Request(
        config.endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
            "X-DIGIKEY-Client-Id": client_id,
            "X-DIGIKEY-Locale-Site": config.locale_site,
            "X-DIGIKEY-Locale-Language": config.locale_language,
            "X-DIGIKEY-Locale-Currency": config.locale_currency,
        },
        method="POST",
    )
    response = _native_json_request(request, config.timeout_seconds, "DigiKey search")
    products = response.get("Products", []) if isinstance(response, dict) else []
    if not isinstance(products, list):
        raise CatalogRemoteError("DigiKey response Products must be an array")
    normalized = [_normalize_digikey_product(item) for item in products]
    return catalog_parts_from_json(normalized)


def _fetch_component_native(config: CatalogEndpoint) -> list[CatalogPart]:
    """Call an approved JLCPCB/LCSC component endpoint in bounded POST mode.

    Both suppliers expose account/application-specific component APIs rather
    than one stable public URL.  The caller therefore supplies the approved
    endpoint, while pcbex owns the safe request envelope and normalizes the
    provider's common ``parts``/``items``/``data`` response wrappers.  Omitting
    ``CatalogEndpoint.query`` retains the deployment-neutral GET gateway mode.
    """

    if not config.query or not config.query.strip():
        raise CatalogRemoteError("native component search requires catalog query")
    token = None
    if config.bearer_token_environment:
        _validate_env_name(config.bearer_token_environment)
        token = os.environ.get(config.bearer_token_environment)
        if not token or not token.strip():
            raise CatalogRemoteError(
                f"catalog bearer-token environment {config.bearer_token_environment} is unset or empty"
            )
    body = json.dumps(
        {"query": config.query[:250], "limit": 50, "offset": 0},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        config.endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "pcbex-agent/1",
            "X-PCBEX-Catalog-Provider": config.provider.lower(),
            "X-PCBEX-Catalog-Native": "component-v1",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
        method="POST",
    )
    response = _native_value_request(request, config.timeout_seconds, f"{config.provider} component search")
    values = _extract_component_parts(response)
    normalized = [_normalize_part(item, config.provider.lower()) for item in values]
    return catalog_parts_from_json(normalized)


def _native_json_request(request: urllib.request.Request, timeout: float, label: str) -> dict[str, Any]:
    value = _native_value_request(request, timeout, label)
    if not isinstance(value, dict):
        raise CatalogRemoteError(f"{label} response must be an object")
    return value


def _native_value_request(request: urllib.request.Request, timeout: float, label: str) -> Any:
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise CatalogRemoteError(f"{label} returned unexpected HTTP status {response.status}")
            if response.headers.get_content_type() != "application/json":
                raise CatalogRemoteError(f"{label} response Content-Type must be application/json")
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise CatalogRemoteError(f"{label} HTTP request failed: {error.code}") from error
    except urllib.error.URLError as error:
        raise CatalogRemoteError(f"{label} request failed: {error.reason}") from error
    if not body or len(body) > MAX_RESPONSE_BYTES:
        raise CatalogRemoteError(f"{label} response exceeded {MAX_RESPONSE_BYTES} bytes")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogRemoteError(f"{label} response is not UTF-8 JSON: {error}") from error
    return value


def _extract_component_parts(value: Any, *, depth: int = 0) -> list[Any]:
    if depth > 8:
        raise CatalogRemoteError("native component response wrapper nesting is too deep")
    if isinstance(value, list):
        return value
    if not isinstance(value, dict):
        raise CatalogRemoteError("native component response must be an array or object")
    for key in ("parts", "items", "results", "products", "components", "Products", "data"):
        candidate = value.get(key)
        if isinstance(candidate, list):
            return candidate
        if isinstance(candidate, dict):
            try:
                return _extract_component_parts(candidate, depth=depth + 1)
            except CatalogRemoteError:
                pass
    raise CatalogRemoteError(
        "native component response must contain parts/items/results/products/components"
    )


def _normalize_digikey_product(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogRemoteError("DigiKey product must be an object")
    description = value.get("Description")
    if isinstance(description, dict):
        description = description.get("ProductDescription") or description.get("DetailedDescription")
    if not isinstance(description, str) or not description.strip():
        description = value.get("ManufacturerProductNumber") or "DigiKey product"
    variations = value.get("ProductVariations")
    package = ""
    if isinstance(variations, list) and variations:
        first = variations[0]
        if isinstance(first, dict):
            package_value = first.get("PackageType")
            if isinstance(package_value, dict):
                package = str(package_value.get("Name") or "")
            elif isinstance(package_value, str):
                package = package_value
    package = package or str(value.get("PackageType") or "DigiKey:Unknown")
    mpn = value.get("ManufacturerProductNumber") or value.get("DigiKeyProductNumber")
    stock = value.get("QuantityAvailable", 0)
    if not isinstance(mpn, str) or not mpn.strip():
        raise CatalogRemoteError("DigiKey product is missing a part number")
    if isinstance(stock, bool) or not isinstance(stock, int) or stock < 0:
        raise CatalogRemoteError(f"DigiKey product {mpn} has invalid QuantityAvailable")
    return {
        "mpn": mpn.strip(),
        "description": str(description).strip(),
        "footprint": package,
        "tags": [tag for tag in ("digikey", str(value.get("ProductStatus") or "")) if tag],
        "vendor": "digikey",
        "stock": stock,
        "basic": False,
        "datasheet_url": str(value.get("DatasheetUrl") or ""),
    }


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
    elif provider == "jlcpcb":
        mpn_keys = (
            "mpn", "part_number", "partNumber", "componentCode", "component_code",
            "product_code", "productCode", "jlcpcb_part", "lcsc_part",
        )
        description_keys = ("description", "comment", "value", "productName", "product_name")
        footprint_keys = ("footprint", "package", "packageType", "package_type", "PackageType")
        stock_keys = (
            "stock", "quantity", "inventory", "stockQty", "stock_quantity",
            "QuantityAvailable",
        )
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

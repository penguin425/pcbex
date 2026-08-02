from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class CatalogPart:
    mpn: str
    description: str
    footprint: str
    tags: tuple[str, ...] = ()
    vendor: str = ""
    stock: int = 0
    basic: bool = False
    datasheet_url: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CatalogPart":
        """Parse the deliberately small, vendor-neutral catalog contract."""
        required = {"mpn", "description", "footprint"}
        missing = required - value.keys()
        if missing:
            raise ValueError(f"catalog part is missing {sorted(missing)}")
        tags = value.get("tags", ())
        if isinstance(tags, str) or not isinstance(tags, (list, tuple)):
            raise ValueError("catalog part tags must be an array of strings")
        if not all(isinstance(tag, str) and tag.strip() for tag in tags):
            raise ValueError("catalog part tags must contain non-empty strings")
        stock = value.get("stock", 0)
        if isinstance(stock, bool) or not isinstance(stock, int) or stock < 0:
            raise ValueError("catalog part stock must be a non-negative integer")
        basic = value.get("basic", False)
        if not isinstance(basic, bool):
            raise ValueError("catalog part basic must be a boolean")
        fields = {
            "mpn": value["mpn"],
            "description": value["description"],
            "footprint": value["footprint"],
            "tags": tuple(tags),
            "vendor": value.get("vendor", ""),
            "stock": stock,
            "basic": basic,
            "datasheet_url": value.get("datasheet_url", ""),
        }
        if not all(isinstance(fields[key], str) and fields[key].strip() for key in
                   ("mpn", "description", "footprint")):
            raise ValueError("catalog part identity fields must be non-empty strings")
        if not isinstance(fields["vendor"], str) or not isinstance(
            fields["datasheet_url"], str
        ):
            raise ValueError("catalog part vendor and datasheet_url must be strings")
        return cls(**fields)


def search_parts(
    catalog: Iterable[CatalogPart],
    query: str,
    *,
    footprint: str | None = None,
    limit: int = 10,
    require_available: bool = False,
    require_basic: bool = False,
) -> list[CatalogPart]:
    """Search an injected catalog with deterministic manufacturing filters.

    Vendor APIs are intentionally kept outside the planner.  A connector can
    normalize its response into :class:`CatalogPart` and use this function as
    the stable, reproducible selection gate.
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")
    words = {word.casefold() for word in query.split() if word}
    scored: list[tuple[int, int, int, str, CatalogPart]] = []
    for part in catalog:
        if footprint and part.footprint != footprint:
            continue
        if require_available and part.stock <= 0:
            continue
        if require_basic and not part.basic:
            continue
        haystack = " ".join((part.mpn, part.description, *part.tags)).casefold()
        score = sum(word in haystack for word in words)
        if not words or score:
            # Availability and JLCPCB-style basic status are tie breakers, not
            # implicit filters, so callers can inspect alternatives explicitly.
            scored.append((-score, -int(part.stock > 0), -int(part.basic), part.mpn, part))
    scored.sort(key=lambda item: item[:-1])
    return [part for *_, part in scored[:limit]]


def catalog_parts_from_json(value: Any) -> list[CatalogPart]:
    """Validate a vendor-neutral JSON catalog payload."""
    if not isinstance(value, list):
        raise ValueError("catalog JSON must be an array")
    parts: list[CatalogPart] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"catalog part at index {index} must be an object")
        parts.append(CatalogPart.from_mapping(item))
    mpns = [part.mpn for part in parts]
    if len(mpns) != len(set(mpns)):
        raise ValueError("catalog JSON contains duplicate MPNs")
    return parts

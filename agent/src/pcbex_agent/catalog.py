from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CatalogPart:
    mpn: str
    description: str
    footprint: str
    tags: tuple[str, ...] = ()


def search_parts(
    catalog: Iterable[CatalogPart],
    query: str,
    *,
    footprint: str | None = None,
    limit: int = 10,
) -> list[CatalogPart]:
    """Search an injected catalog without coupling planning to a vendor API."""
    words = {word.casefold() for word in query.split() if word}
    scored: list[tuple[int, str, CatalogPart]] = []
    for part in catalog:
        if footprint and part.footprint != footprint:
            continue
        haystack = " ".join((part.mpn, part.description, *part.tags)).casefold()
        score = sum(word in haystack for word in words)
        if not words or score:
            scored.append((-score, part.mpn, part))
    scored.sort(key=lambda item: (item[0], item[1]))
    return [part for _, _, part in scored[: max(0, limit)]]

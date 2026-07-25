from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any


class IpcUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ApplyResult:
    tracks_created: int
    vias_created: int


def _official_api() -> SimpleNamespace:
    try:
        import kipy
        from kipy.board_types import Track, Via
        from kipy.geometry import Vector2
        from kipy.util.board_layer import layer_from_canonical_name
    except ImportError as error:
        raise IpcUnavailable(
            "install pcbex-agent[kicad] and enable KiCad's IPC API"
        ) from error
    return SimpleNamespace(
        client_factory=lambda: kipy.KiCad(client_name="pcbex-agent"),
        Track=Track,
        Via=Via,
        Vector2=Vector2,
        layer_from_name=layer_from_canonical_name,
    )


def apply_routes_to_open_board(
    document: dict[str, Any],
    *,
    max_items: int = 10_000,
    api: Any | None = None,
) -> ApplyResult:
    """Apply routed JSON to the board open in KiCad as one undoable commit."""
    api = api or _official_api()
    routes = document.get("routes")
    if not isinstance(routes, list):
        raise ValueError("route document must contain a routes array")
    item_count = sum(
        len(route.get("segments", [])) + len(route.get("vias", []))
        for route in routes
        if isinstance(route, dict)
    )
    if item_count > max_items:
        raise ValueError(f"IPC change contains {item_count} items; limit is {max_items}")
    client = api.client_factory()
    board = client.get_board()
    board_nets = list(board.get_nets())
    nets_by_name = {net.name: net for net in board_nets}
    route_net_names = {
        item["id"]: item["name"]
        for item in document.get("nets", [])
        if isinstance(item, dict) and "id" in item and "name" in item
    }
    items = []
    origin = document.get("origin", {})
    origin_x = int(origin.get("x_nm", 0))
    origin_y = int(origin.get("y_nm", 0))
    track_count = 0
    via_count = 0
    for route in routes:
        net_id = route["net_id"]
        net = nets_by_name.get(route_net_names.get(net_id, ""))
        if net is None:
            net = next(
                (candidate for candidate in board_nets if candidate.code == net_id),
                None,
            )
        if net is None:
            raise ValueError(f"open KiCad board does not contain net code {net_id}")
        for raw in route.get("segments", []):
            track = api.Track()
            track.start = api.Vector2.from_xy(
                raw["start"]["x_nm"] + origin_x, raw["start"]["y_nm"] + origin_y
            )
            track.end = api.Vector2.from_xy(
                raw["end"]["x_nm"] + origin_x, raw["end"]["y_nm"] + origin_y
            )
            track.width = raw["width_nm"]
            track.layer = api.layer_from_name(raw["layer"])
            track.net = net
            items.append(track)
            track_count += 1
        for raw in route.get("vias", []):
            via = api.Via()
            via.position = api.Vector2.from_xy(
                raw["position"]["x_nm"] + origin_x,
                raw["position"]["y_nm"] + origin_y,
            )
            via.diameter = raw["diameter_nm"]
            via.drill_diameter = raw["drill_nm"]
            via.net = net
            items.append(via)
            via_count += 1
    commit = board.begin_commit()
    try:
        board.create_items(items)
        board.push_commit(commit, "Apply pcbex routing")
    except Exception:
        board.drop_commit(commit)
        raise
    return ApplyResult(track_count, via_count)

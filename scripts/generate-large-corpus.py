#!/usr/bin/env python3
"""Generate the deterministic 100-net, six-layer routing regression board."""

import json
import sys


def point(x: int, y: int) -> dict[str, int]:
    return {"x_nm": x, "y_nm": y}


def terminal(x: int, y: int) -> dict[str, object]:
    return {"position": point(x, y), "layers": ["F.Cu"]}


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate-large-corpus.py OUTPUT.json")
    nets = []
    for index in range(100):
        y = 2_000_000 + index * 1_000_000
        nets.append(
            {
                "id": index + 1,
                "name": f"BP_{index + 1:03}",
                "priority": 100 - index,
                "terminals": [
                    terminal(2_000_000, y),
                    terminal(118_000_000, y),
                ],
            }
        )
    board = {
        "schema_version": 2,
        "width_nm": 120_000_000,
        "height_nm": 103_000_000,
        "copper_layers": [
            "F.Cu",
            "In1.Cu",
            "In2.Cu",
            "In3.Cu",
            "In4.Cu",
            "B.Cu",
        ],
        "rules": {
            "grid_nm": 250_000,
            "track_width_nm": 150_000,
            "clearance_nm": 150_000,
            "via_diameter_nm": 500_000,
            "via_drill_nm": 250_000,
            "bend_cost": 8,
            "via_cost": 30,
        },
        "via_strategy": "auto",
        "nets": nets,
    }
    with open(sys.argv[1], "w", encoding="utf-8") as output:
        json.dump(board, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()

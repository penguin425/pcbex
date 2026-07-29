#!/usr/bin/env python3
"""One-shot loopback HTTP witness used only by the composite-Action smoke test."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcbex", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--endpoint-output", type=Path, required=True)
    args = parser.parse_args()
    checkpoint = json.loads(args.checkpoint.read_text(encoding="utf-8"))

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/witness":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= length <= 1024 * 1024:
                self.send_error(413)
                return
            request = json.loads(self.rfile.read(length))
            if (
                set(request) != {"schema_version", "protocol", "checkpoint"}
                or request["schema_version"] != 1
                or request["protocol"] != "pcbex-approval-log-witness-v1"
                or request["checkpoint"] != checkpoint
            ):
                self.send_error(400)
                return
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "witness.json"
                subprocess.run(
                    [
                        str(args.pcbex),
                        "witness-approval-log",
                        str(args.checkpoint),
                        "--private-key",
                        str(args.private_key),
                        "--witness-id",
                        "action-remote-witness",
                        "--observed-at-unix",
                        "3",
                        "--output",
                        str(output),
                    ],
                    check=True,
                )
                response = output.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            self.server.shutdown_requested = True  # type: ignore[attr-defined]

        def log_message(self, format: str, *values: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.shutdown_requested = False  # type: ignore[attr-defined]
    args.endpoint_output.write_text(
        f"http://127.0.0.1:{server.server_port}/v1/witness\n",
        encoding="utf-8",
    )
    while not server.shutdown_requested:  # type: ignore[attr-defined]
        server.handle_request()
    server.server_close()


if __name__ == "__main__":
    main()

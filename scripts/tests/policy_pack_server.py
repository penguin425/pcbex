#!/usr/bin/env python3
"""One-shot loopback policy registry used only by the composite-Action smoke test."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signed-policy-pack", type=Path, required=True)
    parser.add_argument("--endpoint-output", type=Path, required=True)
    parser.add_argument("--bearer-token")
    args = parser.parse_args()
    response = args.signed_policy_pack.read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/v1/current":
                self.send_error(404)
                return
            if args.bearer_token is not None and (
                self.headers.get("Authorization") != f"Bearer {args.bearer_token}"
            ):
                self.send_error(401)
                return
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
        f"http://127.0.0.1:{server.server_port}/v1/current\n",
        encoding="utf-8",
    )
    while not server.shutdown_requested:  # type: ignore[attr-defined]
        server.handle_request()
    server.server_close()


if __name__ == "__main__":
    main()

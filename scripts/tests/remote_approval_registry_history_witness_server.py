#!/usr/bin/env python3
"""One-shot approval registry-history witness server for the Action smoke test."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


PROTOCOL = (
    "pcbex-approval-public-log-gossip-organization-registry-history-"
    "checkpoint-witness-v1"
)
MAX_REQUEST_BYTES = 1024 * 1024


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--witness", type=Path, required=True)
    parser.add_argument("--endpoint-output", type=Path, required=True)
    args = parser.parse_args()
    witness = json.loads(args.witness.read_text(encoding="utf-8"))
    response = json.dumps(
        witness, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/approval-registry-history-checkpoint":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= length <= MAX_REQUEST_BYTES:
                self.send_error(413)
                return
            try:
                request = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_error(400)
                return
            trust_state = request.get("checkpoint_trust_state")
            if (
                set(request)
                != {"schema_version", "protocol", "checkpoint_trust_state"}
                or request["schema_version"] != 1
                or request["protocol"] != PROTOCOL
                or not isinstance(trust_state, dict)
                or trust_state.get("registry_id") != witness["registry_id"]
                or trust_state.get("accepted_generation") != witness["generation"]
                or trust_state.get("checkpoint_sha256")
                != witness["checkpoint_sha256"]
            ):
                self.send_error(400)
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
        "http://127.0.0.1:"
        f"{server.server_port}/v1/approval-registry-history-checkpoint\n",
        encoding="utf-8",
    )
    while not server.shutdown_requested:  # type: ignore[attr-defined]
        server.handle_request()
    server.server_close()


if __name__ == "__main__":
    main()

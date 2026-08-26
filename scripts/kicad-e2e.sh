#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 PCBEX_BINARY OUTPUT_DIRECTORY" >&2
  exit 2
fi

pcbex_binary="$(realpath "$1")"
output_directory=$2
fixtures=(
  examples/simple.kicad_pcb
  examples/nonrect.kicad_pcb
  examples/keepout.kicad_pcb
  examples/curved.kicad_pcb
  examples/multilayer.kicad_pcb
)

mkdir -p "$output_directory"
kicad-cli --version
kicad_cli_binary="$(command -v kicad-cli)"

generated_schematic="$output_directory/circuit-spec-v2.generated.kicad_sch"
repeated_schematic="$output_directory/circuit-spec-v2.repeated.kicad_sch"
generated_netlist="$output_directory/circuit-spec-v2.generated.xml"
generated_handoff="$output_directory/circuit-spec-v2.generated.handoff.json"
"$pcbex_binary" write-circuit-spec-kicad-schematic \
  examples/circuit-spec-v2.json --output "$generated_schematic"
"$pcbex_binary" write-circuit-spec-kicad-schematic \
  examples/circuit-spec-v2.json --output "$repeated_schematic"
cmp "$generated_schematic" "$repeated_schematic"
kicad-cli sch export netlist --format kicadxml "$generated_schematic" \
  --output "$generated_netlist"
test -s "$generated_netlist"
python3 - "$generated_netlist" <<'PY'
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

netlist = Path(sys.argv[1])
root = ET.parse(netlist).getroot()
actual = {
    frozenset((node.attrib["ref"], node.attrib["pin"]) for node in net.findall("node"))
    for net in root.findall("./nets/net")
}
expected = {
    frozenset({("C1", "2"), ("C2", "2"), ("J1", "2"), ("U1", "2")}),
    frozenset({("C1", "1"), ("U1", "5")}),
    frozenset({("C2", "1"), ("J1", "1"), ("U1", "1"), ("U1", "3")}),
    frozenset({("U1", "4")}),
}
if actual != expected:
    render = lambda groups: sorted(sorted(group) for group in groups)
    raise SystemExit(
        f"KiCad native connectivity mismatch: expected {render(expected)}, got {render(actual)}"
    )
PY

run_v1491_external_gossip_quorum_e2e() {
# v1.491 acquires canonical v1.490 observations over bounded remote transport
# and counts only distinct policy-pinned organizations that agree on one exact
# signed external-log head. Two later forks from the same local prefix must not
# be mistaken for one observer quorum.
factory_transparency_external_gossip_quorum_policy_schema="$output_directory/factory-release-transparency-external-gossip-quorum-policy.schema.json"
factory_transparency_external_gossip_observation_schema="$output_directory/factory-release-transparency-external-gossip-observation.schema.json"
factory_transparency_external_gossip_remote_receipt_schema="$output_directory/factory-release-transparency-external-gossip-remote-receipt.schema.json"
factory_transparency_external_gossip_quorum_report_schema="$output_directory/factory-release-transparency-external-gossip-quorum-report.schema.json"
factory_transparency_external_gossip_quorum_policy="$output_directory/factory-release-transparency-external-gossip-quorum.policy.json"
factory_transparency_external_gossip_quorum_policy_digest_file="$output_directory/factory-release-transparency-external-gossip-quorum.policy.sha256"
factory_transparency_external_gossip_observation_a="$output_directory/factory-release-transparency-external-gossip-quorum-observation-a.server.json"
factory_transparency_external_gossip_observation_b="$output_directory/factory-release-transparency-external-gossip-quorum-observation-b.server.json"
factory_transparency_external_gossip_observation_b_fork="$output_directory/factory-release-transparency-external-gossip-quorum-observation-b-fork.server.json"
factory_transparency_external_gossip_private_b="$factory_response_secret_directory/external-gossip-observer-b.hex"
factory_transparency_external_gossip_private_a_next="$factory_response_secret_directory/external-gossip-observer-a-next.hex"
factory_transparency_external_gossip_private_a_fork="$factory_response_secret_directory/external-gossip-observer-a-fork.hex"
factory_transparency_external_gossip_registry_authority_private="$factory_response_secret_directory/external-gossip-registry-authority.hex"

"$pcbex_binary" factory-release-state-transparency-external-gossip-quorum-policy-schema \
  --output "$factory_transparency_external_gossip_quorum_policy_schema"
"$pcbex_binary" factory-release-state-transparency-external-gossip-observation-schema \
  --output "$factory_transparency_external_gossip_observation_schema"
"$pcbex_binary" remote-factory-release-state-transparency-external-gossip-receipt-schema \
  --output "$factory_transparency_external_gossip_remote_receipt_schema"
"$pcbex_binary" factory-release-state-transparency-external-gossip-quorum-verification-report-schema \
  --output "$factory_transparency_external_gossip_quorum_report_schema"

python3 - \
  "$factory_transparency_external_consistency_report_2" \
  "$factory_transparency_external_gossip_receipt" \
  "$factory_transparency_external_gossip_proof" \
  "$factory_transparency_external_anchor_private" \
  "$factory_transparency_external_gossip_public_key_file" \
  "$factory_transparency_external_gossip_private_b" \
  "$factory_transparency_external_gossip_quorum_policy" \
  "$factory_transparency_external_gossip_quorum_policy_digest_file" \
  "$factory_transparency_external_gossip_observation_a" \
  "$factory_transparency_external_gossip_observation_b" \
  "$factory_transparency_external_gossip_observation_b_fork" <<'PY'
import copy
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

local_report_path, receipt_a_path, proof_a_path, external_private_path, \
    observer_a_public_path, observer_b_private_path, policy_path, policy_digest_path, \
    observation_a_path, observation_b_path, observation_b_fork_path = \
    map(Path, sys.argv[1:])
local_report = json.loads(local_report_path.read_bytes())
receipt_a = json.loads(receipt_a_path.read_bytes())
proof_a = json.loads(proof_a_path.read_bytes())
local_head = local_report["consistency_proof"]["current_tree_head"]
external_private = Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex(external_private_path.read_text(encoding="ascii").strip())
)
observer_b_seed = bytes([72]) * 32
observer_b_private = Ed25519PrivateKey.from_private_bytes(observer_b_seed)
observer_b_public = observer_b_private.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()
observer_b_private_path.write_text(observer_b_seed.hex() + "\n", encoding="ascii")
observer_a_public = observer_a_public_path.read_text(encoding="ascii").strip()

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

def merkle_leaf(digest):
    return hashlib.sha256(
        b"\x00" +
        b"pcbex:factory-release-state-transparency-external-anchor-merkle-leaf:v1\0" +
        bytes.fromhex(digest)
    ).digest()

def merkle_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()

def merkle_root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return merkle_node(merkle_root(leaves[:split]), merkle_root(leaves[split:]))

def consistency_subproof(old_size, leaves, complete_subtree):
    if old_size == len(leaves):
        return [] if complete_subtree else [merkle_root(leaves)]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if old_size <= split:
        return consistency_subproof(
            old_size, leaves[:split], complete_subtree
        ) + [merkle_root(leaves[split:])]
    return consistency_subproof(
        old_size - split, leaves[split:], False
    ) + [merkle_root(leaves[:split])]

def sign_head(head):
    payload = {
        "domain": "pcbex-factory-release-state-transparency-external-anchor-tree-head-v1",
        "schema_version": head["schema_version"],
        "tree_head_scope": head["tree_head_scope"],
        "log_id": head["log_id"],
        "tree_size": head["tree_size"],
        "root_sha256": head["root_sha256"],
        "observed_at_unix": head["observed_at_unix"],
        "algorithm": head["algorithm"],
        "public_key": head["public_key"],
    }
    head["signature"] = external_private.sign(compact(payload)).hex()

def head_sha256(head):
    return hashlib.sha256(compact(head)).hexdigest()

def sign_receipt(head, observer_id, observer_public, private_key, expires_at):
    receipt = {
        "schema_version": 1,
        "receipt_scope":
            "factory-release-state-transparency-external-log-gossip-receipt-v1",
        "external_anchor_policy_sha256":
            local_report["external_anchor_policy_sha256"],
        "external_log_id": local_report["external_log_id"],
        "observer_id": observer_id,
        "observed_tree_head_sha256": head_sha256(head),
        "observed_tree_head": head,
        "received_at_unix": head["observed_at_unix"],
        "expires_at_unix": expires_at,
        "algorithm": "ed25519",
        "observer_public_key": observer_public,
        "signature": "",
    }
    payload = {
        "domain":
            "pcbex-factory-release-state-transparency-external-log-gossip-receipt-v1",
        "schema_version": receipt["schema_version"],
        "receipt_scope": receipt["receipt_scope"],
        "external_anchor_policy_sha256": receipt["external_anchor_policy_sha256"],
        "external_log_id": receipt["external_log_id"],
        "observer_id": receipt["observer_id"],
        "observed_tree_head_sha256": receipt["observed_tree_head_sha256"],
        "observed_tree_size": head["tree_size"],
        "observed_root_sha256": head["root_sha256"],
        "observed_tree_head_observed_at_unix": head["observed_at_unix"],
        "external_log_public_key": head["public_key"],
        "received_at_unix": receipt["received_at_unix"],
        "expires_at_unix": receipt["expires_at_unix"],
        "algorithm": receipt["algorithm"],
        "observer_public_key": receipt["observer_public_key"],
    }
    receipt["signature"] = private_key.sign(compact(payload)).hex()
    return receipt

policy = {
    "schema_version": 1,
    "policy_scope":
        "factory-release-state-transparency-external-gossip-quorum-policy-v1",
    "policy_id": "kicad-e2e-external-observers",
    "minimum_organizations": 2,
    "maximum_receipt_age_seconds": 3600,
    "trusted_observers": [
        {
            "organization_id": "independent-observer-org-a",
            "observer_id": "independent-observer-a",
            "algorithm": "ed25519",
            "public_key": observer_a_public,
        },
        {
            "organization_id": "independent-observer-org-b",
            "observer_id": "independent-observer-b",
            "algorithm": "ed25519",
            "public_key": observer_b_public,
        },
    ],
}
write(policy_path, policy)
policy_digest_path.write_text(
    hashlib.sha256(compact(policy)).hexdigest() + "\n", encoding="ascii"
)

receipt_b = sign_receipt(
    receipt_a["observed_tree_head"],
    "independent-observer-b",
    observer_b_public,
    observer_b_private,
    receipt_a["expires_at_unix"],
)
observation_a = {
    "schema_version": 1,
    "observation_scope":
        "factory-release-state-transparency-external-gossip-observation-v1",
    "gossip_receipt": receipt_a,
    "consistency_proof": proof_a,
}
observation_b = {
    "schema_version": 1,
    "observation_scope":
        "factory-release-state-transparency-external-gossip-observation-v1",
    "gossip_receipt": receipt_b,
    "consistency_proof": proof_a,
}
write(observation_a_path, observation_a)
write(observation_b_path, observation_b)

anchor_proof = local_report["external_anchor_report"]["anchor_proof"]
anchor_leaf = merkle_leaf(anchor_proof["leaf_sha256"])
leaves_3 = [
    bytes.fromhex(anchor_proof["audit_path"][0]),
    anchor_leaf,
    bytes.fromhex(anchor_proof["audit_path"][1]),
]
leaves_5 = leaves_3 + [merkle_leaf("66" * 32), merkle_leaf("88" * 32)]
assert merkle_root(leaves_5).hex() == local_head["root_sha256"]
fork_leaves = leaves_5 + [merkle_leaf("aa" * 32)]
fork_head = {
    "schema_version": 1,
    "tree_head_scope":
        "signed-factory-release-state-transparency-external-anchor-tree-head-v1",
    "log_id": local_head["log_id"],
    "tree_size": len(fork_leaves),
    "root_sha256": merkle_root(fork_leaves).hex(),
    "observed_at_unix": receipt_a["observed_tree_head"]["observed_at_unix"],
    "algorithm": "ed25519",
    "public_key": local_head["public_key"],
    "signature": "",
}
sign_head(fork_head)
fork_receipt = sign_receipt(
    fork_head,
    "independent-observer-b",
    observer_b_public,
    observer_b_private,
    receipt_a["expires_at_unix"],
)
fork_proof = {
    "schema_version": 1,
    "proof_scope":
        "factory-release-state-transparency-external-log-consistency-proof-v1",
    "external_anchor_policy_sha256":
        local_report["external_anchor_policy_sha256"],
    "external_log_id": local_report["external_log_id"],
    "previous_tree_head_sha256": head_sha256(local_head),
    "current_tree_head_sha256": head_sha256(fork_head),
    "previous_tree_head": local_head,
    "current_tree_head": fork_head,
    "consistency_path": [
        node.hex()
        for node in consistency_subproof(len(leaves_5), fork_leaves, True)
    ],
}
write(
    observation_b_fork_path,
    {
        "schema_version": 1,
        "observation_scope":
            "factory-release-state-transparency-external-gossip-observation-v1",
        "gossip_receipt": fork_receipt,
        "consistency_proof": fork_proof,
    },
)
PY

factory_transparency_external_gossip_quorum_policy_digest="$(tr -d '\r\n' < "$factory_transparency_external_gossip_quorum_policy_digest_file")"

factory_transparency_external_gossip_remote_a="$output_directory/factory-release-transparency-external-gossip-quorum-observation-a.json"
factory_transparency_external_gossip_remote_b="$output_directory/factory-release-transparency-external-gossip-quorum-observation-b.json"
factory_transparency_external_gossip_remote_b_fork="$output_directory/factory-release-transparency-external-gossip-quorum-observation-b-fork.json"
factory_transparency_external_gossip_transport_a="$output_directory/factory-release-transparency-external-gossip-quorum-transport-a.json"
factory_transparency_external_gossip_transport_b="$output_directory/factory-release-transparency-external-gossip-quorum-transport-b.json"
factory_transparency_external_gossip_transport_b_fork="$output_directory/factory-release-transparency-external-gossip-quorum-transport-b-fork.json"
factory_transparency_external_gossip_quorum_port="$output_directory/factory-release-transparency-external-gossip-quorum.port"
external_gossip_quorum_server_pid=""
trap 'if [ -n "${external_gossip_quorum_server_pid:-}" ]; then kill "$external_gossip_quorum_server_pid" 2>/dev/null || true; fi; if [ -n "${external_gossip_rotation_server_pid:-}" ]; then kill "$external_gossip_rotation_server_pid" 2>/dev/null || true; fi; kill "$signed_release_adapter_server_pid" 2>/dev/null || true; rm -f -- "$factory_response_private_key" "$factory_response_public_der" "$factory_transparency_private_key" "$factory_transparency_public_der" "$factory_transparency_witness_private_a" "$factory_transparency_witness_private_b" "$factory_transparency_external_anchor_private" "$factory_transparency_external_gossip_private" "$factory_transparency_external_gossip_private_b" "$factory_transparency_external_gossip_private_a_next" "$factory_transparency_external_gossip_private_a_fork" "$factory_transparency_external_gossip_registry_authority_private"; rmdir -- "$factory_response_secret_directory" "$factory_witness_secret_directory" 2>/dev/null || true' EXIT

export PCBEX_E2E_EXTERNAL_GOSSIP_TOKEN="v1491-e2e-bearer-token"
python3 - \
  "$factory_transparency_external_gossip_quorum_port" \
  "$factory_transparency_external_gossip_observation_a" \
  "$factory_transparency_external_gossip_observation_b" \
  "$factory_transparency_external_gossip_observation_b_fork" \
  "$PCBEX_E2E_EXTERNAL_GOSSIP_TOKEN" <<'PY' &
import http.server
import json
from pathlib import Path
import sys
import time

port_path, observation_a_path, observation_b_path, observation_b_fork_path = \
    map(Path, sys.argv[1:5])
expected_token = sys.argv[5]
responses = {
    "independent-observer-a": [observation_a_path.read_bytes()],
    "independent-observer-b": [
        observation_b_path.read_bytes(),
        observation_b_fork_path.read_bytes(),
    ],
}
valid_observation = observation_a_path.read_bytes()
request_counts = {
    "/v1/external-gossip": 0,
    "/v1/status": 0,
    "/v1/mime": 0,
    "/v1/oversize": 0,
    "/v1/redirect": 0,
    "/v1/timeout": 0,
}

class Server(http.server.HTTPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        assert self.path in request_counts
        request_counts[self.path] += 1
        assert self.headers.get("Content-Type") == "application/json"
        assert self.headers.get("Accept") == "application/json"
        assert self.headers.get("Authorization") == f"Bearer {expected_token}"
        length = int(self.headers.get("Content-Length", "0"))
        assert 0 < length <= 1024 * 1024
        request = json.loads(self.rfile.read(length))
        assert request["schema_version"] == 1
        assert request["protocol"] == \
            "pcbex-factory-release-state-transparency-external-gossip-observation-v1"
        assert request["local_external_consistency_generation"] == 2
        observer = request["observer_id"]
        if self.path == "/v1/status":
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        if self.path == "/v1/redirect":
            self.send_response(307)
            self.send_header("Location", "/v1/external-gossip")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        if self.path == "/v1/timeout":
            time.sleep(2)
            response = valid_observation
        elif self.path == "/v1/oversize":
            response = b" " * (1024 * 1024 + 1)
        elif self.path == "/v1/mime":
            response = valid_observation
        else:
            response = responses[observer].pop(0)
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain" if self.path == "/v1/mime" else "application/json",
        )
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(response)
        except (BrokenPipeError, ConnectionResetError):
            assert self.path in {"/v1/mime", "/v1/oversize", "/v1/timeout"}

    def log_message(self, *_args):
        return

server = Server(("127.0.0.1", 0), Handler)
port_path.write_text(str(server.server_port) + "\n", encoding="ascii")
for _ in range(8):
    server.handle_request()
server.server_close()
assert not responses["independent-observer-a"]
assert not responses["independent-observer-b"]
assert request_counts == {
    "/v1/external-gossip": 3,
    "/v1/status": 1,
    "/v1/mime": 1,
    "/v1/oversize": 1,
    "/v1/redirect": 1,
    "/v1/timeout": 1,
}
PY
external_gossip_quorum_server_pid=$!
for _ in $(seq 1 200); do
  if [ -s "$factory_transparency_external_gossip_quorum_port" ]; then
    break
  fi
  if ! kill -0 "$external_gossip_quorum_server_pid" 2>/dev/null; then
    wait "$external_gossip_quorum_server_pid"
    exit 1
  fi
  sleep 0.05
done
test -s "$factory_transparency_external_gossip_quorum_port"
factory_transparency_external_gossip_quorum_endpoint="http://127.0.0.1:$(tr -d '\r\n' < "$factory_transparency_external_gossip_quorum_port")/v1/external-gossip"

request_factory_transparency_external_gossip_observation() {
  local organization_id=$1
  local observer_id=$2
  local observation_output=$3
  local transport_output=$4
  local request_endpoint=${5:-$factory_transparency_external_gossip_quorum_endpoint}
  "$pcbex_binary" request-factory-release-state-transparency-external-gossip-observation \
    --local-external-consistency-report "$factory_transparency_external_consistency_report_2" \
    --external-anchor-policy "$factory_transparency_external_anchor_policy" \
    --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
    --external-log-id kicad-e2e-external-anchor-log \
    --observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --organization-id "$organization_id" \
    --observer-id "$observer_id" \
    --endpoint "$request_endpoint" \
    --bearer-token-env PCBEX_E2E_EXTERNAL_GOSSIP_TOKEN \
    --timeout-seconds 5 \
    --evaluated-at-unix "$factory_transparency_external_gossip_time" \
    --output "$observation_output" \
    --receipt-output "$transport_output" \
    --allow-http-loopback
}

request_factory_transparency_external_gossip_observation \
  independent-observer-org-a independent-observer-a \
  "$factory_transparency_external_gossip_remote_a" \
  "$factory_transparency_external_gossip_transport_a"
request_factory_transparency_external_gossip_observation \
  independent-observer-org-b independent-observer-b \
  "$factory_transparency_external_gossip_remote_b" \
  "$factory_transparency_external_gossip_transport_b"
request_factory_transparency_external_gossip_observation \
  independent-observer-org-b independent-observer-b \
  "$factory_transparency_external_gossip_remote_b_fork" \
  "$factory_transparency_external_gossip_transport_b_fork"

expect_factory_transparency_external_gossip_remote_failure() {
  local case_name=$1
  local endpoint_path=$2
  local timeout_seconds=${3:-5}
  local observation_output="$output_directory/factory-release-transparency-external-gossip-${case_name}.observation.json"
  local transport_output="$output_directory/factory-release-transparency-external-gossip-${case_name}.transport.json"
  local error_output="$output_directory/factory-release-transparency-external-gossip-${case_name}.stderr"
  if "$pcbex_binary" request-factory-release-state-transparency-external-gossip-observation \
    --local-external-consistency-report "$factory_transparency_external_consistency_report_2" \
    --external-anchor-policy "$factory_transparency_external_anchor_policy" \
    --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
    --external-log-id kicad-e2e-external-anchor-log \
    --observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --organization-id independent-observer-org-a \
    --observer-id independent-observer-a \
    --endpoint "${factory_transparency_external_gossip_quorum_endpoint%/v1/external-gossip}${endpoint_path}" \
    --bearer-token-env PCBEX_E2E_EXTERNAL_GOSSIP_TOKEN \
    --timeout-seconds "$timeout_seconds" \
    --evaluated-at-unix "$factory_transparency_external_gossip_time" \
    --output "$observation_output" \
    --receipt-output "$transport_output" \
    --allow-http-loopback 2>"$error_output"; then
    echo "expected remote external-gossip ${case_name} rejection" >&2
    exit 1
  fi
  test ! -e "$observation_output"
  test ! -e "$transport_output"
  grep -Fq 'remote factory release transparency external gossip' "$error_output"
}

expect_factory_transparency_external_gossip_remote_failure status /v1/status
expect_factory_transparency_external_gossip_remote_failure mime /v1/mime
expect_factory_transparency_external_gossip_remote_failure oversize /v1/oversize
expect_factory_transparency_external_gossip_remote_failure redirect /v1/redirect
expect_factory_transparency_external_gossip_remote_failure timeout /v1/timeout 1
wait "$external_gossip_quorum_server_pid"
external_gossip_quorum_server_pid=""
unset PCBEX_E2E_EXTERNAL_GOSSIP_TOKEN

factory_transparency_external_gossip_quorum_insufficient="$output_directory/factory-release-transparency-external-gossip-quorum-insufficient.report.json"
factory_transparency_external_gossip_quorum_insufficient_gated="$output_directory/factory-release-transparency-external-gossip-quorum-insufficient-gated.report.json"
factory_transparency_external_gossip_quorum_insufficient_gated_error="$output_directory/factory-release-transparency-external-gossip-quorum-insufficient-gated.stderr"
factory_transparency_external_gossip_quorum_unbacked_accepted="$output_directory/factory-release-transparency-external-gossip-quorum-unbacked-accepted.report.json"
factory_transparency_external_gossip_quorum_unbacked_accepted_error="$output_directory/factory-release-transparency-external-gossip-quorum-unbacked-accepted.stderr"
factory_transparency_external_gossip_quorum_mixed_output="$output_directory/factory-release-transparency-external-gossip-quorum-mixed.report.json"
factory_transparency_external_gossip_quorum_mixed_error="$output_directory/factory-release-transparency-external-gossip-quorum-mixed.stderr"
factory_transparency_external_gossip_quorum_tampered_transport="$output_directory/factory-release-transparency-external-gossip-quorum-transport-tampered.json"
factory_transparency_external_gossip_quorum_tampered_output="$output_directory/factory-release-transparency-external-gossip-quorum-tampered.report.json"
factory_transparency_external_gossip_quorum_tampered_error="$output_directory/factory-release-transparency-external-gossip-quorum-tampered.stderr"
factory_transparency_external_gossip_quorum_stale_output="$output_directory/factory-release-transparency-external-gossip-quorum-stale.report.json"
factory_transparency_external_gossip_quorum_stale_error="$output_directory/factory-release-transparency-external-gossip-quorum-stale.stderr"
factory_transparency_external_gossip_quorum_report_a="$output_directory/factory-release-transparency-external-gossip-quorum-a.report.json"
factory_transparency_external_gossip_quorum_report_b="$output_directory/factory-release-transparency-external-gossip-quorum-b.report.json"
factory_transparency_external_gossip_quorum_replay="$output_directory/factory-release-transparency-external-gossip-quorum-replay.report.json"
factory_transparency_external_gossip_quorum_conflict_output="$output_directory/factory-release-transparency-external-gossip-quorum-conflict.report.json"
factory_transparency_external_gossip_quorum_conflict_error="$output_directory/factory-release-transparency-external-gossip-quorum-conflict.stderr"

python3 - \
  "$factory_transparency_external_gossip_transport_a" \
  "$factory_transparency_external_gossip_quorum_tampered_transport" <<'PY'
import json
from pathlib import Path
import sys

source, output = map(Path, sys.argv[1:])
receipt = json.loads(source.read_bytes())
receipt["response_sha256"] = "00" * 32
output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
PY

verify_factory_transparency_external_gossip_quorum() {
  "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --idempotency-key "$monotonic_key" \
    --log-id kicad-e2e-factory-release-log \
    --policy-pack "$factory_receipt_policy" \
    --expected-policy-sha256 "$fabrication_release_policy_digest" \
    --transparency-policy "$factory_transparency_policy" \
    --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
    --witness-policy "$factory_transparency_witness_policy" \
    --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
    --external-anchor-policy "$factory_transparency_external_anchor_policy" \
    --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
    --external-log-id kicad-e2e-external-anchor-log \
    --observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    "$@"
}

verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --transport-receipt "$factory_transparency_external_gossip_transport_a" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_quorum_insufficient"

if verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --transport-receipt "$factory_transparency_external_gossip_transport_a" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_quorum_insufficient_gated" \
  --require-quorum \
  2>"$factory_transparency_external_gossip_quorum_insufficient_gated_error"; then
  echo "expected insufficient external-gossip quorum gate failure" >&2
  exit 1
fi
cmp "$factory_transparency_external_gossip_quorum_insufficient" \
  "$factory_transparency_external_gossip_quorum_insufficient_gated"
grep -Fq 'organization quorum was not met' \
  "$factory_transparency_external_gossip_quorum_insufficient_gated_error"

if verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --transport-receipt "$factory_transparency_external_gossip_transport_a" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_quorum_unbacked_accepted" \
  --require-accepted \
  2>"$factory_transparency_external_gossip_quorum_unbacked_accepted_error"; then
  echo "expected accepted-state gate to require an external-gossip quorum" >&2
  exit 1
fi
cmp "$factory_transparency_external_gossip_quorum_insufficient" \
  "$factory_transparency_external_gossip_quorum_unbacked_accepted"
grep -Fq 'external-gossip quorum is not met' \
  "$factory_transparency_external_gossip_quorum_unbacked_accepted_error"

if verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --observation "$factory_transparency_external_gossip_remote_b_fork" \
  --transport-receipt "$factory_transparency_external_gossip_transport_a" \
  --transport-receipt "$factory_transparency_external_gossip_transport_b_fork" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_quorum_mixed_output" \
  2>"$factory_transparency_external_gossip_quorum_mixed_error"; then
  echo "expected later external-log forks to fail exact-head observer agreement" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_quorum_mixed_output"
grep -Fq 'detected split-view roots at one observer tree size' \
  "$factory_transparency_external_gossip_quorum_mixed_error"

if verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --observation "$factory_transparency_external_gossip_remote_b" \
  --transport-receipt "$factory_transparency_external_gossip_quorum_tampered_transport" \
  --transport-receipt "$factory_transparency_external_gossip_transport_b" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_quorum_tampered_output" \
  2>"$factory_transparency_external_gossip_quorum_tampered_error"; then
  echo "expected a transport response-hash substitution to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_quorum_tampered_output"
grep -Fq 'transport receipt does not bind the selected request and response' \
  "$factory_transparency_external_gossip_quorum_tampered_error"

if verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --observation "$factory_transparency_external_gossip_remote_b" \
  --transport-receipt "$factory_transparency_external_gossip_transport_a" \
  --transport-receipt "$factory_transparency_external_gossip_transport_b" \
  --evaluated-at-unix "$((factory_transparency_external_gossip_time + 10000))" \
  --output "$factory_transparency_external_gossip_quorum_stale_output" \
  2>"$factory_transparency_external_gossip_quorum_stale_error"; then
  echo "expected stale external-gossip observer receipts to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_quorum_stale_output"
grep -Fq 'receipt is stale, future-dated, expired, or precedes the selected local report' \
  "$factory_transparency_external_gossip_quorum_stale_error"

verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --observation "$factory_transparency_external_gossip_remote_b" \
  --transport-receipt "$factory_transparency_external_gossip_transport_a" \
  --transport-receipt "$factory_transparency_external_gossip_transport_b" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_quorum_report_a" \
  --require-quorum --require-accepted &
factory_transparency_external_gossip_quorum_pid_a=$!
verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --observation "$factory_transparency_external_gossip_remote_b" \
  --transport-receipt "$factory_transparency_external_gossip_transport_a" \
  --transport-receipt "$factory_transparency_external_gossip_transport_b" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_quorum_report_b" \
  --require-quorum --require-accepted &
factory_transparency_external_gossip_quorum_pid_b=$!
wait "$factory_transparency_external_gossip_quorum_pid_a"
wait "$factory_transparency_external_gossip_quorum_pid_b"
cmp "$factory_transparency_external_gossip_quorum_report_a" \
  "$factory_transparency_external_gossip_quorum_report_b"

verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_b" \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --transport-receipt "$factory_transparency_external_gossip_transport_b" \
  --transport-receipt "$factory_transparency_external_gossip_transport_a" \
  --evaluated-at-unix "$((factory_transparency_external_gossip_time + 10000))" \
  --output "$factory_transparency_external_gossip_quorum_replay" \
  --require-quorum --require-accepted
cmp "$factory_transparency_external_gossip_quorum_report_a" \
  "$factory_transparency_external_gossip_quorum_replay"

if verify_factory_transparency_external_gossip_quorum \
  --observation "$factory_transparency_external_gossip_remote_a" \
  --observation "$factory_transparency_external_gossip_remote_b_fork" \
  --transport-receipt "$factory_transparency_external_gossip_transport_a" \
  --transport-receipt "$factory_transparency_external_gossip_transport_b_fork" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_quorum_conflict_output" \
  2>"$factory_transparency_external_gossip_quorum_conflict_error"; then
  echo "expected alternate evidence for a retained observer quorum to conflict" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_quorum_conflict_output"
grep -Fq 'external gossip quorum record conflicts' \
  "$factory_transparency_external_gossip_quorum_conflict_error"

python3 - \
  "$factory_transparency_external_gossip_quorum_insufficient" \
  "$factory_transparency_external_gossip_quorum_report_a" \
  "$factory_transparency_external_consistency_report_2" \
  "$factory_transparency_external_anchor_policy" \
  "$factory_transparency_external_gossip_quorum_policy" \
  "$factory_transparency_external_gossip_remote_a" \
  "$factory_transparency_external_gossip_remote_b" \
  "$factory_transparency_external_gossip_transport_a" \
  "$factory_transparency_external_gossip_transport_b" \
  "$factory_transparency_external_gossip_quorum_policy_schema" \
  "$factory_transparency_external_gossip_observation_schema" \
  "$factory_transparency_external_gossip_remote_receipt_schema" \
  "$factory_transparency_external_gossip_quorum_report_schema" \
  "$monotonic_release_ledger" "$monotonic_key" \
  "$factory_transparency_external_gossip_private" \
  "$factory_transparency_external_gossip_private_b" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

insufficient_path, report_path, local_path, external_policy_path, quorum_policy_path, \
    observation_a_path, observation_b_path, transport_a_path, transport_b_path, \
    policy_schema_path, observation_schema_path, transport_schema_path, report_schema_path, \
    ledger_path = map(Path, sys.argv[1:15])
key, observer_a_private_path, observer_b_private_path = sys.argv[15:]
insufficient = json.loads(insufficient_path.read_bytes())
report_source = report_path.read_bytes()
report = json.loads(report_source)
local_source = local_path.read_bytes()
external_policy_source = external_policy_path.read_bytes()
quorum_policy_source = quorum_policy_path.read_bytes()
observation_sources = [observation_a_path.read_bytes(), observation_b_path.read_bytes()]
transport_sources = [transport_a_path.read_bytes(), transport_b_path.read_bytes()]

assert insufficient["status"] == "insufficient_organizations"
assert insufficient["quorum_met"] is False
assert insufficient["valid_observations"] == 1
assert report["status"] == "verified"
assert report["quorum_met"] is True
assert report["valid_observations"] == 2
assert report["distinct_organizations"] == 2
assert report["minimum_organizations"] == 2
assert report["relationship"] == "local_precedes_observed"
assert report["agreed_observed_external_tree_size"] == 6
assert report["members"][0]["organization_id"] == "independent-observer-org-a"
assert report["members"][1]["organization_id"] == "independent-observer-org-b"
assert report["members"][0]["observation"] == json.loads(observation_sources[0])
assert report["members"][1]["observation"] == json.loads(observation_sources[1])
for claim in (
    "monotonic_state_chain_verified",
    "source_checkpoint_inclusion_verified",
    "complete_source_consistency_chain_verified",
    "source_log_append_only_consistency_verified",
    "witness_quorum_verified",
    "external_anchor_verified",
    "complete_external_consistency_chain_verified",
    "external_log_append_only_consistency_verified",
    "local_external_consistency_report_identity_verified",
    "external_anchor_policy_pin_matched",
    "observer_quorum_policy_pin_matched",
    "observer_policy_role_separation_verified",
    "bounded_remote_acquisition_receipts_verified",
    "observer_pins_matched",
    "observer_receipt_signatures_verified",
    "external_tree_relationships_verified",
    "exact_observed_head_agreement_verified",
    "observed_external_checkpoints_fresh_at_evaluation",
    "distinct_organization_quorum_verified",
    "selected_observer_quorum_verified",
):
    assert report[claim] is True, claim
for claim in (
    "selected_observer_split_view_detected",
    "selected_ledger_external_gossip_quorum_report_committed",
    "global_non_equivocation_verified",
    "selected_ledger_rollback_resistance_verified",
    "trusted_time_verified",
    "independent_organization_operation_verified",
    "endpoint_transport_authenticity_verified",
    "factory_legal_identity_verified",
    "server_side_idempotency_enforced",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim

def identity(source):
    return {"bytes": len(source), "sha256": hashlib.sha256(source).hexdigest()}

assert report["local_external_consistency_report_artifact"] == identity(local_source)
assert report["external_anchor_policy_artifact"] == identity(external_policy_source)
assert report["observer_quorum_policy_artifact"] == identity(quorum_policy_source)
for member, observation_source, transport_source in zip(
    report["members"], observation_sources, transport_sources
):
    assert member["observation_artifact"] == identity(observation_source)
    assert member["transport_receipt_artifact"] == identity(transport_source)
    transport = member["transport_receipt"]
    assert transport["response_sha256"] == hashlib.sha256(observation_source).hexdigest()
    assert transport["response_bytes"] == len(observation_source)

filename_context = {
    "source_log_id": report["source_log_id"],
    "witness_policy_sha256": report["witness_policy_sha256"],
    "external_log_id": report["external_log_id"],
    "external_anchor_policy_sha256": report["external_anchor_policy_sha256"],
    "local_external_consistency_generation":
        report["local_external_consistency_generation"],
    "observer_quorum_policy_sha256": report["observer_quorum_policy_sha256"],
}
context_sha256 = hashlib.sha256(
    b"pcbex:factory-release-state-transparency-external-gossip-quorum-filename:v1\0" +
    json.dumps(filename_context, separators=(",", ":")).encode("ascii")
).hexdigest()
name = (
    f"factory-release-state-transparency-external-gossip-quorum-v1-{key}-"
    f"{report['local_external_consistency_generation']:04}-{context_sha256[:32]}.json"
)
assert (ledger_path / name).read_bytes() == report_source

secrets = [
    Path(observer_a_private_path).read_text(encoding="ascii").strip().encode(),
    Path(observer_b_private_path).read_text(encoding="ascii").strip().encode(),
    b"v1491-e2e-bearer-token",
]
for path in [report_path, transport_a_path, transport_b_path, *ledger_path.iterdir()]:
    source = path.read_bytes()
    for secret in secrets:
        assert secret not in source, path
for schema_path in (
    policy_schema_path,
    observation_schema_path,
    transport_schema_path,
    report_schema_path,
):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.492 binds every v1.491 observer to its immutable base policy and advances
# the selected current key only through one-generation, digest-chained old/new
# dual signatures retained in the same trusted ledger.
factory_transparency_external_gossip_trust_state_schema="$output_directory/factory-release-transparency-external-gossip-observer-trust-state.schema.json"
factory_transparency_external_gossip_rotation_schema="$output_directory/factory-release-transparency-external-gossip-observer-rotation.schema.json"
factory_transparency_external_gossip_trust_report_schema="$output_directory/factory-release-transparency-external-gossip-observer-trust-report.schema.json"
factory_transparency_external_gossip_trust_initial="$output_directory/factory-release-transparency-external-gossip-observer-a.initial.json"
factory_transparency_external_gossip_rotation="$output_directory/factory-release-transparency-external-gossip-observer-a.rotation.json"
factory_transparency_external_gossip_rotation_fork="$output_directory/factory-release-transparency-external-gossip-observer-a.rotation-fork.json"
factory_transparency_external_gossip_rotation_applied_a="$output_directory/factory-release-transparency-external-gossip-observer-a.applied-a.json"
factory_transparency_external_gossip_rotation_applied_b="$output_directory/factory-release-transparency-external-gossip-observer-a.applied-b.json"
factory_transparency_external_gossip_rotation_replay="$output_directory/factory-release-transparency-external-gossip-observer-a.replay.json"
factory_transparency_external_gossip_rotation_fork_output="$output_directory/factory-release-transparency-external-gossip-observer-a.fork-output.json"
factory_transparency_external_gossip_rotation_fork_error="$output_directory/factory-release-transparency-external-gossip-observer-a.fork.stderr"
factory_transparency_external_gossip_rotation_tampered="$output_directory/factory-release-transparency-external-gossip-observer-a.rotation-tampered.json"
factory_transparency_external_gossip_rotation_tampered_output="$output_directory/factory-release-transparency-external-gossip-observer-a.tampered-output.json"
factory_transparency_external_gossip_rotation_tampered_error="$output_directory/factory-release-transparency-external-gossip-observer-a.tampered.stderr"
factory_transparency_external_gossip_effective_policy="$output_directory/factory-release-transparency-external-gossip-effective.policy.json"
factory_transparency_external_gossip_effective_policy_digest_file="$output_directory/factory-release-transparency-external-gossip-effective.policy.sha256"
factory_transparency_external_gossip_rotated_observation_a_server="$output_directory/factory-release-transparency-external-gossip-rotated-observation-a.server.json"
factory_transparency_external_gossip_rotated_observation_a="$output_directory/factory-release-transparency-external-gossip-rotated-observation-a.json"
factory_transparency_external_gossip_rotated_observation_b="$output_directory/factory-release-transparency-external-gossip-rotated-observation-b.json"
factory_transparency_external_gossip_rotated_transport_a="$output_directory/factory-release-transparency-external-gossip-rotated-transport-a.json"
factory_transparency_external_gossip_rotated_transport_b="$output_directory/factory-release-transparency-external-gossip-rotated-transport-b.json"
factory_transparency_external_gossip_rotated_quorum_report="$output_directory/factory-release-transparency-external-gossip-rotated-quorum.report.json"
factory_transparency_external_gossip_trust_report_a="$output_directory/factory-release-transparency-external-gossip-observer-trust-a.report.json"
factory_transparency_external_gossip_trust_report_b="$output_directory/factory-release-transparency-external-gossip-observer-trust-b.report.json"
factory_transparency_external_gossip_trust_replay="$output_directory/factory-release-transparency-external-gossip-observer-trust-replay.report.json"
factory_transparency_external_gossip_trust_rollback_output="$output_directory/factory-release-transparency-external-gossip-observer-trust-rollback.report.json"
factory_transparency_external_gossip_trust_rollback_error="$output_directory/factory-release-transparency-external-gossip-observer-trust-rollback.stderr"
factory_transparency_external_gossip_rotation_port="$output_directory/factory-release-transparency-external-gossip-rotation.port"

"$pcbex_binary" factory-release-state-transparency-external-gossip-observer-trust-state-schema \
  --output "$factory_transparency_external_gossip_trust_state_schema"
"$pcbex_binary" signed-factory-release-state-transparency-external-gossip-observer-key-rotation-schema \
  --output "$factory_transparency_external_gossip_rotation_schema"
"$pcbex_binary" factory-release-state-transparency-external-gossip-observer-trust-verification-report-schema \
  --output "$factory_transparency_external_gossip_trust_report_schema"

python3 - \
  "$factory_transparency_external_gossip_private_a_next" \
  "$factory_transparency_external_gossip_private_a_fork" <<'PY'
from pathlib import Path
import os
import sys

next_path, fork_path = map(Path, sys.argv[1:])
next_path.write_text(bytes([73]).hex() * 32 + "\n", encoding="ascii")
fork_path.write_text(bytes([74]).hex() * 32 + "\n", encoding="ascii")
os.chmod(next_path, 0o600)
os.chmod(fork_path, 0o600)
PY

"$pcbex_binary" export-factory-release-state-transparency-external-gossip-observer-trust-state \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --organization-id independent-observer-org-a \
  --observer-id independent-observer-a \
  --output "$factory_transparency_external_gossip_trust_initial"

for successor_and_output in \
  "$factory_transparency_external_gossip_private_a_next:$factory_transparency_external_gossip_rotation" \
  "$factory_transparency_external_gossip_private_a_fork:$factory_transparency_external_gossip_rotation_fork"; do
  successor=${successor_and_output%%:*}
  rotation_output=${successor_and_output#*:}
  "$pcbex_binary" sign-factory-release-state-transparency-external-gossip-observer-key-rotation \
    --trust-state "$factory_transparency_external_gossip_trust_initial" \
    --old-private-key "$factory_transparency_external_gossip_private" \
    --new-private-key "$successor" \
    --rotated-at-unix "$((factory_transparency_external_gossip_time + 1))" \
    --output "$rotation_output"
done

apply_factory_transparency_external_gossip_rotation() {
  "$pcbex_binary" apply-factory-release-state-transparency-external-gossip-observer-key-rotation \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --rotation "$factory_transparency_external_gossip_rotation" \
    --output "$1"
}

apply_factory_transparency_external_gossip_rotation \
  "$factory_transparency_external_gossip_rotation_applied_a" &
factory_transparency_external_gossip_rotation_pid_a=$!
apply_factory_transparency_external_gossip_rotation \
  "$factory_transparency_external_gossip_rotation_applied_b" &
factory_transparency_external_gossip_rotation_pid_b=$!
wait "$factory_transparency_external_gossip_rotation_pid_a"
wait "$factory_transparency_external_gossip_rotation_pid_b"
cmp "$factory_transparency_external_gossip_rotation_applied_a" \
  "$factory_transparency_external_gossip_rotation_applied_b"

apply_factory_transparency_external_gossip_rotation \
  "$factory_transparency_external_gossip_rotation_replay"
cmp "$factory_transparency_external_gossip_rotation_applied_a" \
  "$factory_transparency_external_gossip_rotation_replay"

if "$pcbex_binary" apply-factory-release-state-transparency-external-gossip-observer-key-rotation \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --rotation "$factory_transparency_external_gossip_rotation_fork" \
  --output "$factory_transparency_external_gossip_rotation_fork_output" \
  2>"$factory_transparency_external_gossip_rotation_fork_error"; then
  echo "expected a competing external-gossip observer rotation fork to fail" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_rotation_fork_output"
grep -Fq 'conflicts with retained history' \
  "$factory_transparency_external_gossip_rotation_fork_error"

python3 - \
  "$factory_transparency_external_gossip_rotation" \
  "$factory_transparency_external_gossip_rotation_tampered" <<'PY'
import json
from pathlib import Path
import sys

source_path, output_path = map(Path, sys.argv[1:])
source = source_path.read_text(encoding="utf-8")
rotation = json.loads(source)
output_path.write_text(
    source.replace(rotation["new_signature"], "00" * 64, 1),
    encoding="utf-8",
)
PY

if "$pcbex_binary" apply-factory-release-state-transparency-external-gossip-observer-key-rotation \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --rotation "$factory_transparency_external_gossip_rotation_tampered" \
  --output "$factory_transparency_external_gossip_rotation_tampered_output" \
  2>"$factory_transparency_external_gossip_rotation_tampered_error"; then
  echo "expected a tampered external-gossip observer rotation to fail" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_rotation_tampered_output"
grep -Fq 'signature verification failed' \
  "$factory_transparency_external_gossip_rotation_tampered_error"

"$pcbex_binary" derive-factory-release-state-transparency-external-gossip-effective-quorum-policy \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --output "$factory_transparency_external_gossip_effective_policy" \
  --digest-output "$factory_transparency_external_gossip_effective_policy_digest_file"
factory_transparency_external_gossip_effective_policy_digest="$(tr -d '\r\n' < "$factory_transparency_external_gossip_effective_policy_digest_file")"

python3 - \
  "$factory_transparency_external_gossip_observation_a" \
  "$factory_transparency_external_gossip_private_a_next" \
  "$factory_transparency_external_gossip_rotated_observation_a_server" <<'PY'
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

source_path, private_path, output_path = map(Path, sys.argv[1:])
observation = json.loads(source_path.read_bytes())
receipt = observation["gossip_receipt"]
head = receipt["observed_tree_head"]
private_key = Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex(private_path.read_text(encoding="ascii").strip())
)
receipt["observer_public_key"] = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()
payload = {
    "domain":
        "pcbex-factory-release-state-transparency-external-log-gossip-receipt-v1",
    "schema_version": receipt["schema_version"],
    "receipt_scope": receipt["receipt_scope"],
    "external_anchor_policy_sha256": receipt["external_anchor_policy_sha256"],
    "external_log_id": receipt["external_log_id"],
    "observer_id": receipt["observer_id"],
    "observed_tree_head_sha256": receipt["observed_tree_head_sha256"],
    "observed_tree_size": head["tree_size"],
    "observed_root_sha256": head["root_sha256"],
    "observed_tree_head_observed_at_unix": head["observed_at_unix"],
    "external_log_public_key": head["public_key"],
    "received_at_unix": receipt["received_at_unix"],
    "expires_at_unix": receipt["expires_at_unix"],
    "algorithm": receipt["algorithm"],
    "observer_public_key": receipt["observer_public_key"],
}
receipt["signature"] = private_key.sign(
    json.dumps(payload, separators=(",", ":")).encode("ascii")
).hex()
output_path.write_text(json.dumps(observation, indent=2) + "\n", encoding="utf-8")
PY

external_gossip_rotation_server_pid=""
rm -f "$factory_transparency_external_gossip_rotation_port"
python3 - \
  "$factory_transparency_external_gossip_rotation_port" \
  "$factory_transparency_external_gossip_rotated_observation_a_server" \
  "$factory_transparency_external_gossip_observation_b" <<'PY' &
import http.server
import json
from pathlib import Path
import sys
import threading

port_path, observation_a_path, observation_b_path = map(Path, sys.argv[1:])
responses = {
    "independent-observer-a": observation_a_path.read_bytes(),
    "independent-observer-b": observation_b_path.read_bytes(),
}

class Handler(http.server.BaseHTTPRequestHandler):
    count = 0

    def do_POST(self):
        if self.path != "/v1/external-gossip":
            self.send_error(404)
            return
        size = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(size))
        body = responses[request["observer_id"]]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        type(self).count += 1
        if type(self).count == 2:
            threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, *_):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
port_path.write_text(str(server.server_address[1]), encoding="ascii")
server.serve_forever()
server.server_close()
PY
external_gossip_rotation_server_pid=$!
for _ in $(seq 1 100); do
  test -s "$factory_transparency_external_gossip_rotation_port" && break
  sleep 0.05
done
test -s "$factory_transparency_external_gossip_rotation_port"
factory_transparency_external_gossip_rotation_endpoint="http://127.0.0.1:$(cat "$factory_transparency_external_gossip_rotation_port")/v1/external-gossip"

for member in \
  "independent-observer-org-a:independent-observer-a:$factory_transparency_external_gossip_rotated_observation_a:$factory_transparency_external_gossip_rotated_transport_a" \
  "independent-observer-org-b:independent-observer-b:$factory_transparency_external_gossip_rotated_observation_b:$factory_transparency_external_gossip_rotated_transport_b"; do
  organization=${member%%:*}
  remainder=${member#*:}
  observer=${remainder%%:*}
  remainder=${remainder#*:}
  observation_output=${remainder%%:*}
  transport_output=${remainder#*:}
  "$pcbex_binary" request-factory-release-state-transparency-external-gossip-observation \
    --local-external-consistency-report "$factory_transparency_external_consistency_report_2" \
    --external-anchor-policy "$factory_transparency_external_anchor_policy" \
    --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
    --external-log-id kicad-e2e-external-anchor-log \
    --observer-quorum-policy "$factory_transparency_external_gossip_effective_policy" \
    --expected-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_effective_policy_digest" \
    --organization-id "$organization" \
    --observer-id "$observer" \
    --endpoint "$factory_transparency_external_gossip_rotation_endpoint" \
    --timeout-seconds 30 \
    --evaluated-at-unix "$factory_transparency_external_gossip_time" \
    --output "$observation_output" \
    --receipt-output "$transport_output" \
    --allow-http-loopback
done
wait "$external_gossip_rotation_server_pid"
external_gossip_rotation_server_pid=""

"$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --observer-quorum-policy "$factory_transparency_external_gossip_effective_policy" \
  --expected-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_effective_policy_digest" \
  --observation "$factory_transparency_external_gossip_rotated_observation_a" \
  --observation "$factory_transparency_external_gossip_rotated_observation_b" \
  --transport-receipt "$factory_transparency_external_gossip_rotated_transport_a" \
  --transport-receipt "$factory_transparency_external_gossip_rotated_transport_b" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_rotated_quorum_report" \
  --require-quorum --require-accepted

verify_factory_transparency_external_gossip_trust() {
  "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-observer-trust \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --effective-observer-quorum-policy "$factory_transparency_external_gossip_effective_policy" \
    --expected-effective-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_effective_policy_digest" \
    --quorum-report "$factory_transparency_external_gossip_rotated_quorum_report" \
    --require-quorum --require-accepted \
    --output "$1"
}

verify_factory_transparency_external_gossip_trust \
  "$factory_transparency_external_gossip_trust_report_a" &
factory_transparency_external_gossip_trust_pid_a=$!
verify_factory_transparency_external_gossip_trust \
  "$factory_transparency_external_gossip_trust_report_b" &
factory_transparency_external_gossip_trust_pid_b=$!
wait "$factory_transparency_external_gossip_trust_pid_a"
wait "$factory_transparency_external_gossip_trust_pid_b"
cmp "$factory_transparency_external_gossip_trust_report_a" \
  "$factory_transparency_external_gossip_trust_report_b"
verify_factory_transparency_external_gossip_trust \
  "$factory_transparency_external_gossip_trust_replay"
cmp "$factory_transparency_external_gossip_trust_report_a" \
  "$factory_transparency_external_gossip_trust_replay"

if "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-observer-trust \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --effective-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-effective-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --quorum-report "$factory_transparency_external_gossip_quorum_report_a" \
  --output "$factory_transparency_external_gossip_trust_rollback_output" \
  2>"$factory_transparency_external_gossip_trust_rollback_error"; then
  echo "expected an old observer policy to fail after selected-ledger rotation" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_trust_rollback_output"
grep -Fq 'does not match the complete observer rotation histories' \
  "$factory_transparency_external_gossip_trust_rollback_error"

python3 - \
  "$factory_transparency_external_gossip_trust_initial" \
  "$factory_transparency_external_gossip_rotation" \
  "$factory_transparency_external_gossip_rotation_applied_a" \
  "$factory_transparency_external_gossip_quorum_policy" \
  "$factory_transparency_external_gossip_effective_policy" \
  "$factory_transparency_external_gossip_rotated_quorum_report" \
  "$factory_transparency_external_gossip_trust_report_a" \
  "$factory_transparency_external_gossip_trust_state_schema" \
  "$factory_transparency_external_gossip_rotation_schema" \
  "$factory_transparency_external_gossip_trust_report_schema" \
  "$monotonic_release_ledger" \
  "$factory_transparency_external_gossip_private" \
  "$factory_transparency_external_gossip_private_a_next" \
  "$factory_transparency_external_gossip_private_a_fork" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

initial_path, rotation_path, applied_path, base_path, effective_path, \
    quorum_path, report_path, state_schema_path, rotation_schema_path, \
    report_schema_path, ledger_path, old_private_path, next_private_path, \
    fork_private_path = map(Path, sys.argv[1:])

initial = json.loads(initial_path.read_bytes())
rotation_source = rotation_path.read_bytes()
rotation = json.loads(rotation_source)
applied = json.loads(applied_path.read_bytes())
base_source = base_path.read_bytes()
base = json.loads(base_source)
effective_source = effective_path.read_bytes()
effective = json.loads(effective_source)
quorum_source = quorum_path.read_bytes()
quorum = json.loads(quorum_source)
report_source = report_path.read_bytes()
report = json.loads(report_source)

assert initial["generation"] == 0
assert initial["current_public_key"] == base["trusted_observers"][0]["public_key"]
assert applied["generation"] == 1
assert applied["last_rotation_sha256"] == hashlib.sha256(
    json.dumps(rotation, separators=(",", ":")).encode("ascii")
).hexdigest()
assert rotation["from_generation"] == 0 and rotation["to_generation"] == 1
assert rotation["previous_rotation_sha256"] is None
assert rotation["old_public_key"] == initial["current_public_key"]
assert rotation["new_public_key"] == applied["current_public_key"]
assert rotation["old_signature"] != rotation["new_signature"]
assert effective["trusted_observers"][0]["public_key"] == applied["current_public_key"]
assert effective["trusted_observers"][1]["public_key"] == base["trusted_observers"][1]["public_key"]
assert quorum["observer_quorum_policy"] == effective

assert report["status"] == "verified"
assert report["quorum_met"] is True
assert report["observer_rotation_count"] == 1
assert report["base_observer_quorum_policy"] == base
assert report["effective_observer_quorum_policy"] == effective
assert report["quorum_report"] == quorum
assert report["observer_trust"][0]["current_trust_state"] == applied
assert len(report["observer_trust"][0]["rotations"]) == 1
assert report["observer_trust"][0]["rotations"][0]["rotation"] == rotation
assert report["observer_trust"][1]["current_trust_state"]["generation"] == 0
assert report["observer_trust"][1]["rotations"] == []
for claim in (
    "base_observer_quorum_policy_pin_matched",
    "complete_observer_rotation_histories_verified",
    "observer_rotation_dual_signatures_verified",
    "observer_rotation_generation_chains_verified",
    "observer_rotation_digest_chains_verified",
    "observer_rotation_timestamps_monotonic",
    "effective_observer_quorum_policy_derived",
    "effective_observer_quorum_policy_pin_matched",
    "current_observer_trust_bound_to_quorum",
    "selected_ledger_latest_observer_rotations_verified",
):
    assert report[claim] is True, claim
for claim in (
    "selected_ledger_rollback_resistance_verified",
    "global_non_equivocation_verified",
    "trusted_time_verified",
    "independent_organization_operation_verified",
    "factory_legal_identity_verified",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim

def identity(source):
    return {"bytes": len(source), "sha256": hashlib.sha256(source).hexdigest()}

assert report["base_observer_quorum_policy_artifact"] == identity(base_source)
assert report["effective_observer_quorum_policy_artifact"] == identity(effective_source)
assert report["quorum_report_artifact"] == identity(quorum_source)
assert report["observer_trust"][0]["rotations"][0]["artifact"] == identity(rotation_source)

rotation_records = list(ledger_path.glob(
    "factory-release-state-transparency-external-gossip-observer-rotation-v1-*.json"
))
assert len(rotation_records) == 1
assert rotation_records[0].read_bytes() == rotation_source
trust_records = list(ledger_path.glob(
    "factory-release-state-transparency-external-gossip-observer-trust-v1-*.json"
))
assert len(trust_records) == 1
assert trust_records[0].read_bytes() == report_source

secrets = [
    old_private_path.read_text(encoding="ascii").strip().encode(),
    next_private_path.read_text(encoding="ascii").strip().encode(),
    fork_private_path.read_text(encoding="ascii").strip().encode(),
]
for artifact in [report_path, *ledger_path.iterdir()]:
    source = artifact.read_bytes()
    for secret in secrets:
        assert secret not in source, artifact

for schema_path in (state_schema_path, rotation_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.493 independently pins an authority-governed organization registry. Each
# selected quorum member must remain active and bind its exact latest v1.492
# observer trust state before the registry-bound report can be retained.
factory_transparency_external_gossip_registry_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry.schema.json"
factory_transparency_external_gossip_registry_transition_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-transition.schema.json"
factory_transparency_external_gossip_registry_report_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-report.schema.json"
factory_transparency_external_gossip_registry_authority_public="$output_directory/factory-release-transparency-external-gossip-registry-authority.public.hex"
factory_transparency_external_gossip_registry_genesis="$output_directory/factory-release-transparency-external-gossip-organization-registry.genesis.json"
factory_transparency_external_gossip_registry_genesis_digest_file="$output_directory/factory-release-transparency-external-gossip-organization-registry.genesis.sha256"
factory_transparency_external_gossip_registry_initial="$output_directory/factory-release-transparency-external-gossip-organization-registry.initial.json"
factory_transparency_external_gossip_registry_observer_a="$output_directory/factory-release-transparency-external-gossip-registry-observer-a.json"
factory_transparency_external_gossip_registry_observer_b="$output_directory/factory-release-transparency-external-gossip-registry-observer-b.json"
factory_transparency_external_gossip_registry_admission_a="$output_directory/factory-release-transparency-external-gossip-registry-admission-a.json"
factory_transparency_external_gossip_registry_admission_b="$output_directory/factory-release-transparency-external-gossip-registry-admission-b.json"
factory_transparency_external_gossip_registry_state_1="$output_directory/factory-release-transparency-external-gossip-organization-registry.state-1.json"
factory_transparency_external_gossip_registry_state_2="$output_directory/factory-release-transparency-external-gossip-organization-registry.state-2.json"
factory_transparency_external_gossip_registry_report_a="$output_directory/factory-release-transparency-external-gossip-organization-registry-a.report.json"
factory_transparency_external_gossip_registry_report_b="$output_directory/factory-release-transparency-external-gossip-organization-registry-b.report.json"
factory_transparency_external_gossip_registry_replay="$output_directory/factory-release-transparency-external-gossip-organization-registry-replay.report.json"
factory_transparency_external_gossip_registry_suspend="$output_directory/factory-release-transparency-external-gossip-registry-suspend-a.json"
factory_transparency_external_gossip_registry_state_3="$output_directory/factory-release-transparency-external-gossip-organization-registry.state-3.json"
factory_transparency_external_gossip_registry_suspended_output="$output_directory/factory-release-transparency-external-gossip-organization-registry-suspended.report.json"
factory_transparency_external_gossip_registry_suspended_error="$output_directory/factory-release-transparency-external-gossip-organization-registry-suspended.stderr"
factory_transparency_external_gossip_registry_reason_sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

"$pcbex_binary" factory-release-state-transparency-external-gossip-organization-registry-schema \
  --output "$factory_transparency_external_gossip_registry_schema"
"$pcbex_binary" signed-factory-release-state-transparency-external-gossip-organization-registry-transition-schema \
  --output "$factory_transparency_external_gossip_registry_transition_schema"
"$pcbex_binary" factory-release-state-transparency-external-gossip-organization-registry-verification-report-schema \
  --output "$factory_transparency_external_gossip_registry_report_schema"

python3 - \
  "$factory_transparency_external_gossip_registry_authority_private" \
  "$factory_transparency_external_gossip_registry_authority_public" <<'PY'
from pathlib import Path
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private_path, public_path = map(Path, sys.argv[1:])
seed = bytes([75]) * 32
private_key = Ed25519PrivateKey.from_private_bytes(seed)
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
private_path.write_text(seed.hex() + "\n", encoding="ascii")
public_path.write_text(public_key.hex() + "\n", encoding="ascii")
os.chmod(private_path, 0o600)
PY

"$pcbex_binary" init-factory-release-state-transparency-external-gossip-organization-registry \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-id production-external-observers \
  --authority-public-key "$factory_transparency_external_gossip_registry_authority_public" \
  --output "$factory_transparency_external_gossip_registry_genesis" \
  --digest-output "$factory_transparency_external_gossip_registry_genesis_digest_file"
factory_transparency_external_gossip_registry_genesis_digest="$(tr -d '\r\n' < "$factory_transparency_external_gossip_registry_genesis_digest_file")"

"$pcbex_binary" export-factory-release-state-transparency-external-gossip-organization-registry \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_genesis_digest" \
  --output "$factory_transparency_external_gossip_registry_initial"
cmp "$factory_transparency_external_gossip_registry_genesis" \
  "$factory_transparency_external_gossip_registry_initial"

for observer in \
  "independent-observer-org-a:independent-observer-a:$factory_transparency_external_gossip_registry_observer_a" \
  "independent-observer-org-b:independent-observer-b:$factory_transparency_external_gossip_registry_observer_b"; do
  organization=${observer%%:*}
  remainder=${observer#*:}
  observer_id=${remainder%%:*}
  observer_output=${remainder#*:}
  "$pcbex_binary" export-factory-release-state-transparency-external-gossip-observer-trust-state \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --organization-id "$organization" \
    --observer-id "$observer_id" \
    --output "$observer_output"
done

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --registry-state "$factory_transparency_external_gossip_registry_initial" \
  --authority-private-key "$factory_transparency_external_gossip_registry_authority_private" \
  --action admit-observer \
  --organization-id independent-observer-org-a \
  --observer-trust-state "$factory_transparency_external_gossip_registry_observer_a" \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_admission_a"

apply_factory_transparency_external_gossip_registry_transition() {
  "$pcbex_binary" apply-factory-release-state-transparency-external-gossip-organization-registry-transition \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --registry-genesis "$factory_transparency_external_gossip_registry_genesis" \
    --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_genesis_digest" \
    --transition "$1" \
    --output "$2"
}

apply_factory_transparency_external_gossip_registry_transition \
  "$factory_transparency_external_gossip_registry_admission_a" \
  "$factory_transparency_external_gossip_registry_state_1"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --registry-state "$factory_transparency_external_gossip_registry_state_1" \
  --authority-private-key "$factory_transparency_external_gossip_registry_authority_private" \
  --action admit-observer \
  --organization-id independent-observer-org-b \
  --observer-trust-state "$factory_transparency_external_gossip_registry_observer_b" \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_admission_b"
apply_factory_transparency_external_gossip_registry_transition \
  "$factory_transparency_external_gossip_registry_admission_b" \
  "$factory_transparency_external_gossip_registry_state_2"

verify_factory_transparency_external_gossip_registry() {
  "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --registry-genesis "$factory_transparency_external_gossip_registry_genesis" \
    --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_genesis_digest" \
    --observer-trust-report "$factory_transparency_external_gossip_trust_report_a" \
    --require-quorum --require-accepted \
    --output "$1"
}

verify_factory_transparency_external_gossip_registry \
  "$factory_transparency_external_gossip_registry_report_a" &
factory_transparency_external_gossip_registry_pid_a=$!
verify_factory_transparency_external_gossip_registry \
  "$factory_transparency_external_gossip_registry_report_b" &
factory_transparency_external_gossip_registry_pid_b=$!
wait "$factory_transparency_external_gossip_registry_pid_a"
wait "$factory_transparency_external_gossip_registry_pid_b"
cmp "$factory_transparency_external_gossip_registry_report_a" \
  "$factory_transparency_external_gossip_registry_report_b"
verify_factory_transparency_external_gossip_registry \
  "$factory_transparency_external_gossip_registry_replay"
cmp "$factory_transparency_external_gossip_registry_report_a" \
  "$factory_transparency_external_gossip_registry_replay"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --registry-state "$factory_transparency_external_gossip_registry_state_2" \
  --authority-private-key "$factory_transparency_external_gossip_registry_authority_private" \
  --action suspend-organization \
  --organization-id independent-observer-org-a \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_suspend"
apply_factory_transparency_external_gossip_registry_transition \
  "$factory_transparency_external_gossip_registry_suspend" \
  "$factory_transparency_external_gossip_registry_state_3"

if verify_factory_transparency_external_gossip_registry \
  "$factory_transparency_external_gossip_registry_suspended_output" \
  2>"$factory_transparency_external_gossip_registry_suspended_error"; then
  echo "expected a suspended external-gossip organization to invalidate the selected quorum" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_registry_suspended_output"
grep -Fq 'organization independent-observer-org-a is not active' \
  "$factory_transparency_external_gossip_registry_suspended_error"

python3 - \
  "$factory_transparency_external_gossip_registry_genesis" \
  "$factory_transparency_external_gossip_registry_genesis_digest_file" \
  "$factory_transparency_external_gossip_registry_admission_a" \
  "$factory_transparency_external_gossip_registry_admission_b" \
  "$factory_transparency_external_gossip_registry_state_2" \
  "$factory_transparency_external_gossip_registry_state_3" \
  "$factory_transparency_external_gossip_trust_report_a" \
  "$factory_transparency_external_gossip_registry_report_a" \
  "$factory_transparency_external_gossip_registry_schema" \
  "$factory_transparency_external_gossip_registry_transition_schema" \
  "$factory_transparency_external_gossip_registry_report_schema" \
  "$monotonic_release_ledger" \
  "$factory_transparency_external_gossip_registry_authority_private" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

genesis_path, genesis_digest_path, transition_a_path, transition_b_path, \
    state_2_path, state_3_path, trust_path, report_path, registry_schema_path, \
    transition_schema_path, report_schema_path, ledger_path, authority_private_path = \
    map(Path, sys.argv[1:])

genesis_source = genesis_path.read_bytes()
genesis = json.loads(genesis_source)
transition_sources = [transition_a_path.read_bytes(), transition_b_path.read_bytes()]
transitions = [json.loads(source) for source in transition_sources]
state_2 = json.loads(state_2_path.read_bytes())
state_3 = json.loads(state_3_path.read_bytes())
trust_source = trust_path.read_bytes()
trust = json.loads(trust_source)
report_source = report_path.read_bytes()
report = json.loads(report_source)

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

def identity(source):
    return {"bytes": len(source), "sha256": hashlib.sha256(source).hexdigest()}

assert genesis["generation"] == 0
assert genesis["organizations"] == []
assert genesis["last_transition_sha256"] is None
assert genesis["last_updated_at_unix"] is None
assert genesis_digest_path.read_text(encoding="ascii").strip() == hashlib.sha256(
    compact(genesis)
).hexdigest()
assert transitions[0]["from_generation"] == 0
assert transitions[0]["to_generation"] == 1
assert transitions[0]["previous_transition_sha256"] is None
assert transitions[1]["from_generation"] == 1
assert transitions[1]["to_generation"] == 2
assert transitions[1]["previous_transition_sha256"] == hashlib.sha256(
    compact(transitions[0])
).hexdigest()
assert state_2["generation"] == 2
assert [entry["status"] for entry in state_2["organizations"]] == ["active", "active"]
assert state_3["generation"] == 3
assert state_3["organizations"][0]["status"] == "suspended"

assert report["status"] == "verified"
assert report["quorum_met"] is True
assert report["registry_transition_count"] == 2
assert report["registry_genesis"] == genesis
assert report["current_registry"] == state_2
assert report["observer_trust_report"] == trust
assert report["registry_genesis_artifact"] == identity(genesis_source)
assert report["observer_trust_report_artifact"] == identity(trust_source)
for index, source in enumerate(transition_sources):
    assert report["registry_transitions"][index]["artifact"] == identity(source)
    assert report["registry_transitions"][index]["transition"] == transitions[index]
for claim in (
    "registry_genesis_pin_matched",
    "complete_registry_history_verified",
    "registry_authority_signatures_verified",
    "registry_generation_chain_verified",
    "registry_digest_chain_verified",
    "registry_timestamps_monotonic",
    "registry_authority_role_separation_verified",
    "current_observer_trust_admissions_verified",
    "selected_observer_organizations_active",
    "registry_effective_before_quorum_evaluation_verified",
    "selected_ledger_latest_registry_verified",
    "selected_ledger_observer_trust_report_verified",
    "selected_ledger_latest_observer_rotations_verified",
):
    assert report[claim] is True, claim
for claim in (
    "selected_ledger_registry_bound_report_committed",
    "selected_ledger_rollback_resistance_verified",
    "global_non_equivocation_verified",
    "trusted_time_verified",
    "independent_organization_operation_verified",
    "factory_legal_identity_verified",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim

transition_records = list(ledger_path.glob(
    "factory-release-state-transparency-external-gossip-organization-registry-transition-v1-*.json"
))
assert len(transition_records) == 3
registry_reports = list(ledger_path.glob(
    "factory-release-state-transparency-external-gossip-organization-registry-v1-*.json"
))
assert len(registry_reports) == 1
assert registry_reports[0].read_bytes() == report_source

secret = authority_private_path.read_text(encoding="ascii").strip().encode()
for artifact in [report_path, state_2_path, state_3_path, *ledger_path.iterdir()]:
    assert secret not in artifact.read_bytes(), artifact

for schema_path in (registry_schema_path, transition_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.494 rotates the organization-registry authority with signatures from both
# the retained and successor keys. The new verifier replays transitions and
# rotations as one generation chain; the v1.493 verifier rejects that history.
factory_transparency_external_gossip_registry_rotation_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-authority-rotation.schema.json"
factory_transparency_external_gossip_registry_rotation_report_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-authority-rotation-report.schema.json"
factory_transparency_external_gossip_registry_rotation_new_private="$output_directory/factory-release-transparency-external-gossip-registry-rotation-new.private.hex"
factory_transparency_external_gossip_registry_rotation_genesis="$output_directory/factory-release-transparency-external-gossip-organization-registry-rotation.genesis.json"
factory_transparency_external_gossip_registry_rotation_genesis_digest_file="$output_directory/factory-release-transparency-external-gossip-organization-registry-rotation.genesis.sha256"
factory_transparency_external_gossip_registry_rotation_initial="$output_directory/factory-release-transparency-external-gossip-organization-registry-rotation.initial.json"
factory_transparency_external_gossip_registry_rotation_admission_a="$output_directory/factory-release-transparency-external-gossip-registry-rotation-admission-a.json"
factory_transparency_external_gossip_registry_rotation_admission_b="$output_directory/factory-release-transparency-external-gossip-registry-rotation-admission-b.json"
factory_transparency_external_gossip_registry_rotation_state_1="$output_directory/factory-release-transparency-external-gossip-organization-registry-rotation.state-1.json"
factory_transparency_external_gossip_registry_rotation_state_2="$output_directory/factory-release-transparency-external-gossip-organization-registry-rotation.state-2.json"
factory_transparency_external_gossip_registry_rotation_artifact="$output_directory/factory-release-transparency-external-gossip-registry-authority-rotation.json"
factory_transparency_external_gossip_registry_rotation_state_3="$output_directory/factory-release-transparency-external-gossip-organization-registry-rotation.state-3.json"
factory_transparency_external_gossip_registry_rotation_report="$output_directory/factory-release-transparency-external-gossip-organization-registry-authority-rotation.report.json"
factory_transparency_external_gossip_registry_rotation_replay="$output_directory/factory-release-transparency-external-gossip-organization-registry-authority-rotation-replay.report.json"
factory_transparency_external_gossip_registry_rotation_legacy_output="$output_directory/factory-release-transparency-external-gossip-organization-registry-authority-rotation-legacy.report.json"
factory_transparency_external_gossip_registry_rotation_legacy_error="$output_directory/factory-release-transparency-external-gossip-organization-registry-authority-rotation-legacy.stderr"

"$pcbex_binary" signed-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-schema \
  --output "$factory_transparency_external_gossip_registry_rotation_schema"
"$pcbex_binary" factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-verification-report-schema \
  --output "$factory_transparency_external_gossip_registry_rotation_report_schema"

python3 - "$factory_transparency_external_gossip_registry_rotation_new_private" <<'PY'
from pathlib import Path
import os
import sys

private_path = Path(sys.argv[1])
private_path.write_text((bytes([76]) * 32).hex() + "\n", encoding="ascii")
os.chmod(private_path, 0o600)
PY

"$pcbex_binary" init-factory-release-state-transparency-external-gossip-organization-registry \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-id rotating-production-external-observers \
  --authority-public-key "$factory_transparency_external_gossip_registry_authority_public" \
  --output "$factory_transparency_external_gossip_registry_rotation_genesis" \
  --digest-output "$factory_transparency_external_gossip_registry_rotation_genesis_digest_file"
factory_transparency_external_gossip_registry_rotation_genesis_digest="$(tr -d '\r\n' < "$factory_transparency_external_gossip_registry_rotation_genesis_digest_file")"

"$pcbex_binary" export-factory-release-state-transparency-external-gossip-organization-registry \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_rotation_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_rotation_genesis_digest" \
  --output "$factory_transparency_external_gossip_registry_rotation_initial"

apply_factory_transparency_external_gossip_registry_rotation_transition() {
  "$pcbex_binary" apply-factory-release-state-transparency-external-gossip-organization-registry-transition \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --registry-genesis "$factory_transparency_external_gossip_registry_rotation_genesis" \
    --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_rotation_genesis_digest" \
    --transition "$1" \
    --output "$2"
}

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --registry-state "$factory_transparency_external_gossip_registry_rotation_initial" \
  --authority-private-key "$factory_transparency_external_gossip_registry_authority_private" \
  --action admit-observer \
  --organization-id independent-observer-org-a \
  --observer-trust-state "$factory_transparency_external_gossip_registry_observer_a" \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_rotation_admission_a"
apply_factory_transparency_external_gossip_registry_rotation_transition \
  "$factory_transparency_external_gossip_registry_rotation_admission_a" \
  "$factory_transparency_external_gossip_registry_rotation_state_1"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --registry-state "$factory_transparency_external_gossip_registry_rotation_state_1" \
  --authority-private-key "$factory_transparency_external_gossip_registry_authority_private" \
  --action admit-observer \
  --organization-id independent-observer-org-b \
  --observer-trust-state "$factory_transparency_external_gossip_registry_observer_b" \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_rotation_admission_b"
apply_factory_transparency_external_gossip_registry_rotation_transition \
  "$factory_transparency_external_gossip_registry_rotation_admission_b" \
  "$factory_transparency_external_gossip_registry_rotation_state_2"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation \
  --registry-state "$factory_transparency_external_gossip_registry_rotation_state_2" \
  --old-authority-private-key "$factory_transparency_external_gossip_registry_authority_private" \
  --new-authority-private-key "$factory_transparency_external_gossip_registry_rotation_new_private" \
  --rotated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_rotation_artifact"
"$pcbex_binary" apply-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_rotation_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_rotation_genesis_digest" \
  --rotation "$factory_transparency_external_gossip_registry_rotation_artifact" \
  --output "$factory_transparency_external_gossip_registry_rotation_state_3"

verify_factory_transparency_external_gossip_registry_authority_rotation() {
  "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-authority-rotation \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --registry-genesis "$factory_transparency_external_gossip_registry_rotation_genesis" \
    --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_rotation_genesis_digest" \
    --observer-trust-report "$factory_transparency_external_gossip_trust_report_a" \
    --require-quorum --require-accepted \
    --output "$1"
}

verify_factory_transparency_external_gossip_registry_authority_rotation \
  "$factory_transparency_external_gossip_registry_rotation_report"
verify_factory_transparency_external_gossip_registry_authority_rotation \
  "$factory_transparency_external_gossip_registry_rotation_replay"
cmp "$factory_transparency_external_gossip_registry_rotation_report" \
  "$factory_transparency_external_gossip_registry_rotation_replay"

if "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_rotation_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_rotation_genesis_digest" \
  --observer-trust-report "$factory_transparency_external_gossip_trust_report_a" \
  --output "$factory_transparency_external_gossip_registry_rotation_legacy_output" \
  2>"$factory_transparency_external_gossip_registry_rotation_legacy_error"; then
  echo "expected the v1.493 registry verifier to reject an authority rotation" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_registry_rotation_legacy_output"
grep -Fq 'v1.493 organization registry verifier cannot accept authority rotations' \
  "$factory_transparency_external_gossip_registry_rotation_legacy_error"

python3 - \
  "$factory_transparency_external_gossip_registry_rotation_genesis" \
  "$factory_transparency_external_gossip_registry_rotation_admission_a" \
  "$factory_transparency_external_gossip_registry_rotation_admission_b" \
  "$factory_transparency_external_gossip_registry_rotation_artifact" \
  "$factory_transparency_external_gossip_registry_rotation_state_2" \
  "$factory_transparency_external_gossip_registry_rotation_state_3" \
  "$factory_transparency_external_gossip_registry_rotation_report" \
  "$factory_transparency_external_gossip_registry_rotation_schema" \
  "$factory_transparency_external_gossip_registry_rotation_report_schema" \
  "$monotonic_release_ledger" \
  "$factory_transparency_external_gossip_registry_authority_private" \
  "$factory_transparency_external_gossip_registry_rotation_new_private" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

genesis_path, transition_a_path, transition_b_path, rotation_path, state_2_path, \
    state_3_path, report_path, rotation_schema_path, report_schema_path, \
    ledger_path, old_private_path, new_private_path = map(Path, sys.argv[1:])

genesis_source = genesis_path.read_bytes()
transition_sources = [transition_a_path.read_bytes(), transition_b_path.read_bytes()]
rotation_source = rotation_path.read_bytes()
genesis = json.loads(genesis_source)
transitions = [json.loads(source) for source in transition_sources]
rotation = json.loads(rotation_source)
state_2 = json.loads(state_2_path.read_bytes())
state_3 = json.loads(state_3_path.read_bytes())
report_source = report_path.read_bytes()
report = json.loads(report_source)

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

def identity(source):
    return {"bytes": len(source), "sha256": hashlib.sha256(source).hexdigest()}

assert rotation["from_generation"] == 2
assert rotation["to_generation"] == 3
assert rotation["previous_transition_sha256"] == hashlib.sha256(
    compact(transitions[1])
).hexdigest()
assert rotation["old_public_key"] == state_2["authority_public_key"]
assert rotation["new_public_key"] == state_3["authority_public_key"]
assert state_3["organizations"] == state_2["organizations"]

assert report["status"] == "verified"
assert report["quorum_met"] is True
assert report["registry_history_event_count"] == 3
assert report["registry_authority_rotation_count"] == 1
assert report["registry_genesis"] == genesis
assert report["current_registry"] == state_3
assert [event["kind"] for event in report["registry_history_events"]] == [
    "organization_transition", "organization_transition", "authority_key_rotation"
]
for index, source in enumerate(transition_sources):
    evidence = report["registry_history_events"][index]
    assert evidence["artifact"] == identity(source)
    assert evidence["transition"] == transitions[index]
rotation_evidence = report["registry_history_events"][2]
assert rotation_evidence["artifact"] == identity(rotation_source)
assert rotation_evidence["rotation"] == rotation
for claim in (
    "registry_genesis_pin_matched",
    "complete_registry_history_verified",
    "registry_authority_transition_signatures_verified",
    "registry_authority_rotation_dual_signatures_verified",
    "registry_authority_successor_possession_verified",
    "registry_authority_key_history_unique",
    "registry_generation_chain_verified",
    "registry_digest_chain_verified",
    "registry_timestamps_monotonic",
    "registry_authority_role_separation_verified",
    "current_observer_trust_admissions_verified",
    "selected_observer_organizations_active",
    "registry_effective_before_quorum_evaluation_verified",
    "selected_ledger_latest_registry_verified",
    "selected_ledger_observer_trust_report_verified",
    "selected_ledger_latest_observer_rotations_verified",
):
    assert report[claim] is True, claim
for claim in (
    "selected_ledger_registry_bound_report_committed",
    "selected_ledger_rollback_resistance_verified",
    "authority_threshold_governance_verified",
    "global_non_equivocation_verified",
    "trusted_time_verified",
    "independent_organization_operation_verified",
    "factory_legal_identity_verified",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim

rotation_records = list(ledger_path.glob(
    "factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-v1-*.json"
))
assert len(rotation_records) == 1
assert rotation_records[0].read_bytes() == rotation_source
report_records = list(ledger_path.glob(
    "factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-v1-*.json"
))
assert len(report_records) == 1
assert report_records[0].read_bytes() == report_source

secrets = [
    old_private_path.read_text(encoding="ascii").strip().encode(),
    new_private_path.read_text(encoding="ascii").strip().encode(),
]
for artifact in [report_path, state_3_path, *ledger_path.iterdir()]:
    source = artifact.read_bytes()
    for secret in secrets:
        assert secret not in source, artifact

for schema_path in (rotation_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.495 replaces root-only registry mutation with a root-authorized 2-of-3
# governance policy. The threshold-aware verifier replays legacy transitions,
# a root rotation, and threshold-approved transitions as one exact history.
factory_transparency_external_gossip_registry_governance_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-governance.schema.json"
factory_transparency_external_gossip_registry_threshold_transition_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold-transition.schema.json"
factory_transparency_external_gossip_registry_threshold_report_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold-governance-report.schema.json"
factory_transparency_external_gossip_registry_threshold_root_private="$output_directory/factory-release-transparency-external-gossip-registry-threshold-root.private.hex"
factory_transparency_external_gossip_registry_threshold_root_public="$output_directory/factory-release-transparency-external-gossip-registry-threshold-root.public.hex"
factory_transparency_external_gossip_registry_threshold_next_root_private="$output_directory/factory-release-transparency-external-gossip-registry-threshold-next-root.private.hex"
factory_transparency_external_gossip_registry_threshold_next_root_public="$output_directory/factory-release-transparency-external-gossip-registry-threshold-next-root.public.hex"
factory_transparency_external_gossip_registry_threshold_authority_a_private="$output_directory/factory-release-transparency-external-gossip-registry-threshold-authority-a.private.hex"
factory_transparency_external_gossip_registry_threshold_authority_a_public="$output_directory/factory-release-transparency-external-gossip-registry-threshold-authority-a.public.hex"
factory_transparency_external_gossip_registry_threshold_authority_b_private="$output_directory/factory-release-transparency-external-gossip-registry-threshold-authority-b.private.hex"
factory_transparency_external_gossip_registry_threshold_authority_b_public="$output_directory/factory-release-transparency-external-gossip-registry-threshold-authority-b.public.hex"
factory_transparency_external_gossip_registry_threshold_authority_c_private="$output_directory/factory-release-transparency-external-gossip-registry-threshold-authority-c.private.hex"
factory_transparency_external_gossip_registry_threshold_authority_c_public="$output_directory/factory-release-transparency-external-gossip-registry-threshold-authority-c.public.hex"
factory_transparency_external_gossip_registry_threshold_genesis="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold.genesis.json"
factory_transparency_external_gossip_registry_threshold_genesis_digest_file="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold.genesis.sha256"
factory_transparency_external_gossip_registry_threshold_initial="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold.initial.json"
factory_transparency_external_gossip_registry_threshold_admission_a="$output_directory/factory-release-transparency-external-gossip-registry-threshold-legacy-admission-a.json"
factory_transparency_external_gossip_registry_threshold_state_1="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold.state-1.json"
factory_transparency_external_gossip_registry_threshold_root_rotation="$output_directory/factory-release-transparency-external-gossip-registry-threshold-root-rotation.json"
factory_transparency_external_gossip_registry_threshold_state_2="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold.state-2.json"
factory_transparency_external_gossip_registry_governance="$output_directory/factory-release-transparency-external-gossip-registry-governance.json"
factory_transparency_external_gossip_registry_threshold_admission_b="$output_directory/factory-release-transparency-external-gossip-registry-threshold-admission-b.json"
factory_transparency_external_gossip_registry_threshold_state_3="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold.state-3.json"
factory_transparency_external_gossip_registry_threshold_report="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold-governance.report.json"
factory_transparency_external_gossip_registry_threshold_replay="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold-governance-replay.report.json"
factory_transparency_external_gossip_registry_threshold_legacy_output="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold-legacy.report.json"
factory_transparency_external_gossip_registry_threshold_legacy_error="$output_directory/factory-release-transparency-external-gossip-organization-registry-threshold-legacy.stderr"
factory_transparency_external_gossip_registry_threshold_root_only_output="$output_directory/factory-release-transparency-external-gossip-registry-threshold-root-only.json"
factory_transparency_external_gossip_registry_threshold_root_only_error="$output_directory/factory-release-transparency-external-gossip-registry-threshold-root-only.stderr"

"$pcbex_binary" signed-factory-release-state-transparency-external-gossip-organization-registry-governance-schema \
  --output "$factory_transparency_external_gossip_registry_governance_schema"
"$pcbex_binary" signed-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-schema \
  --output "$factory_transparency_external_gossip_registry_threshold_transition_schema"
"$pcbex_binary" factory-release-state-transparency-external-gossip-organization-registry-threshold-governance-verification-report-schema \
  --output "$factory_transparency_external_gossip_registry_threshold_report_schema"

python3 - \
  "$factory_transparency_external_gossip_registry_threshold_root_private" \
  "$factory_transparency_external_gossip_registry_threshold_root_public" \
  "$factory_transparency_external_gossip_registry_threshold_next_root_private" \
  "$factory_transparency_external_gossip_registry_threshold_next_root_public" \
  "$factory_transparency_external_gossip_registry_threshold_authority_a_private" \
  "$factory_transparency_external_gossip_registry_threshold_authority_a_public" \
  "$factory_transparency_external_gossip_registry_threshold_authority_b_private" \
  "$factory_transparency_external_gossip_registry_threshold_authority_b_public" \
  "$factory_transparency_external_gossip_registry_threshold_authority_c_private" \
  "$factory_transparency_external_gossip_registry_threshold_authority_c_public" <<'PY'
from pathlib import Path
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

root_private, root_public, next_root_private, next_root_public, \
    authority_a_private, authority_a_public, authority_b_private, \
    authority_b_public, authority_c_private, authority_c_public = \
    map(Path, sys.argv[1:])

def write_keypair(private_path, public_path, marker):
    seed = bytes([marker]) * 32
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_path.write_text(seed.hex() + "\n", encoding="ascii")
    public_path.write_text(public_key.hex() + "\n", encoding="ascii")
    os.chmod(private_path, 0o600)

write_keypair(root_private, root_public, 80)
write_keypair(next_root_private, next_root_public, 81)
write_keypair(authority_a_private, authority_a_public, 82)
write_keypair(authority_b_private, authority_b_public, 83)
write_keypair(authority_c_private, authority_c_public, 84)
PY

"$pcbex_binary" init-factory-release-state-transparency-external-gossip-organization-registry \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-id threshold-production-external-observers \
  --authority-public-key "$factory_transparency_external_gossip_registry_threshold_root_public" \
  --output "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --digest-output "$factory_transparency_external_gossip_registry_threshold_genesis_digest_file"
factory_transparency_external_gossip_registry_threshold_genesis_digest="$(tr -d '\r\n' < "$factory_transparency_external_gossip_registry_threshold_genesis_digest_file")"

"$pcbex_binary" export-factory-release-state-transparency-external-gossip-organization-registry \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
  --output "$factory_transparency_external_gossip_registry_threshold_initial"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --registry-state "$factory_transparency_external_gossip_registry_threshold_initial" \
  --authority-private-key "$factory_transparency_external_gossip_registry_threshold_root_private" \
  --action admit-observer \
  --organization-id independent-observer-org-a \
  --observer-trust-state "$factory_transparency_external_gossip_registry_observer_a" \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_threshold_admission_a"
"$pcbex_binary" apply-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
  --transition "$factory_transparency_external_gossip_registry_threshold_admission_a" \
  --output "$factory_transparency_external_gossip_registry_threshold_state_1"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation \
  --registry-state "$factory_transparency_external_gossip_registry_threshold_state_1" \
  --old-authority-private-key "$factory_transparency_external_gossip_registry_threshold_root_private" \
  --new-authority-private-key "$factory_transparency_external_gossip_registry_threshold_next_root_private" \
  --rotated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_threshold_root_rotation"
"$pcbex_binary" apply-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
  --rotation "$factory_transparency_external_gossip_registry_threshold_root_rotation" \
  --output "$factory_transparency_external_gossip_registry_threshold_state_2"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-governance \
  --registry-state "$factory_transparency_external_gossip_registry_threshold_state_2" \
  --registry-authority-private-key "$factory_transparency_external_gossip_registry_threshold_next_root_private" \
  --minimum-approvals 2 \
  --authority-id registry-admin-c \
  --authority-public-key "$factory_transparency_external_gossip_registry_threshold_authority_c_public" \
  --authority-id registry-admin-a \
  --authority-public-key "$factory_transparency_external_gossip_registry_threshold_authority_a_public" \
  --authority-id registry-admin-b \
  --authority-public-key "$factory_transparency_external_gossip_registry_threshold_authority_b_public" \
  --issued-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_governance"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition \
  --registry-state "$factory_transparency_external_gossip_registry_threshold_state_2" \
  --governance "$factory_transparency_external_gossip_registry_governance" \
  --authority-id registry-admin-c \
  --authority-private-key "$factory_transparency_external_gossip_registry_threshold_authority_c_private" \
  --authority-id registry-admin-a \
  --authority-private-key "$factory_transparency_external_gossip_registry_threshold_authority_a_private" \
  --action admit-observer \
  --organization-id independent-observer-org-b \
  --observer-trust-state "$factory_transparency_external_gossip_registry_observer_b" \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_threshold_admission_b"
"$pcbex_binary" apply-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
  --transition "$factory_transparency_external_gossip_registry_threshold_admission_b" \
  --output "$factory_transparency_external_gossip_registry_threshold_state_3"

verify_factory_transparency_external_gossip_registry_threshold_governance() {
  "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-threshold-governance \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
    --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
    --observer-trust-report "$factory_transparency_external_gossip_trust_report_a" \
    --require-quorum --require-accepted \
    --output "$1"
}

verify_factory_transparency_external_gossip_registry_threshold_governance \
  "$factory_transparency_external_gossip_registry_threshold_report"
verify_factory_transparency_external_gossip_registry_threshold_governance \
  "$factory_transparency_external_gossip_registry_threshold_replay"
cmp "$factory_transparency_external_gossip_registry_threshold_report" \
  "$factory_transparency_external_gossip_registry_threshold_replay"

if "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-authority-rotation \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
  --observer-trust-report "$factory_transparency_external_gossip_trust_report_a" \
  --output "$factory_transparency_external_gossip_registry_threshold_legacy_output" \
  2>"$factory_transparency_external_gossip_registry_threshold_legacy_error"; then
  echo "expected the v1.494 registry verifier to reject threshold governance" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_registry_threshold_legacy_output"
grep -Fq 'authority-rotation registry verifier cannot accept threshold-governed history' \
  "$factory_transparency_external_gossip_registry_threshold_legacy_error"

if "$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --registry-state "$factory_transparency_external_gossip_registry_threshold_state_3" \
  --authority-private-key "$factory_transparency_external_gossip_registry_threshold_next_root_private" \
  --action suspend-organization \
  --organization-id independent-observer-org-a \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_threshold_root_only_output" \
  2>"$factory_transparency_external_gossip_registry_threshold_root_only_error"; then
  echo "expected active threshold governance to reject root-only mutation" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_registry_threshold_root_only_output"
grep -Fq 'rejects root-only transitions' \
  "$factory_transparency_external_gossip_registry_threshold_root_only_error"

python3 - \
  "$factory_transparency_external_gossip_registry_threshold_genesis" \
  "$factory_transparency_external_gossip_registry_threshold_admission_a" \
  "$factory_transparency_external_gossip_registry_threshold_root_rotation" \
  "$factory_transparency_external_gossip_registry_governance" \
  "$factory_transparency_external_gossip_registry_threshold_admission_b" \
  "$factory_transparency_external_gossip_registry_threshold_state_2" \
  "$factory_transparency_external_gossip_registry_threshold_state_3" \
  "$factory_transparency_external_gossip_registry_threshold_report" \
  "$factory_transparency_external_gossip_registry_governance_schema" \
  "$factory_transparency_external_gossip_registry_threshold_transition_schema" \
  "$factory_transparency_external_gossip_registry_threshold_report_schema" \
  "$monotonic_release_ledger" \
  "$factory_transparency_external_gossip_registry_threshold_root_private" \
  "$factory_transparency_external_gossip_registry_threshold_next_root_private" \
  "$factory_transparency_external_gossip_registry_threshold_authority_a_private" \
  "$factory_transparency_external_gossip_registry_threshold_authority_b_private" \
  "$factory_transparency_external_gossip_registry_threshold_authority_c_private" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

genesis_path, legacy_path, rotation_path, governance_path, threshold_path, \
    state_2_path, state_3_path, report_path, governance_schema_path, \
    threshold_schema_path, report_schema_path, ledger_path, *private_paths = \
    map(Path, sys.argv[1:])

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

def identity(source):
    return {"bytes": len(source), "sha256": hashlib.sha256(source).hexdigest()}

genesis_source = genesis_path.read_bytes()
legacy_source = legacy_path.read_bytes()
rotation_source = rotation_path.read_bytes()
governance_source = governance_path.read_bytes()
threshold_source = threshold_path.read_bytes()
genesis = json.loads(genesis_source)
legacy = json.loads(legacy_source)
rotation = json.loads(rotation_source)
governance = json.loads(governance_source)
threshold = json.loads(threshold_source)
state_2 = json.loads(state_2_path.read_bytes())
state_3 = json.loads(state_3_path.read_bytes())
report_source = report_path.read_bytes()
report = json.loads(report_source)

governance_sha256 = hashlib.sha256(compact(governance)).hexdigest()
assert governance["registry_generation"] == 2
assert governance["registry_state_sha256"] == hashlib.sha256(compact(state_2)).hexdigest()
assert governance["minimum_approvals"] == 2
assert [item["authority_id"] for item in governance["authorities"]] == [
    "registry-admin-a", "registry-admin-b", "registry-admin-c"
]
assert threshold["from_generation"] == 2
assert threshold["to_generation"] == 3
assert threshold["previous_transition_sha256"] == hashlib.sha256(compact(rotation)).hexdigest()
assert threshold["governance_sha256"] == governance_sha256
assert threshold["governance"] == governance
assert [item["authority_id"] for item in threshold["approvals"]] == [
    "registry-admin-a", "registry-admin-c"
]
assert state_3["active_governance_sha256"] == governance_sha256

assert report["status"] == "verified"
assert report["quorum_met"] is True
assert report["registry_history_event_count"] == 3
assert report["registry_authority_rotation_count"] == 1
assert report["registry_threshold_transition_count"] == 1
assert report["registry_genesis"] == genesis
assert report["current_registry"] == state_3
assert report["active_governance"] == governance
assert report["active_governance_sha256"] == governance_sha256
assert [event["kind"] for event in report["registry_history_events"]] == [
    "organization_transition", "authority_key_rotation", "threshold_transition"
]
for event, source in zip(
    report["registry_history_events"],
    [legacy_source, rotation_source, threshold_source],
):
    assert event["artifact"] == identity(source)
for claim in (
    "registry_genesis_pin_matched",
    "complete_registry_history_verified",
    "registry_authority_transition_signatures_verified",
    "registry_authority_rotation_dual_signatures_verified",
    "registry_authority_successor_possession_verified",
    "registry_authority_key_history_unique",
    "governance_root_signature_verified",
    "governance_authority_identities_unique",
    "governance_authority_keys_unique",
    "governance_threshold_approvals_verified",
    "root_only_registry_mutations_locked_out",
    "registry_generation_chain_verified",
    "registry_digest_chain_verified",
    "registry_timestamps_monotonic",
    "registry_authority_role_separation_verified",
    "current_observer_trust_admissions_verified",
    "selected_observer_organizations_active",
    "registry_effective_before_quorum_evaluation_verified",
    "selected_ledger_latest_registry_verified",
    "selected_ledger_observer_trust_report_verified",
    "selected_ledger_latest_observer_rotations_verified",
    "authority_threshold_governance_verified",
):
    assert report[claim] is True, claim
for claim in (
    "selected_ledger_registry_bound_report_committed",
    "selected_ledger_rollback_resistance_verified",
    "global_non_equivocation_verified",
    "trusted_time_verified",
    "independent_organization_operation_verified",
    "factory_legal_identity_verified",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim

threshold_records = list(ledger_path.glob(
    "factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-v1-*.json"
))
assert len(threshold_records) == 1
assert threshold_records[0].read_bytes() == threshold_source
report_records = list(ledger_path.glob(
    "factory-release-state-transparency-external-gossip-organization-registry-threshold-governance-v1-*.json"
))
assert len(report_records) == 1
assert report_records[0].read_bytes() == report_source

secrets = [path.read_text(encoding="ascii").strip().encode() for path in private_paths]
for artifact in [governance_path, threshold_path, report_path, state_3_path, *ledger_path.iterdir()]:
    source = artifact.read_bytes()
    for secret in secrets:
        assert secret not in source, artifact

for schema_path in (governance_schema_path, threshold_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.496 changes the active policy only after both the retained 2-of-3 and
# successor 3-of-3 quorums approve one state-bound rotation.
factory_transparency_external_gossip_registry_governance_rotation_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-governance-rotation.schema.json"
factory_transparency_external_gossip_registry_governance_rotation_report_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-governance-rotation-report.schema.json"
factory_transparency_external_gossip_registry_successor_authority_d_private="$output_directory/factory-release-transparency-external-gossip-registry-successor-authority-d.private.hex"
factory_transparency_external_gossip_registry_successor_authority_d_public="$output_directory/factory-release-transparency-external-gossip-registry-successor-authority-d.public.hex"
factory_transparency_external_gossip_registry_successor_authority_e_private="$output_directory/factory-release-transparency-external-gossip-registry-successor-authority-e.private.hex"
factory_transparency_external_gossip_registry_successor_authority_e_public="$output_directory/factory-release-transparency-external-gossip-registry-successor-authority-e.public.hex"
factory_transparency_external_gossip_registry_successor_authority_f_private="$output_directory/factory-release-transparency-external-gossip-registry-successor-authority-f.private.hex"
factory_transparency_external_gossip_registry_successor_authority_f_public="$output_directory/factory-release-transparency-external-gossip-registry-successor-authority-f.public.hex"
factory_transparency_external_gossip_registry_successor_governance="$output_directory/factory-release-transparency-external-gossip-registry-successor-governance.json"
factory_transparency_external_gossip_registry_governance_rotation="$output_directory/factory-release-transparency-external-gossip-registry-governance-rotation.json"
factory_transparency_external_gossip_registry_governance_rotation_state_4="$output_directory/factory-release-transparency-external-gossip-organization-registry-governance-rotation.state-4.json"
factory_transparency_external_gossip_registry_governance_rotation_report="$output_directory/factory-release-transparency-external-gossip-organization-registry-governance-rotation.report.json"
factory_transparency_external_gossip_registry_governance_rotation_replay="$output_directory/factory-release-transparency-external-gossip-organization-registry-governance-rotation-replay.report.json"
factory_transparency_external_gossip_registry_governance_rotation_legacy_output="$output_directory/factory-release-transparency-external-gossip-organization-registry-governance-rotation-legacy.report.json"
factory_transparency_external_gossip_registry_governance_rotation_legacy_error="$output_directory/factory-release-transparency-external-gossip-organization-registry-governance-rotation-legacy.stderr"
factory_transparency_external_gossip_registry_old_governance_output="$output_directory/factory-release-transparency-external-gossip-registry-old-governance-transition.json"
factory_transparency_external_gossip_registry_old_governance_error="$output_directory/factory-release-transparency-external-gossip-registry-old-governance-transition.stderr"
factory_transparency_external_gossip_registry_successor_transition="$output_directory/factory-release-transparency-external-gossip-registry-successor-transition.json"

"$pcbex_binary" signed-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-schema \
  --output "$factory_transparency_external_gossip_registry_governance_rotation_schema"
"$pcbex_binary" factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-verification-report-schema \
  --output "$factory_transparency_external_gossip_registry_governance_rotation_report_schema"

python3 - \
  "$factory_transparency_external_gossip_registry_successor_authority_d_private" \
  "$factory_transparency_external_gossip_registry_successor_authority_d_public" \
  "$factory_transparency_external_gossip_registry_successor_authority_e_private" \
  "$factory_transparency_external_gossip_registry_successor_authority_e_public" \
  "$factory_transparency_external_gossip_registry_successor_authority_f_private" \
  "$factory_transparency_external_gossip_registry_successor_authority_f_public" <<'PY'
from pathlib import Path
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

paths = list(map(Path, sys.argv[1:]))

def write_keypair(private_path, public_path, marker):
    seed = bytes([marker]) * 32
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_path.write_text(seed.hex() + "\n", encoding="ascii")
    public_path.write_text(public_key.hex() + "\n", encoding="ascii")
    os.chmod(private_path, 0o600)

write_keypair(paths[0], paths[1], 85)
write_keypair(paths[2], paths[3], 86)
write_keypair(paths[4], paths[5], 87)
PY

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-successor-governance \
  --registry-state "$factory_transparency_external_gossip_registry_threshold_state_3" \
  --registry-authority-private-key "$factory_transparency_external_gossip_registry_threshold_next_root_private" \
  --minimum-approvals 3 \
  --authority-id registry-admin-f \
  --authority-public-key "$factory_transparency_external_gossip_registry_successor_authority_f_public" \
  --authority-id registry-admin-d \
  --authority-public-key "$factory_transparency_external_gossip_registry_successor_authority_d_public" \
  --authority-id registry-admin-e \
  --authority-public-key "$factory_transparency_external_gossip_registry_successor_authority_e_public" \
  --issued-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_successor_governance"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation \
  --registry-state "$factory_transparency_external_gossip_registry_threshold_state_3" \
  --old-governance "$factory_transparency_external_gossip_registry_governance" \
  --new-governance "$factory_transparency_external_gossip_registry_successor_governance" \
  --old-authority-id registry-admin-b \
  --old-authority-private-key "$factory_transparency_external_gossip_registry_threshold_authority_b_private" \
  --old-authority-id registry-admin-a \
  --old-authority-private-key "$factory_transparency_external_gossip_registry_threshold_authority_a_private" \
  --new-authority-id registry-admin-f \
  --new-authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_f_private" \
  --new-authority-id registry-admin-d \
  --new-authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_d_private" \
  --new-authority-id registry-admin-e \
  --new-authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_e_private" \
  --rotated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_governance_rotation"

"$pcbex_binary" apply-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
  --rotation "$factory_transparency_external_gossip_registry_governance_rotation" \
  --output "$factory_transparency_external_gossip_registry_governance_rotation_state_4"

verify_factory_transparency_external_gossip_registry_governance_rotation() {
  "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-governance-rotation \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
    --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
    --observer-trust-report "$factory_transparency_external_gossip_trust_report_a" \
    --require-quorum --require-accepted \
    --output "$1"
}

verify_factory_transparency_external_gossip_registry_governance_rotation \
  "$factory_transparency_external_gossip_registry_governance_rotation_report"
verify_factory_transparency_external_gossip_registry_governance_rotation \
  "$factory_transparency_external_gossip_registry_governance_rotation_replay"
cmp "$factory_transparency_external_gossip_registry_governance_rotation_report" \
  "$factory_transparency_external_gossip_registry_governance_rotation_replay"

if "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-threshold-governance \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
  --observer-trust-report "$factory_transparency_external_gossip_trust_report_a" \
  --output "$factory_transparency_external_gossip_registry_governance_rotation_legacy_output" \
  2>"$factory_transparency_external_gossip_registry_governance_rotation_legacy_error"; then
  echo "expected the v1.495 registry verifier to reject governance rotation" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_registry_governance_rotation_legacy_output"
grep -Fq 'threshold-governance history event' \
  "$factory_transparency_external_gossip_registry_governance_rotation_legacy_error"

if "$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition \
  --registry-state "$factory_transparency_external_gossip_registry_governance_rotation_state_4" \
  --governance "$factory_transparency_external_gossip_registry_governance" \
  --authority-id registry-admin-a \
  --authority-private-key "$factory_transparency_external_gossip_registry_threshold_authority_a_private" \
  --authority-id registry-admin-b \
  --authority-private-key "$factory_transparency_external_gossip_registry_threshold_authority_b_private" \
  --action suspend-organization \
  --organization-id independent-observer-org-a \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_old_governance_output" \
  2>"$factory_transparency_external_gossip_registry_old_governance_error"; then
  echo "expected rotated registry to reject the old governance" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_registry_old_governance_output"
grep -Fq 'retained active governance' \
  "$factory_transparency_external_gossip_registry_old_governance_error"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition \
  --registry-state "$factory_transparency_external_gossip_registry_governance_rotation_state_4" \
  --governance "$factory_transparency_external_gossip_registry_successor_governance" \
  --authority-id registry-admin-d \
  --authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_d_private" \
  --authority-id registry-admin-e \
  --authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_e_private" \
  --authority-id registry-admin-f \
  --authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_f_private" \
  --action suspend-organization \
  --organization-id independent-observer-org-a \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_successor_transition"

python3 - \
  "$factory_transparency_external_gossip_registry_threshold_genesis" \
  "$factory_transparency_external_gossip_registry_threshold_admission_a" \
  "$factory_transparency_external_gossip_registry_threshold_root_rotation" \
  "$factory_transparency_external_gossip_registry_governance" \
  "$factory_transparency_external_gossip_registry_threshold_admission_b" \
  "$factory_transparency_external_gossip_registry_threshold_state_3" \
  "$factory_transparency_external_gossip_registry_successor_governance" \
  "$factory_transparency_external_gossip_registry_governance_rotation" \
  "$factory_transparency_external_gossip_registry_governance_rotation_state_4" \
  "$factory_transparency_external_gossip_registry_governance_rotation_report" \
  "$factory_transparency_external_gossip_registry_governance_rotation_schema" \
  "$factory_transparency_external_gossip_registry_governance_rotation_report_schema" \
  "$monotonic_release_ledger" \
  "$factory_transparency_external_gossip_registry_threshold_root_private" \
  "$factory_transparency_external_gossip_registry_threshold_next_root_private" \
  "$factory_transparency_external_gossip_registry_threshold_authority_a_private" \
  "$factory_transparency_external_gossip_registry_threshold_authority_b_private" \
  "$factory_transparency_external_gossip_registry_threshold_authority_c_private" \
  "$factory_transparency_external_gossip_registry_successor_authority_d_private" \
  "$factory_transparency_external_gossip_registry_successor_authority_e_private" \
  "$factory_transparency_external_gossip_registry_successor_authority_f_private" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys

genesis_path, legacy_path, root_rotation_path, old_governance_path, \
    threshold_path, state_3_path, new_governance_path, governance_rotation_path, \
    state_4_path, report_path, rotation_schema_path, report_schema_path, \
    ledger_path, *private_paths = map(Path, sys.argv[1:])

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

def identity(source):
    return {"bytes": len(source), "sha256": hashlib.sha256(source).hexdigest()}

genesis_source = genesis_path.read_bytes()
legacy_source = legacy_path.read_bytes()
root_rotation_source = root_rotation_path.read_bytes()
threshold_source = threshold_path.read_bytes()
governance_rotation_source = governance_rotation_path.read_bytes()
old_governance = json.loads(old_governance_path.read_bytes())
new_governance = json.loads(new_governance_path.read_bytes())
state_3 = json.loads(state_3_path.read_bytes())
state_4 = json.loads(state_4_path.read_bytes())
governance_rotation = json.loads(governance_rotation_source)
report_source = report_path.read_bytes()
report = json.loads(report_source)

old_governance_sha256 = hashlib.sha256(compact(old_governance)).hexdigest()
new_governance_sha256 = hashlib.sha256(compact(new_governance)).hexdigest()
assert new_governance["registry_generation"] == 3
assert new_governance["registry_state_sha256"] == hashlib.sha256(compact(state_3)).hexdigest()
assert new_governance["minimum_approvals"] == 3
assert [item["authority_id"] for item in new_governance["authorities"]] == [
    "registry-admin-d", "registry-admin-e", "registry-admin-f"
]
assert governance_rotation["from_generation"] == 3
assert governance_rotation["to_generation"] == 4
assert governance_rotation["previous_transition_sha256"] == hashlib.sha256(compact(json.loads(threshold_source))).hexdigest()
assert governance_rotation["old_governance_sha256"] == old_governance_sha256
assert governance_rotation["new_governance_sha256"] == new_governance_sha256
assert governance_rotation["old_governance"] == old_governance
assert governance_rotation["new_governance"] == new_governance
assert [item["authority_id"] for item in governance_rotation["old_approvals"]] == [
    "registry-admin-a", "registry-admin-b"
]
assert [item["authority_id"] for item in governance_rotation["new_approvals"]] == [
    "registry-admin-d", "registry-admin-e", "registry-admin-f"
]
assert state_4["generation"] == 4
assert state_4["active_governance_sha256"] == new_governance_sha256
assert state_4["organizations"] == state_3["organizations"]
assert state_4["authority_public_key"] == state_3["authority_public_key"]

assert report["status"] == "verified"
assert report["quorum_met"] is True
assert report["registry_history_event_count"] == 4
assert report["registry_authority_rotation_count"] == 1
assert report["registry_threshold_transition_count"] == 1
assert report["registry_governance_rotation_count"] == 1
assert report["current_registry"] == state_4
assert report["active_governance"] == new_governance
assert report["active_governance_sha256"] == new_governance_sha256
assert [event["kind"] for event in report["registry_history_events"]] == [
    "organization_transition", "authority_key_rotation", "threshold_transition",
    "governance_rotation"
]
for event, source in zip(
    report["registry_history_events"],
    [legacy_source, root_rotation_source, threshold_source, governance_rotation_source],
):
    assert event["artifact"] == identity(source)
for claim in (
    "registry_genesis_pin_matched",
    "complete_registry_history_verified",
    "registry_authority_transition_signatures_verified",
    "registry_authority_rotation_dual_signatures_verified",
    "registry_authority_successor_possession_verified",
    "registry_authority_key_history_unique",
    "governance_root_signatures_verified",
    "governance_authority_identities_unique",
    "governance_authority_keys_unique",
    "governance_threshold_approvals_verified",
    "governance_rotation_old_quorum_verified",
    "governance_rotation_new_quorum_verified",
    "successor_governance_state_binding_verified",
    "root_only_registry_mutations_locked_out",
    "registry_generation_chain_verified",
    "registry_digest_chain_verified",
    "registry_timestamps_monotonic",
    "registry_authority_role_separation_verified",
    "current_observer_trust_admissions_verified",
    "selected_observer_organizations_active",
    "registry_effective_before_quorum_evaluation_verified",
    "selected_ledger_latest_registry_verified",
    "selected_ledger_observer_trust_report_verified",
    "selected_ledger_latest_observer_rotations_verified",
    "authority_threshold_governance_verified",
):
    assert report[claim] is True, claim
for claim in (
    "selected_ledger_registry_bound_report_committed",
    "selected_ledger_rollback_resistance_verified",
    "global_non_equivocation_verified",
    "trusted_time_verified",
    "independent_governance_control_verified",
    "independent_organization_operation_verified",
    "factory_legal_identity_verified",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim

rotation_record_name = re.compile(
    r"factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-v1-[0-9a-f]{32}-[0-9]{4}\.json"
)
report_record_name = re.compile(
    r"factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-v1-[0-9a-f]{64}-[0-9]{4}-[0-9a-f]{32}\.json"
)
rotation_records = [
    path for path in ledger_path.iterdir()
    if rotation_record_name.fullmatch(path.name)
]
assert len(rotation_records) == 1
assert rotation_records[0].read_bytes() == governance_rotation_source
report_records = [
    path for path in ledger_path.iterdir()
    if report_record_name.fullmatch(path.name)
]
assert len(report_records) == 1
assert report_records[0].read_bytes() == report_source

secrets = [path.read_text(encoding="ascii").strip().encode() for path in private_paths]
for artifact in [new_governance_path, governance_rotation_path, report_path, state_4_path, *ledger_path.iterdir()]:
    source = artifact.read_bytes()
    for secret in secrets:
        assert secret not in source, artifact

for schema_path in (rotation_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.497 rotates the registry root and active governance atomically only after
# the retained and successor governance quorums approve one state-bound event.
factory_transparency_external_gossip_registry_governed_rotation_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-governed-authority-rotation.schema.json"
factory_transparency_external_gossip_registry_governed_rotation_report_schema="$output_directory/factory-release-transparency-external-gossip-organization-registry-governed-authority-rotation-report.schema.json"
factory_transparency_external_gossip_registry_successor_root_private="$output_directory/factory-release-transparency-external-gossip-registry-successor-root.private.hex"
factory_transparency_external_gossip_registry_successor_root_public="$output_directory/factory-release-transparency-external-gossip-registry-successor-root.public.hex"
factory_transparency_external_gossip_registry_governed_authority_g_private="$output_directory/factory-release-transparency-external-gossip-registry-governed-authority-g.private.hex"
factory_transparency_external_gossip_registry_governed_authority_g_public="$output_directory/factory-release-transparency-external-gossip-registry-governed-authority-g.public.hex"
factory_transparency_external_gossip_registry_governed_authority_h_private="$output_directory/factory-release-transparency-external-gossip-registry-governed-authority-h.private.hex"
factory_transparency_external_gossip_registry_governed_authority_h_public="$output_directory/factory-release-transparency-external-gossip-registry-governed-authority-h.public.hex"
factory_transparency_external_gossip_registry_governed_authority_i_private="$output_directory/factory-release-transparency-external-gossip-registry-governed-authority-i.private.hex"
factory_transparency_external_gossip_registry_governed_authority_i_public="$output_directory/factory-release-transparency-external-gossip-registry-governed-authority-i.public.hex"
factory_transparency_external_gossip_registry_successor_root_governance="$output_directory/factory-release-transparency-external-gossip-registry-successor-root-governance.json"
factory_transparency_external_gossip_registry_governed_rotation="$output_directory/factory-release-transparency-external-gossip-registry-governed-authority-rotation.json"
factory_transparency_external_gossip_registry_governed_rotation_state_5="$output_directory/factory-release-transparency-external-gossip-organization-registry-governed-authority-rotation.state-5.json"
factory_transparency_external_gossip_registry_governed_rotation_report="$output_directory/factory-release-transparency-external-gossip-organization-registry-governed-authority-rotation.report.json"
factory_transparency_external_gossip_registry_governed_rotation_replay="$output_directory/factory-release-transparency-external-gossip-organization-registry-governed-authority-rotation-replay.report.json"
factory_transparency_external_gossip_registry_governed_rotation_legacy_output="$output_directory/factory-release-transparency-external-gossip-organization-registry-governed-authority-rotation-legacy.report.json"
factory_transparency_external_gossip_registry_governed_rotation_legacy_error="$output_directory/factory-release-transparency-external-gossip-organization-registry-governed-authority-rotation-legacy.stderr"
factory_transparency_external_gossip_registry_pre_root_governance_output="$output_directory/factory-release-transparency-external-gossip-registry-pre-root-governance-transition.json"
factory_transparency_external_gossip_registry_pre_root_governance_error="$output_directory/factory-release-transparency-external-gossip-registry-pre-root-governance-transition.stderr"
factory_transparency_external_gossip_registry_successor_root_transition="$output_directory/factory-release-transparency-external-gossip-registry-successor-root-transition.json"

"$pcbex_binary" signed-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-schema \
  --output "$factory_transparency_external_gossip_registry_governed_rotation_schema"
"$pcbex_binary" factory-release-state-transparency-external-gossip-organization-registry-governed-authority-rotation-verification-report-schema \
  --output "$factory_transparency_external_gossip_registry_governed_rotation_report_schema"

python3 - \
  "$factory_transparency_external_gossip_registry_successor_root_private" \
  "$factory_transparency_external_gossip_registry_successor_root_public" \
  "$factory_transparency_external_gossip_registry_governed_authority_g_private" \
  "$factory_transparency_external_gossip_registry_governed_authority_g_public" \
  "$factory_transparency_external_gossip_registry_governed_authority_h_private" \
  "$factory_transparency_external_gossip_registry_governed_authority_h_public" \
  "$factory_transparency_external_gossip_registry_governed_authority_i_private" \
  "$factory_transparency_external_gossip_registry_governed_authority_i_public" <<'PY'
from pathlib import Path
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

paths = list(map(Path, sys.argv[1:]))

def write_keypair(private_path, public_path, marker):
    seed = bytes([marker]) * 32
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_path.write_text(seed.hex() + "\n", encoding="ascii")
    public_path.write_text(public_key.hex() + "\n", encoding="ascii")
    os.chmod(private_path, 0o600)

write_keypair(paths[0], paths[1], 88)
write_keypair(paths[2], paths[3], 89)
write_keypair(paths[4], paths[5], 90)
write_keypair(paths[6], paths[7], 91)
PY

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-successor-root-governance \
  --registry-state "$factory_transparency_external_gossip_registry_governance_rotation_state_4" \
  --successor-registry-authority-private-key "$factory_transparency_external_gossip_registry_successor_root_private" \
  --minimum-approvals 2 \
  --authority-id registry-admin-i \
  --authority-public-key "$factory_transparency_external_gossip_registry_governed_authority_i_public" \
  --authority-id registry-admin-g \
  --authority-public-key "$factory_transparency_external_gossip_registry_governed_authority_g_public" \
  --authority-id registry-admin-h \
  --authority-public-key "$factory_transparency_external_gossip_registry_governed_authority_h_public" \
  --issued-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_successor_root_governance"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation \
  --registry-state "$factory_transparency_external_gossip_registry_governance_rotation_state_4" \
  --old-governance "$factory_transparency_external_gossip_registry_successor_governance" \
  --new-governance "$factory_transparency_external_gossip_registry_successor_root_governance" \
  --old-authority-id registry-admin-f \
  --old-authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_f_private" \
  --old-authority-id registry-admin-d \
  --old-authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_d_private" \
  --old-authority-id registry-admin-e \
  --old-authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_e_private" \
  --new-authority-id registry-admin-h \
  --new-authority-private-key "$factory_transparency_external_gossip_registry_governed_authority_h_private" \
  --new-authority-id registry-admin-g \
  --new-authority-private-key "$factory_transparency_external_gossip_registry_governed_authority_g_private" \
  --rotated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_governed_rotation"

"$pcbex_binary" apply-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
  --rotation "$factory_transparency_external_gossip_registry_governed_rotation" \
  --output "$factory_transparency_external_gossip_registry_governed_rotation_state_5"

verify_factory_transparency_external_gossip_registry_governed_rotation() {
  "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-governed-authority-rotation \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
    --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
    --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
    --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
    --observer-trust-report "$factory_transparency_external_gossip_trust_report_a" \
    --require-quorum --require-accepted \
    --output "$1"
}

verify_factory_transparency_external_gossip_registry_governed_rotation \
  "$factory_transparency_external_gossip_registry_governed_rotation_report"
verify_factory_transparency_external_gossip_registry_governed_rotation \
  "$factory_transparency_external_gossip_registry_governed_rotation_replay"
cmp "$factory_transparency_external_gossip_registry_governed_rotation_report" \
  "$factory_transparency_external_gossip_registry_governed_rotation_replay"

if "$pcbex_binary" verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-governance-rotation \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --base-observer-quorum-policy "$factory_transparency_external_gossip_quorum_policy" \
  --expected-base-observer-quorum-policy-sha256 "$factory_transparency_external_gossip_quorum_policy_digest" \
  --registry-genesis "$factory_transparency_external_gossip_registry_threshold_genesis" \
  --expected-registry-genesis-sha256 "$factory_transparency_external_gossip_registry_threshold_genesis_digest" \
  --observer-trust-report "$factory_transparency_external_gossip_trust_report_a" \
  --output "$factory_transparency_external_gossip_registry_governed_rotation_legacy_output" \
  2>"$factory_transparency_external_gossip_registry_governed_rotation_legacy_error"; then
  echo "expected the v1.496 registry verifier to reject governed authority rotation" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_registry_governed_rotation_legacy_output"
grep -Fq 'governance-rotation history event' \
  "$factory_transparency_external_gossip_registry_governed_rotation_legacy_error"

if "$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition \
  --registry-state "$factory_transparency_external_gossip_registry_governed_rotation_state_5" \
  --governance "$factory_transparency_external_gossip_registry_successor_governance" \
  --authority-id registry-admin-d \
  --authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_d_private" \
  --authority-id registry-admin-e \
  --authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_e_private" \
  --authority-id registry-admin-f \
  --authority-private-key "$factory_transparency_external_gossip_registry_successor_authority_f_private" \
  --action suspend-organization \
  --organization-id independent-observer-org-a \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_pre_root_governance_output" \
  2>"$factory_transparency_external_gossip_registry_pre_root_governance_error"; then
  echo "expected the governed registry root to reject pre-rotation governance" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_registry_pre_root_governance_output"
grep -Fq 'retained root trust' \
  "$factory_transparency_external_gossip_registry_pre_root_governance_error"

"$pcbex_binary" sign-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition \
  --registry-state "$factory_transparency_external_gossip_registry_governed_rotation_state_5" \
  --governance "$factory_transparency_external_gossip_registry_successor_root_governance" \
  --authority-id registry-admin-g \
  --authority-private-key "$factory_transparency_external_gossip_registry_governed_authority_g_private" \
  --authority-id registry-admin-h \
  --authority-private-key "$factory_transparency_external_gossip_registry_governed_authority_h_private" \
  --action suspend-organization \
  --organization-id independent-observer-org-a \
  --reason-sha256 "$factory_transparency_external_gossip_registry_reason_sha256" \
  --effective-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_registry_successor_root_transition"

python3 - \
  "$factory_transparency_external_gossip_registry_threshold_genesis" \
  "$factory_transparency_external_gossip_registry_threshold_admission_a" \
  "$factory_transparency_external_gossip_registry_threshold_root_rotation" \
  "$factory_transparency_external_gossip_registry_threshold_admission_b" \
  "$factory_transparency_external_gossip_registry_governance_rotation" \
  "$factory_transparency_external_gossip_registry_governed_rotation" \
  "$factory_transparency_external_gossip_registry_governance_rotation_state_4" \
  "$factory_transparency_external_gossip_registry_governed_rotation_state_5" \
  "$factory_transparency_external_gossip_registry_successor_governance" \
  "$factory_transparency_external_gossip_registry_successor_root_governance" \
  "$factory_transparency_external_gossip_registry_governed_rotation_report" \
  "$factory_transparency_external_gossip_registry_governed_rotation_schema" \
  "$factory_transparency_external_gossip_registry_governed_rotation_report_schema" \
  "$monotonic_release_ledger" \
  "$factory_transparency_external_gossip_registry_successor_root_private" \
  "$factory_transparency_external_gossip_registry_governed_authority_g_private" \
  "$factory_transparency_external_gossip_registry_governed_authority_h_private" \
  "$factory_transparency_external_gossip_registry_governed_authority_i_private" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys

genesis_path, legacy_path, root_rotation_path, threshold_path, governance_rotation_path, \
    governed_rotation_path, state_4_path, state_5_path, old_governance_path, \
    new_governance_path, report_path, rotation_schema_path, report_schema_path, \
    ledger_path, *private_paths = map(Path, sys.argv[1:])

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

def identity(source):
    return {"bytes": len(source), "sha256": hashlib.sha256(source).hexdigest()}

sources = [
    genesis_path.read_bytes(),
    legacy_path.read_bytes(),
    root_rotation_path.read_bytes(),
    threshold_path.read_bytes(),
    governance_rotation_path.read_bytes(),
    governed_rotation_path.read_bytes(),
]
state_4 = json.loads(state_4_path.read_bytes())
state_5 = json.loads(state_5_path.read_bytes())
old_governance = json.loads(old_governance_path.read_bytes())
new_governance = json.loads(new_governance_path.read_bytes())
rotation = json.loads(sources[-1])
report_source = report_path.read_bytes()
report = json.loads(report_source)

old_governance_sha256 = hashlib.sha256(compact(old_governance)).hexdigest()
new_governance_sha256 = hashlib.sha256(compact(new_governance)).hexdigest()
assert new_governance["registry_generation"] == 4
assert new_governance["registry_state_sha256"] == hashlib.sha256(compact(state_4)).hexdigest()
assert new_governance["registry_authority_public_key"] != state_4["authority_public_key"]
assert new_governance["minimum_approvals"] == 2
assert [item["authority_id"] for item in new_governance["authorities"]] == [
    "registry-admin-g", "registry-admin-h", "registry-admin-i"
]
assert rotation["from_generation"] == 4
assert rotation["to_generation"] == 5
assert rotation["previous_transition_sha256"] == hashlib.sha256(compact(json.loads(sources[-2]))).hexdigest()
assert rotation["old_public_key"] == state_4["authority_public_key"]
assert rotation["new_public_key"] == new_governance["registry_authority_public_key"]
assert rotation["old_governance_sha256"] == old_governance_sha256
assert rotation["new_governance_sha256"] == new_governance_sha256
assert rotation["old_governance"] == old_governance
assert rotation["new_governance"] == new_governance
assert [item["authority_id"] for item in rotation["old_approvals"]] == [
    "registry-admin-d", "registry-admin-e", "registry-admin-f"
]
assert [item["authority_id"] for item in rotation["new_approvals"]] == [
    "registry-admin-g", "registry-admin-h"
]
assert state_5["generation"] == 5
assert state_5["authority_public_key"] == rotation["new_public_key"]
assert state_5["active_governance_sha256"] == new_governance_sha256
assert state_5["organizations"] == state_4["organizations"]

assert report["status"] == "verified"
assert report["quorum_met"] is True
assert report["registry_history_event_count"] == 5
assert report["registry_authority_rotation_count"] == 1
assert report["registry_threshold_transition_count"] == 1
assert report["registry_governance_rotation_count"] == 1
assert report["registry_governed_authority_rotation_count"] == 1
assert report["current_registry"] == state_5
assert report["active_governance"] == new_governance
assert report["active_governance_sha256"] == new_governance_sha256
assert [event["kind"] for event in report["registry_history_events"]] == [
    "organization_transition", "authority_key_rotation", "threshold_transition",
    "governance_rotation", "governed_authority_key_rotation"
]
for event, source in zip(report["registry_history_events"], sources[1:]):
    assert event["artifact"] == identity(source)
for claim in (
    "registry_genesis_pin_matched",
    "complete_registry_history_verified",
    "registry_authority_transition_signatures_verified",
    "registry_authority_rotation_dual_signatures_verified",
    "registry_authority_successor_possession_verified",
    "registry_authority_key_history_unique",
    "governance_root_signatures_verified",
    "governance_authority_identities_unique",
    "governance_authority_keys_unique",
    "governance_threshold_approvals_verified",
    "governance_rotation_old_quorum_verified",
    "governance_rotation_new_quorum_verified",
    "successor_governance_state_binding_verified",
    "governed_authority_rotation_old_quorum_verified",
    "governed_authority_rotation_new_quorum_verified",
    "successor_registry_root_possession_verified",
    "registry_root_and_governance_rotated_atomically",
    "root_only_registry_mutations_locked_out",
    "registry_generation_chain_verified",
    "registry_digest_chain_verified",
    "registry_timestamps_monotonic",
    "registry_authority_role_separation_verified",
    "current_observer_trust_admissions_verified",
    "selected_observer_organizations_active",
    "registry_effective_before_quorum_evaluation_verified",
    "selected_ledger_latest_registry_verified",
    "selected_ledger_observer_trust_report_verified",
    "selected_ledger_latest_observer_rotations_verified",
    "authority_threshold_governance_verified",
):
    assert report[claim] is True, claim
for claim in (
    "selected_ledger_registry_bound_report_committed",
    "selected_ledger_rollback_resistance_verified",
    "global_non_equivocation_verified",
    "trusted_time_verified",
    "independent_governance_control_verified",
    "independent_organization_operation_verified",
    "factory_legal_identity_verified",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim

rotation_record_name = re.compile(
    r"factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-v1-[0-9a-f]{32}-[0-9]{4}\.json"
)
report_record_name = re.compile(
    r"factory-release-state-transparency-external-gossip-organization-registry-governed-authority-rotation-v1-[0-9a-f]{64}-[0-9]{4}-[0-9a-f]{32}\.json"
)
rotation_records = [path for path in ledger_path.iterdir() if rotation_record_name.fullmatch(path.name)]
assert len(rotation_records) == 1
assert rotation_records[0].read_bytes() == sources[-1]
report_records = [path for path in ledger_path.iterdir() if report_record_name.fullmatch(path.name)]
assert len(report_records) == 1
assert report_records[0].read_bytes() == report_source

secrets = [path.read_text(encoding="ascii").strip().encode() for path in private_paths]
for artifact in [new_governance_path, governed_rotation_path, report_path, state_5_path, *ledger_path.iterdir()]:
    source = artifact.read_bytes()
    for secret in secrets:
        assert secret not in source, artifact

for schema_path in (rotation_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY
}
"$pcbex_binary" verify-circuit-kicad-handoff \
  examples/circuit-spec-v2.json "$generated_schematic" \
  --output "$generated_handoff" --require-approved
jq -e '.approved == true and .counts.errors == 0' \
  "$generated_handoff" >/dev/null

# v1.473 adds an opt-in circuit-spec v3 for explicit multi-unit symbols. KiCad
# must merge the two U1 symbol units into one physical component while keeping
# each package pin on its exact declared net; pcbex then collapses those units
# to one board footprint under the same handoff and board-binding gates.
multi_unit_check="$output_directory/circuit-spec-v3.check.json"
multi_unit_schema="$output_directory/circuit-spec-v3.schema.json"
multi_unit_check_schema="$output_directory/circuit-spec-v3-check.schema.json"
multi_unit_schematic="$output_directory/circuit-spec-v3.generated.kicad_sch"
multi_unit_netlist="$output_directory/circuit-spec-v3.generated.xml"
multi_unit_handoff="$output_directory/circuit-spec-v3.generated.handoff.json"
multi_unit_board="$output_directory/circuit-spec-v3.board"
"$pcbex_binary" circuit-spec-v3-schema --output "$multi_unit_schema"
"$pcbex_binary" circuit-spec-v3-check-schema --output "$multi_unit_check_schema"
"$pcbex_binary" check-circuit-spec examples/circuit-board-spec-v3.json \
  --output "$multi_unit_check" --require-approved
"$pcbex_binary" write-circuit-spec-kicad-schematic \
  examples/circuit-board-spec-v3.json --output "$multi_unit_schematic"
kicad-cli sch export netlist --format kicadxml "$multi_unit_schematic" \
  --output "$multi_unit_netlist"
"$pcbex_binary" verify-circuit-kicad-handoff \
  examples/circuit-board-spec-v3.json "$multi_unit_schematic" \
  --output "$multi_unit_handoff" --require-approved
"$pcbex_binary" generate-circuit-kicad-board \
  examples/circuit-board-spec-v3.json "$multi_unit_schematic" \
  --footprint-closure examples/circuit-board-footprint-closure-v1.json \
  --construction-profile examples/circuit-board-construction-profile-v1.json \
  --physical-profile examples/circuit-board-physical-profile-v1.json \
  --output-dir "$multi_unit_board"
python3 - \
  "$multi_unit_netlist" "$multi_unit_check" "$multi_unit_handoff" \
  "$multi_unit_board/board.kicad_pcb" "$multi_unit_board/board-binding.json" \
  "$multi_unit_schema" "$multi_unit_check_schema" <<'PY'
from pathlib import Path
import json
import sys
import xml.etree.ElementTree as ET

netlist_path, check_path, handoff_path, board_path, binding_path, *schema_paths = map(
    Path, sys.argv[1:]
)
root = ET.parse(netlist_path).getroot()
components = [component.attrib["ref"] for component in root.findall("./components/comp")]
assert components.count("U1") == 1, components
assert components.count("R1") == 1, components
actual = {
    frozenset((node.attrib["ref"], node.attrib["pin"]) for node in net.findall("node"))
    for net in root.findall("./nets/net")
}
assert actual == {
    frozenset({("U1", "1"), ("R1", "1")}),
    frozenset({("U1", "2"), ("R1", "2")}),
}, actual

check = json.loads(check_path.read_bytes())
handoff = json.loads(handoff_path.read_bytes())
binding = json.loads(binding_path.read_bytes())
board = board_path.read_text(encoding="utf-8")
assert check["schema_version"] == 2
assert check["normalized_spec"]["schema_version"] == 3
assert check["electrical_review"]["approved"] is True
assert handoff["approved"] is True and handoff["findings"] == []
assert binding["approved"] is True and binding["findings"] == []
assert board.count('(footprint "Package:QFN"') == 1
assert board.count('(fp_text reference "U1"') == 1

for schema_path in schema_paths:
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.474 keeps single-pass routing as the default and adds one explicit,
# aggregate-budgeted convergence report. The real KiCad path must produce
# byte-identical boards/reports, retain a bounded negative before its gate, and
# expose a recursively closed schema.
convergence_first_board="$output_directory/routing-convergence.first.kicad_pcb"
convergence_second_board="$output_directory/routing-convergence.second.kicad_pcb"
convergence_first_report="$output_directory/routing-convergence.first.json"
convergence_second_report="$output_directory/routing-convergence.second.json"
convergence_schema="$output_directory/routing-convergence.schema.json"
convergence_partial_board="$output_directory/routing-convergence.partial.kicad_pcb"
convergence_partial_report="$output_directory/routing-convergence.partial.json"
convergence_partial_error="$output_directory/routing-convergence.partial.stderr"

"$pcbex_binary" routing-convergence-report-schema \
  --output "$convergence_schema"
for pair in \
  "$convergence_first_board:$convergence_first_report" \
  "$convergence_second_board:$convergence_second_report"; do
  board=${pair%%:*}
  report=${pair#*:}
  "$pcbex_binary" route-kicad examples/simple.kicad_pcb \
    --output "$board" \
    --convergence-report "$report" \
    --convergence-rounds 2 \
    --convergence-candidates 3 \
    --convergence-workers 2 \
    --convergence-router-workers 1 \
    --drc
done
cmp "$convergence_first_board" "$convergence_second_board"
cmp "$convergence_first_report" "$convergence_second_report"

if "$pcbex_binary" route-kicad examples/simple.kicad_pcb \
  --output "$convergence_partial_board" \
  --convergence-report "$convergence_partial_report" \
  --convergence-rounds 1 \
  --convergence-candidates 1 \
  --convergence-workers 1 \
  --convergence-router-workers 1 \
  --convergence-work-budget 1 \
  2>"$convergence_partial_error"; then
  echo "expected one-work-unit convergence to retain an unrouted result" >&2
  exit 1
fi
test -s "$convergence_partial_board"
test -s "$convergence_partial_report"
grep -Fq 'routing convergence retained 1 unrouted net(s)' \
  "$convergence_partial_error"

python3 - \
  "$convergence_first_report" "$convergence_partial_report" \
  "$convergence_schema" <<'PY'
import json
from pathlib import Path
import sys

positive_path, partial_path, schema_path = map(Path, sys.argv[1:])
positive = json.loads(positive_path.read_bytes())
partial = json.loads(partial_path.read_bytes())
schema = json.loads(schema_path.read_bytes())

assert positive["schema_version"] == 1
assert positive["scope"] == "bounded_deterministic_routing_convergence"
assert positive["status"] == "converged"
assert positive["converged"] is True
assert positive["design_rules_unchanged"] is True
assert positive["final_metrics"]["unrouted_nets"] == 0
assert positive["final_drc_violation_count"] == 0
assert positive["allocated_work_units"] <= positive["options"]["maximum_work_units"]
for identity in (
    positive["input_board_canonical"],
    positive["final_board_canonical"],
):
    assert identity["bytes"] > 0
    assert len(identity["sha256"]) == 64
    assert set(identity["sha256"]) <= set("0123456789abcdef")
for round_report in positive["rounds"]:
    for candidate in round_report["candidates"]:
        if candidate["selected_as_round_best"]:
            assert candidate["status"] == "admissible"
            assert candidate["drc_violation_count"] == 0

assert partial["status"] == "no_admissible_candidate"
assert partial["converged"] is False
assert partial["final_metrics"]["unrouted_nets"] == 1
assert partial["final_drc_violation_count"] == 0
assert partial["rounds"][0]["candidates"][0]["status"] == "routing_failed"
assert partial["rounds"][0]["candidates"][0]["metrics"] is None
assert partial["rounds"][0]["candidates"][0]["drc_violation_count"] is None

pending = [schema]
while pending:
    value = pending.pop()
    if isinstance(value, dict):
        if value.get("type") == "object":
            assert value.get("additionalProperties") is False
        if value.get("type") == "array":
            assert "maxItems" in value
        pending.extend(value.values())
    elif isinstance(value, list):
        pending.extend(value)
PY

# v1.475 consumes the exact v1.474 source closure again, freshly replays the
# retained convergence decision, and accepts only the exact routed KiCad
# bytes. A truthful partial result is retained before the optional complete
# gate; malformed or substituted evidence produces no verification artifact.
convergence_verification_first="$output_directory/routing-convergence.verification.first.json"
convergence_verification_second="$output_directory/routing-convergence.verification.second.json"
convergence_verification_partial="$output_directory/routing-convergence.verification.partial.json"
convergence_verification_partial_error="$output_directory/routing-convergence.verification.partial.stderr"
convergence_verification_schema="$output_directory/routing-convergence.verification.schema.json"
convergence_verification_tampered_board="$output_directory/routing-convergence.tampered.kicad_pcb"
convergence_verification_tampered_report="$output_directory/routing-convergence.tampered.json"
convergence_verification_tampered_output="$output_directory/routing-convergence.tampered.verification.json"

"$pcbex_binary" routing-convergence-verification-report-schema \
  --output "$convergence_verification_schema"
"$pcbex_binary" verify-kicad-routing-convergence examples/simple.kicad_pcb \
  --routed "$convergence_first_board" \
  --report "$convergence_first_report" \
  --output "$convergence_verification_first" \
  --require-complete
"$pcbex_binary" verify-kicad-routing-convergence examples/simple.kicad_pcb \
  --routed "$convergence_second_board" \
  --report "$convergence_second_report" \
  --output "$convergence_verification_second" \
  --require-complete
cmp "$convergence_verification_first" "$convergence_verification_second"

if "$pcbex_binary" verify-kicad-routing-convergence examples/simple.kicad_pcb \
  --routed "$convergence_partial_board" \
  --report "$convergence_partial_report" \
  --output "$convergence_verification_partial" \
  --require-complete 2>"$convergence_verification_partial_error"; then
  echo "expected fresh routing convergence verification to gate a partial result" >&2
  exit 1
fi
test -s "$convergence_verification_partial"
grep -Fq \
  'fresh routing convergence verification retained an incomplete routing result' \
  "$convergence_verification_partial_error"

cp "$convergence_first_board" "$convergence_verification_tampered_board"
printf '\n' >>"$convergence_verification_tampered_board"
if "$pcbex_binary" verify-kicad-routing-convergence examples/simple.kicad_pcb \
  --routed "$convergence_verification_tampered_board" \
  --report "$convergence_first_report" \
  --output "$convergence_verification_tampered_output"; then
  echo "expected routed KiCad byte substitution to fail verification" >&2
  exit 1
fi
test ! -e "$convergence_verification_tampered_output"

python3 - "$convergence_first_report" "$convergence_verification_tampered_report" <<'PY'
import json
from pathlib import Path
import sys

source, output = map(Path, sys.argv[1:])
report = json.loads(source.read_bytes())
report["final_metrics"]["total_length_nm"] += 1
output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PY
if "$pcbex_binary" verify-kicad-routing-convergence examples/simple.kicad_pcb \
  --routed "$convergence_first_board" \
  --report "$convergence_verification_tampered_report" \
  --output "$convergence_verification_tampered_output"; then
  echo "expected convergence-report substitution to fail fresh replay" >&2
  exit 1
fi
test ! -e "$convergence_verification_tampered_output"

python3 - \
  examples/simple.kicad_pcb "$convergence_first_board" \
  "$convergence_first_report" "$convergence_verification_first" \
  "$convergence_verification_partial" "$convergence_verification_schema" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

input_path, routed_path, convergence_path, positive_path, partial_path, schema_path = map(
    Path, sys.argv[1:]
)
positive = json.loads(positive_path.read_bytes())
partial = json.loads(partial_path.read_bytes())
schema = json.loads(schema_path.read_bytes())

assert positive["schema_version"] == 1
assert positive["scope"] == "fresh_exact_routing_convergence_verification"
assert positive["input_kind"] == "kicad_pcb"
assert positive["status"] == "verified_complete"
assert positive["routing_complete"] is True
assert positive["convergence"]["status"] == "converged"
assert len(positive["binding_sha256"]) == 64
assert set(positive["binding_sha256"]) <= set("0123456789abcdef")
for claim in (
    "source_authenticity_verified",
    "native_kicad_drc_verified",
    "manufacturability_verified",
    "release_authorized",
):
    assert positive[claim] is False
assert set(positive["validation"].values()) == {True}

for role, path in (
    ("input", input_path),
    ("routed_output", routed_path),
    ("retained_report", convergence_path),
):
    source = path.read_bytes()
    assert positive["sources"][role] == {
        "bytes": len(source),
        "sha256": hashlib.sha256(source).hexdigest(),
    }

assert partial["status"] == "verified_no_admissible_candidate"
assert partial["routing_complete"] is False
assert partial["convergence"]["converged"] is False

pending = [schema]
while pending:
    value = pending.pop()
    if isinstance(value, dict):
        if value.get("type") == "object":
            assert value.get("additionalProperties") is False
        if value.get("type") == "array":
            assert "maxItems" in value
        pending.extend(value.values())
    elif isinstance(value, list):
        pending.extend(value)
PY

# v1.476 composes the two fresh boundaries without trusting either retained
# report by itself. The exact routed board accepted by v1.475 must also
# reproduce the retained manufacturing ZIP. An incomplete routing result is a
# retained negative and never invokes fabrication.
routing_manufacturing_directory="$output_directory/routing-manufacturing.package"
routing_manufacturing_package="$routing_manufacturing_directory/manufacturing.zip"
routing_manufacturing_input="$output_directory/routing-manufacturing.input.kicad_pcb"
routing_manufacturing_board="$output_directory/routing-manufacturing.routed.kicad_pcb"
routing_manufacturing_convergence="$output_directory/routing-manufacturing.convergence.json"
routing_manufacturing_verification="$output_directory/routing-manufacturing.verification.json"
routing_manufacturing_positive="$output_directory/routing-manufacturing.handoff.json"
routing_manufacturing_partial="$output_directory/routing-manufacturing.partial.json"
routing_manufacturing_partial_error="$output_directory/routing-manufacturing.partial.stderr"
routing_manufacturing_schema="$output_directory/routing-manufacturing.schema.json"
routing_manufacturing_tampered_verification="$output_directory/routing-manufacturing.tampered-verification.json"
routing_manufacturing_tampered_package="$output_directory/routing-manufacturing.tampered.zip"
routing_manufacturing_tampered_output="$output_directory/routing-manufacturing.tampered-output.json"

"$pcbex_binary" route-kicad examples/multilayer.kicad_pcb \
  --output "$routing_manufacturing_input" --drc
"$pcbex_binary" route-kicad "$routing_manufacturing_input" \
  --output "$routing_manufacturing_board" \
  --convergence-report "$routing_manufacturing_convergence" \
  --convergence-rounds 2 \
  --convergence-candidates 3 \
  --convergence-workers 2 \
  --convergence-router-workers 1 \
  --drc
"$pcbex_binary" verify-kicad-routing-convergence \
  "$routing_manufacturing_input" \
  --routed "$routing_manufacturing_board" \
  --report "$routing_manufacturing_convergence" \
  --output "$routing_manufacturing_verification" \
  --require-complete
mkdir -p "$routing_manufacturing_directory"
"$pcbex_binary" fabricate "$routing_manufacturing_board" \
  --output-dir "$routing_manufacturing_directory"
test -s "$routing_manufacturing_package"

PYTHONPATH=agent/src python3 -m pcbex_agent \
  routing-manufacturing-handoff-report-schema \
  --output "$routing_manufacturing_schema"
PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-manufacturing-handoff \
  "$routing_manufacturing_input" "$routing_manufacturing_board" \
  --convergence-report "$routing_manufacturing_convergence" \
  --routing-verification-report "$routing_manufacturing_verification" \
  --manufacturing-package "$routing_manufacturing_package" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_manufacturing_positive" \
  --require-ready

if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-manufacturing-handoff \
  examples/simple.kicad_pcb "$convergence_partial_board" \
  --convergence-report "$convergence_partial_report" \
  --routing-verification-report "$convergence_verification_partial" \
  --manufacturing-package "$routing_manufacturing_package" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_manufacturing_partial" \
  --require-ready 2>"$routing_manufacturing_partial_error"; then
  echo "expected incomplete routing/manufacturing handoff to fail its final gate" >&2
  exit 1
fi
test -s "$routing_manufacturing_partial"
grep -Fxq \
  'routing/manufacturing handoff report was retained but is not ready' \
  "$routing_manufacturing_partial_error"

python3 - \
  "$routing_manufacturing_verification" \
  "$routing_manufacturing_tampered_verification" <<'PY'
import json
from pathlib import Path
import sys

source, target = map(Path, sys.argv[1:])
value = json.loads(source.read_bytes())
value["engine_version"] += "-substituted"
target.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
PY
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-manufacturing-handoff \
  "$routing_manufacturing_input" "$routing_manufacturing_board" \
  --convergence-report "$routing_manufacturing_convergence" \
  --routing-verification-report "$routing_manufacturing_tampered_verification" \
  --manufacturing-package "$routing_manufacturing_package" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_manufacturing_tampered_output"; then
  echo "expected retained routing-verification substitution to fail" >&2
  exit 1
fi
test ! -e "$routing_manufacturing_tampered_output"

cp "$routing_manufacturing_package" "$routing_manufacturing_tampered_package"
printf 'substitution' >>"$routing_manufacturing_tampered_package"
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-manufacturing-handoff \
  "$routing_manufacturing_input" "$routing_manufacturing_board" \
  --convergence-report "$routing_manufacturing_convergence" \
  --routing-verification-report "$routing_manufacturing_verification" \
  --manufacturing-package "$routing_manufacturing_tampered_package" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_manufacturing_tampered_output"; then
  echo "expected retained manufacturing-package substitution to fail" >&2
  exit 1
fi
test ! -e "$routing_manufacturing_tampered_output"

python3 - \
  "$routing_manufacturing_input" "$routing_manufacturing_board" \
  "$routing_manufacturing_convergence" "$routing_manufacturing_verification" \
  "$routing_manufacturing_package" "$routing_manufacturing_positive" \
  "$routing_manufacturing_partial" "$routing_manufacturing_schema" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

(
    input_board,
    routed_board,
    convergence_report,
    routing_verification,
    manufacturing_package,
    positive_report,
    partial_report,
    schema_path,
) = map(Path, sys.argv[1:])

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

positive = json.loads(positive_report.read_bytes())
partial = json.loads(partial_report.read_bytes())
schema = json.loads(schema_path.read_bytes())
assert positive["schema_version"] == 1
assert positive["verification_scope"] == \
    "fresh-exact-routing-to-manufacturing-handoff-v1"
assert positive["status"] == "verified_ready" and positive["ready"] is True
assert positive["gate_failures"] == []
assert positive["sources"]["input_board"] == identity(input_board)
assert positive["sources"]["routed_board"] == identity(routed_board)
assert positive["sources"]["convergence_report"] == identity(convergence_report)
assert positive["sources"]["routing_verification_report"] == \
    identity(routing_verification)
assert positive["sources"]["manufacturing_package"] == \
    identity(manufacturing_package)
assert positive["routing_verification"]["routing_complete"] is True
assert positive["routing_verification"]["sources"]["routed_output"] == \
    positive["sources"]["routed_board"]
assert {
    key: positive["manufacturing_replay"]["board"][key]
    for key in ("bytes", "sha256")
} == positive["sources"]["routed_board"]
assert positive["manufacturing_replay"]["package"]["fresh"] == \
    positive["sources"]["manufacturing_package"]
assert set(positive["validation"].values()) == {True}
for claim in (
    "source_authenticity_verified",
    "native_kicad_drc_verified",
    "manufacturability_verified",
    "release_authorized",
):
    assert positive[claim] is False

assert partial["status"] == "not_ready" and partial["ready"] is False
assert partial["gate_failures"] == ["routing_incomplete"]
assert partial["manufacturing_replay"] is None
assert partial["validation"]["manufacturing_package_replayed"] is False

pending = [schema]
while pending:
    value = pending.pop()
    if isinstance(value, dict):
        if value.get("type") == "object":
            assert value.get("additionalProperties") is False
        if value.get("type") == "array":
            assert "maxItems" in value
        pending.extend(value.values())
    elif isinstance(value, list):
        pending.extend(value)
PY

# v1.477 binds one additional, independent boundary: the retained
# normalized native KiCad DRC report must freshly replay against the same
# routed board and companions already bound to the exact manufacturing ZIP.
routing_drc_native="$output_directory/routing-drc-manufacturing.native-drc.json"
routing_drc_partial_native="$output_directory/routing-drc-manufacturing.partial-native-drc.json"
routing_drc_positive="$output_directory/routing-drc-manufacturing.handoff.json"
routing_drc_partial="$output_directory/routing-drc-manufacturing.partial.json"
routing_drc_partial_error="$output_directory/routing-drc-manufacturing.partial.stderr"
routing_drc_schema="$output_directory/routing-drc-manufacturing.schema.json"
routing_drc_tampered_native="$output_directory/routing-drc-manufacturing.tampered-native-drc.json"
routing_drc_tampered_handoff="$output_directory/routing-drc-manufacturing.tampered-handoff.json"
routing_drc_tampered_output="$output_directory/routing-drc-manufacturing.tampered-output.json"

"$pcbex_binary" run-native-kicad-drc "$routing_manufacturing_board" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_drc_native" \
  --require-approved
"$pcbex_binary" run-native-kicad-drc "$convergence_partial_board" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_drc_partial_native"

PYTHONPATH=agent/src python3 -m pcbex_agent \
  routing-drc-manufacturing-handoff-report-schema \
  --output "$routing_drc_schema"
PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-manufacturing-handoff \
  "$routing_manufacturing_input" "$routing_manufacturing_board" \
  --convergence-report "$routing_manufacturing_convergence" \
  --routing-verification-report "$routing_manufacturing_verification" \
  --manufacturing-package "$routing_manufacturing_package" \
  --routing-manufacturing-handoff-report "$routing_manufacturing_positive" \
  --native-drc-report "$routing_drc_native" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_drc_positive" \
  --require-ready

if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-manufacturing-handoff \
  examples/simple.kicad_pcb "$convergence_partial_board" \
  --convergence-report "$convergence_partial_report" \
  --routing-verification-report "$convergence_verification_partial" \
  --manufacturing-package "$routing_manufacturing_package" \
  --routing-manufacturing-handoff-report "$routing_manufacturing_partial" \
  --native-drc-report "$routing_drc_partial_native" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_drc_partial" \
  --require-ready 2>"$routing_drc_partial_error"; then
  echo "expected incomplete routing/DRC/manufacturing handoff to fail its final gate" >&2
  exit 1
fi
test -s "$routing_drc_partial"
grep -Fxq \
  'routing/DRC/manufacturing handoff report was retained but is not ready' \
  "$routing_drc_partial_error"

python3 - "$routing_drc_native" "$routing_drc_tampered_native" <<'PY'
import json
from pathlib import Path
import sys

source, target = map(Path, sys.argv[1:])
value = json.loads(source.read_bytes())
value["engine_version"] += "-substituted"
target.write_text(
    json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8"
)
PY
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-manufacturing-handoff \
  "$routing_manufacturing_input" "$routing_manufacturing_board" \
  --convergence-report "$routing_manufacturing_convergence" \
  --routing-verification-report "$routing_manufacturing_verification" \
  --manufacturing-package "$routing_manufacturing_package" \
  --routing-manufacturing-handoff-report "$routing_manufacturing_positive" \
  --native-drc-report "$routing_drc_tampered_native" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_drc_tampered_output"; then
  echo "expected retained native DRC substitution to fail" >&2
  exit 1
fi
test ! -e "$routing_drc_tampered_output"

python3 - \
  "$routing_manufacturing_positive" "$routing_drc_tampered_handoff" <<'PY'
import json
from pathlib import Path
import sys

source, target = map(Path, sys.argv[1:])
value = json.loads(source.read_bytes())
value["binding_sha256"] = "0" * 64
target.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
PY
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-manufacturing-handoff \
  "$routing_manufacturing_input" "$routing_manufacturing_board" \
  --convergence-report "$routing_manufacturing_convergence" \
  --routing-verification-report "$routing_manufacturing_verification" \
  --manufacturing-package "$routing_manufacturing_package" \
  --routing-manufacturing-handoff-report "$routing_drc_tampered_handoff" \
  --native-drc-report "$routing_drc_native" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$routing_drc_tampered_output"; then
  echo "expected retained routing/manufacturing handoff substitution to fail" >&2
  exit 1
fi
test ! -e "$routing_drc_tampered_output"

python3 - \
  "$routing_manufacturing_input" "$routing_manufacturing_board" \
  "$routing_manufacturing_convergence" "$routing_manufacturing_verification" \
  "$routing_manufacturing_package" "$routing_manufacturing_positive" \
  "$routing_drc_native" "$routing_drc_positive" "$routing_drc_partial" \
  "$routing_drc_schema" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

(
    input_board,
    routed_board,
    convergence_report,
    routing_verification,
    manufacturing_package,
    routing_manufacturing_handoff,
    native_drc,
    positive_report,
    partial_report,
    schema_path,
) = map(Path, sys.argv[1:])

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

positive = json.loads(positive_report.read_bytes())
partial = json.loads(partial_report.read_bytes())
schema = json.loads(schema_path.read_bytes())
assert positive["schema_version"] == 1
assert positive["verification_scope"] == \
    "fresh-exact-routing-native-drc-manufacturing-handoff-v1"
assert positive["status"] == "verified_ready" and positive["ready"] is True
assert positive["native_kicad_drc_verified"] is True
assert positive["gate_failures"] == []
assert positive["sources"]["input_board"] == identity(input_board)
assert positive["sources"]["routed_board"] == identity(routed_board)
assert positive["sources"]["convergence_report"] == identity(convergence_report)
assert positive["sources"]["routing_verification_report"] == \
    identity(routing_verification)
assert positive["sources"]["manufacturing_package"] == \
    identity(manufacturing_package)
assert positive["sources"]["routing_manufacturing_handoff_report"] == \
    identity(routing_manufacturing_handoff)
assert positive["sources"]["native_kicad_drc_report"] == identity(native_drc)
assert positive["routing_manufacturing_handoff"]["ready"] is True
assert positive["native_kicad_drc"]["approved"] is True
assert positive["native_kicad_drc"]["source"] == \
    positive["sources"]["routed_board"]
assert set(positive["validation"].values()) == {True}
for claim in (
    "source_authenticity_verified",
    "manufacturability_verified",
    "fabrication_authorized",
    "release_authorized",
):
    assert positive[claim] is False

assert partial["status"] == "not_ready" and partial["ready"] is False
assert partial["native_kicad_drc_verified"] is False
assert partial["gate_failures"] == ["routing_incomplete"]
assert partial["native_kicad_drc"] is None
assert partial["validation"]["native_kicad_drc_replayed"] is False

pending = [schema]
while pending:
    value = pending.pop()
    if isinstance(value, dict):
        if value.get("type") == "object":
            assert value.get("additionalProperties") is False
        if value.get("type") == "array":
            assert "maxItems" in value
        pending.extend(value.values())
    elif isinstance(value, list):
        pending.extend(value)
PY

# v1.478 closes the next offline release boundary. One exact, freshly replayed
# v1.477 routing/native-DRC/manufacturing result must name the same package as
# one factory-required deterministic pipeline, while a caller-pinned canonical
# organization policy must authorize that exact pipeline through two distinct
# Ed25519 fabrication approvals.
fabrication_release_fixture="$output_directory/routing-drc-fabrication.fixture"
fabrication_release_input_dir="$output_directory/routing-drc-fabrication.input"
fabrication_release_routed_dir="$output_directory/routing-drc-fabrication.routed"
fabrication_release_routing_input="$fabrication_release_input_dir/design.kicad_pcb"
fabrication_release_routed_board="$fabrication_release_routed_dir/design.kicad_pcb"
fabrication_release_input_project="$fabrication_release_input_dir/design.kicad_pro"
fabrication_release_routed_project="$fabrication_release_routed_dir/design.kicad_pro"
fabrication_release_convergence="$output_directory/routing-drc-fabrication.convergence.json"
fabrication_release_verification="$output_directory/routing-drc-fabrication.verification.json"
fabrication_release_package_dir="$output_directory/routing-drc-fabrication.package"
fabrication_release_package="$fabrication_release_package_dir/manufacturing.zip"
fabrication_release_routing_handoff="$output_directory/routing-drc-fabrication.routing-handoff.json"
fabrication_release_native_drc="$output_directory/routing-drc-fabrication.native-drc.json"
fabrication_release_retained_routing="$output_directory/routing-drc-fabrication.routing-drc-handoff.json"
fabrication_release_partial_handoff="$output_directory/routing-drc-fabrication.partial-routing-handoff.json"
fabrication_release_partial_retained="$output_directory/routing-drc-fabrication.partial-routing-drc-handoff.json"
fabrication_release_positive="$output_directory/routing-drc-fabrication.release.json"
fabrication_release_single="$output_directory/routing-drc-fabrication.single.json"
fabrication_release_single_error="$output_directory/routing-drc-fabrication.single.stderr"
fabrication_release_routing_negative="$output_directory/routing-drc-fabrication.routing-negative.json"
fabrication_release_routing_negative_error="$output_directory/routing-drc-fabrication.routing-negative.stderr"
fabrication_release_schema="$output_directory/routing-drc-fabrication.schema.json"
fabrication_release_tampered_approval="$output_directory/routing-drc-fabrication.tampered-approval.json"
fabrication_release_tampered_output="$output_directory/routing-drc-fabrication.tampered-output.json"
fabrication_release_pin_output="$output_directory/routing-drc-fabrication.pin-output.json"
factory_receipt_secret_directory="$(mktemp -d)"
factory_receipt_private_key="$factory_receipt_secret_directory/factory-receipt.key"
factory_receipt_public_key="$output_directory/factory-receipt.pub"
factory_response_secret_directory="$(mktemp -d)"
factory_response_private_key="$factory_response_secret_directory/factory-response.pem"
factory_response_public_der="$factory_response_secret_directory/factory-response.der"
factory_response_public_key="$output_directory/factory-response.pub"
factory_transparency_private_key="$factory_response_secret_directory/factory-transparency.pem"
factory_transparency_public_der="$factory_response_secret_directory/factory-transparency.der"
factory_transparency_public_key="$output_directory/factory-transparency.pub"
factory_receipt_policy_template="$output_directory/factory-receipt-policy-template.json"
trap 'rm -f -- "$factory_receipt_private_key" "$factory_response_private_key" "$factory_response_public_der" "$factory_transparency_private_key" "$factory_transparency_public_der"; rmdir -- "$factory_receipt_secret_directory" "$factory_response_secret_directory" 2>/dev/null || true' EXIT

"$pcbex_binary" approval-keygen \
  --private-key "$factory_receipt_private_key" \
  --public-key "$factory_receipt_public_key"
openssl genpkey -algorithm ED25519 -out "$factory_response_private_key"
openssl pkey -in "$factory_response_private_key" -pubout -outform DER \
  -out "$factory_response_public_der"
openssl genpkey -algorithm ED25519 -out "$factory_transparency_private_key"
openssl pkey -in "$factory_transparency_private_key" -pubout -outform DER \
  -out "$factory_transparency_public_der"
python3 - \
  "$factory_response_public_der" "$factory_response_public_key" \
  "$factory_transparency_public_der" "$factory_transparency_public_key" <<'PY'
from pathlib import Path
import sys

arguments = list(map(Path, sys.argv[1:]))
assert len(arguments) == 4
for source, output in zip(arguments[::2], arguments[1::2]):
    encoded = source.read_bytes()
    assert len(encoded) >= 32
    output.write_text(encoded[-32:].hex() + "\n", encoding="ascii")
PY
python3 - \
  examples/acme-policy-pack.json \
  "$factory_receipt_public_key" \
  "$factory_response_public_key" \
  "$factory_receipt_policy_template" <<'PY'
import json
from pathlib import Path
import sys

source, receipt_public_key, response_public_key, output = map(Path, sys.argv[1:])
pack = json.loads(source.read_text(encoding="utf-8"))
pack["factory_receipt_attestation_policy"] = {
    "maximum_validity_seconds": 3600,
    "trusted_keys": [
        {
            "factory_id": "kicad-e2e-factory",
            "provider": "generic",
            "public_key": receipt_public_key.read_text(encoding="ascii").strip(),
        }
    ],
}
pack["factory_adapter_response_authentication_policy"] = {
    "maximum_validity_seconds": 300,
    "trusted_keys": [
        {
            "key_id": "kicad-e2e-factory-response",
            "factory_id": "kicad-e2e-factory",
            "provider": "generic",
            "public_key": response_public_key.read_text(encoding="ascii").strip(),
        }
    ],
}
output.write_bytes(
    json.dumps(pack, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
PY

mkdir -p "$fabrication_release_input_dir" "$fabrication_release_routed_dir"
# This dedicated project ignores only KiCad's installed-library footprint
# comparison. Copper, geometry, connectivity, and manufacturing DRC remain
# enabled; library provenance is an explicit v1.478 nonclaim.
cp crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci/design.kicad_pro \
  "$fabrication_release_input_project"
cp crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci/design.kicad_pro \
  "$fabrication_release_routed_project"
"$pcbex_binary" route-kicad \
  crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci/design.kicad_pcb \
  --project crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci/design.kicad_pro \
  --output "$fabrication_release_routing_input" --drc
"$pcbex_binary" route-kicad "$fabrication_release_routing_input" \
  --project "$fabrication_release_input_project" \
  --output "$fabrication_release_routed_board" \
  --convergence-report "$fabrication_release_convergence" \
  --convergence-rounds 2 \
  --convergence-candidates 3 \
  --convergence-workers 2 \
  --convergence-router-workers 1 \
  --drc
"$pcbex_binary" verify-kicad-routing-convergence \
  "$fabrication_release_routing_input" \
  --routed "$fabrication_release_routed_board" \
  --report "$fabrication_release_convergence" \
  --output "$fabrication_release_verification" \
  --require-complete
mkdir -p "$fabrication_release_package_dir"
"$pcbex_binary" fabricate "$fabrication_release_routed_board" \
  --output-dir "$fabrication_release_package_dir"
PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-manufacturing-handoff \
  "$fabrication_release_routing_input" "$fabrication_release_routed_board" \
  --convergence-report "$fabrication_release_convergence" \
  --routing-verification-report "$fabrication_release_verification" \
  --manufacturing-package "$fabrication_release_package" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --kicad-project "$fabrication_release_routed_project" \
  --output "$fabrication_release_routing_handoff" \
  --require-ready
"$pcbex_binary" run-native-kicad-drc "$fabrication_release_routed_board" \
  --project "$fabrication_release_routed_project" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$fabrication_release_native_drc" \
  --require-approved
PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-manufacturing-handoff \
  "$fabrication_release_routing_input" "$fabrication_release_routed_board" \
  --convergence-report "$fabrication_release_convergence" \
  --routing-verification-report "$fabrication_release_verification" \
  --manufacturing-package "$fabrication_release_package" \
  --routing-manufacturing-handoff-report "$fabrication_release_routing_handoff" \
  --native-drc-report "$fabrication_release_native_drc" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --kicad-project "$fabrication_release_routed_project" \
  --output "$fabrication_release_retained_routing" \
  --require-ready

PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-manufacturing-handoff \
  examples/simple.kicad_pcb "$convergence_partial_board" \
  --convergence-report "$convergence_partial_report" \
  --routing-verification-report "$convergence_verification_partial" \
  --manufacturing-package "$fabrication_release_package" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$fabrication_release_partial_handoff"
PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-manufacturing-handoff \
  examples/simple.kicad_pcb "$convergence_partial_board" \
  --convergence-report "$convergence_partial_report" \
  --routing-verification-report "$convergence_verification_partial" \
  --manufacturing-package "$fabrication_release_package" \
  --routing-manufacturing-handoff-report "$fabrication_release_partial_handoff" \
  --native-drc-report "$routing_drc_partial_native" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --output "$fabrication_release_partial_retained"

python3 scripts/fabrication_authorization_action_ci.py \
  --pcbex "$pcbex_binary" \
  --fixture-dir crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci \
  --policy-template "$factory_receipt_policy_template" \
  --board "$fabrication_release_routed_board" \
  --manufacturing-package "$fabrication_release_package" \
  --output-dir "$fabrication_release_fixture" \
  --timeout-seconds 300 >/dev/null

fabrication_release_plan="$fabrication_release_fixture/factory-required-plan.json"
fabrication_release_pipeline_report="$fabrication_release_fixture/factory-required-report.json"
fabrication_release_approval_a="$fabrication_release_fixture/approval-a.json"
fabrication_release_approval_b="$fabrication_release_fixture/approval-b.json"
fabrication_release_policy_digest="$(python3 - "$fabrication_release_approval_a" "$fabrication_release_approval_b" <<'PY'
import json
from pathlib import Path
import sys

approvals = [json.loads(Path(path).read_bytes()) for path in sys.argv[1:]]
digests = {
    approval["evidence"]["policy_pack"]["canonical_sha256"]
    for approval in approvals
}
assert len(digests) == 1
digest = digests.pop()
assert isinstance(digest, str) and len(digest) == 64
assert all(character in "0123456789abcdef" for character in digest)
print(digest)
PY
)"

fabrication_release_common=(
  "$fabrication_release_routing_input" "$fabrication_release_routed_board"
  --convergence-report "$fabrication_release_convergence"
  --routing-verification-report "$fabrication_release_verification"
  --manufacturing-package "$fabrication_release_package"
  --routing-manufacturing-handoff-report "$fabrication_release_routing_handoff"
  --native-drc-report "$fabrication_release_native_drc"
  --routing-drc-manufacturing-handoff-report "$fabrication_release_retained_routing"
  --deterministic-pipeline-plan "$fabrication_release_plan"
  --deterministic-pipeline-report "$fabrication_release_pipeline_report"
  --expected-policy-pack-canonical-sha256 "$fabrication_release_policy_digest"
  --pcbex "$pcbex_binary"
  --authorization-pcbex "$pcbex_binary"
  --kicad-cli "$kicad_cli_binary"
  --kicad-project "$fabrication_release_routed_project"
  --timeout-seconds 600
)

PYTHONPATH=agent/src python3 -m pcbex_agent \
  routing-drc-fabrication-release-report-schema \
  --output "$fabrication_release_schema"
PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-fabrication-release \
  "${fabrication_release_common[@]}" \
  --approval "$fabrication_release_approval_a" \
  --approval "$fabrication_release_approval_b" \
  --output "$fabrication_release_positive" \
  --require-authorized

if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-fabrication-release \
  "${fabrication_release_common[@]}" \
  --approval "$fabrication_release_approval_a" \
  --output "$fabrication_release_single" \
  --require-authorized 2>"$fabrication_release_single_error"; then
  echo "expected one fabrication approval to fail the final release gate" >&2
  exit 1
fi
test -s "$fabrication_release_single"
grep -Fxq \
  'routing/DRC/fabrication release report was retained but is not authorized' \
  "$fabrication_release_single_error"

if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-fabrication-release \
  examples/simple.kicad_pcb "$convergence_partial_board" \
  --convergence-report "$convergence_partial_report" \
  --routing-verification-report "$convergence_verification_partial" \
  --manufacturing-package "$fabrication_release_package" \
  --routing-manufacturing-handoff-report "$fabrication_release_partial_handoff" \
  --native-drc-report "$routing_drc_partial_native" \
  --routing-drc-manufacturing-handoff-report "$fabrication_release_partial_retained" \
  --deterministic-pipeline-plan "$fabrication_release_plan" \
  --deterministic-pipeline-report "$fabrication_release_pipeline_report" \
  --approval "$fabrication_release_approval_a" \
  --approval "$fabrication_release_approval_b" \
  --expected-policy-pack-canonical-sha256 "$fabrication_release_policy_digest" \
  --pcbex "$pcbex_binary" \
  --authorization-pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --timeout-seconds 600 \
  --output "$fabrication_release_routing_negative" \
  --require-authorized 2>"$fabrication_release_routing_negative_error"; then
  echo "expected incomplete routing evidence to fail the final release gate" >&2
  exit 1
fi
test -s "$fabrication_release_routing_negative"
grep -Fxq \
  'routing/DRC/fabrication release report was retained but is not authorized' \
  "$fabrication_release_routing_negative_error"

python3 - "$fabrication_release_approval_a" "$fabrication_release_tampered_approval" <<'PY'
import json
from pathlib import Path
import sys

source, target = map(Path, sys.argv[1:])
approval = json.loads(source.read_bytes())
approval["signature"] = ("0" if approval["signature"][0] != "0" else "1") + approval["signature"][1:]
target.write_bytes(json.dumps(approval, indent=2).encode("utf-8") + b"\n")
PY
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-fabrication-release \
  "${fabrication_release_common[@]}" \
  --approval "$fabrication_release_tampered_approval" \
  --approval "$fabrication_release_approval_b" \
  --output "$fabrication_release_tampered_output"; then
  echo "expected a tampered fabrication approval to fail without output" >&2
  exit 1
fi
test ! -e "$fabrication_release_tampered_output"

if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-routing-drc-fabrication-release \
  "${fabrication_release_common[@]}" \
  --approval "$fabrication_release_approval_a" \
  --approval "$fabrication_release_approval_b" \
  --expected-policy-pack-canonical-sha256 "$(printf '%064d' 0)" \
  --output "$fabrication_release_pin_output"; then
  echo "expected a mismatched policy pin to fail without output" >&2
  exit 1
fi
test ! -e "$fabrication_release_pin_output"

PYTHONPATH=agent/src python3 - \
  "$fabrication_release_positive" "$fabrication_release_single" \
  "$fabrication_release_routing_negative" "$fabrication_release_schema" \
  "$fabrication_release_retained_routing" "$fabrication_release_package" \
  "$fabrication_release_plan" "$fabrication_release_pipeline_report" \
  "$fabrication_release_approval_a" "$fabrication_release_approval_b" \
  "$fabrication_release_fixture/factory-receipt.json" \
  "$fabrication_release_fixture/final-policy-pack.json" \
  "$fabrication_release_policy_digest" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

from pcbex_agent import render_routing_drc_fabrication_release_report

(
    positive_path,
    single_path,
    routing_negative_path,
    schema_path,
    retained_routing_path,
    package_path,
    plan_path,
    pipeline_report_path,
    approval_a_path,
    approval_b_path,
    receipt_path,
    policy_path,
) = map(Path, sys.argv[1:13])
policy_digest = sys.argv[13]

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

positive = json.loads(positive_path.read_bytes())
single = json.loads(single_path.read_bytes())
routing_negative = json.loads(routing_negative_path.read_bytes())
schema = json.loads(schema_path.read_bytes())

assert positive_path.read_bytes() == render_routing_drc_fabrication_release_report(positive)
assert list(positive) == list(single) == list(routing_negative)
assert positive["schema_version"] == 1
assert positive["verification_scope"] == \
    "fresh-exact-routing-drc-fabrication-release-v1"
assert positive["status"] == "release_authorized"
assert positive["routing_drc_manufacturing_ready"] is True
assert positive["fabrication_authorized"] is True
assert positive["release_authorized"] is True
assert positive["gate_failures"] == []
assert positive["sources"]["routing_drc_manufacturing_handoff_report"] == \
    identity(retained_routing_path)
assert positive["sources"]["deterministic_pipeline_plan"] == identity(plan_path)
assert positive["sources"]["deterministic_pipeline_report"] == \
    identity(pipeline_report_path)
assert positive["sources"]["manufacturing_package"] == identity(package_path)
assert positive["sources"]["factory_receipt"] == identity(receipt_path)
assert positive["sources"]["policy_pack"] == identity(policy_path)
assert positive["sources"]["signed_approvals"] == [
    identity(approval_a_path),
    identity(approval_b_path),
]
assert positive["routing_drc_manufacturing"]["manufacturing_package"] == \
    identity(package_path)
assert positive["fabrication_authorization"]["manufacturing_package"] == \
    identity(package_path)
assert positive["fabrication_authorization"]["approvals"] == 2
assert positive["fabrication_authorization"]["rejections"] == 0
assert positive["fabrication_authorization"]["gate_failures"] == []
assert positive["fabrication_authorization"]["quote_authenticity_verified"] is False
assert positive["fabrication_authorization"]["challenge_one_time_use_enforced"] is False
assert positive["policy_pin"] == {
    "expected_canonical_sha256": policy_digest,
    "matched": True,
}
assert set(positive["validation"].values()) == {True}

for claim in (
    "source_authenticity_verified",
    "toolchain_authenticity_verified",
    "policy_pack_authenticity_verified",
    "factory_receipt_authenticity_verified",
    "manufacturability_verified",
    "external_submission_performed",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "challenge_one_time_use_enforced",
):
    assert positive[claim] is False, claim

assert single["status"] == "not_authorized"
assert single["routing_drc_manufacturing_ready"] is True
assert single["fabrication_authorized"] is False
assert single["release_authorized"] is False
assert single["gate_failures"] == ["fabrication_not_authorized"]
assert single["fabrication_authorization"]["gate_failures"] == [
    "insufficient_fabrication_approvals:required=2:actual=1"
]

assert routing_negative["status"] == "not_authorized"
assert routing_negative["routing_drc_manufacturing_ready"] is False
assert routing_negative["fabrication_authorized"] is True
assert routing_negative["release_authorized"] is False
assert routing_negative["gate_failures"] == [
    "routing_drc_manufacturing_not_ready"
]

pending = [schema]
objects = arrays = 0
while pending:
    value = pending.pop()
    if isinstance(value, dict):
        if value.get("type") == "object":
            objects += 1
            assert value.get("additionalProperties") is False
        if value.get("type") == "array":
            arrays += 1
            assert "maxItems" in value
        pending.extend(value.values())
    elif isinstance(value, list):
        pending.extend(value)
assert objects > 0 and arrays > 0
PY

# v1.479 keeps the complete v1.478 authority intact while requiring the three
# native command entrypoints selected by this deployment to match independent
# expected SHA-256 pins. Each retained report must share its time-invariant
# replay subject with a fresh positive or quorum-negative assessment; a wrong
# pin is a hard pre-child failure.
executable_pinned_positive="$output_directory/executable-pinned-fabrication.release.json"
executable_pinned_negative="$output_directory/executable-pinned-fabrication.negative.json"
executable_pinned_negative_error="$output_directory/executable-pinned-fabrication.negative.stderr"
executable_pinned_wrong_pin="$output_directory/executable-pinned-fabrication.wrong-pin.json"
executable_pinned_schema="$output_directory/executable-pinned-fabrication.schema.json"

read -r executable_pinned_pcbex_sha executable_pinned_kicad_sha <<EOF
$(python3 - "$pcbex_binary" "$kicad_cli_binary" <<'PY'
import hashlib
from pathlib import Path
import sys

print(*(hashlib.sha256(Path(path).resolve(strict=True).read_bytes()).hexdigest()
        for path in sys.argv[1:]))
PY
)
EOF

PYTHONPATH=agent/src python3 -m pcbex_agent \
  executable-pinned-fabrication-release-report-schema \
  --output "$executable_pinned_schema"
PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-executable-pinned-fabrication-release \
  "${fabrication_release_common[@]}" \
  --approval "$fabrication_release_approval_a" \
  --approval "$fabrication_release_approval_b" \
  --routing-drc-fabrication-release-report "$fabrication_release_positive" \
  --expected-routing-pcbex-sha256 "$executable_pinned_pcbex_sha" \
  --expected-authorization-pcbex-sha256 "$executable_pinned_pcbex_sha" \
  --expected-kicad-cli-sha256 "$executable_pinned_kicad_sha" \
  --output "$executable_pinned_positive" \
  --require-authorized

if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-executable-pinned-fabrication-release \
  "${fabrication_release_common[@]}" \
  --approval "$fabrication_release_approval_a" \
  --routing-drc-fabrication-release-report "$fabrication_release_single" \
  --expected-routing-pcbex-sha256 "$executable_pinned_pcbex_sha" \
  --expected-authorization-pcbex-sha256 "$executable_pinned_pcbex_sha" \
  --expected-kicad-cli-sha256 "$executable_pinned_kicad_sha" \
  --output "$executable_pinned_negative" \
  --require-authorized 2>"$executable_pinned_negative_error"; then
  echo "expected the digest-pinned nested quorum negative to fail its final gate" >&2
  exit 1
fi
test -s "$executable_pinned_negative"
grep -Fxq \
  'executable-pinned fabrication release report was retained but is not authorized' \
  "$executable_pinned_negative_error"

if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-executable-pinned-fabrication-release \
  "${fabrication_release_common[@]}" \
  --approval "$fabrication_release_approval_a" \
  --approval "$fabrication_release_approval_b" \
  --routing-drc-fabrication-release-report "$fabrication_release_positive" \
  --expected-routing-pcbex-sha256 "$(printf '%064d' 0)" \
  --expected-authorization-pcbex-sha256 "$executable_pinned_pcbex_sha" \
  --expected-kicad-cli-sha256 "$executable_pinned_kicad_sha" \
  --output "$executable_pinned_wrong_pin"; then
  echo "expected a wrong executable digest pin to fail without output" >&2
  exit 1
fi
test ! -e "$executable_pinned_wrong_pin"

PYTHONPATH=agent/src python3 - \
  "$executable_pinned_positive" "$executable_pinned_negative" \
  "$executable_pinned_schema" "$fabrication_release_positive" \
  "$fabrication_release_single" "$executable_pinned_pcbex_sha" \
  "$executable_pinned_kicad_sha" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

from pcbex_agent import render_executable_pinned_fabrication_release_report
from pcbex_agent import routing_drc_fabrication_release as v1478

(
    positive_path,
    negative_path,
    schema_path,
    nested_positive_path,
    nested_negative_path,
) = map(Path, sys.argv[1:6])
pcbex_sha, kicad_sha = sys.argv[6:8]
positive = json.loads(positive_path.read_bytes())
negative = json.loads(negative_path.read_bytes())
schema = json.loads(schema_path.read_bytes())
nested_positive = json.loads(nested_positive_path.read_bytes())
nested_negative = json.loads(nested_negative_path.read_bytes())

assert positive_path.read_bytes() == \
    render_executable_pinned_fabrication_release_report(positive)
assert positive["schema_version"] == 1
assert positive["verification_scope"] == \
    "fresh-exact-executable-pinned-fabrication-release-v1"
assert positive["status"] == "release_authorized"
assert positive["routing_drc_fabrication_release_authorized"] is True
assert positive["executable_digest_pins_verified"] is True
assert positive["release_authorized"] is True
assert positive["gate_failures"] == []
assert positive["sources"]["routing_drc_fabrication_release_report"] == {
    "bytes": len(nested_positive_path.read_bytes()),
    "sha256": hashlib.sha256(nested_positive_path.read_bytes()).hexdigest(),
    "replay_subject_sha256": v1478._retained_replay_subject_sha256(
        nested_positive
    ),
}
assert v1478._retained_replay_subject_sha256(
    positive["routing_drc_fabrication_release"]
) == v1478._retained_replay_subject_sha256(nested_positive)
assert positive["executable_pins"]["routing_pcbex"]["sha256"] == pcbex_sha
assert positive["executable_pins"]["authorization_pcbex"]["sha256"] == pcbex_sha
assert positive["executable_pins"]["kicad_cli"]["sha256"] == kicad_sha
for pin in positive["executable_pins"].values():
    assert pin["format"] == "elf"
    assert pin["sha256"] == pin["expected_sha256"]
    assert pin["matched"] is True
assert set(positive["validation"].values()) == {True}
for claim in (
    "source_authenticity_verified",
    "executable_origin_authenticity_verified",
    "toolchain_authenticity_verified",
    "policy_pack_authenticity_verified",
    "factory_receipt_authenticity_verified",
    "manufacturability_verified",
    "external_submission_performed",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "challenge_one_time_use_enforced",
):
    assert positive[claim] is False, claim

assert negative["status"] == "not_authorized"
assert negative["routing_drc_fabrication_release_authorized"] is False
assert negative["executable_digest_pins_verified"] is True
assert negative["release_authorized"] is False
assert negative["gate_failures"] == [
    "routing_drc_fabrication_release_not_authorized"
]
assert negative["sources"]["routing_drc_fabrication_release_report"] == {
    "bytes": len(nested_negative_path.read_bytes()),
    "sha256": hashlib.sha256(nested_negative_path.read_bytes()).hexdigest(),
    "replay_subject_sha256": v1478._retained_replay_subject_sha256(
        nested_negative
    ),
}
assert v1478._retained_replay_subject_sha256(
    negative["routing_drc_fabrication_release"]
) == v1478._retained_replay_subject_sha256(nested_negative)

pending = [schema]
objects = arrays = 0
while pending:
    value = pending.pop()
    if isinstance(value, dict):
        if value.get("type") == "object":
            objects += 1
            assert value.get("additionalProperties") is False
        if value.get("type") == "array":
            arrays += 1
            assert "maxItems" in value
        pending.extend(value.values())
    elif isinstance(value, list):
        pending.extend(value)
assert objects > 0 and arrays > 0
PY

# v1.480 authenticates the exact normalized factory receipt selected by the
# freshly replayed v1.479 release. A dedicated factory key is selected by the
# externally pinned organization policy; legal identity, TLS, raw response,
# capacity, order placement, payment, and one-time challenge use stay false.
factory_receipt_source="$fabrication_release_fixture/factory-receipt.json"
factory_receipt_policy="$fabrication_release_fixture/final-policy-pack.json"
factory_receipt_signed="$output_directory/factory-receipt.attestation.json"
factory_receipt_signed_expired="$output_directory/factory-receipt.attestation.expired.json"
factory_receipt_signed_tampered="$output_directory/factory-receipt.attestation.tampered.json"
factory_receipt_report="$output_directory/factory-receipt.attestation-report.json"
factory_receipt_report_expired="$output_directory/factory-receipt.attestation-report.expired.json"
factory_receipt_report_expired_error="$output_directory/factory-receipt.attestation-report.expired.stderr"
factory_receipt_tampered_output="$output_directory/factory-receipt.attestation-report.tampered.json"
factory_receipt_signed_schema="$output_directory/factory-receipt.attestation.schema.json"
factory_receipt_report_schema="$output_directory/factory-receipt.attestation-report.schema.json"
signed_receipt_release_positive="$output_directory/signed-factory-receipt.release.json"
signed_receipt_release_negative="$output_directory/signed-factory-receipt.negative.json"
signed_receipt_release_negative_error="$output_directory/signed-factory-receipt.negative.stderr"
signed_receipt_release_schema="$output_directory/signed-factory-receipt.schema.json"

factory_receipt_now="$(date +%s)"
factory_receipt_issued="$((factory_receipt_now - 10))"
factory_receipt_expires="$((factory_receipt_now + 1800))"

"$pcbex_binary" signed-factory-receipt-attestation-schema \
  --output "$factory_receipt_signed_schema"
"$pcbex_binary" factory-receipt-attestation-report-schema \
  --output "$factory_receipt_report_schema"
"$pcbex_binary" sign-factory-receipt-attestation \
  "$fabrication_release_package" \
  --factory-receipt "$factory_receipt_source" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-pack-canonical-sha256 "$fabrication_release_policy_digest" \
  --private-key "$factory_receipt_private_key" \
  --factory-id kicad-e2e-factory \
  --attestation-id kicad-e2e-receipt-current \
  --challenge "$(printf 'c%.0s' {1..64})" \
  --issued-at-unix "$factory_receipt_issued" \
  --expires-at-unix "$factory_receipt_expires" \
  --output "$factory_receipt_signed"
"$pcbex_binary" sign-factory-receipt-attestation \
  "$fabrication_release_package" \
  --factory-receipt "$factory_receipt_source" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-pack-canonical-sha256 "$fabrication_release_policy_digest" \
  --private-key "$factory_receipt_private_key" \
  --factory-id kicad-e2e-factory \
  --attestation-id kicad-e2e-receipt-expired \
  --challenge "$(printf 'd%.0s' {1..64})" \
  --issued-at-unix 1 \
  --expires-at-unix 2 \
  --output "$factory_receipt_signed_expired"

rm -f -- "$factory_receipt_private_key"
rmdir -- "$factory_receipt_secret_directory"
trap 'rm -f -- "$factory_response_private_key" "$factory_response_public_der" "$factory_transparency_private_key" "$factory_transparency_public_der"; rmdir -- "$factory_response_secret_directory" 2>/dev/null || true' EXIT

"$pcbex_binary" verify-factory-receipt-attestation \
  "$fabrication_release_package" \
  --factory-receipt "$factory_receipt_source" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-pack-canonical-sha256 "$fabrication_release_policy_digest" \
  --signed-attestation "$factory_receipt_signed" \
  --output "$factory_receipt_report" \
  --require-authenticated

if "$pcbex_binary" verify-factory-receipt-attestation \
  "$fabrication_release_package" \
  --factory-receipt "$factory_receipt_source" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-pack-canonical-sha256 "$fabrication_release_policy_digest" \
  --signed-attestation "$factory_receipt_signed_expired" \
  --output "$factory_receipt_report_expired" \
  --require-authenticated 2>"$factory_receipt_report_expired_error"; then
  echo "expected an expired factory receipt attestation to fail its final gate" >&2
  exit 1
fi
test -s "$factory_receipt_report_expired"
grep -Fq \
  'factory receipt attestation is not active under the pinned policy' \
  "$factory_receipt_report_expired_error"

python3 - "$factory_receipt_signed" "$factory_receipt_signed_tampered" <<'PY'
import json
from pathlib import Path
import sys

source, output = map(Path, sys.argv[1:])
value = json.loads(source.read_bytes())
value["signature"] = ("0" if value["signature"][0] != "0" else "1") + value["signature"][1:]
output.write_bytes(json.dumps(value, indent=2).encode("utf-8") + b"\n")
PY
if "$pcbex_binary" verify-factory-receipt-attestation \
  "$fabrication_release_package" \
  --factory-receipt "$factory_receipt_source" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-pack-canonical-sha256 "$fabrication_release_policy_digest" \
  --signed-attestation "$factory_receipt_signed_tampered" \
  --output "$factory_receipt_tampered_output"; then
  echo "expected a tampered factory receipt signature to fail without output" >&2
  exit 1
fi
test ! -e "$factory_receipt_tampered_output"

signed_receipt_release_common=(
  "${fabrication_release_common[@]}"
  --approval "$fabrication_release_approval_a"
  --approval "$fabrication_release_approval_b"
  --routing-drc-fabrication-release-report "$fabrication_release_positive"
  --executable-pinned-fabrication-release-report "$executable_pinned_positive"
  --factory-receipt "$factory_receipt_source"
  --policy-pack "$factory_receipt_policy"
  --expected-routing-pcbex-sha256 "$executable_pinned_pcbex_sha"
  --expected-authorization-pcbex-sha256 "$executable_pinned_pcbex_sha"
  --expected-kicad-cli-sha256 "$executable_pinned_kicad_sha"
)

PYTHONPATH=agent/src python3 -m pcbex_agent \
  signed-factory-receipt-release-report-schema \
  --output "$signed_receipt_release_schema"
PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-signed-factory-receipt-release \
  "${signed_receipt_release_common[@]}" \
  --signed-factory-receipt-attestation "$factory_receipt_signed" \
  --output "$signed_receipt_release_positive" \
  --require-authenticated

if PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-signed-factory-receipt-release \
  "${signed_receipt_release_common[@]}" \
  --signed-factory-receipt-attestation "$factory_receipt_signed_expired" \
  --output "$signed_receipt_release_negative" \
  --require-authenticated 2>"$signed_receipt_release_negative_error"; then
  echo "expected an expired signed receipt release to fail its final gate" >&2
  exit 1
fi
test -s "$signed_receipt_release_negative"
grep -Fxq \
  'signed factory receipt release report was retained but is not authenticated' \
  "$signed_receipt_release_negative_error"

PYTHONPATH=agent/src python3 - \
  "$signed_receipt_release_positive" "$signed_receipt_release_negative" \
  "$signed_receipt_release_schema" "$factory_receipt_report" \
  "$factory_receipt_report_expired" "$factory_receipt_signed" \
  "$fabrication_release_package" "$factory_receipt_source" \
  "$factory_receipt_policy" "$executable_pinned_positive" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

from pcbex_agent import render_signed_factory_receipt_release_report

(
    positive_path,
    negative_path,
    schema_path,
    attestation_report_path,
    expired_report_path,
    signed_path,
    package_path,
    receipt_path,
    policy_path,
    nested_path,
) = map(Path, sys.argv[1:])

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

positive = json.loads(positive_path.read_bytes())
negative = json.loads(negative_path.read_bytes())
schema = json.loads(schema_path.read_bytes())
attestation_report = json.loads(attestation_report_path.read_bytes())
expired_report = json.loads(expired_report_path.read_bytes())

assert positive_path.read_bytes() == render_signed_factory_receipt_release_report(positive)
assert positive["schema_version"] == 1
assert positive["verification_scope"] == \
    "fresh-exact-signed-factory-receipt-release-v1"
assert positive["status"] == "release_authenticated"
assert positive["executable_pinned_fabrication_release_authorized"] is True
assert positive["factory_receipt_attestation_verified"] is True
assert positive["factory_receipt_authenticity_verified"] is True
assert positive["release_authenticated"] is True
assert positive["gate_failures"] == []
assert positive["sources"]["manufacturing_package"] == identity(package_path)
assert positive["sources"]["factory_receipt"] == identity(receipt_path)
assert positive["sources"]["policy_pack"] == identity(policy_path)
assert positive["sources"]["signed_factory_receipt_attestation"] == identity(signed_path)
outer_attestation_report = positive["factory_receipt_attestation"]
for key, value in attestation_report.items():
    if key not in {"evaluated_at_unix", "binding_sha256"}:
        assert outer_attestation_report[key] == value, key
assert (
    outer_attestation_report["attestation"]["issued_at_unix"]
    <= outer_attestation_report["evaluated_at_unix"]
    <= outer_attestation_report["attestation"]["expires_at_unix"]
)
assert positive["attestation_verifier"] == \
    positive["executable_pinned_fabrication_release"]["executable_pins"]["authorization_pcbex"]
assert positive["sources"]["executable_pinned_fabrication_release_report"]["bytes"] == \
    len(nested_path.read_bytes())
assert set(positive["validation"].values()) == {True}

for claim in (
    "trusted_time_verified",
    "factory_legal_identity_verified",
    "endpoint_transport_authenticity_verified",
    "raw_response_authenticity_verified",
    "source_authenticity_verified",
    "executable_origin_authenticity_verified",
    "toolchain_authenticity_verified",
    "policy_pack_authenticity_verified",
    "manufacturability_verified",
    "external_submission_performed",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "challenge_one_time_use_enforced",
):
    assert positive[claim] is False, claim

assert negative["status"] == "not_authenticated"
assert negative["release_authenticated"] is False
assert negative["factory_receipt_authenticity_verified"] is False
assert negative["gate_failures"] == [
    "factory_receipt_attestation_not_authenticated"
]
assert expired_report["status"] == "not_authenticated"
assert expired_report["gate_failures"] == [
    "factory_receipt_attestation_window_inactive"
]

pending = [schema]
objects = arrays = 0
while pending:
    value = pending.pop()
    if isinstance(value, dict):
        if value.get("type") == "object":
            objects += 1
            assert value.get("additionalProperties") is False
        if value.get("type") == "array":
            arrays += 1
            assert "maxItems" in value
        pending.extend(value.values())
    elif isinstance(value, list):
        pending.extend(value)
assert objects > 20 and arrays > 5
PY

# v1.481 freshly replays the same signed-release subject, then consumes its
# attestation challenge once inside one descriptor-pinned local ledger. This
# is a local admission marker only: capacity, submission, order, payment, and
# global one-time use remain false.
signed_release_reservation_ledger="$output_directory/signed-release-reservation-ledger"
signed_release_reservation_id="$(printf 'e%.0s' {1..64})"
signed_release_reservation_schema="$output_directory/signed-release-reservation.schema.json"
signed_release_reservation_ledger_schema="$output_directory/signed-release-reservation-ledger.schema.json"
signed_release_reservation_error="$output_directory/signed-release-reservation.second.stderr"
signed_release_reservation_negative_error="$output_directory/signed-release-reservation.negative.stderr"
mkdir -m 0700 "$signed_release_reservation_ledger"
signed_release_reservation_ledger="$(
  cd "$signed_release_reservation_ledger"
  pwd -P
)"
printf '%s\n' \
  "{\"schema_version\":1,\"ledger_scope\":\"pinned-local-signed-factory-receipt-release-ledger-at-most-once-v1\",\"ledger_id\":\"$signed_release_reservation_id\"}" \
  > "$signed_release_reservation_ledger/.pcbex-signed-factory-receipt-release-reservation-ledger-v1.json"
chmod 0600 "$signed_release_reservation_ledger/.pcbex-signed-factory-receipt-release-reservation-ledger-v1.json"

"$pcbex_binary" signed-factory-receipt-release-reservation-schema \
  --output "$signed_release_reservation_schema"
"$pcbex_binary" signed-factory-receipt-release-reservation-ledger-schema \
  --output "$signed_release_reservation_ledger_schema"

signed_release_reservation_common=(
  "$signed_receipt_release_positive"
  "${signed_receipt_release_common[@]}"
  --signed-factory-receipt-attestation "$factory_receipt_signed"
  --reservation-ledger "$signed_release_reservation_ledger"
  --expected-ledger-id "$signed_release_reservation_id"
)
PYTHONPATH=agent/src python3 -m pcbex_agent \
  reserve-signed-factory-receipt-release \
  "${signed_release_reservation_common[@]}"

signed_release_reservation_marker="$signed_release_reservation_ledger/signed-factory-receipt-release-reservation-v1-$(printf 'c%.0s' {1..64}).json"
test -s "$signed_release_reservation_marker"
signed_release_reservation_marker_sha="$(sha256sum "$signed_release_reservation_marker" | cut -d' ' -f1)"
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  reserve-signed-factory-receipt-release \
  "${signed_release_reservation_common[@]}" \
  2>"$signed_release_reservation_error"; then
  echo "expected the signed release challenge to be burned after one local commit" >&2
  exit 1
fi
grep -Fq 'signed factory receipt release challenge is already reserved' \
  "$signed_release_reservation_error"
test "$signed_release_reservation_marker_sha" = \
  "$(sha256sum "$signed_release_reservation_marker" | cut -d' ' -f1)"

signed_release_reservation_negative_marker="$signed_release_reservation_ledger/signed-factory-receipt-release-reservation-v1-$(printf 'd%.0s' {1..64}).json"
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  reserve-signed-factory-receipt-release \
  "$signed_receipt_release_negative" \
  "${signed_receipt_release_common[@]}" \
  --signed-factory-receipt-attestation "$factory_receipt_signed_expired" \
  --reservation-ledger "$signed_release_reservation_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  2>"$signed_release_reservation_negative_error"; then
  echo "expected a negative signed receipt release to create no reservation" >&2
  exit 1
fi
grep -Fq 'only a freshly authenticated signed receipt release may be reserved' \
  "$signed_release_reservation_negative_error"
test ! -e "$signed_release_reservation_negative_marker"

PYTHONPATH=agent/src python3 - \
  "$signed_release_reservation_marker" \
  "$signed_release_reservation_schema" \
  "$signed_release_reservation_ledger_schema" \
  "$signed_receipt_release_positive" \
  "$signed_release_reservation_id" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

from pcbex_agent import (
    render_signed_factory_receipt_release_reservation,
    signed_factory_receipt_release_subject_sha256,
)

marker_path, schema_path, ledger_schema_path, report_path = map(Path, sys.argv[1:5])
ledger_id = sys.argv[5]
marker = json.loads(marker_path.read_bytes())
report = json.loads(report_path.read_bytes())
assert marker_path.read_bytes() == render_signed_factory_receipt_release_reservation(marker)
assert marker["status"] == "local_reservation_committed"
assert marker["local_challenge_reserved"] is True
assert marker["ledger_id"] == ledger_id
assert marker["release_report_summary"]["release_authenticated"] is True
assert marker["release_report_summary"]["challenge"] == "c" * 64
assert marker["release_report_summary"]["release_subject_sha256"] == \
    signed_factory_receipt_release_subject_sha256(report)
assert marker["release_report_summary"]["retained_report_sha256"] == \
    hashlib.sha256(report_path.read_bytes()).hexdigest()
for claim in (
    "adapter_network_performed",
    "global_challenge_one_time_use_enforced",
    "external_submission_performed",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
):
    assert marker[claim] is False, claim

for schema_file in (schema_path, ledger_schema_path):
    schema = json.loads(schema_file.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.483 preserves the exact v1.482 intent and receipt while authenticating one
# POST and one GET response under the role-disjoint policy key. Replays remain
# local, and reconciliation never retransmits the exact manufacturing ZIP.
signed_release_adapter_intent_schema="$output_directory/signed-release-adapter-intent.schema.json"
signed_release_adapter_ack_schema="$output_directory/signed-release-adapter-ack.schema.json"
signed_release_adapter_receipt_schema="$output_directory/signed-release-adapter-receipt.schema.json"
signed_release_adapter_signature_schema="$output_directory/signed-release-adapter-signature.schema.json"
signed_release_adapter_auth_schema="$output_directory/signed-release-adapter-auth.schema.json"
signed_release_adapter_submit="$output_directory/signed-release-adapter.submit.json"
signed_release_adapter_submit_replay="$output_directory/signed-release-adapter.submit-replay.json"
signed_release_adapter_submit_replay_error="$output_directory/signed-release-adapter.submit-replay.stderr"
signed_release_adapter_reconcile="$output_directory/signed-release-adapter.reconcile.json"
signed_release_adapter_reconcile_replay="$output_directory/signed-release-adapter.reconcile-replay.json"
signed_release_adapter_server="$output_directory/signed-release-adapter-server.py"
signed_release_adapter_submit_ready="$output_directory/signed-release-adapter-submit.ready"
signed_release_adapter_submit_request="$output_directory/signed-release-adapter-submit.request.json"
signed_release_adapter_reconcile_ready="$output_directory/signed-release-adapter-reconcile.ready"
signed_release_adapter_reconcile_request="$output_directory/signed-release-adapter-reconcile.request.json"
signed_release_adapter_token='pcbex-e2e-v1482-bearer-token'
signed_release_adapter_nonce="$(printf 'a%.0s' {1..64})"
signed_release_adapter_reconciliation_id="$(printf 'b%.0s' {1..64})"
export PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN="$signed_release_adapter_token"

"$pcbex_binary" signed-factory-release-submission-intent-schema \
  --output "$signed_release_adapter_intent_schema"
"$pcbex_binary" signed-factory-release-adapter-acknowledgement-schema \
  --output "$signed_release_adapter_ack_schema"
"$pcbex_binary" signed-factory-release-adapter-receipt-schema \
  --output "$signed_release_adapter_receipt_schema"
"$pcbex_binary" factory-release-adapter-http-message-signature-schema \
  --output "$signed_release_adapter_signature_schema"
"$pcbex_binary" factory-release-adapter-response-authentication-report-schema \
  --output "$signed_release_adapter_auth_schema"

cat >"$signed_release_adapter_server" <<'PY'
import base64
import hashlib
import http.server
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

(
    mode,
    status,
    reconciliation_id,
    ready_path,
    request_path,
    token,
    private_key,
) = sys.argv[1:]

class Server(http.server.HTTPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_arguments):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        expected_method = "POST" if mode == "submit" else "GET"
        assert self.command == expected_method
        if mode == "reconcile":
            assert body == b""
            assert self.headers.get("X-PCBEX-Reconciliation-ID") == reconciliation_id
        observed = {
            "method": self.command,
            "path": self.path,
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "authorization_ok": self.headers.get("Authorization") == f"Bearer {token}",
            "response_profile_ok": self.headers.get(
                "X-PCBEX-Response-Signature-Profile"
            ) == "rfc9421-ed25519-content-digest-v1",
            "idempotency_key": self.headers.get("Idempotency-Key"),
            "request_nonce": self.headers.get("X-PCBEX-Request-Nonce"),
        }
        Path(request_path).write_text(
            json.dumps(observed, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        acknowledgement = {
            "schema_version": 1,
            "acknowledgement_scope": "pcbex-signed-factory-release-adapter-acknowledgement-v1",
            "operation": mode,
            "idempotency_key": self.headers["Idempotency-Key"],
            "request_nonce": self.headers["X-PCBEX-Request-Nonce"],
            "reconciliation_id": reconciliation_id if mode == "reconcile" else None,
            "release_subject_sha256": self.headers["X-PCBEX-Release-Subject-SHA256"],
            "manufacturing_package_sha256": self.headers["X-PCBEX-Package-SHA256"],
            "factory_id": self.headers["X-PCBEX-Factory-ID"],
            "provider": "generic",
            "status": status,
            "submission_id": "kicad-e2e-v1482",
        }
        response = json.dumps(
            acknowledgement, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = "sha-256=:" + base64.b64encode(
            hashlib.sha256(response).digest()
        ).decode("ascii") + ":"
        created = int(time.time())
        expires = created + 120
        common = (
            '("@status" "content-digest" "content-type" '
            '"x-pcbex-adapter";req "x-pcbex-schema-version";req '
            '"x-pcbex-response-signature-profile";req '
            '"idempotency-key";req "x-pcbex-request-nonce";req '
        )
        if mode == "reconcile":
            common += '"x-pcbex-reconciliation-id";req '
        common += (
            '"x-pcbex-release-subject-sha256";req '
            '"x-pcbex-package-sha256";req "x-pcbex-factory-id";req '
            '"@method";req "@target-uri";req)'
        )
        parameters = (
            f'{common};created={created};expires={expires};'
            'keyid="kicad-e2e-factory-response";alg="ed25519";'
            'tag="pcbex-signed-factory-release-response-v1"'
        )
        signature_input = "pcbex=" + parameters
        signature_base = [
            '"@status": 200',
            f'"content-digest": {digest}',
            '"content-type": application/json',
            '"x-pcbex-adapter";req: signed-factory-release-http-v1',
            '"x-pcbex-schema-version";req: 1',
            '"x-pcbex-response-signature-profile";req: '
            'rfc9421-ed25519-content-digest-v1',
            f'"idempotency-key";req: {self.headers["Idempotency-Key"]}',
            f'"x-pcbex-request-nonce";req: {self.headers["X-PCBEX-Request-Nonce"]}',
        ]
        if mode == "reconcile":
            signature_base.append(
                f'"x-pcbex-reconciliation-id";req: {reconciliation_id}'
            )
        signature_base.extend([
            '"x-pcbex-release-subject-sha256";req: '
            + self.headers["X-PCBEX-Release-Subject-SHA256"],
            '"x-pcbex-package-sha256";req: '
            + self.headers["X-PCBEX-Package-SHA256"],
            f'"x-pcbex-factory-id";req: {self.headers["X-PCBEX-Factory-ID"]}',
            f'"@method";req: {expected_method}',
            f'"@target-uri";req: http://127.0.0.1:{self.server.server_port}/release',
            f'"@signature-params": {parameters}',
        ])
        with tempfile.NamedTemporaryFile() as signature_base_file:
            signature_base_file.write("\n".join(signature_base).encode("ascii"))
            signature_base_file.flush()
            signed = subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign", "-rawin",
                    "-inkey", private_key, "-in", signature_base_file.name,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Digest", digest)
        self.send_header("Signature-Input", signature_input)
        self.send_header(
            "Signature", "pcbex=:" + base64.b64encode(signed).decode("ascii") + ":"
        )
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response)

    do_POST = _handle
    do_GET = _handle

server = Server(("127.0.0.1", 0), Handler)
Path(ready_path).write_text(
    f"http://127.0.0.1:{server.server_port}/release\n", encoding="utf-8"
)
server.handle_request()
server.server_close()
PY

python3 "$signed_release_adapter_server" \
  submit adapter_pending '' \
  "$signed_release_adapter_submit_ready" \
  "$signed_release_adapter_submit_request" \
  "$signed_release_adapter_token" \
  "$factory_response_private_key" &
signed_release_adapter_server_pid=$!
trap 'kill "$signed_release_adapter_server_pid" 2>/dev/null || true; rm -f -- "$factory_response_private_key" "$factory_response_public_der" "$factory_transparency_private_key" "$factory_transparency_public_der"; rmdir -- "$factory_response_secret_directory" 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
  test -s "$signed_release_adapter_submit_ready" && break
  if ! kill -0 "$signed_release_adapter_server_pid" 2>/dev/null; then
    wait "$signed_release_adapter_server_pid"
  fi
  sleep 0.05
done
test -s "$signed_release_adapter_submit_ready"
signed_release_adapter_submit_endpoint="$(tr -d '\r\n' < "$signed_release_adapter_submit_ready")"
"$pcbex_binary" submit-authenticated-signed-factory-receipt-release \
  "$fabrication_release_package" \
  --reservation-ledger "$signed_release_reservation_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --challenge "$(printf 'c%.0s' {1..64})" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --endpoint "$signed_release_adapter_submit_endpoint" \
  --request-nonce "$signed_release_adapter_nonce" \
  --bearer-token-env PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN \
  --timeout-seconds 30 \
  --allow-http-loopback \
  --output "$signed_release_adapter_submit"
wait "$signed_release_adapter_server_pid"
trap 'rm -f -- "$factory_response_private_key" "$factory_response_public_der" "$factory_transparency_private_key" "$factory_transparency_public_der"; rmdir -- "$factory_response_secret_directory" 2>/dev/null || true' EXIT

signed_release_adapter_key="$(jq -r .adapter_receipt.idempotency_key "$signed_release_adapter_submit")"
if "$pcbex_binary" submit-authenticated-signed-factory-receipt-release \
  "$fabrication_release_package" \
  --reservation-ledger "$signed_release_reservation_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --challenge "$(printf 'c%.0s' {1..64})" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --endpoint "$signed_release_adapter_submit_endpoint" \
  --request-nonce "$signed_release_adapter_nonce" \
  --bearer-token-env PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN \
  --timeout-seconds 30 \
  --allow-http-loopback \
  --require-accepted \
  --output "$signed_release_adapter_submit_replay" \
  2>"$signed_release_adapter_submit_replay_error"; then
  echo "expected the retained pending adapter result to fail its final gate" >&2
  exit 1
fi
cmp "$signed_release_adapter_submit" "$signed_release_adapter_submit_replay"
grep -Fq 'did not accept the release' \
  "$signed_release_adapter_submit_replay_error"

python3 "$signed_release_adapter_server" \
  reconcile adapter_accepted "$signed_release_adapter_reconciliation_id" \
  "$signed_release_adapter_reconcile_ready" \
  "$signed_release_adapter_reconcile_request" \
  "$signed_release_adapter_token" \
  "$factory_response_private_key" &
signed_release_adapter_server_pid=$!
trap 'kill "$signed_release_adapter_server_pid" 2>/dev/null || true; rm -f -- "$factory_response_private_key" "$factory_response_public_der" "$factory_transparency_private_key" "$factory_transparency_public_der"; rmdir -- "$factory_response_secret_directory" 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
  test -s "$signed_release_adapter_reconcile_ready" && break
  if ! kill -0 "$signed_release_adapter_server_pid" 2>/dev/null; then
    wait "$signed_release_adapter_server_pid"
  fi
  sleep 0.05
done
test -s "$signed_release_adapter_reconcile_ready"
signed_release_adapter_reconcile_endpoint="$(tr -d '\r\n' < "$signed_release_adapter_reconcile_ready")"
"$pcbex_binary" reconcile-authenticated-signed-factory-receipt-release \
  --reservation-ledger "$signed_release_reservation_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$signed_release_adapter_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --endpoint "$signed_release_adapter_reconcile_endpoint" \
  --reconciliation-id "$signed_release_adapter_reconciliation_id" \
  --bearer-token-env PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN \
  --timeout-seconds 30 \
  --allow-http-loopback \
  --require-accepted \
  --output "$signed_release_adapter_reconcile"
wait "$signed_release_adapter_server_pid"
trap 'rm -f -- "$factory_response_private_key" "$factory_response_public_der" "$factory_transparency_private_key" "$factory_transparency_public_der"; rmdir -- "$factory_response_secret_directory" 2>/dev/null || true' EXIT

"$pcbex_binary" reconcile-authenticated-signed-factory-receipt-release \
  --reservation-ledger "$signed_release_reservation_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$signed_release_adapter_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --endpoint "$signed_release_adapter_reconcile_endpoint" \
  --reconciliation-id "$signed_release_adapter_reconciliation_id" \
  --bearer-token-env PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN \
  --timeout-seconds 30 \
  --allow-http-loopback \
  --require-accepted \
  --output "$signed_release_adapter_reconcile_replay"
cmp "$signed_release_adapter_reconcile" "$signed_release_adapter_reconcile_replay"

python3 - \
  "$signed_release_adapter_submit" \
  "$signed_release_adapter_reconcile" \
  "$signed_release_adapter_submit_request" \
  "$signed_release_adapter_reconcile_request" \
  "$fabrication_release_package" \
  "$signed_release_reservation_ledger" \
  "$signed_release_adapter_token" \
  "$signed_release_adapter_intent_schema" \
  "$signed_release_adapter_ack_schema" \
  "$signed_release_adapter_receipt_schema" \
  "$signed_release_adapter_signature_schema" \
  "$signed_release_adapter_auth_schema" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

(
    submit_path,
    reconcile_path,
    submit_request_path,
    reconcile_request_path,
    package_path,
    ledger_path,
) = map(Path, sys.argv[1:7])
token = sys.argv[7]
schema_paths = list(map(Path, sys.argv[8:]))
submit_report = json.loads(submit_path.read_bytes())
reconcile_report = json.loads(reconcile_path.read_bytes())
submit = submit_report["adapter_receipt"]
reconcile = reconcile_report["adapter_receipt"]
submit_request = json.loads(submit_request_path.read_bytes())
reconcile_request = json.loads(reconcile_request_path.read_bytes())
package = package_path.read_bytes()

assert submit["status"] == "adapter_pending"
assert submit["accepted"] is False
assert submit["operation"] == "submit"
assert submit["manufacturing_package_transmission_attempted"] is True
assert submit["external_submission_attempted"] is True
assert submit["acknowledgement_validated"] is True
assert reconcile["status"] == "adapter_accepted"
assert reconcile["accepted"] is True
assert reconcile["operation"] == "reconcile"
assert reconcile["manufacturing_package_transmission_attempted"] is False
assert reconcile["external_submission_attempted"] is False
assert reconcile["acknowledgement_validated"] is True
assert reconcile["idempotency_key"] == submit["idempotency_key"]

for report in (submit_report, reconcile_report):
    assert report["status"] == "response_authenticated"
    assert report["response_authenticated"] is True
    assert report["response_signature_verified"] is True
    assert report["response_content_digest_verified"] is True
    assert report["policy_pack_pin_matched"] is True
    assert report["signer_policy_matched"] is True
    assert report["signature_time_active"] is True
    assert report["acknowledgement_authenticated"] is True
    assert report["raw_response_authenticity_verified"] is True
    assert report["signer"]["key_id"] == "kicad-e2e-factory-response"
    assert report["response_signature"]["algorithm"] == "ed25519"
    assert report["authentication_failure"] is None
    for claim in (
        "endpoint_transport_authenticity_verified",
        "factory_legal_identity_verified",
        "trusted_time_verified",
        "server_side_idempotency_enforced",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "exactly_once_execution_verified",
    ):
        assert report[claim] is False, claim

for receipt in (submit, reconcile):
    for claim in (
        "server_side_idempotency_enforced",
        "factory_legal_identity_verified",
        "endpoint_transport_authenticity_verified",
        "raw_response_authenticity_verified",
        "trusted_time_verified",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "exactly_once_execution_verified",
    ):
        assert receipt[claim] is False, claim

    assert isinstance(receipt["attempted_at_unix"], int)
    assert receipt["attempted_at_unix"] >= 0

assert submit_request == {
    "authorization_ok": True,
    "response_profile_ok": True,
    "body_bytes": len(package),
    "body_sha256": hashlib.sha256(package).hexdigest(),
    "idempotency_key": submit["idempotency_key"],
    "method": "POST",
    "path": "/release",
    "request_nonce": "a" * 64,
}
assert reconcile_request == {
    "authorization_ok": True,
    "response_profile_ok": True,
    "body_bytes": 0,
    "body_sha256": hashlib.sha256(b"").hexdigest(),
    "idempotency_key": submit["idempotency_key"],
    "method": "GET",
    "path": "/release",
    "request_nonce": "a" * 64,
}

for path in [submit_path, reconcile_path, *ledger_path.iterdir()]:
    assert token.encode() not in path.read_bytes(), path

ledger_names = {path.name for path in ledger_path.iterdir()}
assert any(name.startswith("authenticated-factory-release-submission-v1-")
           for name in ledger_names)
assert any(name.startswith("authenticated-factory-release-reconciliation-v1-")
           for name in ledger_names)

for schema_path in schema_paths:
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.484 signs the accepted local head and a semantic state chain. The real
# production ZIP moves from pending generation zero to accepted generation one;
# replay repairs locally and a terminal head suppresses every later GET.
monotonic_release_ledger="$output_directory/monotonic-signed-release-ledger"
mkdir -m 0700 "$monotonic_release_ledger"
cp -- \
  "$signed_release_reservation_ledger/.pcbex-signed-factory-receipt-release-reservation-ledger-v1.json" \
  "$monotonic_release_ledger/.pcbex-signed-factory-receipt-release-reservation-ledger-v1.json"
cp -- "$signed_release_reservation_marker" "$monotonic_release_ledger/"
chmod 0600 "$monotonic_release_ledger"/* "$monotonic_release_ledger"/.pcbex-*.json
monotonic_release_ledger="$(cd "$monotonic_release_ledger" && pwd -P)"
monotonic_state_schema="$output_directory/monotonic-factory-state.schema.json"
monotonic_signature_schema="$output_directory/monotonic-factory-signature.schema.json"
monotonic_entry_schema="$output_directory/monotonic-factory-entry.schema.json"
monotonic_report_schema="$output_directory/monotonic-factory-report.schema.json"
monotonic_submit="$output_directory/monotonic-factory.submit.json"
monotonic_submit_replay="$output_directory/monotonic-factory.submit-replay.json"
monotonic_submit_replay_error="$output_directory/monotonic-factory.submit-replay.stderr"
monotonic_reconcile="$output_directory/monotonic-factory.reconcile.json"
monotonic_terminal_replay="$output_directory/monotonic-factory.terminal-replay.json"
monotonic_submit_ready="$output_directory/monotonic-factory-submit.ready"
monotonic_submit_request="$output_directory/monotonic-factory-submit.request.json"
monotonic_reconcile_ready="$output_directory/monotonic-factory-reconcile.ready"
monotonic_reconcile_request="$output_directory/monotonic-factory-reconcile.request.json"
monotonic_nonce="$(printf 'd%.0s' {1..64})"
monotonic_reconciliation_id="$(printf 'f%.0s' {1..64})"

"$pcbex_binary" factory-release-adapter-monotonic-state-schema \
  --output "$monotonic_state_schema"
"$pcbex_binary" factory-release-adapter-monotonic-http-message-signature-schema \
  --output "$monotonic_signature_schema"
"$pcbex_binary" factory-release-adapter-monotonic-state-entry-schema \
  --output "$monotonic_entry_schema"
"$pcbex_binary" factory-release-adapter-monotonic-observation-report-schema \
  --output "$monotonic_report_schema"

cat >"$signed_release_adapter_server" <<'PY'
import base64
import hashlib
import http.server
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

(
    mode,
    status,
    reconciliation_id,
    sequence_text,
    ready_path,
    request_path,
    token,
    private_key,
) = sys.argv[1:]
sequence = int(sequence_text)

class Server(http.server.HTTPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_arguments):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(length)
        expected_method = "POST" if mode == "submit" else "GET"
        assert self.command == expected_method
        if mode == "reconcile":
            assert request_body == b""
            assert self.headers.get("X-PCBEX-Reconciliation-ID") == reconciliation_id
        accepted_sequence = self.headers["X-PCBEX-Accepted-State-Sequence"]
        accepted_sha256 = self.headers["X-PCBEX-Accepted-State-SHA256"]
        if sequence == 0:
            assert accepted_sequence == "none"
            assert accepted_sha256 == "none"
            previous_sha256 = None
            previous_header = "none"
        else:
            assert accepted_sequence == str(sequence - 1)
            assert len(accepted_sha256) == 64
            previous_sha256 = accepted_sha256
            previous_header = accepted_sha256
        assert self.headers.get("X-PCBEX-Response-Signature-Profile") == \
            "rfc9421-ed25519-content-digest-monotonic-state-v1"
        observed = {
            "method": self.command,
            "path": self.path,
            "body_bytes": len(request_body),
            "body_sha256": hashlib.sha256(request_body).hexdigest(),
            "authorization_ok": self.headers.get("Authorization") == f"Bearer {token}",
            "accepted_sequence": accepted_sequence,
            "accepted_sha256": accepted_sha256,
            "idempotency_key": self.headers["Idempotency-Key"],
        }
        Path(request_path).write_text(
            json.dumps(observed, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        acknowledgement = {
            "schema_version": 1,
            "acknowledgement_scope": "pcbex-signed-factory-release-adapter-acknowledgement-v1",
            "operation": mode,
            "idempotency_key": self.headers["Idempotency-Key"],
            "request_nonce": self.headers["X-PCBEX-Request-Nonce"],
            "reconciliation_id": reconciliation_id if mode == "reconcile" else None,
            "release_subject_sha256": self.headers["X-PCBEX-Release-Subject-SHA256"],
            "manufacturing_package_sha256": self.headers["X-PCBEX-Package-SHA256"],
            "factory_id": self.headers["X-PCBEX-Factory-ID"],
            "provider": "generic",
            "status": status,
            "submission_id": "kicad-e2e-v1484",
        }
        response = json.dumps(
            acknowledgement, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        state_material = {
            "schema_version": 1,
            "state_scope": "authenticated-monotonic-factory-release-adapter-state-v1",
            "sequence": sequence,
            "previous_state_sha256": previous_sha256,
            "idempotency_key": acknowledgement["idempotency_key"],
            "submission_id": acknowledgement["submission_id"],
            "factory_id": acknowledgement["factory_id"],
            "provider": acknowledgement["provider"],
            "release_subject_sha256": acknowledgement["release_subject_sha256"],
            "manufacturing_package_sha256": acknowledgement["manufacturing_package_sha256"],
            "status": acknowledgement["status"],
        }
        state_source = json.dumps(
            state_material, separators=(",", ":")
        ).encode("ascii")
        state_sha256 = hashlib.sha256(
            b"pcbex:factory-release-adapter-monotonic-state:v1\0" + state_source
        ).hexdigest()
        digest = "sha-256=:" + base64.b64encode(
            hashlib.sha256(response).digest()
        ).decode("ascii") + ":"
        created = int(time.time())
        expires = created + 120
        common = (
            '("@status" "content-digest" "content-type" '
            '"x-pcbex-state-sequence" "x-pcbex-state-previous-sha256" '
            '"x-pcbex-state-sha256" "x-pcbex-adapter";req '
            '"x-pcbex-schema-version";req '
            '"x-pcbex-response-signature-profile";req '
            '"x-pcbex-accepted-state-sequence";req '
            '"x-pcbex-accepted-state-sha256";req '
            '"idempotency-key";req "x-pcbex-request-nonce";req '
        )
        if mode == "reconcile":
            common += '"x-pcbex-reconciliation-id";req '
        common += (
            '"x-pcbex-release-subject-sha256";req '
            '"x-pcbex-package-sha256";req "x-pcbex-factory-id";req '
            '"@method";req "@target-uri";req)'
        )
        parameters = (
            f'{common};created={created};expires={expires};'
            'keyid="kicad-e2e-factory-response";alg="ed25519";'
            'tag="pcbex-signed-factory-release-monotonic-state-response-v1"'
        )
        signature_input = "pcbex-state=" + parameters
        signature_base = [
            '"@status": 200',
            f'"content-digest": {digest}',
            '"content-type": application/json',
            f'"x-pcbex-state-sequence": {sequence}',
            f'"x-pcbex-state-previous-sha256": {previous_header}',
            f'"x-pcbex-state-sha256": {state_sha256}',
            '"x-pcbex-adapter";req: signed-factory-release-http-v1',
            '"x-pcbex-schema-version";req: 1',
            '"x-pcbex-response-signature-profile";req: '
            'rfc9421-ed25519-content-digest-monotonic-state-v1',
            f'"x-pcbex-accepted-state-sequence";req: {accepted_sequence}',
            f'"x-pcbex-accepted-state-sha256";req: {accepted_sha256}',
            f'"idempotency-key";req: {self.headers["Idempotency-Key"]}',
            f'"x-pcbex-request-nonce";req: {self.headers["X-PCBEX-Request-Nonce"]}',
        ]
        if mode == "reconcile":
            signature_base.append(
                f'"x-pcbex-reconciliation-id";req: {reconciliation_id}'
            )
        signature_base.extend([
            '"x-pcbex-release-subject-sha256";req: '
            + self.headers["X-PCBEX-Release-Subject-SHA256"],
            '"x-pcbex-package-sha256";req: '
            + self.headers["X-PCBEX-Package-SHA256"],
            f'"x-pcbex-factory-id";req: {self.headers["X-PCBEX-Factory-ID"]}',
            f'"@method";req: {expected_method}',
            f'"@target-uri";req: http://127.0.0.1:{self.server.server_port}/release',
            f'"@signature-params": {parameters}',
        ])
        with tempfile.NamedTemporaryFile() as signature_base_file:
            signature_base_file.write("\n".join(signature_base).encode("ascii"))
            signature_base_file.flush()
            signed = subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign", "-rawin",
                    "-inkey", private_key, "-in", signature_base_file.name,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Digest", digest)
        self.send_header("X-PCBEX-State-Sequence", str(sequence))
        self.send_header("X-PCBEX-State-Previous-SHA256", previous_header)
        self.send_header("X-PCBEX-State-SHA256", state_sha256)
        self.send_header("Signature-Input", signature_input)
        self.send_header(
            "Signature", "pcbex-state=:" + base64.b64encode(signed).decode("ascii") + ":"
        )
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response)

    do_POST = _handle
    do_GET = _handle

server = Server(("127.0.0.1", 0), Handler)
Path(ready_path).write_text(
    f"http://127.0.0.1:{server.server_port}/release\n", encoding="utf-8"
)
server.handle_request()
server.server_close()
PY

python3 "$signed_release_adapter_server" \
  submit adapter_pending '' 0 \
  "$monotonic_submit_ready" "$monotonic_submit_request" \
  "$signed_release_adapter_token" "$factory_response_private_key" &
signed_release_adapter_server_pid=$!
trap 'kill "$signed_release_adapter_server_pid" 2>/dev/null || true; rm -f -- "$factory_response_private_key" "$factory_response_public_der" "$factory_transparency_private_key" "$factory_transparency_public_der"; rmdir -- "$factory_response_secret_directory" 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
  test -s "$monotonic_submit_ready" && break
  if ! kill -0 "$signed_release_adapter_server_pid" 2>/dev/null; then
    wait "$signed_release_adapter_server_pid"
  fi
  sleep 0.05
done
test -s "$monotonic_submit_ready"
monotonic_submit_endpoint="$(tr -d '\r\n' < "$monotonic_submit_ready")"
"$pcbex_binary" submit-monotonic-authenticated-signed-factory-receipt-release \
  "$fabrication_release_package" \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --challenge "$(printf 'c%.0s' {1..64})" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --endpoint "$monotonic_submit_endpoint" \
  --request-nonce "$monotonic_nonce" \
  --bearer-token-env PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN \
  --timeout-seconds 30 --allow-http-loopback \
  --output "$monotonic_submit"
wait "$signed_release_adapter_server_pid"

monotonic_key="$(jq -r .adapter_receipt.idempotency_key "$monotonic_submit")"
if "$pcbex_binary" submit-monotonic-authenticated-signed-factory-receipt-release \
  "$fabrication_release_package" \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --challenge "$(printf 'c%.0s' {1..64})" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --endpoint "$monotonic_submit_endpoint" \
  --request-nonce "$monotonic_nonce" \
  --bearer-token-env PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN \
  --timeout-seconds 30 --allow-http-loopback --require-accepted \
  --output "$monotonic_submit_replay" \
  2>"$monotonic_submit_replay_error"; then
  echo "expected retained pending monotonic state to fail its final gate" >&2
  exit 1
fi
cmp "$monotonic_submit" "$monotonic_submit_replay"
grep -Fq 'state has not accepted the release' "$monotonic_submit_replay_error"

python3 "$signed_release_adapter_server" \
  reconcile adapter_accepted "$monotonic_reconciliation_id" 1 \
  "$monotonic_reconcile_ready" "$monotonic_reconcile_request" \
  "$signed_release_adapter_token" "$factory_response_private_key" &
signed_release_adapter_server_pid=$!
for _ in $(seq 1 100); do
  test -s "$monotonic_reconcile_ready" && break
  if ! kill -0 "$signed_release_adapter_server_pid" 2>/dev/null; then
    wait "$signed_release_adapter_server_pid"
  fi
  sleep 0.05
done
test -s "$monotonic_reconcile_ready"
monotonic_reconcile_endpoint="$(tr -d '\r\n' < "$monotonic_reconcile_ready")"
"$pcbex_binary" reconcile-monotonic-authenticated-signed-factory-receipt-release \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --endpoint "$monotonic_reconcile_endpoint" \
  --reconciliation-id "$monotonic_reconciliation_id" \
  --bearer-token-env PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN \
  --timeout-seconds 30 --allow-http-loopback --require-accepted \
  --output "$monotonic_reconcile"
wait "$signed_release_adapter_server_pid"

"$pcbex_binary" reconcile-monotonic-authenticated-signed-factory-receipt-release \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --endpoint "$monotonic_reconcile_endpoint" \
  --reconciliation-id "$(printf '1%.0s' {1..64})" \
  --bearer-token-env PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN \
  --timeout-seconds 30 --allow-http-loopback --require-accepted \
  --output "$monotonic_terminal_replay"
cmp "$monotonic_reconcile" "$monotonic_terminal_replay"

python3 - \
  "$monotonic_submit" "$monotonic_reconcile" \
  "$monotonic_submit_request" "$monotonic_reconcile_request" \
  "$fabrication_release_package" "$monotonic_release_ledger" \
  "$signed_release_adapter_token" \
  "$monotonic_state_schema" "$monotonic_signature_schema" \
  "$monotonic_entry_schema" "$monotonic_report_schema" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

submit_path, reconcile_path, submit_request_path, reconcile_request_path, package_path, ledger_path = \
    map(Path, sys.argv[1:7])
token = sys.argv[7]
schema_paths = list(map(Path, sys.argv[8:]))
submit = json.loads(submit_path.read_bytes())
reconcile = json.loads(reconcile_path.read_bytes())
submit_request = json.loads(submit_request_path.read_bytes())
reconcile_request = json.loads(reconcile_request_path.read_bytes())
package = package_path.read_bytes()

assert submit["response_authenticated"] is True
assert submit["state_continuity_verified"] is True
assert submit["requested_state"] is None
assert submit["observed_state"]["sequence"] == 0
assert submit["observed_state"]["status"] == "adapter_pending"
assert submit["accepted"] is False
assert reconcile["response_authenticated"] is True
assert reconcile["state_continuity_verified"] is True
assert reconcile["requested_state"] == submit["observed_state"]
assert reconcile["observed_state"]["sequence"] == 1
assert reconcile["observed_state"]["previous_state_sha256"] == \
    submit["observed_state"]["state_sha256"]
assert reconcile["observed_state"]["status"] == "adapter_accepted"
assert reconcile["accepted"] is True
for report in (submit, reconcile):
    assert report["state_headers_authenticated"] is True
    assert report["state_digest_verified"] is True
    assert report["request_head_bound"] is True
    assert report["transition_verified"] is True
    assert report["requested_head_continuity_verified"] is True
    assert report["global_non_equivocation_verified"] is False
    for claim in (
        "selected_ledger_state_committed",
        "endpoint_transport_authenticity_verified",
        "factory_legal_identity_verified",
        "trusted_time_verified",
        "server_side_idempotency_enforced",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "exactly_once_execution_verified",
    ):
        assert report[claim] is False, claim

assert submit_request["body_bytes"] == len(package)
assert submit_request["body_sha256"] == hashlib.sha256(package).hexdigest()
assert submit_request["accepted_sequence"] == "none"
assert submit_request["accepted_sha256"] == "none"
assert reconcile_request["body_bytes"] == 0
assert reconcile_request["body_sha256"] == hashlib.sha256(b"").hexdigest()
assert reconcile_request["accepted_sequence"] == "0"
assert reconcile_request["accepted_sha256"] == submit["observed_state"]["state_sha256"]

ledger_names = {path.name for path in ledger_path.iterdir()}
key = submit["adapter_receipt"]["idempotency_key"]
assert f"monotonic-factory-release-state-v1-{key}-0000.json" in ledger_names
assert f"monotonic-factory-release-state-v1-{key}-0001.json" in ledger_names
assert any(name.startswith("monotonic-factory-release-submission-v1-")
           for name in ledger_names)
assert any(name.startswith("monotonic-factory-release-reconciliation-v1-")
           for name in ledger_names)
for path in [submit_path, reconcile_path, *ledger_path.iterdir()]:
    assert token.encode() not in path.read_bytes(), path
for schema_path in schema_paths:
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.485 binds the exact verified v1.484 head into one policy-pinned signed
# Merkle view. The receipt is retained immutably, while global log consistency
# and trusted timestamping remain explicit nonclaims.
factory_transparency_policy_schema="$output_directory/factory-release-transparency-policy.schema.json"
factory_transparency_policy="$output_directory/factory-release-transparency.policy.json"
factory_transparency_policy_digest_file="$output_directory/factory-release-transparency.policy.sha256"
factory_transparency_receipt_schema="$output_directory/factory-release-transparency-receipt.schema.json"
factory_transparency_report_schema="$output_directory/factory-release-transparency-report.schema.json"
factory_transparency_receipt="$output_directory/factory-release-transparency.receipt.json"
factory_transparency_tampered_receipt="$output_directory/factory-release-transparency.tampered.json"
factory_transparency_tampered_output="$output_directory/factory-release-transparency.tampered-output.json"
factory_transparency_tampered_error="$output_directory/factory-release-transparency.tampered.stderr"
factory_transparency_report="$output_directory/factory-release-transparency.report.json"
factory_transparency_replay="$output_directory/factory-release-transparency.replay.json"
factory_transparency_evaluated_at="$output_directory/factory-release-transparency.evaluated-at"

"$pcbex_binary" factory-release-state-transparency-policy-schema \
  --output "$factory_transparency_policy_schema"
"$pcbex_binary" factory-release-state-transparency-receipt-schema \
  --output "$factory_transparency_receipt_schema"
"$pcbex_binary" factory-release-state-transparency-verification-report-schema \
  --output "$factory_transparency_report_schema"

python3 - \
  "$factory_transparency_public_key" "$factory_transparency_policy" \
  "$factory_transparency_policy_digest_file" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

public_key_path, policy_path, digest_path = map(Path, sys.argv[1:])
policy = {
    "schema_version": 1,
    "policy_scope": "factory-release-state-transparency-trust-policy-v1",
    "maximum_checkpoint_age_seconds": 300,
    "trusted_logs": [
        {
            "log_id": "kicad-e2e-factory-release-log",
            "public_key": public_key_path.read_text(encoding="ascii").strip(),
        }
    ],
}
policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
digest = hashlib.sha256(
    json.dumps(policy, separators=(",", ":")).encode("ascii")
).hexdigest()
digest_path.write_text(digest + "\n", encoding="ascii")
PY
factory_transparency_policy_digest="$(tr -d '\r\n' < "$factory_transparency_policy_digest_file")"

python3 - \
  "$monotonic_release_ledger" "$monotonic_key" \
  "$factory_transparency_private_key" "$factory_transparency_public_key" \
  "$factory_transparency_receipt" "$factory_transparency_tampered_receipt" \
  "$factory_transparency_evaluated_at" <<'PY'
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ledger, key, private_key, public_key, receipt_path, tampered_path, evaluated_path = \
    sys.argv[1:]
ledger = Path(ledger)
entry_path = ledger / f"monotonic-factory-release-state-v1-{key}-0001.json"
entry_source = entry_path.read_bytes()
entry = json.loads(entry_source)
state = entry["state"]
assert state["sequence"] == 1
assert state["status"] == "adapter_accepted"
state_entry_sha256 = hashlib.sha256(entry_source).hexdigest()
leaf_material = {
    "state_entry_sha256": state_entry_sha256,
    "observation_sha256": entry["observation"]["sha256"],
    "state_sequence": state["sequence"],
    "state_sha256": state["state_sha256"],
    "state_status": state["status"],
    "idempotency_key": state["idempotency_key"],
    "factory_id": state["factory_id"],
    "provider": state["provider"],
    "release_subject_sha256": state["release_subject_sha256"],
    "manufacturing_package_sha256": state["manufacturing_package_sha256"],
}
leaf_sha256 = hashlib.sha256(
    b"pcbex:factory-release-state-transparency-leaf:v1\0"
    + json.dumps(leaf_material, separators=(",", ":")).encode("ascii")
).hexdigest()
root_sha256 = hashlib.sha256(
    b"\x00pcbex:factory-release-state-transparency-merkle-leaf:v1\0"
    + bytes.fromhex(leaf_sha256)
).hexdigest()
observed_at_unix = int(time.time())
tree_head = {
    "schema_version": 1,
    "tree_head_scope": "signed-factory-release-state-transparency-tree-head-v1",
    "log_id": "kicad-e2e-factory-release-log",
    "tree_size": 1,
    "root_sha256": root_sha256,
    "observed_at_unix": observed_at_unix,
    "algorithm": "ed25519",
    "public_key": Path(public_key).read_text(encoding="ascii").strip(),
    "signature": "",
}
signature_payload = {
    "domain": "pcbex-factory-release-state-transparency-tree-head-v1",
    "tree_head_scope": tree_head["tree_head_scope"],
    "log_id": tree_head["log_id"],
    "tree_size": tree_head["tree_size"],
    "root_sha256": tree_head["root_sha256"],
    "observed_at_unix": tree_head["observed_at_unix"],
}
with tempfile.NamedTemporaryFile() as payload:
    payload.write(json.dumps(signature_payload, separators=(",", ":")).encode("ascii"))
    payload.flush()
    signature = subprocess.run(
        [
            "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", private_key,
            "-in", payload.name,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout
tree_head["signature"] = signature.hex()
receipt = {
    "schema_version": 1,
    "receipt_scope": "policy-pinned-factory-release-state-transparency-receipt-v1",
    "state_entry_sha256": state_entry_sha256,
    "leaf_sha256": leaf_sha256,
    "leaf_index": 0,
    "audit_path": [],
    "tree_head": tree_head,
}
receipt_path = Path(receipt_path)
receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
tampered = copy.deepcopy(receipt)
first = tampered["tree_head"]["signature"][0]
tampered["tree_head"]["signature"] = ("1" if first == "0" else "0") + \
    tampered["tree_head"]["signature"][1:]
Path(tampered_path).write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
Path(evaluated_path).write_text(str(observed_at_unix + 1) + "\n", encoding="ascii")
PY

factory_transparency_time="$(tr -d '\r\n' < "$factory_transparency_evaluated_at")"
if "$pcbex_binary" verify-factory-release-state-transparency-receipt \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --receipt "$factory_transparency_tampered_receipt" \
  --evaluated-at-unix "$factory_transparency_time" \
  --output "$factory_transparency_tampered_output" \
  2>"$factory_transparency_tampered_error"; then
  echo "expected a forged factory transparency receipt to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_tampered_output"
grep -Fq 'tree-head signature' "$factory_transparency_tampered_error"

"$pcbex_binary" verify-factory-release-state-transparency-receipt \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --receipt "$factory_transparency_receipt" \
  --evaluated-at-unix "$factory_transparency_time" \
  --output "$factory_transparency_report" \
  --require-accepted
"$pcbex_binary" verify-factory-release-state-transparency-receipt \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --receipt "$factory_transparency_receipt" \
  --evaluated-at-unix "$((factory_transparency_time + 10000))" \
  --output "$factory_transparency_replay" \
  --require-accepted
cmp "$factory_transparency_report" "$factory_transparency_replay"

python3 - \
  "$factory_transparency_report" "$factory_transparency_policy" \
  "$factory_transparency_receipt" "$factory_transparency_policy_schema" \
  "$factory_transparency_receipt_schema" "$factory_transparency_report_schema" \
  "$monotonic_release_ledger" "$monotonic_key" \
  "$signed_release_adapter_token" "$factory_transparency_policy_digest" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

report_path, policy_path, receipt_path, policy_schema_path, receipt_schema_path, \
    report_schema_path, ledger_path = map(Path, sys.argv[1:8])
key, token, policy_digest = sys.argv[8:]
report = json.loads(report_path.read_bytes())
policy = json.loads(policy_path.read_bytes())
receipt = json.loads(receipt_path.read_bytes())
assert report["status"] == "verified"
for claim in (
    "monotonic_state_chain_verified",
    "state_entry_identity_verified",
    "observation_identity_verified",
    "policy_pack_pin_matched",
    "transparency_policy_pin_matched",
    "transparency_log_policy_matched",
    "tree_head_signature_verified",
    "inclusion_proof_verified",
    "transparency_inclusion_verified",
    "checkpoint_fresh_at_evaluation",
):
    assert report[claim] is True, claim
for claim in (
    "selected_ledger_transparency_report_committed",
    "global_non_equivocation_verified",
    "selected_ledger_rollback_resistance_verified",
    "trusted_time_verified",
    "endpoint_transport_authenticity_verified",
    "factory_legal_identity_verified",
    "server_side_idempotency_enforced",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim
assert report["state_sequence"] == 1
assert report["state_status"] == "adapter_accepted"
assert report["transparency_policy_sha256"] == policy_digest
assert policy["policy_scope"] == \
    "factory-release-state-transparency-trust-policy-v1"
assert report["transparency_receipt"] == receipt
assert report["receipt_artifact"] == {
    "bytes": len(receipt_path.read_bytes()),
    "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
}
ledger_name = (
    f"factory-release-state-transparency-v1-{key}-0001-"
    "kicad-e2e-factory-release-log.json"
)
assert (ledger_path / ledger_name).read_bytes() == report_path.read_bytes()
for path in [report_path, receipt_path, *ledger_path.iterdir()]:
    assert token.encode() not in path.read_bytes(), path
for schema_path in (policy_schema_path, receipt_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.486 proves that two retained signed views from the same log are related by
# strict append-only extension. Two generations exercise both the v1.485
# bootstrap anchor and the durable v1.486 predecessor link.
factory_transparency_consistency_proof_schema="$output_directory/factory-release-transparency-consistency-proof.schema.json"
factory_transparency_consistency_report_schema="$output_directory/factory-release-transparency-consistency-report.schema.json"
factory_transparency_receipt_three="$output_directory/factory-release-transparency.tree-3.receipt.json"
factory_transparency_receipt_four="$output_directory/factory-release-transparency.tree-4.receipt.json"
factory_transparency_consistency_proof_one="$output_directory/factory-release-transparency.consistency-1.proof.json"
factory_transparency_consistency_proof_two="$output_directory/factory-release-transparency.consistency-2.proof.json"
factory_transparency_consistency_tampered_proof="$output_directory/factory-release-transparency.consistency-tampered.proof.json"
factory_transparency_consistency_tampered_output="$output_directory/factory-release-transparency.consistency-tampered.report.json"
factory_transparency_consistency_tampered_error="$output_directory/factory-release-transparency.consistency-tampered.stderr"
factory_transparency_consistency_report_one="$output_directory/factory-release-transparency.consistency-1.report.json"
factory_transparency_consistency_replay="$output_directory/factory-release-transparency.consistency-1.replay.json"
factory_transparency_consistency_report_two="$output_directory/factory-release-transparency.consistency-2.report.json"
factory_transparency_consistency_times="$output_directory/factory-release-transparency.consistency-times"

"$pcbex_binary" factory-release-state-transparency-consistency-proof-schema \
  --output "$factory_transparency_consistency_proof_schema"
"$pcbex_binary" factory-release-state-transparency-consistency-verification-report-schema \
  --output "$factory_transparency_consistency_report_schema"

python3 - \
  "$factory_transparency_receipt" "$factory_transparency_private_key" \
  "$factory_transparency_receipt_three" "$factory_transparency_receipt_four" \
  "$factory_transparency_consistency_proof_one" \
  "$factory_transparency_consistency_proof_two" \
  "$factory_transparency_consistency_tampered_proof" \
  "$factory_transparency_consistency_times" <<'PY'
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

old_receipt_path, private_key, receipt_three_path, receipt_four_path, \
    proof_one_path, proof_two_path, tampered_path, times_path = sys.argv[1:]
old_receipt = json.loads(Path(old_receipt_path).read_bytes())
old_head = old_receipt["tree_head"]
assert old_head["tree_size"] == 1

def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()

def root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return node(root(leaves[:split]), root(leaves[split:]))

def audit_path(leaves, index):
    if len(leaves) == 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return audit_path(leaves[:split], index) + [root(leaves[split:])]
    return audit_path(leaves[split:], index - split) + [root(leaves[:split])]

def subproof(old_size, leaves, complete):
    if old_size == len(leaves):
        return [] if complete else [root(leaves)]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if old_size <= split:
        return subproof(old_size, leaves[:split], complete) + [root(leaves[split:])]
    return subproof(old_size - split, leaves[split:], False) + [root(leaves[:split])]

def compact_sha(value):
    return hashlib.sha256(
        json.dumps(value, separators=(",", ":")).encode("ascii")
    ).hexdigest()

def sign_head(leaves, observed_at):
    head = {
        "schema_version": 1,
        "tree_head_scope": "signed-factory-release-state-transparency-tree-head-v1",
        "log_id": old_head["log_id"],
        "tree_size": len(leaves),
        "root_sha256": root(leaves).hex(),
        "observed_at_unix": observed_at,
        "algorithm": "ed25519",
        "public_key": old_head["public_key"],
        "signature": "",
    }
    payload = {
        "domain": "pcbex-factory-release-state-transparency-tree-head-v1",
        "tree_head_scope": head["tree_head_scope"],
        "log_id": head["log_id"],
        "tree_size": head["tree_size"],
        "root_sha256": head["root_sha256"],
        "observed_at_unix": head["observed_at_unix"],
    }
    with tempfile.NamedTemporaryFile() as source:
        source.write(json.dumps(payload, separators=(",", ":")).encode("ascii"))
        source.flush()
        signature = subprocess.run(
            [
                "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", private_key,
                "-in", source.name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
    head["signature"] = signature.hex()
    return head

def receipt(head, leaves):
    value = copy.deepcopy(old_receipt)
    value["audit_path"] = [item.hex() for item in audit_path(leaves, 0)]
    value["tree_head"] = head
    return value

old_leaf = bytes.fromhex(old_head["root_sha256"])
leaves_three = [old_leaf, hashlib.sha256(b"v1.486-e2e-leaf-1").digest(), hashlib.sha256(b"v1.486-e2e-leaf-2").digest()]
leaves_four = leaves_three + [hashlib.sha256(b"v1.486-e2e-leaf-3").digest()]
head_three = sign_head(leaves_three, old_head["observed_at_unix"] + 10)
head_four = sign_head(leaves_four, old_head["observed_at_unix"] + 20)
receipt_three = receipt(head_three, leaves_three)
receipt_four = receipt(head_four, leaves_four)
proof_one = {
    "schema_version": 1,
    "proof_scope": "factory-release-state-transparency-consistency-proof-v1",
    "previous_tree_head_sha256": compact_sha(old_head),
    "current_tree_head_sha256": compact_sha(head_three),
    "consistency_path": [item.hex() for item in subproof(1, leaves_three, True)],
}
proof_two = {
    "schema_version": 1,
    "proof_scope": "factory-release-state-transparency-consistency-proof-v1",
    "previous_tree_head_sha256": compact_sha(head_three),
    "current_tree_head_sha256": compact_sha(head_four),
    "consistency_path": [item.hex() for item in subproof(3, leaves_four, True)],
}
tampered = copy.deepcopy(proof_one)
tampered["consistency_path"][0] = "0" * 64
for path, value in (
    (receipt_three_path, receipt_three),
    (receipt_four_path, receipt_four),
    (proof_one_path, proof_one),
    (proof_two_path, proof_two),
    (tampered_path, tampered),
):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
Path(times_path).write_text(
    f"{head_three['observed_at_unix'] + 1} {head_four['observed_at_unix'] + 1}\n",
    encoding="ascii",
)
PY
read -r factory_transparency_consistency_time_one factory_transparency_consistency_time_two \
  < "$factory_transparency_consistency_times"

if "$pcbex_binary" verify-factory-release-state-transparency-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --receipt "$factory_transparency_receipt_three" \
  --consistency-proof "$factory_transparency_consistency_tampered_proof" \
  --anchor-state-sequence 1 \
  --evaluated-at-unix "$factory_transparency_consistency_time_one" \
  --output "$factory_transparency_consistency_tampered_output" \
  2>"$factory_transparency_consistency_tampered_error"; then
  echo "expected a tampered factory transparency consistency proof to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_consistency_tampered_output"
grep -Fq 'does not reconstruct both signed roots' \
  "$factory_transparency_consistency_tampered_error"

"$pcbex_binary" verify-factory-release-state-transparency-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --receipt "$factory_transparency_receipt_three" \
  --consistency-proof "$factory_transparency_consistency_proof_one" \
  --anchor-state-sequence 1 \
  --evaluated-at-unix "$factory_transparency_consistency_time_one" \
  --output "$factory_transparency_consistency_report_one" \
  --require-accepted
"$pcbex_binary" verify-factory-release-state-transparency-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --receipt "$factory_transparency_receipt_three" \
  --consistency-proof "$factory_transparency_consistency_proof_one" \
  --anchor-state-sequence 1 \
  --evaluated-at-unix "$((factory_transparency_consistency_time_one + 10000))" \
  --output "$factory_transparency_consistency_replay" \
  --require-accepted
cmp "$factory_transparency_consistency_report_one" \
  "$factory_transparency_consistency_replay"

"$pcbex_binary" verify-factory-release-state-transparency-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --receipt "$factory_transparency_receipt_four" \
  --consistency-proof "$factory_transparency_consistency_proof_two" \
  --evaluated-at-unix "$factory_transparency_consistency_time_two" \
  --output "$factory_transparency_consistency_report_two" \
  --require-accepted

python3 - \
  "$factory_transparency_consistency_report_one" \
  "$factory_transparency_consistency_report_two" \
  "$factory_transparency_consistency_proof_one" \
  "$factory_transparency_consistency_proof_two" \
  "$factory_transparency_consistency_proof_schema" \
  "$factory_transparency_consistency_report_schema" \
  "$factory_transparency_report" "$monotonic_release_ledger" \
  "$monotonic_key" "$signed_release_adapter_token" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

report_one_path, report_two_path, proof_one_path, proof_two_path, \
    proof_schema_path, report_schema_path, anchor_path, ledger_path = \
    map(Path, sys.argv[1:9])
key, token = sys.argv[9:]
report_one = json.loads(report_one_path.read_bytes())
report_two = json.loads(report_two_path.read_bytes())
proof_one = json.loads(proof_one_path.read_bytes())
proof_two = json.loads(proof_two_path.read_bytes())
for report in (report_one, report_two):
    assert report["status"] == "verified"
    for claim in (
        "monotonic_state_chain_verified",
        "previous_checkpoint_inclusion_verified",
        "current_checkpoint_inclusion_verified",
        "same_log_and_key_verified",
        "tree_head_signatures_verified",
        "strict_tree_extension_verified",
        "consistency_proof_verified",
        "complete_consistency_chain_verified",
        "selected_log_append_only_consistency_verified",
    ):
        assert report[claim] is True, claim
    for claim in (
        "selected_ledger_consistency_report_committed",
        "global_non_equivocation_verified",
        "selected_ledger_rollback_resistance_verified",
        "trusted_time_verified",
        "endpoint_transport_authenticity_verified",
        "factory_legal_identity_verified",
        "server_side_idempotency_enforced",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "exactly_once_execution_verified",
    ):
        assert report[claim] is False, claim
assert report_one["checkpoint_generation"] == 1
assert report_one["previous_tree_size"] == 1
assert report_one["current_tree_size"] == 3
assert report_one["anchor_transparency_report_artifact"] == {
    "bytes": len(anchor_path.read_bytes()),
    "sha256": hashlib.sha256(anchor_path.read_bytes()).hexdigest(),
}
assert report_one["previous_consistency_report_artifact"] is None
assert report_one["consistency_proof"] == proof_one
assert report_two["checkpoint_generation"] == 2
assert report_two["previous_tree_size"] == 3
assert report_two["current_tree_size"] == 4
assert report_two["anchor_transparency_report_artifact"] is None
assert report_two["previous_consistency_report_artifact"] == {
    "bytes": len(report_one_path.read_bytes()),
    "sha256": hashlib.sha256(report_one_path.read_bytes()).hexdigest(),
}
assert report_two["previous_transparency_report"] == \
    report_one["current_transparency_report"]
assert report_two["consistency_proof"] == proof_two
for generation, path in ((1, report_one_path), (2, report_two_path)):
    name = (
        f"factory-release-state-transparency-consistency-v1-{key}-"
        f"kicad-e2e-factory-release-log-{generation:04}.json"
    )
    assert (ledger_path / name).read_bytes() == path.read_bytes()
for path in [report_one_path, report_two_path, *ledger_path.iterdir()]:
    assert token.encode() not in path.read_bytes(), path
for schema_path in (proof_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.487 requires independently keyed receipts from distinct configured
# organizations over the exact latest v1.486 report and signed tree head.
factory_transparency_witness_policy_schema="$output_directory/factory-release-transparency-witness-policy.schema.json"
factory_transparency_witness_receipt_schema="$output_directory/factory-release-transparency-witness-receipt.schema.json"
factory_transparency_witness_report_schema="$output_directory/factory-release-transparency-witness-report.schema.json"
factory_transparency_witness_policy="$output_directory/factory-release-transparency-witness.policy.json"
factory_transparency_witness_policy_digest_file="$output_directory/factory-release-transparency-witness.policy.sha256"
factory_transparency_witness_receipt_a="$output_directory/factory-release-transparency-witness-a.receipt.json"
factory_transparency_witness_receipt_b="$output_directory/factory-release-transparency-witness-b.receipt.json"
factory_transparency_witness_receipt_b_alternate="$output_directory/factory-release-transparency-witness-b-alternate.receipt.json"
factory_transparency_witness_unauthenticated_split_receipt="$output_directory/factory-release-transparency-witness-unauthenticated-split.receipt.json"
factory_transparency_witness_split_receipt="$output_directory/factory-release-transparency-witness-split.receipt.json"
factory_transparency_witness_report="$output_directory/factory-release-transparency-witness.report.json"
factory_transparency_witness_replay="$output_directory/factory-release-transparency-witness.replay.json"
factory_transparency_witness_insufficient_output="$output_directory/factory-release-transparency-witness-insufficient.report.json"
factory_transparency_witness_insufficient_error="$output_directory/factory-release-transparency-witness-insufficient.stderr"
factory_transparency_witness_unauthenticated_split_output="$output_directory/factory-release-transparency-witness-unauthenticated-split.report.json"
factory_transparency_witness_unauthenticated_split_error="$output_directory/factory-release-transparency-witness-unauthenticated-split.stderr"
factory_transparency_witness_split_output="$output_directory/factory-release-transparency-witness-split.report.json"
factory_transparency_witness_split_error="$output_directory/factory-release-transparency-witness-split.stderr"
factory_transparency_witness_conflict_output="$output_directory/factory-release-transparency-witness-conflict.report.json"
factory_transparency_witness_conflict_error="$output_directory/factory-release-transparency-witness-conflict.stderr"
factory_witness_secret_directory="$(mktemp -d)"
factory_transparency_witness_private_a="$factory_witness_secret_directory/witness-a.private.hex"
factory_transparency_witness_private_b="$factory_witness_secret_directory/witness-b.private.hex"
factory_transparency_external_anchor_private="$factory_witness_secret_directory/external-anchor.private.hex"
factory_transparency_external_gossip_private="$factory_witness_secret_directory/external-gossip.private.hex"
trap 'kill "$signed_release_adapter_server_pid" 2>/dev/null || true; rm -f -- "$factory_response_private_key" "$factory_response_public_der" "$factory_transparency_private_key" "$factory_transparency_public_der" "$factory_transparency_witness_private_a" "$factory_transparency_witness_private_b" "$factory_transparency_external_anchor_private" "$factory_transparency_external_gossip_private"; rmdir -- "$factory_response_secret_directory" "$factory_witness_secret_directory" 2>/dev/null || true' EXIT

"$pcbex_binary" factory-release-state-transparency-witness-policy-schema \
  --output "$factory_transparency_witness_policy_schema"
"$pcbex_binary" factory-release-state-transparency-witness-receipt-schema \
  --output "$factory_transparency_witness_receipt_schema"
"$pcbex_binary" factory-release-state-transparency-witness-quorum-verification-report-schema \
  --output "$factory_transparency_witness_report_schema"

python3 - \
  "$factory_transparency_witness_policy" \
  "$factory_transparency_witness_policy_digest_file" \
  "$factory_transparency_witness_private_a" \
  "$factory_transparency_witness_private_b" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

policy_path, digest_path, private_a_path, private_b_path = map(Path, sys.argv[1:])
seed_a = bytes([31]) * 32
seed_b = bytes([47]) * 32

def public_key(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

policy = {
    "schema_version": 1,
    "policy_scope": "factory-release-state-transparency-witness-policy-v1",
    "policy_id": "kicad-e2e-release-witnesses",
    "minimum_organizations": 2,
    "maximum_receipt_age_seconds": 300,
    "trusted_witnesses": [
        {
            "organization_id": "independent-org-a",
            "witness_id": "release-witness-a",
            "algorithm": "ed25519",
            "public_key": public_key(seed_a),
        },
        {
            "organization_id": "independent-org-b",
            "witness_id": "release-witness-b",
            "algorithm": "ed25519",
            "public_key": public_key(seed_b),
        },
    ],
}
policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
semantic = json.dumps(policy, separators=(",", ":")).encode("ascii")
digest_path.write_text(hashlib.sha256(semantic).hexdigest() + "\n", encoding="ascii")
private_a_path.write_text(seed_a.hex() + "\n", encoding="ascii")
private_b_path.write_text(seed_b.hex() + "\n", encoding="ascii")
PY
factory_transparency_witness_policy_digest="$(tr -d '\r\n' < "$factory_transparency_witness_policy_digest_file")"
factory_transparency_witness_time="$((factory_transparency_consistency_time_two + 1))"
factory_transparency_witness_expiry="$((factory_transparency_witness_time + 300))"

"$pcbex_binary" sign-factory-release-state-transparency-witness-receipt \
  --consistency-report "$factory_transparency_consistency_report_two" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --organization-id independent-org-a \
  --witness-id release-witness-a \
  --private-key "$factory_transparency_witness_private_a" \
  --witnessed-at-unix "$factory_transparency_witness_time" \
  --expires-at-unix "$factory_transparency_witness_expiry" \
  --output "$factory_transparency_witness_receipt_a"
"$pcbex_binary" sign-factory-release-state-transparency-witness-receipt \
  --consistency-report "$factory_transparency_consistency_report_two" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --organization-id independent-org-b \
  --witness-id release-witness-b \
  --private-key "$factory_transparency_witness_private_b" \
  --witnessed-at-unix "$factory_transparency_witness_time" \
  --expires-at-unix "$factory_transparency_witness_expiry" \
  --output "$factory_transparency_witness_receipt_b"
"$pcbex_binary" sign-factory-release-state-transparency-witness-receipt \
  --consistency-report "$factory_transparency_consistency_report_two" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --organization-id independent-org-b \
  --witness-id release-witness-b \
  --private-key "$factory_transparency_witness_private_b" \
  --witnessed-at-unix "$((factory_transparency_witness_time + 1))" \
  --expires-at-unix "$((factory_transparency_witness_expiry + 1))" \
  --output "$factory_transparency_witness_receipt_b_alternate"

python3 - \
  "$factory_transparency_witness_receipt_a" \
  "$factory_transparency_witness_unauthenticated_split_receipt" \
  "$factory_transparency_witness_split_receipt" \
  "$factory_transparency_witness_private_a" \
  "$factory_transparency_private_key" <<'PY'
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

receipt_path, unauthenticated_path, split_path, private_path, log_private_path = \
    map(Path, sys.argv[1:])
receipt = json.loads(receipt_path.read_bytes())
receipt["tree_head"]["root_sha256"] = "1" * 64
seed = bytes.fromhex(private_path.read_text(encoding="ascii").strip())

def sign_witness(value):
    value["tree_head_sha256"] = hashlib.sha256(
        json.dumps(value["tree_head"], separators=(",", ":")).encode("ascii")
    ).hexdigest()
    payload = {
        "domain": "pcbex-factory-release-state-transparency-witness-receipt-v1",
        "schema_version": value["schema_version"],
        "receipt_scope": value["receipt_scope"],
        "witness_policy_sha256": value["witness_policy_sha256"],
        "organization_id": value["organization_id"],
        "witness_id": value["witness_id"],
        "idempotency_key": value["idempotency_key"],
        "checkpoint_generation": value["checkpoint_generation"],
        "consistency_report_sha256": value["consistency_report_sha256"],
        "tree_head_sha256": value["tree_head_sha256"],
        "tree_head": value["tree_head"],
        "witnessed_at_unix": value["witnessed_at_unix"],
        "expires_at_unix": value["expires_at_unix"],
        "algorithm": value["algorithm"],
        "witness_public_key": value["witness_public_key"],
    }
    value["signature"] = Ed25519PrivateKey.from_private_bytes(seed).sign(
        json.dumps(payload, separators=(",", ":")).encode("ascii")
    ).hex()

unauthenticated = copy.deepcopy(receipt)
sign_witness(unauthenticated)
unauthenticated_path.write_text(
    json.dumps(unauthenticated, indent=2) + "\n", encoding="utf-8"
)

head = receipt["tree_head"]
head_payload = {
    "domain": "pcbex-factory-release-state-transparency-tree-head-v1",
    "tree_head_scope": head["tree_head_scope"],
    "log_id": head["log_id"],
    "tree_size": head["tree_size"],
    "root_sha256": head["root_sha256"],
    "observed_at_unix": head["observed_at_unix"],
}
with tempfile.NamedTemporaryFile() as source:
    source.write(json.dumps(head_payload, separators=(",", ":")).encode("ascii"))
    source.flush()
    head["signature"] = subprocess.run(
        [
            "openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
            log_private_path, "-in", source.name,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.hex()
sign_witness(receipt)
split_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
PY

if "$pcbex_binary" verify-factory-release-state-transparency-witness-quorum \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --witness-receipt "$factory_transparency_witness_receipt_a" \
  --evaluated-at-unix "$factory_transparency_witness_time" \
  --output "$factory_transparency_witness_insufficient_output" \
  2>"$factory_transparency_witness_insufficient_error"; then
  echo "expected an insufficient factory transparency witness quorum to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_witness_insufficient_output"
grep -Fq 'requires 2 to 100 receipts' \
  "$factory_transparency_witness_insufficient_error"

if "$pcbex_binary" verify-factory-release-state-transparency-witness-quorum \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --witness-receipt "$factory_transparency_witness_unauthenticated_split_receipt" \
  --witness-receipt "$factory_transparency_witness_receipt_b" \
  --evaluated-at-unix "$factory_transparency_witness_time" \
  --output "$factory_transparency_witness_unauthenticated_split_output" \
  2>"$factory_transparency_witness_unauthenticated_split_error"; then
  echo "expected an unauthenticated factory transparency split view to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_witness_unauthenticated_split_output"
grep -Fq 'invalid factory release transparency tree-head signature' \
  "$factory_transparency_witness_unauthenticated_split_error"

if "$pcbex_binary" verify-factory-release-state-transparency-witness-quorum \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --witness-receipt "$factory_transparency_witness_split_receipt" \
  --witness-receipt "$factory_transparency_witness_receipt_b" \
  --evaluated-at-unix "$factory_transparency_witness_time" \
  --output "$factory_transparency_witness_split_output" \
  2>"$factory_transparency_witness_split_error"; then
  echo "expected a split factory transparency witness view to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_witness_split_output"
grep -Fq 'detected a split-view root at the selected tree size' \
  "$factory_transparency_witness_split_error"

"$pcbex_binary" verify-factory-release-state-transparency-witness-quorum \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --witness-receipt "$factory_transparency_witness_receipt_b" \
  --witness-receipt "$factory_transparency_witness_receipt_a" \
  --evaluated-at-unix "$factory_transparency_witness_time" \
  --output "$factory_transparency_witness_report" \
  --require-accepted
"$pcbex_binary" verify-factory-release-state-transparency-witness-quorum \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --witness-receipt "$factory_transparency_witness_receipt_a" \
  --witness-receipt "$factory_transparency_witness_receipt_b" \
  --evaluated-at-unix "$((factory_transparency_witness_expiry + 10000))" \
  --output "$factory_transparency_witness_replay" \
  --require-accepted
cmp "$factory_transparency_witness_report" \
  "$factory_transparency_witness_replay"

if "$pcbex_binary" verify-factory-release-state-transparency-witness-quorum \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --witness-receipt "$factory_transparency_witness_receipt_a" \
  --witness-receipt "$factory_transparency_witness_receipt_b_alternate" \
  --evaluated-at-unix "$((factory_transparency_witness_time + 1))" \
  --output "$factory_transparency_witness_conflict_output" \
  2>"$factory_transparency_witness_conflict_error"; then
  echo "expected conflicting factory transparency witness evidence to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_witness_conflict_output"
grep -Fq 'witness quorum record conflicts' \
  "$factory_transparency_witness_conflict_error"

python3 - \
  "$factory_transparency_witness_report" \
  "$factory_transparency_consistency_report_two" \
  "$factory_transparency_witness_policy" \
  "$factory_transparency_witness_receipt_a" \
  "$factory_transparency_witness_receipt_b" \
  "$factory_transparency_witness_policy_schema" \
  "$factory_transparency_witness_receipt_schema" \
  "$factory_transparency_witness_report_schema" \
  "$monotonic_release_ledger" "$monotonic_key" \
  "$factory_transparency_witness_policy_digest" \
  "$factory_transparency_witness_private_a" \
  "$factory_transparency_witness_private_b" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

report_path, consistency_path, policy_path, receipt_a_path, receipt_b_path, \
    policy_schema_path, receipt_schema_path, report_schema_path, ledger_path = \
    map(Path, sys.argv[1:10])
key, policy_digest, private_a_path, private_b_path = sys.argv[10:]
report = json.loads(report_path.read_bytes())
assert report["status"] == "verified"
for claim in (
    "monotonic_state_chain_verified",
    "current_checkpoint_inclusion_verified",
    "complete_consistency_chain_verified",
    "selected_log_append_only_consistency_verified",
    "consistency_report_identity_verified",
    "witness_policy_pin_matched",
    "witness_log_key_role_separation_verified",
    "witness_receipt_signatures_verified",
    "distinct_organization_quorum_verified",
    "selected_witness_checkpoint_agreement_verified",
):
    assert report[claim] is True, claim
for claim in (
    "selected_witness_split_view_detected",
    "selected_ledger_witness_quorum_report_committed",
    "global_non_equivocation_verified",
    "selected_ledger_rollback_resistance_verified",
    "trusted_time_verified",
    "independent_organization_operation_verified",
    "endpoint_transport_authenticity_verified",
    "factory_legal_identity_verified",
    "server_side_idempotency_enforced",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim
assert report["checkpoint_generation"] == 2
assert report["minimum_organizations"] == 2
assert report["valid_receipts"] == 2
assert report["distinct_organizations"] == 2
assert [member["organization_id"] for member in report["members"]] == [
    "independent-org-a", "independent-org-b"
]
assert report["consistency_report"] == json.loads(consistency_path.read_bytes())
assert report["consistency_report_artifact"] == {
    "bytes": len(consistency_path.read_bytes()),
    "sha256": hashlib.sha256(consistency_path.read_bytes()).hexdigest(),
}
assert report["witness_policy"] == json.loads(policy_path.read_bytes())
assert report["witness_policy_sha256"] == policy_digest
expected_receipts = {
    hashlib.sha256(receipt_a_path.read_bytes()).hexdigest(),
    hashlib.sha256(receipt_b_path.read_bytes()).hexdigest(),
}
assert {member["receipt_artifact"]["sha256"] for member in report["members"]} == \
    expected_receipts
name = (
    f"factory-release-state-transparency-witness-quorum-v1-{key}-"
    f"kicad-e2e-factory-release-log-0002-{policy_digest}.json"
)
assert (ledger_path / name).read_bytes() == report_path.read_bytes()
secret_a = Path(private_a_path).read_text(encoding="ascii").strip().encode()
secret_b = Path(private_b_path).read_text(encoding="ascii").strip().encode()
for path in [report_path, *ledger_path.iterdir()]:
    source = path.read_bytes()
    assert secret_a not in source, path
    assert secret_b not in source, path
for schema_path in (policy_schema_path, receipt_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.488 anchors the exact latest v1.487 report into a separately policy-pinned
# signed Merkle view without claiming consistency for that external log.
factory_transparency_external_anchor_policy_schema="$output_directory/factory-release-transparency-external-anchor-policy.schema.json"
factory_transparency_external_anchor_proof_schema="$output_directory/factory-release-transparency-external-anchor-proof.schema.json"
factory_transparency_external_anchor_report_schema="$output_directory/factory-release-transparency-external-anchor-report.schema.json"
factory_transparency_external_anchor_policy="$output_directory/factory-release-transparency-external-anchor.policy.json"
factory_transparency_external_anchor_policy_digest_file="$output_directory/factory-release-transparency-external-anchor.policy.sha256"
factory_transparency_external_anchor_proof="$output_directory/factory-release-transparency-external-anchor.proof.json"
factory_transparency_external_anchor_unauthenticated_proof="$output_directory/factory-release-transparency-external-anchor-unauthenticated.proof.json"
factory_transparency_external_anchor_bad_path_proof="$output_directory/factory-release-transparency-external-anchor-bad-path.proof.json"
factory_transparency_external_anchor_alternate_proof="$output_directory/factory-release-transparency-external-anchor-alternate.proof.json"
factory_transparency_external_anchor_colliding_policy="$output_directory/factory-release-transparency-external-anchor-colliding.policy.json"
factory_transparency_external_anchor_colliding_policy_digest_file="$output_directory/factory-release-transparency-external-anchor-colliding.policy.sha256"
factory_transparency_external_anchor_colliding_proof="$output_directory/factory-release-transparency-external-anchor-colliding.proof.json"
factory_transparency_external_anchor_report="$output_directory/factory-release-transparency-external-anchor.report.json"
factory_transparency_external_anchor_replay="$output_directory/factory-release-transparency-external-anchor.replay.json"
factory_transparency_external_anchor_unauthenticated_output="$output_directory/factory-release-transparency-external-anchor-unauthenticated.report.json"
factory_transparency_external_anchor_unauthenticated_error="$output_directory/factory-release-transparency-external-anchor-unauthenticated.stderr"
factory_transparency_external_anchor_bad_path_output="$output_directory/factory-release-transparency-external-anchor-bad-path.report.json"
factory_transparency_external_anchor_bad_path_error="$output_directory/factory-release-transparency-external-anchor-bad-path.stderr"
factory_transparency_external_anchor_colliding_output="$output_directory/factory-release-transparency-external-anchor-colliding.report.json"
factory_transparency_external_anchor_colliding_error="$output_directory/factory-release-transparency-external-anchor-colliding.stderr"
factory_transparency_external_anchor_conflict_output="$output_directory/factory-release-transparency-external-anchor-conflict.report.json"
factory_transparency_external_anchor_conflict_error="$output_directory/factory-release-transparency-external-anchor-conflict.stderr"

"$pcbex_binary" factory-release-state-transparency-external-anchor-policy-schema \
  --output "$factory_transparency_external_anchor_policy_schema"
"$pcbex_binary" factory-release-state-transparency-external-anchor-proof-schema \
  --output "$factory_transparency_external_anchor_proof_schema"
"$pcbex_binary" factory-release-state-transparency-external-anchor-verification-report-schema \
  --output "$factory_transparency_external_anchor_report_schema"

python3 - \
  "$factory_transparency_witness_report" \
  "$factory_transparency_external_anchor_policy" \
  "$factory_transparency_external_anchor_policy_digest_file" \
  "$factory_transparency_external_anchor_proof" \
  "$factory_transparency_external_anchor_unauthenticated_proof" \
  "$factory_transparency_external_anchor_bad_path_proof" \
  "$factory_transparency_external_anchor_alternate_proof" \
  "$factory_transparency_external_anchor_private" <<'PY'
import copy
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

report_path, policy_path, digest_path, proof_path, unauthenticated_path, \
    bad_path_path, alternate_path, private_path = map(Path, sys.argv[1:])
report_source = report_path.read_bytes()
report = json.loads(report_source)
seed = bytes([59]) * 32
private_key = Ed25519PrivateKey.from_private_bytes(seed)
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()
external_log_id = "kicad-e2e-external-anchor-log"

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

policy = {
    "schema_version": 1,
    "policy_scope": "factory-release-state-transparency-external-anchor-policy-v1",
    "policy_id": "kicad-e2e-external-anchor-policy",
    "maximum_checkpoint_age_seconds": 300,
    "trusted_logs": [
        {
            "log_id": external_log_id,
            "algorithm": "ed25519",
            "public_key": public_key,
        }
    ],
}
policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
policy_digest = hashlib.sha256(compact(policy)).hexdigest()
digest_path.write_text(policy_digest + "\n", encoding="ascii")
private_path.write_text(seed.hex() + "\n", encoding="ascii")

report_digest = hashlib.sha256(report_source).hexdigest()
leaf_binding = {
    "schema_version": 1,
    "witness_quorum_report_sha256": report_digest,
    "witness_quorum_binding_sha256": report["binding_sha256"],
    "idempotency_key": report["idempotency_key"],
    "source_log_id": report["log_id"],
    "checkpoint_generation": report["checkpoint_generation"],
    "current_state_sequence": report["current_state_sequence"],
    "current_tree_head_sha256": report["current_tree_head_sha256"],
    "witness_policy_sha256": report["witness_policy_sha256"],
    "external_anchor_policy_sha256": policy_digest,
    "external_log_id": external_log_id,
}
leaf_digest = hashlib.sha256(
    b"pcbex:factory-release-state-transparency-external-anchor-leaf:v1\0" +
    compact(leaf_binding)
).hexdigest()

def merkle_leaf(digest):
    return hashlib.sha256(
        b"\x00" +
        b"pcbex:factory-release-state-transparency-external-anchor-merkle-leaf:v1\0" +
        bytes.fromhex(digest)
    ).digest()

def merkle_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()

def sign_head(head):
    payload = {
        "domain": "pcbex-factory-release-state-transparency-external-anchor-tree-head-v1",
        "schema_version": head["schema_version"],
        "tree_head_scope": head["tree_head_scope"],
        "log_id": head["log_id"],
        "tree_size": head["tree_size"],
        "root_sha256": head["root_sha256"],
        "observed_at_unix": head["observed_at_unix"],
        "algorithm": head["algorithm"],
        "public_key": head["public_key"],
    }
    head["signature"] = private_key.sign(compact(payload)).hex()

leaf_nodes = [
    merkle_leaf("11" * 32),
    merkle_leaf(leaf_digest),
    merkle_leaf("22" * 32),
]
observed_at = report["evaluated_at_unix"] + 1
head = {
    "schema_version": 1,
    "tree_head_scope": "signed-factory-release-state-transparency-external-anchor-tree-head-v1",
    "log_id": external_log_id,
    "tree_size": 3,
    "root_sha256": merkle_node(
        merkle_node(leaf_nodes[0], leaf_nodes[1]), leaf_nodes[2]
    ).hex(),
    "observed_at_unix": observed_at,
    "algorithm": "ed25519",
    "public_key": public_key,
    "signature": "",
}
sign_head(head)
proof = {
    "schema_version": 1,
    "proof_scope": "factory-release-state-transparency-witness-quorum-external-anchor-proof-v1",
    "external_anchor_policy_sha256": policy_digest,
    "witness_quorum_report_sha256": report_digest,
    "leaf_sha256": leaf_digest,
    "leaf_index": 1,
    "audit_path": [leaf_nodes[0].hex(), leaf_nodes[2].hex()],
    "tree_head": head,
}
proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")

unauthenticated = copy.deepcopy(proof)
unauthenticated["tree_head"]["root_sha256"] = "33" * 32
unauthenticated_path.write_text(
    json.dumps(unauthenticated, indent=2) + "\n", encoding="utf-8"
)

bad_path = copy.deepcopy(proof)
bad_path["audit_path"][0] = "44" * 32
bad_path_path.write_text(json.dumps(bad_path, indent=2) + "\n", encoding="utf-8")

alternate_nodes = [
    leaf_nodes[0], leaf_nodes[1], leaf_nodes[2], merkle_leaf("55" * 32)
]
alternate = copy.deepcopy(proof)
alternate["tree_head"]["tree_size"] = 4
alternate["tree_head"]["root_sha256"] = merkle_node(
    merkle_node(alternate_nodes[0], alternate_nodes[1]),
    merkle_node(alternate_nodes[2], alternate_nodes[3]),
).hex()
alternate["tree_head"]["observed_at_unix"] = observed_at + 1
sign_head(alternate["tree_head"])
alternate["audit_path"] = [
    alternate_nodes[0].hex(),
    merkle_node(alternate_nodes[2], alternate_nodes[3]).hex(),
]
alternate_path.write_text(json.dumps(alternate, indent=2) + "\n", encoding="utf-8")
PY

python3 - \
  "$factory_transparency_witness_report" \
  "$factory_transparency_external_anchor_colliding_policy" \
  "$factory_transparency_external_anchor_colliding_policy_digest_file" \
  "$factory_transparency_external_anchor_colliding_proof" \
  "$factory_transparency_witness_private_a" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

report_path, policy_path, digest_path, proof_path, private_path = \
    map(Path, sys.argv[1:])
report_source = report_path.read_bytes()
report = json.loads(report_source)
seed = bytes.fromhex(private_path.read_text(encoding="ascii").strip())
private_key = Ed25519PrivateKey.from_private_bytes(seed)
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()
external_log_id = "kicad-e2e-colliding-anchor-log"

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

policy = {
    "schema_version": 1,
    "policy_scope": "factory-release-state-transparency-external-anchor-policy-v1",
    "policy_id": "kicad-e2e-colliding-anchor-policy",
    "maximum_checkpoint_age_seconds": 300,
    "trusted_logs": [
        {
            "log_id": external_log_id,
            "algorithm": "ed25519",
            "public_key": public_key,
        }
    ],
}
policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
policy_digest = hashlib.sha256(compact(policy)).hexdigest()
digest_path.write_text(policy_digest + "\n", encoding="ascii")
report_digest = hashlib.sha256(report_source).hexdigest()
leaf_binding = {
    "schema_version": 1,
    "witness_quorum_report_sha256": report_digest,
    "witness_quorum_binding_sha256": report["binding_sha256"],
    "idempotency_key": report["idempotency_key"],
    "source_log_id": report["log_id"],
    "checkpoint_generation": report["checkpoint_generation"],
    "current_state_sequence": report["current_state_sequence"],
    "current_tree_head_sha256": report["current_tree_head_sha256"],
    "witness_policy_sha256": report["witness_policy_sha256"],
    "external_anchor_policy_sha256": policy_digest,
    "external_log_id": external_log_id,
}
leaf_digest = hashlib.sha256(
    b"pcbex:factory-release-state-transparency-external-anchor-leaf:v1\0" +
    compact(leaf_binding)
).hexdigest()
root = hashlib.sha256(
    b"\x00" +
    b"pcbex:factory-release-state-transparency-external-anchor-merkle-leaf:v1\0" +
    bytes.fromhex(leaf_digest)
).hexdigest()
head = {
    "schema_version": 1,
    "tree_head_scope": "signed-factory-release-state-transparency-external-anchor-tree-head-v1",
    "log_id": external_log_id,
    "tree_size": 1,
    "root_sha256": root,
    "observed_at_unix": report["evaluated_at_unix"] + 1,
    "algorithm": "ed25519",
    "public_key": public_key,
    "signature": "",
}
head_payload = {
    "domain": "pcbex-factory-release-state-transparency-external-anchor-tree-head-v1",
    "schema_version": head["schema_version"],
    "tree_head_scope": head["tree_head_scope"],
    "log_id": head["log_id"],
    "tree_size": head["tree_size"],
    "root_sha256": head["root_sha256"],
    "observed_at_unix": head["observed_at_unix"],
    "algorithm": head["algorithm"],
    "public_key": head["public_key"],
}
head["signature"] = private_key.sign(compact(head_payload)).hex()
proof = {
    "schema_version": 1,
    "proof_scope": "factory-release-state-transparency-witness-quorum-external-anchor-proof-v1",
    "external_anchor_policy_sha256": policy_digest,
    "witness_quorum_report_sha256": report_digest,
    "leaf_sha256": leaf_digest,
    "leaf_index": 0,
    "audit_path": [],
    "tree_head": head,
}
proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
PY
factory_transparency_external_anchor_policy_digest="$(tr -d '\r\n' < "$factory_transparency_external_anchor_policy_digest_file")"
factory_transparency_external_anchor_colliding_policy_digest="$(tr -d '\r\n' < "$factory_transparency_external_anchor_colliding_policy_digest_file")"
factory_transparency_external_anchor_time="$((factory_transparency_witness_time + 1))"

if "$pcbex_binary" verify-factory-release-state-transparency-external-anchor \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --anchor-proof "$factory_transparency_external_anchor_unauthenticated_proof" \
  --evaluated-at-unix "$factory_transparency_external_anchor_time" \
  --output "$factory_transparency_external_anchor_unauthenticated_output" \
  2>"$factory_transparency_external_anchor_unauthenticated_error"; then
  echo "expected an unauthenticated external anchor tree head to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_anchor_unauthenticated_output"
grep -Fq 'invalid factory release transparency external tree-head signature' \
  "$factory_transparency_external_anchor_unauthenticated_error"

if "$pcbex_binary" verify-factory-release-state-transparency-external-anchor \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --anchor-proof "$factory_transparency_external_anchor_bad_path_proof" \
  --evaluated-at-unix "$factory_transparency_external_anchor_time" \
  --output "$factory_transparency_external_anchor_bad_path_output" \
  2>"$factory_transparency_external_anchor_bad_path_error"; then
  echo "expected an invalid external anchor audit path to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_anchor_bad_path_output"
grep -Fq 'external-anchor audit path does not reconstruct the signed root' \
  "$factory_transparency_external_anchor_bad_path_error"

if "$pcbex_binary" verify-factory-release-state-transparency-external-anchor \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_colliding_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_colliding_policy_digest" \
  --external-log-id kicad-e2e-colliding-anchor-log \
  --anchor-proof "$factory_transparency_external_anchor_colliding_proof" \
  --evaluated-at-unix "$factory_transparency_external_anchor_time" \
  --output "$factory_transparency_external_anchor_colliding_output" \
  2>"$factory_transparency_external_anchor_colliding_error"; then
  echo "expected an external anchor key assigned to a witness role to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_anchor_colliding_output"
grep -Fq 'external log key is assigned to an inner log or witness role' \
  "$factory_transparency_external_anchor_colliding_error"

"$pcbex_binary" verify-factory-release-state-transparency-external-anchor \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --anchor-proof "$factory_transparency_external_anchor_proof" \
  --evaluated-at-unix "$factory_transparency_external_anchor_time" \
  --output "$factory_transparency_external_anchor_report" \
  --require-accepted
"$pcbex_binary" verify-factory-release-state-transparency-external-anchor \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --anchor-proof "$factory_transparency_external_anchor_proof" \
  --evaluated-at-unix "$((factory_transparency_external_anchor_time + 10000))" \
  --output "$factory_transparency_external_anchor_replay" \
  --require-accepted
cmp "$factory_transparency_external_anchor_report" \
  "$factory_transparency_external_anchor_replay"

if "$pcbex_binary" verify-factory-release-state-transparency-external-anchor \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --anchor-proof "$factory_transparency_external_anchor_alternate_proof" \
  --evaluated-at-unix "$((factory_transparency_external_anchor_time + 1))" \
  --output "$factory_transparency_external_anchor_conflict_output" \
  2>"$factory_transparency_external_anchor_conflict_error"; then
  echo "expected conflicting external anchor evidence to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_anchor_conflict_output"
grep -Fq 'external-anchor record conflicts' \
  "$factory_transparency_external_anchor_conflict_error"

python3 - \
  "$factory_transparency_external_anchor_report" \
  "$factory_transparency_witness_report" \
  "$factory_transparency_external_anchor_policy" \
  "$factory_transparency_external_anchor_proof" \
  "$factory_transparency_external_anchor_policy_schema" \
  "$factory_transparency_external_anchor_proof_schema" \
  "$factory_transparency_external_anchor_report_schema" \
  "$monotonic_release_ledger" "$monotonic_key" \
  "$factory_transparency_external_anchor_policy_digest" \
  "$factory_transparency_external_anchor_private" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

report_path, witness_path, policy_path, proof_path, policy_schema_path, \
    proof_schema_path, report_schema_path, ledger_path = map(Path, sys.argv[1:9])
key, policy_digest, private_path = sys.argv[9:]
report = json.loads(report_path.read_bytes())
witness = json.loads(witness_path.read_bytes())
policy = json.loads(policy_path.read_bytes())
proof = json.loads(proof_path.read_bytes())
assert report["status"] == "verified"
for claim in (
    "monotonic_state_chain_verified",
    "current_checkpoint_inclusion_verified",
    "complete_consistency_chain_verified",
    "selected_log_append_only_consistency_verified",
    "witness_quorum_verified",
    "witness_quorum_report_identity_verified",
    "external_anchor_policy_pin_matched",
    "external_anchor_log_policy_matched",
    "external_anchor_log_role_separation_verified",
    "external_tree_head_signature_verified",
    "external_inclusion_proof_verified",
    "external_anchor_verified",
    "external_checkpoint_fresh_at_evaluation",
):
    assert report[claim] is True, claim
for claim in (
    "selected_ledger_external_anchor_report_committed",
    "external_log_append_only_consistency_verified",
    "global_non_equivocation_verified",
    "selected_ledger_rollback_resistance_verified",
    "trusted_time_verified",
    "independent_organization_operation_verified",
    "endpoint_transport_authenticity_verified",
    "factory_legal_identity_verified",
    "server_side_idempotency_enforced",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim
assert report["source_log_id"] == "kicad-e2e-factory-release-log"
assert report["external_log_id"] == "kicad-e2e-external-anchor-log"
assert report["checkpoint_generation"] == 2
assert report["external_tree_size"] == 3
assert report["witness_quorum_report"] == witness
assert report["witness_quorum_report_artifact"] == {
    "bytes": len(witness_path.read_bytes()),
    "sha256": hashlib.sha256(witness_path.read_bytes()).hexdigest(),
}
assert report["external_anchor_policy"] == policy
assert report["external_anchor_policy_sha256"] == policy_digest
assert report["external_anchor_policy_artifact"] == {
    "bytes": len(policy_path.read_bytes()),
    "sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
}
assert report["anchor_proof"] == proof
assert report["anchor_proof_artifact"] == {
    "bytes": len(proof_path.read_bytes()),
    "sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
}
assert report["external_tree_head_sha256"] == hashlib.sha256(
    json.dumps(proof["tree_head"], separators=(",", ":")).encode("ascii")
).hexdigest()

filename_context = {
    "source_log_id": report["source_log_id"],
    "witness_policy_sha256": report["witness_policy_sha256"],
    "external_log_id": report["external_log_id"],
    "external_anchor_policy_sha256": report["external_anchor_policy_sha256"],
}
context_sha256 = hashlib.sha256(
    b"pcbex:factory-release-state-transparency-external-anchor-filename:v1\0" +
    json.dumps(filename_context, separators=(",", ":")).encode("ascii")
).hexdigest()
name = (
    f"factory-release-state-transparency-external-anchor-v1-{key}-"
    f"{report['checkpoint_generation']:04}-{context_sha256}.json"
)
assert (ledger_path / name).read_bytes() == report_path.read_bytes()
secret = Path(private_path).read_text(encoding="ascii").strip().encode()
for path in [report_path, *ledger_path.iterdir()]:
    assert secret not in path.read_bytes(), path
for schema_path in (policy_schema_path, proof_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.489 proves that later signed views strictly extend the retained v1.488
# external anchor. The local chain remains append-only and no-replace; gossip
# and global non-equivocation remain explicit nonclaims.
factory_transparency_external_consistency_proof_schema="$output_directory/factory-release-transparency-external-consistency-proof.schema.json"
factory_transparency_external_consistency_report_schema="$output_directory/factory-release-transparency-external-consistency-report.schema.json"
factory_transparency_external_consistency_proof_1="$output_directory/factory-release-transparency-external-consistency-1.proof.json"
factory_transparency_external_consistency_proof_2="$output_directory/factory-release-transparency-external-consistency-2.proof.json"
factory_transparency_external_consistency_unauthenticated_proof="$output_directory/factory-release-transparency-external-consistency-unauthenticated.proof.json"
factory_transparency_external_consistency_bad_path_proof="$output_directory/factory-release-transparency-external-consistency-bad-path.proof.json"
factory_transparency_external_consistency_alternate_proof="$output_directory/factory-release-transparency-external-consistency-alternate.proof.json"
factory_transparency_external_consistency_report_1="$output_directory/factory-release-transparency-external-consistency-1.report.json"
factory_transparency_external_consistency_report_2="$output_directory/factory-release-transparency-external-consistency-2.report.json"
factory_transparency_external_consistency_replay="$output_directory/factory-release-transparency-external-consistency.replay.json"
factory_transparency_external_consistency_unauthenticated_output="$output_directory/factory-release-transparency-external-consistency-unauthenticated.report.json"
factory_transparency_external_consistency_unauthenticated_error="$output_directory/factory-release-transparency-external-consistency-unauthenticated.stderr"
factory_transparency_external_consistency_bad_path_output="$output_directory/factory-release-transparency-external-consistency-bad-path.report.json"
factory_transparency_external_consistency_bad_path_error="$output_directory/factory-release-transparency-external-consistency-bad-path.stderr"
factory_transparency_external_consistency_conflict_output="$output_directory/factory-release-transparency-external-consistency-conflict.report.json"
factory_transparency_external_consistency_conflict_error="$output_directory/factory-release-transparency-external-consistency-conflict.stderr"

"$pcbex_binary" factory-release-state-transparency-external-consistency-proof-schema \
  --output "$factory_transparency_external_consistency_proof_schema"
"$pcbex_binary" factory-release-state-transparency-external-consistency-verification-report-schema \
  --output "$factory_transparency_external_consistency_report_schema"

python3 - \
  "$factory_transparency_external_anchor_report" \
  "$factory_transparency_external_consistency_proof_1" \
  "$factory_transparency_external_consistency_proof_2" \
  "$factory_transparency_external_consistency_unauthenticated_proof" \
  "$factory_transparency_external_consistency_bad_path_proof" \
  "$factory_transparency_external_consistency_alternate_proof" \
  "$factory_transparency_external_anchor_private" <<'PY'
import copy
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

anchor_path, proof_1_path, proof_2_path, unauthenticated_path, bad_path_path, \
    alternate_path, private_path = map(Path, sys.argv[1:])
anchor = json.loads(anchor_path.read_bytes())
anchor_proof = anchor["anchor_proof"]
anchor_head = anchor_proof["tree_head"]
policy_digest = anchor["external_anchor_policy_sha256"]
external_log_id = anchor["external_log_id"]
seed = bytes.fromhex(private_path.read_text(encoding="ascii").strip())
private_key = Ed25519PrivateKey.from_private_bytes(seed)

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

def merkle_leaf(digest):
    return hashlib.sha256(
        b"\x00" +
        b"pcbex:factory-release-state-transparency-external-anchor-merkle-leaf:v1\0" +
        bytes.fromhex(digest)
    ).digest()

def merkle_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()

def merkle_root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return merkle_node(merkle_root(leaves[:split]), merkle_root(leaves[split:]))

def consistency_subproof(old_size, leaves, complete_subtree):
    if old_size == len(leaves):
        return [] if complete_subtree else [merkle_root(leaves)]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if old_size <= split:
        return consistency_subproof(
            old_size, leaves[:split], complete_subtree
        ) + [merkle_root(leaves[split:])]
    return consistency_subproof(
        old_size - split, leaves[split:], False
    ) + [merkle_root(leaves[:split])]

def sign_head(head):
    payload = {
        "domain": "pcbex-factory-release-state-transparency-external-anchor-tree-head-v1",
        "schema_version": head["schema_version"],
        "tree_head_scope": head["tree_head_scope"],
        "log_id": head["log_id"],
        "tree_size": head["tree_size"],
        "root_sha256": head["root_sha256"],
        "observed_at_unix": head["observed_at_unix"],
        "algorithm": head["algorithm"],
        "public_key": head["public_key"],
    }
    head["signature"] = private_key.sign(compact(payload)).hex()

def head_sha256(head):
    return hashlib.sha256(compact(head)).hexdigest()

def extension(previous_head, leaves, observed_at):
    old_size = previous_head["tree_size"]
    current = {
        "schema_version": 1,
        "tree_head_scope":
            "signed-factory-release-state-transparency-external-anchor-tree-head-v1",
        "log_id": external_log_id,
        "tree_size": len(leaves),
        "root_sha256": merkle_root(leaves).hex(),
        "observed_at_unix": observed_at,
        "algorithm": "ed25519",
        "public_key": previous_head["public_key"],
        "signature": "",
    }
    sign_head(current)
    return {
        "schema_version": 1,
        "proof_scope":
            "factory-release-state-transparency-external-log-consistency-proof-v1",
        "external_anchor_policy_sha256": policy_digest,
        "external_log_id": external_log_id,
        "previous_tree_head_sha256": head_sha256(previous_head),
        "current_tree_head_sha256": head_sha256(current),
        "previous_tree_head": previous_head,
        "current_tree_head": current,
        "consistency_path": [
            node.hex() for node in consistency_subproof(old_size, leaves, True)
        ],
    }

anchor_leaf = merkle_leaf(anchor_proof["leaf_sha256"])
leaves_3 = [
    bytes.fromhex(anchor_proof["audit_path"][0]),
    anchor_leaf,
    bytes.fromhex(anchor_proof["audit_path"][1]),
]
assert merkle_root(leaves_3).hex() == anchor_head["root_sha256"]
leaves_4 = leaves_3 + [merkle_leaf("66" * 32)]
proof_1 = extension(
    anchor_head, leaves_4, anchor_head["observed_at_unix"] + 1
)
proof_1_path.write_text(json.dumps(proof_1, indent=2) + "\n", encoding="utf-8")

unauthenticated = copy.deepcopy(proof_1)
unauthenticated["current_tree_head"]["root_sha256"] = "33" * 32
unauthenticated_path.write_text(
    json.dumps(unauthenticated, indent=2) + "\n", encoding="utf-8"
)

bad_path = copy.deepcopy(proof_1)
bad_path["consistency_path"][0] = "44" * 32
bad_path_path.write_text(json.dumps(bad_path, indent=2) + "\n", encoding="utf-8")

alternate_leaves = leaves_3 + [merkle_leaf("77" * 32)]
alternate = extension(
    anchor_head, alternate_leaves, anchor_head["observed_at_unix"] + 1
)
alternate_path.write_text(json.dumps(alternate, indent=2) + "\n", encoding="utf-8")

leaves_5 = leaves_4 + [merkle_leaf("88" * 32)]
proof_2 = extension(
    proof_1["current_tree_head"],
    leaves_5,
    proof_1["current_tree_head"]["observed_at_unix"] + 1,
)
proof_2_path.write_text(json.dumps(proof_2, indent=2) + "\n", encoding="utf-8")
PY

factory_transparency_external_consistency_time="$((factory_transparency_external_anchor_time + 1))"

if "$pcbex_binary" verify-factory-release-state-transparency-external-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --anchor-checkpoint-generation 2 \
  --consistency-proof "$factory_transparency_external_consistency_unauthenticated_proof" \
  --evaluated-at-unix "$factory_transparency_external_consistency_time" \
  --output "$factory_transparency_external_consistency_unauthenticated_output" \
  2>"$factory_transparency_external_consistency_unauthenticated_error"; then
  echo "expected an unauthenticated external consistency tree head to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_consistency_unauthenticated_output"
grep -Fq 'invalid factory release transparency external tree-head signature' \
  "$factory_transparency_external_consistency_unauthenticated_error"

if "$pcbex_binary" verify-factory-release-state-transparency-external-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --anchor-checkpoint-generation 2 \
  --consistency-proof "$factory_transparency_external_consistency_bad_path_proof" \
  --evaluated-at-unix "$factory_transparency_external_consistency_time" \
  --output "$factory_transparency_external_consistency_bad_path_output" \
  2>"$factory_transparency_external_consistency_bad_path_error"; then
  echo "expected an invalid external consistency path to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_consistency_bad_path_output"
grep -Fq 'external consistency path does not reconstruct both signed roots' \
  "$factory_transparency_external_consistency_bad_path_error"

"$pcbex_binary" verify-factory-release-state-transparency-external-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --anchor-checkpoint-generation 2 \
  --consistency-proof "$factory_transparency_external_consistency_proof_1" \
  --evaluated-at-unix "$factory_transparency_external_consistency_time" \
  --output "$factory_transparency_external_consistency_report_1" \
  --require-accepted

if "$pcbex_binary" verify-factory-release-state-transparency-external-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --consistency-proof "$factory_transparency_external_consistency_alternate_proof" \
  --evaluated-at-unix "$factory_transparency_external_consistency_time" \
  --output "$factory_transparency_external_consistency_conflict_output" \
  2>"$factory_transparency_external_consistency_conflict_error"; then
  echo "expected a competing external consistency transition to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_consistency_conflict_output"
grep -Fq 'does not extend the selected retained head' \
  "$factory_transparency_external_consistency_conflict_error"

"$pcbex_binary" verify-factory-release-state-transparency-external-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --consistency-proof "$factory_transparency_external_consistency_proof_2" \
  --evaluated-at-unix "$((factory_transparency_external_consistency_time + 1))" \
  --output "$factory_transparency_external_consistency_report_2" \
  --require-accepted
"$pcbex_binary" verify-factory-release-state-transparency-external-consistency \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --consistency-proof "$factory_transparency_external_consistency_proof_2" \
  --evaluated-at-unix "$((factory_transparency_external_consistency_time + 10000))" \
  --output "$factory_transparency_external_consistency_replay" \
  --require-accepted
cmp "$factory_transparency_external_consistency_report_2" \
  "$factory_transparency_external_consistency_replay"

python3 - \
  "$factory_transparency_external_consistency_report_1" \
  "$factory_transparency_external_consistency_report_2" \
  "$factory_transparency_external_consistency_proof_1" \
  "$factory_transparency_external_consistency_proof_2" \
  "$factory_transparency_external_anchor_report" \
  "$factory_transparency_external_consistency_proof_schema" \
  "$factory_transparency_external_consistency_report_schema" \
  "$monotonic_release_ledger" "$monotonic_key" \
  "$factory_transparency_external_anchor_private" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

report_1_path, report_2_path, proof_1_path, proof_2_path, anchor_path, \
    proof_schema_path, report_schema_path, ledger_path = map(Path, sys.argv[1:9])
key, private_path = sys.argv[9:]
report_1 = json.loads(report_1_path.read_bytes())
report_2 = json.loads(report_2_path.read_bytes())
proof_1 = json.loads(proof_1_path.read_bytes())
proof_2 = json.loads(proof_2_path.read_bytes())
anchor = json.loads(anchor_path.read_bytes())
for report, generation, previous_size, current_size, proof in (
    (report_1, 1, 3, 4, proof_1),
    (report_2, 2, 4, 5, proof_2),
):
    assert report["status"] == "verified"
    assert report["external_consistency_generation"] == generation
    assert report["previous_external_tree_size"] == previous_size
    assert report["current_external_tree_size"] == current_size
    assert report["external_anchor_report"] == anchor
    assert report["consistency_proof"] == proof
    for claim in (
        "monotonic_state_chain_verified",
        "source_checkpoint_inclusion_verified",
        "complete_source_consistency_chain_verified",
        "source_log_append_only_consistency_verified",
        "witness_quorum_verified",
        "external_anchor_verified",
        "external_anchor_report_identity_verified",
        "external_anchor_policy_pin_matched",
        "external_log_policy_matched",
        "previous_external_tree_head_signature_verified",
        "current_external_tree_head_signature_verified",
        "same_external_log_and_key_verified",
        "strict_external_tree_extension_verified",
        "external_consistency_proof_verified",
        "complete_external_consistency_chain_verified",
        "external_log_append_only_consistency_verified",
        "current_external_checkpoint_fresh_at_evaluation",
    ):
        assert report[claim] is True, claim
    for claim in (
        "selected_ledger_external_consistency_report_committed",
        "global_non_equivocation_verified",
        "selected_ledger_rollback_resistance_verified",
        "trusted_time_verified",
        "independent_organization_operation_verified",
        "endpoint_transport_authenticity_verified",
        "factory_legal_identity_verified",
        "server_side_idempotency_enforced",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "exactly_once_execution_verified",
    ):
        assert report[claim] is False, claim
assert report_1["previous_external_consistency_report_artifact"] is None
assert report_2["previous_external_consistency_report_artifact"] == {
    "bytes": len(report_1_path.read_bytes()),
    "sha256": hashlib.sha256(report_1_path.read_bytes()).hexdigest(),
}
assert report_1["chain_anchor_external_anchor_report_artifact"] == {
    "bytes": len(anchor_path.read_bytes()),
    "sha256": hashlib.sha256(anchor_path.read_bytes()).hexdigest(),
}
filename_context = {
    "source_log_id": report_2["source_log_id"],
    "witness_policy_sha256": report_2["witness_policy_sha256"],
    "external_log_id": report_2["external_log_id"],
    "external_anchor_policy_sha256": report_2["external_anchor_policy_sha256"],
}
context_sha256 = hashlib.sha256(
    b"pcbex:factory-release-state-transparency-external-consistency-filename:v1\0" +
    json.dumps(filename_context, separators=(",", ":")).encode("ascii")
).hexdigest()
for report_path, generation in ((report_1_path, 1), (report_2_path, 2)):
    name = (
        f"factory-release-state-transparency-external-consistency-v1-{key}-"
        f"{generation:04}-{context_sha256[:32]}.json"
    )
    assert (ledger_path / name).read_bytes() == report_path.read_bytes()
secret = Path(private_path).read_text(encoding="ascii").strip().encode()
for path in [report_1_path, report_2_path, *ledger_path.iterdir()]:
    assert secret not in path.read_bytes(), path
for schema_path in (proof_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

# v1.490 compares the exact latest v1.489 external-log head with a separately
# keyed observer receipt. Unequal sizes require a bounded consistency proof;
# equal-size divergent roots fail closed as a split view.
factory_transparency_external_gossip_receipt_schema="$output_directory/factory-release-transparency-external-gossip-receipt.schema.json"
factory_transparency_external_gossip_report_schema="$output_directory/factory-release-transparency-external-gossip-report.schema.json"
factory_transparency_external_gossip_receipt="$output_directory/factory-release-transparency-external-gossip.receipt.json"
factory_transparency_external_gossip_tampered_receipt="$output_directory/factory-release-transparency-external-gossip-tampered.receipt.json"
factory_transparency_external_gossip_split_receipt="$output_directory/factory-release-transparency-external-gossip-split.receipt.json"
factory_transparency_external_gossip_role_collision_receipt="$output_directory/factory-release-transparency-external-gossip-role-collision.receipt.json"
factory_transparency_external_gossip_competing_receipt="$output_directory/factory-release-transparency-external-gossip-competing.receipt.json"
factory_transparency_external_gossip_proof="$output_directory/factory-release-transparency-external-gossip.proof.json"
factory_transparency_external_gossip_public_key_file="$output_directory/factory-release-transparency-external-gossip.public.hex"
factory_transparency_external_gossip_report="$output_directory/factory-release-transparency-external-gossip.report.json"
factory_transparency_external_gossip_replay="$output_directory/factory-release-transparency-external-gossip.replay.json"
factory_transparency_external_gossip_tampered_output="$output_directory/factory-release-transparency-external-gossip-tampered.report.json"
factory_transparency_external_gossip_tampered_error="$output_directory/factory-release-transparency-external-gossip-tampered.stderr"
factory_transparency_external_gossip_split_output="$output_directory/factory-release-transparency-external-gossip-split.report.json"
factory_transparency_external_gossip_split_error="$output_directory/factory-release-transparency-external-gossip-split.stderr"
factory_transparency_external_gossip_missing_proof_output="$output_directory/factory-release-transparency-external-gossip-missing-proof.report.json"
factory_transparency_external_gossip_missing_proof_error="$output_directory/factory-release-transparency-external-gossip-missing-proof.stderr"
factory_transparency_external_gossip_role_collision_output="$output_directory/factory-release-transparency-external-gossip-role-collision.report.json"
factory_transparency_external_gossip_role_collision_error="$output_directory/factory-release-transparency-external-gossip-role-collision.stderr"
factory_transparency_external_gossip_conflict_output="$output_directory/factory-release-transparency-external-gossip-conflict.report.json"
factory_transparency_external_gossip_conflict_error="$output_directory/factory-release-transparency-external-gossip-conflict.stderr"

"$pcbex_binary" factory-release-state-transparency-external-gossip-receipt-schema \
  --output "$factory_transparency_external_gossip_receipt_schema"
"$pcbex_binary" factory-release-state-transparency-external-gossip-verification-report-schema \
  --output "$factory_transparency_external_gossip_report_schema"

python3 - \
  "$factory_transparency_external_consistency_report_2" \
  "$factory_transparency_external_anchor_private" \
  "$factory_transparency_external_gossip_private" \
  "$factory_transparency_external_gossip_public_key_file" \
  "$factory_transparency_external_gossip_receipt" \
  "$factory_transparency_external_gossip_tampered_receipt" \
  "$factory_transparency_external_gossip_split_receipt" \
  "$factory_transparency_external_gossip_role_collision_receipt" \
  "$factory_transparency_external_gossip_competing_receipt" \
  "$factory_transparency_external_gossip_proof" <<'PY'
import copy
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

local_report_path, external_private_path, observer_private_path, observer_public_path, \
    receipt_path, tampered_path, split_path, role_collision_path, competing_path, \
    proof_path = map(Path, sys.argv[1:])
local_report = json.loads(local_report_path.read_bytes())
local_head = local_report["consistency_proof"]["current_tree_head"]
anchor_proof = local_report["external_anchor_report"]["anchor_proof"]
external_seed = bytes.fromhex(
    external_private_path.read_text(encoding="ascii").strip()
)
external_private = Ed25519PrivateKey.from_private_bytes(external_seed)
observer_seed = bytes([71]) * 32
observer_private = Ed25519PrivateKey.from_private_bytes(observer_seed)
observer_public = observer_private.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()
observer_private_path.write_text(observer_seed.hex() + "\n", encoding="ascii")
observer_public_path.write_text(observer_public + "\n", encoding="ascii")

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")

def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

def merkle_leaf(digest):
    return hashlib.sha256(
        b"\x00" +
        b"pcbex:factory-release-state-transparency-external-anchor-merkle-leaf:v1\0" +
        bytes.fromhex(digest)
    ).digest()

def merkle_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()

def merkle_root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return merkle_node(merkle_root(leaves[:split]), merkle_root(leaves[split:]))

def consistency_subproof(old_size, leaves, complete_subtree):
    if old_size == len(leaves):
        return [] if complete_subtree else [merkle_root(leaves)]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if old_size <= split:
        return consistency_subproof(
            old_size, leaves[:split], complete_subtree
        ) + [merkle_root(leaves[split:])]
    return consistency_subproof(
        old_size - split, leaves[split:], False
    ) + [merkle_root(leaves[:split])]

def sign_head(head):
    payload = {
        "domain": "pcbex-factory-release-state-transparency-external-anchor-tree-head-v1",
        "schema_version": head["schema_version"],
        "tree_head_scope": head["tree_head_scope"],
        "log_id": head["log_id"],
        "tree_size": head["tree_size"],
        "root_sha256": head["root_sha256"],
        "observed_at_unix": head["observed_at_unix"],
        "algorithm": head["algorithm"],
        "public_key": head["public_key"],
    }
    head["signature"] = external_private.sign(compact(payload)).hex()

def head_sha256(head):
    return hashlib.sha256(compact(head)).hexdigest()

def signed_head(leaves, observed_at):
    head = {
        "schema_version": 1,
        "tree_head_scope":
            "signed-factory-release-state-transparency-external-anchor-tree-head-v1",
        "log_id": local_head["log_id"],
        "tree_size": len(leaves),
        "root_sha256": merkle_root(leaves).hex(),
        "observed_at_unix": observed_at,
        "algorithm": "ed25519",
        "public_key": local_head["public_key"],
        "signature": "",
    }
    sign_head(head)
    return head

def signed_receipt(head, observer_id, expires_at):
    received_at = head["observed_at_unix"]
    receipt = {
        "schema_version": 1,
        "receipt_scope":
            "factory-release-state-transparency-external-log-gossip-receipt-v1",
        "external_anchor_policy_sha256":
            local_report["external_anchor_policy_sha256"],
        "external_log_id": local_report["external_log_id"],
        "observer_id": observer_id,
        "observed_tree_head_sha256": head_sha256(head),
        "observed_tree_head": head,
        "received_at_unix": received_at,
        "expires_at_unix": expires_at,
        "algorithm": "ed25519",
        "observer_public_key": observer_public,
        "signature": "",
    }
    payload = {
        "domain":
            "pcbex-factory-release-state-transparency-external-log-gossip-receipt-v1",
        "schema_version": receipt["schema_version"],
        "receipt_scope": receipt["receipt_scope"],
        "external_anchor_policy_sha256":
            receipt["external_anchor_policy_sha256"],
        "external_log_id": receipt["external_log_id"],
        "observer_id": receipt["observer_id"],
        "observed_tree_head_sha256": receipt["observed_tree_head_sha256"],
        "observed_tree_size": head["tree_size"],
        "observed_root_sha256": head["root_sha256"],
        "observed_tree_head_observed_at_unix": head["observed_at_unix"],
        "external_log_public_key": head["public_key"],
        "received_at_unix": receipt["received_at_unix"],
        "expires_at_unix": receipt["expires_at_unix"],
        "algorithm": receipt["algorithm"],
        "observer_public_key": receipt["observer_public_key"],
    }
    receipt["signature"] = observer_private.sign(compact(payload)).hex()
    return receipt

anchor_leaf = merkle_leaf(anchor_proof["leaf_sha256"])
leaves_3 = [
    bytes.fromhex(anchor_proof["audit_path"][0]),
    anchor_leaf,
    bytes.fromhex(anchor_proof["audit_path"][1]),
]
leaves_5 = leaves_3 + [merkle_leaf("66" * 32), merkle_leaf("88" * 32)]
assert merkle_root(leaves_5).hex() == local_head["root_sha256"]
leaves_6 = leaves_5 + [merkle_leaf("99" * 32)]
observed_head = signed_head(leaves_6, local_head["observed_at_unix"] + 1)
receipt = signed_receipt(
    observed_head, "independent-observer-a", observed_head["observed_at_unix"] + 120
)
write(receipt_path, receipt)

tampered = copy.deepcopy(receipt)
tampered["signature"] = "00" * 64
write(tampered_path, tampered)

split_leaves = leaves_3 + [merkle_leaf("66" * 32), merkle_leaf("77" * 32)]
split_head = signed_head(split_leaves, observed_head["observed_at_unix"])
split_receipt = signed_receipt(
    split_head, "independent-observer-a", observed_head["observed_at_unix"] + 120
)
write(split_path, split_receipt)

role_collision = signed_receipt(
    observed_head,
    local_report["external_log_id"],
    observed_head["observed_at_unix"] + 120,
)
write(role_collision_path, role_collision)

competing = signed_receipt(
    observed_head, "independent-observer-a", observed_head["observed_at_unix"] + 121
)
write(competing_path, competing)

proof = {
    "schema_version": 1,
    "proof_scope":
        "factory-release-state-transparency-external-log-consistency-proof-v1",
    "external_anchor_policy_sha256":
        local_report["external_anchor_policy_sha256"],
    "external_log_id": local_report["external_log_id"],
    "previous_tree_head_sha256": head_sha256(local_head),
    "current_tree_head_sha256": head_sha256(observed_head),
    "previous_tree_head": local_head,
    "current_tree_head": observed_head,
    "consistency_path": [
        node.hex()
        for node in consistency_subproof(len(leaves_5), leaves_6, True)
    ],
}
write(proof_path, proof)
PY

factory_transparency_external_gossip_public_key="$(tr -d '\r\n' < "$factory_transparency_external_gossip_public_key_file")"
factory_transparency_external_gossip_time="$((factory_transparency_external_consistency_time + 2))"

verify_factory_transparency_external_gossip() {
  "$pcbex_binary" verify-factory-release-state-transparency-external-gossip \
    --reservation-ledger "$monotonic_release_ledger" \
    --expected-ledger-id "$signed_release_reservation_id" \
    --idempotency-key "$monotonic_key" \
    --log-id kicad-e2e-factory-release-log \
    --policy-pack "$factory_receipt_policy" \
    --expected-policy-sha256 "$fabrication_release_policy_digest" \
    --transparency-policy "$factory_transparency_policy" \
    --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
    --witness-policy "$factory_transparency_witness_policy" \
    --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
    --external-anchor-policy "$factory_transparency_external_anchor_policy" \
    --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
    --external-log-id kicad-e2e-external-anchor-log \
    --observer-id independent-observer-a \
    --expected-observer-public-key "$factory_transparency_external_gossip_public_key" \
    "$@"
}

if verify_factory_transparency_external_gossip \
  --gossip-receipt "$factory_transparency_external_gossip_tampered_receipt" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_tampered_output" \
  2>"$factory_transparency_external_gossip_tampered_error"; then
  echo "expected a tampered external gossip receipt to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_tampered_output"
grep -Fq 'invalid factory release transparency external gossip receipt signature' \
  "$factory_transparency_external_gossip_tampered_error"

if verify_factory_transparency_external_gossip \
  --gossip-receipt "$factory_transparency_external_gossip_split_receipt" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_split_output" \
  2>"$factory_transparency_external_gossip_split_error"; then
  echo "expected an equal-size external-log split view to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_split_output"
grep -Fq 'detected split-view roots at one tree size' \
  "$factory_transparency_external_gossip_split_error"

if verify_factory_transparency_external_gossip \
  --gossip-receipt "$factory_transparency_external_gossip_receipt" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_missing_proof_output" \
  2>"$factory_transparency_external_gossip_missing_proof_error"; then
  echo "expected unequal external-log heads without a proof to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_missing_proof_output"
grep -Fq 'requires a consistency proof for different tree sizes' \
  "$factory_transparency_external_gossip_missing_proof_error"

if "$pcbex_binary" verify-factory-release-state-transparency-external-gossip \
  --reservation-ledger "$monotonic_release_ledger" \
  --expected-ledger-id "$signed_release_reservation_id" \
  --idempotency-key "$monotonic_key" \
  --log-id kicad-e2e-factory-release-log \
  --policy-pack "$factory_receipt_policy" \
  --expected-policy-sha256 "$fabrication_release_policy_digest" \
  --transparency-policy "$factory_transparency_policy" \
  --expected-transparency-policy-sha256 "$factory_transparency_policy_digest" \
  --witness-policy "$factory_transparency_witness_policy" \
  --expected-witness-policy-sha256 "$factory_transparency_witness_policy_digest" \
  --external-anchor-policy "$factory_transparency_external_anchor_policy" \
  --expected-external-anchor-policy-sha256 "$factory_transparency_external_anchor_policy_digest" \
  --external-log-id kicad-e2e-external-anchor-log \
  --observer-id kicad-e2e-external-anchor-log \
  --expected-observer-public-key "$factory_transparency_external_gossip_public_key" \
  --gossip-receipt "$factory_transparency_external_gossip_role_collision_receipt" \
  --consistency-proof "$factory_transparency_external_gossip_proof" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_role_collision_output" \
  2>"$factory_transparency_external_gossip_role_collision_error"; then
  echo "expected an observer assigned to the external-log role to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_role_collision_output"
grep -Fq 'observer identity is assigned to a log, witness, or factory role' \
  "$factory_transparency_external_gossip_role_collision_error"

verify_factory_transparency_external_gossip \
  --gossip-receipt "$factory_transparency_external_gossip_receipt" \
  --consistency-proof "$factory_transparency_external_gossip_proof" \
  --evaluated-at-unix "$factory_transparency_external_gossip_time" \
  --output "$factory_transparency_external_gossip_report" \
  --require-accepted

if verify_factory_transparency_external_gossip \
  --gossip-receipt "$factory_transparency_external_gossip_competing_receipt" \
  --consistency-proof "$factory_transparency_external_gossip_proof" \
  --evaluated-at-unix "$((factory_transparency_external_gossip_time + 1))" \
  --output "$factory_transparency_external_gossip_conflict_output" \
  2>"$factory_transparency_external_gossip_conflict_error"; then
  echo "expected a competing observer receipt for one local generation to fail closed" >&2
  exit 1
fi
test ! -e "$factory_transparency_external_gossip_conflict_output"
grep -Fq 'external gossip record conflicts' \
  "$factory_transparency_external_gossip_conflict_error"

verify_factory_transparency_external_gossip \
  --gossip-receipt "$factory_transparency_external_gossip_receipt" \
  --consistency-proof "$factory_transparency_external_gossip_proof" \
  --evaluated-at-unix "$((factory_transparency_external_gossip_time + 10000))" \
  --output "$factory_transparency_external_gossip_replay" \
  --require-accepted
cmp "$factory_transparency_external_gossip_report" \
  "$factory_transparency_external_gossip_replay"

python3 - \
  "$factory_transparency_external_gossip_report" \
  "$factory_transparency_external_gossip_receipt" \
  "$factory_transparency_external_gossip_proof" \
  "$factory_transparency_external_consistency_report_2" \
  "$factory_transparency_external_anchor_policy" \
  "$factory_transparency_external_gossip_receipt_schema" \
  "$factory_transparency_external_gossip_report_schema" \
  "$monotonic_release_ledger" "$monotonic_key" \
  "$factory_transparency_external_anchor_private" \
  "$factory_transparency_external_gossip_private" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

report_path, receipt_path, proof_path, local_report_path, policy_path, \
    receipt_schema_path, report_schema_path, ledger_path = map(Path, sys.argv[1:9])
key, external_private_path, observer_private_path = sys.argv[9:]
report_source = report_path.read_bytes()
receipt_source = receipt_path.read_bytes()
proof_source = proof_path.read_bytes()
local_source = local_report_path.read_bytes()
policy_source = policy_path.read_bytes()
report = json.loads(report_source)
receipt = json.loads(receipt_source)
proof = json.loads(proof_source)
local_report = json.loads(local_source)

assert report["status"] == "verified"
assert report["relationship"] == "local_precedes_observed"
assert report["local_external_tree_size"] == 5
assert report["observed_external_tree_size"] == 6
assert report["local_external_consistency_generation"] == 2
assert report["observer_id"] == "independent-observer-a"
assert report["local_external_consistency_report"] == local_report
assert report["gossip_receipt"] == receipt
assert report["consistency_proof"] == proof
for claim in (
    "monotonic_state_chain_verified",
    "source_checkpoint_inclusion_verified",
    "complete_source_consistency_chain_verified",
    "source_log_append_only_consistency_verified",
    "witness_quorum_verified",
    "external_anchor_verified",
    "complete_external_consistency_chain_verified",
    "external_log_append_only_consistency_verified",
    "local_external_consistency_report_identity_verified",
    "gossip_receipt_identity_verified",
    "external_anchor_policy_pin_matched",
    "external_log_policy_matched",
    "local_external_tree_head_signature_verified",
    "observed_external_tree_head_signature_verified",
    "observer_pin_matched",
    "observer_receipt_signature_verified",
    "observer_log_and_witness_role_separation_verified",
    "external_tree_relationship_verified",
    "selected_observer_view_consistency_verified",
    "observed_external_checkpoint_fresh_at_evaluation",
    "external_consistency_proof_required",
    "external_consistency_proof_verified",
    "local_external_consistency_extension_available",
):
    assert report[claim] is True, claim
for claim in (
    "split_view_detected",
    "selected_ledger_external_gossip_report_committed",
    "global_non_equivocation_verified",
    "selected_ledger_rollback_resistance_verified",
    "trusted_time_verified",
    "independent_organization_operation_verified",
    "endpoint_transport_authenticity_verified",
    "factory_legal_identity_verified",
    "server_side_idempotency_enforced",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "exactly_once_execution_verified",
):
    assert report[claim] is False, claim

def identity(source):
    return {
        "bytes": len(source),
        "sha256": hashlib.sha256(source).hexdigest(),
    }

assert report["local_external_consistency_report_artifact"] == identity(local_source)
assert report["external_anchor_policy_artifact"] == identity(policy_source)
assert report["gossip_receipt_artifact"] == identity(receipt_source)
assert report["consistency_proof_artifact"] == identity(proof_source)
filename_context = {
    "source_log_id": report["source_log_id"],
    "witness_policy_sha256": report["witness_policy_sha256"],
    "external_log_id": report["external_log_id"],
    "external_anchor_policy_sha256": report["external_anchor_policy_sha256"],
    "local_external_consistency_generation":
        report["local_external_consistency_generation"],
    "observer_id": report["observer_id"],
    "observer_public_key": report["observer_public_key"],
}
context_sha256 = hashlib.sha256(
    b"pcbex:factory-release-state-transparency-external-gossip-filename:v1\0" +
    json.dumps(filename_context, separators=(",", ":")).encode("ascii")
).hexdigest()
name = (
    f"factory-release-state-transparency-external-gossip-v1-{key}-"
    f"{report['local_external_consistency_generation']:04}-{context_sha256[:32]}.json"
)
assert (ledger_path / name).read_bytes() == report_source

secrets = [
    Path(external_private_path).read_text(encoding="ascii").strip().encode(),
    Path(observer_private_path).read_text(encoding="ascii").strip().encode(),
]
for path in [report_path, *ledger_path.iterdir()]:
    source = path.read_bytes()
    for secret in secrets:
        assert secret not in source, path
for schema_path in (receipt_schema_path, report_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY
run_v1491_external_gossip_quorum_e2e
unset PCBEX_E2E_SIGNED_RELEASE_ADAPTER_TOKEN
rm -f -- \
  "$factory_response_private_key" "$factory_response_public_der" \
  "$factory_transparency_private_key" "$factory_transparency_public_der" \
  "$factory_transparency_witness_private_a" "$factory_transparency_witness_private_b" \
  "$factory_transparency_external_anchor_private" \
  "$factory_transparency_external_gossip_private" \
  "$factory_transparency_external_gossip_private_b" \
  "$factory_transparency_external_gossip_private_a_next" \
  "$factory_transparency_external_gossip_private_a_fork" \
  "$factory_transparency_external_gossip_registry_authority_private"
rmdir -- "$factory_response_secret_directory" "$factory_witness_secret_directory"
trap - EXIT

# Reuse the same real Rust binary through the Python saved-generation
# orchestrator. The focused test first obtains a genuine immutable-ERC check,
# then requires the writer and explicit semantic handoff before inspecting the
# atomically published deterministic ZIP. The final test reruns that complete
# handoff chain and requires byte-for-byte reproduction of the archive.
PCBEX_TEST_BINARY="$pcbex_binary" PYTHONPATH=agent/src \
  python3 -m unittest \
  agent.tests.test_circuit_handoff_bundle_v1448.CircuitHandoffBundleTests.test_real_native_erc_writer_and_handoff_when_binary_is_supplied \
  agent.tests.test_circuit_handoff_bundle_v1449.CircuitHandoffBundleV1449Tests.test_real_rust_archive_is_verified_and_extracted_when_binary_is_supplied \
  agent.tests.test_circuit_handoff_bundle_v1450.CircuitHandoffBundleV1450Tests.test_real_rust_handoff_chain_replays_when_binary_is_supplied \
  agent.tests.test_circuit_handoff_bundle_v1451.CircuitHandoffBundleV1451Tests.test_real_rust_and_kicad_replay_when_binary_is_supplied \
  agent.tests.test_circuit_handoff_bundle_v1452.CircuitHandoffBundleV1452Tests.test_real_rust_kicad_and_two_reviewer_quorum_replay_when_binary_is_supplied \
  agent.tests.test_circuit_handoff_bundle_v1453.CircuitHandoffBundleV1453Tests.test_real_rust_catalog_provenance_handoff_replay_when_binary_is_supplied \
  agent.tests.test_circuit_handoff_bundle_v1454.CircuitHandoffBundleV1454Tests.test_real_rust_board_binding_replay_with_deterministic_pipeline_fixture \
  agent.tests.test_manufacturing_replay_v1455.ManufacturingReplayTests.test_real_outer_timeout_reaps_kicad_after_pre_exec_delay

# Native KiCad ERC is a second, independent electrical gate.  The runner uses
# a private staged directory and an error-only invocation, so KiCad's
# timestamp/source-path fields cannot make the retained evidence unstable.
native_erc_first="$output_directory/circuit-spec-v2.native-erc.first.json"
native_erc_second="$output_directory/circuit-spec-v2.native-erc.second.json"
"$pcbex_binary" run-native-kicad-erc "$generated_schematic" \
  --output "$native_erc_first" --require-approved
"$pcbex_binary" run-native-kicad-erc "$generated_schematic" \
  --output "$native_erc_second" --require-approved
cmp "$native_erc_first" "$native_erc_second"
python3 - "$generated_schematic" "$native_erc_first" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

schematic = Path(sys.argv[1])
report_path = Path(sys.argv[2])
source = schematic.read_bytes()
report = json.loads(report_path.read_text(encoding="utf-8"))
assert set(report) == {
    "schema_version", "engine", "engine_version", "kicad_version", "source",
    "invocation", "ignored_checks", "findings", "error_count", "approved",
    "run_sha256",
}
assert report["schema_version"] == 1
assert report["engine"] == "pcbex"
assert report["engine_version"]
assert report["kicad_version"]
assert report["source"] == {
    "bytes": len(source),
    "sha256": hashlib.sha256(source).hexdigest(),
}
assert report["invocation"] == {
    "command": "sch erc",
    "format": "json",
    "units": "mm",
    "severity": "error",
    "exit_code_violations": True,
}
assert isinstance(report["ignored_checks"], list)
assert report["findings"] == []
assert report["error_count"] == 0
assert report["approved"] is True
assert len(report["run_sha256"]) == 64
assert all(character in "0123456789abcdef" for character in report["run_sha256"])
PY

# A known-bad schematic must still publish its rejected evidence before the
# --require-approved gate returns non-zero.  This protects CI diagnostics and
# prevents a failed check from being mistaken for a missing report.
native_erc_rejected="$output_directory/simple.native-erc.json"
if "$pcbex_binary" run-native-kicad-erc examples/simple.kicad_sch \
  --output "$native_erc_rejected" --require-approved; then
  echo "expected native KiCad ERC rejection for examples/simple.kicad_sch" >&2
  exit 1
fi
test -s "$native_erc_rejected"
jq -e '
  .schema_version == 1 and
  .engine == "pcbex" and
  .approved == false and
  (.error_count | type == "number" and . > 0) and
  (.findings | length) == .error_count and
  .invocation.severity == "error"
' "$native_erc_rejected" >/dev/null

native_erc_schema="$output_directory/native-kicad-erc.schema.json"
"$pcbex_binary" native-kicad-erc-report-schema --output "$native_erc_schema"
python3 - "$native_erc_schema" <<'PY'
import json
from pathlib import Path
import sys

schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert schema["$id"].endswith("/schemas/native-kicad-erc-v1.json")
assert schema["additionalProperties"] is False
assert {
    "schema_version", "engine", "engine_version", "kicad_version", "source",
    "invocation", "ignored_checks", "findings", "error_count", "approved",
    "run_sha256",
}.issubset(schema["required"])
assert schema["properties"]["schema_version"] == {"const": 1}
assert schema["properties"]["engine"] == {"const": "pcbex"}
assert schema["properties"]["invocation"]["additionalProperties"] is False
assert schema["$defs"]["finding"]["properties"]["severity"] == {"const": "error"}
PY

# Warning-policy mode is a separate, opt-in report contract. The generated
# circuit is expected to retain 11 known KiCad 10 warnings while remaining
# error-free. Repeat the run to prove volatile KiCad fields are normalized.
native_warning_policy="examples/native-kicad-warning-policy.json"
native_warning_first="$output_directory/circuit-spec-v2.native-warning.first.json"
native_warning_second="$output_directory/circuit-spec-v2.native-warning.second.json"
"$pcbex_binary" run-native-kicad-erc "$generated_schematic" \
  --warning-policy "$native_warning_policy" \
  --output "$native_warning_first" --require-approved
"$pcbex_binary" run-native-kicad-erc "$generated_schematic" \
  --warning-policy "$native_warning_policy" \
  --output "$native_warning_second" --require-approved
cmp "$native_warning_first" "$native_warning_second"
python3 - "$generated_schematic" "$native_warning_policy" "$native_warning_first" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

schematic = Path(sys.argv[1]).read_bytes()
policy_bytes = Path(sys.argv[2]).read_bytes()
policy = json.loads(policy_bytes)
report = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
assert set(report) == {
    "schema_version", "engine", "engine_version", "kicad_version", "source",
    "invocation", "ignored_checks", "findings", "error_count", "warning_count",
    "warning_counts", "warning_policy", "policy_failures", "approved",
    "run_sha256",
}
assert report["schema_version"] == 2
assert report["source"] == {
    "bytes": len(schematic),
    "sha256": hashlib.sha256(schematic).hexdigest(),
}
assert report["invocation"] == {
    "command": "sch erc",
    "format": "json",
    "units": "mm",
    "severities": ["error", "warning"],
    "exit_code_violations": True,
}
assert report["error_count"] == 0
assert report["warning_count"] == 11
assert report["warning_counts"] == [
    {"finding_type": "footprint_link_issues", "count": 4},
    {"finding_type": "lib_symbol_issues", "count": 4},
    {"finding_type": "multiple_net_names", "count": 3},
]
assert len(report["findings"]) == 11
assert {finding["severity"] for finding in report["findings"]} == {"warning"}
assert report["policy_failures"] == []
assert report["approved"] is True
assert report["warning_policy"]["source"] == {
    "bytes": len(policy_bytes),
    "sha256": hashlib.sha256(policy_bytes).hexdigest(),
}
assert report["warning_policy"]["policy"] == policy
assert len(report["warning_policy"]["policy_sha256"]) == 64
assert len(report["run_sha256"]) == 64
PY

# Tightening the global budget must retain a valid rejected report before the
# final gate fails.
strict_warning_policy="$output_directory/native-kicad-warning-policy.strict.json"
python3 - "$native_warning_policy" "$strict_warning_policy" <<'PY'
import json
from pathlib import Path
import sys

policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
policy["id"] = "pcbex-generated-circuit-kicad-10-strict"
policy["maximum_total_warnings"] = 10
Path(sys.argv[2]).write_text(
    json.dumps(policy, ensure_ascii=False, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
native_warning_rejected="$output_directory/circuit-spec-v2.native-warning.rejected.json"
if "$pcbex_binary" run-native-kicad-erc "$generated_schematic" \
  --warning-policy "$strict_warning_policy" \
  --output "$native_warning_rejected" --require-approved; then
  echo "expected native KiCad ERC warning-policy rejection" >&2
  exit 1
fi
jq -e '
  .schema_version == 2 and
  .approved == false and
  .error_count == 0 and
  .warning_count == 11 and
  (.policy_failures | length) == 1 and
  .policy_failures[0].code == "total" and
  .policy_failures[0].actual_count == 11 and
  .policy_failures[0].maximum_count == 10
' "$native_warning_rejected" >/dev/null

native_warning_policy_schema="$output_directory/native-kicad-warning-policy.schema.json"
native_warning_report_schema="$output_directory/native-kicad-warning-report.schema.json"
"$pcbex_binary" native-kicad-erc-warning-policy-schema \
  --output "$native_warning_policy_schema"
"$pcbex_binary" native-kicad-erc-warning-report-schema \
  --output "$native_warning_report_schema"
python3 - "$native_warning_policy_schema" "$native_warning_report_schema" <<'PY'
import json
from pathlib import Path
import sys

policy_schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
report_schema = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
assert policy_schema["$id"].endswith("/schemas/native-kicad-erc-warning-policy-v1.json")
assert report_schema["$id"].endswith("/schemas/native-kicad-erc-v2.json")
assert policy_schema["additionalProperties"] is False
assert report_schema["additionalProperties"] is False
assert report_schema["properties"]["schema_version"] == {"const": 2}
assert report_schema["properties"]["invocation"]["properties"]["severities"] == {
    "const": ["error", "warning"]
}
assert report_schema["$defs"]["finding"]["properties"]["severity"] == {
    "enum": ["error", "warning"]
}
PY

for fixture in "${fixtures[@]}"; do
  name=$(basename "$fixture" .kicad_pcb)
  first="$output_directory/$name.routed.kicad_pcb"
  second="$output_directory/$name.rerouted.kicad_pcb"
  routes="$output_directory/$name.routes.json"
  reroutes="$output_directory/$name.reroutes.json"

  "$pcbex_binary" route-kicad "$fixture" \
    --output "$first" \
    --json-output "$routes" \
    --drc
  jq -e '.routes | length > 0' "$routes" >/dev/null

  "$pcbex_binary" route-kicad "$first" \
    --output "$second" \
    --json-output "$reroutes" \
    --drc
  jq -e '.routes | length > 0' "$reroutes" >/dev/null
  cmp "$first" "$second"
done

# Native KiCad PCB DRC is an independent evidence gate.  The routed simple
# fixture is clean; run it twice into fresh reports so that normalization also
# proves volatile KiCad UUID/date/path fields cannot affect the retained bytes.
native_drc_first="$output_directory/simple.native-drc.first.json"
native_drc_second="$output_directory/simple.native-drc.second.json"
native_drc_board="$output_directory/simple.routed.kicad_pcb"
"$pcbex_binary" run-native-kicad-drc "$native_drc_board" \
  --output "$native_drc_first" --require-approved
"$pcbex_binary" run-native-kicad-drc "$native_drc_board" \
  --output "$native_drc_second" --require-approved
cmp "$native_drc_first" "$native_drc_second"
python3 - "$native_drc_board" "$native_drc_first" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

board_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
board = board_path.read_bytes()
raw = report_path.read_text(encoding="utf-8")
report = json.loads(raw)

expected_fields = {
    "schema_version", "engine", "engine_version", "kicad_version", "source",
    "project", "rules_file", "invocation", "ignored_checks", "findings",
    "violation_count", "unconnected_item_count", "schematic_parity_count",
    "error_count", "warning_count", "approved", "run_sha256",
}
assert set(report) == expected_fields
assert report["schema_version"] == 1
assert report["engine"] == "pcbex"
assert report["engine_version"]
assert report["kicad_version"]
assert report["source"] == {
    "bytes": len(board),
    "sha256": hashlib.sha256(board).hexdigest(),
}
assert report["project"] is None
assert report["rules_file"] is None
assert report["invocation"] == {
    "command": "pcb drc",
    "format": "json",
    "units": "mm",
    "severities": ["error", "warning"],
    "exit_code_violations": True,
    "all_track_errors": False,
    "schematic_parity": False,
    "refill_zones": False,
    "save_board": False,
}
assert isinstance(report["ignored_checks"], list)
assert report["findings"] == []
for field in (
    "violation_count", "unconnected_item_count", "schematic_parity_count",
    "error_count", "warning_count",
):
    assert report[field] == 0, (field, report[field])
assert report["approved"] is True
assert len(report["run_sha256"]) == 64
assert all(character in "0123456789abcdef" for character in report["run_sha256"])
# Raw KiCad evidence is deliberately not retained in the normalized report.
lower = raw.lower()
for forbidden in ('"uuid"', '"date"', '"path"'):
    assert forbidden not in lower, forbidden
PY

native_drc_schema="$output_directory/native-kicad-drc.schema.json"
"$pcbex_binary" native-kicad-drc-report-schema --output "$native_drc_schema"
python3 - "$native_drc_schema" <<'PY'
import json
from pathlib import Path
import sys

schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert schema["$id"].endswith("/schemas/native-kicad-pcb-drc-v1.json")
assert schema["additionalProperties"] is False
required = set(schema["required"])
assert required == {
    "schema_version", "engine", "engine_version", "kicad_version", "source",
    "project", "rules_file", "invocation", "ignored_checks", "findings",
    "violation_count", "unconnected_item_count", "schematic_parity_count",
    "error_count", "warning_count", "approved", "run_sha256",
}
properties = schema["properties"]
assert properties["schema_version"] == {"const": 1}
assert properties["engine"] == {"const": "pcbex"}
invocation = properties["invocation"]
assert invocation["additionalProperties"] is False
assert invocation["properties"]["command"] == {"const": "pcb drc"}
assert invocation["properties"]["format"] == {"const": "json"}
assert invocation["properties"]["units"] == {"const": "mm"}
assert invocation["properties"]["severities"] == {
    "const": ["error", "warning"]
}
for field in (
    "exit_code_violations", "all_track_errors", "schematic_parity",
    "refill_zones", "save_board",
):
    assert field in invocation["required"]
assert invocation["properties"]["exit_code_violations"] == {"const": True}
assert invocation["properties"]["all_track_errors"] == {"const": False}
assert invocation["properties"]["schematic_parity"] == {"const": False}
assert invocation["properties"]["refill_zones"] == {"const": False}
assert invocation["properties"]["save_board"] == {"const": False}
item = schema["$defs"]["item"]
assert item["additionalProperties"] is False
assert set(item["required"]) == {"description", "position_nm"}
assert item["properties"]["position_nm"] == {"$ref": "#/$defs/position"}
position = schema["$defs"]["position"]
assert position["additionalProperties"] is False
assert set(position["required"]) == {"x", "y"}
finding = schema["$defs"]["finding"]
assert finding["properties"]["category"] == {
    "enum": ["violation", "unconnected-item", "schematic-parity"]
}
assert finding["properties"]["type"]["type"] == "string"
assert "type" in finding["required"]
PY

# The source fixture intentionally contains one unconnected item.  KiCad uses
# exit code 5 for that valid rejected report; pcbex must retain and normalize
# it before --require-approved returns non-zero.
native_drc_rejected="$output_directory/simple.native-drc.rejected.json"
if "$pcbex_binary" run-native-kicad-drc examples/simple.kicad_pcb \
  --output "$native_drc_rejected" --require-approved; then
  echo "expected native KiCad PCB DRC rejection for examples/simple.kicad_pcb" >&2
  exit 1
fi
test -s "$native_drc_rejected"
python3 - "examples/simple.kicad_pcb" "$native_drc_rejected" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

board_path, report_path = map(Path, sys.argv[1:])
board = board_path.read_bytes()
raw = report_path.read_text(encoding="utf-8")
report = json.loads(raw)
assert set(report) == {
    "schema_version", "engine", "engine_version", "kicad_version", "source",
    "project", "rules_file", "invocation", "ignored_checks", "findings",
    "violation_count", "unconnected_item_count", "schematic_parity_count",
    "error_count", "warning_count", "approved", "run_sha256",
}
assert report["schema_version"] == 1
assert report["engine"] == "pcbex"
assert report["source"] == {
    "bytes": len(board),
    "sha256": hashlib.sha256(board).hexdigest(),
}
assert report["project"] is None
assert report["rules_file"] is None
assert report["invocation"] == {
    "command": "pcb drc",
    "format": "json",
    "units": "mm",
    "severities": ["error", "warning"],
    "exit_code_violations": True,
    "all_track_errors": False,
    "schematic_parity": False,
    "refill_zones": False,
    "save_board": False,
}
assert report["approved"] is False
assert report["unconnected_item_count"] > 0
assert report["error_count"] > 0
assert report["warning_count"] >= 0
assert report["violation_count"] == 0
assert report["schematic_parity_count"] == 0
assert len(report["findings"]) == report["unconnected_item_count"]
assert all(finding["category"] == "unconnected-item" for finding in report["findings"])
assert len(report["run_sha256"]) == 64
assert all(character in "0123456789abcdef" for character in report["run_sha256"])
lower = raw.lower()
for forbidden in ('"uuid"', '"date"', '"path"'):
    assert forbidden not in lower, forbidden
PY

placed="$output_directory/simple.placed.kicad_pcb"
placement_json="$output_directory/simple.placement.json"
"$pcbex_binary" place-kicad examples/simple.kicad_pcb \
  --output "$placed" \
  --json-output "$placement_json" \
  --iterations 0
jq -e '.components | length == 3' "$placement_json" >/dev/null
"$pcbex_binary" route-kicad "$placed" \
  --output "$output_directory/simple.placed.routed.kicad_pcb" \
  --drc

# KiCad 10 rewrites the numeric IDs in this fixture when it upgrades the board
# (F.Cu=0, In1.Cu=4, In2.Cu=6, B.Cu=2). Keep the upgraded copy separate so
# this exercises the current layer map without changing the routed fixture.
upgraded_multilayer="$output_directory/multilayer.kicad10.routed.kicad_pcb"
cp "$output_directory/multilayer.routed.kicad_pcb" "$upgraded_multilayer"
kicad-cli pcb upgrade --force "$upgraded_multilayer"
grep -F '(0 "F.Cu" signal)' "$upgraded_multilayer" >/dev/null
grep -F '(4 "In1.Cu" signal)' "$upgraded_multilayer" >/dev/null
grep -F '(6 "In2.Cu" signal)' "$upgraded_multilayer" >/dev/null
grep -F '(2 "B.Cu" signal)' "$upgraded_multilayer" >/dev/null

manufacturing_directory="$output_directory/multilayer.manufacturing"
mkdir -p "$manufacturing_directory"
printf '%s\n' "must remain outside the package" >"$manufacturing_directory/unrelated.secret"
"$pcbex_binary" fabricate "$upgraded_multilayer" \
  --output-dir "$manufacturing_directory"

test -f "$manufacturing_directory/bom.csv"
test -f "$manufacturing_directory/cpl.csv"
test -f "$manufacturing_directory/drc.rpt"
test -f "$manufacturing_directory/manifest.json"
test -f "$manufacturing_directory/manufacturing.zip"
compgen -G "$manufacturing_directory/*-In1_Cu.*" >/dev/null
compgen -G "$manufacturing_directory/*-In2_Cu.*" >/dev/null
compgen -G "$manufacturing_directory/*-f_paste.*" >/dev/null
jq -e '
  .schema_version == 1 and
  .input.path == "multilayer.kicad10.routed.kicad_pcb" and
  (.tools.kicad_cli | length > 0) and
  (.tools.kicad_cli_about_sha256 | test("^[0-9a-f]{64}$")) and
  .parts.bom == 2 and
  .parts.placement == 2 and
  all(.artifacts[].path; . != "unrelated.secret") and
  any(.artifacts[].path; contains("-In1_Cu.")) and
  any(.artifacts[].path; contains("-In2_Cu.")) and
  any(.artifacts[].path; contains("-f_paste."))
' "$manufacturing_directory/manifest.json" >/dev/null
python3 - "$manufacturing_directory" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import zipfile

directory = Path(sys.argv[1])
manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
for artifact in manifest["artifacts"]:
    payload = (directory / artifact["path"]).read_bytes()
    assert len(payload) == artifact["bytes"]
    assert hashlib.sha256(payload).hexdigest() == artifact["sha256"]
with zipfile.ZipFile(directory / "manufacturing.zip") as archive:
    names = archive.namelist()
    assert "manifest.json" in names
    assert "unrelated.secret" not in names
PY

cp "$manufacturing_directory/manufacturing.zip" \
  "$manufacturing_directory/first.manufacturing.zip"
"$pcbex_binary" fabricate "$upgraded_multilayer" \
  --output-dir "$manufacturing_directory"
cmp "$manufacturing_directory/first.manufacturing.zip" \
  "$manufacturing_directory/manufacturing.zip"

# The canonical manufacturing ZIP is the retained boundary for the fresh
# replay. Keep the Rust and KiCad executables explicit so the replay cannot
# accidentally select a different producer from PATH; the command publishes
# its path-free result on stdout and leaves no replay artifacts beside the
# retained package.
retained_manufacturing_zip="$manufacturing_directory/manufacturing.zip"
retained_manufacturing_sha_before="$(sha256sum "$retained_manufacturing_zip" | awk '{print $1}')"
retained_manufacturing_bytes_before="$(wc -c <"$retained_manufacturing_zip" | tr -d '[:space:]')"

# v1.465 binds the real upgraded KiCad board to the exact placement list in
# the retained package. This is a vendor-neutral board-coordinate assertion;
# it does not claim circuit-authored positions, a factory transform, assembly,
# procurement authorization, or order placement.
final_cpl_report="$output_directory/multilayer.final-cpl.json"
final_cpl_schema="$output_directory/final-cpl.schema.json"
"$pcbex_binary" verify-final-cpl \
  "$upgraded_multilayer" "$retained_manufacturing_zip" \
  --output "$final_cpl_report" \
  --require-approved
"$pcbex_binary" final-cpl-report-schema --output "$final_cpl_schema"
python3 - \
  "$upgraded_multilayer" \
  "$retained_manufacturing_zip" \
  "$final_cpl_report" \
  "$final_cpl_schema" \
  "$output_directory" <<'PY'
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys
import zipfile

board_path, package_path, report_path, schema_path, output_directory = map(
    Path, sys.argv[1:]
)

def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

board = board_path.read_bytes()
package = package_path.read_bytes()
with zipfile.ZipFile(package_path) as archive:
    manifest = archive.read("manifest.json")
    cpl = archive.read("cpl.csv")

report = json.loads(report_path.read_text(encoding="utf-8"))
assert set(report) == {
    "schema_version", "scope", "engine_version", "board_basename", "sources",
    "counts", "in_pos_parts", "findings", "approved",
}
assert report["schema_version"] == 1
assert report["scope"] == "final_cpl_source_and_canonical_placement_v1"
assert report["engine_version"]
assert report["board_basename"] == board_path.name
assert report["approved"] is True
assert report["findings"] == []
assert report["sources"] == {
    "board": identity(board),
    "manufacturing_package": identity(package),
    "manifest": identity(manifest),
    "cpl": identity(cpl),
    "canonical_cpl": identity(cpl),
    "package_board_source": identity(board),
}
assert report["counts"] == {
    "board_parts": 4,
    "board_in_pos_parts": 2,
    "package_parts": 4,
    "package_placement_parts": 2,
    "findings": 0,
}
assert len(report["in_pos_parts"]) == 2
assert [part["reference"] for part in report["in_pos_parts"]] == sorted(
    part["reference"] for part in report["in_pos_parts"]
)
for part in report["in_pos_parts"]:
    assert set(part) == {"reference", "x_nm", "y_nm", "rotation_mdeg", "layer"}
    assert part["reference"]
    assert type(part["x_nm"]) is int
    assert type(part["y_nm"]) is int
    assert type(part["rotation_mdeg"]) is int
    assert part["layer"] in {"F", "B"}

schema = json.loads(schema_path.read_text(encoding="utf-8"))
assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
assert schema["$id"].endswith("/schema/final-cpl-report-v1.json")
assert schema["additionalProperties"] is False
assert set(schema["required"]) == set(report)
assert schema["properties"]["scope"] == {
    "const": "final_cpl_source_and_canonical_placement_v1"
}
assert schema["properties"]["sources"]["additionalProperties"] is False
assert schema["properties"]["counts"]["additionalProperties"] is False
assert schema["properties"]["in_pos_parts"]["maxItems"] == 256
assert schema["properties"]["in_pos_parts"]["items"]["additionalProperties"] is False

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(report)
PY

# Rebuild a second, structurally and semantically valid classic ZIP after
# changing one CPL coordinate and its manifest artifact digest. The package
# still names the original board identity, so this isolates the canonical-CPL
# finding and proves that a valid mismatch is retained before the final gate.
final_cpl_tampered_package="$output_directory/multilayer.final-cpl.tampered.zip"
final_cpl_tampered_report="$output_directory/multilayer.final-cpl.tampered.json"
final_cpl_tampered_gated_report="$output_directory/multilayer.final-cpl.tampered.gated.json"
final_cpl_tampered_error="$output_directory/multilayer.final-cpl.tampered.stderr"
python3 - "$retained_manufacturing_zip" "$final_cpl_tampered_package" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import zipfile

source, destination = map(Path, sys.argv[1:])
with zipfile.ZipFile(source) as archive:
    members = {item.filename: archive.read(item) for item in archive.infolist()}

cpl = members["cpl.csv"]
match = re.search(rb"(?m)^([^,\r\n]+),(-?[0-9]+\.[0-9]{6}),", cpl)
if match is None:
    raise SystemExit("real manufacturing CPL has no canonical placement row")
coordinate = bytearray(match.group(2))
coordinate[-1] = ord("1") if coordinate[-1] != ord("1") else ord("2")
members["cpl.csv"] = cpl[:match.start(2)] + bytes(coordinate) + cpl[match.end(2):]
assert len(members["cpl.csv"]) == len(cpl)

manifest = json.loads(members["manifest.json"].decode("utf-8"))
cpl_artifacts = [
    artifact for artifact in manifest["artifacts"] if artifact["path"] == "cpl.csv"
]
assert len(cpl_artifacts) == 1
cpl_artifacts[0]["bytes"] = len(members["cpl.csv"])
cpl_artifacts[0]["sha256"] = hashlib.sha256(members["cpl.csv"]).hexdigest()
members["manifest.json"] = (
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
).encode("utf-8")

with zipfile.ZipFile(
    destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6
) as archive:
    for name in sorted(members):
        item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        item.compress_type = zipfile.ZIP_DEFLATED
        item.create_system = 3
        item.external_attr = (stat.S_IFREG | 0o644) << 16
        item.extra = b""
        item.comment = b""
        archive.writestr(
            item,
            members[name],
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        )
PY
"$pcbex_binary" verify-final-cpl \
  "$upgraded_multilayer" "$final_cpl_tampered_package" \
  --output "$final_cpl_tampered_report"
if "$pcbex_binary" verify-final-cpl \
  "$upgraded_multilayer" "$final_cpl_tampered_package" \
  --output "$final_cpl_tampered_gated_report" \
  --require-approved \
  2>"$final_cpl_tampered_error"; then
  echo "expected exact final-CPL gate to reject a canonical placement mismatch" >&2
  exit 1
fi
python3 - \
  "$upgraded_multilayer" \
  "$final_cpl_tampered_package" \
  "$final_cpl_tampered_report" \
  "$final_cpl_tampered_gated_report" \
  "$final_cpl_tampered_error" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import zipfile

board_path, package_path, report_path, gated_path, error_path = map(
    Path, sys.argv[1:]
)

def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

report = json.loads(report_path.read_text(encoding="utf-8"))
gated = json.loads(gated_path.read_text(encoding="utf-8"))
assert gated == report
assert error_path.read_bytes()
assert report["approved"] is False
assert report["findings"] == [{
    "code": "canonical_cpl_mismatch",
    "message": (
        "manufacturing package cpl.csv does not equal the canonical CPL "
        "regenerated from the board"
    ),
}]
board = board_path.read_bytes()
package = package_path.read_bytes()
with zipfile.ZipFile(package_path) as archive:
    cpl = archive.read("cpl.csv")
assert report["sources"]["board"] == identity(board)
assert report["sources"]["package_board_source"] == identity(board)
assert report["sources"]["manufacturing_package"] == identity(package)
assert report["sources"]["cpl"] == identity(cpl)
assert report["sources"]["canonical_cpl"] != identity(cpl)
assert report["counts"]["findings"] == 1
assert report["counts"]["board_in_pos_parts"] == 2
assert report["counts"]["package_placement_parts"] == 2
PY
manufacturing_replay_result="$output_directory/multilayer.manufacturing.replay.json"
PYTHONPATH=agent/src python3 -m pcbex_agent replay-manufacturing-package \
  "$upgraded_multilayer" "$retained_manufacturing_zip" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --timeout-seconds 180 \
  >"$manufacturing_replay_result"
retained_manufacturing_sha_after_success="$(sha256sum "$retained_manufacturing_zip" | awk '{print $1}')"
retained_manufacturing_bytes_after_success="$(wc -c <"$retained_manufacturing_zip" | tr -d '[:space:]')"
test "$retained_manufacturing_sha_after_success" = "$retained_manufacturing_sha_before"
test "$retained_manufacturing_bytes_after_success" = "$retained_manufacturing_bytes_before"
python3 - "$manufacturing_replay_result" "$retained_manufacturing_zip" "$upgraded_multilayer" "$output_directory" <<'PY'
import hashlib
import json
from pathlib import Path
from pathlib import PureWindowsPath
import sys

result_path, retained_path, board_path, output_directory = map(Path, sys.argv[1:])
result = json.loads(result_path.read_text(encoding="utf-8"))
assert set(result) == {
    "schema_version", "verification_scope", "verified", "board", "project",
    "rules", "profile", "package", "validation",
}
assert result["schema_version"] == 1
assert result["verification_scope"] == "manufacturing-package-fresh-replay-v1"
assert result["verified"] is True
board = board_path.read_bytes()
assert result["board"] == {
    "name": board_path.name,
    "bytes": len(board),
    "sha256": hashlib.sha256(board).hexdigest(),
}
assert result["project"] is None
assert result["rules"] is None
assert result["profile"] == {"kind": "none"}
retained = retained_path.read_bytes()
retained_identity = {
    "bytes": len(retained),
    "sha256": hashlib.sha256(retained).hexdigest(),
}
assert result["package"] == {
    "retained": retained_identity,
    "fresh": retained_identity,
    "identical": True,
}
assert result["validation"] == {
    "inputs_captured": True,
    "package_reproduced": True,
    "staged_inputs_unchanged": True,
    "caller_inputs_unchanged": True,
}

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(result)
PY



# Compose the retained manufacturing ZIP with an exact circuit-handoff replay
# and the same upgraded board. The board intentionally need not be approved by
# this unrelated sample circuit: v6 reproduces the retained board-binding
# decision, then proves the manufacturing package was freshly reproduced from
# those exact board bytes without turning verification into authorization.
composed_requirements="$output_directory/multilayer.composed.requirements.txt"
composed_generation="$output_directory/multilayer.composed.generation.json"
composed_handoff_zip="$output_directory/multilayer.composed.handoff.zip"
composed_handoff_extract="$output_directory/multilayer.composed.handoff"
composed_handoff_log="$output_directory/multilayer.composed.handoff.log"
composed_extract_result="$output_directory/multilayer.composed.extract.json"
composed_board_binding_report="$output_directory/multilayer.composed.board-binding.json"
composed_replay_result="$output_directory/multilayer.composed.replay.json"
printf '%s\n' 'Generate the deterministic circuit-spec-v2 example.' \
  >"$composed_requirements"
PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  "$composed_requirements" \
  --output "$composed_generation" \
  --pcbex "$pcbex_binary" \
  --max-attempts 1 \
  --timeout-seconds 120 \
  --provider-command python3 -c \
  'import sys; from pathlib import Path; sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())' \
  examples/circuit-spec-v2.json
PYTHONPATH=agent/src python3 -m pcbex_agent handoff-circuit \
  "$composed_generation" \
  --output "$composed_handoff_zip" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 120 \
  >"$composed_handoff_log"
PYTHONPATH=agent/src python3 -m pcbex_agent extract-circuit-handoff-bundle \
  "$composed_handoff_zip" \
  --output-dir "$composed_handoff_extract" \
  >"$composed_extract_result"
"$pcbex_binary" verify-circuit-kicad-board-binding \
  "$composed_handoff_extract/circuit-spec-v2.json" \
  "$composed_handoff_extract/circuit-spec.kicad_sch" \
  "$upgraded_multilayer" \
  --output "$composed_board_binding_report"
PYTHONPATH=agent/src python3 -m pcbex_agent replay-circuit-handoff-bundle \
  "$composed_handoff_zip" \
  --pcbex "$pcbex_binary" \
  --kicad-board "$upgraded_multilayer" \
  --board-binding-report "$composed_board_binding_report" \
  --manufacturing-package "$retained_manufacturing_zip" \
  --manufacturing-kicad-cli "$kicad_cli_binary" \
  --timeout-seconds 300 \
  >"$composed_replay_result"
retained_manufacturing_sha_after_composition="$(sha256sum "$retained_manufacturing_zip" | awk '{print $1}')"
retained_manufacturing_bytes_after_composition="$(wc -c <"$retained_manufacturing_zip" | tr -d '[:space:]')"
test "$retained_manufacturing_sha_after_composition" = "$retained_manufacturing_sha_before"
test "$retained_manufacturing_bytes_after_composition" = "$retained_manufacturing_bytes_before"
python3 - \
  "$composed_replay_result" \
  "$composed_board_binding_report" \
  "$retained_manufacturing_zip" \
  "$upgraded_multilayer" \
  "$output_directory" <<'PY'
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys

result_path, binding_path, package_path, board_path, output_directory = map(
    Path, sys.argv[1:]
)
result = json.loads(result_path.read_text(encoding="utf-8"))
binding = json.loads(binding_path.read_text(encoding="utf-8"))
board = board_path.read_bytes()
board_identity = {
    "bytes": len(board),
    "sha256": hashlib.sha256(board).hexdigest(),
}
package = package_path.read_bytes()
package_identity = {
    "bytes": len(package),
    "sha256": hashlib.sha256(package).hexdigest(),
}

assert result["schema_version"] == 6
assert result["verification_scope"] == (
    "deterministic-electrical-handoff-chain-manufacturing-package-replay-v6"
)
assert result["verified"] is True
assert result["validation"]["board_binding_replayed"] is True
assert result["validation"]["manufacturing_package_replayed"] is True
assert result["validation"]["manufacturing_board_identity_matched"] is True
assert binding["approved"] is False
assert result["board_binding"]["approved"] is binding["approved"]
assert result["board_binding"]["approval_required"] is False
assert result["board_binding"]["board"] == board_identity
manufacturing = result["manufacturing_package"]
assert manufacturing["schema_version"] == 1
assert manufacturing["verification_scope"] == "manufacturing-package-fresh-replay-v1"
assert manufacturing["verified"] is True
assert manufacturing["board"] == {"name": board_path.name, **board_identity}
assert manufacturing["package"] == {
    "retained": package_identity,
    "fresh": package_identity,
    "identical": True,
}
assert manufacturing["validation"] == {
    "inputs_captured": True,
    "package_reproduced": True,
    "staged_inputs_unchanged": True,
    "caller_inputs_unchanged": True,
}

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(result)
PY

# Bind the same real v6 chain to a freshly retained deterministic-pipeline
# report. Seed the non-shared analysis/firmware inputs from the existing real
# CI fixture, replace every shared artifact with this exact handoff/board/ZIP,
# then compile and run a fresh plan. The supplied review and derived analysis
# intentionally describe the seed design, so the exact report is rejected;
# v7 must preserve that truthful decision while cross-binding all shared bytes
# and the complete nested board-binding report.
pipeline_seed="$output_directory/multilayer.composed.pipeline-seed"
pipeline_seed_summary="$output_directory/multilayer.composed.pipeline-seed.json"
pipeline_case="$output_directory/multilayer.composed.pipeline"
pipeline_plan="$pipeline_case/plan.json"
pipeline_report="$pipeline_case/report.json"
pipeline_replay_result="$output_directory/multilayer.composed.pipeline-replay.json"
python3 scripts/deterministic_pipeline_ci.py \
  --pcbex "$pcbex_binary" \
  --fixture-dir crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci \
  --output-dir "$pipeline_seed" \
  --timeout-seconds 300 \
  >"$pipeline_seed_summary"
mkdir "$pipeline_case"
cp "$pipeline_seed/accepted/intent.json" "$pipeline_case/intent.json"
cp "$pipeline_seed/accepted/electrical-policy.json" \
  "$pipeline_case/electrical-policy.json"
cp "$pipeline_seed/accepted/electrical-review.json" \
  "$pipeline_case/electrical-review.json"
cp -R "$pipeline_seed/accepted/analysis" "$pipeline_case/analysis"
cp -R "$pipeline_seed/accepted/firmware" "$pipeline_case/firmware"
cp "$composed_handoff_extract/circuit-spec-v2.json" \
  "$pipeline_case/circuit-spec-v2.json"
cp "$composed_handoff_extract/circuit-spec.kicad_sch" \
  "$pipeline_case/design.kicad_sch"
cp "$upgraded_multilayer" "$pipeline_case/design.kicad_pcb"
cp "$retained_manufacturing_zip" "$pipeline_case/manufacturing.zip"
(
  cd "$pipeline_case"
  "$pcbex_binary" compile-deterministic-pipeline-plan \
    intent.json --output plan.json
  "$pcbex_binary" run-deterministic-pipeline \
    plan.json --output report.json
)
pipeline_report_sha_before="$(sha256sum "$pipeline_report" | awk '{print $1}')"
pipeline_report_bytes_before="$(wc -c <"$pipeline_report" | tr -d '[:space:]')"
PYTHONPATH=agent/src python3 -m pcbex_agent replay-circuit-handoff-bundle \
  "$composed_handoff_zip" \
  --pcbex "$pcbex_binary" \
  --kicad-board "$upgraded_multilayer" \
  --board-binding-report "$composed_board_binding_report" \
  --manufacturing-package "$retained_manufacturing_zip" \
  --manufacturing-kicad-cli "$kicad_cli_binary" \
  --deterministic-pipeline-plan "$pipeline_plan" \
  --deterministic-pipeline-report "$pipeline_report" \
  --timeout-seconds 480 \
  >"$pipeline_replay_result"
test "$(sha256sum "$pipeline_report" | awk '{print $1}')" = \
  "$pipeline_report_sha_before"
test "$(wc -c <"$pipeline_report" | tr -d '[:space:]')" = \
  "$pipeline_report_bytes_before"
python3 - \
  "$pipeline_replay_result" \
  "$pipeline_plan" \
  "$pipeline_report" \
  "$composed_board_binding_report" \
  "$retained_manufacturing_zip" \
  "$upgraded_multilayer" \
  "$output_directory" <<'PY'
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys

(
    result_path,
    plan_path,
    report_path,
    binding_path,
    package_path,
    board_path,
    output_directory,
) = map(Path, sys.argv[1:])

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

result = json.loads(result_path.read_text(encoding="utf-8"))
plan = json.loads(plan_path.read_text(encoding="utf-8"))
report = json.loads(report_path.read_text(encoding="utf-8"))
binding = json.loads(binding_path.read_text(encoding="utf-8"))

assert result["schema_version"] == 7
assert result["verification_scope"] == (
    "deterministic-electrical-handoff-chain-manufacturing-pipeline-replay-v7"
)
assert result["verified"] is True
for flag in (
    "deterministic_pipeline_replayed",
    "pipeline_circuit_spec_matched",
    "pipeline_schematic_matched",
    "pipeline_effective_policy_matched",
    "pipeline_board_matched",
    "pipeline_manufacturing_package_matched",
    "pipeline_board_binding_matched",
):
    assert result["validation"][flag] is True

pipeline = result["deterministic_pipeline"]
assert pipeline["schema_version"] == 1
assert pipeline["verification_scope"] == "deterministic-pipeline-fresh-replay-v1"
assert pipeline["verified"] is True
assert pipeline["plan"]["source"] == identity(plan_path)
assert pipeline["report"]["retained"] == identity(report_path)
assert pipeline["report"]["fresh"] == identity(report_path)
assert pipeline["report"]["identical"] is True
assert pipeline["report"]["approved"] is False
assert report["approved"] is False
assert report["binding"] == binding
assert result["board_binding"]["report"] == identity(binding_path)
assert result["board_binding"]["board"] == identity(board_path)
assert result["manufacturing_package"]["package"] == {
    "retained": identity(package_path),
    "fresh": identity(package_path),
    "identical": True,
}

case_root = plan_path.parent
for role, expected in (
    ("circuit_spec", "circuit-spec-v2.json"),
    ("schematic", "design.kicad_sch"),
    ("board", "design.kicad_pcb"),
    ("manufacturing_package", "manufacturing.zip"),
):
    descriptor = plan[role]
    source = case_root / descriptor["path"]
    assert source.name == expected
    assert {"bytes": descriptor["bytes"], "sha256": descriptor["sha256"]} == identity(source)

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(result)
PY

# A one-byte change in a retained ZIP must fail closed. Mutate compressed
# member data in place so ZIP structure and the retained path remain
# unchanged; fresh regeneration must then reject it at exact package
# comparison, rather than treating the retained bytes as pre-approved.
manufacturing_tampered_zip="$output_directory/multilayer.manufacturing.tampered.zip"
manufacturing_tampered_result="$output_directory/multilayer.manufacturing.tampered.result.json"
manufacturing_tampered_error="$output_directory/multilayer.manufacturing.tampered.stderr"
cp "$retained_manufacturing_zip" "$manufacturing_tampered_zip"
python3 - "$manufacturing_tampered_zip" <<'PY'
from pathlib import Path
import struct
import sys
import zipfile

path = Path(sys.argv[1])
raw = bytearray(path.read_bytes())
with zipfile.ZipFile(path) as archive:
    info = next(
        (item for item in archive.infolist() if item.compress_size > 0),
        None,
    )
    if info is None:
        raise SystemExit("manufacturing ZIP has no non-empty member to tamper")
    name_length, extra_length = struct.unpack_from("<HH", raw, info.header_offset + 26)
    payload_start = info.header_offset + 30 + name_length + extra_length
    payload_offset = payload_start + min(info.compress_size - 1, info.compress_size // 2)
    if payload_offset >= len(raw):
        raise SystemExit("manufacturing ZIP member offset is invalid")
raw[payload_offset] ^= 1
path.write_bytes(raw)
PY
if PYTHONPATH=agent/src python3 -m pcbex_agent replay-manufacturing-package \
  "$upgraded_multilayer" "$manufacturing_tampered_zip" \
  --pcbex "$pcbex_binary" \
  --kicad-cli "$kicad_cli_binary" \
  --timeout-seconds 180 \
  >"$manufacturing_tampered_result" \
  2>"$manufacturing_tampered_error"; then
  echo "expected manufacturing package replay rejection for one-byte ZIP tamper" >&2
  exit 1
fi
retained_manufacturing_sha_after_tamper="$(sha256sum "$retained_manufacturing_zip" | awk '{print $1}')"
retained_manufacturing_bytes_after_tamper="$(wc -c <"$retained_manufacturing_zip" | tr -d '[:space:]')"
test "$retained_manufacturing_sha_after_tamper" = "$retained_manufacturing_sha_before"
test "$retained_manufacturing_bytes_after_tamper" = "$retained_manufacturing_bytes_before"
python3 - "$manufacturing_tampered_result" "$manufacturing_tampered_error" <<'PY'
from pathlib import Path
import sys

result = Path(sys.argv[1])
error = Path(sys.argv[2])
assert error.read_bytes(), "tampered manufacturing replay produced no diagnostic"
assert not result.read_bytes(), "tampered manufacturing replay unexpectedly emitted success JSON"
PY

# v1.463 closes the circuit/schematic-to-board producer gap. Build the small
# checked-in two-part circuit twice, require byte-identical three-file bundles,
# then pass its placed-but-unrouted board through the existing autorouter and
# KiCad's native PCB parser. The embedded footprints deliberately do not
# resolve host libraries, so the native report retains exactly those warnings
# rather than claiming a clean DRC result.
board_writer_schematic="$output_directory/circuit-board-writer.generated.kicad_sch"
board_writer_first="$output_directory/circuit-board-writer.first"
board_writer_second="$output_directory/circuit-board-writer.second"
board_writer_routed="$output_directory/circuit-board-writer.routed.kicad_pcb"
board_writer_routed_drc="$output_directory/circuit-board-writer.routed.drc"
"$pcbex_binary" write-circuit-spec-kicad-schematic \
  examples/circuit-board-spec-v2.json \
  --output "$board_writer_schematic"
for bundle in "$board_writer_first" "$board_writer_second"; do
  "$pcbex_binary" generate-circuit-kicad-board \
    examples/circuit-board-spec-v2.json "$board_writer_schematic" \
    --footprint-closure examples/circuit-board-footprint-closure-v1.json \
    --construction-profile examples/circuit-board-construction-profile-v1.json \
    --physical-profile examples/circuit-board-physical-profile-v1.json \
    --output-dir "$bundle"
  test "$(find "$bundle" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 3
  test "$(find "$bundle" -mindepth 1 -maxdepth 1 | wc -l)" -eq 3
  jq -e '.approved == true and .counts.errors == 0' \
    "$bundle/board-binding.json" >/dev/null
  jq -e '
    .approved == true and
    .board_state == "placed_but_unrouted" and
    .routing_performed == false and
    .drc_claimed == false and
    .dfm_claimed == false
  ' "$bundle/manifest.json" >/dev/null
done
for artifact in board.kicad_pcb board-binding.json manifest.json; do
  cmp "$board_writer_first/$artifact" "$board_writer_second/$artifact"
done
"$pcbex_binary" route-kicad "$board_writer_first/board.kicad_pcb" \
  --physical-profile examples/circuit-board-physical-profile-v1.json \
  --grid-mm 0.1 --width-mm 0.25 --clearance-mm 0.2 \
  --via-diameter-mm 0.66 --via-drill-mm 0.3 \
  --bend-cost 5 --via-cost 50 \
  --output "$board_writer_routed"
test -s "$board_writer_routed"
"$kicad_cli_binary" pcb drc "$board_writer_routed" \
  --output "$board_writer_routed_drc"
test -s "$board_writer_routed_drc"

# Exercise the legacy layer-table ordinals that KiCad 10 uses for a four-layer
# board. The profile stays at the same total thickness and changes only its
# exact alternating stackup.
board_writer_four_layer_profile="$output_directory/circuit-board-writer.four-layer.json"
board_writer_four_layer="$output_directory/circuit-board-writer.four-layer"
board_writer_four_layer_drc="$output_directory/circuit-board-writer.four-layer.drc"
python3 - \
  examples/circuit-board-construction-profile-v1.json \
  "$board_writer_four_layer_profile" <<'PY'
import json
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
profile = json.loads(source.read_text(encoding="utf-8"))
profile["id"] = "pcbex-four-layer-fr4-v1"
profile["stackup"] = [
    {"kind": "copper", "layer": "F.Cu", "thickness_nm": 35000},
    {"kind": "dielectric", "material": "FR4", "thickness_nm": 400000,
     "dielectric_constant_millionths": 4100000},
    {"kind": "copper", "layer": "In1.Cu", "thickness_nm": 35000},
    {"kind": "dielectric", "material": "FR4", "thickness_nm": 660000,
     "dielectric_constant_millionths": 4100000},
    {"kind": "copper", "layer": "In2.Cu", "thickness_nm": 35000},
    {"kind": "dielectric", "material": "FR4", "thickness_nm": 400000,
     "dielectric_constant_millionths": 4100000},
    {"kind": "copper", "layer": "B.Cu", "thickness_nm": 35000},
]
destination.write_text(
    json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
"$pcbex_binary" generate-circuit-kicad-board \
  examples/circuit-board-spec-v2.json "$board_writer_schematic" \
  --footprint-closure examples/circuit-board-footprint-closure-v1.json \
  --construction-profile "$board_writer_four_layer_profile" \
  --physical-profile examples/circuit-board-physical-profile-v1.json \
  --output-dir "$board_writer_four_layer"
grep -F '(2 "In1.Cu" signal)' "$board_writer_four_layer/board.kicad_pcb" >/dev/null
grep -F '(4 "In2.Cu" signal)' "$board_writer_four_layer/board.kicad_pcb" >/dev/null
"$kicad_cli_binary" pcb drc "$board_writer_four_layer/board.kicad_pcb" \
  --output "$board_writer_four_layer_drc"
test -s "$board_writer_four_layer_drc"
python3 - \
  "$board_writer_routed_drc" 0 \
  "$board_writer_four_layer_drc" 2 <<'PY'
from pathlib import Path
import sys

arguments = sys.argv[1:]
assert len(arguments) % 2 == 0
for offset in range(0, len(arguments), 2):
    report = Path(arguments[offset]).read_text(encoding="utf-8")
    expected_unconnected = int(arguments[offset + 1])
    categories = [
        line.split("]", 1)[0] + "]"
        for line in report.splitlines()
        if line.startswith("[")
    ]
    assert categories.count("[lib_footprint_issues]") == 2, categories
    assert categories.count("[unconnected_items]") == expected_unconnected, categories
    assert set(categories) <= {"[lib_footprint_issues]", "[unconnected_items]"}, categories
    assert "footprint library 'Resistor_SMD'" in report
    assert "footprint library 'Package'" in report
    assert "** Found 2 DRC violations **" in report
    assert f"** Found {expected_unconnected} unconnected pads **" in report
    assert "** Found 0 Footprint errors **" in report
PY

# v1.464 composes the real retained manufacturing ZIP with a fully replayed
# historical catalog selection.  The unrelated catalog circuit is
# intentionally a semantic mismatch: the Rust final-BOM verifier must approve
# the exact upgraded board/package bytes, while the outer procurement intent
# retains a rejected, empty-line-item artifact instead of presenting a partial
# order list.  This is a cross-language canonical-BOM/catalog bridge test, not
# a procurement authorization or live-supplier test.
procurement_snapshot="$output_directory/procurement.catalog-snapshot.json"
procurement_requirements="$output_directory/procurement.requirements.txt"
procurement_generation="$output_directory/procurement.generation.json"
procurement_intent="$output_directory/procurement.intent.json"
procurement_gated_intent="$output_directory/procurement.gated.intent.json"
procurement_gated_error="$output_directory/procurement.gated.stderr"
python3 - examples/catalog-snapshot-v1.json "$procurement_snapshot" <<'PY'
import json
from pathlib import Path
import sys
import time

source, destination = map(Path, sys.argv[1:])
snapshot = json.loads(source.read_text(encoding="utf-8"))
now = int(time.time())
snapshot["snapshot_id"] = "kicad-e2e-v1464"
snapshot["captured_at_unix"] = now - 60
snapshot["expires_at_unix"] = now + 3600
destination.write_text(
    json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
printf '%s\n' 'Generate the catalog-backed circuit-spec-v2 example.' \
  >"$procurement_requirements"
PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  "$procurement_requirements" \
  --output "$procurement_generation" \
  --pcbex "$pcbex_binary" \
  --max-attempts 1 \
  --timeout-seconds 120 \
  --catalog-snapshot "$procurement_snapshot" \
  --allow-footprint-fallback \
  --provider-command python3 -c \
  'import sys; from pathlib import Path; sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())' \
  examples/circuit-spec-v2.json
PYTHONPATH=agent/src python3 -m pcbex_agent build-procurement-intent \
  "$upgraded_multilayer" "$retained_manufacturing_zip" \
  --circuit-generation "$procurement_generation" \
  --catalog-snapshot "$procurement_snapshot" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 180 \
  --output "$procurement_intent"
if PYTHONPATH=agent/src python3 -m pcbex_agent build-procurement-intent \
  "$upgraded_multilayer" "$retained_manufacturing_zip" \
  --circuit-generation "$procurement_generation" \
  --catalog-snapshot "$procurement_snapshot" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 180 \
  --output "$procurement_gated_intent" \
  --require-approved \
  2>"$procurement_gated_error"; then
  echo "expected catalog/final-BOM reference mismatch to fail the final gate" >&2
  exit 1
fi
python3 - \
  "$procurement_intent" \
  "$procurement_gated_intent" \
  "$procurement_gated_error" \
  "$upgraded_multilayer" \
  "$retained_manufacturing_zip" \
  "$procurement_generation" \
  "$procurement_snapshot" \
  "$output_directory" <<'PY'
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys

(
    intent_path,
    gated_path,
    gated_error_path,
    board_path,
    package_path,
    generation_path,
    snapshot_path,
    output_directory,
) = map(Path, sys.argv[1:])

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

intent = json.loads(intent_path.read_text(encoding="utf-8"))
gated = json.loads(gated_path.read_text(encoding="utf-8"))
assert gated == intent
assert gated_error_path.read_bytes()
assert intent["schema_version"] == 1
assert intent["scope"] == "offline-final-bom-catalog-selection-intent-v1"
assert intent["status"] == "rejected"
assert intent["approved"] is False
assert intent["procurement_authorized"] is False
assert intent["network_performed"] is False
assert intent["order_placed"] is False
assert intent["current_availability_verified"] is False
assert intent["supplier_authenticity_verified"] is False
assert intent["quantity_basis"] == "per_board"
assert intent["line_items"] == []
assert intent["validation"]["final_bom_verified"] is True
assert intent["validation"]["catalog_selection_replayed"] is True
assert intent["validation"]["reference_sets_matched"] is False
assert "reference_set_mismatch" in {
    finding["code"] for finding in intent["findings"]
}
assert intent["sources"]["board"] == {
    "name": board_path.name,
    **identity(board_path),
}
assert intent["sources"]["manufacturing_package"] == identity(package_path)
assert intent["sources"]["generation_bundle"] == identity(generation_path)
assert intent["sources"]["catalog_snapshot"] == identity(snapshot_path)
assert intent["sources"]["bom"] == intent["sources"]["canonical_bom"]
assert intent["sources"]["package_board_source"] == identity(board_path)

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(intent)
PY

# v1.467 closes the exact per-board composition gap. Describe the two populated
# terminals of the real multilayer fixture as a catalog-backed circuit, remove
# its two routing-only obstacle footprints after routing, and require the real
# handoff, approved board binding, manufacturing package, procurement intent,
# and CPL to reproduce and cross-bind as one complete result. The snapshot is
# retained historical fixture data; this starts no supplier request and grants
# no assembly, fabrication, procurement, or order authority.
assembly_snapshot="$output_directory/assembly.catalog-snapshot.json"
assembly_spec="$output_directory/assembly.circuit-spec-v2.json"
assembly_requirements="$output_directory/assembly.requirements.txt"
assembly_generation="$output_directory/assembly.generation.json"
assembly_handoff_zip="$output_directory/assembly.handoff.zip"
assembly_handoff_extract="$output_directory/assembly.handoff"
assembly_handoff_log="$output_directory/assembly.handoff.log"
assembly_extract_result="$output_directory/assembly.extract.json"
assembly_board_with_obstacles="$output_directory/assembly.routed.with-obstacles.kicad_pcb"
assembly_board="$output_directory/assembly.routed.kicad_pcb"
assembly_board_binding="$output_directory/assembly.board-binding.json"
assembly_manufacturing_directory="$output_directory/assembly.manufacturing"
assembly_manufacturing_zip="$assembly_manufacturing_directory/manufacturing.zip"
assembly_procurement="$output_directory/assembly.procurement.json"
assembly_final_cpl="$output_directory/assembly.final-cpl.json"
assembly_evidence="$output_directory/assembly.evidence.json"
assembly_schema="$output_directory/assembly-evidence.schema.json"
python3 - "$assembly_snapshot" "$assembly_spec" <<'PY'
import json
from pathlib import Path
import sys
import time

snapshot_path, spec_path = map(Path, sys.argv[1:])
now = int(time.time())
snapshot = {
    "schema_version": 1,
    "supplier": "pcbex-kicad-e2e",
    "snapshot_id": "assembly-complete-v1467",
    "captured_at_unix": now - 60,
    "expires_at_unix": now + 3600,
    "parts": [
        {
            "mpn": "C-LIVE-1",
            "supplier_part_number": "PCBEX-C1001",
            "description": "TEST_POINT terminal fixture",
            "footprint": "terminal",
            "tags": ["test", "point", "terminal"],
            "vendor": "pcbex fixture",
            "stock": 100,
            "basic": True,
            "datasheet_url": None,
        },
    ],
}
spec = {
    "schema_version": 2,
    "parts": [
        {
            "reference": reference,
            "lib_id": "Connector:TestPoint",
            "value": "TEST_POINT",
            "footprint": "terminal",
            "mpn": None,
            "power": {
                "rail_voltage_uv": None,
                "max_voltage_uv": None,
                "requires_decoupling": False,
                "decoupling": False,
            },
            "pins": [
                {
                    "number": "1",
                    "name": "1",
                    "net": "SIGNAL",
                    "electrical_type": "passive",
                }
            ],
        }
        for reference in ("J1", "J2")
    ],
    "nets": [
        {
            "name": "SIGNAL",
            "voltage_uv": None,
            "connections": [
                {"reference": "J1", "pin": "1"},
                {"reference": "J2", "pin": "1"},
            ],
        }
    ],
}
snapshot_path.write_text(
    json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
spec_path.write_text(
    json.dumps(spec, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
printf '%s\n' 'Generate the catalog-backed multilayer terminal fixture.' \
  >"$assembly_requirements"
PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  "$assembly_requirements" \
  --output "$assembly_generation" \
  --pcbex "$pcbex_binary" \
  --max-attempts 1 \
  --timeout-seconds 120 \
  --catalog-snapshot "$assembly_snapshot" \
  --allow-footprint-fallback \
  --provider-command python3 -c \
  'import sys; from pathlib import Path; sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())' \
  "$assembly_spec"
PYTHONPATH=agent/src python3 -m pcbex_agent handoff-circuit \
  "$assembly_generation" \
  --output "$assembly_handoff_zip" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 120 \
  >"$assembly_handoff_log"
PYTHONPATH=agent/src python3 -m pcbex_agent extract-circuit-handoff-bundle \
  "$assembly_handoff_zip" \
  --output-dir "$assembly_handoff_extract" \
  >"$assembly_extract_result"
"$pcbex_binary" route-kicad examples/multilayer.kicad_pcb \
  --output "$assembly_board_with_obstacles" \
  --drc
python3 - "$assembly_board_with_obstacles" "$assembly_board" <<'PY'
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
text = source.read_text(encoding="utf-8")

def remove_form(value, marker):
    start = value.find(marker)
    if start < 0:
        raise SystemExit(f"missing routing-only fixture form: {marker}")
    depth = 0
    quoted = False
    escaped = False
    for index in range(start, len(value)):
        character = value[index]
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return value[:start] + value[index + 1:]
    raise SystemExit(f"unterminated routing-only fixture form: {marker}")

for name in ("front-obstacle", "back-obstacle"):
    text = remove_form(text, f'(footprint "{name}"')
destination.write_text(text, encoding="utf-8")
PY
kicad-cli pcb upgrade --force "$assembly_board"
"$pcbex_binary" verify-circuit-kicad-board-binding \
  "$assembly_handoff_extract/circuit-spec-v2.json" \
  "$assembly_handoff_extract/circuit-spec.kicad_sch" \
  "$assembly_board" \
  --output "$assembly_board_binding" \
  --require-approved
mkdir "$assembly_manufacturing_directory"
"$pcbex_binary" fabricate "$assembly_board" \
  --output-dir "$assembly_manufacturing_directory"
"$pcbex_binary" verify-final-cpl \
  "$assembly_board" "$assembly_manufacturing_zip" \
  --output "$assembly_final_cpl" \
  --require-approved
PYTHONPATH=agent/src python3 -m pcbex_agent build-procurement-intent \
  "$assembly_board" "$assembly_manufacturing_zip" \
  --circuit-generation "$assembly_generation" \
  --catalog-snapshot "$assembly_snapshot" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 180 \
  --output "$assembly_procurement" \
  --require-approved
PYTHONPATH=agent/src python3 -m pcbex_agent build-assembly-evidence \
  "$assembly_handoff_zip" "$assembly_board" "$assembly_manufacturing_zip" \
  --board-binding-report "$assembly_board_binding" \
  --procurement-intent "$assembly_procurement" \
  --catalog-snapshot "$assembly_snapshot" \
  --final-cpl-report "$assembly_final_cpl" \
  --pcbex "$pcbex_binary" \
  --manufacturing-kicad-cli "$kicad_cli_binary" \
  --timeout-seconds 600 \
  --output "$assembly_evidence" \
  --require-complete
PYTHONPATH=agent/src python3 -m pcbex_agent assembly-evidence-schema \
  --output "$assembly_schema"
python3 - \
  "$assembly_evidence" \
  "$assembly_schema" \
  "$assembly_board" \
  "$assembly_manufacturing_zip" \
  "$assembly_generation" \
  "$assembly_snapshot" \
  "$output_directory" <<'PY'
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys

(
    result_path,
    schema_path,
    board_path,
    package_path,
    generation_path,
    snapshot_path,
    output_directory,
) = map(Path, sys.argv[1:])

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

result = json.loads(result_path.read_text(encoding="utf-8"))
schema = json.loads(schema_path.read_text(encoding="utf-8"))
assert set(result) == {
    "schema_version", "scope", "status", "complete", "quantity_basis",
    "assembly_ready", "assembly_authorized", "fabrication_authorized",
    "procurement_authorized", "order_placed", "adapter_network_performed",
    "machine_operation_performed", "sources", "circuit_manufacturing",
    "final_bom", "procurement", "final_cpl", "membership", "findings",
    "validation", "binding_sha256",
}
assert result["schema_version"] == 1
assert result["scope"] == "offline-exact-board-assembly-evidence-v1"
assert result["status"] == "complete"
assert result["complete"] is True
assert result["quantity_basis"] == "per_board"
for field in (
    "assembly_ready", "assembly_authorized", "fabrication_authorized",
    "procurement_authorized", "order_placed", "adapter_network_performed",
    "machine_operation_performed",
):
    assert result[field] is False, field
assert result["circuit_manufacturing"]["schema_version"] == 6
assert result["circuit_manufacturing"]["verified"] is True
assert result["circuit_manufacturing"]["board_binding"]["approved"] is True
assert result["procurement"]["approved"] is True
assert result["final_bom"]["approved"] is True
assert result["final_cpl"]["approved"] is True
assert "in_bom_parts" not in result["final_bom"]
assert "final_bom" not in result["procurement"]
assert "binding_sha256" not in result["procurement"]
assert result["membership"]["both"] == ["J1", "J2"]
assert result["membership"]["bom_only"] == []
assert result["membership"]["cpl_only"] == []
assert result["findings"] == []
assert all(result["validation"].values())
assert result["sources"]["board"] == {
    "name": board_path.name,
    **identity(board_path),
}
assert result["sources"]["manufacturing_package"] == identity(package_path)
assert result["sources"]["handoff_generation_bundle"] == identity(generation_path)
assert result["sources"]["catalog_snapshot"] == identity(snapshot_path)
assert schema["$id"].endswith(
    "/schemas/offline-exact-board-assembly-evidence-v1.json"
)
assert schema["additionalProperties"] is False
assert schema["properties"]["scope"] == {
    "const": "offline-exact-board-assembly-evidence-v1"
}
assert schema["properties"]["assembly_ready"] == {"const": False}

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(result)
PY

# Repeat the same exact board/package/CPL composition with a historical catalog
# selection that truthfully has no supplier part number. Handoff, board binding,
# final BOM, and final CPL remain positive; only procurement is rejected with no
# partial line items. --require-complete must retain that exact incomplete result
# before returning nonzero.
assembly_incomplete_snapshot="$output_directory/assembly.incomplete.catalog-snapshot.json"
assembly_incomplete_generation="$output_directory/assembly.incomplete.generation.json"
assembly_incomplete_handoff="$output_directory/assembly.incomplete.handoff.zip"
assembly_incomplete_extract="$output_directory/assembly.incomplete.handoff"
assembly_incomplete_handoff_log="$output_directory/assembly.incomplete.handoff.log"
assembly_incomplete_extract_result="$output_directory/assembly.incomplete.extract.json"
assembly_incomplete_binding="$output_directory/assembly.incomplete.board-binding.json"
assembly_incomplete_procurement="$output_directory/assembly.incomplete.procurement.json"
assembly_incomplete_evidence="$output_directory/assembly.incomplete.evidence.json"
assembly_incomplete_error="$output_directory/assembly.incomplete.stderr"
python3 - "$assembly_snapshot" "$assembly_incomplete_snapshot" <<'PY'
import json
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
snapshot = json.loads(source.read_text(encoding="utf-8"))
snapshot["snapshot_id"] = "assembly-incomplete-v1467"
assert len(snapshot["parts"]) == 1
snapshot["parts"][0]["supplier_part_number"] = None
destination.write_text(
    json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  "$assembly_requirements" \
  --output "$assembly_incomplete_generation" \
  --pcbex "$pcbex_binary" \
  --max-attempts 1 \
  --timeout-seconds 120 \
  --catalog-snapshot "$assembly_incomplete_snapshot" \
  --allow-footprint-fallback \
  --provider-command python3 -c \
  'import sys; from pathlib import Path; sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())' \
  "$assembly_spec"
PYTHONPATH=agent/src python3 -m pcbex_agent handoff-circuit \
  "$assembly_incomplete_generation" \
  --output "$assembly_incomplete_handoff" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 120 \
  >"$assembly_incomplete_handoff_log"
PYTHONPATH=agent/src python3 -m pcbex_agent extract-circuit-handoff-bundle \
  "$assembly_incomplete_handoff" \
  --output-dir "$assembly_incomplete_extract" \
  >"$assembly_incomplete_extract_result"
"$pcbex_binary" verify-circuit-kicad-board-binding \
  "$assembly_incomplete_extract/circuit-spec-v2.json" \
  "$assembly_incomplete_extract/circuit-spec.kicad_sch" \
  "$assembly_board" \
  --output "$assembly_incomplete_binding" \
  --require-approved
PYTHONPATH=agent/src python3 -m pcbex_agent build-procurement-intent \
  "$assembly_board" "$assembly_manufacturing_zip" \
  --circuit-generation "$assembly_incomplete_generation" \
  --catalog-snapshot "$assembly_incomplete_snapshot" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 180 \
  --output "$assembly_incomplete_procurement"
jq -e '
  .approved == false and
  .status == "rejected" and
  .line_items == [] and
  .final_bom.approved == true and
  any(.findings[]; .code == "supplier_part_number_missing")
' "$assembly_incomplete_procurement" >/dev/null
if PYTHONPATH=agent/src python3 -m pcbex_agent build-assembly-evidence \
  "$assembly_incomplete_handoff" \
  "$assembly_board" \
  "$assembly_manufacturing_zip" \
  --board-binding-report "$assembly_incomplete_binding" \
  --procurement-intent "$assembly_incomplete_procurement" \
  --catalog-snapshot "$assembly_incomplete_snapshot" \
  --final-cpl-report "$assembly_final_cpl" \
  --pcbex "$pcbex_binary" \
  --manufacturing-kicad-cli "$kicad_cli_binary" \
  --timeout-seconds 600 \
  --output "$assembly_incomplete_evidence" \
  --require-complete \
  2>"$assembly_incomplete_error"; then
  echo "expected incomplete assembly evidence to fail the final gate" >&2
  exit 1
fi
python3 - \
  "$assembly_incomplete_evidence" \
  "$assembly_incomplete_error" \
  "$output_directory" <<'PY'
import json
from pathlib import Path, PureWindowsPath
import sys

result_path, error_path, output_directory = map(Path, sys.argv[1:])
result = json.loads(result_path.read_text(encoding="utf-8"))
assert error_path.read_bytes()
assert result["schema_version"] == 1
assert result["scope"] == "offline-exact-board-assembly-evidence-v1"
assert result["status"] == "incomplete"
assert result["complete"] is False
assert result["circuit_manufacturing"]["verified"] is True
assert result["circuit_manufacturing"]["board_binding"]["approved"] is True
assert result["procurement"]["approved"] is False
assert result["procurement"]["line_items"] == []
assert result["final_bom"]["approved"] is True
assert result["final_cpl"]["approved"] is True
assert "in_bom_parts" not in result["final_bom"]
assert "final_bom" not in result["procurement"]
assert "binding_sha256" not in result["procurement"]
assert [finding["code"] for finding in result["findings"]] == [
    "procurement_intent_rejected",
]
assert result["membership"] == {
    "both": ["J1", "J2"],
    "bom_only": [],
    "cpl_only": [],
}
assert all(result["validation"].values())

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(result)
PY

# v1.469 first acquires one exact normalized offer through a genuine local TLS
# socket and the real CLI, then feeds the canonical published bytes into the
# unchanged v1.468 coverage boundary. The test-only endpoint is not a live
# supplier or production-CA interoperability claim. The receipt records only
# the adapter's bounded network observation; supplier/offer/price authenticity,
# currentness, reservation, authorization, payment, and ordering remain false.
supplier_offer="$output_directory/assembly.supplier-offer.json"
supplier_offer_response="$output_directory/assembly.supplier-offer.response.json"
supplier_offer_fetch_receipt="$output_directory/assembly.supplier-offer-fetch-receipt.json"
supplier_offer_fetch_schema="$output_directory/supplier-offer-fetch-receipt.schema.json"
supplier_offer_schema="$output_directory/supplier-offer.schema.json"
supplier_offer_coverage_schema="$output_directory/supplier-offer-coverage.schema.json"
supplier_offer_coverage="$output_directory/assembly.supplier-offer-coverage.json"
supplier_offer_shortfall="$output_directory/assembly.supplier-offer.shortfall.json"
supplier_offer_shortfall_response="$output_directory/assembly.supplier-offer.shortfall.response.json"
supplier_offer_shortfall_fetch_receipt="$output_directory/assembly.supplier-offer.shortfall-fetch-receipt.json"
supplier_offer_shortfall_server_ready="$output_directory/supplier-offer-shortfall-test-server.ready"
supplier_offer_shortfall_server_request="$output_directory/supplier-offer-shortfall-test-server.request.json"
supplier_offer_shortfall_coverage="$output_directory/assembly.supplier-offer.shortfall.coverage.json"
supplier_offer_shortfall_gated_coverage="$output_directory/assembly.supplier-offer.shortfall.gated.coverage.json"
supplier_offer_shortfall_error="$output_directory/assembly.supplier-offer.shortfall.stderr"
supplier_offer_composition="$output_directory/assembly.supplier-offer-evidence.json"
supplier_offer_composition_schema="$output_directory/assembly-supplier-offer-evidence.schema.json"
supplier_offer_shortfall_composition="$output_directory/assembly.supplier-offer.shortfall.evidence.json"
supplier_offer_shortfall_gated_composition="$output_directory/assembly.supplier-offer.shortfall.gated.evidence.json"
supplier_offer_shortfall_composition_error="$output_directory/assembly.supplier-offer.shortfall.evidence.stderr"
supplier_offer_evaluated_at="$(date +%s)"
python3 - \
  "$assembly_procurement" \
  "$supplier_offer_response" \
  "$supplier_offer_evaluated_at" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

intent_path = Path(sys.argv[1])
offer_path = Path(sys.argv[2])
evaluated_at = int(sys.argv[3])
intent_raw = intent_path.read_bytes()
intent = json.loads(intent_raw)
assert intent["approved"] is True
assert intent["quantity_basis"] == "per_board"
assert intent["line_items"]

lines = []
for index, item in enumerate(
    sorted(intent["line_items"], key=lambda value: value["supplier_part_number"])
):
    required_quantity = item["quantity"] * 25
    lines.append(
        {
            "mpn": item["mpn"],
            "supplier_part_number": item["supplier_part_number"],
            "catalog_part_sha256": item["catalog_part_sha256"],
            "quoted_quantity": required_quantity,
            "line_subtotal_micros": required_quantity * (index + 1) * 10_000,
        }
    )

offer = {
    "schema_version": 1,
    "scope": "offline-normalized-supplier-offer-v1",
    "procurement_intent_sha256": hashlib.sha256(intent_raw).hexdigest(),
    "supplier": intent["catalog"]["supplier"],
    "offer_id": "kicad-e2e-v1468-25-boards",
    "valid_from_unix": evaluated_at - 86_400,
    "valid_until_unix": evaluated_at + 86_400,
    "currency": "USD",
    "lines": lines,
}
offer_path.write_bytes(
    json.dumps(offer, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
PY
supplier_offer_tls_key="$output_directory/supplier-offer-test-server.key.pem"
supplier_offer_tls_certificate="$output_directory/supplier-offer-test-server.cert.pem"
supplier_offer_tls_config="$output_directory/supplier-offer-test-server.openssl.cnf"
supplier_offer_server_script="$output_directory/supplier-offer-test-server.py"
supplier_offer_server_ready="$output_directory/supplier-offer-test-server.ready"
supplier_offer_server_request="$output_directory/supplier-offer-test-server.request.json"
supplier_offer_token='pcbex-e2e-v1469-token'
cat >"$supplier_offer_tls_config" <<'EOF'
[req]
distinguished_name = distinguished_name
prompt = no
x509_extensions = extensions
[distinguished_name]
CN = 127.0.0.1
[extensions]
subjectAltName = IP:127.0.0.1
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage = serverAuth
EOF
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 1 \
  -keyout "$supplier_offer_tls_key" \
  -out "$supplier_offer_tls_certificate" \
  -config "$supplier_offer_tls_config" \
  -extensions extensions >/dev/null 2>&1
cat >"$supplier_offer_server_script" <<'PY'
import http.server
import json
from pathlib import Path
import ssl
import sys

certificate, key, response_path, ready_path, request_path, token = sys.argv[1:]
body = Path(response_path).read_bytes()

class Server(http.server.HTTPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_arguments):
        pass

    def do_GET(self):
        observed = {
            "path": self.path,
            "accept": self.headers.get("Accept"),
            "accept_encoding": self.headers.get("Accept-Encoding"),
            "authorization": self.headers.get("Authorization"),
        }
        expected = {
            "path": "/v1/quote",
            "accept": "application/json",
            "accept_encoding": "identity",
            "authorization": f"Bearer {token}",
        }
        Path(request_path).write_text(
            json.dumps(
                {
                    "path": observed["path"],
                    "accept": observed["accept"],
                    "accept_encoding": observed["accept_encoding"],
                    "authorization_matched": observed["authorization"]
                    == expected["authorization"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        if observed != expected:
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

server = Server(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
Path(ready_path).write_text(str(server.server_address[1]) + "\n", encoding="ascii")
server.timeout = 30
server.handle_request()
server.server_close()
if not Path(request_path).is_file():
    raise SystemExit("supplier-offer test server received no request")
PY
python3 "$supplier_offer_server_script" \
  "$supplier_offer_tls_certificate" \
  "$supplier_offer_tls_key" \
  "$supplier_offer_response" \
  "$supplier_offer_server_ready" \
  "$supplier_offer_server_request" \
  "$supplier_offer_token" &
supplier_offer_server_pid=$!
for _attempt in $(seq 1 200); do
  if [[ -s "$supplier_offer_server_ready" ]]; then
    break
  fi
  if ! kill -0 "$supplier_offer_server_pid" 2>/dev/null; then
    wait "$supplier_offer_server_pid"
    echo "supplier-offer test TLS server exited before readiness" >&2
    exit 1
  fi
  sleep 0.05
done
test -s "$supplier_offer_server_ready"
supplier_offer_server_port="$(tr -d '[:space:]' < "$supplier_offer_server_ready")"
supplier_offer_intent_sha256="$(sha256sum "$assembly_procurement" | cut -d ' ' -f 1)"
supplier_offer_supplier="$(python3 - "$assembly_procurement" <<'PY'
import json
from pathlib import Path
import sys
print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["catalog"]["supplier"])
PY
)"
if ! SSL_CERT_FILE="$supplier_offer_tls_certificate" \
  PCBEX_E2E_SUPPLIER_OFFER_TOKEN="$supplier_offer_token" \
  PYTHONPATH=agent/src python3 -m pcbex_agent fetch-supplier-offer \
    --endpoint "https://127.0.0.1:${supplier_offer_server_port}/v1/quote" \
    --supplier "$supplier_offer_supplier" \
    --procurement-intent-sha256 "$supplier_offer_intent_sha256" \
    --output "$supplier_offer" \
    --receipt "$supplier_offer_fetch_receipt" \
    --timeout-seconds 30 \
    --maximum-response-bytes 4194304 \
    --bearer-token-environment PCBEX_E2E_SUPPLIER_OFFER_TOKEN; then
  kill "$supplier_offer_server_pid" 2>/dev/null || true
  wait "$supplier_offer_server_pid" 2>/dev/null || true
  exit 1
fi
wait "$supplier_offer_server_pid"
supplier_offer_evaluated_at="$(python3 - "$supplier_offer_fetch_receipt" <<'PY'
import json
from pathlib import Path
import sys

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["fetched_at_unix"])
PY
)"
PYTHONPATH=agent/src python3 -m pcbex_agent supplier-offer-fetch-receipt-schema \
  --output "$supplier_offer_fetch_schema"
PYTHONPATH=agent/src python3 -m pcbex_agent build-supplier-offer-coverage \
  "$assembly_board" "$assembly_manufacturing_zip" \
  --circuit-generation "$assembly_generation" \
  --catalog-snapshot "$assembly_snapshot" \
  --procurement-intent "$assembly_procurement" \
  --supplier-offer "$supplier_offer" \
  --requested-boards 25 \
  --evaluated-at-unix "$supplier_offer_evaluated_at" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 180 \
  --output "$supplier_offer_coverage" \
  --require-covered
PYTHONPATH=agent/src python3 -m pcbex_agent supplier-offer-schema \
  --output "$supplier_offer_schema"
PYTHONPATH=agent/src python3 -m pcbex_agent supplier-offer-coverage-schema \
  --output "$supplier_offer_coverage_schema"
PYTHONPATH=agent/src python3 - \
  "$supplier_offer_coverage" \
  "$supplier_offer_fetch_receipt" \
  "$supplier_offer_fetch_schema" \
  "$supplier_offer_response" \
  "$supplier_offer_server_request" \
  "$supplier_offer_schema" \
  "$supplier_offer_coverage_schema" \
  "$supplier_offer" \
  "$assembly_procurement" \
  "$assembly_board" \
  "$assembly_manufacturing_zip" \
  "$assembly_generation" \
  "$assembly_snapshot" \
  "$output_directory" <<'PY'
import copy
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys

from pcbex_agent import validate_supplier_offer_fetch_receipt

(
    result_path,
    fetch_receipt_path,
    fetch_schema_path,
    response_path,
    server_request_path,
    offer_schema_path,
    coverage_schema_path,
    offer_path,
    intent_path,
    board_path,
    package_path,
    generation_path,
    snapshot_path,
    output_directory,
) = map(Path, sys.argv[1:])

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

result_raw = result_path.read_bytes()
fetch_receipt_raw = fetch_receipt_path.read_bytes()
fetch_schema_raw = fetch_schema_path.read_bytes()
response_raw = response_path.read_bytes()
offer_raw = offer_path.read_bytes()
offer_schema_raw = offer_schema_path.read_bytes()
coverage_schema_raw = coverage_schema_path.read_bytes()
result = json.loads(result_raw)
fetch_receipt = json.loads(fetch_receipt_raw)
fetch_schema = json.loads(fetch_schema_raw)
server_request = json.loads(server_request_path.read_text(encoding="utf-8"))
offer = json.loads(offer_raw)
intent = json.loads(intent_path.read_text(encoding="utf-8"))
offer_schema = json.loads(offer_schema_raw)
coverage_schema = json.loads(coverage_schema_raw)
assert result_raw == (
    json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
)
assert fetch_receipt_raw == (
    json.dumps(fetch_receipt, indent=2, ensure_ascii=False, sort_keys=True).encode(
        "utf-8"
    )
    + b"\n"
)
assert fetch_schema_raw == (
    json.dumps(fetch_schema, indent=2, ensure_ascii=False).encode("utf-8")
    + b"\n"
)
assert offer_raw == (
    json.dumps(offer, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
    + b"\n"
)
assert offer_schema_raw == (
    json.dumps(offer_schema, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
)
assert coverage_schema_raw == (
    json.dumps(coverage_schema, indent=2, ensure_ascii=False).encode("utf-8")
    + b"\n"
)

assert set(fetch_receipt) == {
    "adapter",
    "adapter_network_performed",
    "current_availability_verified",
    "endpoint_id",
    "fetched_at_unix",
    "inventory_reserved",
    "offer_authenticity_verified",
    "offer_bytes",
    "offer_sha256",
    "order_placed",
    "order_ready",
    "payment_performed",
    "price_authenticity_verified",
    "procurement_authorized",
    "procurement_intent_sha256",
    "request_sha256",
    "response_bytes",
    "response_sha256",
    "schema_version",
    "scope",
    "status",
    "supplier",
    "supplier_authenticity_verified",
    "trusted_time_verified",
}
assert fetch_receipt["schema_version"] == 1
assert fetch_receipt["scope"] == "https-supplier-offer-acquisition-receipt-v1"
assert fetch_receipt["adapter"] == "supplier-offer-http-v1"
assert fetch_receipt["adapter_network_performed"] is True
assert fetch_receipt["status"] == 200
assert isinstance(fetch_receipt["fetched_at_unix"], int)
assert not isinstance(fetch_receipt["fetched_at_unix"], bool)
assert fetch_receipt["fetched_at_unix"] >= 0
assert fetch_receipt["supplier"] == intent["catalog"]["supplier"]
assert fetch_receipt["procurement_intent_sha256"] == identity(intent_path)["sha256"]
assert fetch_receipt["endpoint_id"].startswith("https://127.0.0.1:")
assert fetch_receipt["endpoint_id"].endswith("/v1/quote")
assert fetch_receipt["response_bytes"] == len(response_raw)
assert fetch_receipt["response_sha256"] == hashlib.sha256(response_raw).hexdigest()
assert fetch_receipt["offer_bytes"] == len(offer_raw)
assert fetch_receipt["offer_sha256"] == hashlib.sha256(offer_raw).hexdigest()
request_material = {
    "adapter": "supplier-offer-http-v1",
    "endpoint_id": fetch_receipt["endpoint_id"],
    "method": "GET",
    "procurement_intent_sha256": fetch_receipt["procurement_intent_sha256"],
    "supplier": fetch_receipt["supplier"],
}
assert fetch_receipt["request_sha256"] == hashlib.sha256(
    b"pcbex:https-supplier-offer-acquisition-request-v1\0"
    + json.dumps(
        request_material, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
).hexdigest()
for field in (
    "current_availability_verified",
    "inventory_reserved",
    "offer_authenticity_verified",
    "order_placed",
    "order_ready",
    "payment_performed",
    "price_authenticity_verified",
    "procurement_authorized",
    "supplier_authenticity_verified",
    "trusted_time_verified",
):
    assert fetch_receipt[field] is False, field
assert server_request == {
    "accept": "application/json",
    "accept_encoding": "identity",
    "authorization_matched": True,
    "path": "/v1/quote",
}
assert fetch_schema["$id"].endswith(
    "/schemas/supplier-offer-fetch-receipt-v1.json"
)
assert fetch_schema["additionalProperties"] is False
assert fetch_schema["properties"]["scope"] == {
    "const": "https-supplier-offer-acquisition-receipt-v1"
}
assert fetch_schema["properties"]["adapter_network_performed"] == {
    "const": True
}
assert validate_supplier_offer_fetch_receipt(
    fetch_receipt_path, offer_path
) == fetch_receipt

assert set(result) == {
    "schema_version",
    "scope",
    "status",
    "covered",
    "requested_boards",
    "evaluated_at_unix",
    "quantity_basis",
    "cost_scope",
    "adapter_network_performed",
    "current_availability_verified",
    "supplier_authenticity_verified",
    "offer_authenticity_verified",
    "price_authenticity_verified",
    "trusted_time_verified",
    "inventory_reserved",
    "procurement_authorized",
    "order_ready",
    "order_placed",
    "payment_performed",
    "sources",
    "procurement",
    "supplier_offer",
    "coverage_lines",
    "component_subtotal_micros",
    "findings",
    "validation",
    "binding_sha256",
}
assert result["schema_version"] == 1
assert result["scope"] == "offline-procurement-supplier-offer-coverage-v1"
assert result["status"] == "covered"
assert result["covered"] is True
assert result["requested_boards"] == 25
assert result["evaluated_at_unix"] == fetch_receipt["fetched_at_unix"]
assert result["quantity_basis"] == "explicit_board_quantity"
assert result["cost_scope"] == "component_lines_only"
assert result["findings"] == []
assert result["validation"] == {
    "procurement_intent_replayed": True,
    "procurement_intent_approved": True,
    "procurement_intent_digest_matched": True,
    "offer_normalized": True,
    "supplier_matched": True,
    "line_set_matched": True,
    "line_identities_matched": True,
    "quantities_covered": True,
    "validity_window_matched": True,
    "component_subtotal_checked": True,
    "caller_inputs_unchanged": True,
}
for field in (
    "adapter_network_performed",
    "current_availability_verified",
    "supplier_authenticity_verified",
    "offer_authenticity_verified",
    "price_authenticity_verified",
    "trusted_time_verified",
    "inventory_reserved",
    "procurement_authorized",
    "order_ready",
    "order_placed",
    "payment_performed",
):
    assert result[field] is False, field

assert result["sources"] == {
    "board": {"name": board_path.name, **identity(board_path)},
    "manufacturing_package": identity(package_path),
    "generation_bundle": identity(generation_path),
    "catalog_snapshot": identity(snapshot_path),
    "procurement_intent": identity(intent_path),
    "supplier_offer": identity(offer_path),
}
assert fetch_receipt["offer_sha256"] == result["sources"]["supplier_offer"][
    "sha256"
]
expected_procurement = copy.deepcopy(intent)
del expected_procurement["final_bom"]
del expected_procurement["binding_sha256"]
assert result["procurement"] == expected_procurement
assert result["supplier_offer"] == offer
assert len(result["coverage_lines"]) == len(intent["line_items"])
intent_by_supplier_part = {
    line["supplier_part_number"]: line for line in intent["line_items"]
}
offer_by_supplier_part = {
    line["supplier_part_number"]: line for line in offer["lines"]
}
assert [
    line["supplier_part_number"] for line in result["coverage_lines"]
] == sorted(intent_by_supplier_part)
for line in result["coverage_lines"]:
    assert set(line) == {
        "mpn",
        "supplier_part_number",
        "catalog_part_sha256",
        "footprint",
        "references",
        "per_board_quantity",
        "requested_boards",
        "required_quantity",
        "quoted_quantity",
        "surplus_quantity",
        "line_subtotal_micros",
    }
    intent_line = intent_by_supplier_part[line["supplier_part_number"]]
    offer_line = offer_by_supplier_part[line["supplier_part_number"]]
    assert line["mpn"] == intent_line["mpn"]
    assert line["catalog_part_sha256"] == intent_line["catalog_part_sha256"]
    assert line["footprint"] == intent_line["footprint"]
    assert line["references"] == intent_line["references"]
    assert line["per_board_quantity"] == intent_line["quantity"]
    assert line["requested_boards"] == 25
    assert line["required_quantity"] == intent_line["quantity"] * 25
    assert line["quoted_quantity"] == offer_line["quoted_quantity"]
    assert line["surplus_quantity"] == 0
    assert line["line_subtotal_micros"] == offer_line["line_subtotal_micros"]
assert result["component_subtotal_micros"] == sum(
    line["line_subtotal_micros"] for line in offer["lines"]
)
assert offer_schema["$id"].endswith(
    "/schemas/offline-normalized-supplier-offer-v1.json"
)
assert offer_schema["additionalProperties"] is False
assert offer_schema["properties"]["scope"] == {
    "const": "offline-normalized-supplier-offer-v1"
}
assert coverage_schema["$id"].endswith(
    "/schemas/offline-procurement-supplier-offer-coverage-v1.json"
)
assert coverage_schema["additionalProperties"] is False
assert coverage_schema["properties"]["scope"] == {
    "const": "offline-procurement-supplier-offer-coverage-v1"
}
assert coverage_schema["properties"]["adapter_network_performed"] == {
    "const": False
}

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(result)
PY

# Preserve structural validity and every exact identity while lowering the
# sole quoted line below the 25-board requirement. The first run retains only
# the truthful shortfall; the gated rerun must publish identical bytes before
# returning nonzero.
python3 - "$supplier_offer" "$supplier_offer_shortfall_response" <<'PY'
import json
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
offer = json.loads(source.read_text(encoding="utf-8"))
assert len(offer["lines"]) == 1
assert offer["lines"][0]["quoted_quantity"] > 0
offer["offer_id"] = "kicad-e2e-v1468-one-line-shortfall"
offer["lines"][0]["quoted_quantity"] -= 1
destination.write_bytes(
    json.dumps(offer, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
PY
python3 "$supplier_offer_server_script" \
  "$supplier_offer_tls_certificate" \
  "$supplier_offer_tls_key" \
  "$supplier_offer_shortfall_response" \
  "$supplier_offer_shortfall_server_ready" \
  "$supplier_offer_shortfall_server_request" \
  "$supplier_offer_token" &
supplier_offer_shortfall_server_pid=$!
for _attempt in $(seq 1 200); do
  if [[ -s "$supplier_offer_shortfall_server_ready" ]]; then
    break
  fi
  if ! kill -0 "$supplier_offer_shortfall_server_pid" 2>/dev/null; then
    wait "$supplier_offer_shortfall_server_pid"
    echo "supplier-offer shortfall TLS server exited before readiness" >&2
    exit 1
  fi
  sleep 0.05
done
test -s "$supplier_offer_shortfall_server_ready"
supplier_offer_shortfall_server_port="$(tr -d '[:space:]' < "$supplier_offer_shortfall_server_ready")"
if ! SSL_CERT_FILE="$supplier_offer_tls_certificate" \
  PCBEX_E2E_SUPPLIER_OFFER_TOKEN="$supplier_offer_token" \
  PYTHONPATH=agent/src python3 -m pcbex_agent fetch-supplier-offer \
    --endpoint "https://127.0.0.1:${supplier_offer_shortfall_server_port}/v1/quote" \
    --supplier "$supplier_offer_supplier" \
    --procurement-intent-sha256 "$supplier_offer_intent_sha256" \
    --output "$supplier_offer_shortfall" \
    --receipt "$supplier_offer_shortfall_fetch_receipt" \
    --timeout-seconds 30 \
    --maximum-response-bytes 4194304 \
    --bearer-token-environment PCBEX_E2E_SUPPLIER_OFFER_TOKEN; then
  kill "$supplier_offer_shortfall_server_pid" 2>/dev/null || true
  wait "$supplier_offer_shortfall_server_pid" 2>/dev/null || true
  exit 1
fi
wait "$supplier_offer_shortfall_server_pid"
supplier_offer_shortfall_evaluated_at="$(python3 - "$supplier_offer_shortfall_fetch_receipt" <<'PY'
import json
from pathlib import Path
import sys

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["fetched_at_unix"])
PY
)"
rm -f -- \
  "$supplier_offer_tls_key" \
  "$supplier_offer_tls_certificate" \
  "$supplier_offer_tls_config" \
  "$supplier_offer_server_script"
PYTHONPATH=agent/src python3 -m pcbex_agent build-supplier-offer-coverage \
  "$assembly_board" "$assembly_manufacturing_zip" \
  --circuit-generation "$assembly_generation" \
  --catalog-snapshot "$assembly_snapshot" \
  --procurement-intent "$assembly_procurement" \
  --supplier-offer "$supplier_offer_shortfall" \
  --requested-boards 25 \
  --evaluated-at-unix "$supplier_offer_shortfall_evaluated_at" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 180 \
  --output "$supplier_offer_shortfall_coverage"
if PYTHONPATH=agent/src python3 -m pcbex_agent build-supplier-offer-coverage \
  "$assembly_board" "$assembly_manufacturing_zip" \
  --circuit-generation "$assembly_generation" \
  --catalog-snapshot "$assembly_snapshot" \
  --procurement-intent "$assembly_procurement" \
  --supplier-offer "$supplier_offer_shortfall" \
  --requested-boards 25 \
  --evaluated-at-unix "$supplier_offer_shortfall_evaluated_at" \
  --pcbex "$pcbex_binary" \
  --timeout-seconds 180 \
  --output "$supplier_offer_shortfall_gated_coverage" \
  --require-covered \
  2>"$supplier_offer_shortfall_error"; then
  echo "expected supplier-offer shortfall to fail the final gate" >&2
  exit 1
fi
cmp "$supplier_offer_shortfall_coverage" \
  "$supplier_offer_shortfall_gated_coverage"
python3 - \
  "$supplier_offer_shortfall_coverage" \
  "$supplier_offer_shortfall_error" \
  "$output_directory" <<'PY'
import json
from pathlib import Path, PureWindowsPath
import sys

result_path, error_path, output_directory = map(Path, sys.argv[1:])
result_raw = result_path.read_bytes()
result = json.loads(result_raw)
assert result_raw == (
    json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
)
assert error_path.read_bytes() == (
    b"supplier offer coverage report was retained but the offer does not cover "
    b"the procurement intent\n"
)
assert set(result) == {
    "schema_version",
    "scope",
    "status",
    "covered",
    "requested_boards",
    "evaluated_at_unix",
    "quantity_basis",
    "cost_scope",
    "adapter_network_performed",
    "current_availability_verified",
    "supplier_authenticity_verified",
    "offer_authenticity_verified",
    "price_authenticity_verified",
    "trusted_time_verified",
    "inventory_reserved",
    "procurement_authorized",
    "order_ready",
    "order_placed",
    "payment_performed",
    "sources",
    "procurement",
    "supplier_offer",
    "coverage_lines",
    "component_subtotal_micros",
    "findings",
    "validation",
    "binding_sha256",
}
assert result["schema_version"] == 1
assert result["scope"] == "offline-procurement-supplier-offer-coverage-v1"
assert result["status"] == "not_covered"
assert result["covered"] is False
assert [finding["code"] for finding in result["findings"]] == [
    "quoted_quantity_shortfall",
]
assert result["coverage_lines"] == []
assert result["component_subtotal_micros"] is None
assert result["validation"] == {
    "procurement_intent_replayed": True,
    "procurement_intent_approved": True,
    "procurement_intent_digest_matched": True,
    "offer_normalized": True,
    "supplier_matched": True,
    "line_set_matched": True,
    "line_identities_matched": True,
    "quantities_covered": False,
    "validity_window_matched": True,
    "component_subtotal_checked": True,
    "caller_inputs_unchanged": True,
}

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(result)
PY

# v1.470 composes the full v1.467 assembly result, v1.468 coverage result, and
# v1.469 receipt from one freshly replayed source union. The composer receives
# no independent generation path: coverage is replayed from the exact entry in
# the handoff archive. Receipt/fetch timestamp equality is untrusted
# correlation, not a currentness or trusted-clock claim.
PYTHONPATH=agent/src python3 -m pcbex_agent \
  assembly-supplier-offer-evidence-schema \
  --output "$supplier_offer_composition_schema"
PYTHONPATH=agent/src python3 -m pcbex_agent \
  build-assembly-supplier-offer-evidence \
  "$assembly_handoff_zip" "$assembly_board" "$assembly_manufacturing_zip" \
  --board-binding-report "$assembly_board_binding" \
  --procurement-intent "$assembly_procurement" \
  --catalog-snapshot "$assembly_snapshot" \
  --final-cpl-report "$assembly_final_cpl" \
  --assembly-evidence "$assembly_evidence" \
  --supplier-offer "$supplier_offer" \
  --supplier-offer-fetch-receipt "$supplier_offer_fetch_receipt" \
  --supplier-offer-coverage "$supplier_offer_coverage" \
  --requested-boards 25 \
  --evaluated-at-unix "$supplier_offer_evaluated_at" \
  --pcbex "$pcbex_binary" \
  --manufacturing-kicad-cli "$kicad_cli_binary" \
  --timeout-seconds 600 \
  --output "$supplier_offer_composition" \
  --require-complete

PYTHONPATH=agent/src python3 -m pcbex_agent \
  build-assembly-supplier-offer-evidence \
  "$assembly_handoff_zip" "$assembly_board" "$assembly_manufacturing_zip" \
  --board-binding-report "$assembly_board_binding" \
  --procurement-intent "$assembly_procurement" \
  --catalog-snapshot "$assembly_snapshot" \
  --final-cpl-report "$assembly_final_cpl" \
  --assembly-evidence "$assembly_evidence" \
  --supplier-offer "$supplier_offer_shortfall" \
  --supplier-offer-fetch-receipt "$supplier_offer_shortfall_fetch_receipt" \
  --supplier-offer-coverage "$supplier_offer_shortfall_coverage" \
  --requested-boards 25 \
  --evaluated-at-unix "$supplier_offer_shortfall_evaluated_at" \
  --pcbex "$pcbex_binary" \
  --manufacturing-kicad-cli "$kicad_cli_binary" \
  --timeout-seconds 600 \
  --output "$supplier_offer_shortfall_composition"
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  build-assembly-supplier-offer-evidence \
  "$assembly_handoff_zip" "$assembly_board" "$assembly_manufacturing_zip" \
  --board-binding-report "$assembly_board_binding" \
  --procurement-intent "$assembly_procurement" \
  --catalog-snapshot "$assembly_snapshot" \
  --final-cpl-report "$assembly_final_cpl" \
  --assembly-evidence "$assembly_evidence" \
  --supplier-offer "$supplier_offer_shortfall" \
  --supplier-offer-fetch-receipt "$supplier_offer_shortfall_fetch_receipt" \
  --supplier-offer-coverage "$supplier_offer_shortfall_coverage" \
  --requested-boards 25 \
  --evaluated-at-unix "$supplier_offer_shortfall_evaluated_at" \
  --pcbex "$pcbex_binary" \
  --manufacturing-kicad-cli "$kicad_cli_binary" \
  --timeout-seconds 600 \
  --output "$supplier_offer_shortfall_gated_composition" \
  --require-complete \
  2>"$supplier_offer_shortfall_composition_error"; then
  echo "expected incomplete assembly/supplier-offer evidence to fail the final gate" >&2
  exit 1
fi
cmp "$supplier_offer_shortfall_composition" \
  "$supplier_offer_shortfall_gated_composition"

PYTHONPATH=agent/src python3 - \
  "$supplier_offer_composition" \
  "$supplier_offer_shortfall_composition" \
  "$supplier_offer_shortfall_composition_error" \
  "$supplier_offer_composition_schema" \
  "$assembly_evidence" \
  "$supplier_offer_coverage" \
  "$supplier_offer_fetch_receipt" \
  "$supplier_offer_shortfall_coverage" \
  "$supplier_offer_shortfall_fetch_receipt" \
  "$assembly_handoff_zip" \
  "$assembly_board" \
  "$assembly_manufacturing_zip" \
  "$assembly_board_binding" \
  "$assembly_procurement" \
  "$assembly_snapshot" \
  "$assembly_final_cpl" \
  "$supplier_offer" \
  "$supplier_offer_shortfall" \
  "$assembly_generation" \
  "$output_directory" <<'PY'
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys

(
    complete_path,
    incomplete_path,
    incomplete_error_path,
    schema_path,
    assembly_path,
    coverage_path,
    receipt_path,
    shortfall_coverage_path,
    shortfall_receipt_path,
    handoff_path,
    board_path,
    package_path,
    board_binding_path,
    intent_path,
    snapshot_path,
    final_cpl_path,
    offer_path,
    shortfall_offer_path,
    generation_path,
    output_directory,
) = map(Path, sys.argv[1:])

def load_canonical(path):
    raw = path.read_bytes()
    value = json.loads(raw)
    assert raw == json.dumps(
        value, indent=2, ensure_ascii=False, sort_keys=True
    ).encode("utf-8") + b"\n"
    return value

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

complete = load_canonical(complete_path)
incomplete = load_canonical(incomplete_path)
schema = json.loads(schema_path.read_text(encoding="utf-8"))
assembly = json.loads(assembly_path.read_text(encoding="utf-8"))
coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
shortfall_coverage = json.loads(
    shortfall_coverage_path.read_text(encoding="utf-8")
)
shortfall_receipt = json.loads(
    shortfall_receipt_path.read_text(encoding="utf-8")
)

expected_keys = {
    "schema_version",
    "scope",
    "status",
    "complete",
    "adapter_network_performed",
    "current_availability_verified",
    "supplier_authenticity_verified",
    "offer_authenticity_verified",
    "price_authenticity_verified",
    "trusted_time_verified",
    "inventory_reserved",
    "assembly_ready",
    "assembly_authorized",
    "fabrication_authorized",
    "procurement_authorized",
    "order_ready",
    "order_placed",
    "payment_performed",
    "machine_operation_performed",
    "sources",
    "assembly_evidence",
    "supplier_offer_fetch_receipt",
    "supplier_offer_coverage",
    "findings",
    "validation",
    "binding_sha256",
}
assert set(complete) == expected_keys
assert complete["schema_version"] == 1
assert complete["scope"] == (
    "offline-exact-board-assembly-supplier-offer-evidence-v1"
)
assert complete["status"] == "complete"
assert complete["complete"] is True
assert complete["assembly_evidence"] == assembly
assert complete["supplier_offer_coverage"] == coverage
assert complete["supplier_offer_fetch_receipt"] == receipt
assert complete["findings"] == []

expected_validation = {
    "assembly_evidence_replayed",
    "supplier_offer_coverage_replayed",
    "supplier_offer_fetch_receipt_validated",
    "board_identity_cross_bound",
    "manufacturing_package_identity_cross_bound",
    "handoff_generation_identity_cross_bound",
    "catalog_snapshot_identity_cross_bound",
    "procurement_intent_identity_cross_bound",
    "procurement_projection_cross_bound",
    "supplier_offer_identity_cross_bound",
    "receipt_request_binding_validated",
    "evaluation_timestamp_cross_bound",
    "network_semantics_preserved",
    "caller_inputs_unchanged",
}
assert set(complete["validation"]) == expected_validation
assert all(complete["validation"].values())
for key in (
    "adapter_network_performed",
    "current_availability_verified",
    "supplier_authenticity_verified",
    "offer_authenticity_verified",
    "price_authenticity_verified",
    "trusted_time_verified",
    "inventory_reserved",
    "assembly_ready",
    "assembly_authorized",
    "fabrication_authorized",
    "procurement_authorized",
    "order_ready",
    "order_placed",
    "payment_performed",
    "machine_operation_performed",
):
    assert complete[key] is False, key
assert assembly["adapter_network_performed"] is False
assert coverage["adapter_network_performed"] is False
assert receipt["adapter_network_performed"] is True
assert coverage["evaluated_at_unix"] == receipt["fetched_at_unix"]

expected_source_keys = {
    "assembly_evidence",
    "board",
    "board_binding_report",
    "catalog_snapshot",
    "circuit_handoff_bundle",
    "final_cpl_report",
    "handoff_generation_bundle",
    "manufacturing_package",
    "procurement_intent",
    "supplier_offer",
    "supplier_offer_coverage",
    "supplier_offer_fetch_receipt",
}
assert set(complete["sources"]) == expected_source_keys
assert complete["sources"] == {
    "assembly_evidence": identity(assembly_path),
    "board": {"name": board_path.name, **identity(board_path)},
    "board_binding_report": identity(board_binding_path),
    "catalog_snapshot": identity(snapshot_path),
    "circuit_handoff_bundle": identity(handoff_path),
    "final_cpl_report": identity(final_cpl_path),
    "handoff_generation_bundle": identity(generation_path),
    "manufacturing_package": identity(package_path),
    "procurement_intent": identity(intent_path),
    "supplier_offer": identity(offer_path),
    "supplier_offer_coverage": identity(coverage_path),
    "supplier_offer_fetch_receipt": identity(receipt_path),
}
assert complete["assembly_evidence"]["procurement"] == complete[
    "supplier_offer_coverage"
]["procurement"]
assert complete["sources"]["handoff_generation_bundle"] == complete[
    "supplier_offer_coverage"
]["sources"]["generation_bundle"]
assert complete["sources"]["supplier_offer"]["sha256"] == receipt[
    "offer_sha256"
]
assert complete["sources"]["procurement_intent"]["sha256"] == receipt[
    "procurement_intent_sha256"
]

binding_material = dict(complete)
binding_digest = binding_material.pop("binding_sha256")
assert binding_digest == hashlib.sha256(
    b"pcbex:offline-exact-board-assembly-supplier-offer-evidence-v1\0"
    + json.dumps(
        binding_material, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
).hexdigest()

assert set(incomplete) == expected_keys
assert incomplete["status"] == "incomplete"
assert incomplete["complete"] is False
assert incomplete["assembly_evidence"] == assembly
assert incomplete["supplier_offer_coverage"] == shortfall_coverage
assert incomplete["supplier_offer_fetch_receipt"] == shortfall_receipt
assert incomplete["findings"] == [
    {
        "code": "supplier_offer_not_covered",
        "message": (
            "the freshly replayed supplier-offer coverage is not covered"
        ),
    }
]
assert set(incomplete["validation"]) == expected_validation
assert all(incomplete["validation"].values())
assert shortfall_coverage["covered"] is False
assert shortfall_receipt["adapter_network_performed"] is True
assert shortfall_coverage["evaluated_at_unix"] == shortfall_receipt[
    "fetched_at_unix"
]
assert incomplete["sources"]["supplier_offer"] == identity(
    shortfall_offer_path
)
assert incomplete["sources"]["supplier_offer_fetch_receipt"] == identity(
    shortfall_receipt_path
)
assert incomplete["sources"]["supplier_offer_coverage"] == identity(
    shortfall_coverage_path
)
assert incomplete_error_path.read_bytes() == (
    b"assembly supplier-offer evidence report was retained but evidence "
    b"is incomplete\n"
)

assert schema["$id"].endswith(
    "/schemas/offline-exact-board-assembly-supplier-offer-evidence-v1.json"
)
assert schema["additionalProperties"] is False
assert schema["properties"]["scope"] == {
    "const": "offline-exact-board-assembly-supplier-offer-evidence-v1"
}
assert schema["properties"]["adapter_network_performed"] == {"const": False}

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(output_directory.resolve()) not in value, value
        assert str(Path("/tmp").resolve()) not in value, value

reject_paths(complete)
reject_paths(incomplete)
PY

# v1.471 adds dual-control authorization over the exact complete v1.470
# closure. The ordinary replay child and trusted cryptographic child are named
# separately even though this release-binary E2E intentionally supplies the
# same built artifact for both roles. The policy pin comes from a genuinely
# signed and verified policy envelope, not from hashing the input JSON.
procurement_secret_directory="$(mktemp -d)"
procurement_approval_private_a="$procurement_secret_directory/procurement-approval-a.key"
procurement_approval_public_a="$output_directory/procurement-approval-a.pub"
procurement_approval_private_b="$procurement_secret_directory/procurement-approval-b.key"
procurement_approval_public_b="$output_directory/procurement-approval-b.pub"
procurement_policy_signing_private="$procurement_secret_directory/procurement-policy-signing.key"
procurement_policy_signing_public="$output_directory/procurement-policy-signing.pub"
procurement_policy_unsigned="$output_directory/procurement-policy-pack.unsigned.json"
procurement_policy_signed="$output_directory/procurement-policy-pack.signed.json"
procurement_policy_verified="$output_directory/procurement-policy-pack.verified.json"
procurement_approval_a="$output_directory/procurement-approval-a.json"
procurement_approval_b="$output_directory/procurement-approval-b.json"
procurement_approval_tampered="$output_directory/procurement-approval-a.tampered.json"
procurement_authorization="$output_directory/procurement-authorization.json"
procurement_authorization_single="$output_directory/procurement-authorization.single.json"
procurement_authorization_single_error="$output_directory/procurement-authorization.single.stderr"
procurement_authorization_tampered_output="$output_directory/procurement-authorization.tampered.json"
procurement_authorization_tampered_error="$output_directory/procurement-authorization.tampered.stderr"
procurement_evidence_tampered="$output_directory/assembly.supplier-offer-evidence.tampered.json"
procurement_authorization_source_tampered_output="$output_directory/procurement-authorization.source-tampered.json"
procurement_authorization_source_tampered_error="$output_directory/procurement-authorization.source-tampered.stderr"
procurement_shortfall_approval="$output_directory/procurement-shortfall.approval.json"
procurement_shortfall_approval_error="$output_directory/procurement-shortfall.approval.stderr"
procurement_private_key_must_not_be_read="$output_directory/procurement-forbidden-missing.key"
procurement_approval_schema="$output_directory/signed-procurement-approval.schema.json"
procurement_authorization_schema="$output_directory/procurement-authorization-report.schema.json"
trap 'rm -f -- "$procurement_approval_private_a" "$procurement_approval_private_b" "$procurement_policy_signing_private"; rmdir -- "$procurement_secret_directory" 2>/dev/null || true' EXIT

"$pcbex_binary" approval-keygen \
  --private-key "$procurement_approval_private_a" \
  --public-key "$procurement_approval_public_a"
"$pcbex_binary" approval-keygen \
  --private-key "$procurement_approval_private_b" \
  --public-key "$procurement_approval_public_b"
"$pcbex_binary" policy-keygen \
  --private-key "$procurement_policy_signing_private" \
  --public-key "$procurement_policy_signing_public"

procurement_component_ceiling="$(python3 - "$supplier_offer_coverage" <<'PY'
import json
from pathlib import Path
import sys

coverage = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
subtotal = coverage["component_subtotal_micros"]
assert coverage["covered"] is True
assert isinstance(subtotal, int) and not isinstance(subtotal, bool) and subtotal > 0
assert subtotal < 9_007_199_254_740_991
print(subtotal + 1)
PY
)"
python3 - \
  examples/acme-policy-pack.json \
  "$procurement_approval_public_a" \
  "$procurement_approval_public_b" \
  "$procurement_component_ceiling" \
  "$procurement_policy_unsigned" <<'PY'
import json
from pathlib import Path
import sys

source_path, public_a_path, public_b_path, ceiling, output_path = sys.argv[1:]
pack = json.loads(Path(source_path).read_text(encoding="utf-8"))
pack["procurement_authorization_policy"] = {
    "minimum_approvals": 2,
    "currency": "USD",
    "maximum_validity_seconds": 86400,
    "maximum_receipt_observation_age_seconds": 604800,
    "maximum_component_subtotal_micros": int(ceiling),
    "trusted_keys": [
        {
            "signer_id": "procurement-a",
            "public_key": Path(public_a_path).read_text(encoding="ascii").strip(),
        },
        {
            "signer_id": "procurement-b",
            "public_key": Path(public_b_path).read_text(encoding="ascii").strip(),
        },
    ],
}
Path(output_path).write_bytes(
    json.dumps(pack, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
PY
"$pcbex_binary" sign-policy-pack "$procurement_policy_unsigned" \
  --private-key "$procurement_policy_signing_private" \
  --signer-id procurement-policy-root \
  --output "$procurement_policy_signed"
rm -f -- "$procurement_policy_signing_private"
"$pcbex_binary" verify-policy-pack "$procurement_policy_signed" \
  --public-key "$procurement_policy_signing_public" \
  --output "$procurement_policy_verified"
procurement_policy_digest="$(python3 - \
  "$procurement_policy_signed" \
  "$procurement_policy_verified" <<'PY'
import json
from pathlib import Path
import sys

signed_path, verified_path = map(Path, sys.argv[1:])
signed = json.loads(signed_path.read_text(encoding="utf-8"))
verified = json.loads(verified_path.read_text(encoding="utf-8"))
assert signed["policy_pack"] == verified
digest = signed["policy_pack_sha256"]
assert isinstance(digest, str) and len(digest) == 64
assert all(character in "0123456789abcdef" for character in digest)
print(digest)
PY
)"

procurement_authorization_now="$(date +%s)"
procurement_valid_from="$((procurement_authorization_now - 60))"
procurement_expires_at="$((procurement_authorization_now + 43200))"
procurement_challenge="$(printf '%064x' 1471)"

procurement_complete_arguments=(
  "$supplier_offer_composition"
  "$assembly_handoff_zip"
  "$assembly_board"
  "$assembly_manufacturing_zip"
  --board-binding-report "$assembly_board_binding"
  --procurement-intent "$assembly_procurement"
  --catalog-snapshot "$assembly_snapshot"
  --final-cpl-report "$assembly_final_cpl"
  --assembly-evidence "$assembly_evidence"
  --supplier-offer "$supplier_offer"
  --supplier-offer-fetch-receipt "$supplier_offer_fetch_receipt"
  --supplier-offer-coverage "$supplier_offer_coverage"
  --policy-pack "$procurement_policy_verified"
  --expected-policy-pack-canonical-sha256 "$procurement_policy_digest"
  --requested-boards 25
  --evaluated-at-unix "$supplier_offer_evaluated_at"
  --pcbex "$pcbex_binary"
  --authorization-pcbex "$pcbex_binary"
  --manufacturing-kicad-cli "$kicad_cli_binary"
  --timeout-seconds 600
)

PYTHONPATH=agent/src python3 -m pcbex_agent \
  signed-procurement-approval-schema \
  --output "$procurement_approval_schema"
PYTHONPATH=agent/src python3 -m pcbex_agent \
  procurement-authorization-report-schema \
  --output "$procurement_authorization_schema"

PYTHONPATH=agent/src python3 -m pcbex_agent sign-procurement-approval \
  "${procurement_complete_arguments[@]}" \
  --private-key "$procurement_approval_private_a" \
  --signer-id procurement-a \
  --decision approve \
  --authorization-id procurement-e2e-v1471 \
  --challenge "$procurement_challenge" \
  --maximum-component-subtotal-micros "$procurement_component_ceiling" \
  --valid-from-unix "$procurement_valid_from" \
  --expires-at-unix "$procurement_expires_at" \
  --reason 'Independent approval of the exact covered component lines.' \
  --ticket E2E-1471-A \
  --output "$procurement_approval_a"
PYTHONPATH=agent/src python3 -m pcbex_agent sign-procurement-approval \
  "${procurement_complete_arguments[@]}" \
  --private-key "$procurement_approval_private_b" \
  --signer-id procurement-b \
  --decision approve \
  --authorization-id procurement-e2e-v1471 \
  --challenge "$procurement_challenge" \
  --maximum-component-subtotal-micros "$procurement_component_ceiling" \
  --valid-from-unix "$procurement_valid_from" \
  --expires-at-unix "$procurement_expires_at" \
  --reason 'Independent approval of the exact covered component lines.' \
  --ticket E2E-1471-B \
  --output "$procurement_approval_b"
rm -f -- \
  "$procurement_approval_private_a" \
  "$procurement_approval_private_b"
rmdir -- "$procurement_secret_directory"

PYTHONPATH=agent/src python3 -m pcbex_agent verify-procurement-authorization \
  "${procurement_complete_arguments[@]}" \
  --approval "$procurement_approval_b" \
  --approval "$procurement_approval_a" \
  --output "$procurement_authorization" \
  --require-authorized

# One valid approval is well formed but below the two-key policy quorum. The
# gated invocation must retain its canonical report before returning nonzero.
# A later renderer check below validates those exact retained bytes; a second
# verifier invocation would legitimately sample a different assessment time.
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  verify-procurement-authorization \
  "${procurement_complete_arguments[@]}" \
  --approval "$procurement_approval_a" \
  --output "$procurement_authorization_single" \
  --require-authorized \
  2>"$procurement_authorization_single_error"; then
  echo "expected one procurement approval to fail the final quorum gate" >&2
  exit 1
fi
test -s "$procurement_authorization_single"
python3 - "$procurement_authorization_single_error" <<'PY'
from pathlib import Path
import sys

assert Path(sys.argv[1]).read_bytes() == (
    b"procurement authorization report was retained but the exact release "
    b"was not authorized\n"
)
PY

PYTHONPATH=agent/src python3 - \
  "$procurement_approval_a" \
  "$procurement_approval_b" \
  "$procurement_authorization" \
  "$procurement_authorization_single" \
  "$procurement_approval_schema" \
  "$procurement_authorization_schema" \
  "$supplier_offer_composition" \
  "$supplier_offer_coverage" \
  "$supplier_offer_fetch_receipt" \
  "$procurement_policy_verified" \
  "$procurement_policy_digest" \
  "$procurement_challenge" \
  "$procurement_component_ceiling" \
  "$procurement_valid_from" \
  "$procurement_expires_at" \
  "$output_directory" <<'PY'
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys

from pcbex_agent import (
    procurement_authorization_report_json_schema,
    render_procurement_authorization_report,
    render_signed_procurement_approval,
    signed_procurement_approval_json_schema,
)

(
    approval_a_path,
    approval_b_path,
    authorization_path,
    single_path,
    approval_schema_path,
    authorization_schema_path,
    evidence_path,
    coverage_path,
    receipt_path,
    policy_path,
    policy_digest,
    challenge,
    component_ceiling,
    valid_from,
    expires_at,
    output_directory,
) = sys.argv[1:]
paths = [
    Path(value)
    for value in (
        approval_a_path,
        approval_b_path,
        authorization_path,
        single_path,
        approval_schema_path,
        authorization_schema_path,
        evidence_path,
        coverage_path,
        receipt_path,
        policy_path,
    )
]
(
    approval_a_path,
    approval_b_path,
    authorization_path,
    single_path,
    approval_schema_path,
    authorization_schema_path,
    evidence_path,
    coverage_path,
    receipt_path,
    policy_path,
) = paths
component_ceiling = int(component_ceiling)
valid_from = int(valid_from)
expires_at = int(expires_at)

def load(path):
    return json.loads(path.read_bytes())

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def compact(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=False,
        separators=(",", ":"),
    ).encode("utf-8")

approval_a = load(approval_a_path)
approval_b = load(approval_b_path)
authorization = load(authorization_path)
single = load(single_path)
approval_schema = load(approval_schema_path)
authorization_schema = load(authorization_schema_path)
evidence = load(evidence_path)
coverage = load(coverage_path)
receipt = load(receipt_path)
policy = load(policy_path)

approval_keys = [
    "schema_version",
    "scope",
    "evidence",
    "authorization_scope",
    "decision",
    "reason",
    "ticket",
    "signer_id",
    "algorithm",
    "public_key",
    "signature",
]
false_claims = [
    "adapter_network_performed",
    "current_availability_verified",
    "supplier_authenticity_verified",
    "offer_authenticity_verified",
    "price_authenticity_verified",
    "receipt_observation_authenticity_verified",
    "policy_pack_authenticity_verified",
    "trusted_time_verified",
    "inventory_reserved",
    "assembly_ready",
    "assembly_authorized",
    "fabrication_authorized",
    "order_ready",
    "order_placed",
    "payment_performed",
    "machine_operation_performed",
    "challenge_one_time_use_enforced",
]
report_keys = [
    "schema_version",
    "scope",
    "status",
    "procurement_authorized",
    *false_claims,
    "evidence",
    "authorization_scope",
    "policy_pack",
    "evaluated_at_unix",
    "approvals",
    "rejections",
    "members",
    "signed_approvals",
    "gate_failures",
    "validation",
    "binding_sha256",
]
validation_keys = [
    "assembly_supplier_offer_evidence_replayed",
    "evidence_complete_checked",
    "request_binding_validated",
    "commercial_scope_cross_bound",
    "policy_pack_validated",
    "approval_signatures_verified",
    "distinct_signers_verified",
    "caller_inputs_unchanged",
]

for approval in (approval_a, approval_b):
    assert list(approval) == approval_keys
    assert approval["schema_version"] == 1
    assert approval["scope"] == (
        "offline-exact-procurement-release-approval-v1"
    )
    assert approval["decision"] == "approve"
    assert approval["algorithm"] == "ed25519"
    assert approval["evidence"] == authorization["evidence"]
    assert approval["authorization_scope"] == authorization[
        "authorization_scope"
    ]
assert approval_a["signer_id"] == "procurement-a"
assert approval_b["signer_id"] == "procurement-b"
assert approval_a["public_key"] != approval_b["public_key"]
assert policy["procurement_authorization_policy"] == {
    "minimum_approvals": 2,
    "currency": "USD",
    "maximum_validity_seconds": 86400,
    "maximum_receipt_observation_age_seconds": 604800,
    "maximum_component_subtotal_micros": component_ceiling,
    "trusted_keys": [
        {
            "signer_id": "procurement-a",
            "public_key": approval_a["public_key"],
        },
        {
            "signer_id": "procurement-b",
            "public_key": approval_b["public_key"],
        },
    ],
}
assert approval_a_path.read_bytes() == render_signed_procurement_approval(
    approval_a
)
assert approval_b_path.read_bytes() == render_signed_procurement_approval(
    approval_b
)

expected_scope = {
    "authorization_id": "procurement-e2e-v1471",
    "challenge": challenge,
    "requested_boards": 25,
    "currency": "USD",
    "maximum_component_subtotal_micros": component_ceiling,
    "valid_from_unix": valid_from,
    "expires_at_unix": expires_at,
}
assert authorization["authorization_scope"] == expected_scope
assert valid_from <= authorization["evaluated_at_unix"] <= expires_at

offer = coverage["supplier_offer"]
expected_commercial = {
    "requested_boards": coverage["requested_boards"],
    "supplier": offer["supplier"],
    "offer_id": offer["offer_id"],
    "currency": offer["currency"],
    "covered": coverage["covered"],
    "component_subtotal_micros": coverage[
        "component_subtotal_micros"
    ],
    "offer_valid_from_unix": offer["valid_from_unix"],
    "offer_valid_until_unix": offer["valid_until_unix"],
    "receipt_fetched_at_unix": receipt["fetched_at_unix"],
}
expected_policy_projection = {
    "source": identity(policy_path),
    "canonical_sha256": policy_digest,
    "id": policy["id"],
    "revision": policy["revision"],
}
expected_evidence = {
    "assembly_supplier_offer_evidence": {
        "source": identity(evidence_path),
        "binding_sha256": evidence["binding_sha256"],
        "schema_version": evidence["schema_version"],
        "scope": evidence["scope"],
        "complete": evidence["complete"],
    },
    "commercial": expected_commercial,
    "policy_pack": expected_policy_projection,
}
assert authorization["evidence"] == expected_evidence
assert authorization["policy_pack"] == policy
assert authorization["evaluated_at_unix"] >= receipt["fetched_at_unix"]

def assert_report(report, *, authorized, approvals, failures, signed):
    assert list(report) == report_keys
    assert report["schema_version"] == 1
    assert report["scope"] == (
        "offline-exact-procurement-release-authorization-v1"
    )
    assert report["status"] == (
        "procurement_authorized" if authorized else "not_authorized"
    )
    assert report["procurement_authorized"] is authorized
    for key in false_claims:
        assert report[key] is False, key
    assert report["evidence"] == expected_evidence
    assert report["authorization_scope"] == expected_scope
    assert report["policy_pack"] == policy
    assert report["approvals"] == approvals
    assert report["rejections"] == 0
    assert report["gate_failures"] == failures
    assert list(report["validation"]) == validation_keys
    assert all(report["validation"].values())
    assert report["signed_approvals"] == signed
    assert [member["signer_id"] for member in report["members"]] == [
        value["signer_id"] for value in signed
    ]
    for member, approval in zip(report["members"], signed, strict=True):
        assert member == {
            "signer_id": approval["signer_id"],
            "public_key": approval["public_key"],
            "approval_sha256": hashlib.sha256(compact(approval)).hexdigest(),
            "decision": approval["decision"],
            "reason": approval["reason"],
            "ticket": approval["ticket"],
        }
    binding_material = {
        key: report[key] for key in report_keys if key != "binding_sha256"
    }
    assert report["binding_sha256"] == hashlib.sha256(
        b"pcbex:offline-exact-procurement-release-authorization-v1\0"
        + compact(binding_material)
    ).hexdigest()

assert_report(
    authorization,
    authorized=True,
    approvals=2,
    failures=[],
    signed=[approval_a, approval_b],
)
assert authorization_path.read_bytes() == render_procurement_authorization_report(
    authorization
)
assert_report(
    single,
    authorized=False,
    approvals=1,
    failures=["insufficient_procurement_approvals:required=2:actual=1"],
    signed=[approval_a],
)
assert single_path.read_bytes() == render_procurement_authorization_report(single)

expected_approval_schema = signed_procurement_approval_json_schema()
expected_authorization_schema = procurement_authorization_report_json_schema()
assert approval_schema == expected_approval_schema
assert authorization_schema == expected_authorization_schema
for path, schema in (
    (approval_schema_path, approval_schema),
    (authorization_schema_path, authorization_schema),
):
    assert path.read_bytes() == (
        json.dumps(
            schema, indent=2, sort_keys=True, ensure_ascii=False
        ).encode("utf-8")
        + b"\n"
    )
assert approval_schema["$id"] == (
    "https://github.com/penguin425/pcbex/schemas/"
    "signed-procurement-approval-v1.json"
)
assert authorization_schema["$id"] == (
    "https://github.com/penguin425/pcbex/schemas/"
    "procurement-authorization-report-v1.json"
)
assert approval_schema["additionalProperties"] is False
assert authorization_schema["additionalProperties"] is False
assert approval_schema["required"] == approval_keys
assert authorization_schema["required"] == report_keys
assert approval_schema["properties"]["scope"]["const"] == (
    "offline-exact-procurement-release-approval-v1"
)
assert authorization_schema["properties"]["scope"]["const"] == (
    "offline-exact-procurement-release-authorization-v1"
)
for key in false_claims:
    assert authorization_schema["properties"][key]["const"] is False

def assert_recursive_schema_bounds(value, location="$"):
    if isinstance(value, dict):
        if value.get("type") == "object":
            assert value.get("additionalProperties") is False, location
        if value.get("type") == "array":
            maximum = value.get("maxItems")
            assert isinstance(maximum, int) and not isinstance(
                maximum, bool
            ), location
            assert maximum >= 0, location
        for key, nested in value.items():
            assert_recursive_schema_bounds(nested, f"{location}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            assert_recursive_schema_bounds(nested, f"{location}[{index}]")

assert_recursive_schema_bounds(approval_schema)
assert_recursive_schema_bounds(authorization_schema)

def reject_paths(value):
    if isinstance(value, dict):
        for nested in value.values():
            reject_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_paths(nested)
    elif isinstance(value, str):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value
        assert not PureWindowsPath(value).drive, value
        assert str(Path(output_directory).resolve()) not in value, value

for value in (approval_a, approval_b, authorization, single):
    reject_paths(value)
PY

# Covered evidence is a precondition for approval. A deliberately absent key
# proves an approve attempt against the retained shortfall is rejected before
# the trusted signing child tries to open private key material.
procurement_shortfall_arguments=(
  "$supplier_offer_shortfall_composition"
  "$assembly_handoff_zip"
  "$assembly_board"
  "$assembly_manufacturing_zip"
  --board-binding-report "$assembly_board_binding"
  --procurement-intent "$assembly_procurement"
  --catalog-snapshot "$assembly_snapshot"
  --final-cpl-report "$assembly_final_cpl"
  --assembly-evidence "$assembly_evidence"
  --supplier-offer "$supplier_offer_shortfall"
  --supplier-offer-fetch-receipt "$supplier_offer_shortfall_fetch_receipt"
  --supplier-offer-coverage "$supplier_offer_shortfall_coverage"
  --policy-pack "$procurement_policy_verified"
  --expected-policy-pack-canonical-sha256 "$procurement_policy_digest"
  --requested-boards 25
  --evaluated-at-unix "$supplier_offer_shortfall_evaluated_at"
  --pcbex "$pcbex_binary"
  --authorization-pcbex "$pcbex_binary"
  --manufacturing-kicad-cli "$kicad_cli_binary"
  --timeout-seconds 600
)
test ! -e "$procurement_private_key_must_not_be_read"
if PYTHONPATH=agent/src python3 -m pcbex_agent sign-procurement-approval \
  "${procurement_shortfall_arguments[@]}" \
  --private-key "$procurement_private_key_must_not_be_read" \
  --signer-id procurement-a \
  --decision approve \
  --authorization-id procurement-e2e-v1471 \
  --challenge "$procurement_challenge" \
  --maximum-component-subtotal-micros "$procurement_component_ceiling" \
  --valid-from-unix "$procurement_valid_from" \
  --expires-at-unix "$procurement_expires_at" \
  --reason 'This approve operation must be refused before key access.' \
  --ticket E2E-1471-SHORTFALL \
  --output "$procurement_shortfall_approval" \
  2>"$procurement_shortfall_approval_error"; then
  echo "expected shortfall approval to fail before private-key access" >&2
  exit 1
fi
test ! -e "$procurement_private_key_must_not_be_read"
test ! -e "$procurement_shortfall_approval"
python3 - \
  "$procurement_shortfall_approval_error" \
  "$procurement_private_key_must_not_be_read" <<'PY'
from pathlib import Path
import sys

error_path, private_path = map(Path, sys.argv[1:])
assert error_path.read_bytes() == (
    b"procurement approval signing failed: cannot approve incomplete or "
    b"uncovered procurement evidence\n"
)
assert str(private_path).encode("utf-8") not in error_path.read_bytes()
PY

# Preserve formatting and mutate only one signature nibble so the failure is
# cryptographic rather than a JSON/canonicalization error.
python3 - "$procurement_approval_a" "$procurement_approval_tampered" <<'PY'
from pathlib import Path
import re
import sys

source_path, output_path = map(Path, sys.argv[1:])
raw = source_path.read_bytes()
match = re.search(rb'("signature"\s*:\s*")([0-9a-f])', raw)
assert match is not None
replacement = b"1" if match.group(2) != b"1" else b"0"
tampered = raw[: match.start(2)] + replacement + raw[match.end(2) :]
assert len(tampered) == len(raw) and tampered != raw
output_path.write_bytes(tampered)
PY
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  verify-procurement-authorization \
  "${procurement_complete_arguments[@]}" \
  --approval "$procurement_approval_tampered" \
  --approval "$procurement_approval_b" \
  --output "$procurement_authorization_tampered_output" \
  2>"$procurement_authorization_tampered_error"; then
  echo "expected a tampered procurement signature to fail closed" >&2
  exit 1
fi
test ! -e "$procurement_authorization_tampered_output"
test -s "$procurement_authorization_tampered_error"

# A retained-source mutation is rejected independently before any public
# authorization report can be created.
python3 - "$supplier_offer_composition" "$procurement_evidence_tampered" <<'PY'
from pathlib import Path
import re
import sys

source_path, output_path = map(Path, sys.argv[1:])
raw = source_path.read_bytes()
match = re.search(rb'("binding_sha256"\s*:\s*")([0-9a-f])', raw)
assert match is not None
replacement = b"1" if match.group(2) != b"1" else b"0"
tampered = raw[: match.start(2)] + replacement + raw[match.end(2) :]
assert len(tampered) == len(raw) and tampered != raw
output_path.write_bytes(tampered)
PY
procurement_source_tampered_arguments=("${procurement_complete_arguments[@]}")
procurement_source_tampered_arguments[0]="$procurement_evidence_tampered"
if PYTHONPATH=agent/src python3 -m pcbex_agent \
  verify-procurement-authorization \
  "${procurement_source_tampered_arguments[@]}" \
  --approval "$procurement_approval_a" \
  --approval "$procurement_approval_b" \
  --output "$procurement_authorization_source_tampered_output" \
  2>"$procurement_authorization_source_tampered_error"; then
  echo "expected tampered retained procurement evidence to fail closed" >&2
  exit 1
fi
test ! -e "$procurement_authorization_source_tampered_output"
test -s "$procurement_authorization_source_tampered_error"

# v1.472 replays the complete retained v1.471 authorization and admits its
# challenge exactly once to one caller-pinned local ledger. The new marker is
# local admission evidence only; the underlying v1.471 report remains
# stateless and keeps challenge_one_time_use_enforced=false.
procurement_reservation_ledger="$(realpath -m "$output_directory/procurement-reservation-ledger")"
procurement_reservation_corrupt_ledger="$(realpath -m "$output_directory/procurement-reservation-corrupt-ledger")"
procurement_reservation_negative_ledger="$(realpath -m "$output_directory/procurement-reservation-negative-ledger")"
procurement_reservation_ledger_id="$(printf '%064x' 1472)"
procurement_reservation_manifest_name=".pcbex-procurement-authorization-reservation-ledger-v1.json"
procurement_reservation_marker_name="procurement-authorization-reservation-v1-${procurement_challenge}.json"
procurement_reservation_schema="$output_directory/procurement-authorization-reservation.schema.json"
procurement_reservation_ledger_schema="$output_directory/procurement-authorization-reservation-ledger.schema.json"
procurement_reservation_repeat_error="$output_directory/procurement-authorization-reservation.repeat.stderr"
procurement_reservation_corrupt_error="$output_directory/procurement-authorization-reservation.corrupt.stderr"
procurement_reservation_negative_error="$output_directory/procurement-authorization-reservation.negative.stderr"

for ledger in \
  "$procurement_reservation_ledger" \
  "$procurement_reservation_corrupt_ledger" \
  "$procurement_reservation_negative_ledger"; do
  mkdir -m 0700 -- "$ledger"
  python3 - "$ledger/$procurement_reservation_manifest_name" \
    "$procurement_reservation_ledger_id" <<'PY'
import json
from pathlib import Path
import sys

path, ledger_id = sys.argv[1:]
Path(path).write_bytes(
    json.dumps(
        {
            "schema_version": 1,
            "ledger_scope": (
                "pinned-local-procurement-authorization-ledger-at-most-once-v1"
            ),
            "ledger_id": ledger_id,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    + b"\n"
)
PY
done

"$pcbex_binary" procurement-authorization-reservation-schema \
  --output "$procurement_reservation_schema"
"$pcbex_binary" procurement-authorization-reservation-ledger-schema \
  --output "$procurement_reservation_ledger_schema"

PYTHONPATH=agent/src python3 -m pcbex_agent reserve-procurement-authorization \
  "${procurement_complete_arguments[@]}" \
  --report "$procurement_authorization" \
  --approval "$procurement_approval_b" \
  --approval "$procurement_approval_a" \
  --reservation-ledger "$procurement_reservation_ledger" \
  --expected-ledger-id "$procurement_reservation_ledger_id"

procurement_reservation_marker="$procurement_reservation_ledger/$procurement_reservation_marker_name"
test -s "$procurement_reservation_marker"
test "$(stat -c '%a' "$procurement_reservation_ledger")" = 700
test "$(stat -c '%a' "$procurement_reservation_marker")" = 600

python3 - \
  "$procurement_reservation_marker" \
  "$procurement_authorization" \
  "$procurement_reservation_schema" \
  "$procurement_reservation_ledger_schema" \
  "$procurement_reservation_ledger_id" \
  "$procurement_challenge" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

marker_path, report_path, marker_schema_path, ledger_schema_path = map(
    Path, sys.argv[1:5]
)
ledger_id, challenge = sys.argv[5:]
marker = json.loads(marker_path.read_bytes())
report_raw = report_path.read_bytes()
report = json.loads(report_raw)
summary = marker["authorization_report_summary"]

assert marker["schema_version"] == 1
assert marker["reservation_scope"] == (
    "pinned-local-procurement-authorization-ledger-at-most-once-v1"
)
assert marker["status"] == "local_reservation_committed"
assert marker["local_challenge_reserved"] is True
assert marker["adapter_network_performed"] is False
assert marker["global_challenge_one_time_use_enforced"] is False
assert marker["inventory_reserved"] is False
assert marker["order_placed"] is False
assert marker["payment_performed"] is False
assert marker["ledger_id"] == ledger_id
assert summary["authorization_id"] == report["authorization_scope"]["authorization_id"]
assert summary["challenge"] == challenge
assert summary["supplier"] == report["evidence"]["commercial"]["supplier"]
assert summary["offer_id"] == report["evidence"]["commercial"]["offer_id"]
assert summary["requested_boards"] == 25
assert summary["currency"] == "USD"
assert summary["component_subtotal_micros"] == report["evidence"]["commercial"]["component_subtotal_micros"]
assert summary["maximum_component_subtotal_micros"] == report["authorization_scope"]["maximum_component_subtotal_micros"]
assert summary["approvals"] == 2
assert summary["rejections"] == 0
assert summary["gate_failure_count"] == 0
assert summary["report_bytes"] == len(report_raw)
assert summary["report_sha256"] == hashlib.sha256(report_raw).hexdigest()
assert summary["report_binding_sha256"] == report["binding_sha256"]
assert summary["challenge_one_time_use_enforced"] is False
assert report["challenge_one_time_use_enforced"] is False

for schema_path in (marker_schema_path, ledger_schema_path):
    schema = json.loads(schema_path.read_bytes())
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert "maxItems" in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
PY

marker_before="$(sha256sum "$procurement_reservation_marker" | cut -d' ' -f1)"
if PYTHONPATH=agent/src python3 -m pcbex_agent reserve-procurement-authorization \
  "${procurement_complete_arguments[@]}" \
  --report "$procurement_authorization" \
  --approval "$procurement_approval_a" \
  --approval "$procurement_approval_b" \
  --reservation-ledger "$procurement_reservation_ledger" \
  --expected-ledger-id "$procurement_reservation_ledger_id" \
  2>"$procurement_reservation_repeat_error"; then
  echo "expected repeated procurement challenge reservation to fail" >&2
  exit 1
fi
test "$marker_before" = "$(sha256sum "$procurement_reservation_marker" | cut -d' ' -f1)"
python3 - "$procurement_reservation_repeat_error" <<'PY'
from pathlib import Path
import sys

assert Path(sys.argv[1]).read_bytes() == (
    b"procurement authorization reservation failed: procurement authorization "
    b"challenge is already reserved\n"
)
PY

procurement_reservation_corrupt_marker="$procurement_reservation_corrupt_ledger/$procurement_reservation_marker_name"
printf 'corrupt-but-burned\n' >"$procurement_reservation_corrupt_marker"
if PYTHONPATH=agent/src python3 -m pcbex_agent reserve-procurement-authorization \
  "${procurement_complete_arguments[@]}" \
  --report "$procurement_authorization" \
  --approval "$procurement_approval_a" \
  --approval "$procurement_approval_b" \
  --reservation-ledger "$procurement_reservation_corrupt_ledger" \
  --expected-ledger-id "$procurement_reservation_ledger_id" \
  2>"$procurement_reservation_corrupt_error"; then
  echo "expected corrupt existing reservation marker to burn the challenge" >&2
  exit 1
fi
test "$(cat "$procurement_reservation_corrupt_marker")" = 'corrupt-but-burned'
grep -Fq 'challenge is already reserved' "$procurement_reservation_corrupt_error"

if PYTHONPATH=agent/src python3 -m pcbex_agent reserve-procurement-authorization \
  "${procurement_complete_arguments[@]}" \
  --report "$procurement_authorization_single" \
  --approval "$procurement_approval_a" \
  --reservation-ledger "$procurement_reservation_negative_ledger" \
  --expected-ledger-id "$procurement_reservation_ledger_id" \
  2>"$procurement_reservation_negative_error"; then
  echo "expected non-authorized procurement report to remain unreserved" >&2
  exit 1
fi
test ! -e "$procurement_reservation_negative_ledger/$procurement_reservation_marker_name"
grep -Fq 'fresh authorization did not authorize the exact release' \
  "$procurement_reservation_negative_error"

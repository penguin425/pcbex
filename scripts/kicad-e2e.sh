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
"$pcbex_binary" verify-circuit-kicad-handoff \
  examples/circuit-spec-v2.json "$generated_schematic" \
  --output "$generated_handoff" --require-approved
jq -e '.approved == true and .counts.errors == 0' \
  "$generated_handoff" >/dev/null

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

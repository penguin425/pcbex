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

# v1.468 reuses the exact approved procurement-intent fixture created for the
# v1.467 E2E, not the v1.467 assembly-evidence result. The caller-normalized
# offer below binds the raw intent bytes, quotes exactly 25 populated boards at
# one explicit untrusted instant, and remains a local fixture: no supplier
# request, authenticity/currentness claim, stock reservation, procurement
# authorization, payment, or order is performed.
supplier_offer="$output_directory/assembly.supplier-offer.json"
supplier_offer_schema="$output_directory/supplier-offer.schema.json"
supplier_offer_coverage_schema="$output_directory/supplier-offer-coverage.schema.json"
supplier_offer_coverage="$output_directory/assembly.supplier-offer-coverage.json"
supplier_offer_shortfall="$output_directory/assembly.supplier-offer.shortfall.json"
supplier_offer_shortfall_coverage="$output_directory/assembly.supplier-offer.shortfall.coverage.json"
supplier_offer_shortfall_gated_coverage="$output_directory/assembly.supplier-offer.shortfall.gated.coverage.json"
supplier_offer_shortfall_error="$output_directory/assembly.supplier-offer.shortfall.stderr"
supplier_offer_evaluated_at=1785715200
python3 - \
  "$assembly_procurement" \
  "$supplier_offer" \
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
    "valid_from_unix": evaluated_at - 60,
    "valid_until_unix": evaluated_at + 60,
    "currency": "USD",
    "lines": lines,
}
offer_path.write_bytes(
    json.dumps(offer, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
PY
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
python3 - \
  "$supplier_offer_coverage" \
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

(
    result_path,
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
offer_raw = offer_path.read_bytes()
offer_schema_raw = offer_schema_path.read_bytes()
coverage_schema_raw = coverage_schema_path.read_bytes()
result = json.loads(result_raw)
offer = json.loads(offer_raw)
intent = json.loads(intent_path.read_text(encoding="utf-8"))
offer_schema = json.loads(offer_schema_raw)
coverage_schema = json.loads(coverage_schema_raw)
assert result_raw == (
    json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
)
assert offer_raw == (
    json.dumps(offer, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
assert offer_schema_raw == (
    json.dumps(offer_schema, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
)
assert coverage_schema_raw == (
    json.dumps(coverage_schema, indent=2, ensure_ascii=False).encode("utf-8")
    + b"\n"
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
assert result["status"] == "covered"
assert result["covered"] is True
assert result["requested_boards"] == 25
assert result["evaluated_at_unix"] == 1785715200
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
python3 - "$supplier_offer" "$supplier_offer_shortfall" <<'PY'
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
PYTHONPATH=agent/src python3 -m pcbex_agent build-supplier-offer-coverage \
  "$assembly_board" "$assembly_manufacturing_zip" \
  --circuit-generation "$assembly_generation" \
  --catalog-snapshot "$assembly_snapshot" \
  --procurement-intent "$assembly_procurement" \
  --supplier-offer "$supplier_offer_shortfall" \
  --requested-boards 25 \
  --evaluated-at-unix "$supplier_offer_evaluated_at" \
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
  --evaluated-at-unix "$supplier_offer_evaluated_at" \
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

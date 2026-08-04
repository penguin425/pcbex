#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 PCBEX_BINARY OUTPUT_DIRECTORY" >&2
  exit 2
fi

pcbex_binary=$1
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

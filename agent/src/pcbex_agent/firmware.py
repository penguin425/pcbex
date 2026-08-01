"""Generate and verify a pinout-bound firmware/host bundle from a circuit spec."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping

from .skidl import CircuitSpecError, validate_circuit_spec

MAX_TEMPLATE_BYTES = 2 * 1024 * 1024
MAX_BUILD_SECONDS = 120


class FirmwareGenerationError(ValueError):
    """Raised when a circuit cannot produce a safe firmware bundle."""


def _spec(value: Mapping[str, Any]) -> dict[str, Any]:
    candidate = value.get("spec") if isinstance(value.get("spec"), Mapping) else value
    if not isinstance(candidate, Mapping):
        raise FirmwareGenerationError("firmware input must be a circuit spec or bundle")
    try:
        return validate_circuit_spec(candidate)
    except CircuitSpecError as error:
        raise FirmwareGenerationError(str(error)) from error


def _macro(value: str) -> str:
    output = "PCBEX_NET_"
    for character in value:
        output += character.upper() if character.isascii() and character.isalnum() else "_"
    if output.endswith("_"):
        output += "N"
    return output


def _pin_sort(value: str) -> tuple[int, int, str]:
    try:
        return (0, int(value), value)
    except ValueError:
        return (1, 0, value)


def _run(command: list[str], *, cwd: Path) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            timeout=MAX_BUILD_SECONDS,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FirmwareGenerationError(f"firmware command failed: {error}") from error
    return {
        "command": command,
        "passed": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", errors="replace")[-4096:],
        "stderr": completed.stderr.decode("utf-8", errors="replace")[-4096:],
    }


def _template(path: Path | None) -> str | None:
    if path is None:
        return None
    data = path.read_bytes()
    if not data or len(data) > MAX_TEMPLATE_BYTES:
        raise FirmwareGenerationError(
            f"firmware template must contain 1 to {MAX_TEMPLATE_BYTES} bytes"
        )
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FirmwareGenerationError(f"firmware template is not UTF-8: {path}") from error


def _write(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def _c_escape(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def firmware_bundle_json_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/circuit-firmware-v1.json",
        "title": "pcbex circuit-bound firmware bundle",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version", "mcu_reference", "pins", "files",
            "c_build", "cpp_build", "python_check", "artifacts",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "mcu_reference": {"type": "string", "minLength": 1},
            "pins": {"type": "array", "items": {"$ref": "#/$defs/pin"}},
            "files": {"type": "array", "items": {"type": "string", "minLength": 1}},
            "c_build": {"$ref": "#/$defs/build"},
            "cpp_build": {"$ref": "#/$defs/build"},
            "python_check": {"$ref": "#/$defs/build"},
            "artifacts": {"type": "array", "items": {"$ref": "#/$defs/artifact"}},
        },
        "$defs": {
            "pin": {
                "type": "object", "additionalProperties": False,
                "required": ["reference", "pin_number", "pin_name", "net_name", "gpio", "macro_name"],
                "properties": {
                    "reference": {"type": "string"}, "pin_number": {"type": "string"},
                    "pin_name": {"type": "string"}, "net_name": {"type": "string"},
                    "gpio": {"type": ["string", "null"]}, "macro_name": {"type": "string"},
                },
            },
            "build": {
                "type": "object", "additionalProperties": False,
                "required": ["attempted", "passed", "command"],
                "properties": {
                    "attempted": {"type": "boolean"}, "passed": {"type": "boolean"},
                    "command": {"type": "array", "items": {"type": "string"}},
                },
            },
            "artifact": {
                "type": "object", "additionalProperties": False,
                "required": ["path", "bytes", "sha256"],
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "bytes": {"type": "integer", "minimum": 1},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                },
            },
        },
    }


def generate_firmware_bundle(
    value: Mapping[str, Any],
    output_dir: Path,
    *,
    mcu_reference: str,
    gpio_map: Mapping[str, str] | None = None,
    cc: str = "cc",
    cxx: str = "c++",
    python: str = "python3",
    c_template: Path | None = None,
    cpp_template: Path | None = None,
    host_template: Path | None = None,
    skip_build: bool = False,
) -> dict[str, Any]:
    """Create a pinout-bound bundle and fail closed on compiler/test errors."""

    if not mcu_reference.strip():
        raise FirmwareGenerationError("mcu_reference must not be blank")
    spec = _spec(value)
    part = next((item for item in spec["parts"] if item["reference"] == mcu_reference), None)
    if part is None:
        raise FirmwareGenerationError(f"MCU reference {mcu_reference!r} is not in the circuit")
    gpio_map = {str(key): str(value) for key, value in (gpio_map or {}).items()}
    assignments: list[dict[str, Any]] = []
    for pin in sorted(part["pins"], key=_pin_sort):
        matching = next(
            (
                net["name"]
                for net in spec["nets"]
                for connection in net["connections"]
                if connection["reference"] == mcu_reference and connection["pin"] == pin
            ),
            None,
        )
        if matching is None:
            continue
        assignments.append({
            "reference": mcu_reference,
            "pin_number": pin,
            "pin_name": pin,
            "net_name": matching,
            "gpio": gpio_map.get(pin),
            "macro_name": _macro(matching),
        })
    if not assignments:
        raise FirmwareGenerationError(f"MCU {mcu_reference} has no connected pins")

    output_dir.mkdir(parents=True, exist_ok=True)
    descriptors = ",\n".join(
        "    { %s, %s, %s }" % (
            _c_escape(item["net_name"]),
            _c_escape(item["pin_number"]),
            _c_escape(item["gpio"] or ""),
        )
        for item in assignments
    )
    header_lines = [
        "/* Generated by pcbex; pinout is bound to the validated circuit spec. */",
        "#ifndef PCBEX_PINOUT_H", "#define PCBEX_PINOUT_H", "#include <stddef.h>",
        "#ifdef __cplusplus", "extern \"C\" {", "#endif",
        "typedef struct { const char *net; const char *pin; const char *gpio; } pcbex_pin_descriptor;",
        "extern const pcbex_pin_descriptor pcbex_pins[];",
        "extern const size_t pcbex_pin_count;",
    ]
    header_lines.extend(f"#define {item['macro_name']} {_c_escape(item['net_name'])}" for item in assignments)
    header_lines.extend(["#ifdef __cplusplus", "}", "#endif", "#endif"])
    header = "\n".join(header_lines) + "\n"
    c_default = (
        '#include "pinout.h"\n'
        "const pcbex_pin_descriptor pcbex_pins[] = {\n%s\n};\n"
        "const size_t pcbex_pin_count = sizeof(pcbex_pins) / sizeof(pcbex_pins[0]);\n"
        "int pcbex_firmware_init(void) { return pcbex_pin_count > 0 ? 0 : 1; }\n"
    ) % descriptors
    c_smoke = '#include "pinout.h"\nint pcbex_firmware_init(void);\nint main(void) { return pcbex_firmware_init(); }\n'
    cpp_default = (
        '#include "pinout.h"\n'
        "extern \"C\" const pcbex_pin_descriptor pcbex_pins[] = {\n%s\n};\n"
        "extern \"C\" const size_t pcbex_pin_count = sizeof(pcbex_pins) / sizeof(pcbex_pins[0]);\n"
        "extern \"C\" int pcbex_firmware_init(void) { return pcbex_pin_count > 0 ? 0 : 1; }\n"
    ) % descriptors
    cpp_smoke = 'extern "C" int pcbex_firmware_init(void);\nint main() { return pcbex_firmware_init(); }\n'
    host_default = (
        "#!/usr/bin/env python3\n"
        "import json\n"
        "PINS = %r\n"
        "def self_test():\n    assert PINS\n    assert all(item['net'] and item['pin'] for item in PINS)\n"
        "if __name__ == '__main__':\n    self_test()\n    print(json.dumps(PINS, sort_keys=True))\n"
    ) % [
        {"net": item["net_name"], "pin": item["pin_number"], "gpio": item["gpio"]}
        for item in assignments
    ]
    _write(output_dir / "pinout.h", header)
    _write(output_dir / "firmware.c", _template(c_template) or c_default)
    _write(output_dir / "firmware_smoke_test.c", c_smoke)
    _write(output_dir / "firmware.cpp", _template(cpp_template) or cpp_default)
    _write(output_dir / "firmware_cpp_smoke_test.cpp", cpp_smoke)
    _write(output_dir / "host.py", _template(host_template) or host_default)

    if skip_build:
        c_build = {"attempted": False, "passed": False, "command": []}
        cpp_build = {"attempted": False, "passed": False, "command": []}
        python_check = {"attempted": False, "passed": False, "command": []}
    else:
        c_command = [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", str(output_dir),
                     str(output_dir / "firmware.c"), str(output_dir / "firmware_smoke_test.c"),
                     "-o", str(output_dir / "firmware_smoke_test")]
        c_result = _run(c_command, cwd=output_dir)
        c_build = {"attempted": True, "passed": c_result["passed"], "command": c_command}
        if not c_result["passed"]:
            raise FirmwareGenerationError(f"C firmware build failed: {c_result['stderr']}")
        cpp_command = [cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", str(output_dir),
                       str(output_dir / "firmware.cpp"), str(output_dir / "firmware_cpp_smoke_test.cpp"),
                       "-o", str(output_dir / "firmware_cpp_smoke_test")]
        cpp_result = _run(cpp_command, cwd=output_dir)
        cpp_build = {"attempted": True, "passed": cpp_result["passed"], "command": cpp_command}
        if not cpp_result["passed"]:
            raise FirmwareGenerationError(f"C++ firmware build failed: {cpp_result['stderr']}")
        for binary in ("firmware_smoke_test", "firmware_cpp_smoke_test"):
            smoke = _run([str(output_dir / binary)], cwd=output_dir)
            if not smoke["passed"]:
                raise FirmwareGenerationError(f"{binary} failed")
        python_command = [python, "-m", "py_compile", str(output_dir / "host.py")]
        python_result = _run(python_command, cwd=output_dir)
        python_check = {"attempted": True, "passed": python_result["passed"], "command": python_command}
        if not python_result["passed"]:
            raise FirmwareGenerationError(f"Python firmware host check failed: {python_result['stderr']}")
        host = _run([python, str(output_dir / "host.py")], cwd=output_dir)
        if not host["passed"]:
            raise FirmwareGenerationError("Python firmware host self-test failed")

    files = sorted(path.name for path in output_dir.iterdir() if path.is_file() and path.name != "manifest.json")
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "mcu_reference": mcu_reference,
        "pins": assignments,
        "files": files,
        "c_build": c_build,
        "cpp_build": cpp_build,
        "python_check": python_check,
        "artifacts": [],
    }
    manifest["artifacts"] = [
        {"path": name, "bytes": (output_dir / name).stat().st_size,
         "sha256": hashlib.sha256((output_dir / name).read_bytes()).hexdigest()}
        for name in files
    ]
    _write(output_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return manifest

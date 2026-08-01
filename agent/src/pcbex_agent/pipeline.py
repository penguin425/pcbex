"""Fail-closed, headless orchestration of the hardware development stages."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from .catalog import catalog_parts_from_json
from .catalog_remote import CatalogEndpoint, fetch_catalog
from .circuit import circuit_spec_to_kicad_pcb, circuit_spec_to_netlist
from .circuit_generation import generate_circuit_with_llm
from .firmware import generate_firmware_bundle
from .factory import FactoryEndpoint, submit_factory_package
from .provider import ProviderError, run_provider_command
from .skidl import CircuitSpecError, assign_catalog_parts, generate_skidl

MAX_PIPELINE_SECONDS = 1800
MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024


class PipelineRunError(RuntimeError):
    """Raised when a pipeline phase cannot produce its required artifact."""


def pipeline_run_json_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/pipeline-run-v1.json",
        "title": "pcbex headless end-to-end pipeline report",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "pipeline", "passed", "phases", "failures"],
        "properties": {
            "schema_version": {"const": 1},
            "pipeline": {"const": "pcbex-end-to-end-v1"},
            "passed": {"type": "boolean"},
            "failures": {"type": "array", "items": {"type": "string"}},
            "phases": {"type": "array", "items": {"$ref": "#/$defs/phase"}},
        },
        "$defs": {
            "phase": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "passed", "started_at", "duration_ms", "artifacts", "checks", "failures"],
                "properties": {
                    "name": {"type": "string"},
                    "passed": {"type": "boolean"},
                    "started_at": {"type": "string"},
                    "duration_ms": {"type": "integer", "minimum": 0},
                    "artifacts": {"type": "array", "items": {"type": "string"}},
                    "checks": {"type": "array", "items": {"type": "string"}},
                    "failures": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    }


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    input_bytes: bytes | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if not command or not command[0].strip():
        raise PipelineRunError("pipeline command must not be empty")
    if not 1 <= timeout_seconds <= MAX_PIPELINE_SECONDS:
        raise PipelineRunError("pipeline command timeout is outside 1..1800 seconds")
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            shell=False,
            env=dict(environment) if environment is not None else None,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PipelineRunError(f"command {' '.join(command[:3])} failed: {error}") from error
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if len(stdout) > MAX_COMMAND_OUTPUT_BYTES or len(stderr) > MAX_COMMAND_OUTPUT_BYTES:
        raise PipelineRunError("pipeline command output exceeded bounded limit")
    return {
        "command": list(command),
        "returncode": completed.returncode,
        "passed": completed.returncode == 0,
        "stdout": stdout.decode("utf-8", errors="replace")[-4096:],
        "stderr": stderr.decode("utf-8", errors="replace")[-4096:],
    }


def _phase(name: str, started: float, artifacts: Sequence[Path], checks: Sequence[str], failures: Sequence[str]) -> dict[str, Any]:
    return {
        "name": name,
        "passed": not failures,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "artifacts": [str(path) for path in artifacts],
        "checks": list(checks),
        "failures": list(failures),
    }


def _load_factory_command(path: Path | None) -> list[str] | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        raise PipelineRunError("factory command file must contain a non-empty string array")
    return value


def _package_manufacturing(directory: Path, output: Path, spec: Mapping[str, Any]) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    bom = directory / "bom.csv"
    with bom.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["Reference", "Value", "Footprint", "MPN"])
        for part in sorted(spec["parts"], key=lambda item: item["reference"]):
            writer.writerow([part["reference"], part["value"], part["footprint"], part.get("mpn") or ""])
    cpl = directory / "cpl.csv"
    with cpl.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["Reference", "X_mm", "Y_mm", "Rotation_deg", "Side"])
        for part in sorted(spec["parts"], key=lambda item: item["reference"]):
            writer.writerow([part["reference"], "0", "0", "0", "F.Cu"])
    files = sorted(path for path in directory.rglob("*") if path.is_file() and path.name != "manifest.json")
    archive = output / "manufacturing.zip"
    output.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for path in files:
            zipped.write(path, path.relative_to(directory).as_posix())
    manifest = {
        "schema_version": 1,
        "archive": archive.name,
        "artifacts": [
            {
                "path": path.relative_to(directory).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in files
        ],
        "archive_sha256": _sha256(archive),
        "archive_bytes": archive.stat().st_size,
    }
    _write_json(output / "manifest.json", manifest)
    return manifest


def _factory_receipt(
    package: Path,
    *,
    command: list[str] | None,
    receipt_path: Path | None,
    workspace: Path,
    timeout_seconds: int,
    provider: str,
) -> dict[str, Any]:
    if receipt_path is not None:
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise PipelineRunError("factory receipt must be a JSON object")
        return value
    if command is None:
        raise PipelineRunError("factory receipt or factory command is required")
    environment = os.environ.copy()
    environment.update({
        "PCBEX_PACKAGE_PATH": str(package),
        "PCBEX_PACKAGE_SHA256": _sha256(package),
        "PCBEX_FACTORY_PROVIDER": provider,
    })
    result = _run_command(
        command,
        cwd=workspace,
        timeout_seconds=timeout_seconds,
        input_bytes=package.read_bytes(),
        environment=environment,
    )
    if not result["passed"]:
        raise PipelineRunError(f"factory command failed: {result['stderr']}")
    try:
        value = json.loads(result["stdout"])
    except json.JSONDecodeError as error:
        raise PipelineRunError(f"factory command did not return JSON: {error}") from error
    if not isinstance(value, dict):
        raise PipelineRunError("factory command response must be a JSON object")
    return value


def run_hardware_pipeline(
    requirements: Path,
    output_dir: Path,
    *,
    provider_command: list[str],
    footprint_sizes: Path,
    board_width_nm: int,
    board_height_nm: int,
    mcu_reference: str,
    pcbex: str = "pcbex",
    catalog: Path | None = None,
    catalog_endpoint: CatalogEndpoint | None = None,
    require_basic: bool = False,
    physical_profile: Path | None = None,
    fab: str | None = None,
    convergence_rounds: int = 4,
    max_copper_layers: int = 4,
    placement_iterations: int | None = None,
    seed: int | None = None,
    factory_command_file: Path | None = None,
    factory_receipt: Path | None = None,
    factory_provider: str = "generic",
    factory_endpoint: FactoryEndpoint | None = None,
    require_factory: bool = False,
    factory_timeout_seconds: int = 300,
    gpio_map: Path | None = None,
    c_compiler: str = "cc",
    cxx_compiler: str = "c++",
    python: str = "python3",
    c_template: Path | None = None,
    cpp_template: Path | None = None,
    host_template: Path | None = None,
) -> dict[str, Any]:
    """Run all available stages and retain a phase report on every outcome."""

    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise PipelineRunError(f"pipeline output directory is not empty: {output_dir}")
    sizes = json.loads(footprint_sizes.read_text(encoding="utf-8"))
    requirements_text = requirements.read_text(encoding="utf-8")
    phases: list[dict[str, Any]] = []
    failures: list[str] = []
    bundle: dict[str, Any] | None = None

    def finalize() -> dict[str, Any]:
        report = {
            "schema_version": 1,
            "pipeline": "pcbex-end-to-end-v1",
            "passed": not failures and all(phase["passed"] for phase in phases),
            "phases": phases,
            "failures": failures,
        }
        _write_json(output_dir / "pipeline.json", report)
        return report

    started = time.monotonic()
    try:
        bundle = generate_circuit_with_llm(
            requirements_text,
            lambda prompt: run_provider_command(provider_command, prompt),
        )
        spec = bundle["spec"]
        if catalog is not None:
            spec = assign_catalog_parts(
                spec,
                catalog_parts_from_json(json.loads(catalog.read_text(encoding="utf-8"))),
                require_available=True,
                require_basic=require_basic,
            )
        elif catalog_endpoint is not None:
            spec = assign_catalog_parts(
                spec,
                fetch_catalog(catalog_endpoint),
                require_available=True,
                require_basic=require_basic,
            )
        bundle["spec"] = spec
        bundle["skidl"] = generate_skidl(spec)
        _write_json(output_dir / "circuit-generation.json", bundle)
        (output_dir / "circuit.py").write_text(bundle["skidl"], encoding="utf-8")
        netlist = circuit_spec_to_netlist(spec)
        _write_json(output_dir / "netlist.json", netlist)
        phases.append(_phase("circuit-generation", started, [output_dir / "circuit-generation.json", output_dir / "circuit.py", output_dir / "netlist.json"], ["closed-spec", "electrical-erc", f"netlist-sha256={netlist['sha256']}"], []))
    except (OSError, ProviderError, CircuitSpecError, PipelineRunError, ValueError) as error:
        failures.append(f"circuit-generation: {error}")
        phases.append(_phase("circuit-generation", started, [], [], [str(error)]))
    if bundle is None:
        return finalize()

    spec = bundle["spec"]
    started = time.monotonic()
    try:
        board = circuit_spec_to_kicad_pcb(spec, sizes, width_nm=board_width_nm, height_nm=board_height_nm)
        board_path = output_dir / "circuit.kicad_pcb"
        board_path.write_text(board, encoding="utf-8")
        phases.append(_phase("circuit-kicad-handoff", started, [board_path], ["references", "pin-net assignments"], []))
    except (OSError, CircuitSpecError) as error:
        failures.append(f"circuit-kicad-handoff: {error}")
        phases.append(_phase("circuit-kicad-handoff", started, [], [], [str(error)]))
        return finalize()

    placed = output_dir / "placed.kicad_pcb"
    placement_json = output_dir / "placement.json"
    started = time.monotonic()
    try:
        command = [pcbex, "place-kicad", str(output_dir / "circuit.kicad_pcb"), "--output", str(placed), "--json-output", str(placement_json)]
        if placement_iterations is not None:
            command.extend(["--iterations", str(placement_iterations)])
        if seed is not None:
            command.extend(["--seed", str(seed)])
        result = _run_command(command, cwd=output_dir, timeout_seconds=600)
        if not result["passed"]:
            raise PipelineRunError(result["stderr"] or "placement command failed")
        phases.append(_phase("placement", started, [placed, placement_json], ["pcbex place-kicad"], []))
    except (PipelineRunError, OSError) as error:
        failures.append(f"placement: {error}")
        phases.append(_phase("placement", started, [], [], [str(error)]))
        return finalize()

    routed = output_dir / "routed.kicad_pcb"
    route_json = output_dir / "route.json"
    started = time.monotonic()
    try:
        command = [pcbex, "route-kicad", str(placed), "--output", str(routed), "--json-output", str(route_json), "--drc"]
        if physical_profile is not None:
            command.extend(["--physical-profile", str(physical_profile)])
        if fab is not None:
            command.extend(["--fab", fab])
        # These options are present on the autonomous-routing stack. The runner
        # keeps them explicit so older binaries fail with a useful capability error.
        command.extend(["--convergence-rounds", str(convergence_rounds), "--max-copper-layers", str(max_copper_layers)])
        result = _run_command(command, cwd=output_dir, timeout_seconds=900)
        if not result["passed"]:
            raise PipelineRunError(result["stderr"] or "routing command failed")
        phases.append(_phase("autonomous-routing-drc", started, [routed, route_json], ["convergence", "drc=0"], []))
    except (PipelineRunError, OSError) as error:
        failures.append(f"autonomous-routing-drc: {error}")
        phases.append(_phase("autonomous-routing-drc", started, [], [], [str(error)]))
        return finalize()

    manufacturing = output_dir / "manufacturing"
    started = time.monotonic()
    try:
        result = _run_command([pcbex, "fabricate", str(routed), "--output-dir", str(manufacturing)], cwd=output_dir, timeout_seconds=900)
        if not result["passed"]:
            raise PipelineRunError(result["stderr"] or "fabrication command failed")
        manifest = _package_manufacturing(manufacturing, manufacturing, spec)
        phases.append(_phase("manufacturing-package", started, [manufacturing / "manifest.json", manufacturing / "manufacturing.zip"], ["gerber", "excellon", "bom", "cpl", "sha256"], []))
    except (PipelineRunError, OSError, ValueError) as error:
        failures.append(f"manufacturing-package: {error}")
        phases.append(_phase("manufacturing-package", started, [], [], [str(error)]))
        return finalize()

    firmware = output_dir / "firmware"
    started = time.monotonic()
    try:
        gpio = json.loads(gpio_map.read_text(encoding="utf-8")) if gpio_map else {}
        manifest = generate_firmware_bundle(
            spec,
            firmware,
            mcu_reference=mcu_reference,
            gpio_map=gpio,
            cc=c_compiler,
            cxx=cxx_compiler,
            python=python,
            c_template=c_template,
            cpp_template=cpp_template,
            host_template=host_template,
        )
        phases.append(_phase("firmware-build", started, [firmware / "manifest.json"], ["c11", "c++17", "python"], [] if manifest["c_build"]["passed"] and manifest["cpp_build"]["passed"] and manifest["python_check"]["passed"] else ["firmware build gate failed"]))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        failures.append(f"firmware-build: {error}")
        phases.append(_phase("firmware-build", started, [], [], [str(error)]))
        return finalize()

    if require_factory or factory_command_file is not None or factory_receipt is not None or factory_endpoint is not None:
        started = time.monotonic()
        try:
            command = _load_factory_command(factory_command_file)
            if factory_endpoint is not None and factory_receipt is None and command is None:
                receipt = submit_factory_package(manufacturing / "manufacturing.zip", factory_endpoint)
            else:
                receipt = _factory_receipt(
                    manufacturing / "manufacturing.zip",
                    command=command,
                    receipt_path=factory_receipt,
                    workspace=output_dir,
                    timeout_seconds=factory_timeout_seconds,
                    provider=factory_provider,
                )
            _write_json(output_dir / "factory-receipt.json", receipt)
            accepted = receipt.get("accepted") is True
            dfm_passed = receipt.get("dfm_passed")
            if dfm_passed is None and isinstance(receipt.get("dfm"), Mapping):
                dfm_passed = receipt["dfm"].get("passed")
            if not accepted or dfm_passed is not True:
                raise PipelineRunError("factory receipt is not accepted and DFM-passed")
            phases.append(_phase("factory-dfm", started, [output_dir / "factory-receipt.json"], ["accepted", "dfm_passed"], []))
        except (OSError, PipelineRunError, ValueError, json.JSONDecodeError) as error:
            failures.append(f"factory-dfm: {error}")
            phases.append(_phase("factory-dfm", started, [], [], [str(error)]))

    return finalize()

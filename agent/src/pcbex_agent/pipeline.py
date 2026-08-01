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
MAX_FACTORY_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_FACTORY_ATTEMPTS = 4


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


def _apply_physical_profile_metadata(
    spec: Mapping[str, Any],
    footprint_sizes: Mapping[str, Any],
    profile_path: Path | None,
    *,
    board_width_nm: int,
    board_height_nm: int,
) -> dict[str, Any]:
    """Bind fixed profile coordinates to the library-independent PCB handoff.

    The Rust router applies the complete profile (including keepouts and DFM
    rules) later.  The handoff must nevertheless carry fixed component
    coordinates and lock those footprints before ``place-kicad`` runs, or the
    placement optimizer could move a mechanically constrained connector.
    """

    if profile_path is None:
        return dict(footprint_sizes)
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineRunError(f"invalid physical profile: {error}") from error
    if not isinstance(profile, Mapping) or profile.get("schema_version") != 1:
        raise PipelineRunError("physical profile must be a schema_version 1 object")
    if profile.get("board_width_nm") != board_width_nm or profile.get("board_height_nm") != board_height_nm:
        raise PipelineRunError("physical profile board dimensions must match pipeline dimensions")
    fixed_components = profile.get("fixed_components", [])
    if not isinstance(fixed_components, list):
        raise PipelineRunError("physical profile fixed_components must be an array")
    parts = spec.get("parts")
    if not isinstance(parts, list):
        raise PipelineRunError("circuit spec parts must be an array")
    parts_by_reference = {part.get("reference"): part for part in parts if isinstance(part, Mapping)}
    result: dict[str, Any] = dict(footprint_sizes)
    seen: set[str] = set()
    for fixed in fixed_components:
        if not isinstance(fixed, Mapping):
            raise PipelineRunError("physical profile fixed component must be an object")
        reference = fixed.get("reference")
        if not isinstance(reference, str) or not reference.strip() or reference in seen:
            raise PipelineRunError("physical profile fixed component references must be unique and non-empty")
        seen.add(reference)
        part = parts_by_reference.get(reference)
        if not isinstance(part, Mapping):
            raise PipelineRunError(f"physical profile fixed component {reference} is not in the circuit")
        x_nm = fixed.get("x_nm")
        y_nm = fixed.get("y_nm")
        rotation_mdeg = fixed.get("rotation_mdeg", 0)
        if (
            isinstance(x_nm, bool) or not isinstance(x_nm, int)
            or isinstance(y_nm, bool) or not isinstance(y_nm, int)
            or isinstance(rotation_mdeg, bool) or not isinstance(rotation_mdeg, int)
            or x_nm < 0 or y_nm < 0 or x_nm > board_width_nm or y_nm > board_height_nm
        ):
            raise PipelineRunError(f"physical profile fixed component {reference} has invalid position")
        source = result.get(reference)
        if source is None:
            source = result.get(str(part.get("footprint")))
        if isinstance(source, Mapping):
            dimensions = dict(source)
        elif isinstance(source, Sequence) and not isinstance(source, (str, bytes)) and len(source) == 2:
            dimensions = {"width_nm": source[0], "height_nm": source[1]}
        else:
            raise PipelineRunError(f"missing footprint dimensions for fixed component {reference}")
        dimensions.update({
            "position": {"x_nm": x_nm, "y_nm": y_nm},
            "rotation_deg": rotation_mdeg / 1000,
            "fixed": True,
        })
        result[reference] = dimensions
    return result


def _load_placement_components(path: Path) -> dict[str, Mapping[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineRunError(f"invalid placement report: {error}") from error
    components = value.get("components") if isinstance(value, Mapping) else None
    if not isinstance(components, list):
        raise PipelineRunError("placement report must contain a components array")
    result: dict[str, Mapping[str, Any]] = {}
    for component in components:
        if not isinstance(component, Mapping):
            raise PipelineRunError("placement component must be an object")
        reference = component.get("reference")
        position = component.get("position")
        if not isinstance(reference, str) or not reference.strip() or reference in result:
            raise PipelineRunError("placement references must be unique and non-empty")
        if not isinstance(position, Mapping):
            raise PipelineRunError(f"placement component {reference} has no position")
        x_nm = position.get("x_nm")
        y_nm = position.get("y_nm")
        if (
            isinstance(x_nm, bool) or not isinstance(x_nm, int)
            or isinstance(y_nm, bool) or not isinstance(y_nm, int)
        ):
            raise PipelineRunError(f"placement component {reference} has invalid coordinates")
        rotation = component.get("rotation_deg", 0)
        if isinstance(rotation, bool) or not isinstance(rotation, (int, float)):
            raise PipelineRunError(f"placement component {reference} has invalid rotation")
        side = component.get("side", "front")
        if side not in {"front", "back"}:
            raise PipelineRunError(f"placement component {reference} has invalid side")
        result[reference] = {
            "x_nm": x_nm,
            "y_nm": y_nm,
            "rotation_deg": rotation,
            "side": side,
        }
    return result


def _package_manufacturing(
    directory: Path,
    output: Path,
    spec: Mapping[str, Any],
    *,
    placement_report: Path,
) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    placements = _load_placement_components(placement_report)
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
            reference = part["reference"]
            placement = placements.get(reference)
            if placement is None:
                raise PipelineRunError(f"placement report is missing {reference}")
            writer.writerow([
                reference,
                f"{placement['x_nm'] / 1_000_000:.6f}",
                f"{placement['y_nm'] / 1_000_000:.6f}",
                f"{placement['rotation_deg']:.6f}".rstrip("0").rstrip("."),
                "B.Cu" if placement["side"] == "back" else "F.Cu",
            ])
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


def _factory_passed(receipt: Mapping[str, Any]) -> bool:
    if receipt.get("accepted") is not True:
        return False
    dfm_passed = receipt.get("dfm_passed")
    if dfm_passed is None and isinstance(receipt.get("dfm"), Mapping):
        dfm_passed = receipt["dfm"].get("passed")
    return dfm_passed is True


def _validate_factory_package(path: Path) -> None:
    try:
        metadata = path.stat()
    except OSError as error:
        raise PipelineRunError(f"factory repair did not create a package: {error}") from error
    if not path.is_file() or metadata.st_size == 0 or metadata.st_size > MAX_FACTORY_PACKAGE_BYTES:
        raise PipelineRunError(
            f"factory repair package must contain 1 to {MAX_FACTORY_PACKAGE_BYTES} bytes"
        )
    if not zipfile.is_zipfile(path):
        raise PipelineRunError("factory repair output must be a ZIP archive")


def _run_factory_feedback_loop(
    package: Path,
    *,
    command: list[str] | None,
    receipt_path: Path | None,
    repair_command: list[str] | None,
    factory_endpoint: FactoryEndpoint | None,
    workspace: Path,
    timeout_seconds: int,
    provider: str,
    max_attempts: int,
    report_path: Path,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Submit DFM feedback and optionally repair/resubmit a bounded number of times."""

    if not 1 <= max_attempts <= MAX_FACTORY_ATTEMPTS:
        raise PipelineRunError(f"factory max attempts must be between 1 and {MAX_FACTORY_ATTEMPTS}")
    if factory_endpoint is None and command is None and receipt_path is None:
        raise PipelineRunError("factory endpoint, command, or receipt is required")
    if receipt_path is not None:
        if repair_command is not None:
            raise PipelineRunError("a fixed factory receipt cannot be combined with repair attempts")
        max_attempts = 1
    current = package
    attempts: list[dict[str, Any]] = []
    receipt: dict[str, Any] | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            if factory_endpoint is not None and receipt_path is None and command is None:
                receipt = submit_factory_package(current, factory_endpoint)
            else:
                receipt = _factory_receipt(
                    current,
                    command=command,
                    receipt_path=receipt_path if attempt == 1 else None,
                    workspace=workspace,
                    timeout_seconds=timeout_seconds,
                    provider=provider,
                )
        except (OSError, PipelineRunError, ValueError) as error:
            _write_json(report_path, {
                "schema_version": 1,
                "attempts": attempts,
                "passed": False,
                "failure": str(error),
            })
            raise
        passed = _factory_passed(receipt)
        attempts.append({
            "attempt": attempt,
            "package": current.name,
            "package_sha256": _sha256(current),
            "accepted": receipt.get("accepted"),
            "dfm_passed": receipt.get("dfm_passed"),
            "passed": passed,
        })
        if passed:
            report = {"schema_version": 1, "attempts": attempts, "passed": True}
            _write_json(report_path, report)
            return current, receipt, report
        if repair_command is None or attempt == max_attempts:
            break
        repaired = workspace / f"manufacturing-repaired-{attempt}.zip"
        environment = os.environ.copy()
        environment.update({
            "PCBEX_FACTORY_REPAIR_INPUT_PACKAGE": str(current),
            "PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE": str(repaired),
            "PCBEX_FACTORY_REPAIR_RECEIPT_JSON": "stdin",
            "PCBEX_FACTORY_PROVIDER": provider,
        })
        try:
            result = _run_command(
                repair_command,
                cwd=workspace,
                timeout_seconds=timeout_seconds,
                input_bytes=(json.dumps(receipt, ensure_ascii=False) + "\n").encode("utf-8"),
                environment=environment,
            )
            if not result["passed"]:
                raise PipelineRunError(f"factory repair command failed: {result['stderr']}")
            _validate_factory_package(repaired)
        except (OSError, PipelineRunError, ValueError) as error:
            _write_json(report_path, {
                "schema_version": 1,
                "attempts": attempts,
                "passed": False,
                "failure": str(error),
            })
            raise
        current = repaired
    assert receipt is not None
    report = {"schema_version": 1, "attempts": attempts, "passed": False}
    _write_json(report_path, report)
    return current, receipt, report


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
    factory_repair_command_file: Path | None = None,
    factory_max_attempts: int = MAX_FACTORY_ATTEMPTS,
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
    try:
        sizes = json.loads(footprint_sizes.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineRunError(f"invalid footprint size map: {error}") from error
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
        handoff_sizes = _apply_physical_profile_metadata(
            spec,
            sizes,
            physical_profile,
            board_width_nm=board_width_nm,
            board_height_nm=board_height_nm,
        )
        board = circuit_spec_to_kicad_pcb(
            spec,
            handoff_sizes,
            width_nm=board_width_nm,
            height_nm=board_height_nm,
        )
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
        manifest = _package_manufacturing(
            manufacturing,
            manufacturing,
            spec,
            placement_report=placement_json,
        )
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

    if (
        require_factory
        or factory_command_file is not None
        or factory_repair_command_file is not None
        or factory_receipt is not None
        or factory_endpoint is not None
    ):
        started = time.monotonic()
        try:
            command = _load_factory_command(factory_command_file)
            repair_command = _load_factory_command(factory_repair_command_file)
            final_package, receipt, loop_report = _run_factory_feedback_loop(
                manufacturing / "manufacturing.zip",
                command=command,
                receipt_path=factory_receipt,
                repair_command=repair_command,
                factory_endpoint=factory_endpoint,
                workspace=output_dir,
                timeout_seconds=factory_timeout_seconds,
                provider=factory_provider,
                max_attempts=factory_max_attempts,
                report_path=output_dir / "factory-loop.json",
            )
            _write_json(output_dir / "factory-receipt.json", receipt)
            if not _factory_passed(receipt):
                raise PipelineRunError("factory receipt is not accepted and DFM-passed")
            artifacts = [output_dir / "factory-receipt.json", output_dir / "factory-loop.json"]
            if final_package != manufacturing / "manufacturing.zip":
                artifacts.append(final_package)
            phases.append(_phase("factory-dfm", started, artifacts, ["accepted", "dfm_passed", f"attempts={len(loop_report['attempts'])}"], []))
        except (OSError, PipelineRunError, ValueError, json.JSONDecodeError) as error:
            failures.append(f"factory-dfm: {error}")
            phases.append(_phase("factory-dfm", started, [], [], [str(error)]))

    return finalize()

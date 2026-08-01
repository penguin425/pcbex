from __future__ import annotations

import argparse
import json
from pathlib import Path

from .catalog import catalog_parts_from_json
from .catalog_remote import CatalogEndpoint, CatalogRemoteError, fetch_catalog
from .circuit_generation import (
    CircuitGenerationError,
    circuit_generation_json_schema,
    generate_circuit_with_llm,
)
from .circuit import circuit_spec_to_kicad_pcb, circuit_spec_to_placement_problem
from .drc import normalize_kicad_report
from .executor import apply_constraints
from .ipc import apply_routes_to_open_board
from .models import PlanLimits
from .managed_provider import (
    managed_provider_receipt_json_schema,
    review_schematic_with_managed_provider,
)
from .planner import build_plan
from .provider import (
    ProviderError,
    provider_receipt_json_schema,
    run_provider_command,
    review_schematic_with_command,
)
from .repair import propose_repairs
from .repair_loop import repair_kicad_board, write_repair_report
from .review import ReviewError
from .skidl import (
    CircuitSpecError,
    assign_catalog_parts,
    check_circuit_electrical,
    circuit_erc_json_schema,
    circuit_spec_json_schema,
    generate_skidl,
)


def main() -> None:
    parser = argparse.ArgumentParser(prog="pcbex-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="convert requirements into an execution plan")
    plan.add_argument("requirements", type=Path)
    plan.add_argument("-o", "--output", type=Path, required=True)
    plan.add_argument("--max-iterations", type=int, default=3)
    plan.add_argument("--max-changed-components", type=int, default=12)
    apply = sub.add_parser("apply-constraints", help="merge planned placement constraints")
    apply.add_argument("problem", type=Path)
    apply.add_argument("plan", type=Path)
    apply.add_argument("-o", "--output", type=Path, required=True)
    drc = sub.add_parser("normalize-drc", help="normalize and propose repairs for KiCad DRC")
    drc.add_argument("report", type=Path)
    drc.add_argument("-o", "--output", type=Path, required=True)
    ipc = sub.add_parser("apply-ipc", help="apply routed JSON to the open KiCad board")
    ipc.add_argument("routes", type=Path)
    ipc.add_argument("--max-items", type=int, default=10000)
    review = sub.add_parser(
        "review-schematic",
        help="run a bounded external AI review provider and retain an audit receipt",
    )
    review.add_argument("request", type=Path)
    review.add_argument("-o", "--output", type=Path, required=True)
    review.add_argument("--receipt", type=Path, required=True)
    review.add_argument("--timeout-seconds", type=int, default=120)
    review.add_argument("--maximum-output-bytes", type=int, default=1024 * 1024)
    review.add_argument(
        "--provider-command",
        nargs=argparse.REMAINDER,
        required=True,
        help="executable and arguments; must be the final pcbex-agent option",
    )
    receipt_schema = sub.add_parser(
        "provider-receipt-schema",
        help="write the closed provider-command receipt JSON Schema",
    )
    receipt_schema.add_argument("-o", "--output", type=Path)
    managed_review = sub.add_parser(
        "review-managed",
        help="run a bounded managed AI provider review and retain an audit receipt",
    )
    managed_review.add_argument("request", type=Path)
    managed_review.add_argument("-o", "--output", type=Path, required=True)
    managed_review.add_argument("--receipt", type=Path, required=True)
    managed_review.add_argument(
        "--provider", choices=("openai", "anthropic", "gemini"), required=True
    )
    managed_review.add_argument("--model", required=True)
    managed_review.add_argument("--model-version")
    managed_review.add_argument("--api-key-environment")
    managed_review.add_argument("--endpoint")
    managed_review.add_argument("--timeout-seconds", type=int, default=120)
    managed_review.add_argument(
        "--maximum-response-bytes", type=int, default=1024 * 1024
    )
    managed_review.add_argument("--maximum-output-tokens", type=int, default=4096)
    managed_schema = sub.add_parser(
        "managed-provider-receipt-schema",
        help="write the closed managed-provider receipt JSON Schema",
    )
    managed_schema.add_argument("-o", "--output", type=Path)
    skidl = sub.add_parser(
        "generate-skidl",
        help="validate a closed circuit spec, select available parts, and generate SKiDL",
    )
    skidl.add_argument("spec", type=Path)
    skidl.add_argument("-o", "--output", type=Path, required=True)
    skidl.add_argument(
        "--catalog",
        type=Path,
        help="optional vendor-neutral catalog JSON array used for missing MPNs",
    )
    skidl.add_argument(
        "--catalog-endpoint",
        help="HTTPS catalog gateway endpoint for live supplier inventory",
    )
    skidl.add_argument(
        "--catalog-provider",
        choices=("jlcpcb", "digikey", "lcsc", "generic"),
        default="generic",
    )
    skidl.add_argument(
        "--catalog-bearer-token-environment",
        help="environment variable containing an optional catalog Bearer token",
    )
    skidl.add_argument("--catalog-timeout-seconds", type=float, default=20.0)
    skidl.add_argument(
        "--allow-http-loopback",
        action="store_true",
        help="test-only: permit a loopback HTTP catalog endpoint",
    )
    skidl.add_argument(
        "--allow-out-of-stock",
        action="store_true",
        help="allow catalog candidates with zero reported stock",
    )
    skidl.add_argument(
        "--require-basic",
        action="store_true",
        help="restrict automatic selection to basic parts",
    )
    skidl.add_argument(
        "--no-netlist",
        action="store_true",
        help="omit generate_netlist() from the generated source",
    )
    skidl.add_argument(
        "--erc-output",
        type=Path,
        help="write the deterministic circuit ERC report alongside the SKiDL source",
    )
    skidl_schema = sub.add_parser(
        "circuit-spec-schema", help="write the closed Text-to-Circuit JSON Schema"
    )
    skidl_schema.add_argument("-o", "--output", type=Path)
    circuit_to_placement = sub.add_parser(
        "circuit-to-placement",
        help="convert a validated circuit spec into a pcbex placement problem",
    )
    circuit_to_placement.add_argument("spec", type=Path)
    circuit_to_placement.add_argument("--footprint-sizes", type=Path, required=True)
    circuit_to_placement.add_argument("--board-width-nm", type=int, required=True)
    circuit_to_placement.add_argument("--board-height-nm", type=int, required=True)
    circuit_to_placement.add_argument("--grid-nm", type=int, default=250_000)
    circuit_to_placement.add_argument("--constraints", type=Path)
    circuit_to_placement.add_argument("-o", "--output", type=Path, required=True)
    circuit_to_kicad = sub.add_parser(
        "circuit-to-kicad",
        help="render a validated circuit spec as a minimal KiCad PCB handoff",
    )
    circuit_to_kicad.add_argument("spec", type=Path)
    circuit_to_kicad.add_argument("--footprint-sizes", type=Path, required=True)
    circuit_to_kicad.add_argument("--board-width-nm", type=int, required=True)
    circuit_to_kicad.add_argument("--board-height-nm", type=int, required=True)
    circuit_to_kicad.add_argument("--grid-nm", type=int, default=250_000)
    circuit_to_kicad.add_argument("-o", "--output", type=Path, required=True)
    erc_schema = sub.add_parser(
        "circuit-erc-schema", help="write the closed deterministic circuit ERC JSON Schema"
    )
    erc_schema.add_argument("-o", "--output", type=Path)
    generate_circuit = sub.add_parser(
        "generate-circuit",
        help="convert natural-language requirements into a validated circuit bundle",
    )
    generate_circuit.add_argument("requirements", type=Path)
    generate_circuit.add_argument("-o", "--output", type=Path, required=True)
    generate_circuit.add_argument(
        "--skidl-output",
        type=Path,
        help="also write the validated generated SKiDL source",
    )
    generate_circuit.add_argument("--max-attempts", type=int, default=3)
    generate_circuit.add_argument("--timeout-seconds", type=int, default=120)
    generate_circuit.add_argument("--maximum-output-bytes", type=int, default=1024 * 1024)
    generate_circuit.add_argument(
        "--catalog",
        type=Path,
        help="optional vendor-neutral catalog for deterministic MPN assignment",
    )
    generate_circuit.add_argument("--catalog-endpoint")
    generate_circuit.add_argument(
        "--catalog-provider",
        choices=("jlcpcb", "digikey", "lcsc", "generic"),
        default="generic",
    )
    generate_circuit.add_argument("--catalog-bearer-token-environment")
    generate_circuit.add_argument("--catalog-timeout-seconds", type=float, default=20.0)
    generate_circuit.add_argument("--allow-http-loopback", action="store_true")
    generate_circuit.add_argument("--allow-out-of-stock", action="store_true")
    generate_circuit.add_argument("--require-basic", action="store_true")
    generate_circuit.add_argument(
        "--provider-command",
        nargs=argparse.REMAINDER,
        required=True,
        help="executable and arguments; must be the final pcbex-agent option",
    )
    generation_schema = sub.add_parser(
        "circuit-generation-schema",
        help="write the closed natural-language circuit-generation result schema",
    )
    generation_schema.add_argument("-o", "--output", type=Path)
    repair = sub.add_parser(
        "repair-kicad",
        help="route and repeatedly validate a KiCad board until DRC is clean",
    )
    repair.add_argument("input", type=Path)
    repair.add_argument("-o", "--output", type=Path, required=True)
    repair.add_argument("--report", type=Path, required=True)
    repair.add_argument("--pcbex", default="pcbex")
    repair.add_argument("--kicad-cli", default="kicad-cli")
    repair.add_argument("--max-iterations", type=int, default=4)
    args = parser.parse_args()

    if args.command == "plan":
        result = build_plan(
            args.requirements.read_text(encoding="utf-8"),
            limits=PlanLimits(args.max_iterations, args.max_changed_components),
        )
        args.output.write_text(
            json.dumps(result.as_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    elif args.command == "apply-constraints":
        raw = json.loads(args.plan.read_text(encoding="utf-8"))
        result = build_plan(
            raw["requirements"],
            limits=PlanLimits(**raw["limits"]),
        )
        apply_constraints(args.problem, result, args.output)
    elif args.command == "normalize-drc":
        violations = normalize_kicad_report(args.report.read_text(encoding="utf-8"))
        repairs = propose_repairs(violations)
        args.output.write_text(
            json.dumps(
                {
                    "violations": [v.__dict__ for v in violations],
                    "repairs": [r.__dict__ for r in repairs],
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
    elif args.command == "apply-ipc":
        document = json.loads(args.routes.read_text(encoding="utf-8"))
        result = apply_routes_to_open_board(document, max_items=args.max_items)
        print(
            f"created {result.tracks_created} tracks and "
            f"{result.vias_created} vias in KiCad"
        )
    elif args.command == "review-schematic":
        try:
            receipt = review_schematic_with_command(
                args.request,
                args.output,
                args.receipt,
                args.provider_command,
                timeout_seconds=args.timeout_seconds,
                max_output_bytes=args.maximum_output_bytes,
            )
        except (OSError, ProviderError, ReviewError) as error:
            raise SystemExit(f"schematic review failed: {error}") from error
        print(
            "AI review response written with request "
            f"{receipt['request']['sha256']} and response "
            f"{receipt['response']['sha256']}"
        )
    elif args.command == "provider-receipt-schema":
        rendered = json.dumps(
            provider_receipt_json_schema(), indent=2, ensure_ascii=False
        ) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.command == "review-managed":
        try:
            receipt = review_schematic_with_managed_provider(
                args.request,
                args.output,
                args.receipt,
                provider=args.provider,
                model=args.model,
                model_version=args.model_version,
                api_key_environment=args.api_key_environment,
                endpoint=args.endpoint,
                timeout_seconds=args.timeout_seconds,
                max_response_bytes=args.maximum_response_bytes,
                max_output_tokens=args.maximum_output_tokens,
            )
        except (OSError, ProviderError, ReviewError) as error:
            raise SystemExit(f"managed schematic review failed: {error}") from error
        print(
            f"{receipt['provider']} AI review response written with request "
            f"{receipt['request']['sha256']} and response "
            f"{receipt['response']['sha256']}"
        )
    elif args.command == "managed-provider-receipt-schema":
        rendered = json.dumps(
            managed_provider_receipt_json_schema(), indent=2, ensure_ascii=False
        ) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.command == "generate-skidl":
        try:
            spec = json.loads(args.spec.read_text(encoding="utf-8"))
            if args.catalog:
                catalog = catalog_parts_from_json(
                    json.loads(args.catalog.read_text(encoding="utf-8"))
                )
                spec = assign_catalog_parts(
                    spec,
                    catalog,
                    require_available=not args.allow_out_of_stock,
                    require_basic=args.require_basic,
                )
            elif args.catalog_endpoint:
                catalog = fetch_catalog(
                    CatalogEndpoint(
                        provider=args.catalog_provider,
                        endpoint=args.catalog_endpoint,
                        bearer_token_environment=args.catalog_bearer_token_environment,
                        timeout_seconds=args.catalog_timeout_seconds,
                        allow_http_loopback=args.allow_http_loopback,
                    )
                )
                spec = assign_catalog_parts(
                    spec,
                    catalog,
                    require_available=not args.allow_out_of_stock,
                    require_basic=args.require_basic,
                )
            erc = check_circuit_electrical(spec)
            if not erc["passed"]:
                details = "; ".join(finding["message"] for finding in erc["findings"])
                raise CircuitSpecError(f"electrical ERC failed: {details}")
            if args.erc_output:
                args.erc_output.parent.mkdir(parents=True, exist_ok=True)
                args.erc_output.write_text(
                    json.dumps(erc, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
            source = generate_skidl(spec, include_netlist=not args.no_netlist)
        except (OSError, json.JSONDecodeError, CircuitSpecError, CatalogRemoteError) as error:
            raise SystemExit(f"SKiDL generation failed: {error}") from error
        args.output.write_text(source, encoding="utf-8")
    elif args.command == "circuit-spec-schema":
        rendered = json.dumps(
            circuit_spec_json_schema(), indent=2, ensure_ascii=False
        ) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.command == "circuit-to-placement":
        try:
            source = json.loads(args.spec.read_text(encoding="utf-8"))
            sizes = json.loads(args.footprint_sizes.read_text(encoding="utf-8"))
            constraints = []
            if args.constraints:
                constraints = json.loads(args.constraints.read_text(encoding="utf-8"))
                if not isinstance(constraints, list):
                    raise CircuitSpecError("placement constraints must be a JSON array")
            placement = circuit_spec_to_placement_problem(
                source,
                sizes,
                width_nm=args.board_width_nm,
                height_nm=args.board_height_nm,
                grid_nm=args.grid_nm,
                constraints=constraints,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(placement, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except (OSError, json.JSONDecodeError, CircuitSpecError) as error:
            raise SystemExit(f"circuit placement conversion failed: {error}") from error
    elif args.command == "circuit-to-kicad":
        try:
            source = json.loads(args.spec.read_text(encoding="utf-8"))
            sizes = json.loads(args.footprint_sizes.read_text(encoding="utf-8"))
            board = circuit_spec_to_kicad_pcb(
                source,
                sizes,
                width_nm=args.board_width_nm,
                height_nm=args.board_height_nm,
                grid_nm=args.grid_nm,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(board, encoding="utf-8")
        except (OSError, json.JSONDecodeError, CircuitSpecError) as error:
            raise SystemExit(f"circuit KiCad conversion failed: {error}") from error
    elif args.command == "circuit-erc-schema":
        rendered = json.dumps(circuit_erc_json_schema(), indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.command == "generate-circuit":
        try:
            requirements = args.requirements.read_text(encoding="utf-8")
            bundle = generate_circuit_with_llm(
                requirements,
                lambda prompt: run_provider_command(
                    args.provider_command,
                    prompt,
                    timeout_seconds=args.timeout_seconds,
                    max_output_bytes=args.maximum_output_bytes,
                ),
                max_attempts=args.max_attempts,
            )
            spec = bundle["spec"]
            if args.catalog:
                catalog = catalog_parts_from_json(
                    json.loads(args.catalog.read_text(encoding="utf-8"))
                )
                spec = assign_catalog_parts(
                    spec,
                    catalog,
                    require_available=not args.allow_out_of_stock,
                    require_basic=args.require_basic,
                )
            elif args.catalog_endpoint:
                catalog = fetch_catalog(
                    CatalogEndpoint(
                        provider=args.catalog_provider,
                        endpoint=args.catalog_endpoint,
                        bearer_token_environment=args.catalog_bearer_token_environment,
                        timeout_seconds=args.catalog_timeout_seconds,
                        allow_http_loopback=args.allow_http_loopback,
                    )
                )
                spec = assign_catalog_parts(
                    spec,
                    catalog,
                    require_available=not args.allow_out_of_stock,
                    require_basic=args.require_basic,
                )
            erc = check_circuit_electrical(spec)
            if not erc["passed"]:
                details = "; ".join(finding["message"] for finding in erc["findings"])
                raise CircuitSpecError(f"electrical ERC failed: {details}")
            # Re-render after catalog assignment so the emitted source and JSON
            # are bound to exactly the same normalized spec.
            bundle["spec"] = spec
            bundle["erc"] = erc
            bundle["skidl"] = generate_skidl(spec)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            if args.skidl_output:
                args.skidl_output.parent.mkdir(parents=True, exist_ok=True)
                args.skidl_output.write_text(bundle["skidl"], encoding="utf-8")
        except (
            OSError,
            json.JSONDecodeError,
            CircuitGenerationError,
            CircuitSpecError,
            CatalogRemoteError,
            ProviderError,
        ) as error:
            raise SystemExit(f"circuit generation failed: {error}") from error
    elif args.command == "circuit-generation-schema":
        rendered = json.dumps(
            circuit_generation_json_schema(), indent=2, ensure_ascii=False
        ) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    else:
        result = repair_kicad_board(
            args.input,
            args.output,
            pcbex=args.pcbex,
            kicad_cli=args.kicad_cli,
            max_iterations=args.max_iterations,
        )
        write_repair_report(result, args.report)
        if not result.success:
            raise SystemExit(
                f"repair stopped: {result.stop_reason}; "
                f"best error count: {result.best_error_count}"
            )
        print(
            f"DRC-clean board written to {result.output} "
            f"after {len(result.iterations)} iteration(s)"
        )


if __name__ == "__main__":
    main()

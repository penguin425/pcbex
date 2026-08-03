from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .bounded_io import BoundedIOError, atomic_write, read_text
from .catalog import catalog_parts_from_json
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
    review_schematic_with_command,
)
from .repair import propose_repairs
from .repair_loop import repair_kicad_board, write_repair_report
from .review import ReviewError
from .skidl import (
    CircuitSpecError,
    assign_catalog_parts,
    circuit_spec_json_schema,
    generate_skidl,
)

MAXIMUM_AGENT_FILE_BYTES = 32 * 1024 * 1024


def _read_text(path: Path) -> str:
    return read_text(path, max_bytes=MAXIMUM_AGENT_FILE_BYTES)


def _write_text(path: Path, value: str) -> None:
    atomic_write(
        path,
        value,
        max_bytes=MAXIMUM_AGENT_FILE_BYTES,
    )


def _paths_are_same(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
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
    skidl_schema = sub.add_parser(
        "circuit-spec-schema", help="write the closed Text-to-Circuit JSON Schema"
    )
    skidl_schema.add_argument("-o", "--output", type=Path)
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
            _read_text(args.requirements),
            limits=PlanLimits(args.max_iterations, args.max_changed_components),
        )
        _write_text(
            args.output,
            json.dumps(result.as_dict(), indent=2, ensure_ascii=False) + "\n",
        )
    elif args.command == "apply-constraints":
        raw = json.loads(_read_text(args.plan))
        result = build_plan(
            raw["requirements"],
            limits=PlanLimits(**raw["limits"]),
        )
        apply_constraints(args.problem, result, args.output)
    elif args.command == "normalize-drc":
        violations = normalize_kicad_report(_read_text(args.report))
        repairs = propose_repairs(violations)
        _write_text(
            args.output,
            json.dumps(
                {
                    "violations": [v.__dict__ for v in violations],
                    "repairs": [r.__dict__ for r in repairs],
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
        )
    elif args.command == "apply-ipc":
        document = json.loads(_read_text(args.routes))
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
            _write_text(args.output, rendered)
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
            _write_text(args.output, rendered)
        else:
            print(rendered, end="")
    elif args.command == "generate-skidl":
        try:
            spec = json.loads(_read_text(args.spec))
            if args.catalog:
                catalog = catalog_parts_from_json(
                    json.loads(_read_text(args.catalog))
                )
                spec = assign_catalog_parts(
                    spec,
                    catalog,
                    require_available=not args.allow_out_of_stock,
                    require_basic=args.require_basic,
                )
            source = generate_skidl(spec, include_netlist=not args.no_netlist)
        except (OSError, BoundedIOError, json.JSONDecodeError, CircuitSpecError) as error:
            raise SystemExit(f"SKiDL generation failed: {error}") from error
        _write_text(args.output, source)
    elif args.command == "circuit-spec-schema":
        rendered = json.dumps(
            circuit_spec_json_schema(), indent=2, ensure_ascii=False
        ) + "\n"
        if args.output:
            _write_text(args.output, rendered)
        else:
            print(rendered, end="")
    else:
        if _paths_are_same(args.output, args.report):
            raise SystemExit("repair board output and report paths must differ")
        if _paths_are_same(args.input, args.report):
            raise SystemExit("repair input and report paths must differ")
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

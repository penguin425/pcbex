from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .bounded_io import (
    BoundedIOError,
    atomic_write,
    atomic_write_text_no_clobber,
    read_bytes,
    read_text,
    validate_no_clobber_path,
)
from .catalog import (
    MAX_CATALOG_RAW_BYTES,
    CatalogError,
    catalog_parts_from_json,
    catalog_receipt_json_schema,
    catalog_snapshot_json_schema,
    load_catalog_snapshot,
)
from .catalog_provenance import (
    CatalogGenerationProvenanceError,
    build_catalog_generation_provenance,
    catalog_generation_provenance_json_schema,
)
from .supplier_inventory import (
    MAXIMUM_RECEIPT_BYTES,
    SupplierInventoryError,
    catalog_fetch_receipt_json_schema,
    fetch_catalog_snapshot,
    validate_catalog_fetch_receipt,
)
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
from .circuit_generation import (
    CircuitGenerationError,
    circuit_generation_json_schema,
    fetch_circuit_spec_check_schema,
    fetch_circuit_spec_v2_schema,
    generate_circuit_with_command,
)
from .circuit_handoff_bundle import (
    CircuitHandoffBundleError,
    circuit_handoff_bundle_ai_quorum_replay_result_json_schema,
    circuit_handoff_bundle_board_binding_replay_result_json_schema,
    circuit_handoff_bundle_catalog_provenance_replay_result_json_schema,
    circuit_handoff_bundle_json_schema,
    circuit_handoff_bundle_native_erc_replay_result_json_schema,
    circuit_handoff_bundle_replay_result_json_schema,
    circuit_handoff_bundle_result_json_schema,
    extract_circuit_handoff_bundle,
    handoff_circuit_generation,
    replay_circuit_handoff_bundle,
    verify_circuit_handoff_bundle,
)
from .repair import propose_repairs
from .repair_loop import repair_kicad_board, write_repair_report
from .review import ReviewError
from .manufacturing_replay import (
    ManufacturingReplayError,
    manufacturing_package_replay_result_json_schema,
    replay_manufacturing_package,
)
from .skidl import (
    CircuitSpecError,
    assign_catalog_parts,
    circuit_spec_json_schema,
    generate_skidl,
)

MAXIMUM_AGENT_FILE_BYTES = 32 * 1024 * 1024


class _DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError


def _strict_json_object(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJSONKey,
        ValueError,
        RecursionError,
    ):
        raise CircuitGenerationError(f"{label} is not strict JSON") from None
    if not isinstance(value, dict):
        raise CircuitGenerationError(f"{label} must be a JSON object")
    return value


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
        "--allow-footprint-fallback",
        action="store_true",
        help="allow footprint-only fallback when catalog text has no match",
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
    generate_circuit = sub.add_parser(
        "generate-circuit",
        help="convert bounded natural-language requirements into a checked circuit bundle",
    )
    generate_circuit.add_argument("requirements", type=Path)
    generate_circuit.add_argument("-o", "--output", type=Path, required=True)
    generate_circuit.add_argument("--skidl-output", type=Path)
    generate_circuit.add_argument("--pcbex", default="pcbex")
    generate_circuit.add_argument("--max-attempts", type=int, default=3)
    generate_circuit.add_argument("--timeout-seconds", type=float, default=120.0)
    generate_circuit.add_argument(
        "--maximum-output-bytes", type=int, default=1024 * 1024
    )
    generate_circuit.add_argument(
        "--catalog-snapshot",
        type=Path,
        help="closed local catalog snapshot used to verify or assign every MPN",
    )
    generate_circuit.add_argument(
        "--catalog-fetch-receipt",
        type=Path,
        help=(
            "retained supplier fetch receipt to validate before generation; "
            "requires --catalog-snapshot and --catalog-provenance-output"
        ),
    )
    generate_circuit.add_argument(
        "--catalog-provenance-output",
        type=Path,
        help="write the closed fetch-to-generation provenance sidecar",
    )
    generate_circuit.add_argument(
        "--allow-out-of-stock",
        action="store_true",
        help="allow selection when the snapshot reports insufficient stock",
    )
    generate_circuit.add_argument(
        "--require-basic",
        action="store_true",
        help="require every selected catalog item to be marked basic",
    )
    generate_circuit.add_argument(
        "--allow-footprint-fallback",
        action="store_true",
        help="allow deterministic footprint-only selection when text has no match",
    )
    generate_circuit.add_argument(
        "--provider-command",
        nargs=argparse.REMAINDER,
        required=True,
        help="provider executable and arguments; must be the final pcbex-agent option",
    )
    generation_schema = sub.add_parser(
        "circuit-generation-schema",
        help="write the closed bounded circuit-generation bundle schema",
    )
    generation_schema.add_argument("--pcbex", default=None)
    generation_schema.add_argument("-o", "--output", type=Path)
    handoff_circuit = sub.add_parser(
        "handoff-circuit",
        help=(
            "replay a saved circuit-generation bundle and atomically publish "
            "an approved KiCad handoff ZIP"
        ),
    )
    handoff_circuit.add_argument("generation_bundle", type=Path)
    handoff_circuit.add_argument("-o", "--output", type=Path, required=True)
    handoff_circuit.add_argument("--pcbex", default="pcbex")
    handoff_circuit.add_argument("--timeout-seconds", type=float, default=120.0)
    handoff_schema = sub.add_parser(
        "circuit-handoff-bundle-schema",
        help="write the closed circuit-generation to KiCad handoff manifest schema",
    )
    handoff_schema.add_argument("-o", "--output", type=Path)
    verify_handoff = sub.add_parser(
        "verify-circuit-handoff-bundle",
        help="verify one exact deterministic circuit handoff ZIP without extracting it",
    )
    verify_handoff.add_argument("bundle", type=Path)
    verify_handoff.add_argument("--expected-archive-sha256")
    verify_handoff.add_argument("--expected-bundle-sha256")
    replay_handoff = sub.add_parser(
        "replay-circuit-handoff-bundle",
        help=(
            "verify a handoff ZIP and require the complete producer handoff "
            "chain to reproduce it exactly"
        ),
    )
    replay_handoff.add_argument("bundle", type=Path)
    replay_handoff.add_argument("--pcbex", default="pcbex")
    replay_handoff.add_argument(
        "--catalog-generation-provenance",
        type=Path,
        help=(
            "retained catalog-generation provenance sidecar; requires the "
            "matching fetch receipt and normalized snapshot"
        ),
    )
    replay_handoff.add_argument(
        "--catalog-fetch-receipt",
        type=Path,
        help="retained supplier fetch receipt bound by catalog provenance",
    )
    replay_handoff.add_argument(
        "--catalog-snapshot",
        type=Path,
        help="exact normalized catalog snapshot bound by the retained evidence",
    )
    replay_handoff.add_argument(
        "--native-kicad-erc-report",
        type=Path,
        help=(
            "optionally require a retained native KiCad ERC report to match "
            "a fresh run against the exactly reproduced schematic"
        ),
    )
    replay_handoff.add_argument(
        "--native-kicad-erc-warning-policy",
        type=Path,
        help="exact warning policy required by a schema-v2 native ERC report",
    )
    replay_handoff.add_argument(
        "--kicad-cli",
        help="trusted KiCad CLI used only with --native-kicad-erc-report",
    )
    replay_handoff.add_argument(
        "--require-native-kicad-erc-approved",
        action="store_true",
        help="fail after exact native ERC replay when the retained evidence is rejected",
    )
    replay_handoff.add_argument(
        "--kicad-board",
        type=Path,
        help="retained KiCad board required with --board-binding-report",
    )
    replay_handoff.add_argument(
        "--board-binding-report",
        type=Path,
        help="retained canonical board-binding report required with --kicad-board",
    )
    replay_handoff.add_argument(
        "--board-binding-policy",
        type=Path,
        help="exact custom electrical-policy source used for the fresh replay",
    )
    replay_handoff.add_argument(
        "--require-board-binding-approved",
        action="store_true",
        help="fail after exact board-binding replay when the retained evidence is rejected",
    )
    replay_handoff.add_argument(
        "--ai-quorum-report",
        type=Path,
        help=(
            "optionally require a retained non-session AI quorum report to "
            "match fresh verification against the exactly reproduced schematic"
        ),
    )
    replay_handoff.add_argument(
        "--ai-review-request",
        type=Path,
        help="schema-v1 AI review request bound to the reproduced schematic",
    )
    replay_handoff.add_argument(
        "--ai-policy-pack",
        type=Path,
        help="organization policy pack containing every trusted approval key",
    )
    replay_handoff.add_argument(
        "--ai-approval",
        action="append",
        type=Path,
        help="signed AI approval sidecar; repeat once per reviewer",
    )
    replay_handoff.add_argument(
        "--ai-response",
        action="append",
        type=Path,
        help="AI response paired by order with each --ai-approval",
    )
    replay_handoff.add_argument("--minimum-ai-approvals", type=int)
    replay_handoff.add_argument("--minimum-distinct-ai-providers", type=int)
    replay_handoff.add_argument("--minimum-distinct-ai-models", type=int)
    replay_handoff.add_argument(
        "--require-ai-quorum",
        action="store_true",
        help="fail only after exact evidence replay when the quorum is not met",
    )
    replay_handoff.add_argument("--timeout-seconds", type=float, default=120.0)
    replay_handoff.add_argument("--expected-archive-sha256")
    replay_handoff.add_argument("--expected-bundle-sha256")
    extract_handoff = sub.add_parser(
        "extract-circuit-handoff-bundle",
        help="verify and extract one circuit handoff ZIP to a new directory",
    )
    extract_handoff.add_argument("bundle", type=Path)
    extract_handoff.add_argument("--output-dir", type=Path, required=True)
    extract_handoff.add_argument("--expected-archive-sha256")
    extract_handoff.add_argument("--expected-bundle-sha256")
    handoff_result_schema = sub.add_parser(
        "circuit-handoff-bundle-result-schema",
        help="write the closed handoff ZIP verify/extract result schema",
    )
    handoff_result_schema.add_argument("-o", "--output", type=Path)
    handoff_replay_result_schema = sub.add_parser(
        "circuit-handoff-bundle-replay-result-schema",
        help="write the closed fresh handoff-chain replay result schema",
    )
    handoff_replay_result_schema.add_argument("-o", "--output", type=Path)
    handoff_native_erc_replay_result_schema = sub.add_parser(
        "circuit-handoff-bundle-native-erc-replay-result-schema",
        help="write the closed exact-chain plus native KiCad ERC replay result schema",
    )
    handoff_native_erc_replay_result_schema.add_argument("-o", "--output", type=Path)
    handoff_ai_quorum_replay_result_schema = sub.add_parser(
        "circuit-handoff-bundle-ai-quorum-replay-result-schema",
        help="write the closed exact-chain plus AI schematic quorum replay schema",
    )
    handoff_ai_quorum_replay_result_schema.add_argument("-o", "--output", type=Path)
    handoff_catalog_provenance_replay_result_schema = sub.add_parser(
        "circuit-handoff-bundle-catalog-provenance-replay-result-schema",
        help="write the closed exact-chain plus catalog provenance replay schema",
    )
    handoff_catalog_provenance_replay_result_schema.add_argument(
        "-o", "--output", type=Path
    )
    handoff_board_binding_replay_result_schema = sub.add_parser(
        "circuit-handoff-bundle-board-binding-replay-result-schema",
        help="write the closed exact-chain plus board-binding replay schema",
    )
    handoff_board_binding_replay_result_schema.add_argument(
        "-o", "--output", type=Path
    )
    catalog_snapshot_schema = sub.add_parser(
        "catalog-snapshot-schema",
        help="write the closed local catalog-snapshot JSON Schema",
    )
    catalog_snapshot_schema.add_argument("-o", "--output", type=Path)
    catalog_receipt_schema = sub.add_parser(
        "catalog-selection-receipt-schema",
        help="write the closed catalog-selection receipt JSON Schema",
    )
    catalog_receipt_schema.add_argument("-o", "--output", type=Path)
    catalog_fetch = sub.add_parser(
        "fetch-catalog-snapshot",
        help="fetch one bounded HTTPS catalog snapshot and retain a receipt",
    )
    catalog_fetch.add_argument("--endpoint", required=True)
    catalog_fetch.add_argument("--provider", required=True)
    catalog_fetch.add_argument("-o", "--output", type=Path, required=True)
    catalog_fetch.add_argument("--receipt", type=Path, required=True)
    catalog_fetch.add_argument("--timeout-seconds", type=int, default=30)
    catalog_fetch.add_argument(
        "--maximum-response-bytes", type=int, default=4 * 1024 * 1024
    )
    catalog_fetch.add_argument("--bearer-token-environment")
    catalog_fetch_schema = sub.add_parser(
        "catalog-fetch-receipt-schema",
        help="write the closed catalog-fetch receipt JSON Schema",
    )
    catalog_fetch_schema.add_argument("-o", "--output", type=Path)
    catalog_provenance_schema = sub.add_parser(
        "catalog-generation-provenance-schema",
        help="write the closed catalog-to-generation provenance JSON Schema",
    )
    catalog_provenance_schema.add_argument("-o", "--output", type=Path)
    manufacturing_replay = sub.add_parser(
        "replay-manufacturing-package",
        help="freshly regenerate and exactly verify a retained manufacturing ZIP",
    )
    manufacturing_replay.add_argument("board", type=Path)
    manufacturing_replay.add_argument("retained_package", type=Path)
    manufacturing_replay.add_argument("--pcbex", default="pcbex")
    manufacturing_replay.add_argument("--kicad-cli", default="kicad-cli")
    manufacturing_replay.add_argument("--kicad-project", type=Path)
    manufacturing_replay.add_argument("--kicad-rules", type=Path)
    manufacturing_profiles = manufacturing_replay.add_mutually_exclusive_group()
    manufacturing_profiles.add_argument("--fab")
    manufacturing_profiles.add_argument("--fab-profile", type=Path)
    manufacturing_profiles.add_argument("--physical-profile", type=Path)
    manufacturing_replay.add_argument("--timeout-seconds", type=float, default=120.0)
    manufacturing_replay_schema = sub.add_parser(
        "manufacturing-package-replay-result-schema",
        help="write the closed fresh manufacturing-package replay result schema",
    )
    manufacturing_replay_schema.add_argument("-o", "--output", type=Path)
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
                    allow_footprint_fallback=args.allow_footprint_fallback,
                )
            source = generate_skidl(spec, include_netlist=not args.no_netlist)
        except (
            OSError,
            BoundedIOError,
            json.JSONDecodeError,
            CatalogError,
            CircuitSpecError,
        ) as error:
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
    elif args.command == "generate-circuit":
        try:
            if args.catalog_snapshot is None and (
                args.allow_out_of_stock
                or args.require_basic
                or args.allow_footprint_fallback
            ):
                raise CircuitGenerationError(
                    "catalog policy options require --catalog-snapshot"
                )
            if (args.catalog_fetch_receipt is None) != (
                args.catalog_provenance_output is None
            ):
                raise CircuitGenerationError(
                    "--catalog-fetch-receipt and --catalog-provenance-output "
                    "must be supplied together"
                )
            if (
                args.catalog_fetch_receipt is not None
                and args.catalog_snapshot is None
            ):
                raise CircuitGenerationError(
                    "catalog provenance requires --catalog-snapshot"
                )
            output_paths = [args.output]
            if args.skidl_output:
                output_paths.append(args.skidl_output)
            if args.catalog_provenance_output:
                output_paths.append(args.catalog_provenance_output)
            normalized_paths: list[Path] = []
            for path in output_paths:
                if any(_paths_are_same(path, other) for other in normalized_paths):
                    raise CircuitGenerationError(
                        "circuit bundle, SKiDL, and catalog provenance output "
                        "paths must differ"
                    )
                validate_no_clobber_path(path)
                normalized_paths.append(path)
            requirements = _read_text(args.requirements)
            fetch_receipt_raw: bytes | None = None
            snapshot_raw: bytes | None = None
            catalog_evaluated_at: int | None = None
            if args.catalog_fetch_receipt is not None:
                snapshot_raw = read_bytes(
                    args.catalog_snapshot,
                    max_bytes=MAX_CATALOG_RAW_BYTES,
                )
                fetch_receipt_raw = read_bytes(
                    args.catalog_fetch_receipt,
                    max_bytes=MAXIMUM_RECEIPT_BYTES,
                )
                fetch_receipt = _strict_json_object(
                    fetch_receipt_raw,
                    "catalog fetch receipt",
                )
                fetch_binding = validate_catalog_fetch_receipt(
                    fetch_receipt,
                    snapshot_raw,
                )
                catalog_evaluated_at = fetch_binding["fetched_at_unix"]
                catalog_snapshot = load_catalog_snapshot(
                    args.catalog_snapshot,
                    evaluated_at_unix=catalog_evaluated_at,
                )
                if catalog_snapshot.raw_bytes != snapshot_raw:
                    raise CircuitGenerationError(
                        "catalog snapshot changed during provenance preflight"
                    )
            else:
                catalog_snapshot = (
                    load_catalog_snapshot(args.catalog_snapshot)
                    if args.catalog_snapshot is not None
                    else None
                )
            bundle = generate_circuit_with_command(
                requirements,
                args.pcbex,
                args.provider_command,
                max_attempts=args.max_attempts,
                timeout_seconds=args.timeout_seconds,
                maximum_output_bytes=args.maximum_output_bytes,
                catalog_snapshot=catalog_snapshot,
                require_available=not args.allow_out_of_stock,
                require_basic=args.require_basic,
                allow_footprint_fallback=args.allow_footprint_fallback,
                evaluated_at_unix=catalog_evaluated_at,
            )
            rendered = json.dumps(bundle, indent=2, ensure_ascii=False) + "\n"
            provenance_rendered: str | None = None
            if args.catalog_provenance_output is not None:
                if fetch_receipt_raw is None or snapshot_raw is None:
                    raise CircuitGenerationError(
                        "catalog provenance inputs were not retained"
                    )
                skidl_raw = bundle["skidl"].encode("utf-8", errors="strict")
                provenance = build_catalog_generation_provenance(
                    fetch_receipt_raw,
                    args.catalog_snapshot,
                    rendered.encode("utf-8", errors="strict"),
                    skidl_raw,
                    evaluated_at_unix=catalog_evaluated_at,
                )
                provenance_rendered = (
                    json.dumps(provenance, indent=2, ensure_ascii=False) + "\n"
                )
            atomic_write_text_no_clobber(
                args.output,
                rendered,
                max_bytes=MAXIMUM_AGENT_FILE_BYTES,
            )
            if args.skidl_output:
                atomic_write_text_no_clobber(
                    args.skidl_output,
                    bundle["skidl"],
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            if args.catalog_provenance_output and provenance_rendered is not None:
                atomic_write_text_no_clobber(
                    args.catalog_provenance_output,
                    provenance_rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
        except (
            OSError,
            BoundedIOError,
            CatalogGenerationProvenanceError,
            CircuitGenerationError,
            CatalogError,
            ProviderError,
            SupplierInventoryError,
            UnicodeError,
        ) as error:
            raise SystemExit(f"circuit generation failed: {error}") from error
    elif args.command == "circuit-generation-schema":
        try:
            if args.output:
                validate_no_clobber_path(args.output)
            if args.pcbex:
                schema = circuit_generation_json_schema(
                    native_spec_schema=fetch_circuit_spec_v2_schema(args.pcbex),
                    native_check_schema=fetch_circuit_spec_check_schema(args.pcbex),
                )
            else:
                schema = circuit_generation_json_schema()
            rendered = json.dumps(schema, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, CircuitGenerationError) as error:
            raise SystemExit(f"circuit generation schema failed: {error}") from error
    elif args.command == "handoff-circuit":
        try:
            manifest = handoff_circuit_generation(
                args.generation_bundle,
                args.output,
                args.pcbex,
                timeout_seconds=args.timeout_seconds,
            )
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(f"circuit handoff failed: {error}") from error
        print(
            "approved circuit handoff bundle written with identity "
            f"{manifest['bundle_sha256']}"
        )
    elif args.command == "circuit-handoff-bundle-schema":
        try:
            rendered = (
                json.dumps(
                    circuit_handoff_bundle_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
                validate_no_clobber_path(args.output)
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(f"circuit handoff schema failed: {error}") from error
    elif args.command == "verify-circuit-handoff-bundle":
        try:
            result = verify_circuit_handoff_bundle(
                args.bundle,
                expected_archive_sha256=args.expected_archive_sha256,
                expected_bundle_sha256=args.expected_bundle_sha256,
            )
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(f"circuit handoff bundle verification failed: {error}") from error
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "replay-circuit-handoff-bundle":
        try:
            native_options = {}
            if (
                args.native_kicad_erc_report is not None
                or args.native_kicad_erc_warning_policy is not None
                or args.require_native_kicad_erc_approved
                or args.kicad_cli is not None
            ):
                native_options = {
                    "retained_native_kicad_erc_report": args.native_kicad_erc_report,
                    "kicad_cli": (
                        "kicad-cli" if args.kicad_cli is None else args.kicad_cli
                    ),
                    "native_kicad_erc_warning_policy": (
                        args.native_kicad_erc_warning_policy
                    ),
                    "require_native_kicad_erc_approved": (
                        args.require_native_kicad_erc_approved
                    ),
                }
            board_options = {}
            if (
                args.kicad_board is not None
                or args.board_binding_report is not None
                or args.board_binding_policy is not None
                or args.require_board_binding_approved
            ):
                board_options = {
                    "kicad_board": args.kicad_board,
                    "retained_board_binding_report": args.board_binding_report,
                    "board_binding_policy": args.board_binding_policy,
                    "require_board_binding_approved": (
                        args.require_board_binding_approved
                    ),
                }
            ai_options = {}
            if (
                args.ai_quorum_report is not None
                or args.ai_review_request is not None
                or args.ai_policy_pack is not None
                or args.ai_approval is not None
                or args.ai_response is not None
                or args.minimum_ai_approvals is not None
                or args.minimum_distinct_ai_providers is not None
                or args.minimum_distinct_ai_models is not None
                or args.require_ai_quorum
            ):
                ai_options = {
                    "retained_ai_quorum_report": args.ai_quorum_report,
                    "ai_review_request": args.ai_review_request,
                    "ai_policy_pack": args.ai_policy_pack,
                    "ai_approvals": args.ai_approval,
                    "ai_responses": args.ai_response,
                    "minimum_ai_approvals": args.minimum_ai_approvals,
                    "minimum_distinct_ai_providers": (
                        args.minimum_distinct_ai_providers
                    ),
                    "minimum_distinct_ai_models": args.minimum_distinct_ai_models,
                    "require_ai_quorum": args.require_ai_quorum,
                }
            catalog_options = {}
            if (
                args.catalog_generation_provenance is not None
                or args.catalog_fetch_receipt is not None
                or args.catalog_snapshot is not None
            ):
                catalog_options = {
                    "catalog_generation_provenance": (
                        args.catalog_generation_provenance
                    ),
                    "catalog_fetch_receipt": args.catalog_fetch_receipt,
                    "catalog_snapshot": args.catalog_snapshot,
                }
            result = replay_circuit_handoff_bundle(
                args.bundle,
                args.pcbex,
                **catalog_options,
                **native_options,
                **board_options,
                **ai_options,
                timeout_seconds=args.timeout_seconds,
                expected_archive_sha256=args.expected_archive_sha256,
                expected_bundle_sha256=args.expected_bundle_sha256,
            )
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(f"circuit handoff bundle replay failed: {error}") from error
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "extract-circuit-handoff-bundle":
        try:
            result = extract_circuit_handoff_bundle(
                args.bundle,
                args.output_dir,
                expected_archive_sha256=args.expected_archive_sha256,
                expected_bundle_sha256=args.expected_bundle_sha256,
            )
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(f"circuit handoff bundle extraction failed: {error}") from error
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "circuit-handoff-bundle-result-schema":
        try:
            rendered = (
                json.dumps(
                    circuit_handoff_bundle_result_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
                validate_no_clobber_path(args.output)
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(f"circuit handoff result schema failed: {error}") from error
    elif args.command == "circuit-handoff-bundle-replay-result-schema":
        try:
            rendered = (
                json.dumps(
                    circuit_handoff_bundle_replay_result_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
                validate_no_clobber_path(args.output)
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(f"circuit handoff replay schema failed: {error}") from error
    elif args.command == "circuit-handoff-bundle-native-erc-replay-result-schema":
        try:
            rendered = (
                json.dumps(
                    circuit_handoff_bundle_native_erc_replay_result_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
                validate_no_clobber_path(args.output)
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(
                f"circuit handoff native ERC replay schema failed: {error}"
            ) from error
    elif args.command == "circuit-handoff-bundle-ai-quorum-replay-result-schema":
        try:
            rendered = (
                json.dumps(
                    circuit_handoff_bundle_ai_quorum_replay_result_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
                validate_no_clobber_path(args.output)
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(
                f"circuit handoff AI quorum replay schema failed: {error}"
            ) from error
    elif (
        args.command
        == "circuit-handoff-bundle-catalog-provenance-replay-result-schema"
    ):
        try:
            rendered = (
                json.dumps(
                    circuit_handoff_bundle_catalog_provenance_replay_result_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
                validate_no_clobber_path(args.output)
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(
                f"circuit handoff catalog provenance replay schema failed: {error}"
            ) from error
    elif args.command == "circuit-handoff-bundle-board-binding-replay-result-schema":
        try:
            rendered = (
                json.dumps(
                    circuit_handoff_bundle_board_binding_replay_result_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
                validate_no_clobber_path(args.output)
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, CircuitHandoffBundleError) as error:
            raise SystemExit(
                f"circuit handoff board binding replay schema failed: {error}"
            ) from error
    elif args.command == "fetch-catalog-snapshot":
        try:
            receipt = fetch_catalog_snapshot(
                args.endpoint,
                args.provider,
                args.output,
                args.receipt,
                timeout_seconds=args.timeout_seconds,
                maximum_response_bytes=args.maximum_response_bytes,
                bearer_token_environment=args.bearer_token_environment,
            )
        except (
            OSError,
            BoundedIOError,
            CatalogError,
            SupplierInventoryError,
        ) as error:
            raise SystemExit(f"catalog snapshot fetch failed: {error}") from error
        print(
            "catalog snapshot written with response "
            f"{receipt['response_sha256']} and snapshot "
            f"{receipt['snapshot_sha256']}"
        )
    elif args.command in {
        "catalog-snapshot-schema",
        "catalog-selection-receipt-schema",
        "catalog-fetch-receipt-schema",
        "catalog-generation-provenance-schema",
    }:
        try:
            if args.command == "catalog-snapshot-schema":
                schema = catalog_snapshot_json_schema()
            elif args.command == "catalog-selection-receipt-schema":
                schema = catalog_receipt_json_schema()
            elif args.command == "catalog-fetch-receipt-schema":
                schema = catalog_fetch_receipt_json_schema()
            else:
                schema = catalog_generation_provenance_json_schema()
            rendered = json.dumps(schema, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                validate_no_clobber_path(args.output)
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (
            OSError,
            BoundedIOError,
            CatalogError,
            CatalogGenerationProvenanceError,
        ) as error:
            raise SystemExit(f"catalog schema failed: {error}") from error
    elif args.command == "replay-manufacturing-package":
        try:
            result = replay_manufacturing_package(
                args.board,
                args.retained_package,
                args.pcbex,
                kicad_cli=args.kicad_cli,
                kicad_project=args.kicad_project,
                kicad_rules=args.kicad_rules,
                fab=args.fab,
                fab_profile=args.fab_profile,
                physical_profile=args.physical_profile,
                timeout_seconds=args.timeout_seconds,
            )
        except (OSError, BoundedIOError, ManufacturingReplayError) as error:
            raise SystemExit(f"manufacturing package replay failed: {error}") from error
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "manufacturing-package-replay-result-schema":
        try:
            rendered = (
                json.dumps(
                    manufacturing_package_replay_result_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
                validate_no_clobber_path(args.output)
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, ManufacturingReplayError) as error:
            raise SystemExit(
                f"manufacturing package replay schema failed: {error}"
            ) from error
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

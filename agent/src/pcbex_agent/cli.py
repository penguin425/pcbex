from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import time
import unicodedata

from .assembly_evidence import (
    MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
    AssemblyEvidenceError,
    assembly_evidence_json_schema,
    evaluate_assembly_evidence,
    render_assembly_evidence,
)
from .assembly_supplier_offer_evidence import (
    MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
    AssemblySupplierOfferEvidenceError,
    assembly_supplier_offer_evidence_json_schema,
    evaluate_assembly_supplier_offer_evidence,
    render_assembly_supplier_offer_evidence,
)
from .bounded_io import (
    BoundedIOError,
    atomic_write,
    atomic_write_no_clobber,
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
from .supplier_offer import (
    MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
    SupplierOfferError,
    evaluate_supplier_offer_coverage,
    normalized_supplier_offer_json_schema,
    render_supplier_offer_coverage,
    supplier_offer_coverage_json_schema,
)
from .supplier_offer_acquisition import (
    SupplierOfferAcquisitionError,
    fetch_supplier_offer,
    supplier_offer_fetch_receipt_json_schema,
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
    circuit_handoff_bundle_manufacturing_replay_result_json_schema,
    circuit_handoff_bundle_pipeline_replay_result_json_schema,
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
from .deterministic_pipeline_replay import (
    DeterministicPipelineReplayError,
    deterministic_pipeline_replay_result_json_schema,
    replay_deterministic_pipeline,
)
from .procurement_intent import (
    MAXIMUM_PROCUREMENT_INTENT_BYTES,
    ProcurementIntentError,
    evaluate_procurement_intent,
    procurement_intent_json_schema,
)
from .procurement_release_authorization import (
    MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
    MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES,
    ProcurementReleaseAuthorizationError,
    procurement_authorization_report_json_schema,
    render_procurement_authorization_report,
    render_signed_procurement_approval,
    sign_procurement_approval,
    signed_procurement_approval_json_schema,
    validate_procurement_release_authorization,
    verify_procurement_authorization,
)
from .procurement_authorization_reservation import (
    ProcurementAuthorizationReservationError,
    build_procurement_authorization_reservation,
    commit_procurement_authorization_reservation,
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


def _assembly_supplier_offer_comparison_path(path: Path) -> str:
    try:
        rendered = os.path.realpath(os.path.abspath(path))
        normalized = os.path.normcase(rendered)
        return unicodedata.normalize("NFC", normalized).casefold()
    except (OSError, TypeError, ValueError, UnicodeError):
        raise BoundedIOError(
            "assembly supplier-offer evidence path identity is invalid"
        ) from None


def _preflight_assembly_supplier_offer_output(
    output: Path, inputs: tuple[Path | None, ...]
) -> Path:
    validate_no_clobber_path(output)
    try:
        frozen_output = Path(os.path.abspath(output))
    except (OSError, TypeError, ValueError, UnicodeError):
        raise BoundedIOError(
            "assembly supplier-offer evidence path identity is invalid"
        ) from None
    output_identity = _assembly_supplier_offer_comparison_path(output)
    for source in inputs:
        if source is None:
            continue
        aliases = _assembly_supplier_offer_comparison_path(source) == output_identity
        if not aliases:
            try:
                same_parent = os.path.samefile(output.parent, source.parent)
            except FileNotFoundError:
                same_parent = False
            except OSError:
                raise BoundedIOError(
                    "assembly supplier-offer evidence path identity is invalid"
                ) from None
            if same_parent:
                output_leaf = unicodedata.normalize(
                    "NFC", os.path.normcase(output.name)
                ).casefold()
                source_leaf = unicodedata.normalize(
                    "NFC", os.path.normcase(source.name)
                ).casefold()
                aliases = output_leaf == source_leaf
        if aliases:
            raise BoundedIOError(
                "assembly supplier-offer evidence output must differ from every "
                "input path"
            )
    return frozen_output


def _procurement_authorization_comparison_path(path: Path) -> str:
    try:
        rendered = os.path.realpath(os.path.abspath(path))
        normalized = os.path.normcase(rendered)
        return unicodedata.normalize("NFC", normalized).casefold()
    except (OSError, TypeError, ValueError, UnicodeError):
        raise BoundedIOError(
            "procurement authorization path identity is invalid"
        ) from None


def _procurement_authorization_command_path(command: str) -> Path | None:
    """Return commands that name paths instead of relying on PATH lookup."""

    try:
        path_looking = (
            os.path.isabs(command)
            or command.startswith((".", "~"))
            or "/" in command
            or "\\" in command
            or (len(command) >= 2 and command[1] == ":")
        )
        return Path(command) if path_looking else None
    except (OSError, TypeError, ValueError, UnicodeError):
        raise BoundedIOError(
            "procurement authorization command path identity is invalid"
        ) from None


def _preflight_procurement_authorization_output(
    output: Path, inputs: tuple[Path | None, ...]
) -> Path:
    """Freeze one no-clobber destination and reject every input alias."""

    try:
        validate_no_clobber_path(output)
        frozen_output = Path(os.path.abspath(output))
        validate_no_clobber_path(frozen_output)
    except (OSError, TypeError, ValueError, UnicodeError):
        raise BoundedIOError(
            "procurement authorization output path is unsafe or already exists"
        ) from None
    output_identity = _procurement_authorization_comparison_path(frozen_output)
    for source in inputs:
        if source is None:
            continue
        aliases = (
            _procurement_authorization_comparison_path(source) == output_identity
        )
        if not aliases:
            try:
                same_parent = os.path.samefile(
                    frozen_output.parent, Path(os.path.abspath(source)).parent
                )
            except FileNotFoundError:
                same_parent = False
            except (OSError, TypeError, ValueError, UnicodeError):
                raise BoundedIOError(
                    "procurement authorization path identity is invalid"
                ) from None
            if same_parent:
                output_leaf = unicodedata.normalize(
                    "NFC", os.path.normcase(frozen_output.name)
                ).casefold()
                source_leaf = unicodedata.normalize(
                    "NFC", os.path.normcase(source.name)
                ).casefold()
                aliases = output_leaf == source_leaf
        if aliases:
            raise BoundedIOError(
                "procurement authorization output must differ from every input path"
            )
    return frozen_output


def _add_procurement_authorization_sources(
    command: argparse.ArgumentParser,
) -> None:
    command.add_argument("evidence", type=Path, metavar="EVIDENCE")
    command.add_argument("handoff", type=Path, metavar="HANDOFF")
    command.add_argument("board", type=Path, metavar="BOARD")
    command.add_argument(
        "manufacturing_package", type=Path, metavar="MANUFACTURING_PACKAGE"
    )
    command.add_argument(
        "--board-binding-report", type=Path, required=True, metavar="REPORT"
    )
    command.add_argument(
        "--procurement-intent", type=Path, required=True, metavar="INTENT"
    )
    command.add_argument(
        "--catalog-snapshot", type=Path, required=True, metavar="SNAPSHOT"
    )
    command.add_argument(
        "--final-cpl-report", type=Path, required=True, metavar="REPORT"
    )
    command.add_argument(
        "--assembly-evidence", type=Path, required=True, metavar="REPORT"
    )
    command.add_argument(
        "--supplier-offer", type=Path, required=True, metavar="OFFER"
    )
    command.add_argument(
        "--supplier-offer-fetch-receipt",
        type=Path,
        required=True,
        metavar="RECEIPT",
    )
    command.add_argument(
        "--supplier-offer-coverage",
        type=Path,
        required=True,
        metavar="COVERAGE",
    )
    command.add_argument(
        "--policy-pack", type=Path, required=True, metavar="POLICY_PACK"
    )


def _add_procurement_authorization_replay_options(
    command: argparse.ArgumentParser,
) -> None:
    command.add_argument("--board-binding-policy", type=Path, metavar="POLICY")
    command.add_argument(
        "--manufacturing-kicad-cli", default="kicad-cli", metavar="CMD"
    )
    command.add_argument(
        "--manufacturing-kicad-project", type=Path, metavar="PATH"
    )
    command.add_argument(
        "--manufacturing-kicad-rules", type=Path, metavar="PATH"
    )
    profile = command.add_mutually_exclusive_group()
    profile.add_argument("--manufacturing-fab", metavar="ID")
    profile.add_argument("--manufacturing-fab-profile", type=Path, metavar="PATH")
    profile.add_argument(
        "--manufacturing-physical-profile", type=Path, metavar="PATH"
    )
    command.add_argument("--expected-handoff-archive-sha256", metavar="HEX")
    command.add_argument("--expected-handoff-bundle-sha256", metavar="HEX")


def _add_procurement_authorization_commands(
    command: argparse.ArgumentParser, *, signing: bool
) -> None:
    command.add_argument(
        "--pcbex",
        default="pcbex",
        metavar="CMD",
        help="exact evidence replay command (default: pcbex)",
    )
    command.add_argument(
        "--authorization-pcbex",
        default="pcbex",
        metavar="CMD",
        help=(
            "trusted crypto TCB command that can read the private key "
            "(default: pcbex)"
            if signing
            else "trusted crypto TCB command used to verify signed approvals "
            "(default: pcbex)"
        ),
    )


def _add_procurement_authorization_selectors(
    command: argparse.ArgumentParser,
) -> None:
    command.add_argument("--requested-boards", type=int, required=True, metavar="N")
    command.add_argument(
        "--evaluated-at-unix", type=int, required=True, metavar="N"
    )


def _procurement_authorization_input_paths(
    args: argparse.Namespace,
    *,
    private_key: Path | None = None,
    approvals: tuple[Path, ...] = (),
) -> tuple[Path | None, ...]:
    return (
        args.evidence,
        args.handoff,
        args.board,
        args.manufacturing_package,
        args.board_binding_report,
        args.procurement_intent,
        args.catalog_snapshot,
        args.final_cpl_report,
        args.assembly_evidence,
        args.supplier_offer,
        args.supplier_offer_fetch_receipt,
        args.supplier_offer_coverage,
        args.policy_pack,
        private_key,
        *approvals,
        args.board_binding_policy,
        _procurement_authorization_command_path(args.manufacturing_kicad_cli),
        args.manufacturing_kicad_project,
        args.manufacturing_kicad_rules,
        args.manufacturing_fab_profile,
        args.manufacturing_physical_profile,
        _procurement_authorization_command_path(args.pcbex),
        _procurement_authorization_command_path(args.authorization_pcbex),
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
        "--manufacturing-package",
        type=Path,
        help=(
            "retained manufacturing ZIP to reproduce from the same board used "
            "by the required board-binding replay"
        ),
    )
    replay_handoff.add_argument(
        "--manufacturing-kicad-cli",
        help="trusted KiCad CLI used only by the composed manufacturing replay",
    )
    replay_handoff.add_argument("--manufacturing-kicad-project", type=Path)
    replay_handoff.add_argument("--manufacturing-kicad-rules", type=Path)
    manufacturing_profile = replay_handoff.add_mutually_exclusive_group()
    manufacturing_profile.add_argument("--manufacturing-fab")
    manufacturing_profile.add_argument("--manufacturing-fab-profile", type=Path)
    manufacturing_profile.add_argument(
        "--manufacturing-physical-profile", type=Path
    )
    replay_handoff.add_argument(
        "--deterministic-pipeline-plan",
        type=Path,
        help=(
            "closed deterministic-pipeline plan whose shared circuit, board, "
            "and package inputs must match the complete manufacturing replay"
        ),
    )
    replay_handoff.add_argument(
        "--deterministic-pipeline-report",
        type=Path,
        help="retained deterministic-pipeline report to reproduce exactly",
    )
    replay_handoff.add_argument(
        "--require-deterministic-pipeline-approved",
        action="store_true",
        help="fail after exact cross-bound replay when the pipeline is rejected",
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
    handoff_manufacturing_replay_result_schema = sub.add_parser(
        "circuit-handoff-bundle-manufacturing-replay-result-schema",
        help=(
            "write the closed exact-chain plus board-bound manufacturing "
            "package replay schema"
        ),
    )
    handoff_manufacturing_replay_result_schema.add_argument(
        "-o", "--output", type=Path
    )
    handoff_pipeline_replay_result_schema = sub.add_parser(
        "circuit-handoff-bundle-pipeline-replay-result-schema",
        help=(
            "write the closed exact-chain plus board-bound manufacturing and "
            "deterministic-pipeline replay schema"
        ),
    )
    handoff_pipeline_replay_result_schema.add_argument("-o", "--output", type=Path)
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
    deterministic_pipeline_replay = sub.add_parser(
        "replay-deterministic-pipeline",
        help="freshly rerun a closed plan and exactly verify its retained report",
    )
    deterministic_pipeline_replay.add_argument("plan", type=Path)
    deterministic_pipeline_replay.add_argument("retained_report", type=Path)
    deterministic_pipeline_replay.add_argument("--pcbex", default="pcbex")
    deterministic_pipeline_replay.add_argument(
        "--timeout-seconds", type=float, default=120.0
    )
    deterministic_pipeline_replay.add_argument(
        "--require-approved",
        action="store_true",
        help="fail after exact replay when the retained pipeline was rejected",
    )
    deterministic_pipeline_replay_schema = sub.add_parser(
        "deterministic-pipeline-replay-result-schema",
        help="write the closed fresh deterministic-pipeline replay result schema",
    )
    deterministic_pipeline_replay_schema.add_argument("-o", "--output", type=Path)
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
    procurement_intent = sub.add_parser(
        "build-procurement-intent",
        help="bind one exact final BOM to fully replayed catalog SKU selections",
    )
    procurement_intent.add_argument("board", type=Path)
    procurement_intent.add_argument("manufacturing_package", type=Path)
    procurement_intent.add_argument(
        "--circuit-generation", type=Path, required=True
    )
    procurement_intent.add_argument("--catalog-snapshot", type=Path, required=True)
    procurement_intent.add_argument("--pcbex", default="pcbex")
    procurement_intent.add_argument(
        "--timeout-seconds", type=float, default=120.0
    )
    procurement_intent.add_argument("-o", "--output", type=Path, required=True)
    procurement_intent.add_argument(
        "--require-approved",
        action="store_true",
        help="fail after retaining a technically rejected intent report",
    )
    procurement_intent_schema = sub.add_parser(
        "procurement-intent-schema",
        help="write the closed offline procurement-intent report JSON Schema",
    )
    procurement_intent_schema.add_argument("-o", "--output", type=Path)
    supplier_offer_fetch_help = (
        "fetch one bounded HTTPS supplier offer and retain its receipt"
    )
    supplier_offer_fetch = sub.add_parser(
        "fetch-supplier-offer",
        help=supplier_offer_fetch_help,
        description=supplier_offer_fetch_help,
    )
    supplier_offer_fetch.add_argument(
        "--endpoint", required=True, metavar="URL"
    )
    supplier_offer_fetch.add_argument(
        "--supplier", required=True, metavar="ID"
    )
    supplier_offer_fetch.add_argument(
        "--procurement-intent-sha256", required=True, metavar="HEX"
    )
    supplier_offer_fetch.add_argument(
        "-o", "--output", type=Path, required=True, metavar="OFFER"
    )
    supplier_offer_fetch.add_argument(
        "--receipt", type=Path, required=True, metavar="RECEIPT"
    )
    supplier_offer_fetch.add_argument(
        "--timeout-seconds",
        type=int,
        default=30,
        metavar="SECONDS",
        help="whole-request timeout in seconds (default: 30)",
    )
    supplier_offer_fetch.add_argument(
        "--maximum-response-bytes",
        type=int,
        default=4 * 1024 * 1024,
        metavar="BYTES",
        help="maximum response size in bytes (default: 4194304)",
    )
    supplier_offer_fetch.add_argument(
        "--bearer-token-environment", metavar="NAME"
    )
    supplier_offer_fetch_schema = sub.add_parser(
        "supplier-offer-fetch-receipt-schema",
        help="write the closed supplier-offer fetch receipt JSON Schema",
    )
    supplier_offer_fetch_schema.add_argument(
        "-o", "--output", type=Path, metavar="PATH"
    )
    supplier_offer_help = (
        "evaluate whether one normalized supplier offer covers a procurement intent"
    )
    supplier_offer = sub.add_parser(
        "build-supplier-offer-coverage",
        help=supplier_offer_help,
        description=supplier_offer_help,
    )
    supplier_offer.add_argument("board", type=Path, metavar="BOARD")
    supplier_offer.add_argument(
        "manufacturing_package", type=Path, metavar="MANUFACTURING_ZIP"
    )
    supplier_offer.add_argument(
        "--circuit-generation", type=Path, required=True, metavar="GENERATION"
    )
    supplier_offer.add_argument(
        "--catalog-snapshot", type=Path, required=True, metavar="SNAPSHOT"
    )
    supplier_offer.add_argument(
        "--procurement-intent", type=Path, required=True, metavar="INTENT"
    )
    supplier_offer.add_argument(
        "--supplier-offer", type=Path, required=True, metavar="OFFER"
    )
    supplier_offer.add_argument(
        "--requested-boards", type=int, required=True, metavar="N"
    )
    supplier_offer.add_argument(
        "--evaluated-at-unix", type=int, required=True, metavar="N"
    )
    supplier_offer.add_argument("--pcbex", default="pcbex", metavar="CMD")
    supplier_offer.add_argument(
        "--timeout-seconds", type=float, default=120.0, metavar="SECONDS"
    )
    supplier_offer.add_argument(
        "-o", "--output", type=Path, required=True, metavar="REPORT"
    )
    supplier_offer.add_argument(
        "--require-covered",
        action="store_true",
        help="fail after retaining a report when the offer does not cover the intent",
    )
    supplier_offer_schema = sub.add_parser(
        "supplier-offer-schema",
        help="write the closed normalized supplier-offer JSON Schema",
    )
    supplier_offer_schema.add_argument("-o", "--output", type=Path, metavar="PATH")
    supplier_offer_coverage_schema = sub.add_parser(
        "supplier-offer-coverage-schema",
        help="write the closed supplier-offer coverage report JSON Schema",
    )
    supplier_offer_coverage_schema.add_argument(
        "-o", "--output", type=Path, metavar="PATH"
    )
    assembly_evidence = sub.add_parser(
        "build-assembly-evidence",
        help=(
            "compose exact handoff, board, manufacturing, procurement, and "
            "placement evidence"
        ),
    )
    assembly_evidence.add_argument("handoff_zip", type=Path, metavar="HANDOFF_ZIP")
    assembly_evidence.add_argument("board", type=Path, metavar="BOARD")
    assembly_evidence.add_argument(
        "manufacturing_zip", type=Path, metavar="MANUFACTURING_ZIP"
    )
    assembly_evidence.add_argument(
        "--board-binding-report", type=Path, required=True, metavar="REPORT"
    )
    assembly_evidence.add_argument(
        "--procurement-intent", type=Path, required=True, metavar="INTENT"
    )
    assembly_evidence.add_argument(
        "--catalog-snapshot", type=Path, required=True, metavar="SNAPSHOT"
    )
    assembly_evidence.add_argument(
        "--final-cpl-report", type=Path, required=True, metavar="REPORT"
    )
    assembly_evidence.add_argument(
        "-o", "--output", type=Path, required=True, metavar="REPORT"
    )
    assembly_evidence.add_argument(
        "--board-binding-policy", type=Path, metavar="POLICY"
    )
    assembly_evidence.add_argument(
        "--manufacturing-kicad-cli", default="kicad-cli", metavar="CMD"
    )
    assembly_evidence.add_argument(
        "--manufacturing-kicad-project", type=Path, metavar="PATH"
    )
    assembly_evidence.add_argument(
        "--manufacturing-kicad-rules", type=Path, metavar="PATH"
    )
    assembly_manufacturing_profile = assembly_evidence.add_mutually_exclusive_group()
    assembly_manufacturing_profile.add_argument("--manufacturing-fab", metavar="ID")
    assembly_manufacturing_profile.add_argument(
        "--manufacturing-fab-profile", type=Path, metavar="PATH"
    )
    assembly_manufacturing_profile.add_argument(
        "--manufacturing-physical-profile", type=Path, metavar="PATH"
    )
    assembly_evidence.add_argument(
        "--expected-handoff-archive-sha256", metavar="HEX"
    )
    assembly_evidence.add_argument(
        "--expected-handoff-bundle-sha256", metavar="HEX"
    )
    assembly_evidence.add_argument("--pcbex", default="pcbex", metavar="CMD")
    assembly_evidence.add_argument(
        "--timeout-seconds", type=float, default=120.0, metavar="SECONDS"
    )
    assembly_evidence.add_argument(
        "--require-complete",
        action="store_true",
        help="fail after retaining an incomplete assembly-evidence report",
    )
    assembly_evidence_schema = sub.add_parser(
        "assembly-evidence-schema",
        help="write the closed exact assembly-evidence report JSON Schema",
    )
    assembly_evidence_schema.add_argument(
        "-o", "--output", type=Path, metavar="PATH"
    )
    assembly_supplier_offer_help = (
        "compose exact assembly evidence with retained supplier-offer acquisition "
        "and coverage evidence"
    )
    assembly_supplier_offer = sub.add_parser(
        "build-assembly-supplier-offer-evidence",
        help=assembly_supplier_offer_help,
        description=assembly_supplier_offer_help,
    )
    assembly_supplier_offer.add_argument(
        "handoff_zip", type=Path, metavar="HANDOFF_ZIP"
    )
    assembly_supplier_offer.add_argument("board", type=Path, metavar="BOARD")
    assembly_supplier_offer.add_argument(
        "manufacturing_zip", type=Path, metavar="MANUFACTURING_ZIP"
    )
    assembly_supplier_offer.add_argument(
        "--board-binding-report", type=Path, required=True, metavar="REPORT"
    )
    assembly_supplier_offer.add_argument(
        "--procurement-intent", type=Path, required=True, metavar="INTENT"
    )
    assembly_supplier_offer.add_argument(
        "--catalog-snapshot", type=Path, required=True, metavar="SNAPSHOT"
    )
    assembly_supplier_offer.add_argument(
        "--final-cpl-report", type=Path, required=True, metavar="REPORT"
    )
    assembly_supplier_offer.add_argument(
        "--assembly-evidence", type=Path, required=True, metavar="REPORT"
    )
    assembly_supplier_offer.add_argument(
        "--supplier-offer", type=Path, required=True, metavar="OFFER"
    )
    assembly_supplier_offer.add_argument(
        "--supplier-offer-fetch-receipt",
        type=Path,
        required=True,
        metavar="RECEIPT",
    )
    assembly_supplier_offer.add_argument(
        "--supplier-offer-coverage",
        type=Path,
        required=True,
        metavar="COVERAGE",
    )
    assembly_supplier_offer.add_argument(
        "--requested-boards", type=int, required=True, metavar="N"
    )
    assembly_supplier_offer.add_argument(
        "--evaluated-at-unix", type=int, required=True, metavar="N"
    )
    assembly_supplier_offer.add_argument(
        "--board-binding-policy", type=Path, metavar="POLICY"
    )
    assembly_supplier_offer.add_argument(
        "--manufacturing-kicad-cli", default="kicad-cli", metavar="CMD"
    )
    assembly_supplier_offer.add_argument(
        "--manufacturing-kicad-project", type=Path, metavar="PATH"
    )
    assembly_supplier_offer.add_argument(
        "--manufacturing-kicad-rules", type=Path, metavar="PATH"
    )
    assembly_supplier_offer_profile = (
        assembly_supplier_offer.add_mutually_exclusive_group()
    )
    assembly_supplier_offer_profile.add_argument(
        "--manufacturing-fab", metavar="ID"
    )
    assembly_supplier_offer_profile.add_argument(
        "--manufacturing-fab-profile", type=Path, metavar="PATH"
    )
    assembly_supplier_offer_profile.add_argument(
        "--manufacturing-physical-profile", type=Path, metavar="PATH"
    )
    assembly_supplier_offer.add_argument(
        "--expected-handoff-archive-sha256", metavar="HEX"
    )
    assembly_supplier_offer.add_argument(
        "--expected-handoff-bundle-sha256", metavar="HEX"
    )
    assembly_supplier_offer.add_argument("--pcbex", default="pcbex", metavar="CMD")
    assembly_supplier_offer.add_argument(
        "--timeout-seconds",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help="whole-evaluation timeout in seconds (default: 300.0)",
    )
    assembly_supplier_offer.add_argument(
        "-o", "--output", type=Path, required=True, metavar="REPORT"
    )
    assembly_supplier_offer.add_argument(
        "--require-complete",
        action="store_true",
        help="fail after retaining incomplete assembly supplier-offer evidence",
    )
    assembly_supplier_offer_schema = sub.add_parser(
        "assembly-supplier-offer-evidence-schema",
        help="write the closed assembly supplier-offer evidence JSON Schema",
    )
    assembly_supplier_offer_schema.add_argument(
        "-o", "--output", type=Path, metavar="PATH"
    )
    procurement_approval_help = (
        "sign one exact procurement approval against retained release evidence"
    )
    procurement_approval = sub.add_parser(
        "sign-procurement-approval",
        help=procurement_approval_help,
        description=procurement_approval_help,
    )
    _add_procurement_authorization_sources(procurement_approval)
    procurement_approval.add_argument(
        "--private-key", type=Path, required=True, metavar="PRIVATE_KEY"
    )
    _add_procurement_authorization_selectors(procurement_approval)
    _add_procurement_authorization_commands(procurement_approval, signing=True)
    procurement_approval.add_argument(
        "--expected-policy-pack-canonical-sha256",
        required=True,
        metavar="HEX",
    )
    procurement_approval.add_argument("--signer-id", required=True, metavar="ID")
    procurement_approval.add_argument(
        "--decision", choices=("approve", "reject"), required=True
    )
    procurement_approval.add_argument(
        "--authorization-id", required=True, metavar="ID"
    )
    procurement_approval.add_argument(
        "--challenge", required=True, metavar="CHALLENGE"
    )
    procurement_approval.add_argument(
        "--maximum-component-subtotal-micros",
        type=int,
        required=True,
        metavar="N",
    )
    procurement_approval.add_argument(
        "--valid-from-unix", type=int, required=True, metavar="N"
    )
    procurement_approval.add_argument(
        "--expires-at-unix", type=int, required=True, metavar="N"
    )
    procurement_approval.add_argument("--reason", required=True, metavar="TEXT")
    procurement_approval.add_argument("--ticket", required=True, metavar="TICKET")
    _add_procurement_authorization_replay_options(procurement_approval)
    procurement_approval.add_argument(
        "--timeout-seconds",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help="whole-operation timeout in seconds (default: 300.0)",
    )
    procurement_approval.add_argument(
        "-o", "--output", type=Path, required=True, metavar="APPROVAL"
    )
    procurement_authorization_help = (
        "verify signed approvals for one exact retained procurement release"
    )
    procurement_authorization = sub.add_parser(
        "verify-procurement-authorization",
        help=procurement_authorization_help,
        description=procurement_authorization_help,
    )
    _add_procurement_authorization_sources(procurement_authorization)
    procurement_authorization.add_argument(
        "--approval",
        action="append",
        type=Path,
        required=True,
        metavar="APPROVAL",
        help="signed procurement approval; repeat once per approval",
    )
    _add_procurement_authorization_selectors(procurement_authorization)
    _add_procurement_authorization_commands(
        procurement_authorization, signing=False
    )
    procurement_authorization.add_argument(
        "--expected-policy-pack-canonical-sha256",
        required=True,
        metavar="HEX",
    )
    _add_procurement_authorization_replay_options(procurement_authorization)
    procurement_authorization.add_argument(
        "--timeout-seconds",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help="whole-operation timeout in seconds (default: 300.0)",
    )
    procurement_authorization.add_argument(
        "-o", "--output", type=Path, required=True, metavar="REPORT"
    )
    procurement_authorization.add_argument(
        "--require-authorized",
        action="store_true",
        help="fail only after retaining an exact report that is not authorized",
    )
    procurement_reservation_help = (
        "freshly replay and durably admit one procurement challenge to a local ledger"
    )
    procurement_reservation = sub.add_parser(
        "reserve-procurement-authorization",
        help=procurement_reservation_help,
        description=procurement_reservation_help,
    )
    _add_procurement_authorization_sources(procurement_reservation)
    procurement_reservation.add_argument(
        "--report", type=Path, required=True, metavar="AUTHORIZATION_REPORT"
    )
    procurement_reservation.add_argument(
        "--approval",
        action="append",
        type=Path,
        required=True,
        metavar="APPROVAL",
        help="signed procurement approval; repeat once per approval",
    )
    _add_procurement_authorization_selectors(procurement_reservation)
    _add_procurement_authorization_commands(
        procurement_reservation, signing=False
    )
    procurement_reservation.add_argument(
        "--expected-policy-pack-canonical-sha256",
        required=True,
        metavar="HEX",
    )
    _add_procurement_authorization_replay_options(procurement_reservation)
    procurement_reservation.add_argument(
        "--reservation-ledger",
        type=Path,
        required=True,
        metavar="ABSOLUTE_DIRECTORY",
    )
    procurement_reservation.add_argument(
        "--expected-ledger-id", required=True, metavar="HEX"
    )
    procurement_reservation.add_argument(
        "--timeout-seconds",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help="whole-operation timeout in seconds (default: 300.0)",
    )
    signed_procurement_approval_schema = sub.add_parser(
        "signed-procurement-approval-schema",
        help="write the closed signed procurement approval JSON Schema",
    )
    signed_procurement_approval_schema.add_argument(
        "-o", "--output", type=Path, metavar="PATH"
    )
    procurement_authorization_report_schema = sub.add_parser(
        "procurement-authorization-report-schema",
        help="write the closed procurement authorization report JSON Schema",
    )
    procurement_authorization_report_schema.add_argument(
        "-o", "--output", type=Path, metavar="PATH"
    )
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
            manufacturing_options = {}
            if (
                args.manufacturing_package is not None
                or args.manufacturing_kicad_cli is not None
                or args.manufacturing_kicad_project is not None
                or args.manufacturing_kicad_rules is not None
                or args.manufacturing_fab is not None
                or args.manufacturing_fab_profile is not None
                or args.manufacturing_physical_profile is not None
            ):
                manufacturing_options = {
                    "retained_manufacturing_package": args.manufacturing_package,
                    "manufacturing_kicad_project": (
                        args.manufacturing_kicad_project
                    ),
                    "manufacturing_kicad_rules": args.manufacturing_kicad_rules,
                    "manufacturing_fab": args.manufacturing_fab,
                    "manufacturing_fab_profile": args.manufacturing_fab_profile,
                    "manufacturing_physical_profile": (
                        args.manufacturing_physical_profile
                    ),
                }
                if args.manufacturing_kicad_cli is not None:
                    manufacturing_options["manufacturing_kicad_cli"] = (
                        args.manufacturing_kicad_cli
                    )
            pipeline_options = {}
            if (
                args.deterministic_pipeline_plan is not None
                or args.deterministic_pipeline_report is not None
                or args.require_deterministic_pipeline_approved
            ):
                pipeline_options = {
                    "deterministic_pipeline_plan": (
                        args.deterministic_pipeline_plan
                    ),
                    "retained_deterministic_pipeline_report": (
                        args.deterministic_pipeline_report
                    ),
                    "require_deterministic_pipeline_approved": (
                        args.require_deterministic_pipeline_approved
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
                **manufacturing_options,
                **pipeline_options,
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
    elif args.command == "circuit-handoff-bundle-manufacturing-replay-result-schema":
        try:
            rendered = (
                json.dumps(
                    circuit_handoff_bundle_manufacturing_replay_result_json_schema(),
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
                "circuit handoff manufacturing replay schema failed: "
                f"{error}"
            ) from error
    elif args.command == "circuit-handoff-bundle-pipeline-replay-result-schema":
        try:
            rendered = (
                json.dumps(
                    circuit_handoff_bundle_pipeline_replay_result_json_schema(),
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
                f"circuit handoff pipeline replay schema failed: {error}"
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
    elif args.command == "replay-deterministic-pipeline":
        try:
            result = replay_deterministic_pipeline(
                args.plan,
                args.retained_report,
                args.pcbex,
                timeout_seconds=args.timeout_seconds,
            )
        except (OSError, BoundedIOError, DeterministicPipelineReplayError) as error:
            raise SystemExit(
                f"deterministic pipeline replay failed: {error}"
            ) from error
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if args.require_approved and not result["report"]["approved"]:
            raise SystemExit(
                "deterministic pipeline replay was exact but was not approved"
            )
    elif args.command == "deterministic-pipeline-replay-result-schema":
        try:
            rendered = (
                json.dumps(
                    deterministic_pipeline_replay_result_json_schema(),
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
        except (OSError, BoundedIOError, DeterministicPipelineReplayError) as error:
            raise SystemExit(
                f"deterministic pipeline replay schema failed: {error}"
            ) from error
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
    elif args.command == "build-procurement-intent":
        try:
            validate_no_clobber_path(args.output)
            result = evaluate_procurement_intent(
                args.board,
                args.manufacturing_package,
                args.circuit_generation,
                args.catalog_snapshot,
                args.pcbex,
                timeout_seconds=args.timeout_seconds,
            )
            rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
            atomic_write_text_no_clobber(
                args.output,
                rendered,
                max_bytes=MAXIMUM_PROCUREMENT_INTENT_BYTES,
            )
        except (OSError, BoundedIOError, ProcurementIntentError) as error:
            raise SystemExit(f"procurement intent evaluation failed: {error}") from error
        if args.require_approved and not result["approved"]:
            raise SystemExit(
                "procurement intent report was retained but was not technically approved"
            )
    elif args.command == "procurement-intent-schema":
        try:
            rendered = (
                json.dumps(
                    procurement_intent_json_schema(),
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
        except (OSError, BoundedIOError, ProcurementIntentError) as error:
            raise SystemExit(f"procurement intent schema failed: {error}") from error
    elif args.command == "fetch-supplier-offer":
        try:
            receipt = fetch_supplier_offer(
                args.endpoint,
                args.supplier,
                args.output,
                args.receipt,
                procurement_intent_sha256=args.procurement_intent_sha256,
                timeout_seconds=args.timeout_seconds,
                maximum_response_bytes=args.maximum_response_bytes,
                bearer_token_environment=args.bearer_token_environment,
            )
        except SupplierOfferAcquisitionError as error:
            raise SystemExit(f"supplier offer fetch failed: {error}") from None
        print(
            "supplier offer written with response "
            f"{receipt['response_sha256']} and offer {receipt['offer_sha256']}"
        )
    elif args.command == "supplier-offer-fetch-receipt-schema":
        try:
            if args.output:
                validate_no_clobber_path(args.output)
            rendered = (
                json.dumps(
                    supplier_offer_fetch_receipt_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
                atomic_write_text_no_clobber(
                    args.output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            else:
                print(rendered, end="")
        except (OSError, BoundedIOError, SupplierOfferAcquisitionError) as error:
            raise SystemExit(
                f"supplier offer fetch receipt schema failed: {error}"
            ) from error
    elif args.command == "build-supplier-offer-coverage":
        try:
            validate_no_clobber_path(args.output)
            result = evaluate_supplier_offer_coverage(
                args.board,
                args.manufacturing_package,
                args.circuit_generation,
                args.catalog_snapshot,
                args.procurement_intent,
                args.supplier_offer,
                args.pcbex,
                requested_boards=args.requested_boards,
                evaluated_at_unix=args.evaluated_at_unix,
                timeout_seconds=args.timeout_seconds,
            )
            rendered = render_supplier_offer_coverage(result)
            atomic_write_no_clobber(
                args.output,
                rendered,
                max_bytes=MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
            )
        except (OSError, BoundedIOError, SupplierOfferError) as error:
            raise SystemExit(
                f"supplier offer coverage evaluation failed: {error}"
            ) from error
        if args.require_covered and not result["covered"]:
            raise SystemExit(
                "supplier offer coverage report was retained but the offer does not "
                "cover the procurement intent"
            )
    elif args.command in {
        "supplier-offer-schema",
        "supplier-offer-coverage-schema",
    }:
        try:
            if args.command == "supplier-offer-schema":
                schema = normalized_supplier_offer_json_schema()
            else:
                schema = supplier_offer_coverage_json_schema()
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
        except (OSError, BoundedIOError, SupplierOfferError) as error:
            raise SystemExit(f"supplier offer schema failed: {error}") from error
    elif args.command == "build-assembly-evidence":
        try:
            validate_no_clobber_path(args.output)
            result = evaluate_assembly_evidence(
                args.handoff_zip,
                args.board,
                args.manufacturing_zip,
                args.board_binding_report,
                args.procurement_intent,
                args.catalog_snapshot,
                args.final_cpl_report,
                args.pcbex,
                board_binding_policy=args.board_binding_policy,
                kicad_cli=args.manufacturing_kicad_cli,
                manufacturing_kicad_project=args.manufacturing_kicad_project,
                manufacturing_kicad_rules=args.manufacturing_kicad_rules,
                manufacturing_fab=args.manufacturing_fab,
                manufacturing_fab_profile=args.manufacturing_fab_profile,
                manufacturing_physical_profile=args.manufacturing_physical_profile,
                expected_archive_sha256=args.expected_handoff_archive_sha256,
                expected_bundle_sha256=args.expected_handoff_bundle_sha256,
                timeout_seconds=args.timeout_seconds,
            )
            rendered = render_assembly_evidence(result)
            atomic_write_no_clobber(
                args.output,
                rendered,
                max_bytes=MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
            )
        except (OSError, BoundedIOError, AssemblyEvidenceError) as error:
            raise SystemExit(f"assembly evidence evaluation failed: {error}") from error
        if args.require_complete and not result["complete"]:
            raise SystemExit(
                "assembly evidence report was retained but assembly evidence is incomplete"
            )
    elif args.command == "assembly-evidence-schema":
        try:
            rendered = (
                json.dumps(
                    assembly_evidence_json_schema(),
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
        except (OSError, BoundedIOError, AssemblyEvidenceError) as error:
            raise SystemExit(f"assembly evidence schema failed: {error}") from error
    elif args.command == "build-assembly-supplier-offer-evidence":
        try:
            frozen_output = _preflight_assembly_supplier_offer_output(
                args.output,
                (
                    args.handoff_zip,
                    args.board,
                    args.manufacturing_zip,
                    args.board_binding_report,
                    args.procurement_intent,
                    args.catalog_snapshot,
                    args.final_cpl_report,
                    args.assembly_evidence,
                    args.supplier_offer,
                    args.supplier_offer_fetch_receipt,
                    args.supplier_offer_coverage,
                    args.board_binding_policy,
                    args.manufacturing_kicad_project,
                    args.manufacturing_kicad_rules,
                    args.manufacturing_fab_profile,
                    args.manufacturing_physical_profile,
                ),
            )
            result = evaluate_assembly_supplier_offer_evidence(
                args.handoff_zip,
                args.board,
                args.manufacturing_zip,
                args.board_binding_report,
                args.procurement_intent,
                args.catalog_snapshot,
                args.final_cpl_report,
                args.assembly_evidence,
                args.supplier_offer,
                args.supplier_offer_fetch_receipt,
                args.supplier_offer_coverage,
                args.pcbex,
                requested_boards=args.requested_boards,
                evaluated_at_unix=args.evaluated_at_unix,
                board_binding_policy=args.board_binding_policy,
                kicad_cli=args.manufacturing_kicad_cli,
                manufacturing_kicad_project=args.manufacturing_kicad_project,
                manufacturing_kicad_rules=args.manufacturing_kicad_rules,
                manufacturing_fab=args.manufacturing_fab,
                manufacturing_fab_profile=args.manufacturing_fab_profile,
                manufacturing_physical_profile=args.manufacturing_physical_profile,
                expected_archive_sha256=args.expected_handoff_archive_sha256,
                expected_bundle_sha256=args.expected_handoff_bundle_sha256,
                timeout_seconds=args.timeout_seconds,
            )
            rendered = render_assembly_supplier_offer_evidence(result)
            atomic_write_no_clobber(
                frozen_output,
                rendered,
                max_bytes=MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
            )
        except (OSError, BoundedIOError, AssemblySupplierOfferEvidenceError) as error:
            raise SystemExit(
                f"assembly supplier-offer evidence evaluation failed: {error}"
            ) from None
        if args.require_complete and not result["complete"]:
            raise SystemExit(
                "assembly supplier-offer evidence report was retained but evidence "
                "is incomplete"
            )
    elif args.command == "assembly-supplier-offer-evidence-schema":
        try:
            if args.output:
                validate_no_clobber_path(args.output)
            rendered = (
                json.dumps(
                    assembly_supplier_offer_evidence_json_schema(),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            if args.output:
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
            AssemblySupplierOfferEvidenceError,
        ) as error:
            raise SystemExit(
                f"assembly supplier-offer evidence schema failed: {error}"
            ) from None
    elif args.command == "sign-procurement-approval":
        try:
            frozen_output = _preflight_procurement_authorization_output(
                args.output,
                _procurement_authorization_input_paths(
                    args, private_key=args.private_key
                ),
            )
        except (OSError, TypeError, ValueError) as error:
            raise SystemExit(
                f"procurement approval signing failed: {error}"
            ) from None
        try:
            result = sign_procurement_approval(
                args.evidence,
                args.handoff,
                args.board,
                args.manufacturing_package,
                args.board_binding_report,
                args.procurement_intent,
                args.catalog_snapshot,
                args.final_cpl_report,
                args.assembly_evidence,
                args.supplier_offer,
                args.supplier_offer_fetch_receipt,
                args.supplier_offer_coverage,
                args.policy_pack,
                args.private_key,
                args.pcbex,
                args.authorization_pcbex,
                requested_boards=args.requested_boards,
                evaluated_at_unix=args.evaluated_at_unix,
                expected_policy_pack_canonical_sha256=(
                    args.expected_policy_pack_canonical_sha256
                ),
                signer_id=args.signer_id,
                decision=args.decision,
                authorization_id=args.authorization_id,
                challenge=args.challenge,
                maximum_component_subtotal_micros=(
                    args.maximum_component_subtotal_micros
                ),
                valid_from_unix=args.valid_from_unix,
                expires_at_unix=args.expires_at_unix,
                reason=args.reason,
                ticket=args.ticket,
                board_binding_policy=args.board_binding_policy,
                kicad_cli=args.manufacturing_kicad_cli,
                manufacturing_kicad_project=args.manufacturing_kicad_project,
                manufacturing_kicad_rules=args.manufacturing_kicad_rules,
                manufacturing_fab=args.manufacturing_fab,
                manufacturing_fab_profile=args.manufacturing_fab_profile,
                manufacturing_physical_profile=(
                    args.manufacturing_physical_profile
                ),
                expected_archive_sha256=args.expected_handoff_archive_sha256,
                expected_bundle_sha256=args.expected_handoff_bundle_sha256,
                timeout_seconds=args.timeout_seconds,
            )
            rendered = render_signed_procurement_approval(result)
        except ProcurementReleaseAuthorizationError as error:
            raise SystemExit(
                f"procurement approval signing failed: {error}"
            ) from None
        except OSError:
            raise SystemExit(
                "procurement approval signing failed: local operation failed"
            ) from None
        try:
            atomic_write_no_clobber(
                frozen_output,
                rendered,
                max_bytes=MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES,
            )
        except OSError:
            raise SystemExit(
                "procurement approval signing failed: output publication failed"
            ) from None
    elif args.command == "verify-procurement-authorization":
        try:
            frozen_output = _preflight_procurement_authorization_output(
                args.output,
                _procurement_authorization_input_paths(
                    args, approvals=tuple(args.approval)
                ),
            )
        except (OSError, TypeError, ValueError) as error:
            raise SystemExit(
                f"procurement authorization verification failed: {error}"
            ) from None
        try:
            result = verify_procurement_authorization(
                args.evidence,
                args.handoff,
                args.board,
                args.manufacturing_package,
                args.board_binding_report,
                args.procurement_intent,
                args.catalog_snapshot,
                args.final_cpl_report,
                args.assembly_evidence,
                args.supplier_offer,
                args.supplier_offer_fetch_receipt,
                args.supplier_offer_coverage,
                args.policy_pack,
                args.approval,
                args.pcbex,
                args.authorization_pcbex,
                requested_boards=args.requested_boards,
                evaluated_at_unix=args.evaluated_at_unix,
                expected_policy_pack_canonical_sha256=(
                    args.expected_policy_pack_canonical_sha256
                ),
                board_binding_policy=args.board_binding_policy,
                kicad_cli=args.manufacturing_kicad_cli,
                manufacturing_kicad_project=args.manufacturing_kicad_project,
                manufacturing_kicad_rules=args.manufacturing_kicad_rules,
                manufacturing_fab=args.manufacturing_fab,
                manufacturing_fab_profile=args.manufacturing_fab_profile,
                manufacturing_physical_profile=(
                    args.manufacturing_physical_profile
                ),
                expected_archive_sha256=args.expected_handoff_archive_sha256,
                expected_bundle_sha256=args.expected_handoff_bundle_sha256,
                timeout_seconds=args.timeout_seconds,
            )
            rendered = render_procurement_authorization_report(result)
        except ProcurementReleaseAuthorizationError as error:
            raise SystemExit(
                f"procurement authorization verification failed: {error}"
            ) from None
        except OSError:
            raise SystemExit(
                "procurement authorization verification failed: local operation failed"
            ) from None
        try:
            atomic_write_no_clobber(
                frozen_output,
                rendered,
                max_bytes=MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
            )
        except OSError:
            raise SystemExit(
                "procurement authorization verification failed: "
                "output publication failed"
            ) from None
        if args.require_authorized and not result["procurement_authorized"]:
            raise SystemExit(
                "procurement authorization report was retained but the exact "
                "release was not authorized"
            )
    elif args.command == "reserve-procurement-authorization":
        if os.name != "posix":
            raise SystemExit(
                "procurement authorization reservation failed: local reservation "
                "is supported only on Unix"
            )
        timeout = args.timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 3.0 <= float(timeout) <= 600.0
        ):
            raise SystemExit(
                "procurement authorization reservation failed: timeout must be "
                "between 3 and 600 seconds"
            )
        deadline = time.monotonic() + float(timeout)
        replay_reserve = min(15.0, float(timeout) / 3.0)
        replay_budget = float(timeout) - replay_reserve
        try:
            result = validate_procurement_release_authorization(
                args.report,
                args.evidence,
                args.handoff,
                args.board,
                args.manufacturing_package,
                args.board_binding_report,
                args.procurement_intent,
                args.catalog_snapshot,
                args.final_cpl_report,
                args.assembly_evidence,
                args.supplier_offer,
                args.supplier_offer_fetch_receipt,
                args.supplier_offer_coverage,
                args.policy_pack,
                args.approval,
                args.pcbex,
                args.authorization_pcbex,
                requested_boards=args.requested_boards,
                evaluated_at_unix=args.evaluated_at_unix,
                expected_policy_pack_canonical_sha256=(
                    args.expected_policy_pack_canonical_sha256
                ),
                board_binding_policy=args.board_binding_policy,
                kicad_cli=args.manufacturing_kicad_cli,
                manufacturing_kicad_project=args.manufacturing_kicad_project,
                manufacturing_kicad_rules=args.manufacturing_kicad_rules,
                manufacturing_fab=args.manufacturing_fab,
                manufacturing_fab_profile=args.manufacturing_fab_profile,
                manufacturing_physical_profile=(
                    args.manufacturing_physical_profile
                ),
                expected_archive_sha256=args.expected_handoff_archive_sha256,
                expected_bundle_sha256=args.expected_handoff_bundle_sha256,
                timeout_seconds=replay_budget,
            )
            if not result["procurement_authorized"]:
                raise ProcurementAuthorizationReservationError(
                    "fresh authorization did not authorize the exact release"
                )
            marker = build_procurement_authorization_reservation(
                result, args.expected_ledger_id
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProcurementAuthorizationReservationError(
                    "whole-operation deadline expired before ledger commit"
                )
            protected = tuple(
                path
                for path in (
                    *_procurement_authorization_input_paths(
                        args, approvals=tuple(args.approval)
                    ),
                    args.report,
                )
                if path is not None
            )
            commit_procurement_authorization_reservation(
                marker,
                args.reservation_ledger,
                args.expected_ledger_id,
                args.authorization_pcbex,
                protected,
                timeout_seconds=remaining,
            )
        except (
            ProcurementReleaseAuthorizationError,
            ProcurementAuthorizationReservationError,
        ) as error:
            raise SystemExit(
                f"procurement authorization reservation failed: {error}"
            ) from None
        except OSError:
            raise SystemExit(
                "procurement authorization reservation failed: local operation failed"
            ) from None
        print("procurement authorization reserved durably in trusted local ledger")
    elif args.command in {
        "signed-procurement-approval-schema",
        "procurement-authorization-report-schema",
    }:
        prefix = (
            "signed procurement approval schema failed"
            if args.command == "signed-procurement-approval-schema"
            else "procurement authorization report schema failed"
        )
        frozen_output = None
        if args.output:
            try:
                frozen_output = _preflight_procurement_authorization_output(
                    args.output, ()
                )
            except (OSError, TypeError, ValueError) as error:
                raise SystemExit(f"{prefix}: {error}") from None
        try:
            schema = (
                signed_procurement_approval_json_schema()
                if args.command == "signed-procurement-approval-schema"
                else procurement_authorization_report_json_schema()
            )
            rendered = (
                json.dumps(
                    schema,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
                + "\n"
            )
        except ProcurementReleaseAuthorizationError as error:
            raise SystemExit(f"{prefix}: {error}") from None
        if frozen_output is None:
            try:
                print(rendered, end="")
            except OSError:
                raise SystemExit(f"{prefix}: output publication failed") from None
        else:
            try:
                atomic_write_text_no_clobber(
                    frozen_output,
                    rendered,
                    max_bytes=MAXIMUM_AGENT_FILE_BYTES,
                )
            except OSError:
                raise SystemExit(f"{prefix}: output publication failed") from None
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

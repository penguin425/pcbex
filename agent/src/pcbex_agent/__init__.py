"""Planning and bounded repair orchestration for pcbex."""

from .planner import PlanningError, build_plan
from .managed_provider import (
    managed_provider_receipt_json_schema,
    review_schematic_with_managed_provider,
)
from .provider import (
    ProviderError,
    provider_receipt_json_schema,
    run_provider_command,
    review_schematic_with_command,
)
from .circuit_generation import (
    CircuitCandidateRejected,
    CircuitCatalogRejected,
    CircuitGenerationError,
    circuit_generation_json_schema,
    fetch_circuit_spec_check_schema,
    fetch_circuit_spec_v2_schema,
    generate_circuit_with_command,
    generate_circuit_with_llm,
)
from .circuit_handoff_bundle import (
    CircuitHandoffBundleError,
    build_circuit_handoff_archive,
    circuit_handoff_bundle_json_schema,
    circuit_handoff_bundle_replay_result_json_schema,
    circuit_handoff_bundle_result_json_schema,
    extract_circuit_handoff_bundle,
    handoff_circuit_generation,
    replay_circuit_handoff_bundle,
    validate_circuit_handoff_archive,
    validate_circuit_generation_bundle,
    verify_circuit_handoff_bundle,
)
from .review import ReviewError, review_schematic_with_llm
from .catalog_provenance import (
    CatalogGenerationProvenanceError,
    build_catalog_generation_provenance,
    catalog_generation_provenance_json_schema,
    validate_catalog_generation_provenance,
)
from .supplier_inventory import (
    SupplierInventoryError,
    catalog_fetch_receipt_json_schema,
    fetch_catalog_snapshot,
    validate_catalog_fetch_receipt,
)

__all__ = [
    "PlanningError",
    "ProviderError",
    "ReviewError",
    "SupplierInventoryError",
    "CatalogGenerationProvenanceError",
    "CircuitGenerationError",
    "CircuitCandidateRejected",
    "CircuitCatalogRejected",
    "CircuitHandoffBundleError",
    "build_plan",
    "build_catalog_generation_provenance",
    "build_circuit_handoff_archive",
    "catalog_fetch_receipt_json_schema",
    "catalog_generation_provenance_json_schema",
    "managed_provider_receipt_json_schema",
    "provider_receipt_json_schema",
    "run_provider_command",
    "circuit_generation_json_schema",
    "circuit_handoff_bundle_json_schema",
    "circuit_handoff_bundle_replay_result_json_schema",
    "circuit_handoff_bundle_result_json_schema",
    "extract_circuit_handoff_bundle",
    "fetch_circuit_spec_v2_schema",
    "fetch_circuit_spec_check_schema",
    "generate_circuit_with_command",
    "generate_circuit_with_llm",
    "handoff_circuit_generation",
    "replay_circuit_handoff_bundle",
    "fetch_catalog_snapshot",
    "review_schematic_with_managed_provider",
    "review_schematic_with_command",
    "review_schematic_with_llm",
    "validate_catalog_fetch_receipt",
    "validate_catalog_generation_provenance",
    "validate_circuit_handoff_archive",
    "validate_circuit_generation_bundle",
    "verify_circuit_handoff_bundle",
]

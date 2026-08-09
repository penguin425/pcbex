from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import sys
import tempfile
import unittest
from unittest import mock

from agent.tests.test_circuit_handoff_bundle_v1448 import (
    _catalog_snapshot,
    _render,
    _spec,
    _write_fake_pcbex,
)
from agent.tests.test_circuit_handoff_bundle_v1449 import _archive_entries
from agent.tests.test_circuit_handoff_bundle_v1450 import _valid_archive_with_command
from agent.tests.test_circuit_handoff_bundle_v1451 import (
    _retained_report,
    _write_native_wrapper,
)
from agent.tests.test_circuit_handoff_bundle_v1452 import (
    _write_ai_inputs,
    _write_ai_wrapper,
)
from pcbex_agent import cli
from pcbex_agent import circuit_handoff_bundle as handoff_module
from pcbex_agent import supplier_inventory
from pcbex_agent.catalog import (
    load_catalog_snapshot,
    select_catalog_parts,
    validate_catalog_receipt,
)
from pcbex_agent.catalog_provenance import build_catalog_generation_provenance
from pcbex_agent.circuit_generation import (
    _compact_json,
    generate_circuit_with_command,
    generate_circuit_with_llm,
)
from pcbex_agent.circuit_handoff_bundle import (
    CircuitHandoffBundleError,
    build_circuit_handoff_archive,
    circuit_handoff_bundle_ai_quorum_replay_result_json_schema,
    circuit_handoff_bundle_catalog_provenance_replay_result_json_schema,
    handoff_circuit_generation,
    replay_circuit_handoff_bundle,
)
from pcbex_agent.supplier_inventory import (
    CATALOG_FETCH_ADAPTER,
    _pretty_json_bytes,
    _request_sha256,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _check_envelope(spec: dict[str, object]) -> dict[str, object]:
    review = {
        "schema_version": 1,
        "schematic_sha256": "1" * 64,
        "policy_sha256": "2" * 64,
        "policy_id": "pcbex-electrical-default-v1",
        "approved": True,
        "counts": {"errors": 0, "warnings": 0, "info": 0},
        "findings": [],
    }
    return {
        "schema_version": 1,
        "circuit_spec_sha256": _sha(_compact_json(spec)),
        "electrical_review_sha256": _sha(_compact_json(review)),
        "normalized_spec": spec,
        "electrical_review": review,
    }


def _catalog_generation_bundle(snapshot) -> tuple[dict[str, object], dict[str, object]]:
    initial = _spec()

    def checker(path: Path, _remaining: float) -> dict[str, object]:
        if path.name.startswith("candidate-"):
            selected = initial
        else:
            selected = json.loads(path.read_text(encoding="utf-8"))
        return _check_envelope(selected)

    def selector(spec: dict[str, object], _remaining: float):
        return select_catalog_parts(spec, snapshot, evaluated_at_unix=150)

    def receipt_validator(
        original: dict[str, object],
        resolved: dict[str, object],
        receipt: dict[str, object],
        _remaining: float,
    ) -> None:
        validate_catalog_receipt(
            receipt,
            original,
            resolved,
            snapshot,
            evaluated_at_unix=150,
        )

    bundle = generate_circuit_with_llm(
        "two 1k resistors",
        {"type": "object"},
        lambda _prompt, _remaining: '{"candidate":1}',
        checker,
        catalog_selector=selector,
        catalog_receipt_validator=receipt_validator,
    )
    return bundle, _check_envelope(initial)


def _catalog_artifacts(root: Path, *, source_kind: str = "injected") -> dict[str, object]:
    """Build a catalog archive and all three retained provenance sources offline."""

    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    source_model = _catalog_snapshot()
    snapshot_raw = _pretty_json_bytes(source_model.to_mapping())
    if source_kind == "injected":
        # A JSON string is an injected source, while retaining the normalized
        # pretty bytes that the fetch-receipt adapter admits.
        snapshot = load_catalog_snapshot(
            snapshot_raw.decode("utf-8"),
            evaluated_at_unix=150,
        )
        snapshot_path = root / "catalog-input.json"
        provenance_snapshot_source: object = snapshot_raw
    elif source_kind == "file":
        snapshot_path = root / "nested" / "catalog-source.json"
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        provenance_snapshot_source = snapshot_path
    else:  # pragma: no cover - helper misuse
        raise AssertionError(source_kind)
    snapshot_path.write_bytes(snapshot_raw)
    if source_kind == "file":
        snapshot = load_catalog_snapshot(snapshot_path, evaluated_at_unix=150)

    bundle, initial_check = _catalog_generation_bundle(snapshot)
    bundle_raw = _render(bundle)
    command = _write_fake_pcbex(
        root,
        bundle["check"],
        initial_check=initial_check,
    )
    archive_raw, manifest = build_circuit_handoff_archive(bundle_raw, command)
    archive_path = root / "catalog-handoff.zip"
    archive_path.write_bytes(archive_raw)

    endpoint = "https://supplier.example/catalog"
    response_raw = b"offline supplier response"
    fetch = {
        "schema_version": 1,
        "adapter": CATALOG_FETCH_ADAPTER,
        "provider": snapshot.supplier,
        "endpoint_id": endpoint,
        "request_sha256": _request_sha256(snapshot.supplier, endpoint),
        "response_sha256": _sha(response_raw),
        "response_bytes": len(response_raw),
        "status": 200,
        "fetched_at_unix": 150,
        "expires_at_unix": snapshot.expires_at_unix,
        "snapshot_bytes": len(snapshot_raw),
        "snapshot_sha256": _sha(snapshot_raw),
        "catalog_sha256": snapshot.catalog_sha256,
    }
    fetch_raw = _pretty_json_bytes(fetch)
    provenance = build_catalog_generation_provenance(
        fetch_raw,
        provenance_snapshot_source,
        bundle_raw,
        bundle["skidl"],
        evaluated_at_unix=150,
    )
    provenance_path = root / "catalog-provenance.json"
    fetch_path = root / "catalog-fetch.json"
    provenance_path.write_bytes(_render(provenance))
    fetch_path.write_bytes(fetch_raw)
    return {
        "root": root,
        "archive": archive_path,
        "archive_raw": archive_raw,
        "manifest": manifest,
        "command": command,
        "bundle": bundle,
        "snapshot": snapshot,
        "snapshot_path": snapshot_path,
        "snapshot_raw": snapshot_raw,
        "provenance": provenance_path,
        "provenance_raw": provenance_path.read_bytes(),
        "provenance_value": provenance,
        "fetch": fetch_path,
        "fetch_raw": fetch_raw,
    }


def _catalog_kwargs(artifacts: dict[str, object]) -> dict[str, object]:
    return {
        "catalog_generation_provenance": artifacts["provenance"],
        "catalog_fetch_receipt": artifacts["fetch"],
        "catalog_snapshot": artifacts["snapshot_path"],
    }


def _compact_result(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _expected_ai_evidence(
    report_raw: bytes,
    source_raws: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "quorum_met": True,
        "quorum_required": True,
        "request_sha256": "1" * 64,
        "policy": {
            "minimum_approvals": 2,
            "minimum_distinct_providers": 2,
            "minimum_distinct_models": 2,
        },
        "counts": {
            "members": 2,
            "approvals": 2,
            "rejections": 0,
            "distinct_providers": 2,
            "distinct_models": 2,
        },
        "report": {"bytes": len(report_raw), "sha256": _sha(report_raw)},
        "sources": {
            "request": {
                "bytes": len(source_raws["request"]),
                "sha256": _sha(source_raws["request"]),
            },
            "policy_pack": {
                "bytes": len(source_raws["policy"]),
                "sha256": _sha(source_raws["policy"]),
            },
            "members": [
                {
                    "approval": {
                        "bytes": len(approval),
                        "sha256": _sha(approval),
                    },
                    "response": {
                        "bytes": len(response),
                        "sha256": _sha(response),
                    },
                }
                for approval, response in zip(
                    source_raws["approvals"],
                    source_raws["responses"],
                    strict=True,
                )
            ],
        },
    }


class CircuitHandoffBundleV1453Tests(unittest.TestCase):
    def test_catalog_snapshot_private_leaf_rejects_windows_escapes(self) -> None:
        private = PureWindowsPath("C:/pcbex-private")
        self.assertNotEqual((private / "D:catalog.json").parent, private)

        unsafe_names = (
            "D:catalog.json",
            "catalog.json:payload",
            "CON",
            "nul.json",
            "COM1.txt",
            "LPT\N{SUPERSCRIPT ONE}",
            "catalog.json.",
            "catalog.json ",
            "catalog?.json",
        )
        for source_name in unsafe_names:
            with self.subTest(source_name=source_name), mock.patch.object(
                handoff_module.tempfile,
                "TemporaryDirectory",
            ) as temporary_directory, mock.patch.object(
                handoff_module,
                "atomic_write_no_clobber",
            ) as writer:
                with self.assertRaisesRegex(
                    CircuitHandoffBundleError,
                    "snapshot source is invalid",
                ):
                    handoff_module._catalog_generation_provenance_evidence(
                        b"{}",
                        b"{}",
                        b"{}",
                        b"{}",
                        {
                            "source": {
                                "kind": "file",
                                "name": source_name,
                                "bytes": 2,
                                "sha256": "0" * 64,
                            }
                        },
                        deadline=1.0,
                        clock=lambda: 0.0,
                    )
                temporary_directory.assert_not_called()
                writer.assert_not_called()

    def test_catalog_only_replay_is_closed_path_free_v4_and_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = _catalog_artifacts(Path(directory) / "catalog")
            with mock.patch.object(
                supplier_inventory,
                "_http_get",
                side_effect=AssertionError("catalog replay must not use the network"),
            ):
                result = replay_circuit_handoff_bundle(
                    artifacts["archive"],
                    artifacts["command"],
                    expected_archive_sha256=_sha(artifacts["archive_raw"]),
                    expected_bundle_sha256=artifacts["manifest"]["bundle_sha256"],
                    **_catalog_kwargs(artifacts),
                )
            root_text = str(artifacts["root"])

        self.assertEqual(result["schema_version"], 4)
        self.assertEqual(
            result["verification_scope"],
            handoff_module.CIRCUIT_HANDOFF_BUNDLE_CATALOG_PROVENANCE_REPLAY_SCOPE,
        )
        self.assertTrue(result["validation"]["catalog_input_erc_replayed"])
        self.assertTrue(result["validation"]["catalog_generation_provenance_replayed"])
        self.assertFalse(result["validation"]["native_kicad_erc_replayed"])
        self.assertFalse(result["validation"]["ai_schematic_quorum_replayed"])
        self.assertEqual(
            result["catalog_generation_provenance"],
            {
                **artifacts["provenance_value"],
                "sources": {
                    "provenance": {
                        "bytes": len(artifacts["provenance_raw"]),
                        "sha256": _sha(artifacts["provenance_raw"]),
                    },
                    "fetch_receipt": {
                        "bytes": len(artifacts["fetch_raw"]),
                        "sha256": _sha(artifacts["fetch_raw"]),
                    },
                    "snapshot": {
                        "bytes": len(artifacts["snapshot_raw"]),
                        "sha256": _sha(artifacts["snapshot_raw"]),
                    },
                },
            },
        )
        self.assertNotIn(root_text, json.dumps(result))

        schema = circuit_handoff_bundle_catalog_provenance_replay_result_json_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["$id"],
            "https://github.com/penguin425/pcbex/schemas/"
            "circuit-generation-kicad-handoff-bundle-catalog-provenance-"
            "replay-result-v4.json",
        )
        self.assertIn("catalog_generation_provenance", schema["required"])
        self.assertEqual(
            schema["properties"]["validation"]["properties"][
                "catalog_generation_provenance_replayed"
            ],
            {"const": True},
        )
        self.assertEqual(len(schema["allOf"]), 2)
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        Draft202012Validator.check_schema(schema)
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(result)), [])
        forged = copy.deepcopy(result)
        forged["unexpected"] = True
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(forged)))

    def test_catalog_replay_supports_optional_native_and_ai_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            artifacts = _catalog_artifacts(root / "catalog")
            schematic_raw = _archive_entries(artifacts["archive_raw"])[
                handoff_module.SCHEMATIC_NAME
            ]
            native_report = root / "native-erc.json"
            native_report.write_bytes(_retained_report(schematic_raw))
            native_command = _write_native_wrapper(
                root,
                artifacts["command"],
                schema_version=1,
            )
            ai_options, report_raw, source_raws = _write_ai_inputs(
                root,
                schematic_raw,
            )
            command = _write_ai_wrapper(root, native_command, report_raw)
            with mock.patch.object(
                supplier_inventory,
                "_http_get",
                side_effect=AssertionError("catalog replay must be offline"),
            ):
                result = replay_circuit_handoff_bundle(
                    artifacts["archive"],
                    command,
                    retained_native_kicad_erc_report=native_report,
                    require_native_kicad_erc_approved=True,
                    require_ai_quorum=True,
                    **_catalog_kwargs(artifacts),
                    **ai_options,
                )

        self.assertEqual(result["schema_version"], 4)
        self.assertTrue(result["validation"]["native_kicad_erc_replayed"])
        self.assertTrue(result["validation"]["ai_schematic_quorum_replayed"])
        self.assertTrue(result["validation"]["catalog_generation_provenance_replayed"])
        self.assertTrue(result["native_kicad_erc"]["approved"])
        self.assertTrue(result["ai_schematic_quorum"]["quorum_met"])
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        self.assertEqual(
            list(
                Draft202012Validator(
                    circuit_handoff_bundle_catalog_provenance_replay_result_json_schema()
                ).iter_errors(result)
            ),
            [],
        )

    def test_injected_and_file_snapshot_sources_keep_only_the_basename(self) -> None:
        for source_kind in ("injected", "file"):
            with self.subTest(source_kind=source_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                artifacts = _catalog_artifacts(root / source_kind, source_kind=source_kind)
                entries = _archive_entries(artifacts["archive_raw"])
                generation = json.loads(
                    entries[handoff_module.GENERATION_BUNDLE_NAME]
                )
                source = generation["catalog_receipt"]["source"]
                self.assertEqual(source["kind"], source_kind)
                if source_kind == "injected":
                    self.assertIsNone(source["name"])
                else:
                    self.assertEqual(source["name"], artifacts["snapshot_path"].name)
                    # The replay caller may relocate/rename the source; the
                    # retained selection receipt binds only its private
                    # basename, which the verifier stages independently.
                    moved_snapshot = root / "different" / "renamed-caller.json"
                    moved_snapshot.parent.mkdir()
                    moved_snapshot.write_bytes(artifacts["snapshot_raw"])
                    replay_snapshot = moved_snapshot
                if source_kind == "injected":
                    replay_snapshot = artifacts["snapshot_path"]
                result = replay_circuit_handoff_bundle(
                    artifacts["archive"],
                    artifacts["command"],
                    **{
                        **_catalog_kwargs(artifacts),
                        "catalog_snapshot": replay_snapshot,
                    },
                )
                self.assertTrue(
                    result["validation"]["catalog_generation_provenance_replayed"]
                )
                self.assertNotIn(str(root), json.dumps(result))

    def test_catalog_inputs_are_all_or_none_and_archive_type_is_preflighted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            catalog = _catalog_artifacts(root / "catalog")
            non_catalog_root = root / "non-catalog"
            non_catalog_root.mkdir()
            non_catalog_raw, _manifest, non_catalog_command, _initial = (
                _valid_archive_with_command(non_catalog_root)
            )
            non_catalog_archive = non_catalog_root / "handoff.zip"
            non_catalog_archive.write_bytes(non_catalog_raw)
            sidecars = _catalog_kwargs(catalog)
            incomplete = [
                {"catalog_generation_provenance": sidecars["catalog_generation_provenance"]},
                {"catalog_fetch_receipt": sidecars["catalog_fetch_receipt"]},
                {"catalog_snapshot": sidecars["catalog_snapshot"]},
                {
                    "catalog_generation_provenance": sidecars[
                        "catalog_generation_provenance"
                    ],
                    "catalog_fetch_receipt": sidecars["catalog_fetch_receipt"],
                },
            ]
            for options in incomplete:
                with mock.patch.object(handoff_module, "_run_native") as run_native:
                    with self.subTest(options=options), self.assertRaisesRegex(
                        CircuitHandoffBundleError,
                        "catalog generation provenance replay inputs are incomplete",
                    ):
                        replay_circuit_handoff_bundle(
                            catalog["archive"],
                            catalog["command"],
                            **options,
                        )
                    run_native.assert_not_called()

            with mock.patch.object(handoff_module, "_run_native") as run_native:
                with self.assertRaisesRegex(
                    CircuitHandoffBundleError,
                    "requires a catalog-backed archive",
                ):
                    replay_circuit_handoff_bundle(
                        non_catalog_archive,
                        non_catalog_command,
                        **sidecars,
                    )
                run_native.assert_not_called()

    def test_tampered_empty_and_symlinked_catalog_sources_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            artifacts = _catalog_artifacts(root / "catalog")
            paths = {
                "provenance": artifacts["provenance"],
                "fetch": artifacts["fetch"],
                "snapshot": artifacts["snapshot_path"],
            }

            for label, path in paths.items():
                original = path.read_bytes()
                if label == "provenance":
                    value = json.loads(original)
                    value["catalog_sha256"] = "0" * 64
                    mutated = _render(value)
                elif label == "fetch":
                    value = json.loads(original)
                    value["catalog_sha256"] = "0" * 64
                    mutated = _render(value)
                else:
                    value = json.loads(original)
                    value["snapshot_id"] = "tampered-snapshot"
                    mutated = _render(value)
                path.write_bytes(mutated)
                try:
                    with self.subTest(kind="tampered", source=label), self.assertRaises(
                        CircuitHandoffBundleError
                    ):
                        replay_circuit_handoff_bundle(
                            artifacts["archive"],
                            artifacts["command"],
                            **_catalog_kwargs(artifacts),
                        )
                finally:
                    path.write_bytes(original)

                path.write_bytes(b"")
                try:
                    with mock.patch.object(handoff_module, "_run_native") as run_native:
                        with self.subTest(kind="empty", source=label), self.assertRaises(
                            CircuitHandoffBundleError
                        ):
                            replay_circuit_handoff_bundle(
                                artifacts["archive"],
                                artifacts["command"],
                                **_catalog_kwargs(artifacts),
                            )
                        run_native.assert_not_called()
                finally:
                    path.write_bytes(original)

                if os.name != "nt":
                    target = path.with_name(path.name + ".symlink-target")
                    target.write_bytes(original)
                    path.unlink()
                    try:
                        path.symlink_to(target)
                        with mock.patch.object(
                            handoff_module, "_run_native"
                        ) as run_native:
                            with self.subTest(kind="symlink", source=label), self.assertRaises(
                                CircuitHandoffBundleError
                            ):
                                replay_circuit_handoff_bundle(
                                    artifacts["archive"],
                                    artifacts["command"],
                                    **_catalog_kwargs(artifacts),
                                )
                            run_native.assert_not_called()
                    finally:
                        path.unlink(missing_ok=True)
                        path.write_bytes(original)
                        target.unlink(missing_ok=True)

    def test_catalog_sidecar_mutation_after_ai_child_is_rejected(self) -> None:
        for label in ("provenance", "fetch", "snapshot"):
            with self.subTest(source=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                artifacts = _catalog_artifacts(root / "catalog")
                schematic_raw = _archive_entries(artifacts["archive_raw"])[
                    handoff_module.SCHEMATIC_NAME
                ]
                ai_options, report_raw, _source_raws = _write_ai_inputs(
                    root,
                    schematic_raw,
                )
                mutate_path = {
                    "provenance": artifacts["provenance"],
                    "fetch": artifacts["fetch"],
                    "snapshot": artifacts["snapshot_path"],
                }[label]
                command = _write_ai_wrapper(
                    root,
                    artifacts["command"],
                    report_raw,
                    mutate_caller=str(mutate_path),
                )
                with self.assertRaisesRegex(
                    CircuitHandoffBundleError,
                    "changed during replay",
                ):
                    replay_circuit_handoff_bundle(
                        artifacts["archive"],
                        command,
                        require_ai_quorum=True,
                        **_catalog_kwargs(artifacts),
                        **ai_options,
                    )

    def test_catalog_replay_is_offline_and_deadline_expires_before_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            artifacts = _catalog_artifacts(root / "catalog")
            with mock.patch.object(
                supplier_inventory,
                "_http_get",
                side_effect=AssertionError("network access is forbidden during replay"),
            ):
                replay_circuit_handoff_bundle(
                    artifacts["archive"],
                    artifacts["command"],
                    **_catalog_kwargs(artifacts),
                )

            ticks = iter((0.0, 2.0))
            with mock.patch.object(handoff_module, "_run_native") as run_native:
                with self.assertRaisesRegex(
                    CircuitHandoffBundleError,
                    "aggregate deadline",
                ):
                    replay_circuit_handoff_bundle(
                        artifacts["archive"],
                        artifacts["command"],
                        timeout_seconds=1.0,
                        _clock=lambda: next(ticks),
                        **_catalog_kwargs(artifacts),
                    )
                run_native.assert_not_called()

    def test_catalog_sidecar_per_file_and_aggregate_caps_fail_path_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            artifacts = _catalog_artifacts(root / "catalog")
            with mock.patch.object(
                handoff_module,
                "MAX_PROVENANCE_BYTES",
                1,
            ), mock.patch.object(
                handoff_module,
                "_run_native",
            ) as run_native:
                with self.assertRaises(CircuitHandoffBundleError) as raised:
                    replay_circuit_handoff_bundle(
                        artifacts["archive"],
                        artifacts["command"],
                        **_catalog_kwargs(artifacts),
                    )
                run_native.assert_not_called()
                self.assertNotIn(str(root), str(raised.exception))

            # Keep every individual source below its patched per-file limit,
            # then force the aggregate cap without allocating oversized data.
            with mock.patch.object(
                handoff_module,
                "MAX_PROVENANCE_BYTES",
                1024,
            ), mock.patch.object(
                handoff_module,
                "MAXIMUM_RECEIPT_BYTES",
                1024,
            ), mock.patch.object(
                handoff_module,
                "MAX_CATALOG_RAW_BYTES",
                1024,
            ), mock.patch.object(
                handoff_module,
                "MAX_CATALOG_PROVENANCE_TOTAL_INPUT_BYTES",
                1000,
            ), mock.patch.object(
                handoff_module,
                "_run_native",
            ) as run_native:
                with self.assertRaisesRegex(
                    CircuitHandoffBundleError,
                    "aggregate bound",
                ) as raised:
                    replay_circuit_handoff_bundle(
                        artifacts["archive"],
                        artifacts["command"],
                        **_catalog_kwargs(artifacts),
                    )
                run_native.assert_not_called()
                self.assertNotIn(str(root), str(raised.exception))

    def test_catalog_snapshot_workspace_cleanup_failure_is_typed_and_path_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            artifacts = _catalog_artifacts(root / "catalog", source_kind="file")
            real_temporary_directory = handoff_module.tempfile.TemporaryDirectory

            class CleanupFailure:
                def __init__(self, *args, **kwargs):
                    self._inner = real_temporary_directory(*args, **kwargs)
                    self.name = self._inner.name

                def __enter__(self):
                    return self._inner.__enter__()

                def __exit__(self, *args):
                    return self._inner.__exit__(*args)

                def cleanup(self) -> None:
                    self._inner.cleanup()
                    raise OSError(str(root))

            with mock.patch.object(
                handoff_module.tempfile,
                "TemporaryDirectory",
                CleanupFailure,
            ):
                with self.assertRaises(CircuitHandoffBundleError) as raised:
                    replay_circuit_handoff_bundle(
                        artifacts["archive"],
                        artifacts["command"],
                        **_catalog_kwargs(artifacts),
                    )
            self.assertNotIn(str(root), str(raised.exception))

    def test_omitted_catalog_inputs_keep_exact_v1_v2_v3_serialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive_raw, manifest, base, _initial = _valid_archive_with_command(root)
            archive = root / "handoff.zip"
            archive.write_bytes(archive_raw)
            manifest_raw = _archive_entries(archive_raw)[handoff_module.MANIFEST_NAME]
            expected_v1 = {
                "schema_version": 1,
                "operation": "replay",
                "verified": True,
                "verification_scope": handoff_module.CIRCUIT_HANDOFF_BUNDLE_REPLAY_SCOPE,
                "archive": {"bytes": len(archive_raw), "sha256": _sha(archive_raw)},
                "manifest": {
                    "name": handoff_module.MANIFEST_NAME,
                    "bytes": len(manifest_raw),
                    "sha256": _sha(manifest_raw),
                },
                "expected": {
                    "archive_sha256": None,
                    "bundle_sha256": None,
                },
                "validation": {
                    "internal_consistency": True,
                    "expected_identity_matched": False,
                    "archive_reproduced": True,
                    "native_handoff_replayed": True,
                    "catalog_input_erc_required": False,
                    "catalog_input_erc_replayed": False,
                    "native_kicad_erc_replayed": False,
                },
                "adapter": manifest["adapter"],
                "engine_version": manifest["engine_version"],
                "bundle_sha256": manifest["bundle_sha256"],
                "artifacts": manifest["artifacts"],
                "replayed": True,
            }
            v1 = replay_circuit_handoff_bundle(archive, base)
            self.assertEqual(v1, expected_v1)

            schematic_raw = _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            native_report = root / "native-erc.json"
            native_report.write_bytes(_retained_report(schematic_raw))
            native_command = _write_native_wrapper(root, base, schema_version=1)
            v2 = replay_circuit_handoff_bundle(
                archive,
                native_command,
                retained_native_kicad_erc_report=native_report,
            )
            expected_v2 = copy.deepcopy(expected_v1)
            expected_v2["schema_version"] = 2
            expected_v2["verification_scope"] = (
                handoff_module.CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_SCOPE
            )
            expected_v2["validation"]["native_kicad_erc_replayed"] = True
            expected_v2["native_kicad_erc"] = {
                "schema_version": 1,
                "approved": True,
                "approval_required": False,
                "error_count": 0,
                "warning_count": None,
                "policy_failure_count": None,
                "run_sha256": "c" * 64,
                "report": {
                    "bytes": len(native_report.read_bytes()),
                    "sha256": _sha(native_report.read_bytes()),
                },
                "warning_policy": None,
            }
            self.assertEqual(v2, expected_v2)

            ai_options, report_raw, source_raws = _write_ai_inputs(
                root,
                schematic_raw,
            )
            ai_command = _write_ai_wrapper(root, base, report_raw)
            v3 = replay_circuit_handoff_bundle(
                archive,
                ai_command,
                require_ai_quorum=True,
                **ai_options,
            )
            expected_v3 = copy.deepcopy(expected_v1)
            expected_v3["schema_version"] = 3
            expected_v3["verification_scope"] = (
                handoff_module.CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_SCOPE
            )
            expected_v3["validation"]["ai_schematic_quorum_replayed"] = True
            expected_v3["ai_schematic_quorum"] = _expected_ai_evidence(
                report_raw,
                source_raws,
            )

        for result, version in ((v1, 1), (v2, 2), (v3, 3)):
            self.assertEqual(result["schema_version"], version)
            self.assertNotIn("catalog_generation_provenance", result)
            self.assertNotIn(
                "catalog_generation_provenance_replayed",
                result["validation"],
            )
            self.assertNotIn("catalog_generation_provenance", json.dumps(result))
        self.assertEqual(
            set(v3),
            set(expected_v1) | {"ai_schematic_quorum"},
        )
        self.assertEqual(
            set(v3["validation"]),
            set(expected_v1["validation"]) | {"ai_schematic_quorum_replayed"},
        )
        self.assertEqual(_compact_result(v1), _compact_result(expected_v1))
        self.assertEqual(_compact_result(v2), _compact_result(expected_v2))
        self.assertEqual(_compact_result(v3), _compact_result(expected_v3))
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        self.assertEqual(
            list(
                Draft202012Validator(
                    circuit_handoff_bundle_ai_quorum_replay_result_json_schema()
                ).iter_errors(v3)
            ),
            [],
        )

    def test_real_rust_catalog_provenance_handoff_replay_when_binary_is_supplied(
        self,
    ) -> None:
        binary = os.environ.get("PCBEX_TEST_BINARY")
        if not binary:
            self.skipTest("PCBEX_TEST_BINARY is not set")
        binary_path = Path(binary).resolve()
        if not binary_path.is_file():
            self.fail("PCBEX_TEST_BINARY does not name a regular file")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            source_model = _catalog_snapshot()
            snapshot_raw = _pretty_json_bytes(source_model.to_mapping())
            snapshot = load_catalog_snapshot(
                snapshot_raw.decode("utf-8"),
                evaluated_at_unix=150,
            )
            provider_source = json.dumps(
                _spec(),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            generation = generate_circuit_with_command(
                "two 1k resistors",
                str(binary_path),
                [
                    sys.executable,
                    "-c",
                    "import sys;sys.stdout.write(sys.argv[1])",
                    provider_source,
                ],
                catalog_snapshot=snapshot_raw.decode("utf-8"),
                evaluated_at_unix=150,
                timeout_seconds=60,
            )
            self.assertEqual(
                generation["catalog_receipt"]["source"],
                {
                    "kind": "injected",
                    "name": None,
                    "bytes": len(snapshot_raw),
                    "sha256": _sha(snapshot_raw),
                },
            )
            generation_path = root / "catalog-generation.json"
            generation_raw = _render(generation)
            generation_path.write_bytes(generation_raw)
            archive = root / "catalog-handoff.zip"
            manifest = handoff_circuit_generation(
                generation_path,
                archive,
                str(binary_path),
                timeout_seconds=90,
            )
            archive_raw = archive.read_bytes()

            endpoint = "https://supplier.example/catalog"
            response_raw = b"offline supplier response"
            fetch = {
                "schema_version": 1,
                "adapter": CATALOG_FETCH_ADAPTER,
                "provider": snapshot.supplier,
                "endpoint_id": endpoint,
                "request_sha256": _request_sha256(snapshot.supplier, endpoint),
                "response_sha256": _sha(response_raw),
                "response_bytes": len(response_raw),
                "status": 200,
                "fetched_at_unix": 150,
                "expires_at_unix": snapshot.expires_at_unix,
                "snapshot_bytes": len(snapshot_raw),
                "snapshot_sha256": _sha(snapshot_raw),
                "catalog_sha256": snapshot.catalog_sha256,
            }
            fetch_raw = _pretty_json_bytes(fetch)
            provenance = build_catalog_generation_provenance(
                fetch_raw,
                snapshot_raw,
                generation_raw,
                generation["skidl"],
                evaluated_at_unix=150,
            )
            provenance_path = root / "catalog-provenance.json"
            fetch_path = root / "catalog-fetch.json"
            snapshot_path = root / "catalog-input.json"
            provenance_path.write_bytes(_render(provenance))
            fetch_path.write_bytes(fetch_raw)
            snapshot_path.write_bytes(snapshot_raw)

            result = replay_circuit_handoff_bundle(
                archive,
                str(binary_path),
                catalog_generation_provenance=provenance_path,
                catalog_fetch_receipt=fetch_path,
                catalog_snapshot=snapshot_path,
                timeout_seconds=120,
                expected_archive_sha256=_sha(archive_raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )

        self.assertEqual(result["schema_version"], 4)
        self.assertTrue(result["validation"]["catalog_input_erc_replayed"])
        self.assertTrue(result["validation"]["catalog_generation_provenance_replayed"])
        self.assertFalse(result["validation"]["native_kicad_erc_replayed"])
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        schema = circuit_handoff_bundle_catalog_provenance_replay_result_json_schema()
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(result)), [])

    def test_cli_routes_catalog_inputs_and_schema_no_clobber(self) -> None:
        result = {"schema_version": 4, "operation": "replay", "replayed": True}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / "handoff.zip"
            provenance = root / "provenance.json"
            fetch = root / "fetch.json"
            snapshot = root / "snapshot.json"
            schema_path = root / "catalog-replay-schema.json"
            argv = [
                "pcbex-agent",
                "replay-circuit-handoff-bundle",
                str(archive),
                "--pcbex",
                "native-pcbex",
                "--catalog-generation-provenance",
                str(provenance),
                "--catalog-fetch-receipt",
                str(fetch),
                "--catalog-snapshot",
                str(snapshot),
                "--timeout-seconds",
                "42",
                "--expected-archive-sha256",
                "a" * 64,
                "--expected-bundle-sha256",
                "b" * 64,
            ]
            with (
                mock.patch.object(
                    cli,
                    "replay_circuit_handoff_bundle",
                    return_value=result,
                ) as replay,
                mock.patch.object(sys, "argv", argv),
            ):
                cli.main()
            replay.assert_called_once_with(
                Path(archive),
                "native-pcbex",
                catalog_generation_provenance=Path(provenance),
                catalog_fetch_receipt=Path(fetch),
                catalog_snapshot=Path(snapshot),
                timeout_seconds=42.0,
                expected_archive_sha256="a" * 64,
                expected_bundle_sha256="b" * 64,
            )

            schema_argv = [
                "pcbex-agent",
                "circuit-handoff-bundle-catalog-provenance-replay-result-schema",
                "--output",
                str(schema_path),
            ]
            with mock.patch.object(sys, "argv", schema_argv):
                cli.main()
            original = schema_path.read_bytes()
            self.assertEqual(
                json.loads(original),
                circuit_handoff_bundle_catalog_provenance_replay_result_json_schema(),
            )
            with mock.patch.object(sys, "argv", schema_argv), self.assertRaises(
                SystemExit
            ):
                cli.main()
            self.assertEqual(schema_path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()

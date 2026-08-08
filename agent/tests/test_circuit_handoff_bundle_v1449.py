from __future__ import annotations

import copy
from contextlib import redirect_stdout
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from agent.tests.test_circuit_handoff_bundle_v1448 import (
    _bundle,
    _render,
    _replace_native_check,
    _spec,
    _write_fake_pcbex,
)
from pcbex_agent import bounded_io, cli
from pcbex_agent import circuit_handoff_bundle as handoff_module
from pcbex_agent.circuit_generation import _compact_json
from pcbex_agent.circuit_handoff_bundle import (
    CIRCUIT_HANDOFF_BUNDLE_VERIFICATION_SCOPE,
    CircuitHandoffBundleError,
    build_circuit_handoff_archive,
    circuit_handoff_bundle_result_json_schema,
    extract_circuit_handoff_bundle,
    handoff_circuit_generation,
    validate_circuit_handoff_archive,
    verify_circuit_handoff_bundle,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _valid_archive(root: Path) -> tuple[bytes, dict[str, object]]:
    bundle = _bundle()
    command = _write_fake_pcbex(root, bundle["check"])
    return build_circuit_handoff_archive(_render(bundle), command)


def _archive_entries(raw: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return {info.filename: archive.read(info) for info in archive.infolist()}


def _canonical(entries: dict[str, bytes], names: list[str] | None = None) -> bytes:
    order = list(handoff_module._ARCHIVE_ENTRY_NAMES) if names is None else names
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        return handoff_module._archive([(name, entries[name]) for name in order])


def _metadata_archive(
    entries: dict[str, bytes],
    mutate,
    *,
    archive_comment: bytes = b"",
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
        archive.comment = archive_comment
        for name in handoff_module._ARCHIVE_ENTRY_NAMES:
            info, contents = handoff_module._zip_entry(name, entries[name])
            mutate(info, name)
            archive.writestr(info, contents)
    return output.getvalue()


def _rebind_manifest(entries: dict[str, bytes]) -> None:
    manifest = json.loads(entries[handoff_module.MANIFEST_NAME])
    for role, name in handoff_module._ARTIFACT_NAMES.items():
        raw = entries[name]
        manifest["artifacts"][role] = {
            "name": name,
            "bytes": len(raw),
            "sha256": _sha(raw),
        }
    identity = {
        "schema_version": manifest["schema_version"],
        "adapter": manifest["adapter"],
        "engine_version": manifest["engine_version"],
        "artifacts": manifest["artifacts"],
        "circuit_spec_sha256": manifest["circuit_spec_sha256"],
        "electrical_review_sha256": manifest["electrical_review_sha256"],
        "policy_sha256": manifest["policy_sha256"],
        "approved": manifest["approved"],
    }
    manifest["bundle_sha256"] = _sha(
        handoff_module._BUNDLE_IDENTITY_DOMAIN + _compact_json(identity)
    )
    entries[handoff_module.MANIFEST_NAME] = _render(manifest)


class CircuitHandoffBundleV1449Tests(unittest.TestCase):
    def test_validates_without_native_execution_and_binds_expected_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw, manifest = _valid_archive(Path(directory))
        with mock.patch.object(handoff_module, "run_bounded") as native:
            result, entries = validate_circuit_handoff_archive(
                raw,
                expected_archive_sha256=_sha(raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )
        native.assert_not_called()
        self.assertEqual(result["operation"], "verify")
        self.assertTrue(result["verified"])
        self.assertFalse(result["extracted"])
        self.assertEqual(
            result["verification_scope"],
            CIRCUIT_HANDOFF_BUNDLE_VERIFICATION_SCOPE,
        )
        self.assertEqual(result["archive"], {"bytes": len(raw), "sha256": _sha(raw)})
        self.assertEqual(result["bundle_sha256"], manifest["bundle_sha256"])
        self.assertEqual(
            result["validation"],
            {
                "internal_consistency": True,
                "expected_identity_matched": True,
                "native_handoff_replayed": False,
                "catalog_input_erc_replayed": False,
            },
        )
        self.assertEqual(list(entries), list(handoff_module._ARCHIVE_ENTRY_NAMES))

        for key in ("expected_archive_sha256", "expected_bundle_sha256"):
            arguments = {
                "expected_archive_sha256": _sha(raw),
                "expected_bundle_sha256": manifest["bundle_sha256"],
            }
            arguments[key] = "f" * 64
            with self.subTest(mismatch=key), self.assertRaises(
                CircuitHandoffBundleError
            ):
                validate_circuit_handoff_archive(raw, **arguments)

        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        validator = Draft202012Validator(circuit_handoff_bundle_result_json_schema())
        self.assertEqual(list(validator.iter_errors(result)), [])

    def test_verify_path_and_transactional_exact_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, manifest = _valid_archive(root)
            archive_path = root / "handoff.zip"
            archive_path.write_bytes(raw)
            verified = verify_circuit_handoff_bundle(str(archive_path))
            self.assertEqual(verified["bundle_sha256"], manifest["bundle_sha256"])
            self.assertFalse(verified["validation"]["expected_identity_matched"])

            output = root / "extracted"
            writes: list[str] = []
            real_write = handoff_module.atomic_write_no_clobber

            def record_write(path, contents, *, max_bytes):
                writes.append(Path(path).name)
                return real_write(path, contents, max_bytes=max_bytes)

            with mock.patch.object(
                handoff_module,
                "atomic_write_no_clobber",
                side_effect=record_write,
            ):
                extracted = extract_circuit_handoff_bundle(
                    str(archive_path),
                    str(output),
                    expected_archive_sha256=_sha(raw),
                    expected_bundle_sha256=manifest["bundle_sha256"],
                )
            self.assertEqual(extracted["operation"], "extract")
            self.assertTrue(extracted["extracted"])
            self.assertEqual(writes, list(handoff_module._ARCHIVE_ENTRY_NAMES))
            self.assertEqual(writes[-1], handoff_module.MANIFEST_NAME)
            expected = _archive_entries(raw)
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                sorted(expected),
            )
            for name, contents in expected.items():
                self.assertEqual((output / name).read_bytes(), contents)

    def test_rejects_nonexact_and_unsafe_entry_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw, _manifest = _valid_archive(Path(directory))
        entries = _archive_entries(raw)
        names = list(handoff_module._ARCHIVE_ENTRY_NAMES)
        cases: dict[str, list[str]] = {
            "missing": names[:-1],
            "reordered": [names[1], names[0], *names[2:]],
            "duplicate": [names[0], names[0], *names[2:]],
            "extra": [*names, names[0]],
            "traversal": ["../generation-bundle.json", *names[1:]],
            "nested": ["nested/generation-bundle.json", *names[1:]],
            "absolute": ["/generation-bundle.json", *names[1:]],
            "backslash": ["..\\generation-bundle.json", *names[1:]],
            "case": ["Generation-bundle.json", *names[1:]],
        }
        for label, altered in cases.items():
            available = dict(entries)
            if altered[0] not in available:
                available[altered[0]] = entries[names[0]]
            with self.subTest(case=label), self.assertRaises(
                CircuitHandoffBundleError
            ):
                validate_circuit_handoff_archive(_canonical(available, altered))

    def test_rejects_noncanonical_metadata_and_container_framing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw, _manifest = _valid_archive(Path(directory))
        entries = _archive_entries(raw)

        def timestamp(info, name):
            if name == handoff_module.SCHEMATIC_NAME:
                info.date_time = (1981, 1, 1, 0, 0, 0)

        def compressed(info, name):
            if name == handoff_module.SCHEMATIC_NAME:
                info.compress_type = zipfile.ZIP_DEFLATED

        def symlink(info, name):
            if name == handoff_module.SCHEMATIC_NAME:
                info.external_attr = 0o120777 << 16

        def fifo(info, name):
            if name == handoff_module.SCHEMATIC_NAME:
                info.external_attr = 0o010644 << 16

        def extra(info, name):
            if name == handoff_module.SCHEMATIC_NAME:
                info.extra = b"\xfe\xca\x00\x00"

        for label, mutate in {
            "timestamp": timestamp,
            "compression": compressed,
            "symlink": symlink,
            "fifo": fifo,
            "extra": extra,
        }.items():
            with self.subTest(metadata=label), self.assertRaises(
                CircuitHandoffBundleError
            ):
                validate_circuit_handoff_archive(_metadata_archive(entries, mutate))

        with self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_handoff_archive(
                _metadata_archive(entries, lambda _info, _name: None, archive_comment=b"x")
            )
        for altered in (b"prefix" + raw, raw + b"trailing", raw[:-1], raw[:20]):
            with self.subTest(framing=len(altered)), self.assertRaises(
                CircuitHandoffBundleError
            ):
                validate_circuit_handoff_archive(altered)

    def test_rejects_crc_corruption_and_declared_or_actual_size_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw, _manifest = _valid_archive(Path(directory))
        entries = _archive_entries(raw)
        marker = entries[handoff_module.SCHEMATIC_NAME][:32]
        offset = raw.find(marker)
        self.assertGreaterEqual(offset, 0)
        corrupted = bytearray(raw)
        corrupted[offset] ^= 1
        with self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_handoff_archive(bytes(corrupted))

        with mock.patch.dict(
            handoff_module._ARCHIVE_ENTRY_LIMITS,
            {
                handoff_module.SCHEMATIC_NAME: len(
                    entries[handoff_module.SCHEMATIC_NAME]
                )
                - 1
            },
        ), self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_handoff_archive(raw)
        with mock.patch.object(
            handoff_module,
            "MAX_HANDOFF_ARCHIVE_BYTES",
            len(raw) - 1,
        ), self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_handoff_archive(raw)

    def test_rejects_strict_manifest_and_aggregate_identity_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw, _manifest = _valid_archive(Path(directory))
        base = _archive_entries(raw)

        malformed: list[bytes] = []
        manifest_raw = base[handoff_module.MANIFEST_NAME]
        malformed.append(
            manifest_raw.replace(
                b'{\n  "schema_version": 1,',
                b'{\n  "schema_version": 1,\n  "schema_version": 1,',
                1,
            )
        )
        malformed.append(manifest_raw.replace(b'"approved": true', b'"approved": NaN'))
        malformed.append(b"\xef\xbb\xbf" + manifest_raw)
        malformed.append(manifest_raw.replace(b'"adapter":', b'"extra": true,\n  "adapter":'))
        for index, value in enumerate(malformed):
            entries = dict(base)
            entries[handoff_module.MANIFEST_NAME] = value
            with self.subTest(malformed=index), self.assertRaises(
                CircuitHandoffBundleError
            ):
                validate_circuit_handoff_archive(_canonical(entries))

        manifest = json.loads(manifest_raw)
        for mutation in ("descriptor", "bundle", "approved", "order"):
            forged = copy.deepcopy(manifest)
            if mutation == "descriptor":
                forged["artifacts"]["schematic"]["sha256"] = "f" * 64
            elif mutation == "bundle":
                forged["bundle_sha256"] = "f" * 64
            elif mutation == "approved":
                forged["approved"] = False
            else:
                forged = {"adapter": forged.pop("adapter"), **forged}
            entries = dict(base)
            entries[handoff_module.MANIFEST_NAME] = _render(forged)
            with self.subTest(forgery=mutation), self.assertRaises(
                CircuitHandoffBundleError
            ):
                validate_circuit_handoff_archive(_canonical(entries))

        compact = dict(base)
        compact[handoff_module.MANIFEST_NAME] = json.dumps(
            manifest, separators=(",", ":")
        ).encode()
        with self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_handoff_archive(_canonical(compact))

    def test_rejects_rehashed_but_semantically_inconsistent_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw, _manifest = _valid_archive(Path(directory))
        base = _archive_entries(raw)
        for artifact in (
            handoff_module.GENERATION_BUNDLE_NAME,
            handoff_module.CIRCUIT_SPEC_NAME,
            handoff_module.CIRCUIT_CHECK_NAME,
            handoff_module.SCHEMATIC_NAME,
            handoff_module.HANDOFF_REPORT_NAME,
        ):
            entries = dict(base)
            if artifact == handoff_module.SCHEMATIC_NAME:
                entries[artifact] += b"\n"
            else:
                value = json.loads(entries[artifact])
                if artifact == handoff_module.GENERATION_BUNDLE_NAME:
                    value["spec"]["parts"][0]["value"] = "2k"
                elif artifact == handoff_module.CIRCUIT_SPEC_NAME:
                    value["parts"][0]["value"] = "2k"
                elif artifact == handoff_module.CIRCUIT_CHECK_NAME:
                    value["normalized_spec"]["parts"][0]["value"] = "2k"
                else:
                    value["engine_version"] = "forged-engine"
                entries[artifact] = _render(value)
            _rebind_manifest(entries)
            with self.subTest(artifact=artifact), self.assertRaises(
                CircuitHandoffBundleError
            ):
                validate_circuit_handoff_archive(_canonical(entries))

    def test_invalid_native_fields_stay_inside_the_typed_error_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw, _manifest = _valid_archive(Path(directory))
        base = _archive_entries(raw)

        oversized = dict(base)
        report = json.loads(oversized[handoff_module.HANDOFF_REPORT_NAME])
        report["engine_version"] = "\U0001f680" * 256
        oversized[handoff_module.HANDOFF_REPORT_NAME] = _render(report)
        manifest = json.loads(oversized[handoff_module.MANIFEST_NAME])
        manifest["engine_version"] = report["engine_version"]
        oversized[handoff_module.MANIFEST_NAME] = _render(manifest)
        _rebind_manifest(oversized)
        with self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_handoff_archive(_canonical(oversized))

        malformed = dict(base)
        report = json.loads(malformed[handoff_module.HANDOFF_REPORT_NAME])
        report["schematic_review"]["findings"] = [
            {
                "id": "pcbex-er-0000000000000000",
                "rule": "unconnected_pin",
                "severity": [],
                "message": "malformed",
                "net_id": None,
                "symbols": [],
                "pins": [],
            }
        ]
        malformed[handoff_module.HANDOFF_REPORT_NAME] = _render(report)
        _rebind_manifest(malformed)
        with self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_handoff_archive(_canonical(malformed))

    def test_offline_scope_needs_an_external_root_for_producer_authenticity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw, original_manifest = _valid_archive(Path(directory))
        entries = _archive_entries(raw)
        schematic = b"not a KiCad schematic\n"
        entries[handoff_module.SCHEMATIC_NAME] = schematic
        report = json.loads(entries[handoff_module.HANDOFF_REPORT_NAME])
        report["schematic_source_bytes"] = len(schematic)
        report["schematic_source_sha256"] = _sha(schematic)
        report["schematic_sha256"] = _sha(schematic)
        report["schematic_review"]["schematic_sha256"] = _sha(schematic)
        entries[handoff_module.HANDOFF_REPORT_NAME] = _render(report)
        _rebind_manifest(entries)
        internally_consistent = _canonical(entries)

        result, _verified_entries = validate_circuit_handoff_archive(
            internally_consistent
        )
        self.assertTrue(result["validation"]["internal_consistency"])
        self.assertFalse(result["validation"]["expected_identity_matched"])
        self.assertFalse(result["validation"]["native_handoff_replayed"])
        with self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_handoff_archive(
                internally_consistent,
                expected_archive_sha256=_sha(raw),
            )
        with self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_handoff_archive(
                internally_consistent,
                expected_bundle_sha256=original_manifest["bundle_sha256"],
            )

    def test_paths_collisions_and_failures_never_clobber_owned_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, _manifest = _valid_archive(root)
            archive_path = root / "handoff.zip"
            archive_path.write_bytes(raw)

            existing = root / "existing"
            existing.mkdir()
            sentinel = existing / "sentinel"
            sentinel.write_bytes(b"keep")
            with self.assertRaises(CircuitHandoffBundleError):
                extract_circuit_handoff_bundle(archive_path, existing)
            self.assertEqual(sentinel.read_bytes(), b"keep")

            source_link = root / "source-link.zip"
            output_link = root / "output-link"
            target = root / "target"
            target.mkdir()
            try:
                source_link.symlink_to(archive_path)
                output_link.symlink_to(target, target_is_directory=True)
            except (NotImplementedError, OSError):
                pass
            else:
                with self.assertRaises(CircuitHandoffBundleError):
                    verify_circuit_handoff_bundle(source_link)
                with self.assertRaises(CircuitHandoffBundleError):
                    extract_circuit_handoff_bundle(archive_path, output_link)

            real_write = handoff_module.atomic_write_no_clobber
            calls = 0

            def fail_third(path, contents, *, max_bytes):
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise bounded_io.BoundedIOError(errno.EIO, "injected")
                return real_write(path, contents, max_bytes=max_bytes)

            failed_output = root / "write-failure"
            with mock.patch.object(
                handoff_module,
                "atomic_write_no_clobber",
                side_effect=fail_third,
            ), self.assertRaises(CircuitHandoffBundleError):
                extract_circuit_handoff_bundle(archive_path, failed_output)
            self.assertFalse(failed_output.exists())

    @unittest.skipIf(os.name == "nt", "Windows skips directory fsync")
    def test_final_parent_sync_failure_rolls_back_owned_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, _manifest = _valid_archive(root)
            archive_path = root / "handoff.zip"
            archive_path.write_bytes(raw)
            output = root / "extracted"
            real_sync = handoff_module._sync_directory
            calls = 0

            def fail_parent(path: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise CircuitHandoffBundleError("injected sync failure")
                real_sync(path)

            with mock.patch.object(
                handoff_module,
                "_sync_directory",
                side_effect=fail_parent,
            ), self.assertRaises(CircuitHandoffBundleError):
                extract_circuit_handoff_bundle(archive_path, output)
            self.assertEqual(calls, 2)
            self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "O_DIRECTORY"), "directory fsync is unavailable")
    def test_unsupported_directory_fsync_preserves_portable_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            handoff_module.os,
            "fsync",
            side_effect=OSError(errno.EINVAL, "unsupported"),
        ):
            handoff_module._sync_directory(Path(directory))

    def test_failed_reservation_inspection_never_deletes_unproven_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, _manifest = _valid_archive(root)
            archive_path = root / "handoff.zip"
            archive_path.write_bytes(raw)
            output = root / "reserved"
            with mock.patch.object(
                handoff_module,
                "_reserved_directory_identity",
                side_effect=OSError(errno.EIO, "injected"),
            ), self.assertRaises(CircuitHandoffBundleError):
                extract_circuit_handoff_bundle(archive_path, output)
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])

    def test_cli_verify_extract_and_result_schema_emit_closed_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, manifest = _valid_archive(root)
            archive_path = root / "handoff.zip"
            archive_path.write_bytes(raw)
            output = root / "extracted"

            stdout = io.StringIO()
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "verify-circuit-handoff-bundle",
                    str(archive_path),
                    "--expected-archive-sha256",
                    _sha(raw),
                    "--expected-bundle-sha256",
                    manifest["bundle_sha256"],
                ],
            ), redirect_stdout(stdout):
                cli.main()
            verified = json.loads(stdout.getvalue())
            self.assertTrue(verified["verified"])
            self.assertFalse(verified["extracted"])

            stdout = io.StringIO()
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "extract-circuit-handoff-bundle",
                    str(archive_path),
                    "--output-dir",
                    str(output),
                ],
            ), redirect_stdout(stdout):
                cli.main()
            extracted = json.loads(stdout.getvalue())
            self.assertTrue(extracted["extracted"])
            self.assertTrue((output / handoff_module.MANIFEST_NAME).is_file())

            stdout = io.StringIO()
            with mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", "circuit-handoff-bundle-result-schema"],
            ), redirect_stdout(stdout):
                cli.main()
            self.assertEqual(
                json.loads(stdout.getvalue()),
                circuit_handoff_bundle_result_json_schema(),
            )

    def test_real_rust_archive_is_verified_and_extracted_when_binary_is_supplied(
        self,
    ) -> None:
        binary = os.environ.get("PCBEX_TEST_BINARY")
        if not binary:
            self.skipTest("PCBEX_TEST_BINARY is not set")
        binary_path = Path(binary).resolve()
        if not binary_path.is_file():
            self.fail("PCBEX_TEST_BINARY does not name a regular file")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec_path = root / "spec.json"
            spec_path.write_bytes(_render(_spec()))
            native = subprocess.run(
                [str(binary_path), "check-circuit-spec", str(spec_path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            bundle = _replace_native_check(_bundle(), json.loads(native.stdout))
            source = root / "generation.json"
            source.write_bytes(_render(bundle))
            archive_path = root / "handoff.zip"
            manifest = handoff_circuit_generation(
                source,
                archive_path,
                str(binary_path),
                timeout_seconds=30,
            )
            archive_raw = archive_path.read_bytes()
            verified = verify_circuit_handoff_bundle(
                archive_path,
                expected_archive_sha256=_sha(archive_raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )
            output = root / "verified"
            extracted = extract_circuit_handoff_bundle(
                archive_path,
                output,
                expected_archive_sha256=verified["archive"]["sha256"],
                expected_bundle_sha256=verified["bundle_sha256"],
            )
            self.assertTrue(verified["verified"])
            self.assertTrue(extracted["extracted"])
            self.assertTrue(
                (output / handoff_module.SCHEMATIC_NAME)
                .read_bytes()
                .startswith(b"(kicad_sch\n")
            )
            self.assertEqual(
                json.loads((output / handoff_module.MANIFEST_NAME).read_bytes()),
                manifest,
            )


if __name__ == "__main__":
    unittest.main()

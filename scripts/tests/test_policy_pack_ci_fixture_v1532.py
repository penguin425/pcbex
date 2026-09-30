"""Focused v1.532 policy-pack fixture and native-mode helper tests."""

from __future__ import annotations

import copy
import hashlib
import json
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import deterministic_pipeline_ci as pipeline_fixture
import fabrication_authorization_action_ci as authorization_fixture


ROOT = SCRIPT_DIR.parent
POLICY = ROOT / "examples" / "acme-policy-pack.json"


class PolicyPackCiFixtureV1532Tests(unittest.TestCase):
    def test_rust_typed_policy_and_dfm_domain_digests(self) -> None:
        value = json.loads(POLICY.read_text(encoding="utf-8"))
        # Sorting the input models a parser receiving arbitrary JSON key order.
        value = json.loads(json.dumps(value, sort_keys=True))
        typed = pipeline_fixture._rust_typed_policy_pack(value)
        canonical = json.dumps(typed, ensure_ascii=True, separators=(",", ":")).encode()
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            "d0b35fcd99d8a8a13dd076a27976d53c9ef8ead2483f51208b4310b3d8c0b5da",
        )
        profile = typed["dfm_profile"]
        profile_bytes = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertEqual(
            hashlib.sha256(b"pcbex-dfm-profile-v1\0" + profile_bytes).hexdigest(),
            "7568aff407118ceb2eba906c479dcc9a524c8ed91eb8530928b98319b56e8c5c",
        )

    def test_typed_material_order_defaults_unicode_and_empty_omission(self) -> None:
        value = json.loads(POLICY.read_text(encoding="utf-8"))
        value["description"] = "製造ポリシー"
        value["trusted_human_escalation_keys"] = []
        value["factory_receipt_attestation_policy"] = None
        value["fabrication_authorization_policy"] = {
            "trusted_keys": [{"public_key": "a" * 64, "signer_id": "test-ci"}],
            "maximum_validity_seconds": 3600,
            "minimum_approvals": 1,
        }
        value["factory_adapter_response_authentication_policy"] = {
            "trusted_keys": [{"public_key": "b" * 64, "provider": "generic",
                              "factory_id": "factory", "key_id": "response"}],
            "maximum_validity_seconds": 300,
        }
        value["procurement_authorization_policy"] = {
            "trusted_keys": [{"public_key": "c" * 64, "signer_id": "buyer"}],
            "maximum_component_subtotal_micros": 100,
            "maximum_receipt_observation_age_seconds": 60,
            "maximum_validity_seconds": 3600,
            "currency": "USD",
            "minimum_approvals": 1,
        }
        value["dfm_profile"]["rules"].pop("maximum_via_aspect_ratio")
        value["dfm_profile"]["rules"].pop("minimum_drill_to_drill_nm")
        value["dfm_profile"]["rules"].pop("allow_via_in_pad")
        typed = pipeline_fixture._rust_typed_policy_pack(value)
        self.assertEqual(list(typed)[:6], [
            "schema_version", "id", "revision", "verified_on", "description", "dfm_profile"
        ])
        self.assertEqual(list(typed["electrical_policy"]["rules"]), sorted(typed["electrical_policy"]["rules"]))
        self.assertNotIn("trusted_human_escalation_keys", typed)
        self.assertNotIn("factory_receipt_attestation_policy", typed)
        self.assertEqual(list(typed["fabrication_authorization_policy"]), [
            "minimum_approvals", "maximum_validity_seconds", "trusted_keys"
        ])
        self.assertEqual(list(typed["fabrication_authorization_policy"]["trusted_keys"][0]), [
            "signer_id", "public_key"
        ])
        self.assertEqual(list(typed["factory_adapter_response_authentication_policy"]["trusted_keys"][0]), [
            "key_id", "factory_id", "provider", "public_key"
        ])
        self.assertEqual(list(typed["procurement_authorization_policy"]), [
            "minimum_approvals", "currency", "maximum_validity_seconds",
            "maximum_receipt_observation_age_seconds", "maximum_component_subtotal_micros",
            "trusted_keys",
        ])
        self.assertEqual(typed["dfm_profile"]["rules"]["maximum_via_aspect_ratio"], 10)
        self.assertEqual(typed["dfm_profile"]["rules"]["minimum_drill_to_drill_nm"], 0)
        self.assertTrue(typed["dfm_profile"]["rules"]["allow_via_in_pad"])
        self.assertEqual(typed["description"], "製造ポリシー")
        self.assertIn("製造ポリシー".encode(), json.dumps(typed, ensure_ascii=False).encode())

    def test_manufacturing_package_schema1_and_policy_bound_schema3(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board = root / "board.kicad_pcb"
            board.write_bytes(b"(kicad_pcb (version 20240108))\n")
            legacy = root / "legacy.zip"
            pipeline_fixture._write_manufacturing_package(legacy, board, engine_version="1.532.0")
            with zipfile.ZipFile(legacy) as archive:
                manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["schema_version"], 1)
            self.assertNotIn("dfm_profile", manifest)

            bound = root / "bound.zip"
            raw = POLICY.read_bytes()
            source = root / "original-policy-pack.json"
            source.write_bytes(raw)
            pipeline_fixture._write_manufacturing_package(
                bound, board, engine_version="1.532.0", policy_pack=source
            )
            with zipfile.ZipFile(bound) as archive:
                bound_manifest = json.loads(archive.read("manifest.json"))
            origin = bound_manifest["dfm_profile"]["origin"]
            self.assertEqual(bound_manifest["schema_version"], 3)
            self.assertEqual(origin["source"]["path"], source.name)
            self.assertEqual(origin["source"]["bytes"], len(raw))
            self.assertEqual(origin["source"]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(origin["canonical_sha256"], "d0b35fcd99d8a8a13dd076a27976d53c9ef8ead2483f51208b4310b3d8c0b5da")

    def test_native_helper_rejects_incompatible_flags_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            kwargs = dict(
                pcbex=root / "pcbex",
                fixture_dir=root / "missing-fixture",
                policy_template=POLICY,
                output_dir=output,
                board=None,
                timeout_seconds=1,
                executable_identity=None,
            )
            cases = [
                {"native_manufacturing": False, "kicad_cli": root / "kicad-cli", "kicad_project": None,
                 "manufacturing_package": None},
                {"native_manufacturing": True, "kicad_cli": None, "kicad_project": None,
                 "manufacturing_package": None},
                {"native_manufacturing": True, "kicad_cli": root / "kicad-cli", "kicad_project": None,
                 "manufacturing_package": root / "package.zip"},
            ]
            for case in cases:
                with self.subTest(case=case):
                    with self.assertRaises(authorization_fixture.FixtureError):
                        authorization_fixture._build_fixture(**kwargs, **case)
                    self.assertFalse(output.exists())

    def test_native_parser_captures_all_selections(self) -> None:
        args = authorization_fixture._parser().parse_args([
            "--pcbex", "/bin/true", "--fixture-dir", "fixtures",
            "--policy-template", str(POLICY), "--output-dir", "out",
            "--native-manufacturing", "--kicad-cli", "/usr/bin/kicad-cli",
            "--kicad-project", "project.kicad_pro",
        ])
        self.assertTrue(args.native_manufacturing)
        self.assertEqual(args.kicad_cli, "/usr/bin/kicad-cli")
        self.assertEqual(args.kicad_project, "project.kicad_pro")

    def test_native_main_freezes_relative_and_path_searched_kicad_before_child_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            tools = root / "tools"
            tools.mkdir()
            executable = tools / "kicad-cli"
            executable.write_bytes(b"fixture executable")
            for spelling in ("tools/kicad-cli", "kicad-cli"):
                with self.subTest(spelling=spelling), \
                    mock.patch("os.getcwd", return_value=str(root)), \
                    mock.patch.object(authorization_fixture.shutil, "which", return_value=str(executable)), \
                    mock.patch.object(pipeline_fixture, "_resolve_pcbex", return_value=(root / "pcbex", None)), \
                    mock.patch.object(authorization_fixture, "_build_fixture", return_value={"schema_version": 1}) as build, \
                    mock.patch.object(authorization_fixture.sys, "stdout", SimpleNamespace(buffer=io.BytesIO())):
                    code = authorization_fixture.main([
                        "--pcbex", "pcbex", "--fixture-dir", "fixture",
                        "--policy-template", str(POLICY), "--output-dir", "out",
                        "--native-manufacturing", "--kicad-cli", spelling,
                    ])
                    self.assertEqual(code, 0)
                    self.assertEqual(build.call_args.kwargs["kicad_cli"], executable)


if __name__ == "__main__":
    unittest.main()

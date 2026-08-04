import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class CatalogProvenanceCliV1421Tests(unittest.TestCase):
    def test_schema_command_is_closed_and_no_clobber(self):
        from pcbex_agent import cli

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "catalog-provenance.schema.json"
            argv = [
                "pcbex-agent",
                "catalog-generation-provenance-schema",
                "--output",
                str(output),
            ]
            with patch.object(sys, "argv", argv):
                cli.main()
            schema = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(schema["additionalProperties"])
            self.assertIn("generation_bundle_sha256", schema["properties"])
            original = output.read_bytes()
            with patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(output.read_bytes(), original)

    def test_generate_requires_the_complete_provenance_flag_group(self):
        from pcbex_agent import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            requirements.write_text("make a capacitor", encoding="utf-8")
            base = [
                "pcbex-agent",
                "generate-circuit",
                str(requirements),
                "--output",
                str(root / "bundle.json"),
                "--catalog-snapshot",
                str(root / "snapshot.json"),
            ]
            incomplete = (
                [*base, "--catalog-fetch-receipt", str(root / "fetch.json")],
                [
                    *base,
                    "--catalog-provenance-output",
                    str(root / "provenance.json"),
                ],
            )
            for argv in incomplete:
                with self.subTest(argv=argv[-2]):
                    with (
                        patch.object(
                            sys,
                            "argv",
                            [*argv, "--provider-command", "provider"],
                        ),
                        patch.object(cli, "generate_circuit_with_command") as generate,
                        self.assertRaises(SystemExit),
                    ):
                        cli.main()
                    generate.assert_not_called()

    def test_generate_prevalidates_and_binds_exact_published_bytes(self):
        from pcbex_agent import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            snapshot = root / "snapshot.json"
            fetch_receipt = root / "fetch.json"
            bundle_output = root / "bundle.json"
            skidl_output = root / "generated.py"
            provenance_output = root / "provenance.json"
            requirements.write_text("make a capacitor", encoding="utf-8")
            snapshot_raw = b"{}\n"
            fetch_raw = b'{"schema_version":1}\n'
            snapshot.write_bytes(snapshot_raw)
            fetch_receipt.write_bytes(fetch_raw)
            bundle = {"schema_version": 2, "skidl": "# generated\n"}
            provenance = {
                "schema_version": 1,
                "adapter": "catalog-generation-provenance-v1",
                "generation_bundle_sha256": "a" * 64,
            }
            sentinel_snapshot = SimpleNamespace(raw_bytes=snapshot_raw)
            argv = [
                "pcbex-agent",
                "generate-circuit",
                str(requirements),
                "--output",
                str(bundle_output),
                "--skidl-output",
                str(skidl_output),
                "--catalog-snapshot",
                str(snapshot),
                "--catalog-fetch-receipt",
                str(fetch_receipt),
                "--catalog-provenance-output",
                str(provenance_output),
                "--provider-command",
                "provider",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    cli,
                    "validate_catalog_fetch_receipt",
                    return_value={"fetched_at_unix": 123},
                ) as validate_fetch,
                patch.object(
                    cli,
                    "load_catalog_snapshot",
                    return_value=sentinel_snapshot,
                ) as load_snapshot,
                patch.object(
                    cli,
                    "generate_circuit_with_command",
                    return_value=bundle,
                ) as generate,
                patch.object(
                    cli,
                    "build_catalog_generation_provenance",
                    return_value=provenance,
                ) as build,
            ):
                cli.main()

            validate_fetch.assert_called_once_with(
                {"schema_version": 1},
                snapshot_raw,
            )
            load_snapshot.assert_called_once_with(
                snapshot,
                evaluated_at_unix=123,
            )
            self.assertIs(generate.call_args.kwargs["catalog_snapshot"], sentinel_snapshot)
            self.assertEqual(generate.call_args.kwargs["evaluated_at_unix"], 123)
            rendered_bundle = (
                json.dumps(bundle, indent=2, ensure_ascii=False) + "\n"
            ).encode("utf-8")
            self.assertEqual(
                build.call_args.args,
                (fetch_raw, snapshot, rendered_bundle, b"# generated\n"),
            )
            self.assertEqual(build.call_args.kwargs["evaluated_at_unix"], 123)
            self.assertEqual(bundle_output.read_bytes(), rendered_bundle)
            self.assertEqual(skidl_output.read_bytes(), b"# generated\n")
            self.assertEqual(
                json.loads(provenance_output.read_text(encoding="utf-8")),
                provenance,
            )

    def test_snapshot_change_fails_before_provider_or_publication(self):
        from pcbex_agent import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            snapshot = root / "snapshot.json"
            fetch_receipt = root / "fetch.json"
            output = root / "bundle.json"
            provenance_output = root / "provenance.json"
            requirements.write_text("make a capacitor", encoding="utf-8")
            snapshot.write_bytes(b"{}\n")
            fetch_receipt.write_text('{"schema_version":1}\n', encoding="utf-8")
            argv = [
                "pcbex-agent",
                "generate-circuit",
                str(requirements),
                "--output",
                str(output),
                "--catalog-snapshot",
                str(snapshot),
                "--catalog-fetch-receipt",
                str(fetch_receipt),
                "--catalog-provenance-output",
                str(provenance_output),
                "--provider-command",
                "provider",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    cli,
                    "validate_catalog_fetch_receipt",
                    return_value={"fetched_at_unix": 123},
                ),
                patch.object(
                    cli,
                    "load_catalog_snapshot",
                    return_value=SimpleNamespace(raw_bytes=b'{"changed":true}\n'),
                ),
                patch.object(cli, "generate_circuit_with_command") as generate,
                patch.object(cli, "build_catalog_generation_provenance") as build,
                self.assertRaises(SystemExit),
            ):
                cli.main()
            generate.assert_not_called()
            build.assert_not_called()
            self.assertFalse(output.exists())
            self.assertFalse(provenance_output.exists())

    def test_duplicate_fetch_receipt_fails_before_provider_or_publication(self):
        from pcbex_agent import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            snapshot = root / "snapshot.json"
            fetch_receipt = root / "fetch.json"
            output = root / "bundle.json"
            provenance_output = root / "provenance.json"
            requirements.write_text("make a capacitor", encoding="utf-8")
            snapshot.write_text("{}\n", encoding="utf-8")
            fetch_receipt.write_text('{"a":1,"a":2}\n', encoding="utf-8")
            argv = [
                "pcbex-agent",
                "generate-circuit",
                str(requirements),
                "--output",
                str(output),
                "--catalog-snapshot",
                str(snapshot),
                "--catalog-fetch-receipt",
                str(fetch_receipt),
                "--catalog-provenance-output",
                str(provenance_output),
                "--provider-command",
                "provider",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(cli, "generate_circuit_with_command") as generate,
                patch.object(cli, "build_catalog_generation_provenance") as build,
                self.assertRaises(SystemExit),
            ):
                cli.main()
            generate.assert_not_called()
            build.assert_not_called()
            self.assertFalse(output.exists())
            self.assertFalse(provenance_output.exists())


if __name__ == "__main__":
    unittest.main()

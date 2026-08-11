import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import pcbex_agent
from pcbex_agent import cli, supplier_offer


class SupplierOfferCliV1468Tests(unittest.TestCase):
    @staticmethod
    def _required_arguments(root: Path, output: Path) -> list[str]:
        return [
            "pcbex-agent",
            "build-supplier-offer-coverage",
            str(root / "board.kicad_pcb"),
            str(root / "manufacturing.zip"),
            "--circuit-generation",
            str(root / "generation.json"),
            "--catalog-snapshot",
            str(root / "catalog.json"),
            "--procurement-intent",
            str(root / "intent.json"),
            "--supplier-offer",
            str(root / "offer.json"),
            "--requested-boards",
            "12",
            "--evaluated-at-unix",
            "1700000000",
            "--output",
            str(output),
        ]

    def test_package_facade_exports_the_public_supplier_offer_surface(self) -> None:
        for name in (
            "SupplierOfferError",
            "MAXIMUM_SUPPLIER_OFFER_BYTES",
            "MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES",
            "build_supplier_offer_coverage",
            "evaluate_supplier_offer_coverage",
            "validate_supplier_offer_coverage",
            "render_supplier_offer_coverage",
            "normalized_supplier_offer_json_schema",
            "supplier_offer_coverage_json_schema",
        ):
            with self.subTest(name=name):
                self.assertIn(name, pcbex_agent.__all__)
                self.assertIs(getattr(pcbex_agent, name), getattr(supplier_offer, name))
        self.assertEqual(pcbex_agent.MAXIMUM_SUPPLIER_OFFER_BYTES, 4 * 1024 * 1024)
        self.assertEqual(
            pcbex_agent.MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
            16 * 1024 * 1024,
        )

    def test_help_exposes_the_exact_closed_command_surface(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", "build-supplier-offer-coverage", "--help"],
            ),
            redirect_stdout(stdout),
            self.assertRaises(SystemExit) as stopped,
        ):
            cli.main()
        self.assertEqual(stopped.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertIn("evaluate whether", help_text)
        self.assertNotIn("verify whether", help_text)
        for value in (
            "BOARD",
            "MANUFACTURING_ZIP",
            "--circuit-generation GENERATION",
            "--catalog-snapshot SNAPSHOT",
            "--procurement-intent INTENT",
            "--supplier-offer OFFER",
            "--requested-boards N",
            "--evaluated-at-unix N",
            "--pcbex CMD",
            "--timeout-seconds SECONDS",
            "--output REPORT",
            "--require-covered",
        ):
            with self.subTest(value=value):
                self.assertIn(value, help_text)

        for command in (
            "supplier-offer-schema",
            "supplier-offer-coverage-schema",
        ):
            with self.subTest(command=command):
                schema_stdout = io.StringIO()
                with (
                    mock.patch.object(
                        sys,
                        "argv",
                        ["pcbex-agent", command, "--help"],
                    ),
                    redirect_stdout(schema_stdout),
                    self.assertRaises(SystemExit) as schema_stopped,
                ):
                    cli.main()
                self.assertEqual(schema_stopped.exception.code, 0)
                self.assertIn("[-o PATH]", schema_stdout.getvalue())

    def test_parser_routes_every_option_and_publishes_core_bytes_directly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "coverage.json"
            result = {"schema_version": 1, "covered": True}
            rendered = b'{"rendered-by-core":true}\n'
            argv = [
                *self._required_arguments(root, output),
                "--pcbex",
                "trusted-pcbex",
                "--timeout-seconds",
                "17.5",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli,
                    "evaluate_supplier_offer_coverage",
                    return_value=result,
                ) as evaluate,
                mock.patch.object(
                    cli,
                    "render_supplier_offer_coverage",
                    return_value=rendered,
                ) as render,
                mock.patch.object(
                    cli,
                    "atomic_write_no_clobber",
                    wraps=cli.atomic_write_no_clobber,
                ) as write,
            ):
                cli.main()

            evaluate.assert_called_once_with(
                root / "board.kicad_pcb",
                root / "manufacturing.zip",
                root / "generation.json",
                root / "catalog.json",
                root / "intent.json",
                root / "offer.json",
                "trusted-pcbex",
                requested_boards=12,
                evaluated_at_unix=1700000000,
                timeout_seconds=17.5,
            )
            render.assert_called_once_with(result)
            write.assert_called_once_with(
                output,
                rendered,
                max_bytes=cli.MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
            )
            self.assertEqual(output.read_bytes(), rendered)
            self.assertNotIn(b"\r", rendered)
            self.assertFalse(rendered.endswith(b"\n\n"))

    def test_existing_output_fails_before_evaluation_and_is_not_clobbered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "coverage.json"
            retained = b"do not replace\n"
            output.write_bytes(retained)
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._required_arguments(root, output),
                ),
                mock.patch.object(
                    cli, "evaluate_supplier_offer_coverage"
                ) as evaluate,
                mock.patch.object(cli, "render_supplier_offer_coverage") as render,
                self.assertRaisesRegex(
                    SystemExit,
                    "supplier offer coverage evaluation failed: .*already exists",
                ),
            ):
                cli.main()
            evaluate.assert_not_called()
            render.assert_not_called()
            self.assertEqual(output.read_bytes(), retained)

    def test_not_covered_report_is_retained_before_require_covered_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "coverage.json"
            result = {"schema_version": 1, "covered": False}
            rendered = b'{"covered":false}\n'
            argv = [
                *self._required_arguments(root, output),
                "--require-covered",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli,
                    "evaluate_supplier_offer_coverage",
                    return_value=result,
                ),
                mock.patch.object(
                    cli,
                    "render_supplier_offer_coverage",
                    return_value=rendered,
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "supplier offer coverage report was retained but the offer "
                    "does not cover the procurement intent",
                ),
            ):
                cli.main()
            self.assertEqual(output.read_bytes(), rendered)

    def test_both_schema_commands_are_closed_exact_and_never_clobber(self) -> None:
        for command in (
            "supplier-offer-schema",
            "supplier-offer-coverage-schema",
        ):
            with self.subTest(command=command):
                stdout = io.StringIO()
                with (
                    mock.patch.object(sys, "argv", ["pcbex-agent", command]),
                    redirect_stdout(stdout),
                ):
                    cli.main()
                rendered = stdout.getvalue()
                self.assertTrue(rendered.endswith("\n"))
                self.assertFalse(rendered.endswith("\n\n"))
                self.assertNotIn("\r", rendered)
                self.assertFalse(json.loads(rendered)["additionalProperties"])

                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve(strict=True)
                    output = root / f"{command}.json"
                    argv = ["pcbex-agent", command, "--output", str(output)]
                    with mock.patch.object(sys, "argv", argv):
                        cli.main()
                    retained = output.read_bytes()
                    self.assertEqual(retained, rendered.encode("utf-8"))
                    with (
                        mock.patch.object(sys, "argv", argv),
                        self.assertRaisesRegex(
                            SystemExit,
                            "supplier offer schema failed: .*already exists",
                        ),
                    ):
                        cli.main()
                    self.assertEqual(output.read_bytes(), retained)

    def test_core_and_schema_failures_are_compact_and_publish_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "coverage.json"
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._required_arguments(root, output),
                ),
                mock.patch.object(
                    cli,
                    "evaluate_supplier_offer_coverage",
                    side_effect=cli.SupplierOfferError("offer is invalid"),
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "supplier offer coverage evaluation failed: offer is invalid",
                ),
            ):
                cli.main()
            self.assertFalse(output.exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "coverage.json"
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._required_arguments(root, output),
                ),
                mock.patch.object(
                    cli,
                    "evaluate_supplier_offer_coverage",
                    return_value={"schema_version": 1, "covered": True},
                ),
                mock.patch.object(
                    cli,
                    "render_supplier_offer_coverage",
                    side_effect=cli.SupplierOfferError("result is invalid"),
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "supplier offer coverage evaluation failed: result is invalid",
                ),
            ):
                cli.main()
            self.assertFalse(output.exists())

        with (
            mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", "supplier-offer-schema"],
            ),
            mock.patch.object(
                cli,
                "normalized_supplier_offer_json_schema",
                side_effect=cli.SupplierOfferError("schema unavailable"),
            ),
            self.assertRaisesRegex(
                SystemExit,
                "supplier offer schema failed: schema unavailable",
            ),
        ):
            cli.main()


if __name__ == "__main__":
    unittest.main()

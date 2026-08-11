import io
import json
import sys
import tempfile
import traceback
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import pcbex_agent
from pcbex_agent import cli, supplier_offer_acquisition


class SupplierOfferAcquisitionCliV1469Tests(unittest.TestCase):
    @staticmethod
    def _required_arguments(root: Path, output: Path, receipt: Path) -> list[str]:
        return [
            "pcbex-agent",
            "fetch-supplier-offer",
            "--endpoint",
            "https://offers.example.test/v1/quote",
            "--supplier",
            "example-supplier",
            "--procurement-intent-sha256",
            "a" * 64,
            "--output",
            str(output),
            "--receipt",
            str(receipt),
        ]

    def test_package_facade_exports_the_public_acquisition_surface(self) -> None:
        for name in (
            "SupplierOfferAcquisitionError",
            "MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES",
            "fetch_supplier_offer",
            "validate_supplier_offer_fetch_receipt",
            "supplier_offer_fetch_receipt_json_schema",
        ):
            with self.subTest(name=name):
                self.assertIn(name, pcbex_agent.__all__)
                self.assertIs(
                    getattr(pcbex_agent, name),
                    getattr(supplier_offer_acquisition, name),
                )
        self.assertEqual(pcbex_agent.MAXIMUM_SUPPLIER_OFFER_BYTES, 4 * 1024 * 1024)
        self.assertEqual(
            pcbex_agent.MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
            1 * 1024 * 1024,
        )

    def test_help_exposes_only_the_frozen_command_surface(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", "fetch-supplier-offer", "--help"],
            ),
            redirect_stdout(stdout),
            self.assertRaises(SystemExit) as stopped,
        ):
            cli.main()
        self.assertEqual(stopped.exception.code, 0)
        help_text = stdout.getvalue()
        for value in (
            "--endpoint URL",
            "--supplier ID",
            "--procurement-intent-sha256 HEX",
            "--output OFFER",
            "--receipt RECEIPT",
            "--timeout-seconds SECONDS",
            "default: 30",
            "--maximum-response-bytes BYTES",
            "default: 4194304",
            "--bearer-token-environment NAME",
        ):
            with self.subTest(value=value):
                self.assertIn(value, help_text)
        for hidden in ("--fetched-at-unix", "--allow-insecure-loopback"):
            with self.subTest(hidden=hidden):
                self.assertNotIn(hidden, help_text)

        schema_stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", "supplier-offer-fetch-receipt-schema", "--help"],
            ),
            redirect_stdout(schema_stdout),
            self.assertRaises(SystemExit) as schema_stopped,
        ):
            cli.main()
        self.assertEqual(schema_stopped.exception.code, 0)
        self.assertIn("[-o PATH]", schema_stdout.getvalue())

    def test_hidden_transport_controls_are_rejected_before_core(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            for hidden in ("--fetched-at-unix", "--allow-insecure-loopback"):
                with self.subTest(hidden=hidden):
                    argv = [
                        *self._required_arguments(
                            root,
                            root / f"{hidden[2:]}.json",
                            root / f"{hidden[2:]}.receipt.json",
                        ),
                        hidden,
                    ]
                    if hidden == "--fetched-at-unix":
                        argv.append("1700000000")
                    with (
                        mock.patch.object(sys, "argv", argv),
                        mock.patch.object(cli, "fetch_supplier_offer") as fetch,
                        redirect_stderr(io.StringIO()),
                        self.assertRaises(SystemExit) as stopped,
                    ):
                        cli.main()
                    self.assertEqual(stopped.exception.code, 2)
                    fetch.assert_not_called()

    def test_parser_routes_every_option_and_prints_only_exact_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "offer.json"
            receipt_path = root / "receipt.json"
            receipt = {
                "response_sha256": "b" * 64,
                "offer_sha256": "c" * 64,
            }
            argv = [
                *self._required_arguments(root, output, receipt_path),
                "--timeout-seconds",
                "17",
                "--maximum-response-bytes",
                "4096",
                "--bearer-token-environment",
                "PCBEX_SECRET_OFFER_TOKEN",
            ]
            stdout = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli,
                    "fetch_supplier_offer",
                    return_value=receipt,
                ) as fetch,
                redirect_stdout(stdout),
            ):
                cli.main()

            fetch.assert_called_once_with(
                "https://offers.example.test/v1/quote",
                "example-supplier",
                output,
                receipt_path,
                procurement_intent_sha256="a" * 64,
                timeout_seconds=17,
                maximum_response_bytes=4096,
                bearer_token_environment="PCBEX_SECRET_OFFER_TOKEN",
            )
            self.assertEqual(
                stdout.getvalue(),
                "supplier offer written with response "
                + "b" * 64
                + " and offer "
                + "c" * 64
                + "\n",
            )
            for secret in (
                "offers.example.test",
                "example-supplier",
                "PCBEX_SECRET_OFFER_TOKEN",
            ):
                self.assertNotIn(secret, stdout.getvalue())

    def test_parser_forwards_frozen_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "offer.json"
            receipt_path = root / "receipt.json"
            receipt = {
                "response_sha256": "b" * 64,
                "offer_sha256": "c" * 64,
            }
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._required_arguments(root, output, receipt_path),
                ),
                mock.patch.object(
                    cli,
                    "fetch_supplier_offer",
                    return_value=receipt,
                ) as fetch,
                redirect_stdout(io.StringIO()),
            ):
                cli.main()
            fetch.assert_called_once_with(
                "https://offers.example.test/v1/quote",
                "example-supplier",
                output,
                receipt_path,
                procurement_intent_sha256="a" * 64,
                timeout_seconds=30,
                maximum_response_bytes=4_194_304,
                bearer_token_environment=None,
            )

    def test_fetch_failure_is_compact_and_suppresses_underlying_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "offer.json"
            receipt_path = root / "receipt.json"
            secret = "endpoint-token-or-response-body-secret"
            error = cli.SupplierOfferAcquisitionError("supplier offer request failed")
            error.__cause__ = RuntimeError(secret)
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._required_arguments(root, output, receipt_path),
                ),
                mock.patch.object(
                    cli,
                    "fetch_supplier_offer",
                    side_effect=error,
                ),
                self.assertRaises(SystemExit) as stopped,
            ):
                cli.main()
            self.assertEqual(
                str(stopped.exception),
                "supplier offer fetch failed: supplier offer request failed",
            )
            rendered_trace = "".join(
                traceback.TracebackException.from_exception(
                    stopped.exception
                ).format(chain=True)
            )
            self.assertNotIn(secret, rendered_trace)
            self.assertFalse(output.exists())
            self.assertFalse(receipt_path.exists())

    def test_real_core_preflights_both_outputs_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "offer.json"
            receipt_path = root / "receipt.json"
            retained = b"do not replace\n"
            output.write_bytes(retained)
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._required_arguments(root, output, receipt_path),
                ),
                mock.patch.object(
                    cli,
                    "fetch_supplier_offer",
                    wraps=supplier_offer_acquisition.fetch_supplier_offer,
                ) as fetch,
                mock.patch.object(
                    supplier_offer_acquisition._transport, "_http_get"
                ) as transport,
                self.assertRaisesRegex(
                    SystemExit,
                    "supplier offer fetch failed: supplier-offer output path is "
                    "unsafe or already exists",
                ),
            ):
                cli.main()
            fetch.assert_called_once()
            transport.assert_not_called()
            self.assertEqual(output.read_bytes(), retained)
            self.assertFalse(receipt_path.exists())

            output = root / "offer-for-occupied-receipt.json"
            receipt_path = root / "occupied-receipt.json"
            receipt_path.write_bytes(retained)
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._required_arguments(root, output, receipt_path),
                ),
                mock.patch.object(
                    cli,
                    "fetch_supplier_offer",
                    wraps=supplier_offer_acquisition.fetch_supplier_offer,
                ) as fetch,
                mock.patch.object(
                    supplier_offer_acquisition._transport, "_http_get"
                ) as transport,
                self.assertRaisesRegex(
                    SystemExit,
                    "supplier offer fetch failed: supplier-offer output path is "
                    "unsafe or already exists",
                ),
            ):
                cli.main()
            fetch.assert_called_once()
            transport.assert_not_called()
            self.assertFalse(output.exists())
            self.assertEqual(receipt_path.read_bytes(), retained)

            shared_output = root / "shared.json"
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._required_arguments(root, shared_output, shared_output),
                ),
                mock.patch.object(
                    cli,
                    "fetch_supplier_offer",
                    wraps=supplier_offer_acquisition.fetch_supplier_offer,
                ) as fetch,
                mock.patch.object(
                    supplier_offer_acquisition._transport, "_http_get"
                ) as transport,
                self.assertRaisesRegex(
                    SystemExit,
                    "supplier offer fetch failed: supplier-offer output and receipt "
                    "paths must differ",
                ),
            ):
                cli.main()
            fetch.assert_called_once()
            transport.assert_not_called()
            self.assertFalse(shared_output.exists())

    def test_receipt_schema_stdout_file_and_no_clobber_are_exact(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", "supplier-offer-fetch-receipt-schema"],
            ),
            redirect_stdout(stdout),
        ):
            cli.main()
        rendered = stdout.getvalue()
        self.assertTrue(rendered.endswith("\n"))
        self.assertFalse(rendered.endswith("\n\n"))
        self.assertNotIn("\r", rendered)
        schema = json.loads(rendered)
        self.assertEqual(
            schema["$id"],
            "https://github.com/penguin425/pcbex/schemas/"
            "supplier-offer-fetch-receipt-v1.json",
        )
        self.assertFalse(schema["additionalProperties"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "supplier-offer-fetch-receipt.schema.json"
            argv = [
                "pcbex-agent",
                "supplier-offer-fetch-receipt-schema",
                "--output",
                str(output),
            ]
            with mock.patch.object(sys, "argv", argv):
                cli.main()
            retained = output.read_bytes()
            self.assertEqual(retained, rendered.encode("utf-8"))
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli, "supplier_offer_fetch_receipt_json_schema"
                ) as schema,
                self.assertRaisesRegex(
                    SystemExit,
                    "supplier offer fetch receipt schema failed: .*already exists",
                ),
            ):
                cli.main()
            schema.assert_not_called()
            self.assertEqual(output.read_bytes(), retained)


if __name__ == "__main__":
    unittest.main()

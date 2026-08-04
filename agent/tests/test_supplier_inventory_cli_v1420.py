import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from pcbex_agent.cli import main as agent_main
from pcbex_agent.supplier_inventory import SupplierInventoryError


class SupplierInventoryCliV1420Tests(unittest.TestCase):
    def test_fetch_command_forwards_closed_options_and_prints_only_digests(self):
        receipt = {
            "response_sha256": "a" * 64,
            "snapshot_sha256": "b" * 64,
        }
        arguments = [
            "pcbex-agent",
            "fetch-catalog-snapshot",
            "--endpoint",
            "https://inventory.example.test/catalog/v1",
            "--provider",
            "jlcpcb",
            "--output",
            "snapshot.json",
            "--receipt",
            "receipt.json",
            "--timeout-seconds",
            "17",
            "--maximum-response-bytes",
            "4096",
            "--bearer-token-environment",
            "PCBEX_CATALOG_TOKEN",
        ]
        output = io.StringIO()
        with (
            patch.object(sys, "argv", arguments),
            patch(
                "pcbex_agent.cli.fetch_catalog_snapshot",
                return_value=receipt,
            ) as fetch,
            redirect_stdout(output),
        ):
            agent_main()

        fetch.assert_called_once_with(
            "https://inventory.example.test/catalog/v1",
            "jlcpcb",
            Path("snapshot.json"),
            Path("receipt.json"),
            timeout_seconds=17,
            maximum_response_bytes=4096,
            bearer_token_environment="PCBEX_CATALOG_TOKEN",
        )
        rendered = output.getvalue()
        self.assertIn("a" * 64, rendered)
        self.assertIn("b" * 64, rendered)
        self.assertNotIn("PCBEX_CATALOG_TOKEN", rendered)

    def test_fetch_failure_is_compact(self):
        arguments = [
            "pcbex-agent",
            "fetch-catalog-snapshot",
            "--endpoint",
            "https://inventory.example.test/catalog/v1",
            "--provider",
            "jlcpcb",
            "--output",
            "snapshot.json",
            "--receipt",
            "receipt.json",
        ]
        with (
            patch.object(sys, "argv", arguments),
            patch(
                "pcbex_agent.cli.fetch_catalog_snapshot",
                side_effect=SupplierInventoryError("request failed"),
            ),
            self.assertRaisesRegex(
                SystemExit,
                "catalog snapshot fetch failed: request failed",
            ),
        ):
            agent_main()

    def test_fetch_receipt_schema_prints_the_closed_contract(self):
        output = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                ["pcbex-agent", "catalog-fetch-receipt-schema"],
            ),
            redirect_stdout(output),
        ):
            agent_main()

        schema = json.loads(output.getvalue())
        self.assertEqual(
            schema["$id"],
            "https://github.com/penguin425/pcbex/schema/catalog-fetch-receipt-v1.json",
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["adapter"]["const"], "supplier-inventory-http-v1")


if __name__ == "__main__":
    unittest.main()

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import pcbex_agent.managed_provider as managed_provider
import pcbex_agent.provider as provider
from pcbex_agent.provider import ProviderError


def _request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "request_sha256": "a" * 64,
        "requirements": [],
        "evidence_ids": [],
    }


def _write_request(root: Path) -> Path:
    path = root / "request.json"
    path.write_text(json.dumps(_request()), encoding="utf-8")
    return path


def _symlink_or_skip(case: unittest.TestCase, target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as error:
        case.skipTest(f"symbolic links are unavailable: {error}")


class ProviderBoundaryTests(unittest.TestCase):
    def test_absolute_and_relative_artifact_aliases_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = _write_request(root)
            output = root / "same.json"
            with self.assertRaisesRegex(ProviderError, "paths must differ"):
                provider.review_schematic_with_command(
                    request,
                    output,
                    Path(os.path.relpath(output)),
                    ["must-not-spawn"],
                )

    def test_prompt_limit_is_exact_and_checked_before_spawn(self):
        with patch.object(provider, "MAXIMUM_PROVIDER_PROMPT_BYTES", 4):
            self.assertEqual(provider._encode_provider_prompt("1234"), b"1234")
            with (
                patch.object(provider, "run_bounded") as runner,
                self.assertRaisesRegex(ProviderError, "exceeded 4 bytes"),
            ):
                provider._run_provider(
                    ["must-not-spawn"],
                    "12345",
                    timeout_seconds=1,
                    max_output_bytes=16,
                )
            runner.assert_not_called()

    def test_managed_request_limit_is_exact(self):
        request = {"input": "bounded"}
        encoded = json.dumps(
            request, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        with patch.object(
            managed_provider,
            "MAXIMUM_MANAGED_PROVIDER_REQUEST_BYTES",
            len(encoded),
        ):
            self.assertEqual(
                managed_provider._encode_bounded_provider_request(request),
                encoded,
            )
        with (
            patch.object(
                managed_provider,
                "MAXIMUM_MANAGED_PROVIDER_REQUEST_BYTES",
                len(encoded) - 1,
            ),
            self.assertRaisesRegex(ProviderError, "request exceeded"),
        ):
            managed_provider._encode_bounded_provider_request(request)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_command_provider_rejects_dangling_output_before_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = _write_request(root)
            output = root / "response.json"
            marker = root / "provider-ran"
            _symlink_or_skip(self, root / "missing-target", output)

            with self.assertRaisesRegex(ProviderError, "symbolic link"):
                provider.review_schematic_with_command(
                    request,
                    output,
                    root / "receipt.json",
                    [
                        sys.executable,
                        "-c",
                        "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()",
                        str(marker),
                    ],
                )

            self.assertFalse(marker.exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_managed_provider_rejects_linked_parent_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = _write_request(root)
            linked_parent = root / "linked"
            _symlink_or_skip(self, root, linked_parent)

            with (
                patch.object(managed_provider, "_post_json") as post,
                self.assertRaisesRegex(ProviderError, "symbolic link"),
            ):
                managed_provider.review_schematic_with_managed_provider(
                    request,
                    linked_parent / "response.json",
                    root / "receipt.json",
                    provider="openai",
                    model="reviewer",
                )
            post.assert_not_called()

    def test_command_receipt_failure_retains_published_response(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = _write_request(root)
            output = root / "response.json"
            receipt = root / "receipt.json"
            real_write = provider._atomic_write_new
            calls = 0

            def fail_second_write(path: Path, value: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise ProviderError("simulated receipt publication failure")
                real_write(path, value)

            with (
                patch.object(
                    provider,
                    "review_schematic_with_llm",
                    return_value={"decision": "approve"},
                ),
                patch.object(
                    provider,
                    "_atomic_write_new",
                    side_effect=fail_second_write,
                ),
                self.assertRaisesRegex(ProviderError, "simulated receipt"),
            ):
                provider.review_schematic_with_command(
                    request,
                    output,
                    receipt,
                    ["unused-provider"],
                )

            self.assertEqual(json.loads(output.read_text()), {"decision": "approve"})
            self.assertFalse(receipt.exists())

    def test_managed_receipt_failure_retains_published_response(self):
        raw_provider_response = json.dumps(
            {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": "{}"}],
                    }
                ],
            }
        ).encode("utf-8")

        def fake_review(_request: object, transport: object) -> dict[str, str]:
            transport("bounded prompt")
            return {"decision": "approve"}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = _write_request(root)
            output = root / "response.json"
            receipt = root / "receipt.json"
            real_write = provider._atomic_write_new
            calls = 0

            def fail_second_write(path: Path, value: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise ProviderError("simulated receipt publication failure")
                real_write(path, value)

            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": "secret"}),
                patch.object(
                    managed_provider,
                    "review_schematic_with_llm",
                    side_effect=fake_review,
                ),
                patch.object(
                    managed_provider,
                    "_post_json",
                    return_value=raw_provider_response,
                ),
                patch.object(
                    managed_provider,
                    "_atomic_write_new",
                    side_effect=fail_second_write,
                ),
                self.assertRaisesRegex(ProviderError, "simulated receipt"),
            ):
                managed_provider.review_schematic_with_managed_provider(
                    request,
                    output,
                    receipt,
                    provider="openai",
                    model="reviewer",
                )

            self.assertEqual(json.loads(output.read_text()), {"decision": "approve"})
            self.assertFalse(receipt.exists())

    def test_command_nonzero_uses_stdout_when_stderr_is_empty(self):
        with self.assertRaisesRegex(ProviderError, "stdout diagnostic"):
            provider._run_provider(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('stdout diagnostic'); sys.exit(7)",
                ],
                "prompt",
                timeout_seconds=5,
                max_output_bytes=1024,
            )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import traceback
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import pcbex_agent
import pcbex_agent.procurement_release_authorization as authorization_module
from pcbex_agent import cli


class ProcurementReleaseAuthorizationCliV1471Tests(unittest.TestCase):
    @staticmethod
    def _paths(root: Path) -> dict[str, Path]:
        return {
            "evidence": root / "assembly-supplier-offer-evidence.json",
            "handoff": root / "handoff.zip",
            "board": root / "board.kicad_pcb",
            "manufacturing_package": root / "manufacturing.zip",
            "board_binding_report": root / "board-binding.json",
            "procurement_intent": root / "procurement-intent.json",
            "catalog_snapshot": root / "catalog.json",
            "final_cpl_report": root / "final-cpl.json",
            "assembly_evidence": root / "assembly-evidence.json",
            "supplier_offer": root / "supplier-offer.json",
            "supplier_offer_fetch_receipt": root / "fetch-receipt.json",
            "supplier_offer_coverage": root / "coverage.json",
            "policy_pack": root / "policy-pack.json",
            "private_key": root / "procurement-a.private-key",
            "approval_a": root / "procurement-a.approval.json",
            "approval_b": root / "procurement-b.approval.json",
            "board_binding_policy": root / "board-binding-policy.json",
            "manufacturing_kicad_project": root / "board.kicad_pro",
            "manufacturing_kicad_rules": root / "board.kicad_dru",
            "manufacturing_fab_profile": root / "fab-profile.json",
            "manufacturing_physical_profile": root / "physical-profile.json",
        }

    @staticmethod
    def _source_arguments(paths: dict[str, Path]) -> list[str]:
        return [
            str(paths["evidence"]),
            str(paths["handoff"]),
            str(paths["board"]),
            str(paths["manufacturing_package"]),
            "--board-binding-report",
            str(paths["board_binding_report"]),
            "--procurement-intent",
            str(paths["procurement_intent"]),
            "--catalog-snapshot",
            str(paths["catalog_snapshot"]),
            "--final-cpl-report",
            str(paths["final_cpl_report"]),
            "--assembly-evidence",
            str(paths["assembly_evidence"]),
            "--supplier-offer",
            str(paths["supplier_offer"]),
            "--supplier-offer-fetch-receipt",
            str(paths["supplier_offer_fetch_receipt"]),
            "--supplier-offer-coverage",
            str(paths["supplier_offer_coverage"]),
            "--policy-pack",
            str(paths["policy_pack"]),
            "--requested-boards",
            "25",
            "--evaluated-at-unix",
            "1700000000",
            "--expected-policy-pack-canonical-sha256",
            "d" * 64,
        ]

    @classmethod
    def _sign_arguments(
        cls,
        paths: dict[str, Path],
        output: Path,
        *,
        extra: tuple[str, ...] = (),
    ) -> list[str]:
        return [
            "pcbex-agent",
            "sign-procurement-approval",
            *cls._source_arguments(paths),
            "--private-key",
            str(paths["private_key"]),
            "--signer-id",
            "procurement-a",
            "--decision",
            "approve",
            "--authorization-id",
            "release-1471",
            "--challenge",
            "c" * 64,
            "--maximum-component-subtotal-micros",
            "2500000000",
            "--valid-from-unix",
            "1699999900",
            "--expires-at-unix",
            "1700000100",
            "--reason",
            "Approved for this exact release.",
            "--ticket",
            "HW-1471",
            *extra,
            "--output",
            str(output),
        ]

    @classmethod
    def _verify_arguments(
        cls,
        paths: dict[str, Path],
        output: Path,
        *,
        approvals: tuple[Path, ...] | None = None,
        extra: tuple[str, ...] = (),
    ) -> list[str]:
        selected = approvals or (paths["approval_a"], paths["approval_b"])
        approval_arguments = [
            value
            for approval in selected
            for value in ("--approval", str(approval))
        ]
        return [
            "pcbex-agent",
            "verify-procurement-authorization",
            *cls._source_arguments(paths),
            *approval_arguments,
            *extra,
            "--output",
            str(output),
        ]

    @staticmethod
    def _source_call_arguments(paths: dict[str, Path]) -> tuple[Path, ...]:
        return (
            paths["evidence"],
            paths["handoff"],
            paths["board"],
            paths["manufacturing_package"],
            paths["board_binding_report"],
            paths["procurement_intent"],
            paths["catalog_snapshot"],
            paths["final_cpl_report"],
            paths["assembly_evidence"],
            paths["supplier_offer"],
            paths["supplier_offer_fetch_receipt"],
            paths["supplier_offer_coverage"],
            paths["policy_pack"],
        )

    @staticmethod
    def _default_replay_keywords() -> dict[str, object]:
        return {
            "board_binding_policy": None,
            "kicad_cli": "kicad-cli",
            "manufacturing_kicad_project": None,
            "manufacturing_kicad_rules": None,
            "manufacturing_fab": None,
            "manufacturing_fab_profile": None,
            "manufacturing_physical_profile": None,
            "expected_archive_sha256": None,
            "expected_bundle_sha256": None,
            "timeout_seconds": 300.0,
        }

    @classmethod
    def _default_sign_keywords(cls) -> dict[str, object]:
        return {
            "requested_boards": 25,
            "evaluated_at_unix": 1700000000,
            "expected_policy_pack_canonical_sha256": "d" * 64,
            "signer_id": "procurement-a",
            "decision": "approve",
            "authorization_id": "release-1471",
            "challenge": "c" * 64,
            "maximum_component_subtotal_micros": 2500000000,
            "valid_from_unix": 1699999900,
            "expires_at_unix": 1700000100,
            "reason": "Approved for this exact release.",
            "ticket": "HW-1471",
            **cls._default_replay_keywords(),
        }

    @classmethod
    def _default_verify_keywords(cls) -> dict[str, object]:
        return {
            "requested_boards": 25,
            "evaluated_at_unix": 1700000000,
            "expected_policy_pack_canonical_sha256": "d" * 64,
            **cls._default_replay_keywords(),
        }

    def test_package_facade_exports_the_frozen_public_surface(self) -> None:
        names = (
            "ProcurementReleaseAuthorizationError",
            "sign_procurement_approval",
            "evaluate_procurement_release_authorization",
            "build_procurement_release_authorization",
            "verify_procurement_authorization",
            "validate_procurement_release_authorization",
            "render_signed_procurement_approval",
            "render_procurement_authorization_report",
            "signed_procurement_approval_json_schema",
            "procurement_authorization_report_json_schema",
            "MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES",
            "MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES",
            "MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES",
            "MAXIMUM_PROCUREMENT_APPROVAL_AGGREGATE_BYTES",
        )
        self.assertEqual(set(authorization_module.__all__), set(names))
        for name in names:
            with self.subTest(name=name):
                self.assertIn(name, pcbex_agent.__all__)
                self.assertIs(
                    getattr(pcbex_agent, name),
                    getattr(authorization_module, name),
                )
        self.assertEqual(
            pcbex_agent.MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES,
            1 * 1024 * 1024,
        )
        self.assertEqual(
            pcbex_agent.MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
            128 * 1024 * 1024,
        )
        self.assertEqual(
            pcbex_agent.MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES,
            64 * 1024 * 1024,
        )
        self.assertEqual(
            pcbex_agent.MAXIMUM_PROCUREMENT_APPROVAL_AGGREGATE_BYTES,
            32 * 1024 * 1024,
        )
        self.assertIs(
            pcbex_agent.build_procurement_release_authorization,
            pcbex_agent.evaluate_procurement_release_authorization,
        )

    def test_sign_and_verify_help_expose_only_the_offline_surface(self) -> None:
        shared = (
            "EVIDENCE",
            "HANDOFF",
            "BOARD",
            "MANUFACTURING_PACKAGE",
            "--board-binding-report REPORT",
            "--procurement-intent INTENT",
            "--catalog-snapshot SNAPSHOT",
            "--final-cpl-report REPORT",
            "--assembly-evidence REPORT",
            "--supplier-offer OFFER",
            "--supplier-offer-fetch-receipt RECEIPT",
            "--supplier-offer-coverage COVERAGE",
            "--policy-pack POLICY_PACK",
            "--requested-boards N",
            "--evaluated-at-unix N",
            "--expected-policy-pack-canonical-sha256 HEX",
            "--pcbex CMD",
            "--authorization-pcbex CMD",
            "--board-binding-policy POLICY",
            "--manufacturing-kicad-cli CMD",
            "--manufacturing-kicad-project PATH",
            "--manufacturing-kicad-rules PATH",
            "--manufacturing-fab ID",
            "--manufacturing-fab-profile PATH",
            "--manufacturing-physical-profile PATH",
            "--expected-handoff-archive-sha256 HEX",
            "--expected-handoff-bundle-sha256 HEX",
            "--timeout-seconds SECONDS",
            "default: 300.0",
        )
        command_specific = {
            "sign-procurement-approval": (
                "--private-key PRIVATE_KEY",
                "--signer-id ID",
                "--decision {approve,reject}",
                "--authorization-id ID",
                "--challenge CHALLENGE",
                "--maximum-component-subtotal-micros N",
                "--valid-from-unix N",
                "--expires-at-unix N",
                "--reason TEXT",
                "--ticket TICKET",
                "-o APPROVAL, --output APPROVAL",
            ),
            "verify-procurement-authorization": (
                "--approval APPROVAL",
                "-o REPORT, --output REPORT",
                "--require-authorized",
            ),
        }
        forbidden = (
            "--endpoint",
            "--bearer-token-environment",
            "--maximum-response-bytes",
            "--allow-insecure-loopback",
            "--cart",
            "--order",
            "--payment",
            "--shipping",
            "--tax",
        )
        for command, specific in command_specific.items():
            stdout = io.StringIO()
            with (
                self.subTest(command=command),
                mock.patch.object(sys, "argv", ["pcbex-agent", command, "--help"]),
                redirect_stdout(stdout),
                self.assertRaises(SystemExit) as stopped,
            ):
                cli.main()
            self.assertEqual(stopped.exception.code, 0)
            rendered = stdout.getvalue()
            for expected in (*shared, *specific):
                with self.subTest(command=command, expected=expected):
                    self.assertIn(expected, rendered)
            for unexpected in forbidden:
                with self.subTest(command=command, unexpected=unexpected):
                    self.assertNotIn(unexpected, rendered)

    def test_manufacturing_profiles_are_mutually_exclusive_for_both_commands(
        self,
    ) -> None:
        profile_pairs = (
            (
                ("--manufacturing-fab", "fab-a"),
                ("--manufacturing-fab-profile", "fab.json"),
            ),
            (
                ("--manufacturing-fab", "fab-a"),
                ("--manufacturing-physical-profile", "physical.json"),
            ),
            (
                ("--manufacturing-fab-profile", "fab.json"),
                ("--manufacturing-physical-profile", "physical.json"),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            for command in (
                "sign-procurement-approval",
                "verify-procurement-authorization",
            ):
                for index, (left, right) in enumerate(profile_pairs):
                    extra = (*left, *right)
                    output = root / f"conflict-{command}-{index}.json"
                    argv = (
                        self._sign_arguments(paths, output, extra=extra)
                        if command == "sign-procurement-approval"
                        else self._verify_arguments(paths, output, extra=extra)
                    )
                    with (
                        self.subTest(command=command, left=left[0], right=right[0]),
                        mock.patch.object(sys, "argv", argv),
                        mock.patch.object(cli, "sign_procurement_approval") as sign,
                        mock.patch.object(
                            cli, "verify_procurement_authorization"
                        ) as verify,
                        redirect_stderr(io.StringIO()),
                        self.assertRaises(SystemExit) as stopped,
                    ):
                        cli.main()
                    self.assertEqual(stopped.exception.code, 2)
                    sign.assert_not_called()
                    verify.assert_not_called()

    def test_sign_routes_all_options_and_publishes_exact_renderer_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "signed-approval.json"
            result = {"schema_version": 1, "decision": "approve"}
            canonical = b'{"exact":"signed renderer bytes"}\n'
            extra = (
                "--pcbex",
                "replay-pcbex-custom",
                "--authorization-pcbex",
                "authorization-pcbex-custom",
                "--board-binding-policy",
                str(paths["board_binding_policy"]),
                "--manufacturing-kicad-cli",
                "kicad-cli-custom",
                "--manufacturing-kicad-project",
                str(paths["manufacturing_kicad_project"]),
                "--manufacturing-kicad-rules",
                str(paths["manufacturing_kicad_rules"]),
                "--manufacturing-physical-profile",
                str(paths["manufacturing_physical_profile"]),
                "--expected-handoff-archive-sha256",
                "a" * 64,
                "--expected-handoff-bundle-sha256",
                "b" * 64,
                "--timeout-seconds",
                "17.5",
            )
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._sign_arguments(paths, output, extra=extra),
                ),
                mock.patch.object(
                    cli, "sign_procurement_approval", return_value=result
                ) as sign,
                mock.patch.object(
                    cli,
                    "render_signed_procurement_approval",
                    return_value=canonical,
                ) as render,
                mock.patch.object(
                    cli,
                    "atomic_write_no_clobber",
                    wraps=cli.atomic_write_no_clobber,
                ) as writer,
            ):
                cli.main()
            sign.assert_called_once_with(
                *self._source_call_arguments(paths),
                paths["private_key"],
                "replay-pcbex-custom",
                "authorization-pcbex-custom",
                requested_boards=25,
                evaluated_at_unix=1700000000,
                expected_policy_pack_canonical_sha256="d" * 64,
                signer_id="procurement-a",
                decision="approve",
                authorization_id="release-1471",
                challenge="c" * 64,
                maximum_component_subtotal_micros=2500000000,
                valid_from_unix=1699999900,
                expires_at_unix=1700000100,
                reason="Approved for this exact release.",
                ticket="HW-1471",
                board_binding_policy=paths["board_binding_policy"],
                kicad_cli="kicad-cli-custom",
                manufacturing_kicad_project=paths[
                    "manufacturing_kicad_project"
                ],
                manufacturing_kicad_rules=paths["manufacturing_kicad_rules"],
                manufacturing_fab=None,
                manufacturing_fab_profile=None,
                manufacturing_physical_profile=paths[
                    "manufacturing_physical_profile"
                ],
                expected_archive_sha256="a" * 64,
                expected_bundle_sha256="b" * 64,
                timeout_seconds=17.5,
            )
            render.assert_called_once_with(result)
            writer.assert_called_once_with(
                output,
                canonical,
                max_bytes=1 * 1024 * 1024,
            )
            self.assertEqual(output.read_bytes(), canonical)

    def test_sign_routes_defaults_and_fab_profile_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "signed-approval.json"
            result = {"decision": "approve"}
            extra = (
                "--manufacturing-fab-profile",
                str(paths["manufacturing_fab_profile"]),
            )
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._sign_arguments(paths, output, extra=extra),
                ),
                mock.patch.object(
                    cli, "sign_procurement_approval", return_value=result
                ) as sign,
                mock.patch.object(
                    cli,
                    "render_signed_procurement_approval",
                    return_value=b"{}\n",
                ),
            ):
                cli.main()
            expected_keywords = self._default_sign_keywords()
            expected_keywords["manufacturing_fab_profile"] = paths[
                "manufacturing_fab_profile"
            ]
            sign.assert_called_once_with(
                *self._source_call_arguments(paths),
                paths["private_key"],
                "pcbex",
                "pcbex",
                **expected_keywords,
            )

    def test_private_key_is_forwarded_as_pathlike_and_never_opened_by_cli(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "signed-approval.json"
            result = {"decision": "approve"}
            with (
                mock.patch.object(
                    sys, "argv", self._sign_arguments(paths, output)
                ),
                mock.patch.object(
                    cli, "sign_procurement_approval", return_value=result
                ) as sign,
                mock.patch.object(
                    cli,
                    "render_signed_procurement_approval",
                    return_value=b"{}\n",
                ),
                mock.patch.object(cli, "atomic_write_no_clobber"),
                mock.patch.object(
                    cli,
                    "read_bytes",
                    side_effect=AssertionError("CLI read private-key bytes"),
                ),
                mock.patch.object(
                    cli,
                    "read_text",
                    side_effect=AssertionError("CLI read private-key text"),
                ),
                mock.patch.object(
                    Path,
                    "open",
                    side_effect=AssertionError("CLI opened private-key path"),
                ),
                mock.patch(
                    "builtins.open",
                    side_effect=AssertionError("CLI opened private-key path"),
                ),
                mock.patch.object(
                    cli.os,
                    "open",
                    side_effect=AssertionError("CLI opened private-key path"),
                ),
            ):
                cli.main()
            forwarded = sign.call_args.args[13]
            self.assertIsInstance(forwarded, os.PathLike)
            self.assertEqual(forwarded, paths["private_key"])

    def test_verify_routes_repeated_approvals_and_publishes_authorized_report(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "authorization.json"
            approvals = (paths["approval_a"], paths["approval_b"])
            result = {
                "procurement_authorized": True,
                "decision": "authorized",
            }
            canonical = b'{"exact":"authorization renderer bytes"}\n'
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._verify_arguments(paths, output, approvals=approvals),
                ),
                mock.patch.object(
                    cli,
                    "verify_procurement_authorization",
                    return_value=result,
                ) as verify,
                mock.patch.object(
                    cli,
                    "render_procurement_authorization_report",
                    return_value=canonical,
                ) as render,
                mock.patch.object(
                    cli,
                    "atomic_write_no_clobber",
                    wraps=cli.atomic_write_no_clobber,
                ) as writer,
            ):
                cli.main()
            verify.assert_called_once_with(
                *self._source_call_arguments(paths),
                list(approvals),
                "pcbex",
                "pcbex",
                **self._default_verify_keywords(),
            )
            render.assert_called_once_with(result)
            writer.assert_called_once_with(
                output,
                canonical,
                max_bytes=128 * 1024 * 1024,
            )
            self.assertEqual(output.read_bytes(), canonical)

    def test_sign_output_aliases_sources_private_key_and_command_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            cases = (
                (
                    "direct-source",
                    paths["evidence"],
                    (),
                ),
                (
                    "windows-safe-casefolded-source",
                    paths["evidence"].with_name(paths["evidence"].name.upper()),
                    (),
                ),
                (
                    "policy-pack",
                    paths["policy_pack"],
                    (),
                ),
                (
                    "private-key",
                    paths["private_key"],
                    (),
                ),
                (
                    "path-looking-replay-command",
                    root / "replay-pcbex",
                    ("--pcbex", str(root / "replay-pcbex")),
                ),
                (
                    "path-looking-crypto-command",
                    root / "authorization-pcbex",
                    (
                        "--authorization-pcbex",
                        str(root / "authorization-pcbex"),
                    ),
                ),
            )
            for label, output, extra in cases:
                with (
                    self.subTest(label=label),
                    mock.patch.object(
                        sys,
                        "argv",
                        self._sign_arguments(paths, output, extra=extra),
                    ),
                    mock.patch.object(
                        cli, "sign_procurement_approval"
                    ) as sign,
                    self.assertRaisesRegex(
                        SystemExit,
                        "output must differ from every input path",
                    ),
                ):
                    cli.main()
                sign.assert_not_called()

    def test_verify_output_aliases_an_approval_before_core(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = paths["approval_a"]
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    self._verify_arguments(
                        paths,
                        output,
                        approvals=(output, paths["approval_b"]),
                    ),
                ),
                mock.patch.object(
                    cli, "verify_procurement_authorization"
                ) as verify,
                self.assertRaisesRegex(
                    SystemExit,
                    "output must differ from every input path",
                ),
            ):
                cli.main()
            verify.assert_not_called()

    def test_require_authorized_fails_only_after_exact_report_retention(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "not-authorized.json"
            result = {
                "procurement_authorized": False,
                "decision": "not_authorized",
            }
            canonical = b'{"decision":"not_authorized"}\n'
            argv = self._verify_arguments(
                paths,
                output,
                extra=("--require-authorized",),
            )
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli,
                    "verify_procurement_authorization",
                    return_value=result,
                ),
                mock.patch.object(
                    cli,
                    "render_procurement_authorization_report",
                    return_value=canonical,
                ),
                self.assertRaises(SystemExit) as stopped,
            ):
                cli.main()
            self.assertEqual(
                str(stopped.exception),
                "procurement authorization report was retained but the exact "
                "release was not authorized",
            )
            self.assertEqual(output.read_bytes(), canonical)

    def test_core_failures_are_compact_and_suppress_secret_causes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            cases = (
                (
                    "signing",
                    self._sign_arguments(paths, root / "sign-output.json"),
                    "sign_procurement_approval",
                    "procurement approval signing failed: safe failure",
                ),
                (
                    "verification",
                    self._verify_arguments(paths, root / "verify-output.json"),
                    "verify_procurement_authorization",
                    "procurement authorization verification failed: safe failure",
                ),
            )
            secret = (
                f"PRIVATE-KEY-CONTENTS at {paths['private_key']} "
                "and retained-source-secret"
            )
            for label, argv, target, expected in cases:
                error = cli.ProcurementReleaseAuthorizationError("safe failure")
                error.__cause__ = RuntimeError(secret)
                with (
                    self.subTest(label=label),
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(cli, target, side_effect=error),
                    self.assertRaises(SystemExit) as stopped,
                ):
                    cli.main()
                self.assertEqual(str(stopped.exception), expected)
                self.assertIsNone(stopped.exception.__cause__)
                self.assertTrue(stopped.exception.__suppress_context__)
                rendered_trace = "".join(
                    traceback.TracebackException.from_exception(
                        stopped.exception
                    ).format(chain=True)
                )
                self.assertNotIn(secret, rendered_trace)
                self.assertNotIn(str(paths["private_key"]), rendered_trace)

    def test_publication_failures_do_not_leak_private_or_output_details(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "secret-output-name.json"
            secret = f"private bytes from {paths['private_key']} to {output}"
            with (
                mock.patch.object(
                    sys, "argv", self._sign_arguments(paths, output)
                ),
                mock.patch.object(
                    cli,
                    "sign_procurement_approval",
                    return_value={"decision": "approve"},
                ),
                mock.patch.object(
                    cli,
                    "render_signed_procurement_approval",
                    return_value=b"{}\n",
                ),
                mock.patch.object(
                    cli,
                    "atomic_write_no_clobber",
                    side_effect=OSError(secret),
                ),
                self.assertRaises(SystemExit) as stopped,
            ):
                cli.main()
            self.assertEqual(
                str(stopped.exception),
                "procurement approval signing failed: output publication failed",
            )
            self.assertIsNone(stopped.exception.__cause__)
            rendered_trace = "".join(
                traceback.TracebackException.from_exception(
                    stopped.exception
                ).format(chain=True)
            )
            self.assertNotIn(secret, rendered_trace)
            self.assertNotIn(str(paths["private_key"]), rendered_trace)
            self.assertNotIn(str(output), rendered_trace)

    def test_both_schema_commands_emit_real_sorted_closed_utf8_json(self) -> None:
        schemas = (
            (
                "signed-procurement-approval-schema",
                "https://github.com/penguin425/pcbex/schemas/"
                "signed-procurement-approval-v1.json",
            ),
            (
                "procurement-authorization-report-schema",
                "https://github.com/penguin425/pcbex/schemas/"
                "procurement-authorization-report-v1.json",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            for command, schema_id in schemas:
                stdout = io.StringIO()
                with (
                    self.subTest(command=command, destination="stdout"),
                    mock.patch.object(sys, "argv", ["pcbex-agent", command]),
                    redirect_stdout(stdout),
                ):
                    cli.main()
                schema = json.loads(stdout.getvalue())
                self.assertEqual(schema["$id"], schema_id)
                self.assertIs(schema["additionalProperties"], False)
                expected = (
                    json.dumps(
                        schema,
                        indent=2,
                        sort_keys=True,
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                self.assertEqual(stdout.getvalue(), expected)
                self.assertTrue(stdout.getvalue().endswith("\n"))
                self.assertFalse(stdout.getvalue().endswith("\n\n"))

                output = root / f"{command}.json"
                with (
                    self.subTest(command=command, destination="file"),
                    mock.patch.object(
                        sys,
                        "argv",
                        ["pcbex-agent", command, "--output", str(output)],
                    ),
                ):
                    cli.main()
                self.assertEqual(output.read_bytes(), expected.encode("utf-8"))

    def test_output_race_is_no_clobber_after_signing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "raced.json"
            racer = b"concurrent owner\n"

            def sign(*_args, **_kwargs):
                output.write_bytes(racer)
                return {"decision": "approve"}

            with (
                mock.patch.object(
                    sys, "argv", self._sign_arguments(paths, output)
                ),
                mock.patch.object(
                    cli, "sign_procurement_approval", side_effect=sign
                ),
                mock.patch.object(
                    cli,
                    "render_signed_procurement_approval",
                    return_value=b'{"would":"clobber"}\n',
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "procurement approval signing failed: output publication failed",
                ),
            ):
                cli.main()
            self.assertEqual(output.read_bytes(), racer)

    def test_relative_output_is_frozen_before_verifier_changes_cwd(self) -> None:
        previous_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                root = Path(directory).resolve(strict=True)
                other = root / "other"
                other.mkdir()
                os.chdir(root)
                paths = {
                    name: Path(path.name)
                    for name, path in self._paths(root).items()
                }
                output = Path("authorization.json")

                def verify(*_args, **_kwargs):
                    os.chdir(other)
                    return {
                        "procurement_authorized": True,
                        "decision": "authorized",
                    }

                with (
                    mock.patch.object(
                        sys,
                        "argv",
                        self._verify_arguments(paths, output),
                    ),
                    mock.patch.object(
                        cli,
                        "verify_procurement_authorization",
                        side_effect=verify,
                    ),
                    mock.patch.object(
                        cli,
                        "render_procurement_authorization_report",
                        return_value=b'{"procurement_authorized":true}\n',
                    ),
                ):
                    cli.main()
                self.assertEqual(
                    (root / output).read_bytes(),
                    b'{"procurement_authorized":true}\n',
                )
                self.assertFalse((other / output).exists())
            finally:
                os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()

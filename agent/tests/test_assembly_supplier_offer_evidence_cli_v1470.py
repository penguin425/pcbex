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
import pcbex_agent.assembly_supplier_offer_evidence as evidence_module
from pcbex_agent import cli


class AssemblySupplierOfferEvidenceCliV1470Tests(unittest.TestCase):
    @staticmethod
    def _paths(root: Path) -> dict[str, Path]:
        return {
            "handoff_zip": root / "handoff.zip",
            "board": root / "board.kicad_pcb",
            "manufacturing_zip": root / "manufacturing.zip",
            "board_binding_report": root / "board-binding.json",
            "procurement_intent": root / "procurement-intent.json",
            "catalog_snapshot": root / "catalog.json",
            "final_cpl_report": root / "final-cpl.json",
            "assembly_evidence": root / "assembly-evidence.json",
            "supplier_offer": root / "supplier-offer.json",
            "supplier_offer_fetch_receipt": root / "fetch-receipt.json",
            "supplier_offer_coverage": root / "coverage.json",
        }

    @staticmethod
    def _required_arguments(
        paths: dict[str, Path], output: Path
    ) -> list[str]:
        return [
            "pcbex-agent",
            "build-assembly-supplier-offer-evidence",
            str(paths["handoff_zip"]),
            str(paths["board"]),
            str(paths["manufacturing_zip"]),
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
            "--requested-boards",
            "25",
            "--evaluated-at-unix",
            "1700000000",
            "--output",
            str(output),
        ]

    def test_package_facade_exports_the_frozen_public_surface(self) -> None:
        names = (
            "AssemblySupplierOfferEvidenceError",
            "MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES",
            "evaluate_assembly_supplier_offer_evidence",
            "build_assembly_supplier_offer_evidence",
            "validate_assembly_supplier_offer_evidence",
            "render_assembly_supplier_offer_evidence",
            "assembly_supplier_offer_evidence_json_schema",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertIn(name, pcbex_agent.__all__)
                self.assertIs(
                    getattr(pcbex_agent, name), getattr(evidence_module, name)
                )
        self.assertEqual(
            pcbex_agent.MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
            128 * 1024 * 1024,
        )
        self.assertIs(
            pcbex_agent.build_assembly_supplier_offer_evidence,
            pcbex_agent.evaluate_assembly_supplier_offer_evidence,
        )

    def test_help_exposes_exact_offline_surface_and_mutual_exclusion(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "build-assembly-supplier-offer-evidence",
                    "--help",
                ],
            ),
            redirect_stdout(stdout),
            self.assertRaises(SystemExit) as stopped,
        ):
            cli.main()
        self.assertEqual(stopped.exception.code, 0)
        rendered = stdout.getvalue()
        for expected in (
            "HANDOFF_ZIP",
            "BOARD",
            "MANUFACTURING_ZIP",
            "--board-binding-report REPORT",
            "--procurement-intent INTENT",
            "--catalog-snapshot SNAPSHOT",
            "--final-cpl-report REPORT",
            "--assembly-evidence REPORT",
            "--supplier-offer OFFER",
            "--supplier-offer-fetch-receipt RECEIPT",
            "--supplier-offer-coverage COVERAGE",
            "--requested-boards N",
            "--evaluated-at-unix N",
            "--board-binding-policy POLICY",
            "--manufacturing-kicad-cli CMD",
            "--manufacturing-kicad-project PATH",
            "--manufacturing-kicad-rules PATH",
            "--manufacturing-fab ID",
            "--manufacturing-fab-profile PATH",
            "--manufacturing-physical-profile PATH",
            "--expected-handoff-archive-sha256 HEX",
            "--expected-handoff-bundle-sha256 HEX",
            "--pcbex CMD",
            "--timeout-seconds SECONDS",
            "default: 300.0",
            "-o REPORT, --output REPORT",
            "--require-complete",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, rendered)
        for forbidden in (
            "--endpoint",
            "--bearer-token-environment",
            "--maximum-response-bytes",
            "--allow-insecure-loopback",
            "--fetched-at-unix",
            "--circuit-generation",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)

        schema_stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "assembly-supplier-offer-evidence-schema",
                    "--help",
                ],
            ),
            redirect_stdout(schema_stdout),
            self.assertRaises(SystemExit) as schema_stopped,
        ):
            cli.main()
        self.assertEqual(schema_stopped.exception.code, 0)
        self.assertIn("[-o PATH]", schema_stdout.getvalue())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            argv = [
                *self._required_arguments(paths, root / "output.json"),
                "--manufacturing-fab",
                "fab-a",
                "--manufacturing-fab-profile",
                str(root / "fab.json"),
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli, "evaluate_assembly_supplier_offer_evidence"
                ) as evaluate,
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as conflict,
            ):
                cli.main()
            self.assertEqual(conflict.exception.code, 2)
            evaluate.assert_not_called()

    def test_network_and_unrelated_options_reject_before_evaluator(self) -> None:
        controls = (
            ("--endpoint", "https://offers.example.test"),
            ("--bearer-token-environment", "PCBEX_TOKEN"),
            ("--maximum-response-bytes", "4096"),
            ("--allow-insecure-loopback", None),
            ("--fetched-at-unix", "1700000000"),
            ("--circuit-generation", "generation.json"),
            ("--receipt", "receipt.json"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            for index, (name, value) in enumerate(controls):
                argv = [
                    *self._required_arguments(paths, root / f"output-{index}.json"),
                    name,
                ]
                if value is not None:
                    argv.append(value)
                with (
                    self.subTest(name=name),
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(
                        cli, "evaluate_assembly_supplier_offer_evidence"
                    ) as evaluate,
                    redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as stopped,
                ):
                    cli.main()
                self.assertEqual(stopped.exception.code, 2)
                evaluate.assert_not_called()

    def test_all_options_route_in_exact_order_and_renderer_bytes_are_retained(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "result.json"
            policy = root / "policy.json"
            project = root / "project.kicad_pro"
            rules = root / "rules.kicad_dru"
            physical = root / "physical.json"
            result = {"complete": True, "status": "complete"}
            canonical = b'{"exact":"renderer bytes"}\n'
            argv = [
                *self._required_arguments(paths, output),
                "--board-binding-policy",
                str(policy),
                "--manufacturing-kicad-cli",
                "kicad-cli-custom",
                "--manufacturing-kicad-project",
                str(project),
                "--manufacturing-kicad-rules",
                str(rules),
                "--manufacturing-physical-profile",
                str(physical),
                "--expected-handoff-archive-sha256",
                "a" * 64,
                "--expected-handoff-bundle-sha256",
                "b" * 64,
                "--pcbex",
                "pcbex-custom",
                "--timeout-seconds",
                "17.5",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli,
                    "evaluate_assembly_supplier_offer_evidence",
                    return_value=result,
                ) as evaluate,
                mock.patch.object(
                    cli,
                    "render_assembly_supplier_offer_evidence",
                    return_value=canonical,
                ) as render,
                mock.patch.object(
                    cli,
                    "atomic_write_no_clobber",
                    wraps=cli.atomic_write_no_clobber,
                ) as writer,
                redirect_stdout(io.StringIO()),
            ):
                cli.main()
            evaluate.assert_called_once_with(
                paths["handoff_zip"],
                paths["board"],
                paths["manufacturing_zip"],
                paths["board_binding_report"],
                paths["procurement_intent"],
                paths["catalog_snapshot"],
                paths["final_cpl_report"],
                paths["assembly_evidence"],
                paths["supplier_offer"],
                paths["supplier_offer_fetch_receipt"],
                paths["supplier_offer_coverage"],
                "pcbex-custom",
                requested_boards=25,
                evaluated_at_unix=1700000000,
                board_binding_policy=policy,
                kicad_cli="kicad-cli-custom",
                manufacturing_kicad_project=project,
                manufacturing_kicad_rules=rules,
                manufacturing_fab=None,
                manufacturing_fab_profile=None,
                manufacturing_physical_profile=physical,
                expected_archive_sha256="a" * 64,
                expected_bundle_sha256="b" * 64,
                timeout_seconds=17.5,
            )
            render.assert_called_once_with(result)
            writer.assert_called_once_with(
                output,
                canonical,
                max_bytes=128 * 1024 * 1024,
            )
            self.assertEqual(output.read_bytes(), canonical)

    def test_defaults_and_fab_profile_are_forwarded_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "result.json"
            fab_profile = root / "fab-profile.json"
            result = {"complete": True}
            argv = [
                *self._required_arguments(paths, output),
                "--manufacturing-fab-profile",
                str(fab_profile),
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli,
                    "evaluate_assembly_supplier_offer_evidence",
                    return_value=result,
                ) as evaluate,
                mock.patch.object(
                    cli,
                    "render_assembly_supplier_offer_evidence",
                    return_value=b"{}\n",
                ),
            ):
                cli.main()
            self.assertEqual(evaluate.call_args.args[-1], "pcbex")
            self.assertEqual(
                evaluate.call_args.kwargs,
                {
                    "requested_boards": 25,
                    "evaluated_at_unix": 1700000000,
                    "board_binding_policy": None,
                    "kicad_cli": "kicad-cli",
                    "manufacturing_kicad_project": None,
                    "manufacturing_kicad_rules": None,
                    "manufacturing_fab": None,
                    "manufacturing_fab_profile": fab_profile,
                    "manufacturing_physical_profile": None,
                    "expected_archive_sha256": None,
                    "expected_bundle_sha256": None,
                    "timeout_seconds": 300.0,
                },
            )

    def test_output_aliases_every_path_input_before_evaluator(self) -> None:
        optional_paths = (
            ("--board-binding-policy", "policy.json"),
            ("--manufacturing-kicad-project", "project.kicad_pro"),
            ("--manufacturing-kicad-rules", "rules.kicad_dru"),
            ("--manufacturing-fab-profile", "fab.json"),
            ("--manufacturing-physical-profile", "physical.json"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            for name, output in paths.items():
                with (
                    self.subTest(required=name),
                    mock.patch.object(
                        sys, "argv", self._required_arguments(paths, output)
                    ),
                    mock.patch.object(
                        cli, "evaluate_assembly_supplier_offer_evidence"
                    ) as evaluate,
                    self.assertRaisesRegex(
                        SystemExit, "output must differ from every input path"
                    ),
                ):
                    cli.main()
                evaluate.assert_not_called()
            for option, filename in optional_paths:
                source = root / filename
                argv = [
                    *self._required_arguments(paths, source),
                    option,
                    str(source),
                ]
                with (
                    self.subTest(option=option),
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(
                        cli, "evaluate_assembly_supplier_offer_evidence"
                    ) as evaluate,
                    self.assertRaisesRegex(
                        SystemExit, "output must differ from every input path"
                    ),
                ):
                    cli.main()
                evaluate.assert_not_called()

            lexical_aliases = [
                paths["board"].with_name(paths["board"].name.upper())
            ]
            if os.name != "nt":
                lexical_aliases.append(
                    Path("//" + str(paths["board"]).lstrip("/"))
                )
            for output in lexical_aliases:
                with (
                    self.subTest(lexical_alias=str(output)),
                    mock.patch.object(
                        sys, "argv", self._required_arguments(paths, output)
                    ),
                    mock.patch.object(
                        cli, "evaluate_assembly_supplier_offer_evidence"
                    ) as evaluate,
                    self.assertRaisesRegex(
                        SystemExit, "output must differ from every input path"
                    ),
                ):
                    cli.main()
                evaluate.assert_not_called()

            symlink_output = root / "symlink-target-output.json"
            symlink_board = root / "board-output-link.kicad_pcb"
            try:
                symlink_board.symlink_to(symlink_output)
            except (NotImplementedError, OSError):
                pass
            else:
                linked_paths = {**paths, "board": symlink_board}
                with (
                    mock.patch.object(
                        sys,
                        "argv",
                        self._required_arguments(linked_paths, symlink_output),
                    ),
                    mock.patch.object(
                        cli, "evaluate_assembly_supplier_offer_evidence"
                    ) as evaluate,
                    self.assertRaisesRegex(
                        SystemExit, "output must differ from every input path"
                    ),
                ):
                    cli.main()
                evaluate.assert_not_called()

            occupied = root / "occupied.json"
            occupied.write_bytes(b"owned\n")
            with (
                mock.patch.object(
                    sys, "argv", self._required_arguments(paths, occupied)
                ),
                mock.patch.object(
                    cli, "evaluate_assembly_supplier_offer_evidence"
                ) as evaluate,
                self.assertRaisesRegex(SystemExit, "already exists"),
            ):
                cli.main()
            evaluate.assert_not_called()
            self.assertEqual(occupied.read_bytes(), b"owned\n")

    def test_require_complete_fails_only_after_exact_incomplete_retention(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "incomplete.json"
            result = {"complete": False, "status": "incomplete"}
            canonical = b'{"complete":false,"status":"incomplete"}\n'
            argv = [
                *self._required_arguments(paths, output),
                "--require-complete",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli,
                    "evaluate_assembly_supplier_offer_evidence",
                    return_value=result,
                ),
                mock.patch.object(
                    cli,
                    "render_assembly_supplier_offer_evidence",
                    return_value=canonical,
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "report was retained but evidence is incomplete",
                ),
            ):
                cli.main()
            self.assertEqual(output.read_bytes(), canonical)

    def test_output_race_is_no_clobber_after_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "raced.json"
            racer = b"concurrent owner\n"

            def evaluate(*_args, **_kwargs):
                output.write_bytes(racer)
                return {"complete": True, "status": "complete"}

            with (
                mock.patch.object(
                    sys, "argv", self._required_arguments(paths, output)
                ),
                mock.patch.object(
                    cli,
                    "evaluate_assembly_supplier_offer_evidence",
                    side_effect=evaluate,
                ),
                mock.patch.object(
                    cli,
                    "render_assembly_supplier_offer_evidence",
                    return_value=b'{"would":"clobber"}\n',
                ),
                self.assertRaisesRegex(SystemExit, "already exists"),
            ):
                cli.main()
            self.assertEqual(output.read_bytes(), racer)

    def test_relative_output_is_frozen_before_evaluator_changes_cwd(self) -> None:
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
                output = Path("result.json")

                def evaluate(*_args, **_kwargs):
                    os.chdir(other)
                    return {"complete": True, "status": "complete"}

                with (
                    mock.patch.object(
                        sys, "argv", self._required_arguments(paths, output)
                    ),
                    mock.patch.object(
                        cli,
                        "evaluate_assembly_supplier_offer_evidence",
                        side_effect=evaluate,
                    ),
                    mock.patch.object(
                        cli,
                        "render_assembly_supplier_offer_evidence",
                        return_value=b'{"complete":true}\n',
                    ),
                ):
                    cli.main()
                self.assertEqual(
                    (root / output).read_bytes(), b'{"complete":true}\n'
                )
                self.assertFalse((other / output).exists())
            finally:
                os.chdir(previous_cwd)

    def test_core_failure_is_compact_and_retains_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            paths = self._paths(root)
            output = root / "result.json"
            secret = "retained-body-or-source-path-secret"
            error = cli.AssemblySupplierOfferEvidenceError("fresh replay failed")
            error.__cause__ = RuntimeError(secret)
            with (
                mock.patch.object(
                    sys, "argv", self._required_arguments(paths, output)
                ),
                mock.patch.object(
                    cli,
                    "evaluate_assembly_supplier_offer_evidence",
                    side_effect=error,
                ),
                self.assertRaises(SystemExit) as stopped,
            ):
                cli.main()
            self.assertEqual(
                str(stopped.exception),
                "assembly supplier-offer evidence evaluation failed: fresh replay "
                "failed",
            )
            trace = "".join(
                traceback.TracebackException.from_exception(
                    stopped.exception
                ).format(chain=True)
            )
            self.assertNotIn(secret, trace)
            self.assertFalse(output.exists())

    def test_schema_stdout_file_and_no_clobber_are_exact(self) -> None:
        frozen_schema_id = (
            "https://github.com/penguin425/pcbex/schemas/"
            "offline-exact-board-assembly-supplier-offer-evidence-v1.json"
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", "assembly-supplier-offer-evidence-schema"],
            ),
            redirect_stdout(stdout),
        ):
            cli.main()
        schema = json.loads(stdout.getvalue())
        self.assertEqual(schema["$id"], frozen_schema_id)
        self.assertFalse(schema["additionalProperties"])
        expected = json.dumps(schema, indent=2, ensure_ascii=False) + "\n"
        self.assertEqual(stdout.getvalue(), expected)
        self.assertTrue(stdout.getvalue().endswith("\n"))
        self.assertFalse(stdout.getvalue().endswith("\n\n"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            output = root / "schema.json"
            argv = [
                "pcbex-agent",
                "assembly-supplier-offer-evidence-schema",
                "-o",
                str(output),
            ]
            with mock.patch.object(sys, "argv", argv):
                cli.main()
            self.assertEqual(output.read_text(encoding="utf-8"), expected)
            retained = output.read_bytes()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    cli, "assembly_supplier_offer_evidence_json_schema"
                ) as build_schema,
                self.assertRaisesRegex(SystemExit, "already exists"),
            ):
                cli.main()
            build_schema.assert_not_called()
            self.assertEqual(output.read_bytes(), retained)


if __name__ == "__main__":
    unittest.main()

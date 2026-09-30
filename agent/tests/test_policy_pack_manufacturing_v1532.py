from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional for minimal installs
    Draft202012Validator = None

from pcbex_agent import cli
from pcbex_agent import manufacturing_replay as replay_module
from pcbex_agent import routing_manufacturing_handoff as handoff_module
from pcbex_agent.manufacturing_replay import (
    ManufacturingReplayError,
    manufacturing_package_replay_result_json_schema,
    replay_manufacturing_package,
)
from pcbex_agent.routing_manufacturing_handoff import (
    RoutingManufacturingHandoffError,
    evaluate_routing_manufacturing_handoff,
    render_routing_manufacturing_handoff_report,
    routing_manufacturing_handoff_report_json_schema,
)
from agent.tests import test_routing_manufacturing_handoff_v1476 as legacy_handoff


def _identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": replay_module._sha256(raw)}


class PolicyPackManufacturingV1532Tests(unittest.TestCase):
    def _fake_pcbex(
        self,
        root: Path,
        package: bytes,
        *,
        verification: bytes = b"unused",
        mutation: Path | None = None,
        mutate_stage: bool = False,
    ) -> list[str]:
        (root / "package.bin").write_bytes(package)
        (root / "verification.bin").write_bytes(verification)
        (root / "config.json").write_text(
            json.dumps({
                "mutation": None if mutation is None else str(mutation),
                "mutate_stage": mutate_stage,
            }),
            encoding="utf-8",
        )
        script = root / "fake-pcbex.py"
        script.write_text(
            '''import json, sys
from pathlib import Path
root = Path(__file__).parent
argv = sys.argv[1:]
config = json.loads((root / "config.json").read_text())
def option(name):
    prefix = "--" + name + "="
    for index, value in enumerate(argv):
        if value.startswith(prefix):
            return value[len(prefix):]
        if value == "--" + name:
            return argv[index + 1]
    return None
pack = Path(option("policy-pack"))
calls_path = root / "calls.json"
calls = json.loads(calls_path.read_text()) if calls_path.exists() else []
calls.append({"argv": argv, "pack_name": pack.name,
              "pack_parent": pack.parent.name, "pack_raw": pack.read_bytes().hex()})
calls_path.write_text(json.dumps(calls))
if argv[0] == "verify-kicad-routing-convergence":
    Path(option("output")).write_bytes((root / "verification.bin").read_bytes())
elif argv[0] == "fabricate":
    output = Path(option("output-dir"))
    output.mkdir()
    (output / "manufacturing.zip").write_bytes((root / "package.bin").read_bytes())
else:
    raise SystemExit(91)
if config["mutate_stage"]:
    pack.write_bytes(pack.read_bytes() + b"changed")
if config["mutation"]:
    changed = Path(config["mutation"])
    changed.write_bytes(changed.read_bytes() + b"changed")
''',
            encoding="utf-8",
        )
        return [sys.executable, str(script)]

    def _policy_sources(self, root: Path) -> dict[str, object]:
        sources = legacy_handoff.RoutingManufacturingHandoffTests()._sources(root)
        policy = root / "original policy pack.json"
        policy_raw = b'{"fixture":"policy-pack"}\n'
        policy.write_bytes(policy_raw)
        verification = json.loads(sources["verification_raw"])
        # The shared legacy fixture selects an external DFM; this case selects
        # a policy pack instead, never both selectors at once.
        verification["sources"]["fab_profile"] = None
        verification["sources"]["policy_pack"] = _identity(policy_raw)
        verification["binding_sha256"] = handoff_module._routing_binding(verification)
        verification_raw = (json.dumps(verification, indent=2) + "\n").encode()
        sources["verification"].write_bytes(verification_raw)
        sources.update(policy=policy, policy_raw=policy_raw,
                       verification_raw=verification_raw)
        return sources

    def _evaluate(self, sources, command):
        return evaluate_routing_manufacturing_handoff(
            sources["input"], sources["routed"], sources["convergence"],
            sources["verification"], sources["package"], command,
            kicad_project=sources["project"], kicad_rules=sources["rules"],
            analysis_policy_pack=sources["policy"],
        )

    def test_policy_pack_fresh_replay_forwards_staged_original_basename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._policy_sources(root)
            result = replay_manufacturing_package(
                sources["routed"], sources["package"],
                self._fake_pcbex(root, sources["package_raw"]),
                policy_pack=sources["policy"],
            )
            self.assertEqual(result["profile"], {
                "kind": "policy-pack",
                "source": {"name": sources["policy"].name,
                           **_identity(sources["policy_raw"])},
            })
            observation = json.loads((root / "calls.json").read_text())[0]
            self.assertEqual(observation["pack_name"], sources["policy"].name)
            self.assertEqual(observation["pack_parent"], "profile-input")
            self.assertEqual(observation["pack_raw"], sources["policy_raw"].hex())
            self.assertTrue(any(arg.startswith("--policy-pack=")
                                for arg in observation["argv"]))
            if Draft202012Validator is not None:
                Draft202012Validator(
                    manufacturing_package_replay_result_json_schema()
                ).validate(result)

    def test_manufacturing_schema_contains_closed_policy_pack_variant(self):
        variants = manufacturing_package_replay_result_json_schema()[
            "properties"]["profile"]["oneOf"]
        policy = next(value for value in variants
                      if value["properties"]["kind"].get("const") == "policy-pack")
        self.assertFalse(policy["additionalProperties"])
        self.assertEqual(policy["properties"]["source"]["properties"]["bytes"][
            "maximum"], 64 * 1024 * 1024)

    def test_handoff_schema_exposes_only_optional_nonnull_outer_pack(self):
        schema = routing_manufacturing_handoff_report_json_schema()
        sources = schema["properties"]["sources"]
        self.assertIn("analysis_policy_pack", sources["properties"])
        self.assertNotIn("analysis_policy_pack", sources["required"])
        self.assertEqual(sources["properties"]["analysis_policy_pack"]["type"],
                         "object")
        nested = schema["properties"]["routing_verification"]["properties"]["sources"]
        self.assertNotIn("analysis_policy_pack", nested["properties"])
        self.assertIn("anyOf", nested["properties"]["policy_pack"])

    def test_manufacturing_profile_selection_is_exclusive(self):
        with self.assertRaisesRegex(ManufacturingReplayError, "mutually exclusive"):
            replay_manufacturing_package(
                "missing.kicad_pcb", "missing.zip", "pcbex",
                policy_pack="policy.json", physical_profile="physical.json",
            )

    def test_capture_preserves_policy_pack_raw_identity_and_basename(self):
        with tempfile.TemporaryDirectory() as directory:
            sources = self._policy_sources(Path(directory).resolve(strict=True))
            capture = replay_module._capture_manufacturing_replay_inputs(
                sources["routed"], sources["package"], kicad_project=None,
                kicad_rules=None, fab=None, fab_profile=None,
                policy_pack=sources["policy"], physical_profile=None,
                deadline=time.monotonic() + 10, clock=time.monotonic,
            )
            self.assertEqual(capture.policy_pack_name, sources["policy"].name)
            self.assertEqual(capture.policy_pack_raw, sources["policy_raw"])
            self.assertEqual(capture.policy_pack_identity, _identity(sources["policy_raw"]))

    def test_handoff_policy_pack_primary_replays_both_phases_from_same_raw(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._policy_sources(root)
            result = self._evaluate(sources, self._fake_pcbex(
                root, sources["package_raw"], verification=sources["verification_raw"],
            ))
            self.assertTrue(result["ready"])
            expected = _identity(sources["policy_raw"])
            self.assertEqual(result["sources"]["analysis_policy_pack"], expected)
            self.assertEqual(result["routing_verification"]["sources"]["policy_pack"], expected)
            self.assertEqual(result["manufacturing_replay"]["profile"]["source"],
                             {"name": sources["policy"].name, **expected})
            observations = json.loads((root / "calls.json").read_text())
            self.assertEqual([call["argv"][0] for call in observations],
                             ["verify-kicad-routing-convergence", "fabricate"])
            self.assertEqual([call["pack_raw"] for call in observations],
                             [sources["policy_raw"].hex()] * 2)
            render_routing_manufacturing_handoff_report(result)
            if Draft202012Validator is not None:
                Draft202012Validator(
                    routing_manufacturing_handoff_report_json_schema()
                ).validate(result)

    def test_report_renderer_rejects_rebound_cross_phase_and_selector_forgery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._policy_sources(root)
            result = self._evaluate(sources, self._fake_pcbex(
                root, sources["package_raw"], verification=sources["verification_raw"],
            ))
            for mutation in ("routing", "manufacturing", "missing", "builtin", "null"):
                with self.subTest(mutation=mutation):
                    changed = deepcopy(result)
                    if mutation == "routing":
                        changed["routing_verification"]["sources"]["policy_pack"]["sha256"] = "a" * 64
                    elif mutation == "manufacturing":
                        changed["manufacturing_replay"]["profile"]["source"]["sha256"] = "a" * 64
                    elif mutation == "missing":
                        changed["sources"].pop("analysis_policy_pack")
                    elif mutation == "builtin":
                        changed["routing_verification"]["built_in_dfm_profile"] = "jlcpcb-2layer"
                        changed["manufacturing_replay"]["profile"] = {
                            "kind": "builtin", "id": "jlcpcb-2layer"}
                    else:
                        changed["sources"]["analysis_policy_pack"] = None
                    changed["binding_sha256"] = handoff_module._handoff_binding(changed)
                    with self.assertRaises(RoutingManufacturingHandoffError):
                        render_routing_manufacturing_handoff_report(changed)

    def test_policy_pack_stage_and_caller_mutation_are_rejected(self):
        for mutation in ("stage", "caller"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                sources = self._policy_sources(root)
                command = self._fake_pcbex(
                    root, sources["package_raw"], mutate_stage=mutation == "stage",
                    mutation=sources["policy"] if mutation == "caller" else None,
                )
                with self.assertRaises(ManufacturingReplayError):
                    replay_manufacturing_package(
                        sources["routed"], sources["package"], command,
                        policy_pack=sources["policy"],
                    )

    def test_cli_forwards_policy_pack_and_enforces_selector_exclusion(self):
        argv = ["pcbex-agent", "replay-manufacturing-package", "board.kicad_pcb",
                "package.zip", "--policy-pack", "organization.json"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            cli, "replay_manufacturing_package", return_value={}
        ) as replay, redirect_stdout(io.StringIO()):
            cli.main()
        self.assertEqual(replay.call_args.kwargs["policy_pack"], Path("organization.json"))
        with mock.patch.object(sys, "argv", argv + ["--fab", "jlcpcb-2layer"]), \
             redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as rejected:
            cli.main()
        self.assertEqual(rejected.exception.code, 2)

    def test_cli_forwards_analysis_pack_and_preflights_output_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources = self._policy_sources(root)
            result = self._evaluate(sources, self._fake_pcbex(
                root, sources["package_raw"], verification=sources["verification_raw"],
            ))
            output = root / "handoff.json"
            argv = ["pcbex-agent", "replay-routing-manufacturing-handoff",
                    str(sources["input"]), str(sources["routed"]),
                    "--convergence-report", str(sources["convergence"]),
                    "--routing-verification-report", str(sources["verification"]),
                    "--manufacturing-package", str(sources["package"]),
                    "--analysis-policy-pack", str(sources["policy"]),
                    "--output", str(output)]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                cli, "evaluate_routing_manufacturing_handoff", return_value=result
            ) as evaluate:
                cli.main()
            self.assertEqual(evaluate.call_args.kwargs["analysis_policy_pack"], sources["policy"])
            self.assertEqual(output.read_bytes(), render_routing_manufacturing_handoff_report(result))
            with mock.patch.object(sys, "argv", argv[:-1] + [str(sources["policy"])]), \
                 mock.patch.object(cli, "evaluate_routing_manufacturing_handoff") as evaluate, \
                 self.assertRaises(SystemExit):
                cli.main()
            evaluate.assert_not_called()
            with mock.patch.object(sys, "argv", argv + ["--fab", "jlcpcb-2layer"]), \
                 redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as rejected:
                cli.main()
            self.assertEqual(rejected.exception.code, 2)


if __name__ == "__main__":
    unittest.main()

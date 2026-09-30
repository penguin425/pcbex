from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

try:
    from agent.tests import test_routing_drc_manufacturing_handoff_v1477 as legacy
    from agent.tests import test_routing_drc_fabrication_release_v1478 as release_legacy
except ImportError:
    import test_routing_drc_manufacturing_handoff_v1477 as legacy
    import test_routing_drc_fabrication_release_v1478 as release_legacy

from pcbex_agent import cli
from pcbex_agent import routing_drc_manufacturing_handoff as module
from pcbex_agent import routing_manufacturing_handoff as primary
from pcbex_agent import routing_drc_fabrication_release as release

from pcbex_agent.routing_drc_manufacturing_handoff import (
    RoutingDrcManufacturingHandoffError,
    evaluate_routing_drc_manufacturing_handoff,
    routing_drc_manufacturing_handoff_report_json_schema,
)


class PolicyPackDrcHandoffV1532Tests(unittest.TestCase):
    def _prepare(self, root, *, mutate=False, pack_name="organization-policy.json", pack_raw=None):
        sources = legacy.RoutingDrcManufacturingHandoffTests()._sources(root)
        pack = root / pack_name
        if pack_raw is None:
            pack_raw = b'{"schema_version":1,"id":"selected-policy"}\n'
        pack.write_bytes(pack_raw)
        report = json.loads(sources["verification_raw"])
        report["sources"]["fab_profile"] = None
        report["sources"]["policy_pack"] = legacy._identity(pack_raw)
        report["binding_sha256"] = primary._routing_binding(report)
        fresh_raw = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode()
        sources["verification"].write_bytes(fresh_raw)
        command = legacy._write_fake_pcbex(
            root, package_raw=sources["package_raw"],
            fresh_verification_raw=fresh_raw, mutate=pack if mutate else None,
        )
        wrapper = Path(command[1])
        wrapper.write_text(wrapper.read_text().replace(
            "calls.append(argv)",
            "calls.append(argv)\nfor argument in argv:\n"
            "    if argument.startswith('--policy-pack='):\n"
            f"        assert Path(argument.split('=', 1)[1]).read_bytes() == {pack_raw!r}",
        ))
        handoff = primary.evaluate_routing_manufacturing_handoff(
            sources["input"], sources["routed"], sources["convergence"],
            sources["verification"], sources["package"], command,
            kicad_project=sources["project"], kicad_rules=sources["rules"],
            analysis_policy_pack=pack,
        )
        sources["handoff"].write_bytes(primary.render_routing_manufacturing_handoff_report(handoff))
        sources["pack"] = pack
        return sources, command

    def _evaluate(self, sources, command):
        return evaluate_routing_drc_manufacturing_handoff(
            sources["input"], sources["routed"], sources["convergence"],
            sources["verification"], sources["package"], sources["handoff"],
            sources["native_drc"], command, kicad_project=sources["project"],
            kicad_rules=sources["rules"], analysis_policy_pack=sources["pack"],
        )

    def test_pack_positive_replays_both_phases_and_native_drc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sources, command = self._prepare(root)
            result = self._evaluate(sources, command)
            self.assertTrue(result["ready"])
            identity = legacy._identity(sources["pack"].read_bytes())
            self.assertEqual(result["sources"]["analysis_policy_pack"], identity)
            self.assertEqual(result["routing_manufacturing_handoff"]["sources"]["analysis_policy_pack"], identity)
            calls = json.loads((root / "calls.json").read_bytes())
            selected = [argument for call in calls for argument in call if argument.startswith("--policy-pack=")]
            self.assertEqual(len(selected), 4)
            manufacture_selected = [
                argument for call in calls if call[0] == "fabricate"
                for argument in call if argument.startswith("--policy-pack=")
            ]
            self.assertEqual(len(manufacture_selected), 2)
            self.assertTrue(all(Path(argument.split("=", 1)[1]).name == sources["pack"].name for argument in manufacture_selected))
            if legacy.Draft202012Validator is not None:
                legacy.Draft202012Validator(routing_drc_manufacturing_handoff_report_json_schema()).validate(result)

    def test_projection_pack_substitution_and_omission_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            sources, command = self._prepare(Path(directory).resolve())
            result = self._evaluate(sources, command)
            for mutation in ("outer", "projection", "omission", "null", "builtin"):
                with self.subTest(mutation=mutation):
                    changed = deepcopy(result)
                    if mutation == "outer":
                        changed["sources"]["analysis_policy_pack"]["sha256"] = "0" * 64
                    elif mutation == "projection":
                        changed["routing_manufacturing_handoff"]["sources"]["analysis_policy_pack"]["sha256"] = "0" * 64
                    elif mutation == "omission":
                        del changed["routing_manufacturing_handoff"]["sources"]["analysis_policy_pack"]
                    elif mutation == "null":
                        changed["sources"]["analysis_policy_pack"] = None
                    else:
                        changed["routing_manufacturing_handoff"]["built_in_dfm_profile"] = "jlcpcb"
                    changed["binding_sha256"] = module._binding(changed)
                    with self.assertRaises(RoutingDrcManufacturingHandoffError):
                        module.render_routing_drc_manufacturing_handoff_report(changed)

    def test_native_child_caller_pack_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            sources, command = self._prepare(Path(directory).resolve(), mutate=True)
            with self.assertRaises(RoutingDrcManufacturingHandoffError):
                self._evaluate(sources, command)

    def test_cli_pack_selection_and_output_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            sources, command = self._prepare(Path(directory).resolve())
            with mock.patch("sys.argv", [
                    "pcbex-agent",
                    "replay-routing-drc-manufacturing-handoff", str(sources["input"]), str(sources["routed"]),
                    "--convergence-report", str(sources["convergence"]),
                    "--routing-verification-report", str(sources["verification"]),
                    "--manufacturing-package", str(sources["package"]),
                    "--routing-manufacturing-handoff-report", str(sources["handoff"]),
                    "--native-drc-report", str(sources["native_drc"]),
                    "--analysis-policy-pack", str(sources["pack"]),
                    "--output", str(sources["pack"]),
                ]), self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(sources["pack"].read_bytes(), b'{"schema_version":1,"id":"selected-policy"}\n')

    def test_schema_exposes_optional_nonnull_analysis_policy_pack(self):
        schema = routing_drc_manufacturing_handoff_report_json_schema()
        sources = schema["properties"]["sources"]
        self.assertIn("analysis_policy_pack", sources["properties"])
        self.assertNotIn("analysis_policy_pack", sources["required"])
        self.assertEqual(
            sources["properties"]["analysis_policy_pack"]["type"], "object"
        )

    def test_analysis_policy_pack_is_mutually_exclusive_with_other_profiles(self):
        with self.assertRaisesRegex(RoutingDrcManufacturingHandoffError, "mutually exclusive"):
            evaluate_routing_drc_manufacturing_handoff(
                "input", "routed", "convergence", "verification", "package",
                "handoff", "drc", fab="builtin", analysis_policy_pack="policy",
            )

    def _prepare_release(self, root):
        sources, command = self._prepare(
            root, pack_name="policy.json",
            pack_raw=b'{"id":"fixture-policy","revision":1}\n',
        )
        drc = self._evaluate(sources, command)
        retained = root / "routing-drc.json"
        retained.write_bytes(module.render_routing_drc_manufacturing_handoff_report(drc))
        sources["release"] = retained
        sources.update(release_legacy.RoutingDrcFabricationReleaseTests()._pipeline(root, sources["package_raw"]))
        authorization = release_legacy._write_fake_authorization(
            root, canonical_policy_digest="e" * 64, authorized=True,
        )
        return sources, command, authorization

    def _evaluate_release(self, sources, command, authorization, **extra):
        return release.evaluate_routing_drc_fabrication_release(
            sources["input"], sources["routed"], sources["convergence"],
            sources["verification"], sources["package"], sources["handoff"],
            sources["native_drc"], sources["release"], sources["plan"],
            sources["report"], sources["approvals"], "e" * 64, command, authorization,
            kicad_project=sources["project"], kicad_rules=sources["rules"], **extra,
        )

    def test_release_replays_explicit_retained_pack_from_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            sources, command, authorization = self._prepare_release(Path(directory).resolve())
            result = self._evaluate_release(sources, command, authorization)
            self.assertTrue(result["release_authorized"])
            if release_legacy.Draft202012Validator is not None:
                release_legacy.Draft202012Validator(release.routing_drc_fabrication_release_report_json_schema()).validate(result)

    def test_release_rejects_pack_identity_and_selector_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sources, command, authorization = self._prepare_release(root)
            with self.assertRaisesRegex(release.RoutingDrcFabricationReleaseError, "mutually exclusive"):
                self._evaluate_release(sources, command, authorization, fab_profile=sources["profile"])
            plan = json.loads(sources["plan"].read_bytes())
            pack_path = sources["plan"].parent / plan["analysis_policy_pack"]["path"]
            changed = pack_path.read_bytes() + b" "
            pack_path.write_bytes(changed)
            plan["analysis_policy_pack"].update(legacy._identity(changed))
            sources["plan"].write_bytes((json.dumps(plan, separators=(",", ":")) + "\n").encode())
            with self.assertRaisesRegex(release.RoutingDrcFabricationReleaseError, "routing policy pack"):
                self._evaluate_release(sources, command, authorization)

    def test_release_rejects_same_pack_bytes_with_rebound_basename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sources, command, authorization = self._prepare_release(root)
            plan = json.loads(sources["plan"].read_bytes())
            original = sources["plan"].parent / plan["analysis_policy_pack"]["path"]
            rebound = original.with_name("rebound-policy.json")
            rebound.write_bytes(original.read_bytes())
            plan["analysis_policy_pack"]["path"] = rebound.name
            sources["plan"].write_bytes((json.dumps(plan, separators=(",", ":")) + "\n").encode())
            with self.assertRaisesRegex(release.RoutingDrcFabricationReleaseError, "replay failed"):
                self._evaluate_release(sources, command, authorization)


if __name__ == "__main__":
    unittest.main()

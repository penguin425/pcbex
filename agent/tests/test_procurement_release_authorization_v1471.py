from __future__ import annotations

from collections.abc import Iterator, Mapping
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent.tests.test_assembly_supplier_offer_evidence_v1470 import (
    _arguments as _v1470_arguments,
    _evaluate as _evaluate_v1470,
    _fixture as _v1470_fixture,
)
from pcbex_agent.bounded_process import BoundedProcessResult
import pcbex_agent.procurement_release_authorization as module

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - schema tests remain useful without it
    Draft202012Validator = None


class _OnePassMapping(Mapping[str, object]):
    def __init__(self, value: Mapping[str, object]) -> None:
        self.value = value
        self.calls = 0

    def __getitem__(self, key: str) -> object:
        raise AssertionError("must snapshot through items")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("must snapshot through items")

    def __len__(self) -> int:
        return len(self.value)

    def items(self):  # type: ignore[override]
        self.calls += 1
        if self.calls != 1:
            raise AssertionError("mapping traversed more than once")
        return self.value.items()


class _BytesWithPath(bytes):
    def __fspath__(self) -> str:
        raise AssertionError("bytes must win over PathLike")


class _HookMapping(_OnePassMapping):
    def __init__(self, value: Mapping[str, object], hook) -> None:
        super().__init__(value)
        self.hook = hook

    def items(self):  # type: ignore[override]
        self.hook()
        return super().items()


class _OneShotPath(os.PathLike[str]):
    def __init__(self, path: Path, hook=None) -> None:
        self.path = path
        self.hook = hook
        self.calls = 0

    def __fspath__(self) -> str:
        self.calls += 1
        if self.calls != 1:
            raise RuntimeError("PathLike converted more than once")
        if self.hook is not None:
            self.hook()
        return str(self.path)


class _HostileClass:
    def __init__(self, target: Path, pretend) -> None:
        self.target = target
        self.pretend = pretend
        self.calls = 0

    @property
    def __class__(self):  # type: ignore[override]
        self.calls += 1
        os.chdir(self.target)
        return self.pretend


class _InvalidatingPath(os.PathLike[str]):
    def __init__(self, parent: Path) -> None:
        self.parent = parent
        self.calls = 0

    def __fspath__(self):
        self.calls += 1
        doomed = self.parent / f"deleted-cwd-{self.calls}"
        doomed.mkdir()
        os.chdir(doomed)
        os.rmdir(doomed)
        return object()


class ProcurementReleaseAuthorizationV1471Tests(unittest.TestCase):
    def _case(self, root: Path):
        fixture = _v1470_fixture(root)
        evidence, _count = _evaluate_v1470(fixture)
        evidence_path = root / "assembly-supplier-offer-evidence.json"
        evidence_path.write_bytes(
            module._v1470.render_assembly_supplier_offer_evidence(evidence)
        )
        policy = json.loads(Path("examples/acme-policy-pack.json").read_text())
        policy["procurement_authorization_policy"] = {
            "minimum_approvals": 2,
            "currency": "USD",
            "maximum_validity_seconds": 3600,
            "maximum_receipt_observation_age_seconds": 300,
            "maximum_component_subtotal_micros": 10_000,
            "trusted_keys": [
                {"signer_id": "procurement-a", "public_key": "a" * 64},
                {"signer_id": "procurement-b", "public_key": "b" * 64},
            ],
        }
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        private = root / "private.key"
        private.write_text("not-opened-by-python", encoding="utf-8")
        return fixture, evidence, evidence_path, policy, policy_path, private

    @staticmethod
    def _approval(evidence, scope, signer="procurement-a", decision="approve"):
        key = "a" * 64 if signer == "procurement-a" else "b" * 64
        return {
            "schema_version": 1,
            "scope": module.SIGNED_PROCUREMENT_APPROVAL_SCOPE,
            "evidence": copy.deepcopy(evidence),
            "authorization_scope": copy.deepcopy(scope),
            "decision": decision,
            "reason": "Exact release reviewed.",
            "ticket": "HW-1471",
            "signer_id": signer,
            "algorithm": "ed25519",
            "public_key": key,
            "signature": ("c" if signer == "procurement-a" else "d") * 128,
        }

    @staticmethod
    def _assessment(request, policy, approvals, evaluated):
        signed = sorted(approvals, key=lambda item: item["signer_id"])
        members = [
            {
                "signer_id": item["signer_id"],
                "public_key": item["public_key"],
                "approval_sha256": module._sha256(module._approval_compact(item)),
                "decision": item["decision"],
                "reason": item["reason"],
                "ticket": item["ticket"],
            }
            for item in signed
        ]
        approves = sum(item["decision"] == "approve" for item in signed)
        rejects = len(signed) - approves
        failures = module._expected_gate_failures(
            request["evidence"], request["authorization_scope"], policy,
            approves, rejects, evaluated,
        )
        result = {
            "schema_version": 1,
            "scope": module.PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCOPE,
            "status": "policy_satisfied" if not failures else "not_satisfied",
            "policy_satisfied": not failures,
            "evidence": request["evidence"],
            "authorization_scope": request["authorization_scope"],
            "policy_pack": module._ordered_policy_pack(policy),
            "evaluated_at_unix": evaluated,
            "approvals": approves,
            "rejections": rejects,
            "members": members,
            "signed_approvals": signed,
            "gate_failures": failures,
            "validation": {key: True for key in module._ASSESSMENT_VALIDATION_KEYS},
        }
        result["binding_sha256"] = module._sha256(
            module.PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BINDING_DOMAIN
            + module._compact(result)
        )
        return result

    @staticmethod
    def _common_kwargs():
        return {
            "requested_boards": 3,
            "evaluated_at_unix": 100,
            "expected_policy_pack_canonical_sha256": "e" * 64,
        }

    @staticmethod
    def _sign_arguments(
        fixture, evidence, policy, private, *, replay_command=None,
        authorization_command=None,
    ):
        inherited = _v1470_arguments(fixture)
        return (
            evidence, *inherited[:11], policy, private,
            inherited[11] if replay_command is None else replay_command,
            ["authorization-pcbex"]
            if authorization_command is None else authorization_command,
        )

    @staticmethod
    def _evaluation_arguments(
        fixture, evidence, policy, approvals, *, replay_command=None,
        authorization_command=None,
    ):
        inherited = _v1470_arguments(fixture)
        return (
            evidence, *inherited[:11], policy, approvals,
            inherited[11] if replay_command is None else replay_command,
            ["authorization-pcbex"]
            if authorization_command is None else authorization_command,
        )

    def _authorization_material(
        self, evidence, evidence_raw, policy, policy_raw, *, evaluated=120,
    ):
        projection, _pack = module._extract_request_evidence(
            evidence, evidence_raw, policy_raw, "e" * 64
        )
        scope = module._authorization_scope(
            projection["commercial"], authorization_id="release-1471",
            challenge="f" * 64, maximum_component_subtotal_micros=1000,
            valid_from_unix=100, expires_at_unix=150,
        )
        approvals = [
            self._approval(projection, scope, "procurement-a"),
            self._approval(projection, scope, "procurement-b"),
        ]
        request = module._request(projection, scope)
        assessment = self._assessment(request, policy, approvals, evaluated)
        report = module._normalize_report(module._compose_report(assessment))
        return projection, scope, approvals, request, assessment, report

    def _sign_kwargs(self):
        return {
            **self._common_kwargs(),
            "signer_id": "procurement-a",
            "decision": "approve",
            "authorization_id": "release-1471",
            "challenge": "f" * 64,
            "maximum_component_subtotal_micros": 1000,
            "valid_from_unix": 100,
            "expires_at_unix": 150,
            "reason": "Exact release reviewed.",
            "ticket": "HW-1471",
        }

    def test_request_vector_and_sign_calls_exact_replay_twice_without_reading_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, _policy, policy_path, private = self._case(root)
            original_open = open
            original_read_bytes = module.read_bytes
            observed = []

            def guarded_open(file, *args, **kwargs):
                self.assertNotEqual(os.fspath(file), str(private))
                return original_open(file, *args, **kwargs)

            def guarded_read_bytes(path, *args, **kwargs):
                self.assertNotEqual(os.fspath(path), str(private))
                return original_read_bytes(path, *args, **kwargs)

            def child(argv, **kwargs):
                observed.append(list(argv))
                request = json.loads(Path(argv[2]).read_text())
                payload = {key: request[key] for key in module._REQUEST_KEYS[:-1]}
                self.assertEqual(
                    request["binding_sha256"],
                    module._sha256(
                        module.PROCUREMENT_RELEASE_REQUEST_BINDING_DOMAIN
                        + module._compact(payload)
                    ),
                )
                option = lambda name: argv[argv.index(name) + 1]
                approval = self._approval(
                    request["evidence"], request["authorization_scope"]
                )
                Path(option("--output")).write_bytes(
                    # Public, path-free approval fixture; it contains no private-key bytes.
                    module.render_signed_procurement_approval(approval)  # lgtm[py/clear-text-storage-sensitive-data]
                )
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            args = (
                evidence_path, *_v1470_arguments(fixture)[:11], policy_path,
                private, _v1470_arguments(fixture)[11], ["authorization-pcbex"],
            )
            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    return_value=copy.deepcopy(evidence),
                ) as replay,
                mock.patch.object(module, "run_bounded", side_effect=child),
                mock.patch.object(module, "read_bytes", side_effect=guarded_read_bytes),
                mock.patch("builtins.open", side_effect=guarded_open),
                mock.patch.object(
                    module, "_freeze_private_key", wraps=module._freeze_private_key,
                ) as freeze_key,
            ):
                result = module.sign_procurement_approval(
                    *args, requested_boards=3, evaluated_at_unix=100,
                    expected_policy_pack_canonical_sha256="e" * 64,
                    signer_id="procurement-a", decision="approve",
                    authorization_id="release-1471", challenge="f" * 64,
                    maximum_component_subtotal_micros=1000,
                    valid_from_unix=100, expires_at_unix=150,
                    reason="Exact release reviewed.", ticket="HW-1471",
                )
            self.assertEqual(result["decision"], "approve")
            self.assertEqual(replay.call_count, 2)
            self.assertEqual(freeze_key.call_count, 1)
            self.assertEqual(observed[0][1], "internal-sign-procurement-approval")
            self.assertIn(str(private), observed[0])

    def test_evaluate_projects_assessment_only_after_second_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, _private = self._case(root)
            projection, _pack = module._extract_request_evidence(
                evidence, evidence_path.read_bytes(), policy_path.read_bytes(), "e" * 64
            )
            scope = module._authorization_scope(
                projection["commercial"], authorization_id="release-1471",
                challenge="f" * 64, maximum_component_subtotal_micros=1000,
                valid_from_unix=100, expires_at_unix=150,
            )
            approvals = [
                self._approval(projection, scope, "procurement-a"),
                self._approval(projection, scope, "procurement-b"),
            ]
            order = []

            def replay(*args, **kwargs):
                order.append("replay")
                return copy.deepcopy(evidence)

            def child(argv, **kwargs):
                order.append("child")
                request = json.loads(Path(argv[2]).read_text())
                output = Path(argv[argv.index("--output") + 1])
                assessment = self._assessment(request, policy, approvals, 120)
                output.write_bytes(
                    module._pretty(
                        assessment,
                        module.MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES,
                        "assessment",
                    )
                )
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    side_effect=replay,
                ),
                mock.patch.object(module, "run_bounded", side_effect=child),
            ):
                result = module.evaluate_procurement_release_authorization(
                    evidence_path, *_v1470_arguments(fixture)[:11], policy_path,
                    approvals, _v1470_arguments(fixture)[11], ["authorization-pcbex"],
                    requested_boards=3, evaluated_at_unix=100,
                    expected_policy_pack_canonical_sha256="e" * 64,
                    _wall_clock=lambda: 120.9,
                )
            self.assertEqual(order, ["replay", "child", "replay"])
            self.assertTrue(result["procurement_authorized"])
            self.assertEqual(result["evaluated_at_unix"], 120)
            self.assertTrue(all(result[key] is False for key in module._FALSE_CLAIM_KEYS))
            self.assertEqual(list(result), list(module._REPORT_KEYS))
            self.assertEqual(
                result["binding_sha256"],
                module._sha256(
                    module.PROCUREMENT_AUTHORIZATION_REPORT_BINDING_DOMAIN
                    + module._compact({key: result[key] for key in module._REPORT_KEYS[:-1]})
                ),
            )

    def test_reject_may_sign_negative_but_approve_fails_before_key_and_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, _policy, policy_path, private = self._case(root)
            negative = copy.deepcopy(evidence)
            negative["complete"] = False
            negative["supplier_offer_coverage"]["covered"] = False
            negative["supplier_offer_coverage"]["component_subtotal_micros"] = None
            # The mocked public validator is the authoritative fresh result;
            # retain canonical bytes only to exercise pre-key refusal.
            with (
                mock.patch.object(module, "_normalize_evidence", return_value=negative),
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    return_value=negative,
                ),
                mock.patch.object(module, "run_bounded") as child,
                mock.patch.object(module, "_freeze_private_key") as key,
            ):
                with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                    module.sign_procurement_approval(
                        evidence_path, *_v1470_arguments(fixture)[:11], policy_path,
                        private, _v1470_arguments(fixture)[11], ["authorization-pcbex"],
                        requested_boards=3, evaluated_at_unix=100,
                        expected_policy_pack_canonical_sha256="e" * 64,
                        signer_id="procurement-a", decision="approve",
                        authorization_id="release-1471", challenge="f" * 64,
                        maximum_component_subtotal_micros=1000,
                        valid_from_unix=100, expires_at_unix=150,
                        reason="No.", ticket="HW-1471",
                    )
            child.assert_not_called()
            key.assert_not_called()

    def test_renderer_schemas_and_bytes_pathlike_precedence(self):
        approval_schema = module.signed_procurement_approval_json_schema()
        report_schema = module.procurement_authorization_report_json_schema()
        self.assertFalse(approval_schema["additionalProperties"])
        self.assertFalse(report_schema["additionalProperties"])
        self.assertEqual(
            report_schema["$id"],
            "https://github.com/penguin425/pcbex/schemas/"
            "procurement-authorization-report-v1.json",
        )
        raw = _BytesWithPath(b"{}")
        self.assertEqual(
            module._bounded_bytes(raw, 1024, "test"), b"{}"
        )

    def test_one_pass_mapping_snapshots_once(self):
        value = _OnePassMapping({"a": 1})
        observed = module._snapshot_mapping(value, 1024, "mapping")
        self.assertEqual(observed, {"a": 1})
        self.assertEqual(value.calls, 1)

    def test_capture_is_path_then_bytes_then_mappings_and_approval_mappings_are_deferred(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, _private = self._case(root)
            inherited = _v1470_arguments(fixture)
            board = Path(inherited[1])
            board_raw = board.read_bytes()
            corrupting_policy = _HookMapping(
                policy, lambda: board.write_bytes(board_raw + b"changed")
            )
            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence"
                ) as replay,
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                    module.evaluate_procurement_release_authorization(
                        *self._evaluation_arguments(
                            fixture, evidence_path, corrupting_policy, [{}]
                        ),
                        **self._common_kwargs(),
                    )
            self.assertEqual(corrupting_policy.calls, 1)
            replay.assert_not_called()
            child.assert_not_called()
            board.write_bytes(board_raw)

            mutable_evidence = bytearray(evidence_path.read_bytes())
            policy_raw = module._pretty(
                policy, module.MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES, "policy pack"
            )
            _projection, _scope, approvals, _request, _assessment, _report = (
                self._authorization_material(
                    evidence, bytes(mutable_evidence), policy, policy_raw
                )
            )
            events = []
            captured_policy = _HookMapping(
                policy,
                lambda: (
                    events.append("policy-mapping"),
                    mutable_evidence.__setitem__(slice(None), b"{}\n"),
                ),
            )
            captured_approvals = [
                _HookMapping(value, lambda index=index: events.append(f"mapping-{index}"))
                for index, value in enumerate(approvals)
            ]

            class ApprovalSequence:
                def __iter__(self_nonlocal):
                    events.append("iterator-start")
                    for index, value in enumerate(captured_approvals):
                        events.append(f"next-{index}")
                        yield value
                    events.append("iterator-exhausted")

            def child(argv, **kwargs):
                request = json.loads(Path(argv[2]).read_text())
                output = Path(argv[argv.index("--output") + 1])
                assessment = self._assessment(request, policy, approvals, 120)
                output.write_bytes(module._pretty(
                    assessment,
                    module.MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES,
                    "assessment",
                ))
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    return_value=copy.deepcopy(evidence),
                ),
                mock.patch.object(module, "run_bounded", side_effect=child),
            ):
                result = module.evaluate_procurement_release_authorization(
                    *self._evaluation_arguments(
                        fixture, mutable_evidence, captured_policy, ApprovalSequence()
                    ),
                    **self._common_kwargs(), _wall_clock=lambda: 120,
                )
            self.assertTrue(result["procurement_authorized"])
            self.assertEqual(mutable_evidence, bytearray(b"{}\n"))
            self.assertEqual(
                events,
                [
                    "policy-mapping", "iterator-start", "next-0", "next-1",
                    "iterator-exhausted", "mapping-0", "mapping-1",
                ],
            )
            self.assertEqual([item.calls for item in captured_approvals], [1, 1])

    def test_retained_outer_is_captured_before_approval_iterator_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, _private = self._case(root)
            _projection, _scope, approvals, _request, _assessment, report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy, policy_path.read_bytes()
                )
            )
            retained_path = root / "authorization.json"
            # Public, path-free report fixture; it contains no private-key bytes.
            retained_path.write_bytes(module.render_procurement_authorization_report(report))  # lgtm[py/clear-text-storage-sensitive-data]

            class MutatingApprovals:
                def __iter__(self_nonlocal):
                    retained_path.write_bytes(b"{}\n")
                    return iter(approvals)

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence"
                ) as replay,
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                    module.validate_procurement_release_authorization(
                        retained_path,
                        *self._evaluation_arguments(
                            fixture, evidence_path, policy_path, MutatingApprovals()
                        ),
                        **self._common_kwargs(),
                    )
            replay.assert_not_called()
            child.assert_not_called()

    def test_each_fresh_replay_receives_a_deep_copy_of_all_mutable_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, _private = self._case(root)
            _projection, _scope, approvals, _request, _assessment, _report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy, policy_path.read_bytes()
                )
            )
            arguments = list(self._evaluation_arguments(
                fixture, evidence_path, policy_path, approvals
            ))
            arguments[8] = copy.deepcopy(fixture["assembly"])
            seen = []

            def replay(*args, **kwargs):
                seen.append((
                    copy.deepcopy(args[0]), copy.deepcopy(args[8]), list(args[-1])
                ))
                args[0]["complete"] = False
                args[8]["complete"] = False
                args[-1].append("mutated-by-first-replay")
                return copy.deepcopy(evidence)

            def child(argv, **kwargs):
                request = json.loads(Path(argv[2]).read_text())
                output = Path(argv[argv.index("--output") + 1])
                output.write_bytes(module._pretty(
                    self._assessment(request, policy, approvals, 120),
                    module.MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES,
                    "assessment",
                ))
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    side_effect=replay,
                ),
                mock.patch.object(module, "run_bounded", side_effect=child),
            ):
                module.evaluate_procurement_release_authorization(
                    *arguments, **self._common_kwargs(), _wall_clock=lambda: 120
                )
            self.assertEqual(len(seen), 2)
            self.assertEqual(seen[0], seen[1])
            self.assertTrue(seen[1][0]["complete"])
            self.assertTrue(seen[1][1]["complete"])
            self.assertNotIn("mutated-by-first-replay", seen[1][2])

    def test_validate_none_is_rejected_before_approval_iteration_or_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _evidence, evidence_path, _policy, policy_path, _private = self._case(root)

            class BombApprovals:
                def __iter__(self_nonlocal):
                    raise AssertionError("approval iterator must not run")

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence"
                ) as replay,
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                    module.validate_procurement_release_authorization(
                        None,
                        *self._evaluation_arguments(
                            fixture, evidence_path, policy_path, BombApprovals()
                        ),
                        **self._common_kwargs(),
                    )
            replay.assert_not_called()
            child.assert_not_called()

    def test_caller_hook_cwd_changes_are_restored_for_path_and_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, _policy, policy_path, private = self._case(root)
            original = Path.cwd()
            other = root / "other"
            other.mkdir()
            changing_path = _OneShotPath(
                evidence_path, hook=lambda: os.chdir(other)
            )
            with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                module.sign_procurement_approval(
                    *self._sign_arguments(
                        fixture, changing_path, policy_path, private
                    ),
                    **self._sign_kwargs(),
                )
            self.assertEqual(changing_path.calls, 1)
            self.assertEqual(Path.cwd(), original)

            def changing_clock():
                os.chdir(other)
                return 0.0

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence"
                ) as replay,
                mock.patch.object(module, "_freeze_private_key") as freeze_key,
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                    module.sign_procurement_approval(
                        *self._sign_arguments(
                            fixture, evidence_path, policy_path, private
                        ),
                        **self._sign_kwargs(), _clock=changing_clock,
                    )
            self.assertEqual(Path.cwd(), original)
            replay.assert_not_called()
            freeze_key.assert_not_called()
            child.assert_not_called()

    def test_public_outer_guard_restores_hostile_class_items_and_deleted_cwd_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, private = self._case(root)
            _projection, _scope, approvals, _request, _assessment, _report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy, policy_path.read_bytes()
                )
            )
            entry = Path.cwd()
            other = root / "hostile-cwd"
            other.mkdir()

            original = _HostileClass(other, Path)
            sign_arguments = list(self._sign_arguments(
                fixture, evidence_path, policy_path, private
            ))
            sign_arguments[1] = original
            with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                module.sign_procurement_approval(
                    *sign_arguments, **self._sign_kwargs()
                )
            self.assertGreaterEqual(original.calls, 1)
            self.assertEqual(Path.cwd(), entry)

            retained = _HostileClass(other, dict)
            with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                module.validate_procurement_release_authorization(
                    retained,
                    *self._evaluation_arguments(
                        fixture, evidence_path, policy_path, approvals
                    ),
                    **self._common_kwargs(),
                )
            self.assertGreaterEqual(retained.calls, 1)
            self.assertEqual(Path.cwd(), entry)

            approval = _HostileClass(other, dict)
            with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                module.evaluate_procurement_release_authorization(
                    *self._evaluation_arguments(
                        fixture, evidence_path, policy_path, [approval]
                    ),
                    **self._common_kwargs(),
                )
            self.assertGreaterEqual(approval.calls, 1)
            self.assertEqual(Path.cwd(), entry)

            renderer_mapping = _HookMapping(
                approvals[0], lambda: os.chdir(other)
            )
            with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                module.render_signed_procurement_approval(renderer_mapping)
            self.assertEqual(renderer_mapping.calls, 1)
            self.assertEqual(Path.cwd(), entry)

            invalidating_path = _InvalidatingPath(root)
            with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                module.sign_procurement_approval(
                    *self._sign_arguments(
                        fixture, invalidating_path, policy_path, private
                    ),
                    **self._sign_kwargs(),
                )
            self.assertEqual(invalidating_path.calls, 1)
            self.assertEqual(Path.cwd(), entry)

            def invalidate_cwd():
                doomed = root / "deleted-renderer-cwd"
                doomed.mkdir()
                os.chdir(doomed)
                os.rmdir(doomed)

            invalidating_mapping = _HookMapping(approvals[0], invalidate_cwd)
            with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                module.render_signed_procurement_approval(invalidating_mapping)
            self.assertEqual(invalidating_mapping.calls, 1)
            self.assertEqual(Path.cwd(), entry)

    def test_malformed_mapping_and_approval_iterator_providers_are_sanitized(self):
        class BadMapping(Mapping[str, object]):
            def __getitem__(self, key):
                raise LookupError("secret-provider-detail")

            def __iter__(self):
                raise LookupError("secret-provider-detail")

            def __len__(self):
                return 1

            def items(self):  # type: ignore[override]
                raise LookupError("secret-provider-detail")

        class BadApprovals:
            def __iter__(self):
                raise LookupError("secret-iterator-detail")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _evidence, evidence_path, _policy, policy_path, _private = self._case(root)
            cases = (
                (BadMapping(), [{}]),
                (policy_path, BadApprovals()),
            )
            for policy, approvals in cases:
                with self.subTest(provider=type(policy).__name__ + type(approvals).__name__):
                    with (
                        mock.patch.object(
                            module._v1470,
                            "validate_assembly_supplier_offer_evidence",
                        ) as replay,
                        mock.patch.object(module, "run_bounded") as child,
                    ):
                        with self.assertRaises(
                            module.ProcurementReleaseAuthorizationError
                        ) as caught:
                            module.evaluate_procurement_release_authorization(
                                *self._evaluation_arguments(
                                    fixture, evidence_path, policy, approvals
                                ),
                                **self._common_kwargs(),
                            )
                    self.assertNotIn("secret", str(caught.exception))
                    replay.assert_not_called()
                    child.assert_not_called()

    def test_monotonic_clock_rejects_backwards_time_before_key_or_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, _policy, policy_path, private = self._case(root)
            values = iter((10.0, 9.0))
            observed_clock = []

            def backwards_clock():
                value = next(values)
                observed_clock.append(value)
                return value

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    return_value=copy.deepcopy(evidence),
                ) as replay,
                mock.patch.object(module, "_freeze_private_key") as freeze_key,
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaises(
                    module.ProcurementReleaseAuthorizationError
                ) as caught:
                    module.sign_procurement_approval(
                        *self._sign_arguments(
                            fixture, evidence_path, policy_path, private
                        ),
                        **self._sign_kwargs(), _clock=backwards_clock,
                    )
            self.assertEqual(observed_clock, [10.0, 9.0])
            self.assertNotIn("private", str(caught.exception))
            replay.assert_not_called()
            freeze_key.assert_not_called()
            child.assert_not_called()

    def test_command_whole_token_aliases_and_private_key_command_alias_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, _policy, policy_path, private = self._case(root)
            board = os.fspath(_v1470_arguments(fixture)[1])
            for token in (board, f"@{board}", f"--config={board}", f"-I{board}"):
                with self.subTest(token=token[:12]):
                    with (
                        mock.patch.object(
                            module._v1470,
                            "validate_assembly_supplier_offer_evidence",
                        ) as replay,
                        mock.patch.object(module, "_freeze_private_key") as freeze_key,
                        mock.patch.object(module, "run_bounded") as child,
                    ):
                        with self.assertRaises(
                            module.ProcurementReleaseAuthorizationError
                        ):
                            module.sign_procurement_approval(
                                *self._sign_arguments(
                                    fixture, evidence_path, policy_path, private,
                                    authorization_command=["authorization-pcbex", token],
                                ),
                                **self._sign_kwargs(),
                            )
                    replay.assert_not_called()
                    freeze_key.assert_not_called()
                    child.assert_not_called()

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    return_value=copy.deepcopy(evidence),
                ) as replay,
                mock.patch.object(
                    module, "_freeze_private_key", wraps=module._freeze_private_key,
                ) as freeze_key,
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                    module.sign_procurement_approval(
                        *self._sign_arguments(
                            fixture, evidence_path, policy_path, private,
                            authorization_command=[str(private)],
                        ),
                        **self._sign_kwargs(),
                    )
            self.assertEqual(replay.call_count, 1)
            self.assertEqual(freeze_key.call_count, 1)
            child.assert_not_called()

    def test_private_key_provider_is_untouched_when_public_replay_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _evidence, evidence_path, _policy, policy_path, private = self._case(root)
            private_provider = _OneShotPath(private)
            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    side_effect=RuntimeError("secret-replay-detail"),
                ) as replay,
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaises(
                    module.ProcurementReleaseAuthorizationError
                ) as caught:
                    module.sign_procurement_approval(
                        *self._sign_arguments(
                            fixture, evidence_path, policy_path, private_provider
                        ),
                        **self._sign_kwargs(),
                    )
            self.assertEqual(replay.call_count, 1)
            self.assertEqual(private_provider.calls, 0)
            self.assertNotIn("secret", str(caught.exception))
            child.assert_not_called()

    def test_noncanonical_retained_report_fails_before_replay_and_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, _private = self._case(root)
            _projection, _scope, approvals, _request, _assessment, report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy, policy_path.read_bytes()
                )
            )
            noncanonical = root / "noncanonical-authorization.json"
            noncanonical.write_bytes(
                json.dumps(report, separators=(",", ":")).encode("utf-8")
            )
            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence"
                ) as replay,
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                    module.validate_procurement_release_authorization(
                        noncanonical,
                        *self._evaluation_arguments(
                            fixture, evidence_path, policy_path, approvals
                        ),
                        **self._common_kwargs(),
                    )
            replay.assert_not_called()
            child.assert_not_called()

    def test_retained_validation_accepts_path_bytes_and_one_pass_mapping_at_retained_time(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, _private = self._case(root)
            _projection, _scope, approvals, _request, _assessment, report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy, policy_path.read_bytes()
                )
            )
            report_raw = module.render_procurement_authorization_report(report)
            report_path = root / "authorization.json"
            # Public, path-free report fixture; it contains no private-key bytes.
            report_path.write_bytes(report_raw)  # lgtm[py/clear-text-storage-sensitive-data]
            approval_raw = [
                module.render_signed_procurement_approval(value) for value in approvals
            ]
            approval_paths = []
            for index, raw in enumerate(approval_raw):
                path = root / f"approval-{index}.json"
                # Public, path-free approval fixture; it contains no private-key bytes.
                path.write_bytes(raw)  # lgtm[py/clear-text-storage-sensitive-data]
                approval_paths.append(path)
            retained_mapping = _OnePassMapping(report)
            approval_mappings = [_OnePassMapping(value) for value in approvals]
            cases = (
                ("path", report_path, approval_paths),
                ("bytes", report_raw, approval_raw),
                ("mapping", retained_mapping, approval_mappings),
            )
            for label, retained, represented_approvals in cases:
                observed_times = []

                def child(argv, **kwargs):
                    request = json.loads(Path(argv[2]).read_text())
                    evaluated = int(argv[argv.index("--evaluated-at-unix") + 1])
                    observed_times.append(evaluated)
                    output = Path(argv[argv.index("--output") + 1])
                    output.write_bytes(module._pretty(
                        self._assessment(request, policy, approvals, evaluated),
                        module.MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES,
                        "assessment",
                    ))
                    return BoundedProcessResult(tuple(argv), 0, b"", b"")

                with (
                    self.subTest(representation=label),
                    mock.patch.object(
                        module._v1470,
                        "validate_assembly_supplier_offer_evidence",
                        return_value=copy.deepcopy(evidence),
                    ) as replay,
                    mock.patch.object(module, "run_bounded", side_effect=child),
                ):
                    observed = module.validate_procurement_release_authorization(
                        retained,
                        *self._evaluation_arguments(
                            fixture, evidence_path, policy_path,
                            represented_approvals,
                        ),
                        **self._common_kwargs(),
                    )
                self.assertEqual(observed, report)
                self.assertEqual(observed_times, [120])
                self.assertEqual(replay.call_count, 2)
            self.assertEqual(retained_mapping.calls, 1)
            self.assertEqual([item.calls for item in approval_mappings], [1, 1])

    def test_staged_and_caller_source_mutations_are_hard_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, _private = self._case(root)
            _projection, _scope, approvals, _request, _assessment, _report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy, policy_path.read_bytes()
                )
            )

            def child_for(mutation):
                def child(argv, **kwargs):
                    request = json.loads(Path(argv[2]).read_text())
                    output = Path(argv[argv.index("--output") + 1])
                    output.write_bytes(module._pretty(
                        self._assessment(request, policy, approvals, 120),
                        module.MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES,
                        "assessment",
                    ))
                    mutation(argv)
                    return BoundedProcessResult(tuple(argv), 0, b"", b"")

                return child

            original_policy = policy_path.read_bytes()
            mutations = (
                (
                    "staged",
                    lambda argv: Path(argv[argv.index("--policy-pack") + 1]).write_bytes(
                        b"{}\n"
                    ),
                ),
                (
                    "caller",
                    lambda _argv: policy_path.write_bytes(original_policy + b"changed"),
                ),
            )
            for label, mutation in mutations:
                policy_path.write_bytes(original_policy)
                with (
                    self.subTest(mutation=label),
                    mock.patch.object(
                        module._v1470,
                        "validate_assembly_supplier_offer_evidence",
                        return_value=copy.deepcopy(evidence),
                    ),
                    mock.patch.object(
                        module, "run_bounded", side_effect=child_for(mutation)
                    ),
                ):
                    with self.assertRaises(
                        module.ProcurementReleaseAuthorizationError
                    ):
                        module.evaluate_procurement_release_authorization(
                            *self._evaluation_arguments(
                                fixture, evidence_path, policy_path, approvals
                            ),
                            **self._common_kwargs(), _wall_clock=lambda: 120,
                        )
            policy_path.write_bytes(original_policy)

    def test_final_clock_cannot_swap_staged_tcb_inputs_before_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, private = (
                self._case(root)
            )
            _projection, _scope, approvals, _request, _assessment, _report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy,
                    policy_path.read_bytes(),
                )
            )
            original_stage = module._stage

            # The wall-clock hook arms the attack after every public input has
            # been captured and staged.  The very next monotonic-clock poll is
            # `_run_helper`'s final pre-spawn budget check.
            staged_approvals = []
            armed = False
            swapped = False
            ticks = 0.0
            alternate = copy.deepcopy(approvals)
            for index, item in enumerate(alternate):
                item["reason"] = f"Alternate staged approval {index}."
                item["signature"] = ("e" if index == 0 else "f") * 128
            alternate_raw = [
                module.render_signed_procurement_approval(item)
                for item in alternate
            ]

            def tracking_stage(stage_root, name, raw, maximum, label):
                path = original_stage(stage_root, name, raw, maximum, label)
                if name.startswith("approval-"):
                    staged_approvals.append(path)
                return path

            def wall_clock():
                nonlocal armed
                armed = True
                return 120

            def clock():
                nonlocal swapped, ticks
                ticks += 0.01
                if armed and not swapped:
                    self.assertEqual(len(staged_approvals), len(alternate_raw))
                    for path, raw in zip(
                        staged_approvals, alternate_raw, strict=True
                    ):
                        path.write_bytes(raw)
                    swapped = True
                return ticks

            with (
                mock.patch.object(
                    module._v1470,
                    "validate_assembly_supplier_offer_evidence",
                    return_value=copy.deepcopy(evidence),
                ) as replay,
                mock.patch.object(module, "_stage", side_effect=tracking_stage),
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaisesRegex(
                    module.ProcurementReleaseAuthorizationError,
                    "trusted verification workspace input changed",
                ):
                    module.evaluate_procurement_release_authorization(
                        *self._evaluation_arguments(
                            fixture, evidence_path, policy_path, approvals
                        ),
                        **self._common_kwargs(), _clock=clock,
                        _wall_clock=wall_clock,
                    )
            self.assertTrue(swapped)
            self.assertEqual(replay.call_count, 1)
            child.assert_not_called()

            # Signing has the same last-clock boundary for its request and
            # policy files.  Mutating either after staging must likewise stop
            # before the key-bearing helper is spawned.
            staged_policy = []
            swapped = False
            ticks = 0.0

            def tracking_sign_stage(stage_root, name, raw, maximum, label):
                path = original_stage(stage_root, name, raw, maximum, label)
                if name == "policy.json":
                    staged_policy.append(path)
                return path

            def signing_clock():
                nonlocal swapped, ticks
                ticks += 0.01
                if staged_policy and not swapped:
                    staged_policy[0].write_bytes(b"{}\n")
                    swapped = True
                return ticks

            with (
                mock.patch.object(
                    module._v1470,
                    "validate_assembly_supplier_offer_evidence",
                    return_value=copy.deepcopy(evidence),
                ) as replay,
                mock.patch.object(
                    module, "_stage", side_effect=tracking_sign_stage
                ),
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaisesRegex(
                    module.ProcurementReleaseAuthorizationError,
                    "trusted signing workspace input changed",
                ):
                    module.sign_procurement_approval(
                        *self._sign_arguments(
                            fixture, evidence_path, policy_path, private
                        ),
                        **self._sign_kwargs(), _clock=signing_clock,
                    )
            self.assertTrue(swapped)
            self.assertEqual(replay.call_count, 1)
            child.assert_not_called()

    def test_assessment_must_retain_exact_submitted_approval_envelopes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, _private = (
                self._case(root)
            )
            _projection, _scope, approvals, _request, _assessment, _report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy,
                    policy_path.read_bytes(),
                )
            )
            alternate = copy.deepcopy(approvals)
            alternate[0]["reason"] = "TCB substituted another valid approval."
            alternate[0]["signature"] = "e" * 128

            def child(argv, **kwargs):
                request = json.loads(Path(argv[2]).read_text())
                evaluated = int(argv[argv.index("--evaluated-at-unix") + 1])
                assessment = self._assessment(
                    request, policy, alternate, evaluated
                )
                output = Path(argv[argv.index("--output") + 1])
                output.write_bytes(module._pretty(
                    assessment,
                    module.MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES,
                    "assessment",
                ))
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with (
                mock.patch.object(
                    module._v1470,
                    "validate_assembly_supplier_offer_evidence",
                    return_value=copy.deepcopy(evidence),
                ) as replay,
                mock.patch.object(module, "run_bounded", side_effect=child),
            ):
                with self.assertRaisesRegex(
                    module.ProcurementReleaseAuthorizationError,
                    "exact submitted approvals",
                ):
                    module.evaluate_procurement_release_authorization(
                        *self._evaluation_arguments(
                            fixture, evidence_path, policy_path, approvals
                        ),
                        **self._common_kwargs(), _wall_clock=lambda: 120,
                    )
            self.assertEqual(replay.call_count, 1)

    def test_helper_forgery_is_rejected_by_sign_and_evaluate_apis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, evidence, evidence_path, policy, policy_path, private = self._case(root)
            _projection, _scope, approvals, _request, _assessment, _report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy, policy_path.read_bytes()
                )
            )

            def forged_signer(argv, **kwargs):
                request = json.loads(Path(argv[2]).read_text())
                approval = self._approval(
                    request["evidence"], request["authorization_scope"]
                )
                approval["reason"] = "Helper substituted a different reason."
                output = Path(argv[argv.index("--output") + 1])
                # Public, path-free forged fixture; it contains no private-key bytes.
                output.write_bytes(module.render_signed_procurement_approval(approval))  # lgtm[py/clear-text-storage-sensitive-data]
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    return_value=copy.deepcopy(evidence),
                ) as replay,
                mock.patch.object(module, "run_bounded", side_effect=forged_signer),
            ):
                with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                    module.sign_procurement_approval(
                        *self._sign_arguments(
                            fixture, evidence_path, policy_path, private
                        ),
                        **self._sign_kwargs(),
                    )
            self.assertEqual(replay.call_count, 1)

            def forged_verifier(argv, **kwargs):
                request = json.loads(Path(argv[2]).read_text())
                assessment = self._assessment(request, policy, approvals, 120)
                assessment["members"][0]["ticket"] = "FORGED-HELPER-TICKET"
                assessment["binding_sha256"] = module._sha256(
                    module.PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BINDING_DOMAIN
                    + module._compact({
                        key: assessment[key]
                        for key in module._ASSESSMENT_KEYS[:-1]
                    })
                )
                output = Path(argv[argv.index("--output") + 1])
                output.write_bytes(module._pretty(
                    assessment,
                    module.MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES,
                    "assessment",
                ))
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with (
                mock.patch.object(
                    module._v1470, "validate_assembly_supplier_offer_evidence",
                    return_value=copy.deepcopy(evidence),
                ) as replay,
                mock.patch.object(module, "run_bounded", side_effect=forged_verifier),
            ):
                with self.assertRaises(module.ProcurementReleaseAuthorizationError):
                    module.evaluate_procurement_release_authorization(
                        *self._evaluation_arguments(
                            fixture, evidence_path, policy_path, approvals
                        ),
                        **self._common_kwargs(), _wall_clock=lambda: 120,
                    )
            self.assertEqual(replay.call_count, 1)

    def test_schemas_are_recursively_closed_bounded_and_match_runtime_policy(self):
        def inventories(schema):
            objects = []
            arrays = []

            def visit(value):
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        objects.append(value)
                    if value.get("type") == "array":
                        arrays.append(value)
                    for child in value.values():
                        visit(child)
                elif isinstance(value, list):
                    for child in value:
                        visit(child)

            visit(schema)
            return objects, arrays

        approval_schema = module.signed_procurement_approval_json_schema()
        report_schema = module.procurement_authorization_report_json_schema()
        approval_objects, approval_arrays = inventories(approval_schema)
        report_objects, report_arrays = inventories(report_schema)
        self.assertEqual((len(approval_objects), len(approval_arrays)), (8, 0))
        self.assertTrue(all(
            value.get("additionalProperties") is False
            for value in approval_objects
        ))
        self.assertEqual((len(report_objects), len(report_arrays)), (46, 10))
        self.assertTrue(all(
            value.get("additionalProperties") is False for value in report_objects
        ))
        self.assertTrue(all(
            type(value.get("maxItems")) is int for value in report_arrays
        ))

        report_properties = report_schema["properties"]
        approval_properties = approval_schema["properties"]
        approval_evidence = approval_properties["evidence"]["properties"]
        assembly_source = approval_evidence[
            "assembly_supplier_offer_evidence"
        ]["properties"]["source"]["properties"]["bytes"]
        policy_projection = approval_evidence["policy_pack"]["properties"]
        commercial = approval_evidence["commercial"]
        policy_schema = report_properties["policy_pack"]
        self.assertEqual(
            assembly_source["maximum"],
            module._v1470.MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
        )
        self.assertEqual(
            policy_projection["source"]["properties"]["bytes"]["maximum"],
            module.MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES,
        )
        self.assertEqual(policy_projection["revision"]["maximum"], 2**32 - 1)
        self.assertEqual(
            policy_schema["properties"]["revision"]["maximum"], 2**32 - 1
        )
        conditional = commercial["allOf"][0]
        self.assertEqual(
            conditional["then"]["properties"]["component_subtotal_micros"]["type"],
            "integer",
        )
        self.assertEqual(
            conditional["else"]["properties"]["component_subtotal_micros"]["type"],
            "null",
        )
        self.assertEqual(report_properties["gate_failures"]["maxItems"], 9)
        self.assertEqual(
            policy_schema["properties"]["trusted_human_escalation_keys"]["minItems"],
            1,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _fixture, evidence, evidence_path, policy, policy_path, _private = self._case(root)
            _projection, _scope, approvals, _request, _assessment, report = (
                self._authorization_material(
                    evidence, evidence_path.read_bytes(), policy, policy_path.read_bytes()
                )
            )
            if Draft202012Validator is not None:
                Draft202012Validator.check_schema(approval_schema)
                Draft202012Validator.check_schema(report_schema)
                Draft202012Validator(approval_schema).validate(approvals[0])
                Draft202012Validator(report_schema).validate(report)

            invalid_reports = []

            invalid = copy.deepcopy(report)
            invalid["policy_pack"]["dfm_profile"]["rules"]["extra"] = 1
            invalid_reports.append(("dfm", invalid))

            invalid = copy.deepcopy(report)
            invalid["policy_pack"]["electrical_policy"]["rules"][
                "coverage_incomplete"
            ]["enabled"] = False
            invalid_reports.append(("electrical", invalid))

            invalid = copy.deepcopy(report)
            invalid["policy_pack"]["ai_requirements"][0]["extra"] = True
            invalid_reports.append(("ai", invalid))

            invalid = copy.deepcopy(report)
            invalid["policy_pack"]["trusted_approval_keys"] = []
            invalid_reports.append(("trust", invalid))

            invalid = copy.deepcopy(report)
            invalid["policy_pack"]["trusted_human_escalation_keys"] = []
            invalid_reports.append(("human-default", invalid))

            invalid = copy.deepcopy(report)
            invalid["policy_pack"]["fabrication_authorization_policy"] = None
            invalid_reports.append(("fabrication-default", invalid))

            invalid = copy.deepcopy(report)
            invalid["policy_pack"]["procurement_authorization_policy"][
                "minimum_approvals"
            ] = 101
            invalid_reports.append(("procurement", invalid))

            validator = (
                Draft202012Validator(report_schema)
                if Draft202012Validator is not None else None
            )
            for label, invalid in invalid_reports:
                with self.subTest(policy_subtree=label):
                    if validator is not None:
                        self.assertTrue(list(validator.iter_errors(invalid)))
                    with self.assertRaises(
                        module.ProcurementReleaseAuthorizationError
                    ):
                        module.render_procurement_authorization_report(invalid)

            raw_defaults = copy.deepcopy(policy)
            raw_defaults["trusted_human_escalation_keys"] = []
            raw_defaults["fabrication_authorization_policy"] = None
            self.assertEqual(
                module._policy_semantic(raw_defaults),
                module._policy_semantic(policy),
            )


if __name__ == "__main__":
    unittest.main()

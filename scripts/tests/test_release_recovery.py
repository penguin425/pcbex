"""Targeted dependency-free tests for release_recovery.py."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "release_recovery.py"
SPEC = importlib.util.spec_from_file_location("release_recovery", SCRIPT)
assert SPEC and SPEC.loader
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)

TAG = "v1.533.0"
REPO = "penguin425/pcbex"
SOURCE = "a" * 40
TAG_OBJECT = "b" * 40
WORKFLOW = "c" * 40


class RecoveryTests(unittest.TestCase):
    def args(self, command, archive=None, output=None):
        values = [command, "--repository", REPO, "--tag", TAG,
                  "--expected-sha", SOURCE, "--expected-tag-object", TAG_OBJECT]
        if archive:
            values += ["--archive", archive]
        if output:
            values += ["--output", output]
        if command == "resolve":
            values += ["--rust-toolchain", "1.98.1"]
        if command in ("predicate", "verify"):
            values += ["--workflow-sha", WORKFLOW, "--rust-toolchain", "1.98.1", "--run-id", "17", "--run-attempt", "2"]
        return recovery._parser().parse_args(values)

    def test_resolve_uses_workflow_head_but_reads_source_commit(self):
        args = self.args("resolve")
        with mock.patch.dict(recovery.os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": WORKFLOW}, clear=False), mock.patch.object(recovery, "_run", side_effect=[WORKFLOW, TAG_OBJECT, SOURCE, "", "[workspace.package]\nversion=\"1.533.0\"", "[project]\nversion=\"1.533.0\""]) as run:
            recovery.resolve(args)
        self.assertTrue(any(f"{SOURCE}:Cargo.toml" in call.args[0] for call in run.call_args_list))

    def test_remote_is_exactly_two_reads(self):
        args = self.args("check-remote")
        with mock.patch.object(recovery, "_json_command", side_effect=[{"ref": f"refs/tags/{TAG}", "object": {"type": "tag", "sha": TAG_OBJECT}}, {"object": {"type": "commit", "sha": SOURCE}}]) as command:
            recovery.check_remote(args)
        self.assertEqual(command.call_count, 2)

    def test_predicate_is_closed_and_archive_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / f"pcbex-{TAG}-x86_64-unknown-linux-gnu.tar.gz"
            payload = b"archive"
            archive.write_bytes(payload)
            args = self.args("predicate", archive.name, "predicate.json")
            with mock.patch("release_recovery.Path.cwd", return_value=root):
                recovery.predicate(args)
            value = json.loads((root / "predicate.json").read_text())
            self.assertEqual(set(value), {"archive_name", "archive_sha256", "repository", "run_attempt", "run_id", "schema_version", "source_sha", "tag", "tag_object", "workflow_sha", "rust_toolchain"})
            self.assertEqual(value["archive_sha256"], hashlib.sha256(payload).hexdigest())

    def test_verify_requires_documented_nested_result_and_subject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / f"pcbex-{TAG}-x86_64-unknown-linux-gnu.tar.gz"
            payload = b"archive"
            archive.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            predicate = {"archive_name": archive.name, "archive_sha256": digest, "repository": REPO, "run_attempt": 2, "run_id": 17, "schema_version": 1, "source_sha": SOURCE, "tag": TAG, "tag_object": TAG_OBJECT, "workflow_sha": WORKFLOW, "rust_toolchain": "1.98.1"}
            result = [{"verificationResult": {"statement": {"predicateType": recovery.PREDICATE_TYPE, "predicate": predicate, "subject": [{"name": archive.name, "digest": {"sha256": digest}}]}}}]
            args = self.args("verify", archive.name)
            with mock.patch("release_recovery.Path.cwd", return_value=root), mock.patch.object(recovery, "_json_command", return_value=result) as command:
                recovery.verify(args)
            argv = command.call_args.args[0]
            self.assertNotIn("--signer-workflow", argv)
            self.assertEqual(argv.count("--cert-identity"), 1)

    def test_verify_rejects_boolean_integer_substitution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / f"pcbex-{TAG}-x86_64-unknown-linux-gnu.tar.gz"
            archive.write_bytes(b"archive")
            digest = hashlib.sha256(b"archive").hexdigest()
            predicate = {"archive_name": archive.name, "archive_sha256": digest, "repository": REPO, "run_attempt": True, "run_id": 17, "schema_version": 1, "source_sha": SOURCE, "tag": TAG, "tag_object": TAG_OBJECT, "workflow_sha": WORKFLOW, "rust_toolchain": "1.98.1"}
            result = [{"verificationResult": {"statement": {"predicateType": recovery.PREDICATE_TYPE, "predicate": predicate, "subject": [{"name": archive.name, "digest": {"sha256": digest}}]}}}]
            with mock.patch("release_recovery.Path.cwd", return_value=root), mock.patch.object(recovery, "_json_command", return_value=result):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.verify(self.args("verify", archive.name))

    def test_resolve_rejects_event_ref_and_workflow_sha_before_git(self):
        args = self.args("resolve")
        for environment in (
            {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": WORKFLOW},
            {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/tags/v1.533.0", "GITHUB_SHA": WORKFLOW},
            {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "bad"},
        ):
            with self.subTest(environment=environment), mock.patch.dict(recovery.os.environ, environment, clear=False), mock.patch.object(recovery, "_run") as run:
                with self.assertRaises(recovery.RecoveryError):
                    recovery.resolve(args)
                run.assert_not_called()

    def test_invalid_rust_toolchains_fail_before_external_commands(self):
        invalid = ("stable", "nightly", "1.98", "1.98.1-nightly", "--version", "../../rustc", "1.9999.1", "1.98.1\n")
        for value in invalid:
            with self.subTest(value=value), mock.patch.object(recovery, "_run") as run:
                args = self.args("resolve")
                args.rust_toolchain = value
                with mock.patch.dict(recovery.os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": WORKFLOW}, clear=False):
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.resolve(args)
                run.assert_not_called()

    def test_resolve_rejects_controller_tag_and_ancestry_mutations(self):
        args = self.args("resolve")
        environment = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": WORKFLOW}
        cases = (["wrong-head"], [WORKFLOW, "wrong-tag-object"], [WORKFLOW, TAG_OBJECT, "wrong-source"], [WORKFLOW, TAG_OBJECT, SOURCE, recovery.RecoveryError("ancestor-failed")])
        for side_effect in cases:
            with self.subTest(side_effect=side_effect), mock.patch.dict(recovery.os.environ, environment, clear=False), mock.patch.object(recovery, "_run", side_effect=side_effect):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.resolve(args)

    def test_resolve_rejects_version_mismatch(self):
        args = self.args("resolve")
        environment = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": WORKFLOW}
        with mock.patch.dict(recovery.os.environ, environment, clear=False), mock.patch.object(recovery, "_run", side_effect=[WORKFLOW, TAG_OBJECT, SOURCE, "", "[workspace.package]\nversion=\"1.533.1\"", "[project]\nversion=\"1.533.0\""]):
            with self.assertRaises(recovery.RecoveryError):
                recovery.resolve(args)

    def test_remote_rejects_ref_and_object_mutations_without_extra_gets(self):
        args = self.args("check-remote")
        responses = [
            {"ref": "refs/tags/other", "object": {"type": "tag", "sha": TAG_OBJECT}},
            {"ref": f"refs/tags/{TAG}", "object": {"type": "commit", "sha": TAG_OBJECT}},
            {"ref": f"refs/tags/{TAG}", "object": {"type": "tag", "sha": "d" * 40}},
        ]
        for first in responses:
            with self.subTest(first=first), mock.patch.object(recovery, "_json_command", side_effect=[first, {"object": {"type": "commit", "sha": SOURCE}}]) as command:
                with self.assertRaises(recovery.RecoveryError):
                    recovery.check_remote(args)
                self.assertLessEqual(command.call_count, 2)

    def _verify_fixture(self, root: Path, *, archive_name=None):
        archive_name = archive_name or f"pcbex-{TAG}-x86_64-unknown-linux-gnu.tar.gz"
        archive = root / "dist" / archive_name
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(b"archive")
        digest = hashlib.sha256(b"archive").hexdigest()
        predicate = {"archive_name": archive.name, "archive_sha256": digest, "repository": REPO, "run_attempt": 2, "run_id": 17, "schema_version": 1, "source_sha": SOURCE, "tag": TAG, "tag_object": TAG_OBJECT, "workflow_sha": WORKFLOW, "rust_toolchain": "1.98.1"}
        statement = {"predicateType": recovery.PREDICATE_TYPE, "predicate": predicate, "subject": [{"name": archive.name, "digest": {"sha256": digest}}]}
        return archive, predicate, [{"verificationResult": {"statement": statement}}]

    def test_verify_rejects_each_mutated_predicate_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, predicate, result = self._verify_fixture(root)
            for key, value in {"source_sha": "d" * 40, "tag_object": "d" * 40, "tag": "v1.533.1", "archive_sha256": "d" * 64, "workflow_sha": "d" * 40, "rust_toolchain": "1.99.0", "run_id": 18, "run_attempt": 3, "schema_version": 2}.items():
                mutated = json.loads(json.dumps(result))
                mutated[0]["verificationResult"]["statement"]["predicate"][key] = value
                with self.subTest(key=key), mock.patch("release_recovery.Path.cwd", return_value=root), mock.patch.object(recovery, "_json_command", return_value=mutated):
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.verify(self.args("verify", f"dist/{archive.name}"))

    def test_verify_rejects_extra_missing_and_boolean_schema_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, predicate, result = self._verify_fixture(root)
            mutations = []
            extra = dict(predicate); extra["extra"] = True; mutations.append(extra)
            missing = dict(predicate); del missing["tag"]; mutations.append(missing)
            boolean_schema = dict(predicate); boolean_schema["schema_version"] = True; mutations.append(boolean_schema)
            for mutated_predicate in mutations:
                mutated = json.loads(json.dumps(result)); mutated[0]["verificationResult"]["statement"]["predicate"] = mutated_predicate
                with self.subTest(predicate=mutated_predicate), mock.patch("release_recovery.Path.cwd", return_value=root), mock.patch.object(recovery, "_json_command", return_value=mutated):
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.verify(self.args("verify", f"dist/{archive.name}"))

    def test_verify_rejects_untrusted_shapes_subjects_and_gh_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, _, result = self._verify_fixture(root)
            invalid_results = [[], {}, [{"verificationResult": "PASSED"}], [{"verificationResult": {"statement": {}}}]]
            wrong_subject = json.loads(json.dumps(result)); wrong_subject[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "d" * 64; invalid_results.append(wrong_subject)
            wrong_name = json.loads(json.dumps(result)); wrong_name[0]["verificationResult"]["statement"]["subject"][0]["name"] = "other.zip"; invalid_results.append(wrong_name)
            for invalid in invalid_results:
                with self.subTest(invalid=invalid), mock.patch("release_recovery.Path.cwd", return_value=root), mock.patch.object(recovery, "_json_command", return_value=invalid):
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.verify(self.args("verify", f"dist/{archive.name}"))
            with mock.patch("release_recovery.Path.cwd", return_value=root), mock.patch.object(recovery, "_json_command", side_effect=recovery.RecoveryError("gh failed")):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.verify(self.args("verify", f"dist/{archive.name}"))

    def test_verify_uses_exact_identity_and_hosted_runner_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, _, result = self._verify_fixture(root)
            with mock.patch("release_recovery.Path.cwd", return_value=root), mock.patch.object(recovery, "_json_command", return_value=result) as command:
                recovery.verify(self.args("verify", f"dist/{archive.name}"))
            argv = command.call_args.args[0]
            for option, value in (("--source-digest", WORKFLOW), ("--signer-digest", WORKFLOW), ("--source-ref", "refs/heads/main"), ("--cert-identity", f"https://github.com/{REPO}/.github/workflows/release-recovery.yml@refs/heads/main")):
                self.assertEqual(argv[argv.index(option) + 1], value)
            self.assertIn("--deny-self-hosted-runners", argv)
            self.assertNotIn("--signer-workflow", argv)

    def test_archive_and_output_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / f"pcbex-{TAG}-x86_64-unknown-linux-gnu.tar.gz"
            archive.write_bytes(b"archive")
            for archive_arg in ("../secret", archive.name.replace("x86_64", "bad")):
                with self.subTest(archive_arg=archive_arg), mock.patch("release_recovery.Path.cwd", return_value=root):
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.predicate(self.args("predicate", archive_arg, "control/predicate.json"))
            output = root / "predicate.json"
            with mock.patch("release_recovery.Path.cwd", return_value=root):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.predicate(self.args("predicate", archive.name, "../predicate.json"))

    def test_workspace_shaped_dist_and_control_paths_succeed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "control" / "recovery-assets").mkdir(parents=True)
            archive, _ = self.archive(root / "dist") if False else (root / "dist" / f"pcbex-{TAG}-x86_64-unknown-linux-gnu.tar.gz", None)
            archive.parent.mkdir(); archive.write_bytes(b"archive")
            with mock.patch("release_recovery.Path.cwd", return_value=root):
                recovery.predicate(self.args("predicate", f"dist/{archive.name}", "control/release-source.json"))
            self.assertTrue((root / "control/release-source.json").is_file())

    def test_oversized_sparse_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root / f"pcbex-{TAG}-x86_64-unknown-linux-gnu.tar.gz"
            with archive.open("wb") as handle:
                handle.truncate(recovery.ARCHIVE_LIMIT + 1)
            with mock.patch("release_recovery.Path.cwd", return_value=root):
                with self.assertRaises(Exception):
                    recovery.predicate(self.args("predicate", archive.name, "control/predicate.json"))


if __name__ == "__main__":
    unittest.main()

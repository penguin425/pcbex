from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "stage-pr-comment.py"
SPEC = importlib.util.spec_from_file_location("stage_pr_comment", SCRIPT)
assert SPEC and SPEC.loader
stage_pr_comment = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage_pr_comment)


HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40


def pull_request_event(*, fork: bool = False) -> dict:
    head_repository = "contributor/pcbex" if fork else "penguin425/pcbex"
    return {
        "action": "opened",
        "number": 42,
        "repository": {
            "full_name": "penguin425/pcbex",
            "id": 1001,
            "name": "pcbex",
        },
        "pull_request": {
            "number": 42,
            "head": {
                "sha": HEAD_SHA,
                "ref": "feature/comment-publisher",
                "repo": {
                    "full_name": head_repository,
                    "id": 2002 if fork else 1001,
                },
            },
            "base": {
                "sha": BASE_SHA,
                "ref": "main",
                "repo": {"full_name": "penguin425/pcbex", "id": 1001},
            },
        },
    }


def write_event(directory: Path, event: dict) -> Path:
    path = directory / "event.json"
    path.write_text(json.dumps(event), encoding="utf-8")
    return path


def run_stage(
    root: Path,
    *,
    event: dict | None = None,
    body: bytes = b"# pcbex hardware analysis\n\npass\n",
    output_name: str = "stage",
    fork: bool = False,
):
    event_path = write_event(root, pull_request_event(fork=fork) if event is None else event)
    body_path = root / "pr-comment.md"
    body_path.write_bytes(body)
    return stage_pr_comment.stage(
        event_path=event_path,
        body_path=body_path,
        output_dir=root / output_name,
        workflow_name="Hardware CI",
        workflow_path=".github/workflows/ci.yml",
        comment_id="analysis",
        run_id="123456",
        run_attempt="2",
        event_name="pull_request",
    )


class StagePrCommentTests(unittest.TestCase):
    def test_valid_event_publishes_exact_two_files_and_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binding = run_stage(root)
            output = root / "stage"
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                ["binding.json", "pr-comment.md"],
            )
            self.assertTrue(
                all(
                    path.is_file() and not path.is_symlink()
                    for path in output.iterdir()
                )
            )
            self.assertTrue(
                all(path.stat().st_mode & 0o077 == 0 for path in output.iterdir())
            )
            self.assertEqual(json.loads((output / "binding.json").read_text()), binding)
            self.assertEqual(binding["schema_version"], 1)
            self.assertEqual(binding["body_path"], "pr-comment.md")
            self.assertEqual(binding["repository_id"], 1001)
            self.assertEqual(binding["base_repository_id"], 1001)
            self.assertEqual(binding["head_repository_id"], 1001)
            self.assertEqual(binding["pr_number"], 42)
            self.assertEqual(binding["run_id"], 123456)
            self.assertEqual(binding["run_attempt"], 2)
            self.assertEqual(binding["head_repository"], "penguin425/pcbex")

    def test_fork_head_is_bound_without_being_confused_with_base_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            binding = run_stage(Path(temporary), fork=True)
            self.assertEqual(binding["repository"], "penguin425/pcbex")
            self.assertEqual(binding["base_repository"], "penguin425/pcbex")
            self.assertEqual(binding["head_repository"], "contributor/pcbex")
            self.assertEqual(binding["repository_id"], 1001)
            self.assertEqual(binding["base_repository_id"], 1001)
            self.assertEqual(binding["head_repository_id"], 2002)

    def test_event_must_be_pull_request_and_consistent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for event in (
                {"repository": {"full_name": "penguin425/pcbex"}},
                {
                    **pull_request_event(),
                    "pull_request": {
                        **pull_request_event()["pull_request"],
                        "base": {
                            "sha": BASE_SHA,
                            "ref": "main",
                            "repo": {"full_name": "someone/else"},
                        },
                    },
                },
                {
                    **pull_request_event(),
                    "number": 43,
                },
            ):
                with self.subTest(event=event):
                    with self.assertRaises(stage_pr_comment.StageError):
                        run_stage(root, event=event, output_name=f"bad-{len(list(root.iterdir()))}")

    def test_repository_ids_are_required_positive_and_identity_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = []

            missing = pull_request_event()
            del missing["repository"]["id"]
            cases.append(("missing repository id", missing))

            boolean = pull_request_event()
            boolean["repository"]["id"] = True
            cases.append(("boolean repository id", boolean))

            zero = pull_request_event()
            zero["pull_request"]["head"]["repo"]["id"] = 0
            cases.append(("zero head repository id", zero))

            mismatch = pull_request_event()
            mismatch["pull_request"]["base"]["repo"]["id"] = 9999
            cases.append(("mismatched base repository id", mismatch))

            too_large = pull_request_event()
            too_large["pull_request"]["head"]["repo"]["id"] = 2**63
            cases.append(("oversized head repository id", too_large))

            for label, event in cases:
                with self.subTest(label=label):
                    with self.assertRaises(stage_pr_comment.StageError):
                        run_stage(
                            root,
                            event=event,
                            output_name=f"bad-id-{len(list(root.iterdir()))}",
                        )

    def test_source_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = write_event(root, pull_request_event())
            real_body = root / "real.md"
            real_body.write_text("# report\n", encoding="utf-8")
            body_path = root / "pr-comment.md"
            try:
                body_path.symlink_to(real_body)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable")
            with self.assertRaises(stage_pr_comment.StageError):
                stage_pr_comment.stage(
                    event_path=event_path,
                    body_path=body_path,
                    output_dir=root / "stage",
                    workflow_name="Hardware CI",
                    workflow_path=".github/workflows/ci.yml",
                    comment_id="analysis",
                    run_id="123456",
                    run_attempt="1",
                    event_name="pull_request",
                )
            self.assertFalse((root / "stage").exists())

    def test_output_root_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "real-output"
            target.mkdir()
            sentinel = target / "sentinel"
            sentinel.write_text("keep", encoding="utf-8")
            output = root / "stage"
            try:
                output.symlink_to(target, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable")
            with self.assertRaises(stage_pr_comment.StageError):
                run_stage(root)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            self.assertTrue(output.is_symlink())

    def test_output_path_rejects_lexical_dot_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = write_event(root, pull_request_event())
            body_path = root / "pr-comment.md"
            body_path.write_text("# report\n", encoding="utf-8")
            with self.assertRaises(stage_pr_comment.StageError):
                stage_pr_comment.stage(
                    event_path=event_path,
                    body_path=body_path,
                    output_dir=str(root / ".." / "stage"),
                    workflow_name="Hardware CI",
                    workflow_path=".github/workflows/ci.yml",
                    comment_id="analysis",
                    run_id="123456",
                    run_attempt="1",
                    event_name="pull_request",
                )

    def test_body_utf8_and_both_size_limits_are_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(stage_pr_comment.StageError):
                run_stage(root, body=b"\xff")
            run_stage(
                root,
                body=b"x" * stage_pr_comment.MAX_BODY_CHARS,
                output_name="chars-at-limit",
            )
            with self.assertRaises(stage_pr_comment.StageError):
                run_stage(
                    root,
                    body=("x" * (stage_pr_comment.MAX_BODY_CHARS + 1)).encode(),
                    output_name="chars-over-limit",
                )
            with self.assertRaises(stage_pr_comment.StageError):
                run_stage(
                    root,
                    body=("é" * (stage_pr_comment.MAX_BODY_BYTES // 2 + 1)).encode(),
                    output_name="bytes-over-limit",
                )

    def test_existing_destination_is_not_clobbered_and_no_stale_temp_remains(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "stage"
            output.mkdir()
            stale = output / "stale.txt"
            stale.write_text("keep", encoding="utf-8")
            with self.assertRaises(stage_pr_comment.StageError):
                run_stage(root)
            self.assertEqual(stale.read_text(encoding="utf-8"), "keep")
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                ["event.json", "pr-comment.md", "stage"],
            )
            self.assertEqual(
                sorted(
                    path.name
                    for path in root.iterdir()
                    if path.name.startswith(".pcbex-pr-comment-stage-")
                ),
                [],
            )

    def test_deterministic_json_and_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_stage(root, output_name="one")
            run_stage(root, output_name="two")
            first = (root / "one" / "binding.json").read_bytes()
            second = (root / "two" / "binding.json").read_bytes()
            self.assertEqual(first, second)
            self.assertEqual(first, first.rstrip(b"\n") + b"\n")
            parsed = json.loads(first)
            self.assertEqual(list(parsed), sorted(parsed))
            self.assertEqual(
                parsed["body_sha256"],
                hashlib.sha256(
                    (root / "one" / "pr-comment.md").read_bytes()
                ).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()

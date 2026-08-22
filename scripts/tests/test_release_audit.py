from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "release-audit.py"
SPEC = importlib.util.spec_from_file_location("release_audit", SCRIPT)
assert SPEC and SPEC.loader
release_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_audit)


class ReleaseAuditTests(unittest.TestCase):
    CHECK_SHA = "a" * 40

    def roadmap(self):
        return {
            "schema_version": 1,
            "milestones": [
                {"id": "first", "release": "v1.0.0", "status": "released"},
                {"id": "audit", "release": "v1.1.0", "status": "current"},
            ],
        }

    def required_check_runs(self):
        return [
            {
                "id": index,
                "name": name,
                "head_sha": self.CHECK_SHA,
                "app": {"id": release_audit.GITHUB_ACTIONS_APP_ID},
                "status": "completed",
                "conclusion": "success",
            }
            for index, name in enumerate(sorted(release_audit.REQUIRED_CHECKS), 1)
        ]

    @staticmethod
    def check_run_pages(check_runs):
        return [{"total_count": len(check_runs), "check_runs": check_runs}]

    def test_accepts_a_closed_ordered_roadmap(self):
        self.assertEqual(
            release_audit.validate_roadmap(self.roadmap(), "1.1.0"),
            ["v1.0.0", "v1.1.0"],
        )

    def test_accepts_an_explicitly_bundled_milestone_without_a_tag(self):
        roadmap = {
            "schema_version": 1,
            "milestones": [
                {"id": "first", "release": "v1.0.0", "status": "released"},
                {"id": "bundled", "release": "v1.1.0", "status": "bundled"},
                {"id": "audit", "release": "v1.2.0", "status": "current"},
            ],
        }
        self.assertEqual(
            release_audit.validate_roadmap(roadmap, "1.2.0"),
            ["v1.0.0", "v1.2.0"],
        )

    def test_rejects_duplicate_or_mismatched_roadmaps(self):
        roadmap = self.roadmap()
        roadmap["milestones"][1]["id"] = "first"
        with self.assertRaises(release_audit.AuditError):
            release_audit.validate_roadmap(roadmap, "1.1.0")
        with self.assertRaises(release_audit.AuditError):
            release_audit.validate_roadmap(self.roadmap(), "1.2.0")

    def test_rejects_unbounded_roadmap_work(self):
        roadmap = self.roadmap()
        roadmap["milestones"] = [
            {
                "id": f"release-{index}",
                "release": f"v1.{index}.0",
                "status": "current" if index == release_audit.MAX_ROADMAP_MILESTONES else "released",
            }
            for index in range(release_audit.MAX_ROADMAP_MILESTONES + 1)
        ]
        with self.assertRaisesRegex(release_audit.AuditError, "milestones"):
            release_audit.validate_roadmap(
                roadmap, f"1.{release_audit.MAX_ROADMAP_MILESTONES}.0"
            )

    def test_roadmap_work_honors_aggregate_deadline(self):
        with self.assertRaises(release_audit.ExecutionBoundaryError):
            release_audit.validate_roadmap(
                self.roadmap(), "1.1.0", deadline=release_audit.Deadline(0)
            )

    def test_accepts_the_exact_release_asset_contract(self):
        tag = "v1.1.0"
        release_audit.validate_release(
            {
                "tag_name": tag,
                "target_commitish": "main",
                "draft": False,
                "prerelease": False,
                "assets": [
                    {"name": name, "size": 1, "state": "uploaded"}
                    for name in release_audit.expected_assets(tag)
                ],
            },
            tag,
            "a" * 40,
            allow_draft=False,
        )

    def test_rejects_missing_release_assets(self):
        with self.assertRaises(release_audit.AuditError):
            release_audit.validate_release(
                {
                    "tag_name": "v1.1.0",
                    "target_commitish": "main",
                    "draft": False,
                    "prerelease": False,
                    "assets": [],
                },
                "v1.1.0",
                "a" * 40,
                allow_draft=False,
            )

    def test_rejects_non_object_release_and_asset_metadata(self):
        malformed_asset_release = {
            "tag_name": "v1.1.0",
            "target_commitish": "main",
            "draft": False,
            "prerelease": False,
            "assets": [None],
        }
        for release in ([], malformed_asset_release):
            with self.subTest(release=release):
                with self.assertRaises(release_audit.AuditError):
                    release_audit.validate_release(
                        release,
                        "v1.1.0",
                        "a" * 40,
                        allow_draft=False,
                    )

    def test_rejects_oversized_or_boolean_release_asset_sizes(self):
        tag = "v1.1.0"
        assets = [
            {"name": name, "size": 1, "state": "uploaded"}
            for name in release_audit.expected_assets(tag)
        ]
        assets[0]["size"] = release_audit.asset_size_limit(assets[0]["name"]) + 1
        with self.assertRaisesRegex(release_audit.AuditError, "exceeds"):
            release_audit.validate_release(
                {
                    "tag_name": tag,
                    "target_commitish": "main",
                    "draft": False,
                    "prerelease": False,
                    "assets": assets,
                },
                tag,
                "a" * 40,
                allow_draft=False,
            )
        assets[0]["size"] = True
        with self.assertRaisesRegex(release_audit.AuditError, "incomplete"):
            release_audit.validate_release(
                {
                    "tag_name": tag,
                    "target_commitish": "main",
                    "draft": False,
                    "prerelease": False,
                    "assets": assets,
                },
                tag,
                "a" * 40,
                allow_draft=False,
            )

    def test_finds_draft_release_through_paginated_collection(self):
        pages = [
            [{"tag_name": "v1.0.0", "draft": False}],
            [{"tag_name": "v1.1.0", "draft": True}],
        ]
        with mock.patch.object(
            release_audit, "run", return_value=json.dumps(pages)
        ) as command:
            release = release_audit.github_release_by_tag("owner/repo", "v1.1.0")
        self.assertTrue(release["draft"])
        command.assert_called_once_with(
            "gh",
            "api",
            "--paginate",
            "--slurp",
            "repos/owner/repo/releases?per_page=100",
        )

    def test_rejects_missing_or_duplicate_release_lookup(self):
        with mock.patch.object(release_audit, "run", return_value="[[]]"):
            with self.assertRaises(release_audit.AuditError):
                release_audit.github_release_by_tag("owner/repo", "v1.1.0")

    def test_rejects_unbounded_release_collection_pages(self):
        pages = json.dumps([[]] * 101)
        with mock.patch.object(release_audit, "run", return_value=pages):
            with self.assertRaisesRegex(release_audit.AuditError, "100 pages"):
                release_audit.github_release_by_tag("owner/repo", "v1.1.0")

    def test_rejects_non_object_release_collection_entries(self):
        with mock.patch.object(release_audit, "run", return_value="[[null]]"):
            with self.assertRaisesRegex(release_audit.AuditError, "entries"):
                release_audit.github_release_by_tag("owner/repo", "v1.1.0")
        duplicate = json.dumps(
            [[{"tag_name": "v1.1.0"}], [{"tag_name": "v1.1.0"}]]
        )
        with mock.patch.object(release_audit, "run", return_value=duplicate):
            with self.assertRaises(release_audit.AuditError):
                release_audit.github_release_by_tag("owner/repo", "v1.1.0")

    def test_fetches_latest_github_actions_check_runs_with_bounds(self):
        pages = self.check_run_pages(self.required_check_runs())
        deadline = mock.Mock()
        with mock.patch.object(
            release_audit, "run", return_value=json.dumps(pages)
        ) as command:
            release_audit.github_required_check_runs(
                "owner/repo", self.CHECK_SHA, deadline=deadline
            )
        command.assert_called_once_with(
            "gh",
            "api",
            "--paginate",
            "--slurp",
            (
                f"repos/owner/repo/commits/{self.CHECK_SHA}/check-runs"
                f"?app_id={release_audit.GITHUB_ACTIONS_APP_ID}"
                "&filter=latest&per_page=100"
            ),
            max_stdout_bytes=release_audit.MAX_CHECK_RUNS_RESPONSE_BYTES,
            deadline=deadline,
        )
        deadline.remaining.assert_called_once_with()

    def test_check_required_runs_flag_gates_the_expected_commit(self):
        arguments = [
            "release-audit.py",
            "--repository",
            "owner/repo",
            "--tag",
            "v1.1.0",
            "--expected-sha",
            self.CHECK_SHA,
            "--allow-draft",
            "--skip-download",
            "--check-required-runs",
        ]
        with (
            mock.patch.object(release_audit.sys, "argv", arguments),
            mock.patch.object(release_audit, "workspace_version", return_value="1.1.0"),
            mock.patch.object(release_audit, "read_text", return_value="{}"),
            mock.patch.object(
                release_audit, "validate_roadmap", return_value=["v1.1.0"]
            ),
            mock.patch.object(
                release_audit,
                "run",
                side_effect=["", f"{self.CHECK_SHA}\n"],
            ),
            mock.patch.object(release_audit, "github_release_by_tag", return_value={}),
            mock.patch.object(release_audit, "validate_release"),
            mock.patch.object(release_audit, "github_required_check_runs") as checks,
        ):
            self.assertEqual(release_audit.main(), 0)
        checks.assert_called_once()
        self.assertEqual(checks.call_args.args, ("owner/repo", self.CHECK_SHA))
        self.assertIsInstance(checks.call_args.kwargs["deadline"], release_audit.Deadline)

    def test_accepts_exact_successful_required_check_runs(self):
        runs = self.required_check_runs()
        runs.append(
            {
                "id": 100,
                "name": "Unrelated",
                "head_sha": self.CHECK_SHA,
            }
        )
        release_audit.validate_required_check_runs(
            self.check_run_pages(runs), self.CHECK_SHA
        )

    def test_rejects_missing_or_duplicate_required_check_runs(self):
        runs = self.required_check_runs()
        with self.assertRaisesRegex(release_audit.AuditError, "exactly one"):
            release_audit.validate_required_check_runs(
                self.check_run_pages(runs[:-1]), self.CHECK_SHA
            )

        duplicate = dict(runs[0], id=99)
        with self.assertRaisesRegex(release_audit.AuditError, "exactly one"):
            release_audit.validate_required_check_runs(
                self.check_run_pages([*runs, duplicate]), self.CHECK_SHA
            )

        duplicate_id = dict(runs[0], name="Unrelated")
        with self.assertRaisesRegex(release_audit.AuditError, "duplicate check-run id"):
            release_audit.validate_required_check_runs(
                self.check_run_pages([*runs, duplicate_id]), self.CHECK_SHA
            )

    def test_rejects_failed_or_in_progress_required_check_runs(self):
        for replacement, message in (
            ({"status": "completed", "conclusion": "failure"}, "did not succeed"),
            ({"status": "in_progress", "conclusion": None}, "not completed"),
        ):
            with self.subTest(replacement=replacement):
                runs = self.required_check_runs()
                runs[0].update(replacement)
                with self.assertRaisesRegex(release_audit.AuditError, message):
                    release_audit.validate_required_check_runs(
                        self.check_run_pages(runs), self.CHECK_SHA
                    )

    def test_rejects_wrong_or_malformed_required_check_run_app(self):
        for app in ({"id": 1}, {"id": True}, None, []):
            with self.subTest(app=app):
                runs = self.required_check_runs()
                runs[0]["app"] = app
                with self.assertRaises(release_audit.AuditError):
                    release_audit.validate_required_check_runs(
                        self.check_run_pages(runs), self.CHECK_SHA
                    )

    def test_rejects_check_runs_for_another_commit(self):
        runs = self.required_check_runs()
        runs[0]["head_sha"] = "b" * 40
        with self.assertRaisesRegex(release_audit.AuditError, "expected SHA"):
            release_audit.validate_required_check_runs(
                self.check_run_pages(runs), self.CHECK_SHA
            )

    def test_rejects_malformed_check_run_response_objects(self):
        runs = self.required_check_runs()
        malformed = (
            None,
            {},
            [],
            [None],
            [{"total_count": len(runs), "check_runs": runs, "extra": True}],
            [{"total_count": len(runs), "check_runs": [None]}],
            [{"total_count": len(runs), "check_runs": {}}],
        )
        for pages in malformed:
            with self.subTest(pages=pages):
                with self.assertRaises(release_audit.AuditError):
                    release_audit.validate_required_check_runs(pages, self.CHECK_SHA)

    def test_rejects_invalid_or_inconsistent_check_run_counts(self):
        runs = self.required_check_runs()
        malformed = (
            [{"total_count": True, "check_runs": runs}],
            [{"total_count": -1, "check_runs": runs}],
            [{"total_count": len(runs) + 1, "check_runs": runs}],
            [
                {"total_count": len(runs), "check_runs": runs[:2]},
                {"total_count": len(runs) + 1, "check_runs": runs[2:]},
            ],
        )
        for pages in malformed:
            with self.subTest(pages=pages):
                with self.assertRaises(release_audit.AuditError):
                    release_audit.validate_required_check_runs(pages, self.CHECK_SHA)

    def test_rejects_oversized_check_run_pages_and_lists(self):
        runs = self.required_check_runs()
        too_many_pages = [
            {"total_count": len(runs), "check_runs": []}
            for _ in range(release_audit.MAX_CHECK_RUN_PAGES + 1)
        ]
        with self.assertRaisesRegex(release_audit.AuditError, "bounded"):
            release_audit.validate_required_check_runs(
                too_many_pages, self.CHECK_SHA
            )

        oversized_list = [
            dict(runs[0], id=index + 1, name=f"check-{index}")
            for index in range(release_audit.MAX_CHECK_RUNS_PER_PAGE + 1)
        ]
        with self.assertRaisesRegex(release_audit.AuditError, "exceeds"):
            release_audit.validate_required_check_runs(
                [{"total_count": len(oversized_list), "check_runs": oversized_list}],
                self.CHECK_SHA,
            )

        with self.assertRaisesRegex(release_audit.AuditError, "total_count"):
            release_audit.validate_required_check_runs(
                [{"total_count": release_audit.MAX_CHECK_RUNS + 1, "check_runs": []}],
                self.CHECK_SHA,
            )

    def test_validates_checksums_and_spdx_documents(self):
        tag = "v1.1.0"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for target, extension in release_audit.TARGETS:
                archive = directory / f"pcbex-{tag}-{target}.{extension}"
                archive.write_bytes(target.encode())
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                (directory / f"{archive.name}.sha256").write_text(
                    f"{digest}  {archive.name}\n"
                )
                (directory / f"pcbex-{tag}-{target}.spdx.json").write_text(
                    json.dumps({"spdxVersion": "SPDX-2.3"})
                )
            release_audit.validate_downloaded_assets(directory, tag)

    def test_rejects_checksum_tampering(self):
        tag = "v1.1.0"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for target, extension in release_audit.TARGETS:
                archive = directory / f"pcbex-{tag}-{target}.{extension}"
                archive.write_bytes(target.encode())
                (directory / f"{archive.name}.sha256").write_text(
                    f"{'0' * 64}  {archive.name}\n"
                )
                (directory / f"pcbex-{tag}-{target}.spdx.json").write_text(
                    json.dumps({"spdxVersion": "SPDX-2.3"})
                )
            with self.assertRaises(release_audit.AuditError):
                release_audit.validate_downloaded_assets(directory, tag)

    def test_rejects_oversized_or_linked_downloaded_assets(self):
        tag = "v1.1.0"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            archives = []
            for target, extension in release_audit.TARGETS:
                archive = directory / f"pcbex-{tag}-{target}.{extension}"
                archive.write_bytes(target.encode())
                archives.append(archive)
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                (directory / f"{archive.name}.sha256").write_text(
                    f"{digest}  {archive.name}\n"
                )
                (directory / f"pcbex-{tag}-{target}.spdx.json").write_text(
                    json.dumps({"spdxVersion": "SPDX-2.3"})
                )
            archives[0].write_bytes(b"")
            with archives[0].open("wb") as stream:
                stream.truncate(release_audit.MAX_ARCHIVE_BYTES + 1)
            with self.assertRaisesRegex(release_audit.AuditError, "1 to"):
                release_audit.validate_downloaded_assets(directory, tag)

        if hasattr(os, "symlink"):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary).resolve()
                target = directory / "target"
                target.write_text("data")
                name = next(iter(release_audit.expected_assets(tag)))
                link = directory / name
                try:
                    link.symlink_to(target)
                except OSError:
                    return
                with self.assertRaises(release_audit.AuditError):
                    release_audit.validate_downloaded_assets(directory, tag)

    def test_run_delegates_to_bounded_process_and_rejects_nonzero(self):
        completed = SimpleNamespace(returncode=0, stdout=b"ok\n", stderr=b"")
        with mock.patch.object(
            release_audit, "run_bounded_command", return_value=completed
        ) as bounded:
            self.assertEqual(
                release_audit.run(
                    "git",
                    "status",
                    timeout_seconds=7,
                    max_stdout_bytes=123,
                ),
                "ok\n",
            )
        self.assertEqual(bounded.call_args.kwargs["timeout_seconds"], 7)
        self.assertEqual(bounded.call_args.kwargs["max_stdout_bytes"], 123)

        failed = SimpleNamespace(returncode=9, stdout=b"", stderr=b"failure")
        with mock.patch.object(
            release_audit, "run_bounded_command", return_value=failed
        ):
            with self.assertRaisesRegex(release_audit.AuditError, "status 9"):
                release_audit.run("git", "status")

    def test_accepts_required_main_protection(self):
        release_audit.validate_protection(
            {
                "required_status_checks": {
                    "strict": True,
                    "contexts": [
                        "Rust",
                        "Python",
                        "KiCad E2E",
                        "Deterministic Pipeline",
                    ],
                    "checks": [
                        {"context": "Rust", "app_id": 15368},
                        {"context": "Python", "app_id": 15368},
                        {"context": "KiCad E2E", "app_id": 15368},
                        {"context": "Deterministic Pipeline", "app_id": 15368},
                    ],
                },
                "required_pull_request_reviews": {
                    "required_approving_review_count": 0
                },
                "enforce_admins": {"enabled": True},
                "required_linear_history": {"enabled": True},
                "required_conversation_resolution": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
            }
        )

    def test_rejects_relaxed_main_protection(self):
        with self.assertRaises(release_audit.AuditError):
            release_audit.validate_protection(
                {
                    "required_status_checks": {
                        "strict": False,
                        "contexts": ["Rust"],
                    }
                }
            )

    def test_rejects_malformed_main_protection_shapes(self):
        for protection in (
            [],
            {"required_status_checks": []},
            {"required_status_checks": {"strict": True, "contexts": [None]}},
        ):
            with self.subTest(protection=protection):
                with self.assertRaises(release_audit.AuditError):
                    release_audit.validate_protection(protection)

    def test_rejects_missing_or_unpinned_required_check(self):
        base = {
            "required_status_checks": {
                "strict": True,
                "contexts": [
                    "Rust",
                    "Python",
                    "KiCad E2E",
                    "Deterministic Pipeline",
                ],
                "checks": [
                    {"context": "Rust", "app_id": 15368},
                    {"context": "Python", "app_id": 15368},
                    {"context": "KiCad E2E", "app_id": 15368},
                ],
            },
            "required_pull_request_reviews": {},
            "enforce_admins": {"enabled": True},
            "required_linear_history": {"enabled": True},
            "required_conversation_resolution": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
        }
        with self.assertRaisesRegex(
            release_audit.AuditError, "pinned to GitHub Actions"
        ):
            release_audit.validate_protection(base)

        base["required_status_checks"]["checks"].append(
            {"context": "Deterministic Pipeline", "app_id": 1}
        )
        with self.assertRaisesRegex(
            release_audit.AuditError, "pinned to GitHub Actions"
        ):
            release_audit.validate_protection(base)

    def test_accepts_enabled_actions_with_sha_pinning(self):
        release_audit.validate_actions_permissions(
            {
                "enabled": True,
                "allowed_actions": "all",
                "sha_pinning_required": True,
            }
        )

    def test_rejects_missing_or_false_actions_permissions(self):
        for permissions in (
            {"enabled": True, "sha_pinning_required": True},
            {"allowed_actions": "all", "sha_pinning_required": True},
            {"enabled": True, "allowed_actions": "all"},
            {
                "enabled": False,
                "allowed_actions": "all",
                "sha_pinning_required": True,
            },
            {
                "enabled": True,
                "allowed_actions": "all",
                "sha_pinning_required": False,
            },
        ):
            with self.subTest(permissions=permissions):
                with self.assertRaises(release_audit.AuditError):
                    release_audit.validate_actions_permissions(permissions)

    def test_rejects_non_boolean_or_unknown_actions_permissions(self):
        for permissions in (
            {
                "enabled": 1,
                "allowed_actions": "all",
                "sha_pinning_required": True,
            },
            {
                "enabled": True,
                "allowed_actions": "all",
                "sha_pinning_required": 1,
            },
            {
                "enabled": True,
                "allowed_actions": "all",
                "sha_pinning_required": True,
                "unexpected": False,
            },
            {
                "enabled": True,
                "sha_pinning_required": True,
                "allowed_actions": "invalid",
            },
            {
                "enabled": True,
                "allowed_actions": "selected",
                "sha_pinning_required": True,
                "selected_actions_url": 1,
            },
        ):
            with self.subTest(permissions=permissions):
                with self.assertRaises(release_audit.AuditError):
                    release_audit.validate_actions_permissions(permissions)

    def test_actions_permissions_api_failure_is_not_ignored(self):
        with mock.patch.object(
            release_audit,
            "run",
            side_effect=release_audit.AuditError("GitHub API unavailable"),
        ):
            with self.assertRaisesRegex(
                release_audit.AuditError, "GitHub API unavailable"
            ):
                release_audit.github_json("repos/owner/repo/actions/permissions")


if __name__ == "__main__":
    unittest.main()

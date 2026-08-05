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
    def roadmap(self):
        return {
            "schema_version": 1,
            "milestones": [
                {"id": "first", "release": "v1.0.0", "status": "released"},
                {"id": "audit", "release": "v1.1.0", "status": "current"},
            ],
        }

    def test_accepts_a_closed_ordered_roadmap(self):
        self.assertEqual(
            release_audit.validate_roadmap(self.roadmap(), "1.1.0"),
            ["v1.0.0", "v1.1.0"],
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

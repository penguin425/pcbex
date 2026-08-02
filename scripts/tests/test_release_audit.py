from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
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

    def test_accepts_required_main_protection(self):
        release_audit.validate_protection(
            {
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["Rust", "Python", "KiCad E2E"],
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

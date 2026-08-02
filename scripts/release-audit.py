#!/usr/bin/env python3
"""Audit a release and optional protected-main and Actions policy."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ROADMAP = ROOT / "docs" / "ROADMAP.json"
TARGETS = (
    ("aarch64-apple-darwin", "tar.gz"),
    ("x86_64-apple-darwin", "tar.gz"),
    ("x86_64-pc-windows-msvc", "zip"),
    ("x86_64-unknown-linux-gnu", "tar.gz"),
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
REQUIRED_CHECKS = {"Rust", "Python", "KiCad E2E"}


class AuditError(RuntimeError):
    """A release invariant was not satisfied."""


def run(*arguments: str) -> str:
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise AuditError(f"{' '.join(arguments)} failed: {detail}")
    return result.stdout


def workspace_version() -> str:
    document = tomllib.loads((ROOT / "Cargo.toml").read_text())
    return document["workspace"]["package"]["version"]


def expected_assets(tag: str) -> set[str]:
    return {
        name
        for target, extension in TARGETS
        for name in (
            f"pcbex-{tag}-{target}.{extension}",
            f"pcbex-{tag}-{target}.{extension}.sha256",
            f"pcbex-{tag}-{target}.spdx.json",
        )
    }


def parse_version(tag: str) -> tuple[int, int, int]:
    match = TAG_RE.fullmatch(tag)
    if not match:
        raise AuditError(f"invalid semantic-version tag: {tag}")
    return tuple(int(part) for part in match.groups())


def validate_roadmap(document: Any, version: str) -> list[str]:
    if not isinstance(document, dict) or set(document) != {"schema_version", "milestones"}:
        raise AuditError("roadmap must be a closed object")
    if document["schema_version"] != 1:
        raise AuditError("unsupported roadmap schema version")
    milestones = document["milestones"]
    if not isinstance(milestones, list) or not milestones:
        raise AuditError("roadmap must contain milestones")

    ids: set[str] = set()
    releases: list[str] = []
    current: list[str] = []
    for milestone in milestones:
        if not isinstance(milestone, dict) or set(milestone) != {
            "id",
            "release",
            "status",
        }:
            raise AuditError("every roadmap milestone must be a closed object")
        identifier = milestone["id"]
        release = milestone["release"]
        status = milestone["status"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identifier):
            raise AuditError(f"invalid milestone id: {identifier!r}")
        if identifier in ids:
            raise AuditError(f"duplicate milestone id: {identifier}")
        ids.add(identifier)
        parse_version(release)
        if status not in {"released", "current"}:
            raise AuditError(f"invalid milestone status: {status!r}")
        if status == "current":
            current.append(release)
        releases.append(release)

    parsed = [parse_version(release) for release in releases]
    if parsed != sorted(parsed) or len(set(parsed)) != len(parsed):
        raise AuditError("roadmap releases must be unique and strictly increasing")
    if current != [f"v{version}"] or releases[-1] != f"v{version}":
        raise AuditError("the sole current roadmap milestone must match the workspace version")
    return releases


def validate_release(
    release: Any,
    tag: str,
    expected_sha: str,
    *,
    allow_draft: bool,
) -> None:
    if release.get("tag_name") != tag:
        raise AuditError("release tag does not match")
    if release.get("prerelease") is not False:
        raise AuditError("release must not be a prerelease")
    if not isinstance(release.get("draft"), bool):
        raise AuditError("release draft state is missing")
    if release["draft"] and not allow_draft:
        raise AuditError("release is unexpectedly a draft")
    if release.get("target_commitish") not in {"main", expected_sha}:
        raise AuditError("release target is not main or the audited commit")

    assets = release.get("assets")
    if not isinstance(assets, list):
        raise AuditError("release assets are missing")
    names = [asset.get("name") for asset in assets]
    if len(names) != len(set(names)):
        raise AuditError("release contains duplicate asset names")
    if set(names) != expected_assets(tag):
        missing = sorted(expected_assets(tag) - set(names))
        extra = sorted(set(names) - expected_assets(tag))
        raise AuditError(f"release asset set mismatch; missing={missing}, extra={extra}")
    for asset in assets:
        if asset.get("state") != "uploaded" or not isinstance(asset.get("size"), int) or asset["size"] <= 0:
            raise AuditError(f"release asset is incomplete: {asset.get('name')}")


def validate_downloaded_assets(directory: Path, tag: str) -> None:
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != expected_assets(tag):
        raise AuditError("downloaded release asset set does not match")
    for target, extension in TARGETS:
        archive = directory / f"pcbex-{tag}-{target}.{extension}"
        checksum = directory / f"{archive.name}.sha256"
        fields = checksum.read_text().strip().split()
        if len(fields) != 2 or fields[1].lstrip("*") != archive.name:
            raise AuditError(f"invalid checksum file: {checksum.name}")
        if not SHA256_RE.fullmatch(fields[0]):
            raise AuditError(f"invalid SHA-256 encoding: {checksum.name}")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != fields[0]:
            raise AuditError(f"checksum mismatch: {archive.name}")
        sbom = directory / f"pcbex-{tag}-{target}.spdx.json"
        value = json.loads(sbom.read_text())
        if value.get("spdxVersion") != "SPDX-2.3":
            raise AuditError(f"invalid SPDX document: {sbom.name}")


def validate_protection(protection: Any) -> None:
    checks = protection.get("required_status_checks") or {}
    if checks.get("strict") is not True:
        raise AuditError("main protection must require an up-to-date branch")
    if not REQUIRED_CHECKS.issubset(set(checks.get("contexts") or [])):
        raise AuditError("main protection is missing required status checks")
    if protection.get("required_pull_request_reviews") is None:
        raise AuditError("main protection must require the pull-request workflow")
    if (protection.get("enforce_admins") or {}).get("enabled") is not True:
        raise AuditError("main protection must apply to administrators")
    for field in ("required_linear_history", "required_conversation_resolution"):
        if (protection.get(field) or {}).get("enabled") is not True:
            raise AuditError(f"main protection must enable {field}")
    for field in ("allow_force_pushes", "allow_deletions"):
        if (protection.get(field) or {}).get("enabled") is not False:
            raise AuditError(f"main protection must disable {field}")


def validate_actions_permissions(permissions: Any) -> None:
    """Require repository Actions to be enabled and SHA pinning enforced.

    The release gate does not constrain which documented ``allowed_actions``
    mode the repository uses, but it rejects missing fields, unexpected
    response members, and malformed known values.
    """

    if not isinstance(permissions, dict):
        raise AuditError("GitHub Actions permissions must be an object")
    required = {"enabled", "allowed_actions", "sha_pinning_required"}
    optional = {"selected_actions_url"}
    if set(permissions) - required - optional:
        raise AuditError("GitHub Actions permissions contain unknown fields")
    missing = required - set(permissions)
    if missing:
        raise AuditError(
            "GitHub Actions permissions are missing: "
            + ", ".join(sorted(missing))
        )
    for field in ("enabled", "sha_pinning_required"):
        if type(permissions[field]) is not bool:
            raise AuditError(
                f"GitHub Actions permission {field} must be a boolean"
            )
    if permissions["enabled"] is not True:
        raise AuditError("GitHub Actions must be enabled")
    if permissions["sha_pinning_required"] is not True:
        raise AuditError("GitHub Actions SHA pinning must be required")
    allowed_actions = permissions["allowed_actions"]
    if allowed_actions not in {"all", "local_only", "selected"}:
        raise AuditError("GitHub Actions allowed_actions is invalid")
    if "selected_actions_url" in permissions and (
        not isinstance(permissions["selected_actions_url"], str)
        or not permissions["selected_actions_url"].startswith("https://")
    ):
        raise AuditError("GitHub Actions selected_actions_url is invalid")


def github_json(endpoint: str) -> Any:
    return json.loads(run("gh", "api", endpoint))


def github_release_by_tag(repository: str, tag: str) -> Any:
    pages = json.loads(
        run(
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repository}/releases?per_page=100",
        )
    )
    matches = [
        release
        for page in pages
        for release in page
        if release.get("tag_name") == tag
    ]
    if len(matches) != 1:
        raise AuditError(
            f"expected exactly one release for {tag}, found {len(matches)}"
        )
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, help="owner/repository")
    parser.add_argument("--tag", help="release tag; defaults to workspace version")
    parser.add_argument("--expected-sha", help="commit expected behind the tag")
    parser.add_argument("--allow-draft", action="store_true")
    parser.add_argument("--check-protection", action="store_true")
    parser.add_argument("--skip-download", action="store_true")
    args = parser.parse_args()

    try:
        version = workspace_version()
        tag = args.tag or f"v{version}"
        roadmap = json.loads(ROADMAP.read_text())
        releases = validate_roadmap(roadmap, version)
        if tag not in releases:
            raise AuditError("tag is not recorded in the roadmap")
        for release_tag in releases:
            if release_tag == f"v{version}" and tag != release_tag:
                continue
            run("git", "rev-parse", "--verify", f"refs/tags/{release_tag}")

        tag_sha = run("git", "rev-list", "-n", "1", tag).strip()
        expected_sha = args.expected_sha or tag_sha
        if tag_sha != expected_sha:
            raise AuditError("tag does not resolve to the expected commit")

        # GitHub's "get by tag" endpoint returns 404 for draft releases.
        # The paginated release collection includes drafts for authorized callers.
        release = github_release_by_tag(args.repository, tag)
        validate_release(release, tag, expected_sha, allow_draft=args.allow_draft)

        if not args.skip_download:
            with tempfile.TemporaryDirectory(prefix="pcbex-release-audit-") as temporary:
                run(
                    "gh",
                    "release",
                    "download",
                    tag,
                    "--repo",
                    args.repository,
                    "--dir",
                    temporary,
                )
                validate_downloaded_assets(Path(temporary), tag)

        if args.check_protection:
            protection = github_json(
                f"repos/{args.repository}/branches/main/protection"
            )
            validate_protection(protection)
            actions_permissions = github_json(
                f"repos/{args.repository}/actions/permissions"
            )
            validate_actions_permissions(actions_permissions)
    except (AuditError, json.JSONDecodeError, OSError) as error:
        print(f"release audit failed: {error}", file=sys.stderr)
        return 1

    print(
        f"release audit passed: {tag}, {len(expected_assets(tag))} assets, "
        f"{len(releases)} roadmap milestones"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

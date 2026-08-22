#!/usr/bin/env python3
"""Audit a release and optional protected-main and Actions policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import tomllib
from typing import Any

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from ci_runtime import (
    Deadline,
    ExecutionBoundaryError,
    decode_utf8,
    read_bytes,
    read_text,
    run as run_bounded_command,
)

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
REQUIRED_CHECKS = {"Rust", "Python", "KiCad E2E", "Deterministic Pipeline"}
GITHUB_ACTIONS_APP_ID = 15368
MIB = 1024 * 1024
MAX_CONFIG_BYTES = MIB
MAX_ROADMAP_MILESTONES = 1024
MAX_COMMAND_STDOUT_BYTES = 16 * MIB
MAX_COMMAND_STDERR_BYTES = MIB
MAX_ARCHIVE_BYTES = 128 * MIB
MAX_CHECKSUM_BYTES = 4096
MAX_SBOM_BYTES = 16 * MIB
MAX_RELEASE_ASSET_BYTES = 640 * MIB
MAX_CHECK_RUN_PAGES = 10
MAX_CHECK_RUNS_PER_PAGE = 100
MAX_CHECK_RUNS = MAX_CHECK_RUN_PAGES * MAX_CHECK_RUNS_PER_PAGE
MAX_CHECK_RUNS_RESPONSE_BYTES = 8 * MIB
MAX_CHECK_RUN_NAME_BYTES = 1024
RELEASE_AUDIT_DEADLINE_SECONDS = 8 * 60


class AuditError(RuntimeError):
    """A release invariant was not satisfied."""


def run(
    *arguments: str,
    timeout_seconds: float = 60,
    max_stdout_bytes: int = MAX_COMMAND_STDOUT_BYTES,
    deadline: Deadline | None = None,
) -> str:
    result = run_bounded_command(
        arguments,
        cwd=ROOT,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=MAX_COMMAND_STDERR_BYTES,
        deadline=deadline,
    )
    if result.returncode:
        detail_bytes = result.stderr.strip() or result.stdout.strip()
        detail = detail_bytes.decode("utf-8", errors="replace")[:2048]
        raise AuditError(f"{arguments[0]} failed with status {result.returncode}: {detail}")
    return decode_utf8(result.stdout, role=f"{arguments[0]} stdout")


def workspace_version() -> str:
    document = tomllib.loads(
        read_text(ROOT / "Cargo.toml", max_bytes=MAX_CONFIG_BYTES)
    )
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


def validate_roadmap(
    document: Any, version: str, *, deadline: Deadline | None = None
) -> list[str]:
    if not isinstance(document, dict) or set(document) != {"schema_version", "milestones"}:
        raise AuditError("roadmap must be a closed object")
    if document["schema_version"] != 1:
        raise AuditError("unsupported roadmap schema version")
    milestones = document["milestones"]
    if not isinstance(milestones, list) or not milestones:
        raise AuditError("roadmap must contain milestones")
    if len(milestones) > MAX_ROADMAP_MILESTONES:
        raise AuditError(
            f"roadmap exceeds {MAX_ROADMAP_MILESTONES} milestones"
        )

    ids: set[str] = set()
    releases: list[str] = []
    tagged_releases: list[str] = []
    current: list[str] = []
    for milestone in milestones:
        if deadline is not None:
            deadline.remaining()
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
        if status not in {"released", "bundled", "current"}:
            raise AuditError(f"invalid milestone status: {status!r}")
        if status == "current":
            current.append(release)
        releases.append(release)
        if status != "bundled":
            tagged_releases.append(release)

    parsed = [parse_version(release) for release in releases]
    if parsed != sorted(parsed) or len(set(parsed)) != len(parsed):
        raise AuditError("roadmap releases must be unique and strictly increasing")
    if current != [f"v{version}"] or releases[-1] != f"v{version}":
        raise AuditError("the sole current roadmap milestone must match the workspace version")
    return tagged_releases


def validate_release(
    release: Any,
    tag: str,
    expected_sha: str,
    *,
    allow_draft: bool,
) -> None:
    if not isinstance(release, dict):
        raise AuditError("release metadata must be an object")
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
    if any(not isinstance(asset, dict) for asset in assets):
        raise AuditError("release assets must be objects")
    names = [asset.get("name") for asset in assets]
    if any(not isinstance(name, str) for name in names):
        raise AuditError("release asset names must be strings")
    if len(names) != len(set(names)):
        raise AuditError("release contains duplicate asset names")
    if set(names) != expected_assets(tag):
        missing = sorted(expected_assets(tag) - set(names))
        extra = sorted(set(names) - expected_assets(tag))
        raise AuditError(f"release asset set mismatch; missing={missing}, extra={extra}")
    total_bytes = 0
    for asset in assets:
        name = asset["name"]
        size = asset.get("size")
        if (
            asset.get("state") != "uploaded"
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
        ):
            raise AuditError(f"release asset is incomplete: {asset.get('name')}")
        limit = asset_size_limit(name)
        if size > limit:
            raise AuditError(
                f"release asset exceeds {limit} bytes: {name}"
            )
        total_bytes += size
        if total_bytes > MAX_RELEASE_ASSET_BYTES:
            raise AuditError(
                f"release assets exceed {MAX_RELEASE_ASSET_BYTES} aggregate bytes"
            )


def asset_size_limit(name: str) -> int:
    if name.endswith(".sha256"):
        return MAX_CHECKSUM_BYTES
    if name.endswith(".spdx.json"):
        return MAX_SBOM_BYTES
    return MAX_ARCHIVE_BYTES


def _release_directory_entries(directory: Path) -> dict[str, os.stat_result]:
    entries: dict[str, os.stat_result] = {}
    try:
        iterator = os.scandir(directory)
    except OSError as error:
        raise AuditError(f"cannot enumerate downloaded assets: {directory}") from error
    with iterator:
        for entry in iterator:
            if len(entries) >= len(expected_assets("v0.0.0")):
                raise AuditError("downloaded release contains too many entries")
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise AuditError(
                    f"cannot inspect downloaded release asset: {entry.name}"
                ) from error
            if (
                entry.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or bool((getattr(metadata, "st_file_attributes", 0) or 0) & 0x400)
            ):
                raise AuditError(
                    f"downloaded release entry is not a regular file: {entry.name}"
                )
            if entry.name in entries:
                raise AuditError(f"duplicate downloaded release asset: {entry.name}")
            entries[entry.name] = metadata
    return entries


def validate_downloaded_assets(
    directory: Path, tag: str, *, deadline: Deadline | None = None
) -> None:
    if deadline is not None:
        deadline.remaining()
    entries = _release_directory_entries(directory)
    if set(entries) != expected_assets(tag):
        raise AuditError("downloaded release asset set does not match")
    total_bytes = 0
    for name, metadata in entries.items():
        limit = asset_size_limit(name)
        if metadata.st_size <= 0 or metadata.st_size > limit:
            raise AuditError(
                f"downloaded release asset must contain 1 to {limit} bytes: {name}"
            )
        total_bytes += metadata.st_size
        if total_bytes > MAX_RELEASE_ASSET_BYTES:
            raise AuditError(
                f"downloaded release assets exceed {MAX_RELEASE_ASSET_BYTES} aggregate bytes"
            )
    observed_bytes = 0

    def load(path: Path) -> bytes:
        nonlocal observed_bytes
        if deadline is not None:
            deadline.remaining()
        payload = read_bytes(path, max_bytes=asset_size_limit(path.name))
        if deadline is not None:
            deadline.remaining()
        observed_bytes += len(payload)
        if observed_bytes > MAX_RELEASE_ASSET_BYTES:
            raise AuditError(
                f"downloaded release assets exceed {MAX_RELEASE_ASSET_BYTES} aggregate bytes"
            )
        return payload

    for target, extension in TARGETS:
        if deadline is not None:
            deadline.remaining()
        archive = directory / f"pcbex-{tag}-{target}.{extension}"
        checksum = directory / f"{archive.name}.sha256"
        fields = decode_utf8(load(checksum), role=checksum.name).strip().split()
        if len(fields) != 2 or fields[1].lstrip("*") != archive.name:
            raise AuditError(f"invalid checksum file: {checksum.name}")
        if not SHA256_RE.fullmatch(fields[0]):
            raise AuditError(f"invalid SHA-256 encoding: {checksum.name}")
        digest = hashlib.sha256(load(archive)).hexdigest()
        if digest != fields[0]:
            raise AuditError(f"checksum mismatch: {archive.name}")
        sbom = directory / f"pcbex-{tag}-{target}.spdx.json"
        value = json.loads(decode_utf8(load(sbom), role=sbom.name))
        if not isinstance(value, dict) or value.get("spdxVersion") != "SPDX-2.3":
            raise AuditError(f"invalid SPDX document: {sbom.name}")


def validate_protection(protection: Any) -> None:
    if not isinstance(protection, dict):
        raise AuditError("main protection must be an object")
    checks = protection.get("required_status_checks")
    if not isinstance(checks, dict):
        raise AuditError("main protection status checks must be an object")
    if checks.get("strict") is not True:
        raise AuditError("main protection must require an up-to-date branch")
    contexts = checks.get("contexts")
    if not isinstance(contexts, list) or any(
        not isinstance(context, str) for context in contexts
    ):
        raise AuditError("main protection status-check contexts must be strings")
    if not REQUIRED_CHECKS.issubset(set(contexts)):
        raise AuditError("main protection is missing required status checks")
    protected_checks = checks.get("checks")
    if not isinstance(protected_checks, list):
        raise AuditError("main protection status checks must pin their GitHub Apps")
    pinned_checks: dict[str, int] = {}
    for protected_check in protected_checks:
        if not isinstance(protected_check, dict):
            raise AuditError("main protection status-check bindings must be objects")
        context = protected_check.get("context")
        app_id = protected_check.get("app_id")
        if not isinstance(context, str) or type(app_id) is not int:
            raise AuditError(
                "main protection status-check bindings must contain a context and app_id"
            )
        if context in pinned_checks and pinned_checks[context] != app_id:
            raise AuditError("main protection status-check bindings conflict")
        pinned_checks[context] = app_id
    if any(
        pinned_checks.get(context) != GITHUB_ACTIONS_APP_ID
        for context in REQUIRED_CHECKS
    ):
        raise AuditError("main protection required checks must be pinned to GitHub Actions")
    if not isinstance(protection.get("required_pull_request_reviews"), dict):
        raise AuditError("main protection must require the pull-request workflow")
    enforce_admins = protection.get("enforce_admins")
    if not isinstance(enforce_admins, dict) or enforce_admins.get("enabled") is not True:
        raise AuditError("main protection must apply to administrators")
    for field in ("required_linear_history", "required_conversation_resolution"):
        value = protection.get(field)
        if not isinstance(value, dict) or value.get("enabled") is not True:
            raise AuditError(f"main protection must enable {field}")
    for field in ("allow_force_pushes", "allow_deletions"):
        value = protection.get(field)
        if not isinstance(value, dict) or value.get("enabled") is not False:
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


def validate_required_check_runs(pages: Any, expected_sha: str) -> None:
    """Validate a bounded ``filter=latest`` check-runs response for a commit."""

    if (
        not isinstance(expected_sha, str)
        or re.fullmatch(r"[0-9a-f]{40}", expected_sha) is None
    ):
        raise AuditError(
            "expected check-runs SHA must be a lowercase 40-character hex SHA"
        )
    if (
        not isinstance(pages, list)
        or not pages
        or len(pages) > MAX_CHECK_RUN_PAGES
    ):
        raise AuditError("check-runs response must be a bounded non-empty page list")

    total_count: int | None = None
    check_runs: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for page in pages:
        if not isinstance(page, dict) or set(page) != {"total_count", "check_runs"}:
            raise AuditError("check-runs page has an unexpected shape")
        page_total_count = page["total_count"]
        page_check_runs = page["check_runs"]
        if (
            type(page_total_count) is not int
            or page_total_count < 0
            or page_total_count > MAX_CHECK_RUNS
        ):
            raise AuditError("check-runs total_count is invalid or exceeds the bound")
        if total_count is None:
            total_count = page_total_count
        elif page_total_count != total_count:
            raise AuditError("check-runs pages disagree on total_count")
        if (
            not isinstance(page_check_runs, list)
            or len(page_check_runs) > MAX_CHECK_RUNS_PER_PAGE
        ):
            raise AuditError("check-runs page list is invalid or exceeds the bound")

        for check_run in page_check_runs:
            if not isinstance(check_run, dict):
                raise AuditError("check-runs entry must be an object")
            run_id = check_run.get("id")
            name = check_run.get("name")
            head_sha = check_run.get("head_sha")
            if type(run_id) is not int or run_id <= 0:
                raise AuditError("check-run id must be a positive integer")
            if run_id in seen_ids:
                raise AuditError(f"duplicate check-run id: {run_id}")
            seen_ids.add(run_id)
            if (
                not isinstance(name, str)
                or not name
                or len(name.encode("utf-8")) > MAX_CHECK_RUN_NAME_BYTES
            ):
                raise AuditError("check-run name is invalid or exceeds the bound")
            if head_sha != expected_sha:
                raise AuditError(f"check-run {name!r} does not bind to expected SHA")
            check_runs.append(check_run)

    if total_count is None or len(check_runs) != total_count:
        raise AuditError("check-runs total_count does not match the returned list")
    if len(check_runs) > MAX_CHECK_RUNS:
        raise AuditError("check-runs response exceeds the aggregate bound")

    required_by_name: dict[str, list[dict[str, Any]]] = {}
    for check_run in check_runs:
        name = check_run["name"]
        if name in REQUIRED_CHECKS:
            required_by_name.setdefault(name, []).append(check_run)

    for context in sorted(REQUIRED_CHECKS):
        matching = required_by_name.get(context, [])
        if len(matching) != 1:
            raise AuditError(
                f"required check {context!r} must have exactly one latest check-run"
            )
        check_run = matching[0]
        app = check_run.get("app")
        if not isinstance(app, dict) or type(app.get("id")) is not int:
            raise AuditError(f"required check {context!r} has an invalid app")
        if app["id"] != GITHUB_ACTIONS_APP_ID:
            raise AuditError(
                f"required check {context!r} is not pinned to GitHub Actions"
            )
        if check_run.get("status") != "completed":
            raise AuditError(f"required check {context!r} is not completed")
        if check_run.get("conclusion") != "success":
            raise AuditError(f"required check {context!r} did not succeed")


def github_json(endpoint: str, *, deadline: Deadline | None = None) -> Any:
    return json.loads(run("gh", "api", endpoint, deadline=deadline))


def github_required_check_runs(
    repository: str,
    expected_sha: str,
    *,
    deadline: Deadline | None = None,
) -> None:
    run_options: dict[str, Any] = {
        "max_stdout_bytes": MAX_CHECK_RUNS_RESPONSE_BYTES,
    }
    if deadline is not None:
        run_options["deadline"] = deadline
    pages = json.loads(
        run(
            "gh",
            "api",
            "--paginate",
            "--slurp",
            (
                f"repos/{repository}/commits/{expected_sha}/check-runs"
                f"?app_id={GITHUB_ACTIONS_APP_ID}&filter=latest&per_page=100"
            ),
            **run_options,
        )
    )
    if deadline is not None:
        deadline.remaining()
    validate_required_check_runs(pages, expected_sha)


def github_release_by_tag(
    repository: str, tag: str, *, deadline: Deadline | None = None
) -> Any:
    run_options = {} if deadline is None else {"deadline": deadline}
    pages = json.loads(
        run(
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repository}/releases?per_page=100",
            **run_options,
        )
    )
    if deadline is not None:
        deadline.remaining()
    if not isinstance(pages, list) or len(pages) > 100:
        raise AuditError("GitHub release collection exceeds 100 pages")
    if any(not isinstance(page, list) or len(page) > 100 for page in pages):
        raise AuditError("GitHub release collection page is invalid")
    if any(not isinstance(release, dict) for page in pages for release in page):
        raise AuditError("GitHub release collection entries must be objects")
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
    parser.add_argument("--check-required-runs", action="store_true")
    parser.add_argument("--skip-download", action="store_true")
    args = parser.parse_args()

    try:
        deadline = Deadline.start(RELEASE_AUDIT_DEADLINE_SECONDS)
        version = workspace_version()
        tag = args.tag or f"v{version}"
        roadmap = json.loads(read_text(ROADMAP, max_bytes=MAX_CONFIG_BYTES))
        releases = validate_roadmap(roadmap, version, deadline=deadline)
        if tag not in releases:
            raise AuditError("tag is not recorded in the roadmap")
        for release_tag in releases:
            if release_tag == f"v{version}" and tag != release_tag:
                continue
            run(
                "git",
                "rev-parse",
                "--verify",
                f"refs/tags/{release_tag}",
                timeout_seconds=30,
                max_stdout_bytes=64 * 1024,
                deadline=deadline,
            )

        tag_sha = run(
            "git",
            "rev-list",
            "-n",
            "1",
            tag,
            timeout_seconds=30,
            max_stdout_bytes=64 * 1024,
            deadline=deadline,
        ).strip()
        expected_sha = args.expected_sha or tag_sha
        if tag_sha != expected_sha:
            raise AuditError("tag does not resolve to the expected commit")

        # GitHub's "get by tag" endpoint returns 404 for draft releases.
        # The paginated release collection includes drafts for authorized callers.
        release = github_release_by_tag(args.repository, tag, deadline=deadline)
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
                    timeout_seconds=240,
                    max_stdout_bytes=MIB,
                    deadline=deadline,
                )
                validate_downloaded_assets(
                    Path(temporary).resolve(), tag, deadline=deadline
                )

        if args.check_protection:
            protection = github_json(
                f"repos/{args.repository}/branches/main/protection",
                deadline=deadline,
            )
            validate_protection(protection)
            actions_permissions = github_json(
                f"repos/{args.repository}/actions/permissions",
                deadline=deadline,
            )
            validate_actions_permissions(actions_permissions)
        if args.check_required_runs:
            github_required_check_runs(
                args.repository,
                expected_sha,
                deadline=deadline,
            )
        deadline.remaining()
    except (
        AuditError,
        ExecutionBoundaryError,
        json.JSONDecodeError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        print(f"release audit failed: {error}", file=sys.stderr)
        return 1

    print(
        f"release audit passed: {tag}, {len(expected_assets(tag))} assets, "
        f"{len(releases)} roadmap milestones"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

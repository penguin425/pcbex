#!/usr/bin/env python3
"""Publish a CI pull-request report from a trusted ``workflow_run``.

This command is deliberately a small trust boundary.  It accepts only a
completed, successful run from the repository's protected CI workflow, binds
the downloaded artifact to the exact run/attempt and the current pull request,
and delegates the final marker-addressed write to ``upsert-pr-comment.py``.
The workflow which invokes this script must be a default-branch
``workflow_run`` job; this script never treats an arbitrary event as trusted.
"""

from __future__ import annotations

import hashlib
import html
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Mapping, Sequence
from urllib import error, parse, request
import zipfile


EXPECTED_WORKFLOW_NAME = "CI"
EXPECTED_WORKFLOW_PATH = ".github/workflows/ci.yml"
EXPECTED_WORKFLOW_EVENT = "pull_request"
EXPECTED_RUN_STATUS = "completed"
EXPECTED_RUN_CONCLUSION = "success"
EXPECTED_BINDING_SCHEMA_VERSION = 1
EXPECTED_ARTIFACT_PREFIX = "pcbex-pr-comment-"
EXPECTED_COMMENT_ID = "action-smoke"
EXPECTED_AUTHOR_LOGIN = "github-actions[bot]"
MAX_EVENT_BYTES = 1 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1 * 1024 * 1024
MAX_ARTIFACT_REDIRECTS = 5
MAX_ZIP_FILES = 2
MAX_ZIP_UNCOMPRESSED_BYTES = 1 * 1024 * 1024
MAX_BINDING_BYTES = 64 * 1024
MAX_BODY_BYTES = 262_144
MAX_COMMENT_CHARACTERS = 65_536
MAX_API_PAGES = 100
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HEX_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40,64}$")

EXPECTED_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "repository_id",
        "workflow_name",
        "workflow_path",
        "run_id",
        "run_attempt",
        "pr_number",
        "head_sha",
        "head_ref",
        "head_repository",
        "head_repository_id",
        "base_sha",
        "base_ref",
        "base_repository",
        "base_repository_id",
        "comment_id",
        "body_path",
        "body_bytes",
        "body_sha256",
    }
)


class PublisherError(RuntimeError):
    """A malformed trust input or an unrecoverable GitHub API failure."""


class SkipPublication(RuntimeError):
    """The run is stale, closed, or otherwise superseded; skip safely."""


class _DuplicateKeyError(ValueError):
    pass


def _closed_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json(data: bytes, description: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_closed_json_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError) as exc:
        raise PublisherError(f"{description} is not valid UTF-8 JSON") from exc


def _require_mapping(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PublisherError(f"{description} must be a JSON object")
    return value


def _require_string(value: Any, field: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise PublisherError(f"invalid {field}")
    return value


def _require_int(value: Any, field: str, *, positive: bool = True) -> int:
    # bool is an int subclass, but is never valid for a contract number.
    if isinstance(value, bool) or not isinstance(value, int):
        raise PublisherError(f"invalid {field}")
    if positive and value <= 0:
        raise PublisherError(f"invalid {field}")
    return value


def _repository(value: Any, field: str) -> str:
    value = _require_string(value, field)
    if not REPOSITORY_PATTERN.fullmatch(value):
        raise PublisherError(f"invalid {field}")
    return value


def _sha(value: Any, field: str) -> str:
    value = _require_string(value, field)
    if not HEX_SHA_PATTERN.fullmatch(value):
        raise PublisherError(f"invalid {field}")
    return value.lower()


def _same(actual: Any, expected: Any, field: str) -> None:
    if actual != expected:
        raise PublisherError(f"{field} does not match the trusted event")


def _nested(mapping: Mapping[str, Any], key: str, description: str) -> dict[str, Any]:
    return _require_mapping(mapping.get(key), description)


def _repository_object(
    mapping: Mapping[str, Any], key: str, description: str
) -> dict[str, Any]:
    value = _nested(mapping, key, description)
    repository_id = _require_int(value.get("id"), f"{description} id")
    full_name = _repository(value.get("full_name"), f"{description} full_name")
    name = _require_string(value.get("name"), f"{description} name")
    if full_name.rsplit("/", 1)[-1] != name:
        raise PublisherError(f"{description} name does not match full_name")
    return {
        "id": repository_id,
        "full_name": full_name,
        "name": name,
    }


def _validate_repository_url(
    value: Any,
    full_name: str,
    description: str,
    *,
    api_url: str | None = None,
) -> None:
    url = _require_string(value, f"{description} url")
    parsed = parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise PublisherError(f"invalid {description} url")
    if parsed.query or parsed.fragment:
        raise PublisherError(f"invalid {description} url")
    actual_path = parsed.path.rstrip("/")
    api_base_path = ""
    if api_url is not None:
        api_parsed = parse.urlparse(api_url)
        if api_parsed.scheme != "https" or not api_parsed.netloc:
            raise PublisherError("GitHub API URL must be an absolute HTTPS URL")
        if parsed.netloc.lower() != api_parsed.netloc.lower():
            raise PublisherError(f"{description} url host does not match GitHub API")
        api_base_path = api_parsed.path.rstrip("/")
    expected_path = f"{api_base_path}/repos/{full_name}"
    if actual_path != expected_path:
        raise PublisherError(f"{description} url does not match repository")


def _event_workflow_run(event: Mapping[str, Any], repository: str) -> dict[str, Any]:
    if event.get("action") != "completed":
        raise PublisherError("workflow_run event action must be completed")
    event_repository = _nested(event, "repository", "event repository")
    _same(event_repository.get("full_name"), repository, "event repository")
    run = _nested(event, "workflow_run", "workflow_run")
    run_repository = _nested(run, "repository", "workflow_run repository")
    _same(run_repository.get("full_name"), repository, "workflow_run repository")
    _same(run.get("name"), EXPECTED_WORKFLOW_NAME, "workflow name")
    _same(run.get("path"), EXPECTED_WORKFLOW_PATH, "workflow path")
    _same(run.get("event"), EXPECTED_WORKFLOW_EVENT, "workflow event")
    _same(run.get("status"), EXPECTED_RUN_STATUS, "workflow status")
    _same(run.get("conclusion"), EXPECTED_RUN_CONCLUSION, "workflow conclusion")
    _require_int(run.get("id"), "workflow run id")
    _require_int(run.get("workflow_id"), "workflow id")
    _require_int(run.get("run_number"), "workflow run number")
    _require_int(run.get("run_attempt"), "workflow run attempt")
    _sha(run.get("head_sha"), "workflow head SHA")
    _require_string(run.get("head_branch"), "workflow head ref")
    head_repository = _nested(run, "head_repository", "workflow head repository")
    _repository(head_repository.get("full_name"), "workflow head repository")
    return run


def _extract_run_identity(run: Mapping[str, Any]) -> dict[str, Any]:
    head_repository = _repository_object(
        run, "head_repository", "workflow head repository"
    )
    repository = _repository_object(run, "repository", "workflow repository")
    return {
        "id": _require_int(run.get("id"), "workflow run id"),
        "workflow_id": _require_int(run.get("workflow_id"), "workflow id"),
        "run_number": _require_int(run.get("run_number"), "workflow run number"),
        "run_attempt": _require_int(run.get("run_attempt"), "workflow run attempt"),
        "head_sha": _sha(run.get("head_sha"), "workflow head SHA"),
        "head_ref": _require_string(run.get("head_branch"), "workflow head ref"),
        "head_repository": head_repository["full_name"],
        "head_repository_id": head_repository["id"],
        "repository": repository["full_name"],
        "repository_id": repository["id"],
        "name": _require_string(run.get("name"), "workflow name"),
        "path": _require_string(run.get("path"), "workflow path"),
        "event": _require_string(run.get("event"), "workflow event"),
        "status": _require_string(run.get("status"), "workflow status"),
        "conclusion": _require_string(run.get("conclusion"), "workflow conclusion"),
    }


def _validate_run(event_run: Mapping[str, Any], api_run: Mapping[str, Any], repository: str) -> dict[str, Any]:
    event_run = _require_mapping(event_run, "workflow_run event")
    api_run = _require_mapping(api_run, "workflow run response")
    expected = _extract_run_identity(event_run)
    actual = _extract_run_identity(api_run)
    if expected != actual:
        raise PublisherError("GitHub workflow run changed while being verified")
    if actual["repository"] != repository:
        raise PublisherError("workflow run repository does not match the event")
    for key, expected_value in (
        ("name", EXPECTED_WORKFLOW_NAME),
        ("path", EXPECTED_WORKFLOW_PATH),
        ("event", EXPECTED_WORKFLOW_EVENT),
        ("status", EXPECTED_RUN_STATUS),
        ("conclusion", EXPECTED_RUN_CONCLUSION),
    ):
        _same(actual[key], expected_value, f"workflow {key}")
    return actual


def _zip_regular_file(info: zipfile.ZipInfo) -> bool:
    if info.is_dir():
        return False
    mode = (info.external_attr >> 16) & 0xFFFF
    kind = stat.S_IFMT(mode)
    # ZIPs made on Windows commonly carry no POSIX file type.  A nonzero type
    # is accepted only when it explicitly denotes an ordinary regular file.
    return kind in (0, stat.S_IFREG)


def _validate_zip(data: bytes) -> tuple[bytes, bytes]:
    if not isinstance(data, bytes):
        raise PublisherError("artifact download is not a byte string")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise PublisherError("artifact download exceeds the size limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, zipfile.BadZipFile) as exc:
        raise PublisherError("artifact is not a valid ZIP archive") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) != MAX_ZIP_FILES:
            raise PublisherError("artifact must contain exactly binding.json and pr-comment.md")
        names = [info.filename for info in infos]
        if len(set(names)) != len(names):
            raise PublisherError("artifact contains duplicate files")
        if set(names) != {"binding.json", "pr-comment.md"}:
            raise PublisherError("artifact contains an unexpected file")
        total = 0
        for info in infos:
            if "\\" in info.filename or info.filename.startswith("/"):
                raise PublisherError("artifact contains an unsafe path")
            if not _zip_regular_file(info):
                raise PublisherError("artifact contains a non-regular file")
            if info.file_size < 0 or info.compress_size < 0:
                raise PublisherError("artifact contains invalid ZIP sizes")
            if info.file_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                raise PublisherError("artifact uncompressed size exceeds the limit")
            total += info.file_size
            if total > MAX_ZIP_UNCOMPRESSED_BYTES:
                raise PublisherError("artifact uncompressed size exceeds the limit")
        try:
            binding = archive.read("binding.json")
            body = archive.read("pr-comment.md")
        except (OSError, KeyError, RuntimeError, zipfile.BadZipFile) as exc:
            raise PublisherError("artifact file cannot be read") from exc
    if len(binding) > MAX_BINDING_BYTES or len(body) > MAX_BODY_BYTES:
        raise PublisherError("artifact file exceeds the size limit")
    return binding, body


def _validate_binding(raw: bytes, body: bytes, run: Mapping[str, Any], repository: str) -> dict[str, Any]:
    value = _require_mapping(_parse_json(raw, "binding.json"), "binding.json")
    if frozenset(value) != EXPECTED_BINDING_KEYS:
        raise PublisherError("binding.json has an unexpected schema")
    schema_version = _require_int(
        value.get("schema_version"), "binding schema version", positive=False
    )
    if schema_version != EXPECTED_BINDING_SCHEMA_VERSION:
        raise PublisherError("unsupported binding schema version")
    _same(value.get("repository"), repository, "binding repository")
    _same(
        _require_int(value.get("repository_id"), "binding repository id"),
        run["repository_id"],
        "binding repository id",
    )
    _same(value.get("workflow_name"), EXPECTED_WORKFLOW_NAME, "binding workflow name")
    _same(value.get("workflow_path"), EXPECTED_WORKFLOW_PATH, "binding workflow path")
    _same(
        _require_int(value.get("run_id"), "binding run id"),
        run["id"],
        "binding run id",
    )
    _same(
        _require_int(value.get("run_attempt"), "binding run attempt"),
        run["run_attempt"],
        "binding run attempt",
    )
    _require_int(value.get("pr_number"), "binding PR number")
    _same(_sha(value.get("head_sha"), "binding head SHA"), run["head_sha"], "binding head SHA")
    _same(value.get("head_ref"), run["head_ref"], "binding head ref")
    _same(value.get("head_repository"), run["head_repository"], "binding head repository")
    _same(
        _require_int(value.get("head_repository_id"), "binding head repository id"),
        run["head_repository_id"],
        "binding head repository id",
    )
    _same(value.get("body_path"), "pr-comment.md", "binding body path")
    _same(value.get("base_repository"), run["repository"], "binding base repository")
    _same(
        _require_int(value.get("base_repository_id"), "binding base repository id"),
        run["repository_id"],
        "binding base repository id",
    )
    body_bytes = _require_int(value.get("body_bytes"), "binding body bytes", positive=False)
    if body_bytes != len(body):
        raise PublisherError("binding body byte count does not match artifact")
    digest = _require_string(value.get("body_sha256"), "binding body SHA-256")
    if not SHA256_PATTERN.fullmatch(digest):
        raise PublisherError("invalid binding body SHA-256")
    if not hashlib.sha256(body).hexdigest() == digest:
        raise PublisherError("binding body SHA-256 does not match artifact")
    if body_bytes > MAX_BODY_BYTES:
        raise PublisherError("binding body exceeds the size limit")
    comment_id = _require_string(value.get("comment_id"), "binding comment id")
    if not COMMENT_ID_PATTERN.fullmatch(comment_id):
        raise PublisherError("invalid binding comment id")
    if comment_id != EXPECTED_COMMENT_ID:
        raise PublisherError("binding comment id is not the publisher contract id")
    try:
        decoded_body = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublisherError("pull-request comment is not valid UTF-8") from exc
    if not decoded_body.strip():
        raise PublisherError("pull-request comment must not be blank")
    return value


def _pr_fields(pr: Mapping[str, Any], repository: str, pr_number: int) -> dict[str, str | int]:
    pr = _require_mapping(pr, "pull request response")
    number = _require_int(pr.get("number"), "pull request number")
    if number != pr_number:
        raise PublisherError("pull request number does not match the binding")
    if pr.get("state") == "closed":
        raise SkipPublication("pull request is no longer open")
    if pr.get("state") != "open":
        raise PublisherError("pull request state is invalid")
    head = _nested(pr, "head", "pull request head")
    base = _nested(pr, "base", "pull request base")
    head_repo = _repository_object(head, "repo", "pull request head repository")
    base_repo = _repository_object(base, "repo", "pull request base repository")
    return {
        "pr_number": number,
        "head_sha": _sha(head.get("sha"), "pull request head SHA"),
        "head_ref": _require_string(head.get("ref"), "pull request head ref"),
        "head_repository": head_repo["full_name"],
        "head_repository_id": head_repo["id"],
        "base_sha": _sha(base.get("sha"), "pull request base SHA"),
        "base_ref": _require_string(base.get("ref"), "pull request base ref"),
        "base_repository": base_repo["full_name"],
        "base_repository_id": base_repo["id"],
    }


def _validate_binding_pr(binding: Mapping[str, Any], pr: Mapping[str, Any], run: Mapping[str, Any], repository: str) -> None:
    fields = _pr_fields(pr, repository, binding["pr_number"])
    expected = _binding_pr_fields(binding)
    if fields != expected:
        raise PublisherError("pull request refs do not match the binding")
    if fields["base_repository"] != repository:
        raise PublisherError("pull request base repository does not match the event repository")
    if fields["head_sha"] != run["head_sha"] or fields["head_ref"] != run["head_ref"]:
        raise PublisherError("pull request head does not match the workflow run")
    if (
        fields["head_repository"] != run["head_repository"]
        or fields["head_repository_id"] != run["head_repository_id"]
    ):
        raise PublisherError("pull request head repository does not match the workflow run")
    if (
        fields["base_repository"] != run["repository"]
        or fields["base_repository_id"] != run["repository_id"]
    ):
        raise PublisherError("pull request base repository does not match the workflow run")


def _binding_pr_fields(binding: Mapping[str, Any]) -> dict[str, str | int]:
    return {
        "pr_number": binding["pr_number"],
        "head_sha": str(binding["head_sha"]).lower(),
        "head_ref": binding["head_ref"],
        "head_repository": binding["head_repository"],
        "head_repository_id": binding["head_repository_id"],
        "base_sha": str(binding["base_sha"]).lower(),
        "base_ref": binding["base_ref"],
        "base_repository": binding["base_repository"],
        "base_repository_id": binding["base_repository_id"],
    }


def _validate_binding_pr_types(binding: Mapping[str, Any]) -> None:
    """Validate binding PR fields before treating a live PR mismatch as stale."""
    _sha(binding.get("head_sha"), "binding head SHA")
    _sha(binding.get("base_sha"), "binding base SHA")
    _require_string(binding.get("head_ref"), "binding head ref")
    _require_string(binding.get("base_ref"), "binding base ref")
    _repository(binding.get("head_repository"), "binding head repository")
    _repository(binding.get("base_repository"), "binding base repository")
    _require_int(binding.get("head_repository_id"), "binding head repository id")
    _require_int(binding.get("base_repository_id"), "binding base repository id")


def _run_pull_request_association(
    run: Mapping[str, Any], *, api_url: str | None = None
) -> dict[str, str | int]:
    associations = run.get("pull_requests")
    if not isinstance(associations, list):
        raise SkipPublication("workflow run has no pull-request association")
    if len(associations) == 0:
        raise SkipPublication("workflow run pull-request association disappeared")
    if len(associations) != 1:
        raise SkipPublication("workflow run has an ambiguous pull-request association")
    association = _require_mapping(associations[0], "workflow run pull request")
    number = _require_int(association.get("number"), "workflow run pull request number")
    top_head_repository = _repository_object(
        run, "head_repository", "workflow head repository"
    )
    top_base_repository = _repository_object(run, "repository", "workflow repository")
    top_head_repository_id = top_head_repository["id"]
    top_base_repository_id = top_base_repository["id"]
    top_head_repository_name = top_head_repository["full_name"]
    top_base_repository_name = top_base_repository["full_name"]
    head = _nested(association, "head", "workflow run pull request head")
    base = _nested(association, "base", "workflow run pull request base")
    head_repo = _nested(head, "repo", "workflow run pull request head repository")
    base_repo = _nested(base, "repo", "workflow run pull request base repository")
    head_repo_name = _require_string(
        head_repo.get("name"), "workflow run pull request head repository name"
    )
    base_repo_name = _require_string(
        base_repo.get("name"), "workflow run pull request base repository name"
    )
    if head_repo_name != top_head_repository["name"]:
        raise PublisherError(
            "workflow run pull request head repository name does not match the run"
        )
    if base_repo_name != top_base_repository["name"]:
        raise PublisherError(
            "workflow run pull request base repository name does not match the run"
        )
    _validate_repository_url(
        head_repo.get("url"),
        top_head_repository_name,
        "workflow run pull request head repository",
        api_url=api_url,
    )
    _validate_repository_url(
        base_repo.get("url"),
        top_base_repository_name,
        "workflow run pull request base repository",
        api_url=api_url,
    )
    _same(
        _require_int(head_repo.get("id"), "workflow run pull request head repository id"),
        top_head_repository_id,
        "workflow run pull request head repository",
    )
    _same(
        _require_int(base_repo.get("id"), "workflow run pull request base repository id"),
        top_base_repository_id,
        "workflow run pull request base repository",
    )
    return {
        "pr_number": number,
        "head_sha": _sha(head.get("sha"), "workflow run pull request head SHA"),
        "head_ref": _require_string(head.get("ref"), "workflow run pull request head ref"),
        "head_repository": top_head_repository_name,
        "head_repository_id": top_head_repository_id,
        "base_sha": _sha(base.get("sha"), "workflow run pull request base SHA"),
        "base_ref": _require_string(base.get("ref"), "workflow run pull request base ref"),
        "base_repository": top_base_repository_name,
        "base_repository_id": top_base_repository_id,
    }


def _validate_binding_association(
    binding: Mapping[str, Any],
    association: Mapping[str, str | int],
    run: Mapping[str, Any],
    repository: str,
) -> None:
    expected = _binding_pr_fields(binding)
    if dict(association) != expected:
        raise PublisherError("binding does not match the workflow run pull request")
    if association["base_repository"] != repository:
        raise PublisherError("workflow run pull request base is not this repository")
    if (
        association["head_sha"] != run["head_sha"]
        or association["head_ref"] != run["head_ref"]
        or association["head_repository"] != run["head_repository"]
        or association["head_repository_id"] != run["head_repository_id"]
        or association["base_repository_id"] != run["repository_id"]
    ):
        raise PublisherError("workflow run pull request head does not match the run")


def _run_sort_key(run: Mapping[str, Any]) -> tuple[int, int, str, int]:
    return (
        _require_int(run.get("run_number"), "workflow run number"),
        _require_int(run.get("run_attempt"), "workflow run attempt"),
        _require_string(run.get("created_at", ""), "workflow run creation time", nonempty=False),
        _require_int(run.get("id"), "workflow run id"),
    )


def _ensure_latest_run(runs: Sequence[Mapping[str, Any]], expected: Mapping[str, Any]) -> None:
    if not isinstance(runs, Sequence) or isinstance(runs, (str, bytes, bytearray)):
        raise PublisherError("workflow runs response is not an array")
    candidates: list[Mapping[str, Any]] = []
    for run in runs:
        if not isinstance(run, Mapping):
            raise PublisherError("workflow runs response contains a non-object")
        if run.get("workflow_id") != expected["workflow_id"]:
            continue
        head_sha = run.get("head_sha")
        if not isinstance(head_sha, str) or head_sha.lower() != expected["head_sha"]:
            continue
        if run.get("event") != EXPECTED_WORKFLOW_EVENT:
            continue
        candidates.append(run)
    if not candidates:
        raise PublisherError("workflow run is absent from the latest-run listing")
    latest = max(candidates, key=_run_sort_key)
    latest_identity = (
        _require_int(latest.get("id"), "latest workflow run id"),
        _require_int(latest.get("run_attempt"), "latest workflow run attempt"),
    )
    if latest_identity != (expected["id"], expected["run_attempt"]):
        raise SkipPublication("a newer workflow run or rerun supersedes this run")


class GitHubClient:
    """Minimal GitHub REST client; tests can inject a fake implementing methods."""

    def __init__(self, api_url: str, token: str, opener: Any | None = None) -> None:
        parsed = parse.urlparse(api_url.rstrip("/"))
        if parsed.scheme != "https" or not parsed.netloc:
            raise PublisherError("GitHub API URL must be an absolute HTTPS URL")
        if not token:
            raise PublisherError("GitHub token must not be empty")
        self.api_url = api_url.rstrip("/")
        self.api_host = parsed.netloc.lower()
        self.token = token
        self.opener = opener or request.build_opener(_NoRedirectHandler())

    def _request_json(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[str, Any] | None = None,
        tolerated_statuses: set[int] | None = None,
    ) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        call = request.Request(
            f"{self.api_url}{endpoint}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "pcbex-trusted-pr-comment-publisher",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self.opener.open(call, timeout=30) as response:
                data = response.read(MAX_EVENT_BYTES + 1)
        except error.HTTPError as exc:
            # Response content is intentionally not included in logs.
            if exc.code in (tolerated_statuses or set()):
                return None
            raise PublisherError(f"GitHub API request failed with HTTP {exc.code}") from exc
        except (error.URLError, OSError) as exc:
            raise PublisherError("GitHub API request failed") from exc
        if len(data) > MAX_EVENT_BYTES:
            raise PublisherError("GitHub API response exceeds the size limit")
        return _parse_json(data, "GitHub API response")

    def _json(self, endpoint: str) -> Any:
        return self._request_json("GET", endpoint)

    def get_run(self, repository: str, run_id: int) -> dict[str, Any]:
        return _require_mapping(self._json(f"/repos/{repository}/actions/runs/{run_id}"), "workflow run response")

    def get_pull_request(self, repository: str, number: int) -> dict[str, Any]:
        return _require_mapping(self._json(f"/repos/{repository}/pulls/{number}"), "pull request response")

    def list_comments(self, repository: str, pull_request: int) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        for page in range(1, MAX_API_PAGES + 1):
            value = self._json(
                f"/repos/{repository}/issues/{pull_request}/comments?per_page=100&page={page}"
            )
            page_values = value if isinstance(value, list) else None
            if page_values is None:
                raise PublisherError("comments response is not an array")
            for item in page_values:
                comments.append(_require_mapping(item, "comment listing item"))
            if len(page_values) < 100:
                return comments
        raise PublisherError("comments exceed the page limit")

    def update_comment(
        self, repository: str, comment_id: int, body: str
    ) -> dict[str, Any] | None:
        value = self._request_json(
            "PATCH",
            f"/repos/{repository}/issues/comments/{comment_id}",
            {"body": body},
            tolerated_statuses={403, 404},
        )
        if value is None:
            return None
        return _require_mapping(value, "comment update response")

    def create_comment(
        self, repository: str, pull_request: int, body: str
    ) -> dict[str, Any]:
        value = self._request_json(
            "POST",
            f"/repos/{repository}/issues/{pull_request}/comments",
            {"body": body},
        )
        return _require_mapping(value, "comment creation response")

    def list_runs(self, repository: str, workflow_id: int, head_sha: str) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        for page in range(1, MAX_API_PAGES + 1):
            value = _require_mapping(
                self._json(
                    f"/repos/{repository}/actions/workflows/{workflow_id}/runs"
                    f"?event={EXPECTED_WORKFLOW_EVENT}&head_sha={parse.quote(head_sha)}"
                    f"&per_page=100&page={page}"
                ),
                "workflow runs response",
            )
            page_values = value.get("workflow_runs")
            if not isinstance(page_values, list):
                raise PublisherError("workflow runs response has no workflow_runs array")
            for item in page_values:
                runs.append(_require_mapping(item, "workflow run listing item"))
            if len(page_values) < 100:
                return runs
        raise PublisherError("workflow runs exceed the page limit")

    def list_artifacts(self, repository: str, run_id: int) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for page in range(1, MAX_API_PAGES + 1):
            value = _require_mapping(
                self._json(
                    f"/repos/{repository}/actions/runs/{run_id}/artifacts"
                    f"?per_page=100&page={page}"
                ),
                "artifacts response",
            )
            page_values = value.get("artifacts")
            if not isinstance(page_values, list):
                raise PublisherError("artifacts response has no artifacts array")
            for item in page_values:
                artifacts.append(_require_mapping(item, "artifact listing item"))
            if len(page_values) < 100:
                return artifacts
        raise PublisherError("artifacts exceed the page limit")

    def download_artifact(self, artifact: Mapping[str, Any]) -> bytes:
        url = artifact.get("archive_download_url")
        if not isinstance(url, str):
            raise PublisherError("artifact has no archive download URL")
        return _download_https_redirect_safe(url, self.api_host, self.token, self.opener)


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req: request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _download_https_redirect_safe(url: str, api_host: str, token: str, opener: Any) -> bytes:
    current = url
    for redirect_count in range(MAX_ARTIFACT_REDIRECTS + 1):
        parsed = parse.urlparse(current)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise PublisherError("artifact download URL must use HTTPS without credentials")
        if redirect_count == 0 and parsed.netloc.lower() != api_host.lower():
            raise PublisherError("artifact download must start at the GitHub API host")
        headers = {
            "Accept": "application/octet-stream",
            "User-Agent": "pcbex-trusted-pr-comment-publisher",
        }
        # GitHub API auth is sent only to the API host.  A signed object-store
        # redirect receives no Authorization header, preventing token leakage.
        if parsed.netloc.lower() == api_host.lower():
            headers["Authorization"] = f"Bearer {token}"
        call = request.Request(current, method="GET", headers=headers)
        try:
            response = opener.open(call, timeout=60)
        except error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308}:
                location = exc.headers.get("Location")
                if not location:
                    raise PublisherError("artifact redirect has no Location") from exc
                current = parse.urljoin(current, location)
                if redirect_count >= MAX_ARTIFACT_REDIRECTS:
                    raise PublisherError("artifact download redirect limit exceeded") from exc
                continue
            raise PublisherError(f"artifact download failed with HTTP {exc.code}") from exc
        except (error.URLError, OSError) as exc:
            raise PublisherError("artifact download failed") from exc
        try:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    parsed_length = int(content_length)
                    if parsed_length < 0 or parsed_length > MAX_ARTIFACT_BYTES:
                        raise PublisherError("artifact download exceeds the size limit")
                except ValueError as exc:
                    raise PublisherError("artifact download has an invalid content length") from exc
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = response.read(min(64 * 1024, MAX_ARTIFACT_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_ARTIFACT_BYTES:
                    raise PublisherError("artifact download exceeds the size limit")
            return b"".join(chunks)
        finally:
            response.close()
    raise PublisherError("artifact download redirect limit exceeded")


def _load_upsert_module() -> Any:
    path = Path(__file__).with_name("upsert-pr-comment.py")
    spec = importlib.util.spec_from_file_location("pcbex_upsert_pr_comment", path)
    if spec is None or spec.loader is None:
        raise PublisherError("cannot load the trusted comment writer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _artifact_for_run(client: Any, repository: str, run: Mapping[str, Any]) -> dict[str, Any]:
    expected_name = f"{EXPECTED_ARTIFACT_PREFIX}{run['id']}-{run['run_attempt']}"
    artifacts = client.list_artifacts(repository, run["id"])
    if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes, bytearray)):
        raise PublisherError("artifacts response is not an array")
    normalized = [_require_mapping(item, "artifact listing item") for item in artifacts]
    matching = [item for item in normalized if item.get("name") == expected_name]
    if len(matching) != 1:
        raise PublisherError("PR comment artifact is missing or duplicated")
    artifact = matching[0]
    if artifact.get("expired") is not False:
        raise PublisherError("PR comment artifact is expired")
    size = artifact.get("size_in_bytes")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > MAX_ARTIFACT_BYTES:
        raise PublisherError("PR comment artifact has an invalid size")
    return artifact


def _provenance_banner(binding: Mapping[str, Any]) -> str:
    # Values are all validated contract scalars; keep the banner one line and
    # bounded so no artifact content can become a log or comment injection.
    repository = str(binding["repository"])
    run_id = binding["run_id"]
    attempt = binding["run_attempt"]
    head_sha = str(binding["head_sha"]).lower()
    return (
        "<!-- pcbex trusted publisher: "
        f"run_id={binding['run_id']} run_attempt={binding['run_attempt']} "
        f"head_sha={head_sha} -->\n\n"
        "> **pcbex provenance:** unprivileged PR CI report for commit "
        f"`{head_sha}` from run "
        f"[`{run_id}` attempt `{attempt}`]"
        f"(https://github.com/{repository}/actions/runs/{run_id})\n\n"
    )


def _sanitize_markdown(markdown: str) -> str:
    """Escape untrusted report text and neutralize every ASCII mention."""
    escaped = html.escape(markdown, quote=True)
    # The entity avoids a raw ASCII ``@`` in the rendered source and the
    # zero-width separator prevents a renderer which decodes entities before
    # mention detection from recognizing ``@user``.
    return escaped.replace("@", "&#64;\u200b")


def _comment_body(binding: Mapping[str, Any], body: bytes) -> str:
    try:
        markdown = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublisherError("pull-request comment is not valid UTF-8") from exc
    sanitized = _sanitize_markdown(markdown)
    rendered = (
        f"<!-- pcbex-hardware-ci:{binding['comment_id']} -->\n\n"
        + _provenance_banner(binding)
        + sanitized.rstrip()
        + "\n"
    )
    if len(rendered) > MAX_COMMENT_CHARACTERS:
        raise PublisherError("pull-request comment exceeds the size limit")
    return _provenance_banner(binding) + sanitized


def publish_from_event(
    event: Mapping[str, Any],
    repository: str,
    client: Any,
    *,
    upsert: Callable[..., tuple[str, dict[str, Any]]] | None = None,
) -> str:
    """Verify and publish one workflow_run event.

    Returns ``"published"`` or ``"skipped"``.  ``SkipPublication`` is
    converted to the latter so stale/closed/replayed runs are safe no-ops;
    malformed contracts and API failures raise ``PublisherError``.
    """

    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise PublisherError("repository must use owner/name form")
    event_run = _event_workflow_run(event, repository)
    try:
        api_run = client.get_run(repository, event_run["id"])
        run = _validate_run(event_run, api_run, repository)
        run_association = _run_pull_request_association(
            api_run, api_url=getattr(client, "api_url", None)
        )
        artifact = _artifact_for_run(client, repository, run)
        archive = client.download_artifact(artifact)
        binding_raw, body = _validate_zip(archive)
        binding = _validate_binding(binding_raw, body, run, repository)
        _validate_binding_pr_types(binding)
        _validate_binding_association(binding, run_association, run, repository)
        pr_number = binding["pr_number"]
        current_pr = client.get_pull_request(repository, pr_number)
        current_fields = _pr_fields(current_pr, repository, pr_number)
        if current_fields != _binding_pr_fields(binding):
            raise SkipPublication("pull request refs changed while waiting to publish")
        if current_fields["base_repository"] != repository:
            raise SkipPublication("pull request base repository changed while waiting to publish")
        if current_fields["head_sha"] != run["head_sha"] or current_fields["head_ref"] != run["head_ref"] or current_fields["head_repository"] != run["head_repository"]:
            raise SkipPublication("pull request head changed while waiting to publish")
        _ensure_latest_run(
            client.list_runs(repository, run["workflow_id"], run["head_sha"]), run
        )
        # Re-read the PR immediately before the write to close the TOCTOU race.
        final_pr = client.get_pull_request(repository, pr_number)
        final_fields = _pr_fields(final_pr, repository, pr_number)
        if final_fields != current_fields:
            raise SkipPublication("pull request changed immediately before publishing")
        if final_fields["base_repository"] != repository:
            raise SkipPublication("pull request base repository changed immediately before publishing")
        if final_fields["head_sha"] != run["head_sha"] or final_fields["head_ref"] != run["head_ref"] or final_fields["head_repository"] != run["head_repository"]:
            raise SkipPublication("pull request head changed immediately before publishing")
        # Close the run supersession race as well as the PR ref race: a newer
        # rerun may have appeared while the final PR request was in flight.
        _ensure_latest_run(
            client.list_runs(repository, run["workflow_id"], run["head_sha"]), run
        )
        writer_module = None
        if upsert is None:
            writer_module = _load_upsert_module()
            upsert = writer_module.upsert_comment
        try:
            if writer_module is not None:
                operation, comment = upsert(
                    client,
                    repository,
                    pr_number,
                    binding["comment_id"],
                    _comment_body(binding, body),
                    expected_author=EXPECTED_AUTHOR_LOGIN,
                )
            else:
                operation, comment = upsert(
                    client,
                    repository,
                    pr_number,
                    binding["comment_id"],
                    _comment_body(binding, body),
                )
        except Exception as exc:
            if writer_module is not None:
                raise PublisherError("pull-request comment writer failed") from exc
            raise
        if not isinstance(comment, Mapping):
            raise PublisherError("comment writer returned an invalid response")
        return "published"
    except SkipPublication:
        return "skipped"


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise PublisherError(f"required environment variable is empty: {name}")
    return value


def main() -> int:
    try:
        if os.environ.get("GITHUB_EVENT_NAME") != "workflow_run":
            raise PublisherError("GITHUB_EVENT_NAME must be workflow_run")
        event_path = Path(_required_environment("GITHUB_EVENT_PATH"))
        if event_path.is_symlink() or not event_path.is_file():
            raise PublisherError("GITHUB_EVENT_PATH must be a regular file")
        if event_path.stat().st_size > MAX_EVENT_BYTES:
            raise PublisherError("workflow_run event exceeds the size limit")
        with event_path.open("rb") as event_stream:
            event_bytes = event_stream.read(MAX_EVENT_BYTES + 1)
        if len(event_bytes) > MAX_EVENT_BYTES:
            raise PublisherError("workflow_run event exceeds the size limit")
        event = _require_mapping(
            _parse_json(event_bytes, "workflow_run event"), "workflow_run event"
        )
        repository = _required_environment("GITHUB_REPOSITORY")
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("PCBEX_GITHUB_TOKEN", "")
        client = GitHubClient(os.environ.get("GITHUB_API_URL", "https://api.github.com"), token)
        result = publish_from_event(event, repository, client)
        print(f"pcbex trusted PR comment {result}")
        return 0
    except (PublisherError, OSError, UnicodeError, ValueError) as failure:
        print(f"pcbex trusted PR comment error: {failure}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

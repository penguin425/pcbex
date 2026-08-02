#!/usr/bin/env python3
"""Create or update one marker-addressed pcbex pull-request comment."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any
from urllib import error, parse, request


MAX_COMMENT_CHARACTERS = 65_536
MAX_COMMENT_PAGES = 100
COMMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
REPOSITORY_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
)


class CommentError(RuntimeError):
    """An actionable comment-upsert failure."""


class _NoRedirectHandler(request.HTTPRedirectHandler):
    """Prevent urllib from following API redirects with the bearer token."""

    def redirect_request(
        self,
        req: request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class GitHubClient:
    def __init__(self, api_url: str, token: str, opener: Any | None = None) -> None:
        api_url = api_url.rstrip("/")
        parsed = parse.urlparse(api_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise CommentError("GitHub API URL must be an absolute HTTPS URL")
        if not token:
            raise CommentError("GitHub token must not be empty")
        self.api_url = api_url
        self.token = token
        self.opener = (
            opener if opener is not None else request.build_opener(_NoRedirectHandler())
        )

    def list_comments(self, repository: str, pull_request: int) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        for page in range(1, MAX_COMMENT_PAGES + 1):
            values = self._request(
                "GET",
                f"/repos/{repository}/issues/{pull_request}/comments"
                f"?per_page=100&page={page}",
            )
            if not isinstance(values, list):
                raise CommentError("GitHub comments response is not an array")
            comments.extend(values)
            if len(values) < 100:
                return comments
        raise CommentError(
            f"pull request comments exceed the {MAX_COMMENT_PAGES * 100} item limit"
        )

    def update_comment(
        self, repository: str, comment_id: int, body: str
    ) -> dict[str, Any] | None:
        value = self._request(
            "PATCH",
            f"/repos/{repository}/issues/comments/{comment_id}",
            {"body": body},
            tolerated_statuses={403, 404},
        )
        if value is None:
            return None
        if not isinstance(value, dict):
            raise CommentError("GitHub comment update response is not an object")
        return value

    def create_comment(
        self, repository: str, pull_request: int, body: str
    ) -> dict[str, Any]:
        value = self._request(
            "POST",
            f"/repos/{repository}/issues/{pull_request}/comments",
            {"body": body},
        )
        if not isinstance(value, dict):
            raise CommentError("GitHub comment creation response is not an object")
        return value

    def _request(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
        tolerated_statuses: set[int] | None = None,
    ) -> Any:
        data = None if payload is None else json.dumps(payload).encode()
        call = request.Request(
            f"{self.api_url}{endpoint}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "pcbex-hardware-ci",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self.opener.open(call, timeout=30) as response:
                status = getattr(response, "status", None)
                if status is None:
                    status = response.getcode()
                if status is not None and 300 <= status < 400:
                    # Do not read or include redirect response bodies: they can
                    # contain secrets reflected by a malicious endpoint.
                    raise CommentError(
                        f"GitHub API {method} {endpoint} failed with HTTP redirect {status}"
                    )
                return json.load(response)
        except error.HTTPError as failure:
            if 300 <= failure.code < 400:
                # The no-redirect opener should surface redirects as HTTPError.
                # Never follow them or log their response body/Location header.
                raise CommentError(
                    f"GitHub API {method} {endpoint} failed with HTTP redirect {failure.code}"
                ) from failure
            if failure.code in (tolerated_statuses or set()):
                return None
            raise CommentError(
                f"GitHub API {method} {endpoint} failed with HTTP {failure.code}"
            ) from failure
        except error.URLError as failure:
            raise CommentError(
                f"GitHub API {method} {endpoint} failed: {failure.reason}"
            ) from failure


def marker_for(comment_id: str) -> str:
    if not COMMENT_ID_PATTERN.fullmatch(comment_id):
        raise CommentError(
            "comment id must be 1-64 ASCII letters, digits, dots, underscores, "
            "or hyphens and start with a letter or digit"
        )
    return f"<!-- pcbex-hardware-ci:{comment_id} -->"


def render_body(comment_id: str, markdown: str) -> tuple[str, str]:
    marker = marker_for(comment_id)
    if not markdown.strip():
        raise CommentError("pull-request comment Markdown must not be blank")
    body = f"{marker}\n\n{markdown.rstrip()}\n"
    if len(body) > MAX_COMMENT_CHARACTERS:
        raise CommentError(
            f"pull-request comment exceeds {MAX_COMMENT_CHARACTERS} characters"
        )
    return marker, body


def upsert_comment(
    client: GitHubClient,
    repository: str,
    pull_request: int,
    comment_id: str,
    markdown: str,
    *,
    expected_author: str | None = None,
) -> tuple[str, dict[str, Any]]:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise CommentError("repository must use owner/name form")
    if pull_request <= 0:
        raise CommentError("pull-request number must be positive")
    if expected_author is not None and (
        not isinstance(expected_author, str) or not expected_author
    ):
        raise CommentError("expected author must be a non-empty string")
    marker, body = render_body(comment_id, markdown)
    matches: list[dict[str, Any]] = []
    for comment in client.list_comments(repository, pull_request):
        if not isinstance(comment, dict):
            continue
        comment_body = comment.get("body", "")
        if not isinstance(comment_body, str) or not comment_body.lstrip().startswith(
            marker
        ):
            continue
        if type(comment.get("id")) is not int:
            continue
        if expected_author is not None:
            user = comment.get("user")
            if not isinstance(user, dict):
                continue
            if user.get("login") != expected_author or user.get("type") != "Bot":
                continue
        matches.append(comment)
    matches.sort(key=lambda comment: comment["id"], reverse=True)
    for comment in matches:
        updated = client.update_comment(repository, comment["id"], body)
        if updated is not None:
            return "updated", updated
    return "created", client.create_comment(repository, pull_request, body)


def required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise CommentError(f"required environment variable is empty: {name}")
    return value


def write_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write(f"{name}={value}\n")


def main() -> int:
    try:
        repository = required_environment("PCBEX_REPOSITORY")
        pull_request = int(required_environment("PCBEX_PR_NUMBER"))
        comment_id = required_environment("PCBEX_COMMENT_ID")
        markdown_path = Path(required_environment("PCBEX_COMMENT_BODY"))
        markdown = markdown_path.read_text(encoding="utf-8")
        client = GitHubClient(
            required_environment("PCBEX_API_URL"),
            required_environment("PCBEX_GITHUB_TOKEN"),
        )
        operation, comment = upsert_comment(
            client, repository, pull_request, comment_id, markdown
        )
        comment_url = comment.get("html_url")
        if not isinstance(comment_url, str) or not comment_url.startswith("https://"):
            raise CommentError("GitHub comment response has no HTTPS html_url")
        write_output("comment-url", comment_url)
        print(f"{operation} pcbex pull-request comment: {comment_url}")
        return 0
    except (CommentError, OSError, UnicodeError, ValueError) as failure:
        print(f"pcbex PR comment error: {failure}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

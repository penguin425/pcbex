from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock
from urllib import error


SCRIPT = Path(__file__).resolve().parents[1] / "upsert-pr-comment.py"
SPEC = importlib.util.spec_from_file_location("upsert_pr_comment", SCRIPT)
assert SPEC and SPEC.loader
upsert_pr_comment = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upsert_pr_comment)


class FakeClient:
    def __init__(self, comments=(), editable=()) -> None:
        self.comments = list(comments)
        self.editable = set(editable)
        self.updated: list[tuple[str, int, str]] = []
        self.created: list[tuple[str, int, str]] = []

    def list_comments(self, repository, pull_request):
        self.listed = (repository, pull_request)
        return list(self.comments)

    def update_comment(self, repository, comment_id, body):
        self.updated.append((repository, comment_id, body))
        if comment_id not in self.editable:
            return None
        return {
            "id": comment_id,
            "html_url": f"https://example.test/comments/{comment_id}",
        }

    def create_comment(self, repository, pull_request, body):
        self.created.append((repository, pull_request, body))
        return {"id": 99, "html_url": "https://example.test/comments/99"}


class UpsertPrCommentTests(unittest.TestCase):
    def test_updates_the_newest_editable_marker_comment(self):
        marker = "<!-- pcbex-hardware-ci:layout -->"
        client = FakeClient(
            comments=[
                {"id": 10, "body": marker},
                {"id": 30, "body": f"{marker}\nspoofed"},
                {"id": 20, "body": marker},
                {"id": 40, "body": "unrelated"},
            ],
            editable={20},
        )

        operation, comment = upsert_pr_comment.upsert_comment(
            client, "owner/repository", 42, "layout", "# Fresh result"
        )

        self.assertEqual(operation, "updated")
        self.assertEqual(comment["id"], 20)
        self.assertEqual([entry[1] for entry in client.updated], [30, 20])
        self.assertEqual(client.created, [])
        self.assertTrue(client.updated[-1][2].startswith(marker))
        self.assertTrue(client.updated[-1][2].endswith("# Fresh result\n"))

    def test_creates_once_when_no_editable_marker_exists(self):
        client = FakeClient(
            comments=[
                {
                    "id": 7,
                    "body": "<!-- pcbex-hardware-ci:other -->",
                }
            ]
        )
        operation, comment = upsert_pr_comment.upsert_comment(
            client, "owner/repository", 3, "layout", "report"
        )
        self.assertEqual(operation, "created")
        self.assertEqual(comment["id"], 99)
        self.assertEqual(len(client.created), 1)

    def test_rejects_unsafe_or_unbounded_inputs(self):
        client = FakeClient()
        invalid = [
            ("owner", 1, "layout", "report"),
            ("owner/repository", 0, "layout", "report"),
            ("owner/repository", 1, "<!--", "report"),
            ("owner/repository", 1, "layout", " "),
            (
                "owner/repository",
                1,
                "layout",
                "x" * upsert_pr_comment.MAX_COMMENT_CHARACTERS,
            ),
        ]
        for repository, number, comment_id, body in invalid:
            with self.subTest(
                repository=repository, number=number, comment_id=comment_id
            ):
                with self.assertRaises(upsert_pr_comment.CommentError):
                    upsert_pr_comment.upsert_comment(
                        client, repository, number, comment_id, body
                    )

    def test_http_client_tolerates_only_uneditable_marker_comments(self):
        client = upsert_pr_comment.GitHubClient(
            "https://api.github.example", "secret"
        )
        forbidden = error.HTTPError(
            "https://api.github.example/comment",
            403,
            "Forbidden",
            {},
            io.BytesIO(b'{"message":"forbidden"}'),
        )
        with mock.patch.object(
            upsert_pr_comment.request, "urlopen", side_effect=forbidden
        ):
            self.assertIsNone(
                client.update_comment("owner/repository", 12, "body")
            )

        failure = error.HTTPError(
            "https://api.github.example/comment",
            500,
            "Server Error",
            {},
            io.BytesIO(b'{"message":"failed"}'),
        )
        with mock.patch.object(
            upsert_pr_comment.request, "urlopen", side_effect=failure
        ):
            with self.assertRaises(upsert_pr_comment.CommentError):
                client.update_comment("owner/repository", 12, "body")


if __name__ == "__main__":
    unittest.main()

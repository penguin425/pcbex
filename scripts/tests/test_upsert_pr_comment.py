from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import tempfile
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


class RedirectResponse:
    status = 302

    def __init__(self):
        self.headers = {"Location": "https://attacker.example/collect"}

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def getcode(self):
        return self.status

    def read(self, *args, **kwargs):
        raise AssertionError("redirect response body must not be read")


class RedirectOpener:
    def __init__(self):
        self.calls = []

    def open(self, call, timeout):
        self.calls.append((call, timeout))
        if len(self.calls) > 1:
            raise AssertionError("redirect must not trigger a second request")
        return RedirectResponse()


class JsonResponse(io.BytesIO):
    status = 200

    def __init__(self, payload: bytes, content_length: str | None = None):
        super().__init__(payload)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def getcode(self):
        return self.status


class JsonOpener:
    def __init__(self, responses):
        self.responses = list(responses)

    def open(self, call, timeout):
        del call, timeout
        return self.responses.pop(0)


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
            client.opener, "open", side_effect=forbidden
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
            client.opener, "open", side_effect=failure
        ):
            with self.assertRaises(upsert_pr_comment.CommentError):
                client.update_comment("owner/repository", 12, "body")

    def test_api_redirect_is_not_followed_or_logged(self):
        opener = RedirectOpener()
        client = upsert_pr_comment.GitHubClient(
            "https://api.github.example", "secret-token", opener=opener
        )
        with self.assertRaises(upsert_pr_comment.CommentError) as raised:
            client.list_comments("owner/repository", 12)
        self.assertEqual(len(opener.calls), 1)
        call, timeout = opener.calls[0]
        self.assertEqual(timeout, 30)
        self.assertEqual(
            call.full_url,
            "https://api.github.example/repos/owner/repository/issues/12/comments?"
            "per_page=100&page=1",
        )
        self.assertEqual(call.headers["Authorization"], "Bearer secret-token")
        self.assertNotIn("secret-token", str(raised.exception))
        self.assertNotIn("attacker.example", str(raised.exception))

    def test_http_error_redirect_body_is_not_read_or_logged(self):
        client = upsert_pr_comment.GitHubClient(
            "https://api.github.example", "secret-token"
        )

        class NoReadBody(io.BytesIO):
            def read(self, *args, **kwargs):
                raise AssertionError("redirect response body must not be read")

        failure = error.HTTPError(
            "https://api.github.example/comment",
            302,
            "Found",
            {"Location": "https://attacker.example/collect"},
            NoReadBody(b"secret-token"),
        )
        with mock.patch.object(client.opener, "open", side_effect=failure):
            with self.assertRaises(upsert_pr_comment.CommentError) as raised:
                client.update_comment("owner/repository", 12, "body")
        self.assertNotIn("secret-token", str(raised.exception))
        self.assertNotIn("attacker.example", str(raised.exception))

    def test_api_responses_have_per_response_and_aggregate_byte_limits(self):
        client = upsert_pr_comment.GitHubClient(
            "https://api.github.example",
            "secret-token",
            opener=JsonOpener([JsonResponse(b"[]", "2")]),
        )
        client.response_bytes_remaining = 1
        with self.assertRaisesRegex(upsert_pr_comment.CommentError, "exceeds"):
            client.list_comments("owner/repository", 1)

        client = upsert_pr_comment.GitHubClient(
            "https://api.github.example",
            "secret-token",
            opener=JsonOpener([JsonResponse(b"[" * 8)]),
        )
        with mock.patch.object(upsert_pr_comment, "MAX_API_RESPONSE_BYTES", 7):
            with self.assertRaisesRegex(upsert_pr_comment.CommentError, "exceeds"):
                client.list_comments("owner/repository", 1)

    def test_output_append_is_bounded_and_rejects_multiline_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "github-output"
            output.write_text("a=1\n")
            with (
                mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                mock.patch.object(upsert_pr_comment, "MAX_GITHUB_OUTPUT_BYTES", 8),
            ):
                upsert_pr_comment.write_output("b", "2")
                self.assertEqual(output.read_text(), "a=1\nb=2\n")
                with self.assertRaises(upsert_pr_comment.CommentError):
                    upsert_pr_comment.write_output("c", "3")
                with self.assertRaises(upsert_pr_comment.CommentError):
                    upsert_pr_comment.write_output("bad", "line\nbreak")

    def test_main_rejects_oversized_markdown_before_network_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            markdown = Path(temporary).resolve() / "comment.md"
            with markdown.open("wb") as stream:
                stream.truncate(upsert_pr_comment.MAX_COMMENT_BODY_BYTES + 1)
            environment = {
                "PCBEX_REPOSITORY": "owner/repository",
                "PCBEX_PR_NUMBER": "1",
                "PCBEX_COMMENT_ID": "layout",
                "PCBEX_COMMENT_BODY": str(markdown),
                "PCBEX_API_URL": "https://api.github.example",
                "PCBEX_GITHUB_TOKEN": "secret",
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(upsert_pr_comment, "GitHubClient") as client,
                mock.patch("sys.stderr", new_callable=io.StringIO),
            ):
                self.assertEqual(upsert_pr_comment.main(), 2)
                client.assert_not_called()

    def test_user_marker_is_not_updated_when_expected_bot_author_does_not_match(
        self,
    ):
        marker = "<!-- pcbex-hardware-ci:layout -->"
        client = FakeClient(
            comments=[
                {
                    "id": 30,
                    "body": marker,
                    "user": {"login": "human", "type": "User"},
                }
            ],
            editable={30},
        )
        operation, comment = upsert_pr_comment.upsert_comment(
            client,
            "owner/repository",
            42,
            "layout",
            "# Fresh result",
            expected_author="github-actions[bot]",
        )
        self.assertEqual(operation, "created")
        self.assertEqual(comment["id"], 99)
        self.assertEqual(client.updated, [])
        self.assertEqual(len(client.created), 1)

    def test_expected_bot_marker_is_updated(self):
        marker = "<!-- pcbex-hardware-ci:layout -->"
        client = FakeClient(
            comments=[
                {
                    "id": 30,
                    "body": marker,
                    "user": {"login": "github-actions[bot]", "type": "Bot"},
                }
            ],
            editable={30},
        )
        operation, comment = upsert_pr_comment.upsert_comment(
            client,
            "owner/repository",
            42,
            "layout",
            "# Fresh result",
            expected_author="github-actions[bot]",
        )
        self.assertEqual(operation, "updated")
        self.assertEqual(comment["id"], 30)
        self.assertEqual([entry[1] for entry in client.updated], [30])
        self.assertEqual(client.created, [])

    def test_malformed_expected_author_shape_is_candidate_only(self):
        marker = "<!-- pcbex-hardware-ci:layout -->"
        client = FakeClient(
            comments=[
                {
                    "id": 30,
                    "body": marker,
                    "user": {"login": "github-actions[bot]"},
                },
                {"id": 20, "body": marker, "user": "github-actions[bot]"},
            ],
            editable={20, 30},
        )
        operation, _ = upsert_pr_comment.upsert_comment(
            client,
            "owner/repository",
            42,
            "layout",
            "# Fresh result",
            expected_author="github-actions[bot]",
        )
        self.assertEqual(operation, "created")
        self.assertEqual(client.updated, [])


if __name__ == "__main__":
    unittest.main()

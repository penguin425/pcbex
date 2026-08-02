from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import unittest
from unittest import mock
from urllib import error
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "publish-pr-comment.py"
SPEC = importlib.util.spec_from_file_location("publish_pr_comment", SCRIPT)
assert SPEC and SPEC.loader
publish_pr_comment = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish_pr_comment)


REPOSITORY = "owner/repository"
FORK = "contributor/repository"
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
BASE_REPOSITORY_ID = 1001
HEAD_REPOSITORY_ID = 2002


def make_run(*, run_id=101, attempt=1):
    return {
        "id": run_id,
        "workflow_id": 9,
        "run_number": 20,
        "run_attempt": attempt,
        "name": "CI",
        "path": ".github/workflows/ci.yml",
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": HEAD_SHA,
        "head_branch": "feature",
        "head_repository": {
            "id": HEAD_REPOSITORY_ID,
            "name": "repository",
            "full_name": FORK,
        },
        "repository": {
            "id": BASE_REPOSITORY_ID,
            "name": "repository",
            "full_name": REPOSITORY,
        },
        "created_at": "2026-08-03T00:00:00Z",
        "pull_requests": [
            {
                "number": 7,
                "head": {
                    "sha": HEAD_SHA,
                    "ref": "feature",
                    "repo": {"id": HEAD_REPOSITORY_ID, "name": "repository", "url": "https://api.github.com/repos/contributor/repository"},
                },
                "base": {
                    "sha": BASE_SHA,
                    "ref": "main",
                    "repo": {"id": BASE_REPOSITORY_ID, "name": "repository", "url": "https://api.github.com/repos/owner/repository"},
                },
            }
        ],
    }


def make_event(run):
    return {
        "action": "completed",
        "repository": {"full_name": REPOSITORY},
        "workflow_run": run,
    }


def make_pr(*, head_sha=HEAD_SHA, state="open"):
    return {
        "number": 7,
        "state": state,
        "head": {
            "sha": head_sha,
            "ref": "feature",
            "repo": {
                "id": HEAD_REPOSITORY_ID,
                "name": "repository",
                "full_name": FORK,
            },
        },
        "base": {
            "sha": BASE_SHA,
            "ref": "main",
            "repo": {
                "id": BASE_REPOSITORY_ID,
                "name": "repository",
                "full_name": REPOSITORY,
            },
        },
    }


def make_archive(
    run,
    *,
    body=b"# report\n",
    body_sha=None,
    symlink=False,
    comment_id="action-smoke",
    extra_file=False,
):
    binding = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "repository_id": BASE_REPOSITORY_ID,
        "workflow_name": "CI",
        "workflow_path": ".github/workflows/ci.yml",
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "pr_number": 7,
        "head_sha": HEAD_SHA,
        "head_ref": "feature",
        "head_repository": FORK,
        "head_repository_id": HEAD_REPOSITORY_ID,
        "base_sha": BASE_SHA,
        "base_ref": "main",
        "base_repository": REPOSITORY,
        "base_repository_id": BASE_REPOSITORY_ID,
        "comment_id": comment_id,
        "body_path": "pr-comment.md",
        "body_bytes": len(body),
        "body_sha256": body_sha or hashlib.sha256(body).hexdigest(),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("binding.json", json.dumps(binding, separators=(",", ":")))
        if symlink:
            info = zipfile.ZipInfo("pr-comment.md")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, body)
        else:
            archive.writestr("pr-comment.md", body)
        if extra_file:
            archive.writestr("unexpected.txt", b"no")
    return buffer.getvalue()


class FakeClient:
    def __init__(
        self,
        run,
        archive,
        *,
        prs=None,
        runs=None,
        runs_sequence=None,
        artifacts=None,
    ):
        self.run = run
        self.archive = archive
        self.prs = list(prs or [make_pr()])
        self.runs = list(runs or [run])
        self.runs_sequence = list(runs_sequence or [])
        self.runs_calls = 0
        self.artifacts = artifacts or [
            {
                "name": f"pcbex-pr-comment-{run['id']}-{run['run_attempt']}",
                "expired": False,
                "size_in_bytes": len(archive),
                "archive_download_url": "https://api.github.com/artifacts/1/zip",
            }
        ]
        self.pr_calls = 0

    def get_run(self, repository, run_id):
        self.asserted_run = (repository, run_id)
        return self.run

    def list_artifacts(self, repository, run_id):
        return list(self.artifacts)

    def download_artifact(self, artifact):
        return self.archive

    def get_pull_request(self, repository, number):
        value = self.prs[min(self.pr_calls, len(self.prs) - 1)]
        self.pr_calls += 1
        return value

    def list_runs(self, repository, workflow_id, head_sha):
        if self.runs_sequence:
            value = self.runs_sequence[min(self.runs_calls, len(self.runs_sequence) - 1)]
            self.runs_calls += 1
            return list(value)
        return list(self.runs)


class PublishPrCommentTests(unittest.TestCase):
    def setUp(self):
        self.run = make_run()
        self.event = make_event(self.run)

    def publish(self, client):
        calls = []

        def fake_upsert(client, repository, number, comment_id, body):
            calls.append((repository, number, comment_id, body))
            return "created", {"id": 1, "html_url": "https://github.test/comment/1"}

        result = publish_pr_comment.publish_from_event(
            self.event, REPOSITORY, client, upsert=fake_upsert
        )
        return result, calls

    def test_accepts_fork_pull_request_and_adds_provenance(self):
        result, calls = self.publish(
            FakeClient(self.run, make_archive(self.run))
        )
        self.assertEqual(result, "published")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], (REPOSITORY, 7, "action-smoke"))
        self.assertIn("> **pcbex provenance:**", calls[0][3])
        self.assertIn("run_id=101 run_attempt=1", calls[0][3])
        self.assertIn(HEAD_SHA, calls[0][3])

    def test_closed_pull_request_is_a_safe_skip(self):
        result, calls = self.publish(
            FakeClient(self.run, make_archive(self.run), prs=[make_pr(state="closed")])
        )
        self.assertEqual(result, "skipped")
        self.assertEqual(calls, [])

    def test_run_association_is_required_and_unambiguous(self):
        self.run["pull_requests"] = []
        result, calls = self.publish(FakeClient(self.run, make_archive(self.run)))
        self.assertEqual(result, "skipped")
        self.assertEqual(calls, [])

        self.run["pull_requests"] = [
            self.run["pull_requests"]
            for _ in range(2)
        ]
        result, calls = self.publish(FakeClient(self.run, make_archive(self.run)))
        self.assertEqual(result, "skipped")
        self.assertEqual(calls, [])

    def test_run_association_and_comment_id_are_bound(self):
        api_run = make_run()
        api_run["pull_requests"][0]["number"] = 8
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(api_run, make_archive(self.run)))
        api_run = make_run()
        api_run["pull_requests"][0]["head"]["repo"]["id"] += 1
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(api_run, make_archive(self.run)))
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(
                FakeClient(self.run, make_archive(self.run, comment_id="other"))
            )

    def test_api_run_mismatch_and_malformed_event_fail_closed(self):
        api_run = make_run()
        api_run["path"] = ".github/workflows/other.yml"
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(api_run, make_archive(self.run)))
        malformed = dict(self.event)
        malformed.pop("repository")
        with self.assertRaises(publish_pr_comment.PublisherError):
            publish_pr_comment.publish_from_event(
                malformed,
                REPOSITORY,
                FakeClient(self.run, make_archive(self.run)),
                upsert=lambda *args: ("created", {"id": 1}),
            )

    def test_pr_race_is_a_safe_skip(self):
        changed = make_pr(head_sha="c" * 40)
        result, calls = self.publish(
            FakeClient(self.run, make_archive(self.run), prs=[make_pr(), changed])
        )
        self.assertEqual(result, "skipped")
        self.assertEqual(calls, [])
        changed_id = make_pr()
        changed_id["head"]["repo"]["id"] += 1
        result, calls = self.publish(
            FakeClient(self.run, make_archive(self.run), prs=[make_pr(), changed_id])
        )
        self.assertEqual(result, "skipped")
        self.assertEqual(calls, [])

    def test_untrusted_markdown_is_escaped_and_mentions_are_neutralized(self):
        body = b"<script>alert('x')</script> @everyone & @user\n"
        result, calls = self.publish(
            FakeClient(self.run, make_archive(self.run, body=body))
        )
        self.assertEqual(result, "published")
        rendered = calls[0][3]
        self.assertIn("> **pcbex provenance:**", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("@everyone", rendered)
        self.assertNotIn("@user", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&#64;\u200beveryone", rendered)

    def test_internal_writer_requires_actions_bot_author_contract(self):
        calls = []

        class Writer:
            class CommentError(RuntimeError):
                pass

            @staticmethod
            def upsert_comment(client, repository, number, comment_id, body, **kwargs):
                calls.append(kwargs)
                return "created", {"id": 1, "html_url": "https://github.test/comment/1"}

        with mock.patch.object(publish_pr_comment, "_load_upsert_module", return_value=Writer):
            result = publish_pr_comment.publish_from_event(
                self.event,
                REPOSITORY,
                FakeClient(self.run, make_archive(self.run)),
            )
        self.assertEqual(result, "published")
        self.assertEqual(calls, [{"expected_author": "github-actions[bot]"}])

    def test_association_repository_name_and_url_are_bound(self):
        api_run = make_run()
        api_run["pull_requests"][0]["head"]["repo"]["name"] = "other"
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(api_run, make_archive(self.run)))
        api_run = make_run()
        del api_run["pull_requests"][0]["head"]["repo"]["url"]
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(api_run, make_archive(self.run)))
        api_run = make_run()
        api_run["pull_requests"][0]["base"]["repo"]["url"] = (
            "https://api.github.com/repos/other/repository"
        )
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(api_run, make_archive(self.run)))
        api_run = make_run()
        api_run["pull_requests"][0]["base"]["repo"]["url"] = (
            "https://api.github.com/unexpected/repos/owner/repository"
        )
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(api_run, make_archive(self.run)))

    def test_newer_run_and_rerun_are_safe_skips(self):
        newer = dict(make_run(run_id=102), run_number=21)
        result, _ = self.publish(
            FakeClient(self.run, make_archive(self.run), runs=[self.run, newer])
        )
        self.assertEqual(result, "skipped")

    def test_second_latest_run_check_closes_the_publish_race(self):
        newer = dict(make_run(run_id=102), run_number=21)
        result, calls = self.publish(
            FakeClient(
                self.run,
                make_archive(self.run),
                runs_sequence=[[self.run], [self.run, newer]],
            )
        )
        self.assertEqual(result, "skipped")
        self.assertEqual(calls, [])
        rerun = dict(make_run(attempt=2))
        result, _ = self.publish(
            FakeClient(self.run, make_archive(self.run), runs=[self.run, rerun])
        )
        self.assertEqual(result, "skipped")

    def test_duplicate_or_expired_artifact_fails_closed(self):
        artifact = {
            "name": "pcbex-pr-comment-101-1",
            "expired": False,
            "size_in_bytes": 1,
            "archive_download_url": "https://api.github.com/artifacts/1/zip",
        }
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(
                FakeClient(self.run, make_archive(self.run), artifacts=[artifact, artifact])
            )
        artifact["expired"] = True
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(self.run, make_archive(self.run), artifacts=[artifact]))

    def test_zip_symlink_and_hash_tampering_fail_closed(self):
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(self.run, make_archive(self.run, symlink=True)))
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(
                FakeClient(self.run, make_archive(self.run, body_sha="0" * 64))
            )

        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(self.run, make_archive(self.run, extra_file=True)))
        oversized = b"x" * (publish_pr_comment.MAX_ARTIFACT_BYTES + 1)
        with self.assertRaises(publish_pr_comment.PublisherError):
            self.publish(FakeClient(self.run, oversized))

    def test_redirect_does_not_forward_bearer_token(self):
        class Response:
            def __init__(self, data):
                self.data = data
                self.headers = {}
                self.read_once = False

            def read(self, amount=-1):
                if self.read_once:
                    return b""
                self.read_once = True
                return self.data if amount == -1 else self.data[:amount]

            def close(self):
                pass

        class Opener:
            def __init__(self):
                self.requests = []

            def open(self, req, timeout):
                self.requests.append(req)
                if len(self.requests) == 1:
                    headers = {"Location": "https://objects.example.test/a.zip"}
                    raise error.HTTPError(req.full_url, 302, "Found", headers, io.BytesIO())
                return Response(b"archive")

        opener = Opener()
        data = publish_pr_comment._download_https_redirect_safe(
            "https://api.github.com/repos/o/r/actions/artifacts/1/zip",
            "api.github.com",
            "secret-token",
            opener,
        )
        self.assertEqual(data, b"archive")
        self.assertEqual(opener.requests[0].get_header("Authorization"), "Bearer secret-token")
        self.assertIsNone(opener.requests[1].get_header("Authorization"))


if __name__ == "__main__":
    unittest.main()

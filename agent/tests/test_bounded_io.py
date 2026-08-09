import errno
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pcbex_agent import bounded_io
from pcbex_agent.bounded_io import (
    BoundedIOError,
    atomic_write,
    atomic_write_no_clobber,
    ensure_parent,
    read_bytes,
    read_text,
    validate_no_clobber_path,
)


def _symlink_or_skip(case: unittest.TestCase, target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as error:
        case.skipTest(f"symbolic links are unavailable: {error}")


class BoundedIOTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        # macOS's default temporary path is lexically below ``/var``, which is
        # itself a system symlink.  The test owns this root, so use its trusted
        # canonical spelling before exercising strict descendant checks.
        self.root = Path(self._temporary.name).resolve(strict=True)

    def tearDown(self):
        self._temporary.cleanup()

    def test_positive_limit_and_exact_bound(self):
        path = self.root / "input"
        path.write_bytes(b"1234")
        self.assertEqual(read_bytes(path, max_bytes=4), b"1234")
        self.assertEqual(read_text(path, max_bytes=4), "1234")

        path.write_bytes(b"12345")
        with self.assertRaises(BoundedIOError):
            read_bytes(path, max_bytes=4)
        for invalid in (0, -1, True, False, 1.5):
            with self.subTest(invalid=invalid), self.assertRaises(BoundedIOError):
                read_bytes(path, max_bytes=invalid)

    def test_empty_input_is_stable_across_both_read_passes(self):
        path = self.root / "empty"
        path.write_bytes(b"")
        self.assertEqual(read_bytes(path, max_bytes=1), b"")

    def test_same_size_in_place_mutation_between_read_passes_is_rejected(self):
        path = self.root / "input"
        path.write_bytes(b"first")
        real_lseek = bounded_io.os.lseek
        mutated = False

        def racing_lseek(descriptor, offset, whence):
            nonlocal mutated
            if offset == 0 and whence == os.SEEK_SET and not mutated:
                path.write_bytes(b"other")
                mutated = True
            return real_lseek(descriptor, offset, whence)

        with patch.object(bounded_io.os, "lseek", side_effect=racing_lseek):
            with self.assertRaises(BoundedIOError) as raised:
                read_bytes(path, max_bytes=5)
        self.assertTrue(mutated)
        self.assertIn("contents changed", str(raised.exception))

    def test_invalid_utf8_is_typed(self):
        path = self.root / "invalid-utf8"
        path.write_bytes(b"\xff\xfe")
        with self.assertRaises(BoundedIOError) as raised:
            read_text(path, max_bytes=2)
        self.assertIn("UTF-8", str(raised.exception))

    def test_only_regular_files_are_accepted(self):
        directory = self.root / "directory"
        directory.mkdir()
        with self.assertRaises(BoundedIOError):
            read_bytes(directory, max_bytes=1)
        with self.assertRaises(BoundedIOError):
            atomic_write(directory, b"x", max_bytes=1)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_direct_and_ancestor_symlinks_are_rejected(self):
        target = self.root / "target"
        target.write_bytes(b"safe")
        direct = self.root / "direct"
        _symlink_or_skip(self, target, direct)
        with self.assertRaises(BoundedIOError):
            read_bytes(direct, max_bytes=4)
        with self.assertRaises(BoundedIOError):
            atomic_write(direct, b"unsafe", max_bytes=6)

        linked_parent = self.root / "linked-parent"
        _symlink_or_skip(self, self.root, linked_parent)
        nested = linked_parent / "target"
        with self.assertRaises(BoundedIOError):
            read_bytes(nested, max_bytes=4)
        with self.assertRaises(BoundedIOError):
            atomic_write(linked_parent / "new", b"unsafe", max_bytes=6)
        self.assertEqual(target.read_bytes(), b"safe")

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_parent_traversal_cannot_bypass_ancestor_symlink_checks(self):
        secret = self.root / "secret"
        secret.mkdir()
        protected = secret / "protected"
        protected.write_bytes(b"safe")
        redirected = self.root / "redirected"
        _symlink_or_skip(self, secret, redirected)

        work = self.root / "work"
        decoy = work / "redirected"
        decoy.mkdir(parents=True)
        (decoy / "protected").write_bytes(b"decoy")
        previous = Path.cwd()
        try:
            os.chdir(work)
            escaping = Path("..") / "redirected" / "protected"
            with self.assertRaisesRegex(BoundedIOError, "parent-directory traversal"):
                read_bytes(escaping, max_bytes=5)
            with self.assertRaisesRegex(BoundedIOError, "parent-directory traversal"):
                atomic_write(escaping, b"owned", max_bytes=5)
        finally:
            os.chdir(previous)

        self.assertEqual(protected.read_bytes(), b"safe")
        self.assertEqual((decoy / "protected").read_bytes(), b"decoy")

    def test_parent_creation_and_nested_atomic_overwrite(self):
        path = self.root / "new" / "nested" / "output"
        self.assertEqual(ensure_parent(path), path.parent)
        atomic_write(path, b"new", max_bytes=3)
        self.assertEqual(path.read_bytes(), b"new")

    def test_no_clobber_preserves_existing_destination(self):
        path = self.root / "output"
        atomic_write_no_clobber(path, b"first", max_bytes=5)
        with self.assertRaises(BoundedIOError):
            atomic_write_no_clobber(path, b"second", max_bytes=6)
        self.assertEqual(path.read_bytes(), b"first")

    def test_atomic_writes_accept_exact_byte_limit(self):
        overwrite = self.root / "overwrite"
        overwrite.write_bytes(b"old")
        atomic_write(overwrite, b"1234", max_bytes=4)
        self.assertEqual(overwrite.read_bytes(), b"1234")

        no_clobber = self.root / "no-clobber"
        atomic_write_no_clobber(no_clobber, b"1234", max_bytes=4)
        self.assertEqual(no_clobber.read_bytes(), b"1234")

    def test_oversized_non_ascii_text_is_rejected_before_full_encode(self):
        class DetectFullEncode(str):
            def encode(self, *_args, **_kwargs):
                raise AssertionError("oversized string was encoded as one allocation")

        path = self.root / "unicode-output"
        with self.assertRaises(BoundedIOError):
            atomic_write(
                path,
                DetectFullEncode("日" * 3),
                max_bytes=8,
            )
        self.assertFalse(path.exists())

    def test_write_only_existing_destination_can_be_overwritten(self):
        if os.name == "nt":
            self.skipTest("Unix permission bits are not portable on Windows")
        if not hasattr(os, "fchmod"):
            self.skipTest("fchmod is unavailable")
        path = self.root / "write-only"
        path.write_bytes(b"old")
        os.chmod(path, stat.S_IWUSR)
        atomic_write(path, b"new", max_bytes=3)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), stat.S_IWUSR)
        # The test may run as the file owner without elevated privileges; make
        # the replacement readable before asserting its bytes.
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        self.assertEqual(path.read_bytes(), b"new")

    def test_validate_no_clobber_path_checks_missing_destination_without_writing(self):
        path = self.root / "missing"
        before = set(os.listdir(self.root))
        self.assertEqual(validate_no_clobber_path(path), path)
        self.assertFalse(path.exists())
        self.assertEqual(set(os.listdir(self.root)), before)

        nested = self.root / "not-created" / "yet" / "output"
        self.assertEqual(validate_no_clobber_path(nested), nested)
        self.assertFalse(nested.parent.exists())

        path.write_bytes(b"existing")
        with self.assertRaisesRegex(BoundedIOError, "no-clobber"):
            validate_no_clobber_path(path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_validate_no_clobber_path_rejects_dangling_and_ancestor_symlinks(self):
        dangling = self.root / "dangling"
        _symlink_or_skip(self, self.root / "does-not-exist", dangling)
        with self.assertRaisesRegex(BoundedIOError, "symbolic link"):
            validate_no_clobber_path(dangling)

        linked_parent = self.root / "linked-parent"
        _symlink_or_skip(self, self.root, linked_parent)
        with self.assertRaisesRegex(BoundedIOError, "symbolic link"):
            validate_no_clobber_path(linked_parent / "new")

    def test_overwrite_preserves_unix_mode(self):
        path = self.root / "output"
        path.write_bytes(b"old")
        if not hasattr(os, "fchmod"):
            self.skipTest("fchmod is unavailable")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        atomic_write(path, b"new", max_bytes=3)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    @unittest.skipIf(os.name == "nt", "Windows skips directory fsync")
    def test_unsupported_directory_fsync_keeps_atomic_publication_portable(self):
        path = self.root / "output"
        real_fsync = bounded_io.os.fsync

        def fsync_or_reject_directory(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EINVAL, "directory fsync unsupported")
            return real_fsync(descriptor)

        with patch.object(
            bounded_io.os,
            "fsync",
            side_effect=fsync_or_reject_directory,
        ):
            atomic_write(path, b"published", max_bytes=9)
        self.assertEqual(path.read_bytes(), b"published")

    @unittest.skipIf(os.name == "nt", "Windows skips directory fsync")
    def test_no_clobber_directory_sync_failure_rolls_back_publication(self):
        path = self.root / "output"
        real_fsync = bounded_io.os.fsync

        def fsync_or_fail_directory(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "directory sync failed")
            return real_fsync(descriptor)

        with patch.object(
            bounded_io.os,
            "fsync",
            side_effect=fsync_or_fail_directory,
        ), self.assertRaises(BoundedIOError):
            atomic_write_no_clobber(path, b"uncommitted", max_bytes=11)

        self.assertFalse(path.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_oversize_write_preserves_sentinel_and_leaves_no_temp(self):
        path = self.root / "output"
        path.write_bytes(b"sentinel")
        before = set(os.listdir(self.root))
        with self.assertRaises(BoundedIOError):
            atomic_write(path, b"12345", max_bytes=4)
        with self.assertRaises(BoundedIOError):
            atomic_write(path, "日本", max_bytes=5)
        self.assertEqual(path.read_bytes(), b"sentinel")
        self.assertEqual(set(os.listdir(self.root)), before)

    @unittest.skipIf(
        os.name == "nt",
        "Windows open-handle sharing can prevent the simulated replacement",
    )
    def test_replacement_after_open_is_rejected(self):
        path = self.root / "input"
        replacement = self.root / "replacement"
        path.write_bytes(b"old")
        replacement.write_bytes(b"new")
        real_open = bounded_io.os.open
        swapped = False

        def racing_open(candidate, flags, *args, **kwargs):
            nonlocal swapped
            descriptor = real_open(candidate, flags, *args, **kwargs)
            if Path(candidate) == path and not swapped:
                os.replace(replacement, path)
                swapped = True
            return descriptor

        with patch.object(bounded_io.os, "open", side_effect=racing_open):
            with self.assertRaises(BoundedIOError):
                read_bytes(path, max_bytes=3)
        self.assertTrue(swapped)
        self.assertEqual(path.read_bytes(), b"new")


if __name__ == "__main__":
    unittest.main()

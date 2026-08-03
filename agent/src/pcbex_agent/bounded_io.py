"""Small, bounded and symlink-aware file I/O helpers for the Python agent.

The agent receives paths from callers, so using :class:`pathlib.Path`'s
convenience ``read_*`` and ``write_*`` methods directly would leave several
important checks to the operating system's default (follow-symlink) behavior.
This module keeps those checks in one place:

* every operation has an explicit, positive ``max_bytes`` limit;
* paths are walked with ``lstat`` and direct or ancestor symbolic links (and
  Windows reparse points) are rejected;
* reads compare the path and opened descriptor before and after reading;
* writes stage data beside the destination, sync the staged file, and publish
  it atomically; and
* no-clobber publication uses an atomic hard-link creation, so a destination
  that appears while a file is being staged is not overwritten.

The path checks reduce replacement races but are deliberately not an OS
filesystem sandbox.  A hostile local administrator can still replace an
ancestor between two system calls.  Callers needing that threat model should
run the agent in an isolated filesystem namespace/container.
"""

from __future__ import annotations

import errno
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Final, TypeAlias


PathLike: TypeAlias = str | os.PathLike[str]
_READ_CHUNK: Final = 1024 * 1024
_TEXT_VALIDATION_CHUNK_CHARACTERS: Final = 64 * 1024
# Older Python versions do not expose ``FILE_ATTRIBUTE_REPARSE_POINT`` even
# though ``st_file_attributes`` is present on ``stat_result``.
_FILE_ATTRIBUTE_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class BoundedIOError(OSError):
    """Typed failure raised by all bounded file-I/O helpers.

    ``BoundedIOError`` subclasses :class:`OSError`, preserving the usual
    ``errno``/``filename`` attributes where an underlying system call supplied
    them while giving callers one stable exception type to catch.
    """


def _validation_error(message: str, path: PathLike | None = None) -> BoundedIOError:
    return BoundedIOError(errno.EINVAL, message, os.fspath(path) if path is not None else None)


def _changed_error(path: PathLike, detail: str) -> BoundedIOError:
    return BoundedIOError(
        errno.EIO,
        f"{os.fspath(path)}: {detail}",
        os.fspath(path),
    )


def _oversized_error(path: PathLike, size: int, max_bytes: int) -> BoundedIOError:
    return BoundedIOError(
        errno.EFBIG,
        f"{os.fspath(path)} exceeds the {max_bytes}-byte limit ({size} bytes)",
        os.fspath(path),
    )


def _wrap_os_error(error: OSError, operation: str, path: PathLike) -> BoundedIOError:
    if isinstance(error, BoundedIOError):
        return error
    message = f"{operation} {os.fspath(path)}: {error.strerror or error}"
    if error.errno is not None:
        return BoundedIOError(error.errno, message, os.fspath(path))
    return BoundedIOError(message)


def _path(path: PathLike) -> Path:
    try:
        raw = os.fspath(path)
        if isinstance(raw, bytes):
            raise TypeError("bytes paths are not supported")
        if not raw:
            raise ValueError("path must not be empty")
        value = Path(raw)
    except (TypeError, ValueError) as error:
        raise _validation_error(f"path is not valid: {error}") from error
    if "\x00" in os.fspath(value):
        raise _validation_error("path must not contain a NUL byte", value)
    if ".." in value.parts:
        raise _validation_error(
            "path must not contain parent-directory traversal ('..')", value
        )
    return value


def _validate_max_bytes(max_bytes: int) -> None:
    # bool is an int subclass, but accepting True as a one-byte limit is an
    # especially easy caller mistake to miss.
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise _validation_error("max_bytes must be a positive integer")


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    """Return the platform file identity used for path/descriptor checks."""

    return metadata.st_dev, metadata.st_ino


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return _identity(left) == _identity(right)


def _is_reparse_point(metadata: os.stat_result) -> bool:
    """Return whether a Windows path component is marked as a reparse point."""

    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", 0) or 0
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_link_like(metadata: os.stat_result, path: PathLike, role: str) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise _validation_error(
            f"{role} contains a symbolic link: {os.fspath(path)}", path
        )
    if _is_reparse_point(metadata):
        raise _validation_error(
            f"{role} contains a Windows reparse point: {os.fspath(path)}", path
        )


def _ensure_regular(metadata: os.stat_result, path: PathLike, role: str) -> None:
    _reject_link_like(metadata, path, role)
    if not stat.S_ISREG(metadata.st_mode):
        raise _validation_error(
            f"{role} must be a regular non-symlink file: {os.fspath(path)}", path
        )


def _ensure_directory(metadata: os.stat_result, path: PathLike, role: str) -> None:
    _reject_link_like(metadata, path, role)
    if not stat.S_ISDIR(metadata.st_mode):
        raise _validation_error(f"{role} must be a real directory: {os.fspath(path)}", path)


def _component_paths(path: Path) -> list[tuple[Path, bool]]:
    """Yield lexical path prefixes and whether each is the final component.

    ``Path`` normalizes ``.`` components. Parent-directory traversal is
    rejected by :func:`_path` before this walker is reached, so every prefix is
    anchored unambiguously to the caller's current lexical path.
    """

    parts = path.parts
    if not parts:
        return []
    current = Path(path.anchor) if path.anchor else Path(".")
    result: list[tuple[Path, bool]] = []
    for index, component in enumerate(parts):
        if component == path.anchor or component in ("", "."):
            continue
        current = current / component
        result.append((current, index == len(parts) - 1))
    return result


def _lstat_path(path: PathLike, *, allow_missing_final: bool = False) -> os.stat_result | None:
    """Lstat every path prefix and return the final metadata.

    The final ``os.lstat`` verifies the path after walking its lexical
    components.  ``_path`` rejects parent-directory traversal, while ``Path``
    normalizes ``.`` components before this function is reached.
    """

    value = _path(path)
    prefixes = _component_paths(value)
    for prefix, is_final_component in prefixes:
        try:
            metadata = os.lstat(prefix)
        except OSError as error:
            if (
                allow_missing_final
                and is_final_component
                and error.errno == errno.ENOENT
            ):
                return None
            raise _wrap_os_error(error, "inspect", value) from error
        _reject_link_like(metadata, value, "path")
        if not is_final_component:
            _ensure_directory(metadata, prefix, "path ancestor")

    try:
        metadata = os.lstat(value)
    except OSError as error:
        if allow_missing_final and error.errno == errno.ENOENT:
            return None
        raise _wrap_os_error(error, "inspect", value) from error
    _reject_link_like(metadata, value, "path")
    return metadata


def _parent(path: Path) -> Path:
    parent = path.parent
    return parent if os.fspath(parent) else Path(".")


def _ensure_parent_directory(path: PathLike) -> Path:
    """Create and validate all destination ancestors, returning the parent.

    Existing components are checked with ``lstat`` and newly-created
    components use ``mkdir`` one at a time.  A local administrator can still
    swap a checked component between system calls; this helper therefore offers
    race reduction rather than a privileged filesystem sandbox.
    """

    destination = _path(path)
    parent = _parent(destination)
    prefixes = _component_paths(parent)
    for prefix, _is_final in prefixes:
        try:
            metadata = os.lstat(prefix)
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise _wrap_os_error(error, "inspect parent", parent) from error
            try:
                os.mkdir(prefix, 0o755)
            except OSError as mkdir_error:
                # Another creator may have won the race.  Reinspect and only
                # accept a real directory; a symlink or other object fails
                # closed.
                if mkdir_error.errno != errno.EEXIST:
                    raise _wrap_os_error(mkdir_error, "create parent", prefix) from mkdir_error
                try:
                    metadata = os.lstat(prefix)
                except OSError as inspect_error:
                    raise _wrap_os_error(
                        inspect_error, "inspect parent", prefix
                    ) from inspect_error
            else:
                try:
                    metadata = os.lstat(prefix)
                except OSError as inspect_error:
                    raise _wrap_os_error(
                        inspect_error, "inspect parent", prefix
                    ) from inspect_error
        _reject_link_like(metadata, parent, "parent")
        _ensure_directory(metadata, prefix, "output parent")

    try:
        metadata = os.lstat(parent)
    except OSError as error:
        raise _wrap_os_error(error, "inspect parent", parent) from error
    _reject_link_like(metadata, parent, "parent")
    _ensure_directory(metadata, parent, "output parent")
    return parent


def ensure_parent(path: PathLike) -> Path:
    """Create a destination's parent directories after symlink checks.

    This is intended for agent output paths.  It does not claim to defend
    against a hostile local administrator replacing an ancestor between the
    checks and a later open/rename; use a filesystem namespace for that case.
    """

    return _ensure_parent_directory(path)


def create_safe_parent(path: PathLike) -> Path:
    """Alias for :func:`ensure_parent` used by output-producing callers."""

    return ensure_parent(path)


def validate_no_clobber_path(path: PathLike) -> Path:
    """Validate a safe, currently-missing no-clobber destination.

    Unlike :func:`ensure_parent`, this preflight never creates directories or
    opens the destination for writing.  It is useful before an external
    operation (for example, an AI provider request) so a dangling symlink,
    ancestor symlink/reparse point, or already-existing destination is rejected
    before that operation starts.  The subsequent
    :func:`atomic_write_no_clobber` call remains the authoritative race-safe
    publication check.

    Existing destination-parent components must be real directories.  Missing
    parent components are accepted (and left untouched); the later atomic
    writer will create them one at a time with the same checks.  A missing
    final component is accepted and returned as a normalized ``Path``.
    """

    destination = _path(path)
    parent = _parent(destination)
    parent_complete = True
    prefixes = _component_paths(parent)
    if not prefixes:
        try:
            parent_metadata = os.lstat(parent)
        except OSError as error:
            if error.errno == errno.ENOENT:
                parent_complete = False
            else:
                raise _wrap_os_error(error, "inspect parent", parent) from error
        else:
            _reject_link_like(parent_metadata, parent, "parent")
            _ensure_directory(parent_metadata, parent, "output parent")
    else:
        for prefix, _is_final in prefixes:
            try:
                metadata = os.lstat(prefix)
            except OSError as error:
                if error.errno == errno.ENOENT:
                    parent_complete = False
                    break
                raise _wrap_os_error(error, "inspect parent", parent) from error
            _reject_link_like(metadata, parent, "parent")
            _ensure_directory(metadata, prefix, "output parent")

    # If an ancestor is absent, the final destination cannot currently name an
    # object.  Avoid _lstat_path here because its strict ancestor handling would
    # turn this safe missing-target case into an unnecessary ENOENT failure.
    if not parent_complete:
        return destination

    existing = _lstat_path(destination, allow_missing_final=True)
    if existing is not None:
        _ensure_regular(existing, destination, "output")
        raise BoundedIOError(
            errno.EEXIST,
            f"output already exists (no-clobber): {destination}",
            os.fspath(destination),
        )
    return destination


def _open_read_descriptor(path: Path, expected: os.stat_result) -> tuple[int, os.stat_result]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        # Windows file descriptors otherwise use text mode, so ``os.read``
        # can translate CRLF to LF and make the byte count disagree with
        # ``st_size``.  Bounded I/O must always count the bytes on disk.
        | getattr(os, "O_BINARY", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise _wrap_os_error(error, "open", path) from error
    try:
        opened = os.fstat(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise _wrap_os_error(error, "stat opened", path) from error
    try:
        _ensure_regular(opened, path, "opened input")
        current = _lstat_path(path)
        if (
            current is None
            or not _same_file(expected, opened)
            or opened.st_size != expected.st_size
        ):
            raise _changed_error(path, "path or descriptor changed while opening")
        if not _same_file(expected, current) or current.st_size != expected.st_size:
            raise _changed_error(path, "path changed while opening")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, opened


def read_bytes(path: PathLike, *, max_bytes: int) -> bytes:
    """Read one regular non-symlink file under ``max_bytes`` bytes.

    Exactly ``max_bytes`` bytes is valid; one additional byte is rejected.
    The path and descriptor are checked before, during, and after the read so
    replacement or resize races fail closed.
    """

    _validate_max_bytes(max_bytes)
    value = _path(path)
    try:
        expected = _lstat_path(value)
        if expected is None:  # pragma: no cover - _lstat_path only returns None when allowed
            raise _validation_error(f"input does not exist: {value}", value)
        _ensure_regular(expected, value, "input")
        if expected.st_size > max_bytes:
            raise _oversized_error(value, expected.st_size, max_bytes)

        descriptor, opened = _open_read_descriptor(value, expected)
        try:
            chunks: list[bytes] = []
            total = 0
            # Read one byte beyond the advertised bound.  This catches a file
            # that grows after the initial size check without allocating an
            # unbounded buffer.
            read_limit = max_bytes + 1
            while total < read_limit:
                chunk_size = min(_READ_CHUNK, read_limit - total)
                try:
                    chunk = os.read(descriptor, chunk_size)
                except OSError as error:
                    raise _wrap_os_error(error, "read", value) from error
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > max_bytes:
                raise _oversized_error(value, total, max_bytes)

            try:
                after = os.fstat(descriptor)
            except OSError as error:
                raise _wrap_os_error(error, "stat read", value) from error
            _ensure_regular(after, value, "opened input")
            if (
                not _same_file(opened, after)
                or after.st_size != expected.st_size
                or total != expected.st_size
            ):
                raise _changed_error(value, "changed while being read")

            final = _lstat_path(value)
            if (
                final is None
                or not _same_file(expected, final)
                or final.st_size != expected.st_size
                or not _same_file(opened, final)
            ):
                raise _changed_error(value, "path identity or size changed while being read")
            return b"".join(chunks)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
    except BoundedIOError:
        raise
    except OSError as error:
        raise _wrap_os_error(error, "read", value) from error


def read_text(path: PathLike, *, max_bytes: int) -> str:
    """Read bounded bytes and decode them as strict UTF-8 text."""

    value = _path(path)
    try:
        return read_bytes(value, max_bytes=max_bytes).decode("utf-8", errors="strict")
    except BoundedIOError:
        raise
    except UnicodeDecodeError as error:
        raise BoundedIOError(
            errno.EILSEQ,
            f"{value} is not valid UTF-8: {error}",
            os.fspath(value),
        ) from error


def _as_bytes(contents: Any, path: PathLike, max_bytes: int) -> bytes:
    if isinstance(contents, str):
        # Every Unicode scalar requires at least one UTF-8 byte. Reject an
        # obviously oversized string before allocating its encoded copy.
        if len(contents) > max_bytes:
            raise _oversized_error(path, len(contents), max_bytes)
        try:
            encoded_size = 0
            for offset in range(
                0,
                len(contents),
                _TEXT_VALIDATION_CHUNK_CHARACTERS,
            ):
                chunk = contents[
                    offset : offset + _TEXT_VALIDATION_CHUNK_CHARACTERS
                ]
                encoded_size += len(chunk.encode("utf-8", errors="strict"))
                if encoded_size > max_bytes:
                    raise _oversized_error(path, encoded_size, max_bytes)
            # Only allocate the complete encoded value after proving that it
            # fits. Oversized non-ASCII text therefore cannot transiently
            # allocate up to four times the configured output budget.
            encoded = contents.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise BoundedIOError(
                errno.EILSEQ,
                f"{os.fspath(path)} is not valid UTF-8 text: {error}",
                os.fspath(path),
            ) from error
        return encoded
    if isinstance(contents, bytes):
        if len(contents) > max_bytes:
            raise _oversized_error(path, len(contents), max_bytes)
        return contents
    try:
        view = memoryview(contents)
    except (TypeError, ValueError) as error:
        raise _validation_error("contents must be bytes-like or UTF-8 text", path) from error
    if view.nbytes > max_bytes:
        raise _oversized_error(path, view.nbytes, max_bytes)
    return view.tobytes()


def _open_existing_output(path: Path, expected: os.stat_result) -> tuple[int, os.stat_result]:
    common_flags = (
        getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    # Linux's O_PATH opens an inode for metadata operations without requiring
    # read permission.  That lets an overwrite preserve a write-only (0200)
    # destination's mode while still performing the identity checks below.
    # Platforms without O_PATH first try O_RDONLY and then O_WRONLY without
    # O_TRUNC when read permission is unavailable.
    path_flags = getattr(os, "O_PATH", None)
    if path_flags is not None:
        open_attempts = (path_flags | common_flags,)
    else:
        open_attempts = (os.O_RDONLY | common_flags, os.O_WRONLY | common_flags)
    descriptor: int | None = None
    open_error: OSError | None = None
    for index, flags in enumerate(open_attempts):
        try:
            descriptor = os.open(path, flags)
            break
        except OSError as error:
            open_error = error
            # The writable fallback is only for an access failure.  Other
            # errors (missing path, directory, etc.) should retain their
            # original errno and not be retried with different semantics.
            if index == 0 and len(open_attempts) > 1 and error.errno in (
                errno.EACCES,
                errno.EPERM,
            ):
                continue
            break
    if descriptor is None:
        assert open_error is not None
        raise _wrap_os_error(open_error, "open output", path) from open_error
    try:
        opened = os.fstat(descriptor)
        _ensure_regular(opened, path, "opened output")
        current = _lstat_path(path)
        if (
            current is None
            or not _same_file(expected, opened)
            or opened.st_size != expected.st_size
            or not _same_file(expected, current)
            or current.st_size != expected.st_size
        ):
            raise _changed_error(path, "path or descriptor changed while opening")
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _check_parent_identity(parent: Path, expected: os.stat_result) -> None:
    current = _lstat_path(parent)
    if current is None or not stat.S_ISDIR(current.st_mode) or not _same_file(expected, current):
        raise _changed_error(parent, "output parent changed while being written")


def _write_all(descriptor: int, data: bytes, path: Path) -> None:
    view = memoryview(data)
    offset = 0
    try:
        while offset < len(view):
            count = os.write(descriptor, view[offset : offset + _READ_CHUNK])
            if count <= 0:
                raise OSError(errno.EIO, "write returned no progress")
            offset += count
    except OSError as error:
        raise _wrap_os_error(error, "write temporary file", path) from error


def _sync_file(descriptor: int, path: Path) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise _wrap_os_error(error, "sync temporary file", path) from error


def _sync_parent(parent: Path) -> None:
    # Directory fsync is available on Unix.  Windows generally rejects opening
    # a directory as a normal file; publication remains atomic there, but there
    # is no portable directory durability primitive in the stdlib.
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(parent, flags)
    except OSError as error:
        raise _wrap_os_error(error, "open parent for sync", parent) from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno in {
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }:
            # Some otherwise atomic-write-capable filesystems/platforms do
            # not implement fsync for directory descriptors. The staged file
            # itself was already fsynced; retain atomic publication while
            # documenting that parent-entry crash durability is unavailable.
            return
        raise _wrap_os_error(error, "sync parent", parent) from error
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _set_mode(descriptor: int, existing: os.stat_result | None, path: Path) -> None:
    mode = stat.S_IMODE(existing.st_mode) if existing is not None else 0o644
    try:
        os.fchmod(descriptor, mode)
    except AttributeError:
        # Windows has no fchmod in some Python builds.  mkstemp's mode is still
        # safe; os.chmod on the path would introduce an avoidable race.
        if existing is not None:
            return
    except OSError as error:
        raise _wrap_os_error(error, "set temporary permissions", path) from error


def _publish_overwrite(temporary: Path, destination: Path) -> None:
    try:
        os.replace(temporary, destination)
    except OSError as error:
        raise _wrap_os_error(error, "replace output", destination) from error


def _publish_no_clobber(temporary: Path, destination: Path) -> None:
    try:
        # Hard-link creation is atomic and fails with EEXIST if another writer
        # created the destination after our preflight.  Both paths are in the
        # same parent, so this does not cross filesystems.
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except (TypeError, NotImplementedError):
            # Some Windows Python builds do not expose follow_symlinks for
            # hard links. The source is our freshly-created, identity-checked
            # private regular file, so the two-argument form is equivalent.
            os.link(temporary, destination)
    except OSError as error:
        if error.errno == errno.EEXIST:
            raise BoundedIOError(
                errno.EEXIST,
                f"output already exists (no-clobber): {destination}",
                os.fspath(destination),
            ) from error
        raise _wrap_os_error(error, "publish no-clobber output", destination) from error


def _publish(
    destination: Path,
    data: bytes,
    *,
    max_bytes: int,
    no_clobber: bool,
) -> None:
    if len(data) > max_bytes:
        raise _oversized_error(destination, len(data), max_bytes)

    parent = _ensure_parent_directory(destination)
    parent_metadata = _lstat_path(parent)
    if parent_metadata is None:
        raise _validation_error(f"output parent does not exist: {parent}", parent)
    _ensure_directory(parent_metadata, parent, "output parent")

    existing = _lstat_path(destination, allow_missing_final=True)
    existing_descriptor: int | None = None
    try:
        if existing is not None:
            _ensure_regular(existing, destination, "output")
            if no_clobber:
                raise BoundedIOError(
                    errno.EEXIST,
                    f"output already exists (no-clobber): {destination}",
                    os.fspath(destination),
                )
            existing_descriptor, _opened = _open_existing_output(destination, existing)

        try:
            temporary_descriptor, temporary_name = tempfile.mkstemp(
                prefix=".pcbex-bounded-", dir=os.fspath(parent)
            )
        except OSError as error:
            raise _wrap_os_error(error, "create temporary output", destination) from error
        temporary = Path(temporary_name)
        try:
            _set_mode(temporary_descriptor, existing, destination)
            _write_all(temporary_descriptor, data, destination)
            _sync_file(temporary_descriptor, destination)
            try:
                temporary_metadata = os.fstat(temporary_descriptor)
            except OSError as error:
                raise _wrap_os_error(error, "stat temporary output", destination) from error
            _ensure_regular(temporary_metadata, temporary, "temporary output")
            if temporary_metadata.st_size != len(data):
                raise _changed_error(destination, "temporary output size changed")

            _check_parent_identity(parent, parent_metadata)
            current = _lstat_path(destination, allow_missing_final=True)
            if existing is not None:
                if (
                    current is None
                    or not _same_file(existing, current)
                    or current.st_size != existing.st_size
                    or existing_descriptor is None
                ):
                    raise _changed_error(destination, "output changed while being written")
                descriptor_metadata = os.fstat(existing_descriptor)
                if (
                    not _same_file(existing, descriptor_metadata)
                    or descriptor_metadata.st_size != existing.st_size
                    or not _same_file(descriptor_metadata, current)
                ):
                    raise _changed_error(
                        destination, "output descriptor changed while being written"
                    )
            elif current is not None:
                # Overwrite mode permits a regular destination created by a
                # concurrent writer, matching normal replace semantics.  A
                # symlink or other object remains rejected by the checks above.
                _ensure_regular(current, destination, "output")
                if no_clobber:
                    raise BoundedIOError(
                        errno.EEXIST,
                        f"output appeared (no-clobber): {destination}",
                        os.fspath(destination),
                    )

            # The existing descriptor has done its identity work.  Closing it
            # before replace also permits publication on Windows, where open
            # handles may otherwise deny replacement.
            if existing_descriptor is not None:
                try:
                    os.close(existing_descriptor)
                except OSError as error:
                    raise _wrap_os_error(error, "close existing output", destination) from error
                existing_descriptor = None

            # Windows generally denies rename/link publication while the
            # source is held by a CRT descriptor without delete sharing.
            # Retain the staged identity captured above, close only on that
            # platform, and compare the published path to the captured
            # metadata. Unix keeps the descriptor open for the stronger final
            # descriptor/path identity check.
            if os.name == "nt":
                try:
                    os.close(temporary_descriptor)
                except OSError as error:
                    raise _wrap_os_error(error, "close temporary output", destination) from error
                temporary_descriptor = None

            if no_clobber:
                _publish_no_clobber(temporary, destination)
            else:
                _publish_overwrite(temporary, destination)

            # Verify that the path now names exactly the fully-written staged
            # inode, using the live descriptor where the platform allows it.
            final = _lstat_path(destination)
            if temporary_descriptor is None:
                temporary_after = temporary_metadata
            else:
                try:
                    temporary_after = os.fstat(temporary_descriptor)
                except OSError as error:
                    raise _wrap_os_error(error, "stat published output", destination) from error
            if (
                final is None
                or not _same_file(final, temporary_after)
                or final.st_size != len(data)
                or temporary_after.st_size != len(data)
            ):
                raise _changed_error(destination, "published output identity or size changed")

            if no_clobber:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
            _sync_parent(parent)
        finally:
            if temporary_descriptor is not None:
                try:
                    os.close(temporary_descriptor)
                except OSError:
                    pass
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError:
                # Preserve the primary validation/write error.  A leaked
                # private temporary is preferable to masking it.
                pass
    finally:
        if existing_descriptor is not None:
            try:
                os.close(existing_descriptor)
            except OSError:
                pass


def atomic_write(
    path: PathLike,
    contents: bytes | bytearray | memoryview | str,
    *,
    max_bytes: int,
) -> None:
    """Atomically overwrite a regular destination with bounded contents."""

    _validate_max_bytes(max_bytes)
    destination = _path(path)
    data = _as_bytes(contents, destination, max_bytes)
    _publish(destination, data, max_bytes=max_bytes, no_clobber=False)


def atomic_write_no_clobber(
    path: PathLike,
    contents: bytes | bytearray | memoryview | str,
    *,
    max_bytes: int,
) -> None:
    """Atomically publish bounded contents only if ``path`` is absent."""

    _validate_max_bytes(max_bytes)
    destination = _path(path)
    data = _as_bytes(contents, destination, max_bytes)
    _publish(destination, data, max_bytes=max_bytes, no_clobber=True)


def atomic_write_text(path: PathLike, contents: str, *, max_bytes: int) -> None:
    """UTF-8 text convenience wrapper around :func:`atomic_write`."""

    atomic_write(path, contents, max_bytes=max_bytes)


def atomic_write_text_no_clobber(path: PathLike, contents: str, *, max_bytes: int) -> None:
    """UTF-8 text convenience wrapper around no-clobber publication."""

    atomic_write_no_clobber(path, contents, max_bytes=max_bytes)


# Names parallel to the Rust CLI facade and useful to callers migrating from
# pathlib.  They intentionally preserve the keyword-only max_bytes contract.
read = read_bytes
read_to_string = read_text
write = atomic_write
write_no_clobber = atomic_write_no_clobber
write_text = atomic_write_text
write_text_no_clobber = atomic_write_text_no_clobber
write_atomic = atomic_write
write_atomic_no_clobber = atomic_write_no_clobber


__all__ = [
    "BoundedIOError",
    "atomic_write",
    "atomic_write_no_clobber",
    "atomic_write_text",
    "atomic_write_text_no_clobber",
    "create_safe_parent",
    "ensure_parent",
    "validate_no_clobber_path",
    "read",
    "read_bytes",
    "read_text",
    "read_to_string",
    "write",
    "write_atomic",
    "write_atomic_no_clobber",
    "write_no_clobber",
    "write_text",
    "write_text_no_clobber",
]

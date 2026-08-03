//! Bounded, symlink-safe replacements for the `std::fs` convenience I/O
//! helpers used by the CLI.
//!
//! The CLI accepts paths supplied by a caller.  Keeping the small convenience
//! functions here means that every generic read and write has the same
//! resource and path-safety policy while the rest of the filesystem API can
//! continue to be used normally for directory and staging operations.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

const READ_COMPARE_BUFFER_BYTES: usize = 64 * 1024;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    // The hook makes the otherwise timing-sensitive same-inode mutation test
    // deterministic without changing production behavior.  It is invoked
    // after the first pass and before the second pass below.
    static AFTER_FIRST_READ_HOOK: RefCell<Option<Box<dyn FnOnce()>>> =
        RefCell::new(None);
}

#[cfg(test)]
fn invoke_after_first_read_hook() {
    let hook = AFTER_FIRST_READ_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn set_after_first_read_hook(hook: impl FnOnce() + 'static) {
    AFTER_FIRST_READ_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot.replace(Box::new(hook)).is_none());
    });
}

pub use std::fs::{
    File, Metadata, Permissions, canonicalize, create_dir, create_dir_all, read_dir, remove_dir,
    remove_file, rename, symlink_metadata,
};

/// Maximum size of one file accepted by the generic CLI I/O facade.
pub const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;

/// Read one regular, non-symlink file without allowing an unbounded
/// allocation.  The path and opened-file identities are checked before and
/// after two passes, and the second pass is compared with the first so an
/// in-place same-size mutation fails closed as well.
pub fn read<P>(path: P) -> io::Result<Vec<u8>>
where
    P: AsRef<Path>,
{
    read_with_limit(path, MAX_FILE_BYTES)
}

/// Read with a command-specific ceiling that may only tighten the shared
/// production file limit.
pub fn read_with_limit<P>(path: P, max_bytes: u64) -> io::Result<Vec<u8>>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    if max_bytes > MAX_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "configured file limit {max_bytes} exceeds the production limit {MAX_FILE_BYTES}"
            ),
        ));
    }
    let metadata = inspect_path(path, false)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("file does not exist: {}", path.display()),
        )
    })?;
    ensure_regular(&metadata, path, "input")?;
    if metadata.len() > max_bytes {
        return Err(oversized_error(path, metadata.len(), max_bytes));
    }

    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "file size cannot be represented on this platform: {}",
                path.display()
            ),
        )
    })?;
    let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "bounded file size overflows")
    })?;
    let _read_limit_usize = usize::try_from(read_limit).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "bounded file size cannot be represented on this platform",
        )
    })?;

    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    ensure_regular(&opened, path, "opened input")?;
    if !same_file(&metadata, &opened)
        || opened.len() != metadata.len()
        || !opened_path_matches(&file, path)?
    {
        return Err(changed_error(path, "changed while it was being opened"));
    }

    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)?;

    let bytes_len = u64::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "read byte count cannot be represented",
        )
    })?;

    #[cfg(test)]
    invoke_after_first_read_hook();

    // Read the same opened descriptor a second time using a fixed-size buffer.
    // Comparing against the first pass detects an in-place write that leaves
    // the inode and file length unchanged, which metadata checks alone cannot
    // observe.
    file.seek(SeekFrom::Start(0))?;
    let mut compare_buffer = [0_u8; READ_COMPARE_BUFFER_BYTES];
    let mut compared = 0_usize;
    loop {
        let read = file.read(&mut compare_buffer)?;
        if read == 0 {
            break;
        }
        let end = compared.checked_add(read).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "read byte count overflow")
        })?;
        if end > bytes.len() || compare_buffer[..read] != bytes[compared..end] {
            return Err(changed_error(path, "changed while it was being re-read"));
        }
        compared = end;
    }

    let after = file.metadata()?;
    ensure_regular(&after, path, "opened input")?;
    if !same_file(&opened, &after)
        || after.len() != metadata.len()
        || bytes_len != metadata.len()
        || bytes_len > max_bytes
        || compared != bytes.len()
    {
        return Err(changed_error(path, "changed while it was being read"));
    }

    let final_path = inspect_path(path, false)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("file disappeared while being read: {}", path.display()),
        )
    })?;
    ensure_regular(&final_path, path, "input")?;
    if !same_file(&metadata, &final_path)
        || final_path.len() != metadata.len()
        || !opened_path_matches(&file, path)?
    {
        return Err(changed_error(
            path,
            "path identity changed while it was being read",
        ));
    }

    Ok(bytes)
}

/// Read one regular, non-symlink file and decode it as strict UTF-8.
pub fn read_to_string<P>(path: P) -> io::Result<String>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    let bytes = read(path)?;
    String::from_utf8(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8: {error}", path.display()),
        )
    })
}

/// Atomically replace a regular destination with bounded contents.
///
/// The source bytes are checked before any destination metadata is touched.
/// A private temporary file is created in the destination's real parent,
/// flushed and synced, then renamed into place. Existing Unix mode bits are
/// retained; new files use mode `0644` on Unix.
pub fn write<P, C>(path: P, contents: C) -> io::Result<()>
where
    P: AsRef<Path>,
    C: AsRef<[u8]>,
{
    let path = path.as_ref();
    let contents = contents.as_ref();
    let contents_len = u64::try_from(contents.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "write byte count cannot be represented",
        )
    })?;
    if contents_len > MAX_FILE_BYTES {
        return Err(oversized_error(path, contents_len, MAX_FILE_BYTES));
    }

    let existing = inspect_path(path, true)?;
    let existing_file = if let Some(metadata) = &existing {
        ensure_regular(metadata, path, "output")?;
        let file = File::open(path)?;
        let opened = file.metadata()?;
        ensure_regular(&opened, path, "opened output")?;
        if !same_file(metadata, &opened)
            || metadata.len() != opened.len()
            || !opened_path_matches(&file, path)?
        {
            return Err(changed_error(path, "changed while it was being opened"));
        }
        Some(file)
    } else {
        None
    };

    let parent = destination_parent(path);
    let parent_metadata = inspect_path(&parent, false)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("output parent does not exist: {}", parent.display()),
        )
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "output parent must be a real directory: {}",
                parent.display()
            ),
        ));
    }

    let mut temporary = tempfile::Builder::new()
        .prefix(".pcbex-bounded-")
        .tempfile_in(&parent)?;
    set_output_permissions(temporary.as_file(), existing.as_ref())?;
    temporary.write_all(contents)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;

    // Do not replace a destination that was swapped after the initial
    // preflight.  If the destination did not exist initially, a concurrently
    // created regular file is still compatible with std::fs::write's
    // overwrite semantics; symlinks and non-regular files remain rejected.
    let current = inspect_path(path, true)?;
    match (&existing, current) {
        (Some(expected), Some(current)) => {
            ensure_regular(&current, path, "output")?;
            let opened_still_matches = existing_file
                .as_ref()
                .map(|file| opened_path_matches(file, path))
                .transpose()?
                .unwrap_or(false);
            if !same_file(expected, &current)
                || expected.len() != current.len()
                || !opened_still_matches
            {
                return Err(changed_error(path, "changed while it was being written"));
            }
        }
        (Some(_), None) => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("output disappeared while being written: {}", path.display()),
            ));
        }
        (None, Some(current)) => ensure_regular(&current, path, "output")?,
        (None, None) => {}
    }

    temporary.persist(path).map_err(|error| error.error)?;

    // A directory sync is best effort on platforms where directory handles
    // are not synchronizable.  On Unix, propagate a real sync failure because
    // the caller requested a durable atomic output.
    sync_parent(&parent)
}

fn inspect_path(path: &Path, allow_missing_final: bool) -> io::Result<Option<Metadata>> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must not be empty",
        ));
    }

    let components = path.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must contain at least one component",
        ));
    }

    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                current.push(component.as_os_str());
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir | Component::Normal(_) => current.push(component.as_os_str()),
        }

        match symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(symlink_error(path));
                }
            }
            Err(error)
                if allow_missing_final
                    && index + 1 == components.len()
                    && error.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    }

    match symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                Err(symlink_error(path))
            } else {
                Ok(Some(metadata))
            }
        }
        Err(error) if allow_missing_final && error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn ensure_regular(metadata: &Metadata, path: &Path, role: &str) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{role} must be a regular non-symlink file: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn destination_parent(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn oversized_error(path: &Path, bytes: u64, limit: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{} exceeds the {limit}-byte file limit ({bytes} bytes)",
            path.display()
        ),
    )
}

fn symlink_error(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("path contains a symlink: {}", path.display()),
    )
}

fn changed_error(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}: {}", path.display(), detail),
    )
}

#[cfg(unix)]
pub(crate) fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
pub(crate) fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.file_type().is_file() == right.file_type().is_file() && left.len() == right.len()
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.file_type().is_file() == right.file_type().is_file() && left.len() == right.len()
}

#[cfg(windows)]
pub(crate) fn opened_path_matches(opened: &File, path: &Path) -> io::Result<bool> {
    fn identity(file: &File) -> io::Result<(u32, u32, u32)> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };

        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        let handle = file.as_raw_handle() as HANDLE;
        if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            information.dwVolumeSerialNumber,
            information.nFileIndexHigh,
            information.nFileIndexLow,
        ))
    }

    let current = File::open(path)?;
    Ok(identity(opened)? == identity(&current)?)
}

#[cfg(not(windows))]
pub(crate) fn opened_path_matches(_opened: &File, _path: &Path) -> io::Result<bool> {
    Ok(true)
}

fn set_output_permissions(file: &File, existing: Option<&Metadata>) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = existing
            .map(|metadata| metadata.permissions().mode() & 0o7777)
            .unwrap_or(0o644);
        file.set_permissions(Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    if let Some(metadata) = existing {
        file.set_permissions(metadata.permissions())?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};

    fn directory_entries(path: &Path) -> Vec<PathBuf> {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    #[test]
    fn reads_exact_limit_and_rejects_sparse_over_limit() {
        let workspace = tempfile::tempdir().unwrap();
        let exact = workspace.path().join("exact");
        let exact_file = File::create(&exact).unwrap();
        exact_file.set_len(MAX_FILE_BYTES).unwrap();
        drop(exact_file);
        assert_eq!(read(&exact).unwrap().len() as u64, MAX_FILE_BYTES);

        let oversized = workspace.path().join("oversized");
        let oversized_file = File::create(&oversized).unwrap();
        oversized_file.set_len(MAX_FILE_BYTES + 1).unwrap();
        drop(oversized_file);
        assert_eq!(
            read(&oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn reads_empty_file() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("empty");
        File::create(&path).unwrap();
        assert!(read(&path).unwrap().is_empty());
        assert_eq!(read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn command_specific_read_limit_can_only_tighten_global_limit() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("input");
        fs::write(&path, b"12345").unwrap();
        assert_eq!(read_with_limit(&path, 5).unwrap(), b"12345");
        assert_eq!(
            read_with_limit(&path, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            read_with_limit(&path, MAX_FILE_BYTES + 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn rejects_same_inode_same_size_mutation_between_read_passes() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("input");
        let original = vec![b'a'; READ_COMPARE_BUFFER_BYTES * 2 + 17];
        fs::write(&path, &original).unwrap();
        let before = fs::metadata(&path).unwrap();

        let replacement = vec![b'b'; original.len()];
        let expected_after = replacement.clone();
        let hook_path = path.clone();
        set_after_first_read_hook(move || {
            let mut file = File::options().write(true).open(hook_path).unwrap();
            file.write_all(&replacement).unwrap();
            file.flush().unwrap();
        });

        let error = read(&path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed while it was being re-read"),
            "{error}"
        );
        let after = fs::metadata(&path).unwrap();
        assert!(same_file(&before, &after));
        assert_eq!(before.len(), after.len());
        assert_eq!(fs::read(&path).unwrap(), expected_after);
    }

    #[test]
    fn rejects_invalid_utf8() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("invalid");
        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert_eq!(
            read_to_string(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_direct_and_parent_symlinks() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::write(&target, b"safe").unwrap();
        let direct = workspace.path().join("direct");
        symlink(&target, &direct).unwrap();
        assert!(read(&direct).is_err());

        let parent = workspace.path().join("parent");
        symlink(workspace.path(), &parent).unwrap();
        assert!(read(parent.join("target")).is_err());
    }

    #[test]
    fn atomically_replaces_destination_and_leaves_no_tempfile() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("output");
        fs::write(&path, b"old").unwrap();
        let before = directory_entries(workspace.path());
        write(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(directory_entries(workspace.path()), before);
    }

    #[test]
    fn oversized_write_preserves_old_destination_and_has_no_tempfile() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("output");
        fs::write(&path, b"old").unwrap();
        let before = directory_entries(workspace.path());
        let oversized = vec![0_u8; usize::try_from(MAX_FILE_BYTES + 1).unwrap()];
        let error = write(&path, oversized).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!(directory_entries(workspace.path()), before);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_output_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        let output = workspace.path().join("output");
        fs::write(&target, b"safe").unwrap();
        symlink(&target, &output).unwrap();
        assert!(write(&output, b"unsafe").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"safe");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_output_parent_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let real_parent = workspace.path().join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        let linked_parent = workspace.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(write(linked_parent.join("output"), b"unsafe").is_err());
        assert!(!real_parent.join("output").exists());
    }

    #[test]
    fn rejects_nonregular_output_destination() {
        let workspace = tempfile::tempdir().unwrap();
        let directory = workspace.path().join("directory");
        fs::create_dir(&directory).unwrap();
        assert_eq!(
            write(&directory, b"unsafe").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_existing_permissions_and_uses_0644_for_new_files() {
        use std::os::unix::fs::PermissionsExt;

        let workspace = tempfile::tempdir().unwrap();
        let existing = workspace.path().join("existing");
        fs::write(&existing, b"old").unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o600)).unwrap();
        write(&existing, b"new").unwrap();
        assert_eq!(
            fs::metadata(&existing).unwrap().permissions().mode() & 0o7777,
            0o600
        );

        let new_path = workspace.path().join("new");
        write(&new_path, b"new").unwrap();
        assert_eq!(
            fs::metadata(new_path).unwrap().permissions().mode() & 0o7777,
            0o644
        );
    }
}

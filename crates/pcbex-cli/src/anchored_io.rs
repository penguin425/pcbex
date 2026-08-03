//! Directory-anchored temporary-file publication.
//!
//! A path-only `rename` can be redirected when a parent directory is renamed
//! and replaced between its preflight checks and the commit.  This module
//! keeps an open handle to the validated directory and uses a descriptor
//! relative rename on Unix.  Callers should create temporary files through
//! [`PinnedDirectory::create_temp`] and publish them with
//! [`PinnedDirectory::persist_replace`].

#[cfg(all(not(unix), not(windows)))]
use crate::bounded_io::opened_path_matches;
#[cfg(unix)]
use crate::bounded_io::same_file;
use crate::bounded_io::symlink_metadata;
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(not(unix))]
use tempfile::NamedTempFile;

#[cfg(unix)]
use rustix::fs::{AtFlags, Mode, OFlags, openat, renameat, unlinkat};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    GetFileInformationByHandle,
};

/// A validated output directory retained by identity rather than by path.
///
/// On Unix the open directory handle remains usable even if the directory is
/// renamed.  Before each path-based operation the visible path is compared to
/// that handle; the final publication uses the handle itself so a concurrent
/// parent swap cannot redirect the commit into a replacement directory.
///
/// Windows keeps a directory handle opened with backup semantics for identity
/// checks, but uses a guarded path-based `persist` because this module does not
/// yet have a safe descriptor-relative rename implementation there.  Other
/// non-Unix targets use a private anchor file and the same guarded fallback.
pub(crate) struct PinnedDirectory {
    path: PathBuf,
    #[cfg(unix)]
    directory: File,
    #[cfg(windows)]
    directory: File,
    #[cfg(all(not(unix), not(windows)))]
    anchor: NamedTempFile,
}

/// A temporary file whose name and cleanup are anchored to the pinned
/// directory. Unix callers never use a path-based create or delete: the file
/// is opened and removed with `openat`/`unlinkat` against the retained
/// directory descriptor. Other platforms wrap `NamedTempFile` for the
/// guarded path-based fallback.
pub(crate) struct AnchoredTempFile {
    #[cfg(unix)]
    file: File,
    #[cfg(unix)]
    directory: File,
    #[cfg(unix)]
    name: OsString,
    #[cfg(unix)]
    committed: bool,
    #[cfg(not(unix))]
    inner: NamedTempFile,
}

impl AnchoredTempFile {
    pub(crate) fn as_file(&self) -> &File {
        #[cfg(unix)]
        {
            &self.file
        }
        #[cfg(not(unix))]
        {
            self.inner.as_file()
        }
    }

    pub(crate) fn as_file_mut(&mut self) -> &mut File {
        #[cfg(unix)]
        {
            &mut self.file
        }
        #[cfg(not(unix))]
        {
            self.inner.as_file_mut()
        }
    }
}

impl Write for AnchoredTempFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.as_file_mut().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.as_file_mut().flush()
    }
}

#[cfg(unix)]
impl Drop for AnchoredTempFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = unlinkat(&self.directory, Path::new(&self.name), AtFlags::empty());
        }
    }
}

impl PinnedDirectory {
    /// Validate and pin an existing, real directory.
    ///
    /// The component walk mirrors the CLI bounded I/O policy: every existing
    /// component must be non-symlink, and the final component must be a
    /// directory.
    pub(crate) fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        #[cfg(all(not(unix), not(windows)))]
        {
            inspect_directory(path)?;
            let anchor = tempfile::Builder::new()
                .prefix(".pcbex-anchor-")
                .tempfile_in(path)?;
            let pinned = Self {
                path: path.to_path_buf(),
                anchor,
            };
            pinned.ensure_pinned()?;
            return Ok(pinned);
        }

        #[cfg(unix)]
        {
            let metadata = inspect_directory(path)?;
            let directory = File::open(path)?;
            let opened = directory.metadata()?;
            let current = inspect_directory(path)?;
            if !opened.file_type().is_dir()
                || !same_file(&metadata, &opened)
                || !same_file(&metadata, &current)
            {
                return Err(changed_error(
                    path,
                    "directory changed while it was being opened",
                ));
            }
            Ok(Self {
                path: path.to_path_buf(),
                directory,
            })
        }

        #[cfg(windows)]
        {
            let initial_directory = open_windows_directory(path)?;
            inspect_directory(path)?;
            let directory = open_windows_directory(path)?;
            let opened = directory.metadata()?;
            let current = inspect_directory(path)?;
            let current_directory = open_windows_directory(path)?;
            if !opened.file_type().is_dir()
                || !same_windows_directory(&initial_directory, &directory)?
                || !same_windows_directory(&directory, &current_directory)?
                || !current.file_type().is_dir()
            {
                return Err(changed_error(
                    path,
                    "directory changed while it was being opened",
                ));
            }
            Ok(Self {
                path: path.to_path_buf(),
                directory,
            })
        }
    }

    /// Return the path that was used when the directory was pinned.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Create a named temporary file in the pinned directory.
    ///
    /// The visible path is checked both before and after creation.  If the
    /// parent was swapped before the create, the temporary file is dropped and
    /// no file is left in the replacement directory.
    #[cfg(unix)]
    pub(crate) fn create_temp(&self, prefix: &str) -> io::Result<AnchoredTempFile> {
        self.ensure_pinned()?;
        let name = random_temp_name(prefix)?;
        let directory = self.directory.try_clone()?;
        let owned = openat(
            &self.directory,
            Path::new(&name),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )?;
        let file: File = owned.into();
        let temporary = AnchoredTempFile {
            file,
            directory,
            name,
            committed: false,
        };
        if let Err(error) = self.ensure_pinned() {
            drop(temporary);
            return Err(error);
        }
        Ok(temporary)
    }

    /// Non-Unix guarded fallback.  The path and anchor/handle are checked
    /// before and after creation; publication remains path based on these
    /// targets, so a hostile parent swap during the final persist is detected
    /// after the fact rather than prevented at the syscall boundary.
    #[cfg(not(unix))]
    pub(crate) fn create_temp(&self, prefix: &str) -> io::Result<AnchoredTempFile> {
        self.ensure_pinned()?;
        let inner = tempfile::Builder::new()
            .prefix(prefix)
            .tempfile_in(&self.path)?;
        let temporary = AnchoredTempFile { inner };
        if let Err(error) = self.ensure_pinned() {
            drop(temporary);
            return Err(error);
        }
        Ok(temporary)
    }

    /// Atomically replace a regular destination with a temporary file created
    /// by this directory.
    ///
    /// `destination` may contain a path spelling equivalent to the pinned
    /// directory, but its parent must resolve to the same directory identity.
    /// Existing symlinks and non-regular destinations are rejected.  The
    /// temporary file is synced before the rename and the directory is synced
    /// after it.
    #[cfg(unix)]
    pub(crate) fn persist_replace(
        &self,
        mut temporary: AnchoredTempFile,
        destination: impl AsRef<Path>,
    ) -> io::Result<()> {
        let destination = destination.as_ref();
        let destination_name = self.destination_name(destination)?;
        if temporary.name == destination_name {
            return Err(invalid_path("temporary and destination names must differ"));
        }
        if !temporary.as_file().metadata()?.file_type().is_file() {
            return Err(invalid_path(
                "temporary publication source must be a regular file",
            ));
        }
        reject_existing_non_regular(destination)?;
        let pinned_metadata = self.directory.metadata()?;
        let temporary_directory_metadata = temporary.directory.metadata()?;
        if !same_file(&pinned_metadata, &temporary_directory_metadata) {
            return Err(invalid_path(
                "temporary file is not anchored to the pinned directory",
            ));
        }

        // This check closes the preflight window. If a swap happens after it,
        // renameat still resolves both names relative to the pinned directory.
        self.ensure_pinned()?;
        temporary.as_file().sync_all()?;
        self.ensure_pinned()?;

        renameat(
            &self.directory,
            Path::new(&temporary.name),
            &self.directory,
            Path::new(&destination_name),
        )?;

        temporary.committed = true;
        drop(temporary);

        self.directory.sync_all()?;
        Ok(())
    }

    /// Windows and other non-Unix guarded fallback.  The destination and
    /// parent are checked immediately before and after `persist`; unlike the
    /// Unix implementation, a swap in the narrow syscall window can redirect
    /// the write, so callers must treat a post-persist guard failure as an
    /// invalid publication.
    #[cfg(not(unix))]
    pub(crate) fn persist_replace(
        &self,
        temporary: AnchoredTempFile,
        destination: impl AsRef<Path>,
    ) -> io::Result<()> {
        let destination = destination.as_ref();
        self.destination_name(destination)?;
        if !temporary.as_file().metadata()?.file_type().is_file() {
            return Err(invalid_path(
                "temporary publication source must be a regular file",
            ));
        }
        reject_existing_non_regular(destination)?;
        self.ensure_pinned()?;
        temporary.as_file().sync_all()?;
        self.ensure_pinned()?;
        temporary
            .inner
            .persist(destination)
            .map_err(|error| error.error)?;
        if let Err(error) = self.ensure_pinned() {
            return Err(error);
        }
        reject_existing_non_regular(destination)?;
        Ok(())
    }

    #[cfg(unix)]
    fn ensure_pinned(&self) -> io::Result<()> {
        let current = inspect_directory(&self.path)?;
        let opened = self.directory.metadata()?;
        if !opened.file_type().is_dir() || !same_file(&current, &opened) {
            return Err(changed_error(
                &self.path,
                "directory path no longer names the pinned directory",
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    fn ensure_pinned(&self) -> io::Result<()> {
        let current = inspect_directory(&self.path)?;
        if !current.file_type().is_dir() {
            return Err(changed_error(
                &self.path,
                "directory path no longer names a directory",
            ));
        }
        let current_directory = open_windows_directory(&self.path)?;
        if !same_windows_directory(&self.directory, &current_directory)? {
            return Err(changed_error(
                &self.path,
                "directory path no longer names the pinned directory",
            ));
        }
        Ok(())
    }

    #[cfg(all(not(unix), not(windows)))]
    fn ensure_pinned(&self) -> io::Result<()> {
        inspect_directory(&self.path)?;
        let anchor_metadata = symlink_metadata(self.anchor.path())?;
        if anchor_metadata.file_type().is_symlink() || !anchor_metadata.file_type().is_file() {
            return Err(changed_error(
                &self.path,
                "directory anchor is no longer a regular file",
            ));
        }
        if !opened_path_matches(self.anchor.as_file(), self.anchor.path())? {
            return Err(changed_error(
                &self.path,
                "directory anchor identity changed",
            ));
        }
        Ok(())
    }

    fn destination_name(&self, destination: &Path) -> io::Result<std::ffi::OsString> {
        let name = destination
            .file_name()
            .ok_or_else(|| invalid_path("destination is missing its filename"))?;
        if name.is_empty() || name == "." || name == ".." {
            return Err(invalid_path("destination filename is invalid"));
        }
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let parent_metadata = inspect_directory(parent)?;
        #[cfg(unix)]
        {
            let pinned_metadata = self.directory.metadata()?;
            if !same_file(&parent_metadata, &pinned_metadata) {
                return Err(changed_error(
                    destination,
                    "destination parent is not the pinned directory",
                ));
            }
        }
        #[cfg(windows)]
        {
            let _ = parent_metadata;
            let current_parent = open_windows_directory(parent)?;
            if !same_windows_directory(&self.directory, &current_parent)? {
                return Err(changed_error(
                    destination,
                    "destination parent is not the pinned directory",
                ));
            }
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            let canonical_parent = std::fs::canonicalize(parent)?;
            let canonical_pinned = std::fs::canonicalize(&self.path)?;
            if canonical_parent != canonical_pinned {
                return Err(changed_error(
                    destination,
                    "destination parent is not the pinned directory",
                ));
            }
        }
        Ok(name.to_os_string())
    }
}

fn inspect_directory(path: &Path) -> io::Result<Metadata> {
    if path.as_os_str().is_empty() {
        return Err(invalid_path("directory path must not be empty"));
    }
    let components = path.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(invalid_path("directory path must contain a component"));
    }

    let mut current = PathBuf::new();
    for component in components {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                current.push(component.as_os_str());
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir | Component::Normal(_) => current.push(component.as_os_str()),
        }
        let metadata = symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(symlink_error(path));
        }
    }

    let metadata = symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(symlink_error(path));
    }
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("directory path is not a real directory: {}", path.display()),
        ));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn random_temp_name(prefix: &str) -> io::Result<OsString> {
    if prefix.is_empty() || prefix.as_bytes().contains(&0) || prefix.contains('/') {
        return Err(invalid_path(
            "temporary prefix must be a non-empty single path component",
        ));
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|error| {
        io::Error::other(format!("generating a temporary filename suffix: {error}"))
    })?;
    let mut name = OsString::from(prefix);
    name.push(hex::encode(random));
    Ok(name)
}

fn reject_existing_non_regular(path: &Path) -> io::Result<()> {
    match symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            Err(invalid_path(
                "destination must be a regular non-symlink file",
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn open_windows_directory(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(windows)]
fn windows_directory_identity(file: &File) -> io::Result<(u32, u32, u32)> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: `handle` is borrowed from a live `File`; the API writes only to
    // the stack-owned information structure, whose layout is supplied by
    // windows-sys.
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    ))
}

#[cfg(windows)]
fn same_windows_directory(left: &File, right: &File) -> io::Result<bool> {
    Ok(windows_directory_identity(left)? == windows_directory_identity(right)?)
}

fn invalid_path(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn changed_error(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}: {detail}", path.display()),
    )
}

fn symlink_error(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("path contains a symlink: {}", path.display()),
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn rejects_parent_swap_without_redirecting_publication() -> io::Result<()> {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = PinnedDirectory::open(&output)?;
        let mut temporary = pinned.create_temp(".pcbex-anchor-test-")?;
        temporary.write_all(b"new contents")?;
        temporary.as_file().sync_all()?;

        let moved = workspace.path().join("moved-output");
        fs::rename(&output, &moved)?;
        fs::create_dir(&output)?;
        let destination = output.join("artifact.bin");

        let error = pinned
            .persist_replace(temporary, &destination)
            .expect_err("a swapped parent must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!destination.exists());
        assert!(!moved.join("artifact.bin").exists());
        let orphaned = fs::read_dir(&moved)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".pcbex-"))
            .collect::<Vec<_>>();
        assert!(
            orphaned.is_empty(),
            "orphaned temporary files: {orphaned:?}"
        );
        Ok(())
    }
}

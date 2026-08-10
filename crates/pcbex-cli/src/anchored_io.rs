//! Directory-anchored temporary-file publication.
//!
//! A path-only `rename` can be redirected when a parent directory is renamed
//! and replaced between its preflight checks and the commit.  This module
//! keeps an open handle to the validated directory and uses descriptor
//! relative operations on Unix.  Ordinary callers should create temporary
//! files through [`PinnedDirectory::create_temp`] and publish them with
//! [`PinnedDirectory::persist_replace`].  Durable local ledgers use
//! [`PinnedDirectory::persist_no_replace_with_guards`], whose `linkat`
//! compare-and-swap never overwrites an existing entry.

#[cfg(all(not(unix), not(windows)))]
use crate::bounded_io::opened_path_matches;
#[cfg(unix)]
use crate::bounded_io::same_file;
use crate::bounded_io::symlink_metadata;
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{self, Write};
#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
#[cfg(not(unix))]
use tempfile::NamedTempFile;

#[cfg(unix)]
use rustix::fs::{AtFlags, Mode, OFlags, fstat, linkat, openat, renameat, statat, unlinkat};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// The result of a descriptor-relative no-replace publication.
///
/// `CommittedButCompletionFailed` means that the final name was installed,
/// but one or more later validation, cleanup, or directory-synchronization
/// steps failed. Callers must treat the final marker as present in that case;
/// the implementation never removes it after the successful install.
#[derive(Debug)]
pub(crate) enum NoReplacePublicationOutcome {
    CommittedDurable,
    AlreadyExists,
    CommittedButCompletionFailed(io::Error),
}

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

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> std::os::raw::c_uint;
}

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
type AfterNoreplaceInstallHook = Box<dyn FnOnce() -> io::Result<()>>;

#[cfg(test)]
thread_local! {
    // The hook makes the post-install failure test deterministic without
    // changing production behavior.  It is deliberately invoked only after
    // the final name has been installed with linkat.
    static AFTER_NOREPLACE_INSTALL_HOOK: RefCell<Option<AfterNoreplaceInstallHook>> =
        RefCell::new(None);
}

#[cfg(test)]
fn invoke_after_noreplace_install_hook() -> io::Result<()> {
    let hook = AFTER_NOREPLACE_INSTALL_HOOK.with(|slot| slot.borrow_mut().take());
    hook.map_or(Ok(()), |hook| hook())
}

#[cfg(test)]
fn set_after_noreplace_install_hook(hook: impl FnOnce() -> io::Result<()> + 'static) {
    AFTER_NOREPLACE_INSTALL_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot.replace(Box::new(hook)).is_none());
    });
}

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

    /// Recheck that the visible directory path still names the directory held
    /// by this instance.
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        self.ensure_pinned()
    }

    /// Require the pinned directory to be owned by the effective user and to
    /// have exactly mode `0700`.
    ///
    /// This stricter check is opt-in because existing callers use
    /// [`PinnedDirectory::open`] for ordinary output directories.  The check
    /// is performed on the retained descriptor and the visible path is
    /// revalidated before returning, so a caller can use it as the trust gate
    /// for a local durable ledger.
    #[cfg(unix)]
    pub(crate) fn require_secure_directory(&self) -> io::Result<()> {
        self.ensure_pinned()?;
        let initial = self.directory.metadata()?;
        if !initial.file_type().is_dir() {
            return Err(security_error("pinned path is not a directory"));
        }
        let effective_uid = {
            // SAFETY: `geteuid` has no preconditions and returns the calling
            // process's effective POSIX user ID.
            unsafe { geteuid() }
        };
        if initial.uid() != effective_uid {
            return Err(security_error(
                "pinned directory is not owned by the effective user",
            ));
        }
        if initial.permissions().mode() & 0o7777 != 0o700 {
            return Err(security_error(
                "pinned directory permissions must be exactly 0700",
            ));
        }

        self.ensure_pinned()?;
        let final_metadata = self.directory.metadata()?;
        if !same_file(&initial, &final_metadata)
            || final_metadata.uid() != effective_uid
            || final_metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(changed_error(
                &self.path,
                "pinned directory identity, owner, or mode changed while it was being checked",
            ));
        }
        self.ensure_pinned()
    }

    /// The secure-ledger trust gate is Unix-only.  Other platforms must not
    /// be treated as providing the Unix descriptor and durability contract.
    #[cfg(not(unix))]
    pub(crate) fn require_secure_directory(&self) -> io::Result<()> {
        Err(unsupported_error())
    }

    /// Read one bounded regular file from a single leaf of the pinned
    /// directory without resolving a symlink.
    ///
    /// Unix callers get descriptor-relative `openat`/`fstatat` checks and a
    /// stable two-pass read.  The method intentionally has no path-based
    /// fallback: callers that require this trust boundary must fail closed on
    /// non-Unix targets.
    pub(crate) fn read_regular_file_with_limit(
        &self,
        relative_leaf: impl AsRef<Path>,
        max_bytes: u64,
    ) -> io::Result<Vec<u8>> {
        #[cfg(unix)]
        {
            let leaf = relative_leaf.as_ref();
            let name = single_leaf_name(leaf)?;
            self.ensure_pinned()?;
            let mut file: File = openat(
                &self.directory,
                Path::new(name),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?
            .into();
            let opened = file.metadata()?;
            if !opened.file_type().is_file() {
                return Err(invalid_path(
                    "pinned file must be a regular non-symlink file",
                ));
            }
            let capacity = usize::try_from(opened.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pinned file size cannot be represented on this platform",
                )
            })?;
            if opened.len() > max_bytes {
                return Err(oversized_error(max_bytes));
            }
            let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "bounded file size overflows")
            })?;
            let opened_stat = fstat(&file)?;
            let visible_stat = statat(&self.directory, Path::new(name), AtFlags::SYMLINK_NOFOLLOW)?;
            if !same_stat_identity(&opened_stat, &visible_stat) {
                return Err(changed_error(
                    leaf,
                    "pinned file identity changed while it was being opened",
                ));
            }

            let mut bytes = Vec::with_capacity(capacity);
            Read::by_ref(&mut file)
                .take(read_limit)
                .read_to_end(&mut bytes)?;
            let bytes_len = u64::try_from(bytes.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pinned read byte count overflow",
                )
            })?;
            if bytes_len > max_bytes {
                return Err(oversized_error(max_bytes));
            }

            file.seek(SeekFrom::Start(0))?;
            let mut compare_buffer = [0_u8; 16 * 1024];
            let mut compared = 0_usize;
            loop {
                let read = file.read(&mut compare_buffer)?;
                if read == 0 {
                    break;
                }
                let end = compared.checked_add(read).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "pinned read byte count overflow",
                    )
                })?;
                if end > bytes.len() || compare_buffer[..read] != bytes[compared..end] {
                    return Err(changed_error(
                        leaf,
                        "pinned file changed while it was being read",
                    ));
                }
                compared = end;
            }
            let after = file.metadata()?;
            let after_stat = fstat(&file)?;
            let final_visible_stat =
                statat(&self.directory, Path::new(name), AtFlags::SYMLINK_NOFOLLOW)?;
            if !after.file_type().is_file()
                || !same_file(&opened, &after)
                || opened.len() != after.len()
                || bytes_len != after.len()
                || compared != bytes.len()
                || !same_stat_identity(&opened_stat, &after_stat)
                || !same_stat_identity(&after_stat, &final_visible_stat)
            {
                return Err(changed_error(
                    leaf,
                    "pinned file identity or contents changed while it was being read",
                ));
            }
            self.ensure_pinned()?;
            Ok(bytes)
        }

        #[cfg(not(unix))]
        {
            let _ = (relative_leaf, max_bytes);
            Err(unsupported_error())
        }
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

    /// Publish a staged file without replacement while bracketing the
    /// no-replace installation with caller-supplied validation guards.
    ///
    /// The before-install guard runs after the temporary file is fully synced
    /// and immediately before `linkat`. The after-install guard runs
    /// immediately after a successful `linkat`. A before-install failure
    /// leaves no final entry. An after-install failure is reported as a
    /// committed-but-uncertain outcome, and the final entry is never removed.
    #[cfg(unix)]
    pub(crate) fn persist_no_replace_with_guards<Before, After>(
        &self,
        mut temporary: AnchoredTempFile,
        destination: impl AsRef<Path>,
        before_install: Before,
        after_install: After,
    ) -> io::Result<NoReplacePublicationOutcome>
    where
        Before: FnOnce() -> io::Result<()>,
        After: FnOnce() -> io::Result<()>,
    {
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
        let pinned_metadata = self.directory.metadata()?;
        let temporary_directory_metadata = temporary.directory.metadata()?;
        if !same_file(&pinned_metadata, &temporary_directory_metadata) {
            return Err(invalid_path(
                "temporary file is not anchored to the pinned directory",
            ));
        }

        self.ensure_pinned()?;
        temporary.flush()?;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        temporary.as_file().sync_all()?;
        self.ensure_pinned()?;
        before_install()?;

        match linkat(
            &self.directory,
            Path::new(&temporary.name),
            &self.directory,
            Path::new(&destination_name),
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Ok(NoReplacePublicationOutcome::AlreadyExists);
            }
            Err(error) => {
                // Most Unix filesystems report EEXIST for every existing
                // entry, including symlinks and directories.  The stat check
                // also handles filesystems that report a type-specific error
                // (for example EPERM for a directory hard-link attempt).
                match statat(
                    &self.directory,
                    Path::new(&destination_name),
                    AtFlags::SYMLINK_NOFOLLOW,
                ) {
                    Ok(_) => return Ok(NoReplacePublicationOutcome::AlreadyExists),
                    Err(check) if check.kind() == io::ErrorKind::NotFound => {}
                    Err(check) => return Err(check.into()),
                }
                return Err(error.into());
            }
        }

        // The final marker is installed at this point. Every subsequent
        // action is best effort and, importantly, no branch removes the
        // final name. Collect every post-install error for the caller while
        // still attempting all cleanup and synchronization steps.
        let mut post_install_errors: Vec<(&str, io::Error)> = Vec::new();
        if let Err(error) = after_install() {
            post_install_errors.push(("post-install validation", error));
        }
        #[cfg(test)]
        if let Err(error) = invoke_after_noreplace_install_hook() {
            post_install_errors.push(("after final-name installation", error));
        }
        if let Err(error) = self.ensure_pinned() {
            post_install_errors.push(("pinned directory revalidation", error));
        }
        if let Err(error) = unlinkat(
            &self.directory,
            Path::new(&temporary.name),
            AtFlags::empty(),
        ) {
            post_install_errors.push(("temporary unlink", error.into()));
        } else {
            temporary.committed = true;
        }
        if let Err(error) = self.directory.sync_all() {
            post_install_errors.push(("pinned directory synchronization", error));
        }
        if post_install_errors.is_empty() {
            Ok(NoReplacePublicationOutcome::CommittedDurable)
        } else {
            Ok(committed_but_completion_failed(post_install_errors))
        }
    }

    /// No-replace durable publication is intentionally unavailable on
    /// non-Unix targets; returning `Unsupported` as an I/O error prevents any
    /// caller from treating a path-based fallback as durable.
    #[cfg(not(unix))]
    #[allow(dead_code)] // exercised by the non-Unix fail-closed contract test
    pub(crate) fn persist_no_replace_with_guards<Before, After>(
        &self,
        temporary: AnchoredTempFile,
        destination: impl AsRef<Path>,
        before_install: Before,
        after_install: After,
    ) -> io::Result<NoReplacePublicationOutcome>
    where
        Before: FnOnce() -> io::Result<()>,
        After: FnOnce() -> io::Result<()>,
    {
        let _ = (temporary, destination, before_install, after_install);
        Err(unsupported_error())
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

#[cfg(unix)]
fn single_leaf_name(path: &Path) -> io::Result<&std::ffi::OsStr> {
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) if !name.is_empty() => Ok(name),
        _ => Err(invalid_path(
            "pinned file name must be one non-empty relative path component",
        )),
    }
}

#[cfg(unix)]
fn same_stat_identity(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

#[cfg(unix)]
fn oversized_error(max_bytes: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("pinned file exceeds the {max_bytes}-byte limit"),
    )
}

#[cfg(unix)]
fn security_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(not(unix))]
fn unsupported_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative durable publication is unsupported on this target",
    )
}

#[cfg(unix)]
fn committed_but_completion_failed(
    errors: Vec<(&'static str, io::Error)>,
) -> NoReplacePublicationOutcome {
    let kind = errors
        .first()
        .map(|(_, error)| error.kind())
        .unwrap_or(io::ErrorKind::Other);
    let details = errors
        .into_iter()
        .map(|(phase, error)| format!("{phase}: {error}"))
        .collect::<Vec<_>>()
        .join("; ");
    NoReplacePublicationOutcome::CommittedButCompletionFailed(io::Error::new(
        kind,
        format!("post-install completion failed: {details}"),
    ))
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
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn staged(directory: &PinnedDirectory, bytes: &[u8]) -> io::Result<AnchoredTempFile> {
        let mut temporary = directory.create_temp(".pcbex-noreplace-test-")?;
        temporary.write_all(bytes)?;
        Ok(temporary)
    }

    fn persist_no_replace(
        directory: &PinnedDirectory,
        temporary: AnchoredTempFile,
        destination: impl AsRef<Path>,
    ) -> io::Result<NoReplacePublicationOutcome> {
        directory.persist_no_replace_with_guards(temporary, destination, || Ok(()), || Ok(()))
    }

    #[test]
    fn no_replace_has_exactly_one_concurrent_winner() -> io::Result<()> {
        const THREADS: usize = 8;
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = Arc::new(PinnedDirectory::open(&output)?);
        let destination = output.join("ledger.marker");
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut workers = Vec::with_capacity(THREADS);
        for index in 0..THREADS {
            let pinned = Arc::clone(&pinned);
            let barrier = Arc::clone(&barrier);
            let destination = destination.clone();
            workers.push(thread::spawn(
                move || -> io::Result<NoReplacePublicationOutcome> {
                    let bytes = format!("winner-{index}").into_bytes();
                    let temporary = staged(&pinned, &bytes)?;
                    barrier.wait();
                    persist_no_replace(&pinned, temporary, destination)
                },
            ));
        }

        let mut durable = 0;
        let mut already_exists = 0;
        for worker in workers {
            match worker
                .join()
                .map_err(|_| io::Error::other("publication worker panicked"))??
            {
                NoReplacePublicationOutcome::CommittedDurable => durable += 1,
                NoReplacePublicationOutcome::AlreadyExists => already_exists += 1,
                NoReplacePublicationOutcome::CommittedButCompletionFailed(error) => {
                    return Err(io::Error::other(format!(
                        "unexpected post-install failure for winner: {error}"
                    )));
                }
            }
        }
        assert_eq!(durable, 1);
        assert_eq!(already_exists, THREADS - 1);
        let metadata = fs::symlink_metadata(&destination)?;
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let contents = fs::read(&destination)?;
        assert!(contents.starts_with(b"winner-"));
        Ok(())
    }

    #[test]
    fn no_replace_before_install_guard_failure_leaves_no_marker() -> io::Result<()> {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = PinnedDirectory::open(&output)?;
        let destination = output.join("marker");

        let error = pinned
            .persist_no_replace_with_guards(
                staged(&pinned, b"not committed")?,
                &destination,
                || Err(io::Error::other("authorization expired before install")),
                || Ok(()),
            )
            .expect_err("before-install validation must abort publication");
        assert!(error.to_string().contains("expired before install"));
        assert!(!destination.exists());
        assert!(!fs::read_dir(&output)?.any(|entry| {
            entry
                .ok()
                .map(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".pcbex-noreplace")
                })
                .unwrap_or(false)
        }));
        Ok(())
    }

    #[test]
    fn no_replace_after_install_guard_failure_keeps_marker() -> io::Result<()> {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = PinnedDirectory::open(&output)?;
        let destination = output.join("marker");
        set_after_noreplace_install_hook(|| {
            Err(io::Error::other("injected secondary post-install failure"))
        });

        let outcome = pinned.persist_no_replace_with_guards(
            staged(&pinned, b"committed")?,
            &destination,
            || Ok(()),
            || Err(io::Error::other("authorization expired after install")),
        )?;
        match outcome {
            NoReplacePublicationOutcome::CommittedButCompletionFailed(error) => {
                assert!(error.to_string().contains("post-install validation"));
                assert!(error.to_string().contains("expired after install"));
                assert!(error.to_string().contains("after final-name installation"));
                assert!(error.to_string().contains("secondary post-install failure"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(fs::read(&destination)?, b"committed");
        assert!(!fs::read_dir(&output)?.any(|entry| {
            entry
                .ok()
                .map(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".pcbex-noreplace")
                })
                .unwrap_or(false)
        }));
        Ok(())
    }

    #[test]
    fn existing_regular_symlink_and_directory_are_unchanged() -> io::Result<()> {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = PinnedDirectory::open(&output)?;

        let regular = output.join("regular");
        fs::write(&regular, b"old regular")?;
        let regular_before = fs::symlink_metadata(&regular)?;
        assert!(matches!(
            persist_no_replace(&pinned, staged(&pinned, b"new regular")?, &regular)?,
            NoReplacePublicationOutcome::AlreadyExists
        ));
        let regular_after = fs::symlink_metadata(&regular)?;
        assert_eq!(fs::read(&regular)?, b"old regular");
        assert_eq!(regular_before.dev(), regular_after.dev());
        assert_eq!(regular_before.ino(), regular_after.ino());

        let symlink_target = output.join("symlink-target");
        fs::write(&symlink_target, b"target")?;
        let symlink = output.join("symlink");
        std::os::unix::fs::symlink("symlink-target", &symlink)?;
        let symlink_before = fs::read_link(&symlink)?;
        assert!(matches!(
            persist_no_replace(&pinned, staged(&pinned, b"new symlink")?, &symlink)?,
            NoReplacePublicationOutcome::AlreadyExists
        ));
        assert_eq!(fs::read_link(&symlink)?, symlink_before);

        let directory = output.join("directory");
        fs::create_dir(&directory)?;
        fs::write(directory.join("keep"), b"keep")?;
        assert!(matches!(
            persist_no_replace(&pinned, staged(&pinned, b"new directory")?, &directory)?,
            NoReplacePublicationOutcome::AlreadyExists
        ));
        assert!(directory.is_dir());
        assert_eq!(fs::read(directory.join("keep"))?, b"keep");
        Ok(())
    }

    #[test]
    fn no_replace_forces_mode_0600() -> io::Result<()> {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = PinnedDirectory::open(&output)?;
        let destination = output.join("mode");
        let outcome = persist_no_replace(&pinned, staged(&pinned, b"private")?, &destination)?;
        assert!(matches!(
            outcome,
            NoReplacePublicationOutcome::CommittedDurable
        ));
        let mode = fs::symlink_metadata(destination)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        Ok(())
    }

    #[test]
    fn post_install_failure_keeps_final_marker() -> io::Result<()> {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = PinnedDirectory::open(&output)?;
        let destination = output.join("marker");
        set_after_noreplace_install_hook(|| Err(io::Error::other("injected post-install failure")));
        let outcome = persist_no_replace(&pinned, staged(&pinned, b"committed")?, &destination)?;
        match outcome {
            NoReplacePublicationOutcome::CommittedButCompletionFailed(error) => {
                assert!(error.to_string().contains("after final-name installation"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(fs::read(&destination)?, b"committed");
        assert!(!fs::read_dir(&output)?.any(|entry| {
            entry
                .ok()
                .map(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".pcbex-noreplace")
                })
                .unwrap_or(false)
        }));
        Ok(())
    }

    #[test]
    fn post_install_parent_swap_is_unknown_and_keeps_marker_in_pinned_directory() -> io::Result<()>
    {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = PinnedDirectory::open(&output)?;
        let moved = workspace.path().join("moved-output");
        let destination = output.join("marker");
        let replacement = output.clone();
        let moved_for_hook = moved.clone();
        set_after_noreplace_install_hook(move || {
            fs::rename(&replacement, &moved_for_hook)?;
            fs::create_dir(&replacement)?;
            Ok(())
        });

        let outcome = persist_no_replace(&pinned, staged(&pinned, b"pinned")?, &destination)?;
        match outcome {
            NoReplacePublicationOutcome::CommittedButCompletionFailed(error) => {
                assert!(error.to_string().contains("pinned directory revalidation"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(fs::read(moved.join("marker"))?, b"pinned");
        assert!(!destination.exists());
        assert!(!fs::read_dir(&moved)?.any(|entry| {
            entry
                .ok()
                .map(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".pcbex-noreplace")
                })
                .unwrap_or(false)
        }));
        assert!(fs::read_dir(&output)?.next().is_none());
        Ok(())
    }

    #[test]
    fn descriptor_relative_bounded_read_rejects_symlinks() -> io::Result<()> {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = PinnedDirectory::open(&output)?;
        fs::write(output.join("manifest"), b"manifest bytes")?;
        assert_eq!(
            pinned.read_regular_file_with_limit("manifest", 4096)?,
            b"manifest bytes"
        );
        fs::write(output.join("target"), b"target")?;
        std::os::unix::fs::symlink("target", output.join("alias"))?;
        let error = pinned
            .read_regular_file_with_limit("alias", 4096)
            .expect_err("symlink leaf must be rejected");
        assert_ne!(error.kind(), io::ErrorKind::NotFound);
        Ok(())
    }

    #[test]
    fn secure_directory_gate_checks_owner_mode_and_identity() -> io::Result<()> {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
        let pinned = PinnedDirectory::open(&output)?;
        pinned.require_secure_directory()?;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            pinned
                .require_secure_directory()
                .expect_err("mode must be exact")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        Ok(())
    }

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

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn durable_ledger_contract_is_unsupported() -> io::Result<()> {
        let workspace = tempfile::tempdir()?;
        let output = workspace.path().join("output");
        fs::create_dir(&output)?;
        let pinned = PinnedDirectory::open(&output)?;
        let mut temporary = pinned.create_temp(".pcbex-noreplace-test-")?;
        temporary.write_all(b"marker")?;
        let error = pinned
            .persist_no_replace_with_guards(temporary, output.join("marker"), || Ok(()), || Ok(()))
            .expect_err("non-Unix publication must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            pinned
                .read_regular_file_with_limit("missing", 4096)
                .expect_err("non-Unix descriptor-relative read must fail closed")
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            pinned
                .require_secure_directory()
                .expect_err("non-Unix secure ledger gate must fail closed")
                .kind(),
            io::ErrorKind::Unsupported
        );
        Ok(())
    }
}

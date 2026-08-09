//! Bounded, deterministic traversal of manufacturing workspaces.
//!
//! The factory-repair wrapper runs in a private directory, but the wrapper is
//! still external code and may leave behind arbitrary filesystem entries.  A
//! scanner is therefore run before a candidate can become known-good.  It
//! deliberately uses `symlink_metadata` and an iterative traversal: links are
//! never followed, and each directory entry is charged to the quota before a
//! directory is queued for later inspection.

use anyhow::{Context, Result, bail};
use std::{
    collections::{BTreeSet, VecDeque},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

/// Maximum bytes accepted for one manufacturing package or one package file.
pub(crate) const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum number of entries accepted in a manufacturing ZIP archive.
pub(crate) const MAX_ARCHIVE_ENTRIES: usize = 4096;

/// Maximum sum of expanded manufacturing ZIP entry sizes.
pub(crate) const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum bytes accepted for a manufacturing manifest or Gerber job.
pub(crate) const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Quotas applied while inspecting a private manufacturing workspace.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManufacturingLimits {
    pub(crate) max_entries: usize,
    pub(crate) max_depth: usize,
    pub(crate) max_file_bytes: u64,
    pub(crate) max_total_bytes: u64,
    pub(crate) max_archive_bytes: u64,
    pub(crate) max_archive_uncompressed_bytes: u64,
    pub(crate) max_manifest_bytes: u64,
    pub(crate) max_name_bytes: usize,
}

impl ManufacturingLimits {
    /// The production manufacturing quota contract.
    ///
    /// The aggregate workspace quota is one GiB.  It leaves room for three
    /// staged 128 MiB project inputs, the 512 MiB expanded-artifact budget,
    /// and one 128 MiB package while keeping the workspace finite.
    pub(crate) const fn production() -> Self {
        Self {
            max_entries: MAX_ARCHIVE_ENTRIES,
            max_depth: 16,
            max_file_bytes: MAX_PACKAGE_BYTES,
            max_total_bytes: 1024 * 1024 * 1024,
            max_archive_bytes: MAX_PACKAGE_BYTES,
            max_archive_uncompressed_bytes: MAX_ARCHIVE_UNCOMPRESSED_BYTES,
            max_manifest_bytes: MAX_MANIFEST_BYTES,
            max_name_bytes: 255,
        }
    }
}

/// Measured usage of one scanned manufacturing workspace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WorkspaceUsage {
    pub(crate) entries: usize,
    pub(crate) files: usize,
    pub(crate) bytes: u64,
}

/// Scan a manufacturing workspace without following links or allocating from
/// an unbounded directory walk.
///
/// `entries` counts every descendant directory entry (regular files,
/// directories, links, and other non-regular entries) before that entry is
/// classified or a directory is queued.  `files` and `bytes` count only
/// regular files.  A ZIP-suffixed file is also subject to the archive-byte
/// quota, in addition to the ordinary per-file quota.
pub(crate) fn scan_manufacturing_workspace(
    root: &Path,
    limits: ManufacturingLimits,
    label: &str,
) -> Result<WorkspaceUsage> {
    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("{label}: reading workspace root {}", root.display()))?;
    let root_type = root_metadata.file_type();
    if root_type.is_symlink() {
        bail!(
            "{label}: workspace root must be a real directory, not a symlink: {}",
            root.display()
        );
    }
    if !root_type.is_dir() {
        bail!(
            "{label}: workspace root must be a real directory: {}",
            root.display()
        );
    }

    let mut usage = WorkspaceUsage::default();
    let mut pending = VecDeque::<(PathBuf, usize)>::from([(root.to_path_buf(), 0)]);
    while let Some((directory, depth)) = pending.pop_front() {
        let directory_metadata = fs::symlink_metadata(&directory).with_context(|| {
            format!(
                "{label}: reading workspace directory metadata {}",
                directory.display()
            )
        })?;
        let directory_type = directory_metadata.file_type();
        if directory_type.is_symlink() || !directory_type.is_dir() {
            bail!(
                "{label}: workspace directory must remain a real directory: {}",
                directory.display()
            );
        }
        let remaining_entries = limits.max_entries.saturating_sub(usage.entries);
        let mut children = Vec::with_capacity(remaining_entries.min(64));
        let reader = fs::read_dir(&directory).with_context(|| {
            format!(
                "{label}: listing workspace directory {}",
                directory.display()
            )
        })?;
        for next in reader {
            let entry = next.with_context(|| {
                format!(
                    "{label}: reading workspace directory entries {}",
                    directory.display()
                )
            })?;
            // Keep the temporary directory-entry buffer bounded by the
            // remaining quota.  One extra entry is enough to fail closed;
            // there is no reason to retain an unbounded directory listing.
            if children.len() >= remaining_entries {
                bail!(
                    "{label}: workspace entry count exceeds limit {} at {}",
                    limits.max_entries,
                    entry.path().display()
                );
            }
            children.push(entry);
        }
        // `OsString` ordering is a stable byte/code-unit ordering on each
        // supported platform and, unlike locale ordering, is deterministic.
        children.sort_by_key(|left| left.file_name());

        let mut portable_names = BTreeSet::new();
        for entry in children {
            let entry_path = entry.path();
            let entry_name = entry.file_name();

            // Charge the entry before classifying or queueing it.  This makes
            // links and non-regular entries unable to evade the count quota.
            usage.entries = usage.entries.checked_add(1).ok_or_else(|| {
                anyhow::anyhow!(
                    "{label}: workspace entry count overflow at {}",
                    entry_path.display()
                )
            })?;
            if usage.entries > limits.max_entries {
                bail!(
                    "{label}: workspace entry count exceeds limit {} at {}",
                    limits.max_entries,
                    entry_path.display()
                );
            }

            let child_depth = depth.checked_add(1).ok_or_else(|| {
                anyhow::anyhow!(
                    "{label}: workspace traversal depth overflow at {}",
                    entry_path.display()
                )
            })?;
            if child_depth > limits.max_depth {
                bail!(
                    "{label}: workspace entry depth {} exceeds limit {} at {}",
                    child_depth,
                    limits.max_depth,
                    entry_path.display()
                );
            }

            let entry_name =
                validate_entry_name(&entry_name, limits.max_name_bytes, &entry_path)
                    .with_context(|| format!("{label}: validating workspace entry name"))?;
            if !portable_names.insert(portable_manufacturing_name_key(&entry_name)) {
                bail!(
                    "{label}: workspace directory contains a portable name collision at {}",
                    entry_path.display()
                );
            }
            let metadata = fs::symlink_metadata(&entry_path).with_context(|| {
                format!(
                    "{label}: reading workspace entry metadata {}",
                    entry_path.display()
                )
            })?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                bail!(
                    "{label}: workspace entry must not be a symlink: {}",
                    entry_path.display()
                );
            }
            if file_type.is_dir() {
                pending.push_back((entry_path, child_depth));
                continue;
            }
            if !file_type.is_file() {
                bail!(
                    "{label}: workspace entry must be a regular file or directory: {}",
                    entry_path.display()
                );
            }

            let file_bytes = metadata.len();
            if file_bytes > limits.max_file_bytes {
                bail!(
                    "{label}: workspace file {} exceeds the {}-byte file limit",
                    entry_path.display(),
                    limits.max_file_bytes
                );
            }
            if is_archive_name(&entry_name) && file_bytes > limits.max_archive_bytes {
                bail!(
                    "{label}: workspace archive {} exceeds the {}-byte archive limit",
                    entry_path.display(),
                    limits.max_archive_bytes
                );
            }
            if is_manifest_bounded_name(&entry_name) && file_bytes > limits.max_manifest_bytes {
                bail!(
                    "{label}: workspace manifest-like file {} exceeds the {}-byte limit",
                    entry_path.display(),
                    limits.max_manifest_bytes
                );
            }

            usage.files = usage.files.checked_add(1).ok_or_else(|| {
                anyhow::anyhow!(
                    "{label}: workspace file count overflow at {}",
                    entry_path.display()
                )
            })?;
            usage.bytes = usage.bytes.checked_add(file_bytes).ok_or_else(|| {
                anyhow::anyhow!(
                    "{label}: workspace byte count overflow at {}",
                    entry_path.display()
                )
            })?;
            if usage.bytes > limits.max_total_bytes {
                bail!(
                    "{label}: workspace files exceed the {}-byte aggregate limit at {}",
                    limits.max_total_bytes,
                    entry_path.display()
                );
            }
        }
    }

    Ok(usage)
}

fn validate_entry_name(name: &OsStr, max_name_bytes: usize, path: &Path) -> Result<String> {
    let name = name.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "workspace entry name is not valid UTF-8: {}",
            path.display()
        )
    })?;
    validate_manufacturing_basename(name, max_name_bytes, "workspace entry")
        .with_context(|| format!("invalid path {}", path.display()))?;
    Ok(name.to_owned())
}

/// Validate one UTF-8 basename for portable manufacture/archive use.
pub(crate) fn validate_manufacturing_basename(
    name: &str,
    max_name_bytes: usize,
    label: &str,
) -> Result<()> {
    if name.is_empty() || matches!(name, "." | "..") {
        bail!("{label} name must not be empty, . or ..");
    }
    if name.len() > max_name_bytes {
        bail!("{label} name exceeds the {max_name_bytes}-byte limit: {name:?}");
    }
    if name.chars().any(char::is_control) {
        bail!("{label} name contains a control character: {name:?}");
    }
    if name.chars().any(|character| {
        matches!(
            character,
            ':' | '/' | '\\' | '*' | '?' | '<' | '>' | '"' | '|'
        )
    }) {
        bail!("{label} name contains a non-portable character: {name:?}");
    }
    if name.ends_with([' ', '.']) {
        bail!("{label} name must not end in a space or dot: {name:?}");
    }
    let device_stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    let numbered_device = device_stem.len() == 4
        && (device_stem.starts_with("COM") || device_stem.starts_with("LPT"))
        && matches!(device_stem.as_bytes()[3], b'1'..=b'9');
    if matches!(
        device_stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered_device
    {
        bail!("{label} uses a reserved Windows device name: {name:?}");
    }
    Ok(())
}

/// Collision key for the case-insensitive filesystems used by supported hosts.
pub(crate) fn portable_manufacturing_name_key(name: &str) -> String {
    name.to_lowercase()
}

fn is_archive_name(name: &str) -> bool {
    name.as_bytes()
        .get(name.len().saturating_sub(4)..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(b".zip"))
}

fn is_manifest_bounded_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("manifest.json") || name.to_ascii_lowercase().ends_with("-job.gbrjob")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn test_limits() -> ManufacturingLimits {
        ManufacturingLimits {
            max_entries: 16,
            max_depth: 4,
            max_file_bytes: 16,
            max_total_bytes: 64,
            max_archive_bytes: 16,
            max_archive_uncompressed_bytes: 32,
            max_manifest_bytes: 8,
            max_name_bytes: 32,
        }
    }

    #[test]
    fn reports_exact_entries_files_and_bytes() {
        let temporary = tempdir().unwrap();
        fs::create_dir(temporary.path().join("nested")).unwrap();
        fs::write(temporary.path().join("a.bin"), b"123").unwrap();
        fs::write(temporary.path().join("nested").join("b.bin"), b"45").unwrap();

        let mut limits = test_limits();
        limits.max_entries = 3;
        limits.max_total_bytes = 5;
        limits.max_file_bytes = 3;
        limits.max_depth = 2;
        let usage = scan_manufacturing_workspace(temporary.path(), limits, "test").unwrap();
        assert_eq!(
            usage,
            WorkspaceUsage {
                entries: 3,
                files: 2,
                bytes: 5,
            }
        );
    }

    #[test]
    fn rejects_one_entry_over_the_limit() {
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("a"), b"a").unwrap();
        fs::write(temporary.path().join("b"), b"b").unwrap();
        let mut limits = test_limits();
        limits.max_entries = 1;
        let error = scan_manufacturing_workspace(temporary.path(), limits, "test").unwrap_err();
        assert!(error.to_string().contains("entry count"), "{error:#}");
    }

    #[test]
    fn rejects_one_file_over_the_per_file_limit() {
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("candidate"), b"123").unwrap();
        let mut limits = test_limits();
        limits.max_file_bytes = 2;
        let error = scan_manufacturing_workspace(temporary.path(), limits, "test").unwrap_err();
        assert!(error.to_string().contains("file limit"), "{error:#}");
    }

    #[test]
    fn rejects_one_byte_over_the_aggregate_limit() {
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("a"), b"123").unwrap();
        let mut limits = test_limits();
        limits.max_total_bytes = 2;
        let error = scan_manufacturing_workspace(temporary.path(), limits, "test").unwrap_err();
        assert!(error.to_string().contains("aggregate limit"), "{error:#}");
    }

    #[test]
    fn rejects_one_level_over_the_depth_limit() {
        let temporary = tempdir().unwrap();
        let level = temporary.path().join("level");
        fs::create_dir(&level).unwrap();
        fs::write(level.join("candidate"), b"1").unwrap();
        let mut limits = test_limits();
        limits.max_depth = 1;
        let error = scan_manufacturing_workspace(temporary.path(), limits, "test").unwrap_err();
        assert!(error.to_string().contains("depth"), "{error:#}");
    }

    #[test]
    fn rejects_names_over_the_byte_limit() {
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("abcdef"), b"1").unwrap();
        let mut limits = test_limits();
        limits.max_name_bytes = 5;
        let error = scan_manufacturing_workspace(temporary.path(), limits, "test").unwrap_err();
        assert!(error.to_string().contains("name"), "{error:#}");
    }

    #[test]
    fn rejects_archive_over_its_archive_limit() {
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("manufacturing.zip"), b"123").unwrap();
        let mut limits = test_limits();
        limits.max_archive_bytes = 2;
        let error = scan_manufacturing_workspace(temporary.path(), limits, "test").unwrap_err();
        assert!(error.to_string().contains("archive limit"), "{error:#}");
    }

    #[test]
    fn rejects_manifest_like_files_over_their_limit() {
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("manifest.json"), b"123456789").unwrap();
        let error =
            scan_manufacturing_workspace(temporary.path(), test_limits(), "test").unwrap_err();
        assert!(error.to_string().contains("manifest-like"), "{error:#}");
    }

    #[test]
    fn rejects_reserved_and_trailing_windows_names() {
        for name in [
            "CON.txt",
            "CONIN$",
            "conout$.log",
            "nul",
            "LPT9.gbr",
            "trailing.",
            "trailing ",
            "bad?.gbr",
            "bad*.gbr",
            "bad<name.gbr",
            "bad>name.gbr",
            "bad\"name.gbr",
            "bad|name.gbr",
        ] {
            let error = validate_manufacturing_basename(name, 32, "test").unwrap_err();
            assert!(error.to_string().contains("name"), "{name}: {error:#}");
        }
        validate_manufacturing_basename("controller.gbr", 32, "test").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_case_insensitive_collisions_within_one_directory() {
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("Layer.gbr"), b"1").unwrap();
        fs::write(temporary.path().join("layer.gbr"), b"2").unwrap();
        let error =
            scan_manufacturing_workspace(temporary.path(), test_limits(), "test").unwrap_err();
        assert!(error.to_string().contains("collision"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("target"), b"target").unwrap();
        symlink(
            temporary.path().join("target"),
            temporary.path().join("link"),
        )
        .unwrap();
        let error =
            scan_manufacturing_workspace(temporary.path(), test_limits(), "test").unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_nonregular_entries() {
        use std::os::unix::net::UnixListener;

        let temporary = tempdir().unwrap();
        let _listener = UnixListener::bind(temporary.path().join("socket")).unwrap();
        let error =
            scan_manufacturing_workspace(temporary.path(), test_limits(), "test").unwrap_err();
        assert!(error.to_string().contains("regular"), "{error:#}");
    }

    #[test]
    fn tiny_limits_fail_closed_before_counter_overflow() {
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("candidate"), b"1").unwrap();
        let mut limits = test_limits();
        limits.max_entries = 0;
        limits.max_total_bytes = 0;
        limits.max_file_bytes = 0;
        let error = scan_manufacturing_workspace(temporary.path(), limits, "test").unwrap_err();
        assert!(error.to_string().contains("limit"), "{error:#}");
    }
}

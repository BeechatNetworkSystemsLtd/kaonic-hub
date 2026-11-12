//! Hardened file handling: private modes, no symlinks, owner checks, durable writes.
//! Every file this crate reads or writes goes through here.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::{Error, Result};

/// `<path><suffix>` in the same directory.
pub(crate) fn sibling(path: &Path, suffix: &str) -> Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_owned();
    name.push(suffix);
    Ok(path.with_file_name(name))
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn insecure(path: &Path, reason: impl Into<String>) -> Error {
    Error::Insecure {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

/// Never follow a symlink in the last path component.
fn nofollow() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.custom_flags(libc::O_NOFOLLOW);
    options
}

/// Write-only, mode 0600 when created, never through a symlink.
pub(crate) fn private_options() -> OpenOptions {
    let mut options = nofollow();
    options.write(true).mode(0o600);
    options
}

/// Read a private file (regular, ours, 0600) of at most `max_len` bytes; `None` if missing.
pub(crate) fn read_private(path: &Path, max_len: u64) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let file = match nofollow().read(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        // O_NOFOLLOW on a symlink fails with ELOOP; say why instead of "too many links".
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(insecure(path, "it is a symbolic link"));
        }
        Err(e) => return Err(e.into()),
    };
    let meta = file.metadata()?;
    check_private(path, &meta)?;
    if meta.len() > max_len {
        return Err(Error::Corrupt("file is larger than expected"));
    }
    // Sized up front and capped, so the buffer never reallocates and leaves stray copies.
    let mut bytes = Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    file.take(max_len).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn check_private(path: &Path, meta: &Metadata) -> Result<()> {
    if !meta.is_file() {
        return Err(insecure(path, "not a regular file"));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(insecure(
            path,
            format!("mode {mode:03o} lets group or others access it; use 0600"),
        ));
    }
    if meta.uid() != euid() {
        return Err(insecure(
            path,
            format!("owned by uid {}, not by us", meta.uid()),
        ));
    }
    Ok(())
}

/// The directory holding the store must not let anyone else replace or delete files.
pub(crate) fn check_dir(path: &Path) -> Result<()> {
    let dir = parent(path);
    let meta = fs::metadata(dir)?;
    if !meta.is_dir() {
        return Err(insecure(dir, "not a directory"));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(insecure(
            dir,
            format!("mode {mode:04o} lets group or others write it; use 0700 or 0755"),
        ));
    }
    if meta.uid() != euid() && meta.uid() != 0 {
        return Err(insecure(
            dir,
            format!("owned by uid {}, not by us or root", meta.uid()),
        ));
    }
    Ok(())
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Write and fsync a fresh `<path>.tmp`, removing any leftover so the 0600 mode applies.
fn stage(path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let tmp = sibling(path, ".tmp")?;
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut file = private_options().create_new(true).open(&tmp)?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(tmp)
}

/// Create `path`, failing if it exists. Staged then hard-linked, so never partial.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = stage(path, bytes)?;
    let linked = fs::hard_link(&tmp, path);
    // Only the link matters; a leftover temp file is removed by the next stage().
    let _ = fs::remove_file(&tmp);
    linked?;
    sync_dir(path)
}

/// Atomically replace each target in order, stopping at the first failure, then fsync the
/// shared directory once. Returns how many were replaced and the error that stopped it.
pub(crate) fn replace_in_order(targets: &[&Path], bytes: &[u8]) -> (usize, Result<()>) {
    let mut replaced = 0;
    let mut result = Ok(());
    for target in targets {
        if let Err(e) = stage(target, bytes).and_then(|tmp| Ok(fs::rename(tmp, target)?)) {
            result = Err(e);
            break;
        }
        replaced += 1;
    }
    if replaced > 0
        && let Err(e) = sync_dir(targets[0])
    {
        return (0, Err(e));
    }
    (replaced, result)
}

/// Make a create, rename or unlink in the directory of `path` durable.
fn sync_dir(path: &Path) -> Result<()> {
    File::open(parent(path))?.sync_all()?;
    Ok(())
}

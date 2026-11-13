//! Reads a tar archive into a directory, safely: regular files only, plain relative
//! paths, no duplicates, and a byte and entry budget checked before anything is written.
//!
//! Packages are made with any `tar` (`tar -cf plugin.kpkg -C dir .`). The POSIX ustar
//! layout is read; pax extended headers are read for a long path and otherwise ignored
//! (macOS tar adds them for file attributes). Directories are skipped; they are made as
//! files need them. macOS `._*` and `.DS_Store` files are skipped.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::{Error, names};

const BLOCK: usize = 512;

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Bytes of file content, all files together.
    pub bytes: u64,
    pub entries: usize,
}

/// Unpacks `archive` into the empty directory `into`. Returns the files written, as
/// relative paths with their sizes.
pub fn unpack(archive: &mut impl Read, into: &Path, budget: Budget) -> Result<Vec<(String, u64)>, Error> {
    let bad = |why: String| Error::invalid(format!("the package is not a valid tar: {why}"));
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0u64;
    let mut entries = 0usize;
    let mut long_path: Option<String> = None;
    let mut header = [0u8; BLOCK];
    loop {
        if !read_block(archive, &mut header).map_err(|error| bad(error.to_string()))? {
            return Err(bad("it ends without the end marker".into()));
        }
        if header.iter().all(|&byte| byte == 0) {
            break;
        }
        entries += 1;
        if entries > budget.entries {
            return Err(Error::invalid(format!("the package has more than {} entries", budget.entries)));
        }
        if !checksum_ok(&header) {
            return Err(bad("a header checksum is wrong".into()));
        }
        let size = octal(&header[124..136]).ok_or_else(|| bad("a size field is not a number".into()))?;
        let kind = header[156];
        match kind {
            // pax extended header: read `path`, ignore the rest.
            b'x' => {
                if size > 64 * 1024 {
                    return Err(bad("a pax header is too large".into()));
                }
                let data = read_data(archive, size).map_err(|error| bad(error.to_string()))?;
                long_path = pax_path(&data);
                continue;
            }
            // pax global header: nothing we use.
            b'g' => {
                if size > 64 * 1024 {
                    return Err(bad("a pax header is too large".into()));
                }
                read_data(archive, size).map_err(|error| bad(error.to_string()))?;
                continue;
            }
            b'5' => {
                long_path = None;
                skip(archive, size).map_err(|error| bad(error.to_string()))?;
                continue;
            }
            b'0' | 0 => {}
            other => {
                return Err(Error::invalid(format!(
                    "the package holds something other than files and directories (tar type {:?}); links and devices are not allowed",
                    other as char
                )));
            }
        }
        let path = long_path.take().unwrap_or_else(|| ustar_path(&header));
        let path = path.trim_start_matches("./").to_owned();
        let name = path.rsplit('/').next().unwrap_or_default();
        if name.starts_with("._") || name == ".DS_Store" {
            skip(archive, size).map_err(|error| bad(error.to_string()))?;
            continue;
        }
        names::relative_path(&path)?;
        if !seen.insert(path.clone()) {
            return Err(Error::invalid(format!("{path} appears twice in the package")));
        }
        total = total.saturating_add(size);
        if total > budget.bytes {
            return Err(Error::invalid(format!("the package unpacks to more than {} MiB", budget.bytes >> 20)));
        }
        let target = into.join(&path);
        if let Some(parent) = target.parent() {
            make_dirs(into, parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&target)
            .map_err(Error::io(format!("writing {path}")))?;
        copy_exact(archive, &mut file, size).map_err(|error| bad(error.to_string()))?;
        files.push((path, size));
    }
    Ok(files)
}

/// Makes the directories from `root` down to `dir`, refusing anything that is not a plain
/// directory on the way.
fn make_dirs(root: &Path, dir: &Path) -> Result<(), Error> {
    let relative = dir.strip_prefix(root).map_err(|_| Error::invalid("path outside the package"))?;
    let mut at = root.to_path_buf();
    for part in relative.components() {
        at.push(part);
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(Error::invalid(format!("{} is both a file and a directory", at.display()))),
            Err(_) => fs::create_dir(&at).map_err(Error::io("making a directory"))?,
        }
    }
    Ok(())
}

fn read_block(archive: &mut impl Read, block: &mut [u8; BLOCK]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < BLOCK {
        let read = archive.read(&mut block[filled..])?;
        if read == 0 {
            return if filled == 0 { Ok(false) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
        }
        filled += read;
    }
    Ok(true)
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

fn read_data(archive: &mut impl Read, size: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(size as usize);
    archive.take(size).read_to_end(&mut data)?;
    if data.len() as u64 != size {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    skip_bytes(archive, padding(size)).map(|_| data)
}

/// Skips an entry's data and its padding.
fn skip(archive: &mut impl Read, size: u64) -> io::Result<()> {
    skip_bytes(archive, size + padding(size))
}

fn skip_bytes(archive: &mut impl Read, count: u64) -> io::Result<()> {
    let copied = io::copy(&mut archive.take(count), &mut io::sink())?;
    if copied != count {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

fn copy_exact(archive: &mut impl Read, out: &mut impl Write, size: u64) -> io::Result<()> {
    let copied = io::copy(&mut archive.take(size), out)?;
    if copied != size {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    skip_bytes(archive, padding(size))
}

fn octal(field: &[u8]) -> Option<u64> {
    // Base-256 sizes (high bit set) are for files of 8 GiB and up: refused.
    let text = std::str::from_utf8(field).ok()?;
    let text = text.trim_matches(|c: char| c == '\0' || c == ' ');
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

fn checksum_ok(header: &[u8; BLOCK]) -> bool {
    let Some(stored) = octal(&header[148..156]) else { return false };
    let sum: u64 = header.iter().enumerate().map(|(index, &byte)| if (148..156).contains(&index) { b' ' as u64 } else { byte as u64 }).sum();
    sum == stored
}

fn field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn ustar_path(header: &[u8; BLOCK]) -> String {
    let name = field(&header[0..100]);
    let prefix = if &header[257..262] == b"ustar" { field(&header[345..500]) } else { String::new() };
    if prefix.is_empty() { name } else { format!("{prefix}/{name}") }
}

/// The `path` record of a pax header (`<len> path=<value>\n` records).
fn pax_path(data: &[u8]) -> Option<String> {
    let mut rest = data;
    let mut path = None;
    while !rest.is_empty() {
        let space = rest.iter().position(|&byte| byte == b' ')?;
        let length: usize = std::str::from_utf8(&rest[..space]).ok()?.parse().ok()?;
        if length <= space || length > rest.len() {
            return None;
        }
        let record = &rest[space + 1..length];
        let record = record.strip_suffix(b"\n")?;
        if let Some(value) = record.strip_prefix(b"path=") {
            path = Some(String::from_utf8(value.to_vec()).ok()?);
        }
        rest = &rest[length..];
    }
    path
}

/// Writes a tar of `files` (path, content): for tests and the `pack` command.
pub fn write(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, data) in files {
        out.extend_from_slice(&header(path, data.len() as u64, b'0'));
        out.extend_from_slice(data);
        out.resize(out.len() + padding(data.len() as u64) as usize, 0);
    }
    out.resize(out.len() + 2 * BLOCK, 0);
    out
}

/// One ustar header. Paths longer than 100 bytes are not supported here.
pub fn header(path: &str, size: u64, kind: u8) -> [u8; BLOCK] {
    let mut header = [0u8; BLOCK];
    header[..path.len()].copy_from_slice(path.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].copy_from_slice(b"        ");
    let sum: u64 = header.iter().map(|&byte| byte as u64).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: Budget = Budget { bytes: 1 << 20, entries: 64 };

    fn dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("khi-tar-{}-{}", std::process::id(), crate::hex(&crate::random::<6>().unwrap())));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unpacks_files_into_directories() {
        let into = dir();
        let tar = write(&[("bin/x", b"program"), ("files/a/b.txt", b"hello"), ("._junk", b"mac")]);
        let files = unpack(&mut tar.as_slice(), &into, BUDGET).unwrap();
        assert_eq!(files, vec![("bin/x".to_owned(), 7), ("files/a/b.txt".to_owned(), 5)]);
        assert_eq!(fs::read(into.join("files/a/b.txt")).unwrap(), b"hello");
        assert!(!into.join("._junk").exists());
    }

    #[test]
    fn refuses_what_could_escape_or_overwrite() {
        for (name, tar) in [
            ("traversal", write(&[("../x", b"1")])),
            ("absolute", write(&[("/etc/x", b"1")])),
            ("hidden", write(&[("a/.x", b"1")])),
            ("twice", write(&[("a", b"1"), ("a", b"2")])),
            ("file then dir", write(&[("a", b"1"), ("a/b", b"2")])),
        ] {
            assert!(unpack(&mut tar.as_slice(), &dir(), BUDGET).is_err(), "{name}");
        }
        let mut link = header("a", 0, b'2').to_vec();
        link.resize(link.len() + 2 * BLOCK, 0);
        assert!(unpack(&mut link.as_slice(), &dir(), BUDGET).is_err(), "symlink");
        let mut corrupt = write(&[("a", b"1")]);
        corrupt[0] = b'b';
        assert!(unpack(&mut corrupt.as_slice(), &dir(), BUDGET).is_err(), "checksum");
        let truncated = &write(&[("a", &[7u8; 2000])])[..1024];
        assert!(unpack(&mut &truncated[..], &dir(), BUDGET).is_err(), "truncated");
    }

    #[test]
    fn keeps_to_the_budget_before_writing() {
        // A header that claims a huge size is refused before any byte is written.
        let mut tar = header("big", 4 << 30, b'0').to_vec();
        tar.resize(tar.len() + 2 * BLOCK, 0);
        let into = dir();
        assert!(unpack(&mut tar.as_slice(), &into, BUDGET).is_err());
        assert!(!into.join("big").exists());
        let many: Vec<(String, Vec<u8>)> = (0..100).map(|n| (format!("f{n}"), vec![])).collect();
        let many: Vec<(&str, &[u8])> = many.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        assert!(unpack(&mut write(&many).as_slice(), &dir(), BUDGET).is_err());
    }

    #[test]
    fn reads_a_pax_long_path() {
        let long = format!("files/{}/{}/end.txt", "a".repeat(90), "b".repeat(90));
        let record = {
            // The length counts itself.
            let body = format!("path={long}\n");
            let mut length = body.len() + 2;
            loop {
                let candidate = format!("{length} {body}");
                if candidate.len() == length {
                    break candidate;
                }
                length = candidate.len();
            }
        };
        let mut tar = header("PaxHeader", record.len() as u64, b'x').to_vec();
        tar.extend_from_slice(record.as_bytes());
        tar.resize(tar.len() + padding(record.len() as u64) as usize, 0);
        tar.extend_from_slice(&header("short", 2, b'0'));
        tar.extend_from_slice(b"ok");
        tar.resize(tar.len() + padding(2) as usize + 2 * BLOCK, 0);
        let into = dir();
        let files = unpack(&mut tar.as_slice(), &into, BUDGET).unwrap();
        assert_eq!(files[0].0, long);
        assert_eq!(fs::read(into.join(&long)).unwrap(), b"ok");
    }
}

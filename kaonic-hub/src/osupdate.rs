//! OS updates from a release bundle, the `image-<machine>-v<version>-emmc.tar.gz` the image
//! build makes. The bundle is checked against its `manifest.toml` (machine, boot device and a
//! SHA-256 for every file), then its bootfs and rootfs are written into the A/B slot that is
//! not running, read back and checked again. The bootloaders and the shared partitions
//! (vendorfs, userfs) are never touched.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use sha2::{Digest, Sha256};

const BLOCK: usize = 512;
const CHUNK: usize = 256 * 1024;
/// The only manifest layout known.
const SCHEMA: u32 = 1;
const MANIFEST: &str = "manifest.toml";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    pub schema: u32,
    pub machine: String,
    pub boot_device: String,
    pub version: String,
    pub built: Option<String>,
    pub files: Vec<FileEntry>,
}

/// A bundle that suits this device, with the two images to write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Checked {
    pub version: String,
    pub machine: String,
    pub built: Option<String>,
    #[serde(skip)]
    pub bootfs: FileEntry,
    #[serde(skip)]
    pub rootfs: FileEntry,
}

fn unquote(value: &str) -> Option<String> {
    let value = value.trim();
    value.strip_prefix('"')?.strip_suffix('"').map(str::to_owned)
}

/// Reads the manifest the image build writes: top-level keys, then `[[files]]` tables with
/// `path`, `size` and `sha256`.
pub fn parse_manifest(text: &str) -> Result<Manifest, String> {
    let mut manifest = Manifest::default();
    let mut file: Option<(Option<String>, Option<u64>, Option<String>)> = None;
    let finish = |file: &mut Option<(Option<String>, Option<u64>, Option<String>)>, manifest: &mut Manifest| -> Result<(), String> {
        if let Some((path, size, sha256)) = file.take() {
            match (path, size, sha256) {
                (Some(path), Some(size), Some(sha256)) => manifest.files.push(FileEntry { path, size, sha256: sha256.to_ascii_lowercase() }),
                _ => return Err("a file in the manifest has no path, size or sha256".into()),
            }
        }
        Ok(())
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[files]]" {
            finish(&mut file, &mut manifest)?;
            file = Some((None, None, None));
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { return Err(format!("the manifest line \"{line}\" is not understood")) };
        let (key, value) = (key.trim(), value.trim());
        match &mut file {
            Some((path, size, sha256)) => match key {
                "path" => *path = unquote(value),
                "size" => *size = value.parse().ok(),
                "sha256" => *sha256 = unquote(value),
                _ => {}
            },
            None => match key {
                "schema" => manifest.schema = value.parse().map_err(|_| "the manifest schema is not a number")?,
                "machine" => manifest.machine = unquote(value).unwrap_or_default(),
                "boot_device" => manifest.boot_device = unquote(value).unwrap_or_default(),
                "version" => manifest.version = unquote(value).unwrap_or_default(),
                "built" => manifest.built = unquote(value),
                _ => {}
            },
        }
    }
    finish(&mut file, &mut manifest)?;
    Ok(manifest)
}

/// Whether the bundle suits a device of `machine`: the same machine, an eMMC bundle, and a
/// bootfs and a rootfs image in it.
pub fn compatible(manifest: &Manifest, machine: Option<&str>) -> Result<Checked, String> {
    if manifest.schema != SCHEMA {
        return Err(format!("the bundle's manifest is format {}, and this hub reads format {SCHEMA}", manifest.schema));
    }
    if manifest.version.is_empty() || manifest.machine.is_empty() {
        return Err("the manifest names no machine or version".into());
    }
    let machine = machine.ok_or("this device does not know its machine (/etc/kaonic/kaonic_machine)")?;
    if manifest.machine != machine {
        return Err(format!("this image is for {}, and this device is {machine}", manifest.machine));
    }
    if manifest.boot_device != "emmc" {
        return Err(format!("this is the {} bundle; use the eMMC one (…-emmc.tar.gz)", if manifest.boot_device.is_empty() { "wrong" } else { &manifest.boot_device }));
    }
    let image = |kind: &str| {
        let suffix = format!("-{kind}.ext4");
        let mut found = manifest.files.iter().filter(|file| file.path.ends_with(&suffix) && !file.path.contains('/'));
        match (found.next(), found.next()) {
            (Some(file), None) => Ok(file.clone()),
            (None, _) => Err(format!("the bundle has no {kind} image")),
            _ => Err(format!("the bundle has more than one {kind} image")),
        }
    };
    Ok(Checked { version: manifest.version.clone(), machine: manifest.machine.clone(), built: manifest.built.clone(), bootfs: image("bootfs")?, rootfs: image("rootfs")? })
}

/// Compares dotted versions number by number (`0.10.0` is newer than `0.9.3`).
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |text: &str| text.split(['.', '-']).map(|part| part.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    parts(a).cmp(&parts(b))
}

/* ── reading the bundle ── */

/// `gzip -dc` of a file, fed by a thread that counts the compressed bytes read.
struct Gunzip {
    child: Child,
    out: ChildStdout,
    feeder: Option<std::thread::JoinHandle<io::Result<()>>>,
}

impl Gunzip {
    fn open(path: &Path, read: Arc<AtomicU64>) -> io::Result<Self> {
        let mut input = File::open(path)?;
        let mut child = Command::new("gzip").arg("-dc").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
        let mut stdin = child.stdin.take().expect("piped");
        let out = child.stdout.take().expect("piped");
        let feeder = std::thread::spawn(move || {
            let mut buffer = vec![0u8; CHUNK];
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 {
                    return Ok(());
                }
                // gzip stops reading once the stream ends, or when it is killed.
                if stdin.write_all(&buffer[..count]).is_err() {
                    return Ok(());
                }
                read.fetch_add(count as u64, Ordering::Relaxed);
            }
        });
        Ok(Self { child, out, feeder: Some(feeder) })
    }

    /// Waits for gzip; an error if it failed (a damaged or truncated file).
    fn finish(mut self) -> io::Result<()> {
        // Anything after the archive's end is drained, so gzip is not killed by a full pipe.
        io::copy(&mut self.out, &mut io::sink())?;
        let status = self.child.wait()?;
        if let Some(feeder) = self.feeder.take() {
            feeder.join().map_err(|_| io::Error::other("the reading thread stopped"))??;
        }
        if !status.success() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the file is not a complete tar.gz"));
        }
        Ok(())
    }
}

impl Drop for Gunzip {
    fn drop(&mut self) {
        if self.feeder.is_some() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Read for Gunzip {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.out.read(buffer)
    }
}

fn octal(field: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(field).ok()?.trim_matches(|c: char| c == '\0' || c == ' ');
    if text.is_empty() { Some(0) } else { u64::from_str_radix(text, 8).ok() }
}

fn text(field: &[u8]) -> String {
    let end = field.iter().position(|&byte| byte == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// `./a/b` → `a/b`.
fn clean(path: &str) -> String {
    path.trim_start_matches("./").trim_end_matches('/').to_owned()
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

/// The `path` record of a pax header.
fn pax_path(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    text.lines().find_map(|line| line.split_once(' ').and_then(|(_, record)| record.strip_prefix("path=")).map(str::to_owned))
}

/// Calls `entry` with the path, size and content of each regular file in a tar stream; the
/// content not read is skipped.
pub fn each_file(mut archive: impl Read, mut entry: impl FnMut(&str, u64, &mut dyn Read) -> io::Result<()>) -> io::Result<()> {
    let invalid = |why: &str| io::Error::new(io::ErrorKind::InvalidData, format!("not a valid tar: {why}"));
    let mut header = [0u8; BLOCK];
    let mut long_name: Option<String> = None;
    loop {
        if let Err(error) = archive.read_exact(&mut header) {
            return if error.kind() == io::ErrorKind::UnexpectedEof { Err(invalid("it ends early")) } else { Err(error) };
        }
        if header.iter().all(|&byte| byte == 0) {
            return Ok(());
        }
        let sum: u64 = header.iter().enumerate().map(|(at, &byte)| if (148..156).contains(&at) { u64::from(b' ') } else { u64::from(byte) }).sum();
        if octal(&header[148..156]) != Some(sum) {
            return Err(invalid("a header checksum is wrong"));
        }
        let size = octal(&header[124..136]).ok_or_else(|| invalid("a size is not a number"))?;
        let kind = header[156];
        let mut name = text(&header[0..100]);
        if &header[257..262] == b"ustar" {
            let prefix = text(&header[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        if let Some(long) = long_name.take() {
            name = long;
        }
        match kind {
            b'L' | b'x' => {
                if size > 64 * 1024 {
                    return Err(invalid("a header is too long"));
                }
                let mut data = vec![0u8; size as usize];
                archive.read_exact(&mut data)?;
                io::copy(&mut (&mut archive).take(padding(size)), &mut io::sink())?;
                long_name = if kind == b'L' { Some(text(&data)) } else { pax_path(&data) };
                continue;
            }
            b'0' | 0 => {
                let mut content = (&mut archive).take(size);
                entry(&clean(&name), size, &mut content)?;
                io::copy(&mut content, &mut io::sink())?;
            }
            _ => {
                io::copy(&mut (&mut archive).take(size), &mut io::sink())?;
            }
        }
        io::copy(&mut (&mut archive).take(padding(size)), &mut io::sink())?;
    }
}

/// Copies `from` into `to`, hashing it, with progress per chunk.
fn copy_hashed(from: &mut dyn Read, to: &mut dyn Write, progress: &mut dyn FnMut(u64)) -> io::Result<(u64, String)> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let count = from.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        to.write_all(&buffer[..count])?;
        total += count as u64;
        progress(count as u64);
    }
    Ok((total, crate::random::hex(&hash.finalize())))
}

/// Reads the whole bundle once: every file's SHA-256 must match the manifest, and the
/// bundle must suit `machine`. `progress` gets the share of the file read so far.
pub fn check(path: &Path, machine: Option<&str>, progress: &dyn Fn(f32)) -> Result<Checked, String> {
    let length = std::fs::metadata(path).map_err(|error| format!("the upload is gone: {error}"))?.len().max(1);
    let read = Arc::new(AtomicU64::new(0));
    let mut gunzip = Gunzip::open(path, read.clone()).map_err(|error| format!("cannot unpack the file: {error}"))?;
    let mut seen: HashMap<String, (u64, String)> = HashMap::new();
    let mut manifest_text: Option<String> = None;
    let mut last = 0u64;
    let result = each_file(&mut gunzip, |name, size, content| {
        if name == MANIFEST {
            if size > 1024 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "the manifest is too large"));
            }
            let mut text = String::new();
            content.read_to_string(&mut text)?;
            manifest_text = Some(text);
            return Ok(());
        }
        let (len, sha256) = copy_hashed(content, &mut io::sink(), &mut |_| {
            let now = read.load(Ordering::Relaxed);
            if now - last >= 4 * 1024 * 1024 {
                last = now;
                progress((now as f32 / length as f32).min(0.99));
            }
        })?;
        if len != size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the file ends early"));
        }
        seen.insert(name.to_owned(), (len, sha256));
        Ok(())
    });
    match result {
        Ok(()) => gunzip.finish().map_err(|error| format!("this is not a Kaonic image bundle ({error})"))?,
        Err(error) => return Err(format!("this is not a Kaonic image bundle ({error})")),
    }
    let manifest = parse_manifest(&manifest_text.ok_or("this is not a Kaonic image bundle: it has no manifest.toml")?)?;
    let checked = compatible(&manifest, machine)?;
    for file in &manifest.files {
        match seen.get(&file.path) {
            None => return Err(format!("the bundle is incomplete: {} is missing", file.path)),
            Some((size, sha256)) if *size != file.size || *sha256 != file.sha256 => {
                return Err(format!("the bundle is damaged: {} does not match its checksum", file.path));
            }
            Some(_) => {}
        }
    }
    progress(1.0);
    Ok(checked)
}

/// Where an image goes: a block device, or nowhere in a dry run.
pub enum Target<'a> {
    Device(&'a str),
    DryRun,
}

fn device_size(path: &str) -> io::Result<u64> {
    File::open(path)?.seek(SeekFrom::End(0))
}

/// Writes the bundle's bootfs and rootfs to their targets, checking each image's SHA-256
/// on the way and again by reading the device back. `progress` gets the share done.
pub fn write_images(path: &Path, checked: &Checked, bootfs: Target<'_>, rootfs: Target<'_>, progress: &dyn Fn(f32, &str)) -> Result<(), String> {
    for (entry, target, label) in [(&checked.bootfs, &bootfs, "boot"), (&checked.rootfs, &rootfs, "system")] {
        if let Target::Device(device) = target {
            let room = device_size(device).map_err(|error| format!("cannot open the {label} partition {device}: {error}"))?;
            if room < entry.size {
                return Err(format!("the {label} image ({} MB) does not fit its partition ({} MB)", entry.size >> 20, room >> 20));
            }
        }
    }
    let total = (checked.bootfs.size + checked.rootfs.size).max(1) as f32;
    // Writing is 80% of the work, reading back the rest.
    let mut written = 0u64;
    let read = Arc::new(AtomicU64::new(0));
    let mut gunzip = Gunzip::open(path, read).map_err(|error| format!("cannot unpack the file: {error}"))?;
    let mut done: Vec<&str> = Vec::new();
    let result = each_file(&mut gunzip, |name, _, content| {
        let (entry, target, label) = if name == checked.bootfs.path {
            (&checked.bootfs, &bootfs, "boot")
        } else if name == checked.rootfs.path {
            (&checked.rootfs, &rootfs, "system")
        } else {
            return Ok(());
        };
        progress(0.8 * written as f32 / total, &format!("Writing the {label} partition"));
        let mut device = match target {
            Target::Device(device) => Some(std::fs::OpenOptions::new().write(true).open(device)?),
            Target::DryRun => None,
        };
        let mut sink = io::sink();
        let out: &mut dyn Write = match device.as_mut() {
            Some(file) => file,
            None => &mut sink,
        };
        let mut step = 0u64;
        let (_, sha256) = copy_hashed(content, out, &mut |count| {
            written += count;
            step += count;
            if step >= 8 * 1024 * 1024 {
                step = 0;
                progress(0.8 * written as f32 / total, &format!("Writing the {label} partition"));
            }
        })?;
        if let Some(file) = device {
            file.sync_all()?;
        }
        if sha256 != entry.sha256 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the {label} image changed while it was written")));
        }
        done.push(label);
        Ok(())
    });
    result.map_err(|error| format!("writing the update failed: {error}"))?;
    gunzip.finish().map_err(|error| format!("writing the update failed: {error}"))?;
    if done.len() != 2 {
        return Err("the bundle did not contain both images".into());
    }
    let mut verified = 0u64;
    for (entry, target, label) in [(&checked.bootfs, &bootfs, "boot"), (&checked.rootfs, &rootfs, "system")] {
        let Target::Device(device) = target else { continue };
        let mut file = File::open(device).map_err(|error| format!("cannot read the {label} partition back: {error}"))?;
        let mut step = 0u64;
        let (_, sha256) = copy_hashed(&mut (&mut file).take(entry.size), &mut io::sink(), &mut |count| {
            verified += count;
            step += count;
            if step >= 8 * 1024 * 1024 {
                step = 0;
                progress(0.8 + 0.18 * verified as f32 / total, "Checking what was written");
            }
        })
        .map_err(|error| format!("cannot read the {label} partition back: {error}"))?;
        if sha256 != entry.sha256 {
            return Err(format!("the {label} partition does not read back as written: the storage may be failing"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

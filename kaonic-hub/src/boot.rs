//! A/B boot slots: which slot runs and which boots next, the boot switch, and installing
//! an uploaded kernel into the slot that is not running.
//!
//! Everything that touches the board goes through [`Board`], so the logic is tested
//! without one, and `--boot-dry-run` (the default off Linux) only logs the commands.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Serialize;

pub const ENV_CONFIG: &str = "/etc/fw_env.config.mmc";
const PARTLABELS: &str = "/dev/disk/by-partlabel";
/// Attempts a slot gets, as `kaonic-slot-good` gives them back.
const ATTEMPTS: u8 = 3;
pub const KERNEL_MAX: usize = 24 * 1024 * 1024;
pub const DTB_MAX: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn letter(self) -> &'static str {
        match self {
            Slot::A => "A",
            Slot::B => "B",
        }
    }

    pub fn lower(self) -> &'static str {
        match self {
            Slot::A => "a",
            Slot::B => "b",
        }
    }

    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    pub fn parse(text: &str) -> Option<Slot> {
        match text.trim() {
            "a" | "A" => Some(Slot::A),
            "b" | "B" => Some(Slot::B),
            _ => None,
        }
    }

    fn left_var(self) -> &'static str {
        match self {
            Slot::A => "BOOT_A_LEFT",
            Slot::B => "BOOT_B_LEFT",
        }
    }

    fn partition(self, kind: &str) -> String {
        format!("{PARTLABELS}/{kind}_{}", self.lower())
    }
}

/// The board, as far as the boot code needs it.
pub trait Board: Send + Sync {
    /// Runs a program; its standard output on success.
    fn run(&self, program: &str, args: &[&str]) -> io::Result<String>;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
    fn list(&self, path: &Path) -> io::Result<Vec<String>>;
    fn exists(&self, path: &Path) -> bool;
    fn create_dir(&self, path: &Path) -> io::Result<()>;
    /// Writes `data` to `path` through a temporary file, synced and renamed.
    fn write_atomic(&self, path: &Path, data: &[u8]) -> io::Result<()>;
    /// Points the symlink `link` at `target`, replacing it in one rename.
    fn symlink_atomic(&self, target: &str, link: &Path) -> io::Result<()>;
}

/// The real board.
pub struct System;

impl Board for System {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<String> {
        let output = std::process::Command::new(program).args(args).output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(io::Error::other(format!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim())))
        }
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::read_link(path)
    }

    fn list(&self, path: &Path) -> io::Result<Vec<String>> {
        Ok(std::fs::read_dir(path)?.flatten().map(|entry| entry.file_name().to_string_lossy().into_owned()).collect())
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn write_atomic(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let temporary = path.with_extension("kaonic-new");
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn symlink_atomic(&self, target: &str, link: &Path) -> io::Result<()> {
        let temporary = link.with_extension("kaonic-new");
        let _ = std::fs::remove_file(&temporary);
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &temporary)?;
        #[cfg(not(unix))]
        return Err(io::Error::new(io::ErrorKind::Unsupported, "no symlinks here"));
        std::fs::rename(&temporary, link)
    }
}

/// Logs what it would do; reads nothing from a board.
pub struct DryRun;

impl Board for DryRun {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<String> {
        log::info!("boot (dry run): {program} {}", args.join(" "));
        Ok(String::new())
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        Err(io::Error::new(io::ErrorKind::NotFound, format!("dry run: {}", path.display())))
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        Err(io::Error::new(io::ErrorKind::NotFound, format!("dry run: {}", path.display())))
    }

    fn list(&self, _path: &Path) -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn exists(&self, _path: &Path) -> bool {
        false
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        log::info!("boot (dry run): mkdir {}", path.display());
        Ok(())
    }

    fn write_atomic(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        log::info!("boot (dry run): write {} ({} bytes)", path.display(), data.len());
        Ok(())
    }

    fn symlink_atomic(&self, target: &str, link: &Path) -> io::Result<()> {
        log::info!("boot (dry run): ln -sf {target} {}", link.display());
        Ok(())
    }
}

static DRY_RUN: OnceLock<bool> = OnceLock::new();

/// `--boot-dry-run`; off Linux the hub never touches boot slots.
pub fn configure(dry_run: bool) {
    let _ = DRY_RUN.set(dry_run || !cfg!(target_os = "linux"));
}

pub fn dry_run() -> bool {
    *DRY_RUN.get_or_init(|| !cfg!(target_os = "linux"))
}

pub fn board() -> &'static dyn Board {
    if dry_run() { &DryRun } else { &System }
}

/* ── images ── */

const UIMAGE_MAGIC: u32 = 0x2705_1956;
const FDT_MAGIC: u32 = 0xd00d_feed;

/// What an uploaded file turned out to be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImageInfo {
    pub kind: &'static str,
    pub format: &'static str,
    pub size: usize,
    /// The uImage name (e.g. `Linux-6.6.129-g548f960c059b-dirty`); for a device tree, its model if found.
    pub name: Option<String>,
    /// The kernel release the name implies (`/lib/modules/<version>`).
    pub version: Option<String>,
    pub load_address: Option<String>,
    pub entry_address: Option<String>,
    pub built_ts: Option<i64>,
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// CRC-32 (IEEE), as U-Boot's image headers use.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Checks a legacy U-Boot image of an ARM Linux kernel.
pub fn check_kernel(data: &[u8]) -> Result<ImageInfo, String> {
    if data.len() > KERNEL_MAX {
        return Err(format!("it is larger than {} MiB", KERNEL_MAX / 1024 / 1024));
    }
    if data.len() < 64 || be32(data, 0) != UIMAGE_MAGIC {
        return Err("it is not a U-Boot uImage (a zImage or FIT image must be wrapped as the board's uImage)".into());
    }
    let mut header = data[..64].to_vec();
    let header_crc = be32(&header, 4);
    header[4..8].fill(0);
    if crc32(&header) != header_crc {
        return Err("its header checksum is wrong".into());
    }
    let size = be32(data, 12) as usize;
    if size + 64 != data.len() {
        return Err(format!("its header says {size} bytes of data but the file has {}", data.len() - 64));
    }
    if crc32(&data[64..]) != be32(data, 24) {
        return Err("its data checksum is wrong (the file is damaged)".into());
    }
    let (os, arch, kind) = (data[28], data[29], data[30]);
    if os != 5 {
        return Err("it is not a Linux image".into());
    }
    if arch != 2 {
        return Err("it is not for ARM (the board is a 32-bit ARM Cortex-A7)".into());
    }
    if kind != 2 {
        return Err("it is not a kernel image".into());
    }
    let name = String::from_utf8_lossy(&data[32..64]).trim_end_matches('\0').trim().to_owned();
    let version = name.strip_prefix("Linux-").map(str::to_owned).filter(|version| !version.is_empty());
    Ok(ImageInfo {
        kind: "kernel",
        format: "uimage",
        size: data.len(),
        name: (!name.is_empty()).then_some(name),
        version,
        load_address: Some(format!("0x{:08x}", be32(data, 16))),
        entry_address: Some(format!("0x{:08x}", be32(data, 20))),
        built_ts: Some(i64::from(be32(data, 8))),
    })
}

/// Checks a flattened device tree.
pub fn check_dtb(data: &[u8]) -> Result<ImageInfo, String> {
    if data.len() > DTB_MAX {
        return Err(format!("it is larger than {} KiB", DTB_MAX / 1024));
    }
    if data.len() < 40 || be32(data, 0) != FDT_MAGIC {
        return Err("it is not a device tree blob (.dtb)".into());
    }
    let total = be32(data, 4) as usize;
    if total != data.len() {
        return Err(format!("its header says {total} bytes but the file has {}", data.len()));
    }
    if be32(data, 20) < 16 {
        return Err("its format version is too old".into());
    }
    // The model string is the first property of the root node in practice; good enough to show.
    let model = find_model(data);
    Ok(ImageInfo { kind: "dtb", format: "fdt", size: data.len(), name: model, version: None, load_address: None, entry_address: None, built_ts: None })
}

fn find_model(data: &[u8]) -> Option<String> {
    let strings = be32(data, 12) as usize;
    let structs = be32(data, 8) as usize;
    let strings_size = be32(data, 32) as usize;
    let table = data.get(strings..strings + strings_size)?;
    let model_offset = table.windows(6).position(|window| window == b"model\0")?;
    let mut at = structs;
    while at + 12 <= data.len() {
        match be32(data, at) {
            3 => {
                let length = be32(data, at + 4) as usize;
                let name = be32(data, at + 8) as usize;
                let value = data.get(at + 12..at + 12 + length)?;
                if name == model_offset {
                    return Some(String::from_utf8_lossy(value).trim_end_matches('\0').to_owned());
                }
                at += 12 + length.div_ceil(4) * 4;
            }
            1 => {
                let end = data[at + 4..].iter().position(|&byte| byte == 0)?;
                at += 4 + (end + 1).div_ceil(4) * 4;
            }
            2 | 4 => at += 4,
            _ => return None,
        }
    }
    None
}

/* ── state ── */

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct KernelInfo {
    pub file: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub size: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SlotInfo {
    pub slot: Slot,
    pub attempts_left: Option<u8>,
    /// Its boot partition has a filesystem.
    pub bootfs: bool,
    /// Its root partition has a filesystem.
    pub rootfs: bool,
    pub kernel: Option<KernelInfo>,
    pub dtb: bool,
    /// Kernel releases with modules in its root filesystem.
    pub modules: Vec<String>,
    /// A kernel, a device tree and a root filesystem: the slot can be booted.
    pub bootable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BootState {
    pub current: Option<Slot>,
    pub order: Vec<Slot>,
    /// The slot U-Boot tries first next time.
    pub next: Option<Slot>,
    /// A one-time boot is pending: after it, `order` goes back to `after_once`.
    pub once: bool,
    pub after_once: Vec<Slot>,
    pub fdtfile: Option<String>,
    pub dry_run: bool,
    pub slots: Vec<SlotInfo>,
}

pub fn parse_env(text: &str) -> BTreeMap<String, String> {
    text.lines().filter_map(|line| line.split_once('=')).map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned())).collect()
}

fn parse_order(text: &str) -> Vec<Slot> {
    text.split_whitespace().filter_map(Slot::parse).collect()
}

pub fn current_slot(cmdline: &str) -> Option<Slot> {
    cmdline.split_whitespace().find_map(|word| word.strip_prefix("kaonic.slot=")).and_then(Slot::parse)
}

fn read_env(board: &dyn Board) -> io::Result<BTreeMap<String, String>> {
    Ok(parse_env(&board.run("fw_printenv", &["-c", ENV_CONFIG])?))
}

fn has_filesystem(board: &dyn Board, device: &str) -> bool {
    board.run("blkid", &["-o", "value", "-s", "TYPE", device]).map(|kind| !kind.trim().is_empty()).unwrap_or(false)
}

/// Mounts `device` at `point` for the length of `work`, then unmounts it.
fn with_mount<T>(board: &dyn Board, device: &str, point: &Path, options: &[&str], work: impl FnOnce(&Path) -> T) -> io::Result<T> {
    board.create_dir(point)?;
    let point_text = point.to_string_lossy().into_owned();
    let mut args: Vec<&str> = options.to_vec();
    args.push(device);
    args.push(&point_text);
    board.run("mount", &args)?;
    let result = work(point);
    board.run("umount", &[&point_text])?;
    Ok(result)
}

/// The full kernel release a uImage name implies. The name field holds 32 bytes, so a long
/// release (`Linux-6.6.129-g548f960c059b-dirty`) arrives cut short: then the one module
/// directory that starts with it is the release.
pub fn resolve_release(name: Option<&str>, version: Option<&str>, modules: &[String]) -> Option<String> {
    let version = version?;
    if modules.iter().any(|release| release == version) {
        return Some(version.to_owned());
    }
    let truncated = name.is_some_and(|name| name.len() >= 32);
    let candidates: Vec<&String> = modules.iter().filter(|release| release.starts_with(version)).collect();
    match (truncated, candidates.as_slice()) {
        (true, [only]) => Some((*only).clone()),
        _ => Some(version.to_owned()),
    }
}

fn kernel_in(board: &dyn Board, boot: &Path) -> Option<KernelInfo> {
    let link = boot.join("uImage");
    let file = board.read_link(&link).ok().map(|target| target.to_string_lossy().into_owned());
    let data = board.read(&link).ok()?;
    let info = check_kernel(&data).ok();
    Some(KernelInfo { file, name: info.as_ref().and_then(|info| info.name.clone()), version: info.as_ref().and_then(|info| info.version.clone()), size: Some(data.len()) })
}

fn modules_in(board: &dyn Board, root: &Path) -> Vec<String> {
    let mut modules = board.list(&root.join("lib/modules")).unwrap_or_default();
    modules.sort();
    modules
}

/// Reads the boot state. Mounts the slots' partitions briefly (read-only for the other slot).
pub fn status(board: &dyn Board, run_dir: &Path) -> io::Result<BootState> {
    let cmdline = String::from_utf8_lossy(&board.read(Path::new("/proc/cmdline")).unwrap_or_default()).into_owned();
    let current = current_slot(&cmdline);
    let env = read_env(board).unwrap_or_default();
    let order = env.get("BOOT_ORDER").map(|order| parse_order(order)).filter(|order| !order.is_empty()).unwrap_or(vec![Slot::A, Slot::B]);
    let after_once = env.get("kaonic_after_once").map(|order| parse_order(order)).unwrap_or_default();
    let fdtfile = env.get("fdtfile").cloned().filter(|name| !name.is_empty());
    let inspect = run_dir.join("slot/inspect");
    let mut slots = Vec::new();
    for slot in [Slot::A, Slot::B] {
        let attempts_left = env.get(slot.left_var()).and_then(|left| left.parse().ok());
        let boot_device = slot.partition("bootfs");
        let root_device = slot.partition("rootfs");
        let bootfs = has_filesystem(board, &boot_device);
        let rootfs = has_filesystem(board, &root_device);
        let running = Some(slot) == current;
        let (kernel, dtb) = if bootfs {
            // The running slot's bootfs may be mounted read-write already (on /boot for A): share that mount's flags.
            let options: &[&str] = if running { &[] } else { &["-o", "ro"] };
            with_mount(board, &boot_device, &inspect, options, |boot| {
                (kernel_in(board, boot), fdtfile.as_ref().is_some_and(|name| board.exists(&boot.join(name))))
            })
            .unwrap_or((None, false))
        } else {
            (None, false)
        };
        let modules = if running {
            modules_in(board, Path::new("/"))
        } else if rootfs {
            with_mount(board, &root_device, &inspect, &["-o", "ro"], |root| modules_in(board, root)).unwrap_or_default()
        } else {
            Vec::new()
        };
        let kernel = kernel.map(|kernel| KernelInfo { version: resolve_release(kernel.name.as_deref(), kernel.version.as_deref(), &modules), ..kernel });
        let bootable = kernel.is_some() && dtb && rootfs;
        slots.push(SlotInfo { slot, attempts_left, bootfs, rootfs, kernel, dtb, modules, bootable });
    }
    Ok(BootState { current, next: order.first().copied(), once: !after_once.is_empty(), order, after_once, fdtfile, dry_run: dry_run(), slots })
}

/* ── boot switch ── */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Once,
    Permanent,
}

/// The `fw_setenv` assignments that make `slot` boot next.
pub fn switch_assignments(slot: Slot, mode: Mode, order: &[Slot]) -> Vec<(&'static str, String)> {
    let new_order = format!("{} {}", slot.letter(), slot.other().letter());
    match mode {
        Mode::Once => {
            // Back to the order as it was (or the running slot first) after the one boot.
            let previous = if order.first() == Some(&slot) { vec![slot.other(), slot] } else { order.to_vec() };
            let previous = previous.iter().map(|slot| slot.letter()).collect::<Vec<_>>().join(" ");
            vec![("BOOT_ORDER", new_order), (slot.left_var(), "1".into()), ("kaonic_after_once", previous)]
        }
        Mode::Permanent => vec![("BOOT_ORDER", new_order), (slot.left_var(), ATTEMPTS.to_string()), ("kaonic_after_once", String::new())],
    }
}

/// Sets the next boot slot. Refuses a slot with no bootable system.
pub fn set_next(board: &dyn Board, state: &BootState, slot: Slot, mode: Mode) -> Result<(), String> {
    let info = state.slots.iter().find(|info| info.slot == slot).ok_or("unknown slot")?;
    if !info.bootable && state.current != Some(slot) {
        return Err(format!("Slot {} has no system to boot. Install a kernel into it first.", slot.letter()));
    }
    for (name, value) in switch_assignments(slot, mode, &state.order) {
        let mut args = vec!["-c", ENV_CONFIG, name];
        if !value.is_empty() {
            args.push(&value);
        }
        board.run("fw_setenv", &args).map_err(|error| format!("Could not change the boot settings: {error}"))?;
    }
    Ok(())
}

/// At start-up: a one-time boot of this slot is done, so the previous order comes back.
pub fn after_start(board: &dyn Board) -> Option<String> {
    let env = read_env(board).ok()?;
    let previous = env.get("kaonic_after_once").filter(|order| !order.is_empty())?.clone();
    let cmdline = String::from_utf8_lossy(&board.read(Path::new("/proc/cmdline")).ok()?).into_owned();
    let current = current_slot(&cmdline)?;
    let order = parse_order(env.get("BOOT_ORDER")?);
    if order.first() != Some(&current) {
        return None;
    }
    board.run("fw_setenv", &["-c", ENV_CONFIG, "BOOT_ORDER", &previous]).ok()?;
    board.run("fw_setenv", &["-c", ENV_CONFIG, "kaonic_after_once"]).ok()?;
    Some(format!("one-time boot of slot {} done: next boot follows \"{previous}\" again", current.letter()))
}

/* ── kernel install ── */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prepare {
    /// Copy the running system into the target slot only if it has none.
    Auto,
    Always,
    Never,
}

pub struct Install<'a> {
    pub kernel: Option<(&'a [u8], ImageInfo)>,
    pub dtb: Option<&'a [u8]>,
    pub target: Slot,
    pub prepare: Prepare,
    pub allow_missing_modules: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InstallReport {
    pub slot: Slot,
    pub prepared: bool,
    pub kernel_file: Option<String>,
    pub dtb_file: Option<String>,
    pub modules_present: Option<bool>,
}

struct Mounts<'a> {
    board: &'a dyn Board,
    points: Vec<String>,
}

impl Mounts<'_> {
    fn mount(&mut self, args: &[&str], point: &Path) -> Result<(), String> {
        self.board.create_dir(point).map_err(|error| error.to_string())?;
        let point_text = point.to_string_lossy().into_owned();
        let mut all = args.to_vec();
        all.push(&point_text);
        self.board.run("mount", &all).map_err(|error| error.to_string())?;
        self.points.push(point_text);
        Ok(())
    }
}

impl Drop for Mounts<'_> {
    fn drop(&mut self) {
        let _ = self.board.run("sync", &[]);
        for point in self.points.iter().rev() {
            if let Err(error) = self.board.run("umount", &[point]) {
                log::warn!("boot: {error}");
            }
        }
    }
}

/// Writes the staged files into the slot that is not running, preparing it from the running system first if needed.
pub fn install(board: &dyn Board, run_dir: &Path, state: &BootState, job: &Install<'_>, progress: &dyn Fn(f32, &str)) -> Result<InstallReport, String> {
    let current = state.current.ok_or("The running slot is unknown (no kaonic.slot on the kernel command line).")?;
    if job.target == current {
        return Err("The running slot is never written. Install into the other slot.".into());
    }
    if job.kernel.is_none() && job.dtb.is_none() {
        return Err("Nothing is uploaded to install.".into());
    }
    let target = state.slots.iter().find(|info| info.slot == job.target).ok_or("unknown slot")?;
    let prepare = match job.prepare {
        Prepare::Always => true,
        Prepare::Auto => !(target.bootfs && target.rootfs && target.kernel.is_some()),
        Prepare::Never => false,
    };
    if !prepare && !(target.bootfs && target.rootfs) {
        return Err(format!("Slot {} has no system yet: let the hub copy the running one into it first.", job.target.letter()));
    }
    let dtb_name = match (job.dtb, &state.fdtfile) {
        (Some(_), None) => return Err("The board's environment names no device tree file (fdtfile).".into()),
        (_, name) => name.clone(),
    };
    let base = run_dir.join("slot");
    let (boot, root) = (base.join("boot"), base.join("root"));
    let mut mounts = Mounts { board, points: Vec::new() };
    if prepare {
        progress(0.05, "Formatting the other slot");
        for (kind, label) in [("bootfs", "bootfs"), ("rootfs", "rootfs")] {
            board.run("mkfs.ext4", &["-F", "-q", "-L", label, &job.target.partition(kind)]).map_err(|error| error.to_string())?;
        }
        mounts.mount(&[&job.target.partition("bootfs")], &boot)?;
        mounts.mount(&[&job.target.partition("rootfs")], &root)?;
        let (source_boot, source_root) = (base.join("src-boot"), base.join("src-root"));
        mounts.mount(&[&current.partition("bootfs")], &source_boot)?;
        mounts.mount(&["--bind", "/"], &source_root)?;
        progress(0.15, "Copying the running boot files");
        board.run("cp", &["-a", &format!("{}/.", source_boot.display()), &format!("{}/", boot.display())]).map_err(|error| error.to_string())?;
        progress(0.3, "Copying the running system (a few minutes)");
        board.run("cp", &["-a", &format!("{}/.", source_root.display()), &format!("{}/", root.display())]).map_err(|error| error.to_string())?;
    } else {
        mounts.mount(&[&job.target.partition("bootfs")], &boot)?;
        mounts.mount(&[&job.target.partition("rootfs")], &root)?;
    }
    let mut report = InstallReport { slot: job.target, prepared: prepare, kernel_file: None, dtb_file: None, modules_present: None };
    if let Some((data, info)) = &job.kernel {
        let modules = board.list(&root.join("lib/modules")).unwrap_or_default();
        let version = resolve_release(info.name.as_deref(), info.version.as_deref(), &modules).unwrap_or_else(|| "custom".into());
        let present = board.exists(&root.join("lib/modules").join(&version));
        report.modules_present = Some(present);
        if !present && !job.allow_missing_modules {
            return Err(format!(
                "Slot {} has no modules for kernel {version} (/lib/modules/{version}): the radio driver would not load. Install them, or confirm to boot without them.",
                job.target.letter()
            ));
        }
        progress(0.85, "Writing the kernel");
        let file = format!("uImage-{version}");
        board.write_atomic(&boot.join(&file), data).map_err(|error| error.to_string())?;
        board.symlink_atomic(&file, &boot.join("uImage")).map_err(|error| error.to_string())?;
        report.kernel_file = Some(file);
    }
    if let (Some(data), Some(name)) = (job.dtb, dtb_name) {
        progress(0.92, "Writing the device tree");
        board.write_atomic(&boot.join(&name), data).map_err(|error| error.to_string())?;
        report.dtb_file = Some(name);
    }
    progress(0.97, "Syncing");
    drop(mounts);
    Ok(report)
}

#[cfg(test)]
mod tests;

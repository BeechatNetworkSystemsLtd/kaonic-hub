use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use super::*;

/// A board in memory: files, links, a fixed fw_printenv output and the commands it ran.
#[derive(Default)]
struct Fake {
    env: Mutex<BTreeMap<String, String>>,
    filesystems: BTreeSet<String>,
    files: Mutex<BTreeMap<PathBuf, Vec<u8>>>,
    links: Mutex<BTreeMap<PathBuf, String>>,
    dirs: BTreeMap<PathBuf, Vec<String>>,
    ran: Mutex<Vec<String>>,
    fail: Option<&'static str>,
}

impl Fake {
    fn commands(&self) -> Vec<String> {
        self.ran.lock().unwrap().clone()
    }
}

impl Board for Fake {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<String> {
        let line = format!("{program} {}", args.join(" "));
        self.ran.lock().unwrap().push(line.trim().to_owned());
        if self.fail.is_some_and(|fail| line.starts_with(fail)) {
            return Err(io::Error::other(format!("{program} failed")));
        }
        match program {
            "fw_printenv" => Ok(self.env.lock().unwrap().iter().map(|(name, value)| format!("{name}={value}\n")).collect()),
            "fw_setenv" => {
                let mut env = self.env.lock().unwrap();
                match args {
                    [_, _, name] => {
                        env.remove(*name);
                    }
                    [_, _, name, value] => {
                        env.insert((*name).to_owned(), (*value).to_owned());
                    }
                    _ => {}
                }
                Ok(String::new())
            }
            "blkid" => Ok(if self.filesystems.contains(*args.last().unwrap()) { "ext4\n".into() } else { String::new() }),
            _ => Ok(String::new()),
        }
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let files = self.files.lock().unwrap();
        let links = self.links.lock().unwrap();
        let resolved = links.get(path).map(|target| path.with_file_name(target)).unwrap_or(path.to_path_buf());
        files.get(&resolved).cloned().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.display().to_string()))
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        self.links.lock().unwrap().get(path).map(PathBuf::from).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no link"))
    }

    fn list(&self, path: &Path) -> io::Result<Vec<String>> {
        self.dirs.get(path).cloned().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no dir"))
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.lock().unwrap().contains_key(path) || self.dirs.contains_key(path) || self.links.lock().unwrap().contains_key(path)
    }

    fn create_dir(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }

    fn write_atomic(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        self.ran.lock().unwrap().push(format!("write {}", path.display()));
        self.files.lock().unwrap().insert(path.to_path_buf(), data.to_vec());
        Ok(())
    }

    fn symlink_atomic(&self, target: &str, link: &Path) -> io::Result<()> {
        self.ran.lock().unwrap().push(format!("ln {target} {}", link.display()));
        self.links.lock().unwrap().insert(link.to_path_buf(), target.to_owned());
        Ok(())
    }
}

/// A valid uImage of `payload` named `name`.
fn uimage(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; 64];
    header[0..4].copy_from_slice(&UIMAGE_MAGIC.to_be_bytes());
    header[8..12].copy_from_slice(&1_775_000_000u32.to_be_bytes());
    header[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    header[16..20].copy_from_slice(&0xc200_8000u32.to_be_bytes());
    header[20..24].copy_from_slice(&0xc200_8000u32.to_be_bytes());
    header[24..28].copy_from_slice(&crc32(payload).to_be_bytes());
    header[28] = 5;
    header[29] = 2;
    header[30] = 2;
    header[32..32 + name.len()].copy_from_slice(name.as_bytes());
    let crc = crc32(&header);
    header[4..8].copy_from_slice(&crc.to_be_bytes());
    [header, payload.to_vec()].concat()
}

/// A minimal device tree with a root `model` property.
fn dtb(model: &str) -> Vec<u8> {
    let mut structure = Vec::new();
    structure.extend_from_slice(&1u32.to_be_bytes());
    structure.extend_from_slice(&[0, 0, 0, 0]);
    let value = format!("{model}\0");
    structure.extend_from_slice(&3u32.to_be_bytes());
    structure.extend_from_slice(&(value.len() as u32).to_be_bytes());
    structure.extend_from_slice(&0u32.to_be_bytes());
    let mut padded = value.into_bytes();
    padded.resize(padded.len().div_ceil(4) * 4, 0);
    structure.extend_from_slice(&padded);
    structure.extend_from_slice(&2u32.to_be_bytes());
    structure.extend_from_slice(&9u32.to_be_bytes());
    let strings = b"model\0".to_vec();
    let structs_at = 40 + 16;
    let strings_at = structs_at + structure.len();
    let total = strings_at + strings.len();
    let mut out = vec![0u8; 40];
    for (at, value) in [(0, FDT_MAGIC), (4, total as u32), (8, structs_at as u32), (12, strings_at as u32), (16, 40), (20, 17), (24, 16), (32, strings.len() as u32), (36, structure.len() as u32)] {
        out[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&structure);
    out.extend_from_slice(&strings);
    out
}

fn board() -> Fake {
    let mut fake = Fake::default();
    for (name, value) in [("BOOT_ORDER", "A B"), ("BOOT_A_LEFT", "3"), ("BOOT_B_LEFT", "3"), ("fdtfile", "board.dtb")] {
        fake.env.get_mut().unwrap().insert(name.into(), value.into());
    }
    fake.files.get_mut().unwrap().insert("/proc/cmdline".into(), b"root=PARTLABEL=rootfs_a rw kaonic.slot=a console=ttySTM0".to_vec());
    fake.filesystems = [format!("{PARTLABELS}/bootfs_a"), format!("{PARTLABELS}/rootfs_a")].into();
    let inspect = PathBuf::from("/run/kaonic-hub/slot/inspect");
    fake.files.get_mut().unwrap().insert(inspect.join("uImage-6.6.129"), uimage("Linux-6.6.129", b"kernel"));
    fake.links.get_mut().unwrap().insert(inspect.join("uImage"), "uImage-6.6.129".into());
    fake.files.get_mut().unwrap().insert(inspect.join("board.dtb"), dtb("Kaonic"));
    fake.dirs.insert("/lib/modules".into(), vec!["6.6.129".into()]);
    fake
}

const RUN: &str = "/run/kaonic-hub";

#[test]
fn a_release_cut_short_by_the_32_byte_name_is_found_among_the_modules() {
    let modules = vec!["6.6.129-g548f960c059b-dirty".to_owned(), "6.1.0".to_owned()];
    let name = "Linux-6.6.129-g548f960c059b-dirt";
    assert_eq!(name.len(), 32);
    assert_eq!(resolve_release(Some(name), Some("6.6.129-g548f960c059b-dirt"), &modules).as_deref(), Some("6.6.129-g548f960c059b-dirty"));
    // A short name is taken as it is, and an ambiguous prefix is not guessed.
    assert_eq!(resolve_release(Some("Linux-6.6"), Some("6.6"), &modules).as_deref(), Some("6.6"));
    let two = vec!["6.6.129-a1".to_owned(), "6.6.129-a2".to_owned()];
    assert_eq!(resolve_release(Some("Linux-6.6.129-aaaaaaaaaaaaaaaaaaaa"), Some("6.6.129-a"), &two).as_deref(), Some("6.6.129-a"));
}

#[test]
fn crc32_matches_the_standard_check_value() {
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
}

#[test]
fn a_good_uimage_is_read_and_bad_ones_are_refused_with_a_reason() {
    let good = uimage("Linux-6.6.130-kaonic", b"zImage bytes");
    let info = check_kernel(&good).unwrap();
    assert_eq!((info.version.as_deref(), info.load_address.as_deref(), info.size), (Some("6.6.130-kaonic"), Some("0xc2008000"), good.len()));
    let mut damaged = good.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(check_kernel(&damaged).unwrap_err().contains("data checksum"));
    let mut header = good.clone();
    header[40] ^= 1;
    assert!(check_kernel(&header).unwrap_err().contains("header checksum"));
    let mut arm64 = uimage("Linux-6.6", b"x");
    arm64[29] = 22;
    let crc = {
        let mut h = arm64[..64].to_vec();
        h[4..8].fill(0);
        crc32(&h)
    };
    arm64[4..8].copy_from_slice(&crc.to_be_bytes());
    assert!(check_kernel(&arm64).unwrap_err().contains("ARM"));
    assert!(check_kernel(b"\x7fELF and so on, not an image at all, sixty-four bytes or more of it..").unwrap_err().contains("uImage"));
    assert!(check_kernel(&vec![0u8; KERNEL_MAX + 1]).unwrap_err().contains("larger"));
}

#[test]
fn a_device_tree_is_checked_and_its_model_shown() {
    let tree = dtb("Kaonic 1S r24");
    let info = check_dtb(&tree).unwrap();
    assert_eq!(info.name.as_deref(), Some("Kaonic 1S r24"));
    let mut short = tree.clone();
    short.pop();
    assert!(check_dtb(&short).is_err());
    assert!(check_dtb(&uimage("Linux-1", b"x")).unwrap_err().contains("device tree"));
}

#[test]
fn status_reads_slots_without_touching_the_running_one_read_only() {
    let fake = board();
    let state = status(&fake, Path::new(RUN)).unwrap();
    assert_eq!((state.current, state.next, state.once), (Some(Slot::A), Some(Slot::A), false));
    let a = &state.slots[0];
    assert!(a.bootable && a.dtb && a.attempts_left == Some(3));
    assert_eq!(a.kernel.as_ref().unwrap().version.as_deref(), Some("6.6.129"));
    assert_eq!(a.modules, vec!["6.6.129"]);
    let b = &state.slots[1];
    assert!(!b.bootfs && !b.rootfs && !b.bootable);
    // The running slot's boot partition is mounted with its own flags, never forced read-only.
    assert!(fake.commands().iter().any(|line| line == "mount /dev/disk/by-partlabel/bootfs_a /run/kaonic-hub/slot/inspect"));
}

#[test]
fn switching_to_an_empty_slot_is_refused() {
    let fake = board();
    let state = status(&fake, Path::new(RUN)).unwrap();
    let error = set_next(&fake, &state, Slot::B, Mode::Once).unwrap_err();
    assert!(error.contains("no system"));
    assert!(!fake.commands().iter().any(|line| line.starts_with("fw_setenv")));
}

#[test]
fn a_one_time_boot_comes_back_to_the_old_order_and_a_permanent_one_stays() {
    assert_eq!(
        switch_assignments(Slot::B, Mode::Once, &[Slot::A, Slot::B]),
        vec![("BOOT_ORDER", "B A".into()), ("BOOT_B_LEFT", "1".into()), ("kaonic_after_once", "A B".into())]
    );
    assert_eq!(
        switch_assignments(Slot::B, Mode::Permanent, &[Slot::A, Slot::B]),
        vec![("BOOT_ORDER", "B A".into()), ("BOOT_B_LEFT", "3".into()), ("kaonic_after_once", String::new())]
    );

    // Booted into B once: the hub puts "A B" back and clears the marker.
    let fake = board();
    *fake.files.lock().unwrap().get_mut(Path::new("/proc/cmdline")).unwrap() = b"kaonic.slot=b".to_vec();
    for (name, value) in switch_assignments(Slot::B, Mode::Once, &[Slot::A, Slot::B]) {
        fake.env.lock().unwrap().insert(name.into(), value);
    }
    assert!(after_start(&fake).is_some());
    let env = fake.env.lock().unwrap().clone();
    assert_eq!(env.get("BOOT_ORDER").map(String::as_str), Some("A B"));
    assert!(!env.contains_key("kaonic_after_once"));
    // Nothing pending: nothing changes.
    assert!(after_start(&fake).is_none());
}

#[test]
fn fell_back_after_a_failed_one_time_boot_keeps_the_marker_for_the_next_try() {
    let fake = board();
    for (name, value) in switch_assignments(Slot::B, Mode::Once, &[Slot::A, Slot::B]) {
        fake.env.lock().unwrap().insert(name.into(), value);
    }
    // Still running A (B failed): not the slot the order names first, so the hub leaves it.
    assert!(after_start(&fake).is_none());
}

#[test]
fn installing_prepares_an_empty_slot_from_the_running_one_and_never_writes_the_running_slot() {
    let fake = board();
    let state = status(&fake, Path::new(RUN)).unwrap();
    let kernel = uimage("Linux-6.6.129", b"new kernel");
    let info = check_kernel(&kernel).unwrap();
    let tree = dtb("Kaonic");
    // The copied system will have the running kernel's modules.
    let mut fake = fake;
    fake.files.get_mut().unwrap().insert("/run/kaonic-hub/slot/root/lib/modules/6.6.129".into(), Vec::new());

    let job = Install { kernel: Some((&kernel, info.clone())), dtb: Some(&tree), target: Slot::B, prepare: Prepare::Auto, allow_missing_modules: false };
    let report = install(&fake, Path::new(RUN), &state, &job, &|_, _| {}).unwrap();
    assert!(report.prepared);
    assert_eq!((report.kernel_file.as_deref(), report.dtb_file.as_deref(), report.modules_present), (Some("uImage-6.6.129"), Some("board.dtb"), Some(true)));
    let ran = fake.commands();
    let position = |needle: &str| ran.iter().position(|line| line.contains(needle)).unwrap_or_else(|| panic!("{needle} not run: {ran:#?}"));
    assert!(position("mkfs.ext4 -F -q -L bootfs /dev/disk/by-partlabel/bootfs_b") < position("cp -a /run/kaonic-hub/slot/src-root/."));
    assert!(position("write /run/kaonic-hub/slot/boot/uImage-6.6.129") < position("umount /run/kaonic-hub/slot/boot"));
    assert!(ran.iter().any(|line| line == "ln uImage-6.6.129 /run/kaonic-hub/slot/boot/uImage"));
    // Nothing formats or mounts slot A for writing.
    assert!(!ran.iter().any(|line| line.contains("mkfs") && line.ends_with("_a")));
    // Everything mounted is unmounted again.
    let mounted = ran.iter().filter(|line| line.starts_with("mount ")).count();
    let unmounted = ran.iter().filter(|line| line.starts_with("umount ")).count();
    assert_eq!(mounted, unmounted);
}

#[test]
fn a_kernel_without_its_modules_is_refused_unless_confirmed_and_the_slot_is_unmounted() {
    let fake = board();
    let state = status(&fake, Path::new(RUN)).unwrap();
    let kernel = uimage("Linux-6.7.0", b"other release");
    let info = check_kernel(&kernel).unwrap();
    let job = Install { kernel: Some((&kernel, info.clone())), dtb: None, target: Slot::B, prepare: Prepare::Auto, allow_missing_modules: false };
    let error = install(&fake, Path::new(RUN), &state, &job, &|_, _| {}).unwrap_err();
    assert!(error.contains("6.7.0"));
    let ran = fake.commands();
    assert_eq!(ran.iter().filter(|line| line.starts_with("mount ")).count(), ran.iter().filter(|line| line.starts_with("umount ")).count());
    assert!(!ran.iter().any(|line| line.starts_with("write")));

    let confirmed = Install { allow_missing_modules: true, ..job };
    assert_eq!(install(&fake, Path::new(RUN), &state, &confirmed, &|_, _| {}).unwrap().modules_present, Some(false));
}

#[test]
fn the_running_slot_and_an_empty_install_are_refused() {
    let fake = board();
    let state = status(&fake, Path::new(RUN)).unwrap();
    let kernel = uimage("Linux-6.6.129", b"k");
    let info = check_kernel(&kernel).unwrap();
    let running = Install { kernel: Some((&kernel, info)), dtb: None, target: Slot::A, prepare: Prepare::Auto, allow_missing_modules: true };
    assert!(install(&fake, Path::new(RUN), &state, &running, &|_, _| {}).unwrap_err().contains("never written"));
    let empty = Install { kernel: None, dtb: None, target: Slot::B, prepare: Prepare::Auto, allow_missing_modules: true };
    assert!(install(&fake, Path::new(RUN), &state, &empty, &|_, _| {}).unwrap_err().contains("Nothing"));
    let never = Install { kernel: None, dtb: Some(&dtb("x")), target: Slot::B, prepare: Prepare::Never, allow_missing_modules: true };
    assert!(install(&fake, Path::new(RUN), &state, &never, &|_, _| {}).unwrap_err().contains("no system yet"));
}

#[test]
fn a_failed_copy_unmounts_everything() {
    let mut fake = board();
    fake.fail = Some("cp -a /run/kaonic-hub/slot/src-root");
    let state = status(&fake, Path::new(RUN)).unwrap();
    let job = Install { kernel: None, dtb: Some(&dtb("x")), target: Slot::B, prepare: Prepare::Auto, allow_missing_modules: true };
    assert!(install(&fake, Path::new(RUN), &state, &job, &|_, _| {}).is_err());
    let ran = fake.commands();
    assert_eq!(ran.iter().filter(|line| line.starts_with("mount ")).count(), ran.iter().filter(|line| line.starts_with("umount ")).count());
}

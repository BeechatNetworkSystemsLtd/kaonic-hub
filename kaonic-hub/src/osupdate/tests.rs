use std::path::PathBuf;

use super::*;

const MACHINE: &str = "stm32mp1-kaonic1s-r30";
const BOOTFS: &str = "kaonic-st-image-core-openstlinux-weston-stm32mp1-kaonic1s-r30.splitted-bootfs.ext4";
const ROOTFS: &str = "kaonic-st-image-core-openstlinux-weston-stm32mp1-kaonic1s-r30.splitted-rootfs.ext4";

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kaonic-osupdate-{}", crate::random::hex(&crate::random::bytes::<8>().unwrap())));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha(data: &[u8]) -> String {
    crate::random::hex(&Sha256::digest(data))
}

fn manifest_for(files: &[(&str, &[u8])], machine: &str, boot_device: &str) -> String {
    let mut text = format!("schema = 1\nmachine = \"{machine}\"\nsoc = \"STM32MP151A\"\nboot_device = \"{boot_device}\"\nversion = \"0.3.4\"\nbuilt = \"2026-11-27T10:00:00Z\"\n");
    for (path, data) in files {
        text += &format!("\n[[files]]\npath = \"{path}\"\nsize = {}\nsha256 = \"{}\"\n", data.len(), sha(data));
    }
    text
}

/// A bundle made the way the image build makes it: `tar czf` of a directory, `./` paths.
fn bundle(dir: &Path, files: &[(&str, Vec<u8>)], manifest: &str) -> PathBuf {
    let content = dir.join("content");
    std::fs::create_dir_all(content.join("fip")).unwrap();
    for (path, data) in files {
        std::fs::write(content.join(path), data).unwrap();
    }
    std::fs::write(content.join("manifest.toml"), manifest).unwrap();
    let out = dir.join("image.tar.gz");
    let status = Command::new("tar").args(["czf"]).arg(&out).arg("-C").arg(&content).arg(".").env("COPYFILE_DISABLE", "1").status().unwrap();
    assert!(status.success());
    out
}

fn sample(dir: &Path) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let bootfs: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let rootfs: Vec<u8> = (0..1_500_000u32).map(|i| (i % 241) as u8).collect();
    let fip = b"fip".to_vec();
    let listed: Vec<(&str, &[u8])> = vec![(BOOTFS, &bootfs), (ROOTFS, &rootfs), ("fip/fip.bin", &fip)];
    let manifest = manifest_for(&listed, MACHINE, "emmc");
    let path = bundle(dir, &[(BOOTFS, bootfs.clone()), (ROOTFS, rootfs.clone()), ("fip/fip.bin", fip)], &manifest);
    (path, bootfs, rootfs)
}

#[test]
fn reads_the_manifest_of_a_release_bundle() {
    let manifest = parse_manifest(&manifest_for(&[(BOOTFS, b"boot"), (ROOTFS, b"root")], MACHINE, "emmc")).unwrap();
    assert_eq!(manifest.schema, 1);
    assert_eq!(manifest.version, "0.3.4");
    assert_eq!(manifest.files.len(), 2);
    assert_eq!(manifest.files[1], FileEntry { path: ROOTFS.into(), size: 4, sha256: sha(b"root") });
    let checked = compatible(&manifest, Some(MACHINE), "emmc").unwrap();
    assert_eq!(checked.bootfs.path, BOOTFS);
    assert_eq!(checked.rootfs.path, ROOTFS);
}

#[test]
fn a_bundle_for_another_board_or_boot_device_is_refused() {
    let files: &[(&str, &[u8])] = &[(BOOTFS, b"boot"), (ROOTFS, b"root")];
    let other = parse_manifest(&manifest_for(files, "stm32mp1-kaonic1s-r24", "emmc")).unwrap();
    assert!(compatible(&other, Some(MACHINE), "emmc").unwrap_err().contains("kaonic1s-r24"));
    let sdcard = parse_manifest(&manifest_for(files, MACHINE, "sdcard")).unwrap();
    assert!(compatible(&sdcard, Some(MACHINE), "emmc").unwrap_err().contains("-emmc.tar.gz"));
    assert!(compatible(&sdcard, Some(MACHINE), "sdcard").is_ok(), "an SD card board takes the SD card bundle");
    let emmc = parse_manifest(&manifest_for(files, MACHINE, "emmc")).unwrap();
    assert!(compatible(&emmc, Some(MACHINE), "sdcard").unwrap_err().contains("-sdcard-usb.tar.gz"));
    let no_rootfs = parse_manifest(&manifest_for(&[(BOOTFS, b"boot")], MACHINE, "emmc")).unwrap();
    assert!(compatible(&no_rootfs, Some(MACHINE), "emmc").unwrap_err().contains("rootfs"));
    assert!(compatible(&other, None, "emmc").is_err(), "an unknown machine takes nothing");
}

#[test]
fn versions_compare_by_number() {
    use std::cmp::Ordering::*;
    assert_eq!(compare_versions("0.10.0", "0.9.3"), Greater);
    assert_eq!(compare_versions("0.3.3", "0.3.3"), Equal);
    assert_eq!(compare_versions("0.3.2", "0.3.3"), Less);
}

#[test]
fn a_good_bundle_checks_and_its_images_are_written_and_read_back() {
    let dir = scratch();
    let (path, bootfs, rootfs) = sample(&dir);
    let checked = check(&path, Some(MACHINE), "emmc", &|_| {}).unwrap();
    assert_eq!(checked.version, "0.3.4");
    // Partitions larger than their images, with old data past the end.
    let (boot_dev, root_dev) = (dir.join("bootfs_b"), dir.join("rootfs_b"));
    std::fs::write(&boot_dev, vec![0xAA; 400_000]).unwrap();
    std::fs::write(&root_dev, vec![0xAA; 2_000_000]).unwrap();
    let steps = std::sync::Mutex::new(Vec::new());
    write_images(&path, &checked, Target::Device(boot_dev.to_str().unwrap()), Target::Device(root_dev.to_str().unwrap()), &|done, _| steps.lock().unwrap().push(done)).unwrap();
    assert_eq!(&std::fs::read(&boot_dev).unwrap()[..bootfs.len()], &bootfs[..]);
    assert_eq!(&std::fs::read(&root_dev).unwrap()[..rootfs.len()], &rootfs[..]);
    let steps = steps.into_inner().unwrap();
    assert!(steps.windows(2).all(|pair| pair[0] <= pair[1]), "progress only goes forward");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_partition_too_small_is_refused_before_anything_is_written() {
    let dir = scratch();
    let (path, _, _) = sample(&dir);
    let checked = check(&path, Some(MACHINE), "emmc", &|_| {}).unwrap();
    let (boot_dev, root_dev) = (dir.join("bootfs_b"), dir.join("rootfs_b"));
    std::fs::write(&boot_dev, vec![0xAA; 400_000]).unwrap();
    std::fs::write(&root_dev, vec![0xAA; 1000]).unwrap();
    let error = write_images(&path, &checked, Target::Device(boot_dev.to_str().unwrap()), Target::Device(root_dev.to_str().unwrap()), &|_, _| {}).unwrap_err();
    assert!(error.contains("does not fit"), "{error}");
    assert_eq!(std::fs::read(&boot_dev).unwrap(), vec![0xAA; 400_000], "nothing written");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_damaged_or_foreign_file_is_refused() {
    let dir = scratch();
    let bootfs = vec![1u8; 1000];
    let rootfs = vec![2u8; 1000];
    // The manifest promises other content than the bundle has.
    let manifest = manifest_for(&[(BOOTFS, &bootfs), (ROOTFS, b"something else")], MACHINE, "emmc");
    let path = bundle(&dir, &[(BOOTFS, bootfs), (ROOTFS, rootfs)], &manifest);
    assert!(check(&path, Some(MACHINE), "emmc", &|_| {}).unwrap_err().contains("damaged"));

    let truncated = dir.join("truncated.tar.gz");
    let data = std::fs::read(&path).unwrap();
    std::fs::write(&truncated, &data[..data.len() / 2]).unwrap();
    assert!(check(&truncated, Some(MACHINE), "emmc", &|_| {}).is_err());

    let text = dir.join("notes.tar.gz");
    std::fs::write(&text, b"hello").unwrap();
    assert!(check(&text, Some(MACHINE), "emmc", &|_| {}).unwrap_err().contains("not a Kaonic image bundle"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_boot_storage_is_read_from_the_disk() {
    assert_eq!(disk_of("mmcblk0p11"), "mmcblk0");
    assert_eq!(disk_of("mmcblk1p3"), "mmcblk1");
    assert_eq!(disk_of("mmcblk1"), "mmcblk1");
    assert_eq!(storage_name("SD\n"), Some("sdcard"));
    assert_eq!(storage_name("MMC"), Some("emmc"));
    assert_eq!(storage_name("SDIO"), None);
}

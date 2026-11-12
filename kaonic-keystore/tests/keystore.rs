use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use kaonic_keystore::{
    CopyState, DeviceKey, Error, KdfParams, KeyProvider, Keystore, Passphrase, RawKey, Secret,
};

/// A private temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "kaonic-keystore-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn store(&self) -> PathBuf {
        self.0.join("keystore")
    }

    fn mirror(&self) -> PathBuf {
        self.0.join("keystore.mirror")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn key(byte: u8) -> RawKey {
    RawKey::from_bytes(&[byte; 32])
}

/// Cheap Argon2 parameters so the tests stay fast.
fn passphrase(p: &str) -> Passphrase {
    Passphrase::with_params(
        p,
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        },
    )
}

/// A store at `dir` holding `a = v`, closed again.
fn seeded(dir: &TempDir, v: &str) {
    Keystore::create(dir.store(), &key(1))
        .unwrap()
        .set("a", v)
        .unwrap();
}

/// Primary-file bytes after writing `a = old`, then after `a = new`.
fn old_and_new(dir: &TempDir) -> (Vec<u8>, Vec<u8>) {
    seeded(dir, "old");
    let old = fs::read(dir.store()).unwrap();
    Keystore::open(dir.store(), &key(1))
        .unwrap()
        .set("a", "new")
        .unwrap();
    (old, fs::read(dir.store()).unwrap())
}

fn value<'a>(ks: &'a Keystore, name: &str) -> &'a [u8] {
    ks.get(name).expect("entry present").expose()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn flip_last_byte(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    *bytes.last_mut().unwrap() ^= 0x01;
    fs::write(path, bytes).unwrap();
}

#[test]
fn roundtrip_persists_entries() {
    let dir = TempDir::new();
    {
        let mut ks = Keystore::create(dir.store(), &key(1)).unwrap();
        ks.set("mesh/identity", vec![7u8; 64]).unwrap();
        ks.set("wifi/home", "hunter2").unwrap();
        ks.set("wifi/office", String::from("s3cret")).unwrap();
        assert!(ks.remove("wifi/office").unwrap());
        assert!(!ks.remove("wifi/office").unwrap());
    }
    let ks = Keystore::open(dir.store(), &key(1)).unwrap();
    assert_eq!(value(&ks, "mesh/identity"), &[7u8; 64]);
    assert_eq!(ks.get("wifi/home").unwrap().expose_str(), Some("hunter2"));
    assert!(ks.get("wifi/office").is_none());
    assert_eq!(
        ks.names().collect::<Vec<_>>(),
        ["mesh/identity", "wifi/home"]
    );
    assert!(ks.recovery().is_none());
    assert!(ks.degraded().is_none());
}

#[test]
fn files_are_private_and_mirrored() {
    let dir = TempDir::new();
    let mut ks = Keystore::create(dir.store(), &key(1)).unwrap();
    ks.set("a", "1").unwrap();
    assert_eq!(mode(&dir.store()), 0o600);
    assert_eq!(mode(&dir.mirror()), 0o600);
    assert_eq!(
        fs::read(dir.store()).unwrap(),
        fs::read(dir.mirror()).unwrap()
    );
}

#[test]
fn names_and_values_are_not_in_the_file() {
    let dir = TempDir::new();
    let mut ks = Keystore::create(dir.store(), &key(1)).unwrap();
    ks.set("wifi/home", "plaintext-password").unwrap();
    let bytes = fs::read(dir.store()).unwrap();
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(b"wifi/home"));
    assert!(!contains(b"plaintext-password"));
}

#[test]
fn create_refuses_existing_store() {
    let dir = TempDir::new();
    drop(Keystore::create(dir.store(), &key(1)).unwrap());
    assert!(matches!(
        Keystore::create(dir.store(), &key(1)),
        Err(Error::AlreadyExists(_))
    ));
    fs::remove_file(dir.store()).unwrap();
    // The mirror alone still counts as an existing store.
    assert!(matches!(
        Keystore::create(dir.store(), &key(1)),
        Err(Error::AlreadyExists(_))
    ));
}

#[test]
fn wrong_raw_key_is_rejected() {
    let dir = TempDir::new();
    seeded(&dir, "1");
    assert!(matches!(
        Keystore::open(dir.store(), &key(2)),
        Err(Error::WrongKey)
    ));
}

#[test]
fn wrong_passphrase_is_rejected() {
    let dir = TempDir::new();
    Keystore::create(dir.store(), &passphrase("right")).unwrap();
    assert!(matches!(
        Keystore::open(dir.store(), &passphrase("wrong")),
        Err(Error::WrongKey)
    ));
    assert!(Keystore::open(dir.store(), &passphrase("right")).is_ok());
}

#[test]
fn passphrase_store_opens_with_default_params_provider() {
    // The KDF parameters come from the file, not from the provider used to open it.
    let dir = TempDir::new();
    Keystore::create(dir.store(), &passphrase("pw"))
        .unwrap()
        .set("a", "1")
        .unwrap();
    let ks = Keystore::open(dir.store(), &Passphrase::new("pw")).unwrap();
    assert_eq!(value(&ks, "a"), b"1");
}

#[test]
fn provider_kind_must_match() {
    let dir = TempDir::new();
    Keystore::create(dir.store(), &key(1)).unwrap();
    match Keystore::open(dir.store(), &passphrase("x")) {
        Err(Error::ProviderMismatch { expected, found }) => {
            assert_eq!(expected, "argon2id");
            assert_eq!(found, "raw");
        }
        other => panic!("expected ProviderMismatch, got {other:?}"),
    }
}

#[test]
fn wrong_key_never_destroys_the_store() {
    let dir = TempDir::new();
    Keystore::create(dir.store(), &key(1))
        .unwrap()
        .set("mesh/identity", "id")
        .unwrap();
    let before = fs::read(dir.store()).unwrap();
    assert!(matches!(
        Keystore::open_or_create(dir.store(), &key(2)),
        Err(Error::WrongKey)
    ));
    assert_eq!(fs::read(dir.store()).unwrap(), before);
    assert_eq!(fs::read(dir.mirror()).unwrap(), before);
}

#[test]
fn damaged_primary_is_repaired_from_mirror() {
    let dir = TempDir::new();
    seeded(&dir, "1");
    flip_last_byte(&dir.store());

    let ks = Keystore::open(dir.store(), &key(1)).unwrap();
    assert_eq!(value(&ks, "a"), b"1");
    let recovery = ks.recovery().unwrap();
    assert!(matches!(recovery.primary, CopyState::Damaged(_)));
    assert_eq!(recovery.mirror, CopyState::Current);
    assert_eq!(
        fs::read(dir.store()).unwrap(),
        fs::read(dir.mirror()).unwrap()
    );
}

#[test]
fn damaged_header_is_repaired_from_mirror() {
    let dir = TempDir::new();
    seeded(&dir, "1");
    let mut bytes = fs::read(dir.mirror()).unwrap();
    bytes[20] ^= 0x80; // inside the wrapped data key
    fs::write(dir.mirror(), bytes).unwrap();

    let ks = Keystore::open(dir.store(), &key(1)).unwrap();
    assert_eq!(value(&ks, "a"), b"1");
    assert!(matches!(
        ks.recovery().unwrap().mirror,
        CopyState::Damaged(_)
    ));
}

#[test]
fn missing_primary_is_restored() {
    let dir = TempDir::new();
    seeded(&dir, "1");
    fs::remove_file(dir.store()).unwrap();

    let ks = Keystore::open_or_create(dir.store(), &key(1)).unwrap();
    assert_eq!(value(&ks, "a"), b"1");
    assert_eq!(ks.recovery().unwrap().primary, CopyState::Missing);
    assert!(dir.store().exists());
}

#[test]
fn both_copies_damaged_is_an_error_not_a_reset() {
    let dir = TempDir::new();
    seeded(&dir, "1");
    flip_last_byte(&dir.store());
    flip_last_byte(&dir.mirror());
    let before = fs::read(dir.store()).unwrap();
    assert!(matches!(
        Keystore::open_or_create(dir.store(), &key(1)),
        Err(Error::Tampered)
    ));
    assert_eq!(fs::read(dir.store()).unwrap(), before);
}

/// Power cut after the primary was committed but before the mirror was written.
#[test]
fn stale_mirror_is_brought_forward() {
    let dir = TempDir::new();
    let (old, _) = old_and_new(&dir);
    fs::write(dir.mirror(), old).unwrap();

    let ks = Keystore::open(dir.store(), &key(1)).unwrap();
    assert_eq!(value(&ks, "a"), b"new");
    assert!(matches!(
        ks.recovery().unwrap().mirror,
        CopyState::Stale { .. }
    ));
    assert_eq!(
        fs::read(dir.store()).unwrap(),
        fs::read(dir.mirror()).unwrap()
    );
}

/// A rolled-back primary (e.g. restored from an old image) loses to a newer mirror.
#[test]
fn newest_copy_wins_whichever_it_is() {
    let dir = TempDir::new();
    let (old, _) = old_and_new(&dir);
    fs::write(dir.store(), old).unwrap();

    let ks = Keystore::open(dir.store(), &key(1)).unwrap();
    assert_eq!(value(&ks, "a"), b"new");
    assert!(matches!(
        ks.recovery().unwrap().primary,
        CopyState::Stale { .. }
    ));
}

/// Simulate a write torn at every possible length, without the rename protocol's help
/// (as a misbehaving flash controller might): the store must always open.
#[test]
fn every_torn_primary_recovers() {
    let dir = TempDir::new();
    let (old, new) = old_and_new(&dir);

    for len in 0..new.len() {
        fs::write(dir.store(), &new[..len]).unwrap();
        fs::write(dir.mirror(), &old).unwrap();
        let ks = Keystore::open(dir.store(), &key(1))
            .unwrap_or_else(|e| panic!("torn at {len} bytes: {e}"));
        assert_eq!(value(&ks, "a"), b"old", "torn at {len} bytes");
    }
}

#[test]
fn leftover_temp_file_is_ignored_then_replaced() {
    let dir = TempDir::new();
    seeded(&dir, "1");
    let tmp = dir.0.join("keystore.tmp");
    fs::write(&tmp, b"half a write").unwrap();
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();

    let mut ks = Keystore::open(dir.store(), &key(1)).unwrap();
    assert_eq!(value(&ks, "a"), b"1");
    assert!(ks.recovery().is_none());
    ks.set("b", "2").unwrap();
    assert!(!tmp.exists());
    assert_eq!(mode(&dir.store()), 0o600);
}

#[test]
fn missing_store_is_not_found() {
    let dir = TempDir::new();
    assert!(matches!(
        Keystore::open(dir.store(), &key(1)),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn second_open_is_locked_out() {
    let dir = TempDir::new();
    let _ks = Keystore::create(dir.store(), &key(1)).unwrap();
    assert!(matches!(
        Keystore::open(dir.store(), &key(1)),
        Err(Error::Locked(_))
    ));
}

#[test]
fn world_writable_directory_is_refused() {
    let dir = TempDir::new();
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        Keystore::create(dir.store(), &key(1)),
        Err(Error::Insecure { .. })
    ));
}

#[test]
fn readable_copy_is_treated_as_damaged_and_rewritten() {
    let dir = TempDir::new();
    seeded(&dir, "1");
    fs::set_permissions(dir.store(), fs::Permissions::from_mode(0o644)).unwrap();

    let ks = Keystore::open(dir.store(), &key(1)).unwrap();
    assert!(matches!(
        ks.recovery().unwrap().primary,
        CopyState::Damaged(_)
    ));
    assert_eq!(mode(&dir.store()), 0o600);
}

#[test]
fn symlinked_copy_is_never_followed() {
    let dir = TempDir::new();
    seeded(&dir, "1");
    let elsewhere = dir.0.join("elsewhere");
    fs::write(&elsewhere, b"not touched").unwrap();
    fs::remove_file(dir.store()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.store()).unwrap();

    let mut ks = Keystore::open(dir.store(), &key(1)).unwrap();
    assert!(matches!(
        ks.recovery().unwrap().primary,
        CopyState::Damaged(_)
    ));
    ks.set("b", "2").unwrap();
    assert!(
        !fs::symlink_metadata(dir.store())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&elsewhere).unwrap(), b"not touched");
}

#[test]
fn rekey_switches_provider() {
    let dir = TempDir::new();
    {
        let mut ks = Keystore::create(dir.store(), &key(1)).unwrap();
        ks.set("a", "1").unwrap();
        ks.rekey(&passphrase("pw")).unwrap();
        assert_eq!(ks.provider_kind(), "argon2id");
    }
    assert!(matches!(
        Keystore::open(dir.store(), &key(1)),
        Err(Error::ProviderMismatch { .. })
    ));
    let mut ks = Keystore::open(dir.store(), &passphrase("pw")).unwrap();
    assert_eq!(value(&ks, "a"), b"1");
    ks.rekey(&key(3)).unwrap();
    drop(ks);
    assert!(matches!(
        Keystore::open(dir.store(), &key(1)),
        Err(Error::WrongKey)
    ));
    assert_eq!(
        value(&Keystore::open(dir.store(), &key(3)).unwrap(), "a"),
        b"1"
    );
}

#[test]
fn get_or_generate_is_stable() {
    let dir = TempDir::new();
    let first = {
        let mut ks = Keystore::create(dir.store(), &key(1)).unwrap();
        let id = ks.get_or_generate("mesh/identity", 64).unwrap();
        assert_eq!(id.len(), 64);
        id.expose().to_vec()
    };
    let mut ks = Keystore::open(dir.store(), &key(1)).unwrap();
    assert_eq!(
        ks.get_or_generate("mesh/identity", 64).unwrap().expose(),
        first
    );
}

#[test]
fn names_are_validated_and_listed_by_prefix() {
    let dir = TempDir::new();
    let mut ks = Keystore::create(dir.store(), &key(1)).unwrap();
    for bad in [
        "",
        "/a",
        "a/",
        "a//b",
        "A",
        "a b",
        "../x",
        "a/./b",
        &"x".repeat(129),
    ] {
        assert!(
            matches!(ks.set(bad, "v"), Err(Error::InvalidName(_))),
            "{bad:?}"
        );
    }
    for good in [
        "wifi/home",
        "wifi/office",
        "wifi-ap/psk",
        "plugin/atak-bridge/token",
    ] {
        ks.set(good, "v").unwrap();
    }
    assert_eq!(
        ks.names_under("wifi").collect::<Vec<_>>(),
        ["wifi/home", "wifi/office"]
    );
    assert_eq!(ks.names_under("plugin/").count(), 1);
}

#[test]
fn raw_key_file_roundtrip_and_permissions() {
    let dir = TempDir::new();
    let path = dir.0.join("keystore.key");
    let generated = RawKey::generate_file(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert!(matches!(RawKey::generate_file(&path), Err(Error::Io(_))));

    Keystore::create(dir.store(), &generated)
        .unwrap()
        .set("a", "1")
        .unwrap();
    let loaded = RawKey::load(&path).unwrap();
    assert_eq!(
        value(&Keystore::open(dir.store(), &loaded).unwrap(), "a"),
        b"1"
    );

    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(RawKey::load(&path), Err(Error::Insecure { .. })));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, [0u8; 31]).unwrap();
    assert!(RawKey::load(&path).is_err());
}

#[test]
fn secrets_are_redacted_in_debug_output() {
    let secret = Secret::from("hunter2");
    assert!(!format!("{secret:?}").contains("hunter2"));
    assert_eq!(format!("{:?}", key(0x41)), "RawKey([REDACTED])");
    assert!(!format!("{:?}", passphrase("hunter2")).contains("hunter2"));
}

#[test]
fn custom_provider_plugs_in() {
    /// A stand-in for a hardware backend: delegates to a RawKey under its own kind.
    struct Device(RawKey);
    impl KeyProvider for Device {
        fn kind(&self) -> &str {
            "device"
        }
        fn wrap(
            &self,
            dek: &kaonic_keystore::DataKey,
            aad: &[u8],
        ) -> kaonic_keystore::Result<Vec<u8>> {
            self.0.wrap(dek, aad)
        }
        fn unwrap(
            &self,
            blob: &[u8],
            aad: &[u8],
        ) -> kaonic_keystore::Result<kaonic_keystore::DataKey> {
            self.0.unwrap(blob, aad)
        }
    }
    let dir = TempDir::new();
    Keystore::create(dir.store(), &Device(key(9)))
        .unwrap()
        .set("a", "1")
        .unwrap();
    let ks = Keystore::open(dir.store(), &Device(key(9))).unwrap();
    assert_eq!(ks.provider_kind(), "device");
    drop(ks);
    // Same key, different kind: the kind is authenticated, not just compared.
    let r = Keystore::open(dir.store(), &key(9));
    assert!(matches!(r, Err(Error::ProviderMismatch { .. })), "{r:?}");
}

const UID: &[u8; 12] = b"\x2a\x00\x3b\x00\x13\x51\x31\x30\x33\x34\x37\x39";
const TOKEN: &[u8] = b"0123456789abcdef0123456789abcdef";

fn device(uid: &[u8], token: &[u8]) -> DeviceKey {
    DeviceKey::with_params(
        uid,
        token,
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .unwrap()
}

#[test]
fn device_key_needs_both_the_uid_and_the_token() {
    let dir = TempDir::new();
    Keystore::create(dir.store(), &device(UID, TOKEN))
        .unwrap()
        .set("mesh/identity", "id")
        .unwrap();

    let mut other_uid = *UID;
    other_uid[11] ^= 1;
    let mut other_token = TOKEN.to_vec();
    other_token[0] ^= 1;
    for wrong in [device(&other_uid, TOKEN), device(UID, &other_token)] {
        assert!(matches!(
            Keystore::open(dir.store(), &wrong),
            Err(Error::WrongKey)
        ));
    }
    let ks = Keystore::open(dir.store(), &device(UID, TOKEN)).unwrap();
    assert_eq!(value(&ks, "mesh/identity"), b"id");
    assert_eq!(ks.provider_kind(), "device-argon2id");
}

#[test]
fn device_key_rejects_blank_uid_and_short_token() {
    let fast = KdfParams::default();
    for blank in [&[0x00u8; 12], &[0xFFu8; 12]] {
        assert!(matches!(
            DeviceKey::with_params(blank, TOKEN, fast),
            Err(Error::Provider(_))
        ));
    }
    assert!(matches!(
        DeviceKey::with_params(&[], TOKEN, fast),
        Err(Error::Provider(_))
    ));
    assert!(matches!(
        DeviceKey::with_params(UID, &TOKEN[..15], fast),
        Err(Error::Provider(_))
    ));
}

#[test]
fn device_key_store_does_not_open_as_passphrase() {
    let dir = TempDir::new();
    Keystore::create(dir.store(), &device(UID, TOKEN)).unwrap();
    assert!(matches!(
        Keystore::open(dir.store(), &passphrase("anything")),
        Err(Error::ProviderMismatch { .. })
    ));
    assert_eq!(format!("{:?}", device(UID, TOKEN)), "DeviceKey([REDACTED])");
}

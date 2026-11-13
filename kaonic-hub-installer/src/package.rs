//! The plugin package: a tar of
//!
//! ```text
//! kaonic-plugin.toml   the manifest
//! SHA256SUMS           "<sha256>  <path>" for every other file, as sha256sum writes it
//! SHA256SUMS.sig       optional: ECDSA P-256 signature of SHA256SUMS (DER), by a release key
//! bin/<id>             the program
//! files/...            anything it ships with
//! ```
//!
//! Made with standard tools:
//!
//! ```sh
//! cd plugin && sha256sum kaonic-plugin.toml bin/* $(find files -type f) > SHA256SUMS
//! openssl dgst -sha256 -sign release.key -out SHA256SUMS.sig SHA256SUMS   # official only
//! tar -cf ../audio-ptt-0.3.0.kpkg .
//! ```
//!
//! The signature covers SHA256SUMS, which covers every file, so a signed package is signed
//! whole: manifest, program, arguments and files. Every file in the tar must be listed and
//! every listed file must be there.
//!
//! A device without a release key is a development device: it cannot check signatures, so
//! every package installs as unsigned, and nothing that needs a signature (`root`) is
//! refused for lack of one. With a key, a signature that does not check is refused.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

use crate::manifest::{self, Manifest, Permission};
use crate::{Error, names, tar};

pub const SUMS: &str = "SHA256SUMS";
pub const SIGNATURE: &str = "SHA256SUMS.sig";

/// What unpacking may cost, at most.
pub const BUDGET: tar::Budget = tar::Budget { bytes: 256 << 20, entries: 4096 };

/// A checked package, unpacked in a staging directory.
#[derive(Debug, Clone)]
pub struct Package {
    pub manifest: Manifest,
    /// Signed by one of the release keys.
    pub signed: bool,
    /// Every installed file (relative path → sha256), the manifest included.
    pub files: HashMap<String, String>,
}

/// Unpacks `archive` into the empty directory `staging` and checks it.
pub fn open(archive: &mut impl Read, staging: &Path, release_keys: &[Vec<u8>]) -> Result<Package, Error> {
    let unpacked = tar::unpack(archive, staging, BUDGET)?;
    check(staging, &unpacked, release_keys)
}

fn check(staging: &Path, unpacked: &[(String, u64)], release_keys: &[Vec<u8>]) -> Result<Package, Error> {
    let read = |name: &str, max: u64| -> Result<Vec<u8>, Error> {
        let size = unpacked.iter().find(|(path, _)| path == name).map(|(_, size)| *size);
        match size {
            None => Err(Error::invalid(format!("the package has no {name}"))),
            Some(size) if size > max => Err(Error::invalid(format!("{name} is too large"))),
            Some(_) => fs::read(staging.join(name)).map_err(Error::io(format!("reading {name}"))),
        }
    };
    let sums_bytes = read(SUMS, 256 * 1024)?;
    let development = release_keys.is_empty();
    let signed = match unpacked.iter().any(|(path, _)| path == SIGNATURE) {
        false => false,
        true if development => {
            log::info!("installer: no release key on this device; the package's signature is not checked");
            false
        }
        true => {
            let signature = read(SIGNATURE, 1024)?;
            if !release_keys.iter().any(|key| verify(key, &sums_bytes, &signature)) {
                return Err(Error::invalid("the package's signature does not match any Beechat release key"));
            }
            true
        }
    };

    let sums = std::str::from_utf8(&sums_bytes).map_err(|_| Error::invalid(format!("{SUMS} is not text")))?;
    let mut files = HashMap::new();
    for line in sums.lines().filter(|line| !line.trim().is_empty()) {
        let (hash, path) = line
            .split_once("  ")
            .or_else(|| line.split_once(" *"))
            .ok_or_else(|| Error::invalid(format!("{SUMS}: {line:?} is not \"<sha256>  <path>\"")))?;
        let path = path.trim_start_matches("./");
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::invalid(format!("{SUMS}: bad hash for {path}")));
        }
        names::relative_path(path)?;
        if path == SUMS || path == SIGNATURE {
            return Err(Error::invalid(format!("{SUMS} must not list itself or the signature")));
        }
        if files.insert(path.to_owned(), hash.to_ascii_lowercase()).is_some() {
            return Err(Error::invalid(format!("{SUMS} lists {path} twice")));
        }
    }
    for (path, _) in unpacked {
        if path != SUMS && path != SIGNATURE && !files.contains_key(path) {
            return Err(Error::invalid(format!("{path} is in the package but not in {SUMS}")));
        }
    }
    for (path, hash) in &files {
        if !unpacked.iter().any(|(unpacked, _)| unpacked == path) {
            return Err(Error::invalid(format!("{SUMS} lists {path}, which is not in the package")));
        }
        if &sha256_file(&staging.join(path))? != hash {
            return Err(Error::invalid(format!("{path} does not match its checksum; the package is damaged")));
        }
    }

    let manifest_text = String::from_utf8(read(manifest::FILE, 16 * 1024)?)
        .map_err(|_| Error::invalid(format!("{} is not UTF-8 text", manifest::FILE)))?;
    if !files.contains_key(manifest::FILE) {
        return Err(Error::invalid(format!("{SUMS} must list {}", manifest::FILE)));
    }
    let manifest = manifest::parse(&manifest_text)?;
    let program = manifest.program();
    if !files.contains_key(&program) {
        return Err(Error::invalid(format!("the package has no {program}")));
    }
    for path in files.keys() {
        if path != manifest::FILE && path != &program && !path.starts_with("files/") {
            return Err(Error::invalid(format!("{path}: a package holds {}, {program} and files/ only", manifest::FILE)));
        }
    }
    if let Some(icon) = &manifest.icon
        && !files.contains_key(icon)
    {
        return Err(Error::invalid(format!("the icon {icon} is not in the package")));
    }
    if manifest.has(Permission::Root) && !signed && !development {
        return Err(Error::forbidden("only a signed package may run as root"));
    }
    Ok(Package { manifest, signed, files })
}

pub fn sha256_file(path: &Path) -> Result<String, Error> {
    use sha2::Digest;
    let mut file = fs::File::open(path).map_err(Error::io(format!("reading {}", path.display())))?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(Error::io(format!("reading {}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(crate::hex(&hasher.finalize()))
}

/// Checks an ECDSA P-256 / SHA-256 signature (DER, as `openssl dgst -sha256 -sign` writes)
/// with a PEM public key, as `openssl dgst -sha256 -verify` would.
pub fn verify(key_pem: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // The fixed DER prefix of a P-256 SubjectPublicKeyInfo; the 65-byte point follows.
    const P256_SPKI: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let Ok(text) = std::str::from_utf8(key_pem) else { return false };
    let Some(spki) = pem_body(text, "PUBLIC KEY") else { return false };
    if spki.len() != 91 || spki[..26] != P256_SPKI {
        return false;
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, &spki[26..])
        .verify(message, signature)
        .is_ok()
}

fn pem_body(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = text.split_once(&begin)?.1.split_once(&end)?.0;
    kaonic_hub_common::base64::decode_loose(body)
}

/// Test helpers: build packages and release keys.
#[cfg(test)]
pub mod testing {
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    use super::*;

    pub const MANIFEST: &str = "[kaonic-plugin]\nformat = 2\nid = \"sample\"\nname = \"Sample\"\nversion = \"1.0.0\"\ndeveloper = \"Beechat\"\nicon = \"files/icon.png\"\n";

    pub struct Key {
        pair: EcdsaKeyPair,
    }

    impl Key {
        pub fn generate() -> Self {
            let random = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
            Self { pair: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random).unwrap() }
        }
        pub fn public_pem(&self) -> Vec<u8> {
            let mut spki = vec![
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            ];
            spki.extend_from_slice(self.pair.public_key().as_ref());
            format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", kaonic_hub_common::base64::encode(&spki)).into_bytes()
        }
        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.pair.sign(&SystemRandom::new(), message).unwrap().as_ref().to_vec()
        }
    }

    /// A package from (path, content) files, with SHA256SUMS made for it, signed by `key`.
    pub fn package(files: &[(&str, &[u8])], key: Option<&Key>) -> Vec<u8> {
        let sums: String = files.iter().map(|(path, data)| format!("{}  {path}\n", crate::sha256_hex(data))).collect();
        let mut all: Vec<(&str, Vec<u8>)> = files.iter().map(|(path, data)| (*path, data.to_vec())).collect();
        all.push((SUMS, sums.clone().into_bytes()));
        if let Some(key) = key {
            all.push((SIGNATURE, key.sign(sums.as_bytes())));
        }
        let refs: Vec<(&str, &[u8])> = all.iter().map(|(path, data)| (*path, data.as_slice())).collect();
        tar::write(&refs)
    }

    /// The sample plugin at `version`, with `manifest_extra` lines added to its manifest.
    pub fn sample(version: &str, manifest_extra: &str, key: Option<&Key>) -> Vec<u8> {
        let manifest = format!("{}{manifest_extra}", MANIFEST.replace("1.0.0", version));
        package(&[(manifest::FILE, manifest.as_bytes()), ("bin/sample", b"#!/bin/sh\nsleep 1000\n"), ("files/icon.png", b"png")], key)
    }

    pub fn staging() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("khi-pkg-{}-{}", std::process::id(), crate::hex(&crate::random::<6>().unwrap())));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn open_bytes(bytes: &[u8], keys: &[Vec<u8>]) -> Result<Package, Error> {
        open(&mut &bytes[..], &staging(), keys)
    }

    #[test]
    fn opens_signed_and_unsigned_packages() {
        let key = Key::generate();
        let keys = vec![key.public_pem()];
        let signed = open_bytes(&sample("1.0.0", "", Some(&key)), &keys).unwrap();
        assert!(signed.signed);
        assert_eq!(signed.manifest.id, "sample");
        assert_eq!(signed.files.len(), 3);
        assert!(!open_bytes(&sample("1.0.0", "", None), &keys).unwrap().signed);
    }

    #[test]
    fn a_wrong_signature_is_refused_not_ignored() {
        let key = Key::generate();
        let other = Key::generate();
        let error = open_bytes(&sample("1.0.0", "", Some(&other)), &[key.public_pem()]).unwrap_err();
        assert!(error.message.contains("signature"));
    }

    #[test]
    fn a_device_without_a_release_key_installs_everything_unsigned() {
        let key = Key::generate();
        let package = open_bytes(&sample("1.0.0", "", Some(&key)), &[]).unwrap();
        assert!(!package.signed, "a signature it cannot check does not count");
        let root = sample("1.0.0", "[service]\npermissions = \"root\"\n", None);
        assert!(open_bytes(&root, &[]).is_ok(), "development device: root needs no signature");
        assert!(open_bytes(&root, &[key.public_pem()]).is_err(), "with a key it does");
    }

    #[test]
    fn the_signature_covers_every_file() {
        let key = Key::generate();
        let keys = vec![key.public_pem()];
        // Swap the program after signing: its checksum no longer matches.
        let mut bytes = sample("1.0.0", "", Some(&key));
        let at = bytes.windows(5).position(|window| window == b"sleep").unwrap();
        bytes[at] = b'S';
        assert!(open_bytes(&bytes, &keys).is_err());
        // A file added without listing it.
        let manifest = MANIFEST.to_owned();
        let sums = format!("{}  {}\n{}  bin/sample\n", crate::sha256_hex(manifest.as_bytes()), manifest::FILE, crate::sha256_hex(b"p"));
        let tar = tar::write(&[
            (manifest::FILE, manifest.as_bytes()),
            ("bin/sample", b"p"),
            ("files/icon.png", b"png"),
            (SUMS, sums.as_bytes()),
        ]);
        assert!(open_bytes(&tar, &keys).unwrap_err().message.contains("not in SHA256SUMS"));
    }

    #[test]
    fn refuses_packages_that_reach_outside_their_layout() {
        let with_manifest = |manifest: &str| {
            package(&[(manifest::FILE, manifest.as_bytes()), ("bin/sample", b"p"), ("files/icon.png", b"png")], None)
        };
        assert!(open_bytes(&with_manifest(&MANIFEST.replace("id = \"sample\"", "id = \"other\"")), &[]).is_err(), "no bin/<id>");
        assert!(open_bytes(&with_manifest(&format!("{MANIFEST}[service]\npermissions = \"root\"\n")), &[Key::generate().public_pem()]).is_err(), "root unsigned");
        let stray = package(&[(manifest::FILE, MANIFEST.as_bytes()), ("bin/sample", b"p"), ("files/icon.png", b"png"), ("etc/x", b"x")], None);
        assert!(open_bytes(&stray, &[]).is_err(), "a file outside bin/ and files/");
    }

    #[test]
    fn reads_openssl_style_keys() {
        let key = Key::generate();
        assert!(verify(&key.public_pem(), b"m", &key.sign(b"m")));
        assert!(!verify(&key.public_pem(), b"m2", &key.sign(b"m")));
        assert!(!verify(b"not a key", b"m", &key.sign(b"m")));
    }
}

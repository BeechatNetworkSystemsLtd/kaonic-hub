//! Plugin ids, file names and paths a package may use.

use crate::Error;

/// Ids of the device's own software and system services: never plugins.
pub const RESERVED: &[&str] = &[
    "kaonic-hub",
    "kaonic-hub-installer",
    "kaonic-gateway",
    "kaonic-installer",
    "kaonic-commd",
    "kaonic-factory",
    "kaonic-init",
    "kaonic-slot-good",
    "kaonic-wifi-mode",
    "kaonic-plugin",
];

/// The device's own programs, updated with packages in the plugin format under one of these
/// ids: the installer updates the hub; the hub updates the installer, commd and the factory
/// server. None of them can be removed.
pub const CORE: &[&str] = &["kaonic-hub", "kaonic-hub-installer", "kaonic-commd", "kaonic-factory"];

/// Core programs that do not switch to their update themselves (they come from
/// kaonic-radio): their units start them through `kaonic-hub-installer run-core`.
pub const LAUNCHED: &[&str] = &["kaonic-commd", "kaonic-factory"];

pub fn is_launched(id: &str) -> bool {
    LAUNCHED.contains(&id)
}

pub fn is_core(id: &str) -> bool {
    CORE.contains(&id)
}

/// A plugin id: lowercase letters, digits and `-`, 2-48 long, starting with a letter.
/// It names the directory, the unit (`kaonic-plugin-<id>.service`), the user and the
/// command link, so it is kept narrow.
pub fn id(value: &str) -> Result<&str, Error> {
    let ok = (2..=48).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && !value.ends_with('-')
        && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !ok {
        return Err(Error::invalid(format!(
            "{value:?} is not a plugin id: use 2-48 lowercase letters, digits and '-', starting with a letter"
        )));
    }
    if RESERVED.contains(&value) || value.starts_with("kaonic-hub") || value.starts_with("system") {
        return Err(Error::invalid(format!("{value} is reserved for the device's own software")));
    }
    Ok(value)
}

/// An id from a request: a plugin id or a core id. Checked before it names a path.
pub fn path_id(value: &str) -> Result<&str, Error> {
    if is_core(value) { Ok(value) } else { id(value) }
}

/// A plugin's name on the mesh: the first 8 bytes of sha256(id), big-endian.
pub fn mesh_hash(id: &str) -> u64 {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(id.as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

/// One path segment: ASCII letters, digits, `.`, `_`, `-`; not hidden, not `.`/`..`.
pub fn file_name(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 100
        || value.starts_with('.')
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::invalid(format!("{value:?} is not a plain file name")));
    }
    Ok(())
}

/// A relative path of plain segments, at most 8 deep and 240 bytes.
pub fn relative_path(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 240 || value.split('/').count() > 8 {
        return Err(Error::invalid(format!("{value:?} is not a plain relative path")));
    }
    value.split('/').try_for_each(file_name)
}

/// A dotted version, `1`, `1.2`, `1.2.3` or `1.2.3.4`, compared number by number.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(Vec<u32>);

impl Version {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let parts: Option<Vec<u32>> = text
            .split('.')
            .map(|part| if part.is_empty() || part.len() > 9 || !part.bytes().all(|b| b.is_ascii_digit()) { None } else { part.parse().ok() })
            .collect();
        match parts {
            Some(mut parts) if (1..=4).contains(&parts.len()) => {
                while parts.len() > 1 && parts.last() == Some(&0) {
                    parts.pop();
                }
                Ok(Self(parts))
            }
            _ => Err(Error::invalid(format!("version {text:?} must be numbers separated by dots, like 1.4.2"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_narrow() {
        assert!(id("audio-ptt").is_ok());
        assert!(id("atak2").is_ok());
        for bad in ["", "a", "Audio", "-x", "x-", "a_b", "a.b", "a/b", "kaonic-hub", "kaonic-hub-x", "systemd-x", "kaonic-commd"] {
            assert!(id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn request_ids_are_plugin_or_core_ids() {
        assert!(path_id("kaonic-hub").is_ok() && path_id("sample").is_ok());
        for bad in ["../x", "a/b", "x%2Fy", "kaonic-init", ""] {
            assert!(path_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mesh_hash_is_the_start_of_sha256() {
        // sha256("sample") = af2bdbe1aa9b6ec1...
        assert_eq!(mesh_hash("sample"), 0xaf2bdbe1aa9b6ec1);
        assert_ne!(mesh_hash("sample"), mesh_hash("sample2"));
    }

    #[test]
    fn paths_stay_inside() {
        assert!(relative_path("files/icon.png").is_ok());
        for bad in ["", "/etc/passwd", "../x", "a/../b", "a//b", "a/.hidden", "./a", "a/b c"] {
            assert!(relative_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn versions_compare_by_number() {
        let v = |text| Version::parse(text).unwrap();
        assert!(v("1.10") > v("1.9"));
        assert_eq!(v("1.2.0"), v("1.2"));
        assert!(v("2") > v("1.99.99"));
        for bad in ["", "1.", "a", "1.2.3.4.5", "1.-2", "v1"] {
            assert!(Version::parse(bad).is_err(), "{bad}");
        }
    }
}

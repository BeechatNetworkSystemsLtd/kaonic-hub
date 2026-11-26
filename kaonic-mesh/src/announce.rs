//! What a hub says about itself in its Reticulum announce (the announce's app data).
//!
//! ```text
//! "KHN1" | flags u8 | [admin identity hash 16, if provisioned] | codename len u8 | codename | version len u8 | version
//!        | [0x01 | boot id u32 | uptime secs u32]
//! flags: 0x01 this node is the Kaonic Admin · 0x02 provisioned (certified by an admin)
//! ```
//! The boot id is random per start, so peers can tell a restarted hub from one that
//! announced again. Older hubs neither send nor read it.
//! Announces are signed by the node's identity, so this cannot be forged in
//! its name; it is still only a claim until the link's AUTH proves it.

const MAGIC: &[u8; 4] = b"KHN1";
const ADMIN: u8 = 0x01;
const PROVISIONED: u8 = 0x02;
const BOOT: u8 = 0x01;

/// Which start of the hub announced, and how long it had been running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Boot {
    pub id: u32,
    pub uptime_secs: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub codename: String,
    pub version: String,
    pub is_admin: bool,
    /// The admin this node is certified by: its own hash for the admin, None while unprovisioned.
    pub admin_id: Option<[u8; 16]>,
}

/// What kind of node sent an announce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Announced {
    Hub(NodeInfo),
    Unknown,
}

pub fn encode(info: &NodeInfo) -> Vec<u8> {
    encode_with_boot(info, None)
}

pub fn encode_with_boot(info: &NodeInfo, boot: Option<Boot>) -> Vec<u8> {
    let codename = truncate(&info.codename, 32);
    let version = truncate(&info.version, 32);
    let mut out = Vec::with_capacity(4 + 1 + 16 + 2 + codename.len() + version.len());
    out.extend_from_slice(MAGIC);
    let mut flags = 0;
    if info.is_admin {
        flags |= ADMIN;
    }
    if info.admin_id.is_some() {
        flags |= PROVISIONED;
    }
    out.push(flags);
    if let Some(admin) = info.admin_id {
        out.extend_from_slice(&admin);
    }
    out.push(codename.len() as u8);
    out.extend_from_slice(codename.as_bytes());
    out.push(version.len() as u8);
    out.extend_from_slice(version.as_bytes());
    if let Some(boot) = boot {
        out.push(BOOT);
        out.extend_from_slice(&boot.id.to_be_bytes());
        out.extend_from_slice(&boot.uptime_secs.to_be_bytes());
    }
    out
}

pub fn decode(data: &[u8]) -> Announced {
    let Some(rest) = data.strip_prefix(MAGIC) else { return Announced::Unknown };
    decode_hub(rest).map_or(Announced::Unknown, Announced::Hub)
}

/// The boot an announce carries, if it is a hub's that has one.
pub fn boot_of(data: &[u8]) -> Option<Boot> {
    let rest = data.strip_prefix(MAGIC)?;
    let (_, rest) = decode_fields(rest)?;
    let (&BOOT, rest) = rest.split_first()? else { return None };
    let (id, rest) = rest.split_first_chunk::<4>()?;
    let (uptime, _) = rest.split_first_chunk::<4>()?;
    Some(Boot { id: u32::from_be_bytes(*id), uptime_secs: u32::from_be_bytes(*uptime) })
}

fn decode_hub(data: &[u8]) -> Option<NodeInfo> {
    decode_fields(data).map(|(info, _)| info)
}

/// The node's fields and what follows them.
fn decode_fields(data: &[u8]) -> Option<(NodeInfo, &[u8])> {
    let (&flags, mut rest) = data.split_first()?;
    let admin_id = if flags & PROVISIONED != 0 {
        let (hash, tail) = rest.split_first_chunk::<16>()?;
        rest = tail;
        Some(*hash)
    } else {
        None
    };
    let (codename, rest) = text(rest)?;
    let (version, rest) = text(rest)?;
    Some((NodeInfo { codename, version, is_admin: flags & ADMIN != 0, admin_id }, rest))
}

fn text(data: &[u8]) -> Option<(String, &[u8])> {
    let (&length, rest) = data.split_first()?;
    let (bytes, rest) = rest.split_at_checked(length as usize)?;
    // Shown in the UI: printable characters only.
    let text: String = String::from_utf8_lossy(bytes).chars().filter(|c| !c.is_control()).collect();
    Some((text, rest))
}

fn truncate(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_anything_else() {
        let member = NodeInfo { codename: "kaon7qjt".into(), version: "0.1.0".into(), is_admin: false, admin_id: Some([7; 16]) };
        assert_eq!(decode(&encode(&member)), Announced::Hub(member));
        let fresh = NodeInfo { codename: "bench002".into(), version: "0.1.0".into(), is_admin: false, admin_id: None };
        assert_eq!(decode(&encode(&fresh)), Announced::Hub(fresh));
        assert_eq!(decode(b"kvpn\x02\x81\xa6routes\x90"), Announced::Unknown);
        assert_eq!(decode(b"KHN1\x02short"), Announced::Unknown);
        assert_eq!(decode(b""), Announced::Unknown);
    }

    #[test]
    fn the_boot_travels_after_the_fields_and_older_announces_have_none() {
        let info = NodeInfo { codename: "kaon7qjt".into(), version: "0.2.0".into(), is_admin: false, admin_id: Some([7; 16]) };
        let boot = Boot { id: 0xDEAD_BEEF, uptime_secs: 42 };
        let data = encode_with_boot(&info, Some(boot));
        assert_eq!(decode(&data), Announced::Hub(info.clone()), "older hubs read the fields and ignore the boot");
        assert_eq!(boot_of(&data), Some(boot));
        assert_eq!(boot_of(&encode(&info)), None);
        assert_eq!(boot_of(&data[..data.len() - 1]), None);
        assert_eq!(boot_of(b"kvpn\x02"), None);
    }

    #[test]
    fn control_characters_and_long_names_are_cleaned() {
        let info = NodeInfo { codename: "a\u{1b}[2Jb".into(), version: "x".repeat(100), is_admin: true, admin_id: Some([1; 16]) };
        let Announced::Hub(decoded) = decode(&encode(&info)) else { panic!() };
        assert_eq!(decoded.codename, "a[2Jb");
        assert_eq!(decoded.version.len(), 32);
    }
}

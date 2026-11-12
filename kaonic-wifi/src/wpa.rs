//! The wpa_supplicant (and hostapd) control interface protocol: requests and
//! the text it answers with. Pure parsing and encoding; [`crate::ctrl`] does the I/O.
//!
//! Reference: wpa_supplicant `ctrl_iface.c` and `wpa_ctrl.h` (hostap 2.10/2.11).

use crate::policy::{Problem, Security, Seen};

/// A network as wpa_supplicant numbers it in `LIST_NETWORKS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub id: u32,
    pub ssid: String,
}

/// The parts of `STATUS` the hub uses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// `COMPLETED` when associated and authenticated.
    pub wpa_state: String,
    pub ssid: Option<String>,
    pub id: Option<u32>,
    pub frequency_mhz: Option<u32>,
}

/// An unsolicited message after `ATTACH`, as far as the policy cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    ScanResults,
    ScanFailed,
    /// Associated and the key handshake done, on network `id`.
    Connected { id: Option<u32> },
    Disconnected { reason: Option<u16>, locally_generated: bool },
    /// wpa_supplicant gave up on network `id` for a while; `reason` says why.
    TempDisabled { id: Option<u32>, ssid: String, reason: String },
    NetworkNotFound,
    AssocReject { status_code: Option<u16> },
    AuthReject,
    Terminating,
    Other,
}

impl Notice {
    /// The problem this notice proves, if any. A single association or
    /// authentication reject proves nothing yet: wpa_supplicant retries, and
    /// gives up with `SSID-TEMP-DISABLED` when it is real.
    pub fn problem(&self) -> Option<Problem> {
        match self {
            Notice::TempDisabled { reason, .. } if reason == "WRONG_KEY" => Some(Problem::WrongPassword),
            Notice::TempDisabled { .. } => Some(Problem::Rejected),
            Notice::NetworkNotFound => Some(Problem::NotFound),
            _ => None,
        }
    }
}

/* ── encoding ── */

/// A string as wpa_supplicant's `SET_NETWORK` takes it: hex, unquoted. Hex
/// carries any byte, so a name or password can never break out of the command.
pub fn hex(value: &str) -> String {
    value.bytes().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether a value may be sent at all: wpa_supplicant commands are one line, and
/// the limits are the 802.11 ones.
pub fn valid_ssid(ssid: &str) -> bool {
    (1..=32).contains(&ssid.len())
}

/// WPA passphrases are 8 to 63 printable ASCII characters.
pub fn valid_passphrase(password: &str) -> bool {
    (8..=63).contains(&password.len()) && password.bytes().all(|byte| (0x20..0x7f).contains(&byte))
}

/// The `SET_NETWORK` commands for a network, after `ADD_NETWORK` returned `id`.
/// Secured networks accept WPA2 and WPA3 (SAE) with optional management frame
/// protection, so a network that moves to WPA3 still works.
pub fn network_commands(id: u32, ssid: &str, password: Option<&str>, hidden: bool) -> Vec<String> {
    let mut commands = vec![format!("SET_NETWORK {id} ssid {}", hex(ssid))];
    match password {
        Some(password) => {
            // `psk` given as a quoted passphrase is required for SAE; quotes are safe
            // because `valid_passphrase` allows no control characters, and `"` inside is
            // fine since wpa_supplicant reads up to the last quote.
            commands.push(format!("SET_NETWORK {id} key_mgmt WPA-PSK WPA-PSK-SHA256 SAE"));
            commands.push(format!("SET_NETWORK {id} psk \"{password}\""));
            commands.push(format!("SET_NETWORK {id} ieee80211w 1"));
        }
        None => commands.push(format!("SET_NETWORK {id} key_mgmt NONE")),
    }
    if hidden {
        commands.push(format!("SET_NETWORK {id} scan_ssid 1"));
    }
    // Added disabled: only `SELECT_NETWORK` ever enables one, so the hub alone chooses.
    commands.push(format!("DISABLE_NETWORK {id}"));
    commands
}

/* ── parsing ── */

/// Undoes wpa_supplicant's `printf_encode`: `\\`, `\"`, `\e`, `\n`, `\r`, `\t`, `\xNN`.
/// Returns None for a name that is not UTF-8, which the UI could not show anyway.
pub fn unescape(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut input = text.bytes();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        match input.next()? {
            b'n' => bytes.push(b'\n'),
            b'r' => bytes.push(b'\r'),
            b't' => bytes.push(b'\t'),
            b'e' => bytes.push(0x1b),
            b'x' => {
                let high = (input.next()? as char).to_digit(16)?;
                let low = (input.next()? as char).to_digit(16)?;
                bytes.push((high * 16 + low) as u8);
            }
            other => bytes.push(other),
        }
    }
    String::from_utf8(bytes).ok()
}

/// What the flags of a scan entry say about joining it. None for what the
/// device will not join: WEP, WPA1-only, and enterprise (802.1X) networks.
pub fn security(flags: &str) -> Option<Security> {
    let rsn = flags.contains("[WPA2-") || flags.contains("[RSN-");
    if flags.contains("SAE") && !flags.contains("PSK") {
        return Some(Security::Wpa3);
    }
    if rsn && flags.contains("PSK") {
        return Some(Security::Wpa2);
    }
    if flags.contains("WEP") || flags.contains("[WPA-") || flags.contains("EAP") || rsn {
        return None;
    }
    Some(Security::Open)
}

/// `SCAN_RESULTS`: a header, then `bssid \t frequency \t signal \t flags \t ssid` per line.
/// Hidden networks (empty name) and networks the device cannot join are left out.
pub fn parse_scan_results(text: &str) -> Vec<Seen> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.splitn(5, '\t');
            let _bssid = fields.next()?;
            let frequency_mhz = fields.next()?.trim().parse().ok()?;
            let signal_dbm = fields.next()?.trim().parse().ok()?;
            let security = security(fields.next()?)?;
            let ssid = unescape(fields.next()?)?;
            (!ssid.is_empty()).then_some(Seen { ssid, signal_dbm, security, frequency_mhz })
        })
        .collect()
}

/// `LIST_NETWORKS`: a header, then `id \t ssid \t bssid \t flags`.
pub fn parse_list_networks(text: &str) -> Vec<Listed> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let id = fields.next()?.trim().parse().ok()?;
            let ssid = unescape(fields.next()?)?;
            Some(Listed { id, ssid })
        })
        .collect()
}

/// `STATUS`: `key=value` lines.
pub fn parse_status(text: &str) -> Status {
    let mut status = Status::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        match key {
            "wpa_state" => status.wpa_state = value.to_owned(),
            "ssid" => status.ssid = unescape(value),
            "id" => status.id = value.parse().ok(),
            "freq" => status.frequency_mhz = value.parse().ok(),
            _ => {}
        }
    }
    status
}

/// `SIGNAL_POLL`: the `RSSI=` line, in dBm.
pub fn parse_signal(text: &str) -> Option<i32> {
    text.lines().find_map(|line| line.strip_prefix("RSSI=")?.parse().ok())
}

/// The value of `key=` in an event's text.
fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let start = text.find(&format!("{key}="))? + key.len() + 1;
    let rest = &text[start..];
    if let Some(quoted) = rest.strip_prefix('"') {
        // Quoted values (ssid) run to the last quote before the next field.
        let end = quoted.rfind('"')?;
        return Some(&quoted[..end]);
    }
    Some(rest.split([' ', ']']).next().unwrap_or(rest))
}

/// An unsolicited message: `<level>EVENT text…`.
pub fn parse_notice(message: &str) -> Notice {
    let text = match message.strip_prefix('<') {
        Some(rest) => rest.split_once('>').map_or(rest, |(_, text)| text),
        None => message,
    };
    let (name, rest) = text.split_once(' ').unwrap_or((text, ""));
    match name {
        "CTRL-EVENT-SCAN-RESULTS" => Notice::ScanResults,
        "CTRL-EVENT-SCAN-FAILED" => Notice::ScanFailed,
        "CTRL-EVENT-CONNECTED" => Notice::Connected { id: field(rest, "id").and_then(|id| id.parse().ok()) },
        "CTRL-EVENT-DISCONNECTED" => Notice::Disconnected {
            reason: field(rest, "reason").and_then(|reason| reason.parse().ok()),
            locally_generated: field(rest, "locally_generated") == Some("1"),
        },
        "CTRL-EVENT-SSID-TEMP-DISABLED" => Notice::TempDisabled {
            id: field(rest, "id").and_then(|id| id.parse().ok()),
            ssid: field(rest, "ssid").and_then(unescape).unwrap_or_default(),
            reason: field(rest, "reason").unwrap_or_default().to_owned(),
        },
        "CTRL-EVENT-NETWORK-NOT-FOUND" => Notice::NetworkNotFound,
        "CTRL-EVENT-ASSOC-REJECT" => Notice::AssocReject { status_code: field(rest, "status_code").and_then(|code| code.parse().ok()) },
        "CTRL-EVENT-AUTH-REJECT" => Notice::AuthReject,
        "CTRL-EVENT-TERMINATING" => Notice::Terminating,
        _ => Notice::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_results_keep_joinable_named_networks() {
        let text = "bssid / frequency / signal level / flags / ssid\n\
            aa:bb:cc:dd:ee:01\t2437\t-58\t[WPA2-PSK-CCMP][ESS]\tOffice\n\
            aa:bb:cc:dd:ee:02\t2412\t-66\t[ESS]\tCoffee\\x20Guest\n\
            aa:bb:cc:dd:ee:03\t5180\t-71\t[WPA2-SAE-CCMP][ESS]\tField\n\
            aa:bb:cc:dd:ee:04\t2462\t-75\t[WPA2-PSK+SAE-CCMP][ESS]\tMixed\n\
            aa:bb:cc:dd:ee:05\t2462\t-80\t[WEP][ESS]\tOld\n\
            aa:bb:cc:dd:ee:06\t2462\t-80\t[WPA2-EAP-CCMP][ESS]\tCorp\n\
            aa:bb:cc:dd:ee:07\t2462\t-80\t[WPA2-PSK-CCMP][ESS]\t\n\
            aa:bb:cc:dd:ee:08\t2462\t-80\t[WPA-PSK-TKIP][ESS]\tAncient\n";
        let seen = parse_scan_results(text);
        let summary: Vec<_> = seen.iter().map(|s| (s.ssid.as_str(), s.security, s.signal_dbm, s.frequency_mhz)).collect();
        assert_eq!(
            summary,
            vec![
                ("Office", Security::Wpa2, -58, 2437),
                ("Coffee Guest", Security::Open, -66, 2412),
                ("Field", Security::Wpa3, -71, 5180),
                ("Mixed", Security::Wpa2, -75, 2462),
            ]
        );
    }

    #[test]
    fn unescape_undoes_printf_encode_and_refuses_non_utf8() {
        assert_eq!(unescape(r#"a\"b\\c\x41\t"#).as_deref(), Some("a\"b\\cA\t"));
        assert_eq!(unescape(r"caf\xc3\xa9").as_deref(), Some("café"));
        assert_eq!(unescape(r"\xff"), None);
        assert_eq!(unescape(r"broken\x4"), None);
    }

    #[test]
    fn names_and_passwords_cannot_inject_commands() {
        let commands = network_commands(3, "x\" key_mgmt NONE\nDISCONNECT", Some("pass word\"!"), true);
        assert_eq!(commands[0], "SET_NETWORK 3 ssid 7822206b65795f6d676d74204e4f4e450a444953434f4e4e454354");
        assert!(commands.iter().all(|command| !command.contains('\n')));
        assert!(commands.contains(&"SET_NETWORK 3 scan_ssid 1".to_owned()));
        assert_eq!(commands.last().unwrap(), "DISABLE_NETWORK 3");
        assert!(!valid_passphrase("short"));
        assert!(!valid_passphrase("line\nbreak!"));
        assert!(valid_passphrase("pass word\"!"));
    }

    #[test]
    fn open_networks_get_no_key() {
        assert_eq!(network_commands(0, "Guest", None, false), vec!["SET_NETWORK 0 ssid 4775657374", "SET_NETWORK 0 key_mgmt NONE", "DISABLE_NETWORK 0"]);
    }

    #[test]
    fn status_list_and_signal() {
        let status = parse_status("bssid=aa:bb\nfreq=2437\nssid=Office\nid=2\nmode=station\nwpa_state=COMPLETED\nip_address=192.168.1.23\n");
        assert_eq!(status, Status { wpa_state: "COMPLETED".into(), ssid: Some("Office".into()), id: Some(2), frequency_mhz: Some(2437) });
        assert_eq!(
            parse_list_networks("network id / ssid / bssid / flags\n0\tHome\tany\t[DISABLED]\n1\tOffice\tany\t[CURRENT]\n"),
            vec![Listed { id: 0, ssid: "Home".into() }, Listed { id: 1, ssid: "Office".into() }]
        );
        assert_eq!(parse_signal("RSSI=-61\nLINKSPEED=72\nNOISE=9999\nFREQUENCY=2437\n"), Some(-61));
    }

    #[test]
    fn notices_and_what_they_prove() {
        let wrong = parse_notice("<3>CTRL-EVENT-SSID-TEMP-DISABLED id=1 ssid=\"My \\\"Net\\\"\" auth_failures=1 duration=10 reason=WRONG_KEY");
        assert_eq!(wrong, Notice::TempDisabled { id: Some(1), ssid: "My \"Net\"".into(), reason: "WRONG_KEY".into() });
        assert_eq!(wrong.problem(), Some(Problem::WrongPassword));

        assert_eq!(
            parse_notice("<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=2 id_str=]"),
            Notice::Connected { id: Some(2) }
        );
        assert_eq!(
            parse_notice("<3>CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3 locally_generated=1"),
            Notice::Disconnected { reason: Some(3), locally_generated: true }
        );
        assert_eq!(parse_notice("<3>CTRL-EVENT-NETWORK-NOT-FOUND").problem(), Some(Problem::NotFound));
        let reject = parse_notice("<3>CTRL-EVENT-ASSOC-REJECT bssid=aa status_code=17");
        assert_eq!(reject, Notice::AssocReject { status_code: Some(17) });
        assert_eq!(reject.problem(), None);
        assert_eq!(parse_notice("<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"x\" auth_failures=3 duration=60 reason=CONN_FAILED").problem(), Some(Problem::Rejected));
        assert_eq!(parse_notice("<3>CTRL-EVENT-SCAN-RESULTS "), Notice::ScanResults);
        assert_eq!(parse_notice("<2>CTRL-EVENT-BSS-ADDED 3 aa:bb"), Notice::Other);
    }
}

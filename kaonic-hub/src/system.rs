//! Facts about the device and the few system actions the hub takes, read under
//! a root directory (`/` on the device, a temporary tree in tests).

use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Device {
    root: PathBuf,
}

impl Device {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn read(&self, path: &str) -> Option<String> {
        let text = std::fs::read_to_string(self.root.join(path.trim_start_matches('/'))).ok()?;
        let text = text.trim();
        (!text.is_empty()).then(|| text.to_owned())
    }

    /// Written by kaonic-init from the OTP fuses: `<date>-<suffix>`.
    pub fn serial(&self) -> String {
        self.read("/etc/kaonic/kaonic_serial")
            .unwrap_or_else(|| "unknown".into())
    }

    /// The Yocto machine, e.g. `stm32mp1-kaonic1s-r30`.
    pub fn machine(&self) -> Option<String> {
        self.read("/etc/kaonic/kaonic_machine")
    }

    /// A name for people: `stm32mp1-kaonic1s-r30` → `Kaonic 1S r30`.
    pub fn model(&self) -> String {
        let Some(machine) = self.machine() else {
            return "Kaonic".into();
        };
        let name = machine.strip_prefix("stm32mp1-").unwrap_or(&machine);
        let mut parts = name.split('-');
        match (parts.next(), parts.next()) {
            (Some(board), Some(revision)) if board.starts_with("kaonic") => {
                format!(
                    "Kaonic {} {revision}",
                    board.trim_start_matches("kaonic").to_uppercase()
                )
            }
            _ => format!("Kaonic ({machine})"),
        }
    }

    pub fn hostname(&self) -> String {
        self.read("/etc/hostname")
            .unwrap_or_else(|| "kaonic".into())
    }

    /// `VERSION_ID` or `VERSION` from os-release.
    pub fn os_version(&self) -> String {
        let release = self.read("/etc/os-release").unwrap_or_default();
        let field = |key: &str| {
            release.lines().find_map(|line| {
                line.strip_prefix(key)?
                    .strip_prefix('=')
                    .map(|value| value.trim_matches('"').to_owned())
            })
        };
        field("VERSION")
            .or_else(|| field("VERSION_ID"))
            .unwrap_or_else(|| "unknown".into())
    }

    /// The OS's own name for itself (`PRETTY_NAME` in `/etc/os-release`).
    pub fn os_name(&self) -> Option<String> {
        let release = self.read("/etc/os-release")?;
        release.lines().find_map(|line| Some(line.strip_prefix("PRETTY_NAME=")?.trim_matches('"').to_owned()))
    }

    /// The running kernel's release, as `uname -r` gives it.
    pub fn kernel(&self) -> Option<String> {
        self.read("/proc/sys/kernel/osrelease").map(|text| text.trim().to_owned()).filter(|text| !text.is_empty())
    }

    pub fn uptime_secs(&self) -> u64 {
        self.read("/proc/uptime")
            .and_then(|text| text.split('.').next()?.parse().ok())
            .unwrap_or(0)
    }

}

/// An IPv4 address on an interface, with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceNetwork {
    pub address: std::net::Ipv4Addr,
    pub prefix_len: u8,
}

impl InterfaceNetwork {
    /// Whether `other` is on this address's subnet.
    pub fn contains(&self, other: std::net::Ipv4Addr) -> bool {
        let mask = if self.prefix_len == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix_len.min(32))) };
        u32::from(self.address) & mask == u32::from(other) & mask
    }
}

/// The IPv4 addresses and subnets on an interface, from getifaddrs(3): in-process,
/// microseconds, no `ip` to spawn on the async runtime. Empty if it has none or does not exist.
pub fn interface_networks(interface: &str) -> Vec<InterfaceNetwork> {
    let mut networks = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list` with a linked list we own until freeifaddrs.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return networks;
    }
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a node of the list getifaddrs returned, not yet freed.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_name.is_null() || entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) };
        // SAFETY: ifa_addr points to a sockaddr whose family says how to read it.
        if name.to_bytes() != interface.as_bytes() || i32::from(unsafe { (*entry.ifa_addr).sa_family }) != libc::AF_INET {
            continue;
        }
        // SAFETY: the family is AF_INET, so the sockaddr is a sockaddr_in.
        let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
        let prefix_len = if entry.ifa_netmask.is_null() {
            32
        } else {
            // SAFETY: the netmask of an AF_INET address is a sockaddr_in too.
            let mask = unsafe { &*(entry.ifa_netmask as *const libc::sockaddr_in) };
            u32::from_be(mask.sin_addr.s_addr).leading_ones() as u8
        };
        networks.push(InterfaceNetwork { address: std::net::Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)), prefix_len });
    }
    // SAFETY: `list` came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(list) };
    networks
}

/// The bridge `interface` is a port of, if any.
pub fn bridge_of(interface: &str) -> Option<String> {
    let master = std::fs::read_link(format!("/sys/class/net/{interface}/master")).ok()?;
    Some(master.file_name()?.to_str()?.to_owned())
}

/// Whether the bridge learned `remote` (a neighbour on `bridge`) on its port `port`: the
/// neighbour's MAC from /proc/net/arp, then the port from the bridge's forwarding table.
pub fn bridge_port_has(bridge: &str, port: &str, remote: std::net::Ipv4Addr) -> bool {
    let Ok(arp) = std::fs::read_to_string("/proc/net/arp") else {
        return false;
    };
    let remote = remote.to_string();
    let Some(mac) = arp.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.len() >= 6 && fields[0] == remote && fields[5] == bridge).then(|| fields[3].to_owned())
    }) else {
        return false;
    };
    let Some(mac) = parse_mac(&mac) else {
        return false;
    };
    let Some(number) = std::fs::read_to_string(format!("/sys/class/net/{bridge}/brif/{port}/port_no"))
        .ok()
        .and_then(|text| u16::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok())
    else {
        return false;
    };
    std::fs::read(format!("/sys/class/net/{bridge}/brforward")).is_ok_and(|table| fdb_has(&table, mac, number))
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

/// Whether a bridge forwarding table (`brforward`: `struct __fdb_entry`, 16 bytes each: MAC,
/// port number low byte, is_local, ageing timer, port number high byte) has `mac` on `port`.
fn fdb_has(table: &[u8], mac: [u8; 6], port: u16) -> bool {
    table.as_chunks::<16>().0.iter().any(|entry| entry[..6] == mac && u16::from(entry[6]) | u16::from(entry[12]) << 8 == port)
}

/// The IPv4 addresses on an interface. Empty if it has none or does not exist.
pub fn interface_addresses(interface: &str) -> Vec<std::net::IpAddr> {
    interface_networks(interface).into_iter().map(|network| std::net::IpAddr::V4(network.address)).collect()
}

/// CPU use between two calls, memory, storage and uptime, from /proc and statvfs.
#[derive(Default)]
pub struct Metrics {
    last_cpu: std::sync::Mutex<Option<(u64, u64)>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MetricsView {
    pub cpu_percent: f64,
    pub ram_used_mb: u64,
    pub ram_total_mb: u64,
    pub fs_free_mb: u64,
    pub fs_total_mb: u64,
    pub uptime_secs: u64,
    pub battery: Option<()>,
}

impl Metrics {
    pub fn read(&self, device: &Device, storage: &Path) -> MetricsView {
        let cpu = device.read("/proc/stat").and_then(|stat| {
            let fields: Vec<u64> = stat
                .lines()
                .next()?
                .split_whitespace()
                .skip(1)
                .filter_map(|value| value.parse().ok())
                .collect();
            let idle = fields.get(3)? + fields.get(4).copied().unwrap_or(0);
            Some((fields.iter().sum::<u64>(), idle))
        });
        let cpu_percent = match (
            cpu,
            self.last_cpu
                .lock()
                .ok()
                .and_then(|mut last| std::mem::replace(&mut *last, cpu)),
        ) {
            (Some((total, idle)), Some((last_total, last_idle))) if total > last_total => {
                100.0 * (1.0 - (idle - last_idle) as f64 / (total - last_total) as f64)
            }
            _ => 0.0,
        };
        let meminfo = device.read("/proc/meminfo").unwrap_or_default();
        let kib = |key: &str| {
            meminfo
                .lines()
                .find_map(|line| {
                    line.strip_prefix(key)?
                        .trim()
                        .trim_end_matches(" kB")
                        .trim()
                        .parse::<u64>()
                        .ok()
                })
                .unwrap_or(0)
        };
        let (total, available) = (kib("MemTotal:"), kib("MemAvailable:"));
        let (fs_free_mb, fs_total_mb) = statvfs_mb(storage).unwrap_or((0, 0));
        MetricsView {
            cpu_percent: (cpu_percent * 10.0).round() / 10.0,
            ram_used_mb: total.saturating_sub(available) / 1024,
            ram_total_mb: total / 1024,
            fs_free_mb,
            fs_total_mb,
            uptime_secs: device.uptime_secs(),
            battery: None,
        }
    }
}

fn statvfs_mb(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is a valid C string and `stat` is a valid out-pointer.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs succeeded, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    // The field widths differ between targets (32-bit on the board): widen each.
    #[allow(clippy::useless_conversion)]
    let (block, available, blocks) = (
        u64::from(stat.f_frsize),
        u64::from(stat.f_bavail),
        u64::from(stat.f_blocks),
    );
    Some((
        available * block / (1024 * 1024),
        blocks * block / (1024 * 1024),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_facts_under_its_root() {
        let root = std::env::temp_dir().join(format!("kh-device-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/kaonic")).unwrap();
        std::fs::create_dir_all(root.join("proc")).unwrap();
        std::fs::write(root.join("etc/kaonic/kaonic_serial"), "260412-ABCD\n").unwrap();
        std::fs::write(
            root.join("etc/kaonic/kaonic_machine"),
            "stm32mp1-kaonic1s-r30\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/os-release"),
            "ID=openstlinux\nVERSION=\"5.0 (scarthgap)\"\n",
        )
        .unwrap();
        std::fs::write(root.join("proc/uptime"), "12345.67 99.0\n").unwrap();

        let device = Device::new(&root);
        assert_eq!(device.serial(), "260412-ABCD");
        assert_eq!(device.model(), "Kaonic 1S r30");
        assert_eq!(device.os_version(), "5.0 (scarthgap)");
        assert_eq!(device.uptime_secs(), 12345);
        assert_eq!(device.hostname(), "kaonic");
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod interface_tests {
    use super::*;

    #[test]
    fn a_bridge_forwarding_entry_is_matched_by_mac_and_port() {
        let mac = parse_mac("98:68:0a:d6:2e:45").unwrap();
        let mut table = Vec::new();
        // Another station on port 2 (Wi-Fi), then ours on port 1 (USB).
        table.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        table.extend_from_slice(&[0x98, 0x68, 0x0a, 0xd6, 0x2e, 0x45, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(fdb_has(&table, mac, 1));
        assert!(!fdb_has(&table, mac, 2));
        // The high byte of the port number counts.
        table[16 + 12] = 1;
        assert!(fdb_has(&table, mac, 0x101));
        assert!(!fdb_has(&table, mac, 1));
        assert_eq!(parse_mac("98:68:0a"), None);
        assert_eq!(parse_mac("98:68:0a:d6:2e:45:00"), None);
    }

    #[test]
    fn loopback_has_its_subnet() {
        let lo = if cfg!(target_os = "macos") { "lo0" } else { "lo" };
        let networks = interface_networks(lo);
        let network = networks.iter().find(|network| network.address == std::net::Ipv4Addr::LOCALHOST).expect("127.0.0.1 on loopback");
        assert_eq!(network.prefix_len, 8);
        assert!(network.contains("127.1.2.3".parse().unwrap()));
        assert!(!network.contains("128.0.0.1".parse().unwrap()));
        assert!(interface_networks("no-such-if0").is_empty());
    }
}

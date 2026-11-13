//! Networks this node already reaches through other interfaces, read from
//! `/proc/net/route`. Peers may not advertise these.

use std::net::Ipv4Addr;

use crate::ip::Cidr;

/// Routes in `/proc/net/route` text, except those on `skip` and the default route.
pub fn parse_routes(text: &str, skip: &str) -> Vec<Cidr> {
    let mut routes = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(&iface), Some(&destination), Some(&mask)) = (fields.first(), fields.get(1), fields.get(7)) else { continue };
        if iface == skip {
            continue;
        }
        // Hex u32 in host byte order.
        let (Ok(destination), Ok(mask)) = (u32::from_str_radix(destination, 16), u32::from_str_radix(mask, 16)) else { continue };
        let mask = u32::from_be_bytes(mask.to_ne_bytes());
        let len = mask.count_ones() as u8;
        if len == 0 || mask.leading_ones() != mask.count_ones() {
            continue;
        }
        if let Some(prefix) = Cidr::new(Ipv4Addr::from(destination.to_ne_bytes()), len) {
            routes.push(prefix);
        }
    }
    routes
}

/// One line of `/proc/net/route`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub interface: String,
    /// `0.0.0.0/0` for the default route.
    pub prefix: Cidr,
    /// Directly connected (no gateway).
    pub connected: bool,
}

/// Every route in `/proc/net/route` text, default route included.
pub fn parse_all(text: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(&iface), Some(&destination), Some(&gateway), Some(&mask)) = (fields.first(), fields.get(1), fields.get(2), fields.get(7)) else { continue };
        let (Ok(destination), Ok(gateway), Ok(mask)) = (u32::from_str_radix(destination, 16), u32::from_str_radix(gateway, 16), u32::from_str_radix(mask, 16)) else { continue };
        let mask = u32::from_be_bytes(mask.to_ne_bytes());
        if mask.leading_ones() != mask.count_ones() {
            continue;
        }
        if let Some(prefix) = Cidr::new(Ipv4Addr::from(destination.to_ne_bytes()), mask.count_ones() as u8) {
            routes.push(Route { interface: iface.to_owned(), prefix, connected: gateway == 0 });
        }
    }
    routes
}

/// This node's IPv4 addresses per interface.
pub fn interface_addresses() -> Vec<(String, Ipv4Addr)> {
    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below; entries are read only while it lives.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return out;
    }
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: a node of the list getifaddrs returned.
        let ifa = unsafe { &*entry };
        if !ifa.ifa_addr.is_null() && i32::from(unsafe { (*ifa.ifa_addr).sa_family }) == libc::AF_INET {
            // SAFETY: AF_INET means the address is a sockaddr_in; the name is a C string.
            let address = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
            out.push((name, Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))));
        }
        entry = ifa.ifa_next;
    }
    // SAFETY: the list getifaddrs allocated, freed once.
    unsafe { libc::freeifaddrs(list) };
    out
}

pub fn all_routes() -> Vec<Route> {
    std::fs::read_to_string("/proc/net/route").map(|text| parse_all(&text)).unwrap_or_default()
}

/// The kernel's routes not on `skip`; empty without `/proc`.
pub fn routes(skip: &str) -> Vec<Cidr> {
    std::fs::read_to_string("/proc/net/route").map(|text| parse_routes(&text, skip)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_proc_net_route() {
        // As a little-endian board prints it.
        let le = |octets: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(octets));
        let text = format!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
             wlan0\t{}\t{}\t0003\t0\t0\t600\t{}\t0\t0\t0\n\
             wlan0\t{}\t00000000\t0001\t0\t0\t600\t{}\t0\t0\t0\n\
             br0\t{}\t00000000\t0001\t0\t0\t0\t{}\t0\t0\t0\n\
             kaonic0\t{}\t00000000\t0001\t0\t0\t0\t{}\t0\t0\t0\n",
            le([0, 0, 0, 0]), le([192, 168, 12, 1]), le([0, 0, 0, 0]),
            le([192, 168, 12, 0]), le([255, 255, 255, 0]),
            le([192, 168, 11, 0]), le([255, 255, 255, 0]),
            le([10, 77, 0, 0]), le([255, 255, 0, 0]),
        );
        let routes = parse_routes(&text, "kaonic0");
        assert_eq!(routes, vec!["192.168.12.0/24".parse().unwrap(), "192.168.11.0/24".parse::<Cidr>().unwrap()]);
        assert!(parse_routes("garbage\nwlan0 zz", "kaonic0").is_empty());
        let all = parse_all(&text);
        assert_eq!(all[0], Route { interface: "wlan0".into(), prefix: "0.0.0.0/0".parse().unwrap(), connected: false });
        assert_eq!(all[2], Route { interface: "br0".into(), prefix: "192.168.11.0/24".parse().unwrap(), connected: true });
    }
}

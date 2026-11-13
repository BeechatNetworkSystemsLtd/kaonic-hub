//! Shares the VPN with end clients: devices on a node's hotspot, LAN and USB (`br0`,
//! `usb0`). On by default.
//!
//! - **Client networks are advertised** to the mesh. Every Kaonic ships the same LAN
//!   (192.168.10.0/24), so each node picks its own /24 from the pool (10.78.0.0/16) by
//!   identity and serves that to its clients (`route_lans`). The node is `.1` on it; the
//!   shipped address stays for setup. A client then has the same address everywhere on the
//!   mesh, so addresses that apps share with peers (e.g. ATAK contacts) are correct. If two
//!   nodes pick the same /24, the higher identity hash picks again.
//! - Clients still on the shipped network reach the mesh behind the node's tunnel address
//!   (MASQUERADE) and can't be reached from it. With `route_lans` off, the shipped network
//!   is mapped 1:1 (`NETMAP`) to the node's /24 instead: clients keep their addresses, but
//!   addresses inside app payloads are wrong.
//! - **Clients learn routes by DHCP** (`push_routes`). dnsmasq serves DHCP and pushes
//!   classless static routes (option 121, and 249 for old Windows) for the tunnel network,
//!   the pool and other nodes' networks. No router or DNS is given unless this node can
//!   forward somewhere (gateway, uplink, or `lan_router: always`), so a laptop keeps its own
//!   internet. Leases are short so new routes are picked up. Android ignores option 121, so
//!   with `lan_router: auto` it gets the node as router (a default route for that network only).
//! - **Forwarding**: `ip_forward`, FORWARD rules between client networks and the tunnel, and
//!   TCP MSS clamped to the tunnel MTU.
//! - **Gateway**: a node with an uplink forwards peers' traffic (MASQUERADE) to the
//!   destinations it offers, and announces them with `KVG1`. Not as a 0/0 prefix, which
//!   peers refuse.
//! - **Uplink**: a node routes chosen destinations (or everything) to a gateway peer. The
//!   kernel has no policy routing, so these are main-table routes: with `default_route` the
//!   node's own traffic goes there too.
//!
//! [`plan`] and the dnsmasq config builders have no side effects. [`Applier::apply`] runs the
//! tools and blocks, so it runs on the VPN's network thread.
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::ip::Cidr;

/// Gateway announcement on mux stream 2 (`count` 0 withdraws it):
/// `"KVG1" | count u8 | (address[4] | length u8) * count`
const GATEWAY: &[u8; 4] = b"KVG1";
pub const MAX_GATEWAY_ROUTES: usize = 32;
/// Mapping attempts before a client network is shared unmapped.
pub const MAX_ATTEMPTS: u32 = 16;
const CHAIN_PRE: &str = "KAONIC_VPN_PRE";
const CHAIN_POST: &str = "KAONIC_VPN_POST";
const CHAIN_MSS: &str = "KAONIC_VPN_MSS";
const CHAIN_FWD: &str = "KAONIC_VPN_FWD";
/// Metric of uplink routes; lower than DHCP default routes.
const UPLINK_METRIC: &str = "50";
/// Short DHCP leases, so clients pick up new routes within minutes.
pub const LEASE: &str = "10m";
/// First DHCP host offset and number of addresses.
const POOL_OFFSET: u32 = 10;
const POOL_SIZE: u32 = 100;
/// Our config for the system dnsmasq, and the system's base config.
const SYSTEM_CONF: &str = "/etc/dnsmasq.d/kaonic-hub-dhcp.conf";
const BASE_CONF: &str = "/etc/dnsmasq.d/hostapd-dns.conf";
/// An older DHCP config that would serve the same range; disabled while we serve.
const GATEWAY_CONF: &str = "/etc/dnsmasq.d/kaonic-dhcp.conf";
/// Separate from the hub's private run directory: dnsmasq reads it after dropping root.
const RUN_DIR: &str = "/run/kaonic-hub-dhcp";
const OPTS_FILE: &str = "/run/kaonic-hub-dhcp/dhcp-opts";
const NETWORKD_DROPIN: &str = "kaonic-hub-dhcp.conf";
/// dnsmasq tag for clients that ignore classless routes.
const NO_ROUTES: &str = "kh-noroutes";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanRouter {
    /// Router and DNS only while the node can forward somewhere. Clients that ignore routes
    /// (Android) always get the node as router, without DNS.
    Auto,
    /// Always the router.
    Always,
    Never,
}

impl LanRouter {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "auto" => Some(Self::Auto),
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewaySettings {
    pub enabled: bool,
    /// None: use the default route's interface.
    pub egress_interface: Option<String>,
    /// Destinations forwarded for peers; 0.0.0.0/0 shares everything.
    pub routes: Vec<Cidr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UplinkSettings {
    pub enabled: bool,
    /// Gateway peer; None picks the first one heard.
    pub peer: Option<String>,
    /// Send all traffic, the node's own too, through the gateway.
    pub default_route: bool,
    /// Destinations sent to the gateway if not `default_route`.
    pub routes: Vec<Cidr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareSettings {
    pub share_lans: bool,
    pub lan_interfaces: Vec<String>,
    pub map_lans: bool,
    /// Serve the node's own pool /24 on client interfaces, routed unmapped.
    pub route_lans: bool,
    pub mapping_pool: Cidr,
    /// Serve DHCP with the mesh routes (option 121/249).
    pub push_routes: bool,
    pub lan_router: LanRouter,
    pub dns_servers: Vec<Ipv4Addr>,
    /// Extra prefixes advertised as is (`PUT /vpn/routes`); never mapped.
    pub advertise: Vec<Cidr>,
    pub gateway: GatewaySettings,
    pub uplink: UplinkSettings,
}

impl Default for ShareSettings {
    fn default() -> Self {
        Self {
            share_lans: true,
            lan_interfaces: vec!["br0".into(), "usb0".into()],
            map_lans: true,
            route_lans: true,
            mapping_pool: Cidr::new(Ipv4Addr::new(10, 78, 0, 0), 16).expect("valid prefix"),
            push_routes: true,
            lan_router: LanRouter::Auto,
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
            advertise: Vec::new(),
            gateway: GatewaySettings { enabled: false, egress_interface: None, routes: vec![Cidr::new(Ipv4Addr::UNSPECIFIED, 0).expect("valid prefix")] },
            uplink: UplinkSettings { enabled: false, peer: None, default_route: true, routes: Vec::new() },
        }
    }
}

/// A client network of this node and its prefix on the mesh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanNet {
    pub interface: String,
    pub subnet: Cidr,
    /// Equals `subnet` if not mapped.
    pub mapped: Cidr,
    /// The node's address on it (the clients' next hop).
    pub address: Option<Ipv4Addr>,
    /// If `subnet` is the node's pool /24 added by the hub: the interface's original network,
    /// kept for setup.
    pub base: Option<Cidr>,
}

impl LanNet {
    pub fn is_mapped(&self) -> bool {
        self.mapped != self.subnet
    }
}

/// Maps `subnet` 1:1 into `pool`: a /24 slot picked from the identity, subnet and attempt.
/// Subnets wider than /24 (or pools narrower than /24) are returned unchanged.
pub fn mapped_subnet(identity_hex: &str, subnet: &Cidr, pool: &Cidr, attempt: u32) -> Cidr {
    if subnet.prefix_len() < 24 || pool.prefix_len() > 24 {
        return *subnet;
    }
    let mut seed: u32 = 2_166_136_261;
    let mut mix = |byte: u8| seed = (seed ^ u32::from(byte)).wrapping_mul(16_777_619);
    identity_hex.bytes().for_each(&mut mix);
    subnet.network().octets().into_iter().for_each(&mut mix);
    mix(subnet.prefix_len());
    attempt.to_be_bytes().into_iter().for_each(&mut mix);
    let slots = 1u32 << (24 - pool.prefix_len());
    let slot = seed % slots;
    let base = u32::from(pool.network()) | (slot << 8);
    // Keep the offset inside the /24 (a /25 stays the upper or lower half).
    let offset = u32::from(subnet.network()) & 0xff;
    Cidr::new(Ipv4Addr::from(base | offset), subnet.prefix_len()).unwrap_or(*subnet)
}

/// Encodes a gateway announcement (`KVG1`).
pub fn encode_gateway(routes: &[Cidr]) -> Vec<u8> {
    let mut out = GATEWAY.to_vec();
    out.push(routes.len().min(MAX_GATEWAY_ROUTES) as u8);
    for route in routes.iter().take(MAX_GATEWAY_ROUTES) {
        out.extend_from_slice(&route.network().octets());
        out.push(route.prefix_len());
    }
    out
}

pub fn decode_gateway(data: &[u8]) -> Option<Vec<Cidr>> {
    let rest = data.strip_prefix(GATEWAY)?;
    let (&count, mut rest) = rest.split_first()?;
    if usize::from(count) > MAX_GATEWAY_ROUTES {
        return None;
    }
    let mut routes = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (entry, after) = rest.split_first_chunk::<5>()?;
        routes.push(Cidr::new(Ipv4Addr::new(entry[0], entry[1], entry[2], entry[3]), entry[4])?);
        rest = after;
    }
    rest.is_empty().then_some(routes)
}

/// The active uplink: gateway peer and destinations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UplinkRoutes {
    pub peer: String,
    pub default_route: bool,
    /// Kernel routes into the tunnel (`0.0.0.0/0` is the default route).
    pub routes: Vec<Cidr>,
}

/// A client network served by DHCP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpNet {
    pub interface: String,
    pub address: Ipv4Addr,
    pub subnet: Cidr,
    /// Another on-link network clients reach directly (the setup network).
    pub on_link: Option<Cidr>,
}

/// DHCP settings for the client networks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dhcp {
    pub nets: Vec<DhcpNet>,
    /// Routes through the node (option 121/249), besides the on-link subnet.
    pub routes: Vec<Cidr>,
    /// Also act as router (default route in 121, option 3) and give DNS.
    pub router: bool,
    /// Clients without option 121 (Android) get the node as router even if `router` is off.
    pub router_fallback: bool,
    pub dns: Vec<Ipv4Addr>,
}

/// The wanted kernel and DHCP state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub nat_pre: Vec<Vec<String>>,
    pub nat_post: Vec<Vec<String>>,
    pub mss: Vec<Vec<String>>,
    pub forward: Vec<Vec<String>>,
    pub ip_forward: bool,
    /// The node's pool addresses on client interfaces: `(interface, address, prefix length)`.
    /// Other pool addresses there are removed.
    pub addresses: Vec<(String, Ipv4Addr, u8)>,
    pub pool: Option<Cidr>,
    pub uplink: Option<UplinkRoutes>,
    pub dhcp: Option<Dhcp>,
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

pub struct PlanInput<'a> {
    pub tun: &'a str,
    pub mtu: u16,
    pub tunnel_network: Cidr,
    pub lans: &'a [LanNet],
    pub settings: &'a ShareSettings,
    /// Gateway egress interface, if the gateway is active.
    pub egress: Option<&'a str>,
    /// Peers' source prefixes (tunnel addresses and usable prefixes). Masqueraded on egress
    /// and pushed to clients as routes.
    pub remote_sources: &'a [Cidr],
    pub uplink: Option<UplinkRoutes>,
}

pub fn plan(input: &PlanInput) -> Plan {
    let tun = input.tun;
    let mut plan = Plan::default();
    for lan in input.lans {
        let (subnet, mapped) = (lan.subnet.to_string(), lan.mapped.to_string());
        if lan.is_mapped() {
            plan.nat_pre.push(args(&["-d", &mapped, "-j", "NETMAP", "--to", &subnet]));
            plan.nat_post.push(args(&["-o", tun, "-s", &subnet, "-j", "NETMAP", "--to", &mapped]));
        }
        if let (Some(base), Some(address)) = (lan.base, lan.address) {
            // Clients still on the shipped network are masqueraded behind the node.
            plan.nat_post.push(args(&["-o", tun, "-s", &base.to_string(), "-j", "MASQUERADE"]));
            plan.addresses.push((lan.interface.clone(), address, lan.subnet.prefix_len()));
        }
        plan.forward.push(args(&["-i", &lan.interface, "-o", tun, "-j", "ACCEPT"]));
        plan.forward.push(args(&["-i", tun, "-o", &lan.interface, "-j", "ACCEPT"]));
    }
    if let Some(egress) = input.egress {
        let mut sources: Vec<String> = std::iter::once(input.tunnel_network).chain(input.remote_sources.iter().copied()).map(|source| source.to_string()).collect();
        // The gateway's own clients use the uplink too.
        sources.extend(input.lans.iter().map(|lan| lan.subnet.to_string()));
        sources.dedup();
        for source in &sources {
            plan.nat_post.push(args(&["-o", egress, "-s", source, "-j", "MASQUERADE"]));
        }
        plan.forward.push(args(&["-i", tun, "-o", egress, "-j", "ACCEPT"]));
        plan.forward.push(args(&["-i", egress, "-o", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]));
        for lan in input.lans {
            plan.forward.push(args(&["-i", &lan.interface, "-o", egress, "-j", "ACCEPT"]));
            plan.forward.push(args(&["-i", egress, "-o", &lan.interface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]));
        }
    }
    if !input.lans.is_empty() || input.egress.is_some() || input.uplink.is_some() {
        // Clamp TCP MSS so 1500-byte clients fit the tunnel.
        let mss = input.mtu.saturating_sub(40).max(536).to_string();
        plan.mss.push(args(&["-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss]));
    }
    plan.ip_forward = !input.lans.is_empty() || input.egress.is_some();
    plan.pool = (input.settings.share_lans || !plan.addresses.is_empty()).then_some(input.settings.mapping_pool);
    plan.uplink = input.uplink.clone();

    let nets: Vec<DhcpNet> = input.lans.iter().filter_map(|lan| Some(DhcpNet { interface: lan.interface.clone(), address: lan.address?, subnet: lan.subnet, on_link: lan.base })).collect();
    if input.settings.push_routes && !nets.is_empty() {
        let router = match input.settings.lan_router {
            LanRouter::Always => true,
            LanRouter::Never => false,
            LanRouter::Auto => input.egress.is_some() || input.uplink.as_ref().is_some_and(|uplink| uplink.default_route),
        };
        // Tunnel network, mapping pool, other nodes' prefixes, and uplink destinations unless
        // the uplink takes everything.
        let mut routes = vec![input.tunnel_network];
        if input.settings.map_lans || input.settings.route_lans {
            routes.push(input.settings.mapping_pool);
        }
        for source in input.remote_sources {
            if !routes.iter().any(|route| route.contains(source.network()) && route.prefix_len() <= source.prefix_len()) {
                routes.push(*source);
            }
        }
        if let Some(uplink) = &input.uplink
            && !uplink.default_route
        {
            routes.extend(uplink.routes.iter().filter(|route| route.prefix_len() > 0).copied());
        }
        routes.sort();
        routes.dedup();
        let dns = if router { input.settings.dns_servers.clone() } else { Vec::new() };
        plan.dhcp = Some(Dhcp { nets, routes, router, router_fallback: input.settings.lan_router == LanRouter::Auto, dns });
    }
    plan
}

/// Our dnsmasq config: a range and tag per client network; routes come from the optsfile.
pub fn dnsmasq_conf(dhcp: &Dhcp, standalone: bool) -> String {
    let mut text = "# Written by kaonic-hub: DHCP for the client networks, with routes to the mesh\n# (option 121/249 from the optsfile, kept current by the hub).\n".to_owned();
    if standalone {
        // Our own dnsmasq: DHCP only, on the client interfaces.
        text += "port=0\nbind-dynamic\n";
        for net in &dhcp.nets {
            text += &format!("interface={}\n", net.interface);
        }
    }
    for net in &dhcp.nets {
        let base = u32::from(net.subnet.network());
        let last = u32::from(net.subnet.broadcast()).saturating_sub(1);
        let start = (base + POOL_OFFSET).min(last);
        let end = (start + POOL_SIZE - 1).min(last);
        let mask = Ipv4Addr::from(if net.subnet.prefix_len() == 0 { 0 } else { u32::MAX << (32 - u32::from(net.subnet.prefix_len())) });
        text += &format!("dhcp-range=set:kh-{},{},{},{mask},{LEASE}\n", net.interface, Ipv4Addr::from(start), Ipv4Addr::from(end));
    }
    // Tag Android, which ignores option 121 (see `dnsmasq_opts`).
    text += &format!("dhcp-vendorclass=set:{NO_ROUTES},android-dhcp\n");
    text += &format!("dhcp-optsfile={OPTS_FILE}\ndhcp-authoritative\n");
    text
}

/// The dnsmasq options file: DHCP options per client network.
pub fn dnsmasq_opts(dhcp: &Dhcp) -> String {
    let mut text = String::new();
    for net in &dhcp.nets {
        let tag = format!("tag:kh-{}", net.interface);
        let via = net.address.to_string();
        // Clients with option 121 ignore option 3 (RFC 3442), so the default route goes in 121.
        let mut pairs: Vec<String> = Vec::new();
        if dhcp.router {
            pairs.push(format!("0.0.0.0/0,{via}"));
        }
        pairs.extend(dhcp.routes.iter().filter(|route| !(net.subnet.contains(route.network()) && net.subnet.prefix_len() <= route.prefix_len())).map(|route| format!("{route},{via}")));
        // The client's own network (and the setup network) as on-link routes.
        pairs.push(format!("{},0.0.0.0", net.subnet));
        if let Some(on_link) = net.on_link {
            pairs.push(format!("{on_link},0.0.0.0"));
        }
        let routes = pairs.join(",");
        text += &format!("{tag},option:classless-static-route,{routes}\n{tag},249,{routes}\n");
        if dhcp.router {
            text += &format!("{tag},option:router,{via}\n");
            if !dhcp.dns.is_empty() {
                text += &format!("{tag},option:dns-server,{}\n", dhcp.dns.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
            }
        } else if dhcp.router_fallback {
            // Android gets the node as router (a default route for this network only). Others
            // get no router and no DNS.
            text += &format!("{tag},tag:{NO_ROUTES},option:router,{via}\n{tag},tag:!{NO_ROUTES},option:router\n{tag},option:dns-server\n");
        } else {
            // Empty options, or dnsmasq offers itself as router and DNS.
            text += &format!("{tag},option:router\n{tag},option:dns-server\n");
        }
    }
    text
}

/* ── applying a plan (blocking) ── */

fn find(program: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"].iter().map(|dir| PathBuf::from(dir).join(program)).find(|path| path.exists())
}

fn run(program: &Path, args: &[String]) -> io::Result<bool> {
    Ok(Command::new(program).args(args).stdout(Stdio::null()).stderr(Stdio::null()).status()?.success())
}

fn run_checked(program: &Path, args: &[String]) -> io::Result<()> {
    let output = Command::new(program).args(args).stdout(Stdio::null()).stderr(Stdio::piped()).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{} {}: {}", program.display(), args.join(" "), String::from_utf8_lossy(&output.stderr).trim())))
    }
}

/// Flushes and refills our chain in `table` with `rules`, and adds one jump from `parent`.
fn fill_chain(iptables: &Path, table: &str, parent: &str, chain: &str, jump_match: &[&str], rules: &[Vec<String>]) -> io::Result<()> {
    let base = |rest: &[&str]| -> Vec<String> { ["-t", table].iter().chain(rest.iter()).map(|part| (*part).to_owned()).collect() };
    let _ = run(iptables, &base(&["-N", chain]));
    run_checked(iptables, &base(&["-F", chain]))?;
    for rule in rules {
        let mut command = base(&["-A", chain]);
        command.extend(rule.iter().cloned());
        run_checked(iptables, &command)?;
    }
    let mut jump: Vec<&str> = vec![parent];
    jump.extend_from_slice(jump_match);
    jump.extend_from_slice(&["-j", chain]);
    let mut check = base(&["-C"]);
    check.extend(jump.iter().map(|part| (*part).to_owned()));
    if !run(iptables, &check)? {
        let mut insert = base(&["-I"]);
        insert.push(jump[0].to_owned());
        insert.push("1".to_owned());
        insert.extend(jump[1..].iter().map(|part| (*part).to_owned()));
        run_checked(iptables, &insert)?;
    }
    Ok(())
}

/// The highest-priority networkd `.network` file for `interface` (drop-ins use its name).
fn network_file(interface: &str) -> Option<String> {
    for dir in ["/etc/systemd/network", "/run/systemd/network", "/lib/systemd/network", "/usr/lib/systemd/network"] {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        let mut names: Vec<String> = entries.filter_map(|entry| entry.ok()).map(|entry| entry.file_name().to_string_lossy().into_owned()).filter(|name| name.ends_with(".network")).collect();
        names.sort();
        for name in names {
            let Ok(text) = std::fs::read_to_string(Path::new(dir).join(&name)) else { continue };
            if text.lines().any(|line| line.trim() == format!("Name={interface}")) {
                return Some(name);
            }
        }
    }
    None
}

/// A runtime networkd drop-in: turns off networkd's DHCP server while dnsmasq serves, and
/// lists the node's pool address so networkd keeps it. Returns whether it changed.
fn networkd_dropin(interface: &str, serve: Option<&[(Ipv4Addr, u8)]>) -> io::Result<bool> {
    let Some(file) = network_file(interface) else { return Ok(false) };
    let dir = PathBuf::from("/run/systemd/network").join(format!("{file}.d"));
    let path = dir.join(NETWORKD_DROPIN);
    let current = std::fs::read_to_string(&path).ok();
    let wanted = serve.map(|addresses| {
        let mut text = "# Written by kaonic-hub: dnsmasq serves DHCP here, with the mesh routes.\n[Network]\nDHCPServer=no\n".to_owned();
        for (address, length) in addresses {
            text += &format!("\n[Address]\nAddress={address}/{length}\n");
        }
        text
    });
    if wanted == current {
        return Ok(false);
    }
    match wanted {
        Some(text) => {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&path, text)?;
        }
        None => std::fs::remove_file(&path)?,
    }
    Ok(true)
}

/// Comments out `no-dhcp-interface=<if>` in the base dnsmasq config while we serve; restores it after.
fn base_conf_dhcp(interfaces: &[String], serve: bool) -> io::Result<bool> {
    let Ok(text) = std::fs::read_to_string(BASE_CONF) else { return Ok(false) };
    let mut changed = false;
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            for interface in interfaces {
                let plain = format!("no-dhcp-interface={interface}");
                let parked = format!("#{plain} (DHCP by kaonic-hub-dhcp.conf)");
                if serve && line == plain {
                    changed = true;
                    return parked;
                }
                if !serve && line == parked {
                    changed = true;
                    return plain;
                }
            }
            line.to_owned()
        })
        .collect();
    if changed {
        std::fs::write(BASE_CONF, lines.join("\n") + "\n")?;
    }
    Ok(changed)
}

fn systemd_dnsmasq() -> bool {
    find("systemctl").is_some() && ["/lib/systemd/system/dnsmasq.service", "/usr/lib/systemd/system/dnsmasq.service", "/etc/systemd/system/dnsmasq.service"].iter().any(|path| Path::new(path).exists())
}

/// DHCP for clients: the system dnsmasq service, or our own dnsmasq if there is none.
struct Dnsmasq {
    child: Option<std::process::Child>,
}

impl Dnsmasq {
    fn apply(&mut self, wanted: Option<&Dhcp>, previous: Option<&Dhcp>, all_interfaces: &[String]) -> io::Result<()> {
        if wanted == previous && (wanted.is_none() || systemd_dnsmasq() || self.child.is_some()) {
            return Ok(());
        }
        std::fs::create_dir_all(RUN_DIR)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(RUN_DIR, std::fs::Permissions::from_mode(0o755))?;
        }
        let conf_changed = wanted.map(|dhcp| &dhcp.nets) != previous.map(|dhcp| &dhcp.nets);
        if let Some(dhcp) = wanted {
            std::fs::write(OPTS_FILE, dnsmasq_opts(dhcp))?;
        }
        if systemd_dnsmasq() {
            let systemctl = find("systemctl").expect("checked");
            let interfaces: Vec<String> = wanted.map(|dhcp| dhcp.nets.iter().map(|net| net.interface.clone()).collect()).unwrap_or_default();
            let mut networkd_changed = Vec::new();
            for interface in all_interfaces {
                let own: Vec<(Ipv4Addr, u8)> = wanted.iter().flat_map(|dhcp| &dhcp.nets).filter(|net| &net.interface == interface && net.on_link.is_some()).map(|net| (net.address, net.subnet.prefix_len())).collect();
                if networkd_dropin(interface, interfaces.contains(interface).then_some(own.as_slice()))? {
                    networkd_changed.push(interface.clone());
                }
            }
            match wanted {
                Some(dhcp) => {
                    // An older DHCP config would serve the same range twice.
                    if Path::new(GATEWAY_CONF).exists() {
                        std::fs::rename(GATEWAY_CONF, format!("{GATEWAY_CONF}.disabled-by-kaonic-hub"))?;
                    }
                    let base = base_conf_dhcp(&interfaces, true)?;
                    let conf = dnsmasq_conf(dhcp, false);
                    let fresh = std::fs::read_to_string(SYSTEM_CONF).ok().as_deref() != Some(conf.as_str());
                    if fresh {
                        std::fs::write(SYSTEM_CONF, conf)?;
                    }
                    if fresh || base || conf_changed {
                        run_checked(&systemctl, &["restart".into(), "dnsmasq.service".into()])?;
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        if !run(&systemctl, &["is-active".into(), "--quiet".into(), "dnsmasq.service".into()])? {
                            // Never leave clients without DHCP: hand it back to networkd.
                            let _ = std::fs::remove_file(SYSTEM_CONF);
                            let _ = base_conf_dhcp(&interfaces, false);
                            for interface in &interfaces {
                                let _ = networkd_dropin(interface, None);
                            }
                            if let Some(networkctl) = find("networkctl") {
                                let _ = run(&networkctl, &["reload".to_owned()]);
                                for interface in &interfaces {
                                    let _ = run(&networkctl, &["reconfigure".to_owned(), interface.clone()]);
                                }
                            }
                            let _ = run(&systemctl, &["restart".into(), "dnsmasq.service".into()]);
                            return Err(io::Error::other("dnsmasq did not start with the DHCP config: DHCP given back to networkd, no routes pushed"));
                        }
                    } else {
                        // Only routes changed: dnsmasq re-reads the optsfile on SIGHUP.
                        run_checked(&systemctl, &["kill".into(), "-s".into(), "HUP".into(), "dnsmasq.service".into()])?;
                    }
                }
                None => {
                    let had = Path::new(SYSTEM_CONF).exists();
                    if had {
                        std::fs::remove_file(SYSTEM_CONF)?;
                    }
                    if base_conf_dhcp(all_interfaces, false)? || had {
                        run_checked(&systemctl, &["restart".into(), "dnsmasq.service".into()])?;
                    }
                }
            }
            if !networkd_changed.is_empty()
                && let Some(networkctl) = find("networkctl")
            {
                run_checked(&networkctl, &["reload".to_owned()])?;
                for interface in networkd_changed {
                    let _ = run(&networkctl, &["reconfigure".to_owned(), interface]);
                }
            }
            return Ok(());
        }
        // Our own dnsmasq: restart when networks change, SIGHUP for new routes.
        let running = self.child.as_mut().is_some_and(|child| matches!(child.try_wait(), Ok(None)));
        match wanted {
            Some(dhcp) if running && !conf_changed => {
                let pid = self.child.as_ref().map(|child| child.id() as i32).unwrap_or(0);
                // SAFETY: plain kill(2) on our own child.
                unsafe { libc::kill(pid, libc::SIGHUP) };
                let _ = dhcp;
            }
            Some(dhcp) => {
                self.stop();
                let dnsmasq = find("dnsmasq").ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "dnsmasq is missing: clients get no routes by DHCP"))?;
                let conf = PathBuf::from(RUN_DIR).join("dnsmasq-dhcp.conf");
                std::fs::write(&conf, dnsmasq_conf(dhcp, true))?;
                let child = Command::new(dnsmasq)
                    .args(["--keep-in-foreground", "--log-facility=-", &format!("--conf-file={}", conf.display()), "--pid-file="])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?;
                self.child = Some(child);
            }
            None => self.stop(),
        }
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Applies plans and remembers what it did.
pub struct Applier {
    applied: Plan,
    dnsmasq: Dnsmasq,
}

impl Default for Applier {
    fn default() -> Self {
        Self { applied: Plan::default(), dnsmasq: Dnsmasq { child: None } }
    }
}

impl Applier {
    /// Adds the wanted pool addresses on client interfaces and removes other pool addresses.
    fn addresses(&self, plan: &Plan, lan_interfaces: &[String]) -> io::Result<()> {
        let Some(pool) = plan.pool.or(self.applied.pool) else { return Ok(()) };
        let present = crate::kernel::interface_addresses();
        let ip = find("ip").ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ip is missing: the client network cannot be set up"))?;
        let mut interfaces: Vec<&String> = lan_interfaces.iter().chain(self.applied.addresses.iter().map(|(interface, _, _)| interface)).collect();
        interfaces.sort();
        interfaces.dedup();
        for (interface, address) in present.iter().filter(|(interface, address)| interfaces.contains(&interface) && pool.contains(*address)) {
            if !plan.addresses.iter().any(|(wanted_on, wanted, _)| wanted_on == interface && wanted == address) {
                // Prefix length unknown: try each.
                for length in [24u8, 25, 26, 27, 28, 29, 30] {
                    if run(&ip, &args(&["addr", "del", &format!("{address}/{length}"), "dev", interface]))? {
                        break;
                    }
                }
            }
        }
        for (interface, address, length) in &plan.addresses {
            if !present.iter().any(|(name, existing)| name == interface && existing == address) {
                run_checked(&ip, &args(&["addr", "add", &format!("{address}/{length}"), "brd", "+", "dev", interface]))?;
            }
        }
        Ok(())
    }

    /// Makes the kernel and DHCP match `plan`.
    pub fn apply(&mut self, tun: &str, plan: &Plan, lan_interfaces: &[String]) -> io::Result<()> {
        let iptables = find("iptables").ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "iptables is missing: client networks cannot be shared"))?;
        // Skip if already on (a container's /proc/sys may be read-only).
        if plan.ip_forward && std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").map_or(true, |text| text.trim() != "1") {
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
        }
        fill_chain(&iptables, "nat", "PREROUTING", CHAIN_PRE, &["-i", tun], &plan.nat_pre)?;
        fill_chain(&iptables, "nat", "POSTROUTING", CHAIN_POST, &[], &plan.nat_post)?;
        fill_chain(&iptables, "mangle", "FORWARD", CHAIN_MSS, &[], &plan.mss)?;
        fill_chain(&iptables, "filter", "FORWARD", CHAIN_FWD, &[], &plan.forward)?;

        self.addresses(plan, lan_interfaces)?;

        if self.applied.uplink != plan.uplink {
            if let Some(old) = &self.applied.uplink {
                for route in &old.routes {
                    let _ = crate::tun::remove_uplink_route(tun, route, UPLINK_METRIC);
                }
            }
            if let Some(uplink) = &plan.uplink {
                for route in &uplink.routes {
                    crate::tun::add_uplink_route(tun, route, UPLINK_METRIC)?;
                }
            }
        }
        self.dnsmasq.apply(plan.dhcp.as_ref(), self.applied.dhcp.as_ref(), lan_interfaces)?;
        self.applied = plan.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    const ME: &str = "c2b3d952f91803b4890804e0aa16d84e";
    const OTHER: &str = "f6a2d6196f686da0e005c701f1d484fb";

    #[test]
    fn client_networks_map_one_to_one_into_the_pool() {
        let pool = cidr("10.78.0.0/16");
        let lan = cidr("192.168.10.0/24");
        let mine = mapped_subnet(ME, &lan, &pool, 0);
        assert!(pool.overlaps(&mine) && mine.prefix_len() == 24 && mine.network().octets()[3] == 0);
        assert_eq!(mine, mapped_subnet(ME, &lan, &pool, 0), "the same node always picks the same");
        assert_ne!(mine, mapped_subnet(OTHER, &lan, &pool, 0), "another node picks another");
        assert_ne!(mine, mapped_subnet(ME, &lan, &pool, 1), "the next attempt moves");
        let half = mapped_subnet(ME, &cidr("192.168.10.128/25"), &pool, 0);
        assert_eq!((half.prefix_len(), half.network().octets()[3]), (25, 128));
        assert_eq!(mapped_subnet(ME, &cidr("10.40.0.0/16"), &pool, 0), cidr("10.40.0.0/16"), "wider than /24: as it is");
    }

    #[test]
    fn gateway_announcements_round_trip() {
        let routes = vec![cidr("0.0.0.0/0"), cidr("192.168.50.0/24")];
        assert_eq!(decode_gateway(&encode_gateway(&routes)), Some(routes));
        assert_eq!(decode_gateway(&encode_gateway(&[])), Some(Vec::new()));
        assert_eq!(decode_gateway(b"KVG1\x01\x00"), None);
        assert_eq!(decode_gateway(b"KVH1\x00"), None);
    }

    fn lans() -> Vec<LanNet> {
        vec![LanNet { interface: "br0".into(), subnet: cidr("192.168.10.0/24"), mapped: cidr("10.78.7.0/24"), address: Some(Ipv4Addr::new(192, 168, 10, 1)), base: None }]
    }

    fn rules(rules: &[Vec<String>]) -> Vec<String> {
        rules.iter().map(|rule| rule.join(" ")).collect()
    }

    fn input<'a>(lans: &'a [LanNet], settings: &'a ShareSettings, egress: Option<&'a str>, remote: &'a [Cidr], uplink: Option<UplinkRoutes>) -> PlanInput<'a> {
        PlanInput { tun: "kaonic0", mtu: 792, tunnel_network: cidr("10.77.0.0/16"), lans, settings, egress, remote_sources: remote, uplink }
    }

    #[test]
    fn out_of_the_box_a_lan_is_mapped_forwarded_clamped_and_given_the_routes() {
        let settings = ShareSettings::default();
        let lans = lans();
        let remote = [cidr("10.78.9.0/24"), cidr("172.20.0.0/16")];
        let plan = plan(&input(&lans, &settings, None, &remote, None));
        assert_eq!(rules(&plan.nat_pre), vec!["-d 10.78.7.0/24 -j NETMAP --to 192.168.10.0/24"]);
        assert_eq!(rules(&plan.nat_post), vec!["-o kaonic0 -s 192.168.10.0/24 -j NETMAP --to 10.78.7.0/24"]);
        assert_eq!(rules(&plan.forward), vec!["-i br0 -o kaonic0 -j ACCEPT", "-i kaonic0 -o br0 -j ACCEPT"]);
        assert_eq!(rules(&plan.mss), vec!["-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 752"]);
        assert!(plan.ip_forward);
        let dhcp = plan.dhcp.expect("routes are pushed by default");
        assert!(!dhcp.router, "no upstream: no router, the client keeps its own internet");
        // 10.78.9.0/24 is inside the pool; 172.20.0.0/16 is advertised as is.
        assert_eq!(dhcp.routes, vec![cidr("10.77.0.0/16"), cidr("10.78.0.0/16"), cidr("172.20.0.0/16")]);
        let opts = dnsmasq_opts(&dhcp);
        assert!(opts.contains("tag:kh-br0,option:classless-static-route,10.77.0.0/16,192.168.10.1,10.78.0.0/16,192.168.10.1,172.20.0.0/16,192.168.10.1,192.168.10.0/24,0.0.0.0\n"), "{opts}");
        assert!(opts.contains("tag:kh-br0,249,10.77.0.0/16,192.168.10.1,"));
        // No router or DNS, except a router for Android.
        assert!(opts.contains("tag:kh-br0,tag:kh-noroutes,option:router,192.168.10.1\ntag:kh-br0,tag:!kh-noroutes,option:router\ntag:kh-br0,option:dns-server\n"), "{opts}");
        let never = ShareSettings { lan_router: LanRouter::Never, ..ShareSettings::default() };
        let opts = dnsmasq_opts(&super::plan(&input(&lans, &never, None, &remote, None)).dhcp.unwrap());
        assert!(opts.contains("tag:kh-br0,option:router\ntag:kh-br0,option:dns-server\n") && !opts.contains("kh-noroutes"), "dnsmasq must not offer itself as router");
        let conf = dnsmasq_conf(&dhcp, false);
        assert!(conf.contains("dhcp-range=set:kh-br0,192.168.10.10,192.168.10.109,255.255.255.0,10m\n"), "{conf}");
        assert!(conf.contains("dhcp-optsfile=/run/kaonic-hub-dhcp/dhcp-opts") && !conf.contains("port=0"));
        assert!(conf.contains("dhcp-vendorclass=set:kh-noroutes,android-dhcp\n"));
        assert!(dnsmasq_conf(&dhcp, true).contains("port=0\nbind-dynamic\ninterface=br0\n"));
    }

    #[test]
    fn the_nodes_own_network_is_served_routed_next_to_the_setup_address() {
        let settings = ShareSettings::default();
        let lans = vec![LanNet { interface: "br0".into(), subnet: cidr("10.78.7.0/24"), mapped: cidr("10.78.7.0/24"), address: Some(Ipv4Addr::new(10, 78, 7, 1)), base: Some(cidr("192.168.10.0/24")) }];
        let remote = [cidr("10.78.9.0/24")];
        let plan = plan(&input(&lans, &settings, None, &remote, None));
        assert!(plan.nat_pre.is_empty(), "no address is rewritten on the way in");
        // Only clients still on the shipped network are masqueraded.
        assert_eq!(rules(&plan.nat_post), vec!["-o kaonic0 -s 192.168.10.0/24 -j MASQUERADE"]);
        assert_eq!(rules(&plan.forward), vec!["-i br0 -o kaonic0 -j ACCEPT", "-i kaonic0 -o br0 -j ACCEPT"]);
        assert_eq!(plan.addresses, vec![("br0".to_owned(), Ipv4Addr::new(10, 78, 7, 1), 24)]);
        assert_eq!(plan.pool, Some(cidr("10.78.0.0/16")));
        let dhcp = plan.dhcp.expect("DHCP serves it");
        let conf = dnsmasq_conf(&dhcp, false);
        assert!(conf.contains("dhcp-range=set:kh-br0,10.78.7.10,10.78.7.109,255.255.255.0,10m\n"), "{conf}");
        let opts = dnsmasq_opts(&dhcp);
        // Other nodes' networks via the node; its own and the setup network on-link.
        assert!(opts.contains("tag:kh-br0,option:classless-static-route,10.77.0.0/16,10.78.7.1,10.78.0.0/16,10.78.7.1,10.78.7.0/24,0.0.0.0,192.168.10.0/24,0.0.0.0\n"), "{opts}");
        assert!(opts.contains("tag:kh-br0,tag:kh-noroutes,option:router,10.78.7.1\n"), "{opts}");
    }

    #[test]
    fn android_fallback_makes_the_node_the_router() {
        let settings = ShareSettings { lan_router: LanRouter::Always, ..ShareSettings::default() };
        let lans = lans();
        let dhcp = plan(&input(&lans, &settings, None, &[], None)).dhcp.unwrap();
        assert!(dhcp.router);
        let opts = dnsmasq_opts(&dhcp);
        assert!(opts.contains("classless-static-route,0.0.0.0/0,192.168.10.1,"), "RFC 3442: the default goes in 121 too");
        assert!(opts.contains("tag:kh-br0,option:router,192.168.10.1\ntag:kh-br0,option:dns-server,1.1.1.1,8.8.8.8\n"));
        let off = ShareSettings { push_routes: false, ..ShareSettings::default() };
        assert_eq!(plan(&input(&lans, &off, None, &[], None)).dhcp, None);
    }

    #[test]
    fn a_gateway_masquerades_peers_and_its_own_clients() {
        let settings = ShareSettings::default();
        let lans = lans();
        let remote = [cidr("10.78.9.0/24")];
        let plan = plan(&input(&lans, &settings, Some("wlan0"), &remote, None));
        let post = rules(&plan.nat_post);
        for source in ["10.77.0.0/16", "10.78.9.0/24", "192.168.10.0/24"] {
            assert!(post.contains(&format!("-o wlan0 -s {source} -j MASQUERADE")), "{source}");
        }
        let forward = rules(&plan.forward);
        assert!(forward.contains(&"-i kaonic0 -o wlan0 -j ACCEPT".to_owned()));
        assert!(forward.contains(&"-i wlan0 -o kaonic0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_owned()));
        assert!(!forward.contains(&"-i wlan0 -o kaonic0 -j ACCEPT".to_owned()), "nothing unsolicited from the uplink into the mesh");
        assert!(plan.dhcp.unwrap().router, "auto: the gateway's clients get it as router");
    }

    #[test]
    fn an_uplink_routes_through_the_tunnel_and_tells_clients() {
        let settings = ShareSettings::default();
        let lans = lans();
        let everything = UplinkRoutes { peer: OTHER.into(), default_route: true, routes: vec![cidr("0.0.0.0/0")] };
        let plan_all = plan(&input(&lans, &settings, None, &[], Some(everything.clone())));
        assert_eq!(plan_all.uplink, Some(everything));
        assert!(plan_all.dhcp.unwrap().router);
        let some = UplinkRoutes { peer: OTHER.into(), default_route: false, routes: vec![cidr("198.51.100.0/24")] };
        let dhcp = plan(&input(&lans, &settings, None, &[], Some(some))).dhcp.unwrap();
        assert!(!dhcp.router, "only some destinations: pushed as routes, no router");
        assert!(dhcp.routes.contains(&cidr("198.51.100.0/24")));
    }

    #[test]
    fn nothing_shared_means_no_rules() {
        let settings = ShareSettings { share_lans: false, ..ShareSettings::default() };
        let plan = plan(&input(&[], &settings, None, &[], None));
        assert_eq!(plan, Plan::default());
    }
}

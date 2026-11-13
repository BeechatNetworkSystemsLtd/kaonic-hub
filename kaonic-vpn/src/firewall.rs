//! Blocks this hub's management ports on the tunnel: the web UI and API (TCP 80, 443) and
//! PTT audio (UDP 8781). Clients behind other nodes can reach the advertised networks, but
//! not this hub's management.
//!
//! Uses nftables if `nft` exists, else iptables. Running it again replaces the rules.
//! Blocking: call it off the async runtime.

use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const TABLE: &str = "kaonic_vpn";
const CHAIN: &str = "KAONIC_VPN";

fn find(program: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"].iter().map(|dir| PathBuf::from(dir).join(program)).find(|path| path.exists())
}

/// The nftables ruleset, in its own table so other rules are untouched.
pub fn nft_script(interface: &str, tcp: &[u16], udp: &[u16]) -> String {
    let ports = |ports: &[u16]| ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
    let mut script = format!("table inet {TABLE} {{\n  chain input {{\n    type filter hook input priority -10; policy accept;\n");
    if !tcp.is_empty() {
        script += &format!("    iifname \"{interface}\" tcp dport {{ {} }} drop\n", ports(tcp));
    }
    if !udp.is_empty() {
        script += &format!("    iifname \"{interface}\" udp dport {{ {} }} drop\n", ports(udp));
    }
    script + "  }\n}\n"
}

/// The iptables commands: create and flush our chain, then add the drop rules.
pub fn iptables_commands(interface: &str, tcp: &[u16], udp: &[u16]) -> Vec<Vec<String>> {
    let mut commands: Vec<Vec<String>> = vec![vec!["-N".into(), CHAIN.into()], vec!["-F".into(), CHAIN.into()]];
    for (proto, ports) in [("tcp", tcp), ("udp", udp)] {
        for port in ports {
            commands.push(["-A", CHAIN, "-i", interface, "-p", proto, "--dport", &port.to_string(), "-j", "DROP"].map(String::from).to_vec());
        }
    }
    commands
}

fn run(program: &PathBuf, args: &[String]) -> io::Result<bool> {
    Ok(Command::new(program).args(args).stdout(Stdio::null()).stderr(Stdio::null()).status()?.success())
}

/// Installs or replaces the rules. Returns the tool used.
pub fn protect(interface: &str, tcp: &[u16], udp: &[u16]) -> io::Result<&'static str> {
    if let Some(nft) = find("nft") {
        // Delete our old table first so rules do not stack.
        let _ = run(&nft, &["delete".into(), "table".into(), "inet".into(), TABLE.into()]);
        let mut child = Command::new(&nft).args(["-f", "-"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn()?;
        // Always waited for, even if writing failed, so no zombie is left.
        let written = child.stdin.take().expect("piped").write_all(nft_script(interface, tcp, udp).as_bytes());
        let output = child.wait_with_output()?;
        match written {
            Ok(()) if output.status.success() => return Ok("nftables"),
            Ok(()) => log::warn!("vpn: nft refused the rules ({}); trying iptables", String::from_utf8_lossy(&output.stderr).trim()),
            Err(error) => log::warn!("vpn: could not give nft the rules ({error}); trying iptables"),
        }
    }
    let Some(iptables) = find("iptables") else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "neither nft nor iptables: the hub's API is reachable through the VPN"));
    };
    for args in iptables_commands(interface, tcp, udp) {
        // `-N` fails if the chain exists; that is fine.
        if !run(&iptables, &args)? && args[0] != "-N" {
            return Err(io::Error::other(format!("iptables {} failed", args.join(" "))));
        }
    }
    let jump: Vec<String> = ["INPUT", "-i", interface, "-j", CHAIN].map(String::from).to_vec();
    let check: Vec<String> = std::iter::once("-C".to_owned()).chain(jump.iter().cloned()).collect();
    if !run(&iptables, &check)? {
        let insert: Vec<String> = ["-I", "INPUT", "1"].map(String::from).into_iter().chain(jump[1..].iter().cloned()).collect();
        if !run(&iptables, &insert)? {
            return Err(io::Error::other("iptables could not add the jump to the VPN chain"));
        }
    }
    Ok("iptables")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rules_name_only_the_tunnel_and_the_given_ports() {
        let script = nft_script("kaonic0", &[80, 443], &[8781]);
        assert!(script.contains("table inet kaonic_vpn"));
        assert!(script.contains("iifname \"kaonic0\" tcp dport { 80, 443 } drop"));
        assert!(script.contains("iifname \"kaonic0\" udp dport { 8781 } drop"));
        assert!(!nft_script("kaonic0", &[], &[8781]).contains("tcp"));
        let commands = iptables_commands("kaonic0", &[443], &[8781]);
        assert_eq!(commands[0], vec!["-N", "KAONIC_VPN"]);
        assert_eq!(commands[1], vec!["-F", "KAONIC_VPN"]);
        assert_eq!(commands[2].join(" "), "-A KAONIC_VPN -i kaonic0 -p tcp --dport 443 -j DROP");
        assert_eq!(commands[3].join(" "), "-A KAONIC_VPN -i kaonic0 -p udp --dport 8781 -j DROP");
    }
}

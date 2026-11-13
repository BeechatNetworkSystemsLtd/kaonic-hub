# kaonic-vpn

The mesh VPN: IPv4 between Kaonic nodes over their mesh links, through a TUN device
(`kaonic0`). Phones and laptops on one node can reach the clients of every other node.

```rust
let vpn = kaonic_vpn::Vpn::start(links, mesh.identity_hash(), config).await?;
println!("{:?}", vpn.status());
```

## How it works

- **Addresses.** Each node gets a tunnel address in `10.77.0.0/16`, picked from its
  identity. Nothing to configure, and a peer cannot claim another node's address.
- **HELLO.** Peers tell each other their address and the networks they offer. A network
  that is too wide or clashes with one of ours is refused, so a peer cannot take over our
  traffic.
- **Packets.** Unicast goes to the peer that owns the destination; broadcast and
  multicast go to every peer, rate-limited. A packet from a peer is accepted only if its
  source belongs to that peer.
- **Management stays local.** The web UI, API and PTT audio are not reachable through
  the tunnel.

## Clients

- Each node gives its clients addresses from its own /24 in `10.78.0.0/16`, so a
  client's address is the same for everyone on the mesh.
- DHCP gives clients the routes to the mesh, but no default route: a laptop keeps its
  own internet.
- A node with internet can act as a **gateway** for its peers; others can route through
  it (**uplink**).

## Multicast

Apps that find each other by multicast or broadcast (ATAK, for one) would not see anyone
behind another node. Forwarding rules carry that traffic across the mesh. By default all
of it goes, except LAN control traffic (mDNS, SSDP, NetBIOS) and DHCP.

## On the device

Needs root (or `CAP_NET_ADMIN`), and `ip`, `iptables` or `nft`, and `dnsmasq`.

## Tests

```sh
cargo test -p kaonic-vpn
```

The tests run several nodes in one process on the emulated radio, with in-memory TUN
devices: no root, no board.

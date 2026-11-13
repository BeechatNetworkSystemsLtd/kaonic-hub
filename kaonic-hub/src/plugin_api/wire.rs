//! Plugin traffic on the air.
//!
//! On a link, a mux frame on stream [`STREAM`]:
//!
//! ```text
//! data    = plugin u64 | channel u8 | payload       a message to that plugin
//! control = "KPR2" | { plugin u64 }                  the plugins running here (mesh ones)
//! ```
//! `plugin` is the plugin's mesh hash: the first 8 bytes of SHA-256 of its id, big-endian
//! (`kaonic_hub_installer::names::mesh_hash`; the installer refuses two plugins with one).
//!
//! On the GROUP channel, inside the encrypted packet (PTT's packets start with their version,
//! 2, so it never takes these):
//!
//! ```text
//! "KPB2" | sender [16] | nonce u64 | plugin u64 | channel u8 | payload
//! ```
//! `nonce` is random per broadcast: a receiver drops one it has seen.

/// The mux stream of plugin traffic (1-5 are the VPN, group keys, radio and remote).
pub const STREAM: u8 = 16;
/// Bytes before a message's payload in a data frame.
pub const DATA_HEADER: usize = 9;
const RUNNING: &[u8; 4] = b"KPR2";
const BROADCAST: &[u8; 4] = b"KPB2";
/// Bytes before a broadcast's payload.
pub const BROADCAST_HEADER: usize = 4 + 16 + 8 + DATA_HEADER;
/// At most this many plugins in one running list.
const MAX_RUNNING: usize = 64;

/// The 8-byte name of a plugin on the air.
pub fn id_hash(id: &str) -> u64 {
    kaonic_hub_installer::names::mesh_hash(id)
}

pub fn encode_data(plugin: u64, channel: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_HEADER + data.len());
    out.extend_from_slice(&plugin.to_be_bytes());
    out.push(channel);
    out.extend_from_slice(data);
    out
}

pub fn decode_data(payload: &[u8]) -> Option<(u64, u8, &[u8])> {
    let (plugin, rest) = payload.split_first_chunk::<8>()?;
    let (&channel, data) = rest.split_first()?;
    Some((u64::from_be_bytes(*plugin), channel, data))
}

pub fn encode_running(plugins: &[u64]) -> Vec<u8> {
    let mut out = RUNNING.to_vec();
    for plugin in plugins.iter().take(MAX_RUNNING) {
        out.extend_from_slice(&plugin.to_be_bytes());
    }
    out
}

pub fn decode_running(payload: &[u8]) -> Option<Vec<u64>> {
    let rest = payload.strip_prefix(RUNNING)?;
    if !rest.len().is_multiple_of(8) || rest.len() / 8 > MAX_RUNNING {
        return None;
    }
    Some(rest.as_chunks::<8>().0.iter().map(|chunk| u64::from_be_bytes(*chunk)).collect())
}

pub fn encode_broadcast(sender: &[u8; 16], nonce: u64, plugin: u64, channel: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BROADCAST_HEADER + data.len());
    out.extend_from_slice(BROADCAST);
    out.extend_from_slice(sender);
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(&encode_data(plugin, channel, data));
    out
}

/// A broadcast as heard.
#[derive(Debug, PartialEq, Eq)]
pub struct Broadcast<'a> {
    pub sender: [u8; 16],
    pub nonce: u64,
    pub plugin: u64,
    pub channel: u8,
    pub data: &'a [u8],
}

/// None for anything else on the channel (voice).
pub fn decode_broadcast(packet: &[u8]) -> Option<Broadcast<'_>> {
    let rest = packet.strip_prefix(BROADCAST)?;
    let (sender, rest) = rest.split_first_chunk::<16>()?;
    let (nonce, rest) = rest.split_first_chunk::<8>()?;
    let (plugin, channel, data) = decode_data(rest)?;
    Some(Broadcast { sender: *sender, nonce: u64::from_be_bytes(*nonce), plugin, channel, data })
}

/// A node id (32 hex characters) as bytes.
pub fn node_bytes(id: &str) -> Option<[u8; 16]> {
    if id.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(id.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

pub fn node_hex(bytes: &[u8; 16]) -> String {
    crate::random::hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let plugin = id_hash("echo");
        assert_eq!(plugin, id_hash("echo"));
        assert_ne!(plugin, id_hash("echo2"));
        let frame = encode_data(plugin, 7, b"hello");
        assert_eq!(frame.len(), DATA_HEADER + 5);
        assert_eq!(decode_data(&frame), Some((plugin, 7, &b"hello"[..])));
        assert_eq!(decode_data(&frame[..8]), None);
        assert_eq!(decode_data(&encode_data(plugin, 0, b"")), Some((plugin, 0, &b""[..])));

        let running = encode_running(&[1, plugin]);
        assert_eq!(decode_running(&running), Some(vec![1, plugin]));
        assert_eq!(decode_running(&running[..running.len() - 1]), None);
        assert_eq!(decode_running(b"KPR1"), None, "the 4-byte format is not read");
        assert_eq!(decode_running(b"KPR2"), Some(vec![]));

        let sender = node_bytes("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(node_hex(&sender), "00112233445566778899aabbccddeeff");
        let broadcast = encode_broadcast(&sender, 42, plugin, 3, b"voice");
        assert_eq!(broadcast.len(), BROADCAST_HEADER + 5);
        assert_eq!(decode_broadcast(&broadcast), Some(Broadcast { sender, nonce: 42, plugin, channel: 3, data: &b"voice"[..] }));
        assert!(decode_broadcast(&broadcast[..BROADCAST_HEADER - 1]).is_none());
        let mut old = broadcast.clone();
        old[3] = b'1';
        assert!(decode_broadcast(&old).is_none());
        assert!(node_bytes("0011").is_none() && node_bytes(&"zz".repeat(16)).is_none());
    }

    #[test]
    fn push_to_talk_never_takes_a_plugin_broadcast_nor_the_bridge_a_voice_packet() {
        let sender = [9u8; 16];
        let broadcast = encode_broadcast(&sender, 1, id_hash("p"), 1, &[0u8; 40]);
        assert!(kaonic_ptt::Packet::decode(&broadcast).is_none());
        assert_ne!(broadcast[0], kaonic_ptt::VERSION);
        let voice = kaonic_ptt::Packet {
            flags: kaonic_ptt::flags::START,
            ttl: 4,
            epoch: 1,
            talker: [1, 2, 3, 4],
            burst: 1,
            seq: 0,
            counter: 1,
            codec: kaonic_ptt::codec::OPUS16,
            frames: vec![vec![1; 20]],
            signature: None,
        };
        assert!(decode_broadcast(&voice.encode()).is_none());
    }
}

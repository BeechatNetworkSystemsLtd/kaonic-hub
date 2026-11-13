//! The voice packet, carried inside the encrypted
//! GROUP data, and the admin's signature on every packet of its bursts.
//!
//! ```text
//! 0   1  version (1)
//! 1   1  flags: 0x01 burst start · 0x02 burst end · 0x04 admin priority · 0x08 signed
//! 2   1  ttl (hops left)
//! 3   1  key epoch
//! 4   4  talker: first 4 bytes of the talker's identity hash
//! 8   2  burst id
//! 10  2  seq of the first frame in this packet
//! 12  4  burst counter: grows with every burst of this talker, across restarts
//! 16  1  codec
//! 17  1  frame count n
//! 18  …  n × { len u8 | frame }
//! …   64 Ed25519 signature, only with flag 0x08 (every packet of an admin burst)
//! ```
//! The GROUP encryption authenticates packets to key holders, but says nothing about when
//! they were sent: the burst counter lets listeners refuse a recorded burst played again
//! ([`crate::Replay`]). It is a counter, not a time, because the nodes' clocks are not set.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const VERSION: u8 = 2;

pub mod flags {
    pub const START: u8 = 0x01;
    pub const END: u8 = 0x02;
    pub const ADMIN: u8 = 0x04;
    pub const SIGNED: u8 = 0x08;
}

pub mod codec {
    pub const OPUS16: u8 = 1;
    pub const CODEC2_3200: u8 = 2;
}

/// Frames in one packet at most.
pub const MAX_FRAMES: usize = 16;
pub const HEADER: usize = 18;
const CONTEXT: &[u8] = b"kaonic-ptt-admin v2\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub flags: u8,
    pub ttl: u8,
    pub epoch: u8,
    pub talker: [u8; 4],
    pub burst: u16,
    /// The seq of the first frame; the others follow it.
    pub seq: u16,
    /// The talker's burst counter: the same on every packet of a burst, higher for each new one.
    pub counter: u32,
    pub codec: u8,
    pub frames: Vec<Vec<u8>>,
    pub signature: Option<[u8; 64]>,
}

impl Packet {
    pub fn encode(&self) -> Vec<u8> {
        let frames = self.frames.iter().take(MAX_FRAMES);
        let mut out = Vec::with_capacity(HEADER + self.frames.iter().map(|frame| frame.len() + 1).sum::<usize>() + 64);
        out.push(VERSION);
        let flags = if self.signature.is_some() { self.flags | flags::SIGNED } else { self.flags & !flags::SIGNED };
        out.extend_from_slice(&[flags, self.ttl, self.epoch]);
        out.extend_from_slice(&self.talker);
        out.extend_from_slice(&self.burst.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.push(self.codec);
        out.push(frames.len() as u8);
        for frame in frames {
            let length = frame.len().min(255);
            out.push(length as u8);
            out.extend_from_slice(&frame[..length]);
        }
        if let Some(signature) = &self.signature {
            out.extend_from_slice(signature);
        }
        out
    }

    /// Strict: a known version, at most 16 frames, the signature present exactly when
    /// flagged, nothing left over.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let (header, mut rest) = data.split_first_chunk::<HEADER>()?;
        if header[0] != VERSION {
            return None;
        }
        let count = usize::from(header[17]);
        if count > MAX_FRAMES {
            return None;
        }
        let mut frames = Vec::with_capacity(count);
        for _ in 0..count {
            let (&length, after) = rest.split_first()?;
            let (frame, after) = after.split_at_checked(usize::from(length))?;
            frames.push(frame.to_vec());
            rest = after;
        }
        let signature = if header[1] & flags::SIGNED != 0 {
            Some(<[u8; 64]>::try_from(rest).ok()?)
        } else if rest.is_empty() {
            None
        } else {
            return None;
        };
        Some(Self {
            flags: header[1],
            ttl: header[2],
            epoch: header[3],
            talker: [header[4], header[5], header[6], header[7]],
            burst: u16::from_be_bytes([header[8], header[9]]),
            seq: u16::from_be_bytes([header[10], header[11]]),
            counter: u32::from_be_bytes([header[12], header[13], header[14], header[15]]),
            codec: header[16],
            frames,
            signature,
        })
    }

    /// What identifies a packet among copies relayed by several nodes.
    pub fn key(&self) -> ([u8; 4], u16, u16) {
        (self.talker, self.burst, self.seq)
    }

    /// Flagged as the admin's. Only a verified signature ([`verify_admin`]) makes it so.
    pub fn is_admin(&self) -> bool {
        self.flags & flags::ADMIN != 0
    }

    pub fn is_start(&self) -> bool {
        self.flags & flags::START != 0
    }

    pub fn is_end(&self) -> bool {
        self.flags & flags::END != 0
    }
}

/// What the admin signs: everything but the ttl (relays lower it) and the signature. Every
/// packet of an admin burst is signed: a group member holds the key too and could otherwise
/// add its own packets to the admin's burst.
pub fn admin_signed_bytes(packet: &Packet) -> Vec<u8> {
    let mut out = CONTEXT.to_vec();
    out.push(VERSION);
    out.push(packet.flags | flags::ADMIN | flags::SIGNED);
    out.push(packet.epoch);
    out.extend_from_slice(&packet.talker);
    out.extend_from_slice(&packet.burst.to_be_bytes());
    out.extend_from_slice(&packet.seq.to_be_bytes());
    out.extend_from_slice(&packet.counter.to_be_bytes());
    out.push(packet.codec);
    out.push(packet.frames.len() as u8);
    for frame in &packet.frames {
        out.push(frame.len().min(255) as u8);
        out.extend_from_slice(&frame[..frame.len().min(255)]);
    }
    out
}

/// Flags the packet as a signed admin packet and signs it.
pub fn sign_admin(packet: &mut Packet, key: &SigningKey) {
    packet.flags |= flags::ADMIN | flags::SIGNED;
    packet.signature = Some(key.sign(&admin_signed_bytes(packet)).to_bytes());
}

/// Whether the admin (`admin_key`, its Ed25519 public key) signed this packet.
pub fn verify_admin(packet: &Packet, admin_key: &[u8; 32]) -> bool {
    let Some(signature) = &packet.signature else { return false };
    if packet.flags & (flags::ADMIN | flags::SIGNED) != flags::ADMIN | flags::SIGNED {
        return false;
    }
    let Ok(key) = VerifyingKey::from_bytes(admin_key) else { return false };
    key.verify_strict(&admin_signed_bytes(packet), &Signature::from_bytes(signature)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> Packet {
        Packet { flags: flags::START, ttl: 4, epoch: 3, talker: [1, 2, 3, 4], burst: 0x1234, seq: 7, counter: 41, codec: codec::OPUS16, frames: vec![vec![9; 30], vec![], vec![5; 255]], signature: None }
    }

    #[test]
    fn round_trips_with_and_without_signature() {
        let packet = sample();
        let bytes = packet.encode();
        assert_eq!(bytes.len(), HEADER + 31 + 1 + 256);
        assert_eq!(Packet::decode(&bytes), Some(packet.clone()));
        let mut signed = packet;
        sign_admin(&mut signed, &SigningKey::from_bytes(&[7; 32]));
        assert_eq!(Packet::decode(&signed.encode()), Some(signed));
    }

    #[test]
    fn garbage_is_refused() {
        let bytes = sample().encode();
        assert_eq!(Packet::decode(&bytes[..bytes.len() - 1]), None);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(Packet::decode(&trailing), None);
        let mut version = bytes.clone();
        version[0] = 1;
        assert_eq!(Packet::decode(&version), None);
        let mut too_many = bytes.clone();
        too_many[17] = 17;
        assert_eq!(Packet::decode(&too_many), None);
        let mut claims_signed = bytes;
        claims_signed[1] |= flags::SIGNED;
        assert_eq!(Packet::decode(&claims_signed), None);
        assert_eq!(Packet::decode(&[]), None);
    }

    #[test]
    fn admin_signatures() {
        let admin = SigningKey::from_bytes(&[7; 32]);
        let public = admin.verifying_key().to_bytes();
        let mut packet = sample();
        assert!(!verify_admin(&packet, &public));
        sign_admin(&mut packet, &admin);
        assert!(packet.is_admin());
        assert!(verify_admin(&packet, &public));
        // A relay lowering the ttl keeps it valid.
        let mut relayed = packet.clone();
        relayed.ttl -= 1;
        assert!(verify_admin(&relayed, &public));
        assert!(!verify_admin(&packet, &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()));
        let mut tampered = packet.clone();
        tampered.frames[0][0] ^= 1;
        assert!(!verify_admin(&tampered, &public));
        let mut other_burst = packet;
        other_burst.burst += 1;
        assert!(!verify_admin(&other_burst, &public));
    }
}

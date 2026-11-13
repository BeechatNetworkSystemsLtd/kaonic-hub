//! UDP audio sessions for native clients (phone app, ATAK plugin), in the kaonic-audio-ptt
//! plugin's protocol (its PROTOCOL.md §1-2a), so existing clients work unchanged:
//!
//! ```text
//! "KU" | version 1 | type (1 AUDIO, 2 KEEPALIVE, 3 KEY, 4 UNKEY) | token u32 | seq u32 | payload
//! ```
//! AUDIO carries one 20 ms frame of PCM s16le mono 16 kHz. A client learns nothing until it
//! sends a KEEPALIVE (its address is taken from it); KEY is answered KEY, or UNKEY when the
//! floor is taken; a keyed client silent for 500 ms is unkeyed; a session silent for 30 s
//! ends. The token comes from `POST /ptt/sessions`, over HTTPS.
//!
//! The token travels in the clear in every datagram, so it is not trusted alone:
//! - the first datagram pins the session to its sender's address, and datagrams for it from
//!   any other address are ignored (a client that moves, say from USB to Wi-Fi, asks for a
//!   new session). Audio goes only to the pinned address, so a datagram with a forged source
//!   cannot turn the device into a reflector;
//! - a session belongs to the sign-in that created it, and ends with it (logout, password
//!   change, expiry);
//! - nothing is answered through the mesh VPN.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::broadcast;

use super::opus::FRAME_SAMPLES;
use super::{Control, Ptt, Source};

const MAGIC: &[u8; 2] = b"KU";
const VERSION: u8 = 1;
pub const AUDIO: u8 = 1;
pub const KEEPALIVE: u8 = 2;
pub const KEY: u8 = 3;
pub const UNKEY: u8 = 4;
const HEADER: usize = 12;

pub const KEEPALIVE_INTERVAL_MS: u64 = 1000;
pub const UNKEY_TIMEOUT_MS: u64 = 500;
/// A session with no traffic for this long ends.
const SESSION_IDLE: Duration = Duration::from_secs(30);
/// Audio goes to clients heard within this long.
const LISTENING: Duration = Duration::from_secs(5);
/// At most this many sessions at once.
const MAX_SESSIONS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub kind: u8,
    pub token: u32,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl Datagram {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.payload.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.kind);
        out.extend_from_slice(&self.token.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let rest = data.strip_prefix(MAGIC)?;
        let (&[version, kind], rest) = rest.split_first_chunk::<2>()?;
        if version != VERSION || !(AUDIO..=UNKEY).contains(&kind) {
            return None;
        }
        let (token, rest) = rest.split_first_chunk::<4>()?;
        let (seq, payload) = rest.split_first_chunk::<4>()?;
        Some(Self { kind, token: u32::from_be_bytes(*token), seq: u32::from_be_bytes(*seq), payload: payload.to_vec() })
    }

    fn control(kind: u8, token: u32) -> Vec<u8> {
        Self { kind, token, seq: 0, payload: Vec::new() }.encode()
    }
}

/// One frame of PCM from an AUDIO payload; None unless it is exactly one frame.
pub fn pcm(payload: &[u8]) -> Option<Vec<i16>> {
    (payload.len() == FRAME_SAMPLES * 2).then(|| payload.as_chunks::<2>().0.iter().map(|pair| i16::from_le_bytes(*pair)).collect())
}

struct Session {
    /// Pinned by the first datagram.
    address: Option<SocketAddr>,
    last_heard: Instant,
    seq: u32,
    /// The sign-in (session token hash) that created it.
    owner: Vec<u8>,
}

/// What a datagram for a session means.
#[derive(Debug, PartialEq, Eq)]
enum Heard {
    /// The pinned client.
    Client,
    /// The first datagram of a session: its sender is now the client.
    Pinned,
    /// No such session, or not from its client: ignored.
    Ignored,
}

#[derive(Default)]
pub struct Sessions {
    sessions: Mutex<HashMap<u32, Session>>,
    port: OnceLock<u16>,
}

impl Sessions {
    /// A new session's token for the sign-in `owner`; None when there are too many.
    pub fn create(&self, owner: Vec<u8>) -> Option<u32> {
        let mut sessions = self.sessions.lock().expect("ptt sessions lock");
        if sessions.len() >= MAX_SESSIONS {
            return None;
        }
        let token = loop {
            let token = u32::from_be_bytes(crate::random::bytes::<4>().ok()?);
            if token != 0 && !sessions.contains_key(&token) {
                break token;
            }
        };
        sessions.insert(token, Session { address: None, last_heard: Instant::now(), seq: 0, owner });
        Some(token)
    }

    /// The UDP port sessions use, once it is open.
    pub fn port(&self) -> Option<u16> {
        self.port.get().copied()
    }

    /// Notes traffic from `address` on `token`.
    fn heard(&self, token: u32, address: SocketAddr) -> Heard {
        let mut sessions = self.sessions.lock().expect("ptt sessions lock");
        let Some(session) = sessions.get_mut(&token) else { return Heard::Ignored };
        let heard = match session.address {
            Some(pinned) if pinned == address => Heard::Client,
            Some(_) => return Heard::Ignored,
            None => {
                session.address = Some(address);
                Heard::Pinned
            }
        };
        session.last_heard = Instant::now();
        heard
    }

    fn remove(&self, token: u32) {
        self.sessions.lock().expect("ptt sessions lock").remove(&token);
    }

    /// The sign-ins that own sessions.
    fn owners(&self) -> Vec<Vec<u8>> {
        let sessions = self.sessions.lock().expect("ptt sessions lock");
        let mut owners: Vec<Vec<u8>> = sessions.values().map(|session| session.owner.clone()).collect();
        owners.sort();
        owners.dedup();
        owners
    }

    /// Ends every session of the sign-in `owner`; returns their tokens.
    fn end_owner(&self, owner: &[u8]) -> Vec<u32> {
        let mut sessions = self.sessions.lock().expect("ptt sessions lock");
        let gone: Vec<u32> = sessions.iter().filter(|(_, session)| session.owner == owner).map(|(token, _)| *token).collect();
        for token in &gone {
            sessions.remove(token);
        }
        gone
    }

    fn address(&self, token: u32) -> Option<SocketAddr> {
        self.sessions.lock().expect("ptt sessions lock").get(&token).and_then(|session| session.address)
    }

    /// Where to send a played frame now, with each session's next seq.
    fn listeners(&self) -> Vec<(u32, SocketAddr, u32)> {
        let mut sessions = self.sessions.lock().expect("ptt sessions lock");
        let now = Instant::now();
        sessions
            .iter_mut()
            .filter(|(_, session)| now.duration_since(session.last_heard) < LISTENING)
            .filter_map(|(token, session)| {
                let address = session.address?;
                session.seq = session.seq.wrapping_add(1);
                Some((*token, address, session.seq))
            })
            .collect()
    }

    /// Sessions silent too long, removed.
    fn expire(&self) -> Vec<u32> {
        let mut sessions = self.sessions.lock().expect("ptt sessions lock");
        let now = Instant::now();
        let gone: Vec<u32> = sessions.iter().filter(|(_, session)| now.duration_since(session.last_heard) >= SESSION_IDLE).map(|(token, _)| *token).collect();
        for token in &gone {
            sessions.remove(token);
        }
        gone
    }
}

/// Listens for sessions on `port`, and sends them what is played.
pub fn serve(ptt: Arc<Ptt>, port: u16) {
    tokio::spawn(async move {
        let socket = match UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(socket) => Arc::new(socket),
            Err(error) => {
                log::error!("ptt: UDP sessions on port {port}: {error}");
                return;
            }
        };
        let _ = ptt.udp.port.set(port);
        log::info!("ptt: UDP sessions on port {port}");

        // Played audio and floor changes out to the clients.
        let out = socket.clone();
        let player = ptt.clone();
        tokio::spawn(async move {
            let mut played = player.listen();
            let mut control = player.control();
            let mut expiry = tokio::time::interval(Duration::from_secs(5));
            loop {
                tokio::select! {
                    frame = played.recv() => match frame {
                        Ok(frame) => {
                            let payload: Vec<u8> = frame.iter().flat_map(|sample| sample.to_le_bytes()).collect();
                            for (token, address, seq) in player.udp.listeners() {
                                let _ = out.send_to(&Datagram { kind: AUDIO, token, seq, payload: payload.clone() }.encode(), address).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                    event = control.recv() => {
                        if let Ok(Control::Unkeyed { source: Source::Udp(token), .. }) = event
                            && let Some(address) = player.udp.address(token)
                        {
                            let _ = out.send_to(&Datagram::control(UNKEY, token), address).await;
                        }
                    }
                    _ = expiry.tick() => {
                        let mut ended = player.udp.expire();
                        // A session ends with the sign-in that created it.
                        for owner in player.udp.owners() {
                            let hash = owner.clone();
                            let now = crate::clock::now();
                            let live = player.app.store.call(move |c| kaonic_store::sessions::is_live(c, &hash, now)).await;
                            if matches!(live, Ok(false)) {
                                ended.extend(player.udp.end_owner(&owner));
                            }
                        }
                        for token in ended {
                            player.unkey(Source::Udp(token)).await;
                        }
                    }
                }
            }
        });

        let mut buffer = vec![0u8; 2048];
        loop {
            let (length, address) = match socket.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(error) => {
                    static NOTED: crate::clock::Every = crate::clock::Every::secs(crate::clock::LOG_EVERY);
                    if NOTED.due() {
                        log::warn!("ptt: UDP: {error}");
                    } else {
                        log::debug!("ptt: UDP: {error}");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Some(datagram) = Datagram::decode(&buffer[..length]) else { continue };
            // Unknown sessions, and known ones from anywhere but their client, are ignored.
            match ptt.udp.heard(datagram.token, address) {
                Heard::Client => {}
                Heard::Ignored => continue,
                // Never pinned to an address reached through the mesh VPN: the session ends.
                Heard::Pinned if crate::server::via_tunnel(&ptt.app, address.ip()) => {
                    ptt.udp.remove(datagram.token);
                    continue;
                }
                Heard::Pinned => log::info!("ptt: UDP session {:08x} is {address}", datagram.token),
            }
            let source = Source::Udp(datagram.token);
            match datagram.kind {
                KEEPALIVE => {
                    let _ = socket.send_to(&Datagram::control(KEEPALIVE, datagram.token), address).await;
                }
                KEY => {
                    let answer = if ptt.key(source).await.is_ok() { KEY } else { UNKEY };
                    let _ = socket.send_to(&Datagram::control(answer, datagram.token), address).await;
                }
                UNKEY => {
                    ptt.unkey(source).await;
                    let _ = socket.send_to(&Datagram::control(UNKEY, datagram.token), address).await;
                }
                AUDIO => {
                    if let Some(frame) = pcm(&datagram.payload) {
                        ptt.audio(source, frame);
                    }
                }
                _ => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagrams_round_trip_and_garbage_is_ignored() {
        let audio = Datagram { kind: AUDIO, token: 0x1f2e3d4c, seq: 7, payload: vec![1, 0, 255, 255] };
        let bytes = audio.encode();
        assert_eq!(&bytes[..4], b"KU\x01\x01");
        assert_eq!(&bytes[4..8], &[0x1f, 0x2e, 0x3d, 0x4c]);
        assert_eq!(Datagram::decode(&bytes), Some(audio));
        assert_eq!(Datagram::decode(b"KU\x02\x01\0\0\0\0\0\0\0\0"), None);
        assert_eq!(Datagram::decode(b"KU\x01\x09\0\0\0\0\0\0\0\0"), None);
        assert_eq!(Datagram::decode(b"KU\x01\x01\0\0"), None);
        assert_eq!(Datagram::decode(&Datagram::control(KEY, 5)).unwrap().kind, KEY);
    }

    #[test]
    fn only_whole_frames_are_audio() {
        let frame: Vec<u8> = (0..FRAME_SAMPLES).flat_map(|i| (i as i16).to_le_bytes()).collect();
        assert_eq!(pcm(&frame).unwrap()[3], 3);
        assert!(pcm(&frame[..100]).is_none());
    }

    #[test]
    fn sessions_learn_addresses_and_expire() {
        let sessions = Sessions::default();
        let token = sessions.create(vec![1]).unwrap();
        assert!(sessions.listeners().is_empty(), "nobody heard from yet");
        let address: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert_eq!(sessions.heard(token, address), Heard::Pinned);
        assert_eq!(sessions.heard(token, address), Heard::Client);
        assert_eq!(sessions.heard(token.wrapping_add(1), address), Heard::Ignored);
        assert_eq!(sessions.listeners(), vec![(token, address, 1)]);
        assert_eq!(sessions.listeners()[0].2, 2);
        assert!(sessions.expire().is_empty());
        sessions.sessions.lock().unwrap().get_mut(&token).unwrap().last_heard = Instant::now() - SESSION_IDLE;
        assert_eq!(sessions.expire(), vec![token]);
    }

    #[test]
    fn a_session_stays_with_its_first_address_and_its_sign_in() {
        let sessions = Sessions::default();
        let token = sessions.create(vec![7]).unwrap();
        let client: SocketAddr = "192.168.10.20:40000".parse().unwrap();
        let attacker: SocketAddr = "192.168.10.66:40000".parse().unwrap();
        assert_eq!(sessions.heard(token, client), Heard::Pinned);
        // Someone who sniffed the token cannot take the session over, or point it at a victim.
        assert_eq!(sessions.heard(token, attacker), Heard::Ignored);
        assert_eq!(sessions.listeners(), vec![(token, client, 1)]);
        let other = sessions.create(vec![8]).unwrap();
        assert_eq!(sessions.owners(), vec![vec![7], vec![8]]);
        assert_eq!(sessions.end_owner(&[7]), vec![token]);
        assert_eq!(sessions.heard(token, client), Heard::Ignored, "ended with its sign-in");
        assert_eq!(sessions.heard(other, attacker), Heard::Pinned);
    }
}


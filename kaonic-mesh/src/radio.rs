//! One radio transceiver, as the hub sends and receives whole PHY frames on it.
//!
//! - On the board: the `kaonic_rf215` kernel driver's network interface (`rf09_a`, `rf24_a`,
//!   `rf09_b`, `rf24_b`), with its settings and the last frame's RSSI under
//!   `/sys/class/net/<iface>/rf215/`. Frames go through a non-blocking `AF_PACKET` raw socket
//!   bound to it. kaonic-commd keeps its own socket on the same interface (it drives the
//!   radio front-end); each socket gets its own copy of every received frame.
//! - Without a board: `air://HOST:PORT/NAME`, a node called NAME on a `kaonic-air` emulator,
//!   which delivers each frame to the nodes in range with time on air, loss and collisions.
//!   Datagrams to the air: `0x00 | frame` or `0x01 | name` (register); from the air:
//!   `rssi i8 | frame`.

use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI16, Ordering};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;

/// Frames this socket sends must not come back to it as if received.
#[cfg(target_os = "linux")]
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
/// Room for a few frames: more would only queue stale traffic in front of new.
#[cfg(target_os = "linux")]
const SEND_BUFFER: libc::c_int = 9 * 1024;
/// What the driver reports when it has no signal strength for the frame.
#[cfg(target_os = "linux")]
const RSSI_INVALID: i32 = -128;
/// The largest PHY frame the transceiver sends.
pub const FRAME_SIZE: usize = 2048;

/// The air prefix of an emulated radio.
const AIR_SCHEME: &str = "air://";
/// Datagram tags towards the air.
pub const AIR_FRAME: u8 = 0x00;
pub const AIR_HELLO: u8 = 0x01;
/// The node says who it is again this often, so a restarted air learns it back.
const AIR_HELLO_EVERY: Duration = Duration::from_secs(5);
/// No RSSI yet.
const NO_RSSI: i16 = i16::MIN;
/// What the board spends per frame beyond its time on air (frame load, TX pacing, CCA), measured.
/// The air emulator assumes the same.
const AIR_TX_GAP: Duration = Duration::from_millis(9);
/// Frames the board's socket and driver hold before a send waits (a 9 KiB socket buffer).
const AIR_QUEUE_FRAMES: u32 = 4;

/// Whether `spec` names an emulated radio rather than an interface.
pub fn is_emulated(spec: &str) -> bool {
    spec.starts_with(AIR_SCHEME)
}

pub struct RadioSocket {
    bearer: Bearer,
    iface: String,
}

enum Bearer {
    #[cfg(target_os = "linux")]
    Packet(PacketSocket),
    Air(AirSocket),
}

impl RadioSocket {
    /// Opens `spec`: an interface name (it must exist: the driver has probed its chip), or
    /// `air://HOST:PORT/NAME`. Must run inside a tokio runtime.
    pub fn open(spec: &str) -> io::Result<Self> {
        if let Some(rest) = spec.strip_prefix(AIR_SCHEME) {
            let (address, name) = rest
                .split_once('/')
                .filter(|(address, name)| !address.is_empty() && !name.is_empty())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{spec}: use air://HOST:PORT/NAME")))?;
            return Ok(Self { bearer: Bearer::Air(AirSocket::open(address, name)?), iface: name.to_owned() });
        }
        #[cfg(target_os = "linux")]
        {
            Ok(Self { bearer: Bearer::Packet(PacketSocket::open(spec)?), iface: spec.to_owned() })
        }
        #[cfg(not(target_os = "linux"))]
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("no radio {spec}: radios need Linux and the kaonic_rf215 driver")))
    }

    /// The interface name, or the node name on the air.
    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// Waits for the next frame and copies it into `buffer`. Returns its length,
    /// or None for a frame larger than the buffer (dropped).
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match &self.bearer {
            #[cfg(target_os = "linux")]
            Bearer::Packet(socket) => socket.recv(buffer).await,
            Bearer::Air(socket) => socket.recv(buffer).await,
        }
    }

    /// Queues one frame; waits while the socket is full (that is the pacing of a busy sender).
    pub async fn send(&self, frame: &[u8]) -> io::Result<()> {
        match &self.bearer {
            #[cfg(target_os = "linux")]
            Bearer::Packet(socket) => socket.send(frame).await,
            Bearer::Air(socket) => socket.send(frame).await,
        }
    }

    /// The RSSI of the frame just received, in dBm.
    pub fn last_rssi(&self) -> Option<i8> {
        match &self.bearer {
            #[cfg(target_os = "linux")]
            Bearer::Packet(socket) => socket.last_rssi(),
            Bearer::Air(socket) => socket.last_rssi(),
        }
    }
}

/// A node on a `kaonic-air` emulator.
struct AirSocket {
    socket: UdpSocket,
    hello: Vec<u8>,
    last_hello: Mutex<Instant>,
    rssi: AtomicI16,
    /// When the frames already handed to the air will have left: sends wait like the board's
    /// socket does when its buffer is full, instead of the air dropping them.
    queue_until: Mutex<Instant>,
}

impl AirSocket {
    fn open(address: &str, name: &str) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
        socket.connect(address)?;
        socket.set_nonblocking(true)?;
        let mut hello = vec![AIR_HELLO];
        hello.extend_from_slice(name.as_bytes());
        socket.send(&hello)?;
        Ok(Self {
            socket: UdpSocket::from_std(socket)?,
            hello,
            last_hello: Mutex::new(Instant::now()),
            rssi: AtomicI16::new(NO_RSSI),
            queue_until: Mutex::new(Instant::now()),
        })
    }

    async fn recv(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        let mut datagram = vec![0u8; FRAME_SIZE + 1];
        loop {
            let length = match self.socket.recv(&mut datagram).await {
                Ok(length) => length,
                // The air is not up yet (ICMP port unreachable): keep listening.
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let Some((&rssi, frame)) = datagram[..length].split_first() else { continue };
            self.rssi.store(i16::from(rssi as i8), Ordering::Relaxed);
            if frame.len() > buffer.len() {
                return Ok(None);
            }
            buffer[..frame.len()].copy_from_slice(frame);
            return Ok(Some(frame.len()));
        }
    }

    async fn send(&self, frame: &[u8]) -> io::Result<()> {
        let hello_due = {
            let mut last = self.last_hello.lock().expect("hello lock");
            let due = last.elapsed() >= AIR_HELLO_EVERY;
            if due {
                *last = Instant::now();
            }
            due
        };
        if hello_due {
            let _ = self.socket.send(&self.hello).await;
        }
        let cost = Duration::from_micros(crate::settings::RadioSettings::sub_ghz_default().airtime_us(frame.len())) + AIR_TX_GAP;
        let wait = {
            let mut until = self.queue_until.lock().expect("queue lock");
            let now = Instant::now();
            *until = (*until).max(now) + cost;
            (*until - now).saturating_sub(cost * AIR_QUEUE_FRAMES)
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        let mut datagram = Vec::with_capacity(frame.len() + 1);
        datagram.push(AIR_FRAME);
        datagram.extend_from_slice(frame);
        match self.socket.send(&datagram).await {
            // No air listening: like sending into an empty room.
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
            result => result.map(|_| ()),
        }
    }

    fn last_rssi(&self) -> Option<i8> {
        let value = self.rssi.load(Ordering::Relaxed);
        (value != NO_RSSI).then_some(value as i8)
    }
}

#[cfg(target_os = "linux")]
struct PacketSocket {
    fd: AsyncFd<OwnedFd>,
    rssi_path: PathBuf,
}

#[cfg(target_os = "linux")]
fn cvt(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
}

#[cfg(target_os = "linux")]
fn set_option(fd: libc::c_int, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    // SAFETY: `value` is a valid c_int for the duration of the call.
    cvt(unsafe { libc::setsockopt(fd, level, name, &value as *const libc::c_int as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t) })
        .map(|_| ())
}

#[cfg(target_os = "linux")]
impl PacketSocket {
    fn open(iface: &str) -> io::Result<Self> {
        let name = std::ffi::CString::new(iface).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `name` is a valid C string.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("no radio interface {iface}")));
        }
        // Protocol zero: hear nothing until bound, rather than every interface's frames meanwhile.
        // SAFETY: plain socket(2).
        let raw = cvt(unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) })?;
        // SAFETY: just created and owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        set_option(fd.as_raw_fd(), libc::SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)?;
        set_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, SEND_BUFFER)?;

        // SAFETY: all-zero is a valid sockaddr_ll.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as libc::c_ushort;
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        address.sll_ifindex = index as libc::c_int;
        // SAFETY: the address is initialised and sized correctly.
        cvt(unsafe {
            libc::bind(fd.as_raw_fd(), &address as *const libc::sockaddr_ll as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t)
        })?;
        // SAFETY: the descriptor is owned by the AsyncFd from here on, so it stays open while registered.
        let fd = unsafe { AsyncFd::register(fd) }?;
        Ok(Self { fd, rssi_path: PathBuf::from(format!("/sys/class/net/{iface}/rf215/rssi")) })
    }

    async fn recv(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            let mut guard = self.fd.readable().await?;
            let result = guard.try_io(|fd| {
                // SAFETY: the buffer is valid for its length during the call.
                let length = unsafe { libc::recv(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), libc::MSG_TRUNC) };
                if length < 0 { Err(io::Error::last_os_error()) } else { Ok(length as usize) }
            });
            match result {
                Ok(Ok(length)) => return Ok((length <= buffer.len()).then_some(length)),
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&self, frame: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            let result = guard.try_io(|fd| {
                // SAFETY: the slice is valid for its length during the call.
                let sent = unsafe { libc::send(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
                if sent < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
            });
            match result {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    fn last_rssi(&self) -> Option<i8> {
        let value: i32 = std::fs::read_to_string(&self.rssi_path).ok()?.trim().parse().ok()?;
        // On some hardware the driver reports 0 or -1 for every frame (it misreads the chip); no
        // received frame is that strong, so anything above -10 dBm counts as unknown.
        (value != RSSI_INVALID && value < -10).then(|| value.clamp(i8::MIN as i32, i8::MAX as i32) as i8)
    }
}

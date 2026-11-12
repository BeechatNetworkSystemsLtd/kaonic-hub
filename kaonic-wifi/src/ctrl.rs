//! A client for a wpa_supplicant or hostapd control socket, as `wpa_cli` does it:
//! a Unix datagram socket of our own, bound in a private directory and connected
//! to the daemon's (`/run/wpa_supplicant/wlan0`).
//!
//! Requests are answered in order. A socket that has sent `ATTACH` also receives
//! unsolicited events (`<3>CTRL-EVENT-…`), so the hub uses two: one for requests,
//! one only for events. Both are blocking with timeouts; run them on their own thread.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Longest reply (`SCAN_RESULTS` with many networks).
const MAX_REPLY: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

static NEXT: AtomicU32 = AtomicU32::new(0);

pub struct Ctrl {
    socket: UnixDatagram,
    local: PathBuf,
}

impl Ctrl {
    /// Connects to the daemon socket at `daemon`, binding our end inside `local_dir`
    /// (which must be private to this process: anyone who can write to our socket
    /// can feed us fake events).
    pub fn open(daemon: &Path, local_dir: &Path) -> io::Result<Self> {
        let local = local_dir.join(format!("wpa_ctrl_{}_{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        // A socket file left by an earlier run with the same pid would stop the bind.
        let _ = std::fs::remove_file(&local);
        let socket = UnixDatagram::bind(&local)?;
        let ctrl = Self { socket, local };
        ctrl.socket.connect(daemon)?;
        Ok(ctrl)
    }

    /// Sends `command` and returns the reply, skipping any events that arrive first.
    pub fn request(&self, command: &str) -> io::Result<String> {
        self.socket.send(command.as_bytes())?;
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        loop {
            let reply = self.receive(deadline.saturating_duration_since(Instant::now()))?;
            // An event that slipped in before the reply.
            if !reply.starts_with('<') {
                return Ok(reply);
            }
        }
    }

    /// A request whose only good answer is `OK`.
    pub fn ok(&self, command: &str) -> io::Result<()> {
        let reply = self.request(command)?;
        if reply.trim_end() == "OK" {
            Ok(())
        } else {
            // The command, not the reply, could hold a password: name only its verb.
            let verb = command.split(' ').next().unwrap_or_default();
            Err(io::Error::other(format!("{verb}: {}", reply.trim_end())))
        }
    }

    /// Subscribes this socket to events.
    pub fn attach(&self) -> io::Result<()> {
        self.ok("ATTACH")
    }

    /// Waits up to `timeout` for the next event. None on timeout.
    pub fn next_event(&self, timeout: Duration) -> io::Result<Option<String>> {
        match self.receive(timeout) {
            Ok(message) => Ok(Some(message)),
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn receive(&self, timeout: Duration) -> io::Result<String> {
        // A zero timeout means "block forever" to the OS; never ask for that.
        self.socket.set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        let mut buffer = vec![0u8; MAX_REPLY];
        let length = self.socket.recv(&mut buffer)?;
        buffer.truncate(length);
        String::from_utf8(buffer).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "reply is not UTF-8"))
    }
}

impl Drop for Ctrl {
    fn drop(&mut self) {
        // Tell the daemon to stop sending events here; it would anyway once the socket is gone.
        let _ = self.socket.send(b"DETACH");
        let _ = std::fs::remove_file(&self.local);
    }
}

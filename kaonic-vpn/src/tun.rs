//! The VPN's TUN device (Linux), configured with the `ip` command.
//! [`Tun::pipe`] is an in-memory device for running several nodes in one process (tests).

use std::io;
use std::net::Ipv4Addr;

use tokio::sync::mpsc;

use crate::ip::Cidr;

fn ip(args: &[&str]) -> io::Result<()> {
    let output = std::process::Command::new("ip").args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim())))
    }
}

/// Sets the address and MTU and brings the device up. The kernel adds the tunnel route.
pub fn configure(name: &str, address: Ipv4Addr, network: &Cidr, mtu: u16) -> io::Result<()> {
    ip(&["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"])?;
    ip(&["addr", "flush", "dev", name])?;
    let address = format!("{address}/{}", network.prefix_len());
    ip(&["addr", "add", &address, "broadcast", &network.broadcast().to_string(), "dev", name])
}

pub fn add_route(name: &str, prefix: &Cidr) -> io::Result<()> {
    ip(&["route", "replace", &prefix.to_string(), "dev", name])
}

/// Adds an uplink route into the tunnel with the given metric (`0.0.0.0/0` for default).
pub fn add_uplink_route(name: &str, prefix: &Cidr, metric: &str) -> io::Result<()> {
    ip(&["route", "replace", &prefix.to_string(), "dev", name, "metric", metric])
}

pub fn remove_uplink_route(name: &str, prefix: &Cidr, metric: &str) -> io::Result<()> {
    ip(&["route", "del", &prefix.to_string(), "dev", name, "metric", metric])
}

pub fn remove_route(name: &str, prefix: &Cidr) -> io::Result<()> {
    ip(&["route", "del", &prefix.to_string(), "dev", name])
}

enum Device {
    #[cfg(target_os = "linux")]
    Kernel(linux::Kernel),
    Pipe { from_kernel: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>, to_kernel: mpsc::UnboundedSender<Vec<u8>> },
}

pub struct Tun {
    device: Device,
    name: String,
}

/// The kernel's end of [`Tun::pipe`].
pub struct TunPipe {
    to_vpn: mpsc::UnboundedSender<Vec<u8>>,
    from_vpn: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl TunPipe {
    /// Sends a packet into the tunnel, as the kernel would.
    pub fn send(&self, packet: Vec<u8>) {
        let _ = self.to_vpn.send(packet);
    }

    /// The next packet the VPN delivers to the kernel.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.from_vpn.recv().await
    }
}

impl Tun {
    #[cfg(target_os = "linux")]
    pub fn open(name: &str) -> io::Result<Self> {
        Ok(Self { device: Device::Kernel(linux::Kernel::open(name)?), name: name.to_owned() })
    }

    /// Always fails: the VPN needs Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn open(_name: &str) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "the VPN needs Linux"))
    }

    /// An in-memory device and its kernel end.
    pub fn pipe(name: &str) -> (Self, TunPipe) {
        let (to_vpn, from_kernel) = mpsc::unbounded_channel();
        let (to_kernel, from_vpn) = mpsc::unbounded_channel();
        (Self { device: Device::Pipe { from_kernel: tokio::sync::Mutex::new(from_kernel), to_kernel }, name: name.to_owned() }, TunPipe { to_vpn, from_vpn })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The next packet from the kernel.
    pub async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        match &self.device {
            #[cfg(target_os = "linux")]
            Device::Kernel(kernel) => kernel.read(buffer).await,
            Device::Pipe { from_kernel, .. } => match from_kernel.lock().await.recv().await {
                Some(packet) => Ok(copy(&packet, buffer)),
                // The other end is gone; wait forever.
                None => std::future::pending().await,
            },
        }
    }

    /// A waiting packet, without blocking.
    pub fn try_read(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match &self.device {
            #[cfg(target_os = "linux")]
            Device::Kernel(kernel) => kernel.try_read(buffer),
            Device::Pipe { from_kernel, .. } => Ok(from_kernel.try_lock().ok().and_then(|mut queue| queue.try_recv().ok()).map(|packet| copy(&packet, buffer))),
        }
    }

    pub async fn write(&self, packet: &[u8]) -> io::Result<()> {
        match &self.device {
            #[cfg(target_os = "linux")]
            Device::Kernel(kernel) => kernel.write(packet).await,
            Device::Pipe { to_kernel, .. } => {
                let _ = to_kernel.send(packet.to_vec());
                Ok(())
            }
        }
    }
}

fn copy(packet: &[u8], buffer: &mut [u8]) -> usize {
    let length = packet.len().min(buffer.len());
    buffer[..length].copy_from_slice(&packet[..length]);
    length
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use tokio::io::unix::AsyncFd;

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    pub struct Kernel {
        fd: AsyncFd<OwnedFd>,
    }

    impl Kernel {
        pub fn open(name: &str) -> io::Result<Self> {
            if name.is_empty() || name.len() >= libc::IFNAMSIZ {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad interface name"));
            }
            // SAFETY: plain open(2) of a constant path.
            let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: just opened and owned by nothing else.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut request = IfReq { name: [0; libc::IFNAMSIZ], flags: IFF_TUN | IFF_NO_PI, _pad: [0; 22] };
            for (slot, byte) in request.name.iter_mut().zip(name.bytes()) {
                *slot = byte as libc::c_char;
            }
            // SAFETY: the request is a correctly laid out ifreq that lives for the call.
            if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut request) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the descriptor is owned by the AsyncFd from here on, so it stays open while registered.
            let fd = unsafe { AsyncFd::register(fd) }?;
            Ok(Self { fd })
        }

        pub async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.fd.readable().await?;
                match guard.try_io(|fd| read(fd.as_raw_fd(), buffer)) {
                    Ok(result) => return result,
                    Err(_would_block) => continue,
                }
            }
        }

        pub fn try_read(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
            match read(self.fd.as_raw_fd(), buffer) {
                Ok(length) => Ok(Some(length)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error),
            }
        }

        pub async fn write(&self, packet: &[u8]) -> io::Result<()> {
            loop {
                let mut guard = self.fd.writable().await?;
                let result = guard.try_io(|fd| {
                    // SAFETY: the slice is valid for its length during the call.
                    let written = unsafe { libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
                    if written < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
                });
                match result {
                    Ok(result) => return result,
                    Err(_would_block) => continue,
                }
            }
        }
    }

    fn read(fd: i32, buffer: &mut [u8]) -> io::Result<usize> {
        // SAFETY: the buffer is valid for its length during the call.
        let length = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if length < 0 { Err(io::Error::last_os_error()) } else { Ok(length as usize) }
    }
}

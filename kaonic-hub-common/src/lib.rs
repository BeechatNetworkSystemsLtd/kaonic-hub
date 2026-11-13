//! `kaonic-hub-common`: small pieces shared by `kaonic-hub`, `kaonic-hub-installer` and
//! `kaonic-hub-plugin`, kept here so there is one copy of each.
//!
//! - [`base64`]: the standard and URL-safe alphabets, with decoders as strict as asked.
//! - [`http`]: a minimal HTTP/1.1 client, one request per connection, over any stream.
//! - [`ws`]: a minimal WebSocket client: handshake, frames and messages.
//! - [`peer_uid`]: who is at the other end of a Unix socket.

pub mod base64;
pub mod http;
pub mod ws;

/// The uid of the process at the other end of a Unix socket (`SO_PEERCRED` on Linux,
/// `getpeereid` elsewhere).
pub fn peer_uid(socket: &impl std::os::fd::AsRawFd) -> std::io::Result<u32> {
    let fd = socket.as_raw_fd();
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: cred and len are valid for writes of the sizes given.
        let result = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: uid and gid are valid for writes.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(uid)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_socket_pair_is_our_own() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        // SAFETY: getuid cannot fail.
        assert_eq!(super::peer_uid(&a).unwrap(), unsafe { libc::getuid() });
    }
}

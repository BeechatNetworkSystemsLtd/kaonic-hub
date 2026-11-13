//! A login shell on a pseudo-terminal, for the admin's remote shell.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use tokio::io::unix::AsyncFd;

pub struct Pty {
    master: AsyncFd<OwnedFd>,
    child: Child,
}

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
}

fn set_size(fd: libc::c_int, cols: u16, rows: u16) -> io::Result<()> {
    let size = libc::winsize { ws_row: rows.clamp(2, 500), ws_col: cols.clamp(10, 500), ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ reads one winsize from a valid pointer.
    check(unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size) }).map(|_| ())
}

impl Pty {
    /// `shell -l` in its own session, with the terminal as its controlling terminal.
    pub fn spawn(shell: &str, cols: u16, rows: u16) -> io::Result<Self> {
        let (mut master, mut slave) = (0, 0);
        // SAFETY: openpty writes two descriptors; the name, termios and winsize may be null.
        check(unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) })?;
        // SAFETY: both descriptors were just opened and are owned here.
        let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        set_size(slave.as_raw_fd(), cols, rows)?;
        // SAFETY: F_GETFD/F_SETFD/F_GETFL/F_SETFL on an open descriptor.
        unsafe {
            check(libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC))?;
            let flags = check(libc::fcntl(master.as_raw_fd(), libc::F_GETFL))?;
            check(libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK))?;
        }
        let mut command = Command::new(shell);
        command
            .arg("-l")
            .env_clear()
            .env("TERM", "xterm-256color")
            .env("HOME", "/home/root")
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .current_dir("/")
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            command.pre_exec(|| {
                check(libc::setsid())?;
                check(libc::ioctl(0, libc::TIOCSCTTY as _, 0))?;
                Ok(())
            });
        }
        let child = command.spawn()?;
        // SAFETY: the descriptor is owned by the AsyncFd from here on and closed only with it.
        let master = unsafe { AsyncFd::register(master) }.map_err(io::Error::from)?;
        Ok(Self { master, child })
    }

    /// Some output, or an error once the shell is gone (EIO on Linux).
    pub async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.master.readable().await?;
            // SAFETY: reads at most `buffer.len()` bytes into it.
            let result = ready.try_io(|fd| check(unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) } as libc::c_int).map(|n| n as usize));
            match result {
                Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes all of `bytes` (keystrokes: small).
    pub async fn write(&self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let mut ready = self.master.writable().await?;
            // SAFETY: writes from a valid slice.
            let result = ready.try_io(|fd| check(unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) } as libc::c_int).map(|n| n as usize));
            if let Ok(written) = result {
                bytes = &bytes[written?..];
            }
        }
        Ok(())
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = set_size(self.master.as_raw_fd(), cols, rows);
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        // The shell's whole session goes with it.
        // SAFETY: signalling our own child's process group.
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGHUP);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_shell_runs_a_command_and_echoes() {
        let pty = Pty::spawn("/bin/sh", 80, 24).expect("a pty");
        pty.write(b"echo kaonic-$((40+2))\nexit\n").await.unwrap();
        let mut seen = Vec::new();
        let mut buffer = [0u8; 1024];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, pty.read(&mut buffer)).await {
            seen.extend_from_slice(&buffer[..n]);
            if String::from_utf8_lossy(&seen).contains("kaonic-42") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&seen).contains("kaonic-42"), "{}", String::from_utf8_lossy(&seen));
    }
}

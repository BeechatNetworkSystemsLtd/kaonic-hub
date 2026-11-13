//! Random bytes from the kernel (`getentropy`), for tokens and keys.

use std::io;

pub fn fill(buffer: &mut [u8]) -> io::Result<()> {
    // getentropy takes at most 256 bytes per call.
    for chunk in buffer.chunks_mut(256) {
        // SAFETY: the pointer and length describe `chunk`, which is valid for writes.
        if unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut buffer = [0u8; N];
    fill(&mut buffer)?;
    Ok(buffer)
}

/// 256 random bits as 64 lowercase hex characters.
pub fn token() -> io::Result<String> {
    Ok(hex(&bytes::<32>()?))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

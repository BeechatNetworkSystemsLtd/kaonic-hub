//! What a voice packet costs on the air, ported from the kaonic-audio-ptt plugin
//! (`packing.rs`) for the hub's GROUP packets.
//!
//! `kaonic-net` LDPC-codes every Reticulum packet with `TM2048` (128 bytes in, 256 out) and
//! zero-pads the last block, so airtime comes in 256-byte steps and a packet one byte over a
//! boundary costs a whole extra block. One radio frame holds seven blocks (896 bytes).

/// Header meta 2 + destination hash 16 + context 1.
pub const RNS_HEADER_BYTES: usize = 19;
/// Fernet: 16-byte IV and 32-byte HMAC.
pub const FERNET_OVERHEAD_BYTES: usize = 48;
pub const AES_BLOCK_BYTES: usize = 16;
/// Payload bytes per `TM2048` LDPC block.
pub const LDPC_BLOCK_BYTES: usize = 128;
pub const LDPC_CODED_BLOCK_BYTES: usize = 256;
/// The `kaonic-net` frame header on the air.
pub const LDPC_HEADER_AIR_BYTES: usize = 32;
/// Blocks in one radio frame (896 bytes of Reticulum packet).
pub const BLOCKS_PER_FRAME: usize = 7;
/// What the GROUP channel puts in front of our packet: the key epoch.
pub const GROUP_PREFIX_BYTES: usize = 1;

/// AES-CBC ciphertext size: PKCS#7 pads to the next block and never adds zero.
pub const fn ciphertext_len(plaintext: usize) -> usize {
    AES_BLOCK_BYTES * (plaintext / AES_BLOCK_BYTES + 1)
}

/// The Reticulum packet a voice packet of `packet_len` bytes becomes.
pub const fn wire_len(packet_len: usize) -> usize {
    RNS_HEADER_BYTES + FERNET_OVERHEAD_BYTES + ciphertext_len(GROUP_PREFIX_BYTES + packet_len)
}

pub const fn blocks_for(packet_len: usize) -> usize {
    wire_len(packet_len).div_ceil(LDPC_BLOCK_BYTES)
}

/// Bytes on the air, padding included.
pub const fn air_bytes(packet_len: usize) -> usize {
    LDPC_HEADER_AIR_BYTES + blocks_for(packet_len) * LDPC_CODED_BLOCK_BYTES
}

/// The largest voice packet that still fits `blocks` LDPC blocks (0 if none does).
pub fn max_packet_for_blocks(blocks: usize) -> usize {
    let budget = blocks * LDPC_BLOCK_BYTES;
    let fixed = RNS_HEADER_BYTES + FERNET_OVERHEAD_BYTES;
    if budget <= fixed {
        return 0;
    }
    let cipher_blocks = (budget - fixed) / AES_BLOCK_BYTES;
    // One byte back for the mandatory pad byte, one for the epoch.
    (cipher_blocks * AES_BLOCK_BYTES).saturating_sub(1 + GROUP_PREFIX_BYTES)
}

/// Whether the packet being built should go out now (the plugin's rule): `target` frames
/// are the latency floor, `max` the cap; between them, with `align`, the packet keeps
/// taking frames while they ride free in the blocks it already occupies. `next_cost` must
/// be an upper estimate of the next frame's size. Never past `cap` bytes (one radio frame).
pub fn should_flush(pending: usize, target: usize, max: usize, packet_len: usize, next_cost: usize, align: bool, cap: usize) -> bool {
    if pending == 0 {
        return false;
    }
    if pending >= max || packet_len + next_cost > cap {
        return true;
    }
    if pending < target {
        return false;
    }
    if !align {
        return true;
    }
    packet_len + next_cost > max_packet_for_blocks(blocks_for(packet_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_measured_frames() {
        // A one-block packet: what was measured as 544 bytes on the air for two blocks.
        assert_eq!(air_bytes(10), LDPC_HEADER_AIR_BYTES + LDPC_CODED_BLOCK_BYTES);
        // The GROUP channel's own limit: 814 bytes of packet fill one radio frame.
        assert_eq!(max_packet_for_blocks(BLOCKS_PER_FRAME), 814);
        assert_eq!(blocks_for(814), BLOCKS_PER_FRAME);
        assert_eq!(blocks_for(815), BLOCKS_PER_FRAME + 1);
    }

    #[test]
    fn a_packet_one_byte_over_a_block_costs_a_whole_block() {
        let fits = max_packet_for_blocks(2);
        assert_eq!(blocks_for(fits), 2);
        assert_eq!(blocks_for(fits + 1), 3);
        assert_eq!(air_bytes(fits + 1) - air_bytes(fits), LDPC_CODED_BLOCK_BYTES);
    }

    #[test]
    fn frames_ride_free_until_the_block_is_full() {
        let limit = max_packet_for_blocks(2);
        // Below the floor: keep going; at the cap: flush.
        assert!(!should_flush(2, 4, 8, 100, 50, true, 814));
        assert!(should_flush(8, 4, 8, 100, 50, true, 814));
        // At the floor without alignment: flush.
        assert!(should_flush(4, 4, 8, 100, 50, false, 814));
        // At the floor with alignment: only when the next frame spills a block.
        assert!(!should_flush(4, 4, 8, limit - 60, 50, true, 814));
        assert!(should_flush(4, 4, 8, limit - 40, 50, true, 814));
        // Never past one radio frame.
        assert!(should_flush(2, 4, 8, 800, 50, true, 814));
        assert!(!should_flush(0, 4, 8, 0, 50, true, 814));
    }
}

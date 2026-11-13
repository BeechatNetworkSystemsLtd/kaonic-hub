//! Tests a radio link with raw frames, below Reticulum and LDPC.
//!
//! ```text
//! radio_probe send   <iface> <count> <interval_ms> <length> <tag>
//! radio_probe listen <iface> <seconds>
//! ```
//! A probe frame is `"KPRB" | tag u8 | seq u32 | pattern…`; the listener says
//! for each frame whether every byte arrived as sent, with its RSSI.

use std::time::{Duration, Instant};

use kaonic_mesh::radio::{FRAME_SIZE, RadioSocket};

fn pattern(seq: u32, index: usize) -> u8 {
    (seq as usize).wrapping_mul(31).wrapping_add(index.wrapping_mul(7)) as u8
}

fn usage() -> ! {
    eprintln!("usage: radio_probe send <iface> <count> <interval_ms> <length> <tag> | listen <iface> <seconds>");
    std::process::exit(2)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).cloned().unwrap_or_else(|| usage());
    let iface = args.get(2).cloned().unwrap_or_else(|| usage());
    let socket = RadioSocket::open(&iface)?;
    match mode.as_str() {
        "send" => {
            let count: u32 = args.get(3).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
            let interval: u64 = args.get(4).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
            let length = args.get(5).and_then(|v| v.parse::<usize>().ok()).unwrap_or_else(|| usage()).clamp(16, FRAME_SIZE);
            let tag: u8 = args.get(6).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
            for seq in 0..count {
                let mut frame = vec![0u8; length];
                frame[..4].copy_from_slice(b"KPRB");
                frame[4] = tag;
                frame[5..9].copy_from_slice(&seq.to_be_bytes());
                for (index, byte) in frame.iter_mut().enumerate().skip(9) {
                    *byte = pattern(seq, index);
                }
                socket.send(&frame).await?;
                tokio::time::sleep(Duration::from_millis(interval)).await;
            }
            println!("sent {count} frames of {length} bytes on {iface}");
        }
        "listen" => {
            let seconds: u64 = args.get(3).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
            let deadline = Instant::now() + Duration::from_secs(seconds);
            let (mut good, mut corrupt, mut other) = (0u32, 0u32, 0u32);
            let mut buffer = vec![0u8; FRAME_SIZE];
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                let Ok(received) = tokio::time::timeout(left, socket.recv(&mut buffer)).await else { break };
                let Some(length) = received? else { continue };
                let rssi = socket.last_rssi();
                let frame = &buffer[..length];
                if frame.len() >= 9 && &frame[..4] == b"KPRB" {
                    let seq = u32::from_be_bytes(frame[5..9].try_into().expect("4 bytes"));
                    let bad = frame.iter().enumerate().skip(9).filter(|(index, byte)| **byte != pattern(seq, *index)).count();
                    if bad == 0 { good += 1 } else { corrupt += 1 }
                    println!("tag {} seq {seq:>4} len {length:>4} rssi {:>4} {}", frame[4], rssi.map_or("?".into(), |r| r.to_string()), if bad == 0 { "ok".to_owned() } else { format!("{bad} bytes wrong") });
                } else {
                    other += 1;
                    println!("other frame len {length} rssi {:?}", rssi);
                }
            }
            println!("{iface}: {good} intact, {corrupt} corrupt, {other} other");
        }
        _ => usage(),
    }
    Ok(())
}

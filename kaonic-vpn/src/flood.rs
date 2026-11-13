//! Limits on flooding. Each broadcast or multicast packet is sent to every peer as its own
//! radio transmission, so floods fill the channel fast. Each source gets a token bucket,
//! and background chatter (mDNS, SSDP, IGMP, 224.0.0.0/24) is dropped unless allowed.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::ip::{Cidr, Summary};

const IGMP: u8 = 2;
/// Max sources tracked; the least recently used is dropped beyond this.
const MAX_SOURCES: usize = 256;

/// Whether a flooded packet is background chatter not sent by default.
pub fn is_chatter(summary: &Summary, allow: &[Cidr]) -> bool {
    if allow.iter().any(|allowed| allowed.contains(summary.dst)) {
        return false;
    }
    let link_local_control = summary.dst.octets()[..3] == [224, 0, 0];
    let ssdp = summary.dst == Ipv4Addr::new(239, 255, 255, 250);
    summary.proto == IGMP || link_local_control || ssdp
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

/// One token bucket per source.
pub struct Limiter<K> {
    rate: f64,
    burst: f64,
    buckets: HashMap<K, Bucket>,
}

impl<K: std::hash::Hash + Eq + Clone> Limiter<K> {
    pub fn new(per_second: u32, burst: u32) -> Self {
        Self { rate: f64::from(per_second), burst: f64::from(burst.max(1)), buckets: HashMap::new() }
    }

    /// Takes a token for `source`; false when it has none left.
    pub fn allow(&mut self, source: &K, now: Instant) -> bool {
        if !self.buckets.contains_key(source) && self.buckets.len() >= MAX_SOURCES {
            if let Some(oldest) = self.buckets.iter().min_by_key(|(_, bucket)| bucket.at).map(|(key, _)| key.clone()) {
                self.buckets.remove(&oldest);
            }
        }
        let bucket = self.buckets.entry(source.clone()).or_insert(Bucket { tokens: self.burst, at: now });
        bucket.tokens = (bucket.tokens + now.duration_since(bucket.at).as_secs_f64() * self.rate).min(self.burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{UDP, summarize};
    use std::time::Duration;

    fn summary(dst: [u8; 4], proto: u8) -> Summary {
        summarize(&crate::ip::packet([10, 77, 0, 1], dst, proto, 4)).unwrap()
    }

    #[test]
    fn link_local_chatter_is_not_flooded_unless_allowed() {
        assert!(is_chatter(&summary([224, 0, 0, 251], UDP), &[]));
        assert!(is_chatter(&summary([239, 255, 255, 250], UDP), &[]));
        assert!(is_chatter(&summary([224, 0, 0, 22], IGMP), &[]));
        assert!(!is_chatter(&summary([10, 77, 255, 255], UDP), &[]));
        assert!(!is_chatter(&summary([239, 2, 3, 1], UDP), &[]));
        assert!(!is_chatter(&summary([224, 0, 0, 251], UDP), &["224.0.0.251/32".parse().unwrap()]));
    }

    #[test]
    fn a_source_gets_its_burst_then_its_rate() {
        let mut limiter: Limiter<Ipv4Addr> = Limiter::new(10, 20);
        let a = Ipv4Addr::new(10, 77, 0, 1);
        let b = Ipv4Addr::new(10, 77, 0, 2);
        let start = Instant::now();
        assert_eq!((0..30).filter(|_| limiter.allow(&a, start)).count(), 20);
        assert!(limiter.allow(&b, start), "sources are limited separately");
        assert_eq!((0..30).filter(|_| limiter.allow(&a, start + Duration::from_millis(500))).count(), 5);
    }

    #[test]
    fn many_sources_do_not_grow_it_without_bound() {
        let mut limiter: Limiter<u32> = Limiter::new(10, 20);
        let now = Instant::now();
        for source in 0..1000u32 {
            limiter.allow(&source, now + Duration::from_micros(u64::from(source)));
        }
        assert!(limiter.buckets.len() <= MAX_SOURCES);
    }
}

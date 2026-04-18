use std::time::Instant;

use bitquid_core::Address;
use dashmap::DashMap;

/// Per-peer sliding-window token bucket rate limiter.
///
/// Each peer gets `burst` tokens which refill at `refill_rate` tokens/second.
/// When a peer exhausts its tokens, further messages are rejected until tokens
/// refill. Repeated violations increment a strike counter which the caller can
/// use to disconnect or ban the peer.
pub struct RateLimiter {
    buckets: DashMap<Address, Bucket>,
    config: RateLimitConfig,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum burst size (tokens)
    pub burst: u32,
    /// Tokens added per second
    pub refill_rate: f64,
    /// Strikes before the limiter signals a ban
    pub max_strikes: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst: 120,
            refill_rate: 60.0,
            max_strikes: 5,
        }
    }
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    strikes: u32,
}

/// Result of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Message allowed.
    Allowed,
    /// Throttled — caller should drop the message.
    Throttled,
    /// Peer exceeded max strikes — caller should ban.
    BanRecommended,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: DashMap::new(),
            config,
        }
    }

    /// Attempt to consume one token for `peer`. Returns the verdict.
    pub fn check(&self, peer: &Address) -> RateLimitResult {
        let mut bucket = self.buckets.entry(*peer).or_insert_with(|| Bucket {
            tokens: self.config.burst as f64,
            last_refill: Instant::now(),
            strikes: 0,
        });

        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.config.refill_rate)
            .min(self.config.burst as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateLimitResult::Allowed
        } else {
            bucket.strikes += 1;
            if bucket.strikes >= self.config.max_strikes {
                RateLimitResult::BanRecommended
            } else {
                RateLimitResult::Throttled
            }
        }
    }

    /// Remove state for a disconnected peer.
    pub fn remove_peer(&self, peer: &Address) {
        self.buckets.remove(peer);
    }

    /// Prune peers that have been idle longer than `max_idle_secs`.
    pub fn prune_idle(&self, max_idle_secs: u64) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill).as_secs() < max_idle_secs
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = n;
        Address(bytes)
    }

    #[test]
    fn test_allows_within_burst() {
        let rl = RateLimiter::new(RateLimitConfig {
            burst: 10,
            refill_rate: 1.0,
            max_strikes: 3,
        });
        let peer = test_addr(1);
        for _ in 0..10 {
            assert_eq!(rl.check(&peer), RateLimitResult::Allowed);
        }
    }

    #[test]
    fn test_throttles_over_burst() {
        let rl = RateLimiter::new(RateLimitConfig {
            burst: 3,
            refill_rate: 0.0,
            max_strikes: 100,
        });
        let peer = test_addr(2);
        assert_eq!(rl.check(&peer), RateLimitResult::Allowed);
        assert_eq!(rl.check(&peer), RateLimitResult::Allowed);
        assert_eq!(rl.check(&peer), RateLimitResult::Allowed);
        assert_eq!(rl.check(&peer), RateLimitResult::Throttled);
    }

    #[test]
    fn test_ban_after_max_strikes() {
        let rl = RateLimiter::new(RateLimitConfig {
            burst: 1,
            refill_rate: 0.0,
            max_strikes: 2,
        });
        let peer = test_addr(3);
        assert_eq!(rl.check(&peer), RateLimitResult::Allowed);
        assert_eq!(rl.check(&peer), RateLimitResult::Throttled);
        assert_eq!(rl.check(&peer), RateLimitResult::BanRecommended);
    }

    #[test]
    fn test_independent_peers() {
        let rl = RateLimiter::new(RateLimitConfig {
            burst: 2,
            refill_rate: 0.0,
            max_strikes: 10,
        });
        let p1 = test_addr(10);
        let p2 = test_addr(20);
        assert_eq!(rl.check(&p1), RateLimitResult::Allowed);
        assert_eq!(rl.check(&p1), RateLimitResult::Allowed);
        assert_eq!(rl.check(&p1), RateLimitResult::Throttled);
        assert_eq!(rl.check(&p2), RateLimitResult::Allowed);
        assert_eq!(rl.check(&p2), RateLimitResult::Allowed);
    }

    #[test]
    fn test_remove_peer() {
        let rl = RateLimiter::new(RateLimitConfig {
            burst: 1,
            refill_rate: 0.0,
            max_strikes: 10,
        });
        let peer = test_addr(5);
        assert_eq!(rl.check(&peer), RateLimitResult::Allowed);
        assert_eq!(rl.check(&peer), RateLimitResult::Throttled);
        rl.remove_peer(&peer);
        assert_eq!(rl.check(&peer), RateLimitResult::Allowed);
    }
}

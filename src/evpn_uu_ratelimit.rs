//! EVPN Layer 2 Unknown Unicast Storm Suppression & Rate-Limiting Token Bucket (RFC 7432 Section 16).
//!
//! In EVPN datacenter fabrics, flooded Unknown Unicast (UU) frames can lead to broadcast
//! storm meltdowns if rogue hosts transmit to non-existent MAC addresses.
//!
//! This module implements:
//! * Per-EVI / Per-VNI token bucket rate policer for Unknown Unicast traffic.
//! * Burst size tolerance with microsecond replenishment.
//! * Action policing: pass within CIR/CBS, drop or remark on violation.

use std::collections::HashMap;

/// Result of unknown unicast rate limiting evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuRateLimitVerdict {
    Pass,
    DropExceeded,
}

/// Token bucket state for Unknown Unicast storm policing.
#[derive(Debug, Clone)]
pub struct UuTokenBucket {
    pub rate_bytes_per_sec: u64,
    pub burst_capacity_bytes: u64,
    pub available_tokens: f64,
    pub last_update_us: u64,
}

impl UuTokenBucket {
    pub fn new(rate_bytes_per_sec: u64, burst_capacity_bytes: u64) -> Self {
        UuTokenBucket {
            rate_bytes_per_sec,
            burst_capacity_bytes,
            available_tokens: burst_capacity_bytes as f64,
            last_update_us: 0,
        }
    }

    pub fn consume(&mut self, bytes: usize, now_us: u64) -> UuRateLimitVerdict {
        if self.last_update_us > 0 && now_us > self.last_update_us {
            let elapsed_sec = (now_us - self.last_update_us) as f64 / 1_000_000.0;
            let added_tokens = elapsed_sec * self.rate_bytes_per_sec as f64;
            self.available_tokens =
                (self.available_tokens + added_tokens).min(self.burst_capacity_bytes as f64);
        }
        self.last_update_us = now_us;

        if self.available_tokens >= bytes as f64 {
            self.available_tokens -= bytes as f64;
            UuRateLimitVerdict::Pass
        } else {
            UuRateLimitVerdict::DropExceeded
        }
    }
}

/// EVPN Unknown Unicast Rate Limiter Engine.
#[derive(Debug, Clone)]
pub struct EvpnUuRateLimitEngine {
    /// VNI -> UuTokenBucket
    pub vni_buckets: HashMap<u32, UuTokenBucket>,
    pub total_evaluated_frames: u64,
    pub total_passed_frames: u64,
    pub total_rate_limited_drops: u64,
}

impl EvpnUuRateLimitEngine {
    pub fn new() -> Self {
        EvpnUuRateLimitEngine {
            vni_buckets: HashMap::new(),
            total_evaluated_frames: 0,
            total_passed_frames: 0,
            total_rate_limited_drops: 0,
        }
    }

    pub fn configure_vni_limit(
        &mut self,
        vni: u32,
        rate_bytes_per_sec: u64,
        burst_capacity_bytes: u64,
    ) {
        self.vni_buckets.insert(
            vni,
            UuTokenBucket::new(rate_bytes_per_sec, burst_capacity_bytes),
        );
    }

    /// Evaluates whether an unknown unicast frame on `vni` is permitted.
    pub fn police_unknown_unicast(
        &mut self,
        vni: u32,
        bytes: usize,
        now_us: u64,
    ) -> UuRateLimitVerdict {
        self.total_evaluated_frames += 1;

        if let Some(bucket) = self.vni_buckets.get_mut(&vni) {
            let verdict = bucket.consume(bytes, now_us);
            match verdict {
                UuRateLimitVerdict::Pass => self.total_passed_frames += 1,
                UuRateLimitVerdict::DropExceeded => self.total_rate_limited_drops += 1,
            }
            verdict
        } else {
            // No rate limit configured for this VNI
            self.total_passed_frames += 1;
            UuRateLimitVerdict::Pass
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_uu_ratelimit_token_bucket() {
        let mut engine = EvpnUuRateLimitEngine::new();
        // 1000 bytes/sec, burst 500 bytes
        engine.configure_vni_limit(100, 1000, 500);

        // 1. First 400 bytes -> Pass
        assert_eq!(
            engine.police_unknown_unicast(100, 400, 1_000_000),
            UuRateLimitVerdict::Pass
        );

        // 2. Next 200 bytes immediately -> Exceeds burst limit (100 remaining) -> Drop
        assert_eq!(
            engine.police_unknown_unicast(100, 200, 1_000_000),
            UuRateLimitVerdict::DropExceeded
        );

        // 3. After 1 second (1000 new tokens added) -> Pass
        assert_eq!(
            engine.police_unknown_unicast(100, 400, 2_000_000),
            UuRateLimitVerdict::Pass
        );

        assert_eq!(engine.total_evaluated_frames, 3);
        assert_eq!(engine.total_passed_frames, 2);
        assert_eq!(engine.total_rate_limited_drops, 1);
    }
}

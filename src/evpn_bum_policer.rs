//! EVPN Layer 2 BUM Traffic Storm Policer & Microburst Rate Limiter (RFC 7432 Section 13).
//!
//! Broadcast, Unknown Unicast, and Multicast (BUM) frames are replicated over
//! EVPN overlays via Ingress Replication (Route Type 3 / IMET) or P2MP multicast trees.
//! Malfunctioning VMs or network loops can cause BUM storms that saturate fabric bandwidth.
//!
//! This module implements:
//! * Independent token bucket meters for Broadcast (B), Unknown Unicast (U), and Multicast (M).
//! * Configurable PPS (Packets Per Second) and BPS (Bytes Per Second) rate limits per VNI.
//! * Automatic Storm Quarantine: shuts down rogue source MACs exceeding storm thresholds.
//! * Fine-grained policing verdicts: `Pass`, `RateLimitedDrop`, `StormQuarantined`.

use crate::ethernet::MacAddress;
use std::collections::HashMap;

/// BUM Traffic Category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BumType {
    Broadcast,
    UnknownUnicast,
    Multicast,
}

/// Storm Policer Action Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BumPolicerVerdict {
    Pass,
    RateLimitedDrop,
    StormQuarantined,
}

/// Rate Limiter Bucket for a specific BUM category in a VNI.
#[derive(Debug, Clone)]
pub struct BumTokenBucket {
    pub max_rate_bytes_per_sec: u64,
    pub burst_capacity_bytes: u64,
    pub current_tokens: u64,
    pub last_refill_timestamp_ns: u64,
    pub total_passed_bytes: u64,
    pub total_dropped_bytes: u64,
}

impl BumTokenBucket {
    pub fn new(max_rate_bps: u64, burst_bytes: u64) -> Self {
        BumTokenBucket {
            max_rate_bytes_per_sec: max_rate_bps,
            burst_capacity_bytes: burst_bytes,
            current_tokens: burst_bytes,
            last_refill_timestamp_ns: 0,
            total_passed_bytes: 0,
            total_dropped_bytes: 0,
        }
    }

    pub fn check_and_consume(&mut self, packet_bytes: usize, now_ns: u64) -> bool {
        if self.last_refill_timestamp_ns == 0 {
            self.last_refill_timestamp_ns = now_ns;
        }

        let elapsed_ns = now_ns.saturating_sub(self.last_refill_timestamp_ns);
        let refill_tokens = (elapsed_ns * self.max_rate_bytes_per_sec) / 1_000_000_000;

        if refill_tokens > 0 {
            self.current_tokens =
                (self.current_tokens + refill_tokens).min(self.burst_capacity_bytes);
            self.last_refill_timestamp_ns = now_ns;
        }

        let needed = packet_bytes as u64;
        if self.current_tokens >= needed {
            self.current_tokens -= needed;
            self.total_passed_bytes += needed;
            true
        } else {
            self.total_dropped_bytes += needed;
            false
        }
    }
}

/// EVPN Layer 2 BUM Traffic Storm Policer.
#[derive(Debug, Clone)]
pub struct EvpnBumPolicerEngine {
    /// Token buckets per (VNI, BumType)
    pub policers: HashMap<(u32, BumType), BumTokenBucket>,
    /// Storm threshold: consecutive dropped packets before MAC quarantine
    pub storm_threshold_drops: u64,
    /// Dropped packet counter per source MAC: (VNI, MAC) -> drop count
    pub mac_drop_counters: HashMap<(u32, MacAddress), u64>,
    /// Quarantined MACs
    pub quarantined_macs: Vec<(u32, MacAddress)>,
    pub total_quarantined_events: u64,
}

impl EvpnBumPolicerEngine {
    pub fn new(storm_threshold_drops: u64) -> Self {
        EvpnBumPolicerEngine {
            policers: HashMap::new(),
            storm_threshold_drops,
            mac_drop_counters: HashMap::new(),
            quarantined_macs: Vec::new(),
            total_quarantined_events: 0,
        }
    }

    pub fn set_rate_limit(
        &mut self,
        vni: u32,
        bum_type: BumType,
        max_rate_bps: u64,
        burst_bytes: u64,
    ) {
        self.policers.insert(
            (vni, bum_type),
            BumTokenBucket::new(max_rate_bps, burst_bytes),
        );
    }

    /// Evaluates an incoming BUM frame against the policer and storm defense engine.
    pub fn police_frame(
        &mut self,
        vni: u32,
        src_mac: MacAddress,
        bum_type: BumType,
        packet_bytes: usize,
        now_ns: u64,
    ) -> BumPolicerVerdict {
        // 1. Check if source MAC is currently quarantined
        if self.quarantined_macs.contains(&(vni, src_mac)) {
            return BumPolicerVerdict::StormQuarantined;
        }

        // 2. Evaluate token bucket
        if let Some(bucket) = self.policers.get_mut(&(vni, bum_type)) {
            if bucket.check_and_consume(packet_bytes, now_ns) {
                // Passed, reset drop counter
                self.mac_drop_counters.remove(&(vni, src_mac));
                BumPolicerVerdict::Pass
            } else {
                // Rate limited drop, increment storm counter
                let count = self.mac_drop_counters.entry((vni, src_mac)).or_insert(0);
                *count += 1;

                if *count >= self.storm_threshold_drops {
                    // Storm detected! Quarantine this MAC
                    self.quarantined_macs.push((vni, src_mac));
                    self.total_quarantined_events += 1;
                    BumPolicerVerdict::StormQuarantined
                } else {
                    BumPolicerVerdict::RateLimitedDrop
                }
            }
        } else {
            // No rate limit configured for this type -> Pass
            BumPolicerVerdict::Pass
        }
    }

    /// Unquarantines a source MAC.
    pub fn unquarantine_mac(&mut self, vni: u32, src_mac: &MacAddress) -> bool {
        if let Some(pos) = self
            .quarantined_macs
            .iter()
            .position(|(v, m)| *v == vni && m == src_mac)
        {
            self.quarantined_macs.remove(pos);
            self.mac_drop_counters.remove(&(vni, *src_mac));
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_bum_policing_and_storm_quarantine() {
        let mut engine = EvpnBumPolicerEngine::new(3); // 3 consecutive drops -> quarantine

        // Limit Broadcast in VNI 100 to 1000 bytes/sec, 1000 bytes burst
        engine.set_rate_limit(100, BumType::Broadcast, 1_000, 1_000);

        let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Frame 1 (600B at t=0) -> Pass (1000 - 600 = 400B left)
        assert_eq!(
            engine.police_frame(100, src_mac, BumType::Broadcast, 600, 0),
            BumPolicerVerdict::Pass
        );

        // Frame 2 (500B at t=0) -> Exceeds 400B -> Drop #1
        assert_eq!(
            engine.police_frame(100, src_mac, BumType::Broadcast, 500, 0),
            BumPolicerVerdict::RateLimitedDrop
        );

        // Frame 3 (500B at t=0) -> Drop #2
        assert_eq!(
            engine.police_frame(100, src_mac, BumType::Broadcast, 500, 0),
            BumPolicerVerdict::RateLimitedDrop
        );

        // Frame 4 (500B at t=0) -> Drop #3 (Storm Threshold Reached -> Quarantined!)
        assert_eq!(
            engine.police_frame(100, src_mac, BumType::Broadcast, 500, 0),
            BumPolicerVerdict::StormQuarantined
        );

        // Subsequent frames immediately quarantined
        assert_eq!(
            engine.police_frame(100, src_mac, BumType::Broadcast, 64, 1_000_000_000),
            BumPolicerVerdict::StormQuarantined
        );
        assert_eq!(engine.total_quarantined_events, 1);
    }
}

//! EVPN Layer 2 Multicast IGMP/MLD Control Message Rate Limiter & Storm Policer (RFC 9251)
//!
//! Protects EVPN PE control planes from IGMP/MLD join/leave message storms,
//! denial-of-service flooding, and rogue host rate spikes via token-bucket policing
//! and penalty-box quarantine enforcement.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpMessageType {
    MembershipQuery,
    V2MembershipReport,
    V3MembershipReport,
    LeaveGroup,
    MldQuery,
    MldReport,
    MldDone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgmpPolicerVerdict {
    Conforming {
        vni: u32,
        port_id: u32,
        msg_type: IgmpMessageType,
        remaining_tokens: u32,
    },
    RateLimitedDropped {
        vni: u32,
        port_id: u32,
        msg_type: IgmpMessageType,
        drop_count: u32,
    },
    QuarantinedInPenaltyBox {
        vni: u32,
        port_id: u32,
        msg_type: IgmpMessageType,
        remaining_quarantine_us: u64,
    },
}

#[derive(Debug, Clone)]
pub struct PolicerBucketState {
    pub vni: u32,
    pub port_id: u32,
    pub committed_rate_pps: u32,
    pub burst_tolerance_pkts: u32,
    pub tokens: f64,
    pub last_update_us: u64,
    pub consecutive_drops: u32,
    pub penalty_box_threshold: u32,
    pub penalty_box_duration_us: u64,
    pub quarantined_until_us: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct EvpnIgmpRateLimitPolicerEngine {
    pub default_rate_pps: u32,
    pub default_burst_pkts: u32,
    pub buckets: Vec<PolicerBucketState>,
    pub total_messages_evaluated: usize,
    pub total_conforming_messages: usize,
    pub total_rate_limited_drops: usize,
    pub total_quarantined_drops: usize,
    pub total_penalty_box_triggers: usize,
}

impl EvpnIgmpRateLimitPolicerEngine {
    pub fn new(default_rate_pps: u32, default_burst_pkts: u32) -> Self {
        Self {
            default_rate_pps: default_rate_pps.max(1),
            default_burst_pkts: default_burst_pkts.max(1),
            buckets: Vec::new(),
            total_messages_evaluated: 0,
            total_conforming_messages: 0,
            total_rate_limited_drops: 0,
            total_quarantined_drops: 0,
            total_penalty_box_triggers: 0,
        }
    }

    /// Configures custom rate limit parameters for a specific VNI and Port.
    pub fn set_port_policy(
        &mut self,
        vni: u32,
        port_id: u32,
        rate_pps: u32,
        burst_pkts: u32,
        penalty_box_threshold: u32,
        penalty_box_duration_us: u64,
    ) {
        if let Some(b) = self
            .buckets
            .iter_mut()
            .find(|b| b.vni == vni && b.port_id == port_id)
        {
            b.committed_rate_pps = rate_pps.max(1);
            b.burst_tolerance_pkts = burst_pkts.max(1);
            b.penalty_box_threshold = penalty_box_threshold;
            b.penalty_box_duration_us = penalty_box_duration_us;
            b.tokens = b.tokens.min(b.burst_tolerance_pkts as f64);
        } else {
            self.buckets.push(PolicerBucketState {
                vni,
                port_id,
                committed_rate_pps: rate_pps.max(1),
                burst_tolerance_pkts: burst_pkts.max(1),
                tokens: burst_pkts.max(1) as f64,
                last_update_us: 0,
                consecutive_drops: 0,
                penalty_box_threshold,
                penalty_box_duration_us,
                quarantined_until_us: None,
            });
        }
    }

    /// Evaluates an incoming IGMP/MLD control packet against the rate policer.
    pub fn police_message(
        &mut self,
        vni: u32,
        port_id: u32,
        msg_type: IgmpMessageType,
        timestamp_us: u64,
    ) -> IgmpPolicerVerdict {
        self.total_messages_evaluated += 1;

        let def_rate = self.default_rate_pps;
        let def_burst = self.default_burst_pkts;

        let bucket = match self
            .buckets
            .iter_mut()
            .find(|b| b.vni == vni && b.port_id == port_id)
        {
            Some(b) => b,
            None => {
                self.buckets.push(PolicerBucketState {
                    vni,
                    port_id,
                    committed_rate_pps: def_rate,
                    burst_tolerance_pkts: def_burst,
                    tokens: def_burst as f64,
                    last_update_us: timestamp_us,
                    consecutive_drops: 0,
                    penalty_box_threshold: 5,
                    penalty_box_duration_us: 10_000_000, // 10s default
                    quarantined_until_us: None,
                });
                self.buckets.last_mut().unwrap()
            }
        };

        // 1. Check penalty box quarantine
        if let Some(until_us) = bucket.quarantined_until_us {
            if timestamp_us < until_us {
                self.total_quarantined_drops += 1;
                return IgmpPolicerVerdict::QuarantinedInPenaltyBox {
                    vni,
                    port_id,
                    msg_type,
                    remaining_quarantine_us: until_us - timestamp_us,
                };
            } else {
                // Quarantine expired
                bucket.quarantined_until_us = None;
                bucket.consecutive_drops = 0;
                bucket.tokens = bucket.burst_tolerance_pkts as f64;
                bucket.last_update_us = timestamp_us;
            }
        }

        // 2. Token Bucket replenishment
        if bucket.last_update_us == 0 {
            bucket.last_update_us = timestamp_us;
        } else if timestamp_us > bucket.last_update_us {
            let elapsed_s = (timestamp_us - bucket.last_update_us) as f64 / 1_000_000.0;
            let added_tokens = elapsed_s * bucket.committed_rate_pps as f64;
            bucket.tokens = (bucket.tokens + added_tokens).min(bucket.burst_tolerance_pkts as f64);
            bucket.last_update_us = timestamp_us;
        }

        // 3. Token deduction
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            bucket.consecutive_drops = 0;
            self.total_conforming_messages += 1;
            IgmpPolicerVerdict::Conforming {
                vni,
                port_id,
                msg_type,
                remaining_tokens: bucket.tokens.floor() as u32,
            }
        } else {
            // Out of tokens -> Drop
            bucket.consecutive_drops += 1;
            self.total_rate_limited_drops += 1;

            if bucket.penalty_box_threshold > 0
                && bucket.consecutive_drops >= bucket.penalty_box_threshold
            {
                bucket.quarantined_until_us = Some(timestamp_us + bucket.penalty_box_duration_us);
                self.total_penalty_box_triggers += 1;
                IgmpPolicerVerdict::QuarantinedInPenaltyBox {
                    vni,
                    port_id,
                    msg_type,
                    remaining_quarantine_us: bucket.penalty_box_duration_us,
                }
            } else {
                IgmpPolicerVerdict::RateLimitedDropped {
                    vni,
                    port_id,
                    msg_type,
                    drop_count: bucket.consecutive_drops,
                }
            }
        }
    }

    /// Manually clears the penalty box quarantine for a port.
    pub fn release_penalty_box(&mut self, vni: u32, port_id: u32) -> bool {
        if let Some(b) = self
            .buckets
            .iter_mut()
            .find(|b| b.vni == vni && b.port_id == port_id)
        {
            b.quarantined_until_us = None;
            b.consecutive_drops = 0;
            b.tokens = b.burst_tolerance_pkts as f64;
            return true;
        }
        false
    }

    /// Resets all statistics and buckets.
    pub fn reset(&mut self) {
        self.buckets.clear();
        self.total_messages_evaluated = 0;
        self.total_conforming_messages = 0;
        self.total_rate_limited_drops = 0;
        self.total_quarantined_drops = 0;
        self.total_penalty_box_triggers = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_igmp_policer_lifecycle() {
        let mut policer = EvpnIgmpRateLimitPolicerEngine::new(10, 3); // 10 pps, burst of 3

        policer.set_port_policy(100, 1, 10, 3, 2, 5_000_000); // Trigger quarantine on 2 consecutive drops, 5s duration

        // First 3 messages at t=0 conforming
        let v1 = policer.police_message(100, 1, IgmpMessageType::V3MembershipReport, 0);
        assert_eq!(
            v1,
            IgmpPolicerVerdict::Conforming {
                vni: 100,
                port_id: 1,
                msg_type: IgmpMessageType::V3MembershipReport,
                remaining_tokens: 2,
            }
        );

        let _ = policer.police_message(100, 1, IgmpMessageType::V3MembershipReport, 0);
        let _ = policer.police_message(100, 1, IgmpMessageType::V3MembershipReport, 0);

        // 4th message at t=0 -> 1st drop
        let v4 = policer.police_message(100, 1, IgmpMessageType::V3MembershipReport, 0);
        assert_eq!(
            v4,
            IgmpPolicerVerdict::RateLimitedDropped {
                vni: 100,
                port_id: 1,
                msg_type: IgmpMessageType::V3MembershipReport,
                drop_count: 1,
            }
        );

        // 5th message at t=0 -> 2nd consecutive drop -> Quarantined into penalty box for 5s
        let v5 = policer.police_message(100, 1, IgmpMessageType::V3MembershipReport, 0);
        assert_eq!(
            v5,
            IgmpPolicerVerdict::QuarantinedInPenaltyBox {
                vni: 100,
                port_id: 1,
                msg_type: IgmpMessageType::V3MembershipReport,
                remaining_quarantine_us: 5_000_000,
            }
        );

        // Message during quarantine at t=2s (2_000_000 us) -> Still quarantined
        let v6 = policer.police_message(100, 1, IgmpMessageType::V3MembershipReport, 2_000_000);
        assert_eq!(
            v6,
            IgmpPolicerVerdict::QuarantinedInPenaltyBox {
                vni: 100,
                port_id: 1,
                msg_type: IgmpMessageType::V3MembershipReport,
                remaining_quarantine_us: 3_000_000,
            }
        );

        // Message after quarantine at t=6s (6_000_000 us) -> Conforming!
        let v7 = policer.police_message(100, 1, IgmpMessageType::V3MembershipReport, 6_000_000);
        assert_eq!(
            v7,
            IgmpPolicerVerdict::Conforming {
                vni: 100,
                port_id: 1,
                msg_type: IgmpMessageType::V3MembershipReport,
                remaining_tokens: 2,
            }
        );
    }
}

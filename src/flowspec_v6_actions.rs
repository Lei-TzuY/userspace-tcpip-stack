//! BGP Flowspec IPv6 Action Extended Communities & Remarking Engine (RFC 8956 / RFC 8955).
//!
//! Implements BGP Flowspec extended community actions for IPv6 traffic filtering,
//! including Traffic-Rate limiting, Traffic-Action (terminal/sampling), DSCP remarking,
//! and VRF redirect.

/// Flowspec Extended Community Subtypes under Type 0x80 (RFC 8955 / RFC 8956).
pub const FS_ACTION_SUBTYPE_TRAFFIC_RATE: u8 = 0x06;
pub const FS_ACTION_SUBTYPE_TRAFFIC_ACTION: u8 = 0x07;
pub const FS_ACTION_SUBTYPE_REDIRECT_RT: u8 = 0x08;
pub const FS_ACTION_SUBTYPE_TRAFFIC_MARKING: u8 = 0x09;

/// Flowspec Action Extended Community.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowspecV6ActionCommunity {
    /// Traffic-rate in Bytes/sec (Subtype 0x06). Rate = 0 means Discard/Drop.
    TrafficRate { rate_bytes_sec: f32 },
    /// Traffic-action flags (Subtype 0x07).
    TrafficAction { terminal: bool, sample: bool },
    /// Redirect to VRF Route Target (Subtype 0x08).
    RedirectRouteTarget { admin_asn: u16, target_val: u32 },
    /// Traffic Class / DSCP remarking (Subtype 0x09, 0..63).
    TrafficMarking { dscp: u8 },
}

impl FlowspecV6ActionCommunity {
    /// Serializes the action into an 8-byte BGP Extended Community.
    pub fn serialize(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = 0x80; // Type: Generic Transitive Experimental

        match self {
            FlowspecV6ActionCommunity::TrafficRate { rate_bytes_sec } => {
                buf[1] = FS_ACTION_SUBTYPE_TRAFFIC_RATE;
                let float_bytes = rate_bytes_sec.to_be_bytes();
                buf[4..8].copy_from_slice(&float_bytes);
            }
            FlowspecV6ActionCommunity::TrafficAction { terminal, sample } => {
                buf[1] = FS_ACTION_SUBTYPE_TRAFFIC_ACTION;
                let mut flags = 0u8;
                if *terminal {
                    flags |= 0x01; // Terminal bit (RFC 8955 Section 7.3)
                }
                if *sample {
                    flags |= 0x02; // Sample bit
                }
                buf[7] = flags;
            }
            FlowspecV6ActionCommunity::RedirectRouteTarget {
                admin_asn,
                target_val,
            } => {
                buf[1] = FS_ACTION_SUBTYPE_REDIRECT_RT;
                buf[2..4].copy_from_slice(&admin_asn.to_be_bytes());
                buf[4..8].copy_from_slice(&target_val.to_be_bytes());
            }
            FlowspecV6ActionCommunity::TrafficMarking { dscp } => {
                buf[1] = FS_ACTION_SUBTYPE_TRAFFIC_MARKING;
                buf[7] = *dscp & 0x3F;
            }
        }
        buf
    }

    /// Parses an 8-byte BGP Extended Community into a Flowspec action.
    pub fn parse(buf: &[u8; 8]) -> Option<Self> {
        if buf[0] != 0x80 {
            return None;
        }
        match buf[1] {
            FS_ACTION_SUBTYPE_TRAFFIC_RATE => {
                let float_bytes = [buf[4], buf[5], buf[6], buf[7]];
                let rate = f32::from_be_bytes(float_bytes);
                Some(FlowspecV6ActionCommunity::TrafficRate {
                    rate_bytes_sec: rate,
                })
            }
            FS_ACTION_SUBTYPE_TRAFFIC_ACTION => {
                let flags = buf[7];
                Some(FlowspecV6ActionCommunity::TrafficAction {
                    terminal: (flags & 0x01) != 0,
                    sample: (flags & 0x02) != 0,
                })
            }
            FS_ACTION_SUBTYPE_REDIRECT_RT => {
                let admin_asn = u16::from_be_bytes([buf[2], buf[3]]);
                let target_val = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                Some(FlowspecV6ActionCommunity::RedirectRouteTarget {
                    admin_asn,
                    target_val,
                })
            }
            FS_ACTION_SUBTYPE_TRAFFIC_MARKING => {
                let dscp = buf[7] & 0x3F;
                Some(FlowspecV6ActionCommunity::TrafficMarking { dscp })
            }
            _ => None,
        }
    }
}

/// Token bucket state for real-time packet rate limiting.
#[derive(Debug, Clone)]
pub struct TokenBucketLimiter {
    pub rate_bytes_per_sec: f64,
    pub max_burst_bytes: f64,
    pub current_tokens: f64,
    pub last_update_ns: u64,
}

impl TokenBucketLimiter {
    pub fn new(rate_bytes_sec: f64, burst_bytes: f64) -> Self {
        TokenBucketLimiter {
            rate_bytes_per_sec: rate_bytes_sec,
            max_burst_bytes: burst_bytes,
            current_tokens: burst_bytes,
            last_update_ns: 0,
        }
    }

    /// Evaluates if a packet of `packet_len` bytes is admitted under the rate limit.
    pub fn admit_packet(&mut self, packet_len: usize, now_ns: u64) -> bool {
        if self.rate_bytes_per_sec <= 0.0 {
            return false; // Rate = 0 means Drop
        }

        if self.last_update_ns > 0 && now_ns > self.last_update_ns {
            let elapsed_sec = (now_ns - self.last_update_ns) as f64 / 1_000_000_000.0;
            let replenished = elapsed_sec * self.rate_bytes_per_sec;
            self.current_tokens = (self.current_tokens + replenished).min(self.max_burst_bytes);
        }
        self.last_update_ns = now_ns;

        let cost = packet_len as f64;
        if self.current_tokens >= cost {
            self.current_tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Verdict returned by the Flowspec IPv6 Action Engine.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowspecV6Verdict {
    Pass {
        packet: Vec<u8>,
    },
    Remarked {
        new_dscp: u8,
        packet: Vec<u8>,
    },
    Redirect {
        admin_asn: u16,
        target_val: u32,
        packet: Vec<u8>,
    },
    Drop {
        reason: String,
    },
}

/// Flowspec IPv6 Action Execution Engine.
#[derive(Debug, Clone, Default)]
pub struct FlowspecV6ActionEngine {
    pub actions: Vec<FlowspecV6ActionCommunity>,
}

impl FlowspecV6ActionEngine {
    pub fn new() -> Self {
        FlowspecV6ActionEngine {
            actions: Vec::new(),
        }
    }

    pub fn add_action(&mut self, action: FlowspecV6ActionCommunity) {
        self.actions.push(action);
    }

    /// Rewrites the DSCP (Traffic Class) bits in an IPv6 header.
    pub fn remark_ipv6_dscp(packet: &mut [u8], dscp: u8) {
        if packet.len() >= 40 && (packet[0] >> 4) == 6 {
            let current_ecn = (packet[1] >> 4) & 0x03;
            let new_tc = ((dscp & 0x3F) << 2) | current_ecn;

            packet[0] = (packet[0] & 0xF0) | ((new_tc >> 4) & 0x0F);
            packet[1] = ((new_tc & 0x0F) << 4) | (packet[1] & 0x0F);
        }
    }

    /// Applies configured Flowspec actions to an incoming IPv6 packet.
    pub fn apply_actions(&self, mut packet: Vec<u8>) -> FlowspecV6Verdict {
        if packet.len() < 40 {
            return FlowspecV6Verdict::Drop {
                reason: "IPv6 packet shorter than 40 bytes".to_string(),
            };
        }

        let mut remarked = false;
        let mut final_dscp = 0u8;
        let mut redirect_target = None;

        for action in &self.actions {
            match action {
                FlowspecV6ActionCommunity::TrafficRate { rate_bytes_sec } => {
                    if *rate_bytes_sec <= 0.0 {
                        return FlowspecV6Verdict::Drop {
                            reason: "Traffic-Rate action drop (rate = 0)".to_string(),
                        };
                    }
                }
                FlowspecV6ActionCommunity::TrafficMarking { dscp } => {
                    Self::remark_ipv6_dscp(&mut packet, *dscp);
                    remarked = true;
                    final_dscp = *dscp;
                }
                FlowspecV6ActionCommunity::RedirectRouteTarget {
                    admin_asn,
                    target_val,
                } => {
                    redirect_target = Some((*admin_asn, *target_val));
                }
                FlowspecV6ActionCommunity::TrafficAction {
                    terminal: _,
                    sample: _,
                } => {}
            }
        }

        if let Some((admin_asn, target_val)) = redirect_target {
            FlowspecV6Verdict::Redirect {
                admin_asn,
                target_val,
                packet,
            }
        } else if remarked {
            FlowspecV6Verdict::Remarked {
                new_dscp: final_dscp,
                packet,
            }
        } else {
            FlowspecV6Verdict::Pass { packet }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flowspec_v6_action_codecs() {
        let rate_action = FlowspecV6ActionCommunity::TrafficRate {
            rate_bytes_sec: 1250000.0,
        };
        let rate_ser = rate_action.serialize();
        let rate_parsed = FlowspecV6ActionCommunity::parse(&rate_ser).unwrap();
        assert_eq!(rate_parsed, rate_action);

        let mark_action = FlowspecV6ActionCommunity::TrafficMarking { dscp: 46 }; // EF (Expedited Forwarding)
        let mark_ser = mark_action.serialize();
        let mark_parsed = FlowspecV6ActionCommunity::parse(&mark_ser).unwrap();
        assert_eq!(mark_parsed, mark_action);

        let redir_action = FlowspecV6ActionCommunity::RedirectRouteTarget {
            admin_asn: 65001,
            target_val: 500,
        };
        let redir_ser = redir_action.serialize();
        let redir_parsed = FlowspecV6ActionCommunity::parse(&redir_ser).unwrap();
        assert_eq!(redir_parsed, redir_action);
    }

    #[test]
    fn test_flowspec_v6_dscp_remarking_and_rate_limit() {
        let mut engine = FlowspecV6ActionEngine::new();
        engine.add_action(FlowspecV6ActionCommunity::TrafficMarking { dscp: 34 }); // AF41

        let mut ipv6_pkt = vec![0x60, 0x00, 0x00, 0x00, 0, 10, 59, 64];
        ipv6_pkt.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
        ipv6_pkt.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // dst
        ipv6_pkt.extend_from_slice(b"FlowspecPayload");

        let verdict = engine.apply_actions(ipv6_pkt);
        match verdict {
            FlowspecV6Verdict::Remarked { new_dscp, packet } => {
                assert_eq!(new_dscp, 34);
                let tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
                assert_eq!(tc >> 2, 34);
            }
            other => panic!("Expected Remarked, got {:?}", other),
        }

        let mut limiter = TokenBucketLimiter::new(1000.0, 1500.0);
        assert!(limiter.admit_packet(1000, 1_000_000_000));
        assert!(!limiter.admit_packet(1000, 1_000_000_000));
        assert!(limiter.admit_packet(1000, 2_500_000_000));
    }
}

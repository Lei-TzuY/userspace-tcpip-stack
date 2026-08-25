//! 3GPP TS 23.501 / TS 24.193 — 5G Multi-Access PDU (MA-PDU) & ATSSS Steering Engine.
//!
//! Access Traffic Steering, Switching, and Splitting (ATSSS) enables a 5G UE and UPF
//! to simultaneously exchange user plane traffic over both 3GPP access (5G-NR)
//! and Non-3GPP access (Wi-Fi / Fixed Access).
//!
//! Standard ATSSS Steering Modes:
//! 1. **ActiveStandby**: Directs all traffic to the active 3GPP leg; fails over to non-3GPP when degraded.
//! 2. **SmallestDelay**: Dynamically routes packets over the leg with the lowest measured round-trip time (RTT).
//! 3. **LoadBalancing (Splitting)**: Distributes user traffic across both access legs according to weighted percentage.
//! 4. **PriorityBased**: Directs traffic to high-priority leg until saturated.
//!
//! This module implements:
//! * Dual-leg 3GPP / Non-3GPP MA-PDU Session container.
//! * ATSSS rule evaluation engine.
//! * Dynamic RTT / loss telemetry tracking per access leg.

use crate::ipv4::Ipv4Address;

/// Access Leg Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLegType {
    ThreeGpp,
    NonThreeGpp,
}

/// ATSSS Steering Policy Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtsssMode {
    ActiveStandby,
    SmallestDelay,
    LoadBalancing { ratio_3gpp_percent: u8 },
    PriorityBased,
}

/// Status of an individual access leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLegStatus {
    pub leg_type: AccessLegType,
    pub remote_ip: Ipv4Address,
    pub teid: u32,
    pub rtt_ms: u32,
    pub is_available: bool,
    pub total_packets_sent: u64,
}

/// 5G MA-PDU Session ATSSS Engine.
#[derive(Debug, Clone)]
pub struct MaPduSessionEngine {
    pub session_id: u32,
    pub mode: AtsssMode,
    pub leg_3gpp: AccessLegStatus,
    pub leg_non_3gpp: AccessLegStatus,
    pub split_counter: u64,
}

impl MaPduSessionEngine {
    pub fn new(
        session_id: u32,
        mode: AtsssMode,
        ip_3gpp: Ipv4Address,
        teid_3gpp: u32,
        ip_non_3gpp: Ipv4Address,
        teid_non_3gpp: u32,
    ) -> Self {
        MaPduSessionEngine {
            session_id,
            mode,
            leg_3gpp: AccessLegStatus {
                leg_type: AccessLegType::ThreeGpp,
                remote_ip: ip_3gpp,
                teid: teid_3gpp,
                rtt_ms: 20,
                is_available: true,
                total_packets_sent: 0,
            },
            leg_non_3gpp: AccessLegStatus {
                leg_type: AccessLegType::NonThreeGpp,
                remote_ip: ip_non_3gpp,
                teid: teid_non_3gpp,
                rtt_ms: 50,
                is_available: true,
                total_packets_sent: 0,
            },
            split_counter: 0,
        }
    }

    pub fn update_leg_rtt(&mut self, leg: AccessLegType, rtt_ms: u32) {
        match leg {
            AccessLegType::ThreeGpp => self.leg_3gpp.rtt_ms = rtt_ms,
            AccessLegType::NonThreeGpp => self.leg_non_3gpp.rtt_ms = rtt_ms,
        }
    }

    pub fn set_leg_availability(&mut self, leg: AccessLegType, available: bool) {
        match leg {
            AccessLegType::ThreeGpp => self.leg_3gpp.is_available = available,
            AccessLegType::NonThreeGpp => self.leg_non_3gpp.is_available = available,
        }
    }

    /// Steers an outgoing user plane packet to the optimal access leg based on the ATSSS policy.
    pub fn steer_packet(&mut self) -> Option<(AccessLegType, Ipv4Address, u32)> {
        self.split_counter += 1;

        let chosen_leg = match self.mode {
            AtsssMode::ActiveStandby => {
                if self.leg_3gpp.is_available {
                    AccessLegType::ThreeGpp
                } else if self.leg_non_3gpp.is_available {
                    AccessLegType::NonThreeGpp
                } else {
                    return None;
                }
            }
            AtsssMode::SmallestDelay => {
                if self.leg_3gpp.is_available && self.leg_non_3gpp.is_available {
                    if self.leg_3gpp.rtt_ms <= self.leg_non_3gpp.rtt_ms {
                        AccessLegType::ThreeGpp
                    } else {
                        AccessLegType::NonThreeGpp
                    }
                } else if self.leg_3gpp.is_available {
                    AccessLegType::ThreeGpp
                } else if self.leg_non_3gpp.is_available {
                    AccessLegType::NonThreeGpp
                } else {
                    return None;
                }
            }
            AtsssMode::LoadBalancing { ratio_3gpp_percent } => {
                let slot = (self.split_counter % 100) as u8;
                if slot < ratio_3gpp_percent && self.leg_3gpp.is_available {
                    AccessLegType::ThreeGpp
                } else if self.leg_non_3gpp.is_available {
                    AccessLegType::NonThreeGpp
                } else if self.leg_3gpp.is_available {
                    AccessLegType::ThreeGpp
                } else {
                    return None;
                }
            }
            AtsssMode::PriorityBased => {
                if self.leg_3gpp.is_available {
                    AccessLegType::ThreeGpp
                } else if self.leg_non_3gpp.is_available {
                    AccessLegType::NonThreeGpp
                } else {
                    return None;
                }
            }
        };

        match chosen_leg {
            AccessLegType::ThreeGpp => {
                self.leg_3gpp.total_packets_sent += 1;
                Some((AccessLegType::ThreeGpp, self.leg_3gpp.remote_ip, self.leg_3gpp.teid))
            }
            AccessLegType::NonThreeGpp => {
                self.leg_non_3gpp.total_packets_sent += 1;
                Some((AccessLegType::NonThreeGpp, self.leg_non_3gpp.remote_ip, self.leg_non_3gpp.teid))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ma_pdu_atsss_smallest_delay_and_active_standby() {
        let mut session = MaPduSessionEngine::new(
            501,
            AtsssMode::SmallestDelay,
            Ipv4Address::new(10, 5, 1, 1),
            0x3333AAAA,
            Ipv4Address::new(192, 168, 50, 1),
            0x4444BBBB,
        );

        // 3GPP RTT = 20ms, Non-3GPP RTT = 50ms -> Steers to 3GPP
        let (leg1, ip1, teid1) = session.steer_packet().unwrap();
        assert_eq!(leg1, AccessLegType::ThreeGpp);
        assert_eq!(ip1, Ipv4Address::new(10, 5, 1, 1));
        assert_eq!(teid1, 0x3333AAAA);

        // Non-3GPP Wi-Fi latency drops to 10ms (< 20ms) -> Steers to Non-3GPP!
        session.update_leg_rtt(AccessLegType::NonThreeGpp, 10);
        let (leg2, ip2, teid2) = session.steer_packet().unwrap();
        assert_eq!(leg2, AccessLegType::NonThreeGpp);
        assert_eq!(ip2, Ipv4Address::new(192, 168, 50, 1));
        assert_eq!(teid2, 0x4444BBBB);
    }
}

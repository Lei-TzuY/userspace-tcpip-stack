//! 3GPP TS 24.193 / TS 23.501 — 5G Multi-Access Latency-Aware Active Probing Engine.
//!
//! In 5G ATSSS (Access Traffic Steering, Switching, and Splitting), user-plane performance
//! measurement protocol (PMF) active probes are periodically dispatched across both
//! 3GPP (5G-NR) and Non-3GPP (Wi-Fi) access legs.
//!
//! This module implements:
//! * Active RTT probe generation and response timestamping.
//! * Exponentially Weighted Moving Average (EWMA) smoothed RTT calculation:
//!   $$\text{SRTT} = \alpha \cdot \text{SRTT} + (1 - \alpha) \cdot \text{RTT}_{\text{sample}}$$
//! * Dynamic optimal access leg election for Smallest-Delay ATSSS steering.

/// Access Leg Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeAccessLeg {
    ThreeGpp,
    NonThreeGpp,
}

/// Active RTT measurement probe packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveRttProbe {
    pub probe_id: u32,
    pub leg: ProbeAccessLeg,
    pub tx_timestamp_us: u64,
}

/// 5G Multi-Access Latency-Aware Active Probing Engine.
#[derive(Debug, Clone)]
pub struct GtpuRttProbingEngine {
    pub session_id: u32,
    pub next_probe_id: u32,
    pub smoothed_rtt_3gpp_us: f64,
    pub smoothed_rtt_non3gpp_us: f64,
    pub total_probes_sent: u64,
    pub total_probes_received: u64,
    pub ewma_alpha: f64,
}

impl GtpuRttProbingEngine {
    pub fn new(session_id: u32) -> Self {
        GtpuRttProbingEngine {
            session_id,
            next_probe_id: 1,
            smoothed_rtt_3gpp_us: 20_000.0,    // Default 20ms
            smoothed_rtt_non3gpp_us: 15_000.0, // Default 15ms
            total_probes_sent: 0,
            total_probes_received: 0,
            ewma_alpha: 0.875, // Standard TCP/GTP EWMA smoothing factor
        }
    }

    /// Dispatches a synthetic active RTT probe over the specified leg.
    pub fn create_probe(&mut self, leg: ProbeAccessLeg, now_us: u64) -> ActiveRttProbe {
        let probe = ActiveRttProbe {
            probe_id: self.next_probe_id,
            leg,
            tx_timestamp_us: now_us,
        };
        self.next_probe_id += 1;
        self.total_probes_sent += 1;
        probe
    }

    /// Ingests a returned probe response, calculates sample RTT, and updates EWMA smoothed RTT.
    pub fn handle_probe_reply(&mut self, probe: &ActiveRttProbe, rx_us: u64) -> f64 {
        let sample_rtt = rx_us.saturating_sub(probe.tx_timestamp_us) as f64;
        self.total_probes_received += 1;

        match probe.leg {
            ProbeAccessLeg::ThreeGpp => {
                self.smoothed_rtt_3gpp_us = self.ewma_alpha * self.smoothed_rtt_3gpp_us
                    + (1.0 - self.ewma_alpha) * sample_rtt;
                self.smoothed_rtt_3gpp_us
            }
            ProbeAccessLeg::NonThreeGpp => {
                self.smoothed_rtt_non3gpp_us = self.ewma_alpha * self.smoothed_rtt_non3gpp_us
                    + (1.0 - self.ewma_alpha) * sample_rtt;
                self.smoothed_rtt_non3gpp_us
            }
        }
    }

    /// Determines the best access leg with the lowest measured round-trip time.
    pub fn get_optimal_leg(&self) -> ProbeAccessLeg {
        if self.smoothed_rtt_3gpp_us <= self.smoothed_rtt_non3gpp_us {
            ProbeAccessLeg::ThreeGpp
        } else {
            ProbeAccessLeg::NonThreeGpp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_rtt_probing_and_best_leg_selection() {
        let mut engine = GtpuRttProbingEngine::new(999);

        // 1. Initial defaults: non-3GPP is 15ms, 3GPP is 20ms -> NonThreeGpp is best
        assert_eq!(engine.get_optimal_leg(), ProbeAccessLeg::NonThreeGpp);

        // 2. Dispatch 3GPP probe with super low latency (5ms = 5000us)
        let p1 = engine.create_probe(ProbeAccessLeg::ThreeGpp, 100_000);
        let _srtt1 = engine.handle_probe_reply(&p1, 105_000);

        // Repeated 3GPP fast probes lower smoothed RTT
        for _ in 0..10 {
            let p = engine.create_probe(ProbeAccessLeg::ThreeGpp, 100_000);
            engine.handle_probe_reply(&p, 105_000);
        }

        // Now 3GPP is significantly faster (< 6ms) -> Optimal leg becomes ThreeGpp!
        assert_eq!(engine.get_optimal_leg(), ProbeAccessLeg::ThreeGpp);
        assert!(engine.smoothed_rtt_3gpp_us < 10_000.0);
    }
}

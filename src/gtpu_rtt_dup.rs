// =============================================================================
// 3GPP TS 29.281 / TS 23.501 5G GTP-U RTT-Adaptive Packet Duplication Engine
// =============================================================================
//
// In 5G URLLC (Ultra-Reliable Low-Latency Communication), packet duplication across
// dual 3GPP (Cellular) and Non-3GPP (Wi-Fi) legs maximizes delivery reliability.
//
// To prevent permanent 2x bandwidth overhead, the RTT-Adaptive Duplication Engine
// dynamically enables duplication only when primary leg latency or RTT variance
// exceeds SLA thresholds, and returns to single-path transmission with hysteresis
// dampening once latency stabilizes.
//
// Features:
//   1. Latency & Jitter SLA Monitoring (SRTT and RTTVAR thresholds).
//   2. Dynamic Duplication State Machine (SinglePath vs DuplicationActive).
//   3. Hysteresis Hold-Down Filter to prevent state flapping.
//   4. Multi-Access Leg Dispatch Decision (Primary, Secondary, or Both).
//
// Pure safe Rust, zero external crates.

/// Packet dispatch target leg decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DupDispatchDecision {
    /// Send on primary leg only (normal optimal conditions).
    SinglePrimary,
    /// Send duplicate copies on both primary and secondary legs (degraded primary).
    DuplicateBoth {
        primary_leg_id: u32,
        secondary_leg_id: u32,
    },
}

/// Adaptive Duplication state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicationState {
    /// Low latency/jitter: single path active.
    SinglePath,
    /// High latency/jitter: active packet duplication.
    Duplicating,
}

/// 5G GTP-U RTT-Adaptive Duplication Engine.
pub struct GtpuRttDupEngine {
    pub primary_leg_id: u32,
    pub secondary_leg_id: u32,
    pub max_acceptable_srtt_us: u64,
    pub max_acceptable_rttvar_us: u64,
    pub recovery_hysteresis_count: u32,
    pub current_state: DuplicationState,
    pub consecutive_healthy_samples: u32,
    pub total_single_packets: u64,
    pub total_duplicated_packets: u64,
    pub total_state_transitions: u64,
}

impl GtpuRttDupEngine {
    pub fn new(
        primary_leg_id: u32,
        secondary_leg_id: u32,
        max_acceptable_srtt_us: u64,
        max_acceptable_rttvar_us: u64,
        recovery_hysteresis_count: u32,
    ) -> Self {
        Self {
            primary_leg_id,
            secondary_leg_id,
            max_acceptable_srtt_us,
            max_acceptable_rttvar_us,
            recovery_hysteresis_count: recovery_hysteresis_count.max(1),
            current_state: DuplicationState::SinglePath,
            consecutive_healthy_samples: 0,
            total_single_packets: 0,
            total_duplicated_packets: 0,
            total_state_transitions: 0,
        }
    }

    /// Ingest latest RTT measurements from primary leg telemetry.
    pub fn update_primary_telemetry(&mut self, current_srtt_us: u64, current_rttvar_us: u64) {
        let is_degraded = current_srtt_us > self.max_acceptable_srtt_us
            || current_rttvar_us > self.max_acceptable_rttvar_us;

        match self.current_state {
            DuplicationState::SinglePath => {
                if is_degraded {
                    self.current_state = DuplicationState::Duplicating;
                    self.consecutive_healthy_samples = 0;
                    self.total_state_transitions += 1;
                }
            }
            DuplicationState::Duplicating => {
                if !is_degraded {
                    self.consecutive_healthy_samples += 1;
                    if self.consecutive_healthy_samples >= self.recovery_hysteresis_count {
                        self.current_state = DuplicationState::SinglePath;
                        self.consecutive_healthy_samples = 0;
                        self.total_state_transitions += 1;
                    }
                } else {
                    self.consecutive_healthy_samples = 0;
                }
            }
        }
    }

    /// Determine dispatch target for next outgoing GTP-U PDU.
    pub fn evaluate_dispatch(&mut self) -> DupDispatchDecision {
        match self.current_state {
            DuplicationState::SinglePath => {
                self.total_single_packets += 1;
                DupDispatchDecision::SinglePrimary
            }
            DuplicationState::Duplicating => {
                self.total_duplicated_packets += 1;
                DupDispatchDecision::DuplicateBoth {
                    primary_leg_id: self.primary_leg_id,
                    secondary_leg_id: self.secondary_leg_id,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_rtt_dup_lifecycle() {
        // SRTT threshold: 20ms (20,000 µs), RTTVAR threshold: 5ms (5,000 µs), Hysteresis: 3
        let mut engine = GtpuRttDupEngine::new(1, 2, 20_000, 5_000, 3);

        // 1. Initial healthy state -> Single Primary
        assert_eq!(
            engine.evaluate_dispatch(),
            DupDispatchDecision::SinglePrimary
        );

        // 2. Primary leg experiences latency spike (SRTT = 35,000 µs)
        engine.update_primary_telemetry(35_000, 2_000);
        assert_eq!(engine.current_state, DuplicationState::Duplicating);
        assert_eq!(
            engine.evaluate_dispatch(),
            DupDispatchDecision::DuplicateBoth {
                primary_leg_id: 1,
                secondary_leg_id: 2,
            }
        );

        // 3. Primary recovers, but hysteresis requires 3 healthy updates
        engine.update_primary_telemetry(15_000, 2_000); // 1st
        assert_eq!(engine.current_state, DuplicationState::Duplicating);

        engine.update_primary_telemetry(14_000, 1_500); // 2nd
        assert_eq!(engine.current_state, DuplicationState::Duplicating);

        engine.update_primary_telemetry(13_000, 1_000); // 3rd -> Reverts to SinglePath
        assert_eq!(engine.current_state, DuplicationState::SinglePath);
        assert_eq!(
            engine.evaluate_dispatch(),
            DupDispatchDecision::SinglePrimary
        );
    }
}

// =============================================================================
// 3GPP TS 29.281 / RFC 6298  GTP-U Path RTT Variance & Adaptive RTO Predictor
// =============================================================================
//
// Reliable detection of GTP-U path degradation requires not only smoothed RTT
// (SRTT) but also RTT variance (RTTVAR) tracking.  RFC 6298 specifies the
// classic TCP RTO computation that generalises well to any probe-based path
// health monitor:
//
//     RTTVAR  = (1 − β) × RTTVAR + β × |SRTT − R|
//     SRTT    = (1 − α) × SRTT   + α × R
//     RTO     = SRTT + max(G, K × RTTVAR)
//
// where R is the latest RTT sample, α = 1/8, β = 1/4, G = clock granularity,
// and K = 4.
//
// This module implements:
//   1. Per-path SRTT, RTTVAR, and RTO tracking using fixed-point integer
//      arithmetic (microseconds) to avoid floating-point dependencies.
//   2. First-sample bootstrap as specified in RFC 6298 §2.2.
//   3. Asymmetric delay detection — if the absolute difference between
//      the forward and reverse OWD estimates exceeds a configurable
//      threshold, an asymmetry alert is raised.
//   4. RTO back-off on consecutive timeouts (exponential, capped).
//
// All arithmetic is in microseconds (u64).  Pure safe Rust, zero external
// crates.

/// Default clock granularity G in microseconds (100 µs).
pub const DEFAULT_GRANULARITY_US: u64 = 100;

/// RFC 6298 constant K = 4.
pub const K_FACTOR: u64 = 4;

/// Minimum RTO in microseconds (1 second per RFC 6298 §2.4).
pub const MIN_RTO_US: u64 = 1_000_000;

/// Maximum RTO in microseconds after back-off (60 seconds).
pub const MAX_RTO_US: u64 = 60_000_000;

/// Asymmetry detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsymmetryVerdict {
    Symmetric,
    Asymmetric { forward_us: u64, reverse_us: u64 },
}

/// Per-path RTT variance tracking state.
#[derive(Debug, Clone)]
pub struct PathRttState {
    /// Smoothed RTT (SRTT) in microseconds, scaled ×8 for integer arithmetic.
    srtt_scaled: u64,
    /// RTT variance (RTTVAR) in microseconds, scaled ×4.
    rttvar_scaled: u64,
    /// Computed RTO in microseconds.
    rto_us: u64,
    /// Whether the first sample has been received.
    initialised: bool,
    /// Number of consecutive timeouts (for exponential back-off).
    consecutive_timeouts: u32,
    /// Total samples received.
    sample_count: u64,
    /// Latest raw RTT sample in microseconds.
    latest_rtt_us: u64,
    /// Minimum observed RTT.
    min_rtt_us: u64,
    /// Maximum observed RTT.
    max_rtt_us: u64,
}

impl PathRttState {
    fn new() -> Self {
        Self {
            srtt_scaled: 0,
            rttvar_scaled: 0,
            rto_us: MIN_RTO_US,
            initialised: false,
            consecutive_timeouts: 0,
            sample_count: 0,
            latest_rtt_us: 0,
            min_rtt_us: u64::MAX,
            max_rtt_us: 0,
        }
    }

    /// SRTT in microseconds (unscaled).
    pub fn srtt_us(&self) -> u64 {
        self.srtt_scaled / 8
    }

    /// RTTVAR in microseconds (unscaled).
    pub fn rttvar_us(&self) -> u64 {
        self.rttvar_scaled / 4
    }

    /// Current RTO in microseconds.
    pub fn rto_us(&self) -> u64 {
        self.rto_us
    }

    /// Latest raw RTT sample.
    pub fn latest_rtt_us(&self) -> u64 {
        self.latest_rtt_us
    }

    /// Minimum observed RTT.
    pub fn min_rtt_us(&self) -> u64 {
        self.min_rtt_us
    }

    /// Maximum observed RTT.
    pub fn max_rtt_us(&self) -> u64 {
        self.max_rtt_us
    }

    /// Total number of RTT samples.
    pub fn sample_count(&self) -> u64 {
        self.sample_count
    }

    /// Consecutive timeout counter.
    pub fn consecutive_timeouts(&self) -> u32 {
        self.consecutive_timeouts
    }
}

/// GTP-U Path RTT Variance & Adaptive RTO Engine.
pub struct GtpuRttVarianceEngine {
    /// Path states keyed by a simple tunnel endpoint ID (TEID).
    paths: Vec<(u32, PathRttState)>,
    /// Clock granularity G in microseconds.
    granularity_us: u64,
    /// Asymmetry threshold in microseconds — if |fwd − rev| > threshold, alert.
    asymmetry_threshold_us: u64,
}

impl GtpuRttVarianceEngine {
    /// Create a new engine.
    pub fn new(granularity_us: u64, asymmetry_threshold_us: u64) -> Self {
        Self {
            paths: Vec::new(),
            granularity_us: if granularity_us == 0 {
                DEFAULT_GRANULARITY_US
            } else {
                granularity_us
            },
            asymmetry_threshold_us,
        }
    }

    /// Register a path by TEID.
    pub fn register_path(&mut self, teid: u32) {
        if !self.paths.iter().any(|(t, _)| *t == teid) {
            self.paths.push((teid, PathRttState::new()));
        }
    }

    /// Return the path state for a TEID.
    pub fn path_state(&self, teid: u32) -> Option<&PathRttState> {
        self.paths.iter().find(|(t, _)| *t == teid).map(|(_, s)| s)
    }

    /// Return all tracked TEIDs.
    pub fn tracked_teids(&self) -> Vec<u32> {
        self.paths.iter().map(|(t, _)| *t).collect()
    }

    /// Feed a new RTT sample for a given TEID.
    ///
    /// Implements RFC 6298 §2.2 and §2.3.
    pub fn update_rtt(&mut self, teid: u32, rtt_us: u64) {
        let gran = self.granularity_us;
        let state = match self.paths.iter_mut().find(|(t, _)| *t == teid) {
            Some((_, s)) => s,
            None => return,
        };

        state.sample_count += 1;
        state.latest_rtt_us = rtt_us;
        if rtt_us < state.min_rtt_us {
            state.min_rtt_us = rtt_us;
        }
        if rtt_us > state.max_rtt_us {
            state.max_rtt_us = rtt_us;
        }
        state.consecutive_timeouts = 0;

        if !state.initialised {
            // RFC 6298 §2.2: first measurement.
            state.srtt_scaled = rtt_us * 8;
            state.rttvar_scaled = (rtt_us / 2) * 4;
            state.initialised = true;
        } else {
            // RFC 6298 §2.3: subsequent measurements.
            // RTTVAR = (1 - β)×RTTVAR + β×|SRTT - R|
            //   β = 1/4, so: RTTVAR_scaled = 3/4 × RTTVAR_scaled + |SRTT_scaled - R×8| / 2
            //   (all scaled ×4 to keep integer)
            let srtt_unscaled = state.srtt_scaled / 8;
            let diff = if srtt_unscaled >= rtt_us {
                srtt_unscaled - rtt_us
            } else {
                rtt_us - srtt_unscaled
            };
            // RTTVAR_scaled(×4) = 3×RTTVAR_scaled/4 + diff
            state.rttvar_scaled = (3 * state.rttvar_scaled + diff * 4) / 4;

            // SRTT = (1 - α)×SRTT + α×R, α = 1/8
            // SRTT_scaled(×8) = 7×SRTT_scaled/8 + R
            state.srtt_scaled = (7 * state.srtt_scaled + rtt_us * 8) / 8;
        }

        // RTO = SRTT + max(G, K × RTTVAR)
        let srtt = state.srtt_scaled / 8;
        let rttvar = state.rttvar_scaled / 4;
        let k_rttvar = K_FACTOR * rttvar;
        let addend = if k_rttvar > gran { k_rttvar } else { gran };
        let mut rto = srtt + addend;
        if rto < MIN_RTO_US {
            rto = MIN_RTO_US;
        }
        if rto > MAX_RTO_US {
            rto = MAX_RTO_US;
        }
        state.rto_us = rto;
    }

    /// Notify the engine that an echo probe timed out for a TEID.
    ///
    /// Implements RFC 6298 §5.5: RTO ← RTO × 2 (exponential back-off).
    pub fn notify_timeout(&mut self, teid: u32) {
        let state = match self.paths.iter_mut().find(|(t, _)| *t == teid) {
            Some((_, s)) => s,
            None => return,
        };
        state.consecutive_timeouts = state.consecutive_timeouts.saturating_add(1);
        state.rto_us = (state.rto_us * 2).min(MAX_RTO_US);
    }

    /// Evaluate forward vs reverse one-way delay for asymmetry detection.
    ///
    /// `forward_owd_us` and `reverse_owd_us` are estimated OWD values
    /// (e.g. from PTP or NTP-assisted timestamping).
    pub fn check_asymmetry(&self, forward_owd_us: u64, reverse_owd_us: u64) -> AsymmetryVerdict {
        let diff = if forward_owd_us >= reverse_owd_us {
            forward_owd_us - reverse_owd_us
        } else {
            reverse_owd_us - forward_owd_us
        };
        if diff > self.asymmetry_threshold_us {
            AsymmetryVerdict::Asymmetric {
                forward_us: forward_owd_us,
                reverse_us: reverse_owd_us,
            }
        } else {
            AsymmetryVerdict::Symmetric
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_sample_bootstrap() {
        let mut engine = GtpuRttVarianceEngine::new(DEFAULT_GRANULARITY_US, 5000);
        engine.register_path(1);
        engine.update_rtt(1, 10_000); // 10 ms

        let s = engine.path_state(1).unwrap();
        assert_eq!(s.srtt_us(), 10_000);
        assert_eq!(s.rttvar_us(), 5_000); // R/2
        assert_eq!(s.sample_count(), 1);
        assert!(s.rto_us() >= MIN_RTO_US);
    }

    #[test]
    fn test_subsequent_samples_converge() {
        let mut engine = GtpuRttVarianceEngine::new(DEFAULT_GRANULARITY_US, 5000);
        engine.register_path(1);
        // Feed stable 10 ms RTT samples.
        for _ in 0..20 {
            engine.update_rtt(1, 10_000);
        }
        let s = engine.path_state(1).unwrap();
        assert_eq!(s.srtt_us(), 10_000);
        // RTTVAR should converge towards 0 with stable RTT.
        assert!(s.rttvar_us() < 1_000);
    }

    #[test]
    fn test_timeout_backoff() {
        let mut engine = GtpuRttVarianceEngine::new(DEFAULT_GRANULARITY_US, 5000);
        engine.register_path(1);
        engine.update_rtt(1, 10_000);
        let rto1 = engine.path_state(1).unwrap().rto_us();

        engine.notify_timeout(1);
        let rto2 = engine.path_state(1).unwrap().rto_us();
        assert_eq!(rto2, (rto1 * 2).min(MAX_RTO_US));
        assert_eq!(engine.path_state(1).unwrap().consecutive_timeouts(), 1);
    }

    #[test]
    fn test_asymmetry_detection() {
        let engine = GtpuRttVarianceEngine::new(DEFAULT_GRANULARITY_US, 5000);
        assert_eq!(
            engine.check_asymmetry(8000, 8000),
            AsymmetryVerdict::Symmetric
        );
        assert_eq!(
            engine.check_asymmetry(3000, 9000),
            AsymmetryVerdict::Asymmetric {
                forward_us: 3000,
                reverse_us: 9000,
            }
        );
    }

    #[test]
    fn test_min_max_tracking() {
        let mut engine = GtpuRttVarianceEngine::new(DEFAULT_GRANULARITY_US, 5000);
        engine.register_path(1);
        engine.update_rtt(1, 5_000);
        engine.update_rtt(1, 15_000);
        engine.update_rtt(1, 10_000);
        let s = engine.path_state(1).unwrap();
        assert_eq!(s.min_rtt_us(), 5_000);
        assert_eq!(s.max_rtt_us(), 15_000);
    }
}

// =============================================================================
// 3GPP TS 29.281 5G GTP-U Path RTT Dual-EMA Smoothing & Spike Anomaly Filter
// =============================================================================
//
// In 5G packet core transport paths, RTT measurements can experience sudden
// micro-burst surges due to RAN handover buffers, transport congestion, or
// path re-routing.
//
// The Dual Exponential Moving Average (Dual-EMA) filter tracks:
//   1. Short-term (Fast) EMA: Reacts rapidly to sudden delays.
//   2. Long-term (Slow) EMA: Captures steady-state baseline transport delay.
//
// Anomaly Detection:
//   - Latency Spike Alert: Triggered when `fast_ema > spike_threshold_multiplier * slow_ema`.
//   - Route Shortened / Optimization: Triggered when `fast_ema < slow_ema * drop_ratio`.
//
// All calculations use integer fixed-point (scaled by 256). Safe Rust, zero crates.

pub const FIXED_POINT_SHIFT: u32 = 8;
pub const FIXED_POINT_SCALE: u64 = 1 << FIXED_POINT_SHIFT; // 256

/// Anomaly status for an observed RTT sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RttAnomalyVerdict {
    Normal,
    LatencySpike {
        fast_ema_us: u64,
        slow_ema_us: u64,
        ratio_percent: u32,
    },
    RouteOptimized {
        fast_ema_us: u64,
        slow_ema_us: u64,
    },
}

/// 5G GTP-U Path RTT Smoothing & Anomaly Filter Engine.
pub struct GtpuRttSmoothEngine {
    pub session_id: u32,
    /// Fast alpha weight (scaled by 256, e.g. 64/256 = 0.25)
    pub alpha_fast_scaled: u64,
    /// Slow alpha weight (scaled by 256, e.g. 16/256 = 0.0625)
    pub alpha_slow_scaled: u64,
    /// Multiplier in percentage (e.g. 150 = 1.5x) for spike detection
    pub spike_threshold_pct: u32,
    /// Fast EMA value in microseconds (scaled fixed-point)
    pub fast_ema_fp: u64,
    /// Slow EMA value in microseconds (scaled fixed-point)
    pub slow_ema_fp: u64,
    pub sample_count: u64,
    pub total_spikes_detected: u64,
}

impl GtpuRttSmoothEngine {
    pub fn new(
        session_id: u32,
        alpha_fast_frac: (u64, u64),
        alpha_slow_frac: (u64, u64),
        spike_threshold_pct: u32,
    ) -> Self {
        let alpha_fast_scaled = (alpha_fast_frac.0 * FIXED_POINT_SCALE) / alpha_fast_frac.1.max(1);
        let alpha_slow_scaled = (alpha_slow_frac.0 * FIXED_POINT_SCALE) / alpha_slow_frac.1.max(1);

        Self {
            session_id,
            alpha_fast_scaled,
            alpha_slow_scaled,
            spike_threshold_pct,
            fast_ema_fp: 0,
            slow_ema_fp: 0,
            sample_count: 0,
            total_spikes_detected: 0,
        }
    }

    /// Feed a new raw RTT measurement sample (in microseconds).
    pub fn feed_sample(&mut self, sample_us: u64) -> RttAnomalyVerdict {
        let sample_fp = sample_us << FIXED_POINT_SHIFT;

        if self.sample_count == 0 {
            self.fast_ema_fp = sample_fp;
            self.slow_ema_fp = sample_fp;
            self.sample_count = 1;
            return RttAnomalyVerdict::Normal;
        }

        self.sample_count += 1;

        // Update Fast EMA: EMA_fast = alpha * sample + (1 - alpha) * EMA_fast
        let fast_term1 = (sample_fp * self.alpha_fast_scaled) >> FIXED_POINT_SHIFT;
        let fast_term2 =
            (self.fast_ema_fp * (FIXED_POINT_SCALE - self.alpha_fast_scaled)) >> FIXED_POINT_SHIFT;
        self.fast_ema_fp = fast_term1 + fast_term2;

        // Update Slow EMA: EMA_slow = alpha * sample + (1 - alpha) * EMA_slow
        let slow_term1 = (sample_fp * self.alpha_slow_scaled) >> FIXED_POINT_SHIFT;
        let slow_term2 =
            (self.slow_ema_fp * (FIXED_POINT_SCALE - self.alpha_slow_scaled)) >> FIXED_POINT_SHIFT;
        self.slow_ema_fp = slow_term1 + slow_term2;

        let fast_us = self.fast_ema_us();
        let slow_us = self.slow_ema_us();

        if slow_us == 0 {
            return RttAnomalyVerdict::Normal;
        }

        let ratio_pct = ((fast_us * 100) / slow_us) as u32;

        if ratio_pct >= self.spike_threshold_pct {
            self.total_spikes_detected += 1;
            RttAnomalyVerdict::LatencySpike {
                fast_ema_us: fast_us,
                slow_ema_us: slow_us,
                ratio_percent: ratio_pct,
            }
        } else if ratio_pct <= 60 {
            RttAnomalyVerdict::RouteOptimized {
                fast_ema_us: fast_us,
                slow_ema_us: slow_us,
            }
        } else {
            RttAnomalyVerdict::Normal
        }
    }

    /// Retrieve fast EMA in integer microseconds.
    pub fn fast_ema_us(&self) -> u64 {
        self.fast_ema_fp >> FIXED_POINT_SHIFT
    }

    /// Retrieve slow EMA in integer microseconds.
    pub fn slow_ema_us(&self) -> u64 {
        self.slow_ema_fp >> FIXED_POINT_SHIFT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_ema_smoothing_and_spike_detection() {
        // Fast alpha = 1/4 (0.25), Slow alpha = 1/16 (0.0625), Spike = 150% (1.5x)
        let mut engine = GtpuRttSmoothEngine::new(0x7001, (1, 4), (1, 16), 150);

        // Baseline steady state at 20 ms (20,000 µs)
        for _ in 0..10 {
            engine.feed_sample(20_000);
        }

        assert_eq!(engine.fast_ema_us(), 20_000);
        assert_eq!(engine.slow_ema_us(), 20_000);

        // Sudden severe spike to 100 ms (100,000 µs)
        let v1 = engine.feed_sample(100_000);
        match v1 {
            RttAnomalyVerdict::LatencySpike {
                fast_ema_us,
                slow_ema_us,
                ratio_percent,
            } => {
                assert!(fast_ema_us > slow_ema_us);
                assert!(ratio_percent >= 150);
            }
            _ => panic!("Expected LatencySpike anomaly"),
        }

        assert_eq!(engine.total_spikes_detected, 1);
    }
}

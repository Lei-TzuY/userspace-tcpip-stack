//! 3GPP TS 38.415 / RFC 3550 — 5G GTP-U Path Jitter & Microsecond Delay Measurement Telemetry.
//!
//! In 5G URLLC and Cloud Gaming user-plane transports, tracking one-way delay (OWD)
//! and inter-arrival packet jitter is vital for SLA monitoring and dynamic jitter buffer sizing.
//!
//! This module implements:
//! * Microsecond-accurate transmit timestamp embedding and receive delta evaluation.
//! * Standard RFC 3550 exponential moving average (EMA) jitter algorithm:
//!   $$D(i-1, i) = (R_i - S_i) - (R_{i-1} - S_{i-1})$$
//!   $$J(i) = J(i-1) + \frac{|D(i-1, i)| - J(i-1)}{16}$$
//! * Real-time min / max / average latency and jitter metrics.

/// Jitter and latency measurement sample.
#[derive(Debug, Clone, PartialEq)]
pub struct GtpuLatencySample {
    pub sequence_number: u32,
    pub tx_timestamp_us: u64,
    pub rx_timestamp_us: u64,
    pub one_way_delay_us: u64,
}

/// 5G GTP-U Path Jitter & Microsecond Delay Measurement Engine.
#[derive(Debug, Clone)]
pub struct GtpuJitterTelemetryEngine {
    pub session_id: u32,
    pub last_tx_timestamp_us: Option<u64>,
    pub last_rx_timestamp_us: Option<u64>,
    /// Smoothed jitter in microseconds (RFC 3550 format)
    pub current_jitter_us: f64,
    pub min_delay_us: u64,
    pub max_delay_us: u64,
    pub total_samples: u64,
    pub sum_delay_us: u64,
}

impl GtpuJitterTelemetryEngine {
    pub fn new(session_id: u32) -> Self {
        GtpuJitterTelemetryEngine {
            session_id,
            last_tx_timestamp_us: None,
            last_rx_timestamp_us: None,
            current_jitter_us: 0.0,
            min_delay_us: u64::MAX,
            max_delay_us: 0,
            total_samples: 0,
            sum_delay_us: 0,
        }
    }

    /// Records an arriving packet with its TX and RX timestamps in microseconds.
    pub fn record_sample(&mut self, seq: u32, tx_us: u64, rx_us: u64) -> GtpuLatencySample {
        let delay_us = rx_us.saturating_sub(tx_us);

        self.min_delay_us = self.min_delay_us.min(delay_us);
        self.max_delay_us = self.max_delay_us.max(delay_us);
        self.sum_delay_us += delay_us;
        self.total_samples += 1;

        if let (Some(prev_tx), Some(prev_rx)) =
            (self.last_tx_timestamp_us, self.last_rx_timestamp_us)
        {
            let prev_delay = (prev_rx as i64) - (prev_tx as i64);
            let curr_delay = (rx_us as i64) - (tx_us as i64);
            let diff = (curr_delay - prev_delay).abs() as f64;

            // RFC 3550 Jitter filter: J = J + (diff - J)/16
            self.current_jitter_us += (diff - self.current_jitter_us) / 16.0;
        }

        self.last_tx_timestamp_us = Some(tx_us);
        self.last_rx_timestamp_us = Some(rx_us);

        GtpuLatencySample {
            sequence_number: seq,
            tx_timestamp_us: tx_us,
            rx_timestamp_us: rx_us,
            one_way_delay_us: delay_us,
        }
    }

    pub fn average_delay_us(&self) -> f64 {
        if self.total_samples == 0 {
            0.0
        } else {
            self.sum_delay_us as f64 / self.total_samples as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_jitter_telemetry_calculation() {
        let mut engine = GtpuJitterTelemetryEngine::new(1001);

        // Packet 1: TX at 1000us, RX at 1500us (Delay: 500us)
        let s1 = engine.record_sample(1, 1000, 1500);
        assert_eq!(s1.one_way_delay_us, 500);
        assert_eq!(engine.current_jitter_us, 0.0);

        // Packet 2: TX at 2000us, RX at 2550us (Delay: 550us -> diff = 50us)
        let s2 = engine.record_sample(2, 2000, 2550);
        assert_eq!(s2.one_way_delay_us, 550);
        assert!((engine.current_jitter_us - 3.125).abs() < 1e-3);

        assert_eq!(engine.min_delay_us, 500);
        assert_eq!(engine.max_delay_us, 550);
        assert_eq!(engine.average_delay_us(), 525.0);
    }
}

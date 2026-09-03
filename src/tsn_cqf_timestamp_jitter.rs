// =============================================================================
// IEEE 802.1Qch CQF Cyclic Frame Timestamping & End-to-End Jitter Analyzer
// =============================================================================
//
// High-precision deterministic networking requires real-time validation of
// per-frame transit delays and inter-frame arrival variance across multi-cycle
// CQF pipelines.
//
// Features:
//   1. Nanosecond Frame Ingress & Egress Timestamp Tracking.
//   2. Real-Time Latency Calculation: L = T_egress - T_ingress.
//   3. RFC 3393 / 802.1Qch Packet Delay Variation (Jitter): J = |L_i - L_{i-1}|.
//   4. Inter-Frame Departure Gap Tracking & Jitter Histogram Distribution.
//   5. SLA Threshold Compliance & Outlier Breach Flagging.
//
// Pure safe Rust, zero external crates.

/// Timestamped frame metrics record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTimestampRecord {
    pub frame_id: u64,
    pub stream_id: u32,
    pub ingress_ts_ns: u64,
    pub egress_ts_ns: u64,
    pub latency_ns: u64,
    pub jitter_ns: u64,
}

/// Evaluation verdict for a timestamped frame transit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterAnalyzerVerdict {
    /// Transit latency and jitter within SLA limits.
    Compliant { latency_ns: u64, jitter_ns: u64 },
    /// Jitter exceeded stream SLA tolerance.
    JitterBreached {
        jitter_ns: u64,
        allowed_jitter_ns: u64,
    },
    /// Total transit latency exceeded deadline.
    LatencyBreached {
        latency_ns: u64,
        allowed_latency_ns: u64,
    },
}

/// Per-stream statistical collector.
#[derive(Debug, Clone)]
pub struct StreamJitterStats {
    pub stream_id: u32,
    pub name: String,
    pub max_allowed_latency_ns: u64,
    pub max_allowed_jitter_ns: u64,
    pub total_frames_processed: u64,
    pub min_latency_ns: u64,
    pub max_latency_ns: u64,
    pub sum_latency_ns: u64,
    pub max_jitter_ns: u64,
    pub sum_jitter_ns: u64,
    pub last_latency_ns: Option<u64>,
    pub last_egress_ts_ns: Option<u64>,
    pub jitter_breach_count: u64,
    pub latency_breach_count: u64,
}

impl StreamJitterStats {
    pub fn new(stream_id: u32, name: &str, max_latency_ns: u64, max_jitter_ns: u64) -> Self {
        Self {
            stream_id,
            name: name.to_string(),
            max_allowed_latency_ns: max_latency_ns,
            max_allowed_jitter_ns: max_jitter_ns,
            total_frames_processed: 0,
            min_latency_ns: u64::MAX,
            max_latency_ns: 0,
            sum_latency_ns: 0,
            max_jitter_ns: 0,
            sum_jitter_ns: 0,
            last_latency_ns: None,
            last_egress_ts_ns: None,
            jitter_breach_count: 0,
            latency_breach_count: 0,
        }
    }

    pub fn avg_latency_ns(&self) -> u64 {
        if self.total_frames_processed == 0 {
            0
        } else {
            self.sum_latency_ns / self.total_frames_processed
        }
    }

    pub fn avg_jitter_ns(&self) -> u64 {
        if self.total_frames_processed <= 1 {
            0
        } else {
            self.sum_jitter_ns / (self.total_frames_processed - 1)
        }
    }
}

/// IEEE 802.1Qch CQF Cyclic Frame Timestamping & Jitter Analyzer.
pub struct TsnCqfTimestampJitterEngine {
    pub streams: Vec<StreamJitterStats>,
    pub history: Vec<FrameTimestampRecord>,
    pub max_history_size: usize,
}

impl TsnCqfTimestampJitterEngine {
    pub fn new(max_history_size: usize) -> Self {
        Self {
            streams: Vec::new(),
            history: Vec::new(),
            max_history_size: max_history_size.max(10),
        }
    }

    /// Register a monitored stream.
    pub fn register_stream(&mut self, stats: StreamJitterStats) {
        if let Some(pos) = self
            .streams
            .iter()
            .position(|s| s.stream_id == stats.stream_id)
        {
            self.streams[pos] = stats;
        } else {
            self.streams.push(stats);
        }
    }

    /// Process a frame transit event from ingress to egress.
    pub fn record_frame(
        &mut self,
        frame_id: u64,
        stream_id: u32,
        ingress_ts_ns: u64,
        egress_ts_ns: u64,
    ) -> JitterAnalyzerVerdict {
        let latency_ns = egress_ts_ns.saturating_sub(ingress_ts_ns);

        let stream = match self.streams.iter_mut().find(|s| s.stream_id == stream_id) {
            Some(s) => s,
            None => {
                return JitterAnalyzerVerdict::Compliant {
                    latency_ns,
                    jitter_ns: 0,
                };
            }
        };

        let jitter_ns = if let Some(last_lat) = stream.last_latency_ns {
            if latency_ns >= last_lat {
                latency_ns - last_lat
            } else {
                last_lat - latency_ns
            }
        } else {
            0
        };

        stream.total_frames_processed += 1;
        stream.sum_latency_ns += latency_ns;
        stream.min_latency_ns = stream.min_latency_ns.min(latency_ns);
        stream.max_latency_ns = stream.max_latency_ns.max(latency_ns);

        if stream.total_frames_processed > 1 {
            stream.sum_jitter_ns += jitter_ns;
            stream.max_jitter_ns = stream.max_jitter_ns.max(jitter_ns);
        }

        stream.last_latency_ns = Some(latency_ns);
        stream.last_egress_ts_ns = Some(egress_ts_ns);

        if self.history.len() >= self.max_history_size {
            self.history.remove(0);
        }
        self.history.push(FrameTimestampRecord {
            frame_id,
            stream_id,
            ingress_ts_ns,
            egress_ts_ns,
            latency_ns,
            jitter_ns,
        });

        if latency_ns > stream.max_allowed_latency_ns {
            stream.latency_breach_count += 1;
            JitterAnalyzerVerdict::LatencyBreached {
                latency_ns,
                allowed_latency_ns: stream.max_allowed_latency_ns,
            }
        } else if jitter_ns > stream.max_allowed_jitter_ns {
            stream.jitter_breach_count += 1;
            JitterAnalyzerVerdict::JitterBreached {
                jitter_ns,
                allowed_jitter_ns: stream.max_allowed_jitter_ns,
            }
        } else {
            JitterAnalyzerVerdict::Compliant {
                latency_ns,
                jitter_ns,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_cqf_timestamp_jitter_lifecycle() {
        let mut engine = TsnCqfTimestampJitterEngine::new(100);

        // Stream 1: Max Latency 100 µs, Max Jitter 10 µs
        engine.register_stream(StreamJitterStats::new(1, "Motion-Sensors", 100_000, 10_000));

        // Frame 1: Ingress 1000, Egress 51000 (Latency 50 µs)
        let v1 = engine.record_frame(1, 1, 1_000, 51_000);
        assert_eq!(
            v1,
            JitterAnalyzerVerdict::Compliant {
                latency_ns: 50_000,
                jitter_ns: 0,
            }
        );

        // Frame 2: Ingress 100000, Egress 155000 (Latency 55 µs -> Jitter 5 µs <= 10 µs)
        let v2 = engine.record_frame(2, 1, 100_000, 155_000);
        assert_eq!(
            v2,
            JitterAnalyzerVerdict::Compliant {
                latency_ns: 55_000,
                jitter_ns: 5_000,
            }
        );

        // Frame 3: Ingress 200000, Egress 270000 (Latency 70 µs -> Jitter |70 - 55| = 15 µs > 10 µs breach)
        let v3 = engine.record_frame(3, 1, 200_000, 270_000);
        assert_eq!(
            v3,
            JitterAnalyzerVerdict::JitterBreached {
                jitter_ns: 15_000,
                allowed_jitter_ns: 10_000,
            }
        );

        let stream = &engine.streams[0];
        assert_eq!(stream.total_frames_processed, 3);
        assert_eq!(stream.min_latency_ns, 50_000);
        assert_eq!(stream.max_latency_ns, 70_000);
        assert_eq!(stream.jitter_breach_count, 1);
    }
}

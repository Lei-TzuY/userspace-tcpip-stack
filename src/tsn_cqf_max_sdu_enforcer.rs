//! IEEE 802.1Qch / IEEE 802.1Qci Maximum SDU Size Enforcement & Cyclic Truncation Engine
//!
//! Provides deterministic per-stream Maximum Service Data Unit (max-SDU) length policing,
//! babbling oversized frame detection, non-blocking truncation/drop actions, and cyclic telemetry logging.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxSduAction {
    DropOversized,
    TruncateToMax,
    PassWithAlert,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMaxSduRule {
    pub stream_id: u32,
    pub max_sdu_bytes: usize,
    pub action: MaxSduAction,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaxSduVerdict {
    Conforming {
        stream_id: u32,
        frame_id: u32,
        frame_bytes: usize,
        cycle_idx: u64,
    },
    Truncated {
        stream_id: u32,
        frame_id: u32,
        original_bytes: usize,
        truncated_bytes: usize,
        cycle_idx: u64,
    },
    DroppedOversized {
        stream_id: u32,
        frame_id: u32,
        attempted_bytes: usize,
        max_allowed: usize,
        cycle_idx: u64,
    },
    AlertPass {
        stream_id: u32,
        frame_id: u32,
        frame_bytes: usize,
        max_allowed: usize,
        cycle_idx: u64,
    },
}

#[derive(Debug, Clone)]
pub struct TsnCqfMaxSduEnforcerEngine {
    pub cycle_duration_ns: u64,
    pub default_max_sdu: usize,
    pub rules: Vec<StreamMaxSduRule>,
    pub total_frames_inspected: usize,
    pub total_conforming_frames: usize,
    pub total_truncated_frames: usize,
    pub total_dropped_frames: usize,
    pub total_alert_frames: usize,
    pub total_bytes_inspected: usize,
    pub total_bytes_forwarded: usize,
}

impl TsnCqfMaxSduEnforcerEngine {
    pub fn new(cycle_duration_ns: u64, default_max_sdu: usize) -> Self {
        Self {
            cycle_duration_ns: cycle_duration_ns.max(10_000),
            default_max_sdu: default_max_sdu.max(64),
            rules: Vec::new(),
            total_frames_inspected: 0,
            total_conforming_frames: 0,
            total_truncated_frames: 0,
            total_dropped_frames: 0,
            total_alert_frames: 0,
            total_bytes_inspected: 0,
            total_bytes_forwarded: 0,
        }
    }

    /// Registers a custom Max-SDU rule for a stream.
    pub fn add_rule(
        &mut self,
        stream_id: u32,
        max_sdu_bytes: usize,
        action: MaxSduAction,
        description: &str,
    ) {
        self.rules.retain(|r| r.stream_id != stream_id);
        self.rules.push(StreamMaxSduRule {
            stream_id,
            max_sdu_bytes: max_sdu_bytes.max(64),
            action,
            description: description.to_string(),
        });
    }

    /// Enforces Max-SDU constraints on an incoming frame.
    /// Returns the verdict and the resulting forwarded byte count (0 if dropped).
    pub fn enforce_frame(
        &mut self,
        stream_id: u32,
        frame_id: u32,
        frame_bytes: usize,
        ingress_time_ns: u64,
    ) -> (MaxSduVerdict, usize) {
        self.total_frames_inspected += 1;
        self.total_bytes_inspected += frame_bytes;

        let cycle_idx = ingress_time_ns / self.cycle_duration_ns;

        let (max_sdu, action) = match self.rules.iter().find(|r| r.stream_id == stream_id) {
            Some(rule) => (rule.max_sdu_bytes, rule.action),
            None => (self.default_max_sdu, MaxSduAction::DropOversized),
        };

        if frame_bytes <= max_sdu {
            self.total_conforming_frames += 1;
            self.total_bytes_forwarded += frame_bytes;
            (
                MaxSduVerdict::Conforming {
                    stream_id,
                    frame_id,
                    frame_bytes,
                    cycle_idx,
                },
                frame_bytes,
            )
        } else {
            match action {
                MaxSduAction::DropOversized => {
                    self.total_dropped_frames += 1;
                    (
                        MaxSduVerdict::DroppedOversized {
                            stream_id,
                            frame_id,
                            attempted_bytes: frame_bytes,
                            max_allowed: max_sdu,
                            cycle_idx,
                        },
                        0,
                    )
                }
                MaxSduAction::TruncateToMax => {
                    self.total_truncated_frames += 1;
                    self.total_bytes_forwarded += max_sdu;
                    (
                        MaxSduVerdict::Truncated {
                            stream_id,
                            frame_id,
                            original_bytes: frame_bytes,
                            truncated_bytes: max_sdu,
                            cycle_idx,
                        },
                        max_sdu,
                    )
                }
                MaxSduAction::PassWithAlert => {
                    self.total_alert_frames += 1;
                    self.total_bytes_forwarded += frame_bytes;
                    (
                        MaxSduVerdict::AlertPass {
                            stream_id,
                            frame_id,
                            frame_bytes,
                            max_allowed: max_sdu,
                            cycle_idx,
                        },
                        frame_bytes,
                    )
                }
            }
        }
    }

    /// Resets all statistics and rule tables.
    pub fn reset(&mut self) {
        self.rules.clear();
        self.total_frames_inspected = 0;
        self.total_conforming_frames = 0;
        self.total_truncated_frames = 0;
        self.total_dropped_frames = 0;
        self.total_alert_frames = 0;
        self.total_bytes_inspected = 0;
        self.total_bytes_forwarded = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_cqf_max_sdu_enforcer_lifecycle() {
        let mut enforcer = TsnCqfMaxSduEnforcerEngine::new(125_000, 1500);

        // Register rules: Stream 1 drop oversized (> 500B), Stream 2 truncate (> 1000B), Stream 3 pass with alert (> 800B)
        enforcer.add_rule(
            1,
            500,
            MaxSduAction::DropOversized,
            "Critical Low-Latency Stream",
        );
        enforcer.add_rule(
            2,
            1000,
            MaxSduAction::TruncateToMax,
            "Telemetry Best-Effort Stream",
        );
        enforcer.add_rule(3, 800, MaxSduAction::PassWithAlert, "Diagnostics Stream");

        // 1. Stream 1 conforming frame (300B)
        let (v1, f1) = enforcer.enforce_frame(1, 101, 300, 50_000);
        assert_eq!(f1, 300);
        assert_eq!(
            v1,
            MaxSduVerdict::Conforming {
                stream_id: 1,
                frame_id: 101,
                frame_bytes: 300,
                cycle_idx: 0,
            }
        );

        // 2. Stream 1 oversized frame (600B) -> Dropped
        let (v2, f2) = enforcer.enforce_frame(1, 102, 600, 60_000);
        assert_eq!(f2, 0);
        assert_eq!(
            v2,
            MaxSduVerdict::DroppedOversized {
                stream_id: 1,
                frame_id: 102,
                attempted_bytes: 600,
                max_allowed: 500,
                cycle_idx: 0,
            }
        );

        // 3. Stream 2 oversized frame (1400B) -> Truncated to 1000B
        let (v3, f3) = enforcer.enforce_frame(2, 201, 1400, 130_000);
        assert_eq!(f3, 1000);
        assert_eq!(
            v3,
            MaxSduVerdict::Truncated {
                stream_id: 2,
                frame_id: 201,
                original_bytes: 1400,
                truncated_bytes: 1000,
                cycle_idx: 1,
            }
        );

        // 4. Stream 3 oversized frame (1200B) -> AlertPass
        let (v4, f4) = enforcer.enforce_frame(3, 301, 1200, 260_000);
        assert_eq!(f4, 1200);
        assert_eq!(
            v4,
            MaxSduVerdict::AlertPass {
                stream_id: 3,
                frame_id: 301,
                frame_bytes: 1200,
                max_allowed: 800,
                cycle_idx: 2,
            }
        );

        // 5. Default stream (stream 99) with 1600B frame -> Dropped (default max 1500B)
        let (v5, f5) = enforcer.enforce_frame(99, 901, 1600, 300_000);
        assert_eq!(f5, 0);
        assert_eq!(
            v5,
            MaxSduVerdict::DroppedOversized {
                stream_id: 99,
                frame_id: 901,
                attempted_bytes: 1600,
                max_allowed: 1500,
                cycle_idx: 2,
            }
        );

        assert_eq!(enforcer.total_frames_inspected, 5);
        assert_eq!(enforcer.total_conforming_frames, 1);
        assert_eq!(enforcer.total_dropped_frames, 2);
        assert_eq!(enforcer.total_truncated_frames, 1);
        assert_eq!(enforcer.total_alert_frames, 1);
        assert_eq!(enforcer.total_bytes_forwarded, 300 + 1000 + 1200);
    }
}

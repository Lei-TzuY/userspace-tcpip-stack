// =============================================================================
// 3GPP TS 29.281 / TS 23.501 5G GTP-U Sequence Hole Filling & Proactive NACK Engine
// =============================================================================
//
// In high-bandwidth 5G user plane interfaces (N3 gNodeB <-> UPF, N9 UPF <-> UPF),
// multi-path underlay packet loss creates sequence gaps (holes) in GTP-U streams.
//
// This engine monitors 16-bit / 32-bit GTP-U sequence numbers, tracks missing sequence
// intervals, generates compact bitmask Negative Acknowledgment (NACK) range reports
// for proactive retransmission, and updates hole state upon out-of-order recovery.
//
// Pure safe Rust, zero external dependencies.

/// Represents a detected missing sequence interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceHole {
    pub start_seq: u32,
    pub end_seq: u32,
    pub detected_at_us: u64,
    pub nack_sent_count: u32,
    pub is_resolved: bool,
}

/// Compact NACK range report sent to upstream peer for fast recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuNackReport {
    pub teid: u32,
    pub base_missing_seq: u32,
    pub count: u32,
    pub bitmask: u64,
}

/// Decision verdict for packet ingestion and hole tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoleNackVerdict {
    /// Packet arrived strictly in order or after all holes resolved.
    InOrderPacket { teid: u32, seq_number: u32 },
    /// Sequence gap detected; a new hole is recorded and NACK generated.
    HoleDetectedAndNackGenerated {
        teid: u32,
        missing_start: u32,
        missing_end: u32,
        nack_report: GtpuNackReport,
    },
    /// A previously missing sequence number arrived and filled/shrunk a hole.
    HoleFilled {
        teid: u32,
        seq_number: u32,
        remaining_holes: usize,
    },
    /// Stale duplicate packet arrived.
    StaleOrDuplicatePacket { teid: u32, seq_number: u32 },
}

/// Engine managing GTP-U Sequence Hole Detection and Proactive NACK Generation.
pub struct GtpuHoleNackEngine {
    pub teid: u32,
    pub highest_seq_seen: u32,
    pub max_active_holes: usize,
    pub nack_retransmit_interval_us: u64,
    pub holes: Vec<SequenceHole>,
    pub total_packets_ingested: u64,
    pub total_holes_detected: u64,
    pub total_holes_recovered: u64,
    pub total_nacks_generated: u64,
}

impl GtpuHoleNackEngine {
    pub fn new(teid: u32, max_active_holes: usize, nack_retransmit_interval_us: u64) -> Self {
        Self {
            teid,
            highest_seq_seen: 0,
            max_active_holes,
            nack_retransmit_interval_us,
            holes: Vec::new(),
            total_packets_ingested: 0,
            total_holes_detected: 0,
            total_holes_recovered: 0,
            total_nacks_generated: 0,
        }
    }

    /// Ingests an incoming GTP-U packet sequence number.
    pub fn ingest_packet(&mut self, seq_number: u32, arrival_time_us: u64) -> HoleNackVerdict {
        self.total_packets_ingested += 1;

        if self.highest_seq_seen == 0 && self.holes.is_empty() {
            self.highest_seq_seen = seq_number;
            return HoleNackVerdict::InOrderPacket {
                teid: self.teid,
                seq_number,
            };
        }

        if seq_number > self.highest_seq_seen {
            let gap = seq_number - self.highest_seq_seen;
            if gap > 1 {
                // Sequence gap detected: (highest_seq_seen + 1) .. (seq_number - 1)
                let missing_start = self.highest_seq_seen + 1;
                let missing_end = seq_number - 1;

                let mut bitmask: u64 = 0;
                let count = (missing_end - missing_start + 1).min(64);
                for i in 0..count {
                    bitmask |= 1 << i;
                }

                let nack_report = GtpuNackReport {
                    teid: self.teid,
                    base_missing_seq: missing_start,
                    count,
                    bitmask,
                };

                if self.holes.len() < self.max_active_holes {
                    self.holes.push(SequenceHole {
                        start_seq: missing_start,
                        end_seq: missing_end,
                        detected_at_us: arrival_time_us,
                        nack_sent_count: 1,
                        is_resolved: false,
                    });
                }

                self.highest_seq_seen = seq_number;
                self.total_holes_detected += 1;
                self.total_nacks_generated += 1;

                HoleNackVerdict::HoleDetectedAndNackGenerated {
                    teid: self.teid,
                    missing_start,
                    missing_end,
                    nack_report,
                }
            } else {
                self.highest_seq_seen = seq_number;
                HoleNackVerdict::InOrderPacket {
                    teid: self.teid,
                    seq_number,
                }
            }
        } else {
            // Check if this packet fills any existing active hole
            let mut hole_found = false;
            let mut i = 0;
            while i < self.holes.len() {
                if !self.holes[i].is_resolved
                    && seq_number >= self.holes[i].start_seq
                    && seq_number <= self.holes[i].end_seq
                {
                    hole_found = true;
                    if self.holes[i].start_seq == self.holes[i].end_seq {
                        self.holes[i].is_resolved = true;
                        self.total_holes_recovered += 1;
                    } else if seq_number == self.holes[i].start_seq {
                        self.holes[i].start_seq += 1;
                    } else if seq_number == self.holes[i].end_seq {
                        self.holes[i].end_seq -= 1;
                    } else {
                        // Split hole into two segments
                        let old_end = self.holes[i].end_seq;
                        self.holes[i].end_seq = seq_number - 1;
                        if self.holes.len() < self.max_active_holes {
                            self.holes.push(SequenceHole {
                                start_seq: seq_number + 1,
                                end_seq: old_end,
                                detected_at_us: arrival_time_us,
                                nack_sent_count: self.holes[i].nack_sent_count,
                                is_resolved: false,
                            });
                        }
                    }
                    break;
                }
                i += 1;
            }

            self.holes.retain(|h| !h.is_resolved);

            if hole_found {
                HoleNackVerdict::HoleFilled {
                    teid: self.teid,
                    seq_number,
                    remaining_holes: self.holes.len(),
                }
            } else {
                HoleNackVerdict::StaleOrDuplicatePacket {
                    teid: self.teid,
                    seq_number,
                }
            }
        }
    }

    /// Periodic check to generate retransmitted NACKs for unresolved holes.
    pub fn check_retransmit_nacks(&mut self, current_time_us: u64) -> Vec<GtpuNackReport> {
        let mut reports = Vec::new();
        for h in &mut self.holes {
            if !h.is_resolved
                && current_time_us >= h.detected_at_us + self.nack_retransmit_interval_us
            {
                h.nack_sent_count += 1;
                let count = (h.end_seq - h.start_seq + 1).min(64);
                let mut bitmask: u64 = 0;
                for i in 0..count {
                    bitmask |= 1 << i;
                }
                reports.push(GtpuNackReport {
                    teid: self.teid,
                    base_missing_seq: h.start_seq,
                    count,
                    bitmask,
                });
                self.total_nacks_generated += 1;
            }
        }
        reports
    }

    /// Resets the engine state and sequence counters.
    pub fn reset(&mut self, initial_seq: u32) {
        self.highest_seq_seen = initial_seq;
        self.holes.clear();
        self.total_packets_ingested = 0;
        self.total_holes_detected = 0;
        self.total_holes_recovered = 0;
        self.total_nacks_generated = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_hole_nack_lifecycle() {
        let mut engine = GtpuHoleNackEngine::new(0x10001, 16, 50_000);

        // First packet seq 10
        assert_eq!(
            engine.ingest_packet(10, 1000),
            HoleNackVerdict::InOrderPacket {
                teid: 0x10001,
                seq_number: 10,
            }
        );

        // Gap: next is seq 15 -> missing 11..=14
        let v_gap = engine.ingest_packet(15, 2000);
        match v_gap {
            HoleNackVerdict::HoleDetectedAndNackGenerated {
                missing_start,
                missing_end,
                nack_report,
                ..
            } => {
                assert_eq!(missing_start, 11);
                assert_eq!(missing_end, 14);
                assert_eq!(nack_report.count, 4);
                assert_eq!(nack_report.bitmask, 0b1111);
            }
            _ => panic!("Expected HoleDetectedAndNackGenerated"),
        }
        assert_eq!(engine.holes.len(), 1);

        // Ingest missing seq 11 -> hole shrinks to 12..=14
        assert_eq!(
            engine.ingest_packet(11, 3000),
            HoleNackVerdict::HoleFilled {
                teid: 0x10001,
                seq_number: 11,
                remaining_holes: 1,
            }
        );
        assert_eq!(engine.holes[0].start_seq, 12);
        assert_eq!(engine.holes[0].end_seq, 14);

        // Ingest missing seq 13 -> splits hole into 12 and 14
        assert_eq!(
            engine.ingest_packet(13, 4000),
            HoleNackVerdict::HoleFilled {
                teid: 0x10001,
                seq_number: 13,
                remaining_holes: 2,
            }
        );

        // Ingest 12 and 14 -> all holes resolved
        engine.ingest_packet(12, 5000);
        engine.ingest_packet(14, 6000);
        assert_eq!(engine.holes.len(), 0);
    }
}

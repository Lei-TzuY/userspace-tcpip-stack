// src/tsn_cqf_frame_replication.rs
//
// IEEE 802.1Qch CQF Cyclic Frame Replication & FRER Elimination Interworking Engine
// References:
// - IEEE 802.1Qch Section 8.6.8: Cyclic Queuing and Forwarding
// - IEEE 802.1CB Section 7.4: Frame Replication and Elimination for Reliability (FRER)
// - IEEE 802.1CB Section 7.4.3: Vector Recovery Algorithm & R-TAG format

pub const ETHERTYPE_R_TAG: u16 = 0xF1C1;
pub const R_TAG_HEADER_LEN: usize = 6;
pub const DEFAULT_HISTORY_WINDOW_LEN: usize = 32;

/// IEEE 802.1CB R-TAG Header (6 octets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RTagHeader {
    pub reserved: u16,
    pub sequence_number: u16,
    pub encapsulated_ethertype: u16,
}

impl RTagHeader {
    pub fn new(sequence_number: u16, encapsulated_ethertype: u16) -> Self {
        Self {
            reserved: 0,
            sequence_number,
            encapsulated_ethertype,
        }
    }

    pub fn serialize(&self) -> [u8; R_TAG_HEADER_LEN] {
        let mut buf = [0u8; R_TAG_HEADER_LEN];
        buf[0..2].copy_from_slice(&self.reserved.to_be_bytes());
        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..6].copy_from_slice(&self.encapsulated_ethertype.to_be_bytes());
        buf
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < R_TAG_HEADER_LEN {
            return None;
        }
        let reserved = u16::from_be_bytes([buf[0], buf[1]]);
        let sequence_number = u16::from_be_bytes([buf[2], buf[3]]);
        let encapsulated_ethertype = u16::from_be_bytes([buf[4], buf[5]]);
        Some(Self {
            reserved,
            sequence_number,
            encapsulated_ethertype,
        })
    }
}

/// Transmission path assignment for replicated CQF frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationPath {
    PathA,
    PathB,
}

/// Verdict for an egress frame processed by the elimination recovery engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrerEliminationVerdict {
    Delivered {
        stream_id: u32,
        sequence_number: u16,
        arrival_cycle: u64,
        source_path: ReplicationPath,
    },
    EliminatedDuplicate {
        stream_id: u32,
        sequence_number: u16,
        arrival_cycle: u64,
        source_path: ReplicationPath,
    },
    OutOfWindowDrop {
        stream_id: u32,
        sequence_number: u16,
        arrival_cycle: u64,
        source_path: ReplicationPath,
    },
}

/// Per-stream state for sequence generation (Ingress Replication).
#[derive(Debug, Clone)]
pub struct ReplicationStreamGenerator {
    pub stream_id: u32,
    pub next_sequence_number: u16,
    pub active: bool,
}

/// Per-stream state for elimination / vector recovery (Egress Elimination).
#[derive(Debug, Clone)]
pub struct EliminationStreamRecovery {
    pub stream_id: u32,
    pub highest_sequence_number: u16,
    pub history_window_mask: u32, // Bitmask of last 32 sequence numbers
    pub initialized: bool,
    pub packets_accepted: u64,
    pub packets_discarded: u64,
}

impl EliminationStreamRecovery {
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            highest_sequence_number: 0,
            history_window_mask: 0,
            initialized: false,
            packets_accepted: 0,
            packets_discarded: 0,
        }
    }

    /// IEEE 802.1CB Vector Recovery Algorithm.
    pub fn evaluate_sequence(&mut self, seq: u16) -> bool {
        if !self.initialized {
            self.highest_sequence_number = seq;
            self.history_window_mask = 1; // Mark current seq received
            self.initialized = true;
            self.packets_accepted += 1;
            return true;
        }

        let diff = seq.wrapping_sub(self.highest_sequence_number) as i16;

        if diff > 0 {
            // Sequence advanced forward
            let shift = diff as usize;
            if shift >= DEFAULT_HISTORY_WINDOW_LEN {
                self.history_window_mask = 1;
            } else {
                self.history_window_mask = (self.history_window_mask << shift) | 1;
            }
            self.highest_sequence_number = seq;
            self.packets_accepted += 1;
            true
        } else {
            // Sequence is current or behind
            let lag = (-diff) as usize;
            if lag < DEFAULT_HISTORY_WINDOW_LEN {
                let mask_bit = 1u32 << lag;
                if (self.history_window_mask & mask_bit) != 0 {
                    // Already received -> duplicate frame!
                    self.packets_discarded += 1;
                    false
                } else {
                    // Hole filled within window
                    self.history_window_mask |= mask_bit;
                    self.packets_accepted += 1;
                    true
                }
            } else {
                // Out of history window
                self.packets_discarded += 1;
                false
            }
        }
    }
}

/// TSN CQF Cyclic Frame Replication and FRER Elimination Interworking Engine.
#[derive(Debug, Clone)]
pub struct TsnCqfFrameReplicationEngine {
    pub cycle_duration_ns: u64,
    pub ingress_generators: Vec<ReplicationStreamGenerator>,
    pub egress_recoveries: Vec<EliminationStreamRecovery>,
    pub total_replicated_frames: u64,
    pub total_eliminated_duplicates: u64,
    pub total_delivered_frames: u64,
    pub total_out_of_window_drops: u64,
}

impl TsnCqfFrameReplicationEngine {
    pub fn new(cycle_duration_ns: u64) -> Self {
        Self {
            cycle_duration_ns,
            ingress_generators: Vec::new(),
            egress_recoveries: Vec::new(),
            total_replicated_frames: 0,
            total_eliminated_duplicates: 0,
            total_delivered_frames: 0,
            total_out_of_window_drops: 0,
        }
    }

    /// Register a stream for ingress cyclic frame replication.
    pub fn register_stream(&mut self, stream_id: u32) {
        if !self
            .ingress_generators
            .iter()
            .any(|g| g.stream_id == stream_id)
        {
            self.ingress_generators.push(ReplicationStreamGenerator {
                stream_id,
                next_sequence_number: 1,
                active: true,
            });
        }
        if !self
            .egress_recoveries
            .iter()
            .any(|r| r.stream_id == stream_id)
        {
            self.egress_recoveries
                .push(EliminationStreamRecovery::new(stream_id));
        }
    }

    /// Generate replicated CQF frames with IEEE 802.1CB R-TAG for Path A and Path B.
    pub fn replicate_frame(
        &mut self,
        stream_id: u32,
        encapsulated_ethertype: u16,
    ) -> Option<(RTagHeader, ReplicationPath, ReplicationPath)> {
        let generator = self
            .ingress_generators
            .iter_mut()
            .find(|g| g.stream_id == stream_id && g.active)?;

        let seq = generator.next_sequence_number;
        generator.next_sequence_number = generator.next_sequence_number.wrapping_add(1);

        let r_tag = RTagHeader::new(seq, encapsulated_ethertype);
        self.total_replicated_frames += 2; // Generated on Path A and Path B

        Some((r_tag, ReplicationPath::PathA, ReplicationPath::PathB))
    }

    /// Process an arriving frame at the egress elimination engine.
    pub fn process_egress_frame(
        &mut self,
        stream_id: u32,
        sequence_number: u16,
        arrival_cycle: u64,
        source_path: ReplicationPath,
    ) -> FrerEliminationVerdict {
        let recovery = match self
            .egress_recoveries
            .iter_mut()
            .find(|r| r.stream_id == stream_id)
        {
            Some(r) => r,
            None => {
                let mut r = EliminationStreamRecovery::new(stream_id);
                r.evaluate_sequence(sequence_number);
                self.egress_recoveries.push(r);
                self.total_delivered_frames += 1;
                return FrerEliminationVerdict::Delivered {
                    stream_id,
                    sequence_number,
                    arrival_cycle,
                    source_path,
                };
            }
        };

        if recovery.evaluate_sequence(sequence_number) {
            self.total_delivered_frames += 1;
            FrerEliminationVerdict::Delivered {
                stream_id,
                sequence_number,
                arrival_cycle,
                source_path,
            }
        } else {
            self.total_eliminated_duplicates += 1;
            FrerEliminationVerdict::EliminatedDuplicate {
                stream_id,
                sequence_number,
                arrival_cycle,
                source_path,
            }
        }
    }

    /// Reset all stream state and counters.
    pub fn reset(&mut self) {
        self.ingress_generators.clear();
        self.egress_recoveries.clear();
        self.total_replicated_frames = 0;
        self.total_eliminated_duplicates = 0;
        self.total_delivered_frames = 0;
        self.total_out_of_window_drops = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtag_codec() {
        let rtag = RTagHeader::new(42, 0x0800);
        let bytes = rtag.serialize();
        assert_eq!(bytes.len(), R_TAG_HEADER_LEN);
        let parsed = RTagHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, rtag);
    }

    #[test]
    fn test_tsn_cqf_replication_and_elimination_flow() {
        let mut engine = TsnCqfFrameReplicationEngine::new(100_000);
        engine.register_stream(101);

        // 1. Ingress replication generates dual copies on Path A and Path B
        let (rtag1, path_a, path_b) = engine.replicate_frame(101, 0x0800).unwrap();
        assert_eq!(rtag1.sequence_number, 1);
        assert_eq!(path_a, ReplicationPath::PathA);
        assert_eq!(path_b, ReplicationPath::PathB);

        // 2. Primary frame arrives first on Path A at cycle 10 -> Delivered
        let v1 = engine.process_egress_frame(101, 1, 10, ReplicationPath::PathA);
        assert_eq!(
            v1,
            FrerEliminationVerdict::Delivered {
                stream_id: 101,
                sequence_number: 1,
                arrival_cycle: 10,
                source_path: ReplicationPath::PathA,
            }
        );

        // 3. Duplicate copy arrives late on Path B at cycle 11 -> EliminatedDuplicate
        let v2 = engine.process_egress_frame(101, 1, 11, ReplicationPath::PathB);
        assert_eq!(
            v2,
            FrerEliminationVerdict::EliminatedDuplicate {
                stream_id: 101,
                sequence_number: 1,
                arrival_cycle: 11,
                source_path: ReplicationPath::PathB,
            }
        );

        assert_eq!(engine.total_delivered_frames, 1);
        assert_eq!(engine.total_eliminated_duplicates, 1);
        assert_eq!(engine.total_replicated_frames, 2);
    }
}

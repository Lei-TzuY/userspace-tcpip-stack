// =============================================================================
// IEEE 802.1Qch CQF Stream Redundancy & Dual-Ring Cyclic Alignment Engine
// =============================================================================
//
// In industrial and automotive TSN dual counter-rotating ring topologies
// (Ring 0 / Primary and Ring 1 / Secondary), CQF frames traverse paths with
// unequal hop counts and propagation delays before reaching the destination
// Ring Interworking Bridge (RIB).
//
// Without alignment, frames arriving on the shorter ring arrive multiple CQF cycles
// ahead of the longer ring, causing large jitter buffers and sequence recovery
// desynchronization.
//
// The Dual-Ring Cyclic Alignment Engine aligns cycle phase offsets across both
// rings, buffering early frames until the paired cycle boundary on the secondary
// ring, and feeds aligned pairs into IEEE 802.1CB FRER deduplication engines.
//
// Features:
//   1. Ring Hop & Cycle Delay Offset Modeling per Ring Path.
//   2. Target Synchronized CQF Cycle Calculation ($C_{\text{target}} = C_{\text{tx}} + \max(\Delta_0, \Delta_1)$).
//   3. Ring Redundancy State Machine (DualRingAligned, SingleRingDegraded).
//   4. Early Frame Hold Buffer with Cycle Drain Timeout.
//
// Pure safe Rust, zero external crates.

/// Dual-Ring Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsnRingId {
    Ring0 = 0,
    Ring1 = 1,
}

/// Ring path delay and hop configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingPathConfig {
    pub ring_id: TsnRingId,
    pub hop_count: u32,
    pub cycle_delay: u32, // CQF cycles required to traverse the ring
    pub is_active: bool,
}

/// Ingested ring frame pending alignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingAlignedFrame {
    pub stream_id: u32,
    pub sequence_num: u32,
    pub origin_tx_cycle: u64,
    pub arrival_cycle: u64,
    pub ring_id: TsnRingId,
    pub payload_bytes: usize,
}

/// Alignment verdict when a frame is processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingAlignVerdict {
    /// Frame arrived first from the shorter ring; held in buffer until secondary arrives or target cycle reached.
    HoldForAlignment {
        stream_id: u32,
        seq_num: u32,
        release_cycle: u64,
    },
    /// Frame arrived and paired with existing buffered frame; ready for FRER deduplication release.
    AlignedPairReady {
        stream_id: u32,
        seq_num: u32,
        release_cycle: u64,
        paired_ring: TsnRingId,
    },
    /// Frame arrived on single surviving ring (other ring down/failed); released directly at target cycle.
    SingleRingPass {
        stream_id: u32,
        seq_num: u32,
        release_cycle: u64,
        ring_id: TsnRingId,
    },
    /// Duplicate frame arrived after target cycle already released; dropped as stale.
    StaleDuplicateDrop {
        stream_id: u32,
        seq_num: u32,
        ring_id: TsnRingId,
    },
}

/// TSN Dual-Ring CQF Alignment Engine.
pub struct TsnCqfRingAlignEngine {
    pub cycle_duration_ns: u64,
    pub ring0_config: RingPathConfig,
    pub ring1_config: RingPathConfig,
    pub held_frames: Vec<RingAlignedFrame>,
    pub released_sequences: Vec<(u32, u32)>, // (stream_id, seq_num)
    pub total_aligned_pairs: u64,
    pub total_single_ring_frames: u64,
    pub total_stale_drops: u64,
}

impl TsnCqfRingAlignEngine {
    pub fn new(cycle_duration_ns: u64, ring0_hops: u32, ring1_hops: u32) -> Self {
        Self {
            cycle_duration_ns,
            ring0_config: RingPathConfig {
                ring_id: TsnRingId::Ring0,
                hop_count: ring0_hops,
                cycle_delay: ring0_hops.max(1),
                is_active: true,
            },
            ring1_config: RingPathConfig {
                ring_id: TsnRingId::Ring1,
                hop_count: ring1_hops,
                cycle_delay: ring1_hops.max(1),
                is_active: true,
            },
            held_frames: Vec::new(),
            released_sequences: Vec::new(),
            total_aligned_pairs: 0,
            total_single_ring_frames: 0,
            total_stale_drops: 0,
        }
    }

    /// Calculate max cycle latency across dual rings.
    pub fn max_ring_delay(&self) -> u32 {
        self.ring0_config
            .cycle_delay
            .max(self.ring1_config.cycle_delay)
    }

    /// Ingest a frame from one of the dual rings at the given current cycle.
    pub fn ingest_frame(
        &mut self,
        ring_id: TsnRingId,
        stream_id: u32,
        sequence_num: u32,
        origin_tx_cycle: u64,
        current_cycle: u64,
        payload_bytes: usize,
    ) -> RingAlignVerdict {
        // Check if this sequence was already released
        if self.released_sequences.contains(&(stream_id, sequence_num)) {
            self.total_stale_drops += 1;
            return RingAlignVerdict::StaleDuplicateDrop {
                stream_id,
                seq_num: sequence_num,
                ring_id,
            };
        }

        let target_release_cycle = origin_tx_cycle + self.max_ring_delay() as u64;

        // Check if partner frame from the other ring is already in buffer
        let other_ring = match ring_id {
            TsnRingId::Ring0 => TsnRingId::Ring1,
            TsnRingId::Ring1 => TsnRingId::Ring0,
        };

        if let Some(pos) = self.held_frames.iter().position(|f| {
            f.stream_id == stream_id && f.sequence_num == sequence_num && f.ring_id == other_ring
        }) {
            // Found matching frame from the other ring!
            self.held_frames.remove(pos);
            self.released_sequences.push((stream_id, sequence_num));
            if self.released_sequences.len() > 1000 {
                self.released_sequences.remove(0);
            }
            self.total_aligned_pairs += 1;

            RingAlignVerdict::AlignedPairReady {
                stream_id,
                seq_num: sequence_num,
                release_cycle: target_release_cycle,
                paired_ring: other_ring,
            }
        } else {
            let partner_active = match other_ring {
                TsnRingId::Ring0 => self.ring0_config.is_active,
                TsnRingId::Ring1 => self.ring1_config.is_active,
            };

            if !partner_active {
                // Partner ring is down; release immediately as single ring pass
                self.released_sequences.push((stream_id, sequence_num));
                self.total_single_ring_frames += 1;
                RingAlignVerdict::SingleRingPass {
                    stream_id,
                    seq_num: sequence_num,
                    release_cycle: target_release_cycle,
                    ring_id,
                }
            } else {
                // Buffer frame until partner arrives or cycle ticks
                self.held_frames.push(RingAlignedFrame {
                    stream_id,
                    sequence_num,
                    origin_tx_cycle,
                    arrival_cycle: current_cycle,
                    ring_id,
                    payload_bytes,
                });
                RingAlignVerdict::HoldForAlignment {
                    stream_id,
                    seq_num: sequence_num,
                    release_cycle: target_release_cycle,
                }
            }
        }
    }

    /// Cycle tick handler: flush any held frames whose target release cycle has arrived.
    pub fn advance_cycle(&mut self, current_cycle: u64) -> Vec<RingAlignedFrame> {
        let mut expired = Vec::new();
        let max_delay = self.max_ring_delay() as u64;

        let mut i = 0;
        while i < self.held_frames.len() {
            let target_cycle = self.held_frames[i].origin_tx_cycle + max_delay;
            if current_cycle >= target_cycle {
                let frame = self.held_frames.remove(i);
                self.released_sequences
                    .push((frame.stream_id, frame.sequence_num));
                self.total_single_ring_frames += 1;
                expired.push(frame);
            } else {
                i += 1;
            }
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_cqf_ring_align_lifecycle() {
        // Ring 0 has 2 hops (delay = 2 cycles), Ring 1 has 5 hops (delay = 5 cycles)
        let mut engine = TsnCqfRingAlignEngine::new(100_000, 2, 5);

        assert_eq!(engine.max_ring_delay(), 5);

        // 1. Frame sent at cycle 10.
        // Arrives on Ring 0 at cycle 12 (10 + 2)
        let v1 = engine.ingest_frame(TsnRingId::Ring0, 1, 100, 10, 12, 500);
        assert_eq!(
            v1,
            RingAlignVerdict::HoldForAlignment {
                stream_id: 1,
                seq_num: 100,
                release_cycle: 15, // 10 + 5
            }
        );
        assert_eq!(engine.held_frames.len(), 1);

        // 2. Matching frame arrives on Ring 1 at cycle 15 (10 + 5)
        let v2 = engine.ingest_frame(TsnRingId::Ring1, 1, 100, 10, 15, 500);
        assert_eq!(
            v2,
            RingAlignVerdict::AlignedPairReady {
                stream_id: 1,
                seq_num: 100,
                release_cycle: 15,
                paired_ring: TsnRingId::Ring0,
            }
        );
        assert_eq!(engine.held_frames.len(), 0);
        assert_eq!(engine.total_aligned_pairs, 1);

        // 3. Duplicate arrives later -> stale drop
        let v3 = engine.ingest_frame(TsnRingId::Ring0, 1, 100, 10, 16, 500);
        assert_eq!(
            v3,
            RingAlignVerdict::StaleDuplicateDrop {
                stream_id: 1,
                seq_num: 100,
                ring_id: TsnRingId::Ring0,
            }
        );
    }
}

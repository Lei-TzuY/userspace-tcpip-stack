//! 3GPP TS 29.281 / TS 38.415 5G GTP-U Reliable Transport Sliding Window ACK / SACK Engine
//!
//! Provides cumulative acknowledgment tracking, selective acknowledgment (SACK) block generation,
//! sliding window buffering, and out-of-order packet recovery signaling.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlock {
    pub start_seq: u32,
    pub end_seq: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuAckReport {
    pub teid: u32,
    pub cumulative_ack: u32,
    pub sack_blocks: Vec<SackBlock>,
    pub timestamp_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlidingWindowAckVerdict {
    PacketAckedInOrder {
        teid: u32,
        seq_number: u32,
        cumulative_ack: u32,
    },
    OutOfOrderSackGenerated {
        teid: u32,
        received_seq: u32,
        cumulative_ack: u32,
        sack_blocks: Vec<SackBlock>,
    },
    DuplicatePacketIgnored {
        teid: u32,
        seq_number: u32,
        cumulative_ack: u32,
    },
}

#[derive(Debug, Clone)]
pub struct GtpuSlidingWindowAckEngine {
    pub teid: u32,
    pub window_size: usize,
    pub cumulative_ack: u32,
    pub highest_seq_seen: u32,
    pub received_ooo_seqs: Vec<u32>,
    pub total_packets_received: usize,
    pub total_acks_generated: usize,
    pub total_duplicate_packets: usize,
}

impl GtpuSlidingWindowAckEngine {
    pub fn new(teid: u32, window_size: usize) -> Self {
        Self {
            teid,
            window_size: window_size.max(8),
            cumulative_ack: 0,
            highest_seq_seen: 0,
            received_ooo_seqs: Vec::new(),
            total_packets_received: 0,
            total_acks_generated: 0,
            total_duplicate_packets: 0,
        }
    }

    /// Ingests a packet sequence number and evaluates cumulative ACK / SACK blocks.
    pub fn ingest_packet(&mut self, seq: u32) -> SlidingWindowAckVerdict {
        self.total_packets_received += 1;

        if seq <= self.cumulative_ack || self.received_ooo_seqs.contains(&seq) {
            self.total_duplicate_packets += 1;
            return SlidingWindowAckVerdict::DuplicatePacketIgnored {
                teid: self.teid,
                seq_number: seq,
                cumulative_ack: self.cumulative_ack,
            };
        }

        if seq == self.cumulative_ack + 1 {
            self.cumulative_ack = seq;
            // Advance cumulative ack if consecutive packets were already in received_ooo_seqs
            while let Some(pos) = self
                .received_ooo_seqs
                .iter()
                .position(|&s| s == self.cumulative_ack + 1)
            {
                self.cumulative_ack += 1;
                self.received_ooo_seqs.remove(pos);
            }

            if seq > self.highest_seq_seen {
                self.highest_seq_seen = seq;
            }

            self.total_acks_generated += 1;
            SlidingWindowAckVerdict::PacketAckedInOrder {
                teid: self.teid,
                seq_number: seq,
                cumulative_ack: self.cumulative_ack,
            }
        } else {
            // Out-of-order arrival
            if seq > self.highest_seq_seen {
                self.highest_seq_seen = seq;
            }
            self.received_ooo_seqs.push(seq);
            self.received_ooo_seqs.sort_unstable();
            self.received_ooo_seqs.dedup();

            let sack_blocks = self.compute_sack_blocks();
            self.total_acks_generated += 1;
            SlidingWindowAckVerdict::OutOfOrderSackGenerated {
                teid: self.teid,
                received_seq: seq,
                cumulative_ack: self.cumulative_ack,
                sack_blocks,
            }
        }
    }

    /// Computes consolidated contiguous SACK blocks from out-of-order received sequences.
    pub fn compute_sack_blocks(&self) -> Vec<SackBlock> {
        let mut blocks = Vec::new();
        if self.received_ooo_seqs.is_empty() {
            return blocks;
        }

        let mut start = self.received_ooo_seqs[0];
        let mut end = start;

        for &s in &self.received_ooo_seqs[1..] {
            if s == end + 1 {
                end = s;
            } else {
                blocks.push(SackBlock {
                    start_seq: start,
                    end_seq: end,
                });
                start = s;
                end = s;
            }
        }
        blocks.push(SackBlock {
            start_seq: start,
            end_seq: end,
        });
        blocks
    }

    /// Generates a full ACK / SACK wire report.
    pub fn generate_ack_report(&self, timestamp_us: u64) -> GtpuAckReport {
        GtpuAckReport {
            teid: self.teid,
            cumulative_ack: self.cumulative_ack,
            sack_blocks: self.compute_sack_blocks(),
            timestamp_us,
        }
    }

    /// Resets the engine state.
    pub fn reset(&mut self, initial_seq: u32) {
        self.cumulative_ack = initial_seq;
        self.highest_seq_seen = initial_seq;
        self.received_ooo_seqs.clear();
        self.total_packets_received = 0;
        self.total_acks_generated = 0;
        self.total_duplicate_packets = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sliding_window_in_order_and_sack() {
        let mut engine = GtpuSlidingWindowAckEngine::new(0x1234, 64);

        let v1 = engine.ingest_packet(1);
        assert!(matches!(
            v1,
            SlidingWindowAckVerdict::PacketAckedInOrder {
                cumulative_ack: 1,
                ..
            }
        ));

        let v2 = engine.ingest_packet(3);
        assert!(matches!(
            v2,
            SlidingWindowAckVerdict::OutOfOrderSackGenerated {
                cumulative_ack: 1,
                ..
            }
        ));

        let v3 = engine.ingest_packet(4);
        assert!(matches!(
            v3,
            SlidingWindowAckVerdict::OutOfOrderSackGenerated {
                cumulative_ack: 1,
                ..
            }
        ));

        let v4 = engine.ingest_packet(2);
        assert!(matches!(
            v4,
            SlidingWindowAckVerdict::PacketAckedInOrder {
                cumulative_ack: 4,
                ..
            }
        ));
        assert!(engine.received_ooo_seqs.is_empty());
    }
}

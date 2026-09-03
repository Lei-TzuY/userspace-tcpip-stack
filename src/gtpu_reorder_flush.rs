//! 3GPP TS 29.281 / TS 38.415 5G GTP-U Sequence Reordering Buffer with Dynamic Packet Drop & Early Flush Engine.
//!
//! Reorders out-of-order GTP-U G-PDU packets arriving across cellular and non-3GPP multi-path legs,
//! enforcing bounded in-order delivery and proactive early-flush upon packet loss detection.

/// Single buffered out-of-order packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorderBufferedPacket {
    pub seq_number: u32,
    pub payload_bytes: usize,
    pub arrival_time_us: u64,
}

/// Verdict returned when ingesting, timing out, or early-flushing reordering buffers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GtpuReorderFlushVerdict {
    /// Packet arrived strictly in sequence and was immediately forwarded.
    InOrderPacketEmitted {
        seq_number: u32,
        payload_bytes: usize,
    },
    /// Packet arrived out-of-order and was placed into the reordering queue.
    PacketBuffered {
        seq_number: u32,
        buffer_depth: usize,
        next_expected_seq: u32,
    },
    /// A missing sequence gap was skipped (via early notification or timer expiry), releasing consecutive packets.
    GapSkippedEarlyFlush {
        skipped_seq_count: u32,
        new_expected_seq: u32,
        flushed_packets: Vec<(u32, usize)>,
    },
    /// Packet sequence is older than current expected sequence window and was discarded.
    DuplicateOrStaleDrop {
        seq_number: u32,
        next_expected_seq: u32,
    },
    /// Packet sequence exceeds the maximum reordering window and was discarded.
    WindowOverflowDrop {
        seq_number: u32,
        max_allowed_seq: u32,
    },
    /// No packets flushed during timer check.
    NoTimeoutFlush,
}

/// 5G GTP-U Reordering and Early Flush Engine.
#[derive(Debug, Clone)]
pub struct GtpuReorderFlushEngine {
    pub window_size: u32,
    pub max_hold_timeout_us: u64,
    pub next_expected_seq: u32,
    pub buffer: Vec<ReorderBufferedPacket>,
    pub total_received: u64,
    pub total_in_order_emitted: u64,
    pub total_buffered: u64,
    pub total_flushed_on_gap: u64,
    pub total_stale_drops: u64,
    pub total_overflow_drops: u64,
}

impl GtpuReorderFlushEngine {
    /// Creates a new reordering engine with the given window size and hold timeout.
    pub fn new(window_size: u32, max_hold_timeout_us: u64, initial_seq: u32) -> Self {
        Self {
            window_size,
            max_hold_timeout_us,
            next_expected_seq: initial_seq,
            buffer: Vec::new(),
            total_received: 0,
            total_in_order_emitted: 0,
            total_buffered: 0,
            total_flushed_on_gap: 0,
            total_stale_drops: 0,
            total_overflow_drops: 0,
        }
    }

    /// Ingests a GTP-U packet with sequence number.
    pub fn ingest_packet(
        &mut self,
        seq_number: u32,
        payload_bytes: usize,
        arrival_time_us: u64,
    ) -> GtpuReorderFlushVerdict {
        self.total_received += 1;

        // Check if stale or duplicate
        if seq_number < self.next_expected_seq {
            self.total_stale_drops += 1;
            return GtpuReorderFlushVerdict::DuplicateOrStaleDrop {
                seq_number,
                next_expected_seq: self.next_expected_seq,
            };
        }

        // Check if out of window
        if seq_number >= self.next_expected_seq + self.window_size {
            self.total_overflow_drops += 1;
            return GtpuReorderFlushVerdict::WindowOverflowDrop {
                seq_number,
                max_allowed_seq: self.next_expected_seq + self.window_size - 1,
            };
        }

        // Check if strictly in-order
        if seq_number == self.next_expected_seq {
            self.next_expected_seq += 1;
            self.total_in_order_emitted += 1;

            // Drain any consecutive packets already in buffer
            let mut flushed = Vec::new();
            flushed.push((seq_number, payload_bytes));

            while let Some(pos) = self
                .buffer
                .iter()
                .position(|p| p.seq_number == self.next_expected_seq)
            {
                let p = self.buffer.remove(pos);
                self.next_expected_seq += 1;
                self.total_in_order_emitted += 1;
                flushed.push((p.seq_number, p.payload_bytes));
            }

            if flushed.len() == 1 {
                GtpuReorderFlushVerdict::InOrderPacketEmitted {
                    seq_number,
                    payload_bytes,
                }
            } else {
                GtpuReorderFlushVerdict::GapSkippedEarlyFlush {
                    skipped_seq_count: 0,
                    new_expected_seq: self.next_expected_seq,
                    flushed_packets: flushed,
                }
            }
        } else {
            // Buffer out-of-order packet
            if !self.buffer.iter().any(|p| p.seq_number == seq_number) {
                self.buffer.push(ReorderBufferedPacket {
                    seq_number,
                    payload_bytes,
                    arrival_time_us,
                });
                self.buffer.sort_by_key(|p| p.seq_number);
                self.total_buffered += 1;
            }

            GtpuReorderFlushVerdict::PacketBuffered {
                seq_number,
                buffer_depth: self.buffer.len(),
                next_expected_seq: self.next_expected_seq,
            }
        }
    }

    /// Proactively notifies the engine that a missing packet sequence was lost / dropped by lower layers.
    pub fn notify_gap_dropped(&mut self, dead_seq: u32) -> GtpuReorderFlushVerdict {
        if dead_seq >= self.next_expected_seq && !self.buffer.is_empty() {
            let skipped = dead_seq - self.next_expected_seq + 1;
            self.next_expected_seq = dead_seq + 1;
            self.total_flushed_on_gap += 1;

            // Flush all consecutive packets starting at or above new next_expected_seq
            let mut flushed = Vec::new();
            while let Some(pos) = self
                .buffer
                .iter()
                .position(|p| p.seq_number <= self.next_expected_seq)
            {
                let p = self.buffer.remove(pos);
                if p.seq_number == self.next_expected_seq {
                    self.next_expected_seq += 1;
                }
                flushed.push((p.seq_number, p.payload_bytes));
            }

            // Also advance if buffer has immediately next sequences
            while let Some(pos) = self
                .buffer
                .iter()
                .position(|p| p.seq_number == self.next_expected_seq)
            {
                let p = self.buffer.remove(pos);
                self.next_expected_seq += 1;
                flushed.push((p.seq_number, p.payload_bytes));
            }

            GtpuReorderFlushVerdict::GapSkippedEarlyFlush {
                skipped_seq_count: skipped,
                new_expected_seq: self.next_expected_seq,
                flushed_packets: flushed,
            }
        } else {
            GtpuReorderFlushVerdict::NoTimeoutFlush
        }
    }

    /// Checks buffer timeout and flushes if oldest buffered packet exceeded max hold duration.
    pub fn check_timeouts(&mut self, current_time_us: u64) -> GtpuReorderFlushVerdict {
        if let Some(oldest) = self.buffer.first() {
            if current_time_us.saturating_sub(oldest.arrival_time_us) >= self.max_hold_timeout_us {
                let target_seq = oldest.seq_number;
                let skipped = target_seq.saturating_sub(self.next_expected_seq);
                self.next_expected_seq = target_seq;
                self.total_flushed_on_gap += 1;

                let mut flushed = Vec::new();
                while let Some(pos) = self
                    .buffer
                    .iter()
                    .position(|p| p.seq_number == self.next_expected_seq)
                {
                    let p = self.buffer.remove(pos);
                    self.next_expected_seq += 1;
                    flushed.push((p.seq_number, p.payload_bytes));
                }

                return GtpuReorderFlushVerdict::GapSkippedEarlyFlush {
                    skipped_seq_count: skipped,
                    new_expected_seq: self.next_expected_seq,
                    flushed_packets: flushed,
                };
            }
        }
        GtpuReorderFlushVerdict::NoTimeoutFlush
    }

    /// Resets the reordering engine.
    pub fn reset(&mut self, initial_seq: u32) {
        self.buffer.clear();
        self.next_expected_seq = initial_seq;
        self.total_received = 0;
        self.total_in_order_emitted = 0;
        self.total_buffered = 0;
        self.total_flushed_on_gap = 0;
        self.total_stale_drops = 0;
        self.total_overflow_drops = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_reorder_flush_lifecycle() {
        let mut engine = GtpuReorderFlushEngine::new(64, 50_000, 100);

        // 1. Packet 100 in-order
        let v1 = engine.ingest_packet(100, 1400, 1000);
        assert_eq!(
            v1,
            GtpuReorderFlushVerdict::InOrderPacketEmitted {
                seq_number: 100,
                payload_bytes: 1400,
            }
        );
        assert_eq!(engine.next_expected_seq, 101);

        // 2. Packet 102 arrives before 101 -> Buffered
        let v2 = engine.ingest_packet(102, 1400, 2000);
        assert_eq!(
            v2,
            GtpuReorderFlushVerdict::PacketBuffered {
                seq_number: 102,
                buffer_depth: 1,
                next_expected_seq: 101,
            }
        );

        // 3. Packet 103 arrives -> Buffered
        let v3 = engine.ingest_packet(103, 1400, 3000);
        assert_eq!(
            v3,
            GtpuReorderFlushVerdict::PacketBuffered {
                seq_number: 103,
                buffer_depth: 2,
                next_expected_seq: 101,
            }
        );

        // 4. Missing packet 101 is reported dead/dropped -> triggers Early Flush of 102 & 103
        let v4 = engine.notify_gap_dropped(101);
        match v4 {
            GtpuReorderFlushVerdict::GapSkippedEarlyFlush {
                skipped_seq_count,
                new_expected_seq,
                flushed_packets,
            } => {
                assert_eq!(skipped_seq_count, 1);
                assert_eq!(new_expected_seq, 104);
                assert_eq!(flushed_packets.len(), 2);
                assert_eq!(flushed_packets[0].0, 102);
                assert_eq!(flushed_packets[1].0, 103);
            }
            _ => panic!("Expected GapSkippedEarlyFlush"),
        }
        assert_eq!(engine.buffer.len(), 0);
    }
}

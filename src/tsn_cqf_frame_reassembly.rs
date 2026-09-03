//! IEEE 802.1Qch / IEEE 802.1Qbu Cyclic Frame Preemption Fragment Reassembly Engine
//!
//! Provides deterministic reassembly of preempted frame fragments (mPackets)
//! across cyclic gate transitions with timeout eviction, CRC verification,
//! and target CQF cycle alignment.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsnFragment {
    pub stream_id: u32,
    pub frame_id: u32,
    pub fragment_seq: u16,
    pub is_last: bool,
    pub payload_bytes: usize,
    pub timestamp_ns: u64,
    pub crc_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassemblyBuffer {
    pub stream_id: u32,
    pub frame_id: u32,
    pub next_expected_seq: u16,
    pub accumulated_bytes: usize,
    pub started_at_ns: u64,
    pub target_cycle: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameReassemblyVerdict {
    FragmentBuffered {
        stream_id: u32,
        frame_id: u32,
        fragment_seq: u16,
        accumulated_bytes: usize,
    },
    FrameReassembledAndScheduled {
        stream_id: u32,
        frame_id: u32,
        total_bytes: usize,
        target_cycle: u64,
    },
    SequenceMismatchDropped {
        stream_id: u32,
        frame_id: u32,
        expected_seq: u16,
        received_seq: u16,
    },
    CrcErrorDropped {
        stream_id: u32,
        frame_id: u32,
        fragment_seq: u16,
    },
    BufferOverflowDropped {
        stream_id: u32,
        frame_id: u32,
        attempted_bytes: usize,
        max_capacity: usize,
    },
    TimeoutFlushed {
        stream_id: u32,
        frame_id: u32,
        dropped_bytes: usize,
    },
}

#[derive(Debug, Clone)]
pub struct TsnCqfFrameReassemblyEngine {
    pub cycle_duration_ns: u64,
    pub max_reassembly_timeout_ns: u64,
    pub max_buffer_bytes_per_frame: usize,
    pub buffers: Vec<ReassemblyBuffer>,
    pub total_fragments_ingested: usize,
    pub total_frames_reassembled: usize,
    pub total_crc_errors: usize,
    pub total_seq_errors: usize,
    pub total_timeouts: usize,
    pub total_overflows: usize,
}

impl TsnCqfFrameReassemblyEngine {
    pub fn new(
        cycle_duration_ns: u64,
        max_reassembly_timeout_ns: u64,
        max_buffer_bytes_per_frame: usize,
    ) -> Self {
        Self {
            cycle_duration_ns: cycle_duration_ns.max(10_000),
            max_reassembly_timeout_ns: max_reassembly_timeout_ns.max(1_000),
            max_buffer_bytes_per_frame: max_buffer_bytes_per_frame.max(1500),
            buffers: Vec::new(),
            total_fragments_ingested: 0,
            total_frames_reassembled: 0,
            total_crc_errors: 0,
            total_seq_errors: 0,
            total_timeouts: 0,
            total_overflows: 0,
        }
    }

    /// Ingests a frame fragment (mPacket).
    pub fn ingest_fragment(&mut self, fragment: TsnFragment) -> FrameReassemblyVerdict {
        self.total_fragments_ingested += 1;

        if !fragment.crc_valid {
            self.total_crc_errors += 1;
            // Discard active buffer if corrupted fragment belongs to it
            self.buffers.retain(|b| {
                !(b.stream_id == fragment.stream_id && b.frame_id == fragment.frame_id)
            });
            return FrameReassemblyVerdict::CrcErrorDropped {
                stream_id: fragment.stream_id,
                frame_id: fragment.frame_id,
                fragment_seq: fragment.fragment_seq,
            };
        }

        let cycle_dur = self.cycle_duration_ns;
        let target_cycle = (fragment.timestamp_ns / cycle_dur) + 1;

        let buf_idx = self
            .buffers
            .iter()
            .position(|b| b.stream_id == fragment.stream_id && b.frame_id == fragment.frame_id);

        match buf_idx {
            None => {
                if fragment.fragment_seq != 0 {
                    self.total_seq_errors += 1;
                    return FrameReassemblyVerdict::SequenceMismatchDropped {
                        stream_id: fragment.stream_id,
                        frame_id: fragment.frame_id,
                        expected_seq: 0,
                        received_seq: fragment.fragment_seq,
                    };
                }

                if fragment.payload_bytes > self.max_buffer_bytes_per_frame {
                    self.total_overflows += 1;
                    return FrameReassemblyVerdict::BufferOverflowDropped {
                        stream_id: fragment.stream_id,
                        frame_id: fragment.frame_id,
                        attempted_bytes: fragment.payload_bytes,
                        max_capacity: self.max_buffer_bytes_per_frame,
                    };
                }

                if fragment.is_last {
                    // Single unfragmented frame
                    self.total_frames_reassembled += 1;
                    FrameReassemblyVerdict::FrameReassembledAndScheduled {
                        stream_id: fragment.stream_id,
                        frame_id: fragment.frame_id,
                        total_bytes: fragment.payload_bytes,
                        target_cycle,
                    }
                } else {
                    self.buffers.push(ReassemblyBuffer {
                        stream_id: fragment.stream_id,
                        frame_id: fragment.frame_id,
                        next_expected_seq: 1,
                        accumulated_bytes: fragment.payload_bytes,
                        started_at_ns: fragment.timestamp_ns,
                        target_cycle,
                    });

                    FrameReassemblyVerdict::FragmentBuffered {
                        stream_id: fragment.stream_id,
                        frame_id: fragment.frame_id,
                        fragment_seq: 0,
                        accumulated_bytes: fragment.payload_bytes,
                    }
                }
            }
            Some(idx) => {
                let buf = &mut self.buffers[idx];
                if fragment.fragment_seq != buf.next_expected_seq {
                    self.total_seq_errors += 1;
                    let exp = buf.next_expected_seq;
                    self.buffers.remove(idx);
                    return FrameReassemblyVerdict::SequenceMismatchDropped {
                        stream_id: fragment.stream_id,
                        frame_id: fragment.frame_id,
                        expected_seq: exp,
                        received_seq: fragment.fragment_seq,
                    };
                }

                let new_total = buf.accumulated_bytes + fragment.payload_bytes;
                if new_total > self.max_buffer_bytes_per_frame {
                    self.total_overflows += 1;
                    self.buffers.remove(idx);
                    return FrameReassemblyVerdict::BufferOverflowDropped {
                        stream_id: fragment.stream_id,
                        frame_id: fragment.frame_id,
                        attempted_bytes: new_total,
                        max_capacity: self.max_buffer_bytes_per_frame,
                    };
                }

                buf.accumulated_bytes = new_total;
                buf.next_expected_seq += 1;

                if fragment.is_last {
                    let total_bytes = buf.accumulated_bytes;
                    let sched_cycle = buf.target_cycle;
                    self.buffers.remove(idx);
                    self.total_frames_reassembled += 1;
                    FrameReassemblyVerdict::FrameReassembledAndScheduled {
                        stream_id: fragment.stream_id,
                        frame_id: fragment.frame_id,
                        total_bytes,
                        target_cycle: sched_cycle,
                    }
                } else {
                    let seq = fragment.fragment_seq;
                    let acc = buf.accumulated_bytes;
                    FrameReassemblyVerdict::FragmentBuffered {
                        stream_id: fragment.stream_id,
                        frame_id: fragment.frame_id,
                        fragment_seq: seq,
                        accumulated_bytes: acc,
                    }
                }
            }
        }
    }

    /// Sweeps expired reassembly buffers that have exceeded the timeout threshold.
    pub fn sweep_timeouts(&mut self, current_time_ns: u64) -> Vec<FrameReassemblyVerdict> {
        let mut verdicts = Vec::new();
        let timeout_thresh = self.max_reassembly_timeout_ns;

        let mut remaining = Vec::new();
        for b in self.buffers.drain(..) {
            if current_time_ns.saturating_sub(b.started_at_ns) > timeout_thresh {
                self.total_timeouts += 1;
                verdicts.push(FrameReassemblyVerdict::TimeoutFlushed {
                    stream_id: b.stream_id,
                    frame_id: b.frame_id,
                    dropped_bytes: b.accumulated_bytes,
                });
            } else {
                remaining.push(b);
            }
        }
        self.buffers = remaining;
        verdicts
    }

    /// Resets all buffers and statistics.
    pub fn reset(&mut self) {
        self.buffers.clear();
        self.total_fragments_ingested = 0;
        self.total_frames_reassembled = 0;
        self.total_crc_errors = 0;
        self.total_seq_errors = 0;
        self.total_timeouts = 0;
        self.total_overflows = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reassembly_success() {
        let mut engine = TsnCqfFrameReassemblyEngine::new(100_000, 50_000, 2000);

        let f0 = TsnFragment {
            stream_id: 1,
            frame_id: 100,
            fragment_seq: 0,
            is_last: false,
            payload_bytes: 500,
            timestamp_ns: 10_000,
            crc_valid: true,
        };
        let v0 = engine.ingest_fragment(f0);
        assert!(matches!(
            v0,
            FrameReassemblyVerdict::FragmentBuffered {
                fragment_seq: 0,
                accumulated_bytes: 500,
                ..
            }
        ));

        let f1 = TsnFragment {
            stream_id: 1,
            frame_id: 100,
            fragment_seq: 1,
            is_last: true,
            payload_bytes: 300,
            timestamp_ns: 15_000,
            crc_valid: true,
        };
        let v1 = engine.ingest_fragment(f1);
        assert!(matches!(
            v1,
            FrameReassemblyVerdict::FrameReassembledAndScheduled {
                total_bytes: 800,
                target_cycle: 1,
                ..
            }
        ));
        assert_eq!(engine.total_frames_reassembled, 1);
    }
}

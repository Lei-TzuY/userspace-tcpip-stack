// src/tsn_cqf_burst_absorb.rs
//
// IEEE 802.1Qch Cyclic Queuing and Forwarding (CQF) Cyclic Burst Absorption &
// Leaky Bucket Shaper Engine.
//
// Regulates bursty TSN streams at cycle boundaries by combining token bucket
// rate limiting with an elastic burst absorption buffer. Ingested frames that
// exceed immediate cycle bandwidth are smoothed and scheduled into subsequent
// CQF cycles rather than being dropped, preventing buffer pool exhaustion while
// maintaining deterministic bounded latency.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstStreamConfig {
    pub stream_id: u32,
    pub committed_rate_bps: u64,
    pub committed_burst_size_bytes: usize,
    pub peak_burst_size_bytes: usize,
    pub current_tokens_bytes: usize,
    pub burst_buffer_capacity_bytes: usize,
    pub currently_buffered_bytes: usize,
    pub last_token_update_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BurstAbsorbVerdict {
    ConformingIngress {
        stream_id: u32,
        frame_bytes: usize,
        target_cycle: u64,
        queue_depth_bytes: usize,
    },
    BurstAbsorbedBuffered {
        stream_id: u32,
        frame_bytes: usize,
        scheduled_cycle: u64,
        buffer_occupancy_bytes: usize,
    },
    NonConformingBurstDrop {
        stream_id: u32,
        frame_bytes: usize,
        reason: &'static str,
    },
}

#[derive(Debug, Clone)]
pub struct TsnCqfBurstAbsorbEngine {
    pub cycle_duration_ns: u64,
    pub max_cycle_queue_capacity_bytes: usize,
    pub current_cycle_index: u64,
    pub cycle_queue_odd_bytes: usize,
    pub cycle_queue_even_bytes: usize,
    pub streams: Vec<BurstStreamConfig>,
    pub total_conforming_frames: u64,
    pub total_absorbed_frames: u64,
    pub total_dropped_frames: u64,
    pub total_drained_frames: u64,
}

impl TsnCqfBurstAbsorbEngine {
    pub fn new(cycle_duration_ns: u64, max_cycle_queue_capacity_bytes: usize) -> Self {
        Self {
            cycle_duration_ns: if cycle_duration_ns == 0 {
                100_000
            } else {
                cycle_duration_ns
            },
            max_cycle_queue_capacity_bytes,
            current_cycle_index: 0,
            cycle_queue_odd_bytes: 0,
            cycle_queue_even_bytes: 0,
            streams: Vec::new(),
            total_conforming_frames: 0,
            total_absorbed_frames: 0,
            total_dropped_frames: 0,
            total_drained_frames: 0,
        }
    }

    pub fn register_stream(
        &mut self,
        stream_id: u32,
        committed_rate_bps: u64,
        committed_burst_size_bytes: usize,
        peak_burst_size_bytes: usize,
        burst_buffer_capacity_bytes: usize,
    ) {
        if let Some(existing) = self.streams.iter_mut().find(|s| s.stream_id == stream_id) {
            existing.committed_rate_bps = committed_rate_bps;
            existing.committed_burst_size_bytes = committed_burst_size_bytes;
            existing.peak_burst_size_bytes = peak_burst_size_bytes;
            existing.current_tokens_bytes = committed_burst_size_bytes;
            existing.burst_buffer_capacity_bytes = burst_buffer_capacity_bytes;
            existing.currently_buffered_bytes = 0;
            existing.last_token_update_ns = 0;
        } else {
            self.streams.push(BurstStreamConfig {
                stream_id,
                committed_rate_bps,
                committed_burst_size_bytes,
                peak_burst_size_bytes,
                current_tokens_bytes: committed_burst_size_bytes,
                burst_buffer_capacity_bytes,
                currently_buffered_bytes: 0,
                last_token_update_ns: 0,
            });
        }
    }

    pub fn refill_tokens(&mut self, stream_id: u32, current_time_ns: u64) {
        if let Some(stream) = self.streams.iter_mut().find(|s| s.stream_id == stream_id) {
            if current_time_ns > stream.last_token_update_ns {
                let elapsed_ns = current_time_ns - stream.last_token_update_ns;
                let added_bytes = (elapsed_ns as u128 * stream.committed_rate_bps as u128
                    / 8_000_000_000) as usize;
                stream.current_tokens_bytes =
                    (stream.current_tokens_bytes + added_bytes).min(stream.peak_burst_size_bytes);
                stream.last_token_update_ns = current_time_ns;
            }
        }
    }

    pub fn ingest_frame(
        &mut self,
        stream_id: u32,
        frame_bytes: usize,
        arrival_time_ns: u64,
    ) -> BurstAbsorbVerdict {
        self.refill_tokens(stream_id, arrival_time_ns);

        let stream = match self.streams.iter_mut().find(|s| s.stream_id == stream_id) {
            Some(s) => s,
            None => {
                self.total_dropped_frames += 1;
                return BurstAbsorbVerdict::NonConformingBurstDrop {
                    stream_id,
                    frame_bytes,
                    reason: "Unregistered TSN stream",
                };
            }
        };

        let current_cycle = arrival_time_ns / self.cycle_duration_ns;
        self.current_cycle_index = current_cycle;
        let target_cycle = current_cycle + 1; // CQF: ingest in cycle N, transmit in cycle N+1

        // Check if stream token bucket has sufficient tokens for immediate cycle enqueue
        if stream.current_tokens_bytes >= frame_bytes {
            let active_queue_bytes = if target_cycle % 2 == 0 {
                &mut self.cycle_queue_even_bytes
            } else {
                &mut self.cycle_queue_odd_bytes
            };

            if *active_queue_bytes + frame_bytes <= self.max_cycle_queue_capacity_bytes {
                stream.current_tokens_bytes -= frame_bytes;
                *active_queue_bytes += frame_bytes;
                self.total_conforming_frames += 1;
                return BurstAbsorbVerdict::ConformingIngress {
                    stream_id,
                    frame_bytes,
                    target_cycle,
                    queue_depth_bytes: *active_queue_bytes,
                };
            }
        }

        // Exceeds immediate tokens or cycle queue capacity: attempt burst absorption buffering
        if stream.currently_buffered_bytes + frame_bytes <= stream.burst_buffer_capacity_bytes {
            stream.currently_buffered_bytes += frame_bytes;
            self.total_absorbed_frames += 1;
            let scheduled_cycle = target_cycle + 1; // Delayed to cycle N+2
            BurstAbsorbVerdict::BurstAbsorbedBuffered {
                stream_id,
                frame_bytes,
                scheduled_cycle,
                buffer_occupancy_bytes: stream.currently_buffered_bytes,
            }
        } else {
            self.total_dropped_frames += 1;
            BurstAbsorbVerdict::NonConformingBurstDrop {
                stream_id,
                frame_bytes,
                reason: "Burst absorption buffer overflow",
            }
        }
    }

    pub fn tick_cycle_drain(&mut self, next_cycle: u64) -> usize {
        self.current_cycle_index = next_cycle;
        // In CQF, the cycle being transmitted is emptied
        let drained = if next_cycle % 2 == 0 {
            let d = self.cycle_queue_even_bytes;
            self.cycle_queue_even_bytes = 0;
            d
        } else {
            let d = self.cycle_queue_odd_bytes;
            self.cycle_queue_odd_bytes = 0;
            d
        };

        // Drain buffered burst frames into next transmission queue if capacity permits
        for stream in &mut self.streams {
            if stream.currently_buffered_bytes > 0 {
                let to_drain = stream
                    .currently_buffered_bytes
                    .min(stream.committed_burst_size_bytes);
                let target_queue = if (next_cycle + 1) % 2 == 0 {
                    &mut self.cycle_queue_even_bytes
                } else {
                    &mut self.cycle_queue_odd_bytes
                };

                if *target_queue + to_drain <= self.max_cycle_queue_capacity_bytes {
                    *target_queue += to_drain;
                    stream.currently_buffered_bytes -= to_drain;
                    self.total_drained_frames += 1;
                }
            }
        }

        drained
    }

    pub fn reset(&mut self) {
        self.current_cycle_index = 0;
        self.cycle_queue_odd_bytes = 0;
        self.cycle_queue_even_bytes = 0;
        self.total_conforming_frames = 0;
        self.total_absorbed_frames = 0;
        self.total_dropped_frames = 0;
        self.total_drained_frames = 0;
        for stream in &mut self.streams {
            stream.current_tokens_bytes = stream.committed_burst_size_bytes;
            stream.currently_buffered_bytes = 0;
            stream.last_token_update_ns = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cqf_burst_absorb_lifecycle() {
        let mut engine = TsnCqfBurstAbsorbEngine::new(100_000, 10_000);
        engine.register_stream(1, 80_000_000, 2000, 4000, 3000);

        // Ingest conforming frame within committed burst size
        let v1 = engine.ingest_frame(1, 1500, 10_000);
        assert!(matches!(
            v1,
            BurstAbsorbVerdict::ConformingIngress {
                stream_id: 1,
                frame_bytes: 1500,
                target_cycle: 1,
                ..
            }
        ));

        // Ingest frame exceeding remaining tokens -> Absorbed into burst buffer
        let v2 = engine.ingest_frame(1, 1000, 15_000);
        assert!(matches!(
            v2,
            BurstAbsorbVerdict::BurstAbsorbedBuffered {
                stream_id: 1,
                frame_bytes: 1000,
                ..
            }
        ));

        // Ingest frame exceeding buffer capacity -> Drop
        let v3 = engine.ingest_frame(1, 3500, 20_000);
        assert!(matches!(
            v3,
            BurstAbsorbVerdict::NonConformingBurstDrop {
                stream_id: 1,
                reason: "Burst absorption buffer overflow",
                ..
            }
        ));

        // Cycle drain
        let drained = engine.tick_cycle_drain(1);
        assert!(drained > 0 || engine.total_drained_frames > 0);
    }
}

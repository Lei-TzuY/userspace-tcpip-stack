// =============================================================================
// 3GPP TS 29.281 / TS 23.501 5G GTP-U Path RTT-Adaptive Jitter Buffer Engine
// =============================================================================
//
// In multi-path 5G transport networks, packets experience dynamic delay jitter.
// The RTT-Adaptive Jitter Buffer adjusts packet holding/reordering timeouts based
// on real-time transport latency metrics (SRTT + 4 * RTTVAR) to balance
// in-order delivery against playout latency.
//
// Features:
//   1. Dynamic Hold Delay Computation: TargetDelay = max(min_hold, srtt / 2 + 4 * rttvar).
//   2. Out-of-Order Packet Queuing with Monotonic Sequence Tracking.
//   3. In-Order Immediate Release & Jitter-Buffer Timeout Flush.
//   4. Packet Loss Gap Skipping when hold time expires.
//
// Pure safe Rust, zero external crates.

/// Buffered GTP-U packet representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedGtpuPacket {
    pub seq_num: u32,
    pub payload: Vec<u8>,
    pub arrival_time_us: u64,
}

/// Jitter buffer processing action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitterBufferAction {
    /// Packet released immediately in sequence.
    ReleaseInOrder(Vec<BufferedGtpuPacket>),
    /// Packet queued in jitter buffer waiting for missing predecessor or timeout.
    Queued {
        current_buffered: usize,
        expected_seq: u32,
    },
    /// Duplicate or obsolete sequence number dropped.
    DropDuplicate,
}

/// 5G GTP-U Path RTT-Adaptive Jitter Buffer Engine.
pub struct GtpuJitterBufEngine {
    pub teid: u32,
    pub expected_seq: u32,
    pub min_hold_us: u64,
    pub max_hold_us: u64,
    pub srtt_us: u64,
    pub rttvar_us: u64,
    pub buffer: Vec<BufferedGtpuPacket>,
    pub total_received: u64,
    pub total_released: u64,
    pub total_duplicates: u64,
    pub total_timed_out: u64,
}

impl GtpuJitterBufEngine {
    pub fn new(teid: u32, initial_seq: u32, min_hold_us: u64, max_hold_us: u64) -> Self {
        Self {
            teid,
            expected_seq: initial_seq,
            min_hold_us,
            max_hold_us,
            srtt_us: 10_000,
            rttvar_us: 2_000,
            buffer: Vec::new(),
            total_received: 0,
            total_released: 0,
            total_duplicates: 0,
            total_timed_out: 0,
        }
    }

    /// Update RTT estimates from active GTP-U echo probes.
    pub fn update_rtt(&mut self, srtt_us: u64, rttvar_us: u64) {
        self.srtt_us = srtt_us;
        self.rttvar_us = rttvar_us;
    }

    /// Calculate dynamic hold timeout.
    pub fn target_hold_delay_us(&self) -> u64 {
        let dynamic = (self.srtt_us / 2).saturating_add(self.rttvar_us.saturating_mul(4));
        dynamic.clamp(self.min_hold_us, self.max_hold_us)
    }

    /// Ingress packet handler.
    pub fn push_packet(
        &mut self,
        seq_num: u32,
        payload: Vec<u8>,
        current_time_us: u64,
    ) -> JitterBufferAction {
        self.total_received += 1;

        if seq_num < self.expected_seq {
            self.total_duplicates += 1;
            return JitterBufferAction::DropDuplicate;
        }

        if seq_num == self.expected_seq {
            let mut released = vec![BufferedGtpuPacket {
                seq_num,
                payload,
                arrival_time_us: current_time_us,
            }];
            self.expected_seq = self.expected_seq.wrapping_add(1);

            // Drain contiguous buffered packets
            while let Some(pos) = self
                .buffer
                .iter()
                .position(|p| p.seq_num == self.expected_seq)
            {
                let pkt = self.buffer.remove(pos);
                self.expected_seq = self.expected_seq.wrapping_add(1);
                released.push(pkt);
            }

            self.total_released += released.len() as u64;
            JitterBufferAction::ReleaseInOrder(released)
        } else {
            // Out of order: buffer packet
            if !self.buffer.iter().any(|p| p.seq_num == seq_num) {
                self.buffer.push(BufferedGtpuPacket {
                    seq_num,
                    payload,
                    arrival_time_us: current_time_us,
                });
                self.buffer.sort_by_key(|p| p.seq_num);
            }
            JitterBufferAction::Queued {
                current_buffered: self.buffer.len(),
                expected_seq: self.expected_seq,
            }
        }
    }

    /// Periodic flush for packets that have exceeded the adaptive hold delay.
    pub fn flush_expired(&mut self, current_time_us: u64) -> Vec<BufferedGtpuPacket> {
        let hold_delay = self.target_hold_delay_us();
        let mut released = Vec::new();

        if let Some(first_expired) = self
            .buffer
            .iter()
            .position(|p| current_time_us.saturating_sub(p.arrival_time_us) >= hold_delay)
        {
            let pkt = self.buffer.remove(first_expired);
            self.expected_seq = pkt.seq_num.wrapping_add(1);
            self.total_timed_out += 1;
            released.push(pkt);

            // Drain any now-contiguous subsequent packets
            while let Some(pos) = self
                .buffer
                .iter()
                .position(|p| p.seq_num == self.expected_seq)
            {
                let p = self.buffer.remove(pos);
                self.expected_seq = self.expected_seq.wrapping_add(1);
                released.push(p);
            }
        }

        self.total_released += released.len() as u64;
        released
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_adaptive_jitter_buffer_lifecycle() {
        let mut jbuf = GtpuJitterBufEngine::new(0x5001, 1, 5_000, 50_000);
        jbuf.update_rtt(20_000, 3_000); // Target delay: 20000/2 + 4*3000 = 22000 µs (22 ms)

        assert_eq!(jbuf.target_hold_delay_us(), 22_000);

        // 1. Packet 1 arrives in order
        let a1 = jbuf.push_packet(1, vec![1, 1], 1000);
        if let JitterBufferAction::ReleaseInOrder(pkts) = a1 {
            assert_eq!(pkts.len(), 1);
            assert_eq!(pkts[0].seq_num, 1);
        } else {
            panic!("Expected in-order release");
        }

        // 2. Packet 3 arrives out-of-order (Packet 2 is delayed/missing) -> Queued
        let a3 = jbuf.push_packet(3, vec![3, 3], 1010);
        assert_eq!(
            a3,
            JitterBufferAction::Queued {
                current_buffered: 1,
                expected_seq: 2,
            }
        );

        // 3. Packet 2 arrives at t=1020 -> Contiguous drain of [2, 3]
        let a2 = jbuf.push_packet(2, vec![2, 2], 1020);
        if let JitterBufferAction::ReleaseInOrder(pkts) = a2 {
            assert_eq!(pkts.len(), 2);
            assert_eq!(pkts[0].seq_num, 2);
            assert_eq!(pkts[1].seq_num, 3);
        } else {
            panic!("Expected in-order drain");
        }
        assert_eq!(jbuf.expected_seq, 4);

        // 4. Packet 5 arrives at t=2000 (Packet 4 lost) -> Queued
        let a5 = jbuf.push_packet(5, vec![5, 5], 2000);
        assert_eq!(
            a5,
            JitterBufferAction::Queued {
                current_buffered: 1,
                expected_seq: 4,
            }
        );

        // 5. At t=25000 (elapsed 23000 µs >= 22000 µs target hold delay) -> Timeout flush skips packet 4
        let flushed = jbuf.flush_expired(25_000);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].seq_num, 5);
        assert_eq!(jbuf.expected_seq, 6);
    }
}

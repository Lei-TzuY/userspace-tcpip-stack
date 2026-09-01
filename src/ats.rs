//! IEEE 802.1Qcr Asynchronous Traffic Shaping (ATS / TSN - Urgency-Based Scheduler).
//!
//! Implements Asynchronous Traffic Shaping (ATS) with per-flow Leaky Bucket token tracking
//! and Urgency-Based Scheduler (UBS) for clock-independent deterministic latency bounds.

use std::collections::{HashMap, VecDeque};

/// TSN ATS Ingress Frame Entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtsFrame {
    pub stream_id: u32,
    pub frame_length_bytes: usize,
    pub arrival_time_us: u64,
    pub eligibility_time_us: u64,
    pub payload: Vec<u8>,
}

/// Per-Stream ATS Token/Leaky Bucket Shaper
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtsStreamShaper {
    pub stream_id: u32,
    pub committed_info_rate_bps: u64,    // CIR in bits per second
    pub committed_burst_size_bytes: u32, // CBS in bytes
    pub last_eligibility_time_us: u64,   // Eligibility Time (ET) of previous frame
}

impl AtsStreamShaper {
    pub fn new(stream_id: u32, cir_bps: u64, cbs_bytes: u32) -> Self {
        AtsStreamShaper {
            stream_id,
            committed_info_rate_bps: cir_bps,
            committed_burst_size_bytes: cbs_bytes,
            last_eligibility_time_us: 0,
        }
    }

    /// Computes the Eligibility Time (ET) for a newly arrived frame
    /// ET = max(ET_prev, arrival_time) + frame_transmission_time
    pub fn compute_eligibility_time(
        &mut self,
        frame_length_bytes: usize,
        arrival_time_us: u64,
    ) -> u64 {
        if self.committed_info_rate_bps == 0 {
            return arrival_time_us;
        }

        // Convert serialization time to whole microseconds with ceiling division. Rounding down
        // would make frames faster than one microsecond consume zero scheduler time and allow an
        // unbounded number of frames to receive the same eligibility timestamp.
        let frame_bits_us = (frame_length_bytes as u128) * 8 * 1_000_000;
        let cir = self.committed_info_rate_bps as u128;
        let tx_time_us = frame_bits_us.div_ceil(cir).min(u64::MAX as u128) as u64;

        let base = arrival_time_us.max(self.last_eligibility_time_us);
        let et = base.saturating_add(tx_time_us);

        self.last_eligibility_time_us = et;
        et
    }
}

/// Urgency-Based Scheduler (UBS) Engine
#[derive(Debug, Clone, Default)]
pub struct UrgencyBasedScheduler {
    pub shapers: HashMap<u32, AtsStreamShaper>,
    pub scheduled_queue: VecDeque<AtsFrame>,
    pub transmitted_frames_count: u64,
}

impl UrgencyBasedScheduler {
    pub fn new() -> Self {
        UrgencyBasedScheduler {
            shapers: HashMap::new(),
            scheduled_queue: VecDeque::new(),
            transmitted_frames_count: 0,
        }
    }

    /// Registers a stream shaper
    pub fn register_shaper(&mut self, shaper: AtsStreamShaper) {
        self.shapers.insert(shaper.stream_id, shaper);
    }

    /// Enqueues an ingress frame, assigning its ATS eligibility time
    pub fn enqueue_frame(
        &mut self,
        stream_id: u32,
        arrival_time_us: u64,
        payload: Vec<u8>,
    ) -> Result<u64, &'static str> {
        let frame_len = payload.len();
        let shaper = self
            .shapers
            .get_mut(&stream_id)
            .ok_or("Stream shaper not found")?;
        let et = shaper.compute_eligibility_time(frame_len, arrival_time_us);

        let frame = AtsFrame {
            stream_id,
            frame_length_bytes: frame_len,
            arrival_time_us,
            eligibility_time_us: et,
            payload,
        };

        self.scheduled_queue.push_back(frame);
        Ok(et)
    }

    /// Selects and transmits the next eligible frame whose Eligibility Time <= current_time_us
    pub fn dequeue_eligible_frame(&mut self, current_time_us: u64) -> Option<AtsFrame> {
        if let Some(idx) = self
            .scheduled_queue
            .iter()
            .position(|f| f.eligibility_time_us <= current_time_us)
        {
            let frame = self.scheduled_queue.remove(idx)?;
            self.transmitted_frames_count += 1;
            Some(frame)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ats_eligibility_time_calculation() {
        let mut shaper = AtsStreamShaper::new(1, 8_000_000, 1500); // 8 Mbps (1000 bytes/ms = 1 byte/µs)

        // 1000 bytes at 8 Mbps takes 1000µs
        let et1 = shaper.compute_eligibility_time(1000, 100);
        assert_eq!(et1, 100 + 1000); // 1100µs

        // Next frame arrives at 500µs (before et1) -> ET = 1100 + 1000 = 2100µs
        let et2 = shaper.compute_eligibility_time(1000, 500);
        assert_eq!(et2, 2100);
    }

    #[test]
    fn submicrosecond_frames_still_consume_scheduler_time() {
        let mut shaper = AtsStreamShaper::new(1, 10_000_000_000, 1500);

        // A 64-byte frame takes 0.0512µs at 10 Gbps. Whole-microsecond scheduling must round
        // upward rather than treating the frame as free.
        assert_eq!(shaper.compute_eligibility_time(64, 100), 101);
        assert_eq!(shaper.compute_eligibility_time(64, 100), 102);
    }

    #[test]
    fn eligibility_time_saturates_instead_of_overflowing() {
        let mut shaper = AtsStreamShaper::new(1, 1, 1500);
        assert_eq!(shaper.compute_eligibility_time(1, u64::MAX - 1), u64::MAX);
        assert_eq!(shaper.last_eligibility_time_us, u64::MAX);
    }

    #[test]
    fn test_urgency_based_scheduler_queue_and_dequeue() {
        let mut ubs = UrgencyBasedScheduler::new();
        ubs.register_shaper(AtsStreamShaper::new(10, 8_000_000, 1500));

        let payload = vec![0xAA; 500]; // 500 bytes = 500µs tx time
        let et = ubs.enqueue_frame(10, 1000, payload).unwrap();
        assert_eq!(et, 1500);

        // At t=1200µs: not eligible yet
        assert!(ubs.dequeue_eligible_frame(1200).is_none());

        // At t=1600µs: eligible and dequeued
        let frame = ubs.dequeue_eligible_frame(1600).unwrap();
        assert_eq!(frame.stream_id, 10);
        assert_eq!(ubs.transmitted_frames_count, 1);
    }
}

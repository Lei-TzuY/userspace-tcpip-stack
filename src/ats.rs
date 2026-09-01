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
    pub bucket_empty_time_us: i128,      // Most recent instant at which the token bucket was empty
}

impl AtsStreamShaper {
    pub fn new(stream_id: u32, cir_bps: u64, cbs_bytes: u32) -> Self {
        let empty_to_full_duration_us = Self::duration_us(cbs_bytes as usize, cir_bps);

        AtsStreamShaper {
            stream_id,
            committed_info_rate_bps: cir_bps,
            committed_burst_size_bytes: cbs_bytes,
            last_eligibility_time_us: 0,
            // IEEE 802.1Qcr initializes BucketEmptyTime far enough in the past that the bucket
            // starts full. Using signed scheduler time lets an arrival at t=0 consume that burst.
            bucket_empty_time_us: -empty_to_full_duration_us,
        }
    }

    fn duration_us(bytes: usize, rate_bps: u64) -> i128 {
        if rate_bps == 0 {
            return 0;
        }

        let bits_us = (bytes as u128).saturating_mul(8).saturating_mul(1_000_000);
        bits_us.div_ceil(rate_bps as u128).min(i128::MAX as u128) as i128
    }

    /// Computes the Eligibility Time (ET) for a newly arrived frame.
    ///
    /// This follows the simplified IEEE 802.1Qcr ProcessFrame model for a one-to-one stream,
    /// scheduler, and scheduler-group mapping. CBS controls how far BucketEmptyTime may trail the
    /// current time, allowing a full committed burst to be immediately eligible while CIR controls
    /// the refill rate after that burst is consumed.
    pub fn compute_eligibility_time(
        &mut self,
        frame_length_bytes: usize,
        arrival_time_us: u64,
    ) -> u64 {
        if self.committed_info_rate_bps == 0 {
            let et = arrival_time_us.max(self.last_eligibility_time_us);
            self.last_eligibility_time_us = et;
            return et;
        }

        let length_recovery_duration_us =
            Self::duration_us(frame_length_bytes, self.committed_info_rate_bps);
        let empty_to_full_duration_us = Self::duration_us(
            self.committed_burst_size_bytes as usize,
            self.committed_info_rate_bps,
        );

        let scheduler_eligibility_time_us = self
            .bucket_empty_time_us
            .saturating_add(length_recovery_duration_us);
        let bucket_full_time_us = self
            .bucket_empty_time_us
            .saturating_add(empty_to_full_duration_us);
        let eligibility_time_us = (arrival_time_us as i128)
            .max(self.last_eligibility_time_us as i128)
            .max(scheduler_eligibility_time_us);

        self.bucket_empty_time_us = if eligibility_time_us < bucket_full_time_us {
            scheduler_eligibility_time_us
        } else {
            scheduler_eligibility_time_us
                .saturating_add(eligibility_time_us.saturating_sub(bucket_full_time_us))
        };

        let et = eligibility_time_us.min(u64::MAX as i128) as u64;
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

    /// Selects and transmits the most urgent eligible frame whose Eligibility Time <= current_time_us
    pub fn dequeue_eligible_frame(&mut self, current_time_us: u64) -> Option<AtsFrame> {
        let idx = self
            .scheduled_queue
            .iter()
            .enumerate()
            .filter(|(_, frame)| frame.eligibility_time_us <= current_time_us)
            .min_by_key(|(_, frame)| frame.eligibility_time_us)
            .map(|(idx, _)| idx)?;

        let frame = self.scheduled_queue.remove(idx)?;
        self.transmitted_frames_count += 1;
        Some(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_burst_is_immediately_eligible_then_rate_limits_excess() {
        let mut shaper = AtsStreamShaper::new(1, 8_000_000, 1500); // 1 byte/µs, 1500-byte burst

        assert_eq!(shaper.compute_eligibility_time(1000, 100), 100);
        assert_eq!(shaper.compute_eligibility_time(500, 100), 100);
        assert_eq!(shaper.compute_eligibility_time(1, 100), 101);
    }

    #[test]
    fn idle_time_refills_committed_burst_credit() {
        let mut shaper = AtsStreamShaper::new(1, 8_000_000, 1000); // 1 byte/µs

        assert_eq!(shaper.compute_eligibility_time(1000, 100), 100);
        assert_eq!(shaper.compute_eligibility_time(1000, 500), 1100);

        // Once enough idle time has passed to refill the bucket, another full CBS is eligible at
        // arrival rather than carrying the previous virtual finish time forever.
        assert_eq!(shaper.compute_eligibility_time(1000, 2500), 2500);
    }

    #[test]
    fn regressing_arrival_timestamps_do_not_regress_stream_eligibility() {
        let mut shaper = AtsStreamShaper::new(1, 8_000_000, 1500); // 1 byte/µs

        assert_eq!(shaper.compute_eligibility_time(500, 1000), 1000);
        assert_eq!(shaper.compute_eligibility_time(500, 0), 1000);
        assert_eq!(shaper.last_eligibility_time_us, 1000);
    }

    #[test]
    fn zero_rate_streams_preserve_eligibility_ordering() {
        let mut shaper = AtsStreamShaper::new(1, 0, 1500);

        assert_eq!(shaper.compute_eligibility_time(500, 1000), 1000);
        assert_eq!(shaper.compute_eligibility_time(500, 0), 1000);
        assert_eq!(shaper.last_eligibility_time_us, 1000);
    }

    #[test]
    fn submicrosecond_excess_frames_still_consume_scheduler_time() {
        let mut shaper = AtsStreamShaper::new(1, 10_000_000_000, 64);

        assert_eq!(shaper.compute_eligibility_time(64, 100), 100);
        assert_eq!(shaper.compute_eligibility_time(64, 100), 101);
        assert_eq!(shaper.compute_eligibility_time(64, 100), 102);
    }

    #[test]
    fn eligibility_time_saturates_instead_of_overflowing() {
        let mut shaper = AtsStreamShaper::new(1, 1, 1);
        shaper.bucket_empty_time_us = u64::MAX as i128 - 1;

        assert_eq!(shaper.compute_eligibility_time(1, u64::MAX - 1), u64::MAX);
        assert_eq!(shaper.last_eligibility_time_us, u64::MAX);
    }

    #[test]
    fn test_urgency_based_scheduler_queue_and_dequeue() {
        let mut ubs = UrgencyBasedScheduler::new();
        ubs.register_shaper(AtsStreamShaper::new(10, 8_000_000, 1500));

        let payload = vec![0xAA; 500];
        let et = ubs.enqueue_frame(10, 1000, payload).unwrap();
        assert_eq!(et, 1000);

        assert!(ubs.dequeue_eligible_frame(999).is_none());

        let frame = ubs.dequeue_eligible_frame(1000).unwrap();
        assert_eq!(frame.stream_id, 10);
        assert_eq!(ubs.transmitted_frames_count, 1);
    }

    #[test]
    fn dequeue_prefers_earliest_eligibility_time_when_multiple_are_ready() {
        let mut ubs = UrgencyBasedScheduler::new();
        ubs.register_shaper(AtsStreamShaper::new(1, 8_000_000, 0));
        ubs.register_shaper(AtsStreamShaper::new(2, 16_000_000, 0));

        // Enqueue the less urgent frame first so FIFO ordering would choose incorrectly once both
        // frames are eligible.
        assert_eq!(ubs.enqueue_frame(1, 0, vec![0x11; 1000]).unwrap(), 1000);
        assert_eq!(ubs.enqueue_frame(2, 0, vec![0x22; 400]).unwrap(), 200);

        let first = ubs.dequeue_eligible_frame(1000).unwrap();
        assert_eq!(first.stream_id, 2);
        assert_eq!(first.eligibility_time_us, 200);

        let second = ubs.dequeue_eligible_frame(1000).unwrap();
        assert_eq!(second.stream_id, 1);
        assert_eq!(second.eligibility_time_us, 1000);
    }
}

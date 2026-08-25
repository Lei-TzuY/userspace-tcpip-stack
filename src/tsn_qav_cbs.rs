//! IEEE 802.1Qav Credit-Based Shaper (CBS) Multi-Class Audio/Video Bridging (AVB) Engine.
//!
//! The Credit-Based Shaper (CBS) prevents real-time stream bursts from monopolizing
//! network egress bandwidth, protecting lower-priority best-effort traffic from starvation.
//!
//! Two Stream Reservation (SR) classes are standardized:
//! 1. **SR Class A**: Highest priority AVB stream class (target delay $\le 2\text{ ms}$ over 7 hops).
//! 2. **SR Class B**: Second priority AVB stream class (target delay $\le 10\text{ ms}$ over 7 hops).
//!
//! Algorithm:
//! * When frames are queued and port is transmitting: credit decreases with rate `sendSlope` ($= \text{idleSlope} - \text{portRate}$).
//! * When credit $< 0$ and no frame is transmitting: credit increases with rate `idleSlope`.
//! * Transmission is allowed only when $\text{credit} \ge 0$.
//! * Credit is bounded by `hiCredit` and `loCredit`.
//!
//! This module implements:
//! * Multi-class CBS state machine for Class A and Class B queues.
//! * Fractional integer credit arithmetic with nanosecond granularity.
//! * Frame admission, transmission, and credit tracking.

/// AVB Stream Reservation Class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SrClass {
    ClassA,
    ClassB,
}

/// Credit-Based Shaper Instance for a single Traffic Class queue.
#[derive(Debug, Clone)]
pub struct CreditBasedShaperQueue {
    pub sr_class: SrClass,
    /// Allocated bandwidth in bytes per second (idleSlope).
    pub idle_slope_bps: i64,
    /// Total egress port speed in bytes per second (portRate).
    pub port_rate_bps: i64,
    /// sendSlope = idleSlope - portRate (negative value).
    pub send_slope_bps: i64,
    /// Maximum positive credit cap (hiCredit).
    pub hi_credit: i64,
    /// Minimum negative credit floor (loCredit).
    pub lo_credit: i64,
    /// Current accumulated credit (in bytes or scaled credit units).
    pub current_credit: i64,
    /// Last simulation timestamp in nanoseconds.
    pub last_update_ns: u64,
    /// Whether `last_update_ns` has been initialised. Timestamp zero is valid,
    /// so it cannot double as an uninitialised sentinel.
    time_initialized: bool,
    /// Number of queued frames.
    pub queued_frames: Vec<usize>, // Frame sizes in bytes
    pub is_transmitting: bool,
    pub total_transmitted_frames: u64,
    pub total_transmitted_bytes: u64,
}

impl CreditBasedShaperQueue {
    pub fn new(sr_class: SrClass, idle_slope_bps: i64, port_rate_bps: i64, max_frame_size: usize) -> Self {
        let send_slope_bps = idle_slope_bps - port_rate_bps;
        let hi_credit = (max_frame_size as i64 * idle_slope_bps) / port_rate_bps.max(1);
        let lo_credit = (max_frame_size as i64 * send_slope_bps) / port_rate_bps.max(1);

        CreditBasedShaperQueue {
            sr_class,
            idle_slope_bps,
            port_rate_bps,
            send_slope_bps,
            hi_credit,
            lo_credit,
            current_credit: 0,
            last_update_ns: 0,
            time_initialized: false,
            queued_frames: Vec::new(),
            is_transmitting: false,
            total_transmitted_frames: 0,
            total_transmitted_bytes: 0,
        }
    }

    /// Advances time and updates accumulated credit.
    pub fn advance_time(&mut self, now_ns: u64) {
        if !self.time_initialized {
            self.last_update_ns = now_ns;
            self.time_initialized = true;
            return;
        }

        let delta_ns = now_ns.saturating_sub(self.last_update_ns) as i64;
        if delta_ns <= 0 {
            return;
        }

        if self.is_transmitting {
            // Decrement credit with sendSlope
            let credit_delta = (delta_ns * self.send_slope_bps) / 1_000_000_000;
            self.current_credit = (self.current_credit + credit_delta).max(self.lo_credit);
        } else if !self.queued_frames.is_empty() || self.current_credit < 0 {
            // Replenish credit with idleSlope
            let credit_delta = (delta_ns * self.idle_slope_bps) / 1_000_000_000;
            self.current_credit = self.current_credit + credit_delta;
            if self.queued_frames.is_empty() && self.current_credit > 0 {
                // Credit resets to 0 when queue is empty and credit becomes positive
                self.current_credit = 0;
            } else {
                self.current_credit = self.current_credit.min(self.hi_credit);
            }
        } else if self.queued_frames.is_empty() && self.current_credit > 0 {
            self.current_credit = 0;
        }

        self.last_update_ns = now_ns;
    }

    /// Enqueues a frame.
    pub fn enqueue_frame(&mut self, frame_bytes: usize) {
        self.queued_frames.push(frame_bytes);
    }

    /// Attempts to transmit a frame if credit >= 0.
    pub fn try_transmit(&mut self, now_ns: u64) -> Option<usize> {
        self.advance_time(now_ns);

        if self.current_credit >= 0 && !self.queued_frames.is_empty() {
            let frame_bytes = self.queued_frames.remove(0);
            self.is_transmitting = true;
            self.total_transmitted_frames += 1;
            self.total_transmitted_bytes += frame_bytes as u64;
            Some(frame_bytes)
        } else {
            None
        }
    }

    /// Marks the completion of a frame transmission.
    pub fn complete_transmission(&mut self, now_ns: u64) {
        self.advance_time(now_ns);
        self.is_transmitting = false;
    }
}

/// Dual-Class IEEE 802.1Qav AVB CBS Bridge Port.
#[derive(Debug, Clone)]
pub struct TsnQavBridgePort {
    pub class_a: CreditBasedShaperQueue,
    pub class_b: CreditBasedShaperQueue,
}

impl TsnQavBridgePort {
    pub fn new(port_rate_bps: i64, class_a_bw_bps: i64, class_b_bw_bps: i64) -> Self {
        TsnQavBridgePort {
            class_a: CreditBasedShaperQueue::new(SrClass::ClassA, class_a_bw_bps, port_rate_bps, 1500),
            class_b: CreditBasedShaperQueue::new(SrClass::ClassB, class_b_bw_bps, port_rate_bps, 1500),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_qav_cbs_transmission_and_credit_depletion() {
        // Port: 100 MB/s (100,000,000 B/s), Class A reserved: 20 MB/s (20,000,000 B/s)
        let mut cbs = CreditBasedShaperQueue::new(SrClass::ClassA, 20_000_000, 100_000_000, 1500);

        // Initially credit = 0 -> can transmit frame 1
        cbs.enqueue_frame(1000);
        let tx1 = cbs.try_transmit(0);
        assert_eq!(tx1, Some(1000));
        assert!(cbs.is_transmitting);

        // Transmitting 1000 bytes at 100 MB/s takes 10 microseconds (10,000 ns)
        // sendSlope = 20M - 100M = -80M B/s
        // Credit delta = (10,000 * -80,000,000) / 1,000,000,000 = -800
        cbs.complete_transmission(10_000);
        assert!(!cbs.is_transmitting);
        assert_eq!(cbs.current_credit, -800);

        // Next frame queued: cannot transmit immediately because credit < 0
        cbs.enqueue_frame(1000);
        let tx2_blocked = cbs.try_transmit(10_000);
        assert_eq!(tx2_blocked, None);

        // Replenish credit at idleSlope = 20M B/s.
        // To recover 800 bytes requires 800 / 20M = 40 microseconds (40,000 ns)
        // Advance to t = 50,000 ns (10,000 + 40,000)
        let tx2_ready = cbs.try_transmit(50_000);
        assert_eq!(tx2_ready, Some(1000));
    }
}

// =============================================================================
// IEEE 802.1Qch CQF Dynamic Cycle Duration Scaling & Hitless Boundary Transition
// =============================================================================
//
// In deterministic TSN networks, the CQF cycle period T is usually fixed at
// commissioning time.  However, industrial control loops with varying scan
// rates or mixed-criticality streams benefit from runtime cycle scaling where
// the cycle period can be lengthened (lower scan rate, higher latency budget)
// or shortened (higher scan rate, tighter latency) without packet loss during
// the transition.
//
// This module implements:
//   1. **Admin / Oper dual-state cycle configuration** analogous to Qbv GCL
//      admin/oper swapping, ensuring a pending new cycle period only takes
//      effect at the natural cycle boundary.
//   2. **Hitless boundary transition** — frames already enqueued in the
//      current cycle drain completely before the new period activates.
//   3. **Scaling factor validation** — the new period must be an integer
//      multiple or divisor of the link-speed-dependent minimum cycle time
//      to maintain deterministic phase alignment across multi-hop paths.
//   4. **Transition event logging** for telemetry and diagnostics.
//
// All arithmetic is in nanoseconds (u64) to match TSN precision requirements.
// Pure safe Rust, zero external crates.

/// Minimum permissible cycle duration in nanoseconds (e.g. 125 µs for 1 Gbps).
pub const MIN_CYCLE_NS: u64 = 125_000;

/// Maximum permissible cycle duration in nanoseconds (e.g. 10 ms).
pub const MAX_CYCLE_NS: u64 = 10_000_000;

/// Result of a scale-change request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleScaleResult {
    /// The new period has been accepted and staged as the admin config.
    Accepted,
    /// The new period violates the integer-multiple/divisor constraint.
    InvalidAlignment,
    /// The new period is out of the [MIN, MAX] range.
    OutOfRange,
    /// A transition is already pending; reject until it completes.
    TransitionPending,
}

/// Record of a completed cycle-period transition.
#[derive(Debug, Clone)]
pub struct CycleTransitionEvent {
    /// Wall-clock nanosecond timestamp when the transition took effect.
    pub effective_at_ns: u64,
    /// Previous operational cycle period in nanoseconds.
    pub old_period_ns: u64,
    /// New operational cycle period in nanoseconds.
    pub new_period_ns: u64,
    /// The cycle index at which the swap occurred.
    pub swap_cycle_index: u64,
}

/// CQF Dynamic Cycle Duration Scaling Engine.
pub struct TsnCqfCycleScaleEngine {
    /// Currently active (operational) cycle period in nanoseconds.
    oper_period_ns: u64,
    /// Base cycle granularity — all valid periods must be integer multiples of this.
    base_granularity_ns: u64,
    /// Pending admin cycle period, if any.
    admin_period_ns: Option<u64>,
    /// Monotonic cycle counter.
    cycle_index: u64,
    /// Accumulated wall-clock time in the current cycle (nanoseconds).
    current_cycle_elapsed_ns: u64,
    /// Number of frames still draining from the previous cycle's transmit buffer.
    drain_pending_frames: u32,
    /// Log of completed transitions.
    transition_log: Vec<CycleTransitionEvent>,
    /// Cumulative wall-clock time (nanoseconds).
    wall_clock_ns: u64,
}

impl TsnCqfCycleScaleEngine {
    /// Create a new engine with an initial operational cycle period.
    ///
    /// `base_granularity_ns` is the smallest valid cycle period; all requested
    /// periods must be exact integer multiples of this value.
    pub fn new(initial_period_ns: u64, base_granularity_ns: u64) -> Self {
        let gran = if base_granularity_ns == 0 {
            MIN_CYCLE_NS
        } else {
            base_granularity_ns
        };
        let period = if initial_period_ns < gran {
            gran
        } else {
            initial_period_ns
        };
        Self {
            oper_period_ns: period,
            base_granularity_ns: gran,
            admin_period_ns: None,
            cycle_index: 0,
            current_cycle_elapsed_ns: 0,
            drain_pending_frames: 0,
            transition_log: Vec::new(),
            wall_clock_ns: 0,
        }
    }

    /// Return the current operational cycle period in nanoseconds.
    pub fn oper_period_ns(&self) -> u64 {
        self.oper_period_ns
    }

    /// Return the pending admin cycle period, if any.
    pub fn admin_period_ns(&self) -> Option<u64> {
        self.admin_period_ns
    }

    /// Return the current cycle index.
    pub fn cycle_index(&self) -> u64 {
        self.cycle_index
    }

    /// Return the base granularity in nanoseconds.
    pub fn base_granularity_ns(&self) -> u64 {
        self.base_granularity_ns
    }

    /// Return completed transition events.
    pub fn transition_log(&self) -> &[CycleTransitionEvent] {
        &self.transition_log
    }

    /// Request a new cycle period.  The new period is staged as the *admin*
    /// configuration and will only become *operational* at the next natural
    /// cycle boundary (when `advance_cycle` is called and drain is complete).
    pub fn request_scale(&mut self, new_period_ns: u64) -> CycleScaleResult {
        // Reject if a transition is already pending.
        if self.admin_period_ns.is_some() {
            return CycleScaleResult::TransitionPending;
        }
        // Range check.
        if new_period_ns < MIN_CYCLE_NS || new_period_ns > MAX_CYCLE_NS {
            return CycleScaleResult::OutOfRange;
        }
        // Integer-multiple-of-granularity check.
        if new_period_ns % self.base_granularity_ns != 0 {
            return CycleScaleResult::InvalidAlignment;
        }
        // Same as current — no-op but accept.
        if new_period_ns == self.oper_period_ns {
            return CycleScaleResult::Accepted;
        }
        self.admin_period_ns = Some(new_period_ns);
        CycleScaleResult::Accepted
    }

    /// Notify the engine that `n` frames have been enqueued in the current
    /// transmit cycle and will need to drain before a transition can occur.
    pub fn enqueue_frames(&mut self, n: u32) {
        self.drain_pending_frames = self.drain_pending_frames.saturating_add(n);
    }

    /// Notify the engine that `n` frames have been transmitted (drained) from
    /// the current cycle's buffer.
    pub fn drain_frames(&mut self, n: u32) {
        self.drain_pending_frames = self.drain_pending_frames.saturating_sub(n);
    }

    /// Return the number of frames still awaiting drain.
    pub fn drain_pending(&self) -> u32 {
        self.drain_pending_frames
    }

    /// Advance the wall clock by `delta_ns` nanoseconds.  If the accumulated
    /// time reaches or exceeds the current operational period, a cycle boundary
    /// is crossed.  At the boundary, if an admin config is pending **and** the
    /// drain buffer is empty, the admin→oper swap is executed hitlessly.
    ///
    /// Returns the number of cycle boundaries crossed.
    pub fn advance_time(&mut self, delta_ns: u64) -> u32 {
        self.wall_clock_ns = self.wall_clock_ns.saturating_add(delta_ns);
        self.current_cycle_elapsed_ns = self.current_cycle_elapsed_ns.saturating_add(delta_ns);

        let mut boundaries = 0u32;
        while self.current_cycle_elapsed_ns >= self.oper_period_ns {
            self.current_cycle_elapsed_ns -= self.oper_period_ns;
            self.cycle_index += 1;
            boundaries += 1;

            // Attempt admin→oper swap if drain is complete.
            if let Some(new_period) = self.admin_period_ns {
                if self.drain_pending_frames == 0 {
                    let event = CycleTransitionEvent {
                        effective_at_ns: self.wall_clock_ns,
                        old_period_ns: self.oper_period_ns,
                        new_period_ns: new_period,
                        swap_cycle_index: self.cycle_index,
                    };
                    self.transition_log.push(event);
                    self.oper_period_ns = new_period;
                    self.admin_period_ns = None;
                }
            }
        }
        boundaries
    }

    /// Convenience: immediately advance one full cycle (using the current oper
    /// period) and return the number of boundaries crossed (always 1 unless
    /// the new period is shorter than the old and residual time spills over).
    pub fn advance_cycle(&mut self) -> u32 {
        let remaining = self
            .oper_period_ns
            .saturating_sub(self.current_cycle_elapsed_ns);
        self.advance_time(remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_scale_and_transition() {
        let mut engine = TsnCqfCycleScaleEngine::new(500_000, MIN_CYCLE_NS);
        assert_eq!(engine.oper_period_ns(), 500_000);
        assert_eq!(engine.cycle_index(), 0);

        // Request scale to 250 µs.
        assert_eq!(engine.request_scale(250_000), CycleScaleResult::Accepted);
        assert_eq!(engine.admin_period_ns(), Some(250_000));

        // Advance one full cycle — no drain pending, so swap should happen.
        let b = engine.advance_cycle();
        assert!(b >= 1);
        assert_eq!(engine.oper_period_ns(), 250_000);
        assert_eq!(engine.admin_period_ns(), None);
        assert_eq!(engine.transition_log().len(), 1);
    }

    #[test]
    fn test_drain_blocks_transition() {
        let mut engine = TsnCqfCycleScaleEngine::new(500_000, MIN_CYCLE_NS);
        engine.enqueue_frames(5);
        assert_eq!(engine.request_scale(250_000), CycleScaleResult::Accepted);

        // Advance cycle — drain is not empty, so swap should NOT happen.
        engine.advance_cycle();
        assert_eq!(engine.oper_period_ns(), 500_000);
        assert_eq!(engine.admin_period_ns(), Some(250_000));

        // Drain all frames, then advance again.
        engine.drain_frames(5);
        engine.advance_cycle();
        assert_eq!(engine.oper_period_ns(), 250_000);
        assert_eq!(engine.admin_period_ns(), None);
    }

    #[test]
    fn test_invalid_alignment_rejected() {
        let mut engine = TsnCqfCycleScaleEngine::new(500_000, MIN_CYCLE_NS);
        // 200_000 is not a multiple of 125_000.
        assert_eq!(
            engine.request_scale(200_000),
            CycleScaleResult::InvalidAlignment
        );
    }

    #[test]
    fn test_out_of_range_rejected() {
        let mut engine = TsnCqfCycleScaleEngine::new(500_000, MIN_CYCLE_NS);
        assert_eq!(engine.request_scale(50_000), CycleScaleResult::OutOfRange);
        assert_eq!(
            engine.request_scale(20_000_000),
            CycleScaleResult::OutOfRange
        );
    }

    #[test]
    fn test_duplicate_request_rejected() {
        let mut engine = TsnCqfCycleScaleEngine::new(500_000, MIN_CYCLE_NS);
        assert_eq!(engine.request_scale(250_000), CycleScaleResult::Accepted);
        assert_eq!(
            engine.request_scale(375_000),
            CycleScaleResult::TransitionPending
        );
    }
}

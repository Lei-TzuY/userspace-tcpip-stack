// =============================================================================
// IEEE 802.1Qch CQF Multi-Priority Gate State Coordinated Dispatch Engine
// =============================================================================
//
// In multi-traffic-class deterministic networks, CQF alternates dual buffers
// (Cycle A / Cycle B) across multiple Priority Code Point (PCP) classes (0..7).
// To prevent lower-priority non-deterministic frames from interfering with
// hard-deadline scheduled streams during critical cycle dispatch phases,
// gate states must be coordinated across priority classes with explicit gate
// masks.
//
// Features:
//   1. 8-PCP Priority Gate Matrix: Bitmask-based gate state control for all 8
//      traffic classes during Cycle A and Cycle B.
//   2. Coordinated Phase Dispatch: Ensures that only classes with open gates
//      can drain during the active transmission interval.
//   3. Ingress Priority Admission Policer: Filters ingress frames according
//      to the active receive-gate mask of the receiving cycle.
//   4. Cycle Rotation & Statistics: Tracks per-priority transmitted bytes,
//      admitted frames, and gate-blocked drops.
//
// All timing arithmetic uses integer nanoseconds (u64). Safe Rust, zero crates.

/// Number of priority traffic classes (IEEE 802.1Q PCP 0..7).
pub const NUM_PRIORITIES: usize = 8;

/// A frame enqueued for coordinated CQF dispatch.
#[derive(Debug, Clone)]
pub struct CoordinatedCqfFrame {
    pub stream_id: u32,
    pub priority: u8,
    pub payload_bytes: usize,
    pub enqueue_time_ns: u64,
}

/// Verdict on frame admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateCoordVerdict {
    /// Admitted into active receive queue.
    Admitted { cycle_index: u64, cycle_buffer: u8 },
    /// Rejected because the gate for this priority is currently closed.
    DroppedGateClosed,
    /// Rejected due to invalid priority (must be 0..7).
    DroppedInvalidPriority,
}

/// Per-priority traffic statistics.
#[derive(Debug, Clone, Default)]
pub struct PriorityStats {
    pub frames_admitted: u64,
    pub bytes_admitted: u64,
    pub frames_dispatched: u64,
    pub bytes_dispatched: u64,
    pub frames_gate_blocked: u64,
}

/// CQF Multi-Priority Gate State Coordination Engine.
pub struct TsnCqfGateCoordEngine {
    /// Cycle duration in nanoseconds.
    pub cycle_time_ns: u64,
    /// Gate state bitmask for Cycle 0 transmit / Cycle 1 receive (bit P = priority P open).
    pub gate_mask_cycle_0_tx: u8,
    /// Gate state bitmask for Cycle 1 transmit / Cycle 0 receive.
    pub gate_mask_cycle_1_tx: u8,
    /// Current cycle index (monotonic).
    pub cycle_index: u64,
    /// Monotonic wall-clock time in nanoseconds.
    pub current_time_ns: u64,
    /// Accumulated time in the current cycle.
    pub cycle_elapsed_ns: u64,
    /// Which cycle buffer is currently in TX mode (0 or 1). In RX mode it's 1 - active_tx_buffer.
    pub active_tx_buffer: u8,
    /// Queue buffer 0 frames.
    pub buffer_0: Vec<CoordinatedCqfFrame>,
    /// Queue buffer 1 frames.
    pub buffer_1: Vec<CoordinatedCqfFrame>,
    /// Per-priority statistics.
    pub stats: [PriorityStats; NUM_PRIORITIES],
}

impl TsnCqfGateCoordEngine {
    /// Create a new engine with default cycle duration (e.g. 100 µs = 100,000 ns)
    /// and all priority gates open (0xFF).
    pub fn new(cycle_time_ns: u64) -> Self {
        Self {
            cycle_time_ns: if cycle_time_ns == 0 {
                100_000
            } else {
                cycle_time_ns
            },
            gate_mask_cycle_0_tx: 0xFF,
            gate_mask_cycle_1_tx: 0xFF,
            cycle_index: 0,
            current_time_ns: 0,
            cycle_elapsed_ns: 0,
            active_tx_buffer: 0,
            buffer_0: Vec::new(),
            buffer_1: Vec::new(),
            stats: Default::default(),
        }
    }

    /// Configure the gate masks for both cycle phases.
    /// Bit `p` (1 << p) controls whether priority `p` (0..7) is enabled.
    pub fn set_gate_masks(&mut self, mask_c0_tx: u8, mask_c1_tx: u8) {
        self.gate_mask_cycle_0_tx = mask_c0_tx;
        self.gate_mask_cycle_1_tx = mask_c1_tx;
    }

    /// Check if the gate is open for a given priority during the current TX phase.
    pub fn is_tx_gate_open(&self, priority: u8) -> bool {
        if priority as usize >= NUM_PRIORITIES {
            return false;
        }
        let mask = if self.active_tx_buffer == 0 {
            self.gate_mask_cycle_0_tx
        } else {
            self.gate_mask_cycle_1_tx
        };
        (mask & (1 << priority)) != 0
    }

    /// Check if the receive gate is open for incoming frames during the active phase.
    pub fn is_rx_gate_open(&self, priority: u8) -> bool {
        if priority as usize >= NUM_PRIORITIES {
            return false;
        }
        // Ingress buffer is (1 - active_tx_buffer)
        let mask = if self.active_tx_buffer == 0 {
            self.gate_mask_cycle_1_tx
        } else {
            self.gate_mask_cycle_0_tx
        };
        (mask & (1 << priority)) != 0
    }

    /// Ingest a frame into the receiving cycle buffer.
    pub fn ingest_frame(&mut self, frame: CoordinatedCqfFrame) -> GateCoordVerdict {
        let p = frame.priority as usize;
        if p >= NUM_PRIORITIES {
            return GateCoordVerdict::DroppedInvalidPriority;
        }

        if !self.is_rx_gate_open(frame.priority) {
            self.stats[p].frames_gate_blocked += 1;
            return GateCoordVerdict::DroppedGateClosed;
        }

        let rx_buffer = 1 - self.active_tx_buffer;
        self.stats[p].frames_admitted += 1;
        self.stats[p].bytes_admitted += frame.payload_bytes as u64;

        if rx_buffer == 0 {
            self.buffer_0.push(frame);
        } else {
            self.buffer_1.push(frame);
        }

        GateCoordVerdict::Admitted {
            cycle_index: self.cycle_index,
            cycle_buffer: rx_buffer,
        }
    }

    /// Dispatch frames from the current TX buffer that pass gate checks.
    /// Returns the list of successfully transmitted frames.
    pub fn dispatch_active_buffer(&mut self) -> Vec<CoordinatedCqfFrame> {
        let tx_buf = self.active_tx_buffer;
        let tx_mask = if tx_buf == 0 {
            self.gate_mask_cycle_0_tx
        } else {
            self.gate_mask_cycle_1_tx
        };

        let buffer = if tx_buf == 0 {
            &mut self.buffer_0
        } else {
            &mut self.buffer_1
        };

        let mut dispatched = Vec::new();
        let mut retained = Vec::new();

        for frame in buffer.drain(..) {
            let p = frame.priority as usize;
            let is_open = p < NUM_PRIORITIES && (tx_mask & (1 << frame.priority)) != 0;
            if is_open {
                self.stats[p].frames_dispatched += 1;
                self.stats[p].bytes_dispatched += frame.payload_bytes as u64;
                dispatched.push(frame);
            } else {
                // If TX gate became closed, frame is retained or dropped according to policy
                self.stats[p].frames_gate_blocked += 1;
                retained.push(frame);
            }
        }

        if tx_buf == 0 {
            self.buffer_0 = retained;
        } else {
            self.buffer_1 = retained;
        }

        dispatched
    }

    /// Advance time by `delta_ns` nanoseconds. Rotates cycle when boundary is crossed.
    /// Returns the number of cycle rotations performed.
    pub fn advance_time(&mut self, delta_ns: u64) -> u32 {
        self.current_time_ns = self.current_time_ns.saturating_add(delta_ns);
        self.cycle_elapsed_ns = self.cycle_elapsed_ns.saturating_add(delta_ns);

        let mut rotations = 0;
        while self.cycle_elapsed_ns >= self.cycle_time_ns {
            self.cycle_elapsed_ns -= self.cycle_time_ns;
            self.cycle_index += 1;
            self.active_tx_buffer = 1 - self.active_tx_buffer;
            rotations += 1;
        }
        rotations
    }

    /// Force a single cycle rotation immediately.
    pub fn rotate_cycle(&mut self) {
        self.cycle_index += 1;
        self.active_tx_buffer = 1 - self.active_tx_buffer;
        self.cycle_elapsed_ns = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_coordination_basic() {
        let mut engine = TsnCqfGateCoordEngine::new(100_000);
        // Enable only high priority (P6, P7) in Cycle 0 TX, and P0..P3 in Cycle 1 TX
        engine.set_gate_masks(0b1100_0000, 0b0000_1111);

        // Active TX buffer is 0, so active RX buffer is 1.
        // RX gate check for buffer 1 uses gate_mask_cycle_1_tx (0b0000_1111).
        let frame_p2 = CoordinatedCqfFrame {
            stream_id: 1,
            priority: 2,
            payload_bytes: 256,
            enqueue_time_ns: 0,
        };
        assert_eq!(
            engine.ingest_frame(frame_p2),
            GateCoordVerdict::Admitted {
                cycle_index: 0,
                cycle_buffer: 1
            }
        );

        // Frame with priority 7 is closed on RX buffer 1 (mask is 0x0F)
        let frame_p7 = CoordinatedCqfFrame {
            stream_id: 2,
            priority: 7,
            payload_bytes: 512,
            enqueue_time_ns: 0,
        };
        assert_eq!(
            engine.ingest_frame(frame_p7),
            GateCoordVerdict::DroppedGateClosed
        );

        // Advance to cycle 1 (TX buffer becomes 1, containing frame_p2)
        engine.rotate_cycle();
        assert_eq!(engine.active_tx_buffer, 1);

        let dispatched = engine.dispatch_active_buffer();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].stream_id, 1);
    }
}

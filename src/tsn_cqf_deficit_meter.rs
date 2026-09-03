// =============================================================================
// IEEE 802.1Qch CQF Burst Ingress Deficit Metering & Queue Protection Engine
// =============================================================================
//
// In IEEE 802.1Qch Cyclic Queuing and Forwarding (CQF), uncontrolled micro-bursts
// at ingress can overrun deterministic per-cycle queue buffers. The Deficit
// Ingress Meter assigns a deterministic per-cycle quantum (bytes) to each stream
// and tracks a credit/deficit balance across cycle boundaries.
//
// Features:
//   1. Per-Stream Cycle Quantum Allocation: Strict bandwidth guarantee per cycle.
//   2. Deficit Credit Carryover: Unused byte budget in cycle `k` carries over
//      up to a configured `max_credit_burst_bytes` cap.
//   3. Ingress Admission & Policing: Admitted vs DeficitExceeded verdict.
//   4. Cycle Boundary Rotation: Refills quantum and updates deficit balances.
//
// Pure safe Rust, zero external crates.

/// Verdict for an ingress frame evaluated by the deficit meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeficitMeterVerdict {
    /// Frame is within allocated burst credit and admitted into the current cycle.
    Admitted { remaining_credit_bytes: usize },
    /// Frame exceeds available credit for this cycle; rejected to protect buffer.
    DeficitExceeded {
        required_bytes: usize,
        available_credit_bytes: usize,
    },
}

/// Profile and runtime state for a metered TSN stream.
#[derive(Debug, Clone)]
pub struct DeficitStreamProfile {
    pub stream_id: u32,
    pub name: String,
    /// Quantum (in bytes) replenished at each cycle transition.
    pub cycle_quantum_bytes: usize,
    /// Maximum credit accumulator cap (prevents unbounded burst growth).
    pub max_credit_bytes: usize,
    /// Current available byte credit for the active cycle.
    pub current_credit_bytes: usize,
    /// Statistics
    pub total_admitted_frames: u64,
    pub total_admitted_bytes: u64,
    pub total_dropped_frames: u64,
    pub total_dropped_bytes: u64,
}

impl DeficitStreamProfile {
    pub fn new(
        stream_id: u32,
        name: &str,
        cycle_quantum_bytes: usize,
        max_credit_bytes: usize,
    ) -> Self {
        Self {
            stream_id,
            name: name.to_string(),
            cycle_quantum_bytes,
            max_credit_bytes,
            current_credit_bytes: cycle_quantum_bytes.min(max_credit_bytes),
            total_admitted_frames: 0,
            total_admitted_bytes: 0,
            total_dropped_frames: 0,
            total_dropped_bytes: 0,
        }
    }
}

/// TSN CQF Deficit Metering & Queue Protection Engine.
pub struct TsnCqfDeficitMeterEngine {
    pub cycle_duration_ns: u64,
    pub current_cycle_index: u64,
    pub streams: Vec<DeficitStreamProfile>,
}

impl TsnCqfDeficitMeterEngine {
    pub fn new(cycle_duration_ns: u64) -> Self {
        Self {
            cycle_duration_ns,
            current_cycle_index: 0,
            streams: Vec::new(),
        }
    }

    /// Register or update a stream's deficit meter configuration.
    pub fn register_stream(&mut self, stream: DeficitStreamProfile) {
        if let Some(pos) = self
            .streams
            .iter()
            .position(|s| s.stream_id == stream.stream_id)
        {
            self.streams[pos] = stream;
        } else {
            self.streams.push(stream);
        }
    }

    /// Ingest and meter an incoming frame for a stream.
    pub fn meter_frame(&mut self, stream_id: u32, frame_bytes: usize) -> DeficitMeterVerdict {
        let stream = match self.streams.iter_mut().find(|s| s.stream_id == stream_id) {
            Some(s) => s,
            None => {
                return DeficitMeterVerdict::DeficitExceeded {
                    required_bytes: frame_bytes,
                    available_credit_bytes: 0,
                };
            }
        };

        if frame_bytes <= stream.current_credit_bytes {
            stream.current_credit_bytes -= frame_bytes;
            stream.total_admitted_frames += 1;
            stream.total_admitted_bytes += frame_bytes as u64;
            DeficitMeterVerdict::Admitted {
                remaining_credit_bytes: stream.current_credit_bytes,
            }
        } else {
            stream.total_dropped_frames += 1;
            stream.total_dropped_bytes += frame_bytes as u64;
            DeficitMeterVerdict::DeficitExceeded {
                required_bytes: frame_bytes,
                available_credit_bytes: stream.current_credit_bytes,
            }
        }
    }

    /// Trigger cycle boundary transition: replenish quantum with credit carryover.
    pub fn rotate_cycle(&mut self) {
        self.current_cycle_index = self.current_cycle_index.saturating_add(1);

        for stream in &mut self.streams {
            // Carryover credit + replenish quantum, capped at max_credit_bytes
            let new_credit = stream
                .current_credit_bytes
                .saturating_add(stream.cycle_quantum_bytes)
                .min(stream.max_credit_bytes);
            stream.current_credit_bytes = new_credit;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deficit_meter_lifecycle() {
        let mut engine = TsnCqfDeficitMeterEngine::new(100_000);

        // 1000 bytes quantum per cycle, max 1500 bytes burst capacity
        let stream = DeficitStreamProfile::new(1, "Robotics-Control", 1000, 1500);
        engine.register_stream(stream);

        // Frame 1: 600 bytes -> Admitted (400 remaining)
        assert_eq!(
            engine.meter_frame(1, 600),
            DeficitMeterVerdict::Admitted {
                remaining_credit_bytes: 400
            }
        );

        // Frame 2: 500 bytes -> Exceeded (only 400 available)
        assert_eq!(
            engine.meter_frame(1, 500),
            DeficitMeterVerdict::DeficitExceeded {
                required_bytes: 500,
                available_credit_bytes: 400
            }
        );

        // Frame 3: 400 bytes -> Admitted (0 remaining)
        assert_eq!(
            engine.meter_frame(1, 400),
            DeficitMeterVerdict::Admitted {
                remaining_credit_bytes: 0
            }
        );

        // Rotate cycle -> Replenishes 1000 bytes + 0 carryover = 1000 bytes
        engine.rotate_cycle();

        // Send 400 bytes in new cycle -> 600 left
        assert_eq!(
            engine.meter_frame(1, 400),
            DeficitMeterVerdict::Admitted {
                remaining_credit_bytes: 600
            }
        );

        // Rotate cycle again -> 600 + 1000 = 1600, capped at max 1500 bytes!
        engine.rotate_cycle();
        let s = engine.streams.iter().find(|s| s.stream_id == 1).unwrap();
        assert_eq!(s.current_credit_bytes, 1500);
    }
}

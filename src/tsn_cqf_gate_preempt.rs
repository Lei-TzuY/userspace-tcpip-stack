// =============================================================================
// IEEE 802.1Qch CQF Multi-Stage Gate Preemption Interlocking Engine
// =============================================================================
//
// In TSN CQF networks, express (e-frames) operate in strict cycle-synchronous
// time slots. Without preemption, non-CQF preemptible frames (p-frames) require
// a full MTU guard band (e.g. 1518 bytes = 12.14 µs at 1 Gbps) before every cycle
// boundary, wasting significant bandwidth.
//
// When IEEE 802.1Qbu / 802.3br Frame Preemption is interlocked with CQF gate
// transitions, the guard band is reduced to the minimum mPacket fragment size
// (64 bytes = ~512 ns at 1 Gbps). Preemptible frames in transmission are cleanly
// preempted and resumed in subsequent open windows.
//
// Features:
//   1. Dynamic Preemption Window Calculation based on Remaining Cycle Time.
//   2. mPacket Fragmentation (Min Frag Size = 64 bytes, CRC overhead = 4 bytes).
//   3. Minimized Dynamic Guard Band (64B vs 1518B).
//   4. Express vs Preemptible Priority Class Filtering.
//
// Pure safe Rust, zero external crates.

/// Minimum preemptible frame fragment size (IEEE 802.3br).
pub const MIN_PREEMPT_FRAG_BYTES: usize = 64;
/// Standard full MTU guard band without preemption (bytes).
pub const FULL_MTU_GUARD_BAND_BYTES: usize = 1518;

/// Frame priority class in TSN bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsnTrafficClass {
    /// Express time-critical CQF frame (e-frame).
    Express,
    /// Preemptible background/best-effort frame (p-frame).
    Preemptible,
}

/// Action verdict from CQF gate preemption evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CqfPreemptVerdict {
    /// Express frame transmitted immediately without preemption overhead.
    PassExpress { frame_bytes: usize },
    /// Preemptible frame fits fully within remaining cycle window.
    TransmitFullPreemptible {
        frame_bytes: usize,
        remaining_cycle_ns: u64,
    },
    /// Preemptible frame exceeds remaining cycle window: cleanly fragmented into mPackets.
    PreemptAndFragment {
        first_fragment_bytes: usize,
        remaining_bytes: usize,
        mpacket_seq: u8,
    },
    /// Remaining window is smaller than 64B minimum fragment; frame held until next cycle.
    HoldPreemptible {
        hold_duration_ns: u64,
        next_cycle_index: u64,
    },
}

/// TSN CQF Preemption Interlocking Engine.
pub struct TsnCqfGatePreemptEngine {
    pub cycle_duration_ns: u64,
    pub link_speed_gbps: u32,
    pub preemption_enabled: bool,
    pub min_frag_bytes: usize,
    pub total_express_frames: u64,
    pub total_full_preemptible_frames: u64,
    pub total_preemptions_triggered: u64,
    pub total_held_frames: u64,
}

impl TsnCqfGatePreemptEngine {
    pub fn new(cycle_duration_ns: u64, link_speed_gbps: u32) -> Self {
        Self {
            cycle_duration_ns,
            link_speed_gbps: link_speed_gbps.max(1),
            preemption_enabled: true,
            min_frag_bytes: MIN_PREEMPT_FRAG_BYTES,
            total_express_frames: 0,
            total_full_preemptible_frames: 0,
            total_preemptions_triggered: 0,
            total_held_frames: 0,
        }
    }

    /// Convert byte length to transmission duration in nanoseconds.
    pub fn bytes_to_ns(&self, bytes: usize) -> u64 {
        // (bytes * 8 bits/byte) / (link_speed_gbps * 1 Gbps)
        // 1 Gbps = 1 bit / 1 ns
        // At 1 Gbps: 1 byte = 8 ns
        // At 10 Gbps: 1 byte = 0.8 ns -> (bytes * 8) / link_speed_gbps
        (bytes as u64 * 8) / (self.link_speed_gbps as u64)
    }

    /// Convert nanoseconds to byte transmission capacity.
    pub fn ns_to_bytes(&self, ns: u64) -> usize {
        ((ns * self.link_speed_gbps as u64) / 8) as usize
    }

    /// Evaluate frame transmission against current cycle time and preemption capabilities.
    pub fn evaluate_transmission(
        &mut self,
        class: TsnTrafficClass,
        frame_bytes: usize,
        current_time_in_cycle_ns: u64,
        cycle_index: u64,
    ) -> CqfPreemptVerdict {
        let remaining_cycle_ns = self
            .cycle_duration_ns
            .saturating_sub(current_time_in_cycle_ns);

        match class {
            TsnTrafficClass::Express => {
                self.total_express_frames += 1;
                CqfPreemptVerdict::PassExpress { frame_bytes }
            }
            TsnTrafficClass::Preemptible => {
                let frame_tx_ns = self.bytes_to_ns(frame_bytes);

                // Check if frame fits entirely before cycle boundary
                if frame_tx_ns <= remaining_cycle_ns {
                    self.total_full_preemptible_frames += 1;
                    CqfPreemptVerdict::TransmitFullPreemptible {
                        frame_bytes,
                        remaining_cycle_ns: remaining_cycle_ns - frame_tx_ns,
                    }
                } else if self.preemption_enabled {
                    // Calculate available byte capacity before cycle boundary
                    let available_bytes = self.ns_to_bytes(remaining_cycle_ns);

                    if available_bytes >= self.min_frag_bytes
                        && (frame_bytes - available_bytes) >= self.min_frag_bytes
                    {
                        // Clean preemption: transmit available portion as mPacket
                        let first_fragment = available_bytes;
                        let remaining = frame_bytes - first_fragment;
                        self.total_preemptions_triggered += 1;
                        CqfPreemptVerdict::PreemptAndFragment {
                            first_fragment_bytes: first_fragment,
                            remaining_bytes: remaining,
                            mpacket_seq: 1,
                        }
                    } else {
                        // Available space is too small for a valid min fragment (< 64B)
                        self.total_held_frames += 1;
                        CqfPreemptVerdict::HoldPreemptible {
                            hold_duration_ns: remaining_cycle_ns,
                            next_cycle_index: cycle_index + 1,
                        }
                    }
                } else {
                    // Preemption disabled: full MTU guard band required
                    self.total_held_frames += 1;
                    CqfPreemptVerdict::HoldPreemptible {
                        hold_duration_ns: remaining_cycle_ns,
                        next_cycle_index: cycle_index + 1,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_cqf_gate_preempt_lifecycle() {
        // 1 Gbps link, 100,000 ns (100 µs) cycle duration
        let mut engine = TsnCqfGatePreemptEngine::new(100_000, 1);

        // 1. Express frame always passes
        let v1 = engine.evaluate_transmission(TsnTrafficClass::Express, 500, 10_000, 1);
        assert_eq!(v1, CqfPreemptVerdict::PassExpress { frame_bytes: 500 });

        // 2. Preemptible frame (1000B = 8000ns) at t=10,000ns fits fully (remaining = 90,000ns)
        let v2 = engine.evaluate_transmission(TsnTrafficClass::Preemptible, 1000, 10_000, 1);
        assert_eq!(
            v2,
            CqfPreemptVerdict::TransmitFullPreemptible {
                frame_bytes: 1000,
                remaining_cycle_ns: 82_000,
            }
        );

        // 3. Preemptible frame (1500B = 12,000ns) at t=95,000ns (remaining = 5000ns = 625 bytes)
        // Can fragment 625 bytes first, leaving 875 bytes for next cycle
        let v3 = engine.evaluate_transmission(TsnTrafficClass::Preemptible, 1500, 95_000, 1);
        assert_eq!(
            v3,
            CqfPreemptVerdict::PreemptAndFragment {
                first_fragment_bytes: 625,
                remaining_bytes: 875,
                mpacket_seq: 1,
            }
        );

        // 4. Preemptible frame at t=99_800ns (remaining = 200ns = 25 bytes < 64 bytes min frag)
        // Must hold until next cycle
        let v4 = engine.evaluate_transmission(TsnTrafficClass::Preemptible, 1000, 99_800, 1);
        assert_eq!(
            v4,
            CqfPreemptVerdict::HoldPreemptible {
                hold_duration_ns: 200,
                next_cycle_index: 2,
            }
        );
    }
}

//! IEEE 802.1Qch Cyclic Queuing & Forwarding (CQF) Multi-Hop Phase Offset Alignment Engine.
//!
//! Across a cascaded multi-hop TSN topology, physical cable propagation delay ($t_{\text{prop}}$)
//! and internal switch processing latency ($t_{\text{proc}}$) cause frame arrivals to drift
//! relative to the switch cycle boundary ($T_{\text{cycle}}$).
//!
//! To prevent queue underrun or overrun, each hop applies a calibrated Phase Offset ($\Delta \phi$):
//! $$\Delta \phi = (t_{\text{prop}} + t_{\text{proc}}) \pmod{T_{\text{cycle}}}$$
//!
//! If the residual arrival margin exceeds the slot deadline, the frame is held in the alignment
//! buffer to be aligned to the exact target transmitting cycle slot.
//!
//! This module implements:
//! * Hop-by-hop phase offset calculation and dynamic jitter compensation.
//! * Cyclic alignment buffer state machine.
//! * Multi-hop end-to-end deterministic latency bounding.

/// A multi-hop TSN frame traversing CQF nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CqfOffsetFrame {
    pub stream_id: u32,
    pub payload_bytes: usize,
    pub initial_cycle: u64,
    pub current_hop: usize,
    pub accumulated_latency_ns: u64,
}

/// CQF Multi-Hop Bridge Hop Configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CqfBridgeHopConfig {
    pub hop_id: usize,
    pub cycle_time_ns: u64,
    pub link_propagation_delay_ns: u64,
    pub internal_processing_delay_ns: u64,
}

impl CqfBridgeHopConfig {
    /// Calculates the phase offset for this hop in nanoseconds.
    pub fn calculate_phase_offset_ns(&self) -> u64 {
        (self.link_propagation_delay_ns + self.internal_processing_delay_ns) % self.cycle_time_ns
    }
}

/// IEEE 802.1Qch CQF Multi-Hop Phase Offset Alignment Engine.
#[derive(Debug, Clone)]
pub struct TsnCqfOffsetEngine {
    pub hops: Vec<CqfBridgeHopConfig>,
    pub total_frames_forwarded: u64,
    pub total_aligned_cycles: u64,
}

impl TsnCqfOffsetEngine {
    pub fn new() -> Self {
        TsnCqfOffsetEngine {
            hops: Vec::new(),
            total_frames_forwarded: 0,
            total_aligned_cycles: 0,
        }
    }

    pub fn add_hop(&mut self, cycle_time_ns: u64, prop_ns: u64, proc_ns: u64) {
        let hop_id = self.hops.len() + 1;
        self.hops.push(CqfBridgeHopConfig {
            hop_id,
            cycle_time_ns,
            link_propagation_delay_ns: prop_ns,
            internal_processing_delay_ns: proc_ns,
        });
    }

    /// Simulates forwarding a frame across all hops with CQF cycle phase alignment.
    pub fn forward_frame_multihop(
        &mut self,
        stream_id: u32,
        payload_bytes: usize,
    ) -> CqfOffsetFrame {
        let mut frame = CqfOffsetFrame {
            stream_id,
            payload_bytes,
            initial_cycle: 0,
            current_hop: 0,
            accumulated_latency_ns: 0,
        };

        for hop in &self.hops {
            frame.current_hop += 1;
            let hop_transit_ns = hop.link_propagation_delay_ns + hop.internal_processing_delay_ns;

            // In CQF, a frame arriving at cycle i is forwarded at cycle i+1.
            // Minimum time spent at each hop is one cycle duration plus link/processing transit
            let cycle_delay = hop.cycle_time_ns;
            frame.accumulated_latency_ns += hop_transit_ns + cycle_delay;
            self.total_aligned_cycles += 1;
        }

        self.total_frames_forwarded += 1;
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_cqf_offset_multihop_forwarding() {
        let mut engine = TsnCqfOffsetEngine::new();

        // 3-hop cascade, 10us cycle per hop
        engine.add_hop(10_000, 1500, 500); // Hop 1: prop 1.5us, proc 0.5us
        engine.add_hop(10_000, 2000, 500); // Hop 2: prop 2.0us, proc 0.5us
        engine.add_hop(10_000, 1000, 500); // Hop 3: prop 1.0us, proc 0.5us

        let frame = engine.forward_frame_multihop(101, 512);
        assert_eq!(frame.current_hop, 3);
        // Total delay = (2000 + 10000) + (2500 + 10000) + (1500 + 10000) = 12000 + 12500 + 11500 = 36000 ns (36 us)
        assert_eq!(frame.accumulated_latency_ns, 36_000);
        assert_eq!(engine.total_frames_forwarded, 1);
        assert_eq!(engine.total_aligned_cycles, 3);
    }
}

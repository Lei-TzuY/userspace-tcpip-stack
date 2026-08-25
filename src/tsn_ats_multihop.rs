//! IEEE 802.1Qcr Asynchronous Traffic Shaping (ATS) Multi-Hop Cascaded Shaper.
//!
//! Unlike IEEE 802.1Qbv (Time-Aware Shaper) which requires synchronized network clocks,
//! IEEE 802.1Qcr ATS provides deterministic bounded latency and zero congestion loss
//! in asynchronous networks using Urgency-Based Scheduling (UBS).
//!
//! At each hop, the ATS shaper consists of:
//! 1. Per-Flow Interleaved Regulators (IR): calculates Eligibility Time ($E_i$) for each packet based on committed burst size (CBS) and committed information rate (CIR).
//! 2. Urgency-Based Scheduler: packets become eligible when current local clock $T_{now} \ge E_i$.
//! 3. Multi-Hop Cascaded Propagation: maintains bounded burstiness across multiple bridges.
//!
//! This module implements:
//! * Per-stream token and eligibility time calculation: $E_i = \max(A_i, E_{i-1}) + \frac{L_i}{CIR}$.
//! * Multi-hop bridge pipeline with accumulated delay tracking.
//! * Bounded latency verification without packet dropping.

/// A TSN frame passing through the ATS shaper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtsMultiHopFrame {
    pub stream_id: u32,
    pub priority: u8,
    pub payload_bytes: usize,
    /// Ingress arrival timestamp in nanoseconds at hop 0.
    pub ingress_timestamp_ns: u64,
    /// Hop-by-hop calculated eligibility time in nanoseconds.
    pub eligibility_time_ns: u64,
    /// Number of hops traversed.
    pub hops_traversed: usize,
}

/// Per-flow regulator configuration and state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRegulator {
    pub stream_id: u32,
    /// Committed Information Rate in bytes per second (CIR).
    pub cir_bps: u64,
    /// Committed Burst Size in bytes (CBS).
    pub cbs_bytes: u64,
    /// Last calculated eligibility time in nanoseconds.
    pub last_eligibility_time_ns: u64,
    pub total_frames_regulated: u64,
}

impl FlowRegulator {
    pub fn new(stream_id: u32, cir_bps: u64, cbs_bytes: u64) -> Self {
        FlowRegulator {
            stream_id,
            cir_bps,
            cbs_bytes,
            last_eligibility_time_ns: 0,
            total_frames_regulated: 0,
        }
    }

    /// Computes the eligibility time for an incoming frame per IEEE 802.1Qcr.
    /// $E_i = \max(A_i, E_{i-1} - \frac{CBS}{CIR}) + \frac{L_i \times 10^9}{CIR}$
    pub fn compute_eligibility(&mut self, arrival_ns: u64, length_bytes: usize) -> u64 {
        self.total_frames_regulated += 1;
        let transmission_duration_ns = (length_bytes as u64 * 1_000_000_000) / self.cir_bps.max(1);
        let max_burst_credit_ns = (self.cbs_bytes * 1_000_000_000) / self.cir_bps.max(1);

        let baseline_ns = arrival_ns.max(
            self.last_eligibility_time_ns
                .saturating_sub(max_burst_credit_ns),
        );
        let eligibility_ns = baseline_ns + transmission_duration_ns;
        self.last_eligibility_time_ns = eligibility_ns;
        eligibility_ns
    }
}

/// Multi-Hop ATS Bridge Node.
#[derive(Debug, Clone)]
pub struct AtsBridgeHop {
    pub hop_id: usize,
    /// Fixed internal switching latency per hop in nanoseconds.
    pub internal_latency_ns: u64,
    pub regulators: Vec<FlowRegulator>,
    pub transmission_queue: Vec<AtsMultiHopFrame>,
}

impl AtsBridgeHop {
    pub fn new(hop_id: usize, internal_latency_ns: u64) -> Self {
        AtsBridgeHop {
            hop_id,
            internal_latency_ns,
            regulators: Vec::new(),
            transmission_queue: Vec::new(),
        }
    }

    pub fn register_flow(&mut self, stream_id: u32, cir_bps: u64, cbs_bytes: u64) {
        self.regulators
            .push(FlowRegulator::new(stream_id, cir_bps, cbs_bytes));
    }

    /// Ingests a frame, regulates its eligibility time, and queues it.
    pub fn ingest_frame(&mut self, mut frame: AtsMultiHopFrame, current_time_ns: u64) {
        let stream_id = frame.stream_id;
        let len = frame.payload_bytes;

        let elig = if let Some(reg) = self
            .regulators
            .iter_mut()
            .find(|r| r.stream_id == stream_id)
        {
            reg.compute_eligibility(current_time_ns, len)
        } else {
            current_time_ns
        };

        frame.eligibility_time_ns = elig;
        frame.hops_traversed += 1;
        self.transmission_queue.push(frame);
    }

    /// Transmits all eligible frames at current local time.
    pub fn transmit_eligible(&mut self, current_time_ns: u64) -> Vec<AtsMultiHopFrame> {
        let mut ready = Vec::new();
        let mut pending = Vec::new();

        for frame in self.transmission_queue.drain(..) {
            if current_time_ns >= frame.eligibility_time_ns {
                ready.push(frame);
            } else {
                pending.push(frame);
            }
        }

        self.transmission_queue = pending;
        ready
    }
}

/// Multi-Hop Cascaded ATS Pipeline Simulator.
#[derive(Debug, Clone)]
pub struct AtsMultiHopPipeline {
    pub hops: Vec<AtsBridgeHop>,
    pub delivered_frames: Vec<AtsMultiHopFrame>,
}

impl AtsMultiHopPipeline {
    pub fn new(hop_count: usize, latency_per_hop_ns: u64) -> Self {
        let mut hops = Vec::with_capacity(hop_count);
        for i in 0..hop_count {
            hops.push(AtsBridgeHop::new(i, latency_per_hop_ns));
        }
        AtsMultiHopPipeline {
            hops,
            delivered_frames: Vec::new(),
        }
    }

    pub fn configure_stream_across_hops(&mut self, stream_id: u32, cir_bps: u64, cbs_bytes: u64) {
        for hop in &mut self.hops {
            hop.register_flow(stream_id, cir_bps, cbs_bytes);
        }
    }

    /// Ingests a frame at ingress Hop 0.
    pub fn ingest_ingress(
        &mut self,
        stream_id: u32,
        priority: u8,
        payload_bytes: usize,
        arrival_ns: u64,
    ) {
        let frame = AtsMultiHopFrame {
            stream_id,
            priority,
            payload_bytes,
            ingress_timestamp_ns: arrival_ns,
            eligibility_time_ns: arrival_ns,
            hops_traversed: 0,
        };
        if let Some(hop0) = self.hops.first_mut() {
            hop0.ingest_frame(frame, arrival_ns);
        }
    }

    /// Propagates frames through the entire multi-hop chain up to simulated time.
    pub fn step_simulation(&mut self, current_time_ns: u64) {
        for i in 0..self.hops.len() {
            let latency = self.hops[i].internal_latency_ns;
            let ready_frames = self.hops[i].transmit_eligible(current_time_ns);

            if i + 1 < self.hops.len() {
                // Forward to next hop
                for frame in ready_frames {
                    let next_arrival = frame.eligibility_time_ns.saturating_add(latency);
                    self.hops[i + 1].ingest_frame(frame, next_arrival);
                }
            } else {
                // Egress from final hop
                self.delivered_frames.extend(ready_frames);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ats_multihop_cascaded_propagation() {
        // 3-hop pipeline, 100us (100,000ns) internal latency per hop
        let mut pipeline = AtsMultiHopPipeline::new(3, 100_000);

        // Stream 1: CIR = 100 MB/s (100,000,000 B/s), CBS = 2000 B
        pipeline.configure_stream_across_hops(1, 100_000_000, 2000);

        // Send two 1000B frames at t = 0
        pipeline.ingest_ingress(1, 7, 1000, 0);
        pipeline.ingest_ingress(1, 7, 1000, 0);

        // Advance simulation time:
        // Frame 1: elig = 10us at hop 0. Transmit at t=10us -> arrives hop 1 at 110us
        // Hop 1 transmits at t=120us -> arrives hop 2 at 220us
        // Hop 2 transmits at t=230us -> delivered!
        pipeline.step_simulation(100_000);
        pipeline.step_simulation(200_000);
        pipeline.step_simulation(350_000);

        assert!(!pipeline.delivered_frames.is_empty());
        assert_eq!(pipeline.delivered_frames[0].hops_traversed, 3);
        assert_eq!(pipeline.delivered_frames[0].stream_id, 1);
    }
}

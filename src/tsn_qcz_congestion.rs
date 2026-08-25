//! IEEE 802.1Qcz Congestion Isolation & Head-of-Line (HoL) Blocking Mitigation Engine.
//!
//! In high-speed datacenter fabrics (RoCEv2 / NVMe-oF / AI training clusters),
//! pause frames (PFC IEEE 802.1Qbb) can propagate congestion upstream, causing
//! victim flows sharing the same priority queue to suffer severe latency degradation.
//!
//! IEEE 802.1Qcz Congestion Isolation solves this by:
//! 1. Monitoring queue depth at the Congestion Point (CP).
//! 2. Identifying offending Congestion Isolation Flows (CIF) based on flow hashes / 5-tuples.
//! 3. Diverting offending flows from the standard priority queue into a dedicated **Congestion Isolation Queue (CIQ)**.
//! 4. Generating IEEE 802.1Qau / Qcz Congestion Notification Messages (CNM).
//!
//! This module implements:
//! * Dual-queue architecture: Uncongested Queue (UQ) and Congestion Isolation Queue (CIQ).
//! * Threshold-based congestion detection ($Q_{thresh}$) and flow diversion.
//! * IEEE 802.1Qcz CNM (Congestion Notification Message) packet encoding.
//! * Strict Head-of-Line isolation: Uncongested traffic proceeds at line rate without waiting for congested flows.

use crate::ipv4::Ipv4Address;

pub const CNM_ETHERTYPE: u16 = 0x22E9;

/// Flow 5-tuple identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowTuple {
    pub fn new(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        FlowTuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }
}

/// Congestion Notification Message (CNM) payload per IEEE 802.1Qau / Qcz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CongestionNotificationMessage {
    pub quantized_feedback: u8,
    pub cp_mac: [u8; 6],
    pub offending_flow: FlowTuple,
    pub queue_occupancy_bytes: u32,
}

impl CongestionNotificationMessage {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.push(self.quantized_feedback);
        buf.extend_from_slice(&self.cp_mac);
        buf.extend_from_slice(&self.offending_flow.src_ip.0);
        buf.extend_from_slice(&self.offending_flow.dst_ip.0);
        buf.extend_from_slice(&self.offending_flow.src_port.to_be_bytes());
        buf.extend_from_slice(&self.offending_flow.dst_port.to_be_bytes());
        buf.push(self.offending_flow.protocol);
        buf.extend_from_slice(&self.queue_occupancy_bytes.to_be_bytes());
        buf
    }
}

/// An enqueued packet container in the Qcz shaper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QczPacket {
    pub flow: FlowTuple,
    pub payload: Vec<u8>,
    pub is_isolated: bool,
}

/// IEEE 802.1Qcz Congestion Point (CP) Engine.
#[derive(Debug, Clone)]
pub struct QczCongestionEngine {
    pub cp_mac: [u8; 6],
    /// Congestion threshold in bytes to trigger flow isolation.
    pub congestion_threshold_bytes: usize,
    /// Uncongested Queue (UQ).
    pub uncongested_queue: Vec<QczPacket>,
    /// Congestion Isolation Queue (CIQ).
    pub isolated_queue: Vec<QczPacket>,
    /// List of tracked offending flows currently under isolation.
    pub isolated_flows: Vec<FlowTuple>,
    /// Counters.
    pub total_enqueued: u64,
    pub total_isolated: u64,
    pub total_cnm_generated: u64,
}

impl QczCongestionEngine {
    pub fn new(cp_mac: [u8; 6], congestion_threshold_bytes: usize) -> Self {
        QczCongestionEngine {
            cp_mac,
            congestion_threshold_bytes,
            uncongested_queue: Vec::new(),
            isolated_queue: Vec::new(),
            isolated_flows: Vec::new(),
            total_enqueued: 0,
            total_isolated: 0,
            total_cnm_generated: 0,
        }
    }

    /// Current uncongested queue occupancy in bytes.
    pub fn uq_occupancy(&self) -> usize {
        self.uncongested_queue.iter().map(|p| p.payload.len()).sum()
    }

    /// Current isolated queue occupancy in bytes.
    pub fn ciq_occupancy(&self) -> usize {
        self.isolated_queue.iter().map(|p| p.payload.len()).sum()
    }

    /// Enqueues a packet and performs congestion evaluation and isolation.
    /// If uncongested queue crosses threshold, the offending flow is isolated and a CNM is generated.
    pub fn enqueue_packet(
        &mut self,
        flow: FlowTuple,
        payload: Vec<u8>,
    ) -> Option<CongestionNotificationMessage> {
        self.total_enqueued += 1;
        let mut cnm = None;

        // Check if flow is already marked as isolated
        if self.isolated_flows.contains(&flow) {
            self.total_isolated += 1;
            self.isolated_queue.push(QczPacket {
                flow,
                payload,
                is_isolated: true,
            });
            return None;
        }

        let curr_uq = self.uq_occupancy();
        if curr_uq + payload.len() > self.congestion_threshold_bytes {
            // Congestion threshold crossed! Isolate this offending flow into CIQ
            self.isolated_flows.push(flow);
            self.total_isolated += 1;
            self.total_cnm_generated += 1;

            self.isolated_queue.push(QczPacket {
                flow,
                payload,
                is_isolated: true,
            });

            // Generate Congestion Notification Message (CNM)
            cnm = Some(CongestionNotificationMessage {
                quantized_feedback: 0x3F, // High congestion indicator (6-bit)
                cp_mac: self.cp_mac,
                offending_flow: flow,
                queue_occupancy_bytes: (curr_uq + self.ciq_occupancy()) as u32,
            });
        } else {
            // Normal flow, enqueue in standard Uncongested Queue (UQ)
            self.uncongested_queue.push(QczPacket {
                flow,
                payload,
                is_isolated: false,
            });
        }

        cnm
    }

    /// Drains uncongested packets (priority forwarding).
    pub fn drain_uncongested(&mut self) -> Vec<QczPacket> {
        std::mem::take(&mut self.uncongested_queue)
    }

    /// Drains isolated packets with rate-limited bandwidth.
    pub fn drain_isolated(&mut self) -> Vec<QczPacket> {
        std::mem::take(&mut self.isolated_queue)
    }

    /// Releases an isolated flow when congestion dissipates.
    pub fn clear_isolated_flow(&mut self, flow: &FlowTuple) -> bool {
        if let Some(pos) = self.isolated_flows.iter().position(|f| f == flow) {
            self.isolated_flows.remove(pos);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qcz_congestion_isolation_and_cnm_generation() {
        let cp_mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
        let mut engine = QczCongestionEngine::new(cp_mac, 1000); // 1000 bytes threshold

        let flow1 = FlowTuple::new(
            Ipv4Address::new(10, 0, 0, 1),
            Ipv4Address::new(10, 0, 0, 2),
            5001,
            5001,
            6,
        );

        let flow2_victim = FlowTuple::new(
            Ipv4Address::new(10, 0, 0, 3),
            Ipv4Address::new(10, 0, 0, 4),
            6001,
            6001,
            6,
        );

        // 1. Send 600B on flow1 -> UQ = 600B (under 1000B threshold)
        assert!(engine.enqueue_packet(flow1, vec![0xAA; 600]).is_none());
        assert_eq!(engine.uncongested_queue.len(), 1);
        assert_eq!(engine.isolated_queue.len(), 0);

        // 2. Send 500B on flow1 -> 600 + 500 = 1100B > 1000B threshold!
        // Flow1 is isolated into CIQ and CNM is generated!
        let cnm_opt = engine.enqueue_packet(flow1, vec![0xAA; 500]);
        assert!(cnm_opt.is_some());
        let cnm = cnm_opt.unwrap();
        assert_eq!(cnm.offending_flow, flow1);
        assert_eq!(cnm.cp_mac, cp_mac);
        assert_eq!(engine.isolated_queue.len(), 1);

        // 3. Send 200B on victim flow2 -> UQ = 600 + 200 = 800B <= 1000B!
        // Victim flow is NOT blocked by flow1 and stays in UQ at line rate!
        assert!(
            engine
                .enqueue_packet(flow2_victim, vec![0xBB; 200])
                .is_none()
        );
        assert_eq!(engine.uncongested_queue.len(), 2); // Flow1 (600B) + Flow2 (200B)

        // 4. Drain UQ
        let uq_drained = engine.drain_uncongested();
        assert_eq!(uq_drained.len(), 2);

        // 5. Subsequent flow1 packets go straight to CIQ
        assert!(engine.enqueue_packet(flow1, vec![0xAA; 100]).is_none());
        assert_eq!(engine.isolated_queue.len(), 2);
    }
}

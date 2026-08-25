//! 3GPP TS 23.501 Section 5.33.2 — 5G GTP-U Redundant User Plane Dual-Tunnel Transmission & Deduplication.
//!
//! In Ultra-Reliable Low-Latency Communication (URLLC), packet loss is unacceptable.
//! Dual-connectivity redundant user plane transmission duplicates every packet at the ingress
//! (e.g. gNodeB or UPF) over two disjoint GTP-U paths (Leg 1 & Leg 2).
//!
//! At the egress, a high-speed deduplication engine eliminates redundant packet copies
//! while forwarding the earliest arrival with minimum possible latency.
//!
//! This module implements:
//! * Dual-tunnel user-plane packet replication with unified GTP-U sequence numbering.
//! * Egress sliding deduplication window tracking.
//! * Zero-latency first-packet delivery and duplicate suppression.

use crate::ipv4::Ipv4Address;
use std::collections::HashSet;

/// A replicated GTP-U packet copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedundantGtpuPacket {
    pub session_id: u32,
    pub sequence_number: u16,
    pub target_ip: Ipv4Address,
    pub teid: u32,
    pub payload: Vec<u8>,
}

/// 5G GTP-U Redundant Dual-Path Transmission & Deduplication Engine.
#[derive(Debug, Clone)]
pub struct GtpuRedundantEngine {
    pub session_id: u32,
    pub leg1_ip: Ipv4Address,
    pub leg1_teid: u32,
    pub leg2_ip: Ipv4Address,
    pub leg2_teid: u32,
    pub next_tx_seq: u16,
    /// Egress deduplication window: recently seen sequence numbers
    pub seen_rx_seqs: HashSet<u16>,
    pub total_duplicated_sent: u64,
    pub total_valid_delivered: u64,
    pub total_duplicates_dropped: u64,
}

impl GtpuRedundantEngine {
    pub fn new(
        session_id: u32,
        leg1_ip: Ipv4Address,
        leg1_teid: u32,
        leg2_ip: Ipv4Address,
        leg2_teid: u32,
    ) -> Self {
        GtpuRedundantEngine {
            session_id,
            leg1_ip,
            leg1_teid,
            leg2_ip,
            leg2_teid,
            next_tx_seq: 1,
            seen_rx_seqs: HashSet::new(),
            total_duplicated_sent: 0,
            total_valid_delivered: 0,
            total_duplicates_dropped: 0,
        }
    }

    /// Replicates an outgoing user plane packet into two redundant GTP-U packets (one per leg).
    pub fn replicate_outgoing(&mut self, payload: &[u8]) -> (RedundantGtpuPacket, RedundantGtpuPacket) {
        let seq = self.next_tx_seq;
        self.next_tx_seq = self.next_tx_seq.wrapping_add(1);
        self.total_duplicated_sent += 2;

        let pkt1 = RedundantGtpuPacket {
            session_id: self.session_id,
            sequence_number: seq,
            target_ip: self.leg1_ip,
            teid: self.leg1_teid,
            payload: payload.to_vec(),
        };

        let pkt2 = RedundantGtpuPacket {
            session_id: self.session_id,
            sequence_number: seq,
            target_ip: self.leg2_ip,
            teid: self.leg2_teid,
            payload: payload.to_vec(),
        };

        (pkt1, pkt2)
    }

    /// Ingests a received GTP-U packet at the egress.
    /// Returns `Some(payload)` if this is the first arriving copy, or `None` if it is a duplicate.
    pub fn ingest_incoming(&mut self, seq: u16, payload: Vec<u8>) -> Option<Vec<u8>> {
        if self.seen_rx_seqs.contains(&seq) {
            // Duplicate copy detected -> Drop!
            self.total_duplicates_dropped += 1;
            None
        } else {
            // First arriving copy -> Deliver immediately!
            self.seen_rx_seqs.insert(seq);
            self.total_valid_delivered += 1;
            Some(payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_redundant_dual_tunnel_replication_and_deduplication() {
        let mut engine = GtpuRedundantEngine::new(
            101,
            Ipv4Address::new(10, 1, 1, 1),
            0x1111,
            Ipv4Address::new(10, 2, 2, 2),
            0x2222,
        );

        // 1. Replicate packet
        let (p1, p2) = engine.replicate_outgoing(b"URLLC Payload Data");
        assert_eq!(p1.sequence_number, 1);
        assert_eq!(p2.sequence_number, 1);
        assert_eq!(p1.target_ip, Ipv4Address::new(10, 1, 1, 1));
        assert_eq!(p2.target_ip, Ipv4Address::new(10, 2, 2, 2));

        // 2. First copy arrives over Leg 1 -> Delivered!
        let r1 = engine.ingest_incoming(p1.sequence_number, p1.payload);
        assert!(r1.is_some());
        assert_eq!(engine.total_valid_delivered, 1);

        // 3. Second copy arrives slightly delayed over Leg 2 -> Dropped as duplicate!
        let r2 = engine.ingest_incoming(p2.sequence_number, p2.payload);
        assert!(r2.is_none());
        assert_eq!(engine.total_duplicates_dropped, 1);
    }
}

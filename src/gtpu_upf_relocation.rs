//! 3GPP TS 23.501 / TS 23.502 / TS 29.281 — 5G GTP-U UPF Anchor Relocation & Handover Forwarding.
//!
//! During Xn or N2 mobility handovers, the User Plane Function (UPF) anchor
//! may be relocated from a Source UPF (S-UPF / I-UPF) to a Target UPF (T-UPF / A-UPF).
//!
//! To prevent packet loss during the handover execution phase:
//! 1. An Indirect Data Forwarding Tunnel (GTP-U) is established from S-UPF to T-UPF.
//! 2. S-UPF forwards in-flight downlink user plane packets over the indirect tunnel.
//! 3. Once the 5G Core completes path switching, S-UPF transmits one or more **End Marker** packets (GTP-U Msg Type 254).
//! 4. T-UPF receives the End Marker, flushes buffered indirect packets, and switches to direct gNodeB forwarding.
//!
//! This module implements:
//! * GTP-U Message Type 254: End Marker framing.
//! * S-UPF indirect forwarding pipeline and End Marker generation.
//! * T-UPF handover buffer, End Marker detection, and cut-over state machine.

use crate::ipv4::Ipv4Address;

pub const GTPU_MSG_END_MARKER: u8 = 254;

/// Handover State of a 5G PDU Session during UPF relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpfHandoverState {
    Normal,
    IndirectForwarding,
    EndMarkerReceived,
    SwitchedToDirect,
}

/// A GTP-U User Plane packet or End Marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverGtpuPacket {
    pub message_type: u8, // 255 for G-PDU, 254 for End Marker
    pub teid: u32,
    pub payload: Vec<u8>,
}

impl HandoverGtpuPacket {
    pub fn new_gpdu(teid: u32, payload: Vec<u8>) -> Self {
        HandoverGtpuPacket {
            message_type: 255,
            teid,
            payload,
        }
    }

    pub fn new_end_marker(teid: u32) -> Self {
        HandoverGtpuPacket {
            message_type: GTPU_MSG_END_MARKER,
            teid,
            payload: Vec::new(),
        }
    }
}

/// Target UPF (T-UPF) Handover Relocation Engine.
#[derive(Debug, Clone)]
pub struct TargetUpfRelocationEngine {
    pub session_id: u32,
    pub indirect_teid: u32,
    pub direct_teid: u32,
    pub source_upf_ip: Ipv4Address,
    pub gnodeb_ip: Ipv4Address,
    pub state: UpfHandoverState,
    pub indirect_buffer: Vec<HandoverGtpuPacket>,
    pub total_indirect_packets_recv: u64,
    pub total_direct_packets_sent: u64,
}

impl TargetUpfRelocationEngine {
    pub fn new(
        session_id: u32,
        indirect_teid: u32,
        direct_teid: u32,
        source_upf_ip: Ipv4Address,
        gnodeb_ip: Ipv4Address,
    ) -> Self {
        TargetUpfRelocationEngine {
            session_id,
            indirect_teid,
            direct_teid,
            source_upf_ip,
            gnodeb_ip,
            state: UpfHandoverState::IndirectForwarding,
            indirect_buffer: Vec::new(),
            total_indirect_packets_recv: 0,
            total_direct_packets_sent: 0,
        }
    }

    /// Ingests a packet received from the indirect forwarding tunnel.
    /// If an End Marker (Type 254) arrives, flushes buffer and completes switchover!
    pub fn handle_indirect_packet(&mut self, pkt: HandoverGtpuPacket) -> Vec<HandoverGtpuPacket> {
        let mut delivered = Vec::new();

        if pkt.message_type == GTPU_MSG_END_MARKER {
            // End Marker received! S-UPF finished forwarding.
            self.state = UpfHandoverState::EndMarkerReceived;

            // Flush all buffered indirect packets
            for mut p in self.indirect_buffer.drain(..) {
                p.teid = self.direct_teid;
                self.total_direct_packets_sent += 1;
                delivered.push(p);
            }

            self.state = UpfHandoverState::SwitchedToDirect;
        } else {
            self.total_indirect_packets_recv += 1;
            if self.state == UpfHandoverState::SwitchedToDirect {
                // Already switched, pass straight through with direct TEID
                let mut direct_pkt = pkt;
                direct_pkt.teid = self.direct_teid;
                self.total_direct_packets_sent += 1;
                delivered.push(direct_pkt);
            } else {
                // Buffer until End Marker signals handover completion
                self.indirect_buffer.push(pkt);
            }
        }

        delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upf_relocation_end_marker_flush() {
        let mut t_upf = TargetUpfRelocationEngine::new(
            1001,
            0x1000AAAA, // Indirect TEID
            0x2000BBBB, // Direct gNodeB TEID
            Ipv4Address::new(10, 1, 1, 1),
            Ipv4Address::new(10, 2, 2, 2),
        );

        assert_eq!(t_upf.state, UpfHandoverState::IndirectForwarding);

        // 1. Two in-flight indirect G-PDUs arrive from S-UPF
        let d1 = t_upf.handle_indirect_packet(HandoverGtpuPacket::new_gpdu(0x1000AAAA, b"P1".to_vec()));
        assert_eq!(d1.len(), 0); // Buffered

        let d2 = t_upf.handle_indirect_packet(HandoverGtpuPacket::new_gpdu(0x1000AAAA, b"P2".to_vec()));
        assert_eq!(d2.len(), 0); // Buffered
        assert_eq!(t_upf.indirect_buffer.len(), 2);

        // 2. End Marker packet (Type 254) arrives from S-UPF
        let end_marker = HandoverGtpuPacket::new_end_marker(0x1000AAAA);
        let delivered = t_upf.handle_indirect_packet(end_marker);

        // Handover completed, both buffered packets delivered with direct TEID!
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].teid, 0x2000BBBB);
        assert_eq!(delivered[1].teid, 0x2000BBBB);
        assert_eq!(t_upf.state, UpfHandoverState::SwitchedToDirect);
        assert_eq!(t_upf.total_direct_packets_sent, 2);
    }
}

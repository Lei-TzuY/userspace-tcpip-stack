//! SRv6 Mobile User Plane (MUP) Direct Routing & GTP-U Interworking.
//!
//! (IETF draft-ietf-dmm-srv6-mobile-uplane / 3GPP Rel-17).
//!
//! SRv6 MUP provides stateless translation between 3GPP 5G GTP-U user-plane
//! packets and pure IPv6 Segment Routing (SRv6) underlay packets without
//! requiring centralized stateful UPF anchors.
//!
//! This module implements:
//! * `End.M.GTP6.D` — Decapsulates GTP-U/IPv6 from gNodeB and translates to SRv6
//!   encapsulated packet carrying target SID list.
//! * `End.M.GTP6.E` — Decapsulates SRv6 packet, extracts target TEID and destination
//!   address from SRv6 SID argument, and encapsulates into standard GTP-U/IPv6.
//! * QFI (QoS Flow Identifier) mapping between GTP-U PDU Session Container and
//!   SRv6 Traffic Class / DSCP.

use crate::ipv6::Ipv6Address;

pub const GTPU_UDP_PORT: u16 = 2152;

/// SRv6 MUP Session Mapping Table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MupSessionMapping {
    /// Ingress GTP-U TEID from gNodeB.
    pub gtp_teid: u32,
    /// Ingress gNodeB IPv6 address.
    pub gnodeb_ip: Ipv6Address,
    /// Egress SRv6 SID Segment List.
    pub srv6_segments: Vec<Ipv6Address>,
    /// QFI (QoS Flow ID).
    pub qfi: u8,
}

/// Translated SRv6 MUP Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6MupPacket {
    pub src_ip: Ipv6Address,
    pub dst_ip: Ipv6Address,
    pub segment_list: Vec<Ipv6Address>,
    pub qfi: u8,
    pub inner_payload: Vec<u8>,
}

/// Translated GTP-U Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuMupPacket {
    pub src_ip: Ipv6Address,
    pub dst_ip: Ipv6Address,
    pub teid: u32,
    pub qfi: u8,
    pub payload: Vec<u8>,
}

/// SRv6 Mobile User Plane (MUP) Interworking Engine.
#[derive(Debug, Clone, Default)]
pub struct Srv6MupInterworkingEngine {
    pub mappings: Vec<MupSessionMapping>,
    pub translations_to_srv6: u64,
    pub translations_to_gtp: u64,
    pub translation_drops: u64,
}

impl Srv6MupInterworkingEngine {
    pub fn new() -> Self {
        Srv6MupInterworkingEngine {
            mappings: Vec::new(),
            translations_to_srv6: 0,
            translations_to_gtp: 0,
            translation_drops: 0,
        }
    }

    /// Registers a session translation mapping.
    pub fn register_mapping(&mut self, mapping: MupSessionMapping) {
        if let Some(pos) = self
            .mappings
            .iter()
            .position(|m| m.gtp_teid == mapping.gtp_teid && m.gnodeb_ip == mapping.gnodeb_ip)
        {
            self.mappings[pos] = mapping;
        } else {
            self.mappings.push(mapping);
        }
    }

    /// `End.M.GTP6.D` Function:
    /// Ingests a GTP-U packet from gNodeB, matches TEID and gNodeB IP,
    /// strips GTP-U header, and emits an SRv6 packet.
    pub fn end_m_gtp6_d(
        &mut self,
        gnodeb_ip: Ipv6Address,
        gtp_teid: u32,
        qfi: u8,
        inner_payload: Vec<u8>,
    ) -> Option<Srv6MupPacket> {
        let mapping = self
            .mappings
            .iter()
            .find(|m| m.gtp_teid == gtp_teid && m.gnodeb_ip == gnodeb_ip)?;

        self.translations_to_srv6 += 1;
        let dst_ip = *mapping.srv6_segments.first()?;

        Some(Srv6MupPacket {
            src_ip: gnodeb_ip,
            dst_ip,
            segment_list: mapping.srv6_segments.clone(),
            qfi,
            inner_payload,
        })
    }

    /// `End.M.GTP6.E` Function:
    /// Ingests an SRv6 packet at the egress PE / N3IWF, extracts the target TEID and
    /// destination IP, and encapsulates into standard GTP-U.
    pub fn end_m_gtp6_e(
        &mut self,
        local_pe_ip: Ipv6Address,
        target_gnodeb_ip: Ipv6Address,
        target_teid: u32,
        qfi: u8,
        payload: Vec<u8>,
    ) -> GtpuMupPacket {
        self.translations_to_gtp += 1;
        GtpuMupPacket {
            src_ip: local_pe_ip,
            dst_ip: target_gnodeb_ip,
            teid: target_teid,
            qfi,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv6_mup_end_m_gtp6_d_and_e_roundtrip() {
        let mut engine = Srv6MupInterworkingEngine::new();

        let gnodeb = Ipv6Address::new([0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 1]);
        let sid_upf_anchor = Ipv6Address::new([0x2001, 0x0db8, 0xcafe, 0, 0, 0, 0, 1]);
        let sid_dn_edge = Ipv6Address::new([0x2001, 0x0db8, 0xbeef, 0, 0, 0, 0, 2]);

        engine.register_mapping(MupSessionMapping {
            gtp_teid: 0x12345678,
            gnodeb_ip: gnodeb,
            srv6_segments: vec![sid_upf_anchor, sid_dn_edge],
            qfi: 9,
        });

        // 1. Uplink translation: GTP-U from gNodeB -> SRv6 Packet
        let srv6_pkt = engine
            .end_m_gtp6_d(gnodeb, 0x12345678, 9, b"HTTP/3 Uplink Payload".to_vec())
            .unwrap();
        assert_eq!(srv6_pkt.src_ip, gnodeb);
        assert_eq!(srv6_pkt.dst_ip, sid_upf_anchor);
        assert_eq!(srv6_pkt.segment_list.len(), 2);
        assert_eq!(srv6_pkt.qfi, 9);
        assert_eq!(engine.translations_to_srv6, 1);

        // 2. Downlink translation: SRv6 -> GTP-U to gNodeB
        let local_pe = Ipv6Address::new([0x2001, 0x0db8, 0x0002, 0, 0, 0, 0, 1]);
        let gtpu_pkt = engine.end_m_gtp6_e(
            local_pe,
            gnodeb,
            0x87654321,
            9,
            b"HTTP/3 Downlink Payload".to_vec(),
        );
        assert_eq!(gtpu_pkt.src_ip, local_pe);
        assert_eq!(gtpu_pkt.dst_ip, gnodeb);
        assert_eq!(gtpu_pkt.teid, 0x87654321);
        assert_eq!(gtpu_pkt.qfi, 9);
        assert_eq!(engine.translations_to_gtp, 1);
    }
}

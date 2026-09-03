//! Deterministic IP DetNet-to-TSN Sub-Network Mapping & Stream Interworking (RFC 9024 / RFC 9025 / IEEE 802.1CB).
//!
//! Implements interworking between DetNet IP Service Sub-layer (RFC 8939 / RFC 8964)
//! and IEEE 802.1 TSN Ethernet Data-Link sub-networks (802.1CB FRER, 802.1Qbv TAS).

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

/// IEEE 802.1CB EtherType for Redundancy Tag (R-TAG).
pub const ETHERTYPE_DETNET_RTAG: u16 = 0xF1C1;

/// IEEE 802.1Q VLAN EtherType.
pub const ETHERTYPE_DETNET_8021Q: u16 = 0x8100;

/// 64-bit IEEE 802.1 TSN Stream Identifier (IEEE 802.1CB Clause 9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TsnStreamId(pub [u8; 8]);

impl TsnStreamId {
    pub fn new(mac: MacAddress, stream_unique_id: u16) -> Self {
        let mut bytes = [0u8; 8];
        bytes[0..6].copy_from_slice(&mac.0);
        bytes[6..8].copy_from_slice(&stream_unique_id.to_be_bytes());
        TsnStreamId(bytes)
    }
}

/// DetNet IP Flow Identifier (5-Tuple + DSCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DetNetIpFlowKey {
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub dscp: u8,
}

/// TSN Stream Encapsulation Profile for bridging over a TSN Data-Link sub-network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsnStreamProfile {
    pub stream_id: TsnStreamId,
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub vlan_id: u16, // 12-bit VID (1..4094)
    pub pcp: u8,      // 3-bit Priority Code Point (0..7)
    pub queue_id: u8, // 802.1Qbv TAS Queue (0..7)
}

/// IEEE 802.1CB R-TAG for DetNet Sub-networks (6 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetNetRTagHeader {
    pub sequence_number: u16,
}

impl DetNetRTagHeader {
    pub fn new(seq: u16) -> Self {
        DetNetRTagHeader {
            sequence_number: seq,
        }
    }

    pub fn serialize(&self) -> [u8; 6] {
        let mut buf = [0u8; 6];
        buf[0..2].copy_from_slice(&ETHERTYPE_DETNET_RTAG.to_be_bytes());
        buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // Reserved 2 bytes
        buf[4..6].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 6 {
            return None;
        }
        let ethertype = u16::from_be_bytes([buf[0], buf[1]]);
        if ethertype != ETHERTYPE_DETNET_RTAG {
            return None;
        }
        let seq = u16::from_be_bytes([buf[4], buf[5]]);
        Some(DetNetRTagHeader {
            sequence_number: seq,
        })
    }
}

/// Forwarding verdict from DetNet to TSN Gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetNetTsnForwardResult {
    EncapsulatedTsnFrame {
        stream_id: TsnStreamId,
        vlan_id: u16,
        pcp: u8,
        queue_id: u8,
        frame: Vec<u8>,
    },
    DecapsulatedIpPacket {
        stream_id: TsnStreamId,
        packet: Vec<u8>,
    },
    DuplicateDropped {
        stream_id: TsnStreamId,
        seq: u16,
    },
    NoStreamMatch,
    InvalidFrame(String),
}

/// DetNet-over-TSN Sub-Network Gateway (RFC 9024 / RFC 9025).
#[derive(Debug, Clone, Default)]
pub struct DetNetTsnGateway {
    /// Ingress: IP Flow -> TSN Profile
    pub flow_to_tsn: HashMap<DetNetIpFlowKey, TsnStreamProfile>,
    /// Egress: TSN Stream ID -> Sequence history for Elimination (FRER)
    pub frer_history: HashMap<TsnStreamId, u16>,
    /// Next outgoing R-TAG sequence per TSN Stream ID
    pub next_tx_seq: HashMap<TsnStreamId, u16>,
}

impl DetNetTsnGateway {
    pub fn new() -> Self {
        DetNetTsnGateway {
            flow_to_tsn: HashMap::new(),
            frer_history: HashMap::new(),
            next_tx_seq: HashMap::new(),
        }
    }

    pub fn register_flow_mapping(&mut self, flow: DetNetIpFlowKey, profile: TsnStreamProfile) {
        self.flow_to_tsn.insert(flow, profile);
    }

    /// Ingress: Encapsulate DetNet IP packet into TSN 802.1Q + 802.1CB Ethernet frame.
    pub fn encapsulate_ip_to_tsn(&mut self, ip_packet: &[u8]) -> DetNetTsnForwardResult {
        if ip_packet.len() < 20 {
            return DetNetTsnForwardResult::InvalidFrame("IP packet too short".to_string());
        }

        let dscp = ip_packet[1] >> 2;
        let protocol = ip_packet[9];
        let src_ip = Ipv4Address::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
        let dst_ip = Ipv4Address::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

        let (src_port, dst_port) = if (protocol == 6 || protocol == 17) && ip_packet.len() >= 24 {
            let sp = u16::from_be_bytes([ip_packet[20], ip_packet[21]]);
            let dp = u16::from_be_bytes([ip_packet[22], ip_packet[23]]);
            (sp, dp)
        } else {
            (0, 0)
        };

        let key = DetNetIpFlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            dscp,
        };

        let profile = match self.flow_to_tsn.get(&key) {
            Some(p) => p.clone(),
            None => return DetNetTsnForwardResult::NoStreamMatch,
        };

        // Allocate R-TAG Sequence Number
        let seq = self.next_tx_seq.entry(profile.stream_id).or_insert(0);
        let rtag = DetNetRTagHeader::new(*seq);
        *seq = seq.wrapping_add(1);

        // Build Ethernet Frame:
        // [Dst MAC (6)] [Src MAC (6)] [802.1Q (4)] [R-TAG (6)] [EtherType 0x0800 (2)] [IP Packet]
        let mut frame = Vec::with_capacity(14 + 4 + 6 + 2 + ip_packet.len());
        frame.extend_from_slice(&profile.dst_mac.0);
        frame.extend_from_slice(&profile.src_mac.0);

        // 802.1Q Tag: 0x8100 + TCI ((PCP << 13) | VID)
        let tci = ((profile.pcp as u16) << 13) | (profile.vlan_id & 0x0FFF);
        frame.extend_from_slice(&ETHERTYPE_DETNET_8021Q.to_be_bytes());
        frame.extend_from_slice(&tci.to_be_bytes());

        // 802.1CB R-TAG
        frame.extend_from_slice(&rtag.serialize());

        // Inner EtherType IPv4 (0x0800)
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        // Payload
        frame.extend_from_slice(ip_packet);

        DetNetTsnForwardResult::EncapsulatedTsnFrame {
            stream_id: profile.stream_id,
            vlan_id: profile.vlan_id,
            pcp: profile.pcp,
            queue_id: profile.queue_id,
            frame,
        }
    }

    /// Egress: Decapsulate TSN Frame, execute FRER duplicate elimination, and return DetNet IP packet.
    pub fn decapsulate_tsn_to_ip(
        &mut self,
        stream_id: TsnStreamId,
        tsn_frame: &[u8],
    ) -> DetNetTsnForwardResult {
        if tsn_frame.len() < 12 + 4 + 6 + 2 {
            return DetNetTsnForwardResult::InvalidFrame("TSN Frame too short".to_string());
        }

        // Check 802.1Q tag
        let ethertype_q = u16::from_be_bytes([tsn_frame[12], tsn_frame[13]]);
        if ethertype_q != ETHERTYPE_DETNET_8021Q {
            return DetNetTsnForwardResult::InvalidFrame("Missing 802.1Q tag".to_string());
        }

        // Check R-TAG (at offset 16)
        let rtag = match DetNetRTagHeader::parse(&tsn_frame[16..22]) {
            Some(r) => r,
            None => {
                return DetNetTsnForwardResult::InvalidFrame(
                    "Missing or invalid R-TAG".to_string(),
                );
            }
        };

        // FRER Elimination Check: Check if duplicate sequence
        if let Some(last_seq) = self.frer_history.get(&stream_id) {
            if *last_seq == rtag.sequence_number {
                return DetNetTsnForwardResult::DuplicateDropped {
                    stream_id,
                    seq: rtag.sequence_number,
                };
            }
        }
        self.frer_history.insert(stream_id, rtag.sequence_number);

        // Extract IP payload (starts after inner EtherType at offset 24)
        let ip_payload = tsn_frame[24..].to_vec();

        DetNetTsnForwardResult::DecapsulatedIpPacket {
            stream_id,
            packet: ip_payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detnet_tsn_rtag_codec() {
        let rtag = DetNetRTagHeader::new(12345);
        let ser = rtag.serialize();
        assert_eq!(ser.len(), 6);
        let parsed = DetNetRTagHeader::parse(&ser).unwrap();
        assert_eq!(parsed.sequence_number, 12345);
    }

    #[test]
    fn test_detnet_tsn_ingress_encap_and_egress_frer() {
        let mut gateway = DetNetTsnGateway::new();

        let flow_key = DetNetIpFlowKey {
            src_ip: Ipv4Address::new(10, 0, 0, 1),
            dst_ip: Ipv4Address::new(10, 0, 0, 2),
            src_port: 5000,
            dst_port: 6000,
            protocol: 17, // UDP
            dscp: 46,     // EF
        };

        let stream_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let stream_id = TsnStreamId::new(stream_mac, 1);

        let profile = TsnStreamProfile {
            stream_id,
            src_mac: stream_mac,
            dst_mac: MacAddress([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            vlan_id: 100,
            pcp: 6,
            queue_id: 6,
        };

        gateway.register_flow_mapping(flow_key, profile);

        // Construct DetNet IP packet
        let mut ip_pkt = vec![0x45, (46 << 2), 0, 32, 0, 0, 0, 0, 64, 17, 0, 0];
        ip_pkt.extend_from_slice(&[10, 0, 0, 1]); // src
        ip_pkt.extend_from_slice(&[10, 0, 0, 2]); // dst
        ip_pkt.extend_from_slice(&5000u16.to_be_bytes()); // src_port
        ip_pkt.extend_from_slice(&6000u16.to_be_bytes()); // dst_port
        ip_pkt.extend_from_slice(&[0, 12, 0, 0]); // UDP len + csum
        ip_pkt.extend_from_slice(b"DetNetTSN");

        // Ingress Encap
        let encap_res = gateway.encapsulate_ip_to_tsn(&ip_pkt);
        let tsn_frame = match encap_res {
            DetNetTsnForwardResult::EncapsulatedTsnFrame {
                vlan_id,
                pcp,
                queue_id,
                frame,
                ..
            } => {
                assert_eq!(vlan_id, 100);
                assert_eq!(pcp, 6);
                assert_eq!(queue_id, 6);
                frame
            }
            other => panic!("Expected EncapsulatedTsnFrame, got {:?}", other),
        };

        // Egress Decap 1 (First frame admitted)
        let decap_res1 = gateway.decapsulate_tsn_to_ip(stream_id, &tsn_frame);
        match decap_res1 {
            DetNetTsnForwardResult::DecapsulatedIpPacket { packet, .. } => {
                assert_eq!(packet, ip_pkt);
            }
            other => panic!("Expected DecapsulatedIpPacket, got {:?}", other),
        }

        // Egress Decap 2 (Duplicate frame with identical seq dropped by FRER)
        let decap_res2 = gateway.decapsulate_tsn_to_ip(stream_id, &tsn_frame);
        match decap_res2 {
            DetNetTsnForwardResult::DuplicateDropped {
                stream_id: s_id,
                seq,
            } => {
                assert_eq!(s_id, stream_id);
                assert_eq!(seq, 0);
            }
            other => panic!("Expected DuplicateDropped, got {:?}", other),
        }
    }
}

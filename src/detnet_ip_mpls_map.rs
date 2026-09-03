//! Deterministic IP (DetNet) to MPLS Sub-Layer Mapping & Traffic Class Marking (RFC 8964 / RFC 9024).
//!
//! Provides deterministic 5-tuple IP flow classification, DSCP-to-MPLS Traffic Class (TC/EXP) marking,
//! S-Label/F-Label dual-tier encapsulation with 4-byte d-CW, and egress decapsulation.

use crate::detnet_mpls_cw::DetNetMplsControlWord;
use crate::ipv4::Ipv4Address;
use std::collections::{HashMap, HashSet};

/// 5-Tuple IP Flow Classifier Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DetNetIpFlowKey {
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

impl DetNetIpFlowKey {
    pub fn parse_ipv4_packet(packet: &[u8]) -> Option<(Self, u8)> {
        if packet.len() < 20 {
            return None;
        }
        let version = packet[0] >> 4;
        if version != 4 {
            return None;
        }
        let ihl = (packet[0] & 0x0F) as usize * 4;
        if packet.len() < ihl {
            return None;
        }

        let dscp = packet[1] >> 2;
        let protocol = packet[9];
        let src_ip = Ipv4Address::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Address::new(packet[16], packet[17], packet[18], packet[19]);

        let (src_port, dst_port) = if (protocol == 6 || protocol == 17) && packet.len() >= ihl + 4 {
            let sp = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dp = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            (sp, dp)
        } else {
            (0, 0)
        };

        Some((
            DetNetIpFlowKey {
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
            },
            dscp,
        ))
    }
}

/// Disjoint Forwarding Path for DetNet Packet Replication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetNetFLabelPath {
    pub f_label: u32,
    pub traffic_class: u8, // 3-bit TC / EXP
    pub ttl: u8,
    pub out_if: String,
}

/// Configuration profile mapping an IP micro-flow to DetNet MPLS transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetNetIpMplsFlowProfile {
    pub flow_id: u32,
    pub flow_key: DetNetIpFlowKey,
    pub s_label: u32, // 20-bit DetNet Service Label
    pub s_tc: u8,     // 3-bit Service TC / EXP
    pub f_paths: Vec<DetNetFLabelPath>,
}

/// Result of ingress DetNet IP-to-MPLS mapping & replication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetNetIpMplsIngressResult {
    /// Successfully encapsulated into replicated MPLS packets across paths
    Replicated {
        flow_id: u32,
        seq: u16,
        mpls_packets: Vec<(String, Vec<u8>)>, // (out_if, raw_mpls_frame)
    },
    /// No matching DetNet profile for this IP flow
    NoMatchingProfile,
    /// Malformed IP packet
    InvalidIpPacket,
}

/// Result of egress DetNet MPLS-to-IP decapsulation & deduplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetNetIpMplsEgressResult {
    /// Accepted unique IP packet after peeling labels and verifying d-CW
    AcceptedUnique {
        s_label: u32,
        seq: u16,
        ip_packet: Vec<u8>,
    },
    /// Dropped duplicate sequence packet
    DuplicateDropped { s_label: u32, seq: u16 },
    /// Malformed MPLS or d-CW packet
    InvalidMplsPacket(String),
}

/// Complete DetNet IP-to-MPLS Interworking Engine.
#[derive(Debug, Clone, Default)]
pub struct DetNetIpMplsEngine {
    /// Registered IP flow profiles indexed by flow key
    pub flow_profiles: HashMap<DetNetIpFlowKey, DetNetIpMplsFlowProfile>,
    /// Flow ID -> Next outgoing sequence number
    pub tx_sequences: HashMap<u32, u16>,
    /// S-Label -> Deduplication history of received sequence numbers
    pub pef_history: HashMap<u32, HashSet<u16>>,
}

impl DetNetIpMplsEngine {
    pub fn new() -> Self {
        Self {
            flow_profiles: HashMap::new(),
            tx_sequences: HashMap::new(),
            pef_history: HashMap::new(),
        }
    }

    pub fn register_profile(&mut self, profile: DetNetIpMplsFlowProfile) {
        self.flow_profiles.insert(profile.flow_key, profile);
    }

    /// Maps DSCP (6-bit) to MPLS Traffic Class (3-bit EXP) per RFC 3270 / RFC 9024.
    pub fn dscp_to_mpls_tc(dscp: u8) -> u8 {
        dscp >> 3
    }

    /// Ingress: Classifies raw IP packet, assigns d-CW sequence, builds dual-tier MPLS stack,
    /// and replicates across disjoint paths.
    pub fn ingress_encap(&mut self, ip_packet: &[u8]) -> DetNetIpMplsIngressResult {
        let (flow_key, dscp) = match DetNetIpFlowKey::parse_ipv4_packet(ip_packet) {
            Some(res) => res,
            None => return DetNetIpMplsIngressResult::InvalidIpPacket,
        };

        let profile = match self.flow_profiles.get(&flow_key) {
            Some(p) => p.clone(),
            None => return DetNetIpMplsIngressResult::NoMatchingProfile,
        };

        let seq_entry = self.tx_sequences.entry(profile.flow_id).or_insert(0);
        let seq = *seq_entry;
        *seq_entry = seq_entry.wrapping_add(1);

        let dcw = DetNetMplsControlWord::new(seq);
        let dcw_bytes = dcw.serialize();

        // S-Label (Service Label, Bottom of Stack S = 1)
        // 20-bit Label | 3-bit TC | 1-bit S (1) | 8-bit TTL (64)
        let s_tc = if profile.s_tc > 0 {
            profile.s_tc
        } else {
            Self::dscp_to_mpls_tc(dscp)
        };
        let s_shim = ((profile.s_label & 0xFFFFF) << 12)
            | (((s_tc & 0x07) as u32) << 9)
            | (1 << 8) // S = 1 (Bottom of stack)
            | 64; // TTL = 64
        let s_shim_bytes = s_shim.to_be_bytes();

        let mut mpls_packets = Vec::new();

        for path in &profile.f_paths {
            let mut frame = Vec::with_capacity(8 + 4 + ip_packet.len());

            // Outer F-Label (Forwarding Label, S = 0)
            let f_tc = if path.traffic_class > 0 {
                path.traffic_class
            } else {
                Self::dscp_to_mpls_tc(dscp)
            };
            let f_shim = ((path.f_label & 0xFFFFF) << 12)
                | (((f_tc & 0x07) as u32) << 9)
                | (0 << 8) // S = 0 (Not bottom of stack)
                | (path.ttl as u32);
            frame.extend_from_slice(&f_shim.to_be_bytes());

            // Inner S-Label
            frame.extend_from_slice(&s_shim_bytes);

            // 4-byte d-CW
            frame.extend_from_slice(&dcw_bytes);

            // Original IP payload
            frame.extend_from_slice(ip_packet);

            mpls_packets.push((path.out_if.clone(), frame));
        }

        DetNetIpMplsIngressResult::Replicated {
            flow_id: profile.flow_id,
            seq,
            mpls_packets,
        }
    }

    /// Egress: Strips outer F-Label, pops inner S-Label, inspects d-CW, eliminates duplicates (PEF),
    /// and returns the recovered IP packet.
    pub fn egress_decap(&mut self, mpls_frame: &[u8]) -> DetNetIpMplsEgressResult {
        // Minimum: [F-Label (4B)] [S-Label (4B)] [d-CW (4B)] [IP Header (20B)] = 32B
        if mpls_frame.len() < 32 {
            return DetNetIpMplsEgressResult::InvalidMplsPacket("MPLS frame too short".to_string());
        }

        let mut offset = 0;
        let mut f_labels = Vec::new();

        // Parse label stack until S=1
        loop {
            if offset + 4 > mpls_frame.len() {
                return DetNetIpMplsEgressResult::InvalidMplsPacket(
                    "Incomplete label stack".to_string(),
                );
            }
            let label_raw = u32::from_be_bytes([
                mpls_frame[offset],
                mpls_frame[offset + 1],
                mpls_frame[offset + 2],
                mpls_frame[offset + 3],
            ]);
            let label_val = label_raw >> 12;
            let bos = (label_raw >> 8) & 0x01;
            offset += 4;

            if bos == 1 {
                // This is the S-Label (Bottom of stack)
                let s_label = label_val;

                // Next 4 bytes MUST be d-CW
                if offset + 4 > mpls_frame.len() {
                    return DetNetIpMplsEgressResult::InvalidMplsPacket("Missing d-CW".to_string());
                }
                let dcw = match DetNetMplsControlWord::parse(&mpls_frame[offset..offset + 4]) {
                    Some(cw) => cw,
                    None => {
                        return DetNetIpMplsEgressResult::InvalidMplsPacket(
                            "Invalid d-CW (nibble != 0)".to_string(),
                        );
                    }
                };
                offset += 4;

                // PEF Elimination check
                let history = self.pef_history.entry(s_label).or_default();
                if history.contains(&dcw.sequence_number) {
                    return DetNetIpMplsEgressResult::DuplicateDropped {
                        s_label,
                        seq: dcw.sequence_number,
                    };
                }

                history.insert(dcw.sequence_number);
                if history.len() > 10_000 {
                    history.clear();
                    history.insert(dcw.sequence_number);
                }

                let ip_packet = mpls_frame[offset..].to_vec();
                return DetNetIpMplsEgressResult::AcceptedUnique {
                    s_label,
                    seq: dcw.sequence_number,
                    ip_packet,
                };
            } else {
                f_labels.push(label_val);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detnet_ip_to_mpls_mapping_and_failover() {
        let mut engine = DetNetIpMplsEngine::new();

        let flow_key = DetNetIpFlowKey {
            src_ip: Ipv4Address::new(192, 168, 1, 10),
            dst_ip: Ipv4Address::new(10, 0, 0, 50),
            protocol: 17, // UDP
            src_port: 8000,
            dst_port: 8000,
        };

        engine.register_profile(DetNetIpMplsFlowProfile {
            flow_id: 1,
            flow_key,
            s_label: 4000,
            s_tc: 5,
            f_paths: vec![
                DetNetFLabelPath {
                    f_label: 101,
                    traffic_class: 5,
                    ttl: 64,
                    out_if: "eth0".to_string(),
                },
                DetNetFLabelPath {
                    f_label: 102,
                    traffic_class: 5,
                    ttl: 64,
                    out_if: "eth1".to_string(),
                },
            ],
        });

        // Build sample IP packet
        let mut ip_pkt = vec![
            0x45, 0xA0, 0x00, 0x20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 168, 1, 10, 10, 0, 0, 50,
        ];
        // UDP ports
        ip_pkt.extend_from_slice(&8000u16.to_be_bytes());
        ip_pkt.extend_from_slice(&8000u16.to_be_bytes());
        ip_pkt.extend_from_slice(&[0, 12, 0, 0]); // UDP len & checksum
        ip_pkt.extend_from_slice(b"DetNetPayload");

        // 1. Ingress Encapsulation & Replication
        let encap = engine.ingress_encap(&ip_pkt);
        let frames = match encap {
            DetNetIpMplsIngressResult::Replicated {
                flow_id,
                seq,
                mpls_packets,
            } => {
                assert_eq!(flow_id, 1);
                assert_eq!(seq, 0);
                assert_eq!(mpls_packets.len(), 2);
                mpls_packets
            }
            other => panic!("Expected Replicated, got {:?}", other),
        };

        // 2. Primary frame arrives at egress
        let decap1 = engine.egress_decap(&frames[0].1);
        match decap1 {
            DetNetIpMplsEgressResult::AcceptedUnique {
                s_label,
                seq,
                ip_packet,
            } => {
                assert_eq!(s_label, 4000);
                assert_eq!(seq, 0);
                assert_eq!(ip_packet, ip_pkt);
            }
            other => panic!("Expected AcceptedUnique for primary frame, got {:?}", other),
        }

        // 3. Duplicate backup frame arrives at egress
        let decap2 = engine.egress_decap(&frames[1].1);
        match decap2 {
            DetNetIpMplsEgressResult::DuplicateDropped { s_label, seq } => {
                assert_eq!(s_label, 4000);
                assert_eq!(seq, 0);
            }
            other => panic!(
                "Expected DuplicateDropped for backup frame, got {:?}",
                other
            ),
        }
    }
}

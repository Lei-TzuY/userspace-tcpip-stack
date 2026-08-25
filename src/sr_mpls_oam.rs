//! Segment Routing MPLS Operations, Administration, and Maintenance (SR-MPLS OAM - RFC 8287 / RFC 8402).
//!
//! Implements Segment Routing LSP Ping and Traceroute with Target FEC Stack Sub-TLVs:
//! - Sub-TLV Type 27: IPv4 Prefix SID
//! - Sub-TLV Type 28: IPv6 Prefix SID
//! - Sub-TLV Type 29: IPv4 Adjacency SID
//! Supports Downstream Detailed Mapping (DDMAP) and SR label stack path validation.

use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

/// SR-MPLS Target FEC Stack Sub-TLV Types (RFC 8287 Section 5).
pub const SR_SUB_TLV_IPV4_PREFIX_SID: u16 = 27;
pub const SR_SUB_TLV_IPV6_PREFIX_SID: u16 = 28;
pub const SR_SUB_TLV_IPV4_ADJ_SID: u16 = 29;

/// MPLS LSP Ping Return Codes (RFC 4379 / RFC 8287).
pub const RETURN_CODE_NO_RETURN_CODE: u8 = 0;
pub const RETURN_CODE_MALFORMED_ECHO_REQUEST: u8 = 1;
pub const RETURN_CODE_ONE_OR_MORE_OF_TLVS_NOT_UNDERSTOOD: u8 = 2;
pub const RETURN_CODE_REPLYING_ROUTER_IS_EGRESS: u8 = 3;
pub const RETURN_CODE_REPLYING_ROUTER_NO_MAPPING: u8 = 4;
pub const RETURN_CODE_LABEL_SWITCHED_AT_STACK_DEPTH: u8 = 8;
pub const RETURN_CODE_LABEL_SWITCHED_UPSTREAM: u8 = 9;

/// Target FEC Stack Sub-TLV for Segment Routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrTargetFecSubTlv {
    /// IPv4 Prefix SID (Sub-TLV Type 27).
    Ipv4PrefixSid {
        prefix: Ipv4Address,
        prefix_len: u8,
        sid_label: u32,
        protocol: u8, // 1 = IS-IS, 2 = OSPFv2, 3 = BGP
    },
    /// IPv4 Adjacency SID (Sub-TLV Type 29).
    Ipv4AdjSid {
        local_ip: Ipv4Address,
        remote_ip: Ipv4Address,
        sid_label: u32,
    },
}

impl SrTargetFecSubTlv {
    pub fn sub_tlv_type(&self) -> u16 {
        match self {
            SrTargetFecSubTlv::Ipv4PrefixSid { .. } => SR_SUB_TLV_IPV4_PREFIX_SID,
            SrTargetFecSubTlv::Ipv4AdjSid { .. } => SR_SUB_TLV_IPV4_ADJ_SID,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            SrTargetFecSubTlv::Ipv4PrefixSid {
                prefix,
                prefix_len,
                sid_label,
                protocol,
            } => {
                buf.extend_from_slice(&SR_SUB_TLV_IPV4_PREFIX_SID.to_be_bytes());
                buf.extend_from_slice(&9u16.to_be_bytes()); // Length: 9 octets
                buf.extend_from_slice(&prefix.0);
                buf.push(*prefix_len);
                buf.extend_from_slice(&sid_label.to_be_bytes()[1..4]); // 3-octet Label
                buf.push(*protocol);
            }
            SrTargetFecSubTlv::Ipv4AdjSid {
                local_ip,
                remote_ip,
                sid_label,
            } => {
                buf.extend_from_slice(&SR_SUB_TLV_IPV4_ADJ_SID.to_be_bytes());
                buf.extend_from_slice(&11u16.to_be_bytes()); // Length: 11 octets
                buf.extend_from_slice(&local_ip.0);
                buf.extend_from_slice(&remote_ip.0);
                buf.extend_from_slice(&sid_label.to_be_bytes()[1..4]); // 3-octet Label
            }
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let tlv_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + length {
            return None;
        }

        let body = &data[4..4 + length];
        let total_consumed = 4 + length;

        match tlv_type {
            SR_SUB_TLV_IPV4_PREFIX_SID => {
                if length < 9 {
                    return None;
                }
                let prefix = Ipv4Address::new(body[0], body[1], body[2], body[3]);
                let prefix_len = body[4];
                let sid_label = u32::from_be_bytes([0, body[5], body[6], body[7]]);
                let protocol = body[8];
                Some((
                    SrTargetFecSubTlv::Ipv4PrefixSid {
                        prefix,
                        prefix_len,
                        sid_label,
                        protocol,
                    },
                    total_consumed,
                ))
            }
            SR_SUB_TLV_IPV4_ADJ_SID => {
                if length < 11 {
                    return None;
                }
                let local_ip = Ipv4Address::new(body[0], body[1], body[2], body[3]);
                let remote_ip = Ipv4Address::new(body[4], body[5], body[6], body[7]);
                let sid_label = u32::from_be_bytes([0, body[8], body[9], body[10]]);
                Some((
                    SrTargetFecSubTlv::Ipv4AdjSid {
                        local_ip,
                        remote_ip,
                        sid_label,
                    },
                    total_consumed,
                ))
            }
            _ => None,
        }
    }
}

/// SR LSP Echo Request packet (RFC 8287 / RFC 4379).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrLspEchoRequest {
    pub sender_handle: u32,
    pub seq_number: u32,
    pub target_fec: SrTargetFecSubTlv,
}

/// SR LSP Echo Reply packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrLspEchoReply {
    pub sender_handle: u32,
    pub seq_number: u32,
    pub return_code: u8,
    pub return_subcode: u8,
}

/// Segment Routing MPLS OAM Engine.
#[derive(Debug, Clone, Default)]
pub struct SrMplsOamEngine {
    pub local_ip: Ipv4Address,
    pub local_prefix_sids: HashMap<Ipv4Address, u32>, // Prefix -> Node SID Label
    pub local_adj_sids: HashMap<u32, (Ipv4Address, Ipv4Address)>, // Adj SID Label -> (Local, Remote)
}

impl SrMplsOamEngine {
    pub fn new(local_ip: Ipv4Address) -> Self {
        SrMplsOamEngine {
            local_ip,
            local_prefix_sids: HashMap::new(),
            local_adj_sids: HashMap::new(),
        }
    }

    /// Registers a local Node Prefix SID.
    pub fn register_prefix_sid(&mut self, prefix: Ipv4Address, sid_label: u32) {
        self.local_prefix_sids.insert(prefix, sid_label);
    }

    /// Registers a local Adjacency SID.
    pub fn register_adj_sid(&mut self, sid_label: u32, local: Ipv4Address, remote: Ipv4Address) {
        self.local_adj_sids.insert(sid_label, (local, remote));
    }

    /// Evaluates an incoming SR LSP Echo Request against local Segment Routing state.
    pub fn process_echo_request(&self, req: &SrLspEchoRequest) -> SrLspEchoReply {
        let return_code = match &req.target_fec {
            SrTargetFecSubTlv::Ipv4PrefixSid {
                prefix,
                sid_label,
                ..
            } => {
                if let Some(registered_label) = self.local_prefix_sids.get(prefix) {
                    if registered_label == sid_label {
                        if *prefix == self.local_ip {
                            RETURN_CODE_REPLYING_ROUTER_IS_EGRESS
                        } else {
                            RETURN_CODE_LABEL_SWITCHED_AT_STACK_DEPTH
                        }
                    } else {
                        RETURN_CODE_REPLYING_ROUTER_NO_MAPPING
                    }
                } else {
                    RETURN_CODE_REPLYING_ROUTER_NO_MAPPING
                }
            }
            SrTargetFecSubTlv::Ipv4AdjSid {
                local_ip,
                remote_ip,
                sid_label,
            } => {
                if let Some((loc, rem)) = self.local_adj_sids.get(sid_label) {
                    if loc == local_ip && rem == remote_ip {
                        RETURN_CODE_LABEL_SWITCHED_AT_STACK_DEPTH
                    } else {
                        RETURN_CODE_REPLYING_ROUTER_NO_MAPPING
                    }
                } else {
                    RETURN_CODE_REPLYING_ROUTER_NO_MAPPING
                }
            }
        };

        SrLspEchoReply {
            sender_handle: req.sender_handle,
            seq_number: req.seq_number,
            return_code,
            return_subcode: 0,
        }
    }
}

//! Segment Routing over IPv6 (SRv6) Network Programming & Endpoint Behaviors (RFC 8986).
//!
//! Implements SRv6 Endpoint execution functions: End, End.X, End.DX4, End.DX6, End.DT4, End.DT6, and End.DX2.

use crate::ipv6::Ipv6Address;
use crate::srv6::Srv6Header;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Srv6Behavior {
    /// End: Standard SRv6 Transit Segment (Updates DA to next SID and forwards)
    End,
    /// End.X: Endpoint with Layer-3 Adjacency Cross-Connect
    EndX {
        next_hop_ip: Ipv6Address,
        out_if: String,
    },
    /// End.DX4: Decapsulate outer IPv6 header and forward inner IPv4 packet to next-hop
    EndDx4 {
        next_hop_ipv4: crate::ipv4::Ipv4Address,
    },
    /// End.DX6: Decapsulate outer IPv6 header and forward inner IPv6 packet to next-hop
    EndDx6 { next_hop_ipv6: Ipv6Address },
    /// End.DT4: Decapsulate outer IPv6 header and lookup inner IPv4 in VRF table
    EndDt4 { vrf_id: u32 },
    /// End.DT6: Decapsulate outer IPv6 header and lookup inner IPv6 in VRF table
    EndDt6 { vrf_id: u32 },
    /// End.DT46: Decapsulate outer IPv6 header and lookup inner IPv4 or IPv6 in VRF table (RFC 8986)
    EndDt46 { vrf_id: u32 },
    /// End.DX2: Decapsulate outer IPv6 header and forward inner Layer-2 Ethernet frame
    EndDx2 { out_if: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Srv6ExecutionResult {
    ForwardNextSid {
        next_sid: Ipv6Address,
        updated_srh: Srv6Header,
    },
    ForwardAdjacency {
        next_sid: Ipv6Address,
        next_hop: Ipv6Address,
        out_if: String,
    },
    DecapIpv4 {
        vrf_id: Option<u32>,
        payload: Vec<u8>,
    },
    DecapIpv6 {
        vrf_id: Option<u32>,
        payload: Vec<u8>,
    },
    DecapEthernet {
        out_if: String,
        frame: Vec<u8>,
    },
    EgressComplete {
        payload: Vec<u8>,
    },
    Drop(String),
}

#[derive(Debug, Clone, Default)]
pub struct Srv6Engine {
    /// My-SID Table: Map Local SID -> Srv6Behavior
    pub my_sid_table: HashMap<Ipv6Address, Srv6Behavior>,
}

impl Srv6Engine {
    pub fn new() -> Self {
        Srv6Engine {
            my_sid_table: HashMap::new(),
        }
    }

    pub fn register_sid(&mut self, sid: Ipv6Address, behavior: Srv6Behavior) {
        self.my_sid_table.insert(sid, behavior);
    }

    pub fn process_srv6_packet(
        &self,
        current_dst_ip: Ipv6Address,
        mut srh: Srv6Header,
        inner_payload: &[u8],
    ) -> Srv6ExecutionResult {
        if let Some(behavior) = self.my_sid_table.get(&current_dst_ip) {
            match behavior {
                Srv6Behavior::End => {
                    if srh.segments_left == 0 {
                        return Srv6ExecutionResult::EgressComplete {
                            payload: inner_payload.to_vec(),
                        };
                    }
                    srh.segments_left -= 1;
                    let next_idx = srh.segments_left as usize;
                    if next_idx >= srh.segment_list.len() {
                        return Srv6ExecutionResult::Drop(
                            "Segments left out of bounds".to_string(),
                        );
                    }
                    let next_sid = srh.segment_list[next_idx];
                    Srv6ExecutionResult::ForwardNextSid {
                        next_sid,
                        updated_srh: srh,
                    }
                }
                Srv6Behavior::EndX {
                    next_hop_ip,
                    out_if,
                } => {
                    if srh.segments_left > 0 {
                        srh.segments_left -= 1;
                        let next_idx = srh.segments_left as usize;
                        let next_sid = srh.segment_list[next_idx];
                        Srv6ExecutionResult::ForwardAdjacency {
                            next_sid,
                            next_hop: *next_hop_ip,
                            out_if: out_if.clone(),
                        }
                    } else {
                        Srv6ExecutionResult::EgressComplete {
                            payload: inner_payload.to_vec(),
                        }
                    }
                }
                Srv6Behavior::EndDx4 { .. } => {
                    // Decapsulate outer IPv6 header, inner payload is IPv4
                    Srv6ExecutionResult::DecapIpv4 {
                        vrf_id: None,
                        payload: inner_payload.to_vec(),
                    }
                }
                Srv6Behavior::EndDx6 { .. } => Srv6ExecutionResult::DecapIpv6 {
                    vrf_id: None,
                    payload: inner_payload.to_vec(),
                },
                Srv6Behavior::EndDt4 { vrf_id } => Srv6ExecutionResult::DecapIpv4 {
                    vrf_id: Some(*vrf_id),
                    payload: inner_payload.to_vec(),
                },
                Srv6Behavior::EndDt6 { vrf_id } => {
                    if !inner_payload.is_empty() {
                        let version = inner_payload[0] >> 4;
                        if version == 6 {
                            Srv6ExecutionResult::DecapIpv6 {
                                vrf_id: Some(*vrf_id),
                                payload: inner_payload.to_vec(),
                            }
                        } else {
                            Srv6ExecutionResult::Drop("End.DT6: Non-IPv6 inner payload".to_string())
                        }
                    } else {
                        Srv6ExecutionResult::Drop("End.DT6: Empty payload".to_string())
                    }
                }
                Srv6Behavior::EndDt46 { vrf_id } => {
                    if !inner_payload.is_empty() {
                        let version = inner_payload[0] >> 4;
                        if version == 4 {
                            Srv6ExecutionResult::DecapIpv4 {
                                vrf_id: Some(*vrf_id),
                                payload: inner_payload.to_vec(),
                            }
                        } else if version == 6 {
                            Srv6ExecutionResult::DecapIpv6 {
                                vrf_id: Some(*vrf_id),
                                payload: inner_payload.to_vec(),
                            }
                        } else {
                            Srv6ExecutionResult::Drop(
                                "End.DT46: Unknown inner IP version".to_string(),
                            )
                        }
                    } else {
                        Srv6ExecutionResult::Drop("End.DT46: Empty payload".to_string())
                    }
                }
                Srv6Behavior::EndDx2 { out_if } => Srv6ExecutionResult::DecapEthernet {
                    out_if: out_if.clone(),
                    frame: inner_payload.to_vec(),
                },
            }
        } else {
            Srv6ExecutionResult::Drop("SID not in My-SID Table".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_srv6_end_and_end_dt4_behaviors() {
        let mut engine = Srv6Engine::new();

        let sid_transit = Ipv6Address::from_str("2001:db8:1::100").unwrap();
        let sid_egress = Ipv6Address::from_str("2001:db8:2::200").unwrap();

        engine.register_sid(sid_transit, Srv6Behavior::End);
        engine.register_sid(sid_egress, Srv6Behavior::EndDt4 { vrf_id: 10 });

        // Packet at Transit Node with Segments Left = 1
        let srh = Srv6Header::build(4, &[sid_egress, sid_transit]); // list = [sid_egress, sid_transit], SegmentsLeft=1
        let res1 = engine.process_srv6_packet(sid_transit, srh, b"Inner Payload");

        match res1 {
            Srv6ExecutionResult::ForwardNextSid {
                next_sid,
                updated_srh,
            } => {
                assert_eq!(next_sid, sid_egress);
                assert_eq!(updated_srh.segments_left, 0);
            }
            _ => panic!("Expected ForwardNextSid"),
        }

        // Packet at Egress Node (End.DT4)
        let srh_egress = Srv6Header::build(4, &[sid_egress]);
        let res2 = engine.process_srv6_packet(sid_egress, srh_egress, b"IPv4 Customer Packet");
        match res2 {
            Srv6ExecutionResult::DecapIpv4 { vrf_id, payload } => {
                assert_eq!(vrf_id, Some(10));
                assert_eq!(payload, b"IPv4 Customer Packet");
            }
            _ => panic!("Expected DecapIpv4 with VRF 10"),
        }
    }
}

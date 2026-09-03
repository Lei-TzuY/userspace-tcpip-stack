//! SRv6 End.DT6 IPv6-Only Multi-VRF Routing Behavior & FIB Forwarding (RFC 8986 §4.14).
//!
//! Provides dedicated decapsulation of outer IPv6/SRH headers, strict inner IPv6 validation,
//! and Longest Prefix Match (LPM) forwarding within isolated tenant IPv6 VRF tables.

use crate::ipv6::Ipv6Address;
use crate::srv6_ops::{Srv6Behavior, Srv6Engine, Srv6ExecutionResult};
use std::collections::HashMap;

/// An IPv6 routing table entry in a specific VRF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6VrfRoute {
    pub prefix: Ipv6Address,
    pub prefix_len: u8,
    pub next_hop: Option<Ipv6Address>,
    pub out_if: String,
}

impl Ipv6VrfRoute {
    pub fn matches(&self, dest: &Ipv6Address) -> bool {
        let prefix_bytes = &self.prefix.0;
        let dest_bytes = &dest.0;

        let full_bytes = (self.prefix_len / 8) as usize;
        let rem_bits = self.prefix_len % 8;

        if prefix_bytes[..full_bytes] != dest_bytes[..full_bytes] {
            return false;
        }

        if rem_bits > 0 {
            let mask = !((1u8 << (8 - rem_bits)) - 1);
            if (prefix_bytes[full_bytes] & mask) != (dest_bytes[full_bytes] & mask) {
                return false;
            }
        }

        true
    }
}

/// Result of End.DT6 processing and customer VRF lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndDt6ForwardVerdict {
    /// Successfully decapsulated and routed to customer interface
    ForwardCustomer {
        vrf_id: u32,
        dst_ip: Ipv6Address,
        next_hop: Option<Ipv6Address>,
        out_if: String,
        packet: Vec<u8>,
    },
    /// Route lookup in the VRF failed (no matching route)
    NoRoute { vrf_id: u32, dst_ip: Ipv6Address },
    /// Inner packet is not IPv6
    NonIpv6PayloadDropped,
    /// Packet dropped due to malformed header or invalid SID
    Drop(String),
}

/// Multi-VRF IPv6 Router with SRv6 End.DT6 Endpoint execution.
#[derive(Debug, Clone, Default)]
pub struct Srv6EndDt6Router {
    /// Underlying SRv6 Endpoint Behavior Engine
    pub srv6_engine: Srv6Engine,
    /// VRF ID -> List of IPv6 routes
    pub vrf_tables: HashMap<u32, Vec<Ipv6VrfRoute>>,
}

impl Srv6EndDt6Router {
    pub fn new() -> Self {
        Self {
            srv6_engine: Srv6Engine::new(),
            vrf_tables: HashMap::new(),
        }
    }

    /// Registers a local SID with End.DT6 behavior bound to a specific VRF.
    pub fn register_end_dt6_sid(&mut self, sid: Ipv6Address, vrf_id: u32) {
        self.srv6_engine
            .register_sid(sid, Srv6Behavior::EndDt6 { vrf_id });
    }

    /// Adds an IPv6 route to a specific VRF routing table.
    pub fn add_vrf_route(&mut self, vrf_id: u32, route: Ipv6VrfRoute) {
        let table = self.vrf_tables.entry(vrf_id).or_default();
        table.push(route);
        // Sort descending by prefix length for LPM lookup
        table.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    /// Processes an incoming SRv6 packet at the egress PE node with End.DT6 decapsulation & VRF forwarding.
    pub fn process_end_dt6_packet(
        &self,
        current_dst_ip: Ipv6Address,
        srh: crate::srv6::Srv6Header,
        inner_payload: &[u8],
    ) -> EndDt6ForwardVerdict {
        let exec_res = self
            .srv6_engine
            .process_srv6_packet(current_dst_ip, srh, inner_payload);

        match exec_res {
            Srv6ExecutionResult::DecapIpv6 { vrf_id, payload } => {
                let vrf = match vrf_id {
                    Some(v) => v,
                    None => {
                        return EndDt6ForwardVerdict::Drop(
                            "Missing VRF ID for End.DT6".to_string(),
                        );
                    }
                };

                if payload.len() < 40 {
                    return EndDt6ForwardVerdict::Drop(
                        "Inner IPv6 packet too short (<40 bytes)".to_string(),
                    );
                }

                // Extract Destination IPv6 from inner header (bytes 24..40)
                let mut dst_bytes = [0u8; 16];
                dst_bytes.copy_from_slice(&payload[24..40]);
                let dst_ip = Ipv6Address(dst_bytes);

                // Lookup in VRF table
                if let Some(table) = self.vrf_tables.get(&vrf) {
                    for route in table {
                        if route.matches(&dst_ip) {
                            return EndDt6ForwardVerdict::ForwardCustomer {
                                vrf_id: vrf,
                                dst_ip,
                                next_hop: route.next_hop,
                                out_if: route.out_if.clone(),
                                packet: payload,
                            };
                        }
                    }
                }

                EndDt6ForwardVerdict::NoRoute {
                    vrf_id: vrf,
                    dst_ip,
                }
            }
            Srv6ExecutionResult::Drop(msg) => {
                if msg.contains("Non-IPv6") {
                    EndDt6ForwardVerdict::NonIpv6PayloadDropped
                } else {
                    EndDt6ForwardVerdict::Drop(msg)
                }
            }
            other => EndDt6ForwardVerdict::Drop(format!("Unexpected SRv6 result: {:?}", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_srv6_end_dt6_router_lifecycle() {
        let mut router = Srv6EndDt6Router::new();

        let sid_vrf100 = Ipv6Address::from_str("fc00:100::d06").unwrap();
        router.register_end_dt6_sid(sid_vrf100, 100);

        // Add VRF 100 customer route: 2001:db8:beef::/48 -> eth1
        let cust_prefix = Ipv6Address::from_str("2001:db8:beef::").unwrap();
        router.add_vrf_route(
            100,
            Ipv6VrfRoute {
                prefix: cust_prefix,
                prefix_len: 48,
                next_hop: None,
                out_if: "eth_cust100".to_string(),
            },
        );

        // Construct inner customer IPv6 packet targeting 2001:db8:beef::42
        let mut inner_ipv6 = vec![0u8; 40];
        inner_ipv6[0] = 0x60; // Version 6
        let dst_addr = Ipv6Address::from_str("2001:db8:beef::42").unwrap();
        inner_ipv6[24..40].copy_from_slice(&dst_addr.0);
        inner_ipv6.extend_from_slice(b"CustomerDataPayload");

        let srh = crate::srv6::Srv6Header::build(4, &[sid_vrf100]);

        // Process End.DT6
        let verdict = router.process_end_dt6_packet(sid_vrf100, srh, &inner_ipv6);
        match verdict {
            EndDt6ForwardVerdict::ForwardCustomer {
                vrf_id,
                dst_ip,
                out_if,
                packet,
                ..
            } => {
                assert_eq!(vrf_id, 100);
                assert_eq!(dst_ip, dst_addr);
                assert_eq!(out_if, "eth_cust100");
                assert_eq!(packet, inner_ipv6);
            }
            other => panic!("Expected ForwardCustomer, got {:?}", other),
        }
    }

    #[test]
    fn test_srv6_end_dt6_rejects_ipv4_payload() {
        let mut router = Srv6EndDt6Router::new();
        let sid = Ipv6Address::from_str("fc00:200::d06").unwrap();
        router.register_end_dt6_sid(sid, 200);

        // IPv4 packet payload (version 4 -> 0x45)
        let inner_ipv4 = vec![
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let srh = crate::srv6::Srv6Header::build(4, &[sid]);

        let verdict = router.process_end_dt6_packet(sid, srh, &inner_ipv4);
        assert_eq!(verdict, EndDt6ForwardVerdict::NonIpv6PayloadDropped);
    }
}

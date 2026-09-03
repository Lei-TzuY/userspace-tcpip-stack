//! SRv6 End.DT46 Multi-VRF Dual-Stack Routing Engine (RFC 8986 Section 4.15).
//!
//! Implements the End.DT46 endpoint behavior for multi-tenant L3VPNs where a single SID
//! can decapsulate and route both IPv4 and IPv6 inner packets in a designated VRF FIB.

use crate::ipv4::Ipv4Address;
use crate::ipv6::Ipv6Address;
use crate::srv6::Srv6Header;
use crate::srv6_ops::{Srv6Behavior, Srv6Engine, Srv6ExecutionResult};
use std::collections::HashMap;

/// Next-hop forwarding target for a routed packet within a VRF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VrfNextHop {
    DirectLocal {
        out_if: String,
    },
    GatewayIpv4 {
        next_hop: Ipv4Address,
        out_if: String,
    },
    GatewayIpv6 {
        next_hop: Ipv6Address,
        out_if: String,
    },
}

/// Route entry in a dual-stack VRF FIB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfIpv4Route {
    pub prefix: Ipv4Address,
    pub prefix_len: u8,
    pub next_hop: VrfNextHop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfIpv6Route {
    pub prefix: Ipv6Address,
    pub prefix_len: u8,
    pub next_hop: VrfNextHop,
}

/// Dual-Stack VRF FIB containing both IPv4 and IPv6 routing tables.
#[derive(Debug, Clone, Default)]
pub struct VrfDualStackFib {
    pub vrf_id: u32,
    pub ipv4_routes: Vec<VrfIpv4Route>,
    pub ipv6_routes: Vec<VrfIpv6Route>,
}

impl VrfDualStackFib {
    pub fn new(vrf_id: u32) -> Self {
        VrfDualStackFib {
            vrf_id,
            ipv4_routes: Vec::new(),
            ipv6_routes: Vec::new(),
        }
    }

    pub fn add_ipv4_route(&mut self, prefix: Ipv4Address, prefix_len: u8, next_hop: VrfNextHop) {
        self.ipv4_routes
            .retain(|r| !(r.prefix == prefix && r.prefix_len == prefix_len));
        self.ipv4_routes.push(VrfIpv4Route {
            prefix,
            prefix_len,
            next_hop,
        });
        self.ipv4_routes
            .sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    pub fn add_ipv6_route(&mut self, prefix: Ipv6Address, prefix_len: u8, next_hop: VrfNextHop) {
        self.ipv6_routes
            .retain(|r| !(r.prefix == prefix && r.prefix_len == prefix_len));
        self.ipv6_routes.push(VrfIpv6Route {
            prefix,
            prefix_len,
            next_hop,
        });
        self.ipv6_routes
            .sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    pub fn lookup_ipv4(&self, target: &Ipv4Address) -> Option<&VrfNextHop> {
        let target_u32 = u32::from_be_bytes(target.0);
        for route in &self.ipv4_routes {
            if route.prefix_len == 0 {
                return Some(&route.next_hop);
            }
            let mask = if route.prefix_len >= 32 {
                u32::MAX
            } else {
                !((1 << (32 - route.prefix_len)) - 1)
            };
            let prefix_u32 = u32::from_be_bytes(route.prefix.0);
            if (target_u32 & mask) == (prefix_u32 & mask) {
                return Some(&route.next_hop);
            }
        }
        None
    }

    pub fn lookup_ipv6(&self, target: &Ipv6Address) -> Option<&VrfNextHop> {
        let target_u128 = u128::from_be_bytes(target.0);
        for route in &self.ipv6_routes {
            if route.prefix_len == 0 {
                return Some(&route.next_hop);
            }
            let mask = if route.prefix_len >= 128 {
                u128::MAX
            } else {
                !((1 << (128 - route.prefix_len)) - 1)
            };
            let prefix_u128 = u128::from_be_bytes(route.prefix.0);
            if (target_u128 & mask) == (prefix_u128 & mask) {
                return Some(&route.next_hop);
            }
        }
        None
    }
}

/// Forwarding result after processing an SRv6 End.DT46 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndDt46ForwardResult {
    RoutedIpv4 {
        vrf_id: u32,
        dst_ip: Ipv4Address,
        next_hop: VrfNextHop,
        packet: Vec<u8>,
    },
    RoutedIpv6 {
        vrf_id: u32,
        dst_ip: Ipv6Address,
        next_hop: VrfNextHop,
        packet: Vec<u8>,
    },
    NoRoute {
        vrf_id: u32,
        ip_version: u8,
    },
    Dropped(String),
}

/// End.DT46 Multi-VRF Dual-Stack Decapsulation and Forwarding Engine.
#[derive(Debug, Clone, Default)]
pub struct EndDt46Engine {
    pub srv6_engine: Srv6Engine,
    pub vrfs: HashMap<u32, VrfDualStackFib>,
}

impl EndDt46Engine {
    pub fn new() -> Self {
        EndDt46Engine {
            srv6_engine: Srv6Engine::new(),
            vrfs: HashMap::new(),
        }
    }

    /// Provision an End.DT46 SID mapped to a VRF.
    pub fn register_dt46_sid(&mut self, sid: Ipv6Address, vrf_id: u32) {
        self.srv6_engine
            .register_sid(sid, Srv6Behavior::EndDt46 { vrf_id });
        self.vrfs
            .entry(vrf_id)
            .or_insert_with(|| VrfDualStackFib::new(vrf_id));
    }

    /// Access VRF FIB for route provisioning.
    pub fn get_vrf_mut(&mut self, vrf_id: u32) -> &mut VrfDualStackFib {
        self.vrfs
            .entry(vrf_id)
            .or_insert_with(|| VrfDualStackFib::new(vrf_id))
    }

    /// Ingest an incoming SRv6 packet at the egress PE node.
    pub fn process_packet(
        &self,
        active_sid: Ipv6Address,
        srh: Srv6Header,
        inner_payload: &[u8],
    ) -> EndDt46ForwardResult {
        let exec_result = self
            .srv6_engine
            .process_srv6_packet(active_sid, srh, inner_payload);

        match exec_result {
            Srv6ExecutionResult::DecapIpv4 { vrf_id, payload } => {
                let vrf = match vrf_id {
                    Some(id) => id,
                    None => {
                        return EndDt46ForwardResult::Dropped(
                            "No VRF ID associated with End.DT46".to_string(),
                        );
                    }
                };

                if payload.len() < 20 {
                    return EndDt46ForwardResult::Dropped(
                        "Inner IPv4 packet too short".to_string(),
                    );
                }
                let dst_ip = Ipv4Address::new(payload[16], payload[17], payload[18], payload[19]);

                if let Some(vrf_fib) = self.vrfs.get(&vrf) {
                    if let Some(next_hop) = vrf_fib.lookup_ipv4(&dst_ip) {
                        EndDt46ForwardResult::RoutedIpv4 {
                            vrf_id: vrf,
                            dst_ip,
                            next_hop: next_hop.clone(),
                            packet: payload,
                        }
                    } else {
                        EndDt46ForwardResult::NoRoute {
                            vrf_id: vrf,
                            ip_version: 4,
                        }
                    }
                } else {
                    EndDt46ForwardResult::Dropped(format!("VRF {} not configured", vrf))
                }
            }
            Srv6ExecutionResult::DecapIpv6 { vrf_id, payload } => {
                let vrf = match vrf_id {
                    Some(id) => id,
                    None => {
                        return EndDt46ForwardResult::Dropped(
                            "No VRF ID associated with End.DT46".to_string(),
                        );
                    }
                };

                if payload.len() < 40 {
                    return EndDt46ForwardResult::Dropped(
                        "Inner IPv6 packet too short".to_string(),
                    );
                }
                let mut dst_bytes = [0u8; 16];
                dst_bytes.copy_from_slice(&payload[24..40]);
                let dst_ip = Ipv6Address(dst_bytes);

                if let Some(vrf_fib) = self.vrfs.get(&vrf) {
                    if let Some(next_hop) = vrf_fib.lookup_ipv6(&dst_ip) {
                        EndDt46ForwardResult::RoutedIpv6 {
                            vrf_id: vrf,
                            dst_ip,
                            next_hop: next_hop.clone(),
                            packet: payload,
                        }
                    } else {
                        EndDt46ForwardResult::NoRoute {
                            vrf_id: vrf,
                            ip_version: 6,
                        }
                    }
                } else {
                    EndDt46ForwardResult::Dropped(format!("VRF {} not configured", vrf))
                }
            }
            Srv6ExecutionResult::Drop(reason) => EndDt46ForwardResult::Dropped(reason),
            _ => EndDt46ForwardResult::Dropped(
                "Unexpected execution result for End.DT46".to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv6_end_dt46_dual_stack_routing() {
        let mut engine = EndDt46Engine::new();
        let dt46_sid = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x46]);

        engine.register_dt46_sid(dt46_sid, 100);

        // Populate VRF 100 with IPv4 & IPv6 routes
        let vrf = engine.get_vrf_mut(100);
        vrf.add_ipv4_route(
            Ipv4Address::new(10, 20, 0, 0),
            16,
            VrfNextHop::DirectLocal {
                out_if: "eth_v4_cust".to_string(),
            },
        );
        vrf.add_ipv6_route(
            Ipv6Address([
                0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            64,
            VrfNextHop::DirectLocal {
                out_if: "eth_v6_cust".to_string(),
            },
        );

        let srh = Srv6Header::build(41, &[dt46_sid]);

        // 1. Inner IPv4 Packet to 10.20.1.50
        let mut inner_ipv4 = vec![0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 1, 0, 0];
        inner_ipv4.extend_from_slice(&[192, 168, 1, 1]); // src
        inner_ipv4.extend_from_slice(&[10, 20, 1, 50]); // dst
        inner_ipv4.extend_from_slice(b"Dual-Stack IPv4 Data");

        let res_v4 = engine.process_packet(dt46_sid, srh.clone(), &inner_ipv4);
        match res_v4 {
            EndDt46ForwardResult::RoutedIpv4 {
                vrf_id,
                dst_ip,
                next_hop,
                ..
            } => {
                assert_eq!(vrf_id, 100);
                assert_eq!(dst_ip, Ipv4Address::new(10, 20, 1, 50));
                assert_eq!(
                    next_hop,
                    VrfNextHop::DirectLocal {
                        out_if: "eth_v4_cust".to_string()
                    }
                );
            }
            other => panic!("Expected RoutedIpv4, got {:?}", other),
        }

        // 2. Inner IPv6 Packet to 2001:db8:cafe::1
        let mut inner_ipv6 = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x3b, 0x40]; // IPv6 header start
        inner_ipv6.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
        inner_ipv6.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]); // dst
        inner_ipv6.extend_from_slice(b"Dual-Stack IPv6 Data");

        let res_v6 = engine.process_packet(dt46_sid, srh, &inner_ipv6);
        match res_v6 {
            EndDt46ForwardResult::RoutedIpv6 {
                vrf_id,
                dst_ip,
                next_hop,
                ..
            } => {
                assert_eq!(vrf_id, 100);
                assert_eq!(
                    dst_ip,
                    Ipv6Address([
                        0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
                    ])
                );
                assert_eq!(
                    next_hop,
                    VrfNextHop::DirectLocal {
                        out_if: "eth_v6_cust".to_string()
                    }
                );
            }
            other => panic!("Expected RoutedIpv6, got {:?}", other),
        }
    }
}

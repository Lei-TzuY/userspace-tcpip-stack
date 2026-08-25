//! EVPN Layer 3 Anycast Gateway & Symmetric / Asymmetric IRB Coexistence (RFC 9135 / RFC 9136).
//!
//! Integrated Routing and Bridging (IRB) in EVPN datacenter fabrics connects
//! Layer 2 broadcast domains (VNIs) to Layer 3 IP VRF routing.
//!
//! Two primary architectural models exist:
//! 1. **Symmetric IRB (RFC 9135)**: Ingress PE routes into a tenant Transit L3VNI,
//!    transports packet over overlay with Router MAC, and Egress PE routes from L3VNI to destination L2VNI.
//! 2. **Asymmetric IRB**: Ingress PE routes directly into destination L2VNI,
//!    and Egress PE simply bridges within destination L2VNI.
//! 3. **Distributed Anycast Gateway (RFC 9136)**: Default Gateway IP and virtual MAC
//!    (`00:00:5E:00:01:01`) are simultaneously active on all Leaf PEs.
//!
//! This module implements:
//! * Dual Symmetric & Asymmetric IRB routing/bridging engine.
//! * Distributed Anycast Gateway MAC & IP handling.
//! * Over-the-overlay forwarding and transit L3VNI lookup.

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

pub const DEFAULT_ANYCAST_GATEWAY_MAC: MacAddress =
    MacAddress([0x00, 0x00, 0x5E, 0x00, 0x01, 0x01]);

/// IRB Mode of an EVPN Fabric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrbMode {
    Symmetric,
    Asymmetric,
}

/// Host Binding in an IRB instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIrbBinding {
    pub ip: Ipv4Address,
    pub mac: MacAddress,
    pub l2_vni: u32,
    pub leaf_vtep: Ipv4Address,
}

/// Forwarded overlay packet metadata produced by the IRB engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrbForwardingAction {
    pub target_vtep: Ipv4Address,
    pub overlay_vni: u32,
    pub inner_src_mac: MacAddress,
    pub inner_dst_mac: MacAddress,
    pub mode_used: IrbMode,
}

/// EVPN Layer 3 Anycast Gateway & IRB Engine.
#[derive(Debug, Clone)]
pub struct EvpnAnycastIrbEngine {
    pub local_vtep: Ipv4Address,
    pub anycast_gateway_mac: MacAddress,
    pub local_router_mac: MacAddress,
    /// Default Transit L3VNI used for Symmetric IRB.
    pub transit_l3_vni: u32,
    /// Local Subnet Anycast Gateways: L2VNI -> Gateway IP
    pub anycast_gateways: HashMap<u32, Ipv4Address>,
    /// Global host lookup table: IP -> HostBinding
    pub host_table: HashMap<Ipv4Address, HostIrbBinding>,
    pub total_symmetric_routed: u64,
    pub total_asymmetric_routed: u64,
}

impl EvpnAnycastIrbEngine {
    pub fn new(local_vtep: Ipv4Address, local_router_mac: MacAddress, transit_l3_vni: u32) -> Self {
        EvpnAnycastIrbEngine {
            local_vtep,
            anycast_gateway_mac: DEFAULT_ANYCAST_GATEWAY_MAC,
            local_router_mac,
            transit_l3_vni,
            anycast_gateways: HashMap::new(),
            host_table: HashMap::new(),
            total_symmetric_routed: 0,
            total_asymmetric_routed: 0,
        }
    }

    /// Configures an Anycast Gateway on a specific L2VNI subnet.
    pub fn add_anycast_gateway(&mut self, l2_vni: u32, gateway_ip: Ipv4Address) {
        self.anycast_gateways.insert(l2_vni, gateway_ip);
    }

    /// Learns or syncs a host IP/MAC route from BGP EVPN Type 2.
    pub fn learn_host(
        &mut self,
        ip: Ipv4Address,
        mac: MacAddress,
        l2_vni: u32,
        leaf_vtep: Ipv4Address,
    ) {
        self.host_table.insert(
            ip,
            HostIrbBinding {
                ip,
                mac,
                l2_vni,
                leaf_vtep,
            },
        );
    }

    /// Routes an inter-subnet packet from source L2VNI to destination host IP.
    pub fn route_inter_subnet(
        &mut self,
        _src_vni: u32,
        dst_ip: Ipv4Address,
        preferred_mode: IrbMode,
    ) -> Option<IrbForwardingAction> {
        let host = self.host_table.get(&dst_ip)?;

        match preferred_mode {
            IrbMode::Symmetric => {
                // Symmetric IRB: encapsulated with Transit L3VNI and Local Router MAC
                self.total_symmetric_routed += 1;
                Some(IrbForwardingAction {
                    target_vtep: host.leaf_vtep,
                    overlay_vni: self.transit_l3_vni,
                    inner_src_mac: self.local_router_mac,
                    inner_dst_mac: self.anycast_gateway_mac, // Or target Router MAC
                    mode_used: IrbMode::Symmetric,
                })
            }
            IrbMode::Asymmetric => {
                // Asymmetric IRB: routed at Ingress directly to target L2VNI and bridged at Egress
                self.total_asymmetric_routed += 1;
                Some(IrbForwardingAction {
                    target_vtep: host.leaf_vtep,
                    overlay_vni: host.l2_vni,
                    inner_src_mac: self.anycast_gateway_mac,
                    inner_dst_mac: host.mac,
                    mode_used: IrbMode::Asymmetric,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_and_asymmetric_irb_routing() {
        let local_vtep = Ipv4Address::new(10, 0, 0, 1);
        let router_mac = MacAddress([0x00, 0x1B, 0x21, 0xAA, 0xBB, 0xCC]);
        let mut engine = EvpnAnycastIrbEngine::new(local_vtep, router_mac, 9000); // Transit L3VNI = 9000

        engine.add_anycast_gateway(100, Ipv4Address::new(192, 168, 10, 1));
        engine.add_anycast_gateway(200, Ipv4Address::new(192, 168, 20, 1));

        let host_ip = Ipv4Address::new(192, 168, 20, 55);
        let host_mac = MacAddress([0x52, 0x54, 0x00, 0x20, 0x00, 0x55]);
        let remote_vtep = Ipv4Address::new(10, 0, 0, 2);

        engine.learn_host(host_ip, host_mac, 200, remote_vtep);

        // 1. Route via Symmetric IRB
        let sym_action = engine
            .route_inter_subnet(100, host_ip, IrbMode::Symmetric)
            .expect("Symmetric IRB route");
        assert_eq!(sym_action.overlay_vni, 9000); // Uses Transit L3VNI
        assert_eq!(sym_action.target_vtep, remote_vtep);
        assert_eq!(sym_action.inner_src_mac, router_mac);
        assert_eq!(sym_action.mode_used, IrbMode::Symmetric);
        assert_eq!(engine.total_symmetric_routed, 1);

        // 2. Route via Asymmetric IRB
        let asym_action = engine
            .route_inter_subnet(100, host_ip, IrbMode::Asymmetric)
            .expect("Asymmetric IRB route");
        assert_eq!(asym_action.overlay_vni, 200); // Direct destination L2VNI
        assert_eq!(asym_action.inner_dst_mac, host_mac);
        assert_eq!(asym_action.mode_used, IrbMode::Asymmetric);
        assert_eq!(engine.total_asymmetric_routed, 1);
    }
}

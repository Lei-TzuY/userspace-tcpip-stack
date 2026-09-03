// =============================================================================
// EVPN Layer 2 Unknown Multicast Replication Tree (UMRT) & Selective Pruning
// (RFC 7432 / RFC 9251)
// =============================================================================
//
// In EVPN Layer 2 datacenter networks, Unknown Multicast frames (such as mDNS,
// SSDP, or non-queried cluster multicasts) are flooded via Ingress Replication (IR).
//
// The UMRT Engine optimizes flooding by:
//   1. Remote VTEP Pruning: Only replicates to remote VTEPs participating in the VNI.
//   2. Local Port Filtering: Prunes local edge ports configured with `prune_unknown_mcast`.
//   3. Overlay Split-Horizon: Frames arriving from remote VTEP overlays are never
//      re-encapsulated back to the overlay core.
//
// Pure safe Rust, zero external crates.

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;

/// Forwarding direction / ingress domain of the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressDomain {
    LocalPort(u32),
    OverlayVtep(Ipv4Address),
}

/// Replication plan for an unknown multicast frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UmrtReplicationPlan {
    pub vni: u32,
    pub local_egress_ports: Vec<u32>,
    pub remote_vteps: Vec<Ipv4Address>,
}

/// Local bridge access port configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPortConfig {
    pub port_id: u32,
    pub vni: u32,
    pub prune_unknown_mcast: bool,
}

/// Remote leaf VTEP membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteVtepMembership {
    pub vtep_ip: Ipv4Address,
    pub subscribed_vnis: Vec<u32>,
}

/// EVPN Layer 2 Unknown Multicast Replication Tree (UMRT) Engine.
pub struct EvpnUmrtEngine {
    pub local_vtep_ip: Ipv4Address,
    pub local_ports: Vec<LocalPortConfig>,
    pub remote_vteps: Vec<RemoteVtepMembership>,
    pub total_plans_computed: u64,
    pub total_local_replications: u64,
    pub total_overlay_replications: u64,
}

impl EvpnUmrtEngine {
    pub fn new(local_vtep_ip: Ipv4Address) -> Self {
        Self {
            local_vtep_ip,
            local_ports: Vec::new(),
            remote_vteps: Vec::new(),
            total_plans_computed: 0,
            total_local_replications: 0,
            total_overlay_replications: 0,
        }
    }

    /// Add or update local port config.
    pub fn add_local_port(&mut self, port_id: u32, vni: u32, prune_unknown_mcast: bool) {
        if let Some(pos) = self.local_ports.iter().position(|p| p.port_id == port_id) {
            self.local_ports[pos] = LocalPortConfig {
                port_id,
                vni,
                prune_unknown_mcast,
            };
        } else {
            self.local_ports.push(LocalPortConfig {
                port_id,
                vni,
                prune_unknown_mcast,
            });
        }
    }

    /// Register remote VTEP membership.
    pub fn register_remote_vtep(&mut self, vtep_ip: Ipv4Address, vnis: &[u32]) {
        if let Some(pos) = self.remote_vteps.iter().position(|v| v.vtep_ip == vtep_ip) {
            self.remote_vteps[pos].subscribed_vnis = vnis.to_vec();
        } else {
            self.remote_vteps.push(RemoteVtepMembership {
                vtep_ip,
                subscribed_vnis: vnis.to_vec(),
            });
        }
    }

    /// Check if a MAC address is multicast (least significant bit of first octet is 1).
    pub fn is_multicast_mac(mac: &MacAddress) -> bool {
        (mac.0[0] & 0x01) == 0x01 && *mac != MacAddress::BROADCAST
    }

    /// Compute ingress replication tree for an unknown multicast frame.
    pub fn compute_replication_plan(
        &mut self,
        vni: u32,
        ingress: IngressDomain,
        _dst_mac: MacAddress,
    ) -> UmrtReplicationPlan {
        self.total_plans_computed += 1;

        // 1. Calculate local egress ports
        let mut local_egress_ports = Vec::new();
        for port in &self.local_ports {
            if port.vni == vni && !port.prune_unknown_mcast {
                match ingress {
                    IngressDomain::LocalPort(in_port) => {
                        if port.port_id != in_port {
                            local_egress_ports.push(port.port_id);
                        }
                    }
                    IngressDomain::OverlayVtep(_) => {
                        local_egress_ports.push(port.port_id);
                    }
                }
            }
        }

        // 2. Calculate remote VTEPs (Only if frame arrived on local access port)
        let mut remote_vteps = Vec::new();
        if let IngressDomain::LocalPort(_) = ingress {
            for remote in &self.remote_vteps {
                if remote.vtep_ip != self.local_vtep_ip && remote.subscribed_vnis.contains(&vni) {
                    remote_vteps.push(remote.vtep_ip);
                }
            }
        }

        self.total_local_replications += local_egress_ports.len() as u64;
        self.total_overlay_replications += remote_vteps.len() as u64;

        UmrtReplicationPlan {
            vni,
            local_egress_ports,
            remote_vteps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_umrt_replication_lifecycle() {
        let local_vtep = Ipv4Address::new(10, 0, 0, 1);
        let mut engine = EvpnUmrtEngine::new(local_vtep);

        // Local ports in VNI 100
        engine.add_local_port(1, 100, false); // Active forwarding
        engine.add_local_port(2, 100, true); // Pruned port
        engine.add_local_port(3, 100, false); // Active forwarding
        engine.add_local_port(4, 200, false); // Different VNI

        // Remote VTEPs
        let remote_leaf2 = Ipv4Address::new(10, 0, 0, 2);
        let remote_leaf3 = Ipv4Address::new(10, 0, 0, 3);
        engine.register_remote_vtep(remote_leaf2, &[100, 200]);
        engine.register_remote_vtep(remote_leaf3, &[200]); // Not in VNI 100

        let mcast_mac = MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB]); // mDNS

        // 1. Ingress on local port 1 in VNI 100
        let plan_local =
            engine.compute_replication_plan(100, IngressDomain::LocalPort(1), mcast_mac);
        assert_eq!(plan_local.local_egress_ports, vec![3]); // Port 1 excluded (ingress), Port 2 excluded (pruned)
        assert_eq!(plan_local.remote_vteps, vec![remote_leaf2]); // Only leaf2 is in VNI 100

        // 2. Ingress from overlay VTEP leaf2
        let plan_overlay = engine.compute_replication_plan(
            100,
            IngressDomain::OverlayVtep(remote_leaf2),
            mcast_mac,
        );
        assert_eq!(plan_overlay.local_egress_ports, vec![1, 3]); // Delivered to local access ports
        assert!(plan_overlay.remote_vteps.is_empty()); // Split-horizon: 0 overlay replications
    }
}

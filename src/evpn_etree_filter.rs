//! EVPN E-Tree Ingress/Egress Filtering & BUM Split-Horizon Replication (RFC 8317 Section 5 & 6).
//!
//! Enforces strict Root/Leaf tenant isolation for both Known Unicast and BUM (Broadcast, Unknown
//! Unicast, Multicast) traffic across local access attachment circuits and remote EVPN tunnels.

use crate::ethernet::MacAddress;
use crate::evpn_etree::ETreeRole;
use std::collections::HashMap;

/// Access Interface Attachment Circuit (AC) Configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnETreeAccessPort {
    pub if_name: String,
    pub vlan_id: u16,
    pub role: ETreeRole,
}

/// Remote PE VTEP Information with E-Tree Leaf Indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnETreeRemoteVtep {
    pub vtep_ip: crate::ipv4::Ipv4Address,
    pub vni: u32,
    pub is_leaf_only: bool,
    pub leaf_label: Option<u32>,
}

/// E-Tree Packet Dispatch Decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ETreeForwardVerdict {
    /// Forward to local ports and remote VTEPs
    Forward {
        local_egress_ports: Vec<String>,
        remote_vteps: Vec<crate::ipv4::Ipv4Address>,
    },
    /// Dropped because of Leaf-to-Leaf isolation policy
    DropLeafToLeaf(String),
    /// Unknown destination MAC dropped
    DropUnknown,
}

/// Advanced EVPN E-Tree Forwarding & Split-Horizon Engine.
#[derive(Debug, Clone, Default)]
pub struct EvpnETreeFilterEngine {
    /// Local attachment circuits: (VNI, if_name, vlan_id) -> ETreeRole
    pub access_ports: HashMap<(u32, String, u16), ETreeRole>,
    /// MAC Table: (VNI, MAC) -> (Port, ETreeRole)
    pub mac_table: HashMap<(u32, MacAddress), (String, ETreeRole)>,
    /// Remote PE VTEPs participating in the E-Tree VNI
    pub remote_vteps: HashMap<u32, Vec<EvpnETreeRemoteVtep>>,
}

impl EvpnETreeFilterEngine {
    pub fn new() -> Self {
        Self {
            access_ports: HashMap::new(),
            mac_table: HashMap::new(),
            remote_vteps: HashMap::new(),
        }
    }

    /// Registers a local attachment circuit port as Root or Leaf.
    pub fn add_access_port(&mut self, vni: u32, if_name: &str, vlan_id: u16, role: ETreeRole) {
        self.access_ports
            .insert((vni, if_name.to_string(), vlan_id), role);
    }

    /// Learn or statically program a local or remote MAC address with its E-Tree role.
    pub fn learn_mac(&mut self, vni: u32, mac: MacAddress, port: &str, role: ETreeRole) {
        self.mac_table.insert((vni, mac), (port.to_string(), role));
    }

    /// Registers a remote PE VTEP for a VNI.
    pub fn add_remote_vtep(&mut self, vni: u32, vtep: EvpnETreeRemoteVtep) {
        self.remote_vteps.entry(vni).or_default().push(vtep);
    }

    /// Evaluates Known Unicast Forwarding across the E-Tree fabric.
    pub fn evaluate_known_unicast(
        &self,
        vni: u32,
        ingress_port: &str,
        vlan_id: u16,
        src_mac: MacAddress,
        dst_mac: MacAddress,
    ) -> ETreeForwardVerdict {
        let ingress_role = match self
            .access_ports
            .get(&(vni, ingress_port.to_string(), vlan_id))
        {
            Some(r) => *r,
            None => self
                .mac_table
                .get(&(vni, src_mac))
                .map(|(_, r)| *r)
                .unwrap_or(ETreeRole::Root),
        };

        let (egress_port, target_role) = match self.mac_table.get(&(vni, dst_mac)) {
            Some(entry) => entry,
            None => return ETreeForwardVerdict::DropUnknown,
        };

        // RFC 8317 Rule: Leaf cannot talk to Leaf
        if ingress_role == ETreeRole::Leaf && *target_role == ETreeRole::Leaf {
            return ETreeForwardVerdict::DropLeafToLeaf(format!(
                "Leaf port {} to Leaf destination MAC {}",
                ingress_port, dst_mac
            ));
        }

        ETreeForwardVerdict::Forward {
            local_egress_ports: vec![egress_port.clone()],
            remote_vteps: Vec::new(),
        }
    }

    /// Evaluates BUM (Broadcast / Multicast) Flooding across the E-Tree fabric.
    pub fn evaluate_bum_flooding(
        &self,
        vni: u32,
        ingress_port: &str,
        vlan_id: u16,
    ) -> ETreeForwardVerdict {
        let ingress_role = match self
            .access_ports
            .get(&(vni, ingress_port.to_string(), vlan_id))
        {
            Some(r) => *r,
            None => ETreeRole::Root,
        };

        let mut local_ports = Vec::new();

        // 1. Determine local access ports to flood to
        for ((port_vni, port_name, _), role) in &self.access_ports {
            if *port_vni != vni || port_name == ingress_port {
                continue;
            }
            if ingress_role == ETreeRole::Leaf && *role == ETreeRole::Leaf {
                // Do NOT flood Leaf traffic to other local Leaf ports
                continue;
            }
            local_ports.push(port_name.clone());
        }

        // 2. Determine remote VTEPs to flood to
        let mut remote_dest_vteps = Vec::new();
        if let Some(vteps) = self.remote_vteps.get(&vni) {
            for vtep in vteps {
                if ingress_role == ETreeRole::Leaf && vtep.is_leaf_only {
                    // Do NOT flood to remote PEs containing only Leaf ACs
                    continue;
                }
                remote_dest_vteps.push(vtep.vtep_ip);
            }
        }

        ETreeForwardVerdict::Forward {
            local_egress_ports: local_ports,
            remote_vteps: remote_dest_vteps,
        }
    }

    /// Egress filter when receiving overlay packet from remote PE with Leaf-indication.
    pub fn filter_overlay_ingress_packet(
        &self,
        vni: u32,
        is_remote_source_leaf: bool,
        target_dst_mac: MacAddress,
    ) -> bool {
        if !is_remote_source_leaf {
            // Source is Root, permitted to both Root and Leaf
            return true;
        }

        // Source is Leaf: only deliver if destination is Root
        if let Some((_, role)) = self.mac_table.get(&(vni, target_dst_mac)) {
            *role == ETreeRole::Root
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::Ipv4Address;

    #[test]
    fn test_evpn_etree_ingress_egress_bum_filtering() {
        let mut engine = EvpnETreeFilterEngine::new();
        let vni = 10000;

        // Local ports: Root on eth0, Leaf on eth1, Leaf on eth2
        engine.add_access_port(vni, "eth0", 100, ETreeRole::Root);
        engine.add_access_port(vni, "eth1", 100, ETreeRole::Leaf);
        engine.add_access_port(vni, "eth2", 100, ETreeRole::Leaf);

        // Remote VTEPs
        engine.add_remote_vtep(
            vni,
            EvpnETreeRemoteVtep {
                vtep_ip: Ipv4Address::new(192, 168, 1, 1),
                vni,
                is_leaf_only: false, // Has Root ACs
                leaf_label: None,
            },
        );
        engine.add_remote_vtep(
            vni,
            EvpnETreeRemoteVtep {
                vtep_ip: Ipv4Address::new(192, 168, 1, 2),
                vni,
                is_leaf_only: true, // Only has Leaf ACs
                leaf_label: Some(5000),
            },
        );

        // 1. BUM from Root port eth0 floods to all local Leaf/Root ports & all remote VTEPs
        let bum_root = engine.evaluate_bum_flooding(vni, "eth0", 100);
        match bum_root {
            ETreeForwardVerdict::Forward {
                local_egress_ports,
                remote_vteps,
            } => {
                assert!(local_egress_ports.contains(&"eth1".to_string()));
                assert!(local_egress_ports.contains(&"eth2".to_string()));
                assert_eq!(remote_vteps.len(), 2);
            }
            other => panic!("Expected Forward, got {:?}", other),
        }

        // 2. BUM from Leaf port eth1 only floods to local Root eth0 & remote Root PE (192.168.1.1)
        let bum_leaf = engine.evaluate_bum_flooding(vni, "eth1", 100);
        match bum_leaf {
            ETreeForwardVerdict::Forward {
                local_egress_ports,
                remote_vteps,
            } => {
                assert_eq!(local_egress_ports, vec!["eth0".to_string()]);
                assert_eq!(remote_vteps, vec![Ipv4Address::new(192, 168, 1, 1)]);
            }
            other => panic!("Expected Forward, got {:?}", other),
        }
    }
}

// =============================================================================
// EVPN Selective Multicast Underlay Provider P-Tree / PMSI Mapping Engine
// (RFC 6513 / RFC 6514 / RFC 7432 / RFC 9251)
// =============================================================================
//
// In high-density datacenter fabrics, Ingress Replication (IR) can saturate
// Leaf uplinks when replicating high-bandwidth multicast streams across dozens
// of receiver Leaf PEs.
//
// The EVPN Underlay P-Tree Engine maps overlay $(S, G)$ channels from Type-6
// SMET routes to underlay Core Multicast Distribution Trees (Provider Multicast
// Service Interface - PMSI tunnels, e.g. PIM-SSM underlay or mLDP P2MP LSPs).
//
// When receiver count is low ($\le \text{threshold}$), the engine uses Ingress
// Replication (IR). When receiver count exceeds threshold, the engine automatically
// promotes the stream to a dedicated Underlay P-Tree for hardware line-rate replication.
//
// Features:
//   1. Dynamic Tunnel Type Selection: Ingress Replication (IR) vs Selective P-Tree (S-PMSI).
//   2. Overlay $(VNI, S, G)$ to Underlay $G_{\text{core}}$ Group Mapping.
//   3. Configurable Receiver Threshold for Automatic S-PMSI Tunnel Promotion.
//   4. Provider Tunnel Encapsulation Plan (Underlay Outer IP/VNI/GRE header).
//
// Pure safe Rust, zero external crates.

use crate::ipv4::Ipv4Address;

/// Underlay PMSI Multicast Tunnel Type (RFC 6514 / RFC 7432).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnderlayTunnelType {
    /// Ingress Replication over point-to-point unicast overlay tunnels.
    IngressReplication,
    /// Selective Provider Multicast Distribution Tree (S-PMSI) in core underlay.
    SelectivePTree,
}

/// Active Overlay to Underlay Multicast Mapping Entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnderlaySsmMapping {
    pub vni: u32,
    pub overlay_group: Ipv4Address,
    pub overlay_source: Ipv4Address,
    pub underlay_mcast_group: Option<Ipv4Address>,
    pub receiver_vteps: Vec<Ipv4Address>,
    pub tunnel_type: UnderlayTunnelType,
}

/// Forwarding encapsulation plan for an outgoing overlay multicast packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnderlayEncapsulationPlan {
    /// Send unicast copies to each receiver VTEP.
    UnicastReplication { destination_vteps: Vec<Ipv4Address> },
    /// Send single encapsulated packet to underlay core multicast group.
    CoreMulticast { underlay_group: Ipv4Address },
    /// No receivers; drop packet.
    DropNoReceivers,
}

/// EVPN Selective Multicast Underlay P-Tree Mapping Engine.
pub struct EvpnUnderlayPmsiEngine {
    pub local_vtep_ip: Ipv4Address,
    pub ptree_promotion_threshold: usize, // Number of remote VTEPs before promoting to S-PMSI
    pub next_underlay_group_suffix: u8,
    pub mappings: Vec<UnderlaySsmMapping>,
    pub total_ir_packets: u64,
    pub total_ptree_packets: u64,
    pub total_ptree_promotions: u64,
    pub total_ptree_demotions: u64,
}

impl EvpnUnderlayPmsiEngine {
    pub fn new(local_vtep_ip: Ipv4Address, ptree_promotion_threshold: usize) -> Self {
        Self {
            local_vtep_ip,
            ptree_promotion_threshold: ptree_promotion_threshold.max(1),
            next_underlay_group_suffix: 1,
            mappings: Vec::new(),
            total_ir_packets: 0,
            total_ptree_packets: 0,
            total_ptree_promotions: 0,
            total_ptree_demotions: 0,
        }
    }

    /// Allocate a fresh underlay core multicast group IP (239.255.0.x).
    fn allocate_underlay_group(&mut self) -> Ipv4Address {
        let suffix = self.next_underlay_group_suffix;
        self.next_underlay_group_suffix = self.next_underlay_group_suffix.wrapping_add(1);
        if self.next_underlay_group_suffix == 0 {
            self.next_underlay_group_suffix = 1;
        }
        Ipv4Address::new(239, 255, 0, suffix)
    }

    /// Add a remote receiver VTEP for an overlay $(VNI, S, G)$ channel.
    pub fn add_receiver_vtep(
        &mut self,
        vni: u32,
        overlay_group: Ipv4Address,
        overlay_source: Ipv4Address,
        remote_vtep: Ipv4Address,
    ) -> UnderlayTunnelType {
        let threshold = self.ptree_promotion_threshold;

        if let Some(entry) = self.mappings.iter_mut().find(|m| {
            m.vni == vni && m.overlay_group == overlay_group && m.overlay_source == overlay_source
        }) {
            if !entry.receiver_vteps.contains(&remote_vtep) {
                entry.receiver_vteps.push(remote_vtep);
            }

            if entry.receiver_vteps.len() >= threshold
                && entry.tunnel_type == UnderlayTunnelType::IngressReplication
            {
                // Promote to S-PMSI
                let grp = if let Some(g) = entry.underlay_mcast_group {
                    g
                } else {
                    Ipv4Address::new(239, 255, 0, 10)
                };
                entry.underlay_mcast_group = Some(grp);
                entry.tunnel_type = UnderlayTunnelType::SelectivePTree;
                self.total_ptree_promotions += 1;
            }
            entry.tunnel_type
        } else {
            let initial_tunnel = if threshold <= 1 {
                UnderlayTunnelType::SelectivePTree
            } else {
                UnderlayTunnelType::IngressReplication
            };

            let u_grp = if initial_tunnel == UnderlayTunnelType::SelectivePTree {
                Some(self.allocate_underlay_group())
            } else {
                None
            };

            self.mappings.push(UnderlaySsmMapping {
                vni,
                overlay_group,
                overlay_source,
                underlay_mcast_group: u_grp,
                receiver_vteps: vec![remote_vtep],
                tunnel_type: initial_tunnel,
            });

            if initial_tunnel == UnderlayTunnelType::SelectivePTree {
                self.total_ptree_promotions += 1;
            }
            initial_tunnel
        }
    }

    /// Remove a receiver VTEP when a remote leaf withdraws Type-6 SMET interest.
    pub fn remove_receiver_vtep(
        &mut self,
        vni: u32,
        overlay_group: Ipv4Address,
        overlay_source: Ipv4Address,
        remote_vtep: Ipv4Address,
    ) {
        let threshold = self.ptree_promotion_threshold;

        if let Some(pos) = self.mappings.iter().position(|m| {
            m.vni == vni && m.overlay_group == overlay_group && m.overlay_source == overlay_source
        }) {
            let entry = &mut self.mappings[pos];
            if let Some(p) = entry.receiver_vteps.iter().position(|v| *v == remote_vtep) {
                entry.receiver_vteps.remove(p);
            }

            if entry.receiver_vteps.is_empty() {
                self.mappings.remove(pos);
            } else if entry.receiver_vteps.len() < threshold
                && entry.tunnel_type == UnderlayTunnelType::SelectivePTree
            {
                // Demote back to Ingress Replication
                entry.tunnel_type = UnderlayTunnelType::IngressReplication;
                entry.underlay_mcast_group = None;
                self.total_ptree_demotions += 1;
            }
        }
    }

    /// Evaluate forwarding encapsulation plan for an outgoing overlay multicast stream.
    pub fn evaluate_encapsulation(
        &mut self,
        vni: u32,
        overlay_source: Ipv4Address,
        overlay_group: Ipv4Address,
    ) -> UnderlayEncapsulationPlan {
        if let Some(entry) = self.mappings.iter().find(|m| {
            m.vni == vni && m.overlay_group == overlay_group && m.overlay_source == overlay_source
        }) {
            if entry.receiver_vteps.is_empty() {
                return UnderlayEncapsulationPlan::DropNoReceivers;
            }

            match entry.tunnel_type {
                UnderlayTunnelType::IngressReplication => {
                    self.total_ir_packets += 1;
                    UnderlayEncapsulationPlan::UnicastReplication {
                        destination_vteps: entry.receiver_vteps.clone(),
                    }
                }
                UnderlayTunnelType::SelectivePTree => {
                    self.total_ptree_packets += 1;
                    let grp = entry
                        .underlay_mcast_group
                        .unwrap_or(Ipv4Address::new(239, 255, 0, 1));
                    UnderlayEncapsulationPlan::CoreMulticast {
                        underlay_group: grp,
                    }
                }
            }
        } else {
            UnderlayEncapsulationPlan::DropNoReceivers
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_ssm_underlay_lifecycle() {
        // Promotion threshold: 3 remote VTEPs
        let mut engine = EvpnUnderlayPmsiEngine::new(Ipv4Address::new(10, 0, 0, 1), 3);

        let group = Ipv4Address::new(232, 1, 1, 1);
        let src = Ipv4Address::new(192, 168, 10, 50);

        // 1. Add 1st receiver (10.0.0.2) -> Ingress Replication
        let t1 = engine.add_receiver_vtep(100, group, src, Ipv4Address::new(10, 0, 0, 2));
        assert_eq!(t1, UnderlayTunnelType::IngressReplication);

        // 2. Add 2nd receiver (10.0.0.3) -> Ingress Replication
        let t2 = engine.add_receiver_vtep(100, group, src, Ipv4Address::new(10, 0, 0, 3));
        assert_eq!(t2, UnderlayTunnelType::IngressReplication);

        let plan_ir = engine.evaluate_encapsulation(100, src, group);
        assert_eq!(
            plan_ir,
            UnderlayEncapsulationPlan::UnicastReplication {
                destination_vteps: vec![
                    Ipv4Address::new(10, 0, 0, 2),
                    Ipv4Address::new(10, 0, 0, 3)
                ],
            }
        );

        // 3. Add 3rd receiver (10.0.0.4) -> Meets threshold 3 -> Promoted to S-PMSI P-Tree!
        let t3 = engine.add_receiver_vtep(100, group, src, Ipv4Address::new(10, 0, 0, 4));
        assert_eq!(t3, UnderlayTunnelType::SelectivePTree);
        assert_eq!(engine.total_ptree_promotions, 1);

        let plan_ptree = engine.evaluate_encapsulation(100, src, group);
        match plan_ptree {
            UnderlayEncapsulationPlan::CoreMulticast { underlay_group } => {
                assert_eq!(underlay_group.0[0], 239);
                assert_eq!(underlay_group.0[1], 255);
            }
            _ => panic!("Expected CoreMulticast plan"),
        }

        // 4. Remove 2 receivers -> Drops below threshold 3 -> Demoted to Ingress Replication
        engine.remove_receiver_vtep(100, group, src, Ipv4Address::new(10, 0, 0, 4));
        assert_eq!(
            engine.mappings[0].tunnel_type,
            UnderlayTunnelType::IngressReplication
        );
        assert_eq!(engine.total_ptree_demotions, 1);
    }
}

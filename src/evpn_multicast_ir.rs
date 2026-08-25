//! EVPN Ingress Replication (IR) Selective Multicast Forwarding & Leaf Pruning (RFC 7432 Section 11 / RFC 9251).
//!
//! Standard EVPN BUM Ingress Replication (Route Type 3 / IMET) floods multicast
//! packets to ALL remote PEs in the VNI, causing massive network bandwidth waste.
//!
//! EVPN Selective Multicast Ingress Replication (IR) optimizes this by:
//! 1. Maintaining per-group $(VNI, S, G)$ subscription lists built dynamically from EVPN Route Type 6 (SMET) NLRIs.
//! 2. When a tenant source transmits multicast traffic, replicating frames ONLY to remote PEs with active $(S, G)$ receivers.
//! 3. Pruning all non-interested PEs, saving datacenter core fabric bandwidth.
//!
//! This module implements:
//! * Selective Ingress Replication Table per $(VNI, G)$ or $(VNI, S, G)$.
//! * Dynamic Leaf PE Join / Leave processing.
//! * Selective packet replication engine.
//! * Pruning efficiency statistics (packets saved from broadcast flooding).

use crate::ipv4::Ipv4Address;

/// Multicast Channel Identifier $(S, G)$ in a VNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastChannel {
    pub vni: u32,
    pub source_ip: Option<Ipv4Address>, // None indicates (*, G) Any-Source Multicast
    pub group_ip: Ipv4Address,
}

impl MulticastChannel {
    pub fn new_asm(vni: u32, group_ip: Ipv4Address) -> Self {
        MulticastChannel {
            vni,
            source_ip: None,
            group_ip,
        }
    }

    pub fn new_ssm(vni: u32, source_ip: Ipv4Address, group_ip: Ipv4Address) -> Self {
        MulticastChannel {
            vni,
            source_ip: Some(source_ip),
            group_ip,
        }
    }
}

/// A Selective Multicast Ingress Replication entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectiveIrEntry {
    pub channel: MulticastChannel,
    /// List of interested remote Leaf VTEP IPs that sent SMET Type 6 joins.
    pub receiver_vteps: Vec<Ipv4Address>,
    pub packets_forwarded: u64,
    pub replications_sent: u64,
}

/// EVPN Selective Ingress Replication & Multicast Pruning Engine.
#[derive(Debug, Clone)]
pub struct EvpnSelectiveIrEngine {
    /// Default inclusive IMET VTEP list per VNI (fallback flooding list).
    pub inclusive_vteps: Vec<(u32, Vec<Ipv4Address>)>,
    /// Selective $(S, G)$ entries.
    pub selective_entries: Vec<SelectiveIrEntry>,
    pub total_pruned_packets_saved: u64,
}

impl EvpnSelectiveIrEngine {
    pub fn new() -> Self {
        EvpnSelectiveIrEngine {
            inclusive_vteps: Vec::new(),
            selective_entries: Vec::new(),
            total_pruned_packets_saved: 0,
        }
    }

    /// Registers the default inclusive IMET VTEP list for a VNI.
    pub fn set_inclusive_vteps(&mut self, vni: u32, vteps: Vec<Ipv4Address>) {
        if let Some(pos) = self.inclusive_vteps.iter().position(|(v, _)| *v == vni) {
            self.inclusive_vteps[pos].1 = vteps;
        } else {
            self.inclusive_vteps.push((vni, vteps));
        }
    }

    /// Adds a remote Leaf VTEP to the selective $(S, G)$ receiver list upon receiving Route Type 6 (SMET).
    pub fn add_smet_receiver(&mut self, channel: MulticastChannel, leaf_vtep: Ipv4Address) {
        if let Some(entry) = self.selective_entries.iter_mut().find(|e| e.channel == channel) {
            if !entry.receiver_vteps.contains(&leaf_vtep) {
                entry.receiver_vteps.push(leaf_vtep);
            }
        } else {
            self.selective_entries.push(SelectiveIrEntry {
                channel,
                receiver_vteps: vec![leaf_vtep],
                packets_forwarded: 0,
                replications_sent: 0,
            });
        }
    }

    /// Removes a remote Leaf VTEP upon receiving Route Type 6 withdrawal.
    pub fn remove_smet_receiver(&mut self, channel: &MulticastChannel, leaf_vtep: &Ipv4Address) -> bool {
        if let Some(entry) = self.selective_entries.iter_mut().find(|e| e.channel == *channel) {
            if let Some(pos) = entry.receiver_vteps.iter().position(|v| v == leaf_vtep) {
                entry.receiver_vteps.remove(pos);
                return true;
            }
        }
        false
    }

    /// Resolves the replication list for an outgoing multicast packet.
    /// Returns the target VTEPs and whether selective pruning was applied.
    pub fn resolve_replication_targets(
        &mut self,
        vni: u32,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
    ) -> (Vec<Ipv4Address>, bool) {
        let total_inclusive = self.inclusive_vteps.iter()
            .find(|(v, _)| *v == vni)
            .map(|(_, vteps)| vteps.len())
            .unwrap_or(0);

        // 1. Check SSM match (VNI, S, G)
        let ssm_channel = MulticastChannel::new_ssm(vni, src_ip, dst_ip);
        if let Some(entry) = self.selective_entries.iter_mut().find(|e| e.channel == ssm_channel && !e.receiver_vteps.is_empty()) {
            entry.packets_forwarded += 1;
            entry.replications_sent += entry.receiver_vteps.len() as u64;
            let pruned = total_inclusive.saturating_sub(entry.receiver_vteps.len());
            self.total_pruned_packets_saved += pruned as u64;
            return (entry.receiver_vteps.clone(), true);
        }

        // 2. Check ASM match (VNI, *, G)
        let asm_channel = MulticastChannel::new_asm(vni, dst_ip);
        if let Some(entry) = self.selective_entries.iter_mut().find(|e| e.channel == asm_channel && !e.receiver_vteps.is_empty()) {
            entry.packets_forwarded += 1;
            entry.replications_sent += entry.receiver_vteps.len() as u64;
            let pruned = total_inclusive.saturating_sub(entry.receiver_vteps.len());
            self.total_pruned_packets_saved += pruned as u64;
            return (entry.receiver_vteps.clone(), true);
        }

        // 3. Fallback to default inclusive IMET list
        let fallback = self.inclusive_vteps.iter()
            .find(|(v, _)| *v == vni)
            .map(|(_, vteps)| vteps.clone())
            .unwrap_or_default();

        (fallback, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_selective_multicast_pruning() {
        let mut engine = EvpnSelectiveIrEngine::new();

        // 5 Leaf VTEPs in VNI 100
        let vteps = vec![
            Ipv4Address::new(10, 0, 0, 1),
            Ipv4Address::new(10, 0, 0, 2),
            Ipv4Address::new(10, 0, 0, 3),
            Ipv4Address::new(10, 0, 0, 4),
            Ipv4Address::new(10, 0, 0, 5),
        ];
        engine.set_inclusive_vteps(100, vteps);

        let group_ip = Ipv4Address::new(239, 1, 1, 1);
        let src_ip = Ipv4Address::new(192, 168, 1, 100);
        let ssm_chan = MulticastChannel::new_ssm(100, src_ip, group_ip);

        // Only VTEP 2 and VTEP 4 join via SMET
        engine.add_smet_receiver(ssm_chan, Ipv4Address::new(10, 0, 0, 2));
        engine.add_smet_receiver(ssm_chan, Ipv4Address::new(10, 0, 0, 4));

        // Transmit packet to (192.168.1.100, 239.1.1.1)
        let (targets, is_selective) = engine.resolve_replication_targets(100, src_ip, group_ip);
        assert!(is_selective);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], Ipv4Address::new(10, 0, 0, 2));
        assert_eq!(targets[1], Ipv4Address::new(10, 0, 0, 4));
        assert_eq!(engine.total_pruned_packets_saved, 3); // 5 - 2 = 3 packets saved from flooding!
    }

    #[test]
    fn test_evpn_multicast_fallback_to_imet_when_no_smet() {
        let mut engine = EvpnSelectiveIrEngine::new();
        let vteps = vec![
            Ipv4Address::new(10, 0, 0, 1),
            Ipv4Address::new(10, 0, 0, 2),
        ];
        engine.set_inclusive_vteps(200, vteps);

        let (targets, is_selective) = engine.resolve_replication_targets(
            200,
            Ipv4Address::new(10, 0, 0, 99),
            Ipv4Address::new(239, 255, 0, 1),
        );
        assert!(!is_selective); // Fallback to IMET
        assert_eq!(targets.len(), 2);
    }
}

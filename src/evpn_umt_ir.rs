//! EVPN Layer 2 Unknown Multicast Tree (UMT) & Ingress Replication Optimization (RFC 7432 / RFC 9251).
//!
//! In high-density EVPN datacenter fabrics, broadcasting unknown multicast frames across
//! all VTEPs creates severe fabric congestion.
//!
//! An Unknown Multicast Tree (UMT) dynamically builds an optimized replication list per $(VNI, G)$:
//! 1. If an explicit Selective Multicast (SMET Type 6) replication list exists, replicate ONLY to interested VTEPs.
//! 2. If no selective receivers exist, replicate to the default Inclusive Multicast (IMET Type 3) list or prune completely.
//!
//! This module implements:
//! * Selective vs Inclusive Multicast Ingress Replication (IR) routing.
//! * Dynamic UMT replication list resolution and non-participating leaf pruning.
//! * Head-end replication packet replication statistics.

use crate::ipv4::Ipv4Address;
use std::collections::{HashMap, HashSet};

/// EVPN Unknown Multicast Tree & Ingress Replication Optimization Engine.
#[derive(Debug, Clone)]
pub struct EvpnUmtEngine {
    pub local_vtep: Ipv4Address,
    /// VNI -> Set of all IMET Type 3 VTEPs
    pub inclusive_vtep_map: HashMap<u32, HashSet<Ipv4Address>>,
    /// (VNI, Multicast Group IP) -> Set of interested SMET Type 6 VTEPs
    pub selective_vtep_map: HashMap<(u32, Ipv4Address), HashSet<Ipv4Address>>,
    pub total_multicast_frames_ingressed: u64,
    pub total_copies_replicated: u64,
    pub total_leaves_pruned: u64,
}

impl EvpnUmtEngine {
    pub fn new(local_vtep: Ipv4Address) -> Self {
        EvpnUmtEngine {
            local_vtep,
            inclusive_vtep_map: HashMap::new(),
            selective_vtep_map: HashMap::new(),
            total_multicast_frames_ingressed: 0,
            total_copies_replicated: 0,
            total_leaves_pruned: 0,
        }
    }

    pub fn add_inclusive_vtep(&mut self, vni: u32, vtep: Ipv4Address) {
        if vtep != self.local_vtep {
            self.inclusive_vtep_map.entry(vni).or_default().insert(vtep);
        }
    }

    pub fn add_selective_receiver(&mut self, vni: u32, group_ip: Ipv4Address, vtep: Ipv4Address) {
        if vtep != self.local_vtep {
            self.selective_vtep_map
                .entry((vni, group_ip))
                .or_default()
                .insert(vtep);
        }
    }

    /// Resolves target replication VTEP list for an ingress multicast frame.
    pub fn resolve_replication_targets(
        &mut self,
        vni: u32,
        group_ip: Ipv4Address,
    ) -> Vec<Ipv4Address> {
        self.total_multicast_frames_ingressed += 1;

        if let Some(selective_leaves) = self.selective_vtep_map.get(&(vni, group_ip)) {
            // Selective tree exists: replicate only to interested leaves!
            let targets: Vec<Ipv4Address> = selective_leaves.iter().copied().collect();
            let total_imet = self
                .inclusive_vtep_map
                .get(&vni)
                .map(|s| s.len())
                .unwrap_or(0);
            if total_imet > targets.len() {
                self.total_leaves_pruned += (total_imet - targets.len()) as u64;
            }
            self.total_copies_replicated += targets.len() as u64;
            targets
        } else if let Some(inclusive_leaves) = self.inclusive_vtep_map.get(&vni) {
            // Fallback to inclusive replication
            let targets: Vec<Ipv4Address> = inclusive_leaves.iter().copied().collect();
            self.total_copies_replicated += targets.len() as u64;
            targets
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_umt_selective_pruning() {
        let local_pe = Ipv4Address::new(192, 168, 0, 1);
        let mut umt = EvpnUmtEngine::new(local_pe);

        let pe2 = Ipv4Address::new(192, 168, 0, 2);
        let pe3 = Ipv4Address::new(192, 168, 0, 3);
        let pe4 = Ipv4Address::new(192, 168, 0, 4);

        // All 3 remote PEs in IMET for VNI 500
        umt.add_inclusive_vtep(500, pe2);
        umt.add_inclusive_vtep(500, pe3);
        umt.add_inclusive_vtep(500, pe4);

        // Only PE2 joined selective multicast group 239.1.1.1
        let mcast_group = Ipv4Address::new(239, 1, 1, 1);
        umt.add_selective_receiver(500, mcast_group, pe2);

        // Multicast to 239.1.1.1 -> Only replicates to PE2, PE3 & PE4 are pruned!
        let targets = umt.resolve_replication_targets(500, mcast_group);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0], pe2);
        assert_eq!(umt.total_leaves_pruned, 2);

        // Multicast to unjoined 239.2.2.2 -> Fallback to inclusive (all 3 PEs)
        let unjoined = Ipv4Address::new(239, 2, 2, 2);
        let targets_all = umt.resolve_replication_targets(500, unjoined);
        assert_eq!(targets_all.len(), 3);
    }
}

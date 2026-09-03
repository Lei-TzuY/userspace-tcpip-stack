//! EVPN Optimized Selective Multicast (S-PMSI) Trees (RFC 9572 / RFC 6514 Section 4.2)
//!
//! Provides BGP EVPN Route Type 6 (S-PMSI A-D) and Route Type 7 (Leaf A-D) route serialization,
//! P-Tunnel Attribute (PTA) extended community handling, dynamic flow rate thresholding,
//! and selective leaf replication tree orchestration.
//!
//! # Standard References
//! - RFC 9572: BGP EVPN Extensions for Multicast
//! - RFC 6514: BGP Encodings and Procedures for Multicast in BGP/MPLS IP VPNs

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

/// EVPN Route Types for Multicast (RFC 9572)
pub const EVPN_ROUTE_TYPE_SPMSI_AD: u8 = 6;
pub const EVPN_ROUTE_TYPE_LEAF_AD: u8 = 7;

/// P-Tunnel Attribute (PTA) Tunnel Types (RFC 6514)
pub const PTA_TUNNEL_TYPE_NO_TUNNEL: u8 = 0x00;
pub const PTA_TUNNEL_TYPE_RSVP_TE_P2MP: u8 = 0x01;
pub const PTA_TUNNEL_TYPE_MLDP_P2MP: u8 = 0x02;
pub const PTA_TUNNEL_TYPE_INGRESS_REPL: u8 = 0x06;
pub const PTA_TUNNEL_TYPE_BIER: u8 = 0x0B;

/// P-Tunnel Attribute (PTA) Flags
pub const PTA_FLAG_LEAF_INFO_REQUIRED: u8 = 0x01;

/// BGP P-Tunnel Attribute (RFC 6514 Section 5)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PTunnelAttribute {
    pub flags: u8,
    pub tunnel_type: u8,
    pub mpls_label: u32,
    pub tunnel_endpoint: Ipv4Addr,
}

impl PTunnelAttribute {
    pub fn new(flags: u8, tunnel_type: u8, mpls_label: u32, tunnel_endpoint: Ipv4Addr) -> Self {
        Self {
            flags,
            tunnel_type,
            mpls_label: mpls_label & 0x00FF_FFFF,
            tunnel_endpoint,
        }
    }

    pub fn is_leaf_info_required(&self) -> bool {
        (self.flags & PTA_FLAG_LEAF_INFO_REQUIRED) != 0
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9);
        buf.push(self.flags);
        buf.push(self.tunnel_type);
        // 3-byte MPLS label (20 bits label, 4 bits exp/bos)
        buf.push(((self.mpls_label >> 16) & 0xFF) as u8);
        buf.push(((self.mpls_label >> 8) & 0xFF) as u8);
        buf.push((self.mpls_label & 0xFF) as u8);
        buf.extend_from_slice(&self.tunnel_endpoint.octets());
        buf
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 9 {
            return Err("P-Tunnel attribute too short");
        }
        let flags = bytes[0];
        let tunnel_type = bytes[1];
        let label = ((bytes[2] as u32) << 16) | ((bytes[3] as u32) << 8) | (bytes[4] as u32);
        let endpoint = Ipv4Addr::new(bytes[5], bytes[6], bytes[7], bytes[8]);
        Ok(Self {
            flags,
            tunnel_type,
            mpls_label: label,
            tunnel_endpoint: endpoint,
        })
    }
}

/// EVPN Route Type 6: Selective Multicast Ethernet Tag (S-PMSI) A-D Route (RFC 9572 §4.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnSpmsiRoute {
    pub rd: [u8; 8],
    pub ethernet_tag_id: u32,
    pub source_ip: Ipv4Addr,
    pub group_ip: Ipv4Addr,
    pub originator_ip: Ipv4Addr,
    pub pta: Option<PTunnelAttribute>,
}

impl EvpnSpmsiRoute {
    pub fn new(
        rd: [u8; 8],
        ethernet_tag_id: u32,
        source_ip: Ipv4Addr,
        group_ip: Ipv4Addr,
        originator_ip: Ipv4Addr,
        pta: Option<PTunnelAttribute>,
    ) -> Self {
        Self {
            rd,
            ethernet_tag_id,
            source_ip,
            group_ip,
            originator_ip,
            pta,
        }
    }

    pub fn serialize_nlri(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(28);
        buf.push(EVPN_ROUTE_TYPE_SPMSI_AD);
        let nlri_len: u8 = 8 + 4 + 1 + 4 + 1 + 4 + 1 + 4; // 23 bytes NLRI payload
        buf.push(nlri_len);
        buf.extend_from_slice(&self.rd);
        buf.extend_from_slice(&self.ethernet_tag_id.to_be_bytes());
        buf.push(32); // Source prefix length
        buf.extend_from_slice(&self.source_ip.octets());
        buf.push(32); // Group prefix length
        buf.extend_from_slice(&self.group_ip.octets());
        buf.push(32); // Originator prefix length
        buf.extend_from_slice(&self.originator_ip.octets());
        buf
    }

    pub fn parse_nlri(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 25 {
            return Err("S-PMSI NLRI buffer too short");
        }
        if bytes[0] != EVPN_ROUTE_TYPE_SPMSI_AD {
            return Err("Invalid route type for S-PMSI");
        }
        let _len = bytes[1] as usize;
        let mut rd = [0u8; 8];
        rd.copy_from_slice(&bytes[2..10]);
        let ethernet_tag_id = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        let _src_len = bytes[14];
        let source_ip = Ipv4Addr::new(bytes[15], bytes[16], bytes[17], bytes[18]);
        let _grp_len = bytes[19];
        let group_ip = Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23]);
        let _orig_len = bytes[24];
        let originator_ip = Ipv4Addr::new(bytes[25], bytes[26], bytes[27], bytes[28]);

        Ok(Self {
            rd,
            ethernet_tag_id,
            source_ip,
            group_ip,
            originator_ip,
            pta: None,
        })
    }
}

/// EVPN Route Type 7: Leaf A-D Route (RFC 9572 §4.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnLeafAdRoute {
    pub rd: [u8; 8],
    pub ethernet_tag_id: u32,
    pub source_ip: Ipv4Addr,
    pub group_ip: Ipv4Addr,
    pub originator_ip: Ipv4Addr,
    pub leaf_ip: Ipv4Addr,
}

impl EvpnLeafAdRoute {
    pub fn new(
        rd: [u8; 8],
        ethernet_tag_id: u32,
        source_ip: Ipv4Addr,
        group_ip: Ipv4Addr,
        originator_ip: Ipv4Addr,
        leaf_ip: Ipv4Addr,
    ) -> Self {
        Self {
            rd,
            ethernet_tag_id,
            source_ip,
            group_ip,
            originator_ip,
            leaf_ip,
        }
    }

    pub fn serialize_nlri(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33);
        buf.push(EVPN_ROUTE_TYPE_LEAF_AD);
        let nlri_len: u8 = 8 + 4 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 4; // 28 bytes
        buf.push(nlri_len);
        buf.extend_from_slice(&self.rd);
        buf.extend_from_slice(&self.ethernet_tag_id.to_be_bytes());
        buf.push(32);
        buf.extend_from_slice(&self.source_ip.octets());
        buf.push(32);
        buf.extend_from_slice(&self.group_ip.octets());
        buf.push(32);
        buf.extend_from_slice(&self.originator_ip.octets());
        buf.push(32);
        buf.extend_from_slice(&self.leaf_ip.octets());
        buf
    }

    pub fn parse_nlri(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 30 {
            return Err("Leaf A-D NLRI buffer too short");
        }
        if bytes[0] != EVPN_ROUTE_TYPE_LEAF_AD {
            return Err("Invalid route type for Leaf A-D");
        }
        let mut rd = [0u8; 8];
        rd.copy_from_slice(&bytes[2..10]);
        let ethernet_tag_id = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        let source_ip = Ipv4Addr::new(bytes[15], bytes[16], bytes[17], bytes[18]);
        let group_ip = Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23]);
        let originator_ip = Ipv4Addr::new(bytes[25], bytes[26], bytes[27], bytes[28]);
        let leaf_ip = Ipv4Addr::new(bytes[30], bytes[31], bytes[32], bytes[33]);

        Ok(Self {
            rd,
            ethernet_tag_id,
            source_ip,
            group_ip,
            originator_ip,
            leaf_ip,
        })
    }
}

/// Delivery mode of EVPN Multicast
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastDeliveryMode {
    /// Inclusive PMSI (Replicates to all VTEPs in the EVPN instance)
    Inclusive,
    /// Selective PMSI (Replicates only to subscribed leaf VTEPs)
    Selective,
}

/// Multicast Flow State Key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastFlowKey {
    pub vni: u32,
    pub source_ip: Ipv4Addr,
    pub group_ip: Ipv4Addr,
}

/// Active S-PMSI Multicast Tree State
#[derive(Debug, Clone)]
pub struct SpmsiTreeState {
    pub key: MulticastFlowKey,
    pub mode: MulticastDeliveryMode,
    pub byte_count: u64,
    pub last_rate_bps: u64,
    pub subscribed_leaves: HashSet<Ipv4Addr>,
    pub pta: PTunnelAttribute,
}

/// EVPN Selective Multicast (S-PMSI) Orchestration Engine
#[derive(Debug)]
pub struct EvpnSpmsiEngine {
    pub local_vtep: Ipv4Addr,
    pub rate_threshold_bps: u64,
    pub all_vteps: HashSet<Ipv4Addr>,
    pub trees: HashMap<MulticastFlowKey, SpmsiTreeState>,
}

impl EvpnSpmsiEngine {
    pub fn new(local_vtep: Ipv4Addr, rate_threshold_bps: u64) -> Self {
        Self {
            local_vtep,
            rate_threshold_bps,
            all_vteps: HashSet::new(),
            trees: HashMap::new(),
        }
    }

    /// Register a fabric VTEP in the default inclusive domain
    pub fn register_vtep(&mut self, vtep: Ipv4Addr) {
        if vtep != self.local_vtep {
            self.all_vteps.insert(vtep);
        }
    }

    /// Unregister a fabric VTEP
    pub fn unregister_vtep(&mut self, vtep: &Ipv4Addr) {
        self.all_vteps.remove(vtep);
        for tree in self.trees.values_mut() {
            tree.subscribed_leaves.remove(vtep);
        }
    }

    /// Ingest multicast traffic bytes and determine if promotion to S-PMSI is required
    pub fn record_traffic(
        &mut self,
        vni: u32,
        source_ip: Ipv4Addr,
        group_ip: Ipv4Addr,
        bytes: u64,
        elapsed_secs: u64,
    ) -> (MulticastDeliveryMode, Option<EvpnSpmsiRoute>) {
        let key = MulticastFlowKey {
            vni,
            source_ip,
            group_ip,
        };

        let threshold = self.rate_threshold_bps;
        let local_vtep = self.local_vtep;

        let tree = self.trees.entry(key).or_insert_with(|| SpmsiTreeState {
            key,
            mode: MulticastDeliveryMode::Inclusive,
            byte_count: 0,
            last_rate_bps: 0,
            subscribed_leaves: HashSet::new(),
            pta: PTunnelAttribute::new(
                PTA_FLAG_LEAF_INFO_REQUIRED,
                PTA_TUNNEL_TYPE_INGRESS_REPL,
                vni,
                local_vtep,
            ),
        });

        tree.byte_count += bytes;
        let rate_bps = if elapsed_secs > 0 {
            (bytes * 8) / elapsed_secs
        } else {
            0
        };
        tree.last_rate_bps = rate_bps;

        // Check for promotion from Inclusive to Selective
        if tree.mode == MulticastDeliveryMode::Inclusive && rate_bps >= threshold {
            tree.mode = MulticastDeliveryMode::Selective;
            let spmsi_route = EvpnSpmsiRoute::new(
                [0, 1, 0, 0, 0, 0, 0, 0],
                vni,
                source_ip,
                group_ip,
                local_vtep,
                Some(tree.pta.clone()),
            );
            (MulticastDeliveryMode::Selective, Some(spmsi_route))
        } else {
            (tree.mode, None)
        }
    }

    /// Process a received Leaf A-D Route (Route Type 7) joining the S-PMSI tree
    pub fn process_leaf_join(&mut self, leaf_route: &EvpnLeafAdRoute) -> bool {
        let key = MulticastFlowKey {
            vni: leaf_route.ethernet_tag_id,
            source_ip: leaf_route.source_ip,
            group_ip: leaf_route.group_ip,
        };

        if let Some(tree) = self.trees.get_mut(&key) {
            tree.subscribed_leaves.insert(leaf_route.leaf_ip);
            true
        } else {
            false
        }
    }

    /// Process a leaf prune (Leaf A-D withdrawal)
    pub fn process_leaf_prune(
        &mut self,
        vni: u32,
        source_ip: Ipv4Addr,
        group_ip: Ipv4Addr,
        leaf_ip: &Ipv4Addr,
    ) -> bool {
        let key = MulticastFlowKey {
            vni,
            source_ip,
            group_ip,
        };

        if let Some(tree) = self.trees.get_mut(&key) {
            tree.subscribed_leaves.remove(leaf_ip);
            true
        } else {
            false
        }
    }

    /// Compute egress replication targets for an outgoing multicast frame
    pub fn get_replication_targets(
        &self,
        vni: u32,
        source_ip: Ipv4Addr,
        group_ip: Ipv4Addr,
    ) -> Vec<Ipv4Addr> {
        let key = MulticastFlowKey {
            vni,
            source_ip,
            group_ip,
        };

        if let Some(tree) = self.trees.get(&key) {
            match tree.mode {
                MulticastDeliveryMode::Inclusive => {
                    let mut list: Vec<_> = self.all_vteps.iter().copied().collect();
                    list.sort();
                    list
                }
                MulticastDeliveryMode::Selective => {
                    let mut list: Vec<_> = tree.subscribed_leaves.iter().copied().collect();
                    list.sort();
                    list
                }
            }
        } else {
            // Default to Inclusive replication across all known VTEPs
            let mut list: Vec<_> = self.all_vteps.iter().copied().collect();
            list.sort();
            list
        }
    }

    /// Checks if a multicast flow is currently in Selective (S-PMSI) delivery mode.
    pub fn is_selective(&self, vni: u32, source_ip: Ipv4Addr, group_ip: Ipv4Addr) -> bool {
        let key = MulticastFlowKey {
            vni,
            source_ip,
            group_ip,
        };
        self.trees
            .get(&key)
            .map(|t| t.mode == MulticastDeliveryMode::Selective)
            .unwrap_or(false)
    }

    /// Returns the number of flows currently using Selective (S-PMSI) trees.
    pub fn active_spmsi_count(&self) -> usize {
        self.trees
            .values()
            .filter(|t| t.mode == MulticastDeliveryMode::Selective)
            .count()
    }

    /// Explicitly demotes an S-PMSI tree back to Inclusive mode (e.g. traffic stopped or pruned).
    ///
    /// Returns the S-PMSI A-D withdrawal route if the flow was previously selective.
    pub fn demote_or_teardown_spmsi(
        &mut self,
        vni: u32,
        source_ip: Ipv4Addr,
        group_ip: Ipv4Addr,
    ) -> Option<EvpnSpmsiRoute> {
        let key = MulticastFlowKey {
            vni,
            source_ip,
            group_ip,
        };

        if let Some(tree) = self.trees.get_mut(&key) {
            if tree.mode == MulticastDeliveryMode::Selective {
                tree.mode = MulticastDeliveryMode::Inclusive;
                tree.subscribed_leaves.clear();
                tree.last_rate_bps = 0;

                let withdrawal = EvpnSpmsiRoute::new(
                    [0, 1, 0, 0, 0, 0, 0, 0],
                    vni,
                    source_ip,
                    group_ip,
                    self.local_vtep,
                    None, // No PTA indicates withdrawal / teardown
                );
                return Some(withdrawal);
            }
        }
        None
    }

    /// Audits all active S-PMSI trees and demotes those whose traffic rate has fallen below
    /// the low threshold back to Inclusive mode (RFC 9572 Section 4.2.3).
    pub fn check_demotions(&mut self, low_threshold_bps: u64) -> Vec<EvpnSpmsiRoute> {
        let mut to_demote = Vec::new();
        for (&key, tree) in &self.trees {
            if tree.mode == MulticastDeliveryMode::Selective
                && tree.last_rate_bps < low_threshold_bps
            {
                to_demote.push(key);
            }
        }

        let mut withdrawals = Vec::new();
        for key in to_demote {
            if let Some(route) = self.demote_or_teardown_spmsi(key.vni, key.source_ip, key.group_ip)
            {
                withdrawals.push(route);
            }
        }
        withdrawals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pta_codec() {
        let pta = PTunnelAttribute::new(
            PTA_FLAG_LEAF_INFO_REQUIRED,
            PTA_TUNNEL_TYPE_INGRESS_REPL,
            100500,
            Ipv4Addr::new(10, 0, 0, 1),
        );
        assert!(pta.is_leaf_info_required());
        let encoded = pta.serialize();
        assert_eq!(encoded.len(), 9);

        let parsed = PTunnelAttribute::parse(&encoded).unwrap();
        assert_eq!(parsed, pta);
    }

    #[test]
    fn test_spmsi_route_codec() {
        let route = EvpnSpmsiRoute::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            1001,
            Ipv4Addr::new(192, 168, 10, 10),
            Ipv4Addr::new(239, 1, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        let nlri = route.serialize_nlri();
        assert_eq!(nlri[0], EVPN_ROUTE_TYPE_SPMSI_AD);

        let parsed = EvpnSpmsiRoute::parse_nlri(&nlri).unwrap();
        assert_eq!(parsed.ethernet_tag_id, 1001);
        assert_eq!(parsed.source_ip, Ipv4Addr::new(192, 168, 10, 10));
        assert_eq!(parsed.group_ip, Ipv4Addr::new(239, 1, 1, 1));
        assert_eq!(parsed.originator_ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_leaf_ad_route_codec() {
        let leaf = EvpnLeafAdRoute::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            1001,
            Ipv4Addr::new(192, 168, 10, 10),
            Ipv4Addr::new(239, 1, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let nlri = leaf.serialize_nlri();
        assert_eq!(nlri[0], EVPN_ROUTE_TYPE_LEAF_AD);

        let parsed = EvpnLeafAdRoute::parse_nlri(&nlri).unwrap();
        assert_eq!(parsed.leaf_ip, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn test_spmsi_engine_promotion_and_replication() {
        let mut engine = EvpnSpmsiEngine::new(Ipv4Addr::new(10, 0, 0, 1), 1_000_000); // 1 Mbps threshold

        let leaf2 = Ipv4Addr::new(10, 0, 0, 2);
        let leaf3 = Ipv4Addr::new(10, 0, 0, 3);
        let leaf4 = Ipv4Addr::new(10, 0, 0, 4);

        engine.register_vtep(leaf2);
        engine.register_vtep(leaf3);
        engine.register_vtep(leaf4);

        let src = Ipv4Addr::new(192, 168, 1, 100);
        let grp = Ipv4Addr::new(239, 255, 1, 1);

        // Low rate traffic stays Inclusive
        let (mode, spmsi_opt) = engine.record_traffic(2000, src, grp, 50_000, 1);
        assert_eq!(mode, MulticastDeliveryMode::Inclusive);
        assert!(spmsi_opt.is_none());

        let targets = engine.get_replication_targets(2000, src, grp);
        assert_eq!(targets.len(), 3); // All 3 leaves

        // High rate burst (2 MB in 1 sec = 16 Mbps > 1 Mbps) -> triggers promotion
        let (mode, spmsi_opt) = engine.record_traffic(2000, src, grp, 2_000_000, 1);
        assert_eq!(mode, MulticastDeliveryMode::Selective);
        assert!(spmsi_opt.is_some());

        // Prior to any leaf join, selective targets is empty
        let targets_spmsi = engine.get_replication_targets(2000, src, grp);
        assert_eq!(targets_spmsi.len(), 0);

        // Leaf 2 and Leaf 3 send Leaf A-D routes
        let leaf2_ad =
            EvpnLeafAdRoute::new([0; 8], 2000, src, grp, Ipv4Addr::new(10, 0, 0, 1), leaf2);
        let leaf3_ad =
            EvpnLeafAdRoute::new([0; 8], 2000, src, grp, Ipv4Addr::new(10, 0, 0, 1), leaf3);
        assert!(engine.process_leaf_join(&leaf2_ad));
        assert!(engine.process_leaf_join(&leaf3_ad));

        // Now selective replication targets Leaf 2 and Leaf 3 only (Leaf 4 excluded)
        let targets_after_join = engine.get_replication_targets(2000, src, grp);
        assert_eq!(targets_after_join, vec![leaf2, leaf3]);

        // Leaf 2 leaves (prunes)
        assert!(engine.process_leaf_prune(2000, src, grp, &leaf2));
        let targets_after_prune = engine.get_replication_targets(2000, src, grp);
        assert_eq!(targets_after_prune, vec![leaf3]);
    }
}

//! IS-IS Segment Routing Extensions (RFC 8667)
//!
//! Implements IS-IS TLV/sub-TLV encoding for Segment Routing:
//! - SR Capability sub-TLV (SID/Label Range, SRGB)
//! - Prefix-SID sub-TLV (node SID, algorithm, flags)
//! - Adjacency-SID sub-TLV (per-adjacency label)
//! - SID/Label Binding TLV
//! - SR Algorithm sub-TLV
//!
//! Reference: RFC 8667, RFC 8665 (OSPF-SR), RFC 8402 (SR Architecture)

use std::collections::HashMap;

// ─── IS-IS TLV Types for SR ───

/// IS-IS Router Capability TLV type (RFC 7981).
pub const ISIS_TLV_ROUTER_CAPABILITY: u8 = 242;

/// IS-IS Extended IP Reachability TLV type (RFC 5305).
pub const ISIS_TLV_EXTENDED_IP_REACH: u8 = 135;

/// IS-IS Extended IS Reachability TLV type (RFC 5305).
pub const ISIS_TLV_EXTENDED_IS_REACH: u8 = 22;

/// IS-IS IPv6 IP Reachability TLV type (RFC 5308).
pub const ISIS_TLV_IPV6_IP_REACH: u8 = 236;

/// IS-IS SID/Label Binding TLV type (RFC 8667 §2.4).
pub const ISIS_TLV_SID_LABEL_BINDING: u8 = 149;

// ─── Sub-TLV Types ───

/// SR Capability sub-TLV type (RFC 8667 §3).
pub const ISIS_SUBTLV_SR_CAPABILITY: u8 = 2;

/// SR Algorithm sub-TLV type (RFC 8667 §3.2).
pub const ISIS_SUBTLV_SR_ALGORITHM: u8 = 19;

/// Prefix-SID sub-TLV type (RFC 8667 §2.1).
pub const ISIS_SUBTLV_PREFIX_SID: u8 = 3;

/// Adjacency-SID sub-TLV type (RFC 8667 §2.2).
pub const ISIS_SUBTLV_ADJ_SID: u8 = 31;

/// LAN Adjacency-SID sub-TLV type (RFC 8667 §2.3).
pub const ISIS_SUBTLV_LAN_ADJ_SID: u8 = 32;

// ─── SR Capability Flags ───

/// I-flag: IPv4 MPLS forwarding capability.
pub const SR_CAP_FLAG_IPV4_MPLS: u8 = 0x80;

/// V-flag: IPv6 MPLS forwarding capability.
pub const SR_CAP_FLAG_IPV6_MPLS: u8 = 0x40;

// ─── Prefix-SID Flags ───

/// R-flag: Re-advertisement flag.
pub const PREFIX_SID_FLAG_R: u8 = 0x80;

/// N-flag: Node-SID flag (identifies a node, not a prefix).
pub const PREFIX_SID_FLAG_N: u8 = 0x40;

/// P-flag: No-PHP (no Penultimate Hop Popping).
pub const PREFIX_SID_FLAG_P: u8 = 0x20;

/// E-flag: Explicit-Null flag.
pub const PREFIX_SID_FLAG_E: u8 = 0x10;

/// V-flag: Value flag (SID is an absolute value, not an index).
pub const PREFIX_SID_FLAG_V: u8 = 0x08;

/// L-flag: Local flag (SID has local significance).
pub const PREFIX_SID_FLAG_L: u8 = 0x04;

// ─── Adjacency-SID Flags ───

/// F-flag: Address-Family flag (set = IPv6).
pub const ADJ_SID_FLAG_F: u8 = 0x80;

/// B-flag: Backup flag (protection adjacency).
pub const ADJ_SID_FLAG_B: u8 = 0x40;

/// V-flag: Value flag (SID is an absolute value).
pub const ADJ_SID_FLAG_V: u8 = 0x20;

/// L-flag: Local flag (SID has local significance).
pub const ADJ_SID_FLAG_L: u8 = 0x10;

/// S-flag: Set flag (part of a set of Adj-SIDs).
pub const ADJ_SID_FLAG_S: u8 = 0x08;

/// P-flag: Persistent flag (always advertised).
pub const ADJ_SID_FLAG_P: u8 = 0x04;

// ─── SR Algorithms ───

/// Shortest Path First (SPF) algorithm (default).
pub const SR_ALGORITHM_SPF: u8 = 0;

/// Strict Shortest Path First (S-SPF).
pub const SR_ALGORITHM_STRICT_SPF: u8 = 1;

/// SRGB (Segment Routing Global Block) — label range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrgbRange {
    /// Base label value.
    pub range_base: u32,
    /// Range size (number of labels).
    pub range_size: u32,
}

impl SrgbRange {
    pub fn new(base: u32, size: u32) -> Self {
        Self {
            range_base: base,
            range_size: size,
        }
    }

    /// Check if a given SID index falls within this SRGB range.
    pub fn contains_index(&self, index: u32) -> bool {
        index < self.range_size
    }

    /// Convert a SID index to an absolute MPLS label.
    pub fn index_to_label(&self, index: u32) -> Option<u32> {
        if self.contains_index(index) {
            Some(self.range_base + index)
        } else {
            None
        }
    }
}

/// SR Capability sub-TLV data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsisSegmentRoutingCapability {
    /// SR Capability flags (I, V bits).
    pub flags: u8,
    /// SRGB ranges (typically one, but spec allows multiple).
    pub srgb_ranges: Vec<SrgbRange>,
}

impl IsisSegmentRoutingCapability {
    pub fn new(flags: u8) -> Self {
        Self {
            flags,
            srgb_ranges: Vec::new(),
        }
    }

    /// Add an SRGB range.
    pub fn add_srgb(&mut self, range: SrgbRange) {
        self.srgb_ranges.push(range);
    }

    /// Check if IPv4 MPLS forwarding is supported.
    pub fn ipv4_mpls(&self) -> bool {
        (self.flags & SR_CAP_FLAG_IPV4_MPLS) != 0
    }

    /// Check if IPv6 MPLS forwarding is supported.
    pub fn ipv6_mpls(&self) -> bool {
        (self.flags & SR_CAP_FLAG_IPV6_MPLS) != 0
    }

    /// Serialize to sub-TLV bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(ISIS_SUBTLV_SR_CAPABILITY);
        // Placeholder for length
        let len_pos = buf.len();
        buf.push(0);

        buf.push(self.flags);
        buf.push(0); // Reserved

        for range in &self.srgb_ranges {
            // Range size: 3 bytes
            let size_bytes = range.range_size.to_be_bytes();
            buf.push(size_bytes[1]);
            buf.push(size_bytes[2]);
            buf.push(size_bytes[3]);

            // SID/Label sub-TLV: Type=1, Length=3, Value=label (3 bytes)
            buf.push(1); // SID/Label type
            buf.push(3); // Length
            let label_bytes = range.range_base.to_be_bytes();
            buf.push(label_bytes[1]);
            buf.push(label_bytes[2]);
            buf.push(label_bytes[3]);
        }

        // Fill in length
        let total_len = buf.len() - len_pos - 1;
        buf[len_pos] = total_len as u8;

        buf
    }
}

/// Prefix-SID sub-TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsisPrefixSid {
    /// Prefix-SID flags.
    pub flags: u8,
    /// SR Algorithm (0 = SPF, 1 = Strict-SPF).
    pub algorithm: u8,
    /// SID value (index into SRGB, or absolute label if V-flag is set).
    pub sid_value: u32,
}

impl IsisPrefixSid {
    pub fn new(flags: u8, algorithm: u8, sid_value: u32) -> Self {
        Self {
            flags,
            algorithm,
            sid_value,
        }
    }

    /// Create a Node-SID with typical flags.
    pub fn node_sid(sid_index: u32, algorithm: u8) -> Self {
        Self::new(
            PREFIX_SID_FLAG_R | PREFIX_SID_FLAG_N | PREFIX_SID_FLAG_P,
            algorithm,
            sid_index,
        )
    }

    /// Check if this is a Node-SID.
    pub fn is_node_sid(&self) -> bool {
        (self.flags & PREFIX_SID_FLAG_N) != 0
    }

    /// Check if the V-flag is set (absolute value, not index).
    pub fn is_absolute(&self) -> bool {
        (self.flags & PREFIX_SID_FLAG_V) != 0
    }

    /// Check if No-PHP is requested.
    pub fn no_php(&self) -> bool {
        (self.flags & PREFIX_SID_FLAG_P) != 0
    }

    /// Check if Explicit-Null is requested.
    pub fn explicit_null(&self) -> bool {
        (self.flags & PREFIX_SID_FLAG_E) != 0
    }

    /// Serialize to sub-TLV bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(ISIS_SUBTLV_PREFIX_SID);

        if self.is_absolute() {
            // V-flag set: 3-byte label
            buf.push(5); // Length: flags(1) + algo(1) + label(3)
            buf.push(self.flags);
            buf.push(self.algorithm);
            let label_bytes = self.sid_value.to_be_bytes();
            buf.push(label_bytes[1]);
            buf.push(label_bytes[2]);
            buf.push(label_bytes[3]);
        } else {
            // Index: 4-byte SID index
            buf.push(6); // Length: flags(1) + algo(1) + index(4)
            buf.push(self.flags);
            buf.push(self.algorithm);
            buf.extend_from_slice(&self.sid_value.to_be_bytes());
        }

        buf
    }
}

/// Adjacency-SID sub-TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsisAdjacencySid {
    /// Adjacency-SID flags.
    pub flags: u8,
    /// Weight for load balancing.
    pub weight: u8,
    /// SID value (absolute MPLS label).
    pub sid_value: u32,
    /// System ID of the neighbor (for LAN Adj-SID).
    pub neighbor_system_id: Option<[u8; 6]>,
}

impl IsisAdjacencySid {
    pub fn new(flags: u8, weight: u8, sid_value: u32) -> Self {
        Self {
            flags,
            weight,
            sid_value,
            neighbor_system_id: None,
        }
    }

    /// Create a LAN Adjacency-SID with neighbor system ID.
    pub fn lan_adj_sid(
        flags: u8,
        weight: u8,
        sid_value: u32,
        neighbor_sys_id: [u8; 6],
    ) -> Self {
        Self {
            flags,
            weight,
            sid_value,
            neighbor_system_id: Some(neighbor_sys_id),
        }
    }

    /// Check if this is a backup (protection) adjacency.
    pub fn is_backup(&self) -> bool {
        (self.flags & ADJ_SID_FLAG_B) != 0
    }

    /// Check if the SID has local significance only.
    pub fn is_local(&self) -> bool {
        (self.flags & ADJ_SID_FLAG_L) != 0
    }

    /// Serialize to sub-TLV bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        if self.neighbor_system_id.is_some() {
            buf.push(ISIS_SUBTLV_LAN_ADJ_SID);
        } else {
            buf.push(ISIS_SUBTLV_ADJ_SID);
        }

        let label_bytes = self.sid_value.to_be_bytes();

        if let Some(sys_id) = &self.neighbor_system_id {
            // LAN Adj-SID: flags(1) + weight(1) + sys_id(6) + label(3)
            buf.push(11);
            buf.push(self.flags);
            buf.push(self.weight);
            buf.extend_from_slice(sys_id);
            buf.push(label_bytes[1]);
            buf.push(label_bytes[2]);
            buf.push(label_bytes[3]);
        } else {
            // Adj-SID: flags(1) + weight(1) + label(3)
            buf.push(5);
            buf.push(self.flags);
            buf.push(self.weight);
            buf.push(label_bytes[1]);
            buf.push(label_bytes[2]);
            buf.push(label_bytes[3]);
        }

        buf
    }
}

/// IS-IS SR node database entry.
#[derive(Debug, Clone)]
pub struct IsisSegmentRoutingNode {
    /// IS-IS System ID (6 bytes).
    pub system_id: [u8; 6],
    /// SR Capability (SRGB).
    pub sr_capability: IsisSegmentRoutingCapability,
    /// Supported SR algorithms.
    pub algorithms: Vec<u8>,
    /// Prefix-SIDs advertised by this node.
    pub prefix_sids: Vec<(u32, u8, IsisPrefixSid)>, // (prefix_as_u32, prefix_len, sid)
    /// Adjacency-SIDs advertised by this node.
    pub adjacency_sids: Vec<IsisAdjacencySid>,
}

/// IS-IS Segment Routing Database (SRDB).
///
/// Aggregates SR capabilities, Prefix-SIDs, and Adj-SIDs from all
/// IS-IS nodes in the area/domain.
#[derive(Debug)]
pub struct IsisSegmentRoutingDatabase {
    /// Per-node SR entries, keyed by System ID.
    pub nodes: HashMap<[u8; 6], IsisSegmentRoutingNode>,
    /// Local SRGB for label resolution.
    pub local_srgb: SrgbRange,
}

impl IsisSegmentRoutingDatabase {
    pub fn new(local_srgb: SrgbRange) -> Self {
        Self {
            nodes: HashMap::new(),
            local_srgb,
        }
    }

    /// Register a remote node's SR capability.
    pub fn register_node(
        &mut self,
        system_id: [u8; 6],
        sr_capability: IsisSegmentRoutingCapability,
        algorithms: Vec<u8>,
    ) {
        let node = IsisSegmentRoutingNode {
            system_id,
            sr_capability,
            algorithms,
            prefix_sids: Vec::new(),
            adjacency_sids: Vec::new(),
        };
        self.nodes.insert(system_id, node);
    }

    /// Add a Prefix-SID for a node.
    pub fn add_prefix_sid(
        &mut self,
        system_id: &[u8; 6],
        prefix: u32,
        prefix_len: u8,
        prefix_sid: IsisPrefixSid,
    ) -> bool {
        if let Some(node) = self.nodes.get_mut(system_id) {
            node.prefix_sids.push((prefix, prefix_len, prefix_sid));
            true
        } else {
            false
        }
    }

    /// Add an Adjacency-SID for a node.
    pub fn add_adjacency_sid(
        &mut self,
        system_id: &[u8; 6],
        adj_sid: IsisAdjacencySid,
    ) -> bool {
        if let Some(node) = self.nodes.get_mut(system_id) {
            node.adjacency_sids.push(adj_sid);
            true
        } else {
            false
        }
    }

    /// Resolve a SID index to an MPLS label using the local SRGB.
    pub fn resolve_sid_to_label(&self, sid_index: u32) -> Option<u32> {
        self.local_srgb.index_to_label(sid_index)
    }

    /// Resolve a SID index using a remote node's SRGB.
    pub fn resolve_remote_sid(
        &self,
        system_id: &[u8; 6],
        sid_index: u32,
    ) -> Option<u32> {
        let node = self.nodes.get(system_id)?;
        node.sr_capability
            .srgb_ranges
            .first()
            .and_then(|srgb| srgb.index_to_label(sid_index))
    }

    /// Find the Node-SID for a given system ID.
    pub fn find_node_sid(&self, system_id: &[u8; 6]) -> Option<&IsisPrefixSid> {
        let node = self.nodes.get(system_id)?;
        node.prefix_sids
            .iter()
            .find(|(_, _, sid)| sid.is_node_sid())
            .map(|(_, _, sid)| sid)
    }

    /// Get total count of nodes in the SRDB.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get total count of Prefix-SIDs across all nodes.
    pub fn total_prefix_sids(&self) -> usize {
        self.nodes.values().map(|n| n.prefix_sids.len()).sum()
    }

    /// Get total count of Adjacency-SIDs across all nodes.
    pub fn total_adjacency_sids(&self) -> usize {
        self.nodes.values().map(|n| n.adjacency_sids.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srgb_index_to_label() {
        let srgb = SrgbRange::new(16000, 8000);
        assert_eq!(srgb.index_to_label(0), Some(16000));
        assert_eq!(srgb.index_to_label(100), Some(16100));
        assert_eq!(srgb.index_to_label(7999), Some(23999));
        assert_eq!(srgb.index_to_label(8000), None);
    }

    #[test]
    fn test_prefix_sid_serialization() {
        let node_sid = IsisPrefixSid::node_sid(100, SR_ALGORITHM_SPF);
        assert!(node_sid.is_node_sid());
        assert!(node_sid.no_php());
        assert!(!node_sid.is_absolute());

        let bytes = node_sid.serialize();
        assert_eq!(bytes[0], ISIS_SUBTLV_PREFIX_SID);
        assert_eq!(bytes.len(), 8); // type(1) + len(1) + flags(1) + algo(1) + index(4)
    }

    #[test]
    fn test_adj_sid_serialization() {
        let adj_sid = IsisAdjacencySid::new(
            ADJ_SID_FLAG_V | ADJ_SID_FLAG_L,
            0,
            24001,
        );
        assert!(!adj_sid.is_backup());
        assert!(adj_sid.is_local());

        let bytes = adj_sid.serialize();
        assert_eq!(bytes[0], ISIS_SUBTLV_ADJ_SID);
        assert_eq!(bytes.len(), 7); // type(1) + len(1) + flags(1) + weight(1) + label(3)
    }

    #[test]
    fn test_isis_srdb_full_lifecycle() {
        let local_srgb = SrgbRange::new(16000, 8000);
        let mut srdb = IsisSegmentRoutingDatabase::new(local_srgb);

        // Register Node A
        let node_a_sys_id = [0x01, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut cap_a = IsisSegmentRoutingCapability::new(SR_CAP_FLAG_IPV4_MPLS);
        cap_a.add_srgb(SrgbRange::new(16000, 8000));
        srdb.register_node(node_a_sys_id, cap_a, vec![SR_ALGORITHM_SPF]);

        // Register Node B
        let node_b_sys_id = [0x01, 0x00, 0x00, 0x00, 0x00, 0x02];
        let mut cap_b = IsisSegmentRoutingCapability::new(SR_CAP_FLAG_IPV4_MPLS | SR_CAP_FLAG_IPV6_MPLS);
        cap_b.add_srgb(SrgbRange::new(16000, 8000));
        srdb.register_node(node_b_sys_id, cap_b, vec![SR_ALGORITHM_SPF, SR_ALGORITHM_STRICT_SPF]);

        // Add Prefix-SIDs
        let node_a_sid = IsisPrefixSid::node_sid(100, SR_ALGORITHM_SPF);
        srdb.add_prefix_sid(&node_a_sys_id, 0x0A010101, 32, node_a_sid);

        let node_b_sid = IsisPrefixSid::node_sid(200, SR_ALGORITHM_SPF);
        srdb.add_prefix_sid(&node_b_sys_id, 0x0A010102, 32, node_b_sid);

        // Add Adj-SID from A to B
        let adj_a_to_b = IsisAdjacencySid::new(ADJ_SID_FLAG_V | ADJ_SID_FLAG_L, 0, 24001);
        srdb.add_adjacency_sid(&node_a_sys_id, adj_a_to_b);

        // Verify
        assert_eq!(srdb.node_count(), 2);
        assert_eq!(srdb.total_prefix_sids(), 2);
        assert_eq!(srdb.total_adjacency_sids(), 1);

        // Resolve SID index 100 → label 16100
        assert_eq!(srdb.resolve_sid_to_label(100), Some(16100));
        assert_eq!(srdb.resolve_remote_sid(&node_b_sys_id, 200), Some(16200));

        // Find Node-SID
        let found = srdb.find_node_sid(&node_a_sys_id).unwrap();
        assert_eq!(found.sid_value, 100);
        assert!(found.is_node_sid());
    }
}

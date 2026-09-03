//! Segment Routing over MPLS (SR-MPLS) Data Plane & TI-LFA Engine (RFC 8660 / RFC 8667 / RFC 8402).
//!
//! Provides SRGB / SRLB label indexing, Node-SID / Prefix-SID / Adj-SID label translation,
//! SR-MPLS ingress encapsulation, transit label swapping/popping, and TI-LFA sub-50ms protection paths.

use crate::ipv4::Ipv4Address;
use crate::mpls::MplsHeader;
use std::collections::HashMap;

/// Segment Routing Global Block (SRGB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srgb {
    pub start_label: u32,
    pub range_size: u32,
}

impl Default for Srgb {
    fn default() -> Self {
        Srgb {
            start_label: 16000,
            range_size: 8000, // [16000..24000)
        }
    }
}

impl Srgb {
    pub fn new(start_label: u32, range_size: u32) -> Self {
        Srgb {
            start_label,
            range_size,
        }
    }

    /// Maps a 0-based SID index to an absolute MPLS label.
    pub fn index_to_label(&self, index: u32) -> Option<u32> {
        if index < self.range_size {
            Some(self.start_label + index)
        } else {
            None
        }
    }

    /// Maps an MPLS label back to a SID index if within SRGB.
    pub fn label_to_index(&self, label: u32) -> Option<u32> {
        if label >= self.start_label && label < self.start_label + self.range_size {
            Some(label - self.start_label)
        } else {
            None
        }
    }
}

/// Segment Routing Local Block (SRLB) for dynamic locally-scoped SIDs (e.g., Adj-SIDs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srlb {
    pub start_label: u32,
    pub range_size: u32,
}

impl Default for Srlb {
    fn default() -> Self {
        Srlb {
            start_label: 15000,
            range_size: 1000, // [15000..16000)
        }
    }
}

impl Srlb {
    pub fn new(start_label: u32, range_size: u32) -> Self {
        Srlb {
            start_label,
            range_size,
        }
    }
}

/// SR-MPLS Segment Types (RFC 8402).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrSegment {
    NodeSid {
        router_id: Ipv4Address,
        index: u32,
    },
    PrefixSid {
        prefix: Ipv4Address,
        prefix_len: u8,
        index: u32,
        penultimate_hop_popping: bool,
    },
    AdjSid {
        local_interface: u32,
        peer_router_id: Ipv4Address,
        label: u32,
    },
    BindingSid {
        bsid: u32,
        segment_stack: Vec<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrAction {
    Pop,
    Swap(u32),
    Push(Vec<u32>),
    ForwardPayload,
}

/// SR-MPLS Forwarding Engine and LFIB table.
#[derive(Debug, Clone, Default)]
pub struct SrMplsEngine {
    pub srgb: Srgb,
    pub srlb: Srlb,
    pub node_sids: HashMap<Ipv4Address, u32>,
    pub adj_sids: HashMap<(u32, Ipv4Address), u32>,
    pub binding_sids: HashMap<u32, Vec<u32>>,
}

impl SrMplsEngine {
    pub fn new(srgb: Srgb, srlb: Srlb) -> Self {
        SrMplsEngine {
            srgb,
            srlb,
            node_sids: HashMap::new(),
            adj_sids: HashMap::new(),
            binding_sids: HashMap::new(),
        }
    }

    pub fn register_node_sid(&mut self, router_id: Ipv4Address, index: u32) {
        self.node_sids.insert(router_id, index);
    }

    pub fn register_adj_sid(&mut self, local_if: u32, peer_router_id: Ipv4Address, label: u32) {
        self.adj_sids.insert((local_if, peer_router_id), label);
    }

    pub fn register_binding_sid(&mut self, bsid: u32, stack: Vec<u32>) {
        self.binding_sids.insert(bsid, stack);
    }

    /// Resolves a Node-SID to its absolute MPLS label.
    pub fn resolve_node_sid(&self, router_id: Ipv4Address) -> Option<u32> {
        let idx = *self.node_sids.get(&router_id)?;
        self.srgb.index_to_label(idx)
    }

    /// Encapsulates an IP packet with an SR-MPLS label stack (Ingress node).
    pub fn push_label_stack(&self, payload: &[u8], labels: &[u32], default_ttl: u8) -> Vec<u8> {
        if labels.is_empty() {
            return payload.to_vec();
        }
        let mut buf = Vec::with_capacity(labels.len() * 4 + payload.len());
        for (i, &label) in labels.iter().enumerate() {
            let is_bottom = i == labels.len() - 1;
            let hdr = MplsHeader::new(label, 0, is_bottom, default_ttl);
            buf.extend_from_slice(&hdr.serialize());
        }
        buf.extend_from_slice(payload);
        buf
    }

    /// Processes an incoming SR-MPLS packet (Transit or Egress node).
    pub fn process_incoming_mpls(&self, data: &[u8]) -> Option<(SrAction, Vec<u8>)> {
        if data.len() < 4 {
            return None;
        }
        let top_header = MplsHeader::parse(&data[0..4]).ok()?;
        let rest = data[4..].to_vec();

        // 1. Check Binding SID expansion
        if let Some(stack) = self.binding_sids.get(&top_header.label) {
            let new_packet = self.push_label_stack(&rest, stack, top_header.ttl.saturating_sub(1));
            return Some((SrAction::Push(stack.clone()), new_packet));
        }

        // 2. If Bottom-of-Stack: pop and forward inner payload
        if top_header.bottom_of_stack {
            return Some((SrAction::ForwardPayload, rest));
        }

        // 3. Normal Transit swap/pop
        if top_header.ttl <= 1 {
            return None; // Drop on TTL expiry
        }

        Some((SrAction::Pop, rest))
    }
}

/// Topology-Independent Loop-Free Alternate (TI-LFA) Protection Engine (RFC 8667).
#[derive(Debug, Clone, Default)]
pub struct TiLfaEngine;

impl TiLfaEngine {
    /// Computes backup SR-MPLS label repair stack for surviving link failure.
    ///
    /// When protecting link S -> E:
    /// - P-Node: Last node on post-convergence path reachable from S without traversing S -> E.
    /// - Q-Node: First node on post-convergence path that can reach destination D without traversing S -> E.
    pub fn compute_repair_stack(
        p_node_label: Option<u32>,
        adj_p_q_label: Option<u32>,
        dest_prefix_label: u32,
    ) -> Vec<u32> {
        let mut stack = Vec::new();
        if let Some(p) = p_node_label {
            stack.push(p);
        }
        if let Some(adj) = adj_p_q_label {
            stack.push(adj);
        }
        stack.push(dest_prefix_label);
        stack
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srgb_and_srlb_label_mapping() {
        let srgb = Srgb::new(16000, 8000);
        assert_eq!(srgb.index_to_label(100), Some(16100));
        assert_eq!(srgb.label_to_index(16100), Some(100));
        assert_eq!(srgb.label_to_index(15999), None);
        assert_eq!(srgb.label_to_index(24000), None);
    }

    #[test]
    fn test_sr_mpls_ingress_encapsulation_and_transit() {
        let mut engine = SrMplsEngine::new(Srgb::default(), Srlb::default());
        let router_a = Ipv4Address([10, 0, 0, 1]);
        let router_b = Ipv4Address([10, 0, 0, 2]);

        engine.register_node_sid(router_a, 10); // Label 16010
        engine.register_node_sid(router_b, 20); // Label 16020

        let payload = b"HELLO-SR-MPLS";
        let label_stack = vec![16010, 16020];
        let mpls_packet = engine.push_label_stack(payload, &label_stack, 64);
        assert_eq!(mpls_packet.len(), 8 + payload.len());

        // Transit router pops top label 16010
        let (action1, next_pkt) = engine.process_incoming_mpls(&mpls_packet).unwrap();
        assert_eq!(action1, SrAction::Pop);
        assert_eq!(next_pkt.len(), 4 + payload.len());

        // Egress router pops bottom label 16020 -> yields raw payload
        let (action2, final_payload) = engine.process_incoming_mpls(&next_pkt).unwrap();
        assert_eq!(action2, SrAction::ForwardPayload);
        assert_eq!(final_payload, payload);
    }

    #[test]
    fn test_ti_lfa_repair_stack_generation() {
        let p_node_sid = 16005;
        let adj_sid = 15002;
        let dest_sid = 16009;

        let repair_stack =
            TiLfaEngine::compute_repair_stack(Some(p_node_sid), Some(adj_sid), dest_sid);
        assert_eq!(repair_stack, vec![16005, 15002, 16009]);
    }
}

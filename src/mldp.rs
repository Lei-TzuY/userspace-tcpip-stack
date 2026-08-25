//! Multipoint LDP (mLDP) Extensions for Point-to-Multipoint (P2MP) and Multipoint-to-Multipoint (MP2MP) LSPs (RFC 6388 / RFC 6513).
//!
//! Implements mLDP Multipoint FEC elements (Types 6, 7, 8), Root Node resolution,
//! Opaque Value TLVs (Generic LSP ID, Extended Transit ID), and MPLS core multicast branch replication.

use crate::ipv4::Ipv4Address;
use crate::mpls::MplsHeader;
use std::collections::HashMap;

/// mLDP FEC Element Types (RFC 6388 Section 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MldpFecType {
    /// Point-to-Multipoint (P2MP) FEC Element (Type 6).
    P2mp = 6,
    /// Multipoint-to-Multipoint (MP2MP) Upstream FEC Element (Type 7).
    Mp2mpUpstream = 7,
    /// Multipoint-to-Multipoint (MP2MP) Downstream FEC Element (Type 8).
    Mp2mpDownstream = 8,
}

impl MldpFecType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            6 => Some(MldpFecType::P2mp),
            7 => Some(MldpFecType::Mp2mpUpstream),
            8 => Some(MldpFecType::Mp2mpDownstream),
            _ => None,
        }
    }
}

/// mLDP Opaque Value Types (RFC 6388 Section 2.2).
pub const MLDP_OPAQUE_TYPE_GENERIC_LSP_ID: u8 = 1;
pub const MLDP_OPAQUE_TYPE_EXTENDED_TRANSIT_ID: u8 = 2;
pub const MLDP_OPAQUE_TYPE_OPAQUE_BYTES: u8 = 255;

/// mLDP Multipoint FEC Element (RFC 6388 Section 2.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MldpFecElement {
    pub fec_type: MldpFecType,
    pub root_node: Ipv4Address,
    pub opaque_type: u8,
    pub opaque_value: Vec<u8>,
}

impl MldpFecElement {
    pub fn new_p2mp_generic(root_node: Ipv4Address, lsp_id: u32) -> Self {
        MldpFecElement {
            fec_type: MldpFecType::P2mp,
            root_node,
            opaque_type: MLDP_OPAQUE_TYPE_GENERIC_LSP_ID,
            opaque_value: lsp_id.to_be_bytes().to_vec(),
        }
    }

    pub fn new_mp2mp_upstream_generic(root_node: Ipv4Address, lsp_id: u32) -> Self {
        MldpFecElement {
            fec_type: MldpFecType::Mp2mpUpstream,
            root_node,
            opaque_type: MLDP_OPAQUE_TYPE_GENERIC_LSP_ID,
            opaque_value: lsp_id.to_be_bytes().to_vec(),
        }
    }

    pub fn new_mp2mp_downstream_generic(root_node: Ipv4Address, lsp_id: u32) -> Self {
        MldpFecElement {
            fec_type: MldpFecType::Mp2mpDownstream,
            root_node,
            opaque_type: MLDP_OPAQUE_TYPE_GENERIC_LSP_ID,
            opaque_value: lsp_id.to_be_bytes().to_vec(),
        }
    }

    pub fn generic_lsp_id(&self) -> Option<u32> {
        if self.opaque_type == MLDP_OPAQUE_TYPE_GENERIC_LSP_ID && self.opaque_value.len() == 4 {
            Some(u32::from_be_bytes([
                self.opaque_value[0],
                self.opaque_value[1],
                self.opaque_value[2],
                self.opaque_value[3],
            ]))
        } else {
            None
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 + self.opaque_value.len());
        buf.push(self.fec_type as u8);
        buf.push(4); // Address Length (IPv4 = 4 octets)
        buf.extend_from_slice(&self.root_node.0);
        buf.push(self.opaque_type);
        buf.push(self.opaque_value.len() as u8);
        buf.extend_from_slice(&self.opaque_value);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 7 {
            return None;
        }
        let fec_type = MldpFecType::from_u8(data[0])?;
        let addr_len = data[1] as usize;
        if addr_len != 4 || data.len() < 2 + addr_len + 2 {
            return None;
        }
        let root_node = Ipv4Address::new(data[2], data[3], data[4], data[5]);
        let opaque_type = data[6];
        let opaque_len = data[7] as usize;
        if data.len() < 8 + opaque_len {
            return None;
        }
        let opaque_value = data[8..8 + opaque_len].to_vec();
        let total_consumed = 8 + opaque_len;
        Some((
            MldpFecElement {
                fec_type,
                root_node,
                opaque_type,
                opaque_value,
            },
            total_consumed,
        ))
    }
}

/// Outgoing branch for multicast packet replication in an mLDP core LSR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldpTreeBranch {
    pub out_interface: u32,
    pub out_label: u32,
}

/// mLDP Forwarding and Protocol Engine.
#[derive(Debug, Clone)]
pub struct MldpEngine {
    pub local_ip: Ipv4Address,
    pub upstream_bindings: HashMap<MldpFecElement, (Ipv4Address, u32)>, // FEC -> (Upstream LSR, Label)
    pub downstream_branches: HashMap<MldpFecElement, Vec<MldpTreeBranch>>, // FEC -> [Branches]
    pub replicated_packets_count: usize,
}

impl MldpEngine {
    pub fn new(local_ip: Ipv4Address) -> Self {
        MldpEngine {
            local_ip,
            upstream_bindings: HashMap::new(),
            downstream_branches: HashMap::new(),
            replicated_packets_count: 0,
        }
    }

    /// Sets the upstream parent LSR and assigned label for this mLDP tree FEC.
    pub fn set_upstream_parent(
        &mut self,
        fec: MldpFecElement,
        upstream_lsr: Ipv4Address,
        upstream_label: u32,
    ) {
        self.upstream_bindings
            .insert(fec, (upstream_lsr, upstream_label));
    }

    /// Adds a downstream child branch to replicate packets towards.
    pub fn add_downstream_branch(
        &mut self,
        fec: &MldpFecElement,
        out_interface: u32,
        out_label: u32,
    ) {
        let branches = self.downstream_branches.entry(fec.clone()).or_default();
        if !branches
            .iter()
            .any(|b| b.out_interface == out_interface && b.out_label == out_label)
        {
            branches.push(MldpTreeBranch {
                out_interface,
                out_label,
            });
        }
    }

    /// Removes a downstream child branch (e.g. on prune/withdraw).
    pub fn remove_downstream_branch(
        &mut self,
        fec: &MldpFecElement,
        out_interface: u32,
        out_label: u32,
    ) -> bool {
        if let Some(branches) = self.downstream_branches.get_mut(fec) {
            let initial = branches.len();
            branches.retain(|b| !(b.out_interface == out_interface && b.out_label == out_label));
            branches.len() < initial
        } else {
            false
        }
    }

    /// Replicates an ingress multicast packet across all registered downstream tree branches.
    /// Returns a list of `(out_interface, out_label, encapsulated_packet_bytes)`.
    pub fn replicate_multicast(
        &mut self,
        fec: &MldpFecElement,
        payload: &[u8],
    ) -> Vec<(u32, u32, Vec<u8>)> {
        let mut results = Vec::new();
        if let Some(branches) = self.downstream_branches.get(fec) {
            for b in branches {
                let shim = MplsHeader::new(b.out_label, 0, true, 64);
                let mut pkt = shim.serialize().to_vec();
                pkt.extend_from_slice(payload);
                results.push((b.out_interface, b.out_label, pkt));
                self.replicated_packets_count += 1;
            }
        }
        results
    }
}

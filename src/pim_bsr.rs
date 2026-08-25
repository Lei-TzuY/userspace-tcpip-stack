//! PIM Bootstrap Router (BSR) Mechanism & Source-Specific Multicast (PIM-BSR / PIM-SSM - RFC 5059 / RFC 4607 / RFC 7761).
//!
//! Implements dynamic Candidate-RP (C-RP) and Bootstrap Router (BSR) election,
//! Group-to-RP hash-based deterministic selection, and SSM (232.0.0.0/8) source-tree routing.

use crate::ipv4::Ipv4Address;
use crate::pim::{PimHeader, PimPacket, PIM_TYPE_BOOTSTRAP};

/// PIM Message Type for Candidate-RP Advertisement (RFC 5059 Section 4).
pub const PIM_TYPE_CANDIDATE_RP_ADV: u8 = 8;

/// Default PIM-SSM address range: 232.0.0.0/8 (RFC 4607).
pub const PIM_SSM_PREFIX: [u8; 4] = [232, 0, 0, 0];
pub const PIM_SSM_MASK_LEN: u8 = 8;

/// Encoded-Group Address format (RFC 5059 Section 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncodedGroupAddress {
    pub mask_len: u8,
    pub b_bit: bool, // Bidirectional PIM flag
    pub group_ip: Ipv4Address,
}

impl EncodedGroupAddress {
    pub fn new(group_ip: Ipv4Address, mask_len: u8) -> Self {
        EncodedGroupAddress {
            mask_len,
            b_bit: false,
            group_ip,
        }
    }

    pub fn encode(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = 0x01; // Family 1 (IPv4)
        buf[1] = 0x00; // Encoding Type 0
        buf[2] = if self.b_bit { 0x80 } else { 0x00 };
        buf[3] = self.mask_len;
        buf[4..8].copy_from_slice(&self.group_ip.0);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 8 {
            return None;
        }
        if data[0] != 0x01 || data[1] != 0x00 {
            return None; // Only IPv4 Native Encoding supported
        }
        let b_bit = (data[2] & 0x80) != 0;
        let mask_len = data[3];
        let group_ip = Ipv4Address([data[4], data[5], data[6], data[7]]);
        Some((
            EncodedGroupAddress {
                mask_len,
                b_bit,
                group_ip,
            },
            8,
        ))
    }
}

/// Candidate-RP Record within Group-to-RP Mapping (RFC 5059 Section 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CandidateRpRecord {
    pub rp_ip: Ipv4Address,
    pub holdtime: u16,
    pub priority: u8,
}

impl CandidateRpRecord {
    pub fn new(rp_ip: Ipv4Address, priority: u8, holdtime: u16) -> Self {
        CandidateRpRecord {
            rp_ip,
            priority,
            holdtime,
        }
    }

    pub fn encode(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = 0x01; // Family 1 (IPv4)
        buf[1] = 0x00; // Encoding Type 0
        buf[2..6].copy_from_slice(&self.rp_ip.0);
        buf[6] = self.priority;
        buf[7] = 0; // Reserved
                    // Holdtime is packed separately or within structure
        buf
    }
}

/// Group-to-RP Mapping block in Bootstrap Message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRpMapping {
    pub group: EncodedGroupAddress,
    pub rp_count: u8,
    pub frag_tag: u16,
    pub candidates: Vec<CandidateRpRecord>,
}

/// PIM Bootstrap Message (BSM - RFC 5059 Section 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimBootstrapMessage {
    pub frag_tag: u16,
    pub hash_mask_len: u8,
    pub bsr_priority: u8,
    pub bsr_ip: Ipv4Address,
    pub group_mappings: Vec<GroupRpMapping>,
}

impl PimBootstrapMessage {
    pub fn new(bsr_ip: Ipv4Address, bsr_priority: u8, hash_mask_len: u8) -> Self {
        PimBootstrapMessage {
            frag_tag: 0,
            hash_mask_len,
            bsr_priority,
            bsr_ip,
            group_mappings: Vec::new(),
        }
    }

    /// Serializes the Bootstrap message payload.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.frag_tag.to_be_bytes());
        buf.push(self.hash_mask_len);
        buf.push(self.bsr_priority);

        // Encoded Unicast BSR Address
        buf.push(0x01); // IPv4
        buf.push(0x00);
        buf.extend_from_slice(&self.bsr_ip.0);

        for gm in &self.group_mappings {
            buf.extend_from_slice(&gm.group.encode());
            buf.push(gm.candidates.len() as u8);
            buf.push(0x00); // Reserved
            buf.extend_from_slice(&gm.frag_tag.to_be_bytes());

            for crp in &gm.candidates {
                // Encoded RP Address
                buf.push(0x01);
                buf.push(0x00);
                buf.extend_from_slice(&crp.rp_ip.0);
                buf.extend_from_slice(&crp.holdtime.to_be_bytes());
                buf.push(crp.priority);
                buf.push(0x00); // Reserved
            }
        }

        buf
    }

    /// Parses a Bootstrap message payload.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let frag_tag = u16::from_be_bytes([data[0], data[1]]);
        let hash_mask_len = data[2];
        let bsr_priority = data[3];

        if data[4] != 0x01 || data[5] != 0x00 {
            return None;
        }
        let bsr_ip = Ipv4Address([data[6], data[7], data[8], data[9]]);
        let mut offset = 10;

        let mut group_mappings = Vec::new();
        while offset + 8 <= data.len() {
            let (group, consumed) = EncodedGroupAddress::decode(&data[offset..])?;
            offset += consumed;
            if offset + 4 > data.len() {
                break;
            }
            let rp_count = data[offset];
            let frag_tag = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            let mut candidates = Vec::new();
            for _ in 0..rp_count {
                if offset + 10 > data.len() {
                    break;
                }
                if data[offset] != 0x01 || data[offset + 1] != 0x00 {
                    return None;
                }
                let rp_ip =
                    Ipv4Address([data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]]);
                let holdtime = u16::from_be_bytes([data[offset + 6], data[offset + 7]]);
                let priority = data[offset + 8];
                offset += 10;
                candidates.push(CandidateRpRecord::new(rp_ip, priority, holdtime));
            }

            group_mappings.push(GroupRpMapping {
                group,
                rp_count,
                frag_tag,
                candidates,
            });
        }

        Some(PimBootstrapMessage {
            frag_tag,
            hash_mask_len,
            bsr_priority,
            bsr_ip,
            group_mappings,
        })
    }

    /// Converts this Bootstrap message to a full PIM packet.
    pub fn to_pim_packet(&self) -> PimPacket {
        let payload = self.serialize();
        PimPacket {
            header: PimHeader {
                version: 2,
                msg_type: PIM_TYPE_BOOTSTRAP,
                checksum: 0,
            },
            payload,
        }
    }
}

/// Candidate-RP Advertisement Message (RFC 5059 Section 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimCandidateRpAdv {
    pub prefix_count: u8,
    pub priority: u8,
    pub holdtime: u16,
    pub rp_ip: Ipv4Address,
    pub group_prefixes: Vec<EncodedGroupAddress>,
}

impl PimCandidateRpAdv {
    pub fn new(rp_ip: Ipv4Address, priority: u8, holdtime: u16) -> Self {
        PimCandidateRpAdv {
            prefix_count: 0,
            priority,
            holdtime,
            rp_ip,
            group_prefixes: Vec::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.group_prefixes.len() as u8);
        buf.push(self.priority);
        buf.extend_from_slice(&self.holdtime.to_be_bytes());

        // Encoded Unicast RP Address
        buf.push(0x01);
        buf.push(0x00);
        buf.extend_from_slice(&self.rp_ip.0);

        for g in &self.group_prefixes {
            buf.extend_from_slice(&g.encode());
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let prefix_count = data[0];
        let priority = data[1];
        let holdtime = u16::from_be_bytes([data[2], data[3]]);
        if data[4] != 0x01 || data[5] != 0x00 {
            return None;
        }
        let rp_ip = Ipv4Address([data[6], data[7], data[8], data[9]]);
        let mut offset = 10;

        let mut group_prefixes = Vec::new();
        for _ in 0..prefix_count {
            if offset + 8 > data.len() {
                break;
            }
            let (g, consumed) = EncodedGroupAddress::decode(&data[offset..])?;
            group_prefixes.push(g);
            offset += consumed;
        }

        Some(PimCandidateRpAdv {
            prefix_count,
            priority,
            holdtime,
            rp_ip,
            group_prefixes,
        })
    }
}

/// Dynamic PIM Bootstrap Router (BSR) & SSM Hash Selection Engine.
#[derive(Debug, Clone)]
pub struct PimBsrEngine {
    pub local_ip: Ipv4Address,
    pub is_candidate_bsr: bool,
    pub local_bsr_priority: u8,
    pub hash_mask_len: u8,
    pub elected_bsr: Option<Ipv4Address>,
    pub elected_bsr_priority: u8,
    pub group_rp_set: Vec<GroupRpMapping>,
}

impl PimBsrEngine {
    pub fn new(local_ip: Ipv4Address, is_candidate_bsr: bool, local_bsr_priority: u8) -> Self {
        PimBsrEngine {
            local_ip,
            is_candidate_bsr,
            local_bsr_priority,
            hash_mask_len: 30,
            elected_bsr: if is_candidate_bsr { Some(local_ip) } else { None },
            elected_bsr_priority: if is_candidate_bsr { local_bsr_priority } else { 0 },
            group_rp_set: Vec::new(),
        }
    }

    /// Checks whether an IPv4 multicast address falls in the Source-Specific Multicast (SSM) range (232.0.0.0/8).
    pub fn is_ssm_group(group: Ipv4Address) -> bool {
        group.0[0] == 232
    }

    /// Computes the RFC 5059 / RFC 2362 deterministic hash value for RP selection:
    /// Value = (1103515245 * ((1103515245 * (G & M) + 12345) XOR RP) + 12345) mod 2^31
    pub fn compute_rp_hash(group_ip: Ipv4Address, hash_mask_len: u8, rp_ip: Ipv4Address) -> u32 {
        let g = u32::from_be_bytes(group_ip.0);
        let mask = if hash_mask_len == 0 {
            0
        } else {
            !((1u32 << (32 - hash_mask_len)) - 1)
        };
        let g_masked = g & mask;
        let rp = u32::from_be_bytes(rp_ip.0);

        let c1 = 1103515245u64;
        let c2 = 12345u64;
        let mod_val = 0x8000_0000u64; // 2^31

        let step1 = (c1.wrapping_mul(g_masked as u64).wrapping_add(c2)) as u32;
        let step2 = (step1 ^ rp) as u64;
        let step3 = (c1.wrapping_mul(step2).wrapping_add(c2)) % mod_val;

        step3 as u32
    }

    /// Processes an incoming Bootstrap Message (BSM) and updates the local BSR state and RP-Set.
    pub fn process_bootstrap_message(&mut self, bsm: PimBootstrapMessage) -> bool {
        let incoming_priority = bsm.bsr_priority;
        let incoming_ip = bsm.bsr_ip;

        let should_accept = match self.elected_bsr {
            None => true,
            Some(current_bsr) => {
                if incoming_priority > self.elected_bsr_priority {
                    true
                } else if incoming_priority == self.elected_bsr_priority {
                    incoming_ip.0 >= current_bsr.0
                } else {
                    false
                }
            }
        };

        if should_accept {
            self.elected_bsr = Some(incoming_ip);
            self.elected_bsr_priority = incoming_priority;
            self.hash_mask_len = bsm.hash_mask_len;
            self.group_rp_set = bsm.group_mappings;
            true
        } else {
            false
        }
    }

    /// Adds or updates candidate RPs for a group range (used by active BSR).
    pub fn register_candidate_rp(&mut self, group: EncodedGroupAddress, rp: CandidateRpRecord) {
        if let Some(mapping) = self.group_rp_set.iter_mut().find(|m| m.group == group) {
            if let Some(existing) = mapping.candidates.iter_mut().find(|c| c.rp_ip == rp.rp_ip) {
                *existing = rp;
            } else {
                mapping.candidates.push(rp);
            }
            mapping.candidates.sort_by_key(|c| c.priority);
            mapping.rp_count = mapping.candidates.len() as u8;
        } else {
            self.group_rp_set.push(GroupRpMapping {
                group,
                rp_count: 1,
                frag_tag: 0,
                candidates: vec![rp],
            });
        }
    }

    /// Finds the designated active Rendezvous Point (RP) for a multicast group address.
    /// If the group is in the SSM range (232.0.0.0/8), returns None (RP is bypassed).
    pub fn get_rp_for_group(&self, group: Ipv4Address) -> Option<Ipv4Address> {
        if Self::is_ssm_group(group) {
            return None; // SSM bypasses RP entirely
        }

        // Find longest prefix match group mapping
        let mut best_match: Option<&GroupRpMapping> = None;
        for gm in &self.group_rp_set {
            let mask = if gm.group.mask_len == 0 {
                0
            } else {
                !((1u32 << (32 - gm.group.mask_len)) - 1)
            };
            let g_val = u32::from_be_bytes(group.0);
            let map_val = u32::from_be_bytes(gm.group.group_ip.0);
            if (g_val & mask) == (map_val & mask) {
                match best_match {
                    None => best_match = Some(gm),
                    Some(prev) => {
                        if gm.group.mask_len > prev.group.mask_len {
                            best_match = Some(gm);
                        }
                    }
                }
            }
        }

        let mapping = best_match?;
        if mapping.candidates.is_empty() {
            return None;
        }

        // Lowest priority value is preferred (RFC 5059)
        let min_priority = mapping.candidates.iter().map(|c| c.priority).min().unwrap();
        let eligible: Vec<&CandidateRpRecord> = mapping
            .candidates
            .iter()
            .filter(|c| c.priority == min_priority)
            .collect();

        if eligible.len() == 1 {
            return Some(eligible[0].rp_ip);
        }

        // Multiple candidates with same priority: use Hash Function tie-breaking
        let mut best_rp = eligible[0].rp_ip;
        let mut best_hash = Self::compute_rp_hash(group, self.hash_mask_len, best_rp);

        for crp in eligible.iter().skip(1) {
            let h = Self::compute_rp_hash(group, self.hash_mask_len, crp.rp_ip);
            if h > best_hash || (h == best_hash && crp.rp_ip.0 > best_rp.0) {
                best_hash = h;
                best_rp = crp.rp_ip;
            }
        }

        Some(best_rp)
    }

    /// Generates a new Bootstrap Message originated by this BSR.
    pub fn originate_bootstrap_message(&self) -> Option<PimBootstrapMessage> {
        if !self.is_candidate_bsr || self.elected_bsr != Some(self.local_ip) {
            return None;
        }
        let mut bsm = PimBootstrapMessage::new(self.local_ip, self.local_bsr_priority, self.hash_mask_len);
        bsm.group_mappings = self.group_rp_set.clone();
        Some(bsm)
    }
}

//! MPLS Entropy Label (RFC 6790 / RFC 6391)
//!
//! Implements the Entropy Label Indicator (ELI) and Entropy Label (EL)
//! for ECMP load balancing in MPLS networks. LSRs that do not understand
//! the deep payload can use the entropy label to consistently hash flows
//! across equal-cost paths.
//!
//! Reference: RFC 6790 §3-5, RFC 6391 §4

use std::collections::HashMap;

/// Reserved MPLS label value for Entropy Label Indicator (ELI).
/// ELI = label value 7.
pub const MPLS_LABEL_ELI: u32 = 7;

/// Minimum valid entropy label value (labels 0-15 are reserved).
pub const ENTROPY_LABEL_MIN: u32 = 16;

/// Maximum MPLS label value (20-bit field).
pub const MPLS_LABEL_MAX: u32 = 0xFFFFF;

/// Default EL hash seed.
pub const DEFAULT_HASH_SEED: u64 = 0x517cc1b727220a95;

/// MPLS label stack entry (4 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MplsLabelEntry {
    /// Label value (20 bits).
    pub label: u32,
    /// Traffic Class / Experimental bits (3 bits).
    pub tc: u8,
    /// Bottom-of-Stack flag.
    pub bos: bool,
    /// TTL field (8 bits).
    pub ttl: u8,
}

impl MplsLabelEntry {
    pub fn new(label: u32, tc: u8, bos: bool, ttl: u8) -> Self {
        Self {
            label: label & MPLS_LABEL_MAX,
            tc: tc & 0x07,
            bos,
            ttl,
        }
    }

    /// Create an ELI entry (label 7, TC=0, not BoS).
    pub fn eli(ttl: u8) -> Self {
        Self::new(MPLS_LABEL_ELI, 0, false, ttl)
    }

    /// Create an Entropy Label entry.
    pub fn entropy(el_value: u32, ttl: u8) -> Self {
        Self::new(el_value, 0, false, ttl)
    }

    /// Check if this entry is an ELI.
    pub fn is_eli(&self) -> bool {
        self.label == MPLS_LABEL_ELI
    }

    /// Serialize to 4-byte big-endian encoding.
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut word: u32 = 0;
        word |= (self.label & MPLS_LABEL_MAX) << 12;
        word |= ((self.tc & 0x07) as u32) << 9;
        if self.bos {
            word |= 1 << 8;
        }
        word |= self.ttl as u32;
        word.to_be_bytes()
    }

    /// Parse from 4-byte big-endian encoding.
    pub fn from_bytes(bytes: &[u8; 4]) -> Self {
        let word = u32::from_be_bytes(*bytes);
        Self {
            label: (word >> 12) & MPLS_LABEL_MAX,
            tc: ((word >> 9) & 0x07) as u8,
            bos: ((word >> 8) & 0x01) != 0,
            ttl: (word & 0xFF) as u8,
        }
    }
}

/// MPLS label stack with entropy label support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MplsLabelStack {
    /// Label entries, from top to bottom.
    pub entries: Vec<MplsLabelEntry>,
}

impl MplsLabelStack {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Push a label entry onto the top of the stack.
    pub fn push(&mut self, entry: MplsLabelEntry) {
        // Clear BoS on current entries, set on bottom
        if !self.entries.is_empty() {
            for e in &mut self.entries {
                e.bos = false;
            }
        }
        self.entries.insert(0, entry);
        // Set BoS on the last entry
        if let Some(last) = self.entries.last_mut() {
            last.bos = true;
        }
    }

    /// Find the position of the ELI in the stack (if present).
    pub fn find_eli(&self) -> Option<usize> {
        self.entries.iter().position(|e| e.is_eli())
    }

    /// Extract the entropy label value (the label immediately after ELI).
    pub fn entropy_label_value(&self) -> Option<u32> {
        let eli_pos = self.find_eli()?;
        let el_pos = eli_pos + 1;
        if el_pos < self.entries.len() {
            Some(self.entries[el_pos].label)
        } else {
            None
        }
    }

    /// Check if the stack contains an ELI/EL pair.
    pub fn has_entropy_label(&self) -> bool {
        self.entropy_label_value().is_some()
    }

    /// Insert an ELI/EL pair at the specified position in the stack.
    pub fn insert_entropy_label(&mut self, position: usize, el_value: u32, ttl: u8) {
        let eli = MplsLabelEntry::eli(ttl);
        let el = MplsLabelEntry::entropy(el_value, ttl);

        // Insert ELI first, then EL after it
        if position <= self.entries.len() {
            self.entries.insert(position, el);
            self.entries.insert(position, eli);
        }

        // Fix BoS flags
        for e in &mut self.entries {
            e.bos = false;
        }
        if let Some(last) = self.entries.last_mut() {
            last.bos = true;
        }
    }

    /// Remove the ELI/EL pair from the stack.
    pub fn remove_entropy_label(&mut self) -> Option<u32> {
        let eli_pos = self.find_eli()?;
        let el_pos = eli_pos + 1;
        if el_pos >= self.entries.len() {
            return None;
        }

        let el_value = self.entries[el_pos].label;
        self.entries.remove(el_pos);
        self.entries.remove(eli_pos);

        // Fix BoS flags
        for e in &mut self.entries {
            e.bos = false;
        }
        if let Some(last) = self.entries.last_mut() {
            last.bos = true;
        }

        Some(el_value)
    }

    /// Serialize the entire label stack to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.entries.len() * 4);
        for entry in &self.entries {
            buf.extend_from_slice(&entry.to_bytes());
        }
        buf
    }

    /// Parse a label stack from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EntropyLabelError> {
        if data.len() % 4 != 0 {
            return Err(EntropyLabelError::InvalidStackLength(data.len()));
        }

        let mut entries = Vec::new();
        let mut offset = 0;
        loop {
            if offset + 4 > data.len() {
                break;
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&data[offset..offset + 4]);
            let entry = MplsLabelEntry::from_bytes(&bytes);
            let is_bos = entry.bos;
            entries.push(entry);
            offset += 4;

            if is_bos {
                break;
            }
        }

        Ok(Self { entries })
    }

    /// Stack depth (number of label entries).
    pub fn depth(&self) -> usize {
        self.entries.len()
    }
}

impl Default for MplsLabelStack {
    fn default() -> Self {
        Self::new()
    }
}

/// Entropy label hash computation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyHashStrategy {
    /// Hash from 5-tuple of the inner IP packet.
    FiveTuple,
    /// Hash from the flow label of the inner IPv6 packet.
    Ipv6FlowLabel,
    /// Use a caller-provided entropy value directly.
    Provided,
}

/// ECMP next-hop entry for entropy-based load balancing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmpNextHop {
    /// Identifier for this next-hop.
    pub id: u32,
    /// Outgoing interface name.
    pub interface: String,
    /// Next-hop address (as string for flexibility).
    pub address: String,
    /// Weight for weighted ECMP (1 = equal).
    pub weight: u32,
}

/// Result of entropy-based ECMP selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmpSelectionResult {
    /// The selected next-hop.
    pub selected_hop: EcmpNextHop,
    /// The entropy label value used for selection.
    pub entropy_value: u32,
    /// Hash bucket index.
    pub bucket_index: usize,
    /// Total number of ECMP paths.
    pub total_paths: usize,
}

/// Errors from entropy label processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntropyLabelError {
    /// Label stack length is not a multiple of 4.
    InvalidStackLength(usize),
    /// No ELI/EL pair found in the stack.
    NoEntropyLabel,
    /// No ECMP next-hops configured.
    NoNextHops,
    /// ELI found without a following EL.
    MalformedEliEl,
}

impl std::fmt::Display for EntropyLabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStackLength(len) => {
                write!(f, "Invalid MPLS stack length: {} bytes", len)
            }
            Self::NoEntropyLabel => write!(f, "No entropy label found in stack"),
            Self::NoNextHops => write!(f, "No ECMP next-hops configured"),
            Self::MalformedEliEl => write!(f, "Malformed ELI/EL pair"),
        }
    }
}

/// MPLS Entropy Label Engine.
///
/// Provides entropy label insertion at ingress, entropy-based ECMP
/// selection at transit, and ELI/EL stripping at egress.
#[derive(Debug)]
pub struct MplsEntropyLabelEngine {
    /// Hash seed for deterministic hashing.
    pub hash_seed: u64,
    /// ECMP next-hops per label prefix.
    pub ecmp_groups: HashMap<u32, Vec<EcmpNextHop>>,
    /// Statistics: frames processed with entropy labels.
    pub stats_el_processed: u64,
    /// Statistics: frames where EL was inserted.
    pub stats_el_inserted: u64,
    /// Statistics: frames where EL was stripped.
    pub stats_el_stripped: u64,
}

impl MplsEntropyLabelEngine {
    pub fn new(hash_seed: u64) -> Self {
        Self {
            hash_seed,
            ecmp_groups: HashMap::new(),
            stats_el_processed: 0,
            stats_el_inserted: 0,
            stats_el_stripped: 0,
        }
    }

    /// Add an ECMP group for a given label prefix.
    pub fn add_ecmp_group(&mut self, label: u32, next_hops: Vec<EcmpNextHop>) {
        self.ecmp_groups.insert(label, next_hops);
    }

    /// Compute an entropy hash value from flow data.
    ///
    /// Uses a simplified FNV-1a-like hash for simulation.
    pub fn compute_entropy_hash(&self, flow_data: &[u8]) -> u32 {
        let mut hash = self.hash_seed;
        for &byte in flow_data {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        // Map to valid label range (16..2^20 - 1)
        let raw = (hash & 0xFFFFF) as u32;
        if raw < ENTROPY_LABEL_MIN {
            raw + ENTROPY_LABEL_MIN
        } else {
            raw
        }
    }

    /// Insert an ELI/EL pair into a label stack at ingress.
    ///
    /// The EL is computed from the flow data (e.g., 5-tuple hash).
    pub fn insert_entropy_at_ingress(
        &mut self,
        stack: &mut MplsLabelStack,
        flow_data: &[u8],
        insert_position: usize,
        ttl: u8,
    ) -> u32 {
        let el_value = self.compute_entropy_hash(flow_data);
        stack.insert_entropy_label(insert_position, el_value, ttl);
        self.stats_el_inserted += 1;
        el_value
    }

    /// Select an ECMP next-hop using the entropy label from the stack.
    pub fn select_ecmp_path(
        &mut self,
        top_label: u32,
        stack: &MplsLabelStack,
    ) -> Result<EcmpSelectionResult, EntropyLabelError> {
        let next_hops = self
            .ecmp_groups
            .get(&top_label)
            .ok_or(EntropyLabelError::NoNextHops)?;

        if next_hops.is_empty() {
            return Err(EntropyLabelError::NoNextHops);
        }

        let el_value = stack
            .entropy_label_value()
            .ok_or(EntropyLabelError::NoEntropyLabel)?;

        // Simple modular selection weighted by ECMP path count
        let total_weight: u32 = next_hops.iter().map(|h| h.weight).sum();
        let bucket = (el_value % total_weight) as u32;

        let mut cumulative = 0u32;
        let mut selected_idx = 0;
        for (i, hop) in next_hops.iter().enumerate() {
            cumulative += hop.weight;
            if bucket < cumulative {
                selected_idx = i;
                break;
            }
        }

        self.stats_el_processed += 1;

        Ok(EcmpSelectionResult {
            selected_hop: next_hops[selected_idx].clone(),
            entropy_value: el_value,
            bucket_index: selected_idx,
            total_paths: next_hops.len(),
        })
    }

    /// Strip the ELI/EL pair from the stack at egress.
    pub fn strip_entropy_at_egress(
        &mut self,
        stack: &mut MplsLabelStack,
    ) -> Result<u32, EntropyLabelError> {
        let el_value = stack
            .remove_entropy_label()
            .ok_or(EntropyLabelError::NoEntropyLabel)?;
        self.stats_el_stripped += 1;
        Ok(el_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_label_entry_roundtrip() {
        let entry = MplsLabelEntry::new(16100, 5, true, 64);
        let bytes = entry.to_bytes();
        let parsed = MplsLabelEntry::from_bytes(&bytes);
        assert_eq!(parsed.label, 16100);
        assert_eq!(parsed.tc, 5);
        assert!(parsed.bos);
        assert_eq!(parsed.ttl, 64);
    }

    #[test]
    fn test_eli_and_el_detection() {
        let eli = MplsLabelEntry::eli(255);
        assert!(eli.is_eli());
        assert_eq!(eli.label, MPLS_LABEL_ELI);

        let el = MplsLabelEntry::entropy(54321, 255);
        assert!(!el.is_eli());
    }

    #[test]
    fn test_label_stack_entropy_insertion_and_removal() {
        let mut stack = MplsLabelStack::new();
        stack.push(MplsLabelEntry::new(16100, 0, true, 64));
        stack.push(MplsLabelEntry::new(100, 0, false, 64));

        assert_eq!(stack.depth(), 2);
        assert!(!stack.has_entropy_label());

        // Insert ELI/EL after the top label (position 1)
        stack.insert_entropy_label(1, 99999, 64);
        assert_eq!(stack.depth(), 4); // 100, ELI, EL, 16100
        assert!(stack.has_entropy_label());
        assert_eq!(stack.entropy_label_value(), Some(99999));

        // Remove ELI/EL
        let removed = stack.remove_entropy_label().unwrap();
        assert_eq!(removed, 99999);
        assert_eq!(stack.depth(), 2);
        assert!(!stack.has_entropy_label());
    }

    #[test]
    fn test_entropy_ecmp_selection() {
        let mut engine = MplsEntropyLabelEngine::new(DEFAULT_HASH_SEED);

        // Add 3-way ECMP group for label 100
        engine.add_ecmp_group(100, vec![
            EcmpNextHop { id: 1, interface: "xe-0/0/0".into(), address: "10.0.0.1".into(), weight: 1 },
            EcmpNextHop { id: 2, interface: "xe-0/0/1".into(), address: "10.0.0.2".into(), weight: 1 },
            EcmpNextHop { id: 3, interface: "xe-0/0/2".into(), address: "10.0.0.3".into(), weight: 1 },
        ]);

        // Build stack with ELI/EL
        let mut stack = MplsLabelStack::new();
        stack.push(MplsLabelEntry::new(16100, 0, true, 64));
        stack.push(MplsLabelEntry::new(100, 0, false, 64));
        stack.insert_entropy_label(1, 42, 64);

        let result = engine.select_ecmp_path(100, &stack).unwrap();
        assert_eq!(result.entropy_value, 42);
        assert_eq!(result.total_paths, 3);
        // Bucket index should be 42 % 3 = 0
        assert_eq!(result.bucket_index, 0);
        assert_eq!(result.selected_hop.id, 1);
    }

    #[test]
    fn test_ingress_entropy_insertion() {
        let mut engine = MplsEntropyLabelEngine::new(DEFAULT_HASH_SEED);

        let mut stack = MplsLabelStack::new();
        stack.push(MplsLabelEntry::new(16200, 0, true, 64));
        stack.push(MplsLabelEntry::new(200, 0, false, 64));

        let flow_data = b"10.1.1.1:8080->10.2.2.2:443";
        let el_value = engine.insert_entropy_at_ingress(&mut stack, flow_data, 1, 64);

        assert!(stack.has_entropy_label());
        assert_eq!(stack.entropy_label_value(), Some(el_value));
        assert!(el_value >= ENTROPY_LABEL_MIN);
        assert_eq!(engine.stats_el_inserted, 1);

        // Strip at egress
        let stripped = engine.strip_entropy_at_egress(&mut stack).unwrap();
        assert_eq!(stripped, el_value);
        assert!(!stack.has_entropy_label());
        assert_eq!(engine.stats_el_stripped, 1);
    }
}

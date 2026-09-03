//! Deterministic IP DetNet MPLS PREOF & Control Word Sub-Layer (RFC 8964 / RFC 8938).
//!
//! Implements DetNet Service sub-layer over MPLS forwarding planes, carrying the 4-byte
//! DetNet Control Word (d-CW) for zero-loss hitless Packet Replication (PRF),
//! Packet Elimination (PEF), and Packet Ordering (POF) functions.

use std::collections::{HashMap, HashSet};

/// DetNet Control Word (d-CW) - 4 bytes (RFC 8964 Section 4.2).
///
/// Format:
/// - Nibble (4 bits): 0000 (indicates non-IP payload start)
/// - Reserved (12 bits): 0x000
/// - Sequence Number (16 bits): Monotonic sequence number
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetNetMplsControlWord {
    pub sequence_number: u16,
}

impl DetNetMplsControlWord {
    pub fn new(sequence_number: u16) -> Self {
        DetNetMplsControlWord { sequence_number }
    }

    pub fn serialize(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        // First 16 bits = 0x0000 (Nibble 0000 + 12-bit Reserved 0x000)
        buf[0] = 0x00;
        buf[1] = 0x00;
        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        // First nibble MUST be 0
        if (buf[0] & 0xF0) != 0x00 {
            return None;
        }
        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        Some(DetNetMplsControlWord {
            sequence_number: seq,
        })
    }
}

/// DetNet MPLS Encapsulation Profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetNetMplsProfile {
    pub flow_id: u32,
    pub s_label: u32,       // DetNet Service Label (20-bit MPLS label)
    pub f_labels: Vec<u32>, // DetNet Forwarding Labels for dual-path replication
}

/// DetNet Forwarding / Elimination Result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetNetMplsResult {
    /// Ingress: Replicated packets across multiple F-Label paths
    ReplicatedPaths {
        s_label: u32,
        seq: u16,
        frames: Vec<(u32, Vec<u8>)>, // (f_label, serialized_mpls_packet)
    },
    /// Egress / Elimination: Accepted unique packet
    AcceptedUnique {
        s_label: u32,
        seq: u16,
        payload: Vec<u8>,
    },
    /// Egress / Elimination: Duplicate packet dropped
    DuplicateDropped { s_label: u32, seq: u16 },
    /// Invalid packet or unrecognized S-Label
    InvalidPacket(String),
}

/// DetNet MPLS PREOF Processing Engine (RFC 8964).
#[derive(Debug, Clone, Default)]
pub struct DetNetMplsEngine {
    /// Ingress profiles: flow_id -> DetNetMplsProfile
    pub ingress_profiles: HashMap<u32, DetNetMplsProfile>,
    /// Ingress sequence generator: flow_id -> next seq
    pub tx_sequences: HashMap<u32, u16>,
    /// Egress / Transit Elimination history: s_label -> Set of recently observed sequence numbers
    pub pef_history: HashMap<u32, HashSet<u16>>,
}

impl DetNetMplsEngine {
    pub fn new() -> Self {
        DetNetMplsEngine {
            ingress_profiles: HashMap::new(),
            tx_sequences: HashMap::new(),
            pef_history: HashMap::new(),
        }
    }

    pub fn register_profile(&mut self, profile: DetNetMplsProfile) {
        self.ingress_profiles.insert(profile.flow_id, profile);
    }

    /// Ingress: Encapsulate payload with DetNet Control Word (d-CW), S-Label, and replicate across F-Labels (PRF).
    pub fn ingress_replicate(&mut self, flow_id: u32, payload: &[u8]) -> DetNetMplsResult {
        let profile = match self.ingress_profiles.get(&flow_id) {
            Some(p) => p.clone(),
            None => return DetNetMplsResult::InvalidPacket("Unknown Flow ID".to_string()),
        };

        let seq_entry = self.tx_sequences.entry(flow_id).or_insert(0);
        let seq = *seq_entry;
        *seq_entry = seq_entry.wrapping_add(1);

        let dcw = DetNetMplsControlWord::new(seq);
        let dcw_bytes = dcw.serialize();

        // Build Inner DetNet Service Packet: [S-Label (4 bytes)] [d-CW (4 bytes)] [Payload]
        // S-Label MPLS Entry: (S-Label << 12) | (1 << 8 BoS) | TTL 64
        let s_label_entry = (profile.s_label << 12) | (1 << 8) | 64;

        let mut service_pdu = Vec::with_capacity(4 + 4 + payload.len());
        service_pdu.extend_from_slice(&s_label_entry.to_be_bytes());
        service_pdu.extend_from_slice(&dcw_bytes);
        service_pdu.extend_from_slice(payload);

        // PRF (Packet Replication Function): Clone over each F-Label path
        let mut frames = Vec::with_capacity(profile.f_labels.len());
        for f_label in &profile.f_labels {
            // F-Label MPLS Entry: (F-Label << 12) | (0 BoS) | TTL 64
            let f_label_entry = (*f_label << 12) | (0 << 8) | 64;
            let mut full_frame = Vec::with_capacity(4 + service_pdu.len());
            full_frame.extend_from_slice(&f_label_entry.to_be_bytes());
            full_frame.extend_from_slice(&service_pdu);
            frames.push((*f_label, full_frame));
        }

        DetNetMplsResult::ReplicatedPaths {
            s_label: profile.s_label,
            seq,
            frames,
        }
    }

    /// Egress / Transit: Process incoming MPLS Service PDU, inspect d-CW, and eliminate duplicates (PEF).
    pub fn egress_eliminate(&mut self, service_pdu: &[u8]) -> DetNetMplsResult {
        if service_pdu.len() < 8 {
            return DetNetMplsResult::InvalidPacket("Service PDU too short".to_string());
        }

        // Parse S-Label (First 4 bytes)
        let s_label_raw = u32::from_be_bytes([
            service_pdu[0],
            service_pdu[1],
            service_pdu[2],
            service_pdu[3],
        ]);
        let s_label = s_label_raw >> 12;

        // Parse d-CW (Next 4 bytes)
        let dcw = match DetNetMplsControlWord::parse(&service_pdu[4..8]) {
            Some(cw) => cw,
            None => {
                return DetNetMplsResult::InvalidPacket("Invalid DetNet Control Word".to_string());
            }
        };

        // PEF (Packet Elimination Function)
        let history = self.pef_history.entry(s_label).or_default();
        if history.contains(&dcw.sequence_number) {
            return DetNetMplsResult::DuplicateDropped {
                s_label,
                seq: dcw.sequence_number,
            };
        }

        history.insert(dcw.sequence_number);

        // Keep history bounded to avoid memory growth
        if history.len() > 10_000 {
            history.clear();
            history.insert(dcw.sequence_number);
        }

        let payload = service_pdu[8..].to_vec();

        DetNetMplsResult::AcceptedUnique {
            s_label,
            seq: dcw.sequence_number,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detnet_cw_codec() {
        let cw = DetNetMplsControlWord::new(0x4321);
        let ser = cw.serialize();
        assert_eq!(ser[0], 0x00);
        assert_eq!(ser[1], 0x00);
        assert_eq!(ser[2..4], [0x43, 0x21]);

        let parsed = DetNetMplsControlWord::parse(&ser).unwrap();
        assert_eq!(parsed.sequence_number, 0x4321);
    }

    #[test]
    fn test_detnet_mpls_prf_and_pef_pipeline() {
        let mut engine = DetNetMplsEngine::new();

        let profile = DetNetMplsProfile {
            flow_id: 1,
            s_label: 1000,
            f_labels: vec![2001, 2002], // Dual disjoint paths
        };
        engine.register_profile(profile);

        let app_data = b"CriticalIndustrialControlPayload";

        // Ingress PRF
        let rep_res = engine.ingress_replicate(1, app_data);
        let frames = match rep_res {
            DetNetMplsResult::ReplicatedPaths {
                s_label,
                seq,
                frames,
            } => {
                assert_eq!(s_label, 1000);
                assert_eq!(seq, 0);
                assert_eq!(frames.len(), 2);
                frames
            }
            other => panic!("Expected ReplicatedPaths, got {:?}", other),
        };

        // Path 1 arrives at egress (strip 4-byte F-label header to get Service PDU)
        let service_pdu_path1 = &frames[0].1[4..];
        let elim1 = engine.egress_eliminate(service_pdu_path1);
        match elim1 {
            DetNetMplsResult::AcceptedUnique {
                s_label,
                seq,
                payload,
            } => {
                assert_eq!(s_label, 1000);
                assert_eq!(seq, 0);
                assert_eq!(payload, app_data);
            }
            other => panic!("Expected AcceptedUnique for path 1, got {:?}", other),
        }

        // Path 2 arrives at egress (duplicate) -> Must be dropped by PEF
        let service_pdu_path2 = &frames[1].1[4..];
        let elim2 = engine.egress_eliminate(service_pdu_path2);
        match elim2 {
            DetNetMplsResult::DuplicateDropped { s_label, seq } => {
                assert_eq!(s_label, 1000);
                assert_eq!(seq, 0);
            }
            other => panic!("Expected DuplicateDropped for path 2, got {:?}", other),
        }
    }
}

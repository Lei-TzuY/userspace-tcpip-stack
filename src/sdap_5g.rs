//! 3GPP TS 37.324 5G NR Service Data Adaptation Protocol (SDAP) Engine.
//!
//! SDAP is the topmost user-plane sublayer in the 5G NR radio protocol stack,
//! sitting between the IP layer (QoS Flows from the 5G Core UPF/gNB-CU-UP)
//! and PDCP. It provides:
//!
//! - QoS Flow Identifier (QFI) to Data Radio Bearer (DRB) mapping
//! - SDAP PDU header framing (1-byte: D/C flag, RQI, RDI, 6-bit QFI)
//! - Reflective QoS (RQI) flow-to-DRB mapping (downlink-indicated, UE applies)
//! - End-Marker control PDU for QoS Flow remapping during handover / mobility
//! - Default DRB routing for unmapped QoS Flows

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum QFI value (6 bits → 0..63).
pub const SDAP_MAX_QFI: u8 = 63;

/// SDAP header length in bytes (always 1 byte per TS 37.324 Section 6.2).
pub const SDAP_HEADER_LEN: usize = 1;

// ---------------------------------------------------------------------------
// SDAP Header (TS 37.324 Section 6.2)
// ---------------------------------------------------------------------------

/// Direction of an SDAP PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdapDirection {
    /// Downlink: gNB → UE.
    Downlink,
    /// Uplink: UE → gNB.
    Uplink,
}

/// SDAP Data PDU header (1 byte).
///
/// Bit layout (MSB first):
/// ```text
///   Downlink:  | D/C(1) | RQI(1) | RDI(1) |  QFI(5)  |   — 5-bit QFI (0..31 in DL)
///   Uplink:    | D/C(1) |  R(1)  | R(1)   |  QFI(5)  |   — Reserved bits are 0
/// ```
///
/// When the full 6-bit QFI range (0..63) is needed, the `QFI` field uses bits
/// [5:0] and the `RDI`/`R` bit is repurposed per Release-16+ interpretation.
/// This implementation encodes the full 6-bit QFI for interoperability:
///
/// ```text
///   DL:  | D/C(1) | RQI(1) | QFI[5:0](6) |
///   UL:  | D/C(1) |  R(1)  | QFI[5:0](6) |
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdapHeader {
    /// Data/Control indicator: `true` = Data PDU (D/C = 1), `false` = Control PDU (D/C = 0).
    pub is_data: bool,
    /// Reflective QoS Indication (DL only): when true, UE SHALL create/update
    /// the reflective mapping rule for this QFI → DRB association.
    pub rqi: bool,
    /// QoS Flow Identifier (0..63).
    pub qfi: u8,
}

impl SdapHeader {
    /// Encode this SDAP header into a single byte.
    pub fn encode(&self) -> u8 {
        let dc_bit = if self.is_data { 0x80u8 } else { 0x00u8 };
        let rqi_bit = if self.rqi { 0x40u8 } else { 0x00u8 };
        let qfi_bits = self.qfi & 0x3F;
        dc_bit | rqi_bit | qfi_bits
    }

    /// Decode a single SDAP header byte.
    pub fn decode(byte: u8) -> Self {
        SdapHeader {
            is_data: (byte & 0x80) != 0,
            rqi: (byte & 0x40) != 0,
            qfi: byte & 0x3F,
        }
    }
}

// ---------------------------------------------------------------------------
// SDAP PDU Types (TS 37.324 Section 6)
// ---------------------------------------------------------------------------

/// SDAP Data PDU: carries one IP packet (SDU) with an SDAP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdapDataPdu {
    pub header: SdapHeader,
    pub payload: Vec<u8>,
}

impl SdapDataPdu {
    /// Serialize the SDAP Data PDU to wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SDAP_HEADER_LEN + self.payload.len());
        buf.push(self.header.encode());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse an SDAP Data PDU from wire bytes. Returns `None` if too short.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let header = SdapHeader::decode(data[0]);
        Some(SdapDataPdu {
            header,
            payload: data[1..].to_vec(),
        })
    }
}

/// SDAP Control PDU type (TS 37.324 Section 6.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdapControlPduType {
    /// End-Marker: signals that a QoS Flow has been remapped to a different DRB.
    /// The old DRB receives this marker so the peer knows no more PDUs will
    /// arrive on this QoS Flow via this bearer.
    EndMarker,
}

/// SDAP Control PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdapControlPdu {
    pub pdu_type: SdapControlPduType,
    pub qfi: u8,
}

impl SdapControlPdu {
    /// Encode: D/C = 0, remaining 7 bits carry type (1 bit) + QFI (6 bits).
    /// For End-Marker: type bit = 0, so the byte is `0b0_0_QQQQQQ`.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.pdu_type {
            SdapControlPduType::EndMarker => {
                // D/C = 0 (control), type = 0 (end marker), QFI in bits [5:0]
                let byte = self.qfi & 0x3F;
                vec![byte]
            }
        }
    }

    /// Parse an SDAP Control PDU from wire bytes. Returns `None` if too short.
    /// Caller must verify D/C == 0 before calling this.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let byte = data[0];
        // D/C should be 0 for control
        if (byte & 0x80) != 0 {
            return None;
        }
        // Type bit: bit 6 — 0 = EndMarker
        let _type_bit = (byte & 0x40) != 0;
        let qfi = byte & 0x3F;
        Some(SdapControlPdu {
            pdu_type: SdapControlPduType::EndMarker,
            qfi,
        })
    }
}

// ---------------------------------------------------------------------------
// QoS Flow → DRB Mapping Rule
// ---------------------------------------------------------------------------

/// How a QoS Flow mapping was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingOrigin {
    /// Configured by RRC (explicit gNB signaling).
    RrcConfigured,
    /// Learned via Reflective QoS Indication (RQI) in a downlink SDAP PDU.
    Reflective,
}

/// A single QoS Flow → DRB mapping entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosFlowMapping {
    /// QoS Flow Identifier (0..63).
    pub qfi: u8,
    /// Target DRB identifier (1..32 per TS 38.331).
    pub drb_id: u8,
    /// How this mapping was established.
    pub origin: MappingOrigin,
}

// ---------------------------------------------------------------------------
// SDAP Entity (TS 37.324 Section 5)
// ---------------------------------------------------------------------------

/// Role of the SDAP entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdapRole {
    /// gNB side (network).
    Gnb,
    /// UE side.
    Ue,
}

/// Configuration for SDAP entity header presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdapHeaderConfig {
    /// Whether SDAP header is present in uplink.
    pub ul_header: bool,
    /// Whether SDAP header is present in downlink.
    pub dl_header: bool,
}

impl Default for SdapHeaderConfig {
    fn default() -> Self {
        SdapHeaderConfig {
            ul_header: true,
            dl_header: true,
        }
    }
}

/// The main SDAP protocol entity per PDU session.
///
/// Each PDU Session has one SDAP entity on both the UE and gNB sides.
/// The entity manages QoS Flow ↔ DRB mapping tables, constructs/strips
/// SDAP headers, and handles reflective QoS and end-marker generation.
pub struct SdapEntity {
    /// PDU Session ID this entity belongs to (0..255).
    pub pdu_session_id: u8,
    /// Role: gNB or UE.
    pub role: SdapRole,
    /// Header configuration.
    pub header_config: SdapHeaderConfig,
    /// Default DRB for this PDU session: unmapped QoS Flows are routed here.
    pub default_drb_id: u8,
    /// QoS Flow → DRB mapping table. Key = QFI.
    pub qos_flow_map: HashMap<u8, QosFlowMapping>,
    /// Reflective QoS is enabled for this entity.
    pub reflective_qos_enabled: bool,
    /// Delivered SDUs (QFI, DRB ID, payload) — for testing/integration.
    pub delivered_sdus: Vec<(u8, u8, Vec<u8>)>,
    /// End-marker PDUs generated during remapping — for testing/integration.
    pub generated_end_markers: Vec<SdapControlPdu>,
}

impl SdapEntity {
    /// Create a new SDAP entity for a PDU session.
    pub fn new(pdu_session_id: u8, role: SdapRole, default_drb_id: u8) -> Self {
        SdapEntity {
            pdu_session_id,
            role,
            header_config: SdapHeaderConfig::default(),
            default_drb_id,
            qos_flow_map: HashMap::new(),
            reflective_qos_enabled: false,
            delivered_sdus: Vec::new(),
            generated_end_markers: Vec::new(),
        }
    }

    /// Configure or update a QoS Flow → DRB mapping via RRC.
    ///
    /// If the QFI was previously mapped to a different DRB, an End-Marker
    /// control PDU is generated for the old DRB before remapping.
    pub fn configure_mapping(&mut self, qfi: u8, drb_id: u8) {
        if qfi > SDAP_MAX_QFI {
            return;
        }
        // Check for remapping
        if let Some(existing) = self.qos_flow_map.get(&qfi) {
            if existing.drb_id != drb_id {
                // Generate End-Marker on old DRB
                let end_marker = SdapControlPdu {
                    pdu_type: SdapControlPduType::EndMarker,
                    qfi,
                };
                self.generated_end_markers.push(end_marker);
            }
        }
        self.qos_flow_map.insert(
            qfi,
            QosFlowMapping {
                qfi,
                drb_id,
                origin: MappingOrigin::RrcConfigured,
            },
        );
    }

    /// Enable reflective QoS for this entity.
    pub fn enable_reflective_qos(&mut self) {
        self.reflective_qos_enabled = true;
    }

    /// Resolve which DRB a QoS Flow should be mapped to.
    /// Returns the mapped DRB or the default DRB if no explicit mapping exists.
    pub fn resolve_drb(&self, qfi: u8) -> u8 {
        self.qos_flow_map
            .get(&qfi)
            .map(|m| m.drb_id)
            .unwrap_or(self.default_drb_id)
    }

    // -----------------------------------------------------------------------
    // Transmit path (IP SDU → SDAP PDU → PDCP)
    // -----------------------------------------------------------------------

    /// Process an uplink/downlink SDU from the IP layer, encapsulate with SDAP
    /// header if configured, and return `(drb_id, sdap_pdu_bytes)`.
    ///
    /// - `qfi`: QoS Flow Identifier assigned by the 5GC UPF or gNB scheduler.
    /// - `sdu`: Raw IP packet payload.
    /// - `direction`: Uplink or Downlink.
    /// - `set_rqi`: If true and direction is DL, set the RQI bit to trigger
    ///   reflective QoS mapping at the UE.
    ///
    /// Returns `(drb_id, pdu_bytes)` where `pdu_bytes` includes the SDAP
    /// header (if configured) followed by the SDU payload.
    pub fn build_pdu(
        &self,
        qfi: u8,
        sdu: &[u8],
        direction: SdapDirection,
        set_rqi: bool,
    ) -> (u8, Vec<u8>) {
        let drb_id = self.resolve_drb(qfi);

        let header_present = match direction {
            SdapDirection::Uplink => self.header_config.ul_header,
            SdapDirection::Downlink => self.header_config.dl_header,
        };

        if header_present {
            let rqi = match direction {
                SdapDirection::Downlink => set_rqi && self.reflective_qos_enabled,
                SdapDirection::Uplink => false, // RQI is only meaningful in DL
            };
            let header = SdapHeader {
                is_data: true,
                rqi,
                qfi,
            };
            let pdu = SdapDataPdu {
                header,
                payload: sdu.to_vec(),
            };
            (drb_id, pdu.to_bytes())
        } else {
            // No SDAP header — transparent passthrough
            (drb_id, sdu.to_vec())
        }
    }

    // -----------------------------------------------------------------------
    // Receive path (SDAP PDU from PDCP → IP SDU)
    // -----------------------------------------------------------------------

    /// Process a received SDAP PDU from PDCP, strip the header (if configured),
    /// apply reflective QoS mapping (if RQI is set), and deliver the SDU.
    ///
    /// - `drb_id`: The DRB on which this PDU was received.
    /// - `pdu_bytes`: Raw SDAP PDU bytes (header + payload, or just payload).
    /// - `direction`: The direction from the sender's perspective.
    ///
    /// Returns `Some((qfi, sdu))` on success, `None` if parsing fails.
    pub fn receive_pdu(
        &mut self,
        drb_id: u8,
        pdu_bytes: &[u8],
        direction: SdapDirection,
    ) -> Option<(u8, Vec<u8>)> {
        let header_present = match direction {
            SdapDirection::Downlink => self.header_config.dl_header,
            SdapDirection::Uplink => self.header_config.ul_header,
        };

        if !header_present {
            // No SDAP header — use default QFI = 0 for transparent mode
            let qfi = 0;
            self.delivered_sdus.push((qfi, drb_id, pdu_bytes.to_vec()));
            return Some((qfi, pdu_bytes.to_vec()));
        }

        if pdu_bytes.is_empty() {
            return None;
        }

        let header = SdapHeader::decode(pdu_bytes[0]);

        if !header.is_data {
            // Control PDU — process End-Marker
            if let Some(ctrl) = SdapControlPdu::from_bytes(pdu_bytes) {
                self.handle_end_marker(ctrl.qfi, drb_id);
            }
            return None;
        }

        let sdu = pdu_bytes[1..].to_vec();
        let qfi = header.qfi;

        // Apply reflective QoS mapping (UE side receiving DL with RQI=1)
        if header.rqi
            && self.role == SdapRole::Ue
            && direction == SdapDirection::Downlink
            && self.reflective_qos_enabled
        {
            self.apply_reflective_mapping(qfi, drb_id);
        }

        self.delivered_sdus.push((qfi, drb_id, sdu.clone()));
        Some((qfi, sdu))
    }

    // -----------------------------------------------------------------------
    // Reflective QoS (TS 37.324 Section 5.2.1)
    // -----------------------------------------------------------------------

    /// Apply reflective QoS mapping: when UE receives a DL PDU with RQI=1,
    /// it creates or updates the UL mapping for the same QFI → same DRB.
    fn apply_reflective_mapping(&mut self, qfi: u8, drb_id: u8) {
        self.qos_flow_map.insert(
            qfi,
            QosFlowMapping {
                qfi,
                drb_id,
                origin: MappingOrigin::Reflective,
            },
        );
    }

    // -----------------------------------------------------------------------
    // End-Marker Handling (TS 37.324 Section 5.2.2)
    // -----------------------------------------------------------------------

    /// Handle reception of an End-Marker for a given QFI on a specific DRB.
    /// This signals that the QoS Flow has been remapped to a different DRB
    /// and no more PDUs will arrive on this bearer for that flow.
    fn handle_end_marker(&mut self, qfi: u8, _old_drb_id: u8) {
        // Remove the mapping if it pointed to the old DRB, so the entity
        // falls back to the default DRB until a new explicit mapping arrives.
        if let Some(mapping) = self.qos_flow_map.get(&qfi) {
            if mapping.drb_id == _old_drb_id {
                self.qos_flow_map.remove(&qfi);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Bulk operations
    // -----------------------------------------------------------------------

    /// Remove all mappings (e.g., on PDU Session release).
    pub fn release(&mut self) {
        self.qos_flow_map.clear();
        self.delivered_sdus.clear();
        self.generated_end_markers.clear();
    }

    /// Get the current mapping table as a sorted vector (for debugging/testing).
    pub fn get_mapping_table(&self) -> Vec<QosFlowMapping> {
        let mut entries: Vec<QosFlowMapping> = self.qos_flow_map.values().cloned().collect();
        entries.sort_by_key(|e| e.qfi);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdap_header_encode_decode_roundtrip() {
        // Data PDU, RQI=1, QFI=42
        let hdr = SdapHeader {
            is_data: true,
            rqi: true,
            qfi: 42,
        };
        let byte = hdr.encode();
        // D/C=1 (0x80) | RQI=1 (0x40) | QFI=42 (0x2A) = 0xEA
        assert_eq!(byte, 0xEA);
        let decoded = SdapHeader::decode(byte);
        assert_eq!(decoded, hdr);

        // Control PDU, RQI=0, QFI=7
        let ctrl = SdapHeader {
            is_data: false,
            rqi: false,
            qfi: 7,
        };
        let byte2 = ctrl.encode();
        assert_eq!(byte2, 0x07);
        let decoded2 = SdapHeader::decode(byte2);
        assert_eq!(decoded2, ctrl);
    }

    #[test]
    fn test_sdap_data_pdu_serialization() {
        let pdu = SdapDataPdu {
            header: SdapHeader {
                is_data: true,
                rqi: false,
                qfi: 9,
            },
            payload: vec![0x45, 0x00, 0x00, 0x3C], // minimal IP header start
        };
        let wire = pdu.to_bytes();
        assert_eq!(wire.len(), 5); // 1 header + 4 payload
        assert_eq!(wire[0], 0x80 | 9); // D/C=1, RQI=0, QFI=9
        assert_eq!(&wire[1..], &[0x45, 0x00, 0x00, 0x3C]);

        let parsed = SdapDataPdu::from_bytes(&wire).unwrap();
        assert_eq!(parsed, pdu);
    }

    #[test]
    fn test_sdap_control_end_marker() {
        let em = SdapControlPdu {
            pdu_type: SdapControlPduType::EndMarker,
            qfi: 15,
        };
        let wire = em.to_bytes();
        assert_eq!(wire.len(), 1);
        assert_eq!(wire[0], 15); // D/C=0, type=0, QFI=15

        let parsed = SdapControlPdu::from_bytes(&wire).unwrap();
        assert_eq!(parsed, em);

        // Data PDU byte should fail control PDU parsing
        assert!(SdapControlPdu::from_bytes(&[0x80]).is_none());
    }
}

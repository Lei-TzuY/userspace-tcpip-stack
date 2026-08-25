//! Synchronous Ethernet (SyncE) Ethernet Synchronization Messaging Channel (ESMC - ITU-T G.8264 / IEEE 802.3 Clause 57).
//!
//! Implements SyncE ESMC packet parsing, serialization, Synchronization Status Message (SSM)
//! Quality Level (QL) decoding (QL-PRC, QL-SSU-A, QL-SSU-B, QL-SEC, QL-DNU), and dynamic
//! clock selection arbitration for 5G/RAN fronthaul physical layer frequency synchronization.

use std::collections::HashMap;

/// Slow Protocols EtherType (IEEE 802.3 Clause 57 / 802.1AX).
pub const ETHERTYPE_SLOW_PROTOCOLS: u16 = 0x8809;

/// ESMC Subtype within Slow Protocols (ITU-T G.8264).
pub const ESMC_SUBTYPE: u8 = 0x0A;

/// ITU-T Organizationally Unique Identifier (OUI: 00-19-A7).
pub const ITU_T_OUI: [u8; 3] = [0x00, 0x19, 0xA7];

/// ITU-T ESMC Subtype.
pub const ITU_T_ESMC_SUBTYPE: u16 = 0x0001;

/// ESMC Quality Level (SSM Codes - ITU-T G.781 / G.8264 Option I).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum QualityLevel {
    /// Primary Reference Clock (ITU-T G.811 / Stratum 1).
    QlPrc = 0x02,
    /// Type I SSU (ITU-T G.812 / Stratum 2).
    QlSsuA = 0x04,
    /// Type II SSU (ITU-T G.812).
    QlSsuB = 0x08,
    /// Synchronous Equipment Clock (ITU-T G.8262 / Stratum 3).
    QlSec = 0x0B,
    /// Do Not Use for synchronization.
    QlDnu = 0x0F,
    /// Invalid / Unallocated Quality Level.
    #[default]
    QlInvalid = 0x00,
}

impl QualityLevel {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0x02 => QualityLevel::QlPrc,
            0x04 => QualityLevel::QlSsuA,
            0x08 => QualityLevel::QlSsuB,
            0x0B => QualityLevel::QlSec,
            0x0F => QualityLevel::QlDnu,
            _ => QualityLevel::QlInvalid,
        }
    }

    /// Clock quality rank for best clock selection (lower value = higher quality).
    pub fn rank(&self) -> u8 {
        match self {
            QualityLevel::QlPrc => 1,
            QualityLevel::QlSsuA => 2,
            QualityLevel::QlSsuB => 3,
            QualityLevel::QlSec => 4,
            QualityLevel::QlDnu => 254,
            QualityLevel::QlInvalid => 255,
        }
    }
}

/// SyncE ESMC PDU (ITU-T G.8264 Section 11.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncEEsmcPacket {
    pub event_flag: bool,
    pub quality_level: QualityLevel,
}

impl SyncEEsmcPacket {
    pub fn new(event_flag: bool, quality_level: QualityLevel) -> Self {
        SyncEEsmcPacket {
            event_flag,
            quality_level,
        }
    }

    /// Serializes the ESMC PDU into raw bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36);
        buf.push(ESMC_SUBTYPE);
        buf.extend_from_slice(&ITU_T_OUI);
        buf.extend_from_slice(&ITU_T_ESMC_SUBTYPE.to_be_bytes());

        let flag_byte = if self.event_flag { 0x08 } else { 0x00 };
        buf.push(flag_byte); // Version = 0 (bits 7-4), Event = bit 3
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // 3 reserved bytes

        // QL TLV (Type 0x01, Length 0x0004)
        buf.push(0x01); // Type = QL TLV
        buf.extend_from_slice(&4u16.to_be_bytes()); // Length = 4
        buf.push(self.quality_level as u8); // SSM Code (lower 4 bits)

        // Pad to minimum Slow Protocols payload (36 to 128 bytes)
        while buf.len() < 36 {
            buf.push(0x00);
        }
        buf
    }

    /// Parses an ESMC PDU from raw bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        if data[0] != ESMC_SUBTYPE {
            return None;
        }
        if data[1..4] != ITU_T_OUI {
            return None;
        }
        let itut_sub = u16::from_be_bytes([data[4], data[5]]);
        if itut_sub != ITU_T_ESMC_SUBTYPE {
            return None;
        }

        let event_flag = (data[6] & 0x08) != 0;

        // Parse QL TLV
        let tlv_type = data[10];
        let tlv_len = u16::from_be_bytes([data[11], data[12]]);
        if tlv_type != 0x01 || tlv_len < 4 || data.len() < 14 {
            return None;
        }

        let ql = QualityLevel::from_u8(data[13]);

        Some(SyncEEsmcPacket {
            event_flag,
            quality_level: ql,
        })
    }
}

/// SyncE Clock Source Selection & ESMC Protocol Engine.
#[derive(Debug, Clone, Default)]
pub struct SyncEEsmcEngine {
    pub port_ql: HashMap<u32, QualityLevel>, // Port ID -> Current Quality Level
    pub port_priority: HashMap<u32, u8>,     // Port ID -> Configured Priority (1..255)
    pub selected_port: Option<u32>,
    pub selected_ql: QualityLevel,
    pub event_messages_received: usize,
}

impl SyncEEsmcEngine {
    pub fn new() -> Self {
        SyncEEsmcEngine {
            port_ql: HashMap::new(),
            port_priority: HashMap::new(),
            selected_port: None,
            selected_ql: QualityLevel::QlInvalid,
            event_messages_received: 0,
        }
    }

    /// Configures the administrative priority for a physical SyncE port.
    pub fn set_port_priority(&mut self, port: u32, priority: u8) {
        self.port_priority.insert(port, priority);
    }

    /// Ingests a received ESMC packet on a port and triggers clock selection.
    pub fn process_rx_esmc(&mut self, port: u32, pkt: &SyncEEsmcPacket) {
        if pkt.event_flag {
            self.event_messages_received += 1;
        }
        self.port_ql.insert(port, pkt.quality_level);
        self.arbitrate_clock_selection();
    }

    /// Performs ITU-T G.781 Best Clock Selection Algorithm across all active SyncE ports.
    pub fn arbitrate_clock_selection(&mut self) -> Option<(u32, QualityLevel)> {
        let mut best: Option<(u32, QualityLevel, u8, u8)> = None; // (port, ql, ql_rank, priority)

        for (&port, &ql) in &self.port_ql {
            if ql == QualityLevel::QlDnu || ql == QualityLevel::QlInvalid {
                continue;
            }
            let ql_rank = ql.rank();
            let prio = self.port_priority.get(&port).copied().unwrap_or(128);

            match best {
                None => {
                    best = Some((port, ql, ql_rank, prio));
                }
                Some((_, _, b_rank, b_prio)) => {
                    if ql_rank < b_rank || (ql_rank == b_rank && prio < b_prio) {
                        best = Some((port, ql, ql_rank, prio));
                    }
                }
            }
        }

        if let Some((port, ql, _, _)) = best {
            self.selected_port = Some(port);
            self.selected_ql = ql;
            Some((port, ql))
        } else {
            self.selected_port = None;
            self.selected_ql = QualityLevel::QlDnu;
            None
        }
    }
}

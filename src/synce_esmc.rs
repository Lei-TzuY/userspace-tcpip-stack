//! Synchronous Ethernet (SyncE) Ethernet Synchronization Messaging Channel (ESMC - ITU-T G.8264 / IEEE 802.3 Clause 57).
//!
//! Implements SyncE ESMC packet parsing, serialization, Synchronization Status Message (SSM)
//! Quality Level (QL) decoding (Option I: QL-PRC, QL-SSU-A, QL-SSU-B, QL-SEC, QL-DNU; Option II: QL-PRS, QL-STU, QL-ST2, etc.),
//! ITU-T G.8264 Amendment 1 Extended QL TLVs (ePRC, ePRTC, PRTC, eEEC / ITU-T G.8262.1), Clock Identity,
//! and dynamic clock selection arbitration with Wait-To-Restore (WTR) flap-damping for 5G/RAN fronthaul.

use std::collections::HashMap;

/// Slow Protocols EtherType (IEEE 802.3 Clause 57 / 802.1AX).
pub const ETHERTYPE_SLOW_PROTOCOLS: u16 = 0x8809;

/// ESMC Subtype within Slow Protocols (ITU-T G.8264).
pub const ESMC_SUBTYPE: u8 = 0x0A;

/// ITU-T Organizationally Unique Identifier (OUI: 00-19-A7).
pub const ITU_T_OUI: [u8; 3] = [0x00, 0x19, 0xA7];

/// ITU-T ESMC Subtype.
pub const ITU_T_ESMC_SUBTYPE: u16 = 0x0001;

/// TLV Type for QL TLV (ITU-T G.8264 Section 11.3.1.1).
pub const TLV_TYPE_QL: u8 = 0x01;

/// TLV Type for Extended QL TLV (ITU-T G.8264 Amendment 1 Section 11.3.1.2).
pub const TLV_TYPE_EXTENDED_QL: u8 = 0x02;

/// Standard ESMC QL TLV Length.
pub const QL_TLV_LEN: u16 = 0x0004;

/// Standard Extended QL TLV Length (20 octets total including type and length).
pub const EXTENDED_QL_TLV_LEN: u16 = 0x0014;

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

/// Enhanced Quality Level (ITU-T G.8264 Amendment 1 / G.8262.1 / G.8272).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum EnhancedQualityLevel {
    /// Enhanced Primary Reference Time Clock (ITU-T G.8272.1).
    QlEprtc = 0x20,
    /// Primary Reference Time Clock (ITU-T G.8272).
    QlPrtc = 0x21,
    /// Enhanced Primary Reference Clock (ITU-T G.811.1).
    QlEprc = 0x22,
    /// Enhanced Synchronous Equipment Clock (eEEC - ITU-T G.8262.1).
    QlEeec = 0x23,
    /// Primary Reference Clock (ITU-T G.811).
    QlPrc = 0x02,
    /// Synchronous Equipment Clock (EEC - ITU-T G.8262).
    QlSec = 0x0B,
    /// Do Not Use.
    QlDnu = 0xFF,
    #[default]
    QlUnknown = 0x00,
}

impl EnhancedQualityLevel {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x20 => EnhancedQualityLevel::QlEprtc,
            0x21 => EnhancedQualityLevel::QlPrtc,
            0x22 => EnhancedQualityLevel::QlEprc,
            0x23 => EnhancedQualityLevel::QlEeec,
            0x02 => EnhancedQualityLevel::QlPrc,
            0x0B => EnhancedQualityLevel::QlSec,
            0xFF => EnhancedQualityLevel::QlDnu,
            _ => EnhancedQualityLevel::QlUnknown,
        }
    }

    /// Enhanced clock quality rank (lower value = higher precision).
    pub fn rank(&self) -> u8 {
        match self {
            EnhancedQualityLevel::QlEprtc => 1,
            EnhancedQualityLevel::QlPrtc => 2,
            EnhancedQualityLevel::QlEprc => 3,
            EnhancedQualityLevel::QlPrc => 4,
            EnhancedQualityLevel::QlEeec => 5,
            EnhancedQualityLevel::QlSec => 6,
            EnhancedQualityLevel::QlDnu => 254,
            EnhancedQualityLevel::QlUnknown => 255,
        }
    }
}

/// Option II SSM Quality Levels (ANSI / Telcordia GR-253 / ITU-T G.781 Option II).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum QualityLevelOption2 {
    /// Primary Reference Source (PRS).
    QlPrs = 0x01,
    /// Synchronized - Traceability Unknown (STU).
    QlStu = 0x00,
    /// Stratum 2 (ST2).
    QlSt2 = 0x0C,
    /// Transit Node Clock (TNC).
    QlTnc = 0x04,
    /// Stratum 3E (ST3E).
    QlSt3e = 0x0D,
    /// Stratum 3 (ST3).
    QlSt3 = 0x0A,
    /// SONET Minimum Clock (SMC).
    QlSmc = 0x0E,
    /// Provisionally by Network Operator (PROV).
    QlProv = 0x07,
    /// Do Not Use for Synchronization (DUS).
    QlDus = 0x0F,
    #[default]
    QlInvalid = 0xFF,
}

impl QualityLevelOption2 {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0x01 => QualityLevelOption2::QlPrs,
            0x00 => QualityLevelOption2::QlStu,
            0x0C => QualityLevelOption2::QlSt2,
            0x04 => QualityLevelOption2::QlTnc,
            0x0D => QualityLevelOption2::QlSt3e,
            0x0A => QualityLevelOption2::QlSt3,
            0x0E => QualityLevelOption2::QlSmc,
            0x07 => QualityLevelOption2::QlProv,
            0x0F => QualityLevelOption2::QlDus,
            _ => QualityLevelOption2::QlInvalid,
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            QualityLevelOption2::QlPrs => 1,
            QualityLevelOption2::QlStu => 2,
            QualityLevelOption2::QlSt2 => 3,
            QualityLevelOption2::QlTnc => 4,
            QualityLevelOption2::QlSt3e => 5,
            QualityLevelOption2::QlSt3 => 6,
            QualityLevelOption2::QlSmc => 7,
            QualityLevelOption2::QlProv => 8,
            QualityLevelOption2::QlDus => 254,
            QualityLevelOption2::QlInvalid => 255,
        }
    }
}

/// Extended QL TLV (ITU-T G.8264 Amendment 1 Section 11.3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedQlTlv {
    pub enhanced_ql: EnhancedQualityLevel,
    pub clock_identity: [u8; 8],
    pub mixed_network: bool,
    pub cascaded_eeec_count: u8,
    pub cascaded_eprtc_count: u8,
}

impl ExtendedQlTlv {
    pub fn new(enhanced_ql: EnhancedQualityLevel, clock_identity: [u8; 8]) -> Self {
        Self {
            enhanced_ql,
            clock_identity,
            mixed_network: false,
            cascaded_eeec_count: 0,
            cascaded_eprtc_count: 0,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);
        buf.push(TLV_TYPE_EXTENDED_QL);
        buf.extend_from_slice(&EXTENDED_QL_TLV_LEN.to_be_bytes()); // 20
        buf.push(self.enhanced_ql as u8);
        buf.extend_from_slice(&self.clock_identity);
        let flag_byte = if self.mixed_network { 0x01 } else { 0x00 };
        buf.push(flag_byte);
        buf.push(self.cascaded_eeec_count);
        buf.push(self.cascaded_eprtc_count);
        // 5 bytes reserved padding to reach 20 octets total TLV length
        buf.extend_from_slice(&[0x00; 5]);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 15 {
            return None;
        }
        if data[0] != TLV_TYPE_EXTENDED_QL {
            return None;
        }
        let len = u16::from_be_bytes([data[1], data[2]]);
        if len < 15 || data.len() < len as usize {
            return None;
        }

        let enhanced_ql = EnhancedQualityLevel::from_u8(data[3]);
        let mut clock_identity = [0u8; 8];
        clock_identity.copy_from_slice(&data[4..12]);
        let mixed_network = (data[12] & 0x01) != 0;
        let cascaded_eeec_count = data[13];
        let cascaded_eprtc_count = data[14];

        Some(ExtendedQlTlv {
            enhanced_ql,
            clock_identity,
            mixed_network,
            cascaded_eeec_count,
            cascaded_eprtc_count,
        })
    }
}

/// SyncE ESMC PDU (ITU-T G.8264 Section 11.3.1 & Amendment 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncEEsmcPacket {
    pub event_flag: bool,
    pub quality_level: QualityLevel,
    pub extended_ql: Option<ExtendedQlTlv>,
}

impl SyncEEsmcPacket {
    pub fn new(event_flag: bool, quality_level: QualityLevel) -> Self {
        SyncEEsmcPacket {
            event_flag,
            quality_level,
            extended_ql: None,
        }
    }

    pub fn with_extended_ql(mut self, extended_ql: ExtendedQlTlv) -> Self {
        self.extended_ql = Some(extended_ql);
        self
    }

    /// Serializes the ESMC PDU into raw bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.push(ESMC_SUBTYPE);
        buf.extend_from_slice(&ITU_T_OUI);
        buf.extend_from_slice(&ITU_T_ESMC_SUBTYPE.to_be_bytes());

        let flag_byte = if self.event_flag { 0x08 } else { 0x00 };
        buf.push(flag_byte); // Version = 0 (bits 7-4), Event = bit 3
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // 3 reserved bytes

        // QL TLV (Type 0x01, Length 0x0004)
        buf.push(TLV_TYPE_QL); // Type = QL TLV
        buf.extend_from_slice(&QL_TLV_LEN.to_be_bytes()); // Length = 4
        buf.push(self.quality_level as u8); // SSM Code (lower 4 bits)

        // Extended QL TLV if present
        if let Some(ref ext) = self.extended_ql {
            buf.extend_from_slice(&ext.serialize());
        }

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
        if tlv_type != TLV_TYPE_QL || tlv_len < 4 || data.len() < 14 {
            return None;
        }

        let ql = QualityLevel::from_u8(data[13]);

        // Check for Extended QL TLV
        let mut extended_ql = None;
        let mut offset = 14;
        while offset + 3 <= data.len() {
            let next_type = data[offset];
            let next_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
            if next_type == TLV_TYPE_EXTENDED_QL
                && next_len >= 15
                && offset + next_len <= data.len()
            {
                extended_ql = ExtendedQlTlv::parse(&data[offset..offset + next_len]);
                break;
            } else if next_len == 0 || offset + next_len > data.len() {
                break;
            }
            offset += next_len;
        }

        Some(SyncEEsmcPacket {
            event_flag,
            quality_level: ql,
            extended_ql,
        })
    }
}

/// Port Clock State for Synchronization Arbitration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSyncState {
    Active,
    WaitToRestore { remaining_ticks: u32 },
    Failed,
}

/// SyncE Clock Source Selection & ESMC Protocol Engine with WTR Flap Damping.
#[derive(Debug, Clone)]
pub struct SyncEEsmcEngine {
    pub port_ql: HashMap<u32, QualityLevel>,
    pub port_ext_ql: HashMap<u32, ExtendedQlTlv>,
    pub port_priority: HashMap<u32, u8>,
    pub port_states: HashMap<u32, PortSyncState>,
    pub wtr_ticks_config: u32,
    pub selected_port: Option<u32>,
    pub selected_ql: QualityLevel,
    pub selected_ext_ql: Option<EnhancedQualityLevel>,
    pub event_messages_received: usize,
    pub holdover_active: bool,
}

impl Default for SyncEEsmcEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncEEsmcEngine {
    pub fn new() -> Self {
        SyncEEsmcEngine {
            port_ql: HashMap::new(),
            port_ext_ql: HashMap::new(),
            port_priority: HashMap::new(),
            port_states: HashMap::new(),
            wtr_ticks_config: 0,
            selected_port: None,
            selected_ql: QualityLevel::QlInvalid,
            selected_ext_ql: None,
            event_messages_received: 0,
            holdover_active: false,
        }
    }

    /// Configures the Wait-To-Restore (WTR) timer duration in arbitration ticks.
    pub fn set_wtr_duration(&mut self, ticks: u32) {
        self.wtr_ticks_config = ticks;
    }

    /// Configures the administrative priority for a physical SyncE port.
    pub fn set_port_priority(&mut self, port: u32, priority: u8) {
        self.port_priority.insert(port, priority);
    }

    /// Advances the WTR timer by one tick and arbitrates clock selection.
    pub fn tick_wtr(&mut self) {
        let mut restored = Vec::new();
        for (&port, state) in self.port_states.iter_mut() {
            if let PortSyncState::WaitToRestore { remaining_ticks } = state {
                if *remaining_ticks <= 1 {
                    restored.push(port);
                } else {
                    *remaining_ticks -= 1;
                }
            }
        }
        for port in restored {
            self.port_states.insert(port, PortSyncState::Active);
        }
        self.arbitrate_clock_selection();
    }

    /// Ingests a received ESMC packet on a port and triggers clock selection.
    pub fn process_rx_esmc(&mut self, port: u32, pkt: &SyncEEsmcPacket) {
        if pkt.event_flag {
            self.event_messages_received += 1;
        }

        let new_ql = pkt.quality_level;

        if let Some(ext) = pkt.extended_ql {
            self.port_ext_ql.insert(port, ext);
        } else {
            self.port_ext_ql.remove(&port);
        }

        let is_failed = matches!(self.port_states.get(&port), Some(PortSyncState::Failed));

        // Flap damping: If port was in failed state and now recovers to a valid QL
        if is_failed
            && (new_ql != QualityLevel::QlDnu && new_ql != QualityLevel::QlInvalid)
            && self.wtr_ticks_config > 0
        {
            self.port_states.insert(
                port,
                PortSyncState::WaitToRestore {
                    remaining_ticks: self.wtr_ticks_config,
                },
            );
        } else if new_ql == QualityLevel::QlDnu || new_ql == QualityLevel::QlInvalid {
            self.port_states.insert(port, PortSyncState::Failed);
        } else if !self.port_states.contains_key(&port) {
            self.port_states.insert(port, PortSyncState::Active);
        }

        self.port_ql.insert(port, new_ql);
        self.arbitrate_clock_selection();
    }

    /// Computes the unified quality rank considering base QL and optional Extended QL.
    pub fn effective_rank(base_ql: QualityLevel, ext: Option<EnhancedQualityLevel>) -> u8 {
        if let Some(e) = ext {
            match e {
                EnhancedQualityLevel::QlEprtc => 1,
                EnhancedQualityLevel::QlPrtc => 2,
                EnhancedQualityLevel::QlEprc => 3,
                EnhancedQualityLevel::QlPrc => 4,
                EnhancedQualityLevel::QlEeec => 5,
                EnhancedQualityLevel::QlSec => 6,
                EnhancedQualityLevel::QlDnu => 254,
                EnhancedQualityLevel::QlUnknown => 255,
            }
        } else {
            match base_ql {
                QualityLevel::QlPrc => 4,
                QualityLevel::QlSsuA => 7,
                QualityLevel::QlSsuB => 8,
                QualityLevel::QlSec => 9,
                QualityLevel::QlDnu => 254,
                QualityLevel::QlInvalid => 255,
            }
        }
    }

    /// Performs ITU-T G.781 / G.8264 Amendment 1 Best Clock Selection Algorithm.
    pub fn arbitrate_clock_selection(&mut self) -> Option<(u32, QualityLevel)> {
        let mut best: Option<(u32, QualityLevel, Option<EnhancedQualityLevel>, u8, u8)> = None;

        for (&port, &ql) in &self.port_ql {
            if ql == QualityLevel::QlDnu || ql == QualityLevel::QlInvalid {
                continue;
            }
            // Skip ports currently in Wait-To-Restore or Failed state
            if let Some(state) = self.port_states.get(&port) {
                if matches!(
                    state,
                    PortSyncState::WaitToRestore { .. } | PortSyncState::Failed
                ) {
                    continue;
                }
            }

            let ext_ql = self.port_ext_ql.get(&port).map(|e| e.enhanced_ql);
            let effective_rank = Self::effective_rank(ql, ext_ql);
            let prio = self.port_priority.get(&port).copied().unwrap_or(128);

            match best {
                None => {
                    best = Some((port, ql, ext_ql, effective_rank, prio));
                }
                Some((_, _, _, b_rank, b_prio)) => {
                    if effective_rank < b_rank || (effective_rank == b_rank && prio < b_prio) {
                        best = Some((port, ql, ext_ql, effective_rank, prio));
                    }
                }
            }
        }

        if let Some((port, ql, ext_ql, _, _)) = best {
            self.selected_port = Some(port);
            self.selected_ql = ql;
            self.selected_ext_ql = ext_ql;
            self.holdover_active = false;
            Some((port, ql))
        } else {
            // No valid active candidate port found -> transition into Holdover state
            if self.selected_port.is_some() {
                self.holdover_active = true;
            }
            self.selected_port = None;
            self.selected_ql = QualityLevel::QlDnu;
            self.selected_ext_ql = None;
            None
        }
    }

    /// Generates the outbound ESMC packet to be transmitted on a port.
    ///
    /// According to ITU-T G.781 timing loop prevention:
    /// - If `port == self.selected_port`, the node MUST transmit QL-DNU (Do Not Use)
    ///   towards the master clock source to prevent timing loops.
    /// - For all other ports, the node forwards the current synchronized clock quality
    ///   (`selected_ql` and optional `selected_ext_ql`).
    /// - If in Holdover, transmits QL-SEC (or local oscillator specification).
    pub fn generate_tx_esmc(&self, port: u32, clock_identity: [u8; 8]) -> SyncEEsmcPacket {
        if Some(port) == self.selected_port {
            // Timing loop prevention: Never echo valid clock back to source
            return SyncEEsmcPacket::new(false, QualityLevel::QlDnu);
        }

        if self.holdover_active {
            let mut pkt = SyncEEsmcPacket::new(false, QualityLevel::QlSec);
            if self.selected_ext_ql.is_some() {
                pkt.extended_ql = Some(ExtendedQlTlv::new(
                    EnhancedQualityLevel::QlSec,
                    clock_identity,
                ));
            }
            return pkt;
        }

        if self.selected_port.is_none()
            || self.selected_ql == QualityLevel::QlDnu
            || self.selected_ql == QualityLevel::QlInvalid
        {
            return SyncEEsmcPacket::new(false, QualityLevel::QlDnu);
        }

        let mut pkt = SyncEEsmcPacket::new(false, self.selected_ql);
        if let Some(ext) = self.selected_ext_ql {
            let mut ext_tlv = ExtendedQlTlv::new(ext, clock_identity);
            // If we have an upstream extended TLV on the selected port, copy cascade hops
            if let Some(upstream_ext) = self.selected_port.and_then(|p| self.port_ext_ql.get(&p)) {
                ext_tlv.mixed_network = upstream_ext.mixed_network;
                ext_tlv.cascaded_eeec_count = upstream_ext.cascaded_eeec_count.saturating_add(1);
                ext_tlv.cascaded_eprtc_count = upstream_ext.cascaded_eprtc_count;
            }
            pkt.extended_ql = Some(ext_tlv);
        }
        pkt
    }
}

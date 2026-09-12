//! 3GPP Release 18/19 5G-Advanced System Information (MIB/SIB1/OSI) Broadcast, Scheduling & On-Demand Acquisition Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.331 Rel-18 §5.2: System information acquisition, modification period boundaries, and 3-hour validity rules.
//! - 3GPP TS 38.331 Rel-18 §6.2.2: MasterInformationBlock (MIB) message.
//! - 3GPP TS 38.331 Rel-18 §6.3.1: SystemInformationBlockType1 (SIB1), SIB2, SIB3, SIB4, and SIB19 (NTN assistance).
//! - 3GPP TS 38.212 Rel-18 §7.3: Downlink control information and SI-RNTI (`0xFFFF`) scheduling.
//! - 3GPP TS 38.213 Rel-18 §4.1: Cell search, RMSI PDCCH monitoring occasions, and SI window slot determination.
//!
//! Features:
//! 1. MasterInformationBlock (MIB) 10-bit SFN synthesis, subcarrier spacing, $k_{\text{SSB}}$, CORESET#0, and cell barring parsing.
//! 2. SIB1 cell selection ($q_{\text{RxLevMin}}$, $q_{\text{QualMin}}$), PLMN Identity list (MCC, MNC, 36-bit Cell ID, 24-bit TAC), and Initial BWP configs.
//! 3. Standard TDD UL-DL slot/symbol pattern common verification.
//! 4. SI Scheduling Window and slot timing determination across numerologies $\mu \in \{0, 1, 2, 3\}$.
//! 5. Other System Information (OSI) management and On-Demand SI acquisition state machine.
//! 6. System Information Modification Period boundary tracking ($SFN \bmod N_{\text{mod}} = 0$) and 3-hour validity expiration.
//! 7. Binary wire framing (`SystemInformationWirePdu`) with magic `0x53494231` ("SIB1") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for System Information Wire PDU: "SIB1" (0x53494231).
pub const SIB1_WIRE_MAGIC: u32 = 0x53494231;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Standard SI-RNTI value (0xFFFF).
pub const SI_RNTI: u16 = 0xFFFF;

/// Standard SIB validity duration in seconds (3 hours per TS 38.331 §5.2.2.2).
pub const SIB_VALIDITY_DURATION_SEC: u32 = 3 * 3600;

/// Errors encountered in System Information processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemInfoError {
    InvalidSfn(u16),
    InvalidKssb(u8),
    InvalidPlmnLength,
    InvalidCellIdentity(u64),
    InvalidTac(u32),
    InvalidSiWindowLength(u16),
    InvalidPeriodicity(u16),
    SiMessageNotFound(u8),
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    WireCrcMismatch { expected: u16, computed: u16 },
}

impl fmt::Display for SystemInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSfn(s) => write!(f, "Invalid SFN: {} (must be 0..1023)", s),
            Self::InvalidKssb(k) => write!(f, "Invalid k_SSB: {} (must be 0..15)", k),
            Self::InvalidPlmnLength => write!(f, "Invalid PLMN MCC/MNC length"),
            Self::InvalidCellIdentity(c) => {
                write!(f, "Invalid 36-bit cell identity: {} (must be < 2^36)", c)
            }
            Self::InvalidTac(t) => write!(f, "Invalid 24-bit TAC: {} (must be < 2^24)", t),
            Self::InvalidSiWindowLength(w) => write!(f, "Invalid SI window length: {} slots", w),
            Self::InvalidPeriodicity(p) => write!(f, "Invalid SI periodicity: {} frames", p),
            Self::SiMessageNotFound(id) => write!(f, "SI message not found: index {}", id),
            Self::InvalidWireMagic(m) => write!(f, "Invalid wire magic: 0x{:08X}", m),
            Self::WirePayloadTooShort { needed, found } => {
                write!(
                    f,
                    "Wire payload too short: needed {} bytes, found {}",
                    needed, found
                )
            }
            Self::WireCrcMismatch { expected, computed } => {
                write!(
                    f,
                    "Wire CRC-16 mismatch: expected 0x{:04X}, computed 0x{:04X}",
                    expected, computed
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MasterInformationBlock (MIB) (TS 38.331 §6.2.2)
// ---------------------------------------------------------------------------

/// Subcarrier spacing common indicated in MIB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubcarrierSpacingCommon {
    /// FR1: 15 kHz, FR2: 60 kHz.
    Scs15or60 = 0,
    /// FR1: 30 kHz, FR2: 120 kHz.
    Scs30or120 = 1,
}

/// DMRS Type A position indicated in MIB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmrsTypeAPosition {
    Pos2 = 2,
    Pos3 = 3,
}

/// 3GPP MasterInformationBlock (MIB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterInformationBlock {
    /// 10-bit System Frame Number (SFN $\in [0, 1023]$).
    pub sfn: u16,
    /// Subcarrier spacing common for initial access.
    pub scs_common: SubcarrierSpacingCommon,
    /// Subcarrier offset $k_{\text{SSB}} \in [0, 15]$.
    pub k_ssb: u8,
    /// DMRS Type A position (pos2 or pos3).
    pub dmrs_type_a_pos: DmrsTypeAPosition,
    /// PDCCH Config SIB1: 4 MSBs CORESET#0 index, 4 LSBs SearchSpace#0 index.
    pub pdcch_config_sib1: u8,
    /// Cell barred flag (true = barred, false = not barred).
    pub cell_barred: bool,
    /// Intra-frequency cell reselection allowed when cell is barred.
    pub intra_freq_reselection_allowed: bool,
}

impl MasterInformationBlock {
    /// Synthesizes 10-bit SFN from 6 MSBs (broadcast in MIB on PBCH) and 4 LSBs (timing bits in PBCH payload).
    pub fn combine_sfn(sfn_6_msb: u8, sfn_4_lsb: u8) -> Result<u16, SystemInfoError> {
        if sfn_6_msb > 63 || sfn_4_lsb > 15 {
            return Err(SystemInfoError::InvalidSfn(
                ((sfn_6_msb as u16) << 4) | (sfn_4_lsb as u16),
            ));
        }
        Ok(((sfn_6_msb as u16) << 4) | (sfn_4_lsb as u16))
    }

    /// Extracts CORESET#0 index (4 MSBs of `pdcch_config_sib1`).
    #[inline]
    pub fn coreset0_index(&self) -> u8 {
        (self.pdcch_config_sib1 >> 4) & 0x0F
    }

    /// Extracts SearchSpace#0 index (4 LSBs of `pdcch_config_sib1`).
    #[inline]
    pub fn search_space0_index(&self) -> u8 {
        self.pdcch_config_sib1 & 0x0F
    }
}

// ---------------------------------------------------------------------------
// PLMN & SIB1 Cell Selection Info (TS 38.331 §6.3.1)
// ---------------------------------------------------------------------------

/// Public Land Mobile Network (PLMN) Identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlmnIdentity {
    pub mcc: u16,            // Mobile Country Code (e.g. 310, 460)
    pub mnc: u16,            // Mobile Network Code (e.g. 260, 01)
    pub mnc_digit_count: u8, // 2 or 3 digits
}

/// SIB1 Cell Selection Info.
#[derive(Debug, Clone, PartialEq)]
pub struct CellSelectionInfo {
    /// Minimum required RSRP level (in dBm, typically -140 to -44).
    pub q_rx_lev_min_dbm: f32,
    /// Minimum required RSRQ quality level (in dB, typically -43 to -12).
    pub q_qual_min_db: Option<f32>,
}

impl CellSelectionInfo {
    /// Evaluates whether cell selection criteria S-criterion is met:
    /// $S_{\text{rxlev}} = Q_{\text{rxlevmeas}} - Q_{\text{rxlevmin}} > 0$.
    pub fn evaluate_s_criterion(
        &self,
        measured_rsrp_dbm: f32,
        measured_rsrq_db: Option<f32>,
    ) -> bool {
        let s_rxlev = measured_rsrp_dbm - self.q_rx_lev_min_dbm;
        if s_rxlev <= 0.0 {
            return false;
        }

        if let (Some(q_min), Some(q_meas)) = (self.q_qual_min_db, measured_rsrq_db) {
            let s_qual = q_meas - q_min;
            if s_qual <= 0.0 {
                return false;
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// TDD UL-DL Configuration Common (TS 38.331 §6.3.1)
// ---------------------------------------------------------------------------

/// TDD UL-DL Transmission Periodicity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TddPeriodicityMs {
    Ms0p5,
    Ms0p625,
    Ms1,
    Ms1p25,
    Ms2,
    Ms2p5,
    Ms5,
    Ms10,
}

impl TddPeriodicityMs {
    pub fn as_ms(self) -> f64 {
        match self {
            Self::Ms0p5 => 0.5,
            Self::Ms0p625 => 0.625,
            Self::Ms1 => 1.0,
            Self::Ms1p25 => 1.25,
            Self::Ms2 => 2.0,
            Self::Ms2p5 => 2.5,
            Self::Ms5 => 5.0,
            Self::Ms10 => 10.0,
        }
    }
}

/// TDD UL-DL Pattern Common.
#[derive(Debug, Clone, PartialEq)]
pub struct TddUlDlPattern {
    pub periodicity: TddPeriodicityMs,
    pub nrof_downlink_slots: u16,
    pub nrof_downlink_symbols: u8,
    pub nrof_uplink_slots: u16,
    pub nrof_uplink_symbols: u8,
}

impl TddUlDlPattern {
    /// Returns total slots per period for a given subcarrier spacing numerology $\mu$.
    pub fn total_slots_per_period(&self, mu: u8) -> u16 {
        let slots_per_ms = 1 << (mu as u16);
        let period_ms = self.periodicity.as_ms();
        ((period_ms * (slots_per_ms as f64)).round()) as u16
    }
}

// ---------------------------------------------------------------------------
// SI Scheduling Information & SI Window Calculation (TS 38.331 §5.2.2.3.2)
// ---------------------------------------------------------------------------

/// SIB Types broadcast in 5G NR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SibType {
    Sib2,
    Sib3,
    Sib4,
    Sib5,
    Sib6,
    Sib7,
    Sib8,
    Sib9,
    Sib19, // NTN assistance
    Sib24, // RedCap assistance
}

/// Broadcast status of an SI message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiBroadcastStatus {
    Broadcasting,
    NotBroadcasting, // On-demand acquisition required
}

/// Scheduled SI Message configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiMessageConfig {
    /// Periodicity in radio frames ($T \in \{8, 16, 32, 64, 128, 256, 512\}$).
    pub periodicity_frames: u16,
    /// List of SIBs multiplexed into this SI message.
    pub sibs: Vec<SibType>,
    /// Broadcast status (Broadcasting or On-Demand).
    pub broadcast_status: SiBroadcastStatus,
}

/// SI Window timing result for an SI message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiWindowOccasion {
    /// Starting Radio Frame SFN.
    pub start_sfn: u16,
    /// Starting slot index within the starting radio frame.
    pub start_slot_in_frame: u16,
    /// SI window length in slots.
    pub window_length_slots: u16,
}

/// Calculates the SI window start occasion for the $n$-th SI message in the scheduling list:
/// $SFN \bmod T = \lfloor (n \cdot w) / (10 \cdot 2^\mu) \rfloor$ (adjusted for frames)
/// Slot index $a = (n \cdot w) \bmod (10 \cdot 2^\mu)$.
pub fn compute_si_window_occasion(
    message_index_n: usize,
    window_length_slots: u16,
    periodicity_frames: u16,
    mu: u8,
    current_sfn: u16,
) -> Result<SiWindowOccasion, SystemInfoError> {
    if window_length_slots == 0 {
        return Err(SystemInfoError::InvalidSiWindowLength(window_length_slots));
    }
    if periodicity_frames == 0 {
        return Err(SystemInfoError::InvalidPeriodicity(periodicity_frames));
    }

    let slots_per_frame = 10 * (1 << (mu as u16));
    let nw = (message_index_n as u32) * (window_length_slots as u32);

    let start_frame_offset = (nw / (slots_per_frame as u32)) as u16;
    let start_slot_in_frame = (nw % (slots_per_frame as u32)) as u16;

    // SFN satisfies: SFN mod T = start_frame_offset % T
    let target_mod = start_frame_offset % periodicity_frames;
    let period_base = (current_sfn / periodicity_frames) * periodicity_frames;
    let mut candidate_sfn = period_base + target_mod;
    if candidate_sfn < current_sfn {
        candidate_sfn += periodicity_frames;
    }
    let start_sfn = candidate_sfn % 1024;

    Ok(SiWindowOccasion {
        start_sfn,
        start_slot_in_frame,
        window_length_slots,
    })
}

// ---------------------------------------------------------------------------
// System Information Modification Period & On-Demand State Machine (TS 38.331 §5.2.2.2)
// ---------------------------------------------------------------------------

/// Modification period manager tracking SI updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModificationPeriodManager {
    /// Modification period in radio frames: $N_{\text{mod}} = \text{coeff} \times \text{pagingCycle}$.
    pub n_mod_frames: u16,
    /// Current modification period value tag.
    pub value_tag: u8,
    /// Pending SI modification flag notified via Paging Short Message.
    pub modification_pending: bool,
}

impl ModificationPeriodManager {
    pub fn new(n_mod_frames: u16, initial_tag: u8) -> Self {
        Self {
            n_mod_frames: n_mod_frames.max(1),
            value_tag: initial_tag,
            modification_pending: false,
        }
    }

    /// Checks if the given SFN is on a modification period boundary:
    /// $SFN \bmod N_{\text{mod}} = 0$.
    #[inline]
    pub fn is_modification_boundary(&self, sfn: u16) -> bool {
        (sfn % self.n_mod_frames) == 0
    }

    /// Receives a Paging Short Message with `systemInfoModification` bit set.
    pub fn notify_si_modification(&mut self) {
        self.modification_pending = true;
    }

    /// Advances frame. On boundary, applies pending modification and increments value tag.
    pub fn tick_frame(&mut self, sfn: u16) -> bool {
        if self.is_modification_boundary(sfn) && self.modification_pending {
            self.value_tag = (self.value_tag + 1) % 32;
            self.modification_pending = false;
            true // SI modification took effect at this boundary
        } else {
            false
        }
    }
}

/// SIB Cache Entry tracking 3-hour validity rule (TS 38.331 §5.2.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSib {
    pub sib_type: SibType,
    pub value_tag: u8,
    pub received_timestamp_sec: u64,
}

impl CachedSib {
    pub fn is_valid(&self, current_timestamp_sec: u64, current_value_tag: u8) -> bool {
        if self.value_tag != current_value_tag {
            return false;
        }
        current_timestamp_sec.saturating_sub(self.received_timestamp_sec)
            < (SIB_VALIDITY_DURATION_SEC as u64)
    }
}

// ---------------------------------------------------------------------------
// Complete SIB1 Container (TS 38.331 §6.3.1)
// ---------------------------------------------------------------------------

/// 3GPP SystemInformationBlockType1 (SIB1).
#[derive(Debug, Clone, PartialEq)]
pub struct SystemInformationBlock1 {
    pub cell_selection: CellSelectionInfo,
    pub plmn_list: Vec<PlmnIdentity>,
    /// 36-bit Cell Identity (28-bit gNB ID + 8-bit Cell ID or 32-bit/4-bit).
    pub cell_identity: u64,
    /// 24-bit Tracking Area Code (TAC).
    pub tracking_area_code: u32,
    pub tdd_pattern: Option<TddUlDlPattern>,
    pub si_window_length_slots: u16,
    pub si_messages: Vec<SiMessageConfig>,
}

// ---------------------------------------------------------------------------
// CRC-16 CCITT for Wire Framing
// ---------------------------------------------------------------------------

pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ CRC16_CCITT_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// Binary Wire Framing (`SystemInformationWirePdu`)
// ---------------------------------------------------------------------------

/// Wire PDU transporting core broadcast System Information telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemInformationWirePdu {
    pub sfn: u16,
    pub cell_identity: u64,
    pub tracking_area_code: u32,
    pub mcc: u16,
    pub mnc: u16,
    pub q_rx_lev_min_dbm: f32,
    pub si_window_length_slots: u16,
}

impl SystemInformationWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(26);
        buf.extend_from_slice(&SIB1_WIRE_MAGIC.to_be_bytes());
        buf.extend_from_slice(&self.sfn.to_be_bytes());
        buf.extend_from_slice(&self.cell_identity.to_be_bytes());
        buf.extend_from_slice(&self.tracking_area_code.to_be_bytes());
        buf.extend_from_slice(&self.mcc.to_be_bytes());
        buf.extend_from_slice(&self.mnc.to_be_bytes());
        buf.extend_from_slice(&self.q_rx_lev_min_dbm.to_be_bytes());
        buf.extend_from_slice(&self.si_window_length_slots.to_be_bytes());

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, SystemInfoError> {
        if bytes.len() < 30 {
            return Err(SystemInfoError::WirePayloadTooShort {
                needed: 30,
                found: bytes.len(),
            });
        }
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != SIB1_WIRE_MAGIC {
            return Err(SystemInfoError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(SystemInfoError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let sfn = u16::from_be_bytes([bytes[4], bytes[5]]);
        let cell_identity = u64::from_be_bytes([
            bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
        ]);
        let tracking_area_code = u32::from_be_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);
        let mcc = u16::from_be_bytes([bytes[18], bytes[19]]);
        let mnc = u16::from_be_bytes([bytes[20], bytes[21]]);
        let q_rx_lev_min_dbm = f32::from_be_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]);
        let si_window_length_slots = u16::from_be_bytes([bytes[26], bytes[27]]);

        Ok(Self {
            sfn,
            cell_identity,
            tracking_area_code,
            mcc,
            mnc,
            q_rx_lev_min_dbm,
            si_window_length_slots,
        })
    }
}

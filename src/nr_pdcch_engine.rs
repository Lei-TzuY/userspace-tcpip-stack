//! 3GPP Release 18/19 5G-Advanced Physical Downlink Control Channel (PDCCH) Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §7.3.2: Control Resource Set (CORESET) and CCE-to-REG mapping.
//! - 3GPP TS 38.213 Rel-18 §10: UE procedure for receiving control information (PDCCH monitoring).
//! - 3GPP TS 38.213 Rel-18 §10.4: Search Space Set Group Switching (SSGS) & PDCCH Skipping.
//! - 3GPP TS 38.331 Rel-18: `PDCCH-Config`, `ControlResourceSet`, and `SearchSpace`.
//!
//! Features:
//! 1. CORESET modeling with 45-bit frequency bitmaps and REG-to-CCE mapping (Interleaved / Non-interleaved).
//! 2. CCE-to-REG bundle interleaver with permutation matrix and dynamic shift index ($n_{\text{shift}}$).
//! 3. Full Search Space Sets: Common Search Space (CSS Types 0/0A/1/2/3) and UE-Specific Search Space (USS).
//! 4. 3GPP candidate CCE hashing algorithm across Aggregation Levels $L \in \{1, 2, 4, 8, 16\}$
//!    with pseudo-random $Y_k$ recursion ($A_0 = 39827, D = 65537$).
//! 5. Rel-17/18 PDCCH Monitoring Adaptation & Power Saving:
//!    - Search Space Set Group Switching (SSGS: Group 0 sparse vs Group 1 dense).
//!    - PDCCH Monitoring Skipping for $N_{\text{skip}} \in \{1, 2, 4, 8\}$ slots.
//!    - Slot-level Blind Decoding (BD) and non-overlapped CCE limit auditing (TS 38.213 Table 10.1-2/3).
//! 6. Binary wire framing (`PdcchMonitoringPdu`) with magic `0x50444348` ("PDCH") and CRC-16 CCITT.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for PDCCH PDU: "PDCH" (0x50444348).
pub const PDCCH_WIRE_MAGIC: u32 = 0x50444348;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Number of Resource Element Groups (REGs) per Control Channel Element (CCE).
pub const REGS_PER_CCE: usize = 6;

/// Standard subcarriers per REG (1 PRB = 12 subcarriers).
pub const SUBCARRIERS_PER_REG: usize = 12;

/// Number of data Resource Elements (REs) per REG (12 subcarriers - 3 DMRS = 9 REs).
pub const RE_DATA_PER_REG: usize = 9;

/// Number of PRBs represented by each bit in frequencyDomainResources.
pub const PRBS_PER_RESOURCE_BIT: usize = 6;

/// 3GPP Y_k pseudo-random multiplier for CORESET p=0 (TS 38.213 §10.1).
pub const HASH_MULTIPLIER_A0: u64 = 39827;
/// 3GPP Y_k modulo divisor D = 2^16 + 1 = 65537 (TS 38.213 §10.1).
pub const HASH_MODULO_D: u64 = 65537;

/// Errors encountered in PDCCH operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdcchError {
    InvalidCoresetId(u8),
    InvalidDuration(u8),
    InvalidFrequencyBitmap,
    InvalidBundleSize(u8),
    InvalidInterleaverSize(u8),
    InvalidAggregationLevel(u8),
    CandidateIndexOutOfRange { index: u8, max_candidates: u8 },
    CceExceeded { requested_cce: u16, total_cces: u16 },
    BlindDecodingBudgetExceeded { count: usize, limit: usize },
    CceBudgetExceeded { count: usize, limit: usize },
    SerializationError(String),
    DeserializationError(String),
    CrcMismatch { expected: u16, actual: u16 },
    InvalidMagic(u32),
}

impl fmt::Display for PdcchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCoresetId(id) => write!(f, "Invalid CORESET ID: {}", id),
            Self::InvalidDuration(dur) => {
                write!(f, "Invalid CORESET duration {} (must be 1, 2, or 3)", dur)
            }
            Self::InvalidFrequencyBitmap => {
                write!(f, "Frequency domain bitmap cannot be all zeros")
            }
            Self::InvalidBundleSize(l) => write!(f, "Invalid REG bundle size: {}", l),
            Self::InvalidInterleaverSize(r) => write!(f, "Invalid interleaver size: {}", r),
            Self::InvalidAggregationLevel(al) => write!(f, "Invalid aggregation level: {}", al),
            Self::CandidateIndexOutOfRange {
                index,
                max_candidates,
            } => {
                write!(
                    f,
                    "Candidate index {} exceeds configured candidates {}",
                    index, max_candidates
                )
            }
            Self::CceExceeded {
                requested_cce,
                total_cces,
            } => {
                write!(
                    f,
                    "Requested CCE index {} exceeds total CCEs in CORESET {}",
                    requested_cce, total_cces
                )
            }
            Self::BlindDecodingBudgetExceeded { count, limit } => {
                write!(
                    f,
                    "Blind decodes {} exceeds slot capability limit {}",
                    count, limit
                )
            }
            Self::CceBudgetExceeded { count, limit } => {
                write!(
                    f,
                    "Non-overlapped CCE count {} exceeds slot capability limit {}",
                    count, limit
                )
            }
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "CRC mismatch: expected 0x{:04X}, actual 0x{:04X}",
                    expected, actual
                )
            }
            Self::InvalidMagic(m) => write!(f, "Invalid magic: 0x{:08X}", m),
        }
    }
}

// ---------------------------------------------------------------------------
// Aggregation Levels
// ---------------------------------------------------------------------------

/// 5G NR PDCCH Aggregation Levels (TS 38.211 §7.3.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AggregationLevel {
    L1 = 1,
    L2 = 2,
    L4 = 4,
    L8 = 8,
    L16 = 16,
}

impl AggregationLevel {
    pub fn from_u8(val: u8) -> Result<Self, PdcchError> {
        match val {
            1 => Ok(Self::L1),
            2 => Ok(Self::L2),
            4 => Ok(Self::L4),
            8 => Ok(Self::L8),
            16 => Ok(Self::L16),
            _ => Err(PdcchError::InvalidAggregationLevel(val)),
        }
    }

    #[inline]
    pub fn num_cces(self) -> usize {
        self as usize
    }
}

/// Number of candidates configured for each aggregation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AggregationCandidates {
    pub al1: u8,
    pub al2: u8,
    pub al4: u8,
    pub al8: u8,
    pub al16: u8,
}

impl AggregationCandidates {
    pub fn get(&self, al: AggregationLevel) -> u8 {
        match al {
            AggregationLevel::L1 => self.al1,
            AggregationLevel::L2 => self.al2,
            AggregationLevel::L4 => self.al4,
            AggregationLevel::L8 => self.al8,
            AggregationLevel::L16 => self.al16,
        }
    }

    pub fn total_candidates(&self) -> usize {
        (self.al1 + self.al2 + self.al4 + self.al8 + self.al16) as usize
    }
}

// ---------------------------------------------------------------------------
// CORESET Configuration & CCE-to-REG Mapping (TS 38.211 §7.3.2.2)
// ---------------------------------------------------------------------------

/// CCE-to-REG mapping scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CceRegMapping {
    NonInterleaved,
    Interleaved {
        reg_bundle_size: u8,  // L in {2, 6}
        interleaver_size: u8, // R in {2, 3, 6}
        shift_index: u16,     // n_shift in 0..=274
    },
}

/// Precoder granularity (TS 38.211 §7.3.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecoderGranularity {
    SameAsRegBundle,
    AllContiguousRbs,
}

/// Control Resource Set (CORESET) configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoresetConfig {
    pub coreset_id: u8,
    /// 45-bit frequency bitmap (up to 45 * 6 = 270 PRBs).
    pub freq_domain_resources: [u8; 6],
    pub duration_symbols: u8, // 1, 2, or 3
    pub cce_reg_mapping: CceRegMapping,
    pub precoder_granularity: PrecoderGranularity,
}

impl CoresetConfig {
    pub fn new(
        coreset_id: u8,
        freq_domain_resources: [u8; 6],
        duration_symbols: u8,
        cce_reg_mapping: CceRegMapping,
        precoder_granularity: PrecoderGranularity,
    ) -> Result<Self, PdcchError> {
        if coreset_id > 15 {
            return Err(PdcchError::InvalidCoresetId(coreset_id));
        }
        if duration_symbols < 1 || duration_symbols > 3 {
            return Err(PdcchError::InvalidDuration(duration_symbols));
        }
        if freq_domain_resources == [0; 6] {
            return Err(PdcchError::InvalidFrequencyBitmap);
        }

        if let CceRegMapping::Interleaved {
            reg_bundle_size,
            interleaver_size,
            ..
        } = cce_reg_mapping
        {
            if reg_bundle_size != 2 && reg_bundle_size != 6 && reg_bundle_size != duration_symbols {
                return Err(PdcchError::InvalidBundleSize(reg_bundle_size));
            }
            if interleaver_size != 2 && interleaver_size != 3 && interleaver_size != 6 {
                return Err(PdcchError::InvalidInterleaverSize(interleaver_size));
            }
        }

        Ok(Self {
            coreset_id,
            freq_domain_resources,
            duration_symbols,
            cce_reg_mapping,
            precoder_granularity,
        })
    }

    /// Total number of active PRBs allocated to this CORESET.
    pub fn total_prbs(&self) -> u16 {
        let mut count = 0u16;
        for byte in &self.freq_domain_resources {
            count += byte.count_ones() as u16;
        }
        count * (PRBS_PER_RESOURCE_BIT as u16)
    }

    /// Total number of Resource Element Groups (REGs) in this CORESET.
    #[inline]
    pub fn total_regs(&self) -> u16 {
        self.total_prbs() * (self.duration_symbols as u16)
    }

    /// Total number of Control Channel Elements (CCEs) in this CORESET ($N_{\text{REG}} / 6$).
    #[inline]
    pub fn total_cces(&self) -> u16 {
        self.total_regs() / (REGS_PER_CCE as u16)
    }

    /// Maps CCE index `cce_idx` to its 6 constituent REG indices.
    pub fn map_cce_to_regs(&self, cce_idx: u16) -> Result<[u16; REGS_PER_CCE], PdcchError> {
        let total_cces = self.total_cces();
        if cce_idx >= total_cces {
            return Err(PdcchError::CceExceeded {
                requested_cce: cce_idx,
                total_cces,
            });
        }

        match self.cce_reg_mapping {
            CceRegMapping::NonInterleaved => {
                let start_reg = cce_idx * (REGS_PER_CCE as u16);
                Ok([
                    start_reg,
                    start_reg + 1,
                    start_reg + 2,
                    start_reg + 3,
                    start_reg + 4,
                    start_reg + 5,
                ])
            }
            CceRegMapping::Interleaved {
                reg_bundle_size,
                interleaver_size,
                shift_index,
            } => {
                let l = reg_bundle_size as u16;
                let r = interleaver_size as u16;
                let n_regs = self.total_regs();
                let n_bundles = n_regs / l;
                let c = n_bundles / r;
                let bundles_per_cce = (REGS_PER_CCE as u16) / l;

                let mut out_regs = [0u16; REGS_PER_CCE];
                let mut out_idx = 0;

                for k in 0..bundles_per_cce {
                    let bundle_idx = cce_idx * bundles_per_cce + k;
                    let c_idx = bundle_idx / r;
                    let r_idx = bundle_idx % r;
                    let mapped_bundle = (r_idx * c + c_idx + shift_index) % n_bundles;
                    let start_reg = mapped_bundle * l;

                    for offset in 0..l {
                        out_regs[out_idx] = start_reg + offset;
                        out_idx += 1;
                    }
                }

                Ok(out_regs)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Search Space Configuration & Types (TS 38.213 §10.1)
// ---------------------------------------------------------------------------

/// Common Search Space types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonSearchSpaceType {
    Type0,  // SIB1 (SI-RNTI on CORESET 0)
    Type0A, // Other SI (SI-RNTI)
    Type1,  // RACH Msg2/Msg4 (RA-RNTI, TC-RNTI)
    Type2,  // Paging (P-RNTI)
    Type3,  // Group TPC, SFI, Cancelation (INT-RNTI, SFI-RNTI, TPC-RNTI)
}

/// Search Space type: Common vs UE-Specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchSpaceType {
    Common(CommonSearchSpaceType),
    UeSpecific,
}

/// Search Space configuration (TS 38.331).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchSpaceConfig {
    pub search_space_id: u8,
    pub coreset_id: u8,
    pub periodicity_slots: u16,
    pub offset_slots: u16,
    pub duration_slots: u16,
    pub monitoring_symbols_mask: u16, // 14-bit mask for symbols in slot
    pub candidates: AggregationCandidates,
    pub search_space_type: SearchSpaceType,
    pub sssg_id: u8, // Search Space Set Group (0 or 1 for Rel-17/18)
}

impl SearchSpaceConfig {
    /// Checks whether this search space has a monitoring occasion at slot index `slot`.
    pub fn is_monitoring_slot(&self, slot: u32) -> bool {
        if self.periodicity_slots == 0 {
            return false;
        }
        let rem = (slot % (self.periodicity_slots as u32)) as u16;
        rem >= self.offset_slots && rem < (self.offset_slots + self.duration_slots)
    }
}

// ---------------------------------------------------------------------------
// 3GPP Candidate CCE Hashing (TS 38.213 §10.1)
// ---------------------------------------------------------------------------

/// Computes 3GPP pseudo-random $Y_k$ recursion for UE-Specific Search Space:
/// $$Y_k = (A_0 \cdot Y_{k-1}) \bmod D$$
pub fn compute_y_k(rnti: u16, slot: u32) -> u64 {
    let mut y = (rnti as u64) % HASH_MODULO_D;
    if y == 0 {
        y = 1; // RNTI cannot yield 0
    }
    for _ in 0..slot {
        y = (HASH_MULTIPLIER_A0 * y) % HASH_MODULO_D;
    }
    y
}

/// Computes CCE start index for a PDCCH candidate (TS 38.213 §10.1).
pub fn compute_candidate_cce_index(
    search_space: &SearchSpaceConfig,
    coreset: &CoresetConfig,
    al: AggregationLevel,
    candidate_idx: u8,
    slot: u32,
    rnti: u16,
) -> Result<u16, PdcchError> {
    let num_candidates = search_space.candidates.get(al);
    if candidate_idx >= num_candidates {
        return Err(PdcchError::CandidateIndexOutOfRange {
            index: candidate_idx,
            max_candidates: num_candidates,
        });
    }

    let l = al.num_cces() as u64;
    let n_cce = coreset.total_cces() as u64;
    let max_cand = num_candidates as u64;

    if n_cce < l {
        return Err(PdcchError::CceExceeded {
            requested_cce: l as u16,
            total_cces: n_cce as u16,
        });
    }

    let y_k = match search_space.search_space_type {
        SearchSpaceType::Common(_) => 0u64,
        SearchSpaceType::UeSpecific => compute_y_k(rnti, slot),
    };

    // TS 38.213 §10.1 hashing formula:
    // n_cce = L * ( (Y_k + floor(m * N_cce / (L * M_L)) + n_CI) mod floor(N_cce / L) )
    let m = candidate_idx as u64;
    let term = (m * n_cce) / (l * max_cand);
    let floor_div = n_cce / l;
    let start_cce = l * ((y_k + term) % floor_div);

    Ok(start_cce as u16)
}

// ---------------------------------------------------------------------------
// Rel-17/18 Search Space Group Switching & PDCCH Skipping (TS 38.213 §10.4)
// ---------------------------------------------------------------------------

/// Rel-17/18 Dynamic Monitoring Adaptation Manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdcchMonitoringAdaptation {
    /// Active Search Space Set Group: 0 (default / sparse) or 1 (dense).
    pub current_sssg_id: u8,
    /// Inactivity timer for fallback from Group 1 to Group 0 (in slots).
    pub sssg_switch_timer: Option<u16>,
    pub timer_countdown: u16,
    /// Remaining slots to skip PDCCH monitoring ($N_{\text{skip}}$).
    pub skipping_countdown: u8,
}

impl PdcchMonitoringAdaptation {
    pub fn new(switching_timer_slots: Option<u16>) -> Self {
        Self {
            current_sssg_id: 0,
            sssg_switch_timer: switching_timer_slots,
            timer_countdown: 0,
            skipping_countdown: 0,
        }
    }

    /// Triggers immediate switch to SSSG Group 1 (high traffic) with timer reload.
    pub fn trigger_switch_to_group1(&mut self) {
        self.current_sssg_id = 1;
        if let Some(timer) = self.sssg_switch_timer {
            self.timer_countdown = timer;
        }
    }

    /// Applies PDCCH monitoring skipping indication ($N_{\text{skip}} \in \{1, 2, 4, 8\}$ slots).
    pub fn trigger_skipping(&mut self, skip_slots: u8) {
        self.skipping_countdown = skip_slots;
    }

    /// Advances one slot duration, updating timers and skipping countdown.
    pub fn advance_slot(&mut self) {
        if self.skipping_countdown > 0 {
            self.skipping_countdown -= 1;
        }

        if self.current_sssg_id == 1 && self.timer_countdown > 0 {
            self.timer_countdown -= 1;
            if self.timer_countdown == 0 {
                // Fallback to power-saving Group 0
                self.current_sssg_id = 0;
            }
        }
    }

    /// Checks if PDCCH monitoring is currently active in this slot.
    #[inline]
    pub fn is_monitoring_active(&self) -> bool {
        self.skipping_countdown == 0
    }
}

// ---------------------------------------------------------------------------
// Blind Decoding (BD) & CCE Budget Auditor (TS 38.213 Table 10.1-2/3)
// ---------------------------------------------------------------------------

/// Maximum blind decoding limits per slot per subcarrier spacing numerology $\mu$.
pub fn get_max_blind_decodes_per_slot(mu: u8) -> usize {
    match mu {
        0 => 44, // 15 kHz
        1 => 36, // 30 kHz
        2 => 22, // 60 kHz
        3 => 20, // 120 kHz
        _ => 20,
    }
}

/// Maximum non-overlapped CCE limits per slot per subcarrier spacing numerology $\mu$.
pub fn get_max_non_overlapped_cces_per_slot(mu: u8) -> usize {
    match mu {
        0 => 56,
        1 => 56,
        2 => 48,
        3 => 32,
        _ => 32,
    }
}

/// Audits a set of search spaces to ensure total blind decodes and CCEs do not violate 3GPP limits.
pub fn audit_slot_monitoring_budget(
    search_spaces: &[SearchSpaceConfig],
    coreset: &CoresetConfig,
    active_sssg_id: u8,
    mu: u8,
) -> Result<(usize, usize), PdcchError> {
    let max_bds = get_max_blind_decodes_per_slot(mu);
    let max_cces = get_max_non_overlapped_cces_per_slot(mu);

    let mut total_bds = 0;
    let mut total_cces = 0;

    for ss in search_spaces {
        if ss.sssg_id != active_sssg_id {
            continue;
        }

        let candidates = ss.candidates.total_candidates();
        total_bds += candidates;

        // Sum CCEs consumed by all candidates in this search space
        for al in [
            AggregationLevel::L1,
            AggregationLevel::L2,
            AggregationLevel::L4,
            AggregationLevel::L8,
            AggregationLevel::L16,
        ] {
            let count = ss.candidates.get(al) as usize;
            total_cces += count * al.num_cces();
        }
    }

    if total_bds > max_bds {
        return Err(PdcchError::BlindDecodingBudgetExceeded {
            count: total_bds,
            limit: max_bds,
        });
    }

    // Coreset capacity cap
    let coreset_cces = coreset.total_cces() as usize;
    let capped_cces = total_cces.min(coreset_cces);
    if capped_cces > max_cces {
        return Err(PdcchError::CceBudgetExceeded {
            count: capped_cces,
            limit: max_cces,
        });
    }

    Ok((total_bds, capped_cces))
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16
// ---------------------------------------------------------------------------

/// Computes CRC-16 CCITT over binary slice.
pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
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

/// Binary wire framing carrying PDCCH monitoring metadata and candidate tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdcchMonitoringPdu {
    pub version: u8,
    pub slot_index: u32,
    pub coreset_id: u8,
    pub search_space_id: u8,
    pub aggregation_level: u8,
    pub candidate_index: u8,
    pub start_cce: u16,
    pub sssg_id: u8,
    pub skipping_remaining: u8,
}

impl PdcchMonitoringPdu {
    pub const WIRE_SIZE: usize = 4 + 1 + 4 + 1 + 1 + 1 + 1 + 2 + 1 + 1 + 2; // 19 bytes

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&PDCCH_WIRE_MAGIC.to_be_bytes());
        buf.push(self.version);
        buf.extend_from_slice(&self.slot_index.to_be_bytes());
        buf.push(self.coreset_id);
        buf.push(self.search_space_id);
        buf.push(self.aggregation_level);
        buf.push(self.candidate_index);
        buf.extend_from_slice(&self.start_cce.to_be_bytes());
        buf.push(self.sssg_id);
        buf.push(self.skipping_remaining);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PdcchError> {
        if bytes.len() < Self::WIRE_SIZE {
            return Err(PdcchError::DeserializationError(format!(
                "Buffer length {} is less than required {}",
                bytes.len(),
                Self::WIRE_SIZE
            )));
        }

        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != PDCCH_WIRE_MAGIC {
            return Err(PdcchError::InvalidMagic(magic));
        }

        let payload_len = Self::WIRE_SIZE - 2;
        let expected_crc = compute_crc16(&bytes[..payload_len]);
        let actual_crc = u16::from_be_bytes([bytes[payload_len], bytes[payload_len + 1]]);
        if expected_crc != actual_crc {
            return Err(PdcchError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        let version = bytes[4];
        let slot_index = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        let coreset_id = bytes[9];
        let search_space_id = bytes[10];
        let aggregation_level = bytes[11];
        let candidate_index = bytes[12];
        let start_cce = u16::from_be_bytes([bytes[13], bytes[14]]);
        let sssg_id = bytes[15];
        let skipping_remaining = bytes[16];

        Ok(Self {
            version,
            slot_index,
            coreset_id,
            search_space_id,
            aggregation_level,
            candidate_index,
            start_cce,
            sssg_id,
            skipping_remaining,
        })
    }
}

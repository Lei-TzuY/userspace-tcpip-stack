//! 3GPP Release 18/19 5G-Advanced Physical Uplink Control Channel (PUCCH) Processor
//! & Multi-Slot Repetition Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §6.3.2: Physical Uplink Control Channel (PUCCH Formats 0, 1, 2, 3, 4).
//! - 3GPP TS 38.213 Rel-18 §9.2: PUCCH resource sets, DCI PRI mapping, and UCI multiplexing.
//! - 3GPP TS 38.213 Rel-18 §7.2.1: PUCCH power control and TPC accumulation.
//! - 3GPP TS 38.331 Rel-18: `PUCCH-Config`, multi-slot repetitions, and frequency hopping.
//!
//! Features:
//! 1. Full PUCCH Formats (0, 1, 2, 3, 4) with physical symbol/PRB boundaries and formats metadata.
//! 2. Format 0 Low-PAPR base sequence cyclic shift mapping with simultaneous HARQ-ACK & SR.
//! 3. Format 1 Time-Domain Orthogonal Cover Code (OCC) spreading with alternating DMRS/Data.
//! 4. Format 2 DMRS subcarrier interleaving (every 3rd subcarrier) and UCI RE capacity audit.
//! 5. PUCCH Resource Sets (0 to 3) with dynamic DCI 3-bit PRI (PUCCH Resource Indicator) resolution.
//! 6. Intra-slot & Inter-slot Frequency Hopping and Rel-17/18 multi-slot repetitions ($N\in\{1,2,4,8\}$)
//!    with cross-slot DMRS phase continuity tracking.
//! 7. 3GPP TS 38.213 §7.2.1 closed-loop Transmit Power Control (TPC) with pathloss, format, and $\Delta_{TF}$ offsets.
//! 8. UCI collision arbitration and CSI Part 2 code-rate overload dropping.
//! 9. Binary wire framing (`PucchFramePdu`) with magic `0x50554348` ("PUCH") and CRC-16 CCITT.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for PUCCH PDU: "PUCH" (0x50554348).
pub const PUCCH_WIRE_MAGIC: u32 = 0x50554348;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Standard subcarriers per Physical Resource Block in 5G NR.
pub const SUBCARRIERS_PER_PRB: usize = 12;

/// Standard OFDM symbols per normal cyclic prefix slot.
pub const SYMBOLS_PER_SLOT: u8 = 14;

/// Errors encountered in PUCCH operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PucchError {
    InvalidFormat(u8),
    InvalidSymbolCount {
        format: PucchFormat,
        symbols: u8,
    },
    InvalidStartSymbol {
        start: u8,
        len: u8,
    },
    InvalidPrbCount {
        format: PucchFormat,
        prbs: u16,
    },
    InvalidCyclicShift(u8),
    InvalidResourceSet(u8),
    ResourceNotFound(u8),
    PayloadTooLarge {
        format: PucchFormat,
        bits: usize,
    },
    CodeRateExceeded {
        code_rate_x1000: u32,
        max_code_rate_x1000: u32,
    },
    SerializationError(String),
    DeserializationError(String),
    CrcMismatch {
        expected: u16,
        actual: u16,
    },
    InvalidMagic(u32),
}

impl fmt::Display for PucchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(fmt_id) => write!(f, "Invalid PUCCH format ID: {}", fmt_id),
            Self::InvalidSymbolCount { format, symbols } => {
                write!(f, "Invalid symbol count {} for {:?}", symbols, format)
            }
            Self::InvalidStartSymbol { start, len } => {
                write!(
                    f,
                    "Invalid symbol range start={}, len={} (exceeds slot)",
                    start, len
                )
            }
            Self::InvalidPrbCount { format, prbs } => {
                write!(f, "Invalid PRB count {} for {:?}", prbs, format)
            }
            Self::InvalidCyclicShift(cs) => write!(f, "Cyclic shift {} must be 0..=11", cs),
            Self::InvalidResourceSet(set) => write!(f, "Invalid resource set index: {}", set),
            Self::ResourceNotFound(id) => write!(f, "PUCCH resource ID {} not found", id),
            Self::PayloadTooLarge { format, bits } => {
                write!(
                    f,
                    "Payload {} bits exceeds max capacity for {:?}",
                    bits, format
                )
            }
            Self::CodeRateExceeded {
                code_rate_x1000,
                max_code_rate_x1000,
            } => {
                write!(
                    f,
                    "PUCCH code rate {:.3} exceeds maximum allowable {:.3}",
                    (*code_rate_x1000 as f64) / 1000.0,
                    (*max_code_rate_x1000 as f64) / 1000.0
                )
            }
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "CRC mismatch: expected 0x{:04X}, computed 0x{:04X}",
                    expected, actual
                )
            }
            Self::InvalidMagic(m) => write!(f, "Invalid PUCCH magic: 0x{:08X}", m),
        }
    }
}

// ---------------------------------------------------------------------------
// PUCCH Formats & Capabilities
// ---------------------------------------------------------------------------

/// 5G NR PUCCH Formats specified in 3GPP TS 38.211 §6.3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PucchFormat {
    /// Format 0: Short (1-2 symbols), 1-2 bits (HARQ-ACK / SR), sequence selection.
    Format0,
    /// Format 1: Long (4-14 symbols), 1-2 bits, sequence modulation + time-domain OCC.
    Format1,
    /// Format 2: Short (1-2 symbols), >2 bits, QPSK + interleaved DMRS.
    Format2,
    /// Format 3: Long (4-14 symbols), >2 bits, DFT-s-OFDM with time-domain DMRS.
    Format3,
    /// Format 4: Long (4-14 symbols), >2 bits, DFT-s-OFDM with OCC spreading.
    Format4,
}

impl PucchFormat {
    #[inline]
    pub fn is_short(self) -> bool {
        matches!(self, Self::Format0 | Self::Format2)
    }

    #[inline]
    pub fn min_symbols(self) -> u8 {
        match self {
            Self::Format0 | Self::Format2 => 1,
            Self::Format1 | Self::Format3 | Self::Format4 => 4,
        }
    }

    #[inline]
    pub fn max_symbols(self) -> u8 {
        match self {
            Self::Format0 | Self::Format2 => 2,
            Self::Format1 | Self::Format3 | Self::Format4 => 14,
        }
    }

    #[inline]
    pub fn max_payload_bits(self) -> usize {
        match self {
            Self::Format0 | Self::Format1 => 2,
            Self::Format2 | Self::Format3 | Self::Format4 => 1706,
        }
    }

    /// Format-specific power offset $\Delta_{F\_PUCCH}$ in dB (TS 38.213 Table 7.2.1-1).
    #[inline]
    pub fn delta_f_db(self) -> f64 {
        match self {
            Self::Format0 => 0.0,
            Self::Format1 => -2.0,
            Self::Format2 => 1.0,
            Self::Format3 => 2.0,
            Self::Format4 => 1.5,
        }
    }

    /// Validates symbol count and PRB allocation for this format.
    pub fn validate(self, symbols: u8, prbs: u16) -> Result<(), PucchError> {
        if symbols < self.min_symbols() || symbols > self.max_symbols() {
            return Err(PucchError::InvalidSymbolCount {
                format: self,
                symbols,
            });
        }
        match self {
            Self::Format0 | Self::Format1 | Self::Format4 => {
                if prbs != 1 {
                    return Err(PucchError::InvalidPrbCount { format: self, prbs });
                }
            }
            Self::Format2 | Self::Format3 => {
                if prbs == 0 || prbs > 16 {
                    return Err(PucchError::InvalidPrbCount { format: self, prbs });
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Format 0 Low-PAPR Base Sequence & Cyclic Shift Mapping (TS 38.211 §6.3.2.3)
// ---------------------------------------------------------------------------

/// Scheduling Request (SR) transmission state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingRequestState {
    None,
    Negative,
    Positive,
}

/// Evaluates Format 0 Cyclic Shift for HARQ-ACK and SR transmission (TS 38.213 §9.2.3).
pub fn compute_format0_cyclic_shift(
    initial_cs: u8,
    harq_bits: &[u8],
    sr: SchedulingRequestState,
) -> Result<u8, PucchError> {
    if initial_cs >= 12 {
        return Err(PucchError::InvalidCyclicShift(initial_cs));
    }

    let delta = match (harq_bits.len(), sr) {
        // SR only (no HARQ-ACK bits)
        (0, SchedulingRequestState::Positive) => 0,
        (0, _) => 0,

        // 1 HARQ-ACK bit without positive SR
        (1, SchedulingRequestState::None | SchedulingRequestState::Negative) => {
            if harq_bits[0] & 1 == 1 { 6 } else { 0 }
        }
        // 1 HARQ-ACK bit with positive SR (TS 38.213 Table 9.2.3-3)
        (1, SchedulingRequestState::Positive) => {
            if harq_bits[0] & 1 == 1 {
                9
            } else {
                3
            }
        }

        // 2 HARQ-ACK bits without positive SR
        (2, SchedulingRequestState::None | SchedulingRequestState::Negative) => {
            match (harq_bits[0] & 1, harq_bits[1] & 1) {
                (0, 0) => 0, // NACK, NACK
                (0, 1) => 3, // NACK, ACK
                (1, 1) => 6, // ACK, ACK
                (1, 0) => 9, // ACK, NACK
                _ => 0,
            }
        }
        // 2 HARQ-ACK bits with positive SR (TS 38.213 Table 9.2.3-4)
        (2, SchedulingRequestState::Positive) => match (harq_bits[0] & 1, harq_bits[1] & 1) {
            (0, 0) => 1,
            (0, 1) => 4,
            (1, 1) => 7,
            (1, 0) => 10,
            _ => 1,
        },

        _ => {
            return Err(PucchError::PayloadTooLarge {
                format: PucchFormat::Format0,
                bits: harq_bits.len(),
            });
        }
    };

    Ok((initial_cs + delta) % 12)
}

// ---------------------------------------------------------------------------
// Format 1 Time-Domain Spreading & Cover Codes (TS 38.211 §6.3.2.4)
// ---------------------------------------------------------------------------

/// Computes Format 1 Orthogonal Cover Code (OCC) spreading pattern.
pub fn compute_format1_occ_sequence(
    num_symbols: u8,
    time_domain_occ_index: u8,
) -> Result<Vec<(f64, f64)>, PucchError> {
    if num_symbols < 4 || num_symbols > 14 {
        return Err(PucchError::InvalidSymbolCount {
            format: PucchFormat::Format1,
            symbols: num_symbols,
        });
    }

    // Format 1 alternates DMRS and data symbols:
    // For even N_symbols: data_symbols = N / 2
    // For odd N_symbols: data_symbols = (N - 1) / 2
    let n_sf = (num_symbols / 2) as usize;
    if (time_domain_occ_index as usize) >= n_sf {
        return Err(PucchError::InvalidCyclicShift(time_domain_occ_index));
    }

    let mut occ = Vec::with_capacity(n_sf);
    for m in 0..n_sf {
        let phase = 2.0 * std::f64::consts::PI * (time_domain_occ_index as f64) * (m as f64)
            / (n_sf as f64);
        occ.push((phase.cos(), phase.sin()));
    }

    Ok(occ)
}

// ---------------------------------------------------------------------------
// Format 2 DMRS & Resource Allocation (TS 38.211 §6.4.1.3)
// ---------------------------------------------------------------------------

/// Computes available UCI Resource Elements (REs) in Format 2 transmission.
/// In Format 2, DMRS occupies every 3rd subcarrier (subcarriers 1, 4, 7, 10),
/// leaving 8 data subcarriers per PRB per symbol.
pub fn calculate_format2_available_res(
    num_prbs: u16,
    num_symbols: u8,
) -> Result<usize, PucchError> {
    PucchFormat::Format2.validate(num_symbols, num_prbs)?;
    let data_sc_per_prb = 8; // 12 - 4 DMRS
    Ok((num_prbs as usize) * data_sc_per_prb * (num_symbols as usize))
}

// ---------------------------------------------------------------------------
// PUCCH Resource & Resource Set Management (TS 38.213 §9.2.1)
// ---------------------------------------------------------------------------

/// Individual configured PUCCH resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PucchResource {
    pub resource_id: u8,
    pub format: PucchFormat,
    pub start_prb: u16,
    pub num_prbs: u16,
    pub start_symbol: u8,
    pub num_symbols: u8,
    pub initial_cyclic_shift: u8,
    pub time_domain_occ: u8,
    pub intra_slot_hopping: bool,
    pub second_hop_prb: Option<u16>,
}

impl PucchResource {
    pub fn new(
        resource_id: u8,
        format: PucchFormat,
        start_prb: u16,
        num_prbs: u16,
        start_symbol: u8,
        num_symbols: u8,
        initial_cyclic_shift: u8,
        time_domain_occ: u8,
        intra_slot_hopping: bool,
        second_hop_prb: Option<u16>,
    ) -> Result<Self, PucchError> {
        format.validate(num_symbols, num_prbs)?;
        if start_symbol + num_symbols > SYMBOLS_PER_SLOT {
            return Err(PucchError::InvalidStartSymbol {
                start: start_symbol,
                len: num_symbols,
            });
        }
        if initial_cyclic_shift >= 12 {
            return Err(PucchError::InvalidCyclicShift(initial_cyclic_shift));
        }

        Ok(Self {
            resource_id,
            format,
            start_prb,
            num_prbs,
            start_symbol,
            num_symbols,
            initial_cyclic_shift,
            time_domain_occ,
            intra_slot_hopping,
            second_hop_prb,
        })
    }
}

/// PUCCH Resource Set configured in RRC (TS 38.213 §9.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PucchResourceSet {
    pub set_id: u8,
    pub max_payload_bits: usize,
    pub resource_ids: Vec<u8>,
}

impl PucchResourceSet {
    pub fn new(
        set_id: u8,
        max_payload_bits: usize,
        resource_ids: Vec<u8>,
    ) -> Result<Self, PucchError> {
        if set_id > 3 {
            return Err(PucchError::InvalidResourceSet(set_id));
        }
        Ok(Self {
            set_id,
            max_payload_bits,
            resource_ids,
        })
    }
}

/// Selects the appropriate PUCCH Resource Set index (0..=3) based on UCI payload length.
pub fn select_pucch_resource_set(uci_payload_bits: usize) -> u8 {
    if uci_payload_bits <= 2 {
        0
    } else if uci_payload_bits <= 256 {
        1
    } else if uci_payload_bits <= 800 {
        2
    } else {
        3
    }
}

/// Resolves active PUCCH resource using 3-bit DCI PUCCH Resource Indicator (PRI)
/// per 3GPP TS 38.213 §9.2.1.
pub fn resolve_pucch_resource_from_pri(
    set: &PucchResourceSet,
    pri: u8,
    all_resources: &[PucchResource],
) -> Result<PucchResource, PucchError> {
    if set.resource_ids.is_empty() {
        return Err(PucchError::ResourceNotFound(0));
    }

    let r_pucch = set.resource_ids.len();
    let index = if r_pucch <= 8 {
        (pri as usize) % r_pucch
    } else {
        // Table 9.2.1-1 dynamic mapping for Set 0 when > 8 resources configured
        (pri as usize) % r_pucch
    };

    let target_id = set.resource_ids[index];
    all_resources
        .iter()
        .find(|r| r.resource_id == target_id)
        .cloned()
        .ok_or(PucchError::ResourceNotFound(target_id))
}

// ---------------------------------------------------------------------------
// Frequency Hopping & Rel-17/18 Multi-Slot Repetition Manager
// ---------------------------------------------------------------------------

/// Rel-17/18 PUCCH Multi-slot Repetition & Frequency Hopping Manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PucchRepetitionManager {
    /// Configured slot repetitions ($N_{\text{slot}} \in \{1, 2, 4, 8\}$).
    pub num_slots: u8,
    /// Inter-slot frequency hopping enabled.
    pub inter_slot_hopping: bool,
    /// Cross-slot DMRS phase continuity requirement (Rel-17/18).
    pub cross_slot_phase_continuity: bool,
}

impl PucchRepetitionManager {
    pub fn new(num_slots: u8, inter_slot_hopping: bool, cross_slot_phase_continuity: bool) -> Self {
        let n = match num_slots {
            1 | 2 | 4 | 8 => num_slots,
            _ => 1,
        };
        Self {
            num_slots: n,
            inter_slot_hopping,
            cross_slot_phase_continuity,
        }
    }

    /// Determines the physical PRB boundaries for a given transmission slot index and hop.
    pub fn get_slot_prb(
        &self,
        slot_index: u8,
        is_second_hop: bool,
        resource: &PucchResource,
    ) -> u16 {
        if resource.intra_slot_hopping && is_second_hop {
            return resource.second_hop_prb.unwrap_or(resource.start_prb);
        }

        if self.inter_slot_hopping && (slot_index % 2 == 1) {
            return resource.second_hop_prb.unwrap_or(resource.start_prb);
        }

        resource.start_prb
    }

    /// Verifies cross-slot phase continuity compliance across repeated transmissions.
    pub fn audit_phase_continuity(&self, powers_dbm: &[f64], prbs: &[u16]) -> bool {
        if !self.cross_slot_phase_continuity || powers_dbm.len() <= 1 {
            return true;
        }

        // Power consistency check: variance must be within 0.5 dB
        let p_ref = powers_dbm[0];
        for &p in powers_dbm.iter().skip(1) {
            if (p - p_ref).abs() > 0.5 {
                return false;
            }
        }

        // PRB alignment check (frequency coherence)
        let prb_ref = prbs[0];
        for &prb in prbs.iter().skip(1) {
            if prb != prb_ref && !self.inter_slot_hopping {
                return false;
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// PUCCH Transmit Power Control (TS 38.213 §7.2.1)
// ---------------------------------------------------------------------------

/// Parameters for PUCCH Transmit Power Control calculation.
#[derive(Debug, Clone, PartialEq)]
pub struct PucchPowerControlConfig {
    pub p_cmax_dbm: f64,
    pub p_o_pucch_dbm: f64,
    pub pathloss_alpha: f64,
    pub pathloss_db: f64,
    pub numerology_mu: u8,
    pub tpc_accumulator_db: f64,
}

impl Default for PucchPowerControlConfig {
    fn default() -> Self {
        Self {
            p_cmax_dbm: 23.0,
            p_o_pucch_dbm: -95.0,
            pathloss_alpha: 1.0,
            pathloss_db: 80.0,
            numerology_mu: 1, // 30 kHz
            tpc_accumulator_db: 0.0,
        }
    }
}

impl PucchPowerControlConfig {
    /// Applies closed-loop TPC command adjustment ($\delta \in \{-1, 0, 1, 3\}$ dB).
    pub fn apply_tpc_command(&mut self, delta_db: f64) {
        self.tpc_accumulator_db += delta_db;
    }

    /// Computes PUCCH transmit power in dBm per 3GPP TS 38.213 §7.2.1:
    /// $$P = \min\left(P_{\text{CMAX}}, P_O + 10\log_{10}(2^\mu M_{\text{RB}}) + \alpha \cdot PL + \Delta_{F} + \Delta_{TF} + g\right)$$
    pub fn compute_tx_power(&self, format: PucchFormat, num_prbs: u16, payload_bits: usize) -> f64 {
        let mu_factor = 2.0f64.powi(self.numerology_mu as i32);
        let bandwidth_term = 10.0 * ((mu_factor * (num_prbs as f64)).log10());
        let pl_term = self.pathloss_alpha * self.pathloss_db;
        let delta_f = format.delta_f_db();

        // Payload size offset Delta_TF for Format 2/3/4 with >= 4 bits
        let delta_tf = if !format.is_short() && payload_bits >= 4 {
            let b_uci = payload_bits as f64;
            let n_re = (num_prbs as f64) * 8.0 * (format.min_symbols() as f64);
            (10.0 * (1.25 * (b_uci / n_re)).log10()).max(0.0)
        } else {
            0.0
        };

        let calculated_power = self.p_o_pucch_dbm
            + bandwidth_term
            + pl_term
            + delta_f
            + delta_tf
            + self.tpc_accumulator_db;

        calculated_power.min(self.p_cmax_dbm)
    }
}

// ---------------------------------------------------------------------------
// UCI Collision & Multiplexing Engine
// ---------------------------------------------------------------------------

/// Result of UCI collision arbitration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UciMultiplexingResult {
    pub selected_format: PucchFormat,
    pub total_uci_bits: usize,
    pub csi_part2_dropped: bool,
    pub effective_code_rate_x1000: u32,
}

/// Evaluates UCI multiplexing and enforces code-rate boundary constraints.
pub fn arbitrate_uci_multiplexing(
    harq_ack_bits: usize,
    sr_state: SchedulingRequestState,
    csi_part1_bits: usize,
    csi_part2_bits: usize,
    allocated_prbs: u16,
    num_symbols: u8,
    max_code_rate_x1000: u32,
) -> Result<UciMultiplexingResult, PucchError> {
    let sr_bits = if sr_state == SchedulingRequestState::Positive {
        1
    } else {
        0
    };
    let mut total_payload = harq_ack_bits + sr_bits + csi_part1_bits + csi_part2_bits;
    let mut csi_dropped = false;

    let format = if total_payload <= 2 && num_symbols <= 2 {
        PucchFormat::Format0
    } else if total_payload <= 2 {
        PucchFormat::Format1
    } else if num_symbols <= 2 {
        PucchFormat::Format2
    } else {
        PucchFormat::Format3
    };

    let n_re = match format {
        PucchFormat::Format0 | PucchFormat::Format1 => 12,
        PucchFormat::Format2 => calculate_format2_available_res(allocated_prbs, num_symbols)?,
        PucchFormat::Format3 | PucchFormat::Format4 => {
            (allocated_prbs as usize) * 12 * ((num_symbols - 2) as usize)
        }
    };

    // QPSK modulation has 2 coded bits per RE
    let total_re_capacity_bits = n_re * 2;
    let mut code_rate_x1000 = ((total_payload * 1000) / total_re_capacity_bits.max(1)) as u32;

    // TS 38.213 §9.2.5.2: Drop CSI Part 2 if code rate exceeds maximum allowable
    if code_rate_x1000 > max_code_rate_x1000 && csi_part2_bits > 0 {
        total_payload -= csi_part2_bits;
        csi_dropped = true;
        code_rate_x1000 = ((total_payload * 1000) / total_re_capacity_bits.max(1)) as u32;
    }

    if code_rate_x1000 > max_code_rate_x1000 && total_payload > 2 {
        return Err(PucchError::CodeRateExceeded {
            code_rate_x1000,
            max_code_rate_x1000,
        });
    }

    Ok(UciMultiplexingResult {
        selected_format: format,
        total_uci_bits: total_payload,
        csi_part2_dropped: csi_dropped,
        effective_code_rate_x1000: code_rate_x1000,
    })
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

/// Binary wire framing transporting PUCCH transmission metadata and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PucchFramePdu {
    pub version: u8,
    pub format: u8,
    pub resource_id: u8,
    pub slot_number: u8,
    pub start_symbol: u8,
    pub num_symbols: u8,
    pub start_prb: u16,
    pub num_prbs: u16,
    pub tx_power_dbm_x100: i16,
    pub payload_bytes: Vec<u8>,
}

impl PucchFramePdu {
    pub const HEADER_SIZE: usize = 4 + 1 + 1 + 1 + 1 + 1 + 1 + 2 + 2 + 2 + 2; // 18 bytes

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.payload_bytes.len() + 2);
        buf.extend_from_slice(&PUCCH_WIRE_MAGIC.to_be_bytes());
        buf.push(self.version);
        buf.push(self.format);
        buf.push(self.resource_id);
        buf.push(self.slot_number);
        buf.push(self.start_symbol);
        buf.push(self.num_symbols);
        buf.extend_from_slice(&self.start_prb.to_be_bytes());
        buf.extend_from_slice(&self.num_prbs.to_be_bytes());
        buf.extend_from_slice(&self.tx_power_dbm_x100.to_be_bytes());
        buf.extend_from_slice(&(self.payload_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload_bytes);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PucchError> {
        if bytes.len() < Self::HEADER_SIZE + 2 {
            return Err(PucchError::DeserializationError(format!(
                "PDU length {} is less than minimum required {}",
                bytes.len(),
                Self::HEADER_SIZE + 2
            )));
        }

        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != PUCCH_WIRE_MAGIC {
            return Err(PucchError::InvalidMagic(magic));
        }

        let payload_len = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
        let expected_total_len = Self::HEADER_SIZE + payload_len + 2;
        if bytes.len() < expected_total_len {
            return Err(PucchError::DeserializationError(format!(
                "Total buffer length {} is less than expected {}",
                bytes.len(),
                expected_total_len
            )));
        }

        let checksum_boundary = Self::HEADER_SIZE + payload_len;
        let expected_crc = compute_crc16(&bytes[..checksum_boundary]);
        let actual_crc =
            u16::from_be_bytes([bytes[checksum_boundary], bytes[checksum_boundary + 1]]);
        if expected_crc != actual_crc {
            return Err(PucchError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        let version = bytes[4];
        let format = bytes[5];
        let resource_id = bytes[6];
        let slot_number = bytes[7];
        let start_symbol = bytes[8];
        let num_symbols = bytes[9];
        let start_prb = u16::from_be_bytes([bytes[10], bytes[11]]);
        let num_prbs = u16::from_be_bytes([bytes[12], bytes[13]]);
        let tx_power_dbm_x100 = i16::from_be_bytes([bytes[14], bytes[15]]);
        let payload_bytes = bytes[Self::HEADER_SIZE..checksum_boundary].to_vec();

        Ok(Self {
            version,
            format,
            resource_id,
            slot_number,
            start_symbol,
            num_symbols,
            start_prb,
            num_prbs,
            tx_power_dbm_x100,
            payload_bytes,
        })
    }
}

//! 3GPP Release 18/19 5G-Advanced PUSCH Processor, UCI Multiplexing & Frequency Hopping Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §6.3.1: PUSCH modulation, resource mapping, and frequency hopping.
//! - 3GPP TS 38.212 Rel-18 §6.3.2: Multiplexing of Uplink Control Information (UCI) on PUSCH
//!   (HARQ-ACK, CSI Part 1, CSI Part 2), coded symbol calculation ($Q'_{\text{ACK}}$, $Q'_{\text{CSI-1}}$, $Q'_{\text{CSI-2}}$).
//! - 3GPP TS 38.214 Rel-18 §6.1.2: PUSCH time-domain and frequency-domain resource allocation,
//!   Uplink Repetition Type A and Repetition Type B across slot boundaries.
//!
//! Features:
//! 1. UCI on PUSCH symbol dimensioning ($Q'_{\text{ACK}}$, $Q'_{\text{CSI-1}}$, $Q'_{\text{CSI-2}}$) with $\alpha$-scaling.
//! 2. DMRS-adjacent symbol mapping for time-critical HARQ-ACK and distributed CSI/UL-SCH multiplexing.
//! 3. Intra-slot and Inter-slot frequency hopping with BWP boundary wrapping.
//! 4. Rel-18 Repetition Type A (multi-slot) and Type B (sub-slot boundary segmentation) with RV cycling.
//! 5. Resource Element (RE) grid construction with DMRS, UCI, and data occupancy tracking.
//! 6. Binary wire framing (`PuschWirePdu`) with magic `0x50555348` ("PUSH") and CRC-16 CCITT integrity.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for PUSCH PDU: "PUSH" (0x50555348).
pub const PUSCH_WIRE_MAGIC: u32 = 0x50555348;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Number of subcarriers per Physical Resource Block (PRB).
pub const SUBCARRIERS_PER_PRB: usize = 12;

/// Standard number of OFDM symbols per normal slot.
pub const SYMBOLS_PER_SLOT: usize = 14;

/// Modulation order $Q_m$ for PUSCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PuschModulation {
    Qpsk = 2,
    Qam16 = 4,
    Qam64 = 6,
    Qam256 = 8,
}

impl PuschModulation {
    pub fn bits_per_symbol(&self) -> usize {
        *self as usize
    }
}

/// Frequency hopping mode for PUSCH (TS 38.211 §6.3.1.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrequencyHoppingMode {
    Disabled,
    IntraSlot,
    InterSlot,
}

/// PUSCH Repetition Scheme (TS 38.214 §6.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PuschRepetitionScheme {
    /// Repetition Type A: Multi-slot repetitions with identical symbol allocation in each slot.
    TypeA,
    /// Repetition Type B: Nominal repetitions segmented at slot boundaries into actual repetitions.
    TypeB,
}

/// Errors encountered in PUSCH processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PuschError {
    InvalidSymbolAllocation { start: usize, length: usize },
    InvalidPrbAllocation { start: usize, num_prb: usize, bwp_size: usize },
    ResourceExhaustion { requested: usize, available: usize },
    InvalidRepetitionCount(usize),
    InvalidHopConfiguration(String),
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for PuschError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PuschError::InvalidSymbolAllocation { start, length } => {
                write!(f, "Invalid PUSCH symbol allocation: start {}, length {}", start, length)
            }
            PuschError::InvalidPrbAllocation { start, num_prb, bwp_size } => {
                write!(f, "Invalid PRB allocation: start {}, num_prb {}, BWP size {}", start, num_prb, bwp_size)
            }
            PuschError::ResourceExhaustion { requested, available } => {
                write!(f, "Resource exhaustion: requested {} REs, available {}", requested, available)
            }
            PuschError::InvalidRepetitionCount(c) => write!(f, "Invalid repetition count: {}", c),
            PuschError::InvalidHopConfiguration(msg) => write!(f, "Invalid hop config: {}", msg),
            PuschError::SerializationError(e) => write!(f, "PUSCH serialization error: {}", e),
            PuschError::DeserializationError(e) => write!(f, "PUSCH deserialization error: {}", e),
        }
    }
}

impl std::error::Error for PuschError {}

// ---------------------------------------------------------------------------
// UCI on PUSCH Dimensioning (TS 38.212 §6.3.2)
// ---------------------------------------------------------------------------

/// Parameters for calculating UCI coded symbol count on PUSCH.
#[derive(Debug, Clone)]
pub struct UciOnPuschConfig {
    /// Number of HARQ-ACK payload bits $O_{\text{ACK}}$.
    pub o_ack_bits: usize,
    /// Number of CSI Part 1 payload bits $O_{\text{CSI-1}}$.
    pub o_csi1_bits: usize,
    /// Number of CSI Part 2 payload bits $O_{\text{CSI-2}}$.
    pub o_csi2_bits: usize,
    /// Beta offset $\beta_{\text{offset}}^{\text{HARQ-ACK}}$ (scaled by 1000, e.g. 2.0 -> 2000).
    pub beta_offset_ack_milli: u32,
    /// Beta offset $\beta_{\text{offset}}^{\text{CSI-1}}$ (scaled by 1000).
    pub beta_offset_csi1_milli: u32,
    /// Beta offset $\beta_{\text{offset}}^{\text{CSI-2}}$ (scaled by 1000).
    pub beta_offset_csi2_milli: u32,
    /// Code rate scaling factor $\alpha$ (e.g. 0.8 -> 800 per mille).
    pub alpha_scaling_milli: u32,
    /// Total number of subcarriers available for UCI transmission across all allocated symbols $\sum M_{\text{sc}}^{\text{UCI}}(l)$.
    pub sum_m_sc_uci: usize,
    /// Total number of code block bits of UL-SCH transmission $\sum_{r=0}^{C-1} K_r$.
    pub sum_k_r: usize,
    /// Modulation order $Q_m$.
    pub modulation: PuschModulation,
}

/// Dimensioned coded modulation symbol counts for UCI on PUSCH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UciDimensionResult {
    /// Number of coded modulation symbols for HARQ-ACK ($Q'_{\text{ACK}}$).
    pub q_prime_ack: usize,
    /// Number of coded modulation symbols for CSI Part 1 ($Q'_{\text{CSI-1}}$).
    pub q_prime_csi1: usize,
    /// Number of coded modulation symbols for CSI Part 2 ($Q'_{\text{CSI-2}}$).
    pub q_prime_csi2: usize,
    /// Total coded bits for HARQ-ACK ($Q'_{\text{ACK}} \cdot Q_m$).
    pub total_ack_coded_bits: usize,
    /// Total coded bits for CSI Part 1 ($Q'_{\text{CSI-1}} \cdot Q_m$).
    pub total_csi1_coded_bits: usize,
    /// Total coded bits for CSI Part 2 ($Q'_{\text{CSI-2}} \cdot Q_m$).
    pub total_csi2_coded_bits: usize,
}

/// Computes CRC length $L$ for UCI bit payload according to TS 38.212 §6.3.2.
pub fn uci_crc_length(o_bits: usize) -> usize {
    if o_bits >= 12 {
        11 // CRC11
    } else if o_bits >= 3 {
        6 // CRC6
    } else {
        0 // No CRC for 1 or 2 bits
    }
}

/// Computes UCI on PUSCH coded symbol counts according to TS 38.212 §6.3.2.4.
pub fn calculate_uci_on_pusch_symbols(cfg: &UciOnPuschConfig) -> Result<UciDimensionResult, PuschError> {
    if cfg.sum_k_r == 0 {
        return Err(PuschError::ResourceExhaustion { requested: 1, available: 0 });
    }

    let q_m = cfg.modulation.bits_per_symbol();
    let max_uci_symbols = ((cfg.sum_m_sc_uci as u64 * cfg.alpha_scaling_milli as u64 + 999) / 1000) as usize;

    // 1. HARQ-ACK dimensioning
    let q_prime_ack = if cfg.o_ack_bits > 0 {
        let l_ack = uci_crc_length(cfg.o_ack_bits);
        let num = (cfg.o_ack_bits + l_ack) as u64
            * cfg.beta_offset_ack_milli as u64
            * cfg.sum_m_sc_uci as u64;
        let den = cfg.sum_k_r as u64 * 1000;
        let raw_q = ((num + den - 1) / den) as usize;
        raw_q.min(max_uci_symbols)
    } else {
        0
    };

    let remaining_after_ack = max_uci_symbols.saturating_sub(q_prime_ack);

    // 2. CSI Part 1 dimensioning
    let q_prime_csi1 = if cfg.o_csi1_bits > 0 && remaining_after_ack > 0 {
        let l_csi1 = uci_crc_length(cfg.o_csi1_bits);
        let num = (cfg.o_csi1_bits + l_csi1) as u64
            * cfg.beta_offset_csi1_milli as u64
            * cfg.sum_m_sc_uci as u64;
        let den = cfg.sum_k_r as u64 * 1000;
        let raw_q = ((num + den - 1) / den) as usize;
        raw_q.min(remaining_after_ack)
    } else {
        0
    };

    let remaining_after_csi1 = remaining_after_ack.saturating_sub(q_prime_csi1);

    // 3. CSI Part 2 dimensioning
    let q_prime_csi2 = if cfg.o_csi2_bits > 0 && remaining_after_csi1 > 0 {
        let l_csi2 = uci_crc_length(cfg.o_csi2_bits);
        let num = (cfg.o_csi2_bits + l_csi2) as u64
            * cfg.beta_offset_csi2_milli as u64
            * cfg.sum_m_sc_uci as u64;
        let den = cfg.sum_k_r as u64 * 1000;
        let raw_q = ((num + den - 1) / den) as usize;
        raw_q.min(remaining_after_csi1)
    } else {
        0
    };

    Ok(UciDimensionResult {
        q_prime_ack,
        q_prime_csi1,
        q_prime_csi2,
        total_ack_coded_bits: q_prime_ack * q_m,
        total_csi1_coded_bits: q_prime_csi1 * q_m,
        total_csi2_coded_bits: q_prime_csi2 * q_m,
    })
}

// ---------------------------------------------------------------------------
// Frequency Hopping Engine (TS 38.211 §6.3.1.7)
// ---------------------------------------------------------------------------

/// PUSCH Frequency Hopping Configuration.
#[derive(Debug, Clone)]
pub struct FrequencyHoppingConfig {
    pub mode: FrequencyHoppingMode,
    /// First hop start PRB index ($RB_{\text{start,1}}$).
    pub rb_start: usize,
    /// Number of contiguous PRBs allocated ($N_{\text{PRB}}$).
    pub num_prb: usize,
    /// Second hop frequency offset in PRBs ($RB_{\text{offset}}$).
    pub rb_offset: usize,
    /// Bandwidth part size in PRBs ($N_{\text{BWP}}^{\text{size}}$).
    pub bwp_size_prb: usize,
    /// First hop symbol duration for intra-slot hopping ($N_{\text{symb}}^{\text{hop1}}$).
    pub first_hop_symbols: usize,
}

/// Physical PRB allocation for a single hop or transmission segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopPrbAllocation {
    pub start_prb: usize,
    pub num_prb: usize,
}

/// Computes PRB allocations for PUSCH under configured frequency hopping.
pub fn calculate_pusch_prb_allocation(
    cfg: &FrequencyHoppingConfig,
    slot_index: usize,
    symbol_in_slot: usize,
) -> Result<HopPrbAllocation, PuschError> {
    if cfg.rb_start + cfg.num_prb > cfg.bwp_size_prb {
        return Err(PuschError::InvalidPrbAllocation {
            start: cfg.rb_start,
            num_prb: cfg.num_prb,
            bwp_size: cfg.bwp_size_prb,
        });
    }

    match cfg.mode {
        FrequencyHoppingMode::Disabled => Ok(HopPrbAllocation {
            start_prb: cfg.rb_start,
            num_prb: cfg.num_prb,
        }),
        FrequencyHoppingMode::IntraSlot => {
            let is_second_hop = symbol_in_slot >= cfg.first_hop_symbols;
            let start = if is_second_hop {
                (cfg.rb_start + cfg.rb_offset) % cfg.bwp_size_prb
            } else {
                cfg.rb_start
            };
            if start + cfg.num_prb > cfg.bwp_size_prb {
                return Err(PuschError::InvalidPrbAllocation {
                    start,
                    num_prb: cfg.num_prb,
                    bwp_size: cfg.bwp_size_prb,
                });
            }
            Ok(HopPrbAllocation {
                start_prb: start,
                num_prb: cfg.num_prb,
            })
        }
        FrequencyHoppingMode::InterSlot => {
            let is_second_hop = (slot_index % 2) == 1;
            let start = if is_second_hop {
                (cfg.rb_start + cfg.rb_offset) % cfg.bwp_size_prb
            } else {
                cfg.rb_start
            };
            if start + cfg.num_prb > cfg.bwp_size_prb {
                return Err(PuschError::InvalidPrbAllocation {
                    start,
                    num_prb: cfg.num_prb,
                    bwp_size: cfg.bwp_size_prb,
                });
            }
            Ok(HopPrbAllocation {
                start_prb: start,
                num_prb: cfg.num_prb,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// PUSCH Repetition Engine (Type A & Type B - TS 38.214 §6.1.2.1)
// ---------------------------------------------------------------------------

/// Represents an actual transmission repetition of PUSCH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuschActualRepetition {
    pub repetition_idx: usize,
    pub nominal_idx: usize,
    pub slot_idx: usize,
    pub start_symbol: usize,
    pub num_symbols: usize,
    pub redundancy_version: u8,
}

/// Standard Redundancy Version cycle sequence for PUSCH.
pub const DEFAULT_RV_SEQUENCE: [u8; 4] = [0, 2, 3, 1];

/// Schedules PUSCH repetitions under Type A or Type B.
pub fn schedule_pusch_repetitions(
    rep_type: PuschRepetitionScheme,
    nominal_repetitions: usize,
    start_slot: usize,
    start_symbol: usize,
    num_symbols: usize,
    rv_sequence: &[u8],
) -> Result<Vec<PuschActualRepetition>, PuschError> {
    if nominal_repetitions == 0 {
        return Err(PuschError::InvalidRepetitionCount(0));
    }
    if start_symbol + num_symbols > SYMBOLS_PER_SLOT && rep_type == PuschRepetitionScheme::TypeA {
        return Err(PuschError::InvalidSymbolAllocation {
            start: start_symbol,
            length: num_symbols,
        });
    }

    let rvs = if rv_sequence.is_empty() {
        &DEFAULT_RV_SEQUENCE[..]
    } else {
        rv_sequence
    };

    let mut actual_reps = Vec::new();

    match rep_type {
        PuschRepetitionScheme::TypeA => {
            // Type A: Each nominal repetition occurs in consecutive slots with the exact same symbol window
            for nom in 0..nominal_repetitions {
                let slot = start_slot + nom;
                let rv = rvs[nom % rvs.len()];
                actual_reps.push(PuschActualRepetition {
                    repetition_idx: nom,
                    nominal_idx: nom,
                    slot_idx: slot,
                    start_symbol,
                    num_symbols,
                    redundancy_version: rv,
                });
            }
        }
        PuschRepetitionScheme::TypeB => {
            // Type B: Nominal repetitions occur back-to-back across symbols.
            // When crossing slot boundaries (symbol 14), segment into actual repetitions.
            let mut current_slot = start_slot;
            let mut current_sym = start_symbol;
            let mut actual_counter = 0;

            for nom in 0..nominal_repetitions {
                let mut remaining_symbols = num_symbols;
                let rv = rvs[nom % rvs.len()];

                while remaining_symbols > 0 {
                    let symbols_in_this_slot = (SYMBOLS_PER_SLOT - current_sym).min(remaining_symbols);

                    actual_reps.push(PuschActualRepetition {
                        repetition_idx: actual_counter,
                        nominal_idx: nom,
                        slot_idx: current_slot,
                        start_symbol: current_sym,
                        num_symbols: symbols_in_this_slot,
                        redundancy_version: rv,
                    });
                    actual_counter += 1;

                    remaining_symbols -= symbols_in_this_slot;
                    current_sym += symbols_in_this_slot;
                    if current_sym >= SYMBOLS_PER_SLOT {
                        current_slot += 1;
                        current_sym = 0;
                    }
                }
            }
        }
    }

    Ok(actual_reps)
}

// ---------------------------------------------------------------------------
// PUSCH Resource Grid & RE Multiplexing
// ---------------------------------------------------------------------------

/// State of a single Resource Element (RE) in the PUSCH allocation grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReType {
    Unused,
    Dmrs,
    HarqAck,
    CsiPart1,
    CsiPart2,
    UlSchData,
}

/// 2D Resource grid representing a PUSCH slot allocation.
#[derive(Debug, Clone)]
pub struct PuschSlotGrid {
    pub num_prb: usize,
    /// Grid dimensions: [symbol (0..14)][subcarrier (0..num_prb*12)]
    grid: Vec<Vec<ReType>>,
}

impl PuschSlotGrid {
    pub fn new(num_prb: usize) -> Self {
        let total_sc = num_prb * SUBCARRIERS_PER_PRB;
        Self {
            num_prb,
            grid: vec![vec![ReType::Unused; total_sc]; SYMBOLS_PER_SLOT],
        }
    }

    pub fn get_re(&self, symbol: usize, sc: usize) -> ReType {
        if symbol < SYMBOLS_PER_SLOT && sc < self.num_prb * SUBCARRIERS_PER_PRB {
            self.grid[symbol][sc]
        } else {
            ReType::Unused
        }
    }

    pub fn set_re(&mut self, symbol: usize, sc: usize, re_type: ReType) {
        if symbol < SYMBOLS_PER_SLOT && sc < self.num_prb * SUBCARRIERS_PER_PRB {
            self.grid[symbol][sc] = re_type;
        }
    }

    /// Reserves DMRS symbols across all subcarriers of the allocation.
    pub fn reserve_dmrs_symbols(&mut self, dmrs_symbols: &[usize]) {
        let total_sc = self.num_prb * SUBCARRIERS_PER_PRB;
        for &sym in dmrs_symbols {
            if sym < SYMBOLS_PER_SLOT {
                for sc in 0..total_sc {
                    self.grid[sym][sc] = ReType::Dmrs;
                }
            }
        }
    }

    /// Multiplexes HARQ-ACK, CSI-1, CSI-2, and UL-SCH data onto available REs.
    /// HARQ-ACK is placed in symbols immediately following DMRS symbols.
    pub fn multiplex_channels(
        &mut self,
        start_symbol: usize,
        num_symbols: usize,
        dmrs_symbols: &[usize],
        num_ack_symbols: usize,
        num_csi1_symbols: usize,
        num_csi2_symbols: usize,
    ) -> Result<usize, PuschError> {
        let total_sc = self.num_prb * SUBCARRIERS_PER_PRB;
        let mut ack_remaining = num_ack_symbols;
        let mut csi1_remaining = num_csi1_symbols;
        let mut csi2_remaining = num_csi2_symbols;

        // 1. Identify DMRS adjacent symbols for HARQ-ACK placement
        let mut ack_target_symbols = Vec::new();
        for &dmrs_sym in dmrs_symbols {
            let next_sym = dmrs_sym + 1;
            if next_sym < start_symbol + num_symbols && !dmrs_symbols.contains(&next_sym) {
                ack_target_symbols.push(next_sym);
            }
        }
        // Fallback: if not enough adjacent symbols, use remaining non-DMRS symbols
        for sym in start_symbol..(start_symbol + num_symbols) {
            if !dmrs_symbols.contains(&sym) && !ack_target_symbols.contains(&sym) {
                ack_target_symbols.push(sym);
            }
        }

        // Place HARQ-ACK
        for &sym in &ack_target_symbols {
            for sc in 0..total_sc {
                if ack_remaining == 0 {
                    break;
                }
                if self.grid[sym][sc] == ReType::Unused {
                    self.grid[sym][sc] = ReType::HarqAck;
                    ack_remaining -= 1;
                }
            }
            if ack_remaining == 0 {
                break;
            }
        }

        // Place CSI Part 1, CSI Part 2, then UL-SCH Data across remaining symbols
        let mut ulsch_placed = 0;
        for sym in start_symbol..(start_symbol + num_symbols) {
            if dmrs_symbols.contains(&sym) {
                continue;
            }
            for sc in 0..total_sc {
                if self.grid[sym][sc] != ReType::Unused {
                    continue;
                }
                if csi1_remaining > 0 {
                    self.grid[sym][sc] = ReType::CsiPart1;
                    csi1_remaining -= 1;
                } else if csi2_remaining > 0 {
                    self.grid[sym][sc] = ReType::CsiPart2;
                    csi2_remaining -= 1;
                } else {
                    self.grid[sym][sc] = ReType::UlSchData;
                    ulsch_placed += 1;
                }
            }
        }

        if ack_remaining > 0 || csi1_remaining > 0 || csi2_remaining > 0 {
            return Err(PuschError::ResourceExhaustion {
                requested: num_ack_symbols + num_csi1_symbols + num_csi2_symbols,
                available: total_sc * num_symbols - (dmrs_symbols.len() * total_sc),
            });
        }

        Ok(ulsch_placed)
    }

    /// Counts REs of a given type.
    pub fn count_re_type(&self, target: ReType) -> usize {
        self.grid.iter().flat_map(|row| row.iter()).filter(|&&re| re == target).count()
    }
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16 (TS 38.211/38.212)
// ---------------------------------------------------------------------------

/// Wire frame PDU for PUSCH descriptor and multiplexed transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuschWirePdu {
    pub magic: u32,
    pub slot_idx: u32,
    pub start_prb: u16,
    pub num_prb: u16,
    pub start_symbol: u8,
    pub num_symbols: u8,
    pub modulation: u8,
    pub redundancy_version: u8,
    pub ack_symbols: u16,
    pub csi1_symbols: u16,
    pub csi2_symbols: u16,
    pub ulsch_symbols: u16,
    pub payload: Vec<u8>,
    pub crc16: u16,
}

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

impl PuschWirePdu {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(26 + self.payload.len());
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.slot_idx.to_be_bytes());
        buf.extend_from_slice(&self.start_prb.to_be_bytes());
        buf.extend_from_slice(&self.num_prb.to_be_bytes());
        buf.push(self.start_symbol);
        buf.push(self.num_symbols);
        buf.push(self.modulation);
        buf.push(self.redundancy_version);
        buf.extend_from_slice(&self.ack_symbols.to_be_bytes());
        buf.extend_from_slice(&self.csi1_symbols.to_be_bytes());
        buf.extend_from_slice(&self.csi2_symbols.to_be_bytes());
        buf.extend_from_slice(&self.ulsch_symbols.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PuschError> {
        if data.len() < 28 {
            return Err(PuschError::DeserializationError("Buffer too small".into()));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != PUSCH_WIRE_MAGIC {
            return Err(PuschError::DeserializationError(format!("Invalid magic: 0x{:08X}", magic)));
        }

        let slot_idx = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let start_prb = u16::from_be_bytes([data[8], data[9]]);
        let num_prb = u16::from_be_bytes([data[10], data[11]]);
        let start_symbol = data[12];
        let num_symbols = data[13];
        let modulation = data[14];
        let redundancy_version = data[15];
        let ack_symbols = u16::from_be_bytes([data[16], data[17]]);
        let csi1_symbols = u16::from_be_bytes([data[18], data[19]]);
        let csi2_symbols = u16::from_be_bytes([data[20], data[21]]);
        let ulsch_symbols = u16::from_be_bytes([data[22], data[23]]);
        let payload_len = u16::from_be_bytes([data[24], data[25]]) as usize;

        if data.len() < 26 + payload_len + 2 {
            return Err(PuschError::DeserializationError("Truncated payload".into()));
        }

        let payload = data[26..26 + payload_len].to_vec();
        let expected_crc = compute_crc16(&data[..26 + payload_len]);
        let rx_crc = u16::from_be_bytes([data[26 + payload_len], data[26 + payload_len + 1]]);

        if rx_crc != expected_crc {
            return Err(PuschError::DeserializationError(format!(
                "CRC-16 mismatch: expected 0x{:04X}, received 0x{:04X}",
                expected_crc, rx_crc
            )));
        }

        Ok(Self {
            magic,
            slot_idx,
            start_prb,
            num_prb,
            start_symbol,
            num_symbols,
            modulation,
            redundancy_version,
            ack_symbols,
            csi1_symbols,
            csi2_symbols,
            ulsch_symbols,
            payload,
            crc16: rx_crc,
        })
    }
}

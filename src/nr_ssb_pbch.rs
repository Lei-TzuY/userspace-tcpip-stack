//! 3GPP Release 18/19 5G-Advanced SS/PBCH Block (SSB), MIB & Beam Sweeping Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §7.4.2: Synchronization signals (PSS m-sequence, SSS Gold sequence,
//!   and Physical Cell ID $N_{\text{ID}}^{\text{cell}} = 3 N_{\text{ID}}^{(1)} + N_{\text{ID}}^{(2)}$).
//! - 3GPP TS 38.211 Rel-18 §7.4.3: Demodulation reference signals for PBCH (comb-4 mapping).
//! - 3GPP TS 38.212 Rel-18 §7.1: PBCH payload composition, timing bits, and scrambling.
//! - 3GPP TS 38.213 Rel-18 §4.1: Cell search, SSB burst patterns (Cases A-G), and beam sweeping.
//! - 3GPP TS 38.331 Rel-18 §6.2.2: MasterInformationBlock (MIB) message.
//!
//! Features:
//! 1. PSS generation using length-127 m-sequence with $N_{\text{ID}}^{(2)} \in \{0, 1, 2\}$.
//! 2. SSS generation using length-127 Gold sequence with $N_{\text{ID}}^{(1)} \in [0, 335]$.
//! 3. PBCH DMRS Gold sequence generation and comb-4 subcarrier mapping ($k = 4m + v_{\text{shift}}$).
//! 4. MIB structure and 8-bit timing payload synthesis (SFN, half-frame bit, SSB index).
//! 5. Exact 4 OFDM symbols $\times$ 240 subcarriers (20 PRBs) SSB Resource Grid construction.
//! 6. Beam sweeping burst engine ($L_{\text{max}} \in \{4, 8, 64\}$) with SS-RSRP measurement and best-beam selection.
//! 7. Binary wire framing (`SsbWirePdu`) with magic `0x53534250` ("SSBP") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for SSB Wire PDU: "SSBP" (0x53534250).
pub const SSB_WIRE_MAGIC: u32 = 0x53534250;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Total number of subcarriers per SSB (20 PRBs * 12 subcarriers = 240).
pub const SSB_NUM_SUBCARRIERS: usize = 240;

/// Total number of OFDM symbols per SSB.
pub const SSB_NUM_SYMBOLS: usize = 4;

/// Length of PSS and SSS sequences.
pub const SYNC_SEQUENCE_LENGTH: usize = 127;

/// PSS/SSS subcarrier start index within the 240-subcarrier grid.
pub const SYNC_SUBCARRIER_OFFSET: usize = 56;

/// Total DMRS REs across the 3 PBCH symbols (symbol 1: 60, symbol 2: 24, symbol 3: 60).
pub const PBCH_TOTAL_DMRS_RES: usize = 144;

/// Total PBCH data REs across the 3 symbols (symbol 1: 180, symbol 2: 72, symbol 3: 180).
pub const PBCH_TOTAL_DATA_RES: usize = 432;

/// Maximum number of SSBs per burst ($L_{\text{max}}$).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsbLMax {
    L4 = 4,   // FR1 f <= 3 GHz
    L8 = 8,   // FR1 3 GHz < f <= 6 GHz
    L64 = 64, // FR2 / FR3 mmWave
}

/// SSB subcarrier spacing case (TS 38.213 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsbCase {
    CaseA, // 15 kHz
    CaseB, // 30 kHz
    CaseC, // 30 kHz
    CaseD, // 120 kHz
    CaseE, // 240 kHz
    CaseF, // 480 kHz (Rel-18 FR3)
    CaseG, // 960 kHz (Rel-18 FR3)
}

/// Errors encountered in SSB & PBCH operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsbError {
    InvalidPci(u16),
    InvalidNid1(u16),
    InvalidNid2(u8),
    InvalidSsbIndex { index: u8, max: u8 },
    InvalidSfn(u16),
    ResourceConflict(String),
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for SsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SsbError::InvalidPci(pci) => write!(f, "Invalid Physical Cell ID: {}", pci),
            SsbError::InvalidNid1(nid1) => write!(f, "Invalid N_ID(1): {}", nid1),
            SsbError::InvalidNid2(nid2) => write!(f, "Invalid N_ID(2): {}", nid2),
            SsbError::InvalidSsbIndex { index, max } => {
                write!(f, "Invalid SSB index {} (max allowed: {})", index, max)
            }
            SsbError::InvalidSfn(sfn) => write!(f, "Invalid SFN: {} (must be 0..1023)", sfn),
            SsbError::ResourceConflict(msg) => write!(f, "Resource conflict: {}", msg),
            SsbError::SerializationError(e) => write!(f, "SSB serialization error: {}", e),
            SsbError::DeserializationError(e) => write!(f, "SSB deserialization error: {}", e),
        }
    }
}

impl std::error::Error for SsbError {}

// ---------------------------------------------------------------------------
// Physical Cell Identity & Sync Signals (TS 38.211 §7.4.2)
// ---------------------------------------------------------------------------

/// Represents Physical Cell Identity decomposed into $N_{\text{ID}}^{(1)}$ and $N_{\text{ID}}^{(2)}$.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalCellId {
    pub pci: u16,
    pub n_id_1: u16,
    pub n_id_2: u8,
}

impl PhysicalCellId {
    pub fn new(pci: u16) -> Result<Self, SsbError> {
        if pci >= 1008 {
            return Err(SsbError::InvalidPci(pci));
        }
        let n_id_1 = pci / 3;
        let n_id_2 = (pci % 3) as u8;
        Ok(Self { pci, n_id_1, n_id_2 })
    }

    pub fn from_components(n_id_1: u16, n_id_2: u8) -> Result<Self, SsbError> {
        if n_id_1 > 335 {
            return Err(SsbError::InvalidNid1(n_id_1));
        }
        if n_id_2 > 2 {
            return Err(SsbError::InvalidNid2(n_id_2));
        }
        let pci = 3 * n_id_1 + n_id_2 as u16;
        Ok(Self { pci, n_id_1, n_id_2 })
    }

    pub fn v_shift(&self) -> usize {
        (self.pci % 4) as usize
    }
}

/// Generates Primary Synchronization Signal (PSS) sequence of length 127 (TS 38.211 §7.4.2.2).
/// Returns BPSK values in $\{+1, -1\}$.
pub fn generate_pss(n_id_2: u8) -> Result<[i8; SYNC_SEQUENCE_LENGTH], SsbError> {
    if n_id_2 > 2 {
        return Err(SsbError::InvalidNid2(n_id_2));
    }

    let mut x = [0u8; SYNC_SEQUENCE_LENGTH];
    x[6] = 1;
    for i in 0..120 {
        x[i + 7] = (x[i + 4] ^ x[i]) & 1;
    }

    let mut d = [0i8; SYNC_SEQUENCE_LENGTH];
    for n in 0..SYNC_SEQUENCE_LENGTH {
        let m = (n + 43 * n_id_2 as usize) % SYNC_SEQUENCE_LENGTH;
        d[n] = if x[m] == 0 { 1 } else { -1 };
    }

    Ok(d)
}

/// Generates Secondary Synchronization Signal (SSS) sequence of length 127 (TS 38.211 §7.4.2.3).
/// Returns BPSK values in $\{+1, -1\}$.
pub fn generate_sss(n_id_1: u16, n_id_2: u8) -> Result<[i8; SYNC_SEQUENCE_LENGTH], SsbError> {
    if n_id_1 > 335 {
        return Err(SsbError::InvalidNid1(n_id_1));
    }
    if n_id_2 > 2 {
        return Err(SsbError::InvalidNid2(n_id_2));
    }

    let m0 = 15 * (n_id_1 as usize / 112) + 5 * (n_id_2 as usize);
    let m1 = (n_id_1 as usize) % 112;

    let mut x0 = [0u8; SYNC_SEQUENCE_LENGTH];
    let mut x1 = [0u8; SYNC_SEQUENCE_LENGTH];
    x0[0] = 1;
    x1[0] = 1;

    for i in 0..120 {
        x0[i + 7] = (x0[i + 4] ^ x0[i]) & 1;
        x1[i + 7] = (x1[i + 1] ^ x1[i]) & 1;
    }

    let mut d = [0i8; SYNC_SEQUENCE_LENGTH];
    for n in 0..SYNC_SEQUENCE_LENGTH {
        let b = (x0[(n + m0) % SYNC_SEQUENCE_LENGTH] ^ x1[(n + m1) % SYNC_SEQUENCE_LENGTH]) & 1;
        d[n] = if b == 0 { 1 } else { -1 };
    }

    Ok(d)
}

// ---------------------------------------------------------------------------
// PBCH DMRS Generation (TS 38.211 §7.4.1.4)
// ---------------------------------------------------------------------------

/// Generates 31-degree Gold sequence for PBCH DMRS initialization.
pub fn generate_gold_sequence_31(c_init: u32, length: usize) -> Vec<u8> {
    const NC: usize = 1600;
    let total_len = NC + length;

    let mut x1 = vec![0u8; total_len + 31];
    let mut x2 = vec![0u8; total_len + 31];

    x1[0] = 1;
    for i in 0..31 {
        x2[i] = ((c_init >> i) & 1) as u8;
    }

    for i in 0..total_len {
        x1[i + 31] = (x1[i + 3] ^ x1[i]) & 1;
        x2[i + 31] = (x2[i + 3] ^ x2[i + 2] ^ x2[i + 1] ^ x2[i]) & 1;
    }

    let mut c = Vec::with_capacity(length);
    for n in 0..length {
        c.push((x1[n + NC] ^ x2[n + NC]) & 1);
    }
    c
}

/// Generates 144 PBCH DMRS symbols for a specific SSB index and cell ID.
pub fn generate_pbch_dmrs(
    ssb_index: u8,
    pci: u16,
    l_max: SsbLMax,
) -> Result<Vec<(f64, f64)>, SsbError> {
    let max_val = l_max as u8;
    if ssb_index >= max_val {
        return Err(SsbError::InvalidSsbIndex {
            index: ssb_index,
            max: max_val - 1,
        });
    }

    // TS 38.211 §7.4.1.4.1:
    // i_bar_ssb = i_ssb + 4 * n_hf for L_max = 4
    // i_bar_ssb = i_ssb mod 8 for L_max = 8 or 64
    let i_bar_ssb = (ssb_index % 8) as u32;
    let c_init = (1 << 11) * (i_bar_ssb + 1) * ((pci as u32 / 4) + 1)
        + (1 << 6) * (i_bar_ssb + 1)
        + (pci as u32 % 4);

    // Need 144 QPSK symbols -> 288 pseudo-random bits
    let c = generate_gold_sequence_31(c_init, 288);
    let inv_sqrt2 = 1.0 / std::f64::consts::SQRT_2;

    let mut symbols = Vec::with_capacity(PBCH_TOTAL_DMRS_RES);
    for m in 0..PBCH_TOTAL_DMRS_RES {
        let re = (1.0 - 2.0 * c[2 * m] as f64) * inv_sqrt2;
        let im = (1.0 - 2.0 * c[2 * m + 1] as f64) * inv_sqrt2;
        symbols.push((re, im));
    }

    Ok(symbols)
}

// ---------------------------------------------------------------------------
// MasterInformationBlock (MIB) & Timing Payload (TS 38.331 / TS 38.212 §7.1)
// ---------------------------------------------------------------------------

/// 3GPP MasterInformationBlock (MIB) payload (TS 38.331 §6.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsbMib {
    pub system_frame_number_msb: u8, // 6 bits (SFN bits 9..4)
    pub subcarrier_spacing_common: u8, // 1 bit (0: 15/60 kHz, 1: 30/120 kHz)
    pub ssb_subcarrier_offset: u8,    // 4 bits (k_SSB 4 LSBs)
    pub dmrs_type_a_position: u8,     // 1 bit (0: pos2, 1: pos3)
    pub pdcch_config_sib1: u8,        // 8 bits (CORESET#0 + SearchSpace#0)
    pub cell_barred: bool,            // 1 bit
    pub intra_freq_reselection: bool, // 1 bit
    pub spare: u8,                    // 1 bit
}

impl SsbMib {
    /// Serializes 24-bit MIB (1-bit BCCH-BCH choice prefix + 23 ASN.1 MIB bits) into exactly 24 binary bits.
    pub fn to_bits(&self) -> Vec<u8> {
        let mut bits = Vec::with_capacity(24);
        bits.push(0); // 1-bit BCCH-BCH choice prefix (0 = mib)
        for i in (0..6).rev() {
            bits.push((self.system_frame_number_msb >> i) & 1);
        }
        bits.push(self.subcarrier_spacing_common & 1);
        for i in (0..4).rev() {
            bits.push((self.ssb_subcarrier_offset >> i) & 1);
        }
        bits.push(self.dmrs_type_a_position & 1);
        for i in (0..8).rev() {
            bits.push((self.pdcch_config_sib1 >> i) & 1);
        }
        bits.push(if self.cell_barred { 1 } else { 0 });
        bits.push(if self.intra_freq_reselection { 1 } else { 0 });
        bits.push(self.spare & 1);
        bits
    }

    /// Deserializes from 24 binary bits.
    pub fn from_bits(bits: &[u8]) -> Result<Self, SsbError> {
        if bits.len() < 24 {
            return Err(SsbError::DeserializationError("MIB bitstream too short".into()));
        }

        // bits[0] is the choice prefix
        let mut sfn_msb = 0u8;
        for &b in &bits[1..7] {
            sfn_msb = (sfn_msb << 1) | (b & 1);
        }
        let scs = bits[7] & 1;
        let mut k_ssb = 0u8;
        for &b in &bits[8..12] {
            k_ssb = (k_ssb << 1) | (b & 1);
        }
        let dmrs_pos = bits[12] & 1;
        let mut pdcch = 0u8;
        for &b in &bits[13..21] {
            pdcch = (pdcch << 1) | (b & 1);
        }
        let barred = bits[21] != 0;
        let intra_freq = bits[22] != 0;
        let spare = bits[23] & 1;

        Ok(Self {
            system_frame_number_msb: sfn_msb,
            subcarrier_spacing_common: scs,
            ssb_subcarrier_offset: k_ssb,
            dmrs_type_a_position: dmrs_pos,
            pdcch_config_sib1: pdcch,
            cell_barred: barred,
            intra_freq_reselection: intra_freq,
            spare,
        })
    }
}

/// PBCH payload containing 24-bit MIB and 8-bit timing information (TS 38.212 §7.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbchPayload {
    pub mib: SsbMib,
    pub sfn_lsb: u8,          // 4 bits (SFN bits 3..0)
    pub half_frame_bit: u8,   // 1 bit
    pub ssb_index_msb: u8,    // 3 bits (in FR2/FR3) or k_SSB MSB (FR1)
}

impl PbchPayload {
    pub fn new(
        mib: SsbMib,
        full_sfn: u16,
        half_frame: u8,
        ssb_index: u8,
    ) -> Result<Self, SsbError> {
        if full_sfn > 1023 {
            return Err(SsbError::InvalidSfn(full_sfn));
        }

        let sfn_msb = ((full_sfn >> 4) & 0x3F) as u8;
        let mut updated_mib = mib;
        updated_mib.system_frame_number_msb = sfn_msb;

        let sfn_lsb = (full_sfn & 0x0F) as u8;
        let ssb_index_msb = (ssb_index >> 3) & 0x07;

        Ok(Self {
            mib: updated_mib,
            sfn_lsb,
            half_frame_bit: half_frame & 1,
            ssb_index_msb,
        })
    }

    /// Generates full 32-bit uncoded PBCH payload ($\bar{a}_0 \dots \bar{a}_{31}$).
    pub fn to_32_bits(&self) -> Vec<u8> {
        let mut bits = self.mib.to_bits();
        // 4 bits SFN LSB
        for i in (0..4).rev() {
            bits.push((self.sfn_lsb >> i) & 1);
        }
        // 1 bit half frame
        bits.push(self.half_frame_bit & 1);
        // 3 bits SSB index MSB
        for i in (0..3).rev() {
            bits.push((self.ssb_index_msb >> i) & 1);
        }
        bits
    }

    /// Reconstructs full SFN (0..1023).
    pub fn full_sfn(&self) -> u16 {
        ((self.mib.system_frame_number_msb as u16) << 4) | (self.sfn_lsb as u16)
    }
}

// ---------------------------------------------------------------------------
// SSB Resource Grid Construction (TS 38.211 §7.4.3.1)
// ---------------------------------------------------------------------------

/// State of a single Resource Element within the SSB block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsbReType {
    Empty,
    Pss,
    Sss,
    PbchData,
    PbchDmrs,
    Reserved,
}

/// 4-symbol x 240-subcarrier resource grid for SS/PBCH block.
#[derive(Debug, Clone)]
pub struct SsbResourceGrid {
    pub pci: PhysicalCellId,
    pub ssb_index: u8,
    grid: Vec<Vec<SsbReType>>,
}

impl SsbResourceGrid {
    pub fn new(pci: PhysicalCellId, ssb_index: u8) -> Self {
        Self {
            pci,
            ssb_index,
            grid: vec![vec![SsbReType::Empty; SSB_NUM_SUBCARRIERS]; SSB_NUM_SYMBOLS],
        }
    }

    pub fn get_re(&self, symbol: usize, sc: usize) -> SsbReType {
        if symbol < SSB_NUM_SYMBOLS && sc < SSB_NUM_SUBCARRIERS {
            self.grid[symbol][sc]
        } else {
            SsbReType::Empty
        }
    }

    /// Populates standard SSB mapping according to TS 38.211 §7.4.3.1.
    pub fn populate_grid(&mut self) {
        let v_shift = self.pci.v_shift();

        // 1. Symbol 0: PSS on subcarriers 56..182, others empty
        for sc in SYNC_SUBCARRIER_OFFSET..(SYNC_SUBCARRIER_OFFSET + SYNC_SEQUENCE_LENGTH) {
            self.grid[0][sc] = SsbReType::Pss;
        }

        // 2. Symbol 1: PBCH and DMRS on all 240 subcarriers
        for sc in 0..SSB_NUM_SUBCARRIERS {
            if sc % 4 == v_shift {
                self.grid[1][sc] = SsbReType::PbchDmrs;
            } else {
                self.grid[1][sc] = SsbReType::PbchData;
            }
        }

        // 3. Symbol 2:
        //    - PBCH & DMRS on 0..47
        //    - Reserved on 48..55
        //    - SSS on 56..182
        //    - Reserved on 183..191
        //    - PBCH & DMRS on 192..239
        for sc in 0..48 {
            if sc % 4 == v_shift {
                self.grid[2][sc] = SsbReType::PbchDmrs;
            } else {
                self.grid[2][sc] = SsbReType::PbchData;
            }
        }
        for sc in 48..56 {
            self.grid[2][sc] = SsbReType::Reserved;
        }
        for sc in SYNC_SUBCARRIER_OFFSET..(SYNC_SUBCARRIER_OFFSET + SYNC_SEQUENCE_LENGTH) {
            self.grid[2][sc] = SsbReType::Sss;
        }
        for sc in 183..192 {
            self.grid[2][sc] = SsbReType::Reserved;
        }
        for sc in 192..SSB_NUM_SUBCARRIERS {
            if sc % 4 == v_shift {
                self.grid[2][sc] = SsbReType::PbchDmrs;
            } else {
                self.grid[2][sc] = SsbReType::PbchData;
            }
        }

        // 4. Symbol 3: PBCH and DMRS on all 240 subcarriers
        for sc in 0..SSB_NUM_SUBCARRIERS {
            if sc % 4 == v_shift {
                self.grid[3][sc] = SsbReType::PbchDmrs;
            } else {
                self.grid[3][sc] = SsbReType::PbchData;
            }
        }
    }

    /// Counts total REs of a given type.
    pub fn count_re_type(&self, target: SsbReType) -> usize {
        self.grid.iter().flat_map(|r| r.iter()).filter(|&&re| re == target).count()
    }
}

// ---------------------------------------------------------------------------
// Beam Sweeping & Selection Engine (TS 38.213 §4.1)
// ---------------------------------------------------------------------------

/// SS-RSRP measurement of a single transmitted SSB beam.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SsbBeamMeasurement {
    pub ssb_index: u8,
    pub ss_rsrp_dbm: f64,
    pub ss_rsrq_db: f64,
}

/// SSB Transmission Burst and Multi-Beam Sweeping Manager.
#[derive(Debug, Clone)]
pub struct SsbBurstManager {
    pub pci: PhysicalCellId,
    pub l_max: SsbLMax,
    pub ssb_case: SsbCase,
    pub periodicity_ms: u8, // e.g. 5, 10, 20, 40, 80, 160 ms
    pub transmitted_ssb_mask: u64,
}

impl SsbBurstManager {
    pub fn new(pci: PhysicalCellId, l_max: SsbLMax, ssb_case: SsbCase, periodicity_ms: u8) -> Self {
        let max_beams = l_max as usize;
        let transmitted_ssb_mask = if max_beams == 64 {
            u64::MAX
        } else {
            (1u64 << max_beams) - 1
        };

        Self {
            pci,
            l_max,
            ssb_case,
            periodicity_ms,
            transmitted_ssb_mask,
        }
    }

    /// Checks if a specific SSB index is configured for transmission.
    pub fn is_ssb_transmitted(&self, ssb_index: u8) -> bool {
        if ssb_index >= self.l_max as u8 {
            return false;
        }
        (self.transmitted_ssb_mask & (1u64 << ssb_index)) != 0
    }

    /// Evaluates measurements across all beams and selects the optimal SSB beam for initial access.
    pub fn select_best_beam(
        &self,
        measurements: &[SsbBeamMeasurement],
        rsrp_threshold_dbm: f64,
    ) -> Option<SsbBeamMeasurement> {
        measurements
            .iter()
            .filter(|m| self.is_ssb_transmitted(m.ssb_index) && m.ss_rsrp_dbm >= rsrp_threshold_dbm)
            .max_by(|a, b| a.ss_rsrp_dbm.partial_cmp(&b.ss_rsrp_dbm).unwrap_or(std::cmp::Ordering::Equal))
            .copied()
    }
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16
// ---------------------------------------------------------------------------

/// Wire frame PDU for SSB transmission descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsbWirePdu {
    pub magic: u32,
    pub pci: u16,
    pub ssb_index: u8,
    pub sfn: u16,
    pub half_frame: u8,
    pub l_max: u8,
    pub scs_case: u8,
    pub mib_bits: u32,
    pub payload: Vec<u8>,
    pub crc16: u16,
}

/// Computes CRC-16 CCITT.
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

impl SsbWirePdu {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + self.payload.len());
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.pci.to_be_bytes());
        buf.push(self.ssb_index);
        buf.extend_from_slice(&self.sfn.to_be_bytes());
        buf.push(self.half_frame);
        buf.push(self.l_max);
        buf.push(self.scs_case);
        buf.extend_from_slice(&self.mib_bits.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, SsbError> {
        if data.len() < 20 {
            return Err(SsbError::DeserializationError("Buffer too small".into()));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != SSB_WIRE_MAGIC {
            return Err(SsbError::DeserializationError(format!("Invalid magic: 0x{:08X}", magic)));
        }

        let pci = u16::from_be_bytes([data[4], data[5]]);
        let ssb_index = data[6];
        let sfn = u16::from_be_bytes([data[7], data[8]]);
        let half_frame = data[9];
        let l_max = data[10];
        let scs_case = data[11];
        let mib_bits = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let payload_len = u16::from_be_bytes([data[16], data[17]]) as usize;

        if data.len() < 18 + payload_len + 2 {
            return Err(SsbError::DeserializationError("Truncated payload".into()));
        }

        let payload = data[18..18 + payload_len].to_vec();
        let expected_crc = compute_crc16(&data[..18 + payload_len]);
        let rx_crc = u16::from_be_bytes([data[18 + payload_len], data[18 + payload_len + 1]]);

        if rx_crc != expected_crc {
            return Err(SsbError::DeserializationError(format!(
                "CRC-16 mismatch: expected 0x{:04X}, received 0x{:04X}",
                expected_crc, rx_crc
            )));
        }

        Ok(Self {
            magic,
            pci,
            ssb_index,
            sfn,
            half_frame,
            l_max,
            scs_case,
            mib_bits,
            payload,
            crc16: rx_crc,
        })
    }
}

//! 3GPP Release 18/19 5G-Advanced Downlink Control Information (DCI) Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.212 Rel-18 §7.3.1: DCI formats (0_0, 0_1, 1_0, 1_1, 2_0, 2_1, 2_4).
//! - 3GPP TS 38.212 Rel-18 §7.3.2: CRC attachment and RNTI scrambling for control channels.
//! - 3GPP TS 38.212 Rel-18 §5.1: CRC24C calculation.
//! - 3GPP TS 38.213 Rel-18 §10.1: UE procedure for receiving control information & DCI size budgeting.
//! - 3GPP TS 38.214 Rel-18 §5.1.2.2: Resource allocation in frequency domain (Type 0 and Type 1 RIV).
//!
//! Features:
//! 1. Big-endian bit-level serialization engine (`BitWriter` and `BitReader`) with arbitrary bit widths.
//! 2. Resource Allocation Type 1: Resource Indication Value (RIV) encoding and decoding with standard 3GPP formulas.
//! 3. Resource Allocation Type 0: Resource Block Group (RBG) bitmap configuration and conversion.
//! 4. Comprehensive DCI format representations:
//!    - `DciFormat0_0`: Fallback uplink grant (TS 38.212 §7.3.1.1.1).
//!    - `DciFormat0_1`: Non-fallback uplink grant with CBGTI, SRS, and TPMI (TS 38.212 §7.3.1.1.2).
//!    - `DciFormat1_0`: Fallback downlink assignment (TS 38.212 §7.3.1.2.1).
//!    - `DciFormat1_1`: Non-fallback downlink assignment with TCI, PRI, DAI, and CBGTI/CBGFI (TS 38.212 §7.3.1.2.2).
//!    - `DciFormat2_0`: Dynamic slot format indication (SFI) across serving cells (TS 38.212 §7.3.1.3.1).
//!    - `DciFormat2_1`: Pre-emption indication for DL URLLC multiplexing (INT-RNTI) (TS 38.212 §7.3.1.3.2).
//!    - `DciFormat2_4`: Uplink cancellation indication for UL URLLC multiplexing (CI-RNTI) (TS 38.212 §7.3.1.3.5).
//! 5. DCI size alignment and zero-padding rules (TS 38.212 §7.3.1.0) avoiding 3GPP ambiguous/forbidden sizes.
//! 6. CRC-24C attachment, 16-bit RNTI parity scrambling, and blind RNTI extraction.
//! 7. Binary wire framing (`DciWirePdu`) with magic `0x44434930` ("DCI0") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for DCI Wire PDU: "DCI0" (0x44434930).
pub const DCI_WIRE_MAGIC: u32 = 0x44434930;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// CRC24C generator polynomial: D^24 + D^23 + D^21 + D^20 + D^17 + D^15 + D^13 + D^12 + D^8 + D^4 + D^2 + D + 1
pub const CRC24C_POLY: u32 = 0xB2B117;

/// 3GPP TS 38.212 §7.3.1.0 ambiguous/forbidden DCI payload sizes that require 1 zero-padding bit.
pub const FORBIDDEN_DCI_SIZES: [usize; 9] = [12, 16, 20, 24, 26, 32, 40, 44, 56];

/// Maximum PRBs in 5G NR carrier (TS 38.101).
pub const MAX_NR_PRBS: u16 = 275;

/// Errors in DCI operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DciError {
    InvalidBwpSize(u16),
    InvalidPrbRange { start: u16, length: u16, bwp_size: u16 },
    InvalidRiv { riv: u32, bwp_size: u16 },
    InvalidBitWidth(usize),
    BufferUnderflow { needed_bits: usize, available_bits: usize },
    InvalidRnti(String),
    CrcMismatch { expected: u32, computed: u32 },
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    ForbiddenPayloadSize(usize),
    FieldOutOfRange { field: &'static str, value: u64, max: u64 },
}

impl fmt::Display for DciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBwpSize(s) => write!(f, "Invalid BWP size: {} (must be 1..275)", s),
            Self::InvalidPrbRange { start, length, bwp_size } => {
                write!(f, "Invalid PRB range: start={}, len={} in BWP size {}", start, length, bwp_size)
            }
            Self::InvalidRiv { riv, bwp_size } => {
                write!(f, "Invalid RIV {} for BWP size {}", riv, bwp_size)
            }
            Self::InvalidBitWidth(w) => write!(f, "Invalid bit width: {} (must be 1..64)", w),
            Self::BufferUnderflow { needed_bits, available_bits } => {
                write!(f, "Buffer underflow: needed {} bits, available {}", needed_bits, available_bits)
            }
            Self::InvalidRnti(msg) => write!(f, "Invalid RNTI: {}", msg),
            Self::CrcMismatch { expected, computed } => {
                write!(f, "CRC mismatch: expected 0x{:06X}, computed 0x{:06X}", expected, computed)
            }
            Self::InvalidWireMagic(m) => write!(f, "Invalid DCI wire magic: 0x{:08X}", m),
            Self::WirePayloadTooShort { needed, found } => {
                write!(f, "Wire payload too short: needed {} bytes, found {}", needed, found)
            }
            Self::ForbiddenPayloadSize(s) => write!(f, "Forbidden DCI size: {} bits", s),
            Self::FieldOutOfRange { field, value, max } => {
                write!(f, "Field '{}' value {} exceeds max {}", field, value, max)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BitWriter & BitReader for Big-Endian Network Bit Streams
// ---------------------------------------------------------------------------

/// High-performance bitstream writer (MSB first, Big-Endian 3GPP network order).
#[derive(Debug, Clone, Default)]
pub struct BitWriter {
    bits: Vec<u8>,
}

impl BitWriter {
    /// Creates a new empty `BitWriter`.
    pub fn new() -> Self {
        Self { bits: Vec::new() }
    }

    /// Number of bits currently written.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Returns `true` if no bits have been written.
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// Writes a single bit (0 or 1).
    pub fn push_bit(&mut self, bit: u8) {
        self.bits.push(if bit != 0 { 1 } else { 0 });
    }

    /// Writes `width` bits from `value` (most significant of the `width` bits first).
    pub fn push_bits(&mut self, value: u64, width: usize) {
        for i in (0..width).rev() {
            let b = ((value >> i) & 1) as u8;
            self.bits.push(b);
        }
    }

    /// Appends `count` zeros to the bitstream.
    pub fn pad_zeros(&mut self, count: usize) {
        self.bits.resize(self.bits.len() + count, 0);
    }

    /// Returns a reference to the individual bit vector.
    pub fn as_bit_slice(&self) -> &[u8] {
        &self.bits
    }

    /// Packs bits into a byte vector (MSB first within each byte, zero-padded at end of last byte).
    pub fn to_bytes(&self) -> Vec<u8> {
        let byte_len = (self.bits.len() + 7) / 8;
        let mut out = vec![0u8; byte_len];
        for (i, &bit) in self.bits.iter().enumerate() {
            if bit != 0 {
                let byte_idx = i / 8;
                let bit_idx = 7 - (i % 8);
                out[byte_idx] |= 1 << bit_idx;
            }
        }
        out
    }

    /// Creates a `BitWriter` initialized from a byte slice and exact bit length.
    pub fn from_bytes(bytes: &[u8], total_bits: usize) -> Result<Self, DciError> {
        if bytes.len() * 8 < total_bits {
            return Err(DciError::BufferUnderflow {
                needed_bits: total_bits,
                available_bits: bytes.len() * 8,
            });
        }
        let mut bits = Vec::with_capacity(total_bits);
        for i in 0..total_bits {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let b = (bytes[byte_idx] >> bit_idx) & 1;
            bits.push(b);
        }
        Ok(Self { bits })
    }
}

/// Bitstream reader (MSB first, Big-Endian 3GPP network order).
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    bits: &'a [u8],
    cursor: usize,
}

impl<'a> BitReader<'a> {
    /// Creates a new `BitReader` over a bit slice.
    pub fn new(bits: &'a [u8]) -> Self {
        Self { bits, cursor: 0 }
    }

    /// Number of remaining unread bits.
    pub fn remaining(&self) -> usize {
        self.bits.len().saturating_sub(self.cursor)
    }

    /// Current read cursor index.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Reads a single bit.
    pub fn read_bit(&mut self) -> Result<u8, DciError> {
        if self.cursor >= self.bits.len() {
            return Err(DciError::BufferUnderflow {
                needed_bits: 1,
                available_bits: 0,
            });
        }
        let b = self.bits[self.cursor];
        self.cursor += 1;
        Ok(b)
    }

    /// Reads `width` bits as an integer (`u64`).
    pub fn read_bits(&mut self, width: usize) -> Result<u64, DciError> {
        if width > 64 {
            return Err(DciError::InvalidBitWidth(width));
        }
        if self.remaining() < width {
            return Err(DciError::BufferUnderflow {
                needed_bits: width,
                available_bits: self.remaining(),
            });
        }
        let mut val = 0u64;
        for _ in 0..width {
            val = (val << 1) | (self.bits[self.cursor] as u64);
            self.cursor += 1;
        }
        Ok(val)
    }

    /// Skips `count` bits.
    pub fn skip(&mut self, count: usize) -> Result<(), DciError> {
        if self.remaining() < count {
            return Err(DciError::BufferUnderflow {
                needed_bits: count,
                available_bits: self.remaining(),
            });
        }
        self.cursor += count;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Resource Allocation Type 1: RIV (Resource Indication Value)
// ---------------------------------------------------------------------------

/// Computes the number of bits required for Resource Indication Value (RIV)
/// for a given BWP size in PRBs: $N_{\text{RIV\_bits}} = \lceil \log_2(N(N+1)/2) \rceil$.
pub fn compute_riv_bits(bwp_size: u16) -> Result<usize, DciError> {
    if bwp_size == 0 || bwp_size > MAX_NR_PRBS {
        return Err(DciError::InvalidBwpSize(bwp_size));
    }
    let n = bwp_size as u64;
    let max_combinations = n * (n + 1) / 2;
    let mut bits = 0;
    let mut val = 1u64;
    while val < max_combinations {
        val <<= 1;
        bits += 1;
    }
    Ok(bits)
}

/// Encodes contiguous PRB allocation (start PRB and length in PRBs) into 3GPP RIV (TS 38.214 §5.1.2.2.2).
///
/// If $(L_{\text{RBs}} - 1) \le \lfloor N_{\text{BWP}}^{\text{size}} / 2 \rfloor$:
///   $RIV = N_{\text{BWP}}^{\text{size}} \cdot (L_{\text{RBs}} - 1) + RB_{\text{start}}$
/// Else:
///   $RIV = N_{\text{BWP}}^{\text{size}} \cdot (N_{\text{BWP}}^{\text{size}} - L_{\text{RBs}} + 1) + (N_{\text{BWP}}^{\text{size}} - 1 - RB_{\text{start}})$
pub fn encode_riv(rb_start: u16, l_rbs: u16, bwp_size: u16) -> Result<u32, DciError> {
    if bwp_size == 0 || bwp_size > MAX_NR_PRBS {
        return Err(DciError::InvalidBwpSize(bwp_size));
    }
    if l_rbs == 0 || rb_start + l_rbs > bwp_size {
        return Err(DciError::InvalidPrbRange {
            start: rb_start,
            length: l_rbs,
            bwp_size,
        });
    }

    let n = bwp_size as u32;
    let start = rb_start as u32;
    let len = l_rbs as u32;

    let riv = if len - 1 <= n / 2 {
        n * (len - 1) + start
    } else {
        n * (n - len + 1) + (n - 1 - start)
    };

    Ok(riv)
}

/// Decodes a 3GPP RIV value back into `(rb_start, l_rbs)` given the BWP size (TS 38.214 §5.1.2.2.2).
pub fn decode_riv(riv: u32, bwp_size: u16) -> Result<(u16, u16), DciError> {
    if bwp_size == 0 || bwp_size > MAX_NR_PRBS {
        return Err(DciError::InvalidBwpSize(bwp_size));
    }
    let n = bwp_size as u32;
    let max_combinations = (n * (n + 1)) / 2;
    if riv >= max_combinations {
        return Err(DciError::InvalidRiv { riv, bwp_size });
    }

    let a = riv / n;
    let b = riv % n;

    let (rb_start, l_rbs) = if a + b < n {
        (b, a + 1)
    } else {
        (n - 1 - b, n - a + 1)
    };

    if l_rbs == 0 || rb_start + l_rbs > n {
        return Err(DciError::InvalidRiv { riv, bwp_size });
    }

    Ok((rb_start as u16, l_rbs as u16))
}

// ---------------------------------------------------------------------------
// Resource Allocation Type 0: RBG Bitmaps (TS 38.214 §5.1.2.2.1)
// ---------------------------------------------------------------------------

/// RBG Configuration Type (Config 1 vs Config 2 in TS 38.214 Table 5.1.2.2.1-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbgSizeConfig {
    Config1,
    Config2,
}

/// Determines the nominal Resource Block Group (RBG) size $P$ given BWP size and configuration.
pub fn get_rbg_size(bwp_size: u16, config: RbgSizeConfig) -> u8 {
    match config {
        RbgSizeConfig::Config1 => {
            if bwp_size <= 36 {
                2
            } else if bwp_size <= 72 {
                4
            } else if bwp_size <= 144 {
                8
            } else {
                16
            }
        }
        RbgSizeConfig::Config2 => {
            if bwp_size <= 36 {
                4
            } else if bwp_size <= 72 {
                8
            } else {
                16
            }
        }
    }
}

/// Computes the number of RBG bits required for Type 0 resource allocation bitmap:
/// $N_{\text{RBG}} = \lceil (N_{\text{BWP}}^{\text{size}} + (N_{\text{BWP}}^{\text{start}} \bmod P)) / P \rceil$.
pub fn compute_num_rbgs(bwp_start: u16, bwp_size: u16, p_rbg: u8) -> usize {
    if p_rbg == 0 {
        return 0;
    }
    let p = p_rbg as usize;
    let offset = (bwp_start as usize) % p;
    ((bwp_size as usize) + offset + p - 1) / p
}

/// Converts an RBG bitmap to a list of allocated PRB indices.
pub fn rbg_bitmap_to_prbs(
    bitmap: u32,
    num_rbgs: usize,
    bwp_start: u16,
    bwp_size: u16,
    p_rbg: u8,
) -> Vec<u16> {
    let mut prbs = Vec::new();
    let p = p_rbg as u16;
    let start_offset = (bwp_start % p) as u16;

    for rbg_idx in 0..num_rbgs {
        let bit = (bitmap >> (num_rbgs - 1 - rbg_idx)) & 1;
        if bit == 1 {
            let rbg_prb_start = if rbg_idx == 0 {
                0
            } else {
                (rbg_idx as u16) * p - start_offset
            };
            let rbg_prb_end = if rbg_idx == 0 {
                (p - start_offset).min(bwp_size)
            } else {
                ((rbg_idx as u16 + 1) * p - start_offset).min(bwp_size)
            };
            for prb in rbg_prb_start..rbg_prb_end {
                prbs.push(prb);
            }
        }
    }
    prbs
}

// ---------------------------------------------------------------------------
// Frequency Domain Resource Allocation Variant
// ---------------------------------------------------------------------------

/// Frequency Domain Resource Assignment enum (Type 0 bitmap or Type 1 RIV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdResourceAllocation {
    Type0Bitmap { bitmap: u32, num_bits: usize },
    Type1Riv { riv: u32, num_bits: usize },
}

// ---------------------------------------------------------------------------
// DCI Format Definitions (TS 38.212 Rel-18 §7.3.1)
// ---------------------------------------------------------------------------

/// DCI Format 0_0: Fallback Uplink Grant (TS 38.212 §7.3.1.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DciFormat0_0 {
    pub dci_format_flag: u8,
    pub riv: u32,
    pub riv_bits: usize,
    pub tdra: u8,
    pub freq_hopping: u8,
    pub mcs: u8,
    pub ndi: u8,
    pub rv: u8,
    pub harq_pid: u8,
    pub tpc: u8,
    pub sul_indicator: Option<u8>,
}

impl DciFormat0_0 {
    pub fn serialize(&self) -> Result<BitWriter, DciError> {
        let mut writer = BitWriter::new();
        writer.push_bits(self.dci_format_flag as u64, 1);
        writer.push_bits(self.riv as u64, self.riv_bits);
        writer.push_bits(self.tdra as u64, 4);
        writer.push_bits(self.freq_hopping as u64, 1);
        writer.push_bits(self.mcs as u64, 5);
        writer.push_bits(self.ndi as u64, 1);
        writer.push_bits(self.rv as u64, 2);
        writer.push_bits(self.harq_pid as u64, 4);
        writer.push_bits(self.tpc as u64, 2);
        if let Some(sul) = self.sul_indicator {
            writer.push_bits(sul as u64, 1);
        }
        Ok(writer)
    }

    pub fn deserialize(
        reader: &mut BitReader<'_>,
        riv_bits: usize,
        has_sul: bool,
    ) -> Result<Self, DciError> {
        let dci_format_flag = reader.read_bits(1)? as u8;
        let riv = reader.read_bits(riv_bits)? as u32;
        let tdra = reader.read_bits(4)? as u8;
        let freq_hopping = reader.read_bits(1)? as u8;
        let mcs = reader.read_bits(5)? as u8;
        let ndi = reader.read_bits(1)? as u8;
        let rv = reader.read_bits(2)? as u8;
        let harq_pid = reader.read_bits(4)? as u8;
        let tpc = reader.read_bits(2)? as u8;
        let sul_indicator = if has_sul {
            Some(reader.read_bits(1)? as u8)
        } else {
            None
        };

        Ok(Self {
            dci_format_flag,
            riv,
            riv_bits,
            tdra,
            freq_hopping,
            mcs,
            ndi,
            rv,
            harq_pid,
            tpc,
            sul_indicator,
        })
    }
}

/// DCI Format 0_1: Non-Fallback Uplink Grant (TS 38.212 §7.3.1.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DciFormat0_1 {
    pub carrier_indicator: Option<u8>,
    pub dci_format_flag: u8,
    pub bwp_indicator: u8,
    pub fdra: FdResourceAllocation,
    pub tdra: u8,
    pub freq_hopping: u8,
    pub mcs: u8,
    pub ndi: u8,
    pub rv: u8,
    pub harq_pid: u8,
    pub first_dmrs_seq_init: u8,
    pub sri: u8,
    pub sri_bits: usize,
    pub tpmi: u8,
    pub tpmi_bits: usize,
    pub srs_request: u8,
    pub csi_request: u8,
    pub csi_request_bits: usize,
    pub cbgti: Option<u8>,
    pub cbgti_bits: usize,
    pub ptrs_dmrs_assoc: Option<u8>,
    pub beta_offset_indicator: Option<u8>,
    pub ul_sch_indicator: u8,
}

impl DciFormat0_1 {
    pub fn serialize(&self) -> Result<BitWriter, DciError> {
        let mut writer = BitWriter::new();
        if let Some(ci) = self.carrier_indicator {
            writer.push_bits(ci as u64, 3);
        }
        writer.push_bits(self.dci_format_flag as u64, 1);
        if self.bwp_indicator > 0 {
            writer.push_bits(self.bwp_indicator as u64, 2);
        }
        match &self.fdra {
            FdResourceAllocation::Type0Bitmap { bitmap, num_bits } => {
                writer.push_bits(*bitmap as u64, *num_bits);
            }
            FdResourceAllocation::Type1Riv { riv, num_bits } => {
                writer.push_bits(*riv as u64, *num_bits);
            }
        }
        writer.push_bits(self.tdra as u64, 4);
        writer.push_bits(self.freq_hopping as u64, 1);
        writer.push_bits(self.mcs as u64, 5);
        writer.push_bits(self.ndi as u64, 1);
        writer.push_bits(self.rv as u64, 2);
        writer.push_bits(self.harq_pid as u64, 4);
        writer.push_bits(self.first_dmrs_seq_init as u64, 1);
        if self.sri_bits > 0 {
            writer.push_bits(self.sri as u64, self.sri_bits);
        }
        if self.tpmi_bits > 0 {
            writer.push_bits(self.tpmi as u64, self.tpmi_bits);
        }
        writer.push_bits(self.srs_request as u64, 2);
        if self.csi_request_bits > 0 {
            writer.push_bits(self.csi_request as u64, self.csi_request_bits);
        }
        if let Some(cbgti) = self.cbgti {
            if self.cbgti_bits > 0 {
                writer.push_bits(cbgti as u64, self.cbgti_bits);
            }
        }
        if let Some(ptrs) = self.ptrs_dmrs_assoc {
            writer.push_bits(ptrs as u64, 2);
        }
        if let Some(beta) = self.beta_offset_indicator {
            writer.push_bits(beta as u64, 2);
        }
        writer.push_bits(self.ul_sch_indicator as u64, 1);
        Ok(writer)
    }

    pub fn deserialize(
        reader: &mut BitReader<'_>,
        has_carrier: bool,
        has_bwp: bool,
        fdra_type: bool, // false: Type0 bitmap, true: Type1 RIV
        fdra_bits: usize,
        sri_bits: usize,
        tpmi_bits: usize,
        csi_bits: usize,
        cbgti_bits: usize,
        has_ptrs: bool,
        has_beta: bool,
    ) -> Result<Self, DciError> {
        let carrier_indicator = if has_carrier {
            Some(reader.read_bits(3)? as u8)
        } else {
            None
        };
        let dci_format_flag = reader.read_bits(1)? as u8;
        let bwp_indicator = if has_bwp {
            reader.read_bits(2)? as u8
        } else {
            0
        };
        let fdra = if fdra_type {
            let riv = reader.read_bits(fdra_bits)? as u32;
            FdResourceAllocation::Type1Riv {
                riv,
                num_bits: fdra_bits,
            }
        } else {
            let bitmap = reader.read_bits(fdra_bits)? as u32;
            FdResourceAllocation::Type0Bitmap {
                bitmap,
                num_bits: fdra_bits,
            }
        };
        let tdra = reader.read_bits(4)? as u8;
        let freq_hopping = reader.read_bits(1)? as u8;
        let mcs = reader.read_bits(5)? as u8;
        let ndi = reader.read_bits(1)? as u8;
        let rv = reader.read_bits(2)? as u8;
        let harq_pid = reader.read_bits(4)? as u8;
        let first_dmrs_seq_init = reader.read_bits(1)? as u8;
        let sri = if sri_bits > 0 {
            reader.read_bits(sri_bits)? as u8
        } else {
            0
        };
        let tpmi = if tpmi_bits > 0 {
            reader.read_bits(tpmi_bits)? as u8
        } else {
            0
        };
        let srs_request = reader.read_bits(2)? as u8;
        let csi_request = if csi_bits > 0 {
            reader.read_bits(csi_bits)? as u8
        } else {
            0
        };
        let cbgti = if cbgti_bits > 0 {
            Some(reader.read_bits(cbgti_bits)? as u8)
        } else {
            None
        };
        let ptrs_dmrs_assoc = if has_ptrs {
            Some(reader.read_bits(2)? as u8)
        } else {
            None
        };
        let beta_offset_indicator = if has_beta {
            Some(reader.read_bits(2)? as u8)
        } else {
            None
        };
        let ul_sch_indicator = reader.read_bits(1)? as u8;

        Ok(Self {
            carrier_indicator,
            dci_format_flag,
            bwp_indicator,
            fdra,
            tdra,
            freq_hopping,
            mcs,
            ndi,
            rv,
            harq_pid,
            first_dmrs_seq_init,
            sri,
            sri_bits,
            tpmi,
            tpmi_bits,
            srs_request,
            csi_request,
            csi_request_bits: csi_bits,
            cbgti,
            cbgti_bits,
            ptrs_dmrs_assoc,
            beta_offset_indicator,
            ul_sch_indicator,
        })
    }
}

/// DCI Format 1_0: Fallback Downlink Assignment (TS 38.212 §7.3.1.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DciFormat1_0 {
    pub dci_format_flag: u8,
    pub riv: u32,
    pub riv_bits: usize,
    pub tdra: u8,
    pub vrb_to_prb_mapping: u8,
    pub mcs: u8,
    pub ndi: u8,
    pub rv: u8,
    pub harq_pid: u8,
    pub dai: u8,
    pub tpc_pucch: u8,
    pub pucch_resource_indicator: u8,
    pub pdsch_to_harq_timing: u8,
}

impl DciFormat1_0 {
    pub fn serialize(&self) -> Result<BitWriter, DciError> {
        let mut writer = BitWriter::new();
        writer.push_bits(self.dci_format_flag as u64, 1);
        writer.push_bits(self.riv as u64, self.riv_bits);
        writer.push_bits(self.tdra as u64, 4);
        writer.push_bits(self.vrb_to_prb_mapping as u64, 1);
        writer.push_bits(self.mcs as u64, 5);
        writer.push_bits(self.ndi as u64, 1);
        writer.push_bits(self.rv as u64, 2);
        writer.push_bits(self.harq_pid as u64, 4);
        writer.push_bits(self.dai as u64, 2);
        writer.push_bits(self.tpc_pucch as u64, 2);
        writer.push_bits(self.pucch_resource_indicator as u64, 3);
        writer.push_bits(self.pdsch_to_harq_timing as u64, 3);
        Ok(writer)
    }

    pub fn deserialize(reader: &mut BitReader<'_>, riv_bits: usize) -> Result<Self, DciError> {
        let dci_format_flag = reader.read_bits(1)? as u8;
        let riv = reader.read_bits(riv_bits)? as u32;
        let tdra = reader.read_bits(4)? as u8;
        let vrb_to_prb_mapping = reader.read_bits(1)? as u8;
        let mcs = reader.read_bits(5)? as u8;
        let ndi = reader.read_bits(1)? as u8;
        let rv = reader.read_bits(2)? as u8;
        let harq_pid = reader.read_bits(4)? as u8;
        let dai = reader.read_bits(2)? as u8;
        let tpc_pucch = reader.read_bits(2)? as u8;
        let pucch_resource_indicator = reader.read_bits(3)? as u8;
        let pdsch_to_harq_timing = reader.read_bits(3)? as u8;

        Ok(Self {
            dci_format_flag,
            riv,
            riv_bits,
            tdra,
            vrb_to_prb_mapping,
            mcs,
            ndi,
            rv,
            harq_pid,
            dai,
            tpc_pucch,
            pucch_resource_indicator,
            pdsch_to_harq_timing,
        })
    }
}

/// DCI Format 1_1: Non-Fallback Downlink Assignment (TS 38.212 §7.3.1.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DciFormat1_1 {
    pub carrier_indicator: Option<u8>,
    pub dci_format_flag: u8,
    pub bwp_indicator: u8,
    pub fdra: FdResourceAllocation,
    pub tdra: u8,
    pub vrb_to_prb_mapping: u8,
    pub prb_bundling_indicator: Option<u8>,
    pub rate_matching_indicator: Option<u8>,
    pub zp_csi_rs_trigger: Option<u8>,
    pub mcs: u8,
    pub ndi: u8,
    pub rv: u8,
    pub harq_pid: u8,
    pub dai: u8,
    pub tpc_pucch: u8,
    pub pucch_resource_indicator: u8,
    pub pdsch_to_harq_timing: u8,
    pub antenna_ports: u8,
    pub antenna_port_bits: usize,
    pub tci_state: Option<u8>,
    pub srs_request: u8,
    pub cbgti: Option<u8>,
    pub cbgti_bits: usize,
    pub cbgfi: Option<u8>,
}

impl DciFormat1_1 {
    pub fn serialize(&self) -> Result<BitWriter, DciError> {
        let mut writer = BitWriter::new();
        if let Some(ci) = self.carrier_indicator {
            writer.push_bits(ci as u64, 3);
        }
        writer.push_bits(self.dci_format_flag as u64, 1);
        if self.bwp_indicator > 0 {
            writer.push_bits(self.bwp_indicator as u64, 2);
        }
        match &self.fdra {
            FdResourceAllocation::Type0Bitmap { bitmap, num_bits } => {
                writer.push_bits(*bitmap as u64, *num_bits);
            }
            FdResourceAllocation::Type1Riv { riv, num_bits } => {
                writer.push_bits(*riv as u64, *num_bits);
            }
        }
        writer.push_bits(self.tdra as u64, 4);
        writer.push_bits(self.vrb_to_prb_mapping as u64, 1);
        if let Some(bundling) = self.prb_bundling_indicator {
            writer.push_bits(bundling as u64, 1);
        }
        if let Some(rm) = self.rate_matching_indicator {
            writer.push_bits(rm as u64, 2);
        }
        if let Some(zp) = self.zp_csi_rs_trigger {
            writer.push_bits(zp as u64, 2);
        }
        writer.push_bits(self.mcs as u64, 5);
        writer.push_bits(self.ndi as u64, 1);
        writer.push_bits(self.rv as u64, 2);
        writer.push_bits(self.harq_pid as u64, 4);
        writer.push_bits(self.dai as u64, 2);
        writer.push_bits(self.tpc_pucch as u64, 2);
        writer.push_bits(self.pucch_resource_indicator as u64, 3);
        writer.push_bits(self.pdsch_to_harq_timing as u64, 3);
        writer.push_bits(self.antenna_ports as u64, self.antenna_port_bits);
        if let Some(tci) = self.tci_state {
            writer.push_bits(tci as u64, 3);
        }
        writer.push_bits(self.srs_request as u64, 2);
        if let Some(cbgti) = self.cbgti {
            if self.cbgti_bits > 0 {
                writer.push_bits(cbgti as u64, self.cbgti_bits);
            }
        }
        if let Some(cbgfi) = self.cbgfi {
            writer.push_bits(cbgfi as u64, 1);
        }
        Ok(writer)
    }

    pub fn deserialize(
        reader: &mut BitReader<'_>,
        has_carrier: bool,
        has_bwp: bool,
        fdra_type: bool,
        fdra_bits: usize,
        has_bundling: bool,
        has_rm: bool,
        has_zp: bool,
        antenna_port_bits: usize,
        has_tci: bool,
        cbgti_bits: usize,
        has_cbgfi: bool,
    ) -> Result<Self, DciError> {
        let carrier_indicator = if has_carrier {
            Some(reader.read_bits(3)? as u8)
        } else {
            None
        };
        let dci_format_flag = reader.read_bits(1)? as u8;
        let bwp_indicator = if has_bwp {
            reader.read_bits(2)? as u8
        } else {
            0
        };
        let fdra = if fdra_type {
            let riv = reader.read_bits(fdra_bits)? as u32;
            FdResourceAllocation::Type1Riv {
                riv,
                num_bits: fdra_bits,
            }
        } else {
            let bitmap = reader.read_bits(fdra_bits)? as u32;
            FdResourceAllocation::Type0Bitmap {
                bitmap,
                num_bits: fdra_bits,
            }
        };
        let tdra = reader.read_bits(4)? as u8;
        let vrb_to_prb_mapping = reader.read_bits(1)? as u8;
        let prb_bundling_indicator = if has_bundling {
            Some(reader.read_bits(1)? as u8)
        } else {
            None
        };
        let rate_matching_indicator = if has_rm {
            Some(reader.read_bits(2)? as u8)
        } else {
            None
        };
        let zp_csi_rs_trigger = if has_zp {
            Some(reader.read_bits(2)? as u8)
        } else {
            None
        };
        let mcs = reader.read_bits(5)? as u8;
        let ndi = reader.read_bits(1)? as u8;
        let rv = reader.read_bits(2)? as u8;
        let harq_pid = reader.read_bits(4)? as u8;
        let dai = reader.read_bits(2)? as u8;
        let tpc_pucch = reader.read_bits(2)? as u8;
        let pucch_resource_indicator = reader.read_bits(3)? as u8;
        let pdsch_to_harq_timing = reader.read_bits(3)? as u8;
        let antenna_ports = reader.read_bits(antenna_port_bits)? as u8;
        let tci_state = if has_tci {
            Some(reader.read_bits(3)? as u8)
        } else {
            None
        };
        let srs_request = reader.read_bits(2)? as u8;
        let cbgti = if cbgti_bits > 0 {
            Some(reader.read_bits(cbgti_bits)? as u8)
        } else {
            None
        };
        let cbgfi = if has_cbgfi {
            Some(reader.read_bits(1)? as u8)
        } else {
            None
        };

        Ok(Self {
            carrier_indicator,
            dci_format_flag,
            bwp_indicator,
            fdra,
            tdra,
            vrb_to_prb_mapping,
            prb_bundling_indicator,
            rate_matching_indicator,
            zp_csi_rs_trigger,
            mcs,
            ndi,
            rv,
            harq_pid,
            dai,
            tpc_pucch,
            pucch_resource_indicator,
            pdsch_to_harq_timing,
            antenna_ports,
            antenna_port_bits,
            tci_state,
            srs_request,
            cbgti,
            cbgti_bits,
            cbgfi,
        })
    }
}

/// DCI Format 2_0: Dynamic Slot Format Indication (TS 38.212 §7.3.1.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DciFormat2_0 {
    pub slot_format_indicators: Vec<(u16, usize)>,
}

impl DciFormat2_0 {
    pub fn serialize(&self) -> Result<BitWriter, DciError> {
        let mut writer = BitWriter::new();
        for &(combo, width) in &self.slot_format_indicators {
            writer.push_bits(combo as u64, width);
        }
        Ok(writer)
    }

    pub fn deserialize(
        reader: &mut BitReader<'_>,
        field_widths: &[usize],
    ) -> Result<Self, DciError> {
        let mut indicators = Vec::with_capacity(field_widths.len());
        for &w in field_widths {
            let combo = reader.read_bits(w)? as u16;
            indicators.push((combo, w));
        }
        Ok(Self {
            slot_format_indicators: indicators,
        })
    }
}

/// DCI Format 2_1: Pre-emption Indication / INT-RNTI (TS 38.212 §7.3.1.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DciFormat2_1 {
    pub preemption_indications: Vec<u16>,
}

impl DciFormat2_1 {
    pub const BITS_PER_INT: usize = 14;

    pub fn serialize(&self) -> Result<BitWriter, DciError> {
        let mut writer = BitWriter::new();
        for &int_bitmap in &self.preemption_indications {
            writer.push_bits(int_bitmap as u64, Self::BITS_PER_INT);
        }
        Ok(writer)
    }

    pub fn deserialize(
        reader: &mut BitReader<'_>,
        num_serving_cells: usize,
    ) -> Result<Self, DciError> {
        let mut indications = Vec::with_capacity(num_serving_cells);
        for _ in 0..num_serving_cells {
            let bmp = reader.read_bits(Self::BITS_PER_INT)? as u16;
            indications.push(bmp);
        }
        Ok(Self {
            preemption_indications: indications,
        })
    }
}

/// DCI Format 2_4: Uplink Cancellation Indication / CI-RNTI (TS 38.212 §7.3.1.3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DciFormat2_4 {
    pub cancellation_indications: Vec<(u32, usize)>,
}

impl DciFormat2_4 {
    pub fn serialize(&self) -> Result<BitWriter, DciError> {
        let mut writer = BitWriter::new();
        for &(ci, width) in &self.cancellation_indications {
            writer.push_bits(ci as u64, width);
        }
        Ok(writer)
    }

    pub fn deserialize(
        reader: &mut BitReader<'_>,
        field_widths: &[usize],
    ) -> Result<Self, DciError> {
        let mut indications = Vec::with_capacity(field_widths.len());
        for &w in field_widths {
            let val = reader.read_bits(w)? as u32;
            indications.push((val, w));
        }
        Ok(Self {
            cancellation_indications: indications,
        })
    }
}

// ---------------------------------------------------------------------------
// DCI Size Alignment & Zero-Padding Rules (TS 38.212 §7.3.1.0)
// ---------------------------------------------------------------------------

/// Applies 3GPP size alignment rules between DCI format 0_0 and 1_0:
/// 1. Appends zeros to DCI 0_0 if its size is less than DCI 1_0.
/// 2. If the payload size equals one of the forbidden/ambiguous sizes (12, 16, 20, 24, 26, 32, 40, 44, 56),
///    appends one additional zero bit.
pub fn align_dci_0_0_and_1_0(
    writer_0_0: &mut BitWriter,
    writer_1_0: &mut BitWriter,
) {
    let len_0_0 = writer_0_0.len();
    let len_1_0 = writer_1_0.len();

    if len_0_0 < len_1_0 {
        writer_0_0.pad_zeros(len_1_0 - len_0_0);
    } else if len_1_0 < len_0_0 {
        writer_1_0.pad_zeros(len_0_0 - len_1_0);
    }

    let common_len = writer_0_0.len();
    if is_forbidden_dci_size(common_len) {
        writer_0_0.pad_zeros(1);
        writer_1_0.pad_zeros(1);
    }
}

/// Checks if a payload bit length matches a 3GPP ambiguous size.
pub fn is_forbidden_dci_size(size_bits: usize) -> bool {
    FORBIDDEN_DCI_SIZES.contains(&size_bits)
}

/// Pads a DCI bitwriter if its size matches any forbidden size.
pub fn avoid_forbidden_size(writer: &mut BitWriter) {
    if is_forbidden_dci_size(writer.len()) {
        writer.pad_zeros(1);
    }
}

// ---------------------------------------------------------------------------
// 3GPP RNTI Types & Parity Scrambling (TS 38.212 §7.3.2)
// ---------------------------------------------------------------------------

/// 3GPP RNTI Types for DCI control plane scrambling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RntiType {
    CRnti(u16),
    CsRnti(u16),
    McsCRnti(u16),
    TcRnti(u16),
    RaRnti(u16),
    PRnti,
    SiRnti,
    SfiRnti(u16),
    IntRnti(u16),
    CiRnti(u16),
    TpcPuschRnti(u16),
    TpcPucchRnti(u16),
}

impl RntiType {
    pub fn value(&self) -> u16 {
        match self {
            Self::CRnti(r)
            | Self::CsRnti(r)
            | Self::McsCRnti(r)
            | Self::TcRnti(r)
            | Self::RaRnti(r)
            | Self::SfiRnti(r)
            | Self::IntRnti(r)
            | Self::CiRnti(r)
            | Self::TpcPuschRnti(r)
            | Self::TpcPucchRnti(r) => *r,
            Self::PRnti => 0xFFFE,
            Self::SiRnti => 0xFFFF,
        }
    }
}

// ---------------------------------------------------------------------------
// CRC-24C & Scrambling Engine (TS 38.212 §5.1 / §7.3.2)
// ---------------------------------------------------------------------------

/// Computes 24-bit CRC24C over bit vector (values 0 or 1) with polynomial `0xB2B117`.
pub fn compute_crc24c(bits: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &b in bits {
        let msb = ((crc >> 23) ^ (b as u32)) & 1;
        crc = (crc << 1) & 0xFFFFFF;
        if msb != 0 {
            crc ^= CRC24C_POLY;
        }
    }
    crc & 0xFFFFFF
}

/// Attaches CRC-24C and scrambles the last 16 parity bits with the 16-bit RNTI (TS 38.212 §7.3.2).
pub fn attach_crc24c_and_scramble_rnti(payload_bits: &[u8], rnti: u16) -> Vec<u8> {
    let crc = compute_crc24c(payload_bits);
    let mut out = Vec::with_capacity(payload_bits.len() + 24);
    out.extend_from_slice(payload_bits);

    // First 8 parity bits (p_0..p_7) are NOT scrambled
    for i in (16..24).rev() {
        out.push(((crc >> i) & 1) as u8);
    }
    // Last 16 parity bits (p_8..p_23) are scrambled with r_0..r_15
    for i in (0..16).rev() {
        let p_bit = ((crc >> i) & 1) as u8;
        let r_bit = ((rnti >> i) & 1) as u8;
        out.push(p_bit ^ r_bit);
    }

    out
}

/// Verifies CRC-24C against a specified RNTI on a received $(K + 24)$-bit block.
pub fn verify_crc24c_with_rnti(received_bits: &[u8], rnti: u16) -> Result<Vec<u8>, DciError> {
    if received_bits.len() < 24 {
        return Err(DciError::WirePayloadTooShort {
            needed: 24,
            found: received_bits.len(),
        });
    }
    let k = received_bits.len() - 24;
    let payload = &received_bits[..k];
    let computed_crc = compute_crc24c(payload);

    let mut extracted_crc = 0u32;
    for i in 0..8 {
        let b = received_bits[k + i] as u32;
        extracted_crc = (extracted_crc << 1) | b;
    }
    for i in 0..16 {
        let masked_b = received_bits[k + 8 + i] as u32;
        let r_bit = ((rnti >> (15 - i)) & 1) as u32;
        let unmasked_b = masked_b ^ r_bit;
        extracted_crc = (extracted_crc << 1) | unmasked_b;
    }

    if extracted_crc != computed_crc {
        return Err(DciError::CrcMismatch {
            expected: computed_crc,
            computed: extracted_crc,
        });
    }

    Ok(payload.to_vec())
}

/// Performs blind RNTI extraction by XORing calculated CRC24C parity bits [8..24]
/// with the received parity bits [8..24].
pub fn extract_scrambled_rnti(received_bits: &[u8]) -> Result<u16, DciError> {
    if received_bits.len() < 24 {
        return Err(DciError::WirePayloadTooShort {
            needed: 24,
            found: received_bits.len(),
        });
    }
    let k = received_bits.len() - 24;
    let payload = &received_bits[..k];
    let computed_crc = compute_crc24c(payload);

    let computed_top8 = (computed_crc >> 16) as u8;
    let mut rx_top8 = 0u8;
    for i in 0..8 {
        rx_top8 = (rx_top8 << 1) | received_bits[k + i];
    }
    if computed_top8 != rx_top8 {
        return Err(DciError::CrcMismatch {
            expected: computed_top8 as u32,
            computed: rx_top8 as u32,
        });
    }

    let mut recovered_rnti = 0u16;
    for i in 0..16 {
        let calc_bit = ((computed_crc >> (15 - i)) & 1) as u8;
        let rx_bit = received_bits[k + 8 + i];
        let r_bit = calc_bit ^ rx_bit;
        recovered_rnti = (recovered_rnti << 1) | (r_bit as u16);
    }

    Ok(recovered_rnti)
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
// Binary Wire Framing (`DciWirePdu`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DciWireFormatType {
    Format0_0 = 0x00,
    Format0_1 = 0x01,
    Format1_0 = 0x10,
    Format1_1 = 0x11,
    Format2_0 = 0x20,
    Format2_1 = 0x21,
    Format2_4 = 0x24,
    RawCustom = 0xFF,
}

impl DciWireFormatType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::Format0_0,
            0x01 => Self::Format0_1,
            0x10 => Self::Format1_0,
            0x11 => Self::Format1_1,
            0x20 => Self::Format2_0,
            0x21 => Self::Format2_1,
            0x24 => Self::Format2_4,
            _ => Self::RawCustom,
        }
    }
}

/// DCI Wire Protocol Data Unit for cross-layer transport and serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DciWirePdu {
    pub format_type: DciWireFormatType,
    pub rnti: u16,
    pub bit_length: u16,
    pub payload_bytes: Vec<u8>,
}

impl DciWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.payload_bytes.len());
        buf.extend_from_slice(&DCI_WIRE_MAGIC.to_be_bytes());
        buf.push(self.format_type as u8);
        buf.push(0x00); // Reserved
        buf.extend_from_slice(&self.rnti.to_be_bytes());
        buf.extend_from_slice(&self.bit_length.to_be_bytes());
        buf.extend_from_slice(&(self.payload_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload_bytes);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, DciError> {
        if bytes.len() < 14 {
            return Err(DciError::WirePayloadTooShort {
                needed: 14,
                found: bytes.len(),
            });
        }
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != DCI_WIRE_MAGIC {
            return Err(DciError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(DciError::CrcMismatch {
                expected: expected_crc as u32,
                computed: computed_crc as u32,
            });
        }

        let format_type = DciWireFormatType::from_u8(bytes[4]);
        let rnti = u16::from_be_bytes([bytes[6], bytes[7]]);
        let bit_length = u16::from_be_bytes([bytes[8], bytes[9]]);
        let payload_len = u16::from_be_bytes([bytes[10], bytes[11]]) as usize;

        if body_len < 12 + payload_len {
            return Err(DciError::WirePayloadTooShort {
                needed: 12 + payload_len,
                found: body_len,
            });
        }

        let payload_bytes = bytes[12..12 + payload_len].to_vec();

        Ok(Self {
            format_type,
            rnti,
            bit_length,
            payload_bytes,
        })
    }
}

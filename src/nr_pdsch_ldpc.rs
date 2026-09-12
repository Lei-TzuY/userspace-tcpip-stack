//! 3GPP Release 18/19 5G-Advanced PDSCH LDPC Segmentation, Rate Matching
//! & Code Block Group (CBG) Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.212 Rel-18 §5.1: CRC calculation (CRC24A, CRC24B, CRC16).
//! - 3GPP TS 38.212 Rel-18 §5.2.2: Code block segmentation and code block CRC attachment.
//! - 3GPP TS 38.212 Rel-18 §5.3.2: LDPC base graph selection (BG1 / BG2) and lifting size ($Z_c$) determination.
//! - 3GPP TS 38.212 Rel-18 §5.4.2: Circular buffer rate matching and bit selection ($RV \in \{0, 2, 3, 1\}$).
//! - 3GPP TS 38.214 Rel-18 §5.1.7: Code Block Group (CBG)-based transmission and partial retransmission.
//!
//! Features:
//! 1. Bit-level CRC24A, CRC24B, and CRC16 algorithms.
//! 2. LDPC Base Graph selection criteria (BG1 max 8448 bits vs BG2 max 3840 bits).
//! 3. Standard 51-element lifting size $Z_c$ selection ($Z_c = a \cdot 2^j$).
//! 4. Sub-block circular buffer rate matching with exact 3GPP $k_0$ offsets per Redundancy Version.
//! 5. Code Block Group (CBG) dynamic partitioning ($M_{\text{CBG}} \in \{2, 4, 6, 8\}$) and selective retransmission savings.
//! 6. Binary wire framing (`LdpcPdschPdu`) with magic `0x4C445043` ("LDPC") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for PDSCH LDPC PDU: "LDPC" (0x4C445043).
pub const PDSCH_LDPC_WIRE_MAGIC: u32 = 0x4C445043;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// CRC24A generator polynomial: D^24 + D^23 + D^18 + D^17 + D^14 + D^11 + D^10 + D^7 + D^6 + D^5 + D^4 + D^3 + D + 1
pub const CRC24A_POLY: u32 = 0x864CFB;

/// CRC24B generator polynomial: D^24 + D^23 + D^6 + D^5 + D + 1
pub const CRC24B_POLY: u32 = 0x800063;

/// Maximum code block size for LDPC Base Graph 1.
pub const MAX_CB_SIZE_BG1: usize = 8448;

/// Maximum code block size for LDPC Base Graph 2.
pub const MAX_CB_SIZE_BG2: usize = 3840;

/// Transport Block size threshold for 24-bit vs 16-bit TB CRC (TS 38.212 §7.2.1).
pub const TB_CRC_THRESHOLD_BITS: usize = 3824;

/// 51 standardized LDPC lifting sizes $Z_c$ per 3GPP TS 38.212 Table 5.3.2-1.
pub const LDPC_LIFTING_SIZES: [usize; 51] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 26, 28, 30, 32, 36, 40, 44,
    48, 52, 56, 60, 64, 72, 80, 88, 96, 104, 112, 120, 128, 144, 160, 176, 192, 208, 224, 240, 256,
    288, 320, 352, 384,
];

/// Errors encountered in PDSCH LDPC processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdpcError {
    EmptyPayload,
    InvalidCodeRate(String),
    LiftingSizeNotFound(usize),
    InvalidRedundancyVersion(u8),
    InvalidCbgCount(usize),
    SerializationError(String),
    DeserializationError(String),
    CrcMismatch { expected: u16, actual: u16 },
    InvalidMagic(u32),
}

impl fmt::Display for LdpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => write!(f, "Payload cannot be empty"),
            Self::InvalidCodeRate(msg) => write!(f, "Invalid code rate: {}", msg),
            Self::LiftingSizeNotFound(k) => {
                write!(f, "No valid lifting size Z_c found for block size {}", k)
            }
            Self::InvalidRedundancyVersion(rv) => write!(
                f,
                "Invalid Redundancy Version {} (must be 0, 1, 2, or 3)",
                rv
            ),
            Self::InvalidCbgCount(cbg) => {
                write!(f, "Invalid CBG count {} (must be 2, 4, 6, or 8)", cbg)
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
            Self::InvalidMagic(m) => write!(f, "Invalid magic: 0x{:08X}", m),
        }
    }
}

// ---------------------------------------------------------------------------
// CRC Routines (TS 38.212 §5.1)
// ---------------------------------------------------------------------------

/// Computes 24-bit CRC24A over bit slice (0 and 1 values).
pub fn compute_crc24a(bits: &[u8]) -> u32 {
    let mut crc: u32 = 0;
    for &b in bits {
        let bit = (b & 1) as u32;
        let msb = (crc >> 23) & 1;
        crc = ((crc << 1) | bit) & 0x00FF_FFFF;
        if msb == 1 {
            crc ^= CRC24A_POLY;
        }
    }
    // Append 24 zeros
    for _ in 0..24 {
        let msb = (crc >> 23) & 1;
        crc = (crc << 1) & 0x00FF_FFFF;
        if msb == 1 {
            crc ^= CRC24A_POLY;
        }
    }
    crc
}

/// Computes 24-bit CRC24B over bit slice.
pub fn compute_crc24b(bits: &[u8]) -> u32 {
    let mut crc: u32 = 0;
    for &b in bits {
        let bit = (b & 1) as u32;
        let msb = (crc >> 23) & 1;
        crc = ((crc << 1) | bit) & 0x00FF_FFFF;
        if msb == 1 {
            crc ^= CRC24B_POLY;
        }
    }
    for _ in 0..24 {
        let msb = (crc >> 23) & 1;
        crc = (crc << 1) & 0x00FF_FFFF;
        if msb == 1 {
            crc ^= CRC24B_POLY;
        }
    }
    crc
}

/// Computes 16-bit CRC over bit slice.
pub fn compute_crc16_bits(bits: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bits {
        let bit = (b & 1) as u16;
        let msb = (crc >> 15) & 1;
        crc = (crc << 1) | bit;
        if msb == 1 {
            crc ^= CRC16_CCITT_POLY;
        }
    }
    for _ in 0..16 {
        let msb = (crc >> 15) & 1;
        crc <<= 1;
        if msb == 1 {
            crc ^= CRC16_CCITT_POLY;
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// LDPC Base Graph Selection (TS 38.212 §7.2.2)
// ---------------------------------------------------------------------------

/// LDPC Base Graph type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdpcBaseGraph {
    /// Base Graph 1: High throughput, up to 8448 bits per code block.
    BG1,
    /// Base Graph 2: Low code rate / small transport blocks, up to 3840 bits per code block.
    BG2,
}

impl LdpcBaseGraph {
    #[inline]
    pub fn max_code_block_size(self) -> usize {
        match self {
            Self::BG1 => MAX_CB_SIZE_BG1,
            Self::BG2 => MAX_CB_SIZE_BG2,
        }
    }

    #[inline]
    pub fn kb(self, total_bits_b: usize) -> usize {
        match self {
            Self::BG1 => 22,
            Self::BG2 => {
                if total_bits_b > 640 {
                    10
                } else if total_bits_b > 560 {
                    9
                } else if total_bits_b > 192 {
                    8
                } else {
                    6
                }
            }
        }
    }

    #[inline]
    pub fn total_coded_columns(self) -> usize {
        match self {
            Self::BG1 => 66,
            Self::BG2 => 50,
        }
    }
}

/// Selects LDPC Base Graph per 3GPP TS 38.212 §7.2.2 criteria.
pub fn select_base_graph(tb_size_bits: usize, code_rate: f64) -> Result<LdpcBaseGraph, LdpcError> {
    if tb_size_bits == 0 {
        return Err(LdpcError::EmptyPayload);
    }
    if code_rate <= 0.0 || code_rate > 1.0 {
        return Err(LdpcError::InvalidCodeRate(format!("{}", code_rate)));
    }

    // 3GPP TS 38.212 Section 7.2.2 rules:
    // If A <= 292, or (A <= 3824 and R <= 0.67), or R <= 0.25 -> BG2
    // Otherwise -> BG1
    if tb_size_bits <= 292
        || (tb_size_bits <= TB_CRC_THRESHOLD_BITS && code_rate <= 0.67)
        || code_rate <= 0.25
    {
        Ok(LdpcBaseGraph::BG2)
    } else {
        Ok(LdpcBaseGraph::BG1)
    }
}

// ---------------------------------------------------------------------------
// Lifting Size $Z_c$ Selection (TS 38.212 §5.3.2)
// ---------------------------------------------------------------------------

/// Finds the minimum lifting size $Z_c \in \text{LDPC\_LIFTING\_SIZES}$ satisfying $K_b \cdot Z_c \ge K'$.
pub fn find_lifting_size(kb: usize, k_prime: usize) -> Result<usize, LdpcError> {
    for &zc in &LDPC_LIFTING_SIZES {
        if kb * zc >= k_prime {
            return Ok(zc);
        }
    }
    Err(LdpcError::LiftingSizeNotFound(k_prime))
}

// ---------------------------------------------------------------------------
// Code Block Segmentation (TS 38.212 §5.2.2)
// ---------------------------------------------------------------------------

/// Result of Code Block Segmentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBlockSegmentation {
    pub base_graph: LdpcBaseGraph,
    pub num_code_blocks: usize,
    pub tb_crc_length: usize,
    pub cb_crc_length: usize,
    pub k_prime: usize,
    pub z_c: usize,
    pub k_b: usize,
    pub k_info_bits: usize,
    pub filler_bits: usize,
}

/// Evaluates Code Block Segmentation parameters for a Transport Block of size $A$ bits.
pub fn segment_transport_block(
    tb_size_bits_a: usize,
    code_rate: f64,
) -> Result<CodeBlockSegmentation, LdpcError> {
    let bg = select_base_graph(tb_size_bits_a, code_rate)?;

    // Step 1: Transport block CRC attachment
    let tb_crc_len = if tb_size_bits_a > TB_CRC_THRESHOLD_BITS {
        24 // CRC24A
    } else {
        16 // CRC16
    };
    let b = tb_size_bits_a + tb_crc_len;

    // Step 2: Code block segmentation
    let k_cb = bg.max_code_block_size();
    let (c, cb_crc_len, b_prime) = if b <= k_cb {
        (1, 0, b)
    } else {
        let l_cb = 24; // CRC24B
        let c = (b + k_cb - l_cb - 1) / (k_cb - l_cb);
        let b_prime = b + c * l_cb;
        (c, l_cb, b_prime)
    };

    let k_prime = b_prime / c;
    let k_b = bg.kb(b);
    let z_c = find_lifting_size(k_b, k_prime)?;
    let k_info = k_b * z_c;
    let filler = k_info.saturating_sub(k_prime);

    Ok(CodeBlockSegmentation {
        base_graph: bg,
        num_code_blocks: c,
        tb_crc_length: tb_crc_len,
        cb_crc_length: cb_crc_len,
        k_prime,
        z_c,
        k_b,
        k_info_bits: k_info,
        filler_bits: filler,
    })
}

// ---------------------------------------------------------------------------
// Circular Buffer Rate Matching (TS 38.212 §5.4.2)
// ---------------------------------------------------------------------------

/// Computes starting position $k_0$ in circular buffer for given Redundancy Version (TS 38.212 §5.4.2.1).
pub fn compute_k0(
    bg: LdpcBaseGraph,
    z_c: usize,
    n_cb: usize,
    redundancy_version: u8,
) -> Result<usize, LdpcError> {
    match bg {
        LdpcBaseGraph::BG1 => {
            let total_cols = 66.0;
            let ratio = match redundancy_version {
                0 => 0.0,
                1 => 56.0,
                2 => 17.0,
                3 => 33.0,
                _ => return Err(LdpcError::InvalidRedundancyVersion(redundancy_version)),
            };
            let k0 = ((ratio * (n_cb as f64)) / (total_cols * (z_c as f64))).floor() as usize * z_c;
            Ok(k0)
        }
        LdpcBaseGraph::BG2 => {
            let total_cols = 50.0;
            let ratio = match redundancy_version {
                0 => 0.0,
                1 => 43.0,
                2 => 13.0,
                3 => 25.0,
                _ => return Err(LdpcError::InvalidRedundancyVersion(redundancy_version)),
            };
            let k0 = ((ratio * (n_cb as f64)) / (total_cols * (z_c as f64))).floor() as usize * z_c;
            Ok(k0)
        }
    }
}

/// Performs rate matching bit extraction of length $E_r$ from circular buffer.
/// Skips filler bits ($<NULL>$) inserted during code block segmentation.
pub fn rate_match_extract(
    circular_buffer: &[u8],
    k0: usize,
    output_length_e: usize,
    filler_bit_indices: &[usize],
) -> Vec<u8> {
    let n_cb = circular_buffer.len();
    if n_cb == 0 || output_length_e == 0 {
        return Vec::new();
    }

    let mut output = Vec::with_capacity(output_length_e);
    let mut curr_idx = k0 % n_cb;

    while output.len() < output_length_e {
        if !filler_bit_indices.contains(&curr_idx) {
            output.push(circular_buffer[curr_idx]);
        }
        curr_idx = (curr_idx + 1) % n_cb;
    }

    output
}

// ---------------------------------------------------------------------------
// Code Block Group (CBG) Partitioning & Retransmission (TS 38.214 §5.1.7)
// ---------------------------------------------------------------------------

/// Manages Code Block Groups (CBGs) and computes retransmission savings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbgManager {
    pub max_cbgs_per_tb: usize,
}

impl CbgManager {
    pub fn new(max_cbgs_per_tb: usize) -> Result<Self, LdpcError> {
        if !matches!(max_cbgs_per_tb, 2 | 4 | 6 | 8) {
            return Err(LdpcError::InvalidCbgCount(max_cbgs_per_tb));
        }
        Ok(Self { max_cbgs_per_tb })
    }

    /// Partitions $C$ code blocks into $M_{\text{CBG}}$ groups.
    /// Returns vector mapping CBG index $g \to$ list of code block indices.
    pub fn partition_cbgs(&self, num_code_blocks: usize) -> Vec<Vec<usize>> {
        if num_code_blocks == 0 {
            return Vec::new();
        }

        let m = self.max_cbgs_per_tb;
        let num_cbgs = num_code_blocks.min(m);
        let mut cbgs = vec![Vec::new(); num_cbgs];

        if num_code_blocks <= m {
            for i in 0..num_code_blocks {
                cbgs[i].push(i);
            }
        } else {
            // TS 38.214 §5.1.7.1: First R_c = C mod M groups have floor(C/M) + 1 code blocks
            let r_c = num_code_blocks % m;
            let base_cbs = num_code_blocks / m;
            let mut cb_idx = 0;

            for g in 0..m {
                let count = if g < r_c { base_cbs + 1 } else { base_cbs };
                for _ in 0..count {
                    cbgs[g].push(cb_idx);
                    cb_idx += 1;
                }
            }
        }

        cbgs
    }

    /// Evaluates partial retransmission savings given per-code-block error status.
    /// Returns `(failed_cbg_indices, retransmitted_code_blocks, resource_savings_ratio)`.
    pub fn evaluate_retransmission(
        &self,
        num_code_blocks: usize,
        cb_errors: &[bool], // true = corrupted, false = OK
    ) -> (Vec<usize>, usize, f64) {
        let partitions = self.partition_cbgs(num_code_blocks);
        let mut failed_cbgs = Vec::new();
        let mut retransmitted_cbs = 0;

        for (g_idx, cbs) in partitions.iter().enumerate() {
            let has_error = cbs.iter().any(|&cb| cb < cb_errors.len() && cb_errors[cb]);
            if has_error {
                failed_cbgs.push(g_idx);
                retransmitted_cbs += cbs.len();
            }
        }

        let savings = if num_code_blocks > 0 {
            1.0 - ((retransmitted_cbs as f64) / (num_code_blocks as f64))
        } else {
            0.0
        };

        (failed_cbgs, retransmitted_cbs, savings)
    }
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

/// Binary wire framing carrying PDSCH LDPC segmentation and CBG telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdpcPdschPdu {
    pub version: u8,
    pub tb_size_bytes: u32,
    pub base_graph: u8, // 1 = BG1, 2 = BG2
    pub num_code_blocks: u16,
    pub z_c: u16,
    pub filler_bits: u16,
    pub redundancy_version: u8,
    pub cbg_count: u8,
    pub failed_cbg_mask: u8,
    pub savings_percent: u8,
}

impl LdpcPdschPdu {
    pub const WIRE_SIZE: usize = 4 + 1 + 4 + 1 + 2 + 2 + 2 + 1 + 1 + 1 + 1 + 2; // 22 bytes

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&PDSCH_LDPC_WIRE_MAGIC.to_be_bytes());
        buf.push(self.version);
        buf.extend_from_slice(&self.tb_size_bytes.to_be_bytes());
        buf.push(self.base_graph);
        buf.extend_from_slice(&self.num_code_blocks.to_be_bytes());
        buf.extend_from_slice(&self.z_c.to_be_bytes());
        buf.extend_from_slice(&self.filler_bits.to_be_bytes());
        buf.push(self.redundancy_version);
        buf.push(self.cbg_count);
        buf.push(self.failed_cbg_mask);
        buf.push(self.savings_percent);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LdpcError> {
        if bytes.len() < Self::WIRE_SIZE {
            return Err(LdpcError::DeserializationError(format!(
                "PDU length {} is less than required {}",
                bytes.len(),
                Self::WIRE_SIZE
            )));
        }

        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != PDSCH_LDPC_WIRE_MAGIC {
            return Err(LdpcError::InvalidMagic(magic));
        }

        let payload_len = Self::WIRE_SIZE - 2;
        let expected_crc = compute_crc16(&bytes[..payload_len]);
        let actual_crc = u16::from_be_bytes([bytes[payload_len], bytes[payload_len + 1]]);
        if expected_crc != actual_crc {
            return Err(LdpcError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        let version = bytes[4];
        let tb_size_bytes = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        let base_graph = bytes[9];
        let num_code_blocks = u16::from_be_bytes([bytes[10], bytes[11]]);
        let z_c = u16::from_be_bytes([bytes[12], bytes[13]]);
        let filler_bits = u16::from_be_bytes([bytes[14], bytes[15]]);
        let redundancy_version = bytes[16];
        let cbg_count = bytes[17];
        let failed_cbg_mask = bytes[18];
        let savings_percent = bytes[19];

        Ok(Self {
            version,
            tb_size_bytes,
            base_graph,
            num_code_blocks,
            z_c,
            filler_bits,
            redundancy_version,
            cbg_count,
            failed_cbg_mask,
            savings_percent,
        })
    }
}

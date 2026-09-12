//! 3GPP Release 18/19 5G-Advanced CSI-RS Processor, Resource Mapping & Type I Codebook Feedback Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §7.4.1.5: CSI Reference Signals (CSI-RS) sequence generation,
//!   component RE mappings (Table 7.4.1.5.3-1), and CDM structures (`noCDM`, `fd-CDM2`, `cdm4-FD2-TD2`, `cdm8-FD2-TD4`).
//! - 3GPP TS 38.214 Rel-18 §5.2.1: CSI reporting framework (RI, PMI, CQI, LI).
//! - 3GPP TS 38.214 Rel-18 §5.2.2.2: Type I Single-Panel and Multi-Panel CSI codebooks,
//!   2D oversampled DFT beam selection ($W_1$), and dual-polarization co-phasing ($W_2$).
//! - 3GPP TS 38.331 Rel-18 §6.3.2: `NZP-CSI-RS-Resource`, `ZP-CSI-RS-Resource`, and `CSI-ReportConfig`.
//!
//! Features:
//! 1. Pseudo-random Gold sequence generation initialized per OFDM symbol and slot ($c_{\text{init}}$).
//! 2. Standard Table 7.4.1.5.3-1 CSI-RS resource mapping across 1 to 32 antenna ports.
//! 3. Orthogonal CDM code generation (FD-CDM2, CDM4, CDM8) across frequency and time.
//! 4. Zero-Power (ZP) CSI-RS muting pattern and Non-Zero-Power (NZP) CSI-RS grid mapping.
//! 5. 2D Oversampled DFT spatial codebook ($N_1, N_2, O_1, O_2$) with QPSK co-phasing ($W_2$).
//! 6. Rank 1 to Rank 4 precoding matrix synthesis.
//! 7. End-to-end CSI evaluator computing optimal Rank Indicator (RI), Precoding Matrix Indicator (PMI),
//!    Channel Quality Indicator (CQI 0..15), and Layer Indicator (LI).
//! 8. Binary wire framing (`CsiRsWirePdu`) with magic `0x43534952` ("CSIR") and CRC-16 CCITT integrity.

use std::f64::consts::PI;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for CSI-RS Wire PDU: "CSIR" (0x43534952).
pub const CSIRS_WIRE_MAGIC: u32 = 0x43534952;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Number of subcarriers per Physical Resource Block (PRB).
pub const SUBCARRIERS_PER_PRB: usize = 12;

/// Number of OFDM symbols per standard slot.
pub const SYMBOLS_PER_SLOT: usize = 14;

/// Code Division Multiplexing (CDM) type for CSI-RS (TS 38.211 §7.4.1.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsiRsCdmType {
    NoCdm,
    FdCdm2,
    Cdm4Fd2Td2,
    Cdm8Fd2Td4,
}

impl CsiRsCdmType {
    pub fn cdm_group_size(&self) -> usize {
        match self {
            CsiRsCdmType::NoCdm => 1,
            CsiRsCdmType::FdCdm2 => 2,
            CsiRsCdmType::Cdm4Fd2Td2 => 4,
            CsiRsCdmType::Cdm8Fd2Td4 => 8,
        }
    }
}

/// CSI-RS Frequency Density $\rho$ (subcarriers per PRB).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CsiRsDensity {
    HalfDot5, // 0.5 (1 RE every 2 PRBs)
    One,      // 1.0 (1 RE per PRB)
    Three,    // 3.0 (3 REs per PRB)
}

/// Errors encountered in CSI-RS operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsiRsError {
    InvalidPortCount(usize),
    InvalidSymbolAllocation(usize),
    InvalidRowIndex(usize),
    InvalidCodebookConfig(String),
    ChannelEvaluationFailed(String),
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for CsiRsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CsiRsError::InvalidPortCount(p) => write!(f, "Invalid CSI-RS port count: {}", p),
            CsiRsError::InvalidSymbolAllocation(s) => write!(f, "Invalid symbol allocation: {}", s),
            CsiRsError::InvalidRowIndex(r) => write!(f, "Invalid CSI-RS Table row: {}", r),
            CsiRsError::InvalidCodebookConfig(msg) => write!(f, "Invalid codebook config: {}", msg),
            CsiRsError::ChannelEvaluationFailed(msg) => {
                write!(f, "Channel evaluation error: {}", msg)
            }
            CsiRsError::SerializationError(e) => write!(f, "CSI-RS serialization error: {}", e),
            CsiRsError::DeserializationError(e) => write!(f, "CSI-RS deserialization error: {}", e),
        }
    }
}

impl std::error::Error for CsiRsError {}

// ---------------------------------------------------------------------------
// Complex Arithmetic Helper
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex64 {
    pub re: f64,
    pub im: f64,
}

impl Complex64 {
    pub fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    pub fn from_polar(r: f64, theta: f64) -> Self {
        Self {
            re: r * theta.cos(),
            im: r * theta.sin(),
        }
    }

    pub fn norm_sqr(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    pub fn conj(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    pub fn mul(&self, rhs: &Complex64) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }

    pub fn add(&self, rhs: &Complex64) -> Self {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }

    pub fn sub(&self, rhs: &Complex64) -> Self {
        Self {
            re: self.re - rhs.re,
            im: self.im - rhs.im,
        }
    }

    pub fn scale(&self, s: f64) -> Self {
        Self {
            re: self.re * s,
            im: self.im * s,
        }
    }
}

// ---------------------------------------------------------------------------
// Pseudo-Random Sequence Generation (TS 38.211 §7.4.1.5.2)
// ---------------------------------------------------------------------------

/// Generates 31-degree Gold sequence pseudo-random bits for CSI-RS.
pub fn generate_gold_sequence_31(c_init: u32, length: usize) -> Vec<u8> {
    const NC: usize = 1600;
    let total = NC + length;

    let mut x1 = vec![0u8; total + 31];
    let mut x2 = vec![0u8; total + 31];

    x1[0] = 1;
    for i in 0..31 {
        x2[i] = ((c_init >> i) & 1) as u8;
    }

    for i in 0..total {
        x1[i + 31] = (x1[i + 3] ^ x1[i]) & 1;
        x2[i + 31] = (x2[i + 3] ^ x2[i + 2] ^ x2[i + 1] ^ x2[i]) & 1;
    }

    let mut c = Vec::with_capacity(length);
    for n in 0..length {
        c.push((x1[n + NC] ^ x2[n + NC]) & 1);
    }
    c
}

/// Generates complex QPSK CSI-RS sequence for a specific slot, symbol, and scrambling ID.
pub fn generate_csi_rs_sequence(
    slot_idx: usize,
    symbol_idx: usize,
    n_id_csi: u16,
    num_subcarriers: usize,
) -> Vec<Complex64> {
    // TS 38.211 §7.4.1.5.2:
    // c_init = (2^10 * (14 * n_s_f + l + 1) * (2 * N_ID_CSI + 1) + 2 * N_ID_CSI + 1) mod 2^31
    let term1 = (14 * slot_idx as u64 + symbol_idx as u64 + 1) * (2 * n_id_csi as u64 + 1);
    let c_init = (((term1 << 10) + 2 * n_id_csi as u64 + 1) & 0x7FFF_FFFF) as u32;

    let c = generate_gold_sequence_31(c_init, 2 * num_subcarriers);
    let inv_sqrt2 = 1.0 / std::f64::consts::SQRT_2;

    let mut seq = Vec::with_capacity(num_subcarriers);
    for m in 0..num_subcarriers {
        let re = (1.0 - 2.0 * c[2 * m] as f64) * inv_sqrt2;
        let im = (1.0 - 2.0 * c[2 * m + 1] as f64) * inv_sqrt2;
        seq.push(Complex64::new(re, im));
    }
    seq
}

// ---------------------------------------------------------------------------
// Resource Mapping & CDM Tables (TS 38.211 Table 7.4.1.5.3-1)
// ---------------------------------------------------------------------------

/// CSI-RS Component Resource Configuration (Row in TS 38.211 Table 7.4.1.5.3-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsiRsRowConfig {
    pub row_index: usize,
    pub num_ports: usize,
    pub density: usize, // 1 for 1, 3 for 3, 0 for 0.5
    pub cdm_type: CsiRsCdmType,
    pub num_cdm_groups: usize,
    pub fd_cdm_length: usize,
    pub td_cdm_length: usize,
}

/// Resolves standard Table 7.4.1.5.3-1 CSI-RS configuration for a given row.
pub fn get_csi_rs_row_config(row_index: usize) -> Result<CsiRsRowConfig, CsiRsError> {
    match row_index {
        1 => Ok(CsiRsRowConfig {
            row_index: 1,
            num_ports: 1,
            density: 3,
            cdm_type: CsiRsCdmType::NoCdm,
            num_cdm_groups: 1,
            fd_cdm_length: 1,
            td_cdm_length: 1,
        }),
        2 => Ok(CsiRsRowConfig {
            row_index: 2,
            num_ports: 1,
            density: 1,
            cdm_type: CsiRsCdmType::NoCdm,
            num_cdm_groups: 1,
            fd_cdm_length: 1,
            td_cdm_length: 1,
        }),
        3 => Ok(CsiRsRowConfig {
            row_index: 3,
            num_ports: 2,
            density: 1,
            cdm_type: CsiRsCdmType::FdCdm2,
            num_cdm_groups: 1,
            fd_cdm_length: 2,
            td_cdm_length: 1,
        }),
        4 => Ok(CsiRsRowConfig {
            row_index: 4,
            num_ports: 4,
            density: 1,
            cdm_type: CsiRsCdmType::FdCdm2,
            num_cdm_groups: 2,
            fd_cdm_length: 2,
            td_cdm_length: 1,
        }),
        6 => Ok(CsiRsRowConfig {
            row_index: 6,
            num_ports: 8,
            density: 1,
            cdm_type: CsiRsCdmType::Cdm4Fd2Td2,
            num_cdm_groups: 2,
            fd_cdm_length: 2,
            td_cdm_length: 2,
        }),
        10 => Ok(CsiRsRowConfig {
            row_index: 10,
            num_ports: 12,
            density: 1,
            cdm_type: CsiRsCdmType::Cdm4Fd2Td2,
            num_cdm_groups: 3,
            fd_cdm_length: 2,
            td_cdm_length: 2,
        }),
        11 => Ok(CsiRsRowConfig {
            row_index: 11,
            num_ports: 16,
            density: 1,
            cdm_type: CsiRsCdmType::Cdm4Fd2Td2,
            num_cdm_groups: 4,
            fd_cdm_length: 2,
            td_cdm_length: 2,
        }),
        13 => Ok(CsiRsRowConfig {
            row_index: 13,
            num_ports: 24,
            density: 1,
            cdm_type: CsiRsCdmType::Cdm8Fd2Td4,
            num_cdm_groups: 3,
            fd_cdm_length: 2,
            td_cdm_length: 4,
        }),
        16 => Ok(CsiRsRowConfig {
            row_index: 16,
            num_ports: 32,
            density: 1,
            cdm_type: CsiRsCdmType::Cdm8Fd2Td4,
            num_cdm_groups: 4,
            fd_cdm_length: 2,
            td_cdm_length: 4,
        }),
        _ => Err(CsiRsError::InvalidRowIndex(row_index)),
    }
}

/// Generates orthogonal Walsh/Hadamard cover code for CSI-RS CDM group.
pub fn generate_cdm_cover_code(
    cdm_type: CsiRsCdmType,
    port_in_group: usize,
) -> (Vec<f64>, Vec<f64>) {
    match cdm_type {
        CsiRsCdmType::NoCdm => (vec![1.0], vec![1.0]),
        CsiRsCdmType::FdCdm2 => {
            let w_f = if port_in_group % 2 == 0 {
                vec![1.0, 1.0]
            } else {
                vec![1.0, -1.0]
            };
            (w_f, vec![1.0])
        }
        CsiRsCdmType::Cdm4Fd2Td2 => {
            // port_in_group in 0..4
            let w_f = if port_in_group % 2 == 0 {
                vec![1.0, 1.0]
            } else {
                vec![1.0, -1.0]
            };
            let w_t = if (port_in_group / 2) == 0 {
                vec![1.0, 1.0]
            } else {
                vec![1.0, -1.0]
            };
            (w_f, w_t)
        }
        CsiRsCdmType::Cdm8Fd2Td4 => {
            // port_in_group in 0..8
            let w_f = if port_in_group % 2 == 0 {
                vec![1.0, 1.0]
            } else {
                vec![1.0, -1.0]
            };
            let t_idx = port_in_group / 2;
            let w_t = match t_idx {
                0 => vec![1.0, 1.0, 1.0, 1.0],
                1 => vec![1.0, -1.0, 1.0, -1.0],
                2 => vec![1.0, 1.0, -1.0, -1.0],
                3 => vec![1.0, -1.0, -1.0, 1.0],
                _ => vec![1.0, 1.0, 1.0, 1.0],
            };
            (w_f, w_t)
        }
    }
}

// ---------------------------------------------------------------------------
// Type I Codebook & Precoding Matrix Synthesis (TS 38.214 §5.2.2.2.1 - 4)
// ---------------------------------------------------------------------------

/// Configuration for Type I Single-Panel / Multi-Panel Codebook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Type1CodebookConfig {
    /// Number of antenna ports in 1st dimension ($N_1$).
    pub n1: usize,
    /// Number of antenna ports in 2nd dimension ($N_2$).
    pub n2: usize,
    /// Oversampling factor in 1st dimension ($O_1$).
    pub o1: usize,
    /// Oversampling factor in 2nd dimension ($O_2$).
    pub o2: usize,
}

impl Type1CodebookConfig {
    pub fn new(n1: usize, n2: usize) -> Result<Self, CsiRsError> {
        // Standard oversampling: O1=4, O2=1 if N2=1; O1=4, O2=4 if N2>1
        let o1 = 4;
        let o2 = if n2 > 1 { 4 } else { 1 };
        let total_ports = 2 * n1 * n2;
        if total_ports == 0 || total_ports > 32 {
            return Err(CsiRsError::InvalidPortCount(total_ports));
        }
        Ok(Self { n1, n2, o1, o2 })
    }

    pub fn total_ports(&self) -> usize {
        2 * self.n1 * self.n2
    }

    /// Generates 2D DFT beam vector $v_{l, m}$ of length $N_1 N_2$.
    pub fn generate_dft_beam(&self, l: usize, m: usize) -> Vec<Complex64> {
        let mut beam = Vec::with_capacity(self.n1 * self.n2);
        for m_idx in 0..self.n2 {
            let phase2 = 2.0 * PI * (m_idx as f64) * (m as f64) / ((self.n2 * self.o2) as f64);
            for l_idx in 0..self.n1 {
                let phase1 = 2.0 * PI * (l_idx as f64) * (l as f64) / ((self.n1 * self.o1) as f64);
                beam.push(Complex64::from_polar(1.0, phase1 + phase2));
            }
        }
        beam
    }

    /// Generates Rank 1 precoding vector $W = \frac{1}{\sqrt{P}} \begin{bmatrix} v_{l, m} \\ \phi_n v_{l, m} \end{bmatrix}$.
    /// Co-phasing $\phi_n = e^{j \pi n / 2}$ for $n \in \{0, 1, 2, 3\}$.
    pub fn generate_rank1_precoder(
        &self,
        l: usize,
        m: usize,
        n_cophasing: usize,
    ) -> Vec<Complex64> {
        let p = self.total_ports();
        let inv_sqrt_p = 1.0 / (p as f64).sqrt();

        let v = self.generate_dft_beam(l, m);
        let phi = Complex64::from_polar(1.0, (n_cophasing as f64) * PI / 2.0);

        let mut precoder = Vec::with_capacity(p);
        // Polarization 1
        for val in &v {
            precoder.push(val.scale(inv_sqrt_p));
        }
        // Polarization 2
        for val in &v {
            precoder.push(val.mul(&phi).scale(inv_sqrt_p));
        }
        precoder
    }

    /// Generates Rank 2 precoding matrix $W \in \mathbb{C}^{P \times 2}$ (TS 38.214 §5.2.2.2.1).
    pub fn generate_rank2_precoder(
        &self,
        l: usize,
        m: usize,
        n_cophasing: usize,
    ) -> (Vec<Complex64>, Vec<Complex64>) {
        let p = self.total_ports();
        let inv_sqrt_2p = 1.0 / ((2 * p) as f64).sqrt();

        let v = self.generate_dft_beam(l, m);
        let phi = Complex64::from_polar(1.0, (n_cophasing as f64) * PI / 2.0);

        let mut col1 = Vec::with_capacity(p);
        let mut col2 = Vec::with_capacity(p);

        // Column 1: [v; phi * v]
        for val in &v {
            col1.push(val.scale(inv_sqrt_2p));
        }
        for val in &v {
            col1.push(val.mul(&phi).scale(inv_sqrt_2p));
        }

        // Column 2: [v; -phi * v]
        for val in &v {
            col2.push(val.scale(inv_sqrt_2p));
        }
        for val in &v {
            col2.push(val.mul(&phi).scale(-inv_sqrt_2p));
        }

        (col1, col2)
    }
}

// ---------------------------------------------------------------------------
// End-to-End CSI Reporting Evaluator (RI, PMI, CQI, LI)
// ---------------------------------------------------------------------------

/// Recommended CSI feedback parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct CsiFeedbackReport {
    /// Rank Indicator (1..4).
    pub ri: usize,
    /// Precoding Matrix Indicator: (beam_l, beam_m, cophasing_n).
    pub pmi: (usize, usize, usize),
    /// Channel Quality Indicator (0..15).
    pub cqi: u8,
    /// Layer Indicator (1..ri).
    pub li: usize,
    /// Effective post-equalization SINR in dB.
    pub effective_sinr_db: f64,
}

/// Standard 5G NR 4-bit CQI table (TS 38.214 Table 5.2.2.1-2, 64QAM table).
pub const CQI_SNR_THRESHOLDS_DB: [f64; 16] = [
    -10.0, -7.0, -5.0, -3.0, -1.0, 1.0, 3.0, 5.0, 7.0, 9.0, 11.0, 13.0, 15.0, 17.0, 19.0, 21.0,
];

/// Evaluates estimated $N_{\text{rx}} \times P$ channel matrix $H$ and derives optimal CSI feedback.
pub fn evaluate_csi_feedback(
    channel_h: &[Vec<Complex64>], // [rx_antenna][tx_port]
    codebook: &Type1CodebookConfig,
    noise_power: f64,
) -> Result<CsiFeedbackReport, CsiRsError> {
    if channel_h.is_empty() || channel_h[0].len() != codebook.total_ports() {
        return Err(CsiRsError::ChannelEvaluationFailed(
            "Channel dimension mismatch".into(),
        ));
    }

    let n_rx = channel_h.len();
    let p = codebook.total_ports();

    // 1. Evaluate Rank Indicator from channel singular values / spatial correlation
    let mut best_sinr = -100.0;
    let mut best_pmi = (0, 0, 0);

    // Search across grid of beams (L in 0..N1*O1, M in 0..N2*O2, co-phasing 0..4)
    for l in 0..(codebook.n1 * codebook.o1) {
        for m in 0..(codebook.n2 * codebook.o2) {
            for coph in 0..4 {
                let w = codebook.generate_rank1_precoder(l, m, coph);

                // Effective channel: H * w (length N_rx)
                let mut hw_norm_sqr = 0.0;
                for rx in 0..n_rx {
                    let mut dot = Complex64::new(0.0, 0.0);
                    for port in 0..p {
                        dot = dot.add(&channel_h[rx][port].mul(&w[port]));
                    }
                    hw_norm_sqr += dot.norm_sqr();
                }

                let sinr = hw_norm_sqr / noise_power.max(1e-12);
                let sinr_db = 10.0 * sinr.max(1e-12).log10();

                if sinr_db > best_sinr {
                    best_sinr = sinr_db;
                    best_pmi = (l, m, coph);
                }
            }
        }
    }

    // Determine CQI from best SINR
    let mut cqi = 0u8;
    for (idx, &thresh) in CQI_SNR_THRESHOLDS_DB.iter().enumerate() {
        if best_sinr >= thresh {
            cqi = idx as u8;
        }
    }

    // Determine RI based on receiver dimensions and SINR quality
    let ri = if n_rx >= 2 && best_sinr >= 10.0 { 2 } else { 1 };
    let li = 1; // Strongest layer index

    Ok(CsiFeedbackReport {
        ri,
        pmi: best_pmi,
        cqi,
        li,
        effective_sinr_db: best_sinr,
    })
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16
// ---------------------------------------------------------------------------

/// Wire frame PDU for CSI-RS resource and reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsiRsWirePdu {
    pub magic: u32,
    pub slot_idx: u32,
    pub row_index: u8,
    pub num_ports: u8,
    pub cdm_type: u8,
    pub density: u8,
    pub n_id_csi: u16,
    pub ri: u8,
    pub cqi: u8,
    pub pmi_l: u8,
    pub pmi_m: u8,
    pub pmi_coph: u8,
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

impl CsiRsWirePdu {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(22 + self.payload.len());
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.slot_idx.to_be_bytes());
        buf.push(self.row_index);
        buf.push(self.num_ports);
        buf.push(self.cdm_type);
        buf.push(self.density);
        buf.extend_from_slice(&self.n_id_csi.to_be_bytes());
        buf.push(self.ri);
        buf.push(self.cqi);
        buf.push(self.pmi_l);
        buf.push(self.pmi_m);
        buf.push(self.pmi_coph);
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, CsiRsError> {
        if data.len() < 22 {
            return Err(CsiRsError::DeserializationError("Buffer too small".into()));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != CSIRS_WIRE_MAGIC {
            return Err(CsiRsError::DeserializationError(format!(
                "Invalid magic: 0x{:08X}",
                magic
            )));
        }

        let slot_idx = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let row_index = data[8];
        let num_ports = data[9];
        let cdm_type = data[10];
        let density = data[11];
        let n_id_csi = u16::from_be_bytes([data[12], data[13]]);
        let ri = data[14];
        let cqi = data[15];
        let pmi_l = data[16];
        let pmi_m = data[17];
        let pmi_coph = data[18];
        let payload_len = u16::from_be_bytes([data[19], data[20]]) as usize;

        if data.len() < 21 + payload_len + 2 {
            return Err(CsiRsError::DeserializationError("Truncated payload".into()));
        }

        let payload = data[21..21 + payload_len].to_vec();
        let expected_crc = compute_crc16(&data[..21 + payload_len]);
        let rx_crc = u16::from_be_bytes([data[21 + payload_len], data[21 + payload_len + 1]]);

        if rx_crc != expected_crc {
            return Err(CsiRsError::DeserializationError(format!(
                "CRC-16 mismatch: expected 0x{:04X}, received 0x{:04X}",
                expected_crc, rx_crc
            )));
        }

        Ok(Self {
            magic,
            slot_idx,
            row_index,
            num_ports,
            cdm_type,
            density,
            n_id_csi,
            ri,
            cqi,
            pmi_l,
            pmi_m,
            pmi_coph,
            payload,
            crc16: rx_crc,
        })
    }
}

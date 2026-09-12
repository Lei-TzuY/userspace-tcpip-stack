//! 3GPP Release 18/19 5G-Advanced CSI Calculation, RI/PMI/CQI Selection & Outer-Loop Link Adaptation (OLLA) Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.214 Rel-18 §5.2: CSI reporting procedures, CQI tables, and PMI/RI codebooks.
//! - 3GPP TS 38.214 Rel-18 Tables 5.2.2.1-2 (64QAM), 5.2.2.1-3 (256QAM), 5.2.2.1-4 (1024QAM).
//! - 3GPP TS 38.211 Rel-18 §7.4.1.5: Precoding matrix generation for spatial multiplexing.
//! - 3GPP TS 38.331 Rel-18: CSI-ReportConfig and link adaptation parameter structures.
//!
//! Features:
//! 1. Full 3GPP CQI Tables 1 (64QAM), 2 (256QAM), and Rel-18 Table 3 (1024QAM) with modulation order, code rate, and spectral efficiency.
//! 2. Effective Exponential SNR Mapping (EESM) aggregating frequency-selective subcarrier SINRs into scalar equivalent SINR.
//! 3. Optimal Rank Indicator (RI) selection evaluating mutual information and throughput across rank hypotheses ($r \in [1, 4]$).
//! 4. 3GPP Type I Single-Panel Precoding Matrix Indicator (PMI) selection with dual-polarized 2D-DFT beam steering and co-phasing ($i_1, i_2$).
//! 5. Wideband CQI and Subband differential CQI calculation per TS 38.214 §5.2.1.4.
//! 6. Outer-Loop Link Adaptation (OLLA) closed-loop dynamic SINR offset controller precisely converging to target BLER (10%).
//! 7. Binary wire framing (`CsiReportWirePdu`) with magic `0x43534930` ("CSI0") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for CSI Report Wire PDU: "CSI0" (0x43534930).
pub const CSI_WIRE_MAGIC: u32 = 0x43534930;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Default target BLER for link adaptation (10% per 3GPP TS 38.214 §5.2.2.1).
pub const DEFAULT_TARGET_BLER: f32 = 0.10;

/// Default upward step size for OLLA on ACK (in dB).
pub const DEFAULT_OLLA_STEP_UP_DB: f32 = 0.10;

/// Errors encountered in CSI calculation and link adaptation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkAdaptationError {
    EmptySinrList,
    InvalidRank(usize),
    InvalidSubbandCount,
    InvalidCqiTable(u8),
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    WireCrcMismatch { expected: u16, computed: u16 },
}

impl fmt::Display for LinkAdaptationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySinrList => write!(f, "SINR input list cannot be empty"),
            Self::InvalidRank(r) => write!(f, "Invalid transmission rank: {} (must be 1..4)", r),
            Self::InvalidSubbandCount => {
                write!(f, "Subband list length must match configured subbands")
            }
            Self::InvalidCqiTable(t) => write!(
                f,
                "Invalid CQI table identifier: {} (must be 1, 2, or 3)",
                t
            ),
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
// 3GPP Standard CQI Tables (TS 38.214 §5.2.2.1)
// ---------------------------------------------------------------------------

/// Modulation scheme used in 5G NR PDSCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrModulation {
    Qpsk,
    Qam16,
    Qam64,
    Qam256,
    Qam1024,
}

impl NrModulation {
    #[inline]
    pub fn bits_per_symbol(self) -> usize {
        match self {
            Self::Qpsk => 2,
            Self::Qam16 => 4,
            Self::Qam64 => 6,
            Self::Qam256 => 8,
            Self::Qam1024 => 10,
        }
    }

    #[inline]
    pub fn eesm_beta(self) -> f32 {
        match self {
            Self::Qpsk => 1.5,
            Self::Qam16 => 3.2,
            Self::Qam64 => 7.5,
            Self::Qam256 => 16.0,
            Self::Qam1024 => 35.0,
        }
    }
}

/// Standard 4-bit CQI Table Entry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CqiEntry {
    pub cqi_index: u8,
    pub modulation: NrModulation,
    pub code_rate_x1024: u16,
    pub efficiency: f32,       // bits per RE
    pub snr_threshold_db: f32, // AWGN SNR required for 10% BLER
}

/// CQI Table Type per TS 38.214.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CqiTableType {
    /// Table 1: Up to 64QAM (TS 38.214 Table 5.2.2.1-2)
    Table1_64Qam,
    /// Table 2: Up to 256QAM (TS 38.214 Table 5.2.2.1-3)
    Table2_256Qam,
    /// Table 3: Rel-18 Up to 1024QAM (TS 38.214 Table 5.2.2.1-4)
    Table3_1024Qam,
}

impl CqiTableType {
    /// Returns the standardized entries for the configured CQI Table.
    pub fn entries(self) -> &'static [CqiEntry] {
        match self {
            Self::Table1_64Qam => &CQI_TABLE_1,
            Self::Table2_256Qam => &CQI_TABLE_2,
            Self::Table3_1024Qam => &CQI_TABLE_3,
        }
    }
}

/// 3GPP TS 38.214 Table 5.2.2.1-2 (4-bit CQI Table 1: up to 64QAM).
pub static CQI_TABLE_1: [CqiEntry; 15] = [
    CqiEntry {
        cqi_index: 1,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 78,
        efficiency: 0.1523,
        snr_threshold_db: -6.7,
    },
    CqiEntry {
        cqi_index: 2,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 120,
        efficiency: 0.2344,
        snr_threshold_db: -4.7,
    },
    CqiEntry {
        cqi_index: 3,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 193,
        efficiency: 0.3770,
        snr_threshold_db: -2.3,
    },
    CqiEntry {
        cqi_index: 4,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 308,
        efficiency: 0.6016,
        snr_threshold_db: 0.2,
    },
    CqiEntry {
        cqi_index: 5,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 449,
        efficiency: 0.8770,
        snr_threshold_db: 2.4,
    },
    CqiEntry {
        cqi_index: 6,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 602,
        efficiency: 1.1758,
        snr_threshold_db: 4.3,
    },
    CqiEntry {
        cqi_index: 7,
        modulation: NrModulation::Qam16,
        code_rate_x1024: 378,
        efficiency: 1.4766,
        snr_threshold_db: 5.9,
    },
    CqiEntry {
        cqi_index: 8,
        modulation: NrModulation::Qam16,
        code_rate_x1024: 490,
        efficiency: 1.9141,
        snr_threshold_db: 8.1,
    },
    CqiEntry {
        cqi_index: 9,
        modulation: NrModulation::Qam16,
        code_rate_x1024: 616,
        efficiency: 2.4063,
        snr_threshold_db: 10.3,
    },
    CqiEntry {
        cqi_index: 10,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 466,
        efficiency: 2.7305,
        snr_threshold_db: 11.7,
    },
    CqiEntry {
        cqi_index: 11,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 567,
        efficiency: 3.3223,
        snr_threshold_db: 14.1,
    },
    CqiEntry {
        cqi_index: 12,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 666,
        efficiency: 3.9023,
        snr_threshold_db: 16.3,
    },
    CqiEntry {
        cqi_index: 13,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 772,
        efficiency: 4.5234,
        snr_threshold_db: 18.7,
    },
    CqiEntry {
        cqi_index: 14,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 873,
        efficiency: 5.1152,
        snr_threshold_db: 21.0,
    },
    CqiEntry {
        cqi_index: 15,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 948,
        efficiency: 5.5547,
        snr_threshold_db: 22.7,
    },
];

/// 3GPP TS 38.214 Table 5.2.2.1-3 (4-bit CQI Table 2: up to 256QAM).
pub static CQI_TABLE_2: [CqiEntry; 15] = [
    CqiEntry {
        cqi_index: 1,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 78,
        efficiency: 0.1523,
        snr_threshold_db: -6.7,
    },
    CqiEntry {
        cqi_index: 2,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 193,
        efficiency: 0.3770,
        snr_threshold_db: -2.3,
    },
    CqiEntry {
        cqi_index: 3,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 449,
        efficiency: 0.8770,
        snr_threshold_db: 2.4,
    },
    CqiEntry {
        cqi_index: 4,
        modulation: NrModulation::Qam16,
        code_rate_x1024: 378,
        efficiency: 1.4766,
        snr_threshold_db: 5.9,
    },
    CqiEntry {
        cqi_index: 5,
        modulation: NrModulation::Qam16,
        code_rate_x1024: 490,
        efficiency: 1.9141,
        snr_threshold_db: 8.1,
    },
    CqiEntry {
        cqi_index: 6,
        modulation: NrModulation::Qam16,
        code_rate_x1024: 616,
        efficiency: 2.4063,
        snr_threshold_db: 10.3,
    },
    CqiEntry {
        cqi_index: 7,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 466,
        efficiency: 2.7305,
        snr_threshold_db: 11.7,
    },
    CqiEntry {
        cqi_index: 8,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 567,
        efficiency: 3.3223,
        snr_threshold_db: 14.1,
    },
    CqiEntry {
        cqi_index: 9,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 666,
        efficiency: 3.9023,
        snr_threshold_db: 16.3,
    },
    CqiEntry {
        cqi_index: 10,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 772,
        efficiency: 4.5234,
        snr_threshold_db: 18.7,
    },
    CqiEntry {
        cqi_index: 11,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 873,
        efficiency: 5.1152,
        snr_threshold_db: 21.0,
    },
    CqiEntry {
        cqi_index: 12,
        modulation: NrModulation::Qam256,
        code_rate_x1024: 711,
        efficiency: 5.5547,
        snr_threshold_db: 23.0,
    },
    CqiEntry {
        cqi_index: 13,
        modulation: NrModulation::Qam256,
        code_rate_x1024: 797,
        efficiency: 6.2266,
        snr_threshold_db: 25.2,
    },
    CqiEntry {
        cqi_index: 14,
        modulation: NrModulation::Qam256,
        code_rate_x1024: 885,
        efficiency: 6.9141,
        snr_threshold_db: 27.5,
    },
    CqiEntry {
        cqi_index: 15,
        modulation: NrModulation::Qam256,
        code_rate_x1024: 948,
        efficiency: 7.4063,
        snr_threshold_db: 29.5,
    },
];

/// 3GPP TS 38.214 Rel-18 Table 5.2.2.1-4 (4-bit CQI Table 3: up to 1024QAM).
pub static CQI_TABLE_3: [CqiEntry; 15] = [
    CqiEntry {
        cqi_index: 1,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 78,
        efficiency: 0.1523,
        snr_threshold_db: -6.7,
    },
    CqiEntry {
        cqi_index: 2,
        modulation: NrModulation::Qpsk,
        code_rate_x1024: 231,
        efficiency: 0.4512,
        snr_threshold_db: -1.0,
    },
    CqiEntry {
        cqi_index: 3,
        modulation: NrModulation::Qam16,
        code_rate_x1024: 378,
        efficiency: 1.4766,
        snr_threshold_db: 5.9,
    },
    CqiEntry {
        cqi_index: 4,
        modulation: NrModulation::Qam16,
        code_rate_x1024: 616,
        efficiency: 2.4063,
        snr_threshold_db: 10.3,
    },
    CqiEntry {
        cqi_index: 5,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 466,
        efficiency: 2.7305,
        snr_threshold_db: 11.7,
    },
    CqiEntry {
        cqi_index: 6,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 666,
        efficiency: 3.9023,
        snr_threshold_db: 16.3,
    },
    CqiEntry {
        cqi_index: 7,
        modulation: NrModulation::Qam64,
        code_rate_x1024: 873,
        efficiency: 5.1152,
        snr_threshold_db: 21.0,
    },
    CqiEntry {
        cqi_index: 8,
        modulation: NrModulation::Qam256,
        code_rate_x1024: 711,
        efficiency: 5.5547,
        snr_threshold_db: 23.0,
    },
    CqiEntry {
        cqi_index: 9,
        modulation: NrModulation::Qam256,
        code_rate_x1024: 797,
        efficiency: 6.2266,
        snr_threshold_db: 25.2,
    },
    CqiEntry {
        cqi_index: 10,
        modulation: NrModulation::Qam256,
        code_rate_x1024: 885,
        efficiency: 6.9141,
        snr_threshold_db: 27.5,
    },
    CqiEntry {
        cqi_index: 11,
        modulation: NrModulation::Qam256,
        code_rate_x1024: 948,
        efficiency: 7.4063,
        snr_threshold_db: 29.5,
    },
    CqiEntry {
        cqi_index: 12,
        modulation: NrModulation::Qam1024,
        code_rate_x1024: 805,
        efficiency: 7.8613,
        snr_threshold_db: 32.0,
    },
    CqiEntry {
        cqi_index: 13,
        modulation: NrModulation::Qam1024,
        code_rate_x1024: 853,
        efficiency: 8.3301,
        snr_threshold_db: 34.2,
    },
    CqiEntry {
        cqi_index: 14,
        modulation: NrModulation::Qam1024,
        code_rate_x1024: 911,
        efficiency: 8.8965,
        snr_threshold_db: 36.5,
    },
    CqiEntry {
        cqi_index: 15,
        modulation: NrModulation::Qam1024,
        code_rate_x1024: 963,
        efficiency: 9.4043,
        snr_threshold_db: 39.0,
    },
];

// ---------------------------------------------------------------------------
// Effective Exponential SNR Mapping (EESM)
// ---------------------------------------------------------------------------

/// Computes Effective SINR (dB) from a slice of subband/subcarrier SINRs (dB) using EESM:
/// $\text{SINR}_{\text{eff}} = -\beta \ln\left( \frac{1}{K} \sum_{k=1}^K e^{-\text{SINR}_k^{\text{linear}} / \beta} \right)$.
pub fn compute_eesm_effective_sinr(
    sinrs_db: &[f32],
    beta: f32,
) -> Result<f32, LinkAdaptationError> {
    if sinrs_db.is_empty() {
        return Err(LinkAdaptationError::EmptySinrList);
    }
    let k_count = sinrs_db.len() as f32;
    let mut sum_exp = 0.0f32;

    for &s_db in sinrs_db {
        let s_lin = 10.0f32.powf(s_db / 10.0);
        let arg = (-s_lin / beta).clamp(-50.0, 0.0);
        sum_exp += arg.exp();
    }

    let avg_exp = (sum_exp / k_count).clamp(1e-20, 1.0);
    let eff_lin = -beta * avg_exp.ln();
    let eff_db = 10.0 * eff_lin.max(1e-4).log10();
    Ok(eff_db)
}

/// Maps an effective SINR (dB) to the highest CQI entry satisfying the 10% BLER threshold.
pub fn select_cqi(sinr_eff_db: f32, table_type: CqiTableType) -> u8 {
    let entries = table_type.entries();
    let mut best_cqi = 0u8; // 0 indicates out-of-range (disconnect / unserviceable)

    for entry in entries {
        if sinr_eff_db >= entry.snr_threshold_db {
            best_cqi = entry.cqi_index;
        } else {
            break;
        }
    }
    best_cqi
}

// ---------------------------------------------------------------------------
// Type I Single-Panel Precoding Codebook (TS 38.214 §5.2.2.2)
// ---------------------------------------------------------------------------

/// Antenna Panel Geometry for Type I CSI codebook: $(N_1, N_2)$.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntennaPanelGeometry {
    pub n1: usize, // Horizontal elements per polarization
    pub n2: usize, // Vertical elements per polarization
    pub o1: usize, // Horizontal oversampling factor (typically 4)
    pub o2: usize, // Vertical oversampling factor (typically 4)
}

impl Default for AntennaPanelGeometry {
    fn default() -> Self {
        Self {
            n1: 2,
            n2: 1,
            o1: 4,
            o2: 4,
        }
    }
}

impl AntennaPanelGeometry {
    #[inline]
    pub fn num_tx_ports(self) -> usize {
        2 * self.n1 * self.n2
    }

    #[inline]
    pub fn num_beams_l(self) -> usize {
        self.n1 * self.o1
    }

    #[inline]
    pub fn num_beams_m(self) -> usize {
        self.n2 * self.o2
    }
}

/// Selected Precoding Matrix Indicator (PMI) indices: $(i_1, i_2)$.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmiSelection {
    pub beam_l: u8,    // Horizontal beam index
    pub beam_m: u8,    // Vertical beam index
    pub cophase_n: u8, // Co-phasing index across polarizations: n in {0, 1, 2, 3} -> {1, j, -1, -j}
}

/// Evaluates Type I single-panel precoding matrices and selects the optimal PMI $(l, m, n)$.
///
/// Channel `h_per_subband` has dimensions `[num_subbands][num_rx][num_tx]`.
pub fn select_type1_pmi_rank1(
    channel_taps: &[Vec<Vec<(f32, f32)>>], // (re, im) for [subband][rx][tx]
    panel: AntennaPanelGeometry,
) -> Result<PmiSelection, LinkAdaptationError> {
    if channel_taps.is_empty() {
        return Err(LinkAdaptationError::EmptySinrList);
    }

    let n1 = panel.n1;
    let n2 = panel.n2;
    let o1 = panel.o1;
    let o2 = panel.o2;
    let total_tx = panel.num_tx_ports();

    let mut best_power = -1.0f32;
    let mut best_pmi = PmiSelection {
        beam_l: 0,
        beam_m: 0,
        cophase_n: 0,
    };

    let pi = std::f32::consts::PI;

    // Search over 2D DFT beams (l, m) and co-phasing n in 0..4
    for l in 0..(n1 * o1) {
        for m in 0..(n2 * o2) {
            // Compute 2D DFT beam vector: v[x1, x2] = e^(j 2pi x1 l / (N1 O1)) * e^(j 2pi x2 m / (N2 O2))
            let mut v = Vec::with_capacity(n1 * n2);
            for x2 in 0..n2 {
                for x1 in 0..n1 {
                    let phase = 2.0
                        * pi
                        * ((x1 * l) as f32 / (n1 * o1) as f32 + (x2 * m) as f32 / (n2 * o2) as f32);
                    v.push((phase.cos(), phase.sin()));
                }
            }

            for n in 0..4 {
                let phi_phase = pi * (n as f32) / 2.0;
                let phi = (phi_phase.cos(), phi_phase.sin());

                // Construct full precoder W = [v; phi * v]
                let mut w = Vec::with_capacity(total_tx);
                for &v_val in &v {
                    w.push(v_val);
                }
                for &v_val in &v {
                    // Complex multiplication: phi * v_val
                    let re = phi.0 * v_val.0 - phi.1 * v_val.1;
                    let im = phi.0 * v_val.1 + phi.1 * v_val.0;
                    w.push((re, im));
                }

                // Evaluate average received power: sum ||H * W||^2
                let mut total_metric = 0.0f32;
                for sb_h in channel_taps {
                    for rx_row in sb_h {
                        if rx_row.len() == total_tx {
                            let mut rx_re = 0.0f32;
                            let mut rx_im = 0.0f32;
                            for (tx_idx, &w_val) in w.iter().enumerate() {
                                let h_val = rx_row[tx_idx];
                                rx_re += h_val.0 * w_val.0 - h_val.1 * w_val.1;
                                rx_im += h_val.0 * w_val.1 + h_val.1 * w_val.0;
                            }
                            total_metric += rx_re * rx_re + rx_im * rx_im;
                        }
                    }
                }

                if total_metric > best_power {
                    best_power = total_metric;
                    best_pmi = PmiSelection {
                        beam_l: l as u8,
                        beam_m: m as u8,
                        cophase_n: n as u8,
                    };
                }
            }
        }
    }

    Ok(best_pmi)
}

// ---------------------------------------------------------------------------
// Rank Indicator (RI) Selection
// ---------------------------------------------------------------------------

/// Computes the optimal transmission rank $r \in [1, \text{max\_rank}]$ based on singular values / eigenvalue ratios.
pub fn select_rank_indicator(
    eigenvalues: &[f32], // Singular values squared in descending order
    max_rank: usize,
    snr_db: f32,
) -> Result<usize, LinkAdaptationError> {
    if eigenvalues.is_empty() {
        return Err(LinkAdaptationError::EmptySinrList);
    }
    let snr_lin = 10.0f32.powf(snr_db / 10.0);
    let allowed_ranks = max_rank.min(eigenvalues.len()).clamp(1, 4);

    let mut best_rank = 1;
    let mut max_throughput = 0.0f32;

    for r in 1..=allowed_ranks {
        // Multi-layer transmission requires sufficient SNR on all layers to decode codewords
        let min_layer_snr_db = 10.0
            * ((snr_lin / (r as f32)) * eigenvalues[r - 1])
                .max(1e-6)
                .log10();
        if r > 1 && (snr_db < 0.0 || min_layer_snr_db < -6.0) {
            continue;
        }

        // Shannon-like MIMO capacity estimate for rank r:
        // C(r) = sum_{i=0}^{r-1} log2(1 + (SNR / r) * lambda_i)
        let mut cap = 0.0f32;
        for i in 0..r {
            let lambda = eigenvalues[i];
            let layer_snr = (snr_lin / (r as f32)) * lambda;
            cap += (1.0 + layer_snr).log2();
        }

        // Rank penalty: higher ranks require lower code rates or higher BLER if channels are ill-conditioned
        let condition_ratio = if eigenvalues[0] > 1e-6 {
            eigenvalues[r - 1] / eigenvalues[0]
        } else {
            0.0
        };

        // If sub-streams have very low condition number, penalize capacity
        let throughput = if condition_ratio > 0.05 {
            cap * (1.0 - 0.05 * (r - 1) as f32)
        } else {
            cap * condition_ratio
        };

        if throughput > max_throughput {
            max_throughput = throughput;
            best_rank = r;
        }
    }

    Ok(best_rank)
}

// ---------------------------------------------------------------------------
// Wideband & Subband Differential CQI (TS 38.214 §5.2.1.4)
// ---------------------------------------------------------------------------

/// Complete CSI Feedback Report content.
#[derive(Debug, Clone, PartialEq)]
pub struct CsiFeedbackReport {
    pub rank_indicator: u8,
    pub pmi: PmiSelection,
    pub wideband_cqi: u8,
    /// Subband differential CQI relative to wideband CQI: offset in {-1, 0, +1, +2}.
    pub subband_differential_cqis: Vec<i8>,
}

/// Generates Wideband and Subband CQIs given per-subband SINRs.
pub fn generate_csi_report(
    subband_sinrs_db: &[f32],
    rank: u8,
    pmi: PmiSelection,
    table_type: CqiTableType,
) -> Result<CsiFeedbackReport, LinkAdaptationError> {
    if subband_sinrs_db.is_empty() {
        return Err(LinkAdaptationError::EmptySinrList);
    }

    // Wideband effective SINR
    let wb_sinr = compute_eesm_effective_sinr(subband_sinrs_db, 4.0)?;
    let wideband_cqi = select_cqi(wb_sinr, table_type);

    let mut subband_differential_cqis = Vec::with_capacity(subband_sinrs_db.len());
    for &sb_sinr in subband_sinrs_db {
        let sb_cqi = select_cqi(sb_sinr, table_type);
        // Differential: subband CQI - wideband CQI, clamped to 3GPP allowed range [-1, 2]
        let diff = (sb_cqi as i16 - wideband_cqi as i16).clamp(-1, 2) as i8;
        subband_differential_cqis.push(diff);
    }

    Ok(CsiFeedbackReport {
        rank_indicator: rank,
        pmi,
        wideband_cqi,
        subband_differential_cqis,
    })
}

// ---------------------------------------------------------------------------
// Outer-Loop Link Adaptation (OLLA) Controller
// ---------------------------------------------------------------------------

/// Outer-Loop Link Adaptation (OLLA) tracking SINR offset to maintain target BLER.
#[derive(Debug, Clone, PartialEq)]
pub struct OllaController {
    pub target_bler: f32,
    pub step_up_db: f32,
    pub step_down_db: f32,
    pub offset_db: f32,
    pub min_offset_db: f32,
    pub max_offset_db: f32,
    pub ack_count: u64,
    pub nack_count: u64,
}

impl OllaController {
    /// Creates a new OLLA controller with target BLER (default 0.10) and up-step size.
    pub fn new(target_bler: f32, step_up_db: f32) -> Self {
        let bler = target_bler.clamp(0.01, 0.50);
        // In equilibrium: delta_up * (1 - BLER) = delta_down * BLER
        // delta_down = delta_up * (1 - BLER) / BLER
        let step_down = step_up_db * (1.0 - bler) / bler;
        Self {
            target_bler: bler,
            step_up_db,
            step_down_db: step_down,
            offset_db: 0.0,
            min_offset_db: -8.0,
            max_offset_db: 8.0,
            ack_count: 0,
            nack_count: 0,
        }
    }

    /// Updates OLLA state upon receiving HARQ feedback (true = ACK, false = NACK).
    pub fn on_harq_feedback(&mut self, is_ack: bool) {
        if is_ack {
            self.ack_count += 1;
            self.offset_db = (self.offset_db + self.step_up_db).min(self.max_offset_db);
        } else {
            self.nack_count += 1;
            self.offset_db = (self.offset_db - self.step_down_db).max(self.min_offset_db);
        }
    }

    /// Returns the effective adjusted SINR: $\text{SINR}_{\text{adj}} = \text{SINR}_{\text{raw}} + \Delta_{\text{OLLA}}$.
    #[inline]
    pub fn apply_offset(&self, raw_sinr_db: f32) -> f32 {
        raw_sinr_db + self.offset_db
    }

    /// Computes empirical measured BLER over received feedback.
    pub fn empirical_bler(&self) -> f32 {
        let total = self.ack_count + self.nack_count;
        if total == 0 {
            0.0
        } else {
            (self.nack_count as f32) / (total as f32)
        }
    }

    /// Resets the controller state.
    pub fn reset(&mut self) {
        self.offset_db = 0.0;
        self.ack_count = 0;
        self.nack_count = 0;
    }
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
// Binary Wire Framing (`CsiReportWirePdu`)
// ---------------------------------------------------------------------------

/// Wire PDU transporting CSI feedback reports and OLLA telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct CsiReportWirePdu {
    pub rank_indicator: u8,
    pub pmi_l: u8,
    pub pmi_m: u8,
    pub pmi_n: u8,
    pub wideband_cqi: u8,
    pub olla_offset_db: f32,
    pub subband_diff_cqis: Vec<i8>,
}

impl CsiReportWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.subband_diff_cqis.len());
        buf.extend_from_slice(&CSI_WIRE_MAGIC.to_be_bytes());
        buf.push(self.rank_indicator);
        buf.push(self.pmi_l);
        buf.push(self.pmi_m);
        buf.push(self.pmi_n);
        buf.push(self.wideband_cqi);
        buf.extend_from_slice(&self.olla_offset_db.to_be_bytes());
        buf.extend_from_slice(&(self.subband_diff_cqis.len() as u16).to_be_bytes());
        for &diff in &self.subband_diff_cqis {
            buf.push(diff as u8);
        }

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, LinkAdaptationError> {
        if bytes.len() < 17 {
            return Err(LinkAdaptationError::WirePayloadTooShort {
                needed: 17,
                found: bytes.len(),
            });
        }
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != CSI_WIRE_MAGIC {
            return Err(LinkAdaptationError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(LinkAdaptationError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let rank_indicator = bytes[4];
        let pmi_l = bytes[5];
        let pmi_m = bytes[6];
        let pmi_n = bytes[7];
        let wideband_cqi = bytes[8];
        let olla_offset_db = f32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
        let num_subbands = u16::from_be_bytes([bytes[13], bytes[14]]) as usize;

        if body_len < 15 + num_subbands {
            return Err(LinkAdaptationError::WirePayloadTooShort {
                needed: 15 + num_subbands,
                found: body_len,
            });
        }

        let mut subband_diff_cqis = Vec::with_capacity(num_subbands);
        for i in 0..num_subbands {
            subband_diff_cqis.push(bytes[15 + i] as i8);
        }

        Ok(Self {
            rank_indicator,
            pmi_l,
            pmi_m,
            pmi_n,
            wideband_cqi,
            olla_offset_db,
            subband_diff_cqis,
        })
    }
}

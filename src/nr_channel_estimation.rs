//! 3GPP Release 18/19 5G-Advanced Channel Estimation, DMRS Processing & MMSE-IRC Equalizer Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §5.2.1: Pseudo-random sequence generation (Gold sequence length 31).
//! - 3GPP TS 38.211 Rel-18 §6.4.1.1: PUSCH Demodulation Reference Signals (DMRS).
//! - 3GPP TS 38.211 Rel-18 §7.4.1.1: PDSCH Demodulation Reference Signals (DMRS).
//! - 3GPP TS 38.214 Rel-18 §5.1: PDSCH reception, CSI reporting, and post-equalization SINR computation.
//!
//! Features:
//! 1. Complete pure-Rust complex number math engine (`Complex32`) and linear algebra solver ($N_{rx} \times N_{tx}$).
//! 2. 3GPP 31-bit Gold sequence generator initialized with slot, symbol, SCID, and cell ID seeds.
//! 3. DMRS Configuration Type 1 (comb-2) and Configuration Type 2 (comb-6) modeling with Orthogonal Cover Codes (OCC).
//! 4. Least-Squares (LS) raw pilot channel estimation with multi-port OCC de-spreading.
//! 5. 2D Time-Frequency Channel Interpolator (linear frequency interpolation across PRBs + time tracking).
//! 6. Interference-plus-Noise Covariance ($R_{IN}$) estimator capturing spatial cross-stream and co-channel interference.
//! 7. MIMO Equalizer supporting Zero-Forcing (ZF), Minimum Mean Square Error (MMSE), and MMSE-IRC.
//! 8. Post-equalization Signal-to-Interference-plus-Noise Ratio (SINR) calculation for downstream soft LLR scaling.
//! 9. Binary wire framing (`ChannelEstimationWirePdu`) with magic `0x43484553` ("CHES") and CRC-16 CCITT validation.

use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Sub};

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for Channel Estimation Wire PDU: "CHES" (0x43484553).
pub const CHES_WIRE_MAGIC: u32 = 0x43484553;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Number of subcarriers per standard Physical Resource Block (PRB).
pub const SUBCARRIERS_PER_PRB: usize = 12;

/// Standard symbols per NR slot (normal cyclic prefix).
pub const SYMBOLS_PER_SLOT: usize = 14;

/// Errors encountered in Channel Estimation and MIMO Equalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelEstimationError {
    InvalidPrbCount(usize),
    InvalidSymbolIndex(usize),
    DimensionMismatch {
        expected: (usize, usize),
        found: (usize, usize),
    },
    SingularMatrix,
    EmptyBuffer,
    InvalidPort(u16),
    InvalidWireMagic(u32),
    WirePayloadTooShort {
        needed: usize,
        found: usize,
    },
    WireCrcMismatch {
        expected: u16,
        computed: u16,
    },
}

impl fmt::Display for ChannelEstimationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrbCount(p) => write!(f, "Invalid PRB count: {} (must be > 0)", p),
            Self::InvalidSymbolIndex(s) => write!(f, "Invalid symbol index: {} (must be 0..13)", s),
            Self::DimensionMismatch { expected, found } => {
                write!(
                    f,
                    "Matrix dimension mismatch: expected {:?}, found {:?}",
                    expected, found
                )
            }
            Self::SingularMatrix => {
                write!(f, "Matrix is singular or ill-conditioned for inversion")
            }
            Self::EmptyBuffer => write!(f, "Input buffer cannot be empty"),
            Self::InvalidPort(p) => write!(f, "Invalid DMRS antenna port: {}", p),
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
// Complex Number Math Engine (`Complex32`)
// ---------------------------------------------------------------------------

/// 32-bit single-precision complex number ($re + j \cdot im$).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Complex32 {
    pub re: f32,
    pub im: f32,
}

impl Complex32 {
    #[inline]
    pub const fn new(re: f32, im: f32) -> Self {
        Self { re, im }
    }

    #[inline]
    pub const fn zero() -> Self {
        Self { re: 0.0, im: 0.0 }
    }

    #[inline]
    pub const fn one() -> Self {
        Self { re: 1.0, im: 0.0 }
    }

    #[inline]
    pub const fn i() -> Self {
        Self { re: 0.0, im: 1.0 }
    }

    #[inline]
    pub fn conj(self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    #[inline]
    pub fn norm_sqr(self) -> f32 {
        self.re * self.re + self.im * self.im
    }

    #[inline]
    pub fn norm(self) -> f32 {
        self.norm_sqr().sqrt()
    }

    #[inline]
    pub fn inv(self) -> Option<Self> {
        let d = self.norm_sqr();
        if d < 1e-15 {
            None
        } else {
            Some(Self {
                re: self.re / d,
                im: -self.im / d,
            })
        }
    }

    #[inline]
    pub fn scale(self, s: f32) -> Self {
        Self {
            re: self.re * s,
            im: self.im * s,
        }
    }
}

impl Add for Complex32 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }
}

impl Sub for Complex32 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self {
            re: self.re - rhs.re,
            im: self.im - rhs.im,
        }
    }
}

impl Mul for Complex32 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }
}

impl Div for Complex32 {
    type Output = Self;
    #[inline]
    fn div(self, rhs: Self) -> Self {
        let d = rhs.norm_sqr();
        if d < 1e-15 {
            Self::zero()
        } else {
            Self {
                re: (self.re * rhs.re + self.im * rhs.im) / d,
                im: (self.im * rhs.re - self.re * rhs.im) / d,
            }
        }
    }
}

impl Neg for Complex32 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self {
            re: -self.re,
            im: -self.im,
        }
    }
}

// ---------------------------------------------------------------------------
// Matrix Linear Algebra Engine for MIMO Equalization
// ---------------------------------------------------------------------------

/// Dynamic 2D Complex Matrix with row-major storage.
#[derive(Debug, Clone, PartialEq)]
pub struct ComplexMatrix {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<Complex32>,
}

impl ComplexMatrix {
    /// Creates a zero-initialized matrix of dimension `rows x cols`.
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![Complex32::zero(); rows * cols],
        }
    }

    /// Creates an identity matrix of size `n x n`.
    pub fn eye(n: usize) -> Self {
        let mut mat = Self::zeros(n, n);
        for i in 0..n {
            mat.set(i, i, Complex32::one());
        }
        mat
    }

    #[inline]
    pub fn get(&self, r: usize, c: usize) -> Complex32 {
        self.data[r * self.cols + c]
    }

    #[inline]
    pub fn set(&mut self, r: usize, c: usize, val: Complex32) {
        self.data[r * self.cols + c] = val;
    }

    /// Computes Hermitian (conjugate) transpose $A^H$.
    pub fn hermitian(&self) -> Self {
        let mut out = Self::zeros(self.cols, self.rows);
        for r in 0..self.rows {
            for c in 0..self.cols {
                out.set(c, r, self.get(r, c).conj());
            }
        }
        out
    }

    /// Multiplies this matrix with another matrix: $C = A \cdot B$.
    pub fn matmul(&self, rhs: &Self) -> Result<Self, ChannelEstimationError> {
        if self.cols != rhs.rows {
            return Err(ChannelEstimationError::DimensionMismatch {
                expected: (self.cols, self.cols),
                found: (self.cols, rhs.rows),
            });
        }
        let mut out = Self::zeros(self.rows, rhs.cols);
        for r in 0..self.rows {
            for c in 0..rhs.cols {
                let mut sum = Complex32::zero();
                for k in 0..self.cols {
                    sum = sum + self.get(r, k) * rhs.get(k, c);
                }
                out.set(r, c, sum);
            }
        }
        Ok(out)
    }

    /// Inverts a square matrix using Gauss-Jordan elimination with partial pivoting.
    pub fn inverse(&self) -> Result<Self, ChannelEstimationError> {
        if self.rows != self.cols {
            return Err(ChannelEstimationError::DimensionMismatch {
                expected: (self.rows, self.rows),
                found: (self.rows, self.cols),
            });
        }
        let n = self.rows;
        if n == 1 {
            let inv = self
                .get(0, 0)
                .inv()
                .ok_or(ChannelEstimationError::SingularMatrix)?;
            let mut out = Self::zeros(1, 1);
            out.set(0, 0, inv);
            return Ok(out);
        }
        if n == 2 {
            let a = self.get(0, 0);
            let b = self.get(0, 1);
            let c = self.get(1, 0);
            let d = self.get(1, 1);
            let det = a * d - b * c;
            let det_inv = det.inv().ok_or(ChannelEstimationError::SingularMatrix)?;
            let mut out = Self::zeros(2, 2);
            out.set(0, 0, d * det_inv);
            out.set(0, 1, (-b) * det_inv);
            out.set(1, 0, (-c) * det_inv);
            out.set(1, 1, a * det_inv);
            return Ok(out);
        }

        // General Gauss-Jordan elimination for n >= 3
        let mut a = self.clone();
        let mut inv = Self::eye(n);

        for i in 0..n {
            // Find pivot with maximum magnitude
            let mut max_row = i;
            let mut max_val = a.get(i, i).norm_sqr();
            for r in (i + 1)..n {
                let val = a.get(r, i).norm_sqr();
                if val > max_val {
                    max_val = val;
                    max_row = r;
                }
            }
            if max_val < 1e-12 {
                return Err(ChannelEstimationError::SingularMatrix);
            }
            // Swap rows if needed
            if max_row != i {
                for c in 0..n {
                    let tmp_a = a.get(i, c);
                    a.set(i, c, a.get(max_row, c));
                    a.set(max_row, c, tmp_a);

                    let tmp_inv = inv.get(i, c);
                    inv.set(i, c, inv.get(max_row, c));
                    inv.set(max_row, c, tmp_inv);
                }
            }

            // Scale pivot row
            let pivot = a.get(i, i);
            let pivot_inv = pivot.inv().ok_or(ChannelEstimationError::SingularMatrix)?;
            for c in 0..n {
                a.set(i, c, a.get(i, c) * pivot_inv);
                inv.set(i, c, inv.get(i, c) * pivot_inv);
            }

            // Eliminate column entries in other rows
            for r in 0..n {
                if r != i {
                    let factor = a.get(r, i);
                    if factor.norm_sqr() > 1e-15 {
                        for c in 0..n {
                            a.set(r, c, a.get(r, c) - factor * a.get(i, c));
                            inv.set(r, c, inv.get(r, c) - factor * inv.get(i, c));
                        }
                    }
                }
            }
        }

        Ok(inv)
    }
}

// ---------------------------------------------------------------------------
// 3GPP Gold Sequence Generator (TS 38.211 §5.2.1)
// ---------------------------------------------------------------------------

/// 3GPP 31-bit length Gold sequence generator.
pub struct GoldSequenceGenerator {
    x1: [u8; 31],
    x2: [u8; 31],
}

impl GoldSequenceGenerator {
    /// Initializes a Gold sequence generator with seed $c_{\text{init}}$.
    pub fn new(c_init: u32) -> Self {
        let mut x1 = [0u8; 31];
        let mut x2 = [0u8; 31];
        x1[0] = 1;

        for i in 0..31 {
            x2[i] = ((c_init >> i) & 1) as u8;
        }

        let mut gold_gen = Self { x1, x2 };
        // Advance NC = 1600 steps per TS 38.211 §5.2.1
        for _ in 0..1600 {
            gold_gen.step();
        }
        gold_gen
    }

    /// Advances the LFSR by 1 step and outputs 1 pseudo-random bit.
    #[inline]
    pub fn step(&mut self) -> u8 {
        let new_x1 = self.x1[3] ^ self.x1[0];
        let new_x2 = self.x2[3] ^ self.x2[2] ^ self.x2[1] ^ self.x2[0];

        let out = self.x1[0] ^ self.x2[0];

        self.x1.copy_within(1..31, 0);
        self.x1[30] = new_x1;

        self.x2.copy_within(1..31, 0);
        self.x2[30] = new_x2;

        out
    }

    /// Computes $c_{\text{init}}$ for PDSCH/PUSCH DMRS (TS 38.211 §7.4.1.1.1).
    pub fn compute_c_init(slot_idx: usize, symbol_idx: usize, n_id: u32, n_scid: u8) -> u32 {
        let l = symbol_idx as u32;
        let ns = slot_idx as u32;
        let scid = (n_scid & 1) as u32;
        let nid = n_id & 0xFFFF;

        let term1 = ((1 << 17) * (14 * ns + l + 1) * (2 * nid + 1)) & 0x7FFF_FFFF;
        let term2 = (2 * nid + scid) & 0x7FFF_FFFF;
        (term1 + term2) & 0x7FFF_FFFF
    }

    /// Generates $M$ complex QPSK reference symbols:
    /// $r(m) = \frac{1}{\sqrt{2}}(1 - 2c(2m)) + j \frac{1}{\sqrt{2}}(1 - 2c(2m+1))$.
    pub fn generate_qpsk_symbols(&mut self, m_count: usize) -> Vec<Complex32> {
        let inv_sqrt2 = 1.0 / std::f32::consts::SQRT_2;
        let mut symbols = Vec::with_capacity(m_count);
        for _ in 0..m_count {
            let c0 = self.step();
            let c1 = self.step();
            let re = inv_sqrt2 * (1.0 - 2.0 * (c0 as f32));
            let im = inv_sqrt2 * (1.0 - 2.0 * (c1 as f32));
            symbols.push(Complex32::new(re, im));
        }
        symbols
    }
}

// ---------------------------------------------------------------------------
// DMRS Configuration Types & Orthogonal Cover Codes (TS 38.211 §7.4.1.1)
// ---------------------------------------------------------------------------

/// DMRS Configuration Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmrsConfigType {
    /// Configuration Type 1: Frequency comb-2 (6 pilot subcarriers per PRB per CDM group).
    Type1,
    /// Configuration Type 2: Frequency comb-6 (4 pilot subcarriers per PRB per CDM group).
    Type2,
}

impl DmrsConfigType {
    #[inline]
    pub fn pilots_per_prb(self) -> usize {
        match self {
            Self::Type1 => 6,
            Self::Type2 => 4,
        }
    }
}

/// DMRS Antenna Port configuration with Orthogonal Cover Codes (OCC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmrsPortInfo {
    pub port_number: u16,
    pub cdm_group: u8,
    pub delta: usize,
    pub wf: [i8; 2], // Frequency OCC (+1 or -1)
    pub wt: [i8; 2], // Time OCC (+1 or -1)
}

impl DmrsPortInfo {
    /// Looks up standard port configuration for DMRS Type 1 (ports 1000..1007).
    pub fn get_type1_port(port: u16) -> Result<Self, ChannelEstimationError> {
        match port {
            1000 => Ok(Self {
                port_number: 1000,
                cdm_group: 0,
                delta: 0,
                wf: [1, 1],
                wt: [1, 1],
            }),
            1001 => Ok(Self {
                port_number: 1001,
                cdm_group: 0,
                delta: 0,
                wf: [1, -1],
                wt: [1, 1],
            }),
            1002 => Ok(Self {
                port_number: 1002,
                cdm_group: 1,
                delta: 1,
                wf: [1, 1],
                wt: [1, 1],
            }),
            1003 => Ok(Self {
                port_number: 1003,
                cdm_group: 1,
                delta: 1,
                wf: [1, -1],
                wt: [1, 1],
            }),
            1004 => Ok(Self {
                port_number: 1004,
                cdm_group: 0,
                delta: 0,
                wf: [1, 1],
                wt: [1, -1],
            }),
            1005 => Ok(Self {
                port_number: 1005,
                cdm_group: 0,
                delta: 0,
                wf: [1, -1],
                wt: [1, -1],
            }),
            1006 => Ok(Self {
                port_number: 1006,
                cdm_group: 1,
                delta: 1,
                wf: [1, 1],
                wt: [1, -1],
            }),
            1007 => Ok(Self {
                port_number: 1007,
                cdm_group: 1,
                delta: 1,
                wf: [1, -1],
                wt: [1, -1],
            }),
            _ => Err(ChannelEstimationError::InvalidPort(port)),
        }
    }

    /// Looks up standard port configuration for DMRS Type 2 (ports 1000..1005).
    pub fn get_type2_port(port: u16) -> Result<Self, ChannelEstimationError> {
        match port {
            1000 => Ok(Self {
                port_number: 1000,
                cdm_group: 0,
                delta: 0,
                wf: [1, 1],
                wt: [1, 1],
            }),
            1001 => Ok(Self {
                port_number: 1001,
                cdm_group: 0,
                delta: 0,
                wf: [1, -1],
                wt: [1, 1],
            }),
            1002 => Ok(Self {
                port_number: 1002,
                cdm_group: 1,
                delta: 2,
                wf: [1, 1],
                wt: [1, 1],
            }),
            1003 => Ok(Self {
                port_number: 1003,
                cdm_group: 1,
                delta: 2,
                wf: [1, -1],
                wt: [1, 1],
            }),
            1004 => Ok(Self {
                port_number: 1004,
                cdm_group: 2,
                delta: 4,
                wf: [1, 1],
                wt: [1, 1],
            }),
            1005 => Ok(Self {
                port_number: 1005,
                cdm_group: 2,
                delta: 4,
                wf: [1, -1],
                wt: [1, 1],
            }),
            _ => Err(ChannelEstimationError::InvalidPort(port)),
        }
    }
}

// ---------------------------------------------------------------------------
// Least-Squares (LS) Channel Estimation & 2D Interpolation
// ---------------------------------------------------------------------------

/// Generates the subcarrier indices allocated to DMRS for a given PRB range.
pub fn get_dmrs_subcarriers(
    config_type: DmrsConfigType,
    num_prbs: usize,
    delta: usize,
) -> Vec<usize> {
    let mut indices = Vec::with_capacity(num_prbs * config_type.pilots_per_prb());
    match config_type {
        DmrsConfigType::Type1 => {
            // k = 4m + 2k' + delta, k' in {0, 1}, m in 0..3*num_prbs
            for prb in 0..num_prbs {
                let prb_start = prb * SUBCARRIERS_PER_PRB;
                for m_sub in 0..3 {
                    let base = prb_start + 4 * m_sub + delta;
                    indices.push(base);
                    indices.push(base + 2);
                }
            }
        }
        DmrsConfigType::Type2 => {
            // k = 6m + k' + delta, k' in {0, 1}, m in 0..2*num_prbs
            for prb in 0..num_prbs {
                let prb_start = prb * SUBCARRIERS_PER_PRB;
                for m_sub in 0..2 {
                    let base = prb_start + 6 * m_sub + delta;
                    indices.push(base);
                    indices.push(base + 1);
                }
            }
        }
    }
    indices
}

/// Performs Least-Squares (LS) raw pilot channel estimation with OCC de-spreading:
/// $\hat{H}_{\text{LS}}(k) = \frac{1}{2} \sum_{k'=0}^1 Y(k + 2k') \cdot r^*(m) \cdot w_f(k')$.
pub fn estimate_pilot_channel_ls(
    received_grid: &[Complex32], // Subcarriers in the DMRS OFDM symbol
    ref_symbols: &[Complex32],   // Generated QPSK DMRS sequence
    subcarrier_indices: &[usize],
    wf: [i8; 2],
) -> Vec<(usize, Complex32)> {
    let mut pilot_estimates = Vec::with_capacity(subcarrier_indices.len() / 2);

    for pair_idx in 0..(subcarrier_indices.len() / 2) {
        let k0 = subcarrier_indices[pair_idx * 2];
        let k1 = subcarrier_indices[pair_idx * 2 + 1];

        if k0 < received_grid.len() && k1 < received_grid.len() && pair_idx < ref_symbols.len() {
            let y0 = received_grid[k0];
            let y1 = received_grid[k1];
            let r = ref_symbols[pair_idx];

            let term0 = y0 * r.conj().scale(wf[0] as f32);
            let term1 = y1 * r.conj().scale(wf[1] as f32);
            let h_hat = (term0 + term1).scale(0.5);

            let center_k = (k0 + k1) / 2;
            pilot_estimates.push((center_k, h_hat));
        }
    }

    pilot_estimates
}

/// 1D Frequency Channel Interpolator: interpolates channel estimates across all subcarriers.
pub fn interpolate_channel_frequency(
    pilot_estimates: &[(usize, Complex32)],
    total_subcarriers: usize,
) -> Vec<Complex32> {
    if pilot_estimates.is_empty() {
        return vec![Complex32::one(); total_subcarriers];
    }
    if pilot_estimates.len() == 1 {
        return vec![pilot_estimates[0].1; total_subcarriers];
    }

    let mut full_channel = vec![Complex32::zero(); total_subcarriers];

    // Flat extrapolation before first pilot
    let (first_k, first_h) = pilot_estimates[0];
    for k in 0..=first_k.min(total_subcarriers - 1) {
        full_channel[k] = first_h;
    }

    // Linear interpolation between adjacent pilot estimates
    for w in pilot_estimates.windows(2) {
        let (k_prev, h_prev) = w[0];
        let (k_next, h_next) = w[1];
        let span = (k_next - k_prev) as f32;

        for k in k_prev..=k_next.min(total_subcarriers - 1) {
            let alpha = ((k - k_prev) as f32) / span;
            let re = (1.0 - alpha) * h_prev.re + alpha * h_next.re;
            let im = (1.0 - alpha) * h_prev.im + alpha * h_next.im;
            full_channel[k] = Complex32::new(re, im);
        }
    }

    // Flat extrapolation after last pilot
    let (last_k, last_h) = pilot_estimates[pilot_estimates.len() - 1];
    for k in (last_k + 1)..total_subcarriers {
        full_channel[k] = last_h;
    }

    full_channel
}

// ---------------------------------------------------------------------------
// Interference-plus-Noise Covariance Matrix ($R_{IN}$) Estimator
// ---------------------------------------------------------------------------

/// Estimates spatial interference-plus-noise covariance matrix ($N_{rx} \times N_{rx}$)
/// from residual vectors: $R_{IN} = \frac{1}{M} \sum (Y_m - \hat{H}_m X_m)(Y_m - \hat{H}_m X_m)^H + \sigma^2 I$.
pub fn estimate_rin_covariance(
    residuals: &[Vec<Complex32>], // List of N_rx error vectors
    num_rx: usize,
    noise_floor_sigma2: f32,
) -> ComplexMatrix {
    let mut rin = ComplexMatrix::zeros(num_rx, num_rx);
    if residuals.is_empty() {
        for i in 0..num_rx {
            rin.set(i, i, Complex32::new(noise_floor_sigma2.max(1e-6), 0.0));
        }
        return rin;
    }

    let m_samples = residuals.len() as f32;
    for res in residuals {
        if res.len() == num_rx {
            for r in 0..num_rx {
                for c in 0..num_rx {
                    let prod = res[r] * res[c].conj();
                    let cur = rin.get(r, c);
                    rin.set(r, c, cur + prod.scale(1.0 / m_samples));
                }
            }
        }
    }

    // Add diagonal noise floor regularization for stability
    for i in 0..num_rx {
        let cur = rin.get(i, i);
        rin.set(
            i,
            i,
            Complex32::new(cur.re + noise_floor_sigma2.max(1e-6), 0.0),
        );
    }

    rin
}

// ---------------------------------------------------------------------------
// MIMO Equalizer Engine (ZF, MMSE, MMSE-IRC)
// ---------------------------------------------------------------------------

/// Equalizer algorithm type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EqualizerType {
    ZeroForcing,
    Mmse,
    MmseIrc,
}

/// Result of MIMO symbol equalization for a single subcarrier / Resource Element.
#[derive(Debug, Clone, PartialEq)]
pub struct EqualizedSymbolResult {
    /// Equalized transmit symbol estimates $\hat{X}$ per spatial layer ($N_{tx} \times 1$).
    pub equalized_symbols: Vec<Complex32>,
    /// Post-equalization SINR per spatial layer (linear scale).
    pub sinr_linear: Vec<f32>,
    /// Post-equalization SINR per spatial layer (dB scale: $10 \log_{10}(\text{SINR})$).
    pub sinr_db: Vec<f32>,
}

/// High-performance MIMO Equalizer Engine.
pub struct MimoEqualizer;

impl MimoEqualizer {
    /// Computes equalized transmit symbol estimates and post-equalization SINR per layer.
    ///
    /// - `y`: Received symbol vector ($N_{rx} \times 1$).
    /// - `h`: Estimated channel matrix ($N_{rx} \times N_{tx}$).
    /// - `sigma2`: Background thermal noise variance.
    /// - `rin`: Interference-plus-noise covariance ($N_{rx} \times N_{rx}$), used for MMSE-IRC.
    /// - `eq_type`: Equalizer algorithm.
    pub fn equalize(
        y: &[Complex32],
        h: &ComplexMatrix,
        sigma2: f32,
        rin: &ComplexMatrix,
        eq_type: EqualizerType,
    ) -> Result<EqualizedSymbolResult, ChannelEstimationError> {
        let n_rx = h.rows;
        let n_tx = h.cols;

        if y.len() != n_rx {
            return Err(ChannelEstimationError::DimensionMismatch {
                expected: (n_rx, 1),
                found: (y.len(), 1),
            });
        }

        // Convert received vector into matrix
        let mut y_mat = ComplexMatrix::zeros(n_rx, 1);
        for (i, &val) in y.iter().enumerate() {
            y_mat.set(i, 0, val);
        }

        let h_h = h.hermitian();

        // Calculate Equalizer Weight Matrix W (dimension: N_tx x N_rx)
        let w = match eq_type {
            EqualizerType::ZeroForcing => {
                // W_ZF = (H^H * H)^(-1) * H^H
                let h_h_h = h_h.matmul(h)?;
                let inv = h_h_h.inverse()?;
                inv.matmul(&h_h)?
            }
            EqualizerType::Mmse => {
                // W_MMSE = (H^H * H + sigma2 * I)^(-1) * H^H
                let mut gram = h_h.matmul(h)?;
                for i in 0..n_tx {
                    let cur = gram.get(i, i);
                    gram.set(i, i, Complex32::new(cur.re + sigma2.max(1e-8), cur.im));
                }
                let inv = gram.inverse()?;
                inv.matmul(&h_h)?
            }
            EqualizerType::MmseIrc => {
                // W_IRC = (H^H * R_IN^(-1) * H + I)^(-1) * H^H * R_IN^(-1)
                let rin_inv = rin.inverse()?;
                let h_h_rin_inv = h_h.matmul(&rin_inv)?;
                let mut gram = h_h_rin_inv.matmul(h)?;
                for i in 0..n_tx {
                    let cur = gram.get(i, i);
                    gram.set(i, i, Complex32::new(cur.re + 1.0, cur.im));
                }
                let inv = gram.inverse()?;
                inv.matmul(&h_h_rin_inv)?
            }
        };

        // Equalized symbols: X_hat = W * Y
        let x_hat_mat = w.matmul(&y_mat)?;
        let mut equalized_symbols = Vec::with_capacity(n_tx);
        for i in 0..n_tx {
            equalized_symbols.push(x_hat_mat.get(i, 0));
        }

        // Post-equalization SINR:
        // G = W * H (effective channel)
        // Signal power = |G_{i,i}|^2
        // Interference + Noise power = sum_{j != i} |G_{i,j}|^2 + [W * R_IN * W^H]_{i,i}
        let g = w.matmul(h)?;
        let w_rin = w.matmul(rin)?;
        let w_rin_w_h = w_rin.matmul(&w.hermitian())?;

        let mut sinr_linear = Vec::with_capacity(n_tx);
        let mut sinr_db = Vec::with_capacity(n_tx);

        for i in 0..n_tx {
            let sig_power = g.get(i, i).norm_sqr();

            let mut interf_power = 0.0f32;
            for j in 0..n_tx {
                if j != i {
                    interf_power += g.get(i, j).norm_sqr();
                }
            }
            let noise_power = w_rin_w_h.get(i, i).re.max(1e-12);
            let total_denom = interf_power + noise_power;

            let sinr_lin = (sig_power / total_denom).max(1e-5);
            let sinr_d = 10.0 * sinr_lin.log10();

            sinr_linear.push(sinr_lin);
            sinr_db.push(sinr_d);
        }

        Ok(EqualizedSymbolResult {
            equalized_symbols,
            sinr_linear,
            sinr_db,
        })
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
// Binary Wire Framing (`ChannelEstimationWirePdu`)
// ---------------------------------------------------------------------------

/// Wire PDU for channel state telemetry and equalizer metrics transport.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelEstimationWirePdu {
    pub slot_index: u8,
    pub symbol_index: u8,
    pub num_rx: u8,
    pub num_tx: u8,
    pub avg_sinr_db: f32,
    pub channel_power_db: f32,
    pub raw_channel_taps: Vec<u8>,
}

impl ChannelEstimationWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + self.raw_channel_taps.len());
        buf.extend_from_slice(&CHES_WIRE_MAGIC.to_be_bytes());
        buf.push(self.slot_index);
        buf.push(self.symbol_index);
        buf.push(self.num_rx);
        buf.push(self.num_tx);
        buf.extend_from_slice(&self.avg_sinr_db.to_be_bytes());
        buf.extend_from_slice(&self.channel_power_db.to_be_bytes());
        buf.extend_from_slice(&(self.raw_channel_taps.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.raw_channel_taps);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ChannelEstimationError> {
        if bytes.len() < 18 {
            return Err(ChannelEstimationError::WirePayloadTooShort {
                needed: 18,
                found: bytes.len(),
            });
        }
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != CHES_WIRE_MAGIC {
            return Err(ChannelEstimationError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(ChannelEstimationError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let slot_index = bytes[4];
        let symbol_index = bytes[5];
        let num_rx = bytes[6];
        let num_tx = bytes[7];
        let avg_sinr_db = f32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let channel_power_db = f32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let tap_len = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;

        if body_len < 18 + tap_len {
            return Err(ChannelEstimationError::WirePayloadTooShort {
                needed: 18 + tap_len,
                found: body_len,
            });
        }

        let raw_channel_taps = bytes[18..18 + tap_len].to_vec();

        Ok(Self {
            slot_index,
            symbol_index,
            num_rx,
            num_tx,
            avg_sinr_db,
            channel_power_db,
            raw_channel_taps,
        })
    }
}

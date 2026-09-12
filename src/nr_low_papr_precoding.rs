//! 3GPP Release 18/19 5G-Advanced Low-PAPR Waveform Shaping & Transform Precoding Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §6.3.1.5: "Transform precoding" for PUSCH (DFT-spread-OFDM).
//! - 3GPP TS 38.214 Rel-18 §6.1: Uplink coverage enhancements and modulation schemes.
//! - 3GPP TR 38.830 / RP-213599: Frequency-Domain Spectral Shaping (FDSS) for DFT-s-OFDM.
//! - 3GPP TS 38.101-1 §6.2.2: Maximum Power Reduction (MPR) and Cubic Metric (CM) evaluation.
//!
//! This module implements pure-Rust 5G-Advanced low-PAPR waveform processing:
//! 1. Double-precision Complex arithmetic and discrete Fourier transforms (DFT/IDFT).
//! 2. Modulation mappers: $\pi/2$-BPSK with phase rotation ($e^{j \frac{\pi}{2} n}$), QPSK, 16QAM.
//! 3. Rel-18 Frequency-Domain Spectral Shaping (FDSS) filter banks:
//!    - Raised Cosine (RC) roll-off.
//!    - Root Raised Cosine (RRC) roll-off.
//!    - Half-Sine roll-off.
//!    - Subcarrier power preservation and spectral energy normalization.
//! 4. Continuous-time analog envelope synthesis with $K_{\text{os}}\ge 4$ oversampling.
//! 5. Statistical analytics: Peak-to-Average Power Ratio (PAPR in dB), 3GPP Cubic Metric (CM),
//!    and empirical Complementary Cumulative Distribution Function (CCDF).
//! 6. Power Amplifier (PA) Maximum Power Reduction (MPR) and cell-edge coverage extension modeling.
//! 7. Binary wire serialization and CRC-16 CCITT integrity verification.

use std::f64::consts::PI;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for Low-PAPR PDU: "PAPR" (0x50415052).
pub const LOW_PAPR_MAGIC: u32 = 0x50415052;

/// Standard CRC-16 CCITT polynomial ($x^{16} + x^{12} + x^5 + 1$).
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Standard subcarriers per Physical Resource Block in 5G NR.
pub const SUBCARRIERS_PER_PRB: usize = 12;

/// Reference RMS 3rd-order normalized voltage for WCDMA/QPSK baseline (3GPP TS 36.101 / 38.101).
pub const V_REF_RMS_CUBIC_WCDMA: f64 = 1.52;

/// Errors returned by the Low-PAPR engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LowPaprError {
    InvalidPrbCount(usize),
    EmptyData,
    InvalidBitStreamLength { expected: usize, actual: usize },
    InvalidRollOffFactor(String),
    SerializationError(String),
    DeserializationError(String),
    CrcMismatch { expected: u16, actual: u16 },
    InvalidMagic(u32),
}

impl fmt::Display for LowPaprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrbCount(prb) => write!(f, "Invalid PRB count: {}", prb),
            Self::EmptyData => write!(f, "Data payload cannot be empty"),
            Self::InvalidBitStreamLength { expected, actual } => {
                write!(
                    f,
                    "Invalid bit length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidRollOffFactor(msg) => write!(f, "Invalid roll-off factor: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "CRC-16 mismatch: expected 0x{:04X}, computed 0x{:04X}",
                    expected, actual
                )
            }
            Self::InvalidMagic(m) => write!(f, "Invalid PDU magic: 0x{:08X}", m),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure Rust Complex64 Numerical Representation
// ---------------------------------------------------------------------------

/// Double-precision complex number.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex64 {
    pub re: f64,
    pub im: f64,
}

impl Complex64 {
    pub const ZERO: Self = Self { re: 0.0, im: 0.0 };
    pub const ONE: Self = Self { re: 1.0, im: 0.0 };
    pub const I: Self = Self { re: 0.0, im: 1.0 };

    #[inline]
    pub fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    #[inline]
    pub fn from_polar(r: f64, theta: f64) -> Self {
        Self {
            re: r * theta.cos(),
            im: r * theta.sin(),
        }
    }

    #[inline]
    pub fn norm_sqr(self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    #[inline]
    pub fn abs(self) -> f64 {
        self.norm_sqr().sqrt()
    }

    #[inline]
    pub fn arg(self) -> f64 {
        self.im.atan2(self.re)
    }

    #[inline]
    pub fn conj(self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    #[inline]
    pub fn scale(self, factor: f64) -> Self {
        Self {
            re: self.re * factor,
            im: self.im * factor,
        }
    }
}

impl std::ops::Add for Complex64 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }
}

impl std::ops::Sub for Complex64 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self {
            re: self.re - rhs.re,
            im: self.im - rhs.im,
        }
    }
}

impl std::ops::Mul for Complex64 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }
}

// ---------------------------------------------------------------------------
// Discrete Fourier Transform & Inverse DFT
// ---------------------------------------------------------------------------

/// Computes forward $M$-point normalized discrete Fourier transform:
/// $$X[k] = \frac{1}{\sqrt{M}} \sum_{n=0}^{M-1} x[n] e^{-j 2\pi k n / M}$$
pub fn dft(input: &[Complex64]) -> Vec<Complex64> {
    let m = input.len();
    if m == 0 {
        return Vec::new();
    }
    let norm = 1.0 / (m as f64).sqrt();
    let mut output = Vec::with_capacity(m);

    for k in 0..m {
        let mut sum = Complex64::ZERO;
        for (n, &x_n) in input.iter().enumerate() {
            let angle = -2.0 * PI * (k as f64) * (n as f64) / (m as f64);
            let twiddle = Complex64::from_polar(1.0, angle);
            sum = sum + (x_n * twiddle);
        }
        output.push(sum.scale(norm));
    }

    output
}

/// Computes inverse $N$-point normalized discrete Fourier transform:
/// $$x[n] = \frac{1}{\sqrt{N}} \sum_{k=0}^{N-1} X[k] e^{j 2\pi k n / N}$$
pub fn idft(input: &[Complex64]) -> Vec<Complex64> {
    let n = input.len();
    if n == 0 {
        return Vec::new();
    }
    let norm = 1.0 / (n as f64).sqrt();
    let mut output = Vec::with_capacity(n);

    for idx in 0..n {
        let mut sum = Complex64::ZERO;
        for (k, &x_k) in input.iter().enumerate() {
            let angle = 2.0 * PI * (idx as f64) * (k as f64) / (n as f64);
            let twiddle = Complex64::from_polar(1.0, angle);
            sum = sum + (x_k * twiddle);
        }
        output.push(sum.scale(norm));
    }

    output
}

// ---------------------------------------------------------------------------
// Modulation Schemes
// ---------------------------------------------------------------------------

/// Supported uplink modulation schemes in 3GPP Rel-18/19.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModulationScheme {
    /// $\pi/2$-BPSK with phase rotation $e^{j \frac{\pi}{2} n}$ (lowest PAPR/CM).
    PiHalfBpsk,
    /// Standard Gray-coded QPSK.
    Qpsk,
    /// 16QAM for high data rates.
    Qam16,
}

impl ModulationScheme {
    /// Number of coded bits per constellation symbol.
    #[inline]
    pub fn bits_per_symbol(self) -> usize {
        match self {
            Self::PiHalfBpsk => 1,
            Self::Qpsk => 2,
            Self::Qam16 => 4,
        }
    }

    /// Modulates raw bit slice into complex symbol sequence.
    pub fn modulate(self, bits: &[u8]) -> Result<Vec<Complex64>, LowPaprError> {
        let bps = self.bits_per_symbol();
        if bits.is_empty() {
            return Err(LowPaprError::EmptyData);
        }
        if bits.len() % bps != 0 {
            return Err(LowPaprError::InvalidBitStreamLength {
                expected: ((bits.len() + bps - 1) / bps) * bps,
                actual: bits.len(),
            });
        }

        let num_symbols = bits.len() / bps;
        let mut symbols = Vec::with_capacity(num_symbols);

        match self {
            Self::PiHalfBpsk => {
                // 3GPP TS 38.211 §5.1.1: d(n) = e^{j * pi/2 * n} * (1 - 2*b(n)) / sqrt(2) or normalized
                // Unit energy normalization: (1 - 2*b(n)) has amplitude 1.0.
                for (n, &b) in bits.iter().enumerate() {
                    let bit_val = if b & 1 == 0 { 1.0 } else { -1.0 };
                    let phase = (PI / 2.0) * (n as f64);
                    let rotated = Complex64::from_polar(bit_val, phase);
                    symbols.push(rotated);
                }
            }
            Self::Qpsk => {
                // Standard QPSK: d(n) = 1/sqrt(2) * ((1 - 2*b(2n)) + j*(1 - 2*b(2n+1)))
                let inv_sqrt2 = 1.0 / (2.0f64).sqrt();
                for chunk in bits.chunks_exact(2) {
                    let re = if chunk[0] & 1 == 0 { 1.0 } else { -1.0 };
                    let im = if chunk[1] & 1 == 0 { 1.0 } else { -1.0 };
                    symbols.push(Complex64::new(re * inv_sqrt2, im * inv_sqrt2));
                }
            }
            Self::Qam16 => {
                // Standard 16QAM: Gray-coded with 1/sqrt(10) normalization
                let inv_sqrt10 = 1.0 / (10.0f64).sqrt();
                for chunk in bits.chunks_exact(4) {
                    let map_2bits = |b0: u8, b1: u8| -> f64 {
                        match (b0 & 1, b1 & 1) {
                            (0, 0) => 3.0,
                            (0, 1) => 1.0,
                            (1, 1) => -1.0,
                            (1, 0) => -3.0,
                            _ => 1.0,
                        }
                    };
                    let re = map_2bits(chunk[0], chunk[1]) * inv_sqrt10;
                    let im = map_2bits(chunk[2], chunk[3]) * inv_sqrt10;
                    symbols.push(Complex64::new(re, im));
                }
            }
        }

        Ok(symbols)
    }
}

// ---------------------------------------------------------------------------
// Rel-18 Frequency-Domain Spectral Shaping (FDSS)
// ---------------------------------------------------------------------------

/// Spectral shaping filter type specified in 3GPP Rel-18 TR 38.830.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdssFilterType {
    /// Rectangular window (Bypass FDSS, standard DFT-s-OFDM).
    Rectangular,
    /// Raised Cosine (RC) frequency roll-off filter.
    RaisedCosine,
    /// Root Raised Cosine (RRC) frequency roll-off filter.
    RootRaisedCosine,
    /// Half-Sine smooth edge transition filter.
    HalfSine,
}

/// Configuration for Rel-18 Frequency-Domain Spectral Shaping.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FdssConfig {
    pub filter_type: FdssFilterType,
    /// Roll-off factor $\alpha \in [0.0, 1.0]$.
    pub alpha: f64,
}

impl FdssConfig {
    pub fn new(filter_type: FdssFilterType, alpha: f64) -> Result<Self, LowPaprError> {
        if alpha < 0.0 || alpha > 1.0 {
            return Err(LowPaprError::InvalidRollOffFactor(format!(
                "Roll-off alpha {} must be in range [0.0, 1.0]",
                alpha
            )));
        }
        Ok(Self { filter_type, alpha })
    }

    /// Computes normalized filter response $W(k)$ of length $M$ subcarriers.
    /// Total energy is normalized so that $\sum_{k=0}^{M-1} W(k)^2 = M$.
    pub fn compute_filter_weights(&self, m: usize) -> Vec<f64> {
        if m == 0 {
            return Vec::new();
        }
        if self.filter_type == FdssFilterType::Rectangular || self.alpha <= 1e-6 {
            return vec![1.0; m];
        }

        // Transition width in subcarriers at each edge
        let transition_len = ((self.alpha * (m as f64)) / 2.0).round() as usize;
        let transition_len = transition_len.max(1).min(m / 2);

        let mut weights = vec![1.0; m];

        for i in 0..transition_len {
            let norm_x = (i as f64 + 0.5) / (transition_len as f64);
            let w = match self.filter_type {
                FdssFilterType::Rectangular => 1.0,
                FdssFilterType::RaisedCosine => 0.5 * (1.0 - (PI * norm_x).cos()),
                FdssFilterType::RootRaisedCosine => (0.5 * (1.0 - (PI * norm_x).cos())).sqrt(),
                FdssFilterType::HalfSine => (PI * 0.5 * norm_x).sin(),
            };
            weights[i] = w;
            weights[m - 1 - i] = w;
        }

        // Energy normalization: sum(w^2) = M
        let energy: f64 = weights.iter().map(|&w| w * w).sum();
        if energy > 0.0 {
            let scale = ((m as f64) / energy).sqrt();
            for w in &mut weights {
                *w *= scale;
            }
        }

        weights
    }

    /// Applies FDSS filter in-place to precoded frequency-domain subcarriers.
    pub fn apply_shaping(&self, subcarriers: &mut [Complex64]) {
        let weights = self.compute_filter_weights(subcarriers.len());
        for (sc, &w) in subcarriers.iter_mut().zip(weights.iter()) {
            *sc = sc.scale(w);
        }
    }
}

// ---------------------------------------------------------------------------
// Waveform Synthesizer
// ---------------------------------------------------------------------------

/// Waveform synthesis mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WaveformType {
    /// Conventional CP-OFDM (Cyclic Prefix OFDM).
    CpOfdm,
    /// DFT-spread-OFDM (Transform Precoding) with optional Rel-18 FDSS.
    DftSpreadOfdm { fdss: Option<FdssConfig> },
}

/// Synthesizes time-domain baseband waveforms with oversampling.
#[derive(Debug, Clone)]
pub struct WaveformSynthesizer {
    pub prb_count: usize,
    pub oversampling_factor: usize,
    pub cp_ratio: f64,
}

impl WaveformSynthesizer {
    pub fn new(prb_count: usize, oversampling_factor: usize) -> Result<Self, LowPaprError> {
        if prb_count == 0 || prb_count > 275 {
            return Err(LowPaprError::InvalidPrbCount(prb_count));
        }
        let os = oversampling_factor.max(4); // at least 4x oversampling for analog peak fidelity
        Ok(Self {
            prb_count,
            oversampling_factor: os,
            cp_ratio: 0.07, // ~7% normal CP
        })
    }

    /// Number of active allocated subcarriers $M = \text{PRBs} \times 12$.
    #[inline]
    pub fn num_subcarriers(&self) -> usize {
        self.prb_count * SUBCARRIERS_PER_PRB
    }

    /// Size of oversampled IFFT grid $N_{\text{grid}} = M \times K_{\text{os}}$.
    #[inline]
    pub fn grid_size(&self) -> usize {
        self.num_subcarriers() * self.oversampling_factor
    }

    /// Synthesizes continuous-time analog envelope samples from modulated symbols.
    pub fn synthesize(
        &self,
        symbols: &[Complex64],
        waveform: WaveformType,
    ) -> Result<Vec<Complex64>, LowPaprError> {
        let m = self.num_subcarriers();
        if symbols.len() != m {
            return Err(LowPaprError::InvalidBitStreamLength {
                expected: m,
                actual: symbols.len(),
            });
        }

        // 1. Transform Precoding / FDSS stage
        let precoded_sc = match waveform {
            WaveformType::CpOfdm => {
                // Direct subcarrier mapping (no DFT precoding)
                symbols.to_vec()
            }
            WaveformType::DftSpreadOfdm { fdss } => {
                // Forward M-point DFT precoding
                let mut dft_out = dft(symbols);
                if let Some(cfg) = fdss {
                    cfg.apply_shaping(&mut dft_out);
                }
                dft_out
            }
        };

        // 2. Subcarrier mapping to oversampled grid (centered with zero padding)
        let n_grid = self.grid_size();
        let mut grid = vec![Complex64::ZERO; n_grid];
        let offset = (n_grid - m) / 2;
        grid[offset..offset + m].copy_from_slice(&precoded_sc);

        // 3. Oversampled IDFT to generate continuous time-domain baseband samples
        let time_samples = idft(&grid);

        // 4. Prepend Cyclic Prefix
        let cp_len = ((n_grid as f64) * self.cp_ratio).round() as usize;
        let mut full_ofdm_symbol = Vec::with_capacity(n_grid + cp_len);
        full_ofdm_symbol.extend_from_slice(&time_samples[n_grid - cp_len..]);
        full_ofdm_symbol.extend_from_slice(&time_samples);

        Ok(full_ofdm_symbol)
    }
}

// ---------------------------------------------------------------------------
// Statistical Analytics: PAPR, Cubic Metric & CCDF
// ---------------------------------------------------------------------------

/// Detailed statistical report for a synthesized transmission burst.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PaprReport {
    /// Peak-to-Average Power Ratio in dB ($10 \log_{10}(P_{\text{peak}} / P_{\text{avg}})$).
    pub papr_db: f64,
    /// Linear ratio $P_{\text{peak}} / P_{\text{avg}}$.
    pub raw_papr: f64,
    /// 3GPP TS 38.101-1 Cubic Metric (CM in dB).
    pub cubic_metric_db: f64,
    /// Maximum instantaneous envelope power $|s(t)|^2$.
    pub peak_power: f64,
    /// Average envelope power $\mathbb{E}[|s(t)|^2]$.
    pub avg_power: f64,
}

/// Evaluates PAPR and 3GPP Cubic Metric for a time-domain signal.
pub fn evaluate_papr_and_cm(samples: &[Complex64]) -> Result<PaprReport, LowPaprError> {
    if samples.is_empty() {
        return Err(LowPaprError::EmptyData);
    }

    let mut peak_pwr = 0.0f64;
    let mut sum_pwr = 0.0f64;

    for s in samples {
        let pwr = s.norm_sqr();
        if pwr > peak_pwr {
            peak_pwr = pwr;
        }
        sum_pwr += pwr;
    }

    let avg_pwr = sum_pwr / (samples.len() as f64);
    if avg_pwr <= 1e-12 {
        return Ok(PaprReport {
            papr_db: 0.0,
            raw_papr: 1.0,
            cubic_metric_db: 0.0,
            peak_power: peak_pwr,
            avg_power: avg_pwr,
        });
    }

    let raw_papr = peak_pwr / avg_pwr;
    let papr_db = 10.0 * raw_papr.log10();

    // 3GPP Cubic Metric (CM) calculation:
    // v_norm(t) = |s(t)| / sqrt(avg_pwr)
    // rms_cubic = sqrt( 1/N * sum( (v_norm(t)^3)^2 ) ) = sqrt( 1/N * sum( v_norm(t)^6 ) )
    // CM = [ 20*log10(rms_cubic) - 20*log10(V_ref) ] / 1.85
    let inv_rms = 1.0 / avg_pwr.sqrt();
    let mut sum_v6 = 0.0f64;
    for s in samples {
        let v_norm = s.abs() * inv_rms;
        let v2 = v_norm * v_norm;
        let v6 = v2 * v2 * v2;
        sum_v6 += v6;
    }
    let rms_cubic = (sum_v6 / (samples.len() as f64)).sqrt();
    let cm_raw = (20.0 * rms_cubic.log10() - 20.0 * V_REF_RMS_CUBIC_WCDMA.log10()) / 1.85;
    let cubic_metric_db = cm_raw.max(0.0);

    Ok(PaprReport {
        papr_db,
        raw_papr,
        cubic_metric_db,
        peak_power: peak_pwr,
        avg_power: avg_pwr,
    })
}

/// Point on an empirical Complementary Cumulative Distribution Function (CCDF) curve.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CcdfPoint {
    pub threshold_papr_db: f64,
    pub probability: f64,
}

/// Generates an empirical CCDF curve $\text{Pr}(\text{PAPR} > \gamma)$ across Monte Carlo trials.
pub fn generate_empirical_ccdf(
    synthesizer: &WaveformSynthesizer,
    waveform: WaveformType,
    modulation: ModulationScheme,
    thresholds_db: &[f64],
    num_trials: usize,
    seed: u64,
) -> Result<Vec<CcdfPoint>, LowPaprError> {
    if num_trials == 0 {
        return Err(LowPaprError::EmptyData);
    }

    let m = synthesizer.num_subcarriers();
    let num_bits = m * modulation.bits_per_symbol();
    let mut papr_records = Vec::with_capacity(num_trials);

    let mut lcg_state = seed;
    let mut pseudo_rand_bit = || -> u8 {
        lcg_state = lcg_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((lcg_state >> 32) & 1) as u8
    };

    for _ in 0..num_trials {
        let bits: Vec<u8> = (0..num_bits).map(|_| pseudo_rand_bit()).collect();
        let symbols = modulation.modulate(&bits)?;
        let time_samples = synthesizer.synthesize(&symbols, waveform)?;
        let report = evaluate_papr_and_cm(&time_samples)?;
        papr_records.push(report.papr_db);
    }

    let mut ccdf_curve = Vec::with_capacity(thresholds_db.len());
    for &thresh in thresholds_db {
        let count_above = papr_records.iter().filter(|&&p| p > thresh).count();
        let prob = (count_above as f64) / (num_trials as f64);
        ccdf_curve.push(CcdfPoint {
            threshold_papr_db: thresh,
            probability: prob,
        });
    }

    Ok(ccdf_curve)
}

// ---------------------------------------------------------------------------
// Link Budget & Coverage Extension Model
// ---------------------------------------------------------------------------

/// Computes Maximum Power Reduction (MPR in dB) baseline per 3GPP TS 38.101-1 Table 6.2.2-1.
pub fn compute_mpr(waveform: WaveformType, modulation: ModulationScheme) -> f64 {
    match waveform {
        WaveformType::CpOfdm => match modulation {
            ModulationScheme::PiHalfBpsk => 1.5,
            ModulationScheme::Qpsk => 1.5,
            ModulationScheme::Qam16 => 2.5,
        },
        WaveformType::DftSpreadOfdm { fdss } => {
            let fdss_active = match fdss {
                Some(cfg) => cfg.filter_type != FdssFilterType::Rectangular && cfg.alpha > 0.0,
                None => false,
            };

            match modulation {
                ModulationScheme::PiHalfBpsk => {
                    if fdss_active {
                        0.0 // Rel-18 FDSS pi/2-BPSK achieves 0 dB MPR
                    } else {
                        0.5 // Standard pi/2-BPSK without FDSS
                    }
                }
                ModulationScheme::Qpsk => {
                    if fdss_active {
                        0.5 // Rel-18 FDSS QPSK reduces MPR
                    } else {
                        1.0 // Standard DFT-s-OFDM QPSK
                    }
                }
                ModulationScheme::Qam16 => {
                    if fdss_active {
                        1.5
                    } else {
                        2.0
                    }
                }
            }
        }
    }
}

/// Evaluates cell-edge coverage extension multiplier:
/// $$d_{\text{mult}} = 10^{\frac{\Delta P_{\text{tx}}}{10 \alpha}}$$
pub fn compute_coverage_distance_multiplier(
    baseline_waveform: WaveformType,
    baseline_mod: ModulationScheme,
    enhanced_waveform: WaveformType,
    enhanced_mod: ModulationScheme,
    pathloss_exponent: f64,
) -> f64 {
    let mpr_baseline = compute_mpr(baseline_waveform, baseline_mod);
    let mpr_enhanced = compute_mpr(enhanced_waveform, enhanced_mod);
    let delta_p_tx = mpr_baseline - mpr_enhanced; // positive gain in dB

    let alpha = if pathloss_exponent > 0.0 {
        pathloss_exponent
    } else {
        3.5
    };

    10.0f64.powf(delta_p_tx / (10.0 * alpha))
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

/// Serialized PDU transporting Low-PAPR operational configurations and telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct LowPaprConfigPdu {
    pub version: u8,
    pub waveform_type: u8, // 0 = CP-OFDM, 1 = DFT-s-OFDM
    pub modulation: u8,    // 0 = pi/2-BPSK, 1 = QPSK, 2 = 16QAM
    pub filter_type: u8,   // 0 = Rectangular, 1 = RC, 2 = RRC, 3 = HalfSine
    pub roll_off_alpha_x1000: u16,
    pub prb_count: u16,
    pub measured_papr_x100: u16,
    pub measured_cm_x100: u16,
    pub mpr_db_x100: u16,
}

impl LowPaprConfigPdu {
    pub const FIXED_WIRE_SIZE: usize = 4 + 1 + 1 + 1 + 1 + 2 + 2 + 2 + 2 + 2 + 2; // 20 bytes

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_WIRE_SIZE);
        buf.extend_from_slice(&LOW_PAPR_MAGIC.to_be_bytes());
        buf.push(self.version);
        buf.push(self.waveform_type);
        buf.push(self.modulation);
        buf.push(self.filter_type);
        buf.extend_from_slice(&self.roll_off_alpha_x1000.to_be_bytes());
        buf.extend_from_slice(&self.prb_count.to_be_bytes());
        buf.extend_from_slice(&self.measured_papr_x100.to_be_bytes());
        buf.extend_from_slice(&self.measured_cm_x100.to_be_bytes());
        buf.extend_from_slice(&self.mpr_db_x100.to_be_bytes());

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LowPaprError> {
        if bytes.len() < Self::FIXED_WIRE_SIZE {
            return Err(LowPaprError::DeserializationError(format!(
                "PDU length {} is less than required {}",
                bytes.len(),
                Self::FIXED_WIRE_SIZE
            )));
        }

        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != LOW_PAPR_MAGIC {
            return Err(LowPaprError::InvalidMagic(magic));
        }

        let payload_len = Self::FIXED_WIRE_SIZE - 2;
        let expected_crc = compute_crc16(&bytes[..payload_len]);
        let actual_crc = u16::from_be_bytes([bytes[payload_len], bytes[payload_len + 1]]);
        if expected_crc != actual_crc {
            return Err(LowPaprError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        let version = bytes[4];
        let waveform_type = bytes[5];
        let modulation = bytes[6];
        let filter_type = bytes[7];
        let roll_off_alpha_x1000 = u16::from_be_bytes([bytes[8], bytes[9]]);
        let prb_count = u16::from_be_bytes([bytes[10], bytes[11]]);
        let measured_papr_x100 = u16::from_be_bytes([bytes[12], bytes[13]]);
        let measured_cm_x100 = u16::from_be_bytes([bytes[14], bytes[15]]);
        let mpr_db_x100 = u16::from_be_bytes([bytes[16], bytes[17]]);

        Ok(Self {
            version,
            waveform_type,
            modulation,
            filter_type,
            roll_off_alpha_x1000,
            prb_count,
            measured_papr_x100,
            measured_cm_x100,
            mpr_db_x100,
        })
    }
}

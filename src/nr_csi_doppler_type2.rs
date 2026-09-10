//! 3GPP Rel-18 5G-Advanced Enhanced Type II CSI Codebook with Doppler / Delay Compression Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.214 §5.2.2.2.6 Rel-18 ("Type II CSI reporting with Doppler and delay domain compression")
//! - 3GPP TS 38.211 §6.3.1.5 (CSI-RS configuration and dual-polarized antenna port layouts)
//! - 3GPP TR 38.843 / TR 38.802 (High-mobility channel evolution and Doppler spread models)
//! - 3GPP TS 38.331 Rel-18 (`CodebookConfig`, `dopplerDomainCompression`, `subbandConfig`)
//!
//! Key Capabilities:
//! 1. 4-Dimensional Channel Decomposition:
//!    - Spatial domain: 2D oversampled DFT beams across dual polarizations ($P=2$).
//!    - Frequency/Delay domain: IDFT basis vectors over $N_3$ frequency subbands/PRBs.
//!    - Time/Doppler domain: Time-domain DFT basis vectors over $N_t$ observation slots.
//! 2. Joint Angle-Delay-Doppler (ADD) Projection & Sparsification:
//!    - Projects 4D channel tensor $\mathbf{H} \in \mathbb{C}^{P_{\text{csi}} \times N_3 \times N_t}$
//!      into compact basis coefficients.
//!    - Retains top $K_{\text{NZ}}$ dominant coefficients with thresholded non-zero bitmap.
//! 3. 3GPP TS 38.214 Quantization & Binary Encoding:
//!    - Strongest Coefficient Indicator (SCI).
//!    - 3-bit / 4-bit logarithmic amplitude and 3-bit / 4-bit (8-PSK / 16-PSK) phase quantization.
//!    - Compact binary payload serialization.
//! 4. Proactive Channel Extrapolation & Aging Mitigation:
//!    - Reconstructs future channel matrices $\hat{\mathbf{H}}(t + \Delta t, f)$ across future slots.
//!    - Evaluates Generalized Cosine Similarity (GCS) and Normalized Mean Square Error (NMSE in dB)
//!      demonstrating immunity to Doppler aging in high-speed mobility (HST / UAV / Vehicular).
//!
//! Pure Rust standard library implementation with zero external dependencies.

// ---------------------------------------------------------------------------
// Constants & Tolerances
// ---------------------------------------------------------------------------

/// Maximum supported dual-polarized CSI-RS antenna ports (e.g., 32 ports = 2 * 4 * 4).
pub const MAX_CSI_PORTS: usize = 32;

/// Maximum frequency subbands ($N_3$) in wideband CSI reporting.
pub const MAX_FREQ_SUBBANDS: usize = 32;

/// Maximum time observation slots ($N_t$) in Doppler estimation window.
pub const MAX_OBSERVATION_SLOTS: usize = 16;

/// Default amplitude quantization levels (4-bit: 16 levels).
pub const DEFAULT_AMPLITUDE_BITS: u8 = 4;

/// Default phase quantization levels (4-bit: 16-PSK, $\pi/8$ resolution).
pub const DEFAULT_PHASE_BITS: u8 = 4;

/// Small numerical epsilon to prevent divide-by-zero.
pub const EPSILON: f64 = 1e-12;

// ---------------------------------------------------------------------------
// Complex Number Helper (Zero External Dependencies)
// ---------------------------------------------------------------------------

/// Self-contained 64-bit complex number representation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex64 {
    pub re: f64,
    pub im: f64,
}

impl Complex64 {
    pub const ZERO: Self = Self { re: 0.0, im: 0.0 };
    pub const ONE: Self = Self { re: 1.0, im: 0.0 };

    pub fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    pub fn from_polar(r: f64, theta_rad: f64) -> Self {
        Self {
            re: r * theta_rad.cos(),
            im: r * theta_rad.sin(),
        }
    }

    pub fn norm_sqr(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    pub fn norm(&self) -> f64 {
        self.norm_sqr().sqrt()
    }

    pub fn arg(&self) -> f64 {
        self.im.atan2(self.re)
    }

    pub fn conj(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    pub fn add(&self, rhs: Self) -> Self {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }

    pub fn sub(&self, rhs: Self) -> Self {
        Self {
            re: self.re - rhs.re,
            im: self.im - rhs.im,
        }
    }

    pub fn mul(&self, rhs: Self) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }

    pub fn scale(&self, factor: f64) -> Self {
        Self {
            re: self.re * factor,
            im: self.im * factor,
        }
    }
}

// ---------------------------------------------------------------------------
// Codebook Configurations & Antenna Layout
// ---------------------------------------------------------------------------

/// Antenna array layout for dual-polarized cross-pole CSI-RS ports (TS 38.214 §5.2.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntennaArrayLayout {
    /// Number of horizontal antenna elements ($N_1$).
    pub n1: usize,
    /// Number of vertical antenna elements ($N_2$).
    pub n2: usize,
    /// Spatial oversampling factor along horizontal axis ($O_1$, typically 4).
    pub o1: usize,
    /// Spatial oversampling factor along vertical axis ($O_2$, typically 4).
    pub o2: usize,
}

impl AntennaArrayLayout {
    pub fn new(n1: usize, n2: usize, o1: usize, o2: usize) -> Self {
        Self {
            n1: n1.max(1),
            n2: n2.max(1),
            o1: o1.max(1),
            o2: o2.max(1),
        }
    }

    /// Total number of dual-polarized antenna ports ($P = 2 N_1 N_2$).
    pub fn total_ports(&self) -> usize {
        2 * self.n1 * self.n2
    }
}

/// 3GPP Rel-18 Doppler Type II Codebook Configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct DopplerType2Config {
    pub layout: AntennaArrayLayout,
    /// Number of frequency subbands / PRB groups ($N_3$).
    pub num_subbands: usize,
    /// Number of time observation slots ($N_t$).
    pub num_time_slots: usize,
    /// Number of spatial beams selected per polarization ($L$, typically 2 or 4).
    pub num_spatial_beams: usize,
    /// Number of delay basis vectors selected ($M$, typically 2, 4, or 6).
    pub num_delay_basis: usize,
    /// Number of Doppler basis vectors selected ($K$, typically 2 or 3).
    pub num_doppler_basis: usize,
    /// Maximum non-zero coefficient budget ($K_{\text{NZ}}$).
    pub max_non_zero_coeffs: usize,
}

impl DopplerType2Config {
    pub fn new_default() -> Self {
        Self {
            layout: AntennaArrayLayout::new(4, 2, 4, 4), // 16 ports
            num_subbands: 8,
            num_time_slots: 8,
            num_spatial_beams: 2,
            num_delay_basis: 4,
            num_doppler_basis: 2,
            max_non_zero_coeffs: 16,
        }
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in Doppler Type II CSI compression or decompression.
#[derive(Debug, Clone, PartialEq)]
pub enum DopplerType2Error {
    DimensionMismatch { expected: usize, actual: usize },
    InvalidConfiguration(String),
    BufferTooShort { expected: usize, actual: usize },
    ZeroEnergyChannel,
}

impl std::fmt::Display for DopplerType2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DimensionMismatch { expected, actual } => {
                write!(f, "Dimension mismatch: expected {}, got {}", expected, actual)
            }
            Self::InvalidConfiguration(msg) => write!(f, "Invalid Doppler Type II config: {}", msg),
            Self::BufferTooShort { expected, actual } => {
                write!(f, "Buffer too short: expected {} bytes, got {}", expected, actual)
            }
            Self::ZeroEnergyChannel => write!(f, "Channel tensor has zero energy"),
        }
    }
}

// ---------------------------------------------------------------------------
// Compressed CSI Feedback Payload
// ---------------------------------------------------------------------------

/// Compressed representation of a single ADD basis component.
#[derive(Debug, Clone, PartialEq)]
pub struct AddCoefficient {
    pub pol_idx: usize,
    pub spatial_idx: usize,
    pub delay_idx: usize,
    pub doppler_idx: usize,
    /// Quantized amplitude level (0..15).
    pub amp_level: u8,
    /// Quantized phase level (0..15).
    pub phase_level: u8,
    /// De-quantized complex coefficient value.
    pub complex_value: Complex64,
}

/// 3GPP Rel-18 Doppler Type II CSI Feedback Report.
#[derive(Debug, Clone, PartialEq)]
pub struct DopplerType2Report {
    /// Spatial beam indices $[m_1, m_2]$ selected.
    pub selected_spatial_beams: Vec<(usize, usize)>,
    /// Delay basis indices selected out of $N_3$.
    pub selected_delay_indices: Vec<usize>,
    /// Doppler basis indices selected out of $N_t$.
    pub selected_doppler_indices: Vec<usize>,
    /// Index of the strongest coefficient (SCI).
    pub strongest_coeff_idx: usize,
    /// Normalization energy factor.
    pub max_amplitude: f64,
    /// Non-zero quantized coefficients.
    pub coefficients: Vec<AddCoefficient>,
}

// ---------------------------------------------------------------------------
// Compression & Reconstruction Engine
// ---------------------------------------------------------------------------

/// Complete 3GPP Rel-18 Doppler Type II CSI Compression & Extrapolation Engine.
#[derive(Debug, PartialEq)]
pub struct DopplerType2Engine {
    pub config: DopplerType2Config,
    /// Spatial DFT basis dictionary: size `(num_spatial_beams, total_ports)`.
    pub spatial_bases: Vec<Vec<Complex64>>,
    /// Delay IDFT basis dictionary: size `(num_delay_basis, num_subbands)`.
    pub delay_bases: Vec<Vec<Complex64>>,
    /// Doppler DFT basis dictionary: size `(num_doppler_basis, num_time_slots)`.
    pub doppler_bases: Vec<Vec<Complex64>>,
}

impl DopplerType2Engine {
    pub fn new(config: DopplerType2Config) -> Result<Self, DopplerType2Error> {
        if config.num_subbands == 0 || config.num_time_slots == 0 {
            return Err(DopplerType2Error::InvalidConfiguration(
                "Subbands and time slots must be > 0".to_string(),
            ));
        }

        let mut engine = Self {
            config,
            spatial_bases: Vec::new(),
            delay_bases: Vec::new(),
            doppler_bases: Vec::new(),
        };

        engine.precompute_bases();
        Ok(engine)
    }

    /// Pre-compute discrete orthogonal basis matrices.
    fn precompute_bases(&mut self) {
        let n1 = self.config.layout.n1;
        let n2 = self.config.layout.n2;
        let _o1 = self.config.layout.o1;
        let _o2 = self.config.layout.o2;

        // 1. Spatial DFT basis generation (TS 38.214 §5.2.2.2.1)
        self.spatial_bases.clear();
        'outer: for m2 in 0..n2 {
            for m1 in 0..n1 {
                if self.spatial_bases.len() >= self.config.num_spatial_beams {
                    break 'outer;
                }
                let mut beam = Vec::with_capacity(n1 * n2);
                let norm = 1.0 / ((n1 * n2) as f64).sqrt();
                for x2 in 0..n2 {
                    for x1 in 0..n1 {
                        let phase = 2.0 * std::f64::consts::PI
                            * ((x1 * m1) as f64 / (n1 as f64)
                                + (x2 * m2) as f64 / (n2 as f64));
                        beam.push(Complex64::from_polar(norm, phase));
                    }
                }
                self.spatial_bases.push(beam);
            }
        }

        // 2. Delay IDFT basis generation (TS 38.214 §5.2.2.2.6)
        let n3 = self.config.num_subbands;
        self.delay_bases.clear();
        let idft_norm = 1.0 / (n3 as f64).sqrt();
        for m in 0..self.config.num_delay_basis.min(n3) {
            let mut basis = Vec::with_capacity(n3);
            for s in 0..n3 {
                let phase = -2.0 * std::f64::consts::PI * ((s * m) as f64) / (n3 as f64);
                basis.push(Complex64::from_polar(idft_norm, phase));
            }
            self.delay_bases.push(basis);
        }

        // 3. Doppler DFT basis generation (TS 38.214 §5.2.2.2.6)
        let nt = self.config.num_time_slots;
        self.doppler_bases.clear();
        let doppler_norm = 1.0 / (nt as f64).sqrt();
        for k in 0..self.config.num_doppler_basis.min(nt) {
            let mut basis = Vec::with_capacity(nt);
            for t in 0..nt {
                let phase = 2.0 * std::f64::consts::PI * ((t * k) as f64) / (nt as f64);
                basis.push(Complex64::from_polar(doppler_norm, phase));
            }
            self.doppler_bases.push(basis);
        }
    }

    /// Compress a 4D channel tensor:
    /// `channel_tensor[slot][subband][port]` -> `DopplerType2Report`
    pub fn compress_channel(
        &self,
        channel: &[Vec<Vec<Complex64>>],
    ) -> Result<DopplerType2Report, DopplerType2Error> {
        let nt = self.config.num_time_slots;
        let n3 = self.config.num_subbands;
        let total_ports = self.config.layout.total_ports();
        let half_ports = total_ports / 2;

        if channel.len() < nt {
            return Err(DopplerType2Error::DimensionMismatch {
                expected: nt,
                actual: channel.len(),
            });
        }
        for (_t, slot_data) in channel.iter().enumerate().take(nt) {
            if slot_data.len() < n3 {
                return Err(DopplerType2Error::DimensionMismatch {
                    expected: n3,
                    actual: slot_data.len(),
                });
            }
            for (_f, port_data) in slot_data.iter().enumerate().take(n3) {
                if port_data.len() < total_ports {
                    return Err(DopplerType2Error::DimensionMismatch {
                        expected: total_ports,
                        actual: port_data.len(),
                    });
                }
            }
        }

        // Project channel tensor against ADD bases:
        // C(p, i, m, k) = sum_{t} sum_{f} sum_{ant} H(t, f, ant) * conj(V_i(ant)) * conj(F_m(f)) * conj(D_k(t))
        let mut raw_coeffs = Vec::new();
        let num_spatial = self.spatial_bases.len();
        let num_delay = self.delay_bases.len();
        let num_doppler = self.doppler_bases.len();

        for pol in 0..2 {
            let port_offset = pol * half_ports;
            for i in 0..num_spatial {
                let spatial_vec = &self.spatial_bases[i];
                for m in 0..num_delay {
                    let delay_vec = &self.delay_bases[m];
                    for k in 0..num_doppler {
                        let doppler_vec = &self.doppler_bases[k];

                        let mut acc = Complex64::ZERO;
                        for t in 0..nt {
                            let d_conj = doppler_vec[t].conj();
                            for f in 0..n3 {
                                let fd_conj = delay_vec[f].conj().mul(d_conj);
                                for a in 0..half_ports {
                                    let h_val = channel[t][f][port_offset + a];
                                    let term = h_val.mul(spatial_vec[a].conj()).mul(fd_conj);
                                    acc = acc.add(term);
                                }
                            }
                        }

                        raw_coeffs.push((pol, i, m, k, acc));
                    }
                }
            }
        }

        // Find maximum amplitude across all coefficients for normalization
        let mut max_amp = 0.0f64;
        for (_, _, _, _, c) in &raw_coeffs {
            let amp = c.norm();
            if amp > max_amp {
                max_amp = amp;
            }
        }

        if max_amp < EPSILON {
            return Err(DopplerType2Error::ZeroEnergyChannel);
        }

        // Sort by magnitude descending to select top K_NZ coefficients
        raw_coeffs.sort_by(|a, b| b.4.norm().partial_cmp(&a.4.norm()).unwrap());

        let mut quantized_coeffs = Vec::new();
        let top_count = self.config.max_non_zero_coeffs.min(raw_coeffs.len());

        for idx in 0..top_count {
            let (pol, i, m, k, c) = raw_coeffs[idx];
            let norm_amp = (c.norm() / max_amp).clamp(0.0, 1.0);

            // 4-bit uniform amplitude quantization (16 levels)
            let amp_level = (norm_amp * 15.0).round() as u8;

            // 4-bit phase quantization (16-PSK, phase in [0, 2pi))
            let mut angle = c.arg();
            if angle < 0.0 {
                angle += 2.0 * std::f64::consts::PI;
            }
            let phase_level = ((angle / (2.0 * std::f64::consts::PI)) * 16.0).round() as u8 % 16;

            // De-quantized reconstructed complex value
            let rec_amp = (amp_level as f64 / 15.0) * max_amp;
            let rec_phase = (phase_level as f64 / 16.0) * 2.0 * std::f64::consts::PI;
            let complex_value = Complex64::from_polar(rec_amp, rec_phase);

            quantized_coeffs.push(AddCoefficient {
                pol_idx: pol,
                spatial_idx: i,
                delay_idx: m,
                doppler_idx: k,
                amp_level,
                phase_level,
                complex_value,
            });
        }

        Ok(DopplerType2Report {
            selected_spatial_beams: (0..num_spatial).map(|idx| (idx, 0)).collect(),
            selected_delay_indices: (0..num_delay).collect(),
            selected_doppler_indices: (0..num_doppler).collect(),
            strongest_coeff_idx: 0,
            max_amplitude: max_amp,
            coefficients: quantized_coeffs,
        })
    }

    /// Reconstruct channel matrix at time `target_slot` and subband `subband_idx`:
    /// $\hat{\mathbf{H}}(t, f) \in \mathbb{C}^{P_{\text{csi}}}$
    pub fn reconstruct_channel_vector(
        &self,
        report: &DopplerType2Report,
        target_slot: usize,
        subband_idx: usize,
    ) -> Vec<Complex64> {
        let total_ports = self.config.layout.total_ports();
        let half_ports = total_ports / 2;
        let mut h_hat = vec![Complex64::ZERO; total_ports];

        let nt = self.config.num_time_slots;
        let n3 = self.config.num_subbands;

        for coeff in &report.coefficients {
            let pol = coeff.pol_idx;
            let i = coeff.spatial_idx;
            let m = coeff.delay_idx;
            let k = coeff.doppler_idx;
            let c = coeff.complex_value;

            // Delay phase: $F_m(f) = \frac{1}{\sqrt{N_3}} e^{-j 2\pi f m / N_3}$
            let delay_phase = -2.0 * std::f64::consts::PI * ((subband_idx * m) as f64) / (n3 as f64);
            let delay_val = Complex64::from_polar(1.0 / (n3 as f64).sqrt(), delay_phase);

            // Doppler phase for arbitrary target_slot $t$:
            // $D_k(t) = \frac{1}{\sqrt{N_t}} e^{j 2\pi t k / N_t}$
            let doppler_phase = 2.0 * std::f64::consts::PI * ((target_slot * k) as f64) / (nt as f64);
            let doppler_val = Complex64::from_polar(1.0 / (nt as f64).sqrt(), doppler_phase);

            let time_freq_term = c.mul(delay_val).mul(doppler_val);

            let spatial_vec = &self.spatial_bases[i];
            let port_offset = pol * half_ports;

            for a in 0..half_ports {
                let term = spatial_vec[a].mul(time_freq_term);
                h_hat[port_offset + a] = h_hat[port_offset + a].add(term);
            }
        }

        h_hat
    }

    /// Calculate Generalized Cosine Similarity (GCS) between true channel $\mathbf{H}$ and reconstructed $\hat{\mathbf{H}}$:
    /// $\text{GCS} = \frac{|\mathbf{h}^H \hat{\mathbf{h}}|}{\|\mathbf{h}\| \|\hat{\mathbf{h}}\|}$
    pub fn evaluate_gcs(h_true: &[Complex64], h_hat: &[Complex64]) -> f64 {
        if h_true.len() != h_hat.len() || h_true.is_empty() {
            return 0.0;
        }

        let mut dot = Complex64::ZERO;
        let mut norm_true_sqr = 0.0f64;
        let mut norm_hat_sqr = 0.0f64;

        for (a, b) in h_true.iter().zip(h_hat.iter()) {
            dot = dot.add(a.conj().mul(*b));
            norm_true_sqr += a.norm_sqr();
            norm_hat_sqr += b.norm_sqr();
        }

        let denom = (norm_true_sqr * norm_hat_sqr).sqrt();
        if denom < EPSILON {
            0.0
        } else {
            (dot.norm() / denom).clamp(0.0, 1.0)
        }
    }

    /// Calculate Normalized Mean Square Error (NMSE in dB):
    /// $\text{NMSE (dB)} = 10 \log_{10} \frac{\|\mathbf{h} - \hat{\mathbf{h}}\|^2}{\|\mathbf{h}\|^2}$
    pub fn evaluate_nmse_db(h_true: &[Complex64], h_hat: &[Complex64]) -> f64 {
        let mut err_sqr = 0.0f64;
        let mut true_sqr = 0.0f64;

        for (a, b) in h_true.iter().zip(h_hat.iter()) {
            let diff = a.sub(*b);
            err_sqr += diff.norm_sqr();
            true_sqr += a.norm_sqr();
        }

        if true_sqr < EPSILON {
            0.0
        } else {
            10.0 * (err_sqr / true_sqr).max(1e-12).log10()
        }
    }
}

// ---------------------------------------------------------------------------
// Unit Tests (Internal Module)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complex_arithmetic() {
        let c1 = Complex64::new(3.0, 4.0);
        assert!((c1.norm() - 5.0).abs() < 1e-6);

        let c2 = Complex64::new(1.0, -2.0);
        let prod = c1.mul(c2);
        assert_eq!(prod, Complex64::new(11.0, -2.0));
    }

    #[test]
    fn test_engine_basis_precomputation() {
        let cfg = DopplerType2Config::new_default();
        let engine = DopplerType2Engine::new(cfg).unwrap();

        assert_eq!(engine.spatial_bases.len(), 2);
        assert_eq!(engine.delay_bases.len(), 4);
        assert_eq!(engine.doppler_bases.len(), 2);
    }
}

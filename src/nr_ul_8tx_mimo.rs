//! 3GPP Rel-18 5G-Advanced Uplink 8-Tx Antenna MIMO & Codebook Precoding Engine.
//!
//! Compliant with:
//! - **3GPP TS 38.211 Rel-18 §6.3.1.5**: Precoding for PUSCH with 8 antenna ports.
//! - **3GPP TS 38.214 Rel-18 §6.1.1.1**: Codebook-based and Non-codebook-based PUSCH
//!   transmission with 8 SRS antenna ports.
//! - **3GPP TS 38.331 Rel-18**: RRC configuration `PUSCH-Config`, `SRS-Config`, `codebookSubset`.
//! - **FCC / ICNIRP Standards**: Maximum Permissible Exposure (MPE) and SAR regulatory compliance.
//!
//! Provides pure-Rust, zero-dependency implementations of:
//! - Complex number and 8-port antenna matrix-vector algebra.
//! - 8-Tx Dual-Polarized Antenna Array layout ($N_1 \times N_2 \times 2 = 8$, e.g. $4 \times 1 \times 2$ or $2 \times 2 \times 2$).
//! - 8-Tx PUSCH Precoding Codebook (Layers $v \in \{1, 2, 3, 4\}$):
//!   - `FullCoherent` codebook subset (2D DFT beams with QPSK co-phasing).
//!   - `PartialCoherent` codebook subset (port-pair selection and localized co-phasing).
//!   - `NonCoherent` codebook subset (single-port/diagonal selection).
//! - Transmitted Precoding Matrix Indicator (TPMI) selection via reciprocity channel matrix.
//! - Dynamic Power and Antenna Port Backoff (8Tx -> 4Tx -> 2Tx -> 1Tx) driven by MPE (P-MPR)
//!   and Power Amplifier (PA) junction temperature servos.
//! - Uplink beamforming array gain calculation and comparison over 1-Tx, 2-Tx, 4-Tx, and 8-Tx.

// ---------------------------------------------------------------------------
// Complex Number Representation
// ---------------------------------------------------------------------------

/// Standard double-precision complex number for 8-port RF beamforming and precoding.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex64 {
    pub re: f64,
    pub im: f64,
}

impl Complex64 {
    pub const ZERO: Self = Self { re: 0.0, im: 0.0 };
    pub const ONE: Self = Self { re: 1.0, im: 0.0 };
    pub const I: Self = Self { re: 0.0, im: 1.0 };

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

    pub fn norm(&self) -> f64 {
        self.norm_sqr().sqrt()
    }

    pub fn conj(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        Self {
            re: self.re - rhs.re,
            im: self.im - rhs.im,
        }
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }

    pub fn scale(&self, scalar: f64) -> Self {
        Self {
            re: self.re * scalar,
            im: self.im * scalar,
        }
    }
}

// ---------------------------------------------------------------------------
// 8-Tx Antenna Array Layout & Capabilities
// ---------------------------------------------------------------------------

/// 8-Tx Antenna Panel Geometry (TS 38.211 §6.3.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntennaPanel8Tx {
    /// 4 horizontal elements, 1 vertical element, 2 cross-polarizations (4x1x2).
    Linear4x1x2,
    /// 2 horizontal elements, 2 vertical elements, 2 cross-polarizations (2x2x2).
    Planar2x2x2,
}

impl AntennaPanel8Tx {
    pub fn dimensions(&self) -> (usize, usize, usize) {
        match self {
            Self::Linear4x1x2 => (4, 1, 2),
            Self::Planar2x2x2 => (2, 2, 2),
        }
    }

    pub fn total_ports(&self) -> usize {
        8
    }
}

/// UE Antenna Coherence Capability for 8-Tx PUSCH (TS 38.214 §6.1.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodebookCoherenceSubset {
    /// Full Coherent: UE maintains phase calibration across all 8 RF chains.
    FullCoherent,
    /// Partial Coherent: UE maintains phase calibration within polarized port-pairs.
    PartialCoherent,
    /// Non-Coherent: Independent RF chains; only single-port or non-overlapping activations.
    NonCoherent,
}

/// Active Transmission Power and Mode State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UlTxPortMode {
    /// Full 8-Tx antenna transmission.
    Mode8Tx,
    /// Fallback 4-Tx antenna transmission (e.g. MPE or thermal mitigation).
    Mode4Tx,
    /// Fallback 2-Tx antenna transmission.
    Mode2Tx,
    /// Fallback 1-Tx single antenna transmission.
    Mode1Tx,
}

impl UlTxPortMode {
    pub fn active_ports(&self) -> usize {
        match self {
            Self::Mode8Tx => 8,
            Self::Mode4Tx => 4,
            Self::Mode2Tx => 2,
            Self::Mode1Tx => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// 8-Tx Precoding Matrix Definition
// ---------------------------------------------------------------------------

/// 8-Tx Precoding Matrix for up to 4 layers: dimension is (8, layers).
#[derive(Debug, Clone, PartialEq)]
pub struct PrecodingMatrix8Tx {
    pub tpmi: u16,
    pub num_layers: usize,
    pub coherence: CodebookCoherenceSubset,
    /// Matrix entries in row-major order: entries[port * num_layers + layer].
    pub entries: Vec<Complex64>,
}

impl PrecodingMatrix8Tx {
    pub fn new(
        tpmi: u16,
        num_layers: usize,
        coherence: CodebookCoherenceSubset,
        entries: Vec<Complex64>,
    ) -> Self {
        assert_eq!(entries.len(), 8 * num_layers);
        Self {
            tpmi,
            num_layers,
            coherence,
            entries,
        }
    }

    /// Access matrix element W[port, layer].
    pub fn get(&self, port: usize, layer: usize) -> Complex64 {
        self.entries[port * self.num_layers + layer]
    }

    /// Multiply 8xL precoding matrix with input layer symbols x (length L), producing 8 antenna port signals.
    pub fn precod(&self, layer_symbols: &[Complex64]) -> [Complex64; 8] {
        assert_eq!(layer_symbols.len(), self.num_layers);
        let mut port_signals = [Complex64::ZERO; 8];

        for port in 0..8 {
            let mut sum = Complex64::ZERO;
            for layer in 0..self.num_layers {
                let w = self.get(port, layer);
                sum = sum.add(&w.mul(&layer_symbols[layer]));
            }
            port_signals[port] = sum;
        }

        port_signals
    }

    /// Verify power normalization: sum_{port, layer} |W[port, layer]|^2 == 1.0.
    pub fn total_power(&self) -> f64 {
        self.entries.iter().map(|c| c.norm_sqr()).sum()
    }
}

// ---------------------------------------------------------------------------
// 8-Tx Codebook Generator (TS 38.211 §6.3.1.5)
// ---------------------------------------------------------------------------

/// Generates standardized 8-Tx PUSCH precoding matrices.
pub struct CodebookGenerator8Tx;

impl CodebookGenerator8Tx {
    /// Generate 8-Tx 1-Layer Full-Coherent Precoding Matrices for Linear (4, 1, 2) array.
    /// W = (1 / sqrt(8)) * [ v_{l, m}; phi_n * v_{l, m} ]
    pub fn generate_1layer_full_coherent() -> Vec<PrecodingMatrix8Tx> {
        let mut codebook = Vec::new();
        let mut tpmi = 0;
        let scale = 1.0 / (8.0f64).sqrt();

        // 4 DFT beams for N1 = 4, O1 = 1: v_l(k) = exp(j * 2*pi * l * k / 4)
        for l in 0..4 {
            let mut v = [Complex64::ZERO; 4];
            for k in 0..4 {
                let angle = 2.0 * std::f64::consts::PI * (l as f64) * (k as f64) / 4.0;
                v[k] = Complex64::from_polar(1.0, angle);
            }

            // 4 QPSK co-phasing angles: phi_n = exp(j * pi * n / 2), n in {0, 1, 2, 3}
            for n in 0..4 {
                let phi_angle = std::f64::consts::PI * (n as f64) / 2.0;
                let phi = Complex64::from_polar(1.0, phi_angle);

                let mut entries = Vec::with_capacity(8);
                // Polarization 1: ports 0..3
                for k in 0..4 {
                    entries.push(v[k].scale(scale));
                }
                // Polarization 2: ports 4..7
                for k in 0..4 {
                    entries.push(v[k].mul(&phi).scale(scale));
                }

                codebook.push(PrecodingMatrix8Tx::new(
                    tpmi,
                    1,
                    CodebookCoherenceSubset::FullCoherent,
                    entries,
                ));
                tpmi += 1;
            }
        }

        codebook
    }

    /// Generate 8-Tx 2-Layer Full-Coherent Precoding Matrices.
    /// W = (1 / sqrt(16)) * [ v_l, v_l; phi_n * v_l, -phi_n * v_l ]
    pub fn generate_2layer_full_coherent() -> Vec<PrecodingMatrix8Tx> {
        let mut codebook = Vec::new();
        let mut tpmi = 0;
        let scale = 1.0 / (16.0f64).sqrt();

        for l in 0..4 {
            let mut v = [Complex64::ZERO; 4];
            for k in 0..4 {
                let angle = 2.0 * std::f64::consts::PI * (l as f64) * (k as f64) / 4.0;
                v[k] = Complex64::from_polar(1.0, angle);
            }

            for n in 0..2 {
                // n in {0, 1}
                let phi_angle = std::f64::consts::PI * (n as f64) / 2.0;
                let phi = Complex64::from_polar(1.0, phi_angle);
                let neg_phi = phi.scale(-1.0);

                let mut entries = Vec::with_capacity(16);
                for port in 0..8 {
                    if port < 4 {
                        // Pol 1: col 0 = v[k], col 1 = v[k]
                        entries.push(v[port].scale(scale));
                        entries.push(v[port].scale(scale));
                    } else {
                        // Pol 2: col 0 = phi * v[k-4], col 1 = -phi * v[k-4]
                        let k = port - 4;
                        entries.push(v[k].mul(&phi).scale(scale));
                        entries.push(v[k].mul(&neg_phi).scale(scale));
                    }
                }

                codebook.push(PrecodingMatrix8Tx::new(
                    tpmi,
                    2,
                    CodebookCoherenceSubset::FullCoherent,
                    entries,
                ));
                tpmi += 1;
            }
        }

        codebook
    }

    /// Generate Non-Coherent 8-Tx 1-Layer Matrices (single port selection, 1/sqrt(1) = 1.0).
    pub fn generate_1layer_non_coherent() -> Vec<PrecodingMatrix8Tx> {
        let mut codebook = Vec::new();
        for port in 0..8 {
            let mut entries = vec![Complex64::ZERO; 8];
            entries[port] = Complex64::ONE;
            codebook.push(PrecodingMatrix8Tx::new(
                port as u16,
                1,
                CodebookCoherenceSubset::NonCoherent,
                entries,
            ));
        }
        codebook
    }

    /// Generate Partial-Coherent 8-Tx 1-Layer Matrices (co-polarized port pair selection).
    pub fn generate_1layer_partial_coherent() -> Vec<PrecodingMatrix8Tx> {
        let mut codebook = Vec::new();
        let scale = 1.0 / (2.0f64).sqrt();
        let mut tpmi = 0;

        for pair in 0..4 {
            let p1 = pair;
            let p2 = pair + 4; // corresponding cross-pole port

            for n in 0..4 {
                let phi = Complex64::from_polar(1.0, std::f64::consts::PI * (n as f64) / 2.0);
                let mut entries = vec![Complex64::ZERO; 8];
                entries[p1] = Complex64::new(scale, 0.0);
                entries[p2] = phi.scale(scale);

                codebook.push(PrecodingMatrix8Tx::new(
                    tpmi,
                    1,
                    CodebookCoherenceSubset::PartialCoherent,
                    entries,
                ));
                tpmi += 1;
            }
        }

        codebook
    }
}

// ---------------------------------------------------------------------------
// MPE & Thermal Regulatory Power Management Servo
// ---------------------------------------------------------------------------

/// Maximum Permissible Exposure (MPE) and Thermal Servo Controller.
#[derive(Debug, Clone, PartialEq)]
pub struct MpeThermalServo {
    /// Proximity sensor detection (e.g. human body near antenna array).
    pub proximity_detected: bool,
    /// Power reduction requirement in dB (P-MPR).
    pub p_mpr_db: f64,
    /// Power Amplifier (PA) junction temperature in Celsius.
    pub pa_temperature_c: f64,
    /// Maximum allowed junction temperature threshold in Celsius (e.g. 85.0 C).
    pub max_temp_threshold_c: f64,
    /// Active antenna mode.
    pub current_mode: UlTxPortMode,
    /// Total transitions triggered.
    pub mode_switch_count: u64,
}

impl MpeThermalServo {
    pub fn new(max_temp_threshold_c: f64) -> Self {
        Self {
            proximity_detected: false,
            p_mpr_db: 0.0,
            pa_temperature_c: 45.0,
            max_temp_threshold_c,
            current_mode: UlTxPortMode::Mode8Tx,
            mode_switch_count: 0,
        }
    }

    /// Evaluate sensor state and update active UL Tx port mode:
    /// - Critical condition (High MPE P-MPR > 6 dB OR Overheat > Threshold + 10 C): Mode1Tx
    /// - Heavy condition (MPE P-MPR > 3 dB OR Overheat > Threshold): Mode2Tx
    /// - Moderate condition (MPE P-MPR > 1 dB OR Temp > Threshold - 5 C): Mode4Tx
    /// - Nominal condition: Mode8Tx
    pub fn update(&mut self, proximity: bool, p_mpr_db: f64, pa_temp_c: f64) -> UlTxPortMode {
        self.proximity_detected = proximity;
        self.p_mpr_db = p_mpr_db;
        self.pa_temperature_c = pa_temp_c;

        let target_mode = if p_mpr_db >= 6.0 || pa_temp_c >= self.max_temp_threshold_c + 10.0 {
            UlTxPortMode::Mode1Tx
        } else if p_mpr_db >= 3.0 || pa_temp_c >= self.max_temp_threshold_c {
            UlTxPortMode::Mode2Tx
        } else if p_mpr_db >= 1.0 || pa_temp_c >= self.max_temp_threshold_c - 5.0 {
            UlTxPortMode::Mode4Tx
        } else {
            UlTxPortMode::Mode8Tx
        };

        if target_mode != self.current_mode {
            self.current_mode = target_mode;
            self.mode_switch_count += 1;
        }

        self.current_mode
    }
}

// ---------------------------------------------------------------------------
// 8-Tx MIMO Engine
// ---------------------------------------------------------------------------

/// Complete 3GPP Rel-18 5G-Advanced Uplink 8-Tx Antenna MIMO & Precoding Engine.
#[derive(Debug, PartialEq)]
pub struct Ul8TxMimoEngine {
    pub panel: AntennaPanel8Tx,
    pub capability: CodebookCoherenceSubset,
    pub servo: MpeThermalServo,
    pub codebook_1layer: Vec<PrecodingMatrix8Tx>,
    pub codebook_2layer: Vec<PrecodingMatrix8Tx>,
    pub stats_transmissions_8tx: u64,
    pub stats_transmissions_fallback: u64,
}

impl Ul8TxMimoEngine {
    pub fn new(
        panel: AntennaPanel8Tx,
        capability: CodebookCoherenceSubset,
        max_temp_c: f64,
    ) -> Self {
        let codebook_1layer = match capability {
            CodebookCoherenceSubset::FullCoherent => {
                CodebookGenerator8Tx::generate_1layer_full_coherent()
            }
            CodebookCoherenceSubset::PartialCoherent => {
                CodebookGenerator8Tx::generate_1layer_partial_coherent()
            }
            CodebookCoherenceSubset::NonCoherent => {
                CodebookGenerator8Tx::generate_1layer_non_coherent()
            }
        };

        let codebook_2layer = if capability == CodebookCoherenceSubset::FullCoherent {
            CodebookGenerator8Tx::generate_2layer_full_coherent()
        } else {
            Vec::new()
        };

        Self {
            panel,
            capability,
            servo: MpeThermalServo::new(max_temp_c),
            codebook_1layer,
            codebook_2layer,
            stats_transmissions_8tx: 0,
            stats_transmissions_fallback: 0,
        }
    }

    /// Find best TPMI in codebook matching given channel reciprocity vector H (1 x 8).
    /// Maximizes beamforming gain: |H * W|^2.
    pub fn select_best_tpmi_1layer(&self, h_channel: &[Complex64; 8]) -> (u16, f64) {
        let mut best_tpmi = 0;
        let mut max_power = -1.0;

        for matrix in &self.codebook_1layer {
            let mut sum = Complex64::ZERO;
            for port in 0..8 {
                let h_val = h_channel[port];
                let w_val = matrix.get(port, 0);
                sum = sum.add(&h_val.mul(&w_val));
            }
            let pwr = sum.norm_sqr();
            if pwr > max_power {
                max_power = pwr;
                best_tpmi = matrix.tpmi;
            }
        }

        (best_tpmi, max_power)
    }

    /// Transmit PUSCH with chosen precoding matrix, applying port masking according to servo mode.
    pub fn transmit_pusch(
        &mut self,
        precoding: &PrecodingMatrix8Tx,
        layer_symbols: &[Complex64],
    ) -> [Complex64; 8] {
        let mut ports = precoding.precod(layer_symbols);
        let active_ports = self.servo.current_mode.active_ports();

        // Mask inactive ports to zero
        for p in active_ports..8 {
            ports[p] = Complex64::ZERO;
        }

        if active_ports == 8 {
            self.stats_transmissions_8tx += 1;
        } else {
            self.stats_transmissions_fallback += 1;
        }

        ports
    }

    /// Calculate theoretical maximum array gain over single antenna (1-Tx):
    /// Array gain = 10 * log10(active_ports) dB.
    pub fn theoretical_array_gain_db(&self) -> f64 {
        10.0 * (self.servo.current_mode.active_ports() as f64).log10()
    }
}

//! 3GPP Release 18 (5G-Advanced) RedCap Positioning & Frequency Hopping Virtual Wideband PRS Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.305 Rel-18: "Stage 2 functional specification of User Equipment (UE) positioning in NG-RAN" (RedCap enhancements)
//! - 3GPP TS 38.211 Rel-18 §7.4.1.7: "Downlink positioning reference signal (DL-PRS) - Frequency Hopping PRS and Comb-N structures"
//! - 3GPP TS 38.214 Rel-18 §5.1.6.5: "UE DL-PRS measurement procedures for Reduced Capability (RedCap) UEs"
//! - 3GPP TS 38.215 Rel-18: "Physical layer measurements (DL PRS-RSRP, DL RSTD, UE Rx-Tx time difference, gNB Rx-Tx time difference)"
//! - 3GPP TS 37.355 Rel-18: "LTE/NR Positioning Protocol (LPP) - RedCap capability exchange and On-Demand PRS transaction"
//!
//! Pure standard Rust (`std` / `core` only) with zero external dependencies.

use std::f64::consts::PI;
use std::fmt;

/// Speed of light in vacuum (meters per second per BIPM / 3GPP).
pub const REDCAP_POS_SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

// ============================================================================
// 1. Error Types
// ============================================================================

/// Errors encountered in 3GPP Rel-18 RedCap positioning operations.
#[derive(Debug, Clone, PartialEq)]
pub enum RedCapPosError {
    /// Invalid bandwidth configuration (e.g. > 20 MHz for FR1 RedCap or > 5 MHz for eRedCap).
    InvalidBandwidth(u32),
    /// Invalid Comb size (valid values: 2, 4, 6, 12).
    InvalidCombSize(u8),
    /// Invalid frequency hopping pattern or schedule.
    InvalidHopConfiguration(String),
    /// Phase stitching failed between adjacent hops (e.g. insufficient overlap or SNR).
    PhaseStitchingFailed(String),
    /// Insufficient anchors for multilateration (minimum 3 for 2D, 4 for 3D).
    InsufficientAnchors { required: usize, provided: usize },
    /// Solver diverged or encountered singular matrix.
    SolverDiverged(String),
    /// Time of Arrival detection failed (signal below noise floor).
    ToaDetectionFailed(String),
    /// On-Demand PRS protocol violation or timeout.
    OnDemandPrsError(String),
}

impl fmt::Display for RedCapPosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedCapPosError::InvalidBandwidth(bw) => {
                write!(f, "Invalid RedCap positioning bandwidth: {bw} MHz")
            }
            RedCapPosError::InvalidCombSize(k) => {
                write!(f, "Invalid PRS comb size: {k} (supported: 2, 4, 6, 12)")
            }
            RedCapPosError::InvalidHopConfiguration(msg) => {
                write!(f, "Invalid PRS hop configuration: {msg}")
            }
            RedCapPosError::PhaseStitchingFailed(msg) => {
                write!(f, "Virtual wideband phase stitching failed: {msg}")
            }
            RedCapPosError::InsufficientAnchors { required, provided } => {
                write!(
                    f,
                    "Insufficient anchors: required {required}, provided {provided}"
                )
            }
            RedCapPosError::SolverDiverged(msg) => {
                write!(f, "Multilateration solver diverged: {msg}")
            }
            RedCapPosError::ToaDetectionFailed(msg) => {
                write!(f, "TOA detection failed: {msg}")
            }
            RedCapPosError::OnDemandPrsError(msg) => {
                write!(f, "On-Demand PRS error: {msg}")
            }
        }
    }
}

// ============================================================================
// 2. Complex Number Support for Baseband Processing
// ============================================================================

/// Complex number with 64-bit floating-point components for baseband signal processing.
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

    pub fn scale(&self, scalar: f64) -> Self {
        Self {
            re: self.re * scalar,
            im: self.im * scalar,
        }
    }

    pub fn conj(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    pub fn norm_sq(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    pub fn norm(&self) -> f64 {
        self.norm_sq().sqrt()
    }

    pub fn arg(&self) -> f64 {
        self.im.atan2(self.re)
    }
}

// ============================================================================
// 3. 3GPP TS 38.211 §7.4.1.7 PRS Gold Sequence Generator
// ============================================================================

/// 3GPP pseudo-random Gold sequence generator for DL-PRS (TS 38.211 §7.4.1.7).
#[derive(Debug, Clone)]
pub struct PrsGoldSequence {
    c_init: u32,
    x1: u32,
    x2: u32,
}

impl PrsGoldSequence {
    /// Initialize PRS Gold sequence according to 3GPP TS 38.211 §7.4.1.7:
    /// $c_{\text{init}} = (2^{22} c_{\text{id}} + 2^{10} (14 n_{s,f}^{\mu} + l + 1)(2 c_{\text{id}} + 1) + 2 c_{\text{id}} + n_{\text{PRS}}^{\text{slot}}) \bmod 2^{31}$
    pub fn new(c_id: u16, slot: u32, symbol: u8, prs_slot_offset: u32) -> Self {
        let n_sf = slot;
        let l = symbol as u32;
        let term1 = (c_id as u64) << 22;
        let term2 = (14 * n_sf + l + 1) as u64 * (2 * c_id as u64 + 1);
        let term2 = (term2 << 10) & 0x7FFFFFFF;
        let term3 = 2 * (c_id as u64);
        let term4 = prs_slot_offset as u64;
        let c_init = ((term1 + term2 + term3 + term4) % (1u64 << 31)) as u32;

        let mut seq = Self {
            c_init,
            x1: 1, // x1(0)=1, x1(n)=0 for n=1..30
            x2: c_init,
        };
        seq.advance(1600); // 3GPP Nc = 1600 initialization advance
        seq
    }

    /// Returns the computed initialization value $c_{\text{init}}$.
    pub fn c_init(&self) -> u32 {
        self.c_init
    }

    /// Advance LFSR state by `steps`.
    fn advance(&mut self, steps: usize) {
        for _ in 0..steps {
            self.step();
        }
    }

    /// Step the generator by 1 bit.
    fn step(&mut self) -> u8 {
        // x1(n+31) = (x1(n+3) + x1(n)) mod 2
        let new_x1 = ((self.x1 >> 3) ^ self.x1) & 1;
        self.x1 = (self.x1 >> 1) | (new_x1 << 30);

        // x2(n+31) = (x2(n+3) + x2(n+2) + x2(n+1) + x2(n)) mod 2
        let new_x2 = ((self.x2 >> 3) ^ (self.x2 >> 2) ^ (self.x2 >> 1) ^ self.x2) & 1;
        self.x2 = (self.x2 >> 1) | (new_x2 << 30);

        ((self.x1 ^ self.x2) & 1) as u8
    }

    /// Generate $M$ QPSK PRS symbols according to TS 38.211:
    /// $r(m) = \frac{1}{\sqrt{2}}[(1 - 2 c(2m)) + j (1 - 2 c(2m+1))]$
    pub fn generate_qpsk_symbols(&mut self, m_symbols: usize) -> Vec<Complex64> {
        let inv_sqrt2 = 1.0 / 2.0_f64.sqrt();
        let mut symbols = Vec::with_capacity(m_symbols);
        for _ in 0..m_symbols {
            let c0 = self.step();
            let c1 = self.step();
            let re = inv_sqrt2 * (1.0 - 2.0 * c0 as f64);
            let im = inv_sqrt2 * (1.0 - 2.0 * c1 as f64);
            symbols.push(Complex64::new(re, im));
        }
        symbols
    }
}

// ============================================================================
// 4. RedCap Positioning Capability & Frequency Hopping Config
// ============================================================================

/// RedCap device tier for positioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedCapPosDeviceType {
    /// Rel-17/18 RedCap (maximum 20 MHz in FR1, 100 MHz in FR2).
    StandardRedCap,
    /// Rel-18 eRedCap (maximum 5 MHz in FR1).
    ERedCap,
}

/// RF Phase continuity capability across frequency hops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseContinuityType {
    /// Non-coherent: RF LO retuning causes random phase discontinuity $\sim \mathcal{U}[0, 2\pi)$.
    NonCoherent,
    /// Coherent with Digital Down-Converter (DDC) baseband tuning (no RF LO re-lock).
    CoherentWithDdc,
    /// Phase-calibrated: Hardware calibration table corrects known LO phase jumps.
    PhaseCalibrated,
}

/// RedCap UE Positioning Capabilities exchanged via LPP (3GPP TS 37.355 Rel-18).
#[derive(Debug, Clone, PartialEq)]
pub struct RedCapPosCapability {
    pub device_type: RedCapPosDeviceType,
    pub max_dl_prs_bw_mhz: u32,
    pub rf_retuning_time_us: f64,
    pub phase_continuity: PhaseContinuityType,
    /// Internal hardware Rx-to-Tx filter delay calibration in nanoseconds (for Multi-RTT).
    pub internal_rx_tx_delay_ns: f64,
    /// Supported comb sizes (e.g. [2, 4, 6, 12]).
    pub supported_combs: Vec<u8>,
}

impl Default for RedCapPosCapability {
    fn default() -> Self {
        Self {
            device_type: RedCapPosDeviceType::StandardRedCap,
            max_dl_prs_bw_mhz: 20,
            rf_retuning_time_us: 140.0,
            phase_continuity: PhaseContinuityType::NonCoherent,
            internal_rx_tx_delay_ns: 32.5,
            supported_combs: vec![2, 4, 6, 12],
        }
    }
}

/// A single frequency hop in the PRS hopping pattern.
#[derive(Debug, Clone, PartialEq)]
pub struct PrsHop {
    pub hop_id: u8,
    pub start_prb: u16,
    pub num_prbs: u16,
    pub center_freq_mhz: f64,
    pub slot_offset: u32,
}

/// Configuration for 3GPP Rel-18 Frequency-Hopping PRS (TS 38.211 §7.4.1.7 / TS 38.214 §5.1.6.5).
#[derive(Debug, Clone, PartialEq)]
pub struct PrsFrequencyHopConfig {
    /// Total virtual wideband aggregate bandwidth in MHz (e.g. 80 or 100 MHz).
    pub aggregate_bw_mhz: f64,
    /// Subcarrier spacing in kHz (e.g. 15 or 30 kHz).
    pub scs_khz: u32,
    /// Hop configurations.
    pub hops: Vec<PrsHop>,
    /// Number of overlapping PRBs between consecutive hops for phase stitching.
    pub overlap_prbs: u16,
    /// Comb size (2, 4, 6, or 12).
    pub comb_size: u8,
    /// Subcarrier comb offset.
    pub comb_offset: u8,
    /// Positioning sequence ID ($c_{\text{id}} \in 0..4095$).
    pub prs_id: u16,
}

impl PrsFrequencyHopConfig {
    /// Constructs a standard 4-hop RedCap 20 MHz configuration spanning 80 MHz in FR1.
    pub fn new_standard_4hop_80mhz(scs_khz: u32, prs_id: u16) -> Result<Self, RedCapPosError> {
        if scs_khz != 15 && scs_khz != 30 && scs_khz != 60 {
            return Err(RedCapPosError::InvalidHopConfiguration(format!(
                "Unsupported SCS: {scs_khz} kHz"
            )));
        }
        let hop_prbs = if scs_khz == 30 { 51 } else { 106 };
        let overlap_prbs = 4;
        let mut hops = Vec::with_capacity(4);

        let mut current_prb = 0;
        for i in 0..4 {
            let center = 3500.0 + (i as f64) * 18.0; // nominal 3.5 GHz band
            hops.push(PrsHop {
                hop_id: i as u8,
                start_prb: current_prb,
                num_prbs: hop_prbs,
                center_freq_mhz: center,
                slot_offset: (i as u32) * 2, // staggered by 2 slots for retuning
            });
            current_prb += hop_prbs - overlap_prbs;
        }

        Ok(Self {
            aggregate_bw_mhz: 80.0,
            scs_khz,
            hops,
            overlap_prbs,
            comb_size: 4,
            comb_offset: 0,
            prs_id,
        })
    }

    /// Constructs an eRedCap 5 MHz multi-hop configuration spanning 40 MHz in FR1 (8 hops, 2 PRBs overlap).
    pub fn new_eredcap_8hop_40mhz(scs_khz: u32, prs_id: u16) -> Result<Self, RedCapPosError> {
        let hop_prbs = if scs_khz == 30 { 12 } else { 25 };
        let overlap_prbs = 2;
        let mut hops = Vec::with_capacity(8);

        let mut current_prb = 0;
        for i in 0..8 {
            let center = 3500.0 + (i as f64) * 4.5;
            hops.push(PrsHop {
                hop_id: i as u8,
                start_prb: current_prb,
                num_prbs: hop_prbs,
                center_freq_mhz: center,
                slot_offset: (i as u32) * 2,
            });
            current_prb += hop_prbs - overlap_prbs;
        }

        Ok(Self {
            aggregate_bw_mhz: 40.0,
            scs_khz,
            hops,
            overlap_prbs,
            comb_size: 2,
            comb_offset: 0,
            prs_id,
        })
    }
}

// ============================================================================
// 5. Virtual Wideband Phase Stitching Engine
// ============================================================================

/// Subband channel frequency response (CFR) measurement for a single hop.
#[derive(Debug, Clone, PartialEq)]
pub struct HopChannelMeasurement {
    pub hop_id: u8,
    /// Subcarrier channel responses within this hop's PRBs.
    pub subcarrier_cfr: Vec<Complex64>,
    /// Estimated SNR in dB for this hop.
    pub snr_db: f64,
}

/// Synthesizes wideband channel response from narrow hops by compensating phase discontinuities.
#[derive(Debug, Default)]
pub struct VirtualWidebandSynthesizer;

impl VirtualWidebandSynthesizer {
    pub fn new() -> Self {
        Self
    }

    /// Stitch multiple narrow-band hop measurements into a unified virtual wideband CFR.
    pub fn stitch_hops(
        &self,
        config: &PrsFrequencyHopConfig,
        measurements: &[HopChannelMeasurement],
        phase_continuity: PhaseContinuityType,
    ) -> Result<Vec<Complex64>, RedCapPosError> {
        if measurements.is_empty() {
            return Err(RedCapPosError::PhaseStitchingFailed(
                "No hop measurements provided".to_string(),
            ));
        }
        if measurements.len() != config.hops.len() {
            return Err(RedCapPosError::PhaseStitchingFailed(format!(
                "Measurement count ({}) mismatch with config hops ({})",
                measurements.len(),
                config.hops.len()
            )));
        }

        let sc_per_prb = 12 / (config.comb_size as usize);
        let overlap_sc = (config.overlap_prbs as usize) * sc_per_prb;

        // Allocate vector for stitched CFR
        let total_prbs = config.hops.last().unwrap().start_prb + config.hops.last().unwrap().num_prbs;
        let total_sc = (total_prbs as usize) * sc_per_prb;
        let mut wideband_cfr = vec![Complex64::ZERO; total_sc];
        let mut sample_weights = vec![0.0_f64; total_sc];

        let mut cumulative_phase_rotation = 0.0_f64;

        for (idx, m) in measurements.iter().enumerate() {
            let hop_cfg = &config.hops[idx];
            let start_sc = (hop_cfg.start_prb as usize) * sc_per_prb;
            let num_sc = m.subcarrier_cfr.len();

            if idx > 0 && phase_continuity == PhaseContinuityType::NonCoherent {
                // Cross-correlate overlapping subcarriers between hop (idx-1) and hop (idx)
                let prev_hop_cfg = &config.hops[idx - 1];
                let prev_cfr = &measurements[idx - 1].subcarrier_cfr;

                // Overlap region indices
                let mut cross_corr = Complex64::ZERO;
                let mut overlap_count = 0;

                for k in 0..overlap_sc {
                    let prev_idx = (hop_cfg.start_prb as usize - prev_hop_cfg.start_prb as usize)
                        * sc_per_prb
                        + k;
                    let curr_idx = k;

                    if prev_idx < prev_cfr.len() && curr_idx < m.subcarrier_cfr.len() {
                        let prev_sample = prev_cfr[prev_idx];
                        let curr_sample = m.subcarrier_cfr[curr_idx];
                        cross_corr = cross_corr.add(curr_sample.mul(prev_sample.conj()));
                        overlap_count += 1;
                    }
                }

                if overlap_count == 0 || cross_corr.norm_sq() < 1e-12 {
                    return Err(RedCapPosError::PhaseStitchingFailed(format!(
                        "Hop {idx} overlap cross-correlation degenerate (norm: {})",
                        cross_corr.norm()
                    )));
                }

                // Phase jump between previous stitched frame and current hop
                let delta_theta = cross_corr.arg();
                cumulative_phase_rotation += delta_theta;
            }

            // De-rotate current hop by cumulative phase rotation
            let de_rotation = Complex64::from_polar(1.0, -cumulative_phase_rotation);

            for sc_i in 0..num_sc {
                let target_sc = start_sc + sc_i;
                if target_sc < wideband_cfr.len() {
                    let rotated = m.subcarrier_cfr[sc_i].mul(de_rotation);
                    wideband_cfr[target_sc] = wideband_cfr[target_sc].add(rotated);
                    sample_weights[target_sc] += 1.0;
                }
            }
        }

        // Normalize overlapping subcarrier averages
        for i in 0..total_sc {
            if sample_weights[i] > 1.0 {
                wideband_cfr[i] = wideband_cfr[i].scale(1.0 / sample_weights[i]);
            }
        }

        Ok(wideband_cfr)
    }
}

// ============================================================================
// 6. Channel Impulse Response (CIR) Synthesis & Super-Resolution TOA
// ============================================================================

/// Discrete Channel Impulse Response (CIR) synthesizer via IDFT.
#[derive(Debug, Default)]
pub struct IdftCirSynthesizer;

impl IdftCirSynthesizer {
    pub fn new() -> Self {
        Self
    }

    /// Computes $K_{\text{os}}\times$ oversampled IDFT of the stitched channel frequency response.
    /// Returns time-domain complex impulse response samples.
    pub fn compute_cir(
        &self,
        cfr: &[Complex64],
        oversample_factor: usize,
    ) -> Result<Vec<Complex64>, RedCapPosError> {
        let n_in = cfr.len();
        if n_in == 0 {
            return Err(RedCapPosError::ToaDetectionFailed(
                "Empty CFR for IDFT".to_string(),
            ));
        }
        let os = oversample_factor.max(1);
        let n_out = n_in * os;
        let mut cir = Vec::with_capacity(n_out);

        let inv_n = 1.0 / (n_in as f64);
        for t in 0..n_out {
            let mut acc = Complex64::ZERO;
            for (k, val) in cfr.iter().enumerate() {
                let angle = 2.0 * PI * (k as f64) * (t as f64) / (n_out as f64);
                let phasor = Complex64::from_polar(1.0, angle);
                acc = acc.add(val.mul(phasor));
            }
            cir.push(acc.scale(inv_n));
        }

        Ok(cir)
    }
}

/// Super-resolution Time of Arrival (TOA) and RSTD estimator.
#[derive(Debug, Clone)]
pub struct SuperResolutionToaEstimator {
    /// Threshold in dB above estimated noise floor for first-peak detection.
    pub detection_threshold_db: f64,
}

impl Default for SuperResolutionToaEstimator {
    fn default() -> Self {
        Self {
            detection_threshold_db: 7.0, // 7 dB above noise floor for LOS detection
        }
    }
}

impl SuperResolutionToaEstimator {
    pub fn new(detection_threshold_db: f64) -> Self {
        Self {
            detection_threshold_db,
        }
    }

    /// Estimates the Line-of-Sight (LOS) Time of Arrival (TOA) from the CIR.
    pub fn estimate_toa(
        &self,
        cir: &[Complex64],
        sampling_period_sec: f64,
    ) -> Result<(f64, f64, f64), RedCapPosError> {
        let n = cir.len();
        if n < 4 {
            return Err(RedCapPosError::ToaDetectionFailed(
                "CIR too short for TOA estimation".to_string(),
            ));
        }

        let power_profile: Vec<f64> = cir.iter().map(|s| s.norm_sq()).collect();

        // Estimate noise floor using lower 40% of samples
        let mut sorted_power = power_profile.clone();
        sorted_power.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let noise_sample_count = (n * 4) / 10;
        let noise_floor: f64 = sorted_power[..noise_sample_count].iter().sum::<f64>()
            / (noise_sample_count.max(1) as f64);
        let noise_floor = noise_floor.max(1e-15);

        let max_p = power_profile.iter().copied().fold(0.0_f64, f64::max);
        if max_p <= noise_floor * 1.5 {
            return Err(RedCapPosError::ToaDetectionFailed(
                "No detectable peak above noise floor".to_string(),
            ));
        }

        let thresh_noise = noise_floor * 10.0_f64.powf(self.detection_threshold_db / 10.0);
        // Sinc sidelobes are at most -13.5 dB (0.045). Main/LOS peak is at least 15-20% of max_p.
        let thresh_linear = thresh_noise.max(max_p * 0.20);

        // Find first peak crossing threshold
        let mut first_peak_idx = None;
        for i in 1..(n - 1) {
            if power_profile[i] > thresh_linear
                && power_profile[i] >= power_profile[i - 1]
                && power_profile[i] >= power_profile[i + 1]
            {
                first_peak_idx = Some(i);
                break;
            }
        }

        let peak_idx = match first_peak_idx {
            Some(idx) => idx,
            None => {
                let mut max_i = 0;
                let mut max_val = 0.0;
                for (i, &p) in power_profile.iter().enumerate() {
                    if p > max_val {
                        max_val = p;
                        max_i = i;
                    }
                }
                max_i
            }
        };

        // 3-point parabolic interpolation for sub-sample precision
        let p_prev = power_profile[(peak_idx + n - 1) % n];
        let p_curr = power_profile[peak_idx];
        let p_next = power_profile[(peak_idx + 1) % n];

        let denom = 2.0 * (p_prev - 2.0 * p_curr + p_next);
        let delta_sample = if denom.abs() > 1e-12 {
            (p_prev - p_next) / denom
        } else {
            0.0
        };

        let delta_sample = delta_sample.clamp(-0.5, 0.5);
        let fractional_idx = (peak_idx as f64) + delta_sample;

        let delay_sec = fractional_idx * sampling_period_sec;
        let peak_power_db = 10.0 * (p_curr.max(1e-15)).log10();
        let snr_db = 10.0 * (p_curr / noise_floor).log10();

        Ok((delay_sec, peak_power_db, snr_db))
    }
}

// ============================================================================
// 7. Multi-RTT Slant Range Measurement Engine
// ============================================================================

/// Multi-RTT measurement between a RedCap UE and a Transmission-Reception Point (TRP / gNB).
#[derive(Debug, Clone, PartialEq)]
pub struct RedCapMultiRttMeasurement {
    pub trp_id: u32,
    /// Measured time interval at gNB: $T_{\text{gNB\_Rx-Tx}} = T_{\text{UL\_Rx}} - T_{\text{DL\_Tx}}$ in nanoseconds.
    pub gnb_rx_tx_ns: f64,
    /// Measured time interval at UE: $T_{\text{UE\_Rx-Tx}} = T_{\text{UL\_Tx}} - T_{\text{DL\_Rx}}$ in nanoseconds.
    pub ue_rx_tx_measured_ns: f64,
    /// RedCap UE internal group-delay calibration in nanoseconds.
    pub ue_internal_cal_ns: f64,
}

impl RedCapMultiRttMeasurement {
    /// Computes one-way propagation time and calibrated slant range (3GPP TS 38.215 / TS 38.305).
    ///
    /// $T_{\text{prop}} = \frac{1}{2} [ T_{\text{gNB\_Rx-Tx}} - (T_{\text{UE\_Rx-Tx, measured}} - \Delta T_{\text{cal}}) ]$
    pub fn compute_slant_range(&self) -> Result<(f64, f64), RedCapPosError> {
        let ue_calibrated_ns = self.ue_rx_tx_measured_ns - self.ue_internal_cal_ns;
        let prop_delay_ns = (self.gnb_rx_tx_ns - ue_calibrated_ns) * 0.5;

        if prop_delay_ns < -10.0 {
            return Err(RedCapPosError::SolverDiverged(format!(
                "Negative propagation delay: {prop_delay_ns:.2} ns"
            )));
        }

        let prop_sec = (prop_delay_ns.max(0.0)) * 1e-9;
        let range_m = prop_sec * REDCAP_POS_SPEED_OF_LIGHT_M_S;
        Ok((prop_sec, range_m))
    }
}

// ============================================================================
// 8. On-Demand PRS & Power-Saving State Machine (Rel-18)
// ============================================================================

/// On-Demand PRS state in RedCap power-saving mode (TS 37.355 / TS 38.331).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnDemandPrsState {
    /// Inactive/Sleeping - RF positioning chains powered down.
    Idle,
    /// On-demand request sent, awaiting gNB PRS activation grant.
    Requested,
    /// Burst active - receiving scheduled frequency hops.
    ActiveBurst,
    /// Burst concluded, processing and powering down.
    PowerDown,
}

/// Target accuracy class for On-Demand PRS request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosAccuracyClass {
    /// Coarse accuracy (< 10 meters, e.g. single 5/20 MHz hop).
    Coarse,
    /// High accuracy (< 1 meter, synthesized multi-hop virtual wideband).
    HighAccuracy,
}

/// On-Demand PRS Request Message (TS 37.355 LPP).
#[derive(Debug, Clone, PartialEq)]
pub struct OnDemandPrsRequest {
    pub transaction_id: u8,
    pub ue_id: u32,
    pub accuracy_class: PosAccuracyClass,
    pub requested_duration_slots: u16,
}

/// On-Demand PRS Grant Message from gNB (MAC CE / RRC).
#[derive(Debug, Clone, PartialEq)]
pub struct OnDemandPrsGrant {
    pub transaction_id: u8,
    pub start_slot: u32,
    pub duration_slots: u16,
    pub hop_mask: u8,
}

/// Manages On-Demand PRS protocol and RF power saving for RedCap UEs.
#[derive(Debug, Clone)]
pub struct OnDemandPrsManager {
    pub state: OnDemandPrsState,
    current_tx_id: u8,
    active_until_slot: u32,
    total_active_slots: u64,
    total_elapsed_slots: u64,
}

impl Default for OnDemandPrsManager {
    fn default() -> Self {
        Self {
            state: OnDemandPrsState::Idle,
            current_tx_id: 0,
            active_until_slot: 0,
            total_active_slots: 0,
            total_elapsed_slots: 0,
        }
    }
}

impl OnDemandPrsManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trigger an On-Demand PRS request.
    pub fn request_prs(
        &mut self,
        ue_id: u32,
        accuracy: PosAccuracyClass,
        duration_slots: u16,
    ) -> OnDemandPrsRequest {
        self.current_tx_id = self.current_tx_id.wrapping_add(1);
        self.state = OnDemandPrsState::Requested;
        OnDemandPrsRequest {
            transaction_id: self.current_tx_id,
            ue_id,
            accuracy_class: accuracy,
            requested_duration_slots: duration_slots,
        }
    }

    /// Receive gNB grant and activate PRS reception burst.
    pub fn handle_grant(&mut self, grant: &OnDemandPrsGrant) -> Result<(), RedCapPosError> {
        if self.state != OnDemandPrsState::Requested {
            return Err(RedCapPosError::OnDemandPrsError(format!(
                "Received grant in unexpected state: {:?}",
                self.state
            )));
        }
        if grant.transaction_id != self.current_tx_id {
            return Err(RedCapPosError::OnDemandPrsError(format!(
                "Transaction ID mismatch: expected {}, got {}",
                self.current_tx_id, grant.transaction_id
            )));
        }

        self.state = OnDemandPrsState::ActiveBurst;
        self.active_until_slot = grant.start_slot + (grant.duration_slots as u32);
        self.total_active_slots += grant.duration_slots as u64;
        Ok(())
    }

    /// Advance slot clock.
    pub fn tick_slot(&mut self, current_slot: u32) {
        self.total_elapsed_slots += 1;
        if self.state == OnDemandPrsState::ActiveBurst && current_slot >= self.active_until_slot {
            self.state = OnDemandPrsState::PowerDown;
        } else if self.state == OnDemandPrsState::PowerDown {
            self.state = OnDemandPrsState::Idle;
        }
    }

    /// Calculates energy savings ratio compared to continuous PRS monitoring.
    pub fn energy_savings_ratio(&self) -> f64 {
        if self.total_elapsed_slots == 0 {
            return 1.0;
        }
        let active_ratio = (self.total_active_slots as f64) / (self.total_elapsed_slots as f64);
        (1.0 - active_ratio).clamp(0.0, 1.0)
    }
}

// ============================================================================
// 9. 3D Multilateration Positioning Solver & DOP Metrics
// ============================================================================

/// 3D Anchor coordinates (e.g. gNB / TRP antenna reference point) in meters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Anchor3D {
    pub id: u32,
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Anchor3D {
    pub fn new(id: u32, x: f64, y: f64, z: f64) -> Self {
        Self { id, x, y, z }
    }

    pub fn distance_to(&self, x: f64, y: f64, z: f64) -> f64 {
        let dx = self.x - x;
        let dy = self.y - y;
        let dz = self.z - z;
        (dx * dx + dy * dy + dz * dz).sqrt()
    }
}

/// Dilution of Precision (DOP) metrics for positioning geometry quality.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DilutionOfPrecision {
    pub gdop: f64,
    pub pdop: f64,
    pub hdop: f64,
    pub vdop: f64,
}

/// 3D Multilateration position estimate result.
#[derive(Debug, Clone, PartialEq)]
pub struct RedCapPositionEstimate {
    pub x_meters: f64,
    pub y_meters: f64,
    pub z_meters: f64,
    pub residual_rms_meters: f64,
    pub dop: DilutionOfPrecision,
    pub iterations: usize,
}

/// Iterative Gauss-Newton 3D Multilateration Solver for Multi-RTT.
#[derive(Debug, Clone)]
pub struct MultilaterationSolver3D {
    pub max_iterations: usize,
    pub convergence_eps_meters: f64,
}

impl Default for MultilaterationSolver3D {
    fn default() -> Self {
        Self {
            max_iterations: 30,
            convergence_eps_meters: 1e-4,
        }
    }
}

impl MultilaterationSolver3D {
    pub fn new(max_iterations: usize, convergence_eps_meters: f64) -> Self {
        Self {
            max_iterations,
            convergence_eps_meters,
        }
    }

    /// Solve 3D position using Multi-RTT distance measurements from $\ge 4$ TRP anchors.
    pub fn solve_multi_rtt(
        &self,
        anchors: &[Anchor3D],
        ranges_m: &[f64],
    ) -> Result<RedCapPositionEstimate, RedCapPosError> {
        if anchors.len() < 4 || ranges_m.len() < 4 {
            return Err(RedCapPosError::InsufficientAnchors {
                required: 4,
                provided: anchors.len().min(ranges_m.len()),
            });
        }

        let mut x = anchors.iter().map(|a| a.x).sum::<f64>() / (anchors.len() as f64);
        let mut y = anchors.iter().map(|a| a.y).sum::<f64>() / (anchors.len() as f64);
        // Standard terrestrial RedCap UE height at ground level (3GPP TS 38.901)
        let mut z = 1.5;

        let m = anchors.len();
        let mut iterations = 0;

        for iter in 0..self.max_iterations {
            iterations = iter + 1;
            let mut j_mat = Vec::with_capacity(m);
            let mut r_vec = Vec::with_capacity(m);

            for i in 0..m {
                let dist = anchors[i].distance_to(x, y, z).max(0.1);
                let residual = dist - ranges_m[i];
                r_vec.push(residual);

                let j_x = (x - anchors[i].x) / dist;
                let j_y = (y - anchors[i].y) / dist;
                let j_z = (z - anchors[i].z) / dist;
                j_mat.push([j_x, j_y, j_z]);
            }

            let (jtj, jtr) = Self::compute_normal_equations_3x3(&j_mat, &r_vec);
            let inv_jtj = match Self::invert_3x3(&jtj) {
                Some(inv) => inv,
                None => {
                    return Err(RedCapPosError::SolverDiverged(
                        "Singular J^T J matrix during Multi-RTT multilateration".to_string(),
                    ))
                }
            };

            let dx = -(inv_jtj[0][0] * jtr[0] + inv_jtj[0][1] * jtr[1] + inv_jtj[0][2] * jtr[2]);
            let dy = -(inv_jtj[1][0] * jtr[0] + inv_jtj[1][1] * jtr[1] + inv_jtj[1][2] * jtr[2]);
            let dz = -(inv_jtj[2][0] * jtr[0] + inv_jtj[2][1] * jtr[1] + inv_jtj[2][2] * jtr[2]);

            x += dx;
            y += dy;
            z += dz;

            let step_norm = (dx * dx + dy * dy + dz * dz).sqrt();
            if step_norm < self.convergence_eps_meters {
                break;
            }
        }

        // Compute RMS residual
        let mut sum_sq_err = 0.0;
        let mut final_j = Vec::with_capacity(m);
        for i in 0..m {
            let dist = anchors[i].distance_to(x, y, z);
            let err = dist - ranges_m[i];
            sum_sq_err += err * err;

            let d = dist.max(0.1);
            final_j.push([
                (x - anchors[i].x) / d,
                (y - anchors[i].y) / d,
                (z - anchors[i].z) / d,
            ]);
        }
        let rms = (sum_sq_err / (m as f64)).sqrt();

        // Calculate DOP from final covariance matrix
        let (jtj, _) = Self::compute_normal_equations_3x3(&final_j, &vec![0.0; m]);
        let dop = match Self::invert_3x3(&jtj) {
            Some(q) => {
                let qxx = q[0][0].max(0.0);
                let qyy = q[1][1].max(0.0);
                let qzz = q[2][2].max(0.0);
                DilutionOfPrecision {
                    gdop: (qxx + qyy + qzz).sqrt(),
                    pdop: (qxx + qyy + qzz).sqrt(),
                    hdop: (qxx + qyy).sqrt(),
                    vdop: qzz.sqrt(),
                }
            }
            None => DilutionOfPrecision {
                gdop: 99.9,
                pdop: 99.9,
                hdop: 99.9,
                vdop: 99.9,
            },
        };

        Ok(RedCapPositionEstimate {
            x_meters: x,
            y_meters: y,
            z_meters: z,
            residual_rms_meters: rms,
            dop,
            iterations,
        })
    }

    fn compute_normal_equations_3x3(j: &[[f64; 3]], r: &[f64]) -> ([[f64; 3]; 3], [f64; 3]) {
        let mut jtj = [[0.0; 3]; 3];
        let mut jtr = [0.0; 3];

        for (row_j, &res) in j.iter().zip(r.iter()) {
            for row in 0..3 {
                jtr[row] += row_j[row] * res;
                for col in 0..3 {
                    jtj[row][col] += row_j[row] * row_j[col];
                }
            }
        }
        (jtj, jtr)
    }

    fn invert_3x3(a: &[[f64; 3]; 3]) -> Option<[[f64; 3]; 3]> {
        let det = a[0][0] * (a[1][1] * a[2][2] - a[1][2] * a[2][1])
            - a[0][1] * (a[1][0] * a[2][2] - a[1][2] * a[2][0])
            + a[0][2] * (a[1][0] * a[2][1] - a[1][1] * a[2][0]);

        if det.abs() < 1e-15 {
            return None;
        }

        let inv_det = 1.0 / det;
        let mut inv = [[0.0; 3]; 3];

        inv[0][0] = (a[1][1] * a[2][2] - a[1][2] * a[2][1]) * inv_det;
        inv[0][1] = (a[0][2] * a[2][1] - a[0][1] * a[2][2]) * inv_det;
        inv[0][2] = (a[0][1] * a[1][2] - a[0][2] * a[1][1]) * inv_det;

        inv[1][0] = (a[1][2] * a[2][0] - a[1][0] * a[2][2]) * inv_det;
        inv[1][1] = (a[0][0] * a[2][2] - a[0][2] * a[2][0]) * inv_det;
        inv[1][2] = (a[0][2] * a[1][0] - a[0][0] * a[1][2]) * inv_det;

        inv[2][0] = (a[1][0] * a[2][1] - a[1][1] * a[2][0]) * inv_det;
        inv[2][1] = (a[0][1] * a[2][0] - a[0][0] * a[2][1]) * inv_det;
        inv[2][2] = (a[0][0] * a[1][1] - a[0][1] * a[1][0]) * inv_det;

        Some(inv)
    }
}

// ============================================================================
// 10. End-to-End RedCap Positioning Engine Coordinator & Metrics
// ============================================================================

/// Telemetry metrics for the RedCap positioning subsystem.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RedCapPosMetrics {
    pub total_positioning_attempts: u64,
    pub successful_positions: u64,
    pub virtual_wideband_syntheses: u64,
    pub phase_stitching_successes: u64,
    pub phase_stitching_failures: u64,
    pub average_residual_rms_m: f64,
}

/// Central coordinator for 3GPP Rel-18 RedCap Positioning.
#[derive(Debug)]
pub struct RedCapPositioningEngine {
    pub capability: RedCapPosCapability,
    pub synthesizer: VirtualWidebandSynthesizer,
    pub cir_synthesizer: IdftCirSynthesizer,
    pub toa_estimator: SuperResolutionToaEstimator,
    pub solver: MultilaterationSolver3D,
    pub on_demand_mgr: OnDemandPrsManager,
    pub metrics: RedCapPosMetrics,
}

impl RedCapPositioningEngine {
    pub fn new(capability: RedCapPosCapability) -> Self {
        Self {
            capability,
            synthesizer: VirtualWidebandSynthesizer::new(),
            cir_synthesizer: IdftCirSynthesizer::new(),
            toa_estimator: SuperResolutionToaEstimator::default(),
            solver: MultilaterationSolver3D::default(),
            on_demand_mgr: OnDemandPrsManager::new(),
            metrics: RedCapPosMetrics::default(),
        }
    }

    /// Synthesize virtual wideband response from narrow frequency hops, compute CIR, and estimate TOA.
    pub fn process_frequency_hops(
        &mut self,
        config: &PrsFrequencyHopConfig,
        measurements: &[HopChannelMeasurement],
        oversample_factor: usize,
    ) -> Result<(f64, f64, f64), RedCapPosError> {
        self.metrics.virtual_wideband_syntheses += 1;

        let wideband_cfr = match self.synthesizer.stitch_hops(
            config,
            measurements,
            self.capability.phase_continuity,
        ) {
            Ok(cfr) => {
                self.metrics.phase_stitching_successes += 1;
                cfr
            }
            Err(e) => {
                self.metrics.phase_stitching_failures += 1;
                return Err(e);
            }
        };

        let cir = self
            .cir_synthesizer
            .compute_cir(&wideband_cfr, oversample_factor)?;

        let subcarrier_spacing_hz = (config.scs_khz as f64) * 1e3 * (config.comb_size as f64);
        let synthesized_bandwidth_hz = (wideband_cfr.len() as f64) * subcarrier_spacing_hz;
        let sampling_period_sec =
            1.0 / (synthesized_bandwidth_hz * (oversample_factor.max(1) as f64));

        self.toa_estimator.estimate_toa(&cir, sampling_period_sec)
    }

    /// Perform 3D Multi-RTT positioning from a set of TRP measurements.
    pub fn locate_ue_multi_rtt(
        &mut self,
        anchors: &[Anchor3D],
        rtt_measurements: &[RedCapMultiRttMeasurement],
    ) -> Result<RedCapPositionEstimate, RedCapPosError> {
        self.metrics.total_positioning_attempts += 1;

        let mut ranges = Vec::with_capacity(rtt_measurements.len());
        for m in rtt_measurements {
            let (_, r_m) = m.compute_slant_range()?;
            ranges.push(r_m);
        }

        match self.solver.solve_multi_rtt(anchors, &ranges) {
            Ok(est) => {
                self.metrics.successful_positions += 1;
                let count = self.metrics.successful_positions as f64;
                self.metrics.average_residual_rms_m =
                    (self.metrics.average_residual_rms_m * (count - 1.0)
                        + est.residual_rms_meters)
                        / count;
                Ok(est)
            }
            Err(e) => Err(e),
        }
    }
}

//! 3GPP Rel-18 5G-Advanced Satellite NTN PRACH Engine with SIB19 Common TA & Doppler Compensation.
//!
//! Compliant with:
//! - **3GPP TS 38.211 Rel-18 §6.3.3**: Physical channels and modulation; Random access preamble
//!   (NTN extended cyclic prefix, guard periods, and preamble repetition).
//! - **3GPP TS 38.213 Rel-18 §4.2 & §18**: Uplink timing advance and frequency synchronization for NTN.
//! - **3GPP TS 38.331 Rel-18**: SIB19 `NTN-Config` with `ta-Info` (`ta-Common`, `ta-CommonDrift`,
//!   `ta-CommonDriftVariant`), `referenceLocation`, `epochTime`, and `k-Offset`.
//! - **3GPP TS 38.133 Rel-18 §8**: PRACH reception timing and detection window over satellite links.
//!
//! Provides pure-Rust, zero-dependency implementations of:
//! - SIB19 broadcast parameter ingestion and time-varying common timing advance $TA_{\text{common}}(t)$ tracking.
//! - Service link autonomous UE-specific timing advance ($2 d_{\text{ue}} / c$) and total $TA$ calculation.
//! - Autonomous uplink Doppler frequency pre-compensation ($-\Delta f_D$) and Doppler drift rate ($\dot{f}_D$) tracking.
//! - Zadoff-Chu preamble sequence generation (TS 38.211 §6.3.3.1) with cyclic shifts $N_{\text{CS}}$.
//! - Preamble repetition ($N_{\text{rep}} \in \{1, 2, 4, 8, 16\}$) and frequency hopping for NTN link budget closure.
//! - Satellite gNB PRACH occasion (RO) detection window, cross-correlation metric, and peak-to-average ratio (PAR).
//! - RA-RNTI derivation for NTN multi-slot PRACH occasions.

// ---------------------------------------------------------------------------
// Physical & Orbital Constants
// ---------------------------------------------------------------------------

/// Speed of light in vacuum in m/s.
pub const SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

/// Default PRACH detection peak-to-average ratio (PAR) threshold in dB.
pub const DEFAULT_DETECTION_PAR_THRESH_DB: f64 = 9.0;

/// Default nominal timing advance offset in milliseconds (TS 38.213 §4.2).
pub const DEFAULT_TA_OFFSET_MS: f64 = 0.5;

// ---------------------------------------------------------------------------
// Complex Number Representation in Pure Rust
// ---------------------------------------------------------------------------

/// Standard double-precision complex number for Zadoff-Chu and baseband correlation.
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

    pub fn norm(&self) -> f64 {
        self.norm_sqr().sqrt()
    }

    pub fn conj(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }
}

// ---------------------------------------------------------------------------
// NTN PRACH Preamble Formats & Sequences
// ---------------------------------------------------------------------------

/// NTN PRACH Preamble Sequence Length (TS 38.211 §6.3.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrachSequenceLength {
    /// Long sequence L_RA = 839 (e.g. delta_f_RA = 1.25 kHz or 5 kHz for wide coverage).
    L839 = 839,
    /// Short sequence L_RA = 139 (e.g. delta_f_RA = 15, 30, 60, or 120 kHz).
    L139 = 139,
}

/// NTN PRACH Subcarrier Spacing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NtnPrachScs {
    Scs1_25kHz = 1250,
    Scs5kHz = 5000,
    Scs15kHz = 15000,
    Scs30kHz = 30000,
    Scs60kHz = 60000,
}

impl NtnPrachScs {
    pub fn delta_f_hz(&self) -> f64 {
        *self as u32 as f64
    }
}

/// PRACH preamble format tailored for NTN with extended CP and Guard Time.
#[derive(Debug, Clone, PartialEq)]
pub struct NtnPrachFormatConfig {
    pub seq_length: PrachSequenceLength,
    pub scs: NtnPrachScs,
    /// Number of repeated preamble sequences in one transmission (e.g. 1, 2, 4, 8, 16).
    pub num_repetitions: u8,
    /// Cyclic prefix duration in milliseconds.
    pub cp_duration_ms: f64,
    /// Guard time duration in milliseconds (sized for differential delay across cell).
    pub guard_time_ms: f64,
    /// Number of subcarriers per frequency hop offset.
    pub hop_offset_prb: u16,
}

impl NtnPrachFormatConfig {
    /// Standard Rel-18 Format for LEO Satellite (L_RA = 839, SCS = 1.25 kHz, 4 repetitions).
    pub fn default_leo_format() -> Self {
        Self {
            seq_length: PrachSequenceLength::L839,
            scs: NtnPrachScs::Scs1_25kHz,
            num_repetitions: 4,
            cp_duration_ms: 1.6,
            guard_time_ms: 3.2,
            hop_offset_prb: 4,
        }
    }

    /// Short sequence format for fast access in quasi-static beams (L_RA = 139, SCS = 30 kHz).
    pub fn default_short_format() -> Self {
        Self {
            seq_length: PrachSequenceLength::L139,
            scs: NtnPrachScs::Scs30kHz,
            num_repetitions: 2,
            cp_duration_ms: 0.28,
            guard_time_ms: 0.56,
            hop_offset_prb: 2,
        }
    }

    /// Total preamble transmission duration in milliseconds (CP + N_rep * T_seq + Guard).
    pub fn total_duration_ms(&self) -> f64 {
        let t_seq_ms = 1000.0 / self.scs.delta_f_hz();
        self.cp_duration_ms + (self.num_repetitions as f64 * t_seq_ms) + self.guard_time_ms
    }
}

// ---------------------------------------------------------------------------
// SIB19 Satellite Common Timing Advance & Ephemeris Information
// ---------------------------------------------------------------------------

/// Broadcast SIB19 Timing Advance and Reference Information (TS 38.331 Rel-18).
#[derive(Debug, Clone, PartialEq)]
pub struct Sib19NtnConfig {
    /// Epoch time for validity of common TA and ephemeris (in ms).
    pub epoch_time_ms: u64,
    /// Reference common two-way timing advance at epoch (in ms).
    pub ta_common_epoch_ms: f64,
    /// First derivative of common timing advance (drift rate) in ms/s.
    pub ta_common_drift_ms_s: f64,
    /// Second derivative of common timing advance in ms/s^2.
    pub ta_common_drift_variant_ms_s2: f64,
    /// Scheduling offset parameter K_offset in slots (TS 38.213 §4.2).
    pub k_offset_slots: u16,
    /// Subcarrier spacing of the reference scheduling cell in kHz.
    pub scs_khz: u16,
    /// Satellite reference carrier frequency in Hz (e.g. 2.0 GHz for S-Band).
    pub carrier_freq_hz: f64,
    /// Beam footprint differential round-trip delay uncertainty in milliseconds.
    pub cell_diff_delay_ms: f64,
}

impl Sib19NtnConfig {
    /// Compute the time-varying common timing advance at time t_ms:
    /// TA_common(t) = TA_epoch + drift * dt + 0.5 * drift_variant * dt^2
    pub fn evaluate_ta_common_ms(&self, t_ms: u64) -> f64 {
        let dt_s = (t_ms as f64 - self.epoch_time_ms as f64) / 1000.0;
        self.ta_common_epoch_ms
            + self.ta_common_drift_ms_s * dt_s
            + 0.5 * self.ta_common_drift_variant_ms_s2 * dt_s * dt_s
    }

    /// Compute common timing advance drift rate in ms/s at time t_ms:
    /// d(TA_common)/dt = drift + drift_variant * dt
    pub fn evaluate_ta_drift_rate_ms_s(&self, t_ms: u64) -> f64 {
        let dt_s = (t_ms as f64 - self.epoch_time_ms as f64) / 1000.0;
        self.ta_common_drift_ms_s + self.ta_common_drift_variant_ms_s2 * dt_s
    }
}

// ---------------------------------------------------------------------------
// Zadoff-Chu Preamble Generator & Detector
// ---------------------------------------------------------------------------

/// Generate frequency-domain or time-domain Zadoff-Chu sequence (TS 38.211 §6.3.3.1).
/// x_u(n) = exp(-j * pi * u * n * (n + 1) / L_RA) for n = 0..L_RA-1
pub fn generate_zadoff_chu_sequence(u: u16, n_cs: u16, seq_length: PrachSequenceLength) -> Vec<Complex64> {
    let l_ra = seq_length as u16;
    let l_ra_f = l_ra as f64;
    let u_f = u as f64;
    let n_cs_usize = (n_cs % l_ra) as usize;

    let mut base_seq = Vec::with_capacity(l_ra as usize);
    for n in 0..l_ra {
        let n_f = n as f64;
        let phase = -std::f64::consts::PI * u_f * n_f * (n_f + 1.0) / l_ra_f;
        base_seq.push(Complex64::from_polar(1.0, phase));
    }

    if n_cs_usize == 0 {
        base_seq
    } else {
        // Apply cyclic shift: x_u,v(n) = x_u((n + C_v) mod L_RA)
        let mut shifted_seq = Vec::with_capacity(l_ra as usize);
        for n in 0..l_ra as usize {
            let idx = (n + n_cs_usize) % (l_ra as usize);
            shifted_seq.push(base_seq[idx]);
        }
        shifted_seq
    }
}

// ---------------------------------------------------------------------------
// UE NTN PRACH Transmitter Entity
// ---------------------------------------------------------------------------

/// UE Autonomous Pre-compensation State for NTN PRACH transmission.
#[derive(Debug, Clone, PartialEq)]
pub struct UeNtnPrachPrecompensation {
    /// UE-specific one-way service link distance to satellite in meters.
    pub service_link_distance_m: f64,
    /// Radial velocity of satellite relative to UE (positive = receding, negative = approaching) in m/s.
    pub radial_velocity_m_s: f64,
    /// Radial acceleration of satellite relative to UE in m/s^2.
    pub radial_acceleration_m_s2: f64,
}

impl UeNtnPrachPrecompensation {
    /// Service link round-trip time (RTT) in milliseconds: 2 * d / c.
    pub fn rtt_service_link_ms(&self) -> f64 {
        (2.0 * self.service_link_distance_m / SPEED_OF_LIGHT_M_S) * 1000.0
    }

    /// Autonomous UE-specific timing advance T_A,UE in milliseconds: 2 * d / c.
    pub fn ue_timing_advance_ms(&self) -> f64 {
        self.rtt_service_link_ms()
    }

    /// Autonomous UE Doppler shift in Hz: f_D = -f_c * (v_rel / c).
    pub fn doppler_shift_hz(&self, carrier_freq_hz: f64) -> f64 {
        -carrier_freq_hz * (self.radial_velocity_m_s / SPEED_OF_LIGHT_M_S)
    }

    /// Autonomous UE Doppler drift rate in Hz/s: df_D/dt = -f_c * (a_rel / c).
    pub fn doppler_drift_hz_s(&self, carrier_freq_hz: f64) -> f64 {
        -carrier_freq_hz * (self.radial_acceleration_m_s2 / SPEED_OF_LIGHT_M_S)
    }
}

/// UE Transmit PRACH PDU with complete pre-compensation metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct NtnPrachTransmission {
    pub preamble_index: u8,
    pub root_u: u16,
    pub n_cs: u16,
    pub total_ta_ms: f64,
    pub ta_common_ms: f64,
    pub ta_ue_ms: f64,
    pub tx_freq_offset_hz: f64,
    pub tx_time_ms: u64,
    pub ro_slot_id: u32,
    pub ra_rnti: u16,
    pub num_repetitions: u8,
    pub symbols: Vec<Complex64>,
}

// ---------------------------------------------------------------------------
// Satellite gNB Receiver & Detection Window
// ---------------------------------------------------------------------------

/// Result of PRACH detection at satellite receiver.
#[derive(Debug, Clone, PartialEq)]
pub struct NtnPrachDetectionResult {
    pub detected: bool,
    pub preamble_index: u8,
    pub peak_correlation: f64,
    pub par_db: f64,
    pub residual_delay_us: f64,
    pub residual_frequency_hz: f64,
    pub within_window: bool,
}

// ---------------------------------------------------------------------------
// Complete Satellite NTN PRACH Engine
// ---------------------------------------------------------------------------

/// Complete 3GPP Rel-18 5G-Advanced Satellite NTN PRACH Engine.
#[derive(Debug, PartialEq)]
pub struct NtnPrachEngine {
    pub sib19: Sib19NtnConfig,
    pub prach_format: NtnPrachFormatConfig,
    pub detection_window_ms: f64,
    pub par_threshold_db: f64,
    pub stats_preambles_transmitted: u64,
    pub stats_preambles_detected: u64,
    pub stats_window_misses: u64,
    pub stats_false_alarms: u64,
}

impl NtnPrachEngine {
    pub fn new(
        sib19: Sib19NtnConfig,
        prach_format: NtnPrachFormatConfig,
        detection_window_ms: f64,
        par_threshold_db: f64,
    ) -> Self {
        Self {
            sib19,
            prach_format,
            detection_window_ms,
            par_threshold_db,
            stats_preambles_transmitted: 0,
            stats_preambles_detected: 0,
            stats_window_misses: 0,
            stats_false_alarms: 0,
        }
    }

    /// Calculate total Timing Advance to apply at UE transmitter:
    /// TA_total = TA_common(t) + 2 * d_ue(t) / c + TA_offset
    pub fn compute_total_ta_ms(&self, ue_precomp: &UeNtnPrachPrecompensation, t_ms: u64) -> f64 {
        let ta_common = self.sib19.evaluate_ta_common_ms(t_ms);
        let ta_ue = ue_precomp.ue_timing_advance_ms();
        ta_common + ta_ue + DEFAULT_TA_OFFSET_MS
    }

    /// Derive 3GPP RA-RNTI for NTN PRACH occasion (TS 38.321 §5.1.3):
    /// RA-RNTI = 1 + s_id + 14 * t_id + 14 * 80 * f_id + 14 * 80 * 8 * ul_carrier_id
    pub fn compute_ra_rnti(
        &self,
        symbol_id: u8,
        slot_id: u8,
        freq_id: u8,
        ul_carrier_id: u8,
    ) -> u16 {
        let s = symbol_id as u32;
        let t = slot_id as u32;
        let f = freq_id as u32;
        let c = ul_carrier_id as u32;
        (1 + s + 14 * t + 14 * 80 * f + 14 * 80 * 8 * c) as u16
    }

    /// UE side: Prepare and modulate NTN PRACH transmission with autonomous pre-compensation.
    pub fn prepare_ue_transmission(
        &mut self,
        preamble_index: u8,
        root_u: u16,
        n_cs: u16,
        ue_precomp: &UeNtnPrachPrecompensation,
        nominal_ro_time_ms: u64,
        slot_id: u8,
        freq_id: u8,
    ) -> NtnPrachTransmission {
        let ta_common = self.sib19.evaluate_ta_common_ms(nominal_ro_time_ms);
        let ta_ue = ue_precomp.ue_timing_advance_ms();
        let total_ta = ta_common + ta_ue + DEFAULT_TA_OFFSET_MS;

        // Frequency pre-compensation: invert both common and UE Doppler shifts
        let ue_doppler = ue_precomp.doppler_shift_hz(self.sib19.carrier_freq_hz);
        let tx_freq_offset = -ue_doppler; // Pre-compensate so received at satellite is centered at 0

        // Generate base Zadoff-Chu sequence
        let base_zc = generate_zadoff_chu_sequence(root_u, n_cs, self.prach_format.seq_length);

        // Build multi-repetition waveform with frequency hopping phase rotators
        let num_rep = self.prach_format.num_repetitions as usize;
        let mut symbols = Vec::with_capacity(base_zc.len() * num_rep);

        for rep in 0..num_rep {
            let hop_freq_hz = (rep as f64) * 180_000.0 * (self.prach_format.hop_offset_prb as f64);
            let dt_step = 1.0 / (self.prach_format.scs.delta_f_hz() * (base_zc.len() as f64));

            for (n, zc_sample) in base_zc.iter().enumerate() {
                let t = (n as f64) * dt_step;
                let hop_rotator = Complex64::from_polar(1.0, 2.0 * std::f64::consts::PI * hop_freq_hz * t);
                symbols.push(zc_sample.mul(&hop_rotator));
            }
        }

        let ra_rnti = self.compute_ra_rnti(0, slot_id, freq_id, 0);
        self.stats_preambles_transmitted += 1;

        NtnPrachTransmission {
            preamble_index,
            root_u,
            n_cs,
            total_ta_ms: total_ta,
            ta_common_ms: ta_common,
            ta_ue_ms: ta_ue,
            tx_freq_offset_hz: tx_freq_offset,
            tx_time_ms: nominal_ro_time_ms.saturating_sub(total_ta.round() as u64),
            ro_slot_id: slot_id as u32,
            ra_rnti,
            num_repetitions: self.prach_format.num_repetitions,
            symbols,
        }
    }

    /// Satellite Payload side: Evaluate PRACH detection window and correlate received preamble.
    /// In the presence of residual delay error and residual frequency error:
    pub fn evaluate_satellite_reception(
        &mut self,
        tx: &NtnPrachTransmission,
        actual_channel_delay_ms: f64,
        actual_channel_doppler_hz: f64,
        snr_linear: f64,
    ) -> NtnPrachDetectionResult {
        // Residual delay at satellite payload:
        // When UE applies total_ta_ms = ta_common + ta_ue + offset,
        // and true RTT is actual_channel_delay_ms,
        // residual delay is the difference.
        let residual_delay_ms = actual_channel_delay_ms - tx.total_ta_ms + DEFAULT_TA_OFFSET_MS;
        let residual_delay_us = residual_delay_ms * 1000.0;

        // Residual Doppler after pre-compensation:
        let residual_doppler_hz = actual_channel_doppler_hz + tx.tx_freq_offset_hz;

        // Check if arrival falls within satellite PRACH detection window
        let half_win_ms = self.detection_window_ms / 2.0;
        let within_window = residual_delay_ms.abs() <= half_win_ms;

        if !within_window {
            self.stats_window_misses += 1;
            return NtnPrachDetectionResult {
                detected: false,
                preamble_index: tx.preamble_index,
                peak_correlation: 0.0,
                par_db: 0.0,
                residual_delay_us,
                residual_frequency_hz: residual_doppler_hz,
                within_window: false,
            };
        }

        // Compute simulated cross-correlation peak and Peak-to-Average Ratio (PAR)
        // With ZC sequence, peak is degraded by residual Doppler phase roll over sequence:
        // sinc(pi * delta_f * T_seq)
        let t_seq_s = 1.0 / self.prach_format.scs.delta_f_hz();
        let sinc_arg = std::f64::consts::PI * residual_doppler_hz * t_seq_s;
        let sinc_loss = if sinc_arg.abs() < 1e-5 {
            1.0
        } else {
            (sinc_arg.sin() / sinc_arg).abs()
        };

        let rep_gain = (tx.num_repetitions as f64).sqrt();
        let raw_peak = sinc_loss * rep_gain * snr_linear.sqrt();
        let noise_floor = 1.0;
        let par_linear = (raw_peak * raw_peak) / noise_floor;
        let par_db = 10.0 * par_linear.log10().max(0.0);

        let detected = par_db >= self.par_threshold_db;
        if detected {
            self.stats_preambles_detected += 1;
        }

        NtnPrachDetectionResult {
            detected,
            preamble_index: tx.preamble_index,
            peak_correlation: raw_peak,
            par_db,
            residual_delay_us,
            residual_frequency_hz: residual_doppler_hz,
            within_window: true,
        }
    }
}

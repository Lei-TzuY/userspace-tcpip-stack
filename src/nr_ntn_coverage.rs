//! 3GPP Release 18 (5G-Advanced) NTN Uplink Coverage Enhancement & Adaptive Repetition Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §6.3 / §6.4: "Uplink physical channels and signals - PUSCH/PUCCH repetitions, DMRS bundling, frequency hopping"
//! - 3GPP TS 38.213 Rel-18 §16.8: "Uplink power control and timing procedures for Non-Terrestrial Networks (NTN)"
//! - 3GPP TS 38.214 Rel-18 §6.1: "UE procedures for transmitting PUSCH over multiple slots (TBoMS) and cross-slot DMRS bundling"
//! - 3GPP TS 38.331 Rel-18: "RRC configuration (PUSCH-TimeDomainResourceAllocationList, DMRS-Bundling-Config, NTN-Config)"
//!
//! Pure standard Rust (`std` / `core` only) with zero external dependencies.

use std::f64::consts::PI;
use std::fmt;

/// Speed of light in vacuum (meters per second).
pub const NTN_COV_SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

/// Earth equatorial mean radius in meters (WGS-84).
pub const NTN_COV_EARTH_RADIUS_M: f64 = 6_378_137.0;

/// Boltzmann constant in Joules / Kelvin.
pub const BOLTZMANN_CONSTANT_J_K: f64 = 1.380649e-23;

// ============================================================================
// 1. Error Types
// ============================================================================

/// Errors encountered in 3GPP Rel-18 NTN coverage enhancement operations.
#[derive(Debug, Clone, PartialEq)]
pub enum NtnCovError {
    /// Elevation angle out of range (valid: 0.0 to 90.0 degrees).
    InvalidElevationAngle(f64),
    /// Unsupported repetition factor (valid: 1, 2, 4, 8, 16, 32).
    InvalidRepetitionFactor(u8),
    /// Unsupported DMRS bundle size (valid: 2, 4, 8, 16, 32 slots).
    InvalidBundleSize(u8),
    /// Phase discontinuity break in cross-slot DMRS bundling.
    PhaseDiscontinuityDetected(String),
    /// Transmit power step exceeded the phase continuity limit (typically 0.5 dB).
    PowerControlStepExceeded { step_db: f64, limit_db: f64 },
    /// Invalid slot index or out of bounds.
    InvalidSlotIndex(u32),
    /// Link budget deficit exceeds maximum possible coverage extension capability.
    LinkBudgetExceeded(String),
}

impl fmt::Display for NtnCovError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtnCovError::InvalidElevationAngle(el) => {
                write!(
                    f,
                    "Invalid satellite elevation angle: {el:.2}° (valid: 0.0°..90.0°)"
                )
            }
            NtnCovError::InvalidRepetitionFactor(k) => {
                write!(
                    f,
                    "Unsupported repetition factor: {k} (valid: 1, 2, 4, 8, 16, 32)"
                )
            }
            NtnCovError::InvalidBundleSize(b) => {
                write!(
                    f,
                    "Unsupported DMRS bundle size: {b} slots (valid: 2, 4, 8, 16, 32)"
                )
            }
            NtnCovError::PhaseDiscontinuityDetected(msg) => {
                write!(f, "DMRS bundling phase continuity broken: {msg}")
            }
            NtnCovError::PowerControlStepExceeded { step_db, limit_db } => {
                write!(
                    f,
                    "Power step of {step_db:.2} dB exceeds DMRS bundling threshold {limit_db:.2} dB"
                )
            }
            NtnCovError::InvalidSlotIndex(slot) => write!(f, "Invalid slot index: {slot}"),
            NtnCovError::LinkBudgetExceeded(msg) => write!(f, "NTN link budget exceeded: {msg}"),
        }
    }
}

// ============================================================================
// 2. Satellite Orbit Classification & Slant Range Geometry
// ============================================================================

/// Non-Terrestrial Network Satellite Orbit Classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtnCovOrbitClass {
    /// Low Earth Orbit (LEO: typical altitude 500..1200 km).
    Leo,
    /// Medium Earth Orbit (MEO: typical altitude 7000..20000 km).
    Meo,
    /// Geostationary Orbit (GEO: nominal altitude 35786 km).
    Geo,
}

/// Satellite orbital geometry and pathloss model (3GPP TR 38.811 / TS 38.213 §16.8).
#[derive(Debug, Clone, PartialEq)]
pub struct NtnSatelliteGeometry {
    pub orbit_class: NtnCovOrbitClass,
    /// Satellite orbital altitude above Earth in kilometers.
    pub altitude_km: f64,
    /// Carrier frequency in Hz (e.g. 2.0 GHz S-band or 28 GHz Ka-band).
    pub carrier_freq_hz: f64,
    /// Additional atmospheric and ionospheric attenuation in dB (e.g. 0.5 to 2.5 dB).
    pub atmospheric_loss_db: f64,
}

impl NtnSatelliteGeometry {
    pub fn new_leo_600km(carrier_freq_hz: f64) -> Self {
        Self {
            orbit_class: NtnCovOrbitClass::Leo,
            altitude_km: 600.0,
            carrier_freq_hz,
            atmospheric_loss_db: 0.5,
        }
    }

    pub fn new_geo_35786km(carrier_freq_hz: f64) -> Self {
        Self {
            orbit_class: NtnCovOrbitClass::Geo,
            altitude_km: 35786.0,
            carrier_freq_hz,
            atmospheric_loss_db: 1.2,
        }
    }

    /// Computes geometric slant range $d(\theta)$ in kilometers as a function of elevation angle $\theta$ (degrees).
    ///
    /// Formula:
    /// $$d(\theta) = R_E \left( \sqrt{\left(\frac{R_E + h}{R_E}\right)^2 - \cos^2\theta} - \sin\theta \right)$$
    pub fn slant_range_km(&self, elevation_deg: f64) -> Result<f64, NtnCovError> {
        if !(0.0..=90.0).contains(&elevation_deg) {
            return Err(NtnCovError::InvalidElevationAngle(elevation_deg));
        }

        let re = NTN_COV_EARTH_RADIUS_M / 1000.0; // km
        let h = self.altitude_km;
        let theta_rad = elevation_deg * PI / 180.0;
        let cos_theta = theta_rad.cos();
        let sin_theta = theta_rad.sin();

        let ratio = (re + h) / re;
        let radical = ratio * ratio - cos_theta * cos_theta;
        let radical = radical.max(0.0).sqrt();

        let slant_km = re * (radical - sin_theta);
        Ok(slant_km)
    }

    /// Free-Space Path Loss (FSPL) in dB:
    /// $$FSPL = 20 \log_{10}(d) + 20 \log_{10}(f) + 20 \log_{10}\left(\frac{4\pi}{c}\right) + L_{\text{atm}}$$
    pub fn total_pathloss_db(&self, elevation_deg: f64) -> Result<f64, NtnCovError> {
        let slant_km = self.slant_range_km(elevation_deg)?;
        let slant_m = slant_km * 1000.0;

        let fspl_db = 20.0 * slant_m.log10()
            + 20.0 * self.carrier_freq_hz.log10()
            + 20.0 * ((4.0 * PI) / NTN_COV_SPEED_OF_LIGHT_M_S).log10();

        Ok(fspl_db + self.atmospheric_loss_db)
    }
}

// ============================================================================
// 3. Multi-Slot DMRS Bundling & Cross-Slot Channel Estimation (Rel-18)
// ============================================================================

/// Configuration for 3GPP Rel-18 Multi-Slot DMRS Bundling (TS 38.214 §6.1).
#[derive(Debug, Clone, PartialEq)]
pub struct NtnDmrsBundleConfig {
    /// Bundle size in consecutive uplink slots ($N_{\text{bundle}} \in \{2, 4, 8, 16, 32\}$).
    pub nominal_bundle_size: u8,
    /// Maximum allowable phase drift per slot in radians (typically $\pi/4 \approx 0.785$ rad).
    pub max_phase_drift_rad: f64,
    /// Maximum allowable transmit power step between bundled slots in dB (standard: 0.5 dB).
    pub max_power_step_db: f64,
}

impl Default for NtnDmrsBundleConfig {
    fn default() -> Self {
        Self {
            nominal_bundle_size: 4,
            max_phase_drift_rad: PI / 4.0,
            max_power_step_db: 0.5,
        }
    }
}

/// Status of DMRS bundling for a specific slot.
#[derive(Debug, Clone, PartialEq)]
pub struct DmrsBundleStatus {
    pub slot_idx: u32,
    pub is_bundled_with_prev: bool,
    pub current_bundle_length: usize,
    pub accumulated_snr_gain_db: f64,
    pub phase_break_reason: Option<String>,
}

/// Tracks and verifies phase and power continuity across multi-slot DMRS transmissions.
#[derive(Debug)]
pub struct DmrsBundlingAuditor {
    pub config: NtnDmrsBundleConfig,
    prev_slot_idx: Option<u32>,
    prev_power_dbm: Option<f64>,
    prev_prb_offset: Option<u16>,
    current_bundle_count: usize,
}

impl DmrsBundlingAuditor {
    pub fn new(config: NtnDmrsBundleConfig) -> Self {
        Self {
            config,
            prev_slot_idx: None,
            prev_power_dbm: None,
            prev_prb_offset: None,
            current_bundle_count: 0,
        }
    }

    /// Evaluates if the current slot maintains phase/power continuity with the preceding slot.
    pub fn audit_slot(
        &mut self,
        slot_idx: u32,
        power_dbm: f64,
        prb_offset: u16,
        phase_drift_rad: f64,
    ) -> DmrsBundleStatus {
        let mut is_continuous = true;
        let mut reason = None;

        if let Some(prev_slot) = self.prev_slot_idx {
            // Must be strictly contiguous slot
            if slot_idx != prev_slot + 1 {
                is_continuous = false;
                reason = Some(format!(
                    "Non-contiguous slot gap: prev {prev_slot}, curr {slot_idx}"
                ));
            }

            // Power step limit
            if let Some(prev_p) = self.prev_power_dbm {
                let diff_db = (power_dbm - prev_p).abs();
                if diff_db > self.config.max_power_step_db {
                    is_continuous = false;
                    reason = Some(format!(
                        "Power step {diff_db:.2} dB exceeds limit {} dB",
                        self.config.max_power_step_db
                    ));
                }
            }

            // Frequency hop check (intra-bundle frequency hopping is prohibited in DMRS bundling)
            if let Some(prev_prb) = self.prev_prb_offset {
                if prb_offset != prev_prb {
                    is_continuous = false;
                    reason = Some(format!(
                        "Frequency hopped across bundled slots ({prev_prb} -> {prb_offset})"
                    ));
                }
            }

            // Phase drift limit
            if phase_drift_rad.abs() > self.config.max_phase_drift_rad {
                is_continuous = false;
                reason = Some(format!(
                    "Phase drift {:.3} rad exceeds limit {:.3} rad",
                    phase_drift_rad.abs(),
                    self.config.max_phase_drift_rad
                ));
            }
        } else {
            // First slot in stream starts a new bundle
            is_continuous = false;
        }

        // Bundle size limit check
        if is_continuous {
            self.current_bundle_count += 1;
            if self.current_bundle_count > (self.config.nominal_bundle_size as usize) {
                is_continuous = false;
                self.current_bundle_count = 1;
                reason = Some("Nominal bundle size boundary reached".to_string());
            }
        } else {
            self.current_bundle_count = 1;
        }

        // Update state
        self.prev_slot_idx = Some(slot_idx);
        self.prev_power_dbm = Some(power_dbm);
        self.prev_prb_offset = Some(prb_offset);

        // Theoretical SNR gain from cross-slot channel estimation: 10 * log10(bundle_size)
        let snr_gain_db = 10.0 * (self.current_bundle_count as f64).log10();

        DmrsBundleStatus {
            slot_idx,
            is_bundled_with_prev: is_continuous,
            current_bundle_length: self.current_bundle_count,
            accumulated_snr_gain_db: snr_gain_db,
            phase_break_reason: reason,
        }
    }
}

// ============================================================================
// 4. Transport Block over Multiple Slots (TBoMS) Coding Engine
// ============================================================================

/// Modulation Order for PUSCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtnModulationOrder {
    Qpsk = 2,
    Qam16 = 4,
    Qam64 = 6,
}

/// Evaluates TBoMS joint rate-matching and coding gain over simple slot-level repetition (TS 38.214 §6.1).
#[derive(Debug, Default)]
pub struct TBoMsCodingEngine;

impl TBoMsCodingEngine {
    pub fn new() -> Self {
        Self
    }

    /// Computes effective code rate and coding gain for TBoMS.
    ///
    /// - `tbs_bits`: Transport block size in bits.
    /// - `re_per_slot`: Number of resource elements allocated for PUSCH data per slot.
    /// - `qm`: Modulation order.
    /// - `repetition_k`: Number of slots spanned.
    ///
    /// Returns:
    /// - Effective code rate $R_{\text{eff}} \in (0.0, 1.0]$.
    /// - Coding gain over simple repetition in dB.
    pub fn evaluate_tboms(
        &self,
        tbs_bits: usize,
        re_per_slot: usize,
        qm: NtnModulationOrder,
        repetition_k: u8,
    ) -> (f64, f64) {
        let k = repetition_k.max(1) as f64;
        let bits_per_slot = (re_per_slot as f64) * (qm as u8 as f64);
        let total_coded_bits = bits_per_slot * k;

        let effective_rate = (tbs_bits as f64) / total_coded_bits;
        let effective_rate = effective_rate.clamp(0.01, 1.0);

        // Coding gain model (3GPP TR 38.830 §6.1):
        // Joint low-rate LDPC encoding across K slots provides ~1.5 to 2.8 dB gain over
        // simple repetition chase combining.
        let gain_db = if repetition_k > 1 {
            let base_gain = 1.2 + 0.5 * (k.log2());
            base_gain.min(3.0)
        } else {
            0.0
        };

        (effective_rate, gain_db)
    }
}

// ============================================================================
// 5. Inter-Slot Frequency Hopping Pattern Generator (Rel-18)
// ============================================================================

/// Inter-slot frequency hopping configuration preserving DMRS bundle boundaries.
#[derive(Debug, Clone, PartialEq)]
pub struct NtnFreqHopConfig {
    pub enabled: bool,
    /// PRB offset for Hop 0.
    pub hop0_prb: u16,
    /// PRB offset for Hop 1.
    pub hop1_prb: u16,
    /// Number of slots per hop (must be aligned with DMRS bundle size to prevent phase breaks).
    pub slots_per_hop: u8,
}

/// Generates PRB allocation for bundled inter-slot frequency hopping.
#[derive(Debug)]
pub struct NtnFreqHoppingPatternGenerator {
    pub config: NtnFreqHopConfig,
}

impl NtnFreqHoppingPatternGenerator {
    pub fn new(config: NtnFreqHopConfig) -> Self {
        Self { config }
    }

    /// Get assigned PRB offset for slot index `slot_idx`.
    pub fn get_prb_offset(&self, slot_idx: u32) -> u16 {
        if !self.config.enabled {
            return self.config.hop0_prb;
        }

        let hop_idx = (slot_idx / (self.config.slots_per_hop.max(1) as u32)) % 2;
        if hop_idx == 0 {
            self.config.hop0_prb
        } else {
            self.config.hop1_prb
        }
    }
}

// ============================================================================
// 6. PUCCH Multi-Slot Repetition & Cyclic Shift Hopping (TS 38.213 §16.8)
// ============================================================================

/// Multi-slot PUCCH Repetition Manager for NTN Uplink Control Information (UCI).
#[derive(Debug, Clone)]
pub struct PucchMultiSlotRepetitionManager {
    pub repetition_k: u8, // 1, 2, 4, 8, 16
    pub initial_cyclic_shift: u8,
}

impl PucchMultiSlotRepetitionManager {
    pub fn new(repetition_k: u8, initial_cyclic_shift: u8) -> Result<Self, NtnCovError> {
        if ![1, 2, 4, 8, 16].contains(&repetition_k) {
            return Err(NtnCovError::InvalidRepetitionFactor(repetition_k));
        }
        Ok(Self {
            repetition_k,
            initial_cyclic_shift: initial_cyclic_shift % 12,
        })
    }

    /// Compute cyclic shift index for PUCCH transmission on slot `rep_idx` ($0..K-1$).
    ///
    /// Applies pseudo-random sequence hopping: $n_{\text{cs}}(k) = (n_{\text{cs,init}} + k \cdot 3) \bmod 12$.
    pub fn get_cyclic_shift(&self, rep_idx: usize) -> u8 {
        (self.initial_cyclic_shift as usize + rep_idx * 3) as u8 % 12
    }
}

// ============================================================================
// 7. Satellite Orbital Elevation-Angle Adaptive Repetition Servo
// ============================================================================

/// Dynamic servo that adjusts uplink repetition factor $K_{\text{rep}}$ and transmit power
/// based on satellite pass trajectory (elevation angle $\theta(t)$).
#[derive(Debug, Clone)]
pub struct NtnSlantRangeAdaptiveServo {
    pub geometry: NtnSatelliteGeometry,
    /// UE maximum transmit power in dBm (e.g. 23.0 dBm for Power Class 3).
    pub ue_pcmax_dbm: f64,
    /// Satellite receiver G/T figure of merit in dB/K (e.g. 5.0 dB/K for LEO, -2.0 dB/K for GEO).
    pub sat_g_over_t_db_k: f64,
    /// Target required SINR for PUSCH in dB (e.g. -3.0 dB for low-rate QPSK).
    pub target_sinr_db: f64,
    /// Allocated PUSCH channel bandwidth in Hz (e.g. 180 kHz for 1 PRB or 720 kHz for 4 PRBs).
    pub channel_bandwidth_hz: f64,
}

impl NtnSlantRangeAdaptiveServo {
    pub fn new(
        geometry: NtnSatelliteGeometry,
        ue_pcmax_dbm: f64,
        sat_g_over_t_db_k: f64,
        target_sinr_db: f64,
        channel_bandwidth_hz: f64,
    ) -> Self {
        Self {
            geometry,
            ue_pcmax_dbm,
            sat_g_over_t_db_k,
            target_sinr_db,
            channel_bandwidth_hz,
        }
    }

    /// Evaluates link margin and recommends repetition factor $K_{\text{rep}} \in \{1, 2, 4, 8, 16, 32\}$.
    ///
    /// Returns:
    /// - Recommended repetition factor $K_{\text{rep}}$.
    /// - Recommended DMRS bundle size.
    /// - Recommended UE transmit power in dBm.
    /// - Estimated Link Margin in dB (positive = surplus, negative = deficit).
    pub fn adapt_for_elevation(
        &self,
        elevation_deg: f64,
    ) -> Result<(u8, u8, f64, f64), NtnCovError> {
        let total_pl_db = self.geometry.total_pathloss_db(elevation_deg)?;

        // Standard satellite link budget (3GPP TR 38.821 / TR 38.811):
        // P_tx_dbw = P_tx_dbm - 30.0
        let p_tx_dbw = self.ue_pcmax_dbm - 30.0;
        // Boltzmann constant k = 1.380649e-23 J/K -> 10 * log10(k) = -228.60 dBW/(Hz*K)
        let k_boltzmann_dbw = -228.60;
        let bandwidth_db_hz = 10.0 * self.channel_bandwidth_hz.log10();

        // C/N0 (dB-Hz) = P_TX(dBW) - PathLoss(dB) + (G/T)(dB/K) - k(dBW/K/Hz)
        let c_over_n0 = p_tx_dbw - total_pl_db + self.sat_g_over_t_db_k - k_boltzmann_dbw;
        let raw_snr_db = c_over_n0 - bandwidth_db_hz;

        let margin_single_slot = raw_snr_db - self.target_sinr_db;

        // Select repetition factor to bridge deficit
        let (k_rep, bundle_size) = if margin_single_slot >= 3.0 {
            (1, 1) // Healthy margin, no repetition needed
        } else if margin_single_slot >= 0.0 {
            (2, 2) // Modest coverage boost (+3 dB)
        } else if margin_single_slot >= -3.5 {
            (4, 4) // +6 dB boost
        } else if margin_single_slot >= -7.0 {
            (8, 4) // +9 dB boost (8 reps, 2 bundles of 4)
        } else if margin_single_slot >= -11.0 {
            (16, 4) // +12 dB boost (16 reps, 4 bundles of 4)
        } else {
            (32, 4) // Extreme slant range near horizon (+15 dB boost)
        };

        let repetition_gain_db = 10.0 * (k_rep as f64).log10();
        let net_margin = margin_single_slot + repetition_gain_db;

        // Power control: back off from P_CMAX if margin is excessively high (> 6 dB)
        let tx_power_dbm = if net_margin > 6.0 {
            (self.ue_pcmax_dbm - (net_margin - 6.0)).max(10.0)
        } else {
            self.ue_pcmax_dbm
        };

        Ok((k_rep, bundle_size, tx_power_dbm, net_margin))
    }
}

// ============================================================================
// 8. End-to-End NTN Coverage Engine Coordinator & Metrics
// ============================================================================

/// Performance telemetry for the NTN coverage engine.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NtnCovMetrics {
    pub total_transmitted_slots: u64,
    pub dmrs_bundled_slots: u64,
    pub phase_continuity_breaks: u64,
    pub tboms_transmissions: u64,
    pub pucch_multi_slot_transmissions: u64,
    pub average_repetition_factor: f64,
}

/// Central Coordinator for 3GPP Rel-18 NTN Uplink Coverage Enhancement.
#[derive(Debug)]
pub struct NtnCoverageEngine {
    pub geometry: NtnSatelliteGeometry,
    pub dmrs_auditor: DmrsBundlingAuditor,
    pub tboms_engine: TBoMsCodingEngine,
    pub hop_generator: NtnFreqHoppingPatternGenerator,
    pub adaptive_servo: NtnSlantRangeAdaptiveServo,
    pub metrics: NtnCovMetrics,
}

impl NtnCoverageEngine {
    pub fn new(
        geometry: NtnSatelliteGeometry,
        dmrs_config: NtnDmrsBundleConfig,
        hop_config: NtnFreqHopConfig,
        ue_pcmax_dbm: f64,
        sat_g_over_t_db_k: f64,
        target_sinr_db: f64,
        channel_bandwidth_hz: f64,
    ) -> Self {
        let adaptive_servo = NtnSlantRangeAdaptiveServo::new(
            geometry.clone(),
            ue_pcmax_dbm,
            sat_g_over_t_db_k,
            target_sinr_db,
            channel_bandwidth_hz,
        );

        Self {
            geometry,
            dmrs_auditor: DmrsBundlingAuditor::new(dmrs_config),
            tboms_engine: TBoMsCodingEngine::new(),
            hop_generator: NtnFreqHoppingPatternGenerator::new(hop_config),
            adaptive_servo,
            metrics: NtnCovMetrics::default(),
        }
    }

    /// Process an uplink slot transmission and audit DMRS bundling.
    pub fn transmit_uplink_slot(
        &mut self,
        slot_idx: u32,
        power_dbm: f64,
        phase_drift_rad: f64,
    ) -> (u16, DmrsBundleStatus) {
        self.metrics.total_transmitted_slots += 1;

        let prb_offset = self.hop_generator.get_prb_offset(slot_idx);
        let bundle_status =
            self.dmrs_auditor
                .audit_slot(slot_idx, power_dbm, prb_offset, phase_drift_rad);

        if bundle_status.is_bundled_with_prev {
            self.metrics.dmrs_bundled_slots += 1;
        } else if bundle_status.phase_break_reason.is_some() {
            self.metrics.phase_continuity_breaks += 1;
        }

        (prb_offset, bundle_status)
    }
}

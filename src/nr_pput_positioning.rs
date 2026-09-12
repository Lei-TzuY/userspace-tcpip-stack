//! 3GPP Release 18 (5G-Advanced) Pre-configured Positioning Uplink Transmission (P-PUT) Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.305 Rel-18 §8.10: "Stage 2 functional specification of UE positioning in NG-RAN - Pre-configured Positioning Uplink Transmission (P-PUT) in RRC_INACTIVE and RRC_IDLE"
//! - 3GPP TS 38.331 Rel-18 §6.3.2: "RRC Information Elements - P-PUT-Config, P-PUT-ResourceSet, P-PUT-ValidityCriteria in SuspendConfig"
//! - 3GPP TS 38.211 Rel-18 §6.4.1.4: "Sounding Reference Signal (SRS) for positioning - comb structures and cyclic shifts"
//! - 3GPP TS 38.214 Rel-18 §6.2.1: "UE sounding procedure - SRS transmission in RRC_INACTIVE"
//! - 3GPP TS 38.213 Rel-18 §7.3: "Uplink power control for SRS in RRC_INACTIVE"
//! - 3GPP TS 38.455 Rel-18: "NR Positioning Protocol A (NRPPa) - TRP Measurement Information Transfer for P-PUT"
//!
//! Pure standard Rust (`std` / `core` only) with zero external dependencies.

use std::fmt;

/// Speed of light in vacuum (meters per second).
pub const PPUT_SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

// ============================================================================
// 1. Error Types
// ============================================================================

/// Errors encountered in 3GPP Rel-18 P-PUT operations.
#[derive(Debug, Clone, PartialEq)]
pub enum PputError {
    /// Invalid SRS comb size (valid: 2, 4, 8).
    InvalidCombSize(u8),
    /// Invalid bandwidth or PRB allocation.
    InvalidBandwidth(u16),
    /// Autonomous Timing Advance validation failed (fallback to RACH/SDT required).
    TaValidationFailed(String),
    /// Insufficient TRP measurements for hybrid TDOA/AoA multilateration.
    InsufficientMeasurements { required: usize, provided: usize },
    /// Non-linear multilateration solver diverged.
    SolverDiverged(String),
    /// Power control computation error.
    PowerControlError(String),
    /// P-PUT configuration error.
    ConfigurationError(String),
}

impl fmt::Display for PputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PputError::InvalidCombSize(c) => {
                write!(f, "Invalid P-PUT comb size: {c} (supported: 2, 4, 8)")
            }
            PputError::InvalidBandwidth(prbs) => write!(f, "Invalid PRB allocation: {prbs} PRBs"),
            PputError::TaValidationFailed(msg) => {
                write!(f, "Autonomous TA validation failed: {msg}")
            }
            PputError::InsufficientMeasurements { required, provided } => {
                write!(
                    f,
                    "Insufficient TRP measurements: required {required}, provided {provided}"
                )
            }
            PputError::SolverDiverged(msg) => {
                write!(f, "Hybrid positioning solver diverged: {msg}")
            }
            PputError::PowerControlError(msg) => write!(f, "P-PUT power control error: {msg}"),
            PputError::ConfigurationError(msg) => write!(f, "P-PUT configuration error: {msg}"),
        }
    }
}

// ============================================================================
// 2. Configurations & Resources (TS 38.331 / TS 38.211)
// ============================================================================

/// SRS comb size for P-PUT (TS 38.211 §6.4.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PputCombSize {
    Comb2 = 2,
    Comb4 = 4,
    Comb8 = 8,
}

/// Pre-configured Positioning Uplink Transmission (P-PUT) Resource (TS 38.331 §6.3.2).
#[derive(Debug, Clone, PartialEq)]
pub struct PputResource {
    pub resource_id: u8,
    pub comb_size: PputCombSize,
    pub cyclic_shift: u8,
    pub start_prb: u16,
    pub num_prbs: u16,
    pub num_symbols: u8, // 1, 2, or 4 OFDM symbols
    pub num_ports: u8,   // 1, 2, or 4 antenna ports
    pub sequence_id: u16,
}

impl PputResource {
    pub fn new(
        resource_id: u8,
        comb_size: PputCombSize,
        cyclic_shift: u8,
        start_prb: u16,
        num_prbs: u16,
        num_symbols: u8,
        num_ports: u8,
        sequence_id: u16,
    ) -> Result<Self, PputError> {
        let max_cs = comb_size as u8;
        if cyclic_shift >= max_cs {
            return Err(PputError::ConfigurationError(format!(
                "Cyclic shift {cyclic_shift} exceeds comb limit {max_cs}"
            )));
        }
        if num_prbs == 0 || num_prbs > 273 {
            return Err(PputError::InvalidBandwidth(num_prbs));
        }
        if num_symbols != 1 && num_symbols != 2 && num_symbols != 4 {
            return Err(PputError::ConfigurationError(format!(
                "Invalid symbol count: {num_symbols} (valid: 1, 2, 4)"
            )));
        }
        if num_ports != 1 && num_ports != 2 && num_ports != 4 {
            return Err(PputError::ConfigurationError(format!(
                "Invalid port count: {num_ports} (valid: 1, 2, 4)"
            )));
        }

        Ok(Self {
            resource_id,
            comb_size,
            cyclic_shift,
            start_prb,
            num_prbs,
            num_symbols,
            num_ports,
            sequence_id,
        })
    }
}

/// Validity criteria for autonomous P-PUT transmission in RRC_INACTIVE (TS 38.331).
#[derive(Debug, Clone, PartialEq)]
pub struct PputValidityCriteria {
    /// Maximum duration stored Timing Advance remains valid in milliseconds (e.g. 5120 ms).
    pub ta_validity_timer_ms: u32,
    /// Maximum allowable serving cell SS-RSRP drift in dB (e.g. 6.0 dB).
    pub rsrp_change_threshold_db: f64,
    /// Maximum number of consecutive P-PUT transmissions before validation refresh.
    pub max_consecutive_transmissions: u32,
}

impl Default for PputValidityCriteria {
    fn default() -> Self {
        Self {
            ta_validity_timer_ms: 5120,
            rsrp_change_threshold_db: 6.0,
            max_consecutive_transmissions: 8,
        }
    }
}

/// Evaluation state of autonomous Timing Advance for P-PUT.
#[derive(Debug, Clone, PartialEq)]
pub enum TaValidationState {
    /// TA is valid; UE can immediately transmit P-PUT without RACH.
    Valid,
    /// TA timer expired; must fall back to 2-step RACH / SDT.
    ExpiredTimer { elapsed_ms: u32, limit_ms: u32 },
    /// Serving cell RSRP shifted excessively; UE mobility indicates TA invalid.
    ExcessiveRsrpDrift { drift_db: f64, threshold_db: f64 },
    /// Maximum consecutive transmissions reached.
    MaxTransmissionsExceeded { count: u32, max: u32 },
}

// ============================================================================
// 3. Autonomous Timing Advance Validity Tracker (TS 38.305 / TS 38.331)
// ============================================================================

/// Tracks and audits Timing Advance validity for low-power autonomous P-PUT transmissions.
#[derive(Debug)]
pub struct TaValidityTracker {
    pub criteria: PputValidityCriteria,
    elapsed_ms: u32,
    baseline_rsrp_dbm: f64,
    current_rsrp_dbm: f64,
    consecutive_tx_count: u32,
}

impl TaValidityTracker {
    pub fn new(criteria: PputValidityCriteria, initial_rsrp_dbm: f64) -> Self {
        Self {
            criteria,
            elapsed_ms: 0,
            baseline_rsrp_dbm: initial_rsrp_dbm,
            current_rsrp_dbm: initial_rsrp_dbm,
            consecutive_tx_count: 0,
        }
    }

    /// Reset tracker upon receiving new valid TA from gNB (e.g. via MAC CE or RRC Release).
    pub fn refresh_ta(&mut self, new_rsrp_dbm: f64) {
        self.elapsed_ms = 0;
        self.baseline_rsrp_dbm = new_rsrp_dbm;
        self.current_rsrp_dbm = new_rsrp_dbm;
        self.consecutive_tx_count = 0;
    }

    /// Update elapsed time and latest serving cell RSRP measurement.
    pub fn update_radio_conditions(&mut self, delta_ms: u32, measured_rsrp_dbm: f64) {
        self.elapsed_ms += delta_ms;
        self.current_rsrp_dbm = measured_rsrp_dbm;
    }

    /// Record a P-PUT transmission.
    pub fn record_transmission(&mut self) {
        self.consecutive_tx_count += 1;
    }

    /// Evaluate whether autonomous P-PUT transmission is currently permitted.
    pub fn evaluate_validity(&self) -> TaValidationState {
        if self.elapsed_ms > self.criteria.ta_validity_timer_ms {
            return TaValidationState::ExpiredTimer {
                elapsed_ms: self.elapsed_ms,
                limit_ms: self.criteria.ta_validity_timer_ms,
            };
        }

        let drift_db = (self.current_rsrp_dbm - self.baseline_rsrp_dbm).abs();
        if drift_db > self.criteria.rsrp_change_threshold_db {
            return TaValidationState::ExcessiveRsrpDrift {
                drift_db,
                threshold_db: self.criteria.rsrp_change_threshold_db,
            };
        }

        if self.consecutive_tx_count >= self.criteria.max_consecutive_transmissions {
            return TaValidationState::MaxTransmissionsExceeded {
                count: self.consecutive_tx_count,
                max: self.criteria.max_consecutive_transmissions,
            };
        }

        TaValidationState::Valid
    }
}

// ============================================================================
// 4. P-PUT Open-Loop Power Control (TS 38.213 §7.3)
// ============================================================================

/// Open-loop power control configuration for P-PUT in RRC_INACTIVE.
#[derive(Debug, Clone, PartialEq)]
pub struct PputPowerConfig {
    /// Nominal power $P_{\text{O\_SRS}}$ in dBm (typically -85.0 to -60.0 dBm).
    pub p0_srs_dbm: f64,
    /// Pathloss compensation factor $\alpha_{\text{SRS}} \in [0.0, 1.0]$.
    pub alpha_srs: f64,
    /// Maximum UE transmit power $P_{\text{CMAX}}$ in dBm (e.g. 23.0 dBm).
    pub pcmax_dbm: f64,
}

impl Default for PputPowerConfig {
    fn default() -> Self {
        Self {
            p0_srs_dbm: -80.0,
            alpha_srs: 0.8,
            pcmax_dbm: 23.0,
        }
    }
}

/// Computes open-loop transmit power for P-PUT SRS bursts.
#[derive(Debug)]
pub struct PputPowerController {
    pub config: PputPowerConfig,
}

impl PputPowerController {
    pub fn new(config: PputPowerConfig) -> Self {
        Self { config }
    }

    /// Calculate transmit power in dBm for a P-PUT resource.
    ///
    /// $$P_{\text{SRS}} = \min(P_{\text{CMAX}}, P_{\text{O\_SRS}} + \alpha_{\text{SRS}} \cdot PL + 10 \log_{10}(M_{\text{SRS}} \cdot P_{\text{ports}}))$$
    pub fn calculate_power(&self, pathloss_db: f64, num_prbs: u16, num_ports: u8) -> f64 {
        let bw_scaling = 10.0 * (num_prbs.max(1) as f64).log10();
        let port_scaling = 10.0 * (num_ports.max(1) as f64).log10();

        let open_loop = self.config.p0_srs_dbm
            + self.config.alpha_srs * pathloss_db
            + bw_scaling
            + port_scaling;

        open_loop.min(self.config.pcmax_dbm)
    }
}

// ============================================================================
// 5. Multi-TRP RTOA & AoA Measurement Aggregation (TS 38.455 NRPPa)
// ============================================================================

/// Single TRP measurement of a received P-PUT SRS burst.
#[derive(Debug, Clone, PartialEq)]
pub struct TrpMeasurement {
    pub trp_id: u32,
    pub pos_x: f64,
    pub pos_y: f64,
    pub pos_z: f64,
    /// Relative Time of Arrival (RTOA) in seconds.
    pub rtoa_seconds: f64,
    /// Azimuth Angle of Arrival (AoA) in radians $[-\pi, +\pi]$.
    pub azimuth_rad: f64,
    /// Elevation Angle of Arrival (AoA) in radians $[-\pi/2, +\pi/2]$.
    pub elevation_rad: f64,
    /// SRS-RSRP in dBm.
    pub srs_rsrp_dbm: f64,
}

// ============================================================================
// 6. Hybrid TDOA + AoA 3D Multilateration Solver (LMF in RRC_INACTIVE)
// ============================================================================

/// Result of hybrid 3D positioning estimation.
#[derive(Debug, Clone, PartialEq)]
pub struct PputPositionEstimate {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub residual_rms_m: f64,
    pub iterations: usize,
}

/// Non-linear Gauss-Newton solver fusing TDOA hyperbolas and AoA directional bearing rays.
#[derive(Debug, Clone)]
pub struct HybridTdoaAoaSolver {
    pub max_iterations: usize,
    pub convergence_eps_m: f64,
    /// Weight assigned to AoA angle constraints relative to TDOA range constraints.
    pub aoa_weight: f64,
}

impl Default for HybridTdoaAoaSolver {
    fn default() -> Self {
        Self {
            max_iterations: 25,
            convergence_eps_m: 1e-4,
            aoa_weight: 1.0,
        }
    }
}

impl HybridTdoaAoaSolver {
    pub fn new(max_iterations: usize, convergence_eps_m: f64, aoa_weight: f64) -> Self {
        Self {
            max_iterations,
            convergence_eps_m,
            aoa_weight,
        }
    }

    /// Solves 3D UE position from multi-TRP measurements (requires $\ge 2$ TRPs).
    pub fn solve(
        &self,
        measurements: &[TrpMeasurement],
    ) -> Result<PputPositionEstimate, PputError> {
        if measurements.len() < 2 {
            return Err(PputError::InsufficientMeasurements {
                required: 2,
                provided: measurements.len(),
            });
        }

        // Reference TRP is index 0
        let ref_trp = &measurements[0];
        let c = PPUT_SPEED_OF_LIGHT_M_S;

        // Initial guess: centroid of TRPs projected to typical ground height (z = 1.5 m)
        let mut x = measurements.iter().map(|m| m.pos_x).sum::<f64>() / (measurements.len() as f64);
        let mut y = measurements.iter().map(|m| m.pos_y).sum::<f64>() / (measurements.len() as f64);
        let mut z = 1.5;

        let mut iterations = 0;

        for iter in 0..self.max_iterations {
            iterations = iter + 1;

            let mut j_rows = Vec::new();
            let mut r_vals = Vec::new();

            let d_ref = ((x - ref_trp.pos_x).powi(2)
                + (y - ref_trp.pos_y).powi(2)
                + (z - ref_trp.pos_z).powi(2))
            .sqrt()
            .max(0.1);

            // 1. TDOA equations for TRP i relative to ref_trp:
            // Delta_d_i = (d_i - d_ref) - c * (rtoa_i - rtoa_ref)
            for i in 1..measurements.len() {
                let m = &measurements[i];
                let d_i = ((x - m.pos_x).powi(2) + (y - m.pos_y).powi(2) + (z - m.pos_z).powi(2))
                    .sqrt()
                    .max(0.1);

                let delta_dist_measured = (m.rtoa_seconds - ref_trp.rtoa_seconds) * c;
                let residual = (d_i - d_ref) - delta_dist_measured;

                let jx = (x - m.pos_x) / d_i - (x - ref_trp.pos_x) / d_ref;
                let jy = (y - m.pos_y) / d_i - (y - ref_trp.pos_y) / d_ref;
                let jz = (z - m.pos_z) / d_i - (z - ref_trp.pos_z) / d_ref;

                j_rows.push([jx, jy, jz]);
                r_vals.push(residual);
            }

            // 2. AoA equations for each TRP:
            // Bearing ray: [cos(el)*cos(az), cos(el)*sin(az), sin(el)]
            for m in measurements {
                let dx = x - m.pos_x;
                let dy = y - m.pos_y;
                let dz = z - m.pos_z;

                let u_x = m.elevation_rad.cos() * m.azimuth_rad.cos();
                let u_y = m.elevation_rad.cos() * m.azimuth_rad.sin();

                // Residual in orthogonal directions
                // r_az = dy * u_x - dx * u_y = 0
                let r_az = dy * u_x - dx * u_y;
                let j_az_x = -u_y * self.aoa_weight;
                let j_az_y = u_x * self.aoa_weight;
                let j_az_z = 0.0;
                j_rows.push([j_az_x, j_az_y, j_az_z]);
                r_vals.push(r_az * self.aoa_weight);

                // r_el = dz * cos(el) - (dx*cos(az) + dy*sin(az)) * sin(el) = 0
                let r_el = dz * m.elevation_rad.cos()
                    - (dx * m.azimuth_rad.cos() + dy * m.azimuth_rad.sin()) * m.elevation_rad.sin();
                let j_el_x = -m.azimuth_rad.cos() * m.elevation_rad.sin() * self.aoa_weight;
                let j_el_y = -m.azimuth_rad.sin() * m.elevation_rad.sin() * self.aoa_weight;
                let j_el_z = m.elevation_rad.cos() * self.aoa_weight;
                j_rows.push([j_el_x, j_el_y, j_el_z]);
                r_vals.push(r_el * self.aoa_weight);
            }

            // Solve normal equations: J^T J delta = - J^T r
            let (jtj, jtr) = Self::compute_normal_equations_3x3(&j_rows, &r_vals);
            let inv_jtj = match Self::invert_3x3(&jtj) {
                Some(inv) => inv,
                None => {
                    return Err(PputError::SolverDiverged(
                        "Singular matrix in hybrid TDOA+AoA positioning".to_string(),
                    ));
                }
            };

            let delta_x =
                -(inv_jtj[0][0] * jtr[0] + inv_jtj[0][1] * jtr[1] + inv_jtj[0][2] * jtr[2]);
            let delta_y =
                -(inv_jtj[1][0] * jtr[0] + inv_jtj[1][1] * jtr[1] + inv_jtj[1][2] * jtr[2]);
            let delta_z =
                -(inv_jtj[2][0] * jtr[0] + inv_jtj[2][1] * jtr[1] + inv_jtj[2][2] * jtr[2]);

            x += delta_x;
            y += delta_y;
            z += delta_z;

            let step = (delta_x * delta_x + delta_y * delta_y + delta_z * delta_z).sqrt();
            if step < self.convergence_eps_m {
                break;
            }
        }

        // Calculate final RMS residual
        let mut sum_sq = 0.0;
        for i in 1..measurements.len() {
            let m = &measurements[i];
            let d_i =
                ((x - m.pos_x).powi(2) + (y - m.pos_y).powi(2) + (z - m.pos_z).powi(2)).sqrt();
            let d_ref = ((x - ref_trp.pos_x).powi(2)
                + (y - ref_trp.pos_y).powi(2)
                + (z - ref_trp.pos_z).powi(2))
            .sqrt();
            let delta_m = (m.rtoa_seconds - ref_trp.rtoa_seconds) * c;
            let err = (d_i - d_ref) - delta_m;
            sum_sq += err * err;
        }
        let rms = (sum_sq / ((measurements.len() - 1).max(1) as f64)).sqrt();

        Ok(PputPositionEstimate {
            x,
            y,
            z,
            residual_rms_m: rms,
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
// 7. Energy & Latency Benchmarking (RRC_INACTIVE vs RRC_CONNECTED)
// ============================================================================

/// Comparative benchmark model between legacy RRC_CONNECTED positioning and Rel-18 P-PUT.
#[derive(Debug, Clone, PartialEq)]
pub struct EnergyAndLatencyComparison {
    pub legacy_latency_ms: f64,
    pub pput_latency_ms: f64,
    pub latency_reduction_ratio: f64,
    pub legacy_energy_mj: f64,
    pub pput_energy_mj: f64,
    pub energy_savings_percentage: f64,
}

/// Benchmarking engine for P-PUT low-power gains.
#[derive(Debug, Default)]
pub struct PputBenchmarkEngine;

impl PputBenchmarkEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates latency and energy consumption models.
    pub fn evaluate_savings(&self) -> EnergyAndLatencyComparison {
        // Legacy RRC_CONNECTED positioning procedure:
        // RACH (Msg1-4) ~35 ms + RRC Setup ~20 ms + Security/Capabilities ~30 ms
        // + LPP Request/SRS Config ~80 ms + SRS transmission ~10 ms + RRC Release ~25 ms
        let legacy_latency_ms = 200.0;
        let legacy_avg_power_mw = 550.0;
        let legacy_energy_mj = legacy_latency_ms * legacy_avg_power_mw * 1e-3; // 110 mJ

        // Rel-18 P-PUT in RRC_INACTIVE:
        // Wakeup & TA check ~1 ms + 2-slot SRS burst ~1 ms + RF powerdown ~1 ms
        let pput_latency_ms = 3.0;
        let pput_avg_power_mw = 400.0;
        let pput_energy_mj = pput_latency_ms * pput_avg_power_mw * 1e-3; // 1.2 mJ

        let latency_reduction_ratio = legacy_latency_ms / pput_latency_ms;
        let energy_savings_percentage = (1.0 - pput_energy_mj / legacy_energy_mj) * 100.0;

        EnergyAndLatencyComparison {
            legacy_latency_ms,
            pput_latency_ms,
            latency_reduction_ratio,
            legacy_energy_mj,
            pput_energy_mj,
            energy_savings_percentage,
        }
    }
}

// ============================================================================
// 8. End-to-End P-PUT Positioning Engine Coordinator & Metrics
// ============================================================================

/// Performance telemetry for the P-PUT subsystem.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PputMetrics {
    pub total_positioning_requests: u64,
    pub autonomous_pput_transmissions: u64,
    pub fallback_to_rach_events: u64,
    pub successful_position_fixes: u64,
    pub total_energy_saved_joules: f64,
}

/// Central Coordinator for 3GPP Rel-18 P-PUT Positioning.
#[derive(Debug)]
pub struct PputPositioningEngine {
    pub resource: PputResource,
    pub ta_tracker: TaValidityTracker,
    pub power_controller: PputPowerController,
    pub solver: HybridTdoaAoaSolver,
    pub benchmark: PputBenchmarkEngine,
    pub metrics: PputMetrics,
}

impl PputPositioningEngine {
    pub fn new(
        resource: PputResource,
        validity_criteria: PputValidityCriteria,
        initial_rsrp_dbm: f64,
        power_config: PputPowerConfig,
    ) -> Self {
        Self {
            resource,
            ta_tracker: TaValidityTracker::new(validity_criteria, initial_rsrp_dbm),
            power_controller: PputPowerController::new(power_config),
            solver: HybridTdoaAoaSolver::default(),
            benchmark: PputBenchmarkEngine::new(),
            metrics: PputMetrics::default(),
        }
    }

    /// Trigger P-PUT transmission in RRC_INACTIVE.
    ///
    /// If TA is valid, computes transmit power and permits autonomous transmission.
    /// If TA is invalid, returns error indicating RACH fallback requirement.
    pub fn attempt_pput_transmission(
        &mut self,
        serving_pathloss_db: f64,
    ) -> Result<f64, PputError> {
        self.metrics.total_positioning_requests += 1;

        match self.ta_tracker.evaluate_validity() {
            TaValidationState::Valid => {
                self.ta_tracker.record_transmission();
                self.metrics.autonomous_pput_transmissions += 1;

                let tx_power = self.power_controller.calculate_power(
                    serving_pathloss_db,
                    self.resource.num_prbs,
                    self.resource.num_ports,
                );

                // Energy savings accumulation
                let comp = self.benchmark.evaluate_savings();
                self.metrics.total_energy_saved_joules +=
                    (comp.legacy_energy_mj - comp.pput_energy_mj) * 1e-3;

                Ok(tx_power)
            }
            TaValidationState::ExpiredTimer {
                elapsed_ms,
                limit_ms,
            } => {
                self.metrics.fallback_to_rach_events += 1;
                Err(PputError::TaValidationFailed(format!(
                    "TA timer expired ({elapsed_ms} ms > {limit_ms} ms); RACH fallback required"
                )))
            }
            TaValidationState::ExcessiveRsrpDrift {
                drift_db,
                threshold_db,
            } => {
                self.metrics.fallback_to_rach_events += 1;
                Err(PputError::TaValidationFailed(format!(
                    "RSRP drift {drift_db:.1} dB exceeds threshold {threshold_db:.1} dB; RACH fallback required"
                )))
            }
            TaValidationState::MaxTransmissionsExceeded { count, max } => {
                self.metrics.fallback_to_rach_events += 1;
                Err(PputError::TaValidationFailed(format!(
                    "Max consecutive transmissions reached ({count} >= {max}); TA refresh required"
                )))
            }
        }
    }

    /// Process TRP measurements in LMF to compute 3D position estimate.
    pub fn compute_position(
        &mut self,
        measurements: &[TrpMeasurement],
    ) -> Result<PputPositionEstimate, PputError> {
        match self.solver.solve(measurements) {
            Ok(est) => {
                self.metrics.successful_position_fixes += 1;
                Ok(est)
            }
            Err(e) => Err(e),
        }
    }
}

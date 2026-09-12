//! 3GPP Release 18 (5G-Advanced) Non-Terrestrial Network (NTN) Satellite Mobility Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.300 Rel-18 §16.14: "Mobility in Non-Terrestrial Networks (NTN) - Earth-moving vs Earth-fixed beams, Feeder link switchover"
//! - 3GPP TS 38.331 Rel-18 §5.3.5.4: "Conditional reconfiguration - CHO for NTN (Time-based and Location-based conditions)"
//! - 3GPP TS 38.331 Rel-18 §6.3.2: "RRC Information Elements - condReconfigInfoNTN, ntn-Config, EphemerisInfo"
//! - 3GPP TR 38.821 Rel-18: "Solutions for NR to support Non-Terrestrial Networks (NTN)"
//!
//! Pure standard Rust (`std` / `core` only) with zero external dependencies.

use std::f64::consts::PI;
use std::fmt;

// ============================================================================
// 1. Constants & Astronomical Parameters
// ============================================================================

/// Speed of light in vacuum (meters per second).
pub const NTN_MOB_SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

/// Mean Earth equatorial radius (meters, WGS-84).
pub const NTN_MOB_EARTH_RADIUS_M: f64 = 6_371_000.0;

/// Standard Earth gravitational parameter $\mu = GM$ ($m^3/s^2$).
pub const NTN_MOB_EARTH_MU: f64 = 3.986_004_418e14;

/// Default minimum elevation angle mask in degrees (e.g. 10.0 degrees).
pub const DEFAULT_NTN_MIN_ELEVATION_DEG: f64 = 10.0;

// ============================================================================
// 2. Error Types
// ============================================================================

/// Errors encountered in 3GPP Rel-18 NTN mobility and handover operations.
#[derive(Debug, Clone, PartialEq)]
pub enum NtnMobilityError {
    /// Invalid orbital parameters (e.g. altitude <= 0).
    InvalidOrbit(String),
    /// Handover execution condition failed or not yet met.
    ExecutionConditionNotMet(String),
    /// Candidate target satellite not found or unprepared.
    CandidateNotFound(u32),
    /// Feeder link switchover error.
    FeederLinkSwitchoverError(String),
    /// Target satellite TA or Doppler precompensation out of range.
    PrecompensationError(String),
}

impl fmt::Display for NtnMobilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtnMobilityError::InvalidOrbit(msg) => write!(f, "Invalid NTN orbit: {msg}"),
            NtnMobilityError::ExecutionConditionNotMet(msg) => {
                write!(f, "CHO execution condition not met: {msg}")
            }
            NtnMobilityError::CandidateNotFound(id) => {
                write!(f, "Target candidate satellite {id} not found")
            }
            NtnMobilityError::FeederLinkSwitchoverError(msg) => {
                write!(f, "Feeder link switchover error: {msg}")
            }
            NtnMobilityError::PrecompensationError(msg) => {
                write!(f, "Target precompensation error: {msg}")
            }
        }
    }
}

// ============================================================================
// 3. 3D Vector Geometry & Coordinate Kinematics
// ============================================================================

/// 3D Cartesian vector in Earth-Centered Earth-Fixed (ECEF) or Inertial frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vector3D {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vector3D {
    pub fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub fn zero() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        }
    }

    pub fn norm(&self) -> f64 {
        (self.x * self.x + self.y * self.y + self.z * self.z).sqrt()
    }

    pub fn dot(&self, other: &Self) -> f64 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }

    pub fn scale(&self, s: f64) -> Self {
        Self {
            x: self.x * s,
            y: self.y * s,
            z: self.z * s,
        }
    }

    pub fn unit(&self) -> Self {
        let n = self.norm();
        if n > 1e-12 {
            self.scale(1.0 / n)
        } else {
            Self::zero()
        }
    }
}

// ============================================================================
// 4. Satellite Orbit & Ephemeris Kinematics (TS 38.331 EphemerisInfo)
// ============================================================================

/// Satellite orbit state modeling circular LEO orbit propagation.
#[derive(Debug, Clone, PartialEq)]
pub struct SatelliteOrbitState {
    pub satellite_id: u32,
    /// Orbital altitude in meters (e.g. 600,000 m for 600 km LEO).
    pub altitude_m: f64,
    /// Orbital inclination in radians.
    pub inclination_rad: f64,
    /// Right Ascension of Ascending Node (RAAN) in radians.
    pub raan_rad: f64,
    /// Initial true anomaly at t = 0 in radians.
    pub initial_anomaly_rad: f64,
    /// Center carrier frequency in Hz (e.g. 2.0 GHz S-band or 20.0 GHz Ka-band).
    pub carrier_freq_hz: f64,
}

impl SatelliteOrbitState {
    pub fn new_leo(
        satellite_id: u32,
        altitude_m: f64,
        inclination_deg: f64,
        raan_deg: f64,
        initial_anomaly_deg: f64,
        carrier_freq_hz: f64,
    ) -> Result<Self, NtnMobilityError> {
        if altitude_m <= 0.0 {
            return Err(NtnMobilityError::InvalidOrbit(format!(
                "Altitude must be positive: {altitude_m} m"
            )));
        }

        Ok(Self {
            satellite_id,
            altitude_m,
            inclination_rad: inclination_deg * PI / 180.0,
            raan_rad: raan_deg * PI / 180.0,
            initial_anomaly_rad: initial_anomaly_deg * PI / 180.0,
            carrier_freq_hz,
        })
    }

    /// Semi-major axis $a = R_E + h$.
    pub fn semi_major_axis_m(&self) -> f64 {
        NTN_MOB_EARTH_RADIUS_M + self.altitude_m
    }

    /// Orbital angular velocity $\omega = \sqrt{\mu / a^3}$ (rad/s).
    pub fn mean_motion_rad_s(&self) -> f64 {
        (NTN_MOB_EARTH_MU / self.semi_major_axis_m().powi(3)).sqrt()
    }

    /// Orbital period in seconds.
    pub fn orbital_period_s(&self) -> f64 {
        2.0 * PI / self.mean_motion_rad_s()
    }

    /// Propagate satellite position $\mathbf{r}(t)$ and velocity $\mathbf{v}(t)$ at elapsed time $t$ seconds.
    pub fn propagate(&self, t_seconds: f64) -> (Vector3D, Vector3D) {
        let a = self.semi_major_axis_m();
        let omega = self.mean_motion_rad_s();
        let u = self.initial_anomaly_rad + omega * t_seconds; // Argument of latitude

        let cos_u = u.cos();
        let sin_u = u.sin();
        let cos_raan = self.raan_rad.cos();
        let sin_raan = self.raan_rad.sin();
        let cos_i = self.inclination_rad.cos();
        let sin_i = self.inclination_rad.sin();

        // Orbital plane coordinates
        let x_orb = a * cos_u;
        let y_orb = a * sin_u;

        // Position in ECEF frame (assuming Earth rotation small over single pass or compensated)
        let x = x_orb * cos_raan - y_orb * cos_i * sin_raan;
        let y = x_orb * sin_raan + y_orb * cos_i * cos_raan;
        let z = y_orb * sin_i;

        // Velocity vector in ECEF
        let v_orb = omega * a;
        let vx_orb = -v_orb * sin_u;
        let vy_orb = v_orb * cos_u;

        let vx = vx_orb * cos_raan - vy_orb * cos_i * sin_raan;
        let vy = vx_orb * sin_raan + vy_orb * cos_i * cos_raan;
        let vz = vy_orb * sin_i;

        (Vector3D::new(x, y, z), Vector3D::new(vx, vy, vz))
    }
}

// ============================================================================
// 5. Ground UE Location & Topocentric Geometry
// ============================================================================

/// Geodetic location of the Ground UE.
#[derive(Debug, Clone, PartialEq)]
pub struct GroundUeLocation {
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub alt_m: f64,
}

impl GroundUeLocation {
    pub fn new(lat_deg: f64, lon_deg: f64, alt_m: f64) -> Self {
        Self {
            lat_deg,
            lon_deg,
            alt_m,
        }
    }

    /// Convert to ECEF position vector.
    pub fn to_ecef(&self) -> Vector3D {
        let lat_rad = self.lat_deg * PI / 180.0;
        let lon_rad = self.lon_deg * PI / 180.0;
        let r = NTN_MOB_EARTH_RADIUS_M + self.alt_m;

        let x = r * lat_rad.cos() * lon_rad.cos();
        let y = r * lat_rad.cos() * lon_rad.sin();
        let z = r * lat_rad.sin();

        Vector3D::new(x, y, z)
    }

    /// Local zenith (Up) unit vector in ECEF.
    pub fn up_unit_vector(&self) -> Vector3D {
        self.to_ecef().unit()
    }
}

// ============================================================================
// 6. NTN Beam Footprint Types (TS 38.300 §16.14)
// ============================================================================

/// Antenna beam footprint tracking scheme.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NtnBeamType {
    /// Phased-array steers beam to fixed ground cell coordinates.
    /// Handover occurs when satellite drops below minimum elevation.
    EarthFixed {
        cell_center_lat_deg: f64,
        cell_center_lon_deg: f64,
    },
    /// Fixed antenna pattern moves across Earth's surface with satellite ground velocity (~7 km/s).
    /// Handover occurs frequently as beam sweeps past UE.
    EarthMoving { beam_radius_km: f64 },
}

// ============================================================================
// 7. Time & Location-Based Conditional Handover (CHO-NTN, TS 38.331 §5.3.5.4)
// ============================================================================

/// Conditional Handover execution criteria for NTN (TS 38.331 `condReconfigInfoNTN`).
#[derive(Debug, Clone, PartialEq)]
pub enum NtnChoExecutionCondition {
    /// Time-based execution: Handover triggers when absolute elapsed time $\ge T_1$.
    TimeBased { t1_threshold_s: f64 },
    /// Location-based execution: Handover triggers when distance from UE to serving beam center $\ge D_{\text{thresh}}$.
    LocationBased { max_distance_to_cell_center_m: f64 },
    /// Combined Time and Location: Both criteria must be satisfied.
    TimeAndLocationCombined {
        t1_threshold_s: f64,
        max_distance_to_cell_center_m: f64,
    },
    /// Elevation-based execution: Handover triggers when serving satellite elevation $\le \theta_{\min}$.
    ElevationThreshold { min_elevation_deg: f64 },
}

/// Prepared target candidate satellite cell for Conditional Handover.
#[derive(Debug, Clone, PartialEq)]
pub struct NtnChoCandidate {
    pub candidate_id: u32,
    pub target_sat_id: u32,
    pub target_cell_pci: u16,
    pub condition: NtnChoExecutionCondition,
    pub target_orbit: SatelliteOrbitState,
    pub cfra_preamble_index: Option<u8>,
    pub is_prepared: bool,
}

// ============================================================================
// 8. Autonomous Target Satellite TA & Doppler Precompensation
// ============================================================================

/// Calculated target satellite synchronization state for immediate connection.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetPrecompensationState {
    pub slant_range_m: f64,
    pub relative_velocity_m_s: f64,
    /// Timing Advance in seconds: $TA = 2 d / c$.
    pub timing_advance_s: f64,
    /// Doppler shift in Hz: $f_d = -(v_{\text{rel}} / c) f_c$.
    pub doppler_shift_hz: f64,
    /// Elevation angle to target satellite in degrees.
    pub elevation_deg: f64,
}

/// Computes autonomous TA and Doppler precompensation for target satellite.
#[derive(Debug)]
pub struct TargetSatellitePrecompensationServo;

impl TargetSatellitePrecompensationServo {
    pub fn compute(
        ue_loc: &GroundUeLocation,
        target_orbit: &SatelliteOrbitState,
        t_seconds: f64,
    ) -> TargetPrecompensationState {
        let r_ue = ue_loc.to_ecef();
        let u_up = ue_loc.up_unit_vector();
        let (r_sat, v_sat) = target_orbit.propagate(t_seconds);

        let rho = r_sat.sub(&r_ue);
        let d = rho.norm();
        let c = NTN_MOB_SPEED_OF_LIGHT_M_S;

        // Relative velocity projected onto line of sight
        let v_rel = rho.dot(&v_sat) / d;

        // Elevation angle
        let sin_el = rho.dot(&u_up) / d;
        let el_deg = sin_el.clamp(-1.0, 1.0).asin() * 180.0 / PI;

        let ta_s = (2.0 * d) / c;
        let doppler_hz = -(v_rel / c) * target_orbit.carrier_freq_hz;

        TargetPrecompensationState {
            slant_range_m: d,
            relative_velocity_m_s: v_rel,
            timing_advance_s: ta_s,
            doppler_shift_hz: doppler_hz,
            elevation_deg: el_deg,
        }
    }
}

// ============================================================================
// 9. Feeder Link Switchover (FLS) Manager (TS 38.300 §16.14)
// ============================================================================

/// Operational phase of a Ground Gateway Feeder Link Switchover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlsPhase {
    /// Normal operation on Source Gateway.
    NormalSourceGateway,
    /// Uplink transmission paused to drain buffers.
    UplinkMuting,
    /// Satellite RF feeder beam steered to Target Gateway; in-flight buffers forwarded.
    GatewayRerouting,
    /// Seamless operation resumed on Target Gateway.
    CompletedTargetGateway,
}

/// Manages seamless ground gateway switchover without packet loss.
#[derive(Debug)]
pub struct FeederLinkSwitchoverManager {
    pub source_gw_id: u32,
    pub target_gw_id: u32,
    pub phase: FlsPhase,
    pub muting_duration_ms: f64,
    pub switchover_time_s: f64,
    pub buffered_bytes: usize,
    pub forwarded_packets: u64,
}

impl FeederLinkSwitchoverManager {
    pub fn new(
        source_gw_id: u32,
        target_gw_id: u32,
        switchover_time_s: f64,
        muting_duration_ms: f64,
    ) -> Self {
        Self {
            source_gw_id,
            target_gw_id,
            phase: FlsPhase::NormalSourceGateway,
            muting_duration_ms,
            switchover_time_s,
            buffered_bytes: 0,
            forwarded_packets: 0,
        }
    }

    /// Update FLS phase at current simulation timestamp.
    pub fn update_time(&mut self, current_time_s: f64) -> FlsPhase {
        let dt = current_time_s - self.switchover_time_s;
        let muting_s = self.muting_duration_ms * 1e-3;

        if dt < 0.0 {
            self.phase = FlsPhase::NormalSourceGateway;
        } else if dt <= muting_s {
            self.phase = FlsPhase::UplinkMuting;
        } else if dt <= muting_s * 2.0 {
            self.phase = FlsPhase::GatewayRerouting;
        } else {
            self.phase = FlsPhase::CompletedTargetGateway;
        }

        self.phase
    }

    /// Buffer packet if switchover is underway; otherwise allow direct forwarding.
    pub fn handle_packet(&mut self, packet_size_bytes: usize) -> bool {
        match self.phase {
            FlsPhase::NormalSourceGateway | FlsPhase::CompletedTargetGateway => true,
            FlsPhase::UplinkMuting | FlsPhase::GatewayRerouting => {
                self.buffered_bytes += packet_size_bytes;
                self.forwarded_packets += 1;
                false // Buffered, do not send immediately
            }
        }
    }
}

// ============================================================================
// 10. End-to-End NTN Satellite Mobility & Handover Coordinator
// ============================================================================

/// Telemetry metrics for NTN satellite mobility.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NtnMobilityMetrics {
    pub total_elevation_audits: u64,
    pub cho_evaluations: u64,
    pub successful_handovers: u64,
    pub failed_handovers: u64,
    pub fls_switchovers_completed: u64,
    pub target_precompensations_computed: u64,
}

/// Central Coordinator for 3GPP Rel-18 NTN Satellite Mobility & Handover.
#[derive(Debug)]
pub struct NtnMobilityEngine {
    pub ue_location: GroundUeLocation,
    pub serving_orbit: SatelliteOrbitState,
    pub serving_cell_pci: u16,
    pub beam_type: NtnBeamType,
    pub candidates: Vec<NtnChoCandidate>,
    pub fls_manager: Option<FeederLinkSwitchoverManager>,
    pub metrics: NtnMobilityMetrics,
}

impl NtnMobilityEngine {
    pub fn new(
        ue_location: GroundUeLocation,
        serving_orbit: SatelliteOrbitState,
        serving_cell_pci: u16,
        beam_type: NtnBeamType,
    ) -> Self {
        Self {
            ue_location,
            serving_orbit,
            serving_cell_pci,
            beam_type,
            candidates: Vec::new(),
            fls_manager: None,
            metrics: NtnMobilityMetrics::default(),
        }
    }

    /// Register a prepared target candidate satellite for Conditional Handover.
    pub fn add_cho_candidate(&mut self, candidate: NtnChoCandidate) {
        self.candidates.push(candidate);
    }

    /// Configure Feeder Link Switchover manager.
    pub fn set_feeder_link_switchover(&mut self, fls: FeederLinkSwitchoverManager) {
        self.fls_manager = Some(fls);
    }

    /// Calculate instantaneous elevation angle to serving satellite in degrees.
    pub fn compute_serving_elevation_deg(&mut self, t_seconds: f64) -> f64 {
        self.metrics.total_elevation_audits += 1;
        let r_ue = self.ue_location.to_ecef();
        let u_up = self.ue_location.up_unit_vector();
        let (r_sat, _) = self.serving_orbit.propagate(t_seconds);

        let rho = r_sat.sub(&r_ue);
        let d = rho.norm();
        let sin_el = rho.dot(&u_up) / d;

        sin_el.clamp(-1.0, 1.0).asin() * 180.0 / PI
    }

    /// Evaluate Conditional Handover (CHO) triggers across all prepared candidates.
    ///
    /// Returns index of candidate if its execution condition is satisfied.
    pub fn evaluate_cho_triggers(&mut self, t_seconds: f64) -> Option<usize> {
        self.metrics.cho_evaluations += 1;
        let current_serving_el = self.compute_serving_elevation_deg(t_seconds);

        for (idx, candidate) in self.candidates.iter().enumerate() {
            if !candidate.is_prepared {
                continue;
            }

            let triggered = match &candidate.condition {
                NtnChoExecutionCondition::TimeBased { t1_threshold_s } => {
                    t_seconds >= *t1_threshold_s
                }
                NtnChoExecutionCondition::ElevationThreshold { min_elevation_deg } => {
                    current_serving_el <= *min_elevation_deg
                }
                NtnChoExecutionCondition::LocationBased {
                    max_distance_to_cell_center_m,
                } => {
                    match self.beam_type {
                        NtnBeamType::EarthFixed {
                            cell_center_lat_deg,
                            cell_center_lon_deg,
                        } => {
                            let center = GroundUeLocation::new(
                                cell_center_lat_deg,
                                cell_center_lon_deg,
                                0.0,
                            );
                            let dist = self.ue_location.to_ecef().sub(&center.to_ecef()).norm();
                            dist >= *max_distance_to_cell_center_m
                        }
                        NtnBeamType::EarthMoving { beam_radius_km } => {
                            let (r_sat, _) = self.serving_orbit.propagate(t_seconds);
                            // Nadir ground point
                            let nadir = r_sat.unit().scale(NTN_MOB_EARTH_RADIUS_M);
                            let dist_m = self.ue_location.to_ecef().sub(&nadir).norm();
                            dist_m >= (beam_radius_km * 1000.0)
                        }
                    }
                }
                NtnChoExecutionCondition::TimeAndLocationCombined {
                    t1_threshold_s,
                    max_distance_to_cell_center_m,
                } => {
                    let time_ok = t_seconds >= *t1_threshold_s;
                    let (r_sat, _) = self.serving_orbit.propagate(t_seconds);
                    let nadir = r_sat.unit().scale(NTN_MOB_EARTH_RADIUS_M);
                    let dist_m = self.ue_location.to_ecef().sub(&nadir).norm();
                    let loc_ok = dist_m >= *max_distance_to_cell_center_m;
                    time_ok && loc_ok
                }
            };

            if triggered {
                return Some(idx);
            }
        }

        None
    }

    /// Execute Handover to the specified candidate satellite.
    ///
    /// Pre-calculates target Timing Advance and Doppler offset so connection is immediate.
    pub fn execute_handover(
        &mut self,
        candidate_idx: usize,
        t_seconds: f64,
    ) -> Result<TargetPrecompensationState, NtnMobilityError> {
        if candidate_idx >= self.candidates.len() {
            self.metrics.failed_handovers += 1;
            return Err(NtnMobilityError::CandidateNotFound(candidate_idx as u32));
        }

        let candidate = &self.candidates[candidate_idx];
        let precomp = TargetSatellitePrecompensationServo::compute(
            &self.ue_location,
            &candidate.target_orbit,
            t_seconds,
        );

        self.metrics.target_precompensations_computed += 1;

        if precomp.elevation_deg < DEFAULT_NTN_MIN_ELEVATION_DEG {
            self.metrics.failed_handovers += 1;
            return Err(NtnMobilityError::PrecompensationError(format!(
                "Target satellite elevation {} deg is below minimum mask {} deg",
                precomp.elevation_deg, DEFAULT_NTN_MIN_ELEVATION_DEG
            )));
        }

        // Switch serving satellite and PCI
        self.serving_orbit = candidate.target_orbit.clone();
        self.serving_cell_pci = candidate.target_cell_pci;
        self.metrics.successful_handovers += 1;

        Ok(precomp)
    }
}

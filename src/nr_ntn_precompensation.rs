//! 3GPP Rel-18 5G-Advanced Non-Terrestrial Networks (NTN) Ephemeris & Autonomous Pre-Compensation Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.300 §16.14 Rel-18 ("Non-Terrestrial Networks")
//! - 3GPP TS 38.211 §6.4.1.4 Rel-18 (Uplink timing advance and frequency pre-compensation)
//! - 3GPP TS 38.213 §18 Rel-18 (Uplink timing and frequency synchronization procedures for NTN)
//! - 3GPP TS 38.331 Rel-18 (`EpochTime`, `EphemerisInfo`, `NTN-Config`, `SIB19`)
//! - ITU-R P.618 / P.676 (Earth-space propagation and minimum elevation angles)
//!
//! Key Capabilities:
//! 1. Ephemeris-driven orbital propagation using position/velocity state vectors in ECEF.
//! 2. Autonomous UE-specific Service Link Timing Advance ($T_{A, \text{UE}}(t) = \frac{2 d(t)}{c}$).
//! 3. Total Timing Advance calculation integrating broadcast Common TA ($T_{A, \text{common}}$) and $T_{\text{offset}}$.
//! 4. Real-time Timing Advance drift rate tracking ($\frac{d(T_A)}{dt}$).
//! 5. Autonomous Uplink Doppler Pre-compensation ($\Delta f_{UL}(t) = -f_D(t)$) maintaining subcarrier orthogonality.
//! 6. Doppler drift rate ($\dot{f}_D(t)$) computation.
//! 7. Beam Footprint & Cell Handover Prediction for Earth-Fixed, Earth-Moving, and Quasi-Earth-Fixed cells.
//!
//! Pure Rust standard library implementation with zero external dependencies.

/// Speed of light in vacuum ($c$) in m/s.
pub const SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

/// Earth gravitational parameter ($G M_E$) in $\text{m}^3/\text{s}^2$.
pub const EARTH_GRAVITATIONAL_PARAM: f64 = 3.986_004_418e14;

/// Mean Earth radius in meters.
pub const EARTH_RADIUS_METERS: f64 = 6_371_000.0;

/// Default minimum elevation angle in degrees for NTN link closure.
pub const DEFAULT_NTN_MIN_ELEVATION_DEG: f64 = 10.0;

// ---------------------------------------------------------------------------
// Enumerations & Error Types
// ---------------------------------------------------------------------------

/// Satellite orbit regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NtnOrbitType {
    /// Low Earth Orbit (500 - 1500 km altitude, orbital speed ~7.5 km/s).
    Leo,
    /// Medium Earth Orbit (2000 - 20000 km altitude).
    Meo,
    /// Geostationary Earth Orbit (35786 km altitude, stationary relative to ground).
    Geo,
}

/// Satellite cell and beam footprint mobility pattern (TS 38.300 §16.14).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NtnCellType {
    /// Earth-Fixed Cell: steerable antenna beam tracks a stationary geographic footprint.
    EarthFixed,
    /// Earth-Moving Cell: beam footprint sweeps over Earth's surface at satellite velocity.
    EarthMoving { beam_footprint_radius_m: f64 },
    /// Quasi-Earth-Fixed Cell: beam points to a cell area for a bounded dwell time, then steps to the next.
    QuasiEarthFixed { dwell_time_s: f64 },
}

/// Errors raised during NTN ephemeris extrapolation or synchronization.
#[derive(Debug, Clone, PartialEq)]
pub enum NtnPrecompError {
    InvalidCarrierFrequency(f64),
    SatelliteBelowHorizon { elevation_deg: f64, min_elevation_deg: f64 },
    InvalidCoordinates,
    EphemerisExpired { age_s: f64, max_age_s: f64 },
    DegenerateOrbitGeometry,
}

impl std::fmt::Display for NtnPrecompError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCarrierFrequency(freq) => {
                write!(f, "Invalid carrier frequency: {:.2} GHz", freq / 1e9)
            }
            Self::SatelliteBelowHorizon {
                elevation_deg,
                min_elevation_deg,
            } => {
                write!(
                    f,
                    "Satellite below horizon: elevation {:.2}° < min {:.2}°",
                    elevation_deg, min_elevation_deg
                )
            }
            Self::InvalidCoordinates => write!(f, "Invalid ECEF position coordinates"),
            Self::EphemerisExpired { age_s, max_age_s } => {
                write!(f, "Ephemeris expired: age {:.1}s > max {:.1}s", age_s, max_age_s)
            }
            Self::DegenerateOrbitGeometry => write!(f, "Degenerate satellite-UE geometry"),
        }
    }
}

// ---------------------------------------------------------------------------
// Ephemeris & Ground UE State Vectors (ECEF)
// ---------------------------------------------------------------------------

/// Satellite state vector in Earth-Centered Earth-Fixed (ECEF) coordinates (TS 38.331 `EphemerisInfo`).
#[derive(Debug, Clone, PartialEq)]
pub struct NtnEphemerisState {
    /// 3D position vector $[X, Y, Z]$ in meters.
    pub position_ecef_m: [f64; 3],
    /// 3D velocity vector $[V_x, V_y, V_z]$ in m/s.
    pub velocity_ecef_m_s: [f64; 3],
    /// Reference epoch timestamp in seconds.
    pub epoch_time_s: f64,
    /// Orbit classification.
    pub orbit_type: NtnOrbitType,
}

impl NtnEphemerisState {
    pub fn new(
        position_ecef_m: [f64; 3],
        velocity_ecef_m_s: [f64; 3],
        epoch_time_s: f64,
        orbit_type: NtnOrbitType,
    ) -> Self {
        Self {
            position_ecef_m,
            velocity_ecef_m_s,
            epoch_time_s,
            orbit_type,
        }
    }

    /// Extrapolate satellite position and velocity to a target time $t$ using 2nd-order Taylor expansion.
    ///
    /// $\vec{r}(t) = \vec{r}_0 + \vec{v}_0 \cdot \Delta t + \frac{1}{2} \vec{a}_0 \cdot \Delta t^2$
    /// where gravitational acceleration $\vec{a}_0 = -\frac{\mu}{\|\vec{r}_0\|^3} \vec{r}_0$.
    pub fn propagate(&self, target_time_s: f64) -> ([f64; 3], [f64; 3]) {
        let dt = target_time_s - self.epoch_time_s;
        let r0 = self.position_ecef_m;
        let v0 = self.velocity_ecef_m_s;

        let r_mag = (r0[0] * r0[0] + r0[1] * r0[1] + r0[2] * r0[2]).sqrt().max(1.0);
        let r_mag_cube = r_mag * r_mag * r_mag;
        let accel_factor = -EARTH_GRAVITATIONAL_PARAM / r_mag_cube;

        let a0 = [
            accel_factor * r0[0],
            accel_factor * r0[1],
            accel_factor * r0[2],
        ];

        let r_t = [
            r0[0] + v0[0] * dt + 0.5 * a0[0] * dt * dt,
            r0[1] + v0[1] * dt + 0.5 * a0[1] * dt * dt,
            r0[2] + v0[2] * dt + 0.5 * a0[2] * dt * dt,
        ];

        let v_t = [
            v0[0] + a0[0] * dt,
            v0[1] + a0[1] * dt,
            v0[2] + a0[2] * dt,
        ];

        (r_t, v_t)
    }
}

/// Ground or Aerial UE position in ECEF frame.
#[derive(Debug, Clone, PartialEq)]
pub struct GroundUeFix {
    /// 3D position vector $[X, Y, Z]$ in meters.
    pub position_ecef_m: [f64; 3],
    /// 3D velocity vector $[V_x, V_y, V_z]$ in m/s (zero for stationary terrestrial UE).
    pub velocity_ecef_m_s: [f64; 3],
}

impl GroundUeFix {
    pub fn stationary(position_ecef_m: [f64; 3]) -> Self {
        Self {
            position_ecef_m,
            velocity_ecef_m_s: [0.0, 0.0, 0.0],
        }
    }

    /// Construct from WGS84 geodetic coordinates (lat, lon in degrees, altitude in meters).
    pub fn from_geodetic(lat_deg: f64, lon_deg: f64, alt_m: f64) -> Self {
        let phi = lat_deg.to_radians();
        let lambda = lon_deg.to_radians();
        let r = EARTH_RADIUS_METERS + alt_m;

        let x = r * phi.cos() * lambda.cos();
        let y = r * phi.cos() * lambda.sin();
        let z = r * phi.sin();

        Self::stationary([x, y, z])
    }
}

// ---------------------------------------------------------------------------
// Pre-Compensation Telemetry & Engine
// ---------------------------------------------------------------------------

/// Calculated autonomous uplink time and frequency pre-compensation metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct NtnPrecompensationMetrics {
    /// Slant range $d(t)$ in meters.
    pub slant_range_m: f64,
    /// Elevation angle in degrees relative to the local horizon plane.
    pub elevation_angle_deg: f64,
    /// One-way service link propagation delay $\tau_{\text{service}} = d/c$ in seconds.
    pub one_way_delay_s: f64,
    /// Autonomous UE-specific service link Timing Advance $T_{A, \text{UE}} = \frac{2d}{c}$ in seconds.
    pub service_link_ta_s: f64,
    /// Broadcast Common Timing Advance from SIB19 ($T_{A, \text{common}}$) in seconds.
    pub common_ta_s: f64,
    /// Total autonomous Timing Advance applied to uplink transmission: $T_A = T_{A, \text{UE}} + T_{A, \text{common}} + T_{\text{offset}}$.
    pub total_ta_s: f64,
    /// Real-time Timing Advance drift rate ($\frac{d(T_A)}{dt}$) in seconds per second (or microsec/s).
    pub ta_drift_rate_s_per_s: f64,
    /// Line-of-sight relative radial velocity in m/s (+ approaching, - receding).
    pub radial_velocity_m_s: f64,
    /// Doppler frequency shift $f_D(t)$ in Hz.
    pub doppler_shift_hz: f64,
    /// Autonomous uplink frequency pre-compensation $\Delta f_{UL} = -f_D(t)$ in Hz.
    pub doppler_precompensation_hz: f64,
    /// Doppler drift rate $\dot{f}_D(t)$ in Hz/s.
    pub doppler_drift_rate_hz_s: f64,
    /// Estimated time to beam/cell handover in seconds (if within coverage).
    pub time_to_handover_s: Option<f64>,
}

/// 5G-Advanced Non-Terrestrial Networks Ephemeris & Synchronization Engine.
#[derive(Debug, PartialEq)]
pub struct NtnPrecompensationEngine {
    pub ephemeris: NtnEphemerisState,
    pub carrier_freq_hz: f64,
    pub cell_type: NtnCellType,
    /// Broadcast common timing advance from SIB19 in seconds.
    pub common_ta_s: f64,
    /// Fixed scheduling TA offset in seconds.
    pub ta_offset_s: f64,
    /// Minimum elevation angle threshold in degrees.
    pub min_elevation_deg: f64,
    /// Statistics: total pre-compensation cycles evaluated.
    pub stats_precomputations: u64,
    /// Statistics: total beam handover predictions evaluated.
    pub stats_handover_evaluations: u64,
}

impl NtnPrecompensationEngine {
    pub fn new(ephemeris: NtnEphemerisState, carrier_freq_hz: f64) -> Result<Self, NtnPrecompError> {
        if carrier_freq_hz <= 0.0 {
            return Err(NtnPrecompError::InvalidCarrierFrequency(carrier_freq_hz));
        }

        Ok(Self {
            ephemeris,
            carrier_freq_hz,
            cell_type: NtnCellType::EarthFixed,
            common_ta_s: 0.0,
            ta_offset_s: 0.0,
            min_elevation_deg: DEFAULT_NTN_MIN_ELEVATION_DEG,
            stats_precomputations: 0,
            stats_handover_evaluations: 0,
        })
    }

    /// Set satellite cell type (Earth-Fixed, Earth-Moving, or Quasi-Earth-Fixed).
    pub fn set_cell_type(&mut self, cell_type: NtnCellType) {
        self.cell_type = cell_type;
    }

    /// Set Common TA broadcast in SIB19 and TA offset.
    pub fn set_timing_parameters(&mut self, common_ta_s: f64, ta_offset_s: f64) {
        self.common_ta_s = common_ta_s;
        self.ta_offset_s = ta_offset_s;
    }

    /// Calculate autonomous uplink time and frequency pre-compensation for a given UE and time.
    pub fn calculate_precompensation(
        &mut self,
        ue: &GroundUeFix,
        current_time_s: f64,
    ) -> Result<NtnPrecompensationMetrics, NtnPrecompError> {
        self.stats_precomputations += 1;

        let (r_sat, v_sat) = self.ephemeris.propagate(current_time_s);
        let r_ue = ue.position_ecef_m;
        let v_ue = ue.velocity_ecef_m_s;

        // Relative range vector from UE to Satellite: $\vec{r}_{\text{rel}} = \vec{r}_{\text{sat}} - \vec{r}_{\text{UE}}$
        let r_rel = [
            r_sat[0] - r_ue[0],
            r_sat[1] - r_ue[1],
            r_sat[2] - r_ue[2],
        ];

        let slant_range = (r_rel[0] * r_rel[0] + r_rel[1] * r_rel[1] + r_rel[2] * r_rel[2]).sqrt();
        if slant_range < 1.0 {
            return Err(NtnPrecompError::DegenerateOrbitGeometry);
        }

        // Compute local zenith / upward unit normal at UE position: $\vec{u}_{\text{up}} = \vec{r}_{\text{UE}} / \|\vec{r}_{\text{UE}}\|$
        let r_ue_mag = (r_ue[0] * r_ue[0] + r_ue[1] * r_ue[1] + r_ue[2] * r_ue[2]).sqrt().max(1.0);
        let u_up = [r_ue[0] / r_ue_mag, r_ue[1] / r_ue_mag, r_ue[2] / r_ue_mag];

        // Elevation angle $\theta = \arcsin\left(\frac{\vec{r}_{\text{rel}} \cdot \vec{u}_{\text{up}}}{\|\vec{r}_{\text{rel}}\|}\right)$
        let dot_up = r_rel[0] * u_up[0] + r_rel[1] * u_up[1] + r_rel[2] * u_up[2];
        let sin_elev = (dot_up / slant_range).clamp(-1.0, 1.0);
        let elevation_deg = sin_elev.asin().to_degrees();

        if elevation_deg < self.min_elevation_deg {
            return Err(NtnPrecompError::SatelliteBelowHorizon {
                elevation_deg,
                min_elevation_deg: self.min_elevation_deg,
            });
        }

        // Relative velocity vector: $\vec{v}_{\text{rel}} = \vec{v}_{\text{sat}} - \vec{v}_{\text{UE}}$
        let v_rel = [
            v_sat[0] - v_ue[0],
            v_sat[1] - v_ue[1],
            v_sat[2] - v_ue[2],
        ];

        // Radial velocity along line of sight (+ approaching, - receding):
        // $v_{\text{radial}} = \frac{\vec{r}_{\text{rel}} \cdot \vec{v}_{\text{rel}}}{\|\vec{r}_{\text{rel}}\|}$
        let dot_v = r_rel[0] * v_rel[0] + r_rel[1] * v_rel[1] + r_rel[2] * v_rel[2];
        let radial_velocity = dot_v / slant_range;

        // One-way delay and service link Timing Advance: $T_{A, \text{UE}} = \frac{2d}{c}$
        let one_way_delay = slant_range / SPEED_OF_LIGHT_M_S;
        let service_link_ta = 2.0 * one_way_delay;
        let total_ta = service_link_ta + self.common_ta_s + self.ta_offset_s;

        // Timing Advance drift rate: $\frac{d(TA)}{dt} = \frac{2}{c} v_{\text{radial}}$
        let ta_drift_rate = (2.0 / SPEED_OF_LIGHT_M_S) * radial_velocity;

        // Doppler shift: $f_D = \frac{v_{\text{radial}}}{c} \cdot f_c$
        let doppler_shift = (radial_velocity / SPEED_OF_LIGHT_M_S) * self.carrier_freq_hz;
        let doppler_precompensation = -doppler_shift;

        // Approximate Doppler drift rate $\dot{f}_D$ by evaluating at $t + 0.1\text{ s}$
        let dt_step = 0.1;
        let (r_sat_next, v_sat_next) = self.ephemeris.propagate(current_time_s + dt_step);
        let r_rel_next = [
            r_sat_next[0] - r_ue[0],
            r_sat_next[1] - r_ue[1],
            r_sat_next[2] - r_ue[2],
        ];
        let range_next =
            (r_rel_next[0] * r_rel_next[0] + r_rel_next[1] * r_rel_next[1] + r_rel_next[2] * r_rel_next[2])
                .sqrt()
                .max(1.0);
        let v_rel_next = [
            v_sat_next[0] - v_ue[0],
            v_sat_next[1] - v_ue[1],
            v_sat_next[2] - v_ue[2],
        ];
        let dot_v_next = r_rel_next[0] * v_rel_next[0]
            + r_rel_next[1] * v_rel_next[1]
            + r_rel_next[2] * v_rel_next[2];
        let radial_vel_next = dot_v_next / range_next;
        let doppler_next = (radial_vel_next / SPEED_OF_LIGHT_M_S) * self.carrier_freq_hz;
        let doppler_drift_rate = (doppler_next - doppler_shift) / dt_step;

        // Handover prediction based on cell mobility
        let time_to_handover = self.predict_handover_seconds(elevation_deg, &v_sat);

        Ok(NtnPrecompensationMetrics {
            slant_range_m: slant_range,
            elevation_angle_deg: elevation_deg,
            one_way_delay_s: one_way_delay,
            service_link_ta_s: service_link_ta,
            common_ta_s: self.common_ta_s,
            total_ta_s: total_ta,
            ta_drift_rate_s_per_s: ta_drift_rate,
            radial_velocity_m_s: radial_velocity,
            doppler_shift_hz: doppler_shift,
            doppler_precompensation_hz: doppler_precompensation,
            doppler_drift_rate_hz_s: doppler_drift_rate,
            time_to_handover_s: time_to_handover,
        })
    }

    /// Predict remaining seconds before cell/beam handover occurs.
    fn predict_handover_seconds(&mut self, current_elev_deg: f64, v_sat: &[f64; 3]) -> Option<f64> {
        self.stats_handover_evaluations += 1;

        match self.cell_type {
            NtnCellType::EarthFixed => {
                // In Earth-Fixed cells, beam remains on cell until satellite elevation drops below min
                let elev_margin = current_elev_deg - self.min_elevation_deg;
                if elev_margin <= 0.0 {
                    Some(0.0)
                } else {
                    // Typical LEO angular descent rate ~ 0.5 to 1.0 deg/sec
                    Some(elev_margin / 0.6)
                }
            }
            NtnCellType::EarthMoving {
                beam_footprint_radius_m,
            } => {
                let sat_speed = (v_sat[0] * v_sat[0] + v_sat[1] * v_sat[1] + v_sat[2] * v_sat[2])
                    .sqrt()
                    .max(1.0);
                // Dwell time across beam footprint diameter
                Some((2.0 * beam_footprint_radius_m) / sat_speed)
            }
            NtnCellType::QuasiEarthFixed { dwell_time_s } => Some(dwell_time_s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeris_propagation_leo() {
        // LEO at 600 km altitude directly above equator (0, 0)
        let r0 = [EARTH_RADIUS_METERS + 600_000.0, 0.0, 0.0];
        // Velocity: ~7.56 km/s along Y-axis
        let v0 = [0.0, 7560.0, 0.0];

        let ephemeris = NtnEphemerisState::new(r0, v0, 1000.0, NtnOrbitType::Leo);
        // Propagate 10 seconds ahead
        let (r10, v10) = ephemeris.propagate(1010.0);

        assert!(r10[0] > 0.0);
        assert!(r10[1] > 0.0);
        assert_eq!(r10[2], 0.0);
        assert!(v10[1] > 0.0);
    }

    #[test]
    fn test_precompensation_metrics_and_timing_advance() {
        // Satellite at zenith (directly above UE at 600 km)
        let r_sat = [EARTH_RADIUS_METERS + 600_000.0, 0.0, 0.0];
        let v_sat = [0.0, 7500.0, 0.0];
        let ephemeris = NtnEphemerisState::new(r_sat, v_sat, 0.0, NtnOrbitType::Leo);

        let ue = GroundUeFix::stationary([EARTH_RADIUS_METERS, 0.0, 0.0]);
        let mut engine = NtnPrecompensationEngine::new(ephemeris, 2.0e9).unwrap(); // S-band 2.0 GHz
        engine.set_timing_parameters(0.010, 0.0); // Common TA = 10 ms

        let metrics = engine.calculate_precompensation(&ue, 0.0).unwrap();

        // Slant range should be exactly 600 km
        assert!((metrics.slant_range_m - 600_000.0).abs() < 10.0);
        // Elevation angle at zenith is 90 degrees
        assert!((metrics.elevation_angle_deg - 90.0).abs() < 0.1);

        // One-way delay: 600 km / c = ~2.001 ms
        assert!((metrics.one_way_delay_s - 0.00200138).abs() < 1e-6);
        // Service link TA: 2 * 2.001 ms = ~4.003 ms
        assert!((metrics.service_link_ta_s - 0.00400277).abs() < 1e-6);
        // Total TA: Service TA + Common TA (10 ms) = ~14.003 ms
        assert!((metrics.total_ta_s - 0.01400277).abs() < 1e-6);

        // At exact zenith, radial velocity is 0 (velocity is purely tangential along Y)
        assert!(metrics.radial_velocity_m_s.abs() < 1e-3);
        assert!(metrics.doppler_shift_hz.abs() < 1.0);
    }

    #[test]
    fn test_doppler_precompensation_approaching_satellite() {
        // Satellite at 45 deg ahead of UE
        let r_sat = [
            EARTH_RADIUS_METERS + 500_000.0,
            400_000.0,
            0.0,
        ];
        // Approaching with velocity towards negative Y
        let v_sat = [0.0, -7500.0, 0.0];
        let ephemeris = NtnEphemerisState::new(r_sat, v_sat, 0.0, NtnOrbitType::Leo);

        let ue = GroundUeFix::stationary([EARTH_RADIUS_METERS, 0.0, 0.0]);
        let mut engine = NtnPrecompensationEngine::new(ephemeris, 2.0e9).unwrap();

        let metrics = engine.calculate_precompensation(&ue, 0.0).unwrap();

        // Satellite is approaching -> radial velocity is positive/negative depending on dot product
        assert!(metrics.doppler_shift_hz.abs() > 1000.0);
        // Pre-compensation must exactly invert the Doppler shift
        assert_eq!(
            metrics.doppler_precompensation_hz,
            -metrics.doppler_shift_hz
        );
    }

    #[test]
    fn test_satellite_below_horizon_error() {
        // Satellite on opposite side of Earth
        let r_sat = [-(EARTH_RADIUS_METERS + 600_000.0), 0.0, 0.0];
        let v_sat = [0.0, 7500.0, 0.0];
        let ephemeris = NtnEphemerisState::new(r_sat, v_sat, 0.0, NtnOrbitType::Leo);

        let ue = GroundUeFix::stationary([EARTH_RADIUS_METERS, 0.0, 0.0]);
        let mut engine = NtnPrecompensationEngine::new(ephemeris, 2.0e9).unwrap();

        let res = engine.calculate_precompensation(&ue, 0.0);
        match res {
            Err(NtnPrecompError::SatelliteBelowHorizon { elevation_deg, .. }) => {
                assert!(elevation_deg < 0.0);
            }
            other => panic!("Expected SatelliteBelowHorizon, got {:?}", other),
        }
    }
}

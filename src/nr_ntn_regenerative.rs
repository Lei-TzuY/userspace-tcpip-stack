//! 3GPP Rel-18 5G NR Non-Terrestrial Networks (NTN) Regenerative Payload & Satellite Ephemeris Routing Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.300 Rel-18 §16.14 ("Non-Terrestrial Networks Support - Regenerative Architectures")
//! - 3GPP TR 38.821 Rel-18 ("Solutions for NR to support non-terrestrial networks")
//! - 3GPP TS 38.401 / TS 38.470 (NG-RAN Architecture and F1/E1/Xn Interface Splits)
//! - 3GPP TS 23.501 Rel-18 (5G System Architecture - Edge/Spaceborne UPF & Local Breakout)
//! - ITU-R S.1503 / S.672 (Satellite Constellation Geometry & Coordination)
//!
//! Key Capabilities:
//! 1. Multi-tier Satellite Payload Architectures:
//!    - Full gNodeB onboard (CU-CP + CU-UP + DU + Spaceborne UPF for low-latency local breakout).
//!    - gNodeB-DU onboard (F1 interface over satellite Feeder Link to Ground CU).
//!    - gNodeB-DU + CU-UP onboard (E1 interface to Ground CU-CP).
//!    - Transparent Transponder (bent-pipe RF relay for baseline comparison).
//! 2. High-Precision Keplerian Orbital Ephemeris Propagation:
//!    - Orbital elements ($a, e, i, \Omega, \omega, M_0$).
//!    - Newton-Raphson Kepler's equation solver ($M = E - e \sin E$) for arbitrary eccentricities.
//!    - Position & velocity vector transformations from orbital perifocal to ECI frame.
//!    - ECI to Earth-Centered Earth-Fixed (ECEF) transformation accounting for Earth rotation rate ($\omega_E$).
//!    - Slant range, one-way/RTT propagation latency, elevation, and azimuth calculation.
//! 3. Dynamic Inter-Satellite Link (ISL) Mesh Constellation Routing:
//!    - Laser (Optical) and Millimeter-Wave RF cross-links between satellites.
//!    - Dynamic constellation graph with time-varying inter-satellite distances and propagation latencies.
//!    - Dijkstra shortest-delay path computation across multi-plane satellite mesh networks.
//!    - Automatic link fault detection and alternate ISL detour rerouting.
//! 4. Moving Cell vs Earth-Fixed Cell Beam Footprint Management:
//!    - Earth-Moving Beams (satellite-fixed): Nadir/off-nadir spot beams sweeping ground track at ~7 km/s.
//!    - Earth-Fixed Beams (steerable phased array): Tracking fixed ground geographic coordinates with steering limits.
//!    - Ground point dwell time, beam handover prediction, and elevation threshold evaluation.
//! 5. Space Packet Forwarding & Autonomous Local Breakout:
//!    - Space packet routing headers with QoS flow identifier, ingress/egress satellite IDs, and TTL.
//!    - Onboard switching logic: intra-satellite local breakout vs multi-hop ISL forwarding vs Feeder Link downlink.
//!
//! Pure Rust standard library implementation with zero external dependencies.

use std::collections::{HashMap, VecDeque};
use std::fmt;

/// Speed of light in vacuum ($c$) in meters per second.
pub const SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

/// Standard Earth gravitational parameter ($\mu = G M_E$) in $\text{m}^3 / \text{s}^2$.
pub const EARTH_GRAVITATIONAL_PARAM: f64 = 3.986_004_418e14;

/// Mean Earth equatorial radius ($R_E$) in meters.
pub const EARTH_RADIUS_METERS: f64 = 6_371_000.0;

/// Earth nominal rotation rate ($\omega_E$) in radians per second.
pub const EARTH_ROTATION_RATE_RAD_S: f64 = 7.292_115e-5;

// ---------------------------------------------------------------------------
// 3D Cartesian Vector Math (pure standard Rust)
// ---------------------------------------------------------------------------

/// 3D Cartesian vector used for position, velocity, and direction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vector3D {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vector3D {
    /// Create a new 3D vector.
    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    /// Zero vector.
    pub const fn zero() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        }
    }

    /// Vector dot product.
    pub fn dot(&self, other: &Self) -> f64 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }

    /// Vector cross product.
    pub fn cross(&self, other: &Self) -> Self {
        Self {
            x: self.y * other.z - self.z * other.y,
            y: self.z * other.x - self.x * other.z,
            z: self.x * other.y - self.y * other.x,
        }
    }

    /// Squared magnitude (Euclidean norm).
    pub fn norm_sq(&self) -> f64 {
        self.dot(self)
    }

    /// Euclidean magnitude (norm).
    pub fn magnitude(&self) -> f64 {
        self.norm_sq().sqrt()
    }

    /// Unit vector in the same direction. Returns zero if magnitude is negligible.
    pub fn normalize(&self) -> Self {
        let mag = self.magnitude();
        if mag > 1e-12 {
            Self {
                x: self.x / mag,
                y: self.y / mag,
                z: self.z / mag,
            }
        } else {
            Self::zero()
        }
    }

    /// Vector addition.
    pub fn add(&self, other: &Self) -> Self {
        Self {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }

    /// Vector subtraction.
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }

    /// Scalar multiplication.
    pub fn scale(&self, factor: f64) -> Self {
        Self {
            x: self.x * factor,
            y: self.y * factor,
            z: self.z * factor,
        }
    }

    /// Euclidean distance to another point.
    pub fn distance_to(&self, other: &Self) -> f64 {
        self.sub(other).magnitude()
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in NTN regenerative payload and routing calculations.
#[derive(Debug, Clone, PartialEq)]
pub enum NtnRegenerativeError {
    InvalidOrbitalElements(&'static str),
    KeplerConvergenceFailed,
    SatelliteNotFound(String),
    LinkNotFound(String, String),
    NoRouteAvailable { source: String, target: String },
    TtlExceeded { hops: u8, max_hops: u8 },
    ElevationBelowHorizon { elevation_deg: f64, min_deg: f64 },
    SteeringLimitExceeded { angle_deg: f64, max_deg: f64 },
}

impl fmt::Display for NtnRegenerativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrbitalElements(msg) => write!(f, "Invalid orbital elements: {}", msg),
            Self::KeplerConvergenceFailed => {
                write!(
                    f,
                    "Newton-Raphson Kepler equation solver failed to converge"
                )
            }
            Self::SatelliteNotFound(id) => write!(f, "Satellite '{}' not registered", id),
            Self::LinkNotFound(a, b) => write!(f, "ISL link between '{}' and '{}' not found", a, b),
            Self::NoRouteAvailable { source, target } => {
                write!(f, "No route available from '{}' to '{}'", source, target)
            }
            Self::TtlExceeded { hops, max_hops } => {
                write!(f, "Space packet TTL exceeded: {}/{} hops", hops, max_hops)
            }
            Self::ElevationBelowHorizon {
                elevation_deg,
                min_deg,
            } => write!(
                f,
                "Elevation angle {:.2}° below horizon threshold {:.2}°",
                elevation_deg, min_deg
            ),
            Self::SteeringLimitExceeded { angle_deg, max_deg } => write!(
                f,
                "Beam steering angle {:.2}° exceeded limit {:.2}°",
                angle_deg, max_deg
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Payload Architecture Splits (TS 38.300 §16.14, TR 38.821)
// ---------------------------------------------------------------------------

/// Satellite Payload Architecture Split Options in 3GPP Rel-18 NTN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadArchitecture {
    /// Full gNodeB onboard (CU-CP, CU-UP, DU, Spaceborne UPF).
    /// Direct Uu termination and local breakout in space without ground Feeder Link round-trip.
    FullGnbOnboard,
    /// gNodeB-DU onboard, gNodeB-CU located at ground NTN Gateway.
    /// F1-C / F1-U interface transported across satellite Feeder Link.
    DuOnboardGroundCu,
    /// gNodeB-DU + CU-UP onboard, gNodeB-CU-CP located on ground.
    /// E1 interface to ground; user-plane data can be switched in orbit.
    DuCuUpOnboardGroundCuCp,
    /// Transparent Payload (bent-pipe RF repeater).
    /// All baseband processing is on ground; satellite acts only as RF frequency converter.
    TransparentTransponder,
}

impl PayloadArchitecture {
    /// Whether this architecture supports autonomous onboard packet switching without ground gateway loop.
    pub fn supports_local_breakout(&self) -> bool {
        matches!(self, Self::FullGnbOnboard | Self::DuCuUpOnboardGroundCuCp)
    }

    /// Nominal onboard processing delay in milliseconds for user-plane packets.
    pub fn nominal_onboard_processing_delay_ms(&self) -> f64 {
        match self {
            Self::FullGnbOnboard => 2.5,          // Full L1/L2/L3 + IP lookup
            Self::DuCuUpOnboardGroundCuCp => 2.0, // DU + PDCP + IP switching
            Self::DuOnboardGroundCu => 1.0,       // DU only (RLC/MAC/PHY)
            Self::TransparentTransponder => 0.05, // RF amplification/filtering
        }
    }
}

// ---------------------------------------------------------------------------
// Keplerian Orbital Propagation & Ephemeris
// ---------------------------------------------------------------------------

/// Keplerian Orbital Elements for a satellite.
#[derive(Debug, Clone, PartialEq)]
pub struct KeplerianElements {
    /// Semi-major axis in meters ($a > R_E$).
    pub semi_major_axis_m: f64,
    /// Orbital eccentricity ($0 \le e < 1$ for elliptic orbits).
    pub eccentricity: f64,
    /// Orbital inclination in radians ($i$).
    pub inclination_rad: f64,
    /// Right Ascension of Ascending Node in radians ($\Omega$).
    pub raan_rad: f64,
    /// Argument of Perigee in radians ($\omega$).
    pub arg_perigee_rad: f64,
    /// Mean Anomaly at epoch in radians ($M_0$).
    pub mean_anomaly_epoch_rad: f64,
    /// Epoch timestamp in seconds ($t_0$).
    pub epoch_s: f64,
}

impl KeplerianElements {
    /// Construct circular or near-circular LEO orbit parameters.
    pub fn new_leo(
        altitude_km: f64,
        eccentricity: f64,
        inclination_deg: f64,
        raan_deg: f64,
        arg_perigee_deg: f64,
        epoch_s: f64,
    ) -> Result<Self, NtnRegenerativeError> {
        if altitude_km < 160.0 {
            return Err(NtnRegenerativeError::InvalidOrbitalElements(
                "LEO altitude must be >= 160 km",
            ));
        }
        if !(0.0..1.0).contains(&eccentricity) {
            return Err(NtnRegenerativeError::InvalidOrbitalElements(
                "Eccentricity must be in range [0, 1)",
            ));
        }

        let a = (altitude_km * 1000.0) + EARTH_RADIUS_METERS;
        Ok(Self {
            semi_major_axis_m: a,
            eccentricity,
            inclination_rad: inclination_deg.to_radians(),
            raan_rad: raan_deg.to_radians(),
            arg_perigee_rad: arg_perigee_deg.to_radians(),
            mean_anomaly_epoch_rad: 0.0,
            epoch_s,
        })
    }

    /// Calculate orbital period in seconds ($T = 2\pi \sqrt{a^3 / \mu}$).
    pub fn orbital_period_s(&self) -> f64 {
        let a3 = self.semi_major_axis_m.powi(3);
        2.0 * std::f64::consts::PI * (a3 / EARTH_GRAVITATIONAL_PARAM).sqrt()
    }

    /// Calculate mean motion in radians per second ($n = \sqrt{\mu / a^3}$).
    pub fn mean_motion_rad_s(&self) -> f64 {
        (EARTH_GRAVITATIONAL_PARAM / self.semi_major_axis_m.powi(3)).sqrt()
    }

    /// Solve Kepler's equation $M = E - e \sin E$ for eccentric anomaly $E$ via Newton-Raphson.
    pub fn solve_kepler(&self, mean_anomaly_rad: f64) -> Result<f64, NtnRegenerativeError> {
        let two_pi = 2.0 * std::f64::consts::PI;
        let mut m = mean_anomaly_rad % two_pi;
        if m < 0.0 {
            m += two_pi;
        }

        let e = self.eccentricity;
        // Initial guess
        let mut ecc_anom = if e < 0.8 { m } else { std::f64::consts::PI };

        for _ in 0..64 {
            let f = ecc_anom - e * ecc_anom.sin() - m;
            let f_prime = 1.0 - e * ecc_anom.cos();
            if f_prime.abs() < 1e-15 {
                break;
            }
            let delta = f / f_prime;
            ecc_anom -= delta;
            if delta.abs() < 1e-12 {
                return Ok(ecc_anom);
            }
        }
        Err(NtnRegenerativeError::KeplerConvergenceFailed)
    }

    /// Propagate orbital state at time $t$ to ECI (Earth-Centered Inertial) frame.
    pub fn propagate_eci(&self, t_s: f64) -> Result<(Vector3D, Vector3D), NtnRegenerativeError> {
        let dt = t_s - self.epoch_s;
        let n = self.mean_motion_rad_s();
        let m = self.mean_anomaly_epoch_rad + n * dt;
        let ecc_anom = self.solve_kepler(m)?;

        let e = self.eccentricity;
        let a = self.semi_major_axis_m;

        // True anomaly nu
        let sin_e = ecc_anom.sin();
        let cos_e = ecc_anom.cos();
        let r = a * (1.0 - e * cos_e);

        let sin_nu = ((1.0 - e * e).sqrt() * sin_e) / (1.0 - e * cos_e);
        let cos_nu = (cos_e - e) / (1.0 - e * cos_e);
        let nu = sin_nu.atan2(cos_nu);

        // Position in orbital perifocal frame (PQW)
        let r_orb_x = r * nu.cos();
        let r_orb_y = r * nu.sin();

        // Velocity in orbital perifocal frame
        let p = a * (1.0 - e * e);
        let h = (EARTH_GRAVITATIONAL_PARAM * p).sqrt();
        let v_orb_x = -(EARTH_GRAVITATIONAL_PARAM / h) * nu.sin();
        let v_orb_y = (EARTH_GRAVITATIONAL_PARAM / h) * (e + nu.cos());

        // Transformation to ECI frame using (RAAN, inclination, argument of perigee)
        let o = self.raan_rad;
        let i = self.inclination_rad;
        let w = self.arg_perigee_rad;

        let px = o.cos() * w.cos() - o.sin() * w.sin() * i.cos();
        let py = o.sin() * w.cos() + o.cos() * w.sin() * i.cos();
        let pz = w.sin() * i.sin();

        let qx = -o.cos() * w.sin() - o.sin() * w.cos() * i.cos();
        let qy = -o.sin() * w.sin() + o.cos() * w.cos() * i.cos();
        let qz = w.cos() * i.sin();

        let pos_eci = Vector3D::new(
            r_orb_x * px + r_orb_y * qx,
            r_orb_x * py + r_orb_y * qy,
            r_orb_x * pz + r_orb_y * qz,
        );

        let vel_eci = Vector3D::new(
            v_orb_x * px + v_orb_y * qx,
            v_orb_x * py + v_orb_y * qy,
            v_orb_x * pz + v_orb_y * qz,
        );

        Ok((pos_eci, vel_eci))
    }

    /// Propagate orbital state at time $t$ to ECEF (Earth-Centered Earth-Fixed) frame.
    pub fn propagate_ecef(&self, t_s: f64) -> Result<(Vector3D, Vector3D), NtnRegenerativeError> {
        let (pos_eci, vel_eci) = self.propagate_eci(t_s)?;

        // Earth rotation angle theta = omega_E * t
        let theta = (EARTH_ROTATION_RATE_RAD_S * t_s) % (2.0 * std::f64::consts::PI);
        let cos_t = theta.cos();
        let sin_t = theta.sin();

        // ECI to ECEF rotation about Z-axis
        let pos_ecef = Vector3D::new(
            pos_eci.x * cos_t + pos_eci.y * sin_t,
            -pos_eci.x * sin_t + pos_eci.y * cos_t,
            pos_eci.z,
        );

        // Velocity in ECEF frame includes Earth rotation cross-product
        let vx_rot = vel_eci.x * cos_t + vel_eci.y * sin_t;
        let vy_rot = -vel_eci.x * sin_t + vel_eci.y * cos_t;
        let vz_rot = vel_eci.z;

        let omega_cross_r = Vector3D::new(
            -EARTH_ROTATION_RATE_RAD_S * pos_ecef.y,
            EARTH_ROTATION_RATE_RAD_S * pos_ecef.x,
            0.0,
        );

        let vel_ecef = Vector3D::new(vx_rot - omega_cross_r.x, vy_rot - omega_cross_r.y, vz_rot);

        Ok((pos_ecef, vel_ecef))
    }
}

// ---------------------------------------------------------------------------
// Ground Stations & Geographic Conversion
// ---------------------------------------------------------------------------

/// Ground terminal or gateway position.
#[derive(Debug, Clone, PartialEq)]
pub struct GroundStation {
    pub id: String,
    pub latitude_deg: f64,
    pub longitude_deg: f64,
    pub altitude_m: f64,
    pub position_ecef: Vector3D,
}

impl GroundStation {
    /// Create a new ground station from geodetic coordinates (Spherical approximation).
    pub fn new(id: &str, lat_deg: f64, lon_deg: f64, alt_m: f64) -> Self {
        let lat_rad = lat_deg.to_radians();
        let lon_rad = lon_deg.to_radians();
        let r = EARTH_RADIUS_METERS + alt_m;

        let x = r * lat_rad.cos() * lon_rad.cos();
        let y = r * lat_rad.cos() * lon_rad.sin();
        let z = r * lat_rad.sin();

        Self {
            id: id.to_string(),
            latitude_deg: lat_deg,
            longitude_deg: lon_deg,
            altitude_m: alt_m,
            position_ecef: Vector3D::new(x, y, z),
        }
    }

    /// Calculate slant range, elevation angle, and azimuth to a satellite in ECEF.
    pub fn compute_look_angles(&self, sat_pos_ecef: &Vector3D) -> (f64, f64, f64) {
        let slant_vec = sat_pos_ecef.sub(&self.position_ecef);
        let slant_range_m = slant_vec.magnitude();

        // Local Up, East, North unit vectors at ground station
        let lat = self.latitude_deg.to_radians();
        let lon = self.longitude_deg.to_radians();

        let up = Vector3D::new(lat.cos() * lon.cos(), lat.cos() * lon.sin(), lat.sin());
        let east = Vector3D::new(-lon.sin(), lon.cos(), 0.0);
        let north = Vector3D::new(-lat.sin() * lon.cos(), -lat.sin() * lon.sin(), lat.cos());

        // Elevation
        let sin_el = slant_vec.dot(&up) / slant_range_m;
        let elevation_deg = sin_el.clamp(-1.0, 1.0).asin().to_degrees();

        // Azimuth
        let slant_east = slant_vec.dot(&east);
        let slant_north = slant_vec.dot(&north);
        let mut azimuth_deg = slant_east.atan2(slant_north).to_degrees();
        if azimuth_deg < 0.0 {
            azimuth_deg += 360.0;
        }

        (slant_range_m, elevation_deg, azimuth_deg)
    }
}

// ---------------------------------------------------------------------------
// Beam Footprint Management: Earth-Moving vs Earth-Fixed Beams
// ---------------------------------------------------------------------------

/// Beam Footprint Steering Mode (3GPP Rel-18 NTN).
#[derive(Debug, Clone, PartialEq)]
pub enum BeamFootprintMode {
    /// Earth-Moving Beam (satellite-fixed body beam):
    /// Sweeps across Earth's surface at ground speed ($v_g \approx 7.0\text{ km/s}$).
    EarthMoving {
        beam_radius_km: f64,
        ground_track_speed_kmps: f64,
    },
    /// Earth-Fixed Beam (steerable phased array):
    /// Steers beam electronically to track a designated fixed ground area.
    EarthFixed {
        target_center_ecef: Vector3D,
        max_steering_angle_deg: f64,
    },
}

/// Satellite Spot Beam instance.
#[derive(Debug, Clone, PartialEq)]
pub struct SatelliteBeam {
    pub beam_id: u32,
    pub mode: BeamFootprintMode,
    pub boresight_nadir_angle_deg: f64,
    pub is_active: bool,
}

impl SatelliteBeam {
    /// Create a new Earth-moving spot beam.
    pub fn new_earth_moving(beam_id: u32, beam_radius_km: f64, ground_speed_kmps: f64) -> Self {
        Self {
            beam_id,
            mode: BeamFootprintMode::EarthMoving {
                beam_radius_km,
                ground_track_speed_kmps: ground_speed_kmps,
            },
            boresight_nadir_angle_deg: 0.0,
            is_active: true,
        }
    }

    /// Create a new steerable Earth-fixed spot beam.
    pub fn new_earth_fixed(
        beam_id: u32,
        target_center_ecef: Vector3D,
        max_steering_deg: f64,
    ) -> Self {
        Self {
            beam_id,
            mode: BeamFootprintMode::EarthFixed {
                target_center_ecef,
                max_steering_angle_deg: max_steering_deg,
            },
            boresight_nadir_angle_deg: 0.0,
            is_active: true,
        }
    }

    /// Calculate remaining dwell time in seconds for Earth-moving beam over a point.
    pub fn calculate_dwell_time_s(&self, distance_from_center_km: f64) -> f64 {
        match &self.mode {
            BeamFootprintMode::EarthMoving {
                beam_radius_km,
                ground_track_speed_kmps,
            } => {
                if distance_from_center_km >= *beam_radius_km {
                    0.0
                } else {
                    let remaining_distance = beam_radius_km - distance_from_center_km;
                    remaining_distance / ground_track_speed_kmps
                }
            }
            BeamFootprintMode::EarthFixed { .. } => {
                // Earth-fixed beams dwell until satellite elevation or steering limits are exceeded
                f64::INFINITY
            }
        }
    }

    /// Evaluate steering angle for Earth-fixed beam from satellite position in ECEF.
    pub fn evaluate_steering(&self, sat_pos_ecef: &Vector3D) -> Result<f64, NtnRegenerativeError> {
        match &self.mode {
            BeamFootprintMode::EarthFixed {
                target_center_ecef,
                max_steering_angle_deg,
            } => {
                // Nadir vector points from satellite directly toward Earth center (negative sat_pos)
                let nadir_vec = sat_pos_ecef.scale(-1.0).normalize();
                let sat_to_target = target_center_ecef.sub(sat_pos_ecef).normalize();

                let cos_steering = nadir_vec.dot(&sat_to_target).clamp(-1.0, 1.0);
                let steering_angle_deg = cos_steering.acos().to_degrees();

                if steering_angle_deg > *max_steering_angle_deg {
                    Err(NtnRegenerativeError::SteeringLimitExceeded {
                        angle_deg: steering_angle_deg,
                        max_deg: *max_steering_angle_deg,
                    })
                } else {
                    Ok(steering_angle_deg)
                }
            }
            BeamFootprintMode::EarthMoving { .. } => Ok(self.boresight_nadir_angle_deg),
        }
    }
}

// ---------------------------------------------------------------------------
// Inter-Satellite Links (ISL) & Dynamic Mesh Routing
// ---------------------------------------------------------------------------

/// Type of Inter-Satellite Cross Link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IslType {
    /// Optical Laser Communication Link (High bandwidth, low latency).
    OpticalLaser,
    /// Millimeter-Wave RF Link (Ka-band / V-band).
    MillimeterWaveRf,
}

/// Dynamic Inter-Satellite Link status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IslStatus {
    Up,
    Down,
    Degraded,
}

/// Inter-Satellite Link connecting two satellites in the constellation.
#[derive(Debug, Clone, PartialEq)]
pub struct IslLink {
    pub link_id: String,
    pub sat_a: String,
    pub sat_b: String,
    pub link_type: IslType,
    pub capacity_gbps: f64,
    pub status: IslStatus,
}

impl IslLink {
    pub fn new(
        link_id: &str,
        sat_a: &str,
        sat_b: &str,
        link_type: IslType,
        capacity_gbps: f64,
    ) -> Self {
        Self {
            link_id: link_id.to_string(),
            sat_a: sat_a.to_string(),
            sat_b: sat_b.to_string(),
            link_type,
            capacity_gbps,
            status: IslStatus::Up,
        }
    }

    /// Calculate propagation latency in milliseconds given inter-satellite distance.
    pub fn propagation_delay_ms(&self, distance_m: f64) -> f64 {
        (distance_m / SPEED_OF_LIGHT_M_S) * 1000.0
    }
}

// ---------------------------------------------------------------------------
// Space Packet & Autonomous Routing
// ---------------------------------------------------------------------------

/// Space Packet QoS Flow Priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpaceQosPriority {
    MissionCritical = 0,
    VoiceVideoUrgent = 1,
    InteractiveData = 2,
    BestEffort = 3,
}

/// Spaceborne Packet Header and Payload (Rel-18 Space-Terrestrial Mesh).
#[derive(Debug, Clone, PartialEq)]
pub struct SpacePacket {
    pub packet_id: u64,
    pub source_ue_id: String,
    pub dest_ue_id: String,
    pub ingress_sat_id: String,
    pub target_sat_id: String,
    pub qos_priority: SpaceQosPriority,
    pub hop_count: u8,
    pub max_hops: u8,
    pub payload: Vec<u8>,
}

impl SpacePacket {
    pub fn new(
        packet_id: u64,
        source_ue_id: &str,
        dest_ue_id: &str,
        ingress_sat_id: &str,
        target_sat_id: &str,
        qos_priority: SpaceQosPriority,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            packet_id,
            source_ue_id: source_ue_id.to_string(),
            dest_ue_id: dest_ue_id.to_string(),
            ingress_sat_id: ingress_sat_id.to_string(),
            target_sat_id: target_sat_id.to_string(),
            qos_priority,
            hop_count: 0,
            max_hops: 16,
            payload,
        }
    }
}

/// Forwarding Decision made by the Satellite Onboard Regenerative Switch.
#[derive(Debug, Clone, PartialEq)]
pub enum ForwardingDecision {
    /// Both source and destination UEs are served by this satellite:
    /// Direct onboard switching without ISL or Feeder Link round-trip.
    LocalBreakout {
        egress_beam_id: u32,
        processing_delay_ms: f64,
    },
    /// Next-hop transmission across Inter-Satellite Link.
    IslForward {
        next_hop_sat_id: String,
        link_id: String,
        link_propagation_delay_ms: f64,
    },
    /// Forward down to Ground NTN Gateway over Feeder Link.
    FeederDownlink {
        gateway_id: String,
        feeder_rtt_ms: f64,
    },
    /// Packet dropped due to TTL expiration or link failure.
    Drop { reason: String },
}

// ---------------------------------------------------------------------------
// Satellite Node & Top-Level Regenerative Constellation Engine
// ---------------------------------------------------------------------------

/// Spaceborne Satellite Node in the 5G Constellation.
#[derive(Debug, Clone, PartialEq)]
pub struct SatelliteNode {
    pub sat_id: String,
    pub architecture: PayloadArchitecture,
    pub ephemeris: KeplerianElements,
    pub beams: HashMap<u32, SatelliteBeam>,
    pub registered_ues: HashMap<String, u32>, // UE ID -> Serving Beam ID
}

impl SatelliteNode {
    pub fn new(
        sat_id: &str,
        architecture: PayloadArchitecture,
        ephemeris: KeplerianElements,
    ) -> Self {
        Self {
            sat_id: sat_id.to_string(),
            architecture,
            ephemeris,
            beams: HashMap::new(),
            registered_ues: HashMap::new(),
        }
    }

    /// Add spot beam to satellite.
    pub fn add_beam(&mut self, beam: SatelliteBeam) {
        self.beams.insert(beam.beam_id, beam);
    }

    /// Attach UE to a spot beam.
    pub fn attach_ue(&mut self, ue_id: &str, beam_id: u32) {
        self.registered_ues.insert(ue_id.to_string(), beam_id);
    }

    /// Detach UE.
    pub fn detach_ue(&mut self, ue_id: &str) {
        self.registered_ues.remove(ue_id);
    }
}

/// Top-Level 3GPP Rel-18 NTN Regenerative Constellation Engine.
pub struct NtnRegenerativeEngine {
    pub engine_id: String,
    pub satellites: HashMap<String, SatelliteNode>,
    pub isl_links: HashMap<String, IslLink>,
    pub ground_stations: HashMap<String, GroundStation>,
}

impl NtnRegenerativeEngine {
    /// Create a new NTN regenerative constellation engine.
    pub fn new(engine_id: &str) -> Self {
        Self {
            engine_id: engine_id.to_string(),
            satellites: HashMap::new(),
            isl_links: HashMap::new(),
            ground_stations: HashMap::new(),
        }
    }

    /// Register a satellite node.
    pub fn register_satellite(&mut self, satellite: SatelliteNode) {
        self.satellites.insert(satellite.sat_id.clone(), satellite);
    }

    /// Add an ISL link between two satellites.
    pub fn add_isl_link(&mut self, link: IslLink) {
        self.isl_links.insert(link.link_id.clone(), link);
    }

    /// Register a ground station / gateway.
    pub fn register_ground_station(&mut self, gs: GroundStation) {
        self.ground_stations.insert(gs.id.clone(), gs);
    }

    /// Set status of an ISL link (Up/Down/Degraded).
    pub fn set_isl_status(
        &mut self,
        link_id: &str,
        status: IslStatus,
    ) -> Result<(), NtnRegenerativeError> {
        if let Some(link) = self.isl_links.get_mut(link_id) {
            link.status = status;
            Ok(())
        } else {
            Err(NtnRegenerativeError::LinkNotFound(
                link_id.to_string(),
                "".to_string(),
            ))
        }
    }

    /// Calculate distance between two satellites in ECEF at time $t$.
    pub fn inter_satellite_distance(
        &self,
        sat_a_id: &str,
        sat_b_id: &str,
        t_s: f64,
    ) -> Result<f64, NtnRegenerativeError> {
        let sat_a = self
            .satellites
            .get(sat_a_id)
            .ok_or_else(|| NtnRegenerativeError::SatelliteNotFound(sat_a_id.to_string()))?;
        let sat_b = self
            .satellites
            .get(sat_b_id)
            .ok_or_else(|| NtnRegenerativeError::SatelliteNotFound(sat_b_id.to_string()))?;

        let (pos_a, _) = sat_a.ephemeris.propagate_ecef(t_s)?;
        let (pos_b, _) = sat_b.ephemeris.propagate_ecef(t_s)?;

        Ok(pos_a.distance_to(&pos_b))
    }

    /// Find optimal ISL route (minimum propagation delay) using Dijkstra's algorithm.
    pub fn compute_isl_route(
        &self,
        source_sat_id: &str,
        target_sat_id: &str,
        t_s: f64,
    ) -> Result<(Vec<String>, f64), NtnRegenerativeError> {
        if !self.satellites.contains_key(source_sat_id) {
            return Err(NtnRegenerativeError::SatelliteNotFound(
                source_sat_id.to_string(),
            ));
        }
        if !self.satellites.contains_key(target_sat_id) {
            return Err(NtnRegenerativeError::SatelliteNotFound(
                target_sat_id.to_string(),
            ));
        }
        if source_sat_id == target_sat_id {
            return Ok((vec![source_sat_id.to_string()], 0.0));
        }

        // Build adjacency graph with link propagation delays
        let mut adj: HashMap<&str, Vec<(&str, &str, f64)>> = HashMap::new();
        for sat_id in self.satellites.keys() {
            adj.insert(sat_id.as_str(), Vec::new());
        }

        for link in self.isl_links.values() {
            if link.status != IslStatus::Up {
                continue;
            }
            if let Ok(dist_m) = self.inter_satellite_distance(&link.sat_a, &link.sat_b, t_s) {
                let delay_ms = link.propagation_delay_ms(dist_m);
                if let Some(neighbors) = adj.get_mut(link.sat_a.as_str()) {
                    neighbors.push((link.sat_b.as_str(), link.link_id.as_str(), delay_ms));
                }
                if let Some(neighbors) = adj.get_mut(link.sat_b.as_str()) {
                    neighbors.push((link.sat_a.as_str(), link.link_id.as_str(), delay_ms));
                }
            }
        }

        // Dijkstra search
        let mut distances: HashMap<&str, f64> = HashMap::new();
        let mut previous: HashMap<&str, &str> = HashMap::new();
        let mut unvisited: Vec<&str> = self.satellites.keys().map(|s| s.as_str()).collect();

        for sat_id in &unvisited {
            distances.insert(*sat_id, f64::INFINITY);
        }
        distances.insert(source_sat_id, 0.0);

        while !unvisited.is_empty() {
            // Find unvisited node with minimum distance
            let mut min_idx = 0;
            let mut min_dist = f64::INFINITY;
            for (i, node) in unvisited.iter().enumerate() {
                let d = distances[node];
                if d < min_dist {
                    min_dist = d;
                    min_idx = i;
                }
            }

            if min_dist.is_infinite() {
                break; // Remaining nodes are unreachable
            }

            let current = unvisited.swap_remove(min_idx);
            if current == target_sat_id {
                break;
            }

            if let Some(neighbors) = adj.get(current) {
                for &(neighbor, _, weight) in neighbors {
                    if unvisited.contains(&neighbor) {
                        let new_dist = min_dist + weight;
                        if new_dist < distances[neighbor] {
                            distances.insert(neighbor, new_dist);
                            previous.insert(neighbor, current);
                        }
                    }
                }
            }
        }

        let total_delay = distances[target_sat_id];
        if total_delay.is_infinite() {
            return Err(NtnRegenerativeError::NoRouteAvailable {
                source: source_sat_id.to_string(),
                target: target_sat_id.to_string(),
            });
        }

        // Reconstruct path
        let mut path = VecDeque::new();
        let mut curr = target_sat_id;
        path.push_front(curr.to_string());
        while let Some(&prev) = previous.get(curr) {
            path.push_front(prev.to_string());
            curr = prev;
        }

        Ok((path.into_iter().collect(), total_delay))
    }

    /// Process a space packet through the satellite's regenerative routing engine.
    pub fn process_packet(
        &self,
        current_sat_id: &str,
        packet: &mut SpacePacket,
        gateway_id: Option<&str>,
        t_s: f64,
    ) -> ForwardingDecision {
        let sat = match self.satellites.get(current_sat_id) {
            Some(s) => s,
            None => {
                return ForwardingDecision::Drop {
                    reason: format!("Satellite '{}' not found", current_sat_id),
                };
            }
        };

        // Check TTL
        if packet.hop_count >= packet.max_hops {
            return ForwardingDecision::Drop {
                reason: format!(
                    "TTL exceeded: {}/{} hops",
                    packet.hop_count, packet.max_hops
                ),
            };
        }
        packet.hop_count += 1;

        // 1. Check for Local Breakout:
        // If architecture supports onboard user-plane switching and destination UE is on this satellite
        if sat.architecture.supports_local_breakout() {
            if let Some(&beam_id) = sat.registered_ues.get(&packet.dest_ue_id) {
                return ForwardingDecision::LocalBreakout {
                    egress_beam_id: beam_id,
                    processing_delay_ms: sat.architecture.nominal_onboard_processing_delay_ms(),
                };
            }
        }

        // 2. If destination is served by another satellite in the constellation:
        if current_sat_id != packet.target_sat_id {
            match self.compute_isl_route(current_sat_id, &packet.target_sat_id, t_s) {
                Ok((path, _)) if path.len() >= 2 => {
                    let next_hop = &path[1];
                    // Find ISL link ID between current and next_hop
                    let link = self.isl_links.values().find(|l| {
                        (l.sat_a == current_sat_id && l.sat_b == *next_hop)
                            || (l.sat_b == current_sat_id && l.sat_a == *next_hop)
                    });

                    if let Some(l) = link {
                        if let Ok(dist) =
                            self.inter_satellite_distance(current_sat_id, next_hop, t_s)
                        {
                            return ForwardingDecision::IslForward {
                                next_hop_sat_id: next_hop.clone(),
                                link_id: l.link_id.clone(),
                                link_propagation_delay_ms: l.propagation_delay_ms(dist),
                            };
                        }
                    }
                }
                _ => {
                    // Fall through to Feeder Link or drop
                }
            }
        }

        // 3. Downlink to Ground Gateway over Feeder Link:
        if let Some(gw_id) = gateway_id {
            if let Some(gw) = self.ground_stations.get(gw_id) {
                if let Ok((pos_ecef, _)) = sat.ephemeris.propagate_ecef(t_s) {
                    let (slant_m, el_deg, _) = gw.compute_look_angles(&pos_ecef);
                    if el_deg >= 5.0 {
                        // Gateway visible
                        let rtt_ms = 2.0 * (slant_m / SPEED_OF_LIGHT_M_S) * 1000.0;
                        return ForwardingDecision::FeederDownlink {
                            gateway_id: gw_id.to_string(),
                            feeder_rtt_ms: rtt_ms,
                        };
                    }
                }
            }
        }

        ForwardingDecision::Drop {
            reason: "No suitable ISL path or visible gateway".to_string(),
        }
    }
}

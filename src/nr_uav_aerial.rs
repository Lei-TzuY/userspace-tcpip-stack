//! 3GPP Rel-18 5G-Advanced Aerial UE & Unmanned Aerial Vehicle (UAV) Communications Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.300 §16.17 Rel-18 ("Support for Aerial Vehicles")
//! - 3GPP TS 38.331 Rel-18 §5.5.4 & §6.3.2 (Measurement Events H1/H2, `FlightPathInfoReport`)
//! - 3GPP TS 38.213 §7.1 Rel-18 (Height-dependent uplink power control for Aerial UEs)
//! - 3GPP TS 22.125 (Unmanned Aerial System / UAS 3GPP architectural enablers)
//! - ASTM F3411-22a / 3GPP Remote Identification (Remote ID)
//!
//! Key Capabilities:
//! 1. 3D Flight Path Trajectory Reporting & Waypoint Navigation.
//! 2. Height-Based Measurement Events H1 (Ascent above threshold) and H2 (Descent below threshold).
//! 3. Sidelobe Interference & Multi-Cell LoS Pollution Detection at High Altitude.
//! 4. Height-Adaptive Uplink Transmit Power Control ($\alpha(h)$ backoff preventing terrestrial cell desensitization).
//! 5. UAS Identification, Authorization Status, and Broadcast Remote ID Serialization.
//!
//! Pure Rust standard library implementation with zero external dependencies.

/// Maximum number of waypoints supported in a single FlightPathInfoReport.
pub const MAX_FLIGHT_WAYPOINTS: usize = 32;

/// Default height event H1 threshold in meters above ground level (AGL).
pub const DEFAULT_HEIGHT_H1_THRESHOLD_M: f64 = 120.0;

/// Default height event H2 threshold in meters AGL.
pub const DEFAULT_HEIGHT_H2_THRESHOLD_M: f64 = 90.0;

/// Default antenna sidelobe pollution threshold: number of LoS interferers within 6 dB of serving cell.
pub const DEFAULT_SIDELOBE_POLLUTION_COUNT: usize = 3;

// ---------------------------------------------------------------------------
// Enumerations & Error Types
// ---------------------------------------------------------------------------

/// Aerial vehicle authorization state in the 3GPP network (TS 22.125).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UasAuthorizationStatus {
    /// Drone is authenticated, UAS traffic management (UTM) cleared, and allowed to fly.
    Authorized,
    /// Pending authorization from UAS Service Supplier (USS).
    Pending,
    /// Authorization revoked or flight restricted (e.g. geofence boundary breached).
    Suspended,
    /// Unauthorized: aerial communications disabled, forced landing/rth protocol.
    Unauthorized,
}

/// 3GPP Rel-18 Height-based reporting event (TS 38.331 §5.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeightReportingEvent {
    /// Event H1: Aerial UE altitude becomes higher than configured threshold.
    H1AltitudeAboveThreshold { altitude_m: u32, threshold_m: u32 },
    /// Event H2: Aerial UE altitude becomes lower than configured threshold.
    H2AltitudeBelowThreshold { altitude_m: u32, threshold_m: u32 },
}

/// Errors raised during Aerial UE operations.
#[derive(Debug, Clone, PartialEq)]
pub enum AerialUeError {
    InvalidWaypointCoordinates { lat: f64, lon: f64 },
    InvalidAltitude(f64),
    ExceededMaxWaypoints(usize),
    UnauthorizedFlightAction,
    TrajectoryBufferFull,
}

impl std::fmt::Display for AerialUeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWaypointCoordinates { lat, lon } => {
                write!(f, "Invalid GPS coordinates: lat {:.4}, lon {:.4}", lat, lon)
            }
            Self::InvalidAltitude(alt) => write!(f, "Invalid altitude: {:.1} m", alt),
            Self::ExceededMaxWaypoints(count) => {
                write!(
                    f,
                    "Exceeded max waypoints: {} (limit {})",
                    count, MAX_FLIGHT_WAYPOINTS
                )
            }
            Self::UnauthorizedFlightAction => {
                write!(f, "UAS operation rejected: Aerial UE is not authorized")
            }
            Self::TrajectoryBufferFull => write!(f, "Trajectory report buffer is full"),
        }
    }
}

// ---------------------------------------------------------------------------
// 3D Waypoints & Flight Trajectory (TS 38.331 §6.3.2)
// ---------------------------------------------------------------------------

/// 3D geographic waypoint representing planned or current position.
#[derive(Debug, Clone, PartialEq)]
pub struct FlightWaypoint {
    /// Latitude in degrees (-90.0 .. +90.0).
    pub latitude_deg: f64,
    /// Longitude in degrees (-180.0 .. +180.0).
    pub longitude_deg: f64,
    /// Altitude in meters above ground level (AGL).
    pub altitude_m: f64,
    /// Planned arrival timestamp in epoch seconds.
    pub timestamp_epoch_s: u64,
}

impl FlightWaypoint {
    pub fn new(
        latitude_deg: f64,
        longitude_deg: f64,
        altitude_m: f64,
        timestamp_epoch_s: u64,
    ) -> Result<Self, AerialUeError> {
        if !(-90.0..=90.0).contains(&latitude_deg) || !(-180.0..=180.0).contains(&longitude_deg) {
            return Err(AerialUeError::InvalidWaypointCoordinates {
                lat: latitude_deg,
                lon: longitude_deg,
            });
        }
        if altitude_m < -500.0 || altitude_m > 50_000.0 {
            return Err(AerialUeError::InvalidAltitude(altitude_m));
        }

        Ok(Self {
            latitude_deg,
            longitude_deg,
            altitude_m,
            timestamp_epoch_s,
        })
    }

    /// Calculate 3D Euclidean distance in meters to another waypoint using Haversine approximation.
    pub fn distance_3d_m(&self, other: &Self) -> f64 {
        const EARTH_RADIUS_M: f64 = 6_371_000.0;
        let d_lat = (other.latitude_deg - self.latitude_deg).to_radians();
        let d_lon = (other.longitude_deg - self.longitude_deg).to_radians();
        let lat1 = self.latitude_deg.to_radians();
        let lat2 = other.latitude_deg.to_radians();

        let a = (d_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (d_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).max(0.0).sqrt());
        let horizontal_dist = EARTH_RADIUS_M * c;

        let vertical_dist = (other.altitude_m - self.altitude_m).abs();
        (horizontal_dist * horizontal_dist + vertical_dist * vertical_dist).sqrt()
    }
}

/// Planned 3D Flight Path Trajectory Report transmitted to gNB (TS 38.331).
#[derive(Debug, Clone, PartialEq)]
pub struct FlightPathInfoReport {
    pub trajectory_id: u32,
    pub waypoints: Vec<FlightWaypoint>,
    pub estimated_ground_speed_m_s: f64,
}

impl FlightPathInfoReport {
    pub fn new(trajectory_id: u32, estimated_ground_speed_m_s: f64) -> Self {
        Self {
            trajectory_id,
            waypoints: Vec::new(),
            estimated_ground_speed_m_s,
        }
    }

    pub fn add_waypoint(&mut self, waypoint: FlightWaypoint) -> Result<(), AerialUeError> {
        if self.waypoints.len() >= MAX_FLIGHT_WAYPOINTS {
            return Err(AerialUeError::ExceededMaxWaypoints(self.waypoints.len()));
        }
        self.waypoints.push(waypoint);
        Ok(())
    }

    /// Compute total remaining flight path length in meters.
    pub fn total_trajectory_distance_m(&self) -> f64 {
        if self.waypoints.len() < 2 {
            return 0.0;
        }
        let mut total = 0.0;
        for i in 0..self.waypoints.len() - 1 {
            total += self.waypoints[i].distance_3d_m(&self.waypoints[i + 1]);
        }
        total
    }
}

// ---------------------------------------------------------------------------
// Height Events & Adaptive Power Control
// ---------------------------------------------------------------------------

/// Height-based measurement configuration (TS 38.331).
#[derive(Debug, Clone, PartialEq)]
pub struct HeightReportingConfig {
    pub h1_threshold_m: f64,
    pub h2_threshold_m: f64,
    pub hysteresis_m: f64,
}

impl Default for HeightReportingConfig {
    fn default() -> Self {
        Self {
            h1_threshold_m: DEFAULT_HEIGHT_H1_THRESHOLD_M,
            h2_threshold_m: DEFAULT_HEIGHT_H2_THRESHOLD_M,
            hysteresis_m: 5.0,
        }
    }
}

/// Height-adaptive PUSCH power control parameters (TS 38.213 §7.1).
#[derive(Debug, Clone, PartialEq)]
pub struct AerialPowerControl {
    /// Nominal P0 in dBm for ground-level UEs.
    pub p0_nominal_dbm: f64,
    /// Path loss compensation factor $\alpha$ (0.0 .. 1.0).
    pub alpha_ground: f64,
    /// Maximum allowed uplink transmit power in dBm (e.g. 23 dBm for Power Class 3).
    pub p_max_dbm: f64,
    /// Additional power reduction backoff per 100 meters altitude to prevent terrestrial interference.
    pub height_backoff_db_per_100m: f64,
}

impl Default for AerialPowerControl {
    fn default() -> Self {
        Self {
            p0_nominal_dbm: -80.0,
            alpha_ground: 0.8,
            p_max_dbm: 23.0,
            height_backoff_db_per_100m: 1.5,
        }
    }
}

impl AerialPowerControl {
    /// Calculate adjusted PUSCH transmit power in dBm:
    ///
    /// $P_{\text{tx}} = \min\left(P_{\max}, P_0 + \alpha \cdot PL - \text{Backoff}(h)\right)$
    pub fn calculate_pusch_tx_power(&self, altitude_m: f64, path_loss_db: f64) -> f64 {
        let alt_clamped = altitude_m.max(0.0);
        let backoff = (alt_clamped / 100.0) * self.height_backoff_db_per_100m;
        let calculated = self.p0_nominal_dbm + self.alpha_ground * path_loss_db - backoff;
        calculated.min(self.p_max_dbm)
    }
}

// ---------------------------------------------------------------------------
// Sidelobe Interference & Broadcast Remote ID
// ---------------------------------------------------------------------------

/// Measurement of serving cell and neighboring cell sidelobes (TR 38.825).
#[derive(Debug, Clone, PartialEq)]
pub struct AerialInterferenceMeasurement {
    pub serving_pci: u16,
    pub serving_rsrp_dbm: f64,
    /// Neighbor cell measurements: (PCI, RSRP in dBm).
    pub neighbor_rsrps: Vec<(u16, f64)>,
}

impl AerialInterferenceMeasurement {
    /// Count the number of strong LoS interferers with RSRP within `margin_db` of serving cell.
    pub fn count_strong_interferers(&self, margin_db: f64) -> usize {
        self.neighbor_rsrps
            .iter()
            .filter(|(_, rsrp)| *rsrp >= (self.serving_rsrp_dbm - margin_db))
            .count()
    }

    /// Detect severe sidelobe pollution at high altitude.
    pub fn is_sidelobe_polluted(&self) -> bool {
        self.count_strong_interferers(6.0) >= DEFAULT_SIDELOBE_POLLUTION_COUNT
    }

    /// Calculate Signal-to-Interference Ratio (SIR) in dB.
    pub fn calculate_sir_db(&self) -> f64 {
        let p_serving = 10.0f64.powf(self.serving_rsrp_dbm / 10.0);
        let p_interf: f64 = self
            .neighbor_rsrps
            .iter()
            .map(|(_, rsrp)| 10.0f64.powf(*rsrp / 10.0))
            .sum();

        if p_interf > 0.0 {
            10.0 * (p_serving / p_interf).log10()
        } else {
            50.0 // No interferers
        }
    }
}

/// Standardized Broadcast Remote ID payload for drone identity (ASTM F3411 / 3GPP).
#[derive(Debug, Clone, PartialEq)]
pub struct BroadcastRemoteId {
    pub uas_id: [u8; 20],
    pub operator_id: [u8; 20],
    pub latitude_deg: f64,
    pub longitude_deg: f64,
    pub altitude_m: f32,
    pub speed_m_s: f32,
    pub heading_deg: u16,
}

impl BroadcastRemoteId {
    /// Serialize Remote ID to compact binary frame.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.uas_id);
        buf.extend_from_slice(&self.operator_id);
        buf.extend_from_slice(&self.latitude_deg.to_be_bytes());
        buf.extend_from_slice(&self.longitude_deg.to_be_bytes());
        buf.extend_from_slice(&self.altitude_m.to_be_bytes());
        buf.extend_from_slice(&self.speed_m_s.to_be_bytes());
        buf.extend_from_slice(&self.heading_deg.to_be_bytes());
        buf
    }

    /// Deserialize Remote ID from binary frame.
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 62 {
            return None;
        }
        let mut uas_id = [0u8; 20];
        let mut operator_id = [0u8; 20];
        uas_id.copy_from_slice(&bytes[0..20]);
        operator_id.copy_from_slice(&bytes[20..40]);

        let lat_bytes: [u8; 8] = bytes[40..48].try_into().ok()?;
        let lon_bytes: [u8; 8] = bytes[48..56].try_into().ok()?;
        let alt_bytes: [u8; 4] = bytes[56..60].try_into().ok()?;
        let spd_bytes: [u8; 4] = bytes[60..64].try_into().ok()?;
        let heading_bytes: [u8; 2] = if bytes.len() >= 66 {
            bytes[64..66].try_into().ok()?
        } else {
            [0, 0]
        };

        Some(Self {
            uas_id,
            operator_id,
            latitude_deg: f64::from_be_bytes(lat_bytes),
            longitude_deg: f64::from_be_bytes(lon_bytes),
            altitude_m: f32::from_be_bytes(alt_bytes),
            speed_m_s: f32::from_be_bytes(spd_bytes),
            heading_deg: u16::from_be_bytes(heading_bytes),
        })
    }
}

// ---------------------------------------------------------------------------
// Aerial UE Engine
// ---------------------------------------------------------------------------

/// 5G-Advanced Aerial UE Protocol & Trajectory Management Engine.
#[derive(Debug, PartialEq)]
pub struct AerialUeEngine {
    pub uas_status: UasAuthorizationStatus,
    pub current_waypoint: FlightWaypoint,
    pub trajectory_report: Option<FlightPathInfoReport>,
    pub height_config: HeightReportingConfig,
    pub power_control: AerialPowerControl,
    pub current_altitude_above_h1: bool,
    pub stats_h1_reports: u64,
    pub stats_h2_reports: u64,
    pub stats_power_backoffs: u64,
}

impl AerialUeEngine {
    pub fn new(initial_waypoint: FlightWaypoint) -> Self {
        Self {
            uas_status: UasAuthorizationStatus::Authorized,
            current_waypoint: initial_waypoint,
            trajectory_report: None,
            height_config: HeightReportingConfig::default(),
            power_control: AerialPowerControl::default(),
            current_altitude_above_h1: false,
            stats_h1_reports: 0,
            stats_h2_reports: 0,
            stats_power_backoffs: 0,
        }
    }

    /// Update authorization status from UTM / gNodeB.
    pub fn set_authorization(&mut self, status: UasAuthorizationStatus) {
        self.uas_status = status;
    }

    /// Update aerial UE's real-time position and evaluate height reporting events H1/H2.
    pub fn update_position(&mut self, waypoint: FlightWaypoint) -> Option<HeightReportingEvent> {
        let alt = waypoint.altitude_m;
        self.current_waypoint = waypoint;

        if !self.current_altitude_above_h1 {
            // Check if rising above H1 threshold
            if alt >= (self.height_config.h1_threshold_m + self.height_config.hysteresis_m) {
                self.current_altitude_above_h1 = true;
                self.stats_h1_reports += 1;
                return Some(HeightReportingEvent::H1AltitudeAboveThreshold {
                    altitude_m: alt as u32,
                    threshold_m: self.height_config.h1_threshold_m as u32,
                });
            }
        } else {
            // Check if descending below H2 threshold
            if alt <= (self.height_config.h2_threshold_m - self.height_config.hysteresis_m) {
                self.current_altitude_above_h1 = false;
                self.stats_h2_reports += 1;
                return Some(HeightReportingEvent::H2AltitudeBelowThreshold {
                    altitude_m: alt as u32,
                    threshold_m: self.height_config.h2_threshold_m as u32,
                });
            }
        }

        None
    }

    /// Set or update the planned 3D flight path trajectory.
    pub fn set_flight_trajectory(
        &mut self,
        report: FlightPathInfoReport,
    ) -> Result<(), AerialUeError> {
        if self.uas_status != UasAuthorizationStatus::Authorized {
            return Err(AerialUeError::UnauthorizedFlightAction);
        }
        self.trajectory_report = Some(report);
        Ok(())
    }

    /// Calculate transmit power for PUSCH transmission incorporating altitude backoff.
    pub fn get_pusch_tx_power(&mut self, path_loss_db: f64) -> f64 {
        let tx_power = self
            .power_control
            .calculate_pusch_tx_power(self.current_waypoint.altitude_m, path_loss_db);
        if self.current_waypoint.altitude_m > 50.0 {
            self.stats_power_backoffs += 1;
        }
        tx_power
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waypoint_distance_3d_calculation() {
        // Point A: Ground level (0m)
        let wp1 = FlightWaypoint::new(25.0330, 121.5654, 0.0, 1700000000).unwrap();
        // Point B: 100m straight up
        let wp2 = FlightWaypoint::new(25.0330, 121.5654, 100.0, 1700000010).unwrap();

        let dist = wp1.distance_3d_m(&wp2);
        assert!((dist - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_height_events_h1_and_h2() {
        let wp_ground = FlightWaypoint::new(25.0, 121.0, 10.0, 1000).unwrap();
        let mut engine = AerialUeEngine::new(wp_ground);

        // Climb to 80m (still below H1=120m + 5m hyst)
        let wp_80m = FlightWaypoint::new(25.0, 121.0, 80.0, 1010).unwrap();
        assert_eq!(engine.update_position(wp_80m), None);

        // Climb to 130m (exceeds H1 + hyst = 125m) -> triggers H1
        let wp_130m = FlightWaypoint::new(25.0, 121.0, 130.0, 1020).unwrap();
        let ev1 = engine.update_position(wp_130m);
        assert_eq!(
            ev1,
            Some(HeightReportingEvent::H1AltitudeAboveThreshold {
                altitude_m: 130,
                threshold_m: 120
            })
        );
        assert_eq!(engine.stats_h1_reports, 1);

        // Descend to 100m (between H1 and H2) -> no event
        let wp_100m = FlightWaypoint::new(25.0, 121.0, 100.0, 1030).unwrap();
        assert_eq!(engine.update_position(wp_100m), None);

        // Descend to 80m (falls below H2=90m - 5m hyst = 85m) -> triggers H2
        let wp_80m_down = FlightWaypoint::new(25.0, 121.0, 80.0, 1040).unwrap();
        let ev2 = engine.update_position(wp_80m_down);
        assert_eq!(
            ev2,
            Some(HeightReportingEvent::H2AltitudeBelowThreshold {
                altitude_m: 80,
                threshold_m: 90
            })
        );
        assert_eq!(engine.stats_h2_reports, 1);
    }

    #[test]
    fn test_height_adaptive_power_control() {
        let mut pwr = AerialPowerControl::default();
        pwr.p0_nominal_dbm = -80.0;
        pwr.alpha_ground = 0.8;
        pwr.height_backoff_db_per_100m = 2.0;

        let pl = 90.0;
        // At ground (0m): -80 + 0.8 * 90 = -8 dBm
        let p_ground = pwr.calculate_pusch_tx_power(0.0, pl);
        assert_eq!(p_ground, -8.0);

        // At 200m altitude: backoff is (200/100) * 2.0 = 4.0 dB -> -12 dBm
        let p_200m = pwr.calculate_pusch_tx_power(200.0, pl);
        assert_eq!(p_200m, -12.0);
    }

    #[test]
    fn test_sidelobe_interference_detection() {
        let interf = AerialInterferenceMeasurement {
            serving_pci: 10,
            serving_rsrp_dbm: -80.0,
            neighbor_rsrps: vec![
                (11, -82.0), // within 2 dB
                (12, -84.0), // within 4 dB
                (13, -85.0), // within 5 dB
                (14, -95.0), // 15 dB down (negligible)
            ],
        };

        // 3 interferers within 6 dB
        assert_eq!(interf.count_strong_interferers(6.0), 3);
        assert!(interf.is_sidelobe_polluted());
        assert!(interf.calculate_sir_db() < 0.0);
    }

    #[test]
    fn test_remote_id_serialization_roundtrip() {
        let mut uas_id = [0u8; 20];
        uas_id[0..5].copy_from_slice(b"DRN01");
        let mut operator_id = [0u8; 20];
        operator_id[0..5].copy_from_slice(b"OPR99");

        let remote_id = BroadcastRemoteId {
            uas_id,
            operator_id,
            latitude_deg: 24.12345,
            longitude_deg: 120.98765,
            altitude_m: 150.5,
            speed_m_s: 18.2,
            heading_deg: 270,
        };

        let bytes = remote_id.serialize();
        let restored = BroadcastRemoteId::deserialize(&bytes).unwrap();
        assert_eq!(remote_id, restored);
    }
}

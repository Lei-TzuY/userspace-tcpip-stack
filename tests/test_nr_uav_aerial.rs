//! Integration Tests for 3GPP Rel-18 Aerial UE and UAV Communications Engine.
//!
//! Validates:
//! 1. 3D Flight Path Trajectory reporting, waypoints, and distance calculations.
//! 2. Height measurement reporting events H1 (ascent) and H2 (descent) with hysteresis.
//! 3. Altitude-adaptive uplink power control backoff to prevent terrestrial cell pollution.
//! 4. Aerial sidelobe interference detection and Signal-to-Interference Ratio (SIR) evaluation.
//! 5. UAS authorization state lifecycle and access restriction enforcement.
//! 6. ASTM F3411 / 3GPP Broadcast Remote ID binary encoding/decoding and error handling.

use toy_tcpip::nr_uav_aerial::{
    AerialInterferenceMeasurement, AerialPowerControl, AerialUeEngine, AerialUeError,
    BroadcastRemoteId, FlightPathInfoReport, FlightWaypoint, HeightReportingConfig,
    HeightReportingEvent, UasAuthorizationStatus, DEFAULT_HEIGHT_H1_THRESHOLD_M,
    DEFAULT_HEIGHT_H2_THRESHOLD_M, MAX_FLIGHT_WAYPOINTS,
};

#[test]
fn test_3d_flight_path_trajectory_and_distance() {
    let wp1 = FlightWaypoint::new(24.7800, 120.9900, 50.0, 1000).expect("Valid coordinates");
    let wp2 = FlightWaypoint::new(24.7850, 120.9950, 100.0, 1060).expect("Valid coordinates");
    let wp3 = FlightWaypoint::new(24.7900, 121.0000, 120.0, 1120).expect("Valid coordinates");

    let mut report = FlightPathInfoReport::new(42, 15.0);
    assert_eq!(report.trajectory_id, 42);
    assert_eq!(report.estimated_ground_speed_m_s, 15.0);

    report.add_waypoint(wp1.clone()).unwrap();
    report.add_waypoint(wp2.clone()).unwrap();
    report.add_waypoint(wp3.clone()).unwrap();

    assert_eq!(report.waypoints.len(), 3);
    let total_dist = report.total_trajectory_distance_m();
    assert!(total_dist > 1000.0 && total_dist < 5000.0);

    let mut engine = AerialUeEngine::new(wp1);
    engine.set_flight_trajectory(report).unwrap();
    assert!(engine.trajectory_report.is_some());
}

#[test]
fn test_max_waypoints_capacity_boundary() {
    let mut report = FlightPathInfoReport::new(1, 10.0);
    for i in 0..MAX_FLIGHT_WAYPOINTS {
        let wp = FlightWaypoint::new(25.0, 121.0, 10.0 + (i as f64), 1000 + (i as u64)).unwrap();
        assert!(report.add_waypoint(wp).is_ok());
    }

    // Adding MAX + 1 must fail
    let excess_wp = FlightWaypoint::new(25.0, 121.0, 200.0, 2000).unwrap();
    assert_eq!(
        report.add_waypoint(excess_wp),
        Err(AerialUeError::ExceededMaxWaypoints(MAX_FLIGHT_WAYPOINTS))
    );
}

#[test]
fn test_height_events_h1_and_h2_with_hysteresis() {
    let wp_start = FlightWaypoint::new(24.0, 121.0, 20.0, 100).unwrap();
    let mut engine = AerialUeEngine::new(wp_start);
    engine.height_config = HeightReportingConfig {
        h1_threshold_m: 100.0,
        h2_threshold_m: 70.0,
        hysteresis_m: 5.0,
    };

    // 1. Ascent to 104m (< 100 + 5) -> No event
    let wp_104 = FlightWaypoint::new(24.0, 121.0, 104.0, 110).unwrap();
    assert_eq!(engine.update_position(wp_104), None);
    assert!(!engine.current_altitude_above_h1);

    // 2. Ascent to 106m (> 100 + 5) -> Triggers H1
    let wp_106 = FlightWaypoint::new(24.0, 121.0, 106.0, 120).unwrap();
    let ev1 = engine.update_position(wp_106);
    assert_eq!(
        ev1,
        Some(HeightReportingEvent::H1AltitudeAboveThreshold {
            altitude_m: 106,
            threshold_m: 100,
        })
    );
    assert!(engine.current_altitude_above_h1);
    assert_eq!(engine.stats_h1_reports, 1);

    // 3. Hovering at 80m (> 70 - 5) -> No event
    let wp_80 = FlightWaypoint::new(24.0, 121.0, 80.0, 130).unwrap();
    assert_eq!(engine.update_position(wp_80), None);
    assert!(engine.current_altitude_above_h1);

    // 4. Descent to 64m (< 70 - 5) -> Triggers H2
    let wp_64 = FlightWaypoint::new(24.0, 121.0, 64.0, 140).unwrap();
    let ev2 = engine.update_position(wp_64);
    assert_eq!(
        ev2,
        Some(HeightReportingEvent::H2AltitudeBelowThreshold {
            altitude_m: 64,
            threshold_m: 70,
        })
    );
    assert!(!engine.current_altitude_above_h1);
    assert_eq!(engine.stats_h2_reports, 1);
}

#[test]
fn test_altitude_adaptive_power_control_backoff() {
    let mut engine =
        AerialUeEngine::new(FlightWaypoint::new(24.0, 121.0, 0.0, 100).unwrap());
    engine.power_control = AerialPowerControl {
        p0_nominal_dbm: -75.0,
        alpha_ground: 0.8,
        p_max_dbm: 23.0,
        height_backoff_db_per_100m: 3.0,
    };

    let pl = 80.0;
    // Ground level: -75 + 0.8 * 80 - 0 = -11.0 dBm
    let p_ground = engine.get_pusch_tx_power(pl);
    assert_eq!(p_ground, -11.0);

    // Fly to 200m: backoff = 2 * 3.0 = 6.0 dB -> -17.0 dBm
    engine.current_waypoint.altitude_m = 200.0;
    let p_200m = engine.get_pusch_tx_power(pl);
    assert_eq!(p_200m, -17.0);
    assert!(engine.stats_power_backoffs > 0);

    // Extreme path loss with clipping at P_max (23 dBm)
    let p_max_test = engine.get_pusch_tx_power(200.0);
    assert_eq!(p_max_test, 23.0);
}

#[test]
fn test_airborne_sidelobe_pollution_detection() {
    // Normal terrestrial scenario: only 1 strong neighbor cell
    let normal_interf = AerialInterferenceMeasurement {
        serving_pci: 101,
        serving_rsrp_dbm: -75.0,
        neighbor_rsrps: vec![
            (102, -78.0),
            (103, -92.0),
            (104, -96.0),
            (105, -100.0),
        ],
    };
    assert_eq!(normal_interf.count_strong_interferers(6.0), 1);
    assert!(!normal_interf.is_sidelobe_polluted());
    assert!(normal_interf.calculate_sir_db() > 0.0);

    // High altitude scenario: 4 line-of-sight base stations within 4 dB
    let polluted_interf = AerialInterferenceMeasurement {
        serving_pci: 101,
        serving_rsrp_dbm: -80.0,
        neighbor_rsrps: vec![
            (201, -81.0),
            (202, -82.0),
            (203, -83.0),
            (204, -84.0),
        ],
    };
    assert_eq!(polluted_interf.count_strong_interferers(6.0), 4);
    assert!(polluted_interf.is_sidelobe_polluted());
    assert!(polluted_interf.calculate_sir_db() < 0.0);
}

#[test]
fn test_uas_authorization_states() {
    let wp = FlightWaypoint::new(25.0, 121.0, 10.0, 100).unwrap();
    let mut engine = AerialUeEngine::new(wp);

    let report = FlightPathInfoReport::new(1, 10.0);

    // 1. Authorized -> trajectory can be submitted
    engine.set_authorization(UasAuthorizationStatus::Authorized);
    assert!(engine.set_flight_trajectory(report.clone()).is_ok());

    // 2. Suspended / Unauthorized -> trajectory rejected
    engine.set_authorization(UasAuthorizationStatus::Suspended);
    assert_eq!(
        engine.set_flight_trajectory(report.clone()),
        Err(AerialUeError::UnauthorizedFlightAction)
    );

    engine.set_authorization(UasAuthorizationStatus::Unauthorized);
    assert_eq!(
        engine.set_flight_trajectory(report),
        Err(AerialUeError::UnauthorizedFlightAction)
    );
}

#[test]
fn test_broadcast_remote_id_serialization_and_validation() {
    let mut uas = [0u8; 20];
    uas[0..8].copy_from_slice(b"DRONE-07");
    let mut opr = [0u8; 20];
    opr[0..8].copy_from_slice(b"PILOT-42");

    let remote_id = BroadcastRemoteId {
        uas_id: uas,
        operator_id: opr,
        latitude_deg: 25.04123,
        longitude_deg: 121.55432,
        altitude_m: 110.0,
        speed_m_s: 14.5,
        heading_deg: 180,
    };

    let serialized = remote_id.serialize();
    assert!(serialized.len() >= 64);

    let deserialized = BroadcastRemoteId::deserialize(&serialized).expect("Deserialization ok");
    assert_eq!(remote_id, deserialized);

    // Truncated buffer fails cleanly
    assert!(BroadcastRemoteId::deserialize(&serialized[0..30]).is_none());
}

#[test]
fn test_coordinate_and_altitude_errors() {
    // Latitude out of range (> 90.0)
    let err_lat = FlightWaypoint::new(95.0, 120.0, 50.0, 100);
    assert_eq!(
        err_lat,
        Err(AerialUeError::InvalidWaypointCoordinates {
            lat: 95.0,
            lon: 120.0
        })
    );

    // Longitude out of range (< -180.0)
    let err_lon = FlightWaypoint::new(25.0, -190.0, 50.0, 100);
    assert_eq!(
        err_lon,
        Err(AerialUeError::InvalidWaypointCoordinates {
            lat: 25.0,
            lon: -190.0
        })
    );

    // Unrealistic altitude (> 50,000 m)
    let err_alt = FlightWaypoint::new(25.0, 120.0, 60_000.0, 100);
    assert_eq!(err_alt, Err(AerialUeError::InvalidAltitude(60_000.0)));

    // Defaults check
    assert_eq!(DEFAULT_HEIGHT_H1_THRESHOLD_M, 120.0);
    assert_eq!(DEFAULT_HEIGHT_H2_THRESHOLD_M, 90.0);
}

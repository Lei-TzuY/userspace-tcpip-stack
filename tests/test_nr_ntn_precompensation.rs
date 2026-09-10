//! Integration tests for 3GPP Rel-18 5G-Advanced NTN Ephemeris & Autonomous Pre-Compensation Engine.

use toy_tcpip::nr_ntn_precompensation::{
    GroundUeFix, NtnCellType, NtnEphemerisState, NtnOrbitType, NtnPrecompError,
    NtnPrecompensationEngine, DEFAULT_NTN_MIN_ELEVATION_DEG, EARTH_RADIUS_METERS,
    SPEED_OF_LIGHT_M_S,
};

#[test]
fn test_ephemeris_propagation_leo_and_geo() {
    // 1. LEO at 600 km altitude: radius = 6371 km + 600 km = 6971 km
    let r0_leo = [EARTH_RADIUS_METERS + 600_000.0, 0.0, 0.0];
    let v0_leo = [0.0, 7560.0, 0.0]; // Circular orbital speed ~7.56 km/s
    let eph_leo = NtnEphemerisState::new(r0_leo, v0_leo, 100.0, NtnOrbitType::Leo);

    // Propagate 10s ahead
    let (r_10, v_10) = eph_leo.propagate(110.0);
    assert!((r_10[0] - r0_leo[0]).abs() > 0.0); // Moved along X due to inward gravitational acceleration
    assert!(r_10[1] > 70_000.0); // Moved along Y due to velocity (~75.6 km)
    assert_eq!(r_10[2], 0.0);
    assert!(v_10[0] < 0.0); // Acceleration pulled velocity vector inward (-X)

    // 2. GEO at 35,786 km altitude: radius = ~42,157 km
    let r0_geo = [EARTH_RADIUS_METERS + 35_786_000.0, 0.0, 0.0];
    let v0_geo = [0.0, 3075.0, 0.0]; // GEO speed ~3.075 km/s
    let eph_geo = NtnEphemerisState::new(r0_geo, v0_geo, 0.0, NtnOrbitType::Geo);

    let (r_geo_60, _) = eph_geo.propagate(60.0);
    assert!(r_geo_60[0] > 0.0);
    assert!(r_geo_60[1] > 180_000.0); // ~184.5 km in 60s
}

#[test]
fn test_ground_ue_wgs84_geodetic_conversion() {
    // Equator / Prime Meridian (0° Lat, 0° Lon, 0m altitude)
    let ue_eq = GroundUeFix::from_geodetic(0.0, 0.0, 0.0);
    assert!((ue_eq.position_ecef_m[0] - EARTH_RADIUS_METERS).abs() < 1e-3);
    assert!(ue_eq.position_ecef_m[1].abs() < 1e-3);
    assert!(ue_eq.position_ecef_m[2].abs() < 1e-3);

    // North Pole (90° Lat, 0° Lon, 500m altitude)
    let ue_pole = GroundUeFix::from_geodetic(90.0, 0.0, 500.0);
    assert!(ue_pole.position_ecef_m[0].abs() < 1e-3);
    assert!(ue_pole.position_ecef_m[1].abs() < 1e-3);
    assert!((ue_pole.position_ecef_m[2] - (EARTH_RADIUS_METERS + 500.0)).abs() < 1e-3);

    // 90° East on Equator (0° Lat, 90° Lon, 0m altitude)
    let ue_east = GroundUeFix::from_geodetic(0.0, 90.0, 0.0);
    assert!(ue_east.position_ecef_m[0].abs() < 1e-3);
    assert!((ue_east.position_ecef_m[1] - EARTH_RADIUS_METERS).abs() < 1e-3);
    assert!(ue_east.position_ecef_m[2].abs() < 1e-3);
}

#[test]
fn test_zenith_autonomous_precompensation_and_timing() {
    // Satellite directly overhead at 600 km altitude
    let sat_pos = [EARTH_RADIUS_METERS + 600_000.0, 0.0, 0.0];
    let sat_vel = [0.0, 7500.0, 0.0]; // Tangential velocity
    let ephemeris = NtnEphemerisState::new(sat_pos, sat_vel, 0.0, NtnOrbitType::Leo);

    let ue = GroundUeFix::stationary([EARTH_RADIUS_METERS, 0.0, 0.0]);
    let mut engine = NtnPrecompensationEngine::new(ephemeris, 2.0e9).expect("Valid carrier freq");

    // SIB19 Common TA = 12 ms, TA offset = 0.5 ms
    engine.set_timing_parameters(0.012, 0.0005);

    let metrics = engine
        .calculate_precompensation(&ue, 0.0)
        .expect("Precompensation calculation succeeds");

    // Slant range should be exactly 600 km
    assert!((metrics.slant_range_m - 600_000.0).abs() < 1.0);
    // Elevation angle at zenith is 90°
    assert!((metrics.elevation_angle_deg - 90.0).abs() < 1e-4);

    // One way delay = 600 km / c = 2.001384 ms
    let expected_one_way = 600_000.0 / SPEED_OF_LIGHT_M_S;
    assert!((metrics.one_way_delay_s - expected_one_way).abs() < 1e-7);

    // Service link TA = 2 * one_way_delay
    let expected_service_ta = 2.0 * expected_one_way;
    assert!((metrics.service_link_ta_s - expected_service_ta).abs() < 1e-7);

    // Total TA = Service TA + Common TA (12 ms) + TA Offset (0.5 ms)
    let expected_total_ta = expected_service_ta + 0.012 + 0.0005;
    assert!((metrics.total_ta_s - expected_total_ta).abs() < 1e-7);

    // At exact zenith with tangential velocity, radial velocity is 0
    assert!(metrics.radial_velocity_m_s.abs() < 1e-3);
    assert!(metrics.doppler_shift_hz.abs() < 1.0);
    assert!(metrics.doppler_precompensation_hz.abs() < 1.0);
}

#[test]
fn test_approaching_and_receding_doppler_inversion() {
    let ue = GroundUeFix::stationary([EARTH_RADIUS_METERS, 0.0, 0.0]);
    let carrier_freq = 2.5e9; // 2.5 GHz (n256 NTN band)

    // 1. Approaching satellite: in +Y direction with velocity in -Y direction
    let r_app = [EARTH_RADIUS_METERS + 500_000.0, 300_000.0, 0.0];
    let v_app = [0.0, -7500.0, 0.0];
    let eph_app = NtnEphemerisState::new(r_app, v_app, 0.0, NtnOrbitType::Leo);
    let mut engine_app = NtnPrecompensationEngine::new(eph_app, carrier_freq).unwrap();

    let m_app = engine_app.calculate_precompensation(&ue, 0.0).unwrap();
    // Approaching satellite: distance is decreasing, radial velocity is negative
    assert!(m_app.radial_velocity_m_s < 0.0);
    assert!(m_app.doppler_shift_hz < 0.0); // f_D = v_rad/c * f_c < 0
    // Pre-compensation must exactly cancel out the Doppler shift: delta_f_UL = -f_D
    assert_eq!(
        m_app.doppler_precompensation_hz,
        -m_app.doppler_shift_hz
    );
    assert!(m_app.doppler_precompensation_hz > 0.0);

    // 2. Receding satellite: in +Y direction with velocity in +Y direction
    let r_rec = [EARTH_RADIUS_METERS + 500_000.0, 300_000.0, 0.0];
    let v_rec = [0.0, 7500.0, 0.0];
    let eph_rec = NtnEphemerisState::new(r_rec, v_rec, 0.0, NtnOrbitType::Leo);
    let mut engine_rec = NtnPrecompensationEngine::new(eph_rec, carrier_freq).unwrap();

    let m_rec = engine_rec.calculate_precompensation(&ue, 0.0).unwrap();
    // Receding satellite: distance is increasing, radial velocity is positive
    assert!(m_rec.radial_velocity_m_s > 0.0);
    assert!(m_rec.doppler_shift_hz > 0.0);
    assert_eq!(
        m_rec.doppler_precompensation_hz,
        -m_rec.doppler_shift_hz
    );
    assert!(m_rec.doppler_precompensation_hz < 0.0);

    // TA drift rate must match (2 / c) * radial_velocity
    let expected_ta_drift = (2.0 / SPEED_OF_LIGHT_M_S) * m_rec.radial_velocity_m_s;
    assert!((m_rec.ta_drift_rate_s_per_s - expected_ta_drift).abs() < 1e-12);
}

#[test]
fn test_satellite_below_horizon_error_detection() {
    let ue = GroundUeFix::stationary([EARTH_RADIUS_METERS, 0.0, 0.0]);

    // Satellite below horizon on opposite side of Earth
    let r_below = [-(EARTH_RADIUS_METERS + 600_000.0), 0.0, 0.0];
    let v_below = [0.0, 7500.0, 0.0];
    let eph = NtnEphemerisState::new(r_below, v_below, 0.0, NtnOrbitType::Leo);

    let mut engine = NtnPrecompensationEngine::new(eph, 2.0e9).unwrap();
    let res = engine.calculate_precompensation(&ue, 0.0);

    match res {
        Err(NtnPrecompError::SatelliteBelowHorizon {
            elevation_deg,
            min_elevation_deg,
        }) => {
            assert!(elevation_deg < 0.0);
            assert_eq!(min_elevation_deg, DEFAULT_NTN_MIN_ELEVATION_DEG);
            let display_str = format!(
                "{}",
                NtnPrecompError::SatelliteBelowHorizon {
                    elevation_deg,
                    min_elevation_deg
                }
            );
            assert!(display_str.contains("Satellite below horizon"));
        }
        other => panic!("Expected SatelliteBelowHorizon error, got: {:?}", other),
    }
}

#[test]
fn test_handover_prediction_modes() {
    let sat_pos = [EARTH_RADIUS_METERS + 600_000.0, 200_000.0, 0.0];
    let sat_vel = [0.0, 7500.0, 0.0];
    let ephemeris = NtnEphemerisState::new(sat_pos, sat_vel, 0.0, NtnOrbitType::Leo);
    let ue = GroundUeFix::stationary([EARTH_RADIUS_METERS, 0.0, 0.0]);

    let mut engine = NtnPrecompensationEngine::new(ephemeris, 2.0e9).unwrap();

    // 1. Earth-Fixed cell handover prediction
    engine.set_cell_type(NtnCellType::EarthFixed);
    let m_fixed = engine.calculate_precompensation(&ue, 0.0).unwrap();
    assert!(m_fixed.time_to_handover_s.is_some());
    assert!(m_fixed.time_to_handover_s.unwrap() > 0.0);

    // 2. Earth-Moving cell handover prediction (beam diameter 2 * 25 km = 50 km)
    engine.set_cell_type(NtnCellType::EarthMoving {
        beam_footprint_radius_m: 25_000.0,
    });
    let m_moving = engine.calculate_precompensation(&ue, 0.0).unwrap();
    let expected_moving_dwell = 50_000.0 / 7500.0; // 6.666 s
    assert!(
        (m_moving.time_to_handover_s.unwrap() - expected_moving_dwell).abs() < 1e-2
    );

    // 3. Quasi-Earth-Fixed cell handover prediction (fixed dwell time 45s)
    engine.set_cell_type(NtnCellType::QuasiEarthFixed { dwell_time_s: 45.0 });
    let m_quasi = engine.calculate_precompensation(&ue, 0.0).unwrap();
    assert_eq!(m_quasi.time_to_handover_s, Some(45.0));

    // Check stats counters
    assert_eq!(engine.stats_precomputations, 3);
    assert_eq!(engine.stats_handover_evaluations, 3);
}

#[test]
fn test_precompensation_invalid_inputs() {
    let r0 = [EARTH_RADIUS_METERS + 600_000.0, 0.0, 0.0];
    let v0 = [0.0, 7500.0, 0.0];
    let eph = NtnEphemerisState::new(r0, v0, 0.0, NtnOrbitType::Leo);

    // Invalid negative or zero carrier frequency
    assert!(matches!(
        NtnPrecompensationEngine::new(eph.clone(), 0.0),
        Err(NtnPrecompError::InvalidCarrierFrequency(_))
    ));
    assert!(matches!(
        NtnPrecompensationEngine::new(eph.clone(), -1.0e9),
        Err(NtnPrecompError::InvalidCarrierFrequency(_))
    ));

    // Degenerate geometry (satellite position matches UE position)
    let ue_overlap = GroundUeFix::stationary(r0);
    let mut engine = NtnPrecompensationEngine::new(eph, 2.0e9).unwrap();
    assert!(matches!(
        engine.calculate_precompensation(&ue_overlap, 0.0),
        Err(NtnPrecompError::DegenerateOrbitGeometry)
    ));
}

//! Integration tests for 3GPP TS 38.300 / TS 38.211 / TS 38.331 5G NTN (Non-Terrestrial Networks).

use toy_tcpip::ntn_5g::*;

// ---------------------------------------------------------------------------
// 1. LEO Link Metrics and Overhead Zenith Doppler Test
// ---------------------------------------------------------------------------

#[test]
fn test_ntn_leo_link_metrics_and_doppler_happy_path() {
    let mut ntn = NtnEngine::new("ntn-leo-engine-01");

    // UE on Earth surface at equator
    let ue = GroundUePosition {
        ue_id: "ue-maritime-01".to_string(),
        position_ecef_m: [6_371_000.0, 0.0, 0.0],
    };

    // LEO satellite at 600 km altitude directly overhead, moving in Y direction at 7.5 km/s
    let sat = SatelliteEphemeris {
        sat_id: "sat-leo-star-01".to_string(),
        orbit_type: OrbitType::Leo,
        position_ecef_m: [6_971_000.0, 0.0, 0.0],
        velocity_ecef_mps: [0.0, 7_500.0, 0.0],
        epoch_timestamp_s: 1700000000,
    };

    ntn.register_satellite(sat);

    // Compute metrics at 2.0 GHz S-Band with 30 kHz SCS (0.5 ms slot)
    let metrics = ntn
        .compute_link_metrics("sat-leo-star-01", &ue, 2.0e9, 30)
        .unwrap();

    // 1. Slant range should be exactly 600.0 km
    assert!((metrics.slant_range_km - 600.0).abs() < 1e-3);

    // 2. Propagation delay: OWD ~ 2.001 ms, RTT ~ 4.003 ms
    assert!((metrics.one_way_delay_ms - 2.001).abs() < 0.01);
    assert!((metrics.round_trip_time_ms - 4.003).abs() < 0.01);

    // 3. Timing Advance ~ 4002.7 us
    assert!((metrics.timing_advance_us - 4002.7).abs() < 1.0);

    // 4. K_offset slots for 0.5 ms slot = ceil(4.003 / 0.5) = 9 or 8
    assert_eq!(metrics.k_offset_slots, 9);

    // 5. Elevation angle directly overhead should be ~90.0 degrees
    assert!((metrics.elevation_angle_deg - 90.0).abs() < 0.1);

    // 6. At zenith, tangential velocity is perpendicular to slant vector -> radial velocity = 0 -> Doppler = 0
    assert!(metrics.doppler_shift_hz.abs() < 1.0);
}

// ---------------------------------------------------------------------------
// 2. Approaching vs Receding LEO Doppler Shifts
// ---------------------------------------------------------------------------

#[test]
fn test_ntn_leo_doppler_approaching_and_receding() {
    let mut ntn = NtnEngine::new("ntn-leo-engine-02");

    let ue = GroundUePosition {
        ue_id: "ue-ground-02".to_string(),
        position_ecef_m: [6_371_000.0, 0.0, 0.0],
    };

    // Satellite approaching (Y = -500 km, moving +Y at 7500 m/s)
    let sat_approaching = SatelliteEphemeris {
        sat_id: "sat-approaching".to_string(),
        orbit_type: OrbitType::Leo,
        position_ecef_m: [6_971_000.0, -500_000.0, 0.0],
        velocity_ecef_mps: [0.0, 7_500.0, 0.0],
        epoch_timestamp_s: 1700000001,
    };
    ntn.register_satellite(sat_approaching);

    let m_app = ntn
        .compute_link_metrics("sat-approaching", &ue, 2.0e9, 30)
        .unwrap();

    // Approaching -> positive Doppler shift
    assert!(m_app.doppler_shift_hz > 10_000.0); // > +10 kHz

    // Satellite receding (Y = +500 km, moving +Y at 7500 m/s)
    let sat_receding = SatelliteEphemeris {
        sat_id: "sat-receding".to_string(),
        orbit_type: OrbitType::Leo,
        position_ecef_m: [6_971_000.0, 500_000.0, 0.0],
        velocity_ecef_mps: [0.0, 7_500.0, 0.0],
        epoch_timestamp_s: 1700000002,
    };
    ntn.register_satellite(sat_receding);

    let m_rec = ntn
        .compute_link_metrics("sat-receding", &ue, 2.0e9, 30)
        .unwrap();

    // Receding -> negative Doppler shift
    assert!(m_rec.doppler_shift_hz < -10_000.0); // < -10 kHz
}

// ---------------------------------------------------------------------------
// 3. Handover Evaluation based on Elevation Threshold
// ---------------------------------------------------------------------------

#[test]
fn test_ntn_handover_evaluation_elevation_threshold() {
    let mut ntn = NtnEngine::new("ntn-leo-engine-03");

    let ue = GroundUePosition {
        ue_id: "ue-polar-03".to_string(),
        position_ecef_m: [6_371_000.0, 0.0, 0.0],
    };

    // High elevation satellite (Zenith) -> InService
    let sat_high = SatelliteEphemeris {
        sat_id: "sat-high".to_string(),
        orbit_type: OrbitType::Leo,
        position_ecef_m: [6_971_000.0, 0.0, 0.0],
        velocity_ecef_mps: [0.0, 7_500.0, 0.0],
        epoch_timestamp_s: 1700000010,
    };
    ntn.register_satellite(sat_high);

    let status1 = ntn.evaluate_handover("sat-high", &ue, 10.0).unwrap();
    match status1 {
        NtnHandoverStatus::InService { elevation_deg } => {
            assert!(elevation_deg >= 10.0);
        }
        _ => panic!("Expected InService"),
    }

    // Low elevation satellite near the horizon (~2000 km away horizontally)
    let sat_low = SatelliteEphemeris {
        sat_id: "sat-low".to_string(),
        orbit_type: OrbitType::Leo,
        position_ecef_m: [6_450_000.0, 2_200_000.0, 0.0],
        velocity_ecef_mps: [0.0, 7_500.0, 0.0],
        epoch_timestamp_s: 1700000011,
    };
    ntn.register_satellite(sat_low);

    let status2 = ntn.evaluate_handover("sat-low", &ue, 15.0).unwrap();
    match status2 {
        NtnHandoverStatus::HandoverRequired {
            elevation_deg,
            min_threshold_deg,
        } => {
            assert!(elevation_deg < min_threshold_deg);
        }
        _ => panic!("Expected HandoverRequired"),
    }
}

// ---------------------------------------------------------------------------
// 4. GEO Satellite Propagation Delay and K_offset
// ---------------------------------------------------------------------------

#[test]
fn test_ntn_geo_satellite_delay() {
    let mut ntn = NtnEngine::new("ntn-geo-engine-04");

    let ue = GroundUePosition {
        ue_id: "ue-geo-terminal".to_string(),
        position_ecef_m: [6_371_000.0, 0.0, 0.0],
    };

    // Geostationary satellite at ~35,786 km altitude
    let geo_sat = SatelliteEphemeris {
        sat_id: "sat-geo-01".to_string(),
        orbit_type: OrbitType::Geo,
        position_ecef_m: [42_164_000.0, 0.0, 0.0],
        velocity_ecef_mps: [0.0, 0.0, 0.0], // stationary relative to ECEF
        epoch_timestamp_s: 1700000020,
    };
    ntn.register_satellite(geo_sat);

    let metrics = ntn
        .compute_link_metrics("sat-geo-01", &ue, 2.0e9, 15) // 15 kHz SCS = 1.0 ms slot
        .unwrap();

    // Slant range should be ~35,793 km
    assert!((metrics.slant_range_km - 35793.0).abs() < 10.0);

    // One-way delay ~ 119.39 ms, RTT ~ 238.78 ms
    assert!((metrics.one_way_delay_ms - 119.39).abs() < 0.5);
    assert!((metrics.round_trip_time_ms - 238.78).abs() < 1.0);

    // K_offset slots for 1.0 ms slot = ceil(238.78 / 1.0) = 239 slots
    assert_eq!(metrics.k_offset_slots, 239);

    // Stationary GEO -> Doppler should be 0
    assert_eq!(metrics.doppler_shift_hz, 0.0);
}

// ---------------------------------------------------------------------------
// 5. Error Handling
// ---------------------------------------------------------------------------

#[test]
fn test_ntn_error_handling() {
    let ntn = NtnEngine::new("ntn-err-05");

    let ue = GroundUePosition {
        ue_id: "ue-err".to_string(),
        position_ecef_m: [6_371_000.0, 0.0, 0.0],
    };

    // Unknown satellite
    let err1 = ntn.compute_link_metrics("ghost-sat", &ue, 2.0e9, 30);
    assert_eq!(err1, Err(NtnError::SatelliteNotFound));

    // Invalid carrier frequency
    let err2 = ntn.compute_link_metrics("any-sat", &ue, -1.0, 30);
    assert_eq!(err2, Err(NtnError::InvalidCarrierFrequency));

    // Invalid SCS
    let err3 = ntn.compute_link_metrics("any-sat", &ue, 2.0e9, 0);
    assert_eq!(err3, Err(NtnError::InvalidSubcarrierSpacing));
}

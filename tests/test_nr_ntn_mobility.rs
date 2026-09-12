//! Comprehensive Integration Tests for 3GPP Rel-18 NTN Satellite Mobility & Handover Engine.
//! Standards Reference: 3GPP TS 38.300 §16.14, TS 38.331 §5.3.5.4, TR 38.821 Rel-18.

use toy_tcpip::nr_ntn_mobility::{
    FeederLinkSwitchoverManager, FlsPhase, GroundUeLocation, NTN_MOB_EARTH_RADIUS_M,
    NTN_MOB_SPEED_OF_LIGHT_M_S, NtnBeamType, NtnChoCandidate, NtnChoExecutionCondition,
    NtnMobilityEngine, SatelliteOrbitState, TargetSatellitePrecompensationServo,
};

#[test]
fn test_ntn_satellite_orbit_and_elevation_tracking() {
    // 600 km LEO, equatorial orbit (inclination 0 deg), S-band 2.0 GHz
    let orbit = SatelliteOrbitState::new_leo(1, 600_000.0, 0.0, 0.0, 0.0, 2.0e9)
        .expect("Valid orbit configuration");

    assert_eq!(
        orbit.semi_major_axis_m(),
        NTN_MOB_EARTH_RADIUS_M + 600_000.0
    );
    // Period for 600 km LEO is ~96.7 minutes = 5800 s
    let period = orbit.orbital_period_s();
    assert!(
        period > 5700.0 && period < 5900.0,
        "Period {period} s out of expected range"
    );

    let ue = GroundUeLocation::new(0.0, 0.0, 0.0);
    let mut engine = NtnMobilityEngine::new(
        ue,
        orbit,
        100,
        NtnBeamType::EarthFixed {
            cell_center_lat_deg: 0.0,
            cell_center_lon_deg: 0.0,
        },
    );

    // At t = 0 s, satellite is directly overhead at zenith
    let el_zenith = engine.compute_serving_elevation_deg(0.0);
    assert!(
        (el_zenith - 90.0).abs() < 1.0,
        "Zenith elevation should be ~90 deg, got {el_zenith} deg"
    );

    // At t = 300 s (~5 minutes), satellite moves away; elevation drops
    let el_later = engine.compute_serving_elevation_deg(300.0);
    assert!(
        el_later < el_zenith,
        "Elevation should decrease as satellite moves away"
    );
}

#[test]
fn test_earth_fixed_vs_earth_moving_beam_dynamics() {
    let orbit = SatelliteOrbitState::new_leo(2, 600_000.0, 0.0, 0.0, 0.0, 2.0e9).unwrap();

    let ue = GroundUeLocation::new(0.0, 0.0, 0.0);

    // 1. Earth-Fixed Beam: Cell center stays fixed on ground
    let engine_fixed = NtnMobilityEngine::new(
        ue.clone(),
        orbit.clone(),
        101,
        NtnBeamType::EarthFixed {
            cell_center_lat_deg: 0.0,
            cell_center_lon_deg: 0.0,
        },
    );
    assert!(matches!(
        engine_fixed.beam_type,
        NtnBeamType::EarthFixed { .. }
    ));

    // 2. Earth-Moving Beam: Beam nadir moves across ground at ~7.56 km/s
    let engine_moving = NtnMobilityEngine::new(
        ue,
        orbit.clone(),
        102,
        NtnBeamType::EarthMoving {
            beam_radius_km: 400.0,
        },
    );

    // Check distance to moving beam nadir after 60 seconds (moves ~450 km)
    let (r_sat, _) = orbit.propagate(60.0);
    let nadir = r_sat.unit().scale(NTN_MOB_EARTH_RADIUS_M);
    let dist_m = engine_moving.ue_location.to_ecef().sub(&nadir).norm();
    assert!(
        dist_m > 400_000.0,
        "Moving beam should have swept beyond 400 km after 60s, got {dist_m} m"
    );
}

#[test]
fn test_time_based_conditional_handover_trigger() {
    let serving_orbit = SatelliteOrbitState::new_leo(1, 600_000.0, 0.0, 0.0, 0.0, 2.0e9).unwrap();
    // Target satellite in same orbital plane trailing by 30 degrees (approaching overhead)
    let target_orbit = SatelliteOrbitState::new_leo(2, 600_000.0, 0.0, 0.0, -30.0, 2.0e9).unwrap();

    let ue = GroundUeLocation::new(0.0, 0.0, 0.0);
    let mut engine = NtnMobilityEngine::new(
        ue,
        serving_orbit,
        201,
        NtnBeamType::EarthFixed {
            cell_center_lat_deg: 0.0,
            cell_center_lon_deg: 0.0,
        },
    );

    // Add Time-Based CHO candidate with threshold T1 = 120.0 seconds
    engine.add_cho_candidate(NtnChoCandidate {
        candidate_id: 1,
        target_sat_id: 2,
        target_cell_pci: 301,
        condition: NtnChoExecutionCondition::TimeBased {
            t1_threshold_s: 120.0,
        },
        target_orbit,
        cfra_preamble_index: Some(12),
        is_prepared: true,
    });

    // At t = 100 s: condition not yet met
    assert_eq!(engine.evaluate_cho_triggers(100.0), None);

    // At t = 120.5 s: condition met!
    assert_eq!(engine.evaluate_cho_triggers(120.5), Some(0));
}

#[test]
fn test_location_based_conditional_handover_trigger() {
    let serving_orbit = SatelliteOrbitState::new_leo(1, 600_000.0, 0.0, 0.0, 0.0, 2.0e9).unwrap();
    let target_orbit = SatelliteOrbitState::new_leo(2, 600_000.0, 0.0, 0.0, -20.0, 2.0e9).unwrap();

    let ue = GroundUeLocation::new(0.0, 0.0, 0.0);
    let mut engine = NtnMobilityEngine::new(
        ue,
        serving_orbit,
        202,
        NtnBeamType::EarthMoving {
            beam_radius_km: 300.0,
        },
    );

    // Location-based condition: Handover when distance to serving nadir exceeds 300 km
    engine.add_cho_candidate(NtnChoCandidate {
        candidate_id: 2,
        target_sat_id: 2,
        target_cell_pci: 302,
        condition: NtnChoExecutionCondition::LocationBased {
            max_distance_to_cell_center_m: 300_000.0,
        },
        target_orbit,
        cfra_preamble_index: Some(15),
        is_prepared: true,
    });

    // At t = 0 s: satellite at zenith, distance = 0 m -> Not triggered
    assert_eq!(engine.evaluate_cho_triggers(0.0), None);

    // At t = 50 s: satellite has moved ~380 km -> Triggered!
    assert_eq!(engine.evaluate_cho_triggers(50.0), Some(0));
}

#[test]
fn test_target_satellite_ta_and_doppler_precompensation() {
    let target_orbit = SatelliteOrbitState::new_leo(
        3, 600_000.0, 0.0, 0.0,
        -10.0, // Trailing by 10 deg (~1200 km slant range, visible at high elevation)
        2.0e9, // 2 GHz
    )
    .unwrap();

    let ue = GroundUeLocation::new(0.0, 0.0, 0.0);

    let precomp = TargetSatellitePrecompensationServo::compute(&ue, &target_orbit, 0.0);

    // Slant range should be between 600 km and 1500 km
    assert!(
        precomp.slant_range_m >= 600_000.0 && precomp.slant_range_m <= 1_500_000.0,
        "Slant range {} m out of expected bounds",
        precomp.slant_range_m
    );

    // Elevation should be positive (visible above 10 deg mask, here ~22.2 deg)
    assert!(
        precomp.elevation_deg > 20.0,
        "Elevation {} deg too low",
        precomp.elevation_deg
    );

    // Timing Advance: TA = 2 * d / c (around 4 ms to 10 ms)
    let expected_ta = (2.0 * precomp.slant_range_m) / NTN_MOB_SPEED_OF_LIGHT_M_S;
    assert!((precomp.timing_advance_s - expected_ta).abs() < 1e-9);
    assert!(precomp.timing_advance_s >= 0.004 && precomp.timing_advance_s <= 0.010);

    // Doppler shift at 2 GHz should be bounded within +/- 45 kHz
    assert!(
        precomp.doppler_shift_hz.abs() < 45_000.0,
        "Doppler {} Hz exceeds satellite bounds",
        precomp.doppler_shift_hz
    );
}

#[test]
fn test_feeder_link_switchover_lifecycle() {
    let mut fls = FeederLinkSwitchoverManager::new(
        1001, // Source Gateway
        1002, // Target Gateway
        50.0, // Switchover at t = 50.0 s
        20.0, // 20 ms muting window
    );

    // 1. Before switchover (t = 45.0 s): Normal source gateway
    assert_eq!(fls.update_time(45.0), FlsPhase::NormalSourceGateway);
    assert!(fls.handle_packet(1400), "Packet should be sent directly");
    assert_eq!(fls.buffered_bytes, 0);

    // 2. Muting window (t = 50.010 s): Uplink muting active, packets buffered
    assert_eq!(fls.update_time(50.010), FlsPhase::UplinkMuting);
    assert!(
        !fls.handle_packet(1400),
        "Packet must be buffered during muting"
    );
    assert_eq!(fls.buffered_bytes, 1400);

    // 3. Rerouting window (t = 50.030 s): Feeder rerouting active
    assert_eq!(fls.update_time(50.030), FlsPhase::GatewayRerouting);
    assert!(
        !fls.handle_packet(1400),
        "Packet must be buffered during rerouting"
    );
    assert_eq!(fls.buffered_bytes, 2800);

    // 4. Completed (t = 50.060 s): Target gateway active
    assert_eq!(fls.update_time(50.060), FlsPhase::CompletedTargetGateway);
    assert!(
        fls.handle_packet(1400),
        "Packet sent directly on target gateway"
    );
    assert_eq!(fls.forwarded_packets, 2);
}

#[test]
fn test_end_to_end_ntn_mobility_engine_coordinator() {
    let serving_orbit = SatelliteOrbitState::new_leo(1, 600_000.0, 0.0, 0.0, 0.0, 2.0e9).unwrap();
    let target_orbit = SatelliteOrbitState::new_leo(2, 600_000.0, 0.0, 0.0, -15.0, 2.0e9).unwrap();

    let ue = GroundUeLocation::new(0.0, 0.0, 0.0);
    let mut engine = NtnMobilityEngine::new(
        ue,
        serving_orbit,
        100,
        NtnBeamType::EarthFixed {
            cell_center_lat_deg: 0.0,
            cell_center_lon_deg: 0.0,
        },
    );

    // Candidate configured with Elevation Threshold condition
    engine.add_cho_candidate(NtnChoCandidate {
        candidate_id: 1,
        target_sat_id: 2,
        target_cell_pci: 200,
        condition: NtnChoExecutionCondition::ElevationThreshold {
            min_elevation_deg: 25.0,
        },
        target_orbit,
        cfra_preamble_index: Some(8),
        is_prepared: true,
    });

    // Serving satellite overhead (el = 90 deg) -> No trigger
    assert_eq!(engine.evaluate_cho_triggers(0.0), None);

    // Satellite moves away until elevation drops below 25 deg (around t = 220 s)
    let el_220 = engine.compute_serving_elevation_deg(220.0);
    assert!(
        el_220 < 25.0,
        "Elevation {el_220} deg should be below 25 deg"
    );

    let candidate_idx = engine.evaluate_cho_triggers(220.0);
    assert_eq!(candidate_idx, Some(0));

    // Execute Handover
    let precomp = engine
        .execute_handover(candidate_idx.unwrap(), 220.0)
        .expect("Handover execution should succeed");

    assert!(precomp.elevation_deg >= 10.0);
    assert_eq!(engine.serving_cell_pci, 200);
    assert_eq!(engine.serving_orbit.satellite_id, 2);
    assert_eq!(engine.metrics.successful_handovers, 1);
    assert_eq!(engine.metrics.failed_handovers, 0);
}

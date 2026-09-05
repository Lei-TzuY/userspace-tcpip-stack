use toy_tcpip::ntn_5g::{GroundUePosition, NtnEngine, NtnError, OrbitType, SatelliteEphemeris};

fn valid_ue() -> GroundUePosition {
    GroundUePosition {
        ue_id: "ue-validation".to_string(),
        position_ecef_m: [6_371_000.0, 0.0, 0.0],
    }
}

fn valid_satellite(id: &str) -> SatelliteEphemeris {
    SatelliteEphemeris {
        sat_id: id.to_string(),
        orbit_type: OrbitType::Leo,
        position_ecef_m: [6_971_000.0, 0.0, 0.0],
        velocity_ecef_mps: [0.0, 7_500.0, 0.0],
        epoch_timestamp_s: 1_700_000_000,
    }
}

#[test]
fn rejects_unsupported_subcarrier_spacing_instead_of_falling_back() {
    let mut engine = NtnEngine::new("ntn-validation");
    engine.register_satellite(valid_satellite("sat"));

    let result = engine.compute_link_metrics("sat", &valid_ue(), 2.0e9, 45);

    assert_eq!(result, Err(NtnError::InvalidSubcarrierSpacing));
}

#[test]
fn accepts_240_khz_nr_numerology() {
    let mut engine = NtnEngine::new("ntn-validation");
    engine.register_satellite(valid_satellite("sat"));

    let metrics = engine
        .compute_link_metrics("sat", &valid_ue(), 2.0e9, 240)
        .unwrap();

    assert_eq!(metrics.k_offset_slots, 65);
}

#[test]
fn rejects_non_finite_carrier_frequency() {
    let engine = NtnEngine::new("ntn-validation");

    assert_eq!(
        engine.compute_link_metrics("unused", &valid_ue(), f64::NAN, 30),
        Err(NtnError::InvalidCarrierFrequency)
    );
    assert_eq!(
        engine.compute_link_metrics("unused", &valid_ue(), f64::INFINITY, 30),
        Err(NtnError::InvalidCarrierFrequency)
    );
}

#[test]
fn rejects_non_finite_ephemeris_and_ue_coordinates() {
    let mut engine = NtnEngine::new("ntn-validation");
    let mut sat = valid_satellite("sat-nan");
    sat.position_ecef_m[0] = f64::NAN;
    engine.register_satellite(sat);

    assert_eq!(
        engine.compute_link_metrics("sat-nan", &valid_ue(), 2.0e9, 30),
        Err(NtnError::InvalidGeometry)
    );

    let mut engine = NtnEngine::new("ntn-validation");
    engine.register_satellite(valid_satellite("sat"));
    let ue = GroundUePosition {
        ue_id: "ue-inf".to_string(),
        position_ecef_m: [f64::INFINITY, 0.0, 0.0],
    };

    assert_eq!(
        engine.compute_link_metrics("sat", &ue, 2.0e9, 30),
        Err(NtnError::InvalidGeometry)
    );
}

#[test]
fn rejects_degenerate_geometry_instead_of_returning_nan_metrics() {
    let mut engine = NtnEngine::new("ntn-validation");
    let ue = valid_ue();
    let mut sat = valid_satellite("co-located");
    sat.position_ecef_m = ue.position_ecef_m;
    engine.register_satellite(sat);

    assert_eq!(
        engine.compute_link_metrics("co-located", &ue, 2.0e9, 30),
        Err(NtnError::InvalidGeometry)
    );

    let origin_ue = GroundUePosition {
        ue_id: "origin".to_string(),
        position_ecef_m: [0.0, 0.0, 0.0],
    };
    let mut engine = NtnEngine::new("ntn-validation");
    engine.register_satellite(valid_satellite("sat"));

    assert_eq!(
        engine.compute_link_metrics("sat", &origin_ue, 2.0e9, 30),
        Err(NtnError::InvalidGeometry)
    );
}

#[test]
fn rejects_finite_but_unrepresentable_geometry() {
    let mut engine = NtnEngine::new("ntn-validation");
    let mut sat = valid_satellite("huge");
    sat.position_ecef_m = [f64::MAX, f64::MAX, f64::MAX];
    engine.register_satellite(sat);

    assert_eq!(
        engine.compute_link_metrics("huge", &valid_ue(), 2.0e9, 30),
        Err(NtnError::ComputationOutOfRange)
    );
}

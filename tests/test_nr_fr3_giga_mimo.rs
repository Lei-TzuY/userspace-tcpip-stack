//! Comprehensive Integration Tests for 3GPP Rel-18/19 FR3 Giga-MIMO & Near-Field ELAA Engine.
//! Standards Reference: 3GPP TR 38.868, TR 38.901, TS 38.101-1, TS 38.214.

use toy_tcpip::nr_fr3_giga_mimo::{
    Fr3ArrayGeometry, Fr3GigaMimoEngine, Fr3MimoError, Fr3PhaseNoiseCompensator,
    NearFieldBeamformingSynthesizer, NearFieldFocusTarget, PropagationRegime,
    PtrsTimeDensity, SpatialNonStationarityManager, VisibilityRegion,
    DEFAULT_FR3_CARRIER_FREQ_HZ, FR3_SPEED_OF_LIGHT_M_S,
};

#[test]
fn test_fr3_array_geometry_and_rayleigh_distance() {
    // 1. 256-element UPA (16x16) at 10 GHz
    let geom_256 = Fr3ArrayGeometry::new(16, 16, 10.0e9).expect("Valid 256-element array");
    assert_eq!(geom_256.total_elements(), 256);
    let lambda = FR3_SPEED_OF_LIGHT_M_S / 10.0e9; // 0.029979 m (~3 cm)
    assert!((geom_256.wavelength_m() - lambda).abs() < 1e-6);

    let d_diag = geom_256.aperture_diagonal_m();
    assert!(d_diag > 0.30 && d_diag < 0.35, "Diagonal aperture {d_diag} m out of expected range");

    let rayleigh = geom_256.rayleigh_distance_m();
    assert!(rayleigh > 6.0 && rayleigh < 8.0, "Rayleigh distance {rayleigh} m out of expected range");

    // 2. 1024-element UPA (32x32) at 10 GHz
    let geom_1024 = Fr3ArrayGeometry::new(32, 32, 10.0e9).expect("Valid 1024-element array");
    assert_eq!(geom_1024.total_elements(), 1024);
    let rayleigh_1024 = geom_1024.rayleigh_distance_m();
    assert!(rayleigh_1024 > 25.0 && rayleigh_1024 < 32.0);

    // 3. Error handling: exceeds 1024 elements or invalid carrier frequency
    let err_size = Fr3ArrayGeometry::new(40, 40, 10.0e9);
    assert!(matches!(err_size, Err(Fr3MimoError::ArrayDimensionExceeded { .. })));

    let err_freq = Fr3ArrayGeometry::new(16, 16, 3.5e9); // 3.5 GHz is FR1, not FR3
    assert!(matches!(err_freq, Err(Fr3MimoError::InvalidCarrierFrequency(_))));
}

#[test]
fn test_near_field_spherical_wavefront_focusing() {
    let geom = Fr3ArrayGeometry::new(16, 16, DEFAULT_FR3_CARRIER_FREQ_HZ).unwrap();
    // Rayleigh distance is ~6.7 m. Place target in near-field at z = 2.5 m
    let target = NearFieldFocusTarget::new(0.0, 0.0, 2.5);

    let weights = NearFieldBeamformingSynthesizer::compute_near_field_weights(&geom, &target);
    assert_eq!(weights.len(), 256);

    // Evaluate coherent array factor at focal point (0, 0, 2.5) vs pre-focal (0, 0, 1.2) and post-focal (0, 0, 5.0)
    let af_focus = NearFieldBeamformingSynthesizer::evaluate_array_factor_at_point(
        &geom,
        &weights,
        0.0,
        0.0,
        2.5,
    );
    let af_pre = NearFieldBeamformingSynthesizer::evaluate_array_factor_at_point(
        &geom,
        &weights,
        0.0,
        0.0,
        1.2,
    );
    let af_post = NearFieldBeamformingSynthesizer::evaluate_array_factor_at_point(
        &geom,
        &weights,
        0.0,
        0.0,
        5.0,
    );

    // At focal point, coherent addition achieves full array gain ~16.0 (sqrt(256))
    assert!((af_focus - 16.0).abs() < 1e-4);
    assert!(
        af_focus > af_pre,
        "Focal array factor {af_focus} should exceed pre-focal {af_pre}"
    );
    assert!(
        af_focus > af_post,
        "Focal array factor {af_focus} should exceed post-focal {af_post}"
    );
}

#[test]
fn test_near_field_vs_far_field_regime_transition() {
    let geom = Fr3ArrayGeometry::new(16, 16, 10.0e9).unwrap();
    let rayleigh = geom.rayleigh_distance_m(); // ~6.75 m
    assert!(rayleigh > 6.0 && rayleigh < 8.0);

    // Near-field evaluation: d = 2.0 m < rayleigh
    assert_eq!(geom.classify_regime(2.0), PropagationRegime::NearFieldSphericalWave);

    // Far-field evaluation: d = 15.0 m >= rayleigh
    assert_eq!(geom.classify_regime(15.0), PropagationRegime::FarFieldPlaneWave);
}

#[test]
fn test_hybrid_analog_digital_subarray_precoding() {
    let geom = Fr3ArrayGeometry::new(16, 16, 10.0e9).unwrap();
    let target = NearFieldFocusTarget::new(1.0, 1.0, 3.0);
    let full_weights = NearFieldBeamformingSynthesizer::compute_near_field_weights(&geom, &target);

    // 256 elements split into 16 subarrays of 16 elements each
    let engine = Fr3GigaMimoEngine::new(16, 16, 10.0e9, 16).expect("Engine initialization should succeed");
    let (digital_weights, analog_weights) = engine
        .subarray_precoder
        .compute_hybrid_precoding(&full_weights);

    assert_eq!(digital_weights.len(), 16);
    assert_eq!(analog_weights.len(), 256);

    // All analog phase weights should have magnitude ~1.0
    for w in &analog_weights {
        assert!((w.norm() - 1.0).abs() < 1e-6);
    }
}

#[test]
fn test_spatial_non_stationarity_visibility_regions() {
    let geom = Fr3ArrayGeometry::new(16, 16, 10.0e9).unwrap();
    let target = NearFieldFocusTarget::new(0.0, 0.0, 3.0);
    let mut weights = NearFieldBeamformingSynthesizer::compute_near_field_weights(&geom, &target);

    // 16 subarrays of 16 elements = 256 elements.
    // Subarrays 0, 1, 2, 3 are blocked by an obstacle in the near-field
    let vr = VisibilityRegion::with_blockage(16, &[0, 1, 2, 3]);
    assert_eq!(vr.active_count(), 12);

    SpatialNonStationarityManager::apply_visibility_mask(&mut weights, 16, &vr);

    // First 64 elements (subarrays 0..4) must have 0 power
    for w in &weights[0..64] {
        assert_eq!(w.norm(), 0.0);
    }

    // Unblocked elements must be scaled up by sqrt(16/12) to conserve radiated power
    let scale_factor = (16.0 / 12.0_f64).sqrt();
    let original_norm = 1.0 / (256.0_f64).sqrt();
    let expected_norm = original_norm * scale_factor;

    for w in &weights[64..256] {
        assert!((w.norm() - expected_norm).abs() < 1e-5);
    }
}

#[test]
fn test_fr3_phase_noise_and_ptrs_density_adaptation() {
    let comp_10ghz = Fr3PhaseNoiseCompensator::new(10.0e9);
    // Low MCS at 10 GHz -> Density 4
    assert_eq!(comp_10ghz.select_ptrs_density(8), PtrsTimeDensity::Density4);
    // Medium MCS at 10 GHz -> Density 2
    assert_eq!(comp_10ghz.select_ptrs_density(16), PtrsTimeDensity::Density2);
    // High MCS at 10 GHz -> Density 1
    assert_eq!(comp_10ghz.select_ptrs_density(25), PtrsTimeDensity::Density1);

    let comp_18ghz = Fr3PhaseNoiseCompensator::new(18.0e9);
    // Upper FR3 (>= 14 GHz) mandates Density 1 for all MCS
    assert_eq!(comp_18ghz.select_ptrs_density(5), PtrsTimeDensity::Density1);

    // CPE estimation scales with frequency
    let cpe_10 = comp_10ghz.estimate_cpe_std_rad(1.0);
    let cpe_18 = comp_18ghz.estimate_cpe_std_rad(1.0);
    assert!(cpe_18 > cpe_10, "CPE at 18 GHz must exceed 10 GHz");
}

#[test]
fn test_end_to_end_fr3_giga_mimo_engine_coordinator() {
    let mut engine = Fr3GigaMimoEngine::new(16, 16, 10.0e9, 16)
        .expect("FR3 Giga-MIMO Engine creation");

    // Case 1: UE in near-field (z = 2.0 m)
    let ue_near = NearFieldFocusTarget::new(0.0, 0.0, 2.0);
    let (w_near, regime_near) = engine.synthesize_beam_for_ue(&ue_near, None);
    assert_eq!(regime_near, PropagationRegime::NearFieldSphericalWave);
    assert_eq!(w_near.len(), 256);
    assert_eq!(engine.metrics.near_field_focus_events, 1);

    // Case 2: UE in far-field (z = 20.0 m)
    let ue_far = NearFieldFocusTarget::new(0.0, 0.0, 20.0);
    let (w_far, regime_far) = engine.synthesize_beam_for_ue(&ue_far, None);
    assert_eq!(regime_far, PropagationRegime::FarFieldPlaneWave);
    assert_eq!(w_far.len(), 256);
    assert_eq!(engine.metrics.far_field_steering_events, 1);

    // Array gain in dB for 256 elements = 10 * log10(256) ~ 24.08 dB
    assert!((engine.metrics.avg_array_gain_db - 24.08).abs() < 0.1);
}

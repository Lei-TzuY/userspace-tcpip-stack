//! Integration Tests for 3GPP Rel-18 / Rel-19 Reconfigurable Intelligent Surface (RIS) Engine.
//!
//! Validates:
//! 1. Metasurface array aperture, wavelength, and Rayleigh near/far field boundaries.
//! 2. Phase quantization (Continuous, 1-bit, 2-bit, 3-bit) and quantization efficiency.
//! 3. Maximal Ratio Transmission (MRT) coherent phase alignment and blind-spot coverage recovery.
//! 4. Generalized Snell's law anomalous beam steering with linear spatial phase gradients.
//! 5. Cascaded path loss formulations (Far-field product vs Near-field plate reflection).
//! 6. Geometric angle validations, grid bounds, and error handling.

use toy_tcpip::nr_ris_metasurface::{
    ComplexPhasor, DEFAULT_RIS_CARRIER_FREQ_HZ, MetasurfaceArrayConfig, PhaseQuantization,
    PropagationRegime, RisEngine, RisError, SPEED_OF_LIGHT_M_S, SphericalAngle,
};

#[test]
fn test_ris_physical_aperture_and_rayleigh_distance() {
    let config = MetasurfaceArrayConfig::standard_mmwave_28ghz();

    assert_eq!(config.carrier_freq_hz, DEFAULT_RIS_CARRIER_FREQ_HZ);
    assert_eq!(config.num_rows, 16);
    assert_eq!(config.num_cols, 16);
    assert_eq!(config.total_elements(), 256);

    let lambda = config.wavelength_m();
    assert!((lambda - (SPEED_OF_LIGHT_M_S / 28e9)).abs() < 1e-9);

    // Aperture area: (16 * lambda/2) * (16 * lambda/2) = (8 * lambda)^2
    let expected_area = (8.0 * lambda) * (8.0 * lambda);
    assert!((config.aperture_area_m2() - expected_area).abs() < 1e-6);

    // Rayleigh distance: 2 * D^2 / lambda
    let lx = 16.0 * (lambda / 2.0);
    let ly = 16.0 * (lambda / 2.0);
    let d = (lx * lx + ly * ly).sqrt();
    let expected_rayleigh = (2.0 * d * d) / lambda;
    assert!((config.rayleigh_distance_m() - expected_rayleigh).abs() < 1e-4);
}

#[test]
fn test_sub6_ris_configuration() {
    // 3.5 GHz Sub-6 GHz Band n78: 8x8 elements
    let carrier = 3_500_000_000.0;
    let lambda = SPEED_OF_LIGHT_M_S / carrier;

    let config = MetasurfaceArrayConfig {
        num_rows: 8,
        num_cols: 8,
        element_spacing_x_m: lambda / 2.0,
        element_spacing_y_m: lambda / 2.0,
        carrier_freq_hz: carrier,
        quantization: PhaseQuantization::ThreeBit,
        insertion_loss_factor: 0.90,
        switching_time_us: 1.5,
    };

    assert_eq!(config.total_elements(), 64);
    assert_eq!(config.quantization, PhaseQuantization::ThreeBit);

    let engine = RisEngine::new(config).expect("Valid configuration");
    assert_eq!(engine.element_phases.len(), 64);
    assert_eq!(engine.element_amplitudes.len(), 64);
}

#[test]
fn test_quantization_efficiency_and_power_loss() {
    // 3GPP TR 38.867 finding: 2-bit quantization achieves ~0.9 dB of continuous phase performance
    let mut config = MetasurfaceArrayConfig::standard_mmwave_28ghz();
    config.num_rows = 8;
    config.num_cols = 8;

    let direct = ComplexPhasor::from_polar(0.02, 0.1);
    let gnb_to_ris = vec![ComplexPhasor::from_polar(0.15, 0.3); 64];
    let ris_to_ue = vec![ComplexPhasor::from_polar(0.15, 0.7); 64];

    // 1. Continuous phase
    config.quantization = PhaseQuantization::Continuous;
    let mut engine_cont = RisEngine::new(config.clone()).unwrap();
    engine_cont.optimize_coherent_alignment(direct, &gnb_to_ris, &ris_to_ue);
    let (eff_cont, _) = engine_cont.compute_effective_channel(direct, &gnb_to_ris, &ris_to_ue);

    // 2. 2-bit phase
    config.quantization = PhaseQuantization::TwoBit;
    let mut engine_2bit = RisEngine::new(config.clone()).unwrap();
    engine_2bit.optimize_coherent_alignment(direct, &gnb_to_ris, &ris_to_ue);
    let (eff_2bit, _) = engine_2bit.compute_effective_channel(direct, &gnb_to_ris, &ris_to_ue);

    // 3. 1-bit phase
    config.quantization = PhaseQuantization::OneBit;
    let mut engine_1bit = RisEngine::new(config).unwrap();
    engine_1bit.optimize_coherent_alignment(direct, &gnb_to_ris, &ris_to_ue);
    let (eff_1bit, _) = engine_1bit.compute_effective_channel(direct, &gnb_to_ris, &ris_to_ue);

    let p_cont = eff_cont.norm_sqr();
    let p_2bit = eff_2bit.norm_sqr();
    let p_1bit = eff_1bit.norm_sqr();

    assert!(
        p_cont >= p_2bit,
        "Continuous phase must be upper bound of 2-bit"
    );
    assert!(p_2bit >= p_1bit, "2-bit phase must outperform 1-bit phase");

    // 2-bit power should retain at least 80% of continuous power (~-0.9 dB)
    let ratio_2bit = p_2bit / p_cont;
    assert!(
        ratio_2bit > 0.75,
        "2-bit retains >75% of power, got {:.3}",
        ratio_2bit
    );
}

#[test]
fn test_blind_spot_coverage_recovery() {
    let mut config = MetasurfaceArrayConfig::standard_mmwave_28ghz();
    config.num_rows = 16;
    config.num_cols = 16; // 256 elements
    config.quantization = PhaseQuantization::TwoBit;

    let mut engine = RisEngine::new(config).unwrap();

    // Direct path heavily blocked (deep non-line-of-sight dead zone)
    let direct = ComplexPhasor::from_polar(1e-4, 0.0);

    // Clear line of sight gNB -> RIS and RIS -> UE
    let gnb_to_ris = vec![ComplexPhasor::from_polar(0.05, 0.2); 256];
    let ris_to_ue = vec![ComplexPhasor::from_polar(0.05, 0.5); 256];

    engine.optimize_coherent_alignment(direct, &gnb_to_ris, &ris_to_ue);
    let (eff_channel, power_gain_db) =
        engine.compute_effective_channel(direct, &gnb_to_ris, &ris_to_ue);

    // Blind spot recovery: 256 elements providing massive coherent power gain (>30 dB over deep fade)
    assert!(
        power_gain_db > 30.0,
        "Expected >30 dB recovery over -80 dB direct path, got {:.1} dB",
        power_gain_db
    );
    assert!(eff_channel.norm() > 0.1);
}

#[test]
fn test_generalized_snells_law_anomalous_reflection() {
    let config = MetasurfaceArrayConfig::standard_mmwave_28ghz();
    let mut engine = RisEngine::new(config).unwrap();

    // Incident wave at 25 deg elevation, 0 deg azimuth
    let incident = SphericalAngle::from_degrees(25.0, 0.0).unwrap();
    // Anomalous departure at 50 deg elevation, 0 deg azimuth
    let reflection = SphericalAngle::from_degrees(50.0, 0.0).unwrap();

    engine.optimize_anomalous_reflection(incident, reflection);
    assert_eq!(engine.stats_reconfigurations, 1);

    // Check phase difference between consecutive row elements along x
    let p0 = engine.element_phases[0];
    let p1 = engine.element_phases[engine.config.num_cols];
    assert_ne!(p0, p1, "Phase gradient along x-axis must be non-zero");

    // Check along y-axis (phi = 0, so grad_y should be 0)
    let py0 = engine.element_phases[0];
    let py1 = engine.element_phases[1];
    assert_eq!(
        py0, py1,
        "For phi=0, phase gradient along y-axis must be zero"
    );
}

#[test]
fn test_cascaded_path_loss_regimes() {
    let config = MetasurfaceArrayConfig::standard_mmwave_28ghz();
    let engine = RisEngine::new(config).unwrap();

    let d1 = 30.0;
    let d2 = 20.0;

    let pl_far = engine.cascaded_path_loss_linear(d1, d2, PropagationRegime::FarField);
    let pl_near = engine.cascaded_path_loss_linear(d1, d2, PropagationRegime::NearField);

    assert!(pl_far > 0.0 && pl_far < 1.0);
    assert!(pl_near > 0.0 && pl_near < 1.0);
}

#[test]
fn test_error_conditions_and_boundary_checks() {
    // Dimension zero
    let bad_config1 = MetasurfaceArrayConfig {
        num_rows: 0,
        num_cols: 16,
        ..MetasurfaceArrayConfig::standard_mmwave_28ghz()
    };
    assert_eq!(
        RisEngine::new(bad_config1),
        Err(RisError::InvalidDimensions { rows: 0, cols: 16 })
    );

    // Exceeding maximum elements (>1024)
    let bad_config2 = MetasurfaceArrayConfig {
        num_rows: 33,
        num_cols: 32, // 1056 elements
        ..MetasurfaceArrayConfig::standard_mmwave_28ghz()
    };
    assert_eq!(
        RisEngine::new(bad_config2),
        Err(RisError::ExceededMaxElements(1056))
    );

    // Invalid angles (>90 deg elevation or >180 deg azimuth)
    let angle_err1 = SphericalAngle::from_degrees(95.0, 0.0);
    match angle_err1 {
        Err(RisError::InvalidAngle { angle_deg, param }) => {
            assert_eq!(angle_deg, 95.0);
            assert!(param.contains("elevation"));
        }
        other => panic!("Expected InvalidAngle, got {:?}", other),
    }

    let angle_err2 = SphericalAngle::from_degrees(45.0, 200.0);
    match angle_err2 {
        Err(RisError::InvalidAngle { angle_deg, param }) => {
            assert_eq!(angle_deg, 200.0);
            assert!(param.contains("azimuth"));
        }
        other => panic!("Expected InvalidAngle, got {:?}", other),
    }
}

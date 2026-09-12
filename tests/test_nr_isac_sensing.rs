//! Integration Tests for 3GPP Rel-18 5G-Advanced Integrated Sensing and Communication (ISAC / JCAS).
//!
//! Validates:
//! 1. Radar waveform resolution metrics across FR1 and FR2 numerologies.
//! 2. Kinematic target classification (Pedestrian, Vehicle, Drone/UAV, Static Obstacle).
//! 3. Background static clutter temporal cancellation in 2D OFDM channel grids.
//! 4. 2D Range-Doppler map generation and CA-CFAR target detection.
//! 5. Multiplexing configurations (TDM, FDM, Reference Signal Reuse).
//! 6. Boundary limits, maximum target capacity, and error handling.

use toy_tcpip::nr_isac_sensing::{
    DEFAULT_ISAC_CARRIER_FREQ_HZ, DEFAULT_ISAC_SCS_HZ, IsacError, IsacMultiplexingMode,
    IsacSensingEngine, IsacSensingMode, IsacWaveformConfig, MAX_ISAC_TARGETS, SensingTarget,
    TargetClassification,
};

#[test]
fn test_isac_fr2_waveform_metrics() {
    let config = IsacWaveformConfig::standard_mmwave_fr2();

    assert_eq!(config.carrier_freq_hz, DEFAULT_ISAC_CARRIER_FREQ_HZ);
    assert_eq!(config.subcarrier_spacing_hz, DEFAULT_ISAC_SCS_HZ);
    assert_eq!(config.num_subcarriers, 128);
    assert_eq!(config.num_symbols, 32);

    // Bandwidth: 128 * 120 kHz = 15.36 MHz
    let bw = config.bandwidth_hz();
    assert!((bw - 15.36e6).abs() < 1.0);

    // Range resolution: c / (2 * B) = ~9.76 m
    let r_res = config.range_resolution_m();
    assert!((r_res - 9.7588).abs() < 0.05);

    // Max unambiguous range: c / (2 * scs) = ~1249.13 m
    let max_range = config.max_unambiguous_range_m();
    assert!((max_range - 1249.13).abs() < 0.5);

    // Wavelength at 28 GHz: c / 28e9 = ~0.0107 m
    let lambda = config.wavelength_m();
    assert!((lambda - 0.010706).abs() < 0.0001);

    // Velocity resolution: lambda / (2 * burst_duration)
    let v_res = config.velocity_resolution_m_s();
    assert!(v_res > 0.0 && v_res < 20.0);

    // Max unambiguous velocity: lambda / (4 * symbol_duration)
    let max_v = config.max_unambiguous_velocity_m_s();
    assert!(max_v > 50.0);
}

#[test]
fn test_isac_fr1_waveform_configuration() {
    // Sub-6 GHz FR1: 3.5 GHz carrier, 30 kHz SCS, 256 subcarriers, 14 symbols
    let scs = 30_000.0;
    let t_useful = 1.0 / scs;
    let cp = t_useful * 0.07;

    let fr1_config = IsacWaveformConfig {
        carrier_freq_hz: 3_500_000_000.0,
        subcarrier_spacing_hz: scs,
        num_subcarriers: 256,
        num_symbols: 14,
        cp_duration_s: cp,
        mode: IsacSensingMode::Bistatic {
            baseline_distance_m: 150.0,
        },
        multiplexing: IsacMultiplexingMode::FrequencyDivision {
            sensing_start_prb: 50,
            sensing_num_prbs: 20,
        },
    };

    // Bandwidth: 256 * 30 kHz = 7.68 MHz
    assert_eq!(fr1_config.bandwidth_hz(), 7_680_000.0);

    // Range resolution: c / (2 * 7.68 MHz) = ~19.52 m
    let r_res = fr1_config.range_resolution_m();
    assert!((r_res - 19.517).abs() < 0.05);

    // Max unambiguous range: c / (2 * 30 kHz) = ~4996.54 m
    let max_r = fr1_config.max_unambiguous_range_m();
    assert!((max_r - 4996.54).abs() < 0.5);

    // Mode check
    assert_eq!(
        fr1_config.mode,
        IsacSensingMode::Bistatic {
            baseline_distance_m: 150.0
        }
    );
}

#[test]
fn test_sensing_target_kinematic_classification() {
    let stationary_barrier = SensingTarget::new(101, 35.0, 0.0, 12.0);
    assert_eq!(
        stationary_barrier.classify(),
        TargetClassification::StaticObstacle
    );

    let pedestrian = SensingTarget::new(102, 18.0, 1.4, -6.0).with_azimuth(15.0);
    assert_eq!(pedestrian.azimuth_deg, 15.0);
    assert_eq!(pedestrian.classify(), TargetClassification::Pedestrian);

    let suv_vehicle = SensingTarget::new(103, 120.0, 22.5, 14.0);
    assert_eq!(suv_vehicle.classify(), TargetClassification::Vehicle);

    let surveillance_drone = SensingTarget::new(104, 75.0, 6.5, 1.5);
    assert_eq!(
        surveillance_drone.classify(),
        TargetClassification::DroneUav
    );

    // Linear RCS conversion
    let target_0db = SensingTarget::new(1, 10.0, 0.0, 0.0);
    assert!((target_0db.rcs_linear() - 1.0).abs() < 1e-6);

    let target_20db = SensingTarget::new(2, 10.0, 0.0, 20.0);
    assert!((target_20db.rcs_linear() - 100.0).abs() < 1e-4);

    let target_neg10db = SensingTarget::new(3, 10.0, 0.0, -10.0);
    assert!((target_neg10db.rcs_linear() - 0.1).abs() < 1e-6);
}

#[test]
fn test_engine_target_capacity_and_range_validation() {
    let config = IsacWaveformConfig::standard_mmwave_fr2();
    let max_r = config.max_unambiguous_range_m();
    let mut engine = IsacSensingEngine::new(config);

    // Add up to MAX_ISAC_TARGETS
    for id in 0..MAX_ISAC_TARGETS {
        let target = SensingTarget::new(id as u32, 50.0 + (id as f64) * 10.0, 5.0, 5.0);
        assert!(engine.add_target(target).is_ok());
    }

    // Adding (MAX_ISAC_TARGETS + 1) must return ExceededMaxTargets
    let excess_target = SensingTarget::new(999, 200.0, 5.0, 5.0);
    assert_eq!(
        engine.add_target(excess_target),
        Err(IsacError::ExceededMaxTargets(MAX_ISAC_TARGETS))
    );

    // Clear and test out-of-range detection
    engine.clear_targets();
    assert_eq!(engine.active_targets.len(), 0);

    let far_target = SensingTarget::new(10, max_r + 100.0, 0.0, 10.0);
    match engine.add_target(far_target) {
        Err(IsacError::TargetOutOfRange {
            range_m,
            max_range_m,
        }) => {
            assert!(range_m > max_range_m);
        }
        other => panic!("Expected TargetOutOfRange, got {:?}", other),
    }
}

#[test]
fn test_static_clutter_cancellation_with_moving_target() {
    let mut config = IsacWaveformConfig::standard_mmwave_fr2();
    config.num_subcarriers = 16;
    config.num_symbols = 8;
    let mut engine = IsacSensingEngine::new(config);

    // Static clutter object (e.g. concrete pillar at 25m)
    let pillar = SensingTarget::new(1, 25.0, 0.0, 20.0);
    // Dynamic target (vehicle at 60m moving at 15 m/s)
    let vehicle = SensingTarget::new(2, 60.0, 15.0, 10.0);

    engine.add_target(pillar).unwrap();
    engine.add_target(vehicle).unwrap();

    let mut channel = engine.synthesize_channel_matrix(0.0);
    assert_eq!(channel.len(), 16);
    assert_eq!(channel[0].len(), 8);

    // Static clutter cancellation
    engine.cancel_static_clutter(&mut channel);

    // Verify non-zero response remains due to moving vehicle
    let energy_after: f64 = channel
        .iter()
        .flat_map(|row| row.iter())
        .map(|c| c.norm_sqr())
        .sum();
    assert!(
        energy_after > 0.0,
        "Dynamic target energy must be preserved"
    );
}

#[test]
fn test_end_to_end_sensing_pipeline_and_cfar_detection() {
    let mut config = IsacWaveformConfig::standard_mmwave_fr2();
    config.num_subcarriers = 32;
    config.num_symbols = 16;

    let r_res = config.range_resolution_m();
    let mut engine = IsacSensingEngine::new(config);
    engine.cfar_threshold_factor = 3.0;
    engine.cfar_train_cells = 4;
    engine.cfar_guard_cells = 1;

    // Place a target at bin 6: range = 6 * r_res, velocity = 45 m/s (outside clutter stopband)
    let target_range = 6.0 * r_res;
    let target = SensingTarget::new(1, target_range, 45.0, 15.0);
    engine.add_target(target).unwrap();

    let detections = engine.process_sensing_burst(20.0);

    assert_eq!(engine.stats_frames_processed, 1);
    assert!(!detections.is_empty(), "Expected at least one detection");

    let first = &detections[0];
    // Range estimation accuracy within 2 bins
    assert!(
        (first.estimated_range_m - target_range).abs() <= 2.0 * r_res,
        "Estimated range {:.2} m should be close to target {:.2} m",
        first.estimated_range_m,
        target_range
    );
    assert!(first.peak_power_db > -100.0);
    assert!(first.snr_db > 0.0);
}

#[test]
fn test_isac_multiplexing_and_error_display() {
    let tdm = IsacMultiplexingMode::TimeDivision {
        sensing_slot_period: 40,
        sensing_slot_duration: 2,
    };
    let fdm = IsacMultiplexingMode::FrequencyDivision {
        sensing_start_prb: 10,
        sensing_num_prbs: 8,
    };
    let ref_reuse = IsacMultiplexingMode::ReferenceSignalReuse;

    assert_eq!(
        tdm,
        IsacMultiplexingMode::TimeDivision {
            sensing_slot_period: 40,
            sensing_slot_duration: 2
        }
    );
    assert_ne!(tdm, fdm);
    assert_ne!(fdm, ref_reuse);

    let err1 = IsacError::InvalidBandwidth(5e6);
    assert!(err1.to_string().contains("5.00 MHz"));

    let err2 = IsacError::InvalidSubcarrierSpacing(60_000.0);
    assert!(err2.to_string().contains("60.0 kHz"));

    let err3 = IsacError::InsufficientSamples {
        required: 64,
        actual: 32,
    };
    assert!(err3.to_string().contains("required 64, got 32"));

    let err4 = IsacError::VelocityAmbiguity {
        velocity_m_s: 120.0,
        max_velocity_m_s: 95.0,
    };
    assert!(err4.to_string().contains("120.0 m/s exceeds max"));
}

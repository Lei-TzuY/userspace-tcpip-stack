//! Integration tests for 3GPP Release 18 RedCap Positioning & Frequency Hopping Virtual Wideband PRS Engine.

use toy_tcpip::nr_redcap_positioning::{
    Anchor3D, Complex64, HopChannelMeasurement, IdftCirSynthesizer, MultilaterationSolver3D,
    OnDemandPrsGrant, OnDemandPrsManager, OnDemandPrsState, PhaseContinuityType,
    PosAccuracyClass, PrsFrequencyHopConfig, PrsGoldSequence, RedCapMultiRttMeasurement,
    RedCapPosCapability, RedCapPosDeviceType, RedCapPositioningEngine, SuperResolutionToaEstimator,
    VirtualWidebandSynthesizer, REDCAP_POS_SPEED_OF_LIGHT_M_S,
};
use std::f64::consts::PI;

#[test]
fn test_prs_gold_sequence_and_qpsk_mapping() {
    let mut prs_gen = PrsGoldSequence::new(42, 5, 0, 0);
    let symbols = prs_gen.generate_qpsk_symbols(64);

    assert_eq!(symbols.len(), 64);
    for s in &symbols {
        let p = s.norm_sq();
        // QPSK power should be exactly 1.0 (1/sqrt(2)^2 + 1/sqrt(2)^2 = 0.5 + 0.5 = 1.0)
        assert!((p - 1.0).abs() < 1e-9, "QPSK symbol magnitude should be 1.0, got {p}");
        // Constellation points should have |re| == |im| == 1/sqrt(2)
        assert!((s.re.abs() - 1.0 / 2.0_f64.sqrt()).abs() < 1e-9);
        assert!((s.im.abs() - 1.0 / 2.0_f64.sqrt()).abs() < 1e-9);
    }
}

#[test]
fn test_virtual_wideband_phase_stitching_non_coherent() {
    let config = PrsFrequencyHopConfig::new_standard_4hop_80mhz(30, 505)
        .expect("Config construction should succeed");
    assert_eq!(config.hops.len(), 4);

    let sc_per_prb = 12 / (config.comb_size as usize); // 12 / 4 = 3 sc/PRB
    let subcarrier_spacing_hz = (config.scs_khz as f64) * 1e3 * (config.comb_size as f64);

    // Simulate a channel with propagation delay tau = 60 ns
    let true_delay_sec = 60e-9;

    // Simulate 4 hops with independent random phase discontinuities
    let phase_offsets = [0.0, 1.45, -2.10, 0.88];
    let mut measurements = Vec::new();

    for (i, hop) in config.hops.iter().enumerate() {
        let num_sc = (hop.num_prbs as usize) * sc_per_prb;
        let mut cfr = Vec::with_capacity(num_sc);

        for sc_idx in 0..num_sc {
            let abs_sc = (hop.start_prb as usize) * sc_per_prb + sc_idx;
            let f = (abs_sc as f64) * subcarrier_spacing_hz;
            // Channel: exp(-j 2*pi * f * tau) * exp(j phi_hop)
            let channel_phase = -2.0 * PI * f * true_delay_sec + phase_offsets[i];
            cfr.push(Complex64::from_polar(1.0, channel_phase));
        }

        measurements.push(HopChannelMeasurement {
            hop_id: hop.hop_id,
            subcarrier_cfr: cfr,
            snr_db: 25.0,
        });
    }

    let synthesizer = VirtualWidebandSynthesizer::new();
    let stitched_cfr = synthesizer
        .stitch_hops(&config, &measurements, PhaseContinuityType::NonCoherent)
        .expect("Stitching should succeed");

    assert!(!stitched_cfr.is_empty());

    // Compute CIR and estimate TOA
    let cir_synthesizer = IdftCirSynthesizer::new();
    let cir = cir_synthesizer
        .compute_cir(&stitched_cfr, 4)
        .expect("IDFT CIR synthesis should succeed");

    let total_bw_hz = (stitched_cfr.len() as f64) * subcarrier_spacing_hz;
    let sampling_period_sec = 1.0 / (total_bw_hz * 4.0);

    let estimator = SuperResolutionToaEstimator::default();
    let (est_delay_sec, _peak_power_db, snr_db) = estimator
        .estimate_toa(&cir, sampling_period_sec)
        .expect("TOA estimation should succeed");

    assert!(snr_db > 10.0, "Estimated SNR should be high, got {snr_db}");

    // Accuracy should be within 1.5 nanoseconds of true delay (60 ns)
    let error_ns = (est_delay_sec - true_delay_sec).abs() * 1e9;
    assert!(
        error_ns < 1.5,
        "TOA estimation error too high: {error_ns:.3} ns (est: {:.2} ns, true: {:.2} ns)",
        est_delay_sec * 1e9,
        true_delay_sec * 1e9
    );
}

#[test]
fn test_redcap_multi_rtt_with_internal_cal() {
    let true_slant_range_m = 125.0;
    let prop_time_sec = true_slant_range_m / REDCAP_POS_SPEED_OF_LIGHT_M_S;
    let prop_time_ns = prop_time_sec * 1e9;

    let ue_hardware_cal_ns = 35.0; // RedCap hardware filter delay
    let gnb_rx_tx_ns = 1500.0;
    // gnb_rx_tx - (ue_rx_tx - cal) = 2 * prop_time_ns
    // => ue_rx_tx = gnb_rx_tx - 2 * prop_time_ns + cal
    let ue_rx_tx_measured_ns = gnb_rx_tx_ns - 2.0 * prop_time_ns + ue_hardware_cal_ns;

    let measurement = RedCapMultiRttMeasurement {
        trp_id: 1,
        gnb_rx_tx_ns,
        ue_rx_tx_measured_ns,
        ue_internal_cal_ns: ue_hardware_cal_ns,
    };

    let (_prop_sec, est_range_m) = measurement
        .compute_slant_range()
        .expect("Slant range calculation should succeed");

    let error_m = (est_range_m - true_slant_range_m).abs();
    assert!(
        error_m < 0.01,
        "Range calculation error too large: {error_m:.4} m"
    );
}

#[test]
fn test_on_demand_prs_power_saving_state_machine() {
    let mut manager = OnDemandPrsManager::new();
    assert_eq!(manager.state, OnDemandPrsState::Idle);

    // UE sends On-Demand PRS request
    let req = manager.request_prs(1001, PosAccuracyClass::HighAccuracy, 16);
    assert_eq!(manager.state, OnDemandPrsState::Requested);
    assert_eq!(req.requested_duration_slots, 16);

    // gNB sends grant
    let grant = OnDemandPrsGrant {
        transaction_id: req.transaction_id,
        start_slot: 10,
        duration_slots: 16,
        hop_mask: 0x0F,
    };
    manager.handle_grant(&grant).expect("Grant handling should succeed");
    assert_eq!(manager.state, OnDemandPrsState::ActiveBurst);

    // Clock ticks before burst completion
    for slot in 10..25 {
        manager.tick_slot(slot);
        assert_eq!(manager.state, OnDemandPrsState::ActiveBurst);
    }

    // Burst expires at slot 26
    manager.tick_slot(26);
    assert_eq!(manager.state, OnDemandPrsState::PowerDown);

    manager.tick_slot(27);
    assert_eq!(manager.state, OnDemandPrsState::Idle);

    // Simulate idle slots up to 100
    for slot in 28..100 {
        manager.tick_slot(slot);
    }

    let savings = manager.energy_savings_ratio();
    assert!(
        savings > 0.80,
        "Energy savings ratio should be > 80%, got {:.1}%",
        savings * 100.0
    );
}

#[test]
fn test_3d_multilateration_solver_and_dop_metrics() {
    let anchors = vec![
        Anchor3D::new(0, 0.0, 0.0, 25.0),
        Anchor3D::new(1, 200.0, 0.0, 30.0),
        Anchor3D::new(2, 0.0, 250.0, 20.0),
        Anchor3D::new(3, 180.0, 220.0, 35.0),
    ];

    let true_ue_pos = (85.0, 110.0, 1.8);

    // Calculate exact ranges
    let mut ranges = Vec::new();
    for a in &anchors {
        let r = a.distance_to(true_ue_pos.0, true_ue_pos.1, true_ue_pos.2);
        ranges.push(r);
    }

    let solver = MultilaterationSolver3D::default();
    let estimate = solver
        .solve_multi_rtt(&anchors, &ranges)
        .expect("Solver should converge cleanly");

    let err_x = (estimate.x_meters - true_ue_pos.0).abs();
    let err_y = (estimate.y_meters - true_ue_pos.1).abs();
    let err_z = (estimate.z_meters - true_ue_pos.2).abs();
    let total_err = (err_x * err_x + err_y * err_y + err_z * err_z).sqrt();

    assert!(
        total_err < 0.05,
        "3D Multilateration error too high: {total_err:.4} m (x_err: {err_x:.3}, y_err: {err_y:.3}, z_err: {err_z:.3})"
    );
    assert!(estimate.dop.hdop < 4.0, "HDOP should be good: {}", estimate.dop.hdop);
    assert!(estimate.dop.vdop < 10.0, "VDOP: {}", estimate.dop.vdop);
}

#[test]
fn test_eredcap_8hop_positioning_coordinator() {
    let capability = RedCapPosCapability {
        device_type: RedCapPosDeviceType::ERedCap,
        max_dl_prs_bw_mhz: 5,
        rf_retuning_time_us: 200.0,
        phase_continuity: PhaseContinuityType::CoherentWithDdc,
        internal_rx_tx_delay_ns: 40.0,
        supported_combs: vec![2, 4],
    };

    let mut engine = RedCapPositioningEngine::new(capability);

    let config = PrsFrequencyHopConfig::new_eredcap_8hop_40mhz(30, 202)
        .expect("eRedCap config should succeed");
    assert_eq!(config.hops.len(), 8);

    let sc_per_prb = 12 / (config.comb_size as usize); // 6
    let true_delay = 45e-9;
    let subcarrier_spacing_hz = (config.scs_khz as f64) * 1e3 * (config.comb_size as f64);

    let mut measurements = Vec::new();
    for hop in &config.hops {
        let num_sc = (hop.num_prbs as usize) * sc_per_prb;
        let mut cfr = Vec::with_capacity(num_sc);
        for sc_idx in 0..num_sc {
            let abs_sc = (hop.start_prb as usize) * sc_per_prb + sc_idx;
            let f = (abs_sc as f64) * subcarrier_spacing_hz;
            let phase = -2.0 * PI * f * true_delay;
            cfr.push(Complex64::from_polar(1.0, phase));
        }
        measurements.push(HopChannelMeasurement {
            hop_id: hop.hop_id,
            subcarrier_cfr: cfr,
            snr_db: 30.0,
        });
    }

    let (est_delay, _, _) = engine
        .process_frequency_hops(&config, &measurements, 4)
        .expect("Processing frequency hops should succeed");

    let err_ns = (est_delay - true_delay).abs() * 1e9;
    assert!(
        err_ns < 1.0,
        "eRedCap synthesized delay error too high: {err_ns:.3} ns"
    );

    // Check Multi-RTT positioning through coordinator
    let anchors = vec![
        Anchor3D::new(0, 0.0, 0.0, 20.0),
        Anchor3D::new(1, 150.0, 0.0, 25.0),
        Anchor3D::new(2, 0.0, 180.0, 22.0),
        Anchor3D::new(3, 140.0, 160.0, 30.0),
    ];
    let ue_pos = (60.0, 70.0, 1.2);

    let mut rtt_measurements = Vec::new();
    for a in &anchors {
        let dist = a.distance_to(ue_pos.0, ue_pos.1, ue_pos.2);
        let prop_ns = (dist / REDCAP_POS_SPEED_OF_LIGHT_M_S) * 1e9;
        let gnb_rx_tx_ns = 2000.0;
        let ue_rx_tx_measured_ns = gnb_rx_tx_ns - 2.0 * prop_ns + 40.0;
        rtt_measurements.push(RedCapMultiRttMeasurement {
            trp_id: a.id,
            gnb_rx_tx_ns,
            ue_rx_tx_measured_ns,
            ue_internal_cal_ns: 40.0,
        });
    }

    let est = engine
        .locate_ue_multi_rtt(&anchors, &rtt_measurements)
        .expect("Location calculation should succeed");

    let total_err = ((est.x_meters - ue_pos.0).powi(2)
        + (est.y_meters - ue_pos.1).powi(2)
        + (est.z_meters - ue_pos.2).powi(2))
    .sqrt();

    assert!(
        total_err < 0.1,
        "eRedCap multi-RTT positioning error: {total_err:.3} m"
    );
    assert_eq!(engine.metrics.successful_positions, 1);
    assert_eq!(engine.metrics.virtual_wideband_syntheses, 1);
}

//! Integration tests for 3GPP Rel-18/19 Sidelink Phase-Based Distance Measurement (PBDM) Engine.

use toy_tcpip::nr_sidelink_ranging_pbdm::*;

#[test]
fn test_multi_tone_phase_unwrapping() {
    // Generate carrier tones with known phase wrapping: step = +2.5 rad per tone
    // Consecutive raw values will wrap modulo 2*pi
    let mut tones = Vec::new();
    let f0 = 5_900_000_000.0;
    let df = 2_000_000.0;
    let mut true_phase = 0.5;

    for i in 0..10 {
        let mut wrapped = (true_phase + std::f64::consts::PI) % (2.0 * std::f64::consts::PI);
        if wrapped < 0.0 {
            wrapped += 2.0 * std::f64::consts::PI;
        }
        wrapped -= std::f64::consts::PI;

        tones.push(SlPbdmCarrierTone {
            freq_hz: f0 + (i as f64) * df,
            phase_rad: wrapped,
            snr_db: 25.0,
            amplitude: 1.0,
        });
        true_phase += 1.2; // 1.2 rad step (within [-pi, pi] per step)
    }

    let unwrapped = NrSlPbdmEngine::unwrap_carrier_phases(&tones).expect("unwrapping failed");
    assert_eq!(unwrapped.len(), 10);

    // Verify unwrapped phase steps are all approximately 1.2 radians
    for i in 1..unwrapped.len() {
        let step = unwrapped[i].1 - unwrapped[i - 1].1;
        assert!((step - 1.2).abs() < 1e-4);
    }
}

#[test]
fn test_sub_decimeter_ranging_accuracy_nominal_los() {
    let mut engine = NrSlPbdmEngine::new(PbdmRangingSessionConfig::new(101, 202, 5_900_000_000.0));
    let true_distance_m = 14.375; // 14 meters, 37.5 cm

    let f0 = 5_900_000_000.0;
    let df = 2_000_000.0;
    let num_tones = 16;

    // Generate multi-tone phase measurements:
    // Round-trip phase: phi_k = (4*pi*d / c) * f_k mod 2*pi
    let mut tones = Vec::with_capacity(num_tones);
    for k in 0..num_tones {
        let f_k = f0 + (k as f64) * df;
        let exact_phase = (4.0 * std::f64::consts::PI * true_distance_m / SPEED_OF_LIGHT_M_S) * f_k;
        let mut wrapped = (exact_phase + std::f64::consts::PI) % (2.0 * std::f64::consts::PI);
        if wrapped < 0.0 {
            wrapped += 2.0 * std::f64::consts::PI;
        }
        wrapped -= std::f64::consts::PI;

        tones.push(SlPbdmCarrierTone {
            freq_hz: f_k,
            phase_rad: wrapped,
            snr_db: 30.0,
            amplitude: 1.0,
        });
    }

    // Coarse RTT timestamps with slight +/- 25 cm noise
    let rtt_noisy_distance = true_distance_m + 0.25;
    let tof_s = rtt_noisy_distance / SPEED_OF_LIGHT_M_S;
    let rtt = TwoWayRttTimestamps {
        t1_tx_initiator_s: 0.0,
        t2_rx_responder_s: tof_s,
        t3_tx_responder_s: tof_s + 0.001, // 1 ms turnaround
        t4_rx_initiator_s: 2.0 * tof_s + 0.001,
    };

    let outcome = engine
        .evaluate_ranging_epoch(&rtt, &tones)
        .expect("ranging evaluation failed");

    // Sub-decimeter precision check: fused error must be within 3 cm of true distance!
    let distance_error = (outcome.fused_distance_m - true_distance_m).abs();
    assert!(distance_error < 0.03, "Distance error {:.4} m exceeds 3 cm", distance_error);

    assert_eq!(outcome.channel_condition, RangingChannelCondition::LineOfSight);
    assert!(outcome.phase_r_squared > 0.999);
    assert!(outcome.uncertainty_m < 0.05);
    assert_eq!(engine.state(), PbdmState::Solved);
}

#[test]
fn test_integer_ambiguity_resolution_across_long_distance() {
    let mut engine = NrSlPbdmEngine::new(PbdmRangingSessionConfig::new(102, 203, 5_900_000_000.0));
    // Unambiguous period: c / (2 * 2MHz) = 74.948 meters
    // True distance is 95.5 meters (> 74.95m, so integer cycle N = 1)
    let true_distance_m = 95.50;

    let f0 = 5_900_000_000.0;
    let df = 2_000_000.0;
    let num_tones = 16;

    let mut tones = Vec::with_capacity(num_tones);
    for k in 0..num_tones {
        let f_k = f0 + (k as f64) * df;
        let exact_phase = (4.0 * std::f64::consts::PI * true_distance_m / SPEED_OF_LIGHT_M_S) * f_k;
        let mut wrapped = (exact_phase + std::f64::consts::PI) % (2.0 * std::f64::consts::PI);
        if wrapped < 0.0 {
            wrapped += 2.0 * std::f64::consts::PI;
        }
        wrapped -= std::f64::consts::PI;

        tones.push(SlPbdmCarrierTone {
            freq_hz: f_k,
            phase_rad: wrapped,
            snr_db: 28.0,
            amplitude: 1.0,
        });
    }

    // Coarse RTT distance with 50 cm noise: 96.0 m
    let rtt_noisy_distance = 96.0;
    let tof_s = rtt_noisy_distance / SPEED_OF_LIGHT_M_S;
    let rtt = TwoWayRttTimestamps {
        t1_tx_initiator_s: 0.0,
        t2_rx_responder_s: tof_s,
        t3_tx_responder_s: tof_s + 0.0005,
        t4_rx_initiator_s: 2.0 * tof_s + 0.0005,
    };

    let outcome = engine
        .evaluate_ranging_epoch(&rtt, &tones)
        .expect("evaluation failed");

    // Integer cycle must be correctly resolved to yield accurate 95.5m
    let distance_error = (outcome.fused_distance_m - true_distance_m).abs();
    assert!(distance_error < 0.05, "Error {:.4} m exceeds 5 cm", distance_error);
    assert_eq!(outcome.channel_condition, RangingChannelCondition::LineOfSight);
}

#[test]
fn test_internal_delay_calibration() {
    let mut config = PbdmRangingSessionConfig::new(103, 204, 3_500_000_000.0);
    // 10 nanoseconds internal transceiver delay (approx 3.0 meters of light travel)
    let internal_delay_s = 10.0e-9;
    config.internal_delay_s = internal_delay_s;

    let mut engine = NrSlPbdmEngine::new(config);
    let true_distance_m = 8.25;

    let f0 = 3_500_000_000.0;
    let df = 2_000_000.0;
    let num_tones = 16;

    let mut tones = Vec::with_capacity(num_tones);
    for k in 0..num_tones {
        let f_k = f0 + (k as f64) * df;
        // Total delay includes true round-trip + 2*tau_internal
        let total_delay_s = (2.0 * true_distance_m / SPEED_OF_LIGHT_M_S) + (2.0 * internal_delay_s);
        let exact_phase = 2.0 * std::f64::consts::PI * f_k * total_delay_s;
        let mut wrapped = (exact_phase + std::f64::consts::PI) % (2.0 * std::f64::consts::PI);
        if wrapped < 0.0 {
            wrapped += 2.0 * std::f64::consts::PI;
        }
        wrapped -= std::f64::consts::PI;

        tones.push(SlPbdmCarrierTone {
            freq_hz: f_k,
            phase_rad: wrapped,
            snr_db: 32.0,
            amplitude: 1.0,
        });
    }

    let raw_tof_s = (true_distance_m / SPEED_OF_LIGHT_M_S) + internal_delay_s;
    let rtt = TwoWayRttTimestamps {
        t1_tx_initiator_s: 0.0,
        t2_rx_responder_s: raw_tof_s,
        t3_tx_responder_s: raw_tof_s + 0.0002,
        t4_rx_initiator_s: 2.0 * raw_tof_s + 0.0002,
    };

    let outcome = engine
        .evaluate_ranging_epoch(&rtt, &tones)
        .expect("calibration test failed");

    // Internal delay should be completely calibrated out
    let distance_error = (outcome.fused_distance_m - true_distance_m).abs();
    assert!(distance_error < 0.04);
}

#[test]
fn test_multipath_ripple_detection_and_nlos_fallback() {
    let mut engine = NrSlPbdmEngine::new(PbdmRangingSessionConfig::new(104, 205, 5_900_000_000.0));
    let true_distance_m = 20.0;

    let f0 = 5_900_000_000.0;
    let df = 2_000_000.0;
    let num_tones = 16;

    // Inject strong multipath phase ripple: sin(k * pi / 2) * 1.5 rad
    let mut tones = Vec::with_capacity(num_tones);
    for k in 0..num_tones {
        let f_k = f0 + (k as f64) * df;
        let exact_phase = (4.0 * std::f64::consts::PI * true_distance_m / SPEED_OF_LIGHT_M_S) * f_k;
        let multipath_ripple = (k as f64 * 1.5).sin() * 4.0;
        let distorted = exact_phase + multipath_ripple;

        let mut wrapped = (distorted + std::f64::consts::PI) % (2.0 * std::f64::consts::PI);
        if wrapped < 0.0 {
            wrapped += 2.0 * std::f64::consts::PI;
        }
        wrapped -= std::f64::consts::PI;

        tones.push(SlPbdmCarrierTone {
            freq_hz: f_k,
            phase_rad: wrapped,
            snr_db: 15.0,
            amplitude: 0.5,
        });
    }

    let tof_s = true_distance_m / SPEED_OF_LIGHT_M_S;
    let rtt = TwoWayRttTimestamps {
        t1_tx_initiator_s: 0.0,
        t2_rx_responder_s: tof_s,
        t3_tx_responder_s: tof_s + 0.001,
        t4_rx_initiator_s: 2.0 * tof_s + 0.001,
    };

    let outcome = engine
        .evaluate_ranging_epoch(&rtt, &tones)
        .expect("ranging failed");

    // Engine must detect non-linear phase ripple and flag Multipath or NLOS
    assert!(outcome.channel_condition != RangingChannelCondition::LineOfSight);
    assert!(outcome.residual_sigma_rad > LOS_PHASE_SIGMA_RAD_THRESHOLD);
    assert!(outcome.phase_r_squared < MULTIPATH_R2_THRESHOLD);
    assert!(outcome.uncertainty_m >= 0.20);
}

#[test]
fn test_wire_codec_and_crc16() {
    let outcome = PbdmRangingOutcome {
        session_id: 999,
        coarse_rtt_distance_m: 12.30,
        fine_pbdm_distance_m: 12.345,
        fused_distance_m: 12.345,
        uncertainty_m: 0.025,
        channel_condition: RangingChannelCondition::LineOfSight,
        phase_r_squared: 0.9995,
        residual_sigma_rad: 0.03,
    };

    let engine = NrSlPbdmEngine::new(PbdmRangingSessionConfig::new(999, 1000, 5_900_000_000.0));
    let pdu = engine.generate_report_pdu(&outcome, 1726050000);

    let wire = pdu.encode_wire();
    assert!(wire.len() >= 35);

    let decoded = SlPbdmReportPdu::decode_wire(&wire).expect("decoding failed");
    assert_eq!(decoded.session_id, 999);
    assert_eq!(decoded.timestamp_ms, 1726050000);
    assert_eq!(decoded.channel_condition, RangingChannelCondition::LineOfSight);
    assert!((decoded.fused_distance_m - 12.345).abs() < 1e-3);
    assert!((decoded.uncertainty_m - 0.025).abs() < 1e-3);

    // Corrupted CRC test
    let mut corrupted = wire.clone();
    let idx = corrupted.len() - 1;
    corrupted[idx] ^= 0xAA;
    assert!(matches!(
        SlPbdmReportPdu::decode_wire(&corrupted),
        Err(PbdmError::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_telemetry_tracking() {
    let mut engine = NrSlPbdmEngine::new(PbdmRangingSessionConfig::new(505, 606, 5_900_000_000.0));

    // Generate 1 nominal LoS epoch
    let mut tones = Vec::new();
    let d = 10.0;
    for k in 0..8 {
        let f = 5_900_000_000.0 + (k as f64) * 2_000_000.0;
        let phase = (4.0 * std::f64::consts::PI * d / SPEED_OF_LIGHT_M_S) * f;
        let mut wrapped = (phase + std::f64::consts::PI) % (2.0 * std::f64::consts::PI);
        if wrapped < 0.0 {
            wrapped += 2.0 * std::f64::consts::PI;
        }
        wrapped -= std::f64::consts::PI;
        tones.push(SlPbdmCarrierTone {
            freq_hz: f,
            phase_rad: wrapped,
            snr_db: 30.0,
            amplitude: 1.0,
        });
    }

    let tof = d / SPEED_OF_LIGHT_M_S;
    let rtt = TwoWayRttTimestamps {
        t1_tx_initiator_s: 0.0,
        t2_rx_responder_s: tof,
        t3_tx_responder_s: tof + 0.001,
        t4_rx_initiator_s: 2.0 * tof + 0.001,
    };

    engine.evaluate_ranging_epoch(&rtt, &tones).unwrap();

    let tel = engine.telemetry();
    assert_eq!(tel.total_ranging_epochs, 1);
    assert_eq!(tel.successful_pbdm_epochs, 1);
    assert_eq!(tel.sub_5cm_epochs, 1);
    assert_eq!(tel.high_precision_rate_percent(), 100.0);
    assert!(tel.average_phase_residual_rad() < 0.05);
}

#[test]
fn test_error_display() {
    let e1 = PbdmError::InsufficientTones { count: 2, required: 4 };
    assert!(format!("{}", e1).contains("Insufficient carrier tones: 2"));

    let e2 = PbdmError::InvalidFrequencySpan;
    assert!(format!("{}", e2).contains("Carrier tone frequencies"));

    let e3 = PbdmError::NegativePropagationTime(-1.5e-8);
    assert!(format!("{}", e3).contains("Negative two-way propagation time"));

    let e4 = PbdmError::ChecksumMismatch { expected: 0x1111, calculated: 0x2222 };
    assert!(format!("{}", e4).contains("0x1111"));
}

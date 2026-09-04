//! Integration tests for O-RAN WG4 Open Fronthaul Shared Cell Engine.

use toy_tcpip::oran_shared_cell::*;

#[test]
fn test_ru_registration_and_array_gain() {
    let mut engine = SharedCellEngine::new(
        101,
        CombiningMode::MaximumRatioCombining,
        DEFAULT_SKEW_TOLERANCE_NS,
    );

    assert_eq!(engine.member_count(), 0);
    assert_eq!(engine.metrics().theoretical_array_gain_db, 0.0);

    // Register 4 RUs
    for id in 1..=4 {
        let profile = RuMemberProfile::new(id, 0, 1.0, 15.0, 0.0);
        engine
            .add_ru_member(profile)
            .expect("Adding RU should succeed");
    }

    assert_eq!(engine.member_count(), 4);
    // 4 RUs: array gain = 10 * log10(4) = 6.0206 dB
    let gain = engine.metrics().theoretical_array_gain_db;
    assert!((gain - 6.0206).abs() < 0.01);

    // Duplicate RU ID rejection
    let dup = RuMemberProfile::new(2, 0, 1.0, 10.0, 0.0);
    assert_eq!(
        engine.add_ru_member(dup),
        Err(SharedCellError::DuplicateRuId(2))
    );
}

#[test]
fn test_downlink_distribution_with_delays_and_scaling() {
    let mut engine = SharedCellEngine::new(
        202,
        CombiningMode::SelectionCombining,
        DEFAULT_SKEW_TOLERANCE_NS,
    );

    // RU 1: Delay advance 200 ns, full power (1.0)
    engine
        .add_ru_member(RuMemberProfile::new(1, 200, 1.0, 20.0, 0.0))
        .unwrap();

    // RU 2: Delay retardation -150 ns, half power (0.5)
    engine
        .add_ru_member(RuMemberProfile::new(2, -150, 0.5, 20.0, 0.0))
        .unwrap();

    let mut master_samples = [ComplexIq::default(); SUBCARRIERS_PER_PRB];
    master_samples[0] = ComplexIq::new(10.0, 6.0);

    let air_ts = 1_000_000u64;
    let distributed = engine
        .distribute_downlink_prb(0, 0, 0, 10, air_ts, &master_samples)
        .expect("Downlink distribution should succeed");

    assert_eq!(distributed.len(), 2);

    let pkt1 = distributed.iter().find(|p| p.ru_id == 1).unwrap();
    assert_eq!(pkt1.target_transmit_timestamp_ns, 1_000_000 - 200);
    assert!((pkt1.samples[0].i - 10.0).abs() < 1e-4);
    assert!((pkt1.samples[0].q - 6.0).abs() < 1e-4);

    let pkt2 = distributed.iter().find(|p| p.ru_id == 2).unwrap();
    assert_eq!(pkt2.target_transmit_timestamp_ns, 1_000_000 + 150);
    assert!((pkt2.samples[0].i - 5.0).abs() < 1e-4);
    assert!((pkt2.samples[0].q - 3.0).abs() < 1e-4);
}

#[test]
fn test_uplink_selection_combining() {
    let mut engine = SharedCellEngine::new(
        303,
        CombiningMode::SelectionCombining,
        DEFAULT_SKEW_TOLERANCE_NS,
    );

    // RU 1: 5 dB SNR, RU 2: 22 dB SNR (Best), RU 3: 12 dB SNR
    engine
        .add_ru_member(RuMemberProfile::new(1, 0, 1.0, 5.0, 0.0))
        .unwrap();
    engine
        .add_ru_member(RuMemberProfile::new(2, 0, 1.0, 22.0, 0.0))
        .unwrap();
    engine
        .add_ru_member(RuMemberProfile::new(3, 0, 1.0, 12.0, 0.0))
        .unwrap();

    let mut s1 = [ComplexIq::default(); SUBCARRIERS_PER_PRB];
    s1[0] = ComplexIq::new(1.0, 1.0);
    let mut s2 = [ComplexIq::default(); SUBCARRIERS_PER_PRB];
    s2[0] = ComplexIq::new(20.0, 20.0);
    let mut s3 = [ComplexIq::default(); SUBCARRIERS_PER_PRB];
    s3[0] = ComplexIq::new(10.0, 10.0);

    let packets = vec![
        RuPrbPacket {
            ru_id: 1,
            subframe: 0,
            slot: 0,
            symbol: 0,
            prb_idx: 0,
            arrival_timestamp_ns: 100_000,
            samples: s1,
        },
        RuPrbPacket {
            ru_id: 2,
            subframe: 0,
            slot: 0,
            symbol: 0,
            prb_idx: 0,
            arrival_timestamp_ns: 100_200,
            samples: s2,
        },
        RuPrbPacket {
            ru_id: 3,
            subframe: 0,
            slot: 0,
            symbol: 0,
            prb_idx: 0,
            arrival_timestamp_ns: 100_150,
            samples: s3,
        },
    ];

    let combined = engine
        .aggregate_uplink_prb(&packets)
        .expect("Selection combining should succeed");

    // Must match RU 2 (highest SNR)
    assert!((combined[0].i - 20.0).abs() < 1e-4);
    assert!((combined[0].q - 20.0).abs() < 1e-4);
}

#[test]
fn test_uplink_equal_gain_combining_with_phase_alignment() {
    let mut engine = SharedCellEngine::new(
        404,
        CombiningMode::EqualGainCombining,
        DEFAULT_SKEW_TOLERANCE_NS,
    );

    let pi = std::f32::consts::PI;
    // RU 1: phase 0.0
    engine
        .add_ru_member(RuMemberProfile::new(1, 0, 1.0, 10.0, 0.0))
        .unwrap();
    // RU 2: phase offset +pi/2
    engine
        .add_ru_member(RuMemberProfile::new(2, 0, 1.0, 10.0, pi / 2.0))
        .unwrap();

    let mut s1 = [ComplexIq::default(); SUBCARRIERS_PER_PRB];
    s1[0] = ComplexIq::new(1.0, 0.0); // angle 0

    let mut s2 = [ComplexIq::default(); SUBCARRIERS_PER_PRB];
    s2[0] = ComplexIq::new(0.0, 1.0); // rotated by pi/2

    let packets = vec![
        RuPrbPacket {
            ru_id: 1,
            subframe: 0,
            slot: 0,
            symbol: 0,
            prb_idx: 0,
            arrival_timestamp_ns: 50_000,
            samples: s1,
        },
        RuPrbPacket {
            ru_id: 2,
            subframe: 0,
            slot: 0,
            symbol: 0,
            prb_idx: 0,
            arrival_timestamp_ns: 50_100,
            samples: s2,
        },
    ];

    let combined = engine.aggregate_uplink_prb(&packets).unwrap();

    // After co-phasing, both samples align along real axis: (1.0 + 1.0) / sqrt(2) = sqrt(2) ≈ 1.4142
    assert!((combined[0].i - std::f32::consts::SQRT_2).abs() < 1e-3);
    assert!(combined[0].q.abs() < 1e-3);
}

#[test]
fn test_uplink_maximum_ratio_combining() {
    let mut engine = SharedCellEngine::new(
        505,
        CombiningMode::MaximumRatioCombining,
        DEFAULT_SKEW_TOLERANCE_NS,
    );

    // RU 1: 10 dB SNR -> linear 10.0 (weight sqrt(10) ≈ 3.162)
    engine
        .add_ru_member(RuMemberProfile::new(1, 0, 1.0, 10.0, 0.0))
        .unwrap();
    // RU 2: 20 dB SNR -> linear 100.0 (weight sqrt(100) = 10.0)
    engine
        .add_ru_member(RuMemberProfile::new(2, 0, 1.0, 20.0, 0.0))
        .unwrap();

    let mut s1 = [ComplexIq::default(); SUBCARRIERS_PER_PRB];
    s1[0] = ComplexIq::new(1.0, 0.0);
    let mut s2 = [ComplexIq::default(); SUBCARRIERS_PER_PRB];
    s2[0] = ComplexIq::new(2.0, 0.0);

    let packets = vec![
        RuPrbPacket {
            ru_id: 1,
            subframe: 0,
            slot: 0,
            symbol: 0,
            prb_idx: 0,
            arrival_timestamp_ns: 10_000,
            samples: s1,
        },
        RuPrbPacket {
            ru_id: 2,
            subframe: 0,
            slot: 0,
            symbol: 0,
            prb_idx: 0,
            arrival_timestamp_ns: 10_050,
            samples: s2,
        },
    ];

    let combined = engine.aggregate_uplink_prb(&packets).unwrap();

    // Numerator = 3.162277 * 1.0 + 10.0 * 2.0 = 23.162277
    // Denominator = sqrt(10 + 100) = sqrt(110) ≈ 10.488088
    // Result = 23.162277 / 10.488088 ≈ 2.2084
    let expected = (10.0f32.sqrt() * 1.0 + 10.0 * 2.0) / 110.0f32.sqrt();
    assert!((combined[0].i - expected).abs() < 1e-3);
}

#[test]
fn test_skew_tolerance_violation_and_drop() {
    let mut engine = SharedCellEngine::new(
        606,
        CombiningMode::SelectionCombining,
        5_000, // 5 µs tolerance
    );

    engine
        .add_ru_member(RuMemberProfile::new(1, 0, 1.0, 10.0, 0.0))
        .unwrap();
    engine
        .add_ru_member(RuMemberProfile::new(2, 0, 1.0, 10.0, 0.0))
        .unwrap();

    let packets = vec![
        RuPrbPacket {
            ru_id: 1,
            subframe: 0,
            slot: 0,
            symbol: 0,
            prb_idx: 0,
            arrival_timestamp_ns: 100_000,
            samples: [ComplexIq::default(); SUBCARRIERS_PER_PRB],
        },
        RuPrbPacket {
            ru_id: 2,
            subframe: 0,
            slot: 0,
            symbol: 0,
            prb_idx: 0,
            arrival_timestamp_ns: 106_000, // 6000 ns skew > 5000 ns
            samples: [ComplexIq::default(); SUBCARRIERS_PER_PRB],
        },
    ];

    let res = engine.aggregate_uplink_prb(&packets);
    match res {
        Err(SharedCellError::SkewToleranceExceeded {
            arrival_skew_ns,
            max_ns,
        }) => {
            assert_eq!(arrival_skew_ns, 6_000);
            assert_eq!(max_ns, 5_000);
        }
        _ => panic!("Expected SkewToleranceExceeded, got {:?}", res),
    }

    assert_eq!(engine.metrics().dropped_packets_skew_violation, 2);
}

#[test]
fn test_shared_cell_error_display() {
    let err_ru = SharedCellError::InvalidRuCount(20);
    assert!(err_ru.to_string().contains("Invalid RU count 20"));

    let err_not_found = SharedCellError::RuNotFound(0xABCD);
    assert!(err_not_found.to_string().contains("0xABCD"));

    let err_skew = SharedCellError::SkewToleranceExceeded {
        arrival_skew_ns: 8000,
        max_ns: 5000,
    };
    assert!(err_skew.to_string().contains("exceeds tolerance 5000 ns"));

    let err_branches = SharedCellError::InsufficientBranches {
        available: 0,
        required: 1,
    };
    assert!(
        err_branches
            .to_string()
            .contains("Insufficient O-RU branches")
    );
}

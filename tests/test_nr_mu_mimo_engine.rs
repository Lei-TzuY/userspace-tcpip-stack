//! Integration tests for 3GPP Rel-18/19 Multi-User MIMO (MU-MIMO) Dynamic Pairing & Precoding Engine.

use toy_tcpip::nr_mu_mimo_engine::*;

#[test]
fn test_complex_number_math() {
    let a = Complex64::new(3.0, 4.0);
    assert_eq!(a.norm_sq(), 25.0);
    assert_eq!(a.abs(), 5.0);
    assert_eq!(a.conj(), Complex64::new(3.0, -4.0));

    let b = Complex64::new(1.0, -2.0);
    let sum = a.add(b);
    assert_eq!(sum, Complex64::new(4.0, 2.0));

    let diff = a.sub(b);
    assert_eq!(diff, Complex64::new(2.0, 6.0));

    // (3 + 4i) * (1 - 2i) = 3 - 6i + 4i - 8i^2 = 11 - 2i
    let prod = a.mul(b);
    assert_eq!(prod, Complex64::new(11.0, -2.0));

    // (11 - 2i) / (1 - 2i) should be (3 + 4i)
    let div = prod.div(b);
    assert!((div.re - 3.0).abs() < 1e-6);
    assert!((div.im - 4.0).abs() < 1e-6);

    let polar = Complex64::from_polar(2.0, std::f64::consts::PI / 2.0);
    assert!(polar.re.abs() < 1e-6);
    assert!((polar.im - 2.0).abs() < 1e-6);
}

#[test]
fn test_complex_matrix_inversion() {
    // 2x2 Identity
    let eye2 = vec![
        vec![Complex64::ONE, Complex64::ZERO],
        vec![Complex64::ZERO, Complex64::ONE],
    ];
    let inv_eye = invert_complex_matrix(&eye2).expect("eye2 inversion failed");
    assert_eq!(inv_eye, eye2);

    // 2x2 arbitrary invertible matrix: [[1, 2], [3, 4]]
    let mat = vec![
        vec![Complex64::new(1.0, 0.0), Complex64::new(2.0, 0.0)],
        vec![Complex64::new(3.0, 0.0), Complex64::new(4.0, 0.0)],
    ];
    let inv = invert_complex_matrix(&mat).expect("inversion failed");
    // Product mat * inv should be Identity
    let mut prod = vec![vec![Complex64::ZERO; 2]; 2];
    for i in 0..2 {
        for j in 0..2 {
            for k in 0..2 {
                prod[i][j] = prod[i][j].add(mat[i][k].mul(inv[k][j]));
            }
        }
    }
    assert!((prod[0][0].re - 1.0).abs() < 1e-6);
    assert!(prod[0][0].im.abs() < 1e-6);
    assert!(prod[0][1].re.abs() < 1e-6);
    assert!(prod[1][0].re.abs() < 1e-6);
    assert!((prod[1][1].re - 1.0).abs() < 1e-6);

    // Singular matrix check
    let singular = vec![
        vec![Complex64::new(1.0, 0.0), Complex64::new(2.0, 0.0)],
        vec![Complex64::new(2.0, 0.0), Complex64::new(4.0, 0.0)],
    ];
    assert!(invert_complex_matrix(&singular).is_err());
}

#[test]
fn test_semi_orthogonal_user_selection() {
    let engine = NrMuMimoEngine::new(4, DmrsConfigType::Type1);

    // 4 perfectly orthogonal users (canonical basis in C^4)
    let ue1 = UeChannelState {
        ue_id: 1,
        channel_vector: vec![Complex64::ONE, Complex64::ZERO, Complex64::ZERO, Complex64::ZERO],
        cqi: 15,
    };
    let ue2 = UeChannelState {
        ue_id: 2,
        channel_vector: vec![Complex64::ZERO, Complex64::ONE, Complex64::ZERO, Complex64::ZERO],
        cqi: 14,
    };
    let ue3 = UeChannelState {
        ue_id: 3,
        channel_vector: vec![Complex64::ZERO, Complex64::ZERO, Complex64::ONE, Complex64::ZERO],
        cqi: 13,
    };
    let ue4 = UeChannelState {
        ue_id: 4,
        channel_vector: vec![Complex64::ZERO, Complex64::ZERO, Complex64::ZERO, Complex64::ONE],
        cqi: 12,
    };
    // Collinear user to ue1 (should be discarded by SUS)
    let ue_collinear = UeChannelState {
        ue_id: 5,
        channel_vector: vec![Complex64::new(0.99, 0.0), Complex64::new(0.01, 0.0), Complex64::ZERO, Complex64::ZERO],
        cqi: 15,
    };

    let candidates = vec![ue1, ue_collinear, ue2, ue3, ue4];
    let selected = engine.select_semi_orthogonal_users(&candidates, 4).expect("SUS failed");

    // Must select 4 users and MUST NOT select candidate index 1 (collinear UE 5)
    assert_eq!(selected.len(), 4);
    assert!(!selected.contains(&1));
}

#[test]
fn test_zero_forcing_interference_nulling() {
    let engine = NrMuMimoEngine::new(4, DmrsConfigType::Type1);

    // Non-orthogonal channels
    let h1 = vec![
        Complex64::new(1.0, 0.5),
        Complex64::new(0.5, -0.2),
        Complex64::new(0.1, 0.8),
        Complex64::new(0.3, 0.1),
    ];
    let h2 = vec![
        Complex64::new(0.2, 0.9),
        Complex64::new(1.2, 0.1),
        Complex64::new(0.4, -0.6),
        Complex64::new(0.7, 0.3),
    ];

    let weights = engine
        .compute_precoding_weights(&[h1.clone(), h2.clone()], PrecodingScheme::ZeroForcing)
        .expect("ZF failed");

    assert_eq!(weights.len(), 2);
    let w1 = &weights[0];
    let w2 = &weights[1];

    // Normalized to unit norm
    assert!((complex_vector_norm(w1) - 1.0).abs() < 1e-6);
    assert!((complex_vector_norm(w2) - 1.0).abs() < 1e-6);

    // Inter-user interference check:
    // User 1 signal through User 2 precoder (h1^H * w2) should be approximately ZERO
    let cross_talk_12 = complex_vector_inner_product(&h1, w2).abs();
    assert!(cross_talk_12 < 1e-6, "Cross-talk 1->2 was {}, expected ~0", cross_talk_12);

    // User 2 signal through User 1 precoder (h2^H * w1) should be approximately ZERO
    let cross_talk_21 = complex_vector_inner_product(&h2, w1).abs();
    assert!(cross_talk_21 < 1e-6, "Cross-talk 2->1 was {}, expected ~0", cross_talk_21);
}

#[test]
fn test_regularized_zero_forcing_and_mrt() {
    let engine = NrMuMimoEngine::new(4, DmrsConfigType::Type1);
    let h1 = vec![Complex64::ONE, Complex64::ZERO, Complex64::ZERO, Complex64::ZERO];
    let h2 = vec![Complex64::ZERO, Complex64::ONE, Complex64::ZERO, Complex64::ZERO];

    let rzf_w = engine
        .compute_precoding_weights(&[h1.clone(), h2.clone()], PrecodingScheme::RegularizedZeroForcing)
        .expect("RZF failed");
    assert_eq!(rzf_w.len(), 2);
    assert!((complex_vector_norm(&rzf_w[0]) - 1.0).abs() < 1e-6);

    let mrt_w = engine
        .compute_precoding_weights(&[h1, h2], PrecodingScheme::MaximumRatioTransmission)
        .expect("MRT failed");
    assert_eq!(mrt_w.len(), 2);
    assert!((complex_vector_norm(&mrt_w[0]) - 1.0).abs() < 1e-6);
}

#[test]
fn test_mu_mimo_scheduling_capacity_gain() {
    let mut engine = NrMuMimoEngine::new(8, DmrsConfigType::Type1);

    // 4 mutually orthogonal users across 8 gNB antennas
    let mut candidates = Vec::new();
    for i in 0..4 {
        let mut ch = vec![Complex64::ZERO; 8];
        ch[i * 2] = Complex64::new(1.0, 0.2);
        ch[i * 2 + 1] = Complex64::new(0.5, -0.3);
        candidates.push(UeChannelState {
            ue_id: 100 + i as u32,
            channel_vector: ch,
            cqi: 15,
        });
    }

    let result = engine
        .schedule_mu_mimo_slot(&candidates, PrecodingScheme::ZeroForcing, 4)
        .expect("MU-MIMO scheduling failed");

    assert_eq!(result.paired_users.len(), 4);
    assert!(!result.fallback_to_su_mimo);

    // MU-MIMO sum-rate should deliver significant capacity gain (> 2.0x) over SU-MIMO
    assert!(result.capacity_gain_ratio > 2.0, "Capacity gain was {}", result.capacity_gain_ratio);

    // Check orthogonal DMRS ports: 1000, 1001, 1002, 1003
    for (idx, user) in result.paired_users.iter().enumerate() {
        assert_eq!(user.dmrs_port, 1000 + idx as u16);
        assert_eq!(user.cdm_group, (idx / 4) as u8);
        assert!(user.sinr_db > 15.0);
        assert!(user.throughput_mbps > 50.0);
    }

    // Telemetry checks
    let tel = engine.telemetry();
    assert_eq!(tel.total_scheduling_slots, 1);
    assert_eq!(tel.total_paired_users_served, 4);
    assert_eq!(tel.su_mimo_fallbacks, 0);
    assert!(tel.average_capacity_gain() > 2.0);
}

#[test]
fn test_mu_mimo_fallback_on_collinear_users() {
    let mut engine = NrMuMimoEngine::new(4, DmrsConfigType::Type1);

    // 3 completely collinear users
    let base_ch = vec![Complex64::ONE, Complex64::new(0.5, 0.5), Complex64::ZERO, Complex64::ZERO];
    let candidates = vec![
        UeChannelState { ue_id: 1, channel_vector: base_ch.clone(), cqi: 10 },
        UeChannelState { ue_id: 2, channel_vector: base_ch.clone(), cqi: 10 },
        UeChannelState { ue_id: 3, channel_vector: base_ch, cqi: 10 },
    ];

    let result = engine
        .schedule_mu_mimo_slot(&candidates, PrecodingScheme::ZeroForcing, 4)
        .expect("scheduling failed");

    // SUS should only select 1 user because all others are 100% correlated
    assert_eq!(result.paired_users.len(), 1);
    assert!(result.fallback_to_su_mimo);
    assert_eq!(engine.telemetry().su_mimo_fallbacks, 1);
}

#[test]
fn test_grant_wire_codec_and_crc() {
    let allocations = vec![
        PairedUeAllocation {
            ue_id: 501,
            dmrs_port: 1000,
            cdm_group: 0,
            allocated_power_watts: 10.0,
            sinr_db: 22.5,
            throughput_mbps: 185.0,
        },
        PairedUeAllocation {
            ue_id: 502,
            dmrs_port: 1001,
            cdm_group: 0,
            allocated_power_watts: 10.0,
            sinr_db: 20.0,
            throughput_mbps: 165.0,
        },
    ];

    let frame = MuMimoGrantFrame {
        cell_id: 42,
        slot_number: 108,
        prb_start: 0,
        prb_count: 51,
        precoding_scheme: PrecodingScheme::RegularizedZeroForcing,
        allocations,
    };

    let wire = frame.encode_wire();
    // Magic 'M', 'U', 'M', 0x12
    assert_eq!(wire[0], 0x4D);
    assert_eq!(wire[1], 0x55);
    assert_eq!(wire[2], 0x4D);
    assert_eq!(wire[3], 0x12);

    let decoded = MuMimoGrantFrame::decode_wire(&wire).expect("grant decode failed");
    assert_eq!(decoded.cell_id, 42);
    assert_eq!(decoded.slot_number, 108);
    assert_eq!(decoded.prb_start, 0);
    assert_eq!(decoded.prb_count, 51);
    assert_eq!(decoded.precoding_scheme, PrecodingScheme::RegularizedZeroForcing);
    assert_eq!(decoded.allocations.len(), 2);
    assert_eq!(decoded.allocations[0].ue_id, 501);
    assert_eq!(decoded.allocations[1].ue_id, 502);

    // Corrupt CRC
    let mut bad_wire = wire.clone();
    let l = bad_wire.len() - 1;
    bad_wire[l] ^= 0x55;
    assert!(matches!(
        MuMimoGrantFrame::decode_wire(&bad_wire),
        Err(MuMimoError::ChecksumMismatch { .. })
    ));

    // Corrupt Magic
    let mut bad_magic = wire.clone();
    bad_magic[0] = 0x00;
    let new_crc = compute_crc16(&bad_magic[..bad_magic.len() - 2]);
    let len = bad_magic.len();
    bad_magic[len - 2..len].copy_from_slice(&new_crc.to_be_bytes());
    assert!(matches!(
        MuMimoGrantFrame::decode_wire(&bad_magic),
        Err(MuMimoError::DeserializationError(msg)) if msg.contains("magic")
    ));

    // Truncated buffer
    assert!(MuMimoGrantFrame::decode_wire(&[0x4D, 0x55, 0x4D]).is_err());
}

#[test]
fn test_error_display() {
    let err1 = MuMimoError::InsufficientAntennas {
        required: 8,
        available: 4,
    };
    assert!(format!("{}", err1).contains("insufficient"));

    let err2 = MuMimoError::InvalidPrecodingScheme(99);
    assert!(format!("{}", err2).contains("99"));
}

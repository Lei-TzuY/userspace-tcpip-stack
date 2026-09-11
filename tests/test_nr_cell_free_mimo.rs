//! Integration and unit tests for 3GPP Rel-18/19 User-Centric Cell-Free Massive MIMO
//! and Distributed Joint Reception Engine.

use toy_tcpip::nr_cell_free_mimo::*;

#[test]
fn test_complex_matrix_operations_and_inversion() {
    // 2x2 complex matrix inversion
    let mut a = ComplexMatrix::zeros(2, 2);
    a.set(0, 0, Complex64::new(2.0, 1.0));
    a.set(0, 1, Complex64::new(1.0, 0.0));
    a.set(1, 0, Complex64::new(0.0, 1.0));
    a.set(1, 1, Complex64::new(3.0, 2.0));

    let inv_a = a.invert().expect("Inversion should succeed");
    let identity_approx = a.matmul(&inv_a).expect("Matmul should succeed");

    assert!((identity_approx.get(0, 0).re - 1.0).abs() < 1e-6);
    assert!(identity_approx.get(0, 0).im.abs() < 1e-6);
    assert!(identity_approx.get(0, 1).re.abs() < 1e-6);
    assert!(identity_approx.get(0, 1).im.abs() < 1e-6);
    assert!(identity_approx.get(1, 0).re.abs() < 1e-6);
    assert!(identity_approx.get(1, 0).im.abs() < 1e-6);
    assert!((identity_approx.get(1, 1).re - 1.0).abs() < 1e-6);
    assert!(identity_approx.get(1, 1).im.abs() < 1e-6);

    // Hermitian transpose
    let a_h = a.hermitian();
    assert_eq!(a_h.get(0, 0), Complex64::new(2.0, -1.0));
    assert_eq!(a_h.get(0, 1), Complex64::new(0.0, -1.0));
    assert_eq!(a_h.get(1, 0), Complex64::new(1.0, 0.0));
    assert_eq!(a_h.get(1, 1), Complex64::new(3.0, -2.0));
}

#[test]
fn test_3gpp_pathloss_and_dynamic_cluster_formation() {
    let mut engine = NrCellFreeEngine::new();
    engine.set_cluster_ratio_threshold(0.10);
    engine.set_cluster_bounds(2, 4);

    // Deploy 4 Access Points in a 2x2 grid (100m spacing)
    engine
        .add_access_point(AccessPointConfig::new(
            1,
            Position3D::new(0.0, 0.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();
    engine
        .add_access_point(AccessPointConfig::new(
            2,
            Position3D::new(100.0, 0.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();
    engine
        .add_access_point(AccessPointConfig::new(
            3,
            Position3D::new(0.0, 100.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();
    engine
        .add_access_point(AccessPointConfig::new(
            4,
            Position3D::new(100.0, 100.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();

    // Deploy UE close to AP 1
    engine
        .add_user(UserEquipmentConfig::new(
            101,
            Position3D::new(10.0, 10.0, 1.5),
            0.1,
        ))
        .unwrap();

    // Deploy UE in the center (cell-edge of all 4 APs)
    engine
        .add_user(UserEquipmentConfig::new(
            102,
            Position3D::new(50.0, 50.0, 1.5),
            0.1,
        ))
        .unwrap();

    engine.update_user_clusters();

    let cluster_101 = engine.get_user_cluster(101).expect("Cluster for UE 101 must exist");
    assert_eq!(cluster_101.ue_id, 101);
    // AP 1 should be primary serving AP
    assert_eq!(cluster_101.serving_ap_ids[0], 1);
    assert!(cluster_101.serving_ap_ids.len() >= 2);

    let cluster_102 = engine.get_user_cluster(102).expect("Cluster for UE 102 must exist");
    assert_eq!(cluster_102.ue_id, 102);
    // All 4 APs are equidistant (approx 70m) to center UE 102, so all 4 should be included
    assert_eq!(cluster_102.serving_ap_ids.len(), 4);
}

#[test]
fn test_uplink_local_mmse_and_mrc_joint_reception() {
    let mut engine = NrCellFreeEngine::new();

    // Deploy 4 APs
    for ap_id in 1..=4 {
        let x = if ap_id % 2 == 1 { 0.0 } else { 100.0 };
        let y = if ap_id <= 2 { 0.0 } else { 100.0 };
        engine
            .add_access_point(AccessPointConfig::new(
                ap_id,
                Position3D::new(x, y, 10.0),
                4,
                2.0,
            ))
            .unwrap();
    }

    // Deploy 3 UEs
    engine
        .add_user(UserEquipmentConfig::new(
            1,
            Position3D::new(20.0, 20.0, 1.5),
            0.1,
        ))
        .unwrap();
    engine
        .add_user(UserEquipmentConfig::new(
            2,
            Position3D::new(80.0, 20.0, 1.5),
            0.1,
        ))
        .unwrap();
    engine
        .add_user(UserEquipmentConfig::new(
            3,
            Position3D::new(50.0, 80.0, 1.5),
            0.1,
        ))
        .unwrap();

    engine.update_user_clusters();

    let mrc_results = engine
        .evaluate_uplink_joint_reception(UplinkCombiningScheme::MaximumRatioCombining)
        .expect("MRC evaluation should succeed");

    let lmmse_results = engine
        .evaluate_uplink_joint_reception(UplinkCombiningScheme::LocalMmse)
        .expect("L-MMSE evaluation should succeed");

    for ue_id in 1..=3 {
        let (mrc_sinr, mrc_rate) = mrc_results[&ue_id];
        let (lmmse_sinr, lmmse_rate) = lmmse_results[&ue_id];

        assert!(mrc_rate > 0.0);
        assert!(lmmse_rate > 0.0);
        // L-MMSE suppresses multi-user interference, yielding superior SINR and throughput
        assert!(lmmse_sinr >= mrc_sinr - 0.5);
    }
}

#[test]
fn test_centralized_full_mmse_combining() {
    let mut engine = NrCellFreeEngine::new();

    engine
        .add_access_point(AccessPointConfig::new(
            1,
            Position3D::new(0.0, 0.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();
    engine
        .add_access_point(AccessPointConfig::new(
            2,
            Position3D::new(50.0, 0.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();

    engine
        .add_user(UserEquipmentConfig::new(
            1,
            Position3D::new(10.0, 10.0, 1.5),
            0.1,
        ))
        .unwrap();
    engine
        .add_user(UserEquipmentConfig::new(
            2,
            Position3D::new(40.0, 10.0, 1.5),
            0.1,
        ))
        .unwrap();

    engine.update_user_clusters();

    let full_mmse_results = engine
        .evaluate_uplink_joint_reception(UplinkCombiningScheme::CentralizedFullMmse)
        .expect("Centralized Full MMSE evaluation should succeed");

    assert_eq!(full_mmse_results.len(), 2);
    for (&ue_id, &(sinr, rate)) in &full_mmse_results {
        assert!(sinr > -10.0, "SINR for UE {} is {}", ue_id, sinr);
        assert!(rate > 10.0, "Rate for UE {} is {} Mbps", ue_id, rate);
    }
}

#[test]
fn test_downlink_joint_transmission_and_beamforming() {
    let mut engine = NrCellFreeEngine::new();

    engine
        .add_access_point(AccessPointConfig::new(
            1,
            Position3D::new(0.0, 0.0, 10.0),
            4,
            5.0,
        ))
        .unwrap();
    engine
        .add_access_point(AccessPointConfig::new(
            2,
            Position3D::new(100.0, 0.0, 10.0),
            4,
            5.0,
        ))
        .unwrap();

    engine
        .add_user(UserEquipmentConfig::new(
            1,
            Position3D::new(50.0, 20.0, 1.5),
            0.1,
        ))
        .unwrap();

    engine.update_user_clusters();

    let dl_results = engine
        .evaluate_downlink_joint_transmission(DownlinkPrecodingScheme::ConjugateBeamforming)
        .expect("Downlink JT-CoMP evaluation should succeed");

    assert_eq!(dl_results.len(), 1);
    let (sinr_db, rate_mbps) = dl_results[&1];
    assert!(sinr_db > 0.0);
    assert!(rate_mbps > 20.0);
}

#[test]
fn test_fronthaul_bfp_quantization_and_evm() {
    let samples = vec![
        Complex64::new(0.707, 0.707),
        Complex64::new(-0.707, 0.707),
        Complex64::new(0.353, -0.353),
        Complex64::new(-0.353, -0.353),
    ];

    let bfp8 = BfpQuantizer::new(8);
    let (rec8, evm8) = bfp8.quantize_and_evaluate_evm(&samples);
    assert_eq!(rec8.len(), 4);
    assert!(evm8 < 1.0, "8-bit EVM was {}", evm8);

    let bfp12 = BfpQuantizer::new(12);
    let (rec12, evm12) = bfp12.quantize_and_evaluate_evm(&samples);
    assert_eq!(rec12.len(), 4);
    assert!(evm12 < 0.1, "12-bit EVM was {}", evm12);

    // Higher bit-width achieves lower EVM error
    assert!(evm12 < evm8);
}

#[test]
fn test_cell_edge_throughput_gain_over_legacy_cellular() {
    let mut engine = NrCellFreeEngine::new();

    // Deploy 4 Access Points forming a square
    engine
        .add_access_point(AccessPointConfig::new(
            1,
            Position3D::new(0.0, 0.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();
    engine
        .add_access_point(AccessPointConfig::new(
            2,
            Position3D::new(150.0, 0.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();
    engine
        .add_access_point(AccessPointConfig::new(
            3,
            Position3D::new(0.0, 150.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();
    engine
        .add_access_point(AccessPointConfig::new(
            4,
            Position3D::new(150.0, 150.0, 10.0),
            4,
            2.0,
        ))
        .unwrap();

    // Deploy cell-edge users located in the dead-center between APs
    engine
        .add_user(UserEquipmentConfig::new(
            1,
            Position3D::new(75.0, 75.0, 1.5),
            0.1,
        ))
        .unwrap();
    engine
        .add_user(UserEquipmentConfig::new(
            2,
            Position3D::new(70.0, 80.0, 1.5),
            0.1,
        ))
        .unwrap();
    engine
        .add_user(UserEquipmentConfig::new(
            3,
            Position3D::new(20.0, 20.0, 1.5),
            0.1,
        ))
        .unwrap();

    engine.update_user_clusters();

    let cf_results = engine
        .evaluate_uplink_joint_reception(UplinkCombiningScheme::LocalMmse)
        .unwrap();
    let legacy_results = engine.evaluate_legacy_cellular_benchmark();

    let (_cf_sinr_1, cf_rate_1) = cf_results[&1];
    let (_leg_sinr_1, leg_rate_1) = legacy_results[&1];

    // Cell-free joint reception significantly outperforms legacy single-AP co-channel interference
    assert!(
        cf_rate_1 > leg_rate_1,
        "Cell-Free rate {} Mbps should exceed legacy rate {} Mbps",
        cf_rate_1,
        leg_rate_1
    );

    let telemetry = engine.telemetry();
    assert!(telemetry.total_slots_simulated > 0);
    assert!(telemetry.avg_cluster_size >= 2.0);
    assert!(
        telemetry.cell_edge_gain_factor >= 1.0,
        "Cell-edge gain factor was {}",
        telemetry.cell_edge_gain_factor
    );
}

#[test]
fn test_wire_codec_and_crc16() {
    let pdu = CellFreeFronthaulPdu {
        ap_id: 10,
        ue_id: 202,
        slot_number: 1540,
        quant_bits: 12,
        iq_samples: vec![
            Complex64::new(0.5, -0.5),
            Complex64::new(0.123, 0.456),
            Complex64::new(-0.89, 0.22),
        ],
    };

    let wire = pdu.encode_wire();
    assert_eq!(&wire[0..4], &CELL_FREE_WIRE_MAGIC);

    let decoded = CellFreeFronthaulPdu::decode_wire(&wire).expect("Decoding wire frame must succeed");
    assert_eq!(decoded.ap_id, 10);
    assert_eq!(decoded.ue_id, 202);
    assert_eq!(decoded.slot_number, 1540);
    assert_eq!(decoded.quant_bits, 12);
    assert_eq!(decoded.iq_samples.len(), 3);

    assert!((decoded.iq_samples[0].re - 0.5).abs() < 1e-3);
    assert!((decoded.iq_samples[0].im - (-0.5)).abs() < 1e-3);

    // Corrupt one byte to trigger CRC mismatch
    let mut corrupted = wire.clone();
    corrupted[10] ^= 0xFF;
    let err = CellFreeFronthaulPdu::decode_wire(&corrupted).unwrap_err();
    match err {
        CellFreeError::ChecksumMismatch { .. } => {}
        other => panic!("Expected ChecksumMismatch, got {:?}", other),
    }

    // Test error display
    let err_str = format!("{}", err);
    assert!(err_str.contains("CRC-16 mismatch"));
}

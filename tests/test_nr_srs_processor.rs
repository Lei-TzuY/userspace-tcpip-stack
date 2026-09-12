//! Integration tests for 3GPP Rel-18/19 SRS Processor, Antenna Switching & Channel Sounding Engine.

use toy_tcpip::nr_srs_processor::{
    AntennaSwitchingMode, Complex64, SRS_WIRE_MAGIC, SrsAntennaManager, SrsFrequencyHoppingConfig,
    SrsTransmissionComb, SrsWirePdu, calculate_srs_hopping_index, generate_zc_srs_sequence,
    get_srs_bandwidth_entry, largest_prime_less_than, map_srs_to_subcarriers,
};

#[test]
fn test_largest_prime_less_than() {
    assert_eq!(largest_prime_less_than(36), 31);
    assert_eq!(largest_prime_less_than(48), 47);
    assert_eq!(largest_prime_less_than(72), 71);
    assert_eq!(largest_prime_less_than(96), 89);
    assert_eq!(largest_prime_less_than(144), 139);
}

#[test]
fn test_srs_zadoff_chu_sequence_generation_and_unit_power() {
    let m_sc = 72; // e.g. 24 PRBs with Comb-4: 24 * 12 / 4 = 72
    let seq = generate_zc_srs_sequence(m_sc, 5, 0, 0, 12).unwrap();

    assert_eq!(seq.len(), m_sc);

    // Verify constant modulus (unit power) on all subcarriers
    for sym in &seq {
        let pwr = sym.norm_sqr();
        assert!((pwr - 1.0).abs() < 1e-6, "Power should be 1.0, got {}", pwr);
    }
}

#[test]
fn test_srs_cyclic_shift_orthogonality() {
    let m_sc = 72;
    let max_cs = 12;

    // CS = 0 vs CS = 3
    let seq0 = generate_zc_srs_sequence(m_sc, 0, 0, 0, max_cs).unwrap();
    let seq3 = generate_zc_srs_sequence(m_sc, 0, 0, 3, max_cs).unwrap();

    // Auto-correlation
    let mut auto_corr = Complex64::new(0.0, 0.0);
    for sym in &seq0 {
        let prod = sym.mul(&sym.conj());
        auto_corr.re += prod.re;
        auto_corr.im += prod.im;
    }
    assert!((auto_corr.re - m_sc as f64).abs() < 1e-5);
    assert!(auto_corr.im.abs() < 1e-5);

    // Cross-correlation between different cyclic shifts
    let mut cross_corr = Complex64::new(0.0, 0.0);
    for (a, b) in seq0.iter().zip(seq3.iter()) {
        let prod = a.mul(&b.conj());
        cross_corr.re += prod.re;
        cross_corr.im += prod.im;
    }

    let cross_mag = cross_corr.norm_sqr().sqrt();
    assert!(
        cross_mag < 1e-4,
        "Cyclic shifts must be strictly orthogonal, cross_mag = {}",
        cross_mag
    );
}

#[test]
fn test_srs_cglps_short_sequence_generation() {
    for &m_sc in &[6, 12, 18, 24] {
        let seq = generate_zc_srs_sequence(m_sc, 0, 0, 1, 8).unwrap();
        assert_eq!(seq.len(), m_sc);
        for sym in &seq {
            let pwr = sym.norm_sqr();
            assert!((pwr - 1.0).abs() < 1e-6);
        }
    }
}

#[test]
fn test_srs_transmission_comb2_comb4_comb8_mapping() {
    let seq = generate_zc_srs_sequence(12, 0, 0, 0, 8).unwrap();

    // Comb-2 with offset 1
    let mapped_comb2 = map_srs_to_subcarriers(&seq, SrsTransmissionComb::Comb2, 1, 0, 100).unwrap();
    assert_eq!(mapped_comb2.len(), 12);
    assert_eq!(mapped_comb2[0].0, 1);
    assert_eq!(mapped_comb2[1].0, 3);
    assert_eq!(mapped_comb2[2].0, 5);

    // Comb-4 with offset 2
    let mapped_comb4 = map_srs_to_subcarriers(&seq, SrsTransmissionComb::Comb4, 2, 0, 100).unwrap();
    assert_eq!(mapped_comb4.len(), 12);
    assert_eq!(mapped_comb4[0].0, 2);
    assert_eq!(mapped_comb4[1].0, 6);
    assert_eq!(mapped_comb4[2].0, 10);

    // Comb-8 with offset 5
    let mapped_comb8 = map_srs_to_subcarriers(&seq, SrsTransmissionComb::Comb8, 5, 0, 100).unwrap();
    assert_eq!(mapped_comb8.len(), 12);
    assert_eq!(mapped_comb8[0].0, 5);
    assert_eq!(mapped_comb8[1].0, 13);
    assert_eq!(mapped_comb8[2].0, 21);

    // Invalid comb offset rejected
    assert!(map_srs_to_subcarriers(&seq, SrsTransmissionComb::Comb4, 4, 0, 100).is_err());
}

#[test]
fn test_srs_bandwidth_tree_and_frequency_hopping_pattern() {
    let entry = get_srs_bandwidth_entry(0).unwrap();
    assert_eq!(entry.m_srs, [96, 48, 24, 4]);
    assert_eq!(entry.n_b, [1, 2, 2, 6]);

    let cfg_no_hop = SrsFrequencyHoppingConfig {
        c_srs: 0,
        b_srs: 2,
        b_hop: 2, // b_hop >= b_srs -> no hopping
        n_rrc: 0,
    };

    // Index is constant across transmission instances
    let idx0 = calculate_srs_hopping_index(&cfg_no_hop, 2, 0).unwrap();
    let idx1 = calculate_srs_hopping_index(&cfg_no_hop, 2, 1).unwrap();
    let idx2 = calculate_srs_hopping_index(&cfg_no_hop, 2, 2).unwrap();
    assert_eq!(idx0, idx1);
    assert_eq!(idx1, idx2);

    // Hopping enabled: b_srs = 2, b_hop = 0
    let cfg_hop = SrsFrequencyHoppingConfig {
        c_srs: 0,
        b_srs: 2,
        b_hop: 0,
        n_rrc: 0,
    };

    let h0 = calculate_srs_hopping_index(&cfg_hop, 2, 0).unwrap();
    let h1 = calculate_srs_hopping_index(&cfg_hop, 2, 1).unwrap();
    // N_2 = 2 branches, hopping alternates or advances
    assert!(h0 < 2);
    assert!(h1 < 2);
}

#[test]
fn test_srs_antenna_switching_1t4r_and_reciprocity_estimation() {
    let manager = SrsAntennaManager::new(AntennaSwitchingMode::OneTxFourRx);

    // Verify 1T4R 4-slot antenna cycling: [0] -> [1] -> [2] -> [3] -> [0]
    assert_eq!(manager.active_antennas_for_instance(0), vec![0]);
    assert_eq!(manager.active_antennas_for_instance(1), vec![1]);
    assert_eq!(manager.active_antennas_for_instance(2), vec![2]);
    assert_eq!(manager.active_antennas_for_instance(3), vec![3]);
    assert_eq!(manager.active_antennas_for_instance(4), vec![0]);

    // 2T4R cycling
    let manager_2t4r = SrsAntennaManager::new(AntennaSwitchingMode::TwoTxFourRx);
    assert_eq!(manager_2t4r.active_antennas_for_instance(0), vec![0, 1]);
    assert_eq!(manager_2t4r.active_antennas_for_instance(1), vec![2, 3]);
    assert_eq!(manager_2t4r.active_antennas_for_instance(2), vec![0, 1]);

    // Channel estimation validation
    let tx = vec![(0, Complex64::new(1.0, 0.0)), (4, Complex64::new(0.0, 1.0))];
    // Channel H = 0.5 + j0.2
    let channel_h = Complex64::new(0.5, 0.2);
    let rx = vec![(0, tx[0].1.mul(&channel_h)), (4, tx[1].1.mul(&channel_h))];

    let estimated_cfr = manager.estimate_channel(&rx, &tx);
    assert_eq!(estimated_cfr.len(), 2);
    assert!((estimated_cfr[0].1.re - 0.5).abs() < 1e-6);
    assert!((estimated_cfr[0].1.im - 0.2).abs() < 1e-6);

    let power_dbm = manager.compute_channel_power_dbm(&estimated_cfr);
    assert!(power_dbm > -140.0);
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = SrsWirePdu {
        magic: SRS_WIRE_MAGIC,
        srs_instance: 105,
        c_srs: 7,
        b_srs: 2,
        b_hop: 1,
        comb_size: 4,
        comb_offset: 2,
        cyclic_shift: 5,
        antenna_port: 1,
        start_prb: 12,
        num_prb: 24,
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0xAA],
        crc16: 0,
    };

    let serialized = pdu.serialize();
    assert_eq!(&serialized[..4], &[0x53, 0x52, 0x53, 0x50]); // "SRSP"

    // Successful deserialization
    let deserialized = SrsWirePdu::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.srs_instance, 105);
    assert_eq!(deserialized.c_srs, 7);
    assert_eq!(deserialized.antenna_port, 1);
    assert_eq!(deserialized.payload, pdu.payload);

    // Tampered payload fails CRC
    let mut corrupted = serialized.clone();
    corrupted[22] ^= 0xFF;
    assert!(SrsWirePdu::deserialize(&corrupted).is_err());
}

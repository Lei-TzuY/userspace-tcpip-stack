//! Integration tests for 3GPP Rel-18/19 PRACH Receiver & Timing Advance Engine.

use toy_tcpip::nr_prach_receiver::{
    apply_cyclic_shift, calculate_cyclic_shifts, generate_64_preamble_bank,
    generate_base_zadoff_chu, synthesize_prach_waveform, Complex64, PrachDetector,
    PrachFormat, PrachReceiverConfig, PrachWirePdu, RestrictedSetConfig, PRACH_WIRE_MAGIC,
    PREAMBLES_PER_CELL,
};

#[test]
fn test_prach_zadoff_chu_sequence_generation_and_unit_power() {
    // Short sequence (L_RA = 139)
    let seq_short = generate_base_zadoff_chu(1, 139);
    assert_eq!(seq_short.len(), 139);
    for sym in &seq_short {
        let pwr = sym.norm_sqr();
        assert!((pwr - 1.0).abs() < 1e-6);
    }

    // Long sequence (L_RA = 839)
    let seq_long = generate_base_zadoff_chu(5, 839);
    assert_eq!(seq_long.len(), 839);
    for sym in &seq_long {
        let pwr = sym.norm_sqr();
        assert!((pwr - 1.0).abs() < 1e-6);
    }
}

#[test]
fn test_prach_cyclic_shift_unrestricted_and_restricted_set() {
    let l_ra = 139;
    let n_cs = 13;

    // Unrestricted set: 139 / 13 = 10 shifts
    let shifts_unrest = calculate_cyclic_shifts(l_ra, n_cs, RestrictedSetConfig::UnrestrictedSet).unwrap();
    assert_eq!(shifts_unrest.len(), 10);
    assert_eq!(shifts_unrest[0], 0);
    assert_eq!(shifts_unrest[1], 13);
    assert_eq!(shifts_unrest[2], 26);
    assert_eq!(shifts_unrest[9], 117);

    // Restricted set: wider spacing
    let shifts_rest = calculate_cyclic_shifts(l_ra, n_cs, RestrictedSetConfig::RestrictedSetTypeA).unwrap();
    assert_eq!(shifts_rest.len(), 5);
    assert_eq!(shifts_rest[0], 0);
    assert_eq!(shifts_rest[1], 26);

    // N_CS = 0 => 1 single shift of 0
    let zero_cs = calculate_cyclic_shifts(l_ra, 0, RestrictedSetConfig::UnrestrictedSet).unwrap();
    assert_eq!(zero_cs, vec![0]);

    // Invalid N_CS >= L_RA
    assert!(calculate_cyclic_shifts(l_ra, 140, RestrictedSetConfig::UnrestrictedSet).is_err());
}

#[test]
fn test_prach_64_preamble_bank_multi_root_expansion() {
    let l_ra = 139;
    let n_cs = 13; // 10 preambles per root
    let bank = generate_64_preamble_bank(1, l_ra, n_cs, RestrictedSetConfig::UnrestrictedSet).unwrap();

    assert_eq!(bank.len(), PREAMBLES_PER_CELL); // Exactly 64

    // First 10 preambles from root 1
    for i in 0..10 {
        assert_eq!(bank[i].preamble_index, i);
        assert_eq!(bank[i].root_index, 1);
        assert_eq!(bank[i].cyclic_shift, i * 13);
    }

    // Next 10 preambles from root 2
    for i in 10..20 {
        assert_eq!(bank[i].preamble_index, i);
        assert_eq!(bank[i].root_index, 2);
        assert_eq!(bank[i].cyclic_shift, (i - 10) * 13);
    }

    // Preamble 63 comes from root 7
    assert_eq!(bank[63].preamble_index, 63);
    assert_eq!(bank[63].root_index, 7);
    assert_eq!(bank[63].cyclic_shift, 3 * 13);
}

#[test]
fn test_prach_waveform_synthesis_with_cyclic_prefix() {
    let base_seq = generate_base_zadoff_chu(1, 139);
    let waveform = synthesize_prach_waveform(&base_seq, 26, PrachFormat::FormatA1);

    // Format A1: N_CP = 288, N_seq = 2 repetitions
    let expected_len = 288 + 2 * 139;
    assert_eq!(waveform.len(), expected_len);

    // Verify cyclic prefix integrity: waveform[0] matches tail of sequence
    let shifted = apply_cyclic_shift(&base_seq, 26);
    let cp_start_idx = (139 - (288 % 139)) % 139;
    assert_eq!(waveform[0], shifted[cp_start_idx]);
}

#[test]
fn test_prach_matched_filter_single_preamble_detection_and_ta_extraction() {
    let cfg = PrachReceiverConfig {
        format: PrachFormat::FormatA1,
        starting_root: 1,
        n_cs: 13,
        restricted_set: RestrictedSetConfig::UnrestrictedSet,
        detection_threshold_db: 9.0,
        ta_scale_factor: 16.0,
    };

    let detector = PrachDetector::new(cfg).unwrap();
    let l_ra = 139;

    // Transmit preamble index 2 (root 1, C_v = 2 * 13 = 26)
    let base_zc = generate_base_zadoff_chu(1, l_ra);
    let tx = apply_cyclic_shift(&base_zc, 26);

    // Channel delay = 4 samples
    let delay = 4;
    let mut rx = vec![Complex64::new(0.0, 0.0); l_ra];
    for n in 0..l_ra {
        let src = (n + l_ra - delay) % l_ra;
        rx[n] = tx[src];
    }

    let detected = detector.detect_preambles(&rx);
    assert_eq!(detected.len(), 1, "Exactly 1 preamble should be detected");

    let p = &detected[0];
    assert_eq!(p.preamble_index, 2);
    assert_eq!(p.root_index, 1);
    assert_eq!(p.cyclic_shift, 26);
    assert_eq!(p.estimated_delay_samples, 4.0);
    assert_eq!(p.timing_advance_index, 64); // 4 * 16 = 64
    assert!(p.pnr_db > 15.0);
}

#[test]
fn test_prach_multi_preamble_simultaneous_detection() {
    let cfg = PrachReceiverConfig {
        format: PrachFormat::FormatA1,
        starting_root: 1,
        n_cs: 13,
        restricted_set: RestrictedSetConfig::UnrestrictedSet,
        detection_threshold_db: 9.0,
        ta_scale_factor: 16.0,
    };

    let detector = PrachDetector::new(cfg).unwrap();
    let l_ra = 139;
    let base_zc = generate_base_zadoff_chu(1, l_ra);

    // UE 1: Preamble 1 (C_v = 13, delay = 2)
    let tx1 = apply_cyclic_shift(&base_zc, 13);
    // UE 2: Preamble 4 (C_v = 52, delay = 5)
    let tx2 = apply_cyclic_shift(&base_zc, 52);

    let mut rx = vec![Complex64::new(0.0, 0.0); l_ra];
    for n in 0..l_ra {
        let src1 = (n + l_ra - 2) % l_ra;
        let src2 = (n + l_ra - 5) % l_ra;
        rx[n] = tx1[src1].add(&tx2[src2]);
    }

    let detected = detector.detect_preambles(&rx);
    assert_eq!(detected.len(), 2, "Both preambles must be detected simultaneously");

    let preambles: Vec<usize> = detected.iter().map(|d| d.preamble_index).collect();
    assert!(preambles.contains(&1));
    assert!(preambles.contains(&4));

    for d in &detected {
        if d.preamble_index == 1 {
            assert_eq!(d.estimated_delay_samples, 2.0);
            assert_eq!(d.timing_advance_index, 32); // 2 * 16 = 32
        } else if d.preamble_index == 4 {
            assert_eq!(d.estimated_delay_samples, 5.0);
            assert_eq!(d.timing_advance_index, 80); // 5 * 16 = 80
        }
    }
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = PrachWirePdu {
        magic: PRACH_WIRE_MAGIC,
        occasion_id: 880,
        preamble_index: 23,
        root_index: 3,
        cyclic_shift: 39,
        timing_advance: 64,
        pnr_q4: (18.5 * 16.0) as i16,
        payload: vec![0x11, 0x22, 0x33, 0x44],
        crc16: 0,
    };

    let serialized = pdu.serialize();
    assert_eq!(&serialized[..4], &[0x50, 0x52, 0x43, 0x48]); // "PRCH"

    // Successful deserialization
    let deserialized = PrachWirePdu::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.occasion_id, 880);
    assert_eq!(deserialized.preamble_index, 23);
    assert_eq!(deserialized.root_index, 3);
    assert_eq!(deserialized.cyclic_shift, 39);
    assert_eq!(deserialized.timing_advance, 64);
    assert_eq!(deserialized.payload, pdu.payload);

    // Tampered payload fails CRC
    let mut corrupted = serialized.clone();
    corrupted[19] ^= 0x01;
    assert!(PrachWirePdu::deserialize(&corrupted).is_err());
}

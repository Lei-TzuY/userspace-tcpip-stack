//! Integration tests for 3GPP Rel-18/19 SS/PBCH Block (SSB), MIB & Beam Sweeping Engine.

use toy_tcpip::nr_ssb_pbch::{
    generate_pbch_dmrs, generate_pss, generate_sss, PbchPayload, PhysicalCellId,
    SsbBeamMeasurement, SsbBurstManager, SsbCase, SsbLMax, SsbMib, SsbReType,
    SsbResourceGrid, SsbWirePdu, PBCH_TOTAL_DATA_RES, PBCH_TOTAL_DMRS_RES, SSB_NUM_SUBCARRIERS,
    SSB_WIRE_MAGIC, SYNC_SEQUENCE_LENGTH,
};

#[test]
fn test_physical_cell_id_decomposition_and_v_shift() {
    // Valid PCIs
    let pci0 = PhysicalCellId::new(0).unwrap();
    assert_eq!(pci0.n_id_1, 0);
    assert_eq!(pci0.n_id_2, 0);
    assert_eq!(pci0.v_shift(), 0);

    let pci500 = PhysicalCellId::new(500).unwrap();
    // 500 = 3 * 166 + 2
    assert_eq!(pci500.n_id_1, 166);
    assert_eq!(pci500.n_id_2, 2);
    assert_eq!(pci500.v_shift(), 0); // 500 % 4 == 0

    let pci1007 = PhysicalCellId::new(1007).unwrap();
    // 1007 = 3 * 335 + 2
    assert_eq!(pci1007.n_id_1, 335);
    assert_eq!(pci1007.n_id_2, 2);
    assert_eq!(pci1007.v_shift(), 3); // 1007 % 4 == 3

    // Reconstruction from components
    let reconstructed = PhysicalCellId::from_components(166, 2).unwrap();
    assert_eq!(reconstructed.pci, 500);

    // Invalid PCIs
    assert!(PhysicalCellId::new(1008).is_err());
    assert!(PhysicalCellId::from_components(336, 0).is_err());
    assert!(PhysicalCellId::from_components(0, 3).is_err());
}

#[test]
fn test_pss_m_sequence_orthogonality_and_properties() {
    let pss0 = generate_pss(0).unwrap();
    let pss1 = generate_pss(1).unwrap();
    let pss2 = generate_pss(2).unwrap();

    assert_eq!(pss0.len(), SYNC_SEQUENCE_LENGTH);
    assert_eq!(pss1.len(), SYNC_SEQUENCE_LENGTH);
    assert_eq!(pss2.len(), SYNC_SEQUENCE_LENGTH);

    // Auto-correlation peak = 127
    let auto_corr0 = pss0.iter().map(|&x| (x as i32) * (x as i32)).sum::<i32>();
    let auto_corr1 = pss1.iter().map(|&x| (x as i32) * (x as i32)).sum::<i32>();
    let auto_corr2 = pss2.iter().map(|&x| (x as i32) * (x as i32)).sum::<i32>();
    assert_eq!(auto_corr0, 127);
    assert_eq!(auto_corr1, 127);
    assert_eq!(auto_corr2, 127);

    // Cross-correlation between different PSS sequences = -1 (ideal m-sequence property)
    let cross_corr01 = pss0.iter().zip(pss1.iter()).map(|(&a, &b)| (a as i32) * (b as i32)).sum::<i32>();
    let cross_corr02 = pss0.iter().zip(pss2.iter()).map(|(&a, &b)| (a as i32) * (b as i32)).sum::<i32>();
    let cross_corr12 = pss1.iter().zip(pss2.iter()).map(|(&a, &b)| (a as i32) * (b as i32)).sum::<i32>();

    assert_eq!(cross_corr01, -1);
    assert_eq!(cross_corr02, -1);
    assert_eq!(cross_corr12, -1);
}

#[test]
fn test_sss_gold_sequence_and_pci_generation() {
    let sss_a = generate_sss(100, 1).unwrap();
    let sss_b = generate_sss(250, 0).unwrap();

    assert_eq!(sss_a.len(), SYNC_SEQUENCE_LENGTH);
    assert_eq!(sss_b.len(), SYNC_SEQUENCE_LENGTH);

    // Auto-correlation peak = 127
    let auto_corr = sss_a.iter().map(|&x| (x as i32) * (x as i32)).sum::<i32>();
    assert_eq!(auto_corr, 127);

    // Low cross-correlation between different Gold sequences
    let cross_corr = sss_a.iter().zip(sss_b.iter()).map(|(&a, &b)| (a as i32) * (b as i32)).sum::<i32>();
    assert!(cross_corr.abs() < 35); // Gold sequence cross-correlation bounded
}

#[test]
fn test_pbch_dmrs_gold_sequence_and_comb4_mapping() {
    let pci = 123;
    let dmrs_symbols = generate_pbch_dmrs(3, pci, SsbLMax::L8).unwrap();

    assert_eq!(dmrs_symbols.len(), PBCH_TOTAL_DMRS_RES); // exactly 144

    // Check unit power of QPSK symbols
    for &(re, im) in &dmrs_symbols {
        let power = re * re + im * im;
        assert!((power - 1.0).abs() < 1e-6);
    }
}

#[test]
fn test_mib_and_timing_payload_synthesis_and_extraction() {
    let mib = SsbMib {
        system_frame_number_msb: 0x2A, // 42 in 6 bits
        subcarrier_spacing_common: 1,  // 30 kHz
        ssb_subcarrier_offset: 7,      // k_SSB
        dmrs_type_a_position: 0,       // pos2
        pdcch_config_sib1: 0x84,
        cell_barred: false,
        intra_freq_reselection: true,
        spare: 0,
    };

    let bits = mib.to_bits();
    assert_eq!(bits.len(), 24);

    let restored_mib = SsbMib::from_bits(&bits).unwrap();
    assert_eq!(restored_mib, mib);

    // Full PBCH payload with timing
    let full_sfn = 0x2AB; // 683: MSB = 42 (0x2A), LSB = 11 (0x0B)
    let pbch = PbchPayload::new(mib, full_sfn, 1, 27).unwrap();

    assert_eq!(pbch.full_sfn(), full_sfn);
    assert_eq!(pbch.sfn_lsb, 0x0B);
    assert_eq!(pbch.half_frame_bit, 1);
    assert_eq!(pbch.ssb_index_msb, 3); // 27 >> 3 = 3

    let payload_32 = pbch.to_32_bits();
    assert_eq!(payload_32.len(), 32);
}

#[test]
fn test_ssb_resource_grid_re_allocation_counts() {
    let pci = PhysicalCellId::new(102).unwrap(); // 102 % 4 = 2 (v_shift = 2)
    let mut ssb_grid = SsbResourceGrid::new(pci, 0);
    ssb_grid.populate_grid();

    // Verify exact RE counts according to 3GPP TS 38.211 Table 7.4.3.1-1
    assert_eq!(ssb_grid.count_re_type(SsbReType::Pss), 127);
    assert_eq!(ssb_grid.count_re_type(SsbReType::Sss), 127);
    assert_eq!(ssb_grid.count_re_type(SsbReType::PbchDmrs), PBCH_TOTAL_DMRS_RES); // 144
    assert_eq!(ssb_grid.count_re_type(SsbReType::PbchData), PBCH_TOTAL_DATA_RES); // 432
    assert_eq!(ssb_grid.count_re_type(SsbReType::Reserved), 17); // 8 + 9 in symbol 2
    assert_eq!(ssb_grid.count_re_type(SsbReType::Empty), 113); // 56 + 57 in symbol 0

    // Total REs = 4 symbols * 240 subcarriers = 960
    let total_res = ssb_grid.count_re_type(SsbReType::Pss)
        + ssb_grid.count_re_type(SsbReType::Sss)
        + ssb_grid.count_re_type(SsbReType::PbchDmrs)
        + ssb_grid.count_re_type(SsbReType::PbchData)
        + ssb_grid.count_re_type(SsbReType::Reserved)
        + ssb_grid.count_re_type(SsbReType::Empty);
    assert_eq!(total_res, 4 * SSB_NUM_SUBCARRIERS);

    // Verify DMRS comb-4 subcarrier locations
    // Symbol 1: subcarriers with sc % 4 == 2 must be PbchDmrs, others PbchData
    assert_eq!(ssb_grid.get_re(1, 2), SsbReType::PbchDmrs);
    assert_eq!(ssb_grid.get_re(1, 6), SsbReType::PbchDmrs);
    assert_eq!(ssb_grid.get_re(1, 0), SsbReType::PbchData);
    assert_eq!(ssb_grid.get_re(1, 1), SsbReType::PbchData);
}

#[test]
fn test_beam_sweeping_burst_and_best_beam_selection() {
    let pci = PhysicalCellId::new(45).unwrap();
    let mut manager = SsbBurstManager::new(pci, SsbLMax::L8, SsbCase::CaseC, 20);

    // Configure transmission mask: beams 0, 1, 2, 4 are active (mask 0b00010111 = 23)
    manager.transmitted_ssb_mask = 0b00010111;

    assert!(manager.is_ssb_transmitted(0));
    assert!(manager.is_ssb_transmitted(1));
    assert!(manager.is_ssb_transmitted(2));
    assert!(!manager.is_ssb_transmitted(3)); // inactive
    assert!(manager.is_ssb_transmitted(4));

    let measurements = vec![
        SsbBeamMeasurement { ssb_index: 0, ss_rsrp_dbm: -95.0, ss_rsrq_db: -12.0 },
        SsbBeamMeasurement { ssb_index: 1, ss_rsrp_dbm: -82.0, ss_rsrq_db: -9.0 },
        SsbBeamMeasurement { ssb_index: 2, ss_rsrp_dbm: -88.0, ss_rsrq_db: -10.5 },
        SsbBeamMeasurement { ssb_index: 3, ss_rsrp_dbm: -75.0, ss_rsrq_db: -6.0 }, // highest RSRP but NOT transmitted!
        SsbBeamMeasurement { ssb_index: 4, ss_rsrp_dbm: -80.0, ss_rsrq_db: -8.0 },
    ];

    // Select best beam with threshold -90 dBm
    let best = manager.select_best_beam(&measurements, -90.0).unwrap();
    // Beam 4 has -80.0 dBm (highest among active transmitted beams)
    assert_eq!(best.ssb_index, 4);
    assert_eq!(best.ss_rsrp_dbm, -80.0);

    // If threshold is too high (-70 dBm), no beam is selected
    let none_found = manager.select_best_beam(&measurements, -70.0);
    assert!(none_found.is_none());
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = SsbWirePdu {
        magic: SSB_WIRE_MAGIC,
        pci: 301,
        ssb_index: 5,
        sfn: 888,
        half_frame: 0,
        l_max: 8,
        scs_case: 2, // Case C
        mib_bits: 0x00ABCDEF,
        payload: vec![0x11, 0x22, 0x33, 0x44, 0x55],
        crc16: 0,
    };

    let serialized = pdu.serialize();
    assert_eq!(&serialized[..4], &[0x53, 0x53, 0x42, 0x50]); // "SSBP"

    // Successful deserialization
    let deserialized = SsbWirePdu::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.pci, 301);
    assert_eq!(deserialized.ssb_index, 5);
    assert_eq!(deserialized.sfn, 888);
    assert_eq!(deserialized.payload, pdu.payload);

    // Tampered payload fails CRC
    let mut corrupted = serialized.clone();
    corrupted[19] ^= 0x80;
    assert!(SsbWirePdu::deserialize(&corrupted).is_err());
}

//! Integration and unit tests for 3GPP Rel-18/19 5G-Advanced Physical Uplink Control Channel (PUCCH)
//! Processor and Multi-Slot Repetition Engine.

use toy_tcpip::nr_pucch_processor::*;

#[test]
fn test_pucch_format0_cyclic_shift_and_sr_multiplexing() {
    let initial_cs = 2;

    // 1. 1-bit HARQ without SR
    let cs_nack = compute_format0_cyclic_shift(initial_cs, &[0], SchedulingRequestState::None).unwrap();
    assert_eq!(cs_nack, (2 + 0) % 12); // NACK -> delta = 0 => cs = 2

    let cs_ack = compute_format0_cyclic_shift(initial_cs, &[1], SchedulingRequestState::None).unwrap();
    assert_eq!(cs_ack, (2 + 6) % 12); // ACK -> delta = 6 => cs = 8

    // 2. 1-bit HARQ with Positive SR (TS 38.213 Table 9.2.3-3)
    let cs_nack_pos_sr = compute_format0_cyclic_shift(initial_cs, &[0], SchedulingRequestState::Positive).unwrap();
    assert_eq!(cs_nack_pos_sr, (2 + 3) % 12); // NACK + pos SR -> delta = 3 => cs = 5

    let cs_ack_pos_sr = compute_format0_cyclic_shift(initial_cs, &[1], SchedulingRequestState::Positive).unwrap();
    assert_eq!(cs_ack_pos_sr, (2 + 9) % 12); // ACK + pos SR -> delta = 9 => cs = 11

    // 3. 2-bit HARQ without SR (TS 38.213 Table 9.2.3-2)
    assert_eq!(compute_format0_cyclic_shift(initial_cs, &[0, 0], SchedulingRequestState::None).unwrap(), (2 + 0) % 12);
    assert_eq!(compute_format0_cyclic_shift(initial_cs, &[0, 1], SchedulingRequestState::None).unwrap(), (2 + 3) % 12);
    assert_eq!(compute_format0_cyclic_shift(initial_cs, &[1, 1], SchedulingRequestState::None).unwrap(), (2 + 6) % 12);
    assert_eq!(compute_format0_cyclic_shift(initial_cs, &[1, 0], SchedulingRequestState::None).unwrap(), (2 + 9) % 12);

    // 4. 2-bit HARQ with Positive SR (TS 38.213 Table 9.2.3-4)
    assert_eq!(compute_format0_cyclic_shift(initial_cs, &[0, 0], SchedulingRequestState::Positive).unwrap(), (2 + 1) % 12);
    assert_eq!(compute_format0_cyclic_shift(initial_cs, &[0, 1], SchedulingRequestState::Positive).unwrap(), (2 + 4) % 12);
    assert_eq!(compute_format0_cyclic_shift(initial_cs, &[1, 1], SchedulingRequestState::Positive).unwrap(), (2 + 7) % 12);
    assert_eq!(compute_format0_cyclic_shift(initial_cs, &[1, 0], SchedulingRequestState::Positive).unwrap(), (2 + 10) % 12);

    // 5. Payload too large for Format 0
    assert!(compute_format0_cyclic_shift(initial_cs, &[1, 0, 1], SchedulingRequestState::None).is_err());
}

#[test]
fn test_pucch_format1_time_domain_occ_spreading() {
    let num_symbols = 8; // 4 data symbols, 4 DMRS symbols -> n_sf = 4

    let occ0 = compute_format1_occ_sequence(num_symbols, 0).expect("OCC 0 valid");
    let occ1 = compute_format1_occ_sequence(num_symbols, 1).expect("OCC 1 valid");
    let occ2 = compute_format1_occ_sequence(num_symbols, 2).expect("OCC 2 valid");

    assert_eq!(occ0.len(), 4);
    assert_eq!(occ1.len(), 4);
    assert_eq!(occ2.len(), 4);

    // Unit amplitude check
    for c in &occ1 {
        let norm = (c.0 * c.0 + c.1 * c.1).sqrt();
        assert!((norm - 1.0).abs() < 1e-12);
    }

    // Orthogonality between OCC 0 and OCC 1: sum(w0 * w1*) == 0
    let mut dot_re = 0.0f64;
    let mut dot_im = 0.0f64;
    for (w0, w1) in occ0.iter().zip(occ1.iter()) {
        // w0 * conj(w1) = (w0.0 + j*w0.1) * (w1.0 - j*w1.1)
        dot_re += w0.0 * w1.0 + w0.1 * w1.1;
        dot_im += w0.1 * w1.0 - w0.0 * w1.1;
    }
    assert!(dot_re.abs() < 1e-10);
    assert!(dot_im.abs() < 1e-10);

    // Invalid OCC index check
    assert!(compute_format1_occ_sequence(num_symbols, 4).is_err());
}

#[test]
fn test_pucch_format2_dmrs_subcarrier_grid_allocation() {
    // Format 2: 1 symbol, 1 PRB -> 8 data REs (4 DMRS REs)
    let res_1prb_1sym = calculate_format2_available_res(1, 1).unwrap();
    assert_eq!(res_1prb_1sym, 8);

    // Format 2: 2 symbols, 4 PRBs -> 4 PRBs * 8 REs * 2 symbols = 64 REs
    let res_4prb_2sym = calculate_format2_available_res(4, 2).unwrap();
    assert_eq!(res_4prb_2sym, 64);

    // Format 2: 16 PRBs, 2 symbols -> 16 * 8 * 2 = 256 REs
    let res_16prb_2sym = calculate_format2_available_res(16, 2).unwrap();
    assert_eq!(res_16prb_2sym, 256);

    // Invalid symbol count (> 2 for Format 2)
    assert!(calculate_format2_available_res(4, 4).is_err());
}

#[test]
fn test_pucch_resource_set_selection_and_pri_lookup() {
    // 1. Set selection by payload bits
    assert_eq!(select_pucch_resource_set(1), 0);
    assert_eq!(select_pucch_resource_set(2), 0);
    assert_eq!(select_pucch_resource_set(10), 1);
    assert_eq!(select_pucch_resource_set(256), 1);
    assert_eq!(select_pucch_resource_set(500), 2);
    assert_eq!(select_pucch_resource_set(1200), 3);

    // 2. Resource configuration and PRI mapping
    let res0 = PucchResource::new(10, PucchFormat::Format0, 0, 1, 12, 2, 0, 0, false, None).unwrap();
    let res1 = PucchResource::new(11, PucchFormat::Format0, 10, 1, 12, 2, 3, 0, false, None).unwrap();
    let res2 = PucchResource::new(12, PucchFormat::Format0, 20, 1, 12, 2, 6, 0, false, None).unwrap();
    let res3 = PucchResource::new(13, PucchFormat::Format0, 30, 1, 12, 2, 9, 0, false, None).unwrap();

    let all_resources = vec![res0.clone(), res1.clone(), res2.clone(), res3.clone()];
    let resource_set0 = PucchResourceSet::new(0, 2, vec![10, 11, 12, 13]).unwrap();

    // DCI PRI 0 -> res0 (ID 10)
    let resolved_pri0 = resolve_pucch_resource_from_pri(&resource_set0, 0, &all_resources).unwrap();
    assert_eq!(resolved_pri0.resource_id, 10);

    // DCI PRI 2 -> res2 (ID 12)
    let resolved_pri2 = resolve_pucch_resource_from_pri(&resource_set0, 2, &all_resources).unwrap();
    assert_eq!(resolved_pri2.resource_id, 12);

    // DCI PRI 3 -> res3 (ID 13)
    let resolved_pri3 = resolve_pucch_resource_from_pri(&resource_set0, 3, &all_resources).unwrap();
    assert_eq!(resolved_pri3.resource_id, 13);
}

#[test]
fn test_intra_and_inter_slot_frequency_hopping() {
    let res_hopping = PucchResource::new(
        1,
        PucchFormat::Format1,
        5, // start PRB
        1,
        0,
        14,
        0,
        0,
        true,       // intra-slot hopping enabled
        Some(100),  // second hop PRB
    )
    .unwrap();

    let rep_mgr = PucchRepetitionManager::new(4, true, true);

    // Intra-slot hopping: hop 1 vs hop 2 within slot 0
    let prb_hop1 = rep_mgr.get_slot_prb(0, false, &res_hopping);
    let prb_hop2 = rep_mgr.get_slot_prb(0, true, &res_hopping);
    assert_eq!(prb_hop1, 5);
    assert_eq!(prb_hop2, 100);

    // Resource with only inter-slot hopping
    let res_inter = PucchResource::new(
        2,
        PucchFormat::Format1,
        15,
        1,
        0,
        14,
        0,
        0,
        false,      // no intra-slot hopping
        Some(120),  // inter-slot hop PRB
    )
    .unwrap();

    // Even slot (slot 0) -> start PRB (15)
    assert_eq!(rep_mgr.get_slot_prb(0, false, &res_inter), 15);
    // Odd slot (slot 1) -> second hop PRB (120)
    assert_eq!(rep_mgr.get_slot_prb(1, false, &res_inter), 120);
    // Even slot (slot 2) -> start PRB (15)
    assert_eq!(rep_mgr.get_slot_prb(2, false, &res_inter), 15);
    // Odd slot (slot 3) -> second hop PRB (120)
    assert_eq!(rep_mgr.get_slot_prb(3, false, &res_inter), 120);
}

#[test]
fn test_rel17_18_multi_slot_repetition_and_phase_continuity() {
    let rep_mgr = PucchRepetitionManager::new(4, false, true);
    assert_eq!(rep_mgr.num_slots, 4);

    // Powers compliant with 0.5 dB phase continuity constraint
    let valid_powers = vec![18.2, 18.3, 18.1, 18.4];
    let valid_prbs = vec![50, 50, 50, 50];
    assert!(rep_mgr.audit_phase_continuity(&valid_powers, &valid_prbs));

    // Power divergence exceeding 0.5 dB
    let invalid_powers = vec![18.0, 18.8, 18.0, 18.1];
    assert!(!rep_mgr.audit_phase_continuity(&invalid_powers, &valid_prbs));

    // PRB jump without inter-slot hopping
    let invalid_prbs = vec![50, 50, 55, 50];
    assert!(!rep_mgr.audit_phase_continuity(&valid_powers, &invalid_prbs));
}

#[test]
fn test_pucch_power_control_calculation_and_tpc_accumulation() {
    let mut pwr_cfg = PucchPowerControlConfig {
        p_cmax_dbm: 23.0,
        p_o_pucch_dbm: -90.0,
        pathloss_alpha: 1.0,
        pathloss_db: 80.0,
        numerology_mu: 1, // 30 kHz
        tpc_accumulator_db: 0.0,
    };

    // Format 0 (1 PRB, delta_f = 0.0 dB)
    // BW term = 10 * log10(2^1 * 1) = 3.01 dB
    // Target = -90 + 3.01 + 80 + 0 + 0 + 0 = -6.99 dBm
    let pwr_f0 = pwr_cfg.compute_tx_power(PucchFormat::Format0, 1, 2);
    assert!((pwr_f0 - (-6.9897)).abs() < 0.01);

    // Apply TPC command: +3 dB
    pwr_cfg.apply_tpc_command(3.0);
    let pwr_f0_tpc = pwr_cfg.compute_tx_power(PucchFormat::Format0, 1, 2);
    assert!((pwr_f0_tpc - (pwr_f0 + 3.0)).abs() < 0.01);

    // High pathloss saturating at P_CMAX
    pwr_cfg.pathloss_db = 130.0;
    let pwr_saturated = pwr_cfg.compute_tx_power(PucchFormat::Format0, 1, 2);
    assert_eq!(pwr_saturated, 23.0);
}

#[test]
fn test_uci_multiplexing_and_csi_part2_dropping() {
    // Normal payload: 2 HARQ bits, positive SR, 10 CSI Part 1, 10 CSI Part 2 = 23 bits
    // Allocated: 4 PRBs, 2 symbols in Format 2 -> 64 REs * 2 bits/RE = 128 coded bits
    // Code rate = 23 / 128 ≈ 0.179 <= max 0.600
    let res = arbitrate_uci_multiplexing(
        2,
        SchedulingRequestState::Positive,
        10,
        10,
        4,
        2,
        600, // max code rate 0.600
    )
    .expect("Arbitration should succeed");

    assert_eq!(res.selected_format, PucchFormat::Format2);
    assert_eq!(res.total_uci_bits, 23);
    assert!(!res.csi_part2_dropped);

    // Overloaded payload requiring CSI Part 2 drop:
    // 8 HARQ bits, 0 SR, 20 CSI Part 1, 50 CSI Part 2 = 78 bits
    // Allocated: 1 PRB, 2 symbols in Format 2 -> 16 REs * 2 bits/RE = 32 coded bits
    // 78 / 32 = 2.43 > max 0.800
    // Dropping CSI Part 2 leaves 28 bits. 28 / 32 = 0.875 > max 0.800 -> code rate exceeded!
    assert!(arbitrate_uci_multiplexing(
        8,
        SchedulingRequestState::None,
        20,
        50,
        1,
        2,
        800,
    )
    .is_err());

    // Recoverable overload:
    // 2 HARQ bits, 10 CSI Part 1, 20 CSI Part 2 = 32 bits
    // Allocated: 2 PRBs, 2 symbols -> 32 REs * 2 = 64 coded bits
    // Without drop: 32 / 64 = 0.500 > max 0.300
    // With drop (drop 20 bits): 12 / 64 = 0.1875 <= max 0.300 -> Succeeded with CSI Part 2 dropped!
    let res_drop = arbitrate_uci_multiplexing(
        2,
        SchedulingRequestState::None,
        10,
        20,
        2,
        2,
        300, // max code rate 0.300
    )
    .expect("Should succeed after dropping CSI Part 2");

    assert!(res_drop.csi_part2_dropped);
    assert_eq!(res_drop.total_uci_bits, 12);
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = PucchFramePdu {
        version: 1,
        format: 0,
        resource_id: 5,
        slot_number: 14,
        start_symbol: 12,
        num_symbols: 2,
        start_prb: 24,
        num_prbs: 1,
        tx_power_dbm_x100: 1850, // 18.50 dBm
        payload_bytes: vec![0xAA, 0x55],
    };

    let bytes = pdu.to_bytes();
    assert_eq!(bytes.len(), PucchFramePdu::HEADER_SIZE + 2 + 2); // 18 + 2 payload + 2 CRC = 22 bytes

    // Roundtrip decoding
    let decoded = PucchFramePdu::from_bytes(&bytes).expect("Decoding must succeed");
    assert_eq!(decoded, pdu);

    // CRC mismatch test
    let mut corrupted = bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(matches!(
        PucchFramePdu::from_bytes(&corrupted),
        Err(PucchError::CrcMismatch { .. })
    ));

    // Magic mismatch test
    let mut bad_magic = bytes.clone();
    bad_magic[0] = 0x00;
    assert!(matches!(
        PucchFramePdu::from_bytes(&bad_magic),
        Err(PucchError::InvalidMagic(_))
    ));
}

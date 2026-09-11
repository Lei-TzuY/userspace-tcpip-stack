//! Integration tests for 3GPP Rel-18/19 PUSCH Processor, UCI Multiplexing & Frequency Hopping Engine.

use toy_tcpip::nr_pusch_processor::{
    calculate_pusch_prb_allocation, calculate_uci_on_pusch_symbols, schedule_pusch_repetitions,
    uci_crc_length, FrequencyHoppingConfig, FrequencyHoppingMode, PuschModulation,
    PuschRepetitionScheme, PuschSlotGrid, PuschWirePdu, ReType, UciOnPuschConfig, PUSCH_WIRE_MAGIC,
    SYMBOLS_PER_SLOT,
};

#[test]
fn test_uci_crc_lengths() {
    assert_eq!(uci_crc_length(1), 0);
    assert_eq!(uci_crc_length(2), 0);
    assert_eq!(uci_crc_length(3), 6);
    assert_eq!(uci_crc_length(11), 6);
    assert_eq!(uci_crc_length(12), 11);
    assert_eq!(uci_crc_length(32), 11);
}

#[test]
fn test_uci_q_prime_harq_ack_calculation_and_alpha_clamping() {
    // Normal configuration without clamping
    let cfg_normal = UciOnPuschConfig {
        o_ack_bits: 4,
        o_csi1_bits: 0,
        o_csi2_bits: 0,
        beta_offset_ack_milli: 2000, // beta = 2.0
        beta_offset_csi1_milli: 1000,
        beta_offset_csi2_milli: 1000,
        alpha_scaling_milli: 800, // alpha = 0.8
        sum_m_sc_uci: 500,
        sum_k_r: 1000,
        modulation: PuschModulation::Qam16,
    };

    let res = calculate_uci_on_pusch_symbols(&cfg_normal).unwrap();
    // O_ACK = 4, L_ACK = 6 => O+L = 10.
    // num = 10 * 2000 * 500 = 10,000,000. den = 1,000,000. raw_q = 10.
    assert_eq!(res.q_prime_ack, 10);
    assert_eq!(res.total_ack_coded_bits, 40); // 10 * 4 bits (QAM-16)

    // Clamped configuration: high beta offset demanding more than alpha * sum_m_sc
    let cfg_clamped = UciOnPuschConfig {
        o_ack_bits: 50,
        o_csi1_bits: 0,
        o_csi2_bits: 0,
        beta_offset_ack_milli: 50000, // huge beta offset
        beta_offset_csi1_milli: 1000,
        beta_offset_csi2_milli: 1000,
        alpha_scaling_milli: 500, // alpha = 0.5
        sum_m_sc_uci: 200,
        sum_k_r: 100,
        modulation: PuschModulation::Qpsk,
    };

    let res_clamped = calculate_uci_on_pusch_symbols(&cfg_clamped).unwrap();
    // Max UCI symbols = 200 * 0.5 = 100
    assert_eq!(res_clamped.q_prime_ack, 100);
    assert_eq!(res_clamped.total_ack_coded_bits, 200); // 100 * 2 bits (QPSK)
}

#[test]
fn test_uci_q_prime_csi1_and_csi2_allocation() {
    let cfg = UciOnPuschConfig {
        o_ack_bits: 2,  // L = 0
        o_csi1_bits: 8, // L = 6
        o_csi2_bits: 14, // L = 11
        beta_offset_ack_milli: 1500,
        beta_offset_csi1_milli: 1200,
        beta_offset_csi2_milli: 1000,
        alpha_scaling_milli: 800,
        sum_m_sc_uci: 600,
        sum_k_r: 1200,
        modulation: PuschModulation::Qam64,
    };

    let res = calculate_uci_on_pusch_symbols(&cfg).unwrap();
    assert!(res.q_prime_ack > 0);
    assert!(res.q_prime_csi1 > 0);
    assert!(res.q_prime_csi2 > 0);

    // Ensure total symbols do not exceed alpha budget
    let max_budget = (600 * 800) / 1000;
    assert!(res.q_prime_ack + res.q_prime_csi1 + res.q_prime_csi2 <= max_budget);
}

#[test]
fn test_pusch_intra_slot_frequency_hopping_offsets() {
    let hop_cfg = FrequencyHoppingConfig {
        mode: FrequencyHoppingMode::IntraSlot,
        rb_start: 10,
        num_prb: 20,
        rb_offset: 35,
        bwp_size_prb: 100,
        first_hop_symbols: 7,
    };

    // First hop (symbols 0..6)
    for sym in 0..7 {
        let alloc = calculate_pusch_prb_allocation(&hop_cfg, 0, sym).unwrap();
        assert_eq!(alloc.start_prb, 10);
        assert_eq!(alloc.num_prb, 20);
    }

    // Second hop (symbols 7..13)
    for sym in 7..14 {
        let alloc = calculate_pusch_prb_allocation(&hop_cfg, 0, sym).unwrap();
        // RB_start,2 = (10 + 35) % 100 = 45
        assert_eq!(alloc.start_prb, 45);
        assert_eq!(alloc.num_prb, 20);
    }
}

#[test]
fn test_pusch_inter_slot_frequency_hopping() {
    let hop_cfg = FrequencyHoppingConfig {
        mode: FrequencyHoppingMode::InterSlot,
        rb_start: 15,
        num_prb: 10,
        rb_offset: 50,
        bwp_size_prb: 100,
        first_hop_symbols: 7,
    };

    // Even slot: hop 1
    let alloc_slot0 = calculate_pusch_prb_allocation(&hop_cfg, 0, 3).unwrap();
    assert_eq!(alloc_slot0.start_prb, 15);

    // Odd slot: hop 2
    let alloc_slot1 = calculate_pusch_prb_allocation(&hop_cfg, 1, 3).unwrap();
    assert_eq!(alloc_slot1.start_prb, 65); // (15 + 50) % 100 = 65

    // Next even slot: back to hop 1
    let alloc_slot2 = calculate_pusch_prb_allocation(&hop_cfg, 2, 3).unwrap();
    assert_eq!(alloc_slot2.start_prb, 15);
}

#[test]
fn test_pusch_repetition_type_a_multi_slot_rv_cycling() {
    let reps = schedule_pusch_repetitions(
        PuschRepetitionScheme::TypeA,
        4,   // 4 repetitions
        100, // start slot
        2,   // start symbol
        10,  // length symbols
        &[0, 2, 3, 1],
    )
    .unwrap();

    assert_eq!(reps.len(), 4);
    assert_eq!(reps[0].slot_idx, 100);
    assert_eq!(reps[0].redundancy_version, 0);
    assert_eq!(reps[1].slot_idx, 101);
    assert_eq!(reps[1].redundancy_version, 2);
    assert_eq!(reps[2].slot_idx, 102);
    assert_eq!(reps[2].redundancy_version, 3);
    assert_eq!(reps[3].slot_idx, 103);
    assert_eq!(reps[3].redundancy_version, 1);

    for r in &reps {
        assert_eq!(r.start_symbol, 2);
        assert_eq!(r.num_symbols, 10);
    }
}

#[test]
fn test_pusch_repetition_type_b_slot_boundary_segmentation() {
    // Repetition starting at symbol 10 with duration 8 symbols.
    // Crosses symbol 14! Must be split across slot boundary.
    let reps = schedule_pusch_repetitions(
        PuschRepetitionScheme::TypeB,
        2,  // 2 nominal repetitions
        5,  // start slot
        10, // start symbol
        8,  // length symbols
        &[0, 2],
    )
    .unwrap();

    // Nominal 0: length 8 starting at symbol 10
    // Segment 1: slot 5, symbol 10..14 (length 4)
    // Segment 2: slot 6, symbol 0..4 (length 4)
    // Nominal 1: length 8 starting at symbol 4
    // Segment 3: slot 6, symbol 4..12 (length 8, within slot)
    assert_eq!(reps.len(), 3);

    assert_eq!(reps[0].nominal_idx, 0);
    assert_eq!(reps[0].slot_idx, 5);
    assert_eq!(reps[0].start_symbol, 10);
    assert_eq!(reps[0].num_symbols, 4);
    assert_eq!(reps[0].redundancy_version, 0);

    assert_eq!(reps[1].nominal_idx, 0);
    assert_eq!(reps[1].slot_idx, 6);
    assert_eq!(reps[1].start_symbol, 0);
    assert_eq!(reps[1].num_symbols, 4);
    assert_eq!(reps[1].redundancy_version, 0);

    assert_eq!(reps[2].nominal_idx, 1);
    assert_eq!(reps[2].slot_idx, 6);
    assert_eq!(reps[2].start_symbol, 4);
    assert_eq!(reps[2].num_symbols, 8);
    assert_eq!(reps[2].redundancy_version, 2);
}

#[test]
fn test_pusch_grid_mapping_dmrs_puncturing_and_multiplexing() {
    let num_prb = 4; // 4 * 12 = 48 subcarriers
    let mut grid = PuschSlotGrid::new(num_prb);

    let dmrs_symbols = vec![2, 11]; // Double DMRS
    grid.reserve_dmrs_symbols(&dmrs_symbols);

    assert_eq!(grid.count_re_type(ReType::Dmrs), 2 * 48);

    // Multiplex 40 ACK, 30 CSI-1, 20 CSI-2
    let ulsch_placed = grid
        .multiplex_channels(0, SYMBOLS_PER_SLOT, &dmrs_symbols, 40, 30, 20)
        .unwrap();

    assert_eq!(grid.count_re_type(ReType::HarqAck), 40);
    assert_eq!(grid.count_re_type(ReType::CsiPart1), 30);
    assert_eq!(grid.count_re_type(ReType::CsiPart2), 20);

    // Total non-DMRS REs = 12 symbols * 48 subcarriers = 576 REs.
    // UL-SCH should occupy 576 - (40 + 30 + 20) = 486 REs.
    assert_eq!(ulsch_placed, 486);
    assert_eq!(grid.count_re_type(ReType::UlSchData), 486);

    // Verify HARQ-ACK is placed adjacent to DMRS (e.g. symbol 3)
    assert_eq!(grid.get_re(3, 0), ReType::HarqAck);
    // Verify DMRS symbol itself is untouched
    assert_eq!(grid.get_re(2, 0), ReType::Dmrs);
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = PuschWirePdu {
        magic: PUSCH_WIRE_MAGIC,
        slot_idx: 42,
        start_prb: 5,
        num_prb: 25,
        start_symbol: 0,
        num_symbols: 14,
        modulation: 4, // 16QAM
        redundancy_version: 2,
        ack_symbols: 16,
        csi1_symbols: 24,
        csi2_symbols: 32,
        ulsch_symbols: 1200,
        payload: vec![0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04],
        crc16: 0,
    };

    let serialized = pdu.serialize();
    assert_eq!(&serialized[..4], &[0x50, 0x55, 0x53, 0x48]); // "PUSH"

    // Successful deserialization
    let deserialized = PuschWirePdu::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.slot_idx, 42);
    assert_eq!(deserialized.start_prb, 5);
    assert_eq!(deserialized.num_prb, 25);
    assert_eq!(deserialized.payload, pdu.payload);

    // Tampered payload fails CRC
    let mut corrupted = serialized.clone();
    corrupted[27] ^= 0xFF;
    assert!(PuschWirePdu::deserialize(&corrupted).is_err());
}

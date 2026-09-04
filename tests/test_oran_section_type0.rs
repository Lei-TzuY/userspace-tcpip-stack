//! Integration tests for O-RAN WG4 C-Plane Section Type 0 Engine.

use toy_tcpip::oran_fh_cus::{DataDirection, OranRadioHeader};
use toy_tcpip::oran_section_type0::{
    BlankingGrid, BlankingReason, BlankingReservation, FrameStructure, NR_SUBCARRIERS_PER_PRB,
    NR_SYMBOLS_PER_SLOT, ORAN_SECTION_TYPE_0, ORAN_SECTION_TYPE_0_COMMON_HEADER_LEN,
    ORAN_SECTION_TYPE_0_SECTION_LEN, OranFftSize, OranScs, OranSectionType0CommonHeader,
    OranSectionType0Error, OranSectionType0Message, OranSectionType0Section,
};

#[test]
fn test_radio_header_and_type0_common_header_roundtrip() {
    let radio_header = OranRadioHeader::new(DataDirection::Downlink, 42, 5, 10, 0);
    let frame_structure = FrameStructure::new(OranFftSize::Fft2048, OranScs::Scs30kHz);

    assert_eq!(frame_structure.fft_size.points(), 2048);
    assert_eq!(frame_structure.scs.khz(), 30.0);
    assert_eq!(frame_structure.scs.slot_duration_us(), Some(500.0));

    let common_header = OranSectionType0CommonHeader::new(
        radio_header,
        3,    // 3 sections
        1500, // timeOffset in Ts units
        frame_structure,
        144, // cpLength
    );

    assert_eq!(common_header.section_type, ORAN_SECTION_TYPE_0);
    assert_eq!(common_header.num_sections, 3);
    assert_eq!(common_header.time_offset, 1500);
    assert_eq!(common_header.cp_length, 144);

    let serialized = common_header
        .serialize()
        .expect("serialization should succeed");
    assert_eq!(serialized.len(), ORAN_SECTION_TYPE_0_COMMON_HEADER_LEN);

    let parsed = OranSectionType0CommonHeader::parse(&serialized)
        .expect("parsing common header should succeed");

    assert_eq!(parsed.radio_header.data_direction, DataDirection::Downlink);
    assert_eq!(parsed.radio_header.frame_id, 42);
    assert_eq!(parsed.radio_header.subframe_id, 5);
    assert_eq!(parsed.radio_header.slot_id, 10);
    assert_eq!(parsed.radio_header.symbol_id, 0);
    assert_eq!(parsed.num_sections, 3);
    assert_eq!(parsed.section_type, ORAN_SECTION_TYPE_0);
    assert_eq!(parsed.time_offset, 1500);
    assert_eq!(parsed.frame_structure.fft_size, OranFftSize::Fft2048);
    assert_eq!(parsed.frame_structure.scs, OranScs::Scs30kHz);
    assert_eq!(parsed.cp_length, 144);
}

#[test]
fn test_section_body_serialization_and_effective_prbs() {
    let section = OranSectionType0Section::new(205, 12, 48, 6)
        .with_re_mask(0x0FFF)
        .expect("valid RE mask")
        .with_every_other_rb(true)
        .with_sym_inc(false);

    assert_eq!(section.section_id, 205);
    assert_eq!(section.start_prbc, 12);
    assert_eq!(section.num_prbc, 48);
    assert_eq!(section.num_symbol, 6);
    assert!(section.rb);
    assert!(!section.sym_inc);
    assert_eq!(section.re_mask, 0x0FFF);
    assert_eq!(section.effective_prb_count(273), 48);

    let bytes = section.serialize().expect("serialize section");
    assert_eq!(bytes.len(), ORAN_SECTION_TYPE_0_SECTION_LEN);

    let parsed = OranSectionType0Section::parse(&bytes).expect("parse section");
    assert_eq!(parsed.section_id, 205);
    assert_eq!(parsed.start_prbc, 12);
    assert_eq!(parsed.num_prbc, 48);
    assert_eq!(parsed.num_symbol, 6);
    assert!(parsed.rb);
    assert!(!parsed.sym_inc);
    assert_eq!(parsed.re_mask, 0x0FFF);
    assert!(!parsed.ef);
    assert_eq!(parsed.reserved, 0);

    // Test num_prbc = 0 meaning "all remaining PRBs of carrier"
    let full_carrier_section = OranSectionType0Section::new(1, 20, 0, 14);
    assert_eq!(full_carrier_section.effective_prb_count(100), 80);
    assert_eq!(full_carrier_section.effective_prb_count(273), 253);
}

#[test]
fn test_complete_message_serialization_and_deserialization() {
    let radio_header = OranRadioHeader::new(DataDirection::Downlink, 10, 2, 3, 0);
    let frame_structure = FrameStructure::new(OranFftSize::Fft4096, OranScs::Scs15kHz);
    let common_header = OranSectionType0CommonHeader::new(radio_header, 3, 0, frame_structure, 288);

    // 3 distinct reservations:
    // 1. Edge guardband (PRB 0..5, all 14 symbols)
    let s1 = OranSectionType0Section::new(10, 0, 5, 14);
    // 2. DSS LTE CRS subcarrier puncturing (PRB 5..95, 4 symbols, alternating REs)
    let s2 = OranSectionType0Section::new(11, 5, 90, 4)
        .with_re_mask(0x0249)
        .expect("valid mask");
    // 3. Radar protection gap (PRB 95..100, 14 symbols)
    let s3 = OranSectionType0Section::new(12, 95, 5, 14);

    let msg = OranSectionType0Message::new(common_header, vec![s1, s2, s3]);
    let wire_bytes = msg.serialize().expect("message serialize");

    assert_eq!(
        wire_bytes.len(),
        ORAN_SECTION_TYPE_0_COMMON_HEADER_LEN + 3 * ORAN_SECTION_TYPE_0_SECTION_LEN
    );

    let parsed_msg = OranSectionType0Message::parse(&wire_bytes).expect("message parse");
    assert_eq!(parsed_msg.common_header.num_sections, 3);
    assert_eq!(parsed_msg.sections.len(), 3);

    assert_eq!(parsed_msg.sections[0].section_id, 10);
    assert_eq!(parsed_msg.sections[0].start_prbc, 0);
    assert_eq!(parsed_msg.sections[0].num_prbc, 5);
    assert_eq!(parsed_msg.sections[0].num_symbol, 14);

    assert_eq!(parsed_msg.sections[1].section_id, 11);
    assert_eq!(parsed_msg.sections[1].start_prbc, 5);
    assert_eq!(parsed_msg.sections[1].num_prbc, 90);
    assert_eq!(parsed_msg.sections[1].re_mask, 0x0249);
    assert_eq!(parsed_msg.sections[1].num_symbol, 4);

    assert_eq!(parsed_msg.sections[2].section_id, 12);
    assert_eq!(parsed_msg.sections[2].start_prbc, 95);
    assert_eq!(parsed_msg.sections[2].num_prbc, 5);
}

#[test]
fn test_truncation_and_malformed_input_rejection() {
    // Truncated common header (< 12 bytes)
    let truncated_buf = vec![0u8; 10];
    let err = OranSectionType0CommonHeader::parse(&truncated_buf);
    assert!(matches!(err, Err(OranSectionType0Error::Truncated { .. })));

    // Unsupported section type (e.g. Type 1 passed to Section Type 0 parser)
    let mut valid_header = [0u8; 12];
    valid_header[0] = 0x10; // version 1
    valid_header[4] = 1; // num_sections
    valid_header[5] = 1; // sectionType = 1 (invalid for Type 0)
    valid_header[8] = 0xB0; // FFT 2048, SCS 15 kHz
    let err = OranSectionType0CommonHeader::parse(&valid_header);
    assert_eq!(err, Err(OranSectionType0Error::UnsupportedSectionType(1)));

    // Invalid RE mask (> 0x0FFF)
    let invalid_mask_err = OranSectionType0Section::new(1, 0, 10, 1).with_re_mask(0x1FFF);
    assert!(matches!(
        invalid_mask_err,
        Err(OranSectionType0Error::InvalidReMask(0x1FFF))
    ));

    // Invalid num_symbol (0 or > 14)
    let invalid_sym_err = OranSectionType0Section::new(1, 0, 10, 15).validate();
    assert!(matches!(
        invalid_sym_err,
        Err(OranSectionType0Error::FieldOutOfRange {
            field: "numSymbol",
            ..
        })
    ));

    // Section body truncated
    let mut incomplete_msg = valid_header.to_vec();
    incomplete_msg[5] = 0; // sectionType = 0
    incomplete_msg[4] = 2; // declared 2 sections
    incomplete_msg.extend_from_slice(&[0u8; 8]); // only 1 section provided
    let err = OranSectionType0Message::parse(&incomplete_msg);
    assert!(matches!(err, Err(OranSectionType0Error::Truncated { .. })));
}

#[test]
fn test_blanking_grid_and_collision_detection() {
    let mut grid = BlankingGrid::new(100, OranScs::Scs30kHz);

    // Reserve PRBs 40..60 on symbols 2..7 for Radar / CBRS avoidance
    let radar_res = BlankingReservation::new(
        BlankingReason::RadarProtection,
        501,
        2,      // start symbol 2
        5,      // num symbols 5 (symbols 2, 3, 4, 5, 6)
        40,     // start PRB 40
        20,     // 20 PRBs (40..60)
        0x0FFF, // all 12 REs blanked
    );
    grid.add_reservation(radar_res)
        .expect("add radar reservation");

    // Reserve DSS LTE CRS puncturing on symbols 4..5, PRBs 10..30, only subcarrier 0
    let dss_res = BlankingReservation::new(
        BlankingReason::DssLteCoexistence,
        502,
        4,
        1,
        10,
        20,
        0x0001, // only subcarrier 0 punctured
    );
    grid.add_reservation(dss_res).expect("add dss reservation");

    // Scenario 1: Transmission in safe range (symbols 0..2, PRBs 0..40) -> No collision
    let col = grid.check_collision(0, 2, 0, 40, 0x0FFF);
    assert!(col.is_none(), "no collision expected in unblanked region");

    // Scenario 2: Transmission overlaps radar zone on symbol 3, PRBs 45..50
    let col = grid.check_collision(3, 2, 45, 5, 0x0FFF);
    assert!(col.is_some(), "collision expected in radar protection band");
    let c = col.unwrap();
    assert_eq!(c.section_id, 501);
    assert_eq!(c.reason, BlankingReason::RadarProtection);
    assert_eq!(c.symbol, 3);
    assert_eq!(c.prb, 45);
    assert_eq!(c.overlapping_re_mask, 0x0FFF);

    // Scenario 3: Fine-grained RE collision test on DSS puncturing:
    // Transmission on symbol 4, PRB 15 with RE mask 0x0FFE (subcarrier 0 excluded) -> NO collision!
    let col = grid.check_collision(4, 1, 15, 1, 0x0FFE);
    assert!(
        col.is_none(),
        "subcarrier 0 was avoided, no collision expected"
    );

    // Transmission on symbol 4, PRB 15 with RE mask 0x0001 (subcarrier 0 included) -> COLLISION!
    let col = grid.check_collision(4, 1, 15, 1, 0x0001);
    assert!(col.is_some());
    let c = col.unwrap();
    assert_eq!(c.section_id, 502);
    assert_eq!(c.reason, BlankingReason::DssLteCoexistence);
    assert_eq!(c.symbol, 4);
    assert_eq!(c.prb, 15);
    assert_eq!(c.overlapping_re_mask, 0x0001);
}

#[test]
fn test_micro_sleep_power_savings_calculation() {
    let mut grid = BlankingGrid::new(100, OranScs::Scs30kHz);

    // Blank symbols 8..14 completely across all 100 PRBs for PA micro-sleep
    let sleep_res = BlankingReservation::new(
        BlankingReason::PowerSavingMicroSleep,
        901,
        8, // symbol 8
        6, // 6 symbols: 8, 9, 10, 11, 12, 13
        0, // start PRB 0
        0, // 0 = all 100 PRBs of carrier
        0x0FFF,
    );
    grid.add_reservation(sleep_res)
        .expect("add sleep reservation");

    // Nominal PA power = 250 Watts
    let report = grid.calculate_power_savings(250.0);

    let expected_total_res = 100 * NR_SUBCARRIERS_PER_PRB * NR_SYMBOLS_PER_SLOT; // 100 * 12 * 14 = 16,800
    assert_eq!(report.total_slot_res, expected_total_res);

    let expected_blanked_res = 100 * NR_SUBCARRIERS_PER_PRB * 6; // 100 * 12 * 6 = 7,200
    assert_eq!(report.blanked_res, expected_blanked_res);

    assert_eq!(report.fully_blanked_symbols, 6);

    let expected_ratio = 7200.0 / 16800.0; // 42.857%
    assert!((report.blanking_ratio - expected_ratio).abs() < 1e-6);
    assert!((report.duty_cycle_reduction_percent - (expected_ratio * 100.0)).abs() < 1e-4);

    // Symbol duration at 30 kHz = 1000 / 30 = 33.3333 us
    // 6 symbols = 200.0 us
    assert!((report.sleep_duration_us - 200.0).abs() < 1e-4);

    // Energy saved = 250 W * 200e-6 s = 0.05 Joules per slot
    assert!((report.estimated_energy_saved_joules - 0.05).abs() < 1e-6);
}

#[test]
fn test_compile_message_from_grid() {
    let mut grid = BlankingGrid::new(100, OranScs::Scs15kHz);
    grid.add_reservation(BlankingReservation::new(
        BlankingReason::CarrierGuardband,
        1,
        0,
        14,
        0,
        4,
        0x0FFF,
    ))
    .expect("add res 1");

    grid.add_reservation(BlankingReservation::new(
        BlankingReason::CarrierGuardband,
        2,
        0,
        14,
        96,
        4,
        0x0FFF,
    ))
    .expect("add res 2");

    let radio_header = OranRadioHeader::new(DataDirection::Uplink, 7, 1, 0, 0);
    let msg = grid
        .compile_message(radio_header, 50, OranFftSize::Fft2048, 144)
        .expect("compile message");

    assert_eq!(msg.common_header.num_sections, 2);
    assert_eq!(msg.sections.len(), 2);
    assert_eq!(
        msg.common_header.radio_header.data_direction,
        DataDirection::Uplink
    );
    assert_eq!(msg.common_header.time_offset, 50);

    let wire = msg.serialize().expect("serialize compiled msg");
    let parsed = OranSectionType0Message::parse(&wire).expect("parse compiled msg");
    assert_eq!(parsed.sections.len(), 2);
    assert_eq!(parsed.sections[0].start_prbc, 0);
    assert_eq!(parsed.sections[0].num_prbc, 4);
    assert_eq!(parsed.sections[1].start_prbc, 96);
    assert_eq!(parsed.sections[1].num_prbc, 4);
}

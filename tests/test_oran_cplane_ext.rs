//! Integration tests for O-RAN WG4 Control Plane Section Extensions & Section Type 3 PRACH.

use toy_tcpip::oran_cplane_ext::{
    BfwBundle, BfwCompressionMethod, BfwWeight, CPlaneSectionType3, OranCPlaneError,
    OranCPlaneExtEngine, SectionExtension1, SectionExtension2, SectionExtension4,
};

#[test]
fn test_section_ext_1_64t64r_beamforming_weights_round_trip() {
    let num_antennas = 64;

    // Generate 64 digital beamforming weights for 2 PRB bundles
    let mut weights_bundle1 = Vec::with_capacity(num_antennas);
    let mut weights_bundle2 = Vec::with_capacity(num_antennas);
    for ant in 0..num_antennas {
        weights_bundle1.push(BfwWeight::new(
            (ant as i16) * 100 - 3000,
            3000 - (ant as i16) * 80,
        ));
        weights_bundle2.push(BfwWeight::new(
            1500 - (ant as i16) * 50,
            (ant as i16) * 60 - 2000,
        ));
    }

    let bundle1 = BfwBundle::new(3, weights_bundle1.clone());
    let bundle2 = BfwBundle::new(2, weights_bundle2.clone());

    let ext1 = SectionExtension1::new(
        BfwCompressionMethod::BlockFloatingPoint,
        16,
        vec![bundle1, bundle2],
    );

    let serialized = ext1.serialize();

    // Verify 32-bit (4-byte) word alignment
    assert_eq!(serialized.len() % 4, 0);

    // Parse and validate using OranCPlaneExtEngine
    let parsed = OranCPlaneExtEngine::validate_and_parse_bfw(&serialized, num_antennas)
        .expect("Failed to parse Section Extension 1");

    assert_eq!(
        parsed.bfw_comp_meth,
        BfwCompressionMethod::BlockFloatingPoint
    );
    assert_eq!(parsed.bfw_iq_width, 16);
    assert_eq!(parsed.bundles.len(), 2);

    assert_eq!(parsed.bundles[0].exponent, 3);
    assert_eq!(parsed.bundles[0].weights, weights_bundle1);

    assert_eq!(parsed.bundles[1].exponent, 2);
    assert_eq!(parsed.bundles[1].weights, weights_bundle2);
}

#[test]
fn test_section_ext_1_8bit_uncompressed() {
    let num_antennas = 32;
    let mut weights = Vec::with_capacity(num_antennas);
    for ant in 0..num_antennas {
        weights.push(BfwWeight::new((ant as i16) - 16, 16 - (ant as i16)));
    }

    let bundle = BfwBundle::new(0, weights.clone());
    let ext = SectionExtension1::new(BfwCompressionMethod::Uncompressed, 8, vec![bundle]);
    let serialized = ext.serialize();
    assert_eq!(serialized.len() % 4, 0);

    let parsed = SectionExtension1::parse(&serialized, num_antennas).unwrap();
    assert_eq!(parsed.bfw_comp_meth, BfwCompressionMethod::Uncompressed);
    assert_eq!(parsed.bfw_iq_width, 8);
    assert_eq!(parsed.bundles.len(), 1);
    assert_eq!(parsed.bundles[0].weights, weights);
}

#[test]
fn test_section_ext_2_beam_attributes() {
    let ext2 = SectionExtension2::new(512, 45.50, -12.25);
    let serialized = ext2.serialize();
    assert_eq!(serialized.len() % 4, 0);

    let parsed =
        SectionExtension2::parse(&serialized).expect("Failed to parse Section Extension 2");
    assert_eq!(parsed.bf_id, 512);
    assert!((parsed.azimuth_deg - 45.50).abs() < 0.01);
    assert!((parsed.elevation_deg - (-12.25)).abs() < 0.01);
}

#[test]
fn test_section_ext_4_modulation_compression() {
    let ext4 = SectionExtension4::new(true, 2048);
    let serialized = ext4.serialize();
    assert_eq!(serialized.len() % 4, 0);

    let parsed =
        SectionExtension4::parse(&serialized).expect("Failed to parse Section Extension 4");
    assert!(parsed.csf);
    assert_eq!(parsed.mod_comp_scaler, 2048);
}

#[test]
fn test_section_type_3_prach_scheduling_round_trip() {
    // 5G NR PRACH Section Type 3
    // section_id = 401, start_prbc = 12, num_prbc = 48
    // time_offset = 1250, frame_structure = 0x81 (FFT 2048, SCS 1.25 kHz)
    // cp_length = 3168 samples, frequency_offset = -300 subcarriers
    let prach_sec = CPlaneSectionType3::new(401, 12, 48, 1250, 0x81, 3168, -300);

    let serialized = prach_sec.serialize();
    assert_eq!(serialized.len(), 14);

    let parsed = CPlaneSectionType3::parse(&serialized).expect("Failed to parse Section Type 3");
    assert_eq!(parsed.section_id, 401);
    assert!(parsed.rb);
    assert!(!parsed.sym_inc);
    assert_eq!(parsed.start_prbc, 12);
    assert_eq!(parsed.num_prbc, 48);
    assert_eq!(parsed.re_mask, 0x0FFF);
    assert_eq!(parsed.time_offset, 1250);
    assert_eq!(parsed.frame_structure, 0x81);
    assert_eq!(parsed.cp_length, 3168);
    assert_eq!(parsed.frequency_offset, -300);

    // Verify frequency shift calculation: -300 subcarriers * 1.25 kHz = -375,000 Hz (-375 kHz)
    let shift_hz = OranCPlaneExtEngine::calculate_frequency_shift_hz(parsed.frequency_offset, 1.25);
    assert_eq!(shift_hz, -375_000.0);
}

#[test]
fn test_cplane_ext_engine_malformed_and_bounds() {
    // Truncated buffer
    let short_buf = [1, 0, 1];
    assert_eq!(
        SectionExtension1::parse(&short_buf, 64),
        Err(OranCPlaneError::Truncated { need: 4, got: 3 })
    );

    // Antenna count mismatch
    let ext = SectionExtension1::new(
        BfwCompressionMethod::Uncompressed,
        16,
        vec![BfwBundle::new(0, vec![BfwWeight::new(10, 20); 32])],
    );
    let ser = ext.serialize();
    // Expect 64 antennas but provided only 32
    let res = OranCPlaneExtEngine::validate_and_parse_bfw(&ser, 64);
    assert_eq!(
        res,
        Err(OranCPlaneError::AntennaCountMismatch {
            expected: 64,
            got: 32
        })
    );
}

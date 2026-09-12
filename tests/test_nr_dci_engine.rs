//! Integration tests for 3GPP Rel-18/19 5G-Advanced Downlink Control Information (DCI) Engine.
//! Validates:
//! - Big-endian bitfield streaming (BitWriter / BitReader).
//! - Resource Allocation Type 1 (RIV) encoding, decoding, boundary conditions, and bitwidth formulas.
//! - Resource Allocation Type 0 (RBG bitmap) config, size rules, and PRB mappings.
//! - DCI Formats: 0_0, 0_1, 1_0, 1_1, 2_0, 2_1, 2_4 serialization and deserialization.
//! - DCI size alignment and 3GPP forbidden size avoidance.
//! - CRC-24C calculation and 16-bit RNTI parity scrambling/descrambling.
//! - Blind RNTI recovery from scrambled parity.
//! - Binary wire framing (DciWirePdu) and CRC-16 CCITT integrity.

use toy_tcpip::nr_dci_engine::{
    align_dci_0_0_and_1_0, attach_crc24c_and_scramble_rnti, avoid_forbidden_size,
    compute_crc24c, compute_num_rbgs, compute_riv_bits, decode_riv,
    encode_riv, extract_scrambled_rnti, get_rbg_size, is_forbidden_dci_size,
    rbg_bitmap_to_prbs, verify_crc24c_with_rnti, BitReader, BitWriter, DciError,
    DciFormat0_0, DciFormat0_1, DciFormat1_0, DciFormat1_1, DciFormat2_0,
    DciFormat2_1, DciFormat2_4, DciWireFormatType, DciWirePdu, FdResourceAllocation,
    RbgSizeConfig, RntiType, MAX_NR_PRBS,
};

// ---------------------------------------------------------------------------
// 1. BitWriter and BitReader Tests
// ---------------------------------------------------------------------------

#[test]
fn test_bitwriter_bitreader_basic_and_arbitrary_widths() {
    let mut writer = BitWriter::new();
    assert!(writer.is_empty());
    assert_eq!(writer.len(), 0);

    writer.push_bit(1);
    writer.push_bit(0);
    writer.push_bits(0b101, 3);
    writer.push_bits(0xABCD, 16);
    writer.push_bits(0x123456789ABCDEF0, 64);
    writer.push_bits(7, 4);

    assert_eq!(writer.len(), 1 + 1 + 3 + 16 + 64 + 4);

    let mut reader = BitReader::new(writer.as_bit_slice());
    assert_eq!(reader.remaining(), writer.len());
    assert_eq!(reader.cursor(), 0);

    assert_eq!(reader.read_bit().unwrap(), 1);
    assert_eq!(reader.read_bit().unwrap(), 0);
    assert_eq!(reader.read_bits(3).unwrap(), 0b101);
    assert_eq!(reader.read_bits(16).unwrap(), 0xABCD);
    assert_eq!(reader.read_bits(64).unwrap(), 0x123456789ABCDEF0);
    assert_eq!(reader.read_bits(4).unwrap(), 7);
    assert_eq!(reader.remaining(), 0);

    // Underflow on empty
    assert!(reader.read_bit().is_err());
    assert!(reader.read_bits(1).is_err());
}

#[test]
fn test_bitwriter_to_and_from_bytes() {
    let mut writer = BitWriter::new();
    // 0xAA = 10101010, 0x55 = 01010101, plus 3 bits: 110
    writer.push_bits(0xAA, 8);
    writer.push_bits(0x55, 8);
    writer.push_bits(0b110, 3);
    assert_eq!(writer.len(), 19);

    let bytes = writer.to_bytes();
    assert_eq!(bytes.len(), 3);
    assert_eq!(bytes[0], 0xAA);
    assert_eq!(bytes[1], 0x55);
    // 11000000 = 0xC0
    assert_eq!(bytes[2], 0xC0);

    let reader_writer = BitWriter::from_bytes(&bytes, 19).unwrap();
    assert_eq!(reader_writer.len(), 19);
    assert_eq!(reader_writer.as_bit_slice(), writer.as_bit_slice());
}

#[test]
fn test_bitwriter_pad_zeros() {
    let mut writer = BitWriter::new();
    writer.push_bits(0b11, 2);
    writer.pad_zeros(6);
    assert_eq!(writer.len(), 8);
    let bytes = writer.to_bytes();
    assert_eq!(bytes, vec![0b11000000]);
}

#[test]
fn test_bitreader_skip() {
    let mut writer = BitWriter::new();
    writer.push_bits(0xDEADBEEF, 32);
    let mut reader = BitReader::new(writer.as_bit_slice());
    reader.skip(16).unwrap();
    assert_eq!(reader.remaining(), 16);
    assert_eq!(reader.read_bits(16).unwrap(), 0xBEEF);
    assert!(reader.skip(1).is_err());
}

// ---------------------------------------------------------------------------
// 2. RIV Bit Width and Encoding/Decoding Tests
// ---------------------------------------------------------------------------

#[test]
fn test_riv_bits_calculation() {
    // N=20: 20*21/2 = 210 combinations -> ceil(log2(210)) = 8 bits
    assert_eq!(compute_riv_bits(20).unwrap(), 8);
    // N=50: 50*51/2 = 1275 -> ceil(log2(1275)) = 11 bits
    assert_eq!(compute_riv_bits(50).unwrap(), 11);
    // N=100: 100*101/2 = 5050 -> ceil(log2(5050)) = 13 bits
    assert_eq!(compute_riv_bits(100).unwrap(), 13);
    // N=273: 273*274/2 = 37401 -> ceil(log2(37401)) = 16 bits
    assert_eq!(compute_riv_bits(273).unwrap(), 16);
    // N=275: 275*276/2 = 37950 -> ceil(log2(37950)) = 16 bits
    assert_eq!(compute_riv_bits(275).unwrap(), 16);

    // Invalid BWP sizes
    assert!(compute_riv_bits(0).is_err());
    assert!(compute_riv_bits(MAX_NR_PRBS + 1).is_err());
}

#[test]
fn test_riv_encode_decode_roundtrip_all_combinations_small_bwp() {
    let bwp_size = 20;
    for start in 0..bwp_size {
        for len in 1..=(bwp_size - start) {
            let riv = encode_riv(start, len, bwp_size).unwrap();
            let (dec_start, dec_len) = decode_riv(riv, bwp_size).unwrap();
            assert_eq!(dec_start, start, "Failed for start={}, len={}", start, len);
            assert_eq!(dec_len, len, "Failed for start={}, len={}", start, len);
        }
    }
}

#[test]
fn test_riv_encode_decode_boundaries_large_bwps() {
    let test_bwp_sizes = [50, 100, 273, 275];
    for &n in &test_bwp_sizes {
        // Single PRB at start
        let riv = encode_riv(0, 1, n).unwrap();
        assert_eq!(decode_riv(riv, n).unwrap(), (0, 1));

        // Single PRB at end
        let riv = encode_riv(n - 1, 1, n).unwrap();
        assert_eq!(decode_riv(riv, n).unwrap(), (n - 1, 1));

        // Full carrier allocation
        let riv = encode_riv(0, n, n).unwrap();
        assert_eq!(decode_riv(riv, n).unwrap(), (0, n));

        // Half carrier transition boundary
        let half = n / 2;
        let riv = encode_riv(0, half, n).unwrap();
        assert_eq!(decode_riv(riv, n).unwrap(), (0, half));

        let riv = encode_riv(0, half + 1, n).unwrap();
        assert_eq!(decode_riv(riv, n).unwrap(), (0, half + 1));

        // Mid-carrier allocation
        let riv = encode_riv(n / 4, n / 3, n).unwrap();
        assert_eq!(decode_riv(riv, n).unwrap(), (n / 4, n / 3));
    }
}

#[test]
fn test_riv_error_conditions() {
    // Zero length
    assert!(encode_riv(0, 0, 50).is_err());
    // Start + len > BWP
    assert!(encode_riv(40, 15, 50).is_err());
    // Out of range RIV
    let n = 50;
    let max_comb = (n * (n + 1)) / 2;
    assert!(decode_riv(max_comb, n as u16).is_err());
    assert!(decode_riv(max_comb + 100, n as u16).is_err());
}

// ---------------------------------------------------------------------------
// 3. Resource Allocation Type 0: RBG Bitmaps Tests
// ---------------------------------------------------------------------------

#[test]
fn test_rbg_size_selection() {
    // Config 1
    assert_eq!(get_rbg_size(20, RbgSizeConfig::Config1), 2);
    assert_eq!(get_rbg_size(50, RbgSizeConfig::Config1), 4);
    assert_eq!(get_rbg_size(100, RbgSizeConfig::Config1), 8);
    assert_eq!(get_rbg_size(273, RbgSizeConfig::Config1), 16);

    // Config 2
    assert_eq!(get_rbg_size(20, RbgSizeConfig::Config2), 4);
    assert_eq!(get_rbg_size(50, RbgSizeConfig::Config2), 8);
    assert_eq!(get_rbg_size(100, RbgSizeConfig::Config2), 16);
    assert_eq!(get_rbg_size(273, RbgSizeConfig::Config2), 16);
}

#[test]
fn test_compute_num_rbgs() {
    // BWP start 0, size 50, P=4 -> ceil(50/4) = 13 RBGs
    assert_eq!(compute_num_rbgs(0, 50, 4), 13);
    // BWP start 1, size 50, P=4 -> offset=1, (50+1+3)/4 = 13 RBGs
    assert_eq!(compute_num_rbgs(1, 50, 4), 13);
    // Zero P returns 0
    assert_eq!(compute_num_rbgs(0, 50, 0), 0);
}

#[test]
fn test_rbg_bitmap_to_prbs() {
    let p_rbg = 4;
    let bwp_start = 0;
    let bwp_size = 12; // Exactly 3 RBGs of 4 PRBs: RBG 0 (PRBs 0..3), RBG 1 (PRBs 4..7), RBG 2 (PRBs 8..11)
    let num_rbgs = 3;

    // Allocate RBG 0 and RBG 2: bitmap = 0b101 = 5
    let bitmap = 0b101;
    let prbs = rbg_bitmap_to_prbs(bitmap, num_rbgs, bwp_start, bwp_size, p_rbg);
    assert_eq!(prbs, vec![0, 1, 2, 3, 8, 9, 10, 11]);

    // Allocate all RBGs: bitmap = 0b111 = 7
    let all_prbs = rbg_bitmap_to_prbs(0b111, num_rbgs, bwp_start, bwp_size, p_rbg);
    assert_eq!(all_prbs.len(), 12);
    assert_eq!(all_prbs, (0..12).collect::<Vec<u16>>());
}

// ---------------------------------------------------------------------------
// 4. DCI Format Serialization / Deserialization Tests
// ---------------------------------------------------------------------------

#[test]
fn test_dci_format_0_0_roundtrip() {
    let riv_bits = compute_riv_bits(50).unwrap();
    let riv = encode_riv(10, 15, 50).unwrap();

    let dci = DciFormat0_0 {
        dci_format_flag: 0,
        riv,
        riv_bits,
        tdra: 3,
        freq_hopping: 1,
        mcs: 19,
        ndi: 1,
        rv: 2,
        harq_pid: 7,
        tpc: 2,
        sul_indicator: Some(1),
    };

    let writer = dci.serialize().unwrap();
    let mut reader = BitReader::new(writer.as_bit_slice());
    let dec = DciFormat0_0::deserialize(&mut reader, riv_bits, true).unwrap();

    assert_eq!(dec, dci);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn test_dci_format_0_0_without_sul() {
    let riv_bits = compute_riv_bits(100).unwrap();
    let riv = encode_riv(0, 100, 100).unwrap();

    let dci = DciFormat0_0 {
        dci_format_flag: 0,
        riv,
        riv_bits,
        tdra: 0,
        freq_hopping: 0,
        mcs: 28,
        ndi: 0,
        rv: 0,
        harq_pid: 0,
        tpc: 1,
        sul_indicator: None,
    };

    let writer = dci.serialize().unwrap();
    let mut reader = BitReader::new(writer.as_bit_slice());
    let dec = DciFormat0_0::deserialize(&mut reader, riv_bits, false).unwrap();

    assert_eq!(dec, dci);
}

#[test]
fn test_dci_format_0_1_roundtrip() {
    let fdra = FdResourceAllocation::Type1Riv {
        riv: 1234,
        num_bits: 13,
    };

    let dci = DciFormat0_1 {
        carrier_indicator: Some(2),
        dci_format_flag: 0,
        bwp_indicator: 1,
        fdra,
        tdra: 5,
        freq_hopping: 1,
        mcs: 22,
        ndi: 1,
        rv: 3,
        harq_pid: 12,
        first_dmrs_seq_init: 1,
        sri: 2,
        sri_bits: 2,
        tpmi: 5,
        tpmi_bits: 4,
        srs_request: 3,
        csi_request: 14,
        csi_request_bits: 4,
        cbgti: Some(0xAA),
        cbgti_bits: 8,
        ptrs_dmrs_assoc: Some(1),
        beta_offset_indicator: Some(2),
        ul_sch_indicator: 1,
    };

    let writer = dci.serialize().unwrap();
    let mut reader = BitReader::new(writer.as_bit_slice());
    let dec = DciFormat0_1::deserialize(
        &mut reader,
        true,  // has_carrier
        true,  // has_bwp
        true,  // fdra_type: Type 1 RIV
        13,    // fdra_bits
        2,     // sri_bits
        4,     // tpmi_bits
        4,     // csi_bits
        8,     // cbgti_bits
        true,  // has_ptrs
        true,  // has_beta
    )
    .unwrap();

    assert_eq!(dec, dci);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn test_dci_format_1_0_roundtrip() {
    let riv_bits = compute_riv_bits(50).unwrap();
    let riv = encode_riv(5, 20, 50).unwrap();

    let dci = DciFormat1_0 {
        dci_format_flag: 1,
        riv,
        riv_bits,
        tdra: 2,
        vrb_to_prb_mapping: 0,
        mcs: 16,
        ndi: 1,
        rv: 1,
        harq_pid: 5,
        dai: 3,
        tpc_pucch: 1,
        pucch_resource_indicator: 4,
        pdsch_to_harq_timing: 2,
    };

    let writer = dci.serialize().unwrap();
    let mut reader = BitReader::new(writer.as_bit_slice());
    let dec = DciFormat1_0::deserialize(&mut reader, riv_bits).unwrap();

    assert_eq!(dec, dci);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn test_dci_format_1_1_roundtrip() {
    let fdra = FdResourceAllocation::Type0Bitmap {
        bitmap: 0b1010101,
        num_bits: 7,
    };

    let dci = DciFormat1_1 {
        carrier_indicator: None,
        dci_format_flag: 1,
        bwp_indicator: 0,
        fdra,
        tdra: 1,
        vrb_to_prb_mapping: 1,
        prb_bundling_indicator: Some(1),
        rate_matching_indicator: Some(2),
        zp_csi_rs_trigger: Some(1),
        mcs: 27,
        ndi: 1,
        rv: 0,
        harq_pid: 8,
        dai: 2,
        tpc_pucch: 3,
        pucch_resource_indicator: 7,
        pdsch_to_harq_timing: 3,
        antenna_ports: 4,
        antenna_port_bits: 5,
        tci_state: Some(6),
        srs_request: 1,
        cbgti: Some(0b1100),
        cbgti_bits: 4,
        cbgfi: Some(1),
    };

    let writer = dci.serialize().unwrap();
    let mut reader = BitReader::new(writer.as_bit_slice());
    let dec = DciFormat1_1::deserialize(
        &mut reader,
        false, // has_carrier
        false, // has_bwp
        false, // fdra_type: Type 0 bitmap
        7,     // fdra_bits
        true,  // has_bundling
        true,  // has_rm
        true,  // has_zp
        5,     // antenna_port_bits
        true,  // has_tci
        4,     // cbgti_bits
        true,  // has_cbgfi
    )
    .unwrap();

    assert_eq!(dec, dci);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn test_dci_format_2_0_sfi() {
    let dci = DciFormat2_0 {
        slot_format_indicators: vec![(15, 6), (42, 9), (7, 4)],
    };

    let writer = dci.serialize().unwrap();
    assert_eq!(writer.len(), 6 + 9 + 4);

    let mut reader = BitReader::new(writer.as_bit_slice());
    let dec = DciFormat2_0::deserialize(&mut reader, &[6, 9, 4]).unwrap();
    assert_eq!(dec, dci);
}

#[test]
fn test_dci_format_2_1_preemption() {
    let dci = DciFormat2_1 {
        preemption_indications: vec![0b10101010101010, 0b00001111000011],
    };

    let writer = dci.serialize().unwrap();
    assert_eq!(writer.len(), 2 * 14);

    let mut reader = BitReader::new(writer.as_bit_slice());
    let dec = DciFormat2_1::deserialize(&mut reader, 2).unwrap();
    assert_eq!(dec, dci);
}

#[test]
fn test_dci_format_2_4_cancellation() {
    let dci = DciFormat2_4 {
        cancellation_indications: vec![(0x1234, 14), (0x2678, 14), (0x9ABC, 16)],
    };

    let writer = dci.serialize().unwrap();
    assert_eq!(writer.len(), 14 + 14 + 16);

    let mut reader = BitReader::new(writer.as_bit_slice());
    let dec = DciFormat2_4::deserialize(&mut reader, &[14, 14, 16]).unwrap();
    assert_eq!(dec, dci);
}

// ---------------------------------------------------------------------------
// 5. DCI Size Alignment and Zero-Padding Tests
// ---------------------------------------------------------------------------

#[test]
fn test_align_dci_0_0_and_1_0_equalization() {
    let mut writer_0_0 = BitWriter::new();
    writer_0_0.push_bits(0x1F, 25); // 25 bits

    let mut writer_1_0 = BitWriter::new();
    writer_1_0.push_bits(0x3F, 30); // 30 bits

    align_dci_0_0_and_1_0(&mut writer_0_0, &mut writer_1_0);

    // Both should be equalized to 30 bits
    assert_eq!(writer_0_0.len(), 30);
    assert_eq!(writer_1_0.len(), 30);
}

#[test]
fn test_forbidden_dci_size_padding() {
    // 32 is in FORBIDDEN_DCI_SIZES
    assert!(is_forbidden_dci_size(32));

    let mut writer_0_0 = BitWriter::new();
    writer_0_0.push_bits(0, 32);

    let mut writer_1_0 = BitWriter::new();
    writer_1_0.push_bits(0, 32);

    align_dci_0_0_and_1_0(&mut writer_0_0, &mut writer_1_0);

    // Should have padded 1 zero to avoid 32 bits -> now 33 bits
    assert_eq!(writer_0_0.len(), 33);
    assert_eq!(writer_1_0.len(), 33);
    assert!(!is_forbidden_dci_size(writer_0_0.len()));
}

#[test]
fn test_avoid_forbidden_size_direct() {
    let mut writer = BitWriter::new();
    writer.push_bits(0x1234, 16); // 16 is forbidden
    assert_eq!(writer.len(), 16);

    avoid_forbidden_size(&mut writer);
    assert_eq!(writer.len(), 17);
    assert!(!is_forbidden_dci_size(writer.len()));
}

// ---------------------------------------------------------------------------
// 6. CRC-24C & RNTI Scrambling Tests
// ---------------------------------------------------------------------------

#[test]
fn test_crc24c_calculation_and_bit_flips() {
    let payload = vec![1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0];
    let crc1 = compute_crc24c(&payload);
    assert_ne!(crc1, 0);

    // 1 bit flip must change the CRC
    let mut flipped_payload = payload.clone();
    flipped_payload[3] ^= 1;
    let crc2 = compute_crc24c(&flipped_payload);
    assert_ne!(crc1, crc2);
}

#[test]
fn test_rnti_scrambling_and_verification_all_rnti_types() {
    let payload = vec![0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1];
    let test_rntis = [
        RntiType::CRnti(0x1234),
        RntiType::CsRnti(0x5678),
        RntiType::McsCRnti(0x9ABC),
        RntiType::TcRnti(0x4321),
        RntiType::RaRnti(0x0005),
        RntiType::PRnti,
        RntiType::SiRnti,
        RntiType::SfiRnti(0x789A),
        RntiType::IntRnti(0xBCDE),
        RntiType::CiRnti(0x2345),
        RntiType::TpcPuschRnti(0x6789),
        RntiType::TpcPucchRnti(0xABCD),
    ];

    for rnti_type in test_rntis {
        let rnti_val = rnti_type.value();
        let encoded = attach_crc24c_and_scramble_rnti(&payload, rnti_val);
        assert_eq!(encoded.len(), payload.len() + 24);

        // Verification with correct RNTI succeeds
        let decoded = verify_crc24c_with_rnti(&encoded, rnti_val).unwrap();
        assert_eq!(decoded, payload);

        // Verification with incorrect RNTI fails
        let wrong_rnti = rnti_val ^ 0x0001;
        assert!(verify_crc24c_with_rnti(&encoded, wrong_rnti).is_err());
    }
}

#[test]
fn test_blind_rnti_extraction() {
    let payload = vec![1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0];
    let original_rnti = 0x8765u16;

    let encoded = attach_crc24c_and_scramble_rnti(&payload, original_rnti);
    let recovered_rnti = extract_scrambled_rnti(&encoded).unwrap();

    assert_eq!(recovered_rnti, original_rnti);
}

#[test]
fn test_blind_rnti_extraction_fails_on_corrupted_payload() {
    let payload = vec![1, 0, 0, 1, 1, 1, 0, 1];
    let original_rnti = 0x5432u16;

    let mut encoded = attach_crc24c_and_scramble_rnti(&payload, original_rnti);
    // Corrupt one bit in the payload
    encoded[2] ^= 1;

    // Blind extraction should either fail top-8 bit check or produce mismatched CRC
    let res = extract_scrambled_rnti(&encoded);
    if let Ok(recovered) = res {
        // If it extracted an RNTI, verify that it doesn't match original
        assert_ne!(recovered, original_rnti);
    }
}

// ---------------------------------------------------------------------------
// 7. Binary Wire Framing (DciWirePdu) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = DciWirePdu {
        format_type: DciWireFormatType::Format1_0,
        rnti: 0x4321,
        bit_length: 39,
        payload_bytes: vec![0x12, 0x34, 0x56, 0x78, 0x90],
    };

    let wire_bytes = pdu.to_wire_bytes();
    assert!(wire_bytes.len() >= 14);

    let decoded = DciWirePdu::from_wire_bytes(&wire_bytes).unwrap();
    assert_eq!(decoded, pdu);
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = DciWirePdu {
        format_type: DciWireFormatType::Format0_0,
        rnti: 0x1111,
        bit_length: 28,
        payload_bytes: vec![0xAB, 0xCD, 0xEF],
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    // Corrupt magic
    wire_bytes[0] = 0xFF;

    assert!(matches!(
        DciWirePdu::from_wire_bytes(&wire_bytes),
        Err(DciError::InvalidWireMagic(_))
    ));
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = DciWirePdu {
        format_type: DciWireFormatType::Format0_1,
        rnti: 0x2222,
        bit_length: 45,
        payload_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    let len = wire_bytes.len();
    // Corrupt payload byte
    wire_bytes[len - 4] ^= 0x55;

    assert!(matches!(
        DciWirePdu::from_wire_bytes(&wire_bytes),
        Err(DciError::CrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_truncated() {
    let pdu = DciWirePdu {
        format_type: DciWireFormatType::Format2_0,
        rnti: 0x3333,
        bit_length: 19,
        payload_bytes: vec![0x11, 0x22, 0x33],
    };

    let wire_bytes = pdu.to_wire_bytes();
    let truncated = &wire_bytes[..10];

    assert!(matches!(
        DciWirePdu::from_wire_bytes(truncated),
        Err(DciError::WirePayloadTooShort { .. })
    ));
}

//! Integration tests for 3GPP Rel-18/19 5G-Advanced LDPC Soft-Decision Decoder & HARQ Soft Combiner Engine.
//! Validates:
//! - Standard lifting size sets (Table 5.3.2-1) and index decomposition ($i_{LS} \in [0, 7]$).
//! - Base Graph 1 and Base Graph 2 structure, dimensions, and quasi-cyclic expansion.
//! - Systematic QC-LDPC encoding and parity-check equation satisfaction.
//! - Layered Normalized Min-Sum (NMS) decoding with fast syndrome early stopping.
//! - Error correction capability under bit flips and noisy soft channel LLRs.
//! - Soft LLR circular buffer de-rate-matching across Redundancy Versions (RV 0, 2, 3, 1).
//! - HARQ soft combining (Chase Combining & Incremental Redundancy).
//! - Binary wire framing (`LdpcDecoderWirePdu`) with CRC-16 CCITT integrity.

use toy_tcpip::nr_ldpc_decoder::{
    DEFAULT_NMS_FACTOR, HarqSoftBuffer, LDPC_LIFTING_SIZES, LdpcBaseGraph, LdpcDecoderConfig,
    LdpcDecoderEngine, LdpcDecoderError, LdpcDecoderWirePdu, LdpcEncoder, NUM_PUNCTURED_COLUMNS,
    compute_crc24a, compute_crc24b, de_rate_match, get_lifting_set_index, get_rv_k0_offset,
};

// ---------------------------------------------------------------------------
// 1. Lifting Set Index & Base Graph Tests
// ---------------------------------------------------------------------------

#[test]
fn test_lifting_set_indices_all_sets() {
    // Set 0: a = 2 (powers of 2)
    assert_eq!(get_lifting_set_index(2).unwrap(), 0);
    assert_eq!(get_lifting_set_index(4).unwrap(), 0);
    assert_eq!(get_lifting_set_index(8).unwrap(), 0);
    assert_eq!(get_lifting_set_index(16).unwrap(), 0);
    assert_eq!(get_lifting_set_index(32).unwrap(), 0);
    assert_eq!(get_lifting_set_index(64).unwrap(), 0);
    assert_eq!(get_lifting_set_index(128).unwrap(), 0);
    assert_eq!(get_lifting_set_index(256).unwrap(), 0);

    // Set 1: a = 3
    assert_eq!(get_lifting_set_index(3).unwrap(), 1);
    assert_eq!(get_lifting_set_index(6).unwrap(), 1);
    assert_eq!(get_lifting_set_index(12).unwrap(), 1);
    assert_eq!(get_lifting_set_index(24).unwrap(), 1);
    assert_eq!(get_lifting_set_index(48).unwrap(), 1);
    assert_eq!(get_lifting_set_index(96).unwrap(), 1);
    assert_eq!(get_lifting_set_index(192).unwrap(), 1);
    assert_eq!(get_lifting_set_index(384).unwrap(), 1);

    // Set 2: a = 5
    assert_eq!(get_lifting_set_index(5).unwrap(), 2);
    assert_eq!(get_lifting_set_index(10).unwrap(), 2);
    assert_eq!(get_lifting_set_index(20).unwrap(), 2);
    assert_eq!(get_lifting_set_index(40).unwrap(), 2);
    assert_eq!(get_lifting_set_index(80).unwrap(), 2);
    assert_eq!(get_lifting_set_index(160).unwrap(), 2);
    assert_eq!(get_lifting_set_index(320).unwrap(), 2);

    // Set 3: a = 7
    assert_eq!(get_lifting_set_index(7).unwrap(), 3);
    assert_eq!(get_lifting_set_index(14).unwrap(), 3);
    assert_eq!(get_lifting_set_index(28).unwrap(), 3);
    assert_eq!(get_lifting_set_index(56).unwrap(), 3);

    // Set 4: a = 9
    assert_eq!(get_lifting_set_index(9).unwrap(), 4);
    assert_eq!(get_lifting_set_index(18).unwrap(), 4);
    assert_eq!(get_lifting_set_index(36).unwrap(), 4);

    // Set 5: a = 11
    assert_eq!(get_lifting_set_index(11).unwrap(), 5);
    assert_eq!(get_lifting_set_index(22).unwrap(), 5);
    assert_eq!(get_lifting_set_index(44).unwrap(), 5);

    // Set 6: a = 13
    assert_eq!(get_lifting_set_index(13).unwrap(), 6);
    assert_eq!(get_lifting_set_index(26).unwrap(), 6);
    assert_eq!(get_lifting_set_index(52).unwrap(), 6);

    // Set 7: a = 15
    assert_eq!(get_lifting_set_index(15).unwrap(), 7);
    assert_eq!(get_lifting_set_index(30).unwrap(), 7);
    assert_eq!(get_lifting_set_index(60).unwrap(), 7);

    // Invalid sizes
    assert!(get_lifting_set_index(1).is_err());
    assert!(get_lifting_set_index(17).is_err());
    assert!(get_lifting_set_index(500).is_err());
}

#[test]
fn test_all_51_lifting_sizes_valid() {
    for &zc in &LDPC_LIFTING_SIZES {
        let set_idx = get_lifting_set_index(zc);
        assert!(set_idx.is_ok(), "Failed for Zc={}", zc);
        assert!(set_idx.unwrap() < 8);
    }
}

#[test]
fn test_base_graph_dimensions() {
    assert_eq!(LdpcBaseGraph::BG1.num_info_columns(), 22);
    assert_eq!(LdpcBaseGraph::BG1.num_total_columns(), 68);
    assert_eq!(LdpcBaseGraph::BG1.num_check_rows(), 46);

    assert_eq!(LdpcBaseGraph::BG2.num_info_columns(), 10);
    assert_eq!(LdpcBaseGraph::BG2.num_total_columns(), 52);
    assert_eq!(LdpcBaseGraph::BG2.num_check_rows(), 42);
}

// ---------------------------------------------------------------------------
// 2. Systematic QC-LDPC Encoding & Syndrome Satisfaction Tests
// ---------------------------------------------------------------------------

#[test]
fn test_systematic_encoding_syndrome_satisfied_bg1() {
    let z_c = 8;
    let encoder = LdpcEncoder::new(LdpcBaseGraph::BG1, z_c).unwrap();
    let k = (LdpcBaseGraph::BG1.num_info_columns() - NUM_PUNCTURED_COLUMNS) * z_c; // (22-2)*8 = 160 bits

    // Arbitrary information bit pattern
    let mut info_bits = vec![0u8; k];
    for i in 0..k {
        info_bits[i] = ((i * 7 + 3) % 2) as u8;
    }

    let codeword = encoder.encode(&info_bits).unwrap();
    assert_eq!(codeword.len(), 68 * z_c);

    // Verify systematic bits preserved
    let sys_start = NUM_PUNCTURED_COLUMNS * z_c;
    assert_eq!(&codeword[sys_start..sys_start + k], &info_bits[..]);

    // Ideal channel: map bits to high-confidence LLRs (0 -> +10.0, 1 -> -10.0)
    let mut channel_llrs = vec![0.0f32; codeword.len()];
    for (i, &b) in codeword.iter().enumerate() {
        // Punctured first 2*Zc bits must have 0.0 LLR
        if i >= sys_start {
            channel_llrs[i] = if b == 0 { 10.0 } else { -10.0 };
        }
    }

    let config = LdpcDecoderConfig {
        base_graph: LdpcBaseGraph::BG1,
        z_c,
        max_iterations: 10,
        norm_factor: DEFAULT_NMS_FACTOR,
        early_stopping: true,
    };
    let decoder = LdpcDecoderEngine::new(config).unwrap();
    let result = decoder.decode(&channel_llrs).unwrap();

    assert!(result.syndrome_satisfied);
    assert_eq!(
        result.iterations_used, 1,
        "Clean LLRs should converge in 1 iteration"
    );
    assert_eq!(result.systematic_bits, info_bits);
}

#[test]
fn test_systematic_encoding_syndrome_satisfied_bg2() {
    let z_c = 10;
    let encoder = LdpcEncoder::new(LdpcBaseGraph::BG2, z_c).unwrap();
    let k = (LdpcBaseGraph::BG2.num_info_columns() - NUM_PUNCTURED_COLUMNS) * z_c; // (10-2)*10 = 80 bits

    let mut info_bits = vec![0u8; k];
    for i in 0..k {
        info_bits[i] = ((i * 13 + 5) % 2) as u8;
    }

    let codeword = encoder.encode(&info_bits).unwrap();
    assert_eq!(codeword.len(), 52 * z_c);

    let sys_start = NUM_PUNCTURED_COLUMNS * z_c;
    let mut channel_llrs = vec![0.0f32; codeword.len()];
    for (i, &b) in codeword.iter().enumerate() {
        if i >= sys_start {
            channel_llrs[i] = if b == 0 { 8.0 } else { -8.0 };
        }
    }

    let config = LdpcDecoderConfig {
        base_graph: LdpcBaseGraph::BG2,
        z_c,
        max_iterations: 10,
        norm_factor: DEFAULT_NMS_FACTOR,
        early_stopping: true,
    };
    let decoder = LdpcDecoderEngine::new(config).unwrap();
    let result = decoder.decode(&channel_llrs).unwrap();

    assert!(result.syndrome_satisfied);
    assert_eq!(result.systematic_bits, info_bits);
}

// ---------------------------------------------------------------------------
// 3. Error Correction Capability Under Bit Flips
// ---------------------------------------------------------------------------

#[test]
fn test_error_correction_under_channel_bit_flips() {
    let z_c = 12;
    let encoder = LdpcEncoder::new(LdpcBaseGraph::BG1, z_c).unwrap();
    let k = (22 - NUM_PUNCTURED_COLUMNS) * z_c; // 240 bits

    let mut info_bits = vec![0u8; k];
    for i in 0..k {
        info_bits[i] = ((i * 17 + 1) % 2) as u8;
    }

    let codeword = encoder.encode(&info_bits).unwrap();
    let sys_start = NUM_PUNCTURED_COLUMNS * z_c;

    let mut channel_llrs = vec![0.0f32; codeword.len()];
    for (i, &b) in codeword.iter().enumerate() {
        if i >= sys_start {
            channel_llrs[i] = if b == 0 { 4.0 } else { -4.0 };
        }
    }

    // Invert/flip several LLRs to simulate channel bit errors
    let flip_indices = [
        sys_start + 5,
        sys_start + 19,
        sys_start + 45,
        sys_start + 110,
    ];
    for &idx in &flip_indices {
        channel_llrs[idx] = -channel_llrs[idx]; // Bit flip!
    }

    let config = LdpcDecoderConfig {
        base_graph: LdpcBaseGraph::BG1,
        z_c,
        max_iterations: 15,
        norm_factor: 0.8,
        early_stopping: true,
    };
    let decoder = LdpcDecoderEngine::new(config).unwrap();
    let result = decoder.decode(&channel_llrs).unwrap();

    // Verify all flipped bits were corrected!
    assert!(result.syndrome_satisfied, "Decoder should converge");
    assert_eq!(
        result.systematic_bits, info_bits,
        "All information bits must be correctly recovered"
    );
}

// ---------------------------------------------------------------------------
// 4. Soft LLR De-Rate Matching Tests
// ---------------------------------------------------------------------------

#[test]
fn test_rv_k0_offsets_bg1_and_bg2() {
    let z_c = 16;
    let n_cb_bg1 = 66 * z_c;
    assert_eq!(
        get_rv_k0_offset(0, LdpcBaseGraph::BG1, z_c, n_cb_bg1).unwrap(),
        0
    );
    assert_eq!(
        get_rv_k0_offset(2, LdpcBaseGraph::BG1, z_c, n_cb_bg1).unwrap(),
        17 * z_c
    );
    assert_eq!(
        get_rv_k0_offset(3, LdpcBaseGraph::BG1, z_c, n_cb_bg1).unwrap(),
        33 * z_c
    );
    assert_eq!(
        get_rv_k0_offset(1, LdpcBaseGraph::BG1, z_c, n_cb_bg1).unwrap(),
        56 * z_c
    );

    let n_cb_bg2 = 50 * z_c;
    assert_eq!(
        get_rv_k0_offset(0, LdpcBaseGraph::BG2, z_c, n_cb_bg2).unwrap(),
        0
    );
    assert_eq!(
        get_rv_k0_offset(2, LdpcBaseGraph::BG2, z_c, n_cb_bg2).unwrap(),
        13 * z_c
    );
    assert_eq!(
        get_rv_k0_offset(3, LdpcBaseGraph::BG2, z_c, n_cb_bg2).unwrap(),
        25 * z_c
    );
    assert_eq!(
        get_rv_k0_offset(1, LdpcBaseGraph::BG2, z_c, n_cb_bg2).unwrap(),
        43 * z_c
    );

    // Invalid RV
    assert!(get_rv_k0_offset(4, LdpcBaseGraph::BG1, z_c, n_cb_bg1).is_err());
}

#[test]
fn test_rate_match_and_de_rate_match_roundtrip() {
    let z_c = 8;
    let encoder = LdpcEncoder::new(LdpcBaseGraph::BG1, z_c).unwrap();
    let k = (22 - NUM_PUNCTURED_COLUMNS) * z_c;

    let info_bits = vec![1u8; k];
    let codeword = encoder.encode(&info_bits).unwrap();

    let e_bits = 66 * z_c; // Exactly 1 circular buffer cycle
    let tx_bits = encoder.rate_match(&codeword, 0, e_bits).unwrap();
    assert_eq!(tx_bits.len(), e_bits);

    // Convert bits to soft LLRs: 0 -> +5.0, 1 -> -5.0
    let rx_llrs: Vec<f32> = tx_bits
        .iter()
        .map(|&b| if b == 0 { 5.0 } else { -5.0 })
        .collect();

    let de_rm_llrs = de_rate_match(&rx_llrs, 0, LdpcBaseGraph::BG1, z_c).unwrap();
    assert_eq!(de_rm_llrs.len(), 68 * z_c);

    // Punctured columns must be 0.0
    for i in 0..NUM_PUNCTURED_COLUMNS * z_c {
        assert_eq!(de_rm_llrs[i], 0.0);
    }

    // Decoder check
    let decoder = LdpcDecoderEngine::new(LdpcDecoderConfig {
        base_graph: LdpcBaseGraph::BG1,
        z_c,
        ..Default::default()
    })
    .unwrap();
    let result = decoder.decode(&de_rm_llrs).unwrap();
    assert!(result.syndrome_satisfied);
    assert_eq!(result.systematic_bits, info_bits);
}

// ---------------------------------------------------------------------------
// 5. HARQ Soft Combining Tests (Chase Combining & Incremental Redundancy)
// ---------------------------------------------------------------------------

#[test]
fn test_harq_soft_chase_combining() {
    let z_c = 10;
    let mut harq_buf = HarqSoftBuffer::new(LdpcBaseGraph::BG2, z_c);
    assert_eq!(harq_buf.num_transmissions, 0);

    let e_bits = 50 * z_c;
    // Low SNR transmission 1 (weak LLRs = +1.0)
    let tx1_llrs = vec![1.0f32; e_bits];
    let combined_1 = harq_buf.combine(&tx1_llrs, 0).unwrap();
    assert_eq!(harq_buf.num_transmissions, 1);

    // Check sample magnitude
    let test_idx = NUM_PUNCTURED_COLUMNS * z_c + 5;
    assert_eq!(combined_1[test_idx], 1.0);

    // Retransmission with same RV0 (Chase Combining)
    let tx2_llrs = vec![1.5f32; e_bits];
    let combined_2 = harq_buf.combine(&tx2_llrs, 0).unwrap();
    assert_eq!(harq_buf.num_transmissions, 2);

    // LLRs should accumulate (1.0 + 1.5 = 2.5)
    assert_eq!(combined_2[test_idx], 2.5);
}

#[test]
fn test_harq_incremental_redundancy_and_reset() {
    let z_c = 8;
    let mut harq_buf = HarqSoftBuffer::new(LdpcBaseGraph::BG1, z_c);

    let e_bits = 20 * z_c;
    // Transmission 1 with RV 0
    let llrs_rv0 = vec![2.0f32; e_bits];
    harq_buf.combine(&llrs_rv0, 0).unwrap();

    // Transmission 2 with RV 2 (Incremental Redundancy)
    let llrs_rv2 = vec![2.0f32; e_bits];
    let combined = harq_buf.combine(&llrs_rv2, 2).unwrap();
    assert_eq!(harq_buf.num_transmissions, 2);
    assert_eq!(combined.len(), 68 * z_c);

    // Reset buffer (NDI toggle)
    harq_buf.reset();
    assert_eq!(harq_buf.num_transmissions, 0);
    assert!(harq_buf.buffer.iter().all(|&x| x == 0.0));
}

// ---------------------------------------------------------------------------
// 6. CRC Verification Tests
// ---------------------------------------------------------------------------

#[test]
fn test_crc24a_and_crc24b_calculations() {
    let payload = vec![1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1];
    let crc_a = compute_crc24a(&payload);
    let crc_b = compute_crc24b(&payload);

    assert_ne!(crc_a, 0);
    assert_ne!(crc_b, 0);
    assert_ne!(crc_a, crc_b);

    // Bit flip changes CRC
    let mut flipped = payload.clone();
    flipped[2] ^= 1;
    assert_ne!(compute_crc24a(&flipped), crc_a);
    assert_ne!(compute_crc24b(&flipped), crc_b);
}

// ---------------------------------------------------------------------------
// 7. Binary Wire Framing (LdpcDecoderWirePdu) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = LdpcDecoderWirePdu {
        base_graph: 1,
        z_c: 24,
        iterations_used: 3,
        syndrome_ok: 1,
        payload_bytes: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };

    let wire_bytes = pdu.to_wire_bytes();
    assert!(wire_bytes.len() >= 14);

    let decoded = LdpcDecoderWirePdu::from_wire_bytes(&wire_bytes).unwrap();
    assert_eq!(decoded, pdu);
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = LdpcDecoderWirePdu {
        base_graph: 2,
        z_c: 16,
        iterations_used: 2,
        syndrome_ok: 1,
        payload_bytes: vec![0xAA, 0xBB],
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[0] = 0x00;

    assert!(matches!(
        LdpcDecoderWirePdu::from_wire_bytes(&wire_bytes),
        Err(LdpcDecoderError::InvalidWireMagic(_))
    ));
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = LdpcDecoderWirePdu {
        base_graph: 1,
        z_c: 32,
        iterations_used: 5,
        syndrome_ok: 1,
        payload_bytes: vec![0x01, 0x02, 0x03, 0x04],
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    let len = wire_bytes.len();
    wire_bytes[len - 3] ^= 0xFF; // Corrupt payload byte

    assert!(matches!(
        LdpcDecoderWirePdu::from_wire_bytes(&wire_bytes),
        Err(LdpcDecoderError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_truncated() {
    let pdu = LdpcDecoderWirePdu {
        base_graph: 1,
        z_c: 8,
        iterations_used: 1,
        syndrome_ok: 1,
        payload_bytes: vec![0x99],
    };

    let wire_bytes = pdu.to_wire_bytes();
    let truncated = &wire_bytes[..10];

    assert!(matches!(
        LdpcDecoderWirePdu::from_wire_bytes(truncated),
        Err(LdpcDecoderError::WirePayloadTooShort { .. })
    ));
}

//! Integration and unit tests for 3GPP Rel-18/19 5G-Advanced PDSCH LDPC Segmentation,
//! Rate Matching & Code Block Group (CBG) Engine.

use toy_tcpip::nr_pdsch_ldpc::*;

#[test]
fn test_crc24a_crc24b_and_crc16_algorithms() {
    let test_bits = vec![
        1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0,
        0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
    ];

    let crc24a = compute_crc24a(&test_bits);
    let crc24b = compute_crc24b(&test_bits);
    let crc16 = compute_crc16_bits(&test_bits);

    // CRC values must be within valid bit-widths
    assert!(crc24a <= 0x00FF_FFFF);
    assert!(crc24b <= 0x00FF_FFFF);

    // Different generator polynomials must yield distinct parity words
    assert_ne!(crc24a, crc24b);

    // Single bit flip detection test
    let mut corrupted_bits = test_bits.clone();
    corrupted_bits[5] ^= 1;
    let crc24a_corrupted = compute_crc24a(&corrupted_bits);
    let crc24b_corrupted = compute_crc24b(&corrupted_bits);
    let crc16_corrupted = compute_crc16_bits(&corrupted_bits);

    assert_ne!(crc24a, crc24a_corrupted);
    assert_ne!(crc24b, crc24b_corrupted);
    assert_ne!(crc16, crc16_corrupted);
}

#[test]
fn test_ldpc_base_graph_selection_criteria() {
    // 1. A <= 292 bits -> always BG2
    assert_eq!(select_base_graph(100, 0.8).unwrap(), LdpcBaseGraph::BG2);
    assert_eq!(select_base_graph(292, 0.9).unwrap(), LdpcBaseGraph::BG2);

    // 2. A <= 3824 bits and R <= 0.67 -> BG2
    assert_eq!(select_base_graph(1000, 0.5).unwrap(), LdpcBaseGraph::BG2);
    assert_eq!(select_base_graph(3824, 0.65).unwrap(), LdpcBaseGraph::BG2);

    // 3. A <= 3824 bits but R > 0.67 -> BG1
    assert_eq!(select_base_graph(1000, 0.75).unwrap(), LdpcBaseGraph::BG1);
    assert_eq!(select_base_graph(3824, 0.8).unwrap(), LdpcBaseGraph::BG1);

    // 4. A > 3824 bits and R <= 0.25 -> BG2 (low code rate)
    assert_eq!(select_base_graph(5000, 0.2).unwrap(), LdpcBaseGraph::BG2);

    // 5. A > 3824 bits and R > 0.25 -> BG1 (high throughput)
    assert_eq!(select_base_graph(5000, 0.5).unwrap(), LdpcBaseGraph::BG1);
    assert_eq!(select_base_graph(20000, 0.85).unwrap(), LdpcBaseGraph::BG1);

    // Invalid parameters
    assert!(select_base_graph(0, 0.5).is_err());
    assert!(select_base_graph(100, 0.0).is_err());
    assert!(select_base_graph(100, 1.5).is_err());
}

#[test]
fn test_lifting_size_zc_selection() {
    // For BG1: Kb = 22
    let kb = 22;

    // If K' = 100, minimum Z_c such that 22 * Z_c >= 100 is Z_c = 5 (22*5 = 110 >= 100)
    let zc1 = find_lifting_size(kb, 100).unwrap();
    assert_eq!(zc1, 5);

    // If K' = 8448, 8448 / 22 = 384
    let zc_max = find_lifting_size(kb, 8448).unwrap();
    assert_eq!(zc_max, 384);

    // Beyond max capacity
    assert!(find_lifting_size(kb, 22 * 384 + 1).is_err());
}

#[test]
fn test_code_block_segmentation_single_vs_multiple_cb() {
    // 1. Single Code Block: small TB (A = 2000 bits <= 3824, R = 0.5 -> BG2)
    // B = 2000 + 16 (CRC16) = 2016 bits <= 3840 (max CB for BG2) -> C = 1, cb_crc = 0
    let seg_single = segment_transport_block(2000, 0.5).expect("Segmentation succeeds");
    assert_eq!(seg_single.base_graph, LdpcBaseGraph::BG2);
    assert_eq!(seg_single.num_code_blocks, 1);
    assert_eq!(seg_single.tb_crc_length, 16);
    assert_eq!(seg_single.cb_crc_length, 0);
    assert_eq!(seg_single.k_prime, 2016);
    assert!(seg_single.k_info_bits >= seg_single.k_prime);

    // 2. Multiple Code Blocks: large TB (A = 20000 bits > 3824, R = 0.75 -> BG1)
    // B = 20000 + 24 (CRC24A) = 20024 bits
    // K_cb = 8448, L_cb = 24 => (K_cb - L_cb) = 8424
    // C = ceil(20024 / 8424) = 3
    // B' = 20024 + 3 * 24 = 20096
    // K' = 20096 / 3 = 6698
    let seg_multi = segment_transport_block(20000, 0.75).expect("Segmentation succeeds");
    assert_eq!(seg_multi.base_graph, LdpcBaseGraph::BG1);
    assert_eq!(seg_multi.num_code_blocks, 3);
    assert_eq!(seg_multi.tb_crc_length, 24);
    assert_eq!(seg_multi.cb_crc_length, 24);
    assert_eq!(seg_multi.k_prime, 20096 / 3);
    assert!(seg_multi.k_info_bits >= seg_multi.k_prime);
    assert_eq!(
        seg_multi.filler_bits,
        seg_multi.k_info_bits - seg_multi.k_prime
    );
}

#[test]
fn test_circular_buffer_rate_matching_k0_positions() {
    let zc = 16;
    let n_cb = 66 * zc; // BG1 buffer size = 1056 bits

    // RV0 -> k0 must be 0
    let k0_rv0 = compute_k0(LdpcBaseGraph::BG1, zc, n_cb, 0).unwrap();
    assert_eq!(k0_rv0, 0);

    // RV2 -> k0 = floor(17 * 1056 / 1056) * 16 = 17 * 16 = 272
    let k0_rv2 = compute_k0(LdpcBaseGraph::BG1, zc, n_cb, 2).unwrap();
    assert_eq!(k0_rv2, 17 * zc);

    // RV3 -> k0 = 33 * 16 = 528
    let k0_rv3 = compute_k0(LdpcBaseGraph::BG1, zc, n_cb, 3).unwrap();
    assert_eq!(k0_rv3, 33 * zc);

    // RV1 -> k0 = 56 * 16 = 896
    let k0_rv1 = compute_k0(LdpcBaseGraph::BG1, zc, n_cb, 1).unwrap();
    assert_eq!(k0_rv1, 56 * zc);

    // Invalid RV
    assert!(compute_k0(LdpcBaseGraph::BG1, zc, n_cb, 4).is_err());
}

#[test]
fn test_rate_match_bit_extraction_with_filler_skipping() {
    let circular_buffer = vec![10, 20, 30, 40, 50, 60, 70, 80];
    let filler_indices = vec![2, 5]; // Indices 2 (val 30) and 5 (val 60) are NULL bits

    // Extract 6 bits starting at k0 = 0
    let extracted = rate_match_extract(&circular_buffer, 0, 6, &filler_indices);

    // Should skip indices 2 and 5:
    // idx 0 -> 10
    // idx 1 -> 20
    // idx 2 -> skip
    // idx 3 -> 40
    // idx 4 -> 50
    // idx 5 -> skip
    // idx 6 -> 70
    // idx 7 -> 80
    assert_eq!(extracted, vec![10, 20, 40, 50, 70, 80]);
}

#[test]
fn test_cbg_partitioning_and_selective_retransmission_savings() {
    let cbg_mgr = CbgManager::new(4).unwrap(); // 4 CBGs

    // Partition 10 code blocks into 4 CBGs
    // 10 % 4 = 2 -> First 2 groups have 3 CBs, remaining 2 groups have 2 CBs
    let partitions = cbg_mgr.partition_cbgs(10);
    assert_eq!(partitions.len(), 4);
    assert_eq!(partitions[0], vec![0, 1, 2]);
    assert_eq!(partitions[1], vec![3, 4, 5]);
    assert_eq!(partitions[2], vec![6, 7]);
    assert_eq!(partitions[3], vec![8, 9]);

    // Error scenario: Only code block #1 (in CBG 0) is corrupted
    let mut cb_errors = vec![false; 10];
    cb_errors[1] = true;

    let (failed_cbgs, retrans_cbs, savings) = cbg_mgr.evaluate_retransmission(10, &cb_errors);
    assert_eq!(failed_cbgs, vec![0]);
    assert_eq!(retrans_cbs, 3); // Only CBG 0 (3 CBs) retransmitted
    assert_eq!(savings, 0.70);  // 70% radio resource savings over full TB retransmission!

    // Worst case: Errors in CBG 0 and CBG 2
    cb_errors[6] = true;
    let (failed_multi, retrans_multi, savings_multi) =
        cbg_mgr.evaluate_retransmission(10, &cb_errors);
    assert_eq!(failed_multi, vec![0, 2]);
    assert_eq!(retrans_multi, 5); // 3 + 2 = 5 CBs
    assert_eq!(savings_multi, 0.50); // 50% savings
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = LdpcPdschPdu {
        version: 1,
        tb_size_bytes: 2500,
        base_graph: 1,
        num_code_blocks: 3,
        z_c: 120,
        filler_bits: 44,
        redundancy_version: 0,
        cbg_count: 4,
        failed_cbg_mask: 0x01, // CBG 0 failed
        savings_percent: 75,
    };

    let bytes = pdu.to_bytes();
    assert_eq!(bytes.len(), LdpcPdschPdu::WIRE_SIZE);

    // Decode roundtrip
    let decoded = LdpcPdschPdu::from_bytes(&bytes).expect("Decoding succeeds");
    assert_eq!(decoded, pdu);

    // CRC corruption test
    let mut corrupted = bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(matches!(
        LdpcPdschPdu::from_bytes(&corrupted),
        Err(LdpcError::CrcMismatch { .. })
    ));

    // Bad magic test
    let mut bad_magic = bytes.clone();
    bad_magic[0] = 0x00;
    assert!(matches!(
        LdpcPdschPdu::from_bytes(&bad_magic),
        Err(LdpcError::InvalidMagic(_))
    ));
}

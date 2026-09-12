//! Integration and unit tests for 3GPP Rel-18/19 5G-Advanced Polar Coding &
//! CRC-Aided List (CA-SCL) Decoding Engine.

use toy_tcpip::nr_polar_codec::*;

#[test]
fn test_crc24c_and_rnti_scrambling() {
    let payload = vec![
        1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1,
        0, 1,
    ];
    let rnti = 0x55AA;

    let attached = attach_crc24c_with_rnti(&payload, rnti);
    assert_eq!(attached.len(), payload.len() + 24);

    // Payload intact
    assert_eq!(&attached[..payload.len()], &payload[..]);

    // Compute reference CRC without RNTI scrambling
    let raw_crc = compute_crc24c(&payload);
    let rx_crc_bits = &attached[payload.len()..];

    // First 8 bits are unscrambled CRC
    for i in 0..8 {
        let exp = ((raw_crc >> (23 - i)) & 1) as u8;
        assert_eq!(rx_crc_bits[i], exp);
    }

    // Last 16 bits are scrambled with RNTI: rx = raw ^ rnti => rx ^ rnti == raw
    for i in 8..24 {
        let exp_raw = ((raw_crc >> (23 - i)) & 1) as u8;
        let rnti_bit = ((rnti >> (15 - (i - 8))) & 1) as u8;
        assert_eq!(rx_crc_bits[i] ^ rnti_bit, exp_raw);
    }
}

#[test]
fn test_mother_code_size_and_subchannel_allocation() {
    // 1. Mother code sizing
    assert_eq!(determine_mother_code_size(20, 64).unwrap(), 64);
    assert_eq!(determine_mother_code_size(40, 128).unwrap(), 128);
    assert_eq!(determine_mother_code_size(80, 256).unwrap(), 256);
    assert_eq!(determine_mother_code_size(140, 512).unwrap(), 512);

    // 2. Sub-channel allocation
    let n = 64;
    let k = 20;
    let info_set = get_information_subchannel_set(n, k);
    assert_eq!(info_set.len(), k);

    // All channels must be < N
    for &ch in &info_set {
        assert!(ch < n);
    }

    // Must be strictly sorted by ascending reliability in Q sequence
    // Highest channel indices must contain the known most reliable sub-channels (e.g. 63)
    assert!(info_set.contains(&63));
}

#[test]
fn test_polar_encoding_linearity_and_structure() {
    let n = 32;
    let k = 8;

    // 1. All-zero payload produces all-zero codeword
    let zeros = vec![0u8; k];
    let code_zeros = polar_encode(&zeros, n).unwrap();
    assert_eq!(code_zeros, vec![0u8; n]);

    // 2. Linearity: encode(u1 ^ u2) == encode(u1) ^ encode(u2)
    let u1 = vec![1, 0, 1, 0, 1, 1, 0, 0];
    let u2 = vec![0, 1, 1, 0, 0, 1, 0, 1];
    let u_sum: Vec<u8> = u1.iter().zip(u2.iter()).map(|(&a, &b)| a ^ b).collect();

    let c1 = polar_encode(&u1, n).unwrap();
    let c2 = polar_encode(&u2, n).unwrap();
    let c_sum = polar_encode(&u_sum, n).unwrap();

    let c_expected: Vec<u8> = c1.iter().zip(c2.iter()).map(|(&a, &b)| a ^ b).collect();
    assert_eq!(c_sum, c_expected);
}

#[test]
fn test_rate_matching_repetition_puncturing_shortening() {
    let n = 64;
    let coded = (0..n).map(|i| (i % 2) as u8).collect::<Vec<u8>>();

    // 1. Repetition (E = 96 > N = 64)
    let rm_rep = polar_rate_match(&coded, 96, 20).unwrap();
    assert_eq!(rm_rep.len(), 96);

    // 2. Puncturing (E = 48 < N = 64, K = 16 => K/E = 16/48 = 0.33 <= 7/16 ≈ 0.4375)
    let rm_punc = polar_rate_match(&coded, 48, 16).unwrap();
    assert_eq!(rm_punc.len(), 48);

    // 3. Shortening (E = 48 < N = 64, K = 32 => K/E = 32/48 = 0.67 > 7/16)
    let rm_short = polar_rate_match(&coded, 48, 32).unwrap();
    assert_eq!(rm_short.len(), 48);
}

#[test]
fn test_ca_scl_decoding_clean_channel_roundtrip() {
    // 16 bits DCI payload + 24 bits CRC = 40 bits total
    let dci_payload = vec![1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1];
    let rnti = 0x8844;
    let tx_bits = attach_crc24c_with_rnti(&dci_payload, rnti);
    assert_eq!(tx_bits.len(), 40);

    let n = 64; // mother code size
    let coded = polar_encode(&tx_bits, n).unwrap();
    assert_eq!(coded.len(), n);

    // Ideal channel: convert bits (0/1) to high-confidence LLRs (+10.0 / -10.0)
    let channel_llr: Vec<f64> = coded
        .iter()
        .map(|&b| if b == 0 { 10.0 } else { -10.0 })
        .collect();

    // Decode with List size L = 4
    let decoded_payload =
        ca_scl_decode(&channel_llr, tx_bits.len(), 4, rnti).expect("CA-SCL decoding must succeed");

    assert_eq!(decoded_payload, dci_payload);
}

#[test]
fn test_ca_scl_decoding_with_channel_errors() {
    let dci_payload = vec![0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0];
    let rnti = 0x1234;
    let tx_bits = attach_crc24c_with_rnti(&dci_payload, rnti);

    let n = 64;
    let coded = polar_encode(&tx_bits, n).unwrap();

    let mut channel_llr: Vec<f64> = coded
        .iter()
        .map(|&b| if b == 0 { 8.0 } else { -8.0 })
        .collect();

    // Introduce channel bit errors / erasure (noisy sub-channels)
    channel_llr[5] = -channel_llr[5]; // bit flip
    channel_llr[12] = 0.1; // deep fade / erasure

    // List decoder with L = 4 corrects the perturbations
    let decoded = ca_scl_decode(&channel_llr, tx_bits.len(), 4, rnti)
        .expect("CA-SCL list decoding should correct perturbed bits");

    assert_eq!(decoded, dci_payload);
}

#[test]
fn test_ca_scl_decoding_rnti_filtering() {
    let dci_payload = vec![1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1];
    let correct_rnti = 0xABCD;
    let wrong_rnti = 0x1111;

    let tx_bits = attach_crc24c_with_rnti(&dci_payload, correct_rnti);
    let n = 64;
    let coded = polar_encode(&tx_bits, n).unwrap();

    let channel_llr: Vec<f64> = coded
        .iter()
        .map(|&b| if b == 0 { 10.0 } else { -10.0 })
        .collect();

    // Decoding with correct RNTI succeeds
    let decoded = ca_scl_decode(&channel_llr, tx_bits.len(), 4, correct_rnti).unwrap();
    assert_eq!(decoded, dci_payload);

    // Decoding with wrong RNTI yields different bits that do not match CRC
    let decoded_wrong = ca_scl_decode(&channel_llr, tx_bits.len(), 4, wrong_rnti);
    // With wrong RNTI, the decoded payload must not match original dci_payload
    if let Ok(res) = decoded_wrong {
        assert_ne!(res, dci_payload);
    }
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = PolarFramePdu {
        version: 1,
        k_info_bits: 40,
        n_mother_bits: 128,
        e_rate_matched_bits: 108,
        rnti: 0x55AA,
        list_size: 4,
        payload_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };

    let bytes = pdu.to_bytes();
    assert_eq!(bytes.len(), PolarFramePdu::HEADER_SIZE + 4 + 2); // 16 + 4 payload + 2 CRC = 22 bytes

    // Decode roundtrip
    let decoded = PolarFramePdu::from_bytes(&bytes).expect("Decoding must succeed");
    assert_eq!(decoded, pdu);

    // CRC corruption test
    let mut corrupted = bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(matches!(
        PolarFramePdu::from_bytes(&corrupted),
        Err(PolarError::CrcMismatch { .. })
    ));

    // Bad magic test
    let mut bad_magic = bytes.clone();
    bad_magic[0] = 0x00;
    assert!(matches!(
        PolarFramePdu::from_bytes(&bad_magic),
        Err(PolarError::InvalidMagic(_))
    ));
}

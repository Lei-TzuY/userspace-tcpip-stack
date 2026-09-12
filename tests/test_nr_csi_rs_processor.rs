//! Integration tests for 3GPP Rel-18/19 CSI-RS Processor & Type I Codebook Engine.

use toy_tcpip::nr_csi_rs_processor::{
    CSIRS_WIRE_MAGIC, Complex64, CsiRsCdmType, CsiRsWirePdu, Type1CodebookConfig,
    evaluate_csi_feedback, generate_cdm_cover_code, generate_csi_rs_sequence,
    get_csi_rs_row_config,
};

#[test]
fn test_csi_rs_gold_sequence_and_unit_power() {
    let seq = generate_csi_rs_sequence(5, 9, 300, 48);
    assert_eq!(seq.len(), 48);

    for sym in &seq {
        let pwr = sym.norm_sqr();
        assert!(
            (pwr - 1.0).abs() < 1e-6,
            "Expected unit power 1.0, got {}",
            pwr
        );
    }
}

#[test]
fn test_csi_rs_row_configs_and_ports() {
    let r1 = get_csi_rs_row_config(1).unwrap();
    assert_eq!(r1.num_ports, 1);
    assert_eq!(r1.density, 3);
    assert_eq!(r1.cdm_type, CsiRsCdmType::NoCdm);

    let r3 = get_csi_rs_row_config(3).unwrap();
    assert_eq!(r3.num_ports, 2);
    assert_eq!(r3.cdm_type, CsiRsCdmType::FdCdm2);

    let r4 = get_csi_rs_row_config(4).unwrap();
    assert_eq!(r4.num_ports, 4);

    let r6 = get_csi_rs_row_config(6).unwrap();
    assert_eq!(r6.num_ports, 8);
    assert_eq!(r6.cdm_type, CsiRsCdmType::Cdm4Fd2Td2);

    let r11 = get_csi_rs_row_config(11).unwrap();
    assert_eq!(r11.num_ports, 16);

    let r16 = get_csi_rs_row_config(16).unwrap();
    assert_eq!(r16.num_ports, 32);
    assert_eq!(r16.cdm_type, CsiRsCdmType::Cdm8Fd2Td4);

    // Invalid row rejected
    assert!(get_csi_rs_row_config(99).is_err());
}

#[test]
fn test_cdm_orthogonal_cover_codes() {
    // FdCdm2: port 0 vs port 1
    let (wf0, _wt0) = generate_cdm_cover_code(CsiRsCdmType::FdCdm2, 0);
    let (wf1, _wt1) = generate_cdm_cover_code(CsiRsCdmType::FdCdm2, 1);
    assert_eq!(wf0, vec![1.0, 1.0]);
    assert_eq!(wf1, vec![1.0, -1.0]);

    // Dot product must be zero
    let dot: f64 = wf0.iter().zip(wf1.iter()).map(|(&a, &b)| a * b).sum();
    assert_eq!(dot, 0.0);

    // Cdm4: check all 4 orthogonal pairs
    for p_a in 0..4 {
        for p_b in 0..4 {
            let (wfa, wta) = generate_cdm_cover_code(CsiRsCdmType::Cdm4Fd2Td2, p_a);
            let (wfb, wtb) = generate_cdm_cover_code(CsiRsCdmType::Cdm4Fd2Td2, p_b);

            // 2D Kronecker product cover code
            let mut code_a = Vec::new();
            for &t in &wta {
                for &f in &wfa {
                    code_a.push(t * f);
                }
            }
            let mut code_b = Vec::new();
            for &t in &wtb {
                for &f in &wfb {
                    code_b.push(t * f);
                }
            }

            let inner: f64 = code_a.iter().zip(code_b.iter()).map(|(&a, &b)| a * b).sum();
            if p_a == p_b {
                assert_eq!(inner, 4.0); // self energy
            } else {
                assert_eq!(inner, 0.0); // strictly orthogonal
            }
        }
    }
}

#[test]
fn test_type1_codebook_beamforming_and_cophasing() {
    // 8 ports: N1 = 2, N2 = 2 => P = 2 * 2 * 2 = 8
    let cb = Type1CodebookConfig::new(2, 2).unwrap();
    assert_eq!(cb.total_ports(), 8);

    // Rank 1 precoder
    let w_rank1 = cb.generate_rank1_precoder(1, 0, 2);
    assert_eq!(w_rank1.len(), 8);

    let total_pwr: f64 = w_rank1.iter().map(|c| c.norm_sqr()).sum();
    assert!((total_pwr - 1.0).abs() < 1e-6);

    // Rank 2 precoder
    let (col1, col2) = cb.generate_rank2_precoder(0, 1, 1);
    assert_eq!(col1.len(), 8);
    assert_eq!(col2.len(), 8);

    let pwr1: f64 = col1.iter().map(|c| c.norm_sqr()).sum();
    let pwr2: f64 = col2.iter().map(|c| c.norm_sqr()).sum();
    assert!((pwr1 - 0.5).abs() < 1e-6);
    assert!((pwr2 - 0.5).abs() < 1e-6);

    // Orthogonality between column 1 and column 2
    let mut cross = Complex64::new(0.0, 0.0);
    for (a, b) in col1.iter().zip(col2.iter()) {
        cross = cross.add(&a.mul(&b.conj()));
    }
    assert!(
        cross.norm_sqr().sqrt() < 1e-6,
        "Rank 2 columns must be orthogonal"
    );
}

#[test]
fn test_end_to_end_csi_feedback_evaluation() {
    // 4 antenna ports (N1=2, N2=1)
    let cb = Type1CodebookConfig::new(2, 1).unwrap();
    assert_eq!(cb.total_ports(), 4);

    // Construct synthetic channel aligned with beam l=3, m=0, coph=1
    let target_precoder = cb.generate_rank1_precoder(3, 0, 1);

    // 2 RX antennas
    let mut channel_h = vec![vec![Complex64::new(0.0, 0.0); 4]; 2];
    for rx in 0..2 {
        for port in 0..4 {
            // Channel matches conjugate of target precoder for maximum beamforming gain
            channel_h[rx][port] = target_precoder[port].conj().scale(2.0);
        }
    }

    let noise_power = 0.01;
    let report = evaluate_csi_feedback(&channel_h, &cb, noise_power).unwrap();

    // PMI should match the optimal direction
    assert_eq!(report.pmi, (3, 0, 1));
    assert!(report.effective_sinr_db > 20.0);
    assert!(report.cqi >= 14); // High CQI for strong channel
    assert_eq!(report.ri, 2); // Multi-antenna high SNR selects Rank 2
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = CsiRsWirePdu {
        magic: CSIRS_WIRE_MAGIC,
        slot_idx: 120,
        row_index: 6,
        num_ports: 8,
        cdm_type: 2, // Cdm4Fd2Td2
        density: 1,
        n_id_csi: 450,
        ri: 2,
        cqi: 12,
        pmi_l: 3,
        pmi_m: 1,
        pmi_coph: 2,
        payload: vec![0xCA, 0xFE, 0x01, 0x02, 0x03],
        crc16: 0,
    };

    let serialized = pdu.serialize();
    assert_eq!(&serialized[..4], &[0x43, 0x53, 0x49, 0x52]); // "CSIR"

    // Successful deserialization
    let deserialized = CsiRsWirePdu::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.slot_idx, 120);
    assert_eq!(deserialized.row_index, 6);
    assert_eq!(deserialized.num_ports, 8);
    assert_eq!(deserialized.ri, 2);
    assert_eq!(deserialized.cqi, 12);
    assert_eq!(deserialized.payload, pdu.payload);

    // Tampered payload fails CRC
    let mut corrupted = serialized.clone();
    corrupted[23] ^= 0x80;
    assert!(CsiRsWirePdu::deserialize(&corrupted).is_err());
}

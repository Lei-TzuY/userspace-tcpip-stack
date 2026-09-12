//! Integration tests for 3GPP Rel-18/19 5G-Advanced Initial Cell Search, PSS/SSS Synchronization, CFO Estimation & Beam Timing Acquisition Engine.
//! Validates:
//! - PSS sequence generation and auto/cross-correlation properties for $N_{\text{ID}}^{(2)} \in \{0, 1, 2\}$.
//! - PSS sliding cross-correlation timing detection and false alarm rejection (PSLR).
//! - Fractional Carrier Frequency Offset (FCFO) estimation and phase rotation correction.
//! - SSS cross-correlation and full Physical Cell ID (PCI $N_{\text{ID}}^{\text{cell}} \in [0, 1007]$) derivation.
//! - PBCH DMRS hypothesis testing identifying transmitted SSB beam index.
//! - SS-RSRP, SS-RSSI, SS-RSRQ, and SS-SINR measurement calculations.
//! - Binary wire framing (`CellSearchWirePdu`) with CRC-16 CCITT validation.

use toy_tcpip::nr_cell_search::{
    CellSearchError, CellSearchWirePdu, Complex32, SYNC_SEQUENCE_LENGTH, apply_cfo_correction,
    compute_ss_measurements, detect_pss, detect_ssb_beam_index, detect_sss,
    estimate_fractional_cfo, generate_pss_sequence, generate_sss_sequence,
};

// ---------------------------------------------------------------------------
// 1. PSS Sequence Generation & Auto/Cross-Correlation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_pss_sequence_properties_and_orthogonality() {
    let pss0 = generate_pss_sequence(0).unwrap();
    let pss1 = generate_pss_sequence(1).unwrap();
    let pss2 = generate_pss_sequence(2).unwrap();

    assert_eq!(pss0.len(), SYNC_SEQUENCE_LENGTH);
    assert_eq!(pss1.len(), SYNC_SEQUENCE_LENGTH);
    assert_eq!(pss2.len(), SYNC_SEQUENCE_LENGTH);

    // Sequence elements must be strictly +1 or -1 (BPSK)
    for &val in pss0.iter().chain(pss1.iter()).chain(pss2.iter()) {
        assert!(val == 1 || val == -1);
    }

    // Auto-correlation at lag 0 must equal 127
    let auto_corr0: i32 = pss0.iter().map(|&v| (v as i32) * (v as i32)).sum();
    assert_eq!(auto_corr0, 127);

    // Cross-correlation between different PSS sequences must be low
    let cross_01: i32 = pss0
        .iter()
        .zip(pss1.iter())
        .map(|(&a, &b)| (a as i32) * (b as i32))
        .sum();
    let cross_02: i32 = pss0
        .iter()
        .zip(pss2.iter())
        .map(|(&a, &b)| (a as i32) * (b as i32))
        .sum();
    let cross_12: i32 = pss1
        .iter()
        .zip(pss2.iter())
        .map(|(&a, &b)| (a as i32) * (b as i32))
        .sum();

    assert!(
        cross_01.abs() <= 35,
        "Cross-correlation between PSS 0 and 1 must be small: {}",
        cross_01
    );
    assert!(
        cross_02.abs() <= 35,
        "Cross-correlation between PSS 0 and 2 must be small: {}",
        cross_02
    );
    assert!(
        cross_12.abs() <= 35,
        "Cross-correlation between PSS 1 and 2 must be small: {}",
        cross_12
    );

    // Invalid N_ID^(2) returns error
    assert_eq!(
        generate_pss_sequence(3),
        Err(CellSearchError::InvalidNid2(3))
    );
}

// ---------------------------------------------------------------------------
// 2. PSS Sliding Cross-Correlation Timing & False Alarm Rejection Tests
// ---------------------------------------------------------------------------

#[test]
fn test_pss_sliding_cross_correlation_and_timing_detection() {
    let target_nid2 = 1u8;
    let pss_ref = generate_pss_sequence(target_nid2).unwrap();

    let target_offset = 37usize;
    let total_samples = 250usize;
    let mut rx_buf = vec![Complex32::zero(); total_samples];

    // Embed PSS at target_offset with additive noise
    for n in 0..SYNC_SEQUENCE_LENGTH {
        rx_buf[target_offset + n] = Complex32::new(pss_ref[n] as f32, 0.0);
    }

    // Add small noise
    for s in &mut rx_buf {
        s.re += 0.05;
        s.im += -0.05;
    }

    let result = detect_pss(&rx_buf, 100, 3.0).unwrap();
    assert_eq!(result.timing_offset, target_offset);
    assert_eq!(result.nid2, target_nid2);
    assert!(
        result.pslr > 5.0,
        "PSLR must be high on true peak: {}",
        result.pslr
    );
}

#[test]
fn test_pss_noise_rejection_false_alarm() {
    // Pure noise buffer
    let mut noise_buf = vec![Complex32::zero(); 200];
    for (i, s) in noise_buf.iter_mut().enumerate() {
        let phase = (i as f32) * 1.7;
        s.re = phase.cos() * 0.1;
        s.im = phase.sin() * 0.1;
    }

    // With a high threshold, no peak should be accepted
    let res = detect_pss(&noise_buf, 50, 10.0);
    assert!(matches!(res, Err(CellSearchError::NoPeakDetected { .. })));
}

// ---------------------------------------------------------------------------
// 3. Carrier Frequency Offset (CFO) Estimation & Phase Rotation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_cfo_estimation_and_phase_rotation() {
    let distance = 16usize;
    let normalized_cfo = 0.015f32; // Delta_f * T_s = 0.015 (< 1 / (2 * distance) = 0.03125)
    let two_pi = 2.0 * std::f32::consts::PI;

    let mut seg_a = vec![Complex32::zero(); 32];
    let mut seg_b = vec![Complex32::zero(); 32];

    for i in 0..32 {
        let base = Complex32::new(1.0, 0.5);
        let phase_a = two_pi * normalized_cfo * (i as f32);
        let phase_b = two_pi * normalized_cfo * ((i + distance) as f32);

        seg_a[i] = base.mul(Complex32::new(phase_a.cos(), phase_a.sin()));
        seg_b[i] = base.mul(Complex32::new(phase_b.cos(), phase_b.sin()));
    }

    let estimated_cfo = estimate_fractional_cfo(&seg_a, &seg_b, distance).unwrap();
    assert!(
        (estimated_cfo - normalized_cfo).abs() < 1e-4,
        "Estimated CFO ({}) must match true CFO ({})",
        estimated_cfo,
        normalized_cfo
    );

    // Apply compensation to seg_b
    let corrected_b = apply_cfo_correction(&seg_b, estimated_cfo);
    assert_eq!(corrected_b.len(), seg_b.len());
}

// ---------------------------------------------------------------------------
// 4. SSS Cross-Correlation & Full Physical Cell ID (PCI) Derivation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_sss_detection_and_full_pci_derivation() {
    let test_cases = [
        (0u16, 0u8, 0u16),      // PCI = 0
        (166u16, 2u8, 500u16),  // PCI = 3 * 166 + 2 = 500
        (335u16, 2u8, 1007u16), // PCI = 3 * 335 + 2 = 1007
    ];

    for (target_nid1, nid2, expected_pci) in test_cases {
        let sss_seq = generate_sss_sequence(target_nid1, nid2).unwrap();
        let mut rx_subcarriers = Vec::with_capacity(SYNC_SEQUENCE_LENGTH);
        for &s in &sss_seq {
            rx_subcarriers.push(Complex32::new(s as f32, 0.0));
        }

        let res = detect_sss(&rx_subcarriers, nid2).unwrap();
        assert_eq!(res.nid1, target_nid1, "Detected N_ID^(1) mismatch");
        assert_eq!(res.pci, expected_pci, "Derived PCI mismatch");
        assert!(res.correlation_metric > 10000.0);
    }
}

// ---------------------------------------------------------------------------
// 5. PBCH DMRS Hypothesis Testing & SSB Beam Index Detector Tests
// ---------------------------------------------------------------------------

#[test]
fn test_pbch_dmrs_ssb_beam_index_detection() {
    let pci = 500u16;
    let target_beam_index = 3u8;
    let l_max = 8u8;

    // Synthesize reference DMRS for target_beam_index
    let pci_div4 = (pci / 4) as u32;
    let pci_mod4 = (pci % 4) as u32;
    let issb_p1 = (target_beam_index + 1) as u32;
    let term1 = ((1 << 11) * issb_p1 * (pci_div4 + 1)) & 0x7FFF_FFFF;
    let term2 = ((1 << 6) * issb_p1 + pci_mod4) & 0x7FFF_FFFF;
    let c_init = (term1 + term2) & 0x7FFF_FFFF;

    let mut x1 = [0u8; 31];
    let mut x2 = [0u8; 31];
    x1[0] = 1;
    for i in 0..31 {
        x2[i] = ((c_init >> i) & 1) as u8;
    }
    for _ in 0..1600 {
        let new_x1 = x1[3] ^ x1[0];
        let new_x2 = x2[3] ^ x2[2] ^ x2[1] ^ x2[0];
        x1.copy_within(1..31, 0);
        x1[30] = new_x1;
        x2.copy_within(1..31, 0);
        x2[30] = new_x2;
    }

    let inv_sqrt2 = 1.0 / std::f32::consts::SQRT_2;
    let mut rx_dmrs = Vec::with_capacity(72);
    for _ in 0..72 {
        let new_x1 = x1[3] ^ x1[0];
        let new_x2 = x2[3] ^ x2[2] ^ x2[1] ^ x2[0];
        let c0 = x1[0] ^ x2[0];
        x1.copy_within(1..31, 0);
        x1[30] = new_x1;
        x2.copy_within(1..31, 0);
        x2[30] = new_x2;

        let new_x1b = x1[3] ^ x1[0];
        let new_x2b = x2[3] ^ x2[2] ^ x2[1] ^ x2[0];
        let c1 = x1[0] ^ x2[0];
        x1.copy_within(1..31, 0);
        x1[30] = new_x1b;
        x2.copy_within(1..31, 0);
        x2[30] = new_x2b;

        rx_dmrs.push(Complex32::new(
            inv_sqrt2 * (1.0 - 2.0 * (c0 as f32)),
            inv_sqrt2 * (1.0 - 2.0 * (c1 as f32)),
        ));
    }

    let detected_beam = detect_ssb_beam_index(&rx_dmrs, pci, l_max).unwrap();
    assert_eq!(detected_beam, target_beam_index);
}

// ---------------------------------------------------------------------------
// 6. SS-RSRP, SS-RSSI, SS-RSRQ & SS-SINR Measurement Tests
// ---------------------------------------------------------------------------

#[test]
fn test_ss_measurements_calculation() {
    let sss_len = 127;
    let ssb_len = 240;

    // Unit power symbols: |s|^2 = 1.0
    let sss_subs = vec![Complex32::new(1.0, 0.0); sss_len];
    let ssb_subs = vec![Complex32::new(1.0, 0.0); ssb_len];
    let noise_lin = 0.05f32; // 5% noise power

    let meas = compute_ss_measurements(&sss_subs, &ssb_subs, noise_lin).unwrap();

    // RSRP: power per RE = 1.0 -> 10 * log10(1.0 / 0.001) = 30 dBm
    assert!((meas.ss_rsrp_dbm - 30.0).abs() < 1e-4);

    // RSSI: total power across 240 REs = 240 -> 10 * log10(240 / 0.001) = 53.802 dBm
    assert!((meas.ss_rssi_dbm - 53.802).abs() < 0.05);

    // RSRQ: 20 * RSRP / RSSI = 20 * 1.0 / 240 = 1 / 12 = -10.79 dB
    assert!((meas.ss_rsrq_db - (-10.79)).abs() < 0.05);

    // SINR: (1.0 - 0.05) / 0.05 = 0.95 / 0.05 = 19.0 -> 10 * log10(19) = 12.787 dB
    assert!((meas.ss_sinr_db - 12.787).abs() < 0.05);
}

// ---------------------------------------------------------------------------
// 7. Binary Wire Framing (CellSearchWirePdu) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = CellSearchWirePdu {
        pci: 789,
        timing_offset: 1042,
        ssb_beam_index: 5,
        cfo_hz: 1250.0,
        ss_rsrp_dbm: -82.4,
        ss_sinr_db: 18.6,
    };

    let wire_bytes = pdu.to_wire_bytes();
    assert_eq!(wire_bytes.len(), 25);

    let decoded = CellSearchWirePdu::from_wire_bytes(&wire_bytes).unwrap();
    assert_eq!(decoded.pci, pdu.pci);
    assert_eq!(decoded.timing_offset, pdu.timing_offset);
    assert_eq!(decoded.ssb_beam_index, pdu.ssb_beam_index);
    assert!((decoded.cfo_hz - pdu.cfo_hz).abs() < 1e-3);
    assert!((decoded.ss_rsrp_dbm - pdu.ss_rsrp_dbm).abs() < 1e-3);
    assert!((decoded.ss_sinr_db - pdu.ss_sinr_db).abs() < 1e-3);
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = CellSearchWirePdu {
        pci: 12,
        timing_offset: 0,
        ssb_beam_index: 0,
        cfo_hz: 0.0,
        ss_rsrp_dbm: -90.0,
        ss_sinr_db: 10.0,
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[0] = 0xAA;

    assert!(matches!(
        CellSearchWirePdu::from_wire_bytes(&wire_bytes),
        Err(CellSearchError::InvalidWireMagic(_))
    ));
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = CellSearchWirePdu {
        pci: 45,
        timing_offset: 200,
        ssb_beam_index: 1,
        cfo_hz: -500.0,
        ss_rsrp_dbm: -75.0,
        ss_sinr_db: 22.0,
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[10] ^= 0x55; // Corrupt payload byte

    assert!(matches!(
        CellSearchWirePdu::from_wire_bytes(&wire_bytes),
        Err(CellSearchError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_truncated() {
    let pdu = CellSearchWirePdu {
        pci: 1,
        timing_offset: 0,
        ssb_beam_index: 0,
        cfo_hz: 0.0,
        ss_rsrp_dbm: 0.0,
        ss_sinr_db: 0.0,
    };

    let wire_bytes = pdu.to_wire_bytes();
    let truncated = &wire_bytes[..20];

    assert!(matches!(
        CellSearchWirePdu::from_wire_bytes(truncated),
        Err(CellSearchError::WirePayloadTooShort { .. })
    ));
}

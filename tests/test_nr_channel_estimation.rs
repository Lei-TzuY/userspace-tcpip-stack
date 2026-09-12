//! Integration tests for 3GPP Rel-18/19 5G-Advanced Channel Estimation, DMRS Processing & MMSE-IRC Equalizer Engine.
//! Validates:
//! - Complex32 arithmetic and Matrix linear algebra (multiplication, Hermitian, 1x1, 2x2, 4x4 inversion).
//! - 3GPP 31-bit Gold sequence generator and QPSK reference symbol generation.
//! - DMRS Type 1 and Type 2 port configurations and Orthogonal Cover Codes (OCC).
//! - Least-Squares (LS) raw pilot channel estimation and multi-port OCC de-spreading.
//! - 1D/2D frequency-domain channel interpolation across PRBs.
//! - Interference-plus-noise covariance ($R_{IN}$) estimation.
//! - MIMO Equalization: Zero-Forcing, MMSE, and MMSE-IRC with post-equalization SINR.
//! - Binary wire framing (`ChannelEstimationWirePdu`) with CRC-16 CCITT validation.

use toy_tcpip::nr_channel_estimation::{
    ChannelEstimationError, ChannelEstimationWirePdu, Complex32, ComplexMatrix, DmrsConfigType,
    DmrsPortInfo, EqualizerType, GoldSequenceGenerator, MimoEqualizer, SUBCARRIERS_PER_PRB,
    estimate_pilot_channel_ls, estimate_rin_covariance, get_dmrs_subcarriers,
    interpolate_channel_frequency,
};

// ---------------------------------------------------------------------------
// 1. Complex32 Arithmetic Tests
// ---------------------------------------------------------------------------

#[test]
fn test_complex32_basic_math_and_inversion() {
    let a = Complex32::new(3.0, 4.0);
    let b = Complex32::new(1.0, -2.0);

    // Addition & Subtraction
    let sum = a + b;
    assert_eq!(sum, Complex32::new(4.0, 2.0));
    let diff = a - b;
    assert_eq!(diff, Complex32::new(2.0, 6.0));

    // Multiplication
    // (3 + 4i)(1 - 2i) = 3 - 6i + 4i - 8(-1) = 11 - 2i
    let prod = a * b;
    assert_eq!(prod, Complex32::new(11.0, -2.0));

    // Norm squared and norm
    assert_eq!(a.norm_sqr(), 25.0);
    assert_eq!(a.norm(), 5.0);

    // Conjugate
    assert_eq!(a.conj(), Complex32::new(3.0, -4.0));

    // Inversion: 1 / (3 + 4i) = (3 - 4i) / 25 = 0.12 - 0.16i
    let inv = a.inv().unwrap();
    assert!((inv.re - 0.12).abs() < 1e-6);
    assert!((inv.im - (-0.16)).abs() < 1e-6);

    // Division: a / b = a * inv(b)
    let quot = a / b;
    let expected_quot = a * b.inv().unwrap();
    assert!((quot.re - expected_quot.re).abs() < 1e-6);
    assert!((quot.im - expected_quot.im).abs() < 1e-6);

    // Division by zero returns zero without crashing
    let zero = Complex32::zero();
    assert_eq!(a / zero, Complex32::zero());
    assert!(zero.inv().is_none());
}

// ---------------------------------------------------------------------------
// 2. Complex Matrix Algebra Tests
// ---------------------------------------------------------------------------

#[test]
fn test_complex_matrix_multiplication_hermitian_and_identity() {
    let mut m = ComplexMatrix::zeros(2, 2);
    m.set(0, 0, Complex32::new(1.0, 1.0));
    m.set(0, 1, Complex32::new(2.0, 0.0));
    m.set(1, 0, Complex32::new(0.0, -1.0));
    m.set(1, 1, Complex32::new(3.0, 2.0));

    // Identity matrix product
    let eye = ComplexMatrix::eye(2);
    let m_eye = m.matmul(&eye).unwrap();
    assert_eq!(m, m_eye);

    // Hermitian transpose
    let m_h = m.hermitian();
    assert_eq!(m_h.get(0, 0), Complex32::new(1.0, -1.0));
    assert_eq!(m_h.get(0, 1), Complex32::new(0.0, 1.0));
    assert_eq!(m_h.get(1, 0), Complex32::new(2.0, 0.0));
    assert_eq!(m_h.get(1, 1), Complex32::new(3.0, -2.0));
}

#[test]
fn test_complex_matrix_inversion_1x1_and_2x2() {
    // 1x1 matrix
    let mut m1 = ComplexMatrix::zeros(1, 1);
    m1.set(0, 0, Complex32::new(2.0, 4.0));
    let inv1 = m1.inverse().unwrap();
    let prod1 = m1.matmul(&inv1).unwrap();
    assert!((prod1.get(0, 0).re - 1.0).abs() < 1e-5);
    assert!(prod1.get(0, 0).im.abs() < 1e-5);

    // 2x2 matrix
    let mut m2 = ComplexMatrix::zeros(2, 2);
    m2.set(0, 0, Complex32::new(2.0, 1.0));
    m2.set(0, 1, Complex32::new(1.0, -1.0));
    m2.set(1, 0, Complex32::new(-1.0, 2.0));
    m2.set(1, 1, Complex32::new(3.0, 0.0));

    let inv2 = m2.inverse().unwrap();
    let prod2 = m2.matmul(&inv2).unwrap();

    // Check identity
    assert!((prod2.get(0, 0).re - 1.0).abs() < 1e-4);
    assert!(prod2.get(0, 0).im.abs() < 1e-4);
    assert!(prod2.get(0, 1).norm() < 1e-4);
    assert!(prod2.get(1, 0).norm() < 1e-4);
    assert!((prod2.get(1, 1).re - 1.0).abs() < 1e-4);
    assert!(prod2.get(1, 1).im.abs() < 1e-4);
}

#[test]
fn test_complex_matrix_inversion_4x4_gauss_jordan() {
    let mut m4 = ComplexMatrix::eye(4);
    // Introduce off-diagonal terms
    m4.set(0, 1, Complex32::new(0.5, 0.2));
    m4.set(1, 2, Complex32::new(-0.3, 0.4));
    m4.set(2, 3, Complex32::new(0.2, -0.1));
    m4.set(3, 0, Complex32::new(-0.4, 0.2));

    let inv4 = m4.inverse().unwrap();
    let prod4 = m4.matmul(&inv4).unwrap();

    for r in 0..4 {
        for c in 0..4 {
            let val = prod4.get(r, c);
            if r == c {
                assert!((val.re - 1.0).abs() < 1e-3);
                assert!(val.im.abs() < 1e-3);
            } else {
                assert!(val.norm() < 1e-3);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. 3GPP Gold Sequence & DMRS Port Configuration Tests
// ---------------------------------------------------------------------------

#[test]
fn test_gold_sequence_generator_and_qpsk_symbols() {
    let c_init = GoldSequenceGenerator::compute_c_init(0, 2, 500, 0);
    assert_ne!(c_init, 0);

    let mut gold_gen = GoldSequenceGenerator::new(c_init);
    let symbols = gold_gen.generate_qpsk_symbols(24);
    assert_eq!(symbols.len(), 24);

    // Each QPSK symbol must have unit power: |r(m)|^2 = 1.0
    for s in symbols {
        assert!((s.norm_sqr() - 1.0).abs() < 1e-5);
    }
}

#[test]
fn test_dmrs_port_info_lookup() {
    // Type 1 Ports
    let p1000 = DmrsPortInfo::get_type1_port(1000).unwrap();
    assert_eq!(p1000.cdm_group, 0);
    assert_eq!(p1000.delta, 0);
    assert_eq!(p1000.wf, [1, 1]);

    let p1001 = DmrsPortInfo::get_type1_port(1001).unwrap();
    assert_eq!(p1001.cdm_group, 0);
    assert_eq!(p1001.delta, 0);
    assert_eq!(p1001.wf, [1, -1]);

    let p1002 = DmrsPortInfo::get_type1_port(1002).unwrap();
    assert_eq!(p1002.cdm_group, 1);
    assert_eq!(p1002.delta, 1);

    // Type 2 Ports
    let p2_1004 = DmrsPortInfo::get_type2_port(1004).unwrap();
    assert_eq!(p2_1004.cdm_group, 2);
    assert_eq!(p2_1004.delta, 4);

    // Invalid port
    assert!(DmrsPortInfo::get_type1_port(2000).is_err());
    assert!(DmrsPortInfo::get_type2_port(1006).is_err());
}

#[test]
fn test_dmrs_subcarrier_allocation() {
    let num_prbs = 4;
    // Type 1: 6 pilots per PRB -> 24 subcarriers
    let sc_type1 = get_dmrs_subcarriers(DmrsConfigType::Type1, num_prbs, 0);
    assert_eq!(sc_type1.len(), 24);
    assert_eq!(sc_type1[0], 0);
    assert_eq!(sc_type1[1], 2);
    assert_eq!(sc_type1[2], 4);
    assert_eq!(sc_type1[3], 6);

    // Type 2: 4 pilots per PRB -> 16 subcarriers
    let sc_type2 = get_dmrs_subcarriers(DmrsConfigType::Type2, num_prbs, 0);
    assert_eq!(sc_type2.len(), 16);
    assert_eq!(sc_type2[0], 0);
    assert_eq!(sc_type2[1], 1);
}

// ---------------------------------------------------------------------------
// 4. LS Channel Estimation & OCC De-spreading Tests
// ---------------------------------------------------------------------------

#[test]
fn test_pilot_channel_ls_and_occ_orthogonality() {
    let num_prbs = 2;
    let total_sc = num_prbs * SUBCARRIERS_PER_PRB;
    let subcarriers = get_dmrs_subcarriers(DmrsConfigType::Type1, num_prbs, 0);

    let c_init = GoldSequenceGenerator::compute_c_init(0, 2, 100, 0);
    let mut gold_gen = GoldSequenceGenerator::new(c_init);
    let ref_symbols = gold_gen.generate_qpsk_symbols(subcarriers.len() / 2);

    // Channel for Port 1000: h1 = 0.8 + 0.6i
    // Channel for Port 1001: h2 = -0.5 + 0.5i
    let h1 = Complex32::new(0.8, 0.6);
    let h2 = Complex32::new(-0.5, 0.5);

    let port1000 = DmrsPortInfo::get_type1_port(1000).unwrap();
    let port1001 = DmrsPortInfo::get_type1_port(1001).unwrap();

    let mut rx_grid = vec![Complex32::zero(); total_sc];

    // Transmit superimposed pilots from both ports on the same REs using OCC
    for pair in 0..(subcarriers.len() / 2) {
        let k0 = subcarriers[pair * 2];
        let k1 = subcarriers[pair * 2 + 1];
        let r = ref_symbols[pair];

        // Port 1000 (wf = [+1, +1])
        let tx1_0 = r.scale(port1000.wf[0] as f32);
        let tx1_1 = r.scale(port1000.wf[1] as f32);

        // Port 1001 (wf = [+1, -1])
        let tx2_0 = r.scale(port1001.wf[0] as f32);
        let tx2_1 = r.scale(port1001.wf[1] as f32);

        // Superimposed received signal Y = H1 * X1 + H2 * X2
        rx_grid[k0] = h1 * tx1_0 + h2 * tx2_0;
        rx_grid[k1] = h1 * tx1_1 + h2 * tx2_1;
    }

    // Estimate Port 1000 via OCC de-spreading
    let est1 = estimate_pilot_channel_ls(&rx_grid, &ref_symbols, &subcarriers, port1000.wf);
    for &(_, val) in &est1 {
        assert!((val.re - h1.re).abs() < 1e-4);
        assert!((val.im - h1.im).abs() < 1e-4);
    }

    // Estimate Port 1001 via OCC de-spreading
    let est2 = estimate_pilot_channel_ls(&rx_grid, &ref_symbols, &subcarriers, port1001.wf);
    for &(_, val) in &est2 {
        assert!((val.re - h2.re).abs() < 1e-4);
        assert!((val.im - h2.im).abs() < 1e-4);
    }
}

// ---------------------------------------------------------------------------
// 5. 2D Frequency Channel Interpolation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_frequency_channel_interpolation() {
    let total_sc = 24;
    let pilot_estimates = vec![
        (4, Complex32::new(1.0, 0.0)),
        (16, Complex32::new(2.0, 1.0)),
    ];

    let full_h = interpolate_channel_frequency(&pilot_estimates, total_sc);
    assert_eq!(full_h.len(), total_sc);

    // Boundary flat extrapolation before first pilot (k <= 4)
    for k in 0..=4 {
        assert_eq!(full_h[k], Complex32::new(1.0, 0.0));
    }

    // Midpoint between k=4 and k=16 (k=10): alpha = 6/12 = 0.5
    // re = 0.5 * 1.0 + 0.5 * 2.0 = 1.5, im = 0.5 * 0.0 + 0.5 * 1.0 = 0.5
    assert!((full_h[10].re - 1.5).abs() < 1e-5);
    assert!((full_h[10].im - 0.5).abs() < 1e-5);

    // Boundary flat extrapolation after last pilot (k >= 16)
    for k in 16..total_sc {
        assert_eq!(full_h[k], Complex32::new(2.0, 1.0));
    }
}

// ---------------------------------------------------------------------------
// 6. Interference-plus-Noise Covariance ($R_{IN}$) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_rin_covariance_estimation() {
    let num_rx = 2;
    // Residual error vectors with correlated interference between antenna 0 and 1
    let residuals = vec![
        vec![Complex32::new(1.0, 0.0), Complex32::new(1.0, 0.0)],
        vec![Complex32::new(-1.0, 0.0), Complex32::new(-1.0, 0.0)],
    ];

    let rin = estimate_rin_covariance(&residuals, num_rx, 0.1);
    assert_eq!(rin.rows, 2);
    assert_eq!(rin.cols, 2);

    // Diagonal elements should have signal power + noise floor (1.0 + 0.1 = 1.1)
    assert!((rin.get(0, 0).re - 1.1).abs() < 1e-5);
    assert!((rin.get(1, 1).re - 1.1).abs() < 1e-5);

    // Off-diagonal cross-correlation should be 1.0
    assert!((rin.get(0, 1).re - 1.0).abs() < 1e-5);
    assert!((rin.get(1, 0).re - 1.0).abs() < 1e-5);
}

// ---------------------------------------------------------------------------
// 7. MIMO Equalization Tests (ZF, MMSE, MMSE-IRC)
// ---------------------------------------------------------------------------

#[test]
fn test_mimo_equalization_2x2_zero_forcing_and_mmse() {
    // 2x2 MIMO Channel Matrix:
    // H = [ 1.0+0.5i,  0.2-0.1i ]
    //     [ 0.1+0.3i,  1.2+0.0i ]
    let mut h = ComplexMatrix::zeros(2, 2);
    h.set(0, 0, Complex32::new(1.0, 0.5));
    h.set(0, 1, Complex32::new(0.2, -0.1));
    h.set(1, 0, Complex32::new(0.1, 0.3));
    h.set(1, 1, Complex32::new(1.2, 0.0));

    // Transmitted QPSK symbols
    let qpsk = std::f32::consts::FRAC_1_SQRT_2;
    let x_tx = [
        Complex32::new(qpsk, qpsk),
        Complex32::new(-qpsk, qpsk),
    ];

    // Received symbols Y = H * X
    let y0 = h.get(0, 0) * x_tx[0] + h.get(0, 1) * x_tx[1];
    let y1 = h.get(1, 0) * x_tx[0] + h.get(1, 1) * x_tx[1];
    let y = [y0, y1];

    let rin = ComplexMatrix::eye(2);

    // Zero-Forcing Equalization
    let res_zf = MimoEqualizer::equalize(&y, &h, 0.01, &rin, EqualizerType::ZeroForcing).unwrap();
    assert_eq!(res_zf.equalized_symbols.len(), 2);
    assert!((res_zf.equalized_symbols[0].re - x_tx[0].re).abs() < 1e-4);
    assert!((res_zf.equalized_symbols[0].im - x_tx[0].im).abs() < 1e-4);
    assert!((res_zf.equalized_symbols[1].re - x_tx[1].re).abs() < 1e-4);
    assert!((res_zf.equalized_symbols[1].im - x_tx[1].im).abs() < 1e-4);
    assert!(res_zf.sinr_db[0] > 0.0);
    assert!(res_zf.sinr_db[1] > 0.0);

    // MMSE Equalization
    let res_mmse = MimoEqualizer::equalize(&y, &h, 0.01, &rin, EqualizerType::Mmse).unwrap();
    assert!((res_mmse.equalized_symbols[0].re - x_tx[0].re).abs() < 1e-2);
    assert!((res_mmse.equalized_symbols[1].re - x_tx[1].re).abs() < 1e-2);
}

#[test]
fn test_mimo_equalization_mmse_irc_suppression() {
    // 2x1 SIMO setup with correlated co-channel interferer on Rx antenna 1
    let mut h = ComplexMatrix::zeros(2, 1);
    h.set(0, 0, Complex32::new(1.0, 0.0));
    h.set(1, 0, Complex32::new(1.0, 0.0));

    let x_tx = [Complex32::new(1.0, 0.0)];
    let y = [Complex32::new(1.0, 0.0), Complex32::new(3.0, 0.0)]; // Heavy interference on antenna 1

    // R_IN with strong interference power on antenna 1
    let mut rin = ComplexMatrix::zeros(2, 2);
    rin.set(0, 0, Complex32::new(0.05, 0.0));
    rin.set(1, 1, Complex32::new(4.0, 0.0)); // 40x higher noise/interference on antenna 1

    let res_irc = MimoEqualizer::equalize(&y, &h, 0.05, &rin, EqualizerType::MmseIrc).unwrap();

    // IRC should weight antenna 0 heavily and de-weight antenna 1, recovering x_tx
    assert!((res_irc.equalized_symbols[0].re - x_tx[0].re).abs() < 0.15);
    assert!(res_irc.sinr_db[0] > 10.0);
}

// ---------------------------------------------------------------------------
// 8. Binary Wire Framing (ChannelEstimationWirePdu) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = ChannelEstimationWirePdu {
        slot_index: 3,
        symbol_index: 2,
        num_rx: 4,
        num_tx: 2,
        avg_sinr_db: 22.5,
        channel_power_db: -5.2,
        raw_channel_taps: vec![0x10, 0x20, 0x30, 0x40, 0x50],
    };

    let wire_bytes = pdu.to_wire_bytes();
    assert!(wire_bytes.len() >= 23);

    let decoded = ChannelEstimationWirePdu::from_wire_bytes(&wire_bytes).unwrap();
    assert_eq!(decoded.slot_index, pdu.slot_index);
    assert_eq!(decoded.symbol_index, pdu.symbol_index);
    assert_eq!(decoded.num_rx, pdu.num_rx);
    assert_eq!(decoded.num_tx, pdu.num_tx);
    assert!((decoded.avg_sinr_db - pdu.avg_sinr_db).abs() < 1e-4);
    assert!((decoded.channel_power_db - pdu.channel_power_db).abs() < 1e-4);
    assert_eq!(decoded.raw_channel_taps, pdu.raw_channel_taps);
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = ChannelEstimationWirePdu {
        slot_index: 1,
        symbol_index: 0,
        num_rx: 2,
        num_tx: 1,
        avg_sinr_db: 15.0,
        channel_power_db: -10.0,
        raw_channel_taps: vec![0xAB, 0xCD],
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[0] = 0xFF; // Corrupt magic

    assert!(matches!(
        ChannelEstimationWirePdu::from_wire_bytes(&wire_bytes),
        Err(ChannelEstimationError::InvalidWireMagic(_))
    ));
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = ChannelEstimationWirePdu {
        slot_index: 0,
        symbol_index: 7,
        num_rx: 1,
        num_tx: 1,
        avg_sinr_db: 18.2,
        channel_power_db: -3.0,
        raw_channel_taps: vec![0x01, 0x02, 0x03],
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    let len = wire_bytes.len();
    wire_bytes[len - 3] ^= 0x55; // Corrupt payload byte

    assert!(matches!(
        ChannelEstimationWirePdu::from_wire_bytes(&wire_bytes),
        Err(ChannelEstimationError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_truncated() {
    let pdu = ChannelEstimationWirePdu {
        slot_index: 0,
        symbol_index: 2,
        num_rx: 2,
        num_tx: 2,
        avg_sinr_db: 20.0,
        channel_power_db: 0.0,
        raw_channel_taps: vec![0x77],
    };

    let wire_bytes = pdu.to_wire_bytes();
    let truncated = &wire_bytes[..12];

    assert!(matches!(
        ChannelEstimationWirePdu::from_wire_bytes(truncated),
        Err(ChannelEstimationError::WirePayloadTooShort { .. })
    ));
}

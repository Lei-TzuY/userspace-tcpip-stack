//! Integration tests for 3GPP Rel-18/19 5G-Advanced OFDM Baseband Engine.
//! Validates: constellation mapping, FFT/IFFT, OFDM symbol mod/demod,
//! numerology, CP lengths, soft demapping, CFO correction, wire framing.

use toy_tcpip::nr_ofdm_engine::*;

const EPSILON: f64 = 1e-10;

fn approx_eq(a: f64, b: f64) -> bool {
    (a - b).abs() < EPSILON
}

// ===========================================================================
// FFT / IFFT Round-Trip Tests
// ===========================================================================

#[test]
fn test_fft_ifft_roundtrip_64() {
    let n = 64;
    let mut data: Vec<Complex64> = (0..n)
        .map(|i| Complex64::new((i as f64).sin(), (i as f64).cos()))
        .collect();
    let original = data.clone();

    fft_radix2(&mut data, false); // FFT
    fft_radix2(&mut data, true); // IFFT

    for i in 0..n {
        assert!(
            approx_eq(data[i].re, original[i].re) && approx_eq(data[i].im, original[i].im),
            "Mismatch at index {}: got ({}, {}), expected ({}, {})",
            i,
            data[i].re,
            data[i].im,
            original[i].re,
            original[i].im
        );
    }
}

#[test]
fn test_fft_ifft_roundtrip_256() {
    let n = 256;
    let mut data: Vec<Complex64> = (0..n)
        .map(|i| Complex64::new(i as f64 * 0.01, -(i as f64) * 0.02))
        .collect();
    let original = data.clone();

    fft_radix2(&mut data, false);
    fft_radix2(&mut data, true);

    for i in 0..n {
        assert!(
            approx_eq(data[i].re, original[i].re) && approx_eq(data[i].im, original[i].im),
            "Mismatch at index {}",
            i
        );
    }
}

#[test]
fn test_fft_ifft_roundtrip_1024() {
    let n = 1024;
    let mut data: Vec<Complex64> = (0..n)
        .map(|i| Complex64::new((i as f64 * 0.1).sin(), (i as f64 * 0.1).cos()))
        .collect();
    let original = data.clone();

    fft_radix2(&mut data, false);
    fft_radix2(&mut data, true);

    for i in 0..n {
        assert!(
            (data[i].re - original[i].re).abs() < 1e-8
                && (data[i].im - original[i].im).abs() < 1e-8,
            "Mismatch at index {}",
            i
        );
    }
}

#[test]
fn test_fft_known_dc() {
    // All-ones input should give energy only at bin 0
    let n = 64;
    let mut data = vec![Complex64::new(1.0, 0.0); n];
    fft_radix2(&mut data, false);

    // Bin 0 should be N + 0j
    assert!(approx_eq(data[0].re, n as f64));
    assert!(approx_eq(data[0].im, 0.0));

    // All other bins should be zero
    for i in 1..n {
        assert!(
            approx_eq(data[i].re, 0.0) && approx_eq(data[i].im, 0.0),
            "Non-zero at bin {}: ({}, {})",
            i,
            data[i].re,
            data[i].im
        );
    }
}

// ===========================================================================
// Constellation Mapping Tests (TS 38.211 §5.1)
// ===========================================================================

#[test]
fn test_qpsk_all_symbols() {
    // QPSK should have 4 symbols from 2 bits
    let constellations = [
        (
            [0u8, 0],
            (
                1.0 / std::f64::consts::SQRT_2,
                1.0 / std::f64::consts::SQRT_2,
            ),
        ),
        (
            [0, 1],
            (
                1.0 / std::f64::consts::SQRT_2,
                -1.0 / std::f64::consts::SQRT_2,
            ),
        ),
        (
            [1, 0],
            (
                -1.0 / std::f64::consts::SQRT_2,
                1.0 / std::f64::consts::SQRT_2,
            ),
        ),
        (
            [1, 1],
            (
                -1.0 / std::f64::consts::SQRT_2,
                -1.0 / std::f64::consts::SQRT_2,
            ),
        ),
    ];

    for (bits, (exp_re, exp_im)) in &constellations {
        let syms = modulate(bits, ModulationOrder::Qpsk).unwrap();
        assert_eq!(syms.len(), 1);
        assert!(
            approx_eq(syms[0].re, *exp_re) && approx_eq(syms[0].im, *exp_im),
            "QPSK bits {:?}: got ({}, {}), expected ({}, {})",
            bits,
            syms[0].re,
            syms[0].im,
            exp_re,
            exp_im
        );
    }
}

#[test]
fn test_qpsk_unit_power() {
    // All QPSK constellation points should have unit power
    for b0 in 0..2u8 {
        for b1 in 0..2u8 {
            let syms = modulate(&[b0, b1], ModulationOrder::Qpsk).unwrap();
            let power = syms[0].norm_sqr();
            assert!(
                approx_eq(power, 1.0),
                "QPSK ({}, {}): power = {}",
                b0,
                b1,
                power
            );
        }
    }
}

#[test]
fn test_16qam_power_normalization() {
    // Average power of 16QAM constellation should be 1
    let mut total_power = 0.0;
    let mut count = 0;
    for b0 in 0..2u8 {
        for b1 in 0..2u8 {
            for b2 in 0..2u8 {
                for b3 in 0..2u8 {
                    let syms = modulate(&[b0, b1, b2, b3], ModulationOrder::Qam16).unwrap();
                    total_power += syms[0].norm_sqr();
                    count += 1;
                }
            }
        }
    }
    let avg_power = total_power / count as f64;
    assert!(
        (avg_power - 1.0).abs() < 0.01,
        "16QAM average power: {} (expected 1.0)",
        avg_power
    );
}

#[test]
fn test_64qam_power_normalization() {
    let mut total_power = 0.0;
    let mut count = 0;
    for i in 0..64u32 {
        let bits: Vec<u8> = (0..6).map(|b| ((i >> (5 - b)) & 1) as u8).collect();
        let syms = modulate(&bits, ModulationOrder::Qam64).unwrap();
        total_power += syms[0].norm_sqr();
        count += 1;
    }
    let avg_power = total_power / count as f64;
    assert!(
        (avg_power - 1.0).abs() < 0.01,
        "64QAM average power: {} (expected 1.0)",
        avg_power
    );
}

#[test]
fn test_256qam_power_normalization() {
    let mut total_power = 0.0;
    let mut count = 0;
    for i in 0..256u32 {
        let bits: Vec<u8> = (0..8).map(|b| ((i >> (7 - b)) & 1) as u8).collect();
        let syms = modulate(&bits, ModulationOrder::Qam256).unwrap();
        total_power += syms[0].norm_sqr();
        count += 1;
    }
    let avg_power = total_power / count as f64;
    assert!(
        (avg_power - 1.0).abs() < 0.01,
        "256QAM average power: {} (expected 1.0)",
        avg_power
    );
}

#[test]
fn test_1024qam_power_normalization() {
    let mut total_power = 0.0;
    let mut count = 0;
    for i in 0..1024u32 {
        let bits: Vec<u8> = (0..10).map(|b| ((i >> (9 - b)) & 1) as u8).collect();
        let syms = modulate(&bits, ModulationOrder::Qam1024).unwrap();
        total_power += syms[0].norm_sqr();
        count += 1;
    }
    let avg_power = total_power / count as f64;
    assert!(
        (avg_power - 1.0).abs() < 0.01,
        "1024QAM average power: {} (expected 1.0)",
        avg_power
    );
}

#[test]
fn test_1024qam_unique_points() {
    // All 1024 constellation points must be distinct
    let mut points = Vec::new();
    for i in 0..1024u32 {
        let bits: Vec<u8> = (0..10).map(|b| ((i >> (9 - b)) & 1) as u8).collect();
        let syms = modulate(&bits, ModulationOrder::Qam1024).unwrap();
        points.push((
            (syms[0].re * 1e8).round() as i64,
            (syms[0].im * 1e8).round() as i64,
        ));
    }
    points.sort();
    points.dedup();
    assert_eq!(
        points.len(),
        1024,
        "1024QAM should produce 1024 unique constellation points"
    );
}

#[test]
fn test_modulation_invalid_bits() {
    // 3 bits cannot be evenly divided for QPSK (needs 2)
    let result = modulate(&[0, 1, 0], ModulationOrder::Qpsk);
    assert!(result.is_err());
}

#[test]
fn test_bits_per_symbol() {
    assert_eq!(ModulationOrder::PiOver2Bpsk.bits_per_symbol(), 1);
    assert_eq!(ModulationOrder::Qpsk.bits_per_symbol(), 2);
    assert_eq!(ModulationOrder::Qam16.bits_per_symbol(), 4);
    assert_eq!(ModulationOrder::Qam64.bits_per_symbol(), 6);
    assert_eq!(ModulationOrder::Qam256.bits_per_symbol(), 8);
    assert_eq!(ModulationOrder::Qam1024.bits_per_symbol(), 10);
}

// ===========================================================================
// Numerology & Cyclic Prefix Tests (TS 38.211 §4.2)
// ===========================================================================

#[test]
fn test_numerology_scs_values() {
    // TS 38.211 Table 4.2-1
    assert_eq!(get_numerology(0).unwrap().scs_khz, 15);
    assert_eq!(get_numerology(1).unwrap().scs_khz, 30);
    assert_eq!(get_numerology(2).unwrap().scs_khz, 60);
    assert_eq!(get_numerology(3).unwrap().scs_khz, 120);
    assert_eq!(get_numerology(4).unwrap().scs_khz, 240);
}

#[test]
fn test_numerology_slots_per_subframe() {
    assert_eq!(get_numerology(0).unwrap().slots_per_subframe, 1);
    assert_eq!(get_numerology(1).unwrap().slots_per_subframe, 2);
    assert_eq!(get_numerology(2).unwrap().slots_per_subframe, 4);
    assert_eq!(get_numerology(3).unwrap().slots_per_subframe, 8);
    assert_eq!(get_numerology(4).unwrap().slots_per_subframe, 16);
}

#[test]
fn test_numerology_invalid() {
    assert!(get_numerology(5).is_err());
    assert!(get_numerology(255).is_err());
}

#[test]
fn test_extended_cp_numerology() {
    let ext = get_extended_cp_numerology();
    assert_eq!(ext.scs_khz, 60);
    assert_eq!(ext.symbols_per_slot, 12);
    assert!(ext.extended_cp);
}

#[test]
fn test_normal_cp_lengths_2048() {
    // TS 38.211 for N_FFT = 2048, mu=0
    let num = get_numerology(0).unwrap();
    let n_fft = 2048;

    // First symbol (index 0) and symbol 7 get base=160
    assert_eq!(cyclic_prefix_length(0, n_fft, &num), 160);
    assert_eq!(cyclic_prefix_length(7, n_fft, &num), 160);

    // All other symbols get base=144
    assert_eq!(cyclic_prefix_length(1, n_fft, &num), 144);
    assert_eq!(cyclic_prefix_length(6, n_fft, &num), 144);
    assert_eq!(cyclic_prefix_length(13, n_fft, &num), 144);
}

#[test]
fn test_normal_cp_lengths_4096() {
    let num = get_numerology(0).unwrap();
    let n_fft = 4096;

    // Scaled: 160 * 4096 / 2048 = 320
    assert_eq!(cyclic_prefix_length(0, n_fft, &num), 320);
    // Scaled: 144 * 4096 / 2048 = 288
    assert_eq!(cyclic_prefix_length(1, n_fft, &num), 288);
}

#[test]
fn test_extended_cp_length() {
    let ext = get_extended_cp_numerology();
    // 512 * N_FFT / 2048
    assert_eq!(cyclic_prefix_length(0, 2048, &ext), 512);
    assert_eq!(cyclic_prefix_length(5, 2048, &ext), 512);
    assert_eq!(cyclic_prefix_length(0, 4096, &ext), 1024);
}

// ===========================================================================
// OFDM Modulation / Demodulation Round-Trip Tests
// ===========================================================================

#[test]
fn test_ofdm_moddemod_roundtrip_qpsk() {
    let n_fft = 256;
    let n_sc = 128; // 128 subcarriers
    let num = get_numerology(1).unwrap();
    let cp_len = cyclic_prefix_length(0, n_fft, &num);

    // Generate random-ish QPSK symbols for each subcarrier
    let mut freq_tx = Vec::with_capacity(n_sc);
    for i in 0..n_sc {
        let phase = (i as f64) * 0.37;
        freq_tx.push(Complex64::from_polar(1.0, phase));
    }

    // Modulate
    let time_sym = ofdm_modulate_symbol(&freq_tx, n_fft, cp_len).unwrap();
    assert_eq!(time_sym.len(), cp_len + n_fft);

    // Demodulate
    let freq_rx = ofdm_demodulate_symbol(&time_sym, n_fft, cp_len, n_sc).unwrap();
    assert_eq!(freq_rx.len(), n_sc);

    for i in 0..n_sc {
        assert!(
            (freq_rx[i].re - freq_tx[i].re).abs() < 1e-8
                && (freq_rx[i].im - freq_tx[i].im).abs() < 1e-8,
            "Subcarrier {} mismatch: tx ({}, {}), rx ({}, {})",
            i,
            freq_tx[i].re,
            freq_tx[i].im,
            freq_rx[i].re,
            freq_rx[i].im
        );
    }
}

#[test]
fn test_ofdm_moddemod_roundtrip_1024() {
    let n_fft = 1024;
    let n_sc = 600; // 600 subcarriers (typical for 10 MHz BW)
    let num = get_numerology(0).unwrap();
    let cp_len = cyclic_prefix_length(3, n_fft, &num);

    let mut freq_tx: Vec<Complex64> = Vec::with_capacity(n_sc);
    for i in 0..n_sc {
        freq_tx.push(Complex64::new(
            ((i * 7 + 3) as f64 * 0.1).sin(),
            ((i * 11 + 5) as f64 * 0.1).cos(),
        ));
    }

    let time_sym = ofdm_modulate_symbol(&freq_tx, n_fft, cp_len).unwrap();
    let freq_rx = ofdm_demodulate_symbol(&time_sym, n_fft, cp_len, n_sc).unwrap();

    for i in 0..n_sc {
        assert!(
            (freq_rx[i].re - freq_tx[i].re).abs() < 1e-7
                && (freq_rx[i].im - freq_tx[i].im).abs() < 1e-7,
            "SC {} mismatch",
            i
        );
    }
}

#[test]
fn test_ofdm_invalid_fft_size() {
    let freq = vec![Complex64::zero(); 12];
    assert!(ofdm_modulate_symbol(&freq, 100, 10).is_err()); // Not power of 2
    assert!(ofdm_modulate_symbol(&freq, 32, 10).is_err()); // Too small
    assert!(ofdm_modulate_symbol(&freq, 8192, 10).is_err()); // Too large
}

#[test]
fn test_ofdm_demod_buffer_too_short() {
    let short = vec![Complex64::zero(); 10];
    assert!(ofdm_demodulate_symbol(&short, 256, 20, 128).is_err());
}

// ===========================================================================
// OFDM CP Preservation Test (CP is copy of end of symbol)
// ===========================================================================

#[test]
fn test_cp_is_tail_copy() {
    let n_fft = 256;
    let cp_len = 20;
    let freq = (0..128)
        .map(|i| Complex64::new((i as f64).cos(), (i as f64).sin()))
        .collect::<Vec<_>>();

    let time_sym = ofdm_modulate_symbol(&freq, n_fft, cp_len).unwrap();

    // CP = last cp_len samples of the IFFT output
    for i in 0..cp_len {
        let cp_sample = &time_sym[i];
        let tail_sample = &time_sym[cp_len + n_fft - cp_len + i];
        assert!(
            approx_eq(cp_sample.re, tail_sample.re) && approx_eq(cp_sample.im, tail_sample.im),
            "CP sample {} doesn't match tail: ({}, {}) vs ({}, {})",
            i,
            cp_sample.re,
            cp_sample.im,
            tail_sample.re,
            tail_sample.im
        );
    }
}

// ===========================================================================
// Soft Demapper Tests
// ===========================================================================

#[test]
fn test_soft_demod_qpsk_positive_symbol() {
    let inv_sqrt2 = 1.0 / std::f64::consts::SQRT_2;
    let sym = Complex64::new(inv_sqrt2, inv_sqrt2); // bits [0, 0]
    let llrs = soft_demod_qpsk(&sym, 1.0);
    assert_eq!(llrs.len(), 2);
    // Both LLRs should be positive (meaning bit=0 is more likely)
    assert!(llrs[0] > 0.0, "LLR[0] = {}", llrs[0]);
    assert!(llrs[1] > 0.0, "LLR[1] = {}", llrs[1]);
}

#[test]
fn test_soft_demod_qpsk_negative_symbol() {
    let inv_sqrt2 = 1.0 / std::f64::consts::SQRT_2;
    let sym = Complex64::new(-inv_sqrt2, -inv_sqrt2); // bits [1, 1]
    let llrs = soft_demod_qpsk(&sym, 1.0);
    assert!(llrs[0] < 0.0, "LLR[0] should be negative for bit=1");
    assert!(llrs[1] < 0.0, "LLR[1] should be negative for bit=1");
}

#[test]
fn test_soft_demod_16qam_symmetry() {
    // Mirror symbols should produce opposite-sign LLR[0] and LLR[1]
    let sym_pos = Complex64::new(0.5, 0.5);
    let sym_neg = Complex64::new(-0.5, -0.5);
    let llr_pos = soft_demod_16qam(&sym_pos, 1.0);
    let llr_neg = soft_demod_16qam(&sym_neg, 1.0);

    assert!(
        (llr_pos[0] + llr_neg[0]).abs() < 1e-8,
        "LLR[0] should be symmetric"
    );
    assert!(
        (llr_pos[1] + llr_neg[1]).abs() < 1e-8,
        "LLR[1] should be symmetric"
    );
}

// ===========================================================================
// CFO Correction Tests
// ===========================================================================

#[test]
fn test_cfo_zero_offset() {
    let mut samples = vec![
        Complex64::new(1.0, 0.0),
        Complex64::new(0.0, 1.0),
        Complex64::new(-1.0, 0.0),
    ];
    let original = samples.clone();
    apply_cfo_correction(&mut samples, 0.0, 1000.0);

    for i in 0..3 {
        assert!(
            approx_eq(samples[i].re, original[i].re) && approx_eq(samples[i].im, original[i].im),
            "Zero CFO should not change samples"
        );
    }
}

#[test]
fn test_cfo_roundtrip() {
    // Apply +100 Hz CFO then -100 Hz CFO → should recover original
    let mut samples = vec![
        Complex64::new(1.0, 0.0),
        Complex64::new(0.5, 0.5),
        Complex64::new(-0.3, 0.7),
        Complex64::new(0.0, -1.0),
    ];
    let original = samples.clone();

    apply_cfo_correction(&mut samples, 100.0, 10000.0); // Impair
    apply_cfo_correction(&mut samples, -100.0, 10000.0); // Correct

    for i in 0..4 {
        assert!(
            (samples[i].re - original[i].re).abs() < 1e-10
                && (samples[i].im - original[i].im).abs() < 1e-10,
            "CFO roundtrip mismatch at {}",
            i
        );
    }
}

// ===========================================================================
// Wire PDU Serialization / Deserialization Tests
// ===========================================================================

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = OfdmWirePdu {
        magic: OFDM_WIRE_MAGIC,
        slot_idx: 42,
        symbol_idx: 7,
        numerology_mu: 1,
        n_fft: 2048,
        cp_len: 160,
        modulation_order: 6, // 64QAM
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
        crc16: 0, // Will be computed during serialization
    };

    let wire = pdu.serialize();
    let decoded = OfdmWirePdu::deserialize(&wire).unwrap();

    assert_eq!(decoded.magic, OFDM_WIRE_MAGIC);
    assert_eq!(decoded.slot_idx, 42);
    assert_eq!(decoded.symbol_idx, 7);
    assert_eq!(decoded.numerology_mu, 1);
    assert_eq!(decoded.n_fft, 2048);
    assert_eq!(decoded.cp_len, 160);
    assert_eq!(decoded.modulation_order, 6);
    assert_eq!(decoded.payload, vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
}

#[test]
fn test_wire_pdu_empty_payload() {
    let pdu = OfdmWirePdu {
        magic: OFDM_WIRE_MAGIC,
        slot_idx: 0,
        symbol_idx: 0,
        numerology_mu: 0,
        n_fft: 256,
        cp_len: 20,
        modulation_order: 2,
        payload: vec![],
        crc16: 0,
    };
    let wire = pdu.serialize();
    let decoded = OfdmWirePdu::deserialize(&wire).unwrap();
    assert_eq!(decoded.payload.len(), 0);
}

#[test]
fn test_wire_pdu_invalid_magic() {
    let mut wire = OfdmWirePdu {
        magic: OFDM_WIRE_MAGIC,
        slot_idx: 0,
        symbol_idx: 0,
        numerology_mu: 0,
        n_fft: 256,
        cp_len: 20,
        modulation_order: 2,
        payload: vec![0x01],
        crc16: 0,
    }
    .serialize();

    // Corrupt magic
    wire[0] = 0xFF;
    assert!(OfdmWirePdu::deserialize(&wire).is_err());
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let wire = OfdmWirePdu {
        magic: OFDM_WIRE_MAGIC,
        slot_idx: 100,
        symbol_idx: 13,
        numerology_mu: 3,
        n_fft: 4096,
        cp_len: 288,
        modulation_order: 10,
        payload: vec![0x11, 0x22, 0x33],
        crc16: 0,
    }
    .serialize();

    // Corrupt last byte (CRC)
    let mut corrupted = wire.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(OfdmWirePdu::deserialize(&corrupted).is_err());
}

#[test]
fn test_wire_pdu_truncated() {
    assert!(OfdmWirePdu::deserialize(&[0u8; 5]).is_err());
}

// ===========================================================================
// CRC-16 Tests
// ===========================================================================

#[test]
fn test_crc16_known_values() {
    // CRC-16/CCITT-FALSE of empty data with init=0xFFFF
    let crc_empty = compute_crc16(&[]);
    assert_eq!(crc_empty, 0xFFFF);

    // Known test: "123456789" → CRC-16/CCITT-FALSE = 0x29B1
    let crc_123 = compute_crc16(b"123456789");
    assert_eq!(
        crc_123, 0x29B1,
        "CRC-16 of '123456789': got 0x{:04X}",
        crc_123
    );
}

// ===========================================================================
// Complex64 Arithmetic Tests
// ===========================================================================

#[test]
fn test_complex_mul() {
    let a = Complex64::new(3.0, 4.0);
    let b = Complex64::new(1.0, -2.0);
    let c = a.mul(&b);
    // (3+4i)(1-2i) = 3 - 6i + 4i - 8i^2 = 3 - 2i + 8 = 11 - 2i
    // Wait: (3+4i)(1-2i) = 3*1 - 3*2i + 4i*1 - 4i*2i = 3 - 6i + 4i + 8 = 11 - 2i
    assert!(approx_eq(c.re, 11.0));
    assert!(approx_eq(c.im, -2.0));
}

#[test]
fn test_complex_conj() {
    let a = Complex64::new(3.0, 4.0);
    let ac = a.conj();
    assert!(approx_eq(ac.re, 3.0));
    assert!(approx_eq(ac.im, -4.0));
}

#[test]
fn test_complex_norm_sqr() {
    let a = Complex64::new(3.0, 4.0);
    assert!(approx_eq(a.norm_sqr(), 25.0));
}

#[test]
fn test_complex_from_polar() {
    let c = Complex64::from_polar(2.0, std::f64::consts::PI / 4.0);
    assert!((c.re - std::f64::consts::SQRT_2).abs() < 1e-10);
    assert!((c.im - std::f64::consts::SQRT_2).abs() < 1e-10);
}

// ===========================================================================
// End-to-End: Constellation → OFDM Symbol → Demod → LLR
// ===========================================================================

#[test]
fn test_e2e_qpsk_ofdm_pipeline() {
    let n_fft = 256;
    let n_sc = 64;
    let num = get_numerology(1).unwrap();
    let cp_len = cyclic_prefix_length(0, n_fft, &num);

    // Generate 64 QPSK symbols from 128 bits
    let bits: Vec<u8> = (0..128).map(|i| (i % 2) as u8).collect();
    let qpsk_syms = modulate(&bits, ModulationOrder::Qpsk).unwrap();
    assert_eq!(qpsk_syms.len(), n_sc);

    // OFDM modulate
    let time_sym = ofdm_modulate_symbol(&qpsk_syms, n_fft, cp_len).unwrap();

    // OFDM demodulate
    let rx_syms = ofdm_demodulate_symbol(&time_sym, n_fft, cp_len, n_sc).unwrap();

    // Verify recovered symbols match transmitted
    for i in 0..n_sc {
        assert!(
            (rx_syms[i].re - qpsk_syms[i].re).abs() < 1e-8
                && (rx_syms[i].im - qpsk_syms[i].im).abs() < 1e-8,
            "E2E mismatch at SC {}",
            i
        );
    }

    // Verify LLR signs match original bits
    for i in 0..n_sc {
        let llrs = soft_demod_qpsk(&rx_syms[i], 0.01);
        let bit0 = if llrs[0] > 0.0 { 0u8 } else { 1u8 };
        let bit1 = if llrs[1] > 0.0 { 0u8 } else { 1u8 };
        assert_eq!(
            bit0,
            bits[2 * i],
            "LLR hard-decision mismatch at bit {}",
            2 * i
        );
        assert_eq!(
            bit1,
            bits[2 * i + 1],
            "LLR hard-decision mismatch at bit {}",
            2 * i + 1
        );
    }
}

// ===========================================================================
// Error Display Tests
// ===========================================================================

#[test]
fn test_error_display() {
    assert!(format!("{}", OfdmError::InvalidFftSize(100)).contains("100"));
    assert!(format!("{}", OfdmError::InvalidNumerology(5)).contains("5"));
    assert!(format!("{}", OfdmError::InvalidBitCount(3)).contains("3"));
    assert!(format!("{}", OfdmError::BufferTooShort(10)).contains("10"));
}

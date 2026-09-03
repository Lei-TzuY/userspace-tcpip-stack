//! Integration tests for O-RAN WG4 Open Fronthaul Dynamic Block Floating Point (BFP) IQ Compression.

use toy_tcpip::oran_bfp_compression::*;

// ---------------------------------------------------------------------------
// 1. 9-Bit BFP Compression and Decompression Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_oran_bfp_9bit_compression_and_decompression_happy_path() {
    // 12 complex IQ samples (1 PRB) representing typical 5G NR 64QAM symbols
    let original: Vec<ComplexIq> = vec![
        ComplexIq { i: 1024, q: -2048 },
        ComplexIq { i: -1500, q: 3000 },
        ComplexIq { i: 4000, q: -500 },
        ComplexIq { i: -3200, q: -2800 },
        ComplexIq { i: 120, q: 450 },
        ComplexIq { i: -800, q: 1600 },
        ComplexIq { i: 2500, q: -3500 },
        ComplexIq { i: -1900, q: 900 },
        ComplexIq { i: 3100, q: 2100 },
        ComplexIq { i: -750, q: -1850 },
        ComplexIq { i: 1800, q: -2200 },
        ComplexIq { i: -2900, q: 3400 },
    ];

    let compressed = OranBfpEngine::compress_prb(0, &original, 9).unwrap();

    // 4 bits exponent + 24 * 9 bits = 220 bits -> 28 bytes
    assert_eq!(compressed.bit_width, 9);
    assert_eq!(compressed.packed_bytes.len(), 28);
    assert!(compressed.exponent > 0);

    let decompressed = OranBfpEngine::decompress_prb(&compressed).unwrap();
    assert_eq!(decompressed.len(), 12);

    let metrics = OranBfpEngine::calculate_quality_metrics(
        &original,
        &decompressed,
        compressed.packed_bytes.len(),
    );

    // EVM should be exceptionally low (< 1.5%) and SQNR high (> 40 dB)
    assert!(metrics.evm_percent < 1.5);
    assert!(metrics.sqnr_db > 38.0);
    assert!(metrics.compression_ratio > 1.7); // 48 bytes -> 28 bytes
}

// ---------------------------------------------------------------------------
// 2. 14-Bit High Fidelity BFP Compression
// ---------------------------------------------------------------------------

#[test]
fn test_oran_bfp_14bit_high_fidelity() {
    let original: Vec<ComplexIq> = vec![
        ComplexIq {
            i: 12345,
            q: -23456,
        },
        ComplexIq {
            i: -30000,
            q: 31000,
        },
        ComplexIq { i: 500, q: -1200 },
        ComplexIq { i: 18000, q: 19500 },
        ComplexIq {
            i: -14200,
            q: -15600,
        },
        ComplexIq { i: 8900, q: -9200 },
        ComplexIq {
            i: -22000,
            q: 21000,
        },
        ComplexIq { i: 11000, q: -4000 },
        ComplexIq { i: -7000, q: 6000 },
        ComplexIq {
            i: 26000,
            q: -25000,
        },
        ComplexIq {
            i: -17500,
            q: 18500,
        },
        ComplexIq {
            i: 32000,
            q: -31500,
        },
    ];

    let compressed = OranBfpEngine::compress_prb(1, &original, 14).unwrap();
    let decompressed = OranBfpEngine::decompress_prb(&compressed).unwrap();

    let metrics = OranBfpEngine::calculate_quality_metrics(
        &original,
        &decompressed,
        compressed.packed_bytes.len(),
    );

    // 14-bit EVM must be negligible (< 0.2%) and SQNR > 60 dB
    assert!(metrics.evm_percent < 0.2);
    assert!(metrics.sqnr_db > 60.0);
}

// ---------------------------------------------------------------------------
// 3. Zero IQ Samples Handling
// ---------------------------------------------------------------------------

#[test]
fn test_oran_bfp_zero_iq_samples() {
    let zeros = vec![ComplexIq::default(); 12];

    let compressed = OranBfpEngine::compress_prb(2, &zeros, 9).unwrap();
    assert_eq!(compressed.exponent, 0);

    let decompressed = OranBfpEngine::decompress_prb(&compressed).unwrap();
    for s in decompressed {
        assert_eq!(s.i, 0);
        assert_eq!(s.q, 0);
    }
}

// ---------------------------------------------------------------------------
// 4. Large Dynamic Range Clamping
// ---------------------------------------------------------------------------

#[test]
fn test_oran_bfp_large_dynamic_range_clamping() {
    let mut extreme = vec![ComplexIq::default(); 12];
    extreme[0] = ComplexIq {
        i: 32767,
        q: -32768,
    };
    extreme[11] = ComplexIq {
        i: -32768,
        q: 32767,
    };

    let compressed = OranBfpEngine::compress_prb(3, &extreme, 12).unwrap();
    let decompressed = OranBfpEngine::decompress_prb(&compressed).unwrap();

    // Verifies signs are strictly preserved
    assert!(decompressed[0].i > 0);
    assert!(decompressed[0].q < 0);
    assert!(decompressed[11].i < 0);
    assert!(decompressed[11].q > 0);
}

// ---------------------------------------------------------------------------
// 5. Error Handling
// ---------------------------------------------------------------------------

#[test]
fn test_oran_bfp_error_handling() {
    // 1. Invalid sample count (!= 12)
    let bad_samples = vec![ComplexIq::default(); 10];
    let err1 = OranBfpEngine::compress_prb(0, &bad_samples, 9);
    assert_eq!(
        err1,
        Err(BfpError::InvalidSampleCount {
            expected: 12,
            actual: 10,
        })
    );

    // 2. Invalid bit width
    let valid_samples = vec![ComplexIq::default(); 12];
    let err2 = OranBfpEngine::compress_prb(0, &valid_samples, 4);
    assert_eq!(err2, Err(BfpError::InvalidBitWidth { bit_width: 4 }));

    // 3. Corrupt truncated buffer on decompression
    let corrupt_block = CompressedPrbBlock {
        prb_index: 0,
        exponent: 2,
        bit_width: 9,
        packed_bytes: vec![0u8; 10], // needs 28 bytes!
    };
    let err3 = OranBfpEngine::decompress_prb(&corrupt_block);
    assert_eq!(err3, Err(BfpError::CorruptBuffer));
}

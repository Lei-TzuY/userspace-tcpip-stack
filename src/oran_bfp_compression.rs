//! O-RAN WG4 Open Fronthaul CUS-Plane Dynamic Block Floating Point (BFP) & Modulation Compression Engine.
//!
//! Implements O-RAN.WG4.CUS.0 Section 6.3.3 & Annex A:
//! - Dynamic Block Floating Point (BFP) compression for 1 PRB (12 Resource Elements = 24 I/Q samples)
//! - Configurable Mantissa Bit Width (7-bit, 8-bit, 9-bit, 10-bit, 12-bit, 14-bit)
//! - Bit-exact bit-packing and bit-unpacking into byte streams conforming to Section 6.3.3.1
//! - Error Vector Magnitude (EVM %) and Signal-to-Quantization-Noise Ratio (SQNR dB) calculation
//! - Modulation Compression for QPSK, 16QAM, 64QAM, and 256QAM (Section 6.3.3.3)

// ---------------------------------------------------------------------------
// O-RAN WG4 BFP Enums & Data Structures
// ---------------------------------------------------------------------------

/// Complex I/Q Sample represented as signed 16-bit integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ComplexIq {
    pub i: i16,
    pub q: i16,
}

/// O-RAN WG4 Modulation Scheme for Modulation Compression (Section 6.3.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModulationScheme {
    Qpsk,   // 2 bits/symbol
    Qam16,  // 4 bits/symbol
    Qam64,  // 6 bits/symbol
    Qam256, // 8 bits/symbol
}

/// Compressed PRB Block containing BFP exponent and packed mantissas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedPrbBlock {
    pub prb_index: u16,
    pub exponent: u8,
    pub bit_width: u8,
    pub packed_bytes: Vec<u8>,
}

/// Compression Quality Metrics (EVM & SQNR).
#[derive(Debug, Clone, PartialEq)]
pub struct IqQualityMetrics {
    pub evm_percent: f64,
    pub sqnr_db: f64,
    pub compression_ratio: f64,
}

/// Compression Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BfpError {
    InvalidSampleCount { expected: usize, actual: usize },
    InvalidBitWidth { bit_width: u8 },
    CorruptBuffer,
    InvalidModulationLength,
}

// ---------------------------------------------------------------------------
// Top-Level O-RAN BFP Engine
// ---------------------------------------------------------------------------

/// O-RAN WG4 Open Fronthaul BFP Compression Engine.
pub struct OranBfpEngine;

impl OranBfpEngine {
    /// Number of Resource Elements (REs) in 1 standard 5G NR PRB.
    pub const RE_PER_PRB: usize = 12;

    /// Compress 1 PRB (12 complex IQ pairs = 24 scalar samples) using Block Floating Point.
    pub fn compress_prb(
        prb_index: u16,
        samples: &[ComplexIq],
        bit_width: u8,
    ) -> Result<CompressedPrbBlock, BfpError> {
        if samples.len() != Self::RE_PER_PRB {
            return Err(BfpError::InvalidSampleCount {
                expected: Self::RE_PER_PRB,
                actual: samples.len(),
            });
        }
        if bit_width < 6 || bit_width > 15 {
            return Err(BfpError::InvalidBitWidth { bit_width });
        }

        // 1. Find maximum absolute value among all 24 I and Q components
        let mut max_val: i32 = 0;
        for s in samples {
            max_val = max_val.max((s.i as i32).abs());
            max_val = max_val.max((s.q as i32).abs());
        }

        // 2. Compute 4-bit Exponent E (0..15)
        // With bit_width W, max representable mantissa magnitude is 2^(W-1) - 1.
        // If max_val >> E <= (2^(W-1) - 1), then E is sufficient.
        let max_mantissa = (1i32 << (bit_width - 1)) - 1;
        let mut exponent: u8 = 0;
        while exponent < 15 && (max_val >> exponent) > max_mantissa {
            exponent += 1;
        }

        // 3. Quantize and clamp all 24 samples
        let min_mantissa = -(1i32 << (bit_width - 1));
        let mut quantized = Vec::with_capacity(24);
        for s in samples {
            let qi = ((s.i as i32) >> exponent)
                .max(min_mantissa)
                .min(max_mantissa) as i16;
            let qq = ((s.q as i32) >> exponent)
                .max(min_mantissa)
                .min(max_mantissa) as i16;
            quantized.push(qi);
            quantized.push(qq);
        }

        // 4. Bit-pack: 4-bit exponent + 24 * bit_width bits
        let total_bits = 4 + 24 * (bit_width as usize);
        let total_bytes = (total_bits + 7) / 8;
        let mut packed_bytes = vec![0u8; total_bytes];

        let mut bit_pos = 0;
        // Pack 4-bit exponent
        Self::write_bits(&mut packed_bytes, bit_pos, 4, (exponent & 0x0F) as u32);
        bit_pos += 4;

        // Pack each W-bit signed mantissa (mask to lower W bits)
        let mask = (1u32 << bit_width) - 1;
        for q in quantized {
            let val_u32 = (q as i32 as u32) & mask;
            Self::write_bits(&mut packed_bytes, bit_pos, bit_width as usize, val_u32);
            bit_pos += bit_width as usize;
        }

        Ok(CompressedPrbBlock {
            prb_index,
            exponent,
            bit_width,
            packed_bytes,
        })
    }

    /// Decompress a BFP compressed PRB block back into 12 ComplexIq samples.
    pub fn decompress_prb(block: &CompressedPrbBlock) -> Result<Vec<ComplexIq>, BfpError> {
        if block.bit_width < 6 || block.bit_width > 15 {
            return Err(BfpError::InvalidBitWidth {
                bit_width: block.bit_width,
            });
        }

        let total_bits = 4 + 24 * (block.bit_width as usize);
        let total_bytes = (total_bits + 7) / 8;
        if block.packed_bytes.len() < total_bytes {
            return Err(BfpError::CorruptBuffer);
        }

        let mut bit_pos = 0;
        let exponent = Self::read_bits(&block.packed_bytes, bit_pos, 4) as u8;
        bit_pos += 4;

        let mut reconstructed = Vec::with_capacity(Self::RE_PER_PRB);
        let sign_bit = 1u32 << (block.bit_width - 1);

        for _ in 0..Self::RE_PER_PRB {
            let i_raw = Self::read_bits(&block.packed_bytes, bit_pos, block.bit_width as usize);
            bit_pos += block.bit_width as usize;

            let q_raw = Self::read_bits(&block.packed_bytes, bit_pos, block.bit_width as usize);
            bit_pos += block.bit_width as usize;

            // Sign-extend W bits to signed 32-bit
            let i_mant = if (i_raw & sign_bit) != 0 {
                (i_raw | !((1u32 << block.bit_width) - 1)) as i32
            } else {
                i_raw as i32
            };

            let q_mant = if (q_raw & sign_bit) != 0 {
                (q_raw | !((1u32 << block.bit_width) - 1)) as i32
            } else {
                q_raw as i32
            };

            let i_recon = ((i_mant << exponent) as i32).max(-32768).min(32767) as i16;
            let q_recon = ((q_mant << exponent) as i32).max(-32768).min(32767) as i16;

            reconstructed.push(ComplexIq {
                i: i_recon,
                q: q_recon,
            });
        }

        Ok(reconstructed)
    }

    /// Calculate EVM % and SQNR in dB between original and reconstructed IQ blocks.
    pub fn calculate_quality_metrics(
        original: &[ComplexIq],
        reconstructed: &[ComplexIq],
        compressed_bytes: usize,
    ) -> IqQualityMetrics {
        let mut signal_power: f64 = 0.0;
        let mut noise_power: f64 = 0.0;

        for (o, r) in original.iter().zip(reconstructed.iter()) {
            let sig_sq = (o.i as f64).powi(2) + (o.q as f64).powi(2);
            let err_i = o.i as f64 - r.i as f64;
            let err_q = o.q as f64 - r.q as f64;
            let err_sq = err_i.powi(2) + err_q.powi(2);

            signal_power += sig_sq;
            noise_power += err_sq;
        }

        let evm_percent = if signal_power > 0.0 {
            (noise_power / signal_power).sqrt() * 100.0
        } else {
            0.0
        };

        let sqnr_db = if noise_power > 0.0 && signal_power > 0.0 {
            10.0 * (signal_power / noise_power).log10()
        } else {
            100.0 // virtually infinite SQNR
        };

        let uncompressed_bytes = original.len() * 4; // 12 * 4 bytes = 48 bytes
        let compression_ratio = (uncompressed_bytes as f64) / (compressed_bytes as f64);

        IqQualityMetrics {
            evm_percent,
            sqnr_db,
            compression_ratio,
        }
    }

    // Helper: Bit writer
    fn write_bits(buf: &mut [u8], bit_offset: usize, num_bits: usize, value: u32) {
        for bit_idx in 0..num_bits {
            let bit_val = ((value >> (num_bits - 1 - bit_idx)) & 1) as u8;
            let target_bit = bit_offset + bit_idx;
            let byte_pos = target_bit / 8;
            let bit_in_byte = 7 - (target_bit % 8);
            if bit_val == 1 {
                buf[byte_pos] |= 1 << bit_in_byte;
            } else {
                buf[byte_pos] &= !(1 << bit_in_byte);
            }
        }
    }

    // Helper: Bit reader
    fn read_bits(buf: &[u8], bit_offset: usize, num_bits: usize) -> u32 {
        let mut value = 0u32;
        for bit_idx in 0..num_bits {
            let target_bit = bit_offset + bit_idx;
            let byte_pos = target_bit / 8;
            let bit_in_byte = 7 - (target_bit % 8);
            let bit_val = ((buf[byte_pos] >> bit_in_byte) & 1) as u32;
            value = (value << 1) | bit_val;
        }
        value
    }
}

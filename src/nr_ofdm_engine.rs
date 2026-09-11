//! 3GPP Release 18/19 5G-Advanced OFDM Baseband Modulation, Demodulation,
//! Cyclic Prefix & Subcarrier Grid Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §5.1: Modulation mapping (QPSK, 16QAM, 64QAM, 256QAM, 1024QAM).
//! - 3GPP TS 38.211 Rel-18 §4.2: Numerologies and frame structure ($\mu = 0..6$).
//! - 3GPP TS 38.211 Rel-18 §4.3.1: Frame, subframe, slot, and symbol timing.
//! - 3GPP TS 38.211 Rel-18 §5.3: OFDM baseband signal generation for downlink.
//! - 3GPP TS 38.211 Rel-18 §5.4: OFDM baseband signal generation for uplink (with transform precoding option).
//!
//! Features:
//! 1. Constellation mappers: $\pi/2$-BPSK, QPSK, 16QAM, 64QAM, 256QAM, Rel-18 1024QAM.
//! 2. Max-Log LLR soft demapper for soft-decision LDPC/Polar decoders.
//! 3. Normal and Extended Cyclic Prefix duration computation per numerology.
//! 4. Pure Rust Cooley-Tukey Radix-2 FFT/IFFT engine ($N_{\text{FFT}} \in \{64..4096\}$).
//! 5. OFDM symbol modulation (IFFT + CP prepend) and demodulation (CP strip + FFT).
//! 6. Carrier Frequency Offset (CFO) phase rotator.
//! 7. Binary wire framing with CRC-16 CCITT integrity.

use std::f64::consts::PI;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes for OFDM Wire PDU: "OFDM" (0x4F46444D).
pub const OFDM_WIRE_MAGIC: u32 = 0x4F46444D;

/// CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Maximum supported FFT size.
pub const MAX_FFT_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Complex Arithmetic
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex64 {
    pub re: f64,
    pub im: f64,
}

impl Complex64 {
    pub fn new(re: f64, im: f64) -> Self { Self { re, im } }
    pub fn zero() -> Self { Self { re: 0.0, im: 0.0 } }
    pub fn from_polar(r: f64, theta: f64) -> Self {
        Self { re: r * theta.cos(), im: r * theta.sin() }
    }
    pub fn norm_sqr(&self) -> f64 { self.re * self.re + self.im * self.im }
    pub fn conj(&self) -> Self { Self { re: self.re, im: -self.im } }
    pub fn mul(&self, rhs: &Complex64) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }
    pub fn add(&self, rhs: &Complex64) -> Self {
        Self { re: self.re + rhs.re, im: self.im + rhs.im }
    }
    pub fn sub(&self, rhs: &Complex64) -> Self {
        Self { re: self.re - rhs.re, im: self.im - rhs.im }
    }
    pub fn scale(&self, s: f64) -> Self { Self { re: self.re * s, im: self.im * s } }
}

// ---------------------------------------------------------------------------
// Modulation Order
// ---------------------------------------------------------------------------

/// Modulation scheme (TS 38.211 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModulationOrder {
    PiOver2Bpsk,
    Qpsk,
    Qam16,
    Qam64,
    Qam256,
    Qam1024,
}

impl ModulationOrder {
    /// Returns bits per symbol ($Q_m$).
    pub fn bits_per_symbol(&self) -> usize {
        match self {
            ModulationOrder::PiOver2Bpsk => 1,
            ModulationOrder::Qpsk => 2,
            ModulationOrder::Qam16 => 4,
            ModulationOrder::Qam64 => 6,
            ModulationOrder::Qam256 => 8,
            ModulationOrder::Qam1024 => 10,
        }
    }
}

/// Error types for OFDM operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfdmError {
    InvalidFftSize(usize),
    InvalidNumerology(u8),
    InvalidBitCount(usize),
    BufferTooShort(usize),
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for OfdmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OfdmError::InvalidFftSize(n) => write!(f, "Invalid FFT size: {} (must be power of 2)", n),
            OfdmError::InvalidNumerology(mu) => write!(f, "Invalid numerology mu: {}", mu),
            OfdmError::InvalidBitCount(b) => write!(f, "Invalid bit count: {}", b),
            OfdmError::BufferTooShort(n) => write!(f, "Buffer too short: {}", n),
            OfdmError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            OfdmError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
        }
    }
}

impl std::error::Error for OfdmError {}

// ---------------------------------------------------------------------------
// Constellation Modulation Mapper (TS 38.211 §5.1)
// ---------------------------------------------------------------------------

/// Maps a bit vector to a single QPSK symbol.
fn map_qpsk(b0: u8, b1: u8) -> Complex64 {
    let inv_sqrt2 = 1.0 / std::f64::consts::SQRT_2;
    Complex64::new(
        (1.0 - 2.0 * b0 as f64) * inv_sqrt2,
        (1.0 - 2.0 * b1 as f64) * inv_sqrt2,
    )
}

/// Maps 4 bits to a single 16QAM symbol.
fn map_16qam(bits: &[u8]) -> Complex64 {
    let inv_sqrt10 = 1.0 / (10.0f64).sqrt();
    let re = (1.0 - 2.0 * bits[0] as f64) * (2.0 - (1.0 - 2.0 * bits[2] as f64)) * inv_sqrt10;
    let im = (1.0 - 2.0 * bits[1] as f64) * (2.0 - (1.0 - 2.0 * bits[3] as f64)) * inv_sqrt10;
    Complex64::new(re, im)
}

/// Maps 6 bits to a single 64QAM symbol.
fn map_64qam(bits: &[u8]) -> Complex64 {
    let inv_sqrt42 = 1.0 / (42.0f64).sqrt();
    let re = (1.0 - 2.0 * bits[0] as f64)
        * (4.0 - (1.0 - 2.0 * bits[2] as f64) * (2.0 - (1.0 - 2.0 * bits[4] as f64)))
        * inv_sqrt42;
    let im = (1.0 - 2.0 * bits[1] as f64)
        * (4.0 - (1.0 - 2.0 * bits[3] as f64) * (2.0 - (1.0 - 2.0 * bits[5] as f64)))
        * inv_sqrt42;
    Complex64::new(re, im)
}

/// Maps 8 bits to a single 256QAM symbol.
fn map_256qam(bits: &[u8]) -> Complex64 {
    let inv_sqrt170 = 1.0 / (170.0f64).sqrt();
    let re = (1.0 - 2.0 * bits[0] as f64)
        * (8.0
            - (1.0 - 2.0 * bits[2] as f64)
                * (4.0 - (1.0 - 2.0 * bits[4] as f64) * (2.0 - (1.0 - 2.0 * bits[6] as f64))))
        * inv_sqrt170;
    let im = (1.0 - 2.0 * bits[1] as f64)
        * (8.0
            - (1.0 - 2.0 * bits[3] as f64)
                * (4.0 - (1.0 - 2.0 * bits[5] as f64) * (2.0 - (1.0 - 2.0 * bits[7] as f64))))
        * inv_sqrt170;
    Complex64::new(re, im)
}

/// Maps 10 bits to a single 1024QAM symbol (Rel-18 §5.1).
fn map_1024qam(bits: &[u8]) -> Complex64 {
    let inv_sqrt682 = 1.0 / (682.0f64).sqrt();
    let re = (1.0 - 2.0 * bits[0] as f64)
        * (16.0
            - (1.0 - 2.0 * bits[2] as f64)
                * (8.0
                    - (1.0 - 2.0 * bits[4] as f64)
                        * (4.0
                            - (1.0 - 2.0 * bits[6] as f64)
                                * (2.0 - (1.0 - 2.0 * bits[8] as f64)))))
        * inv_sqrt682;
    let im = (1.0 - 2.0 * bits[1] as f64)
        * (16.0
            - (1.0 - 2.0 * bits[3] as f64)
                * (8.0
                    - (1.0 - 2.0 * bits[5] as f64)
                        * (4.0
                            - (1.0 - 2.0 * bits[7] as f64)
                                * (2.0 - (1.0 - 2.0 * bits[9] as f64)))))
        * inv_sqrt682;
    Complex64::new(re, im)
}

/// Modulates a bit vector into complex constellation symbols.
pub fn modulate(bits: &[u8], order: ModulationOrder) -> Result<Vec<Complex64>, OfdmError> {
    let qm = order.bits_per_symbol();
    if bits.len() % qm != 0 {
        return Err(OfdmError::InvalidBitCount(bits.len()));
    }
    let num_symbols = bits.len() / qm;
    let mut symbols = Vec::with_capacity(num_symbols);

    for i in 0..num_symbols {
        let b = &bits[i * qm..(i + 1) * qm];
        let sym = match order {
            ModulationOrder::PiOver2Bpsk => {
                let phase = PI / 4.0 + (i as f64) * PI / 2.0;
                let val = 1.0 - 2.0 * b[0] as f64;
                Complex64::from_polar(val.abs(), phase + if val < 0.0 { PI } else { 0.0 })
            }
            ModulationOrder::Qpsk => map_qpsk(b[0], b[1]),
            ModulationOrder::Qam16 => map_16qam(b),
            ModulationOrder::Qam64 => map_64qam(b),
            ModulationOrder::Qam256 => map_256qam(b),
            ModulationOrder::Qam1024 => map_1024qam(b),
        };
        symbols.push(sym);
    }
    Ok(symbols)
}

// ---------------------------------------------------------------------------
// Max-Log LLR Soft Demapper
// ---------------------------------------------------------------------------

/// Computes Max-Log LLR soft bits for QPSK under AWGN.
pub fn soft_demod_qpsk(symbol: &Complex64, noise_var: f64) -> Vec<f64> {
    let scale = 2.0 * std::f64::consts::SQRT_2 / noise_var;
    vec![scale * symbol.re, scale * symbol.im]
}

/// Computes Max-Log LLR soft bits for 16QAM under AWGN (approximate).
pub fn soft_demod_16qam(symbol: &Complex64, noise_var: f64) -> Vec<f64> {
    let inv_sqrt10 = 1.0 / (10.0f64).sqrt();
    let scale = 2.0 / noise_var;

    let llr0 = scale * symbol.re / inv_sqrt10;
    let llr1 = scale * symbol.im / inv_sqrt10;
    let llr2 = scale * (symbol.re.abs() / inv_sqrt10 - 2.0);
    let llr3 = scale * (symbol.im.abs() / inv_sqrt10 - 2.0);

    vec![llr0, llr1, llr2, llr3]
}

// ---------------------------------------------------------------------------
// Numerology & Cyclic Prefix (TS 38.211 §4.2 / §4.3)
// ---------------------------------------------------------------------------

/// Numerology configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Numerology {
    pub mu: u8,
    pub scs_khz: u32,
    pub symbols_per_slot: usize,
    pub slots_per_subframe: usize,
    pub extended_cp: bool,
}

/// Returns standard numerology for a given $\mu$ (TS 38.211 Table 4.2-1).
pub fn get_numerology(mu: u8) -> Result<Numerology, OfdmError> {
    match mu {
        0 => Ok(Numerology { mu: 0, scs_khz: 15, symbols_per_slot: 14, slots_per_subframe: 1, extended_cp: false }),
        1 => Ok(Numerology { mu: 1, scs_khz: 30, symbols_per_slot: 14, slots_per_subframe: 2, extended_cp: false }),
        2 => Ok(Numerology { mu: 2, scs_khz: 60, symbols_per_slot: 14, slots_per_subframe: 4, extended_cp: false }),
        3 => Ok(Numerology { mu: 3, scs_khz: 120, symbols_per_slot: 14, slots_per_subframe: 8, extended_cp: false }),
        4 => Ok(Numerology { mu: 4, scs_khz: 240, symbols_per_slot: 14, slots_per_subframe: 16, extended_cp: false }),
        _ => Err(OfdmError::InvalidNumerology(mu)),
    }
}

/// Returns extended CP numerology (60 kHz SCS, 12 symbols per slot).
pub fn get_extended_cp_numerology() -> Numerology {
    Numerology { mu: 2, scs_khz: 60, symbols_per_slot: 12, slots_per_subframe: 4, extended_cp: true }
}

/// Computes cyclic prefix length in samples for a given symbol within a slot.
/// For Normal CP (TS 38.211 §5.3.1):
///   First symbol of each 0.5 ms half-subframe uses extended CP (N_CP = 160 * 2^-mu * N_FFT / 2048)
///   All other symbols use standard CP (N_CP = 144 * 2^-mu * N_FFT / 2048).
pub fn cyclic_prefix_length(
    symbol_in_slot: usize,
    n_fft: usize,
    num: &Numerology,
) -> usize {
    if num.extended_cp {
        // Extended CP: 512 * N_FFT / 2048 for all symbols
        512 * n_fft / 2048
    } else {
        // Normal CP: first symbol of each half-subframe gets 160-unit base, rest get 144
        let is_first = symbol_in_slot == 0 || symbol_in_slot == 7;
        let base = if is_first { 160 } else { 144 };
        base * n_fft / 2048
    }
}

// ---------------------------------------------------------------------------
// Cooley-Tukey Radix-2 FFT / IFFT
// ---------------------------------------------------------------------------

/// Performs in-place Cooley-Tukey Radix-2 Decimation-in-Time FFT.
pub fn fft_radix2(data: &mut [Complex64], inverse: bool) {
    let n = data.len();
    assert!(n.is_power_of_two(), "FFT size must be power of 2");

    // Bit-reversal permutation
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            data.swap(i, j);
        }
    }

    // Butterfly stages
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let angle_sign = if inverse { 1.0 } else { -1.0 };
        let w_base = Complex64::from_polar(1.0, angle_sign * 2.0 * PI / (len as f64));

        let mut start = 0;
        while start < n {
            let mut w = Complex64::new(1.0, 0.0);
            for k in 0..half {
                let u = data[start + k];
                let t = w.mul(&data[start + k + half]);
                data[start + k] = u.add(&t);
                data[start + k + half] = u.sub(&t);
                w = w.mul(&w_base);
            }
            start += len;
        }
        len <<= 1;
    }

    // Scale by 1/N for inverse FFT
    if inverse {
        let inv_n = 1.0 / (n as f64);
        for x in data.iter_mut() {
            *x = x.scale(inv_n);
        }
    }
}

// ---------------------------------------------------------------------------
// OFDM Symbol Modulator & Demodulator (TS 38.211 §5.3 / §5.4)
// ---------------------------------------------------------------------------

/// OFDM modulator: maps frequency-domain subcarriers to time-domain samples via IFFT + CP.
pub fn ofdm_modulate_symbol(
    freq_domain: &[Complex64],
    n_fft: usize,
    cp_len: usize,
) -> Result<Vec<Complex64>, OfdmError> {
    if !n_fft.is_power_of_two() || n_fft < 64 || n_fft > MAX_FFT_SIZE {
        return Err(OfdmError::InvalidFftSize(n_fft));
    }

    // Map subcarriers to FFT bins (center DC)
    let n_sc = freq_domain.len().min(n_fft);
    let mut fft_buf = vec![Complex64::zero(); n_fft];

    // Positive frequencies: indices 1..N_sc/2 map to bins 1..N_sc/2
    // Negative frequencies: indices N_sc/2..N_sc map to bins N_FFT - N_sc/2..N_FFT
    let half_sc = n_sc / 2;
    for i in 0..half_sc {
        fft_buf[i + 1] = freq_domain[half_sc + i]; // positive frequencies
    }
    for i in 0..half_sc {
        fft_buf[n_fft - half_sc + i] = freq_domain[i]; // negative frequencies
    }

    // IFFT
    fft_radix2(&mut fft_buf, true);

    // Prepend CP
    let mut ofdm_sym = Vec::with_capacity(cp_len + n_fft);
    for i in 0..cp_len {
        ofdm_sym.push(fft_buf[n_fft - cp_len + i]);
    }
    ofdm_sym.extend_from_slice(&fft_buf);

    Ok(ofdm_sym)
}

/// OFDM demodulator: strips CP and applies FFT to recover frequency-domain subcarriers.
pub fn ofdm_demodulate_symbol(
    time_domain: &[Complex64],
    n_fft: usize,
    cp_len: usize,
    n_sc: usize,
) -> Result<Vec<Complex64>, OfdmError> {
    if !n_fft.is_power_of_two() || n_fft < 64 || n_fft > MAX_FFT_SIZE {
        return Err(OfdmError::InvalidFftSize(n_fft));
    }
    if time_domain.len() < cp_len + n_fft {
        return Err(OfdmError::BufferTooShort(time_domain.len()));
    }

    // Strip CP and take FFT window
    let mut fft_buf = time_domain[cp_len..cp_len + n_fft].to_vec();

    // FFT
    fft_radix2(&mut fft_buf, false);

    // Extract subcarriers from bins (reverse of mapping in modulator)
    let half_sc = n_sc / 2;
    let mut freq_domain = vec![Complex64::zero(); n_sc];

    for i in 0..half_sc {
        freq_domain[i] = fft_buf[n_fft - half_sc + i]; // negative frequencies
    }
    for i in 0..half_sc {
        freq_domain[half_sc + i] = fft_buf[i + 1]; // positive frequencies
    }

    Ok(freq_domain)
}

// ---------------------------------------------------------------------------
// Carrier Frequency Offset (CFO) Correction
// ---------------------------------------------------------------------------

/// Applies CFO phase rotation correction: $x'(n) = x(n) \cdot e^{-j 2\pi \Delta f \cdot n / f_s}$.
pub fn apply_cfo_correction(
    samples: &mut [Complex64],
    delta_f_hz: f64,
    sample_rate_hz: f64,
) {
    let phase_inc = -2.0 * PI * delta_f_hz / sample_rate_hz;
    for (n, s) in samples.iter_mut().enumerate() {
        let rot = Complex64::from_polar(1.0, phase_inc * (n as f64));
        *s = s.mul(&rot);
    }
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16
// ---------------------------------------------------------------------------

/// Wire frame PDU for OFDM telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfdmWirePdu {
    pub magic: u32,
    pub slot_idx: u32,
    pub symbol_idx: u8,
    pub numerology_mu: u8,
    pub n_fft: u16,
    pub cp_len: u16,
    pub modulation_order: u8,
    pub payload: Vec<u8>,
    pub crc16: u16,
}

/// Computes CRC-16 CCITT.
pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ CRC16_CCITT_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

impl OfdmWirePdu {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.payload.len());
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.slot_idx.to_be_bytes());
        buf.push(self.symbol_idx);
        buf.push(self.numerology_mu);
        buf.extend_from_slice(&self.n_fft.to_be_bytes());
        buf.extend_from_slice(&self.cp_len.to_be_bytes());
        buf.push(self.modulation_order);
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, OfdmError> {
        if data.len() < 17 {
            return Err(OfdmError::DeserializationError("Buffer too small".into()));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != OFDM_WIRE_MAGIC {
            return Err(OfdmError::DeserializationError(format!("Invalid magic: 0x{:08X}", magic)));
        }

        let slot_idx = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let symbol_idx = data[8];
        let numerology_mu = data[9];
        let n_fft = u16::from_be_bytes([data[10], data[11]]);
        let cp_len = u16::from_be_bytes([data[12], data[13]]);
        let modulation_order = data[14];
        let payload_len = u16::from_be_bytes([data[15], data[16]]) as usize;

        if data.len() < 17 + payload_len + 2 {
            return Err(OfdmError::DeserializationError("Truncated payload".into()));
        }

        let payload = data[17..17 + payload_len].to_vec();
        let expected_crc = compute_crc16(&data[..17 + payload_len]);
        let rx_crc = u16::from_be_bytes([data[17 + payload_len], data[17 + payload_len + 1]]);

        if rx_crc != expected_crc {
            return Err(OfdmError::DeserializationError(format!(
                "CRC-16 mismatch: expected 0x{:04X}, received 0x{:04X}",
                expected_crc, rx_crc
            )));
        }

        Ok(Self {
            magic,
            slot_idx,
            symbol_idx,
            numerology_mu,
            n_fft,
            cp_len,
            modulation_order,
            payload,
            crc16: rx_crc,
        })
    }
}

//! 3GPP Release 18/19 5G-Advanced Sounding Reference Signal (SRS) Processor,
//! Antenna Switching & Channel State Acquisition Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §6.4.1.4: Sounding reference signal (SRS) sequences,
//!   cyclic shifts, comb mappings (Comb-2, Comb-4, Comb-8), and frequency hopping.
//! - 3GPP TS 38.214 Rel-18 §6.2.1: UE sounding procedure, antenna switching (1T2R, 1T4R, 2T4R),
//!   and channel state acquisition.
//! - 3GPP TS 38.331 Rel-18 §6.3.2: SRS-Config and SRS-ResourceSet information elements.
//!
//! Features:
//! 1. Low-PAPR Zadoff-Chu (ZC) base sequence generation ($M_{\text{sc}}^{\text{SRS}} \ge 36$) with prime sizing $N_{\text{ZC}}$.
//! 2. Computer-generated sequence generation for short sounding bandwidths ($M_{\text{sc}}^{\text{SRS}} \in \{6, 12, 18, 24\}$).
//! 3. Orthogonal cyclic shift rotation ($\alpha = 2\pi n_{\text{cs}} / N_{\text{ap}}$) with exact cross-correlation nulling.
//! 4. Transmission Comb mapper supporting Comb-2, Comb-4, and Rel-18 Comb-8 with comb offsets.
//! 5. TS 38.211 Table 6.4.1.4.3-1 hierarchical bandwidth configuration and frequency hopping engine ($n_b(n_{\text{SRS}})$).
//! 6. Antenna switching manager (1T2R, 1T4R, 2T4R) for downlink reciprocity-based channel estimation.
//! 7. Frequency-domain channel estimation engine computing Channel Frequency Response (CFR) and Channel Power.
//! 8. Binary wire framing (`SrsWirePdu`) with magic `0x53525350` ("SRSP") and CRC-16 CCITT validation.

use std::f64::consts::PI;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for SRS Wire PDU: "SRSP" (0x53525350).
pub const SRS_WIRE_MAGIC: u32 = 0x53525350;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Number of subcarriers per Physical Resource Block (PRB).
pub const SUBCARRIERS_PER_PRB: usize = 12;

/// Transmission Comb Size $K_{\text{TC}}$ (TS 38.211 §6.4.1.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrsTransmissionComb {
    Comb2 = 2,
    Comb4 = 4,
    Comb8 = 8, // Rel-18 enhanced multiplexing
}

impl SrsTransmissionComb {
    pub fn comb_size(&self) -> usize {
        *self as usize
    }

    pub fn max_cyclic_shifts(&self) -> usize {
        match self {
            SrsTransmissionComb::Comb2 => 8,
            SrsTransmissionComb::Comb4 => 12,
            SrsTransmissionComb::Comb8 => 6,
        }
    }
}

/// SRS Resource Usage (TS 38.214 §6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrsUsage {
    BeamManagement,
    Codebook,
    NonCodebook,
    AntennaSwitching,
}

/// Antenna Switching Capability mode (TS 38.214 §6.2.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntennaSwitchingMode {
    OneTxTwoRx,  // 1T2R: 2 sounding instances
    OneTxFourRx, // 1T4R: 4 sounding instances
    TwoTxFourRx, // 2T4R: 2 sounding instances with 2 ports each
}

/// Errors encountered in SRS operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrsError {
    InvalidCombOffset { offset: usize, comb: usize },
    InvalidCyclicShift { cs: usize, max: usize },
    InvalidBandwidthConfig { c_srs: usize, b_srs: usize },
    InvalidSequenceLength(usize),
    AntennaMismatch(String),
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for SrsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrsError::InvalidCombOffset { offset, comb } => {
                write!(f, "Invalid comb offset {} for Comb-{}", offset, comb)
            }
            SrsError::InvalidCyclicShift { cs, max } => {
                write!(f, "Invalid cyclic shift {} (max {})", cs, max)
            }
            SrsError::InvalidBandwidthConfig { c_srs, b_srs } => {
                write!(
                    f,
                    "Invalid SRS bandwidth config: C_SRS={}, B_SRS={}",
                    c_srs, b_srs
                )
            }
            SrsError::InvalidSequenceLength(len) => write!(f, "Invalid sequence length: {}", len),
            SrsError::AntennaMismatch(msg) => write!(f, "Antenna mismatch: {}", msg),
            SrsError::SerializationError(e) => write!(f, "SRS serialization error: {}", e),
            SrsError::DeserializationError(e) => write!(f, "SRS deserialization error: {}", e),
        }
    }
}

impl std::error::Error for SrsError {}

// ---------------------------------------------------------------------------
// Complex Number Helper for Signal Processing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex64 {
    pub re: f64,
    pub im: f64,
}

impl Complex64 {
    pub fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    pub fn from_polar(r: f64, theta: f64) -> Self {
        Self {
            re: r * theta.cos(),
            im: r * theta.sin(),
        }
    }

    pub fn norm_sqr(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    pub fn conj(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    pub fn mul(&self, rhs: &Complex64) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }

    pub fn div(&self, rhs: &Complex64) -> Self {
        let d = rhs.norm_sqr();
        if d == 0.0 {
            Self { re: 0.0, im: 0.0 }
        } else {
            Self {
                re: (self.re * rhs.re + self.im * rhs.im) / d,
                im: (self.im * rhs.re - self.re * rhs.im) / d,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SRS Base Sequence Generation (TS 38.211 §6.4.1.4.2 / §5.2.2)
// ---------------------------------------------------------------------------

/// Finds the largest prime number strictly less than `n`.
pub fn largest_prime_less_than(n: usize) -> usize {
    if n <= 3 {
        return 2;
    }
    for p in (2..n).rev() {
        let is_prime = (2..=((p as f64).sqrt() as usize)).all(|d| p % d != 0);
        if is_prime {
            return p;
        }
    }
    2
}

/// Generates low-PAPR Zadoff-Chu base sequence for $M_{\text{sc}}^{\text{SRS}} \ge 36$.
pub fn generate_zc_srs_sequence(
    m_sc: usize,
    u_group: usize,
    v_seq: usize,
    cyclic_shift: usize,
    max_cyclic_shifts: usize,
) -> Result<Vec<Complex64>, SrsError> {
    if m_sc < 6 {
        return Err(SrsError::InvalidSequenceLength(m_sc));
    }
    if cyclic_shift >= max_cyclic_shifts {
        return Err(SrsError::InvalidCyclicShift {
            cs: cyclic_shift,
            max: max_cyclic_shifts - 1,
        });
    }

    let alpha = 2.0 * PI * (cyclic_shift as f64) / (max_cyclic_shifts as f64);

    if m_sc >= 36 {
        // Zadoff-Chu sequence with prime length N_ZC
        let n_zc = largest_prime_less_than(m_sc);
        let q_bar = (n_zc as f64) * ((u_group % 30) as f64 + 1.0) / 31.0;
        let q_root = (q_bar + 0.5).floor() as i64
            + (v_seq as i64)
                * if ((2.0 * q_bar).floor() as i64) % 2 == 0 {
                    1
                } else {
                    -1
                };

        let mut seq = Vec::with_capacity(m_sc);
        for n in 0..m_sc {
            let m = n % n_zc;
            let phase_zc = -PI * (q_root as f64) * (m as f64) * ((m + 1) as f64) / (n_zc as f64);
            let total_phase = phase_zc + alpha * (n as f64);
            seq.push(Complex64::from_polar(1.0, total_phase));
        }
        Ok(seq)
    } else {
        // Computer-generated low-PAPR sequence for small lengths (TS 38.211 Table 5.2.2.2-1 to 5.2.2.2-4)
        // Default base phases for length 6, 12, 18, 24
        let base_phases: &[i8] = match m_sc {
            6 => &[-1, 1, 3, -3, 1, -1],
            12 => &[1, -1, 3, 1, 1, -1, -1, -1, 1, 3, -3, 1],
            18 => &[
                -1, 3, -1, -3, 3, 1, -3, -1, 3, -3, 3, -1, 1, 3, 1, -1, -3, 3,
            ],
            24 => &[
                -1, -3, 3, -1, 3, 1, 3, -1, 1, -3, -1, -3, -1, 1, 3, -3, -1, -3, 3, 3, 3, -3, -3,
                -3,
            ],
            _ => &[-1, 1, 3, -3, 1, -1],
        };

        let mut seq = Vec::with_capacity(m_sc);
        for n in 0..m_sc {
            let phi_idx = n % base_phases.len();
            let base_phase = (base_phases[phi_idx] as f64) * PI / 4.0;
            let total_phase = base_phase + alpha * (n as f64);
            seq.push(Complex64::from_polar(1.0, total_phase));
        }
        Ok(seq)
    }
}

// ---------------------------------------------------------------------------
// Bandwidth Configuration & Frequency Hopping (TS 38.211 Table 6.4.1.4.3-1)
// ---------------------------------------------------------------------------

/// Row entry in TS 38.211 Table 6.4.1.4.3-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrsBandwidthEntry {
    pub c_srs: usize,
    pub m_srs: [usize; 4], // m_srs_0, m_srs_1, m_srs_2, m_srs_3 (in PRBs)
    pub n_b: [usize; 4],   // N_0, N_1, N_2, N_3
}

/// Look up table entry for standard SRS bandwidth configurations.
pub fn get_srs_bandwidth_entry(c_srs: usize) -> Result<SrsBandwidthEntry, SrsError> {
    // Representative subset of TS 38.211 Table 6.4.1.4.3-1 covering common bandwidths
    match c_srs {
        0 => Ok(SrsBandwidthEntry {
            c_srs: 0,
            m_srs: [96, 48, 24, 4],
            n_b: [1, 2, 2, 6],
        }),
        1 => Ok(SrsBandwidthEntry {
            c_srs: 1,
            m_srs: [96, 32, 16, 4],
            n_b: [1, 3, 2, 4],
        }),
        7 => Ok(SrsBandwidthEntry {
            c_srs: 7,
            m_srs: [48, 24, 12, 4],
            n_b: [1, 2, 2, 3],
        }),
        14 => Ok(SrsBandwidthEntry {
            c_srs: 14,
            m_srs: [36, 12, 4, 4],
            n_b: [1, 3, 3, 1],
        }),
        20 => Ok(SrsBandwidthEntry {
            c_srs: 20,
            m_srs: [24, 12, 4, 4],
            n_b: [1, 2, 3, 1],
        }),
        28 => Ok(SrsBandwidthEntry {
            c_srs: 28,
            m_srs: [16, 8, 4, 4],
            n_b: [1, 2, 2, 1],
        }),
        36 => Ok(SrsBandwidthEntry {
            c_srs: 36,
            m_srs: [8, 4, 4, 4],
            n_b: [1, 2, 1, 1],
        }),
        63 => Ok(SrsBandwidthEntry {
            c_srs: 63,
            m_srs: [4, 4, 4, 4],
            n_b: [1, 1, 1, 1],
        }),
        _ => Err(SrsError::InvalidBandwidthConfig { c_srs, b_srs: 0 }),
    }
}

/// Frequency hopping and PRB allocation parameters.
#[derive(Debug, Clone)]
pub struct SrsFrequencyHoppingConfig {
    pub c_srs: usize,
    pub b_srs: usize,
    pub b_hop: usize,
    pub n_rrc: usize,
}

/// Computes the frequency hopping PRB allocation index $n_b$ for level $b$ at transmission instance $n_{\text{SRS}}$.
pub fn calculate_srs_hopping_index(
    cfg: &SrsFrequencyHoppingConfig,
    b_level: usize,
    n_srs: usize,
) -> Result<usize, SrsError> {
    let entry = get_srs_bandwidth_entry(cfg.c_srs)?;
    if b_level > 3 || b_level > cfg.b_srs {
        return Err(SrsError::InvalidBandwidthConfig {
            c_srs: cfg.c_srs,
            b_srs: b_level,
        });
    }

    let n_b_val = entry.n_b[b_level];
    if n_b_val == 0 {
        return Ok(0);
    }

    if b_level <= cfg.b_hop {
        // No hopping at this level
        let n_b = ((4 * cfg.n_rrc) / entry.m_srs[b_level]) % n_b_val;
        Ok(n_b)
    } else {
        // Frequency hopping active: TS 38.211 §6.4.1.4.3
        let mut prod_below = 1;
        for b_prime in cfg.b_hop..b_level {
            prod_below *= entry.n_b[b_prime];
        }
        let mut prod_all = prod_below;
        prod_all *= entry.n_b[b_level];

        let f_b = if prod_all > 0 && prod_below > 0 {
            (prod_all * (n_srs / prod_below) + ((n_srs % prod_all) / prod_below)) % n_b_val
        } else {
            0
        };

        let n_b = (f_b + ((4 * cfg.n_rrc) / entry.m_srs[b_level])) % n_b_val;
        Ok(n_b)
    }
}

// ---------------------------------------------------------------------------
// Transmission Comb Mapping (TS 38.211 §6.4.1.4.3)
// ---------------------------------------------------------------------------

/// Maps SRS base sequence symbols onto physical subcarriers according to comb size and offset.
pub fn map_srs_to_subcarriers(
    seq: &[Complex64],
    comb: SrsTransmissionComb,
    comb_offset: usize,
    start_prb: usize,
    total_prb_capacity: usize,
) -> Result<Vec<(usize, Complex64)>, SrsError> {
    let k_tc = comb.comb_size();
    if comb_offset >= k_tc {
        return Err(SrsError::InvalidCombOffset {
            offset: comb_offset,
            comb: k_tc,
        });
    }

    let start_sc = start_prb * SUBCARRIERS_PER_PRB;
    let max_sc = total_prb_capacity * SUBCARRIERS_PER_PRB;

    let mut mapped = Vec::with_capacity(seq.len());
    for (n, &sym) in seq.iter().enumerate() {
        let sc = start_sc + n * k_tc + comb_offset;
        if sc < max_sc {
            mapped.push((sc, sym));
        }
    }

    Ok(mapped)
}

// ---------------------------------------------------------------------------
// Antenna Switching & Channel State Acquisition (TS 38.214 §6.2.1.2)
// ---------------------------------------------------------------------------

/// Antenna switching scheduler and channel estimation result.
#[derive(Debug, Clone)]
pub struct SrsAntennaManager {
    pub mode: AntennaSwitchingMode,
    pub total_rx_antennas: usize,
}

impl SrsAntennaManager {
    pub fn new(mode: AntennaSwitchingMode) -> Self {
        let total_rx_antennas = match mode {
            AntennaSwitchingMode::OneTxTwoRx => 2,
            AntennaSwitchingMode::OneTxFourRx => 4,
            AntennaSwitchingMode::TwoTxFourRx => 4,
        };
        Self {
            mode,
            total_rx_antennas,
        }
    }

    /// Determines which physical antenna port(s) are active for sounding instance `n_srs`.
    pub fn active_antennas_for_instance(&self, n_srs: usize) -> Vec<usize> {
        match self.mode {
            AntennaSwitchingMode::OneTxTwoRx => vec![n_srs % 2],
            AntennaSwitchingMode::OneTxFourRx => vec![n_srs % 4],
            AntennaSwitchingMode::TwoTxFourRx => {
                let pair = n_srs % 2;
                if pair == 0 { vec![0, 1] } else { vec![2, 3] }
            }
        }
    }

    /// Performs least-squares channel estimation $\hat{H}(k) = Y(k) / X(k)$ across subcarriers.
    pub fn estimate_channel(
        &self,
        rx_symbols: &[(usize, Complex64)],
        tx_symbols: &[(usize, Complex64)],
    ) -> Vec<(usize, Complex64)> {
        let mut cfr = Vec::with_capacity(rx_symbols.len());
        for (rx, tx) in rx_symbols.iter().zip(tx_symbols.iter()) {
            if rx.0 == tx.0 {
                let h = rx.1.div(&tx.1);
                cfr.push((rx.0, h));
            }
        }
        cfr
    }

    /// Computes average Channel Power / SS-RSRP in dBm from estimated CFR.
    pub fn compute_channel_power_dbm(&self, cfr: &[(usize, Complex64)]) -> f64 {
        if cfr.is_empty() {
            return -140.0;
        }
        let total_pwr: f64 = cfr.iter().map(|(_, h)| h.norm_sqr()).sum();
        let avg_pwr = total_pwr / (cfr.len() as f64);
        10.0 * avg_pwr.max(1e-14).log10() + 30.0 // dBW to dBm
    }
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16
// ---------------------------------------------------------------------------

/// Wire frame PDU for SRS configuration and channel telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsWirePdu {
    pub magic: u32,
    pub srs_instance: u32,
    pub c_srs: u8,
    pub b_srs: u8,
    pub b_hop: u8,
    pub comb_size: u8,
    pub comb_offset: u8,
    pub cyclic_shift: u8,
    pub antenna_port: u8,
    pub start_prb: u16,
    pub num_prb: u16,
    pub payload: Vec<u8>,
    pub crc16: u16,
}

/// Computes CRC-16 CCITT over binary slice.
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

impl SrsWirePdu {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + self.payload.len());
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.srs_instance.to_be_bytes());
        buf.push(self.c_srs);
        buf.push(self.b_srs);
        buf.push(self.b_hop);
        buf.push(self.comb_size);
        buf.push(self.comb_offset);
        buf.push(self.cyclic_shift);
        buf.push(self.antenna_port);
        buf.extend_from_slice(&self.start_prb.to_be_bytes());
        buf.extend_from_slice(&self.num_prb.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, SrsError> {
        if data.len() < 22 {
            return Err(SrsError::DeserializationError("Buffer too small".into()));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != SRS_WIRE_MAGIC {
            return Err(SrsError::DeserializationError(format!(
                "Invalid magic: 0x{:08X}",
                magic
            )));
        }

        let srs_instance = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let c_srs = data[8];
        let b_srs = data[9];
        let b_hop = data[10];
        let comb_size = data[11];
        let comb_offset = data[12];
        let cyclic_shift = data[13];
        let antenna_port = data[14];
        let start_prb = u16::from_be_bytes([data[15], data[16]]);
        let num_prb = u16::from_be_bytes([data[17], data[18]]);
        let payload_len = u16::from_be_bytes([data[19], data[20]]) as usize;

        if data.len() < 21 + payload_len + 2 {
            return Err(SrsError::DeserializationError("Truncated payload".into()));
        }

        let payload = data[21..21 + payload_len].to_vec();
        let expected_crc = compute_crc16(&data[..21 + payload_len]);
        let rx_crc = u16::from_be_bytes([data[21 + payload_len], data[21 + payload_len + 1]]);

        if rx_crc != expected_crc {
            return Err(SrsError::DeserializationError(format!(
                "CRC-16 mismatch: expected 0x{:04X}, received 0x{:04X}",
                expected_crc, rx_crc
            )));
        }

        Ok(Self {
            magic,
            srs_instance,
            c_srs,
            b_srs,
            b_hop,
            comb_size,
            comb_offset,
            cyclic_shift,
            antenna_port,
            start_prb,
            num_prb,
            payload,
            crc16: rx_crc,
        })
    }
}

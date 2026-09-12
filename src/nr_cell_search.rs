//! 3GPP Release 18/19 5G-Advanced Initial Cell Search, PSS/SSS Synchronization, CFO Estimation & Beam Timing Acquisition Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §7.4.2: Synchronization signals (PSS length-127 m-sequence, SSS length-127 Gold sequence,
//!   and Physical Cell ID $N_{\text{ID}}^{\text{cell}} = 3 N_{\text{ID}}^{(1)} + N_{\text{ID}}^{(2)} \in [0, 1007]$).
//! - 3GPP TS 38.211 Rel-18 §7.4.3: Demodulation reference signals for PBCH (comb-4 subcarrier mapping and $c_{\text{init}}$).
//! - 3GPP TS 38.213 Rel-18 §4.1: Cell search, SSB burst patterns, and timing synchronization procedures.
//! - 3GPP TS 38.215 Rel-18 §5.1: SS-RSRP, SS-RSRQ, and SS-SINR measurement definitions.
//!
//! Features:
//! 1. PSS matched filter and sliding time-domain cross-correlator detecting sample timing and $N_{\text{ID}}^{(2)} \in \{0, 1, 2\}$.
//! 2. Peak-to-Sidelobe Ratio (PSLR) metric rejecting noise spikes and false synchronization triggers.
//! 3. Fractional Carrier Frequency Offset (FCFO) estimator and digital time-domain phase rotator.
//! 4. SSS frequency-domain cross-correlator identifying $N_{\text{ID}}^{(1)} \in [0, 335]$ and computing full PCI ($N_{\text{ID}}^{\text{cell}} \in [0, 1007]$).
//! 5. PBCH DMRS hypothesis testing identifying the transmitted SSB beam index ($i_{\text{SSB}} \in [0, L_{\text{max}}-1]$).
//! 6. Standard SS-RSRP (dBm), SS-RSSI (dBm), SS-RSRQ (dB), and SS-SINR (dB) measurement engine.
//! 7. Binary wire framing (`CellSearchWirePdu`) with magic `0x43454C53` ("CELS") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for Cell Search Wire PDU: "CELS" (0x43454C53).
pub const CELS_WIRE_MAGIC: u32 = 0x43454C53;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Length of standard 3GPP PSS and SSS sequences.
pub const SYNC_SEQUENCE_LENGTH: usize = 127;

/// Total number of subcarriers per SSB (20 PRBs * 12 = 240).
pub const SSB_SUBCARRIERS: usize = 240;

/// Offset of PSS/SSS within the 240 subcarriers of the SSB.
pub const SYNC_SUBCARRIER_OFFSET: usize = 56;

/// Total number of Physical Cell IDs (PCIs) in 5G NR (0..1007).
pub const TOTAL_NR_PCIS: usize = 1008;

/// Errors encountered in cell search and synchronization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellSearchError {
    BufferTooShort { needed: usize, found: usize },
    InvalidNid2(u8),
    InvalidNid1(u16),
    InvalidPci(u16),
    InvalidSsbIndex(u8),
    NoPeakDetected { peak_metric: u32, threshold: u32 },
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    WireCrcMismatch { expected: u16, computed: u16 },
}

impl fmt::Display for CellSearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { needed, found } => {
                write!(
                    f,
                    "Sample buffer too short: needed {}, found {}",
                    needed, found
                )
            }
            Self::InvalidNid2(n) => write!(f, "Invalid N_ID^(2): {} (must be 0, 1, or 2)", n),
            Self::InvalidNid1(n) => write!(f, "Invalid N_ID^(1): {} (must be 0..335)", n),
            Self::InvalidPci(p) => write!(f, "Invalid PCI: {} (must be 0..1007)", p),
            Self::InvalidSsbIndex(i) => write!(f, "Invalid SSB index: {}", i),
            Self::NoPeakDetected {
                peak_metric,
                threshold,
            } => {
                write!(
                    f,
                    "No synchronization peak detected: metric {}, threshold {}",
                    peak_metric, threshold
                )
            }
            Self::InvalidWireMagic(m) => write!(f, "Invalid wire magic: 0x{:08X}", m),
            Self::WirePayloadTooShort { needed, found } => {
                write!(
                    f,
                    "Wire payload too short: needed {} bytes, found {}",
                    needed, found
                )
            }
            Self::WireCrcMismatch { expected, computed } => {
                write!(
                    f,
                    "Wire CRC-16 mismatch: expected 0x{:04X}, computed 0x{:04X}",
                    expected, computed
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Complex Number Support for Receiver DSP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Complex32 {
    pub re: f32,
    pub im: f32,
}

impl Complex32 {
    #[inline]
    pub const fn new(re: f32, im: f32) -> Self {
        Self { re, im }
    }

    #[inline]
    pub const fn zero() -> Self {
        Self { re: 0.0, im: 0.0 }
    }

    #[inline]
    pub fn conj(self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    #[inline]
    pub fn norm_sqr(self) -> f32 {
        self.re * self.re + self.im * self.im
    }

    #[inline]
    pub fn norm(self) -> f32 {
        self.norm_sqr().sqrt()
    }

    #[inline]
    pub fn mul(self, rhs: Self) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }

    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }

    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        Self {
            re: self.re - rhs.re,
            im: self.im - rhs.im,
        }
    }

    #[inline]
    pub fn scale(self, s: f32) -> Self {
        Self {
            re: self.re * s,
            im: self.im * s,
        }
    }
}

// ---------------------------------------------------------------------------
// 3GPP PSS & SSS Sequence Generation (TS 38.211 §7.4.2)
// ---------------------------------------------------------------------------

/// Generates the length-127 PSS sequence for a given $N_{\text{ID}}^{(2)} \in \{0, 1, 2\}$.
/// $d_{\text{PSS}}(n) = 1 - 2 x(m)$ where $m = (n + 43 N_{\text{ID}}^{(2)}) \bmod 127$.
pub fn generate_pss_sequence(nid2: u8) -> Result<[i8; SYNC_SEQUENCE_LENGTH], CellSearchError> {
    if nid2 > 2 {
        return Err(CellSearchError::InvalidNid2(nid2));
    }

    // Length-127 m-sequence generator: x(i+7) = (x(i+4) + x(i)) mod 2
    let mut x = [0u8; SYNC_SEQUENCE_LENGTH];
    x[0] = 0;
    x[1] = 1;
    x[2] = 1;
    x[3] = 0;
    x[4] = 1;
    x[5] = 1;
    x[6] = 1;

    for i in 0..(SYNC_SEQUENCE_LENGTH - 7) {
        x[i + 7] = x[i + 4] ^ x[i];
    }

    let offset = (43 * (nid2 as usize)) % SYNC_SEQUENCE_LENGTH;
    let mut pss = [0i8; SYNC_SEQUENCE_LENGTH];
    for n in 0..SYNC_SEQUENCE_LENGTH {
        let m = (n + offset) % SYNC_SEQUENCE_LENGTH;
        pss[n] = 1 - 2 * (x[m] as i8);
    }

    Ok(pss)
}

/// Generates the length-127 SSS sequence for a given $N_{\text{ID}}^{(1)} \in [0, 335]$ and $N_{\text{ID}}^{(2)} \in \{0, 1, 2\}$.
pub fn generate_sss_sequence(
    nid1: u16,
    nid2: u8,
) -> Result<[i8; SYNC_SEQUENCE_LENGTH], CellSearchError> {
    if nid1 > 335 {
        return Err(CellSearchError::InvalidNid1(nid1));
    }
    if nid2 > 2 {
        return Err(CellSearchError::InvalidNid2(nid2));
    }

    let m0 = 15 * ((nid1 as usize) / 112) + 5 * (nid2 as usize);
    let m1 = (nid1 as usize) % 112;

    // x0 generator: x0(i+7) = (x0(i+4) + x0(i)) mod 2, init [1, 0, 0, 0, 0, 0, 0]
    let mut x0 = [0u8; SYNC_SEQUENCE_LENGTH];
    x0[0] = 1;
    for i in 0..(SYNC_SEQUENCE_LENGTH - 7) {
        x0[i + 7] = x0[i + 4] ^ x0[i];
    }

    // x1 generator: x1(i+7) = (x1(i+1) + x1(i)) mod 2, init [1, 0, 0, 0, 0, 0, 0]
    let mut x1 = [0u8; SYNC_SEQUENCE_LENGTH];
    x1[0] = 1;
    for i in 0..(SYNC_SEQUENCE_LENGTH - 7) {
        x1[i + 7] = x1[i + 1] ^ x1[i];
    }

    let mut sss = [0i8; SYNC_SEQUENCE_LENGTH];
    for n in 0..SYNC_SEQUENCE_LENGTH {
        let idx0 = (n + m0) % SYNC_SEQUENCE_LENGTH;
        let idx1 = (n + m1) % SYNC_SEQUENCE_LENGTH;
        let b0 = 1 - 2 * (x0[idx0] as i8);
        let b1 = 1 - 2 * (x1[idx1] as i8);
        sss[n] = b0 * b1;
    }

    Ok(sss)
}

// ---------------------------------------------------------------------------
// PSS Matched Filter & Timing Detector (TS 38.213 §4.1)
// ---------------------------------------------------------------------------

/// Result of PSS detection and timing synchronization.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PssDetectionResult {
    /// Detected sample timing index where the PSS begins.
    pub timing_offset: usize,
    /// Detected $N_{\text{ID}}^{(2)} \in \{0, 1, 2\}$.
    pub nid2: u8,
    /// Peak correlation metric magnitude.
    pub peak_metric: f32,
    /// Peak-to-Sidelobe Ratio (PSLR) indicating signal confidence.
    pub pslr: f32,
}

/// Detects PSS and sample timing boundary via sliding cross-correlation across $N_{\text{ID}}^{(2)} \in \{0, 1, 2\}$.
pub fn detect_pss(
    received_samples: &[Complex32],
    search_window_size: usize,
    min_pslr_threshold: f32,
) -> Result<PssDetectionResult, CellSearchError> {
    if received_samples.len() < SYNC_SEQUENCE_LENGTH {
        return Err(CellSearchError::BufferTooShort {
            needed: SYNC_SEQUENCE_LENGTH,
            found: received_samples.len(),
        });
    }

    let max_delay = search_window_size.min(received_samples.len() - SYNC_SEQUENCE_LENGTH);

    // Precompute the 3 PSS reference sequences
    let pss_refs = [
        generate_pss_sequence(0)?,
        generate_pss_sequence(1)?,
        generate_pss_sequence(2)?,
    ];

    let mut best_nid2 = 0u8;
    let mut best_delay = 0usize;
    let mut max_corr_sqr = -1.0f32;
    let mut total_corr_sum = 0.0f32;
    let mut total_evals = 0usize;

    for nid2 in 0..3 {
        let ref_seq = &pss_refs[nid2];

        for d in 0..=max_delay {
            let mut corr = Complex32::zero();
            let mut energy = 0.0f32;

            for n in 0..SYNC_SEQUENCE_LENGTH {
                let y = received_samples[d + n];
                let r = ref_seq[n] as f32;
                corr = corr.add(y.scale(r));
                energy += y.norm_sqr();
            }

            let corr_sqr = corr.norm_sqr() / energy.max(1e-9);
            total_corr_sum += corr_sqr;
            total_evals += 1;

            if corr_sqr > max_corr_sqr {
                max_corr_sqr = corr_sqr;
                best_delay = d;
                best_nid2 = nid2 as u8;
            }
        }
    }

    let avg_corr = if total_evals > 1 {
        (total_corr_sum - max_corr_sqr) / ((total_evals - 1) as f32)
    } else {
        1e-6
    };

    let pslr = if avg_corr > 1e-9 {
        max_corr_sqr / avg_corr
    } else {
        1.0
    };

    if pslr < min_pslr_threshold {
        return Err(CellSearchError::NoPeakDetected {
            peak_metric: (pslr * 100.0) as u32,
            threshold: (min_pslr_threshold * 100.0) as u32,
        });
    }

    Ok(PssDetectionResult {
        timing_offset: best_delay,
        nid2: best_nid2,
        peak_metric: max_corr_sqr,
        pslr,
    })
}

// ---------------------------------------------------------------------------
// Carrier Frequency Offset (CFO) Estimator & Phase Rotator
// ---------------------------------------------------------------------------

/// Estimates fractional carrier frequency offset (in normalized units $\Delta f \cdot T_s$)
/// using correlation across two identical or repeated segments separated by `distance_samples`.
pub fn estimate_fractional_cfo(
    segment_a: &[Complex32],
    segment_b: &[Complex32],
    distance_samples: usize,
) -> Result<f32, CellSearchError> {
    if segment_a.is_empty() || segment_a.len() != segment_b.len() {
        return Err(CellSearchError::BufferTooShort {
            needed: segment_a.len().max(1),
            found: segment_b.len(),
        });
    }

    let mut auto_corr = Complex32::zero();
    for i in 0..segment_a.len() {
        let prod = segment_b[i].mul(segment_a[i].conj());
        auto_corr = auto_corr.add(prod);
    }

    let angle = auto_corr.im.atan2(auto_corr.re);
    let norm_cfo = angle / (2.0 * std::f32::consts::PI * (distance_samples as f32));
    Ok(norm_cfo)
}

/// Applies time-domain digital phase rotation to correct carrier frequency offset:
/// $y_{\text{corr}}(n) = y(n) \cdot e^{-j 2\pi \Delta f n T_s}$.
pub fn apply_cfo_correction(
    samples: &[Complex32],
    norm_cfo: f32, // normalized CFO: Delta_f * T_s
) -> Vec<Complex32> {
    let two_pi = 2.0 * std::f32::consts::PI;
    let mut corrected = Vec::with_capacity(samples.len());

    for (n, &s) in samples.iter().enumerate() {
        let phase = -two_pi * norm_cfo * (n as f32);
        let rotator = Complex32::new(phase.cos(), phase.sin());
        corrected.push(s.mul(rotator));
    }

    corrected
}

// ---------------------------------------------------------------------------
// SSS Cross-Correlation & Physical Cell ID (PCI) Derivation (TS 38.211 §7.4.2.1)
// ---------------------------------------------------------------------------

/// Result of SSS detection and full Physical Cell ID derivation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SssDetectionResult {
    /// Full Physical Cell ID: $N_{\text{ID}}^{\text{cell}} = 3 N_{\text{ID}}^{(1)} + N_{\text{ID}}^{(2)} \in [0, 1007]$.
    pub pci: u16,
    /// Detected $N_{\text{ID}}^{(1)} \in [0, 335]$.
    pub nid1: u16,
    /// Peak correlation metric magnitude.
    pub correlation_metric: f32,
}

/// Detects $N_{\text{ID}}^{(1)} \in [0, 335]$ by frequency-domain cross-correlation against candidate SSS sequences.
pub fn detect_sss(
    received_sss_subcarriers: &[Complex32], // Exactly 127 subcarriers of the SSS symbol
    nid2: u8,
) -> Result<SssDetectionResult, CellSearchError> {
    if received_sss_subcarriers.len() < SYNC_SEQUENCE_LENGTH {
        return Err(CellSearchError::BufferTooShort {
            needed: SYNC_SEQUENCE_LENGTH,
            found: received_sss_subcarriers.len(),
        });
    }
    if nid2 > 2 {
        return Err(CellSearchError::InvalidNid2(nid2));
    }

    let mut best_nid1 = 0u16;
    let mut max_corr = -1.0f32;

    for nid1 in 0..=335 {
        let sss_ref = generate_sss_sequence(nid1, nid2)?;
        let mut sum_re = 0.0f32;
        let mut sum_im = 0.0f32;

        for n in 0..SYNC_SEQUENCE_LENGTH {
            let y = received_sss_subcarriers[n];
            let r = sss_ref[n] as f32;
            sum_re += y.re * r;
            sum_im += y.im * r;
        }

        let metric = sum_re * sum_re + sum_im * sum_im;
        if metric > max_corr {
            max_corr = metric;
            best_nid1 = nid1;
        }
    }

    let pci = 3 * best_nid1 + (nid2 as u16);

    Ok(SssDetectionResult {
        pci,
        nid1: best_nid1,
        correlation_metric: max_corr,
    })
}

// ---------------------------------------------------------------------------
// PBCH DMRS Hypothesis Testing & SSB Beam Index Detector (TS 38.211 §7.4.3)
// ---------------------------------------------------------------------------

/// Detects the transmitted SSB beam index ($i_{\text{SSB}} \in [0, L_{\text{max}}-1]$)
/// by evaluating correlation against candidate PBCH DMRS Gold sequences.
pub fn detect_ssb_beam_index(
    received_pbch_dmrs: &[Complex32], // Received DMRS resource elements
    pci: u16,
    l_max: u8,
) -> Result<u8, CellSearchError> {
    if received_pbch_dmrs.is_empty() {
        return Err(CellSearchError::BufferTooShort {
            needed: 1,
            found: 0,
        });
    }
    if pci >= TOTAL_NR_PCIS as u16 {
        return Err(CellSearchError::InvalidPci(pci));
    }

    let candidates = l_max.clamp(1, 8) as usize;
    let mut best_index = 0u8;
    let mut max_corr = -1.0f32;

    let inv_sqrt2 = 1.0 / std::f32::consts::SQRT_2;

    for issb in 0..candidates {
        // Compute c_init per TS 38.211 §7.4.3.1:
        // c_init = 2^11 * (issb + 1) * (floor(PCI / 4) + 1) + 2^6 * (issb + 1) + (PCI % 4) mod 2^31
        let pci_div4 = (pci / 4) as u32;
        let pci_mod4 = (pci % 4) as u32;
        let issb_p1 = (issb + 1) as u32;

        let term1 = ((1 << 11) * issb_p1 * (pci_div4 + 1)) & 0x7FFF_FFFF;
        let term2 = ((1 << 6) * issb_p1 + pci_mod4) & 0x7FFF_FFFF;
        let c_init = (term1 + term2) & 0x7FFF_FFFF;

        // Generate Gold sequence
        let mut x1 = [0u8; 31];
        let mut x2 = [0u8; 31];
        x1[0] = 1;
        for i in 0..31 {
            x2[i] = ((c_init >> i) & 1) as u8;
        }

        // Advance 1600 steps
        for _ in 0..1600 {
            let new_x1 = x1[3] ^ x1[0];
            let new_x2 = x2[3] ^ x2[2] ^ x2[1] ^ x2[0];
            x1.copy_within(1..31, 0);
            x1[30] = new_x1;
            x2.copy_within(1..31, 0);
            x2[30] = new_x2;
        }

        // Generate reference symbols and evaluate correlation
        let mut corr_re = 0.0f32;
        let mut corr_im = 0.0f32;

        for &rx in received_pbch_dmrs {
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

            let ref_re = inv_sqrt2 * (1.0 - 2.0 * (c0 as f32));
            let ref_im = inv_sqrt2 * (1.0 - 2.0 * (c1 as f32));

            // rx * conj(ref)
            corr_re += rx.re * ref_re + rx.im * ref_im;
            corr_im += rx.im * ref_re - rx.re * ref_im;
        }

        let metric = corr_re * corr_re + corr_im * corr_im;
        if metric > max_corr {
            max_corr = metric;
            best_index = issb as u8;
        }
    }

    Ok(best_index)
}

// ---------------------------------------------------------------------------
// SS-RSRP, SS-RSRQ & SS-SINR Measurement Engine (TS 38.215 §5.1)
// ---------------------------------------------------------------------------

/// 3GPP Layer 1 SS Reference Signal Measurements.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SsMeasurements {
    /// SS-RSRP: linear power average over SSS resource elements (dBm).
    pub ss_rsrp_dbm: f32,
    /// SS-RSSI: total received power across the 240 subcarriers of the SSB (dBm).
    pub ss_rssi_dbm: f32,
    /// SS-RSRQ: $N \cdot \text{SS-RSRP} / \text{SS-RSSI}$ (dB).
    pub ss_rsrq_db: f32,
    /// SS-SINR: signal to interference plus noise ratio over SSS REs (dB).
    pub ss_sinr_db: f32,
}

/// Computes SS-RSRP, SS-RSSI, SS-RSRQ, and SS-SINR over measured SSS and SSB symbols.
pub fn compute_ss_measurements(
    sss_subcarriers: &[Complex32],       // Exactly 127 SSS subcarriers
    ssb_total_subcarriers: &[Complex32], // 240 subcarriers across SSB
    noise_power_linear: f32,
) -> Result<SsMeasurements, CellSearchError> {
    if sss_subcarriers.is_empty() || ssb_total_subcarriers.is_empty() {
        return Err(CellSearchError::BufferTooShort {
            needed: 1,
            found: 0,
        });
    }

    // SS-RSRP: average power over SSS REs
    let mut sss_power_sum = 0.0f32;
    for &s in sss_subcarriers {
        sss_power_sum += s.norm_sqr();
    }
    let ss_rsrp_lin = sss_power_sum / (sss_subcarriers.len() as f32);
    let ss_rsrp_dbm = 10.0 * (ss_rsrp_lin.max(1e-12) / 1e-3).log10();

    // SS-RSSI: total received power across all subcarriers in the symbol
    let mut ssb_power_sum = 0.0f32;
    for &s in ssb_total_subcarriers {
        ssb_power_sum += s.norm_sqr();
    }
    let ss_rssi_lin = ssb_power_sum;
    let ss_rssi_dbm = 10.0 * (ss_rssi_lin.max(1e-12) / 1e-3).log10();

    // SS-RSRQ = N * SS_RSRP / SS_RSSI where N = 20 PRBs (TS 38.215 §5.1.3)
    let n_prbs = 20.0f32;
    let ss_rsrq_lin = (n_prbs * ss_rsrp_lin) / ss_rssi_lin.max(1e-12);
    let ss_rsrq_db = 10.0 * ss_rsrq_lin.max(1e-6).log10();

    // SS-SINR: Signal / Noise
    let noise_lin = noise_power_linear.max(1e-12);
    let ss_sinr_lin = (ss_rsrp_lin - noise_lin).max(1e-9) / noise_lin;
    let ss_sinr_db = 10.0 * ss_sinr_lin.log10();

    Ok(SsMeasurements {
        ss_rsrp_dbm,
        ss_rssi_dbm,
        ss_rsrq_db,
        ss_sinr_db,
    })
}

// ---------------------------------------------------------------------------
// CRC-16 CCITT for Wire Framing
// ---------------------------------------------------------------------------

pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= (b as u16) << 8;
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

// ---------------------------------------------------------------------------
// Binary Wire Framing (`CellSearchWirePdu`)
// ---------------------------------------------------------------------------

/// Wire PDU transporting cell search and synchronization telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct CellSearchWirePdu {
    pub pci: u16,
    pub timing_offset: u32,
    pub ssb_beam_index: u8,
    pub cfo_hz: f32,
    pub ss_rsrp_dbm: f32,
    pub ss_sinr_db: f32,
}

impl CellSearchWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(25);
        buf.extend_from_slice(&CELS_WIRE_MAGIC.to_be_bytes());
        buf.extend_from_slice(&self.pci.to_be_bytes());
        buf.extend_from_slice(&self.timing_offset.to_be_bytes());
        buf.push(self.ssb_beam_index);
        buf.extend_from_slice(&self.cfo_hz.to_be_bytes());
        buf.extend_from_slice(&self.ss_rsrp_dbm.to_be_bytes());
        buf.extend_from_slice(&self.ss_sinr_db.to_be_bytes());

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CellSearchError> {
        if bytes.len() < 25 {
            return Err(CellSearchError::WirePayloadTooShort {
                needed: 25,
                found: bytes.len(),
            });
        }
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != CELS_WIRE_MAGIC {
            return Err(CellSearchError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(CellSearchError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let pci = u16::from_be_bytes([bytes[4], bytes[5]]);
        let timing_offset = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let ssb_beam_index = bytes[10];
        let cfo_hz = f32::from_be_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);
        let ss_rsrp_dbm = f32::from_be_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]);
        let ss_sinr_db = f32::from_be_bytes([bytes[19], bytes[20], bytes[21], bytes[22]]);

        Ok(Self {
            pci,
            timing_offset,
            ssb_beam_index,
            cfo_hz,
            ss_rsrp_dbm,
            ss_sinr_db,
        })
    }
}

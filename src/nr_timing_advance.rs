//! 3GPP Release 18/19 5G-Advanced Timing Advance Management, RAR MAC PDU Assembly & Time Alignment Timer (TAT) Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 Rel-18 §4.3.1: Basic time units $T_c$, $T_s$, and ratio $\kappa = 64$.
//! - 3GPP TS 38.213 Rel-18 §4.2: Timing advance procedures, initial 12-bit RAR command ($T_A \in [0, 3846]$),
//!   and 6-bit MAC CE updates ($T_A \in [0, 63]$) across numerologies $\mu \in \{0, 1, 2, 3\}$.
//! - 3GPP TS 38.321 Rel-18 §5.2: Time Alignment Timer (TAT) lifecycle and expiry actions.
//! - 3GPP TS 38.321 Rel-18 §6.1.5, §6.2.3: MAC RAR PDU framing with E/T/RAPID and Backoff Indicator (BI) subheaders.
//! - 3GPP TR 38.821 / Rel-18: Autonomous Timing Advance (ATA) Doppler drift tracking and pre-compensation.
//!
//! Features:
//! 1. High-precision basic time unit conversions ($T_c = 0.5086$ ns, $T_s = 32.552$ ns).
//! 2. Initial TA calculation ($N_{\text{TA}} = T_A \cdot 16 \cdot 64 / 2^\mu$) and total advance time $T_{\text{TA}}$.
//! 3. Closed-loop dynamic MAC CE timing advance updates ($\Delta N_{\text{TA}} = (T_A - 31) \cdot 16 \cdot 64 / 2^\mu$).
//! 4. TimeAlignmentTimer (TAT) state machine managing duration, tick updates, and expiry actions.
//! 5. Rel-18 Autonomous Timing Advance (ATA) velocity-based Doppler drift estimator.
//! 6. Standard MAC RAR PDU framing: E/T/RAPID subheaders, BI subheaders, and 7-byte RAR payloads.
//! 7. Binary wire framing (`TimingAdvanceWirePdu`) with magic `0x54494D41` ("TIMA") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for Timing Advance Wire PDU: "TIMA" (0x54494D41).
pub const TIMA_WIRE_MAGIC: u32 = 0x54494D41;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Speed of light in vacuum (m/s).
pub const SPEED_OF_LIGHT: f64 = 299_792_458.0;

/// Basic time unit $T_c = 1 / (\Delta f_{\max} \cdot N_f) = 1 / (480000 \cdot 4096)$ seconds (approx 0.5086263 ns).
pub const T_C_SECONDS: f64 = 1.0 / (480_000.0 * 4096.0);

/// Basic time unit $T_s = 1 / (\Delta f_{\text{ref}} \cdot N_{f,\text{ref}}) = 1 / (15000 \cdot 2048)$ seconds (approx 32.552083 ns).
pub const T_S_SECONDS: f64 = 1.0 / (15_000.0 * 2048.0);

/// Timing ratio $\kappa = T_s / T_c = 64$.
pub const KAPPA: u32 = 64;

/// Errors encountered in timing advance management and MAC RAR processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimingAdvanceError {
    InvalidNumerology(u8),
    InvalidInitialTaIndex(u16),
    InvalidMacCeTaIndex(u8),
    InvalidRapid(u8),
    InvalidBackoffIndicator(u8),
    RarPduTooShort { needed: usize, found: usize },
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    WireCrcMismatch { expected: u16, computed: u16 },
}

impl fmt::Display for TimingAdvanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNumerology(mu) => {
                write!(f, "Invalid numerology mu: {} (must be 0..3)", mu)
            }
            Self::InvalidInitialTaIndex(ta) => {
                write!(f, "Invalid initial TA index: {} (must be 0..3846)", ta)
            }
            Self::InvalidMacCeTaIndex(ta) => {
                write!(f, "Invalid MAC CE TA index: {} (must be 0..63)", ta)
            }
            Self::InvalidRapid(r) => write!(f, "Invalid RAPID: {} (must be 0..63)", r),
            Self::InvalidBackoffIndicator(bi) => {
                write!(f, "Invalid Backoff Indicator: {} (must be 0..15)", bi)
            }
            Self::RarPduTooShort { needed, found } => {
                write!(
                    f,
                    "RAR PDU too short: needed {} bytes, found {}",
                    needed, found
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
// 3GPP Numerology & Timing Advance Offset (TS 38.211 §4.3.1, TS 38.213 §4.2)
// ---------------------------------------------------------------------------

/// Subcarrier spacing numerology $\mu \in \{0, 1, 2, 3\}$.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrNumerology {
    Mu0_15kHz = 0,
    Mu1_30kHz = 1,
    Mu2_60kHz = 2,
    Mu3_120kHz = 3,
}

impl NrNumerology {
    #[inline]
    pub fn scs_khz(self) -> u32 {
        15 * (1 << (self as u32))
    }

    #[inline]
    pub fn mu(self) -> u8 {
        self as u8
    }
}

/// Standardized fixed timing advance offset $N_{\text{TA, offset}}$ (TS 38.133 / TS 38.213 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingAdvanceOffsetType {
    /// FR1 FDD: $N_{\text{TA, offset}} = 0$.
    Fr1Fdd,
    /// FR1 TDD Default: $N_{\text{TA, offset}} = 25600$.
    Fr1TddDefault,
    /// FR1 TDD Extended: $N_{\text{TA, offset}} = 39936$.
    Fr1TddExtended,
    /// FR2 mmWave: $N_{\text{TA, offset}} = 13792$.
    Fr2MmWave,
}

impl TimingAdvanceOffsetType {
    #[inline]
    pub fn offset_units(self) -> u32 {
        match self {
            Self::Fr1Fdd => 0,
            Self::Fr1TddDefault => 25_600,
            Self::Fr1TddExtended => 39_936,
            Self::Fr2MmWave => 13_792,
        }
    }
}

// ---------------------------------------------------------------------------
// Initial & Closed-Loop Timing Advance Calculator (TS 38.213 §4.2)
// ---------------------------------------------------------------------------

/// Computes $N_{\text{TA}}$ from the 12-bit initial TA index $T_A \in [0, 3846]$:
/// $N_{\text{TA}} = T_A \cdot 16 \cdot \frac{64}{2^\mu}$.
pub fn compute_initial_nta(
    ta_index: u16,
    numerology: NrNumerology,
) -> Result<u32, TimingAdvanceError> {
    if ta_index > 3846 {
        return Err(TimingAdvanceError::InvalidInitialTaIndex(ta_index));
    }
    let mu = numerology as u32;
    let factor = (16 * 64) >> mu;
    Ok((ta_index as u32) * factor)
}

/// Converts a measured one-way propagation delay $\tau$ (in seconds) into the 12-bit initial TA index $T_A \in [0, 3846]$.
/// Round-trip time is $2\tau$. Total sample advance is $2\tau / T_c$.
/// $T_A = \text{round}\left( \frac{2\tau}{T_c \cdot 16 \cdot 64 / 2^\mu} \right)$.
pub fn delay_to_initial_ta_index(
    propagation_delay_sec: f64,
    numerology: NrNumerology,
) -> Result<u16, TimingAdvanceError> {
    let mu = numerology as u32;
    let step_sec = T_C_SECONDS * ((16 * 64 >> mu) as f64);
    let round_trip_sec = 2.0 * propagation_delay_sec.max(0.0);
    let raw_index = (round_trip_sec / step_sec).round() as u64;
    let clamped_index = raw_index.min(3846) as u16;
    Ok(clamped_index)
}

/// Computes total timing advance time $T_{\text{TA}}$ in nanoseconds:
/// $T_{\text{TA}} = (N_{\text{TA}} + N_{\text{TA, offset}}) \cdot T_c \cdot 10^9$.
pub fn compute_total_advance_nanoseconds(nta: u32, offset_type: TimingAdvanceOffsetType) -> f64 {
    let total_units = (nta + offset_type.offset_units()) as f64;
    total_units * T_C_SECONDS * 1e9
}

/// Computes relative adjustment $\Delta N_{\text{TA}}$ from 6-bit MAC CE TA command $T_A \in [0, 63]$:
/// $\Delta N_{\text{TA}} = (T_A - 31) \cdot 16 \cdot \frac{64}{2^\mu}$.
pub fn compute_mac_ce_nta_adjustment(
    ta_command: u8,
    numerology: NrNumerology,
) -> Result<i32, TimingAdvanceError> {
    if ta_command > 63 {
        return Err(TimingAdvanceError::InvalidMacCeTaIndex(ta_command));
    }
    let mu = numerology as u32;
    let factor = (16 * 64 >> mu) as i32;
    let diff = (ta_command as i32) - 31;
    Ok(diff * factor)
}

// ---------------------------------------------------------------------------
// Time Alignment Timer (TAT) Lifecycle Engine (TS 38.321 §5.2)
// ---------------------------------------------------------------------------

/// Standard 3GPP `timeAlignmentTimer` duration (TS 38.331).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeAlignmentTimerConfig {
    Sf500 = 500,
    Sf750 = 750,
    Sf1280 = 1280,
    Sf1920 = 1920,
    Sf2560 = 2560,
    Sf5120 = 5120,
    Sf10240 = 10240,
    Infinity,
}

/// Current state of the Time Alignment Timer (TAT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TatState {
    Stopped,
    Running { remaining_ms: u32 },
    Expired,
}

/// Time Alignment Timer manager for UE Serving Cells.
#[derive(Debug, Clone, PartialEq)]
pub struct TimeAlignmentTimer {
    pub config: TimeAlignmentTimerConfig,
    pub state: TatState,
    pub total_expirations: u64,
}

impl TimeAlignmentTimer {
    pub fn new(config: TimeAlignmentTimerConfig) -> Self {
        Self {
            config,
            state: TatState::Stopped,
            total_expirations: 0,
        }
    }

    /// Starts or restarts the TAT upon receipt of a Timing Advance Command (TS 38.321 §5.2).
    pub fn restart(&mut self) {
        match self.config {
            TimeAlignmentTimerConfig::Infinity => {
                self.state = TatState::Running {
                    remaining_ms: u32::MAX,
                };
            }
            duration => {
                self.state = TatState::Running {
                    remaining_ms: duration as u32,
                };
            }
        }
    }

    /// Advances time by `elapsed_ms`. Returns true if the timer just expired.
    pub fn tick(&mut self, elapsed_ms: u32) -> bool {
        match &mut self.state {
            TatState::Running { remaining_ms } => {
                if self.config == TimeAlignmentTimerConfig::Infinity {
                    return false;
                }
                if elapsed_ms >= *remaining_ms {
                    self.state = TatState::Expired;
                    self.total_expirations += 1;
                    true
                } else {
                    *remaining_ms -= elapsed_ms;
                    false
                }
            }
            _ => false,
        }
    }

    /// Checks if uplink synchronization is maintained (timer is running).
    #[inline]
    pub fn is_sync_maintained(&self) -> bool {
        matches!(self.state, TatState::Running { .. })
    }

    /// Stops the timer.
    pub fn stop(&mut self) {
        self.state = TatState::Stopped;
    }
}

// ---------------------------------------------------------------------------
// Rel-18 Autonomous Timing Advance (ATA) Velocity Tracker
// ---------------------------------------------------------------------------

/// Rel-18 Autonomous Timing Advance (ATA) tracker estimating Doppler-induced timing drift.
#[derive(Debug, Clone, PartialEq)]
pub struct AutonomousTimingAdvanceTracker {
    pub numerology: NrNumerology,
    pub current_nta: u32,
    /// Radial velocity (m/s), positive = moving away (delay increasing), negative = approaching.
    pub radial_velocity_mps: f64,
}

impl AutonomousTimingAdvanceTracker {
    pub fn new(numerology: NrNumerology, initial_nta: u32) -> Self {
        Self {
            numerology,
            current_nta: initial_nta,
            radial_velocity_mps: 0.0,
        }
    }

    /// Updates current N_TA with a closed-loop MAC CE command.
    pub fn apply_mac_ce_update(&mut self, ta_command: u8) -> Result<(), TimingAdvanceError> {
        let adj = compute_mac_ce_nta_adjustment(ta_command, self.numerology)?;
        let new_nta = (self.current_nta as i64) + (adj as i64);
        self.current_nta = new_nta.max(0) as u32;
        Ok(())
    }

    /// Updates velocity and applies autonomous timing advance drift over `elapsed_sec`:
    /// $\frac{d N_{\text{TA}}}{dt} = 2 \frac{v_{\text{radial}}}{c \cdot T_c}$.
    pub fn tick_autonomous_drift(&mut self, elapsed_sec: f64, radial_velocity_mps: f64) {
        self.radial_velocity_mps = radial_velocity_mps;
        // Two-way propagation distance rate of change: 2 * v_rad
        let drift_units =
            (2.0 * radial_velocity_mps * elapsed_sec) / (SPEED_OF_LIGHT * T_C_SECONDS);
        let new_nta = (self.current_nta as f64) + drift_units;
        self.current_nta = new_nta.max(0.0).round() as u32;
    }
}

// ---------------------------------------------------------------------------
// 3GPP MAC RAR PDU Framing & Multiplexing (TS 38.321 §6.1.5, §6.2.3)
// ---------------------------------------------------------------------------

/// 3GPP Table 7.2-1: Backoff Parameter values (in ms) indexed by 4-bit BI.
pub const BACKOFF_TABLE_MS: [u32; 16] = [
    5, 10, 20, 30, 40, 60, 80, 120, 160, 240, 320, 480, 960, 1920, 0, 0, // 14, 15 reserved
];

/// MAC RAR Subheader Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RarSubheader {
    /// E/T/RAPID subheader: E (1 bit), T = 1 (1 bit), RAPID (6 bits).
    Rapid { is_last: bool, rapid: u8 },
    /// E/T/R/R/BI subheader: E (1 bit), T = 0 (1 bit), R=0, R=0, BI (4 bits).
    BackoffIndicator { is_last: bool, bi_index: u8 },
}

impl RarSubheader {
    pub fn encode(self) -> Result<u8, TimingAdvanceError> {
        match self {
            Self::Rapid { is_last, rapid } => {
                if rapid > 63 {
                    return Err(TimingAdvanceError::InvalidRapid(rapid));
                }
                let e_bit = if is_last { 0 } else { 1 << 7 };
                let t_bit = 1 << 6;
                Ok(e_bit | t_bit | rapid)
            }
            Self::BackoffIndicator { is_last, bi_index } => {
                if bi_index > 15 {
                    return Err(TimingAdvanceError::InvalidBackoffIndicator(bi_index));
                }
                let e_bit = if is_last { 0 } else { 1 << 7 };
                let t_bit = 0;
                Ok(e_bit | t_bit | (bi_index & 0x0F))
            }
        }
    }

    pub fn decode(byte: u8) -> Self {
        let is_last = (byte & 0x80) == 0;
        let is_rapid = (byte & 0x40) != 0;
        if is_rapid {
            Self::Rapid {
                is_last,
                rapid: byte & 0x3F,
            }
        } else {
            Self::BackoffIndicator {
                is_last,
                bi_index: byte & 0x0F,
            }
        }
    }
}

/// 7-byte MAC RAR Payload per TS 38.321 §6.1.5 (56 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacRarPayload {
    /// 12-bit Timing Advance Command ($T_A \in [0, 3846]$).
    pub ta_command: u16,
    /// 27-bit Uplink Grant.
    pub ul_grant: u32,
    /// 16-bit Temporary C-RNTI.
    pub temp_crnti: u16,
}

impl MacRarPayload {
    pub fn encode(self) -> Result<[u8; 7], TimingAdvanceError> {
        if self.ta_command > 3846 {
            return Err(TimingAdvanceError::InvalidInitialTaIndex(self.ta_command));
        }

        let mut out = [0u8; 7];
        // Octet 1: R (bit 7 = 0) | TA[11..5] (bits 6..0)
        out[0] = ((self.ta_command >> 5) & 0x7F) as u8;
        // Octet 2: TA[4..0] (bits 7..3) | UL Grant[26..24] (bits 2..0)
        out[1] = (((self.ta_command & 0x1F) << 3) as u8) | (((self.ul_grant >> 24) & 0x07) as u8);
        // Octet 3: UL Grant[23..16]
        out[2] = ((self.ul_grant >> 16) & 0xFF) as u8;
        // Octet 4: UL Grant[15..8]
        out[3] = ((self.ul_grant >> 8) & 0xFF) as u8;
        // Octet 5: UL Grant[7..0]
        out[4] = (self.ul_grant & 0xFF) as u8;
        // Octet 6: Temp C-RNTI[15..8]
        out[5] = ((self.temp_crnti >> 8) & 0xFF) as u8;
        // Octet 7: Temp C-RNTI[7..0]
        out[6] = (self.temp_crnti & 0xFF) as u8;

        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TimingAdvanceError> {
        if bytes.len() < 7 {
            return Err(TimingAdvanceError::RarPduTooShort {
                needed: 7,
                found: bytes.len(),
            });
        }

        let ta_msb = ((bytes[0] & 0x7F) as u16) << 5;
        let ta_lsb = ((bytes[1] >> 3) & 0x1F) as u16;
        let ta_command = ta_msb | ta_lsb;

        let grant_b2 = ((bytes[1] & 0x07) as u32) << 24;
        let grant_b1 = (bytes[2] as u32) << 16;
        let grant_b0 = (bytes[3] as u32) << 8;
        let grant_lsb = bytes[4] as u32;
        let ul_grant = grant_b2 | grant_b1 | grant_b0 | grant_lsb;

        let temp_crnti = u16::from_be_bytes([bytes[5], bytes[6]]);

        Ok(Self {
            ta_command,
            ul_grant,
            temp_crnti,
        })
    }
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
// Binary Wire Framing (`TimingAdvanceWirePdu`)
// ---------------------------------------------------------------------------

/// Wire PDU transporting timing advance state and telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct TimingAdvanceWirePdu {
    pub numerology_mu: u8,
    pub current_nta: u32,
    pub total_advance_ns: f64,
    pub tat_running: bool,
    pub tat_remaining_ms: u32,
    pub radial_velocity_mps: f32,
}

impl TimingAdvanceWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(26);
        buf.extend_from_slice(&TIMA_WIRE_MAGIC.to_be_bytes());
        buf.push(self.numerology_mu);
        buf.extend_from_slice(&self.current_nta.to_be_bytes());
        buf.extend_from_slice(&self.total_advance_ns.to_be_bytes());
        buf.push(if self.tat_running { 1 } else { 0 });
        buf.extend_from_slice(&self.tat_remaining_ms.to_be_bytes());
        buf.extend_from_slice(&self.radial_velocity_mps.to_be_bytes());

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, TimingAdvanceError> {
        if bytes.len() < 26 {
            return Err(TimingAdvanceError::WirePayloadTooShort {
                needed: 26,
                found: bytes.len(),
            });
        }
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != TIMA_WIRE_MAGIC {
            return Err(TimingAdvanceError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(TimingAdvanceError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let numerology_mu = bytes[4];
        let current_nta = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        let total_advance_ns = f64::from_be_bytes([
            bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16],
        ]);
        let tat_running = bytes[17] != 0;
        let tat_remaining_ms = u32::from_be_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]);
        let radial_velocity_mps = f32::from_be_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]);

        Ok(Self {
            numerology_mu,
            current_nta,
            total_advance_ns,
            tat_running,
            tat_remaining_ms,
            radial_velocity_mps,
        })
    }
}

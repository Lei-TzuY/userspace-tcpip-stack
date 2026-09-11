//! 3GPP Release 18/19 5G-Advanced Radio Link Monitoring (RLM) & Radio Link Failure (RLF) Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.213 Rel-18 §5: Radio link monitoring procedure and hypothetical PDCCH BLER evaluation.
//! - 3GPP TS 38.133 Rel-18 §8.1: RLM core requirements, $Q_{\text{out}}$ (10% BLER) and $Q_{\text{in}}$ (2% BLER) thresholds.
//! - 3GPP TS 38.331 Rel-18 §5.3.10: Radio link failure detection, T310/T311/T312 timers, and N310/N311 counters.
//!
//! Features:
//! 1. L1 hypothetical PDCCH BLER estimation and thresholding against $Q_{\text{out}}$ and $Q_{\text{in}}$.
//! 2. L1-to-L3 periodic indication filtering (`OutOfSync`, `InSync`).
//! 3. L3 RLF State Machine managing N310/N311 counters and T310/T311/T312 timers.
//! 4. Fast early recovery via T312 acceleration during active measurement reporting.
//! 5. Rel-18 Multi-TRP (M-TRP) RLM dual-link spatial resilience preventing false RLF under single-link blockage.
//! 6. Comprehensive RLF root-cause diagnostic reporting (T310, T312, RACH, RLC, LBT).
//! 7. Binary wire framing (`RlmWirePdu`) with magic `0x524C4D46` ("RLMF") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for RLM Wire PDU: "RLMF" (0x524C4D46).
pub const RLM_WIRE_MAGIC: u32 = 0x524C4D46;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Default Q_out threshold in dB (hypothetical PDCCH BLER >= 10%).
pub const DEFAULT_Q_OUT_SINR_DB: f64 = -3.0;

/// Default Q_in threshold in dB (hypothetical PDCCH BLER <= 2%).
pub const DEFAULT_Q_IN_SINR_DB: f64 = 0.0;

/// Default N310 counter: consecutive Out-of-Sync indications to start T310.
pub const DEFAULT_N310: usize = 20;

/// Default N311 counter: consecutive In-Sync indications to stop T310.
pub const DEFAULT_N311: usize = 1;

/// Default T310 duration in milliseconds.
pub const DEFAULT_T310_MS: u32 = 1000;

/// Default T311 duration in milliseconds.
pub const DEFAULT_T311_MS: u32 = 3000;

/// Default T312 duration in milliseconds (fast early failure during measurement reporting).
pub const DEFAULT_T312_MS: u32 = 100;

/// Maximum number of RLM Reference Signals per serving cell.
pub const MAX_RLM_RS: usize = 8;

/// Reference Signal Type configured for RLM (TS 38.213 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlmRsType {
    Ssb { ssb_index: u8 },
    CsiRs { resource_id: u16 },
}

/// Transmission Reception Point (TRP) identifier for Multi-TRP RLM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RlmTrpId {
    Trp0,
    Trp1,
}

/// L1 RLM Indication sent from PHY to MAC/RRC (TS 38.213 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L1RlmIndication {
    OutOfSync,
    InSync,
    Indeterminate,
}

/// Radio Link Failure Cause (TS 38.331 §5.3.10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlfCause {
    T310Expiry,
    T312Expiry,
    RandomAccessProblem,
    MaxRlcRetransmissions,
    ConsistentLbtFailure,
}

/// State of the RLM / RLF State Machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlmState {
    NormalInSync,
    OutOfSyncCounting { count: usize },
    DegradedT310Running { remaining_ms: u32 },
    FastRecoveryT312Running { t310_remaining_ms: u32, t312_remaining_ms: u32 },
    RadioLinkFailureDeclared { cause: RlfCause },
    ReEstablishingT311Running { remaining_ms: u32 },
}

/// Errors encountered in RLM operations.
#[derive(Debug, Clone, PartialEq)]
pub enum RlmError {
    NoReferenceSignalsConfigured,
    InvalidTimerDuration(u32),
    InvalidCounterValue(usize),
    InvalidThreshold { q_out: f64, q_in: f64 },
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for RlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RlmError::NoReferenceSignalsConfigured => write!(f, "No RLM reference signals configured"),
            RlmError::InvalidTimerDuration(ms) => write!(f, "Invalid timer duration: {} ms", ms),
            RlmError::InvalidCounterValue(c) => write!(f, "Invalid counter value: {}", c),
            RlmError::InvalidThreshold { q_out, q_in } => {
                write!(f, "Invalid thresholds: Q_out ({}) must be < Q_in ({})", q_out, q_in)
            }
            RlmError::SerializationError(e) => write!(f, "RLM serialization error: {}", e),
            RlmError::DeserializationError(e) => write!(f, "RLM deserialization error: {}", e),
        }
    }
}

impl std::error::Error for RlmError {}

// ---------------------------------------------------------------------------
// RLM Configuration
// ---------------------------------------------------------------------------

/// Configuration for a single RLM Reference Signal.
#[derive(Debug, Clone, PartialEq)]
pub struct RlmRsConfig {
    pub rs: RlmRsType,
    pub trp: RlmTrpId,
}

/// Complete RLM and RLF Configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct RlmConfig {
    pub q_out_sinr_db: f64,
    pub q_in_sinr_db: f64,
    pub n310: usize,
    pub n311: usize,
    pub t310_ms: u32,
    pub t311_ms: u32,
    pub t312_ms: u32,
    pub multi_trp_enabled: bool,
    pub reference_signals: Vec<RlmRsConfig>,
}

impl Default for RlmConfig {
    fn default() -> Self {
        Self {
            q_out_sinr_db: DEFAULT_Q_OUT_SINR_DB,
            q_in_sinr_db: DEFAULT_Q_IN_SINR_DB,
            n310: DEFAULT_N310,
            n311: DEFAULT_N311,
            t310_ms: DEFAULT_T310_MS,
            t311_ms: DEFAULT_T311_MS,
            t312_ms: DEFAULT_T312_MS,
            multi_trp_enabled: false,
            reference_signals: Vec::new(),
        }
    }
}

impl RlmConfig {
    pub fn validate(&self) -> Result<(), RlmError> {
        if self.q_out_sinr_db >= self.q_in_sinr_db {
            return Err(RlmError::InvalidThreshold {
                q_out: self.q_out_sinr_db,
                q_in: self.q_in_sinr_db,
            });
        }
        if self.n310 == 0 {
            return Err(RlmError::InvalidCounterValue(0));
        }
        if self.n311 == 0 {
            return Err(RlmError::InvalidCounterValue(0));
        }
        if self.t310_ms == 0 || self.t311_ms == 0 {
            return Err(RlmError::InvalidTimerDuration(0));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// L1 RLM Measurement & Indication Evaluator (TS 38.213 §5)
// ---------------------------------------------------------------------------

/// Measurement report for an individual RLM reference signal.
#[derive(Debug, Clone, PartialEq)]
pub struct RlmRsMeasurement {
    pub rs: RlmRsType,
    pub sinr_db: f64,
}

/// Evaluates L1 radio link quality against Q_out and Q_in thresholds (TS 38.213 §5).
pub fn evaluate_l1_indications(
    measurements: &[RlmRsMeasurement],
    cfg: &RlmConfig,
) -> Result<L1RlmIndication, RlmError> {
    if measurements.is_empty() {
        return Err(RlmError::NoReferenceSignalsConfigured);
    }

    if cfg.multi_trp_enabled {
        // Rel-18 Multi-TRP RLM:
        // OutOfSync occurs only when BOTH TRPs are completely below Q_out.
        // InSync occurs when ANY RS in either TRP is above Q_in.
        let any_in_sync = measurements.iter().any(|m| m.sinr_db >= cfg.q_in_sinr_db);
        if any_in_sync {
            return Ok(L1RlmIndication::InSync);
        }

        let all_out_of_sync = measurements.iter().all(|m| m.sinr_db < cfg.q_out_sinr_db);
        if all_out_of_sync {
            return Ok(L1RlmIndication::OutOfSync);
        }

        Ok(L1RlmIndication::Indeterminate)
    } else {
        // Single-TRP standard evaluation:
        // OutOfSync: ALL configured RS are worse than Q_out
        // InSync: AT LEAST ONE RS is better than Q_in
        let any_in_sync = measurements.iter().any(|m| m.sinr_db >= cfg.q_in_sinr_db);
        if any_in_sync {
            return Ok(L1RlmIndication::InSync);
        }

        let all_out_of_sync = measurements.iter().all(|m| m.sinr_db < cfg.q_out_sinr_db);
        if all_out_of_sync {
            return Ok(L1RlmIndication::OutOfSync);
        }

        Ok(L1RlmIndication::Indeterminate)
    }
}

// ---------------------------------------------------------------------------
// L3 RLM State Machine & Timers (TS 38.331 §5.3.10)
// ---------------------------------------------------------------------------

/// Radio Link Monitoring and Failure Management Engine.
#[derive(Debug, Clone)]
pub struct NrRlmEngine {
    pub config: RlmConfig,
    pub state: RlmState,
    pub oos_counter: usize,
    pub is_counter: usize,
    pub total_rlf_count: u64,
    pub total_recovery_count: u64,
}

impl NrRlmEngine {
    pub fn new(config: RlmConfig) -> Result<Self, RlmError> {
        config.validate()?;
        Ok(Self {
            config,
            state: RlmState::NormalInSync,
            oos_counter: 0,
            is_counter: 0,
            total_rlf_count: 0,
            total_recovery_count: 0,
        })
    }

    /// Processes a periodic L1 indication from PHY layer.
    pub fn process_l1_indication(&mut self, indication: L1RlmIndication) {
        match indication {
            L1RlmIndication::OutOfSync => {
                self.is_counter = 0;
                match self.state {
                    RlmState::NormalInSync => {
                        self.oos_counter = 1;
                        if self.oos_counter >= self.config.n310 {
                            self.state = RlmState::DegradedT310Running {
                                remaining_ms: self.config.t310_ms,
                            };
                        } else {
                            self.state = RlmState::OutOfSyncCounting { count: self.oos_counter };
                        }
                    }
                    RlmState::OutOfSyncCounting { mut count } => {
                        count += 1;
                        self.oos_counter = count;
                        if count >= self.config.n310 {
                            self.state = RlmState::DegradedT310Running {
                                remaining_ms: self.config.t310_ms,
                            };
                        } else {
                            self.state = RlmState::OutOfSyncCounting { count };
                        }
                    }
                    RlmState::DegradedT310Running { .. } => {
                        // T310 continues running
                    }
                    RlmState::FastRecoveryT312Running { .. } => {
                        // T312 continues running
                    }
                    RlmState::RadioLinkFailureDeclared { .. } | RlmState::ReEstablishingT311Running { .. } => {
                        // Already failed / re-establishing
                    }
                }
            }
            L1RlmIndication::InSync => {
                self.oos_counter = 0;
                match self.state {
                    RlmState::OutOfSyncCounting { .. } => {
                        self.state = RlmState::NormalInSync;
                        self.is_counter = 0;
                    }
                    RlmState::DegradedT310Running { .. } | RlmState::FastRecoveryT312Running { .. } => {
                        self.is_counter += 1;
                        if self.is_counter >= self.config.n311 {
                            // Link recovered!
                            self.state = RlmState::NormalInSync;
                            self.is_counter = 0;
                            self.total_recovery_count += 1;
                        }
                    }
                    _ => {
                        self.is_counter = 0;
                    }
                }
            }
            L1RlmIndication::Indeterminate => {
                // No change to counters
            }
        }
    }

    /// Triggers start of T312 when measurement report is triggered under degraded conditions (TS 38.331 §5.3.10.2).
    pub fn on_measurement_report_triggered(&mut self) {
        if let RlmState::DegradedT310Running { remaining_ms } = self.state {
            self.state = RlmState::FastRecoveryT312Running {
                t310_remaining_ms: remaining_ms,
                t312_remaining_ms: self.config.t312_ms,
            };
        }
    }

    /// Advances simulation time by `elapsed_ms`, decrementing active timers.
    pub fn advance_time_ms(&mut self, elapsed_ms: u32) {
        match self.state {
            RlmState::DegradedT310Running { remaining_ms } => {
                if elapsed_ms >= remaining_ms {
                    self.trigger_rlf(RlfCause::T310Expiry);
                } else {
                    self.state = RlmState::DegradedT310Running {
                        remaining_ms: remaining_ms - elapsed_ms,
                    };
                }
            }
            RlmState::FastRecoveryT312Running {
                t310_remaining_ms,
                t312_remaining_ms,
            } => {
                if elapsed_ms >= t312_remaining_ms {
                    // Fast RLF triggered by T312!
                    self.trigger_rlf(RlfCause::T312Expiry);
                } else if elapsed_ms >= t310_remaining_ms {
                    self.trigger_rlf(RlfCause::T310Expiry);
                } else {
                    self.state = RlmState::FastRecoveryT312Running {
                        t310_remaining_ms: t310_remaining_ms - elapsed_ms,
                        t312_remaining_ms: t312_remaining_ms - elapsed_ms,
                    };
                }
            }
            RlmState::ReEstablishingT311Running { remaining_ms } => {
                if elapsed_ms >= remaining_ms {
                    // T311 expired: re-establishment failed, go back to RRC_IDLE
                    self.state = RlmState::NormalInSync;
                } else {
                    self.state = RlmState::ReEstablishingT311Running {
                        remaining_ms: remaining_ms - elapsed_ms,
                    };
                }
            }
            _ => {}
        }
    }

    /// Explicit external failure triggers (RACH failure, RLC max retries, LBT).
    pub fn trigger_external_failure(&mut self, cause: RlfCause) {
        self.trigger_rlf(cause);
    }

    fn trigger_rlf(&mut self, cause: RlfCause) {
        self.state = RlmState::RadioLinkFailureDeclared { cause };
        self.total_rlf_count += 1;
        self.oos_counter = 0;
        self.is_counter = 0;
    }

    /// Starts RRC Connection Re-establishment (T311).
    pub fn start_reestablishment(&mut self) {
        self.state = RlmState::ReEstablishingT311Running {
            remaining_ms: self.config.t311_ms,
        };
    }

    /// Returns current state.
    pub fn state(&self) -> RlmState {
        self.state
    }
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16
// ---------------------------------------------------------------------------

/// Wire frame PDU for RLM telemetry and RLF reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlmWirePdu {
    pub magic: u32,
    pub timestamp_ms: u32,
    pub state_tag: u8,
    pub oos_count: u16,
    pub is_count: u16,
    pub rlf_count: u32,
    pub rlf_cause: u8,
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

impl RlmWirePdu {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + self.payload.len());
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        buf.push(self.state_tag);
        buf.extend_from_slice(&self.oos_count.to_be_bytes());
        buf.extend_from_slice(&self.is_count.to_be_bytes());
        buf.extend_from_slice(&self.rlf_count.to_be_bytes());
        buf.push(self.rlf_cause);
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, RlmError> {
        if data.len() < 20 {
            return Err(RlmError::DeserializationError("Buffer too small".into()));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != RLM_WIRE_MAGIC {
            return Err(RlmError::DeserializationError(format!("Invalid magic: 0x{:08X}", magic)));
        }

        let timestamp_ms = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let state_tag = data[8];
        let oos_count = u16::from_be_bytes([data[9], data[10]]);
        let is_count = u16::from_be_bytes([data[11], data[12]]);
        let rlf_count = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
        let rlf_cause = data[17];
        let payload_len = u16::from_be_bytes([data[18], data[19]]) as usize;

        if data.len() < 20 + payload_len + 2 {
            return Err(RlmError::DeserializationError("Truncated payload".into()));
        }

        let payload = data[20..20 + payload_len].to_vec();
        let expected_crc = compute_crc16(&data[..20 + payload_len]);
        let rx_crc = u16::from_be_bytes([data[20 + payload_len], data[20 + payload_len + 1]]);

        if rx_crc != expected_crc {
            return Err(RlmError::DeserializationError(format!(
                "CRC-16 mismatch: expected 0x{:04X}, received 0x{:04X}",
                expected_crc, rx_crc
            )));
        }

        Ok(Self {
            magic,
            timestamp_ms,
            state_tag,
            oos_count,
            is_count,
            rlf_count,
            rlf_cause,
            payload,
            crc16: rx_crc,
        })
    }
}

//! 3GPP Release 18/19 5G-Advanced PDCP Data Volume & Delay Status Reporting Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.323 Rel-18 §5.15: PDCP data volume and delay status reporting.
//! - 3GPP TS 38.323 Rel-18 §6.2.3.6: Data volume and delay status report PDU (Control PDU).
//! - 3GPP TS 38.331 Rel-18: `PDCP-Config` (`dataVolumeAndDelayStatusReportConfig-r18`,
//!   `reportInterval-r18`, `excessDelayThreshold-r18`, `discardTimer`).
//!
//! Features:
//! 1. High-precision SDU buffering with microsecond arrival timestamps and PDCP sequence numbers.
//! 2. TS 38.323 §5.2.1 `discardTimer` enforcement: autonomously purges expired SDUs and accounts for discarded packets.
//! 3. Head-of-Line (HOL) Delay computation representing the queuing delay of the oldest pending SDU.
//! 4. Excess Delay tracking: identifies and aggregates volume & count of SDUs exceeding `excessDelayThreshold`.
//! 5. Imminent Discard predictive horizon: detects SDUs about to expire within an imminent discard window.
//! 6. Multi-trigger evaluation: Periodic timer (`reportInterval`), HOL delay threshold, Buffer volume threshold,
//!    and Imminent discard alerts.
//! 7. 3GPP TS 38.323 §6.2.3.6 Control PDU binary serialization and parsing (D/C=0, PDU Type=010).
//! 8. Binary wire framing (`NrPdcpDelayWirePdu`) with magic `0x5044454C` ("PDEL") and CRC-16 CCITT validation.

use std::collections::VecDeque;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & CRC-16
// ---------------------------------------------------------------------------

/// Magic bytes for PDCP Delay Wire PDU: "PDEL" (0x5044454C).
pub const PDCP_DELAY_WIRE_MAGIC: u32 = 0x5044454C;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// PDCP Control PDU Type for Data Volume and Delay Status Report (TS 38.323 Table 6.3.8-1).
pub const PDU_TYPE_DATA_VOLUME_AND_DELAY_STATUS: u8 = 0b010;

/// Standard size of the 3GPP TS 38.323 §6.2.3.6 Control PDU in bytes.
pub const PDCP_DELAY_CONTROL_PDU_SIZE: usize = 22;

/// Standard size of the PDCP Delay Wire PDU in bytes.
pub const PDCP_DELAY_WIRE_PDU_SIZE: usize = 26;

/// Errors in PDCP Delay Status operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdcpDelayStatusError {
    InvalidControlPduSize { needed: usize, found: usize },
    InvalidDcBit(u8),
    InvalidPduType(u8),
    InvalidTriggerCode(u8),
    BufferOverflow { capacity: usize },
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    WireCrcMismatch { expected: u16, computed: u16 },
}

impl fmt::Display for PdcpDelayStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidControlPduSize { needed, found } => {
                write!(f, "Invalid control PDU size: needed {} bytes, found {}", needed, found)
            }
            Self::InvalidDcBit(bit) => write!(f, "Invalid D/C bit (expected 0 for Control PDU, found {})", bit),
            Self::InvalidPduType(pdu_type) => write!(f, "Invalid PDU Type (expected 0b010, found 0b{:03b})", pdu_type),
            Self::InvalidTriggerCode(code) => write!(f, "Invalid trigger code: {}", code),
            Self::BufferOverflow { capacity } => write!(f, "PDCP SDU buffer overflow (capacity: {})", capacity),
            Self::InvalidWireMagic(m) => write!(f, "Invalid wire magic: 0x{:08X}", m),
            Self::WirePayloadTooShort { needed, found } => {
                write!(f, "Wire payload too short: needed {} bytes, found {}", needed, found)
            }
            Self::WireCrcMismatch { expected, computed } => {
                write!(f, "Wire CRC mismatch: expected 0x{:04X}, computed 0x{:04X}", expected, computed)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Enums & Structs (TS 38.323 §5.15 / TS 38.331)
// ---------------------------------------------------------------------------

/// Trigger reason for generating a PDCP Data Volume and Delay Status Report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportTriggerReason {
    Periodic = 0,
    HolDelayThresholdExceeded = 1,
    VolumeThresholdExceeded = 2,
    ImminentDiscardAlert = 3,
    ManualPoll = 4,
}

impl ReportTriggerReason {
    pub fn to_code(&self) -> u8 {
        *self as u8
    }

    pub fn from_code(code: u8) -> Result<Self, PdcpDelayStatusError> {
        match code {
            0 => Ok(Self::Periodic),
            1 => Ok(Self::HolDelayThresholdExceeded),
            2 => Ok(Self::VolumeThresholdExceeded),
            3 => Ok(Self::ImminentDiscardAlert),
            4 => Ok(Self::ManualPoll),
            other => Err(PdcpDelayStatusError::InvalidTriggerCode(other)),
        }
    }
}

/// A buffered PDCP SDU waiting for transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdcpSdu {
    pub sn: u32,
    pub size_bytes: usize,
    pub arrival_time_us: u64,
    pub priority: u8,
}

/// Configuration for PDCP Data Volume and Delay Status Reporting (TS 38.331).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdcpDelayReportConfig {
    pub drb_id: u8,
    /// Discard timer duration in microseconds (`discardTimer`). `None` disables discard.
    pub discard_timer_us: Option<u64>,
    /// Delay threshold in microseconds to qualify an SDU as "Excess Delay".
    pub excess_delay_threshold_us: u64,
    /// Periodic reporting interval in microseconds (`reportInterval-r18`).
    pub report_interval_us: Option<u64>,
    /// HOL delay threshold in microseconds that triggers an event report.
    pub hol_delay_threshold_us: Option<u64>,
    /// Total buffer volume threshold in bytes that triggers an event report.
    pub volume_threshold_bytes: Option<usize>,
    /// Horizon window in microseconds: SDUs expiring within this window are flagged as imminent.
    pub imminent_discard_window_us: u64,
    /// Maximum SDU queue capacity.
    pub max_buffer_capacity: usize,
}

impl Default for PdcpDelayReportConfig {
    fn default() -> Self {
        Self {
            drb_id: 1,
            discard_timer_us: Some(20_000),         // 20 ms (typical for XR video/audio)
            excess_delay_threshold_us: 10_000,      // 10 ms excess delay threshold
            report_interval_us: Some(5_000),        // 5 ms periodic reporting
            hol_delay_threshold_us: Some(8_000),    // 8 ms HOL trigger
            volume_threshold_bytes: Some(64_000),   // 64 KB buffer threshold
            imminent_discard_window_us: 2_000,      // 2 ms imminent discard window
            max_buffer_capacity: 1_000,
        }
    }
}

/// Status report generated by the PDCP entity (TS 38.323 §5.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdcpDelayStatusReport {
    pub drb_id: u8,
    pub trigger: ReportTriggerReason,
    pub hol_delay_us: u64,
    pub total_buffered_bytes: usize,
    pub total_pending_sdus: usize,
    pub excess_delay_bytes: usize,
    pub excess_delay_count: usize,
    pub imminent_discard_bytes: usize,
    pub imminent_discard_count: usize,
    pub cumulative_discarded_sdus: usize,
    pub report_timestamp_us: u64,
}

// ---------------------------------------------------------------------------
// PDCP Data Volume and Delay Status Engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PdcpDelayStatusEngine {
    config: PdcpDelayReportConfig,
    sdu_queue: VecDeque<PdcpSdu>,
    current_time_us: u64,
    last_periodic_report_us: u64,
    cumulative_discarded_sdus: usize,
    next_sn: u32,
}

impl PdcpDelayStatusEngine {
    pub fn new(config: PdcpDelayReportConfig) -> Self {
        Self {
            config,
            sdu_queue: VecDeque::new(),
            current_time_us: 0,
            last_periodic_report_us: 0,
            cumulative_discarded_sdus: 0,
            next_sn: 0,
        }
    }

    /// Enqueues a new PDCP SDU with the current timestamp.
    pub fn enqueue_sdu(&mut self, size_bytes: usize, priority: u8) -> Result<u32, PdcpDelayStatusError> {
        if self.sdu_queue.len() >= self.config.max_buffer_capacity {
            return Err(PdcpDelayStatusError::BufferOverflow {
                capacity: self.config.max_buffer_capacity,
            });
        }

        let sn = self.next_sn;
        self.next_sn = (self.next_sn + 1) & 0x3FFFF; // 18-bit SN wrap

        let sdu = PdcpSdu {
            sn,
            size_bytes,
            arrival_time_us: self.current_time_us,
            priority,
        };

        self.sdu_queue.push_back(sdu);
        Ok(sn)
    }

    /// Transmits and dequeues the oldest pending SDU.
    pub fn transmit_sdu(&mut self) -> Option<PdcpSdu> {
        self.sdu_queue.pop_front()
    }

    /// Advances the simulation clock, purges expired packets (`discardTimer`), and evaluates reporting triggers.
    pub fn advance_time(&mut self, new_time_us: u64) -> Option<PdcpDelayStatusReport> {
        if new_time_us > self.current_time_us {
            self.current_time_us = new_time_us;
        }

        // 1. Enforce TS 38.323 §5.2.1 discardTimer
        self.purge_expired_sdus();

        // 2. Evaluate triggers
        self.evaluate_triggers()
    }

    /// Purges SDUs that have exceeded `discard_timer_us`.
    fn purge_expired_sdus(&mut self) {
        if let Some(discard_timer) = self.config.discard_timer_us {
            let current = self.current_time_us;
            let mut remaining = VecDeque::new();

            while let Some(sdu) = self.sdu_queue.pop_front() {
                let age = current.saturating_sub(sdu.arrival_time_us);
                if age >= discard_timer {
                    self.cumulative_discarded_sdus += 1;
                } else {
                    remaining.push_back(sdu);
                }
            }

            self.sdu_queue = remaining;
        }
    }

    /// Evaluates whether any reporting conditions are satisfied.
    pub fn evaluate_triggers(&mut self) -> Option<PdcpDelayStatusReport> {
        let (hol_delay, total_bytes, pending_sdus, excess_bytes, excess_count, imminent_bytes, imminent_count) =
            self.compute_telemetry();

        let mut trigger = None;

        // 1. Event trigger: Imminent discard alert
        if imminent_count > 0 {
            trigger = Some(ReportTriggerReason::ImminentDiscardAlert);
        }

        // 2. Event trigger: HOL delay threshold
        if trigger.is_none() {
            if let Some(hol_thresh) = self.config.hol_delay_threshold_us {
                if hol_delay >= hol_thresh {
                    trigger = Some(ReportTriggerReason::HolDelayThresholdExceeded);
                }
            }
        }

        // 3. Event trigger: Buffer volume threshold
        if trigger.is_none() {
            if let Some(vol_thresh) = self.config.volume_threshold_bytes {
                if total_bytes >= vol_thresh {
                    trigger = Some(ReportTriggerReason::VolumeThresholdExceeded);
                }
            }
        }

        // 4. Periodic trigger
        if trigger.is_none() {
            if let Some(interval) = self.config.report_interval_us {
                if self.current_time_us >= self.last_periodic_report_us + interval {
                    self.last_periodic_report_us = self.current_time_us;
                    trigger = Some(ReportTriggerReason::Periodic);
                }
            }
        }

        trigger.map(|trig| PdcpDelayStatusReport {
            drb_id: self.config.drb_id,
            trigger: trig,
            hol_delay_us: hol_delay,
            total_buffered_bytes: total_bytes,
            total_pending_sdus: pending_sdus,
            excess_delay_bytes: excess_bytes,
            excess_delay_count: excess_count,
            imminent_discard_bytes: imminent_bytes,
            imminent_discard_count: imminent_count,
            cumulative_discarded_sdus: self.cumulative_discarded_sdus,
            report_timestamp_us: self.current_time_us,
        })
    }

    /// Forces generation of a report (e.g. gNB poll).
    pub fn poll_report(&self) -> PdcpDelayStatusReport {
        let (hol_delay, total_bytes, pending_sdus, excess_bytes, excess_count, imminent_bytes, imminent_count) =
            self.compute_telemetry();

        PdcpDelayStatusReport {
            drb_id: self.config.drb_id,
            trigger: ReportTriggerReason::ManualPoll,
            hol_delay_us: hol_delay,
            total_buffered_bytes: total_bytes,
            total_pending_sdus: pending_sdus,
            excess_delay_bytes: excess_bytes,
            excess_delay_count: excess_count,
            imminent_discard_bytes: imminent_bytes,
            imminent_discard_count: imminent_count,
            cumulative_discarded_sdus: self.cumulative_discarded_sdus,
            report_timestamp_us: self.current_time_us,
        }
    }

    fn compute_telemetry(&self) -> (u64, usize, usize, usize, usize, usize, usize) {
        let pending_sdus = self.sdu_queue.len();
        if pending_sdus == 0 {
            return (0, 0, 0, 0, 0, 0, 0);
        }

        let hol_sdu = self.sdu_queue.front().unwrap();
        let hol_delay = self.current_time_us.saturating_sub(hol_sdu.arrival_time_us);

        let mut total_bytes = 0;
        let mut excess_bytes = 0;
        let mut excess_count = 0;
        let mut imminent_bytes = 0;
        let mut imminent_count = 0;

        for sdu in &self.sdu_queue {
            total_bytes += sdu.size_bytes;
            let age = self.current_time_us.saturating_sub(sdu.arrival_time_us);

            if age >= self.config.excess_delay_threshold_us {
                excess_bytes += sdu.size_bytes;
                excess_count += 1;
            }

            if let Some(discard_timer) = self.config.discard_timer_us {
                let remaining_time = discard_timer.saturating_sub(age);
                if remaining_time <= self.config.imminent_discard_window_us {
                    imminent_bytes += sdu.size_bytes;
                    imminent_count += 1;
                }
            }
        }

        (
            hol_delay,
            total_bytes,
            pending_sdus,
            excess_bytes,
            excess_count,
            imminent_bytes,
            imminent_count,
        )
    }

    // -----------------------------------------------------------------------
    // TS 38.323 §6.2.3.6 Control PDU Serialization / Parsing
    // -----------------------------------------------------------------------

    /// Serializes a `PdcpDelayStatusReport` into 3GPP TS 38.323 §6.2.3.6 Control PDU format (22 bytes).
    pub fn encode_control_pdu(report: &PdcpDelayStatusReport) -> Vec<u8> {
        let mut pdu = vec![0u8; PDCP_DELAY_CONTROL_PDU_SIZE];

        // Byte 0: D/C=0 (bit 7), PDU Type=010 (bits 6-4), Reserved=0000 (bits 3-0)
        pdu[0] = (PDU_TYPE_DATA_VOLUME_AND_DELAY_STATUS & 0x07) << 4;

        // Byte 1: DRB ID (bits 7-3, 5 bits), Trigger code (bits 2-0, 3 bits)
        pdu[1] = ((report.drb_id & 0x1F) << 3) | (report.trigger.to_code() & 0x07);

        // Bytes 2-3: HOL Delay in units of 100 microseconds (16 bits)
        let hol_units = (report.hol_delay_us / 100).min(0xFFFF) as u16;
        pdu[2..4].copy_from_slice(&hol_units.to_be_bytes());

        // Bytes 4-7: Total Buffered Volume (32 bits, bytes)
        let vol = report.total_buffered_bytes.min(u32::MAX as usize) as u32;
        pdu[4..8].copy_from_slice(&vol.to_be_bytes());

        // Bytes 8-9: Total Pending SDUs (16 bits)
        let count = report.total_pending_sdus.min(u16::MAX as usize) as u16;
        pdu[8..10].copy_from_slice(&count.to_be_bytes());

        // Bytes 10-13: Excess Delay Volume (32 bits, bytes)
        let excess_vol = report.excess_delay_bytes.min(u32::MAX as usize) as u32;
        pdu[10..14].copy_from_slice(&excess_vol.to_be_bytes());

        // Bytes 14-15: Excess Delay Count (16 bits)
        let excess_cnt = report.excess_delay_count.min(u16::MAX as usize) as u16;
        pdu[14..16].copy_from_slice(&excess_cnt.to_be_bytes());

        // Bytes 16-19: Imminent Discard Volume (32 bits, bytes)
        let imm_vol = report.imminent_discard_bytes.min(u32::MAX as usize) as u32;
        pdu[16..20].copy_from_slice(&imm_vol.to_be_bytes());

        // Bytes 20-21: Imminent Discard Count (16 bits)
        let imm_cnt = report.imminent_discard_count.min(u16::MAX as usize) as u16;
        pdu[20..22].copy_from_slice(&imm_cnt.to_be_bytes());

        pdu
    }

    /// Parses a 3GPP TS 38.323 §6.2.3.6 Control PDU.
    pub fn decode_control_pdu(bytes: &[u8]) -> Result<PdcpDelayStatusReport, PdcpDelayStatusError> {
        if bytes.len() < PDCP_DELAY_CONTROL_PDU_SIZE {
            return Err(PdcpDelayStatusError::InvalidControlPduSize {
                needed: PDCP_DELAY_CONTROL_PDU_SIZE,
                found: bytes.len(),
            });
        }

        // Byte 0: D/C bit = 0 (Control PDU), PDU Type = 010
        let dc_bit = (bytes[0] >> 7) & 0x01;
        if dc_bit != 0 {
            return Err(PdcpDelayStatusError::InvalidDcBit(dc_bit));
        }

        let pdu_type = (bytes[0] >> 4) & 0x07;
        if pdu_type != PDU_TYPE_DATA_VOLUME_AND_DELAY_STATUS {
            return Err(PdcpDelayStatusError::InvalidPduType(pdu_type));
        }

        let drb_id = (bytes[1] >> 3) & 0x1F;
        let trigger_code = bytes[1] & 0x07;
        let trigger = ReportTriggerReason::from_code(trigger_code)?;

        let hol_units = u16::from_be_bytes([bytes[2], bytes[3]]) as u64;
        let hol_delay_us = hol_units * 100;

        let total_buffered_bytes = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let total_pending_sdus = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;

        let excess_delay_bytes = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
        let excess_delay_count = u16::from_be_bytes([bytes[14], bytes[15]]) as usize;

        let imminent_discard_bytes = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
        let imminent_discard_count = u16::from_be_bytes([bytes[20], bytes[21]]) as usize;

        Ok(PdcpDelayStatusReport {
            drb_id,
            trigger,
            hol_delay_us,
            total_buffered_bytes,
            total_pending_sdus,
            excess_delay_bytes,
            excess_delay_count,
            imminent_discard_bytes,
            imminent_discard_count,
            cumulative_discarded_sdus: 0,
            report_timestamp_us: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// CRC-16 CCITT & Binary Wire Framing (`NrPdcpDelayWirePdu`)
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

/// Binary Wire PDU for PDCP Delay Telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrPdcpDelayWirePdu {
    pub sfn: u16,
    pub slot: u16,
    pub drb_id: u8,
    pub trigger_code: u8,
    pub hol_delay_units: u16,
    pub total_volume_bytes: u32,
    pub pending_sdus: u16,
    pub excess_volume_bytes: u32,
    pub discarded_sdus: u16,
}

impl NrPdcpDelayWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PDCP_DELAY_WIRE_PDU_SIZE);
        buf.extend_from_slice(&PDCP_DELAY_WIRE_MAGIC.to_be_bytes());       // 4 bytes
        buf.extend_from_slice(&self.sfn.to_be_bytes());                    // 2 bytes
        buf.extend_from_slice(&self.slot.to_be_bytes());                   // 2 bytes
        buf.push(self.drb_id);                                             // 1 byte
        buf.push(self.trigger_code);                                       // 1 byte
        buf.extend_from_slice(&self.hol_delay_units.to_be_bytes());         // 2 bytes
        buf.extend_from_slice(&self.total_volume_bytes.to_be_bytes());     // 4 bytes
        buf.extend_from_slice(&self.pending_sdus.to_be_bytes());           // 2 bytes
        buf.extend_from_slice(&self.excess_volume_bytes.to_be_bytes());    // 4 bytes
        buf.extend_from_slice(&self.discarded_sdus.to_be_bytes());         // 2 bytes

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());                         // 2 bytes (total 26 bytes)
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, PdcpDelayStatusError> {
        if bytes.len() < PDCP_DELAY_WIRE_PDU_SIZE {
            return Err(PdcpDelayStatusError::WirePayloadTooShort {
                needed: PDCP_DELAY_WIRE_PDU_SIZE,
                found: bytes.len(),
            });
        }

        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != PDCP_DELAY_WIRE_MAGIC {
            return Err(PdcpDelayStatusError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(PdcpDelayStatusError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let sfn = u16::from_be_bytes([bytes[4], bytes[5]]);
        let slot = u16::from_be_bytes([bytes[6], bytes[7]]);
        let drb_id = bytes[8];
        let trigger_code = bytes[9];
        let hol_delay_units = u16::from_be_bytes([bytes[10], bytes[11]]);
        let total_volume_bytes = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let pending_sdus = u16::from_be_bytes([bytes[16], bytes[17]]);
        let excess_volume_bytes = u32::from_be_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]);
        let discarded_sdus = u16::from_be_bytes([bytes[22], bytes[23]]);

        Ok(Self {
            sfn,
            slot,
            drb_id,
            trigger_code,
            hol_delay_units,
            total_volume_bytes,
            pending_sdus,
            excess_volume_bytes,
            discarded_sdus,
        })
    }
}

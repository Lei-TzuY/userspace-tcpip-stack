//! 3GPP Release 18/19 Multi-Radio Dual Connectivity (MR-DC) Split Bearer & Dynamic Uplink Path Routing Engine.
//!
//! Standards Reference:
//! - 3GPP TS 37.340 Rel-18 §4.2, §4.3: Multi-Radio Dual Connectivity (MR-DC) architecture, MN/SN node termination, MCG/SCG bearers.
//! - 3GPP TS 38.323 Rel-18 §5.2.1: Uplink routing for split bearers, `primaryPath`, and `ul-DataSplitThreshold`.
//! - 3GPP TS 38.323 Rel-18 §5.2.2: PDCP duplication activation/deactivation across cell groups.
//! - 3GPP TS 38.323 Rel-18 §5.2.2.2: Downlink reordering, out-of-order buffering, and duplicate packet discarding.
//! - 3GPP TS 38.331 Rel-18 §5.3.5.3: Rel-18 SCG deactivation / fast reactivation for power saving.
//!
//! Features:
//! 1. Architecture modeling: MN-terminated vs SN-terminated split bearers with Master Cell Group (MCG) and Secondary Cell Group (SCG).
//! 2. Dynamic Uplink Split Routing: Evaluates PDCP buffer load against `ul-DataSplitThreshold`.
//!    - Buffer $\le \text{threshold} \implies$ strictly routes to `primaryPath`.
//!    - Buffer $> \text{threshold} \implies$ dynamically distributes packets across MCG and SCG via Round-Robin, Proportional Load, or Latency-Optimal policies.
//! 3. PDCP Duplication Controller: Clones packets to both MCG and SCG legs when duplication is active.
//! 4. Rel-18 SCG Deactivation / Power Saving: Forces all traffic to primary path when SCG is deactivated, resuming split upon reactivation.
//! 5. Downlink Reordering Buffer: Reorders packets received with arbitrary path delays from MCG and SCG, discards duplicates, and delivers ordered SDUs.
//! 6. Binary wire framing (`MrdcSplitBearerWirePdu`) with magic `0x4D524443` ("MRDC") and CRC-16 CCITT validation.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for MR-DC Wire PDU: "MRDC" (0x4D524443).
pub const MRDC_WIRE_MAGIC: u32 = 0x4D524443;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Errors encountered during MR-DC split bearer processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MrdcError {
    InvalidThreshold(usize),
    InvalidRatio { mcg: u8, scg: u8 },
    ScgDeactivated,
    BufferFull { capacity: usize },
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    WireCrcMismatch { expected: u16, computed: u16 },
}

impl fmt::Display for MrdcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThreshold(t) => write!(f, "Invalid UL data split threshold: {} bytes", t),
            Self::InvalidRatio { mcg, scg } => {
                write!(f, "Invalid split ratio: MCG={}, SCG={} (sum must be > 0)", mcg, scg)
            }
            Self::ScgDeactivated => write!(f, "SCG is currently deactivated for power saving"),
            Self::BufferFull { capacity } => write!(f, "Reordering buffer is full: capacity {}", capacity),
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
// Architecture & Bearer Types (TS 37.340 §4.2 / §4.3)
// ---------------------------------------------------------------------------

/// Dual Connectivity Cell Group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CellGroup {
    /// Master Cell Group (anchored at MN).
    Mcg,
    /// Secondary Cell Group (anchored at SN).
    Scg,
}

/// Node Terminating the Split Bearer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerTermination {
    /// PDCP terminates at Master Node (MN).
    MnTerminated,
    /// PDCP terminates at Secondary Node (SN).
    SnTerminated,
}

/// Transmission Path Tag for PDCP PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmissionPath {
    McgOnly,
    ScgOnly,
    DuplicatedBoth,
}

impl TransmissionPath {
    pub fn to_code(self) -> u8 {
        match self {
            Self::McgOnly => 0x01,
            Self::ScgOnly => 0x02,
            Self::DuplicatedBoth => 0x03,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::McgOnly),
            0x02 => Some(Self::ScgOnly),
            0x03 => Some(Self::DuplicatedBoth),
            _ => None,
        }
    }
}

/// Rel-18 SCG Operational State for Power Saving (TS 38.331 §5.3.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScgState {
    Active,
    Deactivated,
}

/// Uplink Data Split Threshold (TS 38.323 §5.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UlDataSplitThreshold {
    Bytes(usize),
    Infinity,
}

/// Routing Policy for split packets when buffer exceeds threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitPolicy {
    /// Alternates packets between MCG and SCG.
    RoundRobin,
    /// Weights packets according to configured ratio (e.g. 70/30).
    ProportionalLoad { mcg_ratio: u8, scg_ratio: u8 },
    /// Selects path with lower latency.
    LatencyOptimal { mcg_rtt_ms: u32, scg_rtt_ms: u32 },
}

// ---------------------------------------------------------------------------
// Split Bearer Configuration & Engine
// ---------------------------------------------------------------------------

/// Split Bearer Primary Path specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimaryPathConfig {
    pub cell_group: CellGroup,
    pub logical_channel_id: u8,
}

/// Configuration for an MR-DC Split Bearer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitBearerConfig {
    pub bearer_id: u8,
    pub termination: BearerTermination,
    pub primary_path: PrimaryPathConfig,
    pub split_threshold: UlDataSplitThreshold,
    pub duplication_configured: bool,
}

/// Outgoing packet container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingPdu {
    pub sn: u32,
    pub path: TransmissionPath,
    pub payload: Vec<u8>,
}

/// The MR-DC Split Bearer Transmission & Routing Engine.
#[derive(Debug, Clone)]
pub struct MrdcSplitBearerEngine {
    pub config: SplitBearerConfig,
    pub scg_state: ScgState,
    pub duplication_active: bool,
    pub split_policy: SplitPolicy,
    next_sn: u32,
    rr_counter: usize,
    proportional_step: usize,
}

impl MrdcSplitBearerEngine {
    pub fn new(config: SplitBearerConfig, split_policy: SplitPolicy) -> Self {
        Self {
            config,
            scg_state: ScgState::Active,
            duplication_active: false,
            split_policy,
            next_sn: 0,
            rr_counter: 0,
            proportional_step: 0,
        }
    }

    /// Sets the SCG operational state (Active or Deactivated for power saving).
    pub fn set_scg_state(&mut self, state: ScgState) {
        self.scg_state = state;
    }

    /// Toggles PDCP duplication state.
    pub fn set_duplication(&mut self, active: bool) {
        self.duplication_active = active;
    }

    /// Routes a batch of packets given the current total PDCP buffer occupancy.
    pub fn route_packet(&mut self, payload: Vec<u8>, total_buffer_bytes: usize) -> OutgoingPdu {
        let sn = self.next_sn;
        self.next_sn = self.next_sn.wrapping_add(1);

        // 1. If duplication is active and configured, clone to both legs
        if self.duplication_active && self.config.duplication_configured && self.scg_state == ScgState::Active {
            return OutgoingPdu {
                sn,
                path: TransmissionPath::DuplicatedBoth,
                payload,
            };
        }

        // 2. If SCG is deactivated for power saving, all UL traffic routes to primary path (MCG)
        if self.scg_state == ScgState::Deactivated {
            let path = match self.config.primary_path.cell_group {
                CellGroup::Mcg => TransmissionPath::McgOnly,
                CellGroup::Scg => TransmissionPath::ScgOnly,
            };
            return OutgoingPdu { sn, path, payload };
        }

        // 3. Evaluate UL Data Split Threshold (TS 38.323 §5.2.1)
        let route_to_primary = match self.config.split_threshold {
            UlDataSplitThreshold::Infinity => true,
            UlDataSplitThreshold::Bytes(threshold) => total_buffer_bytes <= threshold,
        };

        if route_to_primary {
            let path = match self.config.primary_path.cell_group {
                CellGroup::Mcg => TransmissionPath::McgOnly,
                CellGroup::Scg => TransmissionPath::ScgOnly,
            };
            OutgoingPdu { sn, path, payload }
        } else {
            // Split according to policy
            let selected_path = match self.split_policy {
                SplitPolicy::RoundRobin => {
                    let path = if self.rr_counter % 2 == 0 {
                        TransmissionPath::McgOnly
                    } else {
                        TransmissionPath::ScgOnly
                    };
                    self.rr_counter = self.rr_counter.wrapping_add(1);
                    path
                }
                SplitPolicy::ProportionalLoad { mcg_ratio, scg_ratio } => {
                    let total = (mcg_ratio as usize) + (scg_ratio as usize);
                    let path = if total == 0 || (self.proportional_step % total) < (mcg_ratio as usize) {
                        TransmissionPath::McgOnly
                    } else {
                        TransmissionPath::ScgOnly
                    };
                    self.proportional_step = (self.proportional_step + 1) % if total > 0 { total } else { 1 };
                    path
                }
                SplitPolicy::LatencyOptimal { mcg_rtt_ms, scg_rtt_ms } => {
                    if mcg_rtt_ms <= scg_rtt_ms {
                        TransmissionPath::McgOnly
                    } else {
                        TransmissionPath::ScgOnly
                    }
                }
            };
            OutgoingPdu {
                sn,
                path: selected_path,
                payload,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Downlink Reordering & Duplicate Discard Buffer (TS 38.323 §5.2.2.2)
// ---------------------------------------------------------------------------

/// Reordering buffer to reassemble out-of-order packets from MCG and SCG.
#[derive(Debug, Clone)]
pub struct MrdcReorderingBuffer {
    capacity: usize,
    rx_next: u32,
    received_sns: HashSet<u32>,
    buffer: BTreeMap<u32, Vec<u8>>,
}

impl MrdcReorderingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            rx_next: 0,
            received_sns: HashSet::new(),
            buffer: BTreeMap::new(),
        }
    }

    /// Inserts a received packet arriving via MCG or SCG.
    /// Handles duplicate detection and returns all consecutive, in-sequence packets ready for delivery.
    pub fn receive_pdu(&mut self, sn: u32, payload: Vec<u8>) -> Result<Vec<Vec<u8>>, MrdcError> {
        // Duplicate detection: packet already delivered or in buffer
        if sn < self.rx_next || self.received_sns.contains(&sn) {
            // Drop duplicate cleanly
            return Ok(Vec::new());
        }

        if self.buffer.len() >= self.capacity {
            return Err(MrdcError::BufferFull {
                capacity: self.capacity,
            });
        }

        self.received_sns.insert(sn);
        self.buffer.insert(sn, payload);

        // Collect in-order delivered SDUs
        let mut delivered = Vec::new();
        while let Some(pkt) = self.buffer.remove(&self.rx_next) {
            self.received_sns.remove(&self.rx_next);
            delivered.push(pkt);
            self.rx_next = self.rx_next.wrapping_add(1);
        }

        Ok(delivered)
    }

    pub fn next_expected_sn(&self) -> u32 {
        self.rx_next
    }

    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }
}

// ---------------------------------------------------------------------------
// CRC-16 CCITT & Binary Wire Framing (`MrdcSplitBearerWirePdu`)
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

/// Binary Wire PDU for MR-DC Split Bearer transport over Xn / RLC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrdcSplitBearerWirePdu {
    pub bearer_id: u8,
    pub path: TransmissionPath,
    pub sn: u32,
    pub payload: Vec<u8>,
}

impl MrdcSplitBearerWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.payload.len());
        buf.extend_from_slice(&MRDC_WIRE_MAGIC.to_be_bytes());
        buf.push(self.bearer_id);
        buf.push(self.path.to_code());
        buf.extend_from_slice(&self.sn.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, MrdcError> {
        if bytes.len() < 14 {
            return Err(MrdcError::WirePayloadTooShort {
                needed: 14,
                found: bytes.len(),
            });
        }

        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != MRDC_WIRE_MAGIC {
            return Err(MrdcError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(MrdcError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let bearer_id = bytes[4];
        let path = TransmissionPath::from_code(bytes[5]).ok_or(MrdcError::InvalidWireMagic(0))?;
        let sn = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let payload_len = u16::from_be_bytes([bytes[10], bytes[11]]) as usize;

        if body_len < 12 + payload_len {
            return Err(MrdcError::WirePayloadTooShort {
                needed: 14 + payload_len,
                found: bytes.len(),
            });
        }

        let payload = bytes[12..12 + payload_len].to_vec();

        Ok(Self {
            bearer_id,
            path,
            sn,
            payload,
        })
    }
}

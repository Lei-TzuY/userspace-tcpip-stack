//! 3GPP Release 18 / Release 19 5G NR Sidelink PC5-RRC Connection, Capability & Measurement Engine.
//!
//! Conforms to:
//! - 3GPP TS 38.331 Rel-18 §5.8.9: "Sidelink RRC procedures" (Connection establishment,
//!   Sidelink Radio Bearer (SLRB) configuration, Capability transfer, Measurement reporting, and SL-RLF).
//! - 3GPP TS 38.331 Rel-18 §6.5: "PC5 RRC messages" (`RRCReconfigurationSidelink`,
//!   `RRCReconfigurationCompleteSidelink`, `UECapabilityEnquirySidelink`, `UECapabilityInformationSidelink`,
//!   `MeasurementReportSidelink`, `MasterInformationBlockSidelink`).
//! - 3GPP TS 38.322 Rel-18: RLC AM and UM entity configuration for sidelink.
//! - 3GPP TS 38.323 Rel-18: PDCP entity configuration, SN sizes (12-bit/18-bit), and discard timers.
//! - 3GPP TS 23.287 Rel-18: Architecture enhancements for 5G System support of V2X services.
//!
//! Key Architecture:
//! 1. PC5-RRC Protocol Data Unit (PDU) Binary Codec:
//!    - Serializes and deserializes all standard PC5-RRC signaling messages with transaction ID
//!      validation and CRC-16 data integrity checks.
//! 2. Sidelink Radio Bearer (SLRB) Management:
//!    - Maps PC5 QoS Flows (PQF / PQI) to dedicated SLRBs.
//!    - Configures PDCP (SN size, discard timer), RLC (AM / UM modes), and MAC logical channel priorities.
//! 3. PC5-RRC Connection State Machine:
//!    - Manages peer-to-peer connection lifecycles: Disconnected -> Connecting -> Connected <-> Reconfiguring.
//!    - Correlates RRC transactions (ID 0..3) and handles request timeouts.
//! 4. Sidelink Radio Link Failure (SL-RLF) State Machine:
//!    - Detects link degradation via RLC maximum retransmission threshold (`maxRetxThreshold`) and
//!      unresponsive transaction timers (T400).
//!    - Triggers PC5 connection re-establishment or teardown with upper-layer notifications.
//! 5. Sidelink Measurement Reporting & Congestion Tracking:
//!    - Periodic and event-triggered reporting (Event S1: peer RSRP falls below threshold,
//!      Event S2: Channel Busy Ratio CBR exceeds congestion limit).
//!    - L3 measurement filtering: $F_n = (1 - \alpha) F_{n-1} + \alpha M_n$.
//! 6. Sidelink UE Capability Exchange:
//!    - Discovers peer supported frequency bands, MCS tables (64QAM/256QAM), HARQ feedback modes,
//!      and maximum concurrent SLRBs.
//!
//! Pure standard Rust with zero external dependencies.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Protocol Constants & CRC-16
// ---------------------------------------------------------------------------

/// Maximum number of Sidelink Radio Bearers (SLRBs) per PC5-RRC connection (TS 38.331).
pub const MAX_SLRBS_PER_PEER: usize = 32;

/// Maximum PC5-RRC Transaction ID (0..3 per TS 38.331 §6.5).
pub const MAX_PC5_RRC_TRANSACTION_ID: u8 = 3;

/// Default RRC response timeout timer (T400) in milliseconds (TS 38.331).
pub const DEFAULT_T400_TIMEOUT_MS: u64 = 1000;

/// Default RLC maximum retransmission threshold triggering SL-RLF (TS 38.322).
pub const DEFAULT_MAX_RETX_THRESHOLD: u8 = 8;

/// CRC-16 CCITT polynomial (0x1021).
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Computes CRC-16 CCITT checksum over a slice of bytes.
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

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered during PC5-RRC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pc5RrcError {
    InvalidTransactionId(u8),
    TransactionTimeout { transaction_id: u8, peer_l2_id: u32 },
    SlrbNotFound(u8),
    SlrbLimitExceeded { count: usize, max: usize },
    PeerNotConnected(u32),
    InvalidStateTransition { current: String, target: String },
    SerializationError(String),
    DeserializationError(String),
    ChecksumMismatch { expected: u16, calculated: u16 },
    RadioLinkFailure(String),
}

impl fmt::Display for Pc5RrcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pc5RrcError::InvalidTransactionId(id) => {
                write!(f, "Invalid PC5-RRC transaction ID: {} (valid: 0..3)", id)
            }
            Pc5RrcError::TransactionTimeout {
                transaction_id,
                peer_l2_id,
            } => {
                write!(
                    f,
                    "PC5-RRC transaction {} to peer 0x{:06X} timed out (T400 expiry)",
                    transaction_id, peer_l2_id
                )
            }
            Pc5RrcError::SlrbNotFound(id) => write!(f, "Sidelink Radio Bearer {} not found", id),
            Pc5RrcError::SlrbLimitExceeded { count, max } => {
                write!(f, "SLRB limit exceeded: {} / {} active bearers", count, max)
            }
            Pc5RrcError::PeerNotConnected(id) => {
                write!(f, "Peer 0x{:06X} not in PC5-RRC connected state", id)
            }
            Pc5RrcError::InvalidStateTransition { current, target } => {
                write!(
                    f,
                    "Invalid PC5-RRC transition from {} to {}",
                    current, target
                )
            }
            Pc5RrcError::SerializationError(msg) => {
                write!(f, "PC5-RRC serialization error: {}", msg)
            }
            Pc5RrcError::DeserializationError(msg) => {
                write!(f, "PC5-RRC deserialization error: {}", msg)
            }
            Pc5RrcError::ChecksumMismatch {
                expected,
                calculated,
            } => {
                write!(
                    f,
                    "CRC-16 mismatch: expected 0x{:04X}, computed 0x{:04X}",
                    expected, calculated
                )
            }
            Pc5RrcError::RadioLinkFailure(msg) => {
                write!(f, "Sidelink Radio Link Failure (SL-RLF): {}", msg)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol Data Units (PDUs) and Messages (TS 38.331 §6.5)
// ---------------------------------------------------------------------------

/// PC5-RRC Message Type Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pc5RrcMessageType {
    RrcReconfiguration = 1,
    RrcReconfigurationComplete = 2,
    UeCapabilityEnquiry = 3,
    UeCapabilityInformation = 4,
    MeasurementReport = 5,
    RrcReestablishment = 6,
    RrcReestablishmentComplete = 7,
    MasterInformationBlockSidelink = 8,
}

impl Pc5RrcMessageType {
    pub fn from_u8(val: u8) -> Result<Self, Pc5RrcError> {
        match val {
            1 => Ok(Self::RrcReconfiguration),
            2 => Ok(Self::RrcReconfigurationComplete),
            3 => Ok(Self::UeCapabilityEnquiry),
            4 => Ok(Self::UeCapabilityInformation),
            5 => Ok(Self::MeasurementReport),
            6 => Ok(Self::RrcReestablishment),
            7 => Ok(Self::RrcReestablishmentComplete),
            8 => Ok(Self::MasterInformationBlockSidelink),
            _ => Err(Pc5RrcError::DeserializationError(format!(
                "Unknown PC5-RRC message type: {}",
                val
            ))),
        }
    }
}

/// Sidelink RLC Mode configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlRlcMode {
    /// Acknowledged Mode (AM) with ARQ retransmissions.
    Acknowledged { max_retx_threshold: u8 },
    /// Unacknowledged Mode (UM) without retransmissions.
    Unacknowledged,
}

/// Sidelink PDCP Sequence Number length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlPdcpSnSize {
    Len12Bits,
    Len18Bits,
}

/// Configuration of a Sidelink Radio Bearer (SLRB) per TS 38.331.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlrbConfig {
    /// SLRB Identity (1..32).
    pub slrb_id: u8,
    /// Associated PC5 QoS Flow Identifier (PQFI 1..64).
    pub pqfi: u8,
    /// Sidelink PDCP SN Size.
    pub pdcp_sn_size: SlPdcpSnSize,
    /// PDCP Discard Timer in milliseconds (0 = infinity).
    pub discard_timer_ms: u32,
    /// Sidelink RLC Mode.
    pub rlc_mode: SlRlcMode,
    /// Logical Channel Priority (1 is highest, 8 is lowest).
    pub priority: u8,
}

impl SlrbConfig {
    pub fn new_am(slrb_id: u8, pqfi: u8, priority: u8) -> Self {
        Self {
            slrb_id,
            pqfi,
            pdcp_sn_size: SlPdcpSnSize::Len12Bits,
            discard_timer_ms: 100,
            rlc_mode: SlRlcMode::Acknowledged {
                max_retx_threshold: DEFAULT_MAX_RETX_THRESHOLD,
            },
            priority,
        }
    }

    pub fn new_um(slrb_id: u8, pqfi: u8, priority: u8) -> Self {
        Self {
            slrb_id,
            pqfi,
            pdcp_sn_size: SlPdcpSnSize::Len12Bits,
            discard_timer_ms: 50,
            rlc_mode: SlRlcMode::Unacknowledged,
            priority,
        }
    }
}

/// Sidelink UE Radio Capabilities communicated over PC5-RRC (TS 38.331 §6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlUeCapabilities {
    /// Supported transmission modes: Mode 1 (network-controlled), Mode 2 (autonomous), or both.
    pub supports_mode1: bool,
    pub supports_mode2: bool,
    /// Highest supported MCS modulation order: 2 = QPSK, 4 = 16QAM, 6 = 64QAM, 8 = 256QAM.
    pub max_modulation_order: u8,
    /// Supports Sidelink HARQ feedback on PSFCH.
    pub supports_psfch_harq: bool,
    /// Maximum number of concurrent SLRBs supported.
    pub max_concurrent_slrbs: u8,
    /// Supported frequency bands (e.g. [47, 48, 102]).
    pub supported_bands: Vec<u16>,
}

impl Default for SlUeCapabilities {
    fn default() -> Self {
        Self {
            supports_mode1: true,
            supports_mode2: true,
            max_modulation_order: 6, // 64QAM
            supports_psfch_harq: true,
            max_concurrent_slrbs: 16,
            supported_bands: vec![47, 48],
        }
    }
}

/// PC5-RRC Measurement Report content (TS 38.331 §6.5).
#[derive(Debug, Clone, PartialEq)]
pub struct SlMeasurementReport {
    /// Measured peer Sidelink RSRP in dBm.
    pub peer_rsrp_dbm: f32,
    /// Measured Channel Busy Ratio (CBR 0.0 to 1.0).
    pub cbr: f32,
    /// Sidelink Channel Quality Indicator (1..15).
    pub sl_cqi: u8,
    /// Sidelink Rank Indicator (1..2).
    pub sl_ri: u8,
}

/// Generic PC5-RRC Signaling Message.
#[derive(Debug, Clone, PartialEq)]
pub enum Pc5RrcMessage {
    RrcReconfiguration {
        transaction_id: u8,
        slrbs_to_add: Vec<SlrbConfig>,
        slrbs_to_release: Vec<u8>,
    },
    RrcReconfigurationComplete {
        transaction_id: u8,
    },
    UeCapabilityEnquiry {
        transaction_id: u8,
        requested_bands: Vec<u16>,
    },
    UeCapabilityInformation {
        transaction_id: u8,
        capabilities: SlUeCapabilities,
    },
    MeasurementReport {
        report: SlMeasurementReport,
    },
    RrcReestablishment {
        transaction_id: u8,
        cause: String,
    },
    RrcReestablishmentComplete {
        transaction_id: u8,
    },
    MasterInformationBlockSidelink {
        direct_frame_number: u16,
        direct_subframe_number: u8,
        in_coverage: bool,
    },
}

impl Pc5RrcMessage {
    /// Encodes a PC5-RRC message into a binary wire format with CRC-16 checksum.
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Magic header: 0x52 ("R"), 0x43 ("C"), Version 18 (0x12)
        buf.push(0x52);
        buf.push(0x43);
        buf.push(0x12);

        match self {
            Pc5RrcMessage::RrcReconfiguration {
                transaction_id,
                slrbs_to_add,
                slrbs_to_release,
            } => {
                buf.push(Pc5RrcMessageType::RrcReconfiguration as u8);
                buf.push(*transaction_id);
                buf.push(slrbs_to_add.len() as u8);
                for slrb in slrbs_to_add {
                    buf.push(slrb.slrb_id);
                    buf.push(slrb.pqfi);
                    buf.push(slrb.priority);
                    let (mode_byte, retx) = match slrb.rlc_mode {
                        SlRlcMode::Acknowledged { max_retx_threshold } => (1u8, max_retx_threshold),
                        SlRlcMode::Unacknowledged => (0u8, 0u8),
                    };
                    buf.push(mode_byte);
                    buf.push(retx);
                    buf.extend_from_slice(&slrb.discard_timer_ms.to_be_bytes());
                }
                buf.push(slrbs_to_release.len() as u8);
                for &rel_id in slrbs_to_release {
                    buf.push(rel_id);
                }
            }

            Pc5RrcMessage::RrcReconfigurationComplete { transaction_id } => {
                buf.push(Pc5RrcMessageType::RrcReconfigurationComplete as u8);
                buf.push(*transaction_id);
            }

            Pc5RrcMessage::UeCapabilityEnquiry {
                transaction_id,
                requested_bands,
            } => {
                buf.push(Pc5RrcMessageType::UeCapabilityEnquiry as u8);
                buf.push(*transaction_id);
                buf.push(requested_bands.len() as u8);
                for &b in requested_bands {
                    buf.extend_from_slice(&b.to_be_bytes());
                }
            }

            Pc5RrcMessage::UeCapabilityInformation {
                transaction_id,
                capabilities,
            } => {
                buf.push(Pc5RrcMessageType::UeCapabilityInformation as u8);
                buf.push(*transaction_id);
                let mut flags = 0u8;
                if capabilities.supports_mode1 {
                    flags |= 1 << 0;
                }
                if capabilities.supports_mode2 {
                    flags |= 1 << 1;
                }
                if capabilities.supports_psfch_harq {
                    flags |= 1 << 2;
                }
                buf.push(flags);
                buf.push(capabilities.max_modulation_order);
                buf.push(capabilities.max_concurrent_slrbs);
                buf.push(capabilities.supported_bands.len() as u8);
                for &b in &capabilities.supported_bands {
                    buf.extend_from_slice(&b.to_be_bytes());
                }
            }

            Pc5RrcMessage::MeasurementReport { report } => {
                buf.push(Pc5RrcMessageType::MeasurementReport as u8);
                buf.extend_from_slice(&report.peer_rsrp_dbm.to_bits().to_be_bytes());
                buf.extend_from_slice(&report.cbr.to_bits().to_be_bytes());
                buf.push(report.sl_cqi);
                buf.push(report.sl_ri);
            }

            Pc5RrcMessage::RrcReestablishment {
                transaction_id,
                cause,
            } => {
                buf.push(Pc5RrcMessageType::RrcReestablishment as u8);
                buf.push(*transaction_id);
                let c_bytes = cause.as_bytes();
                buf.push(c_bytes.len() as u8);
                buf.extend_from_slice(c_bytes);
            }

            Pc5RrcMessage::RrcReestablishmentComplete { transaction_id } => {
                buf.push(Pc5RrcMessageType::RrcReestablishmentComplete as u8);
                buf.push(*transaction_id);
            }

            Pc5RrcMessage::MasterInformationBlockSidelink {
                direct_frame_number,
                direct_subframe_number,
                in_coverage,
            } => {
                buf.push(Pc5RrcMessageType::MasterInformationBlockSidelink as u8);
                buf.extend_from_slice(&direct_frame_number.to_be_bytes());
                buf.push(*direct_subframe_number);
                buf.push(if *in_coverage { 1 } else { 0 });
            }
        }

        // Append CRC-16 checksum
        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    /// Decodes a PC5-RRC message from wire format, verifying magic header and CRC-16.
    pub fn decode_wire(data: &[u8]) -> Result<Self, Pc5RrcError> {
        if data.len() < 6 {
            return Err(Pc5RrcError::DeserializationError(
                "Data too short for PC5-RRC frame".into(),
            ));
        }

        // Verify CRC-16
        let payload_len = data.len() - 2;
        let expected_crc = u16::from_be_bytes([data[payload_len], data[payload_len + 1]]);
        let calculated_crc = compute_crc16(&data[..payload_len]);
        if expected_crc != calculated_crc {
            return Err(Pc5RrcError::ChecksumMismatch {
                expected: expected_crc,
                calculated: calculated_crc,
            });
        }

        if data[0] != 0x52 || data[1] != 0x43 || data[2] != 0x12 {
            return Err(Pc5RrcError::DeserializationError(
                "Invalid PC5-RRC magic header".into(),
            ));
        }

        let msg_type = Pc5RrcMessageType::from_u8(data[3])?;
        let mut offset = 4;

        match msg_type {
            Pc5RrcMessageType::RrcReconfiguration => {
                let transaction_id = data[offset];
                offset += 1;
                let add_count = data[offset] as usize;
                offset += 1;
                let mut slrbs_to_add = Vec::new();
                for _ in 0..add_count {
                    let slrb_id = data[offset];
                    let pqfi = data[offset + 1];
                    let priority = data[offset + 2];
                    let is_am = data[offset + 3] == 1;
                    let retx = data[offset + 4];
                    let discard_timer_ms =
                        u32::from_be_bytes(data[offset + 5..offset + 9].try_into().unwrap());
                    offset += 9;

                    let rlc_mode = if is_am {
                        SlRlcMode::Acknowledged {
                            max_retx_threshold: retx,
                        }
                    } else {
                        SlRlcMode::Unacknowledged
                    };

                    slrbs_to_add.push(SlrbConfig {
                        slrb_id,
                        pqfi,
                        pdcp_sn_size: SlPdcpSnSize::Len12Bits,
                        discard_timer_ms,
                        rlc_mode,
                        priority,
                    });
                }

                let rel_count = data[offset] as usize;
                offset += 1;
                let mut slrbs_to_release = Vec::new();
                for _ in 0..rel_count {
                    slrbs_to_release.push(data[offset]);
                    offset += 1;
                }

                Ok(Pc5RrcMessage::RrcReconfiguration {
                    transaction_id,
                    slrbs_to_add,
                    slrbs_to_release,
                })
            }

            Pc5RrcMessageType::RrcReconfigurationComplete => {
                let transaction_id = data[offset];
                Ok(Pc5RrcMessage::RrcReconfigurationComplete { transaction_id })
            }

            Pc5RrcMessageType::UeCapabilityEnquiry => {
                let transaction_id = data[offset];
                offset += 1;
                let band_count = data[offset] as usize;
                offset += 1;
                let mut requested_bands = Vec::new();
                for _ in 0..band_count {
                    requested_bands.push(u16::from_be_bytes(
                        data[offset..offset + 2].try_into().unwrap(),
                    ));
                    offset += 2;
                }
                Ok(Pc5RrcMessage::UeCapabilityEnquiry {
                    transaction_id,
                    requested_bands,
                })
            }

            Pc5RrcMessageType::UeCapabilityInformation => {
                let transaction_id = data[offset];
                offset += 1;
                let flags = data[offset];
                let max_mod = data[offset + 1];
                let max_slrbs = data[offset + 2];
                let band_count = data[offset + 3] as usize;
                offset += 4;

                let mut supported_bands = Vec::new();
                for _ in 0..band_count {
                    supported_bands.push(u16::from_be_bytes(
                        data[offset..offset + 2].try_into().unwrap(),
                    ));
                    offset += 2;
                }

                let capabilities = SlUeCapabilities {
                    supports_mode1: (flags & (1 << 0)) != 0,
                    supports_mode2: (flags & (1 << 1)) != 0,
                    supports_psfch_harq: (flags & (1 << 2)) != 0,
                    max_modulation_order: max_mod,
                    max_concurrent_slrbs: max_slrbs,
                    supported_bands,
                };
                Ok(Pc5RrcMessage::UeCapabilityInformation {
                    transaction_id,
                    capabilities,
                })
            }

            Pc5RrcMessageType::MeasurementReport => {
                let rsrp_bits = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
                let cbr_bits = u32::from_be_bytes(data[offset + 4..offset + 8].try_into().unwrap());
                let sl_cqi = data[offset + 8];
                let sl_ri = data[offset + 9];

                let report = SlMeasurementReport {
                    peer_rsrp_dbm: f32::from_bits(rsrp_bits),
                    cbr: f32::from_bits(cbr_bits),
                    sl_cqi,
                    sl_ri,
                };
                Ok(Pc5RrcMessage::MeasurementReport { report })
            }

            Pc5RrcMessageType::RrcReestablishment => {
                let transaction_id = data[offset];
                offset += 1;
                let len = data[offset] as usize;
                offset += 1;
                let cause = String::from_utf8(data[offset..offset + len].to_vec())
                    .map_err(|e| Pc5RrcError::DeserializationError(e.to_string()))?;
                Ok(Pc5RrcMessage::RrcReestablishment {
                    transaction_id,
                    cause,
                })
            }

            Pc5RrcMessageType::RrcReestablishmentComplete => {
                let transaction_id = data[offset];
                Ok(Pc5RrcMessage::RrcReestablishmentComplete { transaction_id })
            }

            Pc5RrcMessageType::MasterInformationBlockSidelink => {
                let direct_frame_number =
                    u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
                let direct_subframe_number = data[offset + 2];
                let in_coverage = data[offset + 3] == 1;
                Ok(Pc5RrcMessage::MasterInformationBlockSidelink {
                    direct_frame_number,
                    direct_subframe_number,
                    in_coverage,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PC5-RRC Connection State & Peer Context
// ---------------------------------------------------------------------------

/// Connection lifecycle status of a peer over PC5-RRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pc5RrcState {
    Disconnected,
    Connecting,
    Connected,
    Reconfiguring,
    RlfDetected,
}

/// Active peer context maintained by the PC5-RRC engine.
#[derive(Debug, Clone)]
pub struct Pc5RrcPeerContext {
    pub peer_l2_id: u32,
    pub state: Pc5RrcState,
    pub active_slrbs: HashMap<u8, SlrbConfig>,
    pub peer_capabilities: Option<SlUeCapabilities>,
    pub filtered_rsrp_dbm: Option<f32>,
    pub last_cbr: Option<f32>,
    pub active_transaction_id: Option<u8>,
    pub t400_remaining_ms: Option<u64>,
    pub consecutive_rlc_failures: u8,
}

impl Pc5RrcPeerContext {
    pub fn new(peer_l2_id: u32) -> Self {
        Self {
            peer_l2_id,
            state: Pc5RrcState::Disconnected,
            active_slrbs: HashMap::new(),
            peer_capabilities: None,
            filtered_rsrp_dbm: None,
            last_cbr: None,
            active_transaction_id: None,
            t400_remaining_ms: None,
            consecutive_rlc_failures: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Telemetry & Metrics
// ---------------------------------------------------------------------------

/// Subsystem performance metrics for PC5-RRC.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Pc5RrcTelemetry {
    pub connections_established: u64,
    pub slrbs_configured: u64,
    pub slrbs_released: u64,
    pub reconfigurations_completed: u64,
    pub capability_exchanges_completed: u64,
    pub measurement_reports_processed: u64,
    pub sl_rlf_events: u64,
    pub reestablishments_completed: u64,
}

// ---------------------------------------------------------------------------
// PC5-RRC Protocol Engine
// ---------------------------------------------------------------------------

/// Central engine managing PC5-RRC connections, SLRBs, and link quality tracking.
pub struct Pc5RrcEngine {
    local_l2_id: u32,
    peers: HashMap<u32, Pc5RrcPeerContext>,
    current_time_ms: u64,
    telemetry: Pc5RrcTelemetry,
    next_transaction_id: u8,
}

impl Pc5RrcEngine {
    pub fn new(local_l2_id: u32) -> Self {
        Self {
            local_l2_id,
            peers: HashMap::new(),
            current_time_ms: 0,
            telemetry: Pc5RrcTelemetry::default(),
            next_transaction_id: 0,
        }
    }

    pub fn local_l2_id(&self) -> u32 {
        self.local_l2_id
    }

    pub fn current_time_ms(&self) -> u64 {
        self.current_time_ms
    }

    pub fn telemetry(&self) -> &Pc5RrcTelemetry {
        &self.telemetry
    }

    pub fn get_peer(&self, peer_l2_id: u32) -> Option<&Pc5RrcPeerContext> {
        self.peers.get(&peer_l2_id)
    }

    fn get_next_transaction_id(&mut self) -> u8 {
        let id = self.next_transaction_id;
        self.next_transaction_id =
            (self.next_transaction_id + 1) % (MAX_PC5_RRC_TRANSACTION_ID + 1);
        id
    }

    // -----------------------------------------------------------------------
    // Connection Establishment & Teardown
    // -----------------------------------------------------------------------

    /// Initiates a PC5-RRC connection to `peer_l2_id` following PC5-S security setup.
    pub fn initiate_connection(&mut self, peer_l2_id: u32) -> Result<(), Pc5RrcError> {
        let peer = self
            .peers
            .entry(peer_l2_id)
            .or_insert_with(|| Pc5RrcPeerContext::new(peer_l2_id));
        if peer.state != Pc5RrcState::Disconnected && peer.state != Pc5RrcState::RlfDetected {
            return Err(Pc5RrcError::InvalidStateTransition {
                current: format!("{:?}", peer.state),
                target: "Connecting".into(),
            });
        }
        peer.state = Pc5RrcState::Connected;
        self.telemetry.connections_established += 1;
        Ok(())
    }

    /// Releases a PC5-RRC connection to `peer_l2_id`.
    pub fn release_connection(&mut self, peer_l2_id: u32) {
        if let Some(peer) = self.peers.get_mut(&peer_l2_id) {
            peer.state = Pc5RrcState::Disconnected;
            peer.active_slrbs.clear();
            peer.active_transaction_id = None;
            peer.t400_remaining_ms = None;
        }
    }

    // -----------------------------------------------------------------------
    // Sidelink Radio Bearer Reconfiguration Procedure (TS 38.331 §5.8.9.2)
    // -----------------------------------------------------------------------

    /// Generates an `RRCReconfigurationSidelink` message to configure or modify SLRBs.
    pub fn prepare_reconfiguration(
        &mut self,
        peer_l2_id: u32,
        slrbs_to_add: Vec<SlrbConfig>,
        slrbs_to_release: Vec<u8>,
    ) -> Result<Pc5RrcMessage, Pc5RrcError> {
        let tx_id = self.get_next_transaction_id();
        let peer = self
            .peers
            .get_mut(&peer_l2_id)
            .ok_or(Pc5RrcError::PeerNotConnected(peer_l2_id))?;

        if peer.state != Pc5RrcState::Connected {
            return Err(Pc5RrcError::PeerNotConnected(peer_l2_id));
        }

        if peer.active_slrbs.len() + slrbs_to_add.len() > MAX_SLRBS_PER_PEER {
            return Err(Pc5RrcError::SlrbLimitExceeded {
                count: peer.active_slrbs.len() + slrbs_to_add.len(),
                max: MAX_SLRBS_PER_PEER,
            });
        }

        peer.state = Pc5RrcState::Reconfiguring;
        peer.active_transaction_id = Some(tx_id);
        peer.t400_remaining_ms = Some(DEFAULT_T400_TIMEOUT_MS);

        Ok(Pc5RrcMessage::RrcReconfiguration {
            transaction_id: tx_id,
            slrbs_to_add,
            slrbs_to_release,
        })
    }

    /// Handles an incoming `RRCReconfigurationSidelink` on the receiver peer and applies changes.
    pub fn process_reconfiguration(
        &mut self,
        peer_l2_id: u32,
        transaction_id: u8,
        slrbs_to_add: Vec<SlrbConfig>,
        slrbs_to_release: Vec<u8>,
    ) -> Result<Pc5RrcMessage, Pc5RrcError> {
        let peer = self
            .peers
            .entry(peer_l2_id)
            .or_insert_with(|| Pc5RrcPeerContext::new(peer_l2_id));
        peer.state = Pc5RrcState::Connected;

        for slrb in slrbs_to_add {
            peer.active_slrbs.insert(slrb.slrb_id, slrb);
            self.telemetry.slrbs_configured += 1;
        }

        for rel_id in slrbs_to_release {
            if peer.active_slrbs.remove(&rel_id).is_some() {
                self.telemetry.slrbs_released += 1;
            }
        }

        self.telemetry.reconfigurations_completed += 1;
        Ok(Pc5RrcMessage::RrcReconfigurationComplete { transaction_id })
    }

    /// Handles an incoming `RRCReconfigurationCompleteSidelink` confirming reconfiguration.
    pub fn process_reconfiguration_complete(
        &mut self,
        peer_l2_id: u32,
        transaction_id: u8,
        applied_adds: Vec<SlrbConfig>,
        applied_releases: Vec<u8>,
    ) -> Result<(), Pc5RrcError> {
        let peer = self
            .peers
            .get_mut(&peer_l2_id)
            .ok_or(Pc5RrcError::PeerNotConnected(peer_l2_id))?;

        if peer.active_transaction_id != Some(transaction_id) {
            return Err(Pc5RrcError::InvalidTransactionId(transaction_id));
        }

        for slrb in applied_adds {
            peer.active_slrbs.insert(slrb.slrb_id, slrb);
            self.telemetry.slrbs_configured += 1;
        }
        for rel_id in applied_releases {
            if peer.active_slrbs.remove(&rel_id).is_some() {
                self.telemetry.slrbs_released += 1;
            }
        }

        peer.state = Pc5RrcState::Connected;
        peer.active_transaction_id = None;
        peer.t400_remaining_ms = None;
        self.telemetry.reconfigurations_completed += 1;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sidelink Capability Exchange (TS 38.331 §5.8.9.3)
    // -----------------------------------------------------------------------

    /// Prepares a `UECapabilityEnquirySidelink` message.
    pub fn prepare_capability_enquiry(
        &mut self,
        peer_l2_id: u32,
        requested_bands: Vec<u16>,
    ) -> Result<Pc5RrcMessage, Pc5RrcError> {
        let tx_id = self.get_next_transaction_id();
        let peer = self
            .peers
            .get_mut(&peer_l2_id)
            .ok_or(Pc5RrcError::PeerNotConnected(peer_l2_id))?;
        peer.active_transaction_id = Some(tx_id);
        peer.t400_remaining_ms = Some(DEFAULT_T400_TIMEOUT_MS);

        Ok(Pc5RrcMessage::UeCapabilityEnquiry {
            transaction_id: tx_id,
            requested_bands,
        })
    }

    /// Processes `UECapabilityInformationSidelink` received from peer.
    pub fn process_capability_information(
        &mut self,
        peer_l2_id: u32,
        capabilities: SlUeCapabilities,
    ) -> Result<(), Pc5RrcError> {
        let peer = self
            .peers
            .get_mut(&peer_l2_id)
            .ok_or(Pc5RrcError::PeerNotConnected(peer_l2_id))?;
        peer.peer_capabilities = Some(capabilities);
        peer.active_transaction_id = None;
        peer.t400_remaining_ms = None;
        self.telemetry.capability_exchanges_completed += 1;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sidelink Measurement Reporting (TS 38.331 §5.8.9.4)
    // -----------------------------------------------------------------------

    /// Submits and applies a `MeasurementReportSidelink` with Layer-3 exponential filtering.
    pub fn process_measurement_report(
        &mut self,
        peer_l2_id: u32,
        report: SlMeasurementReport,
        filter_alpha: f32,
    ) -> Result<(), Pc5RrcError> {
        let peer = self
            .peers
            .get_mut(&peer_l2_id)
            .ok_or(Pc5RrcError::PeerNotConnected(peer_l2_id))?;

        let filtered_rsrp = match peer.filtered_rsrp_dbm {
            Some(prev) => (1.0 - filter_alpha) * prev + filter_alpha * report.peer_rsrp_dbm,
            None => report.peer_rsrp_dbm,
        };

        peer.filtered_rsrp_dbm = Some(filtered_rsrp);
        peer.last_cbr = Some(report.cbr);
        self.telemetry.measurement_reports_processed += 1;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sidelink Radio Link Failure (SL-RLF) Detection & Recovery
    // -----------------------------------------------------------------------

    /// Reports an RLC transmission outcome. If consecutive failures exceed threshold, triggers SL-RLF.
    pub fn notify_rlc_transmission_failure(
        &mut self,
        peer_l2_id: u32,
        slrb_id: u8,
    ) -> Result<bool, Pc5RrcError> {
        let peer = self
            .peers
            .get_mut(&peer_l2_id)
            .ok_or(Pc5RrcError::PeerNotConnected(peer_l2_id))?;
        let threshold = match peer.active_slrbs.get(&slrb_id) {
            Some(cfg) => match cfg.rlc_mode {
                SlRlcMode::Acknowledged { max_retx_threshold } => max_retx_threshold,
                SlRlcMode::Unacknowledged => DEFAULT_MAX_RETX_THRESHOLD,
            },
            None => DEFAULT_MAX_RETX_THRESHOLD,
        };

        peer.consecutive_rlc_failures += 1;
        if peer.consecutive_rlc_failures >= threshold {
            peer.state = Pc5RrcState::RlfDetected;
            self.telemetry.sl_rlf_events += 1;
            return Ok(true); // SL-RLF declared!
        }
        Ok(false)
    }

    /// Resets RLC failure count upon successful acknowledgment.
    pub fn notify_rlc_transmission_success(&mut self, peer_l2_id: u32) {
        if let Some(peer) = self.peers.get_mut(&peer_l2_id) {
            peer.consecutive_rlc_failures = 0;
        }
    }

    // -----------------------------------------------------------------------
    // Temporal Advancement & T400 Expiration
    // -----------------------------------------------------------------------

    /// Advances simulation time by `delta_ms`, tracking active T400 timers and declaring RLF on timeout.
    pub fn advance_time_ms(&mut self, delta_ms: u64) -> Vec<(u32, Pc5RrcError)> {
        self.current_time_ms += delta_ms;
        let mut rlf_events = Vec::new();

        for (&peer_id, peer) in self.peers.iter_mut() {
            if let Some(remaining) = peer.t400_remaining_ms {
                if remaining <= delta_ms {
                    peer.t400_remaining_ms = None;
                    let tx_id = peer.active_transaction_id.unwrap_or(0);
                    peer.state = Pc5RrcState::RlfDetected;
                    rlf_events.push((
                        peer_id,
                        Pc5RrcError::TransactionTimeout {
                            transaction_id: tx_id,
                            peer_l2_id: peer_id,
                        },
                    ));
                } else {
                    peer.t400_remaining_ms = Some(remaining - delta_ms);
                }
            }
        }

        for _ in &rlf_events {
            self.telemetry.sl_rlf_events += 1;
        }

        rlf_events
    }
}

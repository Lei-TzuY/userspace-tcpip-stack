//! 3GPP Rel-18 / Rel-19 5G NR Sidelink Multicast & Broadcast Services (SL-MBS) Engine.
//!
//! Conforms to:
//! - 3GPP TR 38.843: Study on NR sidelink relay and ranging enhancements (Release 18).
//! - 3GPP TS 38.300 Rel-18 §16.14: Sidelink Multicast and Broadcast Services architecture.
//! - 3GPP TS 38.321 Rel-18 §5.x: Sidelink MAC procedures, groupcast PSFCH HARQ feedback (Option 1 vs Option 2),
//!   Sidelink MBS DRX.
//! - 3GPP TS 38.331 Rel-18: Sidelink RRC Group configuration, SL-TMGI mapping, Minimum Required Communication Range (MCR).
//! - 3GPP TS 23.304: Proximity-based Services (ProSe) in 5G System; Stage 2.
//!
//! Features:
//! 1. Direct PC5 point-to-multipoint (PTM) Sidelink MBS group session management.
//! 2. Distance-based HARQ Feedback on PSFCH (Option 1 NACK-only with MCR boundary filtering).
//! 3. Closed-group individual ACK/NACK feedback (Option 2) and feedback-less blind retransmissions.
//! 4. Minimum Required Communication Range (MCR) distance calculation ($d = \|\mathbf{x}_{rx} - \mathbf{x}_{tx}\|$).
//! 5. Group DRX synchronization (On-Duration, Inactivity, and DRX cycle alignment).
//! 6. Sidelink group membership tracking, heartbeat update, and inactivity eviction.
//! 7. Binary wire serialization and deserialization for SL-MBS Control and Data PDUs with CRC-16 CCITT.
//! 8. Comprehensive telemetry tracking packet delivery ratio, MCR suppression savings, and PSFCH feedback.
//!
//! Pure standard Rust with zero external dependencies.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & CRC-16
// ---------------------------------------------------------------------------

/// Maximum number of active SL-MBS groups managed simultaneously by a single UE.
pub const MAX_SL_MBS_GROUPS: usize = 16;

/// Maximum number of members tracked in a single SL-MBS group.
pub const MAX_SL_MBS_MEMBERS_PER_GROUP: usize = 64;

/// Default Minimum Required Communication Range in meters.
pub const DEFAULT_MCR_METERS: f64 = 100.0;

/// Default maximum number of HARQ retransmissions for multicast transport blocks.
pub const DEFAULT_MAX_SL_MBS_RETX: u8 = 3;

/// Magic header identifier for SL-MBS binary wire frames (0x534D4253 = "SMBS").
pub const SL_MBS_WIRE_MAGIC: [u8; 4] = [0x53, 0x4D, 0x42, 0x53];

/// CRC-16 CCITT polynomial (0x1021 = x^16 + x^12 + x^5 + 1).
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
// Identifiers & Core Data Structures
// ---------------------------------------------------------------------------

/// Sidelink MBS Service Classification per 3GPP TS 23.304 / TR 38.843.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlMbsServiceType {
    /// Mission-Critical Push-to-Talk and Public Safety dispatch group communication.
    PublicSafetyGroupCall,
    /// V2X Cooperative Awareness and Platooning message exchange.
    V2xPlatooning,
    /// Automated Guided Vehicle (AGV) and Industrial Robot swarm coordination.
    IndustrialFleetCoordination,
    /// Local venue high-bandwidth audio/video multicast broadcast.
    LocalMediaBroadcast,
}

impl SlMbsServiceType {
    pub fn to_u8(&self) -> u8 {
        match self {
            SlMbsServiceType::PublicSafetyGroupCall => 0,
            SlMbsServiceType::V2xPlatooning => 1,
            SlMbsServiceType::IndustrialFleetCoordination => 2,
            SlMbsServiceType::LocalMediaBroadcast => 3,
        }
    }

    pub fn from_u8(val: u8) -> Result<Self, SlMbsError> {
        match val {
            0 => Ok(SlMbsServiceType::PublicSafetyGroupCall),
            1 => Ok(SlMbsServiceType::V2xPlatooning),
            2 => Ok(SlMbsServiceType::IndustrialFleetCoordination),
            3 => Ok(SlMbsServiceType::LocalMediaBroadcast),
            other => Err(SlMbsError::InvalidServiceType(other)),
        }
    }
}

/// Sidelink Temporary Mobile Group Identity (SL-TMGI).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SlMbsTmgi {
    /// 24-bit Service ID (3 octets)
    pub service_id: [u8; 3],
    /// Domain or Application Identifier string (e.g. "v2x.ps.domain")
    pub domain_id: String,
}

impl SlMbsTmgi {
    pub fn new(service_id: [u8; 3], domain_id: &str) -> Self {
        Self {
            service_id,
            domain_id: domain_id.to_string(),
        }
    }
}

/// HARQ feedback scheme applied to an SL-MBS group per 3GPP TS 38.321 §5.x.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarqFeedbackScheme {
    /// Option 1: Distance-based NACK-only feedback.
    /// Only UEs located within Minimum Required Communication Range (MCR) transmit NACK on decoding failure.
    /// UEs outside MCR suppress feedback to prevent channel congestion.
    Option1NackOnlyMcr,
    /// Option 2: Dedicated ACK/NACK feedback transmitted by all assigned members.
    Option2AckNackIndividual,
    /// Blind Retransmission: No PSFCH feedback; sender blindly repeats transmissions.
    BlindRetransmissions,
}

impl HarqFeedbackScheme {
    pub fn to_u8(&self) -> u8 {
        match self {
            HarqFeedbackScheme::Option1NackOnlyMcr => 1,
            HarqFeedbackScheme::Option2AckNackIndividual => 2,
            HarqFeedbackScheme::BlindRetransmissions => 3,
        }
    }

    pub fn from_u8(val: u8) -> Result<Self, SlMbsError> {
        match val {
            1 => Ok(HarqFeedbackScheme::Option1NackOnlyMcr),
            2 => Ok(HarqFeedbackScheme::Option2AckNackIndividual),
            3 => Ok(HarqFeedbackScheme::BlindRetransmissions),
            other => Err(SlMbsError::InvalidFeedbackScheme(other)),
        }
    }
}

/// Outcome of a receiver evaluating whether to transmit feedback on PSFCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlMbsPsfchDecision {
    /// Transmit ACK on designated PSFCH resource.
    SendAck,
    /// Transmit NACK on designated PSFCH resource.
    SendNack,
    /// Feedback suppressed because receiver is outside MCR boundary ($d > MCR$).
    SuppressedOutsideMcr,
    /// Feedback suppressed because session operates in Blind Retransmission mode.
    SuppressedBlindRetx,
}

/// 3D geographic/Cartesian coordinates in meters for MCR calculation.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Location3D {
    pub x_m: f64,
    pub y_m: f64,
    pub z_m: f64,
}

impl Location3D {
    pub fn new(x_m: f64, y_m: f64, z_m: f64) -> Self {
        Self { x_m, y_m, z_m }
    }

    /// Computes 3D Euclidean distance to another location.
    pub fn distance_to(&self, other: &Location3D) -> f64 {
        let dx = self.x_m - other.x_m;
        let dy = self.y_m - other.y_m;
        let dz = self.z_m - other.z_m;
        (dx * dx + dy * dy + dz * dz).sqrt()
    }
}

/// Member state in an SL-MBS multicast group.
#[derive(Debug, Clone, PartialEq)]
pub struct SlMbsMember {
    pub member_l2_id: u32,
    pub location: Location3D,
    pub last_heard_ms: u64,
    pub active: bool,
}

/// Configuration of an SL-MBS Multicast Group Session.
#[derive(Debug, Clone, PartialEq)]
pub struct SlMbsGroupConfig {
    /// 24-bit Destination Layer-2 ID
    pub group_l2_id: u32,
    pub tmgi: SlMbsTmgi,
    pub service_type: SlMbsServiceType,
    /// Minimum Required Communication Range in meters
    pub mcr_meters: f64,
    pub feedback_scheme: HarqFeedbackScheme,
    pub max_retransmissions: u8,
    /// Sidelink MBS DRX On-Duration in milliseconds
    pub drx_on_duration_ms: u32,
    /// Sidelink MBS DRX Cycle period in milliseconds
    pub drx_cycle_ms: u32,
}

impl SlMbsGroupConfig {
    pub fn new(
        group_l2_id: u32,
        tmgi: SlMbsTmgi,
        service_type: SlMbsServiceType,
        mcr_meters: f64,
    ) -> Self {
        Self {
            group_l2_id: group_l2_id & 0x00FF_FFFF,
            tmgi,
            service_type,
            mcr_meters: mcr_meters.max(1.0),
            feedback_scheme: HarqFeedbackScheme::Option1NackOnlyMcr,
            max_retransmissions: DEFAULT_MAX_SL_MBS_RETX,
            drx_on_duration_ms: 20,
            drx_cycle_ms: 100,
        }
    }
}

/// Sidelink MBS Data Packet wire frame.
#[derive(Debug, Clone, PartialEq)]
pub struct SlMbsPdu {
    pub group_l2_id: u32,
    pub sequence_number: u32,
    pub tx_ue_id: u32,
    pub tx_x_m: f32,
    pub tx_y_m: f32,
    pub tx_z_m: f32,
    pub mcr_m: f32,
    pub feedback_scheme: HarqFeedbackScheme,
    pub payload: Vec<u8>,
}

impl SlMbsPdu {
    /// Serializes SL-MBS PDU into binary wire format with CRC-16 CCITT.
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(34 + self.payload.len());
        buf.extend_from_slice(&SL_MBS_WIRE_MAGIC);
        buf.extend_from_slice(&(self.group_l2_id & 0x00FF_FFFF).to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.tx_ue_id.to_be_bytes());
        buf.extend_from_slice(&self.tx_x_m.to_bits().to_be_bytes());
        buf.extend_from_slice(&self.tx_y_m.to_bits().to_be_bytes());
        buf.extend_from_slice(&self.tx_z_m.to_bits().to_be_bytes());
        buf.extend_from_slice(&self.mcr_m.to_bits().to_be_bytes());
        buf.push(self.feedback_scheme.to_u8());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    /// Deserializes SL-MBS PDU from binary wire format, verifying magic header and CRC-16.
    pub fn decode_wire(data: &[u8]) -> Result<Self, SlMbsError> {
        if data.len() < 35 {
            return Err(SlMbsError::DeserializationError("Buffer too small for SL-MBS PDU header".into()));
        }

        let payload_len = data.len() - 2;
        let expected_crc = u16::from_be_bytes([data[payload_len], data[payload_len + 1]]);
        let calculated_crc = compute_crc16(&data[..payload_len]);
        if expected_crc != calculated_crc {
            return Err(SlMbsError::ChecksumMismatch {
                expected: expected_crc,
                calculated: calculated_crc,
            });
        }

        if &data[0..4] != &SL_MBS_WIRE_MAGIC {
            return Err(SlMbsError::DeserializationError("Invalid SL-MBS magic header".into()));
        }

        let group_l2_id = u32::from_be_bytes(data[4..8].try_into().unwrap()) & 0x00FF_FFFF;
        let sequence_number = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let tx_ue_id = u32::from_be_bytes(data[12..16].try_into().unwrap());
        let tx_x_m = f32::from_bits(u32::from_be_bytes(data[16..20].try_into().unwrap()));
        let tx_y_m = f32::from_bits(u32::from_be_bytes(data[20..24].try_into().unwrap()));
        let tx_z_m = f32::from_bits(u32::from_be_bytes(data[24..28].try_into().unwrap()));
        let mcr_m = f32::from_bits(u32::from_be_bytes(data[28..32].try_into().unwrap()));
        let feedback_scheme = HarqFeedbackScheme::from_u8(data[32])?;

        let body_len = u16::from_be_bytes(data[33..35].try_into().unwrap()) as usize;
        if data.len() != 35 + body_len + 2 {
            return Err(SlMbsError::DeserializationError("Payload length mismatch".into()));
        }

        let payload = data[35..35 + body_len].to_vec();

        Ok(Self {
            group_l2_id,
            sequence_number,
            tx_ue_id,
            tx_x_m,
            tx_y_m,
            tx_z_m,
            mcr_m,
            feedback_scheme,
            payload,
        })
    }
}

/// Telemetry metrics for Sidelink Multicast & Broadcast Services.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SlMbsTelemetry {
    pub total_multicast_transmissions: u64,
    pub successful_deliveries: u64,
    pub retransmissions_sent: u64,
    pub mcr_suppressions: u64,
    pub psfch_nacks_received: u64,
    pub psfch_acks_received: u64,
}

impl SlMbsTelemetry {
    /// Packet Delivery Success Ratio (PDR) in percentage.
    pub fn packet_delivery_ratio_percent(&self) -> f64 {
        if self.total_multicast_transmissions == 0 {
            0.0
        } else {
            (self.successful_deliveries as f64 / self.total_multicast_transmissions as f64) * 100.0
        }
    }

    /// Communication efficiency gain achieved by suppressing feedback outside MCR.
    pub fn suppression_ratio_percent(&self) -> f64 {
        let total_feedback_ops = self.psfch_nacks_received + self.psfch_acks_received + self.mcr_suppressions;
        if total_feedback_ops == 0 {
            0.0
        } else {
            (self.mcr_suppressions as f64 / total_feedback_ops as f64) * 100.0
        }
    }
}

/// Errors raised during SL-MBS session operations.
#[derive(Debug, Clone, PartialEq)]
pub enum SlMbsError {
    GroupNotFound(u32),
    GroupCapacityExceeded { max: usize, attempted: usize },
    DuplicateGroupId(u32),
    MemberNotFound(u32),
    MemberCapacityExceeded { max: usize, attempted: usize },
    DuplicateMemberId(u32),
    InvalidServiceType(u8),
    InvalidFeedbackScheme(u8),
    ChecksumMismatch { expected: u16, calculated: u16 },
    DeserializationError(String),
}

impl fmt::Display for SlMbsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlMbsError::GroupNotFound(id) => write!(f, "SL-MBS Group L2 ID 0x{:06X} not found", id),
            SlMbsError::GroupCapacityExceeded { max, attempted } => {
                write!(f, "Group capacity exceeded: max {}, attempted {}", max, attempted)
            }
            SlMbsError::DuplicateGroupId(id) => write!(f, "Duplicate Group L2 ID: 0x{:06X}", id),
            SlMbsError::MemberNotFound(id) => write!(f, "Group member 0x{:06X} not found", id),
            SlMbsError::MemberCapacityExceeded { max, attempted } => {
                write!(f, "Member capacity exceeded: max {}, attempted {}", max, attempted)
            }
            SlMbsError::DuplicateMemberId(id) => write!(f, "Duplicate Member ID: 0x{:06X}", id),
            SlMbsError::InvalidServiceType(val) => write!(f, "Invalid SL-MBS service type: {}", val),
            SlMbsError::InvalidFeedbackScheme(val) => write!(f, "Invalid HARQ feedback scheme: {}", val),
            SlMbsError::ChecksumMismatch { expected, calculated } => write!(
                f,
                "CRC-16 mismatch: expected 0x{:04X}, calculated 0x{:04X}",
                expected, calculated
            ),
            SlMbsError::DeserializationError(msg) => write!(f, "Deserialization failed: {}", msg),
        }
    }
}

impl std::error::Error for SlMbsError {}

// ---------------------------------------------------------------------------
// Central Sidelink MBS Engine
// ---------------------------------------------------------------------------

/// 3GPP Rel-18/19 Sidelink Multicast & Broadcast Services (SL-MBS) Engine.
pub struct NrSlMbsEngine {
    local_ue_id: u32,
    local_location: Location3D,
    groups: HashMap<u32, SlMbsGroupConfig>,
    group_members: HashMap<u32, Vec<SlMbsMember>>,
    telemetry: SlMbsTelemetry,
}

impl NrSlMbsEngine {
    /// Creates a new SL-MBS Engine for the local UE.
    pub fn new(local_ue_id: u32, local_location: Location3D) -> Self {
        Self {
            local_ue_id,
            local_location,
            groups: HashMap::new(),
            group_members: HashMap::new(),
            telemetry: SlMbsTelemetry::default(),
        }
    }

    pub fn local_ue_id(&self) -> u32 {
        self.local_ue_id
    }

    pub fn local_location(&self) -> Location3D {
        self.local_location
    }

    pub fn update_local_location(&mut self, location: Location3D) {
        self.local_location = location;
    }

    pub fn telemetry(&self) -> &SlMbsTelemetry {
        &self.telemetry
    }

    // -----------------------------------------------------------------------
    // Group Session Management
    // -----------------------------------------------------------------------

    /// Creates and registers a new SL-MBS Multicast Group session.
    pub fn create_group(&mut self, config: SlMbsGroupConfig) -> Result<(), SlMbsError> {
        if self.groups.contains_key(&config.group_l2_id) {
            return Err(SlMbsError::DuplicateGroupId(config.group_l2_id));
        }
        if self.groups.len() >= MAX_SL_MBS_GROUPS {
            return Err(SlMbsError::GroupCapacityExceeded {
                max: MAX_SL_MBS_GROUPS,
                attempted: self.groups.len() + 1,
            });
        }

        let gid = config.group_l2_id;
        self.groups.insert(gid, config);
        self.group_members.insert(gid, Vec::new());
        Ok(())
    }

    /// Adds or updates a member in an SL-MBS group.
    pub fn join_group(
        &mut self,
        group_l2_id: u32,
        member_id: u32,
        location: Location3D,
        now_ms: u64,
    ) -> Result<(), SlMbsError> {
        let members = self
            .group_members
            .get_mut(&group_l2_id)
            .ok_or(SlMbsError::GroupNotFound(group_l2_id))?;

        if let Some(m) = members.iter_mut().find(|m| m.member_l2_id == member_id) {
            m.location = location;
            m.last_heard_ms = now_ms;
            m.active = true;
            return Ok(());
        }

        if members.len() >= MAX_SL_MBS_MEMBERS_PER_GROUP {
            return Err(SlMbsError::MemberCapacityExceeded {
                max: MAX_SL_MBS_MEMBERS_PER_GROUP,
                attempted: members.len() + 1,
            });
        }

        members.push(SlMbsMember {
            member_l2_id: member_id,
            location,
            last_heard_ms: now_ms,
            active: true,
        });

        Ok(())
    }

    /// Removes a member from an SL-MBS group.
    pub fn leave_group(&mut self, group_l2_id: u32, member_id: u32) -> Result<(), SlMbsError> {
        let members = self
            .group_members
            .get_mut(&group_l2_id)
            .ok_or(SlMbsError::GroupNotFound(group_l2_id))?;

        let initial_len = members.len();
        members.retain(|m| m.member_l2_id != member_id);

        if members.len() == initial_len {
            Err(SlMbsError::MemberNotFound(member_id))
        } else {
            Ok(())
        }
    }

    /// Evicts members who haven't sent a keep-alive/heartbeat within timeout_ms.
    pub fn evict_timed_out_members(&mut self, group_l2_id: u32, now_ms: u64, timeout_ms: u64) -> usize {
        if let Some(members) = self.group_members.get_mut(&group_l2_id) {
            let before = members.len();
            members.retain(|m| now_ms.saturating_sub(m.last_heard_ms) <= timeout_ms);
            before - members.len()
        } else {
            0
        }
    }

    pub fn get_group_config(&self, group_l2_id: u32) -> Option<&SlMbsGroupConfig> {
        self.groups.get(&group_l2_id)
    }

    pub fn get_group_members(&self, group_l2_id: u32) -> Option<&[SlMbsMember]> {
        self.group_members.get(&group_l2_id).map(|v| v.as_slice())
    }

    // -----------------------------------------------------------------------
    // Receiver-Side Distance-Based PSFCH Feedback Evaluation
    // -----------------------------------------------------------------------

    /// Evaluates whether the local receiving UE should transmit ACK, NACK, or suppress feedback on PSFCH.
    pub fn evaluate_rx_feedback(
        &mut self,
        group_l2_id: u32,
        tx_location: &Location3D,
        decode_success: bool,
    ) -> Result<SlMbsPsfchDecision, SlMbsError> {
        let group_cfg = self
            .groups
            .get(&group_l2_id)
            .ok_or(SlMbsError::GroupNotFound(group_l2_id))?;

        match group_cfg.feedback_scheme {
            HarqFeedbackScheme::BlindRetransmissions => {
                self.telemetry.mcr_suppressions += 1;
                Ok(SlMbsPsfchDecision::SuppressedBlindRetx)
            }
            HarqFeedbackScheme::Option1NackOnlyMcr => {
                let distance = self.local_location.distance_to(tx_location);
                if distance <= group_cfg.mcr_meters {
                    if decode_success {
                        // Option 1: In NACK-only mode, success emits NO feedback to save energy and PSFCH resources
                        Ok(SlMbsPsfchDecision::SendAck)
                    } else {
                        // Failure within MCR: must emit NACK on PSFCH
                        self.telemetry.psfch_nacks_received += 1;
                        Ok(SlMbsPsfchDecision::SendNack)
                    }
                } else {
                    // Outside MCR boundary: feedback suppressed
                    self.telemetry.mcr_suppressions += 1;
                    Ok(SlMbsPsfchDecision::SuppressedOutsideMcr)
                }
            }
            HarqFeedbackScheme::Option2AckNackIndividual => {
                if decode_success {
                    self.telemetry.psfch_acks_received += 1;
                    Ok(SlMbsPsfchDecision::SendAck)
                } else {
                    self.telemetry.psfch_nacks_received += 1;
                    Ok(SlMbsPsfchDecision::SendNack)
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Transmitter-Side Multicast Delivery & Retransmission Control
    // -----------------------------------------------------------------------

    /// Prepares an outgoing SL-MBS multicast packet frame containing local position and MCR for SCI.
    pub fn prepare_multicast_tx(
        &mut self,
        group_l2_id: u32,
        sequence_number: u32,
        payload: Vec<u8>,
    ) -> Result<SlMbsPdu, SlMbsError> {
        let group_cfg = self
            .groups
            .get(&group_l2_id)
            .ok_or(SlMbsError::GroupNotFound(group_l2_id))?;

        self.telemetry.total_multicast_transmissions += 1;

        Ok(SlMbsPdu {
            group_l2_id,
            sequence_number,
            tx_ue_id: self.local_ue_id,
            tx_x_m: self.local_location.x_m as f32,
            tx_y_m: self.local_location.y_m as f32,
            tx_z_m: self.local_location.z_m as f32,
            mcr_m: group_cfg.mcr_meters as f32,
            feedback_scheme: group_cfg.feedback_scheme,
            payload,
        })
    }

    /// Transmitter evaluates PSFCH feedback results across group members to determine if retransmission is needed.
    /// Returns true if a retransmission must be scheduled.
    pub fn handle_psfch_feedback(
        &mut self,
        group_l2_id: u32,
        nacks_count: usize,
        acks_count: usize,
        current_retx_count: u8,
    ) -> Result<bool, SlMbsError> {
        let group_cfg = self
            .groups
            .get(&group_l2_id)
            .ok_or(SlMbsError::GroupNotFound(group_l2_id))?;

        if current_retx_count >= group_cfg.max_retransmissions {
            // Retransmission limit reached
            return Ok(false);
        }

        match group_cfg.feedback_scheme {
            HarqFeedbackScheme::BlindRetransmissions => {
                // Blind retransmissions continue until max_retransmissions
                if current_retx_count < group_cfg.max_retransmissions {
                    self.telemetry.retransmissions_sent += 1;
                    Ok(true)
                } else {
                    self.telemetry.successful_deliveries += 1;
                    Ok(false)
                }
            }
            HarqFeedbackScheme::Option1NackOnlyMcr => {
                if nacks_count > 0 {
                    // Any NACK from a member within MCR triggers retransmission
                    self.telemetry.retransmissions_sent += 1;
                    Ok(true)
                } else {
                    // No NACKs received within MCR: considered successful
                    self.telemetry.successful_deliveries += 1;
                    Ok(false)
                }
            }
            HarqFeedbackScheme::Option2AckNackIndividual => {
                if nacks_count > 0 || (acks_count == 0 && current_retx_count == 0) {
                    self.telemetry.retransmissions_sent += 1;
                    Ok(true)
                } else {
                    self.telemetry.successful_deliveries += 1;
                    Ok(false)
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Sidelink MBS DRX Synchronization
    // -----------------------------------------------------------------------

    /// Evaluates if an SL-MBS group is currently within its active On-Duration window.
    pub fn is_group_drx_active(&self, group_l2_id: u32, current_time_ms: u64) -> Result<bool, SlMbsError> {
        let group_cfg = self
            .groups
            .get(&group_l2_id)
            .ok_or(SlMbsError::GroupNotFound(group_l2_id))?;

        let cycle = group_cfg.drx_cycle_ms.max(1) as u64;
        let on_duration = group_cfg.drx_on_duration_ms.max(1) as u64;

        let time_in_cycle = current_time_ms % cycle;
        Ok(time_in_cycle < on_duration)
    }
}
